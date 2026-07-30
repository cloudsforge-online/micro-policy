/**
 * Everything that touches the database on the decision path.
 *
 * The split between this file and `evaluate.ts` is the design, not a preference. Reading is here
 * and can fail; deciding is there and cannot. That is what makes AD-09's fail-closed/fail-open
 * split a property of one function (`failSafe`) called from one place, rather than a `try` around
 * every query with a slightly different answer in each.
 *
 * ## What "the rule store read failed" actually means
 *
 * Not "the database is gone" — if it were, this service could not record the decision either, and
 * an unrecorded decision is an opinion. It means the read of rules, counters, freezes, trusted
 * addresses or timers did not complete: a statement timeout, a lock, a row that will not parse,
 * a replica that has fallen behind. Those are the realistic failures, they are survivable, and
 * they are exactly the ones the split exists for.
 */

import type { Sql, TransactionSql } from 'postgres'
import { isAction, type ActionName } from './actions.ts'
import { parseRuleDefinition, type Rule } from './rules.ts'
import { windowStart, type ActiveFreeze, type DecisionRequest, type Snapshot, type VelocityWindow } from './evaluate.ts'

export type Db = Sql
export type Tx = TransactionSql

/**
 * The port the decision path depends on.
 *
 * An interface rather than the function directly, so a test can make the read fail without
 * breaking the database it also needs in order to assert that the decision was written. There is
 * no other way to test the fail-safe honestly: taking Postgres away takes the evidence with it.
 */
export interface SnapshotReader {
  read(request: DecisionRequest, now: number): Promise<Snapshot>
}

/* ------------------------------------------------------------------ rows */

interface RuleRow {
  readonly id: string
  readonly rule_key: string
  readonly version: number
  readonly action: string
  readonly definition: unknown
  readonly enabled: boolean
  readonly created_at: Date
  readonly created_by: string
  readonly note: string | null
}

function toRule(row: RuleRow): Rule {
  if (!isAction(row.action)) {
    // A rule naming an action the registry no longer has cannot be evaluated, and pretending it
    // evaluated to `allow` would be a silently disabled control. Throwing routes it to the
    // fail-safe, which is the correct answer to "we do not know what this rule means".
    throw new Error(`rule ${row.rule_key}@${row.version} names unknown action "${row.action}"`)
  }
  return {
    id: row.id,
    key: row.rule_key,
    version: row.version,
    action: row.action,
    definition: parseRuleDefinition(row.definition),
    enabled: row.enabled,
    createdAt: row.created_at.toISOString(),
    createdBy: row.created_by,
    note: row.note,
  }
}

/* ------------------------------------------------------------------ the snapshot read */

export function postgresSnapshotReader(sql: Db): SnapshotReader {
  return {
    async read(request, now) {
      // `distinct on (rule_key)` takes the newest version of each rule, whatever its enabled
      // flag. Disabling is itself a new version, so the newest row is always the truth — filtering
      // on `enabled` inside the query would resurrect the previous version of a disabled rule.
      const ruleRows = await sql<RuleRow[]>`
        select distinct on (rule_key)
               id, rule_key, version, action, definition, enabled, created_at, created_by, note
          from policy_rules
         where action = ${request.action}
         order by rule_key, version desc
      `
      const rules = ruleRows.map(toRule).filter((rule) => rule.enabled)

      const freezeRows = await sql<{ id: string; subject: string; scope: string; reason: string }[]>`
        select id, subject, scope, reason
          from freezes
         where subject = ${request.subject} and cleared_at is null
      `
      const freezes: ActiveFreeze[] = freezeRows.map((row) => ({
        id: row.id,
        subject: row.subject,
        scope: row.scope,
        reason: row.reason,
      }))

      const velocity = await readVelocity(sql, request, now, rules)
      const destinationTrusted = await readDestinationTrust(sql, request)

      const timerRows = await sql<{ timer: string; started_at: Date }[]>`
        select timer, started_at
          from cooling_off_timers
         where subject = ${request.subject} and cleared_at is null
      `
      const timersStartedAt: Record<string, number> = {}
      for (const row of timerRows) timersStartedAt[row.timer] = row.started_at.getTime()

      return { rules, freezes, velocity, destinationTrusted, timersStartedAt }
    },
  }
}

/** The distinct window lengths this action's rules care about. Nothing else is read. */
export function velocityWindowsFor(rules: readonly Rule[]): readonly number[] {
  const windows = new Set<number>()
  for (const rule of rules) {
    if (rule.definition.kind === 'velocity') windows.add(rule.definition.windowSeconds)
  }
  return [...windows]
}

async function readVelocity(
  sql: Db,
  request: DecisionRequest,
  now: number,
  rules: readonly Rule[],
): Promise<VelocityWindow[]> {
  const windows = velocityWindowsFor(rules)
  if (windows.length === 0) return []
  const asset = request.context.asset ?? ''

  const out: VelocityWindow[] = []
  for (const windowSeconds of windows) {
    const start = new Date(windowStart(now, windowSeconds))
    // Counts live in the asset-less bucket and amounts in the per-asset one. Keeping them apart is
    // what lets "no more than three withdrawals an hour" mean three withdrawals rather than three
    // per asset, while "no more than 5 ETH an hour" still sums only ETH.
    const rows = await sql<{ asset: string; used_count: number; amount_total: string }[]>`
      select asset, used_count, amount_total
        from velocity_counters
       where subject = ${request.subject}
         and action = ${request.action}
         and window_seconds = ${windowSeconds}
         and window_start = ${start}
         and asset in (${''}, ${asset})
    `
    const countRow = rows.find((row) => row.asset === '')
    const amountRow = asset === '' ? undefined : rows.find((row) => row.asset === asset)
    out.push({
      windowSeconds,
      count: countRow?.used_count ?? 0,
      amountTotal: amountRow?.amount_total ?? '0',
      asset: asset === '' ? null : asset,
    })
  }
  return out
}

async function readDestinationTrust(sql: Db, request: DecisionRequest): Promise<boolean | null> {
  const destination = request.context.destination
  if (destination === undefined || destination === '') return null
  // Matched exactly, and deliberately not case-folded. An EVM address is case-insensitive but a
  // Bitcoin or Solana base58 address is not, so lower-casing here would make two different
  // Solana addresses look like the same trusted destination. Callers normalise per chain.
  const rows = await sql<{ n: number }[]>`
    select count(*)::int as n
      from trusted_addresses
     where subject = ${request.subject}
       and chain = ${request.context.chain ?? ''}
       and address = ${destination}
       and revoked_at is null
       and effective_at <= now()
  `
  return (rows[0]?.n ?? 0) > 0
}

/* ------------------------------------------------------------------ writes on the decision path */

/**
 * Consume velocity budget for a decision that allowed.
 *
 * **Only `allow` consumes.** A denied request did not happen, and counting it would let a subject
 * who is already blocked stay blocked for a whole extra window by retrying — a denial that
 * lengthens itself is a denial nobody can get out of.
 *
 * There is a real approximation here and it is worth naming: policy decides, callers enforce, so
 * an allowed decision the caller then abandoned still consumed budget. That errs towards denying,
 * which is the direction to err in, and the alternative — a confirmation callback — puts policy
 * back in the data path that AD-09 removed it from.
 */
export async function consumeVelocity(
  tx: Tx,
  request: DecisionRequest,
  now: number,
  windows: readonly number[],
): Promise<void> {
  const asset = request.context.asset ?? ''
  const amount = request.context.amount
  for (const windowSeconds of windows) {
    const start = new Date(windowStart(now, windowSeconds))
    await tx`
      insert into velocity_counters (subject, action, window_seconds, window_start, asset, used_count)
      values (${request.subject}, ${request.action}, ${windowSeconds}, ${start}, ${''}, 1)
      on conflict (subject, action, window_seconds, window_start, asset)
      do update set used_count = velocity_counters.used_count + 1, updated_at = now()
    `
    if (asset !== '' && amount !== undefined) {
      await tx`
        insert into velocity_counters (subject, action, window_seconds, window_start, asset, amount_total)
        values (${request.subject}, ${request.action}, ${windowSeconds}, ${start}, ${asset}, ${amount})
        on conflict (subject, action, window_seconds, window_start, asset)
        do update set amount_total = velocity_counters.amount_total + ${amount}, updated_at = now()
      `
    }
  }
}

/**
 * Start a cooling-off timer, unless one is already running.
 *
 * `do nothing` on conflict is the control. If a repeated attempt restarted the clock, a user
 * would never get through — and if it *replaced* an older start with a newer one, an attacker
 * could not shorten it either, but a legitimate user's 24 hours would silently become 48 every
 * time they refreshed the page. The first attempt starts it; every later one reads it.
 *
 * **`started_at` is the decision's clock, not the database's default.** The elapsed check in
 * `evaluate.ts` compares this value against the same `now` the decision was made with, and a row
 * written with `now()` would be comparing a database clock against an application one. Those two
 * agree almost always, which is exactly what makes the disagreement so hard to find: a timer
 * would elapse a second early or late, on one replica, occasionally.
 */
export async function startTimers(
  tx: Tx,
  subject: string,
  timers: readonly string[],
  now: number,
): Promise<void> {
  const startedAt = new Date(now)
  for (const timer of timers) {
    await tx`
      insert into cooling_off_timers (subject, timer, started_at) values (${subject}, ${timer}, ${startedAt})
      on conflict (subject, timer) do nothing
    `
  }
}

/** Obligations of the form `start_timer:<timer>:<seconds>` name the timers to start. */
export function timersFromObligations(obligations: readonly string[]): readonly string[] {
  return obligations
    .filter((obligation) => obligation.startsWith('start_timer:'))
    .map((obligation) => obligation.split(':')[1] ?? '')
    .filter((timer) => timer !== '')
}

/* ------------------------------------------------------------------ admin: rules */

export interface RuleInput {
  readonly key: string
  readonly action: ActionName
  readonly definition: ReturnType<typeof parseRuleDefinition>
  readonly enabled: boolean
  readonly createdBy: string
  readonly note?: string | undefined
}

/**
 * Write the next version of a rule.
 *
 * The version is computed inside the statement rather than read and then written, so two
 * operators editing the same rule at once produce versions 4 and 5 rather than both producing 4
 * and one losing to the unique constraint after already having reported success.
 */
export async function putRule(sql: Db, input: RuleInput): Promise<Rule> {
  const rows = await sql<RuleRow[]>`
    insert into policy_rules (rule_key, version, action, kind, definition, enabled, created_by, note)
    select ${input.key},
           coalesce(max(version), 0) + 1,
           ${input.action},
           ${input.definition.kind},
           ${sql.json(input.definition as unknown as Record<string, never>)},
           ${input.enabled},
           ${input.createdBy},
           ${input.note ?? null}
      from policy_rules where rule_key = ${input.key}
    returning id, rule_key, version, action, definition, enabled, created_at, created_by, note
  `
  const row = rows[0]
  if (!row) throw new Error('rule insert returned no row')
  return toRule(row)
}

export async function listRules(sql: Db, action?: ActionName): Promise<Rule[]> {
  const rows = action
    ? await sql<RuleRow[]>`
        select distinct on (rule_key)
               id, rule_key, version, action, definition, enabled, created_at, created_by, note
          from policy_rules where action = ${action} order by rule_key, version desc
      `
    : await sql<RuleRow[]>`
        select distinct on (rule_key)
               id, rule_key, version, action, definition, enabled, created_at, created_by, note
          from policy_rules order by rule_key, version desc
      `
  return rows.map(toRule)
}

export async function ruleHistory(sql: Db, key: string): Promise<Rule[]> {
  const rows = await sql<RuleRow[]>`
    select id, rule_key, version, action, definition, enabled, created_at, created_by, note
      from policy_rules where rule_key = ${key} order by version desc
  `
  return rows.map(toRule)
}

/**
 * Disable a rule.
 *
 * Not a `DELETE`. A deleted rule takes its history with it, and every decision that cited it now
 * names a version that cannot be looked up — which defeats the only reason `rule_versions[]`
 * exists. Disabling is a new version with `enabled = false`, so the shape of the change is the
 * same as every other change to a rule.
 */
export async function disableRule(sql: Db, key: string, by: string): Promise<Rule | null> {
  const current = (await ruleHistory(sql, key))[0]
  if (!current) return null
  if (!current.enabled) return current
  return putRule(sql, {
    key,
    action: current.action,
    definition: current.definition,
    enabled: false,
    createdBy: by,
    note: 'disabled',
  })
}

/* ------------------------------------------------------------------ admin: trusted addresses */

export async function trustAddress(
  sql: Db,
  input: {
    readonly subject: string
    readonly chain: string
    readonly address: string
    readonly coolingOffSeconds: number
    readonly addedBy: string
  },
): Promise<{ readonly id: string; readonly effectiveAt: string }> {
  const rows = await sql<{ id: string; effective_at: Date }[]>`
    insert into trusted_addresses (subject, chain, address, effective_at, added_by)
    values (
      ${input.subject},
      ${input.chain},
      ${input.address},
      now() + make_interval(secs => ${input.coolingOffSeconds}),
      ${input.addedBy}
    )
    on conflict do nothing
    returning id, effective_at
  `
  const row = rows[0]
  if (!row) throw new Error('that address is already trusted or pending for this subject')
  return { id: row.id, effectiveAt: row.effective_at.toISOString() }
}
