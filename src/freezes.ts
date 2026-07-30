/**
 * Freezes, and the asymmetry between setting one and clearing one.
 *
 * **One operator freezes. Two clear.** The asymmetry is deliberate and it runs in the direction
 * safety runs: the mistake a single operator can make alone is stopping something that should
 * have carried on, which costs availability and is instantly reversible by two people. The
 * mistake two operators are needed to prevent is restarting money movement that was stopped for a
 * reason — a compromised account, a reconciliation drift, an investigation — and that one is not
 * reversible at all once the funds have left.
 *
 * Requiring two to freeze would mean an operator who sees an account being drained at 3am has to
 * find a colleague before they can stop it. That is the trade, stated plainly.
 *
 * ## Why "two" is a table and not a counter
 *
 * `freeze_clearances` has `(freeze_id, operator)` as its primary key, so the same operator asking
 * twice is a conflict in the database rather than a branch in application code. A counter column
 * incremented per request would clear a freeze on one operator's double-click, and no amount of
 * "check first, then increment" fixes that under concurrency — which is exactly the shape of bug
 * a control like this exists to be immune to.
 *
 * ## May the operator who froze be one of the two who clear?
 *
 * Yes, and that is a choice rather than an oversight. The control defends against one person
 * acting alone; the setter counting as one of the two still requires a second person to agree.
 * Excluding them would additionally defend against an operator who freezes in order to unfreeze
 * later, which buys nothing — they could simply not have frozen it.
 */

import { REQUIRED_CLEARANCES } from './migrations.ts'
import type { Db } from './store.ts'

export interface Clearance {
  readonly operator: string
  readonly requestedAt: string
  readonly note: string | null
}

export interface Freeze {
  readonly id: string
  readonly subject: string
  readonly scope: string
  readonly reason: string
  readonly createdBy: string
  readonly createdAt: string
  readonly clearedAt: string | null
  readonly clearances: readonly Clearance[]
  /** How many more distinct operators must ask. Zero once it is cleared. */
  readonly clearancesRequired: number
}

interface FreezeRow {
  readonly id: string
  readonly subject: string
  readonly scope: string
  readonly reason: string
  readonly created_by: string
  readonly created_at: Date
  readonly cleared_at: Date | null
}

interface ClearanceRow {
  readonly operator: string
  readonly requested_at: Date
  readonly note: string | null
}

function toFreeze(row: FreezeRow, clearances: readonly ClearanceRow[]): Freeze {
  return {
    id: row.id,
    subject: row.subject,
    scope: row.scope,
    reason: row.reason,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
    clearedAt: row.cleared_at ? row.cleared_at.toISOString() : null,
    clearances: clearances.map((clearance) => ({
      operator: clearance.operator,
      requestedAt: clearance.requested_at.toISOString(),
      note: clearance.note,
    })),
    clearancesRequired: row.cleared_at ? 0 : Math.max(0, REQUIRED_CLEARANCES - clearances.length),
  }
}

export class FreezeConflictError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FreezeConflictError'
  }
}

/**
 * The scopes a freeze may name.
 *
 * `*` is the whole subject. `asset:<CODE>` is one asset, which is what SD-10's reconciliation
 * drift freeze needs — drift is per-chain and must stop that asset and nothing else. Anything
 * else must be a registered action name, checked by the caller against the action registry so a
 * typo cannot produce a freeze that silently covers nothing.
 */
export function isAssetScope(scope: string): boolean {
  return /^asset:[A-Z][A-Z0-9:_-]{0,31}$/.test(scope)
}

export async function applyFreeze(
  sql: Db,
  input: {
    readonly subject: string
    readonly scope: string
    readonly reason: string
    readonly operator: string
  },
): Promise<Freeze> {
  const rows = await sql<FreezeRow[]>`
    insert into freezes (subject, scope, reason, created_by)
    values (${input.subject}, ${input.scope}, ${input.reason}, ${input.operator})
    on conflict do nothing
    returning id, subject, scope, reason, created_by, created_at, cleared_at
  `
  const row = rows[0]
  if (!row) {
    // The partial unique index refused it: a live freeze on this (subject, scope) already exists.
    // Returning the existing one instead would make a second operator's freeze look like it took
    // effect with their reason attached, when the reason on record is somebody else's.
    throw new FreezeConflictError(`${input.subject} is already frozen for scope ${input.scope}`)
  }
  return toFreeze(row, [])
}

export type ClearanceOutcome =
  | { readonly status: 'pending'; readonly freeze: Freeze }
  | { readonly status: 'cleared'; readonly freeze: Freeze }
  | { readonly status: 'already_cleared'; readonly freeze: Freeze }

/**
 * Record one operator's request to clear, and clear the freeze once enough distinct operators
 * have asked.
 *
 * The whole thing is one transaction over a row locked with `for update`, so two operators
 * clicking at the same instant produce one clearance each and exactly one of them observes the
 * threshold being reached. Without the lock both could read one clearance, both write, and both
 * conclude the freeze is still pending — leaving it frozen with two approvals on record, which is
 * the failure mode that is hardest to notice because nothing errored.
 */
export async function requestClearance(
  sql: Db,
  freezeId: string,
  operator: string,
  note?: string,
): Promise<ClearanceOutcome | null> {
  const outcome = await sql.begin(async (tx) => {
    const frozen = await tx<FreezeRow[]>`
      select id, subject, scope, reason, created_by, created_at, cleared_at
        from freezes where id = ${freezeId} for update
    `
    const row = frozen[0]
    if (!row) return { result: null }

    if (row.cleared_at) {
      const existing = await tx<ClearanceRow[]>`
        select operator, requested_at, note from freeze_clearances
         where freeze_id = ${freezeId} order by requested_at
      `
      return { result: { status: 'already_cleared', freeze: toFreeze(row, existing) } as ClearanceOutcome }
    }

    // A repeat by the same operator is absorbed here. It is not an error — an operator retrying
    // after a timeout should not be told they did something wrong — but it does not advance the
    // count, which is the property the whole control rests on.
    await tx`
      insert into freeze_clearances (freeze_id, operator, note)
      values (${freezeId}, ${operator}, ${note ?? null})
      on conflict (freeze_id, operator) do nothing
    `

    const clearances = await tx<ClearanceRow[]>`
      select operator, requested_at, note from freeze_clearances
       where freeze_id = ${freezeId} order by requested_at
    `

    if (clearances.length < REQUIRED_CLEARANCES) {
      return { result: { status: 'pending', freeze: toFreeze(row, clearances) } as ClearanceOutcome }
    }

    const cleared = await tx<FreezeRow[]>`
      update freezes set cleared_at = now(), cleared_note = ${note ?? null}
       where id = ${freezeId} and cleared_at is null
      returning id, subject, scope, reason, created_by, created_at, cleared_at
    `
    const clearedRow = cleared[0] ?? row
    return { result: { status: 'cleared', freeze: toFreeze(clearedRow, clearances) } as ClearanceOutcome }
  })
  return outcome.result
}

export async function getFreeze(sql: Db, freezeId: string): Promise<Freeze | null> {
  const rows = await sql<FreezeRow[]>`
    select id, subject, scope, reason, created_by, created_at, cleared_at
      from freezes where id = ${freezeId}
  `
  const row = rows[0]
  if (!row) return null
  const clearances = await sql<ClearanceRow[]>`
    select operator, requested_at, note from freeze_clearances
     where freeze_id = ${freezeId} order by requested_at
  `
  return toFreeze(row, clearances)
}

export async function listFreezes(sql: Db, subject: string): Promise<Freeze[]> {
  const rows = await sql<FreezeRow[]>`
    select id, subject, scope, reason, created_by, created_at, cleared_at
      from freezes where subject = ${subject} and cleared_at is null
     order by created_at desc
  `
  const out: Freeze[] = []
  for (const row of rows) {
    const clearances = await sql<ClearanceRow[]>`
      select operator, requested_at, note from freeze_clearances
       where freeze_id = ${row.id} order by requested_at
    `
    out.push(toFreeze(row, clearances))
  }
  return out
}
