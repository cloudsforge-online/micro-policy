/**
 * Decision persistence.
 *
 * 04-domain-model §10.4: **a decision is a record, not just a return value.** "Why was I blocked"
 * must be answerable months later, and it is the input to a dispute. That is the whole reason
 * this file exists rather than the decision being returned and forgotten.
 *
 * The stored context is the *decision's* view of the request, not the request itself. It holds
 * what was actually consulted — amount, asset, destination, the signals the caller asserted — and
 * nothing else. A verbatim copy of the caller's body would pull whatever a caller happened to
 * send into a table retained for two years, which is how a service that stores no personal data
 * ends up storing personal data.
 */

import type { ActionName } from './actions.ts'
import type { Verdict } from './rules.ts'
import type { Db, Tx } from './store.ts'
import type { Decision, DecisionRequest } from './evaluate.ts'

export interface StoredDecision {
  readonly id: string
  readonly subject: string
  readonly action: ActionName
  readonly resourceUrn: string
  readonly decision: Verdict
  readonly reasons: readonly string[]
  readonly obligations: readonly string[]
  readonly riskScore: number
  readonly ruleVersions: readonly string[]
  readonly failOpen: boolean
  readonly correlationId: string
  /** Who asked. A service name or a user, so a dispute can name the caller as well as the rule. */
  readonly decidedFor: string
  readonly evaluationMs: number
  readonly evaluatedAt: string
  readonly context: Record<string, unknown>
}

interface DecisionRow {
  readonly id: string
  readonly subject: string
  readonly action: string
  readonly resource_urn: string
  readonly decision: string
  readonly reasons: string[]
  readonly obligations: string[]
  readonly risk_score: number
  readonly rule_versions: string[]
  readonly fail_open: boolean
  readonly correlation_id: string
  readonly decided_for: string
  readonly evaluation_ms: number
  readonly evaluated_at: Date
  readonly context: Record<string, unknown>
}

function toStored(row: DecisionRow): StoredDecision {
  return {
    id: row.id,
    subject: row.subject,
    action: row.action as ActionName,
    resourceUrn: row.resource_urn,
    decision: row.decision as Verdict,
    reasons: row.reasons,
    obligations: row.obligations,
    riskScore: row.risk_score,
    ruleVersions: row.rule_versions,
    failOpen: row.fail_open,
    correlationId: row.correlation_id,
    decidedFor: row.decided_for,
    evaluationMs: row.evaluation_ms,
    evaluatedAt: row.evaluated_at.toISOString(),
    context: row.context,
  }
}

/** Only the fields that were consulted. See the note at the top of this file. */
function storableContext(request: DecisionRequest): Record<string, unknown> {
  const context = request.context
  return {
    ...(context.amount !== undefined ? { amount: context.amount } : {}),
    ...(context.asset !== undefined ? { asset: context.asset } : {}),
    ...(context.destination !== undefined ? { destination: context.destination } : {}),
    ...(context.chain !== undefined ? { chain: context.chain } : {}),
    ...(context.newDevice !== undefined ? { newDevice: context.newDevice } : {}),
    ...(context.countryChanged !== undefined ? { countryChanged: context.countryChanged } : {}),
    ...(context.mfaSatisfied !== undefined ? { mfaSatisfied: context.mfaSatisfied } : {}),
    ...(context.recentFailures !== undefined ? { recentFailures: context.recentFailures } : {}),
  }
}

export async function recordDecision(
  tx: Tx,
  request: DecisionRequest,
  decision: Decision,
  meta: { readonly decidedFor: string; readonly evaluationMs: number },
): Promise<StoredDecision> {
  const rows = await tx<DecisionRow[]>`
    insert into policy_decisions (
      subject, action, resource_urn, decision, reasons, obligations,
      risk_score, rule_versions, fail_open, context, correlation_id, decided_for, evaluation_ms
    ) values (
      ${request.subject},
      ${request.action},
      ${request.resourceUrn},
      ${decision.verdict},
      ${[...decision.reasons]},
      ${[...decision.obligations]},
      ${decision.riskScore},
      ${[...decision.ruleVersions]},
      ${decision.failOpen},
      ${tx.json(storableContext(request) as Record<string, never>)},
      ${request.correlationId},
      ${meta.decidedFor},
      ${Math.round(meta.evaluationMs)}
    )
    returning id, subject, action, resource_urn, decision, reasons, obligations, risk_score,
              rule_versions, fail_open, correlation_id, decided_for, evaluation_ms, evaluated_at, context
  `
  const row = rows[0]
  if (!row) throw new Error('decision insert returned no row')
  return toStored(row)
}

export async function getDecision(sql: Db, id: string): Promise<StoredDecision | null> {
  const rows = await sql<DecisionRow[]>`
    select id, subject, action, resource_urn, decision, reasons, obligations, risk_score,
           rule_versions, fail_open, correlation_id, decided_for, evaluation_ms, evaluated_at, context
      from policy_decisions where id = ${id}
  `
  const row = rows[0]
  return row ? toStored(row) : null
}

export interface DecisionPage {
  readonly decisions: readonly StoredDecision[]
  /** Absent when there is no further page. Opaque to the caller by construction. */
  readonly nextCursor?: string
}

/**
 * A subject's decisions, newest first, by keyset rather than by offset.
 *
 * `OFFSET` would skip or repeat rows as new decisions arrive between pages, which for this table
 * is guaranteed rather than unlikely — a subject being investigated is a subject generating
 * decisions. The cursor is `(evaluated_at, id)` because two decisions can share a millisecond,
 * and a cursor on the timestamp alone would drop whichever of them sorted second.
 */
export async function listDecisionsForSubject(
  sql: Db,
  subject: string,
  options: { readonly limit: number; readonly cursor?: string | undefined },
): Promise<DecisionPage> {
  const cursor = options.cursor ? decodeCursor(options.cursor) : null
  const rows = cursor
    ? await sql<DecisionRow[]>`
        select id, subject, action, resource_urn, decision, reasons, obligations, risk_score,
               rule_versions, fail_open, correlation_id, decided_for, evaluation_ms, evaluated_at, context
          from policy_decisions
         where subject = ${subject}
           and (evaluated_at, id) < (${cursor.evaluatedAt}, ${cursor.id})
         order by evaluated_at desc, id desc
         limit ${options.limit + 1}
      `
    : await sql<DecisionRow[]>`
        select id, subject, action, resource_urn, decision, reasons, obligations, risk_score,
               rule_versions, fail_open, correlation_id, decided_for, evaluation_ms, evaluated_at, context
          from policy_decisions
         where subject = ${subject}
         order by evaluated_at desc, id desc
         limit ${options.limit + 1}
      `
  // One more row than asked for is fetched, so "is there another page" is a fact rather than a
  // guess from a full page — which is the bug that makes a client poll one empty page for ever.
  const page = rows.slice(0, options.limit).map(toStored)
  const last = rows[options.limit - 1]
  return rows.length > options.limit && last
    ? { decisions: page, nextCursor: encodeCursor({ evaluatedAt: last.evaluated_at, id: last.id }) }
    : { decisions: page }
}

interface Cursor {
  readonly evaluatedAt: Date
  readonly id: string
}

export class BadCursorError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadCursorError'
  }
}

export function encodeCursor(cursor: Cursor): string {
  return Buffer.from(`${cursor.evaluatedAt.toISOString()}|${cursor.id}`, 'utf8').toString('base64url')
}

export function decodeCursor(value: string): Cursor {
  const decoded = Buffer.from(value, 'base64url').toString('utf8')
  const separator = decoded.indexOf('|')
  if (separator < 0) throw new BadCursorError('cursor is not a cursor this service issued')
  const at = new Date(decoded.slice(0, separator))
  const id = decoded.slice(separator + 1)
  if (Number.isNaN(at.getTime()) || id === '') {
    throw new BadCursorError('cursor is not a cursor this service issued')
  }
  return { evaluatedAt: at, id }
}
