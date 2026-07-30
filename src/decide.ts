/**
 * The decision path, end to end. Twelve lines of orchestration around two ideas.
 *
 * The first idea is that the only thing that can fail is the read, so the only `catch` in this
 * service that changes an answer is the one below, and what it does is call `failSafe` — which is
 * a total function over the action registry and cannot be reached with an unregistered action.
 * That is what "encode the split in the rule model so it cannot drift" means in practice: there
 * is exactly one place a fail mode is chosen and it has no arguments to get wrong.
 *
 * The second idea is that the decision, its velocity consumption and its cooling-off timer are
 * one transaction. A decision recorded without the counter it consumed lets a subject repeat it;
 * a counter incremented without the decision that consumed it is a subject blocked by evidence
 * nobody can produce. Neither is acceptable and both are avoidable for the price of a `begin`.
 */

import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { failSafe } from './actions.ts'
import { recordDecision, type StoredDecision } from './decisions.ts'
import { evaluate, type Decision, type DecisionRequest } from './evaluate.ts'
import {
  consumeVelocity,
  timersFromObligations,
  startTimers,
  velocityWindowsFor,
  type Db,
  type SnapshotReader,
} from './store.ts'
import { actionSpec } from './actions.ts'

export interface DecideDeps {
  readonly sql: Db
  readonly reader: SnapshotReader
  readonly metrics: Metrics
  readonly logger: Logger
  /** A seam, so a cooling-off timer can be tested at the second before and after it elapses. */
  readonly now?: () => number
}

export async function decide(
  deps: DecideDeps,
  request: DecisionRequest,
  decidedFor: string,
): Promise<StoredDecision> {
  const now = deps.now?.() ?? Date.now()
  const startedAt = process.hrtime.bigint()

  let decision: Decision
  let velocityWindows: readonly number[] = []

  try {
    const snapshot = await deps.reader.read(request, now)
    decision = evaluate(request, snapshot, now)
    velocityWindows = velocityWindowsFor(snapshot.rules)
  } catch (err) {
    const outcome = failSafe({
      action: request.action,
      amount: request.context.amount,
      asset: request.context.asset,
    })
    decision = {
      verdict: outcome.allow ? 'allow' : 'deny',
      reasons: [outcome.reason],
      // A fail-open allow still carries an obligation: the caller is being told that nothing was
      // checked, and a caller that treats that identically to a checked allow has thrown away the
      // only signal it was given.
      obligations: outcome.allow ? ['unchecked_decision'] : ['operator_review'],
      // No rules were read, so no rule can be scored. Reporting a fabricated zero would let a
      // stored decision look like a clean one.
      riskScore: outcome.allow ? 0 : 100,
      ruleVersions: [],
      failOpen: outcome.allow,
    }

    // The alert AD-09 requires. A fail-open decision is not a normal decision and must never be
    // discoverable only by reading a table: the counter is what a dashboard alerts on, and the
    // log line is what an operator reads next.
    if (outcome.allow) {
      deps.metrics.increment('policy_fail_open_total', { action: request.action })
      deps.logger.error('policy failed OPEN — the rule store could not be read', {
        action: request.action,
        subject: request.subject,
        correlationId: request.correlationId,
        err,
      })
    } else {
      deps.metrics.increment('policy_fail_closed_total', { action: request.action })
      deps.logger.error('policy failed CLOSED — the rule store could not be read', {
        action: request.action,
        subject: request.subject,
        correlationId: request.correlationId,
        err,
      })
    }
  }

  const evaluationMs = Number(process.hrtime.bigint() - startedAt) / 1e6

  const stored = await deps.sql.begin(async (tx) => {
    const record = await recordDecision(tx, request, decision, { decidedFor, evaluationMs })
    // Only an allow consumes budget, and only for an action the registry says is counted. See the
    // note on `consumeVelocity` for why a denial deliberately does not.
    if (decision.verdict === 'allow' && actionSpec(request.action).counted && velocityWindows.length > 0) {
      await consumeVelocity(tx, request, now, velocityWindows)
    }
    const timers = timersFromObligations(decision.obligations)
    if (timers.length > 0) await startTimers(tx, request.subject, timers, now)
    return { record }
  })

  deps.metrics.increment('policy_decisions_total', {
    action: request.action,
    decision: decision.verdict,
  })
  deps.metrics.observe('policy_evaluation_ms', evaluationMs, { action: request.action })

  return stored.record
}
