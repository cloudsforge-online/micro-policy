/**
 * The decision engine. A pure function, deliberately.
 *
 * Everything that can fail — reading rules, reading counters, reading freezes — happens in
 * `snapshot.ts` and is handed to this file as a value. What remains here has no clock of its own,
 * no database and no branches that depend on either, so every rule interaction in this service
 * is testable without a container, and the fail-safe path in `actions.ts` is reachable only from
 * the one place that can actually fail.
 *
 * ## The one thing to get right
 *
 * Verdicts combine by taking the strictest, never by voting or averaging. Two `challenge` rules
 * do not add up to a `deny`, and — much more importantly — a rule that says `allow` cannot
 * cancel a rule that says `deny`. A control that another control can overrule is not a control,
 * and `strictest` in `rules.ts` is where that is enforced once for all of them.
 *
 * ## Reasons are codes, not sentences
 *
 * `reasons[]` is read by a support agent months later and by a dispute process after that, so
 * each entry is a stable machine-readable code with its numbers embedded. A sentence would be
 * rewritten by the next person who touched the file and every stored decision would then be
 * describing a rule text that no longer exists.
 */

import { compareDecimal, type ActionName } from './actions.ts'
import {
  ruleVersionLabel,
  strictest,
  type Rule,
  type Verdict,
} from './rules.ts'

/* ------------------------------------------------------------------ the request */

export interface DecisionContext {
  /** A decimal amount in the asset's display unit. Required by amount and velocity rules. */
  readonly amount?: string | undefined
  readonly asset?: string | undefined
  /** Where money is going. The trusted-address control has nothing to check without it. */
  readonly destination?: string | undefined
  readonly chain?: string | undefined
  /** Signals the calling service already knows and policy cannot see for itself. */
  readonly newDevice?: boolean | undefined
  readonly countryChanged?: boolean | undefined
  readonly mfaSatisfied?: boolean | undefined
  readonly recentFailures?: number | undefined
}

export interface DecisionRequest {
  /** `user:<uuid>`, `service:<name>` or `operator:<id>` — the vocabulary of contracts-events. */
  readonly subject: string
  readonly action: ActionName
  readonly resourceUrn: string
  readonly context: DecisionContext
  readonly correlationId: string
}

/* ------------------------------------------------------------------ the snapshot */

/** A freeze that is in force. Its presence alone denies; nothing else is consulted. */
export interface ActiveFreeze {
  readonly id: string
  readonly subject: string
  /** `*` for the whole subject, or an action name, or `asset:ETH`. */
  readonly scope: string
  readonly reason: string
}

/** How much of a window the subject has already used, for one window length. */
export interface VelocityWindow {
  readonly windowSeconds: number
  readonly count: number
  readonly amountTotal: string
  readonly asset: string | null
}

export interface Snapshot {
  /** Every enabled rule for this action, at its current version. */
  readonly rules: readonly Rule[]
  readonly freezes: readonly ActiveFreeze[]
  readonly velocity: readonly VelocityWindow[]
  /**
   * Whether the named destination is on the trusted list **and** its own cooling-off has passed.
   * `null` when the request named no destination, which is not the same as "not trusted".
   */
  readonly destinationTrusted: boolean | null
  /** Timers that have been started for this subject, by timer key, as epoch milliseconds. */
  readonly timersStartedAt: Readonly<Record<string, number>>
}

/* ------------------------------------------------------------------ the answer */

export interface Decision {
  readonly verdict: Verdict
  readonly reasons: readonly string[]
  /** What the caller must do before proceeding. The caller enforces these; policy does not. */
  readonly obligations: readonly string[]
  readonly riskScore: number
  readonly ruleVersions: readonly string[]
  /**
   * True when this answer was produced by the fail-safe rather than by the rules — i.e. the store
   * could not be read. It is on the decision rather than only in a metric because a dispute needs
   * to know that nothing was actually checked.
   */
  readonly failOpen: boolean
}

/* ------------------------------------------------------------------ risk signals */

/**
 * What each signal contributes to the risk score.
 *
 * Additive and capped at 100. Not a model, and it does not pretend to be one: it is a legible
 * arithmetic that an operator can reproduce on paper from a stored decision, which is worth more
 * here than accuracy nobody can audit. The weights are set so that no single signal reaches a
 * default deny band on its own — AD-09's story is a *combination* (new device, plus an untrusted
 * address, plus a key export within an hour), and a score that denied on one signal would deny
 * every honest user who bought a new laptop.
 */
export const SIGNAL_WEIGHTS = Object.freeze({
  new_device: 30,
  untrusted_destination: 35,
  mfa_not_satisfied: 20,
  country_changed: 15,
  velocity_breached: 25,
  /** Per recent failure, and the total contribution is capped separately below. */
  recent_failure: 5,
})

const RECENT_FAILURE_CAP = 20

export interface RiskSignal {
  readonly signal: keyof typeof SIGNAL_WEIGHTS
  readonly weight: number
}

function riskSignals(request: DecisionRequest, snapshot: Snapshot, velocityBreached: boolean): RiskSignal[] {
  const signals: RiskSignal[] = []
  if (request.context.newDevice === true) {
    signals.push({ signal: 'new_device', weight: SIGNAL_WEIGHTS.new_device })
  }
  if (snapshot.destinationTrusted === false) {
    signals.push({ signal: 'untrusted_destination', weight: SIGNAL_WEIGHTS.untrusted_destination })
  }
  if (request.context.mfaSatisfied === false) {
    signals.push({ signal: 'mfa_not_satisfied', weight: SIGNAL_WEIGHTS.mfa_not_satisfied })
  }
  if (request.context.countryChanged === true) {
    signals.push({ signal: 'country_changed', weight: SIGNAL_WEIGHTS.country_changed })
  }
  if (velocityBreached) {
    signals.push({ signal: 'velocity_breached', weight: SIGNAL_WEIGHTS.velocity_breached })
  }
  const failures = request.context.recentFailures ?? 0
  if (failures > 0) {
    signals.push({
      signal: 'recent_failure',
      weight: Math.min(failures * SIGNAL_WEIGHTS.recent_failure, RECENT_FAILURE_CAP),
    })
  }
  return signals
}

/* ------------------------------------------------------------------ evaluation */

/**
 * Decide.
 *
 * `now` is a parameter rather than a call to `Date.now()` so that a cooling-off timer can be
 * tested at the second before and the second after it elapses without a sleep. A test that sleeps
 * for a real cooling-off period is a test nobody runs.
 */
export function evaluate(request: DecisionRequest, snapshot: Snapshot, now: number): Decision {
  const reasons: string[] = []
  const obligations: string[] = []
  const ruleVersions = snapshot.rules.map(ruleVersionLabel)
  let verdict: Verdict = 'allow'

  // A freeze is checked before any rule and short-circuits the rest. It is not a rule: it is an
  // operator having said "stop", and a rule that could soften it would make the freeze advisory.
  const freeze = snapshot.freezes.find((f) => freezeCovers(f, request))
  if (freeze) {
    return {
      verdict: 'deny',
      reasons: [`frozen:${freeze.scope}`, `freeze_reason:${freeze.reason}`],
      obligations: ['operator_review'],
      // A frozen subject is at maximum risk by definition; computing a score here would invite
      // someone to compare it with an unfrozen one, which is not a comparison that means anything.
      riskScore: 100,
      ruleVersions,
      failOpen: false,
    }
  }

  let velocityBreached = false
  let riskRule: Rule | undefined

  for (const rule of snapshot.rules) {
    const definition = rule.definition

    if (definition.kind === 'amount_limit') {
      const amount = request.context.amount
      if (amount === undefined || request.context.asset !== definition.asset) continue
      for (const threshold of definition.thresholds) {
        const comparison = compareDecimal(amount, threshold.atOrAbove)
        if (comparison !== null && comparison >= 0) {
          verdict = strictest(verdict, threshold.verdict)
          reasons.push(`amount_at_or_above:${threshold.atOrAbove}:${definition.asset}`)
          // Thresholds are stored strictest-first, so the first match is the strictest that
          // applies and the looser ones below it would only add noise to the reasons.
          break
        }
      }
      continue
    }

    if (definition.kind === 'velocity') {
      const window = snapshot.velocity.find((w) => w.windowSeconds === definition.windowSeconds)
      if (!window) continue
      // The count includes this request: a cap of 3 must deny the fourth, and comparing the
      // already-recorded 3 against 3 would allow it. Off by one here is the whole rule.
      const wouldBeCount = window.count + 1
      if (definition.maxCount !== undefined && wouldBeCount > definition.maxCount) {
        verdict = strictest(verdict, definition.verdict)
        velocityBreached = true
        reasons.push(`velocity_count:${wouldBeCount}/${definition.maxCount}:${definition.windowSeconds}s`)
      }
      if (definition.maxAmount !== undefined && definition.asset !== undefined) {
        const amount = request.context.amount
        if (amount !== undefined && request.context.asset === definition.asset && window.asset === definition.asset) {
          const total = addDecimal(window.amountTotal, amount)
          const comparison = total === null ? null : compareDecimal(total, definition.maxAmount)
          if (comparison !== null && comparison > 0) {
            verdict = strictest(verdict, definition.verdict)
            velocityBreached = true
            reasons.push(`velocity_amount:${total}/${definition.maxAmount}:${definition.asset}:${definition.windowSeconds}s`)
          }
        }
      }
      continue
    }

    if (definition.kind === 'trusted_address') {
      if (snapshot.destinationTrusted !== false) continue
      verdict = strictest(verdict, definition.verdict)
      reasons.push('destination_not_trusted')
      if (definition.coolingOffSeconds > 0) {
        obligations.push(`hold_for_seconds:${definition.coolingOffSeconds}`)
      }
      continue
    }

    if (definition.kind === 'cooling_off') {
      const startedAt = snapshot.timersStartedAt[definition.timer]
      if (startedAt === undefined) {
        // The timer has not been started. Denying and telling the caller to start it is what
        // makes a cooling-off period a period rather than a formality: the first attempt is
        // always refused, and the clock begins from that refusal.
        verdict = strictest(verdict, definition.verdict)
        reasons.push(`cooling_off_not_started:${definition.timer}:${definition.seconds}s`)
        obligations.push(`start_timer:${definition.timer}:${definition.seconds}`)
        continue
      }
      const elapsesAt = startedAt + definition.seconds * 1_000
      if (now < elapsesAt) {
        verdict = strictest(verdict, definition.verdict)
        const remaining = Math.ceil((elapsesAt - now) / 1_000)
        reasons.push(`cooling_off_active:${definition.timer}:${remaining}s_remaining`)
      }
      continue
    }

    // The risk bands are applied after the loop, because the score depends on whether a velocity
    // rule breached — which is only known once every other rule has run.
    riskRule = rule
  }

  const signals = riskSignals(request, snapshot, velocityBreached)
  const riskScore = Math.min(
    100,
    signals.reduce((total, signal) => total + signal.weight, 0),
  )

  if (riskRule && riskRule.definition.kind === 'risk_score') {
    const bands = riskRule.definition
    if (riskScore >= bands.denyAtOrAbove) {
      verdict = strictest(verdict, 'deny')
      reasons.push(`risk_score:${riskScore}>=deny:${bands.denyAtOrAbove}`)
    } else if (riskScore >= bands.reviewAtOrAbove) {
      verdict = strictest(verdict, 'review')
      reasons.push(`risk_score:${riskScore}>=review:${bands.reviewAtOrAbove}`)
    } else if (riskScore >= bands.challengeAtOrAbove) {
      verdict = strictest(verdict, 'challenge')
      reasons.push(`risk_score:${riskScore}>=challenge:${bands.challengeAtOrAbove}`)
    }
    for (const signal of signals) reasons.push(`signal:${signal.signal}:${signal.weight}`)
  }

  if (verdict === 'challenge') obligations.push('mfa_reauth')
  if (verdict === 'review') obligations.push('operator_review')
  if (verdict === 'allow' && reasons.length === 0) reasons.push('no_rule_matched')

  return {
    verdict,
    reasons,
    // Deduplicated: two rules can legitimately produce the same obligation and a caller should
    // not have to hold the same request twice.
    obligations: [...new Set(obligations)],
    riskScore,
    ruleVersions,
    failOpen: false,
  }
}

/**
 * Does this freeze cover this request?
 *
 * `*` covers everything for the subject. `asset:ETH` covers any action naming that asset — which
 * is what SD-10's reconciliation-drift freeze needs, because drift is per-chain and must stop
 * withdrawals of that asset and of nothing else. Anything else is matched against the action name.
 */
function freezeCovers(freeze: ActiveFreeze, request: DecisionRequest): boolean {
  if (freeze.subject !== request.subject) return false
  if (freeze.scope === '*') return true
  if (freeze.scope.startsWith('asset:')) return freeze.scope.slice(6) === request.context.asset
  return freeze.scope === (request.action as string)
}

/**
 * Add two non-negative decimals without going through a float.
 *
 * `null` for anything that is not a plain decimal, which the caller treats as "cannot compare"
 * rather than as zero — a velocity cap that silently read a malformed total as zero would be a
 * cap that never fires.
 */
export function addDecimal(left: string, right: string): string | null {
  const pattern = /^\d+(?:\.\d+)?$/
  if (!pattern.test(left) || !pattern.test(right)) return null
  const [leftWhole = '0', leftFraction = ''] = left.split('.')
  const [rightWhole = '0', rightFraction = ''] = right.split('.')
  const width = Math.max(leftFraction.length, rightFraction.length)
  const sum = BigInt(leftWhole + leftFraction.padEnd(width, '0')) + BigInt(rightWhole + rightFraction.padEnd(width, '0'))
  if (width === 0) return sum.toString()
  const digits = sum.toString().padStart(width + 1, '0')
  const whole = digits.slice(0, digits.length - width)
  const fraction = digits.slice(digits.length - width).replace(/0+$/, '')
  return fraction.length > 0 ? `${whole}.${fraction}` : whole
}

/**
 * The window a moment falls in, for a tumbling window of the given length.
 *
 * Exported because the counter store and the evaluator must agree on it exactly: a decision that
 * read one bucket and incremented another would leave every cap permanently unreached.
 */
export function windowStart(now: number, windowSeconds: number): number {
  const width = windowSeconds * 1_000
  return Math.floor(now / width) * width
}
