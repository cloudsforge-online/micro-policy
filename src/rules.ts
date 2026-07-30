/**
 * The rule model. Rules are data, versioned, and immutable once written.
 *
 * ## Why a version rather than an update
 *
 * 04-domain-model §10.4 requires `rule_versions[]` on every decision, and that field is only
 * worth having if the version it names still describes what the rule said. An `UPDATE` on a rule
 * row makes every decision that cited it unreproducible: the row now says something else, the
 * decision says it was evaluated against version 3, and there is no longer any version 3. So a
 * change is an insert at `version + 1` and the previous row stays exactly as it was. "Why was I
 * blocked in March" is answerable in September because March's rule is still there.
 *
 * ## Why the definitions are parsed rather than cast
 *
 * A rule arrives as JSON over an admin route and is stored as `jsonb`. Casting it to a typed
 * interface on the way out would mean a rule with a missing threshold throws inside the evaluator
 * — which is the rule store failing, which routes to the fail-safe, which for a withdrawal denies
 * everything. A malformed rule must be rejected when it is written, by the same parser the
 * evaluator trusts, so that a typo is a 400 to an operator rather than an outage two weeks later.
 */

import { compareDecimal, isAction, type ActionName } from './actions.ts'

export type Verdict = 'allow' | 'deny' | 'challenge' | 'review'

const VERDICTS: readonly Verdict[] = Object.freeze(['allow', 'deny', 'challenge', 'review'])

export function isVerdict(value: unknown): value is Verdict {
  return typeof value === 'string' && (VERDICTS as readonly string[]).includes(value)
}

/**
 * Severity order, used to combine the verdicts of several rules.
 *
 * Strictly ordered, and the order is the point: a rule that says `challenge` cannot soften a rule
 * that says `deny`. Combination is a maximum over this scale and never an average or a vote,
 * because a control that can be outvoted by two weaker controls is not a control.
 */
const SEVERITY: Readonly<Record<Verdict, number>> = Object.freeze({
  allow: 0,
  challenge: 1,
  review: 2,
  deny: 3,
})

export function strictest(left: Verdict, right: Verdict): Verdict {
  return SEVERITY[left] >= SEVERITY[right] ? left : right
}

/* ------------------------------------------------------------------ definitions */

/** A ceiling on a single request's value. The plainest control there is. */
export interface AmountLimitRule {
  readonly kind: 'amount_limit'
  readonly asset: string
  /** Ordered by the parser, strictest first, so evaluation takes the first that matches. */
  readonly thresholds: readonly { readonly atOrAbove: string; readonly verdict: Verdict }[]
}

/**
 * A cap on how much happens in a window, per subject and per action.
 *
 * The window is a length, not a calendar boundary. A fixed calendar window lets a subject spend
 * a full window's budget at 23:59 and another at 00:01; a sliding window of the same length costs
 * a table scan per decision. What this service uses is a tumbling window keyed on the floor of
 * the clock — cheap, and the boundary behaviour is a property the tests pin rather than a
 * surprise, because a caller has to know which one it is to set a sensible cap.
 */
export interface VelocityRule {
  readonly kind: 'velocity'
  readonly windowSeconds: number
  readonly maxCount?: number
  readonly maxAmount?: string
  /** Required with `maxAmount`: summing two assets into one total is meaningless. */
  readonly asset?: string
  readonly verdict: Verdict
}

/** A destination the subject has not sent to before. SD-10's "new destination" control. */
export interface TrustedAddressRule {
  readonly kind: 'trusted_address'
  readonly verdict: Verdict
  /**
   * How long the caller must hold the request. Returned as an obligation rather than enforced
   * here, because policy decides and callers enforce — AD-09.
   */
  readonly coolingOffSeconds: number
}

/** A timer that must have elapsed. Key export's 24 hours is the one that matters. */
export interface CoolingOffRule {
  readonly kind: 'cooling_off'
  /** Names the timer in `cooling_off_timers`, so one rule can govern several actions. */
  readonly timer: string
  readonly seconds: number
  readonly verdict: Verdict
}

/** Where a computed risk score stops being tolerable. */
export interface RiskScoreRule {
  readonly kind: 'risk_score'
  readonly challengeAtOrAbove: number
  readonly reviewAtOrAbove: number
  readonly denyAtOrAbove: number
}

export type RuleDefinition =
  | AmountLimitRule
  | VelocityRule
  | TrustedAddressRule
  | CoolingOffRule
  | RiskScoreRule

export type RuleKind = RuleDefinition['kind']

export const RULE_KINDS: readonly RuleKind[] = Object.freeze([
  'amount_limit',
  'velocity',
  'trusted_address',
  'cooling_off',
  'risk_score',
])

/** A stored rule. `key` is stable across versions; `(key, version)` is what a decision cites. */
export interface Rule {
  readonly id: string
  readonly key: string
  readonly version: number
  readonly action: ActionName
  readonly definition: RuleDefinition
  readonly enabled: boolean
  readonly createdAt: string
  readonly createdBy: string
  readonly note: string | null
}

/** `withdrawal-limit@3`. The spelling that lands in `policy_decisions.rule_versions`. */
export function ruleVersionLabel(rule: Pick<Rule, 'key' | 'version'>): string {
  return `${rule.key}@${rule.version}`
}

/* ------------------------------------------------------------------ validation */

export class RuleValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RuleValidationError'
  }
}

const RULE_KEY_PATTERN = /^[a-z0-9]+(?:[-.][a-z0-9]+)*$/

export function parseRuleKey(value: unknown): string {
  if (typeof value !== 'string' || !RULE_KEY_PATTERN.test(value) || value.length > 64) {
    throw new RuleValidationError('key must be lowercase, 1 to 64 characters of a-z, 0-9, - and .')
  }
  return value
}

export function parseAction(value: unknown): ActionName {
  if (typeof value !== 'string' || !isAction(value)) {
    throw new RuleValidationError(`action "${String(value)}" is not in the action registry`)
  }
  return value
}

function decimal(value: unknown, field: string): string {
  if (typeof value !== 'string' || compareDecimal(value, '0') === null) {
    throw new RuleValidationError(`${field} must be a non-negative decimal string`)
  }
  return value
}

function boundedInteger(value: unknown, field: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new RuleValidationError(`${field} must be a whole number between ${min} and ${max}`)
  }
  return value
}

function verdict(value: unknown, field: string): Verdict {
  if (!isVerdict(value)) {
    throw new RuleValidationError(`${field} must be one of ${VERDICTS.join(', ')}`)
  }
  return value
}

function assetCode(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^[A-Z][A-Z0-9:_-]{0,31}$/.test(value)) {
    throw new RuleValidationError(`${field} must be an upper-case asset code`)
  }
  return value
}

/**
 * Turn stored or submitted JSON into a definition the evaluator can rely on.
 *
 * Every branch is exhaustive over its own fields. The alternative — a permissive parse that
 * tolerates an unknown `kind` — produces a rule that is stored, listed, cited in
 * `rule_versions[]`, and silently does nothing.
 */
export function parseRuleDefinition(value: unknown): RuleDefinition {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RuleValidationError('definition must be a JSON object')
  }
  const record = value as Record<string, unknown>
  const kind = record['kind']

  if (kind === 'amount_limit') {
    const thresholds = record['thresholds']
    if (!Array.isArray(thresholds) || thresholds.length === 0) {
      throw new RuleValidationError('amount_limit.thresholds must be a non-empty array')
    }
    const parsed = thresholds.map((entry, index) => {
      if (typeof entry !== 'object' || entry === null) {
        throw new RuleValidationError(`amount_limit.thresholds[${index}] must be an object`)
      }
      const row = entry as Record<string, unknown>
      return {
        atOrAbove: decimal(row['atOrAbove'], `amount_limit.thresholds[${index}].atOrAbove`),
        verdict: verdict(row['verdict'], `amount_limit.thresholds[${index}].verdict`),
      }
    })
    // Sorted descending here rather than at evaluation time so that the stored rule and the
    // evaluated rule are the same object, and a caller reading the rule back sees the order the
    // evaluator will actually use.
    parsed.sort((a, b) => (compareDecimal(b.atOrAbove, a.atOrAbove) ?? 0))
    return { kind: 'amount_limit', asset: assetCode(record['asset'], 'amount_limit.asset'), thresholds: parsed }
  }

  if (kind === 'velocity') {
    const hasCount = record['maxCount'] !== undefined
    const hasAmount = record['maxAmount'] !== undefined
    if (!hasCount && !hasAmount) {
      throw new RuleValidationError('velocity needs at least one of maxCount or maxAmount')
    }
    if (hasAmount && record['asset'] === undefined) {
      // Summing SHARD and ETH into one total is not a cap, it is a number.
      throw new RuleValidationError('velocity.maxAmount requires velocity.asset')
    }
    return {
      kind: 'velocity',
      windowSeconds: boundedInteger(record['windowSeconds'], 'velocity.windowSeconds', 1, 31_536_000),
      ...(hasCount ? { maxCount: boundedInteger(record['maxCount'], 'velocity.maxCount', 0, 1_000_000) } : {}),
      ...(hasAmount ? { maxAmount: decimal(record['maxAmount'], 'velocity.maxAmount') } : {}),
      ...(record['asset'] !== undefined ? { asset: assetCode(record['asset'], 'velocity.asset') } : {}),
      verdict: verdict(record['verdict'], 'velocity.verdict'),
    }
  }

  if (kind === 'trusted_address') {
    return {
      kind: 'trusted_address',
      verdict: verdict(record['verdict'], 'trusted_address.verdict'),
      coolingOffSeconds: boundedInteger(
        record['coolingOffSeconds'],
        'trusted_address.coolingOffSeconds',
        0,
        2_592_000,
      ),
    }
  }

  if (kind === 'cooling_off') {
    const timer = record['timer']
    if (typeof timer !== 'string' || !RULE_KEY_PATTERN.test(timer)) {
      throw new RuleValidationError('cooling_off.timer must be a lowercase timer key')
    }
    return {
      kind: 'cooling_off',
      timer,
      seconds: boundedInteger(record['seconds'], 'cooling_off.seconds', 1, 2_592_000),
      verdict: verdict(record['verdict'], 'cooling_off.verdict'),
    }
  }

  if (kind === 'risk_score') {
    const challengeAtOrAbove = boundedInteger(record['challengeAtOrAbove'], 'risk_score.challengeAtOrAbove', 0, 100)
    const reviewAtOrAbove = boundedInteger(record['reviewAtOrAbove'], 'risk_score.reviewAtOrAbove', 0, 100)
    const denyAtOrAbove = boundedInteger(record['denyAtOrAbove'], 'risk_score.denyAtOrAbove', 0, 101)
    if (!(challengeAtOrAbove <= reviewAtOrAbove && reviewAtOrAbove <= denyAtOrAbove)) {
      // Out of order, a band is unreachable: a score can never be reviewed if review starts above
      // deny. A rule with an unreachable band reads as a control and is not one.
      throw new RuleValidationError('risk_score bands must ascend: challenge <= review <= deny')
    }
    return { kind: 'risk_score', challengeAtOrAbove, reviewAtOrAbove, denyAtOrAbove }
  }

  throw new RuleValidationError(`definition.kind must be one of ${RULE_KINDS.join(', ')}`)
}
