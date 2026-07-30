/**
 * Everything that needs no database.
 *
 * The first block is the one that matters most. AD-09's fail-closed set is narrow and explicit,
 * and the whole point of deriving `FAIL_CLOSED_ACTIONS` from the registry is that it cannot drift
 * away from the four actions the decision names. The test below writes those four out literally —
 * on purpose, and it is the only place in this repository that does — so that adding a fifth
 * fail-closed action, or quietly opening one of these, is a red build.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SCOPES } from '@cloudsforge/contracts-auth'
import {
  ACTIONS,
  ACTION_NAMES,
  FAIL_CLOSED_ACTIONS,
  FAIL_OPEN_ACTIONS,
  compareDecimal,
  failSafe,
  isAction,
} from './actions.ts'
import { addDecimal, evaluate, windowStart, type Snapshot } from './evaluate.ts'
import { RuleValidationError, parseRuleDefinition, strictest } from './rules.ts'
import { DECIDE_SCOPE } from './server.ts'
import { REQUIRED_CLEARANCES } from './migrations.ts'
import type { Rule } from './rules.ts'

/* ------------------------------------------------------------------ the split */

test('THE RULE: the fail-closed set is exactly the four actions AD-09 names', () => {
  assert.deepEqual([...FAIL_CLOSED_ACTIONS].sort(), [
    'custody.key.export',
    'identity.session.new_device',
    'ledger.treasury_spend',
    'wallet.withdrawal',
  ])
  // And the two sets partition the registry, so no action can be neither — which is how one ends
  // up being decided by whichever branch happens to run first.
  assert.equal(FAIL_CLOSED_ACTIONS.length + FAIL_OPEN_ACTIONS.length, ACTION_NAMES.length)
  assert.equal(new Set([...FAIL_CLOSED_ACTIONS, ...FAIL_OPEN_ACTIONS]).size, ACTION_NAMES.length)
})

test('every registered action declares a fail mode, and the registry is closed', () => {
  for (const name of ACTION_NAMES) {
    const mode = ACTIONS[name].failMode.kind
    assert.ok(['closed', 'open', 'closed_at_or_above'].includes(mode), `${name} has fail mode ${mode}`)
  }
  // An unregistered action cannot reach `failSafe` at all: it is refused at the edge, because
  // defaulting it either way is a decision nobody would make deliberately.
  assert.equal(isAction('custody.key.exprot'), false)
  assert.equal(isAction('wallet.withdrawal'), true)
})

test('a fail-closed action denies when the rule store cannot be read', () => {
  for (const action of ['custody.key.export', 'ledger.treasury_spend', 'identity.session.new_device'] as const) {
    const outcome = failSafe({ action })
    assert.equal(outcome.allow, false, `${action} must deny`)
    assert.match(outcome.reason, /rule_store_unavailable/)
  }
})

test('a fail-open action allows when the rule store cannot be read', () => {
  for (const action of FAIL_OPEN_ACTIONS) {
    const outcome = failSafe({ action })
    assert.equal(outcome.allow, true, `${action} must allow`)
    assert.match(outcome.reason, /fails_open/)
  }
})

test('a withdrawal fails closed above the floor and open below it', () => {
  const above = failSafe({ action: 'wallet.withdrawal', amount: '1000', asset: 'SHARD' })
  assert.equal(above.allow, false, 'at the floor is at or above it')
  const below = failSafe({ action: 'wallet.withdrawal', amount: '999.999999', asset: 'SHARD' })
  assert.equal(below.allow, true)

  // An asset with no floor set is an asset nobody has thought about, and the conservative reading
  // is the only one available for money leaving.
  assert.equal(failSafe({ action: 'wallet.withdrawal', amount: '1', asset: 'DOGE' }).allow, false)
  // A withdrawal that did not say how much, of what, cannot be judged against a floor.
  assert.equal(failSafe({ action: 'wallet.withdrawal' }).allow, false)
  assert.equal(failSafe({ action: 'wallet.withdrawal', amount: 'lots', asset: 'SHARD' }).allow, false)
})

test('thresholds are compared as decimals, never as floats', () => {
  // 0.1 + 0.2 is why. A binary float comparison here would make a value below the floor read as
  // at it, or the other way around, on values that look identical in a log.
  assert.equal(compareDecimal('0.1', '0.10'), 0)
  assert.equal(compareDecimal('0.30000000000000004', '0.3'), 1)
  assert.equal(compareDecimal('0.05', '0.050000000000000001'), -1)
  assert.equal(compareDecimal('9007199254740993', '9007199254740992'), 1, 'beyond 2^53')
  assert.equal(compareDecimal('-1', '0'), null, 'a negative is not decidable, not zero')
  assert.equal(compareDecimal('1e3', '10'), null, 'exponent notation is not a plain decimal')
})

test('decimal addition is exact', () => {
  assert.equal(addDecimal('0.1', '0.2'), '0.3')
  assert.equal(addDecimal('1', '2'), '3')
  assert.equal(addDecimal('0.05', '0.05'), '0.1')
  assert.equal(addDecimal('1.500', '0.5'), '2')
  assert.equal(addDecimal('x', '1'), null)
})

/* ------------------------------------------------------------------ contracts */

test('the decide scope is the one in the contracts registry, not a lookalike', () => {
  // A typo here would be a scope no token can ever carry, and the symptom would be every caller
  // getting 403 with a message naming a scope that does not exist.
  assert.ok(Object.hasOwn(SCOPES, DECIDE_SCOPE))
  assert.equal(SCOPES[DECIDE_SCOPE].service, 'policy')
})

test('a freeze needs two operators, and the constant says so once', () => {
  assert.equal(REQUIRED_CLEARANCES, 2)
})

/* ------------------------------------------------------------------ rule parsing */

test('a malformed rule is refused when it is written, not when it is evaluated', () => {
  // A rule that throws inside the evaluator is a rule store failure, which for a withdrawal
  // denies everything. Rejecting it at the admin route makes a typo a 400 to an operator.
  assert.throws(() => parseRuleDefinition({ kind: 'nonsense' }), RuleValidationError)
  assert.throws(() => parseRuleDefinition({ kind: 'velocity', windowSeconds: 60 }), RuleValidationError)
  assert.throws(
    () => parseRuleDefinition({ kind: 'velocity', windowSeconds: 60, maxAmount: '5', verdict: 'deny' }),
    RuleValidationError,
    'maxAmount without an asset sums two currencies into one number',
  )
  assert.throws(
    () => parseRuleDefinition({ kind: 'risk_score', challengeAtOrAbove: 90, reviewAtOrAbove: 50, denyAtOrAbove: 95 }),
    RuleValidationError,
    'a band that cannot be reached reads as a control and is not one',
  )
  assert.throws(() => parseRuleDefinition({ kind: 'amount_limit', asset: 'SHARD', thresholds: [] }), RuleValidationError)
})

test('amount thresholds are stored strictest first, whatever order they arrive in', () => {
  const definition = parseRuleDefinition({
    kind: 'amount_limit',
    asset: 'SHARD',
    thresholds: [
      { atOrAbove: '100', verdict: 'challenge' },
      { atOrAbove: '10000', verdict: 'deny' },
      { atOrAbove: '1000', verdict: 'review' },
    ],
  })
  assert.equal(definition.kind, 'amount_limit')
  if (definition.kind !== 'amount_limit') return
  assert.deepEqual(definition.thresholds.map((t) => t.atOrAbove), ['10000', '1000', '100'])
})

test('verdicts combine by taking the strictest, never by voting', () => {
  assert.equal(strictest('allow', 'challenge'), 'challenge')
  assert.equal(strictest('challenge', 'review'), 'review')
  assert.equal(strictest('review', 'deny'), 'deny')
  // The direction that matters: an allowing rule cannot cancel a denying one.
  assert.equal(strictest('deny', 'allow'), 'deny')
})

/* ------------------------------------------------------------------ evaluation, pure */

const NOW = Date.UTC(2026, 6, 30, 12, 0, 0)

function rule(key: string, definition: unknown, version = 1): Rule {
  return {
    id: `rule-${key}`,
    key,
    version,
    action: 'wallet.withdrawal',
    definition: parseRuleDefinition(definition),
    enabled: true,
    createdAt: new Date(NOW).toISOString(),
    createdBy: 'operator:test',
    note: null,
  }
}

function snapshot(overrides: Partial<Snapshot> = {}): Snapshot {
  return {
    rules: [],
    freezes: [],
    velocity: [],
    destinationTrusted: null,
    timersStartedAt: {},
    ...overrides,
  }
}

const withdrawal = (context: Record<string, unknown> = {}) => ({
  subject: 'user:u-1',
  action: 'wallet.withdrawal' as const,
  resourceUrn: 'urn:cloudsforge:wallet:w-1',
  context: { amount: '50', asset: 'SHARD', ...context },
  correlationId: 'req-1',
})

test('a request that matches nothing is allowed, and says so', () => {
  const decision = evaluate(withdrawal(), snapshot(), NOW)
  assert.equal(decision.verdict, 'allow')
  assert.deepEqual(decision.reasons, ['no_rule_matched'])
  assert.equal(decision.failOpen, false)
})

test('an amount above a threshold denies, with the threshold in the reason', () => {
  const decision = evaluate(
    withdrawal({ amount: '5000' }),
    snapshot({
      rules: [
        rule('withdrawal-limit', {
          kind: 'amount_limit',
          asset: 'SHARD',
          thresholds: [
            { atOrAbove: '1000', verdict: 'deny' },
            { atOrAbove: '100', verdict: 'challenge' },
          ],
        }),
      ],
    }),
    NOW,
  )
  assert.equal(decision.verdict, 'deny')
  assert.deepEqual(decision.reasons, ['amount_at_or_above:1000:SHARD'])
  // The rule that decided is named on the decision, at the version that decided.
  assert.deepEqual(decision.ruleVersions, ['withdrawal-limit@1'])
})

test('a rule for another asset does not fire', () => {
  const decision = evaluate(
    withdrawal({ amount: '5000', asset: 'ETH' }),
    snapshot({
      rules: [rule('limit', { kind: 'amount_limit', asset: 'SHARD', thresholds: [{ atOrAbove: '1', verdict: 'deny' }] })],
    }),
    NOW,
  )
  assert.equal(decision.verdict, 'allow')
})

test('a freeze denies whatever the rules say, and short-circuits them', () => {
  const decision = evaluate(
    withdrawal({ amount: '1' }),
    snapshot({
      freezes: [{ id: 'f-1', subject: 'user:u-1', scope: '*', reason: 'suspected takeover' }],
      rules: [rule('limit', { kind: 'amount_limit', asset: 'SHARD', thresholds: [{ atOrAbove: '9999', verdict: 'deny' }] })],
    }),
    NOW,
  )
  assert.equal(decision.verdict, 'deny')
  assert.deepEqual(decision.reasons, ['frozen:*', 'freeze_reason:suspected takeover'])
  assert.equal(decision.riskScore, 100)
})

test('an asset-scoped freeze stops that asset and no other', () => {
  // SD-10's reconciliation drift freeze. Freezing every asset because one chain drifted would be
  // a bigger outage than the drift.
  const freezes = [{ id: 'f-1', subject: 'user:u-1', scope: 'asset:ETH', reason: 'reconciliation drift' }]
  assert.equal(evaluate(withdrawal({ asset: 'ETH' }), snapshot({ freezes }), NOW).verdict, 'deny')
  assert.equal(evaluate(withdrawal({ asset: 'SHARD' }), snapshot({ freezes }), NOW).verdict, 'allow')
})

test('an untrusted destination challenges and obliges the caller to hold it', () => {
  const decision = evaluate(
    withdrawal({ destination: '0xdead' }),
    snapshot({
      destinationTrusted: false,
      rules: [rule('new-destination', { kind: 'trusted_address', verdict: 'challenge', coolingOffSeconds: 86400 })],
    }),
    NOW,
  )
  assert.equal(decision.verdict, 'challenge')
  assert.ok(decision.reasons.includes('destination_not_trusted'))
  // Policy decides; the caller enforces. The hold is an obligation, not something this service did.
  assert.ok(decision.obligations.includes('hold_for_seconds:86400'))
  assert.ok(decision.obligations.includes('mfa_reauth'))
})

test('a cooling-off timer that has not elapsed denies, and one that has allows', () => {
  const definition = { kind: 'cooling_off', timer: 'export', seconds: 86_400, verdict: 'deny' }
  const rules = [rule('export-cooloff', definition)]

  // Never started: denied, and the caller is told to start it. The first attempt is always
  // refused — that is what makes a cooling-off period a period rather than a formality.
  const first = evaluate(withdrawal(), snapshot({ rules }), NOW)
  assert.equal(first.verdict, 'deny')
  assert.ok(first.reasons.some((r) => r.startsWith('cooling_off_not_started:export')))
  assert.ok(first.obligations.includes('start_timer:export:86400'))

  // Started 23 hours ago: still denied, and the remaining time is on the decision.
  const started = NOW - 23 * 3_600_000
  const pending = evaluate(withdrawal(), snapshot({ rules, timersStartedAt: { export: started } }), NOW)
  assert.equal(pending.verdict, 'deny')
  assert.ok(pending.reasons.some((r) => r === 'cooling_off_active:export:3600s_remaining'))

  // One second past: allowed. `now` is a parameter precisely so this is a test rather than a
  // 24-hour sleep nobody would ever run.
  const elapsed = evaluate(
    withdrawal(),
    snapshot({ rules, timersStartedAt: { export: started } }),
    started + 86_400_000,
  )
  assert.equal(elapsed.verdict, 'allow')
})

test('a velocity count cap counts this request, so the cap means what it says', () => {
  const rules = [rule('hourly', { kind: 'velocity', windowSeconds: 3_600, maxCount: 3, verdict: 'deny' })]

  const third = evaluate(
    withdrawal(),
    snapshot({ rules, velocity: [{ windowSeconds: 3_600, count: 2, amountTotal: '0', asset: 'SHARD' }] }),
    NOW,
  )
  assert.equal(third.verdict, 'allow', 'the third of three is still within the cap')

  const fourth = evaluate(
    withdrawal(),
    snapshot({ rules, velocity: [{ windowSeconds: 3_600, count: 3, amountTotal: '0', asset: 'SHARD' }] }),
    NOW,
  )
  assert.equal(fourth.verdict, 'deny')
  assert.ok(fourth.reasons.includes('velocity_count:4/3:3600s'))
})

test('a velocity amount cap sums only its own asset', () => {
  const rules = [
    rule('hourly-value', {
      kind: 'velocity',
      windowSeconds: 3_600,
      maxAmount: '100',
      asset: 'SHARD',
      verdict: 'review',
    }),
  ]
  const under = evaluate(
    withdrawal({ amount: '50' }),
    snapshot({ rules, velocity: [{ windowSeconds: 3_600, count: 1, amountTotal: '50', asset: 'SHARD' }] }),
    NOW,
  )
  assert.equal(under.verdict, 'allow', '50 + 50 is exactly the cap, not above it')

  const over = evaluate(
    withdrawal({ amount: '50.01' }),
    snapshot({ rules, velocity: [{ windowSeconds: 3_600, count: 1, amountTotal: '50', asset: 'SHARD' }] }),
    NOW,
  )
  assert.equal(over.verdict, 'review')
  assert.ok(over.reasons.includes('velocity_amount:100.01/100:SHARD:3600s'))
})

test('window boundaries are the floor of the clock, and both sides agree on them', () => {
  const width = 3_600_000
  assert.equal(windowStart(NOW, 3_600), NOW, 'noon exactly is the start of its own hour')
  assert.equal(windowStart(NOW + width - 1, 3_600), NOW)
  assert.equal(windowStart(NOW + width, 3_600), NOW + width, 'one millisecond later is a new window')
})

test('risk signals add up and the bands are applied once', () => {
  const rules = [
    rule('risk', { kind: 'risk_score', challengeAtOrAbove: 30, reviewAtOrAbove: 60, denyAtOrAbove: 90 }),
  ]
  // AD-09's story: a new device, plus an untrusted address, plus no MFA. 30 + 35 + 20 = 85.
  const decision = evaluate(
    withdrawal({ destination: '0xdead', newDevice: true, mfaSatisfied: false }),
    snapshot({ rules, destinationTrusted: false }),
    NOW,
  )
  assert.equal(decision.riskScore, 85)
  assert.equal(decision.verdict, 'review')
  assert.ok(decision.reasons.includes('risk_score:85>=review:60'))
  assert.ok(decision.reasons.includes('signal:new_device:30'))

  // No single signal reaches a default deny band alone: a user who bought a laptop is not an
  // account takeover.
  const laptop = evaluate(withdrawal({ newDevice: true }), snapshot({ rules }), NOW)
  assert.equal(laptop.riskScore, 30)
  assert.equal(laptop.verdict, 'challenge')
})

test('the score is capped at 100 so a band above it is unreachable by construction', () => {
  const rules = [rule('risk', { kind: 'risk_score', challengeAtOrAbove: 0, reviewAtOrAbove: 50, denyAtOrAbove: 100 })]
  const decision = evaluate(
    withdrawal({ destination: '0x1', newDevice: true, mfaSatisfied: false, countryChanged: true, recentFailures: 99 }),
    snapshot({ rules, destinationTrusted: false }),
    NOW,
  )
  assert.equal(decision.riskScore, 100)
  assert.equal(decision.verdict, 'deny')
})
