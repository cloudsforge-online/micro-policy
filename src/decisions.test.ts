/**
 * The decision path against a real database.
 *
 * The two tests that carry the most weight are the pair in the middle: a fail-closed action must
 * deny when the rule store read fails, and a fail-open one must allow *and raise the alert*. They
 * inject the failure at `SnapshotReader` rather than by taking Postgres away, because the whole
 * claim being tested is that the decision is still recorded — and a test that removed the
 * database would remove the evidence along with the rules.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { decide } from './decide.ts'
import { getDecision, listDecisionsForSubject } from './decisions.ts'
import {
  ALICE,
  BOB,
  decideDeps,
  enabled,
  failingReader,
  migrateTestDb,
  openDb,
  resetPolicy,
  seedRule,
  skip,
} from './testsupport.ts'
import type { Db } from './store.ts'
import type { DecisionRequest } from './evaluate.ts'

let sql: postgres.Sql
const db = () => sql as unknown as Db

before(async () => {
  if (!enabled) return
  sql = openDb()
  await migrateTestDb(sql)
})

after(async () => {
  if (!enabled) return
  await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!enabled) return
  await resetPolicy(sql)
})

const withdrawal = (overrides: Partial<DecisionRequest> = {}): DecisionRequest => ({
  subject: ALICE,
  action: 'wallet.withdrawal',
  resourceUrn: 'urn:cloudsforge:wallet:w-1',
  context: { amount: '50', asset: 'SHARD' },
  correlationId: 'req-decisions',
  ...overrides,
})

test('a decision that allows is recorded and retrievable by id', { skip }, async () => {
  const deps = decideDeps(db())
  const decision = await decide(deps, withdrawal(), 'service:wallet')

  assert.equal(decision.decision, 'allow')
  assert.equal(decision.decidedFor, 'service:wallet')
  assert.equal(decision.failOpen, false)

  // "Why was I blocked" must be answerable months later, so the decision has to be a row and not
  // only a return value — 04-domain-model §10.4.
  const fetched = await getDecision(db(), decision.id)
  assert.ok(fetched)
  assert.equal(fetched.id, decision.id)
  assert.equal(fetched.subject, ALICE)
  assert.deepEqual(fetched.reasons, ['no_rule_matched'])
  assert.equal(fetched.correlationId, 'req-decisions')
})

test('a decision that denies records its reasons and the rule versions that decided', { skip }, async () => {
  await seedRule(db(), 'withdrawal-limit', 'wallet.withdrawal', {
    kind: 'amount_limit',
    asset: 'SHARD',
    thresholds: [{ atOrAbove: '1000', verdict: 'deny' }],
  })
  // A second version, so the decision must cite the current one rather than the first.
  await seedRule(db(), 'withdrawal-limit', 'wallet.withdrawal', {
    kind: 'amount_limit',
    asset: 'SHARD',
    thresholds: [{ atOrAbove: '500', verdict: 'deny' }],
  })

  const decision = await decide(decideDeps(db()), withdrawal({ context: { amount: '750', asset: 'SHARD' } }), 'service:wallet')

  assert.equal(decision.decision, 'deny')
  assert.deepEqual(decision.reasons, ['amount_at_or_above:500:SHARD'])
  assert.deepEqual(decision.ruleVersions, ['withdrawal-limit@2'], 'the version that decided, not the first')

  const fetched = await getDecision(db(), decision.id)
  assert.deepEqual(fetched?.reasons, ['amount_at_or_above:500:SHARD'])
})

test('THE RULE: a fail-closed action denies when the rule store read fails', { skip }, async () => {
  const deps = decideDeps(db(), { reader: failingReader() })
  const decision = await decide(deps, withdrawal({ action: 'custody.key.export', context: {} }), 'service:custody')

  assert.equal(decision.decision, 'deny')
  assert.equal(decision.failOpen, false)
  assert.match(decision.reasons[0] ?? '', /rule_store_unavailable_and_custody\.key\.export_fails_closed/)
  // No rule was read, so no rule may be cited. A fabricated citation is worse than none.
  assert.deepEqual(decision.ruleVersions, [])

  // Still a record: a dispute about a refusal that happened during an outage is still a dispute.
  assert.ok(await getDecision(db(), decision.id))
  assert.match(deps.metrics.render(), /policy_fail_closed_total\{action="custody\.key\.export"\} 1/)
  assert.equal(/policy_fail_open_total\{action="custody/.test(deps.metrics.render()), false)
})

test('THE RULE: a fail-open action allows when the rule store read fails, and alerts', { skip }, async () => {
  const deps = decideDeps(db(), { reader: failingReader() })
  const decision = await decide(
    deps,
    withdrawal({ action: 'market.listing.create', context: {} }),
    'service:market',
  )

  assert.equal(decision.decision, 'allow')
  assert.equal(decision.failOpen, true, 'the record must say nothing was checked')
  // The caller is told the allow was unchecked. A caller that treats it as an ordinary allow has
  // thrown away the only signal it was given.
  assert.deepEqual(decision.obligations, ['unchecked_decision'])

  // The alert AD-09 requires. Not a log line to grep for: a counter a dashboard can alert on.
  assert.match(deps.metrics.render(), /policy_fail_open_total\{action="market\.listing\.create"\} 1/)

  const fetched = await getDecision(db(), decision.id)
  assert.equal(fetched?.failOpen, true)
})

test('a withdrawal above the fail-safe floor denies while one below it is allowed', { skip }, async () => {
  const deps = decideDeps(db(), { reader: failingReader() })
  const large = await decide(deps, withdrawal({ context: { amount: '5000', asset: 'SHARD' } }), 'service:wallet')
  const small = await decide(deps, withdrawal({ context: { amount: '5', asset: 'SHARD' } }), 'service:wallet')

  assert.equal(large.decision, 'deny')
  assert.equal(small.decision, 'allow')
  assert.equal(small.failOpen, true)
  // One action, both sides of the split, because the split is per-request for this action alone.
  assert.match(deps.metrics.render(), /policy_fail_open_total\{action="wallet\.withdrawal"\} 1/)
  assert.match(deps.metrics.render(), /policy_fail_closed_total\{action="wallet\.withdrawal"\} 1/)
})

test('a decision is append-only: an update is refused by the database itself', { skip }, async () => {
  const decision = await decide(decideDeps(db()), withdrawal(), 'service:wallet')
  await assert.rejects(
    () => sql`update policy_decisions set decision = 'allow' where id = ${decision.id}`,
    /append-only/,
    'evidence that can be edited afterwards is not evidence',
  )
})

test('the decisions metric counts by action and verdict', { skip }, async () => {
  await seedRule(db(), 'limit', 'wallet.withdrawal', {
    kind: 'amount_limit',
    asset: 'SHARD',
    thresholds: [{ atOrAbove: '100', verdict: 'deny' }],
  })
  const deps = decideDeps(db())
  await decide(deps, withdrawal({ context: { amount: '10', asset: 'SHARD' } }), 'service:wallet')
  await decide(deps, withdrawal({ context: { amount: '500', asset: 'SHARD' } }), 'service:wallet')

  const rendered = deps.metrics.render()
  assert.match(rendered, /policy_decisions_total\{action="wallet\.withdrawal",decision="allow"\} 1/)
  assert.match(rendered, /policy_decisions_total\{action="wallet\.withdrawal",decision="deny"\} 1/)
  assert.match(rendered, /policy_evaluation_ms_bucket\{action="wallet\.withdrawal",le="\+Inf"\}/)
})

test("a subject's decisions page by keyset, newest first, and do not repeat", { skip }, async () => {
  const deps = decideDeps(db())
  for (let index = 0; index < 5; index += 1) {
    await decide(deps, withdrawal({ resourceUrn: `urn:cloudsforge:wallet:w-${index}` }), 'service:wallet')
  }
  await decide(deps, withdrawal({ subject: BOB }), 'service:wallet')

  const first = await listDecisionsForSubject(db(), ALICE, { limit: 2 })
  assert.equal(first.decisions.length, 2)
  assert.ok(first.nextCursor)
  assert.deepEqual(first.decisions.map((d) => d.resourceUrn), [
    'urn:cloudsforge:wallet:w-4',
    'urn:cloudsforge:wallet:w-3',
  ])

  const second = await listDecisionsForSubject(db(), ALICE, { limit: 2, cursor: first.nextCursor })
  assert.deepEqual(second.decisions.map((d) => d.resourceUrn), [
    'urn:cloudsforge:wallet:w-2',
    'urn:cloudsforge:wallet:w-1',
  ])

  const third = await listDecisionsForSubject(db(), ALICE, { limit: 2, cursor: second.nextCursor })
  assert.deepEqual(third.decisions.map((d) => d.resourceUrn), ['urn:cloudsforge:wallet:w-0'])
  assert.equal(third.nextCursor, undefined, 'the last page must not offer another')
  // Bob's decision is Bob's. A subject filter that leaked would be the worst possible bug in a
  // table that exists to answer "why was I blocked".
  assert.equal((await listDecisionsForSubject(db(), BOB, { limit: 10 })).decisions.length, 1)
})

test('an allow consumes velocity budget and a deny does not', { skip }, async () => {
  await seedRule(db(), 'hourly', 'wallet.withdrawal', {
    kind: 'velocity',
    windowSeconds: 3_600,
    maxCount: 1,
    verdict: 'deny',
  })
  const deps = decideDeps(db())

  const first = await decide(deps, withdrawal(), 'service:wallet')
  assert.equal(first.decision, 'allow')

  const second = await decide(deps, withdrawal(), 'service:wallet')
  assert.equal(second.decision, 'deny')

  // A denial that lengthened itself would be a denial nobody could get out of: the subject is
  // already blocked, and counting the refusal would extend the block by another whole window.
  const rows = await sql<{ used_count: number }[]>`
    select used_count from velocity_counters where asset = '' and subject = ${ALICE}
  `
  assert.equal(rows[0]?.used_count, 1)
})
