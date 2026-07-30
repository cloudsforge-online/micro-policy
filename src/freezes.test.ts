/**
 * The freeze asymmetry: one operator sets, two clear.
 *
 * The deliberate part is that these are different numbers. Stopping something is instantly
 * reversible by two people; restarting money movement that was stopped because an account was
 * being drained is not reversible at all. Requiring two to freeze would mean the operator who
 * spots it at 3am has to find a colleague before they can stop it.
 *
 * The test that carries the most weight is the third one: the same operator asking twice must not
 * clear a freeze alone. That is why `freeze_clearances` has `(freeze_id, operator)` as its primary
 * key rather than a counter column — a double-click is a database conflict, not a branch someone
 * has to remember to write.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { decide } from './decide.ts'
import { FreezeConflictError, applyFreeze, getFreeze, listFreezes, requestClearance } from './freezes.ts'
import {
  ALICE,
  BOB,
  OPERATOR_ONE,
  OPERATOR_TWO,
  decideDeps,
  enabled,
  migrateTestDb,
  openDb,
  resetPolicy,
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

const OPERATOR_THREE = 'operator:cccccccc-cccc-4ccc-8ccc-cccccccccccc'

const freezeAlice = () =>
  applyFreeze(db(), { subject: ALICE, scope: '*', reason: 'suspected takeover', operator: OPERATOR_ONE })

const withdrawal: DecisionRequest = {
  subject: ALICE,
  action: 'wallet.withdrawal',
  resourceUrn: 'urn:cloudsforge:wallet:w-1',
  context: { amount: '10', asset: 'SHARD' },
  correlationId: 'req-freeze',
}

test('one operator freezes, alone', { skip }, async () => {
  const freeze = await freezeAlice()
  assert.equal(freeze.createdBy, OPERATOR_ONE)
  assert.equal(freeze.clearedAt, null)
  assert.equal(freeze.clearancesRequired, 2)
  assert.deepEqual((await listFreezes(db(), ALICE)).map((f) => f.id), [freeze.id])
})

test('THE RULE: one operator cannot clear a freeze', { skip }, async () => {
  const freeze = await freezeAlice()

  const first = await requestClearance(db(), freeze.id, OPERATOR_TWO)
  assert.equal(first?.status, 'pending')
  assert.equal(first?.freeze.clearedAt, null)
  assert.equal(first?.freeze.clearancesRequired, 1)

  // Still in force, and still denying. The clearance being recorded must not soften the freeze.
  const decision = await decide(decideDeps(db()), withdrawal, 'service:wallet')
  assert.equal(decision.decision, 'deny')
  assert.ok(decision.reasons.includes('frozen:*'))
})

test('THE RULE: the same operator asking twice does not clear it', { skip }, async () => {
  const freeze = await freezeAlice()

  await requestClearance(db(), freeze.id, OPERATOR_TWO)
  const again = await requestClearance(db(), freeze.id, OPERATOR_TWO)

  // Not an error — an operator retrying after a timeout has done nothing wrong — but it does not
  // advance the count, which is the entire property this control rests on.
  assert.equal(again?.status, 'pending')
  assert.equal(again?.freeze.clearancesRequired, 1)
  assert.equal(again?.freeze.clearances.length, 1)

  const stored = await getFreeze(db(), freeze.id)
  assert.equal(stored?.clearedAt, null)
  assert.equal((await decide(decideDeps(db()), withdrawal, 'service:wallet')).decision, 'deny')
})

test('two distinct operators clear it, and the decision then allows', { skip }, async () => {
  const freeze = await freezeAlice()

  assert.equal((await requestClearance(db(), freeze.id, OPERATOR_TWO))?.status, 'pending')
  const cleared = await requestClearance(db(), freeze.id, OPERATOR_THREE)
  assert.equal(cleared?.status, 'cleared')
  assert.ok(cleared?.freeze.clearedAt)
  assert.deepEqual(cleared?.freeze.clearances.map((c) => c.operator), [OPERATOR_TWO, OPERATOR_THREE])

  assert.equal((await decide(decideDeps(db()), withdrawal, 'service:wallet')).decision, 'allow')
  assert.deepEqual(await listFreezes(db(), ALICE), [], 'a cleared freeze is not in force')
})

test('the operator who froze may be one of the two who clear', { skip }, async () => {
  // A choice rather than an oversight. The control defends against one person acting alone, and
  // the setter counting as one of the two still requires a second person to agree.
  const freeze = await freezeAlice()
  assert.equal((await requestClearance(db(), freeze.id, OPERATOR_ONE))?.status, 'pending')
  assert.equal((await requestClearance(db(), freeze.id, OPERATOR_TWO))?.status, 'cleared')
})

test('clearing an already-cleared freeze says so rather than reopening anything', { skip }, async () => {
  const freeze = await freezeAlice()
  await requestClearance(db(), freeze.id, OPERATOR_ONE)
  await requestClearance(db(), freeze.id, OPERATOR_TWO)

  const third = await requestClearance(db(), freeze.id, OPERATOR_THREE)
  assert.equal(third?.status, 'already_cleared')
  assert.ok(third?.freeze.clearedAt)
})

test('two operators clearing at the same instant clear it exactly once', { skip }, async () => {
  const freeze = await freezeAlice()
  // The row is locked `for update` inside the transaction, so one of these observes the threshold
  // being reached and the other does not. Without the lock both could read one clearance, both
  // write, and both conclude it is still pending — leaving it frozen with two approvals on
  // record, which is the failure mode hardest to notice because nothing errored.
  const [left, right] = await Promise.all([
    requestClearance(db(), freeze.id, OPERATOR_TWO),
    requestClearance(db(), freeze.id, OPERATOR_THREE),
  ])
  const statuses = [left?.status, right?.status].sort()
  assert.deepEqual(statuses, ['cleared', 'pending'])

  const stored = await getFreeze(db(), freeze.id)
  assert.ok(stored?.clearedAt)
  assert.equal(stored?.clearances.length, 2)
})

test('a second freeze on one subject and scope is refused rather than silently merged', { skip }, async () => {
  await freezeAlice()
  // Returning the existing freeze would make the second operator's reason look like it took
  // effect, when the reason on record is somebody else's.
  await assert.rejects(
    () => applyFreeze(db(), { subject: ALICE, scope: '*', reason: 'different reason', operator: OPERATOR_TWO }),
    FreezeConflictError,
  )
})

test('a freeze is per subject, and does not leak to another', { skip }, async () => {
  await freezeAlice()
  const bobs = await decide(
    decideDeps(db()),
    { ...withdrawal, subject: BOB },
    'service:wallet',
  )
  assert.equal(bobs.decision, 'allow')
})

test('an asset-scoped freeze stops that asset alone', { skip }, async () => {
  // SD-10's reconciliation drift freeze. Freezing every asset because one chain drifted would be
  // a bigger outage than the drift it is responding to.
  await applyFreeze(db(), { subject: ALICE, scope: 'asset:ETH', reason: 'reconciliation drift', operator: OPERATOR_ONE })
  const deps = decideDeps(db())

  const eth = await decide(deps, { ...withdrawal, context: { amount: '1', asset: 'ETH' } }, 'service:wallet')
  const shard = await decide(deps, { ...withdrawal, context: { amount: '1', asset: 'SHARD' } }, 'service:wallet')
  assert.equal(eth.decision, 'deny')
  assert.equal(shard.decision, 'allow')
})

test('clearing a freeze that does not exist is a miss, not a crash', { skip }, async () => {
  assert.equal(await requestClearance(db(), '00000000-0000-4000-8000-000000000000', OPERATOR_ONE), null)
})
