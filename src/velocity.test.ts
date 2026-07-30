/**
 * Velocity windows and cooling-off timers, against a real database.
 *
 * Both are controls whose whole behaviour is about time, so both are driven through the `now`
 * seam on `DecideDeps` rather than by sleeping. A test that waited out a one-hour window would be
 * a test nobody runs, and a control nobody tests is a control nobody has.
 *
 * The counter bucket is computed in two places — `windowStart` in the evaluator and the same
 * function in the store's writes — and the test that matters here is the one that crosses a
 * boundary, because a mismatch between those two would leave every cap permanently unreached
 * while every unit test still passed.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { decide } from './decide.ts'
import {
  ALICE,
  decideDeps,
  enabled,
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

/** Noon exactly, so a one-hour window starts here and the next begins at 13:00. */
const NOON = Date.UTC(2026, 6, 30, 12, 0, 0)
const HOUR = 3_600_000

const request: DecisionRequest = {
  subject: ALICE,
  action: 'wallet.withdrawal',
  resourceUrn: 'urn:cloudsforge:wallet:w-1',
  context: { amount: '10', asset: 'SHARD' },
  correlationId: 'req-velocity',
}

test('a count cap fills its window and the next window starts empty', { skip }, async () => {
  await seedRule(db(), 'hourly', 'wallet.withdrawal', {
    kind: 'velocity',
    windowSeconds: 3_600,
    maxCount: 2,
    verdict: 'deny',
  })

  let clock = NOON
  const deps = decideDeps(db(), { now: () => clock })

  assert.equal((await decide(deps, request, 'service:wallet')).decision, 'allow')
  clock = NOON + 60_000
  assert.equal((await decide(deps, request, 'service:wallet')).decision, 'allow')

  clock = NOON + HOUR - 1
  const third = await decide(deps, request, 'service:wallet')
  assert.equal(third.decision, 'deny', 'the last millisecond of the window is still in the window')
  assert.ok(third.reasons.includes('velocity_count:3/2:3600s'))

  // One millisecond later is a different bucket. This is the boundary behaviour a caller has to
  // know about to set a sensible cap, so it is pinned rather than left to be discovered.
  clock = NOON + HOUR
  const fresh = await decide(deps, request, 'service:wallet')
  assert.equal(fresh.decision, 'allow')

  const buckets = await sql<{ window_start: Date; used_count: number }[]>`
    select window_start, used_count from velocity_counters where asset = '' order by window_start
  `
  assert.equal(buckets.length, 2, 'two windows, two buckets')
  assert.equal(buckets[0]?.used_count, 2)
  assert.equal(buckets[1]?.used_count, 1)
})

test('an amount cap accumulates within a window and resets with it', { skip }, async () => {
  await seedRule(db(), 'hourly-value', 'wallet.withdrawal', {
    kind: 'velocity',
    windowSeconds: 3_600,
    maxAmount: '25',
    asset: 'SHARD',
    verdict: 'review',
  })

  let clock = NOON
  const deps = decideDeps(db(), { now: () => clock })

  for (let index = 0; index < 2; index += 1) {
    assert.equal((await decide(deps, request, 'service:wallet')).decision, 'allow')
    clock += 1_000
  }
  // 10 + 10 already spent; a third 10 would be 30, which is above 25.
  const third = await decide(deps, request, 'service:wallet')
  assert.equal(third.decision, 'review')
  assert.ok(third.reasons.includes('velocity_amount:30/25:SHARD:3600s'))

  clock = NOON + HOUR
  assert.equal((await decide(deps, request, 'service:wallet')).decision, 'allow')
})

test('counts and amounts are kept in separate buckets so each cap means what it says', { skip }, async () => {
  await seedRule(db(), 'hourly', 'wallet.withdrawal', {
    kind: 'velocity',
    windowSeconds: 3_600,
    maxCount: 10,
    verdict: 'deny',
  })
  const deps = decideDeps(db(), { now: () => NOON })
  await decide(deps, request, 'service:wallet')
  await decide(deps, { ...request, context: { amount: '10', asset: 'ETH' } }, 'service:wallet')

  const rows = await sql<{ asset: string; used_count: number; amount_total: string }[]>`
    select asset, used_count, amount_total from velocity_counters order by asset
  `
  // The asset-less bucket holds the count across both assets — "three withdrawals an hour" means
  // three withdrawals, not three per asset — and each per-asset bucket holds only its own total.
  const countBucket = rows.find((row) => row.asset === '')
  assert.equal(countBucket?.used_count, 2)
  assert.equal(rows.find((row) => row.asset === 'SHARD')?.amount_total, '10.000000000000000000')
  assert.equal(rows.find((row) => row.asset === 'ETH')?.amount_total, '10.000000000000000000')
})

test('THE RULE: a cooling-off timer that has not elapsed denies, and then allows', { skip }, async () => {
  await seedRule(db(), 'export-cooloff', 'custody.key.export', {
    kind: 'cooling_off',
    timer: 'custody-export',
    seconds: 86_400,
    verdict: 'deny',
  })

  let clock = NOON
  const deps = decideDeps(db(), { now: () => clock })
  const exportRequest: DecisionRequest = {
    subject: ALICE,
    action: 'custody.key.export',
    resourceUrn: 'urn:cloudsforge:custody:key:k-1',
    context: {},
    correlationId: 'req-export',
  }

  // The first attempt is always refused. That refusal is what starts the clock — a period that
  // began before anyone asked for it is not a cooling-off period.
  const first = await decide(deps, exportRequest, 'service:custody')
  assert.equal(first.decision, 'deny')
  assert.ok(first.reasons.some((reason) => reason.startsWith('cooling_off_not_started:')))
  const started = await sql<{ started_at: Date }[]>`
    select started_at from cooling_off_timers where subject = ${ALICE} and timer = 'custody-export'
  `
  assert.equal(started.length, 1)
  // The timer carries the decision's own clock, not the database's default. One clock, so this
  // assertion is exact rather than "within a second or so".
  assert.equal(started[0]?.started_at.getTime(), NOON)

  // 23 hours in: still denied, with the remaining time on the record.
  clock = NOON + 23 * HOUR
  const pending = await decide(deps, exportRequest, 'service:custody')
  assert.equal(pending.decision, 'deny')
  assert.ok(pending.reasons.includes('cooling_off_active:custody-export:3600s_remaining'))

  // One millisecond past the full 24 hours: allowed.
  clock = NOON + 24 * HOUR + 1
  const elapsed = await decide(deps, exportRequest, 'service:custody')
  assert.equal(elapsed.decision, 'allow')
})

test('a repeated attempt does not restart the clock', { skip }, async () => {
  await seedRule(db(), 'export-cooloff', 'custody.key.export', {
    kind: 'cooling_off',
    timer: 'custody-export',
    seconds: 3_600,
    verdict: 'deny',
  })
  const deps = decideDeps(db())
  const exportRequest: DecisionRequest = {
    subject: ALICE,
    action: 'custody.key.export',
    resourceUrn: 'urn:cloudsforge:custody:key:k-1',
    context: {},
    correlationId: 'req-export',
  }

  await decide(deps, exportRequest, 'service:custody')
  const [before] = await sql<{ started_at: Date }[]>`select started_at from cooling_off_timers`
  await decide(deps, exportRequest, 'service:custody')
  await decide(deps, exportRequest, 'service:custody')
  const [after] = await sql<{ started_at: Date }[]>`select started_at from cooling_off_timers`

  // If refreshing the page restarted the clock, a legitimate user would never get through.
  assert.equal(after?.started_at.getTime(), before?.started_at.getTime())
})

test('a trusted destination stops challenging once its own cooling-off has passed', { skip }, async () => {
  await seedRule(db(), 'new-destination', 'wallet.withdrawal', {
    kind: 'trusted_address',
    verdict: 'challenge',
    coolingOffSeconds: 86_400,
  })
  const deps = decideDeps(db())
  const toAddress: DecisionRequest = {
    ...request,
    context: { amount: '10', asset: 'SHARD', destination: '0xabc', chain: 'ethereum' },
  }

  assert.equal((await decide(deps, toAddress, 'service:wallet')).decision, 'challenge')

  // Pending: the row exists so the user can see it, and it is not yet trusted. SD-10 — adding a
  // trusted address is itself a 24-hour operation.
  await sql`
    insert into trusted_addresses (subject, chain, address, effective_at, added_by)
    values (${ALICE}, 'ethereum', '0xabc', now() + interval '1 day', 'operator:test')
  `
  assert.equal((await decide(deps, toAddress, 'service:wallet')).decision, 'challenge')

  await sql`update trusted_addresses set effective_at = now() - interval '1 second'`
  assert.equal((await decide(deps, toAddress, 'service:wallet')).decision, 'allow')
})
