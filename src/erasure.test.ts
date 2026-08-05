/**
 * Right to erasure, policy's half.
 *
 * The point of this file is the LINE, not the mechanics. Policy holds two kinds of row about a
 * person — the record of a control applied to them, and a preference they expressed — and they get
 * opposite answers. Every test below is about that line holding in both directions: a preference
 * must not survive, and a control must not be deletable by the person it was applied to.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import { eraseUser, erasureInstant, subjectForms, UUID } from './erasure.ts'
import {
  ALICE,
  ALICE_ID,
  BOB,
  BOB_ID,
  OPERATOR_ONE,
  enabled,
  migrateTestDb,
  openDb,
  resetPolicy,
  skip,
} from './testsupport.ts'
import type { Db, Tx } from './inbox.ts'

let sql: postgres.Sql

const TOMBSTONE = new Date('2026-09-01T00:00:00.000Z')
const EVENT = '44444444-4444-4444-8444-444444444444'

before(async () => {
  if (!enabled) return
  sql = openDb(4)
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

async function erase(
  userId: string,
  eventId = EVENT,
): Promise<Awaited<ReturnType<typeof eraseUser>>> {
  const outcome = await (sql as unknown as Db).begin(async (tx) => ({
    value: await eraseUser(tx as unknown as Tx, userId, { eventId, tombstoneAt: TOMBSTONE }),
  }))
  return outcome.value
}

async function seedPreferences(subject: string): Promise<void> {
  await sql`
    insert into trusted_addresses (subject, chain, address, effective_at, added_by)
    values (${subject}, 'eth', '0xdestination', now() + interval '1 day', ${subject})
  `
  await sql`
    insert into velocity_counters (subject, action, window_seconds, window_start, used_count)
    values (${subject}, 'withdrawal', 3600, date_trunc('hour', now()), 3)
  `
  await sql`
    insert into cooling_off_timers (subject, timer) values (${subject}, 'withdrawal-refused')
  `
}

async function seedDecision(subject: string): Promise<void> {
  await sql`
    insert into policy_decisions (
      subject, action, resource_urn, decision, reasons, correlation_id, decided_for
    )
    values (
      ${subject}, 'withdrawal', 'cf:wallet:withdrawal:1', 'deny', array['velocity_exceeded'],
      'corr-1', ${subject}
    )
  `
}

async function seedFreeze(subject: string): Promise<void> {
  await sql`
    insert into freezes (subject, scope, reason, created_by)
    values (${subject}, '*', 'suspected fraud', ${OPERATOR_ONE})
  `
}

test('both spellings of one person are matched, ledger spelling first', { skip }, () => {
  assert.deepEqual(subjectForms(ALICE_ID), [ALICE, ALICE_ID])
})

test('the marker is anchored at the tombstone, never at delivery time', { skip }, () => {
  assert.deepEqual(erasureInstant(TOMBSTONE.toISOString()), TOMBSTONE)
  const fallback = new Date('2026-01-01T00:00:00.000Z')
  assert.deepEqual(erasureInstant(undefined, fallback), fallback)
  assert.deepEqual(erasureInstant('not a date', fallback), fallback)
})

test('a preference is deleted: trusted addresses, counters and timers all go', { skip }, async () => {
  await seedPreferences(ALICE)
  const counts = await erase(ALICE_ID)
  assert.equal(counts.trustedAddresses, 1)
  assert.equal(counts.velocityCounters, 1)
  assert.equal(counts.coolingOffTimers, 1)

  for (const table of ['trusted_addresses', 'velocity_counters', 'cooling_off_timers'] as const) {
    const rows = await sql<Array<{ n: number }>>`
      select count(*)::int as n from ${sql(table)} where subject = ${ALICE}
    `
    assert.equal(rows[0]?.n, 0, `${table} should be empty`)
  }
})

test('THE OTHER DIRECTION: a decision log is retained, with its reasons intact', { skip }, async () => {
  await seedDecision(ALICE)
  const counts = await erase(ALICE_ID)
  assert.equal(counts.decisionsRetained, 1)

  const rows = await sql<Array<{ subject: string; decision: string; reasons: string[] }>>`
    select subject, decision, reasons from policy_decisions
  `
  // Retained UNDER ITS OWN NAME. Art 17(3)(b) and (e) — see the handler header. Erasing it would
  // make erasure the cheapest way to destroy the evidence of one's own fraud.
  assert.equal(rows[0]?.subject, ALICE)
  assert.equal(rows[0]?.decision, 'deny')
  assert.deepEqual(rows[0]?.reasons, ['velocity_exceeded'])
})

test('a freeze is not deletable by the person it was applied to', { skip }, async () => {
  await seedFreeze(ALICE)
  const counts = await erase(ALICE_ID)
  assert.equal(counts.freezesRetained, 1)

  const rows = await sql<Array<{ subject: string; cleared_at: Date | null }>>`
    select subject, cleared_at from freezes
  `
  assert.equal(rows[0]?.subject, ALICE)
  // Still live. A deletion request is not a clearance, and a clearance takes two operators.
  assert.equal(rows[0]?.cleared_at, null)
})

test('a marker is written only where something was actually retained', { skip }, async () => {
  // Nothing but preferences: everything goes and NO marker is written, because the marker would
  // then be the only trace of this person that ever existed here.
  await seedPreferences(ALICE)
  const clean = await erase(ALICE_ID)
  assert.equal(clean.marked, false)
  const none = await sql<Array<{ n: number }>>`select count(*)::int as n from erased_subjects`
  assert.equal(none[0]?.n, 0)

  // A decision is retained, so the subject is already held under a lawful basis and the marker
  // adds no identifier the service was not keeping anyway.
  await seedDecision(BOB)
  const marked = await erase(BOB_ID)
  assert.equal(marked.marked, true)
  const rows = await sql<Array<{ subject: string; tombstone_at: Date; event_id: string }>>`
    select subject, tombstone_at, event_id from erased_subjects
  `
  assert.equal(rows[0]?.subject, BOB)
  assert.deepEqual(rows[0]?.tombstone_at, TOMBSTONE)
  assert.equal(rows[0]?.event_id, EVENT)
})

test('THE RACE: a trusted address cannot come back after the erasure', { skip }, async () => {
  await seedDecision(ALICE)
  await seedPreferences(ALICE)
  await erase(ALICE_ID)

  // A request that was in flight when the erasure ran — queued, retried, or replayed by a client
  // that had not noticed the account was gone. The handler has already returned; only the schema
  // can refuse this.
  await assert.rejects(
    () => sql`
      insert into trusted_addresses (subject, chain, address, effective_at, added_by)
      values (${ALICE}, 'eth', '0xlater', now() + interval '1 day', ${ALICE})
    `,
    /has been erased/,
  )
})

test('a marker cannot be rewritten', { skip }, async () => {
  await seedFreeze(ALICE)
  await erase(ALICE_ID)
  await assert.rejects(
    () => sql`update erased_subjects set tombstone_at = now() where subject = ${ALICE}`,
    /append-only/,
  )
})

test('erasing one person does not touch another', { skip }, async () => {
  await seedPreferences(ALICE)
  await seedPreferences(BOB)
  await seedDecision(BOB)

  const counts = await erase(ALICE_ID)
  assert.equal(counts.trustedAddresses, 1)
  assert.equal(counts.decisionsRetained, 0)

  const bob = await sql<Array<{ n: number }>>`
    select count(*)::int as n from trusted_addresses where subject = ${BOB}
  `
  assert.equal(bob[0]?.n, 1)
})

test('a redelivery erases nothing a second time and does not disturb the marker', { skip }, async () => {
  await seedDecision(ALICE)
  await seedPreferences(ALICE)
  await erase(ALICE_ID)

  // `withInbox` makes this unreachable in production. Asserted anyway, and note the marker insert
  // is `on conflict do nothing` rather than an upsert: the table is append-only, so a second
  // attempt that tried to overwrite would raise rather than be absorbed.
  const again = await erase(ALICE_ID, '55555555-5555-4555-8555-555555555555')
  assert.equal(again.trustedAddresses, 0)
  assert.equal(again.velocityCounters, 0)
  assert.equal(again.coolingOffTimers, 0)
  assert.equal(again.decisionsRetained, 1)

  const rows = await sql<Array<{ event_id: string }>>`select event_id from erased_subjects`
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.event_id, EVENT)
})

test('a person stored under the bare uuid is erased too', { skip }, async () => {
  // Defensive: policy writes the ledger spelling everywhere today, and an erasure that silently
  // skipped the other form would report success while leaving the rows in place.
  await seedPreferences(ALICE_ID)
  const counts = await erase(ALICE_ID)
  assert.equal(counts.trustedAddresses, 1)
  assert.equal(counts.velocityCounters, 1)
})

/**
 * THE REGRESSION THAT SHIPPED, AND WHY EVERY TEST IN THIS FILE MISSED IT.
 *
 * `UUID` constrained the version nibble to `[1-5]` and the variant to `[89ab]` —
 * the RFC 4122 shape for versions 1 to 5. Every user id in this estate is a
 * **UUIDv7**: 04-domain-model section 0 requires it, and `identity/src/ids.ts`
 * mints them. So the handler answered 400 to every real erasure event, the relay
 * retried the same event for ever, and the person's rows stayed exactly where
 * they were while the account service reported the deletion as complete.
 *
 * Every test in this file passed the whole time, because the fixtures are v4
 * uuids. Both sides of the test agreed with each other and neither agreed with
 * the producer, which is the failure mode a fixture shared between a test and
 * the code under test cannot detect.
 *
 * The literal below is a real UUIDv7 as identity emits it: 48 bits of Unix
 * milliseconds, then the version nibble `7`. It is not derived from anything in
 * this repository on purpose — a fixture generated by this test would drift back
 * to whatever this repository believes an id looks like, which is the bug.
 *
 * No database. It runs on every checkout, including one with no Postgres.
 */
test('the uuid pattern accepts a UUIDv7, which is the only kind identity mints', () => {
  assert.ok(UUID.test('019fd1a6-c82c-7000-9951-445d80d64a45'), 'a v7 user id must be accepted')
  // v4 stays accepted: event ids come from `gen_random_uuid()` and are v4.
  assert.ok(UUID.test('11111111-1111-4111-8111-111111111111'), 'a v4 event id must be accepted')
  // Still a uuid and nothing else — the shape is checked, the version is not.
  assert.ok(!UUID.test('not-a-uuid'))
  assert.ok(!UUID.test('019fd1a6-c82c-7000-9951-445d80d64a4'), 'one hex short is not a uuid')
  assert.ok(!UUID.test('019fd1a6c82c70009951445d80d64a45'), 'unhyphenated is not this shape')
})
