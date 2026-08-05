/**
 * Shared setup for the database tests.
 *
 * **A database test runs only against a database whose name says it is a test database.** That is
 * not a convenience: `resetPolicy` truncates every table in the schema, and requiring "test" in
 * the name is the difference between a red build and an emptied environment.
 *
 * `failingReader` below is the seam that makes AD-09's split testable. Taking Postgres away would
 * make the rule store fail, but it would also take away the `policy_decisions` table the test has
 * to read afterwards to prove the decision was recorded — so the failure has to be injected at
 * the one port that can fail, which is what `SnapshotReader` exists to be.
 *
 * Not a test file itself — it is excluded from the build and contains no `test()` call.
 */

import { randomBytes, randomUUID } from 'node:crypto'
import postgres from 'postgres'
import { migrate, type Sql as DbSql } from '@cloudsforge/db'
import { EVENT_ID_HEADER, SIGNATURE_HEADER, signDelivery } from '@cloudsforge/contracts-events'
import { Logger, Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import { MIGRATIONS } from './migrations.ts'
import { registerServiceMetrics } from './server.ts'
import { postgresSnapshotReader, putRule, type Db, type SnapshotReader } from './store.ts'
import { parseRuleDefinition } from './rules.ts'
import type { DecideDeps } from './decide.ts'
import type { ActionName } from './actions.ts'

const url = process.env['POLICY_TEST_DATABASE_URL']

/** Both halves are required: a URL, and a URL that names a test database. */
export const enabled = Boolean(url && /test/i.test(url))

export const skip = enabled ? false : 'set POLICY_TEST_DATABASE_URL (name must contain "test")'

/** Every table this service owns. Order does not matter because CASCADE is used. */
const ALL_TABLES = [
  'freeze_clearances',
  'freezes',
  'cooling_off_timers',
  'trusted_addresses',
  'velocity_counters',
  'policy_decisions',
  'policy_rules',
  'erased_subjects',
  'inbox',
  'jobs',
].join(', ')

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture
 * would let the constraints the tests are supposed to prove — the append-only trigger, the
 * clearance primary key — drift away from the ones a deployment actually has.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as DbSql, MIGRATIONS, { service: 'policy-test' })
}

export async function resetPolicy(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${ALL_TABLES} restart identity cascade`)
}

/* ------------------------------------------------------------------ fixtures */

export const ALICE_ID = '11111111-1111-4111-8111-111111111111'
export const BOB_ID = '22222222-2222-4222-8222-222222222222'
export const ALICE = `user:${ALICE_ID}`
export const BOB = `user:${BOB_ID}`

/**
 * The secret the test server accepts event deliveries under.
 *
 * GENERATED per run, never written. `acceptSecretsFrom` now refuses anything that is not SHAPED
 * like a generated secret — base64 or hex, 32 decoded bytes, an entropy floor — and the literal
 * that used to sit here (`test-event-secret-…`) would be refused by the real `loadEnv` on both
 * counts: it is typed, and it says `testonly`-shaped things about itself. A fixture the deployed
 * guard would reject is a fixture testing a configuration no deploy can have, and a fixture exempt
 * from the rule it exercises is how the placeholder in micro-org #142 survived every test in the
 * estate.
 */
export const EVENT_SECRET = randomBytes(48).toString('base64')

/**
 * An envelope signed the way identity's relay signs it.
 *
 * `signDelivery` is imported from the CONTRACT rather than reimplemented. A hand-rolled signer in
 * the fixture could be wrong in the same way as a hand-rolled verifier in the service, and the
 * suite would stay green while every real erasure event was rejected.
 */
export function signedEvent(
  topic: string,
  payload: Record<string, unknown>,
  options: { readonly id?: string; readonly secret?: string } = {},
): { readonly body: string; readonly headers: Record<string, string> } {
  const id = options.id ?? randomUUID()
  const body = JSON.stringify({
    id,
    topic,
    key: String(payload['userId'] ?? id),
    occurredAt: new Date().toISOString(),
    producer: 'identity',
    version: 1,
    actor: null,
    correlationId: null,
    payload,
  })
  return {
    body,
    headers: {
      'content-type': 'application/json',
      [SIGNATURE_HEADER]: signDelivery(body, options.secret ?? EVENT_SECRET),
      [EVENT_ID_HEADER]: id,
    },
  }
}
export const OPERATOR_ONE = 'operator:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
export const OPERATOR_TWO = 'operator:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'

/** A quiet logger. Discarded rather than silenced, so a serialisation failure still throws. */
export function quietLogger(): Logger {
  return new Logger({ service: 'policy-test', sink: () => {} })
}

export function testMetrics(): Metrics {
  return registerServiceMetrics(registerHttpMetrics(new Metrics()))
}

/**
 * A reader that always fails, standing in for a rule store that cannot be read.
 *
 * The message names the injection so a test failure elsewhere does not look like a real database
 * problem for ten minutes.
 */
export function failingReader(): SnapshotReader {
  return {
    async read() {
      throw new Error('injected: the rule store could not be read')
    },
  }
}

export interface DecideHarness extends DecideDeps {
  readonly metrics: Metrics
}

export function decideDeps(
  sql: Db,
  options: { readonly reader?: SnapshotReader; readonly now?: () => number } = {},
): DecideHarness {
  const metrics = testMetrics()
  return {
    sql,
    reader: options.reader ?? postgresSnapshotReader(sql),
    metrics,
    logger: quietLogger(),
    ...(options.now ? { now: options.now } : {}),
  }
}

/** Write a rule at its next version. A thin wrapper so a test reads as the rule it is setting. */
export async function seedRule(
  sql: Db,
  key: string,
  action: ActionName,
  definition: unknown,
): Promise<void> {
  await putRule(sql, {
    key,
    action,
    definition: parseRuleDefinition(definition),
    enabled: true,
    createdBy: OPERATOR_ONE,
  })
}
