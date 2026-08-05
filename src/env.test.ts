/**
 * `env.ts`, which had no test at all until micro-org #142 — which is part of why the inline
 * accept-list checks below could be wrong for as long as they were.
 *
 * No database needed. A valid environment is applied to the process BEFORE `./env.ts` is imported:
 * it validates eagerly and calls `process.exit(1)` on a bad configuration, so the dynamic import
 * is itself a test that these values suffice. `loadEnv` is otherwise pure over its source.
 */

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'

const BASE: Record<string, string> = {
  POLICY_DATABASE_URL: 'postgres://policy:pw@127.0.0.1:5432/policy',
  IDENTITY_JWKS_URL: 'http://identity.test/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://identity.test',
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

/** GENERATED, never written — the guard refuses a typed value, and so must a fixture. */
const generated = (): string => randomBytes(48).toString('base64')

const { EnvError, SERVICE, env, loadEnv } = await import('./env.ts')

test('a complete environment loads, and importing the module did not exit', () => {
  assert.equal(env.databaseUrl, BASE['POLICY_DATABASE_URL'])
  assert.equal(env.port, 4000)
  assert.equal(SERVICE, 'policy')
})

test('a missing variable names itself', () => {
  assert.throws(
    () => loadEnv({ ...BASE, POLICY_DATABASE_URL: undefined }),
    (err: unknown) => err instanceof EnvError && /POLICY_DATABASE_URL is required/.test(err.message),
  )
})

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * THE EVENT KEY. Absent is supported; present-but-rubbish is not.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test('AN ABSENT KEY IS A SUPPORTED STATE, and must never become a boot failure', () => {
  // micro-org #196 measured this variable ABSENT on the running estate — this was the only service
  // of 26 that reads an outbox secret and had never been given one. If the #142 guard had turned
  // absence into an exit(1), shipping it would have taken policy down on a service every money
  // route consults, and the erasure gap would have become an outage.
  //
  // It is not "accept anything" either: `server.ts` answers 503 on an empty list, so the relay
  // retries and the deletion is queued and visible rather than silently dropped.
  assert.doesNotThrow(() => loadEnv(BASE))
  assert.deepEqual(loadEnv(BASE).eventAcceptSecrets, [])
  // A list that lists nothing is the same absence, not a new failure.
  assert.deepEqual(loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: ' , ' }).eventAcceptSecrets, [])
  assert.deepEqual(loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: '' }).eventAcceptSecrets, [])
})

test('the signing secret seeds the accept list, and the accept list overrides it', () => {
  const signing = generated()
  assert.deepEqual(loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: signing }).eventAcceptSecrets, [signing])

  const incoming = generated()
  const rotating = loadEnv({
    ...BASE,
    OUTBOX_SIGNING_SECRET: signing,
    OUTBOX_ACCEPT_SECRETS: `${incoming}, ${signing}`,
  })
  assert.deepEqual(rotating.eventAcceptSecrets, [incoming, signing])
})

test('THE VALUE THAT SAT IN A PUBLIC REPOSITORY IS REFUSED, and every near miss with it', () => {
  // micro-org #142. Each of these cleared the old inline checks — a deny-list of eight exact
  // strings plus a 24-character floor — and each is a real string that was deployed or set in CI,
  // not an invented one. If a future edit weakens the floor, it fails against evidence.
  for (const value of [
    'estate-only-outbox-secret-00000000000000', // 54 lines of a PUBLIC compose file, 40 chars
    'ci-only-not-a-real-secret-000000000000', // 23 CI workflows
    'K2sN4vQ8xR1wB6tY9zL3mF7hC5jD0pA4', // 32 chars, 24 bytes: right alphabet, too little key
    '0'.repeat(64), // right alphabet, right length, no entropy
  ]) {
    // Both spellings, because either can be the one a deploy sets, and the message has to name the
    // one the operator actually wrote.
    for (const [variable, source] of [
      ['OUTBOX_SIGNING_SECRET', { ...BASE, OUTBOX_SIGNING_SECRET: value }],
      ['OUTBOX_ACCEPT_SECRETS', { ...BASE, OUTBOX_ACCEPT_SECRETS: `${generated()},${value}` }],
    ] as const) {
      assert.throws(
        () => loadEnv(source),
        (err: unknown) => {
          // The refusal must not echo the value: the reason this guard exists is that the value
          // was readable, and a message carrying it moves the secret to the log collector.
          const message = (err as Error).message
          assert.ok(!message.includes(value), 'the refusal echoed the value')
          assert.match(message, new RegExp(variable))
          assert.match(message, /openssl rand -base64 48/)
          // Re-wrapped, so `loadEnv` still raises exactly one class.
          return err instanceof EnvError
        },
      )
    }
  }
})

test('a weak entry anywhere in a rotation list is still a weak key', () => {
  // The overlap window is where a filler gets in: the OUTGOING key is the one an attacker already
  // holds if it leaked, so "just for the drain" is not a reason to relax the bar for an entry.
  // Policy signs nothing and only VERIFIES, which makes a weak entry here exactly as bad.
  assert.throws(() => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${generated()},changeme` }), /placeholder/)
  assert.throws(
    () => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${generated()},short` }),
    /bytes of key material/,
  )
})

test('the same secret twice is refused, because a rotation with one key is not a rotation', () => {
  const secret = generated()
  assert.throws(
    () => loadEnv({ ...BASE, OUTBOX_ACCEPT_SECRETS: `${secret},${secret}` }),
    (err: unknown) => err instanceof EnvError && /lists the same secret twice/.test(err.message),
  )
})

test('what the estate actually runs is accepted, in either alphabet', () => {
  assert.doesNotThrow(() => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: randomBytes(48).toString('base64') }))
  assert.doesNotThrow(() => loadEnv({ ...BASE, OUTBOX_SIGNING_SECRET: randomBytes(32).toString('hex') }))
})

test('LOG_LEVEL is a closed set', () => {
  assert.throws(() => loadEnv({ ...BASE, LOG_LEVEL: 'verbose' }), /LOG_LEVEL must be one of/)
})
