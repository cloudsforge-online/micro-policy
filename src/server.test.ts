/**
 * The HTTP surface.
 *
 * The auth-fault mapping is copied from the template and tested again here rather than assumed,
 * because it is the decision most easily got backwards: an unreachable JWKS is **503**, never
 * 401. Answering 401 there signs every user in the estate out because identity is having a bad
 * minute, and five services in the estate currently disagree about it.
 *
 * The route-level test that matters is `DELETE /freezes/:id` answering **202** to the first
 * operator. The status code is the control made visible in the protocol: a client that treats any
 * 2xx as "done" is wrong in a way that shows up in an access log, whereas 200 with
 * `{cleared:false}` would be invisible to everything that did not already know to look.
 */

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type postgres from 'postgres'
import { SignJWT, generateKeyPair } from 'jose'
import { AUDIENCE, Verifier } from '@cloudsforge/auth'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { DECIDE_SCOPE, createServer } from './server.ts'

/**
 * One handle, presented as the per-network selector the server now takes.
 *
 * The fixtures run against a single test database, so mainnet is the only configured network —
 * which means these tests exercise the REFUSAL path for free: anything reaching for testnet here
 * throws rather than quietly reusing this handle.
 */
const singleNetworkSql = (db: unknown) => networkSql({ mainnet: db as RuntimeSql })
import {
  ALICE,
  EVENT_SECRET,
  decideDeps,
  enabled,
  migrateTestDb,
  openDb,
  quietLogger,
  resetPolicy,
  signedEvent,
  skip,
  testMetrics,
} from './testsupport.ts'
import type { Db } from './store.ts'

const ISSUER = 'https://identity.test'
const ALICE_ID = ALICE.slice('user:'.length)

const keys = await generateKeyPair('RS256', { extractable: true })

const sign = (payload: Record<string, unknown>) =>
  new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime('15m')
    .sign(keys.privateKey)

/** A real `Verifier` over a local key set. Nothing here stubs the decision under test. */
const workingVerifier = () =>
  new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet: (async () => keys.publicKey) as never })

/** A real `Verifier` whose JWKS cannot be reached. */
const unreachableVerifier = () =>
  new Verifier({
    jwksUrl: 'http://down',
    issuer: ISSUER,
    keySet: (async () => {
      throw new Error('getaddrinfo EAI_AGAIN identity')
    }) as never,
  })

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

interface Harness {
  readonly url: string
}

async function withServer(
  options: { verifier?: Verifier; eventAcceptSecrets?: readonly string[] } = {},
  fn: (h: Harness) => Promise<void>,
): Promise<void> {
  const lifecycle = new Lifecycle({ cacheMs: 0 })
  const metrics = testMetrics()
  const server: Server = createServer({
    lifecycle,
    logger: quietLogger(),
    metrics,
    verifier: options.verifier ?? workingVerifier(),
    sql: singleNetworkSql(db()),
    singleNetwork: 'mainnet' as const,
    eventAcceptSecrets: options.eventAcceptSecrets ?? [EVENT_SECRET],
    decide: { ...decideDeps(db()), metrics, logger: quietLogger() },
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  lifecycle.markReady()
  const { port } = server.address() as AddressInfo
  try {
    await fn({ url: `http://127.0.0.1:${port}` })
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

const decider = () => sign({ sub: 'service:wallet', scopes: [DECIDE_SCOPE] })
const admin = () => sign({ sub: 'u-ops-1', handle: 'ops1', roles: ['admin'] })
const otherAdmin = () => sign({ sub: 'u-ops-2', handle: 'ops2', roles: ['admin'] })
const player = () => sign({ sub: ALICE_ID, handle: 'alice', roles: ['player'] })

const decisionBody = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    subject: ALICE,
    action: 'wallet.withdrawal',
    resource: 'urn:cloudsforge:wallet:w-1',
    context: { amount: '10', asset: 'SHARD' },
    ...overrides,
  })

/* ------------------------------------------------------------------ health */

test('livez is static and readyz reports real state', { skip }, async () => {
  await withServer({}, async (h) => {
    const live = await fetch(`${h.url}/livez`)
    assert.equal(live.status, 200)
    const ready = await fetch(`${h.url}/readyz`)
    assert.equal(ready.status, 200)
    assert.equal(ready.headers.get('cache-control'), 'no-store')
  })
})

test('metrics render as valid Prometheus exposition', { skip }, async () => {
  await withServer({}, async (h) => {
    await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody(),
    })
    const res = await fetch(`${h.url}/metrics`)
    assert.equal(res.status, 200)
    const text = await res.text()
    const comment = /^# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+$/
    const sample =
      /^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-zA-Z_][a-zA-Z0-9_]*="[^"]*"(,[a-zA-Z_][a-zA-Z0-9_]*="[^"]*")*\})? -?(\d+(\.\d+)?([eE][-+]?\d+)?|\+Inf|NaN)$/
    for (const line of text.split('\n').filter((l) => l.length > 0)) {
      assert.ok(comment.test(line) || sample.test(line), `not valid exposition: ${line}`)
    }
    assert.match(text, /policy_decisions_total\{action="wallet\.withdrawal",decision="allow"\} 1/)
  })
})

/* ------------------------------------------------------------------ auth */

test('an unauthenticated decision request is 401 and carries the request id', { skip }, async () => {
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/decisions`, { method: 'POST', body: decisionBody() })
    assert.equal(res.status, 401)
    const body = (await res.json()) as { error: { code: string; requestId: string } }
    assert.equal(body.error.code, 'unauthenticated')
    assert.equal(body.error.requestId, res.headers.get('x-request-id'))
  })
})

test('THE RULE: an unreachable JWKS is 503, never 401', { skip }, async () => {
  const token = await decider()
  await withServer({ verifier: unreachableVerifier() }, async (h) => {
    const res = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: decisionBody(),
    })
    assert.equal(res.status, 503)
    assert.equal(((await res.json()) as { error: { code: string } }).error.code, 'verifier_unavailable')
  })
})

test('a user token can never submit a decision, however privileged', { skip }, async () => {
  // Deciding on your own behalf is not a thing this service offers, and `requireScope` is false
  // for anything that is not a service token — including an admin.
  await withServer({}, async (h) => {
    for (const token of [await player(), await admin()]) {
      const res = await fetch(`${h.url}/decisions`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: decisionBody(),
      })
      assert.equal(res.status, 403)
      assert.match(((await res.json()) as { error: { message: string } }).error.message, /policy:decide/)
    }
  })
})

/* ------------------------------------------------------------------ decisions */

test('a decision that allows, and one that denies with reasons', { skip }, async () => {
  await withServer({}, async (h) => {
    const adminToken = await admin()
    const rule = await fetch(`${h.url}/rules`, {
      method: 'POST',
      headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        key: 'withdrawal-limit',
        action: 'wallet.withdrawal',
        definition: { kind: 'amount_limit', asset: 'SHARD', thresholds: [{ atOrAbove: '100', verdict: 'deny' }] },
      }),
    })
    assert.equal(rule.status, 201)

    const token = await decider()
    const allowed = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: decisionBody({ context: { amount: '10', asset: 'SHARD' } }),
    })
    assert.equal(allowed.status, 201)
    const allowedBody = (await allowed.json()) as { decision: { id: string; decision: string } }
    assert.equal(allowedBody.decision.decision, 'allow')

    const denied = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
      body: decisionBody({ context: { amount: '500', asset: 'SHARD' } }),
    })
    assert.equal(denied.status, 201)
    const deniedBody = (await denied.json()) as {
      decision: { id: string; decision: string; reasons: string[]; ruleVersions: string[] }
    }
    assert.equal(deniedBody.decision.decision, 'deny')
    assert.deepEqual(deniedBody.decision.reasons, ['amount_at_or_above:100:SHARD'])
    assert.deepEqual(deniedBody.decision.ruleVersions, ['withdrawal-limit@1'])

    // And it is still there afterwards, which is the whole point of §10.4.
    const fetched = await fetch(`${h.url}/decisions/${deniedBody.decision.id}`, {
      headers: { authorization: `Bearer ${token}` },
    })
    assert.equal(fetched.status, 200)
  })
})

test('an unregistered action is 400 and names the registry, rather than being guessed at', { skip }, async () => {
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody({ action: 'custody.key.exprot' }),
    })
    assert.equal(res.status, 400)
    assert.match(((await res.json()) as { error: { message: string } }).error.message, /custody\.key\.export/)
  })
})

test('an amount sent as a JSON number is refused rather than coerced', { skip }, async () => {
  // By the time this code sees a JSON number it has already been through a float, and a threshold
  // comparison on a float is the bug this service exists not to have.
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody({ context: { amount: 10.1, asset: 'SHARD' } }),
    })
    assert.equal(res.status, 400)
  })
})

test('a user may read a decision about themselves and not one about anyone else', { skip }, async () => {
  await withServer({}, async (h) => {
    const created = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody(),
    })
    const { decision } = (await created.json()) as { decision: { id: string } }

    // "Why was I blocked" is the question §10.4 exists to answer, and answering it only to
    // operators makes the record an audit log wearing a dispute process's clothes.
    const mine = await fetch(`${h.url}/decisions/${decision.id}`, {
      headers: { authorization: `Bearer ${await player()}` },
    })
    assert.equal(mine.status, 200)

    const someoneElse = await sign({ sub: 'ffffffff-ffff-4fff-8fff-ffffffffffff', handle: 'mallory', roles: ['player'] })
    const theirs = await fetch(`${h.url}/decisions/${decision.id}`, {
      headers: { authorization: `Bearer ${someoneElse}` },
    })
    assert.equal(theirs.status, 403)
  })
})

/* ------------------------------------------------------------------ freezes */

test('THE RULE: one operator cannot clear a freeze, and the status code says so', { skip }, async () => {
  await withServer({}, async (h) => {
    const one = await admin()
    const two = await otherAdmin()

    const created = await fetch(`${h.url}/freezes`, {
      method: 'POST',
      headers: { authorization: `Bearer ${one}`, 'content-type': 'application/json' },
      body: JSON.stringify({ subject: ALICE, scope: '*', reason: 'suspected takeover' }),
    })
    assert.equal(created.status, 201)
    const { freeze } = (await created.json()) as { freeze: { id: string; clearancesRequired: number } }
    assert.equal(freeze.clearancesRequired, 2)

    // 202, not 200. The request was recorded; the freeze is still in force.
    const first = await fetch(`${h.url}/freezes/${freeze.id}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${one}` },
    })
    assert.equal(first.status, 202)
    const firstBody = (await first.json()) as { status: string; message: string }
    assert.equal(firstBody.status, 'pending')
    assert.match(firstBody.message, /two distinct operators/)

    // The same operator again: still 202, still frozen.
    const repeat = await fetch(`${h.url}/freezes/${freeze.id}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${one}` },
    })
    assert.equal(repeat.status, 202)

    const denied = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody(),
    })
    const deniedBody = (await denied.json()) as { decision: { decision: string; reasons: string[] } }
    assert.equal(deniedBody.decision.decision, 'deny')
    assert.ok(deniedBody.decision.reasons.includes('frozen:*'))

    // A second, distinct operator clears it. 200 this time.
    const second = await fetch(`${h.url}/freezes/${freeze.id}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${two}` },
    })
    assert.equal(second.status, 200)
    assert.equal(((await second.json()) as { status: string }).status, 'cleared')

    const allowed = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody(),
    })
    assert.equal(((await allowed.json()) as { decision: { decision: string } }).decision.decision, 'allow')
  })
})

test('a non-operator cannot set or clear a freeze', { skip }, async () => {
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/freezes`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await player()}`, 'content-type': 'application/json' },
      body: JSON.stringify({ subject: ALICE, reason: 'because' }),
    })
    assert.equal(res.status, 403)
  })
})

test('a freeze scope that would cover nothing is refused', { skip }, async () => {
  // A freeze that covers nothing is worse than no freeze: it reads, on a dashboard, as protection.
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/freezes`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await admin()}`, 'content-type': 'application/json' },
      body: JSON.stringify({ subject: ALICE, scope: 'wallet.withdrawl', reason: 'typo' }),
    })
    assert.equal(res.status, 400)
  })
})

/* ------------------------------------------------------------------ rules */

test('disabling a rule keeps its history, so an old decision can still be explained', { skip }, async () => {
  await withServer({}, async (h) => {
    const token = await admin()
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }
    await fetch(`${h.url}/rules`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        key: 'withdrawal-limit',
        action: 'wallet.withdrawal',
        definition: { kind: 'amount_limit', asset: 'SHARD', thresholds: [{ atOrAbove: '100', verdict: 'deny' }] },
      }),
    })
    const removed = await fetch(`${h.url}/rules/withdrawal-limit`, { method: 'DELETE', headers })
    assert.equal(removed.status, 200)
    const { rule } = (await removed.json()) as { rule: { version: number; enabled: boolean } }
    assert.equal(rule.version, 2, 'a delete here is an insert')
    assert.equal(rule.enabled, false)

    const history = await fetch(`${h.url}/rules/withdrawal-limit`, { headers })
    const { versions } = (await history.json()) as { versions: { version: number }[] }
    assert.deepEqual(versions.map((v) => v.version), [2, 1])

    // And the rule no longer fires.
    const decision = await fetch(`${h.url}/decisions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await decider()}` },
      body: decisionBody({ context: { amount: '5000', asset: 'SHARD' } }),
    })
    assert.equal(((await decision.json()) as { decision: { decision: string } }).decision.decision, 'allow')
  })
})

test('a malformed rule is 400, not a rule that silently does nothing', { skip }, async () => {
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/rules`, {
      method: 'POST',
      headers: { authorization: `Bearer ${await admin()}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        key: 'broken',
        action: 'wallet.withdrawal',
        definition: { kind: 'velocity', windowSeconds: 60, maxAmount: '5', verdict: 'deny' },
      }),
    })
    assert.equal(res.status, 400)
    assert.match(((await res.json()) as { error: { message: string } }).error.message, /velocity\.asset/)
  })
})

test('an unknown path is 404 and does not mint a metric series of its own', { skip }, async () => {
  await withServer({}, async (h) => {
    const res = await fetch(`${h.url}/v1/nothing-here`)
    assert.equal(res.status, 404)

    const scrape = await (await fetch(`${h.url}/metrics`)).text()
    // Any caller could otherwise mint unbounded time series and take the scrape target down.
    assert.match(scrape, /route="unmatched"/)
    assert.equal(/nothing-here/.test(scrape), false)
  })
})

test('a path parameter cannot swallow the rest of the path', { skip }, async () => {
  await withServer({}, async (h) => {
    // `:id` excludes `/`, so this is unmatched rather than being answered by /decisions/:id with
    // an id of "a/b". A route that answered for another route's path is how an admin handler ends
    // up reachable through a public one.
    const res = await fetch(`${h.url}/decisions/aaaa/bbbb`)
    assert.equal(res.status, 404)
  })
})

/* ------------------------------------------------------------------ POST /v1/events */

/**
 * The first inbound event surface this service has ever had, and the only unauthenticated write on
 * it. `erasure.test.ts` covers what erasure does to each table; these cover the door.
 */

async function postEvent(
  h: Harness,
  event: { body: string; headers: Record<string, string> },
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${h.url}/v1/events`, {
    method: 'POST',
    headers: event.headers,
    body: event.body,
  })
  const text = await res.text()
  let body: Record<string, unknown> = {}
  try {
    body = JSON.parse(text) as Record<string, unknown>
  } catch {
    /* not JSON */
  }
  return { status: res.status, body }
}

async function aTrustedAddress(): Promise<void> {
  await sql`
    insert into trusted_addresses (subject, chain, address, effective_at, added_by)
    values (${ALICE}, 'eth', '0xdestination', now() + interval '1 day', ${ALICE})
  `
}

test('a wrongly signed erasure is 403 — never 401, and erases nothing', { skip }, async () => {
  await withServer({}, async (h) => {
    await aTrustedAddress()
    // 401 would say "authenticate and try again", which sends a caller looking for a bearer token
    // this route does not have. The MAC is the credential and it was wrong.
    const forged = signedEvent(
      'identity.user.deleted',
      { userId: ALICE_ID },
      { secret: 'a-different-secret-that-is-long-enough' },
    )
    assert.equal((await postEvent(h, forged)).status, 403)

    const unsigned = signedEvent('identity.user.deleted', { userId: ALICE_ID })
    assert.equal(
      (await postEvent(h, { body: unsigned.body, headers: { 'content-type': 'application/json' } }))
        .status,
      403,
    )

    const rows = await sql`select count(*)::int as n from trusted_addresses`
    assert.equal((rows[0] as { n: number }).n, 1)
  })
})

test('the signature covers the bytes as sent, so a re-serialised body fails', { skip }, async () => {
  await withServer({}, async (h) => {
    const event = signedEvent('identity.user.deleted', { userId: ALICE_ID })
    // Same JSON, different bytes. If the route parsed before verifying, this would pass.
    const reserialised = JSON.stringify(JSON.parse(event.body), null, 2)
    assert.equal(
      (await postEvent(h, { body: reserialised, headers: event.headers })).status,
      403,
    )
  })
})

test('a topic this service does not consume is 202 ignored, never 4xx', { skip }, async () => {
  await withServer({}, async (h) => {
    // A 4xx would pin the producer's relay in a retry loop for ever over something neither side is
    // wrong about.
    const res = await postEvent(h, signedEvent('identity.session.created', { userId: ALICE_ID }))
    assert.equal(res.status, 202)
    assert.equal(res.body['status'], 'ignored')
  })
})

test('a correctly signed erasure is accepted, and erases', { skip }, async () => {
  await withServer({}, async (h) => {
    await aTrustedAddress()
    const res = await postEvent(h, signedEvent('identity.user.deleted', { userId: ALICE_ID }))
    assert.equal(res.status, 202)
    assert.equal(res.body['status'], 'recorded')

    const rows = await sql`select count(*)::int as n from trusted_addresses`
    assert.equal((rows[0] as { n: number }).n, 0)
  })
})

test('a redelivery is a duplicate, not a second erasure', { skip }, async () => {
  await withServer({}, async (h) => {
    await aTrustedAddress()
    const event = signedEvent('identity.user.deleted', { userId: ALICE_ID })
    assert.equal((await postEvent(h, event)).body['status'], 'recorded')
    // Byte for byte, as an at-least-once relay resends it. The inbox is what makes it a no-op.
    const again = await postEvent(h, event)
    assert.equal(again.status, 202)
    assert.equal(again.body['status'], 'duplicate')
  })
})

test('an unreadable erasure is 400 and stays visible, never absorbed into a 202', { skip }, async () => {
  await withServer({}, async (h) => {
    // The relay retries a 400 for ever, which is correct here: an erasure this service cannot read
    // is a person whose data is still present while the deletion is reported as done.
    assert.equal((await postEvent(h, signedEvent('identity.user.deleted', {}))).status, 400)
    assert.equal(
      (await postEvent(h, signedEvent('identity.user.deleted', { userId: 'nope' }))).status,
      400,
    )
    const badId = signedEvent('identity.user.deleted', { userId: ALICE_ID }, { id: 'not-a-uuid' })
    assert.equal((await postEvent(h, badId)).status, 400)
  })
})

test('with no accept secret configured the route is 503, never an open door', { skip }, async () => {
  await withServer({ eventAcceptSecrets: [] }, async (h) => {
    await aTrustedAddress()
    // The estate's compose has never given policy the outbox secrets, so this state is reachable.
    // 503 makes the relay retry — the erasure is queued and visible, not lost — and it is emphatically
    // not "accept anything", which would let an unauthenticated caller erase any user by uuid.
    const res = await postEvent(h, signedEvent('identity.user.deleted', { userId: ALICE_ID }))
    assert.equal(res.status, 503)

    const rows = await sql`select count(*)::int as n from trusted_addresses`
    assert.equal((rows[0] as { n: number }).n, 1)
  })
})
