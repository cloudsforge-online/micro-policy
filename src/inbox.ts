/**
 * The inbox, and the delivery signature that guards it.
 *
 * ── WHY THIS FILE IS NOT `outbox.ts` ───────────────────────────────────────────────────────────
 *
 * The template ships one module holding an outbox, a relay and an inbox, and most services need
 * all three. Policy needs one. It PRODUCES nothing — `@cloudsforge/contracts-events` registers no
 * `policy.*` topic, so there is at present nothing this service is entitled to publish — and a
 * table nothing writes to is worse than an absent one: it arrives with a relay job, a signing
 * secret in the deploy, an `event_subscriptions` row somebody will register against it and a
 * permanently empty dashboard panel.
 *
 * `migrations.ts` used to extend that same reasoning to the inbox — "policy subscribes to nothing
 * today" — and that half is now spent. Rule 6 of 03 §2 is not optional for a service holding a
 * user reference on five tables, and this service holds one on five tables. So the inbox arrives,
 * and only the inbox. The producer half's trigger is unchanged and still written down in
 * `migrations.ts`: the first `policy.*` topic accepted into the registry.
 *
 * ── WHAT MAKES AT-LEAST-ONCE DELIVERY EFFECTIVELY-ONCE ─────────────────────────────────────────
 *
 * `withInbox` inserts `(topic, event_id)` and runs the handler only if that insert was the one
 * that won — AD-10. The insert and the handler share ONE transaction, so a handler that fails
 * leaves no inbox row and the redelivery is processed rather than swallowed, which is the mistake
 * that makes a naive "record then handle" dedupe lose events.
 */

import type { Sql, TransactionSql } from 'postgres'
import { EVENT_ID_HEADER, SIGNATURE_HEADER, verifyDelivery } from '@cloudsforge/contracts-events'

export type Db = Sql
export type Tx = TransactionSql

/**
 * **The signature scheme is the CONTRACT'S, and that is a fact about identity rather than a
 * preference.**
 *
 * The one producer this service subscribes to is identity, and `identity/src/outbox.ts` imports
 * `signDelivery` from `@cloudsforge/contracts-events`: `cf-signature: t=<seconds>,v1=<hmac over
 * "<seconds>.<body>">`. Several older services in the estate still sign the local
 * `x-cloudsforge-signature: sha256=<hmac over body>` on their OUTBOUND relay, and a verifier
 * written to that shape would reject every erasure event for ever — behind a green `/livez`, with
 * a relay retrying a 403 nobody would look at until an audit asked why nothing had been erased.
 *
 * There is deliberately no legacy arm. Nothing has ever delivered an event to this service, so
 * there is no installed base to keep working, and the contract's scheme binds the timestamp INSIDE
 * the signed message — which means a captured delivery stops being a credential after
 * `DELIVERY_TOLERANCE_MS` instead of being replayable for ever.
 *
 * `secrets` is a list so the estate's shared key can be rotated one service at a time: a receiver
 * that accepts only the outgoing key 403s everything the instant the producer moves. Every
 * candidate is compared timing-safely inside `verifyDelivery` — a byte-at-a-time comparison of a
 * MAC is a byte-at-a-time forgery oracle.
 */
export function verifyInboundDelivery(
  body: string,
  presented: string,
  secrets: string | readonly string[],
): boolean {
  if (presented.length === 0) return false
  return verifyDelivery(body, presented, secrets).ok
}

export type InboxOutcome<T> =
  | { readonly status: 'processed'; readonly value: T }
  | { readonly status: 'duplicate' }

/** Run an inbound event's handler exactly once. See the header for why one transaction. */
export async function withInbox<T>(
  sql: Db,
  topic: string,
  eventId: string,
  handle: (tx: Tx) => Promise<T>,
): Promise<InboxOutcome<T>> {
  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ event_id: string }[]>`
      insert into inbox (topic, event_id) values (${topic}, ${eventId})
      on conflict (topic, event_id) do nothing
      returning event_id
    `
    if (claimed.length === 0) return { result: { status: 'duplicate' } as InboxOutcome<T> }
    const value = await handle(tx)
    return { result: { status: 'processed', value } as InboxOutcome<T> }
  })
  return outcome.result
}

export { EVENT_ID_HEADER, SIGNATURE_HEADER }
