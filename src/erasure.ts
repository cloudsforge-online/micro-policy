/**
 * `identity.user.deleted` — right to erasure, policy's half.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHAT THIS SERVICE HELD, AND WHAT HAPPENS TO EACH OF IT
 *
 * Policy is the service where "delete everything" is most obviously wrong and most tempting. It
 * holds no money and no content — only judgements about a person and the controls applied to them
 * — so nothing here has an accounting obligation behind it and there is no ledger to unbalance.
 * What there is instead is the record of WHY somebody was refused, which is simultaneously the
 * evidence in their own dispute and the record of a control that a regulator can ask about.
 *
 * The line drawn below is between the RECORD OF A CONTROL and a PREFERENCE. They do not get the
 * same answer, and the difference is not how sensitive they look.
 *
 * | table               | action     | reasoning + lawful basis if retained                      |
 * |---------------------|------------|-----------------------------------------------------------|
 * | policy_decisions    | RETAIN,    | The risk and fraud decision log: every allow, deny,        |
 * |                     | untouched  | challenge and review, with the reasons, the rule versions  |
 * |                     |            | and the risk score. Retained under **Art 17(3)(b)** —      |
 * |                     |            | AML/CTF record-keeping obligations, for which the record   |
 * |                     |            | of the controls applied to a transaction IS the required   |
 * |                     |            | record — and **Art 17(3)(e)**, the establishment,          |
 * |                     |            | exercise or defence of legal claims: this table's own      |
 * |                     |            | header says "why was I blocked must be answerable months   |
 * |                     |            | later, and it is the input to a dispute". Erasing it on    |
 * |                     |            | request would also make erasure the cheapest way to        |
 * |                     |            | destroy the evidence of one's own fraud, which is the      |
 * |                     |            | outcome Art 17(3) exists to prevent.                       |
 * |                     |            | **It is not retained for ever, and that matters:** the     |
 * |                     |            | retention sweep in `jobs.ts` already deletes past          |
 * |                     |            | POLICY_DECISION_RETENTION_DAYS (730 by default, floor 90). |
 * |                     |            | So this is a bounded retention with a named basis, not an  |
 * |                     |            | exemption that never expires.                              |
 * |                     |            | It is also physically un-updatable — migration 3 installs  |
 * |                     |            | a BEFORE UPDATE trigger that raises, because evidence      |
 * |                     |            | that can be edited is not evidence. De-identifying in      |
 * |                     |            | place would have meant weakening that trigger, and a       |
 * |                     |            | pseudonymised decision log is still personal data anyway:  |
 * |                     |            | a subject key linking one person's refusals to each other  |
 * |                     |            | across two years is a fingerprint whatever it spells.      |
 * |---------------------|------------|-----------------------------------------------------------|
 * | freezes,            | RETAIN,    | A freeze is a compliance action taken BY THE PLATFORM, and |
 * | freeze_clearances   | untouched  | `freeze_clearances` records which two operators agreed to  |
 * |                     |            | lift it. Same basis as the decision log, and one more:     |
 * |                     |            | deleting a freeze on the frozen person's request would let |
 * |                     |            | the subject of a control erase the control. The clearance  |
 * |                     |            | rows are STAFF data about a staff decision — erasing them  |
 * |                     |            | on a user's request would delete somebody else's audit.    |
 * |                     |            | **THE RESIDUAL GAP, STATED PLAINLY:** unlike the decision  |
 * |                     |            | log, freezes have NO retention sweep, so a subject here is |
 * |                     |            | retained indefinitely. That is the one place this service  |
 * |                     |            | still fails a strict reading of storage limitation, and it |
 * |                     |            | is recorded here rather than smoothed over. The fix is a   |
 * |                     |            | sweep keyed on `erased_subjects.tombstone_at` plus the     |
 * |                     |            | AML retention period; the marker this handler writes is    |
 * |                     |            | what makes that sweep a `where` clause rather than a       |
 * |                     |            | migration.                                                 |
 * |---------------------|------------|-----------------------------------------------------------|
 * | trusted_addresses   | DELETE     | **A PREFERENCE, NOT A CONTROL, AND IT GETS THE OPPOSITE    |
 * |                     |            | ANSWER TO EVERYTHING ABOVE.** The user chose to trust a    |
 * |                     |            | destination and the platform recorded the choice. There is |
 * |                     |            | no legal obligation to keep somebody's address book: the   |
 * |                     |            | AML record of where money actually WENT lives on the       |
 * |                     |            | withdrawal in settlement and on the chain, and it is       |
 * |                     |            | unaffected by this. Nothing references these rows and no   |
 * |                     |            | sum depends on them.                                       |
 * |                     |            | Keeping them would also be the more harmful choice on its  |
 * |                     |            | own terms: a list of blockchain addresses a named person   |
 * |                     |            | controls or sends to is exactly the linkage a chain        |
 * |                     |            | analysis needs, and it would sit here for ever with no     |
 * |                     |            | sweep behind it.                                            |
 * |---------------------|------------|-----------------------------------------------------------|
 * | velocity_counters   | DELETE     | Tumbling-window counts: how often this person did a thing  |
 * |                     |            | recently, and for how much. Behavioural data with no basis |
 * |                     |            | for retention past its own window — `jobs.ts` already      |
 * |                     |            | prunes it after POLICY_COUNTER_RETENTION_HOURS. Erasing it |
 * |                     |            | early costs nothing: the cap it enforces protects an       |
 * |                     |            | account that no longer exists.                             |
 * |---------------------|------------|-----------------------------------------------------------|
 * | cooling_off_timers  | DELETE     | A per-subject timer started by a refused attempt. Same     |
 * |                     |            | class as the counters. It looks like a control worth       |
 * |                     |            | keeping, and it is not: a timer only bites the account it  |
 * |                     |            | names, so retaining it protects nobody once that account   |
 * |                     |            | is gone — a person re-registering gets a new user id and   |
 * |                     |            | a fresh timer either way.                                  |
 * |---------------------|------------|-----------------------------------------------------------|
 * | policy_rules        | untouched  | Rules are data, not people. `created_by` is an operator.   |
 * |---------------------|------------|-----------------------------------------------------------|
 * | erased_subjects     | WRITTEN —  | See migration 8. Written ONLY when this service is already |
 * |                     | sometimes  | lawfully retaining that subject in the decision log or a   |
 * |                     |            | freeze, so it never becomes the sole surviving trace of a  |
 * |                     |            | person who had nothing but preferences here.               |
 *
 * ── WHAT REMAINS, HONESTLY ─────────────────────────────────────────────────────────────────────
 *
 * A person who was ever refused, challenged or frozen keeps a named record in this service until
 * its retention expires, and for freezes that expiry does not exist yet. That is a real limit on
 * what "erased" means here, it is deliberate, and it is the answer a regulator should be given
 * rather than a claim that everything was deleted.
 *
 * The other side of the same coin: a person whom policy only ever ALLOWED, and who set no trusted
 * address, is erased completely and leaves no marker at all. The common case is the clean case.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Tx } from './inbox.ts'

/** The topic. Registered in `@cloudsforge/contracts-events` as keyed by `user_id`. */
export const IDENTITY_USER_DELETED = 'identity.user.deleted'

/** Every topic this service consumes. Anything else is acknowledged and ignored — never 4xx'd. */
export const SUBSCRIBED_TOPICS: ReadonlySet<string> = new Set([IDENTITY_USER_DELETED])

/**
 * A uuid, and nothing else. The one shape identity keys this topic by.
 *
 * ── THE VERSION NIBBLE IS NOT CONSTRAINED, AND THAT IS THE WHOLE POINT ────────
 *
 * This pattern read `[1-5]` for the version and `[89ab]` for the variant — the
 * RFC 4122 shape for versions 1 to 5. **Every user id in this estate is a
 * UUIDv7.** 04-domain-model section 0 requires it ("All ids are UUIDv7,
 * time-ordered, so they index well and sort"), and `identity/src/ids.ts`
 * mints them.
 *
 * So this regex rejected every real erasure event. The handler answered 400, the
 * relay treated that as a delivery failure and retried it for ever, and the
 * person's data stayed exactly where it was — while the account service reported
 * the deletion as done.
 *
 * **The unit tests passed throughout**, because their fixtures were v4 uuids
 * from `gen_random_uuid()` and `crypto.randomUUID()`. Both sides of the test
 * agreed with each other and neither agreed with the producer. It was caught by
 * `deploy/scripts/erasure-drill.sh` driving a real deletion through the real
 * bus — the seam, not the mock — and it is the reason that drill exists.
 */
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export interface ErasureCounts {
  readonly trustedAddresses: number
  readonly velocityCounters: number
  readonly coolingOffTimers: number
  /** Retained, not erased. Reported so the number that survives is visible, never inferred. */
  readonly decisionsRetained: number
  readonly freezesRetained: number
  /** Whether a marker was written — i.e. whether anything above was retained. */
  readonly marked: boolean
}

/**
 * The two spellings of one person, and why both are matched.
 *
 * The event payload carries a BARE UUID (`identity/src/deletion.ts`). This service stores
 * the LEDGER SPELLING — `user:<uuid>` — because a decision and the ledger entry it is about must
 * attribute their subject identically; `SUBJECT_PATTERN` in `src/server.ts` is what enforces that
 * on the way in, and `testsupport.ts` fixtures are written the same way.
 *
 * Matching only the ledger spelling would be correct today and silently wrong the first time a row
 * arrives from a path that does not go through that pattern. Matching only the bare uuid would
 * erase nothing at all and report success. So both are matched, explicitly, once, here.
 */
export function subjectForms(userId: string): readonly string[] {
  return [`user:${userId}`, userId]
}

/**
 * When the erasure is anchored.
 *
 * The event carries `tombstoneAt` so a subscriber knows its deadline without having to know
 * identity's configuration. It is stored rather than `now()` because the retention clock it starts
 * — the one a future freeze sweep will run on — is measured from the deletion request, not from
 * whenever a relay happened to succeed. An absent or unparseable value falls back to the current
 * time, never to null: a null would make the marker unusable for exactly the sweep it exists for.
 */
export function erasureInstant(tombstoneAt: unknown, now: Date = new Date()): Date {
  if (typeof tombstoneAt !== 'string' || tombstoneAt.length === 0) return now
  const parsed = new Date(tombstoneAt)
  return Number.isNaN(parsed.getTime()) ? now : parsed
}

/**
 * Erase one user, inside the caller's transaction.
 *
 * The marker is written LAST and only when something was retained, so the decision "is this
 * service still holding this person" is taken against the state after the deletes rather than
 * before them. `withInbox` supplies the transaction; a failure anywhere leaves no inbox row and no
 * partial erasure, and the redelivery does the whole thing again.
 */
export async function eraseUser(
  tx: Tx,
  userId: string,
  input: { readonly eventId: string; readonly tombstoneAt: Date },
): Promise<ErasureCounts> {
  const subjects = subjectForms(userId)

  const trustedAddresses = await tx`
    delete from trusted_addresses where subject = any(${subjects}) returning id
  `
  const velocityCounters = await tx`
    delete from velocity_counters where subject = any(${subjects}) returning subject
  `
  const coolingOffTimers = await tx`
    delete from cooling_off_timers where subject = any(${subjects}) returning subject
  `

  // Counted, not touched. `policy_decisions` cannot be updated at all — migration 3 installs a
  // trigger that raises on UPDATE — and both of these are retained deliberately; see the header.
  const decisions = await tx<{ n: number }[]>`
    select count(*)::int as n from policy_decisions where subject = any(${subjects})
  `
  const freezes = await tx<{ n: number }[]>`
    select count(*)::int as n from freezes where subject = any(${subjects})
  `
  const decisionsRetained = decisions[0]?.n ?? 0
  const freezesRetained = freezes[0]?.n ?? 0

  // THE CONDITION, and it is the whole of the privacy argument for this table: a marker is written
  // only where this service is already lawfully holding the subject somewhere else. Where policy
  // held nothing but preferences, everything has just been deleted and recording "this person was
  // erased" would leave behind the only trace of them that ever existed here.
  const marked = decisionsRetained > 0 || freezesRetained > 0
  if (marked) {
    // The ledger spelling, always — one row per person, not one per spelling. `do nothing` rather
    // than an upsert because the table is append-only: a second deletion of the same subject is the
    // same deletion, and the first marker is the one with the right tombstone on it.
    await tx`
      insert into erased_subjects (subject, tombstone_at, event_id)
      values (${`user:${userId}`}, ${input.tombstoneAt}, ${input.eventId})
      on conflict (subject) do nothing
    `
  }

  return {
    trustedAddresses: trustedAddresses.length,
    velocityCounters: velocityCounters.length,
    coolingOffTimers: coolingOffTimers.length,
    decisionsRetained,
    freezesRetained,
    marked,
  }
}
