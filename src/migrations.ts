/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * **A released migration is immutable.** `@cloudsforge/db` checksums each one and refuses a run
 * where the text changed after it was applied, because two databases would then disagree about
 * what "version 3" means. The fix for a wrong migration is always a new migration.
 *
 * ## Why there is no `outbox` here
 *
 * The template ships one and most services need it. Policy does not, yet, and a table nothing
 * writes to is worse than an absent one: it comes with a relay job, a signing secret in the
 * deploy, an `event_subscriptions` row someone will register against it, and a permanently empty
 * dashboard panel. `contracts-events` registers no `policy.*` topic, so there is at present
 * nothing this service is entitled to publish.
 *
 * The trigger for adding one, written down now so it is a decision rather than an argument: the
 * first `policy.freeze.applied` or `policy.decision.recorded` topic accepted into the registry.
 * At that point a migration adds `outbox`, `event_subscriptions` and `outbox_deliveries` verbatim
 * from the template, and an outbound signing secret enters `env.ts`. Nothing else changes. That
 * trigger has NOT fired: everything below is still consumer-side only.
 *
 * ## Why there IS an `inbox`, as of migration 8
 *
 * The paragraph that used to sit here said the same reasoning removed the inbox, because "policy
 * subscribes to nothing today". **That was true and it was also the defect.** Rule 6 of the same
 * section says every service storing a user reference subscribes to `identity.user.deleted` and
 * erases, and this service stores a subject on five tables — `policy_decisions`,
 * `velocity_counters`, `cooling_off_timers`, `trusted_addresses` and `freezes`. Subscribing to
 * nothing was not a consequence of policy having no upstream; it was a right-to-erasure gap, and a
 * deletion request was answered "done" while every one of those rows stayed put.
 *
 * So migration 8 adds `inbox` and nothing else from the template. The producer half is still
 * absent, and the two are genuinely separate decisions rather than one package.
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift. Copying the DDL by hand is how a service ends up with a jobs
    // table missing the (kind, key) unique constraint, which silently turns every recurring
    // enqueue into a duplicate run.
    up: JOBS_SCHEMA_SQL,
  },
  {
    version: 2,
    name: 'rules',
    up: `
      -- Rules are data and every row is immutable. A change is an insert at version + 1, because
      -- policy_decisions.rule_versions names a version and that name is only worth storing if the
      -- thing it names still says what it said. See the header of src/rules.ts.
      create table if not exists policy_rules (
        id          uuid        primary key default gen_random_uuid(),
        rule_key    text        not null,
        version     integer     not null,
        action      text        not null,
        kind        text        not null,
        definition  jsonb       not null,
        enabled     boolean     not null default true,
        created_at  timestamptz not null default now(),
        created_by  text        not null,
        note        text,
        constraint policy_rules_key_version_uniq unique (rule_key, version),
        constraint policy_rules_version_positive check (version >= 1)
      );

      -- The evaluator's access path: every enabled rule for one action, newest version per key.
      create index if not exists policy_rules_action_idx
        on policy_rules (action, rule_key, version desc);
    `,
  },
  {
    version: 3,
    name: 'decisions',
    up: `
      -- 04-domain-model §10.4. A decision is a record, not just a return value: "why was I
      -- blocked" must be answerable months later, and it is the input to a dispute.
      create table if not exists policy_decisions (
        id             uuid        primary key default gen_random_uuid(),
        subject        text        not null,
        action         text        not null,
        resource_urn   text        not null,
        decision       text        not null,
        reasons        text[]      not null default '{}',
        obligations    text[]      not null default '{}',
        risk_score     integer     not null default 0,
        rule_versions  text[]      not null default '{}',
        -- True when the rule store could not be read and the answer came from the fail-safe in
        -- src/actions.ts. A dispute needs to know that nothing was actually checked.
        fail_open      boolean     not null default false,
        context        jsonb       not null default '{}'::jsonb,
        correlation_id text        not null,
        decided_for    text        not null,
        evaluation_ms  integer     not null default 0,
        evaluated_at   timestamptz not null default now(),
        constraint policy_decisions_verdict check (decision in ('allow','deny','challenge','review')),
        constraint policy_decisions_risk_range check (risk_score between 0 and 100)
      );

      -- GET /subjects/:subject/decisions, newest first. The id tiebreaks so a cursor over two
      -- decisions written in the same millisecond is stable.
      create index if not exists policy_decisions_subject_idx
        on policy_decisions (subject, evaluated_at desc, id desc);

      -- The retention sweep's access path, and the only query that reads across subjects.
      create index if not exists policy_decisions_evaluated_idx on policy_decisions (evaluated_at);

      -- A decision is evidence. Evidence that can be edited is not evidence, and an UPDATE here
      -- would be indistinguishable afterwards from the decision having been made that way. The
      -- retention sweep still deletes, which is a different claim: the record is gone, not
      -- rewritten to say something it never said.
      create or replace function policy_decisions_no_update() returns trigger as $$
      begin
        raise exception 'policy_decisions is append-only; a correction is a new decision';
      end;
      $$ language plpgsql;

      drop trigger if exists policy_decisions_immutable on policy_decisions;
      create trigger policy_decisions_immutable
        before update on policy_decisions
        for each row execute function policy_decisions_no_update();
    `,
  },
  {
    version: 4,
    name: 'velocity_counters',
    up: `
      -- Tumbling windows, keyed on the floor of the clock. The bucket is computed identically in
      -- src/evaluate.ts (windowStart) — a decision that read one bucket and incremented another
      -- would leave every cap permanently unreached.
      create table if not exists velocity_counters (
        subject        text        not null,
        action         text        not null,
        window_seconds integer     not null,
        window_start   timestamptz not null,
        -- Empty string rather than null: this is part of the primary key, and a null there would
        -- let two rows for "no asset" coexist and each hold half the count.
        asset          text        not null default '',
        used_count     integer     not null default 0,
        amount_total   numeric(40,18) not null default 0,
        updated_at     timestamptz not null default now(),
        primary key (subject, action, window_seconds, window_start, asset)
      );

      -- The pruning job's access path. Partial indexes are no use here: every row expires.
      create index if not exists velocity_counters_window_idx on velocity_counters (window_start);
    `,
  },
  {
    version: 5,
    name: 'trusted_addresses',
    up: `
      -- SD-10: adding a trusted address is itself a 24-hour, notified operation. effective_at is
      -- how that is enforced — a row exists immediately, so the user can see it pending, and it
      -- does not make a destination trusted until the clock has passed.
      create table if not exists trusted_addresses (
        id           uuid        primary key default gen_random_uuid(),
        subject      text        not null,
        chain        text        not null default '',
        address      text        not null,
        added_at     timestamptz not null default now(),
        effective_at timestamptz not null,
        revoked_at   timestamptz,
        added_by     text        not null
      );

      -- One live entry per destination. Partial, so a revoked entry does not block re-adding an
      -- address later — which is a thing users legitimately do after losing a wallet.
      create unique index if not exists trusted_addresses_live_uniq
        on trusted_addresses (subject, chain, address)
        where revoked_at is null;
    `,
  },
  {
    version: 6,
    name: 'cooling_off_timers',
    up: `
      -- A timer is started by the first refused attempt, not by a separate call. Whether it has
      -- elapsed is decided in src/evaluate.ts against the rule's own duration, so one timer can
      -- serve several rules and shortening the rule does not require restarting the clock.
      create table if not exists cooling_off_timers (
        subject    text        not null,
        timer      text        not null,
        started_at timestamptz not null default now(),
        cleared_at timestamptz,
        primary key (subject, timer)
      );
    `,
  },
  {
    version: 7,
    name: 'freezes',
    up: `
      create table if not exists freezes (
        id           uuid        primary key default gen_random_uuid(),
        subject      text        not null,
        -- '*' for the whole subject, an action name, or 'asset:<CODE>'. The asset form is what
        -- SD-10's reconciliation-drift freeze needs: it must stop that asset and no other.
        scope        text        not null default '*',
        reason       text        not null,
        created_by   text        not null,
        created_at   timestamptz not null default now(),
        cleared_at   timestamptz,
        cleared_note text
      );

      -- One live freeze per (subject, scope), so a second operator freezing the same thing does
      -- not create a second freeze that then needs clearing twice over.
      create unique index if not exists freezes_live_uniq
        on freezes (subject, scope)
        where cleared_at is null;

      create index if not exists freezes_subject_idx on freezes (subject) where cleared_at is null;

      -- The asymmetry, and the reason it is a table rather than a counter.
      --
      -- A freeze is set by one operator and cleared by two. If clearing incremented a column, the
      -- same operator calling twice would clear it alone, and no amount of application code can
      -- rule that out under concurrency. One row per operator, with the operator IN THE PRIMARY
      -- KEY, makes a second attempt by the same person a conflict at the database rather than a
      -- branch someone can forget to write.
      create table if not exists freeze_clearances (
        freeze_id    uuid        not null references freezes (id) on delete cascade,
        operator     text        not null,
        requested_at timestamptz not null default now(),
        note         text,
        primary key (freeze_id, operator)
      );
    `,
  },
  {
    version: 8,
    name: 'inbox_and_erasure',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- THE INBOX ARRIVES. THE OUTBOX STILL DOES NOT.
      --
      -- This file's header used to say policy subscribes to nothing, and that half is now spent:
      -- rule 6 of 03 §2 is not optional for a service holding a subject on five tables, and this
      -- service holds one on five. So the consumer half lands and the producer half does not — no
      -- 'outbox', no 'event_subscriptions', no 'outbox_deliveries', no relay job. The trigger for
      -- those is unchanged and still the first 'policy.*' topic accepted into the registry.
      --
      -- Copied verbatim from the sibling services rather than written afresh, so the table the
      -- dedupe assumes and the table that exists cannot drift.
      -- ════════════════════════════════════════════════════════════════════════════════════════

      -- Delivery is at-least-once, so the consumer is what makes it effectively-once. The primary
      -- key is the dedupe: a redelivered event conflicts and the handler is never re-run.
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );

      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- ERASURE, AND THE ONE INVARIANT IT NEEDS FROM THE SCHEMA.
      --
      -- 'src/erasure.ts' is the table-by-table reasoning and the lawful basis for each row that
      -- survives. What is here is the part a handler cannot do, which is to make the erasure
      -- DURABLE rather than a one-shot delete.
      --
      -- THE RACE THIS CLOSES. 'trusted_addresses' is written by a user-facing route. A request that
      -- was in flight when the erasure ran — queued behind a slow decision, retried by a client,
      -- replayed from a mobile app that had not noticed the account was gone — lands AFTER the
      -- delete and puts the row straight back. Nothing in the handler can prevent that, because the
      -- handler has already returned. A trigger reading a durable marker can.
      --
      -- ── WHY THIS TABLE IS NOT ITSELF A PRIVACY DEFECT, AND WHEN IT WOULD BE ─────────────────
      --
      -- It stores the subject of an erased person, which is the identifier being erased. That is
      -- defensible in exactly one case and the handler enforces the condition rather than assuming
      -- it: a row is written ONLY when this service is already lawfully retaining that subject
      -- somewhere else — a policy_decisions row under the AML/dispute basis, or a freeze. In that
      -- case the marker adds no identifier the service was not already holding, and it buys the
      -- guarantee above.
      --
      -- Where policy held nothing but preferences, everything is deleted and NO marker is written,
      -- because recording "this person was erased" would leave behind the only trace of them that
      -- ever existed here. The trade is stated honestly in 'src/erasure.ts': those subjects get no
      -- re-insert guard, and a trusted address re-added by an in-flight request would survive until
      -- somebody noticed.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create table if not exists erased_subjects (
        subject     text        not null primary key,
        -- The event's own 'tombstoneAt', not now(). The retention clock an auditor checks runs
        -- from the deletion request, not from whenever a relay happened to succeed.
        tombstone_at timestamptz not null,
        -- The delivery that did it. A random uuid naming an envelope, not a person, and the join
        -- back to the 'inbox' row that proves the event was received exactly once.
        event_id    uuid        not null,
        erased_at   timestamptz not null default now(),
        constraint erased_subjects_subject_shaped
          check (subject like 'user:%' or subject like 'community:%' or subject like 'organisation:%')
      );

      -- A marker is a statement of fact about something that has already happened. Rewriting one
      -- would change which erasure a retained row is accounted for by, and there is no legitimate
      -- reason to: a second deletion of the same subject is the same deletion.
      create or replace function policy_erased_subjects_no_update() returns trigger as $$
      begin
        raise exception 'erased_subjects is append-only; a subject is erased once';
      end;
      $$ language plpgsql;

      drop trigger if exists erased_subjects_immutable on erased_subjects;
      create trigger erased_subjects_immutable
        before update on erased_subjects
        for each row execute function policy_erased_subjects_no_update();

      -- THE GUARD. A trusted address is a standing authorisation to send money somewhere with less
      -- friction; re-creating one for a deleted account is the one re-insert here with a real cost.
      --
      -- Deliberately NOT applied to velocity_counters or cooling_off_timers. Both are written on
      -- the decide path, which is a read-shaped route several services call synchronously, and an
      -- exception raised there would turn a policy lookup into a 500 for a subject nobody should be
      -- evaluating anyway. They are left to their own prune (POLICY_COUNTER_RETENTION_HOURS,
      -- 48h by default), which is bounded and already runs.
      create or replace function policy_refuse_erased_subject() returns trigger as $$
      begin
        if exists (select 1 from erased_subjects where subject = new.subject) then
          raise exception 'subject % has been erased; a trusted address cannot be added', new.subject
            using errcode = 'integrity_constraint_violation';
        end if;
        return new;
      end;
      $$ language plpgsql;

      drop trigger if exists trusted_addresses_refuse_erased on trusted_addresses;
      create trigger trusted_addresses_refuse_erased
        before insert on trusted_addresses
        for each row execute function policy_refuse_erased_subject();
    `,
  },
]

/**
 * The version this build of the service requires. `index.ts` asserts it at boot and refuses to
 * serve below it, which is what stops a replica of the new code answering requests against the
 * old schema when a deploy runs ahead of its migrator.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0)

/**
 * How many distinct operators must ask before a freeze clears.
 *
 * Two, and it lives here beside the table whose primary key enforces the "distinct" half, so the
 * two halves of the control cannot be changed independently.
 */
export const REQUIRED_CLEARANCES = 2

/**
 * A new service baselines nothing. See the note in the template: a non-zero baseline records
 * migrations as applied without running them, which is a one-way bridge for adopting an existing
 * hand-built schema and has no meaning for a database that has never existed.
 */
export const BASELINE_VERSION = 0
