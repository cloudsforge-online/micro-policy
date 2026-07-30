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
 * At that point migration 8 adds `outbox`, `event_subscriptions` and `outbox_deliveries` verbatim
 * from the template, and `OUTBOX_SIGNING_SECRET` enters `env.ts`. Nothing else changes.
 *
 * The same reasoning removes `inbox`: policy subscribes to nothing today. The reconciliation
 * drift freeze in SD-10 is what will change that, and it will arrive with the inbox it needs.
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
