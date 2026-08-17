# micro-policy

[![ci](https://github.com/cloudsforge-online/micro-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-policy/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml)

The decision service. Callers submit a subject, an action, a resource and a context, and receive
allow, deny, challenge or review with reasons and obligations. **It decides; callers enforce.**

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

> **There is no route in this service that blocks anything, holds anything or moves anything.**
> `POST /decisions` returns an opinion and the caller is what acts on it (`src/server.ts`).
> The reason is AD-09: a decision service that also sits in the data path becomes a single point of
> failure for every money movement in the estate. The moment a handler here calls wallet or custody
> that property is gone and cannot be recovered without a rewrite.

It owns rules, limits, velocity counters, trusted addresses, cooling-off timers, approval
workflows, freezes, and device and account risk scores. It publishes no events and subscribes to
none — see [What it does not have](#what-it-does-not-have).

## The one decision this service makes about itself

Everything else here follows from a single question: **what should policy say when it cannot
decide?** A verdict is computed from a snapshot of rule data, reading that snapshot is a database
query, and a database query can fail.

There are exactly two honest answers and both are wrong some of the time. Denying everything turns
one unavailable table into an estate-wide outage — nobody signs in, nobody trades, nobody
withdraws. Allowing everything turns one unavailable table into an unguarded window during which a
private key can be exported. AD-09 refuses to pick one globally: **fail closed on a narrow, named
set of actions and fail open, with an alert, on everything else** (`src/actions.ts`).

The split lives in `src/actions.ts` and not in the rules table, because **it is consulted precisely
when the rules table cannot be read** (`src/actions.ts`). A fail mode stored as a row is a
fail mode that is unavailable at the moment it is needed.

| Action | On store failure | Why |
| --- | --- | --- |
| `custody.key.export` | **deny** | the only action in the estate with no undo (`src/actions.ts`) |
| `ledger.treasury_spend` | **deny** | a spend from a platform account, not a user's (`src/actions.ts`) |
| `identity.session.new_device` | **deny** | the first step of every account takeover in the incident history; the availability cost is paid knowingly (`src/actions.ts`) |
| `wallet.withdrawal` | **deny at or above a floor**, allow below | SHARD 1000, EMBER 100, ETH 0.05, BTC 0.002, XRP 50 (`src/actions.ts`) |
| `wallet.deposit_address.assign`, `wallet.trusted_address.add`, `market.listing.create`, `trade.order.place`, `mint.deploy.request`, `agora.post.create`, `identity.password.reset`, `api.request` | **allow, and alert** | each is a control whose value is statistical; blocking one request because a table blinked buys nothing (`src/actions.ts`) |

Three properties are worth knowing because they are easy to lose:

* **An unregistered action is a 400, never a guess** (`src/actions.ts`, `src/server.ts`).
  Defaulting an unknown action to open would let a caller reach the unchecked path by misspelling
  `custody.key.export`; defaulting it to closed would mean a typo in a new caller silently blocks a
  product. Neither is a choice anyone would make deliberately, so neither is offered.
* **`FAIL_CLOSED_ACTIONS` is derived from the registry, never written out** (`src/actions.ts`),
  and `closed_at_or_above` counts as fail-closed, because there exists a request on that action
  which a store failure denies.
* **A withdrawal has two thresholds and they are different numbers on purpose.** The rule in the
  store governs an ordinary evaluation and is tunable without a deploy; the constant in
  `src/actions.ts` is the floor that survives the store being gone, and it is deliberately more
  conservative (`src/actions.ts`). An asset with no floor is refused rather than defaulted
  (`src/actions.ts`) — a withdrawal in an asset nobody set a floor for is a withdrawal
  nobody has thought about.

A fail-open allow still carries the obligation `unchecked_decision`, `failOpen: true` is stored on
the decision row, and `policy_fail_open_total` increments (`src/decide.ts`). That counter
**must be zero**; a non-zero rate means decisions are being handed out with nothing behind them
(`src/server.ts`). Its twin `policy_fail_closed_total` is not an alert but a symptom: a
non-zero rate there means custody exports and treasury spends are being refused, and somebody is
about to report that the platform is broken when it is doing its job (`src/server.ts`).

## Routes

Read out of `src/server.ts`. Every route except the three probes calls `authenticate()`.
Every response carries `x-request-id` and `cache-control: no-store` — a cached decision is a
decision made against rules that have since changed (`src/server.ts`).

| Method | Path | Who | What it does |
| --- | --- | --- | --- |
| `GET` | `/livez` | public | static; a liveness probe that consults a dependency restarts a healthy process every time the database blinks (`src/server.ts`) |
| `GET` | `/readyz` | public | 503 until the Postgres probe passes (`src/server.ts`) |
| `GET` | `/metrics` | public | Prometheus text; gauges sampled at scrape time (`src/server.ts`) |
| `POST` | `/decisions` | **service only**, scope `policy:decide` | evaluate and record; 201 with the stored decision (`src/server.ts`) |
| `GET` | `/decisions/:id` | operator, `policy:decide`, **or the subject** | one decision (`src/server.ts`) |
| `GET` | `/subjects/:subject/decisions` | operator, `policy:decide`, or the subject | newest first; `?limit` 1–200, `?cursor` (`src/server.ts`) |
| `GET` | `/rules` | `role:admin` | the newest version of every rule, plus the action registry (`src/server.ts`) |
| `POST` | `/rules` | `role:admin` | writes the **next version**; 201 (`src/server.ts`) |
| `GET` | `/rules/:key` | `role:admin` | every version, newest first — where a decision's `key@version` citation is resolved months later (`src/server.ts`) |
| `DELETE` | `/rules/:key` | `role:admin` | disables by writing a new version. 200 with that version rather than 204: a delete here is an insert, and "no content" would hide that the history is still there (`src/server.ts`) |
| `POST` | `/trusted-addresses` | `role:admin` | 201; `coolingOffSeconds` defaults to 86 400, not 0 (`src/server.ts`) |
| `POST` | `/freezes` | `role:admin` | 201; 409 when a live freeze already covers this `(subject, scope)` (`src/server.ts`) |
| `GET` | `/freezes/:id` | `role:admin` | one freeze with its clearances (`src/server.ts`) |
| `GET` | `/subjects/:subject/freezes` | operator, `policy:decide`, or the subject | live freezes only (`src/server.ts`) |
| `DELETE` | `/freezes/:id` | `role:admin` | **202** on the first operator, 200 on the second (`src/server.ts`) |

A user token can never reach `POST /decisions`: `requireScope` is false for anything that is not a
service (`src/server.ts`). Deciding on your own behalf is not offered.

**A user may read a decision about themselves** (`src/server.ts`). That is not a courtesy.
04-domain-model §10.4 says "why was I blocked" must be answerable, and answering it only to
operators means the answer arrives through a support ticket or not at all.

**A verifier that cannot reach identity's JWKS answers 503, never 401** (`src/server.ts`).
Answering 401 there would sign every user in the estate out because identity is having a bad
minute.

### The 202 on `DELETE /freezes/:id`

One operator freezes. Two clear. The status code carries the control: an operator who reads 202
knows their request was recorded and that the freeze is **still in force**, and a client that
treats 2xx as "done" without reading the body is wrong in a way that is visible in an access log.
Answering 200 with `{cleared: false}` would make the difference invisible to everything except code
that already knew to look (`src/server.ts`).

The asymmetry runs in the direction safety runs (`src/freezes.ts`). The mistake one operator
can make alone is stopping something that should have carried on — an availability cost, instantly
reversible by two people. The mistake two are needed to prevent is restarting money movement that
was stopped for a reason, and that one is not reversible once the funds have left. Requiring two to
freeze would mean an operator watching an account being drained at 3am has to find a colleague
first. The operator who froze **may** be one of the two who clear (`src/freezes.ts`):
excluding them would only defend against someone who freezes in order to unfreeze later, which buys
nothing, because they could simply not have frozen it.

## How a decision is reached

`src/evaluate.ts` is a pure function — no clock, no database, and no branch that depends on either.
Everything that can fail happens in `src/store.ts` and is handed in as a value, which is what makes
the fail-safe reachable from exactly one place (`src/decide.ts`).

1. **A freeze short-circuits everything.** It is checked before any rule and no rule can soften it:
   it is an operator having said stop, and a rule that could overrule it would make the freeze
   advisory (`src/evaluate.ts`). The score is reported as 100 rather than computed — a
   frozen subject is at maximum risk by definition, and computing one would invite a comparison
   that means nothing.
2. **Rules combine by taking the strictest, never by voting or averaging** (`src/rules.ts`).
   Two `challenge` verdicts do not add up to a `deny`, and — much more importantly — an `allow`
   cannot cancel a `deny`. A control that another control can outvote is not a control.
3. **Risk bands are applied last**, because the score depends on whether a velocity rule breached,
   which is only known once every other rule has run (`src/evaluate.ts`).

The score is additive, capped at 100, and deliberately not a model: `new_device` 30,
`untrusted_destination` 35, `mfa_not_satisfied` 20, `country_changed` 15, `velocity_breached` 25,
and 5 per recent failure capped at 20 (`src/evaluate.ts`). It is a legible arithmetic an
operator can reproduce on paper from a stored decision, which is worth more here than accuracy
nobody can audit — and the weights are set so **no single signal reaches a deny band on its own**.
AD-09's story is a combination; a score that denied on one signal would deny every honest user who
bought a new laptop.

**Reasons are codes, not sentences** (`src/evaluate.ts`) — `amount_at_or_above:1000:ETH`,
`velocity_count:4/3:3600s`, `cooling_off_active:key-export:3421s_remaining`. A sentence would be
reworded by the next person to touch the file, and every stored decision would then be describing a
rule text that no longer exists.

### The five rule kinds

Parsed, never cast (`src/rules.ts`): a rule arrives as JSON on an admin route, and a
malformed one must be a 400 to the operator writing it rather than an exception inside the
evaluator two weeks later — because an exception there is "the rule store failed", which for a
withdrawal denies everything.

| Kind | What it says | The parser refuses |
| --- | --- | --- |
| `amount_limit` | thresholds on one asset's amount | an empty list; thresholds are stored strictest-first so evaluation takes the first match and the stored rule is the evaluated one (`src/rules.ts`) |
| `velocity` | a cap per tumbling window, per subject and action | neither `maxCount` nor `maxAmount`; a `maxAmount` with no `asset`, because summing SHARD and ETH into one total is not a cap but a number (`src/rules.ts`) |
| `trusted_address` | a destination the subject has not sent to before | returns `hold_for_seconds:<n>` as an obligation rather than holding anything (`src/rules.ts`) |
| `cooling_off` | a named timer that must have elapsed | a timer key that is not lowercase (`src/rules.ts`) |
| `risk_score` | where a score stops being tolerable | bands out of order — an unreachable band reads as a control and is not one (`src/rules.ts`) |

The velocity window is a **tumbling** window keyed on the floor of the clock, and the trade is
stated rather than hidden (`src/rules.ts`): a calendar window lets a subject spend a full
budget at 23:59 and another at 00:01, and a sliding window costs a table scan per decision. The
count compares `window.count + 1` — a cap of 3 must deny the fourth, and comparing an
already-recorded 3 against 3 would allow it (`src/evaluate.ts`).

A cooling-off timer is started by the **first refused attempt**, which is what makes it a period
rather than a formality (`src/evaluate.ts`): the first attempt is always refused and the
clock begins from that refusal.

**Not one comparison in this service goes through a float.** `compareDecimal` and `addDecimal`
split on the point and compare as padded integers (`src/actions.ts`,
`src/evaluate.ts`), and both return `null` for anything that is not a plain decimal, which
callers treat as undecidable rather than as zero — a velocity cap that read a malformed total as
zero would be a cap that never fires. An amount arriving as a JSON number is rejected rather than
coerced: by the time this code saw it, it would already have been through a float
(`src/server.ts`).

## Background work

Two leased jobs and no timers. There is no `setInterval` in this repository and CI greps for one —
rule 8 (`src/jobs.ts`). **The lease key names the contended resource, not the row**: both jobs
are estate-wide sweeps over one table each, so both key on `global`. Keying on a subject would be
right for a per-subject job, and neither of these is one.

| Job | Lease key | Cadence | Two replicas |
| --- | --- | --- | --- |
| `policy.decisions.retention` | `global` | 1 h | one claims it; the other finds nothing (`src/jobs.ts`) |
| `policy.counters.prune` | `global` | 15 min | as above (`src/jobs.ts`) |

Retention deletes in batches of 1000 with a heartbeat between them, up to 100 passes
(`src/jobs.ts`). A single `DELETE` over two years of decisions takes a long transaction and
a lock that stalls every decision being written while it runs, and a retention sweep that causes an
outage is worse than a table that is bigger than it needs to be for another hour.

A recurring job is re-armed from the runner's `completed` event and never from inside its own
handler — the runner deletes the row after the handler returns, so a self-enqueue would be deleted
a moment later and the schedule would stop (`src/jobs.ts`). **A dead-lettered recurring job
is deliberately not re-armed**: the row stays, `jobs_dead_total` increments and `jobs_overdue`
climbs, which is how an operator finds out. Rescheduling it would hide a permanent fault behind a
busy loop.

## The database

Seven migrations, expand/contract only, run by `src/migrator.ts` and never by the service
(`src/migrations.ts`). `index.ts` asserts the version at boot and exits rather than serving,
so a replica of new code cannot answer requests against an old schema (`src/index.ts`).

| Table | Holds |
| --- | --- |
| `policy_rules` | every version of every rule; a change is an insert at `version + 1` |
| `policy_decisions` | the decision record, retained for the dispute window |
| `velocity_counters` | tumbling-window buckets per subject, action, window length and asset |
| `trusted_addresses` | destinations, each with the moment it becomes effective |
| `cooling_off_timers` | when a named timer started for a subject |
| `freezes`, `freeze_clearances` | live and cleared freezes, and who has asked to clear each |
| `jobs` | `@cloudsforge/jobs`, imported verbatim rather than hand-copied, so the claim query and the table cannot drift (`src/migrations.ts`) |

The constraints that carry meaning, and why each is in the schema rather than in a handler:

| Constraint | Refuses | Why here |
| --- | --- | --- |
| `policy_decisions_immutable` (trigger) | any `UPDATE` on a decision | evidence that can be edited is not evidence, and an edit would afterwards be indistinguishable from the decision having been made that way. The retention sweep still deletes, which is a different claim: the record is gone, not rewritten to say something it never said (`src/migrations.ts`) |
| `freeze_clearances` PK `(freeze_id, operator)` | the same operator clearing twice | a counter column would clear a freeze on one operator's double-click, and no amount of "check, then increment" fixes that under concurrency (`src/migrations.ts`) |
| `freezes_live_uniq` (partial, `where cleared_at is null`) | a second live freeze on one `(subject, scope)` | a duplicate would need clearing twice over; the insert answers 409 rather than returning somebody else's freeze with the wrong reason attached (`src/migrations.ts`, `src/freezes.ts`) |
| `trusted_addresses_live_uniq` (partial, `where revoked_at is null`) | two live entries for one destination | partial, so a revoked entry does not block re-adding an address later — which users legitimately do after losing a wallet (`src/migrations.ts`) |
| `velocity_counters` PK including `asset`, defaulted to `''` and never null | two rows for "no asset", each holding half the count | a null in a primary key does not compare equal to itself (`src/migrations.ts`) |
| `policy_rules_key_version_uniq` | a second row at one `(key, version)` | the version is computed inside the insert, so two operators editing at once produce 4 and 5 rather than both producing 4 and one reporting success it did not have (`src/store.ts`) |
| `policy_decisions_verdict`, `policy_decisions_risk_range` | a verdict outside the four, a score outside 0–100 | the wire vocabulary and the schema cannot drift apart (`src/migrations.ts`) |

Two writes are load-bearing beyond their constraints. **Only an `allow` consumes velocity budget**
(`src/store.ts`): a denied request did not happen, and counting it would let an
already-blocked subject stay blocked a whole extra window by retrying — a denial that lengthens
itself is one nobody can get out of. The approximation is named rather than hidden: an allowed
decision the caller then abandoned still consumed budget, which errs towards denying, and the
alternative — a confirmation callback — puts policy back in the data path AD-09 removed it from.
And a cooling-off timer is inserted `on conflict do nothing`, with **the decision's clock rather
than the database's default** (`src/store.ts`): if a repeated attempt restarted the clock a
user would never get through, and a row written with `now()` would be comparing a database clock
against an application one — two clocks that agree almost always, which is exactly what would make
the disagreement impossible to find.

The decision, the velocity it consumed and the timer it started are **one transaction**
(`src/decide.ts`, `src/decide.ts`). A decision recorded without its counter lets a
subject repeat it; a counter without its decision is a subject blocked by evidence nobody can
produce.

The stored `context` is the decision's view of the request and not the request itself
(`src/decisions.ts`): what was actually consulted, and nothing else. A verbatim copy of the
caller's body would pull whatever a caller happened to send into a table kept for two years, which
is how a service that stores no personal data ends up storing personal data.

## Configuration

Every variable the service reads is declared in `src/env.ts` and nowhere else, which is what lets
the deploy manifest be derived from `.env.example` instead of an `env_file:` fan-out handing every
container the estate's secrets (`src/env.ts`). Validation runs at import, so a bad value exits
before the logger exists — and one structured `fatal` line is written by hand rather than through
telemetry, because nothing that can itself fail may sit between a configuration error and the
report of it (`src/env.ts`).

| Variable | Default | If it is wrong |
| --- | --- | --- |
| `POLICY_DATABASE_URL` | — | refuses to start (`src/env.ts`). Rule 1: one database, and CI fails the build on a second connection string |
| `IDENTITY_JWKS_URL` | — | refuses to start (`src/env.ts`); also a **soft** readiness probe, because marking it hard would remove every service in the estate from its balancer on one identity blip (`src/index.ts`) |
| `IDENTITY_ISSUER` | — | refuses to start (`src/env.ts`) |
| `PORT` | `4000` | (`src/env.ts`) |
| `LOG_LEVEL` | `info` | a value outside debug/info/warn/error refuses to start (`src/env.ts`) |
| `POLICY_DATABASE_POOL_MAX` | `10` (1–100) | a pool larger than the database's budget divided by the replica count exhausts Postgres for everything else (`src/env.ts`) |
| `POLICY_DECISION_RETENTION_DAYS` | `730` (**floor 90**) | the floor refuses a value that would delete the evidence before the argument about it has started (`src/env.ts`, `src/env.ts`) |
| `POLICY_COUNTER_RETENTION_HOURS` | `48` (2–720) | too low, and a late decision inside a still-open window finds no bucket (`src/env.ts`) |
| `INSTANCE_ID` | hostname | names this replica in `jobs.locked_by` — the container id under compose, the pod name under Kubernetes (`src/env.ts`) |
| `CLOUDSFORGE_TAG` | `dev` | reported on every log line and in the release manifest (`src/env.ts`) |

There is no `requiredSecret` helper and no `OUTBOX_SIGNING_SECRET`, and both absences are
deliberate (`src/env.ts`). **This service holds no secret at all**: it verifies tokens against
identity's public JWKS and signs nothing. Copying the template's placeholder check in anyway would
be a check with no subject, which reads to the next person as though a secret exists here. `OTEL_*`
is read by the OpenTelemetry SDK loaded ahead of the process rather than by this service, so under
rule 9 it is not declared (`src/index.ts`).

## What it talks to

| Upstream | What for | When it is down |
| --- | --- | --- |
| `micro-identity` | JWKS, to verify bearer tokens. Nothing else | 503 on requests needing a fresh key; readiness stays green, because the probe is soft (`src/index.ts`, `src/server.ts`) |

That is the whole list. Policy calls no wallet, no custody and no ledger — see the refusal at the
top of this file.

## What it does not have

* **No outbox, no inbox, no events.** The template ships an outbox and most services need one, but
  a table nothing writes to is worse than an absent one: it arrives with a relay job, a signing
  secret in the deploy, a subscription somebody will register against it and a permanently empty
  dashboard panel. `contracts-events` registers no `policy.*` topic, so there is at present nothing
  this service is entitled to publish (`src/migrations.ts`). The trigger for adding one is
  written down so that it is a decision and not an argument: the first `policy.freeze.applied` or
  `policy.decision.recorded` topic accepted into the registry, at which point migration 8 adds the
  three tables verbatim from the template and `OUTBOX_SIGNING_SECRET` enters `env.ts`. SD-10's
  reconciliation-drift freeze is what will bring the inbox, and it will arrive with it.
* **No rule is ever deleted.** `DELETE /rules/:key` writes a disabling version
  (`src/store.ts`). A deleted rule takes its history with it, and every decision citing it
  then names a version nobody can look up, which defeats the only reason `rule_versions[]` exists.
  For the same reason a rule is never `UPDATE`d: a row that now says something else makes every
  decision that cited it unreproducible (`src/rules.ts`).

## Running it

```bash
pnpm install
cp .env.example .env      # every value there is a placeholder; src/env.ts refuses to boot on one
pnpm migrate              # a one-shot job. Never run from the service.
pnpm start
```

The suite is `node:test` against a **real Postgres**: deferred constraints, partial unique indexes
and the append-only trigger are the assertions most worth having here, and not one of them survives
a fake. The database name must contain `test` — `resetPolicy` truncates every table, and that check
is the difference between a red build and an emptied environment (`src/testsupport.ts`).

```bash
docker run -d --rm --name policy-pg \
  -e POSTGRES_USER=policy -e POSTGRES_PASSWORD=policy -e POSTGRES_DB=policy_test \
  -p 55432:5432 postgres:17-alpine

POLICY_TEST_DATABASE_URL=postgres://policy:policy@127.0.0.1:55432/policy_test pnpm test
pnpm check                # typecheck, then the suite
```

Without that variable the database-backed files skip and only `src/unit.test.ts` runs. **CI fails
the build when that happens** — a green run that skipped its database tests is worse than a red
one, because it is believed.

`--test-concurrency=1` in the `test` script is required rather than preferred: every database test
file truncates between cases, `node:test` runs files in parallel by default, and a `TRUNCATE` takes
an `AccessExclusiveLock` that deadlocks against another file's inserts with `40P01`
(`package.json`).

| File | Covers |
| --- | --- |
| `src/unit.test.ts` | the action registry, the fail-safe over every action, decimal comparison, verdict combination and rule parsing — no database |
| `src/decisions.test.ts` | recording, the append-only trigger, subject listing and cursor stability |
| `src/velocity.test.ts` | window arithmetic, the off-by-one at the cap, and the split between count and amount buckets |
| `src/freezes.test.ts` | one operator freezes, two clear, and the same operator twice does not |
| `src/server.test.ts` | the routes, the auth mapping, the 202, and the fail-safe end to end |

`failingReader()` (`src/testsupport.ts`) is the seam that makes AD-09's split testable at
all. Taking Postgres away would make the rule store fail, but it would also take away the
`policy_decisions` table the test has to read afterwards in order to prove the decision was still
recorded — so the failure is injected at the one port that can fail.

## Known gaps

* **No events.** Recorded above, with the exact condition that ends it.
* **A velocity budget is consumed by an allowed decision the caller may never act on.** Named at
  `src/store.ts`, with the reason the alternative is worse.
* **A trusted address is matched exactly and deliberately not case-folded**
  (`src/store.ts`). An EVM address is case-insensitive but a Bitcoin or Solana base58
  address is not, so folding here would make two different Solana addresses look like one trusted
  destination. Callers normalise per chain, and a caller that does not will see its user's trusted
  address treated as untrusted.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
