/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable the service reads is named here and
 * nowhere else, so the deploy manifest can be derived from it and `env_file: .env` fan-out (which
 * hands every container the whole estate's secrets) has nothing to justify it.
 *
 * Policy still produces no events — the reason is written out in `migrations.ts` — but it now
 * CONSUMES one, `identity.user.deleted`, and a consumer has to verify the HMAC the producer's
 * relay put on the body. So `OUTBOX_SIGNING_SECRET` is read here after all, and it is read for
 * verification only: nothing in this service signs anything.
 *
 * Every entry of that key family is held to `@cloudsforge/secrets`' shape check rather than to a
 * deny-list of exact strings, which is the estate-wide rule after micro-org #142. ABSENT remains a
 * supported state here and only here — see `acceptSecretsFrom` for why, and for what the route
 * does instead of pretending to be guarded.
 */

import { hostname } from 'node:os'
import { assertGeneratedSecretList, SecretError } from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a
 * migration advisory lock.
 */
export const SERVICE = 'policy'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

type Source = Readonly<Record<string, string | undefined>>

/**
 * `@cloudsforge/secrets` raises `SecretError`; this file's contract is that `loadEnv` raises
 * `EnvError`, and every caller here is written to that.
 *
 * So the shape failures are re-wrapped rather than rethrown, and the message is carried across
 * VERBATIM: it already names the variable and the command that fixes it, and by construction it
 * contains no part of the value. Only the class changes, so there is one thing to catch here and
 * nothing to re-derive by matching on text.
 */
function asEnvError(err: unknown): never {
  throw err instanceof SecretError ? new EnvError(err.message) : err
}

/**
 * The secrets `POST /v1/events` will accept a delivery signature under.
 *
 * ── WHY THIS IS OPTIONAL, AND WHAT THE ROUTE DOES WHEN IT IS EMPTY ─────────────────────────────
 *
 * Every other variable in this file is required, because rule 9's discipline is that a service
 * refuses to start rather than serve half-configured. This one is not, and the reason is a fact
 * about the deploy rather than a preference: policy's compose block did not carry an `env_file`
 * with the outbox secrets in it, because until recently policy neither signed nor verified
 * anything. Making it required would turn the erasure fix into a service that will not boot on the
 * live estate — a bigger outage than the gap it closes, on a service every money route consults.
 *
 * **ABSENT IS STILL A SUPPORTED STATE AFTER micro-org #142, AND THAT IS DELIBERATE.** The guard
 * below refuses a placeholder; it does not turn a missing variable into a boot failure. Only the
 * entries that ARE present have to clear the bar. The two are different facts: an absent list is a
 * deploy that has not been given the key yet, and it is reported rather than hidden; a present
 * rubbish one is a deploy that BELIEVES it is verifying and is not.
 *
 * Unconfigured is NOT silently tolerated. `POST /v1/events` answers **503** when this list is
 * empty: the relay treats that as a delivery failure and retries, so the event is not lost, it is
 * queued and visible in the producer's delivery-failure view until somebody sets the variable. The
 * alternative — verifying against nothing, or accepting unsigned deliveries — would make an
 * unauthenticated caller able to erase any user by uuid. It is a live gap rather than a
 * hypothetical one: micro-org #196 measured this variable ABSENT on the running estate, on the one
 * service of 26 that reads an outbox secret and had never been given one.
 *
 * ── WHY THE ENTRIES ARE HELD TO A SHAPE AND NOT TO A DENY-LIST ─────────────────────────────────
 *
 * The inline checks this replaced could not fail. They refused a fixed list of exact strings and
 * anything under 24 characters, and the value that sat on 54 lines of a PUBLIC compose file —
 * `estate-only-outbox-secret-00000000000000` — was on no list and was 40 characters (micro-org
 * #142). `assertGeneratedSecretList` asserts what a placeholder cannot have, per entry: the base64
 * or hex alphabet (no hyphens — every placeholder this estate wrote had one), 32 decoded BYTES
 * rather than 24 keystrokes, and a measured Shannon entropy floor. No NODE_ENV exemption, no
 * escape hatch.
 *
 * A list rather than a string so the estate's shared key can be rotated one service at a time —
 * and every entry of it clears the same bar, because in an overlap window the OUTGOING key is the
 * one an attacker already holds if it leaked. Policy signs nothing; it only verifies, which makes
 * a weak entry here exactly as bad as a weak signing key elsewhere.
 */
function acceptSecretsFrom(source: Source): readonly string[] {
  // Named for the variable actually read, so an operator is told which of the two to regenerate.
  // The precedence matches the `??` below: an ACCEPT list that is set to the empty string wins,
  // and means the same "not configured yet" an absent one does.
  const name = source['OUTBOX_ACCEPT_SECRETS'] !== undefined ? 'OUTBOX_ACCEPT_SECRETS' : 'OUTBOX_SIGNING_SECRET'
  const raw = (source['OUTBOX_ACCEPT_SECRETS'] ?? source['OUTBOX_SIGNING_SECRET'] ?? '').trim()
  if (raw.length === 0) return Object.freeze([])
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  // Not `assertGeneratedSecretList` unconditionally: it refuses an empty list, and empty is the
  // supported "no key yet" state this route answers 503 to. A value of `,` or ` ` lists nothing
  // and is treated as the same absence rather than as a boot failure.
  if (entries.length === 0) return Object.freeze([])
  try {
    assertGeneratedSecretList(name, entries)
  } catch (err) {
    asEnvError(err)
  }
  if (new Set(entries).size !== entries.length) {
    throw new EnvError(`${name} lists the same secret twice`)
  }
  return Object.freeze(entries)
}

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  /**
   * The TESTNET database, when this deployment serves both networks. Empty means single-network —
   * `networkSql` then holds one handle and REFUSES a testnet request rather than answering it out
   * of mainnet rows (micro-deploy `docs/network-consolidation.md` §2.2).
   */
  readonly databaseUrlTestnet: string
  /**
   * The network to assume when a request carries no `CF-Network`, or empty to refuse. Set for
   * `pnpm dev`, which has no gateway. Never in production, where guessing makes a routing fault a
   * silent cross-network write.
   */
  readonly singleNetwork: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  /**
   * Names this replica in `jobs.locked_by`. Defaults to the hostname, which is the container id
   * under compose and the pod name under Kubernetes — in both cases the thing an operator would
   * search for after finding a stuck lease.
   */
  readonly instanceId: string
  /**
   * How long a decision is kept.
   *
   * 04-domain-model §10.4: "Retained for the dispute window." A decision is the input to a
   * dispute, so the floor here is the longest window in which a user can still open one. Two
   * years by default, and the lower bound below refuses a value that would delete the evidence
   * before the argument about it has started.
   */
  readonly decisionRetentionDays: number
  /**
   * How long a velocity counter bucket is kept after its window closed.
   *
   * Only long enough that a late-arriving decision inside a still-open window finds its bucket.
   * These rows are pruned aggressively because they are the highest-churn table in the service
   * and none of them is evidence of anything once the window has passed.
   */
  readonly counterRetentionHours: number
  /**
   * The secrets `POST /v1/events` accepts a delivery signature under, newest first.
   *
   * Empty is a supported state and is NOT "accept anything" — see `acceptSecretsFrom`. The route
   * answers 503 while it is empty, so the producer retries rather than the event being lost. Every
   * entry that IS present has cleared the estate's generated-secret shape check; absence is a
   * missing credential, not a missing guard.
   */
  readonly eventAcceptSecrets: readonly string[]
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

/**
 * Pure over its source so the failure paths are testable without mutating the process. The eager
 * export below is what makes the service fail fast.
 */
export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }
  return {
    port: integer(source, 'PORT', 4000, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'POLICY_DATABASE_URL'),
    databaseUrlTestnet: optional(source, 'POLICY_DATABASE_URL_TESTNET', ''),
    singleNetwork: optional(source, 'CF_NETWORK_SINGLE', ''),
    // A pool larger than the database's own connection budget divided by the replica count is a
    // service that exhausts Postgres for everything else the moment it scales.
    databasePoolMax: integer(source, 'POLICY_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),
    decisionRetentionDays: integer(source, 'POLICY_DECISION_RETENTION_DAYS', 730, 90, 3_650),
    counterRetentionHours: integer(source, 'POLICY_COUNTER_RETENTION_HOURS', 48, 2, 720),
    eventAcceptSecrets: acceptSecretsFrom(source),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed
 * through the telemetry package: nothing that can itself fail may sit between a configuration
 * error and the report of it. The message is the one `loadEnv` produced, which by construction
 * never contains a value.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
