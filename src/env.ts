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
 */

import { hostname } from 'node:os'

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

const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'dev-secret',
  'dev-outbox-signing-secret',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

/**
 * The secrets `POST /v1/events` will accept a delivery signature under.
 *
 * ── WHY THIS IS OPTIONAL, AND WHAT THE ROUTE DOES WHEN IT IS EMPTY ─────────────────────────────
 *
 * Every other variable in this file is required, because rule 9's discipline is that a service
 * refuses to start rather than serve half-configured. This one is not, and the reason is a fact
 * about the deploy rather than a preference: policy's compose block has never carried an
 * `env_file` with the outbox secrets in it, because until now policy neither signed nor verified
 * anything. Making it required would turn the erasure fix into a service that will not boot on the
 * live estate — a bigger outage than the gap it closes, on a service every money route consults.
 *
 * Unconfigured is NOT silently tolerated. `POST /v1/events` answers **503** when this list is
 * empty: the relay treats that as a delivery failure and retries, so the event is not lost, it is
 * queued and visible in the producer's delivery-failure view until somebody sets the variable. The
 * alternative — verifying against nothing, or accepting unsigned deliveries — would make an
 * unauthenticated caller able to erase any user by uuid.
 *
 * A list rather than a string so the estate's shared key can be rotated one service at a time.
 */
function acceptSecretsFrom(source: Source): readonly string[] {
  const raw = (source['OUTBOX_ACCEPT_SECRETS'] ?? source['OUTBOX_SIGNING_SECRET'] ?? '').trim()
  if (raw.length === 0) return Object.freeze([])
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  for (const entry of entries) {
    // A placeholder or a short key is a configured secret that is worse than an absent one: it
    // makes the route look guarded. Refused at boot, where it is attributable.
    if (PLACEHOLDERS.has(entry.toLowerCase())) {
      throw new EnvError('OUTBOX_ACCEPT_SECRETS contains a known placeholder — generate real secrets')
    }
    if (entry.length < 24) {
      throw new EnvError('OUTBOX_ACCEPT_SECRETS entries must each be at least 24 characters')
    }
  }
  if (new Set(entries).size !== entries.length) {
    throw new EnvError('OUTBOX_ACCEPT_SECRETS lists the same secret twice')
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
   * answers 503 while it is empty, so the producer retries rather than the event being lost.
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
