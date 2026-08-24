/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent.
 *
 * ---------------------------------------------------------------------------------------------
 * **This service decides. It does not enforce.**
 *
 * There is no route here that blocks anything, holds anything or moves anything. `POST /decisions`
 * returns an opinion with reasons and obligations, and the caller is the one that acts on it.
 * AD-09 gives the reason: a decision service that also sits in the data path becomes a single
 * point of failure for every money movement in the estate. The moment a route here starts calling
 * wallet or custody, that property is gone and cannot be got back without a rewrite.
 *
 * The one thing this service does enforce is on itself: a freeze is set by one operator and
 * cleared by two, and `DELETE /freezes/:id` answering **202 rather than 200** on the first
 * operator's request is that control made visible in the protocol.
 * ---------------------------------------------------------------------------------------------
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import {
  ForbiddenError,
  TokenError,
  bearerFrom,
  isAdmin,
  requireAdmin,
  requireScope,
  statusFor,
  type Principal,
} from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql } from '@cloudsforge/db'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { ACTION_NAMES, isAction, type ActionName } from './actions.ts'
import { decide, type DecideDeps } from './decide.ts'
import { postgresSnapshotReader } from './store.ts'
import {
  BadCursorError,
  getDecision,
  listDecisionsForSubject,
  type StoredDecision,
} from './decisions.ts'
import {
  FreezeConflictError,
  applyFreeze,
  getFreeze,
  isAssetScope,
  listFreezes,
  requestClearance,
} from './freezes.ts'
import { RuleValidationError, parseAction, parseRuleDefinition, parseRuleKey } from './rules.ts'
import {
  IDENTITY_USER_DELETED,
  SUBSCRIBED_TOPICS,
  UUID,
  eraseUser,
  erasureInstant,
} from './erasure.ts'
import {
  EVENT_ID_HEADER,
  SIGNATURE_HEADER,
  verifyInboundDelivery,
  withInbox,
} from './inbox.ts'
import { disableRule, listRules, putRule, ruleHistory, trustAddress, type Db } from './store.ts'
import type { DecisionContext, DecisionRequest } from './evaluate.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  /**
   * The per-network SELECTOR, not a handle. Routes use `ctx.sql`; `NetworkSql` has no query
   * methods, so reaching for the process-wide handle does not compile.
   */
  readonly sql: NetworkSql
  /**
   * The network to assume when no `CF-Network` arrives, or `undefined` to refuse. `CF_NETWORK_SINGLE`,
   * for `pnpm dev`, which has no gateway in front of it. Never set in production.
   */
  readonly singleNetwork?: Network
  readonly decide: DecideDeps
  /**
   * The secrets `POST /v1/events` will accept a delivery signature under, newest first.
   *
   * Empty is a supported state and means "cannot verify yet", which the route answers 503 to. It
   * is not "accept anything": see `acceptSecretsFrom` in `env.ts` for why the deploy is allowed to
   * be behind, and why the alternative would let an unauthenticated caller erase any user.
   */
  readonly eventAcceptSecrets: readonly string[]
  readonly beforeScrape?: () => Promise<void>
}

/**
 * The scope, taken from `@cloudsforge/contracts-auth` rather than invented here.
 *
 * It is a string literal so this module does not import a contract package for one value; a test
 * asserts it is exactly the registry's, which is what stops a typo becoming a scope no token can
 * ever carry. contracts-auth describes it as: "Submit a decision request and receive allow, deny,
 * challenge or review."
 */
export const DECIDE_SCOPE = 'policy:decide'

const MAX_BODY_BYTES = 64 * 1024
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/
const DEFAULT_PAGE_SIZE = 50
const MAX_PAGE_SIZE = 200

/**
 * `user:<id>`, `service:<name>`, `operator:<id>` or `system` — the vocabulary of contracts-events,
 * so that a decision and the event it accompanies attribute a subject identically.
 */
const SUBJECT_PATTERN = /^(?:system|(?:user|service|operator):[A-Za-z0-9._:-]{1,128})$/

/**
 * Domain metrics, declared rather than inferred from a log line — AD-20.
 *
 * `policy_fail_open_total` and `policy_fail_closed_total` are the pair that makes AD-09's split
 * observable. The first is the alert: it must be zero, and a non-zero rate means decisions are
 * being handed out with nothing behind them. The second is not an alert but a symptom — a
 * non-zero rate there means custody exports and treasury spends are being refused, and somebody
 * is about to raise a ticket saying the platform is broken when in fact it is doing its job.
 */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'policy_decisions_total',
      help: 'Decisions, by action and verdict',
      kind: 'counter',
      labels: ['action', 'decision'],
    })
    .register({
      name: 'policy_fail_open_total',
      help: 'Decisions allowed because the rule store could not be read. Must be zero.',
      kind: 'counter',
      labels: ['action'],
    })
    .register({
      name: 'policy_fail_closed_total',
      help: 'Decisions denied because the rule store could not be read.',
      kind: 'counter',
      labels: ['action'],
    })
    .register({
      name: 'policy_evaluation_ms',
      help: 'Wall-clock time to reach a decision, including the rule store read',
      kind: 'histogram',
      labels: ['action'],
      buckets: [1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000],
    })
    .register({
      name: 'policy_freezes_active',
      help: 'Freezes currently in force. Sampled at scrape time.',
      kind: 'gauge',
      labels: [],
    })
}

/* ------------------------------------------------------------------ plumbing */

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
  /**
   * The network THIS REQUEST belongs to, from the `CF-Network` header the gateway stamped.
   *
   * Not a property of the process: one pod serves both estates since the network consolidation
   * (micro-deploy `docs/network-consolidation.md`), so "which network am I" has no answer.
   */
  readonly network: Network
  /**
   * The database handle for `network`, resolved ONCE, at the edge of the request.
   *
   * Every route uses this rather than reaching for the process-wide handle, because a wrong handle
   * is not an error — it is a query that SUCCEEDS against the other estate's rows and says nothing.
   * `deps.sql` is a `NetworkSql` with no query methods, so the mistake does not compile.
   */
  readonly sql: Db
}

/**
 * Routes that answer without belonging to a network.
 *
 * Kubelet probes the first two and Prometheus scrapes the third; none arrives through the gateway,
 * so none carries `CF-Network`. Refusing them makes every health probe a 500 and the pod never
 * becomes ready. Three literal paths rather than a prefix, because this is an exemption from a data
 * boundary; none of them queries the database.
 */
const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

interface Route {
  readonly method: string
  /** `/decisions/:id`. Used verbatim as the metric label, so cardinality is bounded. */
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

/**
 * Compile `/subjects/:subject/decisions` into a matcher. The segment pattern excludes `/` so a
 * parameter cannot swallow the rest of the path and make one route answer for another.
 */
function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':')
        ? `(?<${segment.slice(1)}>[^/]+)`
        : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    // Unmatched paths collapse to one label. Using the raw path would let any caller mint
    // unbounded time series and take the scrape target down with cardinality.
    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number, metricNetwork: string) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method,
        route: routeLabel,
        status: String(status),
        // One target now serves both estates, so the network has to be on the SERIES. Labelled
        // per target it would say nothing — micro-org#398 in a form nothing could recover.
        network: metricNetwork,
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method,
        route: routeLabel,
        network: metricNetwork,
      })
    }

    // ── THE NETWORK, THEN THE HANDLE, BEFORE ANY ROUTE RUNS ──────────────────────────────────
    //
    // `requestNetwork` REFUSES an unstamped request rather than assuming mainnet: a 500 is a
    // routing fault made loud, where a default is a cross-network write nothing would ever flag.
    //
    // The operational endpoints are exempt because kubelet and Prometheus do not come through the
    // gateway and never send the header. Refusing them makes the pod never become ready.
    const networkless = matched !== undefined && OPERATIONAL_ROUTES.has(matched.path)
    let network: Network
    try {
      network = networkless
        ? (deps.singleNetwork ?? deps.sql.networks[0] ?? 'mainnet')
        : requestNetwork(req.headers, deps.singleNetwork ? { fallback: deps.singleNetwork } : {})
    } catch (err) {
      log.error('request carries no usable network', {
        err: err instanceof NetworkUnknownError ? err.message : err,
      })
      send(
        res,
        errorReply(500, 'network_unknown', 'this request could not be attributed to a network', requestId),
        requestId,
      )
      finish(500, 'unknown')
      return
    }

    // ── RESOLVED INSIDE A TRY, AND THAT IS NOT DEFENSIVE PADDING ───────────────────────────────
    //
    // `deps.sql.for()` THROWS when this deployment holds no handle for that network, and that
    // refusal is the safety property the consolidation rests on — better a loud 500 than a query
    // answered out of the other estate's rows.
    //
    // It runs BEFORE `handle` returns a promise, so an uncaught throw escapes the `void` expression
    // past a `.catch` that is not attached yet, and the listener returns having sent NOTHING. The
    // connection then hangs until the client gives up: the one path the design most depends on
    // being loud was the one path that was silent.
    let sql: Db
    try {
      sql = deps.sql.for(network) as unknown as Db
    } catch (err) {
      log.error('no usable database handle for this request', { err, network })
      send(
        res,
        errorReply(500, 'network_unavailable', 'this deployment cannot serve that network', requestId),
        requestId,
      )
      finish(500, network)
      return
    }
    void handle(matched, { req, url, requestId, log, params, network, sql }, forRequest(deps, sql))
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status, network)
      })
      .catch((err: unknown) => {
        // Reaching here means the error mapping itself failed. Answer, then say so loudly.
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500, network)
      })
  })
}

/**
 * The deps a REQUEST sees: the process's deps with every database handle replaced by the one for
 * this request's network.
 *
 * `decide` is built once at boot and closes over a handle — and so does its snapshot reader, which
 * is the half that is easy to miss: rebuilding the object while leaving the reader pointed at the
 * other network would make every policy DECISION read the wrong estate while the writes went to the
 * right one. Both are rebuilt here.
 *
 * A plain immutable record, so this is a spread rather than a restructuring.
 */
function forRequest(deps: ServerDeps, sql: Db): ServerDeps {
  return { ...deps, decide: { ...deps.decide, sql, reader: postgresSnapshotReader(sql) } }
}

async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await route.handle(ctx, deps)
  } catch (err) {
    // `statusFor` is the whole point: it is the one place that decides what an auth failure means,
    // so five services cannot disagree about it again.
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      // Answering 401 here would sign every user in the estate out because identity is having a
      // bad minute. Five services in the estate currently disagree about this.
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof BadRequestError || err instanceof RuleValidationError || err instanceof BadCursorError) {
      return errorReply(400, 'bad_request', err.message, ctx.requestId)
    }
    if (err instanceof NotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    if (err instanceof FreezeConflictError) {
      return errorReply(409, 'freeze_conflict', err.message, ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  const routes: Array<Omit<Route, 'pattern'>> = [
    {
      method: 'GET',
      path: '/livez',
      /**
       * Static, deliberately. Liveness answers one question — should this process be killed and
       * restarted — and a liveness probe that consults a dependency restarts a healthy process
       * every time the database blinks. Readiness is where dependencies belong.
       */
      handle: async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async (_ctx, deps) => {
        const report = await deps.lifecycle.readyz()
        return { status: report.ready ? 200 : 503, body: report }
      },
    },
    {
      method: 'GET',
      path: '/metrics',
      handle: async (ctx, deps) => {
        try {
          await deps.beforeScrape?.()
        } catch (err) {
          // A gauge that could not be sampled is a stale gauge. Failing the scrape instead would
          // lose every other metric too, and blind the dashboard at the moment it is needed.
          ctx.log.warn('gauge refresh failed; serving the previous values', { err })
        }
        return {
          status: 200,
          text: deps.metrics.render(),
          contentType: 'text/plain; version=0.0.4; charset=utf-8',
        }
      },
    },

    /* ---------------------------------------------------------------- decisions */

    {
      method: 'POST',
      path: '/decisions',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        // A user token can never reach this route: `requireScope` is false for anything that is
        // not a service. Deciding on your own behalf is not a thing this service offers.
        requireScope(principal, DECIDE_SCOPE)

        const body = await readJson(ctx.req)
        const request = parseDecisionRequest(body, ctx.requestId)
        // Recorded as `service:<name>`, the same actor vocabulary contracts-events uses, so a
        // decision and the event it accompanies name the caller identically.
        const decision = await decide(deps.decide, request, operatorOf(principal))
        ctx.log.info('decision recorded', {
          decisionId: decision.id,
          action: decision.action,
          verdict: decision.decision,
          failOpen: decision.failOpen,
        })
        return { status: 201, body: { decision: toWire(decision) } }
      },
    },
    {
      method: 'GET',
      path: '/decisions/:id',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        const id = ctx.params['id'] ?? ''
        if (!isUuid(id)) throw new BadRequestError('id must be a uuid')
        const decision = await getDecision(deps.decide.sql, id)
        if (!decision) throw new NotFoundError(`no decision ${id}`)
        // A user may read a decision about themselves. That is not a courtesy: "why was I
        // blocked" is the question 04-domain-model §10.4 says must be answerable, and answering
        // it only to operators means the answer arrives through a support ticket or not at all.
        requireReadAccess(principal, decision.subject)
        return { status: 200, body: { decision: toWire(decision) } }
      },
    },
    {
      method: 'GET',
      path: '/subjects/:subject/decisions',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        const subject = decodeURIComponent(ctx.params['subject'] ?? '')
        if (!SUBJECT_PATTERN.test(subject)) throw new BadRequestError('subject is malformed')
        requireReadAccess(principal, subject)

        const limit = parseLimit(ctx.url.searchParams.get('limit'))
        const cursor = ctx.url.searchParams.get('cursor') ?? undefined
        const page = await listDecisionsForSubject(deps.decide.sql, subject, { limit, cursor })
        return {
          status: 200,
          body: {
            decisions: page.decisions.map(toWire),
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        }
      },
    },

    /* ---------------------------------------------------------------- rules (admin) */

    {
      method: 'GET',
      path: '/rules',
      handle: async (ctx, deps) => {
        requireAdmin(await authenticate(ctx, deps))
        const requested = ctx.url.searchParams.get('action')
        const action = requested === null ? undefined : parseAction(requested)
        const rules = await listRules(deps.decide.sql, action)
        return { status: 200, body: { rules, actions: ACTION_NAMES } }
      },
    },
    {
      method: 'POST',
      path: '/rules',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const body = await readJson(ctx.req)
        const key = parseRuleKey(body['key'])
        const action = parseAction(body['action'])
        const definition = parseRuleDefinition(body['definition'])
        const enabled = body['enabled'] === undefined ? true : body['enabled'] === true
        const note = typeof body['note'] === 'string' ? body['note'].slice(0, 500) : undefined
        const rule = await putRule(deps.decide.sql, {
          key,
          action,
          definition,
          enabled,
          createdBy: operatorOf(principal),
          note,
        })
        ctx.log.info('rule version written', { key: rule.key, version: rule.version, action })
        return { status: 201, body: { rule } }
      },
    },
    {
      method: 'GET',
      path: '/rules/:key',
      handle: async (ctx, deps) => {
        requireAdmin(await authenticate(ctx, deps))
        const key = parseRuleKey(ctx.params['key'])
        const versions = await ruleHistory(deps.decide.sql, key)
        if (versions.length === 0) throw new NotFoundError(`no rule ${key}`)
        // Every version, newest first. A decision cites `key@version` and this is where that
        // citation is resolved months later.
        return { status: 200, body: { key, versions } }
      },
    },
    {
      method: 'DELETE',
      path: '/rules/:key',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const key = parseRuleKey(ctx.params['key'])
        const rule = await disableRule(deps.decide.sql, key, operatorOf(principal))
        if (!rule) throw new NotFoundError(`no rule ${key}`)
        // 200 with the new version rather than 204: a delete here is an insert, and answering
        // "no content" would hide the fact that the history is still there.
        return { status: 200, body: { rule } }
      },
    },

    /* ---------------------------------------------------------------- trusted addresses (admin) */

    {
      method: 'POST',
      path: '/trusted-addresses',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const body = await readJson(ctx.req)
        const subject = parseSubject(body['subject'])
        const address = requireString(body['address'], 'address', 200)
        const chain = typeof body['chain'] === 'string' ? body['chain'].slice(0, 64) : ''
        const coolingOffSeconds =
          typeof body['coolingOffSeconds'] === 'number' && Number.isInteger(body['coolingOffSeconds'])
            ? body['coolingOffSeconds']
            : // SD-10: adding a trusted address is itself a 24-hour, notified operation. The
              // default is that period rather than zero, so forgetting the field is safe.
              86_400
        if (coolingOffSeconds < 0 || coolingOffSeconds > 2_592_000) {
          throw new BadRequestError('coolingOffSeconds must be between 0 and 2592000')
        }
        const created = await trustAddress(deps.decide.sql, {
          subject,
          chain,
          address,
          coolingOffSeconds,
          addedBy: operatorOf(principal),
        })
        return { status: 201, body: { trustedAddress: { ...created, subject, chain, address } } }
      },
    },

    /* ---------------------------------------------------------------- freezes (admin) */

    {
      method: 'POST',
      path: '/freezes',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const body = await readJson(ctx.req)
        const subject = parseSubject(body['subject'])
        const scope = parseScope(body['scope'])
        const reason = requireString(body['reason'], 'reason', 500)
        const freeze = await applyFreeze(deps.decide.sql, {
          subject,
          scope,
          reason,
          operator: operatorOf(principal),
        })
        ctx.log.warn('freeze applied', { freezeId: freeze.id, subject, scope, by: freeze.createdBy })
        return { status: 201, body: { freeze } }
      },
    },
    {
      method: 'GET',
      path: '/freezes/:id',
      handle: async (ctx, deps) => {
        requireAdmin(await authenticate(ctx, deps))
        const id = ctx.params['id'] ?? ''
        if (!isUuid(id)) throw new BadRequestError('id must be a uuid')
        const freeze = await getFreeze(deps.decide.sql, id)
        if (!freeze) throw new NotFoundError(`no freeze ${id}`)
        return { status: 200, body: { freeze } }
      },
    },
    {
      method: 'GET',
      path: '/subjects/:subject/freezes',
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        const subject = decodeURIComponent(ctx.params['subject'] ?? '')
        if (!SUBJECT_PATTERN.test(subject)) throw new BadRequestError('subject is malformed')
        requireReadAccess(principal, subject)
        return { status: 200, body: { freezes: await listFreezes(deps.decide.sql, subject) } }
      },
    },
    {
      method: 'DELETE',
      path: '/freezes/:id',
      /**
       * One operator cannot clear a freeze. **202 is the answer, not 200.**
       *
       * The status code carries the control: an operator who reads 202 knows their request was
       * recorded and that the freeze is still in force, and a client that treats 2xx as "done"
       * without reading the body is wrong in a way that is visible in an access log. Answering
       * 200 with `{cleared:false}` would make the difference invisible to everything except code
       * that already knew to look.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireAdmin(principal)
        const id = ctx.params['id'] ?? ''
        if (!isUuid(id)) throw new BadRequestError('id must be a uuid')
        const note = ctx.url.searchParams.get('note') ?? undefined
        const outcome = await requestClearance(deps.decide.sql, id, operatorOf(principal), note)
        if (!outcome) throw new NotFoundError(`no freeze ${id}`)

        if (outcome.status === 'pending') {
          ctx.log.warn('freeze clearance recorded, still frozen', {
            freezeId: id,
            by: operatorOf(principal),
            required: outcome.freeze.clearancesRequired,
          })
          return {
            status: 202,
            body: {
              status: 'pending',
              freeze: outcome.freeze,
              message: `a freeze is cleared by two distinct operators; ${outcome.freeze.clearancesRequired} more required`,
            },
          }
        }
        if (outcome.status === 'already_cleared') {
          return { status: 200, body: { status: 'already_cleared', freeze: outcome.freeze } }
        }
        ctx.log.warn('freeze cleared', { freezeId: id, operators: outcome.freeze.clearances.map((c) => c.operator) })
        return { status: 200, body: { status: 'cleared', freeze: outcome.freeze } }
      },
    },

    /* ---------------------------------------------------------------- events */
    {
      method: 'POST',
      path: '/v1/events',
      /**
       * The inbound event webhook — the first one this service has ever had, and the only
       * unauthenticated write surface on it.
       *
       * There is no bearer token here and there must not be: the MAC over the body IS the
       * credential, and it is checked over the RAW BYTES before anything is parsed. Parsing first
       * would put the JSON parser in front of the check; comparing byte-at-a-time would make the
       * MAC comparison a forgery oracle. `verifyInboundDelivery` does neither.
       *
       * **403, not 401, on a bad signature.** 401 means "authenticate and try again", which sends
       * a caller looking for a token this route does not have. The credential presented was wrong,
       * and 403 is the word for that.
       *
       * **202, not 4xx, on a topic this service does not consume.** The relay treats any non-2xx
       * as a delivery failure and retries, so 4xx-ing an event nobody is wrong about would pin the
       * producer in a retry loop for ever.
       */
      handle: async (ctx, deps) => {
        const raw = await readRaw(ctx.req)

        // Unconfigured is a 503, never an open door. The relay retries a 503, so the erasure is
        // queued and visible rather than lost — and it is loud in the producer's delivery-failure
        // view, which is where an operator will find out the deploy is missing a variable.
        if (deps.eventAcceptSecrets.length === 0) {
          ctx.log.error('an event was delivered but no accept secret is configured', {
            variable: 'OUTBOX_SIGNING_SECRET',
          })
          return errorReply(
            503,
            'events_unconfigured',
            'this service cannot verify event deliveries; retry',
            ctx.requestId,
          )
        }

        if (!verifyInboundDelivery(raw, headerOf(ctx.req, SIGNATURE_HEADER) ?? '', deps.eventAcceptSecrets)) {
          ctx.log.warn('event rejected: bad signature', { eventId: headerOf(ctx.req, EVENT_ID_HEADER) })
          return errorReply(403, 'bad_signature', 'the event signature did not verify', ctx.requestId)
        }

        let envelope: { id?: unknown; topic?: unknown; payload?: unknown }
        try {
          envelope = JSON.parse(raw) as typeof envelope
        } catch {
          return errorReply(400, 'bad_body', 'the event body is not valid JSON', ctx.requestId)
        }
        const topic = typeof envelope.topic === 'string' ? envelope.topic : ''
        const eventId = typeof envelope.id === 'string' ? envelope.id : ''
        if (!UUID.test(eventId)) {
          return errorReply(400, 'bad_envelope', 'the event id must be a uuid', ctx.requestId)
        }
        if (!SUBSCRIBED_TOPICS.has(topic)) return { status: 202, body: { status: 'ignored' } }

        const payload = (envelope.payload ?? {}) as Record<string, unknown>
        const userId = payload['userId']
        // A 400, and the relay will retry it for ever — which is correct. An erasure this service
        // cannot read is a person whose data is still here while the deletion is reported as done.
        if (typeof userId !== 'string' || !UUID.test(userId)) {
          return errorReply(
            400,
            'bad_payload',
            `${IDENTITY_USER_DELETED} requires a uuid userId`,
            ctx.requestId,
          )
        }

        const outcome = await withInbox(ctx.sql, topic, eventId, (tx) =>
          eraseUser(tx, userId, {
            eventId,
            tombstoneAt: erasureInstant(payload['tombstoneAt']),
          }),
        )
        // Counts and field names only. The subject is never logged: writing the identifier of the
        // person who asked to be forgotten into an aggregator with its own retention period would
        // recreate, elsewhere, exactly what this handler just deleted.
        ctx.log.info('erasure processed', {
          topic,
          eventId,
          outcome: outcome.status,
          ...(outcome.status === 'processed' ? outcome.value : {}),
        })
        return {
          status: 202,
          body: { status: outcome.status === 'duplicate' ? 'duplicate' : 'recorded' },
        }
      },
    },
  ]

  return routes.map((route) => ({ ...route, pattern: compile(route.path) }))
}

/* ------------------------------------------------------------------ authorisation */

async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than
  // being a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return deps.verifier.principal(token)
}

/**
 * Who may read a decision: an operator, a service holding `policy:decide`, or the subject.
 *
 * The subject clause is the one that matters. A blocked user asking why is the case
 * 04-domain-model §10.4 is written for, and if only operators can read the record then the record
 * is an internal audit log wearing a dispute process's clothes.
 */
function requireReadAccess(principal: Principal, subject: string): void {
  if (isAdmin(principal)) return
  if (principal.kind === 'service') {
    requireScope(principal, DECIDE_SCOPE)
    return
  }
  if (subject === `user:${principal.userId}`) return
  throw new ForbiddenError('the subject of the decision, or role:admin')
}

function operatorOf(principal: Principal): string {
  return principal.kind === 'user' ? `operator:${principal.userId}` : `service:${principal.service}`
}

/* ------------------------------------------------------------------ parsing */

function requireString(value: unknown, field: string, max: number): string {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > max) {
    throw new BadRequestError(`${field} must be a string of 1 to ${max} characters`)
  }
  return value.trim()
}

function parseSubject(value: unknown): string {
  if (typeof value !== 'string' || !SUBJECT_PATTERN.test(value)) {
    throw new BadRequestError('subject must be system, user:<id>, service:<name> or operator:<id>')
  }
  return value
}

function parseScope(value: unknown): string {
  if (value === undefined || value === null) return '*'
  if (typeof value !== 'string') throw new BadRequestError('scope must be a string')
  if (value === '*' || isAssetScope(value) || isAction(value)) return value
  // A scope that is neither the wildcard, an asset nor a registered action would freeze nothing
  // at all, and a freeze that covers nothing is worse than no freeze: it reads as protection.
  throw new BadRequestError(`scope must be "*", "asset:<CODE>" or one of: ${ACTION_NAMES.join(', ')}`)
}

/**
 * An unregistered action is a 400, never a guess.
 *
 * Defaulting it to fail-open would let a caller reach the unchecked path by misspelling
 * `custody.key.export`; defaulting it to fail-closed would mean a typo in a new caller silently
 * blocks a product. Neither is a decision anyone would make deliberately, so neither is offered —
 * see the header of `actions.ts`.
 */
function parseRequestAction(value: unknown): ActionName {
  if (typeof value !== 'string' || !isAction(value)) {
    throw new BadRequestError(`action must be one of: ${ACTION_NAMES.join(', ')}`)
  }
  return value
}

const DECIMAL_PATTERN = /^\d+(?:\.\d+)?$/

function parseContext(value: unknown): DecisionContext {
  if (value === undefined || value === null) return {}
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new BadRequestError('context must be a JSON object')
  }
  const record = value as Record<string, unknown>

  const amount = record['amount']
  if (amount !== undefined && (typeof amount !== 'string' || !DECIMAL_PATTERN.test(amount))) {
    // Rejected rather than coerced. An amount that arrives as a JSON number has already been
    // through a float by the time this code sees it, and a threshold comparison on a float is
    // the bug this service exists to not have.
    throw new BadRequestError('context.amount must be a non-negative decimal string')
  }
  const asset = record['asset']
  if (asset !== undefined && (typeof asset !== 'string' || !/^[A-Z][A-Z0-9:_-]{0,31}$/.test(asset))) {
    throw new BadRequestError('context.asset must be an upper-case asset code')
  }
  const recentFailures = record['recentFailures']
  if (
    recentFailures !== undefined &&
    (typeof recentFailures !== 'number' || !Number.isInteger(recentFailures) || recentFailures < 0)
  ) {
    throw new BadRequestError('context.recentFailures must be a non-negative whole number')
  }

  const flag = (name: 'newDevice' | 'countryChanged' | 'mfaSatisfied') => {
    const raw = record[name]
    if (raw !== undefined && typeof raw !== 'boolean') {
      throw new BadRequestError(`context.${name} must be a boolean`)
    }
    return raw as boolean | undefined
  }

  const destination = record['destination']
  if (destination !== undefined && (typeof destination !== 'string' || destination.length > 200)) {
    throw new BadRequestError('context.destination must be a string of at most 200 characters')
  }
  const chain = record['chain']
  if (chain !== undefined && (typeof chain !== 'string' || chain.length > 64)) {
    throw new BadRequestError('context.chain must be a string of at most 64 characters')
  }

  return {
    ...(amount !== undefined ? { amount: amount as string } : {}),
    ...(asset !== undefined ? { asset: asset as string } : {}),
    ...(destination !== undefined ? { destination: destination as string } : {}),
    ...(chain !== undefined ? { chain: chain as string } : {}),
    ...(flag('newDevice') !== undefined ? { newDevice: flag('newDevice') } : {}),
    ...(flag('countryChanged') !== undefined ? { countryChanged: flag('countryChanged') } : {}),
    ...(flag('mfaSatisfied') !== undefined ? { mfaSatisfied: flag('mfaSatisfied') } : {}),
    ...(recentFailures !== undefined ? { recentFailures: recentFailures as number } : {}),
  }
}

export function parseDecisionRequest(body: Record<string, unknown>, requestId: string): DecisionRequest {
  const correlationId = typeof body['correlationId'] === 'string' && body['correlationId'].length > 0
    ? body['correlationId'].slice(0, 128)
    : // Falling back to the request id keeps every decision joinable to the log line, the trace
      // and the Lantern issue even when a caller forgot to propagate one.
      requestId
  return {
    subject: parseSubject(body['subject']),
    action: parseRequestAction(body['action']),
    resourceUrn: requireString(body['resource'], 'resource', 500),
    context: parseContext(body['context']),
    correlationId,
  }
}

function parseLimit(raw: string | null): number {
  if (raw === null) return DEFAULT_PAGE_SIZE
  const value = Number(raw)
  if (!Number.isInteger(value) || value < 1 || value > MAX_PAGE_SIZE) {
    throw new BadRequestError(`limit must be a whole number between 1 and ${MAX_PAGE_SIZE}`)
  }
  return value
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value)
}

function toWire(decision: StoredDecision): Record<string, unknown> {
  return {
    id: decision.id,
    subject: decision.subject,
    action: decision.action,
    resource: decision.resourceUrn,
    decision: decision.decision,
    reasons: decision.reasons,
    obligations: decision.obligations,
    riskScore: decision.riskScore,
    ruleVersions: decision.ruleVersions,
    failOpen: decision.failOpen,
    correlationId: decision.correlationId,
    decidedFor: decision.decidedFor,
    evaluationMs: decision.evaluationMs,
    evaluatedAt: decision.evaluatedAt,
    context: decision.context,
  }
}

/* ------------------------------------------------------------------ transport */

/**
 * The body as the bytes that were sent, for the one route that verifies a MAC over them.
 *
 * Separate from `readJson` rather than a flag on it, because the property this needs is that
 * NOTHING has been parsed yet. A re-serialised body is a different byte string — a different key
 * order, a different number rendering — and the signature would fail against it for reasons that
 * look exactly like an attack.
 */
async function readRaw(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory exhaustion primitive that
    // any unauthenticated caller can reach.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  if (size === 0) return {}
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new BadRequestError('request body must be a JSON object')
    }
    return parsed as Record<string, unknown>
  } catch (err) {
    if (err instanceof BadRequestError) throw err
    throw new BadRequestError('request body is not valid JSON')
  }
}

/**
 * The error shape, identical on every failure and always carrying the request id.
 *
 * The id in the body rather than only in the header is what makes a support conversation work: a
 * user can read back what their browser showed them, and it joins to the log line, the trace and
 * the Lantern issue.
 */
function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // Health, metrics and decisions are all point-in-time facts. A cached decision is a decision
    // made against rules that have since changed.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}
