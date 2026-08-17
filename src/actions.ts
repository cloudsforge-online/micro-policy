/**
 * The action registry, and the fail-closed / fail-open split.
 *
 * This is the most important file in the service and the one most likely to be got wrong by
 * someone extending it, so the reasoning is here rather than in a document nobody will open.
 *
 * ## What "fail" means
 *
 * A decision is computed from a snapshot of rule data. Reading that snapshot is a database query
 * and a database query can fail. The question this file answers is the only one that matters when
 * it does: **what should policy say when it cannot decide?**
 *
 * There are exactly two honest answers and both of them are wrong some of the time. Denying
 * everything turns one unavailable table into an estate-wide outage — nobody can sign in, nobody
 * can trade, nobody can withdraw. Allowing everything turns one unavailable table into an
 * unguarded window during which a private key can be exported. AD-09 resolves this by refusing to
 * pick one globally: **fail closed on a narrow, named set of actions, and fail open with an alert
 * on everything else.**
 *
 * ## Why the split lives in code and not in the rules table
 *
 * Because the split is consulted precisely when the rules table cannot be read. A fail mode
 * stored as a row is a fail mode that is unavailable at the exact moment it is needed, and the
 * code would then need a fallback for the fallback — which is this table, minus the audit trail.
 *
 * The same argument applies to the withdrawal threshold in `closedAtOrAbove` below. It is a
 * constant here *and* a rule in the store: the rule is what governs an ordinary evaluation and
 * can be tuned without a deploy, and the constant is the floor that survives the store being
 * gone. They are different numbers for a reason — the constant is deliberately conservative.
 *
 * ## Why the registry is closed
 *
 * An action that is not registered is a 400, not a guess. Defaulting an unknown action to open
 * would let a caller reach the fail-open path by misspelling `custody.key.export`; defaulting it
 * to closed would mean a typo in a new caller silently blocks a product. Neither is a decision
 * anyone would choose deliberately, so neither is available.
 *
 * The four fail-closed actions are AD-09's, restated by SD-10's control table, and
 * `FAIL_CLOSED_ACTIONS` below is derived from this registry rather than written out again. A test
 * asserts the derived set equals those four literally, so adding a fifth or losing one is a red
 * build rather than a review someone was tired during.
 */

/**
 * What to answer when the rule snapshot could not be read.
 *
 *   * `closed` — deny, always. The action is dangerous enough that being unable to check is
 *     itself a reason to refuse.
 *   * `open` — allow, and raise an alert. The rule was advisory (a rate limit, a soft cap) and
 *     enforcing it is worth less than the availability of the product behind it.
 *   * `closed_at_or_above` — deny when the request's declared value reaches the floor, allow with
 *     an alert below it. This is the shape AD-09 names for withdrawals: a small withdrawal is a
 *     soft cap, a large one is money leaving custody unchecked.
 */
export type FailMode =
  | { readonly kind: 'closed' }
  | { readonly kind: 'open' }
  | {
      readonly kind: 'closed_at_or_above'
      /**
       * Per-asset floors, as decimal strings in the asset's display unit.
       *
       * An asset absent from this table is refused rather than defaulted. A withdrawal in an
       * asset whose floor nobody has set is a withdrawal nobody has thought about, and the
       * conservative reading of "we cannot check" is the correct one for money leaving.
       */
      readonly floors: Readonly<Record<string, string>>
    }

export interface ActionSpec {
  readonly description: string
  readonly failMode: FailMode
  /**
   * Whether an allowed decision consumes velocity budget for this action.
   *
   * Only actions with a rate worth limiting. A counter for an action nobody limits is a write
   * per request that nothing ever reads.
   */
  readonly counted: boolean
}

/**
 * Every action policy will decide on. Frozen, and the only place an action name is spelled.
 *
 * The names mirror the owning service's own vocabulary (`custody.key.export` is custody's key
 * export) so that a caller does not have to translate, and so a decision row read months later
 * says what happened without a lookup table.
 */
export const ACTIONS = Object.freeze({
  'custody.key.export': Object.freeze({
    description: 'A private key leaves the platform. Irreversible, and the wallet is self-custodied after it.',
    // AD-09 names this first for a reason: it is the only action in the estate with no undo.
    failMode: Object.freeze({ kind: 'closed' }),
    counted: true,
  }),
  'wallet.withdrawal': Object.freeze({
    description: 'Money leaves custody to an address the user named.',
    failMode: Object.freeze({
      kind: 'closed_at_or_above',
      // Conservative on purpose. These are not the operational limits — those are rules, tunable
      // without a deploy — they are the values below which an unchecked withdrawal is an
      // acceptable loss and above which it is not.
      floors: Object.freeze({ SHARD: '1000', EMBER: '100', ETH: '0.05', BTC: '0.002', XRP: '50' }),
    }),
    counted: true,
  }),
  'ledger.treasury_spend': Object.freeze({
    description: 'A spend from a platform treasury account rather than a user account.',
    failMode: Object.freeze({ kind: 'closed' }),
    counted: true,
  }),
  'identity.session.new_device': Object.freeze({
    description: 'A sign-in from a device this account has not been seen on before.',
    // Fail-closed here denies a sign-in, which is an availability cost paid knowingly: a new
    // device is the first step of every account takeover in the estate's incident history, and
    // an unchecked one is the step that makes the rest possible.
    failMode: Object.freeze({ kind: 'closed' }),
    counted: true,
  }),

  // ---- everything below fails open, with an alert ------------------------------------------
  //
  // Each of these is a control whose whole value is statistical. Blocking one request because a
  // table was briefly unreadable buys nothing; blocking every request does real damage.

  'wallet.deposit_address.assign': Object.freeze({
    description: 'Assign a fresh deposit address. Capped per user on young chains.',
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'wallet.trusted_address.add': Object.freeze({
    description: 'Add an address to the trusted list. Itself a 24-hour, notified operation.',
    // Deliberately open even though SD-10 marks it closed as a *control*: the cooling-off timer
    // is what makes it safe, and the timer is applied by the caller on the obligation this
    // service returns. An unchecked add still cannot shorten a timer that has not started.
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'market.listing.create': Object.freeze({
    description: 'List an item for sale. Rate limited to keep a scripted flood off the feed.',
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'trade.order.place': Object.freeze({
    description: 'Place an order. Soft per-window caps only.',
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'mint.deploy.request': Object.freeze({
    description: 'Deploy a contract, paying gas from the platform deployer.',
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'agora.post.create': Object.freeze({
    description: 'Publish to the Agora. Soft per-window caps that keep a scripted flood off the square.',
    // Open on purpose. The Agora already refuses an unreadable request on its own hourly counter,
    // so a policy outage costs a second opinion, not the only one — and a square that goes silent
    // because a table blinked is a worse failure than a burst nobody throttled.
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'identity.password.reset': Object.freeze({
    description: 'Request a password reset email. Rate limited per subject and per address.',
    failMode: Object.freeze({ kind: 'open' }),
    counted: true,
  }),
  'api.request': Object.freeze({
    description: 'A developer API call. Pure rate limiting.',
    failMode: Object.freeze({ kind: 'open' }),
    // Not counted: the API gateway does its own per-key accounting at a volume this table would
    // not survive, and a counter nobody reads is a write per request.
    counted: false,
  }),
} as const satisfies Readonly<Record<string, ActionSpec>>)

export type ActionName = keyof typeof ACTIONS

export const ACTION_NAMES: readonly ActionName[] = Object.freeze(
  Object.keys(ACTIONS) as ActionName[],
)

export function isAction(value: string): value is ActionName {
  return Object.hasOwn(ACTIONS, value)
}

export function actionSpec(action: ActionName): ActionSpec {
  return ACTIONS[action]
}

/**
 * The actions that deny when policy cannot decide. **Derived, never written out.**
 *
 * `closed_at_or_above` counts as fail-closed because there exists a request on that action which
 * a store failure denies. Calling it "open" because small withdrawals pass would be exactly the
 * drift this file exists to prevent.
 */
export const FAIL_CLOSED_ACTIONS: readonly ActionName[] = Object.freeze(
  ACTION_NAMES.filter((name) => ACTIONS[name].failMode.kind !== 'open'),
)

export const FAIL_OPEN_ACTIONS: readonly ActionName[] = Object.freeze(
  ACTION_NAMES.filter((name) => ACTIONS[name].failMode.kind === 'open'),
)

/**
 * A decimal comparison that does not go through a float.
 *
 * `0.1 + 0.2` is the reason. A threshold that decides whether a withdrawal is checked must not be
 * evaluated in binary floating point, where two strings that look equal can compare unequal and
 * a value one wei under a floor can round to it. Both sides are split on the point and compared
 * as integers, with the fractional parts padded to a common length.
 *
 * Returns `null` for anything that is not a plain non-negative decimal, which the caller must
 * treat as undecidable rather than as zero.
 */
export function compareDecimal(left: string, right: string): number | null {
  const pattern = /^\d+(?:\.\d+)?$/
  if (!pattern.test(left) || !pattern.test(right)) return null
  const [leftWhole = '0', leftFraction = ''] = left.split('.')
  const [rightWhole = '0', rightFraction = ''] = right.split('.')
  const width = Math.max(leftFraction.length, rightFraction.length)
  const leftScaled = BigInt(leftWhole + leftFraction.padEnd(width, '0'))
  const rightScaled = BigInt(rightWhole + rightFraction.padEnd(width, '0'))
  return leftScaled === rightScaled ? 0 : leftScaled > rightScaled ? 1 : -1
}

/** What the fail path needs to know about a request. Never the whole request: see `failSafe`. */
export interface FailSafeInput {
  readonly action: ActionName
  /** The decimal amount the request declared, if it declared one. */
  readonly amount?: string | undefined
  readonly asset?: string | undefined
}

export interface FailSafeOutcome {
  /** `false` means deny. `true` means allow, and the caller must alert. */
  readonly allow: boolean
  readonly reason: string
}

/**
 * What to answer when the rule snapshot could not be read.
 *
 * A total function over the registry, taking only the fields a fail-safe may legitimately depend
 * on. It cannot consult the store — that is the situation it exists for — so it also cannot be
 * accidentally written to, which is why it takes `FailSafeInput` rather than the decision
 * request: a future edit that reached for a rule here would not compile.
 */
export function failSafe(input: FailSafeInput): FailSafeOutcome {
  // Annotated rather than inferred. `as const satisfies` keeps the registry's literal key types,
  // which is what makes `ActionName` a closed union — but it also narrows `floors` to the exact
  // asset codes written above, and an asset that is not one of them must be reachable here so it
  // can be refused rather than rejected by the compiler.
  const mode: FailMode = ACTIONS[input.action].failMode
  if (mode.kind === 'closed') {
    return { allow: false, reason: `rule_store_unavailable_and_${input.action}_fails_closed` }
  }
  if (mode.kind === 'open') {
    return { allow: true, reason: `rule_store_unavailable_and_${input.action}_fails_open` }
  }

  const asset = input.asset
  const amount = input.amount
  if (asset === undefined || amount === undefined) {
    // A withdrawal that did not say how much, of what, cannot be judged against a floor. The
    // request is malformed for this action and the conservative reading is the only one.
    return { allow: false, reason: 'rule_store_unavailable_and_the_request_declared_no_amount' }
  }
  const floor = mode.floors[asset]
  if (floor === undefined) {
    return { allow: false, reason: `rule_store_unavailable_and_no_fail_safe_floor_for_${asset}` }
  }
  const comparison = compareDecimal(amount, floor)
  if (comparison === null) {
    return { allow: false, reason: 'rule_store_unavailable_and_the_declared_amount_is_not_a_decimal' }
  }
  if (comparison >= 0) {
    return { allow: false, reason: `rule_store_unavailable_and_${amount}_${asset}_is_at_or_above_the_fail_safe_floor` }
  }
  return { allow: true, reason: `rule_store_unavailable_and_${amount}_${asset}_is_below_the_fail_safe_floor` }
}
