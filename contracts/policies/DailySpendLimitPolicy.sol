// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title DailySpendLimitPolicy
/// @notice Caps how much of ONE asset ONE tenant may withdraw through ONE vault
///         contract during any TRAILING 24-hour interval.
///
/// @dev  =======================================================================
///       TIME SEMANTICS: A TRUE ROLLING 24-HOUR LEDGER. READ THIS FIRST.
///       =======================================================================
///
///       THE INVARIANT. For an armed subject `S` at every instant `T`:
///
///           sum{ a : (t, a) admitted for S, t > T - WINDOW }  <=  limit(S)
///
///       It is enough to test this at admission: between admissions the left-hand side
///       only ever falls, because entries age out and none are added.
///
///       THE EXACT BOUNDARY. An entry booked at `t` is counted while `block.timestamp <
///       t + WINDOW` and expires at EXACTLY `t + WINDOW`. The live set is the half-open
///       interval `(T - WINDOW, T]`. This is the same `>=` instant the previous
///       tumbling window used for its reset, kept deliberately so the boundary did not
///       move under existing operators while its MEANING changed.
///
///       HOW. {check} appends `(block.timestamp, amount)` to a per-subject ring and
///       maintains the running total incrementally; expiry is a prefix scan from the
///       oldest entry that stops at the first live one. Nothing resets: allowance
///       returns in the same increments it was consumed, at the instants the individual
///       spends age out. See {_liveAt}, which is the single definition of "live" shared
///       by admission and every getter.
///
///       =======================================================================
///       LEDGER CAPACITY: WHY A CAP IS UNAVOIDABLE, AND WHAT IT COSTS.
///       =======================================================================
///
///       To know exactly how much allowance expires at each future instant, the
///       contract must retain the TIMING of live spends. Bounded storage holds at most
///       {MAX_ACTIVE_ENTRIES} `(time, amount)` pairs, so a history needing more entries
///       than that cannot be represented exactly. EXACT AND BOUNDED THEREFORE IMPLIES A
///       CAP — the only open choice is what to do at the cap:
///
///       - REFUSE the admission (chosen). Accounting stays exact; a subject already
///         holding {MAX_ACTIVE_ENTRIES} LIVE ENTRIES is refused any spend that would
///         need a new one, with reason "daily spend ledger full".
///       - MERGE the two oldest entries at the newer timestamp (rejected). Never
///         admits above `limit`, but holds old spend on the books LONGER than the true
///         trailing window, so the cap would be conservative rather than exact. This
///         contract would then be claiming a guarantee it does not implement.
///
///       THE REFUSAL IS SELF-HEALING AND NOT ATTACKER-REACHABLE. A slot frees the
///       instant the oldest entry expires, so a full ledger is never a permanent brick;
///       and entries can only be appended by a caller the subject's own owner delegated
///       via {setAdmitter}, so no third party can fill it.
///
///       THE CAP COUNTS ENTRIES, NOT DISTINCT SECONDS. Admissions sharing a timestamp
///       coalesce into one entry ONLY while their combined amount stays representable
///       in the entry's packed `uint192` — see {MAX_BOOKABLE_AMOUNT}. Above that the
///       booking appends a SECOND entry at the same instant, which is equally exact
///       (entries sharing a timestamp expire together) but consumes another slot. So a
///       same-timestamp burst usually costs one slot and, at `uint192`-scale amounts no
///       real asset reaches, may cost more than one. {activeEntryCount} reports the
///       actual occupancy for exactly this reason, and a capacity refusal carries its
///       own reason string so it is never mistaken for a limit refusal.
///
///       BOUNDED WORK. Admission and every getter scan at most {MAX_ACTIVE_ENTRIES}
///       entries, a CONSTANT that does not grow with lifetime withdrawal count. Each
///       entry is dropped exactly once, so amortized cost per admission is O(1).
///
///       =======================================================================
///       WHAT THIS CAP DOES NOT COVER.
///       =======================================================================
///
///       WHILE DISARMED, NOTHING IS RECORDED. `limit == 0` means unrestricted, and
///       {check} returns before booking, so spends made while disarmed never reach the
///       ledger and are not retroactively counted when a limit is armed again. The
///       guarantee above therefore binds over intervals in which the subject has been
///       CONTINUOUSLY ARMED. This is not a way to launder history — {setDailyLimit}
///       does not touch the ledger, so a disarm/re-arm cycle leaves existing entries
///       intact and expiring on their original schedule — but a subject that is
///       genuinely unrestricted for a period has no accounting for that period.
///
///       That matters because {setDailyLimit} is keyed on `msg.sender`, so whoever
///       controls the owner address can disarm outright. Where the vault owner and its
///       withdrawal signer are the same key — the common case — a compromised signer
///       could already remove the cap entirely. That is a property of the
///       configuration authority, unchanged by rolling accounting, and it is the reason
///       this cap is a damage LIMITER rather than a containment boundary.
///
///       ADMISSION, NOT SETTLEMENT. Spend is booked when a withdrawal is ADMITTED, and
///       expires a WINDOW after that instant. For a queued large transaction that is
///       queue time, not finalize time, so a large-transaction delay longer than
///       {WINDOW} releases the allowance before the payment settles. Settlement is
///       admission plus a per-withdrawal delay fixed at queue time, so settled outflow
///       inherits the admitted spacing rather than compressing it.
///
///       =======================================================================
///       SCOPE SEMANTICS: ACCOUNTING IS KEYED BY THE FULL POLICY SUBJECT.
///       =======================================================================
///
///       Every piece of per-bucket state — the limit, the spend ledger and its running
///       total, the delegation list and its count — hangs off a single {subjectKey}:
///       `keccak256(abi.encode(consumer, owner, asset))`. The ledger lives INSIDE the
///       same {SpendState} struct as the limit, so there is no second mapping that
///       could be reached with a different key.
///
///       WHY ALL THREE DIMENSIONS. This module is a QUANTITY ACCUMULATOR over a finite
///       budget, and a quantity accumulator is never identity-agnostic:
///
///       - Without `consumer`, two vault contracts serving the same tenant draw from
///         one ledger, so a spend in vault A denies vault B and A's entries dictate
///         when B's allowance returns. Behind a shared {CompositePolicyEngine} that
///         collapse used to be unavoidable, which is why the previous release
///         documented a workaround of one dedicated policy instance per consumer.
///         Ledger CAPACITY is per subject for the same reason: a shared ring would let
///         one busy tenant deny every other tenant of the same vault.
///       - Without `asset`, `amount` values in different denominations add into one
///         scalar — 1 ETH (1e18 wei) and 1 mUSDC (1e6 base units) are incomparable
///         magnitudes, so a limit meaningful for one is nonsense for the other.
///
///       Contrast {RecipientAllowlistPolicy} and {SanctionsListPolicy}: those are
///       ADDRESS PREDICATES, idempotent and budget-free, so they reuse safely across
///       consumers and assets and are deliberately NOT subject-keyed.
///
///       AGGREGATE EXPOSURE CHANGES, ON PURPOSE. Because buckets are independent, a
///       tenant who arms `limit` for N distinct subjects can spend up to `N * limit`
///       per trailing 24 hours in total. The previous owner-keyed model capped the tenant at
///       ONE `limit` across everything. That aggregate cap was not a feature being
///       given up cheaply — it was inseparable from the interference defect, since the
///       only reason vault A could constrain vault B's total was that they shared the
///       bucket. Non-interference and aggregate capping cannot both come from a single
///       per-subject counter; a cross-subject cap, if ever wanted, is a separate
///       mechanism and is NOT provided here. Arm only the subjects you intend, and
///       size each limit knowing the others exist.
///
///       =======================================================================
///       IDENTITY VERSUS AUTHORITY. These are two different questions.
///       =======================================================================
///
///       IDENTITY — "which bucket is being referenced" — is answered entirely by the
///       {PolicySubject} argument. An argument cannot authorize anything, so the
///       subject NEVER by itself permits a mutation.
///
///       AUTHORITY — "who may mutate that bucket" — is answered from `msg.sender`
///       against {setAdmitter}, a delegation that only the bucket's own `owner` can
///       write because the setter forces `msg.sender` into the subject's owner slot.
///       The delegation is keyed by the FULL subject, so authority granted for one
///       (consumer, owner, asset) confers nothing for any other: an admitter trusted
///       to book spend originating at vault X cannot present a subject naming vault Y
///       and book there.
///
///       The delegation is BY ADDRESS, so it is sound only if every hop between the
///       vault and this module is itself caller-bound. {CompositePolicyEngine} carries
///       the matching gates for that reason — an admission-caller registry AND a
///       binding of `subject.consumer` to its authenticated caller — without which a
///       composite would be a deputy for exactly the substitution this module refuses.
///
///       SHARED COMPOSITES ARE NOW MECHANICALLY SAFE FOR THIS MODULE. Because the
///       subject survives the composite unchanged, one {CompositePolicyEngine} may
///       serve several consumers without merging their spend state. The previous
///       release's convention — a dedicated policy instance per (consumer, asset), and
///       never a composite shared across consumers — is no longer required to keep
///       accounting separate.
///
///       This contract has NO owner and no admin: every authority IN IT is held by the
///       tenant whose accounting is at stake.
///
///       WHAT A COMPOSITE OWNER CAN AND CANNOT DO. Delegation is transitive, so
///       delegating to a {CompositePolicyEngine} inherits that composite's
///       access-control policy — its owner chooses which consumers may invoke it.
///       Before subject propagation that let the composite owner register an arbitrary
///       relay and burn the delegating tenant's allowance. IT NO LONGER DOES.
///       {CompositePolicyEngine.check} requires `subject.consumer == msg.sender`, so a
///       relay can only ever present a subject naming ITSELF as consumer, and therefore
///       can only ever reach a bucket keyed to the relay — a bucket no tenant arms. The
///       tenant's own bucket names their VAULT as consumer and is reachable only by
///       that vault.
///
///       What remains to the composite owner is DENIAL, not consumption: they can add
///       an always-denying module and block the tenant's withdrawals outright. That
///       power is unescapable within the composition and strictly stronger than the
///       allowance burn ever was, so the operational advice is unchanged — delegate to
///       a composite only where its owner is already trusted for the liveness of that
///       composition. But it touches no accounting: spend never moves, no allowance is
///       manufactured, no other subject is affected, and settlement of an
///       already-queued withdrawal is unaffected. The tenant's unilateral escape from
///       the ACCOUNTING side remains `setDailyLimit(consumer, asset, 0)`.
///
///       Both halves are pinned: C7 asserts the burn is impossible, C7b asserts the
///       denial power survives, in test/DailySpendAdmissionAuthority.test.ts.
///
///       Spending is recorded at {check} time — for large-tx withdrawals this is at
///       queue time, not finalize time, which is intentional and conservative. If the
///       outer transaction reverts after {check} (e.g. TransferFailed), all state
///       including the spend record is rolled back automatically.
///
///       A limit of 0 means unrestricted (default). Set a non-zero limit to enable.
contract DailySpendLimitPolicy is IPolicyEngine {
    uint256 public constant WINDOW = 24 hours;

    /// @notice How many LIVE LEDGER ENTRIES one subject may hold inside the trailing
    ///         window at once.
    /// @dev Entries, NOT distinct seconds: admissions sharing a timestamp normally
    ///      coalesce into one entry, but only while their combined amount fits the
    ///      packed `uint192` (see {MAX_BOOKABLE_AMOUNT}), so an exceptionally large
    ///      same-timestamp total occupies more than one slot. Read {activeEntryCount}
    ///      rather than counting spends.
    ///
    ///      THE PRICE OF BEING BOTH EXACT AND BOUNDED — see the LEDGER CAPACITY section
    ///      of the contract-level documentation for why some such cap is unavoidable.
    ///      A power of two so the ring index is a mask rather than a division.
    uint256 public constant MAX_ACTIVE_ENTRIES = 32;

    /// @dev `MAX_ACTIVE_ENTRIES - 1`. Ring arithmetic uses `& _RING_MASK`, which is
    ///      equivalent to `% MAX_ACTIVE_ENTRIES` only because the capacity is a power
    ///      of two; changing one without the other silently corrupts indexing.
    uint256 private constant _RING_MASK = MAX_ACTIVE_ENTRIES - 1;

    /// @notice The largest single amount this policy can book, `type(uint192).max`.
    /// @dev A ledger entry packs its timestamp and amount into ONE storage slot, which
    ///      is what keeps a prune step at one SLOAD per expired entry. That costs 64
    ///      bits of amount range. The ceiling is ~6.28e57 base units — twenty-four
    ///      orders of magnitude beyond the total supply of any real asset — and
    ///      exceeding it is a clean DENIAL, never a silent truncation and never the
    ///      arithmetic panic the previous accumulator produced near `type(uint256).max`.
    ///      The `limit` itself is deliberately NOT capped: an owner reaching for
    ///      "effectively unlimited" may still set `type(uint256).max`.
    uint256 public constant MAX_BOOKABLE_AMOUNT = type(uint192).max;

    /// @notice How long a weakening (raising a nonzero limit, or disarming to zero)
    ///         must wait between being proposed and being eligible to apply.
    /// @dev Matches the vault's own `POLICY_ENGINE_UPDATE_DELAY` / governance-style
    ///      2-day reaction window; deliberately NOT configurable in this version — a
    ///      configurable delay would itself be an ordered governance object with
    ///      recursive weakening semantics, for no present value.
    uint256 public constant POLICY_CONTROL_DELAY = 2 days;

    /// @notice How long a MATURED weakening remains applicable before it expires.
    /// @dev A matured proposal that never expires would defeat its own timelock — an
    ///      attacker could pre-arm a weakening at a quiet moment and pay zero friction
    ///      at the moment of use. Matches the vault's own governance grace-period
    ///      pairing (2-day delay / 14-day grace).
    uint256 public constant POLICY_CONTROL_GRACE_PERIOD = 14 days;

    /// @notice The one contract permitted to hold `controller` for any subject.
    /// @dev Immutable, set at construction. This is the entirety of L9's provenance
    ///      constraint: {bridgeEnrollController} accepts a `controller` argument only
    ///      when it equals this address, so an attacker who compromises a `vaultOwner`
    ///      key cannot install an arbitrary contract as controller and have it survive
    ///      recovery — the policy structurally cannot be told to trust anything else.
    ///      A bridge upgrade requires a NEW policy instance naming the new bridge here;
    ///      state never migrates (L7).
    address public immutable POLICY_CONTROL_BRIDGE;

    /// @notice `policyControlBridge` was the zero address at construction.
    error ZeroPolicyControlBridge();
    /// @notice `policyControlBridge` was an EOA at construction — an EOA supplied here
    ///         would be able to call every `bridge*` function directly as the trusted
    ///         controller, bypassing PolicyControlBridge's signatures, epoch checks,
    ///         nonce checks, and pause entirely. A malicious CONTRACT deliberately
    ///         installed here is still possible — deployment integrity remains a trust
    ///         assumption this check cannot remove — but this closes the accidental
    ///         zero/EOA case that would silently drop the whole authentication boundary.
    error PolicyControlBridgeNotAContract(address policyControlBridge);

    constructor(address policyControlBridge) {
        if (policyControlBridge == address(0)) revert ZeroPolicyControlBridge();
        if (policyControlBridge.code.length == 0) revert PolicyControlBridgeNotAContract(policyControlBridge);
        POLICY_CONTROL_BRIDGE = policyControlBridge;
    }

    /// @notice One admitted spend: how much, and when it was booked.
    /// @dev Packed into a single 256-bit slot (`uint64` + `uint192`). `uint64` seconds
    ///      overflows in the year 584942417355, so the cast in {check} cannot truncate
    ///      any timestamp this chain will produce.
    struct Entry {
        uint64 at;
        uint192 amount;
    }

    /// @notice All per-subject accounting, gathered into one struct so a single
    ///         {subjectKey} resolves the whole bucket.
    /// @dev One mapping of contiguous slots rather than parallel mappings: the fields
    ///      are always read and written together, and co-locating them makes it
    ///      structurally impossible for one field to be keyed differently from another
    ///      — the exact split-identity defect that keying `limit` by owner while keying
    ///      the spend ledger by subject would have introduced. The ring lives INSIDE
    ///      this struct for the same reason: there is no second mapping that could be
    ///      reached with a different key.
    struct SpendState {
        /// @dev Max spend per trailing window, denominated in the subject's asset.
        ///      0 = unrestricted.
        uint256 limit;
        /// @dev How many admitters this subject's owner has delegated to. Lets
        ///      {setDailyLimit} refuse to arm a limit that no caller could satisfy.
        uint256 admitterCount;
        /// @dev Sum of the ring entries that were live AS OF THE LAST WRITE. Storage
        ///      cannot change without a transaction, so this is a raw figure that lags
        ///      expiry; every read path recomputes through {_liveAt} instead of
        ///      trusting it. Maintained incrementally so admission never has to sum the
        ///      whole ring.
        uint256 rollingSpent;
        /// @dev Ring index of the OLDEST live entry.
        uint32 head;
        /// @dev Number of live entries, `0 <= count <= MAX_ACTIVE_ENTRIES`.
        uint32 count;
        /// @dev The spend ledger. Entries are appended at `(head + count) & _RING_MASK`
        ///      and expire from `head`, so they are always in non-decreasing timestamp
        ///      order — which is what makes expiry a prefix scan that stops at the
        ///      first live entry rather than a search.
        Entry[MAX_ACTIVE_ENTRIES] ring;
        /// @dev address(0): Path 1 (owner-direct) is available. Any other value: ONLY
        ///      that address (always {POLICY_CONTROL_BRIDGE} once set — see
        ///      {bridgeEnrollController}) may strengthen, propose, apply, or cancel for
        ///      this subject. Path 1 has ZERO capability while this is set.
        ///      {bridgeApplyUnenrollController} returns this to address(0), which
        ///      RE-ENABLES Path 1 (design doc §6.2) — unlike {controllerInitialized},
        ///      this field is NOT sticky.
        address controller;
        /// @dev Sticky one-time flag: set on the FIRST successful enrolment and never
        ///      cleared again, including by unenrolment. Gates ONLY the one-time
        ///      {bridgeEnrollController} bootstrap (O3) — once true, THIS policy
        ///      instance can never be bootstrapped into controller mode again, even
        ///      after a later unenrolment returns {controller} to address(0) and Path 1
        ///      to availability. A tenant wanting controller-mode protection again
        ///      after a deliberate unenrolment needs a NEW policy instance (L7, design
        ///      doc §6.1) — this field is what makes that a hard architectural boundary
        ///      rather than a one-transaction reset.
        bool controllerInitialized;
        /// @dev The one pending weakening-CLASS transition a subject may hold at a
        ///      time — a limit change (either path) or a controller removal (bridge
        ///      only, T15; see {PendingWeakening.isUnenrollment}) — created by
        ///      WHICHEVER path currently has authority. `boundEpoch` is meaningful only
        ///      for a bridge-created proposal; Path 1 leaves it at its zero default and
        ///      Path 1's own apply/cancel never consult it, matching the design doc's
        ///      "no epoch to bind" characterization of the direct-user model (§9.7).
        PendingWeakening pending;
    }

    /// @dev See {SpendState.pending}. A separate `exists` flag rather than inferring
    ///      presence from `validAfter == 0`, so a genuine (if degenerate) proposal
    ///      timestamped at the Unix epoch is never confused with "no proposal".
    struct PendingWeakening {
        /// @dev Meaningless when {isUnenrollment} is true — an unenrolment carries no
        ///      limit payload; it only ever clears {SpendState.controller}.
        uint256 newLimit;
        uint64 validAfter;
        uint64 expiresAt;
        uint64 boundEpoch;
        bool exists;
        /// @dev Discriminates the ONE pending-transition slot a subject may hold: a
        ///      limit change (false) or a controller removal (true, T15) — both are
        ///      "weakenings" sharing one delay/grace/epoch pipeline, so a subject can
        ///      never hold a pending limit change AND a pending unenrolment at once.
        ///      {_applyWeakening} branches on this; {bridgeApplyWeakening} and
        ///      {bridgeApplyUnenrollController} each refuse to complete the OTHER kind
        ///      (WrongTransitionKind), so a signed intent for one action can never be
        ///      used to finish the other.
        bool isUnenrollment;
    }

    mapping(bytes32 => SpendState) private _state;

    /// @dev _admitter[subjectKey][caller] — `caller` may book admission spend for that
    ///      exact subject. Written ONLY by a transaction whose msg.sender occupies the
    ///      subject's `owner` slot, so the delegation can never be forged by a third
    ///      party and can never be widened to a subject the writer does not own.
    mapping(bytes32 => mapping(address => bool)) private _admitter;

    event DailyLimitSet(
        bytes32 indexed subjectKey,
        address indexed consumer,
        address indexed owner,
        address asset,
        uint256 limit
    );
    event AdmitterSet(
        bytes32 indexed subjectKey,
        address indexed owner,
        address indexed admitter,
        address consumer,
        address asset,
        bool allowed
    );

    /// @notice `caller` is not an admitter delegated for THIS subject.
    error UnauthorizedAdmitter(address caller, address consumer, address owner, address asset);
    /// @notice Refuses to arm a limit before any admitter exists (would brick the owner).
    error NoAdmitterConfigured(address consumer, address owner, address asset);
    /// @notice Refuses to remove the last admitter while a limit is armed.
    error LastAdmitterWhileArmed(address consumer, address owner, address asset);
    /// @notice A delegated admitter other than the subject's owner must be a contract.
    error AdmitterNotAContract(address admitter);
    error ZeroAdmitter();
    /// @notice A subject with no originating consumer can never be produced by a vault.
    error ZeroConsumer();

    event ControllerEnrolled(
        bytes32 indexed subjectKey,
        address indexed consumer,
        address indexed owner,
        address asset
    );
    event WeakeningProposed(bytes32 indexed subjectKey, uint256 newLimit, uint256 validAfter, uint256 expiresAt);
    event WeakeningApplied(bytes32 indexed subjectKey, uint256 newLimit);
    event WeakeningCancelled(bytes32 indexed subjectKey);
    /// @notice A controller removal (T15) was proposed — delayed, expiring, epoch-bound,
    ///         exactly like a limit weakening (design doc §6.2).
    event UnenrollmentProposed(bytes32 indexed subjectKey, uint256 validAfter, uint256 expiresAt);
    /// @notice A matured, epoch-fresh unenrolment completed: {SpendState.controller} is
    ///         back to address(0) and Path 1 is available again for this subject.
    ///         {SpendState.controllerInitialized} is UNCHANGED — still true forever.
    event ControllerUnenrolled(
        bytes32 indexed subjectKey,
        address indexed consumer,
        address indexed owner,
        address asset
    );

    /// @notice Path 1 (owner-direct) was used while a controller is currently active
    ///         for this subject ({SpendState.controller} != address(0)).
    error ControllerPathRequired(address consumer, address owner, address asset);
    /// @notice {bridgeEnrollController} was reached by anyone but {POLICY_CONTROL_BRIDGE},
    ///         or asked to install a controller other than {POLICY_CONTROL_BRIDGE} itself.
    error NotCanonicalBridge(address attempted);
    /// @notice {bridgeEnrollController} was called on a subject that has EVER completed
    ///         the one-time bootstrap — {SpendState.controllerInitialized} is sticky and
    ///         permanent, so this reverts even after a later unenrolment (O3, design doc
    ///         §6.1: a fresh policy instance is required instead of a re-bootstrap).
    error AlreadyEnrolled(address consumer, address owner, address asset);
    /// @notice A weakening was proposed while one is already pending for this subject.
    error WeakeningAlreadyPending(address consumer, address owner, address asset);
    /// @notice apply/cancelWeakening called with no pending weakening for this subject.
    error NoWeakeningPending(address consumer, address owner, address asset);
    /// @notice applyWeakening called before `pending.validAfter`.
    error WeakeningNotReady(address consumer, address owner, address asset, uint256 validAfter);
    /// @notice applyWeakening called at or after `pending.expiresAt`.
    error WeakeningExpired(address consumer, address owner, address asset, uint256 expiresAt);
    /// @notice `bridgeStrengthenLimit` was asked to perform a WEAKENING, or
    ///         `bridgeProposeWeakening` was asked to perform something that is not
    ///         actually a weakening. The bridge signs a DISTINCT typehash per action
    ///         precisely so a signed intent cannot be silently reinterpreted as the
    ///         other kind of transition (design doc §5.2) — this is that guarantee
    ///         enforced at the policy, one layer past signature verification.
    error WrongTransitionKind(address consumer, address owner, address asset);
    /// @notice A bridge-created proposal's `boundEpoch` no longer matches the epoch the
    ///         bridge asserts is current — the vault's credential authority changed
    ///         after this proposal was made (design doc §5.4, T8). Unconditional: no
    ///         exception for the current legitimate owner choosing to apply an
    ///         old-epoch proposal — a fresh proposal costs one transaction.
    error StaleControlEpoch(address consumer, address owner, address asset, uint64 expected, uint64 provided);
    /// @notice `setDailyLimit`/`bridgeStrengthenLimit` was called with the subject's
    ///         CURRENT limit — neither strengthening nor weakening (design doc §3: the
    ///         `0→0`/`n→n` row is classified "Rejected", not silently accepted).
    error NoOpTransition(address consumer, address owner, address asset);

    // -------------------------------------------------------------------------
    // Subject keying
    // -------------------------------------------------------------------------

    /// @notice The canonical storage key for a {PolicySubject}.
    /// @dev THE ONLY PLACE A KEY IS CONSTRUCTED. Every setter, getter and the admission
    ///      path route through {_subjectKey}, so no two call paths can disagree about
    ///      which bucket a subject names.
    ///
    ///      `abi.encode`, never `abi.encodePacked`. All three fields are fixed-width
    ///      addresses, so packing would in fact be unambiguous TODAY — but the
    ///      collision-safety of the key would then rest on a property of the field
    ///      TYPES rather than of the encoding, and would silently break the first time
    ///      a variable-width field (a bytes id, a string tag) is added to
    ///      {PolicySubject}. `abi.encode` pads every field to 32 bytes and stays
    ///      injective under that change.
    /// @param subject The (consumer, owner, asset) triple to key.
    /// @return The bucket identifier used by every mapping in this contract.
    function subjectKey(PolicySubject calldata subject) external pure returns (bytes32) {
        return _subjectKey(subject.consumer, subject.owner, subject.asset);
    }

    /// @dev See {subjectKey}. Field ORDER is part of the contract: (consumer, owner,
    ///      asset). Permuting the arguments at any call site would silently address a
    ///      different bucket, which is why no caller builds this expression inline.
    function _subjectKey(address consumer, address owner, address asset) internal pure returns (bytes32) {
        return keccak256(abi.encode(consumer, owner, asset));
    }

    // -------------------------------------------------------------------------
    // Configuration — the caller is always the subject's owner
    // -------------------------------------------------------------------------

    /// @notice Sets the caller's spend limit for one (consumer, asset) pair.
    /// @dev The caller IS the subject's owner: `msg.sender` is forced into the owner
    ///      slot of the key, so this can only ever configure a bucket the caller owns.
    ///
    ///      Arming a non-zero limit requires at least one admitter FOR THIS SUBJECT, so
    ///      the failure surfaces here — on the configuration transaction — instead of
    ///      later, as an unexplained revert on the owner's next withdrawal. Disarming
    ///      (`limit == 0`) is deliberately exempt: the documented escape hatch must
    ///      never be blocked.
    ///
    ///      A zero `consumer` is rejected because no vault can ever mint a subject
    ///      naming address(0) as its originator, so such a bucket would be permanently
    ///      unreachable and would give the owner a false sense of being capped. A zero
    ///      `asset` is NOT rejected and must not be: address(0) is the canonical
    ///      identifier for native ETH, i.e. exactly what {WalletWallVault} mints.
    /// @param consumer The vault contract whose withdrawals this limit governs.
    /// @param asset    address(0) for native ETH, else the ERC-20 token address.
    /// @param limit    Max spend per window in that asset's base units. 0 = unrestricted.
    ///
    /// @dev POLICY-CONTROL AUTHORITY (v0.13.0). Strength is an ORDER, not a numeric
    ///      comparison — 0 is the MOST permissive value, not the least. See
    ///      {_isWeakening}. STRENGTHENING (0->n, or n->smaller) applies immediately,
    ///      exactly as before. WEAKENING (n->larger, or n->0) no longer applies here at
    ///      all: it creates a {PendingWeakening} that matures after
    ///      {POLICY_CONTROL_DELAY} and must be separately applied via
    ///      {applyWeakening} — see docs/Policy_Control_Authority_Design.md §3-4.
    ///
    ///      Reverts {ControllerPathRequired} while a controller is currently active for
    ///      this subject ({SpendState.controller} != address(0)) — Path 1 returns once
    ///      that controller is unenrolled (design doc §6.2), though a subject that has
    ///      EVER enrolled can never re-enrol on THIS policy instance
    ///      ({SpendState.controllerInitialized}, O3).
    function setDailyLimit(address consumer, address asset, uint256 limit) external {
        if (consumer == address(0)) revert ZeroConsumer();

        bytes32 key = _subjectKey(consumer, msg.sender, asset);
        SpendState storage s = _state[key];
        if (s.controller != address(0)) revert ControllerPathRequired(consumer, msg.sender, asset);
        if (limit == s.limit) revert NoOpTransition(consumer, msg.sender, asset);

        if (_isWeakening(s.limit, limit)) {
            _proposeWeakening(s, key, consumer, msg.sender, asset, limit, 0, false);
            return;
        }

        if (limit != 0 && s.admitterCount == 0) revert NoAdmitterConfigured(consumer, msg.sender, asset);
        s.limit = limit;
        emit DailyLimitSet(key, consumer, msg.sender, asset, limit);
    }

    /// @notice Applies a matured Path-1 weakening for the caller's own subject.
    /// @dev Path 1 only — reverts once the subject has ever enrolled a controller.
    function applyWeakening(address consumer, address asset) external {
        bytes32 key = _subjectKey(consumer, msg.sender, asset);
        SpendState storage s = _state[key];
        if (s.controller != address(0)) revert ControllerPathRequired(consumer, msg.sender, asset);
        _applyWeakening(s, key, consumer, msg.sender, asset);
    }

    /// @notice Cancels a pending Path-1 weakening for the caller's own subject,
    ///         immediately — cancelling only ever moves toward MORE restriction.
    /// @dev Path 1 only — reverts once the subject has ever enrolled a controller (O2:
    ///      a compromised owner key must not retain a permanent policy-administration
    ///      DoS lever over a subject it can no longer otherwise touch).
    function cancelWeakening(address consumer, address asset) external {
        bytes32 key = _subjectKey(consumer, msg.sender, asset);
        SpendState storage s = _state[key];
        if (s.controller != address(0)) revert ControllerPathRequired(consumer, msg.sender, asset);
        if (!s.pending.exists) revert NoWeakeningPending(consumer, msg.sender, asset);
        delete s.pending;
        emit WeakeningCancelled(key);
    }

    /// @dev Strength as an explicit permissiveness ORDER: 0 is TOP (most permissive).
    ///      `0 -> n` and `n -> smaller` are strengthening; `n -> larger` and `n -> 0`
    ///      are weakening. Deliberately NOT `newLimit > oldLimit` — that inverts at both
    ///      extremes and would delay first-time arming from an unrestricted subject.
    function _isWeakening(uint256 oldLimit, uint256 newLimit) private pure returns (bool) {
        if (newLimit == oldLimit) return false;
        if (newLimit == 0) return oldLimit != 0; // n -> 0, n != 0: disarming is weakening
        if (oldLimit == 0) return false; // 0 -> n: arming is strengthening
        return newLimit > oldLimit;
    }

    /// @dev Shared by Path 1 ({setDailyLimit}) and Path 2 ({bridgeProposeWeakening}).
    ///      `boundEpoch` is 0 for Path 1 — see {SpendState.pending}.
    function _proposeWeakening(
        SpendState storage s,
        bytes32 key,
        address consumer,
        address owner,
        address asset,
        uint256 newLimit,
        uint64 boundEpoch,
        bool isUnenrollment
    ) private {
        if (s.pending.exists) revert WeakeningAlreadyPending(consumer, owner, asset);
        uint64 validAfter = uint64(block.timestamp + POLICY_CONTROL_DELAY);
        uint64 expiresAt = uint64(block.timestamp + POLICY_CONTROL_DELAY + POLICY_CONTROL_GRACE_PERIOD);
        s.pending = PendingWeakening({
            newLimit: newLimit,
            validAfter: validAfter,
            expiresAt: expiresAt,
            boundEpoch: boundEpoch,
            exists: true,
            isUnenrollment: isUnenrollment
        });
        if (isUnenrollment) {
            emit UnenrollmentProposed(key, validAfter, expiresAt);
        } else {
            emit WeakeningProposed(key, newLimit, validAfter, expiresAt);
        }
    }

    /// @dev Shared by Path 1 ({applyWeakening}), which never binds an epoch, and Path 2
    ///      ({bridgeApplyWeakening}, {bridgeApplyUnenrollController}). This function
    ///      itself performs NO epoch check — but each Path-2 caller performs ONE before
    ///      reaching here, and it is deliberately a DIFFERENT check from the bridge's
    ///      own, not a duplicate of it: {PolicyControlBridge._verifyAndConsume} proves
    ///      the SIGNED INTENT is fresh (rejects a stale-epoch signature); the caller
    ///      here (one layer above this function) separately compares the STORED
    ///      proposal's own `boundEpoch` against the epoch the bridge asserts is current
    ///      (rejects a proposal that matured under a since-superseded epoch, even when
    ///      applied with a brand-new, validly-signed intent — see D2, which mutation-
    ///      tests that this second check is not redundant with the first).
    function _applyWeakening(
        SpendState storage s,
        bytes32 key,
        address consumer,
        address owner,
        address asset
    ) private {
        PendingWeakening memory p = s.pending;
        if (!p.exists) revert NoWeakeningPending(consumer, owner, asset);
        if (block.timestamp < p.validAfter) revert WeakeningNotReady(consumer, owner, asset, p.validAfter);
        if (block.timestamp >= p.expiresAt) revert WeakeningExpired(consumer, owner, asset, p.expiresAt);

        delete s.pending;
        if (p.isUnenrollment) {
            s.controller = address(0);
            emit ControllerUnenrolled(key, consumer, owner, asset);
        } else {
            s.limit = p.newLimit;
            emit WeakeningApplied(key, p.newLimit);
        }
    }

    /// @notice Delegates (or revokes) authority to book admission spend for ONE subject
    ///         owned by the caller.
    /// @dev The caller IS the subject's owner, so `_admitter[key(consumer, msg.sender,
    ///      asset)][caller]` is the only write this can perform: it introduces no new
    ///      principal, no contract owner, and — critically — no authority over any
    ///      subject the caller does not own.
    ///
    ///      SCOPE IS PER SUBJECT, NOT PER OWNER. Authorizing a composite engine for
    ///      (vault X, ETH) grants it nothing for (vault Y, ETH) or for (vault X, USDC).
    ///      Delegating broadly therefore takes as many explicit transactions as there
    ///      are buckets, which is the intended friction: cross-consumer authority is
    ///      never acquired as a side effect of a single grant.
    ///
    ///      A delegate other than the owner itself must have code: an EOA admitter
    ///      could burn the subject's allowance at will, which is the very defect this
    ///      gate closes. Self-delegation is permitted and harmless — subject owner and
    ///      delegate coincide, so it grants nobody else anything, and it keeps
    ///      standalone/direct use available.
    /// @param consumer The vault contract this delegation is scoped to.
    /// @param asset    address(0) for native ETH, else the ERC-20 token address.
    /// @param caller   The address permitted to call {check} for that subject.
    /// @param allowed  True to delegate, false to revoke.
    function setAdmitter(address consumer, address asset, address caller, bool allowed) external {
        if (consumer == address(0)) revert ZeroConsumer();
        if (caller == address(0)) revert ZeroAdmitter();
        if (allowed && caller != msg.sender && caller.code.length == 0) {
            revert AdmitterNotAContract(caller);
        }

        bytes32 key = _subjectKey(consumer, msg.sender, asset);
        SpendState storage s = _state[key];
        if (s.controller != address(0)) revert ControllerPathRequired(consumer, msg.sender, asset);

        bool previous = _admitter[key][caller];
        if (previous == allowed) return; // idempotent — keeps admitterCount exact

        if (!allowed && s.admitterCount == 1 && s.limit != 0) {
            revert LastAdmitterWhileArmed(consumer, msg.sender, asset);
        }

        _admitter[key][caller] = allowed;
        s.admitterCount = allowed ? s.admitterCount + 1 : s.admitterCount - 1;
        emit AdmitterSet(key, msg.sender, caller, consumer, asset, allowed);
    }

    // -------------------------------------------------------------------------
    // Path 2 — bridge-only. Callable ONLY by {POLICY_CONTROL_BRIDGE}, which has
    // already authenticated the subject owner's CURRENT credentials (and, for every
    // action but enrolment, the subject's CURRENT policyControlEpoch) before calling
    // here. This contract performs NO further authentication of its own beyond
    // confirming `msg.sender == POLICY_CONTROL_BRIDGE` — that confirmation, plus the
    // bridge's own signature/epoch checks one layer up, is the complete authority
    // chain. See docs/Policy_Control_Authority_Design.md §5-§6.
    // -------------------------------------------------------------------------

    modifier onlyCanonicalBridge() {
        if (msg.sender != POLICY_CONTROL_BRIDGE) revert NotCanonicalBridge(msg.sender);
        _;
    }

    /// @notice The one-time, immediate `PRISTINE -> canonical bridge` enrolment (U2).
    /// @dev `controller` must equal {POLICY_CONTROL_BRIDGE} — checked here independently
    ///      of the `onlyCanonicalBridge` gate on `msg.sender`, as the doc's own
    ///      belt-and-suspenders provenance constraint (L9, T14): the value being
    ///      installed is checked, not merely the caller installing it.
    ///
    ///      PRECONDITION IS `controllerInitialized == false` (O3), NOT `controller ==
    ///      address(0)` — the latter would let {bridgeApplyUnenrollController} reopen
    ///      this one-time bootstrap after a deliberate unenrolment, silently inventing a
    ///      reset-to-PRISTINE path the design doc never approved (M11's defect class,
    ///      generalized from "gated on limit==0" to "gated on a resettable field"). A
    ///      subject that has ever enrolled can never re-enrol on THIS policy instance —
    ///      a fresh policy instance is the only way back into controller mode (§6.1).
    function bridgeEnrollController(
        address consumer,
        address owner,
        address asset,
        address controller
    ) external onlyCanonicalBridge {
        if (controller != POLICY_CONTROL_BRIDGE) revert NotCanonicalBridge(controller);

        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        if (s.controllerInitialized) revert AlreadyEnrolled(consumer, owner, asset);

        s.controller = controller;
        s.controllerInitialized = true;
        emit ControllerEnrolled(key, consumer, owner, asset);
    }

    /// @notice Bridge-path strengthening: immediate, authenticated one layer up.
    /// @dev Reverts {ControllerPathRequired} if this subject has no active controller —
    ///      the bridge itself would never be `msg.sender` of a legitimate call
    ///      otherwise, but the explicit check keeps the invariant enforced here too,
    ///      not only implied by the bridge's own dispatch.
    function bridgeStrengthenLimit(
        address consumer,
        address owner,
        address asset,
        uint256 newLimit
    ) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        if (newLimit == s.limit) revert NoOpTransition(consumer, owner, asset);
        if (_isWeakening(s.limit, newLimit)) revert WrongTransitionKind(consumer, owner, asset);

        if (newLimit != 0 && s.admitterCount == 0) revert NoAdmitterConfigured(consumer, owner, asset);
        s.limit = newLimit;
        emit DailyLimitSet(key, consumer, owner, asset, newLimit);
    }

    /// @notice Bridge-path weakening proposal, bound to the epoch the bridge already
    ///         verified this call's signed intent against.
    function bridgeProposeWeakening(
        address consumer,
        address owner,
        address asset,
        uint256 newLimit,
        uint64 epoch
    ) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        if (!_isWeakening(s.limit, newLimit)) revert WrongTransitionKind(consumer, owner, asset);

        _proposeWeakening(s, key, consumer, owner, asset, newLimit, epoch, false);
    }

    /// @notice Bridge-path weakening application. Requires a fresh signed intent bound
    ///         to the CURRENT epoch (design doc §5.5) — the bridge has already verified
    ///         this before calling here; this function additionally re-checks the
    ///         PROPOSAL's own `boundEpoch` against what the bridge asserts is current.
    ///         Refuses to complete a pending UNENROLMENT (WrongTransitionKind) — a
    ///         signed apply-weakening intent authorizes only a limit change.
    function bridgeApplyWeakening(
        address consumer,
        address owner,
        address asset,
        uint64 epoch
    ) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        if (s.pending.exists && s.pending.isUnenrollment) revert WrongTransitionKind(consumer, owner, asset);
        if (s.pending.exists && s.pending.boundEpoch != epoch) {
            revert StaleControlEpoch(consumer, owner, asset, epoch, s.pending.boundEpoch);
        }
        _applyWeakening(s, key, consumer, owner, asset);
    }

    /// @notice Bridge-path cancellation, immediate — strengthening-ward, so no epoch
    ///         check is required beyond the bridge's own current-credential proof.
    ///         Cancels WHICHEVER kind is pending: cancelling a proposed removal keeps
    ///         the controller active, exactly as strengthening-ward as cancelling a
    ///         proposed limit increase, so no kind check is needed here (unlike apply).
    function bridgeCancelWeakening(address consumer, address owner, address asset) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        if (!s.pending.exists) revert NoWeakeningPending(consumer, owner, asset);
        delete s.pending;
        emit WeakeningCancelled(key);
    }

    /// @notice Bridge-path controller-removal proposal (T15) — a WEAKENING: delayed,
    ///         expiring, epoch-bound, exactly like a limit weakening (design doc §6.2).
    ///         Shares {SpendState.pending} with limit weakenings, so a subject cannot
    ///         hold a pending limit change and a pending unenrolment simultaneously.
    function bridgeProposeUnenrollController(
        address consumer,
        address owner,
        address asset,
        uint64 epoch
    ) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        _proposeWeakening(s, key, consumer, owner, asset, 0, epoch, true);
    }

    /// @notice Bridge-path controller-removal application. Requires a fresh signed
    ///         intent bound to the CURRENT epoch, exactly like {bridgeApplyWeakening} —
    ///         including the same second, POLICY-level re-check of the stored
    ///         proposal's own `boundEpoch` (§9.10: an attacker's pre-recovery proposed
    ///         removal must not survive a recovery that happens before it matures).
    ///         Refuses to complete a pending LIMIT weakening (WrongTransitionKind) — a
    ///         signed apply-unenrol intent authorizes only a controller removal.
    function bridgeApplyUnenrollController(
        address consumer,
        address owner,
        address asset,
        uint64 epoch
    ) external onlyCanonicalBridge {
        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);
        if (s.pending.exists && !s.pending.isUnenrollment) revert WrongTransitionKind(consumer, owner, asset);
        if (s.pending.exists && s.pending.boundEpoch != epoch) {
            revert StaleControlEpoch(consumer, owner, asset, epoch, s.pending.boundEpoch);
        }
        _applyWeakening(s, key, consumer, owner, asset);
    }

    /// @notice Bridge-path admitter repair (L5): immediate, no delay, regardless of
    ///         controller state — adding an admitter confers no capability an existing
    ///         admitter did not already have, so it is a liveness action, not a
    ///         weakening. Available via the bridge once controller-active, since Path 1
    ///         has zero capability at that point.
    function bridgeSetAdmitter(
        address consumer,
        address owner,
        address asset,
        address caller,
        bool allowed
    ) external onlyCanonicalBridge {
        if (caller == address(0)) revert ZeroAdmitter();
        // Self-exemption mirrors Path 1's `caller != msg.sender` exactly, with `owner`
        // (the authenticated tenant) standing in for msg.sender — NOT the bridge, which
        // is never itself a meaningful "self" for this check.
        if (allowed && caller != owner && caller.code.length == 0) revert AdmitterNotAContract(caller);

        bytes32 key = _subjectKey(consumer, owner, asset);
        SpendState storage s = _state[key];
        _requireControllerActive(s, consumer, owner, asset);

        bool previous = _admitter[key][caller];
        if (previous == allowed) return;
        if (!allowed && s.admitterCount == 1 && s.limit != 0) revert LastAdmitterWhileArmed(consumer, owner, asset);

        _admitter[key][caller] = allowed;
        s.admitterCount = allowed ? s.admitterCount + 1 : s.admitterCount - 1;
        emit AdmitterSet(key, owner, caller, consumer, asset, allowed);
    }

    function _requireControllerActive(
        SpendState storage s,
        address consumer,
        address owner,
        address asset
    ) private view {
        if (s.controller == address(0)) revert ControllerPathRequired(consumer, owner, asset);
    }

    // -------------------------------------------------------------------------
    // IPolicyEngine
    // -------------------------------------------------------------------------

    /// @inheritdoc IPolicyEngine
    /// @dev Selects the bucket by the FULL subject, then authorizes the mutation from
    ///      `msg.sender`. Those two steps are independent on purpose: the subject says
    ///      WHICH accounting is referenced and can never say WHO may move it.
    function check(
        PolicySubject calldata subject,
        address,
        uint256 amount,
        uint256
    ) external override returns (bool allowed, string memory reason) {
        bytes32 key = _subjectKey(subject.consumer, subject.owner, subject.asset);
        SpendState storage s = _state[key];

        uint256 limit = s.limit;
        if (limit == 0) return (true, "");

        // AUTHORITY BEFORE POLICY. Derived from msg.sender; the subject only selects
        // which delegation list is consulted. Reverting (rather than returning a denial)
        // keeps a misconfiguration distinguishable from a policy decision — the vaults do
        // not wrap this call in try/catch, so the error reaches the caller intact.
        //
        // Placed AFTER the `limit == 0` return so the gate constrains exactly the armed
        // set — which is exactly the attackable set, since an unarmed subject returns
        // above without touching spend storage. Owners who never armed a limit need no
        // configuration and cannot be locked out by this ordering.
        //
        // Placed BEFORE the ledger reads so an unauthorized caller can never append an
        // entry, advance an index or plant a spend total. Under a ring that is a
        // stronger requirement than it was under a single accumulator: appending also
        // consumes one of a subject's MAX_ACTIVE_ENTRIES slots, so an unauthorized
        // append would be a capacity attack as well as an accounting one.
        if (!_admitter[key][msg.sender]) {
            revert UnauthorizedAdmitter(msg.sender, subject.consumer, subject.owner, subject.asset);
        }

        uint256 nowTs = block.timestamp;
        uint256 storedCount = s.count;

        // Expire everything that has aged out of the trailing window. Computed into
        // locals: a DENIED request must leave storage untouched, exactly as the
        // previous accumulator's reset did.
        (uint256 head, uint256 count, uint256 spent) = _liveAt(s, nowTs);

        // Above `MAX_BOOKABLE_AMOUNT` the entry could not be represented, so refuse it
        // rather than truncate. Ordered BEFORE the limit test so the reason string
        // names the real cause even when the amount would also breach the limit.
        if (amount > MAX_BOOKABLE_AMOUNT) {
            return (false, "amount exceeds bookable range");
        }

        // THE ROLLING INVARIANT. `spent` is the exact total admitted for this subject
        // over `(nowTs - WINDOW, nowTs]`, so admitting `amount` keeps that total at or
        // below `limit`. Cannot overflow: `spent <= MAX_ACTIVE_ENTRIES *
        // MAX_BOOKABLE_AMOUNT < 2**197` and `amount <= 2**192`.
        if (spent + amount > limit) {
            return (false, "daily limit exceeded");
        }

        if (amount != 0) {
            // Same-second admissions coalesce into the newest entry. This is exact —
            // they share an expiry instant, so one entry of `a + b` at `t` decays
            // identically to two of `a` and `b` at `t` — and it keeps a burst of
            // withdrawals inside one block from consuming the ledger.
            // `count == 0` is handled first: `head + count - 1` would underflow, and an
            // empty ledger has no entry to coalesce into.
            uint256 newest = count == 0 ? 0 : (head + count - 1) & _RING_MASK;
            bool coalesce =
                count != 0 &&
                    uint256(s.ring[newest].at) == nowTs &&
                    uint256(s.ring[newest].amount) + amount <= MAX_BOOKABLE_AMOUNT;

            // Capacity is checked only when a NEW slot is actually required, and after
            // coalescing has had its chance, so a full ledger never refuses a spend it
            // could have absorbed into the entry it already holds for this second.
            if (!coalesce && count == MAX_ACTIVE_ENTRIES) {
                return (false, "daily spend ledger full");
            }

            if (coalesce) {
                s.ring[newest].amount = uint192(uint256(s.ring[newest].amount) + amount);
            } else {
                s.ring[(head + count) & _RING_MASK] = Entry({at: uint64(nowTs), amount: uint192(amount)});
                unchecked {
                    count++;
                }
            }
            spent += amount;
        } else if (count == storedCount) {
            // A zero amount that expired nothing changes no state at all. Returning
            // here is what denies the old exploit its free anchor: a zero-amount
            // {check} can no longer move a window boundary, because there is no
            // boundary to move — only entries, and this one books none.
            return (true, "");
        }

        s.rollingSpent = spent;
        s.head = uint32(head);
        s.count = uint32(count);

        return (true, "");
    }

    /// @dev The trailing-window state of `s` as of `nowTs`, with expired entries
    ///      dropped. THE SINGLE DEFINITION OF "LIVE": {check} and every getter route
    ///      through this, so observability and admission cannot disagree about WHAT HAS
    ///      AGED OUT — the failure mode the old raw `windowSpent` getter invited.
    ///
    ///      THAT AGREEMENT IS ABOUT EXPIRY ONLY, NOT ABOUT ADMISSIBILITY. Admission has
    ///      a second, independent constraint — ledger capacity — that this routine does
    ///      not model, so {remainingAllowance} may report a positive figure at the same
    ///      instant {check} refuses with "daily spend ledger full". That is deliberate,
    ///      and it is why the two refusals carry different reason strings.
    ///
    ///      ON USING BLOCK TIMESTAMPS. The invariant this policy enforces is DEFINED in
    ///      chain time: at most `limit` admitted over the chain-time interval
    ///      `(nowTs - WINDOW, nowTs]`. Entry timestamps are not caller-supplied — each
    ///      was written by a previously admitted transaction from its own block. So
    ///      whatever latitude a proposer has over timestamps, it cannot make this
    ///      contract admit more than `limit` within its own measured window; it can only
    ///      shift where that window falls against wall-clock time. A policy capping
    ///      spend per 24 hours of chain time has no other clock available to it.
    ///
    ///      BOUNDARY CONVENTION. An entry booked at `t` is live while `nowTs < t +
    ///      WINDOW` and expires at EXACTLY `t + WINDOW`, so the live set is the
    ///      half-open interval `(nowTs - WINDOW, nowTs]`. That is the same `>=`
    ///      convention the tumbling window used for its reset, carried over deliberately
    ///      so the boundary instant did not silently move under existing operators.
    ///
    ///      BOUNDED WORK. Entries are in non-decreasing timestamp order, so the scan
    ///      stops at the first live entry, and it can never run more than `count <=
    ///      MAX_ACTIVE_ENTRIES` iterations. Each entry is dropped exactly once across
    ///      its lifetime, so the amortized cost per admission is O(1) and the worst
    ///      case is a constant that does NOT grow with lifetime activity.
    /// @return head  Ring index of the oldest still-live entry.
    /// @return count How many entries remain live.
    /// @return spent Exact total admitted over the trailing window.
    function _liveAt(
        SpendState storage s,
        uint256 nowTs
    ) private view returns (uint256 head, uint256 count, uint256 spent) {
        head = s.head;
        count = s.count;
        spent = s.rollingSpent;

        while (count != 0) {
            Entry storage e = s.ring[head];
            if (uint256(e.at) + WINDOW > nowTs) break;
            spent -= e.amount;
            head = (head + 1) & _RING_MASK;
            unchecked {
                count--;
            }
        }
    }

    /// @inheritdoc IPolicyEngine
    /// @dev Intentional no-op: THE DAILY SPEND LIMIT SETTLES AT ADMISSION.
    ///      {check} already validated this withdrawal against the window AND
    ///      booked its amount at queue time; there is nothing left for this
    ///      policy to assert at settlement:
    ///      - Re-booking here would double-count the same withdrawal (a 3 ETH
    ///        withdrawal would consume 6 ETH of allowance).
    ///      - Re-testing `spent + amount <= limit` here would wrongly reject an
    ///        already-admitted withdrawal whose own booking (or a sibling's)
    ///        consumed the allowance in the meantime.
    ///      - Testing `amount <= limit` here would retroactively strand an
    ///        admitted withdrawal after a limit reduction; the limit's meaning
    ///        is a trailing-window ADMISSION total, not a per-settlement cap.
    ///      This function is view (STATICCALL from the vault), so it could not
    ///      book even if a future edit tried to — that attempt would revert
    ///      finalization instead.
    ///      Declared `pure` (strictly stronger than the interface's `view`): this
    ///      no-op reads nothing, so the settlement can never depend on window state,
    ///      and in particular can never depend on the subject it is handed.
    function revalidate(
        PolicySubject calldata,
        address,
        uint256,
        uint256
    ) external pure override returns (bool allowed, string memory reason) {
        return (true, "");
    }

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    /// @notice The armed limit for one subject, in that subject's asset base units.
    /// @return 0 when the subject is unrestricted.
    function dailyLimit(address consumer, address owner, address asset) external view returns (uint256) {
        return _state[_subjectKey(consumer, owner, asset)].limit;
    }

    /// @notice Whether `caller` may book admission spend for one subject.
    function admitter(address consumer, address owner, address asset, address caller) external view returns (bool) {
        return _admitter[_subjectKey(consumer, owner, asset)][caller];
    }

    /// @notice How many admitters the owner has delegated to for one subject.
    function admitterCount(address consumer, address owner, address asset) external view returns (uint256) {
        return _state[_subjectKey(consumer, owner, asset)].admitterCount;
    }

    /// @notice Total admitted for one subject over the trailing {WINDOW} ending NOW.
    /// @dev EFFECTIVE, NOT RAW. Computed through the same {_liveAt} expiry the
    ///      admission path uses, evaluated at the calling block's `block.timestamp`, so
    ///      it decays with the clock and needs no transaction to become accurate. An
    ///      entry booked at `t` is included while `block.timestamp < t + WINDOW` and
    ///      drops out at exactly `t + WINDOW`.
    ///
    ///      This REPLACES the old `windowSpent`, which reported a raw accumulator that
    ///      did not decay and therefore disagreed with {remainingAllowance} for up to a
    ///      full day. There is deliberately no raw equivalent: the stored figure is an
    ///      implementation detail of incremental maintenance, and publishing it again
    ///      would re-create exactly that trap.
    /// @return Admitted total over `(now - WINDOW, now]`, in the subject's base units.
    function rollingSpent(address consumer, address owner, address asset) external view returns (uint256) {
        (, , uint256 spent) = _liveAt(_state[_subjectKey(consumer, owner, asset)], block.timestamp);
        return spent;
    }

    /// @notice Remaining SPEND-CAP allowance for one subject over the trailing {WINDOW}.
    /// @dev `limit - rollingSpent`, floored at zero so a limit lowered below the
    ///      subject's current trailing spend reports 0 rather than reverting. Agrees
    ///      with {check} about EXPIRY by construction — both read it through {_liveAt}.
    ///
    ///      IT IS NOT A PROMISE THAT THIS MUCH IS ADMISSIBLE RIGHT NOW. Admission has a
    ///      second, independent constraint: a subject holding {MAX_ACTIVE_ENTRIES} live
    ///      entries is refused any spend needing a new one, whatever this reports. So a
    ///      positive figure here can coexist with a "daily spend ledger full" refusal —
    ///      pair this with {activeEntryCount} to answer "will my next spend be
    ///      admitted", and read this alone only as "how much of the cap is unused".
    /// @return type(uint256).max when the subject has no limit set.
    function remainingAllowance(address consumer, address owner, address asset) external view returns (uint256) {
        SpendState storage s = _state[_subjectKey(consumer, owner, asset)];

        uint256 limit = s.limit;
        if (limit == 0) return type(uint256).max;

        (, , uint256 spent) = _liveAt(s, block.timestamp);
        return spent >= limit ? 0 : limit - spent;
    }

    /// @notice How many ledger entries one subject currently holds inside the window.
    /// @dev Observability for the {MAX_ACTIVE_ENTRIES} capacity denial: at
    ///      `MAX_ACTIVE_ENTRIES` a spend in a NEW second is refused with "daily spend
    ///      ledger full" until the oldest entry ages out. Operators watching this
    ///      approach the cap can see the refusal coming; without it the denial would be
    ///      indistinguishable from a limit breach.
    function activeEntryCount(address consumer, address owner, address asset) external view returns (uint256) {
        (, uint256 count, ) = _liveAt(_state[_subjectKey(consumer, owner, asset)], block.timestamp);
        return count;
    }

    /// @notice The oldest live ledger entry for one subject: when it was booked, and
    ///         how much it holds.
    /// @dev Exposed because it is the only fact an operator needs to answer "when does
    ///      allowance next return, and how much of it" without replaying history: the
    ///      entry frees `amount` at exactly `at + WINDOW`. Returns `(0, 0)` when the
    ///      ledger is empty — unambiguous, since a booked entry always has a non-zero
    ///      amount and a timestamp in the recent past.
    /// @return at     Timestamp the entry was booked; it expires at `at + WINDOW`.
    /// @return amount Allowance that returns at that instant.
    function oldestActiveEntry(
        address consumer,
        address owner,
        address asset
    ) external view returns (uint256 at, uint256 amount) {
        SpendState storage s = _state[_subjectKey(consumer, owner, asset)];
        (uint256 head, uint256 count, ) = _liveAt(s, block.timestamp);
        if (count == 0) return (0, 0);
        Entry storage e = s.ring[head];
        return (uint256(e.at), uint256(e.amount));
    }
}
