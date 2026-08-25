// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title DailySpendLimitPolicy
/// @notice Caps how much of ONE asset ONE tenant may withdraw through ONE vault
///         contract within a 24-hour window.
///
/// @dev  =======================================================================
///       TIME SEMANTICS: THE WINDOW IS TUMBLING, NOT ROLLING. READ THIS FIRST.
///       =======================================================================
///
///       INTENDED PRODUCT INVARIANT: a true ROLLING 24-hour cap — at every instant,
///       the total admitted over the preceding 24 hours is at most `limit`.
///
///       WHAT THIS CONTRACT ACTUALLY IMPLEMENTS: a TUMBLING (reset-on-first-call)
///       window. {check} compares `block.timestamp` against a single stored
///       `windowStart` anchor; when the anchor is at least {WINDOW} old the anchor is
///       moved to now and `windowSpent` is reset to zero. Nothing decays gradually and
///       no history of individual spends is retained, so the cap is per-window, not
///       per-trailing-24-hours.
///
///       THE OBSERVABLE GAP. Because a window can be re-anchored the instant the old
///       one expires, spend can cluster across a boundary:
///
///       - Over the NORMAL signed vault withdrawal path, `2 * limit - 1` wei is
///         admissible across a ONE-SECOND interval: spend `limit - 1` at
///         `windowStart + WINDOW - 1`, then the full `limit` one second later at
///         `windowStart + WINDOW`, where the `>=` comparison re-anchors.
///       - Exactly `2 * limit` requires anchoring the first window with a ZERO-AMOUNT
///         {check} called directly by an authorized admitter, because both vaults
///         reject `amount == 0` before any policy call and so cannot produce that
///         anchor themselves.
///       - The bound is TIGHT: a third window cannot begin until {WINDOW} after the
///         second anchor, so `2 * limit` is the ceiling within any 24-hour span, not a
///         first term in a series.
///
///       These are pinned as executable facts in test/DailySpendWindowSemantics.test.ts.
///
///       ROLLING ENFORCEMENT REMAINS PENDING. It is deliberately NOT implemented here.
///       Rolling accounting has to know WHICH bucket it is decaying, so it was
///       sequenced after subject identity was fixed — which is what this contract's
///       current version does. Treat the cap as "at most `2 * limit` per 24 hours,
///       `limit` per tumbling window" until rolling lands.
///
///       =======================================================================
///       SCOPE SEMANTICS: ACCOUNTING IS KEYED BY THE FULL POLICY SUBJECT.
///       =======================================================================
///
///       Every piece of per-bucket state — the limit, the window anchor, the spend
///       accumulator, the delegation list and its count — hangs off a single
///       {subjectKey}: `keccak256(abi.encode(consumer, owner, asset))`.
///
///       WHY ALL THREE DIMENSIONS. This module is a QUANTITY ACCUMULATOR over a finite
///       budget, and a quantity accumulator is never identity-agnostic:
///
///       - Without `consumer`, two vault contracts serving the same tenant draw from
///         one accumulator, so a spend in vault A denies vault B and A's anchor sets
///         B's clock. Behind a shared {CompositePolicyEngine} that collapse used to be
///         unavoidable, which is why the previous release documented a workaround of
///         one dedicated policy instance per consumer.
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
///       per window in total (and up to `2 * N * limit` per 24 hours given the
///       tumbling bound above). The previous owner-keyed model capped the tenant at
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
///       tenant whose accounting is at stake. Delegation is transitive, though, so the
///       guarantee is only as narrow as what the subject delegated to. Delegating to a
///       {CompositePolicyEngine} inherits THAT composite's access-control policy: its
///       owner chooses which consumers may invoke it, and can therefore point a
///       registered consumer at this module and burn the delegating tenant's allowance
///       FOR THAT SUBJECT. That is denial-class only — spend never decreases, no
///       allowance is manufactured, no other subject is touched, and settlement of an
///       already-queued withdrawal is unaffected — the tenant can always escape
///       instantly with `setDailyLimit(consumer, asset, 0)`, and the same principal
///       already holds strictly stronger, unescapable denials (adding an always-denying
///       module). Delegate to a composite only where its owner is already trusted for
///       the liveness of that composition.
///
///       Spending is recorded at {check} time — for large-tx withdrawals this is at
///       queue time, not finalize time, which is intentional and conservative. If the
///       outer transaction reverts after {check} (e.g. TransferFailed), all state
///       including the spend record is rolled back automatically.
///
///       A limit of 0 means unrestricted (default). Set a non-zero limit to enable.
contract DailySpendLimitPolicy is IPolicyEngine {
    uint256 public constant WINDOW = 24 hours;

    /// @notice All per-subject accounting, gathered into one struct so a single
    ///         {subjectKey} resolves the whole bucket.
    /// @dev One mapping of four contiguous slots rather than four parallel mappings:
    ///      the fields are always read and written together, and co-locating them makes
    ///      it structurally impossible for one field to be keyed differently from
    ///      another — the exact split-identity defect that keying `limit` by owner while
    ///      keying `windowSpent` by subject would have introduced.
    struct SpendState {
        /// @dev Max spend per window, denominated in the subject's asset. 0 = unrestricted.
        uint256 limit;
        /// @dev Timestamp anchoring the current tumbling window.
        uint256 windowStart;
        /// @dev Amount already booked inside the current window.
        uint256 windowSpent;
        /// @dev How many admitters this subject's owner has delegated to. Lets
        ///      {setDailyLimit} refuse to arm a limit that no caller could satisfy.
        uint256 admitterCount;
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
    function setDailyLimit(address consumer, address asset, uint256 limit) external {
        if (consumer == address(0)) revert ZeroConsumer();

        bytes32 key = _subjectKey(consumer, msg.sender, asset);
        SpendState storage s = _state[key];

        if (limit != 0 && s.admitterCount == 0) revert NoAdmitterConfigured(consumer, msg.sender, asset);
        s.limit = limit;
        emit DailyLimitSet(key, consumer, msg.sender, asset, limit);
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
        // Placed BEFORE the window reads so an unauthorized caller can never plant a
        // `windowSpent` value at all. That also forecloses the near-max-limit case,
        // where the denial branch below is unreachable and a planted ceiling value would
        // make every later admission revert on the checked add instead of denying.
        if (!_admitter[key][msg.sender]) {
            revert UnauthorizedAdmitter(msg.sender, subject.consumer, subject.owner, subject.asset);
        }

        uint256 start = s.windowStart;
        uint256 spent = s.windowSpent;

        // Tumbling reset, not a rolling decay — see the contract-level TIME SEMANTICS
        // note for the exact 2*limit bound this permits across a window boundary.
        if (block.timestamp >= start + WINDOW) {
            start = block.timestamp;
            spent = 0;
        }

        if (spent + amount > limit) {
            return (false, "daily limit exceeded");
        }

        s.windowStart = start;
        s.windowSpent = spent + amount;

        return (true, "");
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
    ///        is a per-window admission total, not a per-settlement cap.
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

    /// @notice Remaining spend allowance for one subject in its current window.
    /// @dev Reports the TUMBLING window's residue: once `windowStart + WINDOW` is
    ///      reached the full limit is reported again, which is the same `>=`
    ///      re-anchoring {check} performs. It is not a rolling-24h figure.
    /// @return type(uint256).max when the subject has no limit set.
    function remainingAllowance(address consumer, address owner, address asset) external view returns (uint256) {
        SpendState storage s = _state[_subjectKey(consumer, owner, asset)];

        uint256 limit = s.limit;
        if (limit == 0) return type(uint256).max;

        if (block.timestamp >= s.windowStart + WINDOW) {
            return limit;
        }

        uint256 spent = s.windowSpent;
        return spent >= limit ? 0 : limit - spent;
    }

    /// @notice The timestamp anchoring one subject's current tumbling window.
    /// @dev Exposed so operators and tests can observe the anchor directly rather than
    ///      inferring it from {remainingAllowance} transitions. 0 means no spend has
    ///      ever been admitted for this subject.
    function windowStart(address consumer, address owner, address asset) external view returns (uint256) {
        return _state[_subjectKey(consumer, owner, asset)].windowStart;
    }

    /// @notice Amount already booked for one subject inside its current window.
    /// @dev RAW STORAGE, NOT AN EFFECTIVE FIGURE: this is the stored accumulator and is
    ///      NOT reset by the passage of time. After a window has expired this still
    ///      reports the previous window's total until the next admitted {check}
    ///      re-anchors. Use {remainingAllowance} for the figure that accounts for
    ///      expiry.
    function windowSpent(address consumer, address owner, address asset) external view returns (uint256) {
        return _state[_subjectKey(consumer, owner, asset)].windowSpent;
    }
}
