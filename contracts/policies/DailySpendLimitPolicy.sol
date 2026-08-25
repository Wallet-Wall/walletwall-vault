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
///       {MAX_ACTIVE_ENTRIES} distinct `(time, amount)` pairs, so more than that many
///       distinct live spend-instants cannot be represented exactly. EXACT AND BOUNDED
///       THEREFORE IMPLIES A CAP — the only open choice is what to do at the cap:
///
///       - REFUSE the admission (chosen). Accounting stays exact; a subject that has
///         already booked {MAX_ACTIVE_ENTRIES} distinct seconds inside the window is
///         refused a spend in a NEW second, with reason "daily spend ledger full".
///       - MERGE the two oldest entries at the newer timestamp (rejected). Never
///         admits above `limit`, but holds old spend on the books LONGER than the true
///         trailing window, so the cap would be conservative rather than exact. This
///         contract would then be claiming a guarantee it does not implement.
///
///       THE REFUSAL IS SELF-HEALING AND NOT ATTACKER-REACHABLE. A slot frees the
///       instant the oldest entry expires, so a full ledger is never a permanent brick;
///       and entries can only be appended by a caller the subject's own owner delegated
///       via {setAdmitter}, so no third party can fill it. Same-second admissions
///       coalesce into one entry, so a burst inside a single block costs one slot.
///       {activeEntryCount} exposes the occupancy, since a capacity refusal is
///       otherwise indistinguishable from a limit refusal.
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

    /// @notice How many distinct-second spends one subject may hold inside the trailing
    ///         window at once.
    /// @dev THE PRICE OF BEING BOTH EXACT AND BOUNDED — see the LEDGER CAPACITY section
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
    ///      through this, so observability and admission can never disagree about what
    ///      has aged out — the failure mode the old raw `windowSpent` getter invited.
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

    /// @notice Remaining spend allowance for one subject over the trailing {WINDOW}.
    /// @dev `limit - rollingSpent`, floored at zero so a limit lowered below the
    ///      subject's current trailing spend reports 0 rather than reverting. Agrees
    ///      with {check} by construction — both read expiry through {_liveAt}.
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
