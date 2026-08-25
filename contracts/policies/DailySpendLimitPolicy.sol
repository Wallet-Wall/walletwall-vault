// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title DailySpendLimitPolicy
/// @notice Caps total spend admitted for a vault owner per 24-hour window.
///
/// @dev WINDOW SEMANTICS — INTENDED vs CURRENTLY ENFORCED. The intended product
///      invariant is a TRUE ROLLING 24-hour cap: at most `limit` inside ANY trailing
///      24-hour interval. THIS IMPLEMENTATION DOES NOT PROVIDE THAT YET, and earlier
///      revisions of this comment wrongly asserted it did.
///
///      What is enforced today is a TUMBLING / RESET window. `_windowStart` re-anchors
///      to `block.timestamp` and `spent` is zeroed wholesale on the first ADMITTED call
///      at or after `_windowStart + WINDOW`. A caller may therefore spend up to `limit`
///      at `_windowStart + WINDOW - 1` and a further `limit` one second later, so up to
///      2 * limit is reachable inside a single 24-hour interval. The bound is EXACTLY 2x
///      and no looser: a denied call does not persist the reset, so successive window
///      anchors are always at least WINDOW apart and no third window fits. The anchor is
///      also chosen by the first admitted spend, not by any calendar — arming a limit
///      starts no window.
///
///      Rolling enforcement is PENDING. Until it lands, treat this module as a
///      per-window cap whose worst case is 2 * limit per 24 hours, not as a rolling cap.
///      test/DailySpendWindowSemantics.test.ts pins the behaviour described here.
///
/// @dev SUBJECT SCOPE — INTENDED vs CURRENTLY ENFORCED. Accounting is keyed by the
///      `vaultOwner` ARGUMENT alone. It carries NO consumer-contract dimension and NO
///      asset dimension, so one instance wired into more than one consumer accumulates
///      every consumer's amounts into a single scalar — including amounts denominated in
///      different units, since {IPolicyEngine} declares `amount` polymorphic ("wei /
///      token base units") and nothing on the path normalizes it. Tenant isolation
///      WITHIN one consumer is correct; the consumer and asset dimensions are missing.
///
///      Explicit subject dimensioning is PENDING. Until it lands, deploy ONE instance per
///      (consumer, asset) and do not delegate a single instance to two consumers. That is
///      an operational convention, NOT an invariant this contract enforces.
///
/// @dev Each vault owner sets their own limit via setDailyLimit(). Spending is
///      recorded at check() time — for large-tx withdrawals this is at queue time,
///      not finalize time, which is intentional and conservative. If the outer
///      transaction reverts after check() (e.g. TransferFailed), all state
///      including the spend record is rolled back automatically.
///
///      A limit of 0 means unrestricted (default). Set a non-zero limit to enable.
///
///      ADMISSION AUTHORITY. {check} is the contract's only state-mutating policy
///      entrypoint, and the accounting it mutates is selected by its `vaultOwner`
///      ARGUMENT. An argument cannot authorize anything, so booking additionally
///      requires that `msg.sender` be an admitter the subject itself delegated to via
///      {setAdmitter} — a msg.sender-keyed setter, the same authority root as
///      {setDailyLimit}. The `vaultOwner` argument therefore only selects WHICH
///      delegation list is consulted; it never by itself satisfies the check.
///
///      The delegation is BY ADDRESS, so it is sound only if every hop between the
///      vault and this module is itself caller-bound. {CompositePolicyEngine} carries
///      the matching gate for that reason: a tenant who delegates to a composite would
///      otherwise be poisonable through the composite's own admission entrypoint.
///
///      This contract has NO owner and no admin: every authority IN IT is held by the
///      vault owner whose accounting is at stake. Under DIRECT wiring (delegate to the
///      vault) that is the whole story — no third party can burn a tenant's allowance.
///
///      Delegation is transitive, though, so the guarantee is only as narrow as what the
///      subject delegated to. Delegating to a {CompositePolicyEngine} inherits THAT
///      composite's access-control policy: its owner chooses which consumers may invoke
///      it, and can therefore point a registered consumer at this module and burn the
///      delegating tenant's allowance. That is denial-class only — spend never decreases,
///      no allowance is manufactured, and settlement of an already-queued withdrawal is
///      unaffected — the tenant can always escape instantly with setDailyLimit(0), and
///      the same principal already holds strictly stronger, unescapable denials
///      (adding an always-denying module). Delegate to a composite only where its owner
///      is already trusted for the liveness of that composition.
contract DailySpendLimitPolicy is IPolicyEngine {
    uint256 public constant WINDOW = 24 hours;

    /// @notice Per-owner spend limit for one window, in the raw units the consumer
    ///         passes to {check} (wei, or token base units). 0 = unrestricted.
    mapping(address => uint256) public dailyLimit;

    /// @notice admitter[vaultOwner][caller] — `caller` may book admission spend against
    ///         `vaultOwner`. Written ONLY by a transaction whose msg.sender IS
    ///         `vaultOwner`, so the delegation can never be forged by a third party.
    mapping(address => mapping(address => bool)) public admitter;

    /// @notice How many admitters `vaultOwner` has delegated to. Lets {setDailyLimit}
    ///         refuse to arm a limit that no caller could ever satisfy.
    mapping(address => uint256) public admitterCount;

    mapping(address => uint256) private _windowStart;
    mapping(address => uint256) private _windowSpent;

    event DailyLimitSet(address indexed vaultOwner, uint256 limit);
    event AdmitterSet(address indexed vaultOwner, address indexed admitter, bool allowed);

    /// @notice `caller` is not an admitter the subject delegated to.
    error UnauthorizedAdmitter(address caller, address vaultOwner);
    /// @notice Refuses to arm a limit before any admitter exists (would brick the owner).
    error NoAdmitterConfigured(address vaultOwner);
    /// @notice Refuses to remove the last admitter while a limit is armed.
    error LastAdmitterWhileArmed(address vaultOwner);
    /// @notice A delegated admitter other than the subject itself must be a contract.
    error AdmitterNotAContract(address admitter);
    error ZeroAdmitter();

    /// @notice Sets the caller's daily spend limit.
    /// @dev Arming a non-zero limit requires at least one admitter, so the failure
    ///      surfaces here — on the configuration transaction — instead of later, as an
    ///      unexplained revert on the owner's next withdrawal. Disarming (`limit == 0`)
    ///      is deliberately exempt: the documented escape hatch must never be blocked.
    /// @param limit Max withdrawable within ONE 24h window, in the raw units the
    ///        consumer passes to {check}. Not a rolling-24h cap — see the window
    ///        semantics note on the contract. 0 = unrestricted.
    function setDailyLimit(uint256 limit) external {
        if (limit != 0 && admitterCount[msg.sender] == 0) revert NoAdmitterConfigured(msg.sender);
        dailyLimit[msg.sender] = limit;
        emit DailyLimitSet(msg.sender, limit);
    }

    /// @notice Delegates (or revokes) authority to book admission spend against the caller.
    /// @dev The caller IS the subject: `admitter[msg.sender][caller]` is the only write,
    ///      so this introduces no new principal and no contract owner. Authorize the vault
    ///      that will admit your withdrawals — or the composite engine, if one sits between.
    ///
    ///      A delegate other than the subject itself must have code: an EOA admitter could
    ///      burn the subject's allowance at will, which is the very defect this gate closes.
    ///      Self-delegation is permitted and harmless — subject and delegate coincide, so it
    ///      grants nobody else anything, and it keeps standalone/direct use available.
    /// @param caller  The address permitted to call {check} for the caller's accounting.
    /// @param allowed True to delegate, false to revoke.
    function setAdmitter(address caller, bool allowed) external {
        if (caller == address(0)) revert ZeroAdmitter();
        if (allowed && caller != msg.sender && caller.code.length == 0) {
            revert AdmitterNotAContract(caller);
        }

        bool previous = admitter[msg.sender][caller];
        if (previous == allowed) return; // idempotent — keeps admitterCount exact

        if (!allowed && admitterCount[msg.sender] == 1 && dailyLimit[msg.sender] != 0) {
            revert LastAdmitterWhileArmed(msg.sender);
        }

        admitter[msg.sender][caller] = allowed;
        admitterCount[msg.sender] = allowed ? admitterCount[msg.sender] + 1 : admitterCount[msg.sender] - 1;
        emit AdmitterSet(msg.sender, caller, allowed);
    }

    /// @inheritdoc IPolicyEngine
    function check(
        address vaultOwner,
        address,
        uint256 amount,
        uint256
    ) external override returns (bool allowed, string memory reason) {
        uint256 limit = dailyLimit[vaultOwner];
        if (limit == 0) return (true, "");

        // AUTHORITY BEFORE POLICY. Derived from msg.sender; `vaultOwner` only selects
        // which delegation list is consulted. Reverting (rather than returning a denial)
        // keeps a misconfiguration distinguishable from a policy decision — the vaults do
        // not wrap this call in try/catch, so the error reaches the caller intact.
        //
        // Placed AFTER the `limit == 0` return so the gate constrains exactly the armed
        // set — which is exactly the attackable set, since an unarmed subject returns
        // above without touching storage. Owners who never armed a limit need no
        // configuration and cannot be locked out by this change.
        //
        // Placed BEFORE the first storage read so an unauthorized caller can never plant
        // a `_windowSpent` value at all. That also forecloses the near-max-limit case,
        // where the denial branch below is unreachable and a planted ceiling value would
        // make every later admission revert on the checked add instead of denying.
        if (!admitter[vaultOwner][msg.sender]) revert UnauthorizedAdmitter(msg.sender, vaultOwner);

        uint256 start = _windowStart[vaultOwner];
        uint256 spent = _windowSpent[vaultOwner];

        if (block.timestamp >= start + WINDOW) {
            start = block.timestamp;
            spent = 0;
        }

        if (spent + amount > limit) {
            return (false, "daily limit exceeded");
        }

        _windowStart[vaultOwner] = start;
        _windowSpent[vaultOwner] = spent + amount;

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
    ///      no-op reads nothing, so the settlement can never depend on window state.
    function revalidate(
        address,
        address,
        uint256,
        uint256
    ) external pure override returns (bool allowed, string memory reason) {
        return (true, "");
    }

    /// @notice Remaining spend allowance in the CURRENT window (the tumbling window
    ///         anchored at the last reset), not the amount still available under a
    ///         rolling 24h cap. Those differ; see the window semantics note above.
    /// @return type(uint256).max when the vault has no limit set.
    function remainingAllowance(address vaultOwner) external view returns (uint256) {
        uint256 limit = dailyLimit[vaultOwner];
        if (limit == 0) return type(uint256).max;

        if (block.timestamp >= _windowStart[vaultOwner] + WINDOW) {
            return limit;
        }

        uint256 spent = _windowSpent[vaultOwner];
        return spent >= limit ? 0 : limit - spent;
    }
}
