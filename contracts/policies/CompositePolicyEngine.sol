// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "../IPolicyEngine.sol";

/**
 * @title CompositePolicyEngine
 * @notice Policy engine that fans withdrawal checks out to multiple IPolicyEngine
 *         modules simultaneously. A withdrawal is permitted only if ALL active
 *         modules approve it (fail-closed composition).
 *
 * @dev  =======================================================================
 *       RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY.
 *       DO NOT USE WITH REAL FUNDS.
 *       =======================================================================
 *
 *       Use this as the single policy engine wired into WalletWallVault when
 *       you need DailySpendLimitPolicy + RecipientAllowlistPolicy +
 *       SanctionsListPolicy to all enforce simultaneously. Each module must
 *       implement IPolicyEngine. Modules with no deployed code are rejected at
 *       registration time.
 *
 *       The module list is hard-capped at {MAX_MODULES} so a misconfigured set can
 *       never make check()/revalidate() un-runnable within a block, and a module can
 *       never be this composite itself (direct self-recursion). Indirect cycles
 *       through another composite are NOT detected on-chain — do not nest composites.
 *
 *       GOVERNANCE NOTE: {addModule} and module removal are deliberately
 *       ASYMMETRIC. Composition here is AND-semantics — a withdrawal is admitted
 *       only if EVERY active module approves it — so adding a module can only
 *       shrink or preserve the set of withdrawals the composite accepts (strictly
 *       monotonic strengthening), while removing one can only grow or preserve it
 *       (strictly monotonic weakening). {addModule} stays instant, onlyOwner, no
 *       delay: it can never weaken the effective policy, so gating it would only
 *       cost urgent-response liveness (e.g. attaching a new sanctions module) for
 *       no security benefit. Removal — including the transition from a non-empty
 *       enforcing set down to a permissive empty one — is the ONLY direction that
 *       can weaken the effective policy, so it now goes through
 *       {proposeRemoveModule} / {applyRemoveModule} behind {MODULE_REMOVAL_DELAY},
 *       matching the governance friction a vault owner would need to replace the
 *       policy engine's ADDRESS outright. The module being removed stays fully
 *       active — evaluated by both {check} and {revalidate} — for the entire
 *       pending window, so it cannot be evicted with less friction than an
 *       engine-address swap would cost. That friction is real only because a
 *       matured proposal also EXPIRES after {MODULE_REMOVAL_GRACE_PERIOD}: an
 *       unbounded one could be pre-armed at a quiet moment and banked, making the
 *       eviction instant exactly when it mattered and delivering none of the
 *       warning the delay is supposed to buy.
 *
 *       FRICTION-EQUIVALENT, NOT OUTCOME-EQUIVALENT FOR ALREADY-QUEUED
 *       WITHDRAWALS. Removal now costs a composite owner the same DELAY a vault
 *       owner would pay to swap the vault's engine address — but that is a
 *       statement about governance FRICTION for future admissions, not a
 *       guarantee that the two mechanisms settle an already-queued withdrawal
 *       identically. WalletWallVault/StablecoinVaultSimulator's
 *       finalizeWithdrawal treats the queue-time engine ADDRESS as a sticky
 *       floor (swapping the vault's active engine after queueing cannot erase
 *       it — see the vault's own finalizeWithdrawal docs). That floor is
 *       ADDRESS-granular, not module-roster-granular: if this composite is
 *       still the sticky-floor engine (its address never changed), a matured
 *       and applied {applyRemoveModule} call on THIS SAME address still
 *       changes what {revalidate} reports for a withdrawal that was already
 *       queued under it, because {revalidate} always reads {_modules} live —
 *       there is no per-withdrawal snapshot of the module roster. So: an
 *       engine-address swap to a permissive engine cannot retroactively free
 *       an already-queued withdrawal (the sticky floor still binds the OLD
 *       engine), but a governed module removal on a composite that IS the
 *       sticky-floor engine legitimately can, once its own delay has fully
 *       elapsed and been applied. Both are intentional and correct under the
 *       existing dual-revalidate model (queue-time engine address x current
 *       engine address x LIVE module set(s) x live module internal state) —
 *       they are simply not the same mechanism, and must not be described as
 *       such.
 */
contract CompositePolicyEngine is IPolicyEngine, Ownable2Step {
    /// @notice Hard cap on registered modules; bounds check()/revalidate() gas.
    /// @dev A module with a pending-but-not-yet-applied removal still counts
    ///      toward this cap (it is still in {getModules} until {applyRemoveModule}
    ///      runs) — rotating several modules at MAX_MODULES may transiently need to
    ///      wait for an old removal to apply before a new one can be added.
    uint256 public constant MAX_MODULES = 16;

    /// @notice Governance delay for a proposed module REMOVAL to become applicable.
    /// @dev Standalone constant on this composite, matched BY CONVENTION to the
    ///      2-day POLICY_ENGINE_UPDATE_DELAY used by WalletWallVault and
    ///      StablecoinVaultSimulator — NOT read from either vault (this composite
    ///      has no reference to any specific vault and may be wired into several).
    ///      The removal-friction invariant this composite enforces only holds
    ///      relative to a consuming vault whose OWN engine-swap delay is >= this
    ///      value; a future vault type with a longer engine-swap delay would need
    ///      re-verification before being wired to a composite using this constant.
    uint256 public constant MODULE_REMOVAL_DELAY = 2 days;

    /// @notice How long a matured removal proposal stays applicable before it expires.
    /// @dev WHY AN UPPER BOUND EXISTS. {MODULE_REMOVAL_DELAY} is only worth the
    ///      reaction window it actually delivers at the moment a module is evicted.
    ///      Without an expiry, a matured proposal stays exercisable forever, so an
    ///      owner can PRE-ARM one at a quiet moment — when nothing is queued and no
    ///      observer has cause to react — let the delay lapse unapplied, and then bank
    ///      an INSTANT eviction indefinitely. Exercised at the moment the module
    ///      actually stands between the owner and a settlement, that costs zero delay
    ///      and yields zero warning, which is precisely the outcome the delay exists to
    ///      prevent. Bounding the applicable window restores the intended property:
    ///      any removal executable right now was announced by a
    ///      {ModuleRemovalProposed} event within the last
    ///      MODULE_REMOVAL_DELAY + MODULE_REMOVAL_GRACE_PERIOD, so monitoring that
    ///      event gives a finite, guaranteed horizon instead of requiring perfect
    ///      recall of every proposal ever made.
    ///
    ///      The 2-day delay / 14-day grace pairing matches Compound's Timelock, which
    ///      carries a GRACE_PERIOD for this same reason. The grace window is generous
    ///      on purpose: expiry is an anti-banking bound, not an execution race, so an
    ///      honest operator applying a matured removal is never realistically rushed.
    uint256 public constant MODULE_REMOVAL_GRACE_PERIOD = 14 days;

    address[] private _modules;

    /// @notice Consumers permitted to invoke {check}. Empty by default — a fresh
    ///         composite admits nothing until its consumer vault is registered.
    mapping(address => bool) public admissionCaller;

    /// @notice Earliest timestamp at which a proposed module removal may be
    ///         applied; zero means no removal is pending for that module.
    mapping(address => uint256) public pendingModuleRemovalValidAfter;

    event ModuleAdded(address indexed module, uint256 moduleCount);
    event ModuleRemoved(address indexed module, uint256 moduleCount);
    event ModuleRemovalProposed(address indexed module, uint256 validAfter);
    event ModuleRemovalCancelled(address indexed module);
    event AdmissionCallerSet(address indexed caller, bool allowed);

    error ZeroModuleAddress();
    error NoCode(address module);
    error DuplicateModule(address module);
    error ModuleNotFound(address module);
    error SelfModule();
    error TooManyModules(uint256 count, uint256 max);
    error UnauthorizedAdmissionCaller(address caller);
    /// @notice The relayed subject claims a consumer other than the authenticated caller.
    error SubjectConsumerMismatch(address claimedConsumer, address caller);
    error NoPendingModuleRemoval(address module);
    error ModuleRemovalNotReady(address module, uint256 validAfter, uint256 currentTimestamp);
    /// @notice The proposal matured but its applicable window has closed; re-propose.
    error ModuleRemovalExpired(address module, uint256 validAfter, uint256 expiresAt, uint256 currentTimestamp);

    constructor() Ownable(msg.sender) {}

    // -------------------------------------------------------------------------
    // Module management
    // -------------------------------------------------------------------------

    /**
     * @notice Adds a policy module to the composition.
     * @dev Reverts if `module` is the zero address, has no deployed bytecode,
     *      or is already registered. Admin-only.
     */
    function addModule(address module) external onlyOwner {
        if (module == address(0)) revert ZeroModuleAddress();
        if (module == address(this)) revert SelfModule();

        uint256 size;
        assembly {
            size := extcodesize(module)
        }
        if (size == 0) revert NoCode(module);

        uint256 len = _modules.length;
        if (len >= MAX_MODULES) revert TooManyModules(len, MAX_MODULES);
        for (uint256 i = 0; i < len; i++) {
            if (_modules[i] == module) revert DuplicateModule(module);
        }

        _modules.push(module);
        emit ModuleAdded(module, _modules.length);
    }

    /**
     * @notice Proposes removing a policy module, effective after {MODULE_REMOVAL_DELAY}.
     * @dev Admin-only. Reverts if `module` is not currently registered. The module
     *      remains fully active — evaluated by both {check} and {revalidate} — for
     *      the entire pending window; only {applyRemoveModule}, once due, actually
     *      removes it. Re-proposing the same module restarts the delay, matching
     *      this repo's other propose/apply flows (the vault's own policy-engine
     *      swap, large-tx params, PQ verifier).
     */
    function proposeRemoveModule(address module) external onlyOwner {
        if (!_isModule(module)) revert ModuleNotFound(module);
        uint256 validAfter = block.timestamp + MODULE_REMOVAL_DELAY;
        pendingModuleRemovalValidAfter[module] = validAfter;
        emit ModuleRemovalProposed(module, validAfter);
    }

    /**
     * @notice Applies a previously proposed module removal once its delay has elapsed.
     * @dev Admin-only. Uses swap-and-pop so removal is O(n) for the lookup and O(1)
     *      for the removal itself. Order is not preserved. Re-checks membership at
     *      apply time (not just the existence of a pending proposal) so a stale
     *      proposal can never remove the wrong thing.
     *
     *      Applicable only within [validAfter, validAfter + {MODULE_REMOVAL_GRACE_PERIOD}].
     *      Past that the proposal has EXPIRED and buys no head start: removal requires a
     *      fresh {proposeRemoveModule} and a fresh full delay. See
     *      {MODULE_REMOVAL_GRACE_PERIOD} for why an unbounded window would void the
     *      delay's entire purpose. An expired proposal can still be cleared with
     *      {cancelRemoveModule}.
     */
    function applyRemoveModule(address module) external onlyOwner {
        uint256 validAfter = pendingModuleRemovalValidAfter[module];
        if (validAfter == 0) revert NoPendingModuleRemoval(module);
        if (block.timestamp < validAfter) revert ModuleRemovalNotReady(module, validAfter, block.timestamp);

        uint256 expiresAt = validAfter + MODULE_REMOVAL_GRACE_PERIOD;
        if (block.timestamp > expiresAt) {
            revert ModuleRemovalExpired(module, validAfter, expiresAt, block.timestamp);
        }

        pendingModuleRemovalValidAfter[module] = 0;

        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            if (_modules[i] == module) {
                _modules[i] = _modules[len - 1];
                _modules.pop();
                emit ModuleRemoved(module, _modules.length);
                return;
            }
        }
        revert ModuleNotFound(module);
    }

    /**
     * @notice Cancels a pending module removal.
     * @dev Admin-only. Reverts if no removal is pending for `module`.
     */
    function cancelRemoveModule(address module) external onlyOwner {
        if (pendingModuleRemovalValidAfter[module] == 0) revert NoPendingModuleRemoval(module);
        pendingModuleRemovalValidAfter[module] = 0;
        emit ModuleRemovalCancelled(module);
    }

    /// @dev Linear membership check — bounded by {MAX_MODULES}, so this is cheap.
    function _isModule(address module) internal view returns (bool) {
        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            if (_modules[i] == module) return true;
        }
        return false;
    }

    /**
     * @notice Registers (or de-registers) a consumer permitted to call {check}.
     * @dev Admin-only, and mandatory before this composite can admit anything.
     *
     *      WHY THIS EXISTS. {check} relays the caller-supplied `vaultOwner` to every
     *      module. A stateful module such as {DailySpendLimitPolicy} gates its own
     *      booking on `msg.sender`, and under composition that msg.sender is THIS
     *      contract — so a tenant who delegates to this composite has delegated to
     *      whoever can reach this composite. Without this gate that is everyone, and
     *      the composite becomes a deputy for exactly the poisoning the module's own
     *      gate refuses. Authority has to hold at every hop of a stateful path.
     *
     *      This adds no new authority class: the owner already holds instant,
     *      untimelocked control of the effective policy set via {addModule} /
     *      {removeModule}, so it can already block admissions at will.
     *
     *      {revalidate} is deliberately NOT gated — it is `view`, mutates nothing, and
     *      restricting it would break the vaults' fail-closed settlement revalidation.
     */
    function setAdmissionCaller(address caller, bool allowed) external onlyOwner {
        if (caller == address(0)) revert ZeroModuleAddress();
        if (caller == address(this)) revert SelfModule();

        // NB: high-level `.code.length` rather than {addModule}'s inline-assembly
        // extcodesize — `caller` is a reserved Yul opcode (it IS msg.sender there).
        // Both compile to EXTCODESIZE.
        if (allowed && caller.code.length == 0) revert NoCode(caller);

        admissionCaller[caller] = allowed;
        emit AdmissionCallerSet(caller, allowed);
    }

    /// @notice Returns the number of active policy modules.
    function moduleCount() external view returns (uint256) {
        return _modules.length;
    }

    /// @notice Returns the full list of active policy module addresses.
    function getModules() external view returns (address[] memory) {
        return _modules;
    }

    // -------------------------------------------------------------------------
    // IPolicyEngine
    // -------------------------------------------------------------------------

    /**
     * @notice Checks a withdrawal against every active module.
     * @dev Returns (false, reason) on the FIRST module that denies the
     *      withdrawal. Returns (true, "") only if all modules allow it.
     *      An empty module list is permissive — attach at least one module
     *      before enabling this as the vault's policy engine.
     *
     *      Restricted to registered consumers ({setAdmissionCaller}); an unregistered
     *      caller reverts rather than being relayed to the modules, so this composite
     *      cannot be used as a deputy to reach a stateful module's admission accounting.
     *
     *      SUBJECT PRESERVATION IS THE POINT OF THIS FUNCTION. `subject` is relayed to
     *      every module BYTE-FOR-BYTE. This composite never substitutes
     *      `subject.consumer` with `address(this)`, never zeroes `subject.asset`, and
     *      never rewrites `subject.owner` — doing any of those would re-collapse the
     *      identities the subject exists to keep apart, and would make one shared
     *      composite silently merge the spend accounting of every vault behind it.
     *
     *      TWO INDEPENDENT GATES, ANSWERING DIFFERENT QUESTIONS. `admissionCaller`
     *      answers "may this caller use this composite at all". The consumer binding
     *      below answers "is this caller the consumer it CLAIMS to be" — without it, a
     *      registered consumer could present a subject naming a DIFFERENT registered
     *      consumer and book spend into that consumer's bucket. Neither gate implies
     *      the other, so both are required.
     *
     *      A side effect worth naming: because the binding requires
     *      `subject.consumer == msg.sender`, a composite nested inside another
     *      composite can no longer admit anything (the inner one would see the outer
     *      composite as caller while the subject still names the vault). The "do not
     *      nest composites" warning above is therefore now MECHANICALLY enforced on the
     *      admission path rather than merely documented.
     */
    function check(
        PolicySubject calldata subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external override returns (bool, string memory) {
        if (!admissionCaller[msg.sender]) revert UnauthorizedAdmissionCaller(msg.sender);
        if (subject.consumer != msg.sender) revert SubjectConsumerMismatch(subject.consumer, msg.sender);

        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            (bool ok, string memory why) = IPolicyEngine(_modules[i]).check(subject, recipient, amount, vaultBalance);
            if (!ok) return (false, why);
        }
        return (true, "");
    }

    /**
     * @notice Re-validates a withdrawal against every CURRENTLY registered module.
     * @dev Fans out to each module's {revalidate} — NEVER {check}, which may
     *      mutate admission accounting. Because this function is view, every
     *      module call executes as a STATICCALL; a module whose revalidation
     *      attempts to write state (or that does not implement {revalidate})
     *      reverts the whole call, which the vault treats as fail-closed.
     *      The module set evaluated is the CURRENT one: a denying module added
     *      after a withdrawal was queued blocks it, and a retained module whose
     *      internal state turned denying blocks it. An empty module list is
     *      permissive, mirroring {check}.
     *
     *      `subject` is relayed unchanged here too, so a module sees the same identity
     *      at settlement that it saw at admission.
     *
     *      WHY THIS PATH CARRIES NEITHER GATE. {check}'s two gates exist because it
     *      MUTATES module accounting: an unauthorized or consumer-spoofing caller could
     *      otherwise book spend into a bucket that is not theirs. This function is
     *      `view`, so every module call it makes executes under STATICCALL and can book
     *      nothing at all. What remains is a caller who lies about a subject and
     *      receives, as a return value to themselves, an answer about someone else's
     *      state — the same information any module's own public getters already expose.
     *      Adding a gate here would buy no confidentiality and would add a new way for
     *      an honest settlement to fail closed, since the vaults call this on the
     *      QUEUE-TIME engine as well as the current one and treat any revert as
     *      PolicyEngineUnavailable.
     */
    function revalidate(
        PolicySubject calldata subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external view override returns (bool, string memory) {
        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            (bool ok, string memory why) = IPolicyEngine(_modules[i]).revalidate(
                subject,
                recipient,
                amount,
                vaultBalance
            );
            if (!ok) return (false, why);
        }
        return (true, "");
    }
}
