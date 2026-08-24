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
 *       GOVERNANCE NOTE: addModule/removeModule take effect IMMEDIATELY (no
 *       timelock), like the content mutations of the individual policies
 *       (sanctions add/remove, allowlist add/remove). Wiring a composite into a
 *       vault therefore places the effective policy set behind the composite
 *       owner's instant control, even though replacing the vault's engine address
 *       itself requires the 2-day governance delay. Whoever owns the composite
 *       owns instant policy-set changes; deployments where the composite owner
 *       must not be able to instantly evict another party's module should not
 *       use a shared composite.
 */
contract CompositePolicyEngine is IPolicyEngine, Ownable2Step {
    /// @notice Hard cap on registered modules; bounds check()/revalidate() gas.
    uint256 public constant MAX_MODULES = 16;

    address[] private _modules;

    event ModuleAdded(address indexed module, uint256 moduleCount);
    event ModuleRemoved(address indexed module, uint256 moduleCount);

    error ZeroModuleAddress();
    error NoCode(address module);
    error DuplicateModule(address module);
    error ModuleNotFound(address module);
    error SelfModule();
    error TooManyModules(uint256 count, uint256 max);

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
     * @notice Removes a policy module from the composition.
     * @dev Uses swap-and-pop so removal is O(n) for the lookup and O(1) for the
     *      removal itself. Order is not preserved. Admin-only.
     */
    function removeModule(address module) external onlyOwner {
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
     */
    function check(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external override returns (bool, string memory) {
        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            (bool ok, string memory why) = IPolicyEngine(_modules[i]).check(
                vaultOwner,
                recipient,
                amount,
                vaultBalance
            );
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
     */
    function revalidate(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external view override returns (bool, string memory) {
        uint256 len = _modules.length;
        for (uint256 i = 0; i < len; i++) {
            (bool ok, string memory why) = IPolicyEngine(_modules[i]).revalidate(
                vaultOwner,
                recipient,
                amount,
                vaultBalance
            );
            if (!ok) return (false, why);
        }
        return (true, "");
    }
}
