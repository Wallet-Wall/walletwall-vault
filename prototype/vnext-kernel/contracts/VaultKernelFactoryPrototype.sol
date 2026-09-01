// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/proxy/Clones.sol";

import "./VaultKernelPrototype.sol";

/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * ONE IMMUTABLE FACTORY PER KERNEL GENERATION (owner decision D8, LOCKED).
 *
 * The implementation target is `immutable`: the choice is consumed at this
 * factory's own construction and is thereafter unreachable by EVERY principal,
 * including the deployer. There is deliberately no:
 *
 *     setImplementation · upgradeFactory · registerNewKernel · beacon
 *     · proxy admin · mutable implementation registry · owner · any
 *       privileged role whatsoever
 *
 * Registering a new generation IS deploying a new factory. This factory holds
 * NO authority over any clone it has already produced, so its authority closure
 * is EMPTY rather than merely bounded.
 */
contract VaultKernelFactoryPrototype {
    /// @notice The kernel implementation every clone from this factory delegates to.
    address public immutable implementation;
    /// @notice The generation this factory is permanently bound to.
    uint64 public immutable generation;

    error ZeroAddress();
    error NoCode();
    error ZeroGeneration();

    event VaultDeployed(address indexed vault, bytes32 indexed genesisSalt, uint64 generation);

    constructor(address implementation_, uint64 generation_) {
        if (implementation_ == address(0)) revert ZeroAddress();
        // A factory bound to a codeless implementation would emit VaultDeployed
        // for clones that delegate into nothing — every call succeeding with
        // empty returndata, which a naive checker reads as "fine".
        if (implementation_.code.length == 0) revert NoCode();
        // Generations are positive; zero is the uninitialised sentinel.
        if (generation_ == 0) revert ZeroGeneration();
        implementation = implementation_;
        generation = generation_;
    }

    /**
     * @notice Deploy AND initialize in ONE transaction (dissent D3), at an
     *         address bound to the COMPLETE genesis authority.
     *
     * @dev `I-COUNTERFACTUAL-IDENTITY-BINDING` — the fix for finding C. An
     *      earlier factory used the caller's raw salt, so the CREATE2 address
     *      committed to nothing about WHO would control the vault. An attacker
     *      could front-run a user's predicted address with their own signer and
     *      guardian set, occupy the identity, and leave the user unable to
     *      instantiate their intended configuration there.
     *
     *      The effective salt now binds every genesis field, so a different
     *      authority yields a DIFFERENT address. A stranger who submits the
     *      user's IDENTICAL authorised configuration lands on the same address
     *      and produces the same state — harmless permissionless execution, not
     *      a takeover, and it is tested as such.
     *
     *      **Atomicity and identity binding solve DIFFERENT problems.** Atomicity
     *      stops an attacker claiming an already-created uninitialised clone.
     *      It never stopped an attacker creating the counterfactual address
     *      first. The earlier PR body conflated the two; this one does not.
     */
    function deployVault(
        bytes32 userSalt,
        VaultKernelPrototype.GenesisConfig calldata g
    ) external returns (address vault) {
        bytes32 salt = VaultKernelPrototype(payable(implementation)).genesisSalt(userSalt, g);
        vault = Clones.cloneDeterministicWithImmutableArgs(implementation, _args(), salt);
        VaultKernelPrototype(payable(vault)).initialize(g);
        emit VaultDeployed(vault, salt, generation);
    }

    /// @notice The counterfactual address for a genesis configuration.
    function predictVault(
        bytes32 userSalt,
        VaultKernelPrototype.GenesisConfig calldata g
    ) external view returns (address) {
        bytes32 salt = VaultKernelPrototype(payable(implementation)).genesisSalt(userSalt, g);
        return Clones.predictDeterministicAddressWithImmutableArgs(implementation, _args(), salt, address(this));
    }

    function _args() internal view returns (bytes memory) {
        return abi.encodePacked(generation);
    }
}
