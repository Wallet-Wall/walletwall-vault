// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/proxy/Clones.sol";

interface IInitializableKernel {
    struct SecurityFloor {
        bool requirePq;
        uint16 pqParamLevel;
        uint32 pqPublicKeyLength;
        uint32 pqSignatureLength;
    }

    function initialize(
        address signer,
        bytes32 pqKeyHash,
        address verifier,
        bytes32 guardianCommitment,
        uint64 threshold,
        SecurityFloor calldata floor
    ) external;
}

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
 * NO authority over any clone it has already produced, and none over any clone
 * it will produce beyond the generation it was born with — so its authority
 * closure is EMPTY, not merely bounded.
 */
contract VaultKernelFactoryPrototype {
    /// @notice The kernel implementation every clone from this factory delegates to.
    address public immutable implementation;
    /// @notice The generation this factory is permanently bound to.
    uint64 public immutable generation;

    error ZeroAddress();

    event VaultDeployed(address indexed vault, bytes32 indexed salt, uint64 generation);

    constructor(address implementation_, uint64 generation_) {
        if (implementation_ == address(0)) revert ZeroAddress();
        implementation = implementation_;
        generation = generation_;
    }

    /**
     * @notice Deploy AND initialize in ONE transaction (dissent D3). An
     *         uninitialised clone therefore never exists between transactions
     *         and cannot be claimed by a front-runner.
     *
     * @dev The generation is appended as per-clone IMMUTABLE ARGS, so it lives
     *      in the clone's own runtime code — committed to by both
     *      `extcodehash(clone)` and the CREATE2 address, and readable by an
     *      offline observer from `eth_getCode` alone.
     */
    function deployVault(
        bytes32 salt,
        address signer,
        bytes32 pqKeyHash,
        address verifier,
        bytes32 guardianCommitment,
        uint64 threshold,
        IInitializableKernel.SecurityFloor calldata floor
    ) external returns (address vault) {
        vault = Clones.cloneDeterministicWithImmutableArgs(implementation, _args(), salt);
        IInitializableKernel(vault).initialize(signer, pqKeyHash, verifier, guardianCommitment, threshold, floor);
        emit VaultDeployed(vault, salt, generation);
    }

    /// @notice The counterfactual address, derivable before deployment.
    function predictVault(bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddressWithImmutableArgs(implementation, _args(), salt, address(this));
    }

    function _args() internal view returns (bytes memory) {
        return abi.encodePacked(generation);
    }
}
