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
 *
 * THE GENERATION'S VERIFIER PROVENANCE ROOT IS BOUND THE SAME WAY
 * (`G-VERIFIER-ADMISSION-PROVENANCE`). `verifierAuthority` is consumed at
 * construction exactly like the implementation, copied into every clone's
 * immutable args beside the generation, and unreachable by every principal
 * afterwards. The kernel reads it from its OWN code at each verifier admission
 * edge, so no clone produced here can adopt a verifier its root did not create,
 * and no later act can change which root that is. Which root a factory binds is
 * the same one-shot construction choice D8 already makes for the implementation:
 * a Generation-1 factory binds `ImmutableAttestationVerifierFactoryPrototype`.
 */
contract VaultKernelFactoryPrototype {
    /// @notice The kernel implementation every clone from this factory delegates to.
    address public immutable implementation;
    /// @notice The generation this factory is permanently bound to.
    uint64 public immutable generation;
    /// @notice The verifier provenance root every clone from this factory consults at admission.
    address public immutable verifierAuthority;

    error ZeroAddress();
    error NoCode();
    error ZeroGeneration();

    event VaultDeployed(address indexed vault, bytes32 indexed genesisSalt, uint64 generation);

    constructor(address implementation_, uint64 generation_, address verifierAuthority_) {
        if (implementation_ == address(0)) revert ZeroAddress();
        // A factory bound to a codeless implementation would emit VaultDeployed
        // for clones that delegate into nothing — every call succeeding with
        // empty returndata, which a naive checker reads as "fine".
        if (implementation_.code.length == 0) revert NoCode();
        // Generations are positive; zero is the uninitialised sentinel.
        if (generation_ == 0) revert ZeroGeneration();
        // A codeless root would make every clone refuse every verifier: fail
        // closed, but a factory that can only produce dead vaults is refused here.
        if (verifierAuthority_ == address(0)) revert ZeroAddress();
        if (verifierAuthority_.code.length == 0) revert NoCode();
        implementation = implementation_;
        generation = generation_;
        verifierAuthority = verifierAuthority_;
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
    /**
     * @param pqKey Forwarded verbatim to `initialize` as the genesis witness
     *        for `g.pqKeyHash` (`I-COMMITMENT-EXHIBITED-AT-ADMISSION`). It is
     *        NOT an input to `genesisSalt`, so `predictVault` keeps its exact
     *        signature and the configuration -> salt map is unchanged. Addresses
     *        themselves still move, because the clone initcode embeds the
     *        implementation address and the implementation changed. A relayer
     *        rewriting these bytes can only make the deployment REVERT — it can
     *        never install a commitment the user did not choose, because the
     *        commitment itself is inside the salted configuration.
     */
    function deployVault(
        bytes32 userSalt,
        VaultKernelPrototype.GenesisConfig calldata g,
        bytes calldata pqKey
    ) external returns (address vault) {
        bytes32 salt = VaultKernelPrototype(payable(implementation)).genesisSalt(userSalt, g);
        vault = Clones.cloneDeterministicWithImmutableArgs(implementation, _args(), salt);
        VaultKernelPrototype(payable(vault)).initialize(g, pqKey);
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

    /// @dev generation (8 bytes) || verifierAuthority (20 bytes). The kernel reads both back from
    ///      its OWN runtime code, never from storage and never from this factory.
    function _args() internal view returns (bytes memory) {
        return abi.encodePacked(generation, verifierAuthority);
    }
}
