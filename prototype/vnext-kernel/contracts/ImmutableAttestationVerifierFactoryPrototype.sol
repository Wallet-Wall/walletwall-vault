// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./interfaces/IKernelPlanes.sol";
import "./verifiers/ImmutableAttestationPQCVerifier.sol";

/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * THE GENERATION-1 VERIFIER PROVENANCE ROOT (`G-VERIFIER-ADMISSION-PROVENANCE`).
 *
 * PROVENANCE BY CONSTRUCTION, NOT APPROVAL BY AN ADMINISTRATOR. This contract can create exactly
 * one verifier class, `ImmutableAttestationPQCVerifier` — a byte-identical copy of
 * contracts/verifiers/ImmutableAttestationPQCVerifier.sol, whose attestor is `immutable` and which
 * has no owner, no setter and no storage writer — and it records that it did so in the same
 * function. There is deliberately no:
 *
 *     owner · curator · register(address) · setApproved · revoke · upgrade · pause
 *     · constructor parameter · any second writer of `isAdmissibleVerifier`
 *
 * so the class is fixed by this contract's CODE, and no principal — its deployer included — can
 * make anything else admissible through it. It holds no authority over any verifier it created and
 * none over any vault: a vault still adopts a verifier only through its own authorised transitions
 * (genesis, setVerifier, guardian recovery).
 *
 * WHY A RECORD RATHER THAN A CREATE2 RECOMPUTATION. Recomputing "the address this root would use
 * for attestor X" establishes that an address is one this root COULD produce, not that this root
 * PRODUCED the code found there: an account reaching that address by a colliding route would pass.
 * The record is written only after this contract's own CREATE2 has succeeded, so it attests the
 * creation itself.
 *
 * THE SALT IS THE ATTESTOR, so a verifier's address commits to its only configuration: two
 * attestors cannot share an address, and re-creating an existing one reverts instead of producing a
 * second verifier.
 */
contract ImmutableAttestationVerifierFactoryPrototype is IKernelVerifierAuthority {
    /// @notice True exactly for verifiers this contract created. Written in one place; never cleared.
    mapping(address => bool) public override isAdmissibleVerifier;

    event VerifierDeployed(address indexed verifier, address indexed attestor);

    /// @notice Creates the Generation-1 verifier for an attestor. Permissionless: creation confers no authority.
    function deployVerifier(address attestor) external returns (address verifier) {
        verifier = address(new ImmutableAttestationPQCVerifier{salt: bytes32(uint256(uint160(attestor)))}(attestor));
        isAdmissibleVerifier[verifier] = true;
        emit VerifierDeployed(verifier, attestor);
    }
}
