// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/ZKMLDSAVerifier.sol";

/**
 * @title ProgramBoundMockSP1Verifier
 * @notice TEST ONLY. A stand-in for an SP1 verifier that, unlike {MockSP1Verifier}, is bound to program
 *         identity: a proof verifies only for a (program vkey, public values) pair a test has registered
 *         as proven. It models SP1 soundness at the program boundary, so tests can show that a verifier
 *         accepts a proof only for the program it pins.
 */
contract ProgramBoundMockSP1Verifier is ISP1Verifier {
    mapping(bytes32 programVKey => mapping(bytes32 publicValuesHash => bool proven)) public proven;

    error ProofNotForProgram(bytes32 programVKey, bytes32 publicValuesHash);

    /// @notice Records that a proof of `programVKey` committing `publicValues` exists.
    function setProven(bytes32 programVKey, bytes calldata publicValues) external {
        proven[programVKey][keccak256(publicValues)] = true;
    }

    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata /*proofBytes*/
    ) external view {
        bytes32 publicValuesHash = keccak256(publicValues);
        if (!proven[programVKey][publicValuesHash]) revert ProofNotForProgram(programVKey, publicValuesHash);
    }
}
