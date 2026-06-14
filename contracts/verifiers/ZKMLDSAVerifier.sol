// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

/**
 * @notice Interface for the auto-generated SP1 Verifier (Groth16/Plonk).
 * @dev See https://docs.succinct.xyz/docs/sp1/verification/solidity
 */
interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

/**
 * @title ZKMLDSAVerifier
 * @notice Trustless verification of ML-DSA-65 signatures using ZK proofs.
 * @dev Replaces the trusted-attestation model with a cryptographic proof.
 */
contract ZKMLDSAVerifier is IPQCVerifier {
    bytes32 public constant ALGORITHM_ID = keccak256("ZK-ML-DSA-65");

    /// @notice The SP1 Verifier contract address.
    address public immutable SP1_VERIFIER;

    /// @notice The verification key for the ML-DSA-65 guest program.
    bytes32 public immutable PROGRAM_VKEY;

    error InvalidSP1Verifier();
    error InvalidProgramVKey();
    error InvalidProof();

    constructor(address _sp1Verifier, bytes32 _programVKey) {
        if (_sp1Verifier.code.length == 0) revert InvalidSP1Verifier();
        if (_programVKey == bytes32(0)) revert InvalidProgramVKey();
        SP1_VERIFIER = _sp1Verifier;
        PROGRAM_VKEY = _programVKey;
    }

    function algorithmId() external pure override returns (bytes32) {
        return ALGORITHM_ID;
    }

    /**
     * @notice Verifies an ML-DSA-65 signature via a ZK proof.
     * @param digest The 32-byte message digest.
     * @param publicKey The raw public key bytes.
     * @param proof The encoded ZK proof (publicValues + proofBytes).
     */
    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata proof
    ) external view override returns (bool) {
        bytes memory publicValues;
        bytes memory proofBytes;
        bytes32 committedDigest;
        bytes32 committedPkHash;
        uint64 committedChainId;
        address committedVerifier;

        try this.decodeProofPayload(proof) returns (
            bytes memory decodedPublicValues,
            bytes memory decodedProofBytes,
            bytes32 decodedDigest,
            bytes32 decodedPkHash,
            uint64 decodedChainId,
            address decodedVerifier
        ) {
            publicValues = decodedPublicValues;
            proofBytes = decodedProofBytes;
            committedDigest = decodedDigest;
            committedPkHash = decodedPkHash;
            committedChainId = decodedChainId;
            committedVerifier = decodedVerifier;
        } catch {
            return false;
        }

        if (committedDigest != digest) return false;
        if (committedPkHash != keccak256(publicKey)) return false;
        if (committedChainId != uint64(block.chainid)) return false;
        if (committedVerifier != address(this)) return false;

        // Verify the proof against the SP1 Verifier
        try ISP1Verifier(SP1_VERIFIER).verifyProof(PROGRAM_VKEY, publicValues, proofBytes) {
            return true;
        } catch {
            return false;
        }
    }

    /**
     * @dev External pure decoder so verify() can catch malformed dynamic ABI offsets
     *      and preserve the IPQCVerifier false-on-invalid contract.
     */
    function decodeProofPayload(
        bytes calldata proof
    )
        external
        pure
        returns (
            bytes memory publicValues,
            bytes memory proofBytes,
            bytes32 committedDigest,
            bytes32 committedPkHash,
            uint64 committedChainId,
            address committedVerifier
        )
    {
        (publicValues, proofBytes) = abi.decode(proof, (bytes, bytes));
        if (publicValues.length != 160 || proofBytes.length == 0) revert InvalidProof();

        (committedDigest, committedPkHash, , /* bytes32 committedSigHash */ committedChainId, committedVerifier) = abi
            .decode(publicValues, (bytes32, bytes32, bytes32, uint64, address));
    }
}
