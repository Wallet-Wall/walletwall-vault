// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
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
contract ZKMLDSAVerifier is IPQCVerifier, Ownable2Step {
    bytes32 public constant ALGORITHM_ID = keccak256("ZK-ML-DSA-65");

    /// @notice The SP1 Verifier contract address.
    address public immutable sp1Verifier;

    /// @notice The verification key for the ML-DSA-65 guest program.
    bytes32 public programVKey;

    event ProgramVKeyUpdated(bytes32 indexed oldVKey, bytes32 indexed newVKey);

    error InvalidProof();
    error MismatchedPublicInput(string field);

    constructor(address _sp1Verifier, bytes32 _programVKey) Ownable(msg.sender) {
        if (_sp1Verifier == address(0)) revert("Zero address");
        sp1Verifier = _sp1Verifier;
        programVKey = _programVKey;
    }

    function algorithmId() external pure override returns (bytes32) {
        return ALGORITHM_ID;
    }

    /**
     * @notice Updates the guest program verification key.
     * @dev Allows for upgrading the guest program (e.g., for optimizations).
     */
    function updateProgramVKey(bytes32 _newVKey) external onlyOwner {
        bytes32 oldVKey = programVKey;
        programVKey = _newVKey;
        emit ProgramVKeyUpdated(oldVKey, _newVKey);
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
        // Decode the public values (journal) and the proof bytes from the payload.
        // The payload format is [uint256 publicValuesOffset][uint256 proofBytesOffset][publicValues][proofBytes]
        if (proof.length < 64) return false;

        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));

        // The journal/public values from our guest program:
        // sp1_zkvm::io::commit(&inputs.withdrawal_digest); (32 bytes)
        // sp1_zkvm::io::commit(&pk_hash); (32 bytes)
        // sp1_zkvm::io::commit(&sig_hash); (32 bytes)
        // sp1_zkvm::io::commit(&inputs.chain_id); (8 bytes, padded to 32)
        // sp1_zkvm::io::commit(&inputs.verifier_address); (20 bytes, padded to 32)

        // Verify the public values against the transaction context to ensure the proof
        // is bound to this specific withdrawal and public key.
        // We expect the journal to be ABI-encoded for robustness and consistency.
        if (publicValues.length < 160) return false;

        (
            bytes32 committedDigest,
            bytes32 committedPkHash,
            ,
            /* bytes32 committedSigHash */ uint64 committedChainId,
            address committedVerifier
        ) = abi.decode(publicValues, (bytes32, bytes32, bytes32, uint64, address));

        if (committedDigest != digest) return false;
        if (committedPkHash != keccak256(publicKey)) return false;
        if (committedChainId != uint64(block.chainid)) return false;
        if (committedVerifier != address(this)) return false;

        // Verify the proof against the SP1 Verifier
        try ISP1Verifier(sp1Verifier).verifyProof(programVKey, publicValues, proofBytes) {
            return true;
        } catch {
            return false;
        }
    }
}
