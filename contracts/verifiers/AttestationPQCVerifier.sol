// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "../IPQCVerifier.sol";

/**
 * @title AttestationPQCVerifier
 * @notice Verifies a trusted attestor's EIP-712 statement that an ML-DSA-65
 *         signature was successfully checked off-chain.
 * @dev This contract does not verify ML-DSA on-chain. Its security depends on
 *      the configured attestor and the attestor's off-chain verification.
 */
contract AttestationPQCVerifier is IPQCVerifier, Ownable, EIP712 {
    bytes32 public constant ATTESTED_ML_DSA_65_ALGORITHM_ID = keccak256("ATTESTED-ML-DSA-65");

    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)"
    );

    address public attestor;

    error ZeroAttestor();

    event AttestorUpdated(address indexed oldAttestor, address indexed newAttestor);

    constructor(address initialAttestor) Ownable(msg.sender) EIP712("AttestationPQCVerifier", "1") {
        if (initialAttestor == address(0)) revert ZeroAttestor();
        attestor = initialAttestor;
    }

    function algorithmId() external pure override returns (bytes32) {
        return ATTESTED_ML_DSA_65_ALGORITHM_ID;
    }

    function updateAttestor(address newAttestor) external onlyOwner {
        if (newAttestor == address(0)) revert ZeroAttestor();

        address oldAttestor = attestor;
        attestor = newAttestor;
        emit AttestorUpdated(oldAttestor, newAttestor);
    }

    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view override returns (bool) {
        if (!_isWellFormedPayload(signature)) return false;

        (bytes memory attestationSignature, uint256 deadline, bytes32 publicKeyHash, bytes32 pqSignatureHash) = abi
            .decode(signature, (bytes, uint256, bytes32, bytes32));

        if (block.timestamp > deadline || publicKeyHash != keccak256(publicKey)) return false;

        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                digest,
                publicKeyHash,
                pqSignatureHash,
                ATTESTED_ML_DSA_65_ALGORITHM_ID,
                address(this),
                block.chainid,
                deadline
            )
        );
        bytes32 attestationDigest = _hashTypedDataV4(structHash);
        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(attestationDigest, attestationSignature);

        return error == ECDSA.RecoverError.NoError && recovered == attestor;
    }

    function _isWellFormedPayload(bytes calldata payload) private pure returns (bool) {
        if (payload.length < 160) return false;

        uint256 signatureOffset;
        uint256 signatureLength;
        assembly ("memory-safe") {
            signatureOffset := calldataload(payload.offset)
            signatureLength := calldataload(add(payload.offset, 128))
        }

        if (signatureOffset != 128 || signatureLength > payload.length - 160) return false;

        uint256 paddedSignatureLength = (signatureLength + 31) & ~uint256(31);
        return payload.length == 160 + paddedSignatureLength;
    }
}
