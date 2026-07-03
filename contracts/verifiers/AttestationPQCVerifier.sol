// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
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
contract AttestationPQCVerifier is IPQCVerifier, Ownable2Step, EIP712 {
    bytes32 public constant ATTESTED_ML_DSA_65_ALGORITHM_ID = keccak256("ATTESTED-ML-DSA-65");

    /**
     * @dev EIP-712 type of the attestor's statement. NOTE on replay: this
     *      attestation is a REPLAYABLE BEARER TOKEN until `deadline`. There is no
     *      nonce or one-time-use marker in this typehash and `verify` is `view`,
     *      so it consumes no state — the SAME attestation payload verifies
     *      successfully any number of times while `block.timestamp <= deadline`.
     *      `deadline` is therefore the SOLE DIRECT replay bound and callers MUST
     *      keep it short. Replay is otherwise bounded only TRANSITIVELY: the
     *      `withdrawalDigest` that is attested to is expected to already commit to
     *      the vault's per-withdrawal nonce, so a replayed attestation can only
     *      re-authorize the exact same withdrawal, which the consuming vault's own
     *      nonce accounting is expected to reject on the second attempt. This
     *      contract does not and cannot enforce that vault-side invariant itself.
     */
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

    /**
     * @notice Verifies a trusted attestor's EIP-712 statement that an ML-DSA-65
     *         signature over `digest` was checked off-chain.
     * @dev REPLAY SEMANTICS (trust concession — read before integrating):
     *      This function is `view` and consumes NO state, so it enforces NO
     *      one-time-use. Any caller holding a valid attestation payload can pass
     *      it here successfully an unlimited number of times until it expires.
     *      The `deadline` field embedded in `signature` is the SOLE DIRECT replay
     *      bound; callers MUST keep it short. Beyond `deadline`, replay is bounded
     *      only TRANSITIVELY by the vault nonce that is expected to be baked into
     *      the attested `withdrawalDigest`: a replayed attestation re-authorizes
     *      only the identical withdrawal, which the consuming vault's own nonce
     *      accounting is expected to reject on re-submission. This verifier does
     *      not track nonces and cannot itself prevent replay within the deadline
     *      window.
     * @param digest The withdrawal digest that was attested to.
     * @param publicKey The ML-DSA public key bytes; its keccak256 must match the
     *        `publicKeyHash` carried in `signature`.
     * @param signature ABI-encoded attestation payload
     *        (bytes attestationSignature, uint256 deadline, bytes32 publicKeyHash,
     *        bytes32 pqSignatureHash). Note `deadline` here is the direct replay
     *        bound described above.
     * @return True iff the payload is well-formed, unexpired, binds the given
     *         public key, and was signed by the configured `attestor`.
     */
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
