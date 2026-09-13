// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "../IPQCVerifier.sol";

/**
 * @title ImmutableAttestationPQCVerifier
 * @notice Verifies a trusted attestor's EIP-712 statement that an ML-DSA-65
 *         signature was successfully checked off-chain. The attestor is fixed at
 *         deployment and can never be changed.
 * @dev Recommended near-term deployment choice over the mutable
 *      `AttestationPQCVerifier`: it removes the owner-controlled `updateAttestor`
 *      authority entirely instead of timelocking it. Changing the attestor means
 *      deploying a new verifier and switching `WalletWallVault` to it through the
 *      vault's existing timelocked `proposePQVerifier` / `applyPQVerifierUpdate`
 *      governance, so an attestor change inherits the vault's two-day review
 *      window instead of taking effect instantly. See
 *      docs/Attestation_Governance_Hardening.md.
 *
 *      This contract does not verify ML-DSA on-chain. Its security depends on the
 *      configured attestor and the attestor's off-chain verification — the same
 *      trust model as `AttestationPQCVerifier`, minus the in-place-rotation admin
 *      surface. It reuses the identical EIP-712 domain (name/version), typehash,
 *      algorithm id, and verifier payload ABI so existing attestation tooling
 *      (e.g. `scripts/attestor-cli.ts`) can target either deployment unmodified,
 *      as long as it is pointed at the correct verifier address.
 */
contract ImmutableAttestationPQCVerifier is IPQCVerifier, EIP712 {
    bytes32 public constant ATTESTED_ML_DSA_65_ALGORITHM_ID = keccak256("ATTESTED-ML-DSA-65");

    /**
     * @dev EIP-712 type of the attestor's statement. Identical semantics to
     *      `AttestationPQCVerifier.ATTESTATION_TYPEHASH`, including its replay
     *      trust concession: this attestation is a replayable bearer token until
     *      `deadline`, bounded directly only by that deadline and transitively by
     *      the vault nonce expected to be baked into `withdrawalDigest`. See that
     *      contract's NatSpec for the full discussion.
     */
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)"
    );

    /// @notice The sole attestation authority for this verifier deployment. Fixed
    ///         at construction; there is no setter and no admin/owner surface of
    ///         any kind. Changing the attestor requires deploying a new verifier.
    address public immutable attestor;

    error ZeroAttestor();

    constructor(address initialAttestor) EIP712("AttestationPQCVerifier", "1") {
        if (initialAttestor == address(0)) revert ZeroAttestor();
        attestor = initialAttestor;
    }

    function algorithmId() external pure override returns (bytes32) {
        return ATTESTED_ML_DSA_65_ALGORITHM_ID;
    }

    /**
     * @notice Verifies a trusted attestor's EIP-712 statement that an ML-DSA-65
     *         signature over `digest` was checked off-chain.
     * @dev Same replay semantics, payload ABI, and binding properties as
     *      `AttestationPQCVerifier.verify` (payload shape, deadline, public-key
     *      hash, EIP-712 recovery, verifier-address and chain-id binding). The
     *      only behavioral difference from that contract is that `attestor` here
     *      can never change after deployment.
     * @param digest The withdrawal digest that was attested to.
     * @param publicKey The ML-DSA public key bytes; its keccak256 must match the
     *        `publicKeyHash` carried in `signature`.
     * @param signature ABI-encoded attestation payload
     *        (bytes attestationSignature, uint256 deadline, bytes32 publicKeyHash,
     *        bytes32 pqSignatureHash).
     * @return True iff the payload is well-formed, unexpired, binds the given
     *         public key, and was signed by the immutable `attestor`.
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
