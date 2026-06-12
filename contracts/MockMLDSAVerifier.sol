// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";

/**
 * @title MockMLDSAVerifier
 * @notice TEST / DEMO ONLY mock that mimics the *interface* and *I/O shape* of an
 *         ML-DSA-65 (FIPS 204, formerly CRYSTALS-Dilithium) signature verifier.
 *
 * @dev  =======================================================================
 *       DO NOT USE IN PRODUCTION. DO NOT USE WITH REAL FUNDS.
 *       THIS CONTRACT PERFORMS *NO* CRYPTOGRAPHIC VERIFICATION OF ML-DSA.
 *       =======================================================================
 *
 *       This mock exists so the WalletWall Vault research prototype can exercise
 *       its verifier trust boundary, replay protection, and hybrid-authorization
 *       flow on a local/testnet network without a real on-chain PQC verifier
 *       (which today is impractical to run natively in the EVM).
 *
 *       What it actually checks (and ONLY this):
 *         1. The public key length matches ML-DSA-65 (1952 bytes).
 *         2. The signature length matches ML-DSA-65 (3309 bytes).
 *         3. The signature is not entirely zero in its first 32 bytes.
 *
 *       It does NOT verify the lattice signature, does NOT bind the signature to
 *       the public key, and does NOT bind the signature to the digest. A real
 *       ML-DSA signature produced off-chain will pass, but so will any well-formed
 *       non-zero blob of the correct length. Treat a passing result as
 *       "structurally plausible", never as "cryptographically authorized".
 *
 *       Real verification must come from one of the paths described in
 *       docs/Verifier_Roadmap.md (trusted attestation, ZK proof, or chain-native
 *       PQ precompile).
 */
contract MockMLDSAVerifier is IPQCVerifier {
    /// @dev ML-DSA-65 (Dilithium3) public key size, in bytes.
    uint256 public constant ML_DSA_65_PUBLIC_KEY_LENGTH = 1952;

    /// @dev ML-DSA-65 (Dilithium3) signature size, in bytes.
    uint256 public constant ML_DSA_65_SIGNATURE_LENGTH = 3309;

    /**
     * @inheritdoc IPQCVerifier
     * @dev Returns a clearly mock-tagged identifier so integrators can detect that
     *      a non-production verifier is wired in.
     */
    function algorithmId() external pure override returns (bytes32) {
        return keccak256("MOCK-ML-DSA-65");
    }

    /**
     * @inheritdoc IPQCVerifier
     * @dev MOCK verification. See contract-level docs: this is structural only and
     *      provides NO cryptographic guarantee. Test/demo use exclusively.
     */
    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata signature
    ) external pure override returns (bool) {
        // Reject the empty digest to surface obviously malformed requests in tests.
        if (digest == bytes32(0)) {
            return false;
        }

        // Structural length checks mirroring ML-DSA-65 (NOT a security check).
        if (publicKey.length != ML_DSA_65_PUBLIC_KEY_LENGTH || signature.length != ML_DSA_65_SIGNATURE_LENGTH) {
            return false;
        }

        // Reject an all-zero signature prefix so a trivially empty signature fails.
        // NOTE: this is purely a smoke test, NOT signature verification.
        for (uint256 i = 0; i < 32; i++) {
            if (signature[i] != 0) {
                return true;
            }
        }

        return false;
    }
}
