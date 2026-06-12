// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPQCVerifier
 * @notice Trust boundary interface for a post-quantum cryptography (PQC) signature
 *         verifier used by the WalletWall Vault research prototype.
 *
 * @dev RESEARCH PROTOTYPE — NOT AUDITED. The vault treats any contract implementing
 *      this interface as the authority on PQ signature validity. The security of the
 *      PQ authorization layer is therefore entirely delegated to the implementation
 *      behind this interface.
 *
 *      Implementations may range from:
 *        - a mock/local verifier (testing only, NO real cryptographic security),
 *        - a trusted-attestation verifier (off-chain verify + on-chain attestation),
 *        - a ZK-proof verifier (e.g. Groth16/Halo2 proving an ML-DSA verification),
 *        - a future chain-native PQ precompile.
 *
 *      See docs/Verifier_Roadmap.md for the trust assumptions of each path.
 */
interface IPQCVerifier {
    /**
     * @notice Identifier of the post-quantum algorithm/scheme this verifier checks.
     * @dev Used by integrators to assert they are wired to the verifier they expect.
     *      Example convention: keccak256("MOCK-ML-DSA-65") for a mock, or a stable
     *      identifier for a production scheme. This is metadata only and carries no
     *      security guarantee by itself.
     * @return A 32-byte algorithm identifier.
     */
    function algorithmId() external view returns (bytes32);

    /**
     * @notice Verifies a post-quantum signature over a 32-byte digest.
     * @param digest    The 32-byte message digest that was signed (e.g. an EIP-712 hash).
     * @param publicKey The PQ public key bytes registered for the signer.
     * @param signature The PQ signature bytes to verify.
     * @return isValid  True if the signature is considered valid by this verifier.
     */
    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool isValid);
}
