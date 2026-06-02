// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPQSignatureVerifier
 * @dev Interface for NIST Post-Quantum Cryptography (PQC) signature verification.
 */
interface IPQSignatureVerifier {
    /**
     * @dev Verifies a PQC signature.
     * @param publicKey The NIST PQ public key.
     * @param messageHash The hash of the message signed.
     * @param signature The PQC signature.
     * @return bool True if the signature is valid, false otherwise.
     */
    function verify(
        bytes calldata publicKey,
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool);
}
