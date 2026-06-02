// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SignatureVerifier
 * @dev Provides reusable signature verification functions, including ECDSA.
 */
contract SignatureVerifier {
    using ECDSA for bytes32;

    /**
     * @dev Verifies an ECDSA signature.
     */
    function verifyECDSA(
        address signer,
        bytes32 messageHash,
        bytes calldata signature
    ) public pure returns (bool) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        return ethSignedMessageHash.recover(signature) == signer;
    }
}
