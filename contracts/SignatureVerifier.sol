// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SignatureVerifier
 * @dev Provides reusable signature verification functions, including ECDSA and WOTS+.
 */
contract SignatureVerifier {
    using ECDSA for bytes32;

    uint256 constant W = 16;
    uint256 constant LEN1 = 64;
    uint256 constant LEN2 = 3;
    uint256 constant LEN = LEN1 + LEN2;

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

    /**
     * @dev Verifies a WOTS+ signature against a public key hash.
     * @param messageHash The hash of the message signed.
     * @param signature The WOTS+ signature (67 elements of 32 bytes).
     * @param expectedPubKeyHash The expected hash of the recovered public key.
     */
    function verifyWOTS(
        bytes32 messageHash,
        bytes32[] calldata signature,
        bytes32 expectedPubKeyHash
    ) public pure returns (bool) {
        require(signature.length == LEN, "Invalid signature length");

        uint256[] memory lengths = getMessageLengths(messageHash);
        bytes32[] memory recoveredPubKey = new bytes32[](LEN);

        for (uint256 i = 0; i < LEN; i++) {
            bytes32 chain = signature[i];
            for (uint256 j = lengths[i]; j < W - 1; j++) {
                chain = sha256(abi.encodePacked(chain));
            }
            recoveredPubKey[i] = chain;
        }

        bytes32 actualPubKeyHash = keccak256(abi.encodePacked(recoveredPubKey));
        return actualPubKeyHash == expectedPubKeyHash;
    }

    function getMessageLengths(bytes32 messageHash) internal pure returns (uint256[] memory) {
        uint256[] memory lengths = new uint256[](LEN);
        uint256 checksum = 0;
        bytes memory msgBytes = abi.encodePacked(messageHash);

        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(msgBytes[i]);
            uint256 left = (b >> 4) & 0x0f;
            uint256 right = b & 0x0f;
            lengths[i * 2] = left;
            lengths[i * 2 + 1] = right;
            checksum += (W - 1 - left);
            checksum += (W - 1 - right);
        }

        // Checksum lengths
        for (uint256 i = 0; i < LEN2; i++) {
            uint256 val = (checksum >> (4 * (LEN2 - 1 - i))) & 0x0f;
            lengths[LEN1 + i] = val;
        }

        return lengths;
    }
}
