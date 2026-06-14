// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/ZKMLDSAVerifier.sol";

/**
 * @title MockSP1Verifier
 * @notice A mock of the SP1 verifier for testing.
 */
contract MockSP1Verifier is ISP1Verifier {
    bool public shouldSucceed = true;

    function setShouldSucceed(bool _shouldSucceed) external {
        shouldSucceed = _shouldSucceed;
    }

    function verifyProof(
        bytes32 /*programVKey*/,
        bytes calldata /*publicValues*/,
        bytes calldata /*proofBytes*/
    ) external view {
        if (!shouldSucceed) {
            revert("MockSP1Verifier: invalid proof");
        }
    }
}
