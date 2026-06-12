// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

/**
 * @title AlwaysFalsePQCVerifier
 * @notice TEST ONLY verifier that always reports a signature as invalid.
 * @dev Used in the test suite to prove that a rejecting PQC verifier blocks
 *      withdrawals at the trust boundary. Has no production purpose.
 */
contract AlwaysFalsePQCVerifier is IPQCVerifier {
    function algorithmId() external pure override returns (bytes32) {
        return keccak256("TEST-ALWAYS-FALSE");
    }

    function verify(
        bytes32 /* digest */,
        bytes calldata /* publicKey */,
        bytes calldata /* signature */
    ) external pure override returns (bool) {
        return false;
    }
}
