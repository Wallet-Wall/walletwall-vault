// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

/**
 * @title AlwaysTruePQCVerifier
 * @notice TEST ONLY verifier that always reports a signature as valid and reports a
 *         NON-mock algorithm id.
 * @dev Used to exercise the PqOnly path against a verifier the vault does not treat as
 *      the disabled mock. It performs NO real cryptographic verification and has no
 *      production purpose — it exists only to stand in for a "real" verifier in tests.
 */
contract AlwaysTruePQCVerifier is IPQCVerifier {
    function algorithmId() external pure override returns (bytes32) {
        return keccak256("TEST-ALWAYS-TRUE");
    }

    function verify(
        bytes32 /* digest */,
        bytes calldata /* publicKey */,
        bytes calldata /* signature */
    ) external pure override returns (bool) {
        return true;
    }
}
