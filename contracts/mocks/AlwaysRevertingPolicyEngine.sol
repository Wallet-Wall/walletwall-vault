// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @notice TEST ONLY. Reverts on every call. Used to prove that vault recovery
///         (executeRecovery) makes no call into any policy contract — if it did, this
///         engine installed would make recovery itself revert, which would be a
///         liveness regression severe enough to lose a vault permanently.
contract AlwaysRevertingPolicyEngine is IPolicyEngine {
    error AlwaysReverts();

    function check(
        PolicySubject calldata,
        address,
        uint256,
        uint256
    ) external pure override returns (bool, string memory) {
        revert AlwaysReverts();
    }

    function revalidate(
        PolicySubject calldata,
        address,
        uint256,
        uint256
    ) external pure override returns (bool, string memory) {
        revert AlwaysReverts();
    }
}
