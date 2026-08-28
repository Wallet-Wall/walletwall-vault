// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice TEST ONLY. Records the last bridge-forwarded enrollController call so the
///         bridge's authentication pipeline (domain, nonce, deadline, epoch, dual
///         ECDSA/PQ signature-against-current-credentials) can be unit tested against a
///         target that isn't the full DailySpendLimitPolicy state machine.
contract PolicyControlTargetMock {
    address public lastCaller;
    address public lastConsumer;
    address public lastOwner;
    address public lastAsset;
    address public lastController;
    uint256 public callCount;

    function bridgeEnrollController(address consumer, address owner, address asset, address controller) external {
        lastCaller = msg.sender;
        lastConsumer = consumer;
        lastOwner = owner;
        lastAsset = asset;
        lastController = controller;
        callCount++;
    }
}
