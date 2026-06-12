// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ForceSend
 * @notice TEST ONLY helper that force-sends ETH to an arbitrary address via
 *         selfdestruct, bypassing any receive()/fallback guard.
 * @dev Used to verify that forced ETH cannot corrupt the vault's internal
 *      per-owner balance accounting. No production purpose.
 */
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
