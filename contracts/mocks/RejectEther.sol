// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RejectEther
 * @notice TEST ONLY contract that reverts on any incoming ETH transfer.
 * @dev Used to exercise the vault's TransferFailed path. No production purpose.
 */
contract RejectEther {
    error EtherRejected();

    receive() external payable {
        revert EtherRejected();
    }
}
