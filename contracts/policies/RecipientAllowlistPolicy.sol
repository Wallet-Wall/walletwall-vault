// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title RecipientAllowlistPolicy
/// @notice Restricts vault withdrawals to a vault-owner-managed set of addresses.
/// @dev Fail-safe: an empty allowlist blocks ALL recipients.
///      Opt-out: adding address(0) permits any recipient.
///      Admin has no control over individual vault allowlists — each vault owner
///      manages their own set directly.
contract RecipientAllowlistPolicy is IPolicyEngine {
    /// @notice vaultOwner => recipient => allowed
    mapping(address => mapping(address => bool)) public allowlist;

    event RecipientAdded(address indexed vaultOwner, address indexed recipient);
    event RecipientRemoved(address indexed vaultOwner, address indexed recipient);

    /// @notice Adds `recipient` to the caller's allowlist.
    ///         Adding address(0) disables the restriction (all recipients permitted).
    function addRecipient(address recipient) external {
        allowlist[msg.sender][recipient] = true;
        emit RecipientAdded(msg.sender, recipient);
    }

    /// @notice Removes `recipient` from the caller's allowlist.
    function removeRecipient(address recipient) external {
        allowlist[msg.sender][recipient] = false;
        emit RecipientRemoved(msg.sender, recipient);
    }

    /// @inheritdoc IPolicyEngine
    function check(
        address vaultOwner,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        if (allowlist[vaultOwner][address(0)]) return (true, "");
        if (allowlist[vaultOwner][recipient]) return (true, "");
        return (false, "recipient not on allowlist");
    }
}
