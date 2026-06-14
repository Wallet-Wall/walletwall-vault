// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "../IPolicyEngine.sol";

/// @title SanctionsListPolicy
/// @notice Compliance-grade deny list for vault withdrawals.
/// @dev Admin-controlled (not vault-owner-controlled). Blocks any withdrawal
///      whose recipient appears on the list. Intended for OFAC-style screening.
///      Uses Ownable2Step so admin rotation requires explicit acceptance.
contract SanctionsListPolicy is IPolicyEngine, Ownable2Step {
    mapping(address => bool) private _sanctioned;

    event AddressAdded(address indexed account);
    event AddressRemoved(address indexed account);

    constructor() Ownable(msg.sender) {}

    /// @notice Adds a single address to the sanctions list.
    function addToSanctionsList(address account) external onlyOwner {
        _sanctioned[account] = true;
        emit AddressAdded(account);
    }

    /// @notice Adds multiple addresses in one transaction.
    function addBatchToSanctionsList(address[] calldata accounts) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            _sanctioned[accounts[i]] = true;
            emit AddressAdded(accounts[i]);
        }
    }

    /// @notice Removes an address from the sanctions list.
    function removeFromSanctionsList(address account) external onlyOwner {
        _sanctioned[account] = false;
        emit AddressRemoved(account);
    }

    /// @notice Returns true if `account` is currently sanctioned.
    function isSanctioned(address account) external view returns (bool) {
        return _sanctioned[account];
    }

    /// @inheritdoc IPolicyEngine
    function check(
        address,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        if (_sanctioned[recipient]) return (false, "recipient is sanctioned");
        return (true, "");
    }
}
