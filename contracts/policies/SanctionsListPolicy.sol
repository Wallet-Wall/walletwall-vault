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

    /// @dev Single predicate shared by {check} and {revalidate} so admission and
    ///      finalization revalidation cannot diverge. Always evaluates the CURRENT
    ///      sanctions state — a recipient sanctioned after a withdrawal was queued
    ///      is therefore caught at finalization.
    function _evaluate(address recipient) internal view returns (bool allowed, string memory reason) {
        if (_sanctioned[recipient]) return (false, "recipient is sanctioned");
        return (true, "");
    }

    /// @inheritdoc IPolicyEngine
    /// @dev The {PolicySubject} is accepted and ignored in full — this policy screens
    ///      the RECIPIENT against a global list, so it is neither tenant-scoped nor
    ///      consumer-scoped nor asset-scoped. A sanctioned address is sanctioned for
    ///      everyone. Naming the parameter would imply a scoping that does not exist.
    function check(
        PolicySubject calldata,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        return _evaluate(recipient);
    }

    /// @inheritdoc IPolicyEngine
    function revalidate(
        PolicySubject calldata,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        return _evaluate(recipient);
    }
}
