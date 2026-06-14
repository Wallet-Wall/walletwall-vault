// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPolicyEngine
/// @notice Optional per-vault withdrawal policy hook for WalletWallVault.
/// @dev The vault calls check() before executing or queuing any withdrawal.
///      A denial reverts with PolicyViolation(reason). The engine is wired in
///      via a timelocked admin flow identical to IPQCVerifier — propose, wait
///      two days, apply. address(0) means no policy (feature disabled).
///
///      Implementations may be stateless (RecipientAllowlistPolicy) or
///      stateful (DailySpendLimitPolicy). The non-view declaration allows
///      stateful implementations; view/pure implementations satisfy it too.
interface IPolicyEngine {
    /// @notice Validates a pending withdrawal against this policy.
    /// @param vaultOwner   The vault whose funds are being withdrawn.
    /// @param recipient    The destination address.
    /// @param amount       The ETH amount in wei.
    /// @param vaultBalance The vault's current balance before deduction.
    /// @return allowed True if the withdrawal is permitted.
    /// @return reason  Human-readable denial reason; empty string when allowed.
    function check(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason);
}
