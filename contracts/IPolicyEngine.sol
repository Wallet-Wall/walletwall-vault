// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPolicyEngine
/// @notice Optional per-vault withdrawal policy hook for WalletWallVault and
///         StablecoinVaultSimulator. The engine is wired in via a timelocked
///         admin flow identical to IPQCVerifier — propose, wait two days,
///         apply. address(0) means no policy (feature disabled).
///
/// @dev The interface deliberately splits two different duties:
///
///      - {check} is ADMISSION: it runs when a withdrawal is committed
///        (immediate `withdraw` and `queueWithdrawal`). It MAY mutate policy
///        accounting — e.g. DailySpendLimitPolicy books spend into its 24-hour
///        window here, exactly once per withdrawal. That window is currently a
///        TUMBLING/reset window, not the rolling one its product invariant calls
///        for; see the window semantics note on DailySpendLimitPolicy.
///
///      - {revalidate} is FINALIZATION REVALIDATION: it runs when a queued
///        withdrawal settles (`finalizeWithdrawal`). It answers "given CURRENT
///        policy state, may this amount still be paid to this recipient?" and
///        MUST NOT mutate anything. It is declared `view`, so vaults invoke it
///        via STATICCALL — an implementation that attempts to write state makes
///        finalization revert (fail-closed) rather than corrupting accounting.
///        Finalization never calls {check}; re-running stateful admission would
///        double-book accounting already settled at queue time.
///
///      Implementations may be stateless (RecipientAllowlistPolicy,
///      SanctionsListPolicy) or stateful (DailySpendLimitPolicy). For a
///      stateless policy the two methods are the same predicate over current
///      state; for a stateful policy {revalidate} asserts only whatever remains
///      meaningful at settlement time, never re-booking admission accounting.
interface IPolicyEngine {
    /// @notice Validates AND admits a withdrawal against this policy.
    /// @dev Called by the vault inside `withdraw` and `queueWithdrawal`, before
    ///      any vault state changes. A denial reverts the vault with
    ///      PolicyViolation(reason). Non-view so stateful implementations can
    ///      record admission accounting; view/pure implementations satisfy it too.
    /// @param vaultOwner   The vault whose funds are being withdrawn.
    /// @param recipient    The destination address.
    /// @param amount       The withdrawal amount (wei / token base units).
    /// @param vaultBalance The vault's accounted balance BEFORE this
    ///                     withdrawal's `amount` is deducted.
    /// @return allowed True if the withdrawal is permitted.
    /// @return reason  Human-readable denial reason; empty string when allowed.
    function check(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason);

    /// @notice Re-validates an already-admitted withdrawal at finalization time.
    /// @dev Called by the vault inside `finalizeWithdrawal` for the engine that
    ///      admitted the withdrawal at queue time AND for the currently active
    ///      engine (once, if they are the same). MUST be free of side effects:
    ///      the interface declares it `view`, so the vault's call executes as a
    ///      STATICCALL regardless of the implementation's declared mutability —
    ///      any attempted state write reverts the finalization.
    ///      A revert (including from a non-conforming engine) fails the
    ///      finalization closed; the owner can always cancel and re-queue.
    /// @param vaultOwner   The vault whose funds are being withdrawn.
    /// @param recipient    The destination address.
    /// @param amount       The withdrawal amount (wei / token base units).
    /// @param vaultBalance The vault's CURRENT accounted balance exclusive of this
    ///                     withdrawal's reservation, computed at finalization as
    ///                     `current accounted balance + reserved amount`. This is the
    ///                     same "balance before this withdrawal's deduction" SEMANTIC
    ///                     as {check}, but it is a LIVE figure, not the admission-time
    ///                     snapshot: deposits (including third-party depositFor) or
    ///                     immediate withdrawals between queueing and finalization
    ///                     move it in either direction. A balance-sensitive
    ///                     revalidation must treat it accordingly.
    /// @return allowed True if settlement is still permitted under current state.
    /// @return reason  Human-readable denial reason; empty string when allowed.
    function revalidate(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external view returns (bool allowed, string memory reason);
}
