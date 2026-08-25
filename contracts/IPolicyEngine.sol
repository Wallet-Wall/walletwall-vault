// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The canonical identity of WHAT a policy evaluation is about.
/// @dev Three dimensions, assembled by the ORIGINATING vault and relayed unchanged to
///      every module. None is attacker-chosen at the point of use, but they earn that
///      status in two different ways and the difference is part of the contract:
///      `consumer` and `asset` are trusted BY PROVENANCE (read from the vault's own
///      execution context, never present in the request), while `owner` is trusted BY
///      AUTHENTICATION — it is request-body data whose safety rests entirely on the
///      EIP-712 signature check the vault performs before calling. A consumer that
///      supplies `owner` without that check would break this interface's guarantees
///      while still satisfying its types.
///
///      The three dimensions:
///
///      - `consumer` — the vault contract that originated this decision. It is always
///        `address(this)` at the mint site, so a vault cannot misreport it, and it is
///        NOT re-derived downstream: under {CompositePolicyEngine} a module's
///        `msg.sender` is the COMPOSITE, so deriving consumer from `msg.sender` at the
///        module would collapse every vault behind one composite into a single
///        identity. That collapse is the exact defect this struct exists to remove.
///
///      - `owner` — the tenant whose vault balance and accounting are at stake. This is
///        the withdrawal request's `vaultOwner`, which the vault has already bound to
///        `vault.ecdsaSigner` / `vault.pqPublicKey` by EIP-712 signature before any
///        policy call is made. It is deliberately NOT `msg.sender`: withdrawal relay is
///        permissionless, so at the vault `msg.sender` carries no identity at all.
///
///      - `asset` — the denomination of `amount`. `address(0)` means native ETH; any
///        other value is the ERC-20 token contract. Both current consumers are
///        single-asset and fix this from immutable state, so no caller ever chooses it.
///
///      WHY ASSET IS NOT DERIVED FROM CONSUMER. Today `asset` happens to be a function
///      of `consumer` — WalletWallVault is ETH-only, StablecoinVaultSimulator is bound
///      to one immutable token. Collapsing the dimension on that basis would encode a
///      property of the current consumer SET, not of the boundary, and would have to be
///      unpicked by the first multi-asset consumer. It stays explicit.
///
///      ORDER IS PART OF THE CONTRACT. Any downstream keying derived from this struct
///      must bind all three fields unambiguously — see {DailySpendLimitPolicy.subjectKey}.
struct PolicySubject {
    address consumer;
    address owner;
    address asset;
}

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
///        accounting — e.g. DailySpendLimitPolicy books spend into its
///        window here, exactly once per withdrawal.
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
///
///      SUBJECT IDENTITY CROSSES THE BOUNDARY EXPLICITLY. Both methods take a
///      {PolicySubject} rather than a bare `vaultOwner`, so no module can receive a
///      withdrawal whose originating consumer or asset has been erased. There is
///      deliberately NO subjectless overload: a legacy engine wired into a vault built
///      against this interface fails its selector lookup, which reverts admission and
///      is reported as PolicyEngineUnavailable at settlement — fail-closed in both
///      directions, which is the correct outcome for an engine that cannot express the
///      identity the vault is asserting.
interface IPolicyEngine {
    /// @notice Validates AND admits a withdrawal against this policy.
    /// @dev Called by the vault inside `withdraw` and `queueWithdrawal`, before
    ///      any vault state changes. A denial reverts the vault with
    ///      PolicyViolation(reason). Non-view so stateful implementations can
    ///      record admission accounting; view/pure implementations satisfy it too.
    ///
    ///      A stateful implementation MUST select its accounting by the full
    ///      {PolicySubject}, and MUST NOT treat any subject field as an authorization:
    ///      the subject says WHICH accounting is referenced, never WHO may mutate it.
    ///      Authority is a separate question answered from `msg.sender` — see
    ///      {DailySpendLimitPolicy.setAdmitter}.
    /// @param subject      Canonical (consumer, owner, asset) identity of this
    ///                     evaluation, minted by the originating vault.
    /// @param recipient    The destination address.
    /// @param amount       The withdrawal amount, denominated in `subject.asset`
    ///                     (wei for address(0), token base units otherwise).
    /// @param vaultBalance The vault's accounted balance BEFORE this
    ///                     withdrawal's `amount` is deducted.
    /// @return allowed True if the withdrawal is permitted.
    /// @return reason  Human-readable denial reason; empty string when allowed.
    function check(
        PolicySubject calldata subject,
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
    ///
    ///      The subject supplied here is reconstructed by the vault from the SAME
    ///      trusted sources as at admission — `address(this)`, the pending
    ///      withdrawal's recorded owner, and the vault's fixed asset — so a queued
    ///      withdrawal cannot settle under a different identity than it was admitted
    ///      under.
    /// @param subject      Canonical (consumer, owner, asset) identity, identical to
    ///                     the one supplied at admission for this withdrawal.
    /// @param recipient    The destination address.
    /// @param amount       The withdrawal amount, denominated in `subject.asset`.
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
        PolicySubject calldata subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external view returns (bool allowed, string memory reason);
}
