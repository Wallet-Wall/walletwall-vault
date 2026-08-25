// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title RecipientAllowlistPolicy
/// @notice Restricts vault withdrawals to a vault-owner-managed set of addresses.
/// @dev Fail-safe: an empty allowlist blocks ALL recipients.
///      Opt-out: adding address(0) permits any recipient.
///      Admin has no control over individual vault allowlists — each vault owner
///      manages their own set directly.
///
///      SUBJECT SCOPE: DELIBERATELY OWNER-KEYED. This policy receives the full
///      {PolicySubject} but keys its allowlist on `subject.owner` alone, ignoring
///      `consumer` and `asset`. That is a decision about what KIND of policy this is,
///      not an oversight. An allowlist is an ADDRESS PREDICATE: "may this tenant pay
///      this recipient". It is idempotent and consumes nothing, so evaluating it from
///      two different consumers, or for two different assets, yields the same answer
///      and leaves no residue — there is no bucket for two consumers to race for.
///      Dimensioning it would force every tenant to re-declare an identical allowlist
///      per vault and per asset, buying no isolation.
///
///      Contrast {DailySpendLimitPolicy}, which is a QUANTITY ACCUMULATOR over a finite
///      budget: there, two consumers sharing one bucket is exactly the defect, so it
///      keys on all three dimensions. The distinction — predicate versus accumulator —
///      is the reason these two policies key differently, and any new module should be
///      classified the same way before choosing its key.
///
///      No asset semantics are invented here: `subject.asset` is not read at all,
///      rather than being folded in as a pretend dimension.
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

    /// @dev Single predicate shared by {check} and {revalidate} so admission and
    ///      finalization revalidation cannot diverge. Always evaluates the CURRENT
    ///      allowlist state — a recipient removed after a withdrawal was queued is
    ///      therefore caught at finalization; a recipient re-added before
    ///      finalization is permitted again.
    function _evaluate(
        address vaultOwner,
        address recipient
    ) internal view returns (bool allowed, string memory reason) {
        if (allowlist[vaultOwner][address(0)]) return (true, "");
        if (allowlist[vaultOwner][recipient]) return (true, "");
        return (false, "recipient not on allowlist");
    }

    /// @inheritdoc IPolicyEngine
    function check(
        PolicySubject calldata subject,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        return _evaluate(subject.owner, recipient);
    }

    /// @inheritdoc IPolicyEngine
    function revalidate(
        PolicySubject calldata subject,
        address recipient,
        uint256,
        uint256
    ) external view override returns (bool allowed, string memory reason) {
        return _evaluate(subject.owner, recipient);
    }
}
