// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title Ownership-renunciation mutation controls
 * @notice TEST-ONLY deliberate mutants. Never deployed, never imported by
 *         production code. They exist so the regression suite can prove its
 *         discriminators actually discriminate.
 *
 * @dev An assertion that only ever passes proves nothing. Each contract here
 *      reproduces the production ownership/pause shape with EXACTLY ONE guard
 *      removed, so a kill is attributable to that one guard.
 */

/**
 * @notice M1 — the pre-fix production shape: `Ownable2Step` + `Pausable` with
 *         `renounceOwnership` left INHERITED.
 * @dev This is the control that makes the T0 claim checkable rather than
 *      rhetorical. `Ownable2Step` overrides `pendingOwner`, `transferOwnership`,
 *      `_transferOwnership` and `acceptOwnership` — but not `renounceOwnership`
 *      — so the inherited `public virtual onlyOwner` version is reachable and
 *      sets the owner to `address(0)`.
 *
 *      `criticalOperation()` stands in for the `whenNotPaused` production
 *      surface (withdraw / queueWithdrawal / finalizeWithdrawal /
 *      rotateCredentials / initiateRecovery / executeRecovery). The suite drives
 *      pause -> renounce -> and then observes REAL STATE: the owner really is
 *      zero, `unpause()` really does revert for every caller, and
 *      `criticalOperation()` really is unreachable with no transaction able to
 *      restore it. The permanence is exercised, not asserted.
 */
contract RenounceableOwnableMutant is Ownable2Step, Pausable {
    constructor() Ownable(msg.sender) {}

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /// @dev Stands in for every `whenNotPaused` production entrypoint.
    function criticalOperation() external view whenNotPaused returns (bool) {
        return true;
    }
}

/**
 * @notice M4 — renunciation is correctly blocked, but `transferOwnership` has
 *         lost its `onlyOwner` guard.
 * @dev Models the failure mode where a fix to one ownership transition silently
 *      opens another. The production suite must reject this: closing the
 *      renunciation path must not hand any non-owner an ownership-changing path.
 */
contract UnguardedTransferMutant is Ownable2Step, Pausable {
    error OwnershipRenunciationDisabled();

    constructor() Ownable(msg.sender) {}

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function renounceOwnership() public pure override {
        revert OwnershipRenunciationDisabled();
    }

    /// @dev THE MUTATION, and the only one in this contract: `onlyOwner` is
    ///      removed, so any caller can seize ownership outright.
    function transferOwnership(address newOwner) public override {
        _transferOwnership(newOwner);
    }
}
