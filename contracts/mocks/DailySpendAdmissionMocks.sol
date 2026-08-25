// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Daily-spend admission authority adversarial mocks
 * @notice TEST ONLY. These contracts exercise the admission-time authority model of
 *         {DailySpendLimitPolicy} — who may cause its 24-hour window accounting to
 *         mutate. None has a production purpose.
 *
 * @dev They deliberately do NOT declare `is IPolicyEngine`: the poisoner is a caller,
 *      not an engine, and the fake vault implements only the sliver of surface an
 *      authority check might look at. Selectors match by signature, so calls land on
 *      a real policy exactly as an arbitrary contract's would.
 */

interface IAdmissionCheck {
    function check(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason);
}

/// @notice Arbitrary unrelated contract that calls a policy's {check} directly.
///         Proves whether contract callers (as opposed to EOAs) can mutate
///         admission accounting they have no relationship to.
contract DailySpendPoisonerMock {
    /// @notice Last answer returned by the poisoned policy; lets a test assert that
    ///         the call SUCCEEDED (rather than merely not reverting).
    bool public lastAllowed;
    string public lastReason;
    uint256 public callCount;

    function poison(
        address policy,
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason) {
        (allowed, reason) = IAdmissionCheck(policy).check(vaultOwner, recipient, amount, vaultBalance);
        lastAllowed = allowed;
        lastReason = reason;
        callCount++;
        return (allowed, reason);
    }
}

/// @notice A contract that merely CLAIMS to be a vault. It has code and a plausible
///         surface, but is registered nowhere. Any authority scheme that accepts a
///         caller because it "looks like a vault" (has code, answers a getter,
///         reports an owner) rather than because it was explicitly authorized must
///         still reject this contract.
contract FakeVaultMock {
    address public policyEngine;
    address public owner;

    constructor(address policyEngine_) {
        policyEngine = policyEngine_;
        owner = msg.sender;
    }

    function admit(
        address vaultOwner,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason) {
        return IAdmissionCheck(policyEngine).check(vaultOwner, recipient, amount, vaultBalance);
    }
}
