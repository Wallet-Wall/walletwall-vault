// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/**
 * @title Daily-spend admission authority adversarial mocks
 * @notice TEST ONLY. These contracts exercise the admission-time authority model of
 *         {DailySpendLimitPolicy} — who may cause its subject-keyed accounting to
 *         mutate, and whether a caller can select a subject it has no claim to. None
 *         has a production purpose.
 *
 * @dev They deliberately do NOT declare `is IPolicyEngine`: the poisoner is a caller,
 *      not an engine, and the fake vault implements only the sliver of surface an
 *      authority check might look at. Selectors match by signature, so calls land on
 *      a real policy exactly as an arbitrary contract's would.
 *
 *      They take the subject's three fields SEPARATELY rather than a prebuilt struct
 *      so a test can compose any triple it likes — including one naming a real vault
 *      as `consumer` while the call actually originates here. That substitution is the
 *      whole point: it is what {DailySpendLimitPolicy}'s per-subject delegation and
 *      {CompositePolicyEngine}'s consumer binding must refuse.
 */

interface IAdmissionCheck {
    function check(
        PolicySubject calldata subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason);
}

/// @notice Arbitrary unrelated contract that calls a policy's {check} directly with a
///         subject of its choosing. Proves whether contract callers (as opposed to
///         EOAs) can mutate admission accounting they have no relationship to, and
///         whether naming someone else's consumer confers that consumer's authority.
contract DailySpendPoisonerMock {
    /// @notice Last answer returned by the poisoned policy; lets a test assert that
    ///         the call SUCCEEDED (rather than merely not reverting).
    bool public lastAllowed;
    string public lastReason;
    uint256 public callCount;

    function poison(
        address policy,
        address consumer,
        address owner,
        address asset,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason) {
        PolicySubject memory subject = PolicySubject({consumer: consumer, owner: owner, asset: asset});
        (allowed, reason) = IAdmissionCheck(policy).check(subject, recipient, amount, vaultBalance);
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
/// @dev {admit} mints the subject the way a REAL vault would — `consumer:
///      address(this)` — which is precisely why it must fail: nobody delegated to this
///      address for that subject. {admitAs} instead lets the test name an arbitrary
///      consumer, covering the spoofing case where a caller borrows a legitimate
///      vault's identity.
contract FakeVaultMock {
    address public policyEngine;
    address public owner;

    constructor(address policyEngine_) {
        policyEngine = policyEngine_;
        owner = msg.sender;
    }

    function admit(
        address vaultOwner,
        address asset,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason) {
        PolicySubject memory subject = PolicySubject({consumer: address(this), owner: vaultOwner, asset: asset});
        return IAdmissionCheck(policyEngine).check(subject, recipient, amount, vaultBalance);
    }

    function admitAs(
        address consumer,
        address vaultOwner,
        address asset,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool allowed, string memory reason) {
        PolicySubject memory subject = PolicySubject({consumer: consumer, owner: vaultOwner, asset: asset});
        return IAdmissionCheck(policyEngine).check(subject, recipient, amount, vaultBalance);
    }
}
