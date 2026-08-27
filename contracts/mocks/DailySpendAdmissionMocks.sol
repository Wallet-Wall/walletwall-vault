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

/// @notice Books several admissions against one subject inside a SINGLE transaction,
///         and therefore inside a single `block.timestamp`.
/// @dev TEST ONLY. Exists because same-second accounting cannot be exercised from an
///      EOA: one externally-owned transaction is one block, and Hardhat requires
///      strictly increasing block timestamps. Disabling automine would reach the same
///      state, but the suite shares ONE network connection across every test file, so a
///      test that failed mid-batch would leave automine off for everything after it.
///
///      The subject names THIS contract as consumer, exactly as a real vault mints its
///      own — so it reaches a bucket the test arms for this address and no other.
///      Each `amounts[i]` is a separate {IPolicyEngine-check} call, which is what makes
///      it a genuine test of coalescing rather than of one pre-summed amount: the
///      policy must arrive at the same total having been asked `n` separate times.
contract DailySpendBatchAdmitterMock {
    address public policyEngine;

    /// @notice Emitted per sub-call so a test can assert WHICH admission was refused,
    ///         not merely that the batch as a whole failed.
    event Admission(uint256 index, bool allowed, string reason);

    constructor(address policyEngine_) {
        policyEngine = policyEngine_;
    }

    /// @param vaultOwner The owner slot of the subject to book against.
    /// @param asset      address(0) for native ETH, else the ERC-20 address.
    /// @param amounts    One admission per element, all in this one block.
    function admitBatch(address vaultOwner, address asset, uint256[] calldata amounts) external {
        _batch(address(this), vaultOwner, asset, amounts);
    }

    /// @notice As {admitBatch}, but naming an arbitrary `consumer`.
    /// @dev Lets a test batch against a subject whose consumer is a REAL vault, so
    ///      same-second behaviour can be exercised on the very bucket the vault path
    ///      fills. It confers no authority: this contract still has to have been
    ///      delegated for that exact subject, which is asserted separately by
    ///      test/DailySpendAdmissionAuthority.test.ts.
    function admitBatchAs(address consumer, address vaultOwner, address asset, uint256[] calldata amounts) external {
        _batch(consumer, vaultOwner, asset, amounts);
    }

    function _batch(address consumer, address vaultOwner, address asset, uint256[] calldata amounts) private {
        PolicySubject memory subject = PolicySubject({consumer: consumer, owner: vaultOwner, asset: asset});
        for (uint256 i = 0; i < amounts.length; i++) {
            (bool allowed, string memory reason) = IAdmissionCheck(policyEngine).check(
                subject,
                address(this),
                amounts[i],
                0
            );
            emit Admission(i, allowed, reason);
        }
    }
}

/// @notice A registered ADMITTER whose own relay logic is broken — reverts
///         unconditionally before ever reaching the policy's {check}. Stands in for a
///         delegate contract (a batching relay, a smart-wallet module — any non-owner
///         admitter) that stops functioning for reasons entirely outside the policy's
///         own control, so a test can prove the OTHER registered admitter is what
///         `setAdmitter`/`bridgeSetAdmitter`'s liveness repair (design doc §9.6, L5) is
///         actually responsible for restoring — not the relay's own internal health.
contract RevertingAdmitterRelayMock {
    error RelayIsDown();

    function relay(
        address policy,
        address consumer,
        address vaultOwner,
        address asset,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external pure returns (bool, string memory) {
        policy;
        consumer;
        vaultOwner;
        asset;
        recipient;
        amount;
        vaultBalance;
        revert RelayIsDown();
    }
}
