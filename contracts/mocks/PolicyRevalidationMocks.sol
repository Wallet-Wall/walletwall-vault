// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/**
 * @title Policy revalidation adversarial mocks
 * @notice TEST ONLY. These contracts exercise the fail-closed properties of the
 *         vaults' read-only finalization revalidation ({IPolicyEngine.revalidate},
 *         invoked via STATICCALL), and the exact preservation of {PolicySubject}
 *         across the policy boundary. None has a production purpose.
 *
 * @dev They deliberately do NOT declare `is IPolicyEngine`: several violate the
 *      interface's `view` mutability on purpose (the compiler would reject the
 *      override), which is exactly the adversarial shape the vaults must survive.
 *      Selectors match by signature, so the vaults call them like any engine.
 */

/// @notice Engine whose {revalidate} attempts a state write. Admission works and
///         is observable via `checkCalls`; finalization must revert (the vault's
///         view call executes this under STATICCALL, where SSTORE is illegal) and
///         `revalidateCalls` must remain 0 — proving finalization cannot mutate
///         policy state through revalidation.
contract MutatingRevalidatePolicyMock {
    uint256 public checkCalls;
    uint256 public revalidateCalls;

    function check(PolicySubject calldata, address, uint256, uint256) external returns (bool, string memory) {
        checkCalls++;
        return (true, "");
    }

    function revalidate(PolicySubject calldata, address, uint256, uint256) external returns (bool, string memory) {
        revalidateCalls++; // SSTORE — illegal under STATICCALL
        return (true, "");
    }
}

/// @notice Engine whose {revalidate} always reverts. Finalization must fail
///         closed (PolicyEngineUnavailable), never silently grant.
contract RevertingRevalidatePolicyMock {
    function check(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        revert("revalidate broken");
    }
}

/// @notice Pre-split engine shape: implements only {check}, has no fallback.
///         A revalidate call hits the dispatcher and reverts — finalization must
///         fail closed rather than treat the missing answer as an allow.
contract LegacyCheckOnlyPolicyMock {
    function check(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }
}

/// @notice PRE-SUBJECT engine shape: implements the OLD subjectless ABI
///         (`address vaultOwner` in place of the struct) and nothing else.
/// @dev Exists to prove there is no accidental compatibility path. Its selectors are
///      `check(address,address,uint256,uint256)` /
///      `revalidate(address,address,uint256,uint256)`, which a subject-carrying vault
///      never emits, so admission reverts on the missing function and finalization is
///      reported as PolicyEngineUnavailable. Both directions fail CLOSED — an engine
///      that cannot express the identity the vault asserts must not silently allow.
contract SubjectlessLegacyPolicyMock {
    function check(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }
}

/// @notice Engine returning data that does not ABI-decode as (bool, string).
///         The vault-side decode of the malformed answer must revert the
///         finalization — a garbled engine cannot grant settlement.
contract MalformedReturnPolicyMock {
    function check(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(PolicySubject calldata, address, uint256, uint256) external pure returns (uint256) {
        return 1; // one word; not decodable as (bool, string memory)
    }
}

/// @notice Engine whose {revalidate} burns a large, deterministic amount of gas
///         and then allows. Used to prove call-count facts (e.g. an engine that is
///         both queue-time and current is revalidated ONCE) through gas
///         measurement, since a view revalidation cannot record a call counter.
contract HeavyRevalidatePolicyMock {
    function check(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(PolicySubject calldata, address, uint256, uint256) external pure returns (bool, string memory) {
        bytes32 acc;
        for (uint256 i = 0; i < 4000; i++) {
            acc = keccak256(abi.encode(acc, i));
        }
        // acc is never zero after 4000 rounds; the data dependency stops the
        // compiler from eliminating the loop.
        return (acc != bytes32(0), "");
    }
}

/// @notice Engine that allows only when the reported `vaultBalance` AND `amount`
///         equal the values fixed at deployment — pins both parameters' semantics
///         at BOTH call sites: admission sees the pre-debit balance directly,
///         finalization must reconstruct the same figure (current balance +
///         reserved amount) and must forward the withdrawal's true amount.
contract BalanceAssertingPolicyMock {
    uint256 public immutable expectedBalance;
    uint256 public immutable expectedAmount;

    constructor(uint256 balance_, uint256 amount_) {
        expectedBalance = balance_;
        expectedAmount = amount_;
    }

    function check(
        PolicySubject calldata,
        address,
        uint256 amount,
        uint256 vaultBalance
    ) external view returns (bool, string memory) {
        if (amount != expectedAmount) return (false, "unexpected admission amount");
        if (vaultBalance != expectedBalance) return (false, "unexpected admission balance");
        return (true, "");
    }

    function revalidate(
        PolicySubject calldata,
        address,
        uint256 amount,
        uint256 vaultBalance
    ) external view returns (bool, string memory) {
        if (amount != expectedAmount) return (false, "unexpected settlement amount");
        if (vaultBalance != expectedBalance) return (false, "unexpected settlement balance");
        return (true, "");
    }
}

/// @notice Probe module that RECORDS the {PolicySubject} it actually received, plus
///         the `msg.sender` that delivered it.
/// @dev The instrument behind the composite-preservation proof. Equality assertions
///      written against a subject the TEST constructed can pass while the composite
///      quietly rewrites a field, because the test's expectation and the composite's
///      output are both derived from the test's own inputs. This mock instead reports
///      what crossed the module boundary, so the comparison is between the vault's
///      minted identity and the bytes a module genuinely observed.
///
///      `lastCaller` is recorded alongside because it is the field that MUST differ
///      between the direct and composite paths (vault vs composite) while every
///      subject field must NOT. A test asserting only the subject could not tell a
///      real composite hop from a direct call, and would pass without exercising the
///      relay at all.
///
///      {revalidate} is `view` and therefore cannot record anything (the vaults
///      STATICCALL it); it exposes the subject by RETURNING a denial reason built from
///      it instead, which the vault surfaces verbatim in PolicyViolation.
contract SubjectRecordingPolicyMock {
    address public lastConsumer;
    address public lastOwner;
    address public lastAsset;
    address public lastCaller;
    address public lastRecipient;
    uint256 public lastAmount;
    uint256 public lastVaultBalance;
    uint256 public checkCalls;

    /// @notice When true, {revalidate} denies and encodes the subject it saw into the
    ///         denial reason, which reaches the test through PolicyViolation(reason).
    bool public denyOnRevalidate;

    function setDenyOnRevalidate(bool deny) external {
        denyOnRevalidate = deny;
    }

    function check(
        PolicySubject calldata subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) external returns (bool, string memory) {
        lastConsumer = subject.consumer;
        lastOwner = subject.owner;
        lastAsset = subject.asset;
        lastCaller = msg.sender;
        lastRecipient = recipient;
        lastAmount = amount;
        lastVaultBalance = vaultBalance;
        checkCalls++;
        return (true, "");
    }

    function revalidate(
        PolicySubject calldata subject,
        address,
        uint256,
        uint256
    ) external view returns (bool, string memory) {
        if (!denyOnRevalidate) return (true, "");
        return (
            false,
            string.concat("subject:", _hex20(subject.consumer), ":", _hex20(subject.owner), ":", _hex20(subject.asset))
        );
    }

    /// @dev Lowercase, unprefixed 40-char hex of an address. Hand-rolled because the
    ///      encoding has to happen inside a `view` function with no library state.
    function _hex20(address a) private pure returns (string memory) {
        bytes20 raw = bytes20(a);
        bytes memory out = new bytes(40);
        bytes16 digits = "0123456789abcdef";
        for (uint256 i = 0; i < 20; i++) {
            out[i * 2] = digits[uint8(raw[i]) >> 4];
            out[i * 2 + 1] = digits[uint8(raw[i]) & 0x0f];
        }
        return string(out);
    }
}
