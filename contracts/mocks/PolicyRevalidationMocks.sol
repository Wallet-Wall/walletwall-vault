// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Policy revalidation adversarial mocks
 * @notice TEST ONLY. These contracts exercise the fail-closed properties of the
 *         vaults' read-only finalization revalidation ({IPolicyEngine.revalidate},
 *         invoked via STATICCALL). None has a production purpose.
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

    function check(address, address, uint256, uint256) external returns (bool, string memory) {
        checkCalls++;
        return (true, "");
    }

    function revalidate(address, address, uint256, uint256) external returns (bool, string memory) {
        revalidateCalls++; // SSTORE — illegal under STATICCALL
        return (true, "");
    }
}

/// @notice Engine whose {revalidate} always reverts. Finalization must fail
///         closed (PolicyEngineUnavailable), never silently grant.
contract RevertingRevalidatePolicyMock {
    function check(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(address, address, uint256, uint256) external pure returns (bool, string memory) {
        revert("revalidate broken");
    }
}

/// @notice Pre-split engine shape: implements only {check}, has no fallback.
///         A revalidate call hits the dispatcher and reverts — finalization must
///         fail closed rather than treat the missing answer as an allow.
contract LegacyCheckOnlyPolicyMock {
    function check(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }
}

/// @notice Engine returning data that does not ABI-decode as (bool, string).
///         The vault-side decode of the malformed answer must revert the
///         finalization — a garbled engine cannot grant settlement.
contract MalformedReturnPolicyMock {
    function check(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(address, address, uint256, uint256) external pure returns (uint256) {
        return 1; // one word; not decodable as (bool, string memory)
    }
}

/// @notice Engine whose {revalidate} burns a large, deterministic amount of gas
///         and then allows. Used to prove call-count facts (e.g. an engine that is
///         both queue-time and current is revalidated ONCE) through gas
///         measurement, since a view revalidation cannot record a call counter.
contract HeavyRevalidatePolicyMock {
    function check(address, address, uint256, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function revalidate(address, address, uint256, uint256) external pure returns (bool, string memory) {
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

    function check(address, address, uint256 amount, uint256 vaultBalance) external view returns (bool, string memory) {
        if (amount != expectedAmount) return (false, "unexpected admission amount");
        if (vaultBalance != expectedBalance) return (false, "unexpected admission balance");
        return (true, "");
    }

    function revalidate(
        address,
        address,
        uint256 amount,
        uint256 vaultBalance
    ) external view returns (bool, string memory) {
        if (amount != expectedAmount) return (false, "unexpected settlement amount");
        if (vaultBalance != expectedBalance) return (false, "unexpected settlement balance");
        return (true, "");
    }
}
