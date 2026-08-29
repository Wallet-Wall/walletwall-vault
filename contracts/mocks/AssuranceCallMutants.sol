// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Fixture-only mutants for test/RecoveryStructuralAssurance.test.ts's AST-backed
 *      "no external call" checker. Each contract below is a minimal, independently
 *      compilable stand-in for one way a recovery entry point could gain an external
 *      call without the old regex/marker check noticing — NOT part of the deployed
 *      vault surface. See docs/Guardian_Authority_Design.md §9.1 L-I.
 */

interface IGuardianControllerM1 {
    function authorize(address vaultOwner) external;
}

/// @dev M1 — arbitrary typed external call through a state-variable dependency.
contract M1ArbitraryExternalCall {
    IGuardianControllerM1 public guardianController;

    function executeRecovery(address vaultOwner) external {
        guardianController.authorize(vaultOwner);
    }
}

interface ISomeAuthorityM2 {
    function check(address vaultOwner) external returns (bool);
}

/// @dev M2 — same shape as M1 but under a dependency name that is neither
///      `pqVerifier` nor `policyEngine`, proving the check does not key on names.
contract M2RenamedExternalDependency {
    ISomeAuthorityM2 public somethingCompletelyDifferent;

    function initiateRecovery(address vaultOwner) external {
        somethingCompletelyDifferent.check(vaultOwner);
    }
}

/// @dev M3 — a plain low-level `.call`.
contract M3LowLevelCall {
    function executeRecovery(address target) external {
        target.call("");
    }
}

/// @dev M4 — every OTHER low-level call form the checker must also reject.
contract M4OtherLowLevelCallForms {
    function viaStaticcall(address target) external view {
        target.staticcall("");
    }

    function viaDelegatecall(address target) external {
        target.delegatecall("");
    }

    function viaSend(address payable target) external {
        target.send(0);
    }

    function viaTransfer(address payable target) external {
        target.transfer(0);
    }
}

interface IGuardianControllerM5 {
    function authorize(address vaultOwner) external;
}

/// @dev M5 — an inline interface cast immediately invoked, never stored in a
///      named state variable at all.
contract M5InlineInterfaceCast {
    function executeRecovery(address controller, address vaultOwner) external {
        IGuardianControllerM5(controller).authorize(vaultOwner);
    }
}

/// @dev M8 — control: an internal helper call must NOT be flagged. If the checker
///      merely rejected every FunctionCall node, this contract would fail too.
contract M8InternalHelperControl {
    function executeRecovery(address vaultOwner) external pure returns (uint256) {
        return _helper(vaultOwner);
    }

    function _helper(address vaultOwner) internal pure returns (uint256) {
        return uint256(uint160(vaultOwner));
    }
}
