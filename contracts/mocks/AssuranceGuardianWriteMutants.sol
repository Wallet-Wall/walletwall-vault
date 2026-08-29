// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Fixture-only mutants for test/RecoveryStructuralAssurance.test.ts's AST-backed
 *      "only setGuardians writes vaultGuardians" checker. Each contract has a
 *      legitimate `setGuardians` plus exactly one mutation path the old regex-based
 *      alias-blind checker would have missed. NOT part of the deployed vault surface.
 *      See docs/Guardian_Authority_Design.md §9.1 L-I / §14.2 regression #2.
 */

/// @dev M6 — three non-alias mutation forms bypassing setGuardians: direct
///      assignment, `delete`, and a direct (non-alias) `.push`.
contract M6DirectGuardianWrite {
    mapping(address => address[]) public vaultGuardians;

    function setGuardians(address[] calldata guardians) external {
        vaultGuardians[msg.sender] = guardians;
    }

    function evilDirectWrite(address owner, address[] calldata attackerSet) external {
        vaultGuardians[owner] = attackerSet;
    }

    function evilDelete(address owner) external {
        delete vaultGuardians[owner];
    }

    function evilDirectPush(address owner, address attacker) external {
        vaultGuardians[owner].push(attacker);
    }
}

/// @dev M7 — the mutation goes through a local storage alias
///      (`address[] storage gs = vaultGuardians[owner]; gs.push(attacker);`),
///      which a checker that only matches `vaultGuardians[...]` textually would miss.
contract M7AliasGuardianWrite {
    mapping(address => address[]) public vaultGuardians;

    function setGuardians(address[] calldata guardians) external {
        vaultGuardians[msg.sender] = guardians;
    }

    function evilAliasPush(address owner, address attacker) external {
        address[] storage gs = vaultGuardians[owner];
        gs.push(attacker);
    }
}
