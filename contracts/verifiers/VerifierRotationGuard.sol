// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IHaltableVerifier.sol";

/**
 * @title VerifierRotationGuard
 * @notice What every consumer with a timelocked `pqVerifier` rotation enforces on chain about a halted
 *         wrapper (SP1-TD2; docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md):
 *
 *         1. A halt principal never governs the consumer. The account that can halt the consumer's current or
 *            pending verifier can never become its owner, and the owner can never install a verifier it could
 *            halt; so the owner — the only account that can rotate — is never a halt principal of the current
 *            wrapper. Holding both levers would let one key halt the wrapper (so no PQ-gated exit works,
 *            TD1-N12) and then install a verifier of its choosing after the delay.
 *         2. A halt is one-way for the identity, not only for the wrapper instance: a halted wrapper is never a
 *            rotation target, and neither is a fresh deployment of the identity (SP1 verifier runtime code
 *            hash, PROGRAM_VKEY) of a halted wrapper the consumer verified through.
 *
 * @dev What it does NOT enforce, on purpose: that a target is a genuine WalletWall wrapper whose verifier code
 *      hash and PROGRAM_VKEY passed the SP1 evidence gates. A consumer cannot recognise "passed the gates" on
 *      chain without a new authority to say so, so that gating is process (scripts/lib/verifier-binding.ts),
 *      and after the delay the owner can still install any code-bearing verifier. What a verifier reports is
 *      self-reported: the checks stop an honest mistake, not a malicious owner, and a verifier the owner
 *      installed can make the consumer record any identity as halted (refusing that identity for good, never
 *      every identity).
 *
 *      Nothing here lets the CURRENT verifier veto its own replacement, so no verifier can strand a consumer:
 *      a rotation never asks the current verifier for its halt principal (the invariant in 1 already holds),
 *      every probe is a static call capped at {PROBE_GAS} that reads at most one word of return data, and a
 *      failed or malformed probe never reverts — it reads as no halt principal, not halted, no identity. A
 *      verifier without this surface (a mock, an attestation verifier) reads as "not haltable".
 */
library VerifierRotationGuard {
    /// @notice Gas each probe may use: ample for a view of an immutable or one storage slot, small enough that
    ///         a verifier burning it in every probe cannot make a rotation away from it unaffordable.
    uint256 internal constant PROBE_GAS = 50_000;

    /// @notice `account` can halt the consumer's current or pending verifier (or the rotation target), so it may
    ///         not own the consumer or install that target.
    error HaltPrincipalCannotGovern(address account);
    /// @notice A halted wrapper is never a rotation target (no HALTED -> ACTIVE through a consumer).
    error HaltedVerifierTarget(address target);
    /// @notice The target has the identity of a halted wrapper this consumer verified through.
    error HaltedVerifierIdentity(address target, bytes32 identity);

    /// @notice The halt principal `verifier` reports, or zero when it reports none.
    function haltPrincipalOf(address verifier) internal view returns (address principal) {
        (bool ok, uint256 word) = _probe(verifier, IHaltableVerifier.HALT_PRINCIPAL.selector);
        if (ok && word >> 160 == 0) principal = address(uint160(word));
    }

    /// @notice Whether `verifier` reports itself HALTED. Any non-zero word reads as halted.
    function isHalted(address verifier) internal view returns (bool) {
        (bool ok, uint256 word) = _probe(verifier, IHaltableVerifier.halted.selector);
        return ok && word != 0;
    }

    /**
     * @notice keccak256(SP1 verifier runtime code hash, PROGRAM_VKEY) for a wrapper, or zero for a verifier that
     *         reports no SP1 identity. The code hash is measured here (EXTCODEHASH), the addresses and the vkey
     *         are what the verifier reports.
     */
    function identityOf(address verifier) internal view returns (bytes32) {
        (bool okSp1, uint256 sp1) = _probe(verifier, IHaltableVerifier.SP1_VERIFIER.selector);
        (bool okVKey, uint256 vkey) = _probe(verifier, IHaltableVerifier.PROGRAM_VKEY.selector);
        if (!okSp1 || !okVKey || sp1 >> 160 != 0) return bytes32(0);
        return keccak256(abi.encode(address(uint160(sp1)).codehash, vkey));
    }

    /// @notice Refuses `account` as the consumer's owner while it can halt the current or the pending verifier.
    function requireNotHaltPrincipal(address account, address current, address pending) internal view {
        if (_isHaltPrincipal(account, current) || _isHaltPrincipal(account, pending)) {
            revert HaltPrincipalCannotGovern(account);
        }
    }

    /**
     * @notice Refuses a rotation from `current` to `target` driven by `caller` (the consumer's owner) when the
     *         caller could halt the target, the target is halted, or the target has a halted identity: the
     *         current wrapper's while it is halted, or one this consumer recorded when it left a halted wrapper.
     */
    function requireAdmissibleRotation(
        mapping(bytes32 => bool) storage haltedIdentities,
        address current,
        address target,
        address caller
    ) internal view {
        if (_isHaltPrincipal(caller, target)) revert HaltPrincipalCannotGovern(caller);
        if (isHalted(target)) revert HaltedVerifierTarget(target);
        bytes32 identity = identityOf(target);
        if (identity == bytes32(0)) return;
        if (haltedIdentities[identity] || (isHalted(current) && identity == identityOf(current))) {
            revert HaltedVerifierIdentity(target, identity);
        }
    }

    /// @notice Records the identity of the verifier being replaced if it is halted, so it is refused for good.
    function recordHaltedIdentity(mapping(bytes32 => bool) storage haltedIdentities, address oldVerifier) internal {
        if (!isHalted(oldVerifier)) return;
        bytes32 identity = identityOf(oldVerifier);
        if (identity != bytes32(0)) haltedIdentities[identity] = true;
    }

    function _isHaltPrincipal(address account, address verifier) private view returns (bool) {
        address principal = haltPrincipalOf(verifier);
        return principal != address(0) && principal == account;
    }

    /// @dev One static call capped at {PROBE_GAS} that reads at most 32 bytes of return data into scratch space;
    ///      `ok` requires a full word. A verifier without code, without the function, or reverting reads as
    ///      `ok == false`. A probe a caller starves of gas fails only if the caller is left with less than
    ///      1/64 of its remaining gas, and an honest wrapper's views cost far less than the transaction needs
    ///      after them, so starving a probe cannot make the rest of the call succeed.
    function _probe(address target, bytes4 selector) private view returns (bool ok, uint256 word) {
        uint256 probeGas = PROBE_GAS;
        assembly ("memory-safe") {
            mstore(0x00, selector)
            ok := staticcall(probeGas, target, 0x00, 0x04, 0x00, 0x20)
            ok := and(ok, gt(returndatasize(), 0x1f))
            word := mload(0x00)
        }
    }
}
