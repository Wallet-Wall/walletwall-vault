// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

interface IOwnable2StepView {
    function owner() external view returns (address);

    function pendingOwner() external view returns (address);
}

/**
 * @title MisbehavingVerifierMock
 * @notice TEST ONLY. A verifier an owner installed through the delayed path that then turns hostile toward the
 *         SP1-TD2 rotation guard's probes, to prove no current verifier can veto its own replacement (strand a
 *         consumer) and to make the guard's documented residual executable. It verifies nothing.
 *
 *         Honest              — no halt surface (every probe reverts), like a mock or an attestation verifier.
 *         ClaimsConsumerOwner — reports the calling consumer's owner as its halt principal.
 *         ClaimsPendingOwner  — reports the calling consumer's pending owner as its halt principal.
 *         BurnsGas            — every probe runs until it is out of gas.
 *         ReturnsHugeData     — every probe returns a mebibyte.
 *         ClaimsHaltedIdentity — reports itself HALTED with the identity it was constructed with.
 */
contract MisbehavingVerifierMock is IPQCVerifier {
    enum Mode {
        Honest,
        ClaimsConsumerOwner,
        ClaimsPendingOwner,
        BurnsGas,
        ReturnsHugeData,
        ClaimsHaltedIdentity
    }

    Mode public mode;
    address public immutable claimedSp1Verifier;
    bytes32 public immutable claimedProgramVKey;

    error NotSupported();

    constructor(address sp1Verifier, bytes32 programVKey) {
        claimedSp1Verifier = sp1Verifier;
        claimedProgramVKey = programVKey;
    }

    function setMode(Mode newMode) external {
        mode = newMode;
    }

    function algorithmId() external pure override returns (bytes32) {
        return keccak256("TEST-MISBEHAVING-VERIFIER");
    }

    function verify(bytes32, bytes calldata, bytes calldata) external pure override returns (bool) {
        return false;
    }

    function HALT_PRINCIPAL() external view returns (address) {
        _misbehave();
        if (mode == Mode.ClaimsConsumerOwner) return IOwnable2StepView(msg.sender).owner();
        if (mode == Mode.ClaimsPendingOwner) return IOwnable2StepView(msg.sender).pendingOwner();
        revert NotSupported();
    }

    function halted() external view returns (bool) {
        _misbehave();
        if (mode == Mode.ClaimsHaltedIdentity) return true;
        revert NotSupported();
    }

    function SP1_VERIFIER() external view returns (address) {
        _misbehave();
        if (mode == Mode.ClaimsHaltedIdentity) return claimedSp1Verifier;
        revert NotSupported();
    }

    function PROGRAM_VKEY() external view returns (bytes32) {
        _misbehave();
        if (mode == Mode.ClaimsHaltedIdentity) return claimedProgramVKey;
        revert NotSupported();
    }

    function _misbehave() private view {
        if (mode == Mode.BurnsGas) {
            uint256 spin;
            while (gasleft() > 0) {
                unchecked {
                    ++spin;
                }
            }
        }
        if (mode == Mode.ReturnsHugeData) {
            assembly {
                return(0, 0x100000)
            }
        }
    }
}
