// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

interface IOwnable2StepView {
    function owner() external view returns (address);

    function pendingOwner() external view returns (address);
}

/**
 * @title MisbehavingVerifierMock
 * @notice TEST ONLY. A verifier whose halt surface (HALT_PRINCIPAL, halted, SP1_VERIFIER, PROGRAM_VKEY) answers
 *         however a test programs it, per function: to prove that no current verifier can veto its own replacement
 *         through the SP1-TD2 rotation guard's probes (strand a consumer), that a malformed answer reads as no answer,
 *         and to make the guard's documented residual executable. It verifies nothing.
 *
 *         Revert           — revert with no data (the default: no halt surface, like a mock or attestation verifier).
 *         Return           — return the programmed word.
 *         RevertWithWord   — revert with the programmed word as 32 bytes of revert data.
 *         ReturnShort      — return only the first byte of the programmed word.
 *         BurnGas          — run until out of gas.
 *         ReturnHuge       — return a mebibyte.
 *         ReturnOwner      — return the calling consumer's owner().
 *         ReturnPendingOwner — return the calling consumer's pendingOwner().
 */
contract MisbehavingVerifierMock is IPQCVerifier {
    enum Behavior {
        Revert,
        Return,
        RevertWithWord,
        ReturnShort,
        BurnGas,
        ReturnHuge,
        ReturnOwner,
        ReturnPendingOwner
    }

    struct Answer {
        Behavior behavior;
        bytes32 word;
    }

    mapping(bytes4 selector => Answer) public answers;

    function program(bytes4 selector, Behavior behavior, bytes32 word) external {
        answers[selector] = Answer(behavior, word);
    }

    function algorithmId() external pure override returns (bytes32) {
        return keccak256("TEST-MISBEHAVING-VERIFIER");
    }

    function verify(bytes32, bytes calldata, bytes calldata) external pure override returns (bool) {
        return false;
    }

    function HALT_PRINCIPAL() external view returns (address) {
        _answer();
    }

    function halted() external view returns (bool) {
        _answer();
    }

    function SP1_VERIFIER() external view returns (address) {
        _answer();
    }

    function PROGRAM_VKEY() external view returns (bytes32) {
        _answer();
    }

    /// @dev Ends the call according to the programmed answer for msg.sig; never returns normally.
    function _answer() private view {
        Answer memory a = answers[msg.sig];
        bytes32 word = a.word;
        if (a.behavior == Behavior.ReturnOwner) word = bytes32(uint256(uint160(IOwnable2StepView(msg.sender).owner())));
        if (a.behavior == Behavior.ReturnPendingOwner) {
            word = bytes32(uint256(uint160(IOwnable2StepView(msg.sender).pendingOwner())));
        }
        if (a.behavior == Behavior.BurnGas) {
            uint256 spin;
            while (gasleft() > 0) {
                unchecked {
                    ++spin;
                }
            }
        }
        Behavior behavior = a.behavior;
        assembly {
            switch behavior
            case 0 {
                revert(0, 0)
            }
            case 2 {
                mstore(0x00, word)
                revert(0x00, 0x20)
            }
            case 3 {
                mstore(0x00, word)
                return(0x00, 0x01)
            }
            case 5 {
                return(0x00, 0x100000)
            }
            default {
                mstore(0x00, word)
                return(0x00, 0x20)
            }
        }
    }
}
