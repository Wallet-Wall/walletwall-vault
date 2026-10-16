// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";
import "./IHaltableVerifier.sol";

/**
 * @notice Interface for the auto-generated SP1 Verifier (Groth16/Plonk).
 * @dev See https://docs.succinct.xyz/docs/sp1/verification/solidity
 */
interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

/**
 * @title ZKMLDSAVerifier
 * @notice Intended to provide trustless verification of ML-DSA-65 signatures
 *         using ZK proofs, in place of the trusted-attestation model.
 * @dev PROTOTYPE — not deployed, unaudited. This contract forwards to an
 *      external ISP1Verifier; there is no on-chain guarantee that
 *      PROGRAM_VKEY corresponds to a genuine ML-DSA-65 verification circuit
 *      (that binding is unproven on-chain). Mock-backed in tests. See
 *      docs/ZK_PQ_Status_Matrix.md for the current capability matrix.
 *
 *      SP1-TD2 LOCAL ONE-WAY VERIFIER HALT (decided by the owner in SP1-TD1, built in SP1-TD2; see
 *      docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md). The wrapper is ACTIVE until {HALT_PRINCIPAL}
 *      calls {halt}; from then on {verify} returns false for every input, for every consumer that verifies
 *      through it. Nothing leads back: there is no unhalt, and the halt principal has no other function.
 *      SP1_VERIFIER and PROGRAM_VKEY stay immutable, halted or not. Upstream signals (a RouteFrozen, an
 *      advisory, a disclosure) are evidence for the halt principal, never inputs to this contract.
 *      Recovery is a new wrapper of an independently established identity, installed through each
 *      consumer's own timelocked rotation ({VerifierRotationGuard} refuses the halted identity).
 */
contract ZKMLDSAVerifier is IPQCVerifier, IHaltableVerifier {
    bytes32 public constant ALGORITHM_ID = keccak256("ZK-ML-DSA-65");

    /// @notice The SP1 Verifier contract address.
    address public immutable override SP1_VERIFIER;

    /// @notice The verification key for the ML-DSA-65 guest program.
    bytes32 public immutable override PROGRAM_VKEY;

    /// @notice The only account that can halt this wrapper; halting is all it can do.
    address public immutable override HALT_PRINCIPAL;

    /// @notice False while ACTIVE; true once HALTED. Set once, by {halt}; never cleared.
    bool public override halted;

    /// @notice The wrapper moved ACTIVE -> HALTED; every later {verify} returns false.
    event VerifierHalted(address indexed haltPrincipal);

    error InvalidSP1Verifier();
    error InvalidProgramVKey();
    error InvalidProof();
    /// @notice A zero halt principal would leave the breaker uncallable forever.
    error ZeroHaltPrincipal();
    error NotHaltPrincipal();
    error AlreadyHalted();

    constructor(address _sp1Verifier, bytes32 _programVKey, address _haltPrincipal) {
        if (_sp1Verifier.code.length == 0) revert InvalidSP1Verifier();
        if (_programVKey == bytes32(0)) revert InvalidProgramVKey();
        if (_haltPrincipal == address(0)) revert ZeroHaltPrincipal();
        SP1_VERIFIER = _sp1Verifier;
        PROGRAM_VKEY = _programVKey;
        HALT_PRINCIPAL = _haltPrincipal;
    }

    function algorithmId() external pure override returns (bytes32) {
        return ALGORITHM_ID;
    }

    /// @notice ACTIVE -> HALTED, the wrapper's only transition and its halt principal's only power.
    function halt() external override {
        if (msg.sender != HALT_PRINCIPAL) revert NotHaltPrincipal();
        if (halted) revert AlreadyHalted();
        halted = true;
        emit VerifierHalted(msg.sender);
    }

    /**
     * @notice Verifies an ML-DSA-65 signature via a ZK proof.
     * @dev Returns false without reading the proof once the wrapper is HALTED.
     * @param digest The 32-byte message digest.
     * @param publicKey The raw public key bytes.
     * @param proof The encoded ZK proof (publicValues + proofBytes).
     */
    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata proof
    ) external view override returns (bool) {
        if (halted) return false;

        bytes memory publicValues;
        bytes memory proofBytes;
        bytes32 committedDigest;
        bytes32 committedPkHash;
        uint64 committedChainId;
        address committedVerifier;

        try this.decodeProofPayload(proof) returns (
            bytes memory decodedPublicValues,
            bytes memory decodedProofBytes,
            bytes32 decodedDigest,
            bytes32 decodedPkHash,
            uint64 decodedChainId,
            address decodedVerifier
        ) {
            publicValues = decodedPublicValues;
            proofBytes = decodedProofBytes;
            committedDigest = decodedDigest;
            committedPkHash = decodedPkHash;
            committedChainId = decodedChainId;
            committedVerifier = decodedVerifier;
        } catch {
            return false;
        }

        if (committedDigest != digest) return false;
        if (committedPkHash != keccak256(publicKey)) return false;
        if (committedChainId != uint64(block.chainid)) return false;
        if (committedVerifier != address(this)) return false;

        // Verify the proof against the SP1 Verifier
        try ISP1Verifier(SP1_VERIFIER).verifyProof(PROGRAM_VKEY, publicValues, proofBytes) {
            return true;
        } catch {
            return false;
        }
    }

    /**
     * @dev External pure decoder so verify() can catch malformed dynamic ABI offsets
     *      and preserve the IPQCVerifier false-on-invalid contract.
     */
    function decodeProofPayload(
        bytes calldata proof
    )
        external
        pure
        returns (
            bytes memory publicValues,
            bytes memory proofBytes,
            bytes32 committedDigest,
            bytes32 committedPkHash,
            uint64 committedChainId,
            address committedVerifier
        )
    {
        (publicValues, proofBytes) = abi.decode(proof, (bytes, bytes));
        if (publicValues.length != 160 || proofBytes.length == 0) revert InvalidProof();

        (committedDigest, committedPkHash, , /* bytes32 committedSigHash */ committedChainId, committedVerifier) = abi
            .decode(publicValues, (bytes32, bytes32, bytes32, uint64, address));
    }
}
