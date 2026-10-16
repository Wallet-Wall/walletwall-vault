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
 *
 *      DIRECT IMMUTABLE SP1 VERIFIER (decided in SP1-TD1, built in the SP1 implementation lane; see
 *      docs/SP1_Implementation_Pin_Designation_Registry.md). The constructor accepts only an SP1 verifier
 *      whose runtime code is Succinct's Groth16 SP1Verifier {SP1_VERSION}: its runtime code hash
 *      {SP1_VERIFIER_CODEHASH} is a compile-time constant, so neither the deployer nor anyone later can
 *      bind the wrapper to the owner-mutable SP1VerifierGateway, another SP1 version, a mock or an
 *      accept-all contract. The pinned code has no reachable SELFDESTRUCT, DELEGATECALL, CALLCODE or
 *      state write (SP1-TD1's runtime scan), so the code at SP1_VERIFIER cannot change after this check,
 *      and nothing here can change SP1_VERIFIER. A code hash pins bytes, not behaviour: each chain's
 *      precompiles decide the verdicts, which the deployment tooling's per-chain execution check measures.
 *      Identity provenance is not soundness: the pin says which verifier this is, not that it is sound.
 */
contract ZKMLDSAVerifier is IPQCVerifier, IHaltableVerifier {
    bytes32 public constant ALGORITHM_ID = keccak256("ZK-ML-DSA-65");

    /// @notice Runtime code hash (EXTCODEHASH) of the only SP1 verifier this wrapper accepts: Succinct's
    ///         Groth16 SP1Verifier v6.1.0 (CREATE2 address 0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2 on
    ///         Ethereum, Base, Sepolia and Base Sepolia). Checked against the generated SP1 designation in CI.
    bytes32 public constant SP1_VERIFIER_CODEHASH = 0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd;

    /// @notice VERIFIER_HASH() the pinned verifier reports (its proofs' 4-byte selector is the prefix).
    bytes32 public constant SP1_VERIFIER_HASH = 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    /// @notice VK_ROOT() the pinned verifier reports.
    bytes32 public constant SP1_VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352;

    /// @notice VERSION() the pinned verifier reports.
    string public constant SP1_VERSION = "v6.1.0";

    /// @notice The SP1 Verifier contract address: fixed here, its code fixed by {SP1_VERIFIER_CODEHASH}.
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
    /// @notice `sp1Verifier`'s runtime code (hash `codehash`) is not the designated verifier's.
    error UndesignatedSP1Verifier(address sp1Verifier, bytes32 codehash);
    error InvalidProgramVKey();
    error InvalidProof();
    /// @notice A zero halt principal would leave the breaker uncallable forever.
    error ZeroHaltPrincipal();
    error NotHaltPrincipal();
    error AlreadyHalted();

    constructor(address _sp1Verifier, bytes32 _programVKey, address _haltPrincipal) {
        if (_sp1Verifier.code.length == 0) revert InvalidSP1Verifier();
        if (_sp1Verifier.codehash != SP1_VERIFIER_CODEHASH) {
            revert UndesignatedSP1Verifier(_sp1Verifier, _sp1Verifier.codehash);
        }
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
        if (!_chainIdMatches(committedChainId, block.chainid)) return false;
        if (committedVerifier != address(this)) return false;

        // Verify the proof against the SP1 Verifier
        try ISP1Verifier(SP1_VERIFIER).verifyProof(PROGRAM_VKEY, publicValues, proofBytes) {
            return true;
        } catch {
            return false;
        }
    }

    /**
     * @dev SP1-P1 finding F-1: the journal's chain id (a uint64 the guest commits unchecked, so a proof-routing
     *      tag) is compared with the FULL 256-bit chain id. Narrowing block.chainid to 64 bits would make a
     *      journal for chain id x match on chain x + k * 2^64; at full width a chain id of 2^64 or more matches
     *      no journal and fails closed. Authorization binds the chain through each consumer's EIP-712 digest,
     *      which always used the full id. Contract-only: the guest, the ELF, PROGRAM_VKEY and the journal are
     *      unchanged.
     */
    function _chainIdMatches(uint64 committed, uint256 chainId) internal pure returns (bool) {
        return uint256(committed) == chainId;
    }

    /**
     * @dev External pure decoder so verify() can catch malformed dynamic ABI offsets
     *      and preserve the IPQCVerifier false-on-invalid contract.
     *      The journal's third word, the signature hash, is non-authoritative and deliberately unchecked
     *      (SP1-P1 finding F-2): any valid signature over the digest authorizes, and replay is stopped by the
     *      digest's nonce and deadline, so no authorization fact depends on which signature was used.
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
