// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./IPQCVerifier.sol";

/// @notice The minimal read surface a policy-control consumer (a WalletWall vault) must
///         expose for {PolicyControlBridge} to authenticate a tenant's CURRENT
///         credentials. Both `WalletWallVault` and `StablecoinVaultSimulator` already
///         satisfy this shape structurally — `vaults` is a public
///         `mapping(address => VaultOwner)` whose struct field order
///         (ecdsaSigner, pqPublicKey, nonce, balance, mode, exists) matches exactly, and
///         both already declare `pqVerifier` and, after this lane, `policyControlEpoch`.
///         No consumer needs to explicitly declare `is IPolicyControlCredentialSource`;
///         Solidity dispatches by selector, not by declared inheritance.
interface IPolicyControlCredentialSource {
    function vaults(
        address owner
    )
        external
        view
        returns (
            address ecdsaSigner,
            bytes memory pqPublicKey,
            uint256 nonce,
            uint256 balance,
            uint8 mode,
            bool exists
        );

    function policyControlEpoch(address owner) external view returns (uint64);

    function pqVerifier() external view returns (IPQCVerifier);
}

/// @notice The bridge-facing surface a policy exposes for its canonical bridge to call,
///         once the bridge has authenticated the tenant's current credentials.
///         DailySpendLimitPolicy implements this and accepts calls ONLY from the
///         immutable POLICY_CONTROL_BRIDGE it was constructed with (design doc §6.1, L9).
interface IPolicyControlTarget {
    function bridgeEnrollController(address consumer, address owner, address asset, address controller) external;

    function bridgeStrengthenLimit(address consumer, address owner, address asset, uint256 newLimit) external;

    function bridgeProposeWeakening(
        address consumer,
        address owner,
        address asset,
        uint256 newLimit,
        uint64 epoch
    ) external;

    function bridgeApplyWeakening(address consumer, address owner, address asset, uint64 epoch) external;

    function bridgeCancelWeakening(address consumer, address owner, address asset) external;

    function bridgeSetAdmitter(address consumer, address owner, address asset, address caller, bool allowed) external;
}

/// @title PolicyControlBridge
/// @notice The canonical authentication layer for the policy-control authority lane
///         (docs/Policy_Control_Authority_Design.md §5, §6, §6.3). Verifies that a
///         signed configuration intent was authorized by a consumer's CURRENT
///         credentials, then forwards it to the named policy AS the trusted controller.
///
/// @dev RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH
///      REAL FUNDS.
///
///      ONE BRIDGE, MANY POLICIES. This contract knows nothing about any specific policy
///      instance; `policy` is a field of every signed intent, so one deployed bridge
///      serves every `DailySpendLimitPolicy` that names it as canonical (§6.1, O4).
///
///      AUTHENTICATION IS READ LIVE, NEVER CACHED. Every call re-reads
///      `IPolicyControlCredentialSource(consumer).vaults(owner)` and
///      `.policyControlEpoch(owner)` at call time — there is no local copy of a tenant's
///      credentials to go stale. Signature recovery against a rotated-away key and the
///      independent epoch check are two SEPARATE gates (design doc §5.4's "the epoch
///      appears twice, on purpose") — either alone would leave a gap.
///
///      REPLAY. `controlNonce[consumer][owner]` is a dedicated, SEQUENTIAL counter,
///      wholly independent of the vault's own withdrawal nonce (L10) — policy
///      administration must never invalidate a signed withdrawal, and a withdrawal must
///      never invalidate a policy-control intent. It increments ONLY on successful use,
///      so a signed-but-never-submitted intent costs nothing and cannot wedge the
///      sequence (§10.6).
///
///      DISTINCT TYPEHASH PER ACTION. `consumer`, `owner`, `policy`, and `asset` are all
///      part of every signed struct, so a signature cannot be relabeled onto a different
///      subject, target, or asset after the fact — see the CROSS-CONSUMER and
///      CROSS-POLICY tests. A DIFFERENT action's struct uses a DIFFERENT typehash, so the
///      same signed bytes can never be reinterpreted as a different action.
contract PolicyControlBridge is EIP712 {
    using ECDSA for bytes32;

    /// @dev Mirrors the vault's own `VaultMode` enum ordinals exactly (EcdsaOnly=0,
    ///      PqOnly=1, Hybrid=2). Not declared as a shared type — the bridge only ever
    ///      receives the raw `uint8` from {IPolicyControlCredentialSource.vaults} and
    ///      compares against these ordinals directly, avoiding any dependency on a
    ///      specific vault's enum declaration.
    uint8 private constant MODE_ECDSA_ONLY = 0;
    uint8 private constant MODE_PQ_ONLY = 1;
    uint8 private constant MODE_HYBRID = 2;

    /// @notice The sole principal permitted to call {pause}. Immutable: no rotation, no
    ///         `transferOwnership`, no renounce. Losing this key loses only the FREEZE
    ///         capability — the fail-safe direction (design doc §6.3).
    address public immutable EMERGENCY_PAUSER;

    /// @notice One-way. There is no `unpause()` — not merely unimplemented, but
    ///         structurally absent from this contract's ABI (design doc L11, T24).
    bool public paused;

    /// @notice Dedicated policy-control nonce, keyed by (consumer, owner). See L10.
    mapping(address consumer => mapping(address owner => uint256)) public controlNonce;

    struct EnrollControllerIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        address controller;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    struct StrengthenLimitIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        uint256 newLimit;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    struct ProposeWeakeningIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        uint256 newLimit;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    struct ApplyWeakeningIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    struct CancelWeakeningIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    struct SetAdmitterIntent {
        address consumer;
        address owner;
        address policy;
        address asset;
        address admitter;
        bool allowed;
        uint64 epoch;
        uint256 nonce;
        uint256 deadline;
    }

    /// @dev Includes `asset`, unlike the design doc's illustrative struct sketch in §5.2.
    ///      Every OTHER signed action there (SetLimit, ProposeWeakening, ApplyWeakening,
    ///      SetAdmitter) is scoped to a full (consumer, owner, asset) subject, matching
    ///      `DailySpendLimitPolicy`'s own per-subject `SpendState` keying and every
    ///      transition-matrix precondition ("P", "C") elsewhere in the design. Enrolling
    ///      without `asset` would be the ONE action in the whole lane operating at a
    ///      different granularity — a strictly BROADER grant of authority than anything
    ///      else here exercises or tests. Treated as a doc omission and corrected
    ///      conservatively rather than implemented as a new, wider capability.
    bytes32 private constant ENROLL_CONTROLLER_TYPEHASH = keccak256(
        "EnrollController(address consumer,address owner,address policy,address asset,address controller,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    bytes32 private constant STRENGTHEN_LIMIT_TYPEHASH = keccak256(
        "StrengthenLimit(address consumer,address owner,address policy,address asset,uint256 newLimit,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    /// @dev DISTINCT from {STRENGTHEN_LIMIT_TYPEHASH} despite the identical field list —
    ///      §5.2's whole point. A tenant signing "ProposeWeakening" is knowingly starting
    ///      a delayed governance action, not authorizing an immediate change; the
    ///      typehash makes that distinction part of the digest itself, not a value the
    ///      policy has to classify after the fact from data that could have moved
    ///      between signing and execution.
    bytes32 private constant PROPOSE_WEAKENING_TYPEHASH = keccak256(
        "ProposeWeakening(address consumer,address owner,address policy,address asset,uint256 newLimit,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    /// @dev Requiring a FRESH signed intent to apply a matured weakening (design doc
    ///      §5.5) forces the caller to hold CURRENT credentials at apply time, not just
    ///      at propose time — and, with O2 removing owner-direct cancellation, preserves
    ///      the tenant's ability to simply decline to apply by never signing this.
    bytes32 private constant APPLY_WEAKENING_TYPEHASH = keccak256(
        "ApplyWeakening(address consumer,address owner,address policy,address asset,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    /// @dev Not named in the design doc's illustrative §5.2 list, which enumerates five
    ///      structs without stating the list is closed. Cancellation is a mutating
    ///      bridge entrypoint exactly like the other five (it clears storage), so it
    ///      needs the same replay-bound, epoch-bound, pausable signed-intent treatment —
    ///      omitting it would leave the one mutating action in the whole lane reachable
    ///      without a signature. Shape mirrors {ApplyWeakeningIntent} exactly; the
    ///      typehash differs so a cancel signature can never be replayed as an apply.
    bytes32 private constant CANCEL_WEAKENING_TYPEHASH = keccak256(
        "CancelWeakening(address consumer,address owner,address policy,address asset,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    bytes32 private constant SET_ADMITTER_TYPEHASH = keccak256(
        "SetAdmitter(address consumer,address owner,address policy,address asset,address admitter,bool allowed,uint64 epoch,uint256 nonce,uint256 deadline)"
    );

    event BridgeRetired();
    event ControllerEnrolled(address indexed consumer, address indexed owner, address indexed policy, address asset);

    /// @notice Emitted `msg.sender` is not {EMERGENCY_PAUSER}.
    error NotPauser();
    /// @notice {pause} called on an already-paused bridge.
    error AlreadyPaused();
    /// @notice Any mutating call attempted once {paused} — including applying an
    ///         already-mature weakening (design doc §6.3's "subtle requirement", §9.12).
    error BridgeIsPaused();
    /// @notice The intent's `deadline` has passed. Bounds submission of the intent —
    ///         distinct from a proposal's own `validAfter`/`expiresAt` (design doc §5.3).
    error IntentExpired(uint256 deadline, uint256 blockTimestamp);
    /// @notice The intent's `nonce` does not match the expected next value for
    ///         (consumer, owner) — covers both replay (too low) and out-of-order
    ///         submission (too high), since nonces are strictly sequential (L10).
    error InvalidNonce(uint256 expected, uint256 provided);
    /// @notice The intent's `epoch` does not match the consumer's CURRENT
    ///         `policyControlEpoch(owner)` — a rotation or recovery happened after this
    ///         intent was signed (design doc §5.4, T8).
    error StaleControlEpoch(uint64 expected, uint64 provided);
    /// @notice Recovered ECDSA signer does not match the consumer's CURRENT
    ///         `ecdsaSigner` for `owner`, under a mode that requires it.
    error InvalidEcdsaSignature();
    /// @notice PQ signature failed verification against the consumer's CURRENT
    ///         `pqPublicKey` for `owner`, under a mode that requires it, via the
    ///         consumer's OWN configured `pqVerifier` — see the corrected L6.
    error InvalidPQSignature();
    /// @notice The named consumer reports no vault for `owner` — fail closed rather than
    ///         authenticate against zeroed/default credentials (§9.11).
    error VaultDoesNotExist();

    constructor(address emergencyPauser) EIP712("WalletWallPolicyControlBridge", "1") {
        EMERGENCY_PAUSER = emergencyPauser;
    }

    /// @notice Permanently disables every mutating bridge entrypoint. One-way; see
    ///         {paused}. Never alters an enforced policy value, a controller, accounting
    ///         state, or `check()`/`revalidate()` — the gate lives entirely here, never
    ///         in the policy (design doc §6.3).
    function pause() external {
        if (msg.sender != EMERGENCY_PAUSER) revert NotPauser();
        if (paused) revert AlreadyPaused();
        paused = true;
        emit BridgeRetired();
    }

    /// @notice The one-time, immediate `PRISTINE -> canonical bridge` enrolment (U2),
    ///         authenticated by the subject owner's CURRENT credentials rather than
    ///         `msg.sender` — see the design doc §15.1 for why owner-direct bootstrap
    ///         would strand a recovered tenant behind a stale key.
    function enrollController(
        EnrollControllerIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _enrollControllerDigest(intent),
            ecdsaSignature,
            pqSignature
        );

        IPolicyControlTarget(intent.policy).bridgeEnrollController(
            intent.consumer,
            intent.owner,
            intent.asset,
            intent.controller
        );
        emit ControllerEnrolled(intent.consumer, intent.owner, intent.policy, intent.asset);
    }

    /// @notice Immediate strengthening once controller-active. Reverts at the policy
    ///         ({DailySpendLimitPolicy.WrongTransitionKind}) if `newLimit` would actually
    ///         be a weakening — a signed StrengthenLimit intent authorizes only that.
    function strengthenLimit(
        StrengthenLimitIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _strengthenLimitDigest(intent),
            ecdsaSignature,
            pqSignature
        );
        IPolicyControlTarget(intent.policy).bridgeStrengthenLimit(
            intent.consumer,
            intent.owner,
            intent.asset,
            intent.newLimit
        );
    }

    /// @notice Proposes a weakening once controller-active. Matures after the policy's
    ///         own POLICY_CONTROL_DELAY; must be separately applied via
    ///         {applyWeakening} with a FRESH signed intent (§5.5).
    function proposeWeakening(
        ProposeWeakeningIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _proposeWeakeningDigest(intent),
            ecdsaSignature,
            pqSignature
        );
        IPolicyControlTarget(intent.policy).bridgeProposeWeakening(
            intent.consumer,
            intent.owner,
            intent.asset,
            intent.newLimit,
            intent.epoch
        );
    }

    /// @notice Applies a matured weakening. Blocked once {paused} EVEN IF the proposal
    ///         is already mature — the subtle requirement design doc §6.3/§9.12 exists
    ///         to close: pausing after an attacker proposes but before they apply must
    ///         not leave the apply half reachable.
    function applyWeakening(
        ApplyWeakeningIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _applyWeakeningDigest(intent),
            ecdsaSignature,
            pqSignature
        );
        IPolicyControlTarget(intent.policy).bridgeApplyWeakening(
            intent.consumer,
            intent.owner,
            intent.asset,
            intent.epoch
        );
    }

    /// @notice Cancels a pending weakening, immediately — strengthening-ward, so this
    ///         needs no epoch re-check at the policy beyond the bridge's own freshness
    ///         proof for THIS intent.
    function cancelWeakening(
        CancelWeakeningIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _cancelWeakeningDigest(intent),
            ecdsaSignature,
            pqSignature
        );
        IPolicyControlTarget(intent.policy).bridgeCancelWeakening(intent.consumer, intent.owner, intent.asset);
    }

    /// @notice Admitter repair (add or remove a delegated admission caller) once
    ///         controller-active. Immediate — a liveness action, not a weakening (L5):
    ///         adding an admitter confers no capability an existing one lacked.
    function setAdmitter(
        SetAdmitterIntent calldata intent,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external {
        _requireNotPaused();
        _verifyAndConsume(
            intent.consumer,
            intent.owner,
            intent.policy,
            intent.epoch,
            intent.nonce,
            intent.deadline,
            _setAdmitterDigest(intent),
            ecdsaSignature,
            pqSignature
        );
        IPolicyControlTarget(intent.policy).bridgeSetAdmitter(
            intent.consumer,
            intent.owner,
            intent.asset,
            intent.admitter,
            intent.allowed
        );
    }

    function _requireNotPaused() private view {
        if (paused) revert BridgeIsPaused();
    }

    /// @dev Split out of {enrollController} to keep that frame within the EVM stack
    ///      limit, mirroring the vault's own {_authorizeRotation} split.
    function _enrollControllerDigest(EnrollControllerIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        ENROLL_CONTROLLER_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.controller,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    function _strengthenLimitDigest(StrengthenLimitIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        STRENGTHEN_LIMIT_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.newLimit,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    function _proposeWeakeningDigest(ProposeWeakeningIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        PROPOSE_WEAKENING_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.newLimit,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    function _applyWeakeningDigest(ApplyWeakeningIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        APPLY_WEAKENING_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    function _cancelWeakeningDigest(CancelWeakeningIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        CANCEL_WEAKENING_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    function _setAdmitterDigest(SetAdmitterIntent calldata intent) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        SET_ADMITTER_TYPEHASH,
                        intent.consumer,
                        intent.owner,
                        intent.policy,
                        intent.asset,
                        intent.admitter,
                        intent.allowed,
                        intent.epoch,
                        intent.nonce,
                        intent.deadline
                    )
                )
            );
    }

    /// @dev THE SHARED AUTHENTICATION CORE. Every bridge action funnels through this:
    ///      deadline, nonce (checked THEN incremented — success-only, per §10.6), epoch,
    ///      and dual ECDSA/PQ signature recovery against the consumer's CURRENT
    ///      credentials, read live via {IPolicyControlCredentialSource}. Reverts fail
    ///      closed on a nonexistent vault (§9.11) rather than authenticating against
    ///      zeroed defaults.
    function _verifyAndConsume(
        address consumer,
        address owner,
        address policy,
        uint64 signedEpoch,
        uint256 signedNonce,
        uint256 deadline,
        bytes32 digest,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) private {
        policy; // reserved for future action-target checks; unused for now

        if (block.timestamp > deadline) revert IntentExpired(deadline, block.timestamp);

        uint256 expectedNonce = controlNonce[consumer][owner];
        if (signedNonce != expectedNonce) revert InvalidNonce(expectedNonce, signedNonce);

        uint64 currentEpoch = IPolicyControlCredentialSource(consumer).policyControlEpoch(owner);
        if (signedEpoch != currentEpoch) revert StaleControlEpoch(currentEpoch, signedEpoch);

        _authenticateCurrentCredentials(consumer, owner, digest, ecdsaSignature, pqSignature);

        // Effects last: authentication must fully succeed before the sequence advances.
        controlNonce[consumer][owner] = expectedNonce + 1;
    }

    /// @dev Split out of {_verifyAndConsume} to keep that frame within the EVM stack
    ///      limit. Reads the consumer's CURRENT credentials live and reverts on any
    ///      failure; returns nothing on success.
    function _authenticateCurrentCredentials(
        address consumer,
        address owner,
        bytes32 digest,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) private view {
        (address ecdsaSigner, bytes memory pqPublicKey, , , uint8 mode, bool exists) = IPolicyControlCredentialSource(
            consumer
        ).vaults(owner);
        if (!exists) revert VaultDoesNotExist();

        bool needEcdsa = mode == MODE_ECDSA_ONLY || mode == MODE_HYBRID;
        bool needPq = mode == MODE_PQ_ONLY || mode == MODE_HYBRID;

        if (needEcdsa && digest.recover(ecdsaSignature) != ecdsaSigner) revert InvalidEcdsaSignature();
        if (needPq) {
            IPQCVerifier verifier = IPolicyControlCredentialSource(consumer).pqVerifier();
            if (!verifier.verify(digest, pqPublicKey, pqSignature)) revert InvalidPQSignature();
        }
    }
}
