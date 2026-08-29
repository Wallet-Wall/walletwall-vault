// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";
import "./IPolicyEngine.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title WalletWallVault
 * @notice Research prototype for a hybrid classical (ECDSA) + post-quantum (PQ)
 *         withdrawal-authorization vault.
 *
 * @dev  =======================================================================
 *       RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY.
 *       DO NOT USE WITH REAL FUNDS.
 *       The PQ verifier wired into this vault may be a mock/placeholder
 *       (see {MockMLDSAVerifier}) that performs NO real cryptographic
 *       verification. Read docs/Security_Assumptions.md before doing anything.
 *       =======================================================================
 *
 *       Withdrawals are authorized by an EIP-712 typed message. Depending on the
 *       vault's {VaultMode}, the authorization requires a classical ECDSA
 *       signature, a post-quantum signature (validated through {IPQCVerifier}),
 *       or both (the intended default). Replay is prevented by a per-owner nonce
 *       and a deadline embedded in the signed message.
 */
contract WalletWallVault is ReentrancyGuard, Pausable, Ownable2Step, EIP712 {
    using ECDSA for bytes32;

    /**
     * @notice Authorization policy for a vault.
     * @dev Hybrid is the intended default and requires BOTH a valid ECDSA
     *      signature and a valid PQ signature. EcdsaOnly / PqOnly exist for
     *      research and migration experiments and are weaker — in particular
     *      PqOnly relies entirely on the (possibly mock) PQ verifier.
     */
    enum VaultMode {
        EcdsaOnly, // 0 - classical signature only (no PQ protection)
        PqOnly, // 1 - PQ signature only (no classical fallback)
        Hybrid // 2 - requires both ECDSA and PQ (intended default)
    }

    struct VaultOwner {
        address ecdsaSigner;
        bytes pqPublicKey;
        uint256 nonce;
        uint256 balance;
        VaultMode mode;
        bool exists;
    }

    /**
     * @notice EIP-712 typed withdrawal authorization.
     * @dev `vaultMode` is encoded as uint8 (the {VaultMode} value). The signature
     *      becomes invalid if any field changes, providing replay/tamper
     *      protection across owner, recipient, amount, nonce, deadline, and mode.
     */
    struct Withdrawal {
        address vaultOwner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
        uint8 vaultMode;
    }

    /// @dev EIP-712 type hash for {Withdrawal}.
    bytes32 public constant WITHDRAWAL_TYPEHASH = keccak256(
        "Withdrawal(address vaultOwner,address recipient,uint256 amount,uint256 nonce,uint256 deadline,uint8 vaultMode)"
    );

    /// @dev EIP-712 type hash for credential rotation.
    bytes32 public constant ROTATE_CREDENTIALS_TYPEHASH = keccak256(
        "RotateCredentials(address vaultOwner,address newEcdsaSigner,bytes newPQPublicKey,uint256 nonce,uint256 deadline)"
    );

    /// @dev Algorithm id reported by {MockMLDSAVerifier}. Must match
    ///      MockMLDSAVerifier.algorithmId() exactly. Used to block the unsafe
    ///      PqOnly configuration while a mock (non-cryptographic) verifier is wired in.
    bytes32 public constant MOCK_ML_DSA_65_ALGORITHM_ID = keccak256("MOCK-ML-DSA-65");

    /// @notice Delay between proposing and applying a PQ verifier update.
    uint256 public constant PQ_VERIFIER_UPDATE_DELAY = 2 days;

    /// @notice Delay required before a recovery request can be executed.
    uint256 public constant RECOVERY_DELAY = 7 days;

    /// @notice Maximum number of guardians per vault.
    /// @dev Bounds the O(n) loops in the recovery flow so a guardian set can never
    ///      be large enough to make initiate/support/execute/cancel un-runnable.
    uint256 public constant MAX_GUARDIANS = 32;

    /// @notice Governance delay for changes to the policy engine.
    uint256 public constant POLICY_ENGINE_UPDATE_DELAY = 2 days;

    /// @notice Governance delay for changes to large-transaction parameters.
    uint256 public constant LARGE_TX_PARAMS_UPDATE_DELAY = 2 days;

    /// @notice How long a MATURED governance proposal stays applicable before expiring.
    /// @dev WHY AN UPPER BOUND EXISTS. A propose/apply delay is only worth the reaction
    ///      window it actually delivers at the instant the change takes effect. With no
    ///      expiry a matured proposal stays exercisable forever, so an owner can PRE-ARM
    ///      one at a quiet moment — when nothing is at stake and no observer has cause to
    ///      react — let the delay lapse unapplied, and bank an INSTANT swap indefinitely.
    ///      Exercised at the moment it matters, that costs zero delay and gives zero fresh
    ///      notice, which is precisely what the delay exists to prevent.
    ///
    ///      This binds hardest on {pqVerifier}. It is contract-level, not per-vault, so one
    ///      swap moves the authorization authority for EVERY vault at once; in
    ///      {VaultMode.PqOnly} it is the SOLE gate (no classical fallback) and, unlike the
    ///      policy engine, nothing pins the verifier a withdrawal was admitted under — there
    ///      is no queue-time sticky floor for it. It also gates {rotateCredentials}, so a
    ///      forging verifier enables credential takeover, not merely one withdrawal. The
    ///      {PqOnlyDisabledForMockVerifier} guard runs only at vault CREATION, so a banked
    ///      swap can retroactively restore exactly the configuration that guard forbids for
    ///      vaults that already exist.
    ///
    ///      Bounding the applicable window restores bounded warning: any governance action
    ///      executable right now was announced by its proposal event within the last
    ///      DELAY + GOVERNANCE_GRACE_PERIOD. The 2-day delay / 14-day grace pairing matches
    ///      Compound's Timelock, which carries a GRACE_PERIOD for this same reason. The
    ///      window is generous on purpose: expiry is an anti-banking bound, not an execution
    ///      race, so an honest operator is never realistically rushed.
    uint256 public constant GOVERNANCE_GRACE_PERIOD = 14 days;

    struct RecoveryRequest {
        address newEcdsaSigner;
        bytes newPQPublicKey;
        uint256 executeAfter;
        uint256 supportCount;
        bool exists;
    }

    /// @notice The four authorizing signatures for {rotateCredentials}, grouped to
    ///         keep the function's stack within limits. Each is interpreted per the
    ///         vault mode: ECDSA fields are ignored for PqOnly, PQ fields for EcdsaOnly.
    /// @param currentEcdsaSignature ECDSA signature from the credential being replaced.
    /// @param currentPqSignature    PQ signature from the credential being replaced.
    /// @param newEcdsaSignature     ECDSA proof-of-possession from the incoming signer.
    /// @param newPqSignature        PQ proof-of-possession from the incoming key.
    struct RotationAuth {
        bytes currentEcdsaSignature;
        bytes currentPqSignature;
        bytes newEcdsaSignature;
        bytes newPqSignature;
    }

    /// @notice A signed large withdrawal reserved for delayed execution.
    struct PendingWithdrawal {
        address owner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 queuedAt;
        uint256 readyAt;
        bytes32 operationId;
        /// @dev Policy engine address active when the withdrawal was queued (the
        ///      engine that ADMITTED it). Finalization revalidates against this
        ///      engine's CURRENT state as a sticky floor — replacing or disabling
        ///      the active engine does not erase the restrictions this withdrawal
        ///      was admitted under — and additionally against the currently active
        ///      engine when different. The floor holds at engine-ADDRESS
        ///      granularity: the engine's internal configuration (sanctions list
        ///      contents, allowlist entries, a composite's module set) is read
        ///      LIVE at finalization and remains mutable by that engine's own
        ///      admin. Revalidation uses the read-only {IPolicyEngine.revalidate},
        ///      never the stateful {IPolicyEngine.check}, so stateful admission
        ///      accounting (e.g. daily spend booked at queue time) is never
        ///      double-counted.
        address policyEngineAtQueue;
        bool exists;
    }

    /// @notice Post-quantum verifier at the vault's PQ trust boundary.
    /// @dev Mutable only through the timelocked proposal/apply flow.
    IPQCVerifier public pqVerifier;

    /// @notice Verifier proposed for the next timelocked update.
    address public pendingPQVerifier;

    /// @notice Earliest timestamp at which the pending verifier can be applied.
    uint256 public pendingPQVerifierValidAfter;

    mapping(address => VaultOwner) public vaults;

    /// @notice Monotonic counter, per vaultOwner, that any external policy-control
    ///         authority (see the canonical `PolicyControlBridge`) binds a signed
    ///         configuration intent to.
    /// @dev Bumped ONLY by {rotateCredentials} and {executeRecovery} — the two events
    ///      after which the vault's own credential authority has genuinely changed.
    ///      Deliberately NOT bumped by {initiateRecovery} or {supportRecovery}: a
    ///      single malicious guardian opening (or supporting) a request must not be able
    ///      to invalidate a tenant's in-flight policy-control actions before recovery
    ///      actually succeeds — see docs/Policy_Control_Authority_Design.md §9.3.
    ///
    ///      This vault makes NO call into any policy contract to bump this counter, in
    ///      either direction. It is a local storage write, so a broken or reverting
    ///      policy engine can never block credential rotation or account recovery —
    ///      see docs/Policy_Control_Authority_Design.md §10.3.
    ///
    ///      Incremented with CHECKED arithmetic (unlike `nonce` at the same call
    ///      sites, which stays `unchecked`): "monotonic" above is meant literally, not
    ///      as a bounded-in-practice approximation — a `uint64` would in fact wrap only
    ///      after 2^64 rotations/recoveries for one vaultOwner, astronomically beyond
    ///      any real usage, but this repo does not rely on that separately-reasoned
    ///      fact to back an executable claim when the checked increment can make the
    ///      claim true by construction instead, at a trivial bytecode cost.
    mapping(address => uint64) public policyControlEpoch;

    /// @notice Guardians for each vault.
    mapping(address => address[]) public vaultGuardians;

    /// @notice Pending recovery request for each vault.
    mapping(address => RecoveryRequest) public recoveryRequests;

    /// @notice Tracks if a guardian has supported a specific recovery request.
    /// @dev vaultOwner => guardian => supported
    mapping(address => mapping(address => bool)) public recoverySupports;

    /// @notice One pending large withdrawal per vault owner.
    mapping(address => PendingWithdrawal) public pendingWithdrawals;

    /// @notice Amount above which withdrawals must use the timelocked queue. Zero disables the feature.
    uint256 public largeTxThreshold;

    /// @notice Delay between queueing and finalizing a large withdrawal.
    uint256 public largeTxDelay;

    uint256 public pendingLargeTxThreshold;
    uint256 public pendingLargeTxDelay;
    uint256 public pendingLargeTxValidAfter;

    /// @notice Active policy engine (address(0) = feature disabled, no check performed).
    IPolicyEngine public policyEngine;

    // Policy engine governance pending state
    address public pendingPolicyEngine;
    uint256 public pendingPolicyEngineValidAfter;

    // -------------------------------------------------------------------------
    // Treasury withdrawal quorum
    // -------------------------------------------------------------------------
    // Distinct from the credential-recovery guardian quorum: uses the same guardian
    // set but with a vault-owner-configurable threshold applied at large-withdrawal
    // finalization rather than at credential recovery execution.

    /// @notice Required guardian approvals before a large withdrawal can finalize.
    ///         Per vault. 0 = treasury quorum disabled for this vault.
    mapping(address => uint256) public treasuryQuorumThreshold;

    /// @notice Guardian approval counts per queued-withdrawal operationId.
    mapping(bytes32 => uint256) public treasuryApprovalCount;

    /// @notice Whether a specific guardian has approved a specific operationId.
    /// @dev operationId => guardian => approved
    mapping(bytes32 => mapping(address => bool)) public treasuryApprovals;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------
    event VaultCreated(address indexed owner, address ecdsaSigner, bytes pqPublicKey, VaultMode mode);
    event Deposited(address indexed owner, address indexed from, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce, VaultMode mode);
    event EcdsaSignerUpdated(address indexed owner, address oldSigner, address newSigner);
    event PQKeyUpdated(address indexed owner);
    event CredentialsRotated(address indexed owner, address newEcdsaSigner);
    event PQVerifierUpdateProposed(
        address indexed currentVerifier,
        address indexed proposedVerifier,
        uint256 validAfter
    );
    event PQVerifierUpdateCancelled(address indexed cancelledVerifier);
    event PQVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event GuardiansSet(address indexed owner, address[] guardians);
    event RecoveryInitiated(address indexed owner, address newEcdsaSigner, uint256 executeAfter);
    event RecoverySupported(address indexed owner, address indexed guardian, uint256 currentSupports);
    event RecoveryExecuted(address indexed owner, address newEcdsaSigner);
    event RecoveryCancelled(address indexed owner);
    event WithdrawalQueued(
        bytes32 indexed operationId,
        address indexed owner,
        address indexed recipient,
        uint256 amount,
        uint256 nonce,
        uint256 queuedAt,
        uint256 readyAt
    );
    event WithdrawalFinalized(
        bytes32 indexed operationId,
        address indexed owner,
        address indexed recipient,
        uint256 amount
    );
    event WithdrawalCancelled(bytes32 indexed operationId, address indexed owner, uint256 amount);
    event LargeTxParamsProposed(uint256 newThreshold, uint256 newDelay, uint256 validAfter);
    event LargeTxParamsApplied(uint256 newThreshold, uint256 newDelay);
    event LargeTxParamsCancelled(uint256 cancelledThreshold, uint256 cancelledDelay);
    event PolicyEngineUpdateProposed(address indexed proposed, uint256 validAfter);
    event PolicyEngineUpdateCancelled(address indexed cancelled);
    event PolicyEngineUpdated(address indexed oldEngine, address indexed newEngine);
    event TreasuryQuorumThresholdSet(address indexed vaultOwner, uint256 threshold);
    event TreasuryWithdrawalApproved(bytes32 indexed operationId, address indexed guardian, uint256 approvalCount);

    // ---------------------------------------------------------------------
    // Custom errors
    // ---------------------------------------------------------------------
    error ZeroAddress();
    error ZeroAmount();
    error ZeroRecipient();
    error EmptyPQPublicKey();
    error VaultAlreadyExists();
    error VaultDoesNotExist();
    error InsufficientBalance();
    error InvalidNonce(uint256 expected, uint256 provided);
    error DeadlineExpired(uint256 deadline, uint256 nowTimestamp);
    error VaultModeMismatch(VaultMode configured, VaultMode requested);
    error PqOnlyDisabledForMockVerifier();
    error InvalidEcdsaSignature();
    error InvalidPQSignature();
    error InvalidRotationSignature();
    error InvalidNewEcdsaProof();
    error InvalidNewPQProof();
    error UseRotateCredentials();
    error TransferFailed();
    error NoPendingPQVerifier();
    error PQVerifierUpdateNotReady(uint256 validAfter, uint256 currentTimestamp);
    /// @notice A proposed or pending governance destination has no runtime code.
    /// @dev Proves only that the address is code-bearing at this instant — not
    ///      interface conformance, behavioral correctness, or future availability.
    error NoCode(address account);
    /// @notice A matured governance proposal outlived {GOVERNANCE_GRACE_PERIOD}; re-propose.
    error ProposalExpired(uint256 validAfter, uint256 expiresAt, uint256 currentTimestamp);
    error NotAGuardian();
    error AlreadySupported();
    error RecoveryNotReady();
    error RecoveryDoesNotExist();
    error InsufficientSupports();
    error InvalidGuardianSet();
    error TooManyGuardians(uint256 provided, uint256 max);
    error ZeroGuardian();
    error DuplicateGuardian(address guardian);
    error GuardianIsOwner();
    error RecoveryAlreadyExists();
    /// @notice The existing request has already reached the guardian majority
    ///         required to execute; only execution or owner cancellation may
    ///         clear it, never replacement by a single guardian.
    error RecoveryAlreadyApproved();
    error PendingWithdrawalExists();
    error NoPendingWithdrawal();
    error NotPendingWithdrawalOwner(address expectedOwner, address caller);
    error PendingWithdrawalMismatch(bytes32 expectedOperationId, bytes32 providedOperationId);
    error WithdrawalNotReady(uint256 readyAt, uint256 currentTimestamp);
    error UseLargeWithdrawal();
    error LargeWithdrawalNotRequired();
    error LargeTxTimelockDisabled();
    error ZeroDelay();
    error NoPendingLargeTxUpdate();
    error LargeTxUpdateNotReady(uint256 validAfter, uint256 currentTimestamp);
    error PolicyViolation(string reason);
    error PolicyEngineUnavailable(address engine);
    error NoPendingPolicyEngine();
    error PolicyEngineUpdateNotReady(uint256 validAfter, uint256 currentTimestamp);
    error TreasuryQuorumNotMet(uint256 required, uint256 current);
    error TreasuryAlreadyApproved();

    /**
     * @param _pqVerifier Address of the {IPQCVerifier} implementation. On a
     *        prototype deployment this is typically {MockMLDSAVerifier}.
     */
    constructor(address _pqVerifier) Ownable(msg.sender) EIP712("WalletWallVault", "1") {
        if (_pqVerifier == address(0)) revert ZeroAddress();
        pqVerifier = IPQCVerifier(_pqVerifier);
    }

    // ---------------------------------------------------------------------
    // Recovery mechanism
    // ---------------------------------------------------------------------

    /**
     * @notice Sets the guardians for the caller's vault.
     * @param guardians Array of guardian addresses.
     * @dev The set must be non-empty, within {MAX_GUARDIANS}, free of the zero
     *      address, free of the vault owner, and free of duplicates. Duplicates are
     *      rejected because the majority threshold is derived from the array length
     *      while each address can only support a recovery once; an unchecked
     *      duplicate would raise the threshold above the number of distinct
     *      supporters and permanently brick recovery. If an armed
     *      {treasuryQuorumThreshold} for this vault would exceed the NEW guardian
     *      count, the shrink is rejected outright (see {setTreasuryQuorumThreshold})
     *      rather than silently stranding the threshold — lower the threshold first.
     */
    function setGuardians(address[] calldata guardians) external {
        if (!vaults[msg.sender].exists) revert VaultDoesNotExist();
        if (guardians.length == 0) revert InvalidGuardianSet();
        if (guardians.length > MAX_GUARDIANS) revert TooManyGuardians(guardians.length, MAX_GUARDIANS);

        uint256 armedTreasuryThreshold = treasuryQuorumThreshold[msg.sender];
        if (armedTreasuryThreshold > guardians.length) {
            revert TooManyGuardians(armedTreasuryThreshold, guardians.length);
        }

        for (uint256 i = 0; i < guardians.length; i++) {
            address guardian = guardians[i];
            if (guardian == address(0)) revert ZeroGuardian();
            if (guardian == msg.sender) revert GuardianIsOwner();
            for (uint256 j = i + 1; j < guardians.length; j++) {
                if (guardians[j] == guardian) revert DuplicateGuardian(guardian);
            }
        }

        // Cancel pending recovery and clear existing supports to maintain consistency
        if (recoveryRequests[msg.sender].exists) {
            delete recoveryRequests[msg.sender];
            emit RecoveryCancelled(msg.sender);
        }

        address[] storage existing = vaultGuardians[msg.sender];
        for (uint256 i = 0; i < existing.length; i++) {
            recoverySupports[msg.sender][existing[i]] = false;
        }

        // Treasury approvals are keyed by operationId and guardian address. Clear them
        // using the OLD guardian set before it is replaced so no stale approvals persist.
        PendingWithdrawal storage pendingForGuardianChange = pendingWithdrawals[msg.sender];
        if (pendingForGuardianChange.exists) {
            _clearTreasuryApprovalsForOp(msg.sender, pendingForGuardianChange.operationId);
        }

        vaultGuardians[msg.sender] = guardians;
        emit GuardiansSet(msg.sender, guardians);
    }

    /**
     * @dev The guardian majority required to execute (or, per H4-A, to protect from
     *      replacement) a recovery request for `vaultOwner`, derived live from the
     *      CURRENT guardian set. Shared by {initiateRecovery} and {executeRecovery}
     *      so the two can never disagree about what majority a request needs.
     */
    function _requiredRecoverySupports(address vaultOwner) internal view returns (uint256) {
        return (vaultGuardians[vaultOwner].length / 2) + 1;
    }

    /**
     * @notice Initiates a recovery request for a vault.
     * @dev Must be called by a guardian of the vault to prevent arbitrary DOS.
     */
    function initiateRecovery(
        address vaultOwner,
        address newEcdsaSigner,
        bytes calldata newPQPublicKey
    ) external whenNotPaused {
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();

        address[] storage guardians = vaultGuardians[vaultOwner];
        if (guardians.length == 0) revert InvalidGuardianSet();

        // A live request may not be overwritten. Once its execution window has
        // elapsed, an under-supported request is replaceable so a single guardian
        // cannot permanently deny recovery when the owner cannot cancel it — but
        // (H4-A) once the request has already reached the guardian majority
        // {executeRecovery} would accept, it is protected exactly like a live one:
        // only execution or owner cancellation may clear it. Reusing the identical
        // majority formula {executeRecovery} applies keeps "already live" and
        // "already approved" from ever disagreeing about the same request.
        RecoveryRequest storage existingRequest = recoveryRequests[vaultOwner];
        if (existingRequest.exists) {
            if (block.timestamp < existingRequest.executeAfter) {
                revert RecoveryAlreadyExists();
            }
            if (existingRequest.supportCount >= _requiredRecoverySupports(vaultOwner)) {
                revert RecoveryAlreadyApproved();
            }
        }
        _validateCredentials(vault.mode, newEcdsaSigner, newPQPublicKey);

        bool isActuallyGuardian = false;
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == msg.sender) {
                isActuallyGuardian = true;
                break;
            }
        }
        if (!isActuallyGuardian) revert NotAGuardian();

        uint256 executeAfter = block.timestamp + RECOVERY_DELAY;
        recoveryRequests[vaultOwner] = RecoveryRequest({
            newEcdsaSigner: newEcdsaSigner,
            newPQPublicKey: newPQPublicKey,
            executeAfter: executeAfter,
            supportCount: 0,
            exists: true
        });

        // Reset supports
        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[vaultOwner][guardians[i]] = false;
        }

        emit RecoveryInitiated(vaultOwner, newEcdsaSigner, executeAfter);
    }

    /**
     * @notice Supports a pending recovery request.
     * @dev Must be called by a designated guardian.
     */
    function supportRecovery(address vaultOwner) external {
        if (!recoveryRequests[vaultOwner].exists) revert RecoveryDoesNotExist();

        bool isActuallyGuardian = false;
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == msg.sender) {
                isActuallyGuardian = true;
                break;
            }
        }
        if (!isActuallyGuardian) revert NotAGuardian();
        if (recoverySupports[vaultOwner][msg.sender]) revert AlreadySupported();

        recoverySupports[vaultOwner][msg.sender] = true;
        recoveryRequests[vaultOwner].supportCount++;

        emit RecoverySupported(vaultOwner, msg.sender, recoveryRequests[vaultOwner].supportCount);
    }

    /**
     * @notice Executes a recovery request after the delay and sufficient support.
     */
    function executeRecovery(address vaultOwner) external nonReentrant whenNotPaused {
        RecoveryRequest storage request = recoveryRequests[vaultOwner];
        if (!request.exists) revert RecoveryDoesNotExist();
        if (block.timestamp < request.executeAfter) revert RecoveryNotReady();

        uint256 required = _requiredRecoverySupports(vaultOwner);
        if (request.supportCount < required) revert InsufficientSupports();

        VaultOwner storage vault = vaults[vaultOwner];
        address recoveredSigner = request.newEcdsaSigner;
        bytes memory recoveredPQPublicKey = request.newPQPublicKey;
        vault.ecdsaSigner = recoveredSigner;
        vault.pqPublicKey = recoveredPQPublicKey;
        unchecked {
            vault.nonce++;
        }
        // Credential authority has genuinely changed: any policy-control action a
        // stale key signed or proposed must stop binding here. CHECKED, not unchecked
        // like `nonce` above — see {policyControlEpoch}'s own doc for why this field's
        // monotonic claim is meant literally.
        policyControlEpoch[vaultOwner]++;

        delete recoveryRequests[vaultOwner];
        // Clean up supports
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[vaultOwner][guardians[i]] = false;
        }

        PendingWithdrawal storage pending = pendingWithdrawals[vaultOwner];
        if (pending.exists) {
            bytes32 operationId = pending.operationId;
            uint256 refund = pending.amount;
            _clearTreasuryApprovalsForOp(vaultOwner, operationId);
            delete pendingWithdrawals[vaultOwner];
            vault.balance += refund;
            emit WithdrawalCancelled(operationId, vaultOwner, refund);
        }

        emit RecoveryExecuted(vaultOwner, recoveredSigner);
    }

    /**
     * @notice Cancels a pending recovery request.
     * @dev Can be called by the vault owner to stop a recovery.
     */
    function cancelRecovery() external {
        if (!recoveryRequests[msg.sender].exists) revert RecoveryDoesNotExist();
        delete recoveryRequests[msg.sender];

        // Clean up supports
        address[] storage guardians = vaultGuardians[msg.sender];
        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[msg.sender][guardians[i]] = false;
        }

        emit RecoveryCancelled(msg.sender);
    }

    // ---------------------------------------------------------------------
    // Vault lifecycle
    // ---------------------------------------------------------------------

    /**
     * @notice Registers a vault for the caller.
     * @param ecdsaSigner The address authorized for classical ECDSA signatures.
     * @param pqPublicKey The PQ public key bytes.
     * @param mode The authorization policy (Hybrid recommended).
     */
    function createVault(
        address ecdsaSigner,
        bytes calldata pqPublicKey,
        VaultMode mode
    ) external payable whenNotPaused {
        if (vaults[msg.sender].exists) revert VaultAlreadyExists();

        // PqOnly is unsafe while the PQ verifier is a mock (no real cryptographic
        // verification), so it must not be the sole authorization layer. EcdsaOnly and
        // Hybrid remain available because they still require a classical signature.
        if (mode == VaultMode.PqOnly && pqVerifier.algorithmId() == MOCK_ML_DSA_65_ALGORITHM_ID) {
            revert PqOnlyDisabledForMockVerifier();
        }

        // Require the credential(s) the chosen mode actually depends on.
        if (mode == VaultMode.EcdsaOnly || mode == VaultMode.Hybrid) {
            if (ecdsaSigner == address(0)) revert ZeroAddress();
        }
        if (mode == VaultMode.PqOnly || mode == VaultMode.Hybrid) {
            if (pqPublicKey.length == 0) revert EmptyPQPublicKey();
        }

        vaults[msg.sender] = VaultOwner({
            ecdsaSigner: ecdsaSigner,
            pqPublicKey: pqPublicKey,
            nonce: 0,
            balance: msg.value,
            mode: mode,
            exists: true
        });

        emit VaultCreated(msg.sender, ecdsaSigner, pqPublicKey, mode);
        if (msg.value > 0) {
            emit Deposited(msg.sender, msg.sender, msg.value);
        }
    }

    /**
     * @notice Removed: direct owner-only credential updates are no longer supported.
     * @dev Tombstone stub — reverts unconditionally and mutates no state. The former
     *      behavior let the vault *owner address* (a classical EOA) replace the ECDSA
     *      signer with no signature from the existing keys, making that classical key
     *      a single point of failure that bypassed PQ protection entirely. Voluntary
     *      rotation now goes through {rotateCredentials} (authorized by the current and
     *      new keys); lost/compromised keys go through guardian recovery. The selector
     *      is retained deliberately so integrators receive an explicit
     *      {UseRotateCredentials} error instead of an opaque missing-function revert.
     */
    function updateEcdsaSigner(address) external pure {
        revert UseRotateCredentials();
    }

    /**
     * @notice Removed: direct owner-only credential updates are no longer supported.
     * @dev Tombstone stub — reverts unconditionally and mutates no state. See
     *      {updateEcdsaSigner}; use {rotateCredentials} for voluntary rotation.
     */
    function updatePQPublicKey(bytes calldata) external pure {
        revert UseRotateCredentials();
    }

    /**
     * @notice Securely rotates vault credentials using both the current and the new keys.
     * @dev Authorization is twofold and mode-dependent:
     *      - The *current* credential(s) must sign the rotation digest, so the keys being
     *        replaced consent to the change. In Hybrid both are required, meaning neither a
     *        broken ECDSA key nor a substituted PQ key can evict the other on its own.
     *      - The *new* credential(s) must also sign the same digest (proof-of-possession),
     *        proving the owner controls them before they take effect. This prevents rotating
     *        to an unusable credential (e.g. a mistyped PQ key) that would otherwise brick a
     *        Pq/Hybrid vault, leaving guardian recovery as the only exit.
     *      Rotation is atomic across both credential fields; to rotate a single credential,
     *      pass the unchanged value (which still must co-sign in Hybrid).
     */
    function rotateCredentials(
        address vaultOwner,
        address newEcdsaSigner,
        bytes calldata newPQPublicKey,
        uint256 deadline,
        RotationAuth calldata auth
    ) external nonReentrant whenNotPaused {
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        _validateCredentials(vault.mode, newEcdsaSigner, newPQPublicKey);

        // Signature verification is delegated so this frame stays within the stack limit.
        _authorizeRotation(vault, vaultOwner, newEcdsaSigner, newPQPublicKey, deadline, auth);

        // ---- Effects ----
        vault.ecdsaSigner = newEcdsaSigner;
        vault.pqPublicKey = newPQPublicKey;
        unchecked {
            vault.nonce++;
        }
        // See {policyControlEpoch}: rotation is the other event that must invalidate
        // any policy-control action the OLD credentials signed or proposed. CHECKED —
        // see {policyControlEpoch}'s own doc.
        policyControlEpoch[vaultOwner]++;

        // A rotation must invalidate every in-flight authorization THAT THE OLD CREDENTIALS
        // SIGNED. The nonce bump above voids signed immediate withdrawals, but a queued large
        // withdrawal is tracked separately and finalizes without re-checking the nonce — so it
        // is cancelled and its reservation refunded here, mirroring {executeRecovery}.
        //
        // Deliberately excluded: a pending guardian recovery request ({recoveryRequests}) is
        // NOT touched here. Guardian recovery is not an authorization derived from (c)/(d)
        // credential authority — it is the documented remedy for LOST OR COMPROMISED
        // credentials, and a successful rotation does not prove the credentials were not
        // compromised: key theft is copy theft, so a thief holding a copied key can rotate
        // too. Cancelling recovery on rotation would hand that thief a standing, pre-signable,
        // front-runnable veto over the exact mechanism this contract designates as the remedy
        // for their own theft. See docs/Guardian_Authority_Design.md §10 for the full
        // adversarial analysis.
        PendingWithdrawal storage pending = pendingWithdrawals[vaultOwner];
        if (pending.exists) {
            bytes32 operationId = pending.operationId;
            uint256 refund = pending.amount;
            _clearTreasuryApprovalsForOp(vaultOwner, operationId);
            delete pendingWithdrawals[vaultOwner];
            vault.balance += refund;
            emit WithdrawalCancelled(operationId, vaultOwner, refund);
        }

        emit CredentialsRotated(vaultOwner, newEcdsaSigner);
    }

    /**
     * @dev Verifies both the current-credential authorization and the new-credential
     *      proof-of-possession for a rotation, reverting on any failure. Split out of
     *      {rotateCredentials} to keep that frame within the EVM stack limit.
     */
    function _authorizeRotation(
        VaultOwner storage vault,
        address vaultOwner,
        address newEcdsaSigner,
        bytes calldata newPQPublicKey,
        uint256 deadline,
        RotationAuth calldata auth
    ) internal view {
        VaultMode mode = vault.mode;
        bool needEcdsa = mode == VaultMode.EcdsaOnly || mode == VaultMode.Hybrid;
        bool needPq = mode == VaultMode.PqOnly || mode == VaultMode.Hybrid;

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ROTATE_CREDENTIALS_TYPEHASH,
                    vaultOwner,
                    newEcdsaSigner,
                    keccak256(newPQPublicKey),
                    vault.nonce,
                    deadline
                )
            )
        );

        // ---- Current-credential authorization (keys being replaced) ----
        if (needEcdsa) {
            if (digest.recover(auth.currentEcdsaSignature) != vault.ecdsaSigner) revert InvalidRotationSignature();
        }
        if (needPq) {
            if (!pqVerifier.verify(digest, vault.pqPublicKey, auth.currentPqSignature)) revert InvalidPQSignature();
        }

        // ---- New-credential proof-of-possession (incoming keys) ----
        if (needEcdsa) {
            if (digest.recover(auth.newEcdsaSignature) != newEcdsaSigner) revert InvalidNewEcdsaProof();
        }
        if (needPq) {
            if (!pqVerifier.verify(digest, newPQPublicKey, auth.newPqSignature)) revert InvalidNewPQProof();
        }
    }

    function _validateCredentials(VaultMode mode, address ecdsaSigner, bytes memory pqPublicKey) internal pure {
        if ((mode == VaultMode.EcdsaOnly || mode == VaultMode.Hybrid) && ecdsaSigner == address(0)) {
            revert ZeroAddress();
        }
        if ((mode == VaultMode.PqOnly || mode == VaultMode.Hybrid) && pqPublicKey.length == 0) {
            revert EmptyPQPublicKey();
        }
    }

    // ---------------------------------------------------------------------
    // Deposits
    // ---------------------------------------------------------------------

    /**
     * @notice Deposits ETH into the caller's own vault.
     */
    function deposit() external payable {
        _deposit(msg.sender);
    }

    /**
     * @notice Deposits ETH into the vault owned by `vaultOwner`.
     * @dev Lets a third party (or relayer) fund an existing vault.
     */
    function depositFor(address vaultOwner) external payable {
        _deposit(vaultOwner);
    }

    function _deposit(address vaultOwner) internal {
        if (msg.value == 0) revert ZeroAmount();
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();
        vault.balance += msg.value;
        emit Deposited(vaultOwner, msg.sender, msg.value);
    }

    // ---------------------------------------------------------------------
    // Withdrawals
    // ---------------------------------------------------------------------

    /**
     * @notice Queues an above-threshold withdrawal for delayed execution.
     * @dev Authorization and policy checks are performed at queue time. The
     *      signed nonce is consumed and the amount is reserved immediately.
     */
    function queueWithdrawal(
        Withdrawal calldata request,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external nonReentrant whenNotPaused {
        VaultOwner storage vault = vaults[request.vaultOwner];

        if (!vault.exists) revert VaultDoesNotExist();
        if (block.timestamp > request.deadline) revert DeadlineExpired(request.deadline, block.timestamp);
        if (request.amount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroRecipient();
        if (request.nonce != vault.nonce) revert InvalidNonce(vault.nonce, request.nonce);
        if (pendingWithdrawals[request.vaultOwner].exists) revert PendingWithdrawalExists();
        if (largeTxThreshold == 0) revert LargeTxTimelockDisabled();
        if (request.amount <= largeTxThreshold) revert LargeWithdrawalNotRequired();

        if (vault.balance < request.amount) revert InsufficientBalance();

        bytes32 operationId;
        {
            VaultMode configuredMode = vault.mode;
            if (request.vaultMode != uint8(configuredMode)) {
                revert VaultModeMismatch(configuredMode, VaultMode(request.vaultMode));
            }

            operationId = _hashTypedDataV4(_structHash(request));
            bool needEcdsa = configuredMode == VaultMode.EcdsaOnly || configuredMode == VaultMode.Hybrid;
            bool needPq = configuredMode == VaultMode.PqOnly || configuredMode == VaultMode.Hybrid;

            if (needEcdsa && operationId.recover(ecdsaSignature) != vault.ecdsaSigner) {
                revert InvalidEcdsaSignature();
            }
            if (needPq && !pqVerifier.verify(operationId, vault.pqPublicKey, pqSignature)) {
                revert InvalidPQSignature();
            }
        }

        // Read the engine ONCE so the recorded policyEngineAtQueue is exactly the
        // engine that admitted this withdrawal, even if governance were somehow
        // interleaved during the external check() call.
        address engineAtQueue = address(policyEngine);
        if (engineAtQueue != address(0)) {
            (bool ok, string memory why) = IPolicyEngine(engineAtQueue).check(
                _policySubject(request.vaultOwner),
                request.recipient,
                request.amount,
                vault.balance
            );
            if (!ok) revert PolicyViolation(why);
        }

        unchecked {
            vault.nonce = request.nonce + 1;
        }
        vault.balance -= request.amount;

        uint256 queuedAt = block.timestamp;
        uint256 readyAt = queuedAt + largeTxDelay;
        pendingWithdrawals[request.vaultOwner] = PendingWithdrawal({
            owner: request.vaultOwner,
            recipient: request.recipient,
            amount: request.amount,
            nonce: request.nonce,
            queuedAt: queuedAt,
            readyAt: readyAt,
            operationId: operationId,
            policyEngineAtQueue: engineAtQueue,
            exists: true
        });

        emit WithdrawalQueued(
            operationId,
            request.vaultOwner,
            request.recipient,
            request.amount,
            request.nonce,
            queuedAt,
            readyAt
        );
    }

    /**
     * @notice Finalizes the caller's queued withdrawal after its delay.
     * @dev In addition to the timelock, two optional gates may block finalization:
     *
     *      1. Treasury quorum — if the vault owner has configured a non-zero
     *         `treasuryQuorumThreshold`, the required number of guardian approvals
     *         (via {approveTreasuryWithdrawal}) must be recorded before this call.
     *
     *      2. Policy revalidation — the withdrawal must still be permitted under
     *         CURRENT policy state, checked read-only via {IPolicyEngine.revalidate}
     *         (never the stateful {IPolicyEngine.check}, whose admission accounting
     *         already settled at queue time). Two engines are consulted, each only
     *         if non-zero, and once if they are the same address:
     *         - the QUEUE-TIME engine ({PendingWithdrawal.policyEngineAtQueue}) — a
     *           sticky floor, so replacing or disabling the engine after queueing
     *           cannot erase the restrictions this withdrawal was admitted under;
     *         - the CURRENT engine — so newly imposed restrictions also apply.
     *         Same-address internal mutation (e.g. a recipient sanctioned after
     *         queueing) is observed because revalidation always reads live state;
     *         address identity is never used as a proxy for policy freshness.
     *         Fail-closed: an engine that denies, reverts, mutates state under
     *         STATICCALL, or no longer answers blocks finalization; the owner can
     *         always {cancelPendingWithdrawal} (ungated) and re-queue. Note that
     *         cancellation does not release daily-spend allowance booked at
     *         admission, so re-queueing under a daily-limit policy may have to
     *         wait for the policy window to roll (≤ 24h).
     */
    function finalizeWithdrawal(address vaultOwner, bytes32 operationId) external nonReentrant whenNotPaused {
        PendingWithdrawal storage pending = pendingWithdrawals[vaultOwner];
        if (!pending.exists) revert NoPendingWithdrawal();
        if (pending.owner != msg.sender) revert NotPendingWithdrawalOwner(pending.owner, msg.sender);
        if (pending.operationId != operationId) {
            revert PendingWithdrawalMismatch(pending.operationId, operationId);
        }
        if (block.timestamp < pending.readyAt) {
            revert WithdrawalNotReady(pending.readyAt, block.timestamp);
        }

        // Gate 1: treasury quorum
        uint256 quorumRequired = treasuryQuorumThreshold[vaultOwner];
        if (quorumRequired > 0) {
            uint256 current = treasuryApprovalCount[operationId];
            if (current < quorumRequired) revert TreasuryQuorumNotMet(quorumRequired, current);
        }

        // Gate 2: read-only policy revalidation — always runs, no drift gate.
        // vaultBalance keeps the same meaning as at admission ("balance before this
        // withdrawal's deduction"): queueing reserved the amount, so reconstruct it.
        {
            uint256 balanceBeforeThisWithdrawal = vaults[vaultOwner].balance + pending.amount;
            address queueEngine = pending.policyEngineAtQueue;
            address currentEngine = address(policyEngine);
            // Rebuilt from the SAME trusted sources as at admission — address(this), the
            // pending withdrawal's recorded owner, and this vault's fixed asset — so a
            // queued withdrawal can never settle under a different subject identity than
            // the one it was admitted under. Built once and shared by both revalidations.
            PolicySubject memory subject = _policySubject(vaultOwner);
            if (queueEngine != address(0)) {
                _revalidatePolicy(queueEngine, subject, pending.recipient, pending.amount, balanceBeforeThisWithdrawal);
            }
            if (currentEngine != address(0) && currentEngine != queueEngine) {
                _revalidatePolicy(
                    currentEngine,
                    subject,
                    pending.recipient,
                    pending.amount,
                    balanceBeforeThisWithdrawal
                );
            }
        }

        address recipient = pending.recipient;
        uint256 amount = pending.amount;
        _clearTreasuryApprovalsForOp(vaultOwner, operationId);
        delete pendingWithdrawals[vaultOwner];

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit WithdrawalFinalized(operationId, vaultOwner, recipient, amount);
    }

    /**
     * @dev Revalidates a pending withdrawal against one policy engine, reverting on
     *      any outcome other than an explicit allow. Because this function is view
     *      and calls through the {IPolicyEngine} type, the engine executes under
     *      STATICCALL — an implementation that attempts to mutate state reverts here
     *      instead of booking anything. Failure taxonomy, all fail-closed:
     *      - engine has no code (never deployed / destroyed) → PolicyEngineUnavailable;
     *      - engine reverts or does not implement {IPolicyEngine.revalidate} →
     *        PolicyEngineUnavailable (caught below);
     *      - engine returns malformed data → the ABI decode reverts this call directly;
     *      - engine answers (false, reason) → PolicyViolation(reason).
     *      The owner's escape from a persistently failing engine is
     *      {cancelPendingWithdrawal}, which is ungated by pause and policy.
     */
    function _revalidatePolicy(
        address engine,
        PolicySubject memory subject,
        address recipient,
        uint256 amount,
        uint256 vaultBalance
    ) internal view {
        if (engine.code.length == 0) revert PolicyEngineUnavailable(engine);
        try IPolicyEngine(engine).revalidate(subject, recipient, amount, vaultBalance) returns (
            bool ok,
            string memory why
        ) {
            if (!ok) revert PolicyViolation(why);
        } catch {
            revert PolicyEngineUnavailable(engine);
        }
    }

    /**
     * @dev Mints the canonical {PolicySubject} for a withdrawal evaluated by THIS vault.
     *      No field is attacker-chosen at the point of use, but the three fields earn
     *      that status in TWO different ways, and the distinction matters when
     *      reviewing this boundary:
     *
     *      - `consumer` and `asset` are trusted BY PROVENANCE. They are read from this
     *        contract's own execution context and never appear in the request at all,
     *        so there is no value a caller could have supplied for them.
     *      - `owner` is trusted BY AUTHENTICATION. It IS request-body data —
     *        `request.vaultOwner`, chosen by whoever assembled the calldata — and
     *        claiming otherwise would misdescribe the boundary. What makes it safe is
     *        that every path reaching this function has already recovered the EIP-712
     *        signature over the whole request and required it to match
     *        `vault.ecdsaSigner` / `vault.pqPublicKey` for the vault registered under
     *        that very address, and has confirmed the vault exists. A forged
     *        `vaultOwner` therefore fails signature verification before any policy call
     *        is made. The guarantee is only as strong as that check: any future caller
     *        of this helper MUST be downstream of the same verification.
     *
     *      Detail on each field:
     *
     *      - `consumer` is `address(this)`. A vault cannot misreport its own address,
     *        and because the value travels in calldata rather than being re-derived per
     *        hop, it survives {CompositePolicyEngine} intact — the composite's modules
     *        see THIS vault, not the composite.
     *      - `owner` is the request's `vaultOwner`, authenticated as above. Relay is
     *        permissionless — anyone may submit someone else's signed request — so
     *        `msg.sender` carries no identity here and is deliberately unused.
     *      - `asset` is `address(0)`: this vault custodies native ETH only, so `amount`
     *        is always wei. The constant is not a placeholder — address(0) IS the
     *        canonical native-asset identifier for {PolicySubject}, and it can never
     *        collide with an ERC-20 token address.
     */
    function _policySubject(address vaultOwner) internal view returns (PolicySubject memory) {
        return PolicySubject({consumer: address(this), owner: vaultOwner, asset: address(0)});
    }

    /**
     * @notice Cancels the caller's queued withdrawal and releases its reservation.
     * @dev Cancellation remains available while paused so reserved funds are not trapped.
     *      Any treasury guardian approvals accumulated for this operationId are cleared
     *      so they cannot be observed or reused elsewhere.
     */
    function cancelPendingWithdrawal(bytes32 operationId) external nonReentrant {
        PendingWithdrawal storage pending = pendingWithdrawals[msg.sender];
        if (!pending.exists) revert NoPendingWithdrawal();
        if (pending.owner != msg.sender) revert NotPendingWithdrawalOwner(pending.owner, msg.sender);
        if (pending.operationId != operationId) {
            revert PendingWithdrawalMismatch(pending.operationId, operationId);
        }

        uint256 refund = pending.amount;
        _clearTreasuryApprovalsForOp(msg.sender, operationId);
        delete pendingWithdrawals[msg.sender];
        vaults[msg.sender].balance += refund;

        emit WithdrawalCancelled(operationId, msg.sender, refund);
    }

    /**
     * @notice Executes a withdrawal authorized by an EIP-712 typed {Withdrawal}.
     * @dev May be submitted by anyone (e.g. a relayer); authorization is by the
     *      attached signatures, not by msg.sender. Uses checks-effects-interactions
     *      and is reentrancy-guarded.
     * @param request The signed withdrawal parameters.
     * @param ecdsaSignature ECDSA signature over the typed-data digest (when the
     *        mode requires it; otherwise ignored).
     * @param pqSignature PQ signature over the typed-data digest (when the mode
     *        requires it; otherwise ignored).
     */
    function withdraw(
        Withdrawal calldata request,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external nonReentrant whenNotPaused {
        VaultOwner storage vault = vaults[request.vaultOwner];

        // ---- Checks ----
        if (!vault.exists) revert VaultDoesNotExist();
        if (block.timestamp > request.deadline) revert DeadlineExpired(request.deadline, block.timestamp);
        if (request.amount == 0) revert ZeroAmount();
        if (request.recipient == address(0)) revert ZeroRecipient();
        if (request.nonce != vault.nonce) revert InvalidNonce(vault.nonce, request.nonce);

        VaultMode configuredMode = vault.mode;
        if (request.vaultMode != uint8(configuredMode)) {
            revert VaultModeMismatch(configuredMode, VaultMode(request.vaultMode));
        }
        if (vault.balance < request.amount) revert InsufficientBalance();
        if (largeTxThreshold > 0 && request.amount > largeTxThreshold) revert UseLargeWithdrawal();

        bytes32 digest = _hashTypedDataV4(_structHash(request));

        bool needEcdsa = configuredMode == VaultMode.EcdsaOnly || configuredMode == VaultMode.Hybrid;
        bool needPq = configuredMode == VaultMode.PqOnly || configuredMode == VaultMode.Hybrid;

        if (needEcdsa) {
            // recover() reverts on malformed signatures; an unexpected signer is
            // surfaced as InvalidEcdsaSignature.
            if (digest.recover(ecdsaSignature) != vault.ecdsaSigner) revert InvalidEcdsaSignature();
        }
        if (needPq) {
            if (!pqVerifier.verify(digest, vault.pqPublicKey, pqSignature)) revert InvalidPQSignature();
        }

        if (address(policyEngine) != address(0)) {
            (bool ok, string memory why) = policyEngine.check(
                _policySubject(request.vaultOwner),
                request.recipient,
                request.amount,
                vault.balance
            );
            if (!ok) revert PolicyViolation(why);
        }

        // ---- Effects ----
        unchecked {
            vault.nonce = request.nonce + 1;
        }
        vault.balance -= request.amount;

        // ---- Interactions ----
        (bool success, ) = request.recipient.call{value: request.amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawn(request.vaultOwner, request.recipient, request.amount, request.nonce, configuredMode);
    }

    // ---------------------------------------------------------------------
    // Admin (contract owner via Ownable2Step)
    // ---------------------------------------------------------------------

    /**
     * @notice Proposes a new PQ verifier at the trust boundary.
     * @dev Admin-only. A later proposal replaces the pending proposal and restarts
     *      the delay. The active verifier remains unchanged until
     *      {applyPQVerifierUpdate} succeeds. `newVerifier` must have code at
     *      proposal time; see {applyPQVerifierUpdate} for why that alone is not
     *      sufficient.
     */
    function proposePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (newVerifier.code.length == 0) revert NoCode(newVerifier);

        uint256 validAfter = block.timestamp + PQ_VERIFIER_UPDATE_DELAY;
        pendingPQVerifier = newVerifier;
        pendingPQVerifierValidAfter = validAfter;

        emit PQVerifierUpdateProposed(address(pqVerifier), newVerifier, validAfter);
    }

    /**
     * @notice Cancels the pending PQ verifier update.
     * @dev Admin-only. Reverts when there is no pending proposal.
     */
    function cancelPQVerifierUpdate() external onlyOwner {
        address cancelledVerifier = pendingPQVerifier;
        if (cancelledVerifier == address(0)) revert NoPendingPQVerifier();

        pendingPQVerifier = address(0);
        pendingPQVerifierValidAfter = 0;

        emit PQVerifierUpdateCancelled(cancelledVerifier);
    }

    /**
     * @notice Applies the pending PQ verifier after the governance delay.
     * @dev Admin-only. Changing the verifier changes who/what is trusted to
     *      validate PQ signatures for every vault. See
     *      docs/Security_Assumptions.md.
     *
     *      Re-checks that the pending verifier still has code, independent of the
     *      check already performed in {proposePQVerifier}: a governance delay
     *      separates proposal from execution, and a destination that was
     *      code-bearing at proposal time can become code-less before the delay
     *      elapses. This re-check runs before any state is mutated, so a rejected
     *      apply leaves the active verifier and the pending proposal untouched —
     *      the proposal remains recoverable via {cancelPQVerifierUpdate}.
     */
    function applyPQVerifierUpdate() external onlyOwner {
        address newVerifier = pendingPQVerifier;
        if (newVerifier == address(0)) revert NoPendingPQVerifier();

        uint256 validAfter = pendingPQVerifierValidAfter;
        if (block.timestamp < validAfter) {
            revert PQVerifierUpdateNotReady(validAfter, block.timestamp);
        }
        _requireNotExpired(validAfter);

        if (newVerifier.code.length == 0) revert NoCode(newVerifier);

        address oldVerifier = address(pqVerifier);
        pqVerifier = IPQCVerifier(newVerifier);

        pendingPQVerifier = address(0);
        pendingPQVerifierValidAfter = 0;

        emit PQVerifierUpdated(oldVerifier, newVerifier);
    }

    /**
     * @notice Proposes new large-transaction threshold and delay parameters.
     * @dev A zero threshold disables the feature. Enabled configurations require
     *      a non-zero delay.
     */
    function proposeLargeTxParams(uint256 newThreshold, uint256 newDelay) external onlyOwner {
        if (newThreshold > 0 && newDelay == 0) revert ZeroDelay();

        uint256 validAfter = block.timestamp + LARGE_TX_PARAMS_UPDATE_DELAY;
        pendingLargeTxThreshold = newThreshold;
        pendingLargeTxDelay = newDelay;
        pendingLargeTxValidAfter = validAfter;

        emit LargeTxParamsProposed(newThreshold, newDelay, validAfter);
    }

    /**
     * @notice Applies pending large-transaction parameters after the governance delay.
     */
    function applyLargeTxParams() external onlyOwner {
        uint256 validAfter = pendingLargeTxValidAfter;
        if (validAfter == 0) revert NoPendingLargeTxUpdate();
        if (block.timestamp < validAfter) {
            revert LargeTxUpdateNotReady(validAfter, block.timestamp);
        }
        _requireNotExpired(validAfter);

        uint256 newThreshold = pendingLargeTxThreshold;
        uint256 newDelay = pendingLargeTxDelay;
        largeTxThreshold = newThreshold;
        largeTxDelay = newDelay;
        pendingLargeTxThreshold = 0;
        pendingLargeTxDelay = 0;
        pendingLargeTxValidAfter = 0;

        emit LargeTxParamsApplied(newThreshold, newDelay);
    }

    /**
     * @notice Cancels a pending large-transaction parameter update.
     */
    function cancelLargeTxParams() external onlyOwner {
        if (pendingLargeTxValidAfter == 0) revert NoPendingLargeTxUpdate();

        uint256 cancelledThreshold = pendingLargeTxThreshold;
        uint256 cancelledDelay = pendingLargeTxDelay;
        pendingLargeTxThreshold = 0;
        pendingLargeTxDelay = 0;
        pendingLargeTxValidAfter = 0;

        emit LargeTxParamsCancelled(cancelledThreshold, cancelledDelay);
    }

    /**
     * @notice Proposes a new policy engine to apply after the governance delay.
     * @dev Admin-only. Pass address(0) to propose disabling the policy engine.
     *      A later proposal replaces the pending one and restarts the delay. A
     *      nonzero `newEngine` must have code at proposal time; see
     *      {applyPolicyEngine} for why that alone is not sufficient.
     */
    function proposePolicyEngine(address newEngine) external onlyOwner {
        _requireCodeBearingPolicyEngine(newEngine);
        uint256 validAfter = block.timestamp + POLICY_ENGINE_UPDATE_DELAY;
        pendingPolicyEngine = newEngine;
        pendingPolicyEngineValidAfter = validAfter;
        emit PolicyEngineUpdateProposed(newEngine, validAfter);
    }

    /**
     * @notice Applies the pending policy engine after the governance delay.
     * @dev Admin-only.
     *
     *      Re-checks that a nonzero pending engine still has code, independent of
     *      the check already performed in {proposePolicyEngine}: a governance
     *      delay separates proposal from execution, and a destination that was
     *      code-bearing at proposal time can become code-less before the delay
     *      elapses. This re-check runs before any state is mutated, so a rejected
     *      apply leaves the active engine and the pending proposal untouched — the
     *      proposal remains recoverable via {cancelPolicyEngine}. address(0)
     *      always passes (disabling the policy engine remains valid).
     */
    function applyPolicyEngine() external onlyOwner {
        if (pendingPolicyEngineValidAfter == 0) revert NoPendingPolicyEngine();
        if (block.timestamp < pendingPolicyEngineValidAfter) {
            revert PolicyEngineUpdateNotReady(pendingPolicyEngineValidAfter, block.timestamp);
        }
        _requireNotExpired(pendingPolicyEngineValidAfter);

        address newEngine = pendingPolicyEngine;
        _requireCodeBearingPolicyEngine(newEngine);

        address oldEngine = address(policyEngine);
        policyEngine = IPolicyEngine(newEngine);
        pendingPolicyEngine = address(0);
        pendingPolicyEngineValidAfter = 0;
        emit PolicyEngineUpdated(oldEngine, newEngine);
    }

    /// @dev address(0) is a valid, intentional policy-engine disable value and
    ///      always passes; any other address must be code-bearing at this instant.
    function _requireCodeBearingPolicyEngine(address engine) private view {
        if (engine != address(0) && engine.code.length == 0) revert PolicyEngineUnavailable(engine);
    }

    /// @dev Reverts once a matured proposal has outlived {GOVERNANCE_GRACE_PERIOD}.
    ///      Callers run this AFTER their own not-ready check and BEFORE mutating any
    ///      state, so a rejected apply leaves both the active value and the pending
    ///      proposal untouched — the proposal stays clearable via its cancel entrypoint,
    ///      and re-proposing pays a fresh full delay.
    function _requireNotExpired(uint256 validAfter) private view {
        uint256 expiresAt = validAfter + GOVERNANCE_GRACE_PERIOD;
        if (block.timestamp > expiresAt) revert ProposalExpired(validAfter, expiresAt, block.timestamp);
    }

    /**
     * @notice Cancels a pending policy engine update.
     * @dev Admin-only.
     */
    function cancelPolicyEngine() external onlyOwner {
        if (pendingPolicyEngineValidAfter == 0) revert NoPendingPolicyEngine();
        address cancelled = pendingPolicyEngine;
        pendingPolicyEngine = address(0);
        pendingPolicyEngineValidAfter = 0;
        emit PolicyEngineUpdateCancelled(cancelled);
    }

    // ---------------------------------------------------------------------
    // Treasury withdrawal quorum
    // ---------------------------------------------------------------------

    /**
     * @notice Sets the required guardian-approval count before a large withdrawal
     *         queued by this vault can be finalized.
     * @dev A threshold of 0 disables treasury quorum for this vault (default).
     *      The threshold must not exceed the current guardian count so that quorum
     *      is always achievable with the existing guardian set. This invariant is
     *      preserved on the other side too: {setGuardians} rejects a shrink that
     *      would leave an already-armed threshold above the new guardian count,
     *      rather than silently stranding it (see docs/Guardian_Authority_Design.md
     *      §9.1 L-D).
     *      Vault-owner-controlled: each vault owner manages their own treasury security.
     */
    function setTreasuryQuorumThreshold(uint256 threshold) external {
        if (!vaults[msg.sender].exists) revert VaultDoesNotExist();
        if (threshold > 0) {
            uint256 guardianCount = vaultGuardians[msg.sender].length;
            if (guardianCount == 0) revert InvalidGuardianSet();
            if (threshold > guardianCount) {
                revert TooManyGuardians(threshold, guardianCount);
            }
        }
        treasuryQuorumThreshold[msg.sender] = threshold;
        emit TreasuryQuorumThresholdSet(msg.sender, threshold);
    }

    /**
     * @notice Records a guardian's approval for a queued large withdrawal.
     * @dev The caller must be a current guardian of `vaultOwner`'s vault.
     *      Duplicate approvals are rejected. Approvals are scoped to `operationId`
     *      so they cannot carry over to a different queued withdrawal.
     *      If the guardian set changes (via {setGuardians}), all existing approvals
     *      for any pending withdrawal are cleared, and removed guardians lose their
     *      previously-recorded approvals.
     */
    function approveTreasuryWithdrawal(address vaultOwner, bytes32 operationId) external {
        PendingWithdrawal storage pending = pendingWithdrawals[vaultOwner];
        if (!pending.exists) revert NoPendingWithdrawal();
        if (pending.operationId != operationId) {
            revert PendingWithdrawalMismatch(pending.operationId, operationId);
        }

        // Caller must be a current guardian of vaultOwner.
        bool isGuardian = false;
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == msg.sender) {
                isGuardian = true;
                break;
            }
        }
        if (!isGuardian) revert NotAGuardian();
        if (treasuryApprovals[operationId][msg.sender]) revert TreasuryAlreadyApproved();

        treasuryApprovals[operationId][msg.sender] = true;
        uint256 newCount = treasuryApprovalCount[operationId] + 1;
        treasuryApprovalCount[operationId] = newCount;

        emit TreasuryWithdrawalApproved(operationId, msg.sender, newCount);
    }

    /**
     * @dev Clears treasury approval state for a specific operationId, iterating
     *      the current guardian set of `vaultOwner`. Must be called while the
     *      guardian set still reflects the approvers (i.e. before {setGuardians}
     *      replaces it).
     */
    function _clearTreasuryApprovalsForOp(address vaultOwner, bytes32 operationId) internal {
        if (treasuryApprovalCount[operationId] == 0) return;
        treasuryApprovalCount[operationId] = 0;
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            delete treasuryApprovals[operationId][guardians[i]];
        }
    }

    /// @notice Pauses vault creation, immediate/queued withdrawal, finalization, and recovery execution. Admin-only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the vault. Admin-only.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice Returns the full vault record for `owner`.
    function getVault(address owner) external view returns (VaultOwner memory) {
        return vaults[owner];
    }

    /// @notice Current withdrawal nonce for `owner`.
    function nonces(address owner) external view returns (uint256) {
        return vaults[owner].nonce;
    }

    /// @notice EIP-712 digest that must be signed for a given {Withdrawal}.
    function hashWithdrawal(Withdrawal calldata request) external view returns (bytes32) {
        return _hashTypedDataV4(_structHash(request));
    }

    function _structHash(Withdrawal calldata request) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    WITHDRAWAL_TYPEHASH,
                    request.vaultOwner,
                    request.recipient,
                    request.amount,
                    request.nonce,
                    request.deadline,
                    request.vaultMode
                )
            );
    }
}
