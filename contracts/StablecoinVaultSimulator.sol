// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";
import "./IPolicyEngine.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title StablecoinVaultSimulator
 * @notice Testnet-only research prototype: mirrors WalletWallVault's hybrid
 *         classical (ECDSA) + post-quantum (PQ) withdrawal-authorization model
 *         over a single ERC-20 test token (mock USDC-style, no real value).
 *
 * @dev  =======================================================================
 *       RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY.
 *       DO NOT USE WITH REAL FUNDS OR REAL STABLECOINS.
 *       TESTNET — RESEARCH PROTOTYPE, NO REAL VALUE.
 *
 *       This contract is a **sibling** of WalletWallVault (ETH-denominated).
 *       It does NOT modify that contract; both coexist independently.
 *
 *       The deposited asset is a mock ERC-20 (e.g. MockUSDC) configured at
 *       construction. Real stablecoins, fee-on-transfer tokens, and rebasing
 *       tokens are explicitly unsupported; this simulator expects a vanilla
 *       ERC-20 whose balance is not externally manipulated.
 *
 *       The EIP-712 domain uses name "WalletWallStablecoinVault" to ensure
 *       a distinct domain separator from WalletWallVault ("WalletWallVault"),
 *       preventing cross-contract signature replay.
 *
 *       The PQ attestation gate is backed by AttestationPQCVerifier (trusted
 *       attestation path): an authorized attestor verifies ML-DSA-65 off-chain
 *       (FIPS 204-compatible) and signs an EIP-712 PQCAttestation; ML-DSA is
 *       NOT verified on-chain. See docs/Attestation_Verifier.md.
 *       =======================================================================
 *
 *       Deposits: caller calls ERC-20 approve(vault, amount) then deposit(amount).
 *       The vault pulls tokens with safeTransferFrom. Direct ERC-20 transfers
 *       to the vault address are NOT credited; only deposit() updates the record.
 *
 *       Withdrawals: same EIP-712 Withdrawal typed message, nonce/deadline replay
 *       protection, policy engine, and large-tx timelock as WalletWallVault —
 *       except the transfer out uses safeTransfer instead of ETH call.
 */
contract StablecoinVaultSimulator is ReentrancyGuard, Pausable, Ownable2Step, EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // -----------------------------------------------------------------------
    // Token
    // -----------------------------------------------------------------------

    /// @notice The single ERC-20 token this simulator accepts. Immutable after deployment.
    IERC20 public immutable token;

    // -----------------------------------------------------------------------
    // Vault mode
    // -----------------------------------------------------------------------

    /**
     * @notice Authorization policy for a vault.
     * @dev Hybrid is the intended default and requires BOTH a valid ECDSA signature
     *      and a valid PQ signature. EcdsaOnly / PqOnly exist for research and
     *      migration experiments — PqOnly is blocked while a mock verifier is wired in.
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
        uint256 balance; // token base units (6 decimals for mUSDC)
        VaultMode mode;
        bool exists;
    }

    /**
     * @notice EIP-712 typed withdrawal authorization.
     * @dev Identical struct shape to WalletWallVault so the app can reuse the
     *      prototype's typed-data construction; only the domain name changes.
     *      The signature becomes invalid if any field changes.
     */
    struct Withdrawal {
        address vaultOwner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
        uint8 vaultMode;
    }

    /// @dev EIP-712 type hash for {Withdrawal} — identical to WalletWallVault's.
    bytes32 public constant WITHDRAWAL_TYPEHASH = keccak256(
        "Withdrawal(address vaultOwner,address recipient,uint256 amount,uint256 nonce,uint256 deadline,uint8 vaultMode)"
    );

    /// @dev EIP-712 type hash for credential rotation.
    bytes32 public constant ROTATE_CREDENTIALS_TYPEHASH = keccak256(
        "RotateCredentials(address vaultOwner,address newEcdsaSigner,bytes newPQPublicKey,uint256 nonce,uint256 deadline)"
    );

    /// @dev Algorithm id reported by {MockMLDSAVerifier}. Used to block PqOnly while a mock is wired in.
    bytes32 public constant MOCK_ML_DSA_65_ALGORITHM_ID = keccak256("MOCK-ML-DSA-65");

    /// @notice Delay between proposing and applying a PQ verifier update.
    uint256 public constant PQ_VERIFIER_UPDATE_DELAY = 2 days;

    /// @notice Delay required before a recovery request can be executed.
    uint256 public constant RECOVERY_DELAY = 7 days;

    /// @notice Maximum number of guardians per vault.
    uint256 public constant MAX_GUARDIANS = 32;

    /// @notice Governance delay for changes to the policy engine.
    uint256 public constant POLICY_ENGINE_UPDATE_DELAY = 2 days;

    /// @notice Governance delay for changes to large-transaction parameters.
    uint256 public constant LARGE_TX_PARAMS_UPDATE_DELAY = 2 days;

    /// @notice How long a MATURED governance proposal stays applicable before expiring.
    /// @dev A propose/apply delay is only worth the reaction window it delivers at the
    ///      instant the change takes effect. With no expiry a matured proposal stays
    ///      exercisable forever, so an owner can PRE-ARM one at a quiet moment, let the
    ///      delay lapse unapplied, and bank an INSTANT swap indefinitely — costing zero
    ///      delay and giving zero fresh notice exactly when it matters. Bounding the
    ///      window restores bounded warning: any governance action executable right now
    ///      was announced by its proposal event within the last
    ///      DELAY + GOVERNANCE_GRACE_PERIOD. Mirrors WalletWallVault; the 2-day / 14-day
    ///      pairing matches Compound's Timelock GRACE_PERIOD.
    uint256 public constant GOVERNANCE_GRACE_PERIOD = 14 days;

    // -----------------------------------------------------------------------
    // Recovery structs
    // -----------------------------------------------------------------------

    struct RecoveryRequest {
        address newEcdsaSigner;
        bytes newPQPublicKey;
        uint256 executeAfter;
        uint256 supportCount;
        bool exists;
    }

    struct RotationAuth {
        bytes currentEcdsaSignature;
        bytes currentPqSignature;
        bytes newEcdsaSignature;
        bytes newPqSignature;
    }

    struct PendingWithdrawal {
        address owner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 queuedAt;
        uint256 readyAt;
        bytes32 operationId;
        /// @dev Engine that ADMITTED this withdrawal at queue time. Finalization
        ///      revalidates its CURRENT state as a sticky floor (plus the currently
        ///      active engine when different) via the read-only
        ///      {IPolicyEngine.revalidate} — see WalletWallVault for the full model.
        address policyEngineAtQueue;
        bool exists;
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// @notice Post-quantum verifier at the vault's PQ trust boundary.
    IPQCVerifier public pqVerifier;

    address public pendingPQVerifier;
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
    mapping(address => address[]) public vaultGuardians;
    mapping(address => RecoveryRequest) public recoveryRequests;
    mapping(address => mapping(address => bool)) public recoverySupports;
    mapping(address => PendingWithdrawal) public pendingWithdrawals;

    uint256 public largeTxThreshold;
    uint256 public largeTxDelay;

    uint256 public pendingLargeTxThreshold;
    uint256 public pendingLargeTxDelay;
    uint256 public pendingLargeTxValidAfter;

    IPolicyEngine public policyEngine;
    address public pendingPolicyEngine;
    uint256 public pendingPolicyEngineValidAfter;

    mapping(address => uint256) public treasuryQuorumThreshold;
    mapping(bytes32 => uint256) public treasuryApprovalCount;
    mapping(bytes32 => mapping(address => bool)) public treasuryApprovals;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------
    event VaultCreated(address indexed owner, address ecdsaSigner, bytes pqPublicKey, VaultMode mode);
    event Deposited(address indexed owner, address indexed from, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce, VaultMode mode);
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

    // -----------------------------------------------------------------------
    // Custom errors
    // -----------------------------------------------------------------------
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
     * @param _token     Address of the ERC-20 test token (e.g. MockUSDC).
     *                   Must be a vanilla ERC-20 — fee-on-transfer and rebasing
     *                   tokens are explicitly unsupported.
     * @param _pqVerifier Address of the {IPQCVerifier} implementation.
     */
    constructor(address _token, address _pqVerifier) Ownable(msg.sender) EIP712("WalletWallStablecoinVault", "1") {
        if (_token == address(0)) revert ZeroAddress();
        if (_pqVerifier == address(0)) revert ZeroAddress();
        token = IERC20(_token);
        pqVerifier = IPQCVerifier(_pqVerifier);
    }

    // -----------------------------------------------------------------------
    // Recovery mechanism
    // -----------------------------------------------------------------------

    /// @dev If an armed {treasuryQuorumThreshold} for this vault would exceed the
    ///      NEW guardian count, the shrink is rejected outright (see
    ///      {setTreasuryQuorumThreshold}) rather than silently stranding the
    ///      threshold — lower the threshold first.
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

        if (recoveryRequests[msg.sender].exists) {
            delete recoveryRequests[msg.sender];
            emit RecoveryCancelled(msg.sender);
        }

        address[] storage existing = vaultGuardians[msg.sender];
        for (uint256 i = 0; i < existing.length; i++) {
            recoverySupports[msg.sender][existing[i]] = false;
        }

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
        // only execution or owner cancellation may clear it.
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

        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[vaultOwner][guardians[i]] = false;
        }

        emit RecoveryInitiated(vaultOwner, newEcdsaSigner, executeAfter);
    }

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

    function cancelRecovery() external {
        if (!recoveryRequests[msg.sender].exists) revert RecoveryDoesNotExist();
        delete recoveryRequests[msg.sender];

        address[] storage guardians = vaultGuardians[msg.sender];
        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[msg.sender][guardians[i]] = false;
        }

        emit RecoveryCancelled(msg.sender);
    }

    // -----------------------------------------------------------------------
    // Vault lifecycle
    // -----------------------------------------------------------------------

    function createVault(address ecdsaSigner, bytes calldata pqPublicKey, VaultMode mode) external whenNotPaused {
        if (vaults[msg.sender].exists) revert VaultAlreadyExists();

        if (mode == VaultMode.PqOnly && pqVerifier.algorithmId() == MOCK_ML_DSA_65_ALGORITHM_ID) {
            revert PqOnlyDisabledForMockVerifier();
        }

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
            balance: 0,
            mode: mode,
            exists: true
        });

        emit VaultCreated(msg.sender, ecdsaSigner, pqPublicKey, mode);
    }

    /**
     * @notice Tombstone: reverts unconditionally. Use {rotateCredentials}.
     */
    function updateEcdsaSigner(address) external pure {
        revert UseRotateCredentials();
    }

    /**
     * @notice Tombstone: reverts unconditionally. Use {rotateCredentials}.
     */
    function updatePQPublicKey(bytes calldata) external pure {
        revert UseRotateCredentials();
    }

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

        _authorizeRotation(vault, vaultOwner, newEcdsaSigner, newPQPublicKey, deadline, auth);

        vault.ecdsaSigner = newEcdsaSigner;
        vault.pqPublicKey = newPQPublicKey;
        unchecked {
            vault.nonce++;
        }
        // See {policyControlEpoch}: rotation is the other event that must invalidate
        // any policy-control action the OLD credentials signed or proposed. CHECKED —
        // see {policyControlEpoch}'s own doc.
        policyControlEpoch[vaultOwner]++;

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

        if (needEcdsa) {
            if (digest.recover(auth.currentEcdsaSignature) != vault.ecdsaSigner) revert InvalidRotationSignature();
        }
        if (needPq) {
            if (!pqVerifier.verify(digest, vault.pqPublicKey, auth.currentPqSignature)) revert InvalidPQSignature();
        }

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

    // -----------------------------------------------------------------------
    // Deposits
    // -----------------------------------------------------------------------

    /**
     * @notice Deposits `amount` tokens into the caller's own vault.
     * @dev The caller must have approved this contract for at least `amount` tokens
     *      before calling. Direct ERC-20 transfers to this contract are NOT credited.
     */
    function deposit(uint256 amount) external whenNotPaused nonReentrant {
        _deposit(msg.sender, amount);
    }

    /**
     * @notice Deposits `amount` tokens into the vault owned by `vaultOwner`.
     * @dev Lets a third party (or relayer) fund an existing vault. Tokens are
     *      pulled from msg.sender, not from vaultOwner.
     */
    function depositFor(address vaultOwner, uint256 amount) external whenNotPaused nonReentrant {
        _deposit(vaultOwner, amount);
    }

    function _deposit(address vaultOwner, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();

        // Checks-effects-interactions: update balance before the external call.
        vault.balance += amount;

        // safeTransferFrom reverts on failure; no return-value check needed.
        token.safeTransferFrom(msg.sender, address(this), amount);

        emit Deposited(vaultOwner, msg.sender, amount);
    }

    // -----------------------------------------------------------------------
    // Withdrawals
    // -----------------------------------------------------------------------

    /**
     * @notice Queues an above-threshold withdrawal for delayed execution.
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
        // engine that admitted this withdrawal (mirrors WalletWallVault).
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

        uint256 quorumRequired = treasuryQuorumThreshold[vaultOwner];
        if (quorumRequired > 0) {
            uint256 current = treasuryApprovalCount[operationId];
            if (current < quorumRequired) revert TreasuryQuorumNotMet(quorumRequired, current);
        }

        // Read-only policy revalidation — always runs, no drift gate. Mirrors
        // WalletWallVault.finalizeWithdrawal exactly: queue-time engine is a sticky
        // floor, current engine adds newly imposed restrictions, each consulted once.
        // vaultBalance keeps its admission meaning ("balance before this withdrawal's
        // deduction"), reconstructed because queueing reserved the amount.
        {
            uint256 balanceBeforeThisWithdrawal = vaults[vaultOwner].balance + pending.amount;
            address queueEngine = pending.policyEngineAtQueue;
            address currentEngine = address(policyEngine);
            // Rebuilt from the SAME trusted sources as at admission — address(this), the
            // pending withdrawal's recorded owner, and this simulator's immutable token —
            // so a queued withdrawal can never settle under a different subject identity
            // than the one it was admitted under. Built once, shared by both revalidations.
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

        // Interactions last (checks-effects-interactions + nonReentrant).
        token.safeTransfer(recipient, amount);

        emit WithdrawalFinalized(operationId, vaultOwner, recipient, amount);
    }

    /**
     * @dev Revalidates a pending withdrawal against one policy engine, reverting on
     *      any outcome other than an explicit allow. Identical to
     *      WalletWallVault._revalidatePolicy — view, so the engine executes under
     *      STATICCALL and cannot mutate state; no-code, reverting, non-conforming,
     *      or denying engines all fail closed ({cancelPendingWithdrawal} remains the
     *      ungated escape).
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
     * @dev Mints the canonical {PolicySubject} for a withdrawal evaluated by THIS
     *      simulator. Mirrors WalletWallVault._policySubject exactly except for the
     *      asset dimension, including the trust argument: `consumer` and `asset` are
     *      trusted BY PROVENANCE (read from this contract's own state, absent from the
     *      request entirely), while `owner` is trusted BY AUTHENTICATION — it IS
     *      request-body data, made safe by the EIP-712 signature check that every path
     *      to this function has already passed, not by any claim that it came from
     *      somewhere else.
     *
     *      - `consumer` is `address(this)`, so modules behind a shared
     *        {CompositePolicyEngine} see THIS simulator rather than the composite.
     *      - `owner` is the request's `vaultOwner`, reached only AFTER the EIP-712
     *        signature over the request has been verified against
     *        `vault.ecdsaSigner` / `vault.pqPublicKey` for the vault registered under
     *        that address. Relay is permissionless — anyone may submit someone else's
     *        signed request — so `msg.sender` carries no identity here and is
     *        deliberately unused.
     *      - `asset` is `address(token)` — the single ERC-20 fixed at construction and
     *        `immutable` thereafter, so `amount` is always that token's base units
     *        (6 decimals for mUSDC). It can never be address(0): the constructor
     *        rejects a zero token, so this simulator's subjects are structurally
     *        incapable of colliding with a native-ETH subject.
     */
    function _policySubject(address vaultOwner) internal view returns (PolicySubject memory) {
        return PolicySubject({consumer: address(this), owner: vaultOwner, asset: address(token)});
    }

    /**
     * @notice Cancels the caller's queued withdrawal and releases its reservation.
     * @dev Available while paused so reserved tokens are not trapped.
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
     * @dev May be submitted by anyone (e.g. a relayer); authorization is by
     *      the attached signatures, not by msg.sender.
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
        token.safeTransfer(request.recipient, request.amount);

        emit Withdrawn(request.vaultOwner, request.recipient, request.amount, request.nonce, configuredMode);
    }

    // -----------------------------------------------------------------------
    // Admin — PQ verifier governance
    // -----------------------------------------------------------------------

    /// @dev Admin-only. A later proposal replaces the pending proposal and restarts
    ///      the delay. `newVerifier` must have code at proposal time; see
    ///      {applyPQVerifierUpdate} for why that alone is not sufficient.
    function proposePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (newVerifier.code.length == 0) revert NoCode(newVerifier);

        uint256 validAfter = block.timestamp + PQ_VERIFIER_UPDATE_DELAY;
        pendingPQVerifier = newVerifier;
        pendingPQVerifierValidAfter = validAfter;

        emit PQVerifierUpdateProposed(address(pqVerifier), newVerifier, validAfter);
    }

    function cancelPQVerifierUpdate() external onlyOwner {
        address cancelledVerifier = pendingPQVerifier;
        if (cancelledVerifier == address(0)) revert NoPendingPQVerifier();

        pendingPQVerifier = address(0);
        pendingPQVerifierValidAfter = 0;

        emit PQVerifierUpdateCancelled(cancelledVerifier);
    }

    /// @dev Admin-only. Re-checks that the pending verifier still has code,
    ///      independent of the check already performed in {proposePQVerifier}: a
    ///      governance delay separates proposal from execution, and a destination
    ///      that was code-bearing at proposal time can become code-less before the
    ///      delay elapses. This re-check runs before any state is mutated, so a
    ///      rejected apply leaves the active verifier and the pending proposal
    ///      untouched — the proposal remains recoverable via
    ///      {cancelPQVerifierUpdate}.
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

    // -----------------------------------------------------------------------
    // Admin — large-tx timelock governance
    // -----------------------------------------------------------------------

    function proposeLargeTxParams(uint256 newThreshold, uint256 newDelay) external onlyOwner {
        if (newThreshold > 0 && newDelay == 0) revert ZeroDelay();

        uint256 validAfter = block.timestamp + LARGE_TX_PARAMS_UPDATE_DELAY;
        pendingLargeTxThreshold = newThreshold;
        pendingLargeTxDelay = newDelay;
        pendingLargeTxValidAfter = validAfter;

        emit LargeTxParamsProposed(newThreshold, newDelay, validAfter);
    }

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

    function cancelLargeTxParams() external onlyOwner {
        if (pendingLargeTxValidAfter == 0) revert NoPendingLargeTxUpdate();

        uint256 cancelledThreshold = pendingLargeTxThreshold;
        uint256 cancelledDelay = pendingLargeTxDelay;
        pendingLargeTxThreshold = 0;
        pendingLargeTxDelay = 0;
        pendingLargeTxValidAfter = 0;

        emit LargeTxParamsCancelled(cancelledThreshold, cancelledDelay);
    }

    // -----------------------------------------------------------------------
    // Admin — policy engine governance
    // -----------------------------------------------------------------------

    /// @dev Admin-only. Pass address(0) to propose disabling the policy engine. A
    ///      nonzero `newEngine` must have code at proposal time; see
    ///      {applyPolicyEngine} for why that alone is not sufficient.
    function proposePolicyEngine(address newEngine) external onlyOwner {
        _requireCodeBearingPolicyEngine(newEngine);
        uint256 validAfter = block.timestamp + POLICY_ENGINE_UPDATE_DELAY;
        pendingPolicyEngine = newEngine;
        pendingPolicyEngineValidAfter = validAfter;
        emit PolicyEngineUpdateProposed(newEngine, validAfter);
    }

    /// @dev Admin-only. Re-checks that a nonzero pending engine still has code,
    ///      independent of the check already performed in {proposePolicyEngine}: a
    ///      governance delay separates proposal from execution, and a destination
    ///      that was code-bearing at proposal time can become code-less before the
    ///      delay elapses. This re-check runs before any state is mutated, so a
    ///      rejected apply leaves the active engine and the pending proposal
    ///      untouched — the proposal remains recoverable via {cancelPolicyEngine}.
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
    ///      Runs AFTER the not-ready check and BEFORE any state mutation, so a rejected
    ///      apply leaves both the active value and the pending proposal untouched.
    function _requireNotExpired(uint256 validAfter) private view {
        uint256 expiresAt = validAfter + GOVERNANCE_GRACE_PERIOD;
        if (block.timestamp > expiresAt) revert ProposalExpired(validAfter, expiresAt, block.timestamp);
    }

    function cancelPolicyEngine() external onlyOwner {
        if (pendingPolicyEngineValidAfter == 0) revert NoPendingPolicyEngine();
        address cancelled = pendingPolicyEngine;
        pendingPolicyEngine = address(0);
        pendingPolicyEngineValidAfter = 0;
        emit PolicyEngineUpdateCancelled(cancelled);
    }

    // -----------------------------------------------------------------------
    // Treasury withdrawal quorum
    // -----------------------------------------------------------------------

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

    function approveTreasuryWithdrawal(address vaultOwner, bytes32 operationId) external {
        PendingWithdrawal storage pending = pendingWithdrawals[vaultOwner];
        if (!pending.exists) revert NoPendingWithdrawal();
        if (pending.operationId != operationId) {
            revert PendingWithdrawalMismatch(pending.operationId, operationId);
        }

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

    function _clearTreasuryApprovalsForOp(address vaultOwner, bytes32 operationId) internal {
        if (treasuryApprovalCount[operationId] == 0) return;
        treasuryApprovalCount[operationId] = 0;
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            delete treasuryApprovals[operationId][guardians[i]];
        }
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    function getVault(address owner) external view returns (VaultOwner memory) {
        return vaults[owner];
    }

    function nonces(address owner) external view returns (uint256) {
        return vaults[owner].nonce;
    }

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
