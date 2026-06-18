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

    function setGuardians(address[] calldata guardians) external {
        if (!vaults[msg.sender].exists) revert VaultDoesNotExist();
        if (guardians.length == 0) revert InvalidGuardianSet();
        if (guardians.length > MAX_GUARDIANS) revert TooManyGuardians(guardians.length, MAX_GUARDIANS);

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

    function initiateRecovery(
        address vaultOwner,
        address newEcdsaSigner,
        bytes calldata newPQPublicKey
    ) external whenNotPaused {
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();

        address[] storage guardians = vaultGuardians[vaultOwner];
        if (guardians.length == 0) revert InvalidGuardianSet();

        RecoveryRequest storage existingRequest = recoveryRequests[vaultOwner];
        if (existingRequest.exists && block.timestamp < existingRequest.executeAfter) {
            revert RecoveryAlreadyExists();
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

        uint256 required = (vaultGuardians[vaultOwner].length / 2) + 1;
        if (request.supportCount < required) revert InsufficientSupports();

        VaultOwner storage vault = vaults[vaultOwner];
        address recoveredSigner = request.newEcdsaSigner;
        bytes memory recoveredPQPublicKey = request.newPQPublicKey;
        vault.ecdsaSigner = recoveredSigner;
        vault.pqPublicKey = recoveredPQPublicKey;
        unchecked {
            vault.nonce++;
        }

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

        if (address(policyEngine) != address(0)) {
            (bool ok, string memory why) = policyEngine.check(
                request.vaultOwner,
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
            policyEngineAtQueue: address(policyEngine),
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

        address currentEngine = address(policyEngine);
        if (currentEngine != address(0) && currentEngine != pending.policyEngineAtQueue) {
            (bool ok, string memory why) = policyEngine.check(
                vaultOwner,
                pending.recipient,
                pending.amount,
                vaults[vaultOwner].balance
            );
            if (!ok) revert PolicyViolation(why);
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
                request.vaultOwner,
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

    function proposePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();

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

    function applyPQVerifierUpdate() external onlyOwner {
        address newVerifier = pendingPQVerifier;
        if (newVerifier == address(0)) revert NoPendingPQVerifier();

        uint256 validAfter = pendingPQVerifierValidAfter;
        if (block.timestamp < validAfter) {
            revert PQVerifierUpdateNotReady(validAfter, block.timestamp);
        }

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

    function proposePolicyEngine(address newEngine) external onlyOwner {
        uint256 validAfter = block.timestamp + POLICY_ENGINE_UPDATE_DELAY;
        pendingPolicyEngine = newEngine;
        pendingPolicyEngineValidAfter = validAfter;
        emit PolicyEngineUpdateProposed(newEngine, validAfter);
    }

    function applyPolicyEngine() external onlyOwner {
        if (pendingPolicyEngineValidAfter == 0) revert NoPendingPolicyEngine();
        if (block.timestamp < pendingPolicyEngineValidAfter) {
            revert PolicyEngineUpdateNotReady(pendingPolicyEngineValidAfter, block.timestamp);
        }
        address oldEngine = address(policyEngine);
        address newEngine = pendingPolicyEngine;
        policyEngine = IPolicyEngine(newEngine);
        pendingPolicyEngine = address(0);
        pendingPolicyEngineValidAfter = 0;
        emit PolicyEngineUpdated(oldEngine, newEngine);
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
