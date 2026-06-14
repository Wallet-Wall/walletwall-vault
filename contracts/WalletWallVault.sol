// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";
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
    uint256 public constant MAX_GUARDIANS = 20;

    struct RecoveryRequest {
        address newEcdsaSigner;
        bytes newPQPublicKey;
        uint256 executeAfter;
        uint256 supportCount;
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

    /// @notice Guardians for each vault.
    mapping(address => address[]) public vaultGuardians;

    /// @notice Pending recovery request for each vault.
    mapping(address => RecoveryRequest) public recoveryRequests;

    /// @notice Tracks if a guardian has supported a specific recovery request.
    /// @dev vaultOwner => guardian => supported
    mapping(address => mapping(address => bool)) public recoverySupports;

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
    error TransferFailed();
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
    error RecoveryAlreadyActive();

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
     *      supporters and permanently brick recovery.
     */
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

        // Cancel pending recovery and clear existing supports to maintain consistency
        if (recoveryRequests[msg.sender].exists) {
            delete recoveryRequests[msg.sender];
            emit RecoveryCancelled(msg.sender);
        }

        address[] storage existing = vaultGuardians[msg.sender];
        for (uint256 i = 0; i < existing.length; i++) {
            recoverySupports[msg.sender][existing[i]] = false;
        }

        vaultGuardians[msg.sender] = guardians;
        emit GuardiansSet(msg.sender, guardians);
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
        if (!vaults[vaultOwner].exists) revert VaultDoesNotExist();

        address[] storage guardians = vaultGuardians[vaultOwner];
        if (guardians.length == 0) revert InvalidGuardianSet();

        // A live request (not yet past its execution window) may not be overwritten.
        // This stops a single guardian from repeatedly re-initiating to wipe the
        // supports other guardians have already cast. The owner can always clear a
        // request with cancelRecovery, and a stuck request becomes replaceable once
        // its executeAfter timestamp has elapsed.
        RecoveryRequest storage existingRequest = recoveryRequests[vaultOwner];
        if (existingRequest.exists && block.timestamp < existingRequest.executeAfter) {
            revert RecoveryAlreadyActive();
        }

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

        uint256 required = (vaultGuardians[vaultOwner].length / 2) + 1;
        if (request.supportCount < required) revert InsufficientSupports();

        VaultOwner storage vault = vaults[vaultOwner];
        vault.ecdsaSigner = request.newEcdsaSigner;
        vault.pqPublicKey = request.newPQPublicKey;

        delete recoveryRequests[vaultOwner];
        // Clean up supports
        address[] storage guardians = vaultGuardians[vaultOwner];
        for (uint256 i = 0; i < guardians.length; i++) {
            recoverySupports[vaultOwner][guardians[i]] = false;
        }

        emit RecoveryExecuted(vaultOwner, request.newEcdsaSigner);
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
    function createVault(address ecdsaSigner, bytes calldata pqPublicKey, VaultMode mode) external whenNotPaused {
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
            balance: 0,
            mode: mode,
            exists: true
        });

        emit VaultCreated(msg.sender, ecdsaSigner, pqPublicKey, mode);
    }

    /**
     * @notice Rotates the ECDSA signer for the caller's vault.
     * @dev Only the vault owner may rotate their own signer.
     */
    function updateEcdsaSigner(address newSigner) external {
        VaultOwner storage vault = vaults[msg.sender];
        if (!vault.exists) revert VaultDoesNotExist();
        if ((vault.mode == VaultMode.EcdsaOnly || vault.mode == VaultMode.Hybrid) && newSigner == address(0))
            revert ZeroAddress();

        address oldSigner = vault.ecdsaSigner;
        vault.ecdsaSigner = newSigner;
        emit EcdsaSignerUpdated(msg.sender, oldSigner, newSigner);
    }

    /**
     * @notice Rotates the PQ public key for the caller's vault.
     * @dev Only the vault owner may rotate their own key.
     */
    function updatePQPublicKey(bytes calldata newPQPublicKey) external {
        VaultOwner storage vault = vaults[msg.sender];
        if (!vault.exists) revert VaultDoesNotExist();
        if ((vault.mode == VaultMode.PqOnly || vault.mode == VaultMode.Hybrid) && newPQPublicKey.length == 0)
            revert EmptyPQPublicKey();

        vault.pqPublicKey = newPQPublicKey;
        emit PQKeyUpdated(msg.sender);
    }

    /**
     * @notice Securely rotates vault credentials using current signatures.
     * @dev Requires signatures from both current keys (if applicable to the mode).
     */
    function rotateCredentials(
        address vaultOwner,
        address newEcdsaSigner,
        bytes calldata newPQPublicKey,
        uint256 deadline,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external nonReentrant whenNotPaused {
        VaultOwner storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

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

        if (vault.mode == VaultMode.EcdsaOnly || vault.mode == VaultMode.Hybrid) {
            if (digest.recover(ecdsaSignature) != vault.ecdsaSigner) revert InvalidRotationSignature();
        }
        if (vault.mode == VaultMode.PqOnly || vault.mode == VaultMode.Hybrid) {
            if (!pqVerifier.verify(digest, vault.pqPublicKey, pqSignature)) revert InvalidPQSignature();
        }

        vault.ecdsaSigner = newEcdsaSigner;
        vault.pqPublicKey = newPQPublicKey;
        unchecked {
            vault.nonce++;
        }

        emit CredentialsRotated(vaultOwner, newEcdsaSigner);
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
     *      {applyPQVerifierUpdate} succeeds.
     */
    function proposePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();

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
     */
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

    /// @notice Pauses createVault and withdraw. Admin-only.
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
