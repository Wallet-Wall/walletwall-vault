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

    /// @notice Post-quantum verifier at the vault's PQ trust boundary.
    /// @dev Admin-controlled (see {updatePQVerifier}); NOT immutable, NOT a proxy.
    IPQCVerifier public pqVerifier;

    mapping(address => VaultOwner) public vaults;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------
    event VaultCreated(address indexed owner, address ecdsaSigner, bytes pqPublicKey, VaultMode mode);
    event Deposited(address indexed owner, address indexed from, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce, VaultMode mode);
    event EcdsaSignerUpdated(address indexed owner, address oldSigner, address newSigner);
    event PQKeyUpdated(address indexed owner);
    event PQVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

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
    error InvalidEcdsaSignature();
    error InvalidPQSignature();
    error TransferFailed();

    /**
     * @param _pqVerifier Address of the {IPQCVerifier} implementation. On a
     *        prototype deployment this is typically {MockMLDSAVerifier}.
     */
    constructor(address _pqVerifier) Ownable(msg.sender) EIP712("WalletWallVault", "1") {
        if (_pqVerifier == address(0)) revert ZeroAddress();
        pqVerifier = IPQCVerifier(_pqVerifier);
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
     * @notice Updates the PQ verifier at the trust boundary.
     * @dev Admin-only. The verifier is admin-controlled and mutable (NOT an
     *      upgradeable proxy and NOT immutable). Changing it changes who/what is
     *      trusted to validate PQ signatures for ALL vaults — see
     *      docs/Security_Assumptions.md.
     */
    function updatePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(pqVerifier);
        pqVerifier = IPQCVerifier(newVerifier);
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
