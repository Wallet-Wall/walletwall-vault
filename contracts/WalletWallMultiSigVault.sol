// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title WalletWallMultiSigVault
 * @notice Multi-signature version of the WalletWall Vault, supporting m-of-n ECDSA
 *         and p-of-q PQ signatures.
 */
contract WalletWallMultiSigVault is ReentrancyGuard, Pausable, Ownable2Step, EIP712 {
    using ECDSA for bytes32;

    struct MultiSigVault {
        address[] ecdsaSigners;
        uint256 ecdsaThreshold;
        bytes[] pqPublicKeys;
        uint256 pqThreshold;
        uint256 nonce;
        uint256 balance;
        bool exists;
    }

    struct MultiSigWithdrawal {
        address vaultOwner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 public constant MULTISIG_WITHDRAWAL_TYPEHASH = keccak256(
        "MultiSigWithdrawal(address vaultOwner,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    IPQCVerifier public pqVerifier;
    mapping(address => MultiSigVault) public vaults;

    event VaultCreated(
        address indexed owner,
        address[] ecdsaSigners,
        uint256 ecdsaThreshold,
        bytes[] pqPublicKeys,
        uint256 pqThreshold
    );
    event Deposited(address indexed owner, address indexed from, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce);

    error ZeroAddress();
    error ZeroAmount();
    error ZeroRecipient();
    error VaultAlreadyExists();
    error VaultDoesNotExist();
    error InsufficientBalance();
    error InvalidNonce(uint256 expected, uint256 provided);
    error DeadlineExpired(uint256 deadline, uint256 nowTimestamp);
    error InvalidThreshold();
    error DuplicateSigner();
    error InvalidSignature();
    error InsufficientSignatures();
    error TransferFailed();

    constructor(address _pqVerifier) Ownable(msg.sender) EIP712("WalletWallMultiSigVault", "1") {
        if (_pqVerifier == address(0)) revert ZeroAddress();
        pqVerifier = IPQCVerifier(_pqVerifier);
    }

    function createVault(
        address[] calldata ecdsaSigners,
        uint256 ecdsaThreshold,
        bytes[] calldata pqPublicKeys,
        uint256 pqThreshold
    ) external whenNotPaused {
        if (vaults[msg.sender].exists) revert VaultAlreadyExists();
        if (ecdsaThreshold == 0 || ecdsaThreshold > ecdsaSigners.length) revert InvalidThreshold();
        if (pqThreshold == 0 || pqThreshold > pqPublicKeys.length) revert InvalidThreshold();

        // Check for duplicates in ECDSA signers
        for (uint256 i = 0; i < ecdsaSigners.length; i++) {
            if (ecdsaSigners[i] == address(0)) revert ZeroAddress();
            for (uint256 j = i + 1; j < ecdsaSigners.length; j++) {
                if (ecdsaSigners[i] == ecdsaSigners[j]) revert DuplicateSigner();
            }
        }

        // Check for duplicates in PQ public keys
        for (uint256 i = 0; i < pqPublicKeys.length; i++) {
            bytes32 hashI = keccak256(pqPublicKeys[i]);
            for (uint256 j = i + 1; j < pqPublicKeys.length; j++) {
                if (hashI == keccak256(pqPublicKeys[j])) revert DuplicateSigner();
            }
        }

        vaults[msg.sender] = MultiSigVault({
            ecdsaSigners: ecdsaSigners,
            ecdsaThreshold: ecdsaThreshold,
            pqPublicKeys: pqPublicKeys,
            pqThreshold: pqThreshold,
            nonce: 0,
            balance: 0,
            exists: true
        });

        emit VaultCreated(msg.sender, ecdsaSigners, ecdsaThreshold, pqPublicKeys, pqThreshold);
    }

    function deposit() external payable {
        _deposit(msg.sender);
    }

    function depositFor(address vaultOwner) external payable {
        _deposit(vaultOwner);
    }

    function _deposit(address vaultOwner) internal {
        if (msg.value == 0) revert ZeroAmount();
        MultiSigVault storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();
        vault.balance += msg.value;
        emit Deposited(vaultOwner, msg.sender, msg.value);
    }

    /**
     * @notice Executes a multi-sig withdrawal.
     * @param request The withdrawal parameters.
     * @param ecdsaSignatures Array of ECDSA signatures, must be sorted by signer address.
     * @param pqSignatures Array of PQ signatures.
     * @param pqKeyIndices Array of indices mapping each PQ signature to a public key in the vault.
     */
    function withdraw(
        MultiSigWithdrawal calldata request,
        bytes[] calldata ecdsaSignatures,
        bytes[] calldata pqSignatures,
        uint256[] calldata pqKeyIndices
    ) external nonReentrant whenNotPaused {
        {
            MultiSigVault storage v = vaults[request.vaultOwner];
            if (!v.exists) revert VaultDoesNotExist();
            if (block.timestamp > request.deadline) revert DeadlineExpired(request.deadline, block.timestamp);
            if (request.amount == 0) revert ZeroAmount();
            if (request.recipient == address(0)) revert ZeroRecipient();
            if (request.nonce != v.nonce) revert InvalidNonce(v.nonce, request.nonce);
            if (v.balance < request.amount) revert InsufficientBalance();

            if (ecdsaSignatures.length < v.ecdsaThreshold) revert InsufficientSignatures();
            if (pqSignatures.length < v.pqThreshold) revert InsufficientSignatures();
            if (pqSignatures.length != pqKeyIndices.length) revert InvalidSignature();
        }

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MULTISIG_WITHDRAWAL_TYPEHASH,
                    request.vaultOwner,
                    request.recipient,
                    request.amount,
                    request.nonce,
                    request.deadline
                )
            )
        );

        _verifySignatures(vaults[request.vaultOwner], digest, ecdsaSignatures, pqSignatures, pqKeyIndices);

        MultiSigVault storage vault = vaults[request.vaultOwner];
        unchecked {
            vault.nonce++;
        }
        vault.balance -= request.amount;

        (bool success, ) = request.recipient.call{value: request.amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawn(request.vaultOwner, request.recipient, request.amount, vault.nonce - 1);
    }

    function _verifySignatures(
        MultiSigVault storage vault,
        bytes32 digest,
        bytes[] calldata ecdsaSignatures,
        bytes[] calldata pqSignatures,
        uint256[] calldata pqKeyIndices
    ) internal view {
        // Verify ECDSA signatures
        address lastSigner = address(0);
        for (uint256 i = 0; i < ecdsaSignatures.length; i++) {
            address signer = ECDSA.recover(digest, ecdsaSignatures[i]);
            if (signer <= lastSigner) revert InvalidSignature();

            bool isAuthorized = false;
            for (uint256 j = 0; j < vault.ecdsaSigners.length; j++) {
                if (vault.ecdsaSigners[j] == signer) {
                    isAuthorized = true;
                    break;
                }
            }
            if (!isAuthorized) revert InvalidSignature();
            lastSigner = signer;
        }

        // Verify PQ signatures
        for (uint256 i = 0; i < pqSignatures.length; i++) {
            uint256 keyIndex = pqKeyIndices[i];
            if (keyIndex >= vault.pqPublicKeys.length) revert InvalidSignature();
            if (i > 0 && keyIndex <= pqKeyIndices[i - 1]) revert InvalidSignature();

            if (!pqVerifier.verify(digest, vault.pqPublicKeys[keyIndex], pqSignatures[i])) {
                revert InvalidSignature();
            }
        }
    }

    function getVault(address owner) external view returns (MultiSigVault memory) {
        return vaults[owner];
    }

    /// @notice Pauses createVault and withdraw. Admin-only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the vault. Admin-only.
    function unpause() external onlyOwner {
        _unpause();
    }
}
