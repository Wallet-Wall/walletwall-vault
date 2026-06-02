// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SignatureVerifier.sol";
import "./IPQSignatureVerifier.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title WalletWallVault
 * @dev A hybrid cryptographic asset vault combining ECDSA and NIST-approved PQC verification.
 */
contract WalletWallVault is ReentrancyGuard, Ownable {
    SignatureVerifier public immutable ecdsaVerifier;
    IPQSignatureVerifier public pqVerifier;

    struct VaultOwner {
        address ecdsaSigner;
        bytes pqPublicKey;
        uint256 nonce;
        uint256 balance;
        bool requireBoth;
    }

    mapping(address => VaultOwner) public vaults;

    event VaultCreated(address indexed owner, address ecdsaSigner, bytes pqPublicKey, bool requireBoth);
    event Deposited(address indexed owner, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce);
    event PQVerifierUpdated(address indexed newVerifier);

    constructor(address _ecdsaVerifier, address _pqVerifier) Ownable(msg.sender) {
        ecdsaVerifier = SignatureVerifier(_ecdsaVerifier);
        pqVerifier = IPQSignatureVerifier(_pqVerifier);
    }

    /**
     * @dev Registers a new vault for the caller.
     * @param ecdsaSigner The address for ECDSA signatures.
     * @param pqPublicKey The NIST PQ public key.
     * @param requireBoth Whether to require both signatures.
     */
    function createVault(address ecdsaSigner, bytes calldata pqPublicKey, bool requireBoth) external {
        require(vaults[msg.sender].ecdsaSigner == address(0), "Vault already exists");
        require(pqPublicKey.length > 0, "PQC public key required");

        vaults[msg.sender] = VaultOwner({
            ecdsaSigner: ecdsaSigner,
            pqPublicKey: pqPublicKey,
            nonce: 0,
            balance: 0,
            requireBoth: requireBoth
        });

        emit VaultCreated(msg.sender, ecdsaSigner, pqPublicKey, requireBoth);
    }

    /**
     * @dev Allows users to deposit ETH into their vault.
     */
    function deposit() external payable {
        require(vaults[msg.sender].ecdsaSigner != address(0), "Vault does not exist");
        vaults[msg.sender].balance += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @dev Withdrawal request requiring NIST-approved PQ authorization.
     * @param amount Amount to withdraw.
     * @param recipient Recipient of the funds.
     * @param nonce Replay protection nonce.
     * @param ecdsaSignature ECDSA signature (optional based on config).
     * @param pqSignature NIST PQ signature.
     */
    function withdraw(
        uint256 amount,
        address recipient,
        uint256 nonce,
        bytes calldata ecdsaSignature,
        bytes calldata pqSignature
    ) external nonReentrant {
        VaultOwner storage vault = vaults[msg.sender];
        require(vault.ecdsaSigner != address(0), "Vault does not exist");
        require(vault.balance >= amount, "Insufficient vault balance");
        require(nonce == vault.nonce, "Invalid nonce");

        // The message hash that signatures must cover
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender,
            amount,
            recipient,
            nonce,
            address(this)
        ));

        // 1. Verify NIST PQ signature
        require(
            pqVerifier.verify(vault.pqPublicKey, messageHash, pqSignature),
            "Invalid PQC signature"
        );

        // 2. Verify ECDSA signature if required
        if (vault.requireBoth) {
            require(
                ecdsaVerifier.verifyECDSA(vault.ecdsaSigner, messageHash, ecdsaSignature),
                "Invalid ECDSA signature"
            );
        }

        // Increment nonce for replay protection
        vault.nonce++;

        // Update balance before transfer (CEI pattern)
        vault.balance -= amount;

        // Transfer funds
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, recipient, amount, nonce);
    }

    /**
     * @dev Allows updating the PQ verifier implementation for future-proofing.
     * Restricted to contract owner.
     */
    function updatePQVerifier(address _newVerifier) external onlyOwner {
        require(_newVerifier != address(0), "Invalid verifier address");
        pqVerifier = IPQSignatureVerifier(_newVerifier);
        emit PQVerifierUpdated(_newVerifier);
    }

    /**
     * @dev Returns the vault details for a given owner.
     */
    function getVault(address owner) external view returns (VaultOwner memory) {
        return vaults[owner];
    }
}
