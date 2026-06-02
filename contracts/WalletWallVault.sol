// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SignatureVerifier.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title WalletWallVault
 * @dev A hybrid cryptographic asset vault combining ECDSA and WOTS+ (PQC) verification.
 */
contract WalletWallVault is ReentrancyGuard {
    SignatureVerifier public verifier;

    struct Vault {
        address owner;
        bytes32 pqcPublicKeyHash;
        uint256 balance;
    }

    mapping(address => Vault) public vaults;

    event VaultCreated(address indexed owner, bytes32 pqcPublicKeyHash);
    event Deposited(address indexed owner, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount);

    constructor(address _verifierAddress) {
        verifier = SignatureVerifier(_verifierAddress);
    }

    /**
     * @dev Registers a new vault for the caller.
     * @param pqcPublicKeyHash The hash of the user's WOTS+ public key.
     */
    function createVault(bytes32 pqcPublicKeyHash) external {
        require(vaults[msg.sender].owner == address(0), "Vault already exists");

        vaults[msg.sender] = Vault({
            owner: msg.sender,
            pqcPublicKeyHash: pqcPublicKeyHash,
            balance: 0
        });

        emit VaultCreated(msg.sender, pqcPublicKeyHash);
    }

    /**
     * @dev Allows users to deposit ETH into their vault.
     */
    function deposit() external payable {
        require(vaults[msg.sender].owner != address(0), "Vault does not exist");
        vaults[msg.sender].balance += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @dev Withdrawal request requiring both ECDSA and WOTS+ authorization.
     * @param amount Amount to withdraw.
     * @param recipient Recipient of the funds.
     * @param ecdsaSignature ECDSA signature of the withdrawal parameters.
     * @param pqcSignature WOTS+ signature for verification.
     */
    function withdraw(
        uint256 amount,
        address recipient,
        bytes calldata ecdsaSignature,
        bytes32[] calldata pqcSignature
    ) external nonReentrant {
        Vault storage vault = vaults[msg.sender];
        require(vault.owner != address(0), "Vault does not exist");
        require(vault.balance >= amount, "Insufficient balance");

        // The message hash that both signatures must cover
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount, recipient));

        // 1. Verify WOTS+ (PQC) signature
        require(
            verifier.verifyWOTS(messageHash, pqcSignature, vault.pqcPublicKeyHash),
            "Invalid PQC signature"
        );

        // 2. Verify ECDSA signature
        // The ECDSA signature covers the same messageHash
        require(
            verifier.verifyECDSA(vault.owner, messageHash, ecdsaSignature),
            "Invalid ECDSA signature"
        );

        // Update state and transfer funds
        vault.balance -= amount;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, recipient, amount);
    }

    /**
     * @dev Returns the vault details for a given owner.
     */
    function getVault(address owner) external view returns (Vault memory) {
        return vaults[owner];
    }
}
