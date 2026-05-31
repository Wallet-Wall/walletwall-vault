# WalletWall Vault - Developer Documentation

## Overview
WalletWall Vault is a hybrid cryptographic asset vault. This Phase 1 MVP demonstrates how to combine traditional ECDSA signatures with simulated Post-Quantum Cryptography (PQC) signatures.

## Core Components

### Smart Contracts
- `SignatureVerifier.sol`: A utility contract that uses OpenZeppelin's ECDSA library to verify Ethereum signatures.
- `WalletWallVault.sol`: The main vault contract. It handles vault registration, ETH deposits, and multi-signature (ECDSA + PQC) withdrawals.

### Off-Chain PQC Layer (Mock)
- `pqc/pqc-signer.ts`: Simulates PQC keypair generation and signing.
- `pqc/pqc-verifier.ts`: Simulates PQC signature verification.

## Workflow

### 1. Vault Creation
A user registers a vault by providing a hash of their PQC public key. This establishes their identity in both classical and post-quantum realms.
```solidity
function createVault(bytes32 pqcPublicKeyHash) external
```

### 2. Deposits
Users can deposit ETH into their registered vault.
```solidity
function deposit() external payable
```

### 3. Hybrid Authorization (Withdrawal)
To withdraw funds, a user must provide:
- A valid ECDSA signature.
- A valid PQC signature (simulated for MVP).

The withdrawal process works as follows:
1. Generate a `withdrawalHash` from `(sender, amount, recipient)`.
2. Generate a `pqcSignature` which is `hash(pqcPublicKeyHash, withdrawalHash)`.
3. Generate an `ecdsaMessageHash` from `(withdrawalHash, pqcSignature)`.
4. Sign the `ecdsaMessageHash` using the Ethereum private key.

The contract verifies:
1. `pqcSignature == hash(storedPqcPublicKeyHash, calculatedWithdrawalHash)`
2. `recover(ecdsaMessageHash, ecdsaSignature) == owner`

## Why PQC is Off-Chain for MVP
Real PQC algorithms like CRYSTALS-Dilithium have large signature and public key sizes, making them expensive to verify directly on-chain in Solidity without optimized precompiles or specialized libraries. This MVP uses a hash-based simulation to demonstrate the architectural flow while keeping the implementation simple and gas-efficient for testing.

## Future Migration Path
- **Phase 2**: Integrate real PQC libraries (e.g., using Succinct or other ZK-proof systems to verify PQC signatures off-chain and submit a proof on-chain).
- **Phase 3**: Implement native Dilithium/SPHINCS+ verification if/or when EVM-optimized implementations become available.
- **Phase 4**: Add support for multi-signature vaults and guardian-based recovery.
