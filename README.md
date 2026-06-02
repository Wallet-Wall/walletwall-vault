# WalletWall Vault - Phase 1 MVP

WalletWall Vault is a hybrid cryptographic asset vault that combines traditional Ethereum ECDSA signatures with Winternitz One-Time Signatures (WOTS+) to provide a post-quantum secure authorization layer.

## Architecture

WalletWall Vault requires two independent cryptographic proofs for any withdrawal:
1. **Classical Layer**: Standard Ethereum ECDSA signature.
2. **Post-Quantum Layer**: WOTS+ signature verified on-chain.

### Components

- `contracts/WalletWallVault.sol`: The main vault contract.
- `contracts/SignatureVerifier.sol`: Reusable verification logic for ECDSA and WOTS+.
- `pqc/pqc-signer.ts`: Off-chain WOTS+ signer implementation.
- `pqc/pqc-verifier.ts`: Off-chain WOTS+ verification and public key recovery.

## Getting Started

### Prerequisites

- Node.js (v18+)
- npm

### Installation

```bash
npm install
```

### Compile Contracts

```bash
npm run compile
```

### Run Tests

```bash
npm test
```

### Deployment

To deploy to a local node:

```bash
npx hardhat node
npm run deploy -- --network localhost
```

## How It Works

### 1. Vault Registration
Users register their vault by providing a hash of their WOTS+ public key.
```solidity
vault.createVault(pqcPublicKeyHash);
```

### 2. Deposits
Anyone can deposit ETH into a vault.
```solidity
vault.deposit({ value: ethers.parseEther("1.0") });
```

### 3. Hybrid Withdrawals
Withdrawals require a message to be signed by both the Ethereum private key and the WOTS+ private key.
```typescript
const messageHash = ethers.solidityPackedKeccak256(...);
const pqcSignature = WOTSSigner.sign(messageHash, pqcPrivateKey);
const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

await vault.withdraw(amount, recipient, ecdsaSignature, pqcSignature);
```

## Security Considerations

- **One-Time Signatures**: WOTS+ is a one-time signature scheme. After a withdrawal, the PQC public key hash should ideally be rotated (not implemented in Phase 1).
- **MVP Status**: This is a Phase 1 Proof-of-Concept. Not for production use.
