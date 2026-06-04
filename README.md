# WalletWall Vault - Phase 1 MVP (ML-DSA Upgrade)

WalletWall Vault is a hybrid cryptographic asset vault that combines traditional Ethereum ECDSA signatures with NIST-approved lattice-based **ML-DSA** (Module-Lattice Digital Signature Algorithm) signatures to provide a secure post-quantum authorization layer.

## Architecture

WalletWall Vault requires two independent cryptographic proofs for any withdrawal:
1. **Classical Layer**: Standard Ethereum ECDSA signature.
2. **Post-Quantum Layer**: ML-DSA-65 (Dilithium3) signature verified on-chain.

### Components

- `contracts/WalletWallVault.sol`: The main vault contract supporting dual ECDSA and ML-DSA verification.
- `contracts/SignatureVerifier.sol`: Reusable classical verification logic for ECDSA.
- `contracts/IPQSignatureVerifier.sol`: Interface for NIST Post-Quantum Cryptography (PQC) signature verification.
- `contracts/MLDSAVerifier.sol`: ML-DSA-65 (Dilithium3) signature verifier contract.
- `pqc/ml-dsa.ts`: Off-chain ML-DSA signer implementation using `@noble/post-quantum`.

## Getting Started

### Prerequisites

- Node.js (v18+)
- npm

### Installation

To install dependencies (including `@noble/post-quantum`):
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

To deploy both the verifiers and the vault contract to a local node:
```bash
npx hardhat node
npm run deploy -- --network localhost
```

## How It Works

### 1. Vault Registration
Users register their vault by providing their ECDSA signer address, their ML-DSA public key (bytes), and a boolean indicating if both signatures are required:
```solidity
vault.createVault(ecdsaSigner, pqPublicKey, requireBoth);
```

### 2. Deposits
Anyone can deposit ETH into a vault:
```solidity
vault.deposit({ value: ethers.parseEther("1.0") });
```

### 3. Hybrid Withdrawals
Withdrawals require a message to be signed by the ML-DSA private key and (if configured) the ECDSA private key.
```typescript
const nonce = await vault.getVault(owner.address).then(v => v.nonce);
const messageHash = ethers.solidityPackedKeccak256(
  ["address", "uint256", "address", "uint256", "address"],
  [owner.address, withdrawAmount, recipient, nonce, vaultAddress]
);

const pqSignature = MLDSASigner.sign(messageHash, pqPrivateKey);
const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

await vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, pqSignature);
```

## Security Considerations

- **Stateless Lattice-Based Signatures**: Unlike stateful OTS schemes (like WOTS+), ML-DSA-65 is stateless, allowing safe key reuse across multiple transactions.
- **On-chain Verification Hook**: Dilithium3 verification is extremely gas-intensive. The contract currently implements an architectural hook verifying signature lengths and non-zero bytes. In production, this should be verified via a Zero-Knowledge proof (like Groth16/Halo2) or protocol precompiles.
- **Replay Protection**: Built-in nonce tracking prevents withdrawal signatures from being replayed.
- **MVP Status**: This is a Phase 1 Proof-of-Concept. Not for production use.
