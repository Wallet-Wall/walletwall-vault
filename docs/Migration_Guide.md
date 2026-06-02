# Migration Guide: From WOTS+ to ML-DSA

This guide outlines the steps for users and developers to migrate from the deprecated WOTS+ vault to the new ML-DSA post-quantum vault.

## For Developers

### 1. Update Dependencies
Ensure you have the latest SDK which includes `@noble/post-quantum`.

### 2. Contract Changes
The `WalletWallVault` constructor now requires two verifier addresses:
```solidity
constructor(address _ecdsaVerifier, address _pqVerifier)
```

The `withdraw` function signature has changed to support reusable keys and nonces:
```solidity
function withdraw(
    uint256 amount,
    address recipient,
    uint256 nonce,
    bytes calldata ecdsaSignature,
    bytes calldata pqSignature
)
```

### 3. Key Management
WOTS+ keys (hash chains) are no longer used. Replace them with ML-DSA-65 keypairs.

## For Users

### 1. New Vault Creation
If you have an existing WOTS+ vault, you must create a new vault using the new ML-DSA public key.

```typescript
import { MLDSASigner } from "./pqc/ml-dsa";

// 1. Generate new PQ keys
const keys = MLDSASigner.generateKeyPair();

// 2. Create vault on-chain
await vault.createVault(
    userAddress,
    MLDSASigner.toHex(keys.publicKey),
    true // requireBoth (Hybrid Mode)
);
```

### 2. Signing Withdrawals
Use the new signing flow:

```typescript
const messageHash = ethers.solidityPackedKeccak256(
    ["address", "uint256", "address", "uint256", "address"],
    [ownerAddress, amount, recipient, nonce, vaultAddress]
);

const pqSignature = MLDSASigner.sign(messageHash, keys.privateKey);
const ecdsaSignature = await wallet.signMessage(ethers.getBytes(messageHash));

await vault.withdraw(amount, recipient, nonce, ecdsaSignature, pqSignature);
```

## Security Note
Unlike WOTS+, ML-DSA keys are **reusable**. You do not need to rotate your public key after every transaction. However, the system now uses a **nonce** for each vault to prevent replay attacks. Ensure you track your vault's nonce (visible via `getVault(address)`).
