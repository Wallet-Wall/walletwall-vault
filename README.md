# WalletWall Vault — hybrid (classical + post-quantum) authorization prototype

> ⚠️ **Prototype only. Not audited. Do not use real funds. The current PQ verifier is a
> mock/placeholder and performs no real cryptographic verification.**
> Local / testnet demo only. See [SECURITY.md](SECURITY.md),
> [docs/Security_Assumptions.md](docs/Security_Assumptions.md), and
> [docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

WalletWall Vault is a **Phase 1 research / hybrid-authorization prototype** that explores
combining a classical Ethereum **ECDSA** signature with a **post-quantum (PQ)** signature
to authorize vault withdrawals, and a migration path toward real post-quantum security.

It is intended to demonstrate **contract security and trust boundaries** — replay
protection, EIP-712 typed authorization, a swappable verifier interface, and honest
documentation — **not** to custody real assets.

## What this is / is not

| | |
| --- | --- |
| ✅ Hybrid authorization prototype (ECDSA + PQ) | ❌ Production custody |
| ✅ Post-quantum migration research | ❌ "Quantum-proof" / "fully quantum-secure" |
| ✅ Testnet / local demo | ❌ Real-fund protection |
| ✅ EIP-712 replay-protected withdrawals | ❌ Audited |
| ✅ Swappable `IPQCVerifier` trust boundary | ❌ Mainnet-ready |

**The PQ verifier shipped here (`MockMLDSAVerifier`) does NOT perform real ML-DSA
verification.** In `Hybrid` mode the effective security today is approximately that of
the ECDSA layer alone.

## Architecture

Withdrawals are authorized by an **EIP-712** typed `Withdrawal` message. Depending on the
vault's `VaultMode`, the vault requires:

- **`Hybrid` (intended default):** a valid ECDSA signature **and** a valid PQ signature.
- **`EcdsaOnly`:** classical signature only.
- **`PqOnly`:** PQ signature only (research/migration; relies entirely on the verifier).

```
EIP-712 Withdrawal(vaultOwner, recipient, amount, nonce, deadline, vaultMode)
        │
        ├── ECDSA signature  ──►  recover() == vault.ecdsaSigner
        └── PQ signature     ──►  IPQCVerifier.verify(digest, pqPublicKey, pqSignature)
                                          │
                                          └── (today) MockMLDSAVerifier  ⚠️ no real crypto
```

### Components

- [`contracts/WalletWallVault.sol`](contracts/WalletWallVault.sol) — vault: deposits,
  EIP-712 withdrawals, per-owner nonces, `VaultMode`, `ReentrancyGuard`, `Pausable`,
  `Ownable2Step`, custom errors.
- [`contracts/IPQCVerifier.sol`](contracts/IPQCVerifier.sol) — PQ verifier trust-boundary
  interface (`algorithmId()`, `verify()`).
- [`contracts/MockMLDSAVerifier.sol`](contracts/MockMLDSAVerifier.sol) — **mock**
  ML-DSA-65 verifier, **test/demo only**, no real verification.
- [`contracts/SignatureVerifier.sol`](contracts/SignatureVerifier.sol) — reusable ECDSA
  helper (legacy/standalone; the vault verifies ECDSA over the EIP-712 digest directly).
- [`contracts/mocks/`](contracts/mocks/) — test-only helpers (`AlwaysFalsePQCVerifier`,
  `ForceSend`).
- [`pqc/ml-dsa.ts`](pqc/ml-dsa.ts) — off-chain ML-DSA-65 signer using
  `@noble/post-quantum`.

## Getting started

### Prerequisites
- Node.js (v18+) and npm

### Install
```bash
npm install
```

### Compile
```bash
npm run compile
```

### Test
```bash
npm test
```

### Coverage
```bash
npm run coverage
```

### Local demo (Hardhat in-memory network)
Runs a full deposit → EIP-712 sign → hybrid withdrawal flow against a mock PQ verifier:
```bash
npm run demo
```

### Deploy (local / testnet ONLY)
```bash
npx hardhat node          # in one terminal
npm run deploy -- --network localhost
```

## How a withdrawal works (off-chain signing)

```typescript
import { MLDSASigner } from "./pqc/ml-dsa";

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 };

const domain = {
  name: "WalletWallVault",
  version: "1",
  chainId,
  verifyingContract: vaultAddress,
};

const types = {
  Withdrawal: [
    { name: "vaultOwner", type: "address" },
    { name: "recipient", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "vaultMode", type: "uint8" },
  ],
};

const request = {
  vaultOwner: owner.address,
  recipient,
  amount,
  nonce: await vault.nonces(owner.address),
  deadline: Math.floor(Date.now() / 1000) + 3600,
  vaultMode: VaultMode.Hybrid,
};

const ecdsaSignature = await owner.signTypedData(domain, types, request);
const digest = ethers.TypedDataEncoder.hash(domain, types, request);
const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, pqPrivateKey));

await vault.withdraw(request, ecdsaSignature, pqSignature);
```

## Security model (summary)

- **Replay protection:** strictly increasing per-owner `nonce` + signed `deadline`.
- **Tamper protection:** owner/recipient/amount/nonce/deadline/mode are all part of the
  EIP-712 message; changing any field invalidates the signature.
- **Domain separation:** binds signatures to contract address, chainId, and name/version.
- **Reentrancy:** `ReentrancyGuard` + checks-effects-interactions.
- **Admin:** `Ownable2Step` owner can update the verifier and pause the vault — a
  documented centralization/trust assumption.
- **Accounting:** ETH force-sent via `selfdestruct` is not credited and cannot be
  withdrawn; internal per-vault balances are unaffected.

Full details: [docs/Security_Assumptions.md](docs/Security_Assumptions.md).

## Post-quantum verifier roadmap

The mock is **Path 0**. Real verification may come from a trusted-attestation verifier, a
ZK-proof verifier, or a future chain-native PQ precompile. See
[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

## Cryptography naming (NIST)

- **ML-DSA / FIPS 204** — formerly **CRYSTALS-Dilithium** (this prototype targets
  ML-DSA-65: 1952-byte public key, 3309-byte signature).
- **SLH-DSA / FIPS 205** — formerly **SPHINCS+** (candidate for future PQ paths).

## License

MIT. Provided **as-is** for research and educational purposes. No warranty. Not audited.
**Do not use with real funds.**
