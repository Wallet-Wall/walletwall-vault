# WalletWall Vault — hybrid (classical + post-quantum) authorization prototype

> ⚠️ **Prototype only. Not audited. Do not use real funds. The repository includes
> a test/demo-only mock verifier and a trusted-attestation verifier that does not
> verify ML-DSA on-chain.**
> Local / testnet demo only. See [SECURITY.md](SECURITY.md),
> [docs/Security_Assumptions.md](docs/Security_Assumptions.md), and
> [docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

WalletWall Vault is a **Phase 1 research / hybrid-authorization prototype** that explores
combining a classical Ethereum **ECDSA** signature with a **post-quantum (PQ)** signature
to authorize vault withdrawals, and a migration path toward stronger future verifier
designs.

It is intended to demonstrate **contract security and trust boundaries** — replay
protection, EIP-712 typed authorization, a swappable verifier interface, and honest
documentation — **not** to custody real assets.

## What this is / is not

|                                                |                                        |
| ---------------------------------------------- | -------------------------------------- |
| ✅ Hybrid authorization prototype (ECDSA + PQ) | ❌ Production custody                  |
| ✅ Post-quantum migration research             | ❌ Production-grade quantum resistance |
| ✅ Testnet / local demo                        | ❌ Real-fund protection                |
| ✅ EIP-712 replay-protected withdrawals        | ❌ Audited                             |
| ✅ Swappable `IPQCVerifier` trust boundary     | ❌ Reviewed deployment system          |

`MockMLDSAVerifier` performs no real ML-DSA verification and remains test/demo-only.
`AttestationPQCVerifier` is non-mock but trusted: it verifies an authorized attestor's
EIP-712 signature, not ML-DSA on-chain. Its security depends on the attestor correctly
verifying ML-DSA off-chain with a real FIPS 204-compatible implementation. This
repository is still not production custody.

## Architecture

Withdrawals are authorized by an **EIP-712** typed `Withdrawal` message. Depending on the
vault's `VaultMode`, the vault requires:

- **`Hybrid` (intended default):** a valid ECDSA signature **and** a valid PQ signature.
- **`EcdsaOnly`:** classical signature only.
- **`PqOnly`:** PQ signature only (research/migration; relies entirely on the verifier).
  **Disabled while the configured verifier is the mock** (`MockMLDSAVerifier`):
  `createVault` reverts with `PqOnlyDisabledForMockVerifier`, since the mock provides no
  real cryptographic security and PqOnly would be its sole authorization layer.

```
EIP-712 Withdrawal(vaultOwner, recipient, amount, nonce, deadline, vaultMode)
        │
        ├── ECDSA signature  ──►  recover() == vault.ecdsaSigner
        └── PQ signature     ──►  IPQCVerifier.verify(digest, pqPublicKey, pqSignature)
                                          │
                                          ├── MockMLDSAVerifier: structural checks only
                                          └── AttestationPQCVerifier: trusted EIP-712 attestor
```

### Components

- [`contracts/WalletWallVault.sol`](contracts/WalletWallVault.sol) — vault: deposits,
  EIP-712 withdrawals, per-owner nonces, `VaultMode`, `ReentrancyGuard`, `Pausable`,
  `Ownable2Step`, timelocked verifier governance, custom errors.
- [`contracts/IPQCVerifier.sol`](contracts/IPQCVerifier.sol) — PQ verifier trust-boundary
  interface (`algorithmId()`, `verify()`).
- [`contracts/MockMLDSAVerifier.sol`](contracts/MockMLDSAVerifier.sol) — **mock**
  ML-DSA-65 verifier, **test/demo only**, no real verification.
- [`contracts/verifiers/AttestationPQCVerifier.sol`](contracts/verifiers/AttestationPQCVerifier.sol)
  — non-mock trusted-attestation path; verifies an authorized EIP-712 attestor
  signature and does not execute ML-DSA on-chain.
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

### Build a sample attestation payload

Generates mock ML-DSA-shaped bytes unless environment overrides are supplied, signs the
attestation, and prints the verifier payload:

```bash
npm run sign:attestation
```

The helper does not verify ML-DSA. See
[docs/Attestation_Verifier.md](docs/Attestation_Verifier.md) for the payload and trust
model.

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
- **Trusted-attestation verifier:** binds the withdrawal digest, public-key hash, PQ
  signature hash, algorithm identifier, verifier, chain ID, and deadline to an
  authorized EIP-712 attestor signature. The attestor remains a central trust boundary.
- **Reentrancy:** `ReentrancyGuard` + checks-effects-interactions.
- **Verifier governance:** the `Ownable2Step` owner proposes a verifier, waits the fixed
  two-day `PQ_VERIFIER_UPDATE_DELAY`, then applies it. The owner can cancel a pending
  proposal before application. The active verifier remains unchanged during the delay.
  Ownership can be assigned to a multisig such as Safe without adding multisig logic to
  this prototype.
- **Admin:** the owner can still choose the verifier and pause the vault. The delay
  improves visibility and reaction time but does not remove the central trust boundary.
- **Accounting:** ETH force-sent via `selfdestruct` is not credited and cannot be
  withdrawn; internal per-vault balances are unaffected.

Full details: [docs/Security_Assumptions.md](docs/Security_Assumptions.md).

## Post-quantum verifier roadmap

The mock is **Path 0**. The implemented trusted-attestation verifier is **Path 1** and
depends on correct off-chain ML-DSA verification by its authorized attestor. Future
stronger paths may use ZK proof verification or native chain support. See
[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

## Cryptography naming (NIST)

- **ML-DSA / FIPS 204** — formerly **CRYSTALS-Dilithium** (this prototype targets
  ML-DSA-65: 1952-byte public key, 3309-byte signature).
- **SLH-DSA / FIPS 205** — formerly **SPHINCS+** (candidate for future PQ paths).

## License

MIT. Provided **as-is** for research and educational purposes. No warranty. Not audited.
**Do not use with real funds.**
