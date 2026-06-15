# WalletWall Vault — hybrid (classical + post-quantum) authorization prototype

> ⚠️ **Prototype only. Not audited. Do not use real funds. The repository includes
> a test/demo-only mock verifier and a trusted-attestation verifier that does not
> verify ML-DSA on-chain.**
> Local / testnet demo only. See [SECURITY.md](SECURITY.md),
> [docs/Security_Assumptions.md](docs/Security_Assumptions.md), and
> [docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

WalletWall Vault is a **research / hybrid-authorization prototype** that explores
combining a classical Ethereum **ECDSA** signature with a **post-quantum (PQ)** signature
to authorize vault withdrawals, and a migration path toward stronger future verifier
designs. **Phase 3 security hardening is complete on `main`**; see
[docs/Phase_3_Status.md](docs/Phase_3_Status.md).

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
  `Ownable2Step`, delayed large withdrawals, guardian recovery and treasury quorum,
  timelocked verifier/policy/parameter governance, and custom errors.
- [`contracts/IPolicyEngine.sol`](contracts/IPolicyEngine.sol) and
  [`contracts/policies/`](contracts/policies/) — optional withdrawal-policy boundary,
  including `CompositePolicyEngine`, daily spend limits, recipient allowlists, and an
  admin-managed sanctions deny list.
- [`contracts/IPQCVerifier.sol`](contracts/IPQCVerifier.sol) — PQ verifier trust-boundary
  interface (`algorithmId()`, `verify()`).
- [`contracts/MockMLDSAVerifier.sol`](contracts/MockMLDSAVerifier.sol) — **mock**
  ML-DSA-65 verifier, **test/demo only**, no real verification.
- [`contracts/verifiers/AttestationPQCVerifier.sol`](contracts/verifiers/AttestationPQCVerifier.sol)
  — non-mock trusted-attestation path; verifies an authorized EIP-712 attestor
  signature and does not execute ML-DSA on-chain. Uses `Ownable2Step` for safer
  ownership transfer (consistent with `WalletWallVault`).
- [`contracts/mocks/`](contracts/mocks/) — test-only helpers (`AlwaysFalsePQCVerifier`,
  `ForceSend`).
- [`pqc/ml-dsa.ts`](pqc/ml-dsa.ts) — off-chain ML-DSA-65 signer using
  `@noble/post-quantum`.
- [`scripts/attestor-cli.ts`](scripts/attestor-cli.ts) — verifies ML-DSA-65 off-chain
  before signing an EIP-712 attestation for `AttestationPQCVerifier`.

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

### Verify ML-DSA and build an attestation

Demo mode verifies deterministic library-generated ML-DSA-65 material before signing,
but that material is only for local demonstration:

```bash
npm run attestor:demo
```

Real verify mode requires explicit withdrawal, ML-DSA, verifier, chain, deadline, and
attestor inputs. It refuses to sign if ML-DSA verification fails or if the known demo
material is supplied:

```bash
npm run attestor:verify -- \
  --withdrawal-digest 0x... \
  --message-file test/fixtures/mldsa/library-generated/message.hex \
  --public-key-file test/fixtures/mldsa/library-generated/public-key.hex \
  --pq-signature-file test/fixtures/mldsa/library-generated/signature.hex \
  --verifier 0x... \
  --chain-id 31337 \
  --deadline 4102444800
```

Set `ATTESTOR_PRIVATE_KEY` or pass `--attestor-private-key` for isolated local
development. The contract still verifies only the trusted EVM attestor signature; it
does not execute ML-DSA.

### Deploy (local / testnet ONLY)

```bash
npx hardhat node          # in one terminal
npm run deploy -- --network localhost
```

Public testnet deployments read credentials and RPC URLs from environment variables.
Copy `.env.example` as a reference, but do not commit populated values and do not paste
private keys into issues, pull requests, or chat.

**Use Sepolia test ETH only. Never send real funds. Frontend write operations must stay
restricted to supported testnet chain IDs and must not silently fall back to mainnet.**

PowerShell example:

```powershell
$env:DEPLOYER_PRIVATE_KEY = "0x..."
$env:SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
npm run deploy:sepolia
```

Shell example:

```bash
DEPLOYER_PRIVATE_KEY=0x... \
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com \
npm run deploy:sepolia
```

If the verifier deployed but the vault deployment failed, set the public verifier
address before retrying so the script reuses the existing contract:

```powershell
$env:PQC_VERIFIER_ADDRESS = "0x..."
npm run deploy:sepolia
```

Supported deployment targets are `hardhat`, `localhost`, `sepolia`, and
`base-sepolia`. The deployer pays testnet gas once; the resulting contracts remain
available on that testnet without an ongoing hosting fee.

The active Ethereum Sepolia test deployment and deprecated historical deployment are
recorded in [docs/Deployments.md](docs/Deployments.md). The active deployment is wired
to `MockMLDSAVerifier`; it is for testnet integration only and provides no real PQ
verification. Its observed runtime is `20,508` bytes, while current public HEAD
recompiles to `22,138` bytes; exact deployment reproducibility is pending public
source/artifact alignment.

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
- **Large-withdrawal timelock:** above-threshold withdrawals are authorized and reserved
  at queue time, then finalized only after the configured delay. Parameter changes use
  a separate two-day proposal/apply flow.
- **Policy boundary:** an optional `IPolicyEngine` can reject withdrawals before state
  changes. `CompositePolicyEngine` composes the daily spend, recipient allowlist, and
  sanctions modules so all enabled checks must pass.
- **Finalization policy check:** a queued withdrawal is checked against the current
  policy engine again if the engine address changed after queueing. The unchanged
  stateful engine is not called twice, avoiding double-counting daily spend.
- **Treasury quorum:** vault owners can require guardian approvals before a queued large
  withdrawal finalizes. Approvals are scoped to the queued operation and cleared on
  cancellation, recovery, rotation, or guardian-set replacement.
- **Trusted-attestation verifier:** binds the withdrawal digest, public-key hash, PQ
  signature hash, algorithm identifier, verifier, chain ID, and deadline to an
  authorized EIP-712 attestor signature. The CLI verifies ML-DSA-65 before signing, but
  the attestor key and service remain central trust boundaries.
- **Reentrancy:** `ReentrancyGuard` + checks-effects-interactions.
- **Verifier governance:** the `Ownable2Step` owner proposes a verifier, waits the fixed
  two-day `PQ_VERIFIER_UPDATE_DELAY`, then applies it. The owner can cancel a pending
  proposal before application. The active verifier remains unchanged during the delay.
  Ownership can be assigned to a multisig such as Safe without adding multisig logic to
  this prototype.
- **Ownership safety:** both `WalletWallVault` and `AttestationPQCVerifier` use
  `Ownable2Step`. Ownership transfer requires the new owner to explicitly accept,
  preventing accidental transfer to an unusable address. Attestor rotation itself remains
  immediate once called by the owner — see
  [docs/Attestation_Verifier.md](docs/Attestation_Verifier.md).
- **Admin:** the owner can still choose the verifier and pause the vault. The delay
  improves visibility and reaction time but does not remove the central trust boundary.
- **Accounting:** ETH force-sent via `selfdestruct` is not credited and cannot be
  withdrawn; internal per-vault balances are unaffected.

Full details: [docs/Security_Assumptions.md](docs/Security_Assumptions.md).

## ML-DSA test vectors

`test/fixtures/mldsa/library-generated/` — deterministic library-generated ML-DSA-65
fixtures used by the existing attestor CLI tests. Not official NIST vectors.

`test/fixtures/mldsa/nist-cavp/` — a 6-vector subset (3 valid + 3 invalid) from the
official [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)
(FIPS 204, ML-DSA-65, sigVer, external interface, pure mode, vsId 42 group 3).
`@noble/post-quantum` `ml_dsa65.verify` passes all 15 test cases in that ACVP group.
See `test/MLDSAConformance.test.ts` and `test/fixtures/mldsa/nist-cavp/README.md`.

## Post-quantum verifier roadmap

The mock is **Path 0**. The implemented trusted-attestation verifier is the current
non-mock prototype path (**Path 1**) and depends on correct off-chain ML-DSA verification
by its authorized attestor. The SP1 path is an unaudited scaffold/roadmap path, not the
active deployment path. Native Solidity ML-DSA remains impractical, and no chain-native
PQ precompile is live or assumed. See
[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

## Cryptography naming (NIST)

- **ML-DSA / FIPS 204** — formerly **CRYSTALS-Dilithium** (this prototype targets
  ML-DSA-65: 1952-byte public key, 3309-byte signature).
- **SLH-DSA / FIPS 205** — formerly **SPHINCS+** (candidate for future PQ paths).

## License

MIT. Provided **as-is** for research and educational purposes. No warranty. Not audited.
**Do not use with real funds.**
