# Migration Guide: From WOTS+ to ML-DSA

> ⚠️ **Research prototype. Not audited. Do not use real funds.**
> See [Security_Assumptions.md](Security_Assumptions.md) and [../README.md](../README.md).

This document describes the architecture transition from the deprecated WOTS+
(Winternitz One-Time Signature) design to the current NIST-approved ML-DSA
(FIPS 204) design. The current API and signing flow are in [../README.md](../README.md).
A runnable end-to-end example is in `scripts/demo-local.ts` (`npm run demo`).

---

## Why the change

The previous WOTS+ prototype had significant limitations:

- **One-time-use keys.** Every withdrawal required a new key or complex Merkle tree
  management.
- **Large, unwieldy signatures.** WOTS+ signatures consist of many concatenated hash
  chain values.
- **On-chain hashing complexity.** Verifying WOTS+ on-chain required many sequential
  hash operations.

---

## Current architecture (ML-DSA-65 / FIPS 204)

The vault now uses ML-DSA-65 (Dilithium3), a NIST-standardized post-quantum signature
scheme. Key properties:

- **Reusable keys.** A single ML-DSA keypair can authorize many withdrawals.
- **FIPS 204 standard.** Formerly CRYSTALS-Dilithium; standardized as ML-DSA by NIST.
- **Hybrid authorization.** The default `Hybrid` mode requires both an ECDSA signature
  and a PQ signature over the same EIP-712 withdrawal digest.
- **Swappable verifier.** PQ verification is isolated behind the `IPQCVerifier` interface,
  so the verification strategy can be upgraded without changing the vault contract.

Technical specs (ML-DSA-65): public key 1952 bytes, signature 3309 bytes, NIST
security category 3.

---

## Constructor

```solidity
constructor(address _pqVerifier)
```

The vault takes a single PQ verifier address. There is no separate ECDSA verifier
argument — ECDSA is verified inline using OpenZeppelin ECDSA over the EIP-712 digest.

---

## Creating a vault

`createVault` now takes a `VaultMode` enum instead of a `requireBoth` boolean:

```solidity
enum VaultMode { EcdsaOnly, PqOnly, Hybrid }

function createVault(
    address ecdsaSigner,
    bytes calldata pqPublicKey,
    VaultMode mode
) external whenNotPaused;
```

`Hybrid` is the intended default. `PqOnly` is blocked at the contract level while
the configured verifier is the mock (`MockMLDSAVerifier`).

TypeScript example:

```typescript
import { MLDSASigner } from "./pqc/ml-dsa";

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

const keys = MLDSASigner.generateKeyPair();

await vault.createVault(
    ecdsaSignerAddress,
    MLDSASigner.toHex(keys.publicKey),
    VaultMode.Hybrid,
);
```

---

## Authorizing withdrawals (EIP-712)

Withdrawals are authorized by an **EIP-712** typed `Withdrawal` message. Both ECDSA
and PQ signatures are produced over the same typed-data digest.

```typescript
const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

const domain = {
    name: "WalletWallVault",
    version: "1",
    chainId,
    verifyingContract: vaultAddress,
};

const types = {
    Withdrawal: [
        { name: "vaultOwner",  type: "address" },
        { name: "recipient",   type: "address" },
        { name: "amount",      type: "uint256" },
        { name: "nonce",       type: "uint256" },
        { name: "deadline",    type: "uint256" },
        { name: "vaultMode",   type: "uint8"   },
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

// ECDSA signature over the EIP-712 typed-data digest
const ecdsaSignature = await owner.signTypedData(domain, types, request);

// ML-DSA signature over the same digest
const digest = ethers.TypedDataEncoder.hash(domain, types, request);
const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, keys.privateKey));

// Withdrawals may be relayed by anyone; auth comes from the signatures
await vault.withdraw(request, ecdsaSignature, pqSignature);
```

Withdraw function signature:

```solidity
function withdraw(
    Withdrawal calldata request,
    bytes calldata ecdsaSignature,
    bytes calldata pqSignature
) external nonReentrant whenNotPaused;
```

---

## Key management

- ML-DSA keys are **reusable** — no need to rotate after each withdrawal.
- Per-owner **nonces** increment after each successful withdrawal, preventing replay.
- The nonce for a vault owner is readable via `vault.nonces(ownerAddress)` or
  `vault.getVault(ownerAddress).nonce`.

### Credential rotation (breaking change)

`updateEcdsaSigner` and `updatePQPublicKey` are **removed**. They are retained only as
tombstone selectors that revert with `UseRotateCredentials()`. They previously let the
vault owner address (a classical EOA) replace either credential with no signature from the
existing keys — a classical single point of failure that bypassed PQ protection. **Update
any integration that calls them to use `rotateCredentials` instead.**

Voluntary rotation now requires signatures from both the **current** and the **new**
credentials, per vault mode:

| Mode | Required signatures |
|---|---|
| `EcdsaOnly` | current ECDSA + new ECDSA |
| `PqOnly` | current PQ + new PQ |
| `Hybrid` | current ECDSA + current PQ + new ECDSA + new PQ |

The new keys must sign the same `RotateCredentials` EIP-712 digest (proof-of-possession),
which prevents rotating to an unusable credential that would brick a Pq/Hybrid vault. Both
credential fields are updated atomically; to change only one, pass the unchanged value for
the other (it still must co-sign in Hybrid). A successful rotation increments the nonce
(invalidating in-flight signed withdrawals) and cancels/refunds any pending large
withdrawal. The `RotateCredentials` typed-data definition is unchanged; only the function's
calldata changed — the four signatures are passed as a single `RotationAuth` struct:

```solidity
struct RotationAuth {
    bytes currentEcdsaSignature;
    bytes currentPqSignature;
    bytes newEcdsaSignature;
    bytes newPqSignature;
}

function rotateCredentials(
    address vaultOwner,
    address newEcdsaSigner,
    bytes calldata newPQPublicKey,
    uint256 deadline,
    RotationAuth calldata auth
) external nonReentrant whenNotPaused;
```

For lost or compromised keys (where the current keys cannot sign), use **guardian
recovery** instead — `rotateCredentials` deliberately cannot help there.

> Indexers: `EcdsaSignerUpdated` / `PQKeyUpdated` no longer fire. Track credential changes
> via `CredentialsRotated` (rotation) and `RecoveryExecuted` (guardian recovery). The two
> legacy event signatures are retained in the ABI for backward compatibility but are dead.

---

## PQ verifier paths

The vault delegates PQ verification to the configured `IPQCVerifier`:

| Verifier | Algorithm ID | On-chain ML-DSA? | Use |
|---|---|---|---|
| `MockMLDSAVerifier` | `MOCK-ML-DSA-65` | No — structural checks only | Tests and local demos |
| `AttestationPQCVerifier` | `ATTESTED-ML-DSA-65` | No — trusted off-chain attestor | Research / testnet |
| Future ZK verifier | TBD | No — succinct proof | Not yet implemented |
| Future precompile | TBD | Yes | Depends on chain support |

See [Verifier_Roadmap.md](Verifier_Roadmap.md) for trust assumptions of each path.

---

## Security notes

- All examples in this document are for a **testnet/local research prototype**.
  Do not use with real funds.
- The mock verifier provides no meaningful cryptographic authorization.
- The attestation verifier (`AttestationPQCVerifier`) delegates trust to a configured
  off-chain attestor. See [Attestation_Verifier.md](Attestation_Verifier.md).
- See [Security_Assumptions.md](Security_Assumptions.md) for the full trust model.
