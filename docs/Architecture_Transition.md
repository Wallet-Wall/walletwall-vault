# WalletWall Vault: Architecture Transition

> ⚠️ **Research prototype. Not audited. Do not use real funds.** The on-chain PQ verifier
> is a mock/placeholder (`MockMLDSAVerifier`) and performs no real cryptographic
> verification.
>
> **Note (current API):** Since the `harden-vault-core` refactor, the verifier interface
> is `IPQCVerifier` (`verify(bytes32 digest, bytes publicKey, bytes signature)`),
> withdrawals are authorized via an **EIP-712** typed `Withdrawal` struct with a
> `deadline` and a `VaultMode` enum, and `MLDSAVerifier` was renamed to
> `MockMLDSAVerifier`. The historical detail below is retained for context — see
> [../README.md](../README.md) and [Security_Assumptions.md](Security_Assumptions.md) for
> current behavior.

This document describes the transition from the deprecated WOTS+ (Winternitz One-Time Signature) architecture to the new NIST-approved ML-DSA (Dilithium) architecture.

## Before: WOTS+ Architecture

The previous system used WOTS+, which had several limitations:
- **One-time use keys**: Every withdrawal required a new key or a complex Merkle tree management.
- **Large signatures**: WOTS+ signatures consist of many hash chain values.
- **High complexity**: On-chain verification required many hash operations.

### Flow (Before)
1. User generates WOTS+ keypair.
2. User registers WOTS+ public key hash in the Vault.
3. For withdrawal:
   - User provides WOTS+ signature (array of 32-byte hashes).
   - Vault calls a `verifyWOTS` helper.
   - `verifyWOTS` reconstructs the public key from the signature and message, then hashes it.
   - Hash is compared with the stored `pqcPublicKeyHash`.

## After: NIST PQ Architecture (ML-DSA)

The new system uses ML-DSA-65 (Dilithium3), a NIST-approved post-quantum digital signature algorithm.

### Key Improvements:
- **Reusable keys**: ML-DSA keys can be used for many signatures, just like ECDSA.
- **Standardized**: Part of the FIPS 204 standard.
- **Hybrid Security**: Built-in support for requiring both ECDSA and PQC signatures.
- **Algorithm Agnostic**: The vault now uses an interface (`IPQCVerifier`), allowing for future upgrades to other NIST algorithms (like SLH-DSA or Falcon).

### Flow (After)
1. User generates ML-DSA-65 keypair.
2. User registers ML-DSA public key in the Vault.
3. For withdrawal:
   - User provides ML-DSA signature.
   - Vault calls `IPQCVerifier.verify`.
   - The verifier (e.g., `MockMLDSAVerifier`) validates the signature against the registered public key.
   - Replay protection is handled via a `nonce`.

## Architecture Diagram

```mermaid
graph TD
    subgraph "Off-chain (TypeScript SDK)"
        A[User Private Keys] --> B[ECDSA Signer]
        A --> C[ML-DSA Signer]
        B --> D[Withdrawal Request]
        C --> D
    end

    subgraph "On-chain (Ethereum)"
        D --> E[WalletWallVault]
        E --> F[OpenZeppelin ECDSA]
        E --> G[IPQCVerifier (ML-DSA)]
        F -- Valid --> H{Both Valid?}
        G -- Valid --> H
        H -- Yes --> I[Release Funds]
        H -- No --> J[Revert]
    end
```

## Chosen Algorithm: ML-DSA-65

We chose **ML-DSA-65** (Dilithium3) for this implementation because:
1. **NIST Approval**: It is the primary recommendation by NIST for general-purpose digital signatures.
2. **Performance**: It offers a good balance between signature size (~3.3 KB) and verification speed.
3. **Security**: It provides NIST Security Category 3 (equivalent to AES-192).

### Technical Specs:
- **Public Key Size**: 1952 bytes
- **Signature Size**: 3309 bytes
- **Standard**: FIPS 204
