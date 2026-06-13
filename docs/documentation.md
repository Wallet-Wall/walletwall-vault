# WalletWall Vault — Developer Documentation

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> The repository includes a mock verifier (`MockMLDSAVerifier`, test/demo only, no real
> cryptographic verification) and a trusted-attestation verifier
> (`AttestationPQCVerifier`, non-mock but not on-chain ML-DSA). Neither path makes this
> prototype suitable for real-fund custody. See [../SECURITY.md](../SECURITY.md) and
> [Security_Assumptions.md](Security_Assumptions.md).

## Overview

WalletWall Vault is a hybrid classical (ECDSA) + post-quantum (PQ) withdrawal-
authorization prototype. Withdrawals are authorized with an **EIP-712** typed message and
protected by **per-owner nonces** and a signed **deadline**.

## Core components

### Smart contracts
- `WalletWallVault.sol` — vault registration, ETH deposits (`deposit` / `depositFor`),
  and EIP-712 authorized withdrawals. Uses `ReentrancyGuard`, `Pausable`, `Ownable2Step`,
  and custom errors. Authorization policy is selected per vault via the `VaultMode` enum
  (`EcdsaOnly`, `PqOnly`, `Hybrid`); **Hybrid is the intended default** and requires both
  signatures. Includes timelocked PQ verifier governance (`proposePQVerifier` →
  `applyPQVerifierUpdate` after a two-day delay, with `cancelPQVerifierUpdate`).
- `IPQCVerifier.sol` — the PQ verifier trust-boundary interface
  (`algorithmId()`, `verify(digest, publicKey, signature)`).
- `MockMLDSAVerifier.sol` — **mock** ML-DSA-65 verifier for tests and local demos only.
  Reports `keccak256("MOCK-ML-DSA-65")`. Performs structural length checks only — no
  real cryptographic verification. `PqOnly` vault creation is blocked while this
  verifier is active.
- `contracts/verifiers/AttestationPQCVerifier.sol` — **trusted-attestation** verifier.
  Reports `keccak256("ATTESTED-ML-DSA-65")`. Verifies an authorized off-chain attestor's
  EIP-712 signature over a statement that binds the withdrawal digest, public-key hash,
  PQ signature hash, algorithm ID, verifier address, chain ID, and deadline. Does **not**
  execute ML-DSA on-chain. Security depends on the attestor correctly verifying ML-DSA
  off-chain. See [Attestation_Verifier.md](Attestation_Verifier.md).
- `contracts/mocks/` — test-only helpers (`AlwaysTruePQCVerifier`,
  `AlwaysFalsePQCVerifier`, `ForceSend`, `RejectEther`).

### Off-chain
- `pqc/ml-dsa.ts` — ML-DSA-65 key generation and signing via `@noble/post-quantum`.
- `scripts/attestor-cli.ts` — verifies ML-DSA-65 off-chain (with `@noble/post-quantum`)
  before signing an EIP-712 attestation for `AttestationPQCVerifier`. Use
  `npm run attestor:demo` or `npm run attestor:verify`. See
  [Attestation_Verifier.md](Attestation_Verifier.md) for usage and trust model.

## Withdrawal flow

1. Build a `Withdrawal` struct: `{ vaultOwner, recipient, amount, nonce, deadline, vaultMode }`.
2. Compute the EIP-712 digest over the domain
   `{ name: "WalletWallVault", version: "1", chainId, verifyingContract }`.
3. Produce the signatures the mode requires:
   - ECDSA: `signer.signTypedData(domain, types, request)`.
   - PQ: `MLDSASigner.sign(digest, pqPrivateKey)` (validated by the configured verifier).
4. Submit `vault.withdraw(request, ecdsaSignature, pqSignature)` — may be relayed by anyone;
   authorization comes from the signatures, not `msg.sender`.

The contract checks: vault exists, deadline not passed, amount > 0, recipient ≠ 0,
nonce matches, requested mode matches the vault's mode, sufficient balance, then the
required signature(s). It follows checks-effects-interactions and increments the nonce
before transferring.

See [../README.md](../README.md) for a complete, runnable example, and `npm run demo` for
an end-to-end local walkthrough.

## Why PQ verification is mocked on-chain

Real ML-DSA verification is impractical to run natively within current EVM gas limits.
This prototype isolates PQ verification behind `IPQCVerifier` so a real verifier
(trusted attestation, ZK proof, or a future chain-native precompile) can be swapped in
without changing the vault. See [Verifier_Roadmap.md](Verifier_Roadmap.md).
