# Security Policy

## ⚠️ Status: research prototype — NOT for real funds

WalletWall Vault is a **Phase 1 research / hybrid-authorization prototype** exploring
classical (ECDSA) + post-quantum (PQ) withdrawal authorization and a post-quantum
migration path for smart-contract vaults.

It is **explicitly not**:

- production custody software,
- production-grade quantum resistance,
- protection for real funds,
- audited,
- a reviewed deployment system.

The repository includes two verifier paths:

- `MockMLDSAVerifier` is test/demo-only and performs no real cryptographic verification.
- `AttestationPQCVerifier` is non-mock but trusted. It verifies an authorized EVM
  attestor signature, not ML-DSA on-chain. Security depends on the attestor correctly
  verifying ML-DSA off-chain before signing.

Neither path makes this prototype suitable for production custody or real funds. See
[docs/Security_Assumptions.md](docs/Security_Assumptions.md) and
[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

> Use on local/testnet networks only. **Do not deposit real funds.**

## Scope

This policy covers the contracts and scripts in this repository:

- `contracts/WalletWallVault.sol`
- `contracts/IPQCVerifier.sol`
- `contracts/MockMLDSAVerifier.sol`
- `contracts/verifiers/AttestationPQCVerifier.sol`
- `contracts/SignatureVerifier.sol`
- `contracts/mocks/*` (test-only helpers)
- `pqc/ml-dsa.ts`, `scripts/*`

It does **not** cover the private WalletWall application repository, which is out of
scope and must not be modified as part of work on this prototype.

## What is (and isn't) protected

| Property                                                        | Status in this prototype                                       |
| --------------------------------------------------------------- | -------------------------------------------------------------- |
| Classical ECDSA authorization of withdrawals                    | Implemented (OpenZeppelin ECDSA over an EIP-712 digest)        |
| Replay protection                                               | Implemented (per-owner nonce + signed deadline)                |
| Tamper protection on owner/recipient/amount/nonce/deadline/mode | Implemented (all fields are part of the EIP-712 typed message) |
| Reentrancy protection                                           | Implemented (`ReentrancyGuard`, checks-effects-interactions)   |
| Pause / admin controls                                          | Implemented (`Pausable`, `Ownable2Step`)                       |
| Verifier update delay                                           | Implemented (two-step proposal + fixed two-day delay)          |
| Trusted off-chain ML-DSA attestation                            | Implemented; relies on an authorized EVM attestor              |
| On-chain ML-DSA verification                                    | Not implemented                                                |

With the mock verifier, the PQ layer provides no meaningful cryptographic authorization.
With `AttestationPQCVerifier`, the additional authorization is only as reliable as the
attestor key, service, and off-chain ML-DSA verification. It is stronger than the mock
only because an authorized attestor signature is enforced.

To prevent an unsafe configuration, **`PqOnly` mode is disabled at the contract level
while the configured verifier is the mock** (`MockMLDSAVerifier`): `createVault` reverts
with `PqOnlyDisabledForMockVerifier`. This keeps a classical ECDSA signature in the loop
(via `Hybrid` or `EcdsaOnly`) until a reviewed non-mock verifier is wired in. See
[docs/Security_Assumptions.md](docs/Security_Assumptions.md).

Verifier changes are not immediate. The owner must call `proposePQVerifier`, wait the
fixed two-day delay, and then call `applyPQVerifierUpdate`. The owner can call
`cancelPQVerifierUpdate` before application to clear the pending proposal. This creates
an observation and response window but does not remove owner trust: a compromised owner
can still propose and later apply a weak verifier. For shared governance, transfer
`Ownable2Step` ownership to a reviewed multisig. This prototype does not include or audit
a multisig implementation.

## Reporting a vulnerability

This is a research prototype maintained on a best-effort basis. If you find an issue:

1. Open a **private** report via GitHub Security Advisories on this repository, or
2. Open a regular issue **only** for non-sensitive findings.

Please do not file reports that depend on the mock verifier being insecure — that is a
known, documented property, not a vulnerability.

Failures that allow bypassing the configured attestor, changing bound attestation
fields, or accepting expired attestations are in scope.

## Cryptography / NIST naming

- **ML-DSA / FIPS 204** — Module-Lattice Digital Signature Algorithm, formerly
  **CRYSTALS-Dilithium**. This prototype targets the ML-DSA-65 parameter set.
- **SLH-DSA / FIPS 205** — Stateless Hash-based Digital Signature Algorithm, formerly
  **SPHINCS+**. A candidate for future, more conservative PQ authorization paths.
