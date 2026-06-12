# Security Policy

## ⚠️ Status: research prototype — NOT for real funds

WalletWall Vault is a **Phase 1 research / hybrid-authorization prototype** exploring
classical (ECDSA) + post-quantum (PQ) withdrawal authorization and a post-quantum
migration path for smart-contract vaults.

It is **explicitly not**:

- production custody software,
- "quantum-proof" / "fully quantum-secure",
- protection for real funds,
- audited,
- mainnet-ready.

**The current on-chain PQ verifier is a mock/placeholder** (`MockMLDSAVerifier`) that
performs **no real cryptographic verification** of ML-DSA. See
[docs/Security_Assumptions.md](docs/Security_Assumptions.md) and
[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md).

> Use on local/testnet networks only. **Do not deposit real funds.**

## Scope

This policy covers the contracts and scripts in this repository:

- `contracts/WalletWallVault.sol`
- `contracts/IPQCVerifier.sol`
- `contracts/MockMLDSAVerifier.sol`
- `contracts/SignatureVerifier.sol`
- `contracts/mocks/*` (test-only helpers)
- `pqc/ml-dsa.ts`, `scripts/*`

It does **not** cover the private WalletWall application repository, which is out of
scope and must not be modified as part of work on this prototype.

## What is (and isn't) protected

| Property | Status in this prototype |
| --- | --- |
| Classical ECDSA authorization of withdrawals | Implemented (OpenZeppelin ECDSA over an EIP-712 digest) |
| Replay protection | Implemented (per-owner nonce + signed deadline) |
| Tamper protection on owner/recipient/amount/nonce/deadline/mode | Implemented (all fields are part of the EIP-712 typed message) |
| Reentrancy protection | Implemented (`ReentrancyGuard`, checks-effects-interactions) |
| Pause / admin controls | Implemented (`Pausable`, `Ownable2Step`) |
| **Real post-quantum signature verification** | **NOT implemented — mock verifier only** |

Because the PQ layer is a mock, in `Hybrid` mode the *effective* security today is
approximately that of the classical ECDSA layer alone. Do not rely on the PQ layer for
any security guarantee in this prototype.

## Reporting a vulnerability

This is a research prototype maintained on a best-effort basis. If you find an issue:

1. Open a **private** report via GitHub Security Advisories on this repository, or
2. Open a regular issue **only** for non-sensitive findings.

Please do not file reports that depend on the mock verifier being insecure — that is a
known, documented property, not a vulnerability.

## Cryptography / NIST naming

- **ML-DSA / FIPS 204** — Module-Lattice Digital Signature Algorithm, formerly
  **CRYSTALS-Dilithium**. This prototype targets the ML-DSA-65 parameter set.
- **SLH-DSA / FIPS 205** — Stateless Hash-based Digital Signature Algorithm, formerly
  **SPHINCS+**. A candidate for future, more conservative PQ authorization paths.
