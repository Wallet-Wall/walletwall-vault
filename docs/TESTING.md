# Testing

> Passing tests do not make this repository production-ready. They only show that the
> current prototype behavior matches the checked test cases.

This document describes the validation commands for the public WalletWall Vault
prototype and the security properties those tests do and do not cover.

## Install

```bash
npm install
```

## Standard Validation

Run these commands before treating a change as locally validated:

```bash
npm run compile
npm test
npm run lint
npm run format:check
```

Optional coverage run:

```bash
npm run coverage
```

## Script Meaning

| Command | Purpose |
| --- | --- |
| `npm run compile` | Compiles contracts and TypeChain output through Hardhat. |
| `npm test` | Runs the Hardhat test suite. |
| `npm run lint` | Runs Solhint on Solidity contracts. |
| `npm run format:check` | Checks formatting for Solidity and TypeScript files covered by Prettier. |
| `npm run coverage` | Runs Solidity coverage instrumentation. |

## Current Test Focus

The suite is intended to cover:

- Vault creation and credential validation.
- EIP-712 withdrawal signing and verification.
- Per-owner nonce replay protection.
- Signed deadline handling.
- Vault mode checks for `EcdsaOnly`, `PqOnly`, and `Hybrid`.
- Blocking `PqOnly` while the mock verifier is active.
- Reentrancy and failed ETH transfer paths.
- Force-sent ETH accounting behavior.
- Pause controls.
- Timelocked PQ verifier proposal, cancellation, and application.
- Trusted-attestation verifier payload binding and expiry checks.
- Attestor CLI fail-closed behavior for malformed, mismatched, demo, and invalid
  ML-DSA inputs.

## What Tests Do Not Prove

The tests do not prove:

- Production readiness.
- Real-fund safety.
- Correctness of a production attestation service.
- Safety of the private WalletWall app.
- Safety of any deployment, multisig, monitoring, or incident-response process.
- On-chain ML-DSA verification, because the repository does not implement it.
- Security against a future quantum-capable adversary.
- Any exact timeline for quantum key-recovery risk.

The mock verifier is intentionally not cryptographic. Tests using it exercise the vault
interface and control flow, not real PQ authorization.

The trusted-attestation verifier tests prove that the contract enforces a configured
attestor signature over bound fields. They do not prove that an off-chain service will
always verify ML-DSA correctly before signing.

## Adding Tests

When changing authorization, replay, governance, or verifier code, add or update tests
for both the successful path and fail-closed behavior. In particular, include tests for:

- Wrong signer or attestor.
- Wrong chain, contract, verifier, digest, key hash, signature hash, nonce, deadline,
  or vault mode.
- Stale or reused authorizations.
- Mock verifier misuse.
- Owner/governance edge cases.

Keep tests explicit about whether they are proving contract behavior, attestor-payload
binding, or only local/demo wiring.
