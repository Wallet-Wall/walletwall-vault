# Experimental ZK Verifier Scaffold for ML-DSA-65

## Overview
This code is an unaudited testnet scaffold for verifying ML-DSA-65 proofs with Succinct's SP1 zkVM. It is a roadmap/prototyping path, not the current operational verifier path. It is not production custody software and must not be used with real funds. It does not include a production SP1 prover integration.

## Components

### 1. ZKVM Guest Program (`zkvm/guest`)
The Rust-based guest program implements the FIPS 204 (ML-DSA-65) verification logic.
- **Security**: Ensures every private witness (raw signature, public key) is bound to the public inputs (hashes) to prevent under-constrained witness vulnerabilities.
- **Optimization**: Designed to run efficiently within the SP1 zkVM, utilizing optimized hash precompiles.

### 2. Prover Client (`scripts/prover-client.ts`)
A TypeScript encoder for proof bytes returned by an independently configured SP1 prover.
- **Fail closed**: It never fabricates proof bytes and rejects malformed public inputs.
- **Prover required**: Callers must build and validate a real SP1 prover integration separately.

### 3. On-chain Verifier (`contracts/verifiers/ZKMLDSAVerifier.sol`)
The Solidity contract that integrates the ZK proof into the `WalletWallVault`.
- **EVM Optimized**: Uses the auto-generated SP1 Groth16/Plonk verifier to keep gas costs below 300,000.
- **Immutable trust root**: The SP1 verifier address and program verification key are fixed at deployment. Upgrades require deploying a new verifier and using the vault's delayed verifier-rotation process.

## Trust Assumptions
- **zkVM Soundness**: Relies on the soundness of the SP1 zkVM and the underlying proof system (Plonky3/Groth16).
- **FIPS 204 Implementation**: Relies on the correctness of the ML-DSA-65 Rust implementation within the guest program.
- **Deployment integrity**: Operators must independently verify the SP1 verifier bytecode, guest build, program verification key, and prover output before proposing the verifier to a vault.
- **Mock isolation**: The deployment script permits the always-accepting mock only on local chain IDs with an explicit `ALLOW_MOCK_SP1=true` opt-in.

## Unverified Claims
Gas usage and end-to-end NIST conformance have not been established for this scaffold. Do not publish performance or compliance claims until the pinned guest is compiled, a real proof is generated, and independent positive and negative vectors pass through the deployed SP1 verifier.

## NIST ACVP Conformance
The repository's current Solidity tests use `MockSP1Verifier` and therefore do not prove zkVM execution or NIST conformance. A production-readiness review requires tests that compile and execute the Rust guest and verify real SP1 proofs.

The active Ethereum Sepolia deployment documented in
[Deployments.md](Deployments.md) does not use `ZKMLDSAVerifier`; it uses
`MockMLDSAVerifier`.
