# Experimental ZK Verifier Scaffold for ML-DSA-65

## Overview
This code is an unaudited testnet scaffold for verifying ML-DSA-65 proofs with Succinct's SP1 zkVM. It is a roadmap/prototyping path, not the current operational verifier path. It is not production custody software and must not be used with real funds. It does not include a production SP1 prover integration.

## Components

### 1. ZKVM Guest Program (`zkvm/guest`)
The Rust-based guest program implements the FIPS 204 (ML-DSA-65) verification logic.
- **Relation (unaudited)**: The withdrawal program (`mldsa65-withdrawal`) accepts only when the ML-DSA-65 signature verifies over exactly the withdrawal digest it commits, under the empty FIPS 204 context, and it commits keccak256 of the public key and signature. NIST ACVP vectors run in the separate `mldsa65-acvp` program, whose vkey a verifier must never pin. This is checked by native relation tests, not by a proof.
- **Optimization**: Designed to run efficiently within the SP1 zkVM, utilizing optimized hash precompiles.

### 2. Prover Client (`scripts/prover-client.ts`)
A TypeScript encoder for proof bytes returned by an independently configured SP1 prover.
- **Fail closed**: It never fabricates proof bytes and rejects malformed public inputs.
- **Prover required**: Callers must build and validate a real SP1 prover integration separately.

### 3. On-chain Verifier (`contracts/verifiers/ZKMLDSAVerifier.sol`)
The Solidity wrapper a PQ consumer (`WalletWallVault`, `StablecoinVaultSimulator`, `PolicyControlBridge`, `WalletWallMultiSigVault`) can use as its `pqVerifier`.
- **Pinned SP1 Groth16 verifier**: `verify()` calls SP1Verifier v6.1.0 (Groth16) directly, never a gateway or a route; gas has not been measured (see Unverified Claims).
- **Pinned identity, not soundness**: The constructor refuses any SP1 verifier whose runtime code hash is not `SP1_VERIFIER_CODEHASH`, and `PROGRAM_VKEY` comes only from a generated designation; both are immutable, so a change means a new wrapper through the vault's delayed verifier-rotation process. A fixed address alone is not a fixed relation (a gateway's routes can change what one address accepts), and provenance is not soundness: see [SP1_Implementation_Pin_Designation_Registry.md](SP1_Implementation_Pin_Designation_Registry.md).
- **One-way halt**: A halt-only principal can move the wrapper from `ACTIVE` to `HALTED` (SP1-TD2); `verify()` then returns false for every consumer verifying through it. Recovery is a wrapper of a successor identity through each consumer's delayed rotation, never a redeployment of the halted identity. See [SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md](SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
- **Full chain id (F-1)**: The journal's `uint64` chain id is compared with the full 256-bit `block.chainid`, so a journal for one chain matches no chain whose id differs above bit 63.

## Trust Assumptions
- **zkVM Soundness**: Relies on the soundness of the SP1 zkVM and the underlying proof system (Plonky3/Groth16), including the v6.1.0 circuit's Groth16 setup. Nothing in the pin, the designation or the registry establishes it.
- **FIPS 204 Implementation**: Relies on the correctness of the ML-DSA-65 Rust implementation within the guest program.
- **Per-chain behaviour**: The pinned bytes behave as the Groth16 verifier only where the chain's precompiles do. The deployment tooling's per-chain execution check (a real proof accepted, a tampered proof and an odd-word canary refused) must pass before deploying, and again whenever a chain may have changed.
- **Deployment integrity**: Off a local chain, `scripts/deploy-zk-verifier.ts` takes the SP1 verifier and `PROGRAM_VKEY` only from a designation, refuses overrides, measures the verifier's code and the per-chain verdicts on the target chain, and reads the wrapper back; operators still review the designation and the deployment before proposing the verifier to a vault, and record the wrapper in the registry from chain reads (`scripts/register-sp1-wrapper.ts`).
- **Proving availability**: A PqOnly exit needs a proof, so the rotation delay protects users only while they can prove. The v6.1.0 circuit artifacts are not archived by WalletWall (`PROVING_AVAILABILITY = OWNER_DOWNLOAD_REQUIRED`, `evidence/zk/sp1-impl/proving-availability.json`).
- **Mock isolation**: The deployment script permits the always-accepting mock only on local chain IDs with an explicit `ALLOW_MOCK_SP1=true` opt-in, labelled TEST ONLY; the binding gate refuses a mock-backed wrapper off a local chain.

## Unverified Claims
Gas usage and end-to-end NIST conformance have not been established for this scaffold. Do not publish performance or compliance claims until a real proof of the designated program is generated, and independent positive and negative vectors pass through the designated SP1 verifier. No WalletWall proof has been generated, and no wrapper is deployed to any chain.

## NIST ACVP Conformance
The repository's current Solidity tests use `MockSP1Verifier` and therefore do not prove zkVM execution or NIST conformance. A production-readiness review requires tests that compile and execute the Rust guest and verify real SP1 proofs.

The active Ethereum Sepolia deployment documented in
[Deployments.md](Deployments.md) does not use `ZKMLDSAVerifier`; it uses
`MockMLDSAVerifier`.
