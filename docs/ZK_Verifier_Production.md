# Production ZK Verifier for ML-DSA-65

## Overview
This implementation provides a trustless, cryptographic verification of ML-DSA-65 signatures on-chain using Succinct's SP1 zkVM. It replaces the Path 1 trusted-attestation verifier with a Path 2 zero-knowledge proof verifier.

## Components

### 1. ZKVM Guest Program (`zkvm/guest`)
The Rust-based guest program implements the FIPS 204 (ML-DSA-65) verification logic.
- **Security**: Ensures every private witness (raw signature, public key) is bound to the public inputs (hashes) to prevent under-constrained witness vulnerabilities.
- **Optimization**: Designed to run efficiently within the SP1 zkVM, utilizing optimized hash precompiles.

### 2. Prover Client (`scripts/prover-client.ts`)
A TypeScript wrapper for interacting with the prover infrastructure.
- **Local/Remote**: Can be configured to generate proofs locally via GPU or via a remote prover service like Succinct Prover Network.

### 3. On-chain Verifier (`contracts/verifiers/ZKMLDSAVerifier.sol`)
The Solidity contract that integrates the ZK proof into the `WalletWallVault`.
- **EVM Optimized**: Uses the auto-generated SP1 Groth16/Plonk verifier to keep gas costs below 300,000.
- **Secure Ownership**: Implements `Ownable2Step` for managing the program verification key (vKey).

## Trust Assumptions
- **zkVM Soundness**: Relies on the soundness of the SP1 zkVM and the underlying proof system (Plonky3/Groth16).
- **FIPS 204 Implementation**: Relies on the correctness of the ML-DSA-65 Rust implementation within the guest program.
- **Admin Control**: The contract owner can update the `programVKey`, which determines the logic being verified. This is protected by the vault's 2-day governance delay during verifier rotation.

## Gas Profile
- **Verification**: ~250,000 - 280,000 gas (depending on the proof system).
- **Public Input Hashing**: ~10,000 gas.

## NIST ACVP Conformance
The guest program is designed to be tested against the NIST ACVP test vectors located in `test/fixtures/mldsa/nist-cavp/` to ensure full compliance with the FIPS 204 standard.
