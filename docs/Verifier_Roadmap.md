# PQ Verifier Roadmap

> ⚠️ **Research prototype. Not audited. Do not use real funds.**
> Today the vault ships with a **mock** PQ verifier (`MockMLDSAVerifier`) that performs
> **no real cryptographic verification**.

The vault depends only on the `IPQCVerifier` interface:

```solidity
interface IPQCVerifier {
    function algorithmId() external view returns (bytes32);
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature)
        external view returns (bool);
}
```

This indirection is the whole point: the *strategy* for verifying post-quantum
signatures can evolve without changing the vault. The verifier is **admin-controlled**
(`updatePQVerifier`, owner-only) — see
[Security_Assumptions.md](Security_Assumptions.md) for the trust implications.

Below are the candidate verification paths, from today's placeholder to a future
chain-native solution.

## Path 0 — Mock / local verifier (current)

- **Contract:** `MockMLDSAVerifier`
- **Security:** none. Structural length/non-zero checks only.
- **Use:** local + testnet demos, wiring up the trust boundary, exercising replay and
  hybrid-authorization flows.
- **Status:** implemented.

## Path 1 — Trusted-attestation verifier

- **Idea:** a trusted off-chain service verifies the real ML-DSA signature
  (e.g. using `@noble/post-quantum`) and produces an on-chain attestation (its own
  ECDSA/threshold signature) that the `IPQCVerifier` checks.
- **Trust:** shifts trust to the attestor / committee. Centralized but cheap and
  deployable today.
- **Security:** real, **conditional on the attestor being honest and available.**
- **Status:** not implemented (design candidate).

## Path 2 — ZK-proof verifier

- **Idea:** prove "this ML-DSA-65 signature verifies for this public key and digest"
  inside a zero-knowledge circuit (e.g. Groth16 / Halo2 / a STARK), and verify the
  succinct proof on-chain.
- **Trust:** trust-minimized — only the proving system and circuit correctness.
- **Cost:** higher proving effort off-chain; modest on-chain verification cost.
- **Security:** real and decentralized if the circuit is correct and audited.
- **Status:** not implemented (preferred long-term software path).

## Path 3 — Optimized native Solidity verifier

- **Idea:** implement ML-DSA verification directly in Solidity/Yul.
- **Reality:** ML-DSA verification is large and currently impractical to run within
  EVM gas limits without specialized support. Listed for completeness.
- **Status:** not implemented; likely impractical without precompiles.

## Path 4 — Chain-native PQ support / precompile

- **Idea:** the underlying L1/L2 exposes a precompile or native opcode for ML-DSA
  (or SLH-DSA) verification; the `IPQCVerifier` implementation simply forwards to it.
- **Trust:** same as the host chain.
- **Status:** depends on future protocol support; the interface is ready for it.

## Algorithm notes (NIST)

- **ML-DSA-65 / FIPS 204** (formerly **CRYSTALS-Dilithium**, Dilithium3): primary target.
  Public key 1952 bytes, signature 3309 bytes, NIST security category 3.
- **SLH-DSA / FIPS 205** (formerly **SPHINCS+**): a stateless, hash-based alternative
  worth supporting where a more conservative, non-lattice assumption is desired.
- The `algorithmId()` getter lets integrators detect which scheme (or mock) is wired in
  before trusting it.

## Migration checklist (when a real verifier is ready)

1. Deploy and **independently audit** the new `IPQCVerifier` implementation.
2. Confirm `algorithmId()` matches the expected scheme.
3. Validate against known-answer test vectors for the chosen parameter set.
4. Switch via `updatePQVerifier` (owner-only) — ideally behind a timelock/multisig.
5. Update docs to drop the "mock verifier" disclaimers **only** once real verification
   is in place and reviewed.
