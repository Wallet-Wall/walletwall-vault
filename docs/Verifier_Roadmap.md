# PQ Verifier Roadmap

> ⚠️ **Research prototype. Not audited. Do not use real funds.**
> The vault includes a test/demo-only mock verifier and a trusted-attestation verifier.
> Neither verifies ML-DSA on-chain.

The vault depends only on the `IPQCVerifier` interface:

```solidity
interface IPQCVerifier {
  function algorithmId() external view returns (bytes32);
  function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature) external view returns (bool);
}
```

This indirection is the whole point: the _strategy_ for verifying post-quantum
signatures can evolve without changing the vault. The verifier is **admin-controlled**
through a timelocked two-step flow (`proposePQVerifier` then
`applyPQVerifierUpdate` after two days). The owner can be a multisig through the existing
`Ownable2Step` ownership model. See
[Security_Assumptions.md](Security_Assumptions.md) for the trust implications.

Below are the candidate verification paths, from today's placeholder to a future
chain-native solution.

## Path 0 — Mock / local verifier (current)

- **Contract:** `MockMLDSAVerifier`
- **Security:** none. Structural length/non-zero checks only.
- **Use:** local + testnet demos, wiring up the trust boundary, exercising replay and
  hybrid-authorization flows.
- **Status:** implemented.

## Path 1 — Trusted-attestation verifier (implemented)

- **Contract:** `AttestationPQCVerifier`
- **Idea:** a trusted off-chain service verifies the ML-DSA signature with a real FIPS
  204-compatible implementation and produces an EIP-712 attestation signed by the
  configured EVM attestor.
- **Trust:** shifts trust to the attestor / committee. Centralized but cheap and
  deployable today.
- **Security:** stronger than the mock only because the contract enforces the authorized
  attestor signature. Correctness remains conditional on the attestor key, service, and
  off-chain ML-DSA verification.
- **On-chain behavior:** binds the withdrawal digest, public-key hash, PQ signature hash,
  algorithm identifier, verifier address, chain ID, and deadline. It does not execute
  ML-DSA verification.
- **Attestor rotation asymmetry:** the vault's two-day verifier governance delay does
  **not** apply to `updateAttestor`. The attestor can be rotated immediately by the
  attestor owner. This means vault users are not protected from immediate attestor
  replacement inside an already-configured `AttestationPQCVerifier`. Operators must
  monitor `AttestorUpdated` events. This asymmetry is a fundamental limitation of the
  trusted-attestation path and cannot be fixed within Path 1; it requires graduating to
  Path 2 (ZK) or Path 4 (chain-native).
- **Status:** implemented for research and testnet evaluation. See
  [Attestation_Verifier.md](Attestation_Verifier.md).
- **Off-chain prototype:** `scripts/attestor-cli.ts` (`npm run attestor:verify`)
  verifies ML-DSA-65 with `@noble/post-quantum` before signing. In real verify mode
  it refuses both demo material and library-generated fixture material. This
  demonstrates the required verification gate but does not remove trust in the
  attestor key or service. The older `scripts/sign-attestation.ts` has been renamed
  to `scripts/demo-sign-attestation-unsafe.ts` (deprecated, no ML-DSA verification)
  and the `sign:attestation` npm script has been removed.
- **Ownership:** `AttestationPQCVerifier` uses `Ownable2Step` (consistent with
  `WalletWallVault`). Attestor rotation itself remains immediate.

## Path 2 — ZK-proof verifier

- **Idea:** prove "this ML-DSA-65 signature verifies for this public key and digest"
  inside a zero-knowledge circuit (e.g. Groth16 / Halo2 / a STARK), and verify the
  succinct proof on-chain.
- **Trust:** reduces dependence on an operational attestor but still depends on the
  proving system, circuit correctness, setup assumptions where applicable, and audits.
- **Cost:** higher proving effort off-chain; modest on-chain verification cost.
- **Status:** not implemented (preferred long-term software path).

ZK verification or native chain support remains a stronger future direction because it
can reduce dependence on the operational attestor. Those approaches still require
correct implementations, review, and deployment-specific security analysis.

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
3. Validate against known-answer test vectors for the chosen parameter set. Official
   NIST ACVP sigVer vectors for ML-DSA-65 are available under
   `test/fixtures/mldsa/nist-cavp/` (FIPS 204, external interface, pure mode).
4. Propose the verifier via `proposePQVerifier` from the owner or owner multisig.
5. Monitor the `PQVerifierUpdateProposed` event and independently verify the proposed
   address and bytecode during the fixed two-day delay. Cancel with
   `cancelPQVerifierUpdate` if review fails or the proposal is no longer intended.
6. Apply via `applyPQVerifierUpdate` only after the delay and review are complete.
7. Update docs to drop the "mock verifier" disclaimers **only** once real verification
   is in place and reviewed.

For local/testnet prototyping, an EOA owner and the built-in delay are sufficient to
exercise the governance flow. A future production design would still need deployment-
specific governance review, a reviewed multisig or timelock controller, monitoring, and
incident procedures. This repository does not claim that the current governance is
production-ready.
