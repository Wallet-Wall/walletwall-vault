# On-Chain Verifier Feasibility

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> **No on-chain ML-DSA verifier is implemented.** The active testnet verifier is the
> **mock**. This repository is **not production custody**, accepts **no mainnet
> deposits**, produces **no real yield**, and makes **no "quantum-proof" guarantee.**

This document records the feasibility, cost, and constraints for _future_ on-chain
ML-DSA-65 verification. It **documents**; it does **not implement or claim** on-chain
verification. It is intentionally narrow: where
[ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md) compares proof _systems_
(RISC Zero, SP1, Noir, Circom, native precompile, wait-and-monitor) in depth, this
doc focuses on the **on-chain verification boundary** — what it would take to verify
on-chain, what it would cost, the trusted-attestation vs direct-verification
tradeoff, governance and mainnet-safety implications, and why none of it is
production-ready.

For the authoritative status of every capability, see
[ZK_PQ_Status_Matrix.md](ZK_PQ_Status_Matrix.md).

## Current state (what actually exists)

| Layer                                                                    | State                                                                                                                                                                      |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Off-chain open PQ verifier (`src/verifier/`)                             | ✅ Pure ML-DSA-65 (FIPS 204) verification; deterministic, hashes-only structured result. **Off-chain only.**                                                               |
| Open-verifier evidence artifact (`walletwall.pq-verifier-evidence.v1`)   | ✅ App-consumable, read-only, hashes only. Not trust-bearing.                                                                                                              |
| Reproducible proof-artifact manifest (`walletwall.pq-proof-artifact.v1`) | ✅ Deterministic SP1 _journal_ manifest; the proof block is **gated** (no real proof).                                                                                     |
| SP1 smoke lane                                                           | ✅ Journal-encoding check, no toolchain; heavy proving gated behind `RUN_SP1_E2E=1`.                                                                                       |
| Trusted attestation (`AttestationPQCVerifier`)                           | 🟡 Off-chain ML-DSA verify → EIP-712 attestation; the EVM checks the **attestor's ECDSA signature**, not ML-DSA. Trusted, not trustless.                                   |
| On-chain ML-DSA verification                                             | ❌ **Not implemented.** `ZKMLDSAVerifier` is a Solidity scaffold backed by `MockMLDSAVerifier` for local/testnet wiring only. The active Sepolia verifier is the **mock**. |

In short: **today the EVM never executes ML-DSA-65 arithmetic.** It either checks a
trusted attestor's ECDSA signature, or (in tests) calls a mock that returns a
preconfigured result.

## What on-chain verification would require

To verify ML-DSA-65 on-chain _without_ a trusted attestor, one of two things must
exist on the target chain:

1. **A verified succinct proof.** An off-chain prover runs ML-DSA-65 verification
   inside a zkVM/circuit and produces a proof; an on-chain verifier contract checks
   that proof plus a public journal binding `(withdrawalDigest, keccak256(pubKey),
keccak256(sig))`. This is the SP1/RISC Zero/Noir/Circom family — see
   [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md). It removes the attestor
   key but introduces trust in the prover, the proving system, and the
   circuit/guest correctness (which is **unaudited and does not exist** for ML-DSA-65
   today).

2. **A native PQ precompile.** The chain adds an ML-DSA (FIPS 204) precompile and the
   `IPQCVerifier` wrapper forwards inputs to it. No prover, no circuit, no trusted
   setup — but no EVM L1 or major L2 has shipped one as of mid-2026.

Either path must, at minimum:

- bind the proof/precompile result to the exact withdrawal digest and the
  `keccak256` of the public key and signature (the journal the SP1 lane already
  pins; see [PQ_Proof_Artifact.md](PQ_Proof_Artifact.md));
- pin the program/circuit identity (SP1 program vKey, RISC Zero image ID, or the
  precompile address) so the verifier cannot be silently swapped for a weaker one;
- preserve the existing `IPQCVerifier` interface so the vault can adopt it through
  governance without redeploying;
- carry conformance coverage against the NIST ACVP ML-DSA-65 sigVer vectors
  (`test/fixtures/mldsa/nist-cavp/`).

## Gas / cost considerations

Order-of-magnitude only; no ML-DSA-65 path has been benchmarked end-to-end here.

| Path                          | On-chain verify gas (approx.)         | Off-chain prover cost                                       | Notes                                                                    |
| ----------------------------- | ------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------ |
| Trusted attestation (today)   | ~30k–60k (ECDSA `ecrecover` + keccak) | ~1 ms ML-DSA verify + 1 ECDSA sign                          | Cheapest; **trusted**, not trustless.                                    |
| SP1 / RISC Zero Groth16 proof | ~200k–350k                            | minutes; ~$0.05–$5+ per proof (unbenchmarked for ML-DSA-65) | Plus the vault's own op gas. STARK-only verify is ~2M+ gas, impractical. |
| Circom / Groth16              | ~200k–250k                            | minutes                                                     | Lowest verify gas, but circuit-specific trusted setup.                   |
| Noir (Honk/UltraPlonk)        | ~300k–600k                            | minutes                                                     | Input handling for 1952-B key / 3309-B sig adds cost.                    |
| Native PQ precompile          | ~5k–50k (if optimized in client)      | none                                                        | Cheapest and trustless — but does not exist yet.                         |

The cost driver for every ZK path is ML-DSA-65's internals: SHAKE-128/256 (not
ZK-friendly), NTT over `q = 8,380,417` (does not embed naturally in BN254), and large
constraint/cycle counts (academic Dilithium-3 estimates run 10M–100M R1CS
constraints; zkVM cycle estimates 50M–500M). See the complexity notes in
[ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md).

## Verifier circuit / proof options (summary)

A one-line summary per candidate; the full analysis lives in
[ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md).

- **SP1 zkVM** — Rust guest in RISC-V; Groth16 wrapper for cheap on-chain verify. This
  repo already has the SP1 _scaffold_ (guest compile, journal lane) but **no audited
  guest and no real proof in CI**.
- **RISC Zero zkVM** — comparable; more battle-tested verifier, no ML-DSA-65 guest.
- **Noir / Circom** — hand-written lattice circuits; very high effort, SHAKE encoding
  is the gating unknown; Circom additionally needs a circuit-specific trusted setup.
- **Native precompile** — trivial wrapper, but blocked on chain-level adoption.

## Trusted attestation vs direct verification — the tradeoff

|                     | Trusted attestation (today)                          | Direct on-chain verification (future)                                                  |
| ------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| What the EVM checks | An attestor's ECDSA signature over a bound statement | A succinct proof (or precompile) of ML-DSA-65 validity                                 |
| Trust removed       | —                                                    | The attestor operational key                                                           |
| Trust introduced    | Attestor key + service availability                  | Prover availability + proving-system soundness + circuit/guest correctness (unaudited) |
| Gas                 | Lowest (~30k–60k)                                    | Higher (~200k–600k) or precompile (~5k–50k)                                            |
| Maturity            | Implemented (testnet, unaudited)                     | Not implemented; no audited ML-DSA-65 circuit exists                                   |
| Honest claim        | "trusted attestation, not trustless"                 | "trustless **iff** circuit + verifier are audited and the prover is honest/available"  |

Direct verification does **not** make the vault production custody. It swaps one
trust assumption (the attestor key) for a different set (prover, proving system,
circuit). Whether that is a net improvement depends entirely on the circuit being
**audited** — which it is not.

## Upgrade / governance implications

- The vault's verifier is swappable via a **timelocked** governance flow behind the
  stable `IPQCVerifier` interface, so a future on-chain verifier can be adopted
  without redeploying the vault.
- **Asymmetry to preserve:** `updateAttestor` on `AttestationPQCVerifier` is immediate
  and owner-controlled, while the verifier swap is timelocked. Any on-chain verifier
  must not reintroduce an un-timelocked trusted key (e.g. an upgradeable proxy admin
  or a mutable program-vKey/image-ID setter) without equivalent timelock + monitoring.
- The program identity (vKey / image ID / precompile address) must be pinned and
  changeable **only** through the same timelocked path, with on-chain events that
  operators monitor.

## Mainnet safety blockers

On-chain verification must **not** ship to mainnet until **all** hold:

1. A working ML-DSA-65 ZK guest/circuit that passes **all** NIST ACVP ML-DSA-65
   sigVer vectors.
2. An **independent security audit** of the guest/circuit (under-constrained circuits
   can accept invalid witnesses → fraudulent withdrawals).
3. An independent audit of the on-chain `IPQCVerifier` wrapper and program-identity
   pinning.
4. Proving cost/latency that is operationally acceptable for the withdrawal frequency.
5. A clear, written statement of trust removed vs trust remaining.
6. Governance/timelock review covering verifier swap **and** any key/program-identity
   mutation.
7. The broader vault custody design (deposits, withdrawals, key management,
   monitoring, incident response) separately designed, threat-modeled, and audited —
   which is **out of scope for this research repo**.

Until then, on-chain verification stays **off**, and the honest framing is trusted
attestation + off-chain verification.

## Why this is not production-ready

- No audited ML-DSA-65 ZK circuit or guest exists publicly (mid-2026).
- The repo's on-chain verifier is a **mock**; the SP1 lane proves nothing (journal
  only); the proof-artifact manifest's proof block is **gated**.
- Even a correct ZK verifier would not make the vault custody — that needs a separate,
  audited custody design.
- The trust this would remove (attestor key) is replaced by trust in an unaudited
  circuit and a prover — not obviously safer without an audit.

## Explicit non-goals / non-claims

- **No on-chain ML-DSA verifier is implemented** in this repository. The active
  testnet verifier is the mock.
- **No production custody.** No deposits/withdrawals of real funds.
- **No mainnet deposits.**
- **No real yield**, interest, APY, or rewards-as-returns.
- **No "quantum-proof" guarantee.**
- This document is **not** a deployment plan or a commitment to implement any path.

## Recommended future PR sequence

Ordered, each independently reviewable; later steps gated on earlier ones. Steps 1–2
are partially in place via the current workstream (the SP1 journal lane and the
`walletwall.pq-proof-artifact.v1` manifest); they are listed for completeness.

1. **Benchmark candidate proof paths.** Minimal SP1 (and/or RISC Zero) ML-DSA-65
   guest run in execute/dev mode against the NIST ACVP vectors; measure cycles,
   proving time, and on-chain verify gas on a local network. No new mainnet surface.
2. **Finalize the proof-artifact schema.** Extend `walletwall.pq-proof-artifact.v1`
   to carry a real (gated) proof reference + program vKey once a guest exists, keeping
   the deterministic journal fields stable. (Schema + validator already landed.)
3. **Add a testnet-only verification mock path.** Wire a `ZKMLDSAVerifier` against the
   real SP1 verifier contract on a testnet, still behind the timelocked
   `IPQCVerifier` swap and clearly labeled non-production. No mainnet.
4. **External security / circuit review.** Independent audit of the guest/circuit, the
   on-chain wrapper, and program-identity pinning before any trust-bearing use.
5. **Only later, consider a mainnet path** — and only if every mainnet-safety blocker
   above is cleared, including a separately audited custody design. Not in scope here.

## Related

- [ZK_PQ_Status_Matrix.md](ZK_PQ_Status_Matrix.md) — authoritative capability status
- [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md) — full proof-system comparison
- [ZK_Verifier_Production.md](ZK_Verifier_Production.md) · [PQ_Proof_Artifact.md](PQ_Proof_Artifact.md) · [SP1_Smoke_Lane.md](SP1_Smoke_Lane.md)
- [Verifier_Roadmap.md](Verifier_Roadmap.md) · [Security_Assumptions.md](Security_Assumptions.md) · [Attestation_Verifier.md](Attestation_Verifier.md)
