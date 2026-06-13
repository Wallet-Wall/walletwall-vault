# ZK Verifier Feasibility — WalletWall Vault

> **Research document. Not a deployment plan. WalletWall Vault is a research prototype
> that is not audited, not production custody, and does not provide trustless PQ
> verification today.** This document evaluates possible future paths for reducing trust
> in the attestor. No path described here has been implemented or audited. Nothing here
> constitutes a commitment to implement any option.

## Purpose

WalletWall Vault currently uses a trusted-attestation path (Path 1) in which an
off-chain service verifies ML-DSA-65 and produces an EIP-712 attestation. The EVM
verifies the attestor's ECDSA signature, not ML-DSA itself. This document evaluates
seven candidate approaches for strengthening that trust model, with the goal of
informing a future prototype decision.

The question evaluated here is:

> What would it take to reduce or eliminate dependence on the operational attestor,
> and which approach is the most realistic next step for a research prototype?

---

## Background: Current Trusted Attestation Path (Path 1)

### What it does

`AttestationPQCVerifier` verifies an EIP-712 signature from a configured, trusted
attestor over a bound statement that includes:

- The withdrawal digest
- `keccak256(pqPublicKey)`
- `keccak256(pqSignature)`
- Algorithm identifier `keccak256("ATTESTED-ML-DSA-65")`
- Verifier address, chain ID, and deadline

The EVM does not execute ML-DSA-65 arithmetic. The security depends on the attestor
having correctly run FIPS 204-compatible verification off-chain before signing.

### Interface

```solidity
interface IPQCVerifier {
    function algorithmId() external view returns (bytes32);
    function verify(
        bytes32 digest,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool);
}
```

A future verifier implementing this interface can be substituted through the vault's
timelocked governance flow without redeploying the vault.

### ML-DSA-65 parameters (FIPS 204)

| Parameter           | Value                  |
| ------------------- | ---------------------- |
| Public key size     | 1952 bytes             |
| Signature size      | 3309 bytes             |
| Security category   | NIST Level 3           |
| Ring dimension n    | 256                    |
| Modulus q           | 8,380,417              |
| Inner algorithm     | Lattice / MLWE + MSIS  |

ML-DSA-65 verification involves expanding a matrix A from a seed, reconstructing a
hint polynomial, computing a verifier-side challenge hash, and checking polynomial norm
bounds. This arithmetic is constraint-heavy in any ZK circuit system.

### Trust gap

`updateAttestor` on `AttestationPQCVerifier` is immediate and owner-controlled. The
vault's two-day verifier-swap timelock does not cover attestor rotation inside an
already-configured verifier. Operators must monitor `AttestorUpdated` events. This
asymmetry is documented in `docs/Attestation_Verifier.md` and cannot be closed without
graduating to a verifier that does not depend on an operational attestor.

---

## Comparison Matrix

| Dimension              | Path 1 Attestation | RISC Zero zkVM | SP1 zkVM | Noir | Circom/snarkjs | Native precompile | Wait-and-monitor |
| ---------------------- | :----------------: | :------------: | :------: | :--: | :------------: | :---------------: | :--------------: |
| Implemented today      | ✅                 | ❌             | ❌       | ❌   | ❌             | ❌                | ✅ (status quo)  |
| On-chain ML-DSA verify | ❌                 | ✓ (if built)   | ✓        | ✓    | ✓              | ✓                 | ❌               |
| Trusted off-chain key  | ✅ (attestor)      | Prover only    | Prover   | None | Trusted setup  | None              | ✅ (attestor)    |
| Audited ML-DSA circuit | N/A                | ❌             | ❌       | ❌   | ❌             | N/A               | N/A              |
| Practical today        | ✅                 | 🔶 proto       | 🔶 proto | 🔶   | 🔶             | ❌                | ✅               |

---

## Option 1 — Current Trusted Attestation Path (Path 1, reference baseline)

### What would be proven / verified

The EVM verifies that the configured attestor's EIP-712 signature is valid over the
bound statement. It does not independently verify ML-DSA arithmetic.

### Public inputs (on-chain)

- Withdrawal digest
- Hash of PQ public key
- Hash of PQ signature
- Algorithm identifier
- Attestor signature
- Verifier address, chain ID, deadline

### Trust assumptions

- The attestor correctly implemented FIPS 204 ML-DSA-65 off-chain.
- The attestor key is not compromised.
- The attestor owner does not rotate to a malicious attestor.
- The attestation service is available when withdrawals are needed.

### Implementation complexity

Already implemented. No additional work required to use it.

### Prover cost

Off-chain: one ML-DSA-65 verification per withdrawal (fast, ~1ms on a modern CPU
using `@noble/post-quantum`). One ECDSA signing operation.

### Verifier gas cost

Roughly 30,000–60,000 gas for ECDSA ecrecover + keccak256 operations in
`AttestationPQCVerifier.verify`.

### Audit risk

The contract is small and auditable. The attestor service code, key management, and
operational deployment are outside the smart contract surface and require separate
review.

### Developer experience

Good. The full flow is working in this repository with CLI tooling.

### Maturity

Implemented. Not audited. Testnet/local prototype.

### Likely blockers

The fundamental limitation is the attestor trust gap. It cannot be closed within
Path 1. Any deployment that requires trustless PQ verification must graduate beyond
this path.

### Recommended next step

Use as the baseline for further prototype work. Monitor `AttestorUpdated` events
in any deployment. Document the attestor rotation gap clearly in user-facing copy.

---

## Option 2 — RISC Zero zkVM

### What would be proven / verified

"I have a valid ML-DSA-65 signature over this digest for this public key" — proven by
executing ML-DSA-65 verification in a RISC-V guest program inside the RISC Zero zkVM.
The STARK proof (or its Groth16 or PLONK wrapper) is verified on-chain by a RISC Zero
verifier contract.

The input/output journal records the withdrawal digest, public key hash, and signature
hash. An `IPQCVerifier` implementation calls the RISC Zero on-chain verifier and
checks that the journal matches the expected inputs.

### Public inputs

- Withdrawal digest (EIP-712 hash)
- Image ID (hash of the guest RISC-V program)
- Journal: `keccak256(pqPublicKey)`, `keccak256(pqSignature)`, result flag

### Trust assumptions

- Correctness of the RISC Zero STARK prover and verifier.
- Correctness of the ML-DSA-65 guest program (the circuit is the Rust/WASM code
  running inside the zkVM — it must be audited).
- RISC Zero's proving service (Bonsai) or a self-hosted prover; self-hosting is an
  operational dependency.
- The on-chain RISC Zero verifier contract (maintained by RISC Zero).
- No per-circuit trusted setup (STARKs are transparent).

The attestor key dependency is eliminated. Prover availability is the new operational
dependency.

### Implementation complexity

**High.** Required steps:

1. Write a Rust RISC-V guest program that calls a conforming ML-DSA-65 verify
   implementation (e.g. `ml-kem` / a FIPS 204 crate).
2. Pin the image ID (the hash of the compiled guest) — changing the implementation
   invalidates the image ID.
3. Deploy or integrate a RISC Zero verifier contract.
4. Write an `IPQCVerifier` contract that calls the verifier, checks the image ID, and
   validates the journal.
5. Write extensive test coverage against NIST ACVP vectors from inside the guest.
6. Independently audit both the guest program and the verifier contract.

There is no audited ML-DSA-65 RISC Zero guest in the public ecosystem as of mid-2026.
Building one from scratch is a significant engineering effort.

### Prover cost

Highly dependent on circuit complexity. ML-DSA-65 verification involves hundreds of
polynomial multiplications, NTT operations, and hash calls.

Estimated guest cycle count: **50M–500M RISC-V cycles** (rough order-of-magnitude;
no public benchmark for ML-DSA-65 in RISC Zero exists as of this writing). At RISC
Zero Bonsai public pricing (roughly $0.001–0.01 per 1M cycles), this implies
**$0.05–$5 per proof** or higher before any optimization. Proving time on typical
cloud hardware: likely 30 seconds to several minutes. Self-hosting is feasible but
adds infrastructure cost.

These are estimates. Actual costs require profiling with a real guest implementation.

### Verifier gas cost

On-chain RISC Zero Groth16 verification: approximately **200,000–300,000 gas**.
This is in addition to existing vault operation gas.

### Audit risk

**High.** Two new auditable components: the RISC-V guest program and the on-chain
`IPQCVerifier` wrapper. The guest program must be a correct FIPS 204 implementation,
must not contain side-channel vulnerabilities that affect proof soundness, and must
produce a journal that the contract interprets correctly. The image ID must be pinned
and verified independently. RISC Zero itself would need a security review from the
project's perspective, in addition to their own published audits.

### Developer experience

**Moderate.** Rust experience required for the guest. The RISC Zero SDK is reasonably
documented. Iterating on guest performance is slow (compilation + proof generation
cycles). The JavaScript/TypeScript toolchain in this repo would need to interact with
a prover service or a local prover binary.

### Maturity

RISC Zero mainnet verifier contracts are deployed and have been used in production
applications. The proving system itself is mature. An ML-DSA-65 guest is a new
application of the technology; no reference implementation exists.

### Likely blockers

- No audited ML-DSA-65 RISC Zero guest exists.
- Prover cost and latency may be unacceptable for interactive withdrawals.
- Operational dependency on a prover service.
- Significant audit scope increase.

### Recommended next step

Benchmark a prototype guest (ML-DSA-65 verify in Rust in the RISC Zero guest) against
the NIST ACVP vectors from `test/fixtures/mldsa/nist-cavp/`. Measure cycle count and
proof time before committing to this path.

---

## Option 3 — SP1 zkVM (Succinct)

### What would be proven / verified

Same goal as RISC Zero: execute ML-DSA-65 verification in a RISC-V guest, produce a
succinct proof verified on-chain. SP1 uses Plonky3-based recursion and supports both
a Groth16 wrapper and a native STARK verifier.

### Public inputs

- Withdrawal digest
- `keccak256(pqPublicKey)`
- `keccak256(pqSignature)`
- Program verification key (pinned hash of the guest ELF)

### Trust assumptions

- Correctness of the SP1 Plonky3 proving system and recursion.
- Correctness of the ML-DSA-65 guest ELF (same audit requirement as RISC Zero).
- SP1 on-chain verifier contracts (maintained by Succinct).
- Succinct's proving network or self-hosted prover.
- No per-circuit trusted setup for the STARK layer; the Groth16 wrapper uses a
  universal trusted setup.

### Implementation complexity

**High** — similar to RISC Zero. The guest is also Rust/RISC-V. SP1 has slightly
different ergonomics (the `sp1_zkvm` SDK) but the core challenge — writing and auditing
an ML-DSA-65 guest — is the same.

SP1 has a `precompile` system that can accelerate hash function calls (SHA-256,
Keccak-256). ML-DSA-65 internally uses SHAKE-128 and SHAKE-256; SP1 precompile support
for these should be verified before committing to this path.

### Prover cost

Similar order of magnitude to RISC Zero. SP1 claims better performance in some
benchmarks due to Plonky3 recursion efficiency and precompile support, but ML-DSA-65
has not been publicly benchmarked in SP1. Proving time and cost depend on whether SHAKE
precompiles are available.

### Verifier gas cost

SP1 Groth16 on-chain verifier: approximately **250,000–350,000 gas**. STARK-only mode
is more expensive (~2M+ gas) and not practical for mainnet withdrawal verification.

### Audit risk

**High.** Same categories as RISC Zero. SP1 is newer than RISC Zero and has a shorter
published audit history. Additional review of the SP1 verifier contract itself should
be budgeted.

### Developer experience

**Moderate.** SP1 has a well-documented SDK with good Rust tooling. The proving network
(Succinct Prover Network) simplifies infrastructure. Debugging guest programs requires
familiarity with RISC-V and the SP1 cycle model.

### Maturity

SP1 launched its mainnet verifier in 2024–2025 and has seen deployment in production
bridge and coprocessor applications. It is less battle-tested than RISC Zero but
actively developed. An ML-DSA-65 guest is again a new application.

### Likely blockers

- No audited ML-DSA-65 SP1 guest exists.
- SHAKE-128/256 precompile availability needs verification.
- Prover latency for interactive use.
- Newer proving system — less historical security analysis than RISC Zero.

### Recommended next step

If RISC Zero cycle benchmarks are discouraging, run the same ML-DSA-65 guest in SP1
and compare. SP1 may outperform if SHAKE precompiles are available.

---

## Option 4 — Noir (Aztec / Barretenberg)

### What would be proven / verified

A Noir circuit that implements ML-DSA-65 verification. Noir compiles to either ACIR
(for the Barretenberg UltraPlonk/Honk backend) or potentially other backends. The
on-chain verifier is a Solidity contract generated from the Noir circuit.

### Public inputs

- Withdrawal digest (32 bytes)
- Public key (1952 bytes — must be public inputs or committed via Pedersen/Poseidon hash)
- Signature (3309 bytes — same consideration)
- Boolean result

The large public key and signature sizes create a constraint on how inputs are handled.
Hashing them inside the circuit (commitment) and exposing only the hashes as public
inputs reduces proof size but requires that the prover supplies the raw values as
private witnesses.

### Trust assumptions

- Soundness of the Barretenberg UltraPlonk/Honk proving system.
- Correctness of the Noir circuit implementing ML-DSA-65 verify.
- No trusted setup: Barretenberg's Honk backend (default since Noir 0.30+) uses a
  KZG setup over BN254 — this requires a universal trusted setup (e.g. the Aztec
  Powers of Tau or Ethereum KZG ceremony). The circuit-specific setup step is
  eliminated with UltraPlonk ACIR, but the SRS itself is a one-time trust event.
- The generated Solidity verifier contract.

### Implementation complexity

**Very high.** ML-DSA-65 requires implementing in Noir:

- SHAKE-128 and SHAKE-256 (or Keccak-based substitutes; ML-DSA uses them for matrix
  expansion and challenge derivation)
- NTT (Number Theoretic Transform) over Z_8380417
- Polynomial arithmetic in Z_q[X]/(X^256 + 1)
- Infinity and L1 norm checks over polynomial coefficients
- Hint bit decompression

Writing correct lattice arithmetic in a constraint system is a specialist task that
has not been publicly completed for ML-DSA-65 as of mid-2026. Academic prototypes
for Dilithium (the NIST candidate predecessor of ML-DSA) in ZK circuits have been
published but are not production-ready and may not match the FIPS 204 finalized spec.

Constraint count would be very large — potentially tens of millions of constraints —
leading to large proving keys and slow proving.

### Prover cost

**Unknown but likely high.** No public benchmark for ML-DSA-65 in a PLONK-family
system exists. Large constraint counts imply long multi-scalar-multiplication times
during proof generation. Rough estimate: minutes per proof on capable hardware,
possibly comparable to zkVM approaches after optimization.

### Verifier gas cost

Barretenberg Honk/UltraPlonk verifiers: approximately **200,000–400,000 gas** for a
fixed-size circuit. Cost scales with the number of public inputs; handling 1952-byte
public keys and 3309-byte signatures as inputs would require batching and commitment.
Estimated total: likely **300,000–600,000 gas** depending on input handling.

### Audit risk

**Very high.** A novel ML-DSA-65 Noir circuit would be a first-of-its-kind
implementation. It requires circuit-level correctness review against FIPS 204, fuzzing
against NIST ACVP vectors, and cryptographic audit of the constraint encoding.
Under-constrained circuits can be satisfiable with incorrect witnesses — an error here
would allow fraudulent withdrawals that pass the on-chain verifier.

### Developer experience

**Difficult.** Noir is a readable DSL but has limited standard library support for
exotic hash functions (SHAKE). The Barretenberg backend is not written in
TypeScript/JavaScript. Integrating with the Hardhat-based toolchain requires careful
wiring. Noir circuit testing against NIST vectors requires a Noir test harness.

### Maturity

Noir is production-deployed in Aztec's L2. The Barretenberg Honk backend is actively
developed. For *standard* circuits (hash preimages, ECDSA, Merkle proofs), Noir is
mature. For lattice-based PQ cryptography, it is uncharted territory.

### Likely blockers

- No ML-DSA-65 Noir circuit exists or is near completion.
- SHAKE hash function support in Noir is limited; ML-DSA's core hash functions are
  non-standard for ZK systems.
- Constraint count may be prohibitive.
- Novel circuit requires a specialist cryptographic audit.

### Recommended next step

Assess whether SHAKE-128/256 can be efficiently encoded in Noir before investing in
circuit development. If the hash function alone is impractical, Noir is not the right
path for ML-DSA-65.

---

## Option 5 — Circom / snarkjs

### What would be proven / verified

A Circom 2 circuit implementing ML-DSA-65 verification, compiled to R1CS, with a
Groth16 or PLONK proof verified by a Solidity verifier.

### Public inputs

- Withdrawal digest
- Public key hash (committed; raw key as private input)
- Signature hash (committed; raw signature as private input)
- Boolean result

### Trust assumptions

- Soundness of the Groth16 or PLONK proof system over BN254.
- **Groth16 requires a circuit-specific trusted setup ceremony.** Any change to the
  circuit requires a new trusted setup. This is a significant operational and trust
  constraint for a prototype that may change.
- Correctness of the Circom circuit implementing ML-DSA-65.
- The generated Solidity verifier contract.

### Implementation complexity

**Very high** — and the Groth16 trusted setup requirement makes iteration expensive
(each circuit revision needs a new setup, ideally with multi-party contribution). PLONK
avoids circuit-specific setups but still requires a universal SRS.

Circom 2 uses a template system that is harder to compose and debug than Noir for
complex arithmetic. Writing NTT, polynomial multiplication, and SHAKE in Circom is a
significant undertaking. The Circom/snarkjs ecosystem has fewer modern tooling
affordances than Noir or the zkVM approaches.

### Prover cost

Similar in principle to Noir (PLONK) or higher (Groth16 is faster to verify but
slower to generate for large R1CS). Likely comparable to Noir — minutes per proof for
large ML-DSA-65 circuits.

### Verifier gas cost

Groth16 verifier: approximately **200,000–250,000 gas** — the lowest on-chain
verification cost of any proof system listed. This is attractive, but the trusted
setup and implementation complexity costs are significant.

### Audit risk

**Very high.** Same circuit correctness risks as Noir, plus the added risk of Groth16
trusted setup management. The setup ceremony itself requires trust or multi-party
computation to be convincing.

### Developer experience

**Difficult.** Circom is less ergonomic than Noir for complex circuits. snarkjs
integration with TypeScript exists but is not well-maintained for modern Hardhat. The
ecosystem is mature for simpler circuits but under-resourced for novel PQ applications.

### Maturity

Circom/Groth16 is the oldest and most battle-tested proof system in the Ethereum ZK
ecosystem. Groth16 on-chain verification is well-understood. However, for ML-DSA-65,
this maturity applies only to the proof system — not to any lattice circuit that would
need to be built from scratch.

### Likely blockers

- Trusted setup requirement.
- No ML-DSA-65 Circom circuit exists.
- SHAKE hash function implementation in Circom.
- High NTT constraint cost.
- Limited ecosystem momentum toward new complex circuits.

### Recommended next step

Not recommended as a primary path given the trusted setup friction and developer
experience relative to Noir or zkVMs. Could be revisited if Groth16's low on-chain
verification gas becomes a decisive factor.

---

## Option 6 — Native Chain Support / PQ Precompile

### What would be proven / verified

An EVM precompile or opcode added by a chain (L1 or L2) that natively verifies ML-DSA
(or SLH-DSA) at the protocol level. The `IPQCVerifier` implementation simply
calls the precompile address and forwards inputs.

This requires no ZK circuit, no trusted setup, and no prover. It is equivalent in
trust to any other EVM precompile (e.g. `ecrecover` at address 0x01).

### Public inputs

- Withdrawal digest
- ML-DSA-65 public key (1952 bytes)
- ML-DSA-65 signature (3309 bytes)

### Trust assumptions

- Correct implementation in the chain's execution client.
- Protocol-level adoption by the target chain.
- No additional cryptographic assumptions beyond the ML-DSA-65 algorithm itself.

### Implementation complexity

**Near-zero for this repo** once the precompile exists. The `IPQCVerifier`
implementation becomes a thin wrapper. The complexity lives entirely at the protocol
layer.

### Prover cost

None. Verification is native execution.

### Verifier gas cost

Likely **5,000–50,000 gas** — comparable to existing hash precompiles, if the chain
optimizes ML-DSA verification in native code. Significantly cheaper than any ZK path.

### Audit risk

**Low for the verifier contract** (a thin wrapper). High for the precompile itself —
but that risk is borne by the chain's security model and review process, not this
project.

### Developer experience

**Excellent** once the precompile is available. The IPQCVerifier wrapper would be
trivial to implement and test.

### Maturity

**Not available.** As of mid-2026, no Ethereum L1 or major EVM-compatible L2 has
deployed an ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) precompile. Discussions exist
in the Ethereum research community around EVM precompile additions for PQ algorithms,
but no EIP has been finalized for ML-DSA. Some L2 teams (e.g. zkSync Era, Polygon)
have explored custom precompiles, but none has shipped ML-DSA support.

The NIST standardization of ML-DSA (FIPS 204, August 2024) is a prerequisite for
serious precompile proposals. The ecosystem is in early discussion phase.

### Likely blockers

- No EIP or chain governance proposal for ML-DSA precompile exists.
- Protocol timeline is entirely outside this project's control.
- Likely years away for Ethereum L1.

### Recommended next step

Monitor EVM and L2 precompile discussions. The `IPQCVerifier` interface is already
designed for this path — once a precompile ships on a target chain, implementation
would be minimal.

---

## Option 7 — Wait-and-Monitor (Status Quo)

### What this means

Continue operating on Path 1 (trusted attestation). Establish concrete trigger
conditions that would justify beginning ZK prototype work, and monitor the ZK ecosystem
for those conditions to be met.

### Trust assumptions

Same as Path 1. The attestor trust gap persists. This is honest and documented.

### Implementation complexity

Zero additional implementation.

### Prover cost

Same as Path 1 (negligible, off-chain ECDSA signing).

### Verifier gas cost

Same as Path 1 (~30,000–60,000 gas in `AttestationPQCVerifier`).

### Audit risk

Same as Path 1. No new audit surface.

### Maturity

N/A — this is not a technical option but a timing decision.

### Likely blockers

The vault remains in the trusted-attestation model. For any deployment that must claim
meaningful PQ security beyond the attestor trust model, this is not a tenable
long-term position.

### Recommended next step

Define explicit trigger conditions. Examples:

- A public audited ML-DSA-65 ZK circuit (Noir, Circom, or zkVM guest) is available.
- The gas cost for ZK verification on the target chain falls below a threshold (e.g.
  300,000 gas inclusive of vault operation).
- A benchmark shows end-to-end proving time under 60 seconds for an ML-DSA-65 proof.
- A target L2 ships an ML-DSA precompile.

If none of these conditions are met within a monitoring window, the prototype remains
at Path 1.

---

## ML-DSA-65 ZK Complexity Notes

To understand the blockers for ZK approaches, it is useful to summarize what
ML-DSA-65 verification requires a ZK system to compute:

1. **Matrix expansion (ExpandA):** generate matrix A ∈ Z_q^{k×l} from seed rho using
   SHAKE-128. For ML-DSA-65: k=6, l=5, yielding 30 NTT-domain polynomials.

2. **Signature parsing:** decode z (l polynomials) and hint h from the signature.

3. **Challenge reconstruction (SampleInDom):** hash the commitment μ and signature
   hint using SHAKE-256 to recover challenge polynomial c.

4. **Verification equation:** compute Az − ct1 · 2^d and check it matches w1' derived
   from the hint. Involves k+l NTT forward/inverse transforms.

5. **Norm checks:** verify ||z||∞ < γ1 − β and that h has the correct weight.

The key constraints:

- **SHAKE-128/256** is not a standard ZK-friendly hash function. Most ZK systems use
  Poseidon, Pedersen, or Keccak. An efficient SHAKE implementation in a constraint
  system requires either a custom gate (circuit-specific) or accepting high constraint
  counts.
- **NTT over Z_q with q = 8,380,417** requires modular arithmetic in a prime field
  that does not naturally embed in BN254's scalar field (order ~254-bit). Mixed-field
  arithmetic adds overhead.
- **Polynomial coefficients** are 23-bit values (since q < 2^23). Encoding them
  efficiently in a ZK circuit field element is possible but verbose.
- **Total constraint estimate:** rough academic estimates for Dilithium-3 (the NIST
  round-3 predecessor) range from 10 million to 100 million R1CS constraints for a
  Groth16 circuit. FIPS 204 ML-DSA-65 uses the same core algorithm. This places
  proving time in the range of tens of seconds to several minutes on capable hardware
  even before optimization.

zkVM approaches (RISC Zero, SP1) replace constraint-by-constraint encoding with cycle
counts. They can run an existing Rust ML-DSA-65 implementation but pay cycle costs for
all the SHAKE calls and polynomial arithmetic, which is why cycle estimates above are
in the 50M–500M range.

---

## Recommendation

### What not to build yet

**Do not build any of the following in the near term:**

- A Circom ML-DSA-65 circuit. The trusted setup friction, SHAKE encoding cost, and
  tooling limitations make this the weakest option relative to effort.
- A Noir ML-DSA-65 circuit from scratch without first validating that SHAKE-128/256
  can be efficiently encoded in the target backend.
- A production-grade ZK verifier contract. No ML-DSA-65 ZK circuit has been publicly
  audited as of mid-2026. Deploying an unaudited ZK verifier for a custody-adjacent
  application would not meaningfully improve on the honest trusted-attestation model,
  and would add significant audit risk.
- Any implementation that relaxes the "not production custody" language on this
  repository. The vault is a research prototype regardless of which verifier path is
  implemented.

### What to prototype next

**Recommended next prototyping step: zkVM cycle benchmark (RISC Zero or SP1).**

The lowest-friction path to evaluating whether ZK is practical for ML-DSA-65 is to
write a minimal Rust guest program that calls a FIPS 204-compatible ML-DSA-65 verify
function and run it in RISC Zero or SP1 in developer mode. The goal is to measure:

- Guest cycle count for one ML-DSA-65 verification.
- End-to-end proof generation time on accessible hardware.
- On-chain verifier gas cost (using the test verifier on a local network).

This prototype requires no new Solidity contracts, no circuit design, and no trusted
setup. It produces a concrete benchmark that can justify or rule out the ZK path before
significant engineering investment.

If the cycle count is below ~100M and proving time is under 60 seconds, a full guest
implementation and `IPQCVerifier` wrapper become worth scoping. If the cycle count
exceeds ~500M or proving time is several minutes, the current attestation path may be
more honest than an impractical ZK verifier.

The NIST ACVP vectors at `test/fixtures/mldsa/nist-cavp/` provide a ready-made test
harness for the guest program.

### What would justify moving beyond the trusted attestation path

Moving the vault from Path 1 to a ZK-backed verifier should be justified by all of the
following:

1. A working ML-DSA-65 ZK guest or circuit that passes all NIST ACVP ML-DSA-65 sigVer
   vectors.
2. An independent security review of the circuit or guest program.
3. An independent review of the on-chain `IPQCVerifier` wrapper.
4. Proving time and cost that are operationally acceptable for the intended withdrawal
   frequency.
5. A clear statement of what trust is removed (the attestor key) versus what trust
   remains (the prover, the proving system, the circuit/guest correctness).
6. Updated `Security_Assumptions.md`, `Verifier_Roadmap.md`, and README to reflect
   the new verifier's trust model accurately — including what it still does not prove.

A ZK verifier does not make the vault production custody. It reduces one specific
trust assumption (the attestor operational key) at the cost of new trust in the proving
system and circuit correctness.

### How this affects WalletWall app copy

Until a ZK or native verifier passes the criteria above, all user-facing and
developer-facing copy for WalletWall Vault should:

- Continue to state that ML-DSA-65 verification is **not performed on-chain**.
- Continue to identify the attestor as a **central trust boundary**.
- Continue to use language like "**research prototype**", "**not production custody**",
  "**trusted attestation path**", "**not trustless today**".
- Not use language like "ZK-secured", "trustless", "quantum-safe", or
  "on-chain PQ verification" until a qualifying verifier is implemented, audited,
  and deployed.
- If and when a ZK verifier is deployed, clearly state what trust remains: the proving
  system, the circuit/guest correctness, and (for PLONK/Groth16) any trusted setup
  assumptions.

The `docs/Verifier_Roadmap.md` "Path 2 — ZK-proof verifier" entry already carries the
correct conservative framing ("not implemented, preferred long-term software path").
This feasibility document is additive context for future maintainers evaluating the
effort required to implement Path 2.

---

## Summary Table

| Option                    | Trust removed         | New trust introduced         | Implementation effort | Recommended action                        |
| ------------------------- | --------------------- | ---------------------------- | :-------------------: | ----------------------------------------- |
| Path 1 Attestation        | —                     | Attestor key + service       | Done                  | Continue; monitor AttestorUpdated events  |
| RISC Zero zkVM            | Attestor key          | Prover service + guest code  | High                  | Benchmark ML-DSA-65 guest cycle count     |
| SP1 zkVM                  | Attestor key          | Prover service + guest code  | High                  | Benchmark if RISC Zero disappoints        |
| Noir                      | Attestor key          | KZG setup + circuit code     | Very high             | Validate SHAKE encoding before committing |
| Circom/snarkjs            | Attestor key          | Groth16 setup + circuit code | Very high             | Not recommended as primary path           |
| Native precompile         | Attestor key + prover | Chain security only          | Near-zero (wrapper)   | Monitor EIP/L2 proposals                  |
| Wait-and-monitor          | —                     | —                            | None                  | Set trigger conditions; check quarterly   |

**Recommended order of evaluation:**
1. Define trigger conditions for ZK prototype (wait-and-monitor).
2. Run an ML-DSA-65 zkVM benchmark (RISC Zero or SP1).
3. Based on benchmark, decide whether to pursue a full guest + verifier prototype.
4. Revisit Noir if zkVM latency is unacceptable and SHAKE precompiles are available.
5. Monitor native precompile developments in parallel.
6. Do not build Circom/Groth16 for this use case unless all other paths fail.

---

## References

- FIPS 204 ML-DSA: <https://csrc.nist.gov/pubs/fips/204/final>
- NIST ACVP ML-DSA sigVer vectors: `test/fixtures/mldsa/nist-cavp/`
- RISC Zero documentation: <https://dev.risczero.com/>
- SP1 documentation: <https://docs.succinct.xyz/>
- Noir documentation: <https://noir-lang.org/>
- Circom documentation: <https://docs.circom.io/>
- `docs/Verifier_Roadmap.md` — current Path 0–4 overview
- `docs/Security_Assumptions.md` — current trust model
- `docs/Attestation_Verifier.md` — attestor rotation delay asymmetry
