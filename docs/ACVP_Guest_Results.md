# NIST ACVP ML-DSA-65 — SP1 Guest Differential Conformance

> ⚠️ **Research prototype. Not audited. Not production custody. Not a complete
> on-chain verifier.** Passing the vectors described here does **not** make the
> WalletWall Vault production-ready, mainnet-ready, custody-safe, or "quantum-proof".
> It is one conformance signal for the ML-DSA-65 verification compiled into the SP1
> ACVP conformance program. Read [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md),
> [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md), and `docs/Security_Assumptions.md`
> first. The SP1 execute-mode run described here is not part of CI.

## What this adds (issue #29)

PR #18 added official NIST ACVP ML-DSA-65 sigVer vectors at the TypeScript/Hardhat
layer. PR #27 added a gated end-to-end test (`RUN_SP1_E2E=1`) that cross-checks a
**TypeScript-produced** signature against the Rust `ml-dsa` guest — a differential
test between two implementations.

The remaining gap that issue #29 closes: the official ACVP vectors had never been
fed **through an SP1 program itself**. Agreement between the TS and Rust impls does
not, on its own, establish that either matches FIPS 204 — both could share a bug.
Routing the standard's own vectors through the program checks it against the
specification, not against a sibling implementation.

## Two programs: withdrawal and ACVP conformance

`zkvm/guest` builds two SP1 programs, each with its own entry point, ELF and program vkey:

| Program              | Source                             | Accepting relation                                                                                                                                                                                                  | Journal                                                                                     |
| -------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `mldsa65-withdrawal` | `zkvm/guest/src/bin/withdrawal.rs` | ML-DSA-65 verifies over exactly the committed 32-byte `withdrawal_digest`, under the empty FIPS 204 context. The input is exactly `withdrawal_digest`, `public_key`, `signature`, `chain_id`, `verifier_address`. | 160 bytes: the digest, keccak256 of the public key and signature, chain id, verifier address |
| `mldsa65-acvp`       | `zkvm/guest/src/bin/acvp.rs`       | ML-DSA-65 verifies over an arbitrary `message` under a `context` of at most 255 bytes (FIPS 204 external interface, pure signing).                                                                                 | 128 bytes: keccak256 of the public key, message, context and signature                      |

A `ZKMLDSAVerifier` pins the withdrawal program's vkey (`mldsa65-host vkey`). The ACVP
program's vkey (`mldsa65-host acvp-vkey`) is a different value and must never be pinned: its
relation is not a withdrawal authorization.

### Why the programs are separate

The ACVP sigVer group used here verifies arbitrary-length messages, each with an explicit
domain-separation context. An earlier version of this document described routing those
vectors through the withdrawal guest itself, via optional `message` and `context` fields in its
input: the guest verified `message` (or the digest, when `message` was empty) under `context`,
and always committed `withdrawal_digest`. Stdin is prover-controlled, so the committed digest
was not bound to the message the signature was verified over; that relation was adjudicated
NOT_BOUND. The vectors now run in the separate ACVP program, and the withdrawal program has no
message, context or mode input.

Scope of that correction:

- No deployment record in this repository uses `ZKMLDSAVerifier` or pins a program vkey; the
  Sepolia deployment uses `MockMLDSAVerifier`. This change deploys nothing.
- The withdrawal relation is checked by native relation tests (`zkvm/relation-tests`) and by
  Solidity consumer tests against a program-bound mock SP1 verifier, not by a real proof and not
  on-chain.
- Both program vkeys must be re-extracted from a reproducible build before any deployment.
- It does not establish the provenance of the SP1 verifier gateway a `ZKMLDSAVerifier` forwards
  to, which remains NOT ESTABLISHED, and it does not satisfy SD-11 Gen-1 provenance (see
  `prototype/vnext-kernel/SD11_VERIFIER_ADMISSION_ADJUDICATION.md`).

## The test

`test/ZKAcvpGuest.e2e.test.ts`, gated behind `RUN_SP1_E2E=1` like
`test/ZKRealProof.e2e.test.ts`. It reuses the existing fixture
`test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json` (no new vectors). For each vector it
builds an ACVP `inputs.json` carrying the vector's `publicKey`, `message`, `context` and
`signature`, and runs the ACVP program with `mldsa65-host acvp-execute` in SP1 **execute** mode
(no proving, no prover credentials). The exit status is the conformance signal:

- **Valid vectors** (`testPassed: true`) — the program must accept (exit 0), report a non-zero
  cycle count, and commit keccak256 of the vector's key, message, context and signature.
- **Invalid vectors** (`testPassed: false`) — the program must revert (non-zero exit).
- **Tampered signature** — a genuine valid vector with its first signature byte flipped must
  revert. This satisfies the issue's explicit negative-case requirement.

It also checks the separation: `vkey` and `acvp-vkey` report different vkeys, the withdrawal
`execute` path refuses an inputs file carrying `message`/`context`, and the withdrawal program
rejects each valid vector's signature presented as a withdrawal authorization.

The fixture currently contains 3 valid (tcId 31, 35, 37 — including non-empty
contexts of 183 B and 133 B, exercising context separation) and 3 invalid (tcId 32,
33, 34) ACVP test cases. The test sweeps all of them plus the tampered case.

In normal CI, without the SP1 toolchain, `zkvm/relation-tests` runs the same vectors through the
ACVP program's source compiled for the host and checks that the withdrawal program rejects them as
withdrawal authorizations. That is native execution of the program sources, not SP1 execution.

## How to run

Requires the SP1 toolchain (`sp1up`, Linux/WSL2-first) and a built host binary:

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKAcvpGuest.e2e.test.ts
```

Without `RUN_SP1_E2E=1` the whole suite is skipped (`describe.skip`), so the normal
`npx hardhat test` run stays fast and toolchain-free.

## What this proves

- The ML-DSA-65 verification compiled into the SP1 ACVP program accepts the official NIST
  ACVP `testPassed: true` sigVer vectors (external/pure), including non-empty
  contexts, and rejects the `testPassed: false` vectors and a tampered signature —
  evaluated in SP1 execute mode.
- Both programs compile the same pinned `ml-dsa` crate; the withdrawal program calls it over the
  32-byte digest under the empty context. These results are evidence about that crate and the ACVP
  program, not a separate check of the withdrawal program binary.
- Combined with PR #27, there is both a TS↔Rust differential check and a direct check
  against the standard's own vectors.

## What this does NOT prove

- **Not full ACVP conformance.** This is the 6-vector subset committed in the repo,
  not the complete NIST ACVP sigVer (or keyGen / sigGen) vector sets.
- **Not an audit.** Neither the programs, the host, the `ml-dsa` crate, nor the SP1
  verifier contract has been independently reviewed.
- **Not a proof-system claim.** Execute mode emulates the program; it does not generate
  or verify a Groth16/STARK proof and says nothing about prover/verifier soundness.
- **Not an on-chain verification claim.** Nothing here is executed on-chain; the
  EVM still does not run ML-DSA-65. The deployed path remains the trusted-attestation
  model described in `docs/Attestation_Verifier.md`.
- **Not production custody / not mainnet-ready / not "quantum-proof".** This is
  research-prototype conformance evidence only.

## References

- FIPS 204 ML-DSA: <https://csrc.nist.gov/pubs/fips/204/final>
- NIST ACVP sigVer vectors (source): `test/fixtures/mldsa/nist-cavp/README.md`
- Gated TS↔Rust differential test: `test/ZKRealProof.e2e.test.ts`
- Native relation tests for both programs: `zkvm/relation-tests/`
- Build/run details: [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md)
