# NIST ACVP ML-DSA-65 — SP1 Guest Differential Conformance

> ⚠️ **Research prototype. Not audited. Not production custody. Not a complete
> on-chain verifier.** Passing the vectors described here does **not** make the
> WalletWall Vault production-ready, mainnet-ready, custody-safe, or "quantum-proof".
> It is one conformance signal for the ML-DSA-65 verification that runs inside the
> SP1 guest. Read [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md),
> [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md), and `docs/Security_Assumptions.md`
> first. None of this runs in CI.

## What this adds (issue #29)

PR #18 added official NIST ACVP ML-DSA-65 sigVer vectors at the TypeScript/Hardhat
layer. PR #27 added a gated end-to-end test (`RUN_SP1_E2E=1`) that cross-checks a
**TypeScript-produced** signature against the Rust `ml-dsa` guest — a differential
test between two implementations.

The remaining gap that issue #29 closes: the official ACVP vectors had never been
fed **through the SP1 guest itself**. Agreement between the TS and Rust impls does
not, on its own, establish that either matches FIPS 204 — both could share a bug.
Routing the standard's own vectors through the guest checks it against the
specification, not against a sibling implementation.

## How the vectors reach the guest

The production withdrawal guest verifies a fixed 32-byte withdrawal digest under an
empty FIPS 204 context. The ACVP sigVer group used here is the **external** interface
with **pure** (no pre-hash) signing, over arbitrary-length messages each carrying an
explicit domain-separation **context**. To verify those faithfully, the guest must
take the raw message and the context — not a 32-byte digest.

`GuestInputs` (in `zkvm/guest/src/main.rs` and mirrored in `zkvm/host/src/main.rs`)
therefore gained two fields:

| Field     | Withdrawal path        | ACVP conformance path                   |
| --------- | ---------------------- | --------------------------------------- |
| `message` | empty                  | the vector's raw message bytes          |
| `context` | empty                  | the vector's `context` bytes (may be 0) |

The guest selects the signed message as `withdrawal_digest` when `message` is empty,
otherwise `message`, and always verifies via FIPS 204 Algorithm 3
(`VerifyingKey::verify_with_context(M, ctx, sig)`). When both new fields are empty
this is **identical** to the previous behavior — verifying the 32-byte digest under
the empty context — so the withdrawal path and its journal commitments are unchanged.
The `inputs.json` fields are optional and default to empty (`#[serde(default)]`), so
existing withdrawal inputs files keep working untouched.

> Note: changing the guest ELF changes the program vKey. Re-extract it
> (`mldsa65-host vkey`) before any deploy; the mock-verifier CI path is unaffected.

## The test

`test/ZKAcvpGuest.e2e.test.ts`, gated behind `RUN_SP1_E2E=1` with the same
`runHostExecute` pattern as `test/ZKRealProof.e2e.test.ts`. It reuses the existing
fixture `test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json` (no new vectors).
For each vector it builds an `inputs.json` carrying the vector's `pk`, `message`,
`context`, and `signature`, binds `withdrawalDigest = keccak256(message)` for the
journal, and runs the guest in SP1 **execute** mode (no proving, no prover
credentials). The exit status is the conformance signal:

- **Valid vectors** (`testPassed: true`) — the guest must accept (exit 0) and report
  a non-zero cycle count and well-formed public values.
- **Invalid vectors** (`testPassed: false`) — the guest must revert (non-zero exit).
- **Tampered signature** — a genuine valid vector with its first signature byte
  flipped must revert. This satisfies the issue's explicit negative-case requirement.

The fixture currently contains 3 valid (tcId 31, 35, 37 — including non-empty
contexts of 183 B and 133 B, exercising context separation) and 3 invalid (tcId 32,
33, 34) ACVP test cases. The test sweeps all of them plus the tampered case.

## How to run

Requires the SP1 toolchain (`sp1up`, Linux/WSL2-first) and a built host binary:

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKAcvpGuest.e2e.test.ts
```

Without `RUN_SP1_E2E=1` the whole suite is skipped (`describe.skip`), so the normal
`npx hardhat test` run stays fast and toolchain-free.

## What this proves

- The ML-DSA-65 verification compiled into the SP1 guest accepts the official NIST
  ACVP `testPassed: true` sigVer vectors (external/pure), including non-empty
  contexts, and rejects the `testPassed: false` vectors and a tampered signature —
  evaluated through the real guest in SP1 execute mode.
- Combined with PR #27, the guest now has both a TS↔Rust differential check and a
  direct check against the standard's own vectors.

## What this does NOT prove

- **Not full ACVP conformance.** This is the 6-vector subset committed in the repo,
  not the complete NIST ACVP sigVer (or keyGen / sigGen) vector sets.
- **Not an audit.** Neither the guest, the host, the `ml-dsa` crate, nor the SP1
  verifier contract has been independently reviewed.
- **Not a proof-system claim.** Execute mode emulates the guest; it does not generate
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
- Build/run details: [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md)
