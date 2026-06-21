# SP1 Smoke Lane

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> The SP1/ZK path is a scaffold. There is **no production ZK verification**, and the
> active testnet verifier is the **mock** path, not on-chain ML-DSA verification. See
> [ZK_Verifier_Production.md](ZK_Verifier_Production.md) and [Verifier_Roadmap.md](Verifier_Roadmap.md).

This document describes the reproducible SP1/ZK lanes, from the cheapest CI check to the
gated, toolchain-heavy proving path. The goal is a deterministic "is the lane wired
correctly?" smoke that runs in CI **without** the SP1 toolchain, while keeping expensive
proving and end-to-end differential tests behind an explicit env flag.

## Three lanes

| Lane | Command | Needs SP1 toolchain? | Runs in CI? | What it does |
| --- | --- | --- | --- | --- |
| **Normal CI** | `npm run compile` · `npm test` · `npm run sp1:smoke` · `cargo check` (guest) · `cargo metadata --locked` (host lockfile) | No | Yes | Compiles the guest, validates the host lockfile, and runs the mock-backed Solidity ZK tests plus the pure smoke check below. |
| **Smoke** | `npm run sp1:smoke` | Optional | Yes (pure part) | Always: derives the guest journal for a fixture and asserts its shape/decoding (no proving). Additionally, **if** a built `mldsa65-host` binary is present, runs the guest in SP1 **execute** mode and checks the host's journal matches. |
| **Gated e2e / proving** | `RUN_SP1_E2E=1 npx hardhat test test/ZKRealProof.e2e.test.ts` · `… test/ZKAcvpGuest.e2e.test.ts` · `cargo run … -- prove inputs.json` | Yes | No | Real guest execution / Groth16 proof generation and TS↔guest + NIST ACVP differential conformance. See [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md). |

## Smoke lane details (`npm run sp1:smoke`)

Source: [`scripts/sp1-smoke.ts`](../scripts/sp1-smoke.ts), tested by
[`test/SP1Smoke.test.ts`](../test/SP1Smoke.test.ts).

1. **Pure deterministic core (always, no toolchain).** Loads the committed valid ML-DSA-65
   fixture (`test/fixtures/mldsa/library-generated/`), derives the guest **journal** (the
   public values: `withdrawalDigest`, `keccak256(publicKey)`, `keccak256(signature)`,
   `chainId`, `verifierAddress`) via `ProverClient.encodePublicValues`, and asserts it is a
   well-formed 160-byte (5×32) encoding that decodes back to the expected fields. This pins
   the TypeScript ↔ Rust-guest journal contract — the same encoding `encodeProof` wraps a
   real proof around — without proving anything.
2. **Execute-only step (optional, toolchain-gated by binary presence).** If `SP1_HOST_BIN`
   is set, or `zkvm/host/target/release/mldsa65-host` exists, the smoke runs
   `mldsa65-host execute` on the fixture (SP1 **execute** mode — no proof) and asserts the
   host's emitted public values equal the expected journal. To enable locally:

   ```bash
   cargo build --release --manifest-path zkvm/host/Cargo.toml
   npm run sp1:smoke   # now also runs the execute-only differential
   ```

The command prints a deterministic JSON summary and exits non-zero on any mismatch.

## What is proven vs executed vs only encoded

| Claim | Smoke (pure) | Smoke (+execute) | Gated e2e / prove |
| --- | --- | --- | --- |
| Journal encoding is well-formed & deterministic | ✅ | ✅ | ✅ |
| Rust guest commits the same journal for a valid signature | — | ✅ (execute) | ✅ |
| Guest **rejects** tampered/invalid signatures | — | — | ✅ |
| NIST ACVP vectors pass through the guest | — | — | ✅ (subset) |
| A real Groth16 **proof** is generated and verifies | — | — | ✅ |
| On-chain ML-DSA verification | ❌ never (mock path on-chain) | ❌ | ❌ |
| Production custody / mainnet fund flow | ❌ | ❌ | ❌ |

"Executed" means the guest ran in SP1 execute mode (cycle-counted, no proof). "Proven" means
a succinct proof was generated. The smoke lane never proves.

## Requirements

- **Pure smoke + normal CI:** Node 20 + `npm ci`. No Rust, no SP1.
- **Execute-only smoke:** the SP1 toolchain (`curl -L https://sp1.succinct.xyz | bash && sp1up`;
  Linux-first, use WSL2 on Windows) and a built `mldsa65-host`.
- **Gated e2e / proving:** as above, plus a configured prover (local CPU/GPU or the Succinct
  Prover Network via `SP1_PROVER` / `NETWORK_PRIVATE_KEY`) for `prove`.

## Boundary

- This lane does **not** establish production ZK verification, gas figures, or full FIPS 204
  conformance. The committed ACVP set is a subset (see [ACVP_Guest_Results.md](ACVP_Guest_Results.md)).
- The active testnet verifier remains the **mock** path; on-chain ML-DSA verification is not
  claimed. A real SP1 verifier deployment is described, not shipped, in
  [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md) and [ZK_Verifier_Production.md](ZK_Verifier_Production.md).
- Research prototype — not audited, testnet/local only, no real funds, not "quantum-proof".
