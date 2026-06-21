# ZK Prover Runbook (SP1 ML-DSA-65)

> ⚠️ **Research prototype. Not audited. Do not use real funds.** This runbook wires
> a *real* SP1 prover to the existing `ZKMLDSAVerifier` scaffold. It does not make
> the vault production custody and does not, by itself, establish NIST conformance.
> Read [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md) and
> [Security_Assumptions.md](Security_Assumptions.md) first.

This is the off-chain half that was missing from the ZK path: tooling to compile the
guest, run the feasibility cycle benchmark, extract the real program verification key,
and generate a real Groth16 proof for on-chain verification. The default test/CI path
still uses `MockSP1Verifier` and a mock vKey — none of this runs in CI.

## Components

- `zkvm/guest/` — the SP1 RISC-V guest that verifies ML-DSA-65 (pinned crates).
- `zkvm/host/` — the SP1 host/prover (`mldsa65-host`), with `execute`, `vkey`, and
  `prove` subcommands. **Not** part of CI; depends on the SP1 toolchain.
- `scripts/prover-client.ts` — `ProverClient.generateProof()` shells out to the host
  and reuses `encodeProof()`; `encodeProof()` remains the mock/encode-only path.
- `test/ZKRealProof.e2e.test.ts` — gated end-to-end TS↔Rust differential test
  (`RUN_SP1_E2E=1`).
- `test/ZKAcvpGuest.e2e.test.ts` — gated NIST ACVP differential-conformance test
  that routes the official sigVer vectors through the guest (`RUN_SP1_E2E=1`). See
  [ACVP_Guest_Results.md](ACVP_Guest_Results.md).
- `scripts/sp1-smoke.ts` — the cheap, deterministic **smoke lane** (`npm run sp1:smoke`).
  Runs in CI with no toolchain (journal-encoding check) and optionally runs the guest in
  execute mode if a host binary is built. See [SP1_Smoke_Lane.md](SP1_Smoke_Lane.md) for how
  the normal CI, smoke, and gated e2e lanes relate and what each proves vs only executes.

## Prerequisites

The SP1 toolchain is Linux-first; on Windows use WSL2.

```bash
# Install the SP1 toolchain (provides `cargo prove` and the proving runtime)
curl -L https://sp1.succinct.xyz | bash
sp1up
cargo prove --version
```

Keep the SP1 versions aligned across all three crates: `zkvm/guest` (`sp1-zkvm`),
`zkvm/host` (`sp1-sdk`, `sp1-build`). They are pinned to the same release; bump them
together and re-extract the vKey afterwards.

### Host lock file

`zkvm/host/Cargo.lock` is committed to the repository and **must remain committed**.
Pinning the full SP1 dependency tree is required for production/real-prover readiness
and keeps dependency versions reproducible for every contributor and CI pipeline.
Do not add `Cargo.lock` to `.gitignore`. CI enforces this via the
`zkvm-host-lockfile` job in `.github/workflows/ci.yml`.

If you bump `sp1-sdk` / `sp1-build` versions in `Cargo.toml`, regenerate and
recommit the lockfile:

```bash
# Resolves the dependency graph only; no compile or SP1 toolchain needed.
cargo generate-lockfile --manifest-path zkvm/host/Cargo.toml
git add zkvm/host/Cargo.lock
git commit -m "chore(zk): regenerate host Cargo.lock after sp1 version bump"
```

## 1. Benchmark (no prover credentials needed)

The feasibility doc's recommended next step. Runs the guest in SP1 **execute** mode
and reports the RISC-V cycle count — the number that decides whether SP1 is practical
for ML-DSA-65 here.

```bash
# inputs.json: { withdrawalDigest, publicKey, signature, chainId, verifierAddress }
# (hex strings; digest 32 bytes, verifierAddress 20 bytes)
# Optional: message, context (hex). Omitted/empty => verify the 32-byte
# withdrawalDigest under the empty FIPS 204 context (the withdrawal path). Set both
# to verify an arbitrary-length message under a domain-separation context, as the
# NIST ACVP external/pure vectors require (see ACVP_Guest_Results.md).
cargo run --release --manifest-path zkvm/host/Cargo.toml -- execute inputs.json
# -> {"cycles": <N>, "publicValues": "0x..."}
```

Decision guide (from ZK_Verifier_Feasibility.md): cycle count under ~100M and proving
time under ~60s justify scoping a full prototype; over ~500M / several minutes means
the trusted-attestation path is the more honest option.

You can generate a valid `inputs.json` with the differential test material — see the
gated test for how a TS-signed message is fed to the guest.

## 2. Extract the program vKey

```bash
cargo run --release --manifest-path zkvm/host/Cargo.toml -- vkey
# -> {"vkey": "0x..."}
```

This bytes32 is what you deploy as `ZKMLDSAVerifier.PROGRAM_VKEY`. It changes whenever
the guest or the SP1 version changes.

## 3. Generate a real proof

Configure a prover. Local proving needs significant CPU/GPU; the Succinct Prover
Network is the practical option:

```bash
export SP1_PROVER=network
export NETWORK_PRIVATE_KEY=...   # Succinct Prover Network key
cargo run --release --manifest-path zkvm/host/Cargo.toml -- prove inputs.json
# -> {"vkey": "0x...", "publicValues": "0x...", "proofBytes": "0x..."}
```

From TypeScript, `ProverClient.generateProof(...)` does the same and returns the
payload `ZKMLDSAVerifier.verify` expects. Build the host first
(`cargo build --release --manifest-path zkvm/host/Cargo.toml`) or set `SP1_HOST_BIN`.

## 4. Deploy against a real SP1 verifier

`scripts/deploy-zk-verifier.ts` deploys `ZKMLDSAVerifier(sp1Verifier, programVKey)`.
For a real deployment, point `SP1_VERIFIER_ADDRESS` at the canonical SP1 Groth16
verifier gateway for your network (from Succinct's `sp1-contracts` deployments) and
`PROGRAM_VKEY` at the value from step 2 — **never** the mock. The mock is permitted
only on local chains with `ALLOW_MOCK_SP1=true`.

```bash
SP1_VERIFIER_ADDRESS=0x<canonical-sp1-groth16-gateway> \
PROGRAM_VKEY=0x<vkey-from-step-2> \
npx hardhat run scripts/deploy-zk-verifier.ts --network <net>
```

Then propose it to the vault via the timelocked governance flow
(`scripts/propose-verifier-update.ts`) and review during the delay.

## 5. Run the gated E2E / differential test

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKRealProof.e2e.test.ts
```

The positive case proves the TS (`@noble/post-quantum`) and Rust (`ml-dsa`)
implementations interoperate: a TS-produced signature must verify inside the guest.
The negative case asserts a tampered signature makes the guest revert.

### ACVP differential conformance (issue #29)

The official NIST ACVP sigVer vectors are routed through the guest by
`test/ZKAcvpGuest.e2e.test.ts`:

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKAcvpGuest.e2e.test.ts
```

Valid vectors must be accepted by the guest; invalid vectors and a tampered
signature must make it revert. This checks the guest against FIPS 204 itself, not
only against the TS implementation. Scope and limits: [ACVP_Guest_Results.md](ACVP_Guest_Results.md).

## What this still does not establish

- No audit of the guest, the host, or the SP1 verifier contract.
- The committed ACVP set is a 6-vector subset, not the complete NIST ACVP vector
  set; passing it is conformance evidence, not full FIPS 204 conformance.
- Gas and proving-time figures must be measured, not assumed, before publishing.
