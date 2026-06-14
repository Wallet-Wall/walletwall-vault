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
- `test/ZKRealProof.e2e.test.ts` — gated end-to-end / differential test
  (`RUN_SP1_E2E=1`).

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

## 1. Benchmark (no prover credentials needed)

The feasibility doc's recommended next step. Runs the guest in SP1 **execute** mode
and reports the RISC-V cycle count — the number that decides whether SP1 is practical
for ML-DSA-65 here.

```bash
# inputs.json: { withdrawalDigest, publicKey, signature, chainId, verifierAddress }
# (hex strings; digest 32 bytes, verifierAddress 20 bytes)
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

## What this still does not establish

- No audit of the guest, the host, or the SP1 verifier contract.
- A single positive vector is not full NIST ACVP conformance; run the official
  sigVer vectors through the guest before making any conformance claim.
- Gas and proving-time figures must be measured, not assumed, before publishing.
