# ZK Prover Runbook (SP1 ML-DSA-65)

> ⚠️ **Research prototype. Not audited. Do not use real funds.** This runbook wires
> a *real* SP1 prover to the existing `ZKMLDSAVerifier` scaffold. It does not make
> the vault production custody and does not, by itself, establish NIST conformance.
> Read [ZK_Verifier_Feasibility.md](ZK_Verifier_Feasibility.md) and
> [Security_Assumptions.md](Security_Assumptions.md) first.

This is the off-chain half that was missing from the ZK path: tooling to compile the
guest, run the feasibility cycle benchmark, extract the real program verification key,
and generate a real Groth16 proof for on-chain verification. The default test/CI path
still uses `MockSP1Verifier` and a mock vKey; of this, only the gated canonical rebuild (§4) runs in CI.

## Components

- `zkvm/guest/` — two SP1 programs (pinned crates): `mldsa65-withdrawal`, the program a `ZKMLDSAVerifier` pins, and `mldsa65-acvp`, ACVP conformance only.
- `zkvm/host/` — the SP1 host/prover (`mldsa65-host`): `execute`, `vkey`, `prove` (withdrawal
  program) and `acvp-execute`, `acvp-vkey` (ACVP program). **Not** part of CI; needs the SP1 toolchain.
- `scripts/prover-client.ts` — `ProverClient.generateProof()` shells out to the host
  and reuses `encodeProof()`; `encodeProof()` remains the mock/encode-only path.
- `test/ZKRealProof.e2e.test.ts` — gated end-to-end TS↔Rust differential test
  (`RUN_SP1_E2E=1`).
- `test/ZKAcvpGuest.e2e.test.ts` — gated NIST ACVP differential-conformance test
  that routes the official sigVer vectors through the ACVP program (`RUN_SP1_E2E=1`). See
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
together; the new subject then needs a successor designation (§4), never a pasted vKey.

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
# (hex strings; digest 32 bytes, verifierAddress 20 bytes) and no other key: the
# withdrawal program verifies the signature over withdrawalDigest itself, under the
# empty FIPS 204 context. NIST ACVP vectors (arbitrary message + context) run in the
# separate ACVP program instead: `-- acvp-execute acvp-inputs.json` with
# { publicKey, message, context, signature } (see ACVP_Guest_Results.md).
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

This bytes32 is your build's withdrawal vkey. A deployment pins only a designated one (§4): a local
build can differ, since its ELF embeds local paths. Never pin `acvp-vkey`; the vkey changes with the program or SP1.

## 3. Generate a real proof

Configure a prover. Self-hosted proving needs the circuit v6.1.0 artifacts, which WalletWall has not archived
(§4, proving availability); the Succinct Prover Network is the hosted option:

```bash
export SP1_PROVER=network
export NETWORK_PRIVATE_KEY=...   # Succinct Prover Network key
cargo run --release --manifest-path zkvm/host/Cargo.toml -- prove inputs.json
# -> {"vkey": "0x...", "publicValues": "0x...", "proofBytes": "0x..."}
```

From TypeScript, `ProverClient.generateProof(...)` does the same and returns the
payload `ZKMLDSAVerifier.verify` expects. Build the host first
(`cargo build --release --manifest-path zkvm/host/Cargo.toml`) or set `SP1_HOST_BIN`.

## 4. Deploy against the designated SP1 verifier

`scripts/deploy-zk-verifier.ts` deploys `ZKMLDSAVerifier(sp1Verifier, programVKey, haltPrincipal)` from a designation.
Off a local chain the SP1 verifier and `PROGRAM_VKEY` come only from the selected designation (never Succinct's
`SP1VerifierGateway`, whose owner can change what its routes accept), and the wrapper's constructor refuses any
verifier whose runtime code is not the pinned SP1Verifier v6.1.0. `SP1_VERIFIER_ADDRESS`, `PROGRAM_VKEY` and
`ALLOW_MOCK_SP1` are refused there. The mock is permitted only on local chains with `ALLOW_MOCK_SP1=true` (TEST ONLY).

```bash
HALT_PRINCIPAL_ADDRESS=0x<halt-only-principal> \
npx hardhat run scripts/deploy-zk-verifier.ts --network <net>
```

`HALT_PRINCIPAL_ADDRESS` is the wrapper's halt-only principal (threshold or multisig control, never the deployer);
`SP1_DESIGNATION_ID` selects a designation when more than one is accepted. Before any transaction the script refuses a
mainnet, an override, an unrecorded wrapper build and an identity the registry records as halted on any chain; it
requires the published records (the registry, the designations, their evidence and the wrapper builds exactly as
`origin/main` holds them, fetched then) and validates them (content and full git history), then reads the target chain
at one finalized block, fetched once: the designated verifier's runtime code hash, and the per-chain execution check —
a real v6.1.0 proof accepted, the same proof tampered and an odd-word canary refused with `ProofInvalid` — with the
canary's positive control run on the in-process EVM. After deploying it reads the wrapper back. An RPC that does not
answer, or names no finalized block, stops it; the one provider it reads is believed, so use one you trust.

Record the wrapper in the registry from chain reads (no transaction), and publish the change by pull request:

```bash
WRAPPER_ADDRESS=0x<wrapper> DEPLOYMENT_TX=0x<tx> \
npx hardhat run scripts/register-sp1-wrapper.ts --network <net>
```

Then propose it to the vault via the timelocked governance flow
(`scripts/propose-verifier-update.ts`) and review during the delay.

**Where the designation comes from.** `evidence/zk/sp1/designations/` holds generated designations, never typed ones:
`mldsa65-withdrawal-d1` binds the zkvm subject, the canonical procedure (the vendor image by digest), the ELF and
`PROGRAM_VKEY` to SP1Verifier v6.1.0. CI fails when the subject on disk no longer matches the latest designation. A
change to the guest, the host or a lockfile therefore needs a successor designation, a program rebuild under the same
procedure: rebuild with the canonical procedure (`scripts/sp1-canonical/canonical-build.sh`;
`.github/workflows/sp1-canonical-build.yml` does it on two runners, recomputes the vkey on a third, and reports the
`SP1 canonical build gate`), commit the evidence bundle, and derive it with
`npm run sp1:designation -- --successor <bundle.json>`. A successor must be a new identity; the same verifier code
and vkey at another address is the same identity and is refused. A change of SP1 itself (its version, the vendor
image, the verifier) is another procedure or verifier, which this tooling cannot designate: it needs its own decision.

**If the wrapper must be halted.** The halt principal calls `halt()` (one-way). Record it for every chain:
`WRAPPER_ADDRESS=0x<wrapper> HALT_TX=0x<tx> HALT_REASON=<reason>` with the same script; once published, the tooling
refuses the identity everywhere. Recovery is a successor identity's wrapper through each consumer's delayed rotation;
a program rebuild can be designated here, a fixed SP1 verifier cannot yet.

**Proving availability (TD1-N9).** The rotation delay protects PqOnly users only while they can prove.
`PROVING_AVAILABILITY = OWNER_DOWNLOAD_REQUIRED`: the v6.1.0 Groth16 artifacts (about 6.21 GB) are not archived by
WalletWall, and none are installed on the proving host. Their `groth16_vk.bin` must hash to `VERIFIER_HASH`
`0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696` (the key `sp1-verifier` 6.3.1 embeds). The
pinned prover downloads them only when `$SP1_GROTH16_CIRCUIT_PATH/v6.1.0` is absent and checks no digest, so a
self-hosted path places a verified archive there, keeps `SP1_CIRCUIT_MODE` unset, and pins the gnark image
(`SP1_GNARK_IMAGE`) by digest. The requirements and the owner's actions are in
`evidence/zk/sp1-impl/proving-availability.json`; see
[SP1_Implementation_Pin_Designation_Registry.md](SP1_Implementation_Pin_Designation_Registry.md).

## 5. Run the gated E2E / differential test

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKRealProof.e2e.test.ts
```

The positive case proves the TS (`@noble/post-quantum`) and Rust (`ml-dsa`)
implementations interoperate: a TS-produced signature must verify inside the guest.
The negative case asserts a tampered signature makes the guest revert.

### ACVP differential conformance (issue #29)

The official NIST ACVP sigVer vectors run through the separate ACVP program
(`mldsa65-acvp`, via `mldsa65-host acvp-execute`) in `test/ZKAcvpGuest.e2e.test.ts`:

```bash
cargo build --release --manifest-path zkvm/host/Cargo.toml
RUN_SP1_E2E=1 npx hardhat test test/ZKAcvpGuest.e2e.test.ts
```

Valid vectors must be accepted by the ACVP program; invalid vectors and a tampered
signature must make it revert. The test also checks that the withdrawal and ACVP
programs report different vkeys and that the withdrawal path rejects ACVP inputs. This
checks the `ml-dsa` verification against FIPS 204 itself, not only against the TS
implementation. Scope and limits: [ACVP_Guest_Results.md](ACVP_Guest_Results.md).

## What this still does not establish

- No audit of the guest, the host, or the SP1 verifier contract.
- No WalletWall proof of the designated program has been generated, and no wrapper is deployed or registered on any
  chain; `PRODUCTION_SP1_BINDING_STATUS` is `NOT_ESTABLISHED`
  (`evidence/zk/sp1-impl/implementation-receipt.json`).
- Designations and the code-hash pin establish which verifier and program a wrapper binds, not that they are sound.
- The committed ACVP set is a 6-vector subset, not the complete NIST ACVP vector
  set; passing it is conformance evidence, not full FIPS 204 conformance.
- Gas and proving-time figures must be measured, not assumed, before publishing.
