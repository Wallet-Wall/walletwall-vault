# SP1 ML-DSA-65 Proof-Input Scaffold

> **Research prototype. Not audited. Testnet/local only. No real funds.**
> This is a deterministic proof **input** and an alignment check — not a proof, not
> on-chain ML-DSA verification, and not a production custody claim.

This scaffold gives the SP1 ML-DSA-65 guest a **committed, deterministic,
manifest-aligned proof input** for the withdrawal path, and a local validator
that keeps that input in lock-step with the
[ML-DSA evidence manifest](ML_DSA_Evidence_Manifest.md).

- **Proof input:** [`zkvm/fixtures/mldsa65-withdrawal.inputs.json`](../zkvm/fixtures/mldsa65-withdrawal.inputs.json)
- **Builder + validator + alignment:** [`scripts/lib/sp1-proof-input.ts`](../scripts/lib/sp1-proof-input.ts)
- **Generator:** [`scripts/generate-sp1-proof-input.ts`](../scripts/generate-sp1-proof-input.ts)

## What it is

The fixture is the flat guest `inputs.json` shape the SP1 host consumes
(`withdrawalDigest`, `publicKey`, `signature`, `chainId`, `verifierAddress`),
mirroring the Rust `InputsFile`/`GuestInputs` in
[`zkvm/host/src/main.rs`](../zkvm/host/src/main.rs) and
[`zkvm/guest/src/main.rs`](../zkvm/guest/src/main.rs). It is **byte-identical** to
what [`scripts/sp1-smoke.ts`](../scripts/sp1-smoke.ts) already feeds the guest, so
no guest, host, or smoke-lane behavior changes. When the SP1 host is built, it is
directly consumable:

```bash
# Build the host first (see docs/ZK_Prover_Runbook.md). Execute-only, no proving:
mldsa65-host execute zkvm/fixtures/mldsa65-withdrawal.inputs.json
```

Because the proof input carries the raw ML-DSA-65 public key and signature (the
guest needs them to verify), it is **not** hash-only like the evidence manifest —
it is the verification *input*, and the manifest is the read-only *evidence*
about it.

## Alignment with the ML-DSA evidence manifest

The manifest is the **input contract**. The proof input mirrors the manifest's
`library-generated-ml-dsa-65` evidence entry: the keccak256 of the proof input's
message/public-key/signature must equal the hashes that entry records, under the
pinned manifest schema version `walletwall.ml-dsa-evidence-manifest.v1`.

```bash
npm run validate:sp1-input    # validate the committed proof input
npm run sp1:proof-input       # regenerate it deterministically
```

`validate:sp1-input` checks the committed fixture three ways — all offline, with
**no SP1 toolchain and no proving**:

1. **Shape** — the flat host inputs shape: a bytes32 withdrawal digest, an
   ML-DSA-65-sized public key (1952 bytes) and signature (3309 bytes), a
   testnet/non-mainnet chain id, and a valid verifier address.
2. **Manifest alignment** — keccak256 of the input's raw material matches the
   hashes the ML-DSA evidence manifest records for the source entry, under the
   pinned manifest schema version.
3. **No drift** — the committed fixture equals a freshly built one and derives the
   same deterministic 160-byte SP1 journal (public values) as the smoke lane.

## What it is NOT

- It does **not** prove anything. No Groth16 proof is generated. Heavy proving
  stays gated behind `RUN_SP1_E2E=1` and an external prover (see
  [ZK Prover Runbook](ZK_Prover_Runbook.md)).
- It does **not** prove production custody security and is **not** audited.
- It does **not** perform on-chain ML-DSA verification. The active testnet
  on-chain verifier is a mock; the non-mock path trusts an EIP-712 attestor.
- Mainnet remains gated by audit, funding, and operational controls.

## Relationship to the other lanes

| Lane | What it does | Toolchain |
| --- | --- | --- |
| [SP1 smoke](SP1_Smoke_Lane.md) | Derives + checks the guest journal for the fixture | none (host step optional) |
| **SP1 proof input** (this) | Commits the deterministic, manifest-aligned guest input | none |
| [PQ proof artifact](PQ_Proof_Artifact.md) | Pins the journal manifest; the proof block stays gated | none |
| Real proving | Generates a Groth16 proof for the input | SP1 prover (gated) |

## Follow-up

The next step is a **ZK verifier adapter boundary** that consumes this proof
input + the resulting (gated) proof and the manifest evidence, defining the
adapter interface without claiming production ZK verification or on-chain
readiness.
