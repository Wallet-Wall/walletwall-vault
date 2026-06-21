# PQ Proof Artifact (reproducible manifest)

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> This manifest is **not a proof**. It pins the deterministic SP1 journal only. No
> Groth16 proof bytes are generated, there is **no on-chain verification**, **no
> custody**, and **no "quantum-proof" guarantee**.

The proof artifact is a deterministic, locally regenerable **manifest** that
demonstrates the _shape_ of a future ZK/PQ proof output for an ML-DSA-65
(FIPS 204) withdrawal-authorization fixture — **without** requiring the SP1
toolchain, a prover, or any network access.

It exists so the private WalletWall app, auditors, and third parties can see and
cross-check the deterministic parts of the ZK lane (the journal / public values
and the evidence core) today, while the heavy proving step stays gated.

## What it pins

| Field                               | Meaning                                                                                                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema`                            | Stable manifest id `walletwall.pq-proof-artifact.v1`.                                                                                                                   |
| `generatedAt`                       | ISO-8601 UTC instant. The **only** non-deterministic field (fixed for the committed example).                                                                           |
| `artifact.kind`                     | `sp1-mldsa65-journal-manifest`.                                                                                                                                         |
| `artifact.vectorSet`                | Vector-set identifier the fixture was drawn from (e.g. `library-generated/ml-dsa-65`).                                                                                  |
| `artifact.verifier`                 | The open verifier build/version (`walletwall-vault-pq-verifier`, schema version).                                                                                       |
| `artifact.tooling`                  | The prover/scheme a future real proof would use (`sp1` / `groth16`).                                                                                                    |
| `artifact.sourceEvidenceHash`       | keccak256 of the canonical deterministic verification result (the evidence core, no timestamp).                                                                         |
| `artifact.input`                    | keccak256 hashes of message / public key / signature — **never** raw bytes.                                                                                             |
| `artifact.journal.publicValues`     | The SP1 guest journal: ABI-encoded `(bytes32, bytes32, bytes32, uint64, address)` = `(withdrawalDigest, pkHash, sigHash, chainId, verifierAddress)`, exactly 160 bytes. |
| `artifact.journal.publicValuesHash` | keccak256 of the journal — the deterministic **output hash**.                                                                                                           |
| `proof`                             | Proof presence. Here `status: "gated"`, `generated: false` — no real proof is produced.                                                                                 |
| `regeneration`                      | The command that reproduces the artifact, and a `deterministic` flag.                                                                                                   |

The journal is the only intentionally long hex field, and it carries **only
hashes plus a chain id and verifier address**. The validator decodes it and
asserts it matches the declared `input` hashes, which proves it embeds no raw
key/signature material.

## What it proves

- The deterministic **journal encoding** (the TypeScript ↔ Rust-guest public-value
  contract) is internally consistent and binds to a known-good ML-DSA-65 fixture.
- The open verifier returns a stable **evidence core** for that fixture, and the
  manifest is a pure function of the fixture (regenerating yields a byte-identical
  artifact).

## What it does **not** prove

- It is **not a proof**: no Groth16 proof bytes are generated. `proof.status` is
  `gated`.
- It is **not on-chain verification**. The active testnet verifier is the mock
  path (see [ZK_PQ_Status_Matrix.md](ZK_PQ_Status_Matrix.md)).
- It is **not production custody**, accepts **no mainnet deposits**, produces **no
  real yield**, and makes **no "quantum-proof" guarantee**.

## Regenerate / validate

```bash
# (Re)write the committed example deterministically.
npm run proof:artifact

# Validate the committed example and assert it has not drifted (exit non-zero otherwise).
npm run proof:artifact:validate
```

Both commands are pure TypeScript and need **no** SP1 toolchain or network. The
committed example lives at
[`docs/schemas/examples/pq-proof-artifact.v1.json`](schemas/examples/pq-proof-artifact.v1.json),
the JSON Schema at
[`docs/schemas/pq-proof-artifact.v1.schema.json`](schemas/pq-proof-artifact.v1.schema.json),
and the builder/validator at
[`scripts/lib/proof-artifact.ts`](../scripts/lib/proof-artifact.ts).
`test/PQProofArtifact.test.ts` re-derives the example and fails on any drift.

## How real proving would fit

Generating an actual proof is the heavy, gated step. It requires the SP1
toolchain plus a configured prover and stays behind `RUN_SP1_E2E=1` (see
[ZK_Prover_Runbook.md](ZK_Prover_Runbook.md) and
[SP1_Smoke_Lane.md](SP1_Smoke_Lane.md)). When run, a future artifact would carry
`proof.status: "generated"` with the proof bytes referenced out-of-band; the
deterministic fields in this manifest would remain unchanged, which is exactly
why they are pinned here first.

## Related

- [Open_PQ_Verifier.md](Open_PQ_Verifier.md) · [PQ_Verifier_Evidence_Artifact.md](PQ_Verifier_Evidence_Artifact.md) · [Verifier_Result_Schema.md](Verifier_Result_Schema.md)
- [SP1_Smoke_Lane.md](SP1_Smoke_Lane.md) · [ZK_Prover_Runbook.md](ZK_Prover_Runbook.md) · [ZK_PQ_Status_Matrix.md](ZK_PQ_Status_Matrix.md)
