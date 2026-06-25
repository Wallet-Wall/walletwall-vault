# Rust Evidence Validator — Canonical ETag / keccak256 Parity

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> **Offline-only.** This document describes a conservative, deterministic step
> that lets the Rust evidence validator
> ([`zkvm/evidence-validator/`](../zkvm/evidence-validator/)) independently
> recompute the canonical keccak256 `etag` of a committed evidence artifact and
> check it for **parity** against the value the TypeScript serializer committed.
> CI compiles and tests the crate offline, but this is **not** a cryptographic
> verifier: it deploys nothing, adds no server, no network listener, no secrets,
> and no API keys, and it makes **no** production-readiness claim.

This step builds directly on
[Rust_Evidence_Validator_Contract_Expansion.md](Rust_Evidence_Validator_Contract_Expansion.md)
and stays strictly inside the bounded, offline-safe Rust role defined by
[Rust_Implementation_Path.md](Rust_Implementation_Path.md). It implements the
**canonical ETag / keccak256 parity** cross-check that those documents named as
future work — the Contract Expansion doc's *Phase 2 (canonical keccak256 parity)*
and the equivalent *adapter ETag re-derivation* described under
[Rust_Implementation_Path.md](Rust_Implementation_Path.md) ("re-derive the
keccak256 of its canonical JSON, and check it against the `etag` field"). It adds
an independent, offline, deterministic second check and **relaxes nothing**.

- **Crate:** [`zkvm/evidence-validator/`](../zkvm/evidence-validator/)
- **Validates the contract:** `walletwall.zk-adapter-evidence-response.v1`
  (see [ZK_Adapter_Evidence_Endpoint.md](ZK_Adapter_Evidence_Endpoint.md))
- **Mirrors the TypeScript serializer:**
  [`scripts/lib/zk-adapter-endpoint.ts`](../scripts/lib/zk-adapter-endpoint.ts)
  (`computeAdapterETag` = `keccak256(JSON.stringify(adapter))`)

## What ETag / canonical parity validates

The committed `etag` is the strong content hash of the embedded `adapter`:

```text
etag == "0x" + keccak256( JSON.stringify(adapter) )   // compact, document key order
```

When the `etag` is well-formed (`0x` + 64 lowercase hex) and the embedded
`adapter` carries its correct identity, the validator:

1. **Reconstructs the canonical payload** exactly as the TypeScript serializer
   does — the adapter re-serialized to compact JSON in **document key order**
   (`serde_json` is built with the `preserve_order` feature so keys are not
   sorted), matching `JSON.stringify(adapter)` byte-for-byte for this artifact
   family.
2. **Computes the expected keccak256 digest** of those UTF-8 bytes (the same
   Ethereum/`ethers` keccak256 the TypeScript side uses), rendered as `0x` + 64
   lowercase hex.
3. **Compares** it to the committed `etag` and **fails validation** with a
   deterministic, specific message if they differ.

This catches a **tampered `etag`**, a **drifted adapter payload left with a stale
`etag`**, and a **re-ordered adapter** that no longer hashes to the committed
value. The parity recompute is gated behind a well-formed `etag` and a credible
adapter identity, so a malformed `etag` or a structurally wrong adapter reports
only its own problem — never a redundant second one. Validation stays
**local-file only**: a path is read from disk and the process exits.

## What it does NOT validate (boundaries preserved)

This is an **offline deterministic** content-hash cross-check, framed as parity,
**not** as cryptographic truth, proof verification, or production readiness:

- **This is not proof verification.** It verifies no Groth16/SNARK/STARK proof,
  no signature, and no on-chain ML-DSA verification.
- **This is not cryptographic truth about chain state.** Matching the keccak256
  content hash says only that the committed `etag` is the hash of the committed
  `adapter`. It makes no claim about any blockchain, deployment, or custody.
- **No proof is generated** and **no prover execution** occurs. There is no SP1
  prove path and no Groth16 proof here; heavy proving stays gated behind
  `RUN_SP1_E2E=1` in the existing host crate, untouched. There is **no live
  proving**.
- **No network or RPC.** The crate performs **no network** I/O and **no RPC**
  call; it reads a local file and exits.
- **No endpoint deployment.** It deploys, starts, and operates no server,
  listener, or HTTP service; there is **no active endpoint deployment**. No
  GitHub Pages and no serverless code are added.
- **No hosted artifact publishing.** It uploads and publishes **no hosted
  artifact** to any external host, CDN, or object store.
- **No contract, ABI, or deployment changes.** It modifies no Solidity contract,
  no ABI, and no deployed contract address; it touches nothing under
  `contracts/`, and it makes no deployment-configuration change.
- **No evidence semantic changes.** It alters no schema or field meaning of any
  evidence artifact type; the response contract is unchanged.
- **No deep adapter re-derivation.** It hashes the whole adapter but does not
  re-derive or deeply validate the adapter's internals (`proofInput`, `journal`,
  `proof`, `evidence`, …); that stays the authoritative TypeScript
  `validateAdapter` pass's responsibility and remains deferred in Rust.
- **No production-ZK, no mainnet custody, no wallet-safety, and no
  deployment-reproducibility claims.** This is **not production zk**, makes **no
  mainnet custody** claim, offers **no** wallet-safety guarantee, and asserts
  **no deployment-reproducibility**. `#![forbid(unsafe_code)]` is set crate-wide,
  so there is no `unsafe` block.

The TypeScript `validate:zk-response` pass remains the CI source of truth; this
crate complements it with an independent, offline, deterministic recomputation.

## Hashing dependency

The keccak256 hash uses `sha3 = "=0.10.8"` — the **same exact pin** the SP1 guest
([`zkvm/guest/Cargo.toml`](../zkvm/guest/Cargo.toml)) already uses, so the whole
repository resolves one Keccak implementation. `serde_json` gains only the
`preserve_order` feature (for document key order). No network, RPC, wallet,
prover, or SP1 dependency is added.

A `Cargo.lock` is **not** committed for this crate: the toolchain is not available
in the authoring environment, so a lockfile cannot be generated cleanly here, and
the existing `Check evidence-validator crate (offline)` CI job already runs
`cargo check` / `cargo test` **without** `--locked` (unlike the SP1 host job).
This keeps the crate's existing convention unchanged.

## How to run it offline

CI runs the offline **`Check evidence-validator crate (offline)`** job in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

```bash
cargo fmt --check --manifest-path zkvm/evidence-validator/Cargo.toml
cargo check --manifest-path zkvm/evidence-validator/Cargo.toml
cargo test  --manifest-path zkvm/evidence-validator/Cargo.toml
```

That job is offline-safe: no SP1 toolchain, no prover, no network/RPC at runtime,
no chain, no keys, no endpoint. Run the same checks locally with `rustup`:

```bash
# from zkvm/evidence-validator/
cargo test                  # build + run unit, negative, and parity tests
cargo fmt --check           # formatting
cargo check                 # type / borrow check

# validate the committed example artifact from disk (shape + etag parity):
cargo run -- ../../evidence/zk/zk-adapter-evidence-response.example.json
# or a local scaffold fixture:
cargo run -- fixtures/zk-adapter-evidence-response.valid.json
```

No flag enables a network, prover, or chain path; none exists. Tests use local,
checked-in fixtures only — the suite fetches nothing over the network.

## Relationship to the Rust implementation path

This work stays inside the bounded role granted by
[Rust_Implementation_Path.md](Rust_Implementation_Path.md): deterministic,
offline canonical-serialization parity that TypeScript validators can cross-check.
It does **not** implement a reviewed prover path or hosted artifact integration;
each of those still needs its own separate, reviewed PR.

## Related

- [Rust evidence validator contract expansion](Rust_Evidence_Validator_Contract_Expansion.md) —
  the deterministic contract-shape checks this parity step builds on.
- [Rust evidence tooling scaffold](Rust_Evidence_Tooling_Scaffold.md) — the Phase 1
  scaffold.
- [Rust implementation path](Rust_Implementation_Path.md) — the bounded role and
  phased rollout.
- [ZK adapter evidence endpoint](ZK_Adapter_Evidence_Endpoint.md) — the read-only
  response-shape contract and the `computeAdapterETag` definition this crate
  mirrors.
- [ZK verifier adapter boundary](ZK_Verifier_Adapter_Boundary.md) — the embedded
  adapter artifact, deeply validated in TypeScript.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — the single source of truth for
  what exists vs what is claimed.
- [SECURITY.md](../SECURITY.md) — prototype status, scope, and reporting.
