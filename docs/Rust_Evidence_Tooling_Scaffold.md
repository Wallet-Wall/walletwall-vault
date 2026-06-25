# Rust Evidence Tooling Scaffold (Phase 1)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> **Scaffold / offline only.** This document describes the first Phase 1 Rust
> scaffold from [Rust_Implementation_Path.md](Rust_Implementation_Path.md). CI
> compiles and tests the crate offline (see "How to run it offline"), but it is
> **not** a cryptographic verifier, it deploys nothing, it adds no server, no
> network listener, no secrets, and no API keys. CI verifies only that the
> scaffold compiles and its shape checks pass — never cryptographic truth,
> proving, endpoint behavior, or production readiness.

This is the first real Rust code added under the bounded, offline-safe role that
[Rust_Implementation_Path.md](Rust_Implementation_Path.md) defined. It implements
**Phase 1 — Rust crate boundary** of that document and nothing beyond it.

> **Update — contract-validation expansion.** A conservative, still-offline Phase 1
> expansion has since strengthened the validator (`status`/`ok` consistency,
> `adapter` identity/version fields, `servedAt` range, and `etag` / `limitations` /
> `regeneration` presence). It remains contract-shape only — no keccak256 recompute,
> no prover, no network/RPC, no endpoint deployment, and no contract/ABI changes. See
> [Rust_Evidence_Validator_Contract_Expansion.md](Rust_Evidence_Validator_Contract_Expansion.md)
> for the full field list and boundaries.

- **Crate:** [`zkvm/evidence-validator/`](../zkvm/evidence-validator/)
- **Library + CLI:** `src/lib.rs`, `src/main.rs`
- **Local fixtures:** `zkvm/evidence-validator/fixtures/`
- **Validates the contract:** `walletwall.zk-adapter-evidence-response.v1`
  (see [ZK_Adapter_Evidence_Endpoint.md](ZK_Adapter_Evidence_Endpoint.md) and the
  schema at
  [`evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`](../evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json))

## What the scaffold validates

The crate reads one committed evidence JSON artifact **from disk** and checks its
**deterministic shape** against the `walletwall.zk-adapter-evidence-response.v1`
response contract. Shape checks only:

- every required top-level field is present and well-typed
  (`schema`, `service`, `mode`, `status`, `ok`, `contentType`, `servedAt`,
  `etag`, `adapter`, `limitations`, `regeneration`);
- no unknown top-level fields are present — `deny_unknown_fields` on the typed
  struct mirrors the schema's `additionalProperties: false`;
- the fixed-constant fields hold their contract values
  (`schema`, `service`, `mode`, `status == 200`, `ok == true`, `contentType`);
- `servedAt` is an ISO-8601 UTC timestamp of the contracted form
  (`YYYY-MM-DDTHH:MM:SS[.mmm]Z`);
- `etag` is a `0x` + 64 lowercase-hex string (`^0x[0-9a-f]{64}$`);
- `limitations` is a non-empty array of non-empty strings;
- `regeneration` carries a non-empty `command` and `deterministic == true`.

The CLI prints a structured, human-readable result and exits `0` on success, `1`
on a validation or read failure, and `2` on a usage error — analogous to the
existing TypeScript `validate:*` scripts.

## What the scaffold deliberately does NOT validate

This is **shape only**, not cryptographic truth:

- It does **not** recompute or verify the keccak256 `etag`. No cryptographic
  truth claim is made or checked here. The TypeScript `validate:zk-response` pass
  remains the authoritative `etag == keccak256(adapter)` cross-check.
- It does **not** deeply validate the embedded `adapter` object — only that it is
  a JSON object. Deep adapter validation stays in TypeScript.
- It does **not** perform production ZK verification, on-chain ML-DSA
  verification, or any proof check. The served adapter is not a proof.
- It relaxes **no** existing validation: the TypeScript validators remain the CI
  source of truth, and this crate only adds an independent, offline shape check.

## Safety boundaries preserved

This scaffold honours every non-goal in
[Rust_Implementation_Path.md](Rust_Implementation_Path.md). It is **offline-only**
and:

- **No prover execution** — there is no SP1 prove path here; no proof is
  generated, and heavy proving stays gated behind `RUN_SP1_E2E=1` in the existing
  host crate, untouched by this scaffold.
- **No network or RPC calls** — the crate performs no network I/O and no RPC; it
  reads a local file and exits.
- **No endpoint deployment** — it deploys, starts, and operates no server,
  listener, or HTTP service, and it publishes no artifact to any external host.
- **No contract or ABI changes** — it modifies no Solidity contract, no ABI, and
  no deployed contract address; it touches nothing under `contracts/`.
- **No mainnet custody** and **no wallet interaction** — it holds no funds, opens
  no wallet, and is never invoked from the private WalletWall app runtime.
- **No private keys and no signing** — it reads, derives, stores, and transmits
  no key material and signs nothing.
- **No on-chain writes and no transaction signing** — it builds, signs, and
  broadcasts no transaction and mutates no on-chain state.
- **No evidence semantic changes** — it alters no schema or field meaning of any
  existing evidence artifact type.
- It makes **no** production-ZK, **no** mainnet-deposit, and **no**
  deployment-reproducibility claim. `#![forbid(unsafe_code)]` is set crate-wide,
  so there is no `unsafe` block.

## How to run it offline

CI runs an offline job — **`Check evidence-validator crate (offline)`** in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — that installs stable
Rust and runs, scoped to this crate only:

```bash
cargo fmt --check --manifest-path zkvm/evidence-validator/Cargo.toml
cargo check --manifest-path zkvm/evidence-validator/Cargo.toml
cargo test  --manifest-path zkvm/evidence-validator/Cargo.toml
```

That job is offline-safe: no SP1 toolchain, no prover, no network/RPC at runtime,
no chain, no keys, no endpoint. It verifies only that the crate compiles and its
shape checks pass — never cryptographic truth, proving, endpoint behavior, or
production readiness. `clippy` is not run (the repo's Rust jobs do not use it).

You can run the same checks locally with `rustup`:

```bash
# from zkvm/evidence-validator/
cargo test                  # build + run unit and negative tests
cargo fmt --check           # formatting
cargo check                 # type / borrow check

# validate the committed example artifact from disk:
cargo run -- ../../evidence/zk/zk-adapter-evidence-response.example.json
# or a local scaffold fixture:
cargo run -- fixtures/zk-adapter-evidence-response.valid.json
```

No flags enable a network, prover, or chain path; none exists. Tests use local,
checked-in fixtures only.

### Dependencies and lockfile

The crate depends only on `serde` + `serde_json` for strict typed JSON parsing —
no SP1, cryptography, HTTP, or network crates. The dependency convention mirrors
`zkvm/guest` and `zkvm/host` (caret minor pins for serde-family crates). A
`Cargo.lock` is **not** committed for this crate, so the CI job runs **without**
`--locked` and `cargo` resolves `serde` + `serde_json` fresh at build time. A
contributor with a toolchain may run `cargo build` and commit the generated
`Cargo.lock` as a follow-up to pin transitive dependencies; the dedicated
`--locked` lockfile gate stays specific to `zkvm/host`.

## Relationship to the Rust implementation path

[Rust_Implementation_Path.md](Rust_Implementation_Path.md) defines five phases.
This scaffold is **Phase 1 — Rust crate boundary** only:

- it adds a new, offline-safe crate entirely within `zkvm/`;
- it reads a committed artifact, checks shape and size constraints, prints a
  structured result, and exits zero/non-zero;
- it requires no network, no prover, no signing, and no SP1 SDK build dependency.

It intentionally does **not** implement Phase 2 (fixture parity / keccak256
cross-check), Phase 3 (adapter re-derivation), Phase 4 (reviewed prover path), or
Phase 5 (hosted artifact integration). Each later phase needs its own separate,
reviewed PR.

## Future expansion path

Within the permission granted by [Rust_Implementation_Path.md](Rust_Implementation_Path.md),
later reviewed PRs may extend this crate toward:

- **Canonical serialization parity (Phase 2).** Produce the canonical byte
  representation of `zkvm/fixtures/mldsa65-withdrawal.inputs.json`, compute its
  keccak256, and compare it against the hash the TypeScript `validate:sp1-input`
  run records — an offline second cross-check, never a replacement.
- **Proof-input validation.** Check that a committed `walletwall.sp1-proof-input.v1`
  fixture satisfies the shape, size, and hash constraints defined by the ML-DSA
  evidence manifest, offline, with no SP1 toolchain.
- **Adapter re-derivation drift check (Phase 3).** Re-derive the keccak256 of the
  committed adapter's canonical JSON and compare it against the `etag` the
  TypeScript `validate:zk-adapter` / `validate:zk-response` passes produce.

None of these begins without its own reviewed PR; this document records the
*direction*, not authorization to implement.

## Related

- [Rust evidence validator contract expansion](Rust_Evidence_Validator_Contract_Expansion.md) —
  the conservative, deterministic Phase 1 expansion that builds on this scaffold.
- [Rust implementation path](Rust_Implementation_Path.md) — the bounded role and
  phased rollout this scaffold implements (Phase 1).
- [ZK adapter evidence endpoint](ZK_Adapter_Evidence_Endpoint.md) — the read-only
  response-shape contract this crate validates.
- [ZK verifier adapter boundary](ZK_Verifier_Adapter_Boundary.md) — the embedded
  adapter artifact, deeply validated in TypeScript.
- [SP1 proof-input scaffold](SP1_Proof_Input.md) — the proof-input fixture a later
  phase may validate.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — the single source of truth for
  what exists vs what is claimed.
- [SECURITY.md](../SECURITY.md) — prototype status, scope, and reporting.
