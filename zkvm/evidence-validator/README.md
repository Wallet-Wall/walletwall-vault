# `evidence-validator` — offline evidence-shape validator (Phase 1 scaffold)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> **SCAFFOLD / OFFLINE ONLY.** This crate is opt-in offline tooling. It is **not**
> part of the default CI lane and is **not** a cryptographic verifier.

A minimal, dependency-light Rust crate that reads a committed evidence JSON
artifact from disk and checks its **deterministic shape** against the
`walletwall.zk-adapter-evidence-response.v1` response contract (see
[`docs/ZK_Adapter_Evidence_Endpoint.md`](../../docs/ZK_Adapter_Evidence_Endpoint.md)
and the JSON Schema at
[`evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`](../../evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json)).

This is the first Phase 1 Rust scaffold described in
[`docs/Rust_Implementation_Path.md`](../../docs/Rust_Implementation_Path.md) and
documented in
[`docs/Rust_Evidence_Tooling_Scaffold.md`](../../docs/Rust_Evidence_Tooling_Scaffold.md).

## What it validates (shape only)

- every required top-level field is present and well-typed;
- no unknown top-level fields are present (`deny_unknown_fields`, mirroring the
  schema's `additionalProperties: false`);
- the fixed-constant fields hold their contract values;
- `servedAt` is an ISO-8601 UTC timestamp of the contracted form;
- `etag` is a `0x` + 64 lowercase-hex string;
- `limitations` is a non-empty array of non-empty strings;
- `regeneration` carries a non-empty `command` and `deterministic == true`.

## What it deliberately does NOT do

- It does **not** recompute or verify the keccak256 `etag` — no cryptographic
  truth claim is made or checked here. The TypeScript `validate:zk-response` pass
  remains the authoritative `etag == keccak256(adapter)` cross-check.
- It does **not** deeply validate the embedded `adapter` (only that it is an
  object). Deep adapter validation stays in TypeScript.
- It performs **no** network I/O, **no** prover execution, **no** SP1 SDK build,
  **no** signing, **no** key access, and **no** chain access.
- It does **not** publish, deploy, or operate any endpoint.

## Run it offline

The Rust toolchain is **not** required by the default CI lane; install it only if
you want to run this crate locally (`rustup`):

```bash
# from zkvm/evidence-validator/
cargo test                 # build + run unit and negative tests
cargo fmt --check          # formatting
cargo check                # type/borrow check
cargo clippy -- -D warnings  # optional lints (not gated in CI)

# validate a committed artifact from disk:
cargo run -- ../../evidence/zk/zk-adapter-evidence-response.example.json
# or a local scaffold fixture:
cargo run -- fixtures/zk-adapter-evidence-response.valid.json
```

Exit codes: `0` shape-valid, `1` invalid or unreadable, `2` usage error.

## Fixtures

`fixtures/` holds local, checked-in scaffold test material — **not** canonical
evidence artifacts. One valid fixture plus several malformed/invalid fixtures
drive the unit and negative tests.
