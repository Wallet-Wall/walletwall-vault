# `evidence-validator` — offline evidence-shape validator (Phase 1 scaffold)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> **SCAFFOLD / OFFLINE ONLY.** CI compiles and tests this crate offline (the
> `Check evidence-validator crate (offline)` job), but it is **not** a
> cryptographic verifier — CI checks compile/shape only, never proving, endpoint
> behavior, or production readiness.

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

## What it validates (deterministic contract shape only)

- every required top-level field is present and well-typed;
- no unknown top-level fields are present (`deny_unknown_fields`, mirroring the
  schema's `additionalProperties: false`);
- the fixed-constant fields hold their contract values;
- `status` and `ok` are internally consistent (a 2xx status requires `ok == true`;
  a non-2xx status requires `ok == false`);
- `servedAt` is an ISO-8601 UTC timestamp of the contracted form, with in-range
  calendar/time components (month `01`–`12`, day `01`–`31`, `00`–`23`/`00`–`59`);
- `etag` is a present, non-empty `0x` + 64 lowercase-hex string;
- the embedded `adapter` is an object carrying its required identity/version
  fields (`schema` + `artifactType` contract constants);
- `limitations` is a non-empty array of non-empty strings;
- `regeneration` is present and carries a non-empty `command` and
  `deterministic == true`.

See
[`docs/Rust_Evidence_Validator_Contract_Expansion.md`](../../docs/Rust_Evidence_Validator_Contract_Expansion.md)
for the full list of contract fields validated and the boundaries preserved.

## What it deliberately does NOT do

- It does **not** recompute or verify the keccak256 `etag` — no cryptographic
  truth claim is made or checked here. The TypeScript `validate:zk-response` pass
  remains the authoritative `etag == keccak256(adapter)` cross-check; re-deriving
  the canonical adapter hash in Rust is **deferred, not implemented**.
- It does **not** deeply validate the embedded `adapter` — only its top-level
  identity/version fields. Deep adapter validation (`proofInput`, `journal`,
  `proof`, `evidence`, …) stays in TypeScript (`validateAdapter`).
- It performs **no** network I/O, **no** prover execution, **no** SP1 SDK build,
  **no** signing, **no** key access, and **no** chain access.
- It does **not** publish, deploy, or operate any endpoint.

## Run it offline

CI runs `cargo fmt --check`, `cargo check`, and `cargo test` for this crate
offline (the `Check evidence-validator crate (offline)` job). Run the same checks
locally with `rustup`:

```bash
# from zkvm/evidence-validator/
cargo test                 # build + run unit and negative tests
cargo fmt --check          # formatting
cargo check                # type/borrow check

# validate a committed artifact from disk:
cargo run -- ../../evidence/zk/zk-adapter-evidence-response.example.json
# or a local scaffold fixture:
cargo run -- fixtures/zk-adapter-evidence-response.valid.json
```

Exit codes: `0` shape-valid, `1` invalid or unreadable, `2` usage error.

## Fixtures

`fixtures/` holds local, checked-in scaffold test material — **not** canonical
evidence artifacts. The valid fixture mirrors the committed TypeScript example
(`evidence/zk/zk-adapter-evidence-response.example.json`), and the tests also run
the validator against that canonical example directly for parity. Negative
fixtures cover malformed JSON, missing required fields (`etag`, `limitations`,
`regeneration`), wrong `schema`/`service` constants, `status`/`ok` inconsistency,
an out-of-range `servedAt`, an empty/bad `etag`, and a malformed or
wrong-identity `adapter`. All fixtures are local; the tests fetch nothing over
the network.
