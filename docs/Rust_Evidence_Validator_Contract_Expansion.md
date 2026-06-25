# Rust Evidence Validator — Contract-Validation Expansion (Phase 1)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> **Scaffold / offline only.** This document describes a conservative,
> deterministic expansion of the Phase 1 Rust evidence validator
> ([`zkvm/evidence-validator/`](../zkvm/evidence-validator/)). CI compiles and
> tests the crate offline, but it is **not** a cryptographic verifier: it deploys
> nothing, adds no server, no network listener, no secrets, and no API keys. CI
> verifies only that the crate compiles and its contract-shape checks pass — never
> cryptographic truth, proving, endpoint behavior, or production readiness.

This expansion stays strictly inside **Phase 1 — Rust crate boundary** of
[Rust_Implementation_Path.md](Rust_Implementation_Path.md) and builds directly on
[Rust_Evidence_Tooling_Scaffold.md](Rust_Evidence_Tooling_Scaffold.md). It makes
the existing offline validator more useful by checking more of the deterministic
contract, while keeping every safety boundary the scaffold already honoured.

- **Crate:** [`zkvm/evidence-validator/`](../zkvm/evidence-validator/)
- **Validates the contract:** `walletwall.zk-adapter-evidence-response.v1`
  (see [ZK_Adapter_Evidence_Endpoint.md](ZK_Adapter_Evidence_Endpoint.md) and the
  schema at
  [`evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`](../evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json))

## What is now validated (deterministic contract shape)

The validator reads one committed evidence JSON artifact **from disk** and checks
its deterministic shape against the response contract. Alongside the original
scaffold checks (required fields, closed top-level shape via `deny_unknown_fields`,
constant values), it now validates:

- **Fixed contract constants** — `schema`, `service`, `mode`, `contentType`, and
  `status == 200` each hold their documented constant values.
- **`status` / `ok` internal consistency** — a 2xx status requires `ok == true`,
  and any non-2xx status requires `ok == false`; a disagreeing pair is rejected.
- **`servedAt` timestamp form and range** — it must be an ISO-8601 UTC instant of
  the contracted form (`YYYY-MM-DDTHH:MM:SS[.mmm]Z`) with in-range calendar/time
  components (month `01`–`12`, day `01`–`31`, hour `00`–`23`, minute/second
  `00`–`59`).
- **`etag` presence and form** — it must be present, non-empty, and match
  `^0x[0-9a-f]{64}$`.
- **`adapter` identity / version fields** — the embedded adapter must be an object
  carrying its required identity/version constants (`schema ==
  walletwall.zk-verifier-adapter.v1` and `artifactType ==
  zk-verifier-adapter-boundary`).
- **`limitations`** — present and a non-empty array of non-empty strings.
- **`regeneration`** — present, with a non-empty `command` and `deterministic ==
  true` (the only two fields the contract defines for it).

The CLI prints a deterministic success/failure summary and exits `0` on success,
`1` on a validation or read failure, and `2` on a usage error. It prints no
secrets, keys, wallet data, or environment values.

## What remains shape / contract validation only

This expansion is still **contract-shape validation, not cryptographic truth**:

- The `etag` is checked for **form only**. The validator does **not** recompute or
  verify the keccak256 content hash, and makes **no** cryptographic truth claim.
  The canonical adapter-canonicalization + keccak256 algorithm lives in TypeScript
  (`scripts/lib/zk-adapter-endpoint.ts`); re-deriving it in Rust is **deferred,
  not implemented**, so no cryptographic semantics are invented here.
- The embedded `adapter` is checked for its **top-level identity/version fields
  only**. Deep adapter validation (`proofInput`, `journal`, `proof`, `evidence`,
  …) stays the authoritative TypeScript `validateAdapter` pass's responsibility.
- The TypeScript `validate:*` scripts remain the CI source of truth. This crate
  **relaxes no existing validation**; it only adds an independent, offline,
  deterministic second check.

## What is NOT verified or claimed

- **No proof is generated** and no prover runs. There is **no prover execution**,
  no SP1 prove path, and no Groth16 proof here; heavy proving stays gated behind
  `RUN_SP1_E2E=1` in the existing host crate, untouched.
- **No cryptographic verification.** No keccak256 recompute, no signature check,
  no on-chain ML-DSA verification, and **no live proving**.
- **No network or RPC.** The crate performs **no network** I/O and **no RPC**
  call; it reads a local file and exits.
- **No endpoint deployment.** It deploys, starts, and operates no server,
  listener, or HTTP service, and publishes no artifact to any external host. No
  GitHub Pages and no serverless code are added; there is **no active endpoint
  deployment**.
- **No contract or ABI changes.** It modifies no Solidity contract, no ABI, and no
  deployed contract address; it touches nothing under `contracts/`, and it makes
  no deployment-configuration change.
- **No evidence semantic changes.** It alters no schema or field meaning of any
  existing evidence artifact type; the response contract is unchanged.
- **No production-ZK, no mainnet custody, no wallet-safety, and no
  deployment-reproducibility claims.** This is **not production zk**, makes **no
  mainnet custody** claim, offers **no** wallet-safety guarantee, and asserts **no
  deployment-reproducibility**. `#![forbid(unsafe_code)]` is set crate-wide, so
  there is no `unsafe` block.

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
cargo test                  # build + run unit and negative tests
cargo fmt --check           # formatting
cargo check                 # type / borrow check

# validate the committed example artifact from disk:
cargo run -- ../../evidence/zk/zk-adapter-evidence-response.example.json
# or a local scaffold fixture:
cargo run -- fixtures/zk-adapter-evidence-response.valid.json
```

No flag enables a network, prover, or chain path; none exists. Tests use local,
checked-in fixtures only — the suite fetches nothing over the network.

## Relationship to the Rust implementation path

This work is **Phase 1 — Rust crate boundary** only, within the permission granted
by [Rust_Implementation_Path.md](Rust_Implementation_Path.md). It does **not**
implement Phase 2 (canonical keccak256 parity), Phase 3 (adapter re-derivation),
Phase 4 (reviewed prover path), or Phase 5 (hosted artifact integration). Each
later phase still needs its own separate, reviewed PR.

## Related

- [Rust evidence tooling scaffold](Rust_Evidence_Tooling_Scaffold.md) — the Phase 1
  scaffold this expansion builds on.
- [Rust implementation path](Rust_Implementation_Path.md) — the bounded role and
  phased rollout (Phase 1).
- [ZK adapter evidence endpoint](ZK_Adapter_Evidence_Endpoint.md) — the read-only
  response-shape contract this crate validates.
- [ZK verifier adapter boundary](ZK_Verifier_Adapter_Boundary.md) — the embedded
  adapter artifact, deeply validated in TypeScript.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — the single source of truth for
  what exists vs what is claimed.
- [SECURITY.md](../SECURITY.md) — prototype status, scope, and reporting.
