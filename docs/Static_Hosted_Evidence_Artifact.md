# Static Hosted Evidence Artifact — Option A (Implementation)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> This change **publishes nothing**. It adds a committed local file, an offline
> validator, and CI wiring. There is **no server**, no network listener, no
> **GitHub Pages** deploy, no CDN upload, no infrastructure, no secret, no API key,
> no transaction, no deploy, no proving, and no chain call. Going live remains
> gated behind the security-review gate in the
> [target decision](Hosted_Evidence_Endpoint_Target_Decision.md).

This document describes the **first committed static evidence artifact** for
**Option A — static JSON from GitHub Pages or an equivalent static host**, the
target selected in the
[hosted evidence endpoint target decision](Hosted_Evidence_Endpoint_Target_Decision.md)
and planned in the
[deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md).

It materializes the bytes a static host **would** serve and proves, **offline**,
that those bytes are a faithful, valid, ETag-correct copy served from a versioned
path. It does **not** activate any endpoint.

## Purpose

Option A serves the committed
`walletwall.zk-adapter-evidence-response.v1` example
([`evidence/zk/zk-adapter-evidence-response.example.json`](../evidence/zk/zk-adapter-evidence-response.example.json))
byte-for-byte from a stable, versioned static URL. Before any live publish, the
exact bytes to be served — and the controls they must satisfy — should be
committed and continuously validated. This artifact is that committed,
machine-checked representation.

## What this adds

- **A committed static artifact** at the versioned path
  `evidence/zk/hosted/v1/zk-adapter-evidence-response.json`. It is **byte-for-byte
  identical** to the canonical example it copies; it is the literal payload a
  static host would serve.
- **An offline generator + validator** (`scripts/generate-static-evidence-artifact.ts`):
  - `npm run static:artifact` — (re)write the committed static artifact from the
    canonical example.
  - `npm run validate:static-artifact` — validate the committed artifact and exit
    non-zero if it is missing, drifted, invalid, mis-ETagged, or not versioned.
- **CI wiring** — a `Validate static hosted evidence artifact` step runs
  `validate:static-artifact` on every PR, alongside the existing
  `validate:zk-response` check.
- **Cross-language validation** — the offline Rust
  [`zkvm/evidence-validator`](../zkvm/evidence-validator/) crate loads the static
  artifact and asserts it passes the same deterministic contract-shape and
  canonical keccak256 ETag-parity check as the canonical example.

## What this does not do

This change **publishes nothing**. In particular it does **not**:

- run a server, a network listener, or any deployed service,
- add **GitHub Pages** configuration, a CI publish/deploy step, infrastructure,
  secrets, API keys, or credentials,
- perform any transaction, deploy, on-chain write, or chain call,
- run a prover, generate a proof, or execute the SP1 toolchain,
- fetch over HTTP/RPC, read any private key, or change any contract, ABI,
  deployment, or evidence semantics,
- change the private app or wire any app integration,
- make any production, mainnet-custody, wallet-safety, or
  deployment-reproducibility claim.

## Validation (offline, deterministic)

`npm run validate:static-artifact` enforces, with no network and no publish:

1. **Exact artifact** — the static artifact is byte-for-byte the committed
   canonical example (it can never serve a divergent or stale copy).
2. **Valid contract shape** — it is a valid
   `walletwall.zk-adapter-evidence-response.v1` (the same strict
   `validateAdapterEvidenceResponse` pass the canonical example uses: shape,
   embedded-adapter validity, limitations coverage, and absence of overclaim
   language on asserted surfaces).
3. **ETag provenance** — its `etag` equals `keccak256(canonical adapter JSON)`.
4. **Versioned path** — the artifact lives under a `vN` path segment so a stale
   consumer can detect version drift.
5. **No drift** — it matches the canonical generator-of-record
   (`npm run zk:adapter:response`).

The Rust `zkvm/evidence-validator` crate independently re-checks (2) and (3) on the
same file, offline. The TypeScript `validate:zk-response` pass remains the source of
truth for the canonical example.

## Controls (committed-artifact scope vs gated for live publish)

The [target decision](Hosted_Evidence_Endpoint_Target_Decision.md) lists ten
required controls. This PR satisfies the **artifact-side** controls and leaves the
**hosting-side** controls explicitly gated for a later, separately reviewed publish:

| Control | Here (offline) | Status |
| --- | --- | --- |
| Exact artifact (byte-for-byte committed file) | enforced by `validate:static-artifact` | ✅ committed-artifact scope |
| ETag provenance (`keccak256(adapter)`) | enforced by TS + Rust validators | ✅ committed-artifact scope |
| Versioned path | enforced (`v1` segment) | ✅ committed-artifact scope |
| Limitations block preserved | enforced (the artifact retains `limitations[]`) | ✅ committed-artifact scope |
| CI gate fails on invalid artifact | `validate:static-artifact` in CI | ✅ committed-artifact scope |
| GET-only / HTTPS-only host | not in scope — no host is configured here | ⛔ gated for live publish |
| Long-lived cache + strong ETag headers | not in scope — no host serves the file here | ⛔ gated for live publish |
| CORS (read-only GET from app origin) | not in scope — no host, no app integration | ⛔ gated for live publish |

The live-publish controls remain gated behind the **security-review gate** in the
target decision. Nothing here activates them.

## Regeneration

```bash
npm run zk:adapter:response     # regenerate the canonical example (if the adapter changed)
npm run static:artifact         # copy the canonical example to the versioned static path
npm run validate:static-artifact  # verify the committed static artifact (offline)
```

## Limitations

- **Publishes nothing** — this is a committed file plus an offline validator; it
  ships no server, no listener, and no deployed-service requirement.
- **Read-only reference material** — the served evidence is gated and off-chain;
  the embedded adapter carries no real proof and does not perform on-chain ML-DSA
  verification (the active on-chain SP1 verifier is a mock).
- **Research prototype — not audited.**
- **Testnet / reference path only** — no mainnet deployment and no production
  custody.
- **No real funds** — every referenced artifact is deterministic test/fixture
  material.

## Acceptance criteria

- [x] The static artifact exists at `evidence/zk/hosted/v1/zk-adapter-evidence-response.json`.
- [x] It is byte-for-byte identical to the canonical example.
- [x] It is a valid `walletwall.zk-adapter-evidence-response.v1` with a matching
      keccak256 `etag`, served from a versioned path.
- [x] `npm run validate:static-artifact` validates it and runs in CI.
- [x] The Rust `zkvm/evidence-validator` crate loads and validates it.
- [x] This doc carries the prototype/testnet/not-audited/no-real-funds disclaimer
      and uses no forbidden overclaim language in affirmative form.
- [x] The README documentation map points to this doc.
- [x] `package.json` is bumped one patch version.
- [ ] **Live publish is not in scope** — it requires a separate implementation PR
      and the security review named in the target decision.

## Related

- [Hosted evidence endpoint target decision: Option A](Hosted_Evidence_Endpoint_Target_Decision.md) —
  selects Option A and lists the required controls and the security-review gate.
- [Hosted evidence endpoint deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md) —
  the contract, artifact generation, validation, cache/ETag, and rollout phases.
- [ZK adapter evidence endpoint](ZK_Adapter_Evidence_Endpoint.md) — the in-process
  read-only contract this artifact is an instance of.
- [Rust evidence validator ETag parity](Rust_Evidence_Validator_Etag_Parity.md) —
  the offline Rust crate that independently re-checks the artifact.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — what exists vs does not.
