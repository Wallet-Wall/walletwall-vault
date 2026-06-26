# Static Hosted Evidence Artifact — Reviewed Publishing Controls (Option A)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> This document **publishes nothing**. It is a **control plan / spec** that defines
> the reviewed host gate for a _future_ static publish of the committed Option A
> evidence artifact. It adds **no** GitHub Pages workflow, **no** CI publish/deploy
> step, **no** server, **no** network listener, **no** CDN upload, **no**
> infrastructure, **no** secret, **no** API key, **no** transaction, **no** deploy,
> **no** proving, and **no** chain call. Going live remains **gated** behind the
> security-review gate in the
> [target decision](Hosted_Evidence_Endpoint_Target_Decision.md).

This document defines the **reviewed publishing controls** — the host gate — that a
future, separately reviewed publish of the committed Option A static evidence
artifact must satisfy before any bytes are served from a real host.

It builds directly on:

- the [deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md) (options A–D,
  cache/ETag model, rollout phases, security boundaries),
- the [target decision](Hosted_Evidence_Endpoint_Target_Decision.md) (Option A
  selected; ten required controls; rollout gate; security-review gate), and
- the [committed static artifact](Static_Hosted_Evidence_Artifact.md) (#88 — the
  byte-for-byte artifact, its offline TypeScript validator, and the offline Rust
  re-check), which **publishes nothing**.

This PR adds the **controls plan and an offline docs guard** only. It is the
bridge between the committed-artifact scope (already merged) and a later,
separately reviewed **publish** PR. It does not perform or enable that publish.

## Publishing decision

**This PR publishes nothing.** It introduces only this control-plan document and a
static, offline docs guard test. In particular, this PR does **not**:

- add a GitHub Pages workflow, a CI publish/deploy step, or any release automation,
- stand up a server, a network listener, a CDN, or any hosted endpoint,
- add infrastructure, secrets, API keys, or credentials,
- change the committed artifact, its generator, or its validators,
- change any contract, ABI, deployment, or evidence semantics,
- add any private-app runtime fetch, connector, or plugin integration.

No artifact becomes live as a result of this PR. A live publish requires a separate,
reviewed implementation PR that satisfies every control below **and** passes the
[security-review gate](#security-review-gate).

## Source of truth

The only thing a future host may serve is the **checked-in** static artifact. Its
provenance chain is fixed and machine-checked, offline, before any publish:

1. **Checked-in artifact only.** The published bytes are exactly the committed file
   at the [artifact path](#artifact-path) — never a value generated, fetched, or
   transformed at request time.
2. **Generated from checked-in inputs.** The artifact is produced by
   `npm run static:artifact` from the committed canonical example, which is itself
   produced by `npm run zk:adapter:response` from the committed adapter, proof
   input, and ML-DSA evidence manifest. No network, no prover, no chain call
   participates in generation.
3. **Validated by the TypeScript validators.** `npm run validate:static-artifact`
   (and the upstream `npm run validate:zk-response`) enforce faithfulness, contract
   shape, keccak256 `etag` provenance, versioned path, and no drift.
4. **Validated by the Rust validator.** The offline
   [`zkvm/evidence-validator`](../zkvm/evidence-validator/) crate independently
   re-checks the same artifact's contract shape and canonical keccak256 ETag parity.
5. **ETag / canonical parity required before publish.** A publish may proceed only
   when the committed `etag` equals `keccak256(canonical adapter JSON)` per both the
   TypeScript and Rust validators, with no drift from the generator-of-record.

If any of these fail, no publish may proceed. The publish step has no authority to
regenerate, edit, or "fix" the artifact — it may only copy the validated checked-in
bytes.

### TypeScript validator role

`npm run validate:static-artifact` is the source-of-truth gate for the served bytes:
it asserts the artifact is byte-for-byte the canonical example, is a valid
`walletwall.zk-adapter-evidence-response.v1`, carries an `etag` equal to
`keccak256(adapter)`, lives under a versioned (`vN`) path, and has not drifted from
`npm run zk:adapter:response`. It runs in CI today and must pass immediately before
any future publish.

### Rust validator role

The offline [`zkvm/evidence-validator`](../zkvm/evidence-validator/) crate is the
independent, cross-language re-check: it loads the same artifact from disk and
asserts the deterministic contract shape and the canonical keccak256 ETag parity
(`keccak256(JSON.stringify(adapter))`, document key order). It performs no network,
RPC, chain, prover, server, or endpoint action; `#![forbid(unsafe_code)]` is set. It
must pass before any future publish, alongside the TypeScript validator. The crate's
own behavior and offline guarantees are described in
[Rust evidence validator ETag parity](Rust_Evidence_Validator_Etag_Parity.md).

## Artifact path

The single artifact in scope is the committed, versioned static file:

```text
evidence/zk/hosted/v1/zk-adapter-evidence-response.json
```

When a future publish proceeds, the host must serve **only** this artifact, at a
stable, versioned URL whose path mirrors the repo path (for example
`…/evidence/zk/hosted/v1/zk-adapter-evidence-response.json`). The `v1` segment lets a
stale consumer detect version drift. No other path, query parameter, or per-request
variant is in scope.

## Publish boundary

A future publish — and this control plan — hold these boundaries unconditionally:

- **GET-only static JSON.** The host serves the file via read-only GET only.
- **No mutation endpoint.** There is no POST/PUT/PATCH/DELETE surface.
- **No serverless write path.** No function may write, regenerate, or mutate the
  artifact.
- **No user-specific evidence.** Only the committed, deterministic artifact is served;
  no per-user, per-wallet, or per-request payload exists.
- **No wallet data collection.** The host receives and stores no wallet data.
- **No credentials or secrets.** The publish path reads no secret of any kind.
- **No API keys.** No API key is required or used by the host.
- **No RPC.** No JSON-RPC or node connection participates in serving the artifact.
- **No chain calls.** No on-chain read or write occurs in the publish or serve path.
- **No prover execution.** No SP1 / Groth16 / SNARK / STARK prover runs.
- **No app runtime proving.** The private app never executes a prover as a result of
  consuming the artifact.
- **No contract / ABI / deployment changes.** Nothing under `contracts/` and no
  deployment metadata changes for publishing.

## Hosting controls

The host configuration a future publish must satisfy:

- **Stable versioned path.** Serve at a versioned path such as
  `evidence/zk/hosted/v1/zk-adapter-evidence-response.json`; never overwrite a
  published version's bytes in place — cut a new `vN` instead.
- **HTTPS-only when hosted.** No plain-HTTP endpoint may serve the artifact.
- **Content type `application/json`.** The artifact already declares
  `"contentType": "application/json"`; the host must serve it with that content type.
- **Cache policy (documented).** Because the artifact is committed and deterministic,
  the host should serve it with a long-lived `Cache-Control` (max-age ≥ 1 hour)
  paired with conditional-GET revalidation. See [Cache and ETag](#cache-and-etag).
- **ETag behavior (documented).** The served strong validator must be derived from
  the committed bytes; the served `etag` field equals `keccak256(canonical adapter
  JSON)`, so the cache key and the served content can never disagree. See
  [Cache and ETag](#cache-and-etag).
- **CORS policy (documented).** If the private app later fetches cross-origin, CORS
  must allow read-only GET from the app origin only; no wildcard origin is permitted
  for production consumption. See [CORS](#cors). Cross-origin app consumption is not
  enabled in this PR.
- **No redirects to mutable/generated endpoints.** The published URL must not redirect
  to any dynamic, generated, or mutable endpoint.
- **No dynamic backend.** No dynamic backend, function, or request-time computation
  serves the artifact.

### Cache and ETag

- The artifact carries a strong `etag` equal to `keccak256` of the canonical adapter
  JSON; the cache key and the served content derive from the same bytes.
- A consumer fetches once, stores the `etag`, and sends `If-None-Match` on re-fetch.
  A matching `If-None-Match` should return `304 Not Modified` with no body; a stale one
  returns a fresh `200`.
- Because the artifact is committed and deterministic, a long-lived cache plus the
  strong `ETag`/`If-None-Match` revalidation pair is the intended model.
- `servedAt` is the only non-deterministic field and must **never** be used as a cache
  key — the `etag` is the cache key.
- A static host that does not honor `If-None-Match` natively is acceptable: the
  consumer then treats the `etag` purely as a content check. No request-time
  validation is assumed.

### CORS

- Cross-origin consumption is **not** enabled by this PR and not required by the
  committed-artifact scope.
- If and when the private app fetches the artifact cross-origin, the host must allow
  read-only GET from the app origin only. No wildcard (`*`) origin is permitted for
  production consumption. This is documented here so the future publish PR and its
  security review can confirm it; nothing here configures CORS.

## Release controls

The reviewed release process a future publish must follow:

- **Publishing requires a reviewed PR.** No artifact may be published except through a
  separate, reviewed implementation PR.
- **Artifact validation must pass before publish.** `npm run validate:static-artifact`
  (and `npm run validate:zk-response`) must pass in CI on the publish PR, immediately
  before any publish step.
- **Rust validator must pass before publish.** The offline `zkvm/evidence-validator`
  crate must pass (`cargo fmt --check` / `cargo check --locked` / `cargo test
  --locked`) on the publish PR before any publish step.
- **No manual artifact edits without validator drift checks.** The artifact may only
  change via `npm run zk:adapter:response` + `npm run static:artifact`; a hand-edited
  artifact is rejected by the drift and parity checks and must never be published.
- **Rollback process (documented).** See [Rollback](#rollback).
- **Incident / offline fallback (documented).** See
  [Incident and offline fallback](#incident-and-offline-fallback).
- **Status matrix updated conservatively.** The
  [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) must reflect, conservatively, that
  the artifact is committed and validated and that publishing remains gated until a
  reviewed publish PR and its security review land.

### Rollback

- The published artifact is a static file under version control; rollback is reverting
  to a previously committed, validated version of the artifact (or removing the
  published file) via a reviewed PR — there is no database, queue, or mutable state to
  unwind.
- Because each version lives under its own `vN` path, a bad publish is rolled back by
  re-pointing consumers to the prior `vN` and/or removing the new file; consumers that
  cannot reach the artifact fall back to their committed/local reference copy (see
  [Incident and offline fallback](#incident-and-offline-fallback)).
- A rollback never requires touching a secret, key, chain, prover, or contract.

### Incident and offline fallback

- If the host is unreachable, returns a non-200, serves an artifact that fails
  validation, or is taken down during an incident, the private app falls back to its
  committed/local reference copy and shows **no** degraded claim.
- The artifact is reference material, not a dependency for any safety-critical action;
  its absence changes no on-chain behavior and unlocks no funds. There is nothing to
  custody and nothing to lose if the host is offline.

## App consumption boundary

- **No private app runtime fetch in this PR.** This PR wires no app fetch of the
  artifact.
- **No connector / plugin integration in this PR.** This PR adds no connector, plugin,
  or integration of any kind.
- **App consumption is future work.** Any app consumption comes in a later, separate,
  reviewed **private app** PR, only after this host gate is reviewed. When it lands, it
  must be read-only, behind a feature flag, validate the payload shape and `etag`, send
  no wallet data or credentials, and fall back safely — per the
  [target decision](Hosted_Evidence_Endpoint_Target_Decision.md) app-consumption
  boundary.
- **Connector / plugin integration is future work.** Any connector or plugin remains
  out of scope until after this host gate and a separate review.
- **No production-ZK, mainnet-custody, or wallet-safety claims** result from consuming
  the artifact; the served adapter is read-only evidence, not a proof.

## Security-review gate

No production publish may be activated before a security review covers, at minimum:

- the static-hosting configuration: HTTPS redirect, headers, cache policy, CORS, and
  the exact published path,
- the publish step: trigger conditions, artifact provenance, and write-access scope,
- confirmation that no secret, key, or credential is reachable from the publish path,
- confirmation that `validate:static-artifact` and the Rust `evidence-validator` run
  and block publish on failure,
- the future app feature-flag gating and safe-fallback path.

The security review is **not** in scope for this control-plan PR. It is a hard gate on
the publish implementation PR and on any production publish activation, as stated in
the [target decision](Hosted_Evidence_Endpoint_Target_Decision.md).

## Safety boundaries preserved

This PR preserves every safety boundary of the lineage. It performs and enables:

- **no prover execution** and **no SP1 proving**,
- **no RPC** and **no chain calls**,
- **no HTTP fetching for artifact generation**,
- **no private keys**, **no credentials**, and **no API keys**,
- **no wallet data** collection,
- **no mutation endpoint** and **no serverless write path**,
- **no app integration** and **no private app changes**,
- **no contract / ABI / deployment changes**,
- **no production-ZK claims**, **no mainnet-custody claims**, and **no wallet-safety
  guarantees**,
- **no live proving** and **no dynamic endpoint deployment**,
- **no deployment-reproducibility claims** beyond the checked-in validators.

The served evidence is **post-quantum-aware**, read-only, gated, and off-chain. It is
**not** quantum-proof, **not** quantum-safe, **not** a quantum-resistant platform,
**not** guaranteed, **not** insured, holds **no** protected funds, produces **no** real
yield, is **not** production custody, is **not** mainnet-ready, and is **not** audited.

## Acceptance criteria

- [x] This control-plan document exists at
      `docs/Static_Hosted_Evidence_Publishing_Controls.md`.
- [x] It states plainly that **this PR publishes nothing**.
- [x] It identifies the static artifact path
      `evidence/zk/hosted/v1/zk-adapter-evidence-response.json`.
- [x] It defines the source-of-truth, publish-boundary, hosting, release, and
      app-consumption controls.
- [x] It documents the TypeScript validator role and the Rust validator role.
- [x] It documents the cache/ETag policy and the CORS policy.
- [x] It documents the rollback process and the incident/offline fallback.
- [x] It states that the security review is a hard gate before any publish.
- [x] It states that app consumption and connector/plugin integration are future work.
- [x] It carries the prototype/testnet/not-audited/no-real-funds disclaimer and uses no
      forbidden overclaim language in affirmative form.
- [x] The README documentation map points to this doc, and the docs guard test passes.
- [x] `package.json` is bumped one patch version.
- [ ] **A live publish is not in scope** — it requires a separate, reviewed publish
      implementation PR and the security review named in the target decision.

## Related

- [Static hosted evidence artifact (Option A)](Static_Hosted_Evidence_Artifact.md) —
  the committed artifact, its TypeScript validator, and the offline Rust re-check
  (#88). Publishes nothing.
- [Hosted evidence endpoint target decision: Option A](Hosted_Evidence_Endpoint_Target_Decision.md) —
  selects Option A; lists the ten required controls, the rollout gate, and the
  security-review gate this plan operationalizes.
- [Hosted evidence endpoint deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md) —
  the cache/ETag model, options A–D, rollout phases, and security boundaries.
- [ZK adapter evidence endpoint](ZK_Adapter_Evidence_Endpoint.md) — the read-only
  response-shape contract this artifact is an instance of.
- [Rust evidence validator ETag parity](Rust_Evidence_Validator_Etag_Parity.md) — the
  offline Rust crate that independently re-checks the artifact.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — the single source of truth for what
  exists vs does not.
