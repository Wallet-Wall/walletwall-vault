# Static Hosted Evidence Artifact — Reviewed Publish Workflow (Option A)

> ⚠️ **Research prototype. Not audited. Testnet/local only. No real funds.**
> Merging this change **publishes nothing**. It adds a **manual-dispatch-only**,
> validation-gated GitHub Actions workflow plus an offline staging script for a
> _future_ static publish of the committed Option A evidence artifact. There is **no**
> push/schedule publish trigger, **no** server, **no** network listener, **no** CDN
> upload at merge time, **no** secret, **no** API key, **no** transaction, **no**
> deploy, **no** proving, and **no** chain call. Going live remains **gated** behind
> the security-review gate in the
> [target decision](Hosted_Evidence_Endpoint_Target_Decision.md).

This document describes the **reviewed publish workflow** that operationalizes the
[publishing controls](Static_Hosted_Evidence_Publishing_Controls.md) for **Option A —
static JSON from GitHub Pages or an equivalent static host**. It is the implementation
that copies the **already-checked-in** static artifact into a controlled staging
directory, validates it, and — only under explicit, protected, manual approval —
deploys exactly that one file.

It builds directly on:

- the [deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md) (options A–D,
  cache/ETag model, rollout phases, security boundaries),
- the [target decision](Hosted_Evidence_Endpoint_Target_Decision.md) (Option A
  selected; ten required controls; rollout gate; security-review gate),
- the [committed static artifact](Static_Hosted_Evidence_Artifact.md) (#88 — the
  byte-for-byte artifact, its offline TypeScript validator, and the offline Rust
  re-check), and
- the [publishing controls](Static_Hosted_Evidence_Publishing_Controls.md) (#89 — the
  reviewed host gate / control plan this workflow implements).

## Publishing decision

**Merging this PR publishes nothing.** It adds a workflow that has **no push,
schedule, or release trigger** — only `workflow_dispatch` (manual). A deploy occurs
**only** when **all** of the following are true:

- a maintainer **manually** runs the workflow with the `publish` input set to `true`
  (the default, `false`, validates and stages the artifact as a **dry run** and
  deploys nothing), **and**
- the protected `github-pages` **environment** approval is granted (a human-configured
  required-reviewer gate — the operational form of the security-review gate), **and**
- GitHub Pages is enabled for the repository by a maintainer.

Until a maintainer takes all three actions, **nothing is served**. This PR therefore
publishes nothing on its own; it builds the gated mechanism only.

## Workflow

The workflow lives at
[`.github/workflows/publish-static-evidence.yml`](../.github/workflows/publish-static-evidence.yml)
(`Publish static hosted evidence (manual, gated)`). It has three jobs:

1. **`validate-and-stage`** — installs dependencies, runs the TypeScript validators,
   stages **only** the one approved artifact via `npm run static:publish:prepare`, and
   uploads the staging directory as a Pages artifact.
2. **`evidence-validator`** — independently re-checks the offline Rust
   `zkvm/evidence-validator` crate with `--locked` (`cargo fmt --check` /
   `cargo check --locked` / `cargo test --locked`).
3. **`deploy`** — runs **only** when `publish` is `true`, `needs` both validation jobs,
   and runs inside the protected `github-pages` environment. It serves the uploaded
   staging directory and nothing else.

The top-level workflow permission is read-only (`contents: read`); only the `deploy`
job widens scope to the `pages: write` / `id-token: write` that GitHub Pages requires.
The workflow references **no** repository secret.

## Artifact source path

The single artifact in scope is the committed, versioned static file:

```text
evidence/zk/hosted/v1/zk-adapter-evidence-response.json
```

The publish path may serve **only** this file. It is never a value generated, fetched,
or transformed at request time. The `v1` segment lets a stale consumer detect version
drift.

## Staged and published path

`npm run static:publish:prepare`
([`scripts/prepare-static-evidence-publish.ts`](../scripts/prepare-static-evidence-publish.ts))
copies the checked-in artifact, byte-for-byte, into a controlled, gitignored staging
directory, mirroring the repo path:

```text
dist/hosted-evidence/evidence/zk/hosted/v1/zk-adapter-evidence-response.json
```

The staging step removes any prior staging tree first, so the staged tree can contain
**only** the one approved file, and then fails if the staged bytes differ from the
checked-in bytes or if any extra file is present. The workflow uploads exactly the
`dist/hosted-evidence` directory; there is no wildcard copy.

When a future, approved deploy proceeds, the host serves the file at a stable,
versioned URL whose path mirrors the repo path — for example
`…/evidence/zk/hosted/v1/zk-adapter-evidence-response.json`. **No live URL is produced
by merging this PR**, so none is asserted here; the exact origin is fixed when a
maintainer enables Pages and the protected deploy runs.

## Validation gates before publish

Every gate below must pass before the gated `deploy` job can run. The `deploy` job
`needs` both validation jobs, so a failure in either blocks any publish:

- `npm run validate:zk-response` — the canonical example is faithful, ETag-correct, and
  has not drifted.
- `npm run validate:static-artifact` — the committed static artifact is byte-for-byte
  the canonical example, a valid `walletwall.zk-adapter-evidence-response.v1`, with an
  `etag` equal to `keccak256(adapter)`, served from a versioned path, with no drift.
- `npm run static:publish:prepare` — stages only the approved artifact and fails on any
  drift or extra file.
- The Rust `zkvm/evidence-validator` crate, `--locked` (`cargo fmt --check`,
  `cargo check --locked`, `cargo test --locked`).

### TypeScript validator role

`npm run validate:static-artifact` is the source-of-truth gate for the served bytes: it
asserts the artifact is byte-for-byte the canonical example, is a valid
`walletwall.zk-adapter-evidence-response.v1`, carries an `etag` equal to
`keccak256(adapter)`, lives under a versioned (`vN`) path, and has not drifted from
`npm run zk:adapter:response`. The staging script
(`npm run static:publish:prepare`) then re-asserts the staged bytes equal the
checked-in bytes. Both run before the deploy job.

### Rust validator role

The offline [`zkvm/evidence-validator`](../zkvm/evidence-validator/) crate is the
independent, cross-language re-check: it loads the same artifact from disk and asserts
the deterministic contract shape and the canonical keccak256 ETag parity
(`keccak256(JSON.stringify(adapter))`, document key order). It performs no network,
RPC, chain, prover, server, or endpoint action; `#![forbid(unsafe_code)]` is set. Its
behavior is described in
[Rust evidence validator ETag parity](Rust_Evidence_Validator_Etag_Parity.md).

## Cache and ETag

- The artifact carries a strong `etag` equal to `keccak256` of the canonical adapter
  JSON; the cache key and the served content derive from the same bytes.
- A consumer fetches once, stores the `etag`, and sends `If-None-Match` on re-fetch. A
  matching `If-None-Match` should return `304 Not Modified` with no body; a stale one
  returns a fresh `200`.
- Because the artifact is committed and deterministic, a long-lived `Cache-Control`
  (max-age ≥ 1 hour) plus the strong `ETag` / `If-None-Match` revalidation pair is the
  intended model.
- `servedAt` is the only non-deterministic field and must **never** be used as a cache
  key — the `etag` is the cache key.
- A static host that does not honor `If-None-Match` natively is acceptable: the
  consumer then treats the `etag` purely as a content check.

## CORS

- Cross-origin consumption is **not** enabled by this PR and not required by the
  committed-artifact scope.
- If and when the private app fetches the artifact cross-origin, the host must allow
  read-only GET from the app origin only. No wildcard (`*`) origin is permitted for
  production consumption. Nothing here configures CORS; this is documented so the
  security review can confirm it on a future deploy.

## Rollback

- The published artifact is a static file under version control; rollback is reverting
  to a previously committed, validated version of the artifact (or removing the
  published file) via a reviewed PR, then re-running the gated deploy — there is no
  database, queue, or mutable state to unwind.
- Because each version lives under its own `vN` path, a bad publish is rolled back by
  re-pointing consumers to the prior `vN` and/or removing the new file. Consumers that
  cannot reach the artifact fall back to their committed/local reference copy and show
  no degraded claim.
- A rollback never requires touching a secret, key, chain, prover, or contract.

## Manual approval and protected environment

- The workflow is **manual-dispatch only** (`workflow_dispatch`). There is no automatic
  publish on `main`.
- The `deploy` job runs in the protected `github-pages` environment. Configuring that
  environment with **required reviewers** is the operational form of the
  security-review gate: a human must approve each deploy. This document does not, and
  cannot, configure those reviewers — a maintainer does so in repository settings.
- The explicit `publish` input is a second, independent gate: a default run
  (`publish: false`) validates and stages only, and deploys nothing.

## App consumption boundary

- **No private app runtime fetch in this PR.** This PR wires no app fetch of the
  artifact.
- **No connector / plugin integration in this PR.** This PR adds no connector, plugin,
  or integration of any kind.
- **App consumption is future work.** Any app consumption comes in a later, separate,
  reviewed **private app** PR, only after this publish path is reviewed. When it lands,
  it must be read-only, behind a feature flag, validate the payload shape and `etag`,
  send no wallet data or credentials, and fall back safely.
- **Connector / plugin integration is future work.** Any connector or plugin remains
  out of scope until after a separate review.
- **No production-ZK, mainnet-custody, or wallet-safety claims** result from consuming
  the artifact; the served adapter is read-only evidence, not a proof.

## Disabling and rolling back publishing

- **Nothing is live until a maintainer acts.** Because the workflow is manual-dispatch
  only, simply not running it leaves the artifact unpublished.
- **To disable publishing**, a maintainer can disable the
  `Publish static hosted evidence (manual, gated)` workflow in the Actions tab, remove
  the protected-environment reviewers' approval, disable GitHub Pages for the repo, or
  delete the workflow file in a reviewed PR. Any one of these prevents a deploy.
- **To roll back a deploy that already ran**, follow [Rollback](#rollback): revert to a
  prior validated `vN` artifact or remove the published file and re-run the gated
  deploy; consumers fall back to their committed/local copy meanwhile.

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

- [x] This workflow document exists at
      `docs/Static_Hosted_Evidence_Publish_Workflow.md`.
- [x] It states plainly that **merging this PR publishes nothing** and what would be
      published, if anything, under explicit manual + protected-environment approval.
- [x] It identifies the source artifact path
      `evidence/zk/hosted/v1/zk-adapter-evidence-response.json` and the staged/published
      path `dist/hosted-evidence/evidence/zk/hosted/v1/zk-adapter-evidence-response.json`.
- [x] It documents the validation gates that run before publish, including the
      TypeScript validator role and the Rust validator role.
- [x] It documents the cache/ETag policy and the CORS policy.
- [x] It documents the rollback process and how to disable publishing.
- [x] It documents the manual-dispatch + protected-environment approval behavior.
- [x] It states that app consumption and connector/plugin integration are future work.
- [x] It carries the prototype/testnet/not-audited/no-real-funds disclaimer and uses no
      forbidden overclaim language in affirmative form.
- [x] The README documentation map points to this doc, the workflow/staging guard test
      passes, and `package.json` is bumped one patch version.
- [ ] **A live publish is not in scope of merging this PR** — it requires a maintainer
      to enable Pages, configure the protected environment, and manually approve a
      deploy, per the security-review gate in the target decision.

## Related

- [Static hosted evidence publishing controls (Option A)](Static_Hosted_Evidence_Publishing_Controls.md) —
  the reviewed host gate / control plan this workflow implements (#89).
- [Static hosted evidence artifact (Option A)](Static_Hosted_Evidence_Artifact.md) —
  the committed artifact, its TypeScript validator, and the offline Rust re-check (#88).
- [Hosted evidence endpoint target decision: Option A](Hosted_Evidence_Endpoint_Target_Decision.md) —
  selects Option A; lists the required controls, the rollout gate, and the
  security-review gate this workflow runs behind.
- [Hosted evidence endpoint deployment plan](Hosted_Evidence_Endpoint_Deployment_Plan.md) —
  the cache/ETag model, options A–D, rollout phases, and security boundaries.
- [Rust evidence validator ETag parity](Rust_Evidence_Validator_Etag_Parity.md) — the
  offline Rust crate that independently re-checks the artifact.
- [ZK / PQ status matrix](ZK_PQ_Status_Matrix.md) — the single source of truth for what
  exists vs does not.
