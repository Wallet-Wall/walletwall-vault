# SP1 host lockfile advisories (zkvm/host RustSec record)

**Status:** `ASSESSMENT_VALID` for designation `mldsa65-withdrawal-d1` (zkvm/host tree `30f72596`), and, separately,
`NOT_DEPENDENCY_SAFE`. **Owner decision (2026-10-16):** `HOST_LOCKFILE_REMEDIATION = DEFER_TO_NEXT_PROGRAM_REBUILD`.

> An advisory record establishes what was assessed and why. It does not make a vulnerable dependency non-vulnerable.
> This is not a security waiver: every finding below is still locked in `zkvm/host/Cargo.lock`, and nothing here
> patches, updates or suppresses anything.

Research prototype. Not audited. Testnet/local only. Do not use real funds.

| | |
|---|---|
| Record (generated, never hand-edited) | [`evidence/zk/sp1-impl/host-lockfile-advisories.json`](../evidence/zk/sp1-impl/host-lockfile-advisories.json) |
| Observation (measured) | [`evidence/zk/sp1-impl/observations/host-advisories-developer-workstation.raw.json`](../evidence/zk/sp1-impl/observations/host-advisories-developer-workstation.raw.json) |
| Claims (reviewed judgment) | [`scripts/lib/sp1-host-advisories.ts`](../scripts/lib/sp1-host-advisories.ts) (`CLAIMS`, `ASSUMPTIONS`, `FEATURE_FACTS`, `SOURCE_FACTS`) |
| Blocking, offline check | `npm run validate:sp1-host-advisories` in CI's `Build, lint & test` |
| Reporting, networked check | [`.github/workflows/rustsec-audit.yml`](../.github/workflows/rustsec-audit.yml): weekly, and on PRs touching Rust manifests, lockfiles or this record; **not** a required check |

## What was found

`cargo audit` (0.22.2, advisory-db `64f92cdc`, `--no-yanked`, with yanked status read from the crates.io index) reports
**22 findings** in `zkvm/host/Cargo.lock`: 12 vulnerabilities and 10 warnings (3 unsound, 1 yanked, 6 unmaintained).

| Bucket | Findings | Meaning |
|---|---:|---|
| `MUST_FIX_BEFORE_REAL_PROVING` | 0 | none is reachable on the frozen proving path |
| `SHOULD_FIX_BEFORE_PRODUCTION` | 8 | compiled, and fixable by a lockfile-only update or reachable only on a path the frozen configuration excludes; deferred to the next program rebuild |
| `NOT_REACHABLE_OR_UPSTREAM_ONLY` | 14 | not compiled, a precondition measured absent with no compatible fix, or unmaintained (no fix exists) |

| Finding | Kind | Compiled | Reachability | Bucket | Fix |
|---|---|---|---|---|---|
| `RUSTSEC-2026-0204 crossbeam-epoch@0.9.18` | vulnerability | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.9.21 |
| `RUSTSEC-2026-0258 h2@0.4.14` | vulnerability | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.4.20 |
| `RUSTSEC-2026-0185 quinn-proto@0.11.14` | vulnerability | **no** | NOT_COMPILED | NOT_REACHABLE_OR_UPSTREAM_ONLY | lockfile-only → 0.11.19 |
| `RUSTSEC-2026-0338 quinn-proto@0.11.14` | vulnerability | **no** | NOT_COMPILED | NOT_REACHABLE_OR_UPSTREAM_ONLY | lockfile-only → 0.11.19 |
| `RUSTSEC-2026-0339 quinn-proto@0.11.14` | vulnerability | **no** | NOT_COMPILED | NOT_REACHABLE_OR_UPSTREAM_ONLY | lockfile-only → 0.11.19 |
| `RUSTSEC-2026-0340 quinn-proto@0.11.14` | vulnerability | **no** | NOT_COMPILED | NOT_REACHABLE_OR_UPSTREAM_ONLY | lockfile-only → 0.11.19 |
| `RUSTSEC-2026-0342 quinn-proto@0.11.14` | vulnerability | **no** | NOT_COMPILED | NOT_REACHABLE_OR_UPSTREAM_ONLY | lockfile-only → 0.11.19 |
| `RUSTSEC-2026-0285 rustls@0.23.40` | vulnerability | yes | CONDITIONAL | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.23.46 |
| `RUSTSEC-2026-0346 rustls@0.23.40` | vulnerability | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.23.46 |
| `RUSTSEC-2026-0348 rustls@0.23.40` | vulnerability | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.23.46 |
| `RUSTSEC-2026-0349 rustls@0.23.40` | vulnerability | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.23.46 |
| `RUSTSEC-2026-0344 ruzstd@0.8.3` | vulnerability | yes | PRECONDITION_ABSENT | NOT_REACHABLE_OR_UPSTREAM_ONLY | upstream-blocked (object v0.37.3 requires ruzstd = "^0.8.1") |
| `RUSTSEC-2026-0002 lru@0.12.5` | unsound | yes | PRECONDITION_ABSENT | NOT_REACHABLE_OR_UPSTREAM_ONLY | upstream-blocked (sp1-prover v6.3.1 requires lru = "^0.12.4") |
| `RUSTSEC-2026-0253 lru@0.12.5` | unsound | yes | PRECONDITION_ABSENT | NOT_REACHABLE_OR_UPSTREAM_ONLY | upstream-blocked (sp1-prover v6.3.1 requires lru = "^0.12.4") |
| `RUSTSEC-2026-0186 memmap2@0.9.10` | unsound | yes | PRECONDITION_ABSENT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.9.11 |
| `yanked spin@0.9.8` | yanked | yes | NO_KNOWN_DEFECT | SHOULD_FIX_BEFORE_PRODUCTION | lockfile-only → 0.9.9 |
| `RUSTSEC-2021-0139 ansi_term@0.12.1` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |
| `RUSTSEC-2025-0141 bincode@1.3.3` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |
| `RUSTSEC-2025-0119 number_prefix@0.4.0` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |
| `RUSTSEC-2024-0436 paste@1.0.15` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |
| `RUSTSEC-2026-0173 proc-macro-error2@2.0.1` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |
| `RUSTSEC-2025-0134 rustls-pemfile@2.2.0` | unmaintained | yes | NO_KNOWN_DEFECT | NOT_REACHABLE_OR_UPSTREAM_ONLY | no patched release |

The record carries, per finding, the advisory as RustSec states it, the dependency edge (direct dependents, the first
path to `mldsa65-host`, whether it is a proc-macro), the exploit precondition, WalletWall's rationale, the evidence ids
it rests on, the measured fix facts and the disposition (`DEFERRED_TO_NEXT_PROGRAM_REBUILD` for all 22).

## A lockfile is not the build graph

`cargo audit` audits every package in `Cargo.lock`. Cargo records a package there when any feature combination could
need it, including an optional crate that a weak dependency feature names (`dep?/feature`) while nothing enables it.
reqwest's rustls feature names `quinn?/ring`; reqwest's `http3` feature, the only one that enables quinn, is off; so
`quinn-proto` (5 advisories) is locked but compiled for no target: `cargo tree --target all -e normal,build,dev -i
quinn-proto@0.11.14` prints nothing. The observation records that output for every finding, and `compiled` is read from
it, never typed.

## Why the compiled findings are not reachable today

Each `PRECONDITION_ABSENT` or `CONDITIONAL` claim names the evidence it rests on, and supports nothing unless every
item holds. Evidence is of three kinds:

- **Assumptions** over this repository's bytes, re-evaluated on every check: the host manifest's exact shape; sp1-sdk
  `=6.3.1` with features `["blocking"]` only (no `network`, `cuda` or `native-gnark`); no network-only, `aws-lc`,
  `brotli` or `sp1-cuda` crate in the lockfile; backtrace locked without ruzstd; `src/main.rs` proving only with
  `.groth16()`; proving availability either `OWNER_DOWNLOAD_REQUIRED` with no WalletWall archive record and no local
  copy, or (SP1-PA2B) `ARCHIVED_VERIFIED_UNEXERCISED` with exactly the one accepted archive record, never an
  unverified local copy where SP1 reads, and in both the self-hosted path unexercised and archive-only.
- **Feature facts** from `cargo tree -e features`: sp1-sdk without `network`; reqwest without `http2`/`http3`; rustls
  without `brotli` and with the ring provider only; backtrace without `ruzstd`.
- **Source facts** from the pinned crates' own bytes, each read from the `.crate` whose sha256 is the lockfile
  checksum, over a declared file set (a fact over zero files proves nothing), and required to cover every locked
  dependent of the crate it is about.

What they establish, in short:

- **h2**: no HTTP/2 connection is ever made. reqwest is HTTP/1.1-only, and no tonic transport is constructed: sp1-prover
  uses tonic for error types and in-process worker channels, and sp1-sdk's gRPC client is in its `network` module,
  which is not compiled.
- **rustls (0285)**: CONDITIONAL. rustls runs only inside SP1's own circuit download (`install_circuit_artifacts`, at the
  Groth16/PLONK wrap stage, when the v6.1.0 circuit directory is absent). The frozen proving configuration installs the
  circuit from a hash-verified WalletWall archive first, so that download never runs; until that archive path exists
  no proving run is authorized. **Before any real proving run, the archive-only install (step 2) must be in place.**
- **rustls (0346, 0348, 0349)**: no custom session store anywhere rustls is configured; no brotli; ring offers only
  X25519/P-256/P-384, so there is no hybrid post-quantum group to downgrade from.
- **ruzstd**: its decoder is reached only through object's section decompression, which neither dependent of object
  calls (sp1-core-executor only writes ELF dumps; backtrace decompresses debug sections itself, its zstd path off).
- **lru**: sp1-prover never calls `iter_mut`, `pop`, or `catch_unwind`, and its cache keys have no `Drop`.
- **memmap2**: no dependent calls `advise_range`/`flush_range`/`flush_async_range`.
- **crossbeam-epoch**: no crate that can name `Atomic`/`Shared` formats one as a pointer.

The buckets are derived by one rule (`bucketOf`), never typed: a vulnerability or unsoundness `REACHABLE` on the frozen
proving path is MUST_FIX; a compiled finding that is `CONDITIONAL`, or a vulnerability, unsoundness or yanked release
with a lockfile-only fix, is SHOULD_FIX; everything else is NOT_REACHABLE_OR_UPSTREAM_ONLY.

## Why d1 is unchanged, and why the refresh waits

Any change to `zkvm/host/Cargo.lock` moves `HEAD:zkvm/host` away from d1's subject, which the designation tripwire
refuses: it needs a successor designation. A host-only change leaves the guest, its lockfile and the SP1 pins as they
are, so the ELF, the vkey and the identity stay d1's, and a successor whose identity equals an earlier one is refused
(the alias rule). There is no admissible designation for a host-only refresh, so the owner deferred it to the next
actual program rebuild, which changes the program identity anyway. Until then, the eight SHOULD_FIX findings stay
locked, none reachable on the frozen proving path.

## Two checks, two verdicts

- `npm run validate:sp1-host-advisories` (blocking, offline: no network, no cargo) passes on `ASSESSMENT_VALID` alone
  and prints the dependency status beside it. It fails with `REASSESSMENT_REQUIRED` when the subject or its evidence
  moved, and `RECORD_INVALID` when the record or the catalog is wrong as it stands.
- `.github/workflows/rustsec-audit.yml` (reporting, networked) re-measures all four lockfiles with the pinned
  cargo-audit against a fresh advisory-db checkout, and reconciles by exact advisory id, kind, crate, version and
  lockfile: exit 1 `SECURITY_DRIFT` (new or changed advisory, another version or lockfile, a changed graph, feature,
  source or fix fact), exit 2 `RECORD_CLEANUP_REQUIRED` (a recorded finding RustSec no longer reports), exit 3
  `AUDIT_UNAVAILABLE` (no usable measurement; never read as clean). A failed fetch step is infrastructure, not a finding.
  It is not a required check, so a RustSec, GitHub or crates.io outage never blocks an unrelated merge.

## Companion lockfiles

| Lockfile | Role | Findings |
|---|---|---|
| `zkvm/guest/Cargo.lock` | designated (d1's guest lockfile) | 0 vulnerabilities; `anyhow@1.0.102` unsound but not compiled; `der@0.8.0` yanked and compiled into the ELF (SHOULD_FIX, lockfile-only → 0.8.2, deferred with the program); `bincode@1.3.3` unmaintained |
| `zkvm/relation-tests/Cargo.lock` | CI test harness, never shipped | the same three warnings; never in a before-production bucket |
| `zkvm/evidence-validator/Cargo.lock` | offline tooling | clean |

"Clean" here means: no RustSec vulnerability, and no warning beyond the recorded ones. A changed companion lockfile is
the networked check's to judge; the offline check refuses only a recorded finding whose version is no longer locked.

## When today's assessment stops being valid

- zkvm/host's tree changes at HEAD or on disk (`Cargo.toml`, `Cargo.lock`, `build.rs`, `src/main.rs`), including a
  dependabot bump;
- a designation succeeds d1, or d1's bytes change (designations are immutable: supersede, never rewrite);
- an assumption stops holding: a new dependency, table or sp1-sdk feature; a network-only, aws-lc, brotli or cuda crate;
  another proof kind or prover in `src/main.rs`;
- proving availability changes (an archive, a local copy, an exercised self-hosted path);
- the networked check reports drift;
- the measurement script, the evidence catalog or the claims change.

## At the next program rebuild

1. Apply the compatible refresh (`remediation.compatibleRefresh`: crossbeam-epoch, h2, quinn-proto, rustls (+
   rustls-webpki), memmap2, spin) and any newer patched releases, and the guest's `der` update.
2. Re-audit every lockfile and re-measure this record's observation with the pinned cargo-audit.
3. Publish a successor designation for the rebuilt program.
4. Run the canonical two-host rebuild.
5. Re-measure the ELF and `PROGRAM_VKEY` outside the build and compare them.
6. Re-measure proving availability for the new lockfile and circuit.

The upstream-only findings (ruzstd, lru, the six unmaintained crates) remain until SP1 releases with newer
requirements; an SP1 upgrade is a new procedure and needs its own decision.

## Reproduce

```bash
npm run validate:sp1-host-advisories                    # offline
npx hardhat test mocha test/Sp1HostAdvisories.test.ts test/RustsecDrift.test.ts test/RustsecAuditWorkflow.test.ts
# re-measure (network: a clean advisory-db checkout, the crates.io index, cargo's index; nothing is written to zkvm/)
git clone --depth 1 https://github.com/rustsec/advisory-db.git /tmp/advisory-db
npm run sp1:measure-host-advisories -- --db /tmp/advisory-db
npm run sp1:host-advisories                             # regenerate the record from the new observation
npm run sp1:rustsec-drift -- --live <observation.json>  # reconcile a measurement with the committed record
```

## Limits

- Source facts are reviewed patterns over pinned sources: a reading of call sites, not a proof about every possible
  execution. They are re-measured by the networked check on every run.
- `compiled` uses `--target all`: compiled for some target, an over-approximation.
- The reachability judgments are WalletWall's; the advisories, their ranges and the yanked flags are upstream data as of
  the measurement.
- Nothing here bears on SP1's soundness, the circuit artifacts' integrity or proving availability.
