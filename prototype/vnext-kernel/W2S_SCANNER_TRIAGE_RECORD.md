# Lane W2S — post-W2 Slither triage re-derivation and scanner evidence closure

> ⚠️ **Research prototype. Not audited. Not production custody.**
>
> **Evidence-only lane.** Zero Solidity bytes change; no authority semantics
> change; no `docs/Vault_vNext_Architecture.md` (#179) edit; no SD-10 work.
> This record closes the one item Lane W2P deliberately deferred
> (`W2_IMPLEMENTATION_RECORD.md` §15.4): `SCANNER_EVIDENCE.json` was
> historical (`0faf7247`), `slither-triage.json` was line-key drifted, and W2
> introduced new `block.timestamp` sites that had never been triaged by key.

## 0. Base and scope

| | |
| --- | --- |
| Base | `77ea92cfdb79e160f3f3fa1a787edd8390a51be6` (tree `247727ecb6005185ff97676990b6dbf3966058d4`) — #188's head, the two-parent merge of #191 (`d3f8ee5c`, Commit B) into `e6964aeb` |
| Read before starting | #191 `MERGED`; #188 `OPEN` / draft, head exactly the SHA above; CI on that head: `vNext Kernel` 5/5 (Prototype Tests, Slither, CodeQL, Stateful Authority, Authority Completeness) and `CI` green |
| What this lane touches | `slither-triage.json`, `generate-scanner-evidence.ts` (one strictly-required input), this record, three one-paragraph doc pointers; then, in a separate successor commit, the regenerated `SCANNER_EVIDENCE.json` and nothing else |
| What it does not touch | any `.sol`; `AUTHORITY.md`'s argument; the workflow pins; `package.json` / lockfile; `stateful/defects.ts`; MEASUREMENTS.json |

## 1. The scanner contract, re-derived from repository source

Read firsthand at the base: `.github/workflows/vnext-kernel-assurance.yml`,
`slither-triage.json`, `SCANNER_EVIDENCE.json`, `generate-scanner-evidence.ts`,
`README.md`, plus the three files of `crytic/slither-action` at the pinned
commit `b52cc1cbfee9ca3e8722dd5224299d16c9a6b80f` (`action.yml`, `Dockerfile`,
`entrypoint.sh`), because the workflow pins the action, and the action — not
the workflow — decides how Slither is installed and invoked.

**What the pinned action actually does** (`entrypoint.sh` at that commit):

1. image `python:3.10`, `pip install solc-select` (Dockerfile);
2. `python3 -m venv /opt/slither`, `pip3 install wheel`, then — because
   `slither-version` is not a `x.y.z` release string — `pip3 install
   "slither-analyzer @ https://github.com/crytic/slither/archive/ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad.tar.gz"`;
3. `solc-select install 0.8.24 && solc-select use 0.8.24`;
4. installs the latest Node via nvm (`v26.8.1` in the CI log) — unused here,
   because `install_deps` runs in the *target* directory
   (`prototype/vnext-kernel/contracts`), which has no `package.json`; the
   OpenZeppelin remap is served by the workflow's own `npm ci` step (Node 22);
5. `fail-on: none` becomes `--no-fail-pedantic`; `sarif:` becomes
   `--sarif=slither-vnext-kernel-results.sarif`; no `slither.config.json`
   exists at the repository root, so no config flag is added;
6. runs, from the repository root, via `xargs`:

```text
slither prototype/vnext-kernel/contracts \
  --sarif=slither-vnext-kernel-results.sarif --no-fail-pedantic \
  --compile-force-framework solc \
  --solc-remaps "@openzeppelin/=node_modules/@openzeppelin/" \
  --solc-args "--evm-version cancun --optimize --optimize-runs 200" \
  --exclude-dependencies
```

**The generator's key** (`generate-scanner-evidence.ts`): a finding is
*own-code* when every element lies outside `node_modules`; its key is
`<check>|<sorted "file:firstLine" of every element>`; the plain `solc`
platform compiles each top-level `.sol` as its own unit, so a finding in
`VaultKernelPrototype.sol` is reported twice (its own unit and the factory's,
which imports it) and the generator collapses duplicates by that key. The key
therefore embeds **every** element line, which is why the GitHub
code-scanning alert list (primary location only) could not have re-keyed
anything, and why a local `--json` run was required.

## 2. Truthful local toolchain

The exact action semantics were reproduced in a disposable virtualenv outside
the repository (WSL2 Ubuntu 24.04, `/root/w2s/venv`; nothing under the
repository, `package.json`, the lockfile or the workflow pins was modified):

| Component | CI (`crytic/slither-action@b52cc1cb…`) | This lane (disposable venv, WSL2 Ubuntu 24.04) |
| --- | --- | --- |
| Slither | `slither-analyzer @ …/archive/ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad.tar.gz` (reports `0.11.5`) | same tarball URL, pip-recorded sha256 `2e2342c9ce4f3cfa9be5d998f105bdf9a1ae58933fc84836e54ba5bebf0d3834`; `slither --version` → `0.11.5` |
| crytic-compile | 0.4.2 | 0.4.2 |
| solc-select | 1.2.0 | 1.2.0 |
| solc | 0.8.24 via `solc-select use` | `Version: 0.8.24+commit.e11b9ed9.Linux.g++`; global `0.8.24` |
| Python | 3.10 (`python:3.10` image) | 3.12.3 — the one difference (see below) |
| Compile framework / remap / compiler args / exclusions | `solc` / `@openzeppelin/=node_modules/@openzeppelin/` / `--evm-version cancun --optimize --optimize-runs 200` / `--exclude-dependencies` | identical (`solc` / `@openzeppelin/=node_modules/@openzeppelin/` / `--evm-version cancun --optimize --optimize-runs 200` / `--exclude-dependencies`) |
| `@openzeppelin/contracts` | from `package-lock.json` via the workflow's `npm ci` (Node 22) | 5.6.1 from the same lockfile via `npm ci` (Node 24.16.0 — irrelevant to solc) |
| Target / cwd | `prototype/vnext-kernel/contracts` from `/github/workspace` (repo root) | `prototype/vnext-kernel/contracts` from `/root/w2s/repo` (repo root) |
| Fail flag / outputs | `--no-fail-pedantic` (`fail-on: none`), `--sarif=slither-vnext-kernel-results.sarif` | identical, plus a second identical-argument run with `--json` for the generator |

The CI job log for `d3f8ee5c` (run 33939718797, job "Slither") resolved the
identical package set — `crytic-compile-0.4.2`, `solc-select-1.2.0`,
`slither-analyzer-0.11.5` (the version string the pinned tarball reports),
`web3-7.16.0`, `pycryptodome-3.23.0`, … — with exactly one difference:
`async-timeout-5.0.1`, a conditional dependency of `aiohttp` that installs
only on Python < 3.11. That is the Python difference (3.12.3 locally, 3.10 in
the action image) and nothing else; it has no bearing on static analysis, and
§3 shows the finding set matched CI's on the same head exactly.

## 3. Raw runs on three clean checkouts

Each run: `git checkout --detach <sha>`, `git clean -fdx` (node_modules kept —
`package.json`/`package-lock.json` are byte-identical across all three
commits, so one `npm ci` serves them; `@openzeppelin/contracts` 5.6.1),
`git status --porcelain` empty, then the CI-exact command above (SARIF +
stdout), then the same arguments with `--json` for the generator's input.
Both invocations agree on every count.

| Checkout | HEAD | Tree | Raw results | Own-code | Distinct keys | raw `--json` sha256 | SARIF sha256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0faf7247 (previous receipt head) | `0faf724761a2` | `2a61eeaea76c` | 213 | 50 | 31 | `cc5a897c38adb400…` | `a5e44325e96e8022…` |
| e6964aeb (#188 head before #191) | `e6964aeb7a44` | `5d19e55a26ba` | 213 | 50 | 31 | `0cca42107f6b50e0…` | `e810f3a9cc50cedd…` |
| 77ea92cf (base of this lane) | `77ea92cfdb79` | `247727ecb600` | 217 | 54 | 33 | `b1c0d9ee94cce47d…` | `59898895f7fa5c6d…` |

Distinct own-code keys per detector:

- 0faf7247: arbitrary-send-eth 2, assembly 1, immutable-states 2, locked-ether 2, low-level-calls 4, missing-inheritance 1, missing-zero-check 4, reentrancy-benign 1, reentrancy-events 3, timestamp 7, uninitialized-local 2, unused-return 2
- e6964aeb: arbitrary-send-eth 2, assembly 1, immutable-states 2, locked-ether 2, low-level-calls 4, missing-inheritance 1, missing-zero-check 4, reentrancy-benign 1, reentrancy-events 3, timestamp 7, uninitialized-local 2, unused-return 2
- 77ea92cf: arbitrary-send-eth 2, assembly 1, immutable-states 2, locked-ether 2, low-level-calls 4, missing-inheritance 1, missing-zero-check 4, reentrancy-benign 1, reentrancy-events 3, timestamp 9, uninitialized-local 2, unused-return 2

Comparison points:

- `0faf7247` reproduces the committed receipt's `rawFindingCount: 213` and
  `distinctOwnCodeFindingCount: 31` exactly. The raw `--json` bytes differ from
  the receipt's `rawOutputSha256` because the JSON embeds `filename_absolute`
  (this run: `/root/w2s/repo/…`; the receipt's run: another machine) — the
  identity that is comparable across environments is the finding set, not the
  byte stream.
- `77ea92cf` reproduces the CI observation on the same head: **217 results**
  (job log line `prototype/vnext-kernel/contracts analyzed (55 contracts with
  102 detectors), 217 result(s) found`), and the 54 own-code alerts GitHub
  lists for the branch are exactly this run's 54 own-code findings by
  (detector, primary line).
- The 163 excluded findings are all inside `node_modules/@openzeppelin` at
  every head (`217 − 54 = 213 − 50 = 163`).

## 4. Old → new mapping, proven semantically

**Method.** Two findings are the *same* finding when they agree on the
detector, on the full element chain (contract → function → node names, i.e.
the source construct), on the finding message with line references stripped,
and on the source text at every element's location in the respective commit.
Matching is exact-once (a candidate is consumed when matched; the run reports
ambiguity if two candidates share a signature — none did). Line deltas are a
*result* of the match, never an input to it. The same procedure was run for
`0faf7247 → e6964aeb` and `e6964aeb → 77ea92cf` to attribute each move to
the pre-W2 stack (SD-1, SD-3, SD-6/7: kernel +190 lines, factory signature
change) or to W2 (`c182db10`: kernel +116 lines at the tail, +22/+42/+53/+114
in between).

Key legend: `K:` = `VaultKernelPrototype.sol`, `F:` = `VaultKernelFactoryPrototype.sol`, `M:` = `PrototypeMocks.sol`, `I:` = `interfaces/IKernelPlanes.sol`; the detector prefix is shown once in its own column. Line Δ is `new − old` for each element in key order (a result of the semantic match, never its input).

| # | Detector | Key at `0faf7247` | Key at `77ea92cf` | Identity | Line Δ (per element) | Attribution | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `arbitrary-send-eth` | `K:1169,K:1180` | `K:1475,K:1486` | UNCHANGED_FINDING_RELOCATED | 306/306 | pre-W2 +190, W2 +116 | FALSE_POSITIVE |
| 2 | `arbitrary-send-eth` | `K:593,K:634` | `K:751,K:792` | UNCHANGED_FINDING_RELOCATED | 158/158 | pre-W2 +116, W2 +42 | FALSE_POSITIVE |
| 3 | `assembly` | `K:913,K:930` | `K:1156,K:1173` | UNCHANGED_FINDING_RELOCATED | 243/243 | pre-W2 +190, W2 +53 | ACCEPTED_DESIGN_TRADEOFF |
| 4 | `immutable-states` | `M:37` | `M:37` | UNCHANGED_FINDING_SAME_KEY | 0 | — | OUT_OF_SCOPE_DEPENDENCY |
| 5 | `immutable-states` | `M:96` | `M:96` | UNCHANGED_FINDING_SAME_KEY | 0 | — | OUT_OF_SCOPE_DEPENDENCY |
| 6 | `locked-ether` | `M:143,M:144` | `M:143,M:144` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | NON_SECURITY_STYLE |
| 7 | `locked-ether` | `M:148,M:159` | `M:148,M:159` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | NON_SECURITY_STYLE |
| 8 | `low-level-calls` | `M:159,M:162` | `M:159,M:162` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | NON_SECURITY_STYLE |
| 9 | `low-level-calls` | `K:1169,K:1180,K:1188` | `K:1475,K:1486,K:1494` | UNCHANGED_FINDING_RELOCATED | 306/306/306 | pre-W2 +190, W2 +116 | ACCEPTED_DESIGN_TRADEOFF |
| 10 | `low-level-calls` | `K:1198,K:1199` | `K:1504,K:1505` | UNCHANGED_FINDING_RELOCATED | 306/306 | pre-W2 +190, W2 +116 | ACCEPTED_DESIGN_TRADEOFF |
| 11 | `low-level-calls` | `K:593,K:634` | `K:751,K:792` | UNCHANGED_FINDING_RELOCATED | 158/158 | pre-W2 +116, W2 +42 | ACCEPTED_DESIGN_TRADEOFF |
| 12 | `missing-inheritance` | `M:69,I:36` | `M:69,I:36` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | NON_SECURITY_STYLE |
| 13 | `missing-zero-check` | `M:131,M:133` | `M:131,M:133` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | OUT_OF_SCOPE_DEPENDENCY |
| 14 | `missing-zero-check` | `M:136,M:138` | `M:136,M:138` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | OUT_OF_SCOPE_DEPENDENCY |
| 15 | `missing-zero-check` | `M:154,M:155` | `M:154,M:155` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | OUT_OF_SCOPE_DEPENDENCY |
| 16 | `missing-zero-check` | `K:740,K:758` | `K:1001,K:983` | UNCHANGED_FINDING_RELOCATED | 243/243 | pre-W2 +190, W2 +53 | FALSE_POSITIVE |
| 17 | `reentrancy-benign` | `M:159,M:162,M:163` | `M:159,M:162,M:163` | UNCHANGED_FINDING_SAME_KEY | 0/0/0/0 | — | NON_SECURITY_STYLE |
| 18 | `reentrancy-events` | `F:71,F:77,F:78` | `F:82,F:89,F:90` | SEMANTICALLY_CHANGED_FINDING | construct changed | pre-W2 (#187) | FALSE_POSITIVE |
| 19 | `reentrancy-events` | `K:1169,K:1180,K:1188,K:1195` | `K:1475,K:1486,K:1494,K:1501` | UNCHANGED_FINDING_RELOCATED | 306/306/306/306/306 | pre-W2 +190, W2 +116 | ACCEPTED_DESIGN_TRADEOFF |
| 20 | `reentrancy-events` | `K:593,K:630,K:633` | `K:751,K:788,K:791` | UNCHANGED_FINDING_RELOCATED | 158/158/158 | pre-W2 +116, W2 +42 | ACCEPTED_DESIGN_TRADEOFF |
| 21 | `timestamp` | — | `K:1250,K:1255` | NEW | — | W2 | ACCEPTED_DESIGN_TRADEOFF |
| 22 | `timestamp` | `K:1033,K:1037,K:1038` | `K:1325,K:1329,K:1333` | SEMANTICALLY_CHANGED_FINDING | construct changed | W2 (c182db10) | ACCEPTED_DESIGN_TRADEOFF |
| 23 | `timestamp` | `K:1068,K:1086` | `K:1372,K:1390` | UNCHANGED_FINDING_RELOCATED | 304/304 | pre-W2 +190, W2 +114 | ACCEPTED_DESIGN_TRADEOFF |
| 24 | `timestamp` | `K:1147,K:1149` | `K:1453,K:1455` | UNCHANGED_FINDING_RELOCATED | 306/306 | pre-W2 +190, W2 +116 | ACCEPTED_DESIGN_TRADEOFF |
| 25 | `timestamp` | `K:1169,K:1174` | `K:1475,K:1480` | UNCHANGED_FINDING_RELOCATED | 306/306 | pre-W2 +190, W2 +116 | ACCEPTED_DESIGN_TRADEOFF |
| 26 | `timestamp` | `K:525,K:536` | `K:640,K:651` | UNCHANGED_FINDING_RELOCATED | 115/115 | pre-W2 +93, W2 +22 | ACCEPTED_DESIGN_TRADEOFF |
| 27 | `timestamp` | `K:547,K:549` | `K:685,K:687` | UNCHANGED_FINDING_RELOCATED | 138/138 | pre-W2 +116, W2 +22 | ACCEPTED_DESIGN_TRADEOFF |
| 28 | `timestamp` | `K:573,K:575` | `K:711,K:713` | UNCHANGED_FINDING_RELOCATED | 138/138 | pre-W2 +116, W2 +22 | ACCEPTED_DESIGN_TRADEOFF |
| 29 | `timestamp` | — | `K:742,K:743` | NEW | — | W2 | ACCEPTED_DESIGN_TRADEOFF |
| 30 | `uninitialized-local` | `K:885` | `K:1128` | UNCHANGED_FINDING_RELOCATED | 243 | pre-W2 +190, W2 +53 | FALSE_POSITIVE |
| 31 | `uninitialized-local` | `K:1176` | `K:1482` | UNCHANGED_FINDING_RELOCATED | 306 | pre-W2 +190, W2 +116 | FALSE_POSITIVE |
| 32 | `unused-return` | `M:180,M:184` | `M:180,M:184` | UNCHANGED_FINDING_SAME_KEY | 0/0 | — | FALSE_POSITIVE |
| 33 | `unused-return` | `K:913,K:923` | `K:1156,K:1166` | UNCHANGED_FINDING_RELOCATED | 243/243 | pre-W2 +190, W2 +53 | FALSE_POSITIVE |

**Outcome:** 11 keys unchanged (every finding in `PrototypeMocks.sol` and
`IKernelPlanes.sol`: files untouched since `0faf7247`), 18 relocated with
byte-identical source text, 2 whose construct changed (§5.3, §6.1), 2 new
(§5.1, §5.2), **0 removed**. Nothing was re-keyed by `oldLine + N`.

## 5. The W2 findings, adjudicated independently

Classifications are drawn from the existing schema
(`ACCEPTED_DESIGN_TRADEOFF`, `FALSE_POSITIVE`, `OUT_OF_SCOPE_DEPENDENCY`,
`NON_SECURITY_STYLE`); no category was invented, and none of the three was
accepted on the strength of the seven pre-existing timestamp entries.

### 5.0 The clock model the adjudication uses

The `timestamp` detector's premise is "`block.timestamp` can be manipulated
by miners". What a block producer can actually do:

| Environment | Producer's discretion over `block.timestamp` | Bound |
| --- | --- | --- |
| Ethereum L1, post-merge (since 2022) | none — the payload timestamp is fixed by the consensus slot (`genesis_time + slot × 12 s`); a block with any other value is invalid. The only lever is *inclusion* (which slot a transaction lands in, or withholding it) | 0 s of skew; 12 s inclusion granularity per slot the producer controls |
| Ethereum L1, PoW era | forward only: `timestamp > parent.timestamp` and peers rejected blocks more than ~15 s ahead of their clock; a *lagging* timestamp raised the miner's own difficulty and was corrected by the next honest block | ≈ 15 s, forward |
| OP-Stack L2 (Base) | the sequencer's block timestamps are bounded against the L1 origin by `max_sequencer_drift` | 1,800 s |

Against the windows at issue — `RECOVERY_DELAY` = 7 days = 604,800 s,
`RECOVERY_EXPIRY` = 14 days = 1,209,600 s — the worst bound is 0.30 % and
0.15 % respectively, and it is one-directional or symmetric, never a
capability. Every recovery clock in this kernel is expressed in the chain's
own clock, in which the request was also created, so a uniform lag or lead
moves *every* principal's window together.

### 5.1 `timestamp | _recoveryIsLive()` — `:742,:743` — NEW — `ACCEPTED_DESIGN_TRADEOFF`

- **Detector / exact source.** `timestamp`, Low/Medium.
  `return recovery.active && block.timestamp < recovery.expiresAt;` (`:743`),
  introduced by `c182db10`. This *is* `I-RECOVERY-EFFECTIVE-LIVENESS`
  (Recovery Amendment §3): authority on the half-open window
  `[executableAt, expiresAt)`.
- **Reachable sequence.** Internal; consulted by `initiateRecovery` (`:1209`,
  live-overwrite refusal), `cancelRecovery` (`:1254`), `cancelRecoveryByQuorum`
  (`:1297`) and `bindMigration` (`:1422`); `executeRecovery` mirrors it with
  `>= expiresAt` (`:1333`).
- **Security impact.** The predicate decides *whether* an already-authorised
  act lands, never *who* is authorised: no signature, quorum or possession
  check reads the clock. Because every consumer applies the same inequality,
  there is no block in which the request is executable but not cancellable,
  or cancellable but not executable.
- **The boundary, explicitly.** `test/W2RecoveryLifecycle.test.ts` §B mines
  one probe per (consumer, instant) in a fresh world at exactly the asserted
  timestamp: at `expiresAt−1` execution succeeds, credential challenge and
  quorum cancellation succeed, migration is blocked (`NoRecovery`), initiation
  is refused (`BadState`, no guardian nonce consumed); at `expiresAt` and
  `expiresAt+1` execution reverts `Expired`, both cancellations revert
  `NoRecovery` consuming neither nonce nor budget, migration binds, and a
  fresh initiation is admitted with its own full delay and the challenge
  count preserved. §G3 pins the three instants as consecutive blocks of one
  world.
- **Can skew…** refund challenge budget? No — `challengesUsed` is written
  only by `+= 1` in `cancelRecovery`, the carry-forward in `initiateRecovery`
  and the whole-struct `delete` in `executeRecovery`. Bypass quorum? No —
  only `initiateRecovery` (quorum-gated) creates an active request. Permit
  expired execution? No — `t ≥ expiresAt` reverts; a producer cannot run the
  chain clock behind itself (§5.0). Create live overwrite? No —
  `initiateRecovery` reverts `BadState` while live; a fresh request over an
  *expired* one is by design not an overwrite, and the quorum could in any
  case have cancelled its own live request. Reduce a principal cut? No — the
  cuts of `AUTHORITY.md` §4 are signature/quorum counts. Forward skew can only
  make a request expire *early* (≤ 15 s PoW-era; 0 s on L1 today), shrinking
  every principal's window together.
- **Regression / evidence.** Mutants `M-K9-expiry-inclusive-off-by-one`,
  `-expired-request-still-challengeable`, `-expired-request-still-quorum-cancellable`,
  `-expired-request-blocks-migration`, `-expired-request-blocks-initiation`,
  `-live-overwrite-allowed`, `-expiry-refunds-budget`
  (`test/W2RecoveryLifecycleMutations.test.ts`), all killed.

### 5.2 `timestamp | cancelRecovery` — `:1250,:1255` — NEW — `ACCEPTED_DESIGN_TRADEOFF`

- **Detector / exact source.** `timestamp`, Low/Medium. Slither's printed
  "dangerous comparison" is `recovery.challengesUsed >= CHALLENGE_LIMIT`
  (`:1255`) — a counter comparison with **no timestamp operand**. The
  function's only clock read is the gate `if (!_recoveryIsLive()) revert
  NoRecovery();` at `:1254`.
- **Why Slither reports it now and not at `e6964aeb`.** Probed with the
  pinned Slither's own `is_dependent` on the base checkout:

```text
### cancelRecovery(uint256,uint64,bytes)
  L1254: ! _recoveryIsLive()
     InternalCall _recoveryIsLive lvalue=TMP_1618 lvalue_dep_ts=True
  L1255: recovery.challengesUsed >= CHALLENGE_LIMIT
     Binary read REF_308        dep(node)=True dep(fn)=False deps=['recovery']
     Binary read CHALLENGE_LIMIT dep(node)=False dep(fn)=False
```

  The detector evaluates dependency in *node* context. After the
  `_recoveryIsLive()` internal call — whose return value depends on
  `block.timestamp` and on the `recovery` struct — the node-context dependency
  set of the `recovery` storage reference includes `block.timestamp`; in
  function context it does not. At `e6964aeb` the gate read the raw
  `recovery.active` byte, so the identical comparison produced no report.
  `challengesUsed` itself is never written from the clock.
- **Reachable sequence / security impact.** The clock decides whether a
  credential challenge is admitted: live → one budget unit consumed and
  request authority cleared; expired → `NoRecovery` before any nonce or
  budget is touched (§B probes "challenge" at all three instants; mutant
  `M-K9-expired-request-still-challengeable`).
- **Can skew…** refund or exceed the budget? No (same write sites as §5.1;
  `CHALLENGE_LIMIT` is a constant). Move authority? It can move the last
  admissible challenge instant by seconds against a 14-day window — no
  capability beyond the bounded challenge that #179 §22 D1 already prices
  (`I-VETO-BOUND`).
- **Why not `FALSE_POSITIVE`.** The printed comparison is mis-attributed, but
  the function *is* deliberately clock-gated through `_recoveryIsLive()`;
  the entry says both, and cross-references §5.1, so a reader is not told
  "no timestamp dependence here".

### 5.3 `timestamp | executeRecovery` — `:1325,:1329,:1333` — SEMANTICALLY_CHANGED — `ACCEPTED_DESIGN_TRADEOFF`

- **What changed.** `block.timestamp > r.expiresAt` (`0faf7247:1038`,
  `e6964aeb:1228`) → `block.timestamp >= r.expiresAt` (`77ea92cf:1333`),
  by `c182db10` (SD-9e). The maturity comparison and the function are the same
  construct; the mapping refused to call this a relocation because the source
  text of one element differs, and it was reviewed on its own.
- **Effect on the argument.** The last authorised instant moved from
  `expiresAt` to `expiresAt−1`, removing the one-second window in which the
  pre-W2 kernel executed a request that every other consumer already treated
  as expired (the outlier row of the amendment's §3 table). The previous
  rationale ("day-scale windows, ~15 s of miner slack immaterial") was not
  false, but it was silent on the boundary that W2 made consistent and on the
  post-merge clock model; the replacement rationale states both. The
  superseded text is preserved in the entry's `provenance`.
- **Can skew…** execute an unmatured or expired request? No. Bypass the
  quorum? No. Reset the epoch? No — the only reset is this function's own
  `delete recovery` after an authorised execution.
- **Regression / evidence.** §B1–B4, §G3; mutant
  `M-K9-expiry-inclusive-off-by-one` (`>` here / `<=` in the predicate).

## 6. Carried-forward entries, re-checked on the W2 kernel

Every one of the 29 carried-forward entries was re-read against `77ea92cf`
with the question "does the rationale still hold on *this* kernel?" — not
"was it accepted before?".

### 6.1 `reentrancy-events | VaultKernelFactoryPrototype.deployVault` — SEMANTICALLY_CHANGED — `FALSE_POSITIVE`

The construct changed *before* W2, in #187 (`3d2aede8`, SD-6/SD-7): `pqKey`
became a forwarded parameter of `deployVault` and `initialize`, so the
function signature and the external-call node in the finding both changed and
the mapping refused to call it a relocation. Re-adjudicated: the external
calls before the event are `genesisSalt` (a STATICCALL to the immutable
implementation) and `initialize(g, pqKey)` on the clone that
`Clones.cloneDeterministicWithImmutableArgs` (internal-library CREATE2) just
produced; the only code at that address is the kernel's own `initialize`,
which makes no external call (verified: it validates `g` and the `pqKey`
exhibit by `keccak256` and length comparison, writes genesis state, emits);
the factory holds no mutable state. The exhibit adds no call and changes
nothing in the reentrancy argument. The previous rationale's "two external
calls" wording was imprecise (the clone creation is an internal library
call); the new text names the calls Slither actually reports.

### 6.2 Rationales with embedded line references (three)

`arbitrary-send-eth|execute`, `missing-zero-check|setPolicy` and
`reentrancy-events|execute` cite lines *inside* `execute`, which moved by
+158 as a block. The citations were moved with it and re-verified at the new
lines (`763-771` digest + `_authorise`; `772` `_consume(DOMAIN_SPEND)`;
`786-789` the policy-plane branch on `policyEngine == address(0)`; `792` the
value transfer). Wording unchanged; the edit is declared in `provenance`.

### 6.3 Entries whose rationale touches the recovery state machine

- `timestamp|_requireIncomingPossession` (`:640,:651`): the flagged lines are
  digest/signature checks; the rationale defers to the enclosing callers'
  entries — one of which (`executeRecovery`) was rewritten in §5.3. Still
  holds; the deferral now points at the re-adjudicated text.
- `timestamp|_effectiveState` (`:711,:713`), `_consume` (`:685,:687`),
  `enterContainment` (`:1372,:1390`), `retire` (`:1453,:1455`), `egress`
  (`:1475,:1480`): the source text is byte-identical and W2 changed none of
  `containedUntil`, deadlines, containment, `BIND_DELAY` or `egress`. The
  "~15 s miner slack" phrasing in these older rationales is the PoW-era
  bound; §5.0 gives the current model, under which the conclusions are only
  stronger. Not rewritten: the user of this file needs the history, and a
  weaker-but-true bound is not a false statement.
- `reentrancy-events|execute` / `egress`, `arbitrary-send-eth|execute` /
  `egress`, `low-level-calls`, `assembly|_attests`, `uninitialized-local`,
  `unused-return`: W2 touched none of these functions; source text identical;
  the SD-6/7 changes to `initialize`/`setVerifier` do not enter any of these
  paths.
- Mock/interface entries (11, same key): files untouched since `0faf7247`.

**No previous suppression rationale was found to be false on the W2
kernel.** One (§5.3) was incomplete and is replaced; one (§6.1) was imprecise
and is replaced; three (§6.2) carried stale line citations and are corrected.
Nothing is grandfathered.

## 7. Accounting at `77ea92cf`

```text
RAW_FINDINGS                      = 217
  excluded (inside node_modules)  = 163
  own-code                        = 54
    reported twice (kernel unit + factory unit)    = 21 keys
    reported once                                  = 12 keys
DISTINCT_OWN_CODE_KEYS            = 33

TRIAGED (33 entries, one per key)
  ACCEPTED_DESIGN_TRADEOFF     = 15
  FALSE_POSITIVE               = 8
  NON_SECURITY_STYLE           = 5
  OUT_OF_SCOPE_DEPENDENCY      = 5
  TRIAGED_ACTION_REQUIRED          = 0   (no such category exists in the schema; none was needed)

UNACCOUNTED (raw key without entry) = 0
DUPLICATE TRIAGE (two entries, one key) = 0   (JSON object keys; builder asserted set equality)
STALE TRIAGE (entry without raw key)   = 0

Identity of the 33 entries against 0faf7247:
  NEW                          = 2
  SEMANTICALLY_CHANGED_FINDING = 2
  UNCHANGED_FINDING_RELOCATED  = 18
  UNCHANGED_FINDING_SAME_KEY   = 11
  REMOVED                          = 0
```

`generate-scanner-evidence.ts --validate --raw <this run>` against the
re-derived triage reports no untriaged finding and no stale key. Against the
*previous* triage it exits 1 with 22 untriaged keys (and 20 of its 31 keys
match no current finding) — the drift this lane closes.

## 8. Receipt protocol (the successor commit)

The generator stamps `git rev-parse HEAD` / `HEAD^{tree}`, so by the
repository's generated-at convention (`W2_IMPLEMENTATION_RECORD.md` §15,
`stateful/README.md`) the receipt is produced from a **clean checkout of the
commit that carries this triage** (Commit S) and committed in its successor
(Commit E) with nothing else. Sequence on the clean checkout of S:
`npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile` →
the CI-exact Slither command with `--json` → `generate-scanner-evidence.ts
--raw … --prototype-tests … --production-tests … --production-coverage …
--solhint …`. The test counts are the suite results measured in the same
environment; S changes no `.sol`, no test, no Hardhat config and no
dependency, which is what makes them the counts *for* S. The `--solhint`
input replaces a value the generator had hardcoded at 32 since `0faf7247`
(36 warnings, 0 errors at `77ea92cf`, as the README already stated) — the
one tooling change in this lane, made because a regenerated receipt that
misstated the solhint total of the tree it names would not be evidence.

## 9. What this lane establishes, and what it does not

- Establishes: the raw finding set on the post-W2 kernel under the exact CI
  pin; a complete, exactly-once map from every pre-W2 triage key to its
  successor with the identity proof stated; an independent adjudication of
  the W2 findings under the current clock model; a triage that accounts for
  every raw finding exactly once; a receipt that names the tree it measured.
- Does not establish: any Solidity semantic coverage beyond what Slither's
  detectors express (`AUTHORITY.md` §7); anything about SD-10 (open, sustained
  in `stateful/defects.ts`); scanner approval — the `vNext Kernel / Slither`
  job is `fail-on: none` by design, and a green job is not evidence of
  anything this record does not state.

## 10. Follow-ups noted, not done here

- `--validate` treats a stale key as a warning; making it fail would have
  caught this drift at the first post-`0faf7247` kernel change. A policy
  change, outside an evidence-only lane.
- CI does not run `--validate` (the action emits SARIF, not `--json`); the
  gate is local. Adding it means touching the pinned action's arguments.
