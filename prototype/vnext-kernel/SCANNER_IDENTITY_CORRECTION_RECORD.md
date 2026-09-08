# Scanner finding identity — correction record

**Lane:** SD-SCAN-ID. **Source subject:** `aaa21d093876d23d9e2d790400661d3d242caa31`
(tree `5e47baa2bb09669e62145b23caa65762791ad518`, contracts tree `dcc42e76a22b2491e05a6f7ccbc98f447e6acbc5`).

This record exists because a scanner receipt and its triage went stale without any
signal, and the quantities that were being published all stayed correct while it
happened. It documents what was measured, what was wrong, and what now prevents a
recurrence.

## 1. What was wrong

`slither-triage.json` v1 keyed each finding by
`<check>|<sorted filename:firstLine of every element>`. That is a **locator** — it
names where a finding was standing, not what it is.

Two commits on this branch moved kernel source without changing what it does in any
way a scanner can see:

| commit | effect on `prototype/vnext-kernel/contracts` |
| --- | --- |
| `be1789f4` — SD5-I, de-authorise PQ shape metadata | tree `da8aef1f` → `dca808ea` |
| `8ba71c90` — derive evidence provenance from declared subject | tree `dca808ea` → `dcc42e76` |

Code below those edits shifted by **+120** and **+133** lines depending on the region.
Under locator keying, 21 of 33 adjudicated findings lost their triage entries.

## 2. What the published numbers said while it was wrong

Every quantity anyone was looking at stayed equal across the drift:

| quantity | at `a46bc50c` (receipt subject) | at `aaa21d09` (branch head) |
| --- | --- | --- |
| raw results | 217 | 217 |
| own-code raw rows | 54 | 54 |
| distinct own-code findings | 33 | 33 |
| findings added | — | **0** |
| findings removed | — | **0** |
| triage keys that still matched | 33 | **12** |

`a46bc50c` is also an ancestor of `aaa21d09`. **Equal counts, equal distinct counts,
and ancestry all held while the receipt stopped describing the head.** None of the
three is evidence of currency, and the corrected tooling consults none of them.

Two further claims were false at the head and are corrected in `MEASUREMENTS.json`
with `supersedes` notes:

- `scannerCoverage.slither.unaccounted: 0` — it was 21.
- "the `--validate` gate fails CI on any untriaged finding" — **no workflow ran
  `--validate` at all**, so nothing could have failed.

## 3. Measurement

The CI-pinned invocation was reproduced on clean checkouts of three commits
(`crytic/slither-action@b52cc1cb` semantics; slither `ff1bf3ff` reporting 0.11.5,
crytic-compile 0.4.2, solc-select 1.2.0, solc 0.8.24+commit.e11b9ed9, target
`prototype/vnext-kernel/contracts`, `--compile-force-framework solc`,
`--solc-remaps "@openzeppelin/=node_modules/@openzeppelin/"` with
`@openzeppelin/contracts` 5.6.1 from the lockfile,
`--solc-args "--evm-version cancun --optimize --optimize-runs 200"`,
`--exclude-dependencies`, `--no-fail-pedantic`):

| subject | raw | own rows | distinct | raw sha256 |
| --- | --- | --- | --- | --- |
| `aaa21d09` (source subject) | 217 | 54 | 33 | `054135ac9e4aff807b5d5215b15447945f960e4e0e2e2bcc8433af7e058c21be` |
| `a46bc50c` (v1 receipt subject) | 217 | 54 | 33 | `e06288cf1611e521354e165d036d2943704b988ae798d3a0ec494f17b551ceb6` |
| `c32e0d74` (v1 triage subject) | 217 | 54 | 33 | `e06288cf1611e521354e165d036d2943704b988ae798d3a0ec494f17b551ceb6` |

The two prior subjects produce **byte-identical** raw output, because the contracts
tree is `da8aef1f` at both. The head's differs. Each run reports
`55 contracts with 102 detectors`, matching the CI analyses' `results_count` of 217
on both `refs/pull/181/merge` and the branch ref.

`e06288cf…` is the value the v1 receipt recorded, so the v1 receipt was **truthful
about its own subject** and simply no longer described the head.

## 4. Mapping, v1 → v2

Matched on semantic identity, never by line arithmetic. All 33 v1 keys consumed
exactly once; the resulting key set equals the current run's.

| class | count |
| --- | --- |
| `UNCHANGED_FINDING_SAME_LOCATOR` | 12 |
| `UNCHANGED_FINDING_RELOCATED` | 20 |
| `SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION` | 1 |
| added | 0 |
| removed | 0 |
| ambiguous | 0 |

The 12 unchanged are all in `PrototypeMocks.sol`, `interfaces/IKernelPlanes.sol` and
`VaultKernelFactoryPrototype.sol` — files these two commits did not touch. The 20
relocations are all in `VaultKernelPrototype.sol` with byte-identical source at every
element. Within one finding every element shifts by the same amount; **across**
findings the shift is +120 or +133, which is why arithmetic cannot be the matcher.

Four rationales carried embedded source line citations that moved with the code
(`:763-771` → `:883-891`, `:786-789` → `:906-909`, `:772` → `:892`, `:1254` → `:1387`).
Wording is otherwise unchanged and the edit is recorded per entry.

## 5. The one re-adjudication

`timestamp` on `_requireIncomingPossession` could not be carried forward as a
relocation: its enclosing function body changed.

- **Source change.** `be1789f4` deleted
  `if (c.newPqKey.length != floor.pqPublicKeyLength || c.newPqPop.length != floor.pqSignatureLength) revert BadSignature();`
  and rewrote the surrounding comment.
- **What the evidence proves.** The narrow fingerprint (node elements — the construct
  Slither actually flagged) is **equal** across `c32e0d74` and `aaa21d09`. The broad
  fingerprint (all elements, enclosing function included) **differs**. So the flagged
  construct did not change; its context did. The entry is classified
  `SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION` and **not**
  `SEMANTIC_CHANGE_PROVEN`, because the trigger does not prove the stronger claim.
- **Re-verified firsthand at the source subject.** `_requireIncomingPossession` reads
  no clock: there is no `block.timestamp`, `deadline` or `expiresAt` anywhere in lines
  753–803. The comparison Slither prints,
  `popDigest.recover(c.newEcdsaPop) != expectedSigner`, has no clock operand. The
  report is the node-context taint described in `W2S_SCANNER_TRIAGE_RECORD.md`: the
  function is reached from `rotateCredential` (line 954) and `executeRecovery`
  (line 1503), both of which do read the clock.
- **Why the classification survives.** The deleted construct is a length equality on
  PQ key and signature bytes. It carries no clock operand and its removal adds and
  removes no `block.timestamp` read, so it cannot move a timestamp adjudication in
  either direction. It is a shape-scoped change, adjudicated on its own merits in the
  SD-5 lane; it is recorded here only because it is why this entry needed re-work.
- **Verdict.** `ACCEPTED_DESIGN_TRADEOFF` stands. The superseded rationale is retained
  verbatim under `provenance.supersededRationale`, with the reason for replacement.

## 6. High-severity findings

GitHub reports 4 high alerts as new. They are **2 distinct findings, each reported
twice** by the per-entry recompile, both previously adjudicated and both re-verified
firsthand at the source subject. Their function bodies are byte-identical to the
adjudicated versions (`execute` L751–794@`a46bc50c` = L871–914@`aaa21d09`; `egress`
L1508–1535 = L1641–1668).

- `arbitrary-send-eth` · `execute(...)` — `recipient` and `amount` are hashed into the
  signed digest before `_authorise`, which reverts `BadSignature()` unless the floor
  signature verifies and, when `requirePq`, the committed key hash matches and the
  verifier returns true. The destination is exactly what the signature covers.
  **FALSE_POSITIVE**, detector premise fails.
- `arbitrary-send-eth` · `egress(address)` — takes no destination parameter. The
  destination is `migration.destinationVault`, writable only by `bindMigration` under
  guardian quorum **and** credential, one-shot, and re-checked against
  `destinationVaultCodeHash` at execution. **FALSE_POSITIVE**, detector premise fails.

A third high, `incorrect-exp` in `node_modules/@openzeppelin/contracts/utils/math/Math.sol`,
is a dependency finding excluded from own-code scope and correctly not counted as new
by GitHub. The `^` in `inverse = (3 * denominator) ^ 2` is deliberate XOR.

**No sustained scanner defect was found.**

## 7. What now prevents recurrence

1. **Identity has no line information.** `scanner-finding-identity.ts` keys findings by
   detector + per-element file, chain and signature + message modulo line references.
   The v1 locators are retained per entry, never deleted.
2. **Change detection is split from identity.** A narrow (node-only) fingerprint proves
   a construct changed; a broad one proves only that context did. `narrowFingerprint` is
   **undefined** — not a hash of nothing — for the 7 findings with no node element, so
   that axis can never silently assert "unchanged" for findings it cannot see.
3. **Ambiguity is fatal.** Two findings sharing an identity while disagreeing on locator
   or fingerprint produce no verdict. The 21 legitimate recompile duplicates agree on all
   three and are collapsed silently — the positive control for that check.
4. **Currency is licensed by bytes.** `scannerInputScope` binds `contractsTree`,
   `externalImportClosureSha256` (derived by walking imports, not hand-listed — it
   independently re-derived the same 12 OpenZeppelin files) and
   `scannerSemanticConfigSha256` (which excludes `--sarif`, `--json` and
   `--no-fail-pedantic`, since none can change the result set).
5. **The gate exists in CI.** The Slither job now emits SARIF and raw JSON from **one**
   execution — verified byte-identical to two separate single-output runs — and then
   validates triage completeness against that same raw output. It fails on untriaged
   findings, stale entries, ambiguous identities, fingerprint drift, and scope mismatch.
   Stale was previously a `console.warn`, which is how 21 entries drifted unnoticed.
6. **Receipts name subjects, never containers.** `SCANNER_EVIDENCE.json` names its source
   and triage subjects and nothing else; `verify-receipt-container.ts` establishes the
   publishing commit afterwards from git ancestry and delta, and refuses a receipt that
   names its own container under any field.

## 8. What is deliberately unchanged

`fail-on: none`, the complete SARIF upload, and GitHub's advisory red result all stay
exactly as they were. No alert was dismissed, no ruleset or severity threshold was
touched, and no scanner output is hidden.

GitHub's "54 new alerts" is not 54 regressions. The base branch has no Slither analysis
for this category and structurally cannot have one — the workflow's triggers are
path-filtered to `prototype/vnext-kernel/**`, which that branch does not contain — so
every alert in changed code is new by definition. The 54 are exactly the own-code raw
rows, i.e. the 33 distinct findings before dedupe. The check is advisory on this base:
no ruleset or branch protection applies to it, and `Slither` is not a required status
check even on `main`. Leaving it red is the correct outcome for a pull request that
introduces a component; the repository's own triage gate is what proves adjudication
completeness.

## 9. Limits of this correction

- Semantic identity is derived from Slither's own element chain and message. A detector
  that reported the same construct under a different chain would present as ADDED plus
  REMOVED rather than as a change. That is the conservative direction, but it is not
  free of judgement.
- The narrow fingerprint can only prove a change for findings that carry a node element
  (26 of 33 here). For the other 7 the strongest available verdict is
  `SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION`.
- `normaliseSolidity` is lexical, not a parser. It strips comments and collapses
  whitespace; it does not understand the code it hashes.
- None of this widens what Slither can see. `AUTHORITY.md` section 7 remains the
  statement of what this analysis does not establish.

## 10. A constraint this lane learned the hard way

`EvidenceSubjectProvenance.test.ts` declares two **measured evidence inputs**:

```
EVIDENCE_INPUTS = ["prototype/vnext-kernel/contracts", "prototype/vnext-kernel/stateful"]
```

Any commit that changes either path, for any reason, moves that path's tree away from
the subject declared in `validation.measuredAtHead` and correctly turns the currency
assertion red. The protocol for a lane that genuinely re-measures those inputs is to
re-declare the subject; a lane that does not re-measure them must not touch them.

This lane's first attempt added an eleven-line cross-reference to
`stateful/README.md`. That file sits inside a measured input, so the pointer moved the
`stateful` tree from `438fc418` to `7e901da7` and broke an assertion that had been green
at `aaa21d09` — over documentation, in a lane that ran no part of the stateful campaign.
Re-declaring `validation.measuredAtHead` to silence it would have asserted that the
campaign figures were measured at this lane's commit, which is false.

The pointer was removed and lives in `README.md` and this record instead, both of which
are outside `EVIDENCE_INPUTS`. **A cross-reference is never worth moving another lane's
evidence anchor.**

Two related lessons from the same episode:

- The regression was invisible until `HEAD` moved. The suite ran green at 765/0 while
  the changes sat uncommitted in the working tree, because the assertion compares the
  declared subject against `git rev-parse HEAD` — which was still `aaa21d09`. A working
  tree is not a commit, and an assertion that reads committed state cannot be exercised
  by one.
- The failure was briefly masked by reporting `npx hardhat test | grep -E "passing|failing"`,
  whose exit code is grep's. Never read a test suite's verdict through a pipe.

## 11. Enforcement gaps closed after the identity work

Semantic identity stopped a moved finding from losing its adjudication. It closed none of
the following, each of which is now covered.

### A. The hashed config could drift from the workflow

`scannerSemanticConfigSha256` hashes `PINNED_SEMANTIC_CONFIG`, which was **transcribed**
from `.github/workflows/vnext-kernel-assurance.yml`. Bump `solc-version` in the workflow
and the constant stays put: the digest keeps attesting to a configuration nothing runs.

`scanner-workflow-config.ts` now extracts the invocation from the workflow and compares
it field by field, fail-closed — an anchor it cannot find is drift, never agreement.
Nine fields are covered (slither commit, solc, EVM, optimizer enabled, optimizer runs,
remap, target, compile framework, dependency policy), each with its own mutation test.

**`crytic-compile` is not among them, and the file says so.** The workflow never names a
version; it is resolved at install time from the pinned Slither commit's own constraints.
It stays in the hashed config because it genuinely affects results, but its authority is
the observed resolution in the receipt and the CI job log. `WORKFLOW_UNPINNED` names that
gap explicitly and a test asserts the list, so a value cannot quietly move between regimes.

**The first version of this verifier was wrong in the most embarrassing way available.**
The workflow documents itself heavily and its comments quote the very flags being
extracted — `# WHY --compile-force-framework solc, not hardhat:` and
``# `fail-on: none` matches production's slither.yml``. Matching raw text captured
`"solc,"` and ``"none`"`` from that prose. The verifier was comparing **documentation** to
the constant and reporting agreement it had never established; someone could have changed
the real argument and left the comment alone. Full-line comments are now stripped before
extraction, and a test asserts the extracted values are the configuration rather than the
prose.

### B. The receipt was hand-editable

`--validate` proves every finding is adjudicated and says nothing about the rest of the
file. Test counts, solhint totals, bytecode sizes and the scope digests could all be
edited with 217/54/33 and every triage entry still valid.

The non-scanner figures moved out of command-line flags into the committed
`scanner-evidence-inputs.json`, so a regeneration depends only on committed state, the raw
run and git. `--check` regenerates and compares **bytes**. A hand-edited field cannot
survive, because the compared bytes are derived rather than read back from the file under
test.

### C. The normaliser could erase string contents

`normaliseSolidity` stripped comments with regexes. A regex cannot tell a comment marker
from the same characters inside a **string literal**, so

```solidity
string constant X = "https://example.com/a";
```

normalised to `string constant X = "https:` — everything after the double slash erased.
Two revisions differing only inside such a string produced identical fingerprints, and a
real source change would have been reported `UNCHANGED`. For a value whose entire job is
detecting change, silently deleting string contents is the worst available failure mode.

Replaced with a string-aware scanner, covered by kill tests for URLs, `//` and `/* */`
inside literals, single quotes and escaped quotes, plus controls proving real comments are
still stripped and whitespace reflow is still ignored.

**The bug was latent, not active.** Re-deriving all 33 stored fingerprints under the new
scanner changed **zero** of them, because no string literal in the analyzed contracts
currently contains `//` or `/*`. The census is unaffected; the fix is preventive.
`keyedAt.fingerprintAlgorithm` now records the scheme and the generator refuses a triage
whose algorithm it does not implement, so comment handling can never change again without
the stored values being re-derived.

### D. Container self-naming was only checked by value

`assertReceiptDoesNotNameContainer` catches an oid that equals the container but cannot
see intent. `FORBIDDEN_RECEIPT_FIELDS` now rejects `container`, `publicationContainer`,
`containerHead`, `containerTree`, `publishedIn`, and `head`/`tree` — the last two because
they are exactly what the v1 receipt stamped from `git rev-parse HEAD`. Neither check
subsumes the other: the name rule stops a field being added to hold the container, the
value rule stops an oid smuggled into an innocuous one.

### The CI ordering, and why

```
Run Slither (SARIF + raw JSON, one execution, fail-on: none)
  -> Upload Slither SARIF          scanner output reaches GitHub FIRST, so no
                                    later failure can suppress it
  -> Validate scanner triage completeness
  -> Compile prototype             the receipt records runtime bytecode
  -> Verify scanner receipt byte identity
  -> Verify publication container
```

The container argument is `github.event.pull_request.head.sha` on `pull_request` and
`GITHUB_SHA` on `push`. **Never `refs/pull/N/merge`**: on a pull_request event `GITHUB_SHA`
is a synthetic merge commit — trigger-dependent, reachable from no branch, recreated
whenever base or head moves. It is not a durable publication container, for the same
reason `evidence-subject.ts` gives.

## 12. The receipt could not reproduce across machines

CI at `0129e2ed` failed the byte-identity check on **one field**, while every
security-relevant quantity agreed exactly — 217 raw, 54 own-code rows, 33 distinct,
0 untriaged, 0 stale, 0 ambiguous, 8/15/5/5:

```
committed rawOutputSha256   054135ac9e4aff807b5d5215b15447945f960e4e0e2e2bcc8433af7e058c21be
CI-regenerated              47c5ed501dd1ffd421425282783ae26208283bd18d8e3df8bf54719dc96d89e1
```

`rawOutputSha256` hashed the entire Slither `--json` file. That value was already known
not to be portable across machines; carrying it into a receipt that must **byte-reproduce**
made two requirements collide. The defect is mine and it was avoidable.

### What actually differed — measured, not assumed

Substituting the CI workspace roots into the local file did **not** reproduce the CI hash:

| variant | sha256 |
| --- | --- |
| local (`/root/w2s/repo`) | `054135ac` |
| substituted `/github/workspace` | `8812f12d` |
| substituted `/home/runner/work/…` | `09afbe87` |
| **actual CI** | **`47c5ed50`** |

So paths were not the only cause, and guessing further would have been exactly the error
this record exists to stop. The raw JSON is now uploaded as a CI artifact; it was
downloaded and diffed structurally. **Two causes, and only two:**

1. **Result ordering.** `results.detectors` is emitted in a different order — **144 of 217
   array positions held a different finding**. This is the dominant cause and is invisible
   to any whole-file hash.
2. **Workspace root** in `filename_absolute`. `filename_relative` and `filename_short` were
   already repo-relative and identical.

Nothing else: after normalising the root and sorting, the two multisets are byte-identical
(0 only-local, 0 only-CI). The size delta was exactly 1215 × 3 bytes — the root-length
difference — which is why size alone looked like it explained everything and did not.

### The canonicalisation

Two digests replace the raw-file hash:

- **`canonicalAllFindingsSha256`** — every finding, dependencies included. Preserves detector,
  impact, confidence, the message with line references normalised, and each element's
  repo-relative file, line span, type, name, signature and parent chain. Elements sorted
  within a finding; findings sorted before hashing.
- **`canonicalDistinctOwnFindingsSha256`** — the 33 distinct own-code findings bound to their
  adjudication: semantic identity, detector, impact, confidence, both fingerprints,
  classification, and the locator as metadata.

Kept separate on purpose. The first answers *"did the scanner see the same thing?"*, the
second *"is the same set of own-code findings still classified the same way?"*. A dependency
bump moves the first and not the second; conflating them would make an OpenZeppelin upgrade
look like a change in this kernel's adjudicated state.

**Excluded, each because it varies without the code varying:** `filename_absolute`, emission
order, byte offsets and columns (`lines` already carries the span, and offsets would make the
digest sensitive to line-ending normalisation), `filename_short`, and JSON key order and
whitespace.

**Measured across the two real environments:**

```
canonicalAllFindingsSha256          55b7fd2b…   local == CI
canonicalDistinctOwnFindingsSha256  12b65196…   local == CI
```

`rawOutputSha256` is **removed**, not renamed. Keeping it and excluding it from regeneration
would have reopened precisely the hole byte-identity closed: an excluded field is an
unverifiable one.

### The crytic-compile pin

Live CI installed crytic-compile 0.4.2 from `crytic-compile<0.5.0,>=0.4.1` — a **range**.
`WORKFLOW_UNPINNED` documented that gap and called the observed version "bound by the
observed resolution". That was not a pin, and describing a gap does not close it.

The action's `slither-plugins` input runs `pip3 install -r <file>` in the **same venv** after
Slither is installed, so `scanner-requirements.txt` pinning `crytic-compile==0.4.2` forces
the exact version and fails the step if it cannot be satisfied.
`assertScannerRequirementsPinned` checks the file against the hashed config;
`assertWorkflowUsesRequirements` checks the workflow actually hands it over — without the
second, the pin could sit in the repository uninstalled. `WORKFLOW_UNPINNED` is now empty and
a test requires it to stay empty. Kills cover a simulated 0.4.3, a range, an empty file, and
the workflow dropping the input.

### One more ordering defect, found by the same test

Regenerating the receipt from the CI raw output still differed from the local one -- by
`triagedByClassification` alone. The five counts were identical; only the **key insertion
order** differed, because the census was accumulated by iterating findings in the scanner's
own emission order and JS object insertion order survives into `JSON.stringify`. That is the
raw-file-hash defect one level up, inside the deterministic artifact itself. Keys are now
sorted, and a test asserts it. The receipt is byte-identical from either environment's raw
output: `0d38572c`.

## 13. Integration boundary: what broke when the stack was actually merged

`c6c99478` merged PR #181 into #179 with an ordinary `--no-ff` merge. Every scanner
claim survived it untouched — receipt bytes, triage bytes, `contracts` tree
`dcc42e76` and `stateful` tree `438fc418` are all byte-identical to the publication
commit `3ce6a18d`, and the merge's tree equals that commit's tree exactly. Slither
still reported 217 raw / 54 own-code rows / 33 distinct with 0 untriaged, 0 stale,
0 ambiguous, and receipt byte identity passed.

**One step failed: `Verify publication container`.**

```
container    c6c99478
first parent 71aee6f3   (the #179 branch tip)
expected     ada95399   (the triage subject)
```

### The verifier was wrong, not the evidence

It required the commit under test to **be** the publication container — `HEAD^1 == T`
and `diff T..HEAD` == the receipt alone. That is true at the publication commit and
false forever afterwards. Publication is a **historical fact about one commit**;
currency is a **live fact about the head**. Conflating them makes every legitimate
integration look like tampering.

The real danger was never the red X. A check that cries wolf on every merge invites
someone to skip it on merge commits — which is exactly where a silent receipt swap
would hide.

### The two-stage model

**Stage 1 — original publication.** From the declared triage subject `T`, find the
unique commit `P` **reachable from the real head** with `P^1 == T` and `diff T..P`
exactly `SCANNER_EVIDENCE.json`. Zero → FAIL. More than one → `FAIL_AMBIGUOUS`.
Candidates come from the head's own ancestry, so an abandoned attempt that no branch
reaches can never create ambiguity.

**Stage 2 — descendant currency.** `P` is an ancestor of `H`; receipt bytes at `H`
equal `P`; triage bytes at `H` equal `P`; scanner-semantic input scope at `H` equals
both `P` and the declared source subject.

Not consulted, because each held while the receipt was stale: ancestry alone, equal
finding counts, equal tree counts, merge status, filename equality.

Ten controls, symmetric by design — half prove legitimate integration passes, half
prove tampering under an integration head still fails. Control 2 is additionally
exercised against **real history**: verifying at `c6c99478` now discovers
`P = 3ce6a18d` and passes every currency proof.

One control was wrong on the first attempt and is worth recording: control 10 made
`H` a direct child of `T` changing only the receipt, which legitimately made `H` its
**own** publication container and passed. The control was malformed, not the rule.

### A second stale claim, and why the whole class is now gone

The receipt declared `prototypeTests: 793`. Live CI at `c6c99478` ran **816 / 0**.
The 23 tests added by the enforcement lane never reached the carried figure. This was
the same defect as the 765→793 one, and byte-identity could not catch either: the
inputs file is the **regeneration source**, so it was self-consistent and wrong about
the world. **Byte-identity proves reproducibility, not the truth of carried figures.**

The fix is domain separation, not a better number. Test execution has its own CI
authority; a scanner receipt restating it was duplicated authority with no mechanism
behind it. The whole `tests` block is removed — prototype, production and coverage —
and `assertReceiptDomain` refuses to emit any of them. **793 was stale; the aggregate
predecessor `c6c99478` ran 816/0; the field is gone because it is out-of-domain
carried observational evidence, not because 816 is being hidden.**

The inputs file is now parsed against a strict **allowlist** (`$schema`,
`description`, `solhint`). The invariant is *unknown input field → FAIL*, not four
forbidden names — a denylist would have stopped `prototypeTests` returning and waved
through `testExecutionSummary`.

Receipt schema `v2 → v3`; inputs schema `v1 → v2`; both asserted exactly. Historical
v2 receipts remain untouched.

**Disclosed residual:** `scanners.solhint` (36/0) is still a hand-carried figure with
the same staleness exposure. It stays because solhint *is* a scanner, so it is
in-domain — but binding it mechanically is a separate lane, deliberately not widened
into here.

### A false absence claim

The receipt asserted *"No fuzzing campaign, no formal verification"*. That was
**false at the receipt's own source subject**:
`prototype/vnext-kernel/test/StatefulAuthorityFuzz.test.ts` exists at `aaa21d09` and
declares a *STATEFUL ADVERSARIAL AUTHORITY / RECOVERY CAMPAIGN* over deterministic
`(profile, seed, depth)`.

A receipt asserting a repository-wide absence it never measured is a stale claim in
prose. `knownAnalysisAbsences` is replaced by `scannerEvidenceDoesNotEstablish`,
scoped to what this receipt can legitimately state: detector-model bounds, CodeQL's
missing Solidity extractor, the element-chain identity limitation, and the
narrow/broad fingerprint limitation. Audit status, formal verification, fuzzing,
PQ verifier assurance and guardian independence are stated by `AUTHORITY.md` and the
campaign receipts, and are deliberately **not** restated here.

### Fixture minimization — stated accurately

The cross-environment fixtures were **10,324,917 bytes — 91% of this stack's entire
insertion count** — because they were pretty-printed and retained parent-chain line
arrays the digest never reads (one contract element carries 1,638 line numbers).

| historical fixture | sha256 | bytes |
| --- | --- | --- |
| `raw-findings.local.json` | `cb5d09372c4d772b3325938ab0db1dccb8d89df8ed18e94538d2f3ca418443bb` | 5,160,636 |
| `raw-findings.ci.json` | `1428aec4c6dc809830e225254261f22e4ae13f1f7ada48ad30f4b38d749d6e64` | 5,164,281 |

Both reproduce the published `canonicalAllFindingsSha256` `55b7fd2b…`, verified before
replacement.

They are replaced by **minimized excerpts selected and derived from those historical
real outputs**, not by the outputs themselves — 32,897 + 32,866 bytes. The excerpts
cover every discriminator: own+node+parent-chain, own with no node element, own
multi-element, a `node_modules` dependency, High/Low/Informational impact, Medium
confidence. The CI excerpt uses the **real** workspace-root substitution and the
**actual relative order** the CI run produced.

The full 12-point matrix was run against both pairs — historical read from git at
`3ce6a18d`, minimized from disk — with identical verdicts: 3 controls (workspace root,
result order, key order/whitespace) and 9 kills (detector, impact, confidence, message,
repo-relative source, line span, signature, removed finding, added finding). **All
discriminators retained.**

This reduces the **current tree and future checkout/diff footprint**. It does **not**
remove the historical blobs from git history — accepted history is immutable and no
rewrite was attempted or permitted.
