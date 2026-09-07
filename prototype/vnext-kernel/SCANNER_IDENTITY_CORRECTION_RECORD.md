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
