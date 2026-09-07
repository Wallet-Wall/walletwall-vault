# Lane W1R — final adversarial review of the W1 evidence-only diff

**Object under review:** the tracked diff against `c67d1439`, materialized in
Lane W1P and minimized here. **This lane reviewed worktree content made visible
by `git add -N` (intent-to-add). Nothing is staged with content, nothing is
committed.** `git diff --cached` is empty; a future commit must `git add` the
explicit path list in §9, never a repository-wide add.

The prior lane records were not treated as authority for this review; the diff
was.

---

## 1. Suites, measured on this diff

| Suite | Result |
| --- | --- |
| `FULL_SUITE_EXACT_W1P` — the 38-file diff as materialized, before pruning | **638 passing · 0 failing · 0 pending · 7 m 57 s** |
| `EVIDENCE_SUITE_EXACT_W1P` — `test/Sd4*.test.ts` after pruning | **144 passing · 0 failing · 50 s** |
| full suite after pruning (`W1_READY_TO_COMMIT` basis) | **611 passing · 0 failing · 0 pending · 10 m 39 s** — matches the 638 − 27 predicted below before the run |

**Deltas, from the discovered test files rather than a carried baseline.**
637 → 638: W1P added `Sd4LaneW1PAbiDelta.test.ts` with one test. 171 → 144
evidence tests after pruning: −13 (`Sd4CandidateG`), −9 (`Sd4CandidateCompile`),
−3 (`Sd4LaneUCompile`), −3 (`Sd4LaneW` D/E/F), +1 (the ABI test now measures
E1 and E0 separately) = −27. The pruned full-suite expectation is therefore
638 − 27 = **611**, and the measured figure is stated below.

## 2. Every file, classified — `W1_MINIMUM_REPRODUCIBLE_FILESET`

Classes: **A** required executable evidence · **B** required semantic/audit
record · **C** required future implementation contract · **D** redundant
intermediate · **E** scratch. The question asked of each: *if it vanished, which
persisted claim becomes non-reproducible or materially harder to audit?*

### Modified tracked files (4)

| Path | Class | Justification |
| --- | --- | --- |
| `stateful/invariants.ts` | B (provenance) | one `source` string; the predicate is unchanged; the four conditions of W1P §1 verified |
| `KERNEL_ADMISSION.md` | B (conformance) | append-only K-9 correction beneath the retained false sentence, on the file's own K-15 precedent |
| `AUTHORITY.md` | B (conformance) | append-only correction beneath #188's retained SD-4 paragraph |
| `stateful/README.md` | B (conformance) | staleness note carrying the receipt's own identity (`head 28adbb88`, `tree 849e140b`) |

### New — canonical records (4)

| Path | Class | Unique content |
| --- | --- | --- |
| `docs/Vault_vNext_Recovery_Amendment.md` | B | the only SOURCE / DERIVED / CONFORMANCE-tagged statement of K-9, the epoch, effective expiry, SD-4's disposition and the replay rule; layered above #179 |
| `SD9_RECOVERY_LIFECYCLE_DEFECTS.md` | B | the only classification distinguishing SD-9a (hazard / spec gap) from b–e (present defects) and SD-10 (separate root) |
| `W2_IMPLEMENTATION_CONTRACT.md` | C | the only statement of Candidate C, its forecast delta (E0, +1 selector) and the 15-mutant contract |
| `semantics/WW-VNEXT-RECOVERY-SOVEREIGNTY.yaml` | B | the only resolution of the seven readings A–G of `I-RECOVERY-SOVEREIGNTY`; its open decision is marked moot |

### New — lane adjudication records (8, this file included)

| Path | Class | Unique evidence it alone carries | Superseded content |
| --- | --- | --- | --- |
| `SD4_TEMPORAL_ADJUDICATION.md` | B | the temporal-authority axis; "the harm lands in no cell of the cut table"; the ladder; the T7b dead-episode hazard | its `clamped` recommendation — reclassified by the clock rule in Lane V, header links |
| `SD4_LANE_U_ADJUDICATION.md` | B | the U1 8×2 postcondition matrix and window collapse; the U5 trilemma refutation attempt; the `AMBIGUOUS` coordinates for `RECOVERY_DELAY`; first location of the `docs/` authority | the 21-day inference, withdrawn in its Lane V header — **preserved, not erased** |
| `SD4_LANE_V_ADJUDICATION.md` | B | the `I-RECOVERY-*` cluster read; the five-point model/kernel divergence; the 28-day baseline; the clock-rule reclassification table; the reasoning that then declined to call overwrite a defect | overwrite verdict, superseded in V2 — preserved |
| `SD4_LANE_V2_ADJUDICATION.md` | B | K-9's missing half; the refund counterexample and its non-forceability; the epoch-key falsification (six cancels); the model-underdetermined verdict | — |
| `SD4_LANE_W_SEMANTIC_FREEZE.md` | B | the five-proof K-9 freeze; **B2 never-reset degeneration (only witness)**; the two state machines; the consumer table | §D boundary (superseded by W1, header); §H–J Candidate P plan (**pruned to a pointer**) |
| `SD4_LANE_W1_BOUNDARY_CORRECTION.md` | B | the cross-artifact boundary table; mined-instant probe method; adopted epoch text; seven-timing two-path table; the positional-tooling finding behind the getter question | Option B (superseded by W1.2, header); §8–9 (**pruned to a pointer**) |
| `SD4_LANE_W12_STATE_MINIMALITY.md` | B | nine-history equivalence; the label-seeded-signer harness trap; six replay cases; the P-vs-C table; mutation discriminability | §G (**pruned to a pointer**) |
| `SD4_LANE_W1R_DIFF_REVIEW.md` | B | this fileset justification, the E0 verdict, the `git add` list | — |

### New — executable evidence (17)

| Path | Class | Claim it alone pins | Deterministic | Deprecated API | Discriminates |
| --- | --- | --- | --- | --- | --- |
| `sd4-candidate-kernels.ts` | A | every in-memory candidate, including the falsified ones; nothing touches `contracts/` | yes | — | — |
| `sd4-harness.ts` | A | shared plumbing | yes | — | — |
| `Sd4CandidateF.test.ts` | A | F's cut regression `min(2,k) → 1` — the only measured cut change in the whole campaign | yes | no | yes |
| `Sd4CandidateGPrime.test.ts` | A | "k guardians install any verifier **today**" on the unmodified kernel; G′'s survival of the cut census (the falsified survivor) | yes | no | yes |
| `Sd4CandidateH.test.ts` | A | H1–H4 kills incl. `G-CHALLENGE-CAP` breach | yes | no | yes |
| `Sd4CorrectionsAB.test.ts` | A | second-preimage correction; stranded-not-bricked correction | yes | no | yes |
| `Sd4RedTeamRound2.test.ts` | A | G's signature-axis kill under a real verifier; F overstated; H1 order-dependence | yes | no | yes |
| `Sd4Round3PremiseAudit.test.ts` | A | containment already obstructs the declaring edge; only `pqSignatureLength` is free — the fact U5 collapses on | yes | no | yes |
| `Sd4PropertyOverApproximation.test.ts` | A | the oracle fires on a repaired recovery — the executable basis of the `invariants.ts` correction | yes | no | yes |
| `Sd4TemporalAuthority.test.ts` | A | T0 positive control (lifetime budget); payload-aging; same-block; the notice ladder; T7b | yes | no | yes |
| `Sd4LaneU.test.ts` | A | U1 matrix; window collapse; U3 equivalence; F extension; G observability; U5 | yes | no | yes |
| `Sd4LaneV.test.ts` | A | B1 mismatch; C five proofs; D stranding; E 28-day baseline | yes | no | yes |
| `Sd4LaneV2.test.ts` | A | K-9 refutation; refund counterexample; composition; epoch-key falsification; first conformant remedy | yes | no | yes |
| `Sd4LaneW.test.ts` | A | **B2 never-reset degeneration**; B1; B3 — D/E/F removed (superseded by W1 on the corrected boundary) | yes | no | yes |
| `Sd4LaneW1.test.ts` | A | E−1/E0/E+1 mined-instant probes; identical-material reset; seven-timing two-path remedy | yes | no | yes |
| `Sd4LaneW12.test.ts` | A | nine-history equivalence; six replay cases | yes | no | yes |
| `Sd4LaneW1PAbiDelta.test.ts` | A | E1 probe +2 / E0 forecast +1; `recovery()` identical | outcome-deterministic (random label; ABI-only assertions) | no | yes |

All are intentionally synthetic — in-memory kernels, never `contracts/` — and
every compiled candidate establishes **candidate feasibility**, not a W2
artifact. None relies on `.to.be.reverted`; the one legacy use was replaced with
`.to.be.revert(ethers)` in Lane T.

### Removed as redundant — `W1_REDUNDANT_FILES` (6 files, 3 sections, 3 tests)

| Removed | Class | Why it was redundant, and where the evidence lives |
| --- | --- | --- |
| `test/Sd4CandidateG.test.ts` | D | proved only G's commitment-axis closure — a superseded partial; the kill is `Sd4RedTeamRound2`, and `buildCandidateG` is exercised by GPrime, LaneU, Round2, Temporal |
| `test/Sd4CandidateCompile.test.ts` | D | every builder it compiled is compiled in another test's `before` (map in the W1R report) |
| `test/Sd4LaneUCompile.test.ts` | D | U1/U2a/U2b/U5 are compiled by `Sd4LaneU` |
| `semantics/WW-VNEXT-RECOVERY-EPISODE.yaml` | D | its seven-question table is Lane U §3; both halves resolved in the amendment and SD-9 |
| `semantics/WW-VNEXT-RECOVERY-CHALLENGE-EPOCH.yaml` | D | a second source of semantic truth for the epoch — the amendment §2 is the one; its expiry-reset nuance is Lane V §2 |
| `SD4_LANE_V_CANDIDATE_DEFECTS.md` | D | candidate wording superseded by SD-9; its overwrite reasoning is Lane V §3 |
| Lane W §H–J, W1 §8–9, W12 §G | D | plans, not evidence; Candidate P's falsification is W12 §E; the surviving contract is persisted once |
| `Sd4LaneW.test.ts` D/E/F | D | measured on the superseded closed boundary; `Sd4LaneW1` asserts strictly more on the corrected one |

Every deletion was checked for dangling references (four found, four repaired;
zero remain). **No falsification was erased**: each superseded conclusion is
either still in its original file under a supersession header, or restated at
the point of supersession.

## 3. Lane records — bloat review

Each record was kept to claim / authority / counterexample / measurement /
verdict / supersession / coordinates. Three plan-shaped sections were pruned
(§2). No command narration or test output is persisted; the test files are the
output.

## 5. `EFFECTIVE_RECOVERY_PUBLIC_GETTER = NOT_REQUIRED`

| Question | Answer |
| --- | --- |
| Does #179 require a kernel getter, or only truthful observability? | Truthful observability. The Observatory publishes identities (§15.2) and holds no authority (`:840`); nothing names a recovery-liveness selector. |
| Can an observatory derive it without trusting external mutable state? | Yes — `active` and `expiresAt` are public tuple fields; "now" is the block being read. |
| Does off-chain timestamp interpretation create ambiguity? | No — the rule is `active && now < expiresAt`, evaluated against the same block on and off chain. |
| Does any on-chain consumer need it public? | No — an internal `_recoveryIsLive()` serves `initiateRecovery`, both cancellations and `bindMigration`. |
| Is `effectiveSafeState()` analogous? | In purpose, not in need: its NatSpec (`:679-683`) exists because a stored **enum** reads as a state the kernel no longer holds. `active`/`expiresAt` are raw fields a reader must already combine — and the oracle already derives safe state from stored fields itself (`invariants.ts:415`). |

Measured: the E0 build adds **one** selector; the E1 probe adds two and is kept
only as the observation instrument for `Sd4LaneW12`. **W2 forecast: +1.** A
public view remains an allowed W2 choice, not the forecast.

## 6. `W2_FORECAST_LABELING`

Every structural figure in `W2_IMPLEMENTATION_CONTRACT.md` sits under a column
or section labeled **forecast**; the structural-delta section is headed *W2
DESIGN FORECAST, not an observation* and states that its numbers are asserted on
an in-memory candidate. Byte figures are labeled *FORECAST — unmeasured*. The
amendment's "byte-identical material", "stale bytes" and "nonce unchanged" are
observations at `c67d1439` or on the probes, and read as such.

## 7. `GUARDIAN_CANCEL_REPLAY_PROOF_ROBUSTNESS`

The amendment §5 now names, for each of the six premises, the `Sd4LaneW12`
assertion that fails if the premise stops holding. The structural mutation
*"`initiateRecovery` stops consuming the `DOMAIN_GUARDIAN` nonce"* fails the
assertion *"initiation consumed the stale nonce"* (`nonces == N+1` after R2)
immediately — the proof fails closed in a test, not a paragraph. The dependency
is stated in the amendment as a review-visible block.

## 8. `GENERATED_EVIDENCE_STALENESS_ACCURACY`

The README note now states the receipt's own identity (`head 28adbb88`, `tree
849e140b`, `solidityChanged.bytes = 299`), that it is carried unchanged to
`c67d1439`, what remains valid (all measurements and the four sustained defects
at that head), what is absent (the oracle source, the SD-4 supersession, SD-9,
SD-10, K-9 partial), why regeneration before W2 would mislead (restamp,
republish superseded text, still omit SD-9/10), and the authorising event (W2
landing and re-measurement). The four artifacts are byte-unchanged.

## 9. `git add` handling

- `git diff --cached` is **empty**: intent-to-add entries carry no content.
- No unintended path is marked: `git status --short` shows exactly the paths in
  the list below plus the four modified tracked files.
- **The future commit must add exactly these paths** (never `git add -A`):

```text
docs/Vault_vNext_Recovery_Amendment.md
prototype/vnext-kernel/AUTHORITY.md
prototype/vnext-kernel/KERNEL_ADMISSION.md
prototype/vnext-kernel/SD4_LANE_U_ADJUDICATION.md
prototype/vnext-kernel/SD4_LANE_V2_ADJUDICATION.md
prototype/vnext-kernel/SD4_LANE_V_ADJUDICATION.md
prototype/vnext-kernel/SD4_LANE_W12_STATE_MINIMALITY.md
prototype/vnext-kernel/SD4_LANE_W1R_DIFF_REVIEW.md
prototype/vnext-kernel/SD4_LANE_W1_BOUNDARY_CORRECTION.md
prototype/vnext-kernel/SD4_LANE_W_SEMANTIC_FREEZE.md
prototype/vnext-kernel/SD4_TEMPORAL_ADJUDICATION.md
prototype/vnext-kernel/SD9_RECOVERY_LIFECYCLE_DEFECTS.md
prototype/vnext-kernel/W2_IMPLEMENTATION_CONTRACT.md
prototype/vnext-kernel/semantics/WW-VNEXT-RECOVERY-SOVEREIGNTY.yaml
prototype/vnext-kernel/stateful/README.md
prototype/vnext-kernel/stateful/invariants.ts
prototype/vnext-kernel/test/Sd4CandidateF.test.ts
prototype/vnext-kernel/test/Sd4CandidateGPrime.test.ts
prototype/vnext-kernel/test/Sd4CandidateH.test.ts
prototype/vnext-kernel/test/Sd4CorrectionsAB.test.ts
prototype/vnext-kernel/test/Sd4LaneU.test.ts
prototype/vnext-kernel/test/Sd4LaneV.test.ts
prototype/vnext-kernel/test/Sd4LaneV2.test.ts
prototype/vnext-kernel/test/Sd4LaneW.test.ts
prototype/vnext-kernel/test/Sd4LaneW1.test.ts
prototype/vnext-kernel/test/Sd4LaneW12.test.ts
prototype/vnext-kernel/test/Sd4LaneW1PAbiDelta.test.ts
prototype/vnext-kernel/test/Sd4PropertyOverApproximation.test.ts
prototype/vnext-kernel/test/Sd4RedTeamRound2.test.ts
prototype/vnext-kernel/test/Sd4Round3PremiseAudit.test.ts
prototype/vnext-kernel/test/Sd4TemporalAuthority.test.ts
prototype/vnext-kernel/test/sd4-candidate-kernels.ts
prototype/vnext-kernel/test/sd4-harness.ts
```

## 10. Properties of the final diff

| Property | Held |
| --- | --- |
| no duplicated authority source | yes — #179 untouched; the amendment is the single derived layer |
| no duplicated source of semantic truth | yes — the epoch/expiry/replay statements live once, in the amendment; two duplicate YAMLs removed |
| no exploratory-only fixture committed | yes — three compile/partial-result tests and three superseded test blocks removed |
| no historical falsification erased | yes — every supersession is a header or a pointer, never a deletion of the falsified text |
| no unimplemented W2 fact presented as observed | yes — §6 |
| no generated evidence restamped | yes — four artifacts byte-unchanged |
