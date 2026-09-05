# SD-10 — implementation record (Lane SD10-I: approved-recovery preservation, implemented)

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> **Local, uncommitted implementation object.** Worktree
> `C:\dev\wv-sd10-implementation`, branch
> `security/vnext-sd10-approved-recovery-preservation`, base
> `a42f5c7e2d517cd25a0fc0c9d90599648f5282a9` (head of PR #188,
> `security/vnext-sd4-recovery-request-semantics`, verified **OPEN / DRAFT**
> before branching; tree `6131f88695198274d52ec5ec9b91328859d8305a`).
> **Nothing is committed, pushed, or proposed. No generated evidence was
> regenerated.** The shared `C:\dev\walletwall-vault` checkout was never
> branch-switched, and the Lane SD10-D1 worktree's six exploratory scratch
> files are NOT part of this object.

This record is the implementation-side counterpart of the Lane SD10-D1
adjudication (`DECISION = PRESERVE APPROVED REQUEST`). It answers the SD10-I
brief item by item and lists everything an independent reviewer should expect
to find red, stale, or deliberately untouched.

---

## 1. Source authority, frozen before implementation

Read firsthand at the base, quoted rather than paraphrased.

| Construct | Location at `a42f5c7e` | Text / behaviour |
| --- | --- | --- |
| `I-RECOVERY-NONVETO` | `docs/Vault_vNext_Architecture.md:945` (and a duplicated `:946`, pre-existing) | "No principal holds an unbounded veto over an otherwise-valid recovery." |
| `I-RECOVERY-TERMINATION` | `docs/Vault_vNext_Architecture.md:948` | "Every quorum-approved request leaves the system by execution, cancellation, or **expiry — and expiry requires no principal to act.**" |
| `I-APPROVED-REQUEST-PRESERVATION` | `docs/Vault_vNext_Architecture.md:951` | "Once a request reaches quorum, a guardian-set replacement cannot clear it." |
| `executeRecovery` generation invalidation | `contracts/VaultKernelPrototype.sol:1334-1335` | `// A roster change since the request invalidates it.` / `if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();` |
| `setGuardians` generation transition | `contracts/VaultKernelPrototype.sol:1085-1112` | `_requireNormal()`, canonical-roster check, digest over the CURRENT `guardianGeneration`, `_requireQuorum`, `_consume`, then `guardianGeneration += 1` and `GuardianCommitmentSet`. It consults nothing about `recovery`. |
| `cancelRecoveryByQuorum` current-generation authorization | `contracts/VaultKernelPrototype.sol:1295-1311` | Digest binds the CURRENT `guardianGeneration`; `_requireQuorum` runs before `_consume`, so a superseded constituency dies as `QuorumNotMet`/`BadRoster` before its nonce is examined. |
| `recoveryPossessionDigest()` | `contracts/VaultKernelPrototype.sol:616-632` | Binds `r.boundGuardianGeneration` — a **stored** field, not the live generation. |

**The frozen target (SD10_TARGET).**

```
an already quorum-approved recovery remains executable across guardian-set
replacement until execution, explicit cancellation, credential challenge,
or expiry

FRESH guardian authority after rotation = CURRENT roster only
OLD guardian approval = preserved pre-committed effect, not fresh authority
```

This is **not** old guardians retaining membership. Section B of the permanent
suite is the standing proof that they retain none.

**A fact the freeze surfaced, load-bearing for the design.**
`recoveryPossessionDigest()` binds `r.boundGuardianGeneration`, and
`kernelGeneration()` is a per-clone constant read from the clone args — not the
guardian generation. So keeping `boundGuardianGeneration` **pinned at G** is
what makes a possession proof signed before a rotation still valid after one.
Re-binding the request to the new generation (the family SD-10's own
`minimalFixSketch` considered under "(b)") would silently invalidate a
pre-signed PoP. Test F2 measures this directly.

---

## 2. The correction

One semantic statement removed from `executeRecovery`, and the comment above it
replaced with one that distinguishes the two generations.

```solidity
-        // A roster change since the request invalidates it.
-        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();
```

`boundGuardianGeneration` is **retained** in `RecoveryRequest`, still written at
initiation, and still bound into the possession digest. `BadRoster` remains in
the ABI: five other `revert BadRoster()` sites remain (`:1054`, `:1055`,
`:1125`, `:1126`, `:1136`), all of which mean "you are not the roster", which is
the error's correct meaning. SD-10 was the case where it also meant "your
already-approved request is stale".

Nothing else changed in Solidity. No storage layout change, no ABI change, no
selector, no event, no ratification, no guardian snapshot, no request id,
`setGuardians` unblocked, no auto-cancel, no clock touched.

**Where the replacement prose lives, and why it moved.** It was first written as
a 27-line comment *inside* `executeRecovery`. That tripped solhint's
`function-max-lines` — "body contains 58 lines but allowed no more than 50",
against 33 on the base — which is a warning this lane introduced and had no
reason to. The rationale now sits in the function's `@dev` NatSpec, above the
signature, where it does not count toward the body and where this kernel already
keeps its design prose; a four-line marker remains at the removal site. The
relocation is **provably comment-only**: the kernel's runtime **executable hash
is identical** across both versions (`0xe82197c28d…`), and only the CBOR
metadata hash moves. `solhint` is back to **36 warnings / 0 errors, exact parity
with the base**.

| Metric | base | first draft | final |
| --- | --- | --- | --- |
| kernel runtime | 18,425 | 18,367 | **18,367** |
| kernel exec bytes | 18,372 | 18,314 | **18,314** |
| kernel exec hash | `0x479b6e40…` | `0xe82197c2…` | **`0xe82197c2…`** |
| solhint warnings | 36 | 37 | **36** |

### 2.1 A correction to the ledger's own fix sketch

`stateful/defects.ts` SD-10 `minimalFixSketch` enumerates two families and
rejects (b):

> (b) PRESERVE the request across a rotation by **re-binding it to the new
> generation** — rejected in principle, because generation binding is exactly
> what kills a stale constituency's authority (mutant M16), and a request
> re-bound to a roster that never approved it is that mutant wearing a
> different hat.

The implemented correction is **neither** family. It freezes
`boundGuardianGeneration` at G — the request is never re-bound to anyone — and
removes only the execution-time re-validation. The rejection of (b) stands and
is untouched; the sketch was incomplete, not wrong. The entry is left as-is
(see §7).

---

## 3. RED → GREEN

The permanent suite was written first and run against the **unmodified** base.

| Run | Kernel | Result |
| --- | --- | --- |
| RED (primary property only, written first) | exact base `a42f5c7e` | **0 passing / 1 failing** — `BadRoster()` at `executeRecovery` |
| RED (the complete permanent suite) | exact base `a42f5c7e` | **10 passing / 13 failing** |
| GREEN | corrected | **23 passing / 0 failing** |

Every one of the 13 RED failures traces to the removed statement:

| Failure shape | Count | Detail |
| --- | --- | --- |
| direct `BadRoster()` revert from `executeRecovery` | 10 | A1, A2, C2, E1, F2, H1, H2, I2, I3, I4 |
| `D1` — "execution succeeded at the last live instant" | 1 | the VM exception at `expiresAt-1` is `BadRoster` |
| `F1` — expected `BadSignature`, **got `BadRoster`** | 1 | on the base the generation gate fires *before* possession is evaluated at all |
| `G1` — `[1, 0]` for `rotate-first` | 1 | `execute-first` gives `[1, 1]`; the outcome depended on block ordering |

The 10 that PASS on the base are the regression guards — section B in full (the
replaced roster holds no fresh authority), C1/C3, D2/D3 (the expiry boundary,
which is refused *before* the generation gate is reached), G2 (nonce
serialisation) and I1 (the honest roster's cancellation recourse, which does not
depend on execution succeeding).

Two of these are worth a reviewer's attention beyond the count:

* **F1** shows that on the base kernel, after a rotation, a forged-possession
  attempt and an honest one are **indistinguishable** — both die at the same
  gate. Removing it is what makes possession failures observable again.
* **G1** independently reproduces Lane SD10-D1's measured race asymmetry: on the
  base, whether an approved recovery survives was decided by the order two
  transactions happened to land in, i.e. by whoever builds the block. Under the
  correction both orders yield `[1, 1]`.

RED attribution is **proven, not assumed**: the only change between the RED and
GREEN runs is the removal of that statement.

---

## 4. Permanent suites added

### `test/Sd10ApprovedRequestPreservation.test.ts` — 23 tests (kernel) + 8 model tests in `VaultVNextArchitectureModel.test.ts`

| § | Covers | Tests |
| --- | --- | --- |
| A | primary property; the new roster gains no retroactive authorship; execution stays permissionless (driven by an outsider) | A1, A2 |
| B | the replaced roster retains **no** fresh authority: quorum cancel, `setGuardians`, containment, fresh initiation, `bindMigration` — each with a positive control | B1, B1b, B1c, B2 |
| C | credential challenge after rotation: counted, clears authority, refunds nothing, stays bounded, refused once expired | C1, C2, C3 |
| D | the half-open window across a rotation at `expiresAt-1 / expiresAt / expiresAt+1`, each in its own world at a MINED instant | D1, D2, D3 |
| E | repeated rotations G → G+1 → G+2 → G+3, then execute the same R1 | E1 |
| F | `PRESERVED_APPROVAL != UNCONDITIONAL_EXECUTION` — four possession probes plus a positive control; and a PoP pre-signed before the rotation | F1, F2 |
| G | same-block races: rotate × execute (both orders), rotate × current-quorum cancel (both orders) | G1, G2 |
| H | the challenge epoch across rotation: partial and exhausted budgets, neither reset nor refunded; execution is still the one reset boundary | H1, H2 |
| I | hand-over to an honest roster after a MALICIOUS approval; containment; the dead-verifier escape; a same-material recovery | I1, I2, I3, I4 |

Section I is the adversarial set the decision has to survive, and two of its
tests were written twice because the first version proved less than it looked:

* **I2** first entered containment at `t0`. `CONTAINMENT_MAX` is 3 days and
  `RECOVERY_DELAY` is 7, so containment would have **self-expired** long before
  maturity and the test would have executed against a NORMAL vault while
  claiming otherwise. It now enters containment one day out and reads the
  **derived** `effectiveSafeState()` at the moment of execution, not the stored
  byte, which can go stale by design.
* **I3** first used the default honest verifier as the vault's live one, so
  "the escape from a dead verifier" was not being exercised at all. It now
  deploys with `verifier: "reverting"` — the same dead verifier the
  `byzantine-verifier` campaign profile uses — so the escape is real.

**A probe-quality note, recorded because it nearly went the other way.**
`initiateRecovery` and `bindMigration` both refuse *before* their quorum check
while a request is live (`BadState` and `NoRecovery` respectively, from W2's
overwrite refusal and migration subordination). Probing the old roster's
authority through them with a live request would have passed while proving
nothing about authority. Both were moved into worlds where the authority gate is
actually reached (B1b, B1c), each with a positive control.

### `test/Sd10PreservationMutations.test.ts` — 10 tests

Mirrors `W2RecoveryLifecycleMutations`' discipline: boolean non-asserting
properties, `setup:` results never credited as kills, a vacuity guard, the
assigned property must hold on the real kernel, and kill credit only for the
exact observation the mutant exists for.

```
SD-10 MUTATION KILL MATRIX
mutant                                                1  2  3
M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST        K  .  .
M-SD10-T-ROTATION-AUTO-TERMINATES-REQUEST             K  .  ?
M-SD10-B-ROTATION-BLOCKED-WHILE-REQUEST-LIVE          ?  K  ?
M-SD10-S-QUORUM-ROSTER-PREIMAGE-UNBOUND               .  .  K

  1 P-SD10-APPROVED-REQUEST-PRESERVED
  2 P-SD10-ROTATION-REMAINS-AVAILABLE
  3 P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY
```

**Property 3 now has a killing mutant.** An earlier draft carried
`P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY` as a deliberately unkilled guard,
which independent review correctly called weak assurance — a property no mutant
exercises may be passing vacuously. `M-SD10-S-QUORUM-ROSTER-PREIMAGE-UNBOUND`
deletes the kernel's **only** roster-preimage binding (`_requireQuorum:1125`).

Two honesty constraints on how that mutant is presented, both from adversarial
verification of the proposal:

* It is **named for what it actually does**, not for the symptom the property
  observes. Deleting that line is not "the old roster keeps its seat" — it is
  universal quorum forgery across all five quorum-gated entries, by addresses
  that were never guardians at any generation. The narrower name would have
  overstated its specificity.
* It guards **BASE** code enforcing `I-GUARDIAN-AUTHORITY-CLOSURE`, untouched by
  this lane and corresponding to no SD10-D1 candidate. It proves the property
  discriminates; it is **not** evidence about anything SD10-I changed, and must
  not be counted as SD-10 coverage.

Candidate **R** (ratification) gets no mutant: it adds a selector, an event and
~292 bytes, so it is not expressible as a semantic edit. Its absence is asserted
structurally instead (no `ratify`/`reaffirm`/`rebind`/`reapprove` surface;
`recovery()` still returns exactly its eight base fields).

---

## 5. Model correction

The reference model was **not** conformant-by-accident; it implemented a
different candidate.

| Site | Before | After |
| --- | --- | --- |
| `test/helpers/vaultVNextModel.ts` `replaceGuardians` | **DENIED** the replacement while an approved request existed — candidate B | Replacement is **admitted**; an **approved** request is preserved intact; an **unapproved** one is still cleared |
| `test/helpers/vaultVNextModel.ts` `executeRecovery` | denied on `!guardianGenerationValid(req.boundGuardianGeneration)` | gate removed (now mutation M61) |
| `test/VaultVNextArchitectureModel.test.ts` I-APPROVED-REQUEST-PRESERVATION | asserted `DENIED` | asserts the replacement is `OK`, the request survives with clocks and provenance intact, and **still executes** at maturity |

**Why an unapproved request is still cleared, deliberately.** Its accumulated
supports are *fresh authority the outgoing constituency was still assembling* —
not an admitted effect — and fresh authority belongs to the roster in force.
That single line is where the model draws the distinction the whole lane turns
on.

**Discrimination.** The model now separates the selected semantics from all
three neighbours by mutation rather than by prose:

| Mutation | Candidate | Killed by |
| --- | --- | --- |
| `M59_GUARDIAN_REPLACEMENT_BLOCKED_BY_APPROVED_REQUEST` | B — block rotation | replacement must remain independently available |
| `M60_GUARDIAN_REPLACEMENT_CLEARS_APPROVED_REQUEST` | T — auto-terminate | request must survive |
| `M61_APPROVED_REQUEST_INVALIDATED_BY_GENERATION_CHANGE` | BASE — SD-10 | preserved must mean **executable**, not merely stored |

M61 exists because a discriminator that only checked for the request's
*presence* would not have seen the base defect at all — which is how it survived
in the kernel for as long as it did.

### 5.1 THE QUORUM-SIZE SEAM — a defect this lane INTRODUCED, found by independent review

The first draft of the model correction admitted the replacement and preserved
the approved request, but did **not** freeze approval. `requiredSupports()` is
`floor(members / 2) + 1` over the roster IN FORCE, and `RecoveryRequest` carried
no approval field — so every question about a stored request's approval was
re-derived under whoever held authority later. Measured, not argued:

```
3 guardians, quorum 2   →  approve 2-of-3            →  approved
rotate to 5 guardians   →  quorum becomes 3
execute                 →  DENIED "insufficient supports"
```

**SD-10 reproduced in the model, through a second door.** The lane's own model
test did not catch it because it rotated to `["h1","h2","h3"]` — same size, same
quorum. A same-size rotation cannot distinguish a latched model from a
re-deriving one, which is exactly the "passes for the wrong reason" failure this
record already documents for the kernel probes (§4), recurring in the model.

A follow-up census found the seam had **four surfaces**, three of them worse
than the one reported, and all four measured before being fixed:

| # | Surface | Consequence |
| --- | --- | --- |
| 1 | `executeRecovery` (the reported one) | preserved request stranded after a growth rotation |
| 2 | `replaceGuardians` | a **SECOND** replacement re-derived `approved` as false and took the **clearing** branch — deleting a preserved request outright, i.e. reproducing candidate T (mutation M60) on a reachable path, in the lane whose purpose is to forbid exactly that |
| 3 | `initiateRecovery` overwrite guard | after a growth rotation the preserved request stopped counting as approved, so a fresh initiation could **overwrite** it with attacker-chosen credential material |
| 4 | downward direction | 2-of-5 unapproved, rotate to 3: would become retroactively sufficient — blocked only incidentally, by `replaceGuardians` clearing unapproved requests |

**The fix: latch approval as an EVENT.** `RecoveryRequest.approved` is set once,
inside `supportRecovery`, at the moment `supports.length` first reaches the
quorum **in force at that moment**, and never recomputed. All four consumers now
route through one accessor, `requestIsApproved()`.

This makes the model MIRROR the kernel rather than invent a rule the kernel
never had: a kernel request only comes into existence after `_requireQuorum`
succeeds inside `initiateRecovery`, so approval there is **atomic at creation**
and cannot be revisited. (Confirmed independently against the Solidity: the
kernel has no supports-accumulation phase at all.)

**And the fix is falsifiable.** A separate finding established that the shipped
152-test model suite had **zero** discriminating power over this seam — it
passed identically with and without the fix — so the latch alone would have been
unguarded. Two things close that:

* `M62_APPROVAL_REEVALUATED_AGAINST_CURRENT_QUORUM` restores the re-derivation.
  One mutation, all three live surfaces, because `requestIsApproved()`
  centralises them.
* every new discriminator rotates to a **different-size** roster. `M61`'s
  discriminator was strengthened the same way: its kill was previously
  **vacuous** in the direction that matters, because the unlatched clean model
  refused the same execution for "insufficient supports" and clean and mutant
  agreed.

### 5.2 CROSS-GENERATION SUPPORT ACCOUNTING — the seam the latch left open

A second independent pass found that the latch fixed *authority* but not
*provenance*. `supportRecovery` checks only that the caller is in the CURRENT
guardian set; it carries no bound-generation check and, after the latch, no
post-approval close. Measured on the corrected model:

```
R1 opened under G, 3 guardians;  g1 + g2 support  →  APPROVED, latched
rotate to G+1, 5 new members     →  R1 correctly survives
new guardian h1 supports R1      →  ACCEPTED
supports = ["g1","g2","h1"]       boundGuardianGeneration still 1, current 2
```

**This was not a cut regression** — the latch means the extra support changes no
outcome — and that is precisely what makes it dangerous. It puts the model in a
provenance state the architecture forbids (`:457`: "per-request support
accounting **keyed to the generation** so support cannot be replayed across a
roster change") while nothing observable goes wrong today. A forbidden state
that is currently inert is the classic shape of a latent common-mode modelling
error that is later read back AS authority.

**Why it became reachable is the same story as §5.1.** Before candidate P a
request never outlived the constituency that opened it: a replacement either
refused (approved) or cleared (unapproved), so cross-generation support was
impossible *by construction*. Preservation removed that accident. Each of these
seams is an assumption that was true only because of the behaviour this lane
deliberately changed.

**The fix: an approved request's support set is FROZEN.** The guard is asked of
the REQUEST, before anything is asked about the supporter, so a refusal names
the real reason. Freezing on approval — rather than adding a
`boundGuardianGeneration === current` test — is the closer mirror of the kernel,
where admission is ATOMIC (a request only exists once `_requireQuorum` has
succeeded) and there is no open support phase at all. In reachable states the
two rules coincide, because an unapproved request is cleared by any rotation; the
freeze is the one that says why.

Four proofs, all with size-changing rotations:

| Proof | Asserts |
| --- | --- |
| SUPPORT-FREEZE 1 | new-roster support DENIED; support bytes and provenance unmoved |
| SUPPORT-FREEZE 2 | three successive rotations (5 → 3 → 7) still collect nothing; R1 still executes |
| SUPPORT-FREEZE 3 | an UNAPPROVED request is still cleared by a rotation — the freeze did not become a way to outlive its constituency |
| SUPPORT-FREEZE 4 | POSITIVE CONTROL: a FRESH request under the new roster collects new-generation support and reaches quorum normally |

`M63_APPROVED_REQUEST_STILL_COLLECTS_SUPPORT` reopens the set. Its
discriminator observes the SUPPORT SET, not execution — a property that only
checked outcomes would pass on the mutant, since the latch makes the extra
support inert.

**The harness caught a defect in this guard's first draft.** `mark()` was placed
inside the firing branch, so the mutant never recorded the guard as evaluated and
`assertMutantKilled`'s vacuity check failed with "guard was never evaluated —
this mutation test is VACUOUS". Marking belongs at the DECISION point, not in the
outcome. The suite's own anti-vacuity machinery found it, which is the machinery
working as designed.

**A declared model limitation.** `guardianGenerationValid` keeps its role as the
model's statement of fresh guardian-authority monotonicity, but the model does
not thread a generation through its guardian acts (they are modelled by
principal, not by digest), so its discriminating consumer is M3's direct
assertion rather than a transition. The kernel *does* enforce the rule by digest
binding, and that is measured end-to-end in section B of the new suite. This is
a limitation of the model, not of the kernel, and it is stated at the predicate.

---

## 6. `R1_RULE_DISPOSITION` — retired, not inverted

Two distinct things were called "R1" in this repository. They are separated
here because conflating them would have retired the wrong one.

| "R1" | Where | Authority | Disposition |
| --- | --- | --- | --- |
| `G-RECOVERY-COMMITMENT-BINDS` | `stateful/invariants.ts:669` | **Source-derived** — the possession digest must bind the approved configuration | **UNCHANGED.** The digest still binds `boundGuardianGeneration`, which stays pinned. Test F2 is the executable confirmation |
| the harness rule | `stateful/actions.ts:970` | **Implementation-derived** — written to agree with the kernel's `BadRoster` line, phrased in the same words as M16's rationale | **RETIRED.** It contradicts `I-APPROVED-REQUEST-PRESERVATION` and has no higher authority |

**Why retired rather than inverted.** "Rotation must void the request" is false,
but its negation is a *liveness* claim about a call that did not happen, and
that hook only judges transitions the kernel **accepted** — a refusal is
invisible to it. The preservation direction is therefore pinned where it can
actually be observed: deterministically in the new suite, and as a permanent
mutation contract. `guardianTransitionsAtApproval` is **kept** on the evidence
record as the model's approval provenance.

---

## 7. `M16_DISPOSITION` — retired from mutation adequacy, with its adjudication preserved

M16 was **reconstructed exactly** against the base and measured rather than
recalled.

* Its mutation is **byte-identical to this lane's removal** — verified
  programmatically by comparing the reconstruction to the lane's edit.
* Run across both of its profiles at all eight campaign seeds — **16 campaigns,
  22–44 successful transitions each** — M16 produced **exactly one violation**:
  `P-MODEL` at `recovery-vs-roster` seed 29.
* Its labelled `expectedProperty`, `P-CUT/CREDENTIAL_REPLACEMENT`, **never fired
  once**.

The catalogue credited the label because `StatefulMutationAdequacy`'s
attribution falls back to `violations[0]` when the expected property is absent
(`test/StatefulMutationAdequacy.test.ts:99`). A mutant's `expectedProperty` is a
**label, not a measurement**.

`P-MODEL` here *was* the harness R1 rule retired in §6. With that rule gone, M16
has no killer — and it should not have one, because its "weakened" behaviour is
the architecture-conformant behaviour.

**The disposition, stated precisely** (an earlier draft of this section was
looser, and an independent review was right to tighten it):

```
M16 is retired because its supposedly weakened behaviour is now the
conformant design. Its old P-CUT attribution was false.
Coverage of the SD-10 seam is preserved by the new INVERSE mutant.
M2 independently proves P-CUT/CREDENTIAL_REPLACEMENT remains discriminating.
```

The distinction matters. `M2-rotate-floor-only` being killed by
`P-CUT/CREDENTIAL_REPLACEMENT` shows that property still has teeth — it rules
out "the property was broken" — but it does **not** replace coverage for SD-10's
semantic seam. What replaces that coverage is
`M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST`, which reinserts the exact
statement, dies deterministically, and is denied kill credit unless the
observation is exactly
`execution of a preserved, mature, validly-proven request was REFUSED (BadRoster)`.
An earlier phrasing here — "no coverage owed: M2 IS killed by that property" —
conflated those two claims and has been withdrawn.

The entry is **retired in place** in `stateful/mutants.ts` — replaced by the
adjudication above as a comment block, not deleted — so the reasoning survives
the mutant.

---

## 8. `LEDGER_PERSISTENCE_PLAN`

SD-10 is **left in `SUSTAINED_DEFECTS`, deliberately.** Moving it is a
persistence act: a `RemediatedDefect` must name the head it was remediated
**on**, and no such head exists until this work is committed and reviewed.
Writing one now would name a commit that does not exist.

What *was* done: the deterministic reproduction in
`test/StatefulSustainedDefects.test.ts` is **inverted in place** — the same
sequence, step for step, with the verdict moved — following the precedent SD-1
set in that file. A final assertion pins the divergence explicitly, so the
ledger and the test cannot drift apart silently in either direction.

**The exact entry required after implementation review** (to be filed by the
persistence lane, with `remediatedOn` set to the commit that carries this diff):

```
id:            SD-10-approved-request-stranded-by-guardian-rotation
sustainedAt:   4b9127269602d8eab3700d96dda4d5cfcf2e0d55
remediatedOn:  <the commit carrying this diff> (security/vnext-sd10-approved-recovery-preservation)
invariant:     I-APPROVED-REQUEST-PRESERVATION (docs/Vault_vNext_Architecture.md:951) —
               once a request reaches quorum, a guardian-set replacement cannot
               clear it. PRESERVED means still EXECUTABLE, not merely still
               stored.
rootCause:     execution-time revalidation of an already-admitted recovery
               against the current guardianGeneration.
remediation:   remove that revalidation; preserve boundGuardianGeneration as
               approval provenance; fresh guardian authority remains
               current-generation only.
rejectedAlternatives:
               T (setGuardians clears recovery.active) — direct violation, and
               worse than the defect: destroys rather than strands.
               B (setGuardians reverts while live) — conformant but dominated;
               an unnecessary liveness/governance restriction, NOT an
               authority-cut violation.
               R (ratify after rotation) — +1 selector, +1 event, ~292 B, an
               extra guardian act, and it REBINDS the possession digest so a
               pre-signed PoP is refused; end state = the same as this one.
               Re-binding boundGuardianGeneration to the new generation — the
               family this entry's own minimalFixSketch considered and
               rejected; the rejection stands and is not what was built.
invertedReproduction:
               test/StatefulSustainedDefects.test.ts (the original sequence,
               verdict moved); test/Sd10ApprovedRequestPreservation.test.ts
               (A1-H2); test/Sd10PreservationMutations.test.ts
               (M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST and the T/B
               candidate guards).
residual:      none identified.
```

**Do not** state that guardian-generation binding was globally removed. It was
not. It still governs every fresh guardian act, and the field remains bound into
the possession digest.

### 8.1 The A / A′ / B topology, and what must move in each

Lane W2P already executed this pattern; `git show` on `c182db1` / `1d9b90a` /
`d3f8ee5` is the template, not a guess. **The intermediate ledger/receipt
mismatch this object carries is acceptable ONLY pre-persistence; the PR head
must be reconciled and must run 0 failing.**

| Commit | Role | Contents |
| --- | --- | --- |
| **A** | reviewed implementation | exactly the diff reviewed here — Solidity, model, tests, this record. Ledger and every generated receipt still at base identity. **Plus** its own `AUTHORITY.md` status block (see 8.2). |
| **A′** | ledger + authority reconciliation | `defects.ts` (SD-10 → `REMEDIATED_DEFECTS`), the ledger suite's identity sets, `MEASUREMENTS.json`, `generate-stateful-evidence.ts`, the `AUTHORITY.md` lead/closing update, and the current-state prose listed below |
| **B** | generated evidence | `STATEFUL_AUTHORITY_EVIDENCE.json` + `AUTHORITY_CENSUS.json` regenerated from a **clean checkout of A′**. Exactly two files. |

**A `RemediatedDefect` has exactly NINE required fields** (`defects.ts:215-237`),
none optional: `id`, `title`, `sustainedAt`, `remediatedOn`, `invariant`,
`sourceDelta`, `rejectedAlternatives`, `invertedReproduction`, `residual`. The
draft in §8 above is prose and **does not typecheck** — it must be rewritten to
that shape, with `sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55"` and
`residual: null`.

**Three artifacts would publish FALSE numbers if B ran without A′ fixing them:**

1. `MEASUREMENTS.json:31-41` still describes the BASE kernel —
   `runtimeBytes: 18425`, `runtimeSha256: 1788408915…`. It is consumed by
   `generate-stateful-evidence.ts:70` and emitted as `kernelRuntimeBytes` /
   `kernelRuntimeHash`. Unfixed, Commit B publishes 18,425 B for a kernel that
   is **18,367**.
2. `generate-stateful-evidence.ts:82` picks the latest remediation via
   `measurements.w2RecoveryLifecycle ?? sd67Remediation ?? …` and emits
   `sd1?.totalDelta`. It does not know SD10-I, so the receipt would report
   **+320 bytes for a −58-byte lane**.
3. `defects.ts`'s file header is **current-state prose, not append-only**, and
   says SD-10 is sustained in three places (lines 4-17, 36-41).

Also in A′: `stateful/README.md` (three current-state claims),
`SD9_RECOVERY_LIFECYCLE_DEFECTS.md` (header + disposition row), and SD-9d's
`residual` pointer, which names SD-10 and is checked by a live assertion.

### 8.2 `AUTHORITY.md` — append, never rewrite

The historical W2 paragraph stays **byte-for-byte**: it opens
"W2 STATUS (Lane W2I … persisted as Commit A / `c182db10…`)" and says
"`SD-10` is untouched" *on this diff*. That is a historical statement about
`c182db10`, pinned to a named commit, and it is still true.

But leaving the **file** untouched is wrong, and this record previously said
otherwise. W2's own precedent settles it: **Commit A wrote its own status block**
(lead: "local implementation diff for independent review"), and **A′ then edited
two things** — the bold lead *and* the closing sentence. SD-10 follows the same
two-stage convention: Commit A appends an SD10-I status block after the W2 block
(the `@@ -94,6 +94,19 @@` slot W2 used); A′ updates its lead and closing
sentence to name the persisted commits. Without it a current reader meets a
stale authoritative security analysis.

Nothing in the test suite enforces this — it is guarded by discipline only, which
is itself worth stating.

---

## 9. `SCANNER_IMPACT` and persistence plan

**Slither was NOT executed in this lane** — no local Slither environment exists
on this machine (`slither` is not on PATH and there is no WSL venv), and §12 of
the brief forbids regenerating canonical scanner evidence here. What follows is
a static analysis of the key impact, computed from `slither-triage.json` and the
measured line delta.

The kernel grew **1509 → 1542 lines (+33)** through **two** insertion points: a
31-line `@dev` block *above* `executeRecovery` (before base line 1324) and a
2-line net change inside the body (base `1334-1335`, two lines becoming four).
`slither-triage.json` is keyed by `<check>|<sorted filename:line elements>`, so
keys at or below either point move.

The line map is **validated against the file**, not asserted: it predicts
`function executeRecovery` at 1356, `< r.executableAt` at 1360 and
`>= r.expiresAt` at 1364 — which is exactly where they are.

| Bucket | Count of 33 classifications |
| --- | --- |
| reference the **removed** line `1335` | **0** — no finding disappears |
| keys that MOVE | **9** |
| unaffected | **24** |

| Finding | base lines | final lines | delta |
| --- | --- | --- | --- |
| `timestamp` (**`executeRecovery` itself**) | 1325, 1329, 1333 | 1356, 1360, 1364 | **+31** |
| `timestamp` | 1372, 1390 | 1405, 1423 | +33 |
| `timestamp` | 1453, 1455 | 1486, 1488 | +33 |
| `timestamp` | 1475, 1480 | 1508, 1513 | +33 |
| `arbitrary-send-eth` | 1475, 1486 | 1508, 1519 | +33 |
| `low-level-calls` | 1475, 1486, 1494 | 1508, 1519, 1527 | +33 |
| `low-level-calls` | 1504, 1505 | 1537, 1538 | +33 |
| `reentrancy-events` | 1475, 1486, 1494, 1501 | 1508, 1519, 1527, 1534 | +33 |
| `uninitialized-local` | 1482 | 1515 | +33 |

**Note the two distinct deltas — this is the part that is easy to get wrong.**
An earlier draft of this lane put the rationale *inside* the function body, which
left `executeRecovery`'s own finding above every insertion point and therefore
unmoved. Relocating the prose into NatSpec (to hold solhint at parity, §2) moved
the `@dev` block ABOVE the function declaration, so that finding now shifts by
**+31** while everything below the body edit shifts by **+33**. A persistence
lane that applied one uniform offset would mis-key it.

Eight of the nine are in `enterContainment` / `bindMigration` / `egress` —
functions this lane does not touch. The ninth is `executeRecovery`'s own
`timestamp` finding, anchored on the function declaration and the two
`block.timestamp` comparisons (`TooEarly`, `Expired`), **both of which are
unchanged**. `TIMESTAMP_FINDINGS = SEMANTICALLY UNCHANGED` — every one of them
relocates and none changes meaning.

**No new finding is expected.** The change removes a revert and adds comments:
no new external call, no new state write, no new storage. `BadRoster` remains
declared and reverted at five sites, so it does not become unused.

**Persistence plan** (for the lane that commits this, not for this one):

1. Do **not** hand-edit `slither-triage.json` for line drift now. The
   implementation object must be reviewed first.
2. After the diff is reviewed and committed, run the pinned
   `crytic/slither-action` entrypoint in the WSL venv against a clone of that
   commit (see `feedback_walletwall_vnext_slither_local_reproduction`), or take
   the PR CI run as authoritative.
3. Re-key the NINE relocated classifications **semantically** from the raw
   `--json`, not by adding a fixed offset to the old keys — the established rule
   from Lane W2S, and doubly so here because the offset is **not uniform**
   (+31 for `executeRecovery`, +33 for the rest). Each should land as
   `UNCHANGED_FINDING_RELOCATED` with its own `lineDelta` and the usual
   identical-detector/element-chain proof.
4. Confirm the count is still 33 and that no verdict changes. A new finding, or
   a disappeared one, is a STOP condition for that lane.
5. Regenerate `SCANNER_EVIDENCE.json` only from a clean checkout of the
   committed head — never on an uncommitted tree, which would stamp the wrong
   `git HEAD`.

---

## 8a. Principal-cut and campaign regression

The full stateful campaign was re-run against the corrected kernel.

```
campaigns                252
transitionsExercised     13,680
successfulTransitions    3,955
globalInvariantsChecked  21
positiveControls         1470/1470
violations               0
knownDefectHits          { SD-4-ecdsa-only-shape-declaration-is-uncounted: 3 }
```

Coverage of the composition this lane changes is not incidental:
`SET_GUARDIANS` 856 actions, `EXECUTE_RECOVERY` 1,139, `INITIATE_RECOVERY` 1,510,
`CANCEL_RECOVERY` 755, `CANCEL_RECOVERY_BY_QUORUM` 91, and 109 observed
`GUARDIAN_TRANSITION` outcomes.

**`OLD_ROSTER_FRESH_AUTHORITY = NONE`, at campaign scale.** `BadRoster` remains
the 7th most common revert with **633 occurrences** — every one of them now from
`_requireQuorum`'s commitment check or `_requireCanonicalRoster`, which is the
error's correct meaning. The attacker profiles exercised include
`one-guardian-attacker`, `mixed-roots-attacker`, `ecdsa-only-attacker`,
`stranger-only`, `commitment-forgery`, `byzantine-verifier`,
`recovery-vs-roster` and `recovery-composition`.

**`PRESERVED_R1_AUTHORITY_CUT` unchanged.** No cut fell: the campaign's 21 global
invariants include the authority-cut census, and it reported zero violations. The
narrative case — a malicious quorum approving R1 and handing over to an honest
roster — is pinned deterministically as test I1, where the honest roster's
recourse (cancellation under the current generation) is shown available at the
last live instant before maturity.

**Production byte gates, run rather than assumed.** `validate:bytecode-size` and
`validate:runtime-byte-claims` both PASS (7 and 8 contracts measured, 27
published claims checked). Both read `artifacts/contracts/`, and the production
Hardhat config shares no source path with the prototype config, so this lane
cannot move them — confirmed by execution.

**Mutation adequacy: 21/21 killed, no survivors.** The matrix also substantiates
the M16 adjudication from the other side: `M2-rotate-floor-only` **is** killed by
`P-CUT/CREDENTIAL_REPLACEMENT`, the property M16 was labelled with. So that
property has teeth — it simply never fired for M16. That rules out "the property
was broken" and leaves only "M16 was never a cut violation". Of the 21, exactly
two die by `P-MODEL` (M5, M6), and both **declare** `P-MODEL` as their expected
property. M16 was the only mutant in the catalogue whose label and whose actual
killer disagreed.

## 9a. Tests inverted in place, and how they were found

Four existing tests asserted the defect. **Lane SD10-D1 named two of them; a
full-suite discovery run found two more.** None was found by reading — each was
found by running the whole prototype suite against the corrected kernel and
looking at what went red.

| Test | Named by D1? | What it asserted | Now |
| --- | --- | --- | --- |
| `StatefulSustainedDefects.test.ts` SD-10 | yes | `BadRoster` at maturity; stranded; cleared only by the new quorum | same sequence, verdict moved; ledger divergence pinned explicitly |
| `W2RecoveryLifecycle.test.ts` H1 | yes | stranded-but-effectively-live blocks initiation and migration | **every W2 assertion retained** — a live request still blocks — only the `executeRecovery` verdict moved |
| `Sd1RecoveryFloorBinding.test.ts` R7b | **no** | "a stale guardian generation still invalidates an approved request" | inverted; its real R7-series claim (the armed PoP digest is not moved) is retained and strengthened |
| `Sd4LaneV.test.ts` D | **no** | the original SD-10 measurement: "the kernel strands, the model denies" | both sides inverted; the **two-sided divergence Lane V recorded is now closed** |

Lane V's D is worth a reviewer's attention: it recorded a divergence in which
the kernel and the model were wrong about the same invariant **in opposite
directions** — the kernel admitted the rotation then refused the request, the
model refused the rotation. That is a large part of why the disagreement
survived so long: each side could point at the other as the outlier.

## 9b. Findings deliberately NOT acted on — pre-existing, out of this lane's scope

The census that found the quorum-size seam also surfaced model gaps that are
**byte-identical to the base** and unrelated to SD-10. They are recorded here
rather than fixed, because widening this lane would make the diff unreviewable
against the one semantic change it exists to justify. Each was independently
verified as pre-existing.

| Finding | Where | Why not here |
| --- | --- | --- |
| `replaceGuardians` never rewrites `guardianCommitment` / `guardianThreshold` / `seats`, so the G-B sub-model evaluates against the constituency frozen at construction | `vaultVNextModel.ts:995` | Base behaviour, untouched by this lane. Real, and it means the latch freezes a **derived proxy** while the authoritative commitment stays stale — worth its own lane |
| `executeRecovery` installs the incoming credential with no proof-of-possession check, while `rotateCredentials` refuses exactly that | `vaultVNextModel.ts:1119` | Base behaviour. The KERNEL does gate this (`_requireIncomingPossession`), and §F of the SD-10 suite proves it; the gap is model-only |
| `securityFloor` read live at execution against an already-approved recovery | `VaultKernelPrototype.sol:653` | This is **SD-4**, already recorded and still SUSTAINED. Not a regression |
| containment budget window is tumbling rather than rolling | model | Re-discovery of **SD-2**, already in the ledger |

The kernel census produced **zero** surviving findings: after the removal, no
other place in the Solidity re-validates an already-admitted request against
current mutable state except the known SD-4 floor read.

## 10. What a reviewer should expect to find red or stale

**One test is expected red, and only one.**

`prototype/vnext-kernel/test/StatefulAuthorityFuzz.test.ts:273`

```ts
expect(receipt.mutationAdequacy.mutations.length).to.equal(MUTATIONS.length);
```

`STATEFUL_AUTHORITY_EVIDENCE.json` records **22** mutations (M16 among them);
the corrected catalogue has **21**. This is the canonical generated-evidence
provenance test, and it is *supposed* to go stale here: receipts stamp `git
HEAD` and must never be regenerated on an uncommitted tree. It closes when the
persistence lane regenerates the receipt from a clean checkout of the committed
head.

Nothing else in that block goes stale: `plannedCampaigns`, `plannedTransitions`,
`profiles.length` and `globalInvariants.length` are all untouched by this lane.
The full-suite run confirms this: exactly **one** test in the whole prototype
suite fails, and it is that one, reported as "the evidence receipt describes the
matrix that actually ran" — **709 passing / 1 failing**.

`ROOT_SUITE` is fully green — **1,658 passing, 11 pending, 0 failing** — with the
corrected reference model, the approval latch, the support freeze, and its five
new mutants (M59/M60/M61/M62/M63) included.

**Not stale, and worth stating:** no test reads `slither-triage.json`, so the
scanner drift in §9 is invisible to the suite. It matters only at regeneration.

---

## 10a. Lane SD10-D1's assumptions, confirmed or falsified by implementation evidence

| D1 claim | Verdict |
| --- | --- |
| Candidate P = delete the single statement at `VaultKernelPrototype.sol:1335` | **CONFIRMED** — that is exactly the edit, at exactly that line |
| shipped kernel runtime `18,425 B`, sha256 `1788408915…` | **CONFIRMED** — reproduced byte-for-byte by `reproduce.ts` at the base |
| kernel runtime ≈ **−58 B** | **CONFIRMED exactly** — 18,425 → 18,367 |
| storage / ABI / selectors / events unchanged | **CONFIRMED** — 17/17 storage entries identical, ABI hash identical, 46 → 46 selectors, 15 events, 24 errors |
| factory executable prefix unchanged | **CONFIRMED** — factory runtime exec hash `0x68f71f67…` identical both sides. **Refined:** the factory's CBOR **metadata** hash *does* change, because Solidity's metadata embeds source hashes for the whole compilation unit and the factory imports the kernel. D1 did not report this; measuring the whole artifact hash would have shown "factory changed" and been misleading |
| possession digest unchanged; a pre-signed PoP survives rotation | **CONFIRMED** — test F2 |
| campaign vs P: 0 `P-CUT`, only the harness `R1` `P-MODEL` rule fires, 1 of 16 | **CONFIRMED by independent re-measurement** — M16 reconstructed against the base, 16 campaigns, exactly one violation: `P-MODEL` at `recovery-vs-roster` seed 29; `P-CUT/CREDENTIAL_REPLACEMENT` never fired |
| BASE same-block races `[1,0]` vs `[1,1]`; P order-independent | **CONFIRMED** — G1 on base: `rotate-first` `[1,0]`, `execute-first` `[1,1]`; corrected: `[1,1]` both orders |
| the reference model effectively blocks replacement while an approved request exists | **CONFIRMED** — `vaultVNextModel.ts` `replaceGuardians` denied it outright (candidate B) |
| "Reference model stays (its denial is a conformant B-realisation)" | **SUPERSEDED, deliberately.** §5 of the SD10-I brief is the later authority and requires the model to represent the SELECTED semantics and discriminate P from BASE / B / T. The model was corrected and now carries M59/M60/M61 |
| the tests needing inversion are `StatefulSustainedDefects` SD-10 and `W2RecoveryLifecycle` H1 | **INCOMPLETE — falsified.** Two more assert the defect: `Sd1RecoveryFloorBinding` R7b and `Sd4LaneV` D (see §9a). D1's list was a reading; this lane's is a measurement |

## 10b. Lane SD10-P — persistence and evidence closure

Executed after three rounds of independent adversarial review. The A / A′ / B
topology is the one Lane W2P used; `git show` on `c182db1` / `1d9b90a` /
`d3f8ee5` is the template.

| Commit | Role |
| --- | --- |
| **A** = `c32e0d748390b79f4163ad4a783c2467cf502e30` (parent `a42f5c7e`, tree `90e1a802`) | the independently reviewed implementation, plus its own append-only `AUTHORITY.md` status block |
| **A′** | ledger, scanner provenance and measurement reconciliation |
| **B** | generated receipts, describing a clean checkout of A′ |

### Re-measured on a clean Commit A, reproduced rather than carried

Base and A were recompiled independently with the pinned solc
(`0.8.24+commit.e11b9ed9`, cancun, optimizer runs 200) — base from a separate
worktree pinned at `a42f5c7e`.

| | base | A | delta |
| --- | --- | --- | --- |
| kernel runtime | 18,425 | **18,367** | **−58** |
| kernel initcode | 18,466 | 18,408 | −58 |
| storage entries | 17 | 17 | identical |
| ABI hash / selector set / event set / error set | — | — | identical (46 / 15 / 24) |
| factory runtime | 2,445 | 2,445 | executable prefix `0x68f71f67…` identical; CBOR metadata only |

`reproduce.ts` (pinned solc, driven directly) and the Hardhat artifact agree
byte-for-byte on `5d8b03ec…`, so the figure is two-tool independent.

### Pinned Slither, run BEFORE ledger closure

Reproduced the CI toolchain exactly — `crytic/slither-action@b52cc1cb`'s
resolved invocation: `slither-analyzer @ ff1bf3ff…` (pip records sha256
`2e2342c9…`), solc 0.8.24, plain `solc` framework, OZ remap,
`--evm-version cancun --optimize --optimize-runs 200`,
`--exclude-dependencies`, `--no-fail-pedantic` — run against BOTH `a42f5c7e`
and Commit A **on one machine and one path**, so the two finding sets are
directly comparable.

```
RAW_COUNT                 base 217   A 217
OWN_CODE_FINDINGS         base  57   A  57
DISTINCT_OWN_CODE_KEYS    base  33   A  33   (generator's canonical dedupe)
UNCHANGED                 24
RELOCATED                  9
SEMANTICALLY_CHANGED       0
REMOVED                    0
NEW                        0        <- no adjudication required
```

Matching is by **detector + construct chain + message normalised of every line
reference**; the line delta is *recorded*, never used to match. That distinction
earned its keep: a first pass stripped `#1475` but left the `-1502` half of
Slither's ranges, which made nine pure relocations look like eight removals plus
eight additions. The measured deltas are **non-uniform** — `[31,31,31]` for
`executeRecovery`'s own `timestamp` finding, `[33,…]` for everything below the
body edit — exactly as §9 predicted from source, now confirmed by measurement.
A persistence lane applying one flat offset would have mis-keyed it.

`slither-triage.json` was re-keyed with the generator's **own** `canonicalKey`
algorithm, so the keys are what the generator will look up:
**33 classifications, 24 unmoved, 9 relocated, UNACCOUNTED 0, STALE 0,
DUPLICATE 0.** Each relocated entry carries `previousKey`,
`relocation: UNCHANGED_FINDING_RELOCATED`, its own `lineDelta`, and a proof
naming the toolchain.

### Ledger reconciliation

SD-10 moved to `REMEDIATED_DEFECTS` with all nine required fields, `sustainedAt`
`4b912726`, `remediatedOn` Commit A, `residual: null`. **SUSTAINED 4 /
REMEDIATED 9**, asserted by identity and not only by count.

Moving it **discharged SD-9d's residual pointer**, which named SD-10 as what W2
did not close. `defects.ts`'s own contract is that "a residual pointing at a
closed defect would be stale evidence, and the ledger test refuses it" — so the
pointer became `null`, with the history kept in prose at that entry rather than
silently blanked. The ledger suite caught this the moment SD-10 moved; it was
not found by reading.

### Measurement truthfulness — what each field MEANS

Two independent falsehoods would have been published had the numbers been
changed carelessly, and one more had they not been changed at all:

* `MEASUREMENTS.json.kernel.*` is **current source identity** → updated
  (18,367 / `5d8b03ec…` / headroom 6,209 and 3,609).
* the per-lane blocks (`sd1Remediation`, `sd3Remediation`, `sd67Remediation`,
  `w2RecoveryLifecycle`) each **mean that lane** → left byte-for-byte. A new
  `sd10Preservation` block was ADDED, carrying this file's first **negative**
  delta.
* `generate-stateful-evidence.ts` picks the latest lane by a newest-first
  `??` chain that did not know SD10-I. Left alone it would have published
  **W2's +320 bytes for a lane that removed 58**. `sd10Preservation` is now
  first in that chain.

`sourceDigests` for both prototype contracts were found **already stale at the
base** (committed `e922dfdf…` / `102df285…` matched neither `a42f5c7e` nor A).
That drift pre-dates this lane; both were corrected to the measured current
values and re-verified by recomputing sha256 from the working tree.

## 11. Reproduce

```bash
git worktree add C:/dev/wv-sd10-implementation -b security/vnext-sd10-approved-recovery-preservation a42f5c7e
cd C:/dev/wv-sd10-implementation && npm ci
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/test/Sd10ApprovedRequestPreservation.test.ts
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/test/Sd10PreservationMutations.test.ts
npx hardhat test test/VaultVNextArchitectureModel.test.ts
npx tsx prototype/vnext-kernel/reproduce.ts --json     # storage layout + selectors, pinned solc
```

To reproduce the RED, restore only the kernel
(`git checkout -- prototype/vnext-kernel/contracts/VaultKernelPrototype.sol`)
and re-run the first suite: 9 passing / 10 failing.
