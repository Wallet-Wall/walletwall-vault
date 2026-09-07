# SD-4 Lane U — temporal equivalence and recovery-episode adjudication

> ## CORRECTED BY LANE V — read `SD4_LANE_V_ADJUDICATION.md` first
>
> This document stands as written. Four of its claims are corrected there, and
> they are listed here so no reader acts on the uncorrected text:
>
> 1. **§3's "21 days rather than one 7-day cycle" is WITHDRAWN.** It was derived
>    from the model's replacement guard without noticing that the model gives the
>    guardian quorum a **separate, explicit `cancelRecovery`**
>    (`vaultVNextModel.ts:1063-1072`). Under model semantics the quorum cancels
>    and re-initiates immediately: **one cycle**. #188's "one extra recovery
>    cycle" is correct under the conformant architecture.
> 2. **§5's "G′ has collapsed to re-initiation" is restated** as
>    `EQUIVALENT_ONLY_TO_NONCONFORMANT_PROTOTYPE_BEHAVIOR`. The comparator used
>    was `initiateRecovery` over a live approved request — the contested path.
> 3. **§4 and §5's `u1full`, `u2a`, `u2b` — and Lane T's `clamped` — are
>    reclassified `REQUIRES_ARCHITECTURE_POLICY_CHANGE`**, not remediations. All
>    write `recovery.executableAt`, and `docs/Vault_vNext_Architecture.md:736`
>    forbids any state transition resetting, extending or suspending any clock,
>    naming recovery delay and recovery expiry explicitly.
> 4. **§3's "owner decision" framing on the challenge counter is superseded.**
>    It is `SOURCE_DERIVED` from `I-RECOVERY-NONVETO` (`:945`, T1); the
>    adopted statement and its derivation are persisted once, in
>    `docs/Vault_vNext_Recovery_Amendment.md` §2.
>
> **Root cause of all four: this lane never consulted `docs/`.** The governing
> invariants live in `docs/Vault_vNext_Architecture.md`, not in
> `prototype/vnext-kernel/`, and Lane U searched only the latter.


**Append-only.** `c67d1439` is not amended, and neither is
`SD4_TEMPORAL_ADJUDICATION.md`. Where this lane contradicts either, the
contradiction is stated here and the earlier text stands.

**No production Solidity. Nothing committed, pushed, or published. The generated
evidence artifact is NOT regenerated.**

---

## 1. Verdicts, reported independently

| Term | Verdict |
| --- | --- |
| `SD4_SNAPSHOT_DESIGN_REJECTED` | **CONFIRMED** — unchanged from #188 |
| `SD4_GENERAL_IMPOSSIBILITY` | **REFUTED** — unchanged; a ratification family exists that is neither design A nor design E |
| `SD4_TEMPORAL_TRILEMMA` | **SURVIVES ATTEMPTED REFUTATION** — not proven |
| `RECOVERY_DELAY_FINAL_PAYLOAD_SEMANTICS` | **AMBIGUOUS** — asymmetrically, see §2 |
| `RECOVERY_EPISODE_SEMANTICS` | **UNRESOLVED SEMANTIC BLOCKER** — split verdict, see §3 |
| `G_PRIME_FULL_DELAY_CLAMP` (U1) | **DOES NOT CLOSE SD-4**, and carries a defect of its own |
| `G_PRIME_REINITIATION_EQUIVALENCE` (U2b/U3) | **BEHAVIOURALLY EQUIVALENT TO RE-INITIATION** |
| `G_PRIME_FINAL_ADMISSION` | **NOT ESTABLISHED — BLOCKED** on §3 |

**`SD4_GENERAL_IMPOSSIBILITY` being refuted does not make any candidate safe,
and nothing here restores it.** The trilemma is a distinct and stronger claim,
adjudicated separately below.

---

## 2. Part A — what `RECOVERY_DELAY` actually promises

**Classification: `AMBIGUOUS`.** The proposition is universally quantified over
*signer, PQ commitment, verifier*, and authority splits on the quantifier.

**Supporting, with coordinates:**

- `docs/Vault_vNext_Hazard_Register.md`, **H-15** (guardian-majority takeover,
  the governing hazard, ACCEPTED by owner decision D1):
  - *Containment* — "7-day delay; guardian-set choice is the tenant's."
  - *Detection* — "`RecoveryInitiated` gives at least `RECOVERY_DELAY` of warning."
  - *Recovery* — "Cancellation within the delay window, by whichever principal
    holds that authority."
  - *Residual risk* — the bounded challenge "buys **time, visibility and
    operational cost**".
- `docs/Vault_vNext_Architecture.md` **§13.2** — "Migration and recovery are
  reachable by the **same** coalition… If binding is faster than recovery,
  migration is **strictly the better attack**: **identical prerequisites, less
  warning**, irreversible outcome… `bindDelay >= recoveryDelay` is therefore an
  **architectural constraint, not a tuning parameter**."
- `docs/Vault_vNext_Architecture.md` **`I-MIGRATION-CLOCK-NEUTRAL` (T1)** —
  migration "may neither shorten nor lengthen the maturity of any pending
  obligation — queued withdrawal, containment expiry, **recovery delay**."
- `docs/Vault_vNext_Architecture.md` **§22 D1** — the challenge "costs the
  attacker `k × recoveryDelay` … while leaving an honest user `k × recoveryDelay`
  to migrate out", pricing the whole defence in units of the delay.

**Limiting, and this is why the answer is not `REQUIRED`:**

- `contracts/VaultKernelPrototype.sol:264` —
  `event RecoveryInitiated(address indexed proposedSigner, uint64 executableAt, uint64 guardianGeneration)`.
  **The detection mechanism H-15 names carries neither `proposedPqKeyHash` nor
  `proposedVerifier`.** H-15's warning claim is literally satisfied for the
  *signer* only, and has never covered the other two — on the unmodified kernel
  either.
- No vNext text asserts request immutability. The nearest clause,
  `docs/Security_Assumptions.md` "Recovery request integrity" — which does name
  "**substituting credentials**" as the harm it prevents — governs the **legacy**
  `WalletWallVault` (that document's scope is the deployed prototype, with an
  *owner*), and the vNext kernel deliberately carries no such guard.

`I-MIGRATION-CLOCK-NEUTRAL` is scoped to migration, so applying it to
ratification is analogical rather than literal. It is cited as the architecture's
*existing treatment of the same shape of harm*, not as governing text.

### 2.1 The 3-day clamp is an OWNER POLICY CHANGE under every classification

This does not depend on resolving the ambiguity:

- under `REQUIRED` — a plain temporal weakening;
- under `AMBIGUOUS` — 3 days is not derivable from authority at all. The only
  interval authority names for recovery is `RECOVERY_DELAY`, and §13.2 states
  that exactly this kind of delay ordering is "an architectural constraint, not
  a tuning parameter";
- under `NOT_REQUIRED` — then no ratification interval is needed and 3 days is
  arbitrary.

There is a precedent for how a second delay constant must be justified:
`VaultKernelPrototype.sol:200` carries
`uint64 public constant BIND_DELAY = 7 days; // >= RECOVERY_DELAY (section 13.2)`.
A `RATIFICATION_DELAY` needs a stated ordering relation of the same kind, and
§13.2's own argument — a faster door with identical prerequisites is the better
attack — yields `>= RECOVERY_DELAY`, not `< RECOVERY_DELAY`.

**Lane T's 3-day value is hereby classified as `OWNER_POLICY_CHANGE`, retained
only as a comparative variant (U4), and is not recommended.**

---

## 3. Part B — what a "recovery episode" is

Recorded here (Lane W1R folded the separate YAML record into this section and
`docs/Vault_vNext_Recovery_Amendment.md`; both halves of the blocker were later
resolved — the counter as the challenge epoch, amendment §2; the replacement
question as `NONCONFORMANT_AND_REDUNDANT`, `SD9_RECOVERY_LIFECYCLE_DEFECTS.md`). Summary:

| Question | Answer |
| --- | --- |
| What begins an episode? | **NOT ESTABLISHED.** The kernel has no episode concept — one `recovery` slot and a counter that survives replacement. |
| What ends one? | Only `delete recovery` in `executeRecovery` clears the counter. Cancellation keeps it; **expiry clears nothing** and leaves `active` true. |
| Does re-initiation begin a new episode? | **SOURCES DISAGREE.** Kernel: continues (counter carried, `:1177`). Prose: implies new. Reference model: the question cannot arise — it *forbids* the replacement. |
| When should the counter reset? | Only on success. Any per-re-initiation refund is excluded by `I-VETO-BOUND` (T0) plus the unguarded `initiateRecovery`. |
| Conformant, doc ambiguity, or real mismatch? | **SPLIT** — see below. |
| Does resetting recreate an unbounded veto? | **YES** (measured, B3). |
| Is "never until success" materially different from "per episode"? | **YES, totally** — two cancels versus six across three re-initiations. |

**The split verdict is the finding:**

- **Challenge-counter semantics — DOCUMENTATION AMBIGUITY.** Kernel and
  reference model *agree* (both lifetime; `vaultVNextModel.ts` never resets
  `credentialChallengesUsed`). Only the prose says "per episode", in two places
  (`VaultKernelPrototype.sol:1183-1187`; Architecture §22 D1). The
  implementation is right and the wording is wrong, because the architecture
  already established the general rule in another context: **"per-episode bounds
  do not compose into a bound on the authority"** (§6 ~line 751, the
  rolling-freeze defect).
- **Request replacement — REAL MODEL/IMPLEMENTATION MISMATCH.**
  `test/helpers/vaultVNextModel.ts:995-999` refuses to replace a live request
  ("a live request may not be replaced") and refuses to replace an approved one.
  The kernel's `initiateRecovery` carries no such guard. Because the kernel takes
  a quorum proof atomically, **every kernel request is approved the instant it
  exists**, so the model's rule transposed to the kernel reads *no request may
  ever be replaced*. **This divergence is recorded nowhere.**

  It compounds with a second, already-known one pointing the same way: the model
  clears an expired request (`vaultVNextModel.ts:1031`,
  `if (req !== null && this.clock >= req.expiresAt) this.kernel.recovery = null`),
  and the kernel never does — the stranded-`active` residue already carried
  against SD-4. Under model semantics an approved request therefore blocks
  replacement until it **expires**, so a poisoned request costs the quorum the
  full `RECOVERY_EXPIRY` before it may try again.

  **This falsifies a premise stated in `defects.ts` and republished in
  `STATEFUL_AUTHORITY_EVIDENCE.json`:** that after an SD-4 revert "the quorum
  self-heals by re-proposing against the declared shape" at "the same one-cycle
  cost". That is true of the kernel and false of the reference model, where the
  cost is 21 days rather than one 7-day cycle.

### 3.1 It undercuts a Lane T premise, and I am recording that rather than defending it

Lane T justified G′ with "the quorum can already re-initiate, so ratification
grants no new end state". If the reference model is authoritative, **that premise
is a defect rather than a design**, and the justification does not stand as
written. This is why `G_PRIME_FINAL_ADMISSION` is blocked here and not merely
qualified.

Lane T's *core* finding survives either reading: within any single episode the
credential must decide whether to spend a cancel using the payload it can see,
and an amendment after that decision defeats the remedy however many cancels
remain. Only the "lifetime budget of two" framing is specification-contingent.

---

## 4. Part D — the full-delay rule, exhaustively

`U1` = amended payload ages `RECOVERY_DELAY`; refuse if it could not then
execute; expiry never moves. Sixteen cells, `t0` = initiation, expiry `t0+21d`.

Every cell held: **signer never amendable, `challengesUsed` never refunded
(0 throughout), guardian generation binding intact (1 throughout).**

| Amendment at | harmless | SD-4 |
| --- | --- | --- |
| `t0` | amended, **executes, spends** | amended, **executes, spends** |
| `t0+7d-1` | amended, executes, spends | amended, executes, spends |
| `t0+7d` | amended, executes, spends | amended, executes, spends |
| `t0+14d-1` | amended, **cannot execute** | amended, **cannot execute** |
| `t0+14d` | amended, **cannot execute** | amended, **cannot execute** |
| `t0+14d+1` | refused `Expired`, original executes | refused `Expired`, **SD-4 unrepaired** |
| `t0+21d-1` | refused `Expired`, original executes | refused `Expired`, SD-4 unrepaired |
| `t0+21d` | refused `Expired`, original executes | refused `Expired`, SD-4 unrepaired |

### 4.1 U1 does not close SD-4

At `t0+14d+1` the request is **active, unexpired, generation-current**, the
amendment is **correctly refused**, and the quorum-approved recovery **can never
execute**. The remedy is another full recovery at a fresh `RECOVERY_DELAY` —
which is precisely the liveness cost #188 called inherent. **For this timing
band, it still is.** Called plainly, as required: *U1 does not close SD-4.*

### 4.2 A defect this lane found in its own lead candidate

The clamp `newExec > expiresAt → revert` excludes only a **negative** window.
Because expiry never moves and the amended payload must age `RECOVERY_DELAY`,
the surviving execution window is `t0 + 14d − t` and **shrinks continuously to
zero**:

| Amendment at | usable window | executes |
| --- | --- | --- |
| `t0` | ~14 d | yes |
| `t0+7d` | exactly 7 d | yes |
| `t0+14d-1` | **1 second** | **no** |
| `t0+14d` | **0 seconds** | **no** |

There is no cliff to defend at `t0+14d`. Worse, the behaviour is
**non-monotonic**: at `t0+14d-1` the amendment is *admitted* and destroys an
otherwise-executable recovery, while at `t0+14d+1` it is *refused* and the
recovery survives. **U1 makes a healthy episode worse at a timing where it makes
a later one better.**

So U1's honest repair band is not `[t0, t0+14d]` but `[t0, t0+14d − W]` for
whatever execution window `W` a deployment considers usable — **and no candidate
in this lane proposes a value for `W`.**

---

## 5. Part E — the families

- **U1 — FULL-DELAY CLAMP.** Not a closure (§4.1), and defective as written
  (§4.2).
- **U2a — FULL RESET, expiry untouched.** Never refuses, so a late amendment
  installs a maturity at or beyond expiry: measured window `≤ 0` and nothing
  executes. This is Lane T's `T7b` re-measured at the authority-required
  interval.
- **U2b / U3 — NEW WINDOW.** Both timers re-derived from the amendment instant.
  Measured against the kernel's existing `initiateRecovery` on an identically
  built world at the same elapsed offset: **same principal, same commitment,
  same verifier, same challenge history, same generation binding, and both
  timers identical relative to each path's own instant.**
  **G′ has collapsed to re-initiation.** It costs the same single guardian quorum
  act, reaches the same state, and is strictly *weaker* (it cannot change the
  signer and requires a generation match). **It has not removed SD-4's existing
  liveness cost — it has renamed it.**
- **U4 — 3-DAY CLAMP.** Comparative only. Classified `OWNER_POLICY_CHANGE` (§2.1).

---

## 6. Part F — window extension

For U2b: repeated amendments immediately before each expiry keep `recovery.active`
continuously true and push expiry indefinitely, with **no challenge refunded**.
The unmodified kernel reaches the identical state by re-initiating on the same
cadence, measured side by side.

**Classification: `SAME AUTHORITY / DIFFERENT PATH`**, tending to
`BEHAVIOURALLY EQUIVALENT TO RE-INITIATION`. The consequence is the same on both
paths and is worth stating because it is not obvious: an indefinitely-held
recovery indefinitely blocks `bindMigration`
(`VaultKernelPrototype.sol:1306`, `if (recovery.active) revert NoRecovery();`,
`I-MIGRATION-SUBORDINATE-TO-RECOVERY`). A quorum that never lets a recovery
settle can therefore deny migration forever — **on the kernel as it stands
today**, with no candidate applied.

---

## 7. Part G — notice must be notice *of the payload*

`RecoveryInitiated` carries `proposedSigner`, `executableAt`,
`guardianGeneration`. The commitment and the verifier are readable only from the
public `recovery` storage slot, and `VerifierChanged` fires only *after*
execution.

On the unmodified kernel one storage read at `t0` suffices, because the payload
cannot change. **Under any ratification design it can**, so an event-driven
observatory is blind and a polling observatory must poll continuously.

**Requirement, not a change made here: any admitted candidate must emit the
final payload on amendment.** Without it, a new notice period is time in which
an observer cannot determine *what changed*, and elapsed seconds do not establish
H-15's detection claim. No production event was added in this lane.

---

## 8. Part C — the trilemma

**Attempted refutation, executed.** `U5` publishes a fallback verifier at
`initiateRecovery` and lets ratification **select** it — the amendment takes no
parameter, so no unobserved value can enter. Notice is satisfied with **no timer
moving at all**, apparently escaping horns A, B and C together.

- Measured: where the declared shape matches the published fallback, U5 repairs
  a 20-day-old SD-4 instance with `executableAt` and `expiresAt` **both
  unchanged**, and the recovered credential spends.
- Measured: where it does not, the selection is admitted and **repairs nothing**
  — the published value was fixed before the shape was known.

The declaring edge chooses `pqSignatureLength` freely across a `uint16`. Any
finite pre-published set leaves instances it cannot repair, which is **horn A**,
reached by the design built specifically to avoid it.

**Verdict: `SURVIVES ATTEMPTED REFUTATION`, not proven.** One refutation family
was constructed and it collapsed. The case analysis over (2) and (3) is
arithmetic — an amendment at `t` needs `t + N ≤ expiresAt` — but it is complete
only under the assumption that repairing SD-4 requires installing a value not
already published, and that assumption is exactly what U5 probed. A different
refutation family may exist.

---

## 9. The squeeze, stated once

Under the full-notice reading, every ratification design faces the same three
exits and takes at least one:

1. **honour the full delay** → late SD-4 is unrepairable in-episode, and the
   usable window collapses continuously (U1);
2. **restore the window** → the design is `initiateRecovery` renamed, with no
   liveness gain (U2b/U3);
3. **shorten the interval** → an owner policy change contradicting §13.2 (U4).

#188 named the wrong dichotomy — A/E was not exhaustive, and that refutation
stands. But its bottom line, that SD-4's liveness cost is real, **survives in a
sharpened form**: it is inherent *for late instances under the full-notice
reading*, and every design avoiding it pays in notice or delivers nothing.

## 8a. Part H — campaign, mutation adequacy, and what was NOT added

The repaired oracle semantics were in force for the whole run, all pre-existing
SD-4 reproductions were preserved unmodified, and the full prototype suite —
stateful composition campaign and mutation-adequacy suite included — was run in
that state: **596 passing, 0 failing, 7 minutes**. That is 476 pre-existing,
plus 87 from rounds 1–3, plus 17 from Lane T, plus 16 from Lane U. No existing
test was edited.

**No mutants were added to the tracked mutation harness, and that is a
deliberate scope call rather than an omission.** The discrimination the brief
asks for — separating the temporal rule from weaker versions of itself — is
already carried by this lane's *compiled variants*: `u1full`, `u2a`, `u2b`,
`clamped` (3 d) and `notice` differ **only** in the temporal clause, are deployed
against the same machinery, and are separated by measurement (§4, §5). Adding
equivalents to `stateful/mutants.ts` would enlarge tracked drift and make the
generated evidence artifact stale in a second way while §9a is unresolved.

A production lane should add two, and they are named here so the gap is explicit:
a mutant deleting the clamp's `newExec > expiresAt` refusal (killed by §4.2's
window measurement), and one replacing `RECOVERY_DELAY` with a shorter constant
in the ratification clause (killed by a notice-guarantee assertion). Neither is
written here.

**A green campaign is necessary, not sufficient**, and in this lane it is not
even the binding constraint: admission is blocked by §3, which no campaign can
settle.

## 9a. Would the published evidence artifact's semantics now be truthful? **No.**

Asked by the brief, answered before any regeneration is considered.
`STATEFUL_AUTHORITY_EVIDENCE.json` embeds `{name, source}` for each invariant
**and the full SD-4 `defects.ts` text**. Regenerating today would land the
repaired `source` string into an artifact whose SD-4 entry is falsified in four
places:

1. *"No fifth family is known."* — false since round 3.
2. *"Every design that preserves the quorum's proposal across the declaring edge
   must either brick the vault or hand the quorum the shape"* — the A/E
   dichotomy, false.
3. *"SD-4's liveness cost is INHERENT"* — not simply false, but requiring the
   qualification in §9: inherent *for late instances under the full-notice
   reading*.
4. *"the quorum self-heals by re-proposing … for the same one-cycle cost"* —
   kernel-true, reference-model-false (§3).

So regeneration is **not** merely blocked by the instruction not to run it; it
would propagate a repaired provenance string into a record that is wrong about
its own conclusion. Correcting that text means amending #188's ledger entry,
which this lane is forbidden to do and should not do — the entry is valuable
falsified evidence. **The sequencing decision is the owner's:** how to represent
a superseded ledger entry without destroying it. Until that is settled, the
artifact should stay stale and the append-only corrections carry the truth.

## 10. Not established

- Both §3 semantic decisions. `G_PRIME_FINAL_ADMISSION` is blocked on them.
- A value for the minimum usable execution window `W` (§4.2).
- Whether any candidate survives the stateful composition campaign — see the
  companion run note.
- Any production Solidity, event, or evidence regeneration.
