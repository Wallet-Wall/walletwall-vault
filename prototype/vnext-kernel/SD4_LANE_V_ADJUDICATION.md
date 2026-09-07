# SD-4 Lane V — recovery lifecycle authority reconciliation

**Append-only.** `c67d1439` is not amended. `SD4_TEMPORAL_ADJUDICATION.md` and
`SD4_LANE_U_ADJUDICATION.md` are left standing; where this lane corrects them,
the correction is stated here. **No production Solidity. Nothing committed,
pushed, or published. No evidence regeneration.**

---

## 1. Verdicts

| Term | Verdict |
| --- | --- |
| `RECOVERY_CHALLENGE_EPOCH` | **SOURCE_DERIVED** — with one bullet corrected |
| `APPROVED_RECOVERY_OVERWRITE` | **AUTHORITY_GENUINELY_CONFLICTS** |
| `EXPIRED_RECOVERY_AUTHORITY_STALE` | **CONFIRMED** — candidate SD-9 |
| `RECOVERY_MODEL_KERNEL_CONFORMANCE` | **NONCONFORMANT ON FIVE POINTS** |
| `SD4_BASELINE_LIVENESS_COST` | one cycle *if the quorum has an immediate exit*; **flat `t0+28d` if not** |
| `G_PRIME_REINITIATION_EQUIVALENCE` | **EQUIVALENT_ONLY_TO_NONCONFORMANT_PROTOTYPE_BEHAVIOR** |
| `G_PRIME_STILL_WORTH_PURSUING` | **NO** |
| `PUBLISHED_STATEFUL_EVIDENCE_REGENERATABLE` | **NO** |

**The cited authority is real.** All four invariants this lane turns on were
verified firsthand in `docs/Vault_vNext_Architecture.md`, and all are T1
(`:1540`): `I-RECOVERY-NONVETO` (`:945`), `I-RECOVERY-TERMINATION` (`:948`),
`I-APPROVED-REQUEST-PRESERVATION` (`:951`), and the generalised **CLOCK RULE**
(`:736`). None of Lanes T or U consulted them, because none of them lives in
`prototype/vnext-kernel/`.

---

## 2. A — `RECOVERY_CHALLENGE_EPOCH = SOURCE_DERIVED`

**No counterexample found for request-local reset.** Nothing rate-limits
`initiateRecovery`; five successive requests were opened in a row (Lane V "A1").
A per-request budget therefore yields `N × CHALLENGE_LIMIT` cancels over `N`
requests, unbounded in the quorum's patience — which is exactly what
`I-RECOVERY-NONVETO` (`:945`) forbids, hazard H-03, mutant M27. Measured: under
the epoch semantics actually implemented, five requests still yield exactly two
cancels.

**Terminology adopted: "challenge epoch", replacing "per episode"** in the
semantic record.

**One bullet of the proposed minimum meaning is corrected.** *"Successful
guardian recovery resets it"* is **kernel behaviour only**. The reference model
never resets `credentialChallengesUsed` **anywhere** — not in `executeRecovery`,
not in `cancelRecovery`; it is initialised to `0` at genesis and only ever
incremented (`vaultVNextModel.ts:393, 532, 1427-1431`). The model is *stricter*
than the kernel. So the source-derived floor is:

- cancellation consumes from one persistent epoch — **source-derived**;
- cancellation / re-initiation does not reset it — **source-derived**;
- **successful guardian recovery resets it — KERNEL-ONLY, model disagrees, and
  this must be decided rather than assumed**;
- no expiry reset is invented — **held**.

**A partial falsification, recorded because it partly succeeds.** The
unboundedness argument does not exclude *every* reset trigger — only triggers the
**credential** can cause. Expiry is not one: it requires the quorum to abandon a
request for `RECOVERY_DELAY + RECOVERY_EXPIRY`, which a determined quorum never
does, so an expiry-triggered reset would remain bounded against an adversarial
quorum. **It is not adopted**, because no primary source establishes it. The
argument for the epoch is therefore sound but narrower than "any reset is
unbounded".

---

## 3. B — `APPROVED_RECOVERY_OVERWRITE = AUTHORITY_GENUINELY_CONFLICTS`

**For preservation:** `I-RECOVERY-TERMINATION` (`:948`) enumerates three exits;
overwrite is a fourth. The reference model refuses replacement of a live request
and of an approved one (`vaultVNextModel.ts:995-999`). The legacy contract
implements `RecoveryAlreadyApproved`, and `Security_Assumptions.md` names
*"substituting credentials"* as the harm that guard prevents.

**Against, and none of it is "the kernel does it":**

- **No architecture text addresses overwrite.** A search of the architecture for
  replacement / overwrite / supersession language returns nothing on this
  subject.
- **`I-APPROVED-REQUEST-PRESERVATION` is scoped verbatim to *guardian-set
  replacement*.** If `I-RECOVERY-TERMINATION` already forbade every unenumerated
  clearing mechanism, this invariant would be **redundant**. Its separate
  existence is evidence the enumeration is not read as exhaustive.
- **The architecture's own operationalisation reads TERMINATION as liveness.**
  Its T1 model test asserts only that an approved request *becomes deletable*
  without a principal acting (`VaultVNextArchitectureModel.test.ts:322`), with
  the message *"a request must never be simultaneously unexecutable and
  undeletable"*. It never asserts that other exits are forbidden.
- **The model's replacement guard cites no invariant**, and its plausible
  provenance is the legacy contract, whose governing document is scoped to the
  legacy vault.

**Neither reading is established.** Verdict: `AUTHORITY_GENUINELY_CONFLICTS`.

### 3.1 The better-founded finding in the same area

The model gives the **guardian quorum** an explicit `cancelRecovery` exit
(`vaultVNextModel.ts:1063-1072`, authorised to `GUARDIAN_QUORUM` under
`ACCOUNT_PER_VAULT`, with the comment that the spending credential holds no veto).
**The kernel has no quorum-side withdrawal at all** — its complete quorum surface,
enumerated from the ABI in Lane V "B1", is `bindMigration, enterContainment,
initiateRecovery, setGuardians`.

The kernel also **merges** the model's two distinct operations: the model's
`challengeRecoveryByCredential` (bounded, credential) and `cancelRecovery`
(unbounded, quorum) become one credential-authorised `cancelRecovery`.

**So overwrite is functioning as a substitute for an enumerated exit the kernel
does not implement.** That reframes the fix: forbidding overwrite *alone* would
remove the quorum's only immediate exit and raise the baseline liveness cost to
a flat `t0+28d` (§5).

### 3.2 Withdrawal, as instructed

Preservation does not cleanly win, but it does not cleanly lose either. The
claim used in Lanes T and U — **"the quorum can already re-initiate"**, asserted
as an *architecture fact* — rested on contested ground and **is withdrawn as an
architecture claim.** It survives only as a measurement of prototype behaviour.
Measurement against a defective prototype is still valid measurement; it is not
normative equivalence.

---

## 4. C — `EXPIRED_RECOVERY_AUTHORITY_STALE = CONFIRMED`

All five proofs executed on the unmodified kernel (Lane V "C"):

1. the request is expired — wall clock past `expiresAt`;
2. `executeRecovery` reverts `Expired`;
3. `bindMigration` reverts `NoRecovery`, and the block lifts the instant the
   request is cleared — isolating the stale flag as the sole cause;
4. **no principal acted**: `active` is still the value `initiateRecovery` wrote,
   `challengesUsed` is still `0`, and `expiresAt` was never rewritten;
5. the model treats the same request as expired **and deletes it**, with no
   principal acting.

This violates `I-RECOVERY-TERMINATION`'s explicit *"expiry requires no principal
to act"*. Recorded as candidate **SD-9**, pre-existing and independent of SD-4 —
it reproduces on a vault that never takes a declaring edge.

A second, independent nonconformance was found while testing it and is recorded
as candidate **SD-10**: `setGuardians` is admitted while a quorum-approved
request is live, and the generation bump strands that request permanently
(`BadRoster` at maturity) — the model **denies** the replacement
(`VaultVNextArchitectureModel.test.ts:334`).

---

## 5. E — `SD4_BASELINE_LIVENESS_COST`, re-priced

**A correction to Lane U first.** Lane U stated that under model semantics an
SD-4 request costs *"21 days rather than one 7-day cycle"*. **That was wrong.**
It was derived from the model's replacement guard without noticing that the
model provides the quorum a **separate, explicit cancellation**. Under the
conformant architecture the quorum cancels immediately and re-initiates, and the
cost is one cycle. #188's *"one extra recovery cycle"* is **correct under the
conformant architecture**, not merely under the prototype.

The regimes differ only in whether the quorum holds an immediate exit:

| SD-4 request dies at | (i) kernel, via overwrite | (ii) conformant, via quorum cancellation | (iii) overwrite forbidden, no quorum cancellation |
| --- | --- | --- | --- |
| just after initiation | `t0+7d` | `t0+7d` | **`t0+28d`** |
| just before maturity | `t0+14d` | `t0+14d` | **`t0+28d`** |
| at maturity | `t0+14d` | `t0+14d` | **`t0+28d`** |
| midway through the window | `t0+21d` | `t0+21d` | **`t0+28d`** |
| just before expiry | `t0+28d` | `t0+28d` | **`t0+28d`** |

- **earliest authorised cancellation** — (i)/(ii) immediately, by the quorum;
  (iii) only by the credential, which costs an epoch slot and requires the
  cooperation of the principal recovery exists to remedy.
- **earliest autonomous expiry** — `t0+21d` in all regimes; the clock is
  anchored at initiation, not at the death, so a late death waits less.
- **earliest fresh initiation** — the cancellation instant, or `t0+21d`.
- **earliest execution** — that instant `+ RECOVERY_DELAY`.
- **does the credential keep spending?** — **Yes, in every regime**, until a
  recovery executes. Measured: the live `ecdsaSigner` is unchanged at `t0+21d`.

Regime (iii)'s flat `t0+28d` is **measured**, not derived (Lane V "E").

**The cheapest correct fix falls out of this table and is not a G′ variant:
add the quorum cancellation the model already has.** It restores the enumerated
exit, removes the need for overwrite, touches no clock, and holds the baseline
at one cycle.

---

## 6. F — `G_PRIME_REINITIATION_EQUIVALENCE`, restated

**`EQUIVALENT_ONLY_TO_NONCONFORMANT_PROTOTYPE_BEHAVIOR`.**

Lane U measured U2b against `initiateRecovery` **over a live approved request** —
the contested path. Against the conformant comparator (quorum cancel, then
initiate) the two are **not** equivalent, and for a sharper reason than
provenance: cancel-then-initiate creates a **new** request carrying new clocks,
whereas U2b **rewrites `executableAt` and `expiresAt` on an existing one**. The
generalised CLOCK RULE forbids the second and permits the first.

The byte-level measurement was correct and is preserved. It is not normative
equivalence.

---

## 7. G — the clock rule, applied to the whole adversarial matrix

`docs/Vault_vNext_Architecture.md:736`, verbatim: *"**Every** clock in this
design — recovery delay, recovery expiry, migration bind delay, migration
deadline, withdrawal maturity, containment expiry — runs on wall clock in every
safe state, and **no state transition may reset, extend, or suspend any of
them**."*

Applying it to every variant built in Lanes T and U:

| Variant | Writes a recovery clock? | Classification |
| --- | --- | --- |
| `atomic` | no | clock-conformant; killed on notice (0 s) |
| `notice` | no | clock-conformant; killed on notice (< 60 s) |
| `delay` (3 d) | **yes** | `REQUIRES_ARCHITECTURE_POLICY_CHANGE` |
| `clamped` (3 d) | **yes** | `REQUIRES_ARCHITECTURE_POLICY_CHANGE` |
| `u1full` | **yes** | `REQUIRES_ARCHITECTURE_POLICY_CHANGE` |
| `u2a` / `u2b` | **yes** | `REQUIRES_ARCHITECTURE_POLICY_CHANGE` |
| `U5` (pre-committed fallback) | **no** | clock-conformant; repairs only pre-published shapes |

**Lane T's recommended `clamped` and Lane U's `u1full` are both reclassified.**
They are not remediations; they are policy-change proposals. The 3-day interval
is not re-derived and is not recommended.

---

## 8. H — `G_PRIME_STILL_WORTH_PURSUING = NO`

1. **Does in-request ratification provide a capability the conforming
   architecture lacks?** No. With quorum cancellation present, the quorum can
   already withdraw and re-propose. Ratification's only gain is *skipping the
   fresh delay* — that is, spending notice.
2. **Can it preserve the original fixed expiry?** Yes — `atomic`, `notice` and
   `U5` all leave `expiresAt` alone.
3. **Can it preserve the authority-required notice on the final payload?** Only
   by writing `executableAt`, which the clock rule forbids — **or** by
   pre-commitment (`U5`), which needs no timer at all.
4. **Does it repair every SD-4 timing?** No. `U5` repairs only shapes the quorum
   published in advance, and the declaring edge chooses `pqSignatureLength`
   across a `uint16`. Every clock-conformant variant repairs a strict subset.
5. **Is partial early repair worth the complexity?** **No.** The only
   clock-conformant, full-notice variant repairs a subset the quorum has to
   guess, while the late-case cost it cannot touch is exactly the cost that
   dominates.

**The conclusion is not "G′ is unsafe" — it is that G′ is solving the wrong
problem.** The measured baseline gap is between regime (ii) and regime (iii),
and it is closed by restoring an enumerated exit the kernel is missing, not by
adding a fourth mechanism that must then be defended against the clock rule.

---

## 9. `RECOVERY_MODEL_KERNEL_CONFORMANCE` — five points

1. **expiry clearing** — model clears (`:1031`), kernel never does → SD-9.
2. **guardian-set replacement during an approved request** — model denies,
   kernel admits and strands → SD-10.
3. **request replacement** — model denies, kernel permits → authority conflicts
   (§3).
4. **quorum cancellation** — model has it, kernel has no quorum-side withdrawal.
5. **challenge-epoch reset on success** — kernel resets, model never resets.

None of the five is recorded anywhere in `defects.ts`, `AUTHORITY.md` or
`KERNEL_ADMISSION.md`.

## 10. `PUBLISHED_STATEFUL_EVIDENCE_REGENERATABLE = NO`

Unchanged from Lane U, with one item **removed** and one **added**. Removed: the
*"same one-cycle cost"* premise is **not** falsified after all — §5 rehabilitates
it. Added: the artifact carries no record of the five conformance points in §9.
Regeneration still requires an owner decision on how to represent #188's
superseded ledger entry without destroying it.
