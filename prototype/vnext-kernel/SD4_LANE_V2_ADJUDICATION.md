# SD-4 Lane V (continued) — K-9's missing half

**Append-only.** `c67d1439` unchanged; earlier lane records stand. **No
production Solidity, no commit, no push, no evidence regeneration, no PR
metadata.**

---

## 1. Verdicts

| Term | Verdict |
| --- | --- |
| `K9_GUARDIAN_CANCEL_CONFORMANCE` | **MISSING_IN_PROTOTYPE** |
| `RECOVERY_REQUEST_LIFECYCLE` | **THREE-WAY TERMINATION NOT IMPLEMENTED** |
| `RECOVERY_CHALLENGE_EPOCH` | **SOUND IN INTENT, FALSIFIED AS KEYED** |
| `CHALLENGE_RESET_ON_SUCCESS` | **AMBIGUOUS — MODEL UNDERDETERMINED** |
| `APPROVED_REQUEST_OVERWRITE` | **NONCONFORMANT** — supersedes Lane V's conflict verdict |
| `EXPIRED_RECOVERY_AUTHORITY_STALE` | **CONFIRMED**, with a sharpened remediation requirement |
| `G_PRIME_INCREMENTAL_VALUE` | **NONE_ESTABLISHED** |
| `SD4_ARCHITECTURE_CONFORMANT_REMEDY` | **implement K-9's missing half; fix expiry without refunding the epoch** |

---

## 2. K-9 — `MISSING_IN_PROTOTYPE`

**The authority, firsthand.** `docs/Vault_vNext_Architecture.md:832`, under the
heading **"Direct capabilities (vNext)"** — normative, not descriptive:

> `| Guardian quorum | APPROVE_RECOVERY, CANCEL_RECOVERY, CHANGE_GUARDIANS, ENTER_CONTAINMENT |`

`prototype/vnext-kernel/KERNEL_ADMISSION.md:37`, K-9 "Recovery cancellation",
authority column: **"credential (bounded count), or guardian quorum"**.

**The implementation.** One `cancelRecovery(nonce, deadline, ecdsaSig)`, gated by
`_floorAuthorises` — the credential. The complete set of quorum-authorised
functions, enumerated from the ABI, is `bindMigration, enterContainment,
initiateRecovery, setGuardians`.

**Refutation attempted on three substitutes, all fail:**

- a "null" overwrite is impossible — `initiateRecovery` rejects a zero signer
  (`ZeroAddress`), so overwrite cannot express *"no request"*;
- containment does not cancel — `_requireRecoveryOpen` admits `CONTAINED`;
- `setGuardians` strands rather than cancels, and that is SD-10, a defect rather
  than a substitute.

### 2.1 The manifest statement, narrowed

`KERNEL_ADMISSION.md:45` states: *"**Every one of the 15 is implemented in the
prototype.** None is omitted for size."*

**This is falsified for K-9 and must be narrowed.** A defensible restatement:
*fifteen kernel-required concerns are addressed; K-9's declared authority names
two principals and only the credential half is implemented.* The row's own
implementation column — *"`cancelRecovery()` with a per-episode challenge
budget"* — describes only that half, so the manifest's summary line is
contradicted by the table it summarises.

---

## 3. `RECOVERY_REQUEST_LIFECYCLE` — three-way termination not implemented

`I-RECOVERY-TERMINATION` (`:948`) names three exits. The kernel:

| Exit | Status |
| --- | --- |
| execution | implemented |
| cancellation — credential, bounded | implemented |
| cancellation — **guardian quorum** | **MISSING** (§2) |
| expiry, autonomous | **BROKEN** — SD-9; `active` survives forever |
| *overwrite* | **PRESENT AND UNENUMERATED** (§6) |

Two of the three enumerated exits are absent or broken, and a fourth
unenumerated one exists in their place.

---

## 4. `RECOVERY_CHALLENGE_EPOCH` — sound in intent, falsified as keyed

The candidate's clause 1 says the epoch is *"scoped to the currently installed
credential generation"*; clause 4 says it *"resets only when guardian recovery
successfully installs a new credential generation"*. **These are consistent only
if recovery is the sole way to bump the generation. It is not.**

`_installCredential` (`:952`) has **two** callers: `rotateCredential` (`:800`)
and `executeRecovery` (`:1242`). Both increment `credentialGeneration`, and
rotation is the **credential's own** authority.

**Measured, on a kernel implementing clause 1 literally** (`Sd4LaneV2` test 4):
exhaust the budget, rotate in place — same signer, same commitment, no new
material — the generation bumps, the epoch resets, and the cycle repeats.
**Six cancels where the design permits two, with no natural end.** That is
hazard H-03 restored by a *semantic definition* rather than by a bug.

**Corrected form.** Clause 4 is the requirement; clause 1 is not a valid way to
implement it. The epoch must be keyed on something the credential cannot
advance — a recovery-caused install specifically, not a generation counter that
rotation shares. Clauses 2 and 3 stand unchanged and are source-derived.

---

## 5. `CHALLENGE_RESET_ON_SUCCESS` — ambiguous, model underdetermined

The reference model never resets `credentialChallengesUsed` — anywhere. The
kernel resets it via `delete recovery`. Which is intended?

- **For "intended vault-lifetime":** the model is a T1 assurance artifact and its
  behaviour is uniform.
- **For "model defect":** the field is named `credentialChallengesUsed`, which
  implies credential scope, and its behaviour is vault scope. §22 D1 frames the
  challenge as the *credential holder's* defence — *"requires the credential
  holder to be absent throughout"* — which implies a new holder gets a new
  budget.
- **Decisive against reading the model as authoritative here:** **no model test
  and no mutant exercises the post-recovery case.** `credentialHoldsUnboundedVeto()`
  probes only within a single generation, and `M27` removes the bound check
  rather than testing its scope. By the model's own stated methodology — *"a
  mutation on a guard the scenario never reaches would otherwise 'pass' while
  proving nothing"* — an unexercised property is **not established**.

**Verdict: `AMBIGUOUS — MODEL UNDERDETERMINED`.** The model's silence is absence
of evidence, not evidence of intent. Not chosen by convenience; the architecture
leans toward reset-on-recovery via D1, but no artifact establishes it.

---

## 6. `APPROVED_REQUEST_OVERWRITE = NONCONFORMANT` — superseding Lane V

Lane V classified this `AUTHORITY_GENUINELY_CONFLICTS`, and the load-bearing
reason was that **overwrite is the quorum's only immediate exit**. That reason
is now gone: §8.1 grants the quorum `CANCEL_RECOVERY` and K-9 declares it. The
exit exists in the architecture; the prototype simply omits it.

Measured comparison of `overwrite(newRequest)` against
`cancelRecoveryByQuorum(); initiateRecovery(newRequest)`:

| | overwrite | cancel + initiate |
| --- | --- | --- |
| required principals | guardian quorum | guardian quorum |
| quorum authorisations | **1** | **2** |
| guardian nonces consumed | **1** | **2** |
| final payload | identical | identical |
| notice on final payload | full `RECOVERY_DELAY` | full `RECOVERY_DELAY` |
| `executableAt` / `expiresAt` | new request, new clocks | new request, new clocks |
| guardian generation | unchanged | unchanged |
| challenge history | carried | carried |
| request identity | **silently replaced** | **explicitly terminated, then created** |
| observability | one `RecoveryInitiated` | `RecoveryCancelled` **then** `RecoveryInitiated` |

Overwrite reaches no state the enumerated path cannot, and provides **no
legitimate capability**. What it does is **collapse two authorised actions into
one while bypassing explicit termination** — and the observability column is
where that costs something: an observer sees a request change identity with no
event marking the old one's end.

**Classified nonconformant**, not necessary liveness behaviour.

---

## 7. Expiry — the remediation requirement, sharpened

The finding stands: an expired request remains stored `active` and blocks
`bindMigration`. **But `delete recovery` is NOT a sufficient remedy**, and this
is measured rather than warned about:

- **Refunding sweep** (`delete recovery`): budget exhausted → request expires →
  sweep → `challengesUsed` reads **0** → the credential cancels again. The
  epoch died with the struct that held it.
- **Preserving sweep** (`recovery.active = false`): request neutralised,
  `challengesUsed` stays at **2**, the next request is still unchallengeable,
  and quorum cancellation composes the same way.

**Is the refund adversarially forceable? No** — and that is reported rather than
inflated. Every clearing trigger is quorum-side or wall-clock: the credential
cannot sweep early (`TooEarly`) and cannot force expiry, since expiry requires
the quorum to decline to execute for `RECOVERY_DELAY + RECOVERY_EXPIRY`.

**What is still lost is real.** §22 D1 prices the defence as costing the attacker
`k × recoveryDelay`. With a refund, that price stops being a constant of the
design and becomes a function of quorum behaviour. A stated bound has become a
behavioural one, which is a weaker property even where it is not forceable.

**Requirement:** expiry must remove the *request's* authority and effects
**without refunding the current credential's bounded challenge budget.** The
structural cause is that the kernel stores `challengesUsed` **inside**
`RecoveryRequest`, where the reference model stores it on the kernel, outside.

---

## 8. `G_PRIME_INCREMENTAL_VALUE = NONE_ESTABLISHED`

The conformant sequence — quorum cancel → fresh initiate with a payload matching
the declared shape → `RECOVERY_DELAY` → execute — was run against SD-4 deaths at
`t0`, `t0+7d`, `t0+14d` and `t0+20d`. **All four repaired**, each with:

- two guardian quorum acts, no other principal;
- a full `RECOVERY_DELAY` of notice on the final payload;
- a full `RECOVERY_EXPIRY` execution window;
- challenge history carried, not refunded;
- guardian generation binding intact;
- the recovered credential actually spending under the declared 32/64 floor;
- **no clock reset, extended or suspended** — the new request simply has new
  clocks, which the generalised CLOCK RULE (`:736`) permits where rewriting an
  existing request's clocks does not.

Compare against the surviving G′ families: `u1full` repairs only `[t0, t0+14d−W]`
and rewrites `executableAt`; `atomic`/`notice` give 0 s and <60 s notice; `U5`
repairs only shapes published in advance. **`t0+20d` is repaired by the
conformant path and by no G′ family.**

**No G′ preserving full final-payload notice provides any security or liveness
capability unavailable through quorum-cancel + fresh initiation.** G′ is not
preserved merely because it is constructible.

---

## 9. `SD4_ARCHITECTURE_CONFORMANT_REMEDY`

Two changes, neither of which is a ratification mechanism and neither of which
touches a clock:

1. **Implement K-9's missing half** — a quorum-authorised recovery cancellation
   (§2). This restores an enumerated exit, removes any need for overwrite, and
   makes the SD-4 repair path two ordinary authorised acts.
2. **Make expiry autonomous without refunding the epoch** (§7) — which requires
   moving the challenge counter out of `RecoveryRequest`, or otherwise
   preserving it across the request's end.

SD-4 itself then needs no dedicated mechanism: it is repaired at every timing by
the path the architecture already specifies.

**Not established, and left open:** `CHALLENGE_RESET_ON_SUCCESS` (§5); the
correct epoch key (§4); and whether the manifest line at
`KERNEL_ADMISSION.md:45` should be narrowed or the missing half implemented
first (§2.1).
