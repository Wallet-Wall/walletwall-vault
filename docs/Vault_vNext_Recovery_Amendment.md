# Vault vNext — Recovery Lifecycle Amendment (derived, layered above #179)

> ⚠️ **Research prototype. Not audited. Not production custody.**
>
> **This document does not modify `Vault_vNext_Architecture.md` (#179) and must
> not be read as if it did.** It is a *derived-vNext amendment* layered above the
> frozen architecture, recording semantics that adjudication lanes T through
> W1.2 established were **not stated by #179**, were **required by its
> composition**, and are **not all implemented or explicitly protected** by the
> prototype at `c67d1439` — §2 finds the challenge-epoch behaviour partly
> realised by existing side effects with no invariant protecting it, while §1,
> §3 and the overwrite finding are outright missing or nonconformant.
> Every statement is tagged with exactly one of three authority classes, and
> the tags are not interchangeable:
>
> | Tag | Meaning |
> |---|---|
> | **SOURCE AUTHORITY** | stated in `Vault_vNext_Architecture.md` or `Vault_vNext_Hazard_Register.md`, with a coordinate |
> | **DERIVED REQUIREMENT** | follows from the composition of source authority; #179 does not state it verbatim, and this document does not pretend it does |
> | **IMPLEMENTATION CONFORMANCE** | what the prototype at `c67d1439` actually does, measured |
>
> The executable evidence is `prototype/vnext-kernel/test/Sd4*.test.ts`; the
> adjudication history is `prototype/vnext-kernel/SD4_*.md`. Falsified
> intermediate conclusions are preserved there append-only and are **not**
> restated here as if they had always been known.

---

## 1. Recovery cancellation authority (K-9)

**SOURCE AUTHORITY.** `Vault_vNext_Architecture.md:832`, table headed *"Direct
capabilities (vNext)"*: `| Guardian quorum | APPROVE_RECOVERY, CANCEL_RECOVERY,
CHANGE_GUARDIANS, ENTER_CONTAINMENT |`. §22 D1 (`~:2225`): the spending
credential may cancel a pending recovery a bounded number of times.
`I-RECOVERY-NONVETO` (`:945`, T1): no principal holds an unbounded veto.
`prototype/vnext-kernel/KERNEL_ADMISSION.md:37`, K-9: *"credential (bounded
count), or guardian quorum"*.

**DERIVED REQUIREMENT.** These are **two authority mechanisms held by two
non-interchangeable principals**, and stay distinct at the authorisation and
event layer even where an implementation shares cleanup code:

```text
K-9 RECOVERY CANCELLATION

A. Spending credential — CHALLENGE
   may terminate an effectively-live recovery, consuming from a finite
   bounded budget (the challenge epoch, §2).

B. Guardian quorum — CANCEL
   may terminate an effectively-live recovery directly, consuming nothing
   from and refunding nothing to the credential's budget.
```

Neither mechanism grants credential, floor, verifier or guardian authority;
`_installCredential` has exactly two callers (`rotateCredential`,
`executeRecovery`) and no cancellation path reaches it. Neither cancellation
mechanism changes credentials. Ordinary `rotateCredential` also changes
credentials, under the credential's own authority; successful guardian recovery
is the only **guardian-authorized recovery-lifecycle transition** that changes
credentials.

**IMPLEMENTATION CONFORMANCE.** Mechanism A implemented. **Mechanism B
missing.** `K9_GUARDIAN_CANCEL_CONFORMANCE = MISSING_IN_PROTOTYPE`. See
`KERNEL_ADMISSION.md` K-9 correction.

## 2. The challenge epoch — `I-RECOVERY-CHALLENGE-EPOCH`

**DERIVED REQUIREMENT — `DERIVED_REQUIREMENT_ADOPTED_FOR_VNEXT`.**
#179 does **not** state the reset boundary. It is derived, and adopted for
vNext by this amendment:

```text
I-RECOVERY-CHALLENGE-EPOCH

The spending credential's bounded recovery-challenge budget is semantically
independent of RecoveryRequest lifetime and of credentialGeneration.

It persists across:  credential challenge · guardian-quorum cancellation ·
                     request expiry · fresh initiation · ordinary credential
                     rotation.

It resets ONLY after a successful guardian recovery.
```

**Derivation** (each step measured, `Sd4LaneV2`, `Sd4LaneW`, `Sd4LaneW1`):

- **reset on credential-authorised rotation → self-refunding veto.**
  `_installCredential` bumps `credentialGeneration` on rotation *and* on
  recovery; keying the epoch on the generation lets the credential refund
  itself by rotating in place — six cancels measured where two are permitted.
  That is hazard **H-03**, which `I-RECOVERY-NONVETO` forbids.
- **never reset → permanent loss of the D1/H-15 defence.** After a legitimate
  recovery, the new credential inherits zero challenge capacity forever; the
  defence §22 D1 prices at `k × recoveryDelay` is silently deleted for every
  credential after the first.
- **successful guardian recovery is the separating authority transition**,
  because the outgoing spending credential cannot authorise it and the recovery
  trust root (§22 D1) is what installs the post-recovery authority. Recovery to
  byte-identical material still resets: the boundary follows the authority, not
  the bytes.

**Semantic independence does not require physical storage separation.** Lane
W1.2 drove a standalone counter and the existing co-located struct field
through nine histories with deep equality on every externally observable state
at every step (`Sd4LaneW12`). The field may remain in `RecoveryRequest`; what
is required is the *lifetime rule* above, not a storage move.

**IMPLEMENTATION CONFORMANCE.** The prototype carries the field forward on
initiation (`:1177`), never touches it on rotation, and resets it via `delete
recovery` on execution (`:1240`) — behaviour consistent with the epoch **by side
effect, with no rule protecting it** (SD-9a).

## 3. Effective recovery expiry — `I-RECOVERY-EFFECTIVE-LIVENESS`

**SOURCE AUTHORITY.** `I-RECOVERY-TERMINATION` (`:948`, T1): expiry *"requires
no principal to act."* The generalised CLOCK RULE (`:736`): no state transition
may reset, extend or suspend any clock. **#179 states no inequality for any
clock boundary.**

**DERIVED REQUIREMENT.** Reconciled across every other authoritative vNext
clock rather than taken from the artifact under review:

| Artifact | Clock | Rule |
|---|---|---|
| reference model `vaultVNextModel.ts:696, :1031, :1040, :1358` | every expiry | `>= expiry` → expired |
| reference model `:1140` | migration *deadline* | `> deadline` → expired (equality still valid) |
| prototype `:691` | containment `containedUntil` | `>= containedUntil` → NORMAL |
| prototype `:665` | signed-action `deadline` | `> deadline` → Expired |
| **prototype `:1228`** | **recovery `expiresAt`** | **`> expiresAt` → Expired — the lone outlier** |

A *deadline* is inclusive; an *expiry* names the instant at which authority
ends. The prototype already holds that distinction for containment and breaks it
for recovery alone.

```text
LIVE_WINDOW          = [executableAt, expiresAt)
effectiveLive(r, t)  = r.active && t < r.expiresAt
t == expiresAt       => expired

An expired request may leave stale bytes in storage. It has zero execution
authority, zero cancellation-target authority, and zero blocking effect. No
security or liveness property may require a sweeper transaction.
```

**IMPLEMENTATION CONFORMANCE.** `PROTOTYPE_EXPIRY_OFF_BY_ONE =
OFF_BY_ONE_CONFORMANCE_DEFECT` (SD-9e). Lane W had earlier frozen the
prototype's own `<=` reading; that conclusion is **superseded** and preserved as
evidence in `SD4_LANE_W_SEMANTIC_FREEZE.md`.

## 4. SD-4 disposition

**DERIVED REQUIREMENT.**

```text
SD4_DEDICATED_REMEDIATION = NOT_REQUIRED
G_PRIME_INCREMENTAL_VALUE = NONE_ESTABLISHED

SD4_REMEDY =
    if old request is effectively live:
        guardian quorum CANCEL_RECOVERY → fresh correctly-shaped recovery
    if old request is expired:
        fresh correctly-shaped recovery, directly

The final executing request always receives a fresh, full RECOVERY_DELAY.
```

Measured at `t0`, `t0+7d`, `t0+14d`, `t0+20d`, `expiresAt−1`, `expiresAt`,
`expiresAt+1`, each landing at its asserted block timestamp, each through to an
actual spend under the declared floor, with no floor mutation and no clock
rewritten (`Sd4LaneW1`).

**What this supersedes, preserved and not rewritten:** #188's A/E impossibility
reasoning (`SD4_TEMPORAL_ADJUDICATION.md`), the `SD4_GENERAL_IMPOSSIBILITY`
refutation, and every G′ variant — `atomic`, `notice`, `delay`, `reset`,
`clamped`, `u1full`, `u2a`, `u2b`, `U5` — all retained as falsified experiments
in `test/sd4-candidate-kernels.ts` and the lane records. They are the evidence
that the architecture-native path dominates them.

**IMPLEMENTATION CONFORMANCE.** The remedy requires mechanism B of §1, which the
prototype lacks; today the prototype reaches the same timing only through the
nonconformant overwrite (SD-9d).

## 5. Guardian-cancel replay — `GUARDIAN_NONCE_SERIALIZATION_SUFFICIENT`

**DERIVED REQUIREMENT.** A cancellation authorisation prepared for request *n*
must not terminate request *n+1*. **No request identifier or hash is required.**
The existing `DOMAIN_GUARDIAN` nonce protocol suffices, and the proof depends on
**all** of the following — this dependency is review-visible by design:

Each premise names the assertion in `test/Sd4LaneW12.test.ts` §D that **fails
closed** if the premise stops holding — so a future change that breaks a premise
breaks a test, not merely a paragraph:

1. **every fresh request consumes a `DOMAIN_GUARDIAN` nonce** (`initiateRecovery`
   is the only creator of a live request, and always calls `_consume`) —
   witness: *"initiation consumed the stale nonce"*, `nonces(GUARDIAN) == N+1`
   after R2. **If `initiateRecovery` ever stops consuming the nonce, this
   assertion fails immediately.**
2. **live overwrite is refused** — witness: `Sd4LaneW12` snapshot
   `canInitiate === "BadState"` while live, and `Sd4LaneW1` E-series;
3. therefore a new request cannot exist without consuming the nonce a stale
   cancellation would need — a consequence of 1 and 2, not a separate premise;
4. **a stale cancel before a replacement sees no live target and consumes
   nothing** — witness: *"revert consumes nothing"*, `nonces(GUARDIAN) == N+1`
   unchanged after the refused cancel, on all three termination paths;
5. **a stale cancel after a replacement fails nonce validation** — witness:
   `BadNonce` after R2, on all three termination paths; and the guardian
   cancellation consumes the *same* serialized domain (`_consume(DOMAIN_GUARDIAN)`);
6. **a guardian-generation change independently invalidates old quorum
   authority** — witness: `QuorumNotMet` after an intervening `setGuardians`,
   because the digest binds `guardianGeneration` and `_requireQuorum` runs
   before `_consume`.

Executable cases preserved in `Sd4LaneW12`: termination by credential
challenge, by expiry, by successful recovery; an intervening guardian-set
change; same-block ordering in both orders; a failed replacement initiation.

> **DEPENDENCY.** If future code ever permits request creation without guardian
> nonce consumption, or live overwrite without nonce serialisation, **this proof
> no longer applies** and must be re-established or replaced by explicit request
> binding.

**IMPLEMENTATION CONFORMANCE.** Condition 2 is not met at `c67d1439` (overwrite
is permitted), so the proof holds only for the W2 target, not the prototype.

---

## W2 status addendum (Lane W2I — local implementation diff for independent review; nothing above is rewritten)

Every **IMPLEMENTATION CONFORMANCE** line in this document describes the
prototype at `c67d1439` and stands as history. On the W2 diff
(`prototype/vnext-kernel/W2_IMPLEMENTATION_RECORD.md`):

| Section | Status at `c67d1439` (above) | Status on the W2 diff |
|---|---|---|
| §1 K-9 | mechanism B `MISSING_IN_PROTOTYPE` | **IMPLEMENTED** — `cancelRecoveryByQuorum(QuorumProof,uint256,uint64)`, `DOMAIN_GUARDIAN` nonce, clears authority only, distinct event |
| §2 challenge epoch | consistent by side effect, unprotected (SD-9a) | **STATED AND GUARDED** — rule at the struct field and at the `delete recovery` reset site; oracle `G-CHALLENGE-EPOCH`; four refund mutants and the no-reset mutant killed; the reference model resets on successful recovery (M58 discriminates) |
| §3 effective expiry | `> expiresAt` outlier (SD-9e) | **HALF-OPEN** — `_recoveryIsLive() = active && block.timestamp < expiresAt`; `executeRecovery` refuses at `>= expiresAt`; an expired request blocks neither migration nor initiation and is no cancellation target; no sweeper |
| §4 SD-4 disposition | remedy requires mechanism B | **REMEDY AVAILABLE** — live: quorum cancel then fresh recovery; expired: fresh recovery directly. `SD4_DEDICATED_REMEDIATION = NOT_REQUIRED` unchanged |
| §5 replay | condition 2 unmet | **ALL SIX PREMISES HOLD** on the real artifact — live overwrite refused before any nonce is consumed; stale cancel finds no target and consumes nothing, then dies as `BadNonce` after the replacement, or as `QuorumNotMet` after a generation change (`test/W2RecoveryLifecycle.test.ts` §E) |

The generated evidence receipts are NOT restamped by this lane (they still
identify `28adbb88`/`c67d1439`); the regeneration plan is in the record.
