# Lane W — recovery lifecycle semantic freeze + implementation brief

> ## CORRECTED BY LANE W1 — the expiry boundary
>
> This document stands as written. **Its §D froze the kernel's own reading of
> recovery expiry** — live while `now <= expiresAt` — and that conclusion is
> **superseded**. It is kept because how the wrong reading was reached is
> evidence: Lane W derived the boundary from the artifact under conformance
> review, which is the one artifact that must not decide it.
>
> 1. **Lane W froze the kernel `>` interpretation** (`VaultKernelPrototype.sol:1228`).
> 2. **Cross-artifact reconciliation selects `>=` expiry / `t < expiresAt`
>    effective liveness.** The model is uniformly `>=` on every expiry
>    (`vaultVNextModel.ts:696, :1031, :1040, :1358`) and `>` only on a
>    *deadline* (`:1140`); the kernel's own containment is `>= containedUntil`
>    (`:691`) and its deadline `> deadline` (`:665`). The kernel already
>    distinguishes an inclusive deadline from an exclusive expiry, and breaks its
>    own convention for recovery alone. #179 is silent on the inequality.
> 3. **The phrase "`t0+21d` = last live instant" is WITHDRAWN.**
> 4. **The last live integer-second probe is `expiresAt − 1`** (measured: a
>    quorum cancellation executed at exactly `expiresAt − 1` succeeds).
> 5. **At `expiresAt` the request is already expired**, and a fresh initiation
>    at that instant is **not overwrite** — the live-request guard does not fire
>    (measured).
>
> `LIVE_WINDOW = [executableAt, expiresAt)`. See `SD4_LANE_W1_BOUNDARY_CORRECTION.md`.
>
> ## ALSO CORRECTED BY LANE W1.2 — §C2 and §H item 1
>
> §C2 concluded a standalone counter was sufficient and §H item 1 made moving
> the field out of `RecoveryRequest` the first implementation step, flagging a
> breaking `recovery()` getter change. **Both are withdrawn.** The field stays
> where it is; its *lifetime* is redefined as the epoch's, and the existing
> `delete recovery` at `:1240` is the reset boundary. SD-9a is narrowed to
> *lifetime coupling* — a remediation hazard, not a struct-placement defect.
> See `SD4_LANE_W12_STATE_MINIMALITY.md`.

**Append-only.** `c67d1439` unchanged. Every prior lane record stands, including
every falsified claim — #188's A/E impossibility reasoning, the
`SD4_GENERAL_IMPOSSIBILITY` refutation, the G′ family failures, Lane U's
withdrawn 21-day inference, Lane V's superseded overwrite ambiguity, and K-9's
false completeness summary. **The correction chain is the evidence.**

**No Solidity edits, commits, pushes, PR changes, or evidence regeneration.**

---

## 0. Verdicts

| Term | Verdict |
| --- | --- |
| `K9_AUTHORITY_SEMANTICS` | **FROZEN** |
| `CHALLENGE_RESET_ON_SUCCESS` | **DERIVED_REQUIREMENT_NEEDS_EXPLICIT_ARCHITECTURE_RECORD** |
| `RECOVERY_CHALLENGE_EPOCH` | **FROZEN** (independent of both `RecoveryRequest` and `credentialGeneration`) |
| `RECOVERY_EFFECTIVE_EXPIRY` | **FROZEN**, with one unresolved boundary inequality |
| `APPROVED_REQUEST_OVERWRITE` | **NONCONFORMANT_AND_REDUNDANT** |
| `SD4_DEDICATED_REMEDIATION` | **NOT_REQUIRED** |
| `G_PRIME_INCREMENTAL_VALUE` | **NONE_ESTABLISHED** |
| `RECOVERY_LIFECYCLE_SEMANTICS_FROZEN` | **YES**, with two named open items |
| `RECOVERY_LIFECYCLE_READY_FOR_IMPLEMENTATION` | **YES** |
| `EVIDENCE_ONLY_PR_READY` | **YES** — W1 recommended |

---

## A. K-9 authority — `FROZEN`

```text
K-9 RECOVERY CANCELLATION — two mechanisms, two principals

1. Spending credential — CHALLENGE
   May terminate a live recovery, consuming from a finite bounded budget.

2. Guardian quorum — CANCEL
   May terminate a live recovery directly, consuming nothing and
   refunding nothing.
```

**These are two authority mechanisms, not one with two callers**, and they stay
distinct at the authorisation and event layer even if a future implementation
shares internal cleanup code.

Proved from primary authority:

| Claim | Coordinate |
| --- | --- |
| guardian quorum holds `CANCEL_RECOVERY` | `docs/Vault_vNext_Architecture.md:832`, table headed **"Direct capabilities (vNext)"** |
| spending credential holds a bounded challenge | `docs/Vault_vNext_Architecture.md` §22 D1 (~`:2225`) — "at most k times per episode", and `:945` `I-RECOVERY-NONVETO` |
| K-9 declares both | `KERNEL_ADMISSION.md:37` — "credential (**bounded count**), or guardian quorum" |
| they are **not** interchangeable principals | `:832` lists the credential's direct capabilities as `MOVE_ASSETS, CHANGE_CREDENTIALS` — `CANCEL_RECOVERY` appears only on the quorum row; §22 D1 gives the credential a *bounded* right precisely because an unbounded one is H-03 |
| neither cancellation grants credential/floor/verifier/guardian authority | measured — cancellation writes only request state; `securityFloor`, `pqVerifier`, `ecdsaSigner`, `pqPublicKeyHash` and `guardianCommitment` are untouched on both paths |
| successful guardian recovery remains the only credential-changing path | `_installCredential` (`:952`) has exactly two callers — `rotateCredential` (`:800`) and `executeRecovery` (`:1242`); no cancellation path reaches it |

**Conformance at `c67d1439`: PARTIAL.** Mechanism 1 implemented; mechanism 2
absent. See §G1.

---

## B. The challenge epoch — `FROZEN`

```text
I-RECOVERY-CHALLENGE-EPOCH

The bounded challenge budget is independent of RecoveryRequest and
independent of credentialGeneration.

It persists across: credential challenge, guardian-quorum cancellation,
request expiry, fresh recovery initiation, and ordinary credential rotation.

It resets only after a successful guardian recovery.
```

### B1 — generation-key self-refund: **falsifies the generation key**

`_installCredential` is shared by `rotateCredential` and `executeRecovery`, so
keying the epoch on `credentialGeneration` lets the credential refund itself by
rotating in place. Lane V2 measured **six cancels where the design permits two,
with no natural end**. Under the frozen candidate the generation still bumps on
rotation and **the epoch does not follow it** — re-measured here.

### B2 — never-reset degeneration: **falsifies the opposite extreme**

Measured on a never-reset kernel: the credential exercises its full bounded
defence, a **legitimate** guardian recovery completes and installs genuinely new
material, and the **new credential inherits zero challenge capacity, permanently**.

This loses no assets. What it silently deletes is the §22 D1 / H-15 defence —
*"a finite, non-zero k costs the attacker `k × recoveryDelay`"* — for every
credential after the first, with no event marking the loss. **A never-reset
design is therefore not a conservative choice; it is a silent one.**

### B3 — reset-on-success: **no manufacture path**

Six transitions measured against the frozen candidate:

| Transition | Epoch |
| --- | --- |
| ordinary rotation **before** recovery | unchanged |
| quorum cancellation immediately before recovery | unchanged |
| expiry immediately before a later recovery | unchanged |
| recovery to genuinely **new** material | **reset** |
| ordinary rotation **after** recovery | unchanged |
| recovery reinstalling **identical** signer/key material | **reset** |

The last row is the important one: **the boundary is the authority transition,
not byte equality of the payload.** A quorum that recovers to identical material
has still exercised the recovery authority, and the epoch follows the authority.

Every reset requires a completed guardian recovery, which requires the quorum;
the credential cannot initiate. **No credential-only path manufactures budget.**

### `CHALLENGE_RESET_ON_SUCCESS` = `DERIVED_REQUIREMENT_NEEDS_EXPLICIT_ARCHITECTURE_RECORD`

**#179 does not state it.** It is *derived* from the composition of D1 (the
challenge is the credential holder's defence, priced in `k × recoveryDelay`),
H-03 (unbounded credential veto), and H-15 (unchallenged guardian takeover):
B1 shows the budget must not follow a credential-controllable key, B2 shows it
must not never-reset. Reset-on-recovery is the only surviving boundary among
those tested — but **calling it #179 authority would be false.** It needs an
explicit architecture record before implementation treats it as settled.

---

## C. Two state machines, decomposed

### C1 — `RecoveryRequest` lifecycle

```text
ABSENT
  │ initiate (quorum)
  ▼
LIVE  ──credential challenge──▶ ABSENT   (consumes epoch)
  │   ──guardian cancellation─▶ ABSENT   (consumes nothing)
  │   ──successful execute────▶ ABSENT   (resets epoch)
  └────wall-clock expiry──────▶ EXPIRED  (zero authority, no principal acts)
```

Request-scoped data only: proposed signer, PQ commitment, proposed verifier,
guardian-generation binding, authorisation binding, `executableAt`, `expiresAt`,
request-local proof material. **It does not own the challenge budget.**

### C2 — challenge-epoch lifecycle

```text
budget available
  │ credential challenges consume it
  │ cancellation / expiry / re-initiation / ordinary rotation DO NOT replenish
  ▼
successful guardian recovery ──▶ new epoch, budget reset
```

**Is a stored `recoveryEpoch` identifier necessary?** Tested as: a single
`uint32 recoveryChallengesUsed` with one reset site is **sufficient** for every
property in §B. An epoch *identifier* would buy exactly one thing the counter
does not: the ability to bind a challenge authorisation to a specific epoch, so
a signature prepared under epoch *n* cannot be replayed after a recovery moved
the vault to epoch *n+1*.

**Trade-off, reported rather than decided:** the kernel's existing per-domain
nonce (`_consume(DOMAIN_CREDENTIAL, …)`) already prevents replay of a *used*
signature, and `credentialGeneration` is bound into the challenge digest — which
a successful recovery bumps. So the replay window an identifier would close is
already closed by the generation binding. **Recommendation: the counter alone**,
unless observability of "which epoch is current" is wanted as a first-class
event field. Less state, no assurance loss identified.

---

## D. Effective expiry — `FROZEN`, one open inequality

```text
I-RECOVERY-EFFECTIVE-LIVENESS

effectiveLive(recovery) := recovery.active AND now <= recovery.expiresAt
```

**No sweeper.** #179 requires expiry with no principal action
(`I-RECOVERY-TERMINATION`, `:948`), and a design that needs a transaction to
realise expiry has not satisfied it.

**The boundary was derived, and the two artifacts disagree** — this is a finding,
not a choice:

| Artifact | Rule | At exactly `expiresAt` |
| --- | --- | --- |
| kernel `VaultKernelPrototype.sol:1228` | `now > expiresAt → Expired` | **LIVE** |
| model `vaultVNextModel.ts:1031`, `:1040` | `clock >= expiresAt → dead` | **DEAD** |

The architecture specifies neither. The frozen statement adopts the **kernel**
boundary because it matches the natural reading of *"has not passed its
authorized expiry"*. **The one-instant divergence must be reconciled**; it is
recorded as an open item rather than silently resolved.

### Consumer obligations

| Consumer | Must observe for an expired request |
| --- | --- |
| `executeRecovery` | refuse — already does (`Expired`) |
| `initiateRecovery` | **must NOT be blocked** — an expired request is replaceable |
| credential challenge | refuse — no cancellation target, **and no epoch consumed** |
| guardian-quorum cancellation | refuse — same reason |
| `bindMigration` | **must not block** — today it tests raw `recovery.active` |
| guardian-set replacement | unaffected by expiry; separately defective (SD-10) |
| effective safe state / recovery gates | must derive from `effectiveLive`, not the stored flag |
| stateful oracle (`invariants.ts`) | snapshot must expose `effectiveLive`, not raw `active` |
| campaign model | already deletes on expiry; must adopt the reconciled inequality |
| observability getters/events | should expose `effectiveLive()` so an observer needs no clock arithmetic |

**Property:** an expired request may leave stale bytes in storage, but it has
**zero execution authority, zero cancellation-target authority, and zero
blocking effect**. Physical cleanup may be opportunistic on a later write. **No
security or liveness property may require a sweeper transaction.** Measured: with
no sweeper called at any point, an expired request refuses execution and both
cancellations, and migration binds successfully.

---

## E. Overwrite — `NONCONFORMANT_AND_REDUNDANT`

| | overwrite | quorum cancel + initiate |
| --- | --- | --- |
| principals | guardian quorum | guardian quorum |
| quorum authorisations | 1 | 2 |
| guardian nonces consumed | 1 | 2 |
| request identity | silently replaced | explicitly terminated, then created |
| terminal event | **none** | `RecoveryCancelledByQuorum` |
| challenge budget | carried | carried |
| guardian generation | unchanged | unchanged |
| `executableAt` / `expiresAt` | new request, new clocks | new request, new clocks |
| final payload | identical | identical |
| stale-signature replay surface | a prepared cancellation aimed at request *n* can meet request *n+1* in the same storage slot | the slot is empty between the two acts |
| ordering | one transaction | two, orderable and observable |

With K-9's quorum cancellation available, overwrite provides **no capability the
explicit lifecycle lacks**. It collapses two authorised actions while bypassing
explicit termination, and costs the terminal event an observer needs.

**Frozen distinction:** an **effectively live** request refuses replacement; an
**expired** one is no longer live and must not block fresh initiation. Both
measured.

---

## F. SD-4 disposition — `NOT_REQUIRED`

```text
guardianCancel → initiateRecovery(correct payload) → RECOVERY_DELAY → execute → spend
```

Run at `t0`, `t0+7d`, `t0+14d`, `t0+20d`, and `t0+21d` (the last effectively-live
instant). **All five repaired**, each asserting: no security-floor mutation by
the remedy; no existing clock reset or extended; the fresh request receives its
own ordinary delay and expiry; full `RECOVERY_DELAY` notice on the actual final
executing payload; challenge budget preserved; guardian generation correct; the
old request emits an observable terminal transition; and the recovered credential
**actually spends** under the declared 32/64 floor.

```text
SD4_DEDICATED_REMEDIATION       = NOT_REQUIRED
SD4_ARCHITECTURE_CONFORMANT_REMEDY = K-9 guardian cancellation
                                   + fresh correctly-shaped recovery
G_PRIME_INCREMENTAL_VALUE       = NONE_ESTABLISHED
```

**The G′ experiments are retained.** They are the evidence that the simpler
architecture-native path dominates them: `u1full` repairs only an early band and
rewrites a clock; `atomic`/`notice` give 0 s and <60 s notice; `U5` needs the
shape guessed in advance. The conformant path repairs every timing tested,
at full notice, with no clock rewritten.

---

## G. Record corrections — drafted, not persisted

### G1 — `KERNEL_ADMISSION.md`

The sentence at `:45` — *"Every one of the 15 is implemented in the prototype.
None is omitted for size."* — **is false for K-9.** Draft correction, preserving
the historical claim:

> **CORRECTION (Lane W).** The sentence above is retained as written and is
> **false for K-9**. K-9 declares two cancellation authorities — the spending
> credential's bounded challenge and the guardian quorum's direct
> `CANCEL_RECOVERY` (`docs/Vault_vNext_Architecture.md:832`). The prototype at
> `c67d1439` implements the credential challenge only; no quorum-side
> cancellation exists on the ABI, whose complete quorum surface is
> `bindMigration, enterContainment, initiateRecovery, setGuardians`. **K-9
> conformance is therefore PARTIAL/FAILED at `c67d1439`**, and the summary line
> is contradicted by the table it summarises.

### G2 — architecture / model semantic record

Add `I-RECOVERY-CHALLENGE-EPOCH` as stated in §B, marked:

> **Status: DERIVED, not sourced.** Composed from §22 D1, H-03 and H-15. #179
> does not state it. The reset boundary (successful guardian recovery) is a
> **new owner decision** required before implementation, not existing authority.

Also record the §D boundary divergence as an open reconciliation item.

### G3 — defect records: **one root cause, three subfindings**

Causal decomposition preferred over SD-number count. The findings share a single
root:

> **SD-9 — `RECOVERY_LIFECYCLE_STATE_OWNERSHIP`.** The kernel models recovery as
> one object where the architecture models two. `challengesUsed` lives inside
> `RecoveryRequest`, and request liveness is a stored flag rather than a
> wall-clock derivation.
>
> - **SD-9a** — challenge budget shares the request's storage lifetime, so any
>   correct expiry cleanup would refund it (measured).
> - **SD-9b** — an expired request retains blocking authority over
>   `bindMigration` and requires a principal to clear (violates
>   `I-RECOVERY-TERMINATION`, `:948`).
> - **SD-9c** — K-9's guardian cancellation is absent, and direct overwrite
>   substitutes for it (violates the enumerated exit set; see §E).

**SD-10 stays separate**: `APPROVED_REQUEST_STRANDED_BY_GUARDIAN_ROTATION`
violates `I-APPROVED-REQUEST-PRESERVATION` (`:951`) and has a different root —
generation binding, not state ownership.

---

## H–J. Implementation brief, mutation plan, persistence sequencing — SUPERSEDED, PRUNED IN LANE W1R

These three sections encoded **Candidate P** (move `challengesUsed` out of
`RecoveryRequest`; explicit compatibility getter). Lane W1.2 falsified that
assumption by nine-history equivalence, and the surviving contract — Candidate
C — is persisted once, in `W2_IMPLEMENTATION_CONTRACT.md`, together with the
mutation contract and the W1/W2 sequencing. The Candidate P text was a plan,
not evidence; its falsification is recorded in `SD4_LANE_W12_STATE_MINIMALITY.md`
§E, which is what history needs. Nothing measured was removed.

## Open items, named

1. **`CHALLENGE_RESET_ON_SUCCESS` needs an explicit architecture record** (§B).
   It is derived, not sourced, and blocks §H item 9.
2. **The expiry boundary inequality** (§D) — kernel `<=` versus model `>=`, one
   instant apart, unspecified by the architecture.
