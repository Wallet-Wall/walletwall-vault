# SD-9 / SD-10 — recovery lifecycle defect records (persisted classification)

**Not entered in `stateful/defects.ts`**, which is #188's ledger and is not
edited. These are the persisted classifications as refined through Lane W1.2;
the Lane V candidate wording that preceded them — including the reasoning that
then declined to call overwrite a defect — is preserved in
`SD4_LANE_V_ADJUDICATION.md` §3–§4 and is superseded here where it differs.

`SD-1`…`SD-8` are taken in `defects.ts`. `SD-9` and `SD-10` are free. No further
numbers are created: the five SD-9 subfindings are symptoms with a common root,
not five defects.

---

## SD-9 — `RECOVERY_LIFECYCLE_STATE_OWNERSHIP`

**Root.** The kernel implements one recovery object with one stored liveness
flag. The architecture's recovery requirements (`I-RECOVERY-TERMINATION`,
`I-RECOVERY-NONVETO`, K-9), composed with the reference model and the adopted
derived-vNext amendment, require **two semantic lifetimes** — the recovery
request and the challenge epoch — three enumerated exits, and wall-clock
liveness. The exits and liveness are source authority; the challenge-epoch
lifetime and its reset boundary are the **derived** requirement of
`docs/Vault_vNext_Recovery_Amendment.md` §2, which #179 does not state verbatim.
**Subfindings are classified individually, because they are not all the same
kind of thing.**

### SD-9a — `RECOVERY_CHALLENGE_EPOCH_LIFETIME_UNSPECIFIED` — **REMEDIATION HAZARD / SPECIFICATION GAP**

**Not a present implementation defect.** At `c67d1439` no executed path deletes
or refunds on expiry — expiry does nothing — so **no refund is exploitable and
none is claimed from storage co-location.** The refund observed in Lane V2 arose
only inside a *probe* that added a naive `delete`-on-expiry sweeper.

What is sustained: no explicit semantic rule protects epoch state from
request-lifetime cleanup, and **the obvious remedy for SD-9b — `delete` the
expired request — would create a refund defect.** Assurance must prevent that
remediation regression: `M-K9-expiry-refunds-budget` in
`W2_IMPLEMENTATION_CONTRACT.md`. Lane W's original "state ownership" diagnosis
overstated this as a placement defect; Lane W1.2 narrowed it.

### SD-9b — expired request retains stale authority / blocking effect — **PRESENT IMPLEMENTATION DEFECT**

`recovery.active` is never cleared on expiry (`expiresAt` is read only by
`executeRecovery`'s guard). `bindMigration` (`:1306`) tests the raw flag, so a
dead request blocks migration until a **principal** acts — violating
`I-RECOVERY-TERMINATION`'s *"expiry requires no principal to act"* (`:948`).
Measured: `Sd4LaneV` "C the five proofs".

### SD-9c — guardian-quorum cancellation absent — **PRESENT IMPLEMENTATION DEFECT (K-9 CONFORMANCE)**

`K9_GUARDIAN_CANCEL_CONFORMANCE = MISSING_IN_PROTOTYPE`. See the
`KERNEL_ADMISSION.md` correction and `docs/Vault_vNext_Recovery_Amendment.md` §1.

### SD-9d — direct overwrite substitutes for explicit termination — **PRESENT IMPLEMENTATION DEFECT**

`initiateRecovery` carries no guard against replacing an effectively-live
request. With mechanism B available in the architecture, overwrite provides no
capability the explicit lifecycle lacks; it collapses two authorised actions into
one, bypasses explicit termination, emits no terminal event, and leaves a
stale-authorisation surface (a cancel aimed at request *n* meets *n+1* in the
same slot). **`APPROVED_REQUEST_OVERWRITE = NONCONFORMANT_AND_REDUNDANT`** for
effectively-live requests. An **expired** request is no longer live and must not
block fresh initiation — that is not overwrite. Lane V's earlier
`AUTHORITY_GENUINELY_CONFLICTS` verdict is superseded (its load-bearing reason
was that overwrite was the quorum's only exit; the architecture provides one).

### SD-9e — recovery expiry equality boundary — **PRESENT IMPLEMENTATION DEFECT (ONE SECOND)**

`:1228` uses `> expiresAt` where the reference model uses `>=` for every expiry
and the kernel's own containment uses `>= containedUntil` (`:691`).
`PROTOTYPE_EXPIRY_OFF_BY_ONE = OFF_BY_ONE_CONFORMANCE_DEFECT`. Measured at
`expiresAt−1`, `expiresAt`, `expiresAt+1` with mined-timestamp assertions
(`Sd4LaneW1`).

### Cut impact, all five

None measured. These are conformance, liveness and authority-hygiene defects;
no compromise cut is lowered.

---

## SD-10 — `APPROVED_REQUEST_STRANDED_BY_GUARDIAN_ROTATION` — **PRESENT IMPLEMENTATION DEFECT, SEPARATE ROOT**

`setGuardians` is admitted while a quorum-approved request is live, and the
generation bump strands it permanently (`BadRoster` at maturity) while it
remains stored `active`. Violates `I-APPROVED-REQUEST-PRESERVATION` (`:951`, T1),
whose scope is verbatim *guardian-set replacement*. The reference model
**denies** the replacement (`VaultVNextArchitectureModel.test.ts:334`). Measured:
`Sd4LaneV` "D"; `Sd4LaneW12` history 9 observes it identically on both epoch
representations without absorbing it.

**Kept separate** because its causal mechanism — generation binding — is
distinct from SD-9's lifecycle ownership. Its remediation is not in the W2
contract and is not decided here.

---

## W2 STATUS (Lane W2I — local implementation diff for independent review; every classification above retained as written)

| Subfinding | Status on the W2 diff | Where |
|---|---|---|
| SD-9a `RECOVERY_CHALLENGE_EPOCH_LIFETIME_UNSPECIFIED` | **Hazard now GUARDED**: the epoch rule is stated at the struct field and at the `delete recovery` reset site in `VaultKernelPrototype.sol`; the refunding remediation is a permanent mutant (`M-K9-expiry-refunds-budget`, killed) and the oracle carries `G-CHALLENGE-EPOCH` | `test/W2RecoveryLifecycleMutations.test.ts`, `stateful/invariants.ts` |
| SD-9b expired request retains blocking effect | **REMEDIATED**: `bindMigration` and `initiateRecovery` consult `_recoveryIsLive()`; an expired request blocks nothing and needs no sweeper | `test/W2RecoveryLifecycle.test.ts` §B, §C |
| SD-9c guardian-quorum cancellation absent | **REMEDIATED**: `cancelRecoveryByQuorum` (K-9 mechanism B) | `test/W2RecoveryLifecycle.test.ts` §A, §E |
| SD-9d overwrite substitutes for termination | **REMEDIATED**: a live request is never overwritten (`BadState`, no nonce consumed); termination is explicit and observable on both principals' paths | `test/W2RecoveryLifecycle.test.ts` §C, §G |
| SD-9e expiry equality boundary | **REMEDIATED**: `>= expiresAt` in `executeRecovery`; `LIVE_WINDOW = [executableAt, expiresAt)` everywhere | `test/W2RecoveryLifecycle.test.ts` §B |
| SD-10 approved request stranded by guardian rotation | **NOT TOUCHED** — `setGuardians` is unchanged. **Blast radius recorded:** a stranded request is still effectively live, so under W2 it blocks re-initiation (`BadState`) and migration (`NoRecovery`) until expiry, where before W2 it could be overwritten directly; the NEW quorum clears it at once with `cancelRecoveryByQuorum` (the digest binds the current generation) and re-proposes. Two explicit acts where there was one silent overwrite; no clock touched | `test/W2RecoveryLifecycle.test.ts` §H |

The historical measurements of SD-9b/9d on the real kernel (`Sd4LaneV` C/A1/B2,
`Sd4LaneU` B1/F, `Sd4RedTeamRound2`, `Sd4LaneV2` test 1) are pinned to the
byte-exact pre-W2 source they measured (`test/fixtures/`), so they remain the
record of the defect; the remediated behaviour lives in the W2 suites.
