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
flag where the architecture and reference model specify two lifecycles (the
request; the challenge epoch), three enumerated exits, and wall-clock liveness.
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
