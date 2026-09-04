# W2 — implementation contract (frozen target; NO Solidity in this lane)

This is the contract a future W2 lane implements. It records **Candidate C**
from Lane W1.2 — co-located, semantically independent — and supersedes the
Candidate P assumptions in `SD4_LANE_W_SEMANTIC_FREEZE.md` §H and
`SD4_LANE_W1_BOUNDARY_CORRECTION.md` §7–§8, which remain as evidence.

## Storage-minimality correction (from Lane W1.2)

Withdrawn: *"the challenge counter must move out of `RecoveryRequest`"* and
`RECOVERY_GETTER_COMPATIBILITY = OPTION B`.

```text
RECOVERY_CHALLENGE_STORAGE_SEPARATION = NOT_REQUIRED
COLOCATED_EPOCH_EQUIVALENCE          = ESTABLISHED
RECOVERY_GETTER_COMPATIBILITY        = NO_CHANGE_REQUIRED
```

Why, from the kernel's four write sites to `recovery`:

- the credential challenge increments the field and clears only `active`
  (`:1206-1208`);
- initiation carries the count forward (`:1177`);
- `rotateCredential` does not reference `recovery` at all;
- effective expiry requires no delete;
- guardian cancellation can clear request authority without deleting epoch
  state;
- successful recovery's existing `delete recovery` (`:1240`) is exactly the
  adopted reset boundary.

Evidence: nine histories, two compiled kernels, deep equality on every
externally observable state at every step (`test/Sd4LaneW12.test.ts`). One
harness artifact was found and normalised — `deployWorld` seeds the original
credential from the world label, so an un-normalised cross-world comparison
reports a false witness on the signer field. **Co-location does not make the two
concepts semantically identical**; the field's *lifetime* is the epoch's, and
that must be stated at the field and at `:1240`.

## Frozen contract — fourteen items

| # | Item | Authority consequence | Storage Δ (forecast) | ABI / selectors (forecast) | Events (forecast) | Nonce / replay | Model | Oracle | Manifest | Mutation | Byte risk (FORECAST — unmeasured) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | preserve `challengesUsed` in existing `RecoveryRequest` storage | none | **none** | none | — | — | model keeps its own counter; behaviour equivalent | snapshot field 6 unchanged, meaning documented | — | initiation/rotation refund mutants | none |
| 2 | preserve public `recovery()` ABI/getter | none | none | **none** | — | — | — | positional consumers unchanged | — | — | none |
| 3 | add guardian-quorum cancellation | implements K-9 mechanism B | none | **+1 selector** `cancelRecoveryByQuorum(QuorumProof,uint256,uint64)` | `RecoveryCancelledByQuorum(uint32)` | consumes `DOMAIN_GUARDIAN`; digest binds `guardianGeneration` | new action | new action | K-9 → conformant | guardian-cancel-missing, -wrong-authority | +150–300 B |
| 4 | credential challenge and guardian cancellation distinct | principal separation | none | two selectors | two events | two domains | two actions | — | — | guardian-cancel-wrong-authority | — |
| 5 | effective liveness `active && now < expiresAt`, as an **internal** helper `_recoveryIsLive()` — Option E0 | none | none | **none** — no selector | — | — | adopt `<` | oracle derives it from the tuple it already reads | — | expiry-inclusive-off-by-one | ~30 B |
| 6 | `executeRecovery` rejects at `now >= expiresAt` | closes SD-9e | none | none | — | — | already `>=` | — | — | expiry-inclusive-off-by-one | ~5 B |
| 7 | effectively-live request cannot be overwritten | removes unenumerated exit (SD-9d) | none | none | — | — | model already denies | new denial | — | live-overwrite-allowed | ~15 B |
| 8 | expired request does not block fresh initiation | liveness | none | none | — | — | model already clears | — | — | expired-request-blocks-initiation | — |
| 9 | expired request does not block migration | closes SD-9b | none | none | — | — | — | — | — | expired-request-blocks-migration | ~10 B |
| 10 | expired request not challengeable / cancellable | zero cancellation-target authority | none | none | — | a refused challenge consumes nothing | — | — | — | expired-still-challengeable, -still-quorum-cancellable | ~20 B |
| 11 | cancel / expiry / re-init / rotation do not reset `challengesUsed` | keeps D1's bound a constant | none | none | — | — | invariant | invariant | — | four refund mutants | — |
| 12 | successful recovery resets the epoch via existing `delete recovery` | restores the defence per credential | none | none | — | — | **model must add reset** (owner decision adopted in the amendment) | invariant | epoch record | success-does-not-reset-budget | none |
| 13 | guardian cancellation uses `DOMAIN_GUARDIAN` nonce serialisation | replay excluded (amendment §5) | none | none | — | proof conditions 1–6 | — | — | — | guardian-cancel-nonce-replay | none |
| 14 | terminal observability distinguishes challenge from cancellation | observer sees every exit | none | none | two distinct events | — | — | — | — | — | small |

## Structural delta — **W2 DESIGN FORECAST**, not an observation

Nothing in this section is measured on a shipped artifact. The figures are
asserted on an **in-memory candidate** by `test/Sd4LaneW1PAbiDelta.test.ts`,
which establishes *candidate feasibility*; the final W2 artifact is what W2
measures.

```text
storage layout:            FORECAST UNCHANGED  (the only added declaration is a
                                                `bytes32 private constant`;
                                                constants occupy no storage)
existing recovery() ABI:   FORECAST UNCHANGED  (8-field tuple, same order/types —
                                                asserted identical on the candidate)
new external selectors:    FORECAST ONE —
                           cancelRecoveryByQuorum(...)   the K-9 mechanism
new events:                FORECAST ONE — RecoveryCancelledByQuorum(uint32)
liveness helper:           INTERNAL (`_recoveryIsLive()`), no selector — Option E0
```

**Option E0 adopted (Lane W1R): `EFFECTIVE_RECOVERY_PUBLIC_GETTER = NOT_REQUIRED`.**
Liveness is a pure function of two fields the existing `recovery()` getter
already exposes and the block a reader is in: `active && now < expiresAt`. No
on-chain consumer needs it external — an internal helper serves
`initiateRecovery`, both cancellations and `bindMigration` — and an observatory
derives it exactly as the stateful oracle already derives safe state from stored
fields (`stateful/invariants.ts:415`). The `effectiveSafeState()` precedent
(`VaultKernelPrototype.sol:679-683`) exists because a stored *enum* reads as a
state the kernel no longer holds; `active` and `expiresAt` are raw fields that
any reader must already combine. #179 requires truthful observability, not a
kernel getter (§15.2, and the Observatory holds no authority, `:840`). A public
view remains an *allowed* W2 choice — the E1 probe used for test observation
compiles at +2 selectors — but it is not the forecast.

**Historical mutants that must remain killed:** M27 (unbounded challenge), M5
(recovery replay), M43 (migration clock).

## Mutation contract — defined, not compiled

One semantic break per mutant. A setup revert is not a kill.

| Mutant | Breaks | Killed by |
|---|---|---|
| `M-K9-guardian-cancel-missing` | K-9 mechanism B absent | quorum-cancellation conformance property |
| `M-K9-guardian-cancel-wrong-authority` | principal separation | cancellation succeeds on a credential signature with no quorum |
| `M-K9-quorum-cancel-refunds-budget` | epoch persistence | `delete recovery` in the quorum cancel; W1.2 history 3 |
| `M-K9-expiry-refunds-budget` | epoch persistence across expiry | a `delete`-on-expiry sweep; W1.2 histories 2, 7 |
| `M-K9-rotation-refunds-budget` | epoch independence from generation | zero the field in `rotateCredential`; W1.2 history 4 |
| `M-K9-initiation-refunds-budget` | carry-forward | `challengesUsed: 0` at `:1177`; W1.2 histories 1–3 |
| `M-K9-success-does-not-reset-budget` | reset boundary | field-wise clear that keeps the count; W1.2 history 5 |
| `M-K9-challenge-limit-removed` | bounded veto | M27; exhaustion in every history |
| `M-K9-live-overwrite-allowed` | SD-9d | drop the `BadState` guard; snapshot `canInitiate` expects `BadState` while live |
| `M-K9-expired-request-blocks-migration` | SD-9b | `bindMigration` reads raw `active`; snapshot `canBindMigration` expects `OK` after expiry |
| `M-K9-expired-request-blocks-initiation` | replaceability | `initiateRecovery` reads raw `active`; W1 E0/E+1 |
| `M-K9-expired-request-still-challengeable` | zero cancellation-target authority | challenge reads raw `active`; W1 E0 expects `NoRecovery` and no epoch consumed |
| `M-K9-expired-request-still-quorum-cancellable` | same, mechanism B | quorum cancel reads raw `active`; W1 E0 |
| `M-K9-expiry-inclusive-off-by-one` | SD-9e | `<=` in `effectiveLive` / `>` in execute; W1 E0 expects expired *at* `expiresAt` |
| `M-K9-guardian-cancel-nonce-replay` | amendment §5 | drop `_consume` from the quorum cancel; W1.2 "after R2" expects `BadNonce` |
