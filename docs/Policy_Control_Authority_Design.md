# Policy-Control Authority — Design

> **RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH REAL FUNDS.**

> **STATUS: DESIGN ONLY. NO CONTRACT CHANGES.** This document is for review before any
> Solidity is written. Every code shape below is a proposal, not an implementation, and
> the open questions in §12 are expected to change it.
>
> Base commit: `4e685be` (main, after #172 `v0.12.0`).

## 1. The seam

`DailySpendLimitPolicy` now enforces an exact rolling 24-hour cap (#172). That cap is
still only a **damage limiter**, not a containment boundary, because the credential it
constrains can remove it.

Two facts on `main`, both verified rather than assumed:

```solidity
// contracts/policies/DailySpendLimitPolicy.sol:363 — setDailyLimit
bytes32 key = _subjectKey(consumer, msg.sender, asset);   // msg.sender IS the owner slot

// contracts/WalletWallVault.sol:486-489 — executeRecovery
VaultOwner storage vault = vaults[vaultOwner];   // indexed by vaultOwner, which never moves
vault.ecdsaSigner  = recoveredSigner;            // only the CREDENTIALS rotate
vault.pqPublicKey  = recoveredPQPublicKey;
```

`limit == 0` means unrestricted and is currently an immediately available escape hatch,
deliberately exempt from the anti-lockout guard at line 349.

These produce two **opposite** failures from the same root cause — configuration
authority is bound to a *credential-bearing address* rather than to a lifecycle:

| Failure | Mechanism | Consequence |
|---|---|---|
| **Compromise** | Attacker holding the `vaultOwner` key calls `setDailyLimit(consumer, asset, 0)` | The damage limiter is removed in one transaction, before any guardian can react |
| **Recovery** | `executeRecovery` rotates `ecdsaSigner` / `pqPublicKey` but not the `vaultOwner` mapping key | Recovered credentials can spend but **cannot configure**; the compromised address retains policy control *permanently*, since no further rotation is coming |

The second is the more surprising one and the reason a delay alone is insufficient. Adding
a two-day timelock to `setDailyLimit` would slow the attacker down and leave the legitimate
recovered tenant with **no** path to policy control at all.

## 2. Target property

> A credential capable of spending must not be able to instantly weaken the restriction
> limiting that spending, while successful recovery must deterministically transfer
> legitimate policy-control capability to the recovered credentials.

### 2.1 Locked design points

These are settled inputs to the design, not open questions.

| # | Point |
|---|---|
| **L1** | Limit strength is an explicit **order**, not a numeric comparison. `0` is maximally permissive. `0→n` and `n→smaller` are immediate strengthening; `n→larger` and `n→0` are delayed weakening. |
| **L2** | A **monotonic policy-control epoch owned by the vault**, bumped on both `rotateCredentials` and `executeRecovery`. Weakening proposals bind the epoch and become invalid when credential authority changes. **No policy callbacks during recovery.** |
| **L3** | `PolicySubject.owner` remains the stable accounting identity. The rotating signer is **never** substituted for it. |
| **L4** | Direct / non-vault consumers are modelled explicitly. They are **not** silently made dependent on a WalletWall vault bridge. |
| **L5** | Recovery from admission lockout is preserved. Limit weakening and admitter/liveness repair are **separate** actions, not forced through one delay. |
| **L6** | Any vault bridge authenticates the tenant's **current credentials** and never inherits `WalletWallVault`'s contract-admin (`onlyOwner`) authority. |
| **L7** | Pending weakening proposals have exact semantics across policy-engine replacement. **Default: no migration** — authority is re-established deliberately. |
| **L8** | Queued withdrawals are tested against both strengthening and pending/applied weakening. The queue-time engine floor must not turn a policy-control proposal into retroactive admission authority. |

## 3. Limit strength as an order (L1)

The bug in any numeric framing is that `0` is not the bottom of the range — it is the
**top of the permissiveness lattice**:

```
        0  (unrestricted)          ← most permissive
        ↑
     large
        ↑
     small                          ← most restrictive
```

Define `permits(a) ⊒ permits(b)` as "configuration `a` admits at least everything `b`
admits". Then:

| Transition | Numeric reading | Correct classification | Timing |
|---|---|---|---|
| `0 → n` | "increase" | **STRENGTHENING** — arming protection where none existed | Immediate |
| `n → m`, `m < n` | decrease | STRENGTHENING | Immediate |
| `n → m`, `m > n` | increase | WEAKENING | Delayed |
| `n → 0` | "decrease" | **WEAKENING** — maximal, removes the cap entirely | Delayed |
| `0 → 0`, `n → n` | — | no-op | Rejected as no-op |

Both extremes invert under a numeric rule, which is why the implementation must compute a
single predicate:

```
isWeakening(old, new) :=  (new == 0 && old != 0)          // disarming
                       || (old != 0 && new != 0 && new > old)
```

and must **not** be expressed as `new > old`.

> **Note for review.** `0 → n` being immediate is what lets a tenant arm protection the
> moment they suspect something, with no waiting period. That is a security-positive
> property and the main reason the order matters rather than being pedantry.

## 4. Trust table

Principals, and what each may do to an armed subject under the proposed design.

| Principal | Spend | Strengthen | Propose weakening | Apply weakening | Repair admitters |
|---|---|---|---|---|---|
| **Tenant, current credentials** (via bridge) | ✔ | ✔ immediate | ✔ | ✔ after delay, same epoch | ✔ immediate |
| **Tenant, stale credentials** (pre-rotation) | ✘ (nonce/sig) | ✘ | ✘ | ✘ epoch mismatch | ✘ |
| **`vaultOwner` address key**, no controller set | ✘¹ | ✔ immediate | ✔ | ✔ after delay | ✔ immediate |
| **`vaultOwner` address key**, controller set | ✘¹ | ✘ | ✘ | ✘ | ✘ |
| **Vault contract admin** (`onlyOwner`) | ✘ | ✘ | ✘ | ✘ | ✘ |
| **Guardian minority** | ✘ | ✘ | ✘ | ✘ | ✘ |
| **Guardian majority** | ✔² | ✔² | ✔² | ✔² | ✔² |
| **Delegated admitter** (composite/vault) | books only | ✘ | ✘ | ✘ | ✘ |
| **Arbitrary caller** | ✘ | ✘ | ✘ | ✘ | ✘ |

¹ The `vaultOwner` address is not itself a spending credential — withdrawal requires the
EIP-712 signature of `vault.ecdsaSigner` (+ PQ). In the common deployment they are the same
key, which is precisely the conflation this design separates.

² A guardian majority can already recover the vault and rotate credentials to itself, so it
can reach any state a legitimate tenant can. This is not a new power; it is the existing
trust assumption of social recovery and must be stated, not engineered around.

**L6 restated as an invariant to test:** no row for the vault contract admin has a ✔.
`proposePolicyEngine` / `applyPolicyEngine` must confer nothing over tenant limits.

## 5. Proposed state machine and API

### 5.1 Two authorization paths

```
Path 1  OWNER-DIRECT     msg.sender == subject.owner
Path 2  CONTROLLER       msg.sender == subject.controller   (controller != 0)
```

**When a controller is set, Path 1 is disabled entirely** — not merely for weakening.

That "entirely" is deliberate and is the answer to a liveness attack described in §8.3: if
Path 1 retained *strengthening*, a compromised `vaultOwner` key could instantly set the
limit to 1 wei and freeze the tenant's withdrawals for the full weakening delay. Disabling
Path 1 outright once a controller exists removes that.

Setting **or clearing** the controller is itself a weakening action (delayed, epoch-bound).
Otherwise an attacker would simply clear the controller to re-enable Path 1.

### 5.2 Per-subject state added to `SpendState`

```solidity
struct PendingWeakening {
    uint256 newLimit;      // proposed configuration
    uint64  validAfter;    // propose + DELAY
    uint64  expiresAt;     // validAfter + GRACE   (bounded; see §8.2)
    uint64  boundEpoch;    // vault policy-control epoch at propose time
}

// added to SpendState
address          controller;   // 0 = Path 1 only
PendingWeakening pending;
```

### 5.3 Vault-side additions

```solidity
mapping(address => uint64) public policyControlEpoch;   // keyed by vaultOwner (L3: not by signer)
// ++ in executeRecovery
// ++ in rotateCredentials
// NOT touched by initiateRecovery, guardian support, withdrawals, or engine replacement
```

The epoch is keyed by `vaultOwner`, the same stable identity the accounting uses (L3).

### 5.4 Lifecycle

```
                    strengthen (immediate)
        ┌──────────────────────────────────────────┐
        │                                          ▼
   ┌─────────┐  proposeWeakening   ┌─────────┐  block.timestamp >= validAfter   ┌────────┐
   │  IDLE   │────────────────────▶│ PENDING │─────────────────────────────────▶│ MATURE │
   └─────────┘                     └─────────┘                                  └────────┘
        ▲                            │     │                                      │    │
        │  cancelWeakening           │     │ epoch changed                        │    │ applyWeakening
        └────────────────────────────┘     │ (recovery / rotation)                │    ▼
        │                                  ▼                                      │  IDLE
        │                              ┌──────┐                                   │
        └──────────────────────────────│ DEAD │◀──────────────────────────────────┘
                       (implicit)      └──────┘        block.timestamp >= expiresAt
```

`DEAD` is **implicit** — nothing is written when a proposal dies. `applyWeakening`
re-derives liveness from `(boundEpoch, validAfter, expiresAt)` and refuses. This is what
makes L2's "no policy callbacks during recovery" achievable: recovery invalidates by
changing a number the proposal already bound, not by reaching into the policy.

### 5.5 Why an epoch rather than a callback

A `revoke`-style hook on `IPolicyEngine` was considered and **rejected**:

- `executeRecovery` today calls **no** policy contract at all. A revoke hook would newly
  couple recovery liveness to policy-module behaviour.
- Under `CompositePolicyEngine` the vault sees one engine but there are N modules, so the
  hook must fan out. Fan-out over attacker-influenced module lists is unbounded work.
- **Any module that reverts would brick `executeRecovery`.** Recovery must never be
  brickable; a fail-closed recovery is a permanently lost vault.

The epoch achieves atomic invalidation with a single storage write, no fan-out, no revert
surface, and composes to any number of modules for free.

## 6. Transition matrix

`E` = epoch unchanged since propose. `E'` = epoch bumped. `C` = controller set.

| # | Action | Caller | Precondition | Result |
|---|---|---|---|---|
| T1 | strengthen | controller | `C` | applied immediately |
| T2 | strengthen | owner | `!C` | applied immediately |
| T3 | strengthen | owner | `C` | **revert** `ControllerPathRequired` |
| T4 | proposeWeakening | controller | `C`, no pending | `PENDING`, binds epoch |
| T5 | proposeWeakening | owner | `C` | **revert** `ControllerPathRequired` |
| T6 | proposeWeakening | any authorized | pending exists | **revert** `WeakeningAlreadyPending` |
| T7 | applyWeakening | authorized | `MATURE`, `E` | applied; `pending` cleared |
| T8 | applyWeakening | authorized | `MATURE`, `E'` | **revert** `StaleControlEpoch` |
| T9 | applyWeakening | authorized | `PENDING` (immature) | **revert** `WeakeningNotReady` |
| T10 | applyWeakening | authorized | past `expiresAt` | **revert** `WeakeningExpired` |
| T11 | cancelWeakening | authorized | pending exists | cleared; no delay (cancelling is strengthening-ward) |
| T12 | setController | authorized | — | **weakening**: delayed + epoch-bound |
| T13 | setAdmitter(add) | authorized | — | immediate (L5; see §7.6) |
| T14 | setAdmitter(remove) | authorized | not last-while-armed | immediate (existing guard retained) |
| T15 | any config | vault admin | — | **revert** — admin is not a principal here (L6) |

**T11 is deliberate**: cancelling a pending weakening moves *toward* restriction, so by L1's
order it needs no delay. This also gives a recovered tenant an immediate way to kill an
attacker's in-flight proposal without waiting for the epoch to do it.

## 7. Adversarial scenarios (executable)

These are written as executable specifications, not prose. Each becomes a test in
`test/PolicyControlAuthority.test.ts`.

### 7.1 Signer/credential rotation with pending weakening

```
GIVEN  subject (vault, alice, ETH) armed at limit = 1 ETH, controller = vault
  AND  a weakening proposal (1 ETH → 0) made at T0, validAfter = T0 + DELAY
WHEN   alice calls rotateCredentials(newSigner, newPQKey) at T0 + 1h
  AND  anyone calls applyWeakening at T0 + DELAY
THEN   revert StaleControlEpoch
  AND  dailyLimit is still 1 ETH
  AND  a NEW proposal made with the new credentials matures normally
```

**Control (must also pass):** rotation with **no** pending weakening changes no policy
state at all — `dailyLimit`, `rollingSpent`, `activeEntryCount`, `controller` all identical
before and after. Without this control, a test suite cannot distinguish "rotation kills
proposals" from "rotation clobbers policy state".

### 7.2 Guardian recovery with pending weakening

```
GIVEN  subject armed at 1 ETH, controller = vault
  AND  ATTACKER holds the compromised credentials
  AND  attacker has a pending weakening (1 ETH → 0) that matures at T0 + DELAY
WHEN   guardians reach majority and executeRecovery succeeds at T0 + 1h
THEN   policyControlEpoch[alice] has incremented
  AND  attacker's applyWeakening at T0 + DELAY reverts StaleControlEpoch
  AND  executeRecovery made NO call to any policy contract   ← assert via call trace / gas
  AND  the recovered credentials can propose and apply their own weakening
```

**The `NO call to any policy contract` assertion is the important one.** It is what pins
L2 mechanically rather than by inspection.

### 7.3 Recovery INITIATION must not invalidate legitimate control

```
GIVEN  subject armed, controller = vault, LEGITIMATE pending weakening
WHEN   a single malicious guardian calls initiateRecovery
  AND  the recovery never reaches majority
THEN   policyControlEpoch is UNCHANGED
  AND  the legitimate weakening still applies at validAfter
```

Rationale: a malicious guardian must not be able to DoS policy administration merely by
opening a request. Only *successful* recovery bumps the epoch.

**Known and accepted:** a guardian *majority* can repeatedly recover and so repeatedly kill
proposals. That majority can already rotate credentials to itself and drain the vault, so
this is not a new power (§4, note 2).

### 7.4 Policy-engine replacement, before and after maturity (L7)

Four distinct cases, because "the engine" and "the policy module holding the proposal" are
not the same object:

```
GIVEN  a pending weakening in policy instance P

CASE A  vault swaps engine P → P2 (a DIFFERENT DailySpendLimitPolicy instance)
THEN    P2 has no limit, no controller, no proposal — authority is re-established
        deliberately (L7 default: NO migration)
  AND   P's proposal is untouched, and remains applicable to P — which now governs nothing
  AND   the tenant is NOT silently left believing P2 is armed        ← assert dailyLimit(P2) == 0

CASE B  vault swaps engine P → composite C, where C wraps the SAME instance P
THEN    the proposal SURVIVES: it lives in P, keyed by subject, and the engine wiring
        did not change the subject
  AND   applyWeakening still works, same epoch

CASE C  swap occurs BEFORE validAfter
THEN    identical to A/B — engine wiring is not an input to proposal maturity

CASE D  swap occurs AFTER maturity but before apply
THEN    identical — maturity is a function of (validAfter, expiresAt, epoch) only
```

**Invariant across all four:** engine replacement never mutates `policyControlEpoch`, and
never causes a proposal to become applicable that was not already applicable.

### 7.5 Queued withdrawal across tightening/weakening transitions (L8)

```
GIVEN  subject armed at 1 ETH, large-tx threshold 0.2 ETH, delay D < WINDOW
  AND  a withdrawal of 0.9 ETH queued at Tq (admission booked once, per #172 F1)

CASE A  STRENGTHENING mid-queue: limit lowered to 0.1 ETH at Tq + 1
THEN    finalizeWithdrawal still succeeds — revalidate() is pure and books nothing
  AND   rollingSpent is unchanged (0.9 ETH), activeEntryCount == 1
  AND   the queued withdrawal is NOT retroactively stranded

CASE B  PENDING weakening mid-queue
THEN    finalization is completely unaffected — a PROPOSAL is not a configuration
  AND   assert the queue-time engine floor (policyEngineAtQueue) does not consult
        `pending` at all                                    ← this is the L8 trap

CASE C  weakening APPLIED mid-queue (1 ETH → 2 ETH)
THEN    finalization unaffected; rollingSpent unchanged
  AND   remainingAllowance increases by exactly 1 ETH — the ledger is not rewritten
```

**The L8 trap, stated precisely:** `finalizeWithdrawal` revalidates against *both* the
queue-time engine and the current engine. If `applyWeakening` were ever reachable through
a `revalidate` path, a policy-control proposal would become retroactive admission
authority. `revalidate` is `pure` in `DailySpendLimitPolicy` today, and this design must
keep it that way — assert it, do not assume it.

### 7.6 Admitter loss / misconfiguration while armed (L5)

The existing guards depend on instant disarm as their escape hatch:

```solidity
if (limit != 0 && s.admitterCount == 0) revert NoAdmitterConfigured(...);   // arming
if (!allowed && s.admitterCount == 1 && s.limit != 0) revert LastAdmitterWhileArmed(...);
```

Delaying disarm would delay that escape. L5 resolves this by **separating the two axes**:

```
GIVEN  subject armed at 1 ETH, its only admitter is a composite whose owner has
       added an always-denying module (an unescapable DENIAL power per #171)
WHEN   the tenant adds a second, direct admitter
THEN   the add is IMMEDIATE — it is a liveness repair, not a weakening
  AND  withdrawals resume through the new admitter without waiting DELAY
```

Justification that adding an admitter is not a weakening: it does not raise the cap. A new
admitter can consume allowance the existing admitter could already consume, so under
compromise it confers no capability the attacker lacks. **Strength is a property of the
limit; authority is a property of the admitter set.** Conflating them is what forces both
through one delay.

```
CONTROL  removing the last admitter while armed still reverts LastAdmitterWhileArmed
  AND    arming with zero admitters still reverts NoAdmitterConfigured
```

### 7.7 Direct policy users with no WalletWall bridge (L4)

```
GIVEN  a subject whose consumer is NOT a bridge-implementing vault
  AND  controller == 0

THEN   Path 1 remains available: msg.sender == owner
  AND  strengthening is immediate
  AND  weakening is STILL delayed (propose → delay → apply → grace)
  AND  there is NO epoch to bind — the consumer has no credential lifecycle
  AND  applyWeakening therefore checks only (validAfter, expiresAt)
```

**This must be explicit in the API, not emergent.** A direct user gets the timelock but not
epoch-based revocation, because there is no rotation event to derive one from. That is an
honest degradation and must be documented as such — the alternative (silently requiring a
bridge) would permanently brick every already-armed direct subject, including its ability to
disarm.

```
REGRESSION  an existing directly-configured armed subject on main can still reach
            limit == 0 after this change (via propose → delay → apply).
            It must NEVER become permanently unmanageable.
```

### 7.8 Compromised credential proposes weakening immediately before recovery

The case that motivates the whole epoch design:

```
GIVEN  attacker has compromised credentials; subject armed at 1 ETH; controller = vault
WHEN   attacker calls proposeWeakening(1 ETH → 0) at T0
  AND  guardians begin recovery at T0 + 1 minute
  AND  executeRecovery succeeds at T0 + 2 days (< validAfter, or > validAfter — test BOTH)
THEN   in both orderings, applyWeakening reverts StaleControlEpoch
  AND  recovery did not need to know the proposal existed
  AND  no enumeration of pending proposals occurred anywhere in the recovery path
```

**Both orderings matter.** If recovery completes *after* maturity, the proposal is in
`MATURE` state and the epoch check is the only thing standing between the attacker and the
disarm. That is the case most likely to be got wrong by an implementation that checks the
epoch at propose time only.

## 8. Failure and liveness analysis

### 8.1 What this closes

Instant removal of the cap by a compromised credential, and the permanent orphaning of
policy control after recovery. Both are the target property in §2.

### 8.2 Grace window is mandatory

A matured proposal that never expires defeats its own timelock: an attacker pre-arms a
weakening at a quiet moment, and at the moment of use the friction is zero. `expiresAt`
must be bounded and non-optional. This mirrors the module-removal expiry already shipped in
the composite engine (#163/#164).

### 8.3 Accepted residual: the freeze DoS

Whoever can strengthen instantly can freeze the tenant's withdrawals instantly (set the
limit to 1 wei), and un-freezing is weakening, therefore delayed.

This is **intrinsic to L1**, not a flaw in the mechanism: any design where protection can
be armed immediately grants the same power to whoever holds that ability. The alternatives
are worse — delaying strengthening would delay protection.

Mitigation is by *scoping who can do it*: once a controller is set, only the controller can
strengthen, so a compromised `vaultOwner` address alone cannot freeze. A compromised
*signer* can, for the duration of the weakening delay, and that is exactly the window
recovery exists to close.

**Classification: denial, never loss.** It must be documented in
`docs/Security_Assumptions.md` and pinned by a test that asserts funds remain withdrawable
after the delay elapses.

### 8.4 Recovery liveness is preserved by construction

No path in `executeRecovery` calls a policy contract; the epoch increment is a local
storage write that cannot revert on external behaviour. **A test must assert this
mechanically** (§7.2), because it is the property most likely to be silently lost by a
later "just add a hook" change.

### 8.5 Bootstrap ordering

Setting a controller is a weakening action (T12), so the *first* controller cannot be set
instantly. For a subject that has never been armed (`limit == 0`), there is nothing to
weaken — **open question O3 in §12**: whether `setController` on an unarmed subject should
be immediate. Getting this wrong makes the feature unusable for new tenants.

## 9. Storage and gas implications

### 9.1 Policy storage per subject

| Field | Type | Notes |
|---|---|---|
| `controller` | `address` | 160 bits |
| `pending.validAfter` | `uint64` | packs with controller (160 + 64 + 32 spare) |
| `pending.expiresAt` | `uint64` | |
| `pending.boundEpoch` | `uint64` | |
| `pending.newLimit` | `uint256` | own slot — cannot be narrowed; `type(uint256).max` must stay settable (pinned by `DailySpendAdmissionAuthority` B5) |

Roughly **+2 slots per subject**, and only for subjects that actually use the feature —
a subject with no controller and no pending proposal writes neither.

Admission cost (`check`) must be **unchanged**: none of these fields are on the hot path.
This is a hard requirement to measure, given #172 already added ~30.5k gas to a steady-state
armed withdrawal.

### 9.2 EIP-170 — the binding constraint this time

| Contract | Runtime | Headroom |
|---|---|---|
| `WalletWallVault` | 22,851 | **1,725** |
| `StablecoinVaultSimulator` | 22,485 | **2,091** |
| `DailySpendLimitPolicy` | 3,907 | 20,669 |

Unlike #172 — where the vaults were byte-identical — this design **must** modify both
vaults, because only they can bump the epoch on `rotateCredentials` / `executeRecovery`.

**Therefore the bridge must not live in the vault.** `getVault(address)` already returns
the full `VaultOwner` struct including `ecdsaSigner` and `pqPublicKey`, so an external
`PolicyControlBridge` contract can:

1. read the tenant's **current** credentials from the vault,
2. verify an EIP-712 configuration intent against them,
3. call the policy as the registered `controller`.

The vault then grows by only a mapping, two increments, and a getter — an estimate to be
**measured at the first compiling implementation, not at the end** (the #172 discipline).

**STOP CONDITION:** if either vault crosses the gate or lands in dangerously small headroom,
redesign — do not weaken the gate.

An external bridge also satisfies L6 structurally: a separate contract has no access to
`WalletWallVault`'s `onlyOwner` role, so admin authority cannot leak into policy control
even by mistake.

## 10. Migration and backward compatibility

### 10.1 Already-deployed vaults have no epoch

Vaults deployed before this change cannot bump a counter that does not exist in their
bytecode, and they are not upgradeable. Two options:

| Option | Mechanism | Trade-off |
|---|---|---|
| **E1 — explicit counter** (the locked choice, L2) | `mapping(address => uint64) policyControlEpoch`, bumped in `rotateCredentials` / `executeRecovery` | Monotonic and cheap to read; requires new vault bytecode, so it applies only to newly deployed vaults |
| **E2 — credential fingerprint** | `keccak256(abi.encode(vault.ecdsaSigner, vault.pqPublicKey))` read via the existing `getVault` | Works against **already-deployed** vaults with zero vault changes; but **not monotonic** — rotating back to a previous credential pair revives a stale proposal — and reading it copies a ~1,952-byte PQ key |

Recommendation for review: **E1 as the design, E2 as a documented adapter** for
already-deployed vaults, with its non-monotonicity stated as a known weakness rather than
smoothed over. Rotating *back* to a compromised key is already catastrophic, but "already
catastrophic" is a reason to document, not to omit.

### 10.2 Existing armed subjects

`policyEngineAddress` is `null` in every deployment manifest, so there are no on-chain
armed subjects to migrate today. The compatibility story is therefore about **API**
consumers, not state:

- `setDailyLimit(consumer, asset, 0)` changes from immediate to delayed. **Breaking.**
- `setDailyLimit` with a *lower* nonzero value keeps working unchanged.
- Any integrator relying on instant disarm must move to propose/apply.

Semver: another breaking minor on the `0.x` line (`0.12.0 → 0.13.0`), by the same reasoning
as #172.

### 10.3 No proposal migration (L7)

Proposals do not migrate across policy instances. A tenant switching to a new policy
instance re-establishes controller and limit deliberately. §7.4 CASE A asserts the tenant
is not left believing the new instance is armed.

## 11. Adversarial test plan

`test/PolicyControlAuthority.test.ts`, mirroring #172's structure.

| Group | Cases |
|---|---|
| **A — strength order** | all five §3 transitions; `0→n` immediate; `n→0` delayed; no-op rejected; the `new > old` mutant must be killed |
| **B — epoch binding** | apply at same epoch; after `rotateCredentials`; after `executeRecovery`; after both; apply before vs after maturity with an intervening bump (§7.8) |
| **C — recovery liveness** | `executeRecovery` makes no policy call; recovery succeeds with a reverting policy module installed; `initiateRecovery` does not bump (§7.3) |
| **D — path exclusivity** | Path 1 disabled once controller set (T3/T5); clearing controller is delayed (T12); vault admin has no path (T15) |
| **E — engine replacement** | §7.4 CASES A–D |
| **F — queued withdrawals** | §7.5 CASES A–C; `revalidate` is still `pure`; queue-time floor never reads `pending` |
| **G — lockout repair** | §7.6 plus both existing-guard controls |
| **H — direct users** | §7.7 including the regression that an existing armed direct subject can still reach `limit == 0` |
| **I — grace window** | apply at `validAfter`; at `expiresAt - 1`; at `expiresAt` (reverts); pre-arm-then-wait defeats nothing |

**Mutation discrimination is required, not optional.** Every group above must kill a
targeted mutant, on the #172 lesson that a test written after the implementation and
passing immediately has demonstrated nothing. Minimum mutants:

1. `isWeakening` replaced by `new > old` — must be killed by A.
2. Epoch checked at propose time only, not at apply — must be killed by B (§7.8 ordering).
3. `initiateRecovery` also bumps the epoch — must be killed by C.
4. Path 1 left enabled for strengthening when a controller is set — must be killed by D.
5. `expiresAt` check removed — must be killed by I.
6. `setAdmitter(add)` routed through the weakening delay — must be killed by G.

## 12. Open questions for review

| # | Question | Why it changes the design |
|---|---|---|
| **O1** | Should `DELAY` match the vault's existing 2-day governance delay, or be tenant-configurable? Tenant-configurable means *lowering the delay is itself a weakening*, which is recursive but tractable. | Determines whether the timelock is a constant or another ordered field |
| **O2** | Is `cancelWeakening` (T11) available to Path 1 even when a controller is set? Arguing yes: cancelling is strengthening-ward and gives a locked-out tenant an emergency brake. Arguing no: it is an authority split. | Affects whether a compromised owner key retains *any* capability |
| **O3** | Should `setController` be immediate on a subject that has never been armed (`limit == 0`)? Otherwise bootstrap requires a delay before protection can even be configured (§8.5). | Makes the feature usable or unusable for new tenants |
| **O4** | Do `StablecoinVaultSimulator` and `WalletWallVault` share one bridge, or one each? Shared means the bridge must key by `(consumer, owner)` and re-derive credentials per consumer. | Bytecode and trust-surface implications |
| **O5** | E1 only, or E1 + the E2 adapter (§10.1)? | Decides whether already-deployed vaults are in scope at all |

---

**Next step after review:** settle O1–O5, then implement in the order
`epoch → bridge → policy state machine → tests`, measuring both vaults' bytecode at the
first compiling implementation rather than at the end.
