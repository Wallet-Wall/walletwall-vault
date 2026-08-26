# Policy-Control Authority — Design

> **RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH REAL FUNDS.**

> **STATUS: IMPLEMENTATION CONTRACT — DESIGN ONLY, NO CONTRACT CHANGES.** Revision 4.
> L1–L11 locked (§2.1); O1–O5 settled (§12); U1 resolved (§6.3); U2 and U3 resolved (§15).
> **No open design questions remain.** The `v0.13.0` Solidity lane implements this document.
>
> Base commit: `4e685be` (main, after #172 `v0.12.0`).

**Two rules carry this design:**

> *The epoch solves stale authority; it does not by itself prove who the new authority is.*

Revision 1 closed only the first half, which let an attacker-installed controller survive
recovery and recreate the orphaning defect (§6).

> *Emergency response may freeze authority; it may never relax authority.*

Revision 3 adds the bridge circuit breaker under that constraint (§6.3), which is why it is
a one-way pause and not an emergency unenrol.

## 1. The seam

`DailySpendLimitPolicy` now enforces an exact rolling 24-hour cap (#172). That cap is still
only a **damage limiter**, not a containment boundary, because the credential it constrains
can remove it.

Two facts on `main`, verified rather than assumed:

```solidity
// contracts/policies/DailySpendLimitPolicy.sol:363 — setDailyLimit
bytes32 key = _subjectKey(consumer, msg.sender, asset);   // msg.sender IS the owner slot

// contracts/WalletWallVault.sol:486-489 — executeRecovery
VaultOwner storage vault = vaults[vaultOwner];   // indexed by vaultOwner, which never moves
vault.ecdsaSigner  = recoveredSigner;            // only the CREDENTIALS rotate
vault.pqPublicKey  = recoveredPQPublicKey;
```

One root cause — configuration authority bound to a *credential-bearing address* rather
than to a lifecycle — produces two **opposite** failures:

| Failure | Mechanism | Consequence |
|---|---|---|
| **Compromise** | Attacker holding the `vaultOwner` key calls `setDailyLimit(consumer, asset, 0)` | The damage limiter is removed in one transaction, before any guardian can react |
| **Recovery** | `executeRecovery` rotates credentials but not the `vaultOwner` mapping key | Recovered credentials can spend but **cannot configure** — permanently, since no further rotation is coming |

A timelock alone fixes the first and makes the second worse.

## 2. Target property

> A credential capable of spending must not be able to instantly weaken the restriction
> limiting that spending, while successful recovery must deterministically transfer
> legitimate policy-control capability to the recovered credentials.

### 2.1 Locked design points

Settled inputs, not open questions.

| # | Point |
|---|---|
| **L1** | Limit strength is an explicit **order**, not a numeric comparison. `0` is maximally permissive. `0→n` and `n→smaller` are immediate strengthening; `n→larger` and `n→0` are delayed weakening. |
| **L2** | A **monotonic policy-control epoch owned by the vault**, bumped on both `rotateCredentials` and `executeRecovery`. Weakening proposals and signed bridge intents both bind it. **No policy callbacks during recovery.** |
| **L3** | `PolicySubject.owner` remains the stable accounting identity. The rotating signer is **never** substituted for it. |
| **L4** | Direct / non-vault consumers are modelled explicitly and keep Path 1. They are **not** silently made dependent on a bridge, and do **not** receive the stronger containment guarantee. |
| **L5** | Recovery from admission lockout is preserved. Limit weakening and admitter/liveness repair are **separate** actions. |
| **L6** | **(REVISED — see §7)** The vault admin receives no **new or direct** policy-control authority from the bridge. Bridge authentication inherits **exactly** the vault's existing credential-verifier trust assumptions and no more. |
| **L7** | Pending weakening proposals have exact semantics across policy-engine replacement. **Default: no migration.** |
| **L8** | Queued withdrawals are tested against strengthening and pending/applied weakening. The queue-time engine floor must not turn a policy-control proposal into retroactive admission authority. |
| **L9** | **(NEW — see §6)** A WalletWall subject may enter controller mode **only** with a controller whose authentication semantics are bound to that consumer's current credential lifecycle. Arbitrary controller contracts are not valid containment controllers. |
| **L10** | **(NEW — see §5)** Every authenticated configuration intent is replay-bound by a **dedicated policy-control nonce**, independent of the withdrawal nonce. |
| **L11** | **(NEW — see §6.3)** Emergency response may **freeze** authority; it may never **relax** authority. The canonical bridge carries a one-way global pause, held by a dedicated immutable pauser, with no `unpause()` and no emergency unenrol. |

## 3. Limit strength as an order (L1)

`0` is not the bottom of the range — it is the **top of the permissiveness lattice**:

```
        0  (unrestricted)          ← most permissive
        ↑
     large
        ↑
     small                          ← most restrictive
```

| Transition | Numeric reading | Correct classification | Timing |
|---|---|---|---|
| `0 → n` | "increase" | **STRENGTHENING** — arming protection where none existed | Immediate |
| `n → m`, `m < n` | decrease | STRENGTHENING | Immediate |
| `n → m`, `m > n` | increase | WEAKENING | Delayed |
| `n → 0` | "decrease" | **WEAKENING** — maximal | Delayed |
| `0 → 0`, `n → n` | — | no-op | Rejected |

Both extremes invert under a numeric rule, so the implementation must compute:

```
isWeakening(old, new) :=  (new == 0 && old != 0)
                       || (old != 0 && new != 0 && new > old)
```

and must **not** be expressed as `new > old`.

## 4. State model

```
LEGACY / DIRECT SUBJECT        owner-direct (Path 1); timelocked weakening; NO epoch guarantee
        │
        │  (WalletWall consumer only)
        ▼
WALLETWALL SUBJECT, PRISTINE   controllerInitialized == false
        │
        │  enrolController(canonical bridge)  ── ONE-TIME, IMMEDIATE,
        │                                        SIGNED by current credentials (§15, U2)
        ▼
WALLETWALL SUBJECT, CONTROLLER-ACTIVE
        · only current tenant credentials, via the bridge, have configuration capability
        · the old vaultOwner address has NONE — including no cancellation (§12, O2)
        · controller removal/replacement: delayed, expiring, epoch-bound
```

**`PRISTINE` is an explicit one-time flag, not `limit == 0`.** Those are not equivalent: a
previously armed subject can be disarmed and return to zero. Gating first enrollment on
`limit == 0` would let an attacker re-enroll instantly after a disarm.

## 5. Bridge authentication and replay model (L10)

Revision 1 said the bridge would "verify an EIP-712 configuration intent" without defining
the message, nonce ownership, or replay boundary. That was the largest hole in the design.
Without it:

- a valid old **strengthening** intent (`setLimit(1 wei)`) could be replayed to freeze the
  tenant repeatedly;
- a signed **proposal** intent could be replayed after the proposal expired, minting a
  fresh proposal and resetting the clock.

### 5.1 Dedicated nonce

```solidity
// PolicyControlBridge
mapping(address consumer => mapping(address owner => uint256)) public controlNonce;
```

Keyed by `(consumer, vaultOwner)`, **never** the withdrawal nonce. Policy administration
must not invalidate signed withdrawals, and ordinary withdrawals must not invalidate a
policy-control transaction. The two authorities move on different clocks and coupling them
creates cross-domain griefing in both directions.

Nonces are **sequential**, not an unordered bitmap: policy-control actions are inherently
ordered (enroll → propose → apply), and reordering them would be a bug rather than a
feature. `deadline` bounds the liveness cost of an unsubmitted intent.

### 5.2 Signed intent

Every authenticated configuration intent binds, at minimum:

```
consumer · owner · policy · asset · action · value/target
         · policyControlEpoch · controlNonce · deadline
```

with `chainId` and the **bridge address** supplied by the EIP-712 domain separator.

**Proposal: one EIP-712 struct (and therefore one typehash) per action**, rather than a
single struct with a union `value/target` field:

```solidity
struct EnrollController { address consumer; address owner; address policy; address controller;
                          uint64 epoch; uint256 nonce; uint256 deadline; }
struct SetLimit         { address consumer; address owner; address policy; address asset;
                          uint256 newLimit; uint64 epoch; uint256 nonce; uint256 deadline; }
struct ProposeWeakening { address consumer; address owner; address policy; address asset;
                          uint256 newLimit; uint64 epoch; uint256 nonce; uint256 deadline; }
struct ApplyWeakening   { address consumer; address owner; address policy; address asset;
                          uint64 epoch; uint256 nonce; uint256 deadline; }
struct SetAdmitter      { address consumer; address owner; address policy; address asset;
                          address admitter; bool allowed;
                          uint64 epoch; uint256 nonce; uint256 deadline; }
```

Distinct typehashes make **cross-action confusion structurally impossible** rather than
merely checked: the same signed bytes cannot be reinterpreted as a different action,
because the typehash is part of the digest. A union field would put that safety on an
`action` discriminator the implementation has to remember to validate.

### 5.3 Two clocks, deliberately distinct

`deadline` bounds **submission of the intent**. `validAfter` / `expiresAt` bound
**maturity of the resulting proposal**. They must never be conflated: a short intent
deadline does not shorten the timelock, and a matured proposal does not extend an expired
intent.

### 5.4 Epoch appears twice, on purpose

The signed intent binds the epoch *and* the stored proposal binds the epoch. This is
deliberate redundancy: the first kills a signature that predates a rotation, the second
kills a proposal whose authority changed after it was stored. Either alone leaves a gap.

### 5.5 `applyWeakening` requires a fresh intent

Applying a matured weakening requires its own signed intent bound to the **current** epoch
and nonce, rather than being permissionless.

Rationale: it forces the attacker to hold current credentials at **both** propose time and
apply time. A permissionless apply would let anyone push a matured proposal through, which
removes the tenant's ability to simply decline to apply — and with O2 removing owner-direct
cancellation, declining to apply is a capability worth preserving.

*Alternative considered:* permissionless apply, relying on `boundEpoch` alone. Rejected as
strictly weaker for the cost of one signature on a rare operation.

## 6. Controller provenance (L9) — the recovery-orphaning defect, wearing a new address

Revision 1 said "once `controller != 0`, owner-direct authority disappears entirely" and
placed no provenance constraint on what may become the controller. That permits:

```
vaultOwner compromised
  → attacker installs a MALICIOUS controller
  → guardian recovery succeeds
  → PolicySubject.owner is stable (L3), so the subject is unchanged
  → the malicious controller is still installed
  → Path 1 is still disabled
  → recovered credentials still cannot administer policy
```

**The epoch does not help here.** It invalidates *pending actions*; the installed
controller is *settled state*. This is the original orphaning defect with an extra hop.

### 6.1 Resolution: only a canonical bridge may hold controller mode

```solidity
contract DailySpendLimitPolicy {
    address public immutable POLICY_CONTROL_BRIDGE;   // set at construction
    // enrollController(...) accepts ONLY POLICY_CONTROL_BRIDGE
}
```

| Property | Result |
|---|---|
| Attacker installs an arbitrary controller | Impossible — the policy rejects any address but the canonical bridge |
| Vault admin influences policy control | No — the bridge is fixed at policy deployment, not admin-selected |
| Bridge upgrade | Requires a **new policy instance** and deliberate re-enrolment, consistent with L7's no-migration default |

*Alternative considered — the consumer names its own bridge* (`consumer.authorizedBridge()`).
Rejected: the vault's bridge pointer would be admin-governed, handing the vault admin a
lever over tenant policy control and violating even the revised L6.

*Alternative considered — `controller == consumer`* (the vault is its own bridge).
Rejected on EIP-170: it puts the authentication code back inside vaults holding 1,725 /
2,091 bytes of headroom (§10.2).

### 6.2 Consequences worth stating

- With a canonical bridge, "controller replacement" collapses to **enrol / unenrol**.
  Unenrolment re-enables Path 1 and is therefore a weakening — delayed, expiring,
  epoch-bound.
- **An attacker enrolling the canonical bridge does not help them.** The bridge demands
  *current* credentials, which recovery rotates away. Enrolment by an attacker is
  functionally the tenant's own enrolment.
- **A fake consumer buys nothing.** The bridge reads credentials from `subject.consumer`;
  a fabricated consumer reaches a bucket keyed to the fabrication, which no tenant armed.
  This is the same argument #171 established for admission and is reused here rather than
  re-derived.
- **Honest cost:** the canonical bridge is a single point of failure for every enrolled
  subject. A bug in it compromises all of them, where arbitrary controllers would have
  isolated blast radius. This design accepts that trade because arbitrary controllers
  reintroduce the defect in §6; it must be stated, not smoothed over.
- Non-WalletWall consumers never enter controller mode and keep Path 1 (L4).


### 6.3 Emergency pause of the canonical bridge (U1 — RESOLVED)

§6.2 accepts a concentration risk: one canonical bridge is one blast radius. That risk has
no natural remedy elsewhere in the design, because **a bridge implementation bug has no
epoch event that makes it stop being buggy.** The epoch handles *credential* compromise
beautifully — credential authority has a lifecycle. Code correctness does not.

> **U1 RESOLVED — one-way global bridge pause, no emergency unenrol and no unpause.**
> A dedicated immutable emergency-pauser may permanently halt configuration through that
> bridge instance. Pausing never changes an enforced policy value, controller, accounting
> state, or authorization path; therefore the pauser gains denial capability only, never
> spend or weakening authority. A paused bridge is retired and replaced, not resumed.

#### Why not an emergency unenrol

Unenrolment changes authority from `canonical bridge → owner-direct`. That is plainly a
**weakening**: it reopens the compromised-owner bypass this whole design exists to close.
An emergency primitive that relaxes authority is not a circuit breaker; it is a backdoor
with a good reason attached.

#### The primitive

```solidity
contract PolicyControlBridge {
    address public immutable EMERGENCY_PAUSER;   // one selector: pause()
    bool    public paused;                       // one-way

    function pause() external {
        if (msg.sender != EMERGENCY_PAUSER) revert NotPauser();
        paused = true;                            // no unpause(), by construction
        emit BridgeRetired();
    }
}
```

`pause()` immediately and permanently disables **all bridge-originated policy-configuration
calls on that bridge instance**. It does **not**: alter any daily limit; clear any
controller; re-enable Path 1; affect `check()` / `revalidate()` / already-enforced policy;
or touch the vault, the epoch, or the rolling ledger.

The pauser holds **one selector**. No upgrade, controller, nonce, limit, proposal, verifier,
or unpause capability.

#### The subtle requirement: pause must block the APPLY half

Every mutating bridge entrypoint hits the same gate — strengthen, propose weakening,
**apply weakening**, controller lifecycle, and admitter repair if routed through the bridge.
Otherwise:

```
1. attacker exploits the bridge
2. proposes 1 ETH → 0
3. proposal matures
4. incident detected, bridge paused
5. attacker applies the already-mature proposal anyway    ← the hole
```

The stored policy proposal is left **untouched**. It simply becomes unreachable through
that retired controller.

#### Why this cannot relax anything: the policy is pause-unaware

The gate lives entirely in the **bridge**, never in the policy. The policy's controller path
is `msg.sender == controller`; a paused bridge simply never makes the call. So:

- `DailySpendLimitPolicy` needs **zero** pause awareness, and gains no ambient admin role —
  preserving the property that the policy has no owner at all;
- there is no policy code path along which a pause could accidentally permit something;
- the mechanism can be, as intended, almost stupidly simple.

#### Recovery is replacement, not resumption

```
Bridge v1 paused  →  deploy Bridge v2 + a policy instance bound immutably to Bridge v2
                  →  deliberately re-establish policy/controller state
                  →  existing policy-engine governance switches to the replacement
```

This is the architecture already chosen: bridge provenance is immutable (§6.1), proposal
migration is forbidden (L7), and authority is re-established deliberately rather than
carried across implementations.

**Consequence to state plainly:** a controller-active subject on the retired instance is
frozen **permanently**, not temporarily. Its last enforced limit stays enforced until the
vault's policy-engine governance moves to the replacement. That is the intended availability
damage, and it is why the pauser is a genuinely serious principal despite holding one
selector.

**Second consequence:** restoration therefore depends on vault-admin engine governance
(§7.2). The admin cannot relax anything through the pause itself, but they are on the
restoration path.

#### Immutable pauser, and what that costs

`EMERGENCY_PAUSER` is immutable — no rotation, no `transferOwnership`, no renounce. Losing
the pauser key loses only the *freeze* capability, which is the fail-safe direction: the
system continues operating under its last configuration. A rotatable pauser would add a
lever whose compromise buys more than the pause itself.

Pause must be observable: a `BridgeRetired` event and a public `paused()` getter, with a
distinct revert reason so a tenant whose configuration call fails can tell retirement from
an ordinary authorization failure.

## 7. Trust table

| Principal | Spend | Strengthen | Propose weakening | Apply weakening | Enrol/unenrol controller | Repair admitters |
|---|---|---|---|---|---|---|
| **Tenant, current credentials** (via bridge) | ✔ | ✔ immediate | ✔ | ✔ after delay, same epoch | ✔ (unenrol delayed) | ✔ immediate |
| **Tenant, stale credentials** | ✘ | ✘ | ✘ | ✘ epoch/nonce | ✘ | ✘ |
| **`vaultOwner` key**, PRISTINE | ✘¹ | ✔ immediate | ✔ | ✔ after delay | ✘ — enrolment is **signed**, not `msg.sender` (U2) | ✔ immediate |
| **`vaultOwner` key**, controller-active | ✘¹ | ✘ | ✘ | ✘ | ✘ | ✘ |
| **Vault contract admin** (`onlyOwner`) | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ — **but see §7.1 and §7.2** |
| **Emergency pauser** (§6.3) | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ — holds **only** `pause()` |
| **Guardian majority** | ✔² | ✔² | ✔² | ✔² | ✔² | ✔² |
| **Delegated admitter** | books only | ✘ | ✘ | ✘ | ✘ | ✘ |
| **Arbitrary caller / arbitrary controller** | ✘ | ✘ | ✘ | ✘ | ✘ (L9) | ✘ |

¹ The `vaultOwner` address is not itself a spending credential — withdrawal requires the
signature of `vault.ecdsaSigner` and/or the PQ key per `VaultMode`. In the common
deployment they are the same key, which is the conflation this design separates.

² A guardian majority can already recover the vault and rotate credentials to itself. Not a
new power; the existing trust assumption of social recovery.

### 7.1 The L6 correction — an independence the system does not actually have

Revision 1 claimed that putting the bridge outside the vault **structurally** denies the
vault admin any policy-control capability. That is too strong, and the mechanism is on
`main`:

```solidity
// both vaults
IPQCVerifier public pqVerifier;                         // MUTABLE
function proposePQVerifier(address) external onlyOwner; // timelocked, admin-governed
function applyPQVerifierUpdate() external onlyOwner;

// WalletWallVault.sol:669-670
bool needEcdsa = mode == VaultMode.EcdsaOnly || mode == VaultMode.Hybrid;
bool needPq    = mode == VaultMode.PqOnly    || mode == VaultMode.Hybrid;
```

In **`Hybrid`** mode, control of the verifier does not supply the required ECDSA
signature, so the admin cannot forge a tenant intent.

In **`PqOnly`** mode, `needEcdsa == false` and the PQ verifier is the *sole* authenticator.
Whatever authority already exists over that verifier is therefore relevant to any bridge
that authenticates against the vault's credential machinery.

**Corrected L6:** the vault admin receives no *new or direct* policy-control authority from
the bridge; bridge authentication **inherits exactly** the vault's existing
credential-verifier trust assumptions and no more. That is a weaker claim than revision 1
made and a truthful one — and it is stronger assurance than asserting an independence that
does not exist.

Testable form: an admin who swaps the PQ verifier gains policy-control capability **iff**
they already had withdrawal capability under that mode. No mode may show the admin gaining
policy control while lacking spend capability.


### 7.2 A second overclaim: the admin can disconnect the policy entirely

The same class of error as §7.1 — asserting an independence the system does not have —
applies to the trust table's vault-admin row, and it is worth stating before implementation
rather than after.

```solidity
// WalletWallVault.sol — zero is explicitly ALLOWED
function _requireCodeBearingPolicyEngine(address engine) private view {
    if (engine != address(0) && engine.code.length == 0) revert PolicyEngineUnavailable(engine);
}

// WalletWallVault.sol:1048 — and zero means "no policy"
if (address(policyEngine) != address(0)) { ... check ... }
```

So the vault admin may propose `address(0)`, wait out `POLICY_ENGINE_UPDATE_DELAY`, and
**disable policy enforcement entirely for that consumer** — without touching the policy,
the limit, the controller, or the ledger.

This is **pre-existing** and out of scope for this lane, but it bounds what this design can
truthfully claim:

- The containment boundary is **tenant credentials *plus* vault-admin engine governance**,
  not tenant credentials alone.
- A pending engine swap is **not epoch-bound**. Recovery invalidates tenant-side weakening
  proposals; it does *not* invalidate a pending swap to `address(0)`. That is a weakening
  path this design does not reach.
- Timing is comparable — the engine-update delay and `POLICY_CONTROL_DELAY` are both on the
  order of the governance reaction window — so the admin path is not meaningfully faster,
  only differently authorized.

**Recorded as a known limit, not fixed here.** Closing it means constraining vault-admin
engine governance itself, which is a separate lane with its own recovery-liveness questions.
The trust table's admin row should be read as "no *new* authority from this design",
consistent with the corrected L6.

## 8. Transition matrix

`E` = epoch unchanged since binding. `E'` = epoch bumped. `C` = controller-active.
`P` = PRISTINE.

| # | Action | Caller | Precondition | Result |
|---|---|---|---|---|
| T1 | strengthen | bridge (authenticated) | `C` | immediate |
| T2 | strengthen | owner | `P` | immediate |
| T3 | strengthen | owner | `C` | **revert** `ControllerPathRequired` |
| T4 | proposeWeakening | bridge | `C`, none pending | `PENDING`, binds epoch |
| T5 | proposeWeakening | owner | `C` | **revert** `ControllerPathRequired` |
| T6 | proposeWeakening | authorized | pending exists | **revert** `WeakeningAlreadyPending` |
| T7 | applyWeakening | bridge (fresh intent) | `MATURE`, `E` | applied; cleared |
| T8 | applyWeakening | any | `MATURE`, `E'` | **revert** `StaleControlEpoch` |
| T9 | applyWeakening | any | immature | **revert** `WeakeningNotReady` |
| T10 | applyWeakening | any | past `expiresAt` | **revert** `WeakeningExpired` |
| T11 | cancelWeakening | bridge | `C` | cleared immediately (strengthening-ward) |
| T12 | cancelWeakening | owner | `C` | **revert** — Path 1 has zero capability (O2) |
| T13 | enrolController | **bridge only**, on a signed `EnrollController` intent from *current* credentials | `P`, controller == canonical | immediate, one-time; sets `controllerInitialized` |
| T13b | enrolController | owner via `msg.sender` | `P` | **revert** — no owner-direct bootstrap (U2) |
| T14 | enrolController | anyone | controller != canonical | **revert** `NotCanonicalBridge` (L9) |
| T15 | unenrolController | bridge | `C` | **weakening**: delayed, expiring, epoch-bound |
| T16 | setAdmitter(add) | authorized path | — | immediate (L5, §9.6) |
| T17 | setAdmitter(remove) | authorized path | not last-while-armed | immediate; existing guard retained |
| T18 | any config | vault admin qua admin | — | **revert** (L6, §7.1) |
| T19 | any bridge action | replayed intent | nonce consumed | **revert** `IntentAlreadyUsed` |
| T20 | any bridge action | intent for another consumer/policy | — | **revert** — `consumer`/`policy` are signed (§5.2) |
| T21 | `pause()` | emergency pauser | not paused | `paused = true`, permanent; `BridgeRetired` |
| T22 | `pause()` | anyone else (incl. vault admin) | — | **revert** `NotPauser` |
| T23 | any bridge mutation | any | `paused` | **revert** `BridgeRetired` — including **applyWeakening on a MATURE proposal** |
| T24 | `unpause()` | — | — | **does not exist** — no callable path returns `paused → active` |
| T25 | `check()` / `revalidate()` | vault | `paused` | **unaffected** — enforcement continues at the last configured value |

**T12 changed from revision 1**, per O2: retaining owner-direct cancellation would leave a
compromised `vaultOwner` a permanent policy-administration DoS lever — able to cancel every
legitimate weakening proposal forever, even after recovery restored spending credentials.
Epoch invalidation already provides the emergency protection cancellation was meant to give.

## 9. Adversarial scenarios (executable)

Each becomes a test in `test/PolicyControlAuthority.test.ts`.

### 9.1 Signer/credential rotation with pending weakening

```
GIVEN  subject (vault, alice, ETH) armed at 1 ETH, controller-active
  AND  a weakening proposal (1 ETH → 0) at T0, validAfter = T0 + DELAY
WHEN   alice calls rotateCredentials at T0 + 1h
  AND  applyWeakening at T0 + DELAY
THEN   revert StaleControlEpoch; dailyLimit still 1 ETH
  AND  a NEW proposal under the new credentials matures normally
CONTROL  rotation with NO pending weakening changes no policy state at all
         (dailyLimit, rollingSpent, activeEntryCount, controller identical)
```

### 9.2 Guardian recovery with pending weakening

```
GIVEN  attacker holds compromised credentials; pending weakening maturing at T0 + DELAY
WHEN   executeRecovery succeeds at T0 + 1h
THEN   policyControlEpoch[alice] incremented
  AND  attacker's applyWeakening reverts StaleControlEpoch
  AND  executeRecovery made NO call to any policy contract     ← assert via trace
  AND  recovered credentials can propose and apply their own weakening
```

### 9.3 Recovery INITIATION must not invalidate legitimate control

```
GIVEN  legitimate pending weakening
WHEN   one malicious guardian calls initiateRecovery; majority never reached
THEN   policyControlEpoch UNCHANGED; the legitimate weakening still applies
```

### 9.4 Policy-engine replacement (L7)

```
CASE A  engine P → different instance P2   → P2 unarmed, no controller, no proposal;
                                             assert dailyLimit(P2) == 0 so the tenant is
                                             not left believing P2 is armed
CASE B  engine P → composite wrapping SAME P → proposal SURVIVES (it lives in P)
CASE C  swap BEFORE validAfter              → identical; wiring is not an input to maturity
CASE D  swap AFTER maturity, before apply   → identical
INVARIANT  replacement never mutates policyControlEpoch and never makes an inapplicable
           proposal applicable
```

### 9.5 Queued withdrawal across transitions (L8)

```
CASE A  STRENGTHENING mid-queue  → finalize still succeeds; revalidate is pure; ledger
                                   unchanged; queued withdrawal NOT retroactively stranded
CASE B  PENDING weakening        → finalization unaffected; assert the queue-time engine
                                   floor never reads `pending`          ← the L8 trap
CASE C  weakening APPLIED        → finalization unaffected; remainingAllowance rises by
                                   exactly the delta; ledger not rewritten
```

### 9.6 Admitter loss while armed (L5)

```
GIVEN  the only admitter is a composite whose owner added an always-denying module
WHEN   the tenant adds a second, direct admitter
THEN   IMMEDIATE — liveness repair, not weakening; withdrawals resume without DELAY
CONTROL  removing the last admitter while armed still reverts LastAdmitterWhileArmed
  AND    arming with zero admitters still reverts NoAdmitterConfigured
```

Justification: adding an admitter does not raise the cap, and confers on an attacker no
capability the existing admitter did not already give them. **Strength is a property of the
limit; authority is a property of the admitter set.**

### 9.7 Direct policy users, no bridge (L4)

```
GIVEN  consumer is not a WalletWall vault; PRISTINE forever
THEN   Path 1 available; strengthening immediate; weakening STILL delayed
  AND  no epoch to bind — applyWeakening checks only (validAfter, expiresAt)
REGRESSION  an existing directly-configured armed subject can still reach limit == 0
            via propose → delay → apply. It must NEVER become permanently unmanageable.
```

### 9.8 Compromised credential proposes weakening immediately before recovery

```
WHEN   attacker proposes (1 ETH → 0) at T0; recovery succeeds at T0 + 2 days
THEN   applyWeakening reverts StaleControlEpoch in BOTH orderings —
       recovery BEFORE maturity, and recovery AFTER maturity
  AND  recovery never enumerated pending proposals anywhere
```

**Both orderings matter.** Recovery *after* maturity is the case an implementation that
checks the epoch only at propose time gets wrong.

### 9.9 Malicious controller enrolment (L9) — the §6 defect

```
GIVEN  attacker holds the compromised vaultOwner key; subject PRISTINE
WHEN   attacker calls enrolController(maliciousController)
THEN   revert NotCanonicalBridge

AND THEN, the full sequence that revision 1 permitted:
GIVEN  attacker enrols the CANONICAL bridge (allowed, and harmless — §6.2)
WHEN   guardian recovery succeeds
THEN   the recovered credentials CAN administer policy through that same bridge
  AND  the attacker's stale credentials cannot (epoch + nonce)
```

### 9.10 Recovery after an attacker proposed controller REMOVAL

```
GIVEN  controller-active; attacker (pre-recovery credentials) proposes unenrolController
WHEN   recovery succeeds before the proposal matures
THEN   applyUnenrol reverts StaleControlEpoch; controller mode SURVIVES
  AND  Path 1 remains disabled, so the compromised vaultOwner regains nothing
```

This is the mirror of §9.8 and the reason unenrolment must be epoch-bound: otherwise an
attacker escapes containment by removing the container.

### 9.11 Vault does not exist / credentials unset

```
GIVEN  bridge asked to authenticate for an owner with no vault at `consumer`
THEN   fail closed — getVault(...).exists == false must revert, never authenticate
```


### 9.12 Pause blocks the apply half of a mature weakening

```
GIVEN  controller-active; attacker has proposed 1 ETH → 0; the proposal has MATURED
WHEN   the emergency pauser calls pause()
  AND  the attacker calls applyWeakening through the bridge
THEN   revert BridgeRetired
  AND  dailyLimit is STILL 1 ETH
  AND  the stored proposal is UNCHANGED — untouched, merely unreachable
```

This is the ordering that makes pause a real circuit breaker rather than a partial one.

### 9.13 Pause freezes the control plane and nothing else

```
GIVEN  controller-active, armed at 1 ETH, a live rolling ledger, epoch E
WHEN   pause()
THEN   dailyLimit, rollingSpent, activeEntryCount, oldestActiveEntry, controller,
       controllerInitialized and policyControlEpoch are ALL bit-identical to before
  AND  check() still admits within the limit and still refuses above it
  AND  revalidate() is unaffected; queued withdrawals still finalize
  AND  Path 1 is STILL disabled — pausing does not re-enable owner-direct authority
  AND  strengthening, proposing and unenrolling all revert BridgeRetired
```

The Path 1 assertion is the one that proves pause cannot relax authority.

### 9.14 Pauser capability is exactly one selector

```
GIVEN  the configured emergency pauser
THEN   it cannot set, strengthen or weaken any limit
  AND  it cannot enrol, unenrol or replace a controller
  AND  it cannot consume or reset a nonce, alter an epoch, or touch the verifier
  AND  there is no unpause path callable by anyone, including the pauser
CONTROL  the vault admin cannot pause unless it IS the configured pauser address
```

### 9.15 Recovery while PRISTINE — enrolment capability must follow the credentials (U2)

The regression that pins §15.1:

```
GIVEN  a WalletWall subject still PRISTINE (controllerInitialized == false)
  AND  the original vaultOwner key is compromised
WHEN   guardian recovery succeeds and rotates ecdsaSigner / pqPublicKey
THEN   the RECOVERED credentials CAN enrol the canonical bridge, immediately,
       via a signed EnrollController intent bound to the NEW epoch
  AND  the STALE vaultOwner address CANNOT enrol — msg.sender confers nothing
  AND  a pre-recovery EnrollController signature is refused (StaleControlEpoch),
       exactly as a pre-recovery weakening proposal is
CONTROL  enrolment remains one-time: a second enrolment attempt reverts even with
         a validly signed intent, because controllerInitialized is already true
```

## 10. Failure and liveness analysis

### 10.1 Grace window is mandatory

A matured proposal that never expires defeats its own timelock: pre-arm at a quiet moment
and friction at the moment of use is zero. `expiresAt` is bounded and non-optional,
mirroring the composite module-removal expiry shipped in #163/#164.

### 10.2 Accepted residual: the freeze DoS

Whoever can strengthen instantly can freeze withdrawals instantly (limit → 1 wei), and
un-freezing is weakening, therefore delayed.

Intrinsic to L1 — delaying strengthening would delay protection, which is worse. Scoped by
§5/§6: once controller-active, only current credentials via the bridge can strengthen, so a
compromised `vaultOwner` address alone cannot freeze. A compromised *signer* can, for the
duration of the delay — exactly the window recovery exists to close.
**Classification: denial, never loss.** Pinned by a test that funds are withdrawable once
the delay elapses.

### 10.3 Recovery liveness preserved by construction

No path in `executeRecovery` calls a policy contract; the epoch increment is a local write
that cannot revert on external behaviour. **Asserted mechanically** (§9.2), because it is
the property most likely to be silently lost by a later "just add a hook" change.

### 10.4 Canonical bridge concentration risk

Stated plainly in §6.2: one bridge, one blast radius. Accepted deliberately, because
arbitrary controllers reintroduce §6's defect — and mitigated, not removed, by the one-way
pause of §6.3. The pause is a containment primitive, not a repair: it stops further
control-plane mutation and hands the system to the replacement path.

### 10.5 Compromised pauser

A compromised pauser obtains **global configuration denial of service** across every subject
enrolled on that bridge: no strengthening, no proposals, no applies, no controller changes,
permanently, on that instance. It obtains **no** loss of funds and **no** weakening — every
enforced value survives untouched, and withdrawals continue to be checked against them.

That is an explicit new trust assumption and a tightly bounded one, and it is the reason the
pauser is a dedicated immutable address rather than either vault's `onlyOwner` or a generic
`Ownable` admin: the blast radius of that role must not be reachable from any role that
already holds other powers.

### 10.6 Nonce liveness

An intent signed and never submitted consumes no nonce (the nonce increments on
*successful* use), so it cannot wedge the sequence. `deadline` bounds how long a signed
intent remains submittable.

## 11. Storage, gas, EIP-170

### 11.1 Policy storage per subject

| Field | Type |
|---|---|
| `controller` | `address` (160 bits; packs with the flags/timestamps below) |
| `controllerInitialized` | `bool` |
| `pending.validAfter` / `expiresAt` / `boundEpoch` | `uint64` ×3 |
| `pending.newLimit` | `uint256` — own slot; `type(uint256).max` must stay settable (pinned by `DailySpendAdmissionAuthority` B5) |

≈ **+2 slots per subject**, written only by subjects that use the feature.

**Hard requirement: `check()` cost is unchanged.** None of these fields are on the
admission hot path — #172 already added ~30.5k gas to a steady-state armed withdrawal.

### 11.2 EIP-170 — binding this time

| Contract | Runtime | Headroom |
|---|---|---|
| `WalletWallVault` | 22,851 | **1,725** |
| `StablecoinVaultSimulator` | 22,485 | **2,091** |
| `DailySpendLimitPolicy` | 3,907 | 20,669 |

Unlike #172, both vaults **must** change: only they can bump the epoch. `getVault()`
already exposes `ecdsaSigner` and `pqPublicKey`, so the bridge lives **outside** the vault
and each vault grows by a mapping, two increments, and a getter.

Measure at the **first compiling implementation**, not at the end (#172 discipline).
**STOP CONDITION:** if either vault crosses the gate or lands in dangerously small
headroom, redesign — do not weaken the gate.

## 12. Settled decisions (formerly O1–O5)

| # | Decision |
|---|---|
| **O1** | **Fixed delay.** `POLICY_CONTROL_DELAY = 2 days`, matching the existing governance reaction window. **Non-configurable in v1** — a configurable delay is another ordered governance object with recursive weakening semantics, more storage and more tests, for no present value. Grace is `POLICY_CONTROL_GRACE_PERIOD = 14 days` (§15, U3). |
| **O2** | **No owner-direct cancellation once controller mode is active.** Path 1 has *zero* capability. Retaining cancellation would leave a compromised `vaultOwner` a permanent policy-administration DoS lever surviving recovery. Epoch invalidation supplies the emergency protection. |
| **O3** | **Immediate one-time initial enrolment**, gated on an explicit `controllerInitialized` transition — **not** on `limit == 0`, since a disarmed subject returns to zero. `PRISTINE → canonical bridge` is immediate **and signed by current credentials** (§15, U2); every later replacement/removal is delayed and epoch-bound. |
| **O4** | **One shared bridge.** State keyed by `(consumer, owner)`; `consumer` is a signed field, so a signature for the ETH vault cannot replay against the stablecoin sibling. Interface differences are handled by narrow adapters, never by cloning security-sensitive code. |
| **O5** | **E1 only** (explicit vault-owned counter). The fingerprint adapter (E2) is **not** shipped: it is non-monotonic and can resurrect a stale proposal if credentials rotate back, and with `policyEngineAddress` `null` in every deployment manifest there is no live armed state forcing us to accept that weakness. E2 stays documented as a possible legacy adapter, out of scope for `v0.13.0`. |

## 13. Test plan

`test/PolicyControlAuthority.test.ts`.

| Group | Cases |
|---|---|
| **A — strength order** | all §3 transitions; `0→n` immediate; `n→0` delayed; no-op rejected |
| **B — epoch binding** | same epoch; after `rotateCredentials`; after `executeRecovery`; both; apply before *and* after maturity with an intervening bump (§9.8) |
| **C — recovery liveness** | no policy call in `executeRecovery`; recovery succeeds with a reverting policy module installed; `initiateRecovery` does not bump (§9.3) |
| **D — path exclusivity** | T3/T5/T12; Path 1 has zero capability once controller-active; vault admin has no path |
| **E — engine replacement** | §9.4 CASES A–D |
| **F — queued withdrawals** | §9.5 CASES A–C; `revalidate` still `pure`; queue-time floor never reads `pending` |
| **G — lockout repair** | §9.6 plus both existing-guard controls |
| **H — direct users** | §9.7 including the never-unmanageable regression |
| **I — grace window** | apply at `validAfter`; at `expiresAt - 1`; at `expiresAt` (reverts); pre-arm-then-wait defeats nothing |
| **J — bridge authentication / provenance** | same-intent replay; cross-consumer replay; cross-policy replay; expired intent; stale-epoch intent; ECDSA / PQ / Hybrid mode correctness; malicious arbitrary-controller enrolment; recovery after an attacker proposed controller replacement (§9.10); nonexistent-vault fail-closed (§9.11); **recovery while PRISTINE — recovered credentials enrol, stale `vaultOwner` cannot (§9.15)** |
| **K — emergency pause** (NEW) | pauser cannot set/strengthen/weaken limits; vault admin cannot pause unless it *is* the configured pauser; pause blocks fresh strengthening; pause blocks proposal creation; **pause blocks application of an already-mature weakening** (§9.12); pause leaves `dailyLimit`, rolling ledger, controller and epoch bit-identical (§9.13); pause does not affect `check()` / `revalidate()`; **no callable path transitions `paused → active`**; unenrolment remains delayed even while paused; Path 1 stays disabled while paused |

### 13.1 Required mutants

Mutation discrimination is mandatory, on the #172 lesson that a test written after the
implementation and passing immediately has demonstrated nothing.

| # | Mutant | Killed by |
|---|---|---|
| M1 | `isWeakening` replaced by `new > old` | A |
| M2 | epoch checked at propose time only | B (§9.8 ordering) |
| M3 | `initiateRecovery` also bumps the epoch | C |
| M4 | Path 1 left enabled for strengthening when controller-active | D |
| M5 | `expiresAt` check removed | I |
| M6 | `setAdmitter(add)` routed through the weakening delay | G |
| **M7** | **bridge nonce not incremented** | **J — same-intent replay** |
| **M8** | **`consumer` omitted from the signed struct** | **J — cross-consumer replay** |
| **M9** | **arbitrary controller accepted instead of the canonical bridge** | **J — malicious enrolment (§9.9)** |
| **M10** | **`policy` omitted from the signed struct** | **J — cross-policy replay** |
| **M11** | **enrolment gated on `limit == 0` instead of `controllerInitialized`** | **J — re-enrol after disarm (O3)** |
| **M12** | **`applyWeakening` omitted from the pause gate** | **K — §9.12, the mature-proposal hole** |
| **M13** | **an `unpause()` path added** | **K — no `paused → active` transition exists** |
| **M14** | **pause also clears the controller (i.e. an "emergency unenrol")** | **K — §9.13, Path 1 must stay disabled** |
| **M15** | **pauser check widened to the vault admin** | **K — admin cannot pause unless configured as pauser** |
| **M16** | **signed enrolment replaced by `msg.sender == owner`** | **J — §9.15: the stale `vaultOwner` must NOT be able to enrol after recovery** |

## 14. Migration and compatibility

- No proposal migration across policy instances (L7). §9.4 CASE A asserts the tenant is not
  left believing a new instance is armed.
- `policyEngineAddress` is `null` in every deployment manifest, so there is **no on-chain
  armed state to migrate**. Compatibility is an API story, not a state story.
- `setDailyLimit(consumer, asset, 0)` moves from immediate to delayed — **breaking**.
- Lowering a nonzero limit is unchanged.
- Semver: breaking minor on the `0.x` line, `0.12.x → 0.13.0`, by #172's reasoning.

## 15. Final resolutions (U2, U3)

| # | Question |
|---|---|
| **U2 — RESOLVED** | **Signed, not `msg.sender == owner`.** The one-time `PRISTINE → canonical bridge` enrolment stays **immediate**, but must carry an `EnrollController` intent signed by the vault's **current** credentials and submitted through the canonical bridge. Immediate is safe because the transition only ever *adds* containment. |
| **U3 — RESOLVED** | `POLICY_CONTROL_GRACE_PERIOD = **14 days**`, matching the existing 2-day-delay / 14-day-grace governance pattern. No new duration is introduced. |

### 15.1 Why enrolment must be signed, not owner-direct

The deciding case is **recovery *before* enrolment**, and it is not hypothetical:

```
GIVEN  a vault still PRISTINE when the original vaultOwner key is compromised
WHEN   guardian recovery rotates the actual spending credentials
THEN   under an owner-direct bootstrap (msg.sender == owner), the RECOVERED tenant
       cannot enrol the controller without cooperation from the STALE key
```

That is a smaller instance of the exact orphaning defect this work exists to eliminate
(§1) — authority stranded on an address that recovery does not move. Requiring the signed
intent binds enrolment to the **credential lifecycle** rather than to the address, so
recovery carries enrolment capability with it like every other configuration action.

**There is no bootstrap circularity.** The policy already knows the canonical bridge
immutably (§6.1), so the bridge can authenticate an `EnrollController` intent *before* it
is installed as the subject's controller. Nothing has to trust the bridge into existence.

The intent is the `EnrollController` struct already specified in §5.2, and it binds the
same epoch, nonce and deadline as every other intent — so a pre-recovery enrolment
signature dies at recovery exactly like a pre-recovery weakening proposal.

**Scope note carried forward:** the vault-admin `address(0)` finding (§7.2) stays **out of
`v0.13.0` scope**. This lane protects against tenant-credential compromise, subject to the
existing vault-admin engine-governance trust assumption. Closing the admin's ability to
disconnect enforcement is a separate governance-hardening lane.

---

**Next step:** on approval of this revision, open the `v0.13.0` Solidity lane in the order
`epoch → bridge → policy state machine → tests`, measuring both vaults' bytecode at the
first compiling implementation.
