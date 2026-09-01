# WalletWall Vault vNext — Assured Minimal Trust Architecture

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> This document adjudicates a **proposed** architecture. Nothing in it is implemented, nothing is
> deployed, and there is no mainnet write path. The repository does not custody user funds, does not
> process production withdrawals, and produces no real yield. Local and Sepolia simulator paths are
> developer/testnet rehearsal exceptions only.
>
> **DESIGN ONLY.** The committed diff under `contracts/` for this lane is empty, by rule.
> No production Solidity was written. `VaultKernel.sol` does not exist and must not be created on
> the strength of this document alone.

---

## 0. Status legend, and why it is enforced pedantically

Five categories, never interchangeable. Any statement in this document belongs to exactly one.

| Status | Meaning |
|---|---|
| **OBSERVED** | Verified firsthand in source at `origin/main` `aaba4d2024932ba5fdf131fd9bba5020345af5fb`, tree `fbfcdb1638b29d4512cccf2cfdf27f82f972455b`, package `0.13.2`. Cited. |
| **MEASURED** | Produced by running a tool this session. The command is named. |
| **PROPOSED** | vNext design intent. Not implemented. Carries no assurance whatsoever. |
| **PROVEN-BY-MODEL** | Holds in `test/helpers/vaultVNextModel.ts` and is killed by a discriminating mutant. Proves the *architecture is coherent*; proves **nothing** about any Solidity. |
| **RESIDUAL** / **UNRESOLVED** | Accepted, or open pending an owner decision. |

The distinction is not bureaucratic. This lane exists because a previous pass in the sibling
guardian lane collapsed "achievable in principle" into "achieved", and the correction consumed a
full revision. Proposed architecture is never written here as if deployed.

---

## 1. Protection goals

In priority order. Where two conflict, the higher number yields.

1. **G1 — Asset conservation.** No principal, coalition, or component failure may remove assets
   from a vault except by an authorization the vault's own declared rules accept.
2. **G2 — Recovery reachability.** Within the declared fault envelope (§2), at least one authorized
   recovery path remains executable, and no replaceable component's failure can eliminate all of them.
3. **G3 — Bounded authority.** Every principal's *transitive* authority is enumerable and bounded.
   A principal that can force eventual asset control is classified as holding asset authority.
4. **G4 — Truthful code identity.** What a vault will execute must be determinable from evidence
   the observer can obtain without trusting the deployer.
5. **G5 — Operational independence.** No authorization path may depend on WalletWall-operated
   infrastructure.
6. **G6 — Evolvability under a hard ceiling.** The architecture must remain able to absorb security
   fixes without exhausting EIP-170.

**G6 is not an aesthetic goal.** It is listed because the current architecture has already failed
it — see §19 and hazard H-20.

---

## 2. Declared failure envelope

### 2.1 In scope — the system must survive these

| Condition | Requirement |
|---|---|
| Any single capability plane becomes permanently unavailable | G1 and G2 both hold |
| Any single capability plane becomes Byzantine | G1 and G2 both hold |
| The signature verifier returns `true` unconditionally | G1 holds |
| The signature verifier reverts forever | G2 holds; G1 degrades to denial, never loss |
| Spending credentials are compromised | G2 holds — recovery is the remedy |
| Spending credentials are lost | G2 holds |
| An emergency principal disappears or turns hostile | G2 holds — containment self-expires |
| WalletWall the company ceases to exist entirely | G1, G2, G5 all hold |
| A plane's state desynchronizes from the kernel's | Detected, or structurally impossible |
| Stale state of any generation is presented | Rejected |

### 2.2 Accepted unrecoverable conditions — explicitly outside the envelope

These are **declared**, not discovered. A scenario falling here is *correctly* unrecoverable.

1. **Kernel invariant failure.** A defect in immutable kernel code. Immutability is the mechanism
   that provides G4; it is also the mechanism that makes kernel bugs permanent. This trade is
   accepted deliberately and is the strongest argument *against* this architecture (§20).
2. **Guardian-majority compromise.** A quorum of a vault's own guardians can recover it to
   credentials they control. This is intrinsic to social recovery and is already an accepted limit
   in the current design. It appears in the authority closure and is **asserted positively** by the
   model — an authority graph that omits a real path is worse than no graph.
3. **Loss of every recovery principal simultaneously.** Credentials lost *and* guardian quorum
   unreachable. No mechanism can recover from the loss of all authority.
4. **Base-chain failure.** Consensus failure, permanent reorg, or chain abandonment.
5. **Simultaneous failure of explicitly accepted trust roots** — specifically `secp256k1` *and*
   the active post-quantum scheme in the same window.

### 2.3 The envelope is decidable

A scenario is inside the envelope iff it names **only** conditions from §2.1 and **none** from §2.2.
This is mechanisable, which is the point: `test/VaultVNextArchitectureModel.test.ts` classifies
scenarios by setting `PlaneHealth` and asserting the outcome, rather than by argument.

---

## 3. Selected vault identity and deployment model

### VERDICT — Architecture C

> **A CREATE2 factory deploying EIP-1167 minimal clones, each bound at its own deploy time to an
> immutable, non-upgradeable kernel implementation generation.**
>
> Vault identity is the **clone's address**. Assets are held **directly** by that address.
> There is **no upgradeable proxy** anywhere in the design, and no beacon.

This delivers Architecture **B's semantics** (one account per vault, address-as-identity, direct
custody) using **C's deployment economics**, because B as literally specified is not constructible
at the current kernel size (§3.3).

### 3.1 "Immutable" is a claim about a mechanism — the distinction the mission demands

These two are routinely both called "proxies". They are not both immutable, and conflating them
would forfeit G4.

| | **EIP-1167 minimal clone** | **ERC-1967 / UUPS / transparent proxy** |
|---|---|---|
| Where the implementation address lives | A **`PUSH20` immediate operand inside the clone's own runtime code** (bytes 10–29 of the 45-byte runtime `363d3d373d3d3d363d73…5af43d82803e903d91602b57fd5bf3`) | A **storage slot** |
| How an observer learns it | `EXTCODEHASH` / `eth_getCode` — pure code read | `SLOAD` — a state read |
| Can it change after deployment? | **No.** Changing it would require changing account code, which the EVM does not permit | **Yes**, by whoever holds upgrade authority |
| Does the code hash identify the implementation? | **Yes.** `extcodehash(clone)` is a total function of the implementation address | **No.** It identifies the *proxy generation only*, and is identical across every implementation it will ever point at |

Therefore: **an EIP-1167 clone bound to a fixed implementation is truthfully immutable. An ERC-1967
proxy is not, and must never be described as such.**

A **beacon proxy** is rejected explicitly as the worst of both: it reproduces the current
architecture's exact system-wide geometry — one storage slot in one beacon governs the code of every
vault simultaneously — while adding a hop and the false comfort of the word "proxy per vault".

### 3.2 Why C, stated as root-cause elimination rather than preference

**R1 — It dissolves the root cause of every failed guardian-hardening candidate.**
`Guardian_Authority_Design.md` §4.2 records that F-1 through F-5 all failed, and §4.1 states the
cause: *(b) is the `vaults[]` mapping key, therefore unrotatable, and every guardian-administration
gate is (b)-keyed*. You cannot revoke a name. Under C the vault's identity is its **address** — the
object called, not a caller — so identity stops being a principal.

> **Necessary, not sufficient — and this correction matters.** The identity split alone does not
> make administration rotatable: *someone* must still be authorized to call `setGuardians` on that
> vault, and a stored owner address would reproduce (b) exactly. The sufficient step is that
> **guardian administration is internal quorum state, not a stored external key.** C makes that
> possible; it does not perform it. The model encodes the sufficient step, not merely the necessary one.

**R2 — It deletes the pooled-solvency class outright** (hazard H-25). OBSERVED: `address(this).balance`
appears **nowhere** in `contracts/`, and no `solvency`/`totalDeposits`/`totalBalance` symbol exists —
**there is no on-chain solvency check at any site**. A per-vault account owns its assets directly, so
there is no second number to disagree with the first. ERC-20 and NFT custody then arrive as ordinary
ownership rather than as new accounting.

**R3 — Plane pointers become per-vault, because a clone shares CODE and owns STORAGE.**
OBSERVED: `WalletWallVault` declares **no** `immutable` variables; `pqVerifier` (L180),
`policyEngine` (L238), `largeTxThreshold` (L228), and the inherited `_owner`/`_paused` are all
**storage**. Under a clone every one of them is per-clone by construction. There is no global slot
for a global admin to hold.

**R4 — Replay separation moves from authentication to provenance.** In a shared contract
`_hashTypedDataV4` binds `address(this)`, which is identical for every tenant, so tenant separation
rests on the signed `vaultOwner` field — trusted *by authentication*, as `IPolicyEngine`'s own
documentation says. Per-vault, the **domain separator itself** separates vaults: a signature for
vault X is structurally invalid at vault Y.

**R5 — MEASURED: the clone factory fits, and the alternative does not** (§3.3).

### 3.3 Rejected alternatives, with the specific reason each died

**Architecture A — retain the shared multi-tenant contract. REJECTED.**
Its strongest argument was that blast radius follows the *admin plane*, not the state layout, and
that splitting state without splitting planes fixes nothing. That argument is **inverted by its own
evidence**: because the contract declares no `immutable`, every "global plane" is storage, and a
clone owns its storage — so C splits the planes automatically. A also cannot reach R1, R2, or R4 at
all. Additionally, the claim "recovery makes zero external calls, therefore recovery is isolated from
every global plane" is **false**: `executeRecovery` is `whenNotPaused` (L534), which reads a single
global `_paused` bit. No call is made, and recovery is still coupled to a cross-tenant object one
principal controls. *(This correction is now encoded as `recoveryDependsOnGlobalState()` in the model.)*

**Architecture B — a full contract deployed per vault via `new Vault{salt}(…)`. REJECTED, on measurement.**
Solidity compiles `new Vault{salt}(...)` by embedding the callee's **entire creation bytecode** into
the factory's own runtime. MEASURED this session: `WalletWallVault` creation bytecode is
**24,574 bytes** against the EIP-170 ceiling of **24,576**. Such a factory is undeployable before a
single byte of dispatcher, CREATE2, or argument-encoding logic is added. B is not merely expensive;
**it is not constructible as specified.**

**Architecture D — three-tier decomposition split by mutability. REJECTED as a forcing argument.**
Its distinguishing move — removing the admin plane — is **orthogonal** to the identity model, and
the contract itself proves it: `policyEngineAtQueue` (L174, bound at L862) is already a *per-instance
plane pointer inside Architecture A*. Plane removal is therefore available under A, B, C, or D
equally, and so distinguishes none of them. Its remaining links do not force the decomposition.
**Its plane-removal component is correct and is adopted inside C.**

### 3.4 Dissent — attacks on the winning position that still stand

Recorded rather than suppressed. Each is a real cost of C.

| # | Standing objection | Status |
|---|---|---|
| D1 | **A clone cannot have per-clone `immutable`s.** Solidity bakes `immutable` into the *implementation's* runtime bytecode, so every clone resolves the identical value. Any "each vault immutably bound to its own verifier" claim is **false**; such bindings must be storage. | ACCEPTED. Aligns with R3, but the naming must never overclaim. |
| D2 | **The EIP-712 cached fast path is permanently unreachable for every clone.** `EIP712.sol:83` uses the cache only when `address(this) == _cachedThis`, an `immutable`. Every clone rebuilds the domain separator on every call. | ACCEPTED, and it is the *price of R4*, not pure waste. |
| D3 | **Clones run no constructor**, so initialization is a call. Deploy-and-initialize must be **atomic** or an uninitialized clone can be claimed by a front-runner. The measured spike does this in one function. | MITIGATED by construction; must be preserved. |
| D4 | **The factory is a shared dependency** and, if immutable, its bugs are unpatchable. A salt-derivation defect is inherited by every clone it ever produced. | RESIDUAL. Bounded: the factory holds **no authority over already-deployed clones**, so its compromise is a *cohort* hazard for future vaults, never a system-wide hazard for existing ones. |
| D5 | **EIP-1167 does not relieve EIP-170 for the implementation.** The kernel is still one contract in the same size class. | ACCEPTED. C improves the *deployment* budget, not the *kernel* budget. §19 addresses the kernel budget separately. |
| D6 | **CREATE2 counterfactual funding is a footgun.** The address commits to the full init code and constructor arguments, so a compiler or optimizer change relocates it. | RESIDUAL. Mitigated by pinning the compiler and publishing the derivation (§16). |
| D7 | **NIST SP 800-160 v1r1 E.3 (Commensurate Protection) explicitly declines to let this choice settle protection strength**: "the needed strength of protection is independent of these design choices (or others, such as distributed versus centralized design)". | ACCEPTED. The verdict is therefore argued from **state-partitioning blast radius and measured constructibility**, never from "distributed is safer". |
| D8 | **E.12's "physical separation" does not transfer.** On a public L1 every contract shares one EVM, one state trie, one validator set. Per-vault instances are **logical** separation only. | ACCEPTED, and the wording throughout this document reflects it. |

---

## 4. Trusted Computing Base

> **Terminology caution.** "Trusted computing base" and "TCB" occur **zero times** in
> NIST SP 800-160 v1r1 (verified by full-text search of the publication). The framing here is ours.
> The citable NIST analogues are **E.20 Minimal Trusted Elements** ("as few trusted system elements
> as practicable") and the reference validation mechanism in D.4.2. This document does not claim
> NIST authority for the TCB vocabulary, and **no compliance mapping has been performed**.

### 4.1 The kernel membership rule

> **R-KERNEL.** A responsibility belongs in the immutable kernel **iff** there exists a declared
> catastrophic requirement (G1 or G2) whose satisfaction cannot be restored by *any* sequence of
> authorized transactions after that responsibility's owning component becomes permanently
> unavailable or Byzantine.

With one sharpening clause that does most of the work:

> **R-KERNEL-CIRCULARITY.** If *replacing* a component requires that component to function, it is
> KERNEL-REQUIRED regardless of the above.

The circularity clause is the mechanised form of mutant **M4** ("a failed plane becomes mandatory
for its own recovery") and it is the single most useful test in this document, because a component
that gates its own replacement converts a liveness failure into a permanent one.

### 4.2 Classification

| Responsibility | Class | Byzantine outcome | Permanently unavailable outcome |
|---|---|---|---|
| Asset custody | **KERNEL-REQUIRED** | Total loss | Total loss |
| Asset execution | **KERNEL-REQUIRED** | Total loss | Assets frozen forever |
| Nonce / replay state | **KERNEL-REQUIRED** | Replay ⇒ loss | No authorization possible |
| Credential commitment | **KERNEL-REQUIRED** | Attacker named as owner ⇒ loss | No authorization possible |
| Guardian membership | **KERNEL-REQUIRED** | Attacker quorum ⇒ loss (H-19) | Recovery unreachable; **and replacing the plane needs guardian authority ⇒ circular** |
| Recovery request state | **KERNEL-REQUIRED** | Forged/erased requests | Recovery unreachable |
| Recovery execution | **KERNEL-REQUIRED** | Arbitrary credential install | Recovery unreachable |
| Recovery cancellation | **KERNEL-REQUIRED** | Unbounded veto | Hostile recovery unstoppable |
| Safe-state machine | **KERNEL-REQUIRED** | Forced terminal state | State frozen |
| Migration authorization | **KERNEL-REQUIRED** | Malicious destination ⇒ total loss | No escape from a dead plane |
| Migration execution | **KERNEL-REQUIRED** | Total loss | No escape from a dead plane |
| Signature verification | **FLOOR + PLANE** (see §4.3) | Forgery **iff** the scheme is the sole authenticator | Denial only, never loss |
| Emergency transition *rules* | **KERNEL-REQUIRED** | — | — |
| Emergency transition *trigger* | **ADAPTER-SAFE** | Spurious containment — bounded, self-expiring | No containment available |
| **Verifier governance** (authority to replace a verifier) | **KERNEL-REQUIRED** | Re-installs a hostile verifier after any remediation | **Circular** — the remediation would be authenticated by the verifier it is replacing |
| Verifier *implementation* (within a scheme) | **PLANE-SAFE** | Bounded by the floor | Denial only |
| Guardian signature aggregation | **PLANE-SAFE** *(conditional)* | Rejected by kernel re-check | Safe **only if** the kernel retains an individual-approval path |
| Policy enforcement | **PLANE-SAFE** | Over-restriction ⇒ denial | Denial; escape via migration |
| Policy administration | **PLANE-SAFE** | Denial | Policy frozen at last value |
| ERC-1271 handling | **ADAPTER-SAFE** | Bad signature answers to third parties | Feature unavailable |
| ERC-4337 validation | **ADAPTER-SAFE** *(conditional)* | See §5 — EntryPoint trust is unavoidable if adopted | Safe **only if** a non-4337 direct path always exists; otherwise a dead EntryPoint strands the account |
| ERC-7579 compatibility | **REJECTED** | Module authority ⇒ total takeover | — |

### 4.2a Where the three lenses disagreed, and how it was adjudicated

Three independent lenses classified every responsibility: **Byzantine failure**, **permanent
unavailability** (with the M4 circularity test as its primary discriminator), and **minimality**
(admit nothing until exclusion is proven unsafe). They agreed unanimously on nine KERNEL-REQUIRED
items: asset custody, asset execution, nonce/replay state, credential commitment, **guardian
membership**, recovery request state, recovery execution, **verifier governance**, migration
authorization.

They disagreed on eight. Disagreements are **not averaged** — each is adjudicated, with the governing
lens named.

| Responsibility | Byzantine | Unavailable | Minimality | Adjudication |
|---|---|---|---|---|
| Signature verification | PLANE-SAFE | KERNEL-REQ | KERNEL-REQ | **Both halves are right about different objects.** Resolved by FLOOR + PLANE (§4.3): the *floor* is KERNEL-REQUIRED, the *implementation* is PLANE-SAFE. |
| Verifier governance | KERNEL-REQ | KERNEL-REQ | KERNEL-REQ | **Unanimous — and it corrects an earlier draft of this document**, which had it PLANE-SAFE. Governs by the circularity clause. |
| Guardian signature aggregation | PLANE-SAFE | KERNEL-REQ | KERNEL-REQ | **PLANE-SAFE, conditionally.** Unavailability governs *unless* the kernel keeps an individual-approval fallback. With the fallback, aggregation is a pure optimisation. The condition is now normative. |
| Recovery cancellation | PLANE-SAFE | KERNEL-REQ | KERNEL-REQ | **KERNEL-REQUIRED.** The Byzantine lens's own circularity note is decisive against its verdict: the remedy for a hostile canceller *is* recovery, and the canceller cancels recovery. |
| Policy administration | KERNEL-REQ | PLANE-SAFE | PLANE-SAFE | **PLANE-SAFE.** The Byzantine worry is over-restriction, which is denial, not loss — and §13's migration is the escape. Denial is inside the envelope; loss is not. |
| Safe-state machine | KERNEL-REQ | KERNEL-REQ | PLANE-SAFE | **KERNEL-REQUIRED.** Minimality is the designated counterweight and its dissent is expected; an external state machine that can force a terminal state is a total-loss path. |
| Emergency transitions | KERNEL-REQ | KERNEL-REQ | PLANE-SAFE | **Split.** The transition *rules* are KERNEL-REQUIRED; the *trigger* is ADAPTER-SAFE (§10). This is the split minimality was reaching for. |
| Migration execution | KERNEL-REQ | KERNEL-REQ | PLANE-SAFE | **KERNEL-REQUIRED.** Migration is the universal escape from plane death; an escape that itself lives in a plane is not an escape. |
| ERC-4337 validation | ADAPTER-SAFE | KERNEL-REQ | ADAPTER-SAFE | **ADAPTER-SAFE, conditionally** — a dead EntryPoint must never strand the account, so a direct non-4337 path must always exist. Reinforces the §5 recommendation not to adopt 4337 in generation 1. |

### 4.3 The decomposition that matters most: FLOOR + PLANE

Signature verification looks KERNEL-REQUIRED (a Byzantine verifier forges) yet must be replaceable
(crypto agility). The resolution, and the reason the kernel stays small:

> **Planes may only SUBTRACT authority; they may never ADD it.**
> The kernel evaluates a **floor** it can compute itself. External planes are consulted only to
> impose *additional* requirements. A plane's answer is therefore conjunctive.

Consequences:
- An **always-true verifier grants nothing**, because its `true` is ANDed with a kernel-evaluated
  requirement. Mutant **M11** dies structurally rather than by vigilance.
- A **Byzantine policy engine** can deny but never permit. Mutant **M13** dies the same way.
- "No policy configured" returns to the **kernel floor**, not to "no restriction" — which is what
  makes the observed `policyEngine == address(0)` disable (H-07) safe under vNext and unsafe today.

Two cheap floor components, both kernel-resident and neither requiring trust in any plane:
1. **Structural length rejection.** FIPS 204 §3.6.2 states an implementation *shall* return false
   when public-key or signature lengths differ from the standard's, because failing to check "may
   interfere with the security properties that ML-DSA is designed to have, like strong
   unforgeability." These are **pure integer comparisons**, so the kernel performs them itself.
2. **Kernel-recorded scheme strength** (§12), never read from the verifier.

---

## 5. No generic privileged execution

**OBSERVED — no production contract has any generic execution surface.** Stated precisely, because
an overstated grep is worthless as evidence:

- **Zero matches anywhere in `contracts/`** for `multicall`, `execute(`, `installModule`,
  `isValidSignature`, `validateUserOp`, `ERC1271`, `7579`, or `initializer`.
- `delegatecall` and `functionCall` appear in exactly **one** file — `contracts/mocks/AssuranceCallMutants.sol`,
  a deliberate mutation fixture that exists to test the AST call analyzer. **No production contract contains either.**
- `WalletWallVault` has **no `receive()` and no `fallback()`**, so a bare ETH send reverts and no
  unaccounted balance can be created. There is no fallback dispatch to confuse `msg.sender`.
- The only low-level calls in the vault are two **value-only** `.call{value: amount}("")` sites
  (L979, L1140) with **empty calldata** — value transfer, never arbitrary invocation.
- Honest exceptions, named rather than glossed: inline `assembly` **does** occur in production, but
  narrowly and for one purpose — `CompositePolicyEngine.sol:163` reads `extcodesize(module)`, as do
  the two attestation verifiers. The apparent `EntryPoint` / `proxy` / `upgrade` hits are **English
  words in comments** ("cancel entrypoint", "a proxy for policy freshness", "a bridge upgrade"), not
  mechanisms.

This absence is a genuine asset and vNext must not spend it.

**PROPOSED — a control plane receives one exact typed capability, never `execute(address,bytes)`.**

### Does interoperability force generic module authority into the kernel? **NO.**

Settled by spec text, not preference:

- **ERC-4337**: `IAccount` is the only required interface; `IAccountExecute` is **MAY**. The spec
  says only that "an expected workflow is for the account to have an `execute` function" — an
  expectation, not an obligation. A vault may expose exact typed selectors and remain conformant.
- **ERC-1271** (Final) is a universally adopted interoperability boundary consisting of **one `view`
  function** that "MUST NOT modify state". Interoperability at a boundary is demonstrably achievable
  with zero execution authority.
- **ERC-7579 / Safe**: module authority *is* total takeover, per the vendor's own documentation —
  "Modules are extensions with unlimited access to a Safe … A malicious module can completely take
  over a Safe." That is the definition of the thing G3 exists to prevent.

**The strongest argument against a module registry is not theft — it is liveness.** Both standards'
authors independently document that the extension mechanism creates an **unremovable** hazard, and
both mitigations reduce to "keep a recovery path outside the extension system". For a vault whose
primary asset is recovery survivability, adopting a mechanism whose own remedy is "have a separate
recovery path" is self-defeating.

### If ERC-4337 is nonetheless adopted — the unavoidable cost, stated

**UNRESOLVED, owner decision required.** Two costs cannot be designed away:

1. **EntryPoint becomes an unconditionally-trusted caller.** The spec requires the account to
   "validate the caller is a trusted EntryPoint", and states that calls from it "may be
   unconditionally trusted". Its Security Considerations state the design works "precisely by
   concentrating security risk in the EntryPoint contract", which "will serve as a central trust
   point for *all* ERC-4337". Blast radius: **total, and system-wide across every adopting account.**
2. **ERC-7562 [OP-011] bans `TIMESTAMP` and `NUMBER` during validation.** Every time-gated authority
   in this design reads the clock — the recovery delay, the plane-replacement delay, the grace
   window. This is a direct conflict and it is *not* the storage rules, which are fine:
   [STO-010] permits account storage access, so reading guardian and recovery state is allowed.
   *(Clean negative result: the storage rules were the expected obstacle and are not one.)*

**Recommendation: do not adopt ERC-4337 in the first kernel generation.** Expose ERC-1271 only.

---

## 6. Safe-state lattice

Five states. Not all are separately necessary; `RECOVERY_ONLY` and `MIGRATION_ONLY` are retained
because they are the states a *constrained actuator* may drive to without being able to spend.

| Action | NORMAL | CONTAINED | RECOVERY_ONLY | MIGRATION_ONLY | RETIRED |
|---|---|---|---|---|---|
| Ordinary spend | ✅ | ❌ | ❌ | ❌ | ❌ |
| Large spend | ✅ | ❌ | ❌ | ❌ | ❌ |
| Queue | ✅ | ❌ | ❌ | ❌ | ❌ |
| Settle existing queue | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Deposit / inflow** | ✅ | ❌ | ❌ | ❌ | ❌ |
| Policy mutation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Guardian mutation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Credential rotation | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Recovery initiation** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Recovery support** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Recovery cancellation** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Recovery execution** | ✅ | ✅ | ✅ | ✅ | ❌ |
| Plane replacement | ✅ | ❌ | ❌ | ❌ | ❌ |
| Migration preparation | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Migration execution** | ✅ | ✅ | ✅ | ✅ | ✅ |

Two rows carry the design.

**Recovery stays available in every non-terminal state.** This is what denies an emergency principal
a veto. Containment withdraws *spending*, never *recovery*.

**Deposit is gated with withdrawal.** OBSERVED defect corrected: today `deposit`/`depositFor` carry
no pause modifier while every payout path does, so a frozen deployment keeps accepting funds it
cannot pay out (hazard H-22). A state that cannot pay out must not take in.

**Migration execution is available even in RETIRED**, which is what stops retirement being an asset
trap.

### Transitions

| Transition | Authorizing principal | Delay | Generation effect | Reversible | Terminal |
|---|---|---|---|---|---|
| NORMAL → CONTAINED | Emergency principal, or guardian quorum | none | none | **Yes — by wall-clock expiry only** | no |
| CONTAINED → NORMAL | **Nobody. Wall-clock expiry.** | bounded | none | — | no |
| NORMAL → RECOVERY_ONLY | Guardian quorum | delayed | none | yes | no |
| any → MIGRATION_ONLY | Guardian quorum + credential | delayed | none | yes | no |
| MIGRATION_ONLY → RETIRED | Migration execution | none | kernel generation advances | **no** | **yes** |

### Required invariants

- **No minor principal can force an irreversible terminal state.** Only a completed migration —
  which is bound to a specific destination — reaches RETIRED.
- **No emergency transition silently increases authority.** Enforced as *authority monotonicity*:
  for every principal, capabilities after ⊆ capabilities before. Mutant **M6**.
- **No reachable degraded state traps the vault.** Every state retains migration execution.
- **No emergency principal gains a permanent recovery veto.** Containment self-expires with **no
  principal acting**, and recovery stays available throughout. Mutant **M7**.

> **A counter-intuitive rule, stated because it looks wrong.** The containment clock and the
> recovery-expiry clock are **wall-clock and must not suspend while contained.** Suspending them
> looks protective and is the opposite: composed with an irreversible freeze it converts a stalled
> recovery request into a **permanently undeletable** one, removing the last exit. A wall-clock bound
> is also strictly cheaper — no per-request accrual state. The sibling guardian lane reached this
> conclusion independently and withdrew an earlier draft that proposed suspension.

---

## 7. Control-plane synchrony

For each PUSH boundary the kernel must specify: authoritative source, consumer state, expected prior
generation, new generation, nonce, atomicity, rollback, failure semantics.

**The preferred mechanism is to have no second copy.** OBSERVED, and already working:
`PolicyControlBridge` holds **no cached epoch** — it reads
`IPolicyControlCredentialSource(consumer).policyControlEpoch(owner)` live
(`PolicyControlBridge.sol:733-734`), so bridge/kernel divergence is **structurally impossible rather
than merely tested**. Generalize this: *the cure for controller/kernel divergence is to not duplicate
the authoritative value.*

Where duplication is genuinely unavoidable:

1. Every PUSH is a **compare-and-swap** carrying the **expected previous** generation.
2. Generations move **strictly forward**. Equal or lower is rejected.
3. The generation binds into **both** the signed intent **and** the stored proposal — either alone
   leaves a gap.
4. Both sides move in one transaction, or neither does.
5. Unavailability is reported as `UNAVAILABLE`, never silently as denial.

### What the consumer can and cannot detect — stated, not glossed

> **RESIDUAL.** A consumer that verifies generation **ordinality** has not thereby verified
> **content**. A plane that advances the generation correctly while pushing a *wrong roster* is not
> detected, and no amount of generation discipline changes that.

This is exactly why **guardian membership is KERNEL-REQUIRED** in vNext rather than externalized:
the only way to avoid trusting a roster-pushing controller is to not have one.

---

## 8. Authority graph and closure

### 8.1 Direct authority

| Principal | Direct capabilities (vNext) |
|---|---|
| Spending credential | MOVE_ASSETS, CHANGE_CREDENTIALS |
| PQ credential | (conjunctive component of the above) |
| Guardian (individual) | RECOVERY_INITIATION, RECOVERY_SUPPORT |
| Guardian quorum | APPROVE_RECOVERY, CANCEL_RECOVERY, CHANGE_GUARDIANS, ENTER_CONTAINMENT |
| Policy plane | CHANGE_POLICY (subtractive only) |
| Credential plane | — |
| Verifier | — (answers a query; holds nothing) |
| Emergency principal | ENTER_CONTAINMENT **only** |
| Migration authority | MIGRATE — **not** SELECT_DESTINATION_KERNEL |
| **Kernel admin** | **NONE — the principal does not exist** |
| Assurance observatory | **NONE** |
| WalletWall infrastructure | **NONE** |
| Arbitrary external caller | May *relay* an authorized action; holds nothing |

### 8.2 Closure results

Closure includes outcomes reachable through intermediate state changes.

| Principal | Closure adds | Reaches assets? |
|---|---|---|
| Spending credential | — | **Yes** (directly) |
| Guardian quorum | CHANGE_CREDENTIALS → MOVE_ASSETS | **Yes — ACCEPTED RESIDUAL, asserted positively** |
| Emergency principal | — (containment self-expires; no EXIT capability) | **No** |
| Migration authority | — (destination is kernel-bound) | **No** |
| Policy plane | — (subtractive only) | **No** |
| Assurance | — (closure is **empty**) | **No** |
| Guardian **plane** *(if ever externalized)* | CHANGE_GUARDIANS → APPROVE_RECOVERY → MOVE_ASSETS | **Yes — which is why it is not externalized** |

### 8.3 Coalitions

| Coalition | Result |
|---|---|
| Credential + guardian minority | No amplification — minority holds no quorum capability |
| Guardian quorum | Asset control (accepted, §2.2) |
| Emergency + credential | Credential's own authority only; containment adds nothing |
| Migration authority + malicious destination | **Blocked** — the destination code hash is bound and re-checked at execution |
| Plane controller + credential | Credential's own authority only; planes are subtractive |

**OBSERVED contrast.** Under the current architecture the coalition table is worse in one specific
place: the contract admin, **alone**, reaches `{CHANGE_CREDENTIALS, MOVE_ASSETS}` for every `PqOnly`
vault, because in `PqOnly` mode `needEcdsa == false` and the swappable verifier is the sole
authenticator, and the mock-verifier guard runs only at `createVault`. Today this is bounded only by
the fact that `PqOnly` vaults cannot be *created* while the mock is wired — i.e. by a configuration
accident rather than a mechanism.

---

## 9. Recovery architecture

### The invariant

> **I-RECOVERY-SOVEREIGNTY.** Within the declared fault envelope (§2), permanent failure or
> Byzantine behaviour of any *replaceable* external plane cannot permanently eliminate every
> authorized recovery path.

Supported by four narrower, individually testable properties:

> **I-RECOVERY-LOCALITY.** Recovery initiation, support, and execution perform **zero external
> calls** *and* depend on **no globally-mutable state**.

The second clause is not redundant. OBSERVED: `executeRecovery` makes no external call yet is
`whenNotPaused`, reading a single global `_paused` bit. Locality stated only over *calls* would
certify a recovery path that one principal can freeze for everyone.

> **I-RECOVERY-NONVETO.** No principal holds an unbounded veto over an otherwise-valid recovery.

> **I-RECOVERY-TERMINATION.** Every quorum-approved request leaves the system by execution,
> cancellation, or **expiry — and expiry requires no principal to act.**

> **I-APPROVED-REQUEST-PRESERVATION.** Once a request reaches quorum, a guardian-set replacement
> cannot clear it.

*(Invariant names are deliberately shared with the sibling guardian lane where they denote the same
property. Divergent names for one property is how two lanes come to disagree without noticing.)*

### Recovery independence does not, by itself, yield an EXIT

A circularity that is easy to miss **precisely because the reassuring fact hides it.** "Recovery
makes zero external calls" is true and valuable — but recovery restores **authority**, not
**liquidity**. A user who recovers credentials into a vault whose withdrawal path still depends on a
dead or hostile plane has recovered control of assets they still cannot move.

> **I-EXIT-REACHABILITY.** Restoring authority must be composed with a path that actually removes
> assets. For every reachable state, at least one of {ordinary withdrawal, migration execution} must
> be available **without consulting any plane**.

This is why §6 keeps `MIGRATION_EXECUTION` available in **every** state including `RETIRED`, and why
§13 binds the migration destination in the kernel: migration is the exit that makes recovery
meaningful. Recovery sovereignty and exit reachability are two invariants, not one, and satisfying
only the first produces a vault that is recoverable and still unusable.

**Explicitly NOT adopted: `I-STRONGER` as literally worded.** "Successful recovery must leave the
vault no more dependent on a previously compromised (b) than before" is a monotonicity claim across a
transition whose two sides have an identical power set — it is **vacuous and satisfied today**. It
must not be cited as assurance.

---

## 10. Assurance versus actuation

> **OBSERVATION ≠ AUTHORITY.**

```
Assurance Observatory  ──produces──>  evidence
                                          │
                                          ▼
                        Constrained Actuator  (authorized INDEPENDENTLY)
                                          │
                                          ▼
                    bounded, self-expiring, authority-REDUCING transition
```

The assurance plane must never transfer assets, replace credentials, replace guardians, choose a
migration destination, or hold arbitrary pause authority. Its authority closure is asserted to be the
**empty set** (mutant M12).

Where automated response is wanted, the actuator is a **separate principal** whose closure is
computed like any other's, and whose only capability is `ENTER_CONTAINMENT` — bounded by §6's
self-expiry, so a compromised actuator obtains **denial for a bounded window**, never loss and never
weakening.

NIST SP 800-160 v2r1 supports this shape directly: Table D-4's Predefined Segmentation examples
include, verbatim, isolating security functions from non-security functions.

---

## 11. Capability planes and plane lifecycle

| Plane | Holds | Failure ⇒ | Replaceable by |
|---|---|---|---|
| Policy | Spending restrictions | Denial only | Vault's own authority |
| Verifier (per scheme) | Signature checking | Denial only (floor still applies) | Vault's own authority, delayed |
| Assurance | Observations | Nothing | Anyone; it holds no authority |

**Guardian membership and credential commitment are NOT planes.** They are kernel-resident (§4.2).

Lifecycle: propose → delay → **re-check the destination is code-bearing at APPLY, not only at
PROPOSE** → apply → matured proposals **expire**. A rejected apply must mutate nothing, leaving both
the active value and the pending proposal recoverable. *(All four rules are OBSERVED lessons from the
current implementation and are adopted unchanged.)*

> **A reusable lesson worth stating separately: a timelock on *replacing* a component does not bound
> state changes *inside* it.** OBSERVED: `AttestationPQCVerifier.updateAttestor` is immediate and is
> not covered by the vault's two-day verifier timelock. Every plane admitted to the design must have
> its **internal** governance examined, not only its replacement path.

---

## 12. Cryptographic lifecycle

**The kernel stores a credential as:** `schemeId`, `credentialCommitment`, `credentialGeneration`,
`verifierGeneration`.

### The distinctions the kernel must keep separate

`algorithm standard` ≠ `implementation` ≠ `verifier bytecode` ≠ `active verifier generation`
≠ `credential generation` ≠ `runtime evidence`. FIPS 204 §8/§14 and NIST CSWP 39-upd1 §5.1 layer these
as standardized → CAVP-validated implementation → CMVP-validated module, and FIPS 204 states plainly
that "conformance to this standard does not ensure that a particular implementation is secure".

### The security-transition rule

> **A scheme may be activated only if its kernel-recorded strength class is greater than or equal to
> that of every currently-ACTIVE scheme. Strength is kernel-recorded at activation and is NEVER read
> from the verifier. No cryptographic generation may become weaker merely because it has a larger
> version number.**

Statuses form a transition lattice: `ACTIVE → DEPRECATED → DISALLOWED`, one-way.
Verifier *implementations* are replaceable **within** a scheme (agility); *schemes* are governed
separately and monotonically (anti-downgrade). Mutants **M10** and **M18**.

### Why `algorithmId()` cannot be the strength signal

NIST CSWP 39-upd1 §3.1 treats an algorithm identifier as a **coordination label assigned and
interpreted by the relying party's registry** — never a property asserted by the entity being
identified. The observed `algorithmId()` **inverts** this: the entity whose strength is in question
asserts the label, and `IPQCVerifier`'s own documentation concedes it "carries no security guarantee
by itself". A denylist of exactly one self-reported value is not a downgrade control.

FIPS 204 §3.3 supplies a **real externally-defined order** the kernel can encode as immutable
constants: ML-DSA-44 (cat 2) < ML-DSA-65 (cat 3) < ML-DSA-87 (cat 5).

> **Do not embed unnecessary algorithm-specific constants in the kernel** — but *do* embed the two
> that pay for themselves: the strength order above, and FIPS 204 §3.6.2's structural length
> rejection, which is a "shall" and costs only integer comparisons.

**Unknown schemes** are rejected. **Broken verifier** ⇒ denial, never forgery, because the floor is
conjunctive. **Hybrid authorization** is the default posture during transition.

---

## 13. Migration protocol

Migration is among the most powerful capabilities in the system and is specified accordingly.

**The binding must carry all of:** source vault · destination vault · **destination kernel code
hash** · destination generation · asset set · credential commitment · guardian commitment · policy
commitment · expected safe state · chain id · nonce · deadline.

**The destination code hash is re-checked at EXECUTION, not only at preparation** — a destination
that was code-bearing and correct at proposal time can change before the delay elapses. This is the
same lesson the current `applyPQVerifierUpdate` already encodes.

**Migration authority is strictly stronger than ordinary spending authority**, and is therefore
decomposed so that **no single principal holds it**: the kernel binds the destination at preparation,
and execution requires the recovery quorum. `MIGRATION_AUTHORITY` alone holds neither
`SELECT_DESTINATION_KERNEL` nor `MOVE_ASSETS` (asserted).

**Explicitly rejected: `migrateEverything(arbitraryAddress)`.** An escape hatch that can send all
assets to a chosen address is indistinguishable from theft (hazard H-11).

Handled: partial migration is disallowed (the asset set is bound); tokens that fail transfer abort
the whole migration; queued withdrawals and pending recoveries must be resolved or explicitly carried;
replay is bound by nonce, chain id, and deadline; the source retires to `RETIRED`, which remains
migration-executable so retirement is never a trap.

Mutants **M8** and **M9**.

---

## 14. Systemic shared dependencies

| Component | Compromised | Unavailable | Blast radius |
|---|---|---|---|
| Kernel implementation generation | Every vault cloned from it | n/a (immutable code) | **cohort** (that generation) |
| Factory | Future vaults only — **no authority over deployed clones** | No new vaults | **cohort**, future only |
| Verifier (if one address is stamped into many clones) | Cohort authorization | Cohort denial | **cohort by default, per-vault by capability** |
| Policy plane | Cohort denial | Cohort denial | **cohort**, escapable |
| Guardian membership | — | — | **per-vault** (kernel-resident) |
| Credential commitment | — | — | **per-vault** |
| EntryPoint *(only if ERC-4337 adopted)* | **Total, across every adopting account** | All UserOps fail | **system-wide** |
| WalletWall infrastructure | Nothing | Nothing | **none, by requirement** |

**The honest statement.** vNext does **not** achieve pure per-vault isolation, and claiming it would
be false. If the factory stamps one verifier address into every clone it deploys — the obvious
default — a verifier compromise is **cohort-wide**. What changes versus today is the *modality*: that
coupling becomes a **default a vault can leave using its own authority**, rather than a **global slot
only a global admin can move**. Default cohort, escapable per-vault, is a materially weaker coupling
than mandatory system-wide — and it is a smaller claim than "isolation".

---

## 15. Operational survivability — WalletWall disappearance

**Requirement (G5).** If the company, frontend, backend and hosted APIs all disappear, a user must
still be able to inspect the vault, construct authorization payloads, execute ordinary actions,
recover, migrate, and verify the active code.

**This is not satisfied by saying "self-custody".** The required artifacts are:

| # | Artifact | Purpose | Status |
|---|---|---|---|
| 1 | Public kernel source, per generation | Read what the code does | OBSERVED (repo is public) |
| 2 | ABI, per generation | Construct calls | OBSERVED |
| 3 | **EIP-712 typed-message schemas**, with domain derivation | Construct signatures offline | PROPOSED |
| 4 | Deployment registry: factory address, implementation address per generation, chain id | Know what to talk to | PROPOSED |
| 5 | **Reproducible build** (pinned solc, evmVersion, optimizer runs, no viaIR) | Rebuild and compare | OBSERVED — pinned at solc 0.8.24, cancun, runs 200 |
| 6 | **Runtime code hashes** per generation, plus the EIP-1167 derivation | Verify a clone from its code alone | PROPOSED |
| 7 | Reference CLI, no network services | Exercise every path | Partially OBSERVED |
| 8 | Written reference recovery procedure | Human-executable | PROPOSED |
| 9 | Migration specification | Exit a dead generation | PROPOSED |

**Why item 6 is the load-bearing one, and why C makes it work.** Because an EIP-1167 clone's
implementation address is a `PUSH20` operand inside the clone's own runtime code, a user with only
`eth_getCode` — no archive node, no event history, no trust in the deployer — computes
`keccak256` of the 45-byte template with the expected implementation and compares. Under an
upgradeable proxy this check is **impossible in principle**, because the code hash is identical
across every implementation the proxy will ever point at.

> **UNRESOLVED.** The attestation verifier path currently depends on a trusted off-chain attestor.
> An attestor that disappears cannot be replaced without action by someone, and
> `AttestationPQCVerifier.updateAttestor` is itself immediate rather than timelocked. G5 is
> **not yet met** on that path. Mutant M15 pins the requirement; it does not close the gap.

---

## 16. Proof tiers

Assurance complexity is bounded by matching method to consequence, not by applying every method
everywhere.

| Tier | Scope | Evidence required |
|---|---|---|
| **T0** | `I-CUSTODY-CONSERVATION`, `I-NO-GENERIC-EXECUTION`, and the absence of any unbounded terminal veto | State model + **stateful fuzzing** + mutation testing + **runtime-byte measurement**; formal verification where affordable |
| **T1** | `I-RECOVERY-SOVEREIGNTY`, `I-RECOVERY-LOCALITY`, `I-RECOVERY-NONVETO`, `I-RECOVERY-TERMINATION`, `I-APPROVED-REQUEST-PRESERVATION`, `I-EXIT-REACHABILITY`, `I-GENERATION-MONOTONE`, `I-NO-SILENT-DOWNGRADE`, `I-MIGRATION-BINDING`, `I-ASSURANCE-NONACTUATION` | State model + mutation testing + **AST-backed structural analysis** + adversarial scenarios |
| **T2** | `I-PLANE-CONJUNCTIVE`, `I-SYNCHRONY`, `I-PARITY` | Integration tests + mutation testing + parity checks |
| **T3** | Ordinary functionality | Unit and integration tests |

> **Every T0/T1 load-bearing claim must have at least one deliberately broken discriminator.**
> An invariant with no killing mutant is decoration.

**The vacuity rule, which is not optional.** A mutation planted on a branch the scenario never
reaches will report a clean kill while proving nothing. Every mutation assertion in this lane
therefore additionally requires that the mutated guard was **actually evaluated**
(`model.exercised`). This caught a real methodological error during authoring: an *asserting* test
fixture was crashing on the way to the state under test, so three mutants were being "killed" by
setup assertions rather than by their invariants. **A discriminator must OBSERVE a failure, never
assert on the way to it** — otherwise "the scenario could not be set up" is silently scored as "the
invariant held".

---

## 17. Mutation matrix

Eighteen mutants, each flipping exactly **one** guard so that a kill is attributable.
All 18 are killed, with the vacuity guard satisfied on every one.
See `test/VaultVNextArchitectureModel.test.ts`.

| # | Mutant | Invariant that kills it |
|---|---|---|
| M1 | Generic module gains arbitrary execution | I-NO-GENERIC-EXECUTION |
| M2 | Stale credential generation remains valid | I-GENERATION-MONOTONE |
| M3 | Stale guardian generation remains valid | I-GENERATION-MONOTONE |
| M4 | Failed plane becomes mandatory for its own recovery | I-RECOVERY-SOVEREIGNTY (circularity) |
| M5 | Controller/kernel state diverges undetected | I-SYNCHRONY |
| M6 | Emergency authority creates stronger authority | Authority monotonicity |
| M7 | Emergency authority permanently vetoes recovery | I-RECOVERY-NONVETO |
| M8 | Migration omits destination code-hash binding | I-MIGRATION-BINDING |
| M9 | Migration permits generation substitution | I-MIGRATION-BINDING |
| M10 | Crypto generation downgrades silently | I-NO-SILENT-DOWNGRADE |
| M11 | Always-true verifier treated as strong evidence | I-PLANE-CONJUNCTIVE |
| M12 | Assurance observatory actuates custody | I-ASSURANCE-NONACTUATION |
| M13 | Policy plane transitively obtains asset authority | I-PLANE-CONJUNCTIVE |
| M14 | Guardian controller's indirect takeover path omitted | Authority-closure completeness *(inverted polarity: the clean model must **report** the path)* |
| M15 | Company-hosted service required for recovery | I-RECOVERY-SOVEREIGNTY |
| M16 | One-sided reference-model divergence | I-PARITY |
| M17 | Unavailable control plane strands local recovery | I-RECOVERY-LOCALITY |
| M18 | Old generation crosses a generational boundary | I-GENERATION-MONOTONE |

---

## 18. Relationship to the hazard register

`docs/Vault_vNext_Hazard_Register.md` holds 26 entries. This document states the architecture; the
register states what can go wrong, who can cause it, and what remains accepted. Every T0/T1 hazard
maps to at least one invariant here, and every accepted residual is named in both.

---

## 19. Derived kernel byte and complexity budget

The budget follows the architecture. The architecture is not weakened to hit a byte target, and the
mission's arbitrary 10–15 KB figure is struck.

### MEASURED this session — clean, non-instrumented compile at `aaba4d2`

`npm run compile && npm run validate:bytecode-size` (solc 0.8.24, cancun, optimizer on, runs 200,
viaIR not set):

| Contract | Runtime | % of 24,576 | Headroom |
|---|---|---|---|
| `WalletWallVault` | **23,231** | 94.5% | **1,345** |
| `StablecoinVaultSimulator` | 22,867 | 93.0% | 1,709 |
| *(creation bytecode, `WalletWallVault`)* | **24,574** | — | — |

**Disposable spike, applied → measured → reverted → identity proven restored:**

| Spike | Runtime | Headroom |
|---|---|---|
| EIP-1167 clone factory, atomic deploy+initialize, CREATE2 | **1,238** | **23,338** |

`contracts/` tree hash after revert: `c1ef598bfff351f4698e4972b664367100f2b483`, byte-identical to
`origin/main:contracts`. No spike source remains.

### What the numbers establish

1. **The current kernel has exhausted its evolution budget.** Two agreed security fixes are bidding
   for the same 1,345 bytes: guardian hardening at 675–1,650 B (an unresolved 2.4× disagreement) and
   recovery proof-of-possession needing 464 B against 339 B available. **At least one provably
   cannot fit.** The threat model has become limited by EIP-170 rather than by engineering judgement.
2. **Architecture B is not constructible.** A `new Vault{salt}(…)` factory must embed 24,574 bytes of
   creation bytecode in its own runtime, exceeding the ceiling before any other logic.
3. **Architecture C's deployment path costs 1,238 bytes** — 5% of the ceiling — for a factory that
   deploys and initializes atomically.

### Target budget for the vNext kernel

| Quantity | Value | Basis |
|---|---|---|
| EIP-170 ceiling | 24,576 | Protocol |
| Safety margin (redesign trigger) | **600** | Adopted from the sibling lane's stop condition |
| Future-change reserve | **2,000** | ≥ the largest single unresolved fix (1,650 B) plus margin |
| **Target kernel ceiling** | **≈ 21,900** | 24,576 − 600 − 2,000, rounded down |

> **Every forward byte figure is a LOWER BOUND.** ~29.8% of the current vault's runtime is
> utility-Yul and unmapped buckets not emitted as `generatedSources`. Two further hard constraints
> carry over: `initiateRecovery` sits at DUP/SWAP reach **15**, one below the ceiling, and
> `_authorizeRotation` / `withdraw` / `queueWithdrawal` sit **at 16**. Those functions are frozen
> against new parameters or struct members.
>
> **STOP CONDITION.** Measure at the first compiling implementation, from a clean non-instrumented
> build — coverage instrumentation inflates measured sizes and must never satisfy or vacuously fail
> a production-byte claim. If the kernel lands below **600 bytes** of headroom: redesign or
> externalize. Do not weaken the gate.

**UNRESOLVED, and stated rather than guessed: no candidate vNext kernel has been compiled.** Removing
the tenant dimension deletes seven per-tenant mappings and their keying, but the logic remains, and
the sibling lane's own experience is that independent estimates of the same change disagreed by 2.4×.
**No number for the vNext kernel's size appears in this document, because none has been measured.**

---

## 20. Explicit non-goals

1. **Not a modular smart account.** No module registry, no executor modules, no fallback handlers.
2. **Not upgradeable.** Deliberately. The price is that kernel defects are permanent (§2.2 item 1) —
   the strongest argument against this architecture, accepted with open eyes.
3. **Not ERC-7579 compatible**, and not seeking to be.
4. **Not ERC-4337 in generation 1** (§5).
5. **Not a claim of NIST compliance.** These are engineering inputs. **No compliance mapping has been
   performed.**
6. **Not production custody**, not audited, not formally verified.
7. **Not a conformance proof.** The model proves architectural coherence and mutant discrimination.
   It imports no production contract and establishes nothing about any Solidity.
8. **Not pure per-vault isolation** (§14).

---

## 21. Implementation sequencing

Ordered by dependency; each step gated on the previous.

| # | Step | Gate |
|---|---|---|
| **0** | **Fix `renounceOwnership()` in current `main`** — override to revert. Measured at **+8 bytes**. Independent of vNext. | Hazard H-01 is the only entry in the register with **no recovery path**. It should not wait for an architecture. |
| 1 | Owner decisions D1–D6 (§22) | Nothing below is safe to build first |
| 2 | Freeze the kernel state layout and the safe-state lattice | Model conformance |
| 3 | **Compile a skeleton kernel and MEASURE it** | Must clear the 21,900 target with ≥600 B headroom, else redesign |
| 4 | Kernel: custody, execution, nonce, credential floor | T0 tests + fuzzing |
| 5 | Kernel: guardians, recovery, safe-state lattice | T1 tests + mutants M2/M3/M4/M6/M7/M17 |
| 6 | Kernel: migration | T1 + mutants M8/M9 |
| 7 | Factory + clone deployment + **atomic** initialization | Address-derivation and front-running tests |
| 8 | Crypto scheme lifecycle | Mutants M10/M11/M18 |
| 9 | Policy plane as a subtractive plane | Mutants M13/M5 |
| 10 | Assurance observatory, then a constrained actuator | Mutant M12 |
| 11 | Reference-model parity enforcement | Mutant M16 |
| 12 | Company-disappearance artifact set (§15) | Mutant M15 |

**Step 0 is deliberately placed before the owner decisions.** It is a two-line change to current
production code that closes a permanent, unrecoverable, cross-tenant freeze. It does not depend on
any vNext verdict, and it is out of scope for *this* design-only lane.

---

## 22. Open owner decisions

| # | Decision | Why it cannot be settled here |
|---|---|---|
| **D1** | **Is the accepted unrecoverable list (§2.2) correct?** Specifically: is guardian-majority takeover accepted, or must recovery require a second independent factor? | Pure risk appetite. It changes the guardian design, the byte budget, and the recovery UX. Every downstream verdict rests on it. |
| **D2** | **Who authorizes migration execution** — guardian quorum, credential authority, or both? | A security/liveness trade with no technically forced answer (H-11). |
| **D3** | **Is ERC-4337 adopted at all?** If yes, the unconditional EntryPoint trust and the [OP-011] timestamp conflict must both be accepted. | Product decision with an unavoidable, spec-mandated security cost (§5). |
| **D4** | **Does the factory stamp a shared verifier into every clone?** This is the difference between cohort and per-vault default coupling (§14). | Operational vs isolation trade. |
| **D5** | **What is the containment bound**, and who holds the emergency principal? | Bound must exist (§6); its value is an operational choice. |
| **D6** | **Is the policy-engine disable a time-bounded exception or a standing configuration?** NIST E.8 Continuous Protection explicitly permits an intentional, exception-case override but not a standing disable — so the classification determines whether the current behaviour is inside or outside the principle. | Governance choice, and it changes what the mechanism must enforce. |
| **D7** | **Does PR #178's ECDSA-local proof-of-possession leg ship**, given its budget shortfall and its liveness cost? | Blocked on D1 and on the byte budget. |

---

## 23. Relationship to PR #177 and PR #178

Both are treated as **empirical evidence**, not as mandatory vNext inputs. Neither is modified by
this lane and neither is a base for it.

**PR #177 (guardian authority lifecycle).** Its C5 external Guardian Authority Controller is
**not adopted for vNext** — not because it is wrong for the current architecture, but because the
constraint that forced it disappears. That controller exists to solve two problems: the
`UNGUARDED → GUARDED` bootstrap (because `createVault` never writes a guardian set) and the
unrotatable (b). Under C, guardians are bound **at deploy time, atomically**, so no unguarded window
exists; and identity is no longer a principal. Externalizing guardian membership would instead
*create* hazard H-19 and would place a roster-pushing controller inside the TCB — which its own §4.8
honestly concedes, since the consumer verifies generation ordinality and never roster content.
Its invariant *names* are adopted where they denote the same property, and its `renounceOwnership`
finding (§9a) is confirmed here independently.

**PR #178 (recovery credential proof-of-possession).** Its root cause is confirmed firsthand and
**vNext eliminates it structurally** by requiring possession proof on every credential write path
rather than adding a second mechanism to one of them. Its byte arithmetic changes: the shortfall
(464 B needed, 339 B available) is a property of the 1,345-byte monolith, not of the design. Its
deeper lesson is adopted directly: **a mitigation can worsen liveness**, and **verifier quality is a
separate axis from algorithm standardization** — which is why §12 separates scheme strength from
verifier implementation.
