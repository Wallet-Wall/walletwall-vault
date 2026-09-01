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

> ## DISPOSITION — **ARCHITECTURE READY FOR MINIMAL-KERNEL PROTOTYPE**
>
> **What this authorises:** compiling the **first disposable / minimal kernel candidate**, so its
> size and its `immutableReferences` can be measured against §19's stop condition.
>
> **What this does NOT authorise, and the distinction is the whole point:** production
> implementation, deployment, or the creation of a production `VaultKernel.sol`. "Ready for
> prototype" means the architecture is **coherent enough to compile against** — that its authority
> graph is determined, its size model is sound, and its remaining unknowns are things to *measure*
> rather than things to *decide*. It is not a statement that the design is correct.
>
> **What changed to earn it.** Every previously-standing blocker is closed: the clone-target runtime
> is **MEASURED** (§19.1), **D1** and **D8** are **DECIDED** (§22), and the **H-22 prerequisite is
> WITHDRAWN** as unsound (§13.0a). Two further defects were found and corrected in this document's
> own reasoning — an **EIP-170/initcode category error** (§19.0) and an over-broad **code-identity**
> claim (§15.1a). Six blockers remain (§25.5); **all six are engineering work or declared residuals,
> none is an open adjudication.**

---

## 0. Status legend, and why it is enforced pedantically

Five categories, never interchangeable. Any statement in this document belongs to exactly one.

| Status | Meaning |
|---|---|
| **OBSERVED** | Verified firsthand in source at `origin/main` `15a44016844fb705dc6044020508cf68697ebb74`, tree `cf379aa5796023a463fb8fb9f489c5cf00140e3f`, package `0.13.3` — i.e. **after PR #180 merged**. Cited. |
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

> **MEASURED CORRECTION — the right-hand column above is right, and the reassuring reading of it is
> wrong.** `extcodehash(clone)` is a total function of the implementation **address**. It is *not* a
> function of the implementation's **code**, and the two are not interchangeable, because
> **an implementation's own runtime code hash is address-dependent.**
>
> Spike, MEASURED this session: two deployments of **byte-identical source** at two addresses produced
> runtime code differing in **51 of 23,239 bytes**. Every differing byte lies inside a declared
> immutable slot; the slot at offset **18,627** holds the contract's **own address**. The cause is
> `WalletWallVault`'s inherited OpenZeppelin `EIP712`, whose `_cachedThis` and `_cachedDomainSeparator`
> are `immutable` and therefore baked into runtime bytecode. The artifact reports **seven** 32-byte
> immutable slots; five are address-independent and were byte-identical across the two deployments.
>
> Three consequences follow, and none of them was stated in the earlier revision:
> 1. **NARROWED — the previous wording overclaimed and is corrected here.** It said there is
>    *"no single publishable 'audited kernel code hash'"*. **Too broad.** What does not necessarily
>    exist is **one universal source-level runtime hash valid for every deployment address**. What
>    always exists is an **authoritative runtime code hash for a PARTICULAR deployed
>    implementation** — `extcodehash(impl)` is a fact about that account, and nothing about
>    immutables makes it unavailable. A verifier who knows only a *constant* cannot check anything
>    when immutables are address-derived; a verifier who knows the *expected address* can compute
>    both the expected clone hash and the expected implementation hash. The check is
>    **address-parameterised, not absent**. §15.1a states the three identities this splits into.
> 2. **A correction to §3.2 R3.** That section says `WalletWallVault` "declares **no** `immutable`
>    variables". True of the contract's own source; **materially misleading**, because it *inherits*
>    seven, two of them address-derived. The conclusion R3 draws — that every plane pointer is storage
>    and therefore per-clone — survives untouched. The supporting sentence does not, and is corrected
>    in place.
> 3. **A kernel requirement falls out of it.** The vNext kernel must **not** inherit an
>    address-caching `EIP712`. Two independent reasons converge on one change: the cache can never hit
>    for a clone (dissent D2), *and* the cached immutables destroy code-hash stability (this note).
>    Removing it makes the kernel's runtime code address-independent, which restores exactly the
>    single-constant comparison item 6 of §15 wants.
>
> §15 states the resulting offline verification procedure in full.

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

**Architecture B — a full contract deployed per vault. SPLIT: B1 rejected on measurement, B2
constructible and rejected on cost. The earlier blanket claim is withdrawn.**

> **CORRECTION, recorded not silently edited.** An earlier revision of this document said
> *"Architecture B is not constructible."* **That claim was too broad and is withdrawn.** What was
> measured was one *construction* of B — a Solidity factory that writes `new Vault{salt}(…)`. A
> contract-per-vault architecture does not require that construction, and the generalisation from
> "this factory does not fit" to "contract-per-vault cannot be built" was not established. It is now
> tested rather than assumed.

Two constructions of B were built, compiled and measured this session, alongside C and a fourth
candidate. All four are disposable spikes: applied → measured → reverted → restoration proven (§19).

| | **B1** Solidity `new Vault{salt}` | **B2** generic CREATE2 deployer | **C** EIP-1167 clone | **C2** EIP-1167 + immutable args |
|---|---|---|---|---|
| Factory runtime, MEASURED | **24,866 — OVER EIP-170 by 290** | **657** | **1,760** | same 1,760 factory |
| Constructible? | **No.** solc itself warns | Yes | Yes | Yes |
| Per-vault deploy gas, MEASURED | n/a | **5,181,105** | **63,692** | **69,342** |
| Relative to C | — | **81.3×** | 1.00× | 1.09× |
| Vault runtime deployed per vault | 23,239 | 23,239 | **45** | **65** (45 + 20 arg bytes) |
| Bound on that runtime | `NETWORK_RUNTIME_LIMIT` | `NETWORK_RUNTIME_LIMIT` | `NETWORK_RUNTIME_LIMIT` (borne by the **implementation**, not the clone) | same |
| Vault **initcode** per vault, and its bound | 24,582 vs `NETWORK_INITCODE_LIMIT` **49,152** | same | n/a — a clone runs no initcode of its own | n/a |
| Vault identity | address | address | address | address |
| Per-vault Solidity `immutable` | yes | yes | **no** | **no — but see immutable ARGS** |
| Per-vault immutable DATA | yes | yes | no | **yes, and code-identity-bound** |
| Constructor runs | yes | yes | **no** | **no** |
| Uninitialised-clone front-running | not possible | not possible | must deploy+init atomically | must deploy+init atomically |
| CREATE2 address commits to | full initcode (24,614 B) | full initcode (24,614 B) | 45-byte template + impl | template + impl + **args** |
| Hops in the code-identity chain | 1 | 1 | 3 | 3 |
| Factory is a shared dependency | yes, and it names the child | **no — it names nothing** | yes | yes |
| EIP-712 cached domain fast path | works | works | **permanently dead** | **permanently dead** |

**B1 — REJECTED, and now decisively rather than marginally.** Solidity compiles `new Vault{salt}(...)`
by embedding the callee's **entire creation bytecode** into the factory's own runtime. MEASURED: the
factory's runtime bytecode is **24,866 bytes against the 24,576 ceiling — over by 290** — and solc
emits its own diagnostic, *"Contract code size is 24866 bytes and exceeds 24576 bytes"*. There is no
dispatcher, no argument encoding and no CREATE2 helper in that figure beyond what the one function
needs. B1 is not deployable.

> **B1's rejection is a RUNTIME failure of the FACTORY, and nothing else — a parenthetical claiming
> otherwise is STRUCK.** The previous revision added: *"after #180 the child's creation bytecode is
> 24,582 B, which **alone** exceeds the runtime ceiling."* **A child's initcode is not governed by
> the runtime limit** (§19.0), and 24,582 is comfortably inside
> `NETWORK_INITCODE_LIMIT(ethereum, current) = 49,152`. The load-bearing arithmetic is entirely on
> the factory side and is unaffected:
>
> ```text
> factory runtime  24,866  =  embedded child initcode 24,582  +  284 B of dispatch/CREATE2
>                  24,866  >  NETWORK_RUNTIME_LIMIT = 24,576   =>  B1 REJECTED, by 290 bytes
> ```
>
> The child's initcode still matters — but only because Solidity **embeds it into the factory's
> runtime** (`feedback_solidity_new_embeds_full_creation_bytecode_in_the_factory`), so it is
> weighed as a *component of a runtime figure*, never compared to a runtime limit on its own.

**B2 — CONSTRUCTIBLE, and cheap to build.** A deployer that takes `bytes initcode` as **calldata** and
CREATE2s it embeds nothing and names no child. MEASURED at **657 bytes** of runtime — *smaller than the
clone factory*. It is also not a WalletWall dependency in any meaningful sense: a canonical public
deterministic CREATE2 deployer already exists on most chains, and such a deployer **holds no authority
over anything it deploys**. So the "shared factory" dissent (D4 below) does not apply to B2 at all.

**B2 is rejected on measured cost, not on constructibility.** Deploying the real `WalletWallVault`
through it costs **5,181,105 gas per vault** against **63,692** for a clone — a **marginal** ratio of
**81.3×**. That gap is *intrinsic, not overhead*: a bare `CREATE` of the same vault costs 5,168,967,
so the deployer adds only **12,138 gas**. The cost is the protocol's 200 gas per runtime byte ×
23,239 bytes ≈ 4.65 M, plus 24,614 bytes of calldata. **B2's per-vault cost scales with the kernel's
size**, which is the one quantity §19 shows is already out of budget.

> **A MARGINAL ratio is not a cost comparison, and §19.2 replaces it with one.** 81.3× compares
> per-vault deployment while silently pricing C's one-time implementation at zero. On **total**
> generation economics the measured break-even is **N = 2**; at `N = 1` **B2 is actually cheaper**,
> and the realised advantage reaches **34.65×** at `N = 1,000` — never 81×, at any fleet size. The
> verdict is unchanged and the *reason* is now stated correctly.

**C2 — ADOPTED as a refinement of C.** OpenZeppelin 5.6.1 ships
`Clones.cloneDeterministicWithImmutableArgs` / `fetchCloneArgs`, which append per-clone bytes **after**
the 45-byte template. MEASURED: this costs **+5,650 gas (+8.9%)** over a plain clone and produces a
65-byte clone for 20 bytes of argument. It matters far beyond the price, because `fetchCloneArgs` reads
those bytes with `extcodecopy(instance, …, 0x2d, …)` — **the arguments are part of the clone's own
runtime code**. Therefore they are committed to by `extcodehash(clone)` *and* by the CREATE2 address.
MEASURED: two clones of the *same* implementation with *different* args have different code hashes, and
the argument suffix reads back byte-exact.

> **This partially reverses dissent D1.** A clone cannot have per-clone Solidity `immutable`s — that
> remains true. It *can* have per-clone immutable **data**, verifiable from `eth_getCode` alone. The
> correct rule is therefore narrower and more useful than "clones cannot hold immutable state":
> **values that must never change belong in immutable args; values that must remain replaceable belong
> in storage.** A verifier *implementation* must stay replaceable (agility, and hazard H-06), so it
> belongs in storage. A vault's genesis commitments — the kernel generation it was born under, its
> chain binding, and the **cryptographic floor it may never fall below** (§12) — must never change, so
> they belong in args, where an offline observer can read them out of the code.

**VERDICT: C, refined to C2 — confirmed, but on a corrected and much narrower basis.** C is selected
because it wins on **total generation cost from a fleet of two vaults upward** (§19.2), not because B
is unbuildable and not on the marginal 81× ratio alone. **The condition under which this
verdict flips is stated so it can be tested later:** if per-vault deployment gas ceases to be a product
constraint *and* the kernel needs per-vault immutables richer than a byte string can carry, **B2 wins**,
and it wins with a shorter code-identity chain (§15) and no atomic-initialisation requirement. That is
a live alternative, not a dead one.

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
| Guardian **authority** — commitment, threshold, generation | **KERNEL-REQUIRED** | Attacker quorum ⇒ loss (H-19) | Recovery unreachable; **and replacing the plane needs guardian authority ⇒ circular** |
| Guardian **roster bytes** — the member addresses themselves | **NOT KERNEL-RESIDENT** (§4.2b) | — (a forged roster fails the commitment check) | Roster preimage unavailable ⇒ recovery unreachable (**new hazard H-27**) |
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

### 4.2b The minimum guardian TCB — a narrowing of the previous verdict

The previous revision classified **guardian membership** as KERNEL-REQUIRED and stopped there. The
question it did not ask is the one that decides the size of the TCB:

> **Not "can guardian logic be externalised?" but "what is the MINIMUM guardian state the kernel must
> hold AUTHORITATIVELY to preserve recovery sovereignty and to detect a forged constituency?"**

Three candidates, compared on the property that actually separates them:

| | **G-A** full roster in kernel storage | **G-B** commitment + threshold + generation in kernel; roster supplied as calldata | **G-C** external controller PUSHes a roster |
|---|---|---|---|
| Who may cause the authoritative bytes to change | the kernel, under its own quorum | **the kernel, under its own quorum** | an external principal |
| Whose liveness is required to change them | no one outside | **no one outside** | the controller's |
| Forged constituency detectable | n/a (kernel holds it) | **yes — a preimage that does not hash to the commitment is rejected** | **no — the consumer verifies generation ordinality, not roster content** |
| Kernel storage | `n` address slots | **3 words** | 2 words + trust |
| Recovery locality | preserved | **preserved — validation is pure hashing** | **destroyed** — recovery depends on a foreign contract |
| Circularity clause (R-KERNEL-CIRCULARITY) | not triggered | **not triggered** | **triggered** — replacing the controller needs the controller |

> **G-B is NOT a disguised G-C, and this is the whole adjudication.** In G-C an external principal
> *writes* the kernel's belief, so its honesty and its liveness are both inside the TCB. In G-B
> **nobody pushes anything**: the kernel writes its own commitment under its own quorum rule, and the
> roster bytes arrive as **untrusted calldata that the kernel validates against a value it wrote
> itself**. Under the separating predicate — *who may cause the authoritative bytes to change, and
> whose liveness is required* — **G-B is indistinguishable from G-A and categorically distinct from
> G-C.** It therefore inherits G-A's classification and G-A's escape from the circularity clause.

**Verdict: G-B is the minimum, and it is adopted.** The kernel holds, authoritatively:
`guardianCommitment`, `threshold`, `guardianGeneration`, plus per-request support accounting **keyed
to the generation** so support cannot be replayed across a roster change. It does **not** hold the
member addresses. Hazard H-19's prevention is therefore restated: what must not be externalised is
**guardian authority**, not the roster bytes — and the previous phrasing over-claimed by conflating
them.

**For realistic `n` this is smaller in BOTH dimensions, which is unusual and worth stating.** With
`MAX_GUARDIANS = 32` (OBSERVED) but realistic sets of `n = 3…7`, G-A costs `n` address slots and needs
in-kernel iteration, deduplication and bounds logic. G-B costs **one** slot for the commitment and,
for small `n`, needs no Merkle verifier at all: a plain `keccak256` over the **injectively encoded**
sorted roster supplied in calldata is cheaper in bytecode than the loop it replaces. **No byte figure
is asserted here, because none was measured** — measuring both is part of §21 step 5, and §19's STOP
CONDITION governs the result.

Four invariants, none of them optional:

> **I-GUARDIAN-AUTHORITY-CLOSURE (T0).** The kernel is the **sole writer** of the guardian commitment,
> and writes it only under a quorum evaluated against the **immediately preceding** commitment.

> **I-GUARDIAN-CONSTITUENCY-BINDING (T1).** Roster material supplied as calldata is authoritative only
> if its **injective** encoding hashes to the current kernel-held commitment. The commitment covers,
> at minimum: the threshold, the ordered member list, and each seat's authentication mode. *Injective
> matters concretely — a naive packed encoding lets two different rosters collide, and a threshold
> left outside the preimage can be supplied by the attacker.*

> **I-QUORUM-DISTINCTNESS (T1).** Attesting guardians count as distinct only via **strictly ascending**
> ordering over the committed roster. No address and no index may be counted twice.

> **I-CONSTITUENCY-RECONSTRUCTIBLE (T1).** Every write of the commitment **emits the full preimage** —
> threshold and all ordered `(address, authMode)` entries — in the same transaction.

**The new hazard G-B creates, named rather than hidden (H-27).** The kernel can hold a perfectly
intact commitment whose **preimage nobody has**. The roster is then unreconstructible and recovery is
unreachable, with no on-chain symptom. `I-CONSTITUENCY-RECONSTRUCTIBLE` is the mitigation, and its
**residual is real and is a G5 dependency**: reconstruction needs log history, so a user with only
`eth_getCode` and no archive access cannot recover the roster. G-A has no such residual. **This is the
price of the smaller TCB and it is charged honestly** — it is the one axis on which G-A beats G-B.

---

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
1. **Structural length rejection** of public keys and signatures. These are **pure integer
   comparisons**, so the kernel performs them itself and needs no trust in any verifier.
   *(An earlier revision attributed this requirement to **FIPS 204 §3.6.2**. That citation is
   **NOT VERIFIED in this lane** and is therefore no longer load-bearing: the check earns its place
   on its own engineering merits, and the argument below does not depend on any standard endorsing
   it. Anyone re-adding the citation must read the clause first.)*
2. **Kernel-recorded scheme strength** (§12), never read from the verifier.

---

### 4.3a The floor as specified is NOT sufficient — a correction that changes a verdict

> **`A ∧ true = A` proves that a plane's marginal contribution is non-positive. It does not prove
> that `A` is safe.** Conjunctivity bounds what a plane can *add*. It says nothing whatsoever about
> whether what remains — the floor — authenticates anybody.

Both floor components above are **structural**. A length comparison is a statement about a byte
string's shape. A kernel-recorded strength ordinal is a statement about a label the kernel itself
wrote down. **Neither demonstrates possession of a private key.** So for any capability whose *only*
positive authentication step is delegated to an external verifier, "the plane is conjunctive" reduces
authorization to **"the caller supplied correctly-sized bytes"** — which every caller can do, because
a public key is public.

**This is not hypothetical, and the demonstration is in this repository.** OBSERVED, read firsthand at
`15a44016` — `contracts/MockMLDSAVerifier.sol`, the concrete `IPQCVerifier` actually deployed on
Sepolia today, returns `true` exactly when:

```
digest != bytes32(0)
&& publicKey.length == 1952        // ML_DSA_65_PUBLIC_KEY_LENGTH
&& signature.length == 3309        // ML_DSA_65_SIGNATURE_LENGTH
&& the first 32 bytes of signature are not all zero
```

It relates the key to the signature **nowhere**, and its own comment says so: *"this is structural
only and provides NO cryptographic guarantee."*

> **Therefore, on the ML-DSA family, the floor this document proposed and an always-true verifier are
> the same function.** The floor is a *strictly weaker* version of the mock — it drops even the
> nonzero-prefix test. The claim "an always-true verifier grants nothing, so mutant M11 dies
> structurally" was **false for `PqOnly`**, and it was refuted by an artifact already in the tree.

Two invariants replace the overclaim. Both are **T0**.

> **I-NO-SOLE-EXTERNAL-AUTHENTICATOR.** No external verifier may be the sole positive authenticator
> for an asset-moving or credential-changing capability. Every such capability's authorization
> predicate must contain at least one conjunct that is a **possession test the kernel evaluates
> itself**, using only its own code and fixed-address consensus precompiles.

> **I-FLOOR-IS-SOUND.** With **every** plane removed, the floor alone must **deny** every principal
> that cannot present a kernel-verifiable possession witness — for every capability, in every safe
> state. A component may be classified PLANE-SAFE only if the floor still denies without it.

**The word "replaceable" is deliberately absent from the first invariant, and that is a change from
the wording the remediation brief proposed.** Binding a verifier *immutably* removes the substitution
hazard and creates **no possession test at all**; it additionally makes the always-*false* failure
permanently unfixable, and under C an immutable binding is per-**generation**, not per-vault — so a
single defective verifier becomes a correlated, unfixable, cohort-wide failure. Immutability is
therefore not a way to satisfy this invariant.

**Consequences, stated as decisions rather than as observations:**

| Mode | Kernel-verifiable possession conjunct | Verdict |
|---|---|---|
| `EcdsaOnly` | `ecrecover` (precompile `0x01`) | **Admissible** |
| `Hybrid` | `ecrecover`, ANDed with the PQ leg | **Admissible — the default** |
| `PqOnly` | **none** | **REJECTED for vNext generation 1** |

**`PqOnly` is rejected**, and re-admitted only by a future kernel generation that has a
kernel-resident PQ possession test. No such primitive exists on Ethereum today (there is no
post-quantum signature precompile), so this is a real constraint, not a deferral.

**The `ecrecover` conjunct is only a possession test under three conditions**, all of which must be
stated because a clone architecture creates the third:
1. **malleability rejected** — `s` in the lower half order, `v ∈ {27, 28}`;
2. **`address(0)` never treated as a match** — the raw precompile returns `address(0)` on malformed
   input;
3. **the stored credential is provably non-zero.** OBSERVED: the current vault satisfies (1) and (2)
   by using OpenZeppelin's `ECDSA.recover`, which reverts rather than returning `address(0)`. (3) is
   **new under C**: a constructor cannot be relied on, so an *uninitialised clone* holds a zero
   credential, and a comparison against it must fail closed rather than accidentally succeed. This is
   the same hazard as dissent D3 (initialisation front-running) reached from the other direction.

**A third invariant follows, and it is what decides D4:**

> **I-NO-CIRCULAR-ESCAPE.** For every replaceable component `X`, the authorization required to replace
> `X`, disable `X`, or migrate away from `X` must be fully evaluable with `X` **unavailable** *and*
> with `X` **Byzantine**.

Under `PqOnly` the escape from a hostile verifier is authenticated *by that verifier*. Rejecting
`PqOnly` is therefore not only a forgery fix — **it is what makes verifier escape non-circular**, and
so it is what makes the cohort coupling in §14 an escapable default rather than a trap (§22, D4).

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

**Accounted deposit is gated with withdrawal.** OBSERVED defect corrected: today `deposit`/`depositFor`
carry no pause modifier while every payout path does, so a frozen deployment keeps **crediting** funds
it cannot pay out (hazard H-22). A state that cannot pay out must not **book** an inflow as though it
could. **The row gates the accounted path only** — unsolicited arrivals (direct transfers, forced ETH,
airdrops, rebases) are outside every lattice state's reach by construction, and §13.0a explains why
pretending otherwise weakened the migration argument rather than strengthening it.

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
- **No reachable degraded state traps the vault.** Every state retains migration egress (§13).
- **No emergency principal gains a permanent recovery veto.** Containment self-expires with **no
  principal acting**, and recovery stays available throughout. Mutant **M7**.

> **A counter-intuitive rule, stated because it looks wrong.** The containment clock and the
> recovery-expiry clock are **wall-clock and must not suspend while contained.** Suspending them
> looks protective and is the opposite: composed with an irreversible freeze it converts a stalled
> recovery request into a **permanently undeletable** one, removing the last exit. A wall-clock bound
> is also strictly cheaper — no per-request accrual state. The sibling guardian lane reached this
> conclusion independently and withdrew an earlier draft that proposed suspension.

> **CLOCK RULE, generalised — because stating it only for containment left three other clocks
> unspecified.** *Every* clock in this design — recovery delay, recovery expiry, migration bind delay,
> migration deadline, withdrawal maturity, containment expiry — runs on **wall clock in every safe
> state**, and no state transition may reset, extend, or suspend any of them. There are exactly two
> options and the previous revision picked neither: if clocks suspend under containment, a bounded
> containment silently extends every pending deadline; if they do not, containment cannot outlast a
> fix window. **This design takes the second**, and pays for it by keeping the containment bound short
> and by never letting containment gate recovery.

#### A bounded timer is not a bounded authority — the rolling-freeze defect

> **This was a real hole in the previous revision and it is recorded rather than quietly patched.**
> §6 said containment is "wall-clock bounded and self-expiring", and nothing anywhere said what
> happens when the emergency principal **triggers it again**. A hostile or captured emergency
> principal simply re-triggers on expiry, and the vault is frozen forever using only a capability the
> document calls bounded. **Per-episode bounds do not compose into a bound on the authority.**

Two rules, both cheap, and both required:

> **I-CONTAINMENT-NO-EXTENSION.** Re-entry while already contained is a **no-op**. `expiresAt` is set
> once, at first entry, and no principal may move it.

> **I-CONTAINMENT-BUDGET (T0).** Over any rolling wall-clock window of length `W`, the total time
> spent in CONTAINED at the emergency principal's instance is at most `B`, with **`B < W`**. The
> window origin advances **only** by elapsed wall clock and can be moved by no principal.

`B < W` is the whole content: it guarantees an infinite sequence of uncontained intervals, so denial
becomes a **duty cycle** rather than a state. The kernel cost is two words (`windowStart`,
`usedInWindow`). Mutant **M46** breaks exactly one thing — it resets `windowStart` on each new
trigger — and the vault becomes indefinitely freezable.

**What remains live under containment**, unchanged and load-bearing: recovery initiation, support,
cancellation and execution; migration binding and egress. **What is withdrawn**: spending, queuing,
**inflow**, and every authority mutation.

> **I-NO-INGRESS-WITHOUT-EGRESS (T1) — SCOPE CORRECTED.** Any state that restricts asset egress must
> restrict every **ACCOUNTED** ingress path — the paths the kernel itself credits. OBSERVED at
> `15a44016` and still live: `deposit()` and `depositFor()` carry no state gate while every payout
> path carries `whenNotPaused` (hazard H-22).
>
> **The invariant is about paths the kernel controls, and it must never be read as "no assets can
> arrive".** It cannot restrain a direct ERC-20 `transfer`, forced ETH, an airdrop, or a rebase,
> because none of those calls a WalletWall function. **The previous revision's gloss — that this is
> "the mechanism by which an unprivileged stranger can veto a migration" — is WITHDRAWN (§13.0a).**
> The stranger's asset arrives without touching any gated path; the migration is protected by
> `I-MIGRATION-NONTRAP`'s unsolicited-asset clause instead, which is where the load belongs.
> This invariant earns its place on **accounting coherence** — a balance the kernel credits while
> refusing to honour it is a promise the kernel knows it is breaking — not on migration safety.

> **I-VETO-BOUND (T0), the general rule the above are instances of.** **Every** veto capability in the
> design — not merely every pause — must carry a bound that lifts **with no principal acting**.
> Applies to: containment (wall clock + budget), recovery cancellation by the spending credential
> (bounded count, §22 D1), a pending migration binding (deadline), and a matured recovery request
> (expiry). A veto with no self-lifting bound is a permanent authority wearing a temporary name.

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
| ~~**Factory operator**~~ **— the principal DOES NOT EXIST (§22 D8, LOCKED)** | **NONE, over any vault, deployed or future.** One immutable factory per kernel generation: the implementation choice is consumed at the factory's own construction and is thereafter unreachable by every principal including the deployer. What remains is a **generation publisher**, whose only power is which factory address is *advertised* — a discovery influence, not an authority (H-32) |
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
| **Factory deployer** (immutable factory, ADOPTED) | **Closure EMPTY.** The implementation choice is spent at construction; over deployed clones it was always empty — a clone's implementation is a `PUSH20` immediate in its own code | **No** |
| **Generation publisher** | Advertises a factory address. Closure adds **discovery influence over FUTURE vaults only**; bounded by §15 offline verification | **No** |
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

> **I-RECOVERY-LOCALITY (v1 — WITHDRAWN, kept for the record).** *"Recovery initiation, support, and
> execution perform **zero external calls** and depend on **no globally-mutable state**."*

The second clause was and remains right. OBSERVED: `executeRecovery` makes no external call yet is
`whenNotPaused`, reading a single global `_paused` bit. Locality stated only over *calls* would
certify a recovery path that one principal can freeze for everyone.

**But "zero external calls" is not satisfiable under the selected deployment model, and it never
was.** Under EIP-1167 *every* entry into a clone is a `DELEGATECALL` from the clone to a different
account. Read literally, v1 is false at the first instruction of every function the vault has. It
also forbids `ecrecover` — a `STATICCALL` to precompile `0x01` — which §4.3a now makes **mandatory**.
An invariant that the architecture violates on entry and that forbids its own floor is not a
requirement; it is a slogan.

> **I-RECOVERY-LOCALITY-V2 (T1) — the replacement.** Recovery initiation, support, cancellation and
> execution may consult **only**:
> 1. the clone's **own immutably-bound implementation** (the `DELEGATECALL` that *is* the vault),
> 2. **fixed-address consensus precompiles**, and
> 3. **guardian principals named in the vault's own committed constituency** (§4.2b);
>
> and they may read **no state mutable by any plane, by any global admin, or by any principal outside
> that constituency**.

**This is weaker than v1 and the weakening is deliberate, so it is named.** v1's real content was
*"no replaceable component's failure can stop recovery"*. Items 1 and 2 cannot fail without the vault
or the chain failing. Item 3 is the genuine concession: it admits **ERC-1271 contract guardians**,
which validate by call.

**Why item 3 is safe, and what it costs.** A guardian is a **principal**, not a plane, and the quorum
already tolerates principals that do not act — that is what `k`-of-`n` *is*. A guardian contract that
reverts is a guardian who did not answer. Admitting them therefore adds no new class of failure,
**provided** each consultation is isolated, which is a separate invariant rather than an assumption:

> **I-GUARDIAN-FAULT-ISOLATION (T1).** For every guardian `g` and **every** behaviour of `g`'s account
> — revert, out-of-gas, unbounded returndata, attempted reentrancy, attempted state mutation, any
> return value — the recovery outcome computed from the remaining guardians must be **unchanged**.
> Enforced by: `STATICCALL` (so no reentrant state change is possible), an explicit **forwarded-gas
> cap**, a **bounded returndata copy**, and **non-bubbling** failure handling.

> **I-ATTESTATION-IS-AFFIRMATIVE (T1).** An ERC-1271 attestation counts **only** when the `STATICCALL`
> succeeds **and** `returndatasize == 32` **and** the returned word equals the ERC-1271 magic value.
> "Did not revert", "returned something", and "returned non-zero" each count as **no attestation**.
> A `CALL` in place of a `STATICCALL` is a defect, not a style choice.

> **I-GUARDIAN-AUTH-MODE-IS-COMMITTED (T1).** Whether a seat authenticates by ECDSA or by ERC-1271 is
> read from the **committed** constituency entry, never inferred from observable chain state —
> not from `extcodesize`, not from a delegation indicator. Inferring it lets an address change its own
> authentication method by acquiring or shedding code.

**The honest cost.** Under v2, a vault whose guardians are *all* ERC-1271 contracts has a recovery
path that depends on those contracts' liveness. The quorum bounds this — `n - k` may fail — but it
does not eliminate it, and a user who chooses `k` contract guardians out of `n = k` has chosen a
recovery path with external dependencies. **That is the user's choice to make and the vault's job to
disclose**, not something the architecture can forbid without also forbidding a Safe as a guardian.
The Observatory (§10) publishes each seat's auth mode for exactly this reason.

> **I-RECOVERY-NONVETO.** No principal holds an unbounded veto over an otherwise-valid recovery.
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

### The security-transition rule — WITHDRAWN and replaced

> **The rule this document previously stated was:** *"A scheme may be activated only if its
> kernel-recorded strength class is greater than or equal to that of every currently-ACTIVE scheme."*
> **That rule is withdrawn.** It is not a weak version of the right rule; it is unsound in the
> dangerous direction, for two independent reasons.

**Defect 1 — it summarises by MAX where the semantics are MIN.** `EcdsaOnly`, `PqOnly` and `Hybrid`
are **alternatives**: a vault that accepts any of them is as strong as the *weakest* path it accepts.
Taking the maximum over ACTIVE schemes therefore reports the strength of the best path while the
attacker uses the worst. Activating ML-DSA-87 (class 5) alongside a still-active ECDSA-only path
*raises* the reported number and changes nothing an attacker faces.

> **The general form, worth stating separately because it recurs:** the strength of a **conjunction**
> is its strongest necessary leg; the strength of a **disjunction** is its **weakest sufficient**
> path. Any aggregate that does not distinguish the two is a downgrade waiting to be labelled an
> upgrade.

**Defect 2 — a scalar asserts a total order that does not exist.** Classical ECC, PQ lattice
(ML-DSA), PQ hash-based (SLH-DSA), and hardware-rooted signers rest on **incomparable** assumptions.
A single ordinal must either invent an ordering between them or silently collapse them.

**Replacement — an explicit `SecurityProfile` and a PARTIAL transition relation.**

A profile is a **disjunction of clauses**; each clause is a **conjunction of factors**. It carries:

| Field | Purpose |
|---|---|
| `clauses` | each a set of factors that **together** authorize |
| `factor.schemeId` | the concrete scheme (`ECDSA_SECP256K1`, `ML_DSA_65`, …) |
| `factor.family` | the assumption family — the axis along which comparison is even meaningful |
| `factor.paramLevel` | the **within-family** level, and only within-family |
| `factor.rootTag` | the **independence root**. Two factors sharing a `rootTag` are ONE root, however different their algorithms |
| `factor.verifierGeneration` | monotone, bumped only together with a change of verifier code identity |
| `factor.anchored` | true iff this factor's possession test is kernel-evaluable (§4.3a) |
| `status` | `ACTIVE → DEPRECATED → DISALLOWED`, one-way, `DISALLOWED` **absorbing** |

`transitionAllowed(old, new)` is a **partial** relation, and every clause below is a refusal:

1. **R1 — no DISALLOWED factor appears in `new`.** The lattice is absorbing; re-activation is refused.
2. **R2 — anchoring.** Every clause of `new` contains at least one `anchored` factor (I-NO-SOLE-EXTERNAL-AUTHENTICATOR, applied clause-wise rather than profile-wise, because a *disjunct* is a complete path to authority).
3. **R3 — clause covering, in the correct quantifier direction.** For **every** clause `n` of `new`
   there exists a clause `o` of `old` such that `n` **dominates** `o`. *(The reverse quantifier —
   every old clause covered by some new clause — permits adding a weak alternative and is the
   classic error.)*
4. **R4 — dominance is within-family only.** `n` dominates `o` iff for every factor in `o` there is a
   factor in `n` of the **same family** with `paramLevel ≥` and `verifierGeneration ≥`. There is no
   cross-family dominance edge, ever.
5. **R5 — independence must not decrease.** `minRoots(new) ≥ minRoots(old)`, where `roots(clause)` is
   the count of **distinct `rootTag`s** in that clause and `minRoots` is the **minimum over clauses**.
   `rootTag` is fixed at registration and is never reassignable.
6. **R6 — no self-dealing.** Profiles are indexed by action class (`SPEND`, `RECOVERY`, `MIGRATION`,
   `PROFILE_CHANGE`). `profile(PROFILE_CHANGE)` must dominate every profile it can change, so the
   rule protecting the crypto cannot be edited under weaker crypto than it protects.
7. **R7 — incomparable is REFUSED, not permitted.** If neither profile dominates the other, the
   transition is denied. Unknown ⇒ deny is the only safe closure of a partial order, and refusing is
   recoverable (propose a comparable profile) while permitting is not.

**Agility survives**, which is the point of R4: ML-DSA-65 → ML-DSA-87 is a within-family
`paramLevel` increase and is allowed; so is any verifier-implementation replacement that raises
`verifierGeneration` within a scheme. What is refused is *changing the shape of the argument*.

**Deprecation is not covered by R1–R7 and is called out rather than glossed.** Marking a broken
scheme `DEPRECATED` necessarily *lowers* the profile, so it can never pass a monotone rule. It is
therefore a distinct, one-way, explicitly-authorized **break declaration**, governed by
`profile(PROFILE_CHANGE)`, and it must reduce the **authorization** predicate — not merely a
comparison constant — or the broken scheme keeps authorizing while being labelled broken.

Mutants **M10**, **M18** and **M32–M38** (§17).

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

Migration is among the most powerful capabilities in the system and is specified accordingly. **This
section was rewritten in full.** The previous version was internally contradictory and its central
mechanism — an atomic, all-or-nothing transfer of a bound asset set — is **unimplementable and
unsafe**, for reasons given below before the replacement.

### 13.0 Why the previous specification fails

It said: *"partial migration is disallowed (the asset set is bound); tokens that fail transfer abort
the whole migration."* Six independent failures, any one of which is disqualifying:

| # | Input | What happens |
|---|---|---|
| 1 | **An ERC-20 that reverts on transfer** (a blacklisting stablecoin blacklisting the destination) | One token permanently aborts the entire escape. The vault is trapped. |
| 2 | **An ERC-20 that returns `false`** | Without a `SafeERC20`-style return check the migration is marked complete having moved nothing. |
| 3 | **A fee-on-transfer or rebasing token** | The amount that arrives is not the amount bound. A bound *amount* can never be satisfied. |
| 4 | **An unexpected airdrop after preparation** | The bound set is stale on arrival. Anything not in it is unreachable forever. |
| 5 | **Many assets** | An unbounded loop over the asset set is a gas-limit denial of service. |
| 6 | **A hostile third party** | see below — the decisive one |

> **The sixth failure settles it.** Under per-vault custody the vault *is* an address, so **anyone**
> can send it an ERC-20 with no function call at all. An **unprivileged third party** can place a
> reverting or blacklisting token into a vault *between binding and execution* and **veto the escape
> of a vault they hold no authority over**. An escape hatch that any stranger can weld shut is not an
> escape hatch.

> **THE H-22 LINKAGE IS WITHDRAWN — re-derived firsthand, and the previous revision's conclusion was
> not merely overstated, it was backwards.** That revision continued: *"and OBSERVED at `15a44016`,
> `deposit()`/`depositFor()` still carry no state gate (hazard H-22) … this is why H-22 is not minor
> hygiene, and why it is not orthogonal to this lane"* — and §21 promoted H-22 to a **migration
> prerequisite** on that basis. **Closing `deposit()`/`depositFor()` cannot prevent failure 6, so no
> migration invariant may depend on it.** The full adjudication is §13.0a. The mechanism above stands
> on its own and needs no help from H-22.

### 13.0a H-22, re-derived — four questions that were being answered as one

**The shape of the finding, OBSERVED firsthand at `15a44016`:**

| Contract | explicit deposit path | gated? | unmediated ingress reachable? |
|---|---|---|---|
| `WalletWallVault` | `deposit()` / `depositFor()`, ETH | **NO gate** | **YES** — `selfdestruct` beneficiary, block-reward coinbase |
| `StablecoinVaultSimulator` | `deposit(uint256)` / `depositFor(address,uint256)`, ERC-20 | `whenNotPaused` | **YES** — a direct `IERC20.transfer` to the contract |

**Three further facts, each verified in this tree rather than assumed:**

1. **`WalletWallVault` declares no `receive()` and no `fallback()`**, and holds **no ERC-20** — the
   only occurrence of "ERC-20" in the file is a comment about address collision. It is ETH-only.
2. **Neither contract's accounting reads its own holdings.** `address(this).balance` appears
   **nowhere** in `contracts/`, and there is no `balanceOf(address(this))` in the simulator. Both
   credit a per-owner `vault.balance` mapping. The simulator's own NatSpec says it outright:
   *"Direct ERC-20 transfers to this contract are NOT credited."*
3. **Forced ETH already reaches the live vault, and the repository already tests it.**
   `contracts/mocks/ForceSend.sol` exists for exactly this, and `test/WalletWallVault.test.ts`
   asserts that after a forced 5 ETH the raw balance grows while the accounted balance does not.

**The four questions, answered separately:**

| # | Question | Verdict |
|---|---|---|
| 1 | Is H-22 a **CURRENT-PRODUCT defect**? | **YES.** A paused vault refuses every payout and still accepts accounted deposits. Closing it is *effective* here, because in an ETH-only contract with no `receive`/`fallback` the explicit deposit path is the only ingress that **credits a balance**. |
| 2 | Is H-22 a **PARITY defect**? | **YES.** Two sibling contracts answer the same question differently, and divergence without a recorded reason is a defect regardless of which answer is right. |
| 3 | Is H-22 a **CONTAINMENT-POLICY choice**? | **YES**, and that is the honest frame for vNext. `I-NO-INGRESS-WITHOUT-EGRESS` is a *policy* — "a state that cannot pay out must not take in" — not a mechanism that can be made total. |
| 4 | Is H-22 a **vNext ARCHITECTURE PREREQUISITE**? | **NO. Withdrawn.** |

**Why 4 is NO, stated as the argument rather than as an assertion.** Gating every explicit deposit
entry point cannot prevent any of:

```text
direct ERC-20 transfers to the vault address
forced ETH (selfdestruct beneficiary; block-reward coinbase)
airdrops and unsolicited ERC-721 / ERC-1155
rebasing balances that grow with no transaction at all
any asset that arrives AFTER the manifest was bound
```

None of these calls a WalletWall function, so none can be refused by a WalletWall modifier. The
attacker in failure 6 does not need `depositFor` and would not use it: they use `transfer`. **A gate
that the attack does not pass through cannot be a prerequisite for defeating the attack.** The
parity target does not help either — the simulator *is* `whenNotPaused` on deposit and is *still*
fully exposed to a direct `transfer`, which is why its own documentation says so.

> **The rule this yields, and it is the one that actually protects migration:**
> **migration MUST be safe under unsolicited assets even if every explicit deposit entry point is
> closed.** That safety is delivered entirely by §13.1's per-entry manifest with independent egress
> — change (1) of H-28's prevention. **Change (2) — "close H-22" — was listed as co-required and is
> now recorded as NOT required for this invariant.** It is retained as product hygiene, at its own
> priority, on the strength of questions 1–3.

> **What this costs, said plainly rather than buried.** Under the previous framing, a closed ingress
> was doing invisible work in the argument — it made "no hostile asset can arrive" feel achievable.
> It never was. Removing the crutch means `I-MIGRATION-NONTRAP` must carry the whole load on its own,
> which is why it is **strengthened** in §13.2 rather than merely restated.

### 13.1 The replacement — manifest-based, per-entry, claim/sweep, salvage-capable

**Authority migration and asset egress are separated.** They fail differently, so they are different
mechanisms.

**Phase 1 — BIND.** One approval fixes: source, destination **vault address**, destination **vault**
code hash, destination generation, credential/guardian/policy commitments, expected safe state, chain
id, nonce, deadline. It binds a **disposition** (`FULL BALANCE`) per asset *class* — **never an
amount**, which is what defeats fee-on-transfer and rebasing tokens (failure 3) — and it does **not**
bind a closed asset set (failure 4).

**Phase 2 — RETIRE.** Authority freezes: no credential enrolment, no guardian change, no plane
replacement, no new binding, no ingress. The binding is now immutable.

**Phase 3 — EGRESS (repeatable, permissionless, per entry).** `egress(assetSpec)` moves one asset
class to the bound destination. The caller supplies the asset identifier — which is what makes ERC-721
and ERC-1155 workable without on-chain enumeration — but **the caller can never supply or influence
the recipient**. Entries are independent: a failing entry marks itself `FAILED` and **reverts nothing
else** (failures 1 and 5).

**Phase 4 — SALVAGE (open-ended).** `egress` never closes. Assets arriving later remain claimable to
the same bound destination forever.

### 13.2 The invariants this forces

> **I-MIGRATION-NONTRAP (T0) — STRENGTHENED by §13.0a.** No accepted migration failure mode may
> convert a recoverable vault into an asset state with no authorized exit. **And, now that the
> closed-ingress crutch is withdrawn, the invariant must hold in the presence of assets the vault
> never agreed to hold:**
>
> **(a) An UNSOLICITED or UNMANIFESTED asset may never veto the movement of an independently
> recoverable manifested asset.** An asset that arrived with no function call, or after the manifest
> was bound, is *inside the vault* but is **not a gate on anything**. Whatever it does — revert,
> return false, rebase, blacklist the source — the manifested entries must still each reach the bound
> destination on their own.
>
> **(b) Entry origin is never an authorization input.** "Manifested" and "unsolicited" classify how an
> asset is *tracked*, never whether it may leave. An unsolicited asset is egressable on exactly the
> same permissionless terms as a manifested one — the alternative would build the trap this invariant
> forbids, one category later.
>
> **(c) NON-ENUMERABILITY, and the retirement condition this forbids.** *"The vault's balance is zero
> across every possible token"* is **not a decidable predicate** — the set of ERC-20 contracts that
> may name this address is unbounded and unenumerable on chain, and a rebasing token can reintroduce
> a non-zero balance with no transaction at all. **Retirement must therefore never be conditioned on
> global asset exhaustion**, and no state transition anywhere in this protocol may be. Retirement is
> conditioned on **authority** (`I-TERMINALITY-IS-AUTHORITY`, §13.3), and egress stays open
> afterwards (`I-EGRESS-RETRY-PERPETUAL`). A design that waits for the last token is a design that
> waits forever, and the waiting is itself the trap.
>
> *(Discriminated in the model: mutants **M52** and **M53**, §17.)*

> **I-EGRESS-INDEPENDENCE (T0).** No entry's outcome may affect the outcome, availability, or gas
> feasibility of any other entry. **This now covers the cross-class case explicitly**: an
> unmanifested entry's failure is not merely isolated from other entries, it is not a precondition
> of any other entry's success.

> **I-EGRESS-RETRY-PERPETUAL (T0).** No state — `RETIRED` included — and no entry status, `ABANDONED`
> included, may remove the permissionless ability to retry an unresolved entry toward the bound
> destination.

> **I-EGRESS-RECIPIENT-FIXED (T0).** Every egress path reads its recipient from the binding, never
> from the caller. This is what keeps a *permissionless* egress from being a withdrawal.

> **I-NO-FALSE-SETTLEMENT (T1).** An entry is marked `MOVED` only on an **observed decrease in the
> source's own balance or ownership** of that asset — never because an external call returned without
> reverting. This closes failure 2 without trusting any token's return convention.

> **I-MIGRATION-SUBORDINATE-TO-RECOVERY (T0).** For every coalition, the minimum time to complete a
> migration must be **at least** the minimum time to complete a recovery, and a pending recovery
> blocks binding.

> **I-MIGRATION-CLOCK-NEUTRAL (T1).** Migration may neither shorten nor lengthen the maturity of any
> pending obligation — queued withdrawal, containment expiry, recovery delay.

**I-MIGRATION-SUBORDINATE-TO-RECOVERY is the sharpest finding in this section, and it was absent from
the previous version.** Migration and recovery are reachable by the **same** coalition — a guardian
quorum. If binding is faster than recovery, migration is **strictly the better attack**: identical
prerequisites, less warning, irreversible outcome. A defence in depth that hands the attacker a faster
door is not depth. `bindDelay >= recoveryDelay` is therefore an architectural constraint, not a tuning
parameter.

### 13.3 Resolving "RETIRED is terminal" versus "migration executes from RETIRED"

The contradiction dissolves once *terminal* is defined over authority rather than over activity:

> **I-TERMINALITY-IS-AUTHORITY (T1).** A state is **terminal** iff no principal may thereafter acquire
> or exercise **discretionary** authority over the object. A non-discretionary, pre-committed function
> whose every parameter — above all its recipient — was fixed before the state was entered **is not
> authority**, and does not make the state non-terminal.

So `RETIRED` is terminal *and* permanently egress-capable, with no contradiction: nothing in `RETIRED`
decides anything. Egress from `RETIRED` is a pull against a commitment made while the vault still had
authority to make it.

### 13.4 The residual, stated rather than engineered away

**One case survives: a token that blacklists the SOURCE.** No destination helps and no protocol change
reaches it. That is a property of the token, not a migration failure mode, and it is recorded in §2.2
as an accepted unrecoverable condition rather than silently absorbed here.

**Abandonment is bookkeeping, never capability removal.** Marking an entry `ABANDONED` changes
settlement accounting only; a later successful transfer still resolves it. `ABANDONED` is **not**
absorbing (mutant M42).

### 13.5 Retained from the previous version, with one correction

**The destination code hash is re-checked at EXECUTION, not only at preparation** — corrected: the
hash re-checked must be `extcodehash` of the destination **VAULT**, not of the implementation it
delegates to. Under C those are different accounts, and hashing the implementation would accept **any**
clone of the right kernel, including one the attacker deployed and controls.

**Explicitly rejected: `migrateEverything(arbitraryAddress)`.** An escape hatch that can send all
assets to a chosen address is indistinguishable from theft (hazard H-11).

**Execution takes no outcome-changing parameter.** Destination and commitments are read from the
approved binding only.

**Migration authority is decomposed so that no single principal holds it** (§22, D2): binding requires
guardian quorum **and** credential authority; egress is permissionless precisely because it has no
discretion left in it.

Mutants **M8**, **M9** and **M39–M45** (§17).

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

### 15.1 Item 6, corrected — code identity is a CHAIN, not a hash

The previous revision wrote item 6 as a one-step check: *"a user with only `eth_getCode` computes
`keccak256` of the 45-byte template with the expected implementation and compares."* **That check is
necessary and it is nowhere near sufficient.** It proves which **address** the clone delegates to. It
proves nothing about what code that address holds, and nothing at all about the vault's configuration.

The real chain has **five links**, and each is a separate fact an offline observer must obtain:

```
  extcodehash(clone)                       PROOF   — code-derived, immutable
        │  the 20-byte PUSH20 immediate, read out of the OBSERVED clone bytes
        ▼
  implementation ADDRESS                   PROOF   — code-derived
        │  a SECOND, INDEPENDENT extcodehash of a DIFFERENT account
        ▼
  implementation runtime code hash         PROOF   — code-derived, but see the masking rule below
        │  reproducible-build registry, compile tuple pinned
        ▼
  kernel generation                        PROOF   — only as strong as the build pin
        │  SLOAD
        ▼
  active configuration / plane commitments OBSERVATION — storage-derived, MUTABLE, timestamped
```

> **I-CODE-IDENTITY-LINKAGE (T1).** The implementation address whose code is hashed **must be the
> 20-byte immediate extracted from the observed clone runtime bytes at the same block.** It may never
> be taken from a registry, a config file, a deployment JSON, or the factory. Taking it from anywhere
> else verifies a claim against itself.

> **I-CLONE-BYTES-EXACT (T1).** A clone's runtime must be **byte-exactly** the canonical template and
> **exactly** 45 bytes (or 45 + `len(args)` under C2, with `len(args)` itself checked). Prefix
> matching, substring matching, and "starts with the 1167 prelude" all admit a superset proxy that
> contains the template **and** additional dispatch that runs first.

> **I-IMPL-NONVACUOUS (T1).** At the moment of any assurance claim, `extcodehash(implementation)` must
> be neither `0` (no such account) nor the hash of the empty string (an account with no code). A clone
> pointing at a codeless address delegates into nothing; every call returns success with empty
> returndata, which a naive checker reads as "fine".

> **I-PURE-CONSTRUCTOR (T1) — forced by measurement.** The kernel implementation's constructor must
> feed **no chain state into any `immutable`** — not `address(this)`, not `block.chainid`. MEASURED
> (§19): two deployments of byte-identical source differ in **51 of 23,239 bytes**, entirely inside
> immutable slots, one of which holds the contract's own address. With address-derived immutables
> there **is no single publishable kernel code hash**; without them there is. This is the same change
> dissent D2 already wanted for a different reason.

> **I-CODE-IMMUTABILITY-IS-FORK-CONDITIONAL (T1).** "Deployed code cannot change" holds only on chains
> **at or after Cancun** (EIP-6780) and only for accounts not created and destroyed inside one
> transaction. **The compiler's `evmVersion: "cancun"` setting is evidence about this repository's
> build, not about any network.** Every deployment target's fork status must be published alongside
> the claim, or the immutability premise is unsupported.

**The offline procedure that follows, stated completely because a partial one is worse than none:**

1. `eth_getCode(clone)` → assert byte-exact template, exact length, extract the implementation address
   and (under C2) the argument suffix.
2. `eth_getCode(implementation)` → assert non-empty and not the empty-code hash.
3. **Mask** the bytes named by the artifact's `immutableReferences` and compare the masked code to the
   published artifact's `deployedBytecode` — which zeroes exactly those slots and is therefore the
   address-independent projection. *(Verified: all seven slots are zero placeholders in the artifact.)*
4. Independently **re-derive** each masked word: the address-derived ones from the implementation
   address, the rest from the pinned source. Masking without step 4 discards real information.
5. Only now read storage. Everything from here is **OBSERVATION with a timestamp**, never proof.

### 15.1a Three identities, kept separate — the narrowing of "there is no kernel code hash"

> **The previous revision's claim was directionally right and categorically too strong**, and a
> too-strong claim here is expensive: it invites a reader to conclude that code identity is simply
> unavailable under C, which would justify skipping the chain. **The five-link chain of §15.1 is NOT
> weakened by this narrowing. It is unchanged.** What changes is which link the word "hash" refers to.

| Identity | What it is | Constant across deployments? |
|---|---|---|
| **SOURCE / BUILD IDENTITY** | implementation **source** + compiler version + settings tuple (`0.8.24`, cancun, optimizer on, runs 200, viaIR off) | **YES** — it names a build, not an account |
| **DEPLOYMENT IDENTITY** | a specific implementation **address** + its actual runtime `extcodehash` | **NO** — one per deployment, and **authoritative for that deployment** |
| **NORMALIZED REPRODUCIBILITY** | the compiled runtime with **declared immutable ranges handled explicitly** — masked *and* independently re-derived | **YES when the ranges are handled**; a hash alone is not this |

**MEASURED, both sides of the distinction, in the §19.1 spike:**

| | current monolith | clone target (§19.1) |
|---|---|---|
| declared immutable slots | **7** | **0** |
| two deployments of identical source differ by | **51 bytes** | **0 bytes** |
| artifact `deployedBytecode` hash `==` on-chain `extcodehash` | **NO** — 136 differing bytes | **YES** |
| a single universal runtime hash exists | **NO** | **YES** — `0x6b25f582…` |

> **Read the right lesson from the right-hand column.** It does **not** say "the problem is solved".
> It says the problem is a **consequence of a design choice** — inheriting an address-caching
> `EIP712` — and that removing that choice removes it, which is precisely what `I-PURE-CONSTRUCTOR`
> requires and what §19.1 demonstrates is achievable. Under `I-PURE-CONSTRUCTOR` the three identities
> above **collapse into agreement**, and normalized reproducibility becomes a plain hash comparison
> with an empty immutable range. **Without it, all three still exist and all three are still
> checkable** — via §15.1's mask-and-re-derive procedure — they simply stop being the same number.
>
> **Two failure modes remain live and both are discriminated (mutants M54, M55).** Treating a
> **build** identity as if it were a **deployment** identity accepts a wrong implementation whenever
> immutables are non-empty. Masking the immutable ranges **without step 4's independent
> re-derivation** discards exactly the bytes an attacker would choose to control.

### 15.2 The Observatory publishes eight identities, never one badge

> **I-IDENTITY-TYPE-SEPARATION (T1).** These are published as **separate typed fields**, each labelled
> `PROOF` (code-derived) or `OBSERVATION` (storage-derived, with a `valid-at`):

| # | Identity | Type | Changes without a transaction? |
|---|---|---|---|
| 1 | clone code identity | PROOF | no |
| 2 | implementation code identity | PROOF | no |
| 3 | kernel generation | PROOF (build-pin strength) | no |
| 4 | active verifier generation | OBSERVATION | no |
| 5 | active policy generation | OBSERVATION | no |
| 6 | credential generation | OBSERVATION | no |
| 7 | guardian generation + commitment | OBSERVATION | no |
| 8 | safe state | OBSERVATION | **yes — containment expires on wall clock** |

Identity 8 is why an aggregate is forbidden: it changes with **no transaction at all**, so any claim
covering it needs a `valid-until`, not only a `valid-at`. **Mixing eight facts of three different
epistemic types into one hash or one green badge destroys exactly the distinction this section
exists to make** — and a single aggregate cannot fail *partially*, which is the failure mode that
matters (mutant **M49**).

**The discriminator the brief demanded, stated precisely:** a model in which the **clone bytes are
correct** — canonical template, right length, right implementation address — while the
**implementation identity evidence is wrong** must make the assurance claim **FAIL**. A checker that
verifies clone *shape* and then reads the implementation's identity from a registry rather than
hashing the account it was pointed at passes this scenario while proving nothing (mutant **M47**).

> **Under B2 this chain is two links instead of five**, because `extcodehash(vault)` *is* the kernel
> code identity with no delegation hop and no second account. That is a genuine assurance advantage of
> B2 which §3.3 weighs and which the 81× deployment cost outweighs — but it is a cost of C, and it is
> recorded as one.

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

### 16.1 Where each invariant is discriminated — and where it is NOT

> **This table exists because the remediation added invariants faster than it added
> assurance, and saying so is worth more than a mutant that would be killed by setup.**
> The reference model is pure TypeScript. It cannot represent bytecode shape, `EXTCODEHASH`,
> gas, calldata, the EIP-150 63/64 rule, transaction ordering, or a chain's fork level.
> An invariant that depends on any of those **cannot** be discriminated here, and claiming
> otherwise would be exactly the over-claim this lane exists to prevent.

| Venue | Meaning | Assurance carried by THIS PR |
|---|---|---|
| **MODEL** | Discriminated by a mutant in `test/VaultVNextArchitectureModel.test.ts` with a vacuity guard | Architectural coherence and discrimination. **Never** conformance. |
| **IMPLEMENTATION-LANE** | Only checkable against compiled bytecode or a live deployment | **NONE.** Recorded as a requirement, not as a result. |
| **OBSERVATORY** | Only checkable by an off-chain evidence assembler against a live chain | **NONE.** |

**MODEL** — discriminated here, mutant named in §17:
`I-NO-SOLE-EXTERNAL-AUTHENTICATOR` · `I-FLOOR-IS-SOUND` · `I-NO-CIRCULAR-ESCAPE` ·
`I-CONTAINMENT-BUDGET` · `I-CONTAINMENT-NO-EXTENSION` · `I-NO-INGRESS-WITHOUT-EGRESS` ·
`I-VETO-BOUND` (bounded challenge) · `I-GUARDIAN-CONSTITUENCY-BINDING` ·
`I-QUORUM-DISTINCTNESS` · `I-GUARDIAN-FAULT-ISOLATION` · `I-ATTESTATION-IS-AFFIRMATIVE` ·
the seven `SecurityProfile` transition rules · `I-MIGRATION-NONTRAP` ·
`I-EGRESS-INDEPENDENCE` · `I-EGRESS-RETRY-PERPETUAL` · `I-EGRESS-RECIPIENT-FIXED` ·
`I-NO-FALSE-SETTLEMENT` · `I-MIGRATION-SUBORDINATE-TO-RECOVERY` ·
`I-TERMINALITY-IS-AUTHORITY` · `I-CODE-IDENTITY-LINKAGE` · `I-CLONE-BYTES-EXACT` (shape only) ·
`I-IMPL-NONVACUOUS` · `I-IDENTITY-TYPE-SEPARATION` ·
**added by the correction pass:** the §19.0 size **truth table** and the MIN-aggregation of
`WALLETWALL_PORTABILITY_BUDGET` (M50, M51) · `I-MIGRATION-NONTRAP` clauses **(a)** and **(c)** —
unsolicited non-veto and the forbidden zero-balance retirement condition (M52, M53) · the §15.1a
**build vs deployment** identity split and the mask-**and**-re-derive rule (M54, M55) · **D8's**
one-immutable-factory-per-generation rule (M56) · **D1's** rule that a bounded challenge does not
move a compromise cut (M57).

> **The size sub-model is a MODEL claim about a RULE, and that distinction is load-bearing.** It
> discriminates *"initcode is judged against the initcode limit"* — a rule, expressible in
> arithmetic over declared parameters. It discriminates **nothing** about any actual contract's
> size, because a TypeScript model has no bytecode. `deployable(target, artifact)` proves the
> comparison is right; only a compiler proves the operands are.

**IMPLEMENTATION-LANE** — stated here, **unproven** here:
**every figure in §19.1 and §19.2** — the clone target's 23,249-byte runtime, its zero immutable
slots, byte-identical redeployment, and every gas number including the break-even `N = 2`. These are
**MEASURED EVIDENCE from a reverted spike**, not model results: they are reproducible from the
procedure §19.1 states, and **no mutant asserts any of them** (§17). They carry the assurance of a
measurement, which is real and is a different kind from a discriminator ·
`I-PURE-CONSTRUCTOR` (needs the artifact's `immutableReferences` — **now DEMONSTRATED achievable**
by the §19.1 spike on a transformed monolith, still **unproven for the vNext kernel**) ·
`I-DEPLOY-INIT-ATOMIC` and `I-SALT-BINDS-PRINCIPAL` (need transaction ordering) ·
`I-DIRECT-IMPL-CALL-INERT` (needs a deployed implementation) ·
the `ecrecover` conditions of §4.3a — malleability rejection, `address(0)` handling, and a
provably non-zero stored credential (need real signature verification) ·
the `STATICCALL` / gas-cap / bounded-returndata mechanics of `I-GUARDIAN-FAULT-ISOLATION`
(the model proves the *isolation property*; only bytecode can prove the *mechanism*).

**OBSERVATORY** — stated here, **unproven** here:
`I-CODE-IMMUTABILITY-IS-FORK-CONDITIONAL` (a claim about a network, not about a build) ·
`I-CONSTITUENCY-RECONSTRUCTIBLE` (needs log availability) ·
the `valid-until` semantics of every OBSERVATION identity.

> **A consequence that must not be lost.** `I-MIGRATION-NONTRAP` and the guardian-isolation
> invariants are **T0**, and their *mechanisms* live in the implementation lane. So a green
> model suite is **not** evidence that a vNext kernel is non-trapping. It is evidence that a
> non-trapping design exists and that this document describes it.

> **The whole matrix must be re-run after any change to these invariants, not only the new
> tests.** Adding conjunctive constraints routinely converts a previously valid kill into a
> vacuous one — a mutant starts being refused by the *new* rule before it reaches the guard it
> breaks. That happened three times while authoring this remediation (M33, M34, M35) and was
> caught by the vacuity guard rather than by review.


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

**Fifty-seven mutants, each flipping exactly ONE guard so that a kill is attributable.
All 57 are killed, and every one carries a vacuity guard requiring the mutated seam to have
actually been evaluated.** See `test/VaultVNextArchitectureModel.test.ts`.

### M1–M18 — the original matrix (unchanged)

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
| M14 | Guardian controller's indirect takeover path omitted | Authority-closure completeness *(inverted polarity)* |
| M15 | Company-hosted service required for recovery | I-RECOVERY-SOVEREIGNTY |
| M16 | One-sided reference-model divergence | I-PARITY |
| M17 | Unavailable control plane strands local recovery | I-RECOVERY-LOCALITY-V2 |
| M18 | Old generation crosses a generational boundary | I-GENERATION-MONOTONE |

### M19–M31 — authentication, containment, ingress, guardians (vault model)

| # | Mutant | Invariant that kills it |
|---|---|---|
| M19 | `PqOnly` is admitted as a credential mode | I-NO-SOLE-EXTERNAL-AUTHENTICATOR |
| M20 | A plane's answer is combined **disjunctively** with the floor | I-PLANE-CONJUNCTIVE (at the authorization level, where M11 only reached the evidence level) |
| M21 | The floor admits on **well-formedness**, conflating shape with possession | I-FLOOR-IS-SOUND |
| M22 | **Immutability** is treated as discharging the authenticator requirement | I-NO-SOLE-EXTERNAL-AUTHENTICATOR |
| M23 | Escaping a hostile verifier requires that verifier | I-NO-CIRCULAR-ESCAPE |
| M24 | The containment budget window resets on every trigger | I-CONTAINMENT-BUDGET |
| M25 | Re-entering containment extends the expiry | I-CONTAINMENT-NO-EXTENSION |
| M26 | Ingress stays open while egress is closed | I-NO-INGRESS-WITHOUT-EGRESS |
| M27 | The credential's challenge right is unbounded | I-VETO-BOUND (restores the H-03 veto) |
| M28 | Roster material is believed without checking the commitment | I-GUARDIAN-CONSTITUENCY-BINDING |
| M29 | Quorum distinctness dropped: one seat counted repeatedly | I-QUORUM-DISTINCTNESS |
| M30 | One hostile ERC-1271 guardian aborts the whole recovery | I-GUARDIAN-FAULT-ISOLATION |
| M31 | "Did not revert" counts as an ERC-1271 attestation | I-ATTESTATION-IS-AFFIRMATIVE |

### M32–M49 — crypto lattice, migration, code identity (sub-models)

| # | Mutant | Invariant that kills it |
|---|---|---|
| M32 | A profile is summarised by **MAX** over clauses instead of MIN | I-DISJUNCTION-TAKES-MIN |
| M33 | The clause-covering quantifier is flipped | R3 (covering direction) |
| M34 | Cross-family dominance permitted | R4 (within-family only) |
| M35 | The independent-root count may decrease | R5 (independence) |
| M36 | A clause need not carry a kernel-evaluable possession test | R2 (anchoring) |
| M37 | The status lattice is no longer absorbing | R1 (DISALLOWED absorbing) |
| M38 | Incomparable transitions permitted instead of refused | R7 (partial order closes to deny) |
| M39 | One failing entry aborts the whole migration | I-EGRESS-INDEPENDENCE |
| M40 | The binding freezes an asset **set**, so an airdrop is unreachable | I-MIGRATION-NONTRAP |
| M41 | The terminal state closes egress | I-EGRESS-RETRY-PERPETUAL |
| M42 | `ABANDONED` becomes absorbing | I-EGRESS-RETRY-PERPETUAL |
| M43 | The bind delay drops below the recovery delay | I-MIGRATION-SUBORDINATE-TO-RECOVERY |
| M44 | The egress recipient is taken from the caller | I-EGRESS-RECIPIENT-FIXED |
| M45 | Settlement recorded on a non-reverting call | I-NO-FALSE-SETTLEMENT |
| M46 | The implementation address is read from a **registry** | I-CODE-IDENTITY-LINKAGE |
| M47 | Clone identity matched by **prefix**, admitting a superset proxy | I-CLONE-BYTES-EXACT |
| M48 | The eight identities published as **one aggregate badge** | I-IDENTITY-TYPE-SEPARATION |
| M49 | A clone delegating into a **codeless** account passes unchecked | I-IMPL-NONVACUOUS |

### M50–M57 — the final architecture-correction pass

| # | Mutant | Invariant that kills it | Correction it protects |
|---|---|---|---|
| M50 | A child's **initcode** is judged against the **runtime** limit | the §19.0 truth table | **A** — EIP-170 vs initcode |
| M51 | The portability budget tracks the **largest** network limit, not the smallest | `WALLETWALL_PORTABILITY_BUDGET <= min(...)` | **B** — chain/fork dependence |
| M52 | An **unsolicited** asset vetoes the egress of a **manifested** one | I-MIGRATION-NONTRAP (a) | **C** — H-22 demotion |
| M53 | Retirement waits for a **zero balance across every token** | I-MIGRATION-NONTRAP (c) | **C** — non-enumerability |
| M54 | One **universal source-level hash** is assumed valid at every address | the §15.1a three-identity split | code identity |
| M55 | Immutable ranges are **masked but never re-derived** | §15.1 procedure, step 4 | code identity |
| M56 | The factory's implementation target is **retargetable** after deployment | D8 — one immutable factory per generation | **D8** |
| M57 | A **bounded challenge** is counted as an increase in the compromise cut | D1 — a delay is not a principal | **D1** |

> **Four REGRESSION assertions accompany them, and they are deliberately not mutants**, because what
> they pin is a truth table rather than a guard: `EIP-170 REGRESSION` (all four rules of §19.0,
> including the case that must be a **non**-event), `PORTABILITY REGRESSION` (the budget aggregates by
> MIN, and a policy failure is distinct from a protocol failure), `D1 REGRESSION`
> (`guardian cut = k` with and without the challenge; the migration path is strictly dominated), and
> `D8 REGRESSION` (a new generation is a deployment, and it leaves the previous factory untouched).
> **A mutant proves a guard is load-bearing; these prove the RULE is the one intended.** The EIP-170
> error would have survived every mutant in this matrix, because no guard was broken — a *comparison*
> was wrong.

> **What was deliberately NOT modelled, and why.** No mutant asserts the §19.1 measurements
> (23,249 bytes, 0 immutable slots, 5,153,134 gas, break-even `N = 2`). A pure TypeScript model
> cannot represent bytecode, gas or compiler output, and a mutant over numbers this document simply
> *states* would discriminate the constant, not the architecture — the definition of decoration.
> Those figures are **IMPLEMENTATION-LANE evidence**, carried by the reverted spike and reproducible
> from the procedure in §19.1, and they are labelled as such in §16.1.

### Scenarios — exercised and adjudicated, deliberately NOT mutants

A configuration is not a broken guard. These four are driven as scenarios because that is
what they are, and the suite records **why each is or is not catastrophic**:

| Scenario | Outcome | Why |
|---|---|---|
| Always-true verifier, `PqOnly` | **CATASTROPHIC — forgery** | The floor is structural only; correctly-sized bytes authorize |
| Always-true verifier, `Hybrid` | **NOT catastrophic — silent DOWNGRADE** | The `ecrecover` conjunct still gates; effective strength falls to ECDSA alone |
| Reverting verifier, `Hybrid` | **NOT catastrophic — DENIAL** | Reported as `UNAVAILABLE`, never as authorization |
| External verifier omitted entirely | **NOT catastrophic** | The floor alone still denies a caller with no secret |

**Three mutants were initially mis-scored while authoring this section, and the harness caught
all three.** M33 and M34 were **masked by defence in depth** — refused by a *different* rule
before reaching the guard they broke, which would have credited a kill to the wrong invariant;
both are now observed on the broken guard directly. M35 tripped the **vacuity guard**: the
mutation deletes the independence check, so the code that marks that guard never ran, and the
mark had to be moved outside the conditional it guards. *A mutation that DELETES a rule must
still record that the rule was reached, or "removed" is indistinguishable from "unreached".*

## 18. Relationship to the hazard register

`docs/Vault_vNext_Hazard_Register.md` holds 26 entries. This document states the architecture; the
register states what can go wrong, who can cause it, and what remains accepted. Every T0/T1 hazard
maps to at least one invariant here, and every accepted residual is named in both.

---

## 19. Derived kernel byte and complexity budget

The budget follows the architecture. The architecture is not weakened to hit a byte target, and the
mission's arbitrary 10–15 KB figure is struck.

### 19.0 The size model — four quantities that must never be conflated

> **A CATEGORY ERROR THIS DOCUMENT COMMITTED, corrected in place rather than silently edited.**
> The previous revision wrote that `WalletWallVault`'s **creation** bytecode, at 24,582 bytes,
> "**exceeds the 24,576 runtime ceiling on its own**", and called that "a fact B1 turns on".
> **That comparison is not meaningful and the sentence is STRUCK.** EIP-170 constrains the
> **deployed runtime code returned by initialisation**. It says nothing whatever about the size of
> the initcode that returns it. Initcode is constrained by a *different* rule (EIP-3860) at a
> *different* limit. Comparing a child's initcode against the runtime limit compares a quantity
> against a bound that does not govern it.
>
> **What survives, and why B1's verdict is unchanged**, is stated in §3.3: B1 fails because the
> **factory's own deployed runtime** is 24,866 bytes. That *is* a runtime figure measured against
> the runtime limit, and solc emits its own diagnostic on it. B1 never needed the initcode
> comparison, and it does not get it.
>
> **This repository's own gate was already right, and says so out loud.** MEASURED — the verbatim
> output of `npm run validate:bytecode-size` on a clean non-instrumented build at `15a44016`:
>
> ```text
> WARN  WalletWallVault
>       runtime bytecode:  23239 bytes (94.6% of 24576)
>       creation bytecode: 24582 bytes (not gated; informational only)
>       headroom:          1337 bytes
> ```
>
> **"not gated; informational only"** — the tool has always labelled the 24,582 figure as
> non-binding, and `test/BytecodeSizeBudget.test.ts` asserts in terms that the gate "reads ONLY
> `deployedBytecode` … proving creation bytecode can never leak into the pass/fail decision".
> The tooling lane had the distinction; the prose lost it, and read the tool's *informational* line
> as a *finding*.

Four quantities. The rest of this document keeps them separate.

| Symbol | What it constrains | Who sets it |
|---|---|---|
| `NETWORK_RUNTIME_LIMIT(chain, fork)` | the **deployed runtime code** an account may hold | the **network**, per fork |
| `NETWORK_INITCODE_LIMIT(chain, fork)` | the **initcode** a creation transaction or `CREATE`/`CREATE2` may execute | the **network**, per fork |
| `WALLETWALL_PORTABILITY_BUDGET` | the runtime size WalletWall will not exceed on **any** declared target | **WalletWall** — a policy, not a protocol fact |
| `WALLETWALL_INTERNAL_RESERVE` | headroom WalletWall withholds from itself for future change | **WalletWall** |

**The decision rules, written out so the error cannot recur:**

```text
runtime  > NETWORK_RUNTIME_LIMIT(chain, fork)    =>  deployment FAILS on that chain
initcode > NETWORK_INITCODE_LIMIT(chain, fork)   =>  creation FAILS on that chain
initcode > NETWORK_RUNTIME_LIMIT(chain, fork)    =>  NOTHING FOLLOWS. Not an EIP-170 event.
runtime  > WALLETWALL_PORTABILITY_BUDGET         =>  a WalletWall POLICY failure, never a protocol one
```

**Values, each labelled with its provenance rather than presented as one undifferentiated fact:**

| Quantity | Value | Status |
|---|---|---|
| `NETWORK_RUNTIME_LIMIT(ethereum, current)` | **24,576** | **ACTIVE.** EIP-170 |
| `NETWORK_INITCODE_LIMIT(ethereum, current)` | **49,152** | **ACTIVE.** EIP-3860, `= 2 x 24,576` |
| `WALLETWALL_PORTABILITY_BUDGET` | **24,576** | **INTERNAL CHOICE.** Retained at the Ethereum figure because it is the *smallest* limit across the declared targets, not because it is eternal |
| `WALLETWALL_INTERNAL_RESERVE` | **2,600** | **INTERNAL CHOICE.** 2,000 future-change reserve + 600 stop-condition margin |

> **The portability budget is a WalletWall constraint, and labelling it correctly changes what a
> breach means.** A kernel over 24,576 is not "illegal"; it is **non-portable to the smallest
> declared target**. That is a deployment-scope decision the owner may take, and it is why the
> budget is named separately instead of being spelled `EIP-170` everywhere.

> **A SCHEDULED CHANGE, recorded as an INPUT and explicitly NOT as authority.** For this pass the
> owner supplied that Ethereum's planned **Glamsterdam** upgrade includes **EIP-7954**, currently
> scheduled to raise the runtime limit `24,576 -> 65,536` and the initcode limit
> `49,152 -> 131,072`. **This lane did not verify that independently, and does not design against
> it.** It is recorded for exactly one purpose: it demonstrates that `NETWORK_RUNTIME_LIMIT` is
> **parameterised by fork**, which is why the parameterisation above exists. Nothing in this
> document may cite it as permission to exceed the portability budget, and **no figure anywhere in
> this document assumes it**. If it lands, the correct response is an owner decision to widen
> `WALLETWALL_PORTABILITY_BUDGET` for a **named subset of targets** — never a silent re-baselining
> of a budget whose whole purpose is to hold across chains that did not change.

**The architecture must remain valid under all three of these simultaneously**, and the
parameterisation is what makes that checkable rather than hoped for:

```text
Ethereum raises its limit          => NETWORK_RUNTIME_LIMIT(ethereum, next) > 24,576
another EVM chain keeps 24 KiB     => NETWORK_RUNTIME_LIMIT(thatChain, *)  = 24,576
another target has a third limit   => NETWORK_RUNTIME_LIMIT(other, *)      = something else

WALLETWALL_PORTABILITY_BUDGET  <=  min over declared targets of NETWORK_RUNTIME_LIMIT
```

*(Discriminated in the model: mutants **M50** and **M51**, §17.)*

### MEASURED — clean, non-instrumented compile at `15a44016` (current `main`, post-#180)

`npm run compile && npm run validate:bytecode-size` (solc 0.8.24, cancun, optimizer on, runs 200,
viaIR not set). The tree was cleaned and rebuilt before measuring; **coverage-instrumented bytecode
was never used for any figure here.**

| Contract | Runtime | % of 24,576 | Headroom | Creation |
|---|---|---|---|---|
| `WalletWallVault` | **23,239** | 94.6% | **1,337** | **24,582** |
| `StablecoinVaultSimulator` | 22,875 | 93.1% | 1,701 | 24,349 |
| `WalletWallMultiSigVault` | 8,714 | 35.5% | 15,862 | 10,071 |

> **Superseded figures, kept so the delta is auditable.** At the previous base `aaba4d2` these were
> 23,231 / headroom 1,345 / creation 24,574, and 22,867 / headroom 1,709. PR #180's
> `renounceOwnership` override added **+8 bytes** to each vault's runtime *and* creation code.
> **The consequence that holds:** headroom is now **1,337**, so §19's "at least one of the two
> competing fixes cannot fit" is *more* true, not less.
>
> **The second consequence claimed here is STRUCK (§19.0).** The previous revision added that
> `WalletWallVault`'s creation bytecode, at 24,582, "now exceeds the 24,576 runtime ceiling on its
> own — a fact B1 turns on". **It exceeds nothing.** 24,582 is initcode; the bound that governs
> initcode is `NETWORK_INITCODE_LIMIT(ethereum, current) = 49,152`, against which it sits at
> **50.0%** with **24,570 bytes** of headroom. `WalletWallVault` deploys today, which is the
> observable proof that no limit was breached. B1's rejection rests on the **factory's own runtime**
> and is untouched (§3.3).

### Deployment-model spikes — MEASURED, applied → measured → reverted → restoration proven

Four disposable contracts were compiled and, for the two viable models, actually **executed** against
the real `WalletWallVault` on an in-process network. Nothing survives in the tree.

| Spike | **Factory's OWN deployed runtime** | vs `NETWORK_RUNTIME_LIMIT(ethereum, current)` = 24,576 |
|---|---|---|
| **B1** — Solidity factory, `new WalletWallVault{salt}(…)` | **24,866** | **OVER by 290 — the FACTORY is undeployable** |
| **B2** — generic CREATE2 deployer, initcode via calldata | **657** | headroom 23,919 |
| **C / C2** — EIP-1167 factory: `cloneDeterministic`, CWIA variant, address predictor, atomic init | **1,760** | headroom 22,816 |

> **Read the column header literally.** Every figure in it is the **factory's own deployed runtime
> code**, compared against the limit that actually governs deployed runtime code. No child's
> initcode appears in this table, and none may be compared against this limit (§19.0).

solc emitted its own diagnostic on B1: *"Contract code size is 24866 bytes and exceeds 24576 bytes."*

**Per-vault deployment gas, MEASURED by executing each path against the real vault:**

| Path | Gas | Relative |
|---|---|---|
| baseline — a bare `CREATE` of `WalletWallVault`, no factory | 5,168,967 | — |
| **B2** — full contract per vault, initcode as calldata (24,614 B) | **5,181,105** | **81.3×** |
| **C** — EIP-1167 clone, deployment only | **63,692** | 1.00× |
| **C2** — clone + 20 bytes of immutable args | **69,342** | 1.09× |
| *(one-time)* B2 factory deployment | 195,331 | — |
| *(one-time)* C factory deployment | 434,867 | — |

> **Read the delta, not the ratio — and then read §19.2, which replaces the ratio entirely.** The
> **81.3×** figure compares *deployment only*; a clone must
> additionally run an `initialize()` performing the storage writes B2's constructor already performed,
> and those writes cost the same on both sides. What does *not* cancel is the **delta of 5,117,413
> gas**, of which **4,638,800 (90.7%)** is the protocol's flat 200 gas per runtime byte applied to
> 23,239 − 45 = 23,194 bytes. Stated so it cannot be argued with: **B2 pays for the kernel's entire
> size once per vault; C pays for it once per generation.** That is the whole of the deployment
> argument, and it is the reason C wins.
>
> Observed on chain, not assumed: clone runtime **45 bytes**, implementation runtime **23,239 bytes**.

**C2 — per-clone immutable arguments, MEASURED.** OpenZeppelin 5.6.1's
`Clones.cloneDeterministicWithImmutableArgs` appends bytes after the 45-byte template;
`fetchCloneArgs` reads them with `extcodecopy(instance, …, 0x2d, …)`. **The arguments are therefore
part of the clone's own runtime code**, and are committed to by both `extcodehash(clone)` and the
CREATE2 address. Measured: a 20-byte argument yields a 65-byte clone at **+5,650 gas (+8.9%)**; two
clones of the *same* implementation with *different* arguments have different code hashes; the
argument suffix reads back byte-exact.

**Code-identity spike — a defect this document previously did not record.** Two deployments of
**byte-identical source** produced runtime code differing in **51 of 23,239 bytes**. Every differing
byte lies inside a declared immutable slot; the artifact declares **seven** 32-byte immutable slots,
of which the one at offset **18,627** holds the contract's **own address**. Cause: inherited
OpenZeppelin `EIP712`, whose `_cachedThis` and `_cachedDomainSeparator` are `immutable`. See §3.1 and
§15 for the consequences and the offline-verification procedure that follows from them.

`contracts/` tree hash after revert: **`236eadb6bb1253285e1f55b175a4c81e294cb96f`** — byte-identical
to `origin/main:contracts`. `scripts/` restored to `f63c29caaf2c6361dcacfb2c1754a7bfb585f589`.
`git status --porcelain` empty. **No spike source remains.**

### What the numbers establish

1. **The current kernel has exhausted its evolution budget**, and by 8 bytes more than before. Two
   agreed security fixes bid for the same **1,337** bytes: guardian hardening at 675–1,650 B and
   recovery proof-of-possession needing 464 B against 339 B available. **At least one provably cannot
   fit.** The threat model is limited by `WALLETWALL_PORTABILITY_BUDGET` — a *runtime* bound
   (§19.0) — rather than by engineering judgement.
2. **B1's FACTORY is not deployable — a statement about B1's factory runtime, not about B, and not
   about any child's initcode.** Both earlier generalisations are withdrawn (§3.3, §19.0).
3. **B2 is constructible at 657 bytes and is rejected on measured cost**, not on feasibility.
4. **C's deployment path costs 1,760 bytes** for a factory that deploys, initialises atomically,
   supports immutable arguments, and predicts addresses.
5. **Clone-targeting does not relieve the kernel budget** (dissent D5), and §19.1 now measures the
   size of that non-relief: **23,249 bytes**, ten *more* than the monolith. C buys a deployment
   budget. It buys no bytes.

### 19.1 The clone-target spike — MEASURED, and what it does NOT settle

The previous revision left this as an open gate: *"C requires the kernel to be recompiled as a clone
target … that number has not been measured."* **It has now been measured.** A second disposable
spike was applied → measured → reverted → restoration proven, exactly as §19's first spike was.

**Mechanical scope of the transform**, stated completely because the result means nothing without it.
`WalletWallVault.sol` was copied and changed in **four** ways and no others — every edit was applied
by a script that asserts on its own anchor text, so a silently-missed edit fails loudly:

1. `constructor(address) Ownable(msg.sender) EIP712(...)` → an external `initialize(address,address)`;
   the retained constructor sets the replay guard so the **implementation itself is permanently
   initialised** and can never be initialised by a caller.
2. Inherited OpenZeppelin `EIP712` → a `CloneSafeEIP712` with **no `immutable` state**, rebuilding the
   domain separator from `block.chainid` and `address(this)` on every call.
3. A one-slot **initialization replay guard**.
4. Per-clone **immutable arguments**, read back through `Clones.fetchCloneArgs(address(this))` — i.e.
   out of the clone's own runtime code, never from storage and never from the factory.

**MEASURED — sizes** (clean, non-instrumented compile; solc 0.8.24, cancun, optimizer 200):

| Contract | Runtime | Initcode | Declared immutable slots |
|---|---|---|---|
| `WalletWallVault` (current monolith) | 23,239 | 24,582 | **7** |
| **`WalletWallVaultCloneTarget`** | **23,249** | **23,509** | **0** |
| Clone factory (immutable impl + CWIA + plain clone + predictor) | 2,036 | 2,250 | 2 |
| Generic CREATE2 deployer (B2 construction) | 369 | 398 | 0 |

| Quantity | Value |
|---|---|
| runtime vs `NETWORK_RUNTIME_LIMIT` 24,576 | **PASSES**, headroom **1,327** |
| runtime vs `WALLETWALL_PORTABILITY_BUDGET` 24,576 | **PASSES**, headroom **1,327** |
| runtime vs the **target kernel ceiling** 21,900 | **FAILS by 1,349** |
| initcode vs `NETWORK_INITCODE_LIMIT` 49,152 | PASSES, headroom 25,643 |

**MEASURED — gas.** Every repeated-path figure was taken **three times with distinct salts**, and
runs 2 and 3 were asserted equal, so each number is a steady-state cost rather than a first-write
artefact. *(This mattered: the first `cloneOnly` reading was 85,744 gas, of which ~17,100 was the
harness's own cold `SSTORE`. The steady-state figure is 68,644.)*

| Path | Gas |
|---|---|
| implementation deployment (**once per generation**) | **5,153,134** |
| factory deployment (once per generation) | **495,374** |
| C — clone deploy **only** | 68,644 |
| C2 — clone deploy **only**, 20 bytes of args | 74,280 (**+5,636**) |
| initializer, as its own transaction (incl. 21,000 intrinsic) | 93,498 |
| **C — deploy + initialize atomically, per vault** | **138,372** |
| **C2 — deploy + initialize atomically, per vault** | **144,374** (+4.3%) |
| **B2 — full monolith per vault** (initcode 24,614 B as calldata) | **5,181,028** |
| baseline — bare `CREATE` of the monolith, no factory | 5,168,967 |

**MEASURED — behaviour, OBSERVED on chain rather than argued:**

| Property | Result |
|---|---|
| implementation `initialize()` reverts (`I-DIRECT-IMPL-CALL-INERT`) | **YES** |
| clone `initialize()` replay reverts | **YES** |
| 20-byte immutable args read back byte-exact from clone code | **YES** |
| clone runtime length / with args | **45** / **65** |
| CREATE2 address predicted before deployment matches | **YES** |
| EIP-712 domain is per-clone (different `verifyingContract`) | **YES** |
| **two deployments of identical source are byte-identical** | **YES — 0 differing bytes** (monolith: **51**) |
| **artifact `deployedBytecode` hash == on-chain `extcodehash`** | **YES** (monolith: **NO**, 136 differing bytes) |

> **CLASSIFICATION: PROTOTYPE FEASIBILITY EVIDENCE. This does NOT settle Architecture C, and the
> temptation to read it as a verdict is exactly the error §19.0 just corrected in the other
> direction.** What was compiled is a **mechanically transformed current monolith**, not the vNext
> kernel. The architecture requirement is and remains:
>
> ```text
> the FINAL selected vNext kernel must fit every declared target deployment environment
> ```
>
> Only a candidate implementing the **actually selected minimal-kernel semantics** can settle that.
> The correct reading of the numbers is narrower and is stated as three separate findings:
>
> 1. **C is not EXCLUDED by size.** The transform lands at 23,249 — inside the portability budget
>    with 1,327 bytes to spare. The previously-stated failure mode ("if the transform pushes the
>    kernel past the ceiling, C is not constructible and B2 wins by default") **did not occur.**
> 2. **C is not VINDICATED either.** 23,249 is **1,349 bytes over the target kernel ceiling**, so
>    the transformed monolith has the same problem the monolith already had: it deploys, and it has
>    no evolution budget. A clone target that cannot absorb the next security fix is not a solution
>    to the byte problem; it is the byte problem in a different shape.
> 3. **A forecast in this document was WRONG, and correcting it is worth more than the byte count.**
>    §3.1 and §15.1 argued that removing the address-caching `EIP712` would restore hash stability
>    *and* implied a leaner kernel. Hash stability was delivered **completely** (7 immutable slots →
>    0; 51 differing bytes → 0). The size went the **other way**: **+10 bytes net**. Removing
>    OpenZeppelin's `ShortStrings` and seven immutables very nearly cancelled against adding
>    `initialize`, the replay guard and `fetchCloneArgs`. **Estimate nothing here; measure it.**

`contracts/` tree hash after the second revert: **`236eadb6bb1253285e1f55b175a4c81e294cb96f`** —
byte-identical to `origin/main:contracts`. `scripts/` unchanged at
`f63c29caaf2c6361dcacfb2c1754a7bfb585f589`. `git status --porcelain` empty.
**No spike source remains in the tree.**

### 19.2 Deployment economics — TOTAL generation cost, not marginal cost

> **The previous revision compared B2 and C on per-vault cost alone and reported an 81.3x ratio.
> A marginal-cost comparison is not a cost comparison**: it silently assigns C's one-time
> implementation deployment a cost of zero, which is exactly the term that decides whether C is
> worth doing at all for a small fleet. Total generation economics, from the figures above:

```text
B2_TOTAL(N)  =  N x 5,181,028

C2_TOTAL(N)  =  5,153,134  +  N x 144,374            (implementation + per-vault, per the brief)
C2_TOTAL*(N) =  5,648,508  +  N x 144,374            (+ the 495,374 factory, which D8 makes mandatory)
```

**Measured break-even.** `N* = 5,153,134 / (5,181,028 − 144,374) = 5,153,134 / 5,036,654 =`
**1.0231**, so the first integer fleet size at which C2 is cheaper in total is **N = 2**.
Including the factory: `N* = 1.1215`, and the answer is still **N = 2**.

| N | `B2_TOTAL` | `C2_TOTAL` | `C2_TOTAL*` (with factory) | B2 / C2 |
|---|---|---|---|---|
| **1** | **5,181,028** | 5,297,508 | 5,792,882 | **0.98x — B2 is CHEAPER** |
| **2** | 10,362,056 | 5,441,882 | 5,937,256 | 1.90x |
| **10** | 51,810,280 | 6,596,874 | 7,092,248 | **7.85x** |
| **100** | 518,102,800 | 19,590,534 | 20,085,908 | **26.45x** |
| **1,000** | 5,181,028,000 | 149,527,134 | 150,022,508 | **34.65x** |

> **Three things this table says that the 81.3x figure did not.**
> **(i)** At `N = 1` **B2 wins outright**. A single-vault deployment pays C2 an implementation it
> never amortises. The 81.3x ratio was never available at any fleet size — it is a *limit*, and even
> at `N = 1,000` the realised total-cost advantage is **34.65x**, not 81x.
> **(ii)** Break-even at **N = 2** is nonetheless decisive: the crossover is immediate, and the
> economic case for C does not depend on optimistic adoption forecasts.
> **(iii)** **Gas is not a security argument, and it is not used as one here.** It is one
> architecture input among several, and §3.3 already records the assurance cost C pays for it — a
> five-link code-identity chain where B2 has two. If per-vault deployment cost ever ceases to be a
> product constraint, that trade is re-openable, and B2 is a live alternative rather than a dead one.

### Target budget for the vNext kernel

| Quantity | Value | Basis |
|---|---|---|
| `WALLETWALL_PORTABILITY_BUDGET` | 24,576 | **WalletWall policy** — the minimum `NETWORK_RUNTIME_LIMIT` across declared targets (§19.0) |
| Safety margin (redesign trigger) | **600** | Adopted from the sibling lane's stop condition |
| Future-change reserve | **2,000** | ≥ the largest single unresolved fix (1,650 B) plus margin |
| `WALLETWALL_INTERNAL_RESERVE` | **2,600** | 600 + 2,000 |
| **Target kernel ceiling** | **≈ 21,900** | `WALLETWALL_PORTABILITY_BUDGET − WALLETWALL_INTERNAL_RESERVE`, rounded down |

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

**UNRESOLVED, and stated rather than guessed: no candidate vNext KERNEL has been compiled.** §19.1
compiled a **mechanically transformed current monolith** as a clone target, which is a different
object: it still carries the multi-tenant `vaults[]` dimension the vNext kernel deletes. Removing the
tenant dimension deletes seven per-tenant mappings and their keying, but the logic remains, and the
sibling lane's own experience is that independent estimates of the same change disagreed by 2.4×.
**No number for the vNext kernel's size appears in this document, because none has been measured** —
23,249 is the transformed monolith's number and may not be substituted for it in either direction.
It is an **upper bound on nothing**: the vNext kernel deletes tenancy but adds guardian commitments,
the migration manifest, the crypto lattice and the safe-state machine.

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
| **0** | ~~Fix `renounceOwnership()` in current `main`~~ — **DONE.** Shipped independently as **PR #180**, merged to `main` `15a44016`. Both vaults now override it to revert with `OwnershipRenunciationDisabled()`, declared `pure` so the ABI's `stateMutability` is tamper-evident. Measured cost **+8 bytes** each, exactly as forecast. | **Closed.** Hazard H-01 is CLOSED in current `main` and its history is preserved in the register rather than deleted. |
| **0a** | **Close hazard H-22** — gate `deposit()`/`depositFor()` with the same state check the payout paths carry. Still **live** at `15a44016`. | **DEMOTED back to product hygiene, and NOT a vNext prerequisite (§13.0a).** The previous revision promoted it on the ground that an open ingress lets a stranger veto a migration; that ground is withdrawn, because the stranger's asset never traverses a gated path. It remains a real current-product defect and a real parity defect, so it keeps a place in the sequence — but **nothing below it is gated on it**, and it may be done at any time, including after step 3. |
| 1 | Owner decisions D1–D6 (§22) | Nothing below is safe to build first |
| 2 | Freeze the kernel state layout and the safe-state lattice | Model conformance |
| 3 | **Compile the MINIMAL KERNEL candidate and MEASURE it** — as a CLONE TARGET: constructor converted to an external `initialize()`, and the address-caching `EIP712` removed (§3.1, §15.1). **The mechanical transform of the current monolith is now measured (§19.1) — that step is done and it did NOT overturn the verdict. What remains is the kernel itself.** | Must clear the 21,900 target ceiling with ≥600 B headroom against `WALLETWALL_PORTABILITY_BUDGET`, **else redesign**. The transformed monolith lands at **23,249** — inside the 24,576 budget, **1,349 over** the target ceiling — so this gate is still open, but it is now open on the *kernel's* content rather than on whether clone-targeting is possible at all. |
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

## 22. Owner decisions — classified, and adjudicated where they are technical

> **The previous revision called all seven "risk-appetite and product calls, not technical
> gaps, and this lane deliberately does not settle them." That framing is withdrawn.** Four of
> them are **architecture blockers**: they determine the authority graph, not the product. An
> architecture whose authority graph is undetermined is not an implementation contract.
>
> Each is now classified, and the technical part of each is adjudicated here. What remains open
> is named precisely, so the owner is asked one question rather than seven.

| # | Decision | Class | Status |
|---|---|---|---|
| **D1** | Guardian-majority trust | ~~ARCHITECTURE BLOCKER~~ | **LOCKED by owner decision.** Quorum of `k` is an accepted recovery trust root; **`guardian compromise cut = k`** |
| **D2** | Migration authority | **ARCHITECTURE BLOCKER** | **RESOLVED** |
| **D3** | ERC-4337 adoption | DEFERRED INTEROPERABILITY | Deferred; generation 1 does not adopt |
| **D4** | Shared verifier coupling | **ARCHITECTURE BLOCKER** | **RESOLVED — forced by section 4.3a** |
| **D5** | Containment authority | **ARCHITECTURE BLOCKER** | **Structurally RESOLVED**; constants OPEN |
| **D6** | Policy-disable semantics | PRODUCT CHOICE | Deferrable — verified it cannot change kernel layout |
| **D7** | PR #178's ECDSA PoP leg | DEFERRED | Blocked on D1 and the byte budget |
| **D8** | Factory generation-registration authority | ~~ARCHITECTURE BLOCKER~~ | **LOCKED by owner decision.** One immutable factory per kernel generation; the principal is **deleted**, not governed |

### D1 — guardian trust model — **LOCKED by owner decision**

> **DECIDED. The appetite question is CLOSED, and the adopted position is stated as an assumption
> rather than as a mitigation:**
>
> ```text
> A quorum of >= k valid current-generation guardians
> IS AN ACCEPTED RECOVERY TRUST ROOT.
>
> guardian compromise cut = k
> ```
>
> A malicious quorum is therefore an **explicitly accepted catastrophic compromise condition**, in
> §2.2, asserted positively by the model rather than omitted from it.

**The claim this decision forbids, permanently.** WalletWall may **not** claim it cryptographically
protects against a malicious guardian quorum while simultaneously allowing that same quorum to
recover credentials. Those are the same capability described twice. Any sentence of the form
*"even a malicious majority of guardians cannot …"* is false by construction under this decision and
must be struck wherever it appears.

> **THE AUTHORITY-CUT RULE, which is where the previous revision overreached.** It wrote that the
> bounded challenge *"is the only mechanism here that raises the cost of path B"*, and §24 then let
> that stand next to the cut arithmetic in a way that reads as though the cut improves. **It does
> not.**
>
> ```text
> a challenge / delay increases:   TIME, VISIBILITY, operational attack COST
> a challenge / delay does NOT increase:   the PRINCIPAL COMPROMISE CUT
>
> the cut rises ONLY IF another INDEPENDENT PRINCIPAL is MANDATORY on the path
> ```
>
> The bounded challenge adds no principal — the challenger is the spending credential, a principal
> already counted, and the challenge is finite by design (`I-VETO-BOUND`). An attacker who holds `k`
> guardians and waits out `k_challenge x recoveryDelay` reaches assets having compromised **`k`
> roots, not `k + 1`**. The challenge is a **cost and detection** control. It is worth having. It is
> not a cut. *(Discriminated in the model: mutant **M57**, §17.)*

**The technical part is settled and the answer is uncomfortable.** A second *independent factor*
for recovery is not available, because the obvious candidate is self-defeating: a factor the
**user** must hold makes recovery unavailable in precisely the scenario recovery exists for —
the user lost everything. A factor a **third party** holds is a new principal with its own
closure, and section 8 would then have to report it reaching assets.

**What IS available is not an authority — it is a bounded challenge.** The spending credential
may cancel a pending recovery **at most k times per episode**:

- `k = 0` leaves a guardian majority **unchallengeable** (hazard H-15);
- unbounded `k` restores hazard **H-03** — a permanent veto held by exactly the principal whose
  compromise recovery exists to remedy;
- a finite, non-zero `k` costs the attacker `k x recoveryDelay` **and** requires the credential
  holder to be absent throughout, while leaving an honest user `k x recoveryDelay` to migrate out.

This is the **only** mechanism in the design that raises the cost of the **dominant** attack path
(section 24) without creating a new principal. It is modelled, and both failure directions are
discriminated (mutant M27). `CREDENTIAL_CHALLENGE_LIMIT = 2` in the model is an illustrative
value, not a recommendation.

> **ANSWERED — YES.** Guardian-majority takeover is **accepted** as an unrecoverable condition.
> §2.2 keeps it, and §8's closure goes on **asserting it positively**: an authority graph that
> omits a real path is worse than none. The alternative branch — "the architecture needs a factor
> this adjudication could not find" — is closed, not deferred. **This was a risk-appetite question,
> the owner has answered it, and D1 is no longer an architecture blocker.**

### D2 — migration authority (architecture blocker; RESOLVED)

Three roles, deliberately not held by one principal:

| Role | Who | Why |
|---|---|---|
| **BIND** (select the destination) | guardian quorum **AND** credential authority | Destination selection closes over *everything* (H-10) |
| **RETIRE** (freeze authority) | the same conjunction, after `bindDelay` | Irreversible; needs the same bar as binding |
| **EGRESS** (move one asset) | **anyone** | It carries **no discretion**: recipient from the binding, amount is the whole balance |

**Can any single principal select the destination AND move assets? No** — by construction, and
asserted in the model. The answer to *who may execute* is deliberately **anyone**, which is safe
only because `I-EGRESS-RECIPIENT-FIXED` holds; remove that and the same design becomes a public
withdrawal function (mutant M44).

**The non-obvious constraint, and the one this adjudication would have missed without composing
two blockers: `bindDelay >= recoveryDelay`.** Migration and recovery are reachable by the *same*
coalition. A faster migration is a strictly better attack — same prerequisites, less warning,
irreversible (section 13.2, mutant M43).

### D4 — does the factory stamp a shared verifier into every clone? (RESOLVED, and forced)

**Yes, it may — but only into STORAGE, never into immutable args.** The distinction is now
load-bearing (section 3.3): args are unchangeable, and a verifier must remain replaceable for
agility and for hazard H-06. What must never be stamped is anything that makes the coupling
*inescapable*.

**Cohort blast radius, quantified per behaviour and per mode:**

| Verifier behaviour | `Hybrid` (admitted) | `PqOnly` (rejected) |
|---|---|---|
| Byzantine (always true) | **cohort-wide silent DOWNGRADE** to ECDSA-only. No loss. Detectable only by reading the verifier's code. | **cohort-wide TOTAL LOSS** |
| Unavailable / reverting | cohort-wide **denial** of spending. Recovery unaffected (section 9). | cohort-wide denial **and** no escape |

**Can each vault leave that verifier generation without depending on it?** Under `Hybrid`,
**yes** — the replacement is authorized by the `ecrecover` conjunct, which the verifier cannot
influence. Under `PqOnly`, **no** — the escape is authenticated by the component being escaped.

> **So D4's answer is not independent: it is produced by section 4.3a.** Rejecting `PqOnly` is
> what converts the cohort coupling from a **trap** into a **default a vault can leave using its
> own authority**. Two blockers, one mechanism, and neither is safe without the other.

### D5 — containment authority (structurally RESOLVED; constants OPEN)

| Question | Answer |
|---|---|
| Who may trigger | The emergency principal, or a guardian quorum |
| Maximum duration | `CONTAINMENT_MAX_DURATION`, wall clock, non-suspending |
| **Do repeat triggers extend it?** | **No.** Re-entry while contained is a **no-op** (M25) |
| Cooldown | A **rolling budget**: at most `B` contained time per window `W`, with **`B < W`**, the window origin advancing **only** by elapsed wall clock (M24) |
| What remains live | **All four recovery actions**, plus migration binding and egress |
| What exits containment | **Nobody.** Wall-clock expiry only |

**`B < W` is the entire content of the rule**: it guarantees an infinite sequence of uncontained
intervals, so denial is a **duty cycle** rather than a state. Kernel cost: two words.

> **This closes a real hole rather than tightening a parameter.** The previous revision said
> containment was "wall-clock bounded and self-expiring" and said nothing about re-triggering —
> so a hostile emergency principal could hold an indefinite rolling freeze using a capability the
> document itself called bounded. **Per-episode bounds do not compose into a bound on the
> authority.** **OPEN:** the numeric values of `CONTAINMENT_MAX_DURATION`, `B` and `W`, and who
> holds the emergency principal. Those are operational.

### D6 — policy-disable semantics (product choice; deferrable, and verified so)

Deferrable **because it cannot change the kernel's state layout**: the policy plane is one storage
word under every reading, and "disabled" resolves to the kernel floor rather than to "no
restriction" (section 4.3). It is a behavioural question about a plane, not a kernel question.

### D8 — factory generation-registration authority (NEW; architecture blocker)

> **This decision was absent from the previous revision, and its absence was a gap in the
> authority graph.** Section 8 records "Kernel admin — **NONE**, the principal does not exist".
> True *per vault*. But under C **somebody decides which implementation the factory points at**,
> and that decides what every FUTURE vault *is*, immutably. That is a capability-**ADDING** power
> inside a doctrine (section 4.3) that forbids them.

> **DECIDED. The recommendation is ADOPTED as a rule, and D8 is no longer an architecture blocker.**
>
> ```text
> ONE IMMUTABLE FACTORY PER KERNEL GENERATION.
> The factory's implementation target is immutable after deployment.
> ```

**Forbidden outright, by name, so that a future PR must argue against a written rule rather than
into a gap:**

```text
setImplementation
upgradeFactory
registerNewKernel on an EXISTING generation
beacon
any mutable implementation registry that controls an existing generation's identity
```

**A new kernel generation is a four-step act, and none of the steps is a permission:**

```text
1. deploy K(n+1)                                    a new implementation
2. deploy F(n+1), immutably bound to K(n+1)         a new factory
3. publish assurance evidence for the pair          the five-link chain, section 15
4. explicit per-user / per-vault migration          section 13, never automatic
```

**What the factory may and may not expose.** It may expose **deterministic deployment mechanics** —
`CREATE2` salts, an address predictor, atomic deploy-and-initialize, immutable-argument append. It
may **not** expose **discretionary generation-selection authority**: no call may cause a *different*
implementation to be used than the one baked into the factory at its own deployment.

**MEASURED — the rule is constructible, not merely stated.** The §19.1 spike factory implements it
exactly (`address public immutable implementation`, plus an `immutable generation`), at **2,036 bytes**
of runtime and **495,374 gas** to deploy — a per-generation cost, carried once, already included in
§19.2's `C2_TOTAL*`.

#### D8 authority graph, RECOMPUTED under the rule

| Principal | Direct authority | Closure | Reaches assets? |
|---|---|---|---|
| **Factory operator, retargetable factory** *(the rejected alternative)* | `setImplementation` | defines the kernel of every future vault **at will, repeatedly** | No for deployed vaults — but a **standing live admin**, which §4.3's doctrine forbids |
| **Factory deployer, immutable factory** *(ADOPTED)* | **NONE.** The capability is consumed at construction | **EMPTY** | **No** |
| **Generation publisher** | Chooses which factory address is *advertised* | **DISCOVERY only** | **No** |

> **The rule does not merely bound the principal — it deletes it.** Under a retargetable factory the
> operator is a *standing* authority: it can act again tomorrow, and every future vault is hostage to
> its continued good behaviour. Under an immutable factory the choice is made **once, at
> construction, by the deployer, and is then unreachable by anyone including the deployer**. There is
> no principal left to govern, no key to rotate, and no timelock to design. That is a strictly
> stronger outcome than governing the same power well, and it is the same move §22 D4 makes with
> immutable args and §3.1 makes by rejecting the beacon.

**Residual, stated rather than dissolved:** whoever publishes a factory address still influences
which generation users *find*. **That residual is now the ONLY thing left of D8**, it is a
**discovery** problem rather than an authority one, and it is bounded by §15's offline verification,
which lets a user check what they actually got without trusting the publisher. It is recorded as a
**cohort** hazard (H-32), not a system one: a mis-advertised factory can mislead future vaults and
can never touch an existing one. *(Discriminated in the model: mutant **M56**, §17.)*

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

**PR #180 (disable unsafe ownership renunciation) — MERGED.** Sequencing step 0 of §21, shipped
independently of any vNext verdict, exactly as this lane recommended. Both vaults now override
`renounceOwnership()` to revert, at a measured **+8 bytes** each. **Hazard H-01 is CLOSED in current
`main`.** The history is preserved rather than deleted (§25): a T0 hazard found by architecture
review, fixed in its own narrow PR, and re-verified here firsthand is stronger assurance history
than a register that never mentions it.

---

## 24. The authority labyrinth — minimum compromise cuts

> Enumerating *controls* is not the same as enumerating *paths*, and counting **controls** is not
> the same as counting **independent failure roots**. Two credentials derived from one seed are
> **one** root. A system is exactly as strong as its cheapest path, not as its most elaborate one.

For each catastrophic outcome: the distinct paths, and the **minimum coalition of independent
roots** that reaches it. `n` is the guardian count and `k = floor(n/2) + 1` the quorum.

### 24.1 Unauthorized asset control

| Path | Requires | Independent roots |
|---|---|---|
| **A — front door** | The spending credential: ECDSA **and** PQ under `Hybrid` | **2** if the keys are independently rooted; **1** if both derive from one seed |
| **B — social** | `k` guardians → recovery → new credentials → assets | **k**, and **1** if the guardians share a root (one custodian, one vendor, one family) |
| **C — migration** | `k` guardians **and** the credential → bind → egress | **k + 1** — strictly harder than B, and never the minimum |
| **D — verifier** | Install/operate an always-true verifier under `PqOnly` | **1** |
| **E — global admin** | Only under `SHARED_MULTITENANT` | **1** |

**Minimum cut before this remediation: 1**, by path D. A single component whose *only* job is to
answer a question would have reached total loss, bypassing — not defeating — every quorum, delay,
binding, code-hash re-check and safe-state transition in the document.

**Minimum cut after this remediation: `min(2, k)`.** Path D is deleted by rejecting `PqOnly`
(§4.3a); path E by architecture C. With the realistic `n = 3, k = 2`, that is **2**.

> **Say the uncomfortable part plainly: path B dominates.** For `n = 3`, two guardians reach assets
> — the same count as compromising both credential factors, but with **no cryptography to break**.
> **Adding a third credential factor does not raise the system's minimum cut.** Every elaborate
> front-door control is bounded above by a social path with a smaller constant.

> **REVISED under the D1 lock — and the revision is a subtraction, not an addition.** D1 is now
> decided: **a quorum of `k` guardians IS an accepted trust root, and `guardian compromise cut = k`.**
> Path B is therefore not a *finding* about the design; it is the design's **declared assumption**,
> and §2.2 carries it as an accepted unrecoverable condition.
>
> **The bounded challenge is re-scored accordingly.** The previous revision's phrasing — that it
> "raises the cost of path B … without creating a new principal" — is true and was being read as
> though it improved the cut. **It does not, and the corrected rule is now explicit (§22 D1):**
>
> ```text
> guardian path cut  =  k        with the bounded challenge
> guardian path cut  =  k        without it
> ```
>
> A delay buys **time, visibility and operational cost**. The cut moves **only** when an independent
> principal becomes **mandatory** on the path, and the challenger — the spending credential — is a
> principal the graph already counts. Every claim in this document that reads as though a delay
> hardens the trust root is corrected to say what it actually does. *(Mutant **M57**.)*

**The correlation caveat is not a footnote.** `k` counts *addresses*, and independence is an
assumption about the world, not a property the chain enforces. Three guardians on one custodian is
**one** root. The `rootTag` field of the `SecurityProfile` exists to make this representable for
credentials (§12); nothing analogous exists for guardians, and that gap is recorded as **H-31**.

### 24.2 Every other catastrophic outcome

| Outcome | Cheapest path | Minimum cut | Note |
|---|---|---|---|
| **Credential replacement** | rotation, or recovery | `min(2, k)` | Identical to 24.1 minus the migration path |
| **Guardian takeover** | `k` guardians | **k** | **DECLARED TRUST ROOT (D1, LOCKED).** Accepted (§2.2), asserted positively by the model. Unchanged by any delay or challenge |
| **Factory / generation takeover** | — | **unreachable** | **D8 LOCKED:** the factory's implementation is `immutable`, so no principal can retarget a generation. Previously this row did not exist |
| **Migration takeover** | quorum **and** credential | **k + 1** | Strictly dominated; never the system minimum |
| **Permanent recovery veto** | — | **unreachable** | Containment self-expires under a budget; the credential's challenge is bounded; H-01 closed by #180 |
| **Silent crypto downgrade** | — | **unreachable** | Every weakening transition is refused by the partial order (§12); an *overt* deprecation needs the `PROFILE_CHANGE` authority |
| **Denial of spending** | one verifier or one policy plane | **1** | **Accepted.** Denial is inside the envelope; loss is not. Recovery and migration stay available |

> **The one-line summary of the whole graph.** After this remediation no *loss* outcome has a
> minimum cut below **`min(2, k)`**, and no *veto* outcome is reachable at all — but **denial**
> still has a cut of **1**, and that is a deliberate, declared trade rather than an oversight. Every
> plane in this design is a liveness single point of failure by construction, because "planes may
> only SUBTRACT authority" is a statement about **safety** and says nothing about **availability**.
> Subtracting availability *is* granting a veto over liveness, and the design accepts that in
> exchange for failing closed on spending — which is why §9 puts recovery and §13 puts egress
> outside every plane's reach.


---

## 25. Remediation record — what was attacked, what changed, what was refused

This section exists because a document that only contains its conclusions is not reviewable, and
because a remediation that quietly deletes its own errors destroys the evidence that it worked.

### 25.1 Claims WITHDRAWN, with what replaced them

| Withdrawn claim | Why it was wrong | Replacement |
|---|---|---|
| "Architecture B is **NOT CONSTRUCTIBLE**" | Generalised from one *construction* failing to the whole class. Only **B1** was measured. | §3.3: B1 measured at **24,866 B, over by 290**; **B2 constructible at 657 B** and rejected on a measured **81.3x** deployment cost |
| "An always-true verifier **grants nothing**" | True of the plane's *marginal* contribution; false of the *composition*, because the floor contains no possession test. Refuted by `MockMLDSAVerifier`, already in this repo. | §4.3a: `I-NO-SOLE-EXTERNAL-AUTHENTICATOR`, `I-FLOOR-IS-SOUND`; **`PqOnly` rejected** |
| "`extcodehash(clone)` is a total function of the implementation" | True, and it proves only which **address** is delegated to. MEASURED: an implementation's own code hash is **address-dependent**. | §3.1 and §15.1: a five-link chain, an eight-identity publication, a masking procedure |
| "`newStrength >= oldStrength`" over a scalar | Summarises a **disjunction** by MAX; asserts a total order across incomparable families | §12: a `SecurityProfile` and a **partial** transition relation that refuses incomparables |
| "Partial migration is disallowed; a failing token aborts the whole migration" | Unimplementable and unsafe: an **unprivileged stranger** can veto the escape | §13: manifest, per-entry egress, perpetual retry, salvage |
| "Guardian **membership** is KERNEL-REQUIRED" | Conflated guardian **authority** with the roster **bytes** | §4.2b: **G-B** — commitment + threshold + generation in the kernel; roster as validated calldata |
| "Recovery performs **zero external calls**" | Unsatisfiable under EIP-1167 — every clone entry is a `DELEGATECALL` — and it forbids `ecrecover`, which §4.3a makes mandatory | §9: `I-RECOVERY-LOCALITY-V2`, plus `I-GUARDIAN-FAULT-ISOLATION` |
| "Containment is wall-clock bounded and self-expiring" | Silent on **re-triggering**. Per-episode bounds do not compose into a bound on the authority | §6 and §22 D5: `I-CONTAINMENT-NO-EXTENSION` + `I-CONTAINMENT-BUDGET`, `B < W` |
| "H-01 is **live** in current `main`" | Fixed by **PR #180**, merged. Re-verified firsthand here | Register: **CLOSED IN CURRENT MAIN**, discovery history preserved |
| "The seven owner decisions are risk-appetite and product calls" | Four are **architecture blockers**; a fifth (D8) was missing entirely | §22: classified and adjudicated. **D1 and D8 are now DECIDED**, so no architecture-blocking decision remains open |
| "`WalletWallVault` declares **no** `immutable` variables" | True of its own source; misleading — it **inherits seven**, two address-derived | §3.1, and R3's conclusion survives unchanged |
| FIPS 204 §3.6.2 cited for structural length rejection | **NOT VERIFIED in this lane.** Four independent reviewers flagged it and none checked it | §4.3: the requirement restated on engineering merit; the citation marked UNVERIFIED and made non-load-bearing |

**Added by the final architecture-correction pass — six of this document's OWN claims:**

| Withdrawn claim | Why it was wrong | Replacement |
|---|---|---|
| "`WalletWallVault`'s **creation** bytecode, at 24,582, exceeds the 24,576 runtime ceiling on its own — a fact B1 turns on" | **Category error.** EIP-170 governs deployed **runtime**; initcode is governed by EIP-3860 at **49,152**. The comparison was against a bound that does not apply, and B1 never needed it | §19.0: four separate quantities and an explicit truth table; B1's rejection restated on the **factory's own runtime** (24,866). Regression-asserted, and mutant **M50** |
| "EIP-170 ceiling — 24,576 — **Protocol**" as a single eternal constant | Conflates a **network** limit with a **WalletWall policy**, and hides that the limit is per-chain and per-fork | §19.0: `NETWORK_RUNTIME_LIMIT(chain, fork)`, `NETWORK_INITCODE_LIMIT(chain, fork)`, `WALLETWALL_PORTABILITY_BUDGET`, `WALLETWALL_INTERNAL_RESERVE`. Mutant **M51** |
| "H-22 … is now a **prerequisite**, not hygiene" and "it is the mechanism by which an unprivileged stranger can veto a migration" | **False.** The attacker uses `transfer` / `selfdestruct` / an airdrop / a rebase and traverses no gated path, so the gate cannot prevent the attack. OBSERVED: forced ETH already reaches the live vault and the repo already tests it | §13.0a: four questions answered separately — current-product **YES**, parity **YES**, containment policy **YES**, architecture prerequisite **NO**. `I-MIGRATION-NONTRAP` strengthened instead. Mutants **M52**, **M53** |
| "There is **no single publishable 'audited kernel code hash'**" | Too broad. What may not exist is *one universal source-level hash valid at every address*; an authoritative hash for a **particular deployment** always exists | §15.1a: SOURCE/BUILD vs DEPLOYMENT vs NORMALIZED REPRODUCIBILITY, measured on both sides. The five-link chain is **unchanged**. Mutants **M54**, **M55** |
| "That number has not been measured, and no vNext kernel has been compiled" *(as a standing gate on C)* | The gate was real and is now discharged — for the transformed monolith. **MEASURED** | §19.1: 23,249 B runtime, **0** immutable slots, byte-identical redeployment. Classified **PROTOTYPE FEASIBILITY EVIDENCE**, not a verdict |
| "**81.3x**" as the B2-versus-C cost comparison | A **marginal**-cost ratio presented as a cost comparison; it assigns C's one-time implementation a cost of zero and is unavailable at any fleet size | §19.2: `B2_TOTAL(N)` vs `C2_TOTAL(N)`, measured break-even at **N = 2**, realised advantage **0.98x** at N=1 and **34.65x** at N=1,000 |

### 25.2 Claims that SURVIVED the attack unchanged

Recorded because a remediation that overturns everything is not adjudicating, it is oscillating.

- **Architecture C wins** — for a measured reason rather than a mistaken one, and the reason is now
  stated as **total** generation economics (break-even **N = 2**, §19.2) rather than as the marginal
  81.3x ratio. The verdict survived; its justification was corrected twice.
- **Planes may only SUBTRACT authority.** Correct, and necessary. It was never *sufficient*.
- **No generic privileged execution**, and interoperability does not force it.
- **Recovery must remain available in every non-terminal state.**
- **Migration execution must remain available from a terminal state** — now with a definition of
  *terminal* that makes the sentence coherent (§13.3).
- **Clocks are wall-clock and must not suspend** — now generalised to *every* clock (§6).
- **Guardian-majority takeover is asserted positively** by the authority closure.
- **The assurance plane's closure is empty.**
- **No candidate vNext KERNEL has been compiled**, so no forward byte figure is claimed for it.
  §19.1's 23,249 is a **transformed monolith**, and is never substituted for the kernel's size.

### 25.3 Proposals considered and REFUSED, with the reason

Adversarial review produced roughly sixty candidate kernel requirements. Adopting all of them
against **1,337 measured bytes of headroom** would itself have been a defect, so what was *not*
adopted is part of the record.

| Refused proposal | Reason |
|---|---|
| Build an on-fork differential bytecode harness in this lane | Requires production Solidity, which this lane forbids. §16.1 instead **routes** those invariants to the implementation lane and claims **no** assurance for them here |
| A monotone strength **high-water mark** | Reintroduces the scalar the partial order replaces. Its real content — that deprecation must not silently permit re-activation — is covered by the absorbing lattice |
| Bind the initial constituency into the CREATE2 salt | Sound, but IMPLEMENTATION-LANE: unprovable in a state model. Recorded as a requirement, not a result |
| Prove-before-strengthen on profile activation | An implementation technique, not an architectural invariant. No discriminator that would not be vacuous here |
| Re-derive the destination by address rather than code hash | Weaker, not stronger: an address is not evidence about code. The correction actually needed was to hash the destination **VAULT**, not its implementation (§13.5) |
| Treat plane **unavailability** as an authority violation | It is a **liveness** fact, and conflating the two would make the subtractive doctrine unfalsifiable. Recorded instead as an explicit accepted residual with a minimum cut of **1** (§24.2) |

### 25.4 What still cannot be claimed

1. **No conformance claim.** Nothing here establishes that any Solidity satisfies any invariant.
2. **No vNext KERNEL exists or has been compiled.** §19.1 compiled a *transformed monolith*, which is
   a different object; its 23,249 bytes may not be substituted for the kernel's size in either
   direction.
3. **The invariant set is not proven complete.** Two consecutive revisions demonstrated this
   concretely: the previous one found an entire missing decision (D8) and an entire missing hazard
   class (§13.0 case 6); **this one found that two of its own load-bearing claims were wrong** — an
   initcode/runtime category error (§19.0) and an H-22 prerequisite that could not do the work
   assigned to it (§13.0a).
4. **The deployment verdict's CONDITION is discharged, and the verdict is still not a licence.**
   §19.1 measured the clone target: C is **not excluded** by size. It is also **not vindicated** —
   23,249 sits 1,349 bytes **over** the target kernel ceiling.
5. **D1 and D8 are DECIDED, so they are no longer blockers.** What that buys is stated exactly:
   the architecture's authority graph is now determined. It does **not** make the architecture
   implementation-ready, and §25.5 lists what still stands.

### 25.5 Blockers after this pass — re-adjudicated from scratch, not carried forward

> **The previous list is NOT inherited.** Each entry below was re-derived against the corrected
> document; entries that no longer hold are recorded as closed rather than quietly dropped.

**CLOSED by this pass:**

| Was | Why it is closed |
|---|---|
| Clone-target kernel runtime **UNMEASURED** | **MEASURED** (§19.1): 23,249 B, 0 immutable slots, inside the portability budget with 1,327 B headroom. The failure mode it guarded against did not occur |
| **D1** appetite call OPEN | **DECIDED** (§22 D1): quorum of `k` is an accepted recovery trust root; `guardian compromise cut = k` |
| **D8** confirmation OPEN | **DECIDED** (§22 D8): one immutable factory per kernel generation; the principal is deleted |
| **H-22 is a prerequisite** | **WITHDRAWN** (§13.0a): the claim was false — the attack traverses no gated path. H-22 stays open as product hygiene and a parity defect, gating nothing |
| *(newly found and closed in the same pass)* the EIP-170/initcode comparison | **CORRECTED** (§19.0), with a regression assertion so it cannot return |
| *(newly found and closed in the same pass)* "no publishable kernel code hash" | **NARROWED** (§15.1a) into three identities, and measured on both sides |

**STILL OPEN — and each is an engineering task, not an adjudication:**

| # | Blocker | Why it still stands |
|---|---|---|
| **B-1** | **No minimal-kernel candidate has been compiled.** | The whole size question is now about the kernel's *content*. The transformed monolith is inside the portability budget and **1,349 B over the target ceiling**, so a kernel that merely inherits the monolith's bulk fails the stop condition even though it deploys |
| **B-2** | **`I-PURE-CONSTRUCTOR` is demonstrated, not delivered.** | Shown achievable on a transformed monolith (7 immutable slots → 0). The vNext kernel must reproduce it, and only its own artifact can show that |
| **B-3** | **D5's constants remain unset** — `CONTAINMENT_MAX_DURATION`, `B`, `W`, and who holds the emergency principal. | Structurally resolved; the numbers are operational and unchosen. **Not an architecture blocker** |
| **B-4** | **H-31: guardian independence is unrepresentable.** | `k` counts addresses; `rootTag` exists for credentials and has no guardian analogue. An accepted, *declared* limit on §24's arithmetic — it bounds what the cut numbers mean |
| **B-5** | **H-17: the attestation verifier still depends on a trusted off-chain attestor**, and `updateAttestor` is immediate rather than timelocked. | G5 is not met on that path. Untouched by this pass |
| **B-6** | **Every IMPLEMENTATION-LANE and OBSERVATORY invariant in §16.1 carries no assurance from this PR.** | Structural and permanent for a design-only lane. Named so it is never mistaken for coverage |

> **What "ready for a minimal-kernel prototype" means, and what it does not.** Every open item above
> is a thing to *build and measure*, not a question to *settle* — that is the difference this pass
> made. **B-1 and B-2 are discharged by compiling the first candidate**, which is precisely the
> activity being authorised. **B-3 through B-6 are accepted residuals** carried into that activity
> with their eyes open. **None of this authorises production implementation**, and §21's stop
> condition — redesign below 600 bytes of headroom — is unchanged and binding.
