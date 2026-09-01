# WalletWall Vault vNext — Hazard Register

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> This register describes a **proposed** vNext architecture alongside the **observed** current
> implementation. Nothing here is deployed. Nothing here is a mainnet write path. The repository
> does not custody user funds, does not process production withdrawals, and produces no real yield.
> Local and Sepolia simulator paths are developer/testnet rehearsal exceptions only.

## How to read this register

This is a safety-engineering hazard register, not a bug list. A hazard is a *condition that can
lead to loss*, whether or not any defect exists today. Each entry carries ten fields, per the
structure agreed for this lane.

Every entry is tagged with its evidentiary status. These are not interchangeable:

| Tag | Meaning |
|---|---|
| **OBSERVED** | Verified firsthand in `contracts/**` at `origin/main` `15a44016` (post-#180). A citation is given. |
| **PROPOSED** | A vNext design intent. Not implemented anywhere. Carries no assurance. |
| **PROVEN-BY-MODEL** | Killed by a discriminating mutant in `test/VaultVNextArchitectureModel.test.ts`. Proves the *architecture* is coherent, **never** that any Solidity conforms to it. |
| **RESIDUAL** | Accepted. Stated deliberately rather than mitigated. |
| **UNRESOLVED** | Open. No verdict. Requires an owner decision or further work. |

Proof tiers are defined in `docs/Vault_vNext_Architecture.md` §17:
**T0** catastrophic kernel invariants · **T1** authority/recovery boundaries ·
**T2** capability-plane safety · **T3** ordinary functionality.

**Blast radius** is stated as `per-vault` / `cohort` / `system-wide` throughout. A hazard whose
blast radius is system-wide is not made per-vault by asserting isolation elsewhere.

---

## Summary

| # | Hazard | Status | Tier | Blast radius |
|---|---|---|---|---|
| H-01 | Irreversible admin pause via `renounceOwnership()` | **CLOSED IN CURRENT MAIN** (#180) | T0 | system-wide |
| H-02 | Unrotatable tenant identity key | OBSERVED | T1 | per-vault |
| H-03 | Credential-keyed veto over honest recovery | OBSERVED | T1 | per-vault |
| H-04 | Recovery installs credentials with no proof of possession | OBSERVED | T1 | per-vault |
| H-05 | Silent cryptographic downgrade by verifier substitution | OBSERVED | T1 | system-wide |
| H-06 | Reverting or gas-burning verifier bricks all spending | OBSERVED | T2 | system-wide |
| H-07 | Policy engine disabled wholesale by a single principal | OBSERVED | T2 | system-wide |
| H-08 | Policy-plane outage denies settlement | OBSERVED | T2 | system-wide |
| H-09 | Controller/kernel generation divergence | PROPOSED | T2 | cohort |
| H-10 | Migration destination substitution | PROPOSED | T1 | per-vault |
| H-11 | Migration authority becomes an unavoidable super-admin | PROPOSED | T0 | per-vault |
| H-12 | Emergency principal acquires a permanent recovery veto | OBSERVED | T1 | system-wide |
| H-13 | Emergency transition increases effective authority | PROPOSED | T1 | per-vault |
| H-14 | Treasury-quorum stranding | OBSERVED | T2 | per-vault |
| H-15 | Guardian-majority takeover | **ACCEPTED (D1)** | T1 | per-vault |
| H-16 | Reference-model (simulator) parity drift — PARTIAL coverage exists | OBSERVED | T2 | cohort |
| H-17 | Operator disappearance strands recovery | PROPOSED | T1 | system-wide |
| H-18 | Assurance plane acquires actuation authority | PROPOSED | T1 | system-wide |
| H-19 | Guardian-plane controller indirect takeover | PROPOSED | T1 | cohort |
| H-20 | Byte budget exhaustion forecloses security fixes | OBSERVED | T0 | system-wide |
| H-21 | Vault born unguarded | OBSERVED | T1 | per-vault |
| H-22 | Deposits accepted while withdrawal is frozen | OBSERVED | T2 | system-wide |
| H-23 | Generic execution authority admitted at a standards boundary | PROPOSED | T0 | per-vault |
| H-24 | Attestor rotation outside the verifier timelock | OBSERVED | T1 | system-wide |
| H-25 | Pooled custody carries no solvency invariant | OBSERVED | T0 | system-wide |
| H-26 | Cross-tenant replay separation rests on a signed field, not the domain | OBSERVED | T1 | system-wide |
| H-27 | Guardian-set commitment intact, preimage unrecoverable | PROPOSED | T1 | per-vault |
| H-28 | A third party vetoes migration by planting a hostile asset | OBSERVED (mechanism) | T0 | per-vault |
| H-29 | An implementation's runtime code hash is address-dependent | **MEASURED** | T1 | cohort |
| H-30 | A bounded emergency authority holds an indefinite rolling freeze | PROPOSED | T0 | per-vault |
| H-31 | Guardian independence is assumed, never represented | OBSERVED (gap) | T1 | per-vault |
| H-32 | The factory's generation-registration authority is unclassified | **CLOSED (D8)** | T1 | cohort (future) |

---

## H-01 — Irreversible admin pause via `renounceOwnership()`

**Status: CLOSED IN CURRENT MAIN by PR #180 · Tier T0 · Blast radius: system-wide**

> **This entry is kept, not deleted, and its history is the point.** The hazard was discovered by
> this architecture review, surfaced independently by the PR #177 lane, shipped as its own narrow
> remediation in **PR #180**, and its closure is re-verified firsthand here. A register that
> silently drops a closed T0 finding loses the only evidence that the process worked.

| Field | Content |
|---|---|
| **Hazard** | Every tenant's assets become permanently immovable and permanently unrecoverable, while the contract continues to accept deposits. |
| **Cause** | `pause()`/`unpause()` are `onlyOwner`. `renounceOwnership()` is inherited from OpenZeppelin `Ownable` as `public virtual onlyOwner`; `Ownable2Step` (OZ 5.6.1) overrides `pendingOwner`, `transferOwnership`, `_transferOwnership` and `acceptOwnership` but **not** `renounceOwnership`. Neither vault overrode it, so it was present and callable in both compiled ABIs. |
| **Direct authority** | (a) contract admin, alone. Two transactions, no delay, no quorum, no expiry. |
| **Authority closure** | `{ENTER_CONTAINMENT}` closed over `{permanent denial of MOVE_ASSETS, CHANGE_CREDENTIALS, APPROVE_RECOVERY for every tenant}`. |
| **Prevention — SHIPPED** | **PR #180, merged to `main` `15a44016`.** Both vaults now declare `function renounceOwnership() public pure override { revert OwnershipRenunciationDisabled(); }`. **Verified firsthand at `15a44016`**: `WalletWallVault.sol:1475` and `StablecoinVaultSimulator.sol:1215`. `pure` was chosen deliberately so the ABI's `stateMutability` is tamper-evident — the inherited implementation is `nonpayable`, so an ABI reporting `nonpayable` for this selector proves the override has been removed. |
| **Cost, MEASURED** | **+8 bytes** on each vault's runtime, exactly as the #177 lane forecast. `WalletWallVault` 23,231 → **23,239**; `StablecoinVaultSimulator` 22,867 → **22,875**. Re-measured independently here from a clean, non-instrumented compile. |
| **Containment** | n/a — the capability is withdrawn from the contract, not withheld from a caller. |
| **Detection** | Was `OwnershipTransferred(previousOwner, address(0))`. No longer reachable. |
| **Recovery** | Was **NONE** — the only entry in this register with no recovery path. |
| **Residual risk** | **Eliminated in current `main`.** Not merely mitigated: the selector reverts unconditionally for every caller. vNext removes the principal entirely, so the hazard has no host in the target architecture either. |
| **Proof tier** | T0. Closed by production code and its own 21-case suite in `test/OwnershipRenunciationDisabled.test.ts`, not by this model. |

> **What did NOT change, and is still live.** `WalletWallVault` accepts deposits while paused
> (hazard H-22) — recorded in #180 as evidence and deliberately left out of a security remediation
> that otherwise carried no behavioural change.
>
> **CORRECTED.** A previous revision of this note continued: *"§13.0 of the architecture document now
> shows this is not minor: under per-vault custody it is the mechanism by which an unprivileged
> stranger can veto another vault's migration."* **That linkage is WITHDRAWN** — architecture §13.0a
> re-derives it firsthand and shows the stranger's asset never traverses a gated path, so closing the
> deposit functions cannot prevent the veto. H-22 remains a real **current-product** defect and a real
> **parity** defect; it is **not** a migration prerequisite. See **H-28**.

---


## H-02 — Unrotatable tenant identity key

**Status: OBSERVED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Loss of the tenant address permanently removes guardian administration, recovery cancellation and queued-withdrawal settlement. Compromise of it hands an attacker those capabilities forever. |
| **Cause** | The tenant identity **is** the `vaults[]` mapping key, written once at `createVault` and never reassigned (`Guardian_Authority_Design.md` §2.1). Identity and authority are the same object, so authority cannot rotate without identity rotating, and identity cannot rotate at all. |
| **Direct authority** | (b) tenant `vaultOwner`. |
| **Authority closure** | `{CHANGE_GUARDIANS, CANCEL_RECOVERY, SETTLE_QUEUE, SET_TREASURY_THRESHOLD}`. Notably this does **not** include `MOVE_ASSETS` directly — withdrawal is signature-authorised by (c)/(d) — but it does include permanent denial of the remedy. |
| **Prevention** | vNext: identity is the vault's own **address**; authority becomes rotatable internal state. This is the root-cause elimination, not a mitigation. |
| **Containment** | Current operational mitigation only: (b) may be a contract, so a Safe can be the tenant. Nothing enforces this. |
| **Detection** | Not detectable on-chain — key loss is indistinguishable from inactivity. |
| **Recovery** | None for identity. Credential recovery still works; administration does not. |
| **Residual risk** | In vNext, whatever principal holds guardian administration remains a loss surface. The hazard is *reduced to a rotatable object*, not abolished. |
| **Proof tier** | T1. `identity-model separation` tests assert `immovableTenantKey === null` under `ACCOUNT_PER_VAULT`. |

This hazard is the **root cause** behind H-03, H-21, and the refutation of every guardian-hardening
candidate recorded in `Guardian_Authority_Design.md` §4.2 (F-1…F-5).

---

## H-03 — Credential-keyed veto over honest recovery

**Status: OBSERVED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | The principal whose compromise recovery exists to remedy can cancel that recovery indefinitely. |
| **Cause** | `cancelRecovery()` (`:580`) is keyed on `msg.sender == (b)` with no delay, no limit, and no pause gate. `setGuardians` (`:396`) additionally deletes any pending request unconditionally at `:416-419` — including a majority-approved one, which the H4-A guard in `initiateRecovery` otherwise protects. |
| **Direct authority** | (b) tenant `vaultOwner`. |
| **Authority closure** | `{CANCEL_RECOVERY}` closes over `{indefinite denial of APPROVE_RECOVERY}` — an unbounded veto, repeatable at zero cost. |
| **Prevention** | vNext: recovery cancellation is **guardian-quorum authority only**. The spending credential holds no veto, because a veto held by the compromised principal defeats the remedy. |
| **Containment** | H4-A (merged in #176) protects an approved request against *guardian* replacement, but not against (b). |
| **Detection** | `RecoveryCancelled` is emitted. |
| **Recovery** | Guardians may re-initiate, paying a fresh 7-day delay each time. The attacker's cancel is cheaper than the defenders' re-initiation, so the exchange is adverse. |
| **Residual risk** | vNext moves the veto to the guardian quorum, which is the same principal that can already take over (H-15). This does not create new authority. |
| **Proof tier** | T1. Asserted in both directions by the identity-model separation tests. |

---

## H-04 — Recovery installs credentials with no proof of possession

**Status: OBSERVED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | A recovery can install credentials that **nobody holds**, permanently bricking the vault. |
| **Cause** | `_authorizeRotation` demands incoming-credential PoP (`:768-774`, `InvalidNewEcdsaProof`/`InvalidNewPQProof`). Recovery writes the **same two storage slots** (`:545-546`) after only `_validateCredentials` (`:777-784`), which is `internal pure` and checks non-zero address / non-empty bytes only. Two paths, same slots, different authentication strength. |
| **Direct authority** | Guardian majority (e). |
| **Authority closure** | `{APPROVE_RECOVERY}` closes over `{permanent denial of MOVE_ASSETS}` when the installed credential is unheld — a *liveness* loss reachable without any malice, e.g. a broken client. |
| **Prevention** | vNext: the kernel requires proof of possession of every incoming credential on **both** write paths. The model refuses `possessionProven: false` unconditionally. |
| **Containment** | None today. |
| **Detection** | Not detectable at install time — an unheld key is indistinguishable from a held one without a signature. |
| **Recovery** | A further guardian recovery round, if guardians remain honest and available. In `Hybrid` mode both credentials must be recovered. |
| **Residual risk** | **UNRESOLVED for the PQ leg.** PR #178's split verdict stands: because the deployed verifier is a mock, a delegated PQ possession proof reduces to a length check and therefore proves nothing cryptographically. Mitigating PoP also *worsens liveness* — it adds a signature the recovering party must produce at initiation. |
| **Proof tier** | T1. |

---

## H-05 — Silent cryptographic downgrade by verifier substitution

**Status: OBSERVED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | The effective authorization strength of every vault is lowered without any vault-visible event indicating weakening. |
| **Cause** | Three composing facts. (i) The only downgrade guard is a **denylist of exactly one self-reported identifier**: `pqVerifier.algorithmId() == MOCK_ML_DSA_65_ALGORITHM_ID` (`:613`). (ii) `IPQCVerifier` itself documents that `algorithmId()` "is metadata only and carries no security guarantee by itself." (iii) The guard runs **only in `createVault`** — `_validateCredentials` is `internal pure` and therefore *structurally cannot* read `pqVerifier`, and `applyPQVerifierUpdate` never re-runs it. |
| **Direct authority** | (a) contract admin, after a 2-day delay inside a 14-day grace window. |
| **Authority closure** | In `PqOnly` mode `needEcdsa == false` and the PQ verifier is the **sole** authenticator (`Policy_Control_Authority_Design.md` §7.1). Therefore `{REPLACE_VERIFIER}` closes over `{CHANGE_CREDENTIALS, MOVE_ASSETS}` for every `PqOnly` vault. In `Hybrid`/`EcdsaOnly` it does not, because a classical signature is still required. |
| **Prevention** | vNext: strength is a **kernel-recorded** ordinal per scheme, never read from the verifier. Verifier *implementations* are replaceable within a scheme; *schemes* are governed separately and monotonically. Additionally, FIPS 204 §3.6.2 mandates length rejection — a pure integer comparison the kernel can perform **without trusting the verifier at all**. |
| **Containment** | The 2-day delay plus 14-day expiry bounds warning to a finite horizon. |
| **Detection** | `PQVerifierUpdateProposed` / `PQVerifierUpdated` are emitted. Detection requires an off-chain monitor with a strength model the chain does not have. |
| **Recovery** | Admin may swap back, which requires trusting the same admin. |
| **Residual risk** | Currently bounded only by the fact that `PqOnly` vaults cannot be *created* while the mock is wired. The safety of the deployment therefore rests on a configuration accident rather than a mechanism. |
| **Proof tier** | T1. Modelled as `M10` and `M11`. |

> `Security_Assumptions.md` §4 already concedes the retroactive path: "a banked swap can
> retroactively restore exactly the configuration that guard forbids for vaults that already exist."

---

## H-06 — Reverting or gas-burning verifier bricks all spending

**Status: OBSERVED · Tier T2 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | Every withdrawal, rotation, and queue operation fails for every tenant simultaneously. |
| **Cause** | `pqVerifier.verify(...)` is called **bare at four sites** (`:765`, `:773`, `:854`, `:1120`) with **no `try/catch` and no gas cap**. The only `try/catch` in the vault guards policy `revalidate` (`:1007`). |
| **Direct authority** | (a) contract admin (by substitution), or the verifier operator (by defect). |
| **Authority closure** | `{REPLACE_VERIFIER}` closes over `{denial of MOVE_ASSETS, CHANGE_CREDENTIALS}` system-wide. Denial only — never theft. |
| **Prevention** | vNext: no plane call may be unbounded or uncaught on a path the kernel must complete. A plane's failure fails **closed for that plane's contribution**, never fails the whole transaction where the kernel can proceed on its own floor. |
| **Containment** | Recovery is unaffected — the recovery path makes **zero external calls**, so a dead verifier cannot brick it. This is the design's strongest existing property. |
| **Detection** | Reverted transactions are observable. |
| **Recovery** | Admin substitutes a working verifier after the 2-day delay. If the admin has renounced (H-01), there is none. |
| **Residual risk** | Accepted for spending. **Explicitly not accepted for recovery**, and the current code already honours that. |
| **Proof tier** | T2. Modelled as `M17`. |

---

## H-07 — Policy engine disabled wholesale by a single principal

**Status: OBSERVED · Tier T2 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | All policy enforcement is removed for every tenant, with no tenant consent and no tenant-visible weakening event on the policy itself. |
| **Cause** | `address(0)` is an explicitly allowed policy-engine value meaning "no policy" (`_requireCodeBearingPolicyEngine`, `:1318-1320`). The admin may propose it, wait `POLICY_ENGINE_UPDATE_DELAY`, and apply. |
| **Direct authority** | (a) contract admin. |
| **Authority closure** | `{WEAKEN_POLICY}` system-wide. It does **not** close over `MOVE_ASSETS` — withdrawal still requires tenant signatures. |
| **Prevention** | vNext: policy is a plane that may only **subtract** authority. Disabling it returns to the kernel floor rather than to "no restriction", so "no policy" is not a weaker state than the kernel's own rules. |
| **Containment** | `policyEngineAtQueue` provides a sticky admission floor for already-queued withdrawals, honestly bounded at engine-**address** granularity. |
| **Detection** | `PolicyEngineUpdateProposed` / `PolicyEngineUpdated`. |
| **Recovery** | Re-enable, requiring the same admin. |
| **Residual risk** | Recorded as a known limit in `Policy_Control_Authority_Design.md` §7.2. A pending swap to `address(0)` is **not epoch-bound**: recovery invalidates tenant-side weakening proposals but does not invalidate this one. |
| **Proof tier** | T2. |

---

## H-08 — Policy-plane outage denies settlement

**Status: OBSERVED · Tier T2 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | An unavailable or Byzantine policy engine blocks withdrawal admission and settlement. |
| **Cause** | Fail-closed, **asymmetrically**. `check` (admission) is declared non-`view`, so it is a full CALL — state-mutating, reentrancy-capable, gas-unbounded — and is **not** wrapped in `try/catch` (`:863-871`, `:1123-1131`). `revalidate` is declared `view`, so it executes under STATICCALL and **is** wrapped (`:1006-1014`). |
| **Direct authority** | Policy plane operator; (a) by substitution. |
| **Authority closure** | `{CHANGE_POLICY}` closes over `{denial of MOVE_ASSETS}`, never over `MOVE_ASSETS` itself. |
| **Prevention** | vNext: a plane consulted on a settlement path must be `view` so the call type is STATICCALL fixed at the call site, and every such call must be caught. Admission and settlement must have the same failure taxonomy. |
| **Containment** | `cancelPendingWithdrawal` is ungated by pause **and** by policy, so reserved funds are never trapped by a dead engine. |
| **Detection** | `PolicyEngineUnavailable` is a distinct error from `PolicyViolation` — the taxonomy is already correct. |
| **Recovery** | Migration is the universal escape from a dead plane in vNext. |
| **Residual risk** | Accepted: fail-closed on spending is the correct trade. Fail-closed on **recovery** would not be, and is structurally excluded. |
| **Proof tier** | T2. |

---

## H-09 — Controller/kernel generation divergence

**Status: PROPOSED (hazard is prospective) · Tier T2 · Blast radius: cohort**

| Field | Content |
|---|---|
| **Hazard** | A controller believes generation `N` while the kernel believes `N-1`, so an authority decision is made against state that no longer exists. |
| **Cause** | Any design in which authoritative state is **duplicated** across a PUSH boundary. |
| **Direct authority** | Plane controller. |
| **Authority closure** | `{REPLACE_PLANE}` closes over `{acting on stale authority}` for every subject on that controller. |
| **Prevention** | Two mechanisms, in preference order. **(1) Do not duplicate.** The existing `PolicyControlBridge` holds **no cached epoch** — it reads `policyControlEpoch(owner)` live (`PolicyControlBridge.sol:733-734`), making divergence *structurally impossible* rather than merely tested. This is the preferred pattern. **(2) Where duplication is unavoidable**, every PUSH must be a compare-and-swap carrying the **expected previous** generation, and must strictly increase. |
| **Containment** | Bind the generation into **both** the signed intent and the stored proposal — either alone leaves a gap (`Policy_Control_Authority_Design.md` §5.4). |
| **Detection** | Divergence is detectable only where the consumer holds an independent copy to compare. |
| **Recovery** | Re-push at the correct expected-previous generation. |
| **Residual risk** | **Stated explicitly and not hidden:** a consumer that verifies generation **ordinality** does not thereby verify **content**. A controller that advances the generation correctly while pushing a wrong roster is not detected. PR #177 §4.8 concedes exactly this and places it inside the accepted controller-code TCB. vNext avoids the residual by not externalising guardian membership at all (see H-19). |
| **Proof tier** | T2. Modelled as `M5`. |

---

## H-10 — Migration destination substitution

**Status: PROPOSED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Assets migrate to a destination that is not the audited kernel the migration was authorised for. |
| **Cause** | A migration binding that omits, or fails to re-check, the destination's code identity. |
| **Direct authority** | Migration authority. |
| **Authority closure** | `{SELECT_DESTINATION_KERNEL}` closes over `{MOVE_ASSETS, CHANGE_CREDENTIALS, CHANGE_GUARDIANS}` — i.e. **everything**, because the destination defines what happens next. This is why destination selection must never be a capability held by the migration authority alone. |
| **Prevention** | The binding must carry all of: source, destination, **destination kernel code hash**, destination generation, asset set, credential commitment, guardian commitment, policy commitment, expected safe state, chain id, nonce, deadline. The code hash must be re-checked **at execution**, not only at preparation — a destination code-bearing at proposal time can change before the delay elapses (the lesson already encoded in `applyPQVerifierUpdate`). |
| **Containment** | Deadline plus nonce bound replay. |
| **Detection** | Preparation and execution both emit; the bound hash is public. |
| **Recovery** | None once executed. Migration is one-way. |
| **Residual risk** | A code hash proves *which code*, never that the code is correct. Destination auditing is out of band. |
| **Proof tier** | T1. Modelled as `M8` and `M9`. |

---

## H-11 — Migration authority becomes an unavoidable super-admin

**Status: PROPOSED · Tier T0 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | The escape hatch becomes the attack. A capability that can move all assets to a chosen address is indistinguishable from theft. |
| **Cause** | Designing migration as `migrateEverything(arbitraryAddress)`. |
| **Direct authority** | Migration authority. |
| **Authority closure** | Unbounded — see H-10. |
| **Prevention** | Migration authority is **strictly stronger** than ordinary spending authority and is deliberately decomposed so that no single principal holds it: the destination is bound by the *kernel* at preparation, and execution requires the same quorum that governs recovery. The model asserts that `MIGRATION_AUTHORITY` alone holds neither `SELECT_DESTINATION_KERNEL` nor `MOVE_ASSETS`. |
| **Containment** | Migration is available in degraded states precisely so it is the escape from plane death — which is only safe *because* the destination is bound. |
| **Detection** | Full binding is public at preparation time, giving a delay-bounded warning window. |
| **Recovery** | None post-execution. |
| **Residual risk** | **UNRESOLVED — owner decision required.** Whether migration execution requires guardian quorum, credential authority, or both, is a policy question this adjudication deliberately does not settle. |
| **Proof tier** | T0. This is a mission stop-condition: if migration cannot be specified without an unavoidable super-admin, vNext must stop. It can be, so it does not. |

---

## H-12 — Emergency principal acquires a permanent recovery veto

**Status: OBSERVED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | A containment capability, intended to be suspensive, becomes an indefinite denial of recovery. |
| **Cause** | `pause()` gates `initiateRecovery` and `executeRecovery` but not `supportRecovery`/`cancelRecovery` (`Guardian_Authority_Design.md` §2.4). `pause()` itself carries **no delay, no expiry and no quorum**. Composed with H-01 it becomes permanent. |
| **Direct authority** | (a) contract admin. |
| **Authority closure** | `{ENTER_CONTAINMENT}` closes over `{indefinite denial of APPROVE_RECOVERY}` system-wide. |
| **Prevention** | vNext: containment is **wall-clock bounded and self-expiring** — it lapses with no principal acting, so a disappeared or hostile emergency principal cannot hold it. Recovery actions remain available *throughout* containment; only spending is withdrawn. |
| **Containment** | Pause is suspensive in current main: quorum keeps accruing and the clock keeps running, so a matured request executes at the first post-unpause block. That property is destroyed by H-01. |
| **Detection** | `Paused` / `Unpaused` events. |
| **Recovery** | `unpause()`, unless ownership was renounced. |
| **Residual risk** | None in vNext by construction. **Live and unmitigated in current main.** |
| **Proof tier** | T1. Modelled as `M7`. |

> **Design note, and a genuinely counter-intuitive one.** An expiry clock that *suspends* while the
> system is paused looks protective and is not. Composed with an irreversible pause it converts a
> frozen request into a **permanently undeletable** one, removing the last exit. The expiry bound
> must therefore be wall-clock and must not suspend. PR #177 §7.1a C2 reaches the same conclusion
> independently and withdraws an earlier draft that proposed suspension.

---

## H-13 — Emergency transition increases effective authority

**Status: PROPOSED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Entering a "safer" state silently grants some principal a capability it did not previously hold. |
| **Cause** | Emergency states that *add* powers (e.g. an emergency unenrol, an emergency override, or an exit capability paired with an entry capability). |
| **Direct authority** | Emergency principal. |
| **Authority closure** | If containment grants `EXIT_CONTAINMENT`, the principal holds a reversible switch — strictly more authority than a one-way brake. |
| **Prevention** | **Authority monotonicity**: for every principal, the capability set after an emergency transition must be a **subset** of the set before. Asserted directly over all principals in the model. |
| **Containment** | Emergency primitives that *relax* authority are rejected by construction — "an emergency primitive that relaxes authority is not a circuit breaker; it is a backdoor" (`Policy_Control_Authority_Design.md` §6.3). |
| **Detection** | Capability-set comparison is mechanisable and is asserted in the suite. |
| **Recovery** | n/a — prevented rather than recovered. |
| **Residual risk** | None identified. |
| **Proof tier** | T1. Modelled as `M6`. |

---

## H-14 — Treasury-quorum stranding

**Status: OBSERVED · Tier T2 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Large withdrawals cannot settle because guardians will not or cannot approve. |
| **Cause** | `finalizeWithdrawal` gate 1 requires `treasuryApprovalCount >= treasuryQuorumThreshold` (`:941-946`). |
| **Direct authority** | Guardians (e), by refusal. |
| **Authority closure** | `{APPROVE_RECOVERY}` does **not** close over permanent asset denial here. **This is a rate limit, not a veto**, for two independent reasons: (i) `setTreasuryQuorumThreshold(0)` disarms it and is (b)-keyed, ungated by pause; (ii) `withdraw` reverts only when `amount > largeTxThreshold` (`:1107`), so sub-threshold withdrawals always take the immediate path. |
| **Prevention** | Preserve both escapes explicitly in vNext. |
| **Containment** | `cancelPendingWithdrawal` returns reserved funds to the ledger balance. |
| **Detection** | Approval counts are public. |
| **Recovery** | Disarm the threshold, or withdraw below it repeatedly. |
| **Residual risk** | The escape depends on (b), so it **fails exactly when (b) is lost** (H-02). Additionally `largeTxThreshold` is set by (a) **globally**, so the admin's parameter choice sets the escape rate of every tenant who has lost (b) (`Guardian_Authority_Design.md` §2.5). |
| **Proof tier** | T2. |

---

## H-15 — Guardian-majority takeover

**Status: OBSERVED · RESIDUAL, ACCEPTED BY OWNER DECISION D1 · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | A guardian majority recovers the vault to credentials it controls and takes the assets. |
| **Cause** | Intrinsic to social recovery. `executeRecovery` needs zero credentials and is permissionless to call once the objective gates pass. |
| **Direct authority** | Guardian majority (e). |
| **Authority closure** | `{APPROVE_RECOVERY}` closes over `{CHANGE_CREDENTIALS, MOVE_ASSETS}`. **The model asserts this closure is reported rather than hidden** — an authority graph that omits a real path is worse than none. |
| **Prevention** | Not prevented. This is the accepted price of social recovery (`Guardian_Authority_Design.md` §3.13). |
| **Containment** | 7-day delay; guardian-set choice is the tenant's. |
| **Detection** | `RecoveryInitiated` gives at least `RECOVERY_DELAY` of warning. |
| **Recovery** | Cancellation within the delay window, by whichever principal holds that authority. |
| **Residual risk** | **ACCEPTED AND DECLARED — now by an explicit owner decision rather than by inheritance.** Architecture §22 **D1** adopts a quorum of `>= k` valid current-generation guardians as an **accepted recovery trust root**, so a malicious quorum is an explicitly accepted catastrophic compromise condition and **`guardian compromise cut = k`**. It is inside the recovery fault envelope, not outside it. **Two consequences.** (1) WalletWall may never claim it cryptographically protects against a malicious quorum while letting that same quorum recover credentials — those are one capability described twice. (2) The bounded challenge (`I-VETO-BOUND`, D1) buys **time, visibility and operational cost**; it does **not** raise the cut, because the challenger is a principal the graph already counts and no independent principal is made mandatory (mutant **M57**). |
| **Proof tier** | T1. Asserted positively — the closure test *requires* `MOVE_ASSETS` to appear. |

---

## H-16 — Reference-model (simulator) parity drift

**Status: OBSERVED · Tier T2 · Blast radius: cohort**

| Field | Content |
|---|---|
| **Hazard** | A security-relevant change lands on one implementation and not its sibling, so the deployed pair disagree about authority. |
| **Cause** | `StablecoinVaultSimulator` is a **de-facto second implementation of the same semantics** — comment-stripped, the two contracts differ by only 22 inserted and 27 deleted code lines, with identical typehash, structs, constants and guardian/recovery surface. Any property not covered by a parity assertion can diverge one-sidedly and still pass CI. |
| **Direct authority** | Any contributor. |
| **Authority closure** | n/a — this is an assurance-process hazard, not a principal capability. |
| **Prevention** | Extend parity coverage beyond the guardian/recovery/treasury surface, and prefer a digest over *named* properties asserted equal across both implementations. Modelled as `parityDigest()` vs `siblingParityDigest()`. |
| **Containment** | Partial, and **better than an earlier draft of this register stated** — see the correction note below. |
| **Detection** | **PARTIAL, not absent.** `test/GuardianRecoverySimulatorParity.test.ts` (added by #176, present at `aaba4d2`) runs the same scenario against **both** contracts and asserts the same outcome across five cases: under-supported matured request remains replaceable; quorum-approved matured request is protected from replacement and remains executable; rotation does not cancel a pending recovery; guardian-set replacement invalidates a pending recovery; `setGuardians` rejects a shrink that would strand an armed treasury threshold. |
| **Recovery** | Re-sync by hand. |
| **Residual risk** | Real but **narrower than first written**. The existing test is **behavioural parity, not source-text equality**, and its scope is guardian / recovery / treasury-quorum only. Divergence in withdrawal, policy, verifier-governance or large-tx surfaces is **not** covered, and a digest over *named* properties still cannot detect drift in properties nobody thought to name. |

> **CORRECTION (recorded, not silently edited).** An earlier revision of this register asserted
> "**nothing in the repository enforces this parity**… Detection: currently **none**." **That was
> wrong for current `main`.** It was inherited from `Guardian_Authority_Design.md` §2.6, which was
> accurate when written but was superseded by #176 — the very commit this lane is based on. Verified
> firsthand: the file exists (7,704 bytes) and its own header states it closed exactly this gap.
> The hazard survives in reduced form because the coverage is partial, not because it is absent.
| **Proof tier** | T2. Modelled as `M16`. |

---

## H-17 — Operator disappearance strands recovery

**Status: PROPOSED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | WalletWall the company, its frontend, backend and hosted APIs cease to exist, and users cannot recover or migrate. |
| **Cause** | Any dependency of an authorization path on a hosted service — payload construction, an attestation endpoint, an indexer, or a key registry. |
| **Direct authority** | WalletWall infrastructure. |
| **Authority closure** | `{operate hosted service}` must **not** close over `{APPROVE_RECOVERY}` or `{MOVE_ASSETS}`. If it does, the operator holds a silent veto. |
| **Prevention** | The kernel must consult **no external service** on any authorization path, and the artifacts required to exercise every path independently must be published and reproducible. See `docs/Vault_vNext_Architecture.md` §16 for the enumerated artifact set. |
| **Containment** | The current recovery path already makes zero external calls, so recovery is already service-independent. The *payload construction* path is not yet proven independent. |
| **Detection** | Not detectable on-chain. |
| **Recovery** | Only via the published independent operating path. |
| **Residual risk** | **UNRESOLVED.** The attestation verifier path currently depends on a trusted off-chain attestor. An attestor that disappears cannot be replaced without admin action, and `AttestationPQCVerifier.updateAttestor` is itself immediate rather than timelocked (H-24). |
| **Proof tier** | T1. Modelled as `M15`. |

---

## H-18 — Assurance plane acquires actuation authority

**Status: PROPOSED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | The observatory becomes an actor, and a compromised monitoring system becomes a compromised custody system. |
| **Cause** | Convenience wiring — allowing a detector to "just pause" or "just freeze". |
| **Direct authority** | Assurance plane. |
| **Authority closure** | Must be **empty**. The model asserts `authorityClosure("ASSURANCE")` is exactly the empty set. |
| **Prevention** | `OBSERVATION ≠ AUTHORITY`, enforced structurally. Where automated response is wanted, it is a **separate principal** — a constrained actuator, independently authorised, able to effect only bounded, self-expiring, authority-reducing transitions — and its own closure is computed like any other principal's. |
| **Containment** | The actuator inherits H-13's monotonicity requirement and H-12's self-expiry requirement. |
| **Detection** | Capability-set assertion is mechanisable. |
| **Recovery** | n/a — prevented. |
| **Residual risk** | An actuator that can only *contain* still holds a denial capability. That is bounded by self-expiry, not by trust. |
| **Proof tier** | T1. Modelled as `M12`. |

---

## H-19 — Guardian-plane controller indirect takeover

**Status: PROPOSED · Tier T1 · Blast radius: cohort**

| Field | Content |
|---|---|
| **Hazard** | An external guardian controller rewrites a roster, installs itself a quorum, and thereby reaches recovery and then assets — without ever holding a spending credential. |
| **Cause** | Externalising **guardian membership** to a plane. The consumer verifies generation ordinality, not roster content, so a controller that advances the generation correctly while pushing a wrong roster is undetected (PR #177 §4.8, conceded). |
| **Direct authority** | Guardian-plane controller. |
| **Authority closure** | `{write roster}` closes over `{CHANGE_GUARDIANS, APPROVE_RECOVERY, CHANGE_CREDENTIALS, MOVE_ASSETS}`. **This path must appear in the authority graph.** Omitting it is itself the defect (mutant `M14`). |
| **Prevention** | vNext: guardian membership is **KERNEL-REQUIRED** and is not externalised. This is a direct consequence of the kernel-membership rule: replacing a failed guardian plane would itself require guardian authority, which is a circularity. |
| **Containment** | If a controller is nonetheless adopted, it is inside the TCB and must be declared as such. |
| **Detection** | Roster writes are observable; roster *correctness* is not machine-checkable by the consumer. |
| **Recovery** | Replacement of the controller, which requires the authority the controller holds. |
| **Residual risk** | Eliminated by not externalising. **This is where the vNext adjudication departs from PR #177's C5 external controller** — not because that design is wrong for the current architecture, but because the identity change removes the constraint that forced it. |
| **Proof tier** | T1. Modelled as `M14`, with inverted polarity: the clean model must **report** the path. |

---

## H-20 — Byte budget exhaustion forecloses security fixes

**Status: OBSERVED · Tier T0 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | The threat model becomes limited by the **deployed-runtime** size limit rather than by engineering judgement: a known, agreed security fix cannot be deployed because it does not fit. **The binding quantity is `NETWORK_RUNTIME_LIMIT(chain, fork)`, and WalletWall's own `WALLETWALL_PORTABILITY_BUDGET` sits at its minimum across declared targets** (architecture §19.0) — a per-chain, per-fork parameter, not an eternal constant. |
| **Cause** | Re-measured from a clean non-instrumented compile at `15a44016` (solc 0.8.24, cancun, optimizer on, runs 200, no viaIR): `WalletWallVault` runtime **23,239 / 24,576 bytes (94.6%)**, headroom **1,337**. `StablecoinVaultSimulator` 22,875, headroom 1,701. Superseded figures at `aaba4d2`: 23,231 / headroom 1,345 and 22,867 / headroom 1,709 — PR #180 added the +8 bytes. **CORRECTED:** this cell previously added *"creation bytecode 24,582, which now exceeds the 24,576 RUNTIME ceiling on its own"*. **Struck** — creation bytecode is initcode, governed by EIP-3860 at **49,152**, against which 24,582 sits at 50.0%. The gate's own output labels it *"not gated; informational only"*. See architecture §19.0. |
| **Direct authority** | n/a — structural. |
| **Authority closure** | n/a. |
| **Prevention** | vNext: the kernel carries **one** vault's semantics, not `N` tenants' — no owner-keyed mapping indirection, no per-tenant loops. Capability planes hold what the kernel need not. |
| **Containment** | The size gate (`scripts/validate-bytecode-size.ts`) compares `deployedBytecode` only — **correctly**, and `test/BytecodeSizeBudget.test.ts` asserts that creation bytecode can never leak into the pass/fail decision. It must be run from a **clean non-instrumented compile**; coverage instrumentation inflates measured sizes. |
| **Detection** | `npm run validate:bytecode-size`. |
| **Recovery** | Externalisation or redesign. |
| **Residual risk** | **Two agreed security fixes are competing for the same 1,337 bytes and at least one provably cannot fit**: guardian hardening prices at 675–1,650 B (an unresolved 2.4× disagreement), and recovery PoP needs 464 B against 339 B available. Separately, ~29.8% of the vault's runtime is utility-Yul and unmapped buckets not emitted as `generatedSources`, so **every forward byte estimate is a lower bound**. **Architecture C does NOT relieve this hazard** (dissent D5): architecture §19.1 measured the monolith mechanically transformed into a clone target at **23,249** — inside the portability budget, and **1,349 bytes over** the target kernel ceiling. Clone-targeting moves the *deployment* budget, never the *kernel* budget. |
| **Proof tier** | T0. Measured, not modelled. |

---

## H-21 — Vault born unguarded

**Status: OBSERVED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Between creation and the first `setGuardians`, recovery is unreachable. Assets deposited in that window have no remedy for credential loss. |
| **Cause** | `createVault` never writes `vaultGuardians`; `setGuardians` is the sole write site. Every vault therefore starts with an empty guardian set, and `initiateRecovery` reverts `InvalidGuardianSet`. |
| **Direct authority** | (b), by omission. |
| **Authority closure** | n/a — a gap, not a capability. |
| **Prevention** | vNext: guardians are bound **at construction**, atomically with vault creation, so the unguarded window does not exist. This also dissolves the bootstrap problem that forced PR #177 to introduce an external controller for the `UNGUARDED → GUARDED` transition. |
| **Containment** | Operational only: instruct tenants to set guardians immediately. |
| **Detection** | An empty guardian set is publicly readable. |
| **Recovery** | Set guardians — which requires (b). |
| **Residual risk** | Constructor-bound guardians must still be *chosen correctly*; the architecture removes the window, not the choice. |
| **Proof tier** | T1. Asserted directly by the identity-model separation tests. |

---

## H-22 — Deposits accepted while withdrawal is frozen

**Status: OBSERVED · Tier T2 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | A paused deployment continues to accept funds it cannot pay out, deepening the loss of any concurrent freeze. |
| **Cause** | `deposit()` and `depositFor()` carry **no** `whenNotPaused` modifier, while `withdraw`, `queueWithdrawal`, `finalizeWithdrawal` and `executeRecovery` all do. **OBSERVED context that bounds the fix:** `WalletWallVault` is **ETH-only** and declares **no `receive()` and no `fallback()`**, so the explicit deposit path is the only ingress that **credits a balance** — which is why closing it is *effective here* and *insufficient in general*. Forced ETH already reaches the live vault via `selfdestruct`, and `test/WalletWallVault.test.ts` already asserts it does not corrupt accounting. The sibling `StablecoinVaultSimulator` **is** `whenNotPaused` on deposit and is still fully exposed to a direct `IERC20.transfer`, as its own NatSpec states. |
| **Direct authority** | Any depositor, unwittingly. |
| **Authority closure** | n/a. |
| **Prevention** | vNext: the safe-state lattice governs **accounted inflow and outflow together** — a state that cannot pay out must not **book** an inflow as though it could. **Scope corrected (architecture §6):** `I-NO-INGRESS-WITHOUT-EGRESS` restrains the paths the kernel credits, and can restrain nothing else. It earns its place on **accounting coherence**, not on migration safety. |
| **Containment** | None today. |
| **Detection** | `Deposited` events during a paused period are trivially detectable off-chain. |
| **Recovery** | Unpause — subject to H-01. |
| **Residual risk** | **RE-ADJUDICATED. The previous revision's elevation to migration prerequisite is WITHDRAWN; the underlying defect is unchanged and still live.** Architecture §13.0a separates four questions that were being answered as one: **(1) current-product defect — YES**; **(2) parity defect — YES**; **(3) containment-policy choice — YES**; **(4) vNext architecture prerequisite — NO.** Question 4 fails because gating `deposit()`/`depositFor()` cannot refuse a direct ERC-20 transfer, forced ETH, an airdrop, a rebase, or an asset arriving after the manifest is bound — none of which calls a WalletWall function. The H-28 attacker uses `transfer`, not `depositFor`, so **a gate the attack does not pass through cannot be a prerequisite for defeating it**. Severity is therefore back where #180 put it: a real defect, at product-hygiene priority, **not** gating any vNext step. **Still live at `15a44016`**: verified firsthand that `deposit()` and `depositFor()` carry no state gate while `withdraw`, `queueWithdrawal`, `finalizeWithdrawal` and `executeRecovery` all carry `whenNotPaused`. |
| **Proof tier** | T2. |

---

## H-23 — Generic execution authority admitted at a standards boundary

**Status: PROPOSED · Tier T0 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | Adopting an account-abstraction or modularity standard imports a generic `execute(target, data)` capability, and one grant becomes total account takeover. |
| **Cause** | Cargo-culting a standard's *expected workflow* as if it were a *requirement*. |
| **Direct authority** | Whichever principal the standard designates — EntryPoint, an executor module, a fallback handler. |
| **Authority closure** | Unbounded by definition. Safe's own documentation states it plainly: modules are "extensions with unlimited access to a Safe… A malicious module can completely take over a Safe." |
| **Prevention** | Interoperability at a **boundary** does not imply generic module authority in the **kernel**, and this is settled by spec text rather than opinion. ERC-4337 requires only `IAccount`; `IAccountExecute` is `MAY`, and the spec says merely that an `execute` function is "an expected workflow." ERC-1271 (Final) is a universally adopted interoperability boundary consisting of **one `view` function** that "MUST NOT modify state." A vault may therefore expose exact typed capabilities and remain interoperable. |
| **Containment** | If any generic execution is ever admitted, the architecture document must record the exact principal, its full authority closure, why typed capabilities were insufficient, the recovery implications, and the blast radius. |
| **Detection** | Structural — the model asserts `genericExecutionAvailable() === false`; the current contracts contain no `delegatecall`, `execute(`, `installModule`, or fallback dispatch at all. |
| **Recovery** | n/a — prevented. |
| **Residual risk** | Adopting ERC-4337 **unavoidably** makes the EntryPoint an unconditionally-trusted caller of every EntryPoint-gated function, with no signature check at that boundary; the spec works "precisely by concentrating security risk in the EntryPoint contract." That is a real, non-optional cost and is recorded as **UNRESOLVED** pending an owner decision on whether 4337 is adopted at all. Separately, ERC-7562 rule **[OP-011] bans `TIMESTAMP` and `NUMBER` during validation**, which conflicts directly with every time-gated authority this vault has (7-day recovery delay, 2-day timelock, 14-day grace). |
| **Proof tier** | T0. Modelled as `M1`. |

---

## H-24 — Attestor rotation outside the verifier timelock

**Status: OBSERVED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | The effective PQ authority changes instantly, bypassing the governance delay that the verifier swap is subject to. |
| **Cause** | `AttestationPQCVerifier.updateAttestor` is **immediate** and is not covered by the vault's two-day verifier timelock (`THREAT_MODEL.md`, Known Gaps). |
| **Direct authority** | Verifier owner. |
| **Authority closure** | Where the attested scheme is the sole authenticator, `{rotate attestor}` closes over `{CHANGE_CREDENTIALS, MOVE_ASSETS}` with **zero delay** — strictly faster than the H-05 path. |
| **Prevention** | `ImmutableAttestationPQCVerifier` makes the attestor immutable, converting rotation into replacement, which is then subject to the verifier timelock. |
| **Containment** | The vault-level 2-day delay applies to verifier *replacement* but not to state changes *inside* an already-active verifier. |
| **Detection** | Emitted by the verifier, not by the vault. |
| **Recovery** | Replace the verifier. |
| **Residual risk** | A general and reusable lesson: **a timelock on replacing a component does not bound state changes inside that component.** Any plane admitted to the design must have its *internal* governance examined, not only its replacement path. |
| **Proof tier** | T1. |

---

## H-25 — Pooled custody carries no solvency invariant

**Status: OBSERVED · Tier T0 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | The sum of accounted tenant balances silently diverges from the ETH actually held, and the first tenant to notice is the one whose withdrawal reverts. Under pooled custody an accounting error is a **system-wide solvency event by construction**, not a per-tenant one. |
| **Cause** | All tenants' ETH sits in one `address(this).balance`, accounted per tenant in `vaults[o].balance`. **Verified firsthand by grep at `aaba4d2`: `address(this).balance` appears NOWHERE in `contracts/`** — the contract never reads its own balance — and there is no `solvency`, `totalDeposits`, or `totalBalance` symbol anywhere either. **No on-chain solvency check exists at any site.** |
| **Direct authority** | None — this is a structural property, not a capability. |
| **Authority closure** | n/a. Any principal that can cause an accounting error inherits system-wide reach. |
| **Prevention** | vNext: a per-vault account **owns its assets directly**. `address(this).balance` *is* the balance; there is no second number to disagree with it, so the entire divergence class is deleted rather than checked for. This also makes ERC-20 and NFT custody arrive for free, since a token transfer to the vault address is simply ownership. |
| **Containment** | Force-sent ETH is not credited (there is no `receive()`/`fallback()`, so bare sends revert), which removes one direction of drift. The other direction is unguarded. |
| **Detection** | Only off-chain, by summing events. Nothing on-chain compares the two figures. |
| **Recovery** | None once assets are over-committed: the shortfall is discovered by a failed transfer. |
| **Residual risk** | Under vNext this hazard is eliminated by construction rather than mitigated. That is the single strongest *structural* argument for per-vault custody, and it is independent of the identity argument. |
| **Proof tier** | T0. Modelled by `I-CUSTODY-CONSERVATION`. |

---

## H-26 — Cross-tenant replay separation rests on a signed field, not the domain

**Status: OBSERVED · Tier T1 · Blast radius: system-wide**

| Field | Content |
|---|---|
| **Hazard** | An authorization intended for one tenant is accepted for another. |
| **Cause** | In a shared contract, `_hashTypedDataV4` binds `address(this)` — which is the **same value for every tenant**. Tenant separation therefore comes from the `vaultOwner` field *inside* the signed struct plus the vault's own lookup, not from the EIP-712 domain. The `IPolicyEngine` documentation names this distinction precisely: `consumer` and `asset` are trusted **BY PROVENANCE**, while `owner` is trusted **BY AUTHENTICATION** — "request-body data whose safety rests entirely on the EIP-712 signature check the vault performs before calling." |
| **Direct authority** | Any relayer (submission is permissionless). |
| **Authority closure** | Empty **today**: the check is correctly implemented, so no principal reaches another tenant's assets. The hazard is that the guarantee is only as strong as that one check, and `WalletWallVault.sol:1035-1040` says so in its own words — "any future caller of this helper MUST be downstream of the same verification." |
| **Prevention** | vNext: each vault is its own contract, so `address(this)` differs per vault and the **domain separator itself** separates tenants. A signature for vault X is structurally invalid at vault Y. Separation moves from authentication to provenance — from a check that must be remembered to a property that cannot be forgotten. |
| **Containment** | n/a. |
| **Detection** | Only by code review of every new caller. |
| **Recovery** | n/a. |
| **Residual risk** | **No defect exists today.** This entry records a *structural* difference in how the property is obtained, because a guarantee that depends on future maintainers preserving an ordering is weaker than one the EVM enforces. Note the cost side honestly: OpenZeppelin's cached-domain-separator fast path (`EIP712.sol:83`, guarded by `address(this) == _cachedThis`, an `immutable`) is **permanently unreachable for every EIP-1167 clone**, so per-vault domain separation is paid for with a `keccak256` rebuild on every call. |
| **Proof tier** | T1. |

---

## H-27 — Guardian-set commitment intact, preimage unrecoverable

**Status: PROPOSED · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | The kernel holds a perfectly valid guardian commitment whose **preimage nobody has**. No roster can be presented that hashes to it, so recovery is unreachable — with no on-chain symptom whatsoever. |
| **Cause** | **Introduced by the G-B minimisation itself** (architecture §4.2b). Storing a commitment instead of the roster moves the member addresses outside kernel state; if the roster is not retained off-chain, the commitment becomes a lock with no key. |
| **Direct authority** | None — this is an availability property, not a capability. |
| **Authority closure** | n/a. |
| **Prevention** | `I-CONSTITUENCY-RECONSTRUCTIBLE`: every write of the commitment **emits the full preimage** — threshold and all ordered `(address, authMode)` entries — in the same transaction, so the roster is reconstructible from chain history alone. |
| **Containment** | Publishing the roster in the company-disappearance artifact set (§15) is a second, independent copy. |
| **Detection** | Not detectable on-chain: an unrecoverable commitment is indistinguishable from an unused one. |
| **Recovery** | None once the preimage is lost. This is why the mitigation is a **write-time** requirement rather than an operational recommendation. |
| **Residual risk** | **Real, and it is the one axis on which G-A beats G-B.** Reconstruction depends on **log availability**, so a user holding only `eth_getCode` and no archive access cannot rebuild the roster. G-A has no such dependency. The smaller TCB is paid for here, and the charge is recorded rather than absorbed. |
| **Proof tier** | T1. `I-GUARDIAN-CONSTITUENCY-BINDING` is discriminated (M28); `I-CONSTITUENCY-RECONSTRUCTIBLE` is **OBSERVATORY** and carries no assurance from this PR (§16.1). |

---

## H-28 — A third party vetoes migration by planting a hostile asset

**Status: OBSERVED (mechanism) · Tier T0 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | An **unprivileged stranger**, holding no authority over the vault at all, permanently prevents it from escaping a dead or hostile kernel generation. |
| **Cause** | Three facts compose. (i) Under per-vault custody a vault **is** an address, so anyone may send it an ERC-20 with no function call. (ii) **no ingress gate can help**, because the attacker calls no WalletWall function at all — `transfer`, `selfdestruct`, an airdrop and a rebase each reach the vault without one, so H-22's open deposit path is **incidental to this hazard rather than causal** (§13.0a). (iii) The previous migration design bound a closed **asset set** and aborted the whole migration if any transfer failed. An attacker sends one blacklisting or reverting token **between binding and execution** and the escape is welded shut. |
| **Direct authority** | **None.** That is precisely what makes it severe. |
| **Authority closure** | `{send a token}` closes over `{permanent denial of MIGRATION}` under an asset-set-binding design. |
| **Prevention** | **ONE change, and it is sufficient on its own.** Architecture §13: **no bound asset set and no bound amounts** — a per-entry manifest with independent egress, so a failing entry marks only itself. **The previously co-required second change is WITHDRAWN (§13.0a):** `I-NO-INGRESS-WITHOUT-EGRESS` / closing H-22 does not prevent this hazard, because the hostile asset arrives by `transfer`, `selfdestruct`, airdrop or rebase and traverses no gated path. Strengthened instead: `I-MIGRATION-NONTRAP` clause **(a)** — an unsolicited or unmanifested asset may never veto the movement of an independently recoverable manifested asset (mutant **M52**) — and clause **(c)**, which forbids conditioning retirement on a zero balance across every token, a predicate that is not enumerable on ERC-20 (mutant **M53**). |
| **Containment** | `I-EGRESS-RETRY-PERPETUAL`: a failed entry may always be retried, so even a temporary refusal is not terminal. |
| **Detection** | The incoming transfer is public, but detection does not help if the design is already committed to atomicity. |
| **Recovery** | Under the replacement design the remaining assets leave normally; only the hostile token stays. |
| **Residual risk** | A token that blacklists the **SOURCE** is unreachable by any destination and by any protocol change. That is a property of the token, recorded in architecture §13.4 and §2.2 as an accepted unrecoverable condition rather than absorbed silently here. |
| **Proof tier** | T0. Modelled as `M39`, `M40`, `M41`, `M42`, and — carrying the load the withdrawn ingress gate used to appear to carry — `M52` and `M53`. `I-NO-INGRESS-WITHOUT-EGRESS` keeps `M26` on its own, narrower, accounting-coherence footing. |

---

## H-29 — An implementation's runtime code hash is address-dependent

**Status: MEASURED · Tier T1 · Blast radius: cohort**

| Field | Content |
|---|---|
| **Hazard** | An offline observer cannot verify "this vault runs the audited kernel" by comparing against a **published constant**, because no such constant exists **for a build whose immutables are address-derived**. A verifier who believes one does will either accept a wrong implementation or reject a correct one. **NARROWED (architecture §15.1a):** what may be unavailable is *one universal source-level runtime hash valid at every address*. An **authoritative runtime hash for a PARTICULAR deployed implementation** always exists — `extcodehash(impl)` is a fact about that account. The check is address-parameterised, not absent. |
| **Cause** | **MEASURED this session.** Two deployments of **byte-identical source** produced runtime code differing in **51 of 23,239 bytes**. Every differing byte lies inside a declared immutable slot; the artifact declares **seven** 32-byte immutable slots, and the one at offset **18,627** holds the contract's **own address**. Cause: inherited OpenZeppelin `EIP712`, whose `_cachedThis` and `_cachedDomainSeparator` are `immutable` and therefore baked into runtime bytecode. |
| **Direct authority** | None — structural. |
| **Authority closure** | n/a, but it **weakens every claim built on code identity**, including the migration destination check. |
| **Prevention** | `I-PURE-CONSTRUCTOR`: the vNext kernel must feed **no chain state into any `immutable`**. Two independent reasons converge on that one change — the EIP-712 cache can never hit for a clone anyway (dissent D2), and the cached immutables destroy hash stability. **MEASURED ACHIEVABLE (architecture §19.1):** the clone-target spike removed the address-caching `EIP712` and the artifact's declared immutable slots went **7 → 0**, two deployments of identical source became **byte-identical** (51 differing bytes → **0**), and the artifact's `deployedBytecode` hash came to **equal** the on-chain `extcodehash` (previously 136 differing bytes). Demonstrated on a transformed monolith; **still unproven for the vNext kernel**, which has not been written. |
| **Containment** | Until then, the five-step masking procedure in architecture §15.1: mask the ranges named by the artifact's `immutableReferences`, compare to the artifact's `deployedBytecode` (**verified**: all seven slots are zero placeholders there), then re-derive the address-dependent words independently. Masking **without** the re-derivation step discards real information. |
| **Detection** | Trivially detectable once looked for, and invisible until then. |
| **Recovery** | n/a — a verification-procedure defect, not a state. |
| **Residual risk** | The masking procedure is **OBSERVATORY** and carries no assurance from this PR. A verifier that skips step 4 accepts any implementation whose non-immutable bytes match. |
| **Proof tier** | T1. Measured, not modelled. The model discriminates the **chain shape** (`M46`, `M47`, `M49`), never the bytes. |

---


## H-30 — A bounded emergency authority holds an indefinite rolling freeze

**Status: PROPOSED · Tier T0 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | A capability the design calls "bounded" produces an **unbounded** denial: the vault is frozen forever, one nominally-expiring episode at a time. |
| **Cause** | **A gap in the previous revision of the architecture, not in the code.** §6 specified that containment is wall-clock bounded and self-expiring, and said **nothing** about what happens when the emergency principal triggers it **again**. A hostile or captured principal simply re-triggers on expiry. **Per-episode bounds do not compose into a bound on the authority.** |
| **Direct authority** | Emergency principal, alone. |
| **Authority closure** | `{ENTER_CONTAINMENT}` closes over `{indefinite denial of spending and of every authority mutation}` — recovery excepted, because §6 keeps it live throughout, which is what stops this becoming loss rather than denial. |
| **Prevention** | Two rules, each with its own discriminator. `I-CONTAINMENT-NO-EXTENSION`: re-entry while contained is a **no-op**, so the expiry cannot be pushed (M25). `I-CONTAINMENT-BUDGET`: at most `B` contained time per rolling window `W` with **`B < W`**, the window origin advancing **only** by elapsed wall clock (M24). `B < W` is the whole content — it guarantees an infinite sequence of uncontained intervals. |
| **Containment** | Recovery and migration egress stay available *during* containment, so even a maximal freeze never reaches loss. |
| **Detection** | Entry and expiry are both observable. |
| **Recovery** | Wall-clock expiry, requiring **no principal to act** — the property `I-VETO-BOUND` generalises to every veto in the design. |
| **Residual risk** | The vault is still deniable for up to `B` in every window. That is an accepted duty-cycle cost of having an emergency brake at all. **OPEN:** the numeric values of `B` and `W` (owner decision D5). |
| **Proof tier** | T0. Modelled as `M24` and `M25`, with `rollingFreezeReachable()` as the discriminating predicate. |

---

## H-31 — Guardian independence is assumed, never represented

**Status: OBSERVED (gap) · Tier T1 · Blast radius: per-vault**

| Field | Content |
|---|---|
| **Hazard** | A `k`-of-`n` guardian set whose members share one operator, one custodian, one wallet vendor, or one household is **one** failure root wearing `n` addresses. The authority graph reports a minimum cut of `k`; the real cut is 1. |
| **Cause** | `k` counts **addresses**. Address distinctness is enforced by the chain; **independence is an assumption about the world** and nothing represents it. Architecture §24.1 shows the guardian path already **dominates** every credential control, so an over-stated `k` over-states the security of the whole system. |
| **Direct authority** | Whoever controls the correlated seats. |
| **Authority closure** | `{correlated guardian majority}` closes over `{CHANGE_CREDENTIALS, MOVE_ASSETS}` — the H-15 closure, reached at a fraction of the advertised cost. |
| **Prevention** | **Not prevented, and this is a genuine asymmetry worth naming.** The `SecurityProfile` introduces `rootTag` so that correlated *credential* factors cannot be counted twice (§12, mutant M35). **Nothing analogous exists for guardians.** The same defect is closed on one axis and open on the other. |
| **Containment** | Operational only: guardian selection is the user's, and the vault can *disclose* seat metadata (§10) without being able to verify it. |
| **Detection** | Not detectable on-chain. Correlation is off-chain by definition. |
| **Recovery** | Replace the guardian set — which requires a quorum of the set being replaced. |
| **Residual risk** | **UNRESOLVED and newly recorded.** Extending `rootTag` to guardian seats is representable but would place an unverifiable off-chain assumption inside kernel state, which is its own hazard. This register states the gap rather than closing it badly. |
| **Proof tier** | T1 for the credential axis (modelled); **no proof** for the guardian axis. |

---

## H-32 — The factory's generation-registration authority is unclassified

**Status: CLOSED BY DESIGN DECISION (D8) · Tier T1 · Blast radius: cohort (future vaults only)**

| Field | Content |
|---|---|
| **Hazard** | Under architecture C, whoever decides which implementation the factory points at decides what every **future** vault immutably **is**. That is a capability-**ADDING** power inside a doctrine that forbids them, and the previous revision's authority table did not contain it. |
| **Cause** | §8 recorded "Kernel admin — **NONE**, the principal does not exist". True *per vault*, and it made a real principal invisible: the factory operator sits on **no vault's** code-identity chain, so no amount of §15 verification reveals them. |
| **Direct authority** | Factory operator, where the implementation pointer is mutable. |
| **Authority closure** | `{retarget the factory}` closes over `{define the kernel of every future vault}`. It closes over **nothing** for vaults already deployed — a clone's implementation is a `PUSH20` immediate in its own code, so the factory holds no authority over its own output. |
| **Prevention** | **ADOPTED — the principal is removed rather than governed** (owner decision D8, LOCKED): the factory's implementation pointer is `immutable`, so registering a generation **is** deploying a new factory and no principal can retarget an existing one. `setImplementation`, `upgradeFactory`, `registerNewKernel` on an existing generation, beacons and mutable implementation registries are forbidden **by name**. MEASURED constructible in the §19.1 spike: 2,036 bytes of factory runtime, 495,374 gas, one per generation. |
| **Containment** | Blast radius is bounded to future vaults by construction, and §15's offline verification lets a user check what they actually got without trusting whoever published the address. |
| **Detection** | A retarget is observable; a user who never looks is unaffected until their next deployment. |
| **Recovery** | Deploy from a correct factory. Already-deployed vaults need no remedy. |
| **Residual risk** | **Discovery, not authority — and that is now ALL that remains of this entry.** Whoever publishes a factory address influences which generation users find. That is bounded by §15 verification, not eliminated by it. **D8 is DECIDED**, so the authority half of this hazard has no host in the target architecture. |
| **Proof tier** | T1. **Now modelled as `M56`** in a sub-model of its own (`FactoryGenerationModel`) — deliberately NOT bolted onto the vault state machine, which would have destroyed mutant attributability. The model discriminates the **rule** (an attempted retarget changes nothing; a new generation is a deployment). It discriminates nothing about Solidity: `immutable` is an IMPLEMENTATION-LANE property. |

---

## Hazards deliberately NOT claimed as closed

Honesty requires naming what this register does **not** resolve.

1. **No conformance claim.** Nothing here establishes that any Solidity implementation satisfies any
   invariant. The model proves architectural coherence and mutant discrimination only.
2. **UNRESOLVED, each requiring an owner decision:** H-04's PQ leg · H-11's authority split
   (now narrowed by architecture §22 D2) · H-17's attestor dependency · H-23's ERC-4337 decision ·
   **H-31's guardian-independence gap**.
   **Two entries have LEFT this list by owner decision:** **H-32's factory authority** is resolved by
   architecture §22 **D8** (one immutable factory per kernel generation — the principal is deleted,
   not governed), and the appetite call behind **H-15** is resolved by §22 **D1**
   (`guardian compromise cut = k`, an **accepted trust root** rather than an open question). §24
   still shows the guardian path is the **dominant** path to asset control; it is now dominant **by
   declared assumption** rather than as an unadjudicated finding.
3. **H-22 is live. It is product hygiene and a parity defect — NOT a vNext prerequisite.** The
   previous revision's promotion to prerequisite is **withdrawn** (architecture §13.0a): gating the
   explicit deposit functions cannot refuse a direct ERC-20 transfer, forced ETH, an airdrop, a
   rebase, or anything arriving after the manifest is bound, so no migration invariant may rest on
   it. H-28 is prevented by the per-entry manifest alone.
4. **The invariant set is not proven complete**, and this revision demonstrated that concretely:
   remediation added six hazards (H-27..H-32), two of which — H-27 and H-30 — are defects of the
   **previous revision of the architecture itself** rather than of any code. Absence of a hazard from
   this register is not evidence that none exists.
5. **Per-tenant instancing does not by itself remove a global admin.** NIST SP 800-160 v1r1 E.10/E.16
   bear on the admin directly, and the tenancy model does not settle it — the admin must be designed
   out explicitly, which §8 of the architecture document does and which this register tracks under
   H-01, H-05, H-07 and H-12. **Architecture §22 D8 adds the principal §8 had missed** — the
   factory operator (H-32).
