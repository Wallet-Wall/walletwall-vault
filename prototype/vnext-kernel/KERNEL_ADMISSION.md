# Kernel Admission Manifest — vNext Minimal Trust Kernel, prototype v0

**Derived firsthand from PR #179 at `71aee6f3062c3c9784020caf2e3db52f9b700c3f`.**
Every row cites the §179 section it comes from. Where #179 does not settle a question, this file says
so rather than improvising.

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> This manifest governs a measurement prototype. It is not a production specification.

## The admission rule, quoted rather than paraphrased

> **R-KERNEL** (§4.1). A responsibility belongs in the immutable kernel **iff** there exists a
> declared catastrophic requirement (G1 or G2) whose satisfaction cannot be restored by _any_
> sequence of authorized transactions after that responsibility's owning component becomes
> permanently unavailable or Byzantine.

> **R-KERNEL-CIRCULARITY** (§4.1). If _replacing_ a component requires that component to function,
> it is KERNEL-REQUIRED regardless of the above.

**A component is admitted only when exclusion is proven unsafe.** Presence in
`contracts/WalletWallVault.sol` is not an argument and is never cited as one below.

---

## 1. KERNEL — admitted, with the irreducibility argument for each

| #    | Responsibility                                                                         | Why irreducible (§179)                                                                                                                                             | Catastrophic invariant protected                     | Authority held                                                             | External dependency                                           | Prototype representation                                                          |
| ---- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| K-1  | **Asset custody**                                                                      | §4.2: Byzantine ⇒ total loss; unavailable ⇒ total loss. Unanimous across all three lenses (§4.2a)                                                                  | `I-CUSTODY-CONSERVATION`                             | none — custody is a _fact_, not a capability                               | none                                                          | the clone holds ETH directly; `receive()` accepts unsolicited value               |
| K-2  | **Asset execution**                                                                    | §4.2: unavailable ⇒ assets frozen forever. An executor outside the kernel that dies strands the vault                                                              | `I-CUSTODY-CONSERVATION`                             | spending credential                                                        | none                                                          | `execute(SpendAuth, sigs)` — **exact typed**, never `execute(address,bytes)` (§5) |
| K-3  | **Nonce / replay state**                                                               | §4.2: Byzantine ⇒ replay ⇒ loss; unavailable ⇒ no authorization possible                                                                                           | `I-NO-REPLAY`                                        | none — it is state, not a principal                                        | none                                                          | four **separate** nonce domains (§ below)                                         |
| K-4  | **Credential commitment**                                                              | §4.2: Byzantine ⇒ attacker named as owner ⇒ loss                                                                                                                   | `I-CUSTODY-CONSERVATION`                             | rotation: credential; replacement: guardian quorum                         | none                                                          | `ecdsaSigner`, `pqPublicKeyHash`, `credentialGeneration`                          |
| K-5  | **Kernel-evaluated possession floor**                                                  | §4.3a `I-NO-SOLE-EXTERNAL-AUTHENTICATOR` / `I-FLOOR-IS-SOUND`. With every plane removed the floor must still **deny**                                              | `I-FLOOR-IS-SOUND`                                   | none                                                                       | `ecrecover` precompile `0x01` **only**                        | `ECDSA.recover` on every asset-moving and credential-changing path                |
| K-6  | **Guardian AUTHORITY** — commitment, threshold, generation                             | §4.2b G-B. Circularity: replacing a guardian plane needs guardian authority                                                                                        | `I-GUARDIAN-AUTHORITY-CLOSURE`                       | kernel is the **sole writer**, under its own preceding quorum              | none — validation is pure hashing                             | `guardianCommitment`, `guardianThreshold`, `guardianGeneration` (3 words)         |
| K-7  | **Recovery request state**                                                             | §4.2: Byzantine ⇒ forged/erased requests; unavailable ⇒ recovery unreachable                                                                                       | `I-RECOVERY-SOVEREIGNTY`                             | none                                                                       | none                                                          | `RecoveryRequest` struct, keyed by guardian generation                            |
| K-8  | **Recovery execution**                                                                 | §4.2: Byzantine ⇒ arbitrary credential install                                                                                                                     | `I-RECOVERY-SOVEREIGNTY`                             | guardian quorum ≥ `k`                                                      | guardian principals only (§9 `I-RECOVERY-LOCALITY-V2` item 3) | `executeRecovery()`                                                               |
| K-9  | **Recovery cancellation**                                                              | §4.2a: adjudicated **KERNEL-REQUIRED** against the Byzantine lens — the remedy for a hostile canceller _is_ recovery, and the canceller cancels recovery           | `I-VETO-BOUND`                                       | credential (**bounded count**), or guardian quorum                         | none                                                          | `cancelRecovery()` with a per-episode challenge budget                            |
| K-10 | **Safe-state machine**                                                                 | §4.2a: minimality dissented and was overruled — an external state machine that can force a terminal state is a total-loss path                                     | `I-EXIT-REACHABILITY`                                | see the transition table                                                   | none                                                          | `SafeState` enum + an action matrix                                               |
| K-11 | **Emergency transition RULES**                                                         | §4.2 split: rules KERNEL, trigger ADAPTER                                                                                                                          | `I-CONTAINMENT-BUDGET`, `I-CONTAINMENT-NO-EXTENSION` | none — rules are not a principal                                           | none                                                          | wall-clock expiry, rolling budget `B < W`                                         |
| K-12 | **Migration authorization (BIND)**                                                     | §4.2: Byzantine ⇒ malicious destination ⇒ total loss                                                                                                               | `I-MIGRATION-BINDING`                                | guardian quorum **AND** credential (§22 D2)                                | none                                                          | `bindMigration(Binding, sigs)`                                                    |
| K-13 | **Migration execution (EGRESS)**                                                       | §4.2a: "migration is the universal escape from plane death; an escape that itself lives in a plane is not an escape"                                               | `I-MIGRATION-NONTRAP`                                | **anyone** — it carries no discretion (§22 D2)                             | the asset contract being moved                                | `egress(assetSpec)`, recipient from the binding                                   |
| K-14 | **Verifier GOVERNANCE** (authority to replace a verifier)                              | §4.2: **unanimous**, and it corrects an earlier draft. Circular — the remediation would be authenticated by the verifier being replaced                            | `I-NO-CIRCULAR-ESCAPE`                               | credential (the `ecrecover` conjunct, which the verifier cannot influence) | none                                                          | `setVerifier()` gated on the ECDSA conjunct **alone**                             |
| K-15 | **Kernel-recorded cryptographic FLOOR** — `requirePq`, param level, structural lengths | §4.3 floor component 2: _"kernel-recorded scheme strength, **never read from the verifier**"_, plus §12's transition rules. A plane cannot report its own strength | `I-NO-SILENT-DOWNGRADE`, `I-FLOOR-IS-SOUND`          | no principal may WEAKEN it; strengthening rides with `setVerifier`         | none — pure integer comparisons                               | `SecurityFloor` struct + `_requireNoDowngrade`                                    |

**Every one of the 15 is implemented in the prototype.** None is omitted for size.

> **K-9 CORRECTION (Lane V2 / W1P) — the sentence above is retained as written
> and is FALSE for K-9.** K-9 declares **two** cancellation authorities, and its
> own authority column says so: *"credential (bounded count), or guardian
> quorum"*. `docs/Vault_vNext_Architecture.md` §8.1 (`:832`), under the heading
> *"Direct capabilities (vNext)"*, grants the guardian quorum `CANCEL_RECOVERY`.
>
> ```text
> K-9 declared cancellation authority:
>
> A. spending credential:
>    bounded recovery challenge/cancellation
>
> B. guardian quorum:
>    direct CANCEL_RECOVERY
>
> prototype at c67d1439:
>    A implemented   — cancelRecovery(nonce, deadline, ecdsaSig), gated by
>                      _floorAuthorises, capped by CHALLENGE_LIMIT
>    B missing       — the complete quorum-authorised surface, enumerated from
>                      the ABI, is bindMigration, enterContainment,
>                      initiateRecovery, setGuardians
>
> K9_GUARDIAN_CANCEL_CONFORMANCE = MISSING_IN_PROTOTYPE
> K9_CONFORMANCE                 = PARTIAL / FAILED FOR THE DECLARED DUAL MECHANISM
> ```
>
> Three substitutes were tested and refuted (`test/Sd4LaneV2.test.ts`): a
> "null" overwrite cannot express *no request* (`ZeroAddress`); containment does
> not cancel (`_requireRecoveryOpen` admits `CONTAINED`); `setGuardians` strands
> rather than cancels, which is a defect of its own (SD-10). The row's own
> implementation column — *"`cancelRecovery()` with a per-episode challenge
> budget"* — describes only mechanism A, so the summary line is contradicted by
> the table it summarises. A defensible restatement is: *fifteen kernel-required
> concerns are addressed; K-9's declared authority names two principals and only
> the credential half is implemented.* The direct overwrite the prototype permits
> instead is classified `NONCONFORMANT_AND_REDUNDANT` — see
> `SD9_RECOVERY_LIFECYCLE_DEFECTS.md` and `docs/Vault_vNext_Recovery_Amendment.md`.

> **K-9 W2 STATUS (Lane W2I; reviewed in Lane W2R; persisted as Commit A
> `c182db1099d92ff5830ae71116613c739b034bd9` in Lane W2P; the block above is
> retained as history).** Mechanism B is now implemented in
> `contracts/VaultKernelPrototype.sol` as
> `cancelRecoveryByQuorum(QuorumProof,uint256,uint64)` — guardian quorum under the
> CURRENT commitment and generation, `DOMAIN_GUARDIAN` nonce, clears request
> authority only, leaves `challengesUsed` standing, emits
> `RecoveryCancelledByQuorum`. The quorum-authorised surface is now FIVE:
> `bindMigration`, `cancelRecoveryByQuorum`, `enterContainment`,
> `initiateRecovery`, `setGuardians`.
>
> ```text
> K9_GUARDIAN_CANCEL_CONFORMANCE = IMPLEMENTED (W2 Commit A c182db10, reviewed in W2R)
> K9_CONFORMANCE                 = BOTH MECHANISMS PRESENT — executable-conformant
>                                  (test/W2RecoveryLifecycle.test.ts §A,
>                                   test/W2RecoveryLifecycleMutations.test.ts)
> ```
>
> The direct overwrite the prototype permitted is REFUSED (`BadState` while a
> request is effectively live); an expired request holds no authority and blocks
> nothing; the executable window is half-open `[executableAt, expiresAt)`; the
> challenge epoch persists across every exit and resets only through
> `executeRecovery`'s `delete recovery`. The sentence *"Every one of the 15 is
> implemented"* is therefore true again as written, and the row's implementation
> column now reads `cancelRecovery()` (credential, per-epoch challenge budget) +
> `cancelRecoveryByQuorum()` (guardian quorum). Record:
> `W2_IMPLEMENTATION_RECORD.md`.

> **K-15 WAS MISSING FROM THE FIRST DRAFT OF THIS MANIFEST, and its absence was
> a live defect rather than a documentation gap.** The authority-closure pass
> (AUTHORITY.md) asked which principal could reach a _silent crypto downgrade_
> and found the answer was **anyone holding the ECDSA key alone** — because the
> first `_authorise` engaged the PQ conjunct only when the CALLER supplied a
> non-empty signature. Passing an empty blob downgraded HYBRID to ECDSA-only
> through the argument list, with no state transition for §12's partial order to
> refuse. Recording the requirement in the KERNEL and making it the kernel's
> decision closes it (mutants **M-K26**, **M-K27**). Cost: **+1,199 bytes**.
>
> This is the finding the lane exists to produce. It was not found by a test —
> the tests all passed — but by mapping the prototype back onto #179's authority
> model and noticing an outcome whose cut had silently dropped to 1.

> **K-15 CORRECTION (Lane SD5-I) — the row above is retained as written and is
> now PARTLY FALSE, in two separate ways.** The K-9 correction is the precedent
> for stating that in place rather than rewriting history.
>
> **(1) THE ROW OVER-SCOPES ITSELF.** Its title reads *"requirePq, param level,
> structural lengths"*, but its CITATION is to §4.3 floor **component 2**
> (*"kernel-recorded scheme strength, never read from the verifier"*). The
> structural lengths are component **1** — a different component with a different
> justification, carried here under a citation that never covered them. Lane
> SD5-I DE-AUTHORISES all three, so only `requirePq` remains security authority.
> The other three are `SIGNED_METADATA` + `IDENTITY_BOUND_METADATA` +
> `NON_AUTHORITATIVE_SECURITY_METADATA` + `ABI_COMPATIBILITY`, and explicitly NOT
> `AUTHORIZATION_INPUT`, NOT `RECOVERY_SATISFIABILITY_INPUT`, NOT
> `CRYPTOGRAPHIC_STRENGTH`. The invariants column moves with them:
> `I-FLOOR-IS-SOUND` is satisfied by the kernel-evaluable anchored ECDSA factor
> and NEVER rested on scheme-shape metadata (§4.3a says so in terms — "neither
> demonstrates possession of a private key"), and `I-NO-SILENT-DOWNGRADE` narrows
> to `I-NO-SILENT-DOWNGRADE-G1`: a mandatory PQ conjunct may not be silently
> disabled, and nothing more. `I-FLOOR-SHAPE-IMMUTABLE` is RETIRED and replaced by
> `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`.
>
> **(2) "plus §12's transition rules" WAS NEVER IMPLEMENTED**, so *"Every one of
> the 15 is implemented in the prototype"* is false for K-15 in a way the W2
> correction did not reach. §12 replaces the flat strength scalar with a
> `SecurityProfile` — `schemeId`, `family`, `paramLevel`, `rootTag`,
> `verifierGeneration`, `anchored`, clause structure — and the prototype
> implements a flat four-field struct carrying **one** of those seven. §12
> explicitly WITHDREW the flat scalar as *"a scalar asserts a total order that
> does not exist"*, and `pqParamLevel` **is** that withdrawn construct.
> `SECURITY_PROFILE_DISPOSITION = DEFERRED_TO_FUTURE_GENERATION`; Generation 1
> claims no strength policy at all.
>
> **THE VERIFIER-ADMISSION OBLIGATION, which K-15 must now carry because nothing
> else does.** `GEN1_SCHEME_SEMANTICS = VERIFIER_DEFINED`: the kernel does not
> know, and does not claim to know, which cryptographic relation its verifier
> implements. Its only constraint at all three admission points — `initialize`,
> `setVerifier`, `initiateRecovery` — is a nonzero code length. Verifier admission
> is therefore a DEPLOYMENT PRECONDITION in two parts, and BOTH are required:
>
> &nbsp;&nbsp;**(a)** the admitted verifier's INTENDED relation conforms to FIPS 204,
> including §3.6.2 — which binds *an implementation of ML-DSA* to return false on
> wrong-length inputs, and places no duty on a scheme-agnostic kernel; **and**
>
> &nbsp;&nbsp;**(b)** admission SEPARATELY establishes that the verifier exposes **no
> unauthorized accepting relation** over a committed key.
>
> **(a) DOES NOT IMPLY (b)**, and that is measured rather than argued: lane
> SD5-A1R built a single verifier with a FIPS-shaped strong leg AND a forgeable
> second leg over the same committed key, and carried the weak leg through to
> asset movement and a credential change. Anyone writing "mitigated by FIPS 204"
> has lost the distinction. The kernel CANNOT discharge (b) — it cannot prove
> arbitrary bytecode exposes only one relation, and requiring it to would replace
> the old length-based pseudo-binding with an unverifiable one — so (b) is an
> artifact/admission obligation and the gap is recorded as **SD-11A**.
>
> Whether an ALREADY-ADMITTED verifier can change its relation in place is
> **SD-11B**, recorded as NOT EXCLUDED and NOT MEASURED. The kernel pins no
> verifier codehash and never re-validates after admission, while `bindMigration`
> DOES pin `codehash` for migration destinations — so the mechanism exists in this
> contract and is simply not applied to the verifier. Note before reaching for it:
> a codehash pin would address metamorphic redeploy but NOT a delegatecall proxy,
> whose codehash is stable while its implementation pointer moves.
>
> Measured cost of the amendment: runtime **18,367 → 17,695 bytes (−672)**, with
> storage layout, ABI, selectors, events, errors and `securityFloor()`'s return
> shape BYTE-IDENTICAL. Record: `SD5_A1R_ADVERSARIAL_CLOSURE.scratch.md`.

---

## 2. NOT KERNEL — excluded, with the exclusion argument

| Responsibility                          | Class (§179)                     | Why excluded                                                                                                                                                            | Where it goes                                                                                                |
| --------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Guardian **roster bytes**               | **NOT KERNEL-RESIDENT** (§4.2b)  | A forged roster fails the commitment check, so the bytes need no protection — only the _commitment_ does. G-B is indistinguishable from G-A on the separating predicate | untrusted **calldata**, validated against the kernel's own commitment. Residual **H-27** is charged honestly |
| Verifier **implementation**             | PLANE-SAFE (§4.2)                | Bounded by the floor; unavailable ⇒ denial only, never loss                                                                                                             | external `IPQCVerifier`, consulted **conjunctively**                                                         |
| Guardian signature **aggregation**      | PLANE-SAFE _conditional_ (§4.2a) | Safe **only if** the kernel retains an individual-approval path — the condition is normative                                                                            | not implemented; the kernel keeps the individual path, which is what makes aggregation optional              |
| Policy **enforcement**                  | PLANE-SAFE (§4.2)                | Over-restriction is denial, not loss; migration is the escape                                                                                                           | external `IPolicyEngine`, **subtractive only**                                                               |
| Policy **administration**               | PLANE-SAFE (§4.2a)               | Byzantine worry is over-restriction ⇒ denial. Denial is inside the envelope; loss is not                                                                                | outside the kernel                                                                                           |
| Emergency **trigger**                   | ADAPTER-SAFE (§4.2)              | Spurious containment is bounded and self-expiring                                                                                                                       | an address; the _rules_ (K-11) bound it                                                                      |
| **ERC-1271 handling** (vault as signer) | ADAPTER-SAFE (§4.2)              | One `view` function that MUST NOT modify state; zero execution authority                                                                                                | **NOT IN GENERATION 1** — no consumer in the prototype                                                       |
| **ERC-4337 validation**                 | ADAPTER-SAFE _conditional_ (§5)  | EntryPoint becomes an unconditionally-trusted caller; ERC-7562 [OP-011] bans `TIMESTAMP`, which every time-gated authority here reads                                   | **NOT IN GENERATION 1** — §5 recommendation                                                                  |
| **ERC-7579 modules**                    | **REJECTED** (§4.2, §5)          | Module authority _is_ total takeover, per the vendor's own documentation                                                                                                | never                                                                                                        |
| Assurance **observatory**               | OBSERVATORY (§10)                | Observation gets no custody capability                                                                                                                                  | events + public getters only; **no assurance admin**                                                         |
| **Large-tx queue / timelock**           | —                                | Not classified KERNEL by §4.2. It is a _policy_ over spending, and §4.3 sends "no policy configured" to the kernel floor                                                | **NOT IN GENERATION 1.** Present in the monolith; **not admitted here**                                      |
| **Treasury quorum**                     | —                                | Same. A spending policy, not a custody invariant                                                                                                                        | **NOT IN GENERATION 1**                                                                                      |
| **Per-owner `vaults[]` mapping**        | —                                | An artefact of Architecture A. Under C the clone address **is** the identity (§3.2 R1)                                                                                  | **structurally forbidden** — see the stop condition                                                          |
| Verifier **timelock** (propose/apply)   | —                                | Governance _timing_, not governance _authority_. K-14 admits the authority; the delay is a parameter                                                                    | **NOT IN GENERATION 1** — deferred, and named so                                                             |

---

## 3. Nonce domain adjudication (§179 requires the domains be adjudicated, not assumed)

Four authority domains genuinely differ, so a single global counter would let one domain's
consumption block another's — and would let a queued spend authorization be invalidated by an
unrelated guardian action.

| Domain              | Nonce                | Why separate                                     |
| ------------------- | -------------------- | ------------------------------------------------ |
| asset execution     | `nonces[SPEND]`      | high frequency, credential-authorized            |
| credential change   | `nonces[CREDENTIAL]` | must not be consumable by spending               |
| guardian / recovery | `nonces[GUARDIAN]`   | authorized by a _different principal set_        |
| migration           | `nonces[MIGRATION]`  | one-shot, and must survive a credential rotation |

Implemented as `mapping(uint8 => uint256)` — one slot per domain, four domains.

---

## 4. What the prototype deliberately does NOT prove

- **PQ cryptography is NOT proven.** The prototype consults an `IPQCVerifier` interface. Per §4.3a,
  the deployed `MockMLDSAVerifier` is a **structural** check with _"NO cryptographic guarantee"_.
  The prototype's claim is only that the PQ leg is a **conjunctive barrier**, never an authenticator.
- **No conformance to the §179 model** is claimed. The TypeScript reference model and this Solidity
  are independent artifacts.
- **No production readiness.** No audit, no fuzzing campaign, no formal verification.
