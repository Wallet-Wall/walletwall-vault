# SD-11A / SD-11B — verifier admission and verifier semantic integrity

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> Diagnosis and adjudication only. This lane changes **zero bytes** of
> `VaultKernelPrototype.sol`, of production `contracts/`, of governance and of
> deployment configuration. It adds a tracked reproduction, the tooling that
> makes it reproducible, and this record.

**Base:** `origin/main` = `535be8a17afd0290f42dc34c1da1e1c83e0aef9c`, tree
`c0344cbf1e02a35caf314ace6568f02f20315284` (the true-merge of PR #179).
**Baseline before any edit:** prototype suite **844 passing / 0 failing**.

## 0. Evidence labels, and the rule they encode

SD5-A1R had to withdraw a published claim because `setCode` was read as
deployment reachability. That correction is inherited as a rule rather than as a
memory:

| Label | Means |
|---|---|
| `REACHABLE` | a named principal calls a real function on a really deployed contract, and the system moves |
| `REPRESENTABLE` | the interface admits the shape; nothing is claimed about any deployed or intended verifier exposing it |
| `CONSTRUCTED_CONTROL` | built only to test whether a PROPOSED CONTROL detects a mechanism; never evidence that a repository verifier has it |
| `NOT ESTABLISHED` | the question was asked and the answer is not in evidence |

`test/Sd11VerifierAdmissionSemantics.test.ts` §F asserts mechanically that this
lane's reproduction calls no `hardhat_setCode`, `setStorageAt`, `setBalance` or
`impersonateAccount`, so a later edit cannot silently downgrade a reachability
claim into a representability one.

---

## 1. Phase D1 — the verifier lifecycle, re-derived from source

Five questions, answered at `VaultKernelPrototype.sol` rather than from the
ledger's prose.

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | how is a verifier ADMITTED? | a single test, `code.length != 0`, at three sites | `:378`/`:380` (initialize), `:997`/`:998` (setVerifier), `:1343`/`:1344` (initiateRecovery) |
| 2 | what identity is STORED? | `address public pqVerifier` — an address and nothing else | `:135`; three writes at `:417`, `:1107`, `:1521`, one per admission site |
| 3 | how is it INVOKED? | `IKernelPQVerifier(...).verify(digest, pqKey, pqSig)`, a STATICCALL returning a bare `bool` | `:619` (`_authorise`), `:802` (`_requireIncomingPossession`); interface at `interfaces/IKernelPlanes.sol:13` |
| 4 | how is it CHANGED? | only by re-admission: `setVerifier` (HYBRID) or `initiateRecovery`→`executeRecovery` (quorum). **The kernel has no in-place mutation path** | `:1107`, `:1521` |
| 5 | how does the kernel know the accepting relation is still the admitted one? | **It does not.** No codehash is recorded, nothing is re-validated, and the return carries no relation identity | absence at `:619`, `:802` |

**The contrast is inside the same contract.** `bindMigration` binds
`destinationVaultCodeHash` (`:1607`) and `egress` RE-CHECKS it at execution
(`:1646`, `DestinationMismatch`). So the kernel possesses the code-identity
mechanism and applies it to migration destinations and not to verifiers. The
stateful model agrees: its only verifier property is `G-VERIFIER-HAS-CODE`
(`stateful/invariants.ts:374`).

### 1.1 Eight concepts, kept apart

The lane's central discipline. Nothing below is treated as implying anything
else without a proof.

| Concept | Kernel's grip on it |
|---|---|
| verifier ADDRESS identity | the whole of what is stored (`pqVerifier`) |
| runtime BYTECODE identity | never read, never stored, never compared |
| IMPLEMENTATION identity (behind a delegating address) | invisible by construction |
| ACCEPTING-RELATION identity | never observed: `verify` returns one bit |
| cryptographic SCHEME identity | `algorithmId()` exists on `IPQCVerifier` and the kernel **never calls it**; §12 of the architecture explains why it could not be trusted if it did (`docs/Vault_vNext_Architecture.md:1112`) |
| KEY-MATERIAL validity | only `keccak256(pqKey) == pqPublicKeyHash` — a preimage identity, not well-formedness (this is SD-8) |
| ADMISSION authority | deployer at genesis (cut 0), credential via `setVerifier` (cut 2 armed / cut 1 dormant), guardian quorum via recovery (cut k) |
| POST-ADMISSION mutability | **a property of the verifier contract, not of the kernel** — the subject of SD-11B |

**Measured, not asserted** (§A of the reproduction): the kernel admits a
`DestinationStub` — a contract with no `verify` function at all — because it has
code (A1). The only refusal is a codeless address (A2, `ZeroAddress`). Admission
therefore tests nothing semantic whatsoever.

---

## 2. Phase D2 — SD-11B reachability

### 2.1 Classification, per architecture actually in this repository

| Verifier | Class | Exact mechanism | Label |
|---|---|---|---|
| **`AttestationPQCVerifier`** (production, Path 1 "implemented") | `MUTABLE_WITH_STABLE_ADDRESS` | `updateAttestor(address) onlyOwner` (`:53`) writes the storage variable `attestor` (`:38`) that `verify` reads at call time (`:113`). Runtime code is untouched. | **REACHABLE** (C2–C6) |
| **`ImmutableAttestationPQCVerifier`** | `IMMUTABLE_BY_CONSTRUCTION` | `address public immutable attestor` (`:49`), no setter, no owner, no admin surface. Changing the attestor requires a NEW DEPLOYMENT, i.e. a new address — which is `MUTABLE_WITH_ADDRESS_CHANGE`, and the kernel's stored address already sees it. | **REACHABLE-NEGATIVE** (C7, positive control passes) |
| **`ZKMLDSAVerifier`** | `UNKNOWN / NOT ESTABLISHED` | Its own state is immutable (`SP1_VERIFIER` `:28`, `PROGRAM_VKEY` `:31`), but `verify` forwards to `ISP1Verifier(SP1_VERIFIER)` (`:90`). The accepting relation is therefore a function of **another contract's** semantics. `docs/ZK_Prover_Runbook.md:117-123` directs operators to point `SP1_VERIFIER_ADDRESS` at "the canonical SP1 Groth16 verifier **gateway**". A gateway's routing table is not pinned, measured, or even present in this repository. | **NOT ESTABLISHED** — external, unmeasured |
| `MockMLDSAVerifier`, `EcdsaBackedVerifier`, `ConfigurableVerifier` | `IMMUTABLE_BY_CONSTRUCTION` | `pure`, or constructor-set with no setter | — |
| delegatecall proxy | not present in this repository | — | `CONSTRUCTED_CONTROL` only (D1) |
| metamorphic redeploy | — | requires removing code from an existing account | **NOT REACHABLE** for an already-admitted verifier (E1) |

### 2.2 The reproduction — A through E, on the REAL production contract

`test/Sd11VerifierAdmissionSemantics.test.ts` §C, using
`contracts/verifiers/AttestationPQCVerifier.sol` compiled from its own source by
the pinned solc and deployed by an ordinary transaction. No `setCode`.

| Required | Established |
|---|---|
| **A** verifier admitted | genesis admits it; `pqVerifier` = its address |
| **B** kernel-visible address unchanged | asserted identical across the mutation |
| **C** a previously-rejected relation is accepted | a spend attested by **B** reverts `VerifierDenied` before, and succeeds after |
| **D** no kernel admission action between B and C | the only transaction is `updateAttestor(B)` **on the verifier**; the kernel emits **zero** logs, `credentialGeneration` and `pqPublicKeyHash` are unchanged, and the refused spend consumed no nonce |
| **E** the kernel acts on the changed relation | the identical call bytes move 1 ETH |

Two further facts make the finding precise rather than merely alarming:

* **The relation MOVED, it did not widen** (C6): attestor A, accepted before, is
  refused after. This is a re-assignment of the second factor's root.
* **The runtime bytecode is bit-identical across the change** (C4). The authority
  lives in STORAGE, which G2 measures directly: the mutable verifier's attestor
  is found in a storage slot and **not** in its runtime code, while the immutable
  verifier's is in its runtime code and **not** in storage.

### 2.3 What is new here, and what was already known

**Already documented, and not claimed as a discovery:** that
`updateAttestor` is instant and escapes the *production vault's* two-day verifier
timelock. `docs/THREAT_MODEL.md:122`, `docs/Security_Assumptions.md:63-65` and
`docs/Attestation_Governance_Hardening.md:37-47` all say so, and
`test/AttestationPQCVerifier.test.ts:303-364` already executes the rotation at
the verifier level.

**What this lane adds:**

1. the class SD-11B recorded as **NOT MEASURED** is now **MEASURED**, against the
   vNext kernel's own admission model, as a tracked deterministic reproduction;
2. the mechanism is **not** in SD-11B's enumerated list. The entry names
   "upgradeable, proxied or metamorphic". The reachable mechanism is **none of
   those**: it is ordinary owner-controlled storage behind unchanged code;
3. therefore the control the entry floats — a codehash pin — **does not close the
   reachable case**, which C4 measures rather than argues.

### 2.4 The bound on the claim, stated so it cannot be over-read

The verifier is a **conjunctive plane**: it can deny, and it can fail to deny. It
cannot authorise on its own. So the consequence of C2–C6 is **not** "cut 2 → 1".
It is an **authority-set substitution**: the vault's second factor moves from
{holder of the committed PQ key} to {whoever the verifier's owner names}, with no
kernel-visible event. Reaching assets still requires the ECDSA credential root as
well, so the *count* stays 2 while the *set* changes without the vault's consent.

Against the architecture's declared envelope this is the `PLANE-SAFE` outcome
already accepted at `docs/Vault_vNext_Architecture.md:397` ("Byzantine ⇒ bounded
by the floor"). **What is new is timing and observability**: the verifier need not
be Byzantine when it is admitted, and nothing in the kernel ever revisits it.

---

## 3. Phase D3 — SD-11A, re-derived

The prior experiment is `prototype/vnext-kernel/SD5_A1R_ADVERSARIAL_CLOSURE.scratch.md`
with harness `sd5-scratch/a1r/` — **untracked** in another worktree, exactly as
the ledger says. Its N0–N5 series is sound and its conclusions reproduce. This
lane re-derived the construction independently and then compared.

### 3.1 The four propositions, kept apart

| # | Proposition | Verdict | Evidence |
|---|---|---|---|
| 1 | the interface can REPRESENT multiple accepting relations | **PROVEN** | B1: one deployed verifier accepts a strong witness and a forgeable weak one, and refuses a wrong one (vacuity guard) |
| 2 | a specific PRODUCTION candidate exposes multiple accepting relations | **NOT CLAIMED** | no production verifier examined by this lane does. This is asserted nowhere in the suite |
| 3 | an attacker can cause such a verifier to be ADMITTED | **REACHABLE, at a named cut** | B2: admitted by a real HYBRID `setVerifier` (cut 2). Admission is an authorised act by a named principal — not something an outsider does |
| 4 | a cut is actually REDUCED in a reachable state | **REACHABLE** | B3: the ECDSA root **alone** moves value through the weak leg. B5: it also completes a `rotateCredential`, replacing both factors |

**Attribution** (B6): the identical forged witness is refused by the honest
single-relation `EcdsaBackedVerifier`, and the honest witness still spends. The
success in B3 is therefore a property of the admitted verifier, not a kernel
weakness — the distinction the ledger's own wording depends on.

**The kernel cannot distinguish which relation answered** (B4): `verify` returns
one bit; the kernel emits its ordinary `Executed` event either way. The weak leg
is placed at the **declared** 65-byte length, so the structural gate SD5-I
removed would not have separated them either (SD5-A1R's M6, reproduced here
without `setCode`).

### 3.2 Tracked evidence now exists

SD-11A's `reproducedBy` said: *"that record is UNTRACKED lane scratch, so this
entry names no tracked deterministic reproduction. Promoting one is owed by the
lane that acts on SD-11A."* That debt is discharged by §B of the new suite.

---

## 4. Phase D4 — SD-8's relationship to SD-11

**Verdict: INDEPENDENT defect, SHARED root cause, NOT subsumed.**

The question is not "can the kernel parse ML-DSA" but: *what mechanically
checkable fact can establish that committed key material belongs to the accepting
relation represented by the admitted verifier?*

Four things must stay apart, and the kernel reaches only the first:

| Property | Who could establish it | Kernel today |
|---|---|---|
| knowledge of a PREIMAGE | the kernel, by `keccak256` | **established** (`:412`, `:801`) |
| key STRUCTURAL validity | only a scheme-aware verifier | not established (SD-8) |
| SCHEME MEMBERSHIP | a registry naming the scheme | not established — `algorithmId()` is self-asserted and uncalled |
| POSSESSION of signing capability | a proof of possession against a trusted verifier | not established at genesis; self-certifying there (`:397-405`) |

**Why they are two defects and not one.** They fail at different times and to
different parties:

* **SD-8** fails at **commitment** time: the bytes committed may not be a key of
  any scheme. `test/Sd67CommitmentAdmission.test.ts` states it in its own header
  — an exhibit "proves possession of a preimage; it says nothing about that
  preimage being a well-formed key of any scheme."
* **SD-11A** fails at **admission** time: the verifier may accept relations the
  admitter did not authorise over that same committed value.

Neither implies the other. A perfectly well-formed ML-DSA key is still exposed by
a dual-relation verifier (SD-11A with SD-8 closed); a single-relation verifier
still cannot make garbage bytes into a key (SD-8 with SD-11A closed).

**What they share** is one missing edge: there is no binding between *the
committed key* and *the relation the admitted verifier actually implements*. That
is `GEN1_SCHEME_SEMANTICS = VERIFIER_DEFINED` seen from two sides. SD-8's own
`minimalFixSketch` already rejects the three candidate fixes, and this lane finds
no fourth: every one of them requires a party the kernel does not have, and a
verifier leg at genesis is self-certification because the deployer chooses the
verifier in the same transaction.

**SD-8 is therefore correctly scoped today.** It should not be folded into
SD-11A, and folding it would lose the preimage-versus-possession distinction that
is the whole content of the entry.

**Append-only correction (lane SD-8, 2026-09-14,
`test/Sd8KeyWellFormednessAdjudication.test.ts`).** Two statements in this section
name the wrong judge and are corrected here rather than rewritten. The row "key
STRUCTURAL validity — only a scheme-aware verifier" and the sentence "a verifier
leg at genesis is self-certification because the deployer chooses the verifier"
both assume an on-chain verifier could judge the bytes. Under the admitted
Generation-1 relation NO verifier does: `ImmutableAttestationPQCVerifier.verify`
reads `publicKey` once, as `keccak256(publicKey)`. The judge is the relation's
trusted OFF-CHAIN attestor, at attestation time, and what it judges for ML-DSA-65
is exactly `length == 1,952` plus signature validity. Self-certification at
genesis survives on a different ground: after this lane the CLASS is root-fixed,
but the ATTESTOR is the deployer's choice (it is the root's CREATE2 salt), so a
genesis possession proof under the deployer's own attestor proves nothing —
measured: the empty key "proves possession". The verdict of this section —
independent defect, shared root cause, not subsumed — stands. SD-8's ledger entry
now records the gap at four sites (genesis, dormant rotation, dormant recovery,
the arming edge), for bytes of any length, zero included; the "three candidate
fixes" above are re-adjudicated in that entry's `minimalFixSketch`.

---

## 5. Phase A1 — candidate control matrix

Derived **after** D1–D4, not before. Every row carries an adversarial kill,
because a control with no kill is not established.

### A — address only (Generation-1 status quo)

* **Closes:** every mutation that moves the verifier's ADDRESS — including the
  `ImmutableAttestationPQCVerifier` redeployment path, which is the documented
  way to change that class's attestor.
* **Does not close:** storage-driven authority behind a stable address (C2–C6);
  delegating designs (D1); external-registry indirection (ZK path, unmeasured).
* **New authority:** none. **Gen-1 compatible:** it *is* Gen-1. **Bytes:** zero.
* **Adversarial kill:** C2–C6.

### B — EXTCODEHASH pin (the mechanism `bindMigration` already uses)

* **Would close:** replacement of an admitted verifier's CODE.
* **Does not close — measured, not argued:**
  * the **reachable** repository case: C4, runtime bytecode bit-identical across
    the relation change;
  * the delegatecall case the ledger itself names: D1, proxy codehash unmoved
    while the implementation pointer moves (`CONSTRUCTED_CONTROL`);
  * and its nominal target is **empty for an admitted verifier**: E1 measures that
    under the pinned cancun EVM a later-transaction `SELFDESTRUCT` sweeps the
    balance but **leaves the code in place** (EIP-6780), so metamorphic
    replacement of a verifier that outlived its creation transaction is not
    reachable at all.
* **New authority:** none. **Cost:** one storage word plus a re-check at every
  authorisation.
* **Verdict: REJECT as an SD-11B closure.** It would buy a *false* assurance
  against the case that is actually reachable. The ledger's instruction — "Do not
  present a codehash pin as closing SD-11B" — is upheld and now has executed
  evidence behind it.
* **Residual, named:** the same-transaction create + admit + selfdestruct
  composition is **NOT MEASURED** by this lane.

### C — approved implementation / artifact registry

The conceptual chain `AUTHORIZED_RELATION ← APPROVED_VERIFIER_ARTIFACT ←
mechanically identifiable admission evidence`. What would have to be bound, and
what survives each:

| Bound | Still movable afterwards |
|---|---|
| runtime codehash | the attestor, via storage (C4) |
| constructor / immutable config | nothing — it is inside the codehash (G2, immutable side) |
| algorithm / scheme id | the relation, while `algorithmId()` stays constant — it is self-asserted (`docs/Vault_vNext_Architecture.md:1112`) |
| implementation codehash (for a delegating design) | the implementation POINTER (D1) |
| deployment provenance | everything above |

* **New authority introduced:** a registry curator — a **governance principal
  this kernel deliberately does not have**. `AUTHORITY.md:327` lists `KERNEL
  ADMIN — DOES NOT EXIST`, and calls deleting that principal "the single largest
  authority-graph difference from the monolith". SD-8's `minimalFixSketch`
  already rejected an allowlist on exactly this ground, twice.
* **Gen-1 compatibility:** poor — it gates deployment on a new root.
* **Adversarial kill:** approving a codehash does not approve the *storage* behind
  it, so a registry that binds code alone is killed by C2–C6 unchanged.
* **Verdict: DEFER**, and note that the property such a registry would need to
  certify — "this artifact holds no post-admission authority over its accepting
  relation" — is an **off-chain assurance obligation**, because it is not a
  function of any on-chain identity the kernel can read.

### D — `SecurityProfile` / future-generation binding (architecture §12)

* §12 is the intended long-run home and is already
  `SECURITY_PROFILE_DISPOSITION = DEFERRED_TO_FUTURE_GENERATION`.
* **A finding ABOUT §12, produced by this lane:** `factor.verifierGeneration` is
  specified as *"monotone, bumped only together with a change of verifier code
  identity"* (`:1075`), and R4's dominance rule compares it. C2–C6 shows an
  accepting relation moving with **no change of code identity at all**, so a
  generation keyed to code identity would not move either, and R4 would rate the
  post-rotation profile as dominating. **§12 as written inherits the same gap.**
* **Verdict: DEFER to a future generation**, with that correction recorded so the
  next lane does not implement §12 believing it closes SD-11B.

### Bias check

The instruction was to bias against expanding Generation 1. The measurements
support that bias rather than fighting it: the only control that closes the
reachable case is a restriction on **which verifiers may be admitted**, and that
is an admission-policy question for the owner, not a kernel mechanism.

---

## 6. What this lane does NOT establish

1. **No production candidate is claimed to expose two accepting relations.**
   Proposition 2 of §3.1 is untouched.
2. **The ZK path is NOT MEASURED.** Whether an SP1 gateway's owner can move the
   relation behind `ZKMLDSAVerifier` is an external question this repository does
   not pin. It is recorded as `NOT ESTABLISHED`, not as a defect.
3. **No claim about same-transaction metamorphic composition.**
4. **No cut in `AUTHORITY.md` §3 is claimed to move.** §2.4 states the bound.
5. **The delegatecall result is a `CONSTRUCTED_CONTROL`**, evidence about a
   control's adequacy and never about a repository verifier.

---

## 7. Corrections this lane makes to existing records

Recorded here rather than silently applied; items 1–3 are applied to the ledger
because the measurements establish the current wording is false or materially
incomplete. Items 4–5 are **reported only** — they touch documents outside this
lane's allowed edits.

1. **SD-11B `rootsRequired` — "UNKNOWN"** is superseded for one class: moving the
   relation requires the admitted verifier's **owner key**, composed with the
   vault's ECDSA credential root to reach assets.
2. **SD-11B "NOT MEASURED" / `reproducedBy: NONE`** — both now false.
3. **SD-11B's mechanism list** ("upgradeable, proxied or metamorphic") is
   materially incomplete: it omits the only mechanism found reachable, and names
   one (metamorphic) that E1 measures as unreachable for an admitted verifier.
4. **`docs/ZK_Verifier_Production.md:21`** calls the SP1 verifier address an
   *"Immutable trust root … fixed at deployment"*. The ADDRESS is fixed; the
   relation behind it is not necessarily, and the repository's own runbook
   directs that address at a gateway. This conflates address identity with
   semantic immutability — the exact conflation SD-11B exists to name.
5. **`docs/Vault_vNext_Architecture.md:1075`** — see §5 D.

---

## 8. Verification

```
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test \
  prototype/vnext-kernel/test/Sd11VerifierAdmissionSemantics.test.ts
```

The ledger correction in `stateful/defects.ts` is carried into the receipt, which
is regenerated rather than hand-edited:

```
npx tsx prototype/vnext-kernel/generate-stateful-evidence.ts
git diff -- prototype/vnext-kernel/STATEFUL_AUTHORITY_EVIDENCE.json
```

| Measurement | Result |
|---|---|
| baseline at `535be8a1`, before any edit | **844 passing / 0 failing** |
| the new reproduction alone | **16 passing / 0 failing** |
| full prototype suite, final tree | **860 passing / 0 failing** (= 844 + 16; no regression) |
| tests intentionally left red | **none** |

**The receipt regeneration is bounded and idempotent, and both were checked
rather than assumed.** The diff touches exactly SEVEN keys — `reproducedBy` on
SD-11A, and `title`, `rootsRequired`, `rootCause`, `notAnEscalationBecause`,
`minimalFixSketch`, `reproducedBy` on SD-11B — and no count, digest, measured
figure or provenance field moves with them. Running the generator a second time
reproduces the identical file (`sha256:8e2765ee…`), which is what CI's
`git diff --exit-code` step actually enforces. The receipt still declares subject
`88ee0c09…` from `MEASUREMENTS.json`, never this uncommitted tree, so
regenerating here does not stamp a working tree as evidence.

Nothing in this lane writes to `prototype/vnext-kernel/contracts`. Verified, not
asserted: `git rev-parse HEAD:prototype/vnext-kernel/contracts` is
`dcc42e76a22b2491e05a6f7ccbc98f447e6acbc5`, which is the `contractsTree` value
`SCANNER_EVIDENCE.json` already records, and the directory has no working-tree
changes. The scanner-input scope is therefore byte-unchanged and the committed
Slither result keeps its currency licence without a new run.

**Solidity delta is ZERO in both compilation units** — no `.sol` file is modified
and none is added, in `contracts/` or in `prototype/vnext-kernel/contracts/`. The
reproduction's fixtures are compiled in memory by the pinned solc and the two
production verifiers are read from their own sources, which is why a lane that
measures production contracts still changes none of them.
