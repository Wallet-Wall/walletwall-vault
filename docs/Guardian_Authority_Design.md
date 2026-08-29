# Guardian-Set Authority — Design

> **RESEARCH PROTOTYPE. NOT AUDITED. TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH REAL FUNDS.**
> This document is an implementation contract for a future change. §4 onward describes behaviour
> that does **not** exist on `main`. §2 and §3 describe behaviour that **does** exist, re-derived
> from source and additionally proven, during the original investigation, by an executed throwaway
> test harness (11/11 passing; see §3's note on its "EVIDENCE N" tags — the harness itself is not
> part of this repository).

**Status: v3 — TIGHTENED after a final adversarial pass.** No Solidity written, nothing deployed,
nothing merged, nothing pushed. This pass leaves the disk exactly at anchor: the one disposable
compile spike it ran (§13.1) was reverted with `git checkout --` and reconfirmed byte-identical to
`origin/main` before this document was touched.

> **v3 sharpens v2's central claim and corrects one conflation.** v2 showed the post-bootstrap
> invariant is achievable in principle, uniquely via existing guardians, and left it there. v3
> (a) states and tests the sharper property the brief actually cares about —
> **I-GUARDIAN-INDEPENDENCE** (§4.1a): guardian-replacement authority independent of *both*
> `vaultOwner` compromise *and* spending-credential compromise — against nine named principals,
> and finds the **current implementation VIOLATES it** while **target design feasibility is
> ACHIEVABLE IN PRINCIPLE (concrete mechanism not yet locked)** — the same feasibility I-REFINED
> already established, so no new backlog item is created; (b) re-adjudicates H3 scenario-by-scenario
> and supplies
> the exact corrected NatSpec text for `:671` (§10); (c) corrects v2 §11's conflation of H2 and
> H4 — they do **not** share a fix — by adjudicating the cheap single-slot candidate **H4-A**
> before escalating to request IDs, and **confirms it SOUND WITH CONDITIONS** by an executed
> red→green test against this exact commit plus a measured +64-byte compile spike (§11, §13.1).
> H2 stays open, deliberately unsolved here (§11.4). Nothing here is achieved by inventing a new
> impossibility or a new hierarchy — see §4.1a's closing note and §14.1.

**Anchor commit:** `032fe0141d805a15d467fb47e783cdf37327b9ae` (`origin/main`, package `0.13.0`).

---

## 1. The seam

`docs/Policy_Control_Authority_Design.md:41-49` already named this defect class, one seam over:

> One root cause — configuration authority bound to a *credential-bearing address* rather than
> to a lifecycle — produces two **opposite** failures. […] **A timelock alone fixes the first and
> makes the second worse.**

`setGuardians` is the last un-migrated instance of that pattern, and the one that matters most,
because the configuration it controls *is the authority that can rewrite the vault's credentials*.

```solidity
// contracts/WalletWallVault.sol:389-390 — the entire authorization
function setGuardians(address[] calldata guardians) external {
    if (!vaults[msg.sender].exists) revert VaultDoesNotExist();

// contracts/WalletWallVault.sol:510-514 — executeRecovery
VaultOwner storage vault = vaults[vaultOwner];   // storage POINTER; the key never moves
vault.ecdsaSigner  = recoveredSigner;            // only the CREDENTIALS rotate
vault.pqPublicKey  = recoveredPQPublicKey;
```

One root cause, two opposite failures:

| Failure | Mechanism | Consequence |
|---|---|---|
| **Compromise** | Attacker holding the tenant `vaultOwner` key calls `setGuardians([attacker])`, then drives recovery | Full credential takeover in 7 days with **zero** signatures from the existing credentials |
| **Recovery-orphaning** | `executeRecovery` rotates credentials but not the `vaults[]` mapping key | Recovered credentials can spend but **can never** reconfigure guardians — permanently |

`docs/Security_Assumptions.md:202-208` documents only the first, and credits a 7-day delay plus
an owner veto. §3 shows both halves of that credit are weaker than stated. §4 shows the second
failure is precisely why the obvious fixes are all wrong.

The lane's tentative target property was:

> Possession of `vaultOwner` alone should not be sufficient to rewrite the authority that can
> later recover the vault into attacker-selected credentials.

**That property, taken as an unconditional claim over every vault state, is not what this document
ends up defending — see §4 for the corrected verdict.** It splits in two: at bootstrap (`n == 0`)
it is genuinely not achievable, because no other candidate authorizer exists (§4.0's P1). Once a
guardian set is established, the corrected, sharper form of this property
(I-REFINED, §4.1; I-GUARDIAN-INDEPENDENCE, §4.1a) is **achievable in principle** — the concrete
mechanism is simply not yet locked, and the **current implementation violates it** (§4.1a): it does
not follow that guardian hardening is impossible. §4.0 explains why v1's original four-part proof of
unconditional non-achievability does not hold post-bootstrap.

---

## 2. Current-state model (source-backed)

### 2.1 Five identities, never interchangeable

| # | Identity | Kind | Moves on recovery? |
|---|---|---|---|
| **(a)** | Contract admin — `Ownable2Step.owner()` | Global, one per deployment | n/a |
| **(b)** | Tenant `vaultOwner` — the `vaults[]` **mapping key**, `msg.sender` at `createVault` | **Stable identity** | **No — never** |
| **(c)** | `vault.ecdsaSigner` | Rotating authority | Yes |
| **(d)** | `vault.pqPublicKey` | Rotating authority | Yes |
| **(e)** | Guardian addresses | Rotating constituency | No |

`vaults[msg.sender] = VaultOwner({...})` at `:593` is the **only** wholesale assignment to a
`vaults[]` entry, gated once-only by `:576`. `executeRecovery` writes through the storage pointer
obtained at `:510`. Therefore **(b) can never be revoked, reassigned, or recovered.** Every
finding below follows from that one fact.

Functions keyed on `msg.sender == (b)`: `setGuardians` `:390`, `cancelRecovery` `:549`,
`createVault` `:576`, `deposit` `:752`, `finalizeWithdrawal` `:891`, `cancelPendingWithdrawal`
`:1022`, `setTreasuryQuorumThreshold` `:1315`.

Nothing restricts (b) to an externally-owned account — the only `code.length` checks are on the
policy engine (`:964`, `:1277`) and the PQ verifier (`:1118`, `:1165`). **A Safe can be the tenant
`vaultOwner`**, and needs no `receive()` because refunds are ledger credits. That makes the
operational mitigation in §9.4 real and free.

### 2.2 Lifecycle, re-derived

| # | Question | Answer (`contracts/WalletWallVault.sol`) |
|---|---|---|
| 1 | Who may call `setGuardians` | (b) only. Sole gate `vaults[msg.sender].exists` `:390`. **No modifier at all** |
| 2 | Bootstrap | `setGuardians` only. `createVault` `:593-600` never writes `vaultGuardians`. **Every vault is born unguarded**; `:421` is the sole write site |
| 3 | Replacement | Full-set replacement only. No add/remove/index mutation exists anywhere |
| 4 | Removal / shrink | By replacement with a shorter array. Minimum **1**; `length == 0` reverts `InvalidGuardianSet` `:391`. Empty is unreachable after bootstrap |
| 5 | Threshold | `(vaultGuardians[o].length / 2) + 1`, read **live** at `:507`. 1→1, 2→2, 3→2, 4→3, 5→3, 32→17. Never stored on the request |
| 6 | Initiation | `whenNotPaused`. Guardian membership checked **last**, after the replace predicate `:444` and `_validateCredentials` `:447`. (b) can never initiate — barred from its own set by `:397` |
| 7 | Support | **No modifiers, no timestamp check.** Keyed `recoverySupports[owner][guardian]` — a flag that does **not** bind the request it supports |
| 8 | Replacing a request | `exists && block.timestamp < executeAfter` `:443-446`. **`supportCount` is not consulted** — wider than its own comment `:440-442` and wider than its only test |
| 9 | Cancellation | (b) only, `:548`. **No modifiers** — pause-immune |
| 10 | Execution | `nonReentrant whenNotPaused`, **permissionless caller**. Writes in order: signer `:513`, PQ key `:514`, `nonce++` unchecked `:516`, `policyControlEpoch++` checked `:522`, delete request `:524`, clear supports `:527-529`, cancel+refund pending withdrawal `:531-539` |
| 11 | Rotation vs recovery | `rotateCredentials` needs **four** signatures in Hybrid. `executeRecovery` needs **zero**. Both reach the same two storage slots |
| 12 | Nonce | Bumped by `executeRecovery` `:516`, `rotateCredentials` `:664`, `withdraw` `:1093`, `queueWithdrawal` `:832`. Not by `setGuardians` / `initiate` / `support` / `cancel` |
| 13 | Pending withdrawal | `setGuardians` clears treasury approvals `:416-419`; `executeRecovery` `:531-539` and `rotateCredentials` `:675-683` cancel **and refund** |
| 14 | `policyControlEpoch` | **Only** `executeRecovery` `:522` and `rotateCredentials` `:669`. `setGuardians` bumps nothing — deliberate, `:193-198` |
| 15 | Survives admin ownership transfer | **All** per-tenant state. (a) holds zero direct power over any tenant's guardians or recovery |
| 16 | Survives credential rotation | Guardians, **the recovery request and its supports**, treasury threshold. Not the pending withdrawal |
| 17 | Survives guardian mutation | `policyControlEpoch`, `treasuryQuorumThreshold` (**not** re-validated), the credentials. **Not** the request, supports, or treasury approvals |
| 18 | Survives a live/matured request | Everything. A live request freezes nothing: withdrawal, rotation, guardian replacement and quorum changes all proceed |

**Zero external calls on the recovery path.** The complete external-call census is `:581`, `:723`,
`:731`, `:812`, `:822`, `:965`, `:1078`, `:1082`; not one falls inside `:389-560`. Even the refund
at `:537` is a ledger credit, not a transfer. Recovery is therefore module-independent by
construction and cannot be bricked by a reverting policy engine — pinned executably by
`test/PolicyControlEpoch.test.ts:136-157`. **This is the design's strongest asset and the single
strongest reason to reject every candidate that adds a callback.**

### 2.3 An undocumented ordering invariant holds the whole thing up

`setGuardians` is sound today only because of statement order: it unconditionally deletes any
pending request at `:404-407` and clears treasury approvals at `:416-419` **before** the sole
array write at `:421`. That is what makes the live threshold read at `:507` sound and guarantees
`supportCount <= length` at all times.

No comment states it. No test enters the `:404-407` branch — **no test in the repository calls
`setGuardians` while a recovery request exists.** Any propose/apply or add/remove guardian API —
the shape every hardening candidate takes — opens a window in which the set mutates under a live
request and destroys this invariant silently.

### 2.4 Pause is a one-sided brake

| Function | `whenNotPaused`? |
|---|---|
| `initiateRecovery` `:433` | **Yes** |
| `executeRecovery` `:502` | **Yes** |
| `supportRecovery` `:479` | No |
| `cancelRecovery` `:548` | No |
| `setGuardians` `:389` | No |

Pause blocks *starting* and *finishing* a recovery but never *assembling* one, and never blocks
the (b)-keyed veto. **A pause therefore strictly favours whoever holds (b).** Crucially, today it
is **suspensive, not destructive**: quorum keeps accruing, the wall clock keeps running, and the
matured request executes intact at the first post-unpause block. This distinction is the hinge on
which the entire expiry question (H2, §11.4) turns.

### 2.5 The exit hatch, and its exact size

`withdraw` `:1046` and `queueWithdrawal` `:780` are **permissionless-caller, signature-authorized**,
so a credential holder who does *not* hold (b) can still move funds out. But `finalizeWithdrawal`
`:891` requires `pending.owner == msg.sender`, i.e. **(b)**. So when `largeTxThreshold > 0` the
exit is capped at `largeTxThreshold` **per transaction** (repeatable, nonce-incrementing), subject
to the policy engine; when it is `0` the exit is unlimited. `largeTxThreshold` is set by **(a)**,
globally — so the admin's parameter choice silently sets the escape rate of every tenant who has
lost (b).

### 2.6 Simulator parity

`StablecoinVaultSimulator`'s guardian and recovery surface is **identical to the vault at the
executable-statement level** — a comment-stripped diff of vault `:376-560` against simulator
`:345-497` yields zero executable differences, confirmed independently at the ABI level. Every
constant this design leans on exists on both sides: `RECOVERY_DELAY` (sim `:119`), `MAX_GUARDIANS`
(sim `:122`), `GOVERNANCE_GRACE_PERIOD` (sim `:140`), `_requireNotExpired` (sim `:1095-1097`),
`policyControlEpoch` (sim `:211`).

**Nothing in the repository enforces this parity.** There is no cross-contract parity test, and
`test/TreasuryQuorum.test.ts` deploys `WalletWallVault` only (`:5`, `:51`). A one-sided guardian
change passes CI today. Closing that is a locked item (§9.1 L-E).

---

## 3. Confirmed findings

Ranked by what a reasonable operator would assume. Every HIGH and MEDIUM below was **executably
proven** during the original investigation by a throwaway test harness (11/11 passing against
unmodified main) that lived in a prior session's scratchpad and was never part of this repository
or worktree — the "*Proven: §10.0 EVIDENCE N*" tags below identify which of that harness's 11
executed cases established each finding; they are historical citations to that external harness,
**not** a resolvable cross-reference within this document. This pass independently re-confirmed
every load-bearing line citation and control-flow claim these findings depend on directly against
current source (§1, §2, §4.1a) rather than relying on the harness's prior output.

### 3.1 BLOCKER — none

No finding blocks the prototype from continuing to exist as a documented, testnet-only research
artefact. The takeover path in HIGH-1 is real and complete, but it is *documented*, *delayed*,
*observable*, and mitigable operationally at zero contract cost (§9.4).

### 3.2 HIGH-1 — Tenant-EOA compromise is a complete, consent-free credential takeover

`setGuardians([attacker])` → threshold 1 → initiate + support → 7 days → `executeRecovery` (by
**any** address) → drain. Zero signatures from (c) or (d) at any step.
*Proven: §10.0 EVIDENCE 1.* This is the documented residual at `docs/Security_Assumptions.md:202-208`.

**What the removal of `updateEcdsaSigner` actually bought.** The tombstones at `:619`/`:628` were
removed because (b) could rewrite credentials with no signature from the existing keys. That is
*still true* through this path. The removal bought **latency, observability, and an escape
window**; it bought **no cryptographic consent**. HIGH-2 gives most of the latency back.

### 3.3 HIGH-2 — A matured recovery never expires

`executeRecovery`'s complete precondition set is `exists` `:504`, `block.timestamp >= executeAfter`
`:505`, and `supportCount >= required` `:507-508`. There is no upper bound anywhere, and
`supportRecovery` `:479-497` carries no timestamp check at all.
*Proven: §10.0 EVIDENCE 9 — executed successfully after five simulated years.*

This is verbatim the banking defect the contract's own NatSpec condemns at `:104-110` and enforces
via `_requireNotExpired` `:1280-1288` on all three admin propose/apply pairs. **The recovery
request is the only delayed action in the codebase that rewrites credentials with zero signatures,
and the only one with no upper bound.** So the 7-day delay is a one-time setup cost, not a standing
guarantee: exercised at the moment it matters, it gives one block of notice.

**But see §11.4 (H2) and §9.2 O-4′ — the obvious fix is refuted.** This finding is real; its
repair remains *open*, deliberately not addressed in this pass.

### 3.4 HIGH-3 — `rotateCredentials` does not touch a live recovery

`recoveryRequests` is written only at `:405`, `:459`, `:494`, `:524`, `:550`. `rotateCredentials`
spans `:645-686` and contains none of them — it cancels a pending *withdrawal* but not a pending
*recovery*. A tenant who detects a hostile recovery and rotates to rescue credentials using all
four signatures is **silently overwritten** when the hostile request matures, and the freshly
rotated holder has no veto: `cancelRecovery` is keyed on (b), never on a signature.
*Proven: §10.0 EVIDENCE 8.*

The strongest-authenticated operation in the contract cannot defuse the weakest-authenticated one.
**No behavioral repair is adopted — see §10.** Every naive fix (cancel-on-rotation, in any form)
hands a credential *thief* an unlimited denial lever over the rescue path; the correct disposition
is INTENTIONAL AUTHORITY PRECEDENCE, documented as such, with only the misleading `:671` NatSpec
corrected (§10.1).

### 3.5 HIGH-4 — One guardian can annihilate a complete honest majority, forever

The replace predicate `:443-446` ignores `supportCount`, so a **fully-supported matured** request
is exactly as overwritable as an under-supported one. At `block.timestamp == executeAfter` both
gates open simultaneously, so it is front-runnable. One member of a 32-guardian set can deny a
legitimate majority indefinitely at one transaction a week.
*Proven: §10.0 EVIDENCE 10.*

The code is strictly wider than both its comment (`:440-442`, which describes only an
under-supported request) and its only test (`test/AdvancedSecurity.test.ts:197-207`).
**A repair candidate is now adjudicated SOUND WITH CONDITIONS — see §11.1–§11.2 (H4-A).** The
naive threshold latch v1 attempted is a different, refuted candidate; H4-A survives the adversarial
scenarios that refuted it (§11.1).

### 3.6 HIGH-5 — Recovery installs credentials with no proof-of-possession and no shape check

`_validateCredentials` `:735-742` rejects only `address(0)` and zero-length bytes. A 4-byte
`newPQPublicKey` passes `:447`, is written at `:514`, and thereafter every `pqVerifier.verify`
at `:812`, `:1078`, `:723` fails — killing spending **and** voluntary rotation. The only exit is
another full recovery cycle.
*Proven: §10.0 EVIDENCE 11.*

The asymmetry is explicit in the source: `rotateCredentials` enforces new-credential PoP at
`:727-732` and its NatSpec `:638-641` says the reason is to prevent bricking a Hybrid vault
"leaving guardian recovery as the only exit". Recovery — the strictly weaker-authenticated path
to the same two slots — enforces neither. Existing coverage
(`test/AdvancedSecurity.test.ts:209-218`) tests only `address(0)` and `"0x"`, never a wrong length.

**This is reachable by an honest majority BY MISTAKE, with no revert to warn them.** v1 treated a
hardcoded ML-DSA-65 length check (L-C) as the cheapest fix and locked it; **that check is STRUCK**
(§9.3 S-3) — correct only for the mock verifier, and it would convert a per-vault, self-repairable
liveness fault into a contract-wide one under any real verifier. The verifier-agnostic replacement
— P2, delegated proof-of-possession — is proposed but **OPEN, not locked**; see §12.

### 3.7 HIGH-6 — A held tenant EOA is an unbounded veto over honest recovery

`cancelRecovery` `:548` is pause-immune, unbounded, and costs one transaction. An attacker holding
(b) kills a matured, fully-supported honest recovery every cycle, forever.
*Proven: §10.0 EVIDENCE 3 — three consecutive rounds.*

`docs/Security_Assumptions.md:220-222` frames `cancelRecovery` as "the primary protection against
a malicious guardian set". That framing is **incomplete**: it is equally the attacker's permanent
veto against honest guardians, and because recovery never moves (b), it survives the very recovery
it obstructs. This is the reason hardening `setGuardians` alone would not restore recovery liveness.

### 3.8 HIGH-7 — Recovery does not survive the compromise it was invoked to remedy

After a successful `executeRecovery`, the recovered credential cannot call `setGuardians`,
`cancelRecovery`, or `setTreasuryQuorumThreshold` — all revert, because it is not a `vaults[]` key.
The **original** (b) retains full guardian authority.
*Proven: §10.0 EVIDENCE 5.*

So an honest recovery against a compromised (b) is undone the next block. Documented only
obliquely, for a different mechanism, at `docs/Security_Assumptions.md:353-359`.

### 3.9 MEDIUM-1 — `setGuardians` can strand `treasuryQuorumThreshold`

`setTreasuryQuorumThreshold` validates `threshold <= guardianCount` at `:1319-1321`, but
`setGuardians` never re-reads it. Shrink the set below the armed threshold and
`finalizeWithdrawal`'s gate 1 (`:900-903`) becomes unsatisfiable for that `operationId`.
*Proven: §10.0 EVIDENCE 4.*

The NatSpec claim at `:1310-1311` — "the threshold must not exceed the current guardian count so
that quorum is always achievable" — is **false after a shrink**. Escapes exist
(`setTreasuryQuorumThreshold`, `cancelPendingWithdrawal`) but both are (b)-keyed, so a lost (b)
strands the reservation. Liveness only; no under-authorization is possible.

### 3.10 MEDIUM-2 — Pause hands the admin a de-facto lever over tenant recovery

(a) has no direct power over guardians (§2.2 #15), but `pause()` blocks `executeRecovery` while
leaving the (b)-keyed veto live. Today this is *suspensive*. Note for §9.2: `pause()` followed by
`renounceOwnership()` is terminal for every tenant's recovery.

### 3.11 MEDIUM-3 — Guardian support is a bearer flag, not bound to a request

`recoverySupports[owner][guardian]` does not reference the request it supports. Correctness rests
entirely on four reset loops (`:411`, `:469`, `:528`, `:555`) plus the §2.3 ordering invariant. A
grep of `test/` for `recoverySupports` returns **zero hits** — the loops are only ever observed
indirectly through `supportCount`.

### 3.12 MEDIUM-4 — `THREAT_MODEL.md` is effectively silent on guardians

The guardian trust boundary is documented only in `docs/Security_Assumptions.md` §4a. A reader
consulting the threat model does not learn that a guardian majority can seize a vault.

### 3.13 ACCEPTED LIMIT — guardian-majority takeover

`docs/Security_Assumptions.md:216-219` states it plainly: a colluding majority can seize the vault.
This is social recovery, not trustless recovery. **Not a defect.** It is, however, the reason
HIGH-5 matters: a majority can trigger a permanent brick *by accident*, which the accepted limit
does not cover.

### 3.14 ACCEPTED LIMIT — the deployed vault is not this code

`deployments/reproducibility/walletwall-vault-sepolia.json` records `0x210ceD9C…` at
`observedRuntimeBytes: 20508` against `publicHeadRuntimeBytes: 23121` — a 2,613-byte gap, status
`remediation-gated`, `reportedSourceCommitInPublicHistory: false`. **No finding here describes the
live instance.** See §13.

### 3.15 NOT A DEFECT — the absence of an epoch bump on `setGuardians`

Bumping `policyControlEpoch` in `setGuardians` would let the guardian-set mutator — identity (b),
the least-trusted key — instantly and freely void every in-flight intent signed by (c)/(d). That
is a category error (the authority that changed is (e), not (c)/(d)) and a strictly worse form of
what `:193-198` already forbids for `initiateRecovery`. **Leave it as it is.**

---


---

## 4. Target invariant — CORRECTED

### 4.0 What the first pass got wrong

The v1 report concluded "the target property is not achievable" and froze `setGuardians` on the
strength of four proofs. **Three of the four do not bind on the property actually at issue, and the
report committed a quantifier error.**

| v1 proof | What it actually establishes | Where it binds |
|---|---|---|
| **P1** bootstrap has no other possible authorizer | True — at `n == 0` the candidate authorizers are exhausted and only (b) remains | **S-A only** |
| **P2** repair cannot be carved out | A **liveness cost** in a compound failure, not an impossibility | S-C only |
| **P3** circularity | Refutes credential **consent over recovery**; does not touch a credential **veto** over administration | Mis-scoped |
| **P4** no terminal state | True, and it is why the *stronger* invariant is hard; does not bear on **bounded delays** | Not on this property |

The report then generalised all four to the established state (S-B). That is the four-context
collapse: it proves ∃ a state where the property fails and concludes ∀ states.

Worse, the generalisation is not merely unproven at `n >= 1` — **it is false there**. P1 excludes
principal (e) because the guardian set is empty. Verified this pass: `:421` is the sole write to
`vaultGuardians`, `:391` unconditionally forbids an empty set, and there is **no `delete`, no
`.pop()`, no `.length =`** anywhere in either contract. So `n >= 1` is **absorbing per address**:
the single fact that makes (e) unavailable at bootstrap is the one fact that provably never recurs.
**(e) is a permanently available principal in every established state.**

Four further v1 conclusions are struck; see §9.3.

### 4.1 The refined invariant — ACHIEVABLE IN PRINCIPLE

> **I-REFINED.** Once a guardian set has been ESTABLISHED (`n >= 1`), no sequence of transactions
> authorized solely by (b) can cause an address outside the established set to become a recoverer,
> nor lower the number of supports required.

**Verdict: ACHIEVABLE — the v1 refutation is withdrawn.** The exhaustive-principal argument, re-run
*in the established state* rather than at bootstrap:

- **(a) contract admin — REJECTED.** Creates per-tenant admin power that does not exist today
  (§2.2 #15) and is global in blast radius. Independently rejected by the sibling lane's own
  precedent (`docs/Policy_Control_Authority_Design.md:256-258`).
- **(c)/(d) credentials — REJECTED, but not for v1's reason.** v1's circularity argument is
  *wrong*: `initiateRecovery` `:429-456`, `supportRecovery` `:479-497` and `executeRecovery`
  `:502-542` contain **no read of `vault.ecdsaSigner` or `vault.pqPublicKey`**, so recovery is
  credential-free and the credentials-lost/quorum-intact case has no circularity at all. The
  correct refutation is `rotateCredentials` `:645-651`: it is permissionless-caller, takes
  `vaultOwner` as a *parameter*, and is authorized purely by current credentials plus a new-key
  PoP. Key theft is **copy** theft, so a thief rotates to make their holding **exclusive** and then
  holds guardian administration outright, with no honest counter-move — `:391` forbids the empty
  set and there is no transition back to unguarded. That makes a credential thief *sufficient*,
  which is strictly worse than the defect being repaired, and it removes the remedy `:615`
  designates for compromised keys. Aggravating: there is no ERC-1271/SignatureChecker anywhere in
  `contracts/`, so `ecdsaSigner` is irreducibly one secp256k1 key, whereas (b) is `msg.sender`-keyed
  with no code check and **may be a Safe**. Credential authority moves administration from the
  identity that *can* be hardened to the one that cannot.
- **(e) existing guardians — the unique survivor.** Available in every established state, by the
  absorbing-state fact above.

So the invariant is reachable, and only via (e). **A bare (b)-keyed timelock is not a mechanism for
it** — "(b) alone is sufficient, after D days" still fails the invariant as written. This also
disposes of the cheapest candidate surfaced this pass (a per-vault recovery-quorum *floor*,
~570 B): every gate on it is (b)-keyed, so it **prices** the defect without closing it.

### 4.1a I-GUARDIAN-INDEPENDENCE — the sharper property, tested per principal

"(e) is the unique survivor" (§4.1) is a claim about the *design space of candidate future
mechanisms*, not a claim about who holds this authority today. Stated loosely it invites a
misreading: that (c)/(d) are excluded merely because they are "unsuitable," without saying
unsuitable *for what threat*. This section states the threat precisely and re-runs the survivor
argument against it, per the brief's instruction not to use "unique survivor" language until the
proof actually quantifies over the full principal set.

> **I-GUARDIAN-INDEPENDENCE.** Once a guardian set has been established, authority to replace it
> must remain independent of (i) compromise of `vaultOwner` (b) alone, and (ii) compromise of the
> spending credentials (c)/(d) alone — because guardian recovery exists specifically to remediate
> loss or compromise of (c)/(d), so a repair mechanism that (c)/(d) could also control would let a
> credential thief disable the remedy for their own theft, exactly as §10 (H3) shows for
> `rotateCredentials`.

**Verdict — two separate claims. Current-state conformance and design feasibility are different
questions and must not be collapsed into one mixed verdict:**

> **CURRENT IMPLEMENTATION: VIOLATES I-GUARDIAN-INDEPENDENCE.**
>
> **TARGET DESIGN FEASIBILITY: ACHIEVABLE IN PRINCIPLE. CONCRETE MECHANISM NOT YET LOCKED.**

Not a new achievability result — see the Conclusion below. Two questions, kept separate:

**(1) Does today's mechanism satisfy it?** No. `vaultGuardians[o]` has exactly one write site
(`:421`), gated by exactly one condition (`:390`, `msg.sender == o`). (b) alone is fully
sufficient — this is HIGH-1 restated under the sharper name, not a new finding. (c)/(d) are never
read by that gate, so the mechanism is *vacuously* independent of (c)/(d) compromise — independence
by irrelevance, not by design strength, and not something to credit the design for.

**(2) Among candidate authorities for a future mechanism, which can satisfy it?** Re-run
per-principal, `principal compromised alone → can it replace the established guardian set?`:

| Principal | Alone, today | Why |
|---|---|---|
| **(b) `vaultOwner`** | **YES** | The entire gate. HIGH-1. |
| **(c) current ECDSA signer** | No | Never read by `:389-423`. Orthogonal secret from (b) — `ecdsaSigner` is a *stored* value rotatable only via `rotateCredentials`, not the `msg.sender` key. |
| **(d) current PQ credential** | No | Same — never read, orthogonal secret. |
| **(e) current guardians (incl. a full malicious set)** | No | Counter-intuitive but load-bearing: `initiateRecovery`/`supportRecovery`/`executeRecovery` never call `setGuardians` and never write `vaultGuardians`. A guardian majority can steal (c)/(d) (§3.13, accepted) but cannot touch its **own** roster. Guardians have recovery power with zero self-governance. |
| **(a) global contract admin** | No | Zero write path (§2.2 #15, re-verified this pass: `pause`/`unpause` and the three propose/apply pairs never touch `vaultGuardians` or `recoveryRequests`). Holds only a *suspensive* cross-tenant lever via `pause()` — denial, not replacement. |
| **`PolicyControlBridge`** | No | Verified this pass by direct source read: its only reference to vault state is a `view` call to `policyControlEpoch(owner)` (`PolicyControlBridge.sol:733`); zero references to `vaultGuardians`, `recoveryRequests`, or any guardian-mutating selector anywhere in the file. Structurally cannot reach the surface, not merely unauthorized to. |
| **Policy engine (any `IPolicyEngine`)** | No | Stronger than "unauthorized": **unreachable**. §2.2's external-call census shows zero calls out of the vault from anywhere in `:389-560`, re-confirmed this pass. The policy engine has no invocation point on this path from which to act. |
| **`PolicyControlBridge`'s `EMERGENCY_PAUSER`** | No | A separate immutable address on a separate contract, gating only that contract's own pause flag (`PolicyControlBridge.sol:307-317`). `WalletWallVault`'s `Pausable` state is a distinct instance gated by the vault's own `onlyOwner` (`:1378-1385`, principal (a)). The bridge pauser cannot pause the vault's recovery path either. |
| **A proposed external guardian controller (C5 PUSH, §8)** | **UNRESOLVED** | Not a restatement of (e) — a *new* principal whose own provenance rule is undesigned. §9.2 O-1′'s "canonical-controller provenance" item is exactly this question, now re-scoped: the controller must be shown NOT to reduce to (b) or (c)/(d) before it can be credited. |

**The combined scenario** (`vaultOwner compromised + spending credentials compromised → can the
attacker replace guardian authority without guardian participation?`) **collapses to the same
answer as (b) alone: YES.** Adding (c)/(d) compromise to (b) compromise contributes nothing extra
— the gate never reads (c)/(d), so it was never a second factor to defeat.

**Conclusion.** (e) is the unique survivor **among already-established principals** — this is
exactly I-REFINED's own claim (§4.1), not a new achievability result. The genuine addition here is
negative and free: **no candidate examined (C1-C5) ever gave (c)/(d) a pathway to `vaultGuardians`
in the first place**, so every (e)-based mechanism that satisfies I-REFINED satisfies
I-GUARDIAN-INDEPENDENCE's clause (ii) as a byproduct, at zero extra design cost. Clause (i) is
exactly what §4.2's F-1…F-4 and O-1′/O-2′/O-3′ already have to close for I-REFINED. **This pass
adds no new backlog item** — it raises the bar the existing backlog must clear, and gives O-1′ a
sharper acceptance test for the controller's provenance rule once one is proposed.

### 4.2 But every concrete mechanism proposed so far is REFUTED

Achievable-in-principle is not buildable-today. The asymmetric in-vault mechanism (cheap
threshold-preserving contraction; delayed, guardian-vetoable expansion) was attacked on three
lenses and failed all three on grounds **independent of bytecode**:

- **F-1 Duplicate collapse (FATAL).** The cheap predicate `N ⊆ C ∧ t(|N|) == t(|C|)` is stated over
  a **multiset**. From `[g1..g5]`, `setGuardians([g1,g1,g1,g1,g1])` satisfies subset and preserves
  `t == 3`, while `:507` derives `required` from array **length** and `:491` caps each distinct
  address at one support — so distinct recoverers *and* distinct vetoers collapse to one. The
  proposal's own induction is satisfied while the property it protects is destroyed. **The
  invariant is stated over the wrong object.** Note the consequence: this design would promote the
  duplicate guard `:398-400` from a liveness check to an **authorization** check.
- **F-2 Even-`n` contraction is empty (FATAL).** With `t(k) = k/2 + 1`, for every even `n = 2m` all
  proper subsets have `t <= m` while `t(n) = m + 1`. Enumerated over `n ∈ 1..32`: a cheap
  contraction exists **only at odd `n`** — empty at 16 of 32 legal sizes including the canonical
  `n = 4`. So at even `n` *every* removal falls to the vetoable path, and the guardian being evicted
  sits inside the constituency vetoing its own eviction — reinstating exactly the self-veto the
  design claimed to escape. Emergency eviction goes from 0 days to 7.
- **F-3 The veto flag cannot be epoch-invalidated (FATAL).** `mapping(address => mapping(address =>
  bool))` keyed `(owner, guardian)` has no generation dimension, so a separate epoch counter
  invalidates nothing — the contract's own identically-shaped `recoverySupports` is cleared by
  **four** explicit O(n) loops (`:409-412`, `:467-470`, `:526-529`, `:553-556`) for precisely this
  reason. As specified a guardian may veto once *ever*, so (b) buys out the entire constituency with
  one throwaway proposal and re-proposes unvetoed.
- **F-4 Apply-window liveness (MAJOR).** A 7-day delay under the existing 14-day
  `GOVERNANCE_GRACE_PERIOD` gives a hard `[T+7d, T+21d]` window, and a (b)-keyed `apply` means a
  tenant Safe convening monthly can **never** complete any guardian change — an operation that is
  unconditionally one transaction today.
- **F-5 Bytecode unresolved.** The adjudication priced it at ~675 B/contract; independent
  re-derivation from the same source map returned ~1,650 B central. A 2.4× disagreement against
  **1,455 B** of vault headroom cannot be resolved without compiling.

F-1 through F-4 are all repairable in principle (strict ascending-address ordering yields
distinctness plus an O(n) subset merge; a generation-keyed veto; a permissionless `apply`). **None
has been re-adjudicated after repair.** That work is not done, and this document must not pretend
it is.

### 4.3 The stronger invariant

> **I-STRONGER.** Successful recovery must leave the recovered vault no more dependent on a
> previously compromised (b) than it was before recovery.

**The literal wording is vacuous and must not be adopted.** "No *more* dependent than before" is a
monotonicity claim across the `executeRecovery` transition, and the (b)-power set is **identical**
on both sides — `:502-542` touches neither the `vaults[]` key nor any (b)-keyed gate. So the
invariant as written is **satisfied today**, and H7 does not falsify it.

The operative form is: *after recovery, the principal recovery installs must hold at least the
administration authority the pre-recovery (b) holds.* That fails today — (b) holds five gates
(`:390`, `:549`, `:891`, `:1022`, `:1315`); recovery installs a principal holding a **disjoint**
set (`withdraw`, `queueWithdrawal`, `rotateCredentials`) that can reach none of them.

**Does it require changing the permanent vault identity model? NO — and this is the load-bearing
answer to the brief's explicit question.** The mapping key's immovability was never the obstacle.
The obstacle is that every (b)-keyed gate **fuses two roles into one value**: `msg.sender` is
simultaneously the storage lookup key *and* the authorization proof. Unfuse them —
`msg.sender == _admin(vaultOwner)` where `_admin(o)` defaults to `o` — and authority becomes
rotatable while the key stays frozen forever. Zero mappings re-keyed, zero migration, zero
orphaning, zero external-consumer impact.

**Re-keying `vaults[]` (the obvious alternative) is affirmatively unsound, not merely expensive.**
`DailySpendLimitPolicy._subjectKey = keccak256(abi.encode(consumer, owner, asset))` is `internal
pure` with **no re-key entry point**, and every `bridge*` setter accepts only the canonical bridge —
the vault cannot migrate it. After a re-key the vault addresses an **unarmed** bucket where
`check()` returns `(true, "")` on `limit == 0` *before* the admitter gate: **the tenant's daily
spend limit is silently and completely bypassed**, and `controllerInitialized == false` re-enables
Path-1 owner-direct configuration. A mechanism whose purpose is to defend against a compromised (b),
whose effect is to disarm the tenant's spend limit, is disqualified.

**Nonetheless I-STRONGER is NOT recommended, for two reasons that survive the cheap mechanism:**

1. **It does not compile.** `initiateRecovery` already emits `DUP15` at `:459` — one slot below the
   `DUP16` ceiling under legacy (non-viaIR) codegen — and the mechanism adds two stack slots at
   exactly that statement. Measured DUP/SWAP reach: `setGuardians` 6, `executeRecovery` 12,
   `initiateRecovery` **15**, `_authorizeRotation` 16, `withdraw` 16. Any function at 15–16 is
   frozen against new parameters or struct members.
2. **It makes H1 terminal.** Today an H1 seizure leaves the (b) gates in place, so an honest tenant
   who *also* holds (b) can re-arm guardians and recover back. Rotating the administrative root to
   an address the honest tenant does not hold breaks that loop permanently in the attacker's favour
   — converting a contested, reversible seizure into a final one. It also widens the accepted limit
   at `docs/Security_Assumptions.md:216-219`: a guardian majority would gain the five (b) gates in
   addition to the credentials.

---

## 5–7. Trust table, state machine, transition matrix

Carried forward from v1 unchanged — they describe CURRENT behaviour, which this pass confirmed.
Two facts are now VERIFIED rather than asserted:

- **`S1 → S2` is absorbing per address** (`:421` sole write, `:391` forbids empty, no `delete`,
  `.pop()` or `.length =` anywhere in either contract). This is what makes (e) a permanently
  available principal in every established state, and it is the fact §4.0 turns on.
- **The recovery quorum is derived, never stored** — `required = (length/2)+1` read live at exactly
  one site `:507`, no threshold field on `RecoveryRequest` `:130-136`, no floor anywhere. So
  **lowering the quorum and replacing the set are the same operation**, which is why the current
  design must price both at the weakest authority either requires.

### 5. Trust table

| Actor | CAN | CANNOT |
|---|---|---|
| **(a) Contract admin** | `pause()` — block `initiateRecovery` and `executeRecovery`; swap the PQ verifier and policy engine (timelocked, expiring); set `largeTxThreshold`, which caps every lost-(b) tenant's exit rate; `renounceOwnership()` — with a live pause, terminal for all recovery | Call `setGuardians`, `cancelRecovery`, or `executeRecovery` for any tenant; read or write any tenant's guardian set; cancel a tenant's recovery |
| **(b) Tenant `vaultOwner`** | **Everything that matters.** Replace the guardian set instantly, unconsented, pause-immune, to any size ≥ 1; cancel any recovery, unboundedly; set the treasury quorum; finalize/cancel queued withdrawals | Move funds without (c)/(d); initiate or support a recovery (barred from its own set by `:397`) |
| **(c) `ecdsaSigner` + (d) `pqPublicKey`** | Authorize withdrawals and queued withdrawals (permissionless relay); rotate themselves via `rotateCredentials` | **Touch the guardian set at all.** Cancel, delay, or void a hostile recovery. Reconfigure anything after recovery (HIGH-7) |
| **(e) Individual guardian** | Initiate a recovery; support once; **replace any request while it is not live** (`:443-446`) — including a fully-supported matured one (HIGH-4); approve a treasury withdrawal | Execute alone below threshold; change the guardian set; cancel a request |
| **Guardian majority** | **Seize the vault**: rewrite (c) and (d) to attacker-chosen values after 7 days (accepted limit, §3.13); brick the vault by mistake via HIGH-5 | Move funds directly; survive a (b)-holder's veto or a `setGuardians` call |
| **Policy engine** | Block withdrawals and queued-withdrawal finalization | **Affect guardians or recovery in any way** — zero external calls on that path (§2.2) |
| **`PolicyControlBridge` / its pauser** | Relay credential-signed policy intents; freeze the policy control plane one-way | Touch guardians or recovery |
| **A proposed guardian-control contract (C5 PUSH)** | — | Does not exist yet, so no CAN/CANNOT applies. **Not "not recommended"** — v1's REJ-5 argument for that is itself struck (§9.3 S-2). Current status: re-opened, **the live path** for a future mechanism (§8 C5, §9.2 O-1′); its own provenance rule is undesigned and must clear I-GUARDIAN-INDEPENDENCE (§4.1a) before it can be credited |

**The single most important row is (c)/(d) CANNOT.** A credential holder — including the
legitimate owner — has *no* guardian authority and *no* recovery veto. That is the asymmetry this
lane investigated, and §4.1 explains why it cannot simply be inverted.

---

### 6. State machine

Two machines, coupled only through `setGuardians`.

### 6.1 Machine A — guardian constituency

```
S0 UNREGISTERED          vaults[o].exists == false
      |
      |  createVault                                    [ (b), whenNotPaused ]
      v
S1 UNGUARDED             vaultGuardians[o].length == 0        <-- BIRTH STATE OF EVERY VAULT
      |                  recovery impossible: initiateRecovery reverts InvalidGuardianSet :438
      |                  setTreasuryQuorumThreshold(>0) reverts InvalidGuardianSet :1318
      |
      |  setGuardians(n >= 1)                           [ (b), immediate, pause-immune ]
      v
S2 GUARDED(n)            1 <= n <= 32                         <-- ABSORBING: no path back to S1
      ^                  threshold = (n / 2) + 1, read live at :507
      |
      +-- setGuardians(m) --+   full-set replacement; ALWAYS deletes any live request (:404-407)
                                and clears the OLD set's supports (:409-412) BEFORE the write (:421)
```

`S1 -> S2` is one-way: `:391` forbids an empty set and there is no delete or pop anywhere. **A
tenant can never opt out of social recovery once armed**, and the smallest legal set (n = 1) is
also the maximally dangerous one (threshold 1).

### 6.2 Machine B — recovery request

```
R0 NONE                  recoveryRequests[o].exists == false
      |
      |  initiateRecovery                    [ (e) member, whenNotPaused, credentials NOT validated
      v                                        beyond non-emptiness :447 -- see HIGH-5 ]
R1 LIVE                  block.timestamp < executeAfter          executeAfter = t + 7 days
      |                  NOT replaceable (:444).  supportRecovery accrues (no modifier, no clock).
      |
      |  time
      v
R2 MATURED               block.timestamp >= executeAfter
      |                  replaceable by ANY single guardian (:443-446 ignores supportCount)
      |                  executable IFF supportCount >= required (:507)
      |                  NO UPPER BOUND -- persists forever (HIGH-2)
      |
      +-- executeRecovery --> R0, credentials rewritten   [ PERMISSIONLESS caller, whenNotPaused ]
      +-- initiateRecovery --> R1, supportCount := 0, all flags cleared   [ any (e) member ]
      +-- cancelRecovery   --> R0                          [ (b) only, pause-immune, UNBOUNDED ]
      +-- setGuardians     --> R0                          [ (b) only, pause-immune ]
```

At exactly `block.timestamp == executeAfter` **both** the replace gate (`:444`) and the execute
gate (`:505`) open, so R2's two outgoing edges are a same-block race (HIGH-4).

---

### 7. Transition matrix

| Actor | Preconditions | Transition | Delay | Expiry | Authorization | Stale authority | Result | Failure mode |
|---|---|---|---|---|---|---|---|---|
| (b) | `vaults[o].exists` | `createVault` | none | n/a | `msg.sender` | n/a | S0→S1 | `whenNotPaused`; once-only `:576` |
| (b) | S1 or S2 | `setGuardians` | **none** | **none** | `msg.sender` only | **None — no epoch, no nonce, no signature** | S1/S2→S2, **R\*→R0** | Reverts on empty / >32 / zero / self / duplicate. **Pause-immune** |
| (e) | S2, R0 or R2 | `initiateRecovery` | sets +7d | **none** | Membership, checked **last** | Request frozen at initiation; `vault.mode` immutable so this is sound | R\*→R1 | `whenNotPaused`. Accepts malformed PQ key (HIGH-5) |
| (e) | R1 or R2 | `supportRecovery` | none | **none — no clock at all** | Membership + not-already | Flag does **not** bind the request (MEDIUM-3) | R→R | **Pause-immune** |
| **anyone** | R2, `supportCount >= required` | `executeRecovery` | — | **none (HIGH-2)** | **The supports alone** | Threshold read live `:507`; sound only via §2.3 ordering | R2→R0, (c)/(d) rewritten | `whenNotPaused`, `nonReentrant`. **Zero external calls** |
| (b) | R1 or R2 | `cancelRecovery` | none | none | `msg.sender` only | n/a | R\*→R0 | **Pause-immune, unbounded (HIGH-6)** |
| (c)+(d) | vault exists | `rotateCredentials` | none | `deadline` | 4 sigs in Hybrid | Bumps `policyControlEpoch`; **does not touch R** (HIGH-3) | (c)/(d) rewritten | `whenNotPaused`; needs `pqVerifier` |
| (b) | S2 | `setTreasuryQuorumThreshold` | none | none | `msg.sender` | Validated at set time only; **not re-validated on shrink** (MEDIUM-1) | quorum set | — |
| (a) | — | `pause` / `unpause` | none | none | `onlyOwner` | n/a | blocks initiate+execute | Suspensive today, **not** destructive |

---


---

## 8. Candidate comparison — CORRECTED

| | v1 verdict | **Corrected verdict** | Why the change |
|---|---|---|---|
| **C1 Timelock** | REJECT | **REJECT — sustained** | The usable-`D` interval is still empty, and a (b)-keyed delay cannot satisfy I-REFINED by construction |
| **C2 Credential authorization** | REJECT (circular) | **REJECT — different reason** | Circularity is *wrong*: recovery reads no credential field. The real refutation is `rotateCredentials` exclusivity: a copy-thief makes their holding exclusive and takes administration outright |
| **C3 Guardian consent** | REJECT (n == 0) | **RE-OPENED; survives inverted, then refuted on mechanism** | `n == 0` is a bootstrap state, and it never recurs. Consent on **removals** is correctly rejected (self-veto); "additions cheaper" is *fatally* wrong — a compromised (b) reaches quorum by **DILUTION** (`n=3` + 4 attacker addresses ⇒ `t(7)=4`). The surviving shape is the **mirror image**: contract freely, gate expansion. Then refuted by F-1…F-4 |
| **C4 Delayed + vetoable** | REJECT | **PARTIALLY WITHDRAWN** | "The veto cannot be given to anyone" was too strong. (e) is a valid veto-holder in every established state. It fails on mechanism (F-1…F-4), not on principle |
| **C5 External PUSH controller** | REJECT (credential wrapper) | **RE-OPENED — v1 was wrong on its stated ground** | In a PUSH architecture the controller is the **sole writer** of `vaultGuardians`, so it authenticates against **its own authoritative state**, not "what the vault exposes". Housing is genuinely orthogonal to authority model — it can host C3's versioned consent, not only C2's credentials. **This is now the live path**, chiefly because it relocates the EIP-170 constraint that blocks every in-vault form |
| **C6 No change** | ADOPT result, REJECT scope | **Result WITHDRAWN, scope sustained** | Its achievability half rested on v1's P1–P4 generalisation, which is struck. Its scope half stands: "no change" leaves H2–H5 open and is not the honest minimum |

---

## 9. Design points — CORRECTED

### 9.1 LOCKED

| # | Point | Change from v1 |
|---|---|---|
| **L-A′** | **`setGuardians`'s predicate is frozen FOR NOW — as a consequence of EIP-170 and of the fact that no proposed mechanism has survived refutation, NOT because the property is unachievable.** | **Materially weakened.** v1 froze it as a positive architectural decision. It is now a *provisional* engineering constraint with a named path out (C5 PUSH) |
| **L-B′** | Amend `docs/Security_Assumptions.md` §4/§4a: (b) is the vault's root authority **today**, and state that the post-bootstrap invariant is achievable-in-principle via existing-guardian participation but is currently blocked on EIP-170 and on unrepaired mechanism defects | Softened from "root authority by construction" |
| **L-D** | Close MEDIUM-1 (treasury-quorum stranding on shrink), or correct the false NatSpec at `:1310-1311` | Unchanged |
| **L-E** | Simulator parity mandatory; add the cross-contract guardian-parity test that does not exist today | Unchanged. Sharpened: the simulator's reproducibility record is **live-green** with a committed 149 KB evidence bundle, so editing it breaks an independently-confirmed third-party claim — the more expensive half of mirroring |
| **L-F′** | Pin the **semantic** property, not the statement order: *a recovery authorized under guardian-set generation N can never execute under generation N+1*. Determine during implementation whether the existing unconditional delete already expresses it or whether a generation counter expresses it structurally | **Replaces** v1's L-F(i), which fossilised source layout |
| **L-G** | No new `whenNotPaused` on any guardian/recovery entry point; no wall-clock ceiling a pause could run out | Unchanged |
| **L-H** | Do not bump `policyControlEpoch` in `setGuardians` | Unchanged |
| **L-I** | **AST assertion retained only for the structural property**: recovery execution performs no external authorization callback. Anchor it to a **function-name set**, never a line range | Narrowed per the brief |
| **L-J** *(new, v3)* | **H4-A's majority-preserving replacement semantic** (§11.1-11.2): once `supportCount >= required`, a matured request cannot be replaced by `initiateRecovery` while the guardian set that approved it is unchanged. SOUND WITH CONDITIONS; measured **+64 bytes**; zero regressions against the existing 19-test suite | New this pass |
| **L-K** *(new, v3)* | **H3's `:671` NatSpec is corrected, not the code** (§10.1): the exact replacement text is specified; behavior (no cancellation on rotation) is unchanged and locked as intentional | New this pass |

### 9.2 OPEN

| # | Question | Status |
|---|---|---|
| **O-1′** | **I-REFINED via C5 PUSH housing.** The live path. Needs: canonical-controller provenance; whether controller failure bricks only administration (it should — recovery uses the existing set and makes zero external calls); whether the controller needs a stable vault identity independent of (b); exact vault-side bytes. **v3 addendum:** the provenance question must now also clear I-GUARDIAN-INDEPENDENCE (§4.1a) — show the controller's own authorization does not reduce to (b) or (c)/(d) | **Promoted to primary open work** |
| **O-2′** | The four mechanism defects F-1…F-4, each repairable in principle, **none re-adjudicated after repair** | Blocks any in-vault form |
| **O-3′** | Bytecode: 675 B vs 1,650 B for the asymmetric contraction mechanism, unresolved without a compile. **Unaffected by H4-A**, which is a separate, now-measured (+64 B) candidate — see §13.1 | Blocks sizing decisions for the asymmetric mechanism specifically |
| **O-4′** *(corrected, v3 — was O-4)* | **H2 only.** A sufficiently supported matured recovery has no execution expiry. Request identity is **not** a fix for this (§11.4) and is not pursued (§11.3). Still open; no candidate proposed or costed in this pass | Narrowed. Does not depend on, and is not resolved by, §11's H4-A adoption |

### 9.3 STRUCK from v1

| # | v1 claim | Why struck |
|---|---|---|
| **S-1** | "The target property is not achievable" | Quantifier error; false at `n >= 1` |
| **S-2** | REJ-5, external controller is "C2 wearing a new address" | Wrong on its stated ground — the controller is the sole writer and authenticates against its own state |
| **S-3** | L-C, hardcode an ML-DSA-65 length check | Correct only for the **mock**; defeated by 1952 random bytes so it constrains no adversary; breaks `IPQCVerifier` genericity; under the documented SLH-DSA/precompile paths it converts a per-vault, 7-day, self-repairable liveness fault into a **contract-wide** one |
| **S-4** | "H2 and H4 cannot be fixed" | v1 refuted one candidate per defect and generalised. The **request-identity axis was never evaluated** — v1's whole candidate table is about `setGuardians` authorization, not about the request object its own §9 named as the correct target |
| **S-5** | L-F(i), freeze statement ordering as the security contract | Replaced by L-F′'s semantic form |
| **S-6** | "The veto cannot be given to anyone" (C4) | (e) is a valid veto-holder in every established state |
| **S-7** *(new, v3)* | v2 §11: "H2 and H4 are both fixable, by the same repair" | Wrong framing, struck this pass. H4 has a cheap standalone fix (H4-A, §11.1) needing no request-identity change. Request identity does not fix H2 either — it changes *who* can be erased, not *how long* a matured request survives unexecuted (§11.4). The two were never one problem |

### 9.4 Operational mitigation *(referenced from §2.1 and §3.1; written out here, v3 — this
content was previously cited but never given its own section)*

Nothing restricts (b) to an externally-owned account (§2.1) — the only `code.length` checks in the
contract gate the policy engine and the PQ verifier, never `vaultOwner`. A tenant can therefore make
**(b) a multisig Safe instead of a single EOA today, at zero contract cost**: no code change, no
redeploy, no `receive()` needed (refunds from `cancelRecovery`/`executeRecovery`/`rotateCredentials`
are ledger credits to `vault.balance`, not ETH transfers). This directly raises the bar for HIGH-1
(§3.2) — full credential takeover via `setGuardians([attacker])` now requires compromising the
Safe's own threshold, not one key — which is why §3.1 rates HIGH-1 real-but-not-blocking: it is
*documented*, *delayed* (7 days), *observable* (on-chain events at every step), and *mitigable
operationally* by this deployment choice alone, before any of §4's harder design work lands.

---

## 10. H3 verdict — EXPLICIT

> **VERDICT: NO. A successful `rotateCredentials` must NOT cancel a pending recovery request or
> clear its supports.**

The security direction is real and proven (EVIDENCE 8): a four-signature operation is defeated by a
zero-signature one. And `:671` does state "A rotation must invalidate every in-flight
authorization" while enumerating only the nonce bump and the queued withdrawal.

**But the liveness reasoning the brief proposes does not hold.** The brief's chain is: rotation
requires the current credentials; if they are lost, rotation cannot succeed; therefore a successful
rotation proves they were not lost; therefore cancellation is strictly safe. The step that fails is
the last: **"not lost" is not "not compromised", and key theft is copy theft.** A thief holding
copied credentials *can* rotate, so cancellation hands them a permanent, **pre-signable and
front-runnable** veto over the exact mechanism `:615` designates as the remedy for *compromised*
keys. On the currently deployed configuration this is worse than it sounds: with a mock PQ verifier
the effective barrier is a single stolen classical ECDSA key.

Rejected variants: **V1** delete-on-rotation, **V2** epoch/generation-binding the request
(materially identical in effect), **V4** cancel-only-below-threshold. All three hand the thief the
veto.

**H3 is therefore an accepted asymmetry, documented — not a fix.** Two consequences the brief asked
about:

- **Independence:** H3 *is* cleanly separable from H2/H4 — it touches `rotateCredentials`, they
  touch the request object. But the correct disposition is "no change", so separability is moot.
- **Simulator parity:** exact (`StablecoinVaultSimulator.sol:487` and the statement-identical
  rotation region), so a hypothetical change would land twice.

The residual — a stale recovery can overwrite a fresh rotation — must be stated plainly in
`docs/Security_Assumptions.md` rather than closed.

### 10.1 H3 scenarios — explicit, source-checked against `:645-733`

| # | Scenario | Verdict |
|---|---|---|
| **H3-S1** honest routine rotation: recovery pending, legitimate owner still holds credentials, legitimate `rotateCredentials` | Recovery **remains capable of later executing** — `rotateCredentials` (`:645-686`) contains no reference to `recoveryRequests`, confirmed by direct read this pass. Correct: a routine rotation is not evidence the recovery was spurious. **UI implication:** an operator dashboard must surface "a guardian recovery is pending" as its own, separately-acknowledged banner during rotation — a rotating owner who does not know a recovery is in flight has no reason to also call `cancelRecovery`, and today nothing prompts them to. |
| **H3-S2** copied-credential attack: thief holds copied credentials, honest guardian recovery pending, attacker calls `rotateCredentials` | Does **not** cancel — proven by the same fact as S1. This is what makes cancel-on-rotation the wrong fix: it would hand the thief a pre-signable veto (they can rotate the instant recovery matures, using the same copied key that got them here). |
| **H3-S3** rotation before recovery, support after | Sound. Support (`:479-497`) checks only current guardian membership and an unset flag; it does not read `vault.ecdsaSigner`/`pqPublicKey` at all. A rotation between initiation and support changes neither the request's target credentials nor any guardian's ability to support it. |
| **H3-S4** rotation after recovery reaches quorum | Should **not** supersede — and does not: nothing in `rotateCredentials` reads `recoveryRequests` or `supportCount`. A quorum-approved request is exactly as untouched by rotation as an under-supported one; H3's verdict does not depend on how far along the request is. |
| **H3-S5** repeated rotations | Cannot change a request's meaning. `RecoveryRequest.newEcdsaSigner`/`newPQPublicKey` are copied into request storage once, at `initiateRecovery` (`:459-465`), by value. No function ever rewrites a `recoveryRequests[o]` field in place except `executeRecovery` deleting it and `initiateRecovery` replacing it wholesale — both require guardian action, never rotation. |
| **H3-S6** recovered target credentials fixed | Confirmed — `RecoveryRequest.newEcdsaSigner`/`newPQPublicKey` (`:131-132`) are written only at `:460-461` (initiation) and read-only thereafter until `:511-514` (execution, which copies them verbatim into `vault.ecdsaSigner`/`pqPublicKey`). `rotateCredentials` cannot reach this struct at all — same fact as S1/S4. |

**Required H3 verdict: INTENTIONAL AUTHORITY PRECEDENCE, but MISDOCUMENTED.** The behavior (no
cancellation) is correct and should not change. The `:671` comment is the defect — it overclaims a
property the code deliberately does not have, and would mislead the next editor into "fixing" the
overclaim by adding the cancellation this pass (and v2 before it) refutes.

**Exact replacement text for `:671-674`:**

> ```solidity
> // A rotation must invalidate every in-flight authorization THAT THE OLD CREDENTIALS SIGNED.
> // The nonce bump above voids signed immediate withdrawals, but a queued large withdrawal is
> // tracked separately and finalizes without re-checking the nonce — so it is cancelled and its
> // reservation refunded here, mirroring {executeRecovery}.
> //
> // Deliberately excluded: a pending guardian recovery request ({recoveryRequests}) is NOT
> // touched here. Guardian recovery is not an authorization derived from (c)/(d) credential
> // authority — it is the documented remedy for LOST OR COMPROMISED credentials, and a
> // successful rotation does not prove the credentials were not compromised: key theft is copy
> // theft, so a thief holding a copied key can rotate too. Cancelling recovery on rotation would
> // hand that thief a standing, pre-signable, front-runnable veto over the exact mechanism this
> // contract designates as the remedy for their own theft. See
> // docs/Guardian_Authority_Design.md §10 for the full adversarial analysis.
> ```

**Regression tests to pin this precedence (none exist in the repo today — a `grep` of `test/` for
`rotateCredentials` calls alongside a live `recoveryRequests` entry returns zero hits):**

1. Initiate + reach quorum on a recovery; call `rotateCredentials` with valid current+new
   proof-of-possession; assert `recoveryRequests(owner).exists == true` and every field unchanged.
2. Same, then advance past `executeAfter` and call `executeRecovery`; assert it **succeeds** and
   installs the request's original target credentials, not the rotated ones.
3. A structural (AST or selector-census) assertion that `rotateCredentials` and `_authorizeRotation`
   contain no call to any function that writes `recoveryRequests` — same style as L-I, so a future
   edit that adds a cancellation cannot pass silently.

---

## 11. H4 disposition — CORRECTED, and separated from H2

**§11 as v2 wrote it is struck (S-7, §9.3): "H2 and H4 are both fixable, by the same repair" is the
wrong framing.** v2 refuted v1's unrepairability claim (correctly) then jumped straight to request
IDs as "the most promising direction" without first testing whether H4 has a cheap standalone fix
that needs no request-identity change at all. It does. And request identity does not fix H2 either
— it changes *who* can be erased, not *how long* a matured request survives unexecuted (§11.4).
This section adjudicates H4 to a verdict; §11.4 keeps H2 explicitly open.

### 11.1 H4-A — majority-preserving replacement

> **Candidate.** Extend `initiateRecovery`'s existing replace-guard (`:443-446`): before
> `executeAfter`, replacement stays forbidden (unchanged). At or after `executeAfter`, replacement
> is forbidden **additionally** when the existing request's `supportCount` has already reached
> `(vaultGuardians[o].length / 2) + 1` — the identical formula `executeRecovery` already computes
> at `:507`. Under-supported matured requests remain replaceable, unchanged.

**Adversarial scenarios, tested against the live commit (empirical method in §13.1):**

| # | Scenario | Result under H4-A |
|---|---|---|
| **H4-1** malicious minority initiates alone, nobody supports | Unchanged from today: under-supported once matured, so honest guardians can still replace it. H4-A only forbids replacement once support **reaches** the threshold. |
| **H4-2** honest majority reaches quorum, matures | **Fixed.** A lone dissenter's replacement call now reverts. This is HIGH-4 closed — see the executed proof below. |
| **H4-3** malicious majority reaches quorum (accepted-limit takeover) — does blocking minority replacement grant the attacker anything new? | **No.** Explicitly: today's unconditional replacement is bilateral — it lets a lone *malicious* guardian erase an honest majority (HIGH-4, the defect) exactly as it lets a lone *honest* dissenter erase a malicious majority (an accidental, race-dependent, undocumented side effect nothing in `Security_Assumptions.md` credits as a defense). H4-A removes both symmetrically. The accepted limit itself (§3.13) is untouched — a genuine majority could already reach quorum and execute; H4-A does not change what a majority can *achieve*, only whether a non-majority can *erase* what a majority already achieved. (b)'s independent `cancelRecovery` veto (H4-7 below) is and remains the primary defense against a malicious majority when (b) is honest; it was never the lone-dissenter trick. |
| **H4-4** near-quorum request, one supporter stops participating | Two readings, both unaffected by H4-A: if "disappears" means removed from the guardian set, `setGuardians` deletes the request outright (`:404-407`) regardless of H4-A, and a fresh request starts clean under the new set. If it means the supporter goes silent but stays a guardian, the request remains under-supported and stays replaceable after maturity, exactly as today. |
| **H4-5** threshold edge, n = 1..5, 32 | `required = ⌊n/2⌋+1` for every n (1,2,2,3,3,17 at n=1,2,3,4,5,32 — matches §2.2 #5 exactly). H4-A reuses this existing formula at a second call site rather than introducing new arithmetic; n=2's `required=2` (unanimity, not simple majority) is a pre-existing property of the formula, not something H4-A introduces or worsens. |
| **H4-6** interaction with `setGuardians` (which already cancels pending recovery) | H4-A does not change this. `setGuardians` deletes **any** request — live, matured, under- or fully-supported — unconditionally at `:404-407`, before H4-A's guard (which lives inside `initiateRecovery`) is ever consulted. (b) can still destroy a quorum-approved request via `setGuardians`; H4-A closes only the guardian-vs-guardian replacement hole. |
| **H4-7** compromised `vaultOwner` | `cancelRecovery()` (`:548`) still erases a quorum-approved request — unconditional, pause-immune, untouched by H4-A. **This is HIGH-6, a separate authority (b's veto) from guardian-replacement authority (this candidate's scope). H4-A does not solve H6 and is not claimed to.** |
| **H4-8** pause | No new interaction. Replacement-via-reinitiation was already gated `whenNotPaused` (`:433`); H4-A adds a revert condition *inside* that already-gated function, it doesn't change the gate. Minor incidental benefit: since a quorum-approved request can no longer be replaced, it also can't be front-run away in the block that follows an `unpause()` — see H4-9. |
| **H4-9** front-running at the maturity block: `executeRecovery()` vs `initiateRecovery(R2)` | **Race eliminated, not just narrowed, for the quorum-approved case.** `supportCount` is fixed by transactions mined in *prior* blocks (support has no timestamp gate, but each support call is its own already-mined transaction). So by the maturity block, H4-A's guard condition (`supportCount >= required`) is already settled **before** either candidate transaction is ordered — the replacement call reverts regardless of whether it lands before or after the execution call in that block. For an under-supported request the race is unaffected (nothing to protect). |
| **H4-10** does `supportCount >= required` mean what it claims at that instant? | **Proven, not assumed.** `setGuardians` deletes any existing request (`:404-407`) *before* it overwrites `vaultGuardians` (`:421`) — the same statement-ordering fact §2.3 already established as load-bearing for `executeRecovery`. Consequently a `RecoveryRequest` and the guardian array it was built against can never observably diverge: any array mutation destroys the request first. `supportCount` is therefore always a count of *current* guardians who explicitly supported *this exact* request. H4-A adds no new trust in this invariant — it reuses the one `executeRecovery` already depends on, at a second call site. |

**Executed proof (this pass, against `origin/main` HEAD `032fe01`, throwaway harness deleted
before this document was written):** 3 guardians, `required = 2`. `guardian1` initiates,
`guardian1` + `guardian2` support (`supportCount = 2`, quorate). Time advanced past `executeAfter`.
`guardian3` (the lone dissenter) calls `initiateRecovery` to replace it with attacker-chosen
credentials.

- **Against unpatched HEAD:** replacement **succeeds** — `supportCount` resets to `0`, the request's
  target credential becomes the dissenter's chosen address. HIGH-4 reproduced live.
- **Against the H4-A patch:** the same call **reverts** `RecoveryAlreadyExists`; the request is
  unchanged — `supportCount` still `2`, target credential still the majority's original choice.
- The existing 19-test `AdvancedSecurity.test.ts` suite (including "blocks overwriting a live
  recovery request" and "allows replacing an under-supported request after its execution window
  elapses") **passes unchanged** under the patch — neither existing test exercises the
  matured-and-quorate branch, confirming this was genuinely untested behavior, not a behavior
  change to something pinned.

### 11.2 H4-A verdict

> **H4-A SOUND WITH CONDITIONS.**

Sound on security and liveness: closes HIGH-4 exactly as scoped, proven both by adversarial
scenario walkthrough (11.1) and by an executed red→green test against this commit; does not touch
H6, H2, or the accepted majority-takeover limit; introduces no new external call (still zero on the
recovery path, confirmed by re-reading `:389-560` this pass) and no new storage. Explicitly, H4-A:

- does **not** remove or narrow the vault-owner `cancelRecovery()` veto (H4-7) — that authority is
  untouched, unbounded, and pause-immune exactly as documented in §3.7 (HIGH-6);
- does **not** solve H2 (§11.4) — a quorum-approved request is, if anything, longer-lived under
  H4-A, which sharpens H2's question rather than answering it;
- does **not** change the declared trust assumption that a malicious guardian majority can recover
  the vault (§3.13, accepted limit) — H4-3 shows explicitly that blocking minority replacement
  grants a majority nothing it could not already do;
- does **not** require concurrent recovery IDs or any other change to `recoveryRequests`' single-slot
  shape (§11.3) — it is exactly one added guard condition inside the existing `initiateRecovery`.

Two conditions are implementation-quality, not soundness gaps, and should be satisfied before this
ships:

1. Factor `(vaultGuardians[o].length / 2) + 1` into one shared internal helper used by both
   `initiateRecovery`'s guard and `executeRecovery`'s check (`:507`), rather than leaving two
   independent inline computations that could silently diverge under a future edit.
2. Use a distinct revert reason from the live-window case (e.g. `RecoveryAlreadyApproved`) so a
   caller/UI can distinguish "still live, wait" from "already quorate, go support execution
   instead" — the measurement below used the existing `RecoveryAlreadyExists` purely to keep the
   spike minimal.

### 11.3 H4-A vs H4-B (request IDs / concurrent proposals)

**Per the brief: escalate only if H4-A fails. It does not fail any scenario in 11.1, so H4-B is not
adopted.** Comparison, for the record:

| Dimension | H4-A (single slot, majority-preserving) | H4-B (request IDs, concurrent) |
|---|---|---|
| Security | Reuses the existing, already-load-bearing §2.3 ordering invariant and the existing `required` formula; zero new attack surface | New ID scheme; must define what happens when two *different* proposals both approach quorum for different target credentials — undefined today |
| Liveness | Fixes exactly HIGH-4; under-supported-stays-replaceable preserved by design | Marginally more expressive (a dissenter can propose in parallel without griefing) at the cost of new coordination complexity — which proposal should guardians support? |
| State complexity | Zero new storage shape | New mapping dimension (`owner => id => RecoveryRequest`), support accounting becomes 3-level |
| Griefing/DoS surface | None added | Unbounded distinct concurrent proposals unless capped; a cap reintroduces an eviction policy — a variant of the problem being solved |
| Storage growth | None (still 1 slot) | Grows with concurrent proposal count; needs pruning — pulls H2 in as a hard dependency (§11.4 explains why that's backwards to require here) |
| Support accounting | Unchanged bearer-flag (MEDIUM-3 stands, orthogonal) | Must become request-scoped; needs a rule for whether a guardian can move support between proposals |
| Stale request cleanup | N/A — `delete` on execute/cancel/`setGuardians`, unchanged | Needs an explicit expiry/cleanup mechanism or accepts unbounded growth |
| Execution races | **Proven eliminated** for the quorum-approved case (H4-9) | New race: which of several eventually-quorate proposals executes, and does executing one invalidate the others? Unspecified |
| UI/operator complexity | None — same single "current request" view, plus a boolean | Guardians must disambiguate multiple live proposals; higher error risk for a research-prototype operator audience |
| Bytecode size | **Measured: +64 bytes** (§13.1) against 1,455 B headroom | Unmeasured; categorically larger (new mapping dimension, ID generation/lookup, rewritten support accounting) — the kind of change F-5 already shows this repo cannot safely estimate without compiling |
| Simulator parity | Small, cheap to mirror and pin (L-E) | Parity burden scales with mechanism size |
| Mutation-test burden | A handful of targeted mutants (§10, mutation plan) | Materially larger space: ID collision, cross-request support leakage, wrong-request-executed, missing sibling-invalidation-on-execute |

**Recommendation: adopt H4-A's semantics as a target (subject to the two conditions in §11.2 and
normal PR-level review); do not pursue H4-B.** H4-B is not rejected as universally bad — it is
**unnecessary while the materially smaller H4-A satisfies the currently targeted H4 invariant**
(§11.1's ten scenarios, none of which H4-A fails), and it is strictly more expensive on every axis
measured. A future finding H4-A genuinely cannot address would be grounds to revisit H4-B on its
own merits — none has been identified in this pass.

### 11.4 H2 — kept explicitly separate, still OPEN

**Do not read anything above as fixing H2.** H2 is: *a sufficiently supported matured recovery has
no final execution expiry* — unrelated to who can erase it (H4) and unrelated to who can approve it
(request identity). Request identity, had it been adopted, would change *which* recoverer's request
survives contention; it says nothing about *how long* an unexecuted-but-quorate request may sit
before it should be considered stale. H4-A does not touch this axis at all — a quorum-approved
request is, if anything, now **longer**-lived than before (immune to erasure), which sharpens H2's
question rather than answering it: a permanently-protected, never-expiring, quorum-approved request
is exactly the object H2 already worried about, now with one fewer way to get rid of it besides
executing or (b) intervening.

This pass does not design an expiry state machine for H2 (out of scope, per the brief). One
observation only: [[feedback-expiry-cannot-transplant-to-destructive-restart]] already rules out the
obvious fix (reusing `GOVERNANCE_GRACE_PERIOD`) because re-announcement via `initiateRecovery`
destroys accumulated support — and that restart cost is **unchanged by H4-A**, since H4-A does not
alter what `initiateRecovery` does when it *is* permitted to replace a request. H2 remains OPEN,
unsolved, and is not made harder or easier to eventually solve by adopting H4-A.

---

## 12. PQ-key validation verdict — CORRECTED

> **VERDICT: STRIKE v1's L-C. Do not put a hardcoded ML-DSA-65 length check in either vault.**

Of the brief's three categories, **H5 is category (3) — verifier-specific format validation —
wearing category (1)'s clothes.** "A credential that cannot possibly work" is not a vault-knowable
property: `IPQCVerifier` declares `publicKey` as opaque `bytes calldata`, documents `algorithmId()`
as metadata carrying **no security guarantee**, and admits mock, attestation, ZK and precompile
implementations. All three *real* verifiers bind only `keccak256(publicKey)`
(`AttestationPQCVerifier:96`, `ImmutableAttestationPQCVerifier:89`, `ZKMLDSAVerifier:85`). Only the
mock requires 1952 bytes.

A vault-level length check therefore: is correct **only for the mock** (the verifier the roadmap
labels security-none); **constrains no adversary**, since 1952 random bytes pass it; and under the
documented SLH-DSA / precompile migration converts a per-vault, 7-day, self-repairable liveness
fault into a **contract-wide** one at the moment a new verifier is applied.

**H5 is a usability/footgun defect, not a security defect** — a guardian majority is already trusted
to choose replacement credentials and can already choose hostile ones. Its distinguishing feature is
that it is reachable **by mistake with no revert to warn**.

The verifier-agnostic fix is **P2 — delegated proof-of-possession**: require a PQ signature from
the incoming key over the recovery digest via `pqVerifier.verify`, exactly as `rotateCredentials`
does at `:731`. The verifier then decides what a valid key is, and genericity is preserved by
construction. **The open question is placement:** at `initiateRecovery` it adds a module dependency
to the very path that is the escape hatch when the verifier is broken. `executeRecovery` must stay
call-free regardless. **OPEN — do not lock.**

---

## 13. EIP-170 — CORRECTED

Measured figures unchanged (vault 23,121 / headroom **1,455**; simulator 22,743 / headroom 1,833).
Newly measured this pass and now binding on the design:

| Construct | Bytes | Note |
|---|---|---|
| DUP/SWAP reach — `setGuardians` | 6 | Large headroom; safe to extend |
| DUP/SWAP reach — `executeRecovery` | 12 | Safe |
| DUP/SWAP reach — **`initiateRecovery`** | **15** | **One below the ceiling — frozen against new parameters** |
| DUP/SWAP reach — `_authorizeRotation`, `withdraw`, `queueWithdrawal` | 16 | **At the ceiling** |
| Clearing loop (the `recoverySupports` idiom) | 90–104 | ×4 sites |
| Creation bytecode | 24,464 / 24,217 | Against EIP-3860's 49,152 — not binding |

**Two figures in open conflict, unresolved without a compile:** the asymmetric in-vault mechanism
prices at ~675 B (adjudication) versus ~1,650 B (independent re-derivation), against 1,455 B. Note
~29.8% of the vault's runtime is utility-Yul and unmapped buckets that this build does not emit as
`generatedSources`, so **every forward figure is a lower bound**.

> **STOP CONDITION (unchanged in force, corrected in trigger).** Measure at the first compiling
> implementation, on the **vault**, before mirroring. Any function at DUP reach 15–16 is frozen
> against new parameters or struct members. If the vault lands below **600 B** headroom, redesign or
> externalize. Run the size gate from a clean, **non-instrumented** compile — coverage
> instrumentation inflates measured sizes.

### 13.1 H4-A — measured, this pass

Per the brief's discipline ("do not use speculative byte numbers when direct compilation can answer
cheaply"), H4-A's cost was **compiled, not estimated**. Method: patched `initiateRecovery` with the
§11.1 guard inside `wv-guardian-authority` (the dedicated worktree), ran `npm run compile` +
`npm run validate:bytecode-size` from a clean non-instrumented build, then restored the file with
`git checkout -- contracts/WalletWallVault.sol` and reconfirmed `git diff HEAD` empty and
`rev-parse HEAD`/`origin/main` both still `032fe01` before writing this document.

| | Baseline (HEAD) | H4-A patch | Delta |
|---|---|---|---|
| `WalletWallVault` runtime bytes | 23,121 | 23,185 | **+64** |
| `WalletWallVault` headroom | 1,455 | 1,391 | −64 |
| `StablecoinVaultSimulator` runtime bytes | 22,743 | 22,743 (not mirrored in the spike) | n/a — mirroring costs another ~64 B against its 1,833 B headroom |

**+64 bytes is unambiguously cheap** — 4.4% of the vault's headroom, against the asymmetric
contraction mechanism's still-unresolved 675–1,650 B range over the *same* 1,455 B budget. O-3′
(bytecode sizing) is **resolved for H4-A specifically**; it remains open for the unrelated,
larger F-1…F-4 mechanism.

---

## 14. Corrected implementation PR ordering

The v1 ordering led with L-C, which is now struck. v3 folds H4-A and the H3 documentation fix into
PR-2, per their measured cost and zero-regression evidence (§11, §13.1) — there is no reason to gate
either behind the harder, still-open C5/F-1…F-4 work, since neither touches it:

1. **PR-1 (docs only, no Solidity).** Commit this corrected document. Amend
   `docs/Security_Assumptions.md` per L-B′, including the H3 asymmetry (§10, with the exact §10.1
   replacement text for `:671`) and the H5 characterisation (§12). Zero bytecode, zero redeploy, no
   evidence recapture.
2. **PR-2 (small, in-vault).** L-D treasury-quorum clamp; L-E parity test; L-F′ generation-semantic
   test; L-I AST test anchored to function names; **L-J** H4-A's guard plus its two conditions
   (§11.2) plus the H4-2/H4-9 regression tests; **L-K** the H3 regression tests (§10.1). Measure
   both vaults. This is the only in-vault work whose soundness is settled.
3. **PR-3 (spike, no merge).** Resolve O-3′ *for the asymmetric contraction mechanism* by compiling
   a throwaway implementation purely to obtain a real byte figure, and repair F-1…F-4 (strict
   ascending-address ordering for distinctness; generation-keyed veto; permissionless `apply`).
   **Re-adjudicate after repair** — this is the step v1 skipped.
4. **PR-4 (design, no Solidity).** C5 PUSH-controller design round, informed by PR-3's numbers and
   required to clear I-GUARDIAN-INDEPENDENCE (§4.1a) for the controller's own provenance rule.
5. **Not scheduled:** H2 expiry (O-4′), H4-B request identity (§11.3, not adopted), H5 delegated PoP
   placement, I-STRONGER.

Sequencing against the already-committed `redeploy-from-public-head` remediation is unchanged: any
bytecode change should land **before** that redeploy or it is paid twice.

---

### 14.1 Corrected authority hierarchy

**No single linear ranking exists, and this pass does not invent one.** The five principals named
in the brief relate on **two largely separate axes** — a guardian/credential-authority axis and a
withdrawal-policy axis — that intersect at exactly one point (`policyControlEpoch`, a value
recovery/rotation *write* and the policy-control bridge only ever *reads*, never the reverse). Where
a genuine relation exists on the same axis, it is a **veto/override** relation (can destroy what the
other builds), not a **directive** one (can act in the other's stead):

| Principal | Axis | Can | Cannot | Relation to others on its axis |
|---|---|---|---|---|
| **Vault identity (b)** | Guardian/credential | Unilaterally replace the guardian roster; cancel any recovery; set treasury quorum — all pause-immune | Move funds alone (needs c/d); be replaced by anyone, ever | **Dominates (e) procedurally**: `setGuardians`/`cancelRecovery` unconditionally destroy anything guardians build (§2.2 #9, #13). Does not thereby gain (e)'s power — cannot install new credentials without (c)/(d) or a recovery it doesn't control |
| **Spending credentials (c)/(d)** | Guardian/credential | Move funds (valid sigs); self-rotate (old+new PoP) | Touch the guardian roster or recovery **in any way** — zero pathway, verified structurally (§4.1a) | Strictly weaker post-recovery than pre-recovery (b) (HIGH-7) — recovery installs a principal holding a *disjoint*, smaller gate set |
| **Guardian recovery authority (e)** | Guardian/credential | Eventually overwrite (c)/(d) (majority + 7-day delay) | Touch its **own** roster (§4.1a); move funds directly; override (b)'s `cancelRecovery` or `setGuardians` veto | **Dominates (c)/(d)** on this axis (can eventually replace them); **subordinate to (b)** (b can always destroy an in-flight recovery) |
| **Global admin (a)** | Orthogonal — cross-tenant circuit breaker | Suspend (`pause`) initiate/execute contract-wide; govern shared infra (`pqVerifier`, policy engine, large-tx params) under timelock | Touch **any** per-tenant guardian/recovery/credential state directly (§4.1a, re-verified) | Incomparable to (b)/(c)/(d)/(e) — global and suspensive only, never directive, on the guardian/credential axis |
| **Policy authority** (engine, composite, DailySpend, bridge) | Withdrawal-policy | Block/permit withdrawals per configured rule; the bridge relays credential-signed policy intents | Touch guardians or recovery **at all** — zero external calls exist on the recovery path (§2.2, re-confirmed §4.1a); the bridge only *reads* `policyControlEpoch` | Subordinate to all four guardian-axis principals *on that axis* (zero power); primary gate on the orthogonal withdrawal axis |

The one cross-axis link is directional and narrow: `executeRecovery`/`rotateCredentials` **write**
`policyControlEpoch`; `PolicyControlBridge` **reads** it to detect staleness (`PolicyControlBridge.sol:733`).
Nothing on the policy axis can write back into the guardian axis. This is why §4.1a's per-principal
table finds the policy engine and the bridge not merely *unauthorized* but structurally
*unreachable* from the recovery path — the two axes do not merge.

### 14.2 Future regression matrix

None of these exist in the repository today (verified by grep against `test/` this pass, where
noted). All are test **specifications** for the PR sequence in §14, not code written in this pass.

| # | Property | Exists today? | Where it lands |
|---|---|---|---|
| 1 | Post-bootstrap owner compromise cannot rewrite guardians under any eventual chosen hardening | No — depends on a mechanism not yet chosen | PR-4, once C5/repaired-in-vault is selected. This *is* I-REFINED (§4.1) |
| 2 | Compromised credentials cannot rewrite recovery authority | True by construction today (no code path); **not** pinned by any test | PR-2 — an allowlist-style AST assertion ("only `setGuardians` may write `vaultGuardians`"), same style as L-I, so a future function cannot silently open a second write site |
| 3 | Credential rotation does not destroy honest recovery (no-cancel precedence, §10) | No — `grep test/ rotateCredentials` alongside a live `recoveryRequests` entry returns zero hits | PR-2, §10.1 items 1-2 |
| 4 | Under-supported matured request becomes replaceable | **Yes** — `test/AdvancedSecurity.test.ts:197-207`, reconfirmed passing under the H4-A patch this pass | Already shipped; cross-reference only |
| 5 | Quorum-supported matured request cannot be erased by one guardian (if H4-A ships) | No — confirmed absent this pass (neither existing griefing test reaches this branch); this pass's throwaway version proved the property and was deleted, never committed | PR-2 — promote the throwaway to a permanent test |
| 6 | Malicious majority remains capable of recovery (declared trust model, §3.13) | **Yes**, incidentally — `test/AdvancedSecurity.test.ts`'s "Should execute recovery after delay and sufficient supports" passed unchanged under the H4-A patch, confirming H4-A blocks *replacement* only, never *execution* | Already shipped; cross-reference from L-J |
| 7 | Guardian-set mutation invalidates stale recovery authorization semantically | Yes, as source behavior (`:404-407`); the **semantic**-form test is L-F′, still not written | PR-2 |
| 8 | No recovery external callbacks | Yes, as source behavior (§2.2, re-verified this pass); the AST-anchored test is L-I, still not written | PR-2 |

### 14.3 Mutation plan

| # | Mutant | Expected kill | Status |
|---|---|---|---|
| 1 | Allow owner-only established-set replacement under the eventual mechanism | Regression #1 | Pending mechanism choice |
| 2 | Let current credentials unilaterally replace guardians (new (c)/(d)-signed branch on any guardian-mutating function) | Regression #2's allowlist assertion | Needs the allowlist form specifically — a `rotateCredentials`-only spot check would miss a mutant that adds an *entirely new* function |
| 3 | Cancel recovery inside `rotateCredentials` | Regression #3 | Ready to write now (PR-2) |
| 4 | Allow replacement of quorum-approved matured recovery (revert H4-A to baseline) | Regression #5 | **Already executed this pass** — see §11.1's red/green proof |
| 5 | Forbid replacement of under-supported matured recovery (make the guard unconditional post-maturity) | Regression #4 (existing test) | Confirmed killed: the existing "allows replacing an under-supported request" test asserts success and would fail against this mutant |
| 6 | Compute majority from a stale guardian-set generation | — | **Vacuously unreachable today** — §2.3's ordering invariant makes this mutant impossible to trigger under the single-slot design (any array mutation destroys the request first). Becomes a *real, necessary* test only if H4-B is ever adopted — a concrete instance of §11.3's "mutation-test burden" row |
| 7 | Reuse support from a prior guardian generation | — | Same as #6 — vacuously unreachable single-slot, real only under H4-B |
| 8 | Add an external authorization callback during recovery | Regression #8 | Ready to write now (PR-2) |
| 9 | Hardcode a mock-specific PQ key length into the vault (struck design, S-3) | New test, not yet written: a real verifier (`AttestationPQCVerifier`/`ImmutableAttestationPQCVerifier`/`ZKMLDSAVerifier`) admitting a non-1952-byte key through `initiateRecovery`/`executeRecovery` | Existing HIGH-5 coverage only tests `address(0)`/`"0x"` (§3.6) — this specific length-diversity case is new |

---

## 15. Scope boundary

Unchanged from v1, with one addition: **this pass does not settle whether the post-bootstrap
invariant should be built.** It settles only that the invariant is *achievable in principle*, that
v1's impossibility argument was invalid, and that no mechanism has yet survived refutation. Turning
"the first attempted mechanisms were unsound" into "the existing authority model is optimal" is
precisely the error this pass exists to prevent — and it is an error v1 committed.

**v3 addendum:** this pass does not decide whether H4-A ships — it establishes that H4-A is sound,
cheap, and evidenced, so that decision is no longer blocked on missing analysis. It does not solve
H2 or H6, and does not claim to. It does not design the C5 controller's provenance rule — it gives
that future design a sharper bar (I-GUARDIAN-INDEPENDENCE, §4.1a) to clear. Treating "the cheap H4
candidate turned out to be sufficient" as "H2 is therefore also close to solved" would repeat
exactly the conflation this pass exists to correct (§9.3 S-7).
