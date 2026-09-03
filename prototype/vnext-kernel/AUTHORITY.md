# Authority-labyrinth conformance — prototype v0 mapped onto PR #179

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**

## 0. THE PREVIOUS VERDICT ON THIS FILE WAS WRONG, AND IS WITHDRAWN

An independent review of the compiled kernel at head `79e05a34` alleged four
authority gaps contradicting the minimum-cut table this file published. **Every
one was attempted firsthand against the real kernel, and every one REPRODUCED.**
The `KERNEL_PROTOTYPE_PASSES_ARCHITECTURE` verdict that stood on those numbers
is withdrawn; what follows is the re-derivation after remediation.

The failed claims are kept rather than deleted, because a table that quietly
corrects itself destroys the evidence that the correction happened.

| Finding | Claim it falsified                          | Reproduced end state                                                                                                                          | Real cut was            |
| ------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| **A1**  | `credential replacement = min(2, k)`        | ECDSA-only attacker rotated **both** factors, then moved 10 ETH                                                                               | **1**                   |
| **A2**  | `silent crypto downgrade = unreachable`     | ECDSA-only attacker installed an ALWAYS-TRUE verifier with the floor untouched, then spent using the **public** PQ key and a forged signature | **1**                   |
| **B**   | `guardian takeover = k`                     | roster `[A, A, B]`, threshold 2, ONE principal signing at indices 0 and 1 reached quorum, recovered, and drained the vault                    | **1**                   |
| **C**   | "atomic deployment prevents front-running"  | attacker occupied the user's `predictVault` address with their own signer and guardian set                                                    | n/a — identity takeover |
| **D**   | _(unstated)_                                | rotation installed a credential nobody possessed; the vault was stranded behind guardian recovery                                             | n/a — liveness          |
| **E**   | "the implementation can never hold custody" | 1 ETH sent to the implementation, accepted                                                                                                    | n/a — claim error       |
| **F**   | _(unstated)_                                | two 1 ETH spends both passed a 1.5 ETH cumulative cap                                                                                         | n/a — plane boundary    |

**A FIFTH CLAIM WAS FALSIFIED LATER, BY THE STATEFUL LANE, AND IS RECORDED THE
SAME WAY.** The stateful adversarial campaign at head `ec5adce9` sustained
**SD-1**: `setVerifier` could move `SecurityFloor.pqPublicKeyLength` /
`pqSignatureLength` freely while `_requireIncomingPossession` measured an
already-quorum-approved recovery against those fields LIVE, so the credential
principal held a veto over guardian recovery that `CHALLENGE_LIMIT` never saw.

| Finding  | Claim it falsified                      | Reproduced end state                                                                                                                                       | Real cut was                        |
| -------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------- |
| **SD-1** | `permanent recovery veto = unreachable` | an honest `k = 2` quorum approved a recovery; the credential changed ONE floor length; the matured recovery became unexecutable with `challengesUsed == 0` | **2** — no cut moved; a DENIAL only |

**SD-1 is now REMEDIATED on `security/vnext-sd1-recovery-floor-binding` by
`I-FLOOR-SHAPE-IMMUTABLE`** — see the "Permanent recovery veto" row in section 3.
The reproduction was INVERTED IN PLACE rather than deleted
(`test/StatefulSustainedDefects.test.ts`); its ledger entry moved to
`REMEDIATED_DEFECTS` in `stateful/defects.ts`, carrying the head it was sustained
at; and the residual it leaves is carried as **SD-4** in the sustained ledger.
**SD-2 and SD-3 remain SUSTAINED and unfixed.**

**SD-3 IS NOW REMEDIATED TOO, on `security/vnext-sd3-sd4-authentication-satisfiability`, and re-deriving it corrected the record in three places. SD-4 IS NOT.**

> **CORRECTION, `security/vnext-sd6-sd7-commitment-admission`.** This block
> previously read "SD-3 AND SD-4 ARE NOW REMEDIATED TOO", tabulated SD-4 as
> closed, and named **`I-DECLARATION-SUBORDINATE-TO-LIVE-RECOVERY`** as one of
> "two INDEPENDENT clauses on that one edge". **That invariant does not exist in
> any Solidity file.** The interlock that would have carried it was built,
> measured at +141 B and REMOVED, because refusing a ONE-SHOT transition hands
> the guardian quorum a renewable veto over a capability no guardian path can
> itself exercise. SD-4 has been in `SUSTAINED_DEFECTS` throughout, the kernel
> comment at `setVerifier` says so, and
> `test/Sd34AuthenticationSatisfiability.test.ts` asserts the declaration
> SUCCEEDS and the approved recovery then dies. The stale text contradicted the
> code, the ledger and the tests, and the "Permanent recovery veto" row in
> section 3 below — which correctly carried SD-4 as open — contradicted it too.

| Finding  | Claim it falsified                                   | Reproduced end state                                                                                                                                     | Real cut was |
| -------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| **SD-3** | `credential stranding = unreachable` (via the FLOOR) | one root armed `requirePq` against material that cannot satisfy it, and every credential path then died on a conjunct with no preimage                    | **1**        |

SD-3 is closed by **`I-DECLARATION-EXHIBITED`**. The prior lane's hypothesis that
closing SD-4 "necessarily intersects" SD-3 is **refuted**: the exhibit binds
`pqPublicKeyHash` while SD-4 is about `recovery.proposedPqKeyHash`, and in the
reproduced counterexample the declared key length matches the incumbent EXACTLY,
so the exhibit passes on both conjuncts and the approved recovery still dies.
**SD-4 remains SUSTAINED, deliberately** — its analysis and the only sound design
are in `stateful/defects.ts`.

**SD-6 AND SD-7 ARE NOW REMEDIATED, on `security/vnext-sd6-sd7-commitment-admission`,
by a single invariant over the whole commitment ingress surface.**

| Finding  | Claim it falsified                                 | Reproduced end state                                                                                                                        | Real cut was |
| -------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| **SD-6** | `credential stranding = unreachable` (via ROTATION) | while `requirePq` was false, rotation and recovery both wrote a `pqPublicKeyHash` attested by nothing                                        | **1**        |
| **SD-7** | `initialize` validates its own genesis              | a vault BORN committing a 48-byte key under a declared 32-byte shape — unable to authorise from block one, with the shape already frozen     | **0**        |

**`I-COMMITMENT-EXHIBITED-AT-ADMISSION`** — every accepted transition that writes
a NON-ZERO `pqPublicKeyHash` must exhibit a preimage of the value being written;
where the governing floor already mandates PQ, that preimage must also carry the
declared key length. `pqPublicKeyHash` has exactly two write sites (`initialize`,
`_installCredential`) and `_installCredential` exactly two callers, so one rule
covers all three admitting transitions. It is what gives
`I-DECLARATION-EXHIBITED` an **authenticated base case**: before it, the value a
declaration was measured against was settable by the same cut-1 principal one
transaction earlier, so the exhibit proved only that the declarer knew a preimage
of a hash the declarer chose.

**Zero is not a commitment.** `bytes32(0)` remains admissible wherever the floor
does not mandate PQ — that is what preserves the ECDSA-only rotation and the
cold-ceremony deployment (deploy with no commitment, run the ceremony, rotate the
real one in). **The dormant clause deliberately compares NO length**: while
`requirePq` is false the floor lengths are unvalidated and unfrozen, so reading
them at install time would let one `false -> false` `setVerifier` at cut 1 make
every later credential install — `executeRecovery` included — undeliverable
forever. That is the SD-4 interlock's failure in a worse form, and it was
rejected for the same reason.

A fourth recorded claim was wrong. SD-7's `minimalFixSketch` deferred the only
fix that closes it because "`GenesisConfig` is hashed into `genesisSalt`, so
adding a member changes EVERY vault address the factory can produce".
**`genesisSalt` hashes an ENUMERATED FIELD LIST, not the struct as a unit**, so
that is false. The witness is nonetheless kept OUT of `GenesisConfig` and passed
as a parameter, on the correct and narrower ground that the salt binds genesis
AUTHORITY and a preimage proof confers none.

**What that preserves is the SALT, not addresses, and the distinction is not
pedantic.** `genesisSalt(userSalt, g)` is unchanged as a function — the same
configuration yields the same salt, pinned in
`test/Sd67AdmissionInvariants.test.ts` against a constant captured from the
parent build. A deployed clone's address, however, is
`CREATE2(factory, salt, keccak256(initcode))`, and the ERC-1167 initcode embeds
the IMPLEMENTATION address; the implementation moved by +299 bytes and the
factory by +219, so both must be redeployed and every clone address moves. That
is true of every remediation in this stack and no change to this kernel could
avoid it. An earlier draft of this section claimed "every vault address is
unchanged" — the pinned constant asserts the salt and cannot assert an address.

Three recorded claims were wrong, and are corrected here rather than quietly
dropped. SD-3's title said "permanently bricking" while its own
`notAnEscalationBecause` said "escapable at k" — the field was right. SD-3's
`minimalFixSketch` proposed a zero-hash check that a NON-ZERO commitment defeats
unchanged, so implementing the ledger's own sketch would have shipped a fix that
left the defect open. And the asset-control, crypto-downgrade and
credential-stranding rows in section 3 all lacked the ECDSA-only scope caveat
they needed.

**Still SUSTAINED after all of the above: SD-2** (tumbling containment window),
**SD-4** (the declaring edge destroys an approved recovery, uncounted), **SD-5**
(permanent shape capture — an exhibit proves possession of a preimage, not that
the preimage is a usable key, and `pqSignatureLength` is bound by no commitment
at all, so a one-byte shape is still reachable and still permanent), and the new
**SD-8** — the declared residual of SD-7's fix: an exhibit can never establish
that key bytes are WELL-FORMED for a scheme, because the only party who could
judge that is a verifier the admitting principal chooses in the same transaction.
A deployer determined to build a dead vault still can; what is closed is the
self-contradictory genesis a well-intentioned one reaches by accident.

**Why the existing suite missed all of them.** 55 tests passed throughout. Every
one exercised a path where the attacker COOPERATES — supplying a PQ signature,
using distinct guardians, deploying at a fresh salt. None asked what an attacker
_declines_ to do, and none followed a governance transition through to the asset
movement it enables. **A dangerous setter returning success is not a finding; the
drained vault is.** Every discriminator added in this pass carries the attack
through to the balance check.

---

## 1. Direct authority

| Principal                                            | Direct capabilities in the prototype                                                                                               | Notes                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Spending credential** (`ecdsaSigner`)              | `execute` · `rotateCredential` · `setVerifier` · `setPolicy` · `cancelRecovery` (bounded) · the credential half of `bindMigration` | The kernel-evaluated possession root                         |
| **Guardian quorum** (`>= k` of the committed roster) | `setGuardians` · `initiateRecovery` · `enterContainment` · the quorum half of `bindMigration`                                      | **Accepted trust root (D1)**                                 |
| **Guardian (individual)**                            | none                                                                                                                               | Attests; holds nothing alone                                 |
| **Anyone**                                           | `executeRecovery` (after maturity) · `egress` · `retire` (after delay)                                                             | **No discretion**: recipient and effect are pre-committed    |
| **PQ verifier**                                      | none                                                                                                                               | Answers a query. Conjunctive barrier only                    |
| **Policy plane**                                     | none                                                                                                                               | May only refuse                                              |
| **Factory deployer**                                 | none                                                                                                                               | Choice consumed at construction (D8)                         |
| **Generation publisher**                             | none on-chain                                                                                                                      | Discovery influence only (H-32)                              |
| **KERNEL ADMIN**                                     | **DOES NOT EXIST**                                                                                                                 | No `owner`, no `pause`, no `upgrade`, no `transferOwnership` |

> **The single largest authority-graph difference from the monolith.**
> `WalletWallVault` exposes `pause`, `unpause`, `transferOwnership` and
> `acceptOwnership` — a live global admin over every tenant. The prototype
> exposes **none of the four**. That is not a byte saving; it is the deletion of
> a principal, and it is what dissolves hazards H-01, H-05, H-07 and H-12 at the
> root rather than bounding them.

## 2. Closure

| Principal           | Closure adds                                                                               | Reaches assets?                                       |
| ------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| Spending credential | —                                                                                          | **Yes**, directly                                     |
| Guardian quorum     | `initiateRecovery` → `executeRecovery` → new credential → `execute`                        | **Yes — ACCEPTED RESIDUAL, asserted positively** (D1) |
| Anyone              | — (`egress` recipient is bound; `executeRecovery` installs the _proposed_ credential only) | **No**                                                |
| PQ verifier         | — (denial only; the ECDSA conjunct is unreachable to it)                                   | **No**                                                |
| Policy plane        | — (subtractive)                                                                            | **No**                                                |
| Factory deployer    | **EMPTY**                                                                                  | **No**                                                |
| Kernel admin        | n/a — no such principal                                                                    | —                                                     |

## 3. Minimum compromise cuts — RECOMPUTED from the remediated implementation

`n` guardians, `k = floor(n/2) + 1`. Fixture: `n = 3, k = 2`. Every row below is
re-derived from the compiled kernel, NOT carried forward from #179 §24.

| Outcome                    | #179 §24         | at `79e05a34` (measured) | NOW             | Enforced by                                                                                                                                         |
| -------------------------- | ---------------- | ------------------------ | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized asset control | `min(2, k)`      | **1** (A1, A2)           | **`min(2, k)` on a vault whose floor mandates PQ; `1` on one born ECDSA-only** | `execute`, `rotateCredential`, `setVerifier` and `setPolicy` all call `_authorise` — the ECDSA conjunct **AND** the PQ conjunct. M-K28, M-K29. **SCOPE, previously missing:** `_authorise` returns at `if (!floor.requirePq) return;` before the PQ leg, so on an ECDSA-only-floor vault the conjunction this row cites does not exist and the real cut is 1. Measured in `test/Sd34AuthenticationSatisfiability.test.ts` |
| Credential replacement     | `min(2, k)`      | **1** (A1)               | **`min(2, k)`** | rotation is HYBRID-authorised and additionally requires possession of both INCOMING factors. M-K28, M-K34                                           |
| Guardian takeover          | `k`              | **1** (B)                | **`k`**         | `I-QUORUM-PRINCIPAL-DISTINCTNESS`: the committed roster must be strictly ascending by address, so `k` seats are `k` PRINCIPALS. M-K30, M-K31, M-K32 |
| Migration takeover         | `k + 1`          | `k + 1`                  | **`k + 1`**     | `bindMigration` requires quorum **AND** credential. Unchanged                                                                                       |
| Permanent recovery veto    | unreachable      | **2** (SD-1)             | **unreachable, on any vault whose floor already mandates PQ** | containment budgeted `B < W`; challenge capped; no pause exists; **`I-FLOOR-SHAPE-IMMUTABLE`** freezes the two STRUCTURAL floor fields once `requirePq` holds, so no credential-writable state remains in the recovery satisfiability condition. **Scope, stated rather than buried:** on a vault born ECDSA-only the `requirePq` false -> true edge declares the shape for the first time and retains ONE uncounted, one-shot, self-healing move — carried as **SD-4** |
| Silent crypto downgrade    | unreachable      | **1** (A2)               | **unreachable** | `setVerifier` is HYBRID; the floor may only strengthen — true of all four fields **once `requirePq` already holds**, which is what `I-FLOOR-SHAPE-IMMUTABLE` establishes. **SCOPE, corrected:** on the one-shot `requirePq` false -> true DECLARING edge two of the four are still free, and `I-DECLARATION-EXHIBITED` binds only the key shape to the committed material, never the signature shape. The residue is **SD-5**, and it is permanent. The escape from a dead verifier is the GUARDIAN quorum, not one factor |
| Vault identity takeover    | _(not modelled)_ | **1** (C)                | **unreachable** | `I-COUNTERFACTUAL-IDENTITY-BINDING`: the CREATE2 salt binds the complete genesis authority. M-K33                                                   |
| Credential stranding       | _(not modelled)_ | **1** (D)                | **unreachable by ACCIDENT; still reachable DELIBERATELY at 1** | `I-INCOMING-CREDENTIAL-POSSESSION` on both rotation and recovery. M-K34, M-K35. **SCOPE, narrowed rather than removed.** The earlier caveat read "unreachable while `requirePq` holds", because `_requireIncomingPossession` returned before every PQ check while it did not, so on an ECDSA-only floor BOTH paths installed a commitment attested by nothing (**SD-6**); `initialize` was never a call site of that helper at all (**SD-7**). `I-COMMITMENT-EXHIBITED-AT-ADMISSION` closes both. **It does NOT make stranding unreachable, and saying so unqualified would repeat the over-claim this table has already made twice.** An exhibit proves knowledge of a PREIMAGE of PUBLIC bytes — never possession of a signing capability — so a cut-1 principal may still install a correctly-shaped key it does not hold and then arm it, reproducing finding D end state. What is closed is the UNATTESTED install and the self-contradictory genesis: the forms a well-intentioned operator reaches by ACCIDENT. M21, M22. **Residuals: SD-5** (the shape is still free) and **SD-8** (a preimage is not a proof of well-formedness) |
| Denial of spending         | **1**            | **1**                    | **1**           | one verifier or one policy plane. **Accepted and declared**                                                                                         |

**No cut is now lower than #179 §24, and two outcomes §24 never modelled are
closed.** The migration path stays `k + 1` and is never the minimum; the guardian
path dominates at `k`, exactly as §24 says.

> **The one cut that got WORSE, stated rather than buried.** Closing A2 means the
> ECDSA factor can no longer replace a dead verifier unilaterally. A vault whose
> PQ verifier dies is therefore **spend-denied until a guardian quorum acts** —
> the denial cut is unchanged at 1, but the _remedy_ now needs `k`. That is a
> deliberate trade of liveness for safety, and it is the reason recovery carries
> a replacement verifier rather than leaving the escape to one factor.

## 4. What each finding cost to close

| Fix                                                                  | Runtime cost                  | Note                                                                                                                                                                 |
| -------------------------------------------------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** HYBRID governance on rotation / verifier / policy              | **-75 bytes**                 | **The most important fix was FREE.** Calling the existing `_authorise` is _cheaper_ than the inline one-factor path it replaced — the defect was not buying anything |
| **B** canonical (ascending, distinct) roster                         | **+186**                      | one comparison per member; duplicates become unrepresentable rather than merely detected                                                                             |
| **D** incoming credential possession                                 | **+725**                      | the single largest security cost, and the one #178 already argued for                                                                                                |
| **E** genesis validation, verifier code checks, `effectiveSafeState` | **+352**                      |                                                                                                                                                                      |
| **C** counterfactual identity binding                                | _(in the FACTORY)_            | factory 1,642 -> 2,226 B, once per generation                                                                                                                        |
| residual                                                             | +1,880                        | `GenesisConfig` / `CredentialChange` calldata plumbing that findings C and D require structurally, plus optimizer interaction between overlapping ablations          |
| **TOTAL**                                                            | **14,339 -> 17,407 (+3,068)** | TARGET PASS, 4,569 B under the 21,976 ceiling                                                                                                                        |
| **SD-1** `I-FLOOR-SHAPE-IMMUTABLE` (+ the `MAX_PQ_LENGTH` bound)     | **+215**                      | **17,407 -> 17,622.** TARGET PASS, 4,354 B under the ceiling. Storage layout byte-identical; ABI additive only (selectors 44 -> 45, the new `MAX_PQ_LENGTH()` getter) |
| **SD-3** `I-DECLARATION-EXHIBITED`                                   | **+184**                      | **17,622 -> 17,806.** TARGET PASS, 4,170 B under the ceiling. Storage layout AND ABI byte-identical — two comparisons reusing an existing parameter, on the `requirePq` false -> true edge only. SD-4 is NOT closed; see its ledger entry |
| **SD-6 + SD-7** `I-COMMITMENT-EXHIBITED-AT-ADMISSION`               | **+299**                      | **17,806 -> 18,105.** TARGET PASS, 3,871 B under the ceiling. Storage layout byte-identical. **ABI: exactly two entries move** — `initialize` and `deployVault` each gain a trailing `bytes` WITNESS; selector COUNTS unchanged at 45 and 4, and `genesisSalt`/`predictVault` are untouched, so the configuration -> salt map is unchanged (addresses still move, as they do for every bytecode change — the clone initcode embeds the implementation address). The factory carries **+219** of its own to forward the witness |

**No T0/T1 invariant was deleted to recover bytes.** The ablated variants that
produce these deltas are diagnostic only, and every one of them reintroduces a
defect reproduced against the real kernel.

### The earlier K-15 finding, kept as history

The pass before this one found that `_authorise` engaged the PQ conjunct only
when the CALLER supplied a non-empty signature — a downgrade through the argument
list. That fix (K-15, +1,199 bytes) is still in place and still necessary. It was
**not sufficient**: it made the PQ conjunct mandatory _where `_authorise` was
called_, and the three governance paths were not calling it. **Closing a hole in
a helper does not close the paths that bypass the helper**, which is precisely
what the transitive-closure pass exists to catch and what a green suite did not.

## 5. External-call inventory

Every call the kernel can make, and why. There are **six**, and none is generic.

| #   | Site                                                   | Target             | Classification                         | Bound                                                                                                                                                                                         |
| --- | ------------------------------------------------------ | ------------------ | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `ECDSA.recover`                                        | precompile `0x01`  | **authentication**                     | Fixed address, consensus-defined                                                                                                                                                              |
| 2   | `IKernelPQVerifier.verify`                             | `pqVerifier`       | **authentication** (conjunctive plane) | Cannot grant; failure = denial                                                                                                                                                                |
| 3   | `IKernelPolicy.admit`                                  | `policyEngine`     | **other** (subtractive plane)          | **NOW NON-VIEW** (finding F): a `view` boundary is a STATICCALL, so the plane could never persist consumption and a cumulative rule was unrepresentable. Still cannot grant; failure = denial |
| 4   | `recipient.call{value}("")`                            | spend recipient    | **asset operation**                    | **Empty calldata** — value transfer only, never arbitrary execution                                                                                                                           |
| 5   | `guardian.staticcall`                                  | committed guardian | **guardian attestation**               | `STATICCALL` + 30,000 gas cap + one-word returndata copy + non-bubbling                                                                                                                       |
| 6   | `asset.call(transfer)` / `asset.staticcall(balanceOf)` | migration asset    | **asset operation**                    | **Fixed selectors** `0xa9059cbb` / `0x70a08231`, recipient from the binding                                                                                                                   |

**No unexplained external calls.** Sites 4 and 6 are the only ones that move
value, and in both the destination is fixed by the kernel — by the signed
parameters in 4, by the immutable binding in 6.

## 6. Reentrancy — no mutex, and the argument that replaces it

The monolith carries `ReentrancyGuard` on four functions. The prototype carries
none, and that is a decision rather than an omission:

- **`execute`** consumes the nonce **before** the external call. A reentrant call
  needs a signature for `nonce + 1`, which only the credential holder can
  produce — so reentry is _authorized spending_, not an exploit.
- **`egress`** is permissionless **and has no discretion**: the recipient comes
  from the binding, so reentering it can only move more of the vault to the
  destination it was already committed to.
- **Cross-function**: `execute` requires `NORMAL`; once a migration is bound the
  state is `MIGRATION_ONLY`, so the two paths are mutually exclusive by the
  state machine rather than by a mutex.

- **The policy plane is now a NON-VIEW call** (finding F), so it can re-enter.
  It is invoked AFTER the nonce is consumed and BEFORE value moves, so a
  reentrant plane holds nothing it did not already have: a nested `execute`
  needs a signature for `nonce + 1`. A plane that reverts denies, which is the
  already-accepted denial cut of 1.

Exercised by `ReentrantRecipient` in the suite: the re-entrant replay is refused
with `BadNonce` while the outer spend completes.

## 7. What this analysis does NOT establish

1. **No conformance claim.** Nothing here shows the prototype satisfies #179's
   TypeScript reference model; they are independent artifacts.
2. **No audit.** No third party has reviewed this code.
3. **No cryptographic claim about PQ.** The verifier is a mock. Per §4.3a the
   deployed `MockMLDSAVerifier` is structural with _"NO cryptographic
   guarantee"_, so the only claim made is that the PQ leg is a conjunctive
   barrier the kernel requires.
4. **Independence of guardians is assumed, not enforced** (H-31). `k` now counts
   DISTINCT addresses — the canonical-roster rule guarantees that much — but
   three distinct addresses behind one custodian is still **one** root, and no
   on-chain mechanism detects it. Distinctness is necessary, not sufficient.
5. **Slither now runs against this code** (`vNext Kernel / Slither` CI job,
   path-scoped and branch-unrestricted); every finding is triaged firsthand in
   `slither-triage.json` and summarised in `SCANNER_EVIDENCE.json`. No
   sustained security defect was found; every finding is FALSE_POSITIVE,
   ACCEPTED_DESIGN_TRADEOFF, NON_SECURITY_STYLE or OUT_OF_SCOPE_DEPENDENCY.
   **CodeQL has no Solidity extractor** — the `vNext Kernel / CodeQL` job
   covers only this prototype's own JavaScript/TypeScript tooling, never the
   contracts. Neither scanner changes anything below: they are additional
   independent analysis, not a replacement for the authority-closure argument
   this file makes, or a proof that this argument is complete.
6. **A dead PQ verifier now denies spending until a guardian quorum acts.** The
   price of closing A2, stated in section 3.
