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

**SD-3 AND SD-4 ARE NOW REMEDIATED TOO, on `security/vnext-sd3-sd4-authentication-satisfiability`, and re-deriving them corrected the record in three places.**

| Finding  | Claim it falsified                                   | Reproduced end state                                                                                                                                     | Real cut was |
| -------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| **SD-3** | `credential stranding = unreachable` (via the FLOOR) | one root armed `requirePq` against material that cannot satisfy it, and every credential path then died on a conjunct with no preimage                    | **1**        |
| **SD-4** | `permanent recovery veto = unreachable`              | the same edge added a whole authentication conjunct to an ALREADY-approved recovery, destroying it with `challengesUsed == 0` and the request left active | **1**        |

Both are closed by two INDEPENDENT clauses on that one edge —
**`I-DECLARATION-EXHIBITED`** and **`I-DECLARATION-SUBORDINATE-TO-LIVE-RECOVERY`**.
The prior lane's hypothesis that closing SD-4 "necessarily intersects" SD-3 is
**refuted**: the exhibit binds `pqPublicKeyHash` while SD-4 is about
`recovery.proposedPqKeyHash`, and in the reproduced counterexample the declared
key length matches the incumbent EXACTLY, so the exhibit passes on both conjuncts
and only the interlock refuses.

Three recorded claims were wrong, and are corrected here rather than quietly
dropped. SD-3's title said "permanently bricking" while its own
`notAnEscalationBecause` said "escapable at k" — the field was right. SD-3's
`minimalFixSketch` proposed a zero-hash check that a NON-ZERO commitment defeats
unchanged, so implementing the ledger's own sketch would have shipped a fix that
left the defect open. And the asset-control, crypto-downgrade and
credential-stranding rows in section 3 all lacked the ECDSA-only scope caveat
they needed.

**SD-2 remains SUSTAINED, and the remediation's own residuals are recorded as
SD-5 (permanent shape capture on the declaring edge) and SD-6 (unattested
commitment install while `requirePq` is false).**

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
| Credential stranding       | _(not modelled)_ | **1** (D)                | **unreachable while `requirePq` holds** | `I-INCOMING-CREDENTIAL-POSSESSION` on both rotation and recovery. M-K34, M-K35. **SCOPE, previously missing:** `_requireIncomingPossession` returns before every PQ check while `requirePq` is false, so on an ECDSA-only floor BOTH paths install a PQ commitment attested by nothing — recorded as **SD-6** |
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
