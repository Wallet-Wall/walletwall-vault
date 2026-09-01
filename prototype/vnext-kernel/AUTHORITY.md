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
| Unauthorized asset control | `min(2, k)`      | **1** (A1, A2)           | **`min(2, k)`** | `execute`, `rotateCredential`, `setVerifier` and `setPolicy` all call `_authorise` — the ECDSA conjunct **AND** the PQ conjunct. M-K28, M-K29       |
| Credential replacement     | `min(2, k)`      | **1** (A1)               | **`min(2, k)`** | rotation is HYBRID-authorised and additionally requires possession of both INCOMING factors. M-K28, M-K34                                           |
| Guardian takeover          | `k`              | **1** (B)                | **`k`**         | `I-QUORUM-PRINCIPAL-DISTINCTNESS`: the committed roster must be strictly ascending by address, so `k` seats are `k` PRINCIPALS. M-K30, M-K31, M-K32 |
| Migration takeover         | `k + 1`          | `k + 1`                  | **`k + 1`**     | `bindMigration` requires quorum **AND** credential. Unchanged                                                                                       |
| Permanent recovery veto    | unreachable      | unreachable              | **unreachable** | containment budgeted `B < W`; challenge capped; no pause exists                                                                                     |
| Silent crypto downgrade    | unreachable      | **1** (A2)               | **unreachable** | `setVerifier` is HYBRID; the floor may only strengthen; the escape from a dead verifier is the GUARDIAN quorum, not one factor                      |
| Vault identity takeover    | _(not modelled)_ | **1** (C)                | **unreachable** | `I-COUNTERFACTUAL-IDENTITY-BINDING`: the CREATE2 salt binds the complete genesis authority. M-K33                                                   |
| Credential stranding       | _(not modelled)_ | **1** (D)                | **unreachable** | `I-INCOMING-CREDENTIAL-POSSESSION` on both rotation and recovery. M-K34, M-K35                                                                      |
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
5. **Slither and CodeQL have NEVER run against this code.** Neither is available
   in this environment and neither fires on a PR based on a design branch. That
   is recorded as absent evidence, not as a pass.
6. **A dead PQ verifier now denies spending until a guardian quorum acts.** The
   price of closing A2, stated in section 3.
