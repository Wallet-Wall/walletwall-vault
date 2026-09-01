# Authority-labyrinth conformance — prototype v0 mapped onto PR #179

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**

Measured against #179 at `71aee6f3`. The question this file answers is not
"is the prototype small?" but **"did the prototype silently reduce a minimum cut?"**
A tiny kernel that lowers a cut is a failure, not a success.

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

## 3. Minimum compromise cuts

`n` guardians, `k = floor(n/2) + 1`. Fixture: `n = 3, k = 2`.

| Outcome                    | #179 §24    | Prototype                                                                                               | Verdict                            |
| -------------------------- | ----------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Unauthorized asset control | `min(2, k)` | **`min(2, k)`** — credential path needs both factors under a `requirePq` floor; guardian path needs `k` | **MATCHES**                        |
| Credential replacement     | `min(2, k)` | **`min(2, k)`** — `rotateCredential` needs the credential; recovery needs `k`                           | **MATCHES**                        |
| Guardian takeover          | `k`         | **`k`**                                                                                                 | **MATCHES** — declared trust root  |
| Migration takeover         | `k + 1`     | **`k + 1`** — `bindMigration` requires quorum **AND** credential                                        | **MATCHES**, strictly dominated    |
| Permanent recovery veto    | unreachable | **unreachable** — containment is budgeted (`B < W`), the challenge is capped at 2, and no pause exists  | **MATCHES**                        |
| Silent crypto downgrade    | unreachable | **unreachable — but only after K-15 was added**                                                         | **See §4**                         |
| Denial of spending         | **1**       | **1** — one verifier or one policy plane                                                                | **MATCHES**, accepted and declared |

**No cut is lower in the prototype than in #179 §24.** The migration path is
`k + 1` and never the minimum; the guardian path dominates at `k`, exactly as
§24 says it does.

## 4. The gap this pass found, and what it cost

**Before K-15 the "silent crypto downgrade" cut was `1`, not `unreachable`.**

The first `_authorise` engaged the PQ conjunct only when the caller passed a
non-empty signature:

```solidity
if (pqSig.length != 0) { ...consult the verifier... }   // WRONG
```

So a caller holding **only** the ECDSA key could hand in an empty blob and be
authorized under a vault whose declared posture was HYBRID. The downgrade needed
no state transition, so §12's partial order had nothing to refuse — the weakening
went through the **argument list**.

**Cut before: 1** (the credential alone, which the design already assumes may be
compromised in the scenario recovery exists for).
**Cut after: unreachable** — `requirePq` lives in the kernel, `_authorise` reads
it rather than the caller, and `_requireNoDowngrade` refuses every weakening
transition outright. Measured cost: **+1,199 bytes** (13,140 → 14,339).

> **How it was found matters as much as the fix.** Every test passed. The suite
> had a positive control, mutants for the verifier plane, and an explicit
> "always-true verifier is not a sole authenticator" discriminator — and all of
> them were satisfied, because they all supplied a PQ signature. **The defect
> lived in the path nobody tested: the one where the attacker declines to.**
> Mapping the implementation back onto the authority model, outcome by outcome,
> is what surfaced it. That is why §179 requires the mapping rather than treating
> a green suite as conformance.

## 5. External-call inventory

Every call the kernel can make, and why. There are **six**, and none is generic.

| #   | Site                                                   | Target             | Classification                         | Bound                                                                       |
| --- | ------------------------------------------------------ | ------------------ | -------------------------------------- | --------------------------------------------------------------------------- |
| 1   | `ECDSA.recover`                                        | precompile `0x01`  | **authentication**                     | Fixed address, consensus-defined                                            |
| 2   | `IKernelPQVerifier.verify`                             | `pqVerifier`       | **authentication** (conjunctive plane) | Cannot grant; failure = denial                                              |
| 3   | `IKernelPolicy.check`                                  | `policyEngine`     | **other** (subtractive plane)          | Cannot grant; failure = denial                                              |
| 4   | `recipient.call{value}("")`                            | spend recipient    | **asset operation**                    | **Empty calldata** — value transfer only, never arbitrary execution         |
| 5   | `guardian.staticcall`                                  | committed guardian | **guardian attestation**               | `STATICCALL` + 30,000 gas cap + one-word returndata copy + non-bubbling     |
| 6   | `asset.call(transfer)` / `asset.staticcall(balanceOf)` | migration asset    | **asset operation**                    | **Fixed selectors** `0xa9059cbb` / `0x70a08231`, recipient from the binding |

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
4. **Independence of guardians is assumed, not enforced** (H-31). `k` counts
   addresses. Three guardians behind one custodian is **one** root, and no
   on-chain mechanism here detects that.
