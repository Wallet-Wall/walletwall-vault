# vNext kernel authority-path completeness

> EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION.

Turns the authority model `AUTHORITY.md` argues in prose into an executable
check: every externally reachable state-changing function in
`VaultKernelPrototype`/`VaultKernelFactoryPrototype` must be classified, its
declared authorization mechanism must actually be reached in the compiled
source, and that reach must occur *before* any privileged effect. It exists
to make one specific failure class structurally hard to reintroduce:

> a correct authorization helper, with a privileged externally reachable
> path that bypasses it.

That is exactly what the prototype's round-2 review found and fixed
(`AUTHORITY.md` section 0, findings A1/A2): `_authorise` was correct
everywhere it was called; `rotateCredential`/`setVerifier` simply didn't
call it. Slither and CodeQL (the independent-analysis lane this stacks on,
PR #182) cannot see this class of defect — a pattern-matching detector has
no notion of "the architecture's own authority model," and neither scanner
found anything wrong with the withdrawn `79e05a34` head. This checker is a
different, complementary assurance authority, not a replacement for either.

## What is independently DERIVED vs. declared

| Component | Status | How |
| --- | --- | --- |
| External state-changing surface (`discover.ts`) | **Independently derived** | Walks the compiled Solidity AST's own `ContractDefinition`/`FunctionDefinition` nodes — visibility, mutability, selector, modifiers — never grep, never a remembered function list. A new or renamed function is found by the SAME code path that finds every existing one. |
| Gate/effect classification and ordering (`trace.ts`) | **Independently derived** | Ground truth is solc's own `stateMutability` proof: a `view`/`pure` callee provably cannot write state (the compiler already enforces this). Gate primitives are identified by resolved AST declaration id, never by name string, so a same-named shadow cannot spoof one. Statement order is source order. |
| Outcome taxonomy, expected mechanism, expected cut (`authority-manifest.json`) | **Declared** | A human classification, cross-checked against the derived facts above but not derivable from them — "this outcome requires `min(2,k)`" is an architecture decision, not a compiler fact. Every entry cites the `AUTHORITY.md` section it comes from. |
| Ordering exceptions | **Declared, source-bound** | Only used where the static ordering pass cannot resolve a genuine control-flow shape (see "Known limitations"); each one names the exact construct, argues why it's safe, and points at the mutation test that independently covers the risk it can't statically prove. |
| Historical/adversarial mutation survival | **Empirical** | `test/AuthorityCompletenessMutations.test.ts` compiles real mutated copies of the source (never the tracked files) and asserts the checker's actual verdict — not argued, run. |

## Outcome taxonomy

The smallest set that faithfully covers this kernel's actual privileged
effects (not the mission's superset merely for completeness — see the PR
description for what was and wasn't needed):

`ASSET_MOVEMENT · CREDENTIAL_REPLACEMENT · VERIFIER_REPLACEMENT ·
POLICY_CHANGE · GUARDIAN_CHANGE · RECOVERY_START · RECOVERY_CANCEL ·
RECOVERY_COMPLETION · MIGRATION · CONTAINMENT_OR_SAFE_STATE_CHANGE ·
COUNTERFACTUAL_IDENTITY_CREATION · GENESIS_AUTHORITY_CREATION`

`RECOVERY_CANCEL` is the one addition beyond the mission's suggested list:
`cancelRecovery`'s bounded-veto behavior (`I-VETO-BOUND`) is neither a
"start" nor a "completion" and has its own distinct, intentionally weaker
authority model — collapsing it into either neighbor would misrepresent it.

## Mechanism vocabulary

Four primitives, resolved once by AST id from `VaultKernelPrototype`
(`internal` visibility means no other contract, including the factory, can
ever reach them regardless of import — so the factory's own entries
correctly show zero mechanisms, not an error):

| Mechanism | Primitive | What it proves |
| --- | --- | --- |
| `HYBRID` | `_authorise` | ECDSA **and**, when the recorded floor requires it, the PQ verifier |
| `FLOOR_ONLY` | `_floorAuthorises` | ECDSA alone — used directly outside `_authorise` in exactly two places, both a declared, bounded exception (`cancelRecovery`'s veto; `bindMigration`'s dual-principal requirement) |
| `QUORUM` | `_requireQuorum` | guardian quorum, distinct principals (`I-QUORUM-PRINCIPAL-DISTINCTNESS`) |
| `POSSESSION_PROOF` | `_requireIncomingPossession` | the caller genuinely holds the incoming credential material (finding D) |

A function's `expectedMechanisms` is the SET that must each be reached
*before* the function's first privileged effect — order matters as much as
presence (PHASE 8).

## Known limitations (declared, not hidden)

1. **A hand-inlined equivalent of a gate, never calling the named
   primitive, is not distinguished from "no check at all."** The checker
   cannot prove semantic equivalence between two different code shapes — it
   can only prove whether a call was routed through one of the four named,
   audited primitives. This is a *safe* limitation, not a silent gap: such
   inlining is rejected as `MECHANISM_MISMATCH` (see the "hand-inlined
   equivalent" mutation test), forcing explicit re-review rather than
   passing silently. It could, in principle, also reject a legitimate
   equivalent refactor — that tradeoff is deliberate.
2. **Complex control flow is UNRESOLVED, not analyzed.** The static
   ordering pass only understands: sequential statements; `Block`/
   `UncheckedBlock` lexical nesting (transparent, no branching); and the
   single `if (!cond) revert ...;` guard idiom. Anything else — loops,
   `if`/`else`, a true-body with more than a bare revert, `try`/`catch`,
   inline assembly — is reported `UNRESOLVED` and requires either a
   declared `orderingExceptionReason` (source-bound, specific, minimal —
   see three examples in `authority-manifest.json`) or the check fails.
   Fails closed; never silently assumed safe.
3. **No inheritance support beyond "prove there is none."**
   `discover.ts` throws if either contract's `baseContracts` becomes
   non-empty, rather than silently missing an inherited function. Neither
   contract inherits today.
4. **Selector collisions are not defended against.** Keying by 4-byte
   selector (not full signature) means a hash collision between two
   different signatures would be missed — cryptographically implausible,
   noted for completeness.

## Running it

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx tsx prototype/vnext-kernel/authority/check.ts
npx tsx prototype/vnext-kernel/authority/check.ts --out prototype/vnext-kernel/AUTHORITY_CENSUS.json
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test   # includes AuthorityCompletenessMutations.test.ts
```

Exit code 0 only if every discovered state-changing function is classified,
every expected mechanism is observed before any effect, and no manifest
entry is stale or malformed.

## Adding a new privileged function

1. Implement it.
2. Recompile and run `check.ts` — it fails with
   `UNCLASSIFIED_EXTERNAL_STATE_CHANGE` naming the new
   `Contract:selector`.
3. Add a manifest entry: outcome(s) from the taxonomy above (extend it only
   if truly needed), the mechanism(s) the implementation actually reaches,
   the minimum cut re-derived from the implementation (not copied from a
   neighboring row), and a `justification` citing where in `AUTHORITY.md`
   or the implementation this comes from.
4. Re-run `check.ts`. If it reports `UNRESOLVED_ORDERING_NO_EXCEPTION`,
   either simplify the function's control flow or add a specific,
   source-bound `orderingExceptionReason` — never a blanket one.
5. If the new function changes an existing minimum-cut claim, update
   `AUTHORITY.md`'s own table too — this manifest should never silently
   diverge from the prose it's meant to make executable.
