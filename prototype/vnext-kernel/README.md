# vNext Minimal Trust Kernel — prototype v0

> # EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT · DO NOT MERGE INTO MAIN
>
> A measurement prototype for the architecture adjudicated in **PR #179**
> (`design/vault-vnext-trust-architecture`, head `71aee6f3`). It exists to answer
> one question and produce numbers. It is **not** a production specification, has
> **no** audit, **no** fuzzing campaign and **no** formal verification, and
> nothing here has been or may be deployed.
>
> **This tree is OUTSIDE the production Hardhat compilation unit** — see
> _Compilation boundary_ below. `contracts/` is untouched.

## The question

> Can the Assured Minimal Trust architecture be expressed as an actually small,
> clone-safe, understandable kernel **without silently re-importing the
> monolith's authority**?

## The answer

**Yes on size. On authority — only after TWO rounds of correction, the second
prompted by an independent review that reproduced four one-root paths to total
loss against this exact kernel.**

> ### The first verdict on this prototype was WRONG
>
> Head `79e05a34` published `KERNEL_PROTOTYPE_PASSES_ARCHITECTURE` on a
> minimum-cut table that did not survive review. Findings A1, A2, B and C were
> each REPRODUCED against the compiled kernel, carried through to a drained
> vault or a stolen identity, and only then fixed. The verdict was **withdrawn**
> and re-earned. `AUTHORITY.md` §0 keeps the failed claims rather than deleting
> them.

|                                                   | runtime    | vs budget 24,576         | vs target ceiling 21,976        |
| ------------------------------------------------- | ---------- | ------------------------ | ------------------------------- |
| `WalletWallVault` (current monolith)              | 23,239     | pass, headroom 1,337     | **FAIL by 1,263**               |
| Mechanically clone-targeted monolith (#179 §19.1) | 23,249     | pass, headroom 1,327     | **FAIL by 1,273**               |
| `VaultKernelPrototype` at `79e05a34` (WITHDRAWN)  | 14,339     | pass                     | pass — but the cuts were wrong  |
| `VaultKernelPrototype` (findings A-E remediated)  | 17,407     | pass, headroom 7,169     | TARGET PASS, headroom 4,569     |
| `VaultKernelPrototype` (SD-1 remediated)          | 17,622     | pass, headroom 6,954     | TARGET PASS, headroom 4,354     |
| **`VaultKernelPrototype` (SD-3 remediated)**      | **17,806** | **pass, headroom 6,770** | **TARGET PASS, headroom 4,170** |

**23.4% smaller than the monolith** — 5,433 bytes — and still the only one of the
three to clear the internal target. The factory adds **2,226** bytes, once per
generation. Remediating findings A-E cost **+3,068** bytes; per-fix attribution is
in `AUTHORITY.md` §4 and reproducible with `deltas.ts`. Remediating **SD-1** with
`I-FLOOR-SHAPE-IMMUTABLE` cost a further **+215**, and closing **SD-3** with `I-DECLARATION-EXHIBITED`
another **+184** — every one with the storage layout byte-identical and the ABI
change additive only.

**Authority surface**, which is the part that actually matters:

|                        | state-changing functions | global admin                                                  |
| ---------------------- | ------------------------ | ------------------------------------------------------------- |
| `WalletWallVault`      | **28**                   | `pause` · `unpause` · `transferOwnership` · `acceptOwnership` |
| `VaultKernelPrototype` | **13**                   | **none — the principal does not exist**                       |

## What produced the difference

Not compression. Fourteen responsibilities were admitted by rule
(`KERNEL_ADMISSION.md`); the rest were excluded because their failure yields
**denial** or is **restorable**, so R-KERNEL does not admit them:

| Excluded                                            | Where it went                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------- |
| `mapping(owner => Vault)` and all per-tenant keying | dissolved — the clone address **is** the identity                         |
| `pause` / `unpause` / `Ownable2Step`                | deleted — no global admin exists                                          |
| Large-tx queue + timelock, treasury quorum          | a spending **policy**, not a custody invariant → PLANE                    |
| Verifier propose/apply timelock                     | governance _timing_; the **authority** (K-14) is kernel, the delay is not |
| Guardian roster storage (`n` address slots)         | **G-B**: 3 words of commitment; roster is validated calldata              |
| OZ `EIP712` (ShortStrings, 7 immutables)            | replaced by a constant-based, immutable-free domain                       |
| `ReentrancyGuard`                                   | replaced by an argument (`AUTHORITY.md` §6), not by omission              |

## The findings — two rounds, and what each cost

**Round 1 (authored here).** `_authorise` engaged the PQ conjunct only when the
CALLER supplied a non-empty signature — a downgrade through the argument list.
Closed by admitting **K-15**, the kernel-recorded cryptographic floor. **+1,199 B.**

**Round 2 (independent review).** Every claim below was REPRODUCED against the
compiled kernel, carried through to a drained vault or a stolen identity, and
only then fixed:

| #      | The attack, carried through to the end state                                                                                                 | Fix                                                                                                               |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **A1** | ECDSA-only attacker rotates **both** factors, then drains 10 ETH                                                                             | rotation is HYBRID-authorised — **−75 B**, the fix was _free_                                                     |
| **A2** | ECDSA-only attacker installs an ALWAYS-TRUE verifier with the floor untouched, then spends with the **public** PQ key and a forged signature | `setVerifier` is HYBRID; the escape from a dead verifier moves to the **guardian quorum**, which recovery carries |
| **B**  | roster `[A, A, B]`, threshold 2 — ONE principal signs at indices 0 and 1, reaches quorum, recovers, drains                                   | canonical roster: strictly ascending by address — **+186 B**                                                      |
| **C**  | attacker occupies the user's `predictVault` address with their own signer and guardian set                                                   | the CREATE2 salt binds the complete genesis authority — in the factory                                            |
| **D**  | rotation installs a credential nobody holds; the vault is stranded                                                                           | incoming possession proven for both factors — **+725 B**                                                          |
| **E**  | 1 ETH sent to the implementation, accepted                                                                                                   | the CLAIM was corrected, not the code                                                                             |
| **F**  | two 1 ETH spends both pass a 1.5 ETH cumulative cap                                                                                          | the policy boundary becomes a non-`view` **admission** call                                                       |

> **Why 55 green tests missed all of it.** Every existing test exercised a path
> where the attacker COOPERATES — supplying a PQ signature, using distinct
> guardians, deploying at a fresh salt. None asked what an attacker _declines_ to
> do, and none followed a governance transition through to the asset movement it
> enables. **A dangerous setter returning success is not a finding; the drained
> vault is.** Every discriminator added in round 2 ends at a balance check.

> **And K-15 shows why the closure pass was necessary at all.** Round 1 made the
> PQ conjunct mandatory _where `_authorise` was called_ — and the three
> governance paths were not calling it. **Closing a hole in a helper does not
> close the paths that bypass the helper.**

## Layout

```text
prototype/vnext-kernel/
  README.md               this file
  KERNEL_ADMISSION.md     which responsibilities enter the kernel, and why
  AUTHORITY.md            authority graph, closure, minimum cuts, call inventory
  hardhat.config.ts       ISOLATED build — separate sources/artifacts/cache
  measure.ts              size verdicts from compiled artifacts
  reproduce.ts            independent solc rebuild + storage layout + selectors
  decompose.ts            K0..K6 byte attribution (diagnostic only)
  deltas.ts               per-FIX byte attribution for the closure remediation
  contracts/
    VaultKernelPrototype.sol         the kernel
    VaultKernelFactoryPrototype.sol  one immutable factory per generation (D8)
    PrototypeMocks.sol               adversaries and controls, test-only
    interfaces/IKernelPlanes.sol     the two plane boundaries
  test/
    connection.ts
    KernelPrototype.test.ts          M-K01..M-K27 (migrated to the remediated API)
    KernelAuthorityClosure.test.ts   M-K28..M-K37 — the independent closure review
```

## Running it

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test
npx tsx prototype/vnext-kernel/measure.ts
npx tsx prototype/vnext-kernel/reproduce.ts
npx tsx prototype/vnext-kernel/decompose.ts
```

## Build settings, pinned

```text
solc        0.8.24+commit.e11b9ed9
evmVersion  cancun
optimizer   enabled, runs 200
viaIR       false
```

Identical to the production config, so every byte figure is comparable to the
monolith's without a compiler caveat. **`viaIR` stays off**: turning it on to
escape a stack-too-deep would have made the comparison meaningless. The kernel
groups its guardian proof into a calldata struct instead.

**Reproducibility, verified:** `reproduce.ts` drives the pinned solc directly
from sources on disk and produces bytecode **byte-identical** to the Hardhat
artifact — same length _and_ same `sha256`. Getting the second half of that right
required reproducing Hardhat 3's source-key scheme (`project/…`, `npm/pkg@ver/…`)
exactly, because solc hashes the metadata JSON — which contains those keys — into
a CBOR blob appended to the runtime code. A build that matches on length and not
on hash is not a reproducible build.

## K0–K6 byte attribution

Diagnostic only. Each level is the full kernel with later responsibilities
ablated; storage and getters are held constant, so a delta is the cost of
**logic**. Only K6 is a candidate.

```text
K0  identity + initialization                       2,998
K1  + execution / floor auth / replay               5,404   +2,406
K2  + guardian commitment + quorum                  7,580   +2,176
K3  + recovery                                      9,552   +1,972
K4  + full safe-state machine                      10,300     +748
K5  + migration                                    12,598   +2,298
K6  + rotation, governance, no-downgrade  [FULL]   14,339   +1,741
```

## Measured code identity

| Property                                                     | Result                                 |
| ------------------------------------------------------------ | -------------------------------------- |
| implementation runtime                                       | **14,339** bytes                       |
| implementation initcode                                      | **14,380** bytes                       |
| `immutableReferences`                                        | **0** — `I-PURE-CONSTRUCTOR` satisfied |
| two deployments of identical source                          | **byte-identical**                     |
| artifact `deployedBytecode` hash `==` on-chain `extcodehash` | **yes**                                |
| clone runtime                                                | **53** bytes (45 template + 8 args)    |
| implementation address recoverable from clone code           | **yes**                                |
| CREATE2 prediction `==` deployed address                     | **yes**                                |
| declared storage slots                                       | 11 (+3 recovery, +3 migration)         |
| selectors                                                    | 40 — **13 state-changing**             |

## Static analysis coverage

| Scanner     | Status                                                                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **solhint** | **RUN in CI** (`vNext Kernel / Prototype Tests`) — 32 warnings, 0 errors                                                                                                                                     |
| **Slither** | **RUN in CI** (`vNext Kernel / Slither`, path-scoped, branch-unrestricted) — every finding triaged firsthand in `slither-triage.json`; see `SCANNER_EVIDENCE.json` for the receipt                          |
| **CodeQL**  | **RUN in CI** (`vNext Kernel / CodeQL`) for the prototype's own JavaScript/TypeScript tooling ONLY — GitHub CodeQL has **no Solidity extractor**, so this is not, and cannot be, Solidity security analysis |

**No claim of Solidity semantic scanner coverage is made.** Slither's own
coverage is bounded by what its detectors can express — see `AUTHORITY.md`
section 7 for what this analysis does not establish, independent of any
scanner. The real security argument for this kernel remains the
authority-closure analysis in `AUTHORITY.md` and the adversarial tests it
cites, not scanner cleanliness.

## Non-goals

Not upgradeable · not ERC-7579 · not ERC-4337 in generation 1 · not a modular
smart account · **not a claim about PQ cryptography**: the verifier is a mock,
and per #179 §4.3a the deployed `MockMLDSAVerifier` is structural with _"NO
cryptographic guarantee"_. The only claim made is that the PQ leg is a
**conjunctive barrier the kernel requires**.

## Compilation boundary

The production Hardhat config compiles `contracts/` → `artifacts/` and runs
`test/`. This config compiles `prototype/vnext-kernel/contracts/` →
`prototype/vnext-kernel/artifacts/` and runs `prototype/vnext-kernel/test/`. They
share **no** source, artifact or cache path. `prettier`, `solhint`, `tsc` and the
production test glob all scope to `contracts/`, `{src,scripts,test,pqc}` — none
reaches `prototype/`. That is what keeps production runtime-byte claims,
deployment manifests and reproducibility evidence untouched by this experiment,
and it is verified rather than assumed: `git diff origin/main -- contracts/` is
empty and every production validator is re-run unchanged.
