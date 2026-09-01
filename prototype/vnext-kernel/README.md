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

**Yes on size, and yes on authority — but only after the authority pass found a
defect the tests did not.**

|                                                   | runtime    | vs budget 24,576          | vs target ceiling 21,976        |
| ------------------------------------------------- | ---------- | ------------------------- | ------------------------------- |
| `WalletWallVault` (current monolith)              | 23,239     | pass, headroom 1,337      | **FAIL by 1,263**               |
| Mechanically clone-targeted monolith (#179 §19.1) | 23,249     | pass, headroom 1,327      | **FAIL by 1,273**               |
| **`VaultKernelPrototype` (this lane)**            | **14,339** | **pass, headroom 10,237** | **TARGET PASS, headroom 7,637** |

**38.3% smaller than the monolith** — 8,900 bytes — and the first of the three to
clear the internal target at all. The factory adds **1,642** bytes, once per
generation.

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

## The finding

**The authority-closure pass found a live downgrade path that every test missed.**

The first `_authorise` engaged the PQ conjunct only when the _caller_ supplied a
non-empty signature. Anyone holding the ECDSA key alone could pass an empty blob
and be authorized under a vault whose declared posture was HYBRID — a silent
downgrade reached through the **argument list**, so §12's partial order had no
transition to refuse. The suite was green throughout: every test supplied a PQ
signature, so none exercised the path where an attacker declines to.

Fixed by admitting **K-15**, the kernel-recorded cryptographic floor (#179 §4.3
component 2), which #179 classifies kernel-resident and the first draft of the
manifest omitted. `requirePq` is now the kernel's decision; `_requireNoDowngrade`
refuses every weakening transition. Cost **+1,199 bytes**. Discriminated by
**M-K26** and **M-K27**. Full write-up in `AUTHORITY.md` §4.

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
  contracts/
    VaultKernelPrototype.sol         the kernel
    VaultKernelFactoryPrototype.sol  one immutable factory per generation (D8)
    PrototypeMocks.sol               adversaries and controls, test-only
    interfaces/IKernelPlanes.sol     the two plane boundaries
  test/
    connection.ts
    KernelPrototype.test.ts          55 tests, M-K01..M-K27
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
