# SD-11 implementation — `G-VERIFIER-ADMISSION-PROVENANCE`

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> Implementation lane for the owner decision on verifier admission. Production
> Solidity (`contracts/`) is unchanged, `WalletWallVault.sol` is untouched, no
> production verifier's behaviour changes, and nothing is deployed, pushed or merged.

## 0. The decision implemented, and the property claimed

**Owner decision (fixed, not reopened):** Generation 1 MUST only admit verifiers whose
accepting relation is fixed after deployment and whose implementation provenance is
mechanically established. Generation 1 does NOT promise safe admission of arbitrary
verifier implementations.

**Invariant:** a verifier may become ACTIVE only if (1) it belongs to a
Generation-1-approved implementation class, (2) its accepting-relation configuration is
immutable after deployment, (3) that fact is mechanically attributable rather than
documentary, and (4) every path that can change the active verifier applies the same check.

**Inherited evidence** (`SD11_VERIFIER_ADMISSION_ADJUDICATION.md`, frozen as commit
`4b887e81`): SD-11A — the interface represents multiple accepting relations and such a
verifier is admissible and reduces the cut; SD-11B — the real `AttestationPQCVerifier`
changes its relation behind a stable address and codehash; `ImmutableAttestationPQCVerifier`
is the positive control; `ZKMLDSAVerifier` is NOT ESTABLISHED. None of it is re-proven here.

## 1. Commits (local, branch `security/vnext-sd11-verifier-admission-provenance`)

| Commit | Role | Solidity |
| --- | --- | --- |
| `4b887e81` | the adjudication lane, frozen exactly as found (six files, hashes verified) | none |
| `7cf73a07` | RED-0: `test/Sd11VerifierAdmissionProvenance.test.ts` only | none |
| `cc427baf` | RED-1: provenance root, class copy, factory binding, fixture, harness — **no enforcement** | kernel executable prefix unchanged |
| `b058715b` | GREEN: enforcement at the three admission edges | kernel +269 B |
| `40ba7059` | comment-only move of prose into NatSpec (solhint `function-max-lines`) | executable prefix identical |

The ledger/triage reconciliation, the scanner receipt and the measurements follow in
separate commits, on the repository's two-subject evidence protocol.

## 2. RED, then GREEN

**RED-0 — tests only, zero Solidity** (`7cf73a07`): **0 passing / 17 failing** (16 tests plus
the M7 hook). Every failure is the missing mechanism: 14 on the absent provenance-root
artifact, one on the absent class copy, the M6 AST census finding no admission check on any
edge (a genuine assertion failure), and the M7 hook finding no mutant anchor.

**RED-1 — scaffolding, kernel logic unchanged** (`cc427baf`; the kernel's 17,642-byte
executable prefix still hashes to `c9566975…`, the value lane SD5-I recorded):
**6 passing / 11 failing**. Each failure is a hostile artifact **ADMITTED** where refusal is
required — M1, M2, M3 at genesis; M3 with the vault's own attestor; M5-A, M5-B, M5-C; M5-E
(a rootless clone did not fail closed); M6 recovery re-proposal — plus the census and the
M7 anchors. This is the "current kernel admits it" evidence for every mutant class.

**GREEN** (`b058715b`): **24 passing / 0 failing**; every M7 mutant killed.

| Mutant | Previous behaviour | Required | First failing assertion (RED) | Discrimination guard |
| --- | --- | --- | --- | --- |
| **M1** arbitrary code (`DestinationStub`) | admitted at every edge | refused at every edge | "GENESIS must refuse the artifact": `ADMITTED` vs `InadmissibleVerifier` | positive control per edge on the same vault; the ungated fixture still admits it |
| **M2** dual-relation fixture | admitted; weak leg spends | refused; weak leg still accepts | same, at genesis | M7-K1/K2/K3; K2 restores the ECDSA-only spend |
| **M3** real `AttestationPQCVerifier` | admitted; owner rotates relation | refused; owner can still rotate | same; and "expected 'ADMITTED' to equal 'InadmissibleVerifier'" with the vault's own attestor | `updateAttestor` asserted to work after refusal |
| **M4** root-created `ImmutableAttestationPQCVerifier` | (admitted — trivially) | admitted end to end, immutable, exact class | failed at RED-0 (no root) | opcode sweep flags SSTORE / DELEGATECALL / SELFDESTRUCT on three controls; exact-class comparison fails against the mutable class |
| **M5** counterfeits | identical-codehash copy, self-asserter and counterfeit root all admitted; rootless clone initialised | all refused; rootless clone fails closed | "expected 'ADMITTED' to equal 'InadmissibleVerifier'" | M7-K4 (self-assertion), M7-K5 (fail-open), M7-A1/A2 (weakened roots) |
| **M6** path completeness | no check at any edge | one check per edge, on the written value, before the write | census "expected [] to deeply equal […]" | census re-run on each K-mutant loses exactly its edge |
| **M7** seven mutants | n/a (anchors absent) | each killed on the hostile verifier observed ACTIVE | hook: "expected exactly 1 occurrence … found 0" | kill credit only on `pqVerifier == hostile`; live kernel refuses the same sequence |

## 3. Deriving the smallest mechanism (Phase I2)

Two measured facts decided the space before any design was preferred:

1. The kernel has **no immutables** by design (`I-PURE-CONSTRUCTOR`), so it cannot learn a
   registry through constructor state. The only per-clone, code-level, non-storage channel is
   the ERC-1167 **clone immutable args**, which already carry the generation.
2. Every other suite admits mock verifiers at every edge, so any correct gate either lets a
   generation deployment choose its root, or evicts every mock-verifier suite from the real
   kernel and factory.

| Candidate | Provenance forgeable? | Semantics mutate after admission? | Human principal? | Config bound? | Storage | Bytes | ABI / creation | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Status quo: `code.length != 0` | yes, any code | yes (SD-11B C4) | none | no | 0 | 0 | none | the defect |
| EXTCODEHASH pin at admission | no for code | **yes**: storage (C4), delegate (D1); an identical-codehash copy passes (M5-A) | none | code only | +1 word, +1 in request | ~+100 | none | **rejected**, refuted by execution |
| Owner/governance registry | n/a | depends on curator | **yes** | curator's choice | ≥1 | — | new admin ABI | **forbidden** |
| Class skeleton hash in the kernel (mask immutables) | no | no | none | admits non-constructor immutables | 0 | ~+300 | none | **rejected**: pins one compilation incl. metadata; evicts every mock suite |
| CREATE2 recomputation, no record | **collision route**: "could produce" ≠ "did produce" | no | none | attestor via salt | 0 | large (class initcode) | extra input or verifier callback | **rejected** |
| Root in `GenesisConfig` | per-vault choice | — | deployer per vault | — | +1 | — | salt/ABI break | **rejected**: a generation could not promise what it admits |
| Root as kernel immutable | no | no | none | yes | 0 | small | — | **rejected**: violates `I-PURE-CONSTRUCTOR` |
| Root created inside the factory's code | no | no | none | yes | 0 | factory +~4 KB | ctor unchanged | sound; **not chosen**: evicts mock suites, and the factory's code already names the root via its immutable |
| Existing kernel factory as the root | no | no | none | yes | factory +1 | factory +~4 KB | couples vault and verifier creation | **rejected**: same eviction, more coupling |
| Provenance recorded in the verifier | **self-asserted** unless CREATE2-recomputed | — | none | — | — | — | modifies the class | **rejected**: production class must stay identical |
| **CHOSEN** — fixed-class root, recorded at CREATE2; bound per generation in clone args; checked at three edges | **no** (M5-A/B/C) | **no** (M4) | **none after construction** (D8 residual) | attestor = CREATE2 salt, immutable in code | kernel 0; root 1 mapping | kernel +269; factory +106; root 4,196 | kernel +1 error; factory ctor +1 arg, +1 getter; clone 53 → 73 B | **adopted** |

"Deployed by X" is sufficient here only because X's **code** fixes what X can deploy: the root
contains exactly one creation site for one class and no other writer of its record, and M7-A1
and M7-A2 show that one extra writer — with no curator at all — reopens SD-11A.

## 4. The mechanism, exactly

**Legitimate provenance** is `isAdmissibleVerifier[v] == true` on the root bound in the
vault's own clone args, which is true exactly when that root's `deployVerifier` created `v`.

**Why it cannot be self-asserted.** The kernel never asks the candidate (M7-K4 kills the
variant that does); the root's answer is written only after its own CREATE2 succeeded; the
root is read from the clone's CODE, so no transaction of the vault can move it (M5-D); and a
counterfeit root, however exact its ABI, is a different address the vault does not name (M5-C).
A byte-identical, identically configured, working copy of an admitted verifier — same
EXTCODEHASH — is refused (M5-A).

**Configuration bound.** The attestor is the CREATE2 salt and an `immutable` of the class: two
attestors cannot share an address and an existing verifier cannot be re-created.

**Immutable, and measured as such.** The class has no writing ABI entry and its runtime has no
SSTORE, DELEGATECALL, CALLCODE, CALL, CREATE, CREATE2 or SELFDESTRUCT instruction (a linear
sweep, the decoding the EVM uses for JUMPDEST analysis). The root holds no power over any
verifier it created. The factory's binding is `immutable`.

**Not proven.** That the class exposes ONE accepting relation is a review of one contract, not
an on-chain proof. The class's single STATICCALL target is stack-supplied in the bytecode and
attributed to the ecrecover precompile by source. Nothing about the attestor's honesty. Nothing
about key well-formedness or possession (SD-8). The relation's environment inputs —
`block.timestamp` for the attestation deadline and `block.chainid` in its domain — are fixed
rules over the environment, not mutation paths.

**New trust root.** One contract, `ImmutableAttestationVerifierFactoryPrototype`, whose CODE is
the Generation-1 verifier class boundary. It has no principal. Which root a factory binds is a
one-shot construction choice of the same kind D8 already makes for the implementation.

## 5. Authority analysis

| Question | Answer |
| --- | --- |
| New owner? | **No.** |
| Curator? | **No.** |
| Mutable registry? | **No** human-mutable one. The root's record is append-only and written only by its own creation of the fixed class. |
| Admin upgrade path? | **No.** No proxy, no setter on the kernel, factory, root or class. |
| Authority able to admit arbitrary verifier logic? | **Not in Generation 1.** A factory constructed with a different root yields vaults admitting what that root approves — a different generation deployment, distinguishable by address and by `genesisCommitments()`. That is D8's generation-publisher residual (H-32), with no authority over any existing vault. |
| Did any existing principal gain authority? | **No.** Admission is still genesis (cut 0), `setVerifier` (cut 2 armed / 1 dormant), recovery (`k`), each now additionally constrained. The kernel gains one external call site, a `view` STATICCALL that can only refuse. |

**Stop conditions checked:** no mutable allowlist was needed; provenance is non-self-asserted
without an architecture change; no mutation path was found in the immutable class; recovery
liveness is preserved (`deployVerifier` is permissionless and cannot be blocked — M4 and M6
complete recoveries end to end) and no cut outside SD-11 moves; no on-chain proof of relation
semantics is pretended; no production code changed.

## 6. SD-11A, SD-11B and the ZK verifier

| | Admission (Generation 1) | Semantic mutability | Ledger |
| --- | --- | --- | --- |
| Dual-relation fixture (SD-11A) | **REFUSED** at all three edges | still hostile: weak leg accepts | SD-11A **CONDITIONALLY REMEDIATED** |
| `AttestationPQCVerifier` (SD-11B) | **REFUSED** at all three edges | still mutable: `updateAttestor` works | SD-11B **CONDITIONALLY REMEDIATED** |
| `ImmutableAttestationPQCVerifier` (root-created) | **ADMITTED** at all three edges | immutable (M4) | — |
| `ZKMLDSAVerifier` | not admissible: the root cannot create it | NOT ESTABLISHED (forwards to an unpinned SP1 verifier) | out of Generation 1 |

The adjudication lane's reproductions are **not neutralised**: `Sd11VerifierAdmissionSemantics.test.ts`
binds `UngatedVerifierAuthority`, the pre-lane rule, and still passes 16/16 — the weak-leg spend,
the credential replacement and the in-place attestor rotation all still reproduce there.

**Conditions** (carried in the ledger's `condition` field and published beside the verdict):
generation binding (both); class assurance (SD-11A); source attribution of one STATICCALL
(SD-11B). SD-8 is unchanged.

## 7. Path completeness

The M6 census reads the compiler's AST, not source text: `pqVerifier` is written in exactly
`initialize ← g.verifier`, `setVerifier ← verifier` and `executeRecovery ← r.proposedVerifier`;
`r` is the stored request; the only writer of a proposal is `initiateRecovery ← proposedVerifier`;
the only other whole-struct write is `delete recovery`; no inline assembly writes storage; and
`_requireAdmissibleVerifier` is called exactly at `initialize(g.verifier)`,
`setVerifier(verifier)` and `initiateRecovery(proposedVerifier)`, each before its write. A raw
clone bound to the root, with no factory involved, is enforced by `initialize` itself (M5-E).

## 8. Cost

| Artifact | Before | After | Δ |
| --- | --- | --- | --- |
| kernel runtime / initcode | 17,695 / 17,736 B | 17,964 / 18,005 B | +269 / +269 |
| kernel storage | 17 entries, 11 slots | unchanged | 0 |
| kernel ABI | 46 functions, 15 events, 24 errors | 46, 15, 25 | +1 error |
| factory runtime / initcode | 2,445 / 2,794 B | 2,551 / 3,030 B | +106 / +236 |
| factory ABI | ctor `(address,uint64)`, 4 functions | ctor `(address,uint64,address)`, 5 | +1 arg, +1 getter |
| root (new) | — | runtime 4,196 B, initcode 4,225 B, 1 mapping | new |
| class (new copy, created by root) | — | runtime 2,653 B, initcode 3,772 B | new |
| clone runtime | 53 B | 73 B | +20 |
| external calls per admission | 0 | 1 `view` STATICCALL | +1 |

Gas was not measured; no measurement existed to reuse without expanding scope.

## 9. Scanner

Pinned Slither on a clean checkout of `40ba7059`: **285 raw, 58 own-code rows, 37 distinct,
0 ambiguities**. Joined to the stored triage on `semanticId`: **10 unchanged, 23 relocated
(fingerprints byte-equal), 0 source-changed, 0 removed, 4 added**, every added finding in the
byte-identical production copies (`unused-return`, `timestamp`, `assembly` in the class;
`solc-version` on its interface), each adjudicated firsthand. solhint **41 warnings / 0 errors**
(36 before: +4 in the class copy, +1 on the factory's new immutable). Authority completeness
**PASS**, 18 entries, 0 failed. CodeQL is not runnable locally.

## 10. What this lane does not establish

1. Anything about an attestor's honesty or an ML-DSA signature — the class verifies an attestation.
2. That the kernel implementation alone enforces Generation 1: the root is bound per generation.
3. Key well-formedness or possession (SD-8).
4. Any property of the ZK/SP1 path.
5. Gas cost.
6. Anything about production deployments of these contracts — none exist.
