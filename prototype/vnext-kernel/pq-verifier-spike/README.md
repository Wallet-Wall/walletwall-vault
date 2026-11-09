# ML-DSA-65 verifier conformance spike (GEN2-PQ-CONFORMANCE-1)

> # EXPERIMENTAL · UNAUDITED · NOT PRODUCTION · NOT CONNECTED TO ANY KERNEL
>
> This directory holds a **pinned copy** of one third-party on-chain ML-DSA-65 (FIPS 204) verifier, the test
> vectors it was run against, the tests that run them, the numbers those runs produced, and the record of what
> that does and does not establish. It changes nothing in `contracts/`, in the vNext kernel prototype, in the
> Generation-2 candidate, in any production gate, workflow or dependency. Nothing here was deployed anywhere.
>
> **Passing every vector here is partial conformance evidence for one implementation on one simulated EVM. It is
> not an independent cryptographic review, not an audit, and not a production approval.** `UNRESOLVED.md` lists what
> is open; `SPIKE_RECORD.md` is the auditor-readable summary of what ran.

## Why this exists

The Generation-2 kernel design requires a post-quantum signature on every authority predicate (ECDSA ∧ ML-DSA).
The feasibility lane (owner record `GEN2-PQ-FEASIBILITY-1`, outside this repository) found exactly one public
implementation with ML-DSA-65 support, on a branch, unaudited: ZKNoxHQ/ETHDILITHIUM `mldsa-65` @ `4c370bb5`. Its
measured results existed only in a scratch harness. This spike makes them version-controlled and reproducible by
anyone with this repository and its lockfile, and puts the open questions where a reviewer will find them.

## Layout

```text
pq-verifier-spike/
  README.md               this file
  SPIKE_RECORD.md         auditor-readable evidence summary: what ran, counts, commands, diagnostics, what did not run
  PROVENANCE.md           where every byte came from, licences, the one artefact nobody can regenerate
  SOURCE_PINS.json        machine-readable pins: upstream path, commit, size, sha256 of every vendored file
  TOOLCHAIN.md            what tooling ran (and what could not be installed), with the exact commands
  UNRESOLVED.md           open vulnerabilities and risks; nothing here is closed by passing vectors
  PUBLISHER_BINDING.md    design note: how a deterministic publisher would bind a canonical key to its blobs (not built)
  REVIEW.md               an independent fresh-context review of this package (AI-assisted; not a security audit)
  hardhat.config.ts       ISOLATED config: compiles only harness/, tests only test/, own cache and artifacts
  tsconfig.json           type-checks this directory's own TypeScript (the root tsconfig excludes prototype/)
  vendor/                 byte-identical upstream sources: ZKNOX (verifier closure + js expansion), sstore2,
                          InterfaceVerifier, the Fireblocks Keccak-f[1600] helper bytes and its rebuild tool
  harness/SpikeProbe.sol  measurement probe (forwards calls, reports success/return data/gas); not production
  lib/compile.ts          compiles the vendored closure in memory with the pinned solc and the vendor's settings
  lib/world.ts            one simulated EVM, helper + verifier + probe deployed, publish/verify helpers
  fixtures/               ACVP tgId 3 extract, Wycheproof (verbatim), NIST .rsp counts 0..9, vendor vectors,
                          generated vectors, expansion digests
  test/                   Pins, Build, Conformance, Adversarial, Measurements
  results/                the committed records every test run must reproduce exactly
  upstream-run/           the configuration and logs of the vendor's own Foundry suites run on Hardhat 3's
                          Solidity runner outside this repository (forge could not be installed)
```

## Running it

From the repository root, after `npm ci` (no dependency is added by this directory):

```bash
npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts test
```

The first run downloads solc 0.8.30 into Hardhat's compiler cache (the vendor's pin; the production project pins
0.8.24). The whole suite takes under a minute on a workstation. Every suite compares what it measured with the
committed `results/*.json` and fails on any difference; to regenerate the records deliberately:

```bash
SPIKE_WRITE_RESULTS=1 npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts test
```

Type-check this directory's own code:

```bash
npx tsc -p prototype/vnext-kernel/pq-verifier-spike/tsconfig.json
```

**No CI workflow runs these suites.** Workflow changes are outside this lane's authority, and the prototype
workflow's `paths` trigger covers `prototype/vnext-kernel/**` only for the jobs it already defines. Results in
`results/` and `SPIKE_RECORD.md` were produced locally; `TOOLCHAIN.md` records the environment.

## What the suites establish (and the one-line caveat on each)

| Suite | Establishes | Caveat |
| --- | --- | --- |
| `Pins` | every vendored byte and fixture is the pinned upstream byte | pins are only as good as the commit they name |
| `Build` | the deployed bytecode equals the compiler's output with the helper in its immutable slot; selectors; helper code-hash binding | reproduces **this** pinned build; the vendor published no ML-DSA-65 artefact to compare with |
| `Conformance` | 292 vectors (ACVP, Wycheproof, NIST KAT, vendor, generated) return the expected verdict; `@noble/post-quantum` agrees on every one | vectors, not a review; two oracles agreeing is not soundness |
| `Adversarial` | what the verifier does with hostile handles, blobs, degenerate keys, malformed signatures, a replaced helper, and how its sponge compares with an independent Keccak | each accepted hostile input is a **finding** (see `UNRESOLVED.md`), not a pass |
| `Measurements` | local gas, code sizes, and which multi-verification shapes fit the EIP-7825 per-transaction cap | local EVM only; Base economics UNKNOWN |

## Explicitly outside this directory's scope

No kernel adapter, no key publisher, no emergency escape credential, no deployment, no gate or workflow change, no
claim of independent review. The owner decisions these results feed are listed in the feasibility record
(OD-G2PQ-01..25), outside this repository.
