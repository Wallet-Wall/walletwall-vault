# Generation-2 candidate — the ERC-20 kernel under admission

> # EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT
>
> Everything here is an admission candidate compiled in-test against a **local mock** asset. Nothing was
> deployed, no network configuration exists, and no real token or address appears anywhere in this tree.

The record of what this tree establishes, and what it does not, is
[`../GEN2_ADMISSION.md`](../GEN2_ADMISSION.md). This file is only the map.

## Why this tree exists

`contracts/` and `stateful/` are the Generation-1 evidence subject, guarded byte for byte; `erc20-spend-plane/`
is what PR #237 measured, and this lane measures against it, so neither may move. The candidate therefore has
its own tree, its own identity and its own receipts. It reuses Generation 1's PRNG, cut model, defect ledger,
global invariants, quorum shapes and authority checker **by import**, so an edit there reaches both generations
and none of them is re-implemented here.

## Layout

```text
generation-2/
  ADMISSION_CRITERIA.json   the bar, committed BEFORE the candidate existed; later rows are appended and marked
  admission-matrix.ts       every criterion, classified, with its evidence; the verdict is derived from this
  run-record.ts             what the two heavy suites did, exactly; they compare themselves with it and the verdict reads it
  GEN2_RUN_RECORD.json      that record, written with G2_WRITE_RUN_RECORD=1 and reviewed like code
  contracts/                the candidate (kernel, factory, interface) and Gen2TokenZoo.sol, the test fixtures
  compile.ts                the pinned solc path, in memory; never writes artifacts
  identity.ts               the candidate's reconstructible identity
  world.ts                  the fixture every suite drives; mirrors digests, never reads back what to sign
  authority/                the Generation-2 manifest, and the census: the real checker plus a derived comparison
  stateful/                 the campaign on the candidate: actions, properties, profiles, engine, mutants
  scanner.ts                every Slither finding on the candidate, adjudicated by semantic identity
  scanner-run.json          the reduction of one pinned Slither run, with no machine path in it
  GEN2_GAS_RECORD.json      exact local gas figures: not a cost claim for any network
  generate-evidence.ts      writes the four GEN2_*.json receipts for a named subject commit
  test/                     the two heavy suites, run by explicit path (below)
```

## Running it

The deterministic suites are in `prototype/vnext-kernel/test/Gen2*.test.ts` and run with the prototype suite.
The campaign and the mutation catalogue take about nine minutes between them and live outside the suite's test
path, because the prototype CI job already uses most of its time budget:

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/generation-2/test/Gen2StatefulCampaign.test.ts
```

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/generation-2/test/Gen2MutationAdequacy.test.ts
```

Regenerating the receipts follows the two-commit protocol: commit the code, then run the generator on that clean
commit and commit what it writes. It refuses any input that differs from the subject.

```bash
npx tsx prototype/vnext-kernel/generation-2/generate-evidence.ts --subject <40-hex commit>
```
