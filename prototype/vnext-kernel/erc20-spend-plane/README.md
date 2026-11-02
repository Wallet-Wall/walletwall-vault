# Admitted-asset ERC-20 spend plane — Generation-2 CANDIDATES

> # EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT
>
> Measurement candidates for a FUTURE kernel generation, built to answer the custody
> adjudication's open questions (`docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md` §7.1, §7.2,
> §10) with numbers. The admitted asset in every test is a **local mock ERC-20**; no mainnet
> address, network configuration or deploy script exists here, and nothing in this
> directory authorises real value. The record is
> [`../ERC20_SPEND_PLANE_MEASUREMENT.md`](../ERC20_SPEND_PLANE_MEASUREMENT.md).

## Why these sources are NOT under `prototype/vnext-kernel/contracts/`

That directory is the evidence subject of two guards: `test/EvidenceSubjectProvenance.test.ts`
compares its git tree between the declared subject and the publishing commit, and
`scanner-input-scope.ts` licenses `SCANNER_EVIDENCE.json` on the same tree. One added file there
turns both red until every receipt is regenerated under a fresh pinned Slither run — a publication
lane's work, not a measurement's. So, as the SD-11 lane did for its verifier fixtures, the candidates
are compiled **in-test with the pinned solc** (`compile.ts`, settings identical to
`../hardhat.config.ts`) and deployed from their creation bytecode by ordinary transactions. The
Hardhat config never compiles them; `measure.ts`, `reproduce.ts`, the stateful campaign and the
scanner scope are untouched.

## Layout

```text
erc20-spend-plane/
  README.md                                   this file
  compile.ts                                  pinned-solc compile + measurement (shared by the suites and the CLI)
  measure.ts                                  CLI: prints the byte record; --write updates the JSON below
  ERC20_SPEND_PLANE_MEASUREMENTS.json         the record: bytes (compile-derived), gas (suite-derived), verdict
  contracts/
    VaultKernelErc20Prototype.sol             variant A — Generation-1 kernel + the admitted-asset plane;
                                              genesis KEEPS the admissible-verifier requirement
    VaultKernelErc20NullVerifierPrototype.sol variant B — as A; genesis ACCEPTS address(0) when requirePq == false
    VaultKernelErc20FactoryPrototype.sol      Generation-1 factory + a 4th immutable, admittedAsset
    interfaces/IKernelPlanes.sol              byte-identical copy of the Generation-1 interface (pinned by test)
    Erc20PlaneMocks.sol                       the adversarial token zoo and the three settlement MODELS (test-only)
../test/
  erc20-spend-plane-world.ts                  fixture + digest mirrors
  Erc20SpendPlaneMeasurement.test.ts          bytes, headroom, storage, ABI, positive control against Generation 1
  Erc20SpendPlane.test.ts                     ERC20-1..10, migration, atomicity, hooks, issuer upgrades, gas
  Erc20SpendPlaneSettlement.test.ts           the zoo against models A / B / C and against the kernel
  Erc20SpendPlaneAuthorityCensus.test.ts      authority/check.ts run on the candidates with the Generation-1 manifest
  Erc20SpendPlaneMutations.test.ts            four weakened kernels, each killed by a named observation
```

## What a candidate changes, and nothing else

- `execute` moves the **admitted asset** — the ERC-20 whose address the factory binds into the clone's
  immutable args as the third field (`generation (8) || verifierAuthority (20) || admittedAsset (20)`) —
  and judges settlement on an **exact observed balance decrease** (`I-NO-FALSE-SETTLEMENT`), never on the
  call's success or the token's boolean. `execute` keeps its selector and its `(recipient, amount)`
  parameter hash.
- `admittedAsset()` reads that address back out of the clone's **own code**, so "this vault spends only
  asset X" is checkable offline from `eth_getCode`.
- Native value is no longer spendable: it still arrives unsolicited (`receive()`) and leaves only through
  `egress(address(0))`.
- Variant B adds `_requireAdmissibleGenesisVerifier`: `address(0)` is admissible at genesis, and only
  there, when the floor does not require the PQ conjunct.

Authority model, nonce domains, recovery, containment, migration, the floor and every signature digest
are unchanged; the authority census passes with the Generation-1 manifest unchanged.

## Running it

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile      # caches the pinned solc; builds the Generation-1 artifacts the suites compare against
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test         # the whole prototype suite, these suites included
npx tsx prototype/vnext-kernel/erc20-spend-plane/measure.ts                # print the byte record
npx tsx prototype/vnext-kernel/erc20-spend-plane/measure.ts --write        # regenerate the record (preserves gas, verdict, recommendation)
```

The gas block is measured by `Erc20SpendPlane.test.ts` ("gas"), which prints a fresh table and
asserts the recorded one; when a candidate changes, re-record from that table.
