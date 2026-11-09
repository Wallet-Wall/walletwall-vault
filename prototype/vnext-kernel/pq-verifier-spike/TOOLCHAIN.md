# Toolchain record: what ran, where, and what could not be installed

> EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. A tool that was not available is recorded as missing evidence, never
> as a pass. Commands are given so a reviewer can reproduce each step; machine-specific paths are the only thing a
> reviewer must substitute.

## 1. Inside this repository (the committed evidence)

| Component | Version | Source of the pin |
| --- | --- | --- |
| Node.js | v24.16.0 (the repository requires ≥ 22.13.0) | local |
| Hardhat / EDR | 3.14.0 / 0.17.0 | `package-lock.json` (unchanged) |
| solc (native) | 0.8.30+commit.73712a01, downloaded by Hardhat on the first compile of `hardhat.config.ts` | vendor's `foundry.toml`; `hardhat.config.ts` of this spike |
| ethers / @noble/post-quantum / @noble/hashes / chai / mocha | 6.17.0 / 0.7.0 / 2.3.0 / 6.2.2 / 11.7.6 | `package-lock.json` (unchanged) |
| TypeScript | 7.0.2 (`npx tsc -p prototype/vnext-kernel/pq-verifier-spike/tsconfig.json` passes) | `package-lock.json` (unchanged) |
| Simulated EVM | EDR `edr-simulated`, chainType `l1`, hardfork `osaka`, block gas limit 40,000,000, EIP-170 enforced, EIP-7825 per-transaction cap 16,777,216 enforced | `hardhat.config.ts` of this spike |
| Python (for the helper rebuild check only) | 3.13.14, `python -I` | local; the test skips when absent |
| Host of record | win32-x64; nothing platform-specific is compared (solc's platform suffix is excluded from the comparable record) | `results/*.json` `environment` |

Commands (repository root):

```bash
npm ci
npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts compile    # harness only; fetches solc 0.8.30
npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts test       # all five suites, ~20 s
npx tsc -p prototype/vnext-kernel/pq-verifier-spike/tsconfig.json
```

The vendored closure is compiled by `lib/compile.ts` directly through the cached solc binary (standard JSON, the
vendor's source-unit names and settings), so no Hardhat artifact of the verifier exists; the harness contract is
the only thing Hardhat compiles.

## 2. Upstream Foundry test suites (outside this repository)

`forge` could not be installed: the Foundry release download was refused by this environment's policy during the
feasibility lane and was not retried. The upstream suites were instead executed on **Hardhat 3's Solidity test
runner (EDR)**, which implements the forge-std cheatcode interface, in a scratch project outside the repository:

- the ZKNOX tree at 4c370bb5 (`src/`, `test/`, `script/`, `test/KAT/`), forge-std at the vendor's pinned submodule
  commit `8ba9031ffcbe25aa0d1224d3ca263a995026e477`, sstore2 `0a28fe61` and InterfaceVerifier `5ec0596c` exposed as
  local npm-style packages (Hardhat 3 has no user remappings);
- **one textual deviation**: Hardhat 3 rejects the non-lowercase package name `InterfaceVerifier`, so the import
  specifier `"InterfaceVerifier/IVerifier.sol"` was rewritten to `"interface-verifier/IVerifier.sol"` in the four
  files that carry it (`src/ZKNOX_dilithium.sol`, `src/ZKNOX_dilithium65.sol`, `src/ZKNOX_ethdilithium.sol`,
  `test/dilithium65_vectors.t.sol`). Nothing else in any upstream file was changed. The vendored copies in this
  repository are untouched (`test/Pins.test.ts`).
- configuration: `upstream-run/hardhat.config.upstream-tests.ts` (solc 0.8.30, osaka, via-IR, runs 1,000,000;
  `ffi: true` because `test/F1600Helper.sol` deploys the helper with `vm.ffi(["cat", "test/f1600_170.hex"])`;
  explicit `readFile` permissions for the six KAT files; per-transaction cap disabled as forge does).

Result for the ML-DSA-65 verifier and its hash layer (`upstream-run/mldsa65-suites.log.txt`; the compile log is
`upstream-run/compile.log.txt`):

```bash
npx hardhat test solidity test/dilithium65_vectors.t.sol test/dilithium65KATS.t.sol test/dilithium65_core_packed.t.sol test/shake_fast.t.sol
```

| Suite | Tests | Result |
| --- | --- | --- |
| `test/dilithium65_vectors.t.sol` | `testNistVectors` (28 vendor vectors: 15 valid, 13 rejected as expected), `testInterfaceSelector` | 2/2 pass |
| `test/dilithium65KATS.t.sol` | `testVerify` (reference KAT count 0, 1,544,360 gas), `testRejects` | 2/2 pass |
| `test/shake_fast.t.sol` | 4 unit tests + 3 fuzz tests × 256 runs on the helper-backed SHAKE256 and SampleInBall | 7/7 pass |
| `test/dilithium65_core_packed.t.sol` | 12 unit tests (useHint, z unpacking incl. boundaries, SampleInBall KAT, blob reading, saturated mat-vec, hint masks, packed core vs scalar reference on a real signature, decoder rejections, hint byte checks) + 6 fuzz tests × 256 runs | 18/18 pass |
| **total** | | **29/29 pass** |

Caveats: this is EDR, not forge; fuzz inputs are EDR's, not forge's; `forge coverage`, `forge snapshot` and
anything that depends on forge's own inspectors were not run. The vendor's full suite also contains ML-DSA-44 and
ETH-Dilithium tests that need the vendor's Python virtual environment (`pythonref/myenv/bin/python` via `vm.ffi`)
and the `startBroadcast` cheatcode Hardhat does not support; those are outside the candidate and were not
exercised (see the full-suite log summary below).

Full upstream suite on the same runner (`npx hardhat test solidity`, `upstream-run/full-suite.log.txt`): 19 test
contracts, **85 passing, 8 failing**. Every failure is outside the ML-DSA-65 candidate and caused by the runner, not
by the code under test: `DilithiumTest#testVerifyShorter`, `ETHDilithiumTest#testVerifyShorter`,
`BenchmarksTest#testMLDSA`, `BenchmarksTest#testMLDSAETH`, `DilithiumCorePackedTest#test_readPubKeyPacked` and
`#test_core2_packed_matches_scalar_real_signature` use the `startBroadcast` cheatcode (forge scripting), which
Hardhat does not implement; `DilithiumCorePackedTest#test_unpackZPacked_real_signature` and `#test_checkHintBytes`
shell out through `vm.ffi` to the vendor's Python virtual environment (`pythonref/myenv/bin/python`), which does
not exist here. The ML-DSA-44 and ETH-Dilithium suites are therefore only partially exercised, and they are not the
candidate. Nothing was skipped silently: every failure and its cause is in the log.

## 3. Formal checks

- ZKNOX publishes **no formal artefact** for ML-DSA-65 at 4c370bb5.
- fireblocks-labs/evm-ml-dsa-verifier ships Z3 obligations, a Lean 4 development and halmos runs for **its**
  ML-DSA-44 verifier. Items `C18.kec_*` in `formal/z3/verify_all.py` concern the sponge glue that
  `ZKNOX_shake_fast.sol` copied verbatim (`_M64_170` lane mask, rate 136 at every site, the batched `returndatasize`
  gate, the 800-byte dispatch collision). They were **not run**: the `z3-solver` Python package, Lean 4 and halmos
  are not installed here and installing them was outside this lane's bounds. Recorded as missing evidence
  (`UNRESOLVED.md` U-9).
- The only formal-adjacent artefact that was re-executed is the Fireblocks helper rebuild
  (`tools/build_f1600_batch.py --check`): the dispatcher is rebuilt from the core byte-for-byte; the core's generator
  remains lost.

## 4. What was deliberately not done

- No Foundry install, no Slither/CodeQL run on the vendored code (the repository's scanners target other trees),
  no third oracle (libcrux, RustCrypto), no Base fork, no network of any kind, no hosted service, no change to
  `package.json` dependencies or to any workflow.
