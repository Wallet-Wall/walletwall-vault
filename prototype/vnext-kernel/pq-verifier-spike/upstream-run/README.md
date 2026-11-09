# Upstream suites run outside this repository

These files record how the vendor's own Foundry test suites (ZKNoxHQ/ETHDILITHIUM `mldsa-65` @ `4c370bb5`) were
executed when `forge` could not be installed: on Hardhat 3.14.0's Solidity test runner (EDR 0.17.0), in a scratch
project that is **not** part of this repository. `TOOLCHAIN.md` §2 explains the setup and its one textual deviation
(the `InterfaceVerifier/` import specifier rewritten to a lowercase package name Hardhat accepts).

| File | What it is |
| --- | --- |
| `hardhat.config.upstream-tests.ts` | the scratch project's configuration: solc 0.8.30, osaka, via-IR, runs 1,000,000; `ffi: true` (the vendor deploys the Keccak helper through `vm.ffi(["cat", ...])`); explicit `readFile` permissions for the six KAT files; forge's defaults for the transaction cap and block gas limit |
| `compile.log.txt` | `npx hardhat compile`: 41 Solidity files compiled; the warnings are the vendor's |
| `mldsa65-suites.log.txt` | the four ML-DSA-65 / hash-layer suites: 29 passing, 0 failing |
| `full-suite.log.txt` | every upstream suite: 85 passing, 8 failing, each failure an ML-DSA-44 / ETH-Dilithium test needing `startBroadcast` (unsupported by Hardhat) or the vendor's Python virtual environment through `vm.ffi` |

To reproduce: clone the vendor at `4c370bb5` with its submodules, copy `src/`, `test/`, `script/` into a directory
holding this configuration and a `package.json` with `"type": "module"`, expose forge-std (`8ba9031f`, under
`node_modules/forge-std/src/`), sstore2 (`node_modules/sstore2/*.sol`) and `node_modules/interface-verifier/IVerifier.sol`
as local packages, apply the import rewrite to the four files named in `TOOLCHAIN.md`, make this repository's
`node_modules` resolvable from that directory, and run `npx hardhat test solidity`. `cat` must be on `PATH`.

The logs were produced on 2026-11-09 on a Windows host; they contain no machine-specific paths.
