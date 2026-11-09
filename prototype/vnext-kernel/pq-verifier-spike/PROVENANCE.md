# Provenance and dependency record

> EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. This file says where every byte in this directory came from, under
> which licence, and which of those bytes nobody can regenerate. `SOURCE_PINS.json` is the machine-readable form;
> `test/Pins.test.ts` re-verifies every size and sha256 and refuses unlisted files under `vendor/`.

## 1. The candidate: ZKNoxHQ/ETHDILITHIUM, branch `mldsa-65`, commit `4c370bb5ff90d98e1ce8fb96f867126f0fbb9046`

- Licence: MIT (`vendor/zknox-ethdilithium-4c370bb5/LICENSE`, Copyright (c) 2025 ZKNoxHQ). Every vendored Solidity
  file keeps its upstream header and `SPDX-License-Identifier: MIT`.
- Commit date 2026-09-16, message "Add the MLDSA 65 files". The repository's `main` (f9f4fe1d at the time of the
  feasibility lane) carries a README claim but **no ML-DSA-65 source**; the code exists only on this branch. A pin to
  `main` would pin nothing.
- What is vendored is the **import closure of the verifier**, nothing more: `src/ZKNOX_dilithium65.sol` and the six
  files it reaches (`ZKNOX_dilithium65_core_packed.sol`, `ZKNOX_dilithium_core_packed.sol`, `ZKNOX_dilithium_utils.sol`,
  `ZKNOX_NTT_dilithium_mont.sol` (3,180 generated lines), `ZKNOX_shake_fast.sol`) plus the two submodule files it
  imports (below). `ZKNOX_dilithium65_utils.sol` is **not** in the closure (its constants are duplicated where
  used) and is not vendored, although a NatSpec comment in `ZKNOX_dilithium65.sol` still names it. Total: 5,527
  lines / 267,737 bytes across 9 Solidity files.
- The client-side key expansion `js/mldsa65.js`, `js/ntt_mldsa.js`, `js/utils_mldsa.js` (404 lines, MIT) is vendored
  byte-identical and imported directly by the tests (the repository's `@noble/post-quantum` 0.7.0, `@noble/hashes`
  2.3.0 and `ethers` 6.17.0 satisfy its imports). `lib/zknox-js.d.ts` only supplies types.
- Upstream test material is **not** vendored (it depends on forge-std and `vm.ffi`); see `TOOLCHAIN.md` for how the
  upstream suites were exercised outside this repository, and `fixtures/vendor-vectors.json` for the one upstream
  test file whose content is re-used (hash-pinned).

## 2. Submodules the verifier imports

| Package | Commit | Licence | Role |
| --- | --- | --- | --- |
| 0xsequence/sstore2 | `0a28fe61b6e81de9a05b462a24b9f4ba8c70d5b7` | MIT (`LICENSE.md`, Ismael Ramos Silvan) | `SSTORE2.write`: `setKey` stores each 20,160-byte key half as the code of a new contract behind a `0x00` STOP byte (`contracts/SSTORE2.sol`, `contracts/utils/Bytecode.sol`). |
| ZKNOXHQ/InterfaceVerifier | `5ec0596c7fad2fcdde8bdb2dd50565858c84007c` | MIT | `ISigVerifier`: `setKey(bytes)` and the ERC-7913-style `verify(bytes,bytes32,bytes) returns (bytes4)`. |

Both pins are the vendor's own (`.gitmodules` at 4c370bb5). forge-std (`8ba9031f`) is a test-only submodule and is
not vendored.

## 3. The Keccak-f[1600] helper: fireblocks-labs/evm-ml-dsa-verifier @ `cca262b5`

- Licence: MIT (Copyright (c) 2026 Fireblocks Ltd.).
- `helpers/f1600_170.hex` (21,622 bytes of raw EVM runtime; sha256 `f26320c4…612c4`; keccak256
  `0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b`) is the permutation the ZKNOX verifier binds by
  `EXTCODEHASH` on construction and on every call (`F1600_CODEHASH`). ZKNOX's own copy (`test/f1600_170.hex` at
  4c370bb5) is byte-identical (same sha256); only the Fireblocks copy is vendored, with its README and rebuild tool.
- `helpers/f1600_core.hex` (19,617 bytes; sha256 `46fbc67c4040f22929be6abb43abb935a3f2ae6b03398729c09afe0c898764ee`) is
  the bare 24-round permutation the dispatcher wraps. **Its generator was not preserved by anyone**
  (`helpers/README.md`): it is the one artefact in the whole dependency chain with no rebuild path. `tools/build_f1600_batch.py --check`
  rebuilds `f1600_170.hex` from it deterministically (verified locally, `test/Pins.test.ts`), which pins the
  dispatcher but not the core.
- The sponge glue in `ZKNOX_shake_fast.sol` (`_xorBlockFast170`, `_squeezeBlockFast170`, `_absorbFast170`,
  `shake256Fast`) is Fireblocks code copied verbatim into the ZKNOX file (header notice). Fireblocks' own Z3
  obligations (`formal/z3/verify_all.py`, items `C18.kec_*`) target that glue in **their** repository; they were not
  run here (`TOOLCHAIN.md`).
- Consequence for independence claims: the two public EVM ML-DSA verifiers (ZKNOX, Fireblocks) share this helper.
  They are not independent implementations of the hash layer.

## 4. Test vectors

| Fixture | Source | Hash pinned | Licence |
| --- | --- | --- | --- |
| `acvp-mldsa65-sigver-tgid3.json` | usnistgov/ACVP-Server `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`, vsId 42, tgId 3 (ML-DSA-65, external interface, pure) | source sha256 `47cdd631…5437`; 15 tests extracted | NIST, public domain (US) |
| `wycheproof-mldsa_65_verify_test.json` | C2SP/wycheproof `testvectors_v1/mldsa_65_verify_test.json` (branch main), copied verbatim | `1ca235f6…9034`; 210 tests, 25 groups | Apache-2.0 |
| `nist-rsp-dilithium3-counts0-9.json` | pq-crystals reference KAT `PQCsignKAT_Dilithium3.rsp` as vendored in ZKNOX `test/KAT/` | source sha256 `46b223fc…9795`; counts 0..9 extracted | NIST KAT material |
| `vendor-vectors.json` | ZKNOX `test/KAT/mldsa65_vectors.json` (written by `js/gen_test_vectors65.js`) | `fc38096d…8ff8`; 3 js vectors, the hash32 vector and all 28 blob digests taken; the ACVP/.rsp content is re-derived from the primary sources instead | MIT |
| `generated-vectors.json` | GEN2-PQ-FEASIBILITY-1 harness (2026-11-08): `@noble/post-quantum` 0.7.0 signer; hedged signatures are random, so the committed file is the fixture | counts pinned in `test/Pins.test.ts` | this repository |
| `expanded-key-digests.json` | the feasibility run's key expansions, done by the upstream ESM `js/mldsa65.js` (the same code as the vendored module: this pins against **drift**, not against an independent expansion; the expansion's correctness is evidenced by the on-chain acceptances) | 41 pk→blob sha256 pairs | this repository |

The extraction scripts live outside the repository (the lane's work directory); every extract records the sha256 of
the file it was cut from, so a reviewer can re-cut it from the public source and compare.

## 5. Toolchain the evidence was produced with

| Component | Version | Pinned by |
| --- | --- | --- |
| solc | 0.8.30+commit.73712a01 (native binary cached by Hardhat) | `hardhat.config.ts` of this spike; the vendor's `foundry.toml [profile.default]` |
| Compiler settings | evm `osaka`, via-IR, optimizer runs 1,000,000 | vendor's `foundry.toml`; `lib/compile.ts` |
| Hardhat / EDR | 3.14.0 / 0.17.0 | repository `package-lock.json` (unchanged by this PR) |
| ethers / @noble/post-quantum / @noble/hashes | 6.17.0 / 0.7.0 / 2.3.0 | repository `package-lock.json` (unchanged) |
| Simulated EVM | EDR `edr-simulated`, chainType l1, hardfork `osaka` (EIP-7825 16,777,216 per-transaction gas cap enforced) | `hardhat.config.ts` of this spike |

No dependency was added to `package.json`; no hosted service was used; nothing was deployed to any network.

## 6. What no record here can supply

- The generator of `f1600_core.hex` (§3).
- A build artefact or deployment of ML-DSA-65 published by the vendor to compare bytes against: none exists; the
  byte reproduction in `results/build.json` is of **this** pinned build (`TOOLCHAIN.md`).
- An independent cryptographic review of any vendored line. Vectors passing is conformance evidence for the inputs
  that were run; it is not that review.
