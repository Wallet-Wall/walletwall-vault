# SPIKE_RECORD — ML-DSA-65 verifier conformance evidence (GEN2-PQ-CONFORMANCE-1)

> **Status line:** `PQ_VERIFICATION_CONFORMANCE: PARTIAL_EVIDENCE_UNREVIEWED` for ZKNoxHQ/ETHDILITHIUM
> `mldsa-65` @ `4c370bb5ff90d98e1ce8fb96f867126f0fbb9046`, measured on a local simulated EVM.
> `INDEPENDENT_CRYPTOGRAPHIC_REVIEW: NOT_STARTED`. `PRODUCTION_APPROVAL: NOT_REQUESTED`.
>
> EXPERIMENTAL · UNAUDITED · NOT PRODUCTION · NOT CONNECTED TO ANY KERNEL. Every number below was produced by the
> suites in `test/` on 2026-11-09 and is reproduced exactly by `results/*.json` on every run. Nothing below is an
> audit finding of absence: a vector that passes says the implementation agreed with the expected verdict on that
> input, nothing more.

## 0. What was done, in one table

| Task | Done | Where | Not done |
| --- | --- | --- | --- |
| Pinned, licensed, provenance-recorded copy of the verifier closure and client expansion | yes | `vendor/`, `SOURCE_PINS.json`, `PROVENANCE.md`, `test/Pins.test.ts` | — |
| Conformance campaign from committed fixtures, raw inputs and expected outcomes preserved | yes: 292 vectors, 288 on chain, 0 inconsistent, 0 chain/client splits | `fixtures/`, `test/Conformance.test.ts`, `results/conformance.json` | no third oracle |
| Upstream Foundry suites | partially: see §6 | `TOOLCHAIN.md` | `forge` itself could not be installed |
| Upstream formal checks | none exist for ML-DSA-65; Fireblocks' obligations for the shared sponge glue not run | `TOOLCHAIN.md`, `UNRESOLVED.md` U-9 | Z3 / Lean / halmos not installed |
| Exact interfaces, overloaded selectors, immutable helper, runtime code hash, compiler settings, **deployed bytecode reproduced** | yes | `test/Build.test.ts`, `results/build.json` | no vendor artefact exists to compare with |
| Malformed keys, degenerate forgeries, invalid blobs, substituted handles, malformed signatures, helper behaviour | yes: every behaviour recorded with its finding text; the accepted hostile inputs are the findings (§5) | `test/Adversarial.test.ts`, `results/adversarial.json`, `UNRESOLVED.md` | the full extent of the degenerate-key class (a floor is known, not the boundary) |
| Publisher binding design | design note only | `PUBLISHER_BINDING.md` | not implemented, not approved |
| Gas, code size, deployment cost, transaction constraints (local) | yes | `test/Measurements.test.ts`, `results/measurements.json` | Base economics UNKNOWN |
| Independent fresh-context review | done, 11 findings, acted on (§8) | `REVIEW.md` | it is AI-assisted review, not a security audit |

## 1. The subject

| Fact | Value |
| --- | --- |
| Repository / branch / commit | ZKNoxHQ/ETHDILITHIUM, `mldsa-65`, `4c370bb5ff90d98e1ce8fb96f867126f0fbb9046` (2026-09-16); MIT |
| Contract | `ZKNOX_dilithium65` (`src/ZKNOX_dilithium65.sol`), import closure of 9 Solidity files, 5,527 lines / 267,737 bytes |
| Parameter set | ML-DSA-65 (FIPS 204, category 3): k=6, l=5, τ=49, γ1=2¹⁹, γ2=(q−1)/32, ω=55, β=196, λ=192; pk 1,952 B; signature 3,309 B = c̃ 48 ‖ z 3,200 ‖ h 61 |
| Key representation on chain | a 40-byte **handle** = two addresses whose code is the expanded key (`A` in NTT domain, `t1·2¹³` in NTT domain, `tr`), 2 × 20,160 bytes behind a `0x00` byte; written by `setKey`, read in place |
| Hash layer | SHAKE256 (μ, c̃, SampleInBall) through an external Keccak-f[1600] helper (21,622 bytes of raw runtime, Fireblocks origin), bound by `EXTCODEHASH` `0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b` at construction and on every call; for every input except exactly 800 bytes, padding, absorb and squeeze all run inside the helper. SHAKE128 (ExpandA) runs only client-side, in the key expansion |

## 2. Interfaces and selectors (`results/build.json`)

| Function | Selector | Behaviour |
| --- | --- | --- |
| `setKey(bytes)` | `0x218ebfa3` | takes `half0 ‖ half1` (40,320 bytes), two SSTORE2 `CREATE`s, returns the 40-byte handle; **state-changing** |
| `verify(bytes pk, bytes32 m, bytes signature) returns (bytes4)` | `0x024ad318` | ERC-7913 shape: returns its own selector on success, `0xFFFFFFFF` on failure or wrong signature length; reverts `BadHelper`, `BadPubKeyBlob`, `BadLength` |
| `verify(bytes pk, bytes m, bytes signature, bytes ctx) returns (bool)` | `0x067874cf` | FIPS 204 context path; reverts `InvalidSignatureLength`, `ContextTooLong`, `BadHelper`, `BadPubKeyBlob`, `BadLength` |
| `f1600Helper() returns (address)` | `0xac7e2e2d` | the immutable helper address |

The ERC-7913 "magic value" is the selector of the 3-argument overload (`0x024ad318`). The Generation-2 kernel's
`IKernelPQVerifier.verify(bytes32 digest, bytes publicKey, bytes signature) returns (bool)` is selector
`0x5bf48e3a`: a different function with a different argument order and return type. **An adapter is required and
none exists here** (`UNRESOLVED.md` U-5).

## 3. Build reproduction (`test/Build.test.ts`, `results/build.json`)

| Fact | Value |
| --- | --- |
| Compiler | solc 0.8.30+commit.73712a01 (native binary cached by Hardhat 3.14.0) |
| Settings | evm `osaka`, via-IR, optimizer enabled, runs 1,000,000, remappings `sstore2/=lib/sstore2/contracts/`, `InterfaceVerifier/=lib/InterfaceVerifier/src/` (the vendor's `foundry.toml [profile.default]`) |
| Creation bytecode | 24,479 bytes, sha256 `321ee558bcdc81c49534f18703d9788fd7c1f7a98b0063f23989c4c49cac5c01` |
| Runtime bytecode (compiler output, immutable slot zero) | **24,272 bytes** (EIP-170 headroom 304), sha256 `8e813d0c43c8d79c45dc4dc26a6dfed8233c4ec3a30af69c3616b1138d722148` |
| Runtime minus CBOR metadata (51 bytes) | sha256 `5c7943db56e110d8c911e9e20a1da91aa6285b484a61c37927c3e137906205fb`; identical under a different source-unit naming and under `bytecodeHash: none` |
| Immutable references | `f1600Helper` at runtime offsets 907, 1107, 1531, 3342 (32 bytes each); the address appears nowhere else |
| Deployed code | `eth_getCode` of the deployed verifier equals the runtime with the helper address written into those four slots (byte-for-byte); deployed codehash in the canonical local deployment `0xc81c07674a9c0de9f1a360a4ea7cffcab499c8c679f214939b83e55234c3e192` (helper at nonce 0, verifier at nonce 1 of the first default account) |
| Helper | 21,622 bytes; keccak256 equals the `F1600_CODEHASH` constant; sha256 `f26320c4…612c4`; rebuilt from `f1600_core.hex` by the vendor's tool (`--check` passes); the core's generator is lost upstream |
| Constructor refusal | deploying with the probe's address, the verifier's own address or an address without code reverts `BadHelper` |

What this does **not** show: equality with a build made by the vendor's `forge build`. No ML-DSA-65 artefact or
deployment has been published by the vendor; `forge` could not be installed here (`TOOLCHAIN.md`). The metadata
hash embeds source-unit names, so even an identical compiler and settings give a different last 51 bytes under a
different layout; the code before the CBOR tail is the comparable quantity, and it is recorded.

## 4. Conformance campaign (`test/Conformance.test.ts`, `results/conformance.json`)

Command (from the repository root):

```bash
npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts test prototype/vnext-kernel/pq-verifier-spike/test/Conformance.test.ts
```

| Family | Source | n | ACCEPT | REJECT | REVERT | not run | Expected verdicts met |
| --- | --- | --- | --- | --- | --- | --- | --- |
| acvp | NIST ACVP ML-DSA-65 sigVer vsId 42 tgId 3 (external, pure; contexts 0–255 B, messages ≤ 8 KB) | 15 | 3 | 12 | 0 | 0 | 15/15 |
| wycheproof | C2SP Wycheproof `mldsa_65_verify_test.json` (79 valid, 131 invalid; flags: ValidSignature 66, BoundaryCondition 75, InfinityNormViolation 52, ZeroPublicKey 51, InvalidSignature 49, ManySteps 48, InvalidHintsEncoding 9, ModifiedSignature 8, InvalidContext 5, IncorrectPublicKeyLength 4, IncorrectSignatureLength 3, InvalidPrivateKey 2) | 210 | 79 | 119 | 8 | 4 | 206/206 on chain; the 4 `IncorrectPublicKeyLength` vectors are refused by the client expansion and never reach the verifier |
| rsp | pq-crystals reference KAT `PQCsignKAT_Dilithium3.rsp` counts 0–9 (empty context) | 10 | 10 | 0 | 0 | 0 | 10/10 |
| vendor | ZKNOX's 3 js-generated vectors + the 32-byte-hash vector + one complemented-digest control | 5 | 3 | 2 | 0 | 0 | 5/5 |
| digest32_valid | WalletWall-shaped 32-byte digests, 8 seeded keys, deterministic and hedged signatures | 32 | 32 | 0 | 0 | 0 | 32/32 |
| digest32_negative | wrong digest, zero digest, cross key, 5 single-bit flips, 2 wrong lengths | 10 | 0 | 10 | 0 | 0 | 10/10 |
| znorm_boundary | ‖z‖∞ = γ1−β−1 (accept) and the same field moved to ±(γ1−β) (reject) | 3 | 1 | 2 | 0 | 0 | 3/3 |
| hint_canonicality | valid control + non-zero padding, duplicate index, unsorted indices, count = ω+1, non-monotone counts | 6 | 1 | 5 | 0 | 0 | 6/6 |
| degenerate_key | pk = ρ ‖ 0¹⁹²⁰ with a key-free forgery | 1 | 1 | 0 | 0 | 0 | 1/1 (ACCEPT is the expected, and the finding) |
| **total** | | **292** | **130** | **150** | **8** | **4** | **288/288 on chain, 4 refused client-side as expected; 0 chain/client splits** |

Diagnostics preserved per vector in `results/conformance.json` (`rows[]`: source, interface, expected, outcome,
custom-error name or raw selector, callee gas, `@noble/post-quantum` 0.7.0 verdict, note). Notable rows:

- The 8 REVERTs are Wycheproof's 5 `InvalidContext` vectors (`ContextTooLong`: a 256-byte context, including the
  four encodings of a mis-signed length) and its 3 `IncorrectSignatureLength` vectors (`InvalidSignatureLength`).
  The verifier refuses with a custom error rather than returning `false` on the context path; on the ERC-7913 path a
  wrong signature length returns `0xFFFFFFFF` at ≈ 3.4 k gas.
- The 4 not-run vectors are Wycheproof's `IncorrectPublicKeyLength` groups (1,951 and 1,953 bytes): the client
  expansion refuses them before any chain state exists; the verifier never sees a canonical public key.
- Hint-canonicality and ACVP "modified signature - hint" rejections fire in the decoder at ≈ 49–51 k gas; the norm
  gate rejects at ≈ 140 k gas; full verifications cost 1.53–2.46 M depending on message length.
- Expansion pins: all 52 published keys' blobs match an earlier expansion (26 pinned by the vendor's own test
  file, 26 by the feasibility run on the upstream ESM module). Both pin sources are outputs of the same
  `js/mldsa65.js`, so this is a **drift check**, not an independent oracle; the expansion's correctness is
  evidenced by the 130 on-chain acceptances across 52 keys (a wrong `A`, `t1` or `tr` makes `c̃` mismatch).

**This is partial conformance evidence.** It covers the inputs listed. It is not an independent cryptographic
review (`INDEPENDENT_CRYPTOGRAPHIC_REVIEW: NOT_STARTED`), and the agreement of two implementations (`@noble` and
this verifier) on every vector is not soundness (`UNRESOLVED.md` U-13).

## 5. Adversarial challenges (`test/Adversarial.test.ts`, `results/adversarial.json`)

| Challenge | Result | Finding? |
| --- | --- | --- |
| Handles: zero, EOA pointers, non-key code, 1,000-byte blob, swapped halves, hybrid halves from two keys, 39/20/0-byte | REVERT `BadPubKeyBlob` or REJECT; none ACCEPT the genuine signature | no |
| Handles with trailing bytes (41, 72 bytes) | **ACCEPT** | **yes**: only the first 40 bytes are read; an adapter must enforce exactly 40 bytes before any commitment |
| Blobs deployed by a plain `CREATE` outside `setKey` | **ACCEPT** | **yes**: `setKey` adds nothing the verifier checks; handle→key binding must come from a publisher |
| Single-bit flips placed by content: coefficient bytes, padding bits, `tr`, `t1` | REJECT (silently a different key) | **yes**: no integrity signal for a corrupted expansion; a mis-published key is a frozen PQ conjunct |
| Single-bit flip in an ABI length word the reader never loads; single-bit flip in half 1's copy of `tr` (validated for length, never read) | **ACCEPT**, **ACCEPT** | **yes**: blobs with different code hashes name the same key; `EXTCODEHASH(blob)` is not a key identity |
| Half 0 with the row-1 offset word aliased to row 0 (non-canonical ABI layout) | REJECT, no revert | **yes**: shape checks only; a non-canonical layout is read as a different key, not refused |
| Degenerate keys: `t1 = 0` (two fresh ρ), forgery with no secret; `t1 = 1023` everywhere (`pk = ρ ‖ 0xff¹⁹²⁰`), signed by its public witness `(s1, s2, t0) = (0, −1, 0)` over a registrar-chosen challenge | **ACCEPT** ×3 by the verifier and by `@noble`; the `t1 == 0` gate does not see the third key | **yes** (design-level, FIPS-conformant): registration must apply a criterion on the canonical key — seed binding (complete) or the centred-lift floor (0/1,536 large coefficients for all three degenerate keys, 1,413–1,447/1,536 for the genuine ones); a proof of possession cannot reject the class |
| Signatures of 0 / 3,308 / 3,310 / 4,096 bytes; constant 0x00 and 0xFF signatures | wrong lengths: `0xFFFFFFFF` at 3,433–3,437 gas (3-arg), `InvalidSignatureLength` at ≈ 3.8 k (4-arg); constants REJECT at 82–138 k | no |
| Public keys of 0 / 32 / 1,951 / 1,953 / 40,320 bytes at expansion | refused by the client | no (but canonical-key validation is entirely off-chain) |
| Helper code replaced at the bound address (`hardhat_setCode`), twice | REVERT `BadHelper` on every call; restored → ACCEPT | no: the pin holds; residual risk is the pinned bytes' provenance |
| Raw permutation on 50 states and batched SHAKE256 on 37 messages (36 distinct lengths) vs `@noble/hashes` | agree | behavioural, not provenance |
| `shake256Any` routing at a µ preimage of exactly 800 bytes (|M| = 734, empty context) | ACCEPT via the raw-permutation path; 733 and 735 via the batched path | no |

## 6. Upstream test suites and formal checks

`forge` could not be installed (`TOOLCHAIN.md` §2). The vendor's Foundry suites for the ML-DSA-65 verifier and its
hash layer were executed instead on Hardhat 3's Solidity test runner (EDR), in a scratch project outside this
repository, with one import-specifier rewrite (`InterfaceVerifier/` → `interface-verifier/`) that Hardhat's
package-name rule forces and that touches no logic:

| Upstream suite | Result on EDR |
| --- | --- |
| `test/dilithium65_vectors.t.sol` (28 vendor vectors + the ERC-7913 selector test) | 2/2 pass |
| `test/dilithium65KATS.t.sol` (reference KAT count 0) | 2/2 pass |
| `test/shake_fast.t.sol` (helper-backed SHAKE256 / SampleInBall, 3 fuzz × 256) | 7/7 pass |
| `test/dilithium65_core_packed.t.sol` (packed core vs scalar reference, boundaries, decoder rejections, 6 fuzz × 256) | 18/18 pass |
| **ML-DSA-65 total** | **29/29 pass** (`upstream-run/mldsa65-suites.log.txt`) |

The rest of the vendor's suite (ML-DSA-44, ETH-Dilithium) needs the vendor's Python venv through `vm.ffi` and the
unsupported `startBroadcast` cheatcode; it is outside the candidate and was not exercised. **No formal artefact
exists for ML-DSA-65**; Fireblocks' Z3 obligations for the shared sponge glue were not run (no Z3 here). Running
a suite under EDR is not running it under forge: coverage, snapshots and forge's fuzzer were not used.

## 7. Measurements (`test/Measurements.test.ts`, `results/measurements.json`; local EDR, Osaka rules, no base fee, no L1 data fee)

| Quantity | Value |
| --- | --- |
| Helper deploy | 4,716,328 gas; 21,622 runtime bytes |
| Verifier deploy | 5,242,460 gas; 24,272 runtime bytes (24,479 creation) |
| `setKey` (8 keys) | 8,709,985 – 8,710,285 gas used (estimate 8,804,523 – 8,804,819); 40,388 calldata bytes; two code halves of 20,161 bytes |
| `verify(pk, bytes32, sig)`, STATICCALL cost including the callee, 32 valid digests | 1,538,385 – 1,548,867 gas, mean 1,543,262 (a `gasleft()` delta around the probe's STATICCALL: the verifier's consumption plus the call opcode itself, ~0.2 %) |
| Direct transaction (6 vectors): execution gas = `eth_estimateGas` − intrinsic calldata gas | 1,543,322 – 1,549,072 gas; 3,556 calldata bytes; raw estimates in this run 1,618,806 – 1,624,712 (the intrinsic part moves by a few gas with the zero bytes of the handle's addresses, so only the execution part is compared) |
| k verifications in one call, k = 1..10: STATICCALL loop cost (callee plus call opcodes) | 1,543,566 / 3,082,348 / 4,624,703 / 6,167,486 / 7,704,235 / 9,239,718 / 10,780,497 / 12,322,082 / 13,856,017 / 15,390,213 |
| k = 1..10: transaction execution gas (estimate − intrinsic) | 1,544,511 / 3,083,294 / 4,625,650 / 6,168,434 / 7,705,184 / 9,240,668 / 10,781,447 / 12,323,033 / 13,856,969 / 15,391,166; calldata 3,780 + 3,552·(k−1) bytes |
| EIP-7825 cap (16,777,216) | k = 10 sent as a real transaction at exactly the cap: 15,958,382 gas used in this run (15,391,166 execution + 567,216 intrinsic); a transaction at cap + 1 is refused by the node ("exceeds transaction gas cap"); k = 11 would not fit |
| Refusals | wrong signature length 3,437; `BadPubKeyBlob` 15,580; norm gate 140,307; hint count 48,793; wrong digest / cross key ≈ 1.54 M (full verification) |

Compared with the feasibility lane's figures (solc 0.8.26, cancun, in-process Hardhat 2): runtime size identical
(24,272), direct-transaction estimates identical (1,618,806 – 1,624,712), `setKey` within 0.7 %, deploy within 20
gas. **Base-specific economics stay UNKNOWN** (`UNRESOLVED.md` U-10).

## 8. Independent fresh-context review

`REVIEW.md` holds, verbatim, a fresh-context review of the vendored code, the tests, the records and the
documents (AI-assisted, read-only, 2026-11-09; **not a security audit**), followed by the response. It re-derived
the z decoder, the hint parser and `useHint` from the source and checked them exhaustively against FIPS 204, ran
the suite, and ran its own degenerate-key experiment. Its findings, and what happened to each:

| Finding | Severity | Response in this PR |
| --- | --- | --- |
| A-1 the degenerate-key class is wider than `t1 = 0` and a proof of possession cannot reject it | HIGH | confirmed on chain (`t1 = 1023` key, public witness); `PUBLISHER_BINDING.md` rule 3 and U-3 rewritten around seed binding / the centred-lift floor; the PoP-as-remedy claim withdrawn |
| A-2 soundness rests on an unregenerable 19,617-byte Keccak core; behavioural evidence only | HIGH | U-2 re-rated HIGH; open |
| A-3 the handle binds to nothing canonical; census missed half 1's `tr` and aliased offsets | MEDIUM | both added to the census (half-1 `tr` ACCEPTS; aliased layout accepted as a blob); U-4 extended |
| A-4 `PUBLISHER_BINDING.md` inconsistencies (H(pk) "without registry state", SHAKE128 through the helper, PoP) | MEDIUM | all three corrected |
| A-5 unexercised accept-path code: SampleInBall fallback, inverse-NTT lane canonicality | MEDIUM | recorded as U-15, U-16; open |
| A-6 expansion pins are a drift check against the same code; counts wrong | LOW | wording and counts corrected (26/26) |
| A-7 documentation drift (SHAKE128 attribution, 36/37, 210/210 headline, stale file names, uncommitted state) | LOW | all corrected; the reviewed state is now committed |
| A-8 "callee gas" includes the STATICCALL opcode | LOW | labels corrected, figures unchanged |
| A-9, A-10 collapsed failure modes; `pk` length unchecked | INFO | recorded (U-4, U-5) |
| A-11 what was verified correct | INFO | kept as the reviewer's own words |

What the review did **not** change: the status line of this record. One AI-assisted review is not the independent
cryptographic review the open items require.

## 9. What a reader may conclude, and what not

May: the pinned implementation agreed with NIST, Wycheproof, the reference KAT and the vendor's own vectors on
every input run here; its bytes compile reproducibly under the pinned toolchain and the deployed code is exactly
the compiler's output; the helper pin is enforced; the recorded gas and size figures are what this EVM produced.

May not: that the verifier is sound, that it has no defect outside these inputs, that the helper bytes implement
Keccak-f[1600] for all inputs, that the shared hash layer is acceptable, that any registration rule short of seed
binding or the centred-lift floor stops the degenerate-key class, that a kernel can consume it without an adapter
and a publisher, or that any of this is approved. Those are the open items of `UNRESOLVED.md` and the owner
decisions of the feasibility record.

Stop line of this lane: `GEN2-PQ-CONFORMANCE-1_HUMAN_REVIEW_REQUIRED`.
