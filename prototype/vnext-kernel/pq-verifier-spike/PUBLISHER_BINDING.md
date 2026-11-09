# How a deterministic publisher would bind a canonical ML-DSA-65 public key to its two expanded-key contracts

> **DESIGN NOTE ONLY. Nothing here is implemented.** This lane does not build the publisher, does not change
> any kernel credential commitment, and does not approve any production component. The design exists so the
> owner and a reviewer can judge the gap the conformance evidence exposed before any implementation is proposed.
> Owner decisions it depends on: OD-G2PQ-19 (handle identity), OD-G2PQ-21 (publisher), OD-G2PQ-20 (degenerate-key
> refusal) in `C:/dev/GEN2-PQ-FEASIBILITY-1.md` §3 (owner copy; not in this repository).
>
> Revised after the fresh-context review (`REVIEW.md`, A-1 and A-4): an earlier draft of this note claimed that
> a proof of possession excludes degenerate keys and that the handle is recomputable from the key "without
> registry state". Both claims were wrong and are corrected below.

## 1. What the evidence shows the verifier does, and does not, bind

The vendored verifier (`ZKNOX_dilithium65` at 4c370bb5) takes a 40-byte **handle**: two addresses whose code is
the expanded key (`half0 || half1`, 2 × 20,160 bytes behind a `0x00` STOP byte). `test/Adversarial.test.ts`
records, on the local simulated EVM:

| Observation | Consequence |
| --- | --- |
| Two blobs deployed by a plain `CREATE` outside `setKey`, holding the same bytes, verify exactly like the published ones. | `setKey` adds nothing the verifier later checks. Any address pair with the right code is a key. |
| A corrupted coefficient, `tr` or `t1` byte makes a valid signature fail with no integrity error. | A wrong expansion is silently a *different key*, not a detectable fault: a mis-published key is a permanently unsatisfiable PQ conjunct (liveness). |
| A flipped byte in an ABI framing word the reader never loads, or anywhere in half 1's copy of `tr` (validated for length, never read), leaves every verdict unchanged. | Two blobs with **different code hashes** name the **same key**. A blob's `EXTCODEHASH` is therefore not a key identity. |
| A half whose row offsets alias one polynomial set is accepted as a well-formed blob (for a different key). | The reader checks shape, not canonical layout or field ranges. |
| Bytes after the first 40 of the handle are ignored; `pk.length` is never checked. | Distinct handle encodings (40, 41, 72 bytes) name one key; `keccak256(handle)` over an unnormalised handle is not injective. |
| The verifier never receives the canonical 1,952-byte FIPS 204 public key. | Nothing on-chain today ties a handle to a canonical key, a seed, or a user. Degenerate keys are accepted; only a gate that sees the canonical key can refuse them. |

The kernel in `prototype/vnext-kernel/generation-2` commits to `keccak256(publicKey bytes)` and is scheme-agnostic
(feasibility correction CR-4: the handle can be the committed bytes with no kernel change). What is missing is
the authenticated chain **canonical pk → expanded blobs → handle**, and a registration criterion that excludes
degenerate keys. That is the publisher's job.

## 2. The binding, stated as an invariant

For a canonical key `pk` (1,952 bytes, `rho || t1Encode(t1)`), define

```
E(pk) = (half0, half1) = encodePublicKeyBlob65(expandPublicKey65(pk))      // vendored js/mldsa65.js, deterministic
```

A publisher `P` at a fixed address binds `pk` to a handle `H(pk) = (addr0, addr1)` iff all of the following hold
for every `pk` ever accepted by a kernel:

1. **Address determinism.** `addr_i = CREATE2(P, salt_i(pk), initcode(half_i))` with `salt_i(pk) = keccak256(i || pk)`.
   Because a CREATE2 address commits to `keccak256(initcode)` and the initcode embeds `half_i`, **computing
   `H(pk)` requires computing `E(pk)`**: anyone can do it *off-chain* from `pk` alone (expansion is deterministic
   and the publisher address is fixed), so a registration is auditable without trusting registry state; but a
   contract that wants `H(pk)` *on-chain* must either recompute the expansion (option A below) or read a
   `keccak256(pk) → handle` mapping that `P` wrote at publication. Those are the two choices; this note does not
   claim both at once.
2. **Content determinism.** `EXTCODE(addr_i) == 0x00 || half_i` where `(half0, half1) = E(pk)`. Under rule 1 the
   address itself commits to the exact blob bytes, so the unread-byte and non-canonical-layout observations above
   are harmless: the only blob that can live at `addr_i` is `E(pk)_i` verbatim.
3. **Canonical-key validation at publication.** `P` refuses `pk` unless `pk.length == 1952` **and** the key passes
   a degenerate-key criterion evaluated on the canonical key. The evidence here (`test/Adversarial.test.ts`,
   degenerate keys) and fireblocks-labs/evm-ml-dsa-verifier `docs/SAFETY.md` §3 fix what that criterion can be:
   - **Complete criterion: binding to the KeyGen seed ξ.** The registrant supplies ξ (or proves knowledge of it
     in zero knowledge); `P`, or the client software the kernel already trusts, re-runs FIPS 204 Algorithm 1 and
     requires `pkEncode(rho, t1)` to equal the submitted `pk` byte for byte. No ξ maps to a degenerate key. Cost:
     the registrant must retain ξ; a bare imported `pk` cannot be registered this way.
   - **Registrar-evaluable floor: the centred-lift criterion.** For each of the 1,536 `t1` coefficients `v`, let
     `lift(v) = centre((v · 2¹³) mod q)`; refuse unless enough coefficients have `|lift| > γ2` (here `γ2 = 261,888`).
     `test/Adversarial.test.ts` measures 0/1,536 large coefficients for every degenerate key tried (`t1 = 0` and
     `t1 = 1023`) and 1,413–1,447/1,536 for genuine seeded keys. Fireblocks measured the cheaply forgeable set at
     roughly `|lift| ≲ γ2/4` under message grinding, so this is a **floor to refuse beneath, never a certificate**.
   - **What does not work: a proof of possession, or any proof about the private key.** A key-free-forgeable key
     "has every owner": `test/Adversarial.test.ts` signs a registrar-chosen challenge for the `t1 = 1023` key with
     the public witness `(s1, s2, t0) = (0, −1, 0)` and the verifier accepts it. PoP still has a purpose (binding an
     honest key to the account that registers it) and may be required **in addition**, never instead.
   - **What does not work either: `t1 == 0`.** It is only the most visible member of the class; the all-`0xff`
     key passes it.
4. **Immutability.** `P` has no owner, no upgrade path, no pause, and the blobs are code (EIP-6780: immutable
   after creation). Re-publication of the same `pk` is idempotent (the addresses already have code) and cannot
   change bytes.
5. **No kernel authority.** `P` is called by the user (or anyone) before registration; the kernel only ever reads
   `extcodesize(addr_i) != 0` and, if it commits to `pk` rather than to the handle, the mapping or the recomputed
   `H(pk)`. `P` cannot move assets, approve anything or influence a verdict other than by refusing to publish.

## 3. Three ways to establish rule 2 (content determinism)

| Option | What `P` does | Cost (local figures where measured; Base UNKNOWN) | Trust left over |
| --- | --- | --- | --- |
| **A. Expand on-chain** | Receives `pk`; recomputes `E(pk)` in the EVM; CREATE2-deploys both halves. **Needs SHAKE128 (rate 168) sponge glue over the helper's raw 800-byte permutation entry** for ExpandA: the helper's batched entry is SHAKE256-only (rate 136 hard-wired), and no SHAKE128 glue exists in the vendored closure. Then thirty `RejNTTPoly` samplings and six NTTs of `t1 · 2¹³`. | UNMEASURED. Lower bound: the two SSTORE2 writes alone cost ≈ 8.71 M gas here (`results/measurements.json`, `setKey`); the expansion and the new glue come on top; upper bound 16,777,216 (EIP-7825, enforced on this EVM). Plausible, not shown. | Adds new code (SHAKE128 glue, ExpandA, bit-packing) to the audit scope; the helper is already in the TCB. |
| **B. Expand off-chain, bind by salt only** | Receives `(pk, half0, half1)`; CREATE2-deploys the halves under `salt_i(pk)`; records `keccak256(pk) → handle`. | ≈ 8.71 M gas plus 40,320 bytes of calldata per key (measured for `setKey`). | **Insufficient alone**: the salt binds `pk`, but nothing checks `half_i == E(pk)_i`. A wrong expansion for one's own `pk` is one's own frozen key; a kernel record then carries a `pk` that does not match the verifying key. |
| **C. Expand off-chain, verify a possession signature on-chain** | As B, then verifies one ML-DSA-65 signature over `keccak256(P, pk, addr0, addr1)` through the admissible verifier using the freshly deployed handle. | ≈ 8.71 M + ≈ 1.54 M gas + calldata (40,320 + 3,309 bytes) ≈ 10.3 M, under the per-transaction cap. | Binds the handle to the *submitter's* key, not to the canonical `pk` in the salt (inconsistent `(pk, blobs)` pairs pass if the blobs encode a key the submitter controls), and **does nothing against degenerate keys** (rule 3). |
| **A + rule 3** (recommended for review) | On-chain expansion (so `blobs == E(pk)` by construction) and the degenerate-key criterion of rule 3 (seed binding where ξ is available, the centred-lift floor otherwise), with PoP optionally added for account binding. | Sum of A and the criterion; the centred-lift floor is 1,536 coefficient checks (cheap); seed binding is a full KeyGen (expensive on-chain; cheap in the trusted client). UNMEASURED. | What remains is the verifier's own soundness, the helper's provenance and the correctness of the new expansion code. |

If on-chain expansion proves too expensive under the cap, the fallback that keeps rule 2 honest is **spot-check
expansion**: `P` recomputes a pseudo-random subset of the polynomials of `A` from `rho` and compares them to the
submitted blob words. That is probabilistic, so it must be sized and justified in a review; it is listed, not
endorsed. It does not replace rule 3.

## 4. What the kernel would commit to (no change proposed here)

The kernel already commits to `keccak256(publicKey)` (CR-4). Under this design the committed bytes are the
**canonical `pk`**, never the handle; an adapter obtains the handle either from `P`'s mapping or, if option A is
chosen with the mapping omitted, by recomputing `H(pk)` (which means recomputing `E(pk)` on-chain at every use,
and is therefore not what anyone would build). Committing to `pk` removes the handle-encoding malleability
observed above (the adapter never hashes a handle), keeps the kernel scheme-agnostic, and lets anyone audit a
registration off-chain from the canonical key alone. Whether to commit to `pk` or to `H(pk)` is OD-G2PQ-19 and stays
with the owner. Note also the kernel's rotation proof of possession (`VaultKernelGen2Prototype.sol`,
`_requireIncomingPossession`): under a degenerate key it, too, is answerable by anyone, which is one more reason the
criterion of rule 3 must sit at registration.

## 5. Explicitly not in this lane

- No `P` contract, no CREATE2 factory, no adapter, no kernel change, no test of any of them.
- No decision between seed binding and the centred-lift floor: it depends on whether clients retain ξ (an owner
  decision with a product cost, OD-G2PQ-20).
- No one-time emergency escape credential (excluded by the brief).
- No Base cost figure: every gas number above is from the local simulated EVM in `results/measurements.json`.
