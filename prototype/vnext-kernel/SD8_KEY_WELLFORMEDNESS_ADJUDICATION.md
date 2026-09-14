# SD-8 — key well-formedness at every credential-installation edge

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> Adjudication only. This lane changes **zero bytes** of `VaultKernelPrototype.sol`, of the
> Generation-1 root, of the admitted verifier class, of production `contracts/`, of the ledger
> (`stateful/defects.ts`) and of every receipt. It adds one tracked reproduction and this record.
> Nothing was pushed, no PR was opened, no version was bumped.

**Base:** `origin/main` = `e9cd74e6fbed0273489b819f58d44316f72b90a9`, tree
`19b2f6f35c9d705dea9e82707560ece4f1441186` (the merge commit of PR #198, SD-11).
**Worktree:** `C:\dev\wv-sd8-adjudication`, branch
`security/vnext-sd8-key-wellformedness-adjudication`, created at exactly that commit; the shared
checkout was never branch-switched.
**Frozen input:** SD-11 / PR #198. Only root-created `ImmutableAttestationPQCVerifier` instances
are admissible; verifier provenance is never the variable below. Every verifier in the
reproduction is created by `ImmutableAttestationVerifierFactoryPrototype.deployVerifier`.
**Baseline before any edit:** `test/Sd67CommitmentAdmission.test.ts` (the file SD-8's
`reproducedBy` names) **20 passing / 0 failing**.
**This lane's evidence:** `test/Sd8KeyWellFormednessAdjudication.test.ts`, sha256
`dcc244f787f8f0cae8477dc0f0f1322206f79bd2baf6c3f813a455b592248189`,
**29 passing / 0 failing** (mocha's own summary).

## 0. The question, and the five properties it is made of

Genesis proves knowledge of a preimage of the PQ credential commitment
(`I-COMMITMENT-EXHIBITED-AT-ADMISSION`). Does it also establish that the supplied preimage is a
valid, well-formed public key for the admitted Generation-1 verifier relation?

The lane's central discipline is to keep five properties apart, because collapsing them is how
the answer gets over- or under-read:

| # | Property | Who can establish it | Where it is established today |
|---|---|---|---|
| P1 | knowledge of bytes | anyone who can produce calldata | trivially, by calling |
| P2 | preimage consistency: `keccak256(bytes) == commitment` | the kernel | **every edge** — the kernel's ONLY check on key bytes (§1) |
| P3 | verifier acceptance: `verify(...) == true` | the admitted class | armed rotation and armed recovery only; it is an EIP-712 statement by the attestor binding `keccak256(publicKey)` and nothing else about the bytes (§1.3) |
| P4 | key well-formedness: the bytes decode as an ML-DSA-65 public key | for ML-DSA-65, **exactly** `length == 1952` (§1.4) | **off-chain only**, in the attestor's verifier `src/verifier/ml-dsa-65.ts:62` |
| P5 | proof of possession: a signature under the key verifies | the attestor's off-chain ML-DSA verification (`ml-dsa-65.ts:70`) | **off-chain only**; the chain sees the attestor's word |

Evidence labels are inherited from lane SD-11: `REACHABLE` (a named principal calls a real
function on a really deployed contract), `CONSTRUCTED_CONTROL` (built only to measure what a layer
checks). The BLIND attestor used below is a constructed control — an attestor key that signs
whatever it is handed. It is not a claim that the repository's attestor tooling is blind; that
tooling (`verifyMLDSA65Detailed`, the function `scripts/lib/attestation.ts:195` gates signing on)
is imported and IS the HONEST attestor. §F of the test asserts mechanically that no `setCode`,
`setStorageAt`, `setBalance` or `impersonateAccount` is called.

---

## 1. Phase D1 — the admission chain, re-derived from source and from the compiler's AST

### 1.1 Genesis, in execution order (`VaultKernelPrototype.sol`)

| Step | Check | Line | About the key bytes? |
|---|---|---|---|
| input | `initialize(GenesisConfig calldata g, bytes calldata pqKey)`; `g.pqKeyHash` is enumerated into `genesisSalt`, `pqKey` is a witness parameter and NOT salted | `:370`, `:233` | `pqKey` is the only key material; it is never stored |
| 1 | `g.signer`, `g.verifier` non-zero; `g.verifier.code.length != 0` | `:380`–`:382` | no |
| 2 | `_requireAdmissibleVerifier(g.verifier)` — the Generation-1 root created it (SD-11, frozen) | `:385`, helper `:577` | no |
| 3 | `_requireCanonicalRoster` | `:388` | no |
| 4 | `_requireSaneFloor(g.floor)` — VACUOUS since SD5-I: `if (!floor.requirePq) return;` is its whole body | `:389`, body `:462` | no |
| 5 | `requirePq && pqKeyHash == 0` refused | `:392` | zero-ness of the commitment only |
| 6 | **`g.pqKeyHash != 0 && keccak256(pqKey) != g.pqKeyHash` → `BadSignature`** | `:417` | **P2 and nothing else** |
| write | `pqPublicKeyHash = g.pqKeyHash` | `:421` | the hash; the bytes are discarded |

There is no possession digest at genesis. The "exhibit" is the raw bytes compared by keccak256.
No verifier is consulted, by design (`:403`–`:410`: the deployer chooses `g.verifier` in the same
transaction).

### 1.2 The AST census (test §A1–A2, from `solc --standard-json` over the kernel, never from text)

Every read of PQ key bytes in the kernel — the `pqKey` parameters and `CredentialChange.newPqKey`
— falls into exactly three classes, and the counts are asserted:

| Class | Count | Sites |
|---|---|---|
| `keccak256(<key>)` — P2 | **5** | `initialize:417`, `_authorise:658`, `_requireIncomingPossession:839` (dormant) and `:843` (armed), `setVerifier:1123` (the arming edge) |
| `<verifier>.verify(_, <key>, _)` — P3 | **2** | `_authorise:661`, `_requireIncomingPossession:844` |
| forwarded verbatim to `_authorise` | 4 | `execute`, `rotateCredential`, `setVerifier`, `setPolicy` |
| **`<key>.length`** | **0** | — |
| any other read | **0** | — |
| `algorithmId` referenced anywhere | **0** | `IPQCVerifier.algorithmId()` exists and the kernel never calls it |
| `pqPublicKeyLength` / `pqSignatureLength` read anywhere | **0** | the floor is copied as a struct (`:419`) and its length fields are never consulted — E-PRIME measured, not asserted |

### 1.3 The admitted class (test §A3, from the Hardhat build-info AST and the artifact ABI)

`ImmutableAttestationPQCVerifier.verify` (`contracts/verifiers/ImmutableAttestationPQCVerifier.sol:79`)
reads `publicKey` **exactly once**, as the argument of `keccak256` at `:89`
(`publicKeyHash != keccak256(publicKey)` → `false`). It never reads `publicKey.length`. Its ABI is
exactly `{ATTESTED_ML_DSA_65_ALGORITHM_ID, algorithmId, attestor, eip712Domain, verify}` — there
is no entry point a kernel could call to ask "is this a key". The prototype copy is byte-identical
to the production file (sha256 `c505a890…`, SD-11 CLASS ASSURANCE), so this is a statement about
production too.

**Stated precisely, as the lane brief asked:** under the Generation-1 relation the on-chain
verifier treats `publicKey` as **opaque bytes whose keccak256 is attested off-chain**. "Well-formed
for the admitted relation" is a vacuous predicate on chain: every byte string, the empty string
included, is "well-formed" for it. Well-formedness lives in one place — the attestor's off-chain
verifier — and is applied at attestation time, never at commitment time.

### 1.4 What "well-formed ML-DSA-65 public key" mechanically means (test §A4, `@noble/post-quantum` 0.7.0)

| Input | Library behaviour |
|---|---|
| 0, 1, 32, 1951, 1953 bytes | `verify` **throws** on input validation: `"publicKey" expected Uint8Array of length 1952` — refused before any cryptography |
| 1952 bytes, any content (arbitrary, all-zero, all-0xff) | **decodes** as a public key and `verify` returns `false` for the presented signature |
| the real key from `keygen` | `verify` returns `true` for its own signature |

FIPS 204 `pkDecode` is total on 1952-byte inputs (t1 is packed in 10-bit fields and every 10-bit
value is in range), so there is no "encoding-invalid" 1952-byte key. For ML-DSA-65, P4 is exactly
`length == 1952`; everything beyond it is P5.

---

## 2. Phase D2 — deterministic reproductions at genesis, against the real admitted class (test §B)

One Generation-1 root, one root-created verifier, one factory bound to the root. Nine genesis
configurations, all `requirePq = true` with the declared ML-DSA-65 shape 1952/3309, commitment
`keccak256(K)`, witness `K`. Every row is `REACHABLE`. The honest attestor is the repository's
own `verifyMLDSA65Detailed`, handed a 3309-byte claimed signature so its refusal is attributable
to the key and never to the signature's shape.

| K | length | length-valid | honest attestor's reason | genesis | spend, honest attestor | spend, blind attestor |
|---|---|---|---|---|---|---|
| REAL ML-DSA-65 (positive control) | 1952 | yes | `ML_DSA_65_VALID` | ADMITTED | **ADMITTED** (1 ETH moved) | ADMITTED |
| K0-empty | **0** | no | `INVALID_PUBLIC_KEY_LENGTH` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1-one-byte | 1 | no | `INVALID_PUBLIC_KEY_LENGTH` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K32-harness-shape | 32 | no | `INVALID_PUBLIC_KEY_LENGTH` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1951-short | 1951 | no | `INVALID_PUBLIC_KEY_LENGTH` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1953-long | 1953 | no | `INVALID_PUBLIC_KEY_LENGTH` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1952-arbitrary | 1952 | yes | `VERIFY_FAILED` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1952-all-zero | 1952 | yes | `VERIFY_FAILED` | ADMITTED | `VerifierDenied` | **ADMITTED** |
| K1952-all-ones | 1952 | yes | `VERIFY_FAILED` | ADMITTED | `VerifierDenied` | **ADMITTED** |

Controls that make the table attributable:

* **B1 (negative):** the same 1952-byte construction with **no** witness is refused with
  `BadSignature` — the preimage leg is live, so every `ADMITTED` above is a consistent exhibit,
  never a missing check.
* **B0 (positive):** the real key is admitted, the honest attestor attests, the vault spends.
* **Blind column (constructed control):** same vault, same bytes, same digest, same attestor key;
  only the attestor's conduct differs, and the spend lands for every construction including the
  empty key. The chain's grip on the key is therefore exactly the attestor's statement about its
  hash.
* **B3 (degenerate case):** `keccak256("")` is a fixed, non-zero, universally known value. A
  deployer who commits it "exhibits" it by passing **no bytes at all**: an omitted witness and an
  exhibited empty key are the same calldata, so for this one commitment the exhibit requirement is
  vacuous. Documentary, not authority-bearing — an exhibit never proved possession of anything.

**What is and is not claimed about the 1952-byte rows.** They are length-valid, they decode, and
the signature presented does not verify under them. Whether any secret key exists for them is the
MLWE problem and is not decided here.

---

## 3. Phase D3 — consequence: what actually fails, and for whom (test §C)

Measured on the extreme construction (armed vault committed to `keccak256("")`):

| Outcome asked about | Measured | Evidence |
|---|---|---|
| dead / unspendable credential | **YES, self-inflicted at cut 0.** `execute` → `VerifierDenied` under the honest attestor | B2, C1 |
| downgrade of the PQ factor | **NO.** The ECDSA factor alone cannot spend (`pqSig` empty → `VerifierDenied`); the conjunct is mandatory and unsatisfiable, not bypassed | C1 |
| recovery-only liveness dependence | **YES.** `rotateCredential` and `setVerifier` are HYBRID-authorised, so the credential cannot repair its own vault (`VerifierDenied` on the outgoing leg); a guardian quorum can — `initiateRecovery` → +7 d → `executeRecovery` with the honest attestor's PoP over a real key → the vault spends again | C2, C4 |
| false proof-of-possession | **NO under the honest attestor** (armed rotation and armed recovery refuse malformed material, §4). Possible only under a blind attestor, which already forges every spend outright — attestor compromise dominates everything SD-8 touches and adds nothing to it | D1, D4 |
| state incoherence | **YES, documentary.** `securityFloor().pqPublicKeyLength == 1952` while the committed preimage is 0 bytes. §1.2 measured that no kernel function reads that field: it is signed metadata E-PRIME de-authorised. It can mislead an observer; it changes no authorisation, possession or recovery outcome | C5 |
| attacker gains authority | **NONE.** The commitment is inside the CREATE2 salt: with the same label, salt, signer and roster, every malformed configuration lands at a different address from the honest one and from each other (`I-COUNTERFACTUAL-IDENTITY-BINDING`). Rotation needs the outgoing HYBRID authorisation; recovery needs the quorum. No cut moves | C3 |
| honest owner loses authority | only a deployer who commits bytes they cannot sign — indistinguishable from committing a real key and destroying it, as the ledger already says | — |

**Authority delta: zero.** Roots required: 0. Escapable at `k`. The consequence is a
self-inflicted, escapable liveness outcome plus non-authoritative metadata incoherence.

---

## 4. Phase D4 — the same question at every credential-installation edge (test §D)

| Edge | Kernel's check on the bytes | Verifier consulted? | Honest attestor | Blind attestor (control) |
|---|---|---|---|---|
| genesis, armed or dormant | P2 (`:417`) | **no** | — | — |
| `rotateCredential`, armed floor | P2 (`:843`) + PoP via `verify` (`:844`) against the **current** verifier | yes | refuses K0 and K1952-arbitrary (`BadSignature`), admits a second real key | **installs the empty key and arms it**; the vault is then dead under the honest attestor |
| `rotateCredential`, dormant floor | P2 (`:839`) | **no** — `newPqPop` empty and the install lands | — | — |
| `setVerifier`, the arming edge (`requirePq` false → true) | P2 (`:1123`) | **no** | — | a dormant empty commitment becomes MANDATORY on a preimage alone; the vault is dead afterwards and not downgradable back |
| `initiateRecovery` | none — a bare `proposedPqKeyHash`, no exhibit (by design; the exhibit is at install) | no | — | — |
| `executeRecovery`, armed floor | P2 (`:843`) + PoP via `verify` (`:844`) against the **incoming** verifier | yes | refuses the empty key; the request stays live (`recovery.active == true`) — a refused completion consumes nothing | the same live request then **installs the empty key** |
| `executeRecovery`, dormant floor | P2 (`:839`) | **no** | — | — |

**Per-edge result.** The on-chain gap is identical at **four** sites, not one: genesis, dormant
rotation, dormant recovery and the arming edge. The two armed install paths enforce something
stronger — but only by virtue of the attestor's OFF-CHAIN check inside the PoP, never by anything
the chain evaluates about the bytes. A fix covering genesis only would leave three sites with the
same gap; a fix that assumed the armed paths already establish P4/P5 on chain would be wrong.

---

## 5. Phase D5 — candidate controls (test §E measures the discriminators; no kernel was mutated, no candidate implemented)

| Candidate | Proves | Does NOT prove | New principal / authority? | Couples kernel to a scheme? | Liveness / upgrade problem? | Enforceable at every Gen-1 install path? | Disposition |
|---|---|---|---|---|---|---|---|
| **(a) fixed kernel length gate, 1952** | P4 — for ML-DSA-65 that is the whole of FIPS 204 well-formedness (§1.4) | P5. E1 measured: it refuses five of eight constructions and **admits the three 1952-byte ones, which are exactly as dead** (`VerifierDenied`) | no | **yes, to one scheme.** Every other suite's honest verifier commits 32-byte keys (`HONEST_FLOOR.pqPublicKeyLength == 32`); a later generation with another parameter set needs a kernel change | upgrade: yes — the exact-tuple family SD5-D1 rejected ("closes only by making the kernel single-scheme") | yes, at the five preimage sites | **REJECTED** for the kernel: repeats a rejected family and buys install-time refusal of the accidental wrong-length class only |
| **(b) verifier-class-supplied validation** (e.g. `isWellFormedKey(bytes)` on the class, called by the kernel at every install site) | P4 per class. Post-SD-11 this is **not** self-certification: the class is fixed by the root, and length involves no attestor | P5 — the same three 1952-byte rows pass it and are dead | no | to the class, which is already scheme-named; the KERNEL gains a second plane call per install | genesis/dormant/arming gain a STATICCALL to a root-fixed class (no attestor liveness); adding the entry point **changes the byte-identical production class** and `IKernelPQVerifier`, so SD-11 CLASS ASSURANCE must be re-established and `contracts/` changes (out of this lane's scope) | yes: three new call sites plus the two existing verifier sites | **POSSIBLE, LOW VALUE.** The only candidate that proves anything on chain without a new principal; what it proves is length. Owner decision |
| **(c) possession proof against the admitted relation at genesis / dormant / arming** | P3 at that moment; under an honest attestor, P4 + P5 | anything against a DELIBERATE deployer. E3 measured: the deployer chooses the attestor (it is the root verifier's salt), so the deployer's own attestor "proves possession" of the empty key | no new principal — but the attestor becomes a party to genesis | no | **yes:** `verify` with no attestation returns `false` (E3), so no vault can be born, no dormant rotation land and no arming succeed while the attestor is unavailable; the digest at genesis must bind the predicted address | mechanically yes | **REJECTED** as a defence (self-certification survives SD-11 unchanged); moves an ACCIDENT from first use to install at the price of attestor liveness on three more edges. This is the ledger's rejected candidate (c), re-measured |
| **(d) attestor-backed validity statement** (a second typed statement, "this hash is a well-formed key") | P4 by the attestor's word | P5; anything the attestor did not check | same principal as (c) | no | same liveness cost as (c); needs a new statement type on the class → same SD-11 re-establishment as (b) | yes | **DOMINATED** by (b) (which needs no attestor) and by (c) (which also proves P5 when honest) |
| **(e) opaque bytes — the status quo, stated deliberately** | P2 on chain | P4, P5 on chain; both are the attestor's off-chain duties under the Generation-1 trust model the class's own NatSpec states | no | no | no | uniform at every edge | **THE CURRENT DESIGN.** Correct to keep unless the owner wants (b); what it lacks is a ledger entry that says this precisely |

**Bias check.** The status quo is not chosen because it is cheapest. It is chosen because §1.3 and
§2 measure that the admitted relation cannot establish P4 or P5 on chain at all, so every candidate
either proves only length (a, b, d) or delegates to the attestor (c, d) — the trusted-attestor
model is the whole content of Generation 1.

---

## 6. Verdict

**SD-8: `SUSTAINED` as a declared residual, `RE-CHARACTERISED` in three respects, `NO SECURITY
DEFECT ESTABLISHED`. Three of the brief's stop conditions are met, so this lane STOPS before
remediation.**

What stands, measured: no layer on chain establishes key well-formedness or possession at any
credential-installation edge; the exhibit proves P2 and nothing else. That is the ledger's claim
and it is true.

What the existing characterisation gets wrong (corrections owed, not applied — the ledger is
outside this lane's write scope):

1. **Judging party.** The entry says "the only party able to judge whether key bytes are well-formed
   for a scheme is a verifier". Under the admitted Generation-1 relation the verifier **cannot**
   judge it (§1.3). The judging party is the attestor's off-chain verifier
   (`src/verifier/ml-dsa-65.ts`), and it judges at attestation time, not commitment time. The
   same sentence appears in `AUTHORITY.md:212` and in `SD11_VERIFIER_ADMISSION_ADJUDICATION.md`
   §4 ("key STRUCTURAL validity — only a scheme-aware verifier").
2. **Length scope.** The title says "correct-length garbage". Every length is admitted, **zero
   included** (§2), and for the empty key the exhibit requirement is vacuous (B3).
3. **Edge scope.** The id says "genesis-exhibit". The identical gap is at four sites (§4); the
   armed paths are stronger only through the attestor.
4. **A figure.** `rootCause` says keccak256 "cannot distinguish an ML-DSA public key from 1,312
   bytes of noise". 1,312 bytes is ML-DSA-44; the admitted class is `ATTESTED-ML-DSA-65`, whose key
   is 1,952 bytes.
5. **`reproducedBy`** should name this file beside `Sd67CommitmentAdmission.test.ts`.

Stop conditions met (from the brief):

* *the trusted-attestor model makes "key validity" a property that cannot be independently
  established on-chain* — measured at §1.3 and in the blind column of §2;
* *the existing SD-8 characterisation is materially wrong* — in the four respects above, though
  not in its verdict;
* *the evidence does not establish an actual security/liveness defect* — §3: authority delta zero,
  self-inflicted, escapable at `k`; the only liveness outcome is the one the ledger already
  declares.

**Implementation: NOT WARRANTED** on this evidence. Candidate (b) is the only control that proves
anything on chain without a new principal, and what it proves is a length that leaves three of the
eight constructions exactly as dead; it costs a change to the byte-identical production class and
an SD-11 re-establishment. That trade is the owner's to make, not this lane's.

---

## 7. What this lane does NOT establish

* That any 1952-byte construction has no secret key (MLWE).
* Anything about the attestor's honesty as a trust assumption; Generation 1's trust model is the
  class's NatSpec, and this lane measures inside it.
* Anything about SD-11 (frozen), SD-2 or SD-4, the ZK/SP1 path, or any future generation.
* Whether the ledger's `classification: STATE_INCOHERENCE` should read `LIVENESS_DENIAL`: the
  measured consequence is both a self-inflicted liveness outcome and a documentary incoherence.
  That is a wording decision for the owner.

## 8. Verification

| Item | Value |
|---|---|
| new tracked files | `test/Sd8KeyWellFormednessAdjudication.test.ts`, this record |
| tracked files modified | **0** — `git status` shows only the two additions |
| `contracts/`, `prototype/vnext-kernel/contracts/`, `stateful/`, receipts, `package.json` | untouched |
| new test | 29 passing / 0 failing (6 sections: A ×4, B ×11, C ×5, D ×5, E ×3, F ×1) |
| baseline `Sd67CommitmentAdmission.test.ts` | 20 passing / 0 failing |
| whole prototype suite with the new file present | **913 passing / 0 failing** (7 min; mocha's own summary, exit 0) = the 884 recorded at the SD-11 head plus the 29 here; every ledger, currency and provenance guard still green |
| constructions | 8 malformed + 1 real positive control; 4 controls (B0, B1, B3, blind column) |
| edges measured | genesis, rotation (armed, dormant), arming edge, recovery (armed, dormant) |
| ML-DSA-65 library | `@noble/post-quantum` 0.7.0, lengths `{publicKey: 1952, signature: 3309, seed: 32}` |
| network writes | none; no push, no PR, no deployment, no version bump |

---

## 9. Reconciliation — applied in the second local commit, after this record was frozen

This record and its test are the FINDING commit (`e77ef423`) and are unchanged by what
follows except for this section. The reconciliation commit that follows it applies the
corrections §6 listed as "owed, not applied", and nothing else:

| Site | What changed |
|---|---|
| `stateful/defects.ts`, SD-8 entry | title, `rootsRequired`, `contradicts`, `rootCause`, `notAnEscalationBecause`, `minimalFixSketch` and `reproducedBy` rewritten to the measured characterisation: judging party = the relation's OFF-CHAIN attestor; ANY length, zero included; FOUR sites; ML-DSA-65 at 1,952 bytes. The five properties (PREIMAGE KNOWLEDGE, HASH CONSISTENCY, OPAQUE-BYTE COMMITMENT, ATTESTOR VERIFICATION, SECRET-KEY POSSESSION) are named and kept apart. The id is retained, deliberately: SD-6 and SD-7 name it as their residual, and the entry is corrected in place on the SD-1 precedent. |
| `test/StatefulSustainedDefects.test.ts` | one new ledger assertion pins the corrected claims by text and asserts the refuted forms absent, so the earlier wording cannot return through an edit nobody re-measures. |
| `stateful/invariants.ts` (`G-COMMITMENT-ATTESTED` comment), `test/Sd67CommitmentAdmission.test.ts` (residual-test comment) | the same judging-party sentence corrected; no predicate and no assertion changed. |
| `AUTHORITY.md`, `SD11_VERIFIER_ADMISSION_ADJUDICATION.md` §4 | append-only corrections on the precedent of the earlier ones; the original sentences are retained as written. |

**Classification chosen: `STATE_INCOHERENCE`, retained** — and §7's open question is thereby
closed. The ledger's two values divide by MECHANISM, not by outcome (every entry is a liveness
outcome by the ledger's own header): `LIVENESS_DENIAL` entries (SD-1, SD-2, SD-4, SD-5) each
have a principal depriving another beyond a declared bound; `STATE_INCOHERENCE` entries (SD-6,
SD-7, SD-11A, SD-11B) each admit state that does not carry the property the published
semantics attribute to it. SD-8 measured is the second kind: a commitment the floor declares
mandatory is not a credential of the admitted relation, and no on-chain layer can tell (§1).
It has roots 0 and overshoots no bound, so `LIVENESS_DENIAL` would assert a denier the evidence
does not contain — a classification may not assert more than its trigger proves. A third value
was considered and rejected: it would widen the receipt vocabulary for a distinction the pair
already carries. The liveness manifestation (§3) is recorded in `notAnEscalationBecause`,
exactly as SD-7 recorded its own.

**Not changed:** `contracts/`, `prototype/vnext-kernel/contracts/`, the verifier class, the
root, the factory, any SD-11 entry or condition, any assertion in this lane's 29 tests. The
stateful receipt is regenerated in a following evidence commit against this reconciliation
commit as its declared subject, per `evidence-subject.ts`.
