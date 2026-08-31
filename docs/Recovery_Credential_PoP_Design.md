# Recovery Credential Proof-of-Possession (P2) — Design

> **RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY. DO NOT USE WITH REAL FUNDS.**
> The PQ verifier wired into these contracts today is `MockMLDSAVerifier`, which performs **no**
> cryptographic verification. Read `docs/Security_Assumptions.md` before acting on anything here.
> This document is **design and assurance only**. It changes no production contract and authorizes
> no deployment.

**Source anchor.** `origin/main` = `aaba4d2024932ba5fdf131fd9bba5020345af5fb`
(tree `fbfcdb1638b29d4512cccf2cfdf27f82f972455b`), package version `0.13.2`. Every line citation,
byte count, and behavioural claim below was re-derived firsthand at that commit in a dedicated
worktree. All contract sources are byte-identical to that tree; the measurement spikes described in
§11 were reverted and the restore verified by SHA-256 (§11.6).

**Scope boundary.** This lane is **non-overlapping** with the open Guardian Authority remediation
(PR #177, branch `design/guardian-authority-lifecycle-v2`). It is based on `origin/main`, not on
that branch, and it decides none of that lane's open questions. Where the two interact, this
document states the interaction as a **quantified dependency for the owner to resolve** (§11.5,
§16), never as a decision taken here.

---

## 1. CURRENT — the defect, re-derived

### 1.1 The asymmetry

`rotateCredentials` requires proof-of-possession from the **incoming** credentials.
`_authorizeRotation` (`contracts/WalletWallVault.sol:735-775`) builds one EIP-712 digest and checks
four signatures against it — two from the credentials being replaced, two from the credentials
arriving:

```solidity
// ---- New-credential proof-of-possession (incoming keys) ----
if (needEcdsa) {
    if (digest.recover(auth.newEcdsaSignature) != newEcdsaSigner) revert InvalidNewEcdsaProof();
}
if (needPq) {
    if (!pqVerifier.verify(digest, newPQPublicKey, auth.newPqSignature)) revert InvalidNewPQProof();
}
```

Its NatSpec (`:638-641`) states the reason in as many words: this "prevents rotating to an unusable
credential (e.g. a mistyped PQ key) that would otherwise brick a Pq/Hybrid vault, **leaving guardian
recovery as the only exit**."

Guardian recovery — the strictly weaker-authenticated path to **the same two storage slots** —
enforces none of it. `initiateRecovery` (`:451-505`) applies only `_validateCredentials`
(`:777-791`), which is a shape check and nothing more:

```solidity
function _validateCredentials(VaultMode mode, address ecdsaSigner, bytes memory pqPublicKey) internal pure {
    if ((mode == VaultMode.EcdsaOnly || mode == VaultMode.Hybrid) && ecdsaSigner == address(0)) {
        revert ZeroAddress();
    }
    if ((mode == VaultMode.PqOnly || mode == VaultMode.Hybrid) && pqPublicKey.length == 0) {
        revert EmptyPQPublicKey();
    }
}
```

`executeRecovery` (`:534-573`) then writes the guardian-chosen values straight into the vault
(`:545-546`) after the 7-day delay and guardian majority. **Recovery performs no incoming-credential
possession check of any kind, at any point in its lifecycle.** Confirmed by reading all four entry
points; confirmed independently by `test/RecoveryStructuralAssurance.test.ts`, which proves each of
them makes zero external calls — so no `pqVerifier.verify` can be hiding in them.

The same asymmetry exists identically in `contracts/StablecoinVaultSimulator.sol`
(`initiateRecovery:406-455`, `executeRecovery:479-518`, `_authorizeRotation:613-651`). The recovery
surfaces of the two contracts are **executable-statement identical**; only comment text and the
EIP-712 domain `name` differ (`"WalletWallVault"` vs `"WalletWallStablecoinVault"`).

This is already recorded upstream as **HIGH-5** in `docs/Guardian_Authority_Design.md:266-285`,
where the verifier-agnostic remedy is named "P2 — delegated proof-of-possession" and left explicitly
**"OPEN — do not lock"** (`:970-975`). This document closes that question.

### 1.2 The failure cases, classified

Not all of the obvious cases are defects, and treating them as one class is the first mistake
available here.

| # | Case | Class | Is it P2's business? |
|---|---|---|---|
| 1 | Typo in `newEcdsaSigner` | **Possession/liveness** | Yes |
| 2 | Typo or truncation in `newPQPublicKey` | **Possession/liveness** | Yes |
| 3 | Honest guardians recover to a key nobody controls | **Possession/liveness** | Yes |
| 4 | Malformed / wrong-length PQ key accepted into storage | **Possession/liveness** | Yes |
| 5 | Hybrid: one incoming credential valid, the other unavailable | **Possession/liveness** | Yes |
| 6 | Guardians agree on a key nobody controls | **Possession/liveness** | Yes |
| 7 | Malicious guardian majority chooses its own key | **Accepted trust root** | **No** |

Case 7 is not a defect and P2 must not claim to address it. `docs/Security_Assumptions.md:216-219`
states it plainly — a colluding majority can seize the vault; this is social recovery, not trustless
recovery. `docs/Guardian_Authority_Design.md:337-342` repeats it as an ACCEPTED LIMIT. A malicious
majority that *possesses* the credentials it installs is operating the mechanism exactly as
designed, and any PoP check passes for them.

What the accepted limit does **not** cover, and what makes cases 1–6 worth engineering attention, is
stated in the same place: a majority can trigger a permanent brick **by accident**.

### 1.3 What "bricked" actually costs

Precision matters here, because the size of the defect bounds how much liveness risk a cure may
introduce.

After recovery installs an uncontrolled PQ key into a Hybrid or PqOnly vault, every
`pqVerifier.verify` site fails: `withdraw` (`:1120`), `queueWithdrawal`, `finalizeWithdrawal`, and —
critically — `_authorizeRotation` (`:765`, `:773`). So spending stops **and** the voluntary
self-repair path stops with it.

The exit is not absent, though. It is **another full guardian recovery cycle**: 7 days, guardian
coordination, no funds at risk (`executeRecovery` moves no value; the pending-withdrawal refund at
`:568` is a ledger credit to `vault.balance`, not a transfer). So the true cost is:

> **per-vault, ~7 days plus guardian coordination, repeatable, self-repairable, no funds lost.**

That is a real liveness fault. It is **not** an unrecoverable one, and no cure that converts it into
an unrecoverable or contract-wide one can be justified by it.

---

## 2. The property P2 should provide

The candidate wording in the brief was:

```
I-RECOVERY-TARGET-POSSESSION
No recovery may commit credentials requiring authority under the vault's configured
mode unless control of each required incoming credential was demonstrated for that
exact recovery target.
```

**This wording is not adoptable as written**, for one reason that is fatal and one that is
merely misleading.

**Fatal — "demonstrated" is not vault-knowable for the PQ leg.** `IPQCVerifier` declares
`publicKey` as opaque `bytes`, and documents `algorithmId()` as metadata carrying *no security
guarantee*. What `verify()` means is entirely the configured implementation's business. §5 shows
that under the verifier **actually deployed today**, `verify()` carries no possession information at
all. An invariant that asserts possession was "demonstrated" would therefore be **false in the
deployed configuration** while appearing green. The repository has already struck one mechanism
(S-3, `docs/Guardian_Authority_Design.md:722`) for exactly this error — being correct only for the
mock.

**Misleading — "no recovery may commit" reads as a safety property.** It is a *liveness* property
wearing safety's clothes. It does not prevent an attacker from doing anything; it prevents a
principal who is already fully authorized from producing an unusable result. Naming it as a
prohibition invites readers to believe recovery is now harder to abuse. It is not.

### 2.1 The adopted property

```
I-RECOVERY-TARGET-ECDSA-POSSESSION  (target; not implemented in this PR)

  For a vault in EcdsaOnly or Hybrid mode, a recovery request cannot be created
  unless the holder of the incoming ECDSA credential signed, under this contract's
  EIP-712 domain and a dedicated typehash, a statement naming exactly:
  this vault owner, this incoming ECDSA signer, the hash of this incoming PQ key,
  this vault mode, and a deadline.

  It does NOT constrain who may recover, and does NOT bind the incoming PQ key to
  any possession claim.
```

and, as a separate and deliberately *negative* statement:

```
A-RECOVERY-TARGET-PQ-POSSESSION-UNAVAILABLE  (accepted limit; adopted by this PR)

  This system cannot express incoming PQ-credential possession honestly at any
  point in the recovery lifecycle, because the strength of any such check is
  exactly the strength of the configured IPQCVerifier, and that is presently nil.
  The residual is accepted and recorded, not mechanised.
```

Splitting the invariant in two is not a stylistic choice. §5 and §11 show the two legs have
opposite verdicts, and a single merged invariant would have to be reported at the strength of its
weaker half while being *named* at the strength of its stronger half.

---

## 3. Authority model — five identities, and what P2 may touch

Reusing the identity vocabulary already established in `docs/Guardian_Authority_Design.md:86-109`:

| | Identity | Today's authority |
|---|---|---|
| (a) | Contract `owner` (`Ownable2Step`) | Pause, PQ-verifier governance, policy-engine governance |
| (b) | `vaultOwner` — the `vaults[]` key | `setGuardians`, `cancelRecovery`, `createVault` |
| (c) | `ecdsaSigner` | Withdrawal + rotation authorization |
| (d) | `pqPublicKey` | Withdrawal + rotation authorization |
| (e) | Guardian set | Recovery initiation, support, execution |

**P2 introduces no sixth identity and grants no new authority.** This is the single hardest
constraint on the design space and it disqualifies more candidates than EIP-170 does.

A proof of possession is a *predicate on the target*, not a *capability of the target*. Concretely,
the incoming credential holder must not gain any ability to:

- create a recovery request (that is (e)'s, and only (e)'s);
- advance, support, or execute one;
- prevent one;
- influence which target a guardian majority chooses.

The holder's only power under P2 is **refusal**: by declining to sign, they prevent guardians from
naming *them* as the target. That is not authority over the vault — it is the ordinary inability to
volunteer someone else's key.

---

## 4. ECDSA and PQ must not be collapsed

The two legs differ in one respect that decides the entire design:

| | Incoming ECDSA PoP | Incoming PQ PoP |
|---|---|---|
| Verification primitive | `ECDSA.recover` — a **precompile**, in-contract | `pqVerifier.verify` — an **external contract call** |
| Trust boundary | none beyond secp256k1 | the configured `IPQCVerifier`, contract-level, owner-swappable |
| Liveness boundary | none | verifier must exist, not revert, and return true |
| Can be checked inside a recovery entry point without breaking recovery locality? | **Yes** | **No** |
| Meaning under the currently deployed verifier | genuine possession | **none** (§5) |

`ECDSA.recover` resolves to the `ecrecover` precompile. The repository's own AST external-call
classifier (`test/helpers/astExternalCallAnalysis.ts`, applied by
`test/RecoveryStructuralAssurance.test.ts`) does not flag it, because it is not a contract or
address-typed member call. This is not a loophole being exploited — it reflects the real property
the invariant exists to protect: `recover` introduces no dependency on any mutable, external,
possibly-dead contract.

Therefore a **mixed** treatment is not merely warranted, it is forced. Requiring symmetry between
the legs would mean either dragging the ECDSA leg down to the PQ leg's placement constraints, or
dragging the PQ leg into the recovery path along with its liveness boundary. §11 shows both cost
more than the defect is worth.

---

## 5. What a PQ proof-of-possession would actually prove

This section is the load-bearing evidence for the split verdict. Every claim is read from source.

### 5.1 Per-verifier

| Verifier | Binds sig→digest? | Binds sig→key? | What `verify() == true` means |
|---|---|---|---|
| `MockMLDSAVerifier` (`contracts/MockMLDSAVerifier.sol:57-81`) | **No** | **No** | `publicKey.length == 1952` **and** `signature.length == 3309` **and** the signature's first 32 bytes are not all zero. Nothing else. |
| `AttestationPQCVerifier` / `ImmutableAttestationPQCVerifier` (`:79-106`) | Yes | Yes, as `keccak256(publicKey)` | A **trusted attestor's** ECDSA-signed statement that an ML-DSA signature over this digest under this key was checked off-chain. Possession is real but **delegated to the attestor**. |
| `ZKMLDSAVerifier` (`contracts/verifiers/ZKMLDSAVerifier.sol:60-93`) | Yes | Yes, as `keccak256(publicKey)` | A genuine SP1 proof of ML-DSA verification. Real cryptographic possession — at the cost of a **second** external hop to `SP1_VERIFIER`. |

### 5.2 The decisive fact

**The verifier deployed today is the mock.** `deployments/sepolia/stablecoin-vault-simulator.json`
records `verifierAddress: 0x4736138c99e0619D06663D971C8cD347de186F6d` with the explicit warning:
*"PQ gate uses MockMLDSAVerifier — structural checks only. No real on-chain ML-DSA cryptographic
verification."* `scripts/validate-bytecode-size.ts` names it "the concrete IPQCVerifier actually
deployed on Sepolia today".

`MockMLDSAVerifier.verify` is therefore **constant over all correctly-sized inputs**: it returns the
same answer for a real ML-DSA signature and for 3,309 bytes of noise, and it never looks at the
relationship between key, signature, and digest.

So an incoming-PQ-PoP check adopted today would deliver, exactly and only:

> `newPQPublicKey.length == 1952`, plus a well-formed non-zero blob of length 3309.

That is a **hardcoded ML-DSA-65 length assertion**, which is precisely the check the repository
already struck as S-3 (`docs/Guardian_Authority_Design.md:722`) on the grounds that it is
"[c]orrect only for the **mock**; defeated by 1952 random bytes so it constrains no adversary;
breaks `IPQCVerifier` genericity". Reintroducing it wearing a possession error's name is the same
mistake at one remove — and this time it would also import a contract-wide liveness boundary
(§8) that S-3 never did.

The design doc's §12 reasoning — *"the verifier then decides what a valid key is, and genericity is
preserved by construction"* — is correct **in principle**. §5.1 is the observation that under the
deployed verifier that delegation currently resolves to a null check. This makes the PQ leg a
**timing** question, not a permanent impossibility: it becomes worth mechanising when, and only
when, an attestation or ZK verifier is actually wired in. By then the byte budget (§11) must be
re-answered anyway.

---

## 6. Candidate comparison

All byte figures are **measured**, not estimated — method and full table in §11.

| | Candidate | Deploys? | Recovery locality | Verifies possession? | Verdict |
|---|---|---|---|---|---|
| **A-full** | ECDSA + PQ PoP in `initiateRecovery` | Yes, +663 | **Broken** — `initiateRecovery` gains `pqVerifier.verify` | ECDSA yes; PQ vacuously | **REJECT** |
| **A-reduced** | **ECDSA-only PoP in `initiateRecovery`** | **Yes, +464** | **Preserved** — zero external calls | ECDSA yes; PQ not claimed | **SOUND; NOT ADOPTED (§11.5)** |
| **B** | PoP verified in `executeRecovery` | **No — 24,851 > 24,576** | Broken at the worst point | — | **REJECT** |
| **C** | Pre-register a target, then consume | **No — 24,589 > 24,576** | Preserved | ECDSA yes; PQ vacuously | **REJECT (on measurement)** |
| **C-mixed** | ECDSA local + PQ pre-registered ticket | **No — 24,720 > 24,576** | Preserved | ECDSA yes; PQ vacuously | **REJECT (on measurement)** |
| **D** | External PUSH attestation component | n/a | Preserved | same as C | **REJECT — dominated** |
| **E** | Guardian-attested PoP only | n/a | Preserved | **No** | **REJECT** |
| **F** | No on-chain P2; accept the residual | Yes, +0 | Preserved | No | **ADOPTED for the PQ leg** |

### 6.1 Why B is rejected

Three independent grounds, any one sufficient.

1. **It does not deploy.** Measured 24,851 runtime bytes on the vault — 275 bytes **over** the
   EIP-170 ceiling. `CREATE`/`CREATE2` reverts.
2. **The frozen design already closed it.** `docs/Guardian_Authority_Design.md:974`:
   "`executeRecovery` must stay call-free regardless."
3. **It converts a repairable fault into a deadlock.** Since #176, a matured quorum-approved request
   is unreplaceable (`RecoveryAlreadyApproved`, `:475-477`) and `cancelRecovery` is owner-only
   (`:580`). A request whose PoP cannot be produced at execution time then has **no exit**: not
   execution, not replacement, and not cancellation if (b) is the lost key that motivated recovery.
   That is strictly worse than §1.3's defect.

### 6.2 Why C and C-mixed are rejected

C is **sound in mechanism** — it is the only shape that carries a real PQ proof while leaving all
four recovery entry points callback-free, and it correctly confers no recovery authority on the
preparer. It is rejected purely on measurement: **24,589 and 24,720 runtime bytes, both over the
EIP-170 ceiling**. The cost is structural, not incidental — C needs a new external entry point, a
new storage mapping, a commitment helper, *and* the consumption check, and pays for all four.

An ECDSA-only variant of C was also measured: **24,369 bytes**, which deploys but leaves 207 bytes
of headroom — far below the repository's own 600-byte floor, and 2.4× the cost of A-reduced for the
same verified property. C is dominated by A-reduced on every axis except that it avoids touching
`initiateRecovery`'s parameter list.

### 6.3 Why D is rejected

D is C plus a foreign contract. Its only reason to exist is to carry the PQ leg off-vault — but the
PQ leg is the leg §5 shows to be vacuous today. So D pays a new deployed contract, a new immutable
provenance problem, and a new controller-concentration risk, to relocate a check that presently
proves nothing. It also runs directly against a decision the Guardian Authority lane has already
taken for itself — *"external callback from the vault: **Do not transfer.** The controller pushes;
the recovery path never pulls."* Adding a second controller here would create precisely the
proliferation both lanes are trying to avoid.

### 6.4 Why E is rejected

If the vault cannot distinguish "guardians verified possession" from "guardians did not verify
possession", then the check is a comment with a gas cost. E adds an error selector, an event field
and a struct member attached to a predicate **no input can fail**. Everything E delivers over F —
perfect locality, total verifier-independence — F delivers at zero bytes, zero ABI break, and zero
new call sites. E receives **no invariant-level proof credit** in this document.

---

## 7. SELECTED — the split verdict

> ### Should P2 be on-chain at all?
> **The PQ leg: no — now or under the deployed verifier. The ECDSA leg: yes in principle, and it is
> specified here in implementable detail — but it is NOT adopted in this PR, because it does not fit
> the remaining EIP-170 budget alongside the already-selected Guardian Authority consumer boundary
> (§11.5). That ordering is an owner decision, not this lane's.**

Concretely, this PR adopts:

1. **`A-RECOVERY-TARGET-PQ-POSSESSION-UNAVAILABLE`** as a written, named accepted limit — promoting
   HIGH-5's PQ half from "OPEN — do not lock" to a closed, honestly-stated residual (§13).
2. **`I-RECOVERY-TARGET-ECDSA-POSSESSION`** as a **fully specified, measured, implementation-ready
   target** (§8–§11), explicitly *not implemented*, with a single quantified gate on adoption.
3. Two **zero-risk recommendations** (§14) that are cheap, independent of the verdict, and needed by
   every candidate including F.

### 7.1 What the ECDSA leg does and does not close

It must be stated in the verdict line, not a footnote:

- **EcdsaOnly vaults:** the defect is fully closed.
- **Hybrid vaults:** closed for the ECDSA credential; **open for the PQ credential**. A perfectly
  proven incoming ECDSA signer does not un-brick a Hybrid vault whose PQ key is junk, because
  `withdraw` (`:1117`, `:1120`) requires both legs.
- **PqOnly vaults:** no coverage at all. The mechanism is inert by construction.

So the ECDSA leg changes the **probability** of a brick, not its **possibility**. It is worth having
because the honest-mistake mass is concentrated in the leg it closes — a 20-byte address is
hand-transcribable and human-mistypeable, while a 1,952-byte PQ blob is tool-generated and mistyped
only by a tool bug. But any adopted implementation must carry its own partiality in its name, its
NatSpec, and its changelog entry.

---

## 8. ECDSA PoP — exact design

Verified in a compiling spike (§11); reverted. Not committed.

```solidity
// New typehash, sibling to ROTATE_CREDENTIALS_TYPEHASH (:77-79).
bytes32 public constant RECOVERY_TARGET_POP_TYPEHASH = keccak256(
    "RecoveryTargetPoP(address vaultOwner,address newEcdsaSigner,"
    "bytes32 newPQPublicKeyHash,uint8 vaultMode,uint256 deadline)"
);

// Bundled exactly like RotationAuth (:145-150) — one calldata pointer, one stack slot.
struct RecoveryTargetProof {
    uint256 deadline;
    bytes ecdsaProof;
}

function initiateRecovery(
    address vaultOwner,
    address newEcdsaSigner,
    bytes calldata newPQPublicKey,
    RecoveryTargetProof calldata proof
) external whenNotPaused { ... }

// Split into its own frame, mirroring _authorizeRotation's rationale (:733-736).
function _verifyRecoveryTargetPoP(...) internal view {
    if (vault.mode == VaultMode.PqOnly) return;
    if (block.timestamp > proof.deadline) revert DeadlineExpired(proof.deadline, block.timestamp);
    bytes32 popDigest = _hashTypedDataV4(keccak256(abi.encode(
        RECOVERY_TARGET_POP_TYPEHASH, vaultOwner, newEcdsaSigner,
        keccak256(newPQPublicKey), uint8(vault.mode), proof.deadline
    )));
    if (popDigest.recover(proof.ecdsaProof) != newEcdsaSigner) revert InvalidRecoveryTargetEcdsaProof();
}
```

**The calldata struct is mandatory, not cosmetic.** `docs/Guardian_Authority_Design.md:988` measures
`initiateRecovery`'s DUP/SWAP reach at **15 — one below the ceiling** — and declares it "frozen
against new parameters". That prediction was confirmed empirically: a first spike passing
`uint256 popDeadline, bytes calldata newEcdsaProof, bytes calldata newPqProof` as loose parameters
failed to compile with **Stack too deep** at the `RecoveryRequest` struct literal. Each
`bytes calldata` costs two stack slots (offset + length); one calldata struct pointer costs one.
Bundling is what makes the design compile at all.

The helper split is also load-bearing and, unexpectedly, **cheaper**: inlining the same logic
directly into `initiateRecovery` measured **+515** bytes versus **+464** for the helper form (§11.2).

### 8.1 Exact bound fields, and the fields deliberately excluded

| Field | Bound | Why |
|---|---|---|
| EIP-712 domain (`chainId`, `verifyingContract`) | **implicitly**, via `_hashTypedDataV4` | Kills cross-chain and cross-contract replay by construction. The vault and simulator already use distinct domain `name`s, so a proof cannot cross between them. |
| `vaultOwner` | yes | Kills cross-owner replay. |
| `newEcdsaSigner` | yes | The subject of the claim. |
| `keccak256(newPQPublicKey)` | yes | Binds the ECDSA holder's consent to the **exact credential pair**, so a guardian cannot pair a proven ECDSA key with a substituted PQ key. Hashed, not raw: cheaper, and EIP-712 requires `bytes` be hashed anyway. |
| `uint8(vaultMode)` | yes | A proof given for a Hybrid vault must not be replayable if the mode differs. Costs a measured 15 bytes (§11.2); cheap enough not to trade away. |
| `deadline` | yes | Anti-banking. See §8.2 for why this is **not** H2. |
| **`vault.nonce`** | **NO — deliberately excluded** | **See below. This is the most important line in this section.** |
| `policyControlEpoch` | NO | Different principal. `docs/Guardian_Authority_Design.md` §7.7 is explicit that credential epoch and guardian epoch represent different principals and must not be conflated. |
| Guardian set / epoch | NO | §10. |
| Withdrawal nonce | NO | Different principal, and shared with an unrelated replay domain. |

**Why `vault.nonce` must not be bound.** An earlier iteration of this design bound `vault.nonce`
into the digest, reasoning that it self-expires the proof on any credential change. That is a
**defect**, and a subtle one. `vault.nonce` is bumped by `rotateCredentials` (`:695-697`) — which a
credential *thief* can call, because key theft is copy theft. Binding it would let a thief
invalidate every freshly-signed recovery-target proof by rotating repeatedly, handing them a
standing, cheap, repeatable veto over the exact mechanism `:708-716` exists to deny them. The
contract deliberately does not let rotation cancel recovery; a nonce-bound PoP would restore that
veto through the back door.

Nothing is lost by excluding it. Replay across owners, targets, modes, contracts and chains is
already impossible; the only remaining "replay" is reusing a proof for a second request naming the
**same target for the same owner** within the deadline — which is harmless, because it is the same
possession claim about the same key. The deadline alone carries the anti-banking property.

The corrected binding is also **cheaper**: +464 bytes versus +475 for the nonce-bound form.

### 8.2 The deadline is not H2

`proof.deadline` is a **PoP validity / anti-banking bound**, checked exactly once, inside
`initiateRecovery`, against a signature that is **never stored**. It bounds how long a possession
statement may be banked before it is used to create a request.

**H2 is recovery-execution expiry** — how long a matured, quorum-approved request may sit
unexecuted. It is `O-4′`, still OPEN (`docs/Guardian_Authority_Design.md:714`, `:928-947`), and
this lane does not touch it.

The distinction is structural, not verbal, and there is a trap worth naming: **any deadline on a
*stored* artifact consumed at execution time silently becomes a de-facto execution expiry and would
decide H2 covertly.** That is one more independent reason candidates B and C are wrong shapes here —
both store the proof across the delay. A deadline checked once at creation, on a signature that is
discarded immediately, cannot do this.

### 8.3 Contract accounts as recovery targets — a non-issue, verified

A natural objection is that requiring a raw ECDSA signature permanently excludes Safe / ERC-4337
contract accounts from being recovery targets, since there is no `SignatureChecker` (EIP-1271)
anywhere in `contracts/` — verified by grep, zero matches.

**The objection does not survive checking.** Every existing authorization against `vault.ecdsaSigner`
is already a plain `ECDSA.recover`: `:762`, `:851`, `:1117`. A contract account cannot produce a
recoverable secp256k1 signature, so it can never be a *functioning* `ecdsaSigner` today, with or
without P2. Moreover `rotateCredentials` **already** requires exactly this proof from
`newEcdsaSigner` (`:770`). A PoP requirement in recovery therefore excludes nothing the withdrawal
path does not already exclude, and merely brings recovery into line with rotation.

(This is distinct from making the *vault owner*, identity (b), a Safe — which
`docs/Guardian_Authority_Design.md:728-742` recommends as an operational mitigation and which P2
does not affect in any way.)

---

## 9. PQ PoP — the design, and why it is not adopted

For completeness, the shape a PQ leg would take when a real verifier exists: a
`prepareRecoveryPQCredential` entry point (candidate C's shape) proving possession **outside** the
recovery path and recording a bound commitment that `initiateRecovery` consumes locally — so
recovery never calls the verifier and locality is preserved.

It is not adopted for four independent reasons, in descending order of finality:

1. **It does not deploy.** Measured 24,589 / 24,720 runtime bytes — over the EIP-170 ceiling (§11).
2. **It proves nothing under the deployed verifier** (§5.2).
3. **It would import a contract-wide liveness lever.** `pqVerifier` is one contract-level slot
   (`:180`) serving every vault. A reverting, false-returning, or codeless verifier would make
   recovery *uncreatable* for every Pq/Hybrid vault at once. Trading §1.3's bounded, per-vault,
   self-repairable fault for an unbounded contract-wide one is the exact inversion S-3 was struck
   for.
4. **PQ key length validation is not a substitute.** Explicitly not resurrected here — see §13.2.

---

## 10. Semantics across every lifecycle event

### 10.1 Mode matrix

| `VaultMode` | Incoming ECDSA PoP | Incoming PQ PoP | Rationale |
|---|---|---|---|
| `EcdsaOnly` (0) | **MANDATORY** | not required | The mode does not use a PQ credential. Requiring proof for an unused credential would block legitimate recovery for no benefit. |
| `PqOnly` (1) | not required | not available (§9) | The mode does not use an ECDSA credential. `_verifyRecoveryTargetPoP` returns immediately. **P2 provides PqOnly vaults with nothing.** |
| `Hybrid` (2) | **MANDATORY** | not available (§9) | Partial coverage, stated as such (§7.1). |

The mandatory set is exactly the set the mode's own authorization path requires — matching
`_authorizeRotation`'s `needEcdsa` / `needPq` derivation (`:748-750`). No proof is demanded from a
credential the mode does not use.

### 10.2 Verifier-change semantics

The two claims that must never be merged:

```
provable:      "this party controlled key K at time T"
NOT provable:  "K will remain usable under every future verifier"
```

Since the adopted leg makes **no** call to `pqVerifier`, P2 as specified is **completely
independent of verifier identity, verifier configuration, and verifier availability**. A verifier
swap during the 7-day delay changes nothing about a recovery request's validity, because nothing in
the request was ever validated by a verifier.

This is a genuine advantage and it should be stated positively: the adopted design is the *only*
candidate for which the question "what happens across a verifier update?" has the answer
"**nothing**". Every candidate carrying a PQ leg has to answer it, and none answers it well —
revalidating under V2 makes matured requests unexecutable; honouring a V1 proof means the vault
enforces a policy its own configured verifier has since rejected; pinning a verifier epoch adds
state and a new failure mode.

### 10.3 Recovery / rotation interaction

`rotateCredentials` deliberately does **not** cancel a pending recovery (`:708-716`; pinned by
`test/CredentialRotationRecoveryPrecedence.test.ts`; H3 verdict at
`docs/Guardian_Authority_Design.md:743`). P2 must not disturb this, and as specified it does not:

| Sequence | Outcome under the adopted design |
|---|---|
| PoP signed → credentials rotate → recovery initiated | **PoP still valid.** It binds no credential-movable counter (§8.1). Correct: a rotation says nothing about whether the *target* still controls their own key. |
| PoP signed → recovery initiated → credentials rotate → recovery executes | **Executes.** The proof was consumed at creation; rotation does not touch `recoveryRequests`. Unchanged from today. |
| PoP signed → deadline passes → recovery initiated | **Rejected** at creation, `DeadlineExpired`. Anti-banking, as intended. |
| Guardian set changes while a request is under-supported | Request is deleted by `setGuardians` (`:415-419`), as today. The **PoP is not consumed or invalidated** — the same signature may be reused for a fresh request within its deadline. Correct: possession of a key is not a function of who the guardians are. |

That last row is the key design statement: **the possession proof and the recovery authorization are
different objects with different lifetimes.** Conflating them is how a possession proof accidentally
becomes recovery authority.

### 10.4 Guardian-epoch semantics

**P2 requires no guardian epoch and introduces none.** This is deliberate, and it is what keeps this
lane non-overlapping with #177.

Verified: there is no guardian-set version, epoch, or hash anywhere in `contracts/` — grep for
`guardianSetHash|guardianEpoch|guardianVersion` returns zero matches. `vaultGuardians` is the sole
source of truth and the majority threshold is derived live (`:443-445`).

It is not needed because the PoP is a statement about a **key**, not about a **constituency**. Its
truth does not vary with the guardian set. Binding a guardian epoch into it would make possession
expire for a reason unrelated to possession — and would force this lane to adopt a concrete shape
for a counter that #177 has not settled.

Where a future implementation needs the notion, it should refer to a generic *"guardian epoch /
recovery generation"* and take its shape from whatever #177 settles — never hard-code one here.

### 10.5 Malicious-majority disposition

**Unchanged, and explicitly not addressed.**

```
malicious majority + valid attacker PoP  →  recovery succeeds        (EXPECTED, accepted limit)
any majority + NO possession of target   →  request cannot be created (what the ECDSA leg kills)
```

P2 makes recovery **neither harder nor easier to abuse**. An attacker majority signs with their own
key and proceeds exactly as before. The only behaviour removed is installing a credential *nobody*
controls — which no attacker wants and only honest operators do by accident.

### 10.6 Recovery-locality disposition

**PRESERVED, in full, with no invariant narrowing required.**

`test/RecoveryStructuralAssurance.test.ts` asserts (AST-verified, function-name-anchored, across
both contracts) that `initiateRecovery`, `supportRecovery`, `executeRecovery` and `cancelRecovery`
make zero external calls. The adopted design adds only `ECDSA.recover` — a precompile, not a
contract call, and explicitly not flagged by the classifier.

Consequences, stated precisely so no stale claim is left behind:

- **L-I needs no retirement and no narrowing.** The invariant remains true as written.
- **No documentation or test currently claiming callback-free recovery becomes stale.**
- The two candidates that *would* have required retiring it (A-full, B) are rejected on independent
  grounds, so the question does not arise.
- Recovery remains executable when `pqVerifier` is dead, reverting, or codeless. **P2 does not
  reduce recovery liveness by any amount.**

---

## 11. EIP-170 — measurements

### 11.1 Method

Clean, non-instrumented `npm run compile` (solc 0.8.24, optimizer enabled, `runs: 200`, evm target
`cancun`) followed by `deployedBytecode` length, the same primitive `scripts/validate-bytecode-size.ts`
uses. Each spike was applied by a harness that patches a **pristine** copy of each contract and
asserts every anchor matches exactly once — so a silent mis-splice fails loudly rather than
producing a meaningless delta. Both contracts were patched for every spike from §11.2 onward.

**Baseline re-measured at `aaba4d2`** (the brief's figures were from an older base and required
re-derivation; #176 had since added 110 bytes):

| Contract | Runtime bytes | Headroom |
|---|---|---|
| `WalletWallVault` | **23,231** | **1,345** |
| `StablecoinVaultSimulator` | **22,867** | **1,709** |

### 11.2 Candidate costs — measured

| Spike | Design | Vault | Δ | Vault headroom | Simulator | Δ | Sim headroom |
|---|---|---:|---:|---:|---:|---:|---:|
| — | baseline | 23,231 | — | 1,345 | 22,867 | — | 1,709 |
| **V1** | **A-reduced, adopted binding (no nonce)** | **23,695** | **+464** | **881** | **23,319** | **+452** | **1,257** |
| U2 | A-reduced, binding without `vaultMode` | 23,680 | +449 | 896 | 23,304 | +437 | 1,272 |
| U1 | A-reduced, binding incl. `vault.nonce` | 23,706 | +475 | 870 | 23,330 | +463 | 1,246 |
| U3 | A-reduced, inlined (no helper frame) | 23,746 | +515 | 830 | 23,370 | +503 | 1,206 |
| T1 | A-full (ECDSA + PQ in `initiateRecovery`) | 23,894 | +663 | 682 | 23,518 | +651 | 1,058 |
| T3 | C — prepare(ECDSA+PQ) then consume | 24,589 | +1,358 | **−13** | 24,189 | +1,322 | 387 |
| T3M | C-mixed — ECDSA local + PQ ticket | 24,720 | +1,489 | **−144** | 24,320 | +1,453 | 256 |
| T2B | B — PoP verified in `executeRecovery` | 24,851 | +1,620 | **−275** | 24,475 | +1,608 | 101 |
| S3E | C, ECDSA-only prepare (vault only) | 24,369 | +1,138 | 207 | not spiked | — | — |
| F | no change | 23,231 | **0** | 1,345 | 22,867 | **0** | 1,709 |

**Negative headroom means the contract does not deploy.** B, C and C-mixed all exceed EIP-170's
24,576-byte ceiling on the vault. This is a hard protocol limit, not a policy threshold.

Two incidental results worth recording:

- An unused `bytes pqProof` member in the calldata proof struct costs **0** runtime bytes (T1E and
  U1 both measured 23,706). Calldata struct shape is free until it is read.
- Inlining the check **costs** 51 bytes rather than saving them (U3 vs V1). The optimizer prefers
  the separate frame — the same reason `_authorizeRotation` exists.

### 11.3 Two candidates were initially mis-measured — corrected

Reported honestly because the first numbers were wrong and would have been damning:

- **A-full and B first failed to compile** with *Stack too deep*, using loose `bytes calldata`
  parameters. That was a property of the spike's stack layout, not of the design; the repository had
  already solved the same problem with `RotationAuth`. Re-spiked with a calldata struct, **both
  compile**. Reporting the first result as "candidate B cannot be implemented" would have been
  false.
- **B then failed again** on a genuine splice bug in the harness (the proof struct was not inserted
  into the simulator). Fixed and re-measured at 24,851. Only that third number is used.

### 11.4 Composition is additive — validated, not assumed

A reconstruction of the Guardian Authority lane's consumer boundary was spiked to test **whether
two independent deltas compose additively**, since that is the rule any composition estimate relies
on.

The reconstruction is **NOT authoritative**: it measured **+1,606** bytes against that lane's own
measured **+406**, because it duplicated `setGuardians`' validation body (including the O(n²)
duplicate scan) where the real minimized version parameterizes and reuses it. Its absolute value is
therefore discarded.

Its *relative* behaviour is the useful result:

| Composition | Predicted (sum of isolated deltas) | **Measured** | Error |
|---|---:|---:|---:|
| reconstruction + A-reduced | 1,606 + 475 = 2,081 | **2,081** | **0** |
| reconstruction + A-full | 1,606 + 663 = 2,269 | **2,269** | **0** |

Exact, twice, on independent designs. Composition may therefore be estimated by **addition of
independently measured deltas** — which is what §11.5 does, using the other lane's authoritative
figure rather than this reconstruction.

### 11.5 The composition result — and the single gate on adoption

Using the Guardian Authority lane's own measured `+406` (vault 23,231 → 23,637, headroom 939):

| Composed | Vault runtime | Headroom | Repo's 600-byte floor |
|---|---:|---:|---|
| #177 consumer alone | 23,637 | 939 | pass |
| #177 + **A-reduced (+464)** | 24,101 | **475** | **FAIL — short by 125** |
| #177 + A-full (+663) | 24,300 | 276 | fail |
| #177 + C (+1,358) | 24,995 | **−419** | does not deploy |

The 600-byte floor is not invented here. It is that lane's own stop condition, and it has already
been **enforced against that lane's own work**: an earlier consumer spike measuring 455 bytes of
headroom was rejected for exactly this reason, which is what motivated the minimized design.
Applying it to the composed total is the consistent reading — the floor is on the vault's headroom,
whoever consumes it.

> **The gate, stated as a number.** Budget available to P2 after the Guardian Authority consumer,
> under the 600-byte floor: `1,345 − 406 − 600 = ` **339 bytes**.
> Cheapest sound design measured: **464 bytes**. **Short by 125.**
>
> No micro-optimization closes it. Removing `vaultMode` from the binding saves 15 bytes and weakens
> replay binding; inlining costs 51. The gap is structural.

**This is why the ECDSA leg is specified but not adopted here.** Both lanes cannot land under the
current floor. Which one gets the remaining budget — or whether the floor is revisited, or the vault
refactored to create room — is an **owner decision about ordering and budget**, and deciding it
inside this lane would be deciding for #177.

### 11.6 Spike disposal — proven

Every spike modified only `contracts/WalletWallVault.sol` and `contracts/StablecoinVaultSimulator.sol`,
and every one was reverted from a pristine pre-spike copy. After the final spike:

- `git status --porcelain` — empty
- `git diff --stat` — empty
- `sha256(contracts/WalletWallVault.sol)` = `43611d03cff1283f3fefa274435db8c4e2f02685bfb5bc09d61e710e35caa5a2` — matches pre-spike
- `sha256(contracts/StablecoinVaultSimulator.sol)` = `8c5b89d3554ad55293fc33cd6da66c60beaf72ea21df237f0e34c886ac508415` — matches pre-spike
- `HEAD` tree still `fbfcdb1638b29d4512cccf2cfdf27f82f972455b`

**No `contracts/**` change is part of this PR.** `test/RecoveryCredentialPoPDesign.test.ts` asserts
this mechanically against the compiled artifacts, so the claim cannot go stale silently.

---

## 12. Implementation contract

Binding on any future lane that implements `I-RECOVERY-TARGET-ECDSA-POSSESSION`.

1. **Gate first.** Do not start until the §11.5 budget question is resolved by the owner. Re-measure
   the baseline from a clean non-instrumented compile at that time — it has already moved once.
2. **Stop at 600 bytes** of vault headroom, measured on the composed result, not on P2 alone.
3. **ECDSA leg only.** No `pqVerifier` call in any recovery entry point.
4. **Calldata struct, not loose parameters** — `initiateRecovery`'s stack reach forbids the latter
   (§8). Verify by compiling, not by reasoning.
5. **Verification in its own internal frame** (`_verifyRecoveryTargetPoP`) — measured cheaper than
   inlining, and mirrors `_authorizeRotation`.
6. **Bind exactly the §8.1 field set.** In particular bind **no** credential-movable counter;
   `vault.nonce` is forbidden, with the §8.1 reasoning reproduced as a code comment so a future
   reader cannot "helpfully" add it back.
7. **A new typehash**, never `ROTATE_CREDENTIALS_TYPEHASH` — otherwise a rotation signature is
   replayable as a recovery PoP.
8. **Mode-gated**, with a negative test per mode.
9. **Mirror statement-for-statement into `StablecoinVaultSimulator.sol`** (L-E), and keep
   `test/GuardianRecoverySimulatorParity.test.ts` green.
10. **The verdict line must state that it does not close HIGH-5** — it closes HIGH-5 for EcdsaOnly
    and for Hybrid's ECDSA half only.
11. **Do not implement H2.** The PoP deadline is not an execution expiry (§8.2).
12. Expect ABI churn: `initiateRecovery` has many call sites across `test/`, all of which must be
    updated, plus the simulator mirror.

---

## 13. RESIDUAL — accepted limits

### 13.1 `A-RECOVERY-TARGET-PQ-POSSESSION-UNAVAILABLE`

**Accepted.** No available verifier lets the vault express incoming-PQ possession honestly:

- `MockMLDSAVerifier` — the verifier **actually deployed** — is constant over correctly-sized
  inputs; a PQ PoP against it is a length assertion, i.e. the struck S-3 check.
- The attestation verifiers deliver possession **only as strong as the trusted attestor**.
- `ZKMLDSAVerifier` delivers real possession but is not deployed, and adds a second external hop.

Consequently the strength of any PQ PoP is exactly the configured verifier's strength, and is
**presently nil**. The residual — a guardian majority can install an uncontrolled PQ key, bricking
spending and voluntary rotation for that vault until another 7-day recovery cycle — is accepted, and
is bounded as in §1.3: per-vault, repairable, no funds at risk.

This **closes** `docs/Guardian_Authority_Design.md:970-975`'s "OPEN — do not lock" for the PQ half.
It should be revisited when, and only when, a non-mock verifier is wired in.

### 13.2 PQ key length/shape validation is not resurrected

S-3 stays struck. Shape validation is not proof of possession and this document does not offer it as
a substitute. Where key validity is defined at all, the authority is the configured `IPQCVerifier`,
which `IPQCVerifier.sol:27-29` documents as carrying no security guarantee by itself.

One narrower variant was considered and is **also not adopted**:
`newPQPublicKey.length == vaults[owner].pqPublicKey.length` — a *relative* check against per-vault
state rather than a global constant, which would avoid S-3's contract-wide failure mode. It is
rejected because it would block the documented migration path: under a verifier change from ML-DSA
to a scheme with a different key size, recovery is precisely the escape hatch, and this check would
close it exactly when it is needed.

### 13.3 PqOnly vaults receive nothing

Stated plainly rather than buried. The adopted leg is inert for `VaultMode.PqOnly`.

---

## 14. Two zero-risk recommendations (separate PRs; not implemented here)

Independent of the verdict, cheap, and needed by every candidate including F.

**R1 — `RecoveryInitiated` omits the incoming PQ key.**
`event RecoveryInitiated(address indexed owner, address newEcdsaSigner, uint256 executeAfter)`
(`:279`; simulator `:247`) carries no PQ material. Adding `bytes32 newPQPublicKeyHash` would let a
pure log-driven indexer detect a wrong incoming key during the 7-day window.

Precision, because it is easy to overstate: the pending key **is** readable today via the
`recoveryRequests(address)` auto-getter, which the compiled ABI confirms returns `newPQPublicKey`.
So an off-chain preview is implementable right now by RPC read. The gap is real but narrow — it
affects event-only indexers, not monitoring in general.

**R2 — there is no reverting-verifier fixture.** `contracts/mocks/` has `AlwaysTruePQCVerifier` and
`AlwaysFalsePQCVerifier`, but nothing that **reverts** (cf. `AlwaysRevertingPolicyEngine.sol`, which
exists for the policy engine). Every liveness claim in this document — and every candidate's
liveness analysis — would be better evidenced by a behavioural test showing all four recovery entry
points still function with a reverting verifier installed. Zero contract-size cost.

---

## 15. Adversarial matrix

`M` = modelled executably in `test/RecoveryCredentialPoPDesign.test.ts`;
`C` = adjudicated against the current contract; `D` = design-level disposition.

| # | Scenario | Disposition | |
|---|---|---|---|
| 1 | Valid ECDSA PoP | Accepted | M |
| 2 | Wrong ECDSA key signs | Rejected, `InvalidRecoveryTargetEcdsaProof` | M |
| 3 | Valid PQ PoP | **Not modelled — vacuous under the deployed verifier** | M (vacuity proven) |
| 4 | Invalid PQ PoP | Same; the mock cannot distinguish | M (vacuity proven) |
| 5 | Hybrid, only ECDSA proof | Accepted — this is the adopted design | M |
| 6 | Hybrid, only PQ proof | Rejected: ECDSA leg mandatory in Hybrid | D |
| 7 | EcdsaOnly requires no PQ proof | By construction | M |
| 8 | PqOnly requires no ECDSA proof | By construction (early return) | M |
| 9 | Proof for vault A replayed at vault B | Impossible — domain separator binds `verifyingContract` | M |
| 10 | Proof for owner A replayed for owner B | Impossible — `vaultOwner` bound | M |
| 11 | Proof for target A reused for target B | Impossible — `newEcdsaSigner` + `newPQPublicKeyHash` bound | M |
| 12 | Expired proof | Rejected, `DeadlineExpired` | M |
| 13 | Proof generated before a credential rotation | **Still valid — deliberate** (§8.1) | M |
| 14 | Proof across a verifier update | **Unaffected — no verifier dependency** (§10.2) | D |
| 15 | Proof across a guardian-set change | Not invalidated; reusable for a fresh request (§10.3) | D |
| 16 | Malicious majority + valid attacker PoP | **Succeeds — accepted limit** (§10.5) | D |
| 17 | Majority chooses a key nobody controls | ECDSA leg: blocked. PQ leg: **residual** (§13.1) | M |
| 18 | Malformed PQ key | **Residual** — shape checks not resurrected (§13.2) | C |
| 19 | Reverting PQ verifier | Recovery unaffected — no verifier call | C |
| 20 | Malicious / reentrant verifier | Not reachable from recovery. `verify` is `view`. | C |
| 21 | Mock verifier + PqOnly | Blocked at `createVault` (`:613-615`); P2 adds nothing | C |
| 22 | Recovery after verifier retirement | Unaffected | D |
| 23 | Failed PoP must not mutate recovery state | Check precedes all writes; revert reverts everything | D |
| 24 | Failed execution must not partially rotate | Unchanged — `executeRecovery` untouched | C |
| 25 | Simulator and production semantics match | Recovery surfaces executable-statement identical | M |

---

## 16. Escalated to the repository owner — NOT decided here

1. **The EIP-170 budget split** between this lane and the Guardian Authority consumer. Quantified in
   §11.5: both cannot land under the 600-byte floor; P2 is short by 125 bytes. Ordering is an owner
   call.
2. **Whether HIGH-5's PQ half is formally accepted** as §13.1 proposes, closing
   `docs/Guardian_Authority_Design.md:970-975`.
3. **Whether `docs/Security_Assumptions.md` §4a should gain a residual bullet** recording §13.1 in
   that file's house style. Not edited here to keep this PR's surface minimal.

Explicitly **not** decided here, and left to #177: controller emergency-pause semantics, H2 coupling,
treasury-threshold/cardinality authority, dual controller/vault guardian-state assurance, and the
concrete shape of any guardian epoch.

---

## 17. Non-goals

- **Not** preventing a malicious guardian majority from recovering to credentials it controls.
- **Not** implementing H2 recovery-execution expiry.
- **Not** reintroducing hardcoded PQ key length validation.
- **Not** implementing the ECDSA leg in this PR (§11.5).
- **Not** modifying `docs/Guardian_Authority_Design.md` or
  `test/GuardianAuthorityLifecycleDesign.test.ts`.
- **Not** deploying anything. No deployment, no merge, no production contract change.
