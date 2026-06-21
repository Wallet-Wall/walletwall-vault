# Attestation Governance Hardening

> Research prototype. Not audited. Not production custody. Do not use real funds.

This document analyzes the remaining architectural risk in the trusted-attestation
verifier — the **attestation governance model** — and lays out hardening options before
any implementation. It is a planning document. It does **not** change any contract.

It builds on the asymmetry already documented in
[Attestation_Verifier.md](Attestation_Verifier.md#attestor-rotation-delay-asymmetry),
[Verifier_Roadmap.md](Verifier_Roadmap.md#path-1--trusted-attestation-verifier-implemented),
[Security_Assumptions.md](Security_Assumptions.md), and
[THREAT_MODEL.md](THREAT_MODEL.md). Nothing here weakens those existing warnings.

## Current model

The relevant on-chain facts (verified against the contracts on `main`):

- A **trusted attestor** verifies an ML-DSA-65 signature off-chain and signs an EIP-712
  `PQCAttestation` statement that binds the withdrawal digest, public-key hash, PQ
  signature hash, algorithm id, verifier address, chain id, and deadline.
- The **verifier contract checks the configured attestor**:
  `AttestationPQCVerifier.verify` recovers the EIP-712 signer and compares it to the
  stored `attestor` address. It does **not** verify ML-DSA on-chain.
- The **owner can rotate the attestor immediately**:
  `AttestationPQCVerifier.updateAttestor(address)` is `onlyOwner`, takes effect in the
  same transaction, and emits `AttestorUpdated(oldAttestor, newAttestor)`. There is no
  pending state, delay, or cancel for attestor rotation.
- The **vault's verifier replacement is timelocked**: `WalletWallVault` changes
  `pqVerifier` only through `proposePQVerifier` → wait `PQ_VERIFIER_UPDATE_DELAY`
  (`2 days`) → `applyPQVerifierUpdate`, with `cancelPQVerifierUpdate` available while a
  proposal is pending.
- Therefore, **attestor rotation inside an already-configured verifier bypasses the
  vault-level delay.** The verifier *address* the vault trusts stays the same while the
  attestor *authority* behind it can change instantly.

Both `WalletWallVault` and `AttestationPQCVerifier` use `Ownable2Step`. Note this only
makes *ownership transfer* two-step; it does **not** add any delay to `updateAttestor`.

This behavior is intentional and already covered by tests in
[`test/AttestationPQCVerifier.test.ts`](../test/AttestationPQCVerifier.test.ts),
including a dedicated `Documented attack surface: immediate attestor rotation` block that
demonstrates the full path (rotate immediately, accept attestations from the new attestor
in the next block, and a compromised owner installing a malicious attestor).

## Risks

- **Compromised attestor key.** A leaked attestor key lets an attacker sign attestations
  the verifier accepts. (Inherent to the trusted-attestation model; not unique to
  rotation.)
- **Compromised attestor owner.** The owner of `AttestationPQCVerifier` can swap in a
  new, attacker-controlled attestor.
- **Malicious immediate rotation.** Because `updateAttestor` is instant, a compromised
  owner can replace a legitimate attestor with no observation window — fraudulent
  attestations become acceptable from the very next block.
- **Monitoring blind spot.** Detection depends entirely on someone watching the
  `AttestorUpdated` event. The vault's governance events (`PQVerifierUpdateProposed` /
  `PQVerifierUpdated`) do **not** fire for an attestor rotation, so vault-focused
  monitoring misses it.
- **Operator trust concentration.** The attestor owner is a single administrative
  authority gating *every* vault that trusts this verifier.
- **False sense of "trustless" security.** Users who see the vault's two-day verifier
  timelock may incorrectly assume *all* PQ-authorization changes are delayed. The
  attestor authority is not.
- **Liveness risk.** If the single attestor is unavailable, PQ-authorized withdrawals
  through this verifier cannot be attested, blocking the flow until rotation — which is
  itself a centralized action.

## Hardening options

### Option A — Immutable-attestor verifier deployments

Make `attestor` a constructor-set immutable and remove (or deprecate) `updateAttestor`.
Changing the attestor means **deploying a new verifier contract** and switching the vault
to it through the existing delayed `proposePQVerifier` / `applyPQVerifierUpdate` flow.

- **Pros:** simplest mental model; reuses the vault's existing verifier timelock; reduces
  the mutable admin surface to zero inside the verifier; trivially monitorable — any
  attestor change shows up as a verifier-address change with a two-day window.
- **Cons:** requires a new verifier deployment per attestor change; operationally less
  convenient; still a trusted attestation, not trustless.

### Option B — Timelocked attestor rotation

Keep `updateAttestor` but split it into `proposeAttestor` → delay → `applyAttestor`, with
`cancelAttestorUpdate`, mirroring the vault's verifier-governance pattern.

- **Pros:** preserves the same verifier deployment; gives an explicit observation window;
  consistent with the existing vault governance shape.
- **Cons:** more contract state and surface to test; a *second*, separate timelock that
  users/operators must independently monitor (distinct from the vault-level one); still
  trusted attestation.

### Option C — Threshold attestations

Require M-of-N attestors to sign a verification result.

- **Pros:** reduces single-key / single-owner compromise risk; lets independent verifier
  operators participate.
- **Cons:** more complex payload format and verification logic; higher gas and
  operational complexity; key-rotation/governance complexity multiplied across signers;
  still not ZK / native PQ.

### Option D — Transparency log / signed result registry

Publish signed verification results to an append-only log or on-chain registry.

- **Pros:** observability and an audit trail; enables cross-operator comparison.
- **Cons:** does not by itself *prevent* a malicious attestation — it only makes it
  visible after the fact; raises storage/indexing and privacy questions.

### Option E — ZK / native PQ verification (future)

Replace trusted attestation entirely with a ZK proof of ML-DSA verification or a
chain-native PQ precompile (Paths 2 / 4 in [Verifier_Roadmap.md](Verifier_Roadmap.md)).

- **Pros:** removes the trusted attestor from the trust model — the real
  trust-minimization endpoint.
- **Cons:** not implemented; depends on circuit/prover maturity or future protocol
  support; out of scope as a near-term change.

## Recommendation

A staged path:

1. **Short term — immutable-attestor verifier deployment (Option A).**
2. **Medium term — optional timelocked attestor rotation (Option B)**, only if per-attestor
   redeployment proves operationally painful.
3. **Longer term — threshold attestations (Option C) or ZK / native PQ (Option E)** for
   genuine trust minimization.

### Why immutable-attestor is the best next step

- **Simplest.** It *removes* mutable state rather than adding a second governance machine.
- **Aligns with the existing vault timelock.** Attestor changes inherit the vault's
  two-day `proposePQVerifier` / `applyPQVerifierUpdate` review window for free, instead of
  introducing a parallel delay.
- **Closes the hidden mutation.** There is no in-place attestor swap to miss — the
  authority is fixed for the life of a deployment.
- **Easiest to explain publicly.** "One verifier address = one attestor" is a one-line
  invariant.
- **Easiest to monitor.** Watching the vault's `PQVerifierUpdated` event (and the verifier
  address) is sufficient; no separate `AttestorUpdated` watch is required.

### What it does not change

Immutable-attestor is still **trusted attestation**. It is **not** ZK, **not** on-chain
ML-DSA verification, **not** production custody, **not** audited, and involves **no real
funds**. It narrows the *administrative* attack surface; it does not remove trust in the
attestor key or the off-chain verification.

## Follow-up checklist (for a future implementation PR)

> Tracking aid only. Do not open GitHub issues from this document.

**Implement immutable-attestor verifier variant**

- [ ] Add `ImmutableAttestationPQCVerifier` implementing `IPQCVerifier`, with `attestor`
      set once in the constructor (reverting on the zero address) and no `updateAttestor`.
- [ ] Reuse the existing EIP-712 domain, `PQCAttestation` typehash, and `algorithmId`, and
      keep the `abi.encode(bytes, uint256, bytes32, bytes32)` payload ABI-compatible.
- [ ] Mirror the existing verification checks (payload shape, deadline, public-key hash,
      EIP-712 recovery, verifier-address and chain-id binding).
- [ ] Add `test/ImmutableAttestationPQCVerifier.test.ts` covering valid/invalid
      attestation, wrong attestor, expiry, altered fields, malformed payload, verifier
      binding, and the *absence* of any attestor-rotation path.
- [ ] Keep the mutable `AttestationPQCVerifier` available as the legacy/research path;
      document immutable-attestor as the recommended near-term deployment.
- [ ] Document the operational flow: change attestor ⇒ deploy a new verifier ⇒ move the
      vault via `proposePQVerifier` / `applyPQVerifierUpdate`.

## See also

- [Attestation_Verifier.md](Attestation_Verifier.md) — trusted-attestation verifier
  reference and the rotation delay asymmetry.
- [Verifier_Roadmap.md](Verifier_Roadmap.md) — verifier paths 0–4.
- [Security_Assumptions.md](Security_Assumptions.md) — admin/trust assumptions.
- [THREAT_MODEL.md](THREAT_MODEL.md) — threat boundaries and known gaps.
- [Open_PQ_Verifier.md](Open_PQ_Verifier.md) — the open, hostable verification boundary.
