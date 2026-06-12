# Security Assumptions

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> The current PQ verifier is a mock/placeholder and performs no real cryptographic
> verification.

This document states the trust assumptions and threat model that the WalletWall Vault
prototype operates under. It is intended to keep claims honest and to make the trust
boundaries explicit.

## 1. What this prototype is

- A **hybrid authorization prototype**: withdrawals are authorized by an EIP-712 typed
  message that, depending on `VaultMode`, must carry a classical ECDSA signature, a
  post-quantum (PQ) signature, or both.
- A **post-quantum migration research** vehicle: the PQ verifier sits behind the
  `IPQCVerifier` interface so different verification strategies can be swapped in.
- **Testnet / local demo only.**

## 2. What this prototype is NOT

- Not audited.
- Not production custody.
- Not "quantum-proof", "fully quantum-secure", or "real-fund protection".
- Not mainnet-ready.

## 3. The PQ verifier trust boundary (most important assumption)

The vault delegates **all** PQ signature validity decisions to whatever contract is
configured as `pqVerifier` (an `IPQCVerifier`). The vault itself does not implement
lattice cryptography.

In this repository the default implementation is **`MockMLDSAVerifier`**, which:

- checks only that the public key is 1952 bytes and the signature is 3309 bytes
  (the ML-DSA-65 sizes),
- checks that the signature's first 32 bytes are not all zero,
- performs **no** binding of signature ↔ public key ↔ digest, and therefore provides
  **no cryptographic security**.

**Consequence:** In `Hybrid` mode the *effective* protection today is roughly that of
the ECDSA layer alone. In `PqOnly` mode the prototype would have effectively **no**
meaningful authorization security, because any well-formed blob of the right length
passes the mock.

**Enforced guard:** Because of this, creating a `PqOnly` vault is **blocked at the
contract level while the configured verifier is the mock**. `createVault` reverts with
`PqOnlyDisabledForMockVerifier` when `mode == PqOnly` and
`pqVerifier.algorithmId() == MOCK_ML_DSA_65_ALGORITHM_ID`. The `VaultMode.PqOnly` enum
value is retained for future compatibility and becomes usable once a non-mock verifier
is wired in. `EcdsaOnly` and `Hybrid` are unaffected — they still require a classical
ECDSA signature.

See [Verifier_Roadmap.md](Verifier_Roadmap.md) for the paths toward a real verifier.

## 4. Admin / trust assumptions

- **Verifier is admin-controlled and timelocked.** The contract owner proposes a new
  verifier with `proposePQVerifier`, waits the fixed two-day
  `PQ_VERIFIER_UPDATE_DELAY`, and applies it with `applyPQVerifierUpdate`. The active
  verifier remains unchanged during the delay. The owner can clear a pending proposal
  with `cancelPQVerifierUpdate` before it is applied.
- **Why mutable instead of immutable:** the Phase 1 trust boundary is specifically
  intended to support replacing the mock with a future attestation, ZK, or chain-native
  verifier. Immutability would require redeploying the entire vault contract and would
  strand the existing per-vault state.
- **The delay does not eliminate owner trust.** Whoever controls the owner can still
  select the verifier trusted for *every* vault. A malicious or compromised owner can
  propose a permissive verifier and apply it after the delay. A later proposal replaces
  the pending proposal and restarts the delay.
- **Ownership uses two-step transfer** (`Ownable2Step`) to avoid transferring ownership
  to an unusable address. The owner may be a multisig such as Safe; no additional
  multisig contract logic is required in the vault. A pending verifier proposal remains
  pending across ownership transfer, so a new owner must review it before applying.
- **Recommended governance:** an EOA owner is acceptable only for local/testnet
  prototyping. Any future deployment beyond isolated research should use a reviewed
  multisig owner, operational monitoring of proposal events, and an independently
  reviewed delay appropriate to the deployment. This is not a production-readiness
  claim.
- **Pause is a global kill-switch.** The owner can pause `createVault` and `withdraw`.
  This protects against incidents but is also a centralization/liveness assumption:
  a paused vault cannot process withdrawals.
- Per-vault credential rotation (`updateEcdsaSigner`, `updatePQPublicKey`) is restricted
  to the vault's own owner address.

## 5. Authorization & replay model

- Withdrawals are authorized by an **EIP-712** typed `Withdrawal` message. The domain
  separator binds the signature to the **contract address**, **chainId**, and
  **name/version**, preventing cross-contract and cross-chain replay.
- The signed message includes `vaultOwner`, `recipient`, `amount`, `nonce`, `deadline`,
  and `vaultMode`. Changing **any** field invalidates the signature.
- **Replay protection** is provided by a strictly increasing per-owner `nonce` plus a
  `deadline`. A consumed nonce cannot be reused; an expired deadline is rejected.
- Withdrawals may be **submitted by anyone** (e.g. a relayer). Authorization derives
  from the signatures, not from `msg.sender`. This is intentional and does not weaken
  the model as long as the signatures are sound.

## 6. Fund-accounting assumptions

- Each vault tracks its own `balance`. Deposits credit a specific vault
  (`deposit` / `depositFor`).
- The contract has **no payable `receive`/`fallback`**, so the only accounted path for
  ETH is via deposits. ETH **force-sent** (e.g. via `selfdestruct`) raises the raw
  contract balance but is **not** credited to any vault and cannot be withdrawn — it is
  effectively stuck. Internal accounting is unaffected (covered by tests).

## 7. Known limitations / out of scope

- No real PQ verification (the central limitation).
- No ERC-20 / NFT support; ETH only.
- No multi-signature, guardian recovery, or time-delayed recovery (see
  `Project_Phases.md` for the longer-term vision; these are not implemented here).
- Not gas-optimized; not formally verified; not audited.

## 8. Cryptography naming (NIST)

- **ML-DSA / FIPS 204** — formerly **CRYSTALS-Dilithium** (this prototype targets
  ML-DSA-65).
- **SLH-DSA / FIPS 205** — formerly **SPHINCS+**.
