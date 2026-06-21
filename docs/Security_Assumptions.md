# Security Assumptions

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> The repository includes a test/demo-only mock verifier and a trusted-attestation
> verifier. Neither performs ML-DSA verification on-chain.

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
- **Phase 3 hardening is complete.** This means the documented prototype controls are
  merged and tested; it does not mean the system is audited or production-ready.

## 2. What this prototype is NOT

- Not audited.
- Not production custody.
- Does not provide production-grade quantum resistance or real-fund protection.
- Not a reviewed deployment system.

## 3. The PQ verifier trust boundary (most important assumption)

The vault delegates **all** PQ signature validity decisions to whatever contract is
configured as `pqVerifier` (an `IPQCVerifier`). The vault itself does not implement
lattice cryptography.

The test/demo implementation is **`MockMLDSAVerifier`**, which:

- checks only that the public key is 1952 bytes and the signature is 3309 bytes
  (the ML-DSA-65 sizes),
- checks that the signature's first 32 bytes are not all zero,
- performs **no** binding of signature ↔ public key ↔ digest, and therefore provides
  **no cryptographic security**.

**Consequence:** In `Hybrid` mode the _effective_ protection today is roughly that of
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

The repository also implements **`AttestationPQCVerifier`**. It is non-mock because it
cryptographically enforces an authorized EVM attestor signature over the withdrawal
digest, public-key hash, PQ signature hash, algorithm identifier, verifier address,
chain ID, and deadline. It does not verify ML-DSA on-chain.

Its security depends on the attestor correctly verifying ML-DSA off-chain with a real
FIPS 204-compatible implementation before signing. A compromised attestor key,
incorrect verifier service, or malicious attestor can authorize invalid PQ inputs. The
contract owner can immediately rotate the verifier's attestor, creating an additional
administrative trust boundary.

The repository's attestor CLI uses `@noble/post-quantum` to verify ML-DSA-65 before
signing and refuses known demo material in real verify mode. This reduces accidental
mis-signing in the demonstrated flow, but it does not remove trust in the attestor key,
host, service code, deployment process, or operator. A compromised attestor can still
approve invalid PQ claims.

The core ML-DSA-65 verification is factored into an **open, independently hostable
verifier boundary** ([`src/verifier/`](../src/verifier/), `npm run verifier:verify`).
It is deterministic for the same inputs, returns a structured result, and **never signs,
custodies funds, stores private keys, or constructs an attestation**. This makes
verification reproducible by auditors, operators, and third parties, but it does not
change the trust model: the on-chain verifier still trusts the attestor's EIP-712
signature, not an on-chain ML-DSA check. Trusted attestation is not trustless
verification, and it is not a ZK proof. See [Open_PQ_Verifier.md](Open_PQ_Verifier.md).

`AttestationPQCVerifier` is stronger than the mock only because it requires the
configured attestor's valid EIP-712 signature. It does not make the vault production
custody. See [Attestation_Verifier.md](Attestation_Verifier.md) and
[Verifier_Roadmap.md](Verifier_Roadmap.md).

## 4. Admin / trust assumptions

- **Verifier is admin-controlled and timelocked.** The contract owner proposes a new
  verifier with `proposePQVerifier`, waits the fixed two-day
  `PQ_VERIFIER_UPDATE_DELAY`, and applies it with `applyPQVerifierUpdate`. The active
  verifier remains unchanged during the delay. The owner can clear a pending proposal
  with `cancelPQVerifierUpdate` before it is applied.
- **Why mutable instead of immutable:** the verifier trust boundary is specifically
  intended to support replacing the mock with a future attestation, ZK, or chain-native
  verifier. Immutability would require redeploying the entire vault contract and would
  strand the existing per-vault state.
- **The delay does not eliminate owner trust.** Whoever controls the owner can still
  select the verifier trusted for _every_ vault. A malicious or compromised owner can
  propose a permissive verifier and apply it after the delay. A later proposal replaces
  the pending proposal and restarts the delay.
- **Attestor rotation is immediate and untimelocked (important asymmetry).** The vault's
  two-day verifier governance delay (`PQ_VERIFIER_UPDATE_DELAY`) protects against the
  _vault owner_ swapping in a new verifier contract. It does **not** protect users
  against the _attestor owner_ rotating the attestor inside an already-configured
  `AttestationPQCVerifier`. `updateAttestor` is an immediate, owner-controlled call on
  the verifier contract itself. A compromised or malicious attestor owner can rotate to
  a malicious attestor without any delay and without triggering the vault governance
  flow. Operators and users must monitor the `AttestorUpdated` event emitted by
  `AttestationPQCVerifier` to detect unexpected rotations. This is a trusted attestation
  model — not trustless PQ verification. Until a non-custodial verifier (ZK proof or
  chain-native) replaces the attestation path, trust must be placed in whoever controls
  the attestor and the attestor owner key.
- **Ownership uses two-step transfer** (`Ownable2Step`) on both `WalletWallVault` and
  `AttestationPQCVerifier`, to avoid transferring ownership to an unusable address.
  The owner may be a multisig such as Safe; no additional multisig contract logic is
  required. A pending verifier proposal remains pending across vault ownership transfer,
  so a new owner must review it before applying.
- **Recommended governance:** an EOA owner is acceptable only for local/testnet
  prototyping. Any future deployment beyond isolated research should use a reviewed
  multisig owner, operational monitoring of proposal events, and an independently
  reviewed delay appropriate to the deployment. This is not a production-readiness
  claim.
- **Pause is a global kill-switch.** The owner can pause `createVault`, `withdraw`,
  `queueWithdrawal`, and `finalizeWithdrawal`. This protects against incidents but is
  also a centralization/liveness assumption: a paused vault cannot execute withdrawals.
  Owners can still call `cancelPendingWithdrawal` while paused to release reserved funds.
- **Credential rotation requires the keys, not the owner account.** The direct
  owner-only mutators (`updateEcdsaSigner`, `updatePQPublicKey`) are removed — they survive
  only as tombstone selectors that revert with `UseRotateCredentials()`. They previously let
  the vault owner address (a classical EOA) swap either credential with no signature from the
  existing keys, which made that classical key a single point of failure capable of replacing
  the PQ credential and defeating post-quantum protection. Voluntary rotation now goes through
  `rotateCredentials`, which requires both the current credential(s) **and** a
  proof-of-possession from the new credential(s), per vault mode (Hybrid requires all four).
  In Hybrid this means neither a broken ECDSA key nor a substituted PQ key can evict the other
  on its own. Rotation increments the nonce and cancels/refunds any pending large withdrawal.
- **Residual owner-account risk.** The owner account remains a classical EOA and still
  controls `setGuardians`. A compromise of the owner key can therefore still lead to takeover
  by installing attacker guardians and driving guardian recovery — but only after the 7-day
  `RECOVERY_DELAY`, during which the owner can `cancelRecovery`. Removing the direct mutators
  converts what was an *instant* classical takeover into a *delayed, vetoable* one; it does
  not make the classical owner key irrelevant. Hardening `setGuardians` (e.g. a timelock or
  existing-guardian consent) is possible future work, out of scope for this change.

## 4a. Guardian recovery model

The vault implements **guardian-based social recovery** so an owner who loses their
signing keys can have credentials reset by a configured guardian set. This introduces a
distinct trust boundary that vault owners must understand:

- **Guardian majority can take over a vault.** Recovery resets the vault's `ecdsaSigner`
  and `pqPublicKey` to attacker-chosen values once `(guardians.length / 2) + 1` guardians
  support a request and the `RECOVERY_DELAY` (7 days) has elapsed. A colluding majority of
  guardians can therefore seize the vault. **Choose guardians accordingly.**
- **Owner override.** The owner can abort any pending recovery at any time with
  `cancelRecovery`, which is the primary protection against a malicious guardian set as
  long as the owner still controls their vault address.
- **Guardian set integrity (enforced).** `setGuardians` rejects an empty set, more than
  `MAX_GUARDIANS` (32), the zero address, the owner itself, and duplicates. Duplicates are
  rejected specifically because the majority threshold is derived from the array length
  while each address can only support once — an unchecked duplicate would push the
  threshold above the number of distinct supporters and permanently brick recovery.
- **Recovery request integrity.** An active recovery request cannot be overwritten before
  its `executeAfter` timestamp, preventing a guardian from resetting accumulated supports
  or substituting credentials. An under-supported request becomes replaceable after that
  window so a single guardian cannot permanently deny recovery when the owner is unavailable
  to call `cancelRecovery`.
- **Credential validation.** Recovery and signed credential rotation reject a zero ECDSA
  signer when ECDSA authorization is active and reject an empty PQ public key when PQ
  authorization is active. Valid credentials for the vault's configured mode are unchanged.
- **Replay and pending-withdrawal safety.** Successful recovery increments the vault nonce,
  invalidating stale signed withdrawals, and cancels/refunds any reserved large withdrawal
  before the recovered credentials take control.
- **Residual trust.** Guardians are semi-trusted by construction. The 7-day delay and the
  owner cancel path bound, but do not eliminate, guardian power. This is social recovery,
  not trustless recovery.

## 4b. Large transaction timelock

The optional large-transaction timelock separates authorization from execution for
withdrawals above `largeTxThreshold`. When enabled, `withdraw` continues to execute
amounts at or below the threshold immediately, but rejects larger amounts. A valid
above-threshold request must be submitted through `queueWithdrawal`.

Queueing performs the normal EIP-712, PQ, balance, nonce, and active policy-engine
checks. It then consumes the nonce and reserves the amount by subtracting it from the
vault's available balance. The pending record binds the vault owner, recipient, amount,
signed nonce, queue time, ready time, and EIP-712 digest used as the operation identity.
Only that vault owner can finalize after `largeTxDelay` or cancel and refund the
reservation, and both actions must name the matching operation identity. A completed,
cancelled, or replaced operation cannot be finalized by a stale transaction.

**Governance.** The contract owner controls `largeTxThreshold` and `largeTxDelay`
through `proposeLargeTxParams`, the fixed two-day
`LARGE_TX_PARAMS_UPDATE_DELAY`, and `applyLargeTxParams`. A pending change can be
cleared with `cancelLargeTxParams`. A zero threshold disables the feature; an enabled
configuration requires a non-zero delay. This observation window does not remove admin
trust, and parameter changes do not alter the recorded deadline of an already queued
withdrawal.

**Recovery interaction.** Successful guardian recovery cancels any pending large
withdrawal and refunds the reserved amount to the vault before the recovered
credentials take control. Recovery also advances the vault nonce, invalidating other
withdrawal authorizations pre-signed by the old credentials for the previously current
nonce.

**Limitations.** The feature supports one pending withdrawal per vault, covers ETH only,
and does not make the prototype production custody. It does not prevent a compromised
admin from proposing weak threshold/delay settings and applying them after the
governance delay. Monitoring, reviewed governance, audits, and formal verification
remain out of scope.

## 5. Policy engine (optional withdrawal filter)

The vault supports an optional pluggable policy engine wired in through the
`IPolicyEngine` interface. When configured, `check()` is called inside `withdraw` or
`queueWithdrawal` before any state changes occur. A denial reverts with
`PolicyViolation(reason)`.

**Governance.** The policy engine is admin-controlled through a timelocked
two-step flow (`proposePolicyEngine`, wait two days, `applyPolicyEngine`).
`address(0)` disables the feature. The same governance constraints that apply
to the PQ verifier also apply here: the delay does not eliminate trust in the
contract owner.

**Included reference implementations (research / non-audited):**

- `CompositePolicyEngine` — the single engine wired into the vault when multiple
  modules must apply simultaneously. It calls each configured module and fails on the
  first denial. Module administration uses `Ownable2Step`.
- `DailySpendLimitPolicy` — per-vault vault-owner-managed rolling 24-hour spend
  cap. Each vault owner sets their own limit via `setDailyLimit()`. Spending is
  recorded at `check()` time and rolled back if the outer transaction reverts.
  For a successfully queued large withdrawal, later cancellation or recovery refunds
  the vault reservation but does not restore policy allowance; the amount remains
  counted until the policy window resets. A limit of 0 means unrestricted.
- `RecipientAllowlistPolicy` — vault-owner-managed allowlist. An empty allowlist
  blocks all recipients (fail-safe). Adding `address(0)` disables the restriction.
  Admin has no control over individual vault allowlists.
- `SanctionsListPolicy` — admin-controlled (`Ownable2Step`) deny list intended
  for OFAC-style screening. Blocks any withdrawal whose recipient appears on the
  list. Admin can add/remove addresses and batch-add.

**Trust assumptions for policy implementations:**

- `DailySpendLimitPolicy` and `RecipientAllowlistPolicy` are vault-owner-controlled.
  They protect vault owners who opt in; the contract admin cannot bypass them.
  However, the admin can replace the engine via the governance flow.
- `SanctionsListPolicy` is admin-controlled. A malicious or compromised admin can
  add any recipient, potentially censoring legitimate withdrawals. The two-day
  governance delay protects against silently removing the engine but not against
  manipulating list contents (those calls are immediate).
- A stateful policy engine that reverts unexpectedly (e.g. due to a bug) would
  permanently block withdrawals from the vault. The admin can disable the engine
  via `proposePolicyEngine(address(0))` followed by `applyPolicyEngine` after
  the delay. A vault owner cannot bypass an active policy engine unilaterally.
- Large-withdrawal finalization re-checks policy only if the active engine address
  changed after queueing. This closes stale-engine bypasses while avoiding a second
  call to the same stateful engine, which would double-count daily spend.

## 6. Authorization & replay model

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

## 7. Fund-accounting assumptions

- Each vault tracks its own `balance`. Deposits credit a specific vault
  (`deposit` / `depositFor`).
- The contract has **no payable `receive`/`fallback`**, so the only accounted path for
  ETH is via deposits. ETH **force-sent** (e.g. via `selfdestruct`) raises the raw
  contract balance but is **not** credited to any vault and cannot be withdrawn — it is
  effectively stuck. Internal accounting is unaffected (covered by tests).

## 8. Known limitations / out of scope

- No on-chain ML-DSA verification. The attestation path delegates verification to a
  trusted off-chain service and EVM attestor.
- The SP1 implementation is an unaudited scaffold, not the active Sepolia verifier and
  not evidence of production-grade ZK/PQ verification.
- Native Solidity ML-DSA is not a production path. Chain-native PQ verification depends
  on future protocol support; no live precompile is assumed.
- The attestor CLI is a prototype without key isolation, threshold signing, hardened
  service deployment, audit logging, monitoring, or availability guarantees.
- No ERC-20 / NFT support; ETH only.
- Guardian-based, time-delayed social recovery **is** implemented (see §4a) and a
  separate `WalletWallMultiSigVault` provides p-of-q withdrawal authorization. Both are
  research implementations: they are not audited and carry the trust assumptions noted
  above (notably, a guardian majority can take over a recoverable vault).
- Not gas-optimized; not formally verified; not audited.

## 9. Cryptography naming (NIST)

- **ML-DSA / FIPS 204** — formerly **CRYSTALS-Dilithium** (this prototype targets
  ML-DSA-65).
- **SLH-DSA / FIPS 205** — formerly **SPHINCS+**.
