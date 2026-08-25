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
- **A matured governance proposal EXPIRES after `GOVERNANCE_GRACE_PERIOD` (14 days).**
  A propose/apply delay is only worth the reaction window it delivers at the instant
  the change takes effect. Previously no matured proposal expired, so an owner could
  PRE-ARM one at a quiet moment — nothing at stake, no observer with cause to react —
  let the two days lapse unapplied, and bank an instantly-exercisable swap
  indefinitely; exercised at the moment it mattered it cost zero delay and gave zero
  fresh notice. This binds hardest on the PQ verifier: `pqVerifier` is
  contract-level rather than per-vault, so ONE swap moves the authorization authority
  for every vault at once; in `VaultMode.PqOnly` it is the SOLE authorization gate
  (there is no classical fallback, and unlike the policy engine nothing pins the
  verifier a withdrawal was admitted under — there is no queue-time sticky floor for
  it); it also gates `rotateCredentials`, so a forging verifier enables credential
  takeover rather than a single withdrawal; and the `PqOnlyDisabledForMockVerifier`
  guard runs only at vault CREATION, so a banked swap can retroactively restore
  exactly the configuration that guard forbids for vaults that already exist. The
  bound applies uniformly to all three governance pairs on BOTH vaults
  (`proposePQVerifier`, `proposePolicyEngine`, `proposeLargeTxParams`). Past the
  window a proposal buys no head start — it must be re-proposed and pay a fresh full
  delay — and it remains clearable via its cancel entrypoint. A rejected expired
  apply mutates nothing, leaving both the active value and the pending proposal
  intact. The property restored is bounded warning: any governance action executable
  right now was announced by its proposal event within the last
  `DELAY + GOVERNANCE_GRACE_PERIOD`, so monitoring those events gives a finite,
  guaranteed horizon instead of requiring perfect recall of every proposal ever made.
  The 2-day delay / 14-day grace pairing matches Compound's Timelock `GRACE_PERIOD`,
  which exists for this same reason.
- **Governance now enforces a code-bearing destination at proposal and execution**,
  identically on `WalletWallVault` and `StablecoinVaultSimulator` — each has its own
  independent PQ verifier trust boundary, with its own `pqVerifier`/`pendingPQVerifier`
  state and its own `proposePQVerifier`/`applyPQVerifierUpdate` pair, and this guard
  applies to both. `proposePQVerifier` rejects any nonzero `newVerifier` whose
  `code.length` is zero (`NoCode`), and `applyPQVerifierUpdate` independently re-checks
  the SAME condition on the pending verifier immediately before it takes effect. The
  re-check exists
  because the two-day delay separates proposal from execution: a destination that
  was code-bearing when proposed can become code-less before the delay elapses (see
  the `AttestationPQCVerifier`/`ImmutableAttestationPQCVerifier` bullets above for
  why a verifier might later be redeployed or retired), and proposal-time validation
  alone does not carry forward. A rejected apply mutates no state — the active
  verifier and the pending proposal are both left exactly as they were, so the
  proposal remains recoverable via `cancelPQVerifierUpdate`. **This guard proves
  only that the address held runtime code at the instant the call executed** — not
  interface conformance, behavioral correctness, immutability of that code, or
  future availability; a code-bearing address can still be `AlwaysFalsePQCVerifier`
  or any other contract that misbehaves once installed. It does not change who is
  trusted once a verifier is active (see the next bullet).
- **Why mutable instead of immutable:** the verifier trust boundary is specifically
  intended to support replacing the mock with a future attestation, ZK, or chain-native
  verifier. Immutability would require redeploying the entire vault contract and would
  strand the existing per-vault state.
- **The delay does not eliminate owner trust.** Whoever controls the owner can still
  select the verifier trusted for _every_ vault. A malicious or compromised owner can
  propose a permissive verifier and apply it after the delay. A later proposal replaces
  the pending proposal and restarts the delay.
- **`AttestationPQCVerifier` (legacy, mutable): attestor rotation is immediate and
  untimelocked (important asymmetry).** This bullet describes the mutable
  `AttestationPQCVerifier` specifically — see the following bullet for how the immutable
  variant differs. The vault's two-day verifier governance delay
  (`PQ_VERIFIER_UPDATE_DELAY`) protects against the _vault owner_ swapping in a new
  verifier contract. It does **not** protect users against the _attestor owner_ rotating
  the attestor inside an already-configured `AttestationPQCVerifier`. `updateAttestor` is
  an immediate, owner-controlled call on the verifier contract itself. A compromised or
  malicious attestor owner can rotate to a malicious attestor without any delay and
  without triggering the vault governance flow. Operators and users must monitor the
  `AttestorUpdated` event emitted by `AttestationPQCVerifier` to detect unexpected
  rotations. For this variant, trust must be placed in both the attestor key **and** the
  separate attestor-owner key that controls `updateAttestor`.
- **`ImmutableAttestationPQCVerifier`: no attestor-owner authority.** This variant removes
  the asymmetry above rather than timelocking it: `attestor` is `immutable`, and the
  contract has no `updateAttestor`, no owner, and no admin surface of any kind — there is
  no attestor-owner key to compromise and no in-place rotation to monitor for. Changing
  the attestor requires deploying a new `ImmutableAttestationPQCVerifier` and moving the
  vault to it through the vault's existing timelocked `proposePQVerifier` /
  `applyPQVerifierUpdate` governance, so the change inherits the vault's own two-day
  review window. This is the recommended near-term hardening for the asymmetry above; see
  [Attestation_Governance_Hardening.md](Attestation_Governance_Hardening.md) and
  [Attestation_Verifier.md](Attestation_Verifier.md#immutable-attestor-variant).
  **This does not make the attestation path trustless.** Both variants are a trusted
  attestation model, not trustless PQ verification: removing the attestor-owner rotation
  authority removes only the administrative rotation risk, not trust in the attestor key
  itself or the off-chain ML-DSA verification it performs. Until a non-custodial verifier
  (ZK proof or chain-native) replaces the attestation path entirely, trust must still be
  placed in whoever controls the attestor key — and, for the legacy mutable variant only,
  the separate attestor-owner key as well.
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
  converts what was an _instant_ classical takeover into a _delayed, vetoable_ one; it does
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
`IPolicyEngine` interface, which splits two duties:

- `check()` — **admission**: called inside `withdraw` or `queueWithdrawal` before
  any state changes occur. It may mutate policy accounting (e.g. book daily spend).
  A denial reverts with `PolicyViolation(reason)`.
- `revalidate()` — **finalization revalidation**: a `view` method called inside
  `finalizeWithdrawal`, executed as a STATICCALL so it structurally cannot mutate
  policy state. It answers whether the queued withdrawal is still permitted under
  CURRENT policy state, without re-booking admission accounting. Finalization never
  calls `check()`.

**Governance.** The policy engine is admin-controlled through a timelocked
two-step flow (`proposePolicyEngine`, wait two days, `applyPolicyEngine`).
`address(0)` disables the feature. The same governance constraints that apply
to the PQ verifier also apply here: the delay does not eliminate trust in the
contract owner.

**Governance now enforces a code-bearing destination at proposal and execution**,
identically on `WalletWallVault` and `StablecoinVaultSimulator`. `proposePolicyEngine`
rejects any nonzero `newEngine` whose `code.length` is zero (`PolicyEngineUnavailable`),
and `applyPolicyEngine` independently re-checks the SAME condition on the pending
engine immediately before it takes effect — the re-check exists because the two-day
delay separates proposal from execution, and a destination that was code-bearing when
proposed can become code-less before the delay elapses. `address(0)` is exempt from
this check at both points and remains a valid, intentional way to disable the policy
engine. A rejected apply mutates no state — the active engine and the pending
proposal are both left exactly as they were, so the proposal remains recoverable via
`cancelPolicyEngine`. **This guard proves only that the address held runtime code at
the instant the call executed** — not interface conformance, behavioral correctness,
immutability of that code, or future availability; a code-bearing address can still
misbehave once installed (the existing `revalidate()` fail-closed check, described
above, is the separate runtime defense for a CURRENTLY active engine that later loses
its code).

**Included reference implementations (research / non-audited):**

- `CompositePolicyEngine` — the single engine wired into the vault when multiple
  modules must apply simultaneously. It calls each configured module and fails on the
  first denial. Module administration uses `Ownable2Step`. Adding a module is
  immediate; removing one requires `proposeRemoveModule` / `applyRemoveModule`
  behind a two-day `MODULE_REMOVAL_DELAY` (see the asymmetric-governance bullet
  below for why). Its `check()` accepts only
  consumers registered by the owner via `setAdmissionCaller()`: because a module sees
  the COMPOSITE as `msg.sender`, a tenant who delegates to a composite has delegated
  to whoever can reach it, so admission authority must hold at that hop too. A fresh
  composite admits nothing until its consumer vault is registered. Registration
  is necessary but NOT sufficient: `check()` additionally requires
  `subject.consumer == msg.sender`, so a registered consumer cannot present a subject
  naming a DIFFERENT consumer and book into that consumer's accounting
  (`SubjectConsumerMismatch`). The two gates answer different questions — "may this
  caller use this composite" and "is this caller the consumer it claims to be" — and
  neither implies the other. A side effect: because the binding compares against
  `msg.sender`, a composite nested inside another composite can no longer admit
  anything, so the "do not nest composites" warning is now mechanically enforced on the
  admission path rather than merely documented. Subject fields are relayed to every
  module unchanged; the composite never substitutes `address(this)` for
  `subject.consumer`, never zeroes `subject.asset`, and never rewrites
  `subject.owner`. `revalidate()` is
  deliberately NOT gated — it is `view` and gating it would break the vaults'
  fail-closed settlement revalidation. A composite carrying ONLY stateless modules
  still requires registration: the composite cannot tell whether a module is
  stateful, so the gate is unconditional and fail-closed, which for that particular
  composition is a configuration step with no security benefit.
- Rotating a vault's policy engine to a NEW intermediary that still routes to the
  same `DailySpendLimitPolicy` changes the `msg.sender` that module observes, so an
  armed tenant's existing delegation no longer matches and their admissions revert
  `UnauthorizedAdmitter` until they re-delegate. `pendingPolicyEngine` is public and
  emitted on proposal, so tenants can pre-delegate during the two-day
  `POLICY_ENGINE_UPDATE_DELAY` for zero downtime; a tenant who misses the window is
  restored by ONE permissionless transaction of their own
  (`setAdmitter(consumer, asset, newEngine, true)`, or
  `setDailyLimit(consumer, asset, 0)` to disarm). Withdrawals
  already queued are unaffected, because settlement uses the ungated `revalidate()`.
  Corollary for socially recovered vaults: `setAdmitter` and `setDailyLimit` are both
  keyed on `msg.sender == vaultOwner`, and `executeRecovery` rotates the vault's
  SIGNER while leaving the `vaultOwner` mapping key unchanged — so a vault recovered
  after key loss cannot change its own daily-limit configuration. That limitation
  predates this change (`setDailyLimit` was already `msg.sender`-keyed); admission
  delegation now inherits it.
- `DailySpendLimitPolicy` — per-vault vault-owner-managed 24-hour spend cap.
  WINDOW SEMANTICS: a TRUE ROLLING 24-hour cap. For an armed subject at every instant
  `T`, the sum of amounts admitted at times `t` with `t > T - WINDOW` is at most `L`.
  EXACT BOUNDARY: an entry booked at `t` is counted while `block.timestamp < t + WINDOW`
  and expires at EXACTLY `t + WINDOW` — the live set is the half-open interval
  `(T - WINDOW, T]`. That is the same `>=` instant the previous tumbling implementation
  used for its reset, retained deliberately so the boundary did not move while its
  meaning changed. Allowance returns in the increments it was consumed, as individual
  spends age out, rather than resetting.
  HISTORICAL — NO LONGER REACHABLE: the previous release enforced a TUMBLING/reset
  window under which close to 2x the limit was reachable inside one 24-hour interval
  (`2L - 1 wei` within ONE SECOND over the signed vault path, and exactly `2L` when a
  zero-amount `check()` from an authorized admitter anchored the window for free).
  Both constructions are now REFUSED, and the two tests that pinned them as reachable
  have been inverted in place rather than replaced, so the closure reads as a diff.
  A zero-amount `check()` books nothing and creates no entry, so it no longer buys an
  anchor of any kind.
  LEDGER CAPACITY — A NEW DENIAL MODE: exactness with bounded storage is only possible
  with a cap on how many spend records a subject may hold inside the window, because
  reproducing expiry exactly requires retaining their timing. That cap is
  `MAX_ACTIVE_ENTRIES = 32` LIVE LEDGER ENTRIES per `(consumer, owner, asset)`. A spend
  that would need a 33rd entry is refused with reason `"daily spend ledger full"` —
  distinct from `"daily limit exceeded"`, and observable in advance via
  `activeEntryCount()`. The refusal is SELF-HEALING (a slot frees the instant the oldest
  entry expires, so a full ledger is never a permanent brick) and is not
  attacker-reachable (only a caller the subject's own owner delegated via
  `setAdmitter()` can append).
  THE CAP COUNTS ENTRIES, NOT DISTINCT SECONDS. Admissions sharing a timestamp coalesce
  into one entry ONLY while their combined amount stays representable in the entry's
  packed `uint192` (see MAX_BOOKABLE_AMOUNT below); above that the booking appends a
  SECOND entry at the same instant. That is equally exact — entries sharing a timestamp
  expire together — but it consumes another slot, so a same-timestamp burst usually
  costs one slot and, at `uint192`-scale amounts no real asset reaches, may cost more.
  Read `activeEntryCount()` rather than counting spends. Pinned by D2d in
  `test/DailySpendRollingWindow.test.ts`.
  The rejected alternative was merging the two oldest entries at the newer timestamp: it
  never admits above `L`, but holds old spend on the books longer than the true trailing
  window, which would make the cap conservative rather than exact.
  BOUNDED WORK: admission and every getter scan at most 32 entries — a constant that does
  NOT grow with lifetime withdrawal count — and each entry is dropped exactly once, so
  amortized cost per admission is O(1).
  OBSERVABILITY IS ABOUT EXPIRY, NOT ADMISSIBILITY: `rollingSpent()` and
  `remainingAllowance()` route through the same expiry routine the admission path uses,
  so they cannot disagree with `check()` about WHAT HAS AGED OUT — the failure the old
  raw `windowSpent()` invited. They do not model the capacity constraint, so a positive
  `remainingAllowance()` can coexist with a `"daily spend ledger full"` refusal. Read
  `remainingAllowance()` as "how much of the cap is unused", not "this much is
  admissible right now"; pair it with `activeEntryCount()` for the latter.
  BLOCK TIMESTAMPS: this policy's invariant is DEFINED in chain time — at most `L`
  admitted over the chain-time interval `(T - WINDOW, T]`. Entry timestamps are not
  caller-supplied; each was written by a previously admitted transaction from its own
  block. Proposer latitude over timestamps therefore cannot make the contract admit more
  than `L` within its own measured window, only shift where that window falls against
  wall-clock time. A cap denominated in 24 hours of chain time has no other clock
  available to it. (Slither `2-1-timestamp` on `_liveAt` is triaged on this basis.)
  SCOPE OF THE GUARANTEE: the invariant binds over intervals in which the subject has
  been CONTINUOUSLY ARMED. While `limit == 0` the subject is unrestricted and `check()`
  returns before booking, so spends made while disarmed are not recorded and are not
  counted retroactively when a limit is armed again. This is not a laundering route —
  `setDailyLimit()` does not touch the ledger, so a disarm/re-arm cycle leaves existing
  entries intact and expiring on their original schedule — but note that
  `setDailyLimit()` is `msg.sender`-keyed, so whoever controls the owner address can
  disarm outright. Where the vault owner and its withdrawal signer are the same key (the
  common case) a compromised signer could already remove the cap entirely; that is a
  property of the configuration authority, unchanged by rolling accounting, and it is
  why this cap is a damage LIMITER rather than a containment boundary.
  ADMISSION, NOT SETTLEMENT: spend is booked when a withdrawal is ADMITTED and expires a
  WINDOW after that instant. For a queued large transaction that is queue time, so a
  large-transaction delay longer than WINDOW releases the allowance before the payment
  settles; settlement is admission plus a per-withdrawal delay fixed at queue time, so
  settled outflow inherits the admitted spacing rather than compressing it.
  SUBJECT SCOPE: accounting is now keyed
  by the full POLICY SUBJECT — `(consumer, owner, asset)` — hashed with
  `keccak256(abi.encode(...))` into a single bucket identifier. The subject is minted
  by the ORIGINATING vault from trusted state (`consumer = address(this)`, `owner` =
  the EIP-712-authenticated request owner, `asset` = `address(0)` for native ETH or
  the immutable token) and is relayed unchanged through `CompositePolicyEngine`, so a
  module always sees the vault that originated the withdrawal rather than whatever
  intermediary happened to call it. Consequently:
    - two vault contracts serving the same tenant no longer share an accumulator or a
      window anchor;
    - wei and token base units can no longer sum into one scalar;
    - a shared `CompositePolicyEngine` may serve several consumers WITHOUT merging
      their spend state.
  The previous release's operational workaround — a dedicated `DailySpendLimitPolicy`
  instance per (consumer, asset), installed directly or behind a CONSUMER-SPECIFIC
  composite, and never behind a shared one — is therefore RETIRED. It was a convention;
  the separation is now an invariant the contract enforces.
  AGGREGATE EXPOSURE CHANGED WITH IT: buckets are independent, so a tenant who arms
  `limit` for N subjects may spend up to `N * limit` per window in total, where the
  old owner-keyed model capped them at ONE `limit` across everything. That aggregate
  cap was inseparable from the interference defect — the only reason one vault could
  constrain another's total was that they shared the bucket — and no cross-subject cap
  is provided in its place. Arm only the subjects you intend, and size each limit
  knowing the others exist. Tenant isolation within one consumer is unchanged and
  remains correct. The ROLLING invariant, its exact boundary, ledger capacity, subject
  isolation under rolling accounting, queue/finalize single-booking and revert atomicity
  are pinned by `test/DailySpendRollingWindow.test.ts`; the SCOPE behaviours and the
  inverted historical burst constructions by `test/DailySpendWindowSemantics.test.ts`;
  and subject propagation across the whole boundary by
  `test/PolicySubjectPropagation.test.ts`.
  DOCUMENTATION HISTORY: the contract's NatSpec once described a rolling window it did
  not implement, was corrected to state the tumbling semantics and the `2L` bound
  truthfully, and now describes the rolling ledger that replaced them. THIS document and
  `test/DailySpendRollingWindow.test.ts` are the authority on window semantics.
  Each vault owner sets their own limit via `setDailyLimit()`. Spending is
  recorded at `check()` time and rolled back if the outer transaction reverts.
  Booking additionally requires ADMISSION AUTHORITY: `check()` mutates accounting
  selected by its `PolicySubject` argument, so it also demands that `msg.sender` be an
  admitter delegated FOR THAT EXACT SUBJECT via `setAdmitter()` — the same
  `msg.sender`-keyed authority root as `setDailyLimit()`, since both setters force
  `msg.sender` into the subject's `owner` slot and so can only ever configure a bucket
  the caller owns. Authority granted for one `(consumer, owner, asset)` confers nothing
  for any other, so an admitter trusted for vault X cannot present a subject naming
  vault Y and book there. Arming a non-zero limit
  therefore requires delegating first (`NoAdmitterConfigured` otherwise), and the
  last admitter cannot be revoked while a limit is armed (`LastAdmitterWhileArmed`);
  disarming to 0 is always permitted so the escape hatch is never blocked. Owners
  who never armed a limit need no configuration — the gate sits after the
  `limit == 0` short-circuit, which is also the point before which nothing is
  mutable. `revalidate()` stays ungated so settlement never depends on admission
  authority. The delegation is TRANSITIVE and only as narrow as what the subject
  delegated to, so delegating to a `CompositePolicyEngine` inherits that composite's
  access-control policy — its owner chooses which consumers may invoke it. What that
  buys the composite owner changed with subject propagation, and the current position
  is: they CANNOT consume the tenant's allowance, and they CAN deny outright.
  - Cannot consume: `CompositePolicyEngine.check()` requires
    `subject.consumer == msg.sender`, so a registered relay can only present a subject
    naming ITSELF as consumer and therefore only ever reaches a bucket keyed to the
    relay — one no tenant arms. The tenant's own bucket names their VAULT as consumer
    and is reachable only by that vault. (Before subject propagation this was a real,
    documented weakness: the composite owner could register an arbitrary relay and burn
    the delegating tenant's allowance.)
  - Can deny: the composite owner may add an always-denying module and block the
    tenant's withdrawals. That is unescapable within the composition and is strictly
    stronger than the allowance burn ever was, so the operational advice is unchanged —
    delegate to a composite only where its owner is already trusted for the liveness of
    that composition. It touches no accounting: spend never moves, no allowance is
    manufactured, queued withdrawals still settle, and no other subject is affected.
  The tenant's unilateral escape from the ACCOUNTING side remains
  `setDailyLimit(consumer, asset, 0)`. Both halves are pinned — C7 asserts the burn is
  impossible, C7b asserts the denial power survives — in
  `test/DailySpendAdmissionAuthority.test.ts`.
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
- A policy engine that reverts unexpectedly (e.g. due to a bug) blocks the
  withdrawals it gates, fail-closed. The admin can disable the engine via
  `proposePolicyEngine(address(0))` followed by `applyPolicyEngine` after the
  delay, which frees NEW withdrawals. A withdrawal already queued under the broken
  engine remains gated by it (see the sticky floor below); its owner's escape is
  `cancelPendingWithdrawal` — ungated by pause and policy — followed by re-queueing
  under the current configuration. Note that cancellation does not restore
  daily-spend allowance booked at admission (see the `DailySpendLimitPolicy` bullet
  above), so re-queueing under a daily-limit policy may have to wait for the
  24-hour window to roll. A vault owner cannot bypass an active policy engine
  unilaterally.
- Composite module management is deliberately ASYMMETRIC. Composition is
  AND-semantics (a withdrawal is admitted only if every active module
  approves), so `addModule` can only ever shrink-or-preserve the composite's
  accepted set (monotonic strengthening) and stays IMMEDIATE — no proposal, no
  delay — the same as sanctions/allowlist content additions, because it can
  never weaken the effective policy. Removing a module can only ever
  grow-or-preserve the accepted set (monotonic weakening), including the
  transition from a non-empty enforcing set down to a permissive empty one —
  so `removeModule` no longer exists as an instant call: removal now goes
  through `proposeRemoveModule` / `applyRemoveModule` behind a two-day
  `MODULE_REMOVAL_DELAY`, matching the friction of replacing the vault's engine
  ADDRESS outright. The module being removed stays fully active — evaluated by
  both `check()` and `revalidate()` — for the entire pending window, so it
  cannot be evicted with less friction than an engine-address swap would cost.
  `MODULE_REMOVAL_DELAY` is a standalone constant on the composite (it has no
  reference to any specific vault and may be wired into several) matched to
  the two named vaults' `POLICY_ENGINE_UPDATE_DELAY` BY CONVENTION, not by
  reference — a future vault type with a longer engine-swap delay would need
  this re-verified before relying on the invariant.

  **A matured removal proposal EXPIRES.** `MODULE_REMOVAL_DELAY` only buys a
  reaction window if the proposal cannot be banked, so `applyRemoveModule` is
  applicable only within `[validAfter, validAfter + MODULE_REMOVAL_GRACE_PERIOD]`
  (14 days, matching Compound's Timelock `GRACE_PERIOD`). Without that bound a
  matured proposal stayed exercisable forever, so a composite owner could
  pre-arm one at a quiet moment — nothing queued, no observer with cause to
  react — let the two days lapse unapplied, and bank an INSTANT eviction
  indefinitely. Exercised at the moment the module actually stood between the
  owner and a settlement, that cost zero delay and gave zero warning, which is
  exactly what the delay exists to prevent; such a pre-armed proposal could
  free an already-queued withdrawal that `revalidate()` was correctly blocking.
  With expiry, any removal executable right now was announced by a
  `ModuleRemovalProposed` event within the last
  `MODULE_REMOVAL_DELAY + MODULE_REMOVAL_GRACE_PERIOD`, so monitoring that event
  gives a finite, guaranteed horizon rather than requiring perfect recall of
  every proposal ever made. An expired proposal buys no head start — removal
  needs a fresh proposal and a fresh full delay — and can still be cleared with
  `cancelRemoveModule`.

  **This is friction-equivalence, not settlement-outcome-equivalence for
  already-queued withdrawals — the two must not be conflated.** The sticky
  floor described below holds at engine-**address** granularity, not at
  module-**roster** granularity. An engine-address swap (e.g. to a permissive
  engine) cannot retroactively free an already-queued withdrawal, because the
  sticky floor still binds the OLD (queue-time) engine address regardless of
  what the vault's CURRENT engine is. But if a composite is the queue-time
  engine and its address never changes, its LIVE module roster is what
  `revalidate()` reads at settlement — there is no per-withdrawal snapshot of
  that roster. So once a proposed module removal on that same composite has
  both fully matured and been explicitly applied, a withdrawal that was queued
  while the module was present CAN legitimately settle, because the module is
  simply no longer part of that composite's live roster. This is intentional
  module-roster mutability after a governed delay, not an erosion of the
  sticky floor: a queued withdrawal's finalization remains governed by
  `queue-time engine address x current engine address x live module set(s) x
live module internal state` (unchanged from PR #152) — module removal only
  ever changes the "live module set(s) x live module internal state" factors,
  never the address factors the sticky floor itself is defined over.

- Large-withdrawal finalization ALWAYS revalidates policy, read-only, with no
  address-comparison gate — address identity is not used as a proxy for policy
  freshness, so same-address state mutations (e.g. a recipient sanctioned after
  queueing) are observed. Two engines are consulted, each once and only if
  non-zero:
  - the **queue-time engine** (recorded as `policyEngineAtQueue`) — a sticky
    floor: replacing or disabling the engine after queueing does not erase the
    restrictions the withdrawal was admitted under;
  - the **current engine** — newly imposed restrictions also apply.
    Restrictive drift blocks finalization; permissive drift (a restriction lifted
    before settlement) is honored. Because `revalidate()` is a STATICCALL and the
    daily-spend policy books at admission only, no path double-counts daily spend.

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
