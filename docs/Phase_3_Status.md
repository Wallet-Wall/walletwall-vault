# Phase 3 Security Hardening — Status Matrix

> **RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH REAL FUNDS.**
> All items below are prototype implementations for research purposes only.

Last updated: 2026-06-15
Status: **complete and merged to `main` in PR #35**
Release: `v0.4.12`

---

## Status key

| Symbol                    | Meaning                                      |
| ------------------------- | -------------------------------------------- |
| ✅ Implemented / Hardened | Feature present and covered by passing tests |
| ⚠️ Partial                | Implemented but has known gaps (noted)       |
| 🔮 Future / Out of scope  | Not implemented; intentionally deferred      |

---

## Phase 3 hardening matrix

### Core withdrawal controls

| Feature                    | Status                    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Large-withdrawal timelock  | ✅ Implemented / Hardened | `largeTxThreshold`, `largeTxDelay`, timelocked `queueWithdrawal` + `finalizeWithdrawal`; governance-delayed parameter changes; cancellation preserves reserved funds                                                                                                                                                                                                                                                                                                                                       |
| Daily spend limit policy   | ✅ Done | `DailySpendLimitPolicy`; per-`PolicySubject` configurable; 0 = unrestricted. **Both previously documented semantics gaps are now CLOSED.** (1) TIME: **CLOSED.** Enforcement is a TRUE ROLLING 24-hour cap — for an armed subject at every instant `T`, the sum of amounts admitted at times `t > T - WINDOW` is at most `L`. An entry booked at `t` counts while `block.timestamp < t + WINDOW` and expires at EXACTLY `t + WINDOW` (live set `(T - WINDOW, T]`), the same `>=` instant the old tumbling reset used, kept so the boundary did not move while its meaning changed. The historical `2L - 1 wei` burst over the signed path and the exact `2L` burst anchored by a free zero-amount `check()` are both REFUSED; the two tests that pinned them as reachable were inverted in place rather than replaced. A zero-amount `check()` now books nothing and creates no entry. Allowance returns in the increments it was consumed, as individual spends age out. NEW DENIAL MODE: exact accounting with bounded storage requires a cap on stored spend records, `MAX_ACTIVE_ENTRIES = 32` LIVE LEDGER ENTRIES per subject; a spend needing a 33rd entry is refused with `"daily spend ledger full"`, distinct from `"daily limit exceeded"` and visible in advance via `activeEntryCount()`. It is self-healing (a slot frees when the oldest entry expires) and appendable only by a delegated admitter. THE CAP COUNTS ENTRIES, NOT DISTINCT SECONDS: same-timestamp admissions coalesce into one entry only while their combined amount stays representable in the packed `uint192`, so an exceptionally large same-timestamp total occupies more than one slot (pinned by D2d) — read `activeEntryCount()` rather than counting spends. BOUNDED WORK: admission and every getter scan at most 32 entries, a constant independent of lifetime withdrawal count; each entry is dropped exactly once, so amortized cost is O(1). SCOPE OF GUARANTEE: binds over CONTINUOUSLY ARMED intervals — while `limit == 0` the subject is unrestricted and nothing is booked. `setDailyLimit()` never touches the ledger, so disarm/re-arm does not reset history; but it is `msg.sender`-keyed, so whoever controls the owner address can disarm outright, which is why this is a damage LIMITER rather than a containment boundary. Observability: `rollingSpent()`, `remainingAllowance()`, `activeEntryCount()`, `oldestActiveEntry()`. These route through the same expiry routine as admission, so they cannot disagree with `check()` about what has aged out — but they do not model capacity, so a positive `remainingAllowance()` can coexist with a `"daily spend ledger full"` refusal; it means "how much of the cap is unused", not "this much is admissible now". the tumbling-specific `windowStart()`/`windowSpent()` are REMOVED (breaking, 0.11.x line) because they no longer described anything real — `windowSpent` in particular was a raw accumulator that could disagree with `remainingAllowance` for a full day. (2) SCOPE: **CLOSED.** Accounting is keyed by the full `PolicySubject` — `(consumer, owner, asset)` — via `keccak256(abi.encode(...))`, so two vault contracts serving one tenant share neither ledger nor expiry clock, and wei cannot sum with token base units. Ledger CAPACITY is per subject for the same reason: a shared ring would let one busy tenant deny every other tenant of the same vault. The subject is minted by the originating vault from trusted state and relayed unchanged through `CompositePolicyEngine`. Aggregate exposure: N armed subjects permit `N * limit` per trailing 24 hours. Pinned by `test/DailySpendRollingWindow.test.ts` (rolling invariant, boundary, capacity, limit toggles, queue/finalize single-booking, revert atomicity, isolation), `test/DailySpendWindowSemantics.test.ts` (scope, plus the inverted historical bursts) and `test/PolicySubjectPropagation.test.ts`. Neither gap was ever production-reachable — `policyEngineAddress` is `null` in every deployment manifest. Admission authority: booking requires `msg.sender` to be an admitter delegated FOR THAT EXACT SUBJECT via `setAdmitter()`, so the subject argument selects the accounting but never authorizes it. The gate sits BEFORE any ledger read, so an unauthorized caller can neither plant a total nor consume a capacity slot. `CompositePolicyEngine.check()` carries the matching `setAdmissionCaller()` gate plus a `subject.consumer == msg.sender` binding. Regression-tested in `test/DailySpendAdmissionAuthority.test.ts` |
| Recipient allowlist policy | ✅ Implemented / Hardened | `RecipientAllowlistPolicy`; fail-safe empty list blocks all; `address(0)` opt-out; vault-owner self-managed                                                                                                                                                                                                                                                                                                                                                                                                |
| Sanctions deny-list policy | ✅ Implemented / Hardened | `SanctionsListPolicy`; admin-controlled; `Ownable2Step`; batch add                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### Policy engine composition

| Feature                                     | Status                    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Composite policy engine                     | ✅ Implemented / Hardened | `CompositePolicyEngine` — fans `IPolicyEngine.check()` to N modules simultaneously; fail-closed (first denial wins); `Ownable2Step` admin; rejects zero-address and no-code module addresses; `addModule` / `removeModule` with events; backward-compatible with single-policy deployments (use it as the single engine wired into the vault). Relays the `PolicySubject` to every module BYTE-FOR-BYTE — never substituting `address(this)` for `subject.consumer`, never zeroing `subject.asset` — and binds `subject.consumer == msg.sender` on `check()` so a registered consumer cannot impersonate another (`SubjectConsumerMismatch`); that binding also makes the long-standing "do not nest composites" warning mechanically enforced on the admission path. Preservation is proved by a recording probe module in `test/PolicySubjectPropagation.test.ts`, which asserts the subject is unchanged while `msg.sender` demonstrably differs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| All three policies operating simultaneously | ✅ Implemented / Hardened | Tested: `DailySpendLimitPolicy + RecipientAllowlistPolicy + SanctionsListPolicy` all enforce in a single withdrawal check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Policy revalidation at finalization         | ✅ Implemented / Hardened | `finalizeWithdrawal` **always** revalidates policy via the read-only `IPolicyEngine.revalidate()` (STATICCALL — structurally unable to mutate policy state), consulting both the queue-time engine (`policyEngineAtQueue`, a sticky floor that survives engine replacement or disablement) and the current engine, each once. Address identity is never used as a proxy for policy freshness, so same-address mutations (e.g. recipient added to the sanctions list after queuing) block settlement. Admission (`check()`) remains the only mutating call: `DailySpendLimitPolicy` books spend once at queue time and finalization never re-books it. An earlier revision re-checked only on engine-address change, which missed same-address state mutations — fixed and regression-tested in `test/PolicyFinalizationAuthority.test.ts` / `test/SimulatorPolicyFinalizationAuthority.test.ts` |

### Events and audit logging

| Feature                      | Status                    | Notes                                                                                                                                                                                                         |
| ---------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Events for all state changes | ✅ Implemented / Hardened | All vault operations emit events; composite policy module additions/removals emit `ModuleAdded` / `ModuleRemoved`; treasury quorum changes emit `TreasuryQuorumThresholdSet` and `TreasuryWithdrawalApproved` |

### Treasury withdrawal quorum

| Feature                                                             | Status                    | Notes                                                                                                                                                                                        |
| ------------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Treasury guardian quorum for large withdrawals                      | ✅ Implemented / Hardened | `treasuryQuorumThreshold` per vault (vault-owner-configurable); `approveTreasuryWithdrawal` for guardian approvals; `finalizeWithdrawal` enforces quorum before execution                    |
| Distinct from credential-recovery quorum                            | ✅ Implemented / Hardened | Uses the same guardian set but separate threshold mapping and approval state; credential-recovery quorum (`(N/2)+1` hardcoded) is unchanged                                                  |
| Duplicate approvals blocked                                         | ✅ Implemented / Hardened | `TreasuryAlreadyApproved` error on second approval from same guardian                                                                                                                        |
| Removed guardians blocked from approving                            | ✅ Implemented / Hardened | `approveTreasuryWithdrawal` checks current guardian set; removed guardians receive `NotAGuardian`                                                                                            |
| Approval state cannot replay across queued withdrawals              | ✅ Implemented / Hardened | Approvals are keyed by `operationId` (EIP-712 hash including nonce); nonces increment on each queue so different withdrawals always have different operationIds; approvals cleared on cancel |
| Canceled withdrawals cannot execute                                 | ✅ Implemented / Hardened | `cancelPendingWithdrawal` deletes `pending.exists`; finalization checks `pending.exists` first                                                                                               |
| Quorum threshold update is vault-owner controlled                   | ✅ Implemented / Hardened | `setTreasuryQuorumThreshold` validates caller has a vault; validates threshold ≤ guardian count                                                                                              |
| Guardian set change clears pending treasury approvals               | ✅ Implemented / Hardened | `setGuardians` clears treasury approvals for any pending withdrawal using the OLD guardian set before replacing it                                                                           |
| Recovery and rotation cancel pending withdrawal and clear approvals | ✅ Implemented / Hardened | `executeRecovery` and `rotateCredentials` both call `_clearTreasuryApprovalsForOp` before deleting the pending withdrawal                                                                    |

---

## Test coverage for Phase 3 final hardening

### CompositePolicyEngine tests (`test/CompositePolicyEngine.test.ts`)

| Test                                                                                                                   | Result                                          |
| ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Starts with empty module list                                                                                          | ✅                                              |
| `addModule` registers a deployed contract                                                                              | ✅                                              |
| `addModule` rejects zero address                                                                                       | ✅                                              |
| `addModule` rejects EOA (no code)                                                                                      | ✅                                              |
| `addModule` rejects random address with no code                                                                        | ✅                                              |
| `addModule` rejects duplicate module                                                                                   | ✅                                              |
| Non-owner cannot `addModule`                                                                                           | ✅                                              |
| `proposeRemoveModule` / `applyRemoveModule` removes a module (after `MODULE_REMOVAL_DELAY`) and emits `ModuleRemoved`  | ✅                                              |
| `proposeRemoveModule` reverts for unknown module; `applyRemoveModule` reverts before the delay / with none pending     | ✅                                              |
| Can re-add module after its removal is fully applied; a second removal needs its own fresh delay (no stale replay)     | ✅                                              |
| Daily limit + allowlist + sanctions all pass (valid withdrawal)                                                        | ✅                                              |
| Sanctioned recipient blocked even if allowlisted                                                                       | ✅                                              |
| Non-allowlisted recipient blocked                                                                                      | ✅                                              |
| Daily limit exceeded blocked                                                                                           | ✅                                              |
| First-failing module's reason returned                                                                                 | ✅                                              |
| Empty module list is permissive                                                                                        | ✅                                              |
| A denying engine installed after queueing blocks finalization                                                          | ✅                                              |
| Finalization revalidates an unchanged engine against current state and passes while it still permits                   | ✅                                              |
| Same-address policy mutation after queue blocks finalization (sanctions add / allowlist revoke / composite module add) | ✅ (`test/PolicyFinalizationAuthority.test.ts`) |
| Queue-time engine is a sticky floor across engine replacement and disable-to-`address(0)`                              | ✅                                              |
| Daily spend booked once at admission; finalization never re-books (STATICCALL revalidation)                            | ✅                                              |
| Control A: an engine-address swap (even after its full delay) cannot erase the queue-time composite's sticky floor     | ✅ (`test/CompositeModuleGovernanceAuthority.test.ts`) |
| Control B: a matured, applied module removal on that SAME composite legitimately changes the outcome (address unchanged, roster changed) — address-level sticky floor != module-roster snapshot | ✅ (`test/CompositeModuleGovernanceAuthority.test.ts`) |

### Treasury quorum tests (`test/TreasuryQuorum.test.ts`)

| Test                                                                | Result |
| ------------------------------------------------------------------- | ------ |
| Quorum threshold update is vault-owner controlled                   | ✅     |
| Non-vault-owner cannot set threshold                                | ✅     |
| Threshold of 0 disables treasury quorum                             | ✅     |
| Threshold exceeding guardian count rejected                         | ✅     |
| Threshold > 0 with no guardians rejected                            | ✅     |
| Large withdrawal cannot finalize without required quorum            | ✅     |
| Large withdrawal cannot finalize with insufficient quorum           | ✅     |
| Large withdrawal can finalize after timelock + quorum               | ✅     |
| Finalization blocked before timelock even with full quorum          | ✅     |
| Large withdrawal with quorum disabled finalizes without approvals   | ✅     |
| `TreasuryWithdrawalApproved` emitted with incrementing count        | ✅     |
| Duplicate approval rejected                                         | ✅     |
| Removed guardian cannot approve after `setGuardians`                | ✅     |
| Non-guardian cannot approve                                         | ✅     |
| Reverts when no pending withdrawal                                  | ✅     |
| Reverts with mismatched operationId                                 | ✅     |
| Approval state cannot be reused across different queued withdrawals | ✅     |
| Canceled withdrawal cannot execute even after quorum was met        | ✅     |
| `setGuardians` clears treasury approvals; re-approval required      | ✅     |
| Recovery execution clears treasury approvals on pending withdrawal  | ✅     |

---

## Out of scope / future work

| Feature                                                | Status                                                                               |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| HSM integration                                        | 🔮 Future — requires hardware custody infrastructure outside this prototype          |
| External compliance feeds (live OFAC API, Chainalysis) | 🔮 Future — off-chain oracle integration not in scope                                |
| Token treasury support (ERC-20, ERC-721)               | 🔮 Future — vault currently handles ETH only                                         |
| Production custody                                     | 🔮 Future — this is a research prototype; no mainnet deployment intended             |
| Wallet connection                                      | 🔮 Out of scope for this component                                                   |
| Mainnet deployment                                     | 🔮 Out of scope; prototype only                                                      |
| SP1 ZK prover / verifier                               | ⚠️ Unaudited scaffold only; not the active Sepolia verifier and not production-ready |

---

## Validation summary (merged Phase 3 hardening)

```
npm test          → 220 passing, 2 pending (intentional ZK E2E, require RUN_SP1_E2E=1)
npm run coverage  → CompositePolicyEngine 100% stmt/func; WalletWallVault 99.57% stmt
npm run compile   → 0 errors
npm run lint      → 0 errors (49 gas/style warnings, consistent with pre-existing baseline)
git diff --check  → clean (no trailing whitespace)
prettier --check  → clean on all changed files
```
