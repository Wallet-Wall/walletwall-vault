# Phase 3 Security Hardening — Status Matrix

> **RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL DEMO ONLY. DO NOT USE WITH REAL FUNDS.**
> All items below are prototype implementations for research purposes only.

Last updated: 2026-06-15
Status: **complete and merged to `main` in PR #35**
Release: `v0.4.12`

---

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ Implemented / Hardened | Feature present and covered by passing tests |
| ⚠️ Partial | Implemented but has known gaps (noted) |
| 🔮 Future / Out of scope | Not implemented; intentionally deferred |

---

## Phase 3 hardening matrix

### Core withdrawal controls

| Feature | Status | Notes |
|---------|--------|-------|
| Large-withdrawal timelock | ✅ Implemented / Hardened | `largeTxThreshold`, `largeTxDelay`, timelocked `queueWithdrawal` + `finalizeWithdrawal`; governance-delayed parameter changes; cancellation preserves reserved funds |
| Daily spend limit policy | ✅ Implemented / Hardened | `DailySpendLimitPolicy`; rolling 24-hour window; per-vault-owner configurable; 0 = unrestricted |
| Recipient allowlist policy | ✅ Implemented / Hardened | `RecipientAllowlistPolicy`; fail-safe empty list blocks all; `address(0)` opt-out; vault-owner self-managed |
| Sanctions deny-list policy | ✅ Implemented / Hardened | `SanctionsListPolicy`; admin-controlled; `Ownable2Step`; batch add |

### Policy engine composition

| Feature | Status | Notes |
|---------|--------|-------|
| Composite policy engine | ✅ Implemented / Hardened | `CompositePolicyEngine` — fans `IPolicyEngine.check()` to N modules simultaneously; fail-closed (first denial wins); `Ownable2Step` admin; rejects zero-address and no-code module addresses; `addModule` / `removeModule` with events; backward-compatible with single-policy deployments (use it as the single engine wired into the vault) |
| All three policies operating simultaneously | ✅ Implemented / Hardened | Tested: `DailySpendLimitPolicy + RecipientAllowlistPolicy + SanctionsListPolicy` all enforce in a single withdrawal check |
| Policy re-check at finalization | ✅ Implemented / Hardened | `finalizeWithdrawal` re-checks the current policy engine **only when it has changed since the withdrawal was queued** (`policyEngineAtQueue` field in `PendingWithdrawal`). This prevents stale-policy bypasses (e.g. recipient added to sanctions list after queuing) while avoiding double-counting in stateful policies (e.g. `DailySpendLimitPolicy` records spend once at queue time, not again at finalization if the engine is unchanged) |

### Events and audit logging

| Feature | Status | Notes |
|---------|--------|-------|
| Events for all state changes | ✅ Implemented / Hardened | All vault operations emit events; composite policy module additions/removals emit `ModuleAdded` / `ModuleRemoved`; treasury quorum changes emit `TreasuryQuorumThresholdSet` and `TreasuryWithdrawalApproved` |

### Treasury withdrawal quorum

| Feature | Status | Notes |
|---------|--------|-------|
| Treasury guardian quorum for large withdrawals | ✅ Implemented / Hardened | `treasuryQuorumThreshold` per vault (vault-owner-configurable); `approveTreasuryWithdrawal` for guardian approvals; `finalizeWithdrawal` enforces quorum before execution |
| Distinct from credential-recovery quorum | ✅ Implemented / Hardened | Uses the same guardian set but separate threshold mapping and approval state; credential-recovery quorum (`(N/2)+1` hardcoded) is unchanged |
| Duplicate approvals blocked | ✅ Implemented / Hardened | `TreasuryAlreadyApproved` error on second approval from same guardian |
| Removed guardians blocked from approving | ✅ Implemented / Hardened | `approveTreasuryWithdrawal` checks current guardian set; removed guardians receive `NotAGuardian` |
| Approval state cannot replay across queued withdrawals | ✅ Implemented / Hardened | Approvals are keyed by `operationId` (EIP-712 hash including nonce); nonces increment on each queue so different withdrawals always have different operationIds; approvals cleared on cancel |
| Canceled withdrawals cannot execute | ✅ Implemented / Hardened | `cancelPendingWithdrawal` deletes `pending.exists`; finalization checks `pending.exists` first |
| Quorum threshold update is vault-owner controlled | ✅ Implemented / Hardened | `setTreasuryQuorumThreshold` validates caller has a vault; validates threshold ≤ guardian count |
| Guardian set change clears pending treasury approvals | ✅ Implemented / Hardened | `setGuardians` clears treasury approvals for any pending withdrawal using the OLD guardian set before replacing it |
| Recovery and rotation cancel pending withdrawal and clear approvals | ✅ Implemented / Hardened | `executeRecovery` and `rotateCredentials` both call `_clearTreasuryApprovalsForOp` before deleting the pending withdrawal |

---

## Test coverage for Phase 3 final hardening

### CompositePolicyEngine tests (`test/CompositePolicyEngine.test.ts`)

| Test | Result |
|------|--------|
| Starts with empty module list | ✅ |
| `addModule` registers a deployed contract | ✅ |
| `addModule` rejects zero address | ✅ |
| `addModule` rejects EOA (no code) | ✅ |
| `addModule` rejects random address with no code | ✅ |
| `addModule` rejects duplicate module | ✅ |
| Non-owner cannot `addModule` | ✅ |
| `removeModule` removes module and emits event | ✅ |
| `removeModule` reverts for unknown module | ✅ |
| Can re-add module after removal | ✅ |
| Daily limit + allowlist + sanctions all pass (valid withdrawal) | ✅ |
| Sanctioned recipient blocked even if allowlisted | ✅ |
| Non-allowlisted recipient blocked | ✅ |
| Daily limit exceeded blocked | ✅ |
| First-failing module's reason returned | ✅ |
| Empty module list is permissive | ✅ |
| Policy failure at finalization blocks when engine changed since queuing | ✅ |
| Finalization passes when engine unchanged (no double-check) | ✅ |

### Treasury quorum tests (`test/TreasuryQuorum.test.ts`)

| Test | Result |
|------|--------|
| Quorum threshold update is vault-owner controlled | ✅ |
| Non-vault-owner cannot set threshold | ✅ |
| Threshold of 0 disables treasury quorum | ✅ |
| Threshold exceeding guardian count rejected | ✅ |
| Threshold > 0 with no guardians rejected | ✅ |
| Large withdrawal cannot finalize without required quorum | ✅ |
| Large withdrawal cannot finalize with insufficient quorum | ✅ |
| Large withdrawal can finalize after timelock + quorum | ✅ |
| Finalization blocked before timelock even with full quorum | ✅ |
| Large withdrawal with quorum disabled finalizes without approvals | ✅ |
| `TreasuryWithdrawalApproved` emitted with incrementing count | ✅ |
| Duplicate approval rejected | ✅ |
| Removed guardian cannot approve after `setGuardians` | ✅ |
| Non-guardian cannot approve | ✅ |
| Reverts when no pending withdrawal | ✅ |
| Reverts with mismatched operationId | ✅ |
| Approval state cannot be reused across different queued withdrawals | ✅ |
| Canceled withdrawal cannot execute even after quorum was met | ✅ |
| `setGuardians` clears treasury approvals; re-approval required | ✅ |
| Recovery execution clears treasury approvals on pending withdrawal | ✅ |

---

## Out of scope / future work

| Feature | Status |
|---------|--------|
| HSM integration | 🔮 Future — requires hardware custody infrastructure outside this prototype |
| External compliance feeds (live OFAC API, Chainalysis) | 🔮 Future — off-chain oracle integration not in scope |
| Token treasury support (ERC-20, ERC-721) | 🔮 Future — vault currently handles ETH only |
| Production custody | 🔮 Future — this is a research prototype; no mainnet deployment intended |
| Wallet connection | 🔮 Out of scope for this component |
| Mainnet deployment | 🔮 Out of scope; prototype only |
| SP1 ZK prover / verifier | ⚠️ Unaudited scaffold only; not the active Sepolia verifier and not production-ready |

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
