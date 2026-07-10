# Testnet Stablecoin Vault Simulator — Implementation Spec

> ⚠️ **Research prototype. Not audited. Testnet / local only. Do not use real funds.**
> **Status update:** this document originated as a docs/spec proposal ("adds no Solidity,
> scripts, deployment artifacts, ABIs, or frontend integration"); that framing is no longer
> current. The design below has since been **implemented and deployed**:
> [`contracts/StablecoinVaultSimulator.sol`](../../contracts/StablecoinVaultSimulator.sol)
> and [`contracts/mocks/MockUSDC.sol`](../../contracts/mocks/MockUSDC.sol) exist as a
> prototype implementation, and a Sepolia testnet research deployment exists — see
> [docs/Deployments.md](../Deployments.md) for addresses, deployment timestamp, and
> package version. This is a non-production Sepolia research deployment: no custody or
> production asset protection, not audited, no claim of quantum-proof security (the
> deployed PQ gate is the mock verifier, not on-chain ML-DSA), and a testnet deployment
> does not establish production readiness. It has no bearing on production WalletWall's
> actual security posture, which is separate and unrelated. The sections below remain the
> original design rationale; the §10 implementation checklist describes work that is now
> complete. For current operator-facing status see
> [docs/Sepolia_Rehearsal_Operator_Path.md](../Sepolia_Rehearsal_Operator_Path.md); for the
> up-to-date capability summary see
> [docs/ZK_PQ_Status_Matrix.md](../ZK_PQ_Status_Matrix.md).
>
> **One-line framing:** A **testnet-only** simulator where a user can deposit and withdraw
> a **mock USDC-style ERC-20 test token (no monetary value)** through the vault's existing
> **EIP-712-authorized**, **PQ-attestation-gated** flow — to *rehearse* a quantum-resistant
> stablecoin vault migration. Never real custody, never mainnet, never yield.

This spec is the **public vault-repo counterpart** to the WalletWall app's
[Stablecoin Vault MVP — Product & Boundary Spec](https://github.com/Wallet-Wall/walletwall)
(`docs/product/stablecoin-vault-mvp.md` in the private app repo). That app spec defines the
**intelligence / readiness layer** and the four-outcome funnel (Monitor / Prepare / Testnet
Rehearsal / Not Enough Data) that routes a user toward the simulator. This document defines
the **action layer** that lives here: the mock stablecoin token, the ERC-20-aware vault, and
the testnet posture that backs the rehearsal.

The split is deliberate and matches [WALLETWALL_APP_BOUNDARY.md](../WALLETWALL_APP_BOUNDARY.md):

- The **app owns** product UI, the readiness workflow, the conditional simulator entry, and
  the disclosures it renders.
- This **vault repo owns** the contracts, verifier boundary, attestation path, testnet
  deployment, and security model.

---

## 1. Why a new asset, not a new security model

The existing [`WalletWallVault`](../../contracts/WalletWallVault.sol) is **ETH-denominated**:
`deposit()` / `depositFor()` are `payable`, per-vault `balance` is tracked in wei, and
withdrawals push value with `recipient.call{value: amount}("")`. It already implements the
full authorization and governance model the simulator needs:

- EIP-712 typed `Withdrawal(vaultOwner, recipient, amount, nonce, deadline, vaultMode)`.
- Per-owner `nonce` + signed `deadline` replay protection.
- `VaultMode` (`EcdsaOnly` / `PqOnly` / `Hybrid`), with `PqOnly` blocked while the mock
  verifier is active.
- The swappable [`IPQCVerifier`](../../contracts/IPQCVerifier.sol) trust boundary
  (`MockMLDSAVerifier`, `AttestationPQCVerifier`).
- The optional [`IPolicyEngine`](../../contracts/IPolicyEngine.sol) hook.
- Large-transaction queue → timelock → finalize.
- Timelocked admin governance (2-day PQ-verifier, policy-engine, and large-tx-param delays).
- Guardian recovery (7-day delay) and treasury quorum.

**The only meaningful delta this MVP introduces is the deposited asset:** a mock USDC-style
ERC-20 instead of native ETH. So the goal is to **port the existing model to an ERC-20
asset**, not to invent new authorization or governance mechanics. The simulator must reuse
every security property above; the rehearsal exists to teach that model on a stablecoin-shaped
asset that matches WalletWall's stablecoin-vault thesis.

The behavioral delta from ETH to ERC-20:

| Concern | ETH vault (today) | Stablecoin simulator (this spec) |
| --- | --- | --- |
| Deposit | `deposit()` `payable`, credits `msg.value` | `approve(vault, amount)` then `deposit(amount)`; vault pulls via `safeTransferFrom` |
| Withdraw transfer | `recipient.call{value: amount}("")` | `IERC20.safeTransfer(recipient, amount)` |
| Balance unit | wei | token base units (mock-USDC, 6 decimals) |
| Force-send / accounting quirk | ETH `selfdestruct` not credited | direct ERC-20 transfers to the vault are **not** credited; only `deposit()` updates records |
| Reentrancy surface | `.call` to recipient | ERC-20 transfer (use `SafeERC20` + `nonReentrant`, keep checks-effects-interactions) |

---

## 2. Simulator MVP

### 2.1 Mock USDC-style ERC-20 token

- **New contract** (working name `MockUSDC`, e.g. `contracts/mocks/MockUSDC.sol`).
- Standard OpenZeppelin `ERC20`. **6 decimals** to mirror real USDC (override `decimals()`).
- Name/symbol that are unmistakably a test token, e.g. name `WalletWall Mock USD`,
  symbol `mUSDC`.
- **Freely mintable faucet:** a permissionless `mint(address to, uint256 amount)` (or
  `faucet()` that mints a fixed amount to `msg.sender`), so any testnet user can self-serve.
  Optionally cap per-call mint size to keep balances sane; **never** a purchase path.
- No pause, no blocklist, no fee-on-transfer, no rebasing — a plain test token. The vault’s
  accounting assumes a vanilla ERC-20; document that fee-on-transfer / rebasing tokens are
  explicitly unsupported.
- Clear NatSpec header: testnet/local only, no monetary value, not audited.

### 2.2 ERC-20-aware vault (simulator)

- **New contract** (working name `StablecoinVaultSimulator`, e.g.
  `contracts/StablecoinVaultSimulator.sol`) that mirrors `WalletWallVault` but escrows a
  single ERC-20 token configured at construction (`address token` + the `IPQCVerifier`).
- Reuse the **identical** `Withdrawal` struct shape and EIP-712 typing so the app can reuse
  the prototype's typed-data construction with only a domain change. Recommended EIP-712
  domain: `name = "WalletWallStablecoinVault"`, `version = "1"` (distinct domain separator
  prevents cross-contract signature replay between the ETH vault and the simulator).
- **Deposit:** non-payable `deposit(uint256 amount)` / `depositFor(address owner, uint256 amount)`
  that pulls tokens with `SafeERC20.safeTransferFrom(msg.sender, address(this), amount)` and
  credits the per-vault record.
- **Withdraw:** same EIP-712-authorized `withdraw(...)` and `queueWithdrawal(...) →
  finalizeWithdrawal(...)` flow, transferring out with `SafeERC20.safeTransfer`.
- Carry over `ReentrancyGuard`, `Pausable`, `Ownable2Step`, custom errors, and the full
  governance/recovery surface unchanged in behavior.

> **Decision to confirm in the implementation session:** single-token-at-construction
> (recommended, simplest, matches the app's "one mock stablecoin" framing) **vs.** a
> `token` field inside the `Withdrawal` struct for multi-asset support. The MVP recommends
> single-token; multi-asset is a non-goal here.

### 2.3 Deposit

The depositor moves mock-USDC into **their own** vault record from **their own** wallet, in
two inspectable steps: ERC-20 `approve(vault, amount)`, then `deposit(amount)`. WalletWall
holds no signing authority and never custodies keys. `depositFor` allows a relayer/third party
to fund an existing vault, mirroring the ETH `depositFor`.

### 2.4 Withdraw

Always user-initiated and authorized by an **EIP-712 typed `Withdrawal`** with per-vault nonce
replay protection. Small withdrawals execute immediately via `withdraw(...)`; above-threshold
withdrawals route through `queueWithdrawal(...)` → timelock → `finalizeWithdrawal(...)`,
exactly as the ETH vault does.

### 2.5 EIP-712 withdrawal authorization

The withdrawal digest uses the same typed-data construction the prototype already uses
(`hashWithdrawal` equivalent). The app renders the human-readable typed message for review
before the user's wallet signs. Tamper protection: owner / recipient / amount / nonce /
deadline / mode are all part of the signed struct; changing any field invalidates the
signature.

### 2.6 PQ attestation gate

In `Hybrid` (intended default) and `PqOnly` modes, a withdrawal requires a valid PQ signature
checked through the `IPQCVerifier` boundary.

- **MVP default verifier:** [`AttestationPQCVerifier`](../../contracts/verifiers/AttestationPQCVerifier.sol)
  — the **trusted-attestation** path. An authorized attestor verifies ML-DSA-65 **off-chain**
  (FIPS 204-compatible, via the existing `scripts/attestor-cli.ts` + `pqc/ml-dsa.ts`) and signs
  an EIP-712 `PQCAttestation`; **ML-DSA is not verified on-chain.**
- `MockMLDSAVerifier` remains **local/test-only** (structural checks, no real crypto).
- `PqOnly` stays disabled while a mock verifier is wired in (the existing
  `PqOnlyDisabledForMockVerifier` guard).
- The app **must** label this as a **trusted attestor**, never trustless on-chain PQ
  verification. See [Attestation_Verifier.md](../Attestation_Verifier.md) and
  [Verifier_Roadmap.md](../Verifier_Roadmap.md).

### 2.7 Replay protection

Strictly increasing per-owner `nonce` plus a signed `deadline`, identical to the ETH vault.
A consumed nonce voids the signed authorization; rotation/recovery bump the nonce and cancel
any queued withdrawal. The EIP-712 domain separator binds signatures to this contract's
address, chain ID, and name/version.

### 2.8 Policy / timelock / recovery expectations

The simulator must exercise the full governance surface so the rehearsal teaches *governance*,
not just deposit/withdraw:

- **Policy engine:** optional `IPolicyEngine` (recipient allowlist, daily spend limit,
  sanctions deny list, composed via `CompositePolicyEngine`) checked before a withdrawal
  executes or queues, and re-checked at finalize if the engine address changed.
- **Large-tx timelock:** above-threshold withdrawals reserved at queue time, finalized only
  after the configured delay.
- **Admin timelocks:** 2-day propose → apply for PQ verifier, policy engine, and large-tx
  parameters.
- **Guardian recovery:** 7-day delay (`initiateRecovery` → `executeRecovery` /
  `cancelRecovery`), majority-of-guardians support.
- **Treasury quorum:** optional guardian approvals before a queued large withdrawal finalizes.

These are **reused as-is** from the existing contracts where the code is asset-agnostic, or
ported field-for-field where the ETH transfer call must become an ERC-20 transfer.

### 2.9 Testnet-only deployment posture

- Deploy tooling **hard-fails** on any non-testnet chain (extend the existing
  `ALLOWED_NETWORKS` allowlist: `hardhat`, `localhost`, `sepolia`, `base-sepolia`).
- Mock token only; no real stablecoin address is ever referenced.
- Persistent "TESTNET — RESEARCH PROTOTYPE, NO REAL VALUE" framing in all docs and any future
  UI; a blocking acknowledgement before any write; inline "no monetary value" qualifier on
  balances.
- Recorded in [docs/Deployments.md](../Deployments.md) with the same honesty bar as the
  existing Sepolia record (no reproducibility or audit claims beyond what is verified).

---

## 3. User stories

1. **User deposits mock stablecoin.**
   *As a testnet user, I mint mock-USDC from the faucet, `approve` the simulator vault, and
   `deposit` it into my vault record from my own wallet — so I can rehearse funding a vault
   without any real asset.*
   Acceptance: faucet mint succeeds; `deposit` pulls exactly the approved amount; the vault
   record reflects the deposit; a direct ERC-20 transfer (no `deposit` call) is **not**
   credited.

2. **User rehearses a withdrawal.**
   *As a user with a funded vault, I construct an EIP-712 `Withdrawal`, sign it with my own
   wallet, and submit it — so I learn what authorizing a quantum-resistant withdrawal feels
   like.*
   Acceptance: a correctly signed withdrawal transfers mock-USDC to the recipient and bumps
   the nonce; an above-threshold amount is rejected for the immediate path and must be queued.

3. **User sees the PQ attestation requirement.**
   *As a user in Hybrid mode, my withdrawal is rejected without a valid PQ attestation, and the
   flow makes clear the attestation comes from a **trusted attestor** (off-chain ML-DSA-65),
   not on-chain ML-DSA.*
   Acceptance: a withdrawal missing/with an invalid PQ signature reverts `InvalidPQSignature`;
   a valid attestation from the configured attestor succeeds; copy never implies trustless
   on-chain PQ verification.

4. **User tests the recovery / emergency path.**
   *As a user who set guardians, I can rehearse credential recovery (7-day delay, guardian
   majority) and observe that a pending queued withdrawal is cancelled and its reservation
   refunded on recovery; I can also see the admin pause as an emergency stop.*
   Acceptance: recovery executes only after delay + sufficient support; a queued withdrawal is
   refunded to the vault balance on recovery/rotation; `pause()` blocks new
   deposits-considered-writes/withdrawals while cancellation of a queued withdrawal remains
   available so funds are not trapped.

---

## 4. Non-goals

Explicitly **out of scope** for the simulator MVP — and these must never be implied in code,
docs, or app copy:

- **No real stablecoins.** No real USDC/USDT/DAI or any real-value token, ever.
- **No mainnet custody.** No mainnet network, RPC, address, token, or deposit. Deploy tooling
  hard-fails off testnet.
- **No yield.** No mechanism that grows a balance over time.
- **No interest.** No accrual, simulated or otherwise, framed as interest.
- **No APY / APR / returns.** No annualized rate, rate-of-return, or payout countdown anywhere.
- **No claim of trustless on-chain PQ verification.** ML-DSA is verified **off-chain** by a
  trusted attestor in this MVP. No "quantum-proof," "quantum-safe today," "audited," or
  "protects assets from quantum attacks today" claims.
- **No multi-asset vault** (single mock token per simulator vault in this MVP).
- **No production custody / no key storage / no seed-phrase requests** by WalletWall.
- **No fee-on-transfer / rebasing token support** (the mock is a vanilla ERC-20).

---

## 5. Contract boundaries

### 5.1 New contracts that may be needed

- **`MockUSDC` (ERC-20 test token)** — freely mintable, 6 decimals, no value. `contracts/mocks/`.
- **`StablecoinVaultSimulator` (ERC-20-aware vault)** — mirrors `WalletWallVault`'s
  authorization/governance model over a single ERC-20 asset, using `SafeERC20` for transfers
  and an `approve` + `transferFrom` deposit path. `contracts/`.
- **(Optional) a small deposit/withdraw demo script** for the simulator, parallel to
  `scripts/demo-local.ts` — but scripts are **out of scope for this docs PR**.

### 5.2 Existing contracts / modules that can be reused unchanged

- [`IPQCVerifier`](../../contracts/IPQCVerifier.sol) — verifier trust boundary interface.
- [`AttestationPQCVerifier`](../../contracts/verifiers/AttestationPQCVerifier.sol) — trusted
  attestation path (MVP default for the PQ gate).
- [`MockMLDSAVerifier`](../../contracts/MockMLDSAVerifier.sol) — local/test verifier.
- [`IPolicyEngine`](../../contracts/IPolicyEngine.sol) and
  [`contracts/policies/`](../../contracts/policies/) — `CompositePolicyEngine`,
  `DailySpendLimitPolicy`, `RecipientAllowlistPolicy`, `SanctionsListPolicy`. These are
  asset-agnostic (they take amounts/addresses) and can be reused directly.
- [`pqc/ml-dsa.ts`](../../pqc/ml-dsa.ts) and [`scripts/attestor-cli.ts`](../../scripts/attestor-cli.ts)
  — off-chain ML-DSA-65 signing + attestation, unchanged.
- Test helpers in `test/helpers/` and the ML-DSA fixtures under `test/fixtures/mldsa/`.

### 5.3 What should NOT change

- **`WalletWallVault.sol`** — the ETH vault stays as-is. The simulator is a **new sibling
  contract**, not a refactor of the ETH vault. Do not generalize the ETH vault into the token
  vault in this MVP (that risks regressing a contract with an active testnet deployment).
- **`WalletWallMultiSigVault.sol`** — untouched.
- **`IPQCVerifier` / `IPolicyEngine` interfaces** — extend behavior via the new vault, not by
  changing these interfaces. The existing verifiers and policy engines must keep working with
  both vaults.
- The existing **Sepolia deployment record** and its provenance notes in `docs/Deployments.md`.

---

## 6. Test plan

New tests (e.g. `test/StablecoinVaultSimulator.test.ts`, `test/MockUSDC.test.ts`) mirroring the
style of `test/WalletWallVault.test.ts` and `test/AttestationPQCVerifier.test.ts`. Coverage:

| Area | Cases |
| --- | --- |
| **Deposit success** | `approve` + `deposit` credits the exact amount; `depositFor` funds another owner; faucet mint works |
| **Deposit failure** | deposit without sufficient allowance reverts; deposit of 0 reverts; deposit to non-existent vault reverts; raw ERC-20 transfer to the vault is **not** credited |
| **Withdrawal success** | valid EIP-712 withdrawal in `EcdsaOnly` and `Hybrid`; correct token transfer out; nonce increments; event emitted |
| **Withdrawal failure** | wrong signer, expired deadline, wrong nonce, amount > balance, zero recipient, `vaultMode` mismatch, above-threshold amount routed to immediate path (`UseLargeWithdrawal`) |
| **Replay rejection** | re-submitting a used signature reverts on `InvalidNonce`; a signature for the ETH vault domain is rejected by the simulator domain (cross-contract replay) |
| **Bad attestation rejection** | `Hybrid`/`PqOnly` withdrawal with missing/expired/wrong-attestor/altered-payload attestation reverts `InvalidPQSignature`; valid attestor signature succeeds |
| **Timelock / policy checks** | large-tx `queueWithdrawal` reserves funds; `finalizeWithdrawal` before `readyAt` reverts; policy allowlist/daily-limit/sanctions reject as expected; finalize re-check when policy engine changed; 2-day admin propose/apply timing |
| **Recovery / emergency path** | guardian set rules; `initiateRecovery` → support → `executeRecovery` only after 7-day delay + majority; queued withdrawal cancelled + token reservation refunded on recovery and on `rotateCredentials`; `pause()` blocks writes; `cancelPendingWithdrawal` still works while paused; treasury quorum gating |

The implementation session should also run `npm run coverage` and keep the new contracts at or
above the repo's existing coverage bar. Tests prove only that current prototype behavior matches
the checked cases — not production-readiness (see [TESTING.md](../TESTING.md)).

---

## 7. Deployment plan

- **Local (default):** `npx hardhat node` + a simulator deploy script that deploys `MockUSDC`,
  a verifier (`MockMLDSAVerifier` locally, `AttestationPQCVerifier` for attestation rehearsal),
  and `StablecoinVaultSimulator(token, verifier)`. Also works against **anvil** (Foundry) as a
  drop-in local EVM node.
- **Sepolia (optional):** reuse the existing testnet flow and `ALLOWED_NETWORKS` hard-fail;
  deploy `MockUSDC` + simulator wired to the trusted-attestation verifier. Base Sepolia is the
  other already-supported target.
- **Mock token only:** the simulator is constructed against the deployed `MockUSDC` address; no
  real-stablecoin address is ever accepted.
- **No real value:** test ETH for gas only; the mock token has no value. Record the deployment
  in `docs/Deployments.md` with the same honesty bar (no audit/reproducibility overclaim).
- Secrets stay in env vars (`DEPLOYER_PRIVATE_KEY`, RPC URLs per `.env.example`); never commit
  populated values or paste keys into issues/PRs/chat.

---

## 8. App integration boundary

Mirrors [WALLETWALL_APP_BOUNDARY.md](../WALLETWALL_APP_BOUNDARY.md) and the app spec's repo
boundary.

- The app **may** link to this repo's docs (`README.md`, `SECURITY.md`,
  `docs/THREAT_MODEL.md`, `docs/Verifier_Roadmap.md`, `docs/Attestation_Verifier.md`, this
  spec) and **may** read published deployment metadata (addresses, ABI, custom errors, events,
  EIP-712 schema, chain IDs) **later**, once published.
- The app **must not** copy contract source, ABIs, or deployment artifacts into the app repo as
  a canonical source of truth **until a deliberate, versioned integration PR** pins them. The
  app references; this repo owns.
- **No private keys or secrets** cross the boundary in either direction. Attestor keys,
  deployer keys, and RPC credentials stay in this repo's env-var configuration and are never
  shared with the app.
- The app must label every simulator surface as **testnet / research prototype**, mark the PQ
  gate as a **trusted attestor** (not on-chain ML-DSA), and avoid the overclaim vocabulary in
  [WALLETWALL_APP_BOUNDARY.md](../WALLETWALL_APP_BOUNDARY.md) (§"What the App Should Avoid
  Saying").

---

## 9. Relationship to the roadmap

This simulator is a **Phase 1 / Phase 2** artifact (research prototype + security hardening) in
[ROADMAP.md](../ROADMAP.md): it extends the prototype's asset coverage to a stablecoin-shaped
test token while keeping every existing claim boundary. It does **not** advance any
production, audit, or mainnet claim. The trusted-attestation PQ gate remains **Path 1** in
[Verifier_Roadmap.md](../Verifier_Roadmap.md); on-chain ML-DSA verification is still out of
scope.

## 10. Implementation checklist (for a later session)

> Docs-only PR. The list below is for *future* engineering sessions; **do not** implement here.

- [ ] Confirm single-token-at-construction vs. `token`-in-struct (recommend single-token).
- [ ] Author `MockUSDC` (6 decimals, faucet mint, no value, vanilla ERC-20).
- [ ] Author `StablecoinVaultSimulator` mirroring `WalletWallVault` with `SafeERC20` transfers
      and an `approve` + `transferFrom` deposit path; distinct EIP-712 domain.
- [ ] Reuse `IPQCVerifier`, `AttestationPQCVerifier`, `IPolicyEngine` + policies unchanged.
- [ ] Do **not** modify `WalletWallVault`, `WalletWallMultiSigVault`, or the verifier/policy
      interfaces.
- [ ] Add tests per §6; run `npm run compile`, `npm test`, `npm run lint`,
      `npm run format:check`, `npm run coverage`.
- [ ] Add a testnet-only deploy script with a non-testnet hard-fail; record in
      `docs/Deployments.md`.
- [ ] Keep all disclosures honest: testnet only, no value, trusted attestor, not audited.
- [ ] Coordinate any app consumption through a separate versioned integration PR.
