# Base Mainnet Custody Adjudication — shared-contract ledger versus per-vault clones

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> This document adjudicates a **proposed** real-value architecture. Nothing in it is deployed, there is
> no mainnet write path, and nothing here authorises Base Mainnet deployment or the use of real USDC.
> The repository does not custody user funds, does not process production withdrawals, and produces no
> real yield. Local and Sepolia simulator paths are developer/testnet rehearsal exceptions only.
>
> **This is engineering design input, not legal advice.** Every legal or compliance question the
> architecture raises is **gated, not answered, here**: see the `LEGAL_REVIEW_REQUIRED` gates in
> [BASE_MAINNET_PRODUCTION_GATES.md](BASE_MAINNET_PRODUCTION_GATES.md).

Lane: `design/base-mainnet-custody-adjudication`. Every **OBSERVED** fact below was read firsthand at
`origin/main` `b9fcd4d5` (package `0.13.31`). Line numbers refer to that commit.

---

## 0. Verdict

**Q1 — Should the current shared-contract `mapping(owner => balance)` architecture be categorically
rejected for the real-value design?** **YES.** Not because of a label, but because of its authority
graph: one address holds every tenant's asset under an internal ledger; the contract admin holds an
unbounded cross-tenant freeze; for the `PqOnly` mode the admin, and separately the WalletWall-operated
attestor, hold a unilateral asset-movement path; every lifecycle action is keyed on `msg.sender`, so
gas sponsorship cannot even reach it. The reasons are enumerated in §4 with line citations. Disclaimers
cannot repair any of them. **`StablecoinVaultSimulator` must never be promoted into a production
contract**, and neither monolith is a base for one.

**Q2 — Does the existing vNext direction already give the correct production topology, or is a new
production-asset architecture required?** **The topology is correct and is adopted: vNext Architecture
C2** — one immutable factory per kernel generation, EIP-1167 clones with immutable arguments, each clone
holding its own asset directly, **no kernel admin, no pause, zero `msg.sender` authority, every entrypoint
signature- or quorum-authorised and therefore relayable by anyone**. What vNext does **not** yet give is
the **asset plane**: the prototype kernel spends **native ETH only**. A real-USDC vault therefore needs a
**new kernel generation** that adds an _admitted-asset ERC-20 spend path_ with the USDC contract bound into
the clone's code, plus the deltas in §7. That is a new generation of the vNext kernel, **not** a new
topology and **not** a port of the monoliths.

**Q3 — Can WalletWall operate a gas-paying relayer without acquiring withdrawal authority?** Under C2,
**yes by construction**: the vNext authority graph already classifies an "arbitrary external caller" as
"may relay an authorized action; holds nothing"
(`Vault_vNext_Architecture.md` §8.1), and the kernel consults `msg.sender` **nowhere**. The relayer is one
such caller. Its own threat model is [BASE_MAINNET_GAS_RELAYER_THREAT_MODEL.md](BASE_MAINNET_GAS_RELAYER_THREAT_MODEL.md).

**What this verdict does NOT say.** It does not say the vNext prototype is production-ready (it is not:
no audit, illustrative constants, native-ETH asset plane, open blockers B-1..B-6 in the architecture
document §25.5). It settles no legal or compliance question; it establishes which architecture can
_truthfully_ carry the factual premises that a qualified legal/compliance review will evaluate
(`LEGAL_REVIEW_REQUIRED`).

---

## 1. Method — substance over labels

The brief forbids treating "noncustodial" or "smart contract" as conclusions. So each architecture is
interrogated with questions that have **code-observable** answers, chosen so that a later qualified review
can map them onto whatever custody and control standards apply:

| #   | Question                                                                                 | How it is answered from code                                                                         |
| --- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Q-A | **Whose address holds the asset?**                                                       | Is the balance at a per-user account, or at one provider-deployed contract with an internal ledger?  |
| Q-B | **Who can move the asset?**                                                              | Enumerate every path that transfers value out, and every principal whose signature or role gates it. |
| Q-C | **Who can prevent movement, for how long, for whom?**                                    | Enumerate pause/deny/delay levers, their bound, and their blast radius.                              |
| Q-D | **Who can change the rules after deployment?**                                           | Upgradeability, swappable verifiers, policy engines, parameter governance, factory retargeting.      |
| Q-E | **Can the operator's capability change by configuration?**                               | A capability that depends on a per-vault mode flag is a capability.                                  |
| Q-F | **What is the blast radius of an external freeze (USDC blocklist)?**                     | Does one blocklisted account freeze one user or everyone?                                            |
| Q-G | **Does every user action survive a dead relayer, dead RPC, dead billing, dead company?** | Are entrypoints permissionless? Are the offline artifacts published?                                 |
| Q-H | **Can a sponsored user act at all without holding ETH?**                                 | Is any user action keyed on `msg.sender` rather than on a signature?                                 |

A "yes, the operator can" answer to Q-B or an unbounded "yes" to Q-C is disqualifying for a real-value
design regardless of how the product is described.

---

## 2. Architecture inventory (OBSERVED at `b9fcd4d5`)

| Id     | Contract                                                                                        | Asset                                                        | Tenancy                                                                            | Status in repo                                                                           |
| ------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **A1** | `contracts/WalletWallVault.sol`                                                                 | native ETH                                                   | shared: `mapping(address => VaultOwner) vaults` (L198), per-record `balance` (L52) | research prototype; Sepolia testnet deployment with the **mock** verifier                |
| **A2** | `contracts/StablecoinVaultSimulator.sol`                                                        | one ERC-20 fixed at construction (`token`, `immutable`, L61) | shared: `vaults` mapping (L197)                                                    | testnet rehearsal of a stablecoin-shaped vault; **never real value by its own spec**     |
| **A3** | `contracts/WalletWallMultiSigVault.sol`                                                         | native ETH                                                   | shared: `vaults` mapping (L79), p-of-q signers                                     | research prototype; "no recovery path of any kind" (its own NatSpec, L366-369)           |
| **B**  | `prototype/vnext-kernel/contracts/VaultKernelPrototype.sol` + `VaultKernelFactoryPrototype.sol` | native ETH (spend); any asset (migration egress)             | **one clone = one vault**; identity = clone address                                | measurement prototype, "NOT PRODUCTION", compiled and tested in an isolated Hardhat unit |

A1, A2 and A3 are **Model A** in the brief's terms (a provider-operated contract holding aggregate value
with internal per-user accounting). B is **Model B** (dedicated per-user vaults, each holding its own
asset).

---

## 3. Authority census — Model A (A1 and A2; A3 differs only in lacking recovery)

Capabilities named in the vNext vocabulary: `MOVE_ASSETS`, `FREEZE`, `DENY`, `DELAY`, `CHANGE_RULES`,
`CHANGE_CREDENTIALS`.

| Principal                                                                                       | Entry points (A1 lines; A2 mirrors them)                                                                                                                                | Capability                                                                                                                                                                                                                                                                        | Bound                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Contract admin** (`Ownable2Step` owner — WalletWall)                                          | `pause()` / `unpause()` L1458-1465                                                                                                                                      | **FREEZE, every tenant**: `withdraw`, `queueWithdrawal`, `finalizeWithdrawal`, `rotateCredentials`, `initiateRecovery`, `executeRecovery`, `createVault`, `deposit` are all `whenNotPaused`                                                                                       | **none** — until the admin unpauses. A lost admin key while paused is a **permanent** cross-tenant freeze; the contract's own NatSpec calls it "the one failure in this contract with no recovery path of any kind" (L1474-1482)                                                                           |
| Contract admin                                                                                  | `proposePQVerifier` / `applyPQVerifierUpdate` / `cancel` L1175-1249                                                                                                     | **CHANGE_RULES for every vault at once**; in `PqOnly` mode this is **MOVE_ASSETS and CHANGE_CREDENTIALS**: `needEcdsa == false` (L1128-1129), so the verifier the admin installs is the sole authenticator for `withdraw` (L1136-1138), `queueWithdrawal` and `rotateCredentials` | 2-day delay, 14-day grace. The `PqOnlyDisabledForMockVerifier` guard runs **only at `createVault`** (L625-627) and only for the mock's `algorithmId`; it does not protect existing vaults and does not fire for any non-mock permissive verifier (`Vault_vNext_Architecture.md` §8.3, "OBSERVED contrast") |
| Contract admin                                                                                  | `proposePolicyEngine` / `applyPolicyEngine` L1311-1347                                                                                                                  | **DENY**, selective or total (an always-denying engine), or disable enforcement (`address(0)` is valid, L1349-1353)                                                                                                                                                               | 2-day delay                                                                                                                                                                                                                                                                                                |
| Contract admin                                                                                  | `proposeLargeTxParams` / `applyLargeTxParams` L1256-1287                                                                                                                | **DELAY** any withdrawal above a threshold by an arbitrary `largeTxDelay`                                                                                                                                                                                                         | 2-day delay; no upper bound on the delay value                                                                                                                                                                                                                                                             |
| **`SanctionsListPolicy` owner** (admin-controlled by design, `SanctionsListPolicy.sol` L6-8)    | `addToSanctionsList`                                                                                                                                                    | **DENY** a recipient for every tenant, immediately                                                                                                                                                                                                                                | none                                                                                                                                                                                                                                                                                                       |
| **Attestor** (`AttestationPQCVerifier.attestor`, L42) — a WalletWall-operated off-chain service | signs `PQCAttestation`; `verify` returns true iff signed by `attestor` (L93-121)                                                                                        | For `PqOnly` vaults: **sole authenticator → MOVE_ASSETS and CHANGE_CREDENTIALS, instantly, no delay.** For `Hybrid`: conjunct only (ECDSA still required)                                                                                                                         | none for `PqOnly`; the attestor owner can also rotate the attestor instantly (`updateAttestor`, L52; hazard H-24)                                                                                                                                                                                          |
| **Vault-owner EOA** (the `vaults[]` mapping key)                                                | `createVault` L615, `setGuardians` L408, `cancelRecovery` L592, `setTreasuryQuorumThreshold` L1393, `finalizeWithdrawal` L947-950, `cancelPendingWithdrawal` L1078-1081 | lifecycle authority, **keyed on `msg.sender`**, not on a signature                                                                                                                                                                                                                | the key is **unrotatable** (it is the mapping key — hazard H-02). A compromised EOA can replace the guardian set and drive a delayed takeover (`Security_Assumptions.md` §4, "Residual owner-account risk")                                                                                                |
| **Signing credentials** (`ecdsaSigner`, `pqPublicKey`)                                          | `withdraw` L1105, `queueWithdrawal` L839, `rotateCredentials` L689                                                                                                      | MOVE_ASSETS, CHANGE_CREDENTIALS — **relayable** ("May be submitted by anyone", L1096)                                                                                                                                                                                             | per-owner nonce + deadline                                                                                                                                                                                                                                                                                 |
| **Guardian majority** (user-chosen)                                                             | `initiateRecovery` / `supportRecovery` / `executeRecovery` L463-586                                                                                                     | CHANGE_CREDENTIALS after 7 days → MOVE_ASSETS (accepted social-recovery residual)                                                                                                                                                                                                 | 7-day delay; owner cancel                                                                                                                                                                                                                                                                                  |
| **Anyone**                                                                                      | `depositFor` L818, `executeRecovery`, relaying `withdraw`/`queueWithdrawal`                                                                                             | inflow; relay of authorised actions                                                                                                                                                                                                                                               | —                                                                                                                                                                                                                                                                                                          |
| **Nobody**                                                                                      | —                                                                                                                                                                       | there is **no** admin sweep, no `rescue`, no upgrade proxy: the admin cannot call a function that moves a tenant's balance directly                                                                                                                                               | —                                                                                                                                                                                                                                                                                                          |

Two facts that are _good_ about Model A are recorded so they are not lost: the implementation is not
upgradeable, and no administrative function moves balances directly. They are necessary. They are not
sufficient, as §4 shows.

---

## 4. Why Model A fails the real-value test

### 4.1 One address holds everyone's asset (Q-A, Q-F)

A2 pulls every tenant's token into `address(this)` (`safeTransferFrom(msg.sender, address(this), amount)`,
A2 L705) and pays out from the same pool (`token.safeTransfer(recipient, amount)`, A2 L985). The per-user
`balance` is **internal accounting over a commingled pool**. Consequences:

- **USDC issuer blocklist blast radius is total.** The issuer (Circle) can blocklist _addresses_. If the
  pooled contract address is blocklisted — for whatever reason the issuer or an authority acts against
  one tenant's funds — **every tenant's USDC is frozen**, and no contract logic can undo it. Under Model B
  the same action freezes one clone.
- **A freeze aimed at one tenant cannot be isolated.** Any order or issuer action aimed at one user's
  funds lands on an address that holds everyone's. Under Model B it lands on an account whose only
  authority is that user's own credential.
- **No solvency invariant exists** (hazard H-25): nothing checks `token.balanceOf(this) >= Σ balance`. An
  accounting defect in a pool is a loss spread across tenants; in a per-vault account there is no second
  number to disagree with the first (`Vault_vNext_Architecture.md` §3.2 R2).
- **Unsolicited transfers are trapped forever.** A direct ERC-20 transfer to A2 is "NOT credited" (A2
  L45-46) and no path can ever move it. Under Model B the clone _is_ the owner of anything sent to it and
  can egress it (`egress(asset)`, B L1749-1776).

### 4.2 The operator holds an unbounded, cross-tenant freeze (Q-C)

`pause()` suspends every payout path **and recovery execution** for every tenant, with no expiry, no
budget and no second principal. The only live user action under pause is `cancelPendingWithdrawal`, which
returns the reservation to a balance that still cannot leave the contract. The architecture document
records the same observation as a correction to its own earlier text: recovery is "coupled to a
cross-tenant object one principal controls" (§3.3, Architecture A). A freeze the operator can impose on
all users indefinitely is an administrative-authority fact any reviewer will weigh regardless of what the
product is called.

### 4.3 The operator's asset-movement capability is a configuration, not a mechanism (Q-B, Q-E)

In `PqOnly` mode the ECDSA floor is off (`needEcdsa == false`) and **whatever the verifier accepts moves
the money**. The verifier is (i) swappable by the admin after a two-day delay, for every vault at once, and
(ii) in the attestation design, a contract that returns true for anything the WalletWall-operated attestor
signs. So:

- the **attestor key** — WalletWall infrastructure — can authorise withdrawals and credential rotations
  for every `PqOnly` vault with **no user signature and no delay**;
- the **admin key** can reach the same outcome for every `PqOnly` vault by installing a permissive
  verifier (`Vault_vNext_Architecture.md` §8.3 and §24.1 path D: minimum cut **1**);
- the only thing standing between users and this is that the `createVault` guard forbids `PqOnly` while
  the verifier is _the mock_. That is "a configuration accident rather than a mechanism" (§8.3).

The brief's requirement is that WalletWall "never possess a credential capable of independently
withdrawing user assets". Model A satisfies it only for users who happen to choose `Hybrid` or
`EcdsaOnly`. A property that depends on a per-vault mode flag cannot be stated as a property of the
system, and the brief explicitly forbids papering over it: _"If the legal classification depends
materially on contract architecture, do not paper over it with disclaimers. Change the architecture."_

### 4.4 Identity is `msg.sender`, so gas sponsorship cannot reach the lifecycle (Q-H)

`createVault` keys the vault to `msg.sender` (L620, L637); `setGuardians`, `cancelRecovery`,
`setTreasuryQuorumThreshold`, `finalizeWithdrawal` and `cancelPendingWithdrawal` all check `msg.sender`.
A relayer cannot perform any of them _for_ the user: a relayer that calls `createVault` creates **its own**
vault. A sponsored user therefore still needs ETH on Base to create, configure, finalize or cancel — the
exact dependency gas sponsorship exists to remove. Only `withdraw`, `queueWithdrawal` and `depositFor`
are relayable. The same `msg.sender` identity is **unrotatable** (H-02): after a credential rotation the
old EOA still administers guardians and finalization.

### 4.5 Global slots, one domain separator (Q-D)

`pqVerifier`, `policyEngine`, `largeTxThreshold`/`largeTxDelay` and `_paused` are **contract-level
storage shared by every tenant**: one admin action changes every tenant's authorisation semantics. Replay
separation between tenants rests on the signed `vaultOwner` field rather than on the EIP-712 domain,
which is identical for all tenants (hazard H-26; `Vault_vNext_Architecture.md` §3.2 R4).

### 4.6 The architecture lane already rejected it

`Vault_vNext_Architecture.md` §3.3 records **"Architecture A — retain the shared multi-tenant contract.
REJECTED"**, with the reasons above, and the owner has since **locked** the two decisions (D1 guardian
trust root, D8 immutable factory per generation) that make Architecture C the implementation contract.
This adjudication reaches the same verdict from the custody-and-control direction and adds §4.1's issuer-
blocklist blast radius and §4.4's sponsorship incompatibility, which that lane did not need to weigh.

### 4.7 Summary of the substance

Under Model A the value is held at **one address WalletWall deployed and administers**; WalletWall can
**stop every user from moving value indefinitely**; for a mode the contract lets users select, WalletWall's
attestor **can move the value**; and users are identified by an **internal ledger keyed on their EOA**.
Whatever label a reviewer attaches to that, it is not a system about which "WalletWall does not
independently control or possess user assets" can be stated as a fact.

---

## 5. Authority census — Model B (vNext kernel prototype at `b9fcd4d5`)

`VaultKernelPrototype.sol` contains **no occurrence of `msg.sender`** (verified by search at `b9fcd4d5`).
Every entrypoint authenticates a signature or a guardian quorum proof over an EIP-712 digest bound to
`block.chainid` and `address(this)` (L534-535), with one nonce domain per authority class and a deadline.

| Principal                                                                            | Entry points                                                                                                                                                          | Capability                                                                                                                                                                                | Bound                                                                                                                                    |
| ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Spending credential** (ECDSA floor; PQ conjunct only if `securityFloor.requirePq`) | `execute` L930, `rotateCredential` L994, `setVerifier` L1046, `setPolicy` L1177                                                                                       | MOVE_ASSETS, CHANGE_CREDENTIALS, CHANGE_RULES **for this vault only**                                                                                                                     | nonce + deadline; `requirePq` may never be silently disabled (`_requireNoDowngrade`, L735)                                               |
| **Guardian quorum** (user-chosen roster committed in the kernel)                     | `setGuardians` L1272, `initiateRecovery` L1388, `cancelRecoveryByQuorum` L1492, `enterContainment` L1602, `bindMigration` L1682 (**with** the credential, L1707-1709) | CHANGE_GUARDIANS, APPROVE_RECOVERY, CANCEL_RECOVERY, ENTER_CONTAINMENT, BIND_MIGRATION → after `RECOVERY_DELAY`, CHANGE_CREDENTIALS → MOVE_ASSETS (**declared, accepted trust root, D1**) | delays; `CHALLENGE_LIMIT` bounded credential veto                                                                                        |
| **Spending credential** (challenge)                                                  | `cancelRecovery` L1447                                                                                                                                                | bounded veto over a pending recovery                                                                                                                                                      | `CHALLENGE_LIMIT = 2` per epoch                                                                                                          |
| **Anyone**                                                                           | `deployVault` (factory L190), `executeRecovery` L1553 (of a quorum-approved, matured request), `retire` L1727, `egress` L1749                                         | relay; permissionless execution that carries **no discretion** (recipient fixed by the binding, amount = full balance)                                                                    | `genesisSalt` binds the complete genesis authority (L493-507), so a stranger deploying a user's configuration lands the same state       |
| **Emergency principal**                                                              | = the **guardian quorum** (`enterContainment` takes a `QuorumProof`)                                                                                                  | ENTER_CONTAINMENT only                                                                                                                                                                    | `CONTAINMENT_MAX = 3 days`, rolling budget 6 days per 30 (L259-261); re-entry no-op; wall-clock expiry; recovery and migration stay live |
| **Kernel admin**                                                                     | —                                                                                                                                                                     | **does not exist**                                                                                                                                                                        | —                                                                                                                                        |
| **Factory operator**                                                                 | —                                                                                                                                                                     | **none**: `implementation`, `generation`, `verifierAuthority` are `immutable` (factory L128-132); no `setImplementation`, no owner, no privileged role                                    | D8, locked                                                                                                                               |
| **Verifier**                                                                         | consulted by `_authorise` L678 only when `requirePq`                                                                                                                  | subtractive plane: Byzantine → downgrade to the ECDSA floor; unavailable → denial                                                                                                         | admission restricted to the generation's provenance root (`_requireAdmissibleVerifier`, L594)                                            |
| **Policy plane** (`IKernelPolicy.admit`)                                             | consulted in `execute` L965-968 only if set                                                                                                                           | subtractive: may only refuse                                                                                                                                                              | user-settable; `address(0)` = kernel floor                                                                                               |
| **WalletWall infrastructure**                                                        | —                                                                                                                                                                     | **none**                                                                                                                                                                                  | architecture goal G5                                                                                                                     |

Properties that follow, each OBSERVED in code:

- **Assets are held by the vault's own address.** `receive()` L521; `execute` pays from `address(this)`
  (L971); `egress` moves `address(this).balance` or `balanceOf(address(this))` (L1757-1773). There is no
  ledger, no pool, no second number.
- **No freeze principal outside the user's own constituency.** Containment is bounded, self-expiring,
  budgeted, and triggered only by the user's guardians. Spending denial has a cut of 1 only through planes
  the _user_ installed, and migration egress stays open from every state including `RETIRED`
  (`Vault_vNext_Architecture.md` §6, §24.2).
- **The rules cannot be changed for a vault by anyone but its own principals**, and the implementation
  cannot be changed at all (EIP-1167 immediate operand; §3.1).
- **Every action is relayable.** A relayer that pays gas changes nothing about _who authorised_ the action.

---

## 6. Fit against the brief's required properties

| Brief requirement                                                              | Model A                                                                                       | Model B (vNext C2)                                                                                                                                                                   |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| each Vault directly holds its own admitted asset                               | ✗ pooled, internal ledger                                                                     | ✓ clone holds it (ETH today; **USDC needs the new spend plane, §7.1**)                                                                                                               |
| WalletWall has no unilateral `MOVE_ASSETS` capability                          | ✗ attestor / admin for `PqOnly`; mode-dependent                                               | ✓ no WalletWall principal exists                                                                                                                                                     |
| implementations immutable; migration requires user-bound authority             | ✓ not upgradeable / ✗ verifier, policy, params are admin-swappable globally                   | ✓ immutable clone + immutable factory; `bindMigration` = quorum **and** credential (D2)                                                                                              |
| relayer failure cannot trap assets                                             | ✗ lifecycle is `msg.sender`-keyed; a sponsored user without ETH is stuck                      | ✓ every entrypoint permissionless; the user or any third party can submit                                                                                                            |
| RPC failure cannot trap assets                                                 | ✓/✗ no RPC is in the contract, but see relayer row                                            | ✓ no RPC is in the contract; any provider or a self-run node works; sequencer bypass via L1 forced inclusion is a documented Base property (gate SG-04)                              |
| billing failure cannot trap assets                                             | ✓ billing is not on-chain                                                                     | ✓ billing is not on-chain and is never an authorisation input                                                                                                                        |
| WalletWall company failure does not destroy the exit path                      | ✗ pause + lost admin key = permanent freeze; attestor loss strands `PqOnly`/`Hybrid` spending | ✓ **conditional**: no WalletWall-operated attestor on the spend path (hence `requirePq=false` in v1, §7.2) **and** the §15 artifact set published and exercised (gates PG-15, SG-03) |
| administrative pause/governance powers minimised and explicitly modelled       | ✗ unbounded pause; global governance slots                                                    | ✓ no admin; containment by the user's guardians, bounded by `B < W`; authority graph published (§8)                                                                                  |
| RPC providers replaceable without contract change, migration or new signatures | ✓                                                                                             | ✓ (no provider identity anywhere on-chain)                                                                                                                                           |

---

## 7. What vNext does NOT yet give — the production-asset generation

Each item below is **new work for a new kernel generation**, following the four-step generation act in
`Vault_vNext_Architecture.md` §22 D8 (deploy kernel, deploy factory bound to it, publish evidence, explicit
per-user migration). None of it is a patch to the prototype's measured bytes, and none of it is a change
to `contracts/`.

### 7.1 Admitted-asset ERC-20 spend plane (REQUIRED)

- `execute` today moves native value only (`recipient.call{value: amount}`, L971). The production
  generation needs an `execute` whose transfer is `IERC20(admittedAsset).transfer(recipient, amount)`,
  with settlement judged on an **observed balance decrease** exactly as `egress` already does
  (`I-NO-FALSE-SETTLEMENT`, L1764-1772), never on "the call did not revert".
- The **admitted asset address must be bound into the clone's immutable args** (C2), beside `generation`
  and `verifierAuthority` (factory `_args`, L212-214), and read back from the clone's own code. That makes
  "this vault moves only native Base USDC" a **code-identity fact verifiable offline** from `eth_getCode`,
  not a storage value and not a registry claim. Native ETH then arrives only as unsolicited value and
  leaves only through `egress(address(0))`.
- The brief's "no generic ERC-20 custody in v1" is satisfied structurally: one asset per generation, pinned.
  Anything else that lands on the clone is reachable only by migration egress.
- **Issuer controls are external.** If the issuer blocklists a clone or a recipient, `transfer` reverts, the
  whole `execute` reverts (no nonce consumed), and no WalletWall action can change that. The product
  disclosure must say so (gate PG-13).

### 7.2 Floor for v1: `requirePq = false` (REQUIRED for the operational-independence goal)

- The prototype's `_requireSaneFloor` and `initialize` accept a genesis with `requirePq == false`
  (L478-480, L409). `_authorise` then returns after the ECDSA floor (L651-654) and the verifier is never
  consulted on a spend.
- With `requirePq == true` the only Generation-1-admissible verifier class is
  `ImmutableAttestationPQCVerifier`, whose attestor is an **off-chain WalletWall-operated service**
  (architecture blocker **B-5**, hazard **H-17**). On the spend path that is a WalletWall **liveness**
  dependency (never a loss path — the ECDSA floor is evaluated first), which violates goal **G5** and the
  brief's "WalletWall company failure does not destroy the user's cryptographic exit path".
- Therefore the real-value generation ships with an **ECDSA floor only** (secp256k1 is a declared accepted
  trust root, §2.2 item 5). The `false → true` arming edge stays available to the user later, one-way.
  **Consequence for marketing:** no "quantum" claim of any kind can attach to the v1 product, which the
  brief independently requires.
- Design question for the implementation lane: whether a generation may accept a null verifier when
  `requirePq == false` (today `initialize` demands an admissible, code-bearing verifier, L397-402). Keeping
  the admission root bound costs nothing in authority; dropping it saves bytes. Measure, then decide.

### 7.3 Constants (OPEN — owner decisions, architecture B-3)

`RECOVERY_DELAY`, `RECOVERY_EXPIRY`, `BIND_DELAY`, `CONTAINMENT_MAX`, `CONTAINMENT_WINDOW`,
`CONTAINMENT_BUDGET`, `CHALLENGE_LIMIT` are "illustrative values for a measurement prototype" (L253-262).
Production values are product/risk decisions. Note that on Base these clocks run on **L2 block
timestamps set by the sequencer**; delays must be sized with that in mind (relayer threat model T-11).

### 7.4 WalletWall's on-chain footprint: none in v1 (RECOMMENDED)

- **No guardian seat by default.** A WalletWall-held seat is an additional authorization key; `k` seats is
  total control. Rule for any later offering: WalletWall seats **< threshold**, enforced by the product
  flow and disclosed. v1: zero seats, so WalletWall's authority closure over every vault is literally empty.
- **No emergency key.** Containment is already the guardian quorum's.
- **No on-chain policy plane operated by WalletWall.** Sanctions screening happens **at the relayer, at
  execution** (relayer threat model §6). A WalletWall-owned `SanctionsListPolicy`-style plane would be a
  selective-deny lever over opted-in users; it is subtractive and user-escapable, but it is also a
  WalletWall principal, and v1 does not need one.

### 7.5 Artifacts the company-disappearance requirement needs (architecture §15, all PROPOSED)

EIP-712 typed-message schemas with domain derivation; deployment registry (factory, implementation, chain
id, admitted asset); runtime code hashes with the EIP-1167 derivation; a network-free reference CLI; a
written recovery procedure; the migration specification. Each is a production gate (PG-15, SG-03).

### 7.6 Assurance (architecture §25.5)

No audit, no formal verification; the prototype has a stateful fuzz campaign and mutation evidence but
calls itself a measurement prototype. The byte budget must be re-measured after the ERC-20 plane is added:
`prototype/vnext-kernel/MEASUREMENTS.json` records the kernel at **18,331 bytes** of runtime with **0**
immutable slots against a `TARGET_KERNEL_CEILING` of **21,976** (headroom 3,645; verdict `TARGET PASS`),
and the architecture's stop condition is **600 bytes** of headroom (`Vault_vNext_Architecture.md` §19.2).

---

## 8. Attacks on the Model B verdict that still stand (dissent, recorded)

| #   | Objection                                                                                           | Standing                                                                                                                                                                                                                                                                                                                           |
| --- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D-1 | **"A clone is still WalletWall's code."** Authorship could be argued as control.                    | Partly. Immutability plus the five-link offline verification chain (§15.1) is what lets a user rely on _code_ rather than on _WalletWall_; whether authorship of immutable code counts as control is a question for qualified legal review (`LEGAL_REVIEW_REQUIRED`). The design makes the factual record checkable, nothing more. |
| D-2 | **The relayer's own transaction is what moves the user's value**, even though it never holds value. | Stands as a characterisation question; `LEGAL_REVIEW_REQUIRED`. Technically the relayer adds no authority, cannot alter the payload, and is one of arbitrarily many possible submitters; the user can always self-submit.                                                                                                          |
| D-3 | **A user without any ETH depends on _some_ relayer.**                                               | True. It is a **liveness** dependency, not custody, and it is why the gates require an honest disclosure of sponsorship limits and a documented self-submission path. Third-party relayers are possible because nothing in the kernel names WalletWall.                                                                            |
| D-4 | **The generation publisher can mis-advertise a factory** (H-32).                                    | Residual, cohort-scoped to _future_ vaults; bounded by offline verification and the published registry.                                                                                                                                                                                                                            |
| D-5 | **The issuer can freeze a clone.**                                                                  | External asset risk no architecture removes; it is why USDC is the only admitted asset and why the disclosure gate exists. A frozen clone cannot egress its USDC.                                                                                                                                                                  |
| D-6 | **Kernel defects are permanent.**                                                                   | Accepted with open eyes (§2.2 item 1, §20 item 2); migration egress is the designed exit; independent audit is a hard gate.                                                                                                                                                                                                        |
| D-7 | **Guardian quorum reaches assets.**                                                                 | Declared trust root (D1, locked). Must never be marketed as "even a malicious majority cannot…" (§22 D1).                                                                                                                                                                                                                          |

---

## 9. Disposition of existing contracts

| Contract                       | Disposition                                                                                                                                                                                                                                                |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WalletWallVault.sol`          | stays a research/testnet prototype. **Not** a base for real value.                                                                                                                                                                                         |
| `StablecoinVaultSimulator.sol` | stays a testnet rehearsal. **Must never** be deployed to Base Mainnet, pointed at real USDC, or renamed into a production contract. Its deploy script's mainnet refusal (`scripts/deploy-simulator.ts`, `FORBIDDEN_MAINNET_CHAIN_IDS` incl. `8453`) stays. |
| `WalletWallMultiSigVault.sol`  | research prototype; Model A with no recovery path; not a base for real value.                                                                                                                                                                              |
| `prototype/vnext-kernel/*`     | the **basis** for the production-asset generation; itself never deployed.                                                                                                                                                                                  |
| Repository real-funds warnings | **unchanged** by this lane.                                                                                                                                                                                                                                |

---

## 10. Decisions this lane cannot make (owner)

1. Pin the admitted asset in immutable args (recommended: **yes**; alternative: storage, rejected because
   a storage value is an OBSERVATION, not a PROOF, §15.2).
2. Ship v1 with `requirePq = false` (recommended: **yes**; alternative: Hybrid with a WalletWall attestor,
   rejected under G5).
3. WalletWall guardian seats in v1 (recommended: **none**).
4. Production constants (§7.3).
5. Chain scope: **Base Mainnet (8453) only** in v1 (recommended; the relayer's chain allowlist and the
   EIP-712 domain both pin it).
6. Whether the new generation accepts a null verifier when `requirePq == false` (measure first).

---

## 11. Evidence index

- Contracts at `b9fcd4d5`: `contracts/WalletWallVault.sol` (lines cited above), `contracts/StablecoinVaultSimulator.sol`,
  `contracts/WalletWallMultiSigVault.sol`, `contracts/verifiers/AttestationPQCVerifier.sol`,
  `contracts/policies/SanctionsListPolicy.sol`, `prototype/vnext-kernel/contracts/VaultKernelPrototype.sol`,
  `prototype/vnext-kernel/contracts/VaultKernelFactoryPrototype.sol`.
- Architecture: `docs/Vault_vNext_Architecture.md` §3 (verdict C), §3.3 (A rejected), §5, §6, §8.1-8.3, §9,
  §14, §15, §19.2, §20, §22 (D1, D2, D4, D5, D8), §24, §25.5 (B-1..B-6);
  `prototype/vnext-kernel/KERNEL_ADMISSION.md`; `docs/Vault_vNext_Hazard_Register.md` H-02, H-05, H-06, H-07,
  H-15, H-17, H-22, H-24, H-25, H-26, H-28, H-32.
- Executable evidence added by this lane: `test/BaseMainnetCustodyAdjudication.test.ts` pins §4 against
  `StablecoinVaultSimulator` on a local Hardhat network, each attack paired with a positive control:
  **E-1** the admin's pause freezes every tenant's spend and a matured recovery for a year with no bound
  while the tokens stay pooled (§4.2); **E-2** the attestor alone moves a `PqOnly` tenant's tokens with no
  tenant signature, while a `Hybrid` tenant is protected only by the ECDSA conjunct (§4.3); **E-3** the
  lifecycle entrypoints refuse a relayer and `createVault` by a relayer creates the relayer's own vault,
  while `withdraw`/`queueWithdrawal` relay (§4.4); **E-4** one pooled balance, an uncredited direct transfer
  no entrypoint can move (§4.1). It deploys nothing and authorises nothing for real value.
- Pre-existing executable evidence: `test/WalletWallVault.test.ts` ("PqOnly: succeeds with only a PQ
  signature against a non-mock verifier") pins the sole-authenticator fact of §4.3 for the ETH vault; the
  prototype's authority census (`prototype/vnext-kernel/AUTHORITY_CENSUS.json`) and stateful campaign pin §5.
- Companion documents: [BASE_MAINNET_GAS_RELAYER_THREAT_MODEL.md](BASE_MAINNET_GAS_RELAYER_THREAT_MODEL.md),
  [BASE_MAINNET_PRODUCTION_GATES.md](BASE_MAINNET_PRODUCTION_GATES.md).
