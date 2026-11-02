# Base Mainnet Gas Relayer — threat model

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> This document models a **proposed** WalletWall-operated transaction relayer for a **proposed** real-value
> vault generation. No relayer exists, no production relayer secrets exist, nothing is deployed, and there
> is no mainnet write path in this repository. The repository does not custody user funds, does not process
> production withdrawals, and produces no real yield.
>
> Engineering design input, not legal advice. Legal and compliance questions are **gated**
> (`LEGAL_REVIEW_REQUIRED`) in [BASE_MAINNET_PRODUCTION_GATES.md](BASE_MAINNET_PRODUCTION_GATES.md), not
> answered here.

Companion: [BASE_MAINNET_CUSTODY_ADJUDICATION.md](BASE_MAINNET_CUSTODY_ADJUDICATION.md) establishes that
under the vNext C2 topology the relayer is an _arbitrary external caller_ with **no** authority over any
vault. This document asks what can still go wrong with such a caller, and what bounds it.

---

## 0. The model in one picture

```
User signs an authorized Vault action (EIP-712, bound to chain 8453, the vault address, a nonce domain, a deadline)
        │
        ▼
WalletWall service: verifies the signature decodes to the stated action; checks sponsorship eligibility
(subscription state from the off-chain billing provider); screens the parties (sanctions, jurisdiction);
simulates; applies the bounds in §4
        │
        ▼
WalletWall relayer: wraps the user's calldata in a Base transaction
        │  spends WalletWall-owned ETH only
        ▼
generic Ethereum JSON-RPC (any provider, or a self-run node)
        │
        ▼
Base Mainnet (sequencer; or L1 forced inclusion if the user bypasses the sequencer themselves)
        │
        ▼
per-user WalletWall Vault (an EIP-1167 clone that holds its own assets)
        │
        ▼
native Base USDC (the single admitted asset, bound into the vault's code)
```

**What the relayer is:** a payer of gas and a submitter of other people's authorizations.
**What the relayer is not:** a signer of vault actions, a holder of user assets or credentials, a guardian,
an attestor, a policy plane, an emergency principal, a party required for recovery or exit, or an
authorization input of any kind.

**What the stack does not contain, by design:** no ERC-4337, no bundler, no paymaster, no EIP-7702, no
vendor-specific gas or wallet API, no wallet SDK dependency, no protocol-level billing dependency, no prepaid
gas token, no transferable gas credit, no user-owned ETH ledger inside WalletWall. Billing (optionally
Stripe) is off-chain infrastructure outside the Vault security boundary.

---

## 1. Assets and the protection ranking

| Rank | Asset                                  | Required property                                                                                                                                                                                             |
| ---- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **User vault assets (USDC in clones)** | **Unreachable** by the relayer, its operators, or anyone who compromises them. This is a property of the kernel (custody adjudication §5), _not_ of the relayer; the relayer must never acquire a path to it. |
| 2    | **User authorization liveness**        | A dead, hostile or compromised relayer can delay a user, never trap them: every entrypoint is permissionless, so the user or any third party can submit.                                                      |
| 3    | **WalletWall operating ETH**           | Bounded loss under any single failure (key theft, griefing, gas spike).                                                                                                                                       |
| 4    | **Relayer signing keys**               | Compromise yields rank-3 loss and griefing, never rank-1 loss.                                                                                                                                                |
| 5    | **Compliance evidence**                | Screening decisions and relayed-transaction records are complete, tamper-evident and retained for the period the compliance review sets.                                                                      |
| 6    | **User data**                          | Minimum collected; nothing retained longer than a documented purpose requires.                                                                                                                                |

---

## 2. Principals and trust

| Principal                                      | Trusted for                                                                    | NOT trusted for                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| User's spending credential (and guardians)     | authorising vault actions                                                      | nothing else                                                                                          |
| WalletWall relayer key(s)                      | spending WalletWall ETH; choosing which authorized payloads to submit and when | any vault authority; it holds none                                                                    |
| WalletWall operators                           | configuring bounds, refilling the hot wallet, halting                          | any vault authority                                                                                   |
| RPC providers (replaceable, ≥ 2)               | transporting JSON-RPC                                                          | truthfulness of any single answer; availability                                                       |
| Base sequencer                                 | ordering and including L2 transactions                                         | censorship resistance (the user's remedy is L1 forced inclusion); liveness                            |
| USDC issuer (Circle)                           | honouring `transfer` for non-blocklisted parties                               | not freezing: it can blocklist addresses under its own policy and legal process — external asset risk |
| Off-chain billing provider (optionally Stripe) | billing truth                                                                  | any authorization role; its state only decides whether WalletWall _pays_                              |
| The kernel generation (immutable code)         | enforcing authorization                                                        | being bug-free (audit gate)                                                                           |

---

## 3. Relayer authority — the complete list

| The relayer CAN                                                                   | The relayer CANNOT (kernel property; cite)                                                                                                    |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| spend its own ETH on gas                                                          | move any USDC: `execute` requires the user's signature over `(recipient, amount, nonce, deadline)` (`VaultKernelPrototype.sol` L942-950)      |
| decide which authorized payloads to submit, and when (within the user's deadline) | alter a payload: any change invalidates the signature                                                                                         |
| refuse to relay (and must, for sanctions)                                         | block a user from acting through another submitter: no entrypoint checks `msg.sender`                                                         |
| front-run or delay a submission                                                   | pause, freeze or contain a vault: containment needs a guardian `QuorumProof` (L1602-1614)                                                     |
| deploy a vault for a user (`deployVault`)                                         | choose that vault's authority: the salt binds the complete genesis configuration (L493-507); a different configuration is a different address |
| execute permissionless steps (`executeRecovery`, `egress`, `retire`)              | add discretion to them: recipient and amount are fixed by the kernel state they act on                                                        |
| observe calldata and timing (metadata)                                            | learn private keys or sign on anyone's behalf                                                                                                 |

Every "cannot" is a claim about the **kernel generation**, re-verified at deployment by the authority census
(gate PG-02). If any future kernel change gives `msg.sender` a role, this table is void and the design
must be re-adjudicated.

---

## 4. Bounding controls (the brief's list, made concrete)

| Control                                     | Specification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Fails how                                            |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| **B-1 Chain allowlist**                     | Exactly `8453` (Base Mainnet). `eth_chainId` checked at startup and before every batch; transactions signed EIP-155 with `chainId = 8453`; the vault's EIP-712 domain independently binds `block.chainid`. Base Sepolia `84532` only in a separately configured non-production relayer.                                                                                                                                                                                                                                         | closed: mismatch halts relaying                      |
| **B-2 Contract allowlist by code identity** | A target is admissible iff (a) it is the generation's factory address from the signed deployment registry, or (b) `eth_getCode(target)` is **byte-exactly** the EIP-1167 template plus the generation's immutable-args length, the embedded implementation address hashes (`eth_getCode`) to the published generation runtime hash, and the args decode to the expected generation, verifier root and **admitted asset**. Never a registry lookup alone (`I-CODE-IDENTITY-LINKAGE`, `I-CLONE-BYTES-EXACT`, architecture §15.1). | closed: unknown code is refused                      |
| **B-3 Selector allowlist**                  | Per target type: factory → `deployVault`; clone → the exact typed entrypoints the product sponsors (v1 proposal: `execute`, `rotateCredential`, `setGuardians`, `initiateRecovery`, `cancelRecovery`, `cancelRecoveryByQuorum`, `executeRecovery`, `enterContainment`, `bindMigration`, `retire`, `egress`). No raw calldata path exists.                                                                                                                                                                                       | closed                                               |
| **B-4 Payload validation**                  | Decode against the generation ABI; deadline inside `[now + minLead, now + maxWindow]`; nonce equals the on-chain domain nonce (`eth_call nonces(domain)`); recipient/destination/guardian addresses screened (§6).                                                                                                                                                                                                                                                                                                              | closed                                               |
| **B-5 Simulation before spend**             | `eth_call` + `eth_estimateGas` against `pending`; a reverting payload is never paid for. A payload that passes simulation and later reverts (nonce consumed by another submitter) is an accepted bounded loss counted toward B-8.                                                                                                                                                                                                                                                                                               | bounded                                              |
| **B-6 Gas ceiling**                         | Per-selector gas limit cap (hard max, and ≤ 1.25 × estimate); `maxFeePerGas` and `maxPriorityFeePerGas` caps; Base **L1 data fee** component estimated through the OP Stack `GasPriceOracle` predeploy (`getL1Fee` / `getL1FeeUpperBound`) via ordinary `eth_call` and included in the per-operation ETH ceiling. An operation above the published ceiling is **deferred or refused**, never sponsored at a loss; the user may self-submit.                                                                                     | closed                                               |
| **B-7 Rate limits**                         | Per account per period: **published counts** (plan limits); per account burst limit; global operations-per-minute; anomaly trip (failure-rate, revert-rate, gas-per-op drift).                                                                                                                                                                                                                                                                                                                                                  | closed                                               |
| **B-8 Circuit breakers**                    | ETH spent per hour and per day caps; hot-wallet **floor** below which sponsorship pauses ("sponsorship unavailable"); treasury ceiling (hot wallet holds ≤ N days of expected spend); automatic halt on `eth_chainId` change, RPC disagreement, reconciliation mismatch (B-15), or signature-verification failure spikes.                                                                                                                                                                                                       | closed to WalletWall loss; **denial only** for users |
| **B-9 Kill switch**                         | Operators can stop relaying instantly. Its only effect is denial of sponsorship. It touches no vault.                                                                                                                                                                                                                                                                                                                                                                                                                           | denial only                                          |
| **B-10 Nonce manager**                      | One relayer key = one sequential nonce stream (or a small pool of keys, each independent). Stuck transactions are replaced **with the same payload** and a fee bump within B-6; never with a different payload.                                                                                                                                                                                                                                                                                                                 | bounded                                              |
| **B-11 Receipt verification**               | A relayed transaction is reported to the user as `included` only when ≥ 2 independent RPC providers (or one self-run node plus one provider) agree on `status`, `blockHash` and logs; `safe`/`finalized` block tags are surfaced separately. The UI never treats "sent" as "done".                                                                                                                                                                                                                                              | closed to false success                              |
| **B-12 Provider replaceability**            | Only standard JSON-RPC methods: `eth_chainId`, `eth_getCode`, `eth_call`, `eth_estimateGas`, `eth_feeHistory`, `eth_maxPriorityFeePerGas`, `eth_getTransactionCount`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_getLogs`. Provider URLs are configuration. No vendor SDK, no vendor gas API, no account-abstraction stack (no ERC-4337, no paymaster, no bundler, no EIP-7702). Swapping a provider changes **no** contract, signature, or semantics.                                 | —                                                    |
| **B-13 Transaction-value constraints**      | Published per-operation and per-period **value ceilings for sponsored operations** (the USDC amount an `execute` moves, the number of guardian or migration actions per period). These bound WalletWall's exposure to abuse of its sponsorship; they are not a spending policy over user funds — above the ceiling the user self-submits with own gas and the vault enforces nothing different.                                                                                                                                 | closed to WalletWall exposure; denial only for users |
| **B-14 Replay / idempotency**               | Every relay request is keyed by the EIP-712 digest it carries (which commits to nonce and deadline); the relayer never submits the same digest twice, never resubmits a digest whose nonce is already consumed on-chain, and deduplicates across relayer instances through a shared store. A client retry returns the existing submission's status.                                                                                                                                                                             | closed                                               |
| **B-15 Reconciliation**                     | For every relayed operation: submitted transaction → mined receipt → `gasUsed`, effective gas price, L1 fee → ETH actually spent → ledger entry; nightly totals reconciled against relayer-wallet balance movements. Any unexplained difference trips B-8.                                                                                                                                                                                                                                                                      | closed to silent loss                                |

---

## 5. Threat catalog

Severity is for the **user**; WalletWall-only loss is marked `WW`.

| Id   | Threat                                                                                                          | Impact                                                                                        | Mitigation                                                                                                                                                                 | Residual                                          |
| ---- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| T-01 | **Relayer key compromise**                                                                                      | `WW` ETH drained as gas; griefing (front-running, delaying, burning sponsored quota)          | B-6, B-8 (hot wallet ceiling), key in HSM/KMS, rotation runbook (gate PG-14); vault authority unaffected by construction                                                   | bounded `WW` loss; users self-submit              |
| T-02 | **Malicious insider / hostile operator**                                                                        | selective refusal (denial); metadata misuse                                                   | B-9 is denial-only; audit logs of every decision; the kernel gives insiders no asset path; disclosure that WalletWall may refuse and that self-submission always exists    | denial; privacy (§8)                              |
| T-03 | **RPC provider lies** (fake receipt, fake nonce, fake code)                                                     | false success shown; wasted gas; wrong screening inputs                                       | B-11 cross-provider agreement; B-2 code identity from ≥ 2 providers; prefer a self-run node for `eth_getCode`                                                              | bounded                                           |
| T-04 | **RPC provider censors or is down**                                                                             | sponsorship stalls                                                                            | provider failover (B-12); self-submission; nothing on-chain depends on any provider                                                                                        | denial                                            |
| T-05 | **Payload injection** (target is not a genuine clone; a look-alike proxy with extra dispatch; wrong generation) | relayer pays for an attacker's call; could be an approval or transfer in an attacker contract | B-2 byte-exact clone check and implementation hash; B-3 selectors; the relayer only ever calls allowlisted code                                                            | closed                                            |
| T-06 | **Gas griefing** (reverting payloads; payloads that pass simulation then revert; max-gas payloads)              | `WW` ETH waste                                                                                | B-5, B-6, B-7, B-8 trip on revert-rate                                                                                                                                     | bounded `WW`                                      |
| T-07 | **Nonce/deadline races** (user or a third party submits the same payload first)                                 | relayer tx reverts, gas lost; user action already done                                        | B-5 at `pending`; B-14 idempotency (do not count a reverted relay against the user's quota); B-8                                                                           | bounded `WW`                                      |
| T-08 | **Front-running `deployVault`**                                                                                 | none to authority (salt binds genesis; same address, same state — factory NatSpec L161-177)   | —                                                                                                                                                                          | harmless                                          |
| T-09 | **Sanctions exposure** (relaying for a screened vault owner, recipient, guardian or destination)                | WalletWall's own transaction facilitates a prohibited transfer                                | §6: screening at **execution**, refusal, evidence retention, re-screen policy; never a WalletWall-held asset                                                               | exact duties `LEGAL_REVIEW_REQUIRED` (gate PG-09) |
| T-10 | **Billing-provider webhook spoofing / replay / state drift**                                                    | wrong sponsorship decision (free rides, or wrongful refusal)                                  | signature verification, idempotent event ledger, fetch-before-project; **billing state is never an authorization input** (invariant R-5)                                   | `WW` billing loss or denial only                  |
| T-11 | **L2 timestamp / ordering latitude of the sequencer**                                                           | a deadline judged slightly differently than wall clock; delays                                | deadlines carry generous windows; recovery/containment clocks are sized for L2 timestamps (custody §7.3)                                                                   | accepted                                          |
| T-12 | **Sequencer outage or censorship**                                                                              | relayer cannot land anything                                                                  | denial only; users may use **L1 forced inclusion** (OP Stack deposit transaction) with their own L1 ETH — a documented Base property, disclosed as the remedy (gate SG-04) | accepted; sponsorship cannot cover L1             |
| T-13 | **Gas-price spike**                                                                                             | sponsorship becomes uneconomic                                                                | B-6 ceiling → defer/refuse; published; users may self-submit                                                                                                               | denial                                            |
| T-14 | **USD price source manipulation** (for accounting records)                                                      | wrong accounting                                                                              | records only; pinned reputable source with timestamp; method chosen by the CPA (§9)                                                                                        | accounting                                        |
| T-15 | **Metadata leakage** (IP ↔ vault address ↔ account)                                                             | privacy harm                                                                                  | data minimisation (§8): raw IP not retained beyond the screening window; jurisdiction _decision_ retained, not the IP                                                      | residual                                          |
| T-16 | **UI trusts the relayer as oracle of truth**                                                                    | user believes a transfer happened                                                             | B-11; UI reads chain state, not relayer state                                                                                                                              | closed                                            |
| T-17 | **Replayable attestation** (`AttestationPQCVerifier` payloads are bearer tokens until `deadline`)               | re-authorise the same digest                                                                  | **not in v1**: `requirePq = false` (custody §7.2); if ever enabled, short deadlines + kernel nonce                                                                         | n/a in v1                                         |
| T-18 | **Supply-chain compromise of relayer software**                                                                 | arbitrary behaviour within B-* bounds                                                         | pinned, reproducible dependencies; bounds enforced in a separate process from payload intake; HSM holds keys                                                               | bounded                                           |
| T-19 | **Relayer treated as a guardian / attestor / emergency key**                                                    | would convert a payer into an authority                                                       | invariant R-3: relayer keys are **never** enrolled in any vault role; checked by the authority census at every release                                                     | closed by policy + census                         |
| T-20 | **Sponsorship quota becomes stored value** (balances, top-ups, transfers, redemption)                           | changes the product's nature                                                                  | §7; STOP condition (gate ST-01)                                                                                                                                            | STOP                                              |

---

## 6. Sanctions screening at execution — minimum viable control

The relayer's own transaction is **WalletWall's act**, so the design screens every relay regardless of custody
status, not only at signup, and refusal is the control. Which sanctions duties attach to the service is
`LEGAL_REVIEW_REQUIRED` (gate PG-09); the design assumes the strict case. It keeps WalletWall out of the
identity-collection business: it screens **addresses and jurisdiction**, not identities.

1. **Inputs screened per operation:** the vault address; the recovered signer address; every recipient,
   destination, guardian or proposed signer the payload names; for `deployVault`, the genesis signer and
   guardians.
2. **Lists:** the official U.S. sanctions lists' digital-currency address identifiers (the same EVM
   addresses apply on Base), refreshed on every list update, plus any list the compliance review
   requires; optionally a replaceable blockchain-analytics provider (never the sole source; its vendor must
   be swappable without product change).
3. **Jurisdiction:** restricted jurisdictions, as determined by the compliance review, are refused at
   account and at execution time using IP geolocation and declared country; VPN/proxy signals are a risk
   flag, not a verdict. No passport, no identity document is collected for this purpose. The geo-fence
   covers **every** WalletWall touchpoint — app access, customer support, documentation — not only the
   relay call, and geo-blocking is tested continuously so that a silently broken block is detected.
4. **Decision:** `ALLOW` → relay; `REFUSE` → do not relay, no WalletWall transaction, record the decision;
   the user keeps every on-chain ability (the kernel is permissionless) — WalletWall simply does not act.
5. **False positives:** a refusal shows the reason class (not the list entry) and a review path; review
   overrides are logged with reviewer identity; the list version that produced the hit is retained.
6. **Lookback / re-screen:** on every list update, re-screen the set of addresses WalletWall has relayed for
   in the retention window; hits are escalated under the compliance procedure, and any reporting decision is
   `LEGAL_REVIEW_REQUIRED`.
7. **Screened after deposit:** if a vault owner, or the vault address, becomes a screening hit after USDC is
   in the vault: WalletWall stops relaying for it; the issuer may blocklist it independently; WalletWall
   never had, and does not acquire, control of the funds. Any reporting obligation is determined by the
   compliance review (`LEGAL_REVIEW_REQUIRED`).
8. **Evidence retained per decision:** timestamp, chain id, vault address, screened addresses, list
   identifiers and versions, jurisdiction decision (not raw IP after the screening window), decision,
   reviewer (if any), relayer transaction id and hash (if relayed).

What this control does **not** claim: that sanctions obligations do not apply to a noncustodial service; that
a refusal "blocks" anything on-chain; that address screening catches a counterparty using a fresh address.
Those limits are stated in the disclosures.

---

## 7. The stored-value boundary — how sponsorship is expressed

Allowed shapes (either, or both):

```
Plan: $29 / month. Includes up to N sponsored vault operations per month,
each up to G gas and up to F ETH-equivalent network fee at the time of relay.
Unused operations do not roll over, are not refundable, and are not transferable.
```

```
Transparent billing in arrears: operations beyond the plan are billed at the end of the
period at a published per-operation price, through the billing provider, as a software-service charge.
```

Forbidden shapes — each is a **STOP condition** (gate ST-01) requiring qualified legal review before any
design work:

- a user-visible **balance** denominated in dollars, ETH or "gas" that decreases as the user acts;
- **prepaid top-ups**, deposits "into your gas wallet", or any purchase whose consideration is a future
  network-fee payment held for the user;
- **transferable**, **convertible**, **redeemable** or **refundable-as-value** credits;
- any promise that a billing payment represents ownership of specific ETH;
- WalletWall converting a user's fiat into ETH **for** the user;
- any user-owned ETH ledger inside WalletWall.

These shapes are architectural requirements: the user buys **software and a service** (relaying); the ETH is
WalletWall's property before and after, and the product must never create a user claim on it. WalletWall's
product rule applies unchanged: every account limit is a **published count**, never a hidden dollar budget.

---

## 8. Records and data minimisation

**Per relayed operation (compliance record):** timestamp; chain id (8453); vault address; selector; relayer
transaction hash; inclusion block; status; gas used; effective gas price; L1 fee; ETH spent; screening
result and list versions; jurisdiction decision; pseudonymous account id.

**Not retained beyond the screening window:** raw IP addresses, device fingerprints, geolocation
coordinates. The _decision_ is kept; the inputs that identify a person are not.

**Retention:** the compliance record for the period the compliance review sets (`LEGAL_REVIEW_REQUIRED`); the
design must not hard-code a maximum shorter than that period, whatever it turns out to be. Tax records are kept
for the longer of the tax retention period and the compliance period. A written schedule with deletion jobs
is gate PG-13.

**Personal data:** wallet addresses linked to an account, and IP-derived data, are treated as personal data
under applicable privacy law (applicability `LEGAL_REVIEW_REQUIRED`, gate SG-08). The billing provider
retains payment identity; WalletWall does not copy it.

---

## 9. Tax and accounting records (for the CPA, not implemented by the relayer's logic)

Every gas spend is a use of WalletWall-owned ETH. The relayer **records**; it decides nothing about
treatment:

- **ETH acquisition:** date, amount, counterparty, USD cost basis, lot identifier (per-wallet basis
  tracking, method chosen by the CPA under applicable tax guidance).
- **Per spend:** timestamp, ETH amount (gas × effective price + L1 fee), USD fair market value at the
  timestamp from a pinned, named price source, transaction hash, the lot(s) relieved.
- **Reconciliation:** monthly, hot-wallet and warm-wallet balances to the ledger; refills recorded as
  internal transfers (see B-15).

The accounting treatment (expense recognition, gain/loss on disposition of ETH, classification, fair-value
measurement) is **flagged for the CPA / tax advisers**; nothing in this design asserts one.

---

## 10. Invariants the relayer must satisfy (checked at every release)

| Id  | Invariant                                                                                                                                   | Check                                                                                                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| R-1 | The relayer holds only WalletWall operating ETH; it never receives, holds or forwards user USDC, and never accepts tokens as reimbursement. | no `transfer`/`transferFrom`/`approve` selectors toward the asset from relayer keys; balance monitors on relayer addresses for any ERC-20 inflow → alert and return path |
| R-2 | No relayer key can authorise any vault action, and the relayer never possesses a user's spending credential.                                | the key is not a signer, guardian, proposed signer, or destination of any clone; authority census (PG-02)                                                                |
| R-3 | No relayer key is enrolled in any vault role, ever.                                                                                         | pre-deploy and periodic census over all clones' `Initialized`/`GuardianCommitmentSet` events and `ecdsaSigner()` reads                                                   |
| R-4 | The relayer never converts fiat to ETH for a user and never holds ETH _for_ a user.                                                         | product flow review; no per-user ETH accounting exists                                                                                                                   |
| R-5 | Billing-provider state is never an authorization input and never changes any on-chain state.                                                | code review: the sponsorship decision module has no write path to the chain except the relay of **already-authorized** payloads                                          |
| R-6 | Every relayed transaction is bounded by B-1..B-15.                                                                                          | configuration tests with adversarial payloads (wrong chain, foreign code, disallowed selector, over-ceiling gas, duplicate digest)                                       |
| R-7 | Sponsorship is expressed only as published counts and ceilings; no balance, no transfer, no redemption.                                     | product copy review against §7                                                                                                                                           |
| R-8 | Refusal to relay changes nothing on-chain and leaves self-submission available; the relayer is never required for recovery or exit.         | documented and tested self-submission path (PG-15)                                                                                                                       |

---

## 11. Failure matrix

| Failure                                     | Effect on user assets                                                    | Effect on liveness                | User remedy                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------- |
| Relayer down / halted / out of ETH          | **none**                                                                 | sponsored actions stall           | self-submit with own ETH on Base; any third-party relayer                                   |
| All RPC providers down                      | **none**                                                                 | relayer stalls                    | user's own RPC / node                                                                       |
| Base sequencer down or censoring            | **none**                                                                 | nobody lands L2 transactions      | L1 forced inclusion (own L1 ETH); wait                                                      |
| Billing provider down / subscription lapsed | **none**                                                                 | sponsorship refused               | self-submit; resubscribe                                                                    |
| Issuer blocklists the vault or recipient    | USDC in that vault frozen by the **issuer**; WalletWall cannot change it | `execute`/`egress` of USDC revert | the issuer's own process; disclosed up front                                                |
| WalletWall ceases to exist                  | **none**                                                                 | no sponsorship, no UI             | §15 artifact set: offline CLI, schemas, registry, recovery and migration procedures (PG-15) |
| Relayer key stolen                          | **none**                                                                 | griefing until rotation           | — (WalletWall-side incident)                                                                |

---

## 12. Open items (routed)

- `LEGAL_REVIEW_REQUIRED` (gates PG-09, PG-11, PG-12): the characterisation of a relayer that pays gas for
  user-authorised transfers; any reporting obligation when a past relay counterparty later becomes a
  screening hit; the retention period for compliance records.
- **Owner:** which sponsored selectors belong in v1 (B-3), and the numeric bounds for B-6, B-7, B-8 and B-13.
- **Ops:** hot-wallet treasury sizing and refill process → gate PG-14.
