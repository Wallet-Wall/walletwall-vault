# ERC-20 spend plane — admitted-asset measurement record (Generation-2 candidates)

> # EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT
>
> This record measures whether a **single admitted ERC-20 asset** can be spent through the vNext
> minimal-trust kernel without changing its authority model, and what it costs. Everything measured
> is a **candidate** in `prototype/vnext-kernel/erc20-spend-plane/`, compiled in-test against a
> **local mock** asset. Nothing was deployed, no mainnet or testnet configuration exists, no production
> asset is named, and the repository's real-funds warnings are unchanged. A measurement verdict is
> **not** a production admission; the owner decisions in
> `docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md` §10 stay the owner's.

Lane: `measure/vnext-erc20-spend-plane`, on `main` `5ac076fe` (v0.13.32, the merge of PR #235).
Figures: `erc20-spend-plane/ERC20_SPEND_PLANE_MEASUREMENTS.json` (asserted field-for-field against a
fresh compile by `test/Erc20SpendPlaneMeasurement.test.ts`). Method: the pinned solc
`0.8.24+commit.e11b9ed9`, cancun, optimizer 200 runs, `viaIR` off — identical to
`prototype/vnext-kernel/hardhat.config.ts` — with the Generation-1 kernel compiled through the same
path as the positive control (18,331 bytes, equal to `MEASUREMENTS.json kernel.runtimeBytes`, executable
prefix byte-identical to the Hardhat artifact's).

## 0. Verdict

```text
MEASUREMENT_SUPPORTS_ADMISSION
```

The admitted-asset plane fits the kernel admission rule as a change of **which ledger K-2 settles
on**, not as a new kernel responsibility; it adds **no principal**, **no selector with authority**,
**no storage word**, and **no immutable slot** to the implementation; it costs **+241 bytes** of runtime
(18,572; headroom 3,404 against `TARGET_KERNEL_CEILING`, 2,804 above the 600-byte stop line); every
invariant the lane brief names (ERC20-1 … ERC20-10) holds under attack with a positive control beside
each; observed-balance settlement is **justified by execution**, not by preference (§6); and the
authority census passes with the Generation-1 manifest **unchanged** (§4). The one hypothesis the
custody adjudication left open is **refuted** by measurement: accepting a null verifier at genesis does
not save bytes — it costs **57 more** (§3, §9).

This is not equivalent to production admission. §10 lists what stands between this record and a
production-generation lane.

## 1. What was measured, and how

**Hypothesis (lane brief).** The kernel can support one admitted ERC-20 with the smallest possible
delta: asset fixed per vault, not caller-selectable, no token parameter on spend, no registry, oracle,
allowance, swap, bridge, yield, metadata dependency, vendor SDK or chain-specific API.

**Sources.** The Generation-1 kernel and factory were copied and edited by exact-once textual
substitution into `erc20-spend-plane/contracts/` (the edits are the whole of §2; the Generation-1 header
is retained verbatim below the new one). They live beside, not inside, `prototype/vnext-kernel/contracts/`
because that directory is the evidence subject of the evidence-currency and scanner-scope guards
(`erc20-spend-plane/README.md` explains). They are compiled in-test with the pinned solc — the SD-11
lane's method for out-of-tree fixtures — and deployed from creation bytecode by ordinary
transactions, never `setCode`.

**Two variants, because §10 item 6 said "measure first".**

| Variant | Genesis rule when `requirePq == false`                                                                                                                   |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**   | `VaultKernelErc20Prototype` — as Generation 1: the verifier must be non-null, code-bearing and created by the provenance root bound in the clone's args  |
| **B**   | `VaultKernelErc20NullVerifierPrototype` — `address(0)` is admissible at genesis and only there; `setVerifier` and `initiateRecovery` still refuse a null |

Variant B differs from A in `initialize` and one internal view helper, and in nothing else (asserted by
chunk comparison in `Erc20SpendPlaneMeasurement.test.ts`).

## 2. Architecture delta

| Item               | Generation 1 (`VaultKernelPrototype`)                               | Candidate                                                                                                                                                      |
| ------------------ | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `execute` transfer | `recipient.call{value: amount}("")`                                 | `asset.call(transfer(recipient, amount))`, `asset = _admittedAsset()`; settlement = **exact** observed decrease of `balanceOf(this)`                           |
| `execute` ABI      | `execute(address payable,uint256,uint256,uint64,bytes,bytes,bytes)` | `execute(address,uint256,uint256,uint64,bytes,bytes,bytes)` — recipient no longer `payable`; **selector unchanged** (`6bc44090`); params hash unchanged        |
| Asset identity     | none (native value)                                                 | bytes 28..48 of the clone's immutable args; `admittedAsset()` view (new selector, the only one); `_admittedAsset()` internal                                   |
| Clone args         | `generation (8) ∥ verifierAuthority (20)` = 28 B                    | `generation (8) ∥ verifierAuthority (20) ∥ admittedAsset (20)` = 48 B; clone runtime 73 → **93 B**                                                             |
| Factory            | 3 immutables                                                        | 4 immutables (`admittedAsset`, refused if zero or codeless), `admittedAsset()` getter; `deployVault`/`predictVault` signatures unchanged; **no setter**        |
| Native value       | spendable                                                           | arrives unsolicited (`receive()`), leaves only via `egress(address(0))`                                                                                        |
| Storage            | 17 entries / 11 slots                                               | **identical** (both variants)                                                                                                                                  |
| Immutable slots    | 0 (`I-PURE-CONSTRUCTOR`)                                            | **0** (both variants) — the asset is in the CLONE's code, never the implementation's                                                                           |
| Nonce domains      | 4                                                                   | 4, unchanged; `execute` consumes `DOMAIN_SPEND` **before** the asset call                                                                                      |
| Everything else    | —                                                                   | **unchanged**: floor, `_authorise`, rotation, verifier governance, guardians, recovery, containment, migration binding, `egress`, EIP-712 domain, every digest |

**Where the asset is bound — three options, decided on authority, not size.**

| Binding                                                                                   | Who can change it                                                              | Verifiable from                                             | Disposition                                                                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Immutable clone args** (chosen)                                                      | nobody — the args are EIP-1167 code, written once by CREATE2                   | `eth_getCode(vault)` alone                                  | The asset becomes part of the vault's **identity**: two vaults with byte-identical genesis and different assets land at different addresses (ERC20-3 test). The implementation stays asset-agnostic and keeps `I-PURE-CONSTRUCTOR`. Changing the asset = a new generation. |
| 2. Immutable implementation-generation configuration (a constant/immutable in the kernel) | nobody                                                                         | the implementation's code + the clone's delegate target     | One implementation **per asset**, so every asset is a new kernel audit surface; an `immutable` would additionally break `I-PURE-CONSTRUCTOR` (address-dependent runtime). Rejected: it moves a per-vault fact into the shared implementation.                              |
| 3. Factory-written storage at `initialize`                                                | any future kernel path that writes storage; depends on no writer ever existing | a storage read, i.e. an **observation** (custody doc §10.1) | Rejected: a storage value is what the vault _believes_, not what it _can do_, and it is invisible to `eth_getCode`. Authority-neutral only as long as a code property is maintained forever.                                                                               |

Options 1 and 2 give no principal a write path; option 3 relies on one never being added. Option 1
keeps the single-asset fact where the generation's other identity facts already live (generation,
provenance root), so the architecture's rule — _values that must never change belong in immutable
args_ (`Vault_vNext_Architecture.md` §3.1) — decides it.

**A compiler finding, recorded rather than smoothed over.** With `viaIR` off (the pinned build, kept so
every byte figure stays comparable to Generation 1 and to the monolith) the first draft of the new
`execute` body **did not compile** (`CompilerError: Stack too deep` at `recipient` in the transfer
calldata): the settlement needs four locals above the function's ten parameter slots. The digest and
the policy-plane locals are therefore scoped into blocks so their words are freed before settlement —
the idiom `bindMigration` already uses. The authority tracer treats blocks as transparent, so the census
result is unaffected (§4). The alternative, `viaIR`, would have made this measurement incomparable.

## 3. Byte measurement

| Contract                                            | Runtime (B) | Initcode (B) |  Δ runtime vs Gen-1 | Headroom vs ceiling 21,976 | Headroom vs budget 24,576 | Above the 600 B stop line | Verdict           |
| --------------------------------------------------- | ----------: | -----------: | ------------------: | -------------------------: | ------------------------: | ------------------------: | ----------------- |
| Generation-1 kernel (positive control, re-measured) |      18,331 |       18,510 |                   — |                      3,645 |                     6,245 |                     3,045 | `TARGET PASS`     |
| **Variant A** — verifier required at genesis        |  **18,572** |       18,751 |            **+241** |                  **3,404** |                     6,004 |                 **2,804** | **`TARGET PASS`** |
| **Variant B** — null verifier accepted              |  **18,629** |       18,808 |            **+298** |                  **3,347** |                     5,947 |                 **2,747** | **`TARGET PASS`** |
| Generation-1 factory                                |       2,551 |        3,030 |                   — |                          — |                         — |                         — | —                 |
| Generation-2 factory                                |       2,645 |        3,245 | +94 (initcode +215) |                          — |                         — |                         — | —                 |

- **Variant B − Variant A = +57 bytes.** The null-verifier admission is a branch added to genesis while
  `_requireAdmissibleVerifier` must stay for the arming and recovery edges, so nothing is removed and the
  hypothesis "dropping it saves bytes" (custody doc §7.2) is **refuted**.
- Both variants keep **0 immutable slots**, **17 storage entries over 11 slots** identical to Generation 1,
  **46 → 47 selectors** (+`admittedAsset()`, view), **14 state-changing selectors identical** to
  Generation 1. The interface copy is byte-identical to Generation 1's.
- The stop condition (`Vault_vNext_Architecture.md` §19.2, read against the target ceiling as the custody
  adjudication §7.6 reads it) is cleared by **2,804 B** (A) and **2,747 B** (B). Against EIP-170 the headroom
  is 6,004 B and 5,947 B.
- Method control: the Generation-1 kernel compiled through this path measures exactly 18,331 B and its
  executable prefix equals the Hardhat artifact's byte for byte; only the 53-byte CBOR metadata tail differs,
  because solc hashes the source keys into it. The whole-runtime hashes are therefore **not** compared across
  methods, and the record says so rather than hiding it.

## 4. Authority delta

| Question                                         | Answer, by test                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New principal?                                   | **None.** `msg.sender` does not occur in either candidate (asserted). The factory's only state-changing function is `deployVault`; it has no setter, owner, pause or upgrade path (asserted on the ABI).                                                                                                                                                                                                                              |
| New externally reachable state-changing surface? | **None.** The state-changing selector set equals Generation 1's in both variants; the only new selector is the view `admittedAsset()` (`Erc20SpendPlaneAuthorityCensus.test.ts`, `Erc20SpendPlaneMeasurement.test.ts`).                                                                                                                                                                                                               |
| Authority census                                 | `authority/check.ts` run with the **Generation-1 manifest unchanged** on the candidates compiled under the Generation-1 names (in-memory rename): **0 failures, 0 unclassified, 0 stale**, verdict per gated entry identical to Generation 1's (16 `PASS`, 2 `PASS_WITH_DECLARED_EXCEPTION`, the same two). `execute` still reaches `HYBRID` before its first effect; its only unresolved shape is the declared policy-plane nesting. |
| Relayer                                          | ERC20-1: a stranger relays a signed spend and gains nothing; its own signature, a redirected recipient and a resized amount are each refused `BadSignature`.                                                                                                                                                                                                                                                                          |
| Caller discretion over the asset                 | ERC20-2: `execute` has no asset parameter; a second token held by the vault is untouched by any spend and reachable only through `egress`.                                                                                                                                                                                                                                                                                            |
| WalletWall                                       | Holds no key, seat, plane or setter anywhere in the plane. The verifier an ECDSA-only vault must name under variant A is created **permissionlessly** from the Generation root (`deployVerifier(attestor)`, executed by the outsider in the test) and is never consulted while `requirePq == false`.                                                                                                                                  |
| Migration                                        | ERC20-7/8/9: the stranger executes `egress`; the admitted asset, an unsolicited token and native value each go in full to the bound destination; there is no recipient parameter; a failed egress mutates no migration word; a completed migration cannot bind again or move twice; `retire` by a stranger after `BIND_DELAY`; egress stays open from `RETIRED`.                                                                      |

## 5. Invariant evidence (test map)

All in `prototype/vnext-kernel/test/`. Each attack carries its positive control in the same test.

| Property                                              | Test (file: name)                                                                                                                                                                              |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ERC20-1 relayer gains no authority                    | `Erc20SpendPlane`: "ERC20-1 — the relayer gains NO authority…"                                                                                                                                 |
| ERC20-2 asset cannot be caller-selected               | `Erc20SpendPlane`: "execute takes NO asset parameter…", "ERC20-8 — the caller chooses WHICH holding…"                                                                                          |
| ERC20-3 cross-asset replay fails                      | `Erc20SpendPlane`: "ERC20-3 — a signature for the vault of asset A does not move asset B…" (identical genesis, different asset, different address)                                             |
| ERC20-4 nonce replay fails                            | `Erc20SpendPlane`: "ERC20-4 — the same authorised payload cannot be replayed…"                                                                                                                 |
| ERC20-5 failed transfer is atomic                     | `Erc20SpendPlane`: "ERC20-5 — an issuer-blocklisted recipient…", "…a token that returns TRUE without moving…"; `Erc20SpendPlaneSettlement`: nonce unconsumed on every refusal                  |
| ERC20-6 direct transfer does not corrupt spendability | `Erc20SpendPlane`: "ERC20-6 — a DIRECT token transfer… and so is a rebase the vault never saw"                                                                                                 |
| ERC20-7 migration recipient fixed                     | `Erc20SpendPlane`: "ERC20-7/9 — any stranger executes egress…", "a stranger cannot bind a destination of their own…"                                                                           |
| ERC20-8 migration asset fixed                         | `Erc20SpendPlane`: "ERC20-8 — …", "a FAILED egress mutates no migration state…", "a completed migration cannot be replayed…"                                                                   |
| ERC20-9 arbitrary caller executes                     | relayed `execute`, outsider `egress`, outsider `retire`, outsider `deployVerifier` (above)                                                                                                     |
| ERC20-10 no new WalletWall capability                 | `Erc20SpendPlane`: "ERC20-10 — …"; `Erc20SpendPlaneAuthorityCensus` (whole file); `Erc20SpendPlaneMeasurement`: "source discipline"                                                            |
| Zero-amount spend                                     | admitted; consumes the nonce; moves nothing; a blocklisted recipient still refuses it                                                                                                          |
| Codeless asset                                        | refused by the factory (`NoCode`); a raw clone naming one can never settle a non-zero spend; a zero spend is vacuous (recorded)                                                                |
| Hook-bearing asset (reentrancy)                       | same-payload replay from the hook → `BadNonce` inside, outer settles; a valid second spend from the hook breaks the outer exact delta → both revert                                            |
| Issuer-upgraded asset (proxy)                         | lying upgrade refused with no nonce consumed; honest logic settles before and after                                                                                                            |
| Hybrid floor and policy plane                         | unchanged: PQ conjunct still demanded on a hybrid vault; a denying plane still refuses after the nonce                                                                                         |
| Variant B genesis                                     | null admitted only with `requirePq == false`; refused with the conjunct; `setVerifier`/`initiateRecovery` refuse null; arming with an admissible verifier succeeds                             |
| Mutation adequacy                                     | `Erc20SpendPlaneMutations`: M-E1 boolean trust, M-E2 any decrease, M-E3 nonce after settlement, M-E4 call failure ignored — each LIVE on the vanilla control and KILLED by a named observation |

## 6. Accounting adjudication — observed-balance settlement, proved not preferred

Three accounting rules were built as model contracts with **no authorization** (so the rule alone is
under test) and run against the adversarial zoo; the kernel then ran the same zoo through `execute`.

| Token (what it really does)                                          | A: internal ledger         | B: boolean trust (SafeERC20) | **C: observed exact delta** | Kernel |
| -------------------------------------------------------------------- | -------------------------- | ---------------------------- | --------------------------- | ------ |
| `VanillaToken` — moves `amount`, returns true (control)              | settled                    | settled                      | **settled**                 | = C    |
| `NoReturnToken` — moves `amount`, returns nothing                    | settled                    | settled                      | **settled**                 | = C    |
| `FalseReturningToken` — returns false, moves nothing                 | refused                    | refused                      | **refused**                 | = C    |
| `LyingToken` — returns true, moves nothing                           | **FOOLED** (nothing moved) | **FOOLED** (nothing moved)   | **refused**                 | = C    |
| `ShortPayToken` — moves `amount/2`, returns true                     | **FOOLED** (half)          | **FOOLED** (half)            | **refused**                 | = C    |
| `SenderFeeToken` — debits `amount + 1 %`, recipient gets `amount`    | **FOOLED** (over-debit)    | **FOOLED** (over-debit)      | **refused**                 | = C    |
| `RebasingToken` at index 1.5 — rounds shares down, settles short     | **FOOLED** (short)         | **FOOLED** (short)           | **refused**                 | = C    |
| `RecipientFeeToken` — debits `amount`, recipient gets `amount − 1 %` | fooled                     | fooled                       | **fooled**                  | = C    |

Findings:

- **The preference is justified by execution.** Model C refuses every adversary models A and B accept,
  and the kernel's outcome equals model C's on every row with the nonce unconsumed on every refusal.
- **Model A has a second failure the table cannot show:** a direct `transfer` to the model is invisible to
  its ledger (unspendable), and a rebase drifts the ledger from the token (ERC20-6 shows the kernel has
  neither problem because it keeps no ledger).
- **The one adversary no sender-side rule can see** is a fee taken from the **recipient's** leg: the
  vault's own balance — the only ledger it owns — tells the truth about the vault. That is the asset's
  semantics, not a kernel defect, and it is why the first production generation should admit only an asset
  known to have vanilla transfer semantics (§8).
- `egress` keeps its "any decrease, full balance" rule; `execute` uses **exact** equality because a sized
  spend that under-settles would publish a movement that did not happen in full, and one that over-debits
  would move value the credential never signed for (mutant M-E2 shows exactness is load-bearing).

## 7. Gas — local comparative measurements (NOT cost claims)

Hardhat network (EDR, cancun), receipts' `gasUsed`, isolated accounts, fresh worlds per probe.

| Probe                                           | Generation 1 (native ETH) | Candidate A (ERC-20) | Candidate B | Note                                                                                |
| ----------------------------------------------- | ------------------------: | -------------------: | ----------: | ----------------------------------------------------------------------------------- |
| Authorised spend, relayed by a stranger         |                    76,456 |          **108,310** |     108,310 | +31,854: the token's two balance writes (recipient slot cold) and two balance reads |
| Refused authorisation (`BadSignature`)          |                    38,493 |               38,506 |           — | the floor is unchanged                                                              |
| Refused transfer — blocklisted recipient        |                         — |               62,313 |           — | token reverts → `TransferFailed`, nothing consumed                                  |
| Refused transfer — lying token (observed delta) |                         — |               76,413 |           — | the settlement check's own cost on a false success                                  |
| Migration egress of the asset (stranger)        |              42,308 (ETH) |               71,388 |           — | ERC-20 transfer + two balance reads vs a native send                                |
| `deployVault` (first clone of a fresh factory)  |                   206,501 |              210,746 |           — | +4,245: 20 more bytes of clone code and calldata                                    |
| Implementation deployment                       |                 4,041,517 |            4,093,713 |   4,106,033 |                                                                                     |
| Factory deployment                              |                   615,189 |              639,852 |           — |                                                                                     |

These are measured on a local network with mock contracts and must not be extrapolated into Base-dollar
claims (lane brief). The suite asserts the recorded figures exactly and prints a fresh table for
re-recording when a candidate changes.

## 8. Known unsupported or external behaviours (the asset trust boundary)

| Behaviour                                                    | Kernel outcome                                                                                 | Disposition                                                                                                           |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Recipient-leg fee on transfer                                | settles (sender's leg is exact)                                                                | **Unsupported by design**; admissible only for an asset known to have vanilla semantics                               |
| Sender-leg fee, partial settlement, success without movement | refused, nothing consumed                                                                      | supported refusal                                                                                                     |
| Rebasing / index tokens                                      | settle only when the decrease is exactly `amount`; dust-short transfers refused                | **Unsupported**: a rebasing asset will refuse spends unpredictably                                                    |
| Transfer hooks (ERC-777-shaped)                              | replay refused `BadNonce`; a nested valid spend reverts both                                   | safe, but a hook-bearing asset can make legitimate spends fragile; not vanilla                                        |
| Issuer blocklist of recipient or vault                       | spend reverts; nothing WalletWall can do                                                       | external control; disclosure obligation (custody doc §7.1, gate PG-13)                                                |
| Issuer-upgradeable asset (proxy)                             | the kernel pins an ADDRESS, never behaviour; a lying upgrade is refused, an honest one settles | **external trust**; a codehash pin would be meaningless for a proxy (same observation as SD-11B)                      |
| Asset whose `balanceOf` lies                                 | undetectable by construction (the asset IS the ledger)                                         | the admitted asset is the trust boundary; no kernel can judge an asset against itself                                 |
| Codeless asset                                               | refused at the factory; a raw clone cannot settle non-zero; zero is vacuous                    | post-Cancun, code at a fixed address cannot vanish after its creating transaction, so this is a genesis-time property |
| Zero-amount spend                                            | admitted: burns a nonce, moves nothing                                                         | the credential's idiom to retire an outstanding signature; a reverting asset still refuses it                         |
| Native value                                                 | not spendable; leaves via `egress(address(0))`                                                 | by design (custody doc §7.1)                                                                                          |

**The safest admission is therefore the narrow one the brief anticipated:** only an asset with vanilla
ERC-20 transfer semantics (exact debit, no fee, no rebasing, no hooks) — of which native Base USDC is the
intended instance — and that admission is a property of the **asset**, decided by the owner, not of the
kernel.

## 9. Section 10 item 6 — recommendation with numbers (the owner decides)

> _"Whether the new generation accepts a null verifier when `requirePq == false` (measure first)."_

| Measure                                | Variant A — keep the requirement                                                                                                           | Variant B — accept null                                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Runtime bytes                          | 18,572                                                                                                                                     | 18,629 (**+57**)                                                                                        |
| Authority                              | unchanged from Generation 1                                                                                                                | unchanged (census identical)                                                                            |
| New kernel state                       | none                                                                                                                                       | a vault with `pqVerifier == address(0)` exists; every later edge must keep refusing null (two do today) |
| What an ECDSA-only genesis must supply | an admissible verifier it never consults: **one permissionless call** to the root (`deployVerifier`, by anyone, once per attestor address) | nothing                                                                                                 |
| Spend-path gas                         | 108,310                                                                                                                                    | 108,310 (identical)                                                                                     |
| What the owner is deciding             | one extra deployment step at genesis                                                                                                       | 57 bytes and a new state every reader of `pqVerifier` must special-case                                 |

**Recommendation: keep the requirement (variant A).** The byte argument for the null variant does not
exist — it is the more expensive one — and its only benefit is skipping a permissionless call that costs
no authority and introduces no WalletWall dependency. The decision remains the owner's; both variants
are measured and tested here so it can be made on numbers.

## 10. Blockers before a production-generation lane

Everything below stands between this record and a production-generation lane; none of it is closed here.

1. **Owner decisions** in `docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md` §10, items 1–6 (asset in immutable
   args; `requirePq = false` in v1; guardian seats; constants; chain scope; item 6 as above).
2. **Production constants** (§7.3) and the EIP-712 `name`/`version` for the new generation (this record keeps
   `0-prototype`; `kernelGeneration()` already separates the digests).
3. **A Generation-2 provenance root decision:** the candidates bind the same `IKernelVerifierAuthority`
   interface; whether Generation 2 reuses the Generation-1 root or publishes its own is a generation-act
   question (`Vault_vNext_Architecture.md` §22 D8).
4. **Scanner and campaign coverage of the candidates:** Slither/CodeQL run only on the scanner scope, which
   the candidates are deliberately outside of; the stateful campaign and its mutation catalogue bind
   Generation 1. A publication lane must bring the plane into both (new scope, new receipts).
5. **The asset admission itself** (§8): vanilla semantics, blocklist disclosure, proxy governance — a
   property of the admitted asset, established off-chain and disclosed.
6. **Independent audit, formal review of the settlement rule, and the §15 artifact set** (custody doc §7.5,
   §7.6; gates PG-15, SG-03): none of this record is an audit.
7. **No deployment of any kind** until the gates in `docs/BASE_MAINNET_PRODUCTION_GATES.md` are met; this
   lane created none and must not be read as a step towards one.

## 11. What this record does not establish

No audit, no formal verification, no production readiness, no gas or cost claim for any live network, no
statement about any real asset's behaviour, no legal or compliance conclusion of any kind, and no change
to the measured Generation-1 kernel (whose `MEASUREMENTS.json` figures are unchanged; the
`erc20SpendPlaneMeasurement` block there is a pointer, not a remediation entry).

## 12. Reproduction

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test   # whole prototype suite, these suites included
npx tsx prototype/vnext-kernel/erc20-spend-plane/measure.ts          # byte record
npx tsx prototype/vnext-kernel/authority/check.ts                    # Generation-1 census, unchanged
```
