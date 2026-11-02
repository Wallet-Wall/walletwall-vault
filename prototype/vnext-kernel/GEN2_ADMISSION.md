# Generation-2 kernel admission — the record

> # EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT
>
> This record decides whether one measured kernel may become the **canonical Generation-2 candidate**.
> That is the only thing it decides. Nothing was deployed. No real token, no production address and no
> network configuration exists anywhere in this lane; the asset in every test is a local mock. The
> repository's real-funds warnings are unchanged.

Lane: `admission/vnext-gen2-erc20`, on `main` `c9c13ea2` (v0.13.34, the merge of PR #237). The bar was committed
before the candidate existed: [`generation-2/ADMISSION_CRITERIA.json`](generation-2/ADMISSION_CRITERIA.json),
in commit `dbe06a68`. Eleven rows were appended later, each marked, none replacing a registered row or relaxing the
residual policy: from two fresh-context reviews, a re-reading the first prompted, and a mechanical scan of every invariant
the normative documents name. `test/Gen2AdmissionMatrix.test.ts` compares the registered rows with that commit.

## Verdict

```text
GEN2_ADMISSION_BLOCKED
```

```text
PRODUCTION_BASE_USDC = NOT_ADMITTED
MAINNET_REAL_FUNDS = NOT_APPROVED
```

**The candidate cannot be admitted until you answer four questions.** On each, the kernel and the repository's own
text disagree, on every kernel here including Generation 1, and the residual policy has no clause that settles it. So each
is a choice between changing the words and changing the kernel, which is yours, and this record does not guess.

| Blocking decision | The words | Every kernel here, measured | Rows |
| --- | --- | --- | --- |
| **OD-BINDING-LIFETIME** | I-VETO-BOUND (T0): "a pending migration binding (deadline)" must lift with no principal acting. Section 6 reads delayed and reversible. I-MIGRATION-NONTRAP (T0) forbids an asset state with no authorized exit, and 13.0's failure 1 names a blacklisted destination as that trap | A binding is immediate, one-way and has no deadline. With an issuer blocking the destination, ten years on, spending, rotation, recovery, containment and rebinding are all still refused. Any stranger can retire it | K-12-VETO and K-13, T0; K-RETIRE, T1 |
| **OD-NONFUNGIBLE-EXIT** | I-MIGRATION-NONTRAP (T0). 13.1 calls ERC-721 and ERC-1155 "workable", and custody 7.1 says anything else that lands on the clone is reachable by egress | Egress has one call shape, `transfer(address,uint256)`. A non-fungible holding has no exit, though it vetoes nothing else | K-13-NONFUNGIBLE, T0 |
| **OD-RECOVERY-LOCALITY** | I-RECOVERY-LOCALITY-V2 (T1): recovery consults only the implementation, precompiles and committed guardians, and reads no state a principal outside them can write | Initiation asks the provenance root on every floor. Execution on an armed floor asks the verifier the request names, and reads the credential-writable floor and the challenge-writable flag | K-7, T1 |
| **OD-SECURITY-PROFILE** | Section 12 and H-05 (T1) require a kernel-recorded strength per scheme. Generation 1's admission deferred that to a future generation, and this is one | Four flat fields, the construct section 12 withdrew. No document says whether the deferral carries over | K-SECURITY-PROFILE, T1 |

Section 14 sets out each option and a recommendation. Generation 1 has all of these shapes and no ledger records them, so
none is new. They were found here because this is the first lane to hold the kernel to these sentences.

**What your answer does.** Amending moves no byte, and it is not a formality: the text changes first, at the places section 14
lists, and those rows are registered again against it and re-adjudicated. If they then pass, nothing else in this matrix stands
between these bytes and `GEN2_ADMITTED_WITH_DECLARED_RESIDUALS`. `test/Gen2AdmissionMatrix.test.ts` shows the same function says
so, as a hypothetical over the function: it does not write the amended rows. Building any of them instead is a new candidate,
which re-runs all of this.

**Measured Variant A was not admissible as measured, and this lane closed what it could.** Seven rows failed on it by execution
and pass on the candidate, from five causes: a movement published that did not happen, on a spend and on a native egress; a migration
completed in the bind block; a binding the kernel could see would strand the vault; a binding's signatures outliving what they were
given under; and an ERC-1271 answer counted on its first four bytes. The candidate is Variant A plus the smallest change for each,
+342 bytes in all. Everything else in the matrix passes, and the rows that pass with a residual place it under a clause the
repository's own policy already allows. **Two of the changes have a real cost, and are yours to accept:** the 7-day egress delay, measured
in section 9, and the checks at binding (OD-EGRESS-DELAY, OD-DEAD-BINDING).

The verdict is computed by `deriveAdmissionVerdict` from the matrix rows, the decision table and what the heavy suites
recorded, and `test/Gen2AdmissionMatrix.test.ts` shows the same function can return the other three.

Even a technically admitted Generation 2 would still be `NOT_APPROVED_FOR_MAINNET_REAL_FUNDS`. Kernel admission asks whether
the kernel can securely support a fixed admitted ERC-20 semantic. Whether a particular token satisfies that
semantic is asset admission, a later lane. Kernel admission does not satisfy these gates, and neither does anything
else in this lane:

```text
LEGAL_REVIEW_REQUIRED
SANCTIONS_CONTROL_REVIEW_REQUIRED
PAYMENTS_PROVIDER_APPROVAL_REQUIRED_IF_APPLICABLE
```

## The matrix

Every row was classified on measured Variant A **before** the candidate changed anything. `Variant A` is that
classification, and `candidate` is the result here. `UNPROVEN` on Variant A means no Generation-2 evidence existed
for the row, however much Generation-1 evidence did. The evidence behind each row is in
`generation-2/admission-matrix.ts`, and `test/Gen2AdmissionMatrix.test.ts` resolves every test, property and mutant
it names.

| Row | Concern | Tier | Variant A | Candidate |
| --- | --- | --- | --- | --- |
| K-1 | asset custody | T0 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-ASSET-BOUNDARY) |
| K-2 | execution authority | T0 | UNPROVEN | PASS |
| K-3 | replay state | T1 | UNPROVEN | PASS |
| K-4 | credential commitment | T1 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-SD8) |
| K-5 | ECDSA possession floor | T0 | UNPROVEN | PASS |
| K-6 | guardian authority | T0 | UNPROVEN | PASS |
| K-6-ATTESTATION (appended) | an ERC-1271 answer | T1 | **FAIL** | PASS, by admission delta |
| K-7 | recovery state | T1 | UNPROVEN | **FAIL**, blocked on OD-RECOVERY-LOCALITY |
| K-8 | recovery execution | T1 | UNPROVEN | PASS |
| K-9 | recovery cancellation and challenge | T0 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-SD4) |
| K-10 | safe-state machine | T1 | UNPROVEN | PASS |
| K-11 | emergency transition rules | T0 | UNPROVEN | PASS |
| K-12 | migration binding | T1 | UNPROVEN | PASS |
| K-12-SCOPE (appended) | what a binding commits to | T1 | **FAIL** | PASS, by admission delta |
| K-12-TIME | migration subordinate to recovery | T0 | **FAIL** | PASS, by admission delta |
| K-12-VETO (appended) | a binding's veto is bounded | T0 | **FAIL** | **FAIL**, blocked on OD-BINDING-LIFETIME |
| K-12-CLOCK (appended) | migration and pending clocks | T1 | UNPROVEN | PASS |
| K-13 | migration egress | T0 | PASS_WITH_DECLARED_RESIDUAL | **FAIL**, blocked on OD-BINDING-LIFETIME. The statement holds and its source does not: section 9 |
| K-13-SETTLE | no false settlement | T1 | **FAIL** | PASS, by admission delta |
| K-13-DEAD-BINDING (appended) | a binding the kernel can see would strand the vault | T0 | **FAIL** | PASS, by admission delta |
| K-13-NONFUNGIBLE (appended) | exit for every holding class | T0 | **FAIL** | **FAIL**, blocked on OD-NONFUNGIBLE-EXIT |
| K-RETIRE (appended) | who reaches the terminal state | T1 | **FAIL** | **FAIL**, blocked on OD-BINDING-LIFETIME |
| K-14 | verifier governance | T1 | UNPROVEN | PASS |
| K-15 | security floor | T1 | UNPROVEN | PASS |
| K-GENERATION (appended) | generation monotonicity | T1 | **FAIL** | PASS, by admission delta |
| K-INGRESS (appended) | accounted ingress | T1 | UNPROVEN | PASS |
| K-SECURITY-PROFILE (appended) | section 12's strength policy | T1 | **FAIL** | **FAIL**, blocked on OD-SECURITY-PROFILE |
| PLANE-ISOLATION | capability-plane isolation | T2 | UNPROVEN | PASS |
| IMPL-IMMUTABILITY | implementation immutability | T1 | UNPROVEN | PASS |
| FACTORY-GENERATION | factory-generation binding | T1 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-SD11-CONDITION) |
| AUTH-COMPLETENESS | authority completeness | T1 | UNPROVEN | PASS |
| AUTH-SATISFIABILITY | authority satisfiability | T1 | UNPROVEN | PASS |
| STATEFUL-COMPOSITION | stateful compositional authority | T0 | UNPROVEN | PASS |
| SCANNER-BOUNDARY | scanner and static-analysis boundary | T1 | UNPROVEN | PASS |
| PROVENANCE | evidence currency and provenance | T1 | UNPROVEN | PASS |
| RUNTIME-CEILING | runtime byte ceiling | T0 | PASS | PASS |
| G2-ASSET-1 to G2-ASSET-6 | asset identity | T1 | UNPROVEN | PASS |
| G2-ASSET-7 | no asset-selection authority | T1 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-SD11-CONDITION) |
| G2-ASSET-8 to G2-ASSET-10 | asset identity | T1 | UNPROVEN | PASS |
| G2-SEM-KERNEL | ERC-20 settlement | T1 | **FAIL** | PASS, by admission delta |
| G2-SEM-BOUNDARY | kernel versus asset admission | T2 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-ASSET-BOUNDARY) |
| G2-NO-ALLOWANCE | ERC-20 effect surface | T1 | UNPROVEN | PASS |
| G2-VERIFIER-1 to G2-VERIFIER-8 | Variant A verifier decision | T1 | UNPROVEN | PASS |
| G2-REENTRANCY | the external-call boundary | T1 | UNPROVEN | PASS |
| DEFECT-CARRY | existing defects carried | T1 | UNPROVEN | PASS_WITH_DECLARED_RESIDUAL (R-SD4, R-SD8, R-SD11-CONDITION) |
| OBSERVATORY-CLAIMS | claims a kernel cannot carry | T1 | NOT_APPLICABLE | NOT_APPLICABLE |
| OFF-KERNEL-INVARIANTS (appended) | named invariants with no kernel subject | T2 | NOT_APPLICABLE | NOT_APPLICABLE |

Totals on the candidate: **61 rows: 46 PASS, 7 PASS_WITH_DECLARED_RESIDUAL, 6 FAIL (each blocked on one of the four owner decisions), 2 NOT_APPLICABLE, 0 UNPROVEN.**

## 1. Exact candidate identity

| | |
| --- | --- |
| Status | **Under review, not canonical.** This identity is what the four blocking decisions are about |
| Source tree | `generation-2/contracts/VaultKernelGen2Prototype.sol`, `VaultKernelGen2FactoryPrototype.sol`, `interfaces/IKernelPlanes.sol` |
| Compiler | solc `0.8.24+commit.e11b9ed9`, cancun, optimizer 200 runs, `viaIR` off: identical to `hardhat.config.ts` |
| Kernel runtime | 18,914 B, sha256 `dc1b9e000b5be02262df9c633f23f3ff1fffcdccaf3248f9fb7673e7bf2ef463`, executable prefix `e48001e7ab93e144a0170a37ed4877b596d0de744d312999d6ee96a684f5ccac` |
| Kernel initcode | 19,093 B, sha256 `c081d8123e76e67bcba2ba6551c8080020580eacc21e856a8b6a1461ecff28ba` |
| Factory | 2,645 B runtime, 3,245 B initcode, template sha256 `c74bef02e1fe5b96928984b7eba4f65a2166619bd5967a00945872693c5e1f0c`, four immutables |
| Clone | 93 B: `363d3d373d3d3d363d73` + implementation + `5af43d82803e903d91602b57fd5bf3` + 48 B of args |
| Args layout | generation (8) ‖ verifierAuthority (20) ‖ admittedAsset (20) |
| Generation identifier | 2, the factory's constructor argument |
| Admitted-asset binding | bytes 28..48 of the args, i.e. runtime bytes 73..93 of the clone. No storage word holds it |
| Authority manifest | `generation-2/authority/gen2-authority-manifest.json` |
| Receipts | `GEN2_ADMISSION_EVIDENCE.json` (identity, matrix), `GEN2_AUTHORITY_CENSUS.json`, `GEN2_STATEFUL_AUTHORITY_EVIDENCE.json`, `GEN2_SCANNER_EVIDENCE.json` |

**How it differs from what was measured.** With comments stripped, from `erc20-spend-plane/contracts/VaultKernelErc20Prototype.sol`,
pinned by `test/Gen2CandidateDerivation.test.ts`:

```diff
-contract VaultKernelErc20Prototype {
+contract VaultKernelGen2Prototype {
 function bindMigration(...) external {
     ...
     if (destination.vault == address(0) || destination.codeHash == bytes32(0)) revert DestinationMismatch();
+    if (destination.vault.code.length == 0 || destination.vault == address(this)) revert DestinationMismatch();
+    if (destination.vault.codehash != destination.codeHash) revert DestinationMismatch();
     ...
-    keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation)),
+    keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation, credentialGeneration, policyEngine, _effectiveState())),
 function egress(address asset) external {
     ...
     if (!b.bound) revert NotBound();
+    if (block.timestamp < b.boundAt + BIND_DELAY) revert TooEarly();
     ...
     if (asset == address(0)) {
-        moved = address(this).balance;
-        if (moved != 0) {
-            (bool ok, ) = payable(b.destinationVault).call{value: moved}("");
+        uint256 before = address(this).balance;
+        if (before != 0) {
+            (bool ok, ) = payable(b.destinationVault).call{value: before}("");
             if (!ok) revert TransferFailed();
+            uint256 remaining = address(this).balance;
+            if (remaining >= before) revert TransferFailed();
+            moved = before - remaining;
         }
 function _balanceOf(address asset) internal view returns (uint256) {
     ...
-    if (!ok || data.length < 32) return 0;
+    if (!ok || data.length < 32) revert TransferFailed();
 function _attests(...) internal view returns (bool) {
     ...
-    return ok && bytes4(answer) == ERC1271_MAGIC;
+    return ok && answer == bytes32(ERC1271_MAGIC);
```

That comparison is statement for statement, in order, and the factory differs only in its names. Comments changed too, and the
changes are part of the delta: the header says what this tree is and no longer that the implementation "can never hold custody", which
AUTHORITY.md records as falsified; two comments in `_admittedAsset` and `execute` that made false claims about failing closed were
corrected; and so was the recovery section's claim to consult only the invariant's list. A comment that lies is a defect in a kernel whose
comments carry its invariants.

Each finding is measured on both sides, in `test/Gen2AdmissionFindings.test.ts`, because a fix asserted only on the
fixed kernel proves nothing about whether the defect existed:

- **F-SETTLE (K-13-SETTLE, G2-SEM-KERNEL).** Measured Variant A read a failed balance query as an observed zero. A
  spend of exactly the vault's balance, whose post-transfer query reverts or returns short, **settled with nothing
  moved and the nonce consumed**, and egress published the whole balance as moved. The kernel's own comment claimed
  this failed closed. Its native egress published what it sent because the call returned, so a destination handing the
  value straight back left an event saying it all moved and a balance saying none of it had. Generation 1's egress does both.
- **F-TIME (K-12-TIME, T0).** `BIND_DELAY` gated only `retire`, which gates nothing. On an armed floor the coalition
  {k guardians, ECDSA key, no PQ key} drained a vault in the block after binding, against 7 days for its recovery
  path. Generation 1 has the same code, no ledger entry records it, and H-11's Detection clause claims a
  delay-bounded warning window that did not exist.
- **F-DEAD-BINDING (K-13-DEAD-BINDING, T0).** `bindMigration` accepted any non-zero hash and `egress` compares it, so one
  wrong hash signed at k+1 left egress, spending, recovery and rebinding refused for good. A vault bound to itself passes the hash and
  its balance can never fall. A funded empty address has a hash to name, and loses it the moment something is deployed there. Architecture
  13.5 re-checks "at EXECUTION, not only at preparation", and the preparation half was never there. On the candidate all three are refused
  at binding, consuming nothing. Generation 1 has the same code.
- **F-BINDING-SCOPE (K-12-SCOPE, K-GENERATION).** H-10 lists what a binding must carry, and the digest omitted the credential's generation,
  the plane and the safe state. Signed, then rotated away and back to the same key, a credential leg from two generations ago still bound.
- **F-ATTESTATION (K-6-ATTESTATION).** I-ATTESTATION-IS-AFFIRMATIVE says the returned word equals the magic value. The kernel compared its
  first four bytes, so magic plus anything reached quorum.
- **F-FREEZE (K-13, T0), F-VETO (K-12-VETO, T0) and F-NONFUNGIBLE (K-13-NONFUNGIBLE, T0).** Measured on every kernel and **not closed
  here**: see the verdict and section 9.

## 2. The Variant A decision

Custody section 10 item 6 asked whether the generation should accept a null verifier while `requirePq` is false. #237
measured that accepting one costs **57 bytes more**. Being smaller is not the same as being safe, so all eight claims
were executed, in `test/Gen2VerifierAdjudication.test.ts`, with the real provenance root bound wherever a claim is about
admission:

| # | Claim | Result |
| --- | --- | --- |
| G2-VERIFIER-1 | Presence creates no WalletWall authority root | Neither root nor class has an owner, setter or vault reference. An attestor key used as a credential is refused |
| G2-VERIFIER-2 | No asset movement while `requirePq == false`; not consulted | A spend settles with a **reverting** verifier installed, which it could not if the verifier were called |
| G2-VERIFIER-3 | No liveness dependency on WalletWall infrastructure | A complete lifecycle (spend, policy, verifier change, rotation, recovery, migration) with **no attestor statement anywhere**, and a vault a stranger creates end to end |
| G2-VERIFIER-4 | Deployable permissionlessly, with no privilege | The outsider creates every verifier in these worlds. A byte-identical copy outside the root is refused |
| G2-VERIFIER-5 | Later transitions satisfy the cuts | Provenance at all three edges under the real root. On an armed floor the ECDSA key alone cannot change the verifier |
| G2-VERIFIER-6 | A malicious verifier stays bounded | Under the real root a bare always-true contract is refused. A root-created verifier under an attacker's own attestor is admissible, because the root checks the class and not the attestor: installing it takes what installing any verifier takes, and it then voids only the PQ factor, the declared degradation |
| G2-VERIFIER-7 | Verifier loss cannot trap exit | Verifier down: spending stops, while a binding by quorum and ECDSA, the egress and the recovery all still work |
| G2-VERIFIER-8 | No trusted-attestor hard dependency | None on a dormant floor. On an armed floor no *particular* attestor is needed for exit, and a compromised attestor alone moves nothing |

**Recommendation: keep the requirement, Variant A.** Nothing overturns the measurement. An armed floor stakes spending on the
installed verifier's attestor. It stakes a recovery on *some* attestor's statement, which the recovering party can make itself:
`test/Gen2VerifierAdjudication.test.ts` runs one end to end with a stranger-created verifier and no other infrastructure.
Migration by quorum and ECDSA needs none. That is an argument for custody 10.2, and the decision stays yours. The
`G2-VERIFIER-*` rows are about the installed verifier: that recovery consults the proposed one is K-7's row.
Variant B stays the comparator: it admits `address(0)` and is larger, re-asserted in the same suite.

## 3. Asset-binding model

```text
Generation  -> a factory constructor argument, spent once
Factory     -> four immutables; no storage, no owner, no setter
Clone args  -> generation || verifierAuthority || admittedAsset, in the clone's own code
admittedAsset -> read from that code at every spend, never from calldata and never from storage
```

`test/Gen2AssetIdentity.test.ts` reconstructs the whole chain offline, from public facts only, down to the CREATE2 address.

| Row | Requirement | How it is true |
| --- | --- | --- |
| G2-ASSET-1 | Fixed at creation | A vault's asset is its factory's constructor argument from its first block |
| G2-ASSET-2 | No setter | From the ABI, from the layout, and by value: no storage word of a live vault holds it |
| G2-ASSET-3 | Caller cannot select | `execute` has no such parameter, and appended calldata changes nothing |
| G2-ASSET-4 | Relayer cannot select | A relayer chooses whether and when. Rewriting a signed field is refused and consumes nothing |
| G2-ASSET-5 | Credential cannot mutate in place | Code byte-identical after every credential act, across every campaign history |
| G2-ASSET-6 | Quorum cannot mutate in place | The same, recovery included |
| G2-ASSET-7 | WalletWall owns no selection authority | Any deployer gets identical bytes for identical arguments. The one choice is spent before any vault exists (R-SD11-CONDITION) |
| G2-ASSET-8 | Changing asset needs a new Vault | A migration moves an asset and never converts it. At a vault of another asset it is a holding that can leave and cannot be spent |
| G2-ASSET-9 | A different asset is a different identity | With factory, salt, genesis and implementation fixed, the asset alone moves the address, and so the domain separator |
| G2-ASSET-10 | Cross-asset replay fails | Both directions, over histories, one credential on both vaults, no nonce burned |

**The signature does not name the asset, and does not need to.** It names the vault, through the domain separator, and the
vault's address commits to the asset. M-G2-3 removes the vault from the domain and dies by P-CROSS-ASSET.

## 4. Authority census

`GEN2_AUTHORITY_CENSUS.json`. Two layers, because they answer different questions.

**The real checker, unchanged.** `authority/check.ts` runs on the candidate, compiled in memory under the two contract names
it is hard-coded to, against a manifest written for Generation 2: **18 gated entries, 16 PASS, 2 PASS_WITH_DECLARED_EXCEPTION
(`execute`, `egress`), 0 failed.**

**A derived comparison with Generation 1.** The verdict is computed from the two ASTs, and five mutants in
`test/Gen2AuthorityCensus.test.ts` show the same code answers otherwise when a principal or an edge is added:

```text
NO_NEW_PRIVILEGED_PRINCIPAL
```

| Compared | Generation 1 | Candidate |
| --- | --- | --- |
| State-changing selectors | 14 | the same 14 |
| Authorisation path, per selector | | identical on all |
| State effects, per selector | | identical on all |
| Address holders in storage | `ecdsaSigner`, `policyEngine`, `pqVerifier` | the same three |
| Caller identity in kernel or factory | none | none |
| Function bodies (AST) | | 40 identical; `bindMigration`, `execute`, `egress`, `_balanceOf`, `_attests` differ; `admittedAsset`, `_admittedAsset` added |
| Views added | | `admittedAsset()` |

**The new effect surface.** The ERC-20 call is not a new human principal, and it is a new effect surface, so it is modelled as
one: `execute -> lowlevel.call:asset:0xa9059cbb` and `execute -> lowlevel.staticcall:asset:0x70a08231` are the only edges added,
and `execute -> lowlevel.call:recipient:value` is the edge removed. Per-function caller discretion is in the manifest:
`execute` none beyond whether and when; `egress` which holding leaves and when, never where or how much; `retire` when, after
the delay. The factory adds nothing. The checks at binding read the destination's code size and hash, which the census does not count as
an edge because no call is made, and they move no cut.

**The census answers a narrower question than custody.** An issuer's power over its own ledger is not a kernel principal, so it is
outside this comparison, and it is real: R-ASSET-BOUNDARY.

## 5. Stateful authority result

`GEN2_STATEFUL_AUTHORITY_EVIDENCE.json`, `generation-2/test/Gen2StatefulCampaign.test.ts`. Generation 1's record was not inherited:
the campaign ran **on the candidate**, at Generation 1's exact seeds and depths, across all 19 inherited profiles with their
adversaries intact and 13 ERC-20 profiles.

| Measure | Result |
| --- | --- |
| Campaigns | **448** |
| Transitions | **24,320**, 9,431 successful |
| **Violations unexplained by the ledger** | **0** |
| Positive controls | **3976/3976**, every step of each one succeeding |
| Refusals really mined | 14,863 |
| Seams recorded | 43, of which every required one was reached |
| Balance controls run / skipped as unaskable | 190 / 203 |
| Protected outcomes reached | ASSET_MOVEMENT 665, CONTAINMENT 179, CREDENTIAL_REPLACEMENT 247, GUARDIAN_TRANSITION 126, MIGRATION_BINDING 55, POLICY_CHANGE 308, RECOVERY_QUORUM_CANCEL 8, VERIFIER_REPLACEMENT 251 |
| Sustained defect still reproducing | SD-4 (2) |
| Suite | 458 passing, 0 failing |

Generation 1's global invariants run unchanged, imported rather than copied. The oracle stays asymmetric: IF a protected outcome
occurred, by state diff, THEN its authority cut was satisfied. The asset properties read the token's own ledger, never the kernel's
view of it, so a kernel that believes a lying token is caught rather than agreed with. No refusal is judged mid-history. The two
liveness properties, P-EXIT-REACHABLE and P-BALANCE-SPENDABLE, are judged at the **end** of each history, so they need no model of why
any step was refused.

Every sequence the brief lists is reached, each by a named seam the suite requires non-zero: relayed spend settled, unauthorised
spend refused, direct and repeated direct transfers, spend after a direct transfer, failed transfer, lying result, short pay, sender
fee, rebase and dust, cross-asset replay, binding, egress, recovery then spend, containment then spend, verifier transition then spend,
policy denial then spend, replayed spend, replayed migration, replayed egress. So are the ones the first draft of this campaign could
not reach: a binding naming the wrong hash or the vault itself, a misbehaving token on the egress path, and a destination that hands native value back or refuses it.

**What the numbers are.** A campaign's decisions are a function of (profile, seed, depth, label), so `generation-2/GEN2_RUN_RECORD.json` holds the
exact outcome. The chain's clock follows the wall between time advances, and every advance is at least an hour, so only a stall of that order could change a
decision, and that fails loudly. Two complete runs of each suite came out identical. The heavy suites compare themselves with the record and fail on any
difference, the receipt reports it, and the verdict reads it: a record showing a violation, a failed control or a survivor forces `GEN2_NOT_ADMITTED` whatever the rows
say. The record cannot prove a run happened, and nothing committed could. It makes a hand-edit fail the next real run, and that run is by hand until a CI job exists for these suites.

## 6. Mutation adequacy

`generation-2/test/Gen2MutationAdequacy.test.ts`. A kill counts only if the mutant compiled, **the named positive control still passed
on it**, **the named property fired**, and **the same profile, seed and depth run clean on the real candidate**, because the catalogue's
seeds are not the campaign's. Liveness is judged on the campaign that killed it, not on any earlier one. Anything else is INCONCLUSIVE or SURVIVED and says so. The suite also
requires every Generation-2 property to die on some mutant, so a property that can never fire fails here. M-G2-18 and M-G2-19 are one mutation of the source, entered twice because each
is the only mutant for its property.

**Generation-2 catalogue: 25/25 killed.** Mutation suite: 53 passing, 0 failing.

| Mutant | Verdict | Killed by | Where |
| --- | --- | --- | --- |
| M-G2-1-caller-chooses-token | KILLED | P-SPEND-TOUCHES-ONLY-ASSET | erc20-relayer seed 47 |
| M-G2-2-asset-outside-the-identity | KILLED | P-ASSET-CODE-IDENTITY | erc20-direct-transfer seed 11 |
| M-G2-3-cross-asset-replay-accepted | KILLED | P-CROSS-ASSET | erc20-cross-asset seed 11 |
| M-G2-4-boolean-trust | KILLED | P-SETTLEMENT-EXACT | erc20-settlement-zoo seed 11 |
| M-G2-5-any-decrease-accepted | KILLED | P-SETTLEMENT-EXACT | erc20-settlement-zoo seed 11 |
| M-G2-6-nonce-after-token-call | KILLED | P-NONCE-SPENT-BEFORE-TOKEN-RUNS | erc20-reentrancy seed 83 |
| M-G2-7-failed-transfer-ignored | KILLED | P-SPEND-COMPLETED-TRANSFER | erc20-settlement-zoo seed 11 |
| M-G2-8-migration-caller-chooses-token | KILLED | P-EXIT-REACHABLE | erc20-migration-and-freeze seed 47 |
| M-G2-9-migration-caller-chooses-recipient | KILLED | P-EGRESS-RECIPIENT | erc20-migration-and-freeze seed 197 |
| M-G2-10-relayer-identity-gains-privilege | KILLED | P-CUT/ASSET_MOVEMENT | stranger-only seed 29 |
| M-G2-11-egress-delay-removed | KILLED | P-MIGRATION-TIME | erc20-migration-and-freeze seed 197 |
| M-G2-12-lenient-balance-read | KILLED | P-SETTLEMENT-EXACT | erc20-settlement-zoo seed 197 |
| M-G2-13-spend-nonce-not-consumed | KILLED | P-NONCE-ON-SPEND | replay-composition seed 11 |
| M-G2-14-relayer-chooses-recipient | KILLED | P-SPEND-PAYS-RECIPIENT | erc20-relayer seed 11 |
| M-G2-15-credential-moves-the-asset-in-place | KILLED | P-ASSET-CODE-IDENTITY | erc20-policy-then-spend seed 11 |
| M-G2-16-quorum-moves-the-asset-in-place | KILLED | P-ASSET-CODE-IDENTITY | quorum-without-credential seed 11 |
| M-G2-17-signed-recipient-unbound | KILLED | P-UNAUTHORISED-INPUT-NEVER-SETTLES | erc20-relayer seed 11 |
| M-G2-18-spent-nonce-accepted | KILLED | P-NO-REPLAY | replay-composition seed 29 |
| M-G2-19-replay-accepted-inside-the-transfer | KILLED | P-REENTRY-NO-REPLAY | erc20-reentrancy seed 47 |
| M-G2-20-full-balance-unspendable | KILLED | P-BALANCE-SPENDABLE | erc20-direct-transfer seed 11 |
| M-G2-21-verifier-provenance-unchecked | KILLED | P-VERIFIER-PROVENANCE | erc20-real-root-floor seed 11 |
| M-G2-22-egress-publishes-the-whole-balance | KILLED | P-EGRESS-PUBLISHES-THE-TRUTH | erc20-migration-and-freeze seed 197 |
| M-G2-23-dead-binding-accepted | KILLED | P-EXIT-REACHABLE | erc20-migration-and-freeze seed 47 |
| M-G2-24-self-binding-accepted | KILLED | P-EXIT-REACHABLE | erc20-migration-and-freeze seed 29 |
| M-G2-25-native-published-unobserved | KILLED | P-EGRESS-PUBLISHES-THE-TRUTH | erc20-migration-and-freeze seed 131 |

Generation 1's catalogue also ran on the candidate: **21/21 killed**, 7 by a cut property, the rest by their model or global invariant. M23, the tumbling-window defect, **survived** the inherited straddle
profile on all eight seeds, and then a first dedicated profile too. It was treated as the stop condition it is and diagnosed: a scripted
straddle on the mutant showed the oracle firing, so the property had teeth and the generator was at fault, because the seam needs several
containment entries to succeed in sequence and most generated quorum shapes are adversarial. `erc20-containment-straddle` now mostly attempts
honest ones, and M23 dies by the same independent oracle. The straddle is also pinned deterministically on the candidate, in
`test/Gen2KernelRows.test.ts`.

Two more mutants are deterministic rather than in the catalogue, because a campaign cannot generate their seams, in `test/Gen2Migration.test.ts`: remove `egress`'s
re-check and a destination destroyed in its creating transaction is paid anyway; remove the no-code check and a funded empty address binds, and the deployment that
follows it is refused for good. The other deterministic mutants are the census's five, in section 4. The measured Variant A arm of each finding is the same comparison made on real bytes.

## 7. ERC-20 semantic assumptions

Formal admission is for **one specifically admitted vanilla ERC-20 semantic class**. It is not arbitrary-ERC-20 admission.

**The required semantic:** deterministic balance accounting; no fee on either leg; no rebasing that invalidates an exact observed
settlement; a transfer that either reduces the sender's balance by exactly the amount and credits the recipient by exactly the amount,
or reverts; a `balanceOf` that tells the truth; fixed contract identity; no callback trusted for authorisation.

**The settlement rule is preserved from #237, tightened:**

```text
balance read strictly -> transfer -> balance read strictly -> beforeBalance - afterBalance == amount
```

The call must not revert, and its boolean is trusted in neither direction: a token returning nothing, or false while moving, settles on the
observed delta. A failed query refuses. Every refusal is atomic, and the signature survives it.

**What the kernel can observe, against what asset admission must guarantee:**

```text
kernel-level settlement proof != complete token-economic semantics proof
```

| Behaviour | The kernel | Why |
| --- | --- | --- |
| Short pay, sender fee, dust short, no move with `true` | **refuses** | The observed decrease is wrong |
| Revert, `false` with no move, failed query | **refuses** | Not an observation |
| No return value; `false` while moving | settles | The delta is exact, and the boolean is not the rule |
| **Recipient-side fee** | **settles** | Its own balance fell by exactly the amount. Invisible from here |
| **`balanceOf` lying by exactly the expected debit** | **settles, nothing moved, nonce burned** | Nothing in the kernel can tell |
| Rebase between spends | settles on what is there | There is no ledger to desynchronise |
| Rebase during a transfer | **refuses** | The observed decrease is wrong |
| **An issuer's seizure or downward rebase** | **nothing to refuse** | The kernel takes no part in it |
| **An issuer's upgrade** | **sees nothing** | The address is fixed. The behaviour is not |

The bold-named rows are R-ASSET-BOUNDARY, asserted on purpose in `test/Gen2Settlement.test.ts`. **Asset admission must close them.**

**Asset-admission checklist.** This lane formalises the interface and admits no token. A real token must answer every line with evidence:

1. **Code identity.** The exact bytecode, and what it delegates to.
2. **Chain.** Which network, and that it is the only one this generation names.
3. **Proxy and upgrade structure.** Whether the address's behaviour can change. A vault's asset is an address, so an issuer upgrade changes the behaviour of every vault at once and the kernel sees nothing.
4. **Issuer controls.** Who can mint, burn, pause, seize or upgrade, and under what process.
5. **Freeze and blocklist semantics.** Source and destination both: R-ASSET-BOUNDARY and row K-13 follow from this answer.
6. **Transfer semantics.** Exactly the amount, on both legs, or a revert.
7. **Decimals.** Fixed, and what the relayer and interface assume.
8. **Balance behaviour.** `balanceOf` truthful, 32-byte return, no reverting state, no gas surprise.
9. **Return and revert behaviour.** What failure looks like. The kernel does not need a boolean, and does need failure not to look like success.
10. **Fee behaviour.** None today, and whether one can be switched on later: this is where a recipient-side fee would come from.
11. **Rebase behaviour.** None, or the exact-settlement rule stops describing the asset.
12. **Known callback behaviour.** Any hook on transfer. The candidate tolerates one (section 8), which does not make one acceptable.
13. **Administrative upgrade risk.** Who decides, how fast, and what a vault holder can do first. A generation's asset is immutable; the token's behaviour is not, and migration takes 7 days.

No real contract address appears in the candidate, in this record or anywhere in the lane's tree. The Base USDC answers belong to a later lane.

## 8. Reentrancy result

**No guard, and none earned.** The argument is state ordering, and `test/Gen2Reentrancy.test.ts` attacks each of its legs, with the hook before and after the debit:

```text
authorise -> consume nonce -> plane -> snapshot balance -> token runs -> read balance -> exact delta, or revert everything
```

| Claim | Result |
| --- | --- |
| Cannot double-spend | A second **valid** spend at nonce + 1 breaks the outer exact delta, and the whole call reverts, nonce included |
| Cannot replay | The same calldata from inside dies on the nonce the outer call already consumed |
| Cannot alter the migration disposition | An authorised bind from the hook fixes the signed destination: bind-after-spend. Unauthorised, it is refused. A nested egress can only reach the same destination |
| Cannot escape a safe state | A containment from the hook stops the next spend: spend-then-contain. A spend from a hook during egress is refused by the state |
| Cannot exploit nonce ordering | The token reads the vault's nonce getter mid-transfer and finds it already consumed. M-G2-6 removes this order and dies |
| Failure is atomic | A containment that **succeeded** inside a refused spend is rolled back with it, and every storage word is byte-identical |
| Observation cannot be manipulated | A credit or rebase during the transfer makes the delta wrong, so it refuses. The plane runs **before** the snapshot, so it cannot touch it |
| Nested authority acts | A rotation, a roster change and a recovery initiation from the hook are each spend-then-act, and refused unsigned or below quorum |

The claim tested throughout is **serial equivalence**: a hook can only sequence acts someone authorised, so every outcome is one an ordering of authorised acts could
produce, or the call reverts. The campaign's two reentrancy profiles compose this over histories with P-CUT charged to the hook's own roots. One thing it looks like from
inside, disclosed as N-NESTED-ACTS: the outer spend settles *after* the nested act, in the state that act left, so a spend can settle while contained. A token with a hook can do this, which asset admission refuses, and so can a policy plane, which the credential installed, with a vanilla token.

## 9. Migration and egress result

`test/Gen2Migration.test.ts`, and each kernel side by side in `test/Gen2AdmissionFindings.test.ts`.

**What holds.** Binding needs the quorum **and** the credential, fixes the destination vault and its code hash, names no amount and no asset set, and can never be rebound. Its signatures
commit to what they were given under, H-10's list field by field (K-12-SCOPE), so a rotation, a plane change or a change of safe state voids them. Every holding is refused until exactly
bind + 7 days and leaves at that exact second, on armed and dormant floors, measured from the mined bind block. Egress is permissionless with no discretion, entries are independent, retry
is perpetual including from RETIRED, and a hostile holding vetoes nothing. A movement is published only as an observed decrease, on native value too. Across every campaign history that ended
in a binding, with the token and the destination behaving again, a stranger's egress moved every class out: P-EXIT-REACHABLE, with M-G2-8, M-G2-23 and M-G2-24 showing it has teeth. A binding made
while contained moves no clock word (K-12-CLOCK).

**The two checks of the destination.** At binding, a destination with no code, the vault itself, and a hash the destination's code does not have are each refused. At egress the hash is checked
again, as 13.5 requires: since EIP-6780 a contract's code can vanish only in the transaction that created it, so a destination created, bound and destroyed in one transaction is refused, and re-creating
the same code at the same address restores the exit, where the creator can. Remove the re-check and that vault pays an address with no code. A destination must now have code to be bound (N-DESTINATION-EXISTS). The factory
is permissionless, so that costs a transaction.

**What is not met.**

- **K-13 and K-12-VETO.** This is the first thing to read in this section. K-13's registered statement is true, and the row fails on its source. I-MIGRATION-NONTRAP forbids an asset state with no authorized exit, an issuer's
  block of the bound destination is one, 13.0's failure 1 names exactly that as the trap, and 13.4 keeps only the *source* case. So it is not a residual: the block is external and the trap is not. Only a binding that can lift would avoid it, and none can.
  With the asset's own contract refusing, the vault waits on nobody it can reach, and recovery is refused for as long as it waits. That also makes 24.2's "Permanent recovery veto: unreachable" untrue, at k+1 plus an issuer.
- **What a code hash cannot show** (N-BINDING-SCOPE). A destination with no `receive()` keeps native value in the vault, with the same unbounded wait. Under EIP-7702 a delegated account has code whose hash its owner can change at will. That one is **not measured**, because the pinned EVM is cancun.
- **K-13-NONFUNGIBLE.** A non-fungible holding has no exit: section 14.
- **K-RETIRE.** A stranger can force RETIRED after the delay, with no migration completed. Today that closes nothing a binding has not already closed. It stops being harmless if a binding can lapse.

**What the delay costs, measured.** Nothing can stop a bound egress in those 7 days: MIGRATION_ONLY refuses containment, recovery, spending and a rebind (N-EGRESS-WINDOW). It gives time and
visibility, which is what I-MIGRATION-SUBORDINATE-TO-RECOVERY and H-11 ask for, and no more. It costs honest migrations a week. And it removes something measured Variant A had by accident: a
wrapper could bind and egress in one transaction, so a block already on the destination reverted both and trapped nothing. On the candidate that is refused with `TooEarly`, so every binding
is exposed to an issuer's block for 7 days. The T0 asks for this delay, and it is still yours to accept.

## 10. Scanner and static-analysis result

`GEN2_SCANNER_EVIDENCE.json`. No Generation-1 result is carried.

| Tool | Result |
| --- | --- |
| **Slither**, pinned `ff1bf3ff`, on `generation-2/contracts` itself | 216 raw, 138 dependency-only, **52 distinct own-code**: 27 on the candidate, 25 on the test fixture. 2 High, 7 Medium, 25 Low, 18 Informational |
| **Authority scanner** | Section 4 |
| **Prohibited patterns** | Executable-code sweep: no DELEGATECALL, CALLCODE, CREATE, CREATE2 or SELFDESTRUCT. No `msg.sender`, `tx.origin`, owner or pause. The sweep's teeth shown on the factory and on a clone |
| **solhint** | 0 errors, 49 warnings, style and gas only |
| **CodeQL** | **NOT RUN LOCALLY.** It ships no Solidity extractor, so it cannot analyse the candidate at any commit, and it is not installed here. It covers this lane's TypeScript in CI at publication |
| **Evidence and provenance** | Section 12 |
| **Runtime-byte validation** | Section 11 |

All 27 candidate findings are **PASS_WITH_DECLARED_EXCEPTION**, each with its exact source location, why static analysis cannot resolve it, the dynamic property that covers it and the
mutant showing that property has teeth, enforced by `test/Gen2Scanner.test.ts`. The High on the candidate is `arbitrary-send-eth` on `egress`: the recipient comes from a k+1 binding in an earlier
transaction, which Slither cannot see, covered by P-EGRESS-RECIPIENT and M-G2-9. The other High is `suicidal` on `Gen2EphemeralDestination`, a test fixture whose whole purpose is to lose its code.

**What was not scanned.** The tree holds the candidate and its fixture. The provenance root and the verifier class are Generation 1's, compiled unchanged and scanned by that lane's job, not re-run here. The raw
Slither output is not committed: its reduction is, with no machine path in it, and `generation-2/scanner.ts` reproduces it from a run.

**CI boundary.** The repository's Slither job targets `contracts/` only. Adding this tree is a workflow edit the App cannot push, an owner act at publication. Until then this is a reproducible
local run, recorded as such.

## 11. Runtime and gas measurements

Re-measured after every admission change. Pinned in `test/Gen2Measurement.test.ts`.

| Bytes | Candidate | Note |
| --- | --- | --- |
| **Final runtime** | **18,914** | |
| Delta from measured Variant A (18,572) | **+342** | The admission changes in section 1 |
| Delta from Generation 1 (18,331) | +583 | |
| Headroom to EIP-170 (24,576) | 5,662 | |
| Headroom to `TARGET_KERNEL_CEILING` (21,976) | 3,062 | |
| Headroom above the internal stop line | 2,462 | |
| Initcode | 19,093 | +342 from Variant A; limit 49,152 |
| Factory runtime / initcode | 2,645 / 3,245 | Unchanged from #237 |
| Clone runtime | 93 | |

| Gas, local Hardhat network | Candidate | Delta from Variant A |
| --- | --- | --- |
| Authorised ERC-20 spend | 108,310 | 0 |
| Rejected authorisation | 38,506 | 0 |
| Transfer failure (blocklisted recipient) | 62,325 | +12 |
| Lying token, refused | 76,413 | 0 |
| Migration egress | 71,550 | +162 |
| Spend after recovery | 108,298 | not measured on Variant A |
| Deploy vault | 210,770 | +24 |
| Deploy implementation | 4,167,698 | +73,985 |
| Deploy factory | 639,852 | 0 |

Local and comparative only. Not converted to any currency, and not a claim about any network's fees. These are #237's fixtures on isolated accounts, so the kernel is what they measure. A difference of a few tens on a deployment row is calldata: the addresses differ, and so do their zero bytes. Binding has no row: it is not one of the paths the brief names. Its checks add an EXTCODESIZE and an EXTCODEHASH and its digest three reads.

## 12. Provenance

**Two-commit protocol.** Commit A carries the code; commit B carries the receipts naming A. A receipt names the commit it is about, never its container, and `generate-evidence.ts` refuses to run
if any measured input differs from the subject by a byte. Currency is licensed by **byte equality of the inputs**, recomputed by `test/Gen2Provenance.test.ts`, never by ancestry or equal counts. The
candidate's identity recompiles to what the receipt says; no timestamp or machine path enters it; line endings are normalised, so a CRLF checkout cannot move an identity. The same suite shows that
`contracts/`, `stateful/`, `erc20-spend-plane/` and `authority/` are byte-identical to the base: Generation 1's evidence subject did not move.

**Evidence-quality findings.** Reported because they are the point of the exercise:

1. **Generation 1's P-ATOMICITY tests nothing, and neither does this lane's.** Generation 1's harness sends refused calls with no gas limit, so they die in gas estimation and **no block is mined**: it compares a
   state with itself. Its digest also includes clock-derived views, so it would fire falsely on any mined revert. Here every refusal is really mined (14,863 in the final run, required non-zero as a seam) and the oracle digests
   raw storage, so it is a check on the harness. It still cannot fire on a kernel, because a reverted call cannot change storage by the EVM's own rule. It is not evidence for K-3, and is no longer cited as such.
2. **Generation 1's harness silently stops testing after a replay.** A replayed rotation that succeeds moves the chain and not the harness's model, so its honest actor signs with a dead key for the rest of the
   campaign and nothing reports it. P-BALANCE-SPENDABLE found this here. The Generation-2 harness re-reads who holds what after each step has been judged, and that does feed which roots later steps are charged with: its
   first comment said "construction only", which the review showed was not so, and it now says what it does.
3. **M23 survived the inherited profile** (section 6). A survivor is a stop condition, and it was treated as one: the oracle was shown to fire before the generator was changed.
4. **A naive opcode sweep reads a data byte as CREATE2**: the compiler places a constant after the last INVALID, and it contains `0xf5`, in both generations. The sweep now skips what cannot execute rather than whitelisting the hit.
5. **Every F-finding in section 1 is on Generation 1 with no ledger entry**, and the reference model's egress has no delay either: its test checks only the constant. Reported, not changed: `contracts/` and `stateful/` are frozen here. 24.2's "Silent crypto downgrade: refused by the partial order" describes something no kernel built so far has.
6. **Architecture 13.4 says the source-blacklist case is recorded in 2.2, and H-28 repeats it. It is not.**
7. **The review caught this lane's own first verdict.** The first draft of this record said `GEN2_ADMITTED_WITH_DECLARED_RESIDUALS`. A fresh-context review, given the code and not the conclusion, found that:
   - four of its nine residuals stood under clauses the draft had invented ("inherited narrowing"), two of them on a T0 row, and the matrix test checked only that the clause text was longer than ten characters;
   - the dead binding was left out of the residual that should have named it, and "the same on every kernel" overstated a freeze the delta had made worse;
   - K-7's note said recovery consults no plane, which the kernel's own inventory contradicts;
   - the verdict was tied to hand-typed strings, and the receipt reported the campaign's plan rather than its result.
   Each was verified against source first, and all are fixed here: the closed list is now a type, the verdict reads the run record, and the mechanical invariant scan it prompted is a permanent test.
   **A second fresh-context review then caught the fix.** The first check at binding compared hashes only, so a vault bound to itself and a funded empty address still reached the trap, and its row said a binding that could never succeed was not accepted. The residual the draft had kept for a blocked destination stood on a clause the architecture contradicts: 13.0 names that case as the trap. "These exact bytes would then come out admitted" hand-flipped three rows. K-7 undercounted, `K-GENERATION` was false on the binding's credential leg, native egress published without observing, an ERC-1271 answer was compared on four bytes, a property restated the fix's own comparison, and H-05 and H-10 had no row, because the scan read invariant names and not hazards. All verified against source, then fixed or reclassified, and the hazard register now has a test of its own. So this record failed two reviews before reaching this form. A third might well find more, which is part of what "not an audit" means.
8. **The harness was weaker than its first report said**, and the same review showed where. Mutation seeds were never run on the real candidate, so a defect could have scored as a kill. A positive control could pass on a later step after an earlier one failed. Any fired hook suspended the settlement oracles, even one that moved nothing, and signature-less hooks were charged to the armer's roots. `P-REENTRY-NO-REPLAY` replayed stale calldata and was close to unfalsifiable. Six properties had no mutant, and egress's false-settlement refusal had none. A seam could count a refusal it did not check. Each is fixed above, and none of them was hiding a kernel defect.
9. **This lane's other mistakes:** a probe that died at the wrong guard until refusals asserted decoded names; a results test that ran before the suites it reported on, because Mocha runs a suite's own tests first; a derivation check that compared sets, so a reordering would have passed. It now compares in order.

## 13. Existing residual defects

| Id | What | Answer | Policy clause |
| --- | --- | --- | --- |
| **R-ASSET-BOUNDARY** | What a sender cannot observe, and what an issuer can do with no kernel act, including a block of the clone itself | New by construction: section 7. Custody names blocklisting and freezing; "Issuer controls are external" is the class, and your lane requirements 6 and 12 place the rest of it on asset admission. It rests on that class, not on a sentence naming each behaviour | External asset behaviour (custody 7.1, 8 D-5; 13.4) |
| **R-SD4** | The ECDSA-only declaration destroys an approved recovery | **Preserved, not worsened.** 21 days against 14, and it self-heals. Reachable through the asset only as a carrier for the same signature | Sustained defect with a disposition: `SD4_DEDICATED_REMEDIATION = NOT_REQUIRED` |
| **R-SD8** | A preimage proves no key is well-formed | **Preserved, not worsened.** Cut 0, self-inflicted; recovery and migration both still reach the asset | Sustained defect with a disposition |
| **R-SD11-CONDITION** | SD-11A and SD-11B hold on a factory binding the real root | **Preserved under the same condition.** Also covers: the factory enforces non-zero generation only | Generation-publisher discovery (H-32) |

An issuer's block of the bound *destination* was a residual in an earlier draft of this record. It is row K-13 now: section 9.

Nothing was accidentally fixed. Each is re-executed on the candidate in `test/Gen2CarriedDefects.test.ts`, or in the suite the matrix names.

**Disclosed narrowings.** Where the candidate is narrower than a document says. **The residual policy has no clause for these, so they are not residuals, and no row rests on one.** A row passes only where its registered statement is literally true without them. You should know they are here, and some may be worth amending when you answer section 14.

| Id | What | Against |
| --- | --- | --- |
| **N-EGRESS-WINDOW** | Nothing can stop a bound egress during its 7 days | H-11 promises a warning window and names no remedy |
| **N-BINDING-SCOPE** | What a code hash does not prove: a destination's generation is a signed label, asset match is the signers' responsibility at k+1, one with no `receive()` keeps native value in the vault, and an EIP-7702 account can change its hash at will (not measured: the pinned EVM is cancun) | H-10's own residual risk |
| **N-LATTICE** | Recovery is refused in MIGRATION_ONLY, RECOVERY_ONLY is never assigned, the kernel generation does not advance on RETIRED, and there is no manifest: one egress call is one entry | Section 6; 13.1 |
| **N-DESTINATION-EXISTS** | A destination must have code to be bound, so a migration deploys it first and cannot name an externally-owned account | Nothing written; measured Variant A accepted both |
| **N-ONE-SPENDABLE-ASSET** | Native value and unsolicited ERC-20 holdings can leave and cannot be spent | Generation 1's native spend; this is what the plane is |
| **N-NESTED-ACTS** | An authorised act nested in a token's hook or a policy plane takes effect before the outer spend settles | Nothing: section 8 |

**Hazard coverage.** Every T0 and T1 hazard in the register is mapped to the row that answers it, in `HAZARD_COVERAGE`, and a test parses the register. H-03's Prevention ("guardian-quorum authority only") is superseded by D1's bounded challenge, which is what K-9 holds the kernel to. H-15 and H-31 are not prevented, in the register's own words, and are unchanged.

## 14. Unresolved owner decisions

| Decision | Previous state | Measurement evidence | Admission evidence | Recommendation | Owner decision required? |
| --- | --- | --- | --- | --- | --- |
| 10.1 Pin the asset in immutable args | Recommended yes | 93-byte clone; one factory immutable | G2-ASSET-1..10; M-G2-2, M-G2-15, M-G2-16 | Yes. This lane's brief also requires it | No |
| 10.2 Ship v1 with `requirePq = false` | Recommended yes | None | Kernel-neutral. A dormant floor needs no attestor anywhere. An armed floor stakes spending on the installed verifier's attestor, and recovery on some attestor's statement, which the recovering party can make | Yes, unchanged | **Yes** |
| 10.3 WalletWall guardian seats | Recommended none | None | Kernel-neutral: a roster is genesis configuration | None, unchanged | **Yes** |
| 10.4 Production constants; EIP-712 name and version | Open | None | The candidate carries prototype constants. A production build is a **new identity** that must re-run this suite | Decide in the deployment lane | **Yes** |
| 10.5 Chain scope | Recommended Base Mainnet only | None | Kernel-neutral: the domain carries the live chain id, and no chain is named | Unchanged | **Yes** |
| 10.6 Null verifier | Variant B 57 B larger | 18,629 vs 18,572, re-asserted | G2-VERIFIER-1..8 all PASS | **Keep the requirement** | **Yes**, to confirm |
| **OD-BINDING-LIFETIME** (new, **blocks**) | Text says deadline and reversible, and names the blocked destination as the trap; every kernel has neither remedy; unrecorded | None | K-12-VETO, K-13 and K-RETIRE FAIL on all three kernels | **Build (B)**, below | **Yes** |
| **OD-NONFUNGIBLE-EXIT** (new, **blocks**) | Text says workable; every kernel has one call shape; unrecorded | None | K-13-NONFUNGIBLE FAIL on all three kernels | **Amend (A)**, below | **Yes** |
| **OD-RECOVERY-LOCALITY** (new, **blocks**) | Closed list omits two recorded calls, and its last clause forbids two reads the design relies on; unreconciled | None | K-7 FAIL as registered. The list's stated purpose holds by execution | **Amend (A)**, below | **Yes** |
| **OD-SECURITY-PROFILE** (new, **blocks**) | Deferred to a future generation by K-15's disposition; this is one, and nothing says whether the deferral carries over | None | K-SECURITY-PROFILE FAIL. K-15 passes on what it states | **Defer again (A)**, below | **Yes** |
| **OD-EGRESS-DELAY** (new) | Absent, against 13.2 and H-11 | Section 11: spend gas unchanged, egress +162 | K-12-TIME FAIL on Variant A, PASS here; M-G2-11. Cost: section 9 | **Accept.** Removing it returns the row to FAIL | **Yes** |
| **OD-DEAD-BINDING** (new) | Absent, against 13.5 | Section 11 | K-13-DEAD-BINDING FAIL on Variant A, PASS here; M-G2-23, M-G2-24. Cost: N-DESTINATION-EXISTS | **Accept** | **Yes** |
| **OD-ROOT** (new) | Unstated | None | Deployment-only; the root has no owner | Either is safe. Decide in the deployment lane | **Yes** |

**Four block this verdict, and they are not yes-or-no questions about the same thing.**

**OD-BINDING-LIFETIME.** A binding vetoes everything but egress. Normally that is fine: anyone can egress at day 7, and the vault is done. It matters when egress cannot succeed, which for the admitted asset means that its own contract refuses, and for native value also that the destination does.

- **(A) Amend.** All of these come to say what the kernel does: section 6's transitions, action matrix and Required invariants; I-VETO-BOUND's binding clause; NONTRAP's head sentence and 13.0's failure 1; section 16's T0 scope, "the absence of any unbounded terminal veto"; D2's RETIRE row; 24.2's "Permanent recovery veto: unreachable" and the "no veto outcome" summary under it; the matching row in AUTHORITY.md; and 2.2 and 13.4, to declare the blocked destination. No bytes change, and this is the only option that leaves these bytes canonical. It rewrites a T0.
- **(B) Build.** A dedicated lane adds a self-lifting lapse and re-runs this suite on the new bytes. A sketch, **not adjudicated here**: a binding under which the admitted asset has moved nothing lapses at bind + `BIND_DELAY` + a window; only admitted-asset movement pins it, because native value or unsolicited dust is griefable; permissionless `retire` could pin a blocked binding, so it may need D2's conjunction, which would also answer K-RETIRE.
- **Recommendation: (B).** Headroom is ample (section 11), and it makes a T0 true rather than rewriting it, for the one failure a vault holder has no other way out of. If you judge the case too remote to spend a kernel edge on, (A) is coherent, and it should then be said out loud at each of those places.

**OD-NONFUNGIBLE-EXIT.**

- **(A) Amend.** Scope this kernel's egress to holdings with the ERC-20 transfer shape, in NONTRAP and 13.1, 13.0a, H-25 and custody 7.1, and declare an unsolicited non-fungible holding in 2.2. No bytes change.
- **(B) Build.** A per-class egress: new selectors, token-id discretion under the same no-recipient rule, settlement on observed ownership, and a callback into the destination on the safe paths. Its byte cost is not measured.
- **Recommendation: (A).** A generation whose purpose is one admitted fungible asset gains little from a new call shape in the kernel, and nothing else is affected: every other holding leaves. The words have to change, and only you can change them. Custody's sentence is the one a user could most reasonably have relied on, so that one matters most.

**OD-RECOVERY-LOCALITY.**

- **(A) Amend.** Add both consults to the closed list, naming their bounds: the provenance root at initiation, immutable, ownerless, able only to refuse, with a permissionless cure; and on an armed floor the verifier the approved request names, chosen by the quorum and re-proposable. Narrow the last clause to except the credential's bounded challenge and SD-4's disposition. KERNEL_ADMISSION K-8 and K-7's registered statement move with it.
- **(B)** is not really available: removing the root's call reopens SD-11, and removing the armed possession proof contradicts I-INCOMING-CREDENTIAL-POSSESSION, on which K-4 passes.
- **Recommendation: (A).** What the invariant says its words are for, "no replaceable component's failure can stop recovery", is shown by execution, including with a recovering party running its own attestor. Section 24.2's accepted denial does not cover this, because it is denial of *spending*, and it says recovery stays available. So this is not a residual and needs your words.

**OD-SECURITY-PROFILE.**

- **(A) Defer again, saying so.** This generation claims no strength policy either, and 24.2's row and H-05 are corrected to what is built. No bytes change.
- **(B) Build.** Section 12's lattice in the kernel: a large lane.
- **Recommendation: (A)**, for a generation custody 10.2 recommends shipping with `requirePq = false`, where there is no PQ strength to rate, with the policy as a condition of the first generation that arms PQ for real value.

Items 10.2 to 10.5 are deployment configuration the candidate is neutral to. OD-EGRESS-DELAY and OD-DEAD-BINDING ask you to keep changes this record already made, and neither is a question the verdict waits on.

## 15. What admission does NOT establish

- **Not an admission.** The verdict is blocked, so this candidate is not canonical, and the rows that pass are evidence for your decision and not a result of it.
- **Not production readiness, whatever you decide.** `PRODUCTION_BASE_USDC = NOT_ADMITTED`. `MAINNET_REAL_FUNDS = NOT_APPROVED`. This is `NOT_APPROVED_FOR_MAINNET_REAL_FUNDS`.
- **Not an audit.** No third party has reviewed this code.
- **Not asset admission.** Nothing here says any real token meets section 7.
- **Not a legal or compliance result.** The gates at the top are untouched and stay `REQUIRED`.
- **Not exhaustive.** A bounded, seeded campaign over a bounded vocabulary. "No violation found" is not "no violation exists".
- **Not formal verification.** Mutation score is adequacy, not coverage.
- **Not a cryptographic claim.** Under the fixture root the second factor is an ECDSA key standing in for a PQ scheme.
- **Not a statement about any deployed bytes.** A build with different constants is a different candidate. Which asset, root and generation a deployed factory binds is checkable offline and is not established here.
- **Not a claim that the prior lanes were wrong to measure what they measured.** #237's verdict was `MEASUREMENT_SUPPORTS_ADMISSION`, and measurement is what supported attempting this.
- **Not a judgement that the kernel is wrong and the text right.** On the blocking rows the two disagree. Which one moves is the question.

## Next lane

**Your four decisions come first.** Where you amend, the architecture changes in its own lane, and these rows are registered again against the new text. Where you build, that is the next lane, and it re-runs this suite.

Only after that:

Base native USDC asset-admission adjudication: section 7's checklist, answered for one real token. **Not** production deployment. Not begun here.
