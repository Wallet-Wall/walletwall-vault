# Deployment Records

> Research prototype. Not audited. Testnet only. Do not use real funds.

This file records public test deployments for integration and bytecode comparison. It
does not represent a production deployment, mainnet availability, an audit, or
production-grade post-quantum verification.

## Ethereum Sepolia - active testnet

Status: **active testnet**

| Field | Value |
| --- | --- |
| Network | Ethereum Sepolia |
| Chain ID | `11155111` |
| `WalletWallVault` | [`0x210ceD9C12AF27b10B06eB5506b24a51E11506E9`](https://sepolia.etherscan.io/address/0x210ceD9C12AF27b10B06eB5506b24a51E11506E9) |
| PQ verifier | [`0x832E223c6D889A96bCFF434a609e8a5782C706e9`](https://sepolia.etherscan.io/address/0x832E223c6D889A96bCFF434a609e8a5782C706e9) |
| Deployment transaction | [`0x8f15e6c99ee4ac789836716c75d26a8dc8df240dad731cbc8a7c9515e91cc3e1`](https://sepolia.etherscan.io/tx/0x8f15e6c99ee4ac789836716c75d26a8dc8df240dad731cbc8a7c9515e91cc3e1) |
| Reported source commit | `828bf219c0e2612fcd1aba5f085c4abeba29de88` |
| Live Sepolia runtime observed | `20,508` bytes |
| Current public HEAD runtime | `22,701` bytes |
| Reproducibility status | **Remediation-gated** — not reproducible from public sources today; see the remediation runbook below |
| Machine-checkable manifest | [`deployments/reproducibility/walletwall-vault-sepolia.json`](../deployments/reproducibility/walletwall-vault-sepolia.json) (validated by `npm run validate:reproducibility`) |
| Last independently re-checked | 2026-08-23 |

Read-only Sepolia RPC checks confirmed that the deployment transaction succeeded, the
transaction created the listed vault, the observed live runtime is `20,508` bytes, and
`WalletWallVault.pqVerifier()` returns the listed verifier address. These checks confirm
the live deployment record; they do not establish source-level reproducibility.

The verifier reports `keccak256("MOCK-ML-DSA-65")`. It is
`MockMLDSAVerifier`, which performs structural checks only and provides **no real
ML-DSA verification**. This deployment is suitable only for testnet integration,
contract-flow testing, and frontend testing with Sepolia test ETH.

### Deployment provenance

This is a valid, live, and tested Sepolia deployment. However, the reported source
commit `828bf219c0e2612fcd1aba5f085c4abeba29de88` is absent from the public repository
history, and the current public HEAD recompiles `WalletWallVault` to a `22,701`-byte
runtime rather than the observed `20,508`-byte deployed runtime.

The public repository therefore does **not** currently provide a clean third-party
reproduction path for this exact deployment. This is recorded honestly rather than
papered over: the reproducibility status is **remediation-gated**, and the facts above
are captured in a machine-checkable manifest at
[`deployments/reproducibility/walletwall-vault-sepolia.json`](../deployments/reproducibility/walletwall-vault-sepolia.json).
`npm run validate:reproducibility` enforces that this deployment **cannot** be marked
`reproducible` while its reported commit is absent from public history or its runtime
bytecode differs from public HEAD.

### Reproducibility remediation runbook

Two paths can move this deployment from *remediation-gated* to *reproducible*. Pick whichever
is feasible; both end by updating this record **and** the manifest, then re-validating.

**Path A — redeploy from public HEAD (preferred; the reported commit is unpublishable):**

1. From a clean checkout of public `main`, run `npm ci` and `npm run compile`. Record the
   compiler version, optimizer settings, and the `keccak256` of the `WalletWallVault` runtime
   bytecode — this becomes `artifactManifest.bytecodeHash`.
2. Deploy `WalletWallVault` + `MockMLDSAVerifier` from public HEAD to **Ethereum Sepolia**
   (chain ID `11155111`) using the safe deploy path. Use a **funded throwaway** testnet key
   only — never a real-funds wallet. No mainnet.
3. Read the live runtime bytecode of the new address and confirm its byte length and
   `keccak256` match the locally compiled public-HEAD artifact.
4. Update this section and the manifest with the new `deployedAddress`, `deploymentTx`,
   `reportedSourceCommit` (a commit that **is** in public history), `observedRuntimeBytes`,
   and `artifactManifest`; set `reproducibilityStatus` to `reproducible`.
5. Run `npm run validate:reproducibility` and `npm run validate:deployments`; commit only
   after both pass.

**Path B — publish the exact source tag + artifact manifest:** if the exact deployment commit
can be located and published as a public tag, publish it alongside a build artifact manifest
(compiler version, settings, and the runtime bytecode `keccak256` that reproduces the deployed
`20,508`-byte runtime), then set `reproducibilityStatus` to `reproducible` with that
`artifactManifest`.

No on-chain action is performed by this documentation change. Until one path is completed,
the deployment remains a valid, live, **testnet-only research-prototype** deployment whose
source-level reproducibility is explicitly gated.

## StablecoinVaultSimulator — Sepolia deployed

The `StablecoinVaultSimulator`, `MockUSDC`, and `MockMLDSAVerifier` contracts were
deployed to Ethereum Sepolia on 2026-06-18. The metadata record is at
`deployments/sepolia/stablecoin-vault-simulator.json`.

| Field | Value |
| --- | --- |
| Network | Ethereum Sepolia |
| Chain ID | `11155111` |
| `MockUSDC` | [`0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac15`](https://sepolia.etherscan.io/address/0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac15) |
| `MockMLDSAVerifier` | [`0x4736138c99e0619D06663D971C8cD347de186F6d`](https://sepolia.etherscan.io/address/0x4736138c99e0619D06663D971C8cD347de186F6d) |
| `StablecoinVaultSimulator` | [`0x32f489842DD515Fa4b4b258714F0067B8B8133ae`](https://sepolia.etherscan.io/address/0x32f489842DD515Fa4b4b258714F0067B8B8133ae) |
| Metadata file | `deployments/sepolia/stablecoin-vault-simulator.json` |
| Deployment commit | [`35c25fa294bebea44b3089aa2435a190a5adf3fb`](https://github.com/Wallet-Wall/walletwall-vault/commit/35c25fa294bebea44b3089aa2435a190a5adf3fb) (tag `v0.4.24`) |
| Deployed package version | `0.4.24` |
| Repo package version (this PR) | `0.10.12` |
| Deployed at | `2026-06-18T20:23:48.000Z` |
| Explorer source verification | Not configured (see [Source verification](#source-verification-explorer) below — a distinct claim from reproducibility) |
| Reproducibility (from public source) | **Reproducible** — see [Reproducibility](#reproducibility) below |

**Limitations and disclosures:**

- Testnet/research prototype only. No production security guarantee.
- MockUSDC (mUSDC) has no monetary value. There is no purchase path, no custody,
  and no income-generating product or promised returns.
- MockMLDSAVerifier performs structural checks only — no real on-chain ML-DSA
  cryptographic verification.
- No mainnet deployment exists or is planned.
- No custody of real assets.
- Explorer source verification is not configured for these addresses (a distinct claim from
  reproducibility — see below).
- Reproducibility from `35c25fa294bebea44b3089aa2435a190a5adf3fb` **has** been independently
  confirmed for all three contracts, with an explicit, machine-checkable scope: see
  [Reproducibility](#reproducibility).

### Reproducibility

All executable runtime bytecode, and — for `StablecoinVaultSimulator` — all 8 EIP-712 /
`immutable` constructor-time values, were independently reproduced from public commit
`35c25fa294bebea44b3089aa2435a190a5adf3fb` (tag `v0.4.24`) and matched the live Sepolia
deployment **exactly**. Each contract has a machine-checkable manifest, validated by
`npm run validate:reproducibility`:

| Contract | Manifest | Deployment runtime bytes | Executable code match | Metadata hash match |
| --- | --- | --- | --- | --- |
| `MockUSDC` | [`deployments/reproducibility/mock-usdc-sepolia.json`](../deployments/reproducibility/mock-usdc-sepolia.json) | `1,994` | ✅ exact | ❌ excluded (see below) |
| `MockMLDSAVerifier` | [`deployments/reproducibility/mock-mldsa-verifier-sepolia.json`](../deployments/reproducibility/mock-mldsa-verifier-sepolia.json) | `569` | ✅ exact | ❌ excluded (see below) |
| `StablecoinVaultSimulator` | [`deployments/reproducibility/stablecoin-vault-simulator-sepolia.json`](../deployments/reproducibility/stablecoin-vault-simulator-sepolia.json) | `21,807` | ✅ exact (incl. all 8 immutables) | ❌ excluded (see below) |

Last independently re-checked: **2026-08-23**.

**This is a replayable claim, not a self-reported one.** Each manifest names an `evidenceFile`
under [`deployments/reproducibility/evidence/`](../deployments/reproducibility/evidence/) — a
committed bundle of raw, captured facts only (the live on-chain runtime bytecode; solc's own
`deployedBytecode.object` + `immutableReferences` from a build pinned to the deployment commit;
the same from a build at current public HEAD). It contains **no** derived verdict. Every run of
`npm run validate:reproducibility` deterministically **re-derives** the executable-code
comparison, the normalized hash, the decoded metadata boundary, and every immutable's
expected-vs-observed value from that evidence (`scripts/lib/reproducibility-evidence.ts`), and
fails if the manifest's own recorded fields disagree with the fresh recomputation. No manifest
field is ever accepted on its own say-so.
[`test/ReproducibilityEvidenceCheck.test.ts`](../test/ReproducibilityEvidenceCheck.test.ts) proves
this by mutation: it tampers with the hash, an executable byte, the metadata boundary, the
excluded-byte count, an immutable's derivation input, its observed on-chain value, its byte-range
reference, the recorded source commit, the recorded deployed address, and the live runtime code
hash — one at a time — and asserts the checker rejects every one of those ten mutations for the
correct reason.

To replay every manifest against its committed evidence yourself (offline, no network,
no toolchain — just reads the committed bundles): `npx tsx scripts/reproducibility-evidence.ts
check`. This is the same check `npm run validate:reproducibility` runs automatically; the
standalone command is useful for a quick re-verification without the rest of that validator's
output. `scripts/reproducibility-evidence.ts` also has `capture-live` (reads live on-chain
bytecode from a public RPC with provenance) and `capture-build` (records a Hardhat build already
compiled locally) subcommands — see the script's header for exact usage — which is how the
evidence bundles below were produced.

**Method (from a clean checkout pinned to the exact deployment commit, not public HEAD):**

1. Checked out `35c25fa294bebea44b3089aa2435a190a5adf3fb` in an isolated worktree, ran
   `npm ci` (the commit's own committed lockfile — Hardhat 2, solc `0.8.24+commit.e11b9ed9`,
   optimizer `runs=200`, `evmVersion=cancun`) and `npx hardhat compile`. This yields
   `reportedCommitRuntimeBytes` — the decisive figure for "reproducible from the deployment
   commit". Separately, current public HEAD (`5792975d4db331156845de72addbae95d079c0f8` at
   capture time — itself since migrated to Hardhat 3) was compiled too, giving
   `publicHeadRuntimeBytes`: a distinct, informational claim ("source hasn't drifted since the
   deployment commit"), never conflated with reproducibility against the deployment commit
   itself, since the two builds can legitimately use different toolchains. Informational, but not
   unchecked — `npm run validate:runtime-byte-claims` recompiles each subject and rejects any
   published copy of that number, in a manifest or in prose, that the compiler disagrees with.
   Both builds' `capture-build`
   step binds `sourceDigests` to the literal `content` embedded in solc's own standard-json input
   (not a separately-taken disk snapshot), so a source digest can only ever describe what solc
   actually compiled, never merely what happens to sit on disk with a matching filename —
   `sourceDigests` is independently re-verified by the checker against the claimed commit's real
   git objects (`git show`), and is the actual replayed source-binding authority. Each build
   capture also records a `compilerInputHash` — keccak256 of the full canonical compiler input,
   including dependency sources — but this is a **capture-time audit fingerprint only**: the
   committed evidence bundle does not retain the full standard-json input, so
   `validate:reproducibility` cannot independently recompute or replay `compilerInputHash`
   offline; it exists for a party who separately retains the original build-info (e.g. CI build
   artifacts) to audit against. `npm run validate:reproducibility` additionally requires
   `publicHeadBuild.headCommit` to be non-stale: it rejects the claim if any commit between that
   capture and the validating repo's current HEAD touched one of the source files it covers, even
   when the manifest and evidence agree with each other on the (stale) commit. This staleness
   check currently watches only the `sourceDigests`-covered Solidity source paths — it does not
   watch `hardhat.config.ts`, `package.json`/`package-lock.json`, or other compiler/toolchain
   configuration, so a non-stale result does not by itself guarantee current HEAD recompiles
   byte-identically under every possible toolchain/config change since that commit (tracked as a
   follow-up). It also independently re-checks that `liveRuntime.runtimeCodeHash` really is
   `keccak256(liveRuntime.runtimeBytecode)`, rather than trusting the two fields to agree because
   they were captured together.
2. Read the live runtime bytecode for all three addresses via `eth_getCode` against a public
   Sepolia RPC, and confirmed `eth_chainId` is `11155111`.
3. Decoded the trailing solc CBOR metadata region directly from the bytecode's own trailing
   2-byte length prefix (not assumed) — a genuine **53-byte** region in every case (a 2-byte
   length suffix plus a 51-byte CBOR map: `{ipfs: <34-byte multihash>, solc: <3-byte version>}`).
   Comparing live vs. locally-built bytecode, only **32 of those 53 bytes** actually differ — the
   32-byte sha256 digest inside the `ipfs` multihash; the `solc` version tag and the rest of the
   CBOR structure are byte-identical. The checker proves every differing byte lies strictly
   inside this decoded region (`excludedRange ⊆ decodedSolcMetadataRange`), not merely under an
   arbitrary count ceiling. This was cross-checked against a second, independent solc build
   variant (solc-js/WASM, not just Hardhat's downloaded native binary) to rule out a trivial
   compiler-binary cause; both local builds agree with each other and both differ from the live
   deployment in the identical way, isolated to that one region.
4. `StablecoinVaultSimulator` additionally declares one `immutable` (`token`) and inherits 7
   more from OpenZeppelin 5.6.1's `EIP712` (`_cachedDomainSeparator`, `_cachedChainId`,
   `_cachedThis`, `_hashedName`, `_hashedVersion`, `_name`, `_version`) — solc bakes these into
   fixed byte ranges of the runtime code at construction time (11 physical PUSH-site references
   across those 8 variables, since `token` is referenced 4 times), so they are necessarily
   per-deployment and cannot be produced by any fresh, differently-addressed redeploy. Instead
   of redeploying, all 8 values were **independently re-derived from public inputs only**
   (the known constructor arguments, this contract's own deployed address, chain ID `11155111`,
   and the EIP-712 domain literals `"WalletWallStablecoinVault"`/`"1"` read from source) and
   confirmed to match the live on-chain bytes exactly, byte for byte — each with its own
   identity, derivation method, and expected/observed values recorded in the evidence bundle,
   not folded into a single hand-set boolean.

**What this claim does and does not cover:** "Reproducible" here means every byte the EVM
actually executes — the full contract logic, and every immutable constructor value — is
proven to come from the public commit above. It explicitly **excludes** the 32 differing
metadata-hash bytes (out of a 53-byte decoded region), which are not code and do not affect
on-chain behavior; those are recorded as excluded (`metadataHashMatch: false`,
`metadataTrailerBytesExcluded: 32`) rather than silently ignored, in every manifest.

### Source verification (explorer)

None of the three addresses are marked "verified" on a public explorer today. Explorer source
verification and source-level reproducibility (above) are **distinct claims**: verification
publishes source to a specific explorer/UI for human/API browsing, while this repo's
reproducibility record is an independent, machine-checkable comparison against public git
history. Given the confirmed compiler settings above, explorer verification for all three
addresses is a low-risk, deterministic follow-up (flatten or standard-JSON-input verify via
`hardhat-verify`/Etherscan or Sourcify using solc `0.8.24`, optimizer `runs=200`,
`evmVersion=cancun`, source commit `35c25fa294bebea44b3089aa2435a190a5adf3fb`); it requires an
explorer API key to actually submit and is intentionally **not** performed by this record.

### Safe deployment path: the deploy-only script

Use **`scripts/deploy-simulator.ts`** (npm: `deploy:simulator` / `deploy:simulator:sepolia`).
It is a **deploy-only** script — it deploys the contracts and stops. It performs **no**
faucet, approve, deposit, withdraw, vault-creation, or other demo/state transactions, and
it never reads, prints, or persists your private key.

What it deploys (MockUSDC mode only):

1. `MockUSDC` — the `mUSDC` test token (6 decimals, freely mintable, **no monetary value**).
2. `MockMLDSAVerifier` — the PQ gate (structural checks only, **no real on-chain ML-DSA
   verification**).
3. `StablecoinVaultSimulator` — wired to the MockUSDC token and the mock verifier.

The policy engine, large-transaction/governance timelock, and guardian recovery are **not**
separate deployed contracts: the policy engine is optional and wired post-deploy through the
governance-delayed `proposePolicyEngine` flow, the delay is an in-contract constant, and
recovery guardians are configured per-vault by vault owners. They therefore remain `null`
in the deployment metadata.

The script **hard-fails** on unsupported networks, refuses any chain ID it recognises as a
mainnet, and aborts before sending a transaction if the RPC's chain ID does not match the
expected testnet chain ID (a guard against a misconfigured RPC URL).

> `scripts/demo-simulator.ts` (`npm run demo:simulator`) is a **local/demo walkthrough only**.
> It requires two signers and exercises deposits/withdrawals — it is **not** the safe Sepolia
> deployment path. Do not point it at Sepolia.

### `.env` setup (never commit this file)

The repo ships a `.env.example`. Copy it to `.env` (which is git-ignored) and fill in your
own values locally:

```sh
cp .env.example .env
# then edit .env:
#   DEPLOYER_PRIVATE_KEY=<your funded THROWAWAY Sepolia testnet key>
#   SEPOLIA_RPC_URL=<your Sepolia RPC endpoint>   # optional; a public default exists
```

`hardhat.config.ts` loads `.env` automatically (via `import "dotenv/config"`), so the
values above are picked up by `hardhat run` / the `npm run deploy:*` scripts without any
extra step — you do **not** need to export them into your shell. (If you prefer, exporting
them as real environment variables still works and takes precedence.)

Never commit `.env`, a private key, a mnemonic, an RPC URL, or any other secret. The
deployer must be a **funded throwaway** testnet wallet holding only a small amount of
**Sepolia test ETH** — never a wallet that controls real funds.

### Running the Sepolia deployment (operator, locally)

```sh
# Print metadata to stdout only (does not write or commit anything):
npm run deploy:simulator:sepolia

# Or persist metadata to a file for review + validation:
DEPLOYMENT_METADATA_OUT=deployments/sepolia/stablecoin-vault-simulator.json \
  npm run deploy:simulator:sepolia
```

After a successful deploy, **inspect** the generated metadata, run
`npm run validate:deployments`, and only then commit the metadata file (and an update to
this section) in a follow-up PR. **Do not commit metadata before a deployment succeeds, and
never fabricate or copy-paste addresses.** If a deploy fails, commit nothing.

### Operator checklist

- [ ] Create a **throwaway** deployer wallet — do not reuse any wallet that holds real value.
- [ ] Fund it with a **small** amount of Sepolia test ETH only (from a faucet).
- [ ] Never use a main wallet, real private key, or real-funds mnemonic.
- [ ] Confirm `.env` is git-ignored and contains no committed secrets.
- [ ] Verify the network/RPC before running (the script aborts on a chain-ID mismatch or any
      mainnet, but check anyway).
- [ ] Run `npm run deploy:simulator:sepolia` and watch for a clean, successful run.
- [ ] **Inspect** the emitted metadata (addresses, `chainId` 11155111, `deploymentCommit`,
      `deployedAt`) before saving it.
- [ ] Run `npm run validate:deployments` after the metadata file is generated.
- [ ] Commit the metadata + this doc update only after the deployment succeeds and validates.

**Limitations (record these when this section is filled):**

- MockUSDC is freely mintable — no value, no purchase path, no custody, no yield.
- No yield, interest, APY, APR, returns, rewards, payout, or profit of any kind.
- PQ gate uses `MockMLDSAVerifier` — ML-DSA is **not verified on-chain**.
- Simulator is a research prototype; it is not audited and makes no production claims.
- Fee-on-transfer / rebasing tokens are explicitly unsupported by the vault accounting.
- No mainnet deployment exists or is planned for this contract.

## Deprecated Ethereum Sepolia deployment

The older Sepolia deployment commonly referenced as `0x8c5B...CF24` (and sometimes
mistyped as `0x8cB5...`) is **deprecated and stale. Do not reuse it.**

Reasons:

- its historical runtime did not match the current `WalletWallVault` artifact; and
- the old vault was created with a 32-byte PQ key instead of an ML-DSA-65 public key.

It must not be used as a frontend default, deployment fallback, verification target, or
source of assumptions about the current contract state.

## Testnet usage

- Use Sepolia test ETH only.
- Do not send real funds.
- Frontend writes must remain testnet-only and explicitly gated to supported chain IDs.
- This repository documents no Ethereum mainnet deployment.
- No native ML-DSA/PQ precompile is live or used by these deployments.
