# Operator Checklist — Stablecoin Vault Simulator (Sepolia)

> **Research prototype. Not audited. Testnet only. Do not use real funds.**
> No yield, interest, APY, returns, or income of any kind.
> No mainnet deployment. No production custody. No real stablecoins.
> No quantum-proof or audited claims. No agent receives secrets.

This checklist covers the full operator lifecycle for the
`StablecoinVaultSimulator` on Ethereum Sepolia. Complete each phase in order.
Do not skip items. If an item fails or a gate check returns an unexpected result,
stop and investigate before continuing to the next item.

See [`docs/Sepolia_Rehearsal_Operator_Path.md`](Sepolia_Rehearsal_Operator_Path.md)
for narrative explanations of each phase.

---

## Phase 0 — Safety confirmation

Read and confirm each statement before proceeding:

- [ ] I understand this simulator uses **MockUSDC (mUSDC)**, which has no
      monetary value. No real stablecoins are ever involved.
- [ ] I understand the PQ gate (`MockMLDSAVerifier`) performs structural checks
      only — **no real on-chain ML-DSA verification**.
- [ ] I understand this simulator targets **Ethereum Sepolia only**. There is no
      mainnet deployment and the deploy script hard-fails on any mainnet chain ID.
- [ ] I will not claim this simulator is audited, quantum-proof, or
      production-ready.
- [ ] I will not imply yield, interest, APY, APR, returns, rewards, payout, or
      profit of any kind.
- [ ] I will not store the deployer private key anywhere other than a local,
      git-ignored `.env` file.
- [ ] I will not pass the deployer private key to any agent, CI system, or
      external service.

---

## Phase 1 — Preflight

### 1a. Environment setup

- [ ] Confirm Node.js ≥ 18 and npm ≥ 9 are installed.
- [ ] Clone the repository (or pull the latest `main`).
- [ ] Run `npm install` to install dependencies.
- [ ] Confirm the repo builds cleanly: `npm run compile`.
- [ ] Confirm tests pass on the in-memory Hardhat network: `npm test`.

### 1b. Throwaway deployer wallet

- [ ] Generate a **new, dedicated throwaway wallet** for this deployment.
  - Do NOT reuse any wallet that holds real ETH, ERC-20s, or any real-value
    asset.
  - Do NOT use a hardware wallet or a wallet associated with production funds.
  - Suggested: `cast wallet new` (Foundry) or any standard keygen tool.
- [ ] Record only the throwaway wallet address (public) — keep the private key
      offline except where `DEPLOYER_PRIVATE_KEY` is set in `.env`.
- [ ] Fund the throwaway wallet with a **small** amount of Sepolia test ETH
      only:
  - [sepoliafaucet.com](https://sepoliafaucet.com)
  - [faucets.chain.link/sepolia](https://faucets.chain.link/sepolia)
  - 0.1–0.2 Sepolia test ETH is sufficient for three contract deployments.
- [ ] Confirm the faucet transfer is confirmed on Sepolia before continuing.

### 1c. Environment file

- [ ] Copy `.env.example` to `.env` in the repo root:
  ```sh
  cp .env.example .env
  ```
- [ ] Open `.env` and set:
  - `DEPLOYER_PRIVATE_KEY=<64-hex private key of the throwaway wallet>`
  - `SEPOLIA_RPC_URL=<your Sepolia RPC endpoint>` (optional; a public default
    exists but a private RPC is more reliable)
- [ ] Confirm `.env` is listed in `.gitignore`:
  ```sh
  git check-ignore .env && echo "IGNORED — OK" || echo "NOT IGNORED — STOP"
  ```
  If the output is not `IGNORED — OK`, stop and fix `.gitignore` before
  continuing.
- [ ] Confirm `DEPLOYER_PRIVATE_KEY` does not appear in any tracked file:
  ```sh
  git grep -r "DEPLOYER_PRIVATE_KEY=" --cached || echo "Clean — OK"
  ```

### 1d. Network sanity check

- [ ] Confirm the Sepolia RPC is reachable and returns the expected chain ID.
  You can use `cast chain-id --rpc-url <SEPOLIA_RPC_URL>` or a curl to the RPC.
  Expected result: `11155111`.
- [ ] Confirm the throwaway deployer address has a non-zero Sepolia ETH balance:
  ```sh
  cast balance <deployer_address> --rpc-url <SEPOLIA_RPC_URL>
  ```

---

## Phase 2 — Deploy

### 2a. Dry run (stdout only — recommended first)

Run the deploy script **without** setting `DEPLOYMENT_METADATA_OUT` so that
metadata is printed to stdout only and nothing is written to disk:

```sh
npm run deploy:simulator:sepolia
```

- [ ] Script starts without an immediate error.
- [ ] Output shows `Network: sepolia` and `Chain ID: 11155111`.
- [ ] Deployer address matches the throwaway wallet address.
- [ ] Balance line shows non-zero Sepolia test ETH.
- [ ] All three contracts deploy successfully with valid `0x...` addresses.
- [ ] The printed metadata JSON contains:
  - `"environment": "sepolia"`
  - `"chainId": 11155111`
  - `"tokenMode": "mock"`
  - `"tokenSymbol": "mUSDC"`
  - Non-null `tokenAddress`, `stablecoinVaultSimulatorAddress`, `verifierAddress`
  - `"warnings"` array with at least one entry

> If the dry run fails, do not proceed to 2b. Investigate and fix.

### 2b. Persist metadata (write to file)

If the dry run succeeded, run again with `DEPLOYMENT_METADATA_OUT` set to
persist the metadata to the standard path:

```sh
DEPLOYMENT_METADATA_OUT=deployments/sepolia/stablecoin-vault-simulator.json \
  npm run deploy:simulator:sepolia
```

- [ ] Script completes with exit code 0.
- [ ] Output shows "Metadata written" followed by the file path.
- [ ] The metadata file now exists at
      `deployments/sepolia/stablecoin-vault-simulator.json`.

> **Important:** Do not run the deploy command a second time with the same
> `DEPLOYMENT_METADATA_OUT` unless you intend to overwrite the record with a
> fresh deployment. If the file already contains valid addresses from a prior
> deploy, overwriting it without a real re-deployment would create a false
> record.

---

## Phase 3 — Verify metadata

### 3a. Inspect the metadata file

Open `deployments/sepolia/stablecoin-vault-simulator.json` and verify:

- [ ] `"environment"` is `"sepolia"`.
- [ ] `"chainId"` is `11155111`.
- [ ] `"tokenMode"` is `"mock"`.
- [ ] `"tokenSymbol"` is `"mUSDC"`.
- [ ] `"tokenAddress"` is a non-null `0x`-prefixed 40-hex address.
- [ ] `"stablecoinVaultSimulatorAddress"` is a non-null `0x`-prefixed 40-hex
      address.
- [ ] `"verifierAddress"` is a non-null `0x`-prefixed 40-hex address.
- [ ] `"deploymentCommit"` is a 40-character hex SHA (matches your local
      `git rev-parse HEAD`).
- [ ] `"deployedAt"` is a plausible ISO 8601 timestamp close to the current UTC
      time.
- [ ] `"warnings"` is a non-empty array of strings.
- [ ] No fields other than those defined in the schema are present.

### 3b. Run the schema validator

```sh
npm run validate:deployments
```

- [ ] Exits 0 (`1 passed, 0 failed`).
- [ ] No `[error]` lines in the output.
- [ ] Any `[warning]` lines are expected for a newly deployed record; read them.

### 3c. Optional — On-chain confirmation

You can confirm the deployment on-chain using Etherscan or curl:

```sh
# Check the simulator contract has code:
cast code <stablecoinVaultSimulatorAddress> --rpc-url <SEPOLIA_RPC_URL>
# Expected: non-empty bytecode

# Confirm the token address stored in the simulator:
cast call <stablecoinVaultSimulatorAddress> "token()(address)" \
  --rpc-url <SEPOLIA_RPC_URL>
# Expected: matches tokenAddress in the metadata

# Confirm the verifier algorithm ID:
cast call <verifierAddress> "algorithmId()(bytes32)" \
  --rpc-url <SEPOLIA_RPC_URL>
# Expected: keccak256("MOCK-ML-DSA-65")
```

- [ ] On-chain contract code is non-empty.
- [ ] `token()` on the simulator returns the `tokenAddress` from metadata.

---

## Phase 4 — Publish status / commit metadata

### 4a. Update Deployments.md

Open `docs/Deployments.md` and update the `StablecoinVaultSimulator — Sepolia`
section with:

- [ ] The three contract addresses (from the metadata file).
- [ ] The `deploymentCommit` value.
- [ ] The `deployedAt` timestamp.
- [ ] The current `packageVersion`.
- [ ] A note that source verification is not configured (until it is).

### 4b. Open a PR

- [ ] Stage only the metadata file and the `Deployments.md` update — nothing
      else.
  ```sh
  git add deployments/sepolia/stablecoin-vault-simulator.json
  git add docs/Deployments.md
  git commit -m "chore: record Sepolia simulator deployment (package vX.Y.Z)"
  ```
- [ ] Open a PR targeting `main`. PR title must clearly state it is a Sepolia
      deployment record.
- [ ] PR description must include the deployer address (public key only, never
      the private key), the three contract addresses, and the standard disclaimer:
      "Testnet only — no real funds, no custody, no yield, no mainnet."
- [ ] Request review before merging.

### 4c. App read-only consumption

Once the PR is merged and the metadata file is in `main`:

- [ ] Confirm the app (private repo) reads the file from the canonical GitHub
      URL or a local copy, not from an in-repo copy.
- [ ] Confirm the app asserts `tokenMode === "mock"` before any write.
- [ ] Confirm the app asserts `chainId === 11155111` before any write.
- [ ] Confirm the app shows at least one `warnings` entry to the user before any
      write interaction.
- [ ] Confirm the app labels the token as `mUSDC` (not "USDC") and the simulator
      as "testnet research prototype."

---

## Phase 5 — Rollback / cleanup

### 5a. If the deployment failed

- [ ] Do NOT commit any metadata file.
- [ ] Delete any partially written metadata file:
  ```sh
  rm -f deployments/sepolia/stablecoin-vault-simulator.json
  ```
- [ ] Investigate the error (gas, RPC, network mismatch, etc.).
- [ ] Fix the root cause and return to Phase 1.

### 5b. If the deployment succeeded but the metadata is wrong

- [ ] Do NOT commit the metadata file.
- [ ] Delete it and re-deploy from scratch (a new set of contracts):
  ```sh
  rm deployments/sepolia/stablecoin-vault-simulator.json
  # Return to Phase 2 — new addresses will be produced
  ```
- [ ] There is no on-chain rollback for deployed contracts. A failed or
      misconfigured deploy simply results in unused contracts on Sepolia, which
      is acceptable because Sepolia test ETH has no monetary value.

### 5c. Deployer key cleanup

- [ ] After the deployment is committed and verified, treat the deployer private
      key as burned.
- [ ] Clear the `DEPLOYER_PRIVATE_KEY` value from `.env` (or delete `.env`
      entirely):
  ```sh
  sed -i 's/^DEPLOYER_PRIVATE_KEY=.*/DEPLOYER_PRIVATE_KEY=/' .env
  # or simply: rm .env
  ```
- [ ] Do not reuse the throwaway wallet for future deployments.
- [ ] Any remaining Sepolia test ETH on the throwaway wallet can be left or
      discarded — it has no monetary value.

### 5d. If the private key is exposed

If the throwaway key ever appears in a log, PR, commit, chat message, or any
output:

- [ ] Treat it as compromised immediately.
- [ ] Generate a new throwaway wallet.
- [ ] Re-deploy from the new wallet.
- [ ] Open a separate PR to update the metadata to the new contract addresses.
- [ ] Do NOT attempt to "clean" a git history that contains a private key without
      expert guidance, as the git reflog and remote history may retain it.

---

## Phase 6 — Ongoing safety checks

Run these checks whenever the simulator metadata or deploy scripts are touched:

- [ ] `npm test` — all tests must pass on the in-memory Hardhat network.
- [ ] `npm run validate:deployments` — all deployment records must validate.
- [ ] `npm run lint` — Solidity linting must pass.
- [ ] `npm run format:check` — formatting must be correct.
- [ ] Confirm that no mainnet chain ID appears in any deployment record.
- [ ] Confirm that no private key, mnemonic, or RPC credential appears in any
      tracked file (`git grep -r "DEPLOYER_PRIVATE_KEY=" --cached`).
- [ ] Confirm that `deploy-simulator.ts` still contains all three network safety
      checks (allowlist, mainnet blocklist, chain-ID check).
- [ ] Confirm that the `warnings` array in each metadata file is non-empty and
      includes at least one testnet-only disclosure string.

---

## Quick reference — key commands

```sh
# Install dependencies
npm install

# Compile contracts
npm run compile

# Run all tests (in-memory Hardhat)
npm test

# Run Sepolia deploy (stdout only — dry run)
npm run deploy:simulator:sepolia

# Run Sepolia deploy (persist metadata)
DEPLOYMENT_METADATA_OUT=deployments/sepolia/stablecoin-vault-simulator.json \
  npm run deploy:simulator:sepolia

# Validate all deployment metadata files
npm run validate:deployments

# Lint Solidity
npm run lint

# Check formatting
npm run format:check

# Local simulator demo (in-memory Hardhat only — NOT safe for Sepolia)
npm run demo:simulator
```

---

## Scope and limitations

This checklist covers **deployment and metadata management** only.

| In scope | Out of scope |
| --- | --- |
| Operator deploy path | Demo/user deposit-withdraw flows (`demo:simulator`) |
| Metadata commit workflow | PQ verifier implementation (`AttestationPQCVerifier`) |
| App read-only metadata consumption | ZK prover / SP1 guest code |
| Rollback and key cleanup | Attestation signing logic |
| Ongoing safety checks | Contract source code changes |

For the demo (local walkthrough) see `scripts/demo-simulator.ts` and run it
with `npm run demo:simulator` on a local Hardhat network only — not against
Sepolia, as it requires two local signers.

For attestation and PQ verifier operator guidance see
[`docs/PQ_Verifier_Operator_Guide.md`](PQ_Verifier_Operator_Guide.md) and
[`docs/Attestation_Verifier.md`](Attestation_Verifier.md).
