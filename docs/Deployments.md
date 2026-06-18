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
| Current public HEAD runtime | `22,138` bytes |
| Reproducibility status | **Pending public artifact/source alignment** |
| Last independently re-checked | 2026-06-15 |

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
history, and the current public HEAD recompiles `WalletWallVault` to a `22,138`-byte
runtime rather than the observed `20,508`-byte deployed runtime.

The public repository therefore does **not** currently provide a clean third-party
reproduction path for this exact deployment. Reproducibility remains pending an aligned
public source tag and artifact manifest.

**Follow-up TODO:** publish the exact deployment source commit/tag and artifact manifest,
or redeploy from public HEAD and update this deployment record with the replacement
address, transaction, source tag, and runtime.

## StablecoinVaultSimulator — not yet deployed to testnet

The `StablecoinVaultSimulator` and `MockUSDC` contracts introduced in v0.4.22 have
**not yet been deployed** to Sepolia or Base Sepolia. No deployment was performed in the
change that added the deploy-only tooling below — there are no Sepolia addresses to record
yet. This section, and a metadata record under `deployments/`, will be filled in **only
after** an operator runs the deploy locally and verifies the output (see below).

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
