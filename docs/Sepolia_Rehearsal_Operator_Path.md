# Sepolia Rehearsal Operator Path

> **Research prototype. Not audited. Testnet only. Do not use real funds.**
> No yield, interest, APY, returns, or income of any kind.
> No mainnet deployment. No production custody. No real stablecoins.
> No quantum-proof or audited claims. No agent receives secrets.

This document describes the complete operator path for running a
`StablecoinVaultSimulator` rehearsal on Ethereum Sepolia. It is intended for:

- Operators deploying or re-deploying the simulator stack to Sepolia.
- The private WalletWall app, which reads simulator status and metadata
  read-only and must surface disclosures before any write interaction.
- Developers who need to understand what the simulator is and is not
  before integrating or referencing it.

See [`Operator_Checklist_Simulator.md`](Operator_Checklist_Simulator.md)
for the step-by-step operator checklist. See
[`docs/specs/testnet-stablecoin-vault-simulator.md`](specs/testnet-stablecoin-vault-simulator.md)
for the full implementation spec.

---

## 1. What the simulator is

The `StablecoinVaultSimulator` is a **testnet-only research prototype** that
mirrors the hybrid classical (ECDSA) + post-quantum (PQ) withdrawal-authorization
model of `WalletWallVault` over a single ERC-20 test token instead of ETH.

Its purpose is to let operators and app users **rehearse** a quantum-resistant
stablecoin vault migration path on a public testnet using mock funds and a mock
PQ gate — so the flow is familiar before any real-asset or production system
ever exists.

The simulator stack deployed to Sepolia consists of three contracts:

| Contract | Address (Sepolia) | Role |
| --- | --- | --- |
| `MockUSDC` | `0x8ffc8cE04789e9a7b53685a2d78CDa54E6Faac15` | Freely mintable mock token (mUSDC, no monetary value) |
| `MockMLDSAVerifier` | `0x4736138c99e0619D06663D971C8cD347de186F6d` | Structural-only PQ gate (no real on-chain ML-DSA) |
| `StablecoinVaultSimulator` | `0x32f489842DD515Fa4b4b258714F0067B8B8133ae` | ERC-20-aware vault wired to both of the above |

The canonical metadata record is at
[`deployments/sepolia/stablecoin-vault-simulator.json`](../deployments/sepolia/stablecoin-vault-simulator.json).

### What the simulator exercises

- ERC-20 `approve` + `deposit` flow (user funds their own vault record).
- EIP-712-authorized `withdraw` / `queueWithdrawal` → `finalizeWithdrawal` flow.
- PQ attestation gate (`IPQCVerifier` boundary) — mock verifier for local/testnet.
- Optional policy engine (`IPolicyEngine`, `CompositePolicyEngine`, spend limits, allowlists).
- Large-transaction timelock and governance timelocks.
- Guardian recovery and treasury quorum.

The rehearsal teaches *governance and authorization*, not just deposit/withdraw.
Users see what authorizing a quantum-resistant withdrawal actually looks like —
with a mock stablecoin-shaped asset — before any production system exists.

---

## 2. What the simulator is NOT

These constraints are hard requirements, not caveats. They must never be relaxed
or implied away in docs, app copy, or code.

| Claim / capability | Status |
| --- | --- |
| Real stablecoins (USDC, USDT, DAI, etc.) | **Never** |
| Real monetary value of any kind | **Never** |
| Mainnet deployment | **Never** — deploy script hard-fails on all mainnet chain IDs |
| Production custody of assets | **Never** |
| Yield, interest, APY, APR, returns, rewards, payout | **Never** |
| On-chain ML-DSA / quantum-proof verification | **Not in this simulator** — PQ gate is a mock |
| Audited contract | **Not audited** |
| "Quantum-safe," "quantum-proof," "audited" claim | **Not applicable** |
| Fee-on-transfer / rebasing token support | **Explicitly unsupported** |
| Multi-asset vault (multi-token) | **Not in this MVP** |

See
[`docs/WALLETWALL_APP_BOUNDARY.md`](WALLETWALL_APP_BOUNDARY.md)
§"What the App Should Avoid Saying" for the full list of overclaim vocabulary
to avoid in any app surface that references this simulator.

---

## 3. Allowed networks

The deploy script (`scripts/deploy-simulator.ts`) enforces a three-layer
hard-fail before sending any transaction:

1. **Network allowlist** — only `hardhat`, `localhost`, `sepolia`, and
   `base-sepolia` are accepted. Any other Hardhat network name causes an
   immediate `Error` with no transaction sent.

2. **Mainnet chain-ID blocklist** — the script reads the live chain ID from the
   RPC before deploying and refuses to continue if it matches any of:

   | Chain ID | Network |
   | --- | --- |
   | 1 | Ethereum mainnet |
   | 8453 | Base mainnet |
   | 137 | Polygon mainnet |
   | 10 | Optimism mainnet |
   | 42161 | Arbitrum One mainnet |
   | 56 | BNB Smart Chain mainnet |
   | 43114 | Avalanche C-Chain mainnet |

3. **Expected chain-ID check** — even if the network name is allowed, the live
   chain ID must equal the expected value for that network (31337 for local,
   11155111 for Sepolia, 84532 for Base Sepolia). A misconfigured RPC URL that
   points at a different network causes an `Error` before any gas is spent.

These checks are inside `main()` in `scripts/deploy-simulator.ts`. Do not remove
or bypass them.

Supported deployment targets and their canonical npm scripts:

| Target | npm script | Notes |
| --- | --- | --- |
| Hardhat in-memory | `npm run deploy:simulator` | No persistent state; use for local testing |
| Local Hardhat node | `npm run deploy:simulator -- --network localhost` | Requires a running `npx hardhat node` |
| Ethereum Sepolia | `npm run deploy:simulator:sepolia` | **Primary testnet target** |
| Base Sepolia | (add `--network base-sepolia`) | Secondary testnet target |

---

## 4. Required environment variables

Copy `.env.example` to `.env` (git-ignored) and populate before running any
deploy or Sepolia-targeting script. `hardhat.config.ts` loads `.env`
automatically via `dotenv/config`; you do not need to export variables into your
shell.

```sh
cp .env.example .env
# edit .env — see descriptions below
```

| Variable | Required for Sepolia | Description |
| --- | --- | --- |
| `DEPLOYER_PRIVATE_KEY` | Yes | 64-hex private key of the **throwaway** deployer wallet. Must be funded only with Sepolia test ETH. Never a wallet holding real funds. |
| `SEPOLIA_RPC_URL` | Optional | Sepolia JSON-RPC endpoint. Defaults to a public node if unset. Set to a private RPC for reliability. |
| `BASE_SEPOLIA_RPC_URL` | Only for Base Sepolia | Base Sepolia JSON-RPC endpoint. |
| `DEPLOYMENT_METADATA_OUT` | Optional | Relative path under the repo root where the deploy script writes the metadata JSON (e.g. `deployments/sepolia/stablecoin-vault-simulator.json`). If unset, metadata is printed to stdout only. |
| `PQC_VERIFIER_ADDRESS` | Optional | Reuse a verifier from a partial/prior deployment instead of paying to re-deploy it. Leave empty to deploy a fresh `MockMLDSAVerifier`. |

Never set `DEPLOYMENT_METADATA_OUT` to a path outside the repo's `deployments/`
directory tree. Never commit a populated `.env` file.

---

## 5. Safe operator key handling

The Sepolia deployment requires a funded throwaway key. Follow these rules without
exception:

- **Throwaway wallet only.** Generate a fresh wallet exclusively for this
  deployment (e.g. `cast wallet new` or any standard keygen tool). Do not reuse
  an existing wallet.
- **No real funds on this key, ever.** Fund it only with a small amount of
  Sepolia test ETH from a public faucet (see [sepoliafaucet.com](https://sepoliafaucet.com)
  or [faucets.chain.link](https://faucets.chain.link/sepolia)). Never transfer
  mainnet ETH, ERC-20s, or any real-value asset to this key.
- **Set in `.env`, never committed.** Store the key in your local `.env` file
  (git-ignored). Never paste it into a PR, issue, commit message, comment, or
  chat.
- **No agent or CI secret access.** Never configure this key in CI environment
  variables or pass it to any agent, tool, or external service. This is a
  local-operator-only operation.
- **Treat as burned after use.** Once the deployment is done, treat the key as
  compromised and do not reuse it. Any remaining Sepolia test ETH can be left
  or discarded — it has no monetary value.
- **Rotate if exposed.** If the key ever appears in a log, output, or commit,
  generate a new throwaway key and re-deploy rather than attempting to "clean"
  the exposed one.

The deploy script never reads, prints, or persists the private key value itself.
It accesses the key only through `ethers.Wallet(key, provider)` and logs only
the derived public deployer address.

---

## 6. How deployment metadata is produced

The deploy script (`scripts/deploy-simulator.ts`) is **deploy-only**. It:

1. Validates the network and chain ID (see §3).
2. Deploys `MockUSDC`, `MockMLDSAVerifier`, and `StablecoinVaultSimulator`
   in sequence, waiting for each transaction to be mined.
3. Reads the on-chain block timestamp from the simulator's deployment
   transaction receipt.
4. Assembles a schema-shaped JSON metadata object and prints it to stdout.
5. If `DEPLOYMENT_METADATA_OUT` is set, also writes the JSON to that file path.

The metadata shape is versioned (`"version": "1"`) and validated by
`scripts/validate-deployments.ts` (run: `npm run validate:deployments`).
See [`deployments/schema/simulator-deployment.schema.json`](../deployments/schema/simulator-deployment.schema.json)
for the full field specification.

The script does **not** perform any faucet call, approval, deposit, withdrawal,
vault creation, or other state transaction. It deploys contracts and stops.

After a successful deployment:

```sh
# 1. Inspect the generated metadata (example path):
cat deployments/sepolia/stablecoin-vault-simulator.json

# 2. Validate the metadata file:
npm run validate:deployments

# 3. Update docs/Deployments.md with the new record, then open a PR.
```

The metadata file must be committed only in a dedicated follow-up PR (never
pre-filled before the deployment succeeds, never with fabricated or copy-pasted
addresses).

### Metadata fields the app cares about

| Field | Type | App usage |
| --- | --- | --- |
| `environment` | `"sepolia" \| "base-sepolia" \| "local"` | Gate which network the simulator is on |
| `chainId` | `number` | Confirm the app is on the correct network before any write |
| `stablecoinVaultSimulatorAddress` | `string \| null` | Primary contract address |
| `tokenAddress` | `string \| null` | MockUSDC address (mUSDC, no value) |
| `verifierAddress` | `string \| null` | MockMLDSAVerifier address |
| `tokenSymbol` | `string \| null` | `"mUSDC"` — always display this label, never "USDC" |
| `tokenMode` | `"mock"` | Assert this is always `"mock"` before any write |
| `warnings` | `string[]` | Surface at least one to the user before any write interaction |
| `deployedAt` | `string \| null` | ISO 8601 deployment timestamp (informational only) |
| `docsUrl` | `string \| null` | Link to the spec doc |

---

## 7. How the private app consumes metadata read-only

The app may read `deployments/sepolia/stablecoin-vault-simulator.json` as static
metadata. It must do so defensively:

**Do:**
- Read the JSON file as static, versioned metadata.
- Assert `tokenMode === "mock"` before any write interaction.
- Assert `chainId === 11155111` (or the expected testnet chain ID) before any write.
- Surface at least one string from the `warnings` array to the user before any
  write interaction with the simulator.
- Treat all address fields as potentially stale; perform on-chain checks before
  any write.
- Label the simulator as "testnet / research prototype" in all UI copy.
- Label the PQ gate as "mock" or "structural-only" — never "quantum-proof" or
  "on-chain ML-DSA."
- Label the token as `mUSDC` or "mock USDC (no monetary value)" — never "USDC."

**Do not:**
- Infer that the simulator is reachable, live, funded, or unpaused from metadata
  alone.
- Treat a non-null address as proof that the contract is ready for transactions.
- Use metadata as a substitute for on-chain reads before any write.
- Store or re-publish addresses without linking to this repository as the
  canonical source.
- Imply yield, interest, APY, returns, rewards, payout, or income from any
  simulator surface.
- Imply custody, production-grade security, or mainnet availability.

A TypeScript consumer pattern:

```ts
import metadata from "./deployments/sepolia/stablecoin-vault-simulator.json";

// Hard gates before any write:
if (metadata.tokenMode !== "mock") throw new Error("Non-mock token not allowed");
if (metadata.chainId !== 11155111) throw new Error("Wrong network");
if (!metadata.stablecoinVaultSimulatorAddress) throw new Error("Simulator not deployed");

// Surface disclosure:
const disclosure = metadata.warnings[0]; // show to user before any write

// On-chain check (pseudo-code — perform before any write):
// const contract = new ethers.Contract(metadata.stablecoinVaultSimulatorAddress, abi, provider);
// const paused = await contract.paused();
// if (paused) throw new Error("Simulator is paused");
```

See [`deployments/examples/app-status.example.json`](../deployments/examples/app-status.example.json)
for a concrete example of what a consuming app should derive and assert.

---

## 8. Safety invariants summary

These invariants must hold at all times. If any of them is violated, stop and
investigate before continuing.

- No real funds are ever at risk. MockUSDC (mUSDC) has zero monetary value.
- No mainnet transaction is ever sent. The deploy script aborts before any
  mainnet transaction.
- No production custody relationship is established. The simulator is a research
  prototype.
- No yield, interest, APY, APR, returns, rewards, payout, or profit of any kind
  is generated or implied.
- No quantum-proof claim is made. The PQ gate is `MockMLDSAVerifier` (structural
  checks only) — ML-DSA is not verified on-chain.
- No agent, CI system, or external service receives the deployer private key.
- No deployer private key is ever committed to this repository or logged to
  stdout.
- No user is ever shown "USDC" for the mock token — always `mUSDC` or
  "mock USDC (no monetary value)."

---

## 9. Related documents

| Document | Location | Purpose |
| --- | --- | --- |
| Operator checklist | [`docs/Operator_Checklist_Simulator.md`](Operator_Checklist_Simulator.md) | Step-by-step deployment and safety checklist |
| Implementation spec | [`docs/specs/testnet-stablecoin-vault-simulator.md`](specs/testnet-stablecoin-vault-simulator.md) | Full contract boundary spec |
| Deployment records | [`docs/Deployments.md`](Deployments.md) | Canonical deployment record table |
| Deployment metadata dir | [`deployments/`](../deployments/) | Versioned JSON metadata files |
| Deployment metadata schema | [`deployments/schema/simulator-deployment.schema.json`](../deployments/schema/simulator-deployment.schema.json) | JSON Schema v1 |
| App status example | [`deployments/examples/app-status.example.json`](../deployments/examples/app-status.example.json) | App consumption pattern |
| App boundary | [`docs/WALLETWALL_APP_BOUNDARY.md`](WALLETWALL_APP_BOUNDARY.md) | Overclaim vocabulary and integration rules |
| Security assumptions | [`docs/Security_Assumptions.md`](Security_Assumptions.md) | Threat model and security posture |
| Attestation verifier | [`docs/Attestation_Verifier.md`](Attestation_Verifier.md) | Trusted attestor vs. on-chain ML-DSA |
