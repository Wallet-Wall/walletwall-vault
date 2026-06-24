# StablecoinVaultSimulator — Deployment Metadata

> Research prototype. Not audited. Testnet only. Do not use real funds.

This directory holds versioned static deployment metadata for `StablecoinVaultSimulator`.

## Directory layout

```
deployments/
  schema/
    simulator-deployment.schema.json   — JSON Schema v1 for all metadata files
  examples/
    simulator.local.example.json       — annotated example (NOT a deployment record)
  reproducibility/
    schema/reproducibility.schema.json — JSON Schema v1 for reproducibility manifests
    <subject>-<network>.json           — reproducibility manifests (validated separately)
  simulator.<network>.json             — live deployment records (added post-deployment)
  README.md                            — this file
```

Files under `schema/`, `examples/`, and `reproducibility/` are excluded from
`npm run validate:deployments`. Reproducibility manifests have their own shape and are
checked by `npm run validate:reproducibility` (see
[Reproducibility manifests](#reproducibility-manifests) below).

## Rules for deployment records

### Addresses MUST remain null until deployed

Every contract address field (`tokenAddress`, `stablecoinVaultSimulatorAddress`,
`verifierAddress`, `policyEngineAddress`, `timelockAddress`, `recoveryAddress`) **must be
`null`** in any file committed to this repository until the corresponding deployment
transaction has been confirmed on-chain. Do not invent, estimate, or copy-paste addresses
from other deployments. Use the exact address returned by the deployment script after the
transaction is mined.

Similarly, `deploymentCommit` and `deployedAt` must remain `null` until deployment.

### Creating a record after a real deployment

1. Copy `examples/simulator.local.example.json` to `deployments/simulator.<network>.json`
   (e.g. `deployments/simulator.sepolia.json`).
2. Remove the `_note` key.
3. Fill in all address and timestamp fields from the confirmed deployment transaction.
4. Run `npm run validate:deployments` and confirm it passes.
5. Open a PR with only this new record (and a corresponding update to `docs/Deployments.md`).

### What the WalletWall app may do with these files

The app may **read** these files as static metadata to display simulator status, link to
documentation, or surface the deployment environment. It **must not**:

- Infer that the simulator is reachable or ready for transactions from metadata alone.
- Treat a populated address as proof that the contract is live, funded, or unpaused.
- Use metadata as a substitute for on-chain checks before any write interaction.
- Store or re-publish addresses without linking to this repository as the canonical source.

The app must show at least one warning from the `warnings` array before any write interaction
with the simulator.

## Schema

See [`schema/simulator-deployment.schema.json`](schema/simulator-deployment.schema.json)
for field definitions, allowed values, and validation constraints.

## Validation

```sh
npm run validate:deployments
```

Validates all JSON files in `deployments/` (excluding `schema/` and `examples/`) against
the schema rules. Exits 0 if all records are valid or if no records exist. Exits 1 on any
error.

## Reproducibility manifests

`reproducibility/<subject>-<network>.json` records whether a public testnet deployment can be
reproduced from public repository sources, and — when it cannot — the **committed remediation
path**. This keeps the trust story honest: a deployment is either provably reproducible or
**clearly remediation-gated**, never silently assumed.

```sh
npm run validate:reproducibility
```

The validator enforces an **honesty cross-check**: a manifest may only declare
`reproducibilityStatus: "reproducible"` when its own recorded facts support it (the reported
source commit is in public history, the observed and public-HEAD runtime byte counts match, and
an `artifactManifest` with a source tag + bytecode hash is present). Any other status **must**
carry a concrete `remediation` plan (`chosenPath` + non-empty `steps`). See
[`docs/Deployments.md`](../docs/Deployments.md) for the human-readable remediation runbook.

## Security reminders

- Never commit `DEPLOYER_PRIVATE_KEY`, RPC URLs, mnemonics, or secrets to this directory.
- Never reference mainnet addresses or networks in these files.
- Never use real USDC or any real-value token in the simulator.
- No yield, interest, APY, APR, returns, or payout of any kind.
