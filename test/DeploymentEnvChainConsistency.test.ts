/**
 * Deployment environment ↔ chain-ID consistency guard.
 *
 * Complements DeploymentMetadata.test.ts. That suite already proves no live
 * record carries a mainnet chain ID and that `environment` is in the allowed
 * set — but it does NOT assert, across every record, that the declared
 * `environment` actually MATCHES the `chainId` (and `networkName`). The exact
 * "sepolia → 11155111" check there is hardcoded to one specific file, so a
 * second record (or a future one) labelled "sepolia" while carrying a different
 * testnet's chain ID would slip through both that suite and the standalone
 * `validate-deployments.ts` script (which only requires a positive integer).
 *
 * This guard pins the cross-field invariant for ALL live records:
 *   environment "local"        ⇒ chainId 31337
 *   environment "sepolia"      ⇒ chainId 11155111  (Ethereum Sepolia)
 *   environment "base-sepolia" ⇒ chainId 84532     (Base Sepolia)
 * and that `networkName`, when it is a recognised Hardhat network name, agrees
 * with the declared environment.
 *
 * Pure, fast, static reads of the committed JSON. No network, no contracts,
 * no deployment.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
import { expect } from "chai";

const REPO_ROOT = join(__dirname, "..");
const DEPLOYMENTS_DIR = join(REPO_ROOT, "deployments");

// Canonical chain ID for each deployment environment (testnet / local only).
const ENV_CHAIN_ID: Record<string, number> = {
  local: 31337,
  sepolia: 11155111,
  "base-sepolia": 84532,
};

// Recognised Hardhat network names → the environment they belong to. A record
// may legitimately use another networkName, but if it uses one of these it must
// agree with `environment`.
const NETWORK_NAME_ENV: Record<string, string> = {
  hardhat: "local",
  localhost: "local",
  sepolia: "sepolia",
  "base-sepolia": "base-sepolia",
};

function collectLiveRecords(): string[] {
  if (!existsSync(DEPLOYMENTS_DIR)) return [];
  const result: string[] = [];
  for (const entry of readdirSync(DEPLOYMENTS_DIR)) {
    const fullPath = join(DEPLOYMENTS_DIR, entry);
    if (statSync(fullPath).isDirectory()) {
      // not live records (reproducibility manifests have their own validator)
      if (entry === "schema" || entry === "examples" || entry === "reproducibility") continue;
      for (const f of readdirSync(fullPath)) {
        if (f.endsWith(".json")) result.push(join(fullPath, f));
      }
    } else if (entry.endsWith(".json")) {
      result.push(fullPath);
    }
  }
  return result;
}

function rel(path: string): string {
  return path
    .slice(REPO_ROOT.length + 1)
    .split("\\")
    .join("/");
}

describe("Deployment env ↔ chainId consistency", () => {
  const records = collectLiveRecords().map((path) => ({
    path: rel(path),
    data: JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>,
  }));

  it("finds at least one live record and includes the Sepolia simulator record", () => {
    expect(records.length).to.be.greaterThan(0, "expected at least one live deployment record to validate");
    expect(records.map((r) => r.path)).to.include("deployments/sepolia/stablecoin-vault-simulator.json");
  });

  it("every record's chainId matches the canonical chainId for its environment", () => {
    for (const { path, data } of records) {
      const env = data["environment"] as string;
      expect(env in ENV_CHAIN_ID).to.equal(true, `${path}: unknown environment "${env}"`);
      expect(data["chainId"]).to.equal(
        ENV_CHAIN_ID[env],
        `${path}: environment "${env}" must use chainId ${ENV_CHAIN_ID[env]}, got ${JSON.stringify(data["chainId"])}`,
      );
    }
  });

  it("every recognised networkName agrees with the declared environment", () => {
    for (const { path, data } of records) {
      const networkName = data["networkName"] as string;
      const env = data["environment"] as string;
      if (networkName in NETWORK_NAME_ENV) {
        expect(NETWORK_NAME_ENV[networkName]).to.equal(
          env,
          `${path}: networkName "${networkName}" does not match environment "${env}"`,
        );
      }
    }
  });
});
