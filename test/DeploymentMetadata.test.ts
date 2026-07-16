/**
 * Deployment metadata validation tests.
 *
 * These tests run against the committed JSON files in deployments/ to ensure
 * they conform to the required shape, contain correct testnet-only values, and
 * do not accidentally reference mainnet chain IDs or missing required fields.
 *
 * They do not deploy contracts or interact with a network. They are fast,
 * purely structural checks on static JSON.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, dirname } from "path";
import { expect } from "chai";

const REPO_ROOT = join(import.meta.dirname, "..");
const DEPLOYMENTS_DIR = join(REPO_ROOT, "deployments");
const SEPOLIA_RECORD = join(DEPLOYMENTS_DIR, "sepolia", "stablecoin-vault-simulator.json");
const SCHEMA_DIR = join(DEPLOYMENTS_DIR, "schema");
const EXAMPLES_DIR = join(DEPLOYMENTS_DIR, "examples");

// Chain IDs that must never appear in a deployment record (all known mainnets).
const FORBIDDEN_CHAIN_IDS = new Set([1, 8453, 137, 10, 42161, 56, 43114]);

// Chain IDs that are explicitly allowed (testnets and local).
const ALLOWED_CHAIN_IDS = new Set([31337, 11155111, 84532]);

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

function collectLiveRecords(): string[] {
  if (!existsSync(DEPLOYMENTS_DIR)) return [];
  const result: string[] = [];
  for (const entry of readdirSync(DEPLOYMENTS_DIR)) {
    const fullPath = join(DEPLOYMENTS_DIR, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      // Skip schema/, examples/, and reproducibility/ (reproducibility manifests
      // have their own shape + validator) — only live network record subdirs.
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

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("Deployment metadata — schema and safety", () => {
  describe("Sepolia stablecoin-vault-simulator.json", () => {
    let record: Record<string, unknown>;

    before(function () {
      if (!existsSync(SEPOLIA_RECORD)) {
        this.skip();
      }
      record = loadJson(SEPOLIA_RECORD) as Record<string, unknown>;
    });

    it("has schema version '1'", () => {
      expect(record["version"]).to.equal("1");
    });

    it("environment is 'sepolia'", () => {
      expect(record["environment"]).to.equal("sepolia");
    });

    it("chainId is 11155111 (Ethereum Sepolia)", () => {
      expect(record["chainId"]).to.equal(11155111);
    });

    it("chainId is not a mainnet chain ID", () => {
      const chainId = record["chainId"] as number;
      expect(FORBIDDEN_CHAIN_IDS.has(chainId)).to.equal(
        false,
        `chainId ${chainId} is a mainnet chain ID — must never appear in a deployment record`,
      );
    });

    it("chainId is a known allowed testnet or local value", () => {
      const chainId = record["chainId"] as number;
      expect(ALLOWED_CHAIN_IDS.has(chainId)).to.equal(
        true,
        `chainId ${chainId} is not in the allowed set ${[...ALLOWED_CHAIN_IDS].join(", ")}`,
      );
    });

    it("tokenMode is 'mock'", () => {
      expect(record["tokenMode"]).to.equal("mock");
    });

    it("tokenSymbol is 'mUSDC'", () => {
      expect(record["tokenSymbol"]).to.equal("mUSDC");
    });

    it("tokenDecimals is 6 (mirrors real USDC)", () => {
      expect(record["tokenDecimals"]).to.equal(6);
    });

    it("stablecoinVaultSimulatorAddress is a valid address", () => {
      const addr = record["stablecoinVaultSimulatorAddress"] as string | null;
      expect(addr).to.match(ADDRESS_RE, "stablecoinVaultSimulatorAddress must be a valid 0x address");
    });

    it("tokenAddress is a valid address", () => {
      const addr = record["tokenAddress"] as string | null;
      expect(addr).to.match(ADDRESS_RE, "tokenAddress must be a valid 0x address");
    });

    it("verifierAddress is a valid address", () => {
      const addr = record["verifierAddress"] as string | null;
      expect(addr).to.match(ADDRESS_RE, "verifierAddress must be a valid 0x address");
    });

    it("deploymentCommit is a valid 40-character hex SHA", () => {
      const commit = record["deploymentCommit"] as string | null;
      expect(commit).to.match(COMMIT_RE, "deploymentCommit must be a 40-char lowercase hex SHA");
    });

    it("packageVersion is a semver string", () => {
      expect(record["packageVersion"]).to.match(SEMVER_RE);
    });

    it("deployedAt is an ISO 8601 date-time string", () => {
      const ts = record["deployedAt"] as string | null;
      expect(ts).to.match(ISO_DATE_RE, "deployedAt must be an ISO 8601 date-time string");
    });

    it("warnings is a non-empty array", () => {
      const warnings = record["warnings"] as unknown[];
      expect(Array.isArray(warnings)).to.equal(true);
      expect(warnings.length).to.be.greaterThan(0, "warnings must contain at least one disclosure string");
    });

    it("every warning is a non-trivial string (≥ 10 chars)", () => {
      const warnings = record["warnings"] as string[];
      for (const w of warnings) {
        expect(typeof w).to.equal("string");
        expect(w.length).to.be.greaterThanOrEqual(10, `Warning is too short: "${w}"`);
      }
    });

    it("at least one warning mentions 'TESTNET' or 'testnet' or 'research prototype'", () => {
      const warnings = record["warnings"] as string[];
      const hasTestnetDisclosure = warnings.some(
        (w) =>
          w.toLowerCase().includes("testnet") ||
          w.toLowerCase().includes("research prototype") ||
          w.toLowerCase().includes("no real value"),
      );
      expect(hasTestnetDisclosure).to.equal(
        true,
        "At least one warning must disclose testnet-only / research-prototype / no-real-value status",
      );
    });

    it("policyEngineAddress is null (not wired at deploy time)", () => {
      expect(record["policyEngineAddress"]).to.equal(null);
    });

    it("timelockAddress is null (in-contract constant, not a separate deployment)", () => {
      expect(record["timelockAddress"]).to.equal(null);
    });

    it("recoveryAddress is null (configured per-vault by vault owners, not at deploy time)", () => {
      expect(record["recoveryAddress"]).to.equal(null);
    });

    it("docsUrl is present", () => {
      expect(record["docsUrl"]).to.be.a("string").with.length.greaterThan(0);
    });
  });

  describe("All live deployment records — mainnet safety", () => {
    let records: Array<{ path: string; data: Record<string, unknown> }>;

    before(() => {
      const files = collectLiveRecords();
      records = files.map((f) => ({
        path: f,
        data: loadJson(f) as Record<string, unknown>,
      }));
    });

    it("no deployment record has a mainnet chain ID", () => {
      for (const { path, data } of records) {
        const chainId = data["chainId"] as number;
        expect(FORBIDDEN_CHAIN_IDS.has(chainId)).to.equal(
          false,
          `${path}: chainId ${chainId} is a mainnet chain ID — must never appear in a deployment record`,
        );
      }
    });

    it("every deployment record has a non-empty warnings array", () => {
      for (const { path, data } of records) {
        const warnings = data["warnings"] as unknown[] | undefined;
        expect(Array.isArray(warnings) && warnings.length > 0).to.equal(
          true,
          `${path}: warnings must be a non-empty array`,
        );
      }
    });

    it("every deployment record has version '1'", () => {
      for (const { path, data } of records) {
        expect(data["version"]).to.equal("1", `${path}: version must be '1'`);
      }
    });

    it("every deployment record has an allowed environment value", () => {
      const ALLOWED = new Set(["local", "sepolia", "base-sepolia"]);
      for (const { path, data } of records) {
        expect(ALLOWED.has(data["environment"] as string)).to.equal(
          true,
          `${path}: environment '${data["environment"]}' is not in the allowed set`,
        );
      }
    });

    it("every deployment record has tokenMode 'mock' or 'external-test-token'", () => {
      const ALLOWED = new Set(["mock", "external-test-token"]);
      for (const { path, data } of records) {
        expect(ALLOWED.has(data["tokenMode"] as string)).to.equal(
          true,
          `${path}: tokenMode '${data["tokenMode"]}' is not allowed`,
        );
      }
    });
  });

  describe("Schema and example files — not validated as live records", () => {
    it("schema/simulator-deployment.schema.json is valid JSON", () => {
      const schemaPath = join(SCHEMA_DIR, "simulator-deployment.schema.json");
      expect(existsSync(schemaPath)).to.equal(true, "schema file must exist");
      expect(() => loadJson(schemaPath)).to.not.throw();
    });

    it("examples/simulator.local.example.json is valid JSON", () => {
      const exPath = join(EXAMPLES_DIR, "simulator.local.example.json");
      expect(existsSync(exPath)).to.equal(true, "local example file must exist");
      expect(() => loadJson(exPath)).to.not.throw();
    });

    it("examples/app-status.example.json is valid JSON", () => {
      const exPath = join(EXAMPLES_DIR, "app-status.example.json");
      expect(existsSync(exPath)).to.equal(true, "app-status example must exist");
      expect(() => loadJson(exPath)).to.not.throw();
    });

    it("app-status.example.json has appGates.noRealFunds = true", () => {
      const exPath = join(EXAMPLES_DIR, "app-status.example.json");
      if (!existsSync(exPath)) return;
      const ex = loadJson(exPath) as Record<string, Record<string, unknown>>;
      expect(ex["appGates"]?.["noRealFunds"]).to.equal(true);
    });

    it("app-status.example.json has appGates.noMainnetDeployment = true", () => {
      const exPath = join(EXAMPLES_DIR, "app-status.example.json");
      if (!existsSync(exPath)) return;
      const ex = loadJson(exPath) as Record<string, Record<string, unknown>>;
      expect(ex["appGates"]?.["noMainnetDeployment"]).to.equal(true);
    });

    it("app-status.example.json has appGates.tokenModeIsMock = true", () => {
      const exPath = join(EXAMPLES_DIR, "app-status.example.json");
      if (!existsSync(exPath)) return;
      const ex = loadJson(exPath) as Record<string, Record<string, unknown>>;
      expect(ex["appGates"]?.["tokenModeIsMock"]).to.equal(true);
    });
  });
});
