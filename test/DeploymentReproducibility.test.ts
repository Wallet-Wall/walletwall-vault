/**
 * Deployment reproducibility manifest tests.
 *
 * These tests run against the committed JSON manifests in
 * deployments/reproducibility/ to ensure the repo's trust story is either
 * provably reproducible or clearly remediation-gated — and that a manifest can
 * never claim "reproducible" while its own recorded facts contradict it.
 *
 * They do not deploy contracts or touch a network — purely structural checks
 * on static JSON. They mirror scripts/validate-reproducibility.ts so the same
 * honesty rule is enforced both in CI tests and via the npm validator.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
import { expect } from "chai";

const REPO_ROOT = join(__dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");
const VAULT_MANIFEST = join(REPRO_DIR, "walletwall-vault-sepolia.json");

const FORBIDDEN_CHAIN_IDS = new Set([1, 8453, 137, 10, 42161, 56, 43114]);
const ALLOWED_STATUSES = new Set(["reproducible", "pending-source-alignment", "remediation-gated", "deprecated"]);
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTECODE_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

function collectManifests(): string[] {
  if (!existsSync(REPRO_DIR)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(REPRO_DIR)) {
    const full = join(REPRO_DIR, entry);
    if (statSync(full).isDirectory()) {
      if (entry === "schema") continue;
      for (const f of readdirSync(full)) if (f.endsWith(".json")) out.push(join(full, f));
    } else if (entry.endsWith(".json")) {
      out.push(full);
    }
  }
  return out;
}

function loadJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

describe("Deployment reproducibility — manifests are reproducible or remediation-gated", () => {
  describe("WalletWallVault Sepolia manifest", () => {
    let m: Record<string, unknown>;

    before(function () {
      if (!existsSync(VAULT_MANIFEST)) this.skip();
      m = loadJson(VAULT_MANIFEST);
    });

    it("has version '1' and a contract subject", () => {
      expect(m["version"]).to.equal("1");
      expect(m["subject"]).to.be.a("string").with.length.greaterThan(0);
    });

    it("is a Sepolia testnet record (not a mainnet chain ID)", () => {
      expect(m["environment"]).to.equal("sepolia");
      expect(m["chainId"]).to.equal(11155111);
      expect(FORBIDDEN_CHAIN_IDS.has(m["chainId"] as number)).to.equal(false);
    });

    it("records a valid deployed address", () => {
      expect(m["deployedAddress"]).to.match(ADDRESS_RE);
    });

    it("reproducibilityStatus is an allowed value", () => {
      expect(ALLOWED_STATUSES.has(m["reproducibilityStatus"] as string)).to.equal(true);
    });

    it("carries a testnet / research-prototype disclosure", () => {
      const disclosures = m["disclosures"] as string[];
      expect(Array.isArray(disclosures)).to.equal(true);
      expect(disclosures.length).to.be.greaterThan(0);
      const blob = disclosures.join(" ").toLowerCase();
      expect(/testnet|research prototype|not audited|no real funds/.test(blob)).to.equal(true);
    });

    it("is honestly remediation-gated with a concrete redeploy plan (current state)", () => {
      // The active deployment is not reproducible from public sources today, so the
      // manifest must NOT claim "reproducible" and must carry a remediation plan.
      expect(m["reproducibilityStatus"]).to.not.equal("reproducible");
      const remediation = m["remediation"] as Record<string, unknown>;
      expect(remediation).to.be.an("object");
      expect(["redeploy-from-public-head", "publish-source-tag-and-manifest"]).to.include(remediation["chosenPath"]);
      const steps = remediation["steps"] as string[];
      expect(Array.isArray(steps) && steps.length > 0).to.equal(true);
      expect(remediation["recordToUpdate"]).to.be.a("string").with.length.greaterThan(0);
    });
  });

  describe("All reproducibility manifests — honesty cross-check", () => {
    it("a manifest may only claim 'reproducible' when its own facts support it", () => {
      for (const path of collectManifests()) {
        const m = loadJson(path);
        const status = m["reproducibilityStatus"];
        if (status === "reproducible") {
          expect(m["reportedSourceCommitInPublicHistory"]).to.equal(
            true,
            `${path}: cannot be 'reproducible' with reportedSourceCommitInPublicHistory false`,
          );
          const observed = m["observedRuntimeBytes"];
          const head = m["publicHeadRuntimeBytes"];
          if (typeof observed === "number" && typeof head === "number") {
            expect(observed).to.equal(head, `${path}: 'reproducible' requires matching runtime bytes`);
          }
          const manifest = m["artifactManifest"] as Record<string, unknown> | null;
          expect(manifest, `${path}: 'reproducible' requires an artifactManifest`).to.be.an("object");
          expect(manifest!["sourceTag"]).to.be.a("string").with.length.greaterThan(0);
          expect(manifest!["bytecodeHash"]).to.match(BYTECODE_HASH_RE);
        } else {
          const remediation = m["remediation"] as Record<string, unknown> | undefined;
          expect(remediation, `${path}: non-reproducible status requires a remediation plan`).to.be.an("object");
          const steps = remediation!["steps"] as unknown[];
          expect(Array.isArray(steps) && steps.length > 0).to.equal(
            true,
            `${path}: remediation.steps must be a non-empty array`,
          );
        }
      }
    });

    it("no manifest references a mainnet chain ID", () => {
      for (const path of collectManifests()) {
        const m = loadJson(path);
        expect(FORBIDDEN_CHAIN_IDS.has(m["chainId"] as number)).to.equal(
          false,
          `${path}: chainId ${m["chainId"]} is a mainnet chain ID`,
        );
      }
    });
  });
});
