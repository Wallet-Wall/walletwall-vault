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

import { checkEvidenceAgainstManifest, type EvidenceBundle } from "../scripts/lib/reproducibility-evidence";

const REPO_ROOT = join(import.meta.dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");
const VAULT_MANIFEST = join(REPRO_DIR, "walletwall-vault-sepolia.json");

const SIMULATOR_MANIFESTS: Array<{ subject: string; file: string; deployedAddress: string; hasImmutables: boolean }> = [
  {
    subject: "StablecoinVaultSimulator",
    file: join(REPRO_DIR, "stablecoin-vault-simulator-sepolia.json"),
    deployedAddress: "0x32f489842DD515Fa4b4b258714F0067B8B8133ae",
    hasImmutables: true,
  },
  {
    subject: "MockUSDC",
    file: join(REPRO_DIR, "mock-usdc-sepolia.json"),
    deployedAddress: "0x8ffc8cE04789e9a7b53685a2d78CDa54E6Faac15",
    hasImmutables: false,
  },
  {
    subject: "MockMLDSAVerifier",
    file: join(REPRO_DIR, "mock-mldsa-verifier-sepolia.json"),
    deployedAddress: "0x4736138c99e0619D06663D971C8cD347de186F6d",
    hasImmutables: false,
  },
];

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
      if (entry === "schema" || entry === "evidence") continue;
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

  describe("StablecoinVaultSimulator stack Sepolia manifests", () => {
    for (const spec of SIMULATOR_MANIFESTS) {
      describe(`${spec.subject} manifest`, () => {
        let m: Record<string, unknown>;

        before(function () {
          if (!existsSync(spec.file)) this.skip();
          m = loadJson(spec.file);
        });

        it("has version '1' and matches the expected subject/address/chain", () => {
          expect(m["version"]).to.equal("1");
          expect(m["subject"]).to.equal(spec.subject);
          expect(m["environment"]).to.equal("sepolia");
          expect(m["chainId"]).to.equal(11155111);
          expect((m["deployedAddress"] as string).toLowerCase()).to.equal(spec.deployedAddress.toLowerCase());
        });

        it("reports the deployment commit as present in public history", () => {
          expect(m["reportedSourceCommit"]).to.equal("35c25fa294bebea44b3089aa2435a190a5adf3fb");
          expect(m["reportedSourceCommitInPublicHistory"]).to.equal(true);
        });

        it("is honestly reproducible: runtime bytes match the DEPLOYMENT COMMIT build (not just public HEAD), and the artifact manifest proves it", () => {
          expect(m["reproducibilityStatus"]).to.equal("reproducible");
          // reportedCommitRuntimeBytes (compiled from the pinned deployment commit's OWN
          // toolchain) is the decisive figure. publicHeadRuntimeBytes is a distinct,
          // separately-captured claim (today's toolchain, which has since migrated
          // Hardhat 2 -> 3) and must never be conflated with it.
          expect(m["reportedCommitRuntimeBytes"]).to.equal(m["observedRuntimeBytes"]);
          expect(m["publicHeadRuntimeBytes"]).to.be.a("number");
          const manifest = m["artifactManifest"] as Record<string, unknown>;
          expect(manifest).to.be.an("object");
          expect(manifest["sourceTag"]).to.equal("v0.4.24");
          expect(manifest["bytecodeHash"]).to.match(BYTECODE_HASH_RE);
          expect(manifest["executableBytecodeMatch"]).to.equal(true);
        });

        it("discloses the excluded solc metadata hash precisely (does not overclaim raw-byte equality)", () => {
          const manifest = m["artifactManifest"] as Record<string, unknown>;
          expect(manifest["metadataHashMatch"]).to.equal(false);
          // The decoded solc metadata region is 53 bytes; only 32 of those bytes actually
          // differ (the ipfs hash digest) — the checker proves this by decoding the
          // region, not by trusting a hand-set count. See ReproducibilityEvidenceCheck.test.ts.
          expect(manifest["metadataTrailerBytesExcluded"]).to.equal(32);
          const disclosures = m["disclosures"] as string[];
          const blob = disclosures.join(" ").toLowerCase();
          expect(/metadata|cbor/.test(blob)).to.equal(true);
        });

        it("names a committed evidence bundle that validate:reproducibility replays this manifest against", () => {
          expect(m["evidenceFile"]).to.equal(`deployments/reproducibility/evidence/${spec.file.split(/[\\/]/).pop()}`);
          const evidencePath = join(REPRO_DIR, "evidence", spec.file.split(/[\\/]/).pop()!);
          expect(existsSync(evidencePath), `${evidencePath} must exist`).to.equal(true);
        });

        if (spec.hasImmutables) {
          it("independently verifies every immutable constructor value (not merely observed)", () => {
            const manifest = m["artifactManifest"] as Record<string, unknown>;
            expect(manifest["immutableValuesIndependentlyVerified"]).to.equal(true);
            expect(Array.isArray(manifest["constructorArgs"])).to.equal(true);
            expect((manifest["constructorArgs"] as unknown[]).length).to.be.greaterThan(0);
          });
        }

        it("carries a testnet / research-prototype disclosure and a mock-verifier disclosure where relevant", () => {
          const disclosures = m["disclosures"] as string[];
          const blob = disclosures.join(" ").toLowerCase();
          expect(/testnet|research prototype|not audited|no real funds/.test(blob)).to.equal(true);
          if (spec.subject !== "MockUSDC") {
            expect(
              /mock/.test(blob) && /ml-dsa|mldsa|pq/i.test(blob),
              `${spec.file}: expected a MockMLDSAVerifier / no-real-PQ-verification disclosure`,
            ).to.equal(true);
          }
        });
      });
    }
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
          // reportedCommitRuntimeBytes (recompiled from the DEPLOYMENT COMMIT'S own
          // toolchain) is the decisive comparison for "reproducible" — NOT
          // publicHeadRuntimeBytes, which is today's toolchain and a separate claim.
          const observed = m["observedRuntimeBytes"];
          const reportedCommit = m["reportedCommitRuntimeBytes"];
          if (typeof observed === "number" && typeof reportedCommit === "number") {
            expect(observed).to.equal(
              reportedCommit,
              `${path}: 'reproducible' requires observedRuntimeBytes to match reportedCommitRuntimeBytes`,
            );
          } else {
            expect.fail(`${path}: 'reproducible' requires reportedCommitRuntimeBytes to be recorded`);
          }
          const manifest = m["artifactManifest"] as Record<string, unknown> | null;
          expect(manifest, `${path}: 'reproducible' requires an artifactManifest`).to.be.an("object");
          expect(manifest!["sourceTag"]).to.be.a("string").with.length.greaterThan(0);
          expect(manifest!["bytecodeHash"]).to.match(BYTECODE_HASH_RE);

          // A manifest may claim "reproducible" while explicitly excluding the non-executed
          // solc build-metadata hash (known to vary by build environment even for identical
          // source) — but only if it proves the executable code still matches exactly, bounds
          // the excluded region, and discloses the exclusion. Mirrors
          // scripts/validate-reproducibility.ts.
          if (manifest!["metadataHashMatch"] === false) {
            expect(
              manifest!["executableBytecodeMatch"],
              `${path}: metadataHashMatch: false requires executableBytecodeMatch: true`,
            ).to.equal(true);
            const excluded = manifest!["metadataTrailerBytesExcluded"];
            expect(typeof excluded, `${path}: metadataTrailerBytesExcluded must be a number`).to.equal("number");
            expect(excluded as number).to.be.at.least(0);
            expect(excluded as number, `${path}: excluded region must stay small (≤128 bytes)`).to.be.at.most(128);
            const disclosures = m["disclosures"] as string[];
            const blob = disclosures.join(" ").toLowerCase();
            expect(
              /metadata|cbor/.test(blob),
              `${path}: metadataHashMatch: false requires a disclosure mentioning the excluded metadata/CBOR hash`,
            ).to.equal(true);
          }

          // When an evidenceFile is present, the manifest's claims are not merely
          // structurally valid — they must be exactly what a fresh, deterministic
          // replay of the committed evidence bundle derives. Mirrors
          // scripts/validate-reproducibility.ts's evidence-based replay.
          const evidenceFile = m["evidenceFile"];
          if (typeof evidenceFile === "string" && evidenceFile.length > 0) {
            const evidencePath = join(REPO_ROOT, evidenceFile);
            expect(existsSync(evidencePath), `${path}: evidenceFile ${evidenceFile} does not exist`).to.equal(true);
            const evidence = JSON.parse(readFileSync(evidencePath, "utf8")) as EvidenceBundle;
            const replay = checkEvidenceAgainstManifest(evidence, m);
            expect(
              replay.errors,
              `${path}: evidence replay disagreed with the manifest:\n${replay.errors.join("\n")}`,
            ).to.deep.equal([]);
          }
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
