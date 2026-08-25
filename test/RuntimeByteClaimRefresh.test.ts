/**
 * Runtime-byte claim REFRESH tests (scripts/lib/runtime-byte-claim-refresh.ts).
 *
 * The gate is a validator, not a generator: a normal check is read-only and a
 * refresh is a separate, deliberate mutation. These tests pin the properties
 * that keep the refresh honest —
 *
 *   - it only ever writes the compiler's own measurement, never an argument;
 *   - it refuses to touch `observed-live` claims, which record what a past
 *     deployment actually put on chain and which the compiler cannot overrule;
 *   - it refuses to "fix" an evidence bundle by editing a length, because the
 *     bundle's authority is its captured bytecode, not a number — that needs a
 *     real recapture via `reproducibility-evidence.ts capture-build`.
 *
 * A refresh that silently papered over either of the last two would reintroduce
 * exactly the class of false assurance this work exists to remove.
 */
import { expect } from "chai";

import { planRuntimeByteRefresh } from "../scripts/lib/runtime-byte-claim-refresh";
import type { ProseClaimSite } from "../scripts/lib/runtime-byte-claim-sources";

const MEASUREMENTS = [
  { subject: "WalletWallVault", artifactRelPath: "a.json", runtimeBytes: 22701 },
  { subject: "MockUSDC", artifactRelPath: "b.json", runtimeBytes: 1994 },
];

const SITE: ProseClaimSite = {
  file: "README.md",
  subject: "WalletWallVault",
  slot: "public-head",
  pattern: /^recompiles to `([\d,]+)` bytes;/,
  note: "fixture",
};

describe("runtime-byte claim refresh", function () {
  describe("prose", function () {
    it("rewrites a stale public-head claim to the measured value, preserving comma grouping", function () {
      const plan = planRuntimeByteRefresh({
        files: { "README.md": "intro\nrecompiles to `22,367` bytes; and so on" },
        sites: [SITE],
        measurements: MEASUREMENTS,
      });
      expect(plan.unfixable).to.deep.equal([]);
      expect(plan.edits).to.have.length(1);
      expect(plan.edits[0].after).to.equal("recompiles to `22,701` bytes; and so on");
      expect(plan.edits[0].file).to.equal("README.md");
      expect(plan.edits[0].line).to.equal(2);
    });

    it("preserves an ungrouped number style when that is what the document used", function () {
      const plan = planRuntimeByteRefresh({
        files: { "README.md": "recompiles to `22367` bytes;" },
        sites: [SITE],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits[0].after).to.equal("recompiles to `22701` bytes;");
    });

    it("plans no edit when the claim already matches the measurement", function () {
      const plan = planRuntimeByteRefresh({
        files: { "README.md": "recompiles to `22,701` bytes;" },
        sites: [SITE],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.deep.equal([]);
    });

    it("never rewrites an observed-live claim — that is an on-chain fact, not a compiler output", function () {
      const observedSite: ProseClaimSite = { ...SITE, slot: "observed-live" };
      const plan = planRuntimeByteRefresh({
        files: { "README.md": "recompiles to `20,508` bytes;" },
        sites: [observedSite],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.deep.equal([]);
    });
  });

  describe("reproducibility manifests", function () {
    const manifest = [
      "{",
      '  "subject": "MockUSDC",',
      '  "observedRuntimeBytes": 1994,',
      '  "publicHeadRuntimeBytes": 1900',
      "}",
    ].join("\n");

    it("rewrites publicHeadRuntimeBytes to the measurement", function () {
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/mock-usdc-sepolia.json": manifest },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.have.length(1);
      expect(plan.edits[0].after).to.equal('  "publicHeadRuntimeBytes": 1994');
    });

    it("leaves observedRuntimeBytes alone even when it differs from the measurement", function () {
      const drifted = manifest.replace('"observedRuntimeBytes": 1994', '"observedRuntimeBytes": 1500');
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/mock-usdc-sepolia.json": drifted },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits.every((e) => !e.after.includes("observedRuntimeBytes"))).to.equal(true);
    });

    it("also refreshes the manifest's own NARRATIVE copies, not just the machine-readable field", function () {
      // The remediation-gated vault record states the size in prose as well as in
      // publicHeadRuntimeBytes. Refreshing only the field is exactly the partial
      // fix that let the prose rot for two releases.
      const site: ProseClaimSite = {
        file: "deployments/reproducibility/mock-usdc-sepolia.json",
        subject: "MockUSDC",
        slot: "public-head",
        pattern: /public HEAD recompiles it to a ([\d,]+)-byte runtime/,
        note: "rationale",
      };
      const text = [
        "{",
        '  "subject": "MockUSDC",',
        '  "publicHeadRuntimeBytes": 1900,',
        '  "rationale": "public HEAD recompiles it to a 1,900-byte runtime."',
        "}",
      ].join("\n");
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/mock-usdc-sepolia.json": text },
        sites: [site],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits.map((e) => e.line)).to.deep.equal([3, 4]);
      expect(plan.edits[1].after).to.include("1,994-byte runtime");
    });

    it("reports a manifest whose subject has no measurement instead of guessing", function () {
      const unknown = manifest.replace('"subject": "MockUSDC"', '"subject": "SomethingElse"');
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/x.json": unknown },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.deep.equal([]);
      expect(plan.unfixable.join("\n")).to.match(/SomethingElse/);
    });
  });

  describe("markdown tables", function () {
    it("rewrites a public-HEAD table cell to the measurement", function () {
      const text = [
        "| Contract | Public HEAD runtime bytes |",
        "| --- | --- |",
        "| `WalletWallVault` | `22,367` |",
      ].join("\n");
      const plan = planRuntimeByteRefresh({
        files: { "docs/Deployments.md": text },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.have.length(1);
      expect(plan.edits[0].after).to.equal("| `WalletWallVault` | `22,701` |");
    });

    it("leaves a deployment (observed-live) table cell alone", function () {
      const text = [
        "| Contract | Deployment runtime bytes |",
        "| --- | --- |",
        "| `WalletWallVault` | `20,508` |",
      ].join("\n");
      const plan = planRuntimeByteRefresh({
        files: { "docs/Deployments.md": text },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.deep.equal([]);
    });
  });

  describe("evidence bundles cannot be refreshed by editing a number", function () {
    it("reports a stale publicHeadBuild as unfixable, naming the recapture command", function () {
      const evidence = JSON.stringify(
        { subject: "MockUSDC", publicHeadBuild: { deployedBytecodeObject: "0x" + "60".repeat(1900) } },
        null,
        2,
      );
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/evidence/mock-usdc-sepolia.json": evidence },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.edits).to.deep.equal([]);
      expect(plan.unfixable.join("\n")).to.match(/capture-build/);
      expect(plan.unfixable.join("\n")).to.match(/1900.*1994|1994.*1900/s);
    });

    it("says nothing about an evidence bundle that already agrees with the compiler", function () {
      const evidence = JSON.stringify(
        { subject: "MockUSDC", publicHeadBuild: { deployedBytecodeObject: "0x" + "60".repeat(1994) } },
        null,
        2,
      );
      const plan = planRuntimeByteRefresh({
        files: { "deployments/reproducibility/evidence/mock-usdc-sepolia.json": evidence },
        sites: [],
        measurements: MEASUREMENTS,
      });
      expect(plan.unfixable).to.deep.equal([]);
    });
  });
});
