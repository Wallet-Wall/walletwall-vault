/**
 * Runtime-byte claim binding tests (scripts/lib/runtime-byte-claims.ts).
 *
 * The invariant under test:
 *
 *     compiled runtime bytecode -> measurement -> every published claim
 *     claim != measurement  =>  gate fails
 *
 * The adversarial section is the point of this file. Agreement between two
 * declarations is NOT proof of correctness — the compiler measurement is the
 * only authority, so a pair of downstream copies edited together to the same
 * wrong value must still fail. That case is what the pre-existing
 * manifest/evidence cross-check could not catch: it compared a manifest field
 * against a checked-in COPY of solc output rather than against solc.
 */
import { join } from "node:path";

import { expect } from "chai";
import { globalOptions } from "hardhat";

import { collectRuntimeByteClaims } from "../scripts/lib/runtime-byte-claim-sources";
import {
  reconcileRuntimeByteClaims,
  type RuntimeByteDeclaration,
  type RuntimeByteMeasurement,
} from "../scripts/lib/runtime-byte-claims";

const VAULT: RuntimeByteMeasurement = {
  subject: "WalletWallVault",
  artifactRelPath: "artifacts/contracts/WalletWallVault.sol/WalletWallVault.json",
  runtimeBytes: 22701,
};

const VAULT_MANIFEST = "deployments/reproducibility/walletwall-vault-sepolia.json";

function decl(over: Partial<RuntimeByteDeclaration> = {}): RuntimeByteDeclaration {
  return {
    location: VAULT_MANIFEST,
    subject: "WalletWallVault",
    slot: "public-head",
    value: 22701,
    ...over,
  };
}

describe("runtime-byte claim binding", function () {
  describe("the compiler measurement is the authority", function () {
    it("accepts a public-head claim that equals the measured runtime bytes", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl()],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.errors).to.deep.equal([]);
      expect(result.ok).to.equal(true);
    });

    it("rejects a public-head claim that is one byte off the measured runtime bytes", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ value: 22700 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.match(/WalletWallVault.*claims 22700.*compiler.*22701/s);
    });

    it("rejects the historical drift case verbatim: evidence still advertises 22,367 after the contract moved on", function () {
      // The concrete regression this gate exists for. publicHeadRuntimeBytes said
      // 22,367 in four places while the compiled contract had already become
      // 22,574, and nothing failed because the record is remediation-gated and
      // carries no evidenceFile. Under this gate that state is unmergeable.
      const result = reconcileRuntimeByteClaims({
        measurements: [{ ...VAULT, runtimeBytes: 22574 }],
        declarations: [decl({ value: 22367 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.include("22367");
      expect(result.errors.join("\n")).to.include("22574");
    });
  });

  describe("agreement between declarations is not proof of correctness", function () {
    it("rejects TWO downstream declarations edited together to the same wrong value", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ value: 22700 }), decl({ location: "README.md", value: 22700 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      // BOTH sites must be named — a gate that reported only the first would let a
      // partial fix look complete.
      expect(result.errors.join("\n")).to.include(VAULT_MANIFEST);
      expect(result.errors.join("\n")).to.include("README.md");
    });

    it("rejects FOUR downstream declarations edited together to the same wrong value", function () {
      const locations = [VAULT_MANIFEST, "docs/Deployments.md", "README.md", "SECURITY.md"];
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: locations.map((location) => decl({ location, value: 22367 })),
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      for (const location of locations) {
        expect(result.errors.join("\n"), `${location} must be named`).to.include(location);
      }
    });

    it("unanimous agreement across every declaration still fails when the compiler disagrees", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ value: 1 }), decl({ location: "README.md", value: 1 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
    });
  });

  describe("conflicting declarations", function () {
    it("rejects two declarations of the same subject and slot that disagree with each other", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ value: 22701 }), decl({ location: "README.md", value: 22367 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.match(/conflicting/i);
    });
  });

  describe("coverage is required, not optional", function () {
    it("rejects a required subject that has no compiler measurement bound to it", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [],
        declarations: [],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.match(/WalletWallVault.*no runtime bytecode measurement/s);
    });

    it("rejects an off-declaration subject: a claim about a contract nothing measures", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ subject: "SomeNewVault", location: "docs/Deployments.md" })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.match(/SomeNewVault/);
    });

    it("a subject that is measured but declared nowhere is not an error (measurement is a superset)", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT, { subject: "ZKMLDSAVerifier", artifactRelPath: "z.json", runtimeBytes: 2180 }],
        declarations: [decl()],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(true);
    });
  });

  describe("malformed values", function () {
    for (const bad of [22701.5, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      it(`rejects ${String(bad)} as a runtime-byte value`, function () {
        const result = reconcileRuntimeByteClaims({
          measurements: [VAULT],
          declarations: [decl({ value: bad })],
          coverageRequired: ["WalletWallVault"],
        });
        expect(result.ok).to.equal(false);
        expect(result.errors.join("\n")).to.match(/not a non-negative integer/);
      });
    }
  });

  describe("observed-live claims are on-chain facts, never adjudicated by the compiler", function () {
    it("does NOT fail an observed-live claim that differs from today's compiled size", function () {
      // WalletWallVault's live Sepolia runtime is 20,508 bytes while public HEAD
      // compiles to 22,701. That divergence is the whole reason the record is
      // remediation-gated — it is a true fact about a past deployment, and a gate
      // that "fixed" it by overwriting it with the compiler measurement would be
      // falsifying history.
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [decl({ slot: "observed-live", value: 20508 })],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.errors).to.deep.equal([]);
      expect(result.ok).to.equal(true);
    });

    it("still requires every copy of an observed-live claim to agree with every other copy", function () {
      const result = reconcileRuntimeByteClaims({
        measurements: [VAULT],
        declarations: [
          decl({ slot: "observed-live", value: 20508 }),
          decl({ slot: "observed-live", location: "README.md", value: 20509 }),
        ],
        coverageRequired: ["WalletWallVault"],
      });
      expect(result.ok).to.equal(false);
      expect(result.errors.join("\n")).to.match(/conflicting/i);
    });
  });

  describe("the repository as it stands", function () {
    // The in-suite half of the gate. `npm run validate:runtime-byte-claims` is the
    // dedicated CI step; this makes a plain `npm test` fail too, so the drift
    // cannot survive a local run either.
    it("every published runtime-byte claim in this tree matches the compiler", function () {
      if (globalOptions.coverage) {
        // `hardhat test --coverage` recompiles with coverage instrumentation, which
        // injects tracking code and disables the optimizer. Every contract's runtime
        // bytecode is legitimately inflated — measured under coverage, WalletWallVault
        // is 41,026 bytes against a real 22,701, and StablecoinVaultSimulator 40,401
        // against 22,301 — so the published claims SHOULD disagree there, and a
        // comparison in that mode would be measuring the instrumentation.
        //
        // Skipped rather than silently passed, so this stays honest about what a
        // coverage run can prove. The binding gate for real deployment artifacts is
        // the dedicated CI step that runs immediately after a plain `npm run compile`
        // and before any coverage recompile; test/CIValidatorCoverage.test.ts pins
        // that the step exists, is unconditional, and runs post-compile. Same
        // reasoning and same treatment as the EIP-170 ceiling assertions in
        // test/BytecodeSizeBudget.test.ts, which share this measurement primitive.
        this.skip();
      }
      const collected = collectRuntimeByteClaims(join(import.meta.dirname, ".."));
      expect(collected.errors, "collection").to.deep.equal([]);
      const result = reconcileRuntimeByteClaims({
        measurements: collected.measurements,
        declarations: collected.declarations,
        coverageRequired: collected.coverageRequired,
      });
      expect(result.errors, "reconciliation").to.deep.equal([]);
    });
  });
});
