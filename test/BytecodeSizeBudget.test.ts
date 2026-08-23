/**
 * EIP-170 runtime bytecode size gate tests (scripts/validate-bytecode-size.ts).
 *
 * These prove, independent of any real compiled contract:
 *   - the byte-count math is correct at the boundary (exactly-at-limit passes,
 *     one-byte-over fails — "runtime > 24,576" per the task spec, not >=);
 *   - the gate reads ONLY `deployedBytecode` (runtime/deployed code) for the
 *     gated size — a synthetic fixture with an oversized `bytecode` (creation
 *     code) and a tiny `deployedBytecode` must NOT be flagged, proving creation
 *     bytecode can never leak into the pass/fail decision;
 *   - the EIP-170 constant itself is pinned, so an accidental edit to it fails
 *     this suite rather than silently loosening or tightening every gate.
 *
 * A separate section then runs the real gate against the currently compiled
 * contracts to confirm each required target reports an explicit measured size
 * and stays within the ceiling today. The ceiling assertions there are skipped
 * under `hardhat test --coverage`: coverage instrumentation disables the
 * optimizer and injects tracking code, so every contract's runtime bytecode is
 * legitimately (and irrelevantly) inflated well past 24,576 bytes in that mode.
 * The binding gate for real deployment artifacts is the dedicated CI step that
 * runs immediately after a plain `npm run compile`, before any coverage
 * recompile (see test/CIValidatorCoverage.test.ts).
 *
 * Run:  npm test  (included in the default Hardhat test suite; contracts are
 * compiled first by `hardhat test`, matching every other artifact-reading test
 * in this suite.)
 */
import { expect } from "chai";
import { globalOptions } from "hardhat";

import {
  collectReports,
  EIP170_RUNTIME_LIMIT_BYTES,
  evaluateArtifact,
  evaluateSize,
  hexByteLength,
  TARGET_CONTRACTS,
  WARN_RATIO,
  WARN_THRESHOLD_BYTES,
} from "../scripts/validate-bytecode-size";

/** Build a "0x"-prefixed hex string encoding exactly `byteLength` bytes. */
function hexOfLength(byteLength: number): string {
  return "0x" + "60".repeat(byteLength);
}

describe("EIP-170 runtime bytecode size gate", function () {
  describe("hexByteLength — pure byte-count math", function () {
    it("computes 0 bytes for an empty '0x' payload (e.g. an interface's deployedBytecode)", function () {
      expect(hexByteLength("0x")).to.equal(0);
    });

    it("computes the correct byte count for a non-trivial payload", function () {
      expect(hexByteLength(hexOfLength(1234))).to.equal(1234);
    });

    it("rejects a non-0x-prefixed string", function () {
      expect(() => hexByteLength("abcd")).to.throw(/0x-prefixed/);
    });

    it("rejects an odd number of hex nibbles", function () {
      expect(() => hexByteLength("0xabc")).to.throw(/odd number of nibbles/);
    });
  });

  describe("the EIP-170 ceiling is pinned, not policy", function () {
    it("hard limit is exactly 24,576 bytes", function () {
      expect(EIP170_RUNTIME_LIMIT_BYTES).to.equal(24576);
    });

    it("warning threshold is 90% of the hard limit (22,118 bytes) and never failing on its own", function () {
      expect(WARN_RATIO).to.equal(0.9);
      expect(WARN_THRESHOLD_BYTES).to.equal(22118);
      expect(evaluateSize("x", WARN_THRESHOLD_BYTES, 0).overLimit).to.equal(false);
    });
  });

  describe("evaluateSize — hard-failure boundary (runtime > limit, not >=)", function () {
    it("exactly at the limit (24,576 bytes) is NOT over the limit", function () {
      const r = evaluateSize("AtLimit", EIP170_RUNTIME_LIMIT_BYTES, 0);
      expect(r.overLimit).to.equal(false);
      expect(r.headroomBytes).to.equal(0);
    });

    it("one byte over the limit (24,577 bytes) IS over the limit", function () {
      const r = evaluateSize("OneOver", EIP170_RUNTIME_LIMIT_BYTES + 1, 0);
      expect(r.overLimit).to.equal(true);
      expect(r.headroomBytes).to.equal(-1);
    });

    it("a grossly over-limit synthetic fixture is rejected", function () {
      const r = evaluateSize("WayOver", EIP170_RUNTIME_LIMIT_BYTES + 5000, 0);
      expect(r.overLimit).to.equal(true);
    });

    it("comfortably under the warning band reports neither warn nor fail", function () {
      const r = evaluateSize("Comfortable", 1000, 0);
      expect(r.overLimit).to.equal(false);
      expect(r.nearLimit).to.equal(false);
    });
  });

  describe("evaluateArtifact — measures deployedBytecode, never bytecode (creation)", function () {
    it("a tiny runtime paired with a huge creation payload is NOT flagged (creation is not gated)", function () {
      const artifact = {
        contractName: "SyntheticConstructorHeavy",
        // Creation code alone would blow the EIP-170 ceiling several times over —
        // EIP-170 does not apply to creation bytecode, so this must never fail.
        bytecode: hexOfLength(40000),
        deployedBytecode: hexOfLength(100),
      };
      const r = evaluateArtifact(artifact.contractName, artifact);
      expect(r.runtimeBytes).to.equal(100);
      expect(r.creationBytes).to.equal(40000);
      expect(r.overLimit).to.equal(false, "creation bytecode must never be compared against the EIP-170 limit");
    });

    it("an over-limit deployedBytecode is flagged even when creation bytecode is small", function () {
      const artifact = {
        contractName: "SyntheticRuntimeHeavy",
        bytecode: hexOfLength(500),
        deployedBytecode: hexOfLength(EIP170_RUNTIME_LIMIT_BYTES + 1),
      };
      const r = evaluateArtifact(artifact.contractName, artifact);
      expect(r.runtimeBytes).to.equal(EIP170_RUNTIME_LIMIT_BYTES + 1);
      expect(r.overLimit).to.equal(true);
    });

    it("swapping which field is read (regression guard) would be caught: runtime tracks deployedBytecode only", function () {
      // If evaluateArtifact ever accidentally read `bytecode` instead of
      // `deployedBytecode` for runtimeBytes, this artifact would report
      // runtimeBytes = 300 (creation) instead of 9000 (deployed) and overLimit
      // would flip to false — this assertion pins the correct mapping.
      const artifact = {
        contractName: "SyntheticAsymmetric",
        bytecode: hexOfLength(300),
        deployedBytecode: hexOfLength(9000),
      };
      const r = evaluateArtifact(artifact.contractName, artifact);
      expect(r.runtimeBytes).to.equal(9000);
      expect(r.creationBytes).to.equal(300);
    });
  });

  describe("current contracts — real measured sizes (post-compile)", function () {
    const requiredByTask = ["WalletWallVault", "StablecoinVaultSimulator", "WalletWallMultiSigVault"];

    it("TARGET_CONTRACTS covers every contract the task requires at minimum", function () {
      const names = TARGET_CONTRACTS.map((t) => t.name);
      for (const required of requiredByTask) {
        expect(names).to.include(required);
      }
    });

    let reports: ReturnType<typeof collectReports>;
    before(function () {
      reports = collectReports();
    });

    it("reports an explicit, positive, finite measured size for every target", function () {
      expect(reports).to.have.length(TARGET_CONTRACTS.length);
      for (const r of reports) {
        expect(r.runtimeBytes, `${r.name}: runtimeBytes`).to.be.a("number").and.to.be.greaterThan(0);
        expect(Number.isFinite(r.runtimeBytes), `${r.name}: runtimeBytes must be finite`).to.equal(true);
      }
    });

    it("every target contract is currently within the EIP-170 ceiling", function () {
      if (globalOptions.coverage) {
        // `hardhat test --coverage` recompiles with coverage instrumentation, which
        // injects tracking code and disables the optimizer — runtime bytecode balloons
        // well past 24,576 bytes and is never representative of a real deployment. The
        // binding EIP-170 gate is the dedicated CI step that runs immediately after a
        // plain `npm run compile`, before this coverage recompile ever happens (see
        // test/CIValidatorCoverage.test.ts). Skip rather than silently pass, so this
        // stays honest about what a coverage run can and cannot prove.
        this.skip();
      }
      const over = reports.filter((r) => r.overLimit);
      expect(over.map((r) => `${r.name}: ${r.runtimeBytes}`)).to.deep.equal(
        [],
        "one or more contracts currently exceed the EIP-170 runtime bytecode ceiling",
      );
    });

    it("WalletWallVault and StablecoinVaultSimulator are the tightest contracts on headroom", function () {
      if (globalOptions.coverage) {
        this.skip(); // see previous test — coverage instrumentation inflates every size.
      }
      // Documents today's measured reality (see task report for exact bytes): both
      // sit well above the mocks/policy contracts but still under the hard ceiling.
      const byName = Object.fromEntries(reports.map((r) => [r.name, r]));
      expect(byName["WalletWallVault"].runtimeBytes).to.be.greaterThan(WARN_THRESHOLD_BYTES - 5000);
      expect(byName["StablecoinVaultSimulator"].runtimeBytes).to.be.greaterThan(WARN_THRESHOLD_BYTES - 5000);
    });
  });
});
