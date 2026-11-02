/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * The BYTE measurement of the admitted-asset ERC-20 spend plane, under test. The
 * candidates (`erc20-spend-plane/contracts/`) are compiled here with the pinned
 * solc under the prototype's exact build settings, and the committed record
 * (`erc20-spend-plane/ERC20_SPEND_PLANE_MEASUREMENTS.json`) must equal a fresh
 * derivation field for field — so a source edit without `measure.ts --write`, or a
 * hand-edited figure, fails this suite rather than publishing a stale number.
 *
 * THE POSITIVE CONTROL FOR THE METHOD comes first: the Generation-1 kernel compiled
 * through the same path must measure `MEASUREMENTS.json kernel.runtimeBytes`
 * exactly and reproduce the Hardhat artifact's executable prefix byte for byte. A
 * measurement method that cannot reproduce the known figure cannot be trusted with
 * the unknown one.
 *
 * Nothing here deploys to any network, and no figure here is a production claim.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";

import {
  compileGen1Baseline,
  executablePrefix,
  GEN1_FACTORY,
  GEN1_KERNEL,
  isStateChanging,
  measurePlane,
  MEASUREMENTS_JSON,
  PLANE_CONTRACTS,
  PLANE_FACTORY,
  PLANE_RECORD_JSON,
  STOP_CONDITION_HEADROOM,
  TARGET_KERNEL_CEILING,
  VARIANT_A,
  VARIANT_B,
  WALLETWALL_PORTABILITY_BUDGET,
  type Compiled,
  type PlaneBytesRecord,
} from "../erc20-spend-plane/compile.js";
import { plane } from "./erc20-spend-plane-world.js";

const GEN1_ARTIFACT = path.join(
  "prototype",
  "vnext-kernel",
  "artifacts",
  "prototype",
  "vnext-kernel",
  "contracts",
  "VaultKernelPrototype.sol",
  "VaultKernelPrototype.json",
);

interface Record {
  bytes: PlaneBytesRecord;
  gas: unknown;
  verdict: string;
  recommendation: unknown;
}

describe("ERC-20 spend plane — byte measurement", function () {
  this.timeout(120_000);

  let compiled: Compiled;
  let gen1: Compiled;
  let fresh: PlaneBytesRecord;
  let record: Record;
  let measurements: { kernel: { runtimeBytes: number; initcodeBytes: number }; factory: { runtimeBytes: number } };

  before(function () {
    compiled = plane();
    gen1 = compileGen1Baseline();
    fresh = measurePlane(compiled, gen1);
    record = JSON.parse(fs.readFileSync(PLANE_RECORD_JSON, "utf8")) as Record;
    measurements = JSON.parse(fs.readFileSync(MEASUREMENTS_JSON, "utf8"));
  });

  describe("positive control — the method reproduces the Generation-1 figure", function () {
    it("the Generation-1 kernel compiled through this path measures exactly MEASUREMENTS.json kernel.runtimeBytes", function () {
      expect(fresh.baseline.kernel.runtimeBytes).to.equal(measurements.kernel.runtimeBytes);
      expect(fresh.baseline.kernel.initcodeBytes).to.equal(measurements.kernel.initcodeBytes);
      expect(fresh.baseline.factory.runtimeBytes).to.equal(measurements.factory.runtimeBytes);
    });

    it("its EXECUTABLE PREFIX is byte-identical to the Hardhat artifact's; only the 53-byte metadata tail differs", function () {
      // The artifact exists because CI (and the documented local flow) compiles the prototype before testing.
      const artifact = JSON.parse(fs.readFileSync(GEN1_ARTIFACT, "utf8")) as { deployedBytecode: string };
      const fromArtifact = executablePrefix(artifact.deployedBytecode);
      const fromSolc = executablePrefix(gen1.units.get(GEN1_KERNEL)!.deployedBytecode);
      expect(fromSolc.metadataTailBytes).to.equal(53);
      expect(fromArtifact.metadataTailBytes).to.equal(53);
      expect(fromSolc.prefix).to.equal(fromArtifact.prefix);
      // The whole-runtime hashes DIFFER, because solc hashes the source KEYS into the tail: stated, not hidden.
      expect(gen1.units.get(GEN1_KERNEL)!.deployedBytecode).to.not.equal(artifact.deployedBytecode);
      expect((artifact.deployedBytecode.length - 2) / 2).to.equal(fresh.baseline.kernel.runtimeBytes);
    });
  });

  describe("the committed record is a fresh derivation, not a transcription", function () {
    it("ERC20_SPEND_PLANE_MEASUREMENTS.json `bytes` equals measurePlane() field for field", function () {
      expect(record.bytes).to.deep.equal(fresh);
    });

    it("every candidate source is digested into the record, so a source edit without --write is visible", function () {
      for (const key of Object.keys(record.bytes.sourceSha256)) {
        expect(key.startsWith(PLANE_CONTRACTS + "/"), key).to.equal(true);
      }
      expect(Object.keys(record.bytes.sourceSha256)).to.have.length(5);
    });

    it("the verdict is one of the three the lane brief allows", function () {
      expect([
        "MEASUREMENT_SUPPORTS_ADMISSION",
        "MEASUREMENT_REFUTES_ADMISSION",
        "MEASUREMENT_INCONCLUSIVE",
      ]).to.include(record.verdict);
    });
  });

  describe("the byte budget (architecture section 19.2, custody adjudication section 7.6)", function () {
    it("variant A (admissible verifier required at genesis) clears TARGET_KERNEL_CEILING with the 600 B stop condition intact", function () {
      const a = fresh.variants.A;
      expect(a.runtimeBytes).to.be.lessThanOrEqual(TARGET_KERNEL_CEILING);
      expect(a.headroomVsTargetCeiling).to.equal(TARGET_KERNEL_CEILING - a.runtimeBytes);
      expect(a.headroomVsTargetCeiling).to.be.greaterThanOrEqual(STOP_CONDITION_HEADROOM);
      expect(a.stopCondition).to.equal("CLEAR");
      expect(a.verdict).to.equal("TARGET PASS");
      expect(a.headroomVsPortabilityBudget).to.equal(WALLETWALL_PORTABILITY_BUDGET - a.runtimeBytes);
    });

    it("variant B (null verifier accepted at genesis) clears it too", function () {
      const b = fresh.variants.B;
      expect(b.runtimeBytes).to.be.lessThanOrEqual(TARGET_KERNEL_CEILING);
      expect(b.headroomVsTargetCeiling).to.be.greaterThanOrEqual(STOP_CONDITION_HEADROOM);
      expect(b.stopCondition).to.equal("CLEAR");
      expect(b.verdict).to.equal("TARGET PASS");
    });

    it("the plane's delta against the Generation-1 kernel is positive and recorded", function () {
      expect(fresh.variants.A.deltaVsGen1Kernel).to.equal(
        fresh.variants.A.runtimeBytes - measurements.kernel.runtimeBytes,
      );
      expect(fresh.variants.A.deltaVsGen1Kernel).to.be.greaterThan(0);
    });

    it("accepting a null verifier at genesis is NOT a byte saving: variant B is LARGER than variant A", function () {
      // The custody adjudication's hypothesis (section 7.2) was "dropping it saves bytes". Measured, it does not:
      // the admission helper stays for the other two edges, so the null case only adds a branch.
      expect(fresh.variants.variantDeltaBytesBMinusA).to.equal(
        fresh.variants.B.runtimeBytes - fresh.variants.A.runtimeBytes,
      );
      expect(fresh.variants.variantDeltaBytesBMinusA).to.be.greaterThan(0);
    });

    it("both kernels keep ZERO immutable slots (I-PURE-CONSTRUCTOR): the asset lives in CLONE args, not in the implementation", function () {
      expect(fresh.variants.A.immutableSlots).to.equal(0);
      expect(fresh.variants.B.immutableSlots).to.equal(0);
      expect(Object.keys(compiled.units.get(VARIANT_A)!.immutableReferences)).to.deep.equal([]);
    });

    it("the factory gains exactly one immutable (the admitted asset) and a bounded delta", function () {
      expect(fresh.factory.immutableSlots).to.equal(4);
      expect(fresh.factory.deltaVsGen1Factory).to.equal(fresh.factory.runtimeBytes - measurements.factory.runtimeBytes);
      expect(fresh.factory.deltaVsGen1Factory).to.be.greaterThan(0);
      expect(fresh.factory.deltaVsGen1Factory).to.be.lessThan(300);
    });

    it("a clone is 93 bytes: the 45-byte EIP-1167 template plus 48 bytes of args", function () {
      expect(fresh.clone).to.deep.equal({
        runtimeBytes: 93,
        argsBytes: 48,
        argsLayout: "generation (8) || verifierAuthority (20) || admittedAsset (20)",
      });
    });
  });

  describe("identity preserved from Generation 1", function () {
    it("storage layout: 17 entries over 11 slots, identical by slot, offset, type and size in both variants", function () {
      expect(fresh.storage).to.deep.equal({ identicalToGen1: true, entries: 17, slots: 11 });
    });

    it("the state-changing selector set is IDENTICAL to Generation 1; the only addition is the view admittedAsset()", function () {
      expect(fresh.abi.stateChangingSelectorsIdenticalToGen1).to.equal(true);
      expect(fresh.abi.addedSelectors).to.deep.equal(["admittedAsset()"]);
      expect(fresh.abi.removedSelectors).to.deep.equal([]);
      expect(fresh.abi.executeSignature).to.equal("execute(address,uint256,uint256,uint64,bytes,bytes,bytes)");
      expect(fresh.variants.A.stateChangingSelectors).to.equal(fresh.baseline.kernel.stateChangingSelectors);
      expect(fresh.variants.A.selectors).to.equal(fresh.baseline.kernel.selectors + 1);
    });

    it("execute keeps its Generation-1 selector, so no signing tooling changes", function () {
      const signature = "execute(address,uint256,uint256,uint64,bytes,bytes,bytes)";
      const gen1 = gen1Selectors().get(signature);
      const a = compiled.units.get(VARIANT_A)!.methodIdentifiers[signature];
      const b = compiled.units.get(VARIANT_B)!.methodIdentifiers[signature];
      expect(a).to.equal("6bc44090");
      expect(gen1).to.equal(a);
      expect(b).to.equal(a);
    });

    it("the interface copy is byte-identical to the Generation-1 interface", function () {
      expect(fresh.interfaceCopyByteIdenticalToGen1).to.equal(true);
    });

    it("the factory's only state-changing function is still deployVault", function () {
      const factory = compiled.units.get(PLANE_FACTORY)!;
      const stateChanging = (factory.abi as { type?: string; name?: string; stateMutability?: string }[])
        .filter(isStateChanging)
        .map((f) => f.name);
      expect(stateChanging).to.deep.equal(["deployVault"]);
      const names = (factory.abi as { type?: string; name?: string }[])
        .filter((f) => f.type === "function")
        .map((f) => f.name!);
      expect(names.filter((n) => /^set|admin|owner|pause|upgrade|register/i.test(n))).to.deep.equal([]);
      expect(names).to.include("admittedAsset");
    });
  });

  describe("source discipline", function () {
    const read = (file: string) => fs.readFileSync(path.join(PLANE_CONTRACTS, file), "utf8");

    it("neither kernel candidate contains msg.sender (zero caller authority, as the custody adjudication's section 5 observed of Generation 1)", function () {
      for (const file of ["VaultKernelErc20Prototype.sol", "VaultKernelErc20NullVerifierPrototype.sol"]) {
        expect(/msg\.sender/.test(read(file)), file).to.equal(false);
      }
    });

    it("both candidates and the factory carry the NOT PRODUCTION label", function () {
      for (const file of [
        "VaultKernelErc20Prototype.sol",
        "VaultKernelErc20NullVerifierPrototype.sol",
        "VaultKernelErc20FactoryPrototype.sol",
        "Erc20PlaneMocks.sol",
      ]) {
        expect(read(file)).to.include("NOT PRODUCTION");
      }
    });

    it("variant B differs from variant A ONLY in initialize and the genesis helper it adds", function () {
      const normalise = (s: string) =>
        s.split("VaultKernelErc20NullVerifierPrototype").join("VaultKernelErc20Prototype");
      const bodyOf = (s: string) => s.slice(s.indexOf("contract VaultKernelErc20Prototype {"));
      // CODE ONLY: comment lines are dropped, because a new function's documentation precedes its
      // `function` keyword and would otherwise be counted against the function ABOVE it.
      const codeOnly = (s: string) =>
        s
          .split("\n")
          .filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line))
          .join("\n");
      const a = codeOnly(bodyOf(normalise(read("VaultKernelErc20Prototype.sol"))));
      const b = codeOnly(bodyOf(normalise(read("VaultKernelErc20NullVerifierPrototype.sol"))));
      // Chunks begin at each `function` keyword; the preamble (storage, events, errors, constants) is chunk 0.
      const chunksOf = (s: string) => s.split(/(?=\n    function )/);
      const ca = chunksOf(a);
      const cb = chunksOf(b);
      const nameOf = (chunk: string) => /function\s+([A-Za-z0-9_]+)/.exec(chunk)?.[1] ?? "<preamble>";
      const mapA = new Map(ca.map((c) => [nameOf(c), c]));
      const mapB = new Map(cb.map((c) => [nameOf(c), c]));
      const onlyInB = [...mapB.keys()].filter((k) => !mapA.has(k));
      const onlyInA = [...mapA.keys()].filter((k) => !mapB.has(k));
      expect(onlyInA).to.deep.equal([]);
      expect(onlyInB).to.deep.equal(["_requireAdmissibleGenesisVerifier"]);
      const differing = [...mapA.keys()].filter((k) => mapA.get(k) !== mapB.get(k));
      expect(differing).to.deep.equal(["initialize"]);
      // The differing initialize bodies differ by the genesis admission statements alone.
      expect(mapB.get("initialize")).to.include("_requireAdmissibleGenesisVerifier(g.verifier);");
      expect(mapB.get("initialize")).to.include(
        "if (g.floor.requirePq && g.verifier == address(0)) revert ZeroAddress();",
      );
      expect(mapA.get("initialize")).to.include("_requireAdmissibleVerifier(g.verifier);");
      expect(mapA.get("initialize")).to.include(
        "if (g.signer == address(0) || g.verifier == address(0)) revert ZeroAddress();",
      );
    });

    it("the Generation-1 factory's deployVault selector is unchanged in the Generation-2 factory", function () {
      const gen1Factory = gen1.units.get(GEN1_FACTORY)!.methodIdentifiers;
      const planeFactory = compiled.units.get(PLANE_FACTORY)!.methodIdentifiers;
      const deployVaultKey = Object.keys(gen1Factory).find((k) => k.startsWith("deployVault("))!;
      expect(planeFactory[deployVaultKey]).to.equal(gen1Factory[deployVaultKey]);
    });
  });

  describe("MEASUREMENTS.json carries a pointer that agrees with the record", function () {
    it("the erc20SpendPlaneMeasurement block names the record and repeats its headline figures exactly", function () {
      const block = (measurements as unknown as { erc20SpendPlaneMeasurement?: Record<string, unknown> })
        .erc20SpendPlaneMeasurement;
      expect(block, "MEASUREMENTS.json has no erc20SpendPlaneMeasurement block").to.not.equal(undefined);
      expect(block!.record).to.equal("prototype/vnext-kernel/erc20-spend-plane/ERC20_SPEND_PLANE_MEASUREMENTS.json");
      expect(block!.variantA_runtimeBytes).to.equal(fresh.variants.A.runtimeBytes);
      expect(block!.variantB_runtimeBytes).to.equal(fresh.variants.B.runtimeBytes);
      expect(block!.variantA_headroomVsTargetCeiling).to.equal(fresh.variants.A.headroomVsTargetCeiling);
      expect(block!.variantB_headroomVsTargetCeiling).to.equal(fresh.variants.B.headroomVsTargetCeiling);
      expect(block!.factoryRuntimeBytes).to.equal(fresh.factory.runtimeBytes);
      expect(block!.verdict).to.equal(record.verdict);
      // It must NOT masquerade as a remediation of the measured kernel: the stateful generator's chain
      // keys on before/after/totalDelta, and this block changes no byte of Generation 1.
      expect(block!.beforeRuntime).to.equal(undefined);
      expect(block!.afterRuntime).to.equal(undefined);
      expect(block!.totalDelta).to.equal(undefined);
      expect(measurements.kernel.runtimeBytes).to.equal(fresh.baseline.kernel.runtimeBytes);
    });
  });

  function gen1Selectors(): Map<string, string> {
    return new Map(Object.entries(gen1.units.get(GEN1_KERNEL)!.methodIdentifiers));
  }
});
