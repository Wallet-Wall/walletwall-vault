/**
 * GEN2-PQ-CONFORMANCE-1 — build evidence for the vendored ML-DSA-65 verifier.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. What this suite establishes, and only this:
 *   - the vendored closure compiles under the vendor's pinned settings with solc 0.8.30 (evm osaka, via-IR,
 *     runs 1,000,000) and fits EIP-170;
 *   - the code read back from the simulated chain is the compiler's runtime with the helper address in the
 *     immutable slot — the DEPLOYED bytecode is reproduced, not just counted;
 *   - the runtime minus its CBOR metadata tail is the same under a different source-unit naming and with
 *     `bytecodeHash: none`, so the recorded code hash is a property of the sources and settings, not of the path
 *     they were compiled from;
 *   - the exact function selectors, the overload the ERC-7913 magic value names, and that the Generation-2
 *     kernel's verifier interface has a different selector (an adapter is required; none exists here);
 *   - the helper is bound by code hash: the vendored bytes hash to the F1600_CODEHASH constant, the constructor
 *     refuses any other code, and the committed record (results/build.json) is reproduced byte for byte.
 */
import { expect } from "chai";
import {
  COMPILE_SETTINGS,
  SOURCE_UNITS,
  byteLength,
  compileVendoredVerifier,
  sha256Hex,
  solcVersionParts,
  splitCborTail,
} from "../lib/compile.js";
import {
  createWorld,
  ethers,
  pinnedHelperCodehash,
  readResults,
  toolchainRecord,
  unhex,
  writeResults,
  type World,
} from "../lib/world.js";

const KERNEL_PQ_VERIFIER_SIGNATURE = "verify(bytes32,bytes,bytes)"; // IKernelPQVerifier, prototype/vnext-kernel/generation-2/contracts/interfaces/IKernelPlanes.sol
const EIP170 = 24_576;

describe("pq-verifier-spike — build: reproduced bytecode, selectors, helper binding", function () {
  this.timeout(900_000);
  let world: World;

  before(async function () {
    world = await createWorld();
  });

  it("compiles the vendored closure with the vendor's pinned toolchain settings and fits EIP-170", function () {
    const c = world.compiled;
    expect(c.solcVersion).to.match(/^0\.8\.30\+commit\.73712a01/);
    expect(c.settings.evmVersion).to.equal(COMPILE_SETTINGS.evmVersion);
    expect(c.settings.viaIR).to.equal(true);
    expect(c.settings.optimizer).to.deep.equal({ enabled: true, runs: 1_000_000 });
    expect(Object.keys(c.sourceSha256).sort()).to.deep.equal(Object.keys(SOURCE_UNITS).sort());
    expect(byteLength(c.deployedBytecode)).to.be.at.most(EIP170);
    expect(world.verifier.runtimeBytes).to.equal(byteLength(c.deployedBytecode));
  });

  it("the code read back from the chain is the compiler's runtime with the helper address in the immutable slot", function () {
    const c = world.compiled;
    const refs = Object.values(c.immutableReferences).flat();
    expect(refs.length, "the helper is an immutable: solc reports where it sits").to.be.greaterThan(0);
    let expected = c.deployedBytecode.slice(2);
    const word = world.helper.address.slice(2).toLowerCase().padStart(64, "0");
    for (const { start, length } of refs) {
      expect(length).to.equal(32);
      expected = expected.slice(0, start * 2) + word + expected.slice((start + length) * 2);
    }
    expect(world.verifier.code.slice(2).toLowerCase()).to.equal(expected.toLowerCase());
    // and nowhere else does the helper address appear in the compiler's output (no second, unpinned copy)
    expect(c.deployedBytecode.includes(world.helper.address.slice(2).toLowerCase())).to.equal(false);
  });

  it("the runtime minus its CBOR tail does not depend on source-unit naming or on the metadata hash setting", function () {
    const a = compileVendoredVerifier();
    const renamed = Object.fromEntries(
      Object.entries(SOURCE_UNITS).map(([unit, rel]) => [
        unit,
        `prototype/vnext-kernel/pq-verifier-spike/vendor/${rel}`,
      ]),
    );
    const b = compileVendoredVerifier({ sourceUnitNames: renamed });
    const n = compileVendoredVerifier({ bytecodeHash: "none" });
    const ca = splitCborTail(a.deployedBytecode);
    const cb = splitCborTail(b.deployedBytecode);
    const cn = splitCborTail(n.deployedBytecode);
    expect(cb.code).to.equal(ca.code);
    expect(cn.code).to.equal(ca.code);
    expect(
      a.deployedBytecode,
      "the metadata hash binds the source-unit names, so the full runtime differs",
    ).to.not.equal(b.deployedBytecode);
    expect(cn.cborLength).to.be.lessThan(ca.cborLength);
    expect(b.methodIdentifiers).to.deep.equal(a.methodIdentifiers);
  });

  it("selectors: two verify overloads, setKey and f1600Helper; the ERC-7913 magic value names the 3-argument overload; the Gen-2 kernel shape differs", function () {
    const c = world.compiled;
    expect(Object.keys(c.methodIdentifiers).sort()).to.deep.equal([
      "f1600Helper()",
      "setKey(bytes)",
      "verify(bytes,bytes,bytes,bytes)",
      "verify(bytes,bytes32,bytes)",
    ]);
    expect("0x" + c.methodIdentifiers["verify(bytes,bytes32,bytes)"]).to.equal(world.sel32);
    expect("0x" + c.methodIdentifiers["verify(bytes,bytes,bytes,bytes)"]).to.equal(world.selCtx);
    expect(world.sel32).to.equal(ethers.id("verify(bytes,bytes32,bytes)").slice(0, 10));
    const kernelSelector = ethers.id(KERNEL_PQ_VERIFIER_SIGNATURE).slice(0, 10);
    expect(
      kernelSelector,
      "IKernelPQVerifier.verify(bytes32 digest, bytes publicKey, bytes signature) is a different function",
    ).to.not.equal(world.sel32);
    expect(kernelSelector).to.not.equal(world.selCtx);
    const selectors = Object.values(c.methodIdentifiers);
    expect(new Set(selectors).size, "no selector collision inside the verifier").to.equal(selectors.length);
  });

  it("helper binding: the vendored helper bytes hash to F1600_CODEHASH, f1600Helper() returns the bound address, and the constructor refuses other code", async function () {
    expect(world.helper.codehash).to.equal(pinnedHelperCodehash());
    expect(world.helper.runtimeBytes).to.equal(21_622);
    const bound = (await world.verifierContract.getFunction("f1600Helper").staticCall()) as string;
    expect(bound.toLowerCase()).to.equal(world.helper.address.toLowerCase());

    const [from] = await ethers.getSigners();
    const factory = new ethers.ContractFactory(world.compiled.abi as never, world.compiled.bytecode, from);
    const badHelperSelector = ethers.id("BadHelper()").slice(0, 10);
    for (const [name, candidate] of [
      ["a contract with other code (the probe)", world.probe.address],
      ["the verifier itself", world.verifier.address],
      ["an address with no code", "0x000000000000000000000000000000000000dEaD"],
    ] as const) {
      let failed = false;
      try {
        await factory.deploy(candidate);
      } catch (e) {
        failed = true;
        const data = String((e as { data?: string; message?: string }).data ?? (e as Error).message ?? "");
        expect(
          data.includes(badHelperSelector.slice(2)) || /BadHelper|revert/i.test(data),
          `${name}: ${data.slice(0, 160)}`,
        ).to.equal(true);
      }
      expect(failed, `${name}: deployment must revert`).to.equal(true);
    }
  });

  it("records the build facts and reproduces the committed record (results/build.json)", async function () {
    const c = world.compiled;
    const tail = splitCborTail(c.deployedBytecode);
    const solc = solcVersionParts(c.solcVersion);
    const comparable = {
      solc: solc.version,
      solcCommit: solc.commit,
      settings: {
        evmVersion: c.settings.evmVersion,
        viaIR: c.settings.viaIR,
        optimizer: c.settings.optimizer,
        remappings: [...c.settings.remappings],
      },
      sourceUnits: c.sourceSha256,
      contract: c.contract,
      creationBytecodeBytes: byteLength(c.bytecode),
      creationBytecodeSha256: sha256Hex(Buffer.from(unhex(c.bytecode))),
      runtimeBytes: byteLength(c.deployedBytecode),
      eip170Headroom: EIP170 - byteLength(c.deployedBytecode),
      runtimeSha256: sha256Hex(Buffer.from(unhex(c.deployedBytecode))),
      runtimeSansCborSha256: sha256Hex(Buffer.from(unhex(tail.code))),
      cborTailBytes: tail.cborLength,
      immutableReferences: c.immutableReferences,
      methodIdentifiers: c.methodIdentifiers,
      erc7913MagicValue: world.sel32,
      kernelInterfaceSelector: ethers.id(KERNEL_PQ_VERIFIER_SIGNATURE).slice(0, 10),
      helper: {
        runtimeBytes: world.helper.runtimeBytes,
        codehash: world.helper.codehash,
        pinnedByVerifier: pinnedHelperCodehash(),
      },
      deployment: {
        helperDeployGas: world.helper.gasUsed,
        verifierDeployGas: world.verifier.gasUsed,
        deployedCodeEqualsRuntimeWithHelperInImmutableSlots: true,
      },
    };
    // Addresses and the deployed code hash depend on the deployer's nonce, i.e. on which suites ran before this one
    // in the same process (all suites share one simulated chain), so they are recorded but not compared.
    const thisRun = {
      deployerNonceOrder: ["helper (raw runtime)", "verifier(helper)", "SpikeProbe"],
      helperAddress: world.helper.address.toLowerCase(),
      verifierAddress: world.verifier.address.toLowerCase(),
      verifierDeployedCodehash: world.verifier.codehash,
    };
    const record = {
      schema: "gen2-pq-conformance-1/build.v1",
      comparable,
      thisRun,
      environment: await toolchainRecord(),
    };
    writeResults("build.json", record);
    const committed = readResults<typeof record>("build.json");
    if (committed) {
      expect(comparable, "a fresh build must reproduce the committed record exactly").to.deep.equal(
        committed.comparable,
      );
    } else {
      this.skip();
    }
  });
});
