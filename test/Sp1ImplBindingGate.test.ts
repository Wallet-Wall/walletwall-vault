/**
 * SP1 implementation lane: the binding gate on the published record (docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * The SP1-TD2 binding gate keeps every rule it had. On the implementation lane's evidence it adds:
 *   - CROSS-CHAIN HALTED IDENTITY — an identity the registry records HALTED on ANY chain is refused as a binding target
 *     on every chain, even where that identity's wrapper is still ACTIVE and even under the local override. It is
 *     repository-published evidence read at deployment time: no online oracle, no new authority (a halt fact can only
 *     refuse, and nothing can remove one).
 *   - The registry and the chain must agree on a registered wrapper's halt; a halt the chain shows and the registry does
 *     not must be published before anything binds on that chain.
 *   - R2-3 — each registered wrapper is judged against the build its registration records, so a later build never turns
 *     an earlier deployment "not genuine".
 *   - Off a local chain, a wrapper's SP1 verifier must run the code its own build pins: a deployment that bypassed the
 *     constructor's pin (the gateway behind a genuine runtime) is refused whatever a designation says.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers } from "./helpers/connection";
import { deployPinnedSp1Verifier, withPinnedSp1Code } from "./helpers/sp1PinnedVerifier";
import { installWrapperOfBuild, laterBuild, registryFromProfiles } from "./helpers/registryHelpers";
import { readWrapperBuilds, type WrapperBuild } from "../scripts/lib/sp1-wrapper-build";
import {
  bindingRefusals,
  checkDeploymentBinding,
  profileVerifier,
  readDesignations,
  readHaltScope,
  type BindingRequest,
  type Designation,
  type VerifierProfile,
} from "../scripts/lib/verifier-binding";

const TD1 = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td1/decision-receipt.json"), "utf8"));
const BYTECODE = JSON.parse(
  readFileSync(resolve("evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json"), "utf8"),
);
const D1_VKEY: string = TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey;
const SEPOLIA = 11155111n;
const BASE_SEPOLIA = 84532n;
const LOCAL = 31337n;
const word = (label: string) => ethers.id(label);

describe("SP1 implementation lane — the binding gate on the published record", function () {
  let admin: any, haltPrincipal: any, otherHaltPrincipal: any;
  let builds: WrapperBuild[];
  let designated: VerifierProfile;

  const wrapperOver = async (sp1: string, vkey: string, principal: string) =>
    (await ethers.getContractFactory("ZKMLDSAVerifier")).deploy(sp1, vkey, principal);

  before(async function () {
    [admin, haltPrincipal, otherHaltPrincipal] = await ethers.getSigners();
    builds = readWrapperBuilds(".");
    const zk = await wrapperOver(await deployPinnedSp1Verifier(), D1_VKEY, haltPrincipal.address);
    designated = await profileVerifier(ethers.provider, await zk.getAddress());
  });

  /** A Sepolia binding of `target` with the committed designations, registered, and a registry that mirrors it. */
  const request = (target: VerifierProfile, overrides: Partial<BindingRequest> = {}): BindingRequest => {
    const base = {
      consumer: "WalletWallVault",
      target,
      chainId: SEPOLIA,
      signer: admin.address,
      allowMockSp1: false,
      current: null,
      currentIdentity: null,
      targetIdentityRecordedHalted: false,
      scope: readHaltScope(),
      designations: readDesignations(),
      registered: [target],
      ...overrides,
    };
    return { ...base, registry: overrides.registry ?? registryFromProfiles(base.chainId, base.registered) };
  };
  /** The same identity, registered and halted on another chain (Base Sepolia), at another address. */
  const haltedElsewhere = (identity: string) => [
    {
      kind: "WRAPPER_REGISTERED" as const,
      chainId: BASE_SEPOLIA.toString(),
      address: ethers.getAddress(ethers.dataSlice(word("the Base Sepolia wrapper"), 12)),
      identity,
      observedAt: { block: 5, blockHash: word("observed on Base Sepolia") },
      wrapperBuild: "zkmldsa-verifier-b1",
      designation: "mldsa65-withdrawal-d1",
      sp1Verifier: { address: TD1.trustTarget.verifier, runtimeCodeKeccak: TD1.trustTarget.codeKeccak },
      programVKey: D1_VKEY,
      haltPrincipal: ethers.getAddress(otherHaltPrincipal.address),
      deployment: { txHash: word("deployed on Base Sepolia"), block: 5, deployer: ethers.getAddress(admin.address) },
      replaces: null,
    },
    {
      kind: "WRAPPER_HALTED" as const,
      chainId: BASE_SEPOLIA.toString(),
      address: ethers.getAddress(ethers.dataSlice(word("the Base Sepolia wrapper"), 12)),
      identity,
      observedAt: { block: 9, blockHash: word("halt observed on Base Sepolia") },
      reason: "VERIFIER_SOUNDNESS",
      halt: { txHash: word("halted on Base Sepolia"), block: 9 },
    },
  ];

  it("positive control: the designated wrapper, registered and ACTIVE, binds off a local chain", function () {
    expect(designated.wrapperBuild).to.equal("zkmldsa-verifier-b1");
    expect(designated.pinnedSp1VerifierCodehash).to.equal(TD1.trustTarget.codeKeccak);
    expect(bindingRefusals(request(designated))).to.deep.equal([]);
  });

  describe("an identity halted on one chain is refused on every chain", function () {
    it("refused on Sepolia when the registry records its halt on Base Sepolia, though the Sepolia wrapper is ACTIVE", function () {
      const registry = registryFromProfiles(SEPOLIA, [designated], haltedElsewhere(designated.identity!));
      expect(bindingRefusals(request(designated, { registry })).join("\n")).to.match(
        /identity .* is recorded HALTED in the WalletWall registry \(fact #3: .* on chain 84532, VERIFIER_SOUNDNESS\)/,
      );
      // Positive control: registered on Base Sepolia but not halted there, nothing is refused.
      const notHalted = registryFromProfiles(SEPOLIA, [designated], haltedElsewhere(designated.identity!).slice(0, 1));
      expect(bindingRefusals(request(designated, { registry: notHalted }))).to.deep.equal([]);
    });

    it("refused as a fresh, unregistered deployment too, and under the local override", function () {
      const registry = registryFromProfiles(BASE_SEPOLIA, [], haltedElsewhere(designated.identity!));
      for (const overrides of [
        { chainId: SEPOLIA, registered: [] },
        { chainId: LOCAL, allowMockSp1: true, registered: [] },
        { chainId: LOCAL, registered: [] },
      ]) {
        expect(
          bindingRefusals(request(designated, { ...overrides, registry })).join("\n"),
          `chain ${overrides.chainId}, override ${String(overrides.allowMockSp1 ?? false)}`,
        ).to.match(/recorded HALTED in the WalletWall registry/);
      }
      // Another identity is untouched by that halt.
      const other = { ...designated, programVKey: word("another program"), identity: word("another identity") };
      expect(
        bindingRefusals(request(other, { chainId: LOCAL, allowMockSp1: true, registered: [], registry })),
      ).to.deep.equal([]);
    });

    it("end to end: the deployment entry point refuses it from a registry that records the halt only on another chain", async function () {
      const registry = registryFromProfiles(BASE_SEPOLIA, [], haltedElsewhere(designated.identity!));
      await assert.rejects(
        checkDeploymentBinding(ethers.provider, "WalletWallVault", designated.address, admin.address, {
          allowMockSp1: true,
          registry,
        }),
        /recorded HALTED in the WalletWall registry/,
      );
      await checkDeploymentBinding(ethers.provider, "WalletWallVault", designated.address, admin.address, {
        allowMockSp1: true,
        registry: registryFromProfiles(BASE_SEPOLIA, [], []),
      });
    });
  });

  describe("the registry and the chain agree on a registered wrapper's halt", function () {
    it("a halt the registry records but the chain does not show is refused: one of them is wrong", function () {
      const registry = registryFromProfiles(SEPOLIA, [{ ...designated, halted: true }]);
      expect(bindingRefusals(request(designated, { registry })).join("\n")).to.match(
        /the registry records .* HALTED but the chain reports it ACTIVE/,
      );
    });

    it("a halt the chain shows but the registry does not record must be published before anything binds there", async function () {
      const zk = await wrapperOver(
        await deployPinnedSp1Verifier(),
        word("another build of the program"),
        otherHaltPrincipal.address,
      );
      await zk.connect(otherHaltPrincipal).halt();
      const halted = await profileVerifier(ethers.provider, await zk.getAddress());
      expect(halted.halted).to.equal(true);
      const silent = registryFromProfiles(SEPOLIA, [designated, { ...halted, halted: false }]);
      expect(
        bindingRefusals(request(designated, { registered: [designated, halted], registry: silent })).join("\n"),
      ).to.match(/HALTED on chain 11155111 but the registry does not record it: append its WRAPPER_HALTED fact/);
      // Positive control: once published, the binding of the other identity proceeds.
      expect(bindingRefusals(request(designated, { registered: [designated, halted] }))).to.deep.equal([]);
    });
  });

  describe("R2-3: a registered wrapper is judged against the build it was deployed from", function () {
    it("a later recorded build leaves an earlier deployment genuine", async function () {
      const later = laterBuild(builds[0], word("a fixed verifier's code"), 2);
      const p = await profileVerifier(ethers.provider, designated.address, [...builds, later]);
      expect([p.genuineWrapper, p.wrapperBuild]).to.deep.equal([true, "zkmldsa-verifier-b1"]);
      expect(bindingRefusals(request(p))).to.deep.equal([]);
    });

    it("a registration that records another build than the code runs is refused", function () {
      const registry = registryFromProfiles(SEPOLIA, [{ ...designated, wrapperBuild: "zkmldsa-verifier-b2" }]);
      expect(bindingRefusals(request(designated, { registry })).join("\n")).to.match(
        /runs build zkmldsa-verifier-b1, not the build its registration records \(zkmldsa-verifier-b2\)/,
      );
    });
  });

  describe("off a local chain, a wrapper's SP1 verifier must run the code its build pins", function () {
    it("a wrapper whose constructor pin was bypassed to bind the gateway is refused, whatever a designation says", async function () {
      const gatewayAddress = (
        await (
          await admin.sendTransaction({
            data: ethers.concat([
              BYTECODE.deployments.gateway.creationCode,
              ethers.AbiCoder.defaultAbiCoder().encode(["address"], [admin.address]),
            ]),
          })
        ).wait()
      ).contractAddress;
      const factory = await ethers.getContractFactory("ZKMLDSAVerifier");
      const bypassed = await withPinnedSp1Code(gatewayAddress, () =>
        factory.deploy(gatewayAddress, D1_VKEY, haltPrincipal.address),
      );
      const p = await profileVerifier(ethers.provider, await bypassed.getAddress());
      expect([p.genuineWrapper, p.wrapperBuild]).to.deep.equal([true, "zkmldsa-verifier-b1"]);
      const gatewayDesignation: Designation = {
        source: "a designation of the gateway's code (what no designation process would produce)",
        sp1VerifierCodeKeccak: p.sp1VerifierCodeKeccak!,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: D1_VKEY,
      };
      expect(bindingRefusals(request(p, { designations: [gatewayDesignation] })).join("\n")).to.match(
        /its SP1 verifier runs code .*, not the code its build pins \(0xcceb864c/,
      );
    });

    it("a fixed verifier needs a later build that pins it, and a successor designation: then it binds; the earlier build over it never does", async function () {
      const fixed = await (await ethers.getContractFactory("MockSP1Verifier")).deploy();
      const fixedCode = ethers.keccak256(await ethers.provider.getCode(await fixed.getAddress()));
      const b2 = laterBuild(builds[0], fixedCode, 2);
      const recoveryAddress = await installWrapperOfBuild(
        b2,
        await fixed.getAddress(),
        D1_VKEY,
        otherHaltPrincipal.address,
      );
      const recovery = await profileVerifier(ethers.provider, recoveryAddress, [...builds, b2]);
      expect([recovery.wrapperBuild, recovery.pinnedSp1VerifierCodehash, recovery.sp1VerifierCodeKeccak]).to.deep.equal(
        ["zkmldsa-verifier-b2", fixedCode, fixedCode],
      );
      const haltedDesignated = { ...designated, halted: true };
      const successor: Designation = {
        source: "a successor designation of the fixed verifier",
        sp1VerifierCodeKeccak: fixedCode,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: D1_VKEY,
      };
      const registered = [haltedDesignated, recovery];
      expect(
        bindingRefusals(request(recovery, { registered, designations: [...readDesignations(), successor] })),
      ).to.deep.equal([]);
      // On the first designation alone it is refused: a recovery identity needs its successor designation.
      expect(bindingRefusals(request(recovery, { registered })).join("\n")).to.match(/matches no designation/);
      // The earlier build over the fixed verifier (its pin bypassed) is refused even with the successor designation.
      const factory = await ethers.getContractFactory("ZKMLDSAVerifier");
      const earlierOverFixed = await withPinnedSp1Code(await fixed.getAddress(), async () =>
        factory.deploy(await fixed.getAddress(), D1_VKEY, otherHaltPrincipal.address),
      );
      const e = await profileVerifier(ethers.provider, await earlierOverFixed.getAddress(), [...builds, b2]);
      expect(
        bindingRefusals(
          request(e, { registered: [haltedDesignated, e], designations: [...readDesignations(), successor] }),
        ).join("\n"),
      ).to.match(/not the code its build pins/);
    });
  });
});
