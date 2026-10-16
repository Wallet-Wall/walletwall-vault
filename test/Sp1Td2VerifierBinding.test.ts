/**
 * SP1-TD2 — the binding gate in the deployment and rotation tooling (scripts/lib/verifier-binding.ts;
 * docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 *
 *   EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER — WalletWallMultiSigVault, kept outside the halt until its gate
 *     TD2-MULTISIG-ROTATION is built, tested and admitted by the owner, is refused a haltable wrapper (and any other
 *     part of the SP1 path) by the deployment and rotation tooling; the consumers in scope are not.
 *   TD1-N12, recovery-target gating BY PROCESS — on a non-local chain, with no override, a binding or rotation
 *     target must be an ACTIVE haltable wrapper whose SP1 verifier code hash and PROGRAM_VKEY are the SP1-TD1
 *     designations, not a halted identity, and not haltable by the signer.
 *
 * Scope and designations are read from the SP1-TD1 receipt; this suite checks that they are, then exercises the
 * gate's rules on profiles measured from deployed contracts (the real v6.1.0 bytes included), each refusal with a
 * positive control.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers, networkHelpers } from "./helpers/connection";
import { ROTATION_DELAY, VKEY_A, VKEY_B, deploySp1, deployWrapper } from "./helpers/td2Helpers";
import {
  CONSUMERS,
  ZK_ALGORITHM_ID,
  bindingRefusals,
  checkDeploymentBinding,
  checkRotationBinding,
  identifyConsumer,
  isHaltable,
  isOnSp1Path,
  profileVerifier,
  readDesignations,
  readHaltScope,
  type BindingRequest,
  type VerifierProfile,
} from "../scripts/lib/verifier-binding";

const TD1 = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td1/decision-receipt.json"), "utf8"));
const BYTECODE = JSON.parse(
  readFileSync(resolve("evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json"), "utf8"),
);
const SEPOLIA = 11155111n;
const LOCAL = 31337n;
const MOCK_OK = { allowMockSp1: true };

describe("SP1-TD2 verifier binding gate (deployment and rotation tooling)", function () {
  let admin: any, haltPrincipal: any, otherHaltPrincipal: any, stranger: any;
  let sp1: any, haltable: any, unhaltable: any, mock: any;

  beforeEach(async function () {
    [admin, haltPrincipal, otherHaltPrincipal, stranger] = await ethers.getSigners();
    sp1 = await deploySp1();
    haltable = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
    unhaltable = await (
      await ethers.getContractFactory("UnhaltableZkVerifierMock")
    ).deploy(await sp1.getAddress(), VKEY_A);
    mock = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
  });

  const request = (target: VerifierProfile, overrides: Partial<BindingRequest> = {}): BindingRequest => ({
    consumer: "WalletWallVault",
    target,
    chainId: SEPOLIA,
    signer: admin.address,
    allowMockSp1: false,
    current: null,
    targetIdentityRecordedHalted: false,
    scope: readHaltScope(),
    designations: readDesignations(),
    ...overrides,
  });

  describe("inputs come from the SP1-TD1 receipt, never typed", function () {
    it("the halt scope is the owner's amended scope: three consumers, the multisig vault excluded under its own gate", function () {
      const frozen = TD1.decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope;
      expect(readHaltScope()).to.deep.equal(frozen);
      expect(readHaltScope().applies).to.deep.equal([
        "PolicyControlBridge",
        "StablecoinVaultSimulator",
        "WalletWallVault",
      ]);
      expect(readHaltScope().excludedUntilRecoverable).to.deep.equal([
        { consumer: "WalletWallMultiSigVault", gate: "TD2-MULTISIG-ROTATION", interim: "NOT_BOUND_TO_THE_SP1_PATH" },
      ]);
      expect([...CONSUMERS].sort()).to.deep.equal([...TD1.decisions.DEFECT_RESPONSE_COUPLING.measuredConsumers].sort());
    });

    it("the designations are the trust target's code hash (per chain) and the designated PROGRAM_VKEY", function () {
      const d = readDesignations();
      expect(d.sp1VerifierCodeKeccak).to.equal(TD1.trustTarget.codeKeccak);
      expect(d.programVKey).to.equal(TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey);
      expect(Object.keys(d.sp1VerifierCodeKeccakByChain).sort()).to.deep.equal(["1", "11155111", "8453", "84532"]);
      for (const c of TD1.trustTarget.chains) expect(d.sp1VerifierCodeKeccakByChain[c.chainId]).to.equal(c.codeKeccak);
    });
  });

  describe("measuring a verifier from the chain", function () {
    it("profiles a haltable wrapper, a non-haltable SP1 verifier, the mock and an account without code", async function () {
      const p = await profileVerifier(ethers.provider, await haltable.getAddress());
      expect(p).to.include({
        hasCode: true,
        algorithmId: ZK_ALGORITHM_ID,
        sp1Verifier: await sp1.getAddress(),
        programVKey: VKEY_A,
        haltPrincipal: haltPrincipal.address,
        halted: false,
      });
      expect([isOnSp1Path(p), isHaltable(p)]).to.deep.equal([true, true]);
      const u = await profileVerifier(ethers.provider, await unhaltable.getAddress());
      expect([isOnSp1Path(u), isHaltable(u), u.haltPrincipal, u.halted]).to.deep.equal([true, false, null, null]);
      const m = await profileVerifier(ethers.provider, await mock.getAddress());
      expect([isOnSp1Path(m), isHaltable(m), m.identity]).to.deep.equal([false, false, null]);
      const eoa = await profileVerifier(ethers.provider, stranger.address);
      expect([eoa.hasCode, isOnSp1Path(eoa)]).to.deep.equal([false, false]);
      await haltable.connect(haltPrincipal).halt();
      expect((await profileVerifier(ethers.provider, await haltable.getAddress())).halted).to.equal(true);
    });

    it("computes the same identity the on-chain guard records", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      await haltable.connect(haltPrincipal).halt();
      await vault.proposePQVerifier(await recovery.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await vault.applyPQVerifierUpdate();
      const identity = (await profileVerifier(ethers.provider, await haltable.getAddress())).identity!;
      expect(await vault.haltedVerifierIdentities(identity)).to.equal(true);
      expect(
        await vault.haltedVerifierIdentities(
          (await profileVerifier(ethers.provider, await recovery.getAddress())).identity!,
        ),
      ).to.equal(false);
    });
  });

  describe("EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER", function () {
    it("deployment tooling refuses WalletWallMultiSigVault a haltable wrapper, and the consumers in scope are not refused it", async function () {
      await assert.rejects(
        checkDeploymentBinding(
          ethers.provider,
          "WalletWallMultiSigVault",
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /WalletWallMultiSigVault waits outside the halt for TD2-MULTISIG-ROTATION.*haltable wrapper would lock its funds/s,
      );
      // Positive controls: the same wrapper for each consumer in scope that is deployed bound to a verifier...
      for (const consumer of ["WalletWallVault", "StablecoinVaultSimulator"] as const) {
        await checkDeploymentBinding(ethers.provider, consumer, await haltable.getAddress(), admin.address, MOCK_OK);
      }
      // ...and the multisig vault itself, off the SP1 path (the mock verifier).
      await checkDeploymentBinding(
        ethers.provider,
        "WalletWallMultiSigVault",
        await mock.getAddress(),
        admin.address,
        MOCK_OK,
      );
    });

    it("refuses the multisig vault any part of the SP1 path, a non-haltable SP1 verifier included (its interim is NOT_BOUND_TO_THE_SP1_PATH)", async function () {
      await assert.rejects(
        checkDeploymentBinding(
          ethers.provider,
          "WalletWallMultiSigVault",
          await unhaltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /may be bound to no part of the SP1 path/,
      );
    });

    it("rotation tooling refuses to rotate a deployed multisig vault onto a haltable wrapper; a vault in scope may be", async function () {
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await multisig.getAddress(),
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /WalletWallMultiSigVault waits outside the halt/,
      );
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      const ok = await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await haltable.getAddress(),
        admin.address,
        MOCK_OK,
      );
      expect(ok.consumer).to.equal("WalletWallVault");
    });

    it("the scripts that bind a consumer go through the gate, naming the consumer they deploy", function () {
      const source = (rel: string) => readFileSync(resolve(rel), "utf8");
      expect(source("scripts/deploy.ts")).to.match(/checkDeploymentBinding\(\s*ethers\.provider,\s*"WalletWallVault",/);
      expect(source("scripts/deploy-multisig.ts")).to.match(
        /checkDeploymentBinding\(\s*ethers\.provider,\s*"WalletWallMultiSigVault",/,
      );
      // The gate runs before the consumer is deployed, so a refusal costs no deployment.
      for (const [rel, factory] of [
        ["scripts/deploy.ts", '"WalletWallVault"'],
        ["scripts/deploy-multisig.ts", '"WalletWallMultiSigVault"'],
      ]) {
        const s = source(rel);
        expect(s.indexOf("checkDeploymentBinding("), rel).to.be.lessThan(s.indexOf(`getContractFactory(${factory}`));
      }
      const propose = source("scripts/propose-verifier-update.ts");
      expect(propose).to.match(/checkRotationBinding\(/);
      expect(propose.indexOf("checkRotationBinding(")).to.be.lessThan(propose.indexOf(".proposePQVerifier("));
    });
  });

  describe("TD1-N12: recovery-target gating by process", function () {
    let designated: VerifierProfile;
    let mockSp1Wrapper: VerifierProfile;

    beforeEach(async function () {
      // A wrapper over the real SP1Verifier v6.1.0 bytes (CREATE2-authenticated in SP1-TD1) with the designated vkey.
      const receipt = await (await admin.sendTransaction({ data: BYTECODE.deployments["v6.1.0"].initcode })).wait();
      const real = await (
        await ethers.getContractFactory("ZKMLDSAVerifier")
      ).deploy(receipt.contractAddress, TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey, haltPrincipal.address);
      designated = await profileVerifier(ethers.provider, await real.getAddress());
      mockSp1Wrapper = await profileVerifier(ethers.provider, await haltable.getAddress());
    });

    it("positive control: a wrapper over the designated verifier code with the designated vkey passes on a non-local chain", function () {
      expect(designated.sp1VerifierCodeKeccak).to.equal(TD1.trustTarget.codeKeccak);
      expect(bindingRefusals(request(designated))).to.deep.equal([]);
    });

    it("refuses another SP1 verifier code or another PROGRAM_VKEY on a non-local chain, and grants no override there", function () {
      expect(bindingRefusals(request(mockSp1Wrapper)).join("\n")).to.match(/runtime code hash .* not the designated/);
      expect(bindingRefusals(request({ ...designated, programVKey: VKEY_B })).join("\n")).to.match(
        /PROGRAM_VKEY is .* not the designated/,
      );
      expect(bindingRefusals(request(mockSp1Wrapper, { allowMockSp1: true })).join("\n")).to.match(
        /no override exists on chain 11155111/,
      );
      // The override works only where it is meant to: a local chain.
      expect(bindingRefusals(request(mockSp1Wrapper, { chainId: LOCAL, allowMockSp1: true }))).to.deep.equal([]);
      expect(bindingRefusals(request(mockSp1Wrapper, { chainId: LOCAL })).length, "no flag, no mock").to.be.greaterThan(
        0,
      );
    });

    it("refuses a halted target, a recorded halted identity, a fresh deployment of the current halted identity, and a signer that can halt", function () {
      const cases: [string, BindingRequest, RegExp][] = [
        ["halted target", request({ ...designated, halted: true }), /is HALTED/],
        [
          "recorded halted identity",
          request(designated, { targetIdentityRecordedHalted: true }),
          /halted wrapper .* recorded/,
        ],
        [
          "fresh deployment of the current halted identity",
          request(designated, { current: { ...designated, address: stranger.address, halted: true } }),
          /fresh deployment of the halted identity/,
        ],
        [
          "signer is the target's halt principal",
          request(designated, { signer: haltPrincipal.address }),
          /halt principal never governs/,
        ],
        [
          "signer can halt the current verifier",
          request(designated, { current: { ...mockSp1Wrapper, haltPrincipal: admin.address } }),
          /can halt the current verifier/,
        ],
      ];
      for (const [label, req, refusal] of cases) expect(bindingRefusals(req).join("\n"), label).to.match(refusal);
      // Positive control: an ACTIVE current wrapper of the same identity does not disqualify a redeploy.
      expect(
        bindingRefusals(request(designated, { current: { ...designated, address: stranger.address } })),
      ).to.deep.equal([]);
    });

    it("refuses an SP1-path verifier that cannot be halted for a consumer in scope, and any consumer the scope does not name", function () {
      const u = { ...designated, haltPrincipal: null, halted: null };
      expect(bindingRefusals(request(u)).join("\n")).to.match(/not haltable: the halt would not reach WalletWallVault/);
      expect(bindingRefusals(request(designated, { consumer: "SomeOtherVault" })).join("\n")).to.match(
        /not a consumer the halt's scope names/,
      );
    });

    it("a verifier off the SP1 path (the mock) is outside these rules for the consumers in scope", async function () {
      const m = await profileVerifier(ethers.provider, await mock.getAddress());
      expect(bindingRefusals(request(m))).to.deep.equal([]);
      expect(bindingRefusals(request(m, { consumer: "StablecoinVaultSimulator" }))).to.deep.equal([]);
    });

    it("HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET, process side: on a live vault the tooling refuses a fresh deployment of its halted identity, as the chain does", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      await haltable.connect(haltPrincipal).halt();
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await vault.getAddress(),
          await fresh.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /fresh deployment of the halted identity/,
      );
      await expect(vault.proposePQVerifier(await fresh.getAddress())).to.be.revertedWithCustomError(
        vault,
        "HaltedVerifierIdentity",
      );
      // Positive control: an independent identity passes both.
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await recovery.getAddress(),
        admin.address,
        MOCK_OK,
      );
      await vault.proposePQVerifier(await recovery.getAddress());
    });

    it("HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET, process side: while excluded, the multisig vault is refused every SP1 target, a fresh deployment of a halted identity included", async function () {
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      await haltable.connect(haltPrincipal).halt();
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      for (const target of [haltable, fresh, recovery]) {
        await assert.rejects(
          checkRotationBinding(
            ethers.provider,
            await multisig.getAddress(),
            await target.getAddress(),
            admin.address,
            MOCK_OK,
          ),
          /WalletWallMultiSigVault waits outside the halt/,
        );
      }
      // Positive control: off the SP1 path the multisig vault's rotation tooling still works.
      const otherMock = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
      const profile = await profileVerifier(ethers.provider, await otherMock.getAddress());
      expect(bindingRefusals(request(profile, { consumer: "WalletWallMultiSigVault" }))).to.deep.equal([]);
    });
  });

  describe("identifying a consumer for rotation", function () {
    it("recognises the three rotating consumers by their EIP-712 domain and refuses anything else", async function () {
      const token = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      const sim = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await mock.getAddress());
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      const bridge = await (await ethers.getContractFactory("PolicyControlBridge")).deploy(stranger.address);
      expect(await identifyConsumer(ethers.provider, await vault.getAddress())).to.equal("WalletWallVault");
      expect(await identifyConsumer(ethers.provider, await sim.getAddress())).to.equal("StablecoinVaultSimulator");
      expect(await identifyConsumer(ethers.provider, await multisig.getAddress())).to.equal("WalletWallMultiSigVault");
      for (const other of [await bridge.getAddress(), await mock.getAddress(), stranger.address]) {
        await assert.rejects(
          identifyConsumer(ethers.provider, other),
          /not a WalletWall consumer with a verifier rotation/,
        );
      }
    });
  });
});
