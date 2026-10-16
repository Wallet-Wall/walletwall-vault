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

    it("reads a malformed answer as no answer, as the on-chain guard does (positive control: well-formed answers are read)", async function () {
      const m = await (await ethers.getContractFactory("MisbehavingVerifierMock")).deploy();
      const sel = (signature: string) => ethers.id(signature).slice(0, 10);
      const [RETURN, REVERT_WITH_WORD, RETURN_SHORT] = [1, 2, 3];
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.toBeHex(BigInt(admin.address) | (1n << 200n), 32));
      await m.program(sel("halted()"), RETURN_SHORT, ethers.toBeHex(1n << 248n, 32));
      await m.program(sel("SP1_VERIFIER()"), REVERT_WITH_WORD, ethers.zeroPadValue(await sp1.getAddress(), 32));
      await m.program(sel("PROGRAM_VKEY()"), RETURN, VKEY_A);
      const p = await profileVerifier(ethers.provider, await m.getAddress());
      expect([p.haltPrincipal, p.halted, p.sp1Verifier, p.sp1VerifierCodeKeccak, p.identity]).to.deep.equal([
        null,
        null,
        null,
        null,
        null,
      ]);
      expect(p.programVKey).to.equal(VKEY_A);
      // A zero halt principal names no one; an SP1 verifier without code has no code hash, so no identity.
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.ZeroHash);
      await m.program(sel("SP1_VERIFIER()"), RETURN, ethers.zeroPadValue(stranger.address, 32));
      const z = await profileVerifier(ethers.provider, await m.getAddress());
      expect([z.haltPrincipal, z.sp1Verifier, z.sp1VerifierCodeKeccak, z.identity]).to.deep.equal([
        null,
        stranger.address,
        null,
        null,
      ]);
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.zeroPadValue(admin.address, 32));
      await m.program(sel("halted()"), RETURN, ethers.zeroPadValue("0x01", 32));
      await m.program(sel("SP1_VERIFIER()"), RETURN, ethers.zeroPadValue(await sp1.getAddress(), 32));
      const q = await profileVerifier(ethers.provider, await m.getAddress());
      expect([q.haltPrincipal, q.halted, q.sp1Verifier]).to.deep.equal([admin.address, true, await sp1.getAddress()]);
      expect(q.identity).to.equal((await profileVerifier(ethers.provider, await haltable.getAddress())).identity);
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
      // deploy.ts gates the vault itself; deploy-multisig.ts runs deployMultisigVault, which gates the multisig vault
      // (exercised in test/Sp1Td2DeploymentTooling.test.ts). Each gate runs before its consumer is deployed.
      expect(source("scripts/deploy.ts")).to.match(/checkDeploymentBinding\(\s*ethers\.provider,\s*"WalletWallVault",/);
      expect(source("scripts/deploy-multisig.ts")).to.match(/deployMultisigVault\(/);
      expect(source("scripts/deploy-multisig.ts")).to.not.match(/getContractFactory\(/);
      const lib = source("scripts/lib/deployment-guards.ts");
      expect(lib).to.match(/checkDeploymentBinding\(\s*ethers\.provider,\s*"WalletWallMultiSigVault",/);
      for (const [rel, factory] of [
        ["scripts/deploy.ts", '"WalletWallVault"'],
        ["scripts/lib/deployment-guards.ts", '"WalletWallMultiSigVault"'],
      ]) {
        const text = source(rel);
        expect(text.indexOf("checkDeploymentBinding("), rel).to.be.lessThan(
          text.indexOf(`getContractFactory(${factory}`),
        );
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

    it("refuses a target without code; a designated wrapper passes on a local chain without any override", function () {
      expect(bindingRefusals(request({ ...designated, hasCode: false })).join("\n")).to.match(/has no code/);
      expect(bindingRefusals(request(designated, { chainId: LOCAL }))).to.deep.equal([]);
    });

    it("checks the code hash designated for the chain, falling back to the trust target's only where the chain has none", function () {
      const other = `0x${"ab".repeat(32)}`;
      const designations = {
        ...readDesignations(),
        sp1VerifierCodeKeccakByChain: { ...readDesignations().sp1VerifierCodeKeccakByChain, "11155111": other },
      };
      expect(bindingRefusals(request({ ...designated, sp1VerifierCodeKeccak: other }, { designations }))).to.deep.equal(
        [],
      );
      expect(bindingRefusals(request(designated, { designations })).join("\n")).to.match(/not the designated 0xabab/);
      // A chain the designations do not list falls back to the trust target's code hash.
      expect(bindingRefusals(request(designated, { designations, chainId: 10_000n }))).to.deep.equal([]);
    });

    it("anything that answers one part of the SP1 surface is on the SP1 path, and a wrapper needs both halves of the halt surface", function () {
      const bare: VerifierProfile = {
        address: stranger.address,
        hasCode: true,
        algorithmId: null,
        sp1Verifier: null,
        sp1VerifierCodeKeccak: null,
        programVKey: null,
        haltPrincipal: null,
        halted: null,
        identity: null,
      };
      expect(isOnSp1Path(bare), "positive control: nothing answered").to.equal(false);
      for (const part of [
        { algorithmId: ZK_ALGORITHM_ID },
        { sp1Verifier: stranger.address },
        { programVKey: VKEY_A },
        { haltPrincipal: haltPrincipal.address },
        { halted: false },
      ]) {
        const p = { ...bare, ...part };
        expect(isOnSp1Path(p), JSON.stringify(part)).to.equal(true);
        expect(bindingRefusals(request(p, { consumer: "WalletWallMultiSigVault" })).join("\n")).to.match(
          /may be bound to no part of the SP1 path/,
        );
      }
      expect(isHaltable({ ...bare, haltPrincipal: haltPrincipal.address })).to.equal(false);
      expect(isHaltable({ ...bare, halted: false })).to.equal(false);
      expect(isHaltable({ ...bare, haltPrincipal: haltPrincipal.address, halted: false })).to.equal(true);
      for (const half of [{ halted: null }, { haltPrincipal: null }]) {
        expect(bindingRefusals(request({ ...designated, ...half })).join("\n"), JSON.stringify(half)).to.match(
          /not haltable/,
        );
      }
    });

    it("end to end: after a vault leaves a halted wrapper, the tooling refuses that identity from the record the vault keeps", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      await haltable.connect(haltPrincipal).halt();
      await vault.proposePQVerifier(await recovery.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await vault.applyPQVerifierUpdate();
      // The current wrapper is ACTIVE now; only the recorded identity can refuse the redeploy.
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await vault.getAddress(),
          await fresh.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /has the identity of a halted wrapper WalletWallVault recorded/,
      );
      const independent = await deployWrapper(await deploySp1(), VKEY_B, haltPrincipal.address);
      await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await independent.getAddress(),
        admin.address,
        MOCK_OK,
      );
    });

    it("refuses an impostor that reports a consumer's EIP-712 domain but has no verifier", async function () {
      const impostor = await (await ethers.getContractFactory("Eip712DomainOnlyMock")).deploy("WalletWallVault");
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await impostor.getAddress(),
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /reports no pqVerifier/,
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
