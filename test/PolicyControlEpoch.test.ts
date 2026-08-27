import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, StablecoinVaultSimulator, MockMLDSAVerifier, MockUSDC } from "../typechain-types";

/**
 * The vault-owned policyControlEpoch (design doc L2): a monotonic counter, keyed by
 * vaultOwner, bumped on rotateCredentials and executeRecovery, and NOT bumped by
 * initiateRecovery/supportRecovery — a malicious guardian opening a request must not
 * be able to invalidate policy-control state before recovery actually succeeds (§9.3).
 *
 * This is the FIRST piece of the v0.13.0 policy-control authority lane and is measured
 * against EIP-170 immediately after it compiles, per the design doc's explicit stop
 * condition — before any bridge or policy work begins.
 */
describe("Policy-control epoch (vault-owned, L2)", function () {
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;
  const ROTATION_TYPES = {
    RotateCredentials: [
      { name: "vaultOwner", type: "address" },
      { name: "newEcdsaSigner", type: "address" },
      { name: "newPQPublicKey", type: "bytes" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;
  let verifier: MockMLDSAVerifier;

  beforeEach(async function () {
    [admin, owner, guardian1, guardian2, newSigner] = await ethers.getSigners();
    const Verifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
  });

  describe("WalletWallVault", function () {
    let vault: WalletWallVault;

    beforeEach(async function () {
      const Vault = await ethers.getContractFactory("WalletWallVault", admin);
      vault = await Vault.deploy(await verifier.getAddress());
      await vault.waitForDeployment();
      await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
    });

    /** Builds and submits a valid rotateCredentials call for `owner`, permissionless caller. */
    async function rotate(newSignerAddr: string, newPq: string) {
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const domain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await vault.getAddress(),
      };
      const request = {
        vaultOwner: owner.address,
        newEcdsaSigner: newSignerAddr,
        newPQPublicKey: newPq,
        nonce: Number(await vault.nonces(owner.address)),
        deadline,
      };
      const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const auth = {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
        currentPqSignature: blob(),
        newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, request),
        newPqSignature: blob(),
      };
      return vault.rotateCredentials(owner.address, newSignerAddr, newPq, deadline, auth);
    }

    it("starts at epoch 0 for a fresh vault owner", async function () {
      expect(await vault.policyControlEpoch(owner.address)).to.equal(0n);
    });

    it("bumps on rotateCredentials", async function () {
      const before = await vault.policyControlEpoch(owner.address);
      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await rotate(newSigner.address, newPq);
      expect(await vault.policyControlEpoch(owner.address)).to.equal(before + 1n);
    });

    it("bumps on executeRecovery", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      const before = await vault.policyControlEpoch(owner.address);

      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await vault.executeRecovery(owner.address);
      expect(await vault.policyControlEpoch(owner.address)).to.equal(before + 1n);
    });

    it("does NOT bump on initiateRecovery — opening a request must not invalidate control (§9.3)", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      const before = await vault.policyControlEpoch(owner.address);

      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq);
      expect(await vault.policyControlEpoch(owner.address)).to.equal(before);
    });

    it("does NOT bump on supportRecovery — support alone must not invalidate control (§9.3)", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      const before = await vault.policyControlEpoch(owner.address);

      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq);
      await vault.connect(guardian1).supportRecovery(owner.address);
      expect(await vault.policyControlEpoch(owner.address)).to.equal(before);
    });

    it("is independent per vaultOwner — rotating one owner's credentials does not bump another's", async function () {
      const [, , , , , otherOwner] = await ethers.getSigners();
      await vault
        .connect(otherOwner)
        .createVault(otherOwner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("1") });

      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await rotate(newSigner.address, newPq);

      expect(await vault.policyControlEpoch(owner.address)).to.equal(1n);
      expect(await vault.policyControlEpoch(otherOwner.address)).to.equal(0n);
    });

    it("executeRecovery makes NO call to any policy contract (recovery liveness, §9.2/§10.3)", async function () {
      // A policy engine that reverts on every call must not block recovery. If
      // executeRecovery ever called into the policy engine, this test would revert
      // instead of succeeding.
      const AlwaysReverts = await ethers.getContractFactory("AlwaysRevertingPolicyEngine");
      const badEngine = await AlwaysReverts.deploy();
      await badEngine.waitForDeployment();

      await vault.connect(admin).proposePolicyEngine(await badEngine.getAddress());
      await networkHelpers.time.increase(2 * 24 * 60 * 60);
      await vault.connect(admin).applyPolicyEngine();

      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(vault.executeRecovery(owner.address)).to.not.revert(ethers);
      expect(await vault.policyControlEpoch(owner.address)).to.equal(1n);
    });
  });

  describe("StablecoinVaultSimulator", function () {
    let sim: StablecoinVaultSimulator;
    let token: MockUSDC;

    beforeEach(async function () {
      const Token = await ethers.getContractFactory("MockUSDC");
      token = await Token.deploy();
      await token.waitForDeployment();

      const Sim = await ethers.getContractFactory("StablecoinVaultSimulator", admin);
      sim = await Sim.deploy(await token.getAddress(), await verifier.getAddress());
      await sim.waitForDeployment();

      await token.mint(owner.address, ethers.parseUnits("1000", 6));
      await token.connect(owner).approve(await sim.getAddress(), ethers.parseUnits("1000", 6));
      await sim.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);
      await sim.connect(owner).deposit(ethers.parseUnits("100", 6));
    });

    async function rotateSim(newSignerAddr: string, newPq: string) {
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const domain = {
        name: "WalletWallStablecoinVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await sim.getAddress(),
      };
      const request = {
        vaultOwner: owner.address,
        newEcdsaSigner: newSignerAddr,
        newPQPublicKey: newPq,
        nonce: Number(await sim.nonces(owner.address)),
        deadline,
      };
      const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const auth = {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
        currentPqSignature: blob(),
        newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, request),
        newPqSignature: blob(),
      };
      return sim.rotateCredentials(owner.address, newSignerAddr, newPq, deadline, auth);
    }

    it("starts at epoch 0, bumps on rotateCredentials, bumps on executeRecovery", async function () {
      expect(await sim.policyControlEpoch(owner.address)).to.equal(0n);

      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      await rotateSim(newSigner.address, newPq);
      expect(await sim.policyControlEpoch(owner.address)).to.equal(1n);

      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      const newPq2 = ethers.hexlify(ethers.randomBytes(1952));
      await sim.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq2);
      await sim.connect(guardian1).supportRecovery(owner.address);
      await sim.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60);
      await sim.executeRecovery(owner.address);
      expect(await sim.policyControlEpoch(owner.address)).to.equal(2n);
    });
  });
});
