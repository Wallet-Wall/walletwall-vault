import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, StablecoinVaultSimulator, MockMLDSAVerifier, MockUSDC } from "../typechain-types";

// L-E (docs/Guardian_Authority_Design.md §9.1): the vault and the simulator share
// an executable-statement-identical guardian/recovery/treasury-quorum surface, but
// nothing in the repo enforced that before this file — a one-sided guardian change
// could pass CI. These tests run the SAME scenario against both contracts and
// assert the SAME outcome, so a future one-sided edit fails here instead of
// silently diverging. Behavioral parity, not source-text equality.

const ROTATION_TYPES = {
  RotateCredentials: [
    { name: "vaultOwner", type: "address" },
    { name: "newEcdsaSigner", type: "address" },
    { name: "newPQPublicKey", type: "bytes" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

interface RotatableVault {
  getAddress(): Promise<string>;
  nonces(owner: string): Promise<bigint>;
  rotateCredentials(
    vaultOwner: string,
    newEcdsaSigner: string,
    newPQPublicKey: string,
    deadline: number,
    auth: {
      currentEcdsaSignature: string;
      currentPqSignature: string;
      newEcdsaSignature: string;
      newPqSignature: string;
    },
  ): Promise<unknown>;
}

async function signAndRotate(
  contract: RotatableVault,
  domainName: string,
  vaultOwnerAddr: string,
  currentSigner: HardhatEthersSigner,
  newEcdsaSigner: HardhatEthersSigner,
  newPQPublicKey: string,
) {
  const deadline = (await networkHelpers.time.latest()) + 3600;
  const domain = {
    name: domainName,
    version: "1",
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await contract.getAddress(),
  };
  const request = {
    vaultOwner: vaultOwnerAddr,
    newEcdsaSigner: newEcdsaSigner.address,
    newPQPublicKey,
    nonce: Number(await contract.nonces(vaultOwnerAddr)),
    deadline,
  };
  const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
  const auth = {
    currentEcdsaSignature: await currentSigner.signTypedData(domain, ROTATION_TYPES, request),
    currentPqSignature: blob(),
    newEcdsaSignature: await newEcdsaSigner.signTypedData(domain, ROTATION_TYPES, request),
    newPqSignature: blob(),
  };
  return contract.rotateCredentials(vaultOwnerAddr, newEcdsaSigner.address, newPQPublicKey, deadline, auth);
}

describe("Vault / simulator guardian-recovery parity (L-E)", function () {
  let owner: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;
  let recoveryTarget: HardhatEthersSigner;
  let rotationTarget: HardhatEthersSigner;

  let vault: WalletWallVault;
  let sim: StablecoinVaultSimulator;
  let verifier: MockMLDSAVerifier;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));

  beforeEach(async function () {
    [owner, guardian1, guardian2, guardian3, recoveryTarget, rotationTarget] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());
    await vault.createVault(owner.address, PQ_KEY, 2); // Hybrid

    const Token = await ethers.getContractFactory("MockUSDC");
    const token: MockUSDC = await Token.deploy();
    const Sim = await ethers.getContractFactory("StablecoinVaultSimulator");
    sim = await Sim.deploy(await token.getAddress(), await verifier.getAddress());
    await sim.connect(owner).createVault(owner.address, PQ_KEY, 2); // Hybrid

    await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
    await sim.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
  });

  it("parity: an under-supported matured request remains replaceable on both contracts", async function () {
    for (const c of [vault, sim] as const) {
      await c.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, PQ_KEY);
      await c.connect(guardian1).supportRecovery(owner.address); // 1 < required(2)
      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(c.connect(guardian2).initiateRecovery(owner.address, guardian3.address, PQ_KEY)).to.not.revert(
        ethers,
      );
      expect((await c.recoveryRequests(owner.address)).newEcdsaSigner).to.equal(guardian3.address);
    }
  });

  it("parity: a quorum-approved matured request is protected from replacement, and remains executable, on both contracts", async function () {
    for (const c of [vault, sim] as const) {
      await c.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, PQ_KEY);
      await c.connect(guardian1).supportRecovery(owner.address);
      await c.connect(guardian2).supportRecovery(owner.address); // 2 = required(2)
      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(
        c.connect(guardian3).initiateRecovery(owner.address, guardian3.address, PQ_KEY),
      ).to.be.revertedWithCustomError(c, "RecoveryAlreadyApproved");
      await expect(c.executeRecovery(owner.address)).to.not.revert(ethers);
      expect((await c.getVault(owner.address)).ecdsaSigner).to.equal(recoveryTarget.address);
    }
  });

  it("parity: credential rotation does not cancel a pending recovery on either contract", async function () {
    const domainName = { vault: "WalletWallVault", sim: "WalletWallStablecoinVault" };
    for (const [key, c] of [
      ["vault", vault],
      ["sim", sim],
    ] as const) {
      await c.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, PQ_KEY);
      await c.connect(guardian1).supportRecovery(owner.address);
      await c.connect(guardian2).supportRecovery(owner.address);

      const rotatedPQ = ethers.hexlify(ethers.randomBytes(1952));
      await signAndRotate(c, domainName[key], owner.address, owner, rotationTarget, rotatedPQ);
      expect((await c.recoveryRequests(owner.address)).exists).to.be.true;

      await networkHelpers.time.increase(7 * 24 * 60 * 60);
      await c.executeRecovery(owner.address);
      expect((await c.getVault(owner.address)).ecdsaSigner).to.equal(recoveryTarget.address);
    }
  });

  it("parity: guardian-set replacement invalidates a pending recovery, on both contracts", async function () {
    for (const c of [vault, sim] as const) {
      await c.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, PQ_KEY);
      await c.connect(guardian1).supportRecovery(owner.address);
      await c.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      expect((await c.recoveryRequests(owner.address)).exists).to.be.false;
    }
  });

  it("parity: setGuardians rejects a shrink that would strand an armed treasury quorum threshold, on both contracts", async function () {
    const [, , , , , , guardian4] = await ethers.getSigners();
    for (const c of [vault, sim] as const) {
      await c.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address, guardian4.address]);
      await c.connect(owner).setTreasuryQuorumThreshold(3);

      await expect(c.connect(owner).setGuardians([guardian1.address, guardian2.address]))
        .to.be.revertedWithCustomError(c, "TooManyGuardians")
        .withArgs(3, 2);
      expect(await c.treasuryQuorumThreshold(owner.address)).to.equal(3);
    }
  });
});
