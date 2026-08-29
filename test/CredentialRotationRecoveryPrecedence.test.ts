import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier } from "../typechain-types";

// H3 (docs/Guardian_Authority_Design.md §10): guardian recovery is independent
// recovery authority and is NOT invalidated by a later credential rotation.
// rotateCredentials deliberately does not touch recoveryRequests — a successful
// rotation proves the current keys were not LOST, not that they were never
// COMPROMISED (key theft is copy theft), so cancelling recovery on rotation would
// hand a credential thief a standing, pre-signable veto over their own remedy.
// This file pins that precedence behaviorally. No contract behavior changes here.

const ROTATION_TYPES = {
  RotateCredentials: [
    { name: "vaultOwner", type: "address" },
    { name: "newEcdsaSigner", type: "address" },
    { name: "newPQPublicKey", type: "bytes" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

async function signRotation(
  vault: WalletWallVault,
  vaultOwnerAddr: string,
  currentSigner: HardhatEthersSigner,
  newEcdsaSigner: HardhatEthersSigner,
  newPQPublicKey: string,
) {
  const deadline = (await networkHelpers.time.latest()) + 3600;
  const domain = {
    name: "WalletWallVault",
    version: "1",
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await vault.getAddress(),
  };
  const request = {
    vaultOwner: vaultOwnerAddr,
    newEcdsaSigner: newEcdsaSigner.address,
    newPQPublicKey,
    nonce: Number(await vault.nonces(vaultOwnerAddr)),
    deadline,
  };
  const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
  const auth = {
    currentEcdsaSignature: await currentSigner.signTypedData(domain, ROTATION_TYPES, request),
    currentPqSignature: blob(),
    newEcdsaSignature: await newEcdsaSigner.signTypedData(domain, ROTATION_TYPES, request),
    newPqSignature: blob(),
  };
  return { deadline, auth };
}

describe("Guardian recovery survives credential rotation (H3)", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let owner: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let recoveryTarget: HardhatEthersSigner;
  let rotationTarget: HardhatEthersSigner;
  let rotationTarget2: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));

  beforeEach(async function () {
    [owner, guardian1, guardian2, other, recoveryTarget, rotationTarget, rotationTarget2] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    await vault.createVault(owner.address, PQ_KEY, 2); // Hybrid
    await vault.setGuardians([guardian1.address, guardian2.address, other.address]);
  });

  it("H3-1: rotation after reaching guardian quorum leaves the pending request completely unchanged", async function () {
    const recoveryPQKey = ethers.hexlify(ethers.randomBytes(1952));
    await vault.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, recoveryPQKey);
    await vault.connect(guardian1).supportRecovery(owner.address);
    await vault.connect(guardian2).supportRecovery(owner.address); // quorum: 2 of 3
    const before = await vault.recoveryRequests(owner.address);

    const rotatedPQKey = ethers.hexlify(ethers.randomBytes(1952));
    const { deadline, auth } = await signRotation(vault, owner.address, owner, rotationTarget, rotatedPQKey);
    await expect(vault.rotateCredentials(owner.address, rotationTarget.address, rotatedPQKey, deadline, auth)).to.emit(
      vault,
      "CredentialsRotated",
    );

    const after = await vault.recoveryRequests(owner.address);
    expect(after.exists).to.be.true;
    expect(after.newEcdsaSigner).to.equal(before.newEcdsaSigner);
    expect(after.newPQPublicKey).to.equal(before.newPQPublicKey);
    expect(after.executeAfter).to.equal(before.executeAfter);
    expect(after.supportCount).to.equal(before.supportCount);
  });

  it("H3-2: execution after rotation still succeeds and installs the recovery request's original target, not the rotated credentials", async function () {
    const recoveryPQKey = ethers.hexlify(ethers.randomBytes(1952));
    await vault.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, recoveryPQKey);
    await vault.connect(guardian1).supportRecovery(owner.address);
    await vault.connect(guardian2).supportRecovery(owner.address);

    const rotatedPQKey = ethers.hexlify(ethers.randomBytes(1952));
    const { deadline, auth } = await signRotation(vault, owner.address, owner, rotationTarget, rotatedPQKey);
    await vault.rotateCredentials(owner.address, rotationTarget.address, rotatedPQKey, deadline, auth);

    await networkHelpers.time.increase(7 * 24 * 60 * 60);
    await expect(vault.executeRecovery(owner.address))
      .to.emit(vault, "RecoveryExecuted")
      .withArgs(owner.address, recoveryTarget.address);

    const vaultInfo = await vault.getVault(owner.address);
    expect(vaultInfo.ecdsaSigner).to.equal(recoveryTarget.address);
    expect(vaultInfo.pqPublicKey).to.equal(recoveryPQKey);
  });

  it("H3-3: rotation before support is fully collected does not block the remaining guardians from supporting, and recovery still executes to its original target", async function () {
    const recoveryPQKey = ethers.hexlify(ethers.randomBytes(1952));
    await vault.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, recoveryPQKey);

    const rotatedPQKey = ethers.hexlify(ethers.randomBytes(1952));
    const { deadline, auth } = await signRotation(vault, owner.address, owner, rotationTarget, rotatedPQKey);
    await vault.rotateCredentials(owner.address, rotationTarget.address, rotatedPQKey, deadline, auth);

    // Support collected AFTER the rotation must still count normally.
    await vault.connect(guardian1).supportRecovery(owner.address);
    await expect(vault.connect(guardian2).supportRecovery(owner.address)).to.emit(vault, "RecoverySupported");
    expect((await vault.recoveryRequests(owner.address)).supportCount).to.equal(2);

    await networkHelpers.time.increase(7 * 24 * 60 * 60);
    await vault.executeRecovery(owner.address);
    expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(recoveryTarget.address);
  });

  it("H3-4: repeated valid rotations never mutate the pending recovery's target credentials", async function () {
    const recoveryPQKey = ethers.hexlify(ethers.randomBytes(1952));
    await vault.connect(guardian1).initiateRecovery(owner.address, recoveryTarget.address, recoveryPQKey);
    await vault.connect(guardian1).supportRecovery(owner.address);

    let currentSigner = owner;
    const rotationTargets = [rotationTarget, rotationTarget2];
    for (const target of rotationTargets) {
      const pq = ethers.hexlify(ethers.randomBytes(1952));
      const { deadline, auth } = await signRotation(vault, owner.address, currentSigner, target, pq);
      await vault.rotateCredentials(owner.address, target.address, pq, deadline, auth);
      currentSigner = target;

      const request = await vault.recoveryRequests(owner.address);
      expect(request.newEcdsaSigner).to.equal(recoveryTarget.address);
      expect(request.newPQPublicKey).to.equal(recoveryPQKey);
    }
  });
});
