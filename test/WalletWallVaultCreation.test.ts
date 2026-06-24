import { expect } from "chai";
import { ethers } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { WalletWallVault, MockMLDSAVerifier } from "../typechain-types";

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

describe("WalletWallVault - Payable Creation", function () {
  let vault: WalletWallVault;
  let mockVerifier: MockMLDSAVerifier;
  let owner: HardhatEthersSigner;
  let otherAccount: HardhatEthersSigner;
  let pqPublicKey: Uint8Array;

  beforeEach(async function () {
    [owner, otherAccount] = await ethers.getSigners();

    const MockMLDSAVerifierFactory = await ethers.getContractFactory("MockMLDSAVerifier");
    mockVerifier = await MockMLDSAVerifierFactory.deploy();
    await mockVerifier.waitForDeployment();

    const WalletWallVaultFactory = await ethers.getContractFactory("WalletWallVault");
    vault = await WalletWallVaultFactory.deploy(await mockVerifier.getAddress());
    await vault.waitForDeployment();

    const keyPair = MLDSASigner.generateKeyPair();
    pqPublicKey = keyPair.publicKey;
  });

  it("Should allow creating a vault with 0 deposit (msg.value = 0)", async function () {
    const pqHex = MLDSASigner.toHex(pqPublicKey);
    await expect(vault.createVault(owner.address, pqHex, VaultMode.Hybrid))
      .to.emit(vault, "VaultCreated")
      .withArgs(owner.address, owner.address, pqHex, VaultMode.Hybrid);

    const details = await vault.getVault(owner.address);
    expect(details.balance).to.equal(0n);
    expect(details.exists).to.be.true;
  });

  it("Should allow creating a vault with initial deposit (msg.value > 0) and emit Deposited", async function () {
    const pqHex = MLDSASigner.toHex(pqPublicKey);
    const depositAmount = ethers.parseEther("1.5");

    await expect(vault.createVault(owner.address, pqHex, VaultMode.Hybrid, { value: depositAmount }))
      .to.emit(vault, "VaultCreated")
      .withArgs(owner.address, owner.address, pqHex, VaultMode.Hybrid)
      .and.to.emit(vault, "Deposited")
      .withArgs(owner.address, owner.address, depositAmount);

    const details = await vault.getVault(owner.address);
    expect(details.balance).to.equal(depositAmount);
    expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(depositAmount);
  });
});
