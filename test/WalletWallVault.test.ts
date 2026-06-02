import { expect } from "chai";
import { ethers } from "hardhat";
import { WOTSSigner } from "../pqc/pqc-signer";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { WalletWallVault, SignatureVerifier } from "../typechain-types";

describe("WalletWallVault", function () {
  let vault: WalletWallVault;
  let verifier: SignatureVerifier;
  let owner: HardhatEthersSigner;
  let otherAccount: HardhatEthersSigner;
  let pqcKeyHash: string;
  let pqcPrivateKey: string[];

  beforeEach(async function () {
    [owner, otherAccount] = await ethers.getSigners();

    const SignatureVerifier = await ethers.getContractFactory("SignatureVerifier");
    verifier = await SignatureVerifier.deploy();
    await verifier.waitForDeployment();

    const WalletWallVault = await ethers.getContractFactory("WalletWallVault");
    vault = await WalletWallVault.deploy(await verifier.getAddress());
    await vault.waitForDeployment();

    const seed = ethers.randomBytes(32);
    const keyPair = WOTSSigner.generateKeyPair(seed);
    pqcKeyHash = keyPair.publicKeyHash;
    pqcPrivateKey = keyPair.privateKey;
  });

  describe("Vault Creation", function () {
    it("Should create a vault with owner and PQC public key hash", async function () {
      await expect(vault.createVault(pqcKeyHash))
        .to.emit(vault, "VaultCreated")
        .withArgs(owner.address, pqcKeyHash);

      const vaultDetails = await vault.getVault(owner.address);
      expect(vaultDetails.owner).to.equal(owner.address);
      expect(vaultDetails.pqcPublicKeyHash).to.equal(pqcKeyHash);
    });
  });

  describe("Withdrawal", function () {
    const depositAmount = ethers.parseEther("10.0");
    const withdrawAmount = ethers.parseEther("1.0");

    beforeEach(async function () {
      await vault.createVault(pqcKeyHash);
      await vault.deposit({ value: depositAmount });
    });

    it("Should succeed with valid ECDSA and WOTS+ signatures", async function () {
      const recipient = otherAccount.address;
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "address"],
        [owner.address, withdrawAmount, recipient]
      );

      const pqcSignature = WOTSSigner.sign(messageHash, pqcPrivateKey);
      const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

      await expect(vault.withdraw(withdrawAmount, recipient, ecdsaSignature, pqcSignature))
        .to.emit(vault, "Withdrawn")
        .withArgs(owner.address, recipient, withdrawAmount);
    });

    it("Should fail with invalid PQC signature", async function () {
      const recipient = otherAccount.address;
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "address"],
        [owner.address, withdrawAmount, recipient]
      );

      const pqcSignature = WOTSSigner.sign(messageHash, pqcPrivateKey);
      pqcSignature[0] = ethers.ZeroHash; // Corrupt signature
      const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

      await expect(vault.withdraw(withdrawAmount, recipient, ecdsaSignature, pqcSignature))
        .to.be.revertedWith("Invalid PQC signature");
    });
  });
});
