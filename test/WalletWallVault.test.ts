import { expect } from "chai";
import { ethers } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { WalletWallVault, SignatureVerifier, MLDSAVerifier } from "../typechain-types";

describe("WalletWallVault", function () {
  let vault: WalletWallVault;
  let ecdsaVerifier: SignatureVerifier;
  let mlDsaVerifier: MLDSAVerifier;
  let owner: HardhatEthersSigner;
  let otherAccount: HardhatEthersSigner;

  let pqPublicKey: Uint8Array;
  let pqPrivateKey: Uint8Array;

  beforeEach(async function () {
    [owner, otherAccount] = await ethers.getSigners();

    const SignatureVerifier = await ethers.getContractFactory("SignatureVerifier");
    ecdsaVerifier = await SignatureVerifier.deploy();
    await ecdsaVerifier.waitForDeployment();

    const MLDSAVerifier = await ethers.getContractFactory("MLDSAVerifier");
    mlDsaVerifier = await MLDSAVerifier.deploy();
    await mlDsaVerifier.waitForDeployment();

    const WalletWallVault = await ethers.getContractFactory("WalletWallVault");
    vault = await WalletWallVault.deploy(await ecdsaVerifier.getAddress(), await mlDsaVerifier.getAddress());
    await vault.waitForDeployment();

    const keyPair = MLDSASigner.generateKeyPair();
    pqPublicKey = keyPair.publicKey;
    pqPrivateKey = keyPair.privateKey;
  });

  describe("Vault Creation", function () {
    it("Should create a vault with owner, ECDSA signer and NIST PQ public key", async function () {
      const pqPubKeyHex = MLDSASigner.toHex(pqPublicKey);
      await expect(vault.createVault(owner.address, pqPubKeyHex, true))
        .to.emit(vault, "VaultCreated")
        .withArgs(owner.address, owner.address, pqPubKeyHex, true);

      const vaultDetails = await vault.getVault(owner.address);
      expect(vaultDetails.ecdsaSigner).to.equal(owner.address);
      expect(vaultDetails.pqPublicKey).to.equal(pqPubKeyHex);
      expect(vaultDetails.requireBoth).to.be.true;
    });
  });

  describe("Balance Tracking", function () {
    it("Should track deposits correctly for each vault", async function () {
        await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), true);
        await vault.connect(otherAccount).createVault(otherAccount.address, MLDSASigner.toHex(pqPublicKey), true);

        const depositAmount = ethers.parseEther("1.0");
        await vault.deposit({ value: depositAmount });

        let ownerVault = await vault.getVault(owner.address);
        let otherVault = await vault.getVault(otherAccount.address);

        expect(ownerVault.balance).to.equal(depositAmount);
        expect(otherVault.balance).to.equal(0n);

        await vault.connect(otherAccount).deposit({ value: depositAmount });
        otherVault = await vault.getVault(otherAccount.address);
        expect(otherVault.balance).to.equal(depositAmount);
    });

    it("Should fail withdrawal if individual vault balance is insufficient", async function () {
        await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), true);
        await vault.connect(otherAccount).createVault(otherAccount.address, MLDSASigner.toHex(pqPublicKey), true);

        // otherAccount deposits 5 ETH
        await vault.connect(otherAccount).deposit({ value: ethers.parseEther("5.0") });

        // owner deposits only 1 ETH
        await vault.deposit({ value: ethers.parseEther("1.0") });

        const recipient = owner.address;
        const withdrawAmount = ethers.parseEther("2.0");
        const nonce = 0;
        const messageHash = ethers.solidityPackedKeccak256(
            ["address", "uint256", "address", "uint256", "address"],
            [owner.address, withdrawAmount, recipient, nonce, await vault.getAddress()]
        );

        const pqSignature = MLDSASigner.sign(messageHash, pqPrivateKey);
        const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

        // Should fail even if contract has enough total ETH (6.0), because owner only has 1.0
        await expect(vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, MLDSASigner.toHex(pqSignature)))
            .to.be.revertedWith("Insufficient vault balance");
    });
  });

  describe("Access Control", function () {
    it("Should only allow owner to update PQ verifier", async function () {
        const newVerifier = await (await ethers.getContractFactory("MLDSAVerifier")).deploy();
        const newVerifierAddr = await newVerifier.getAddress();

        await expect(vault.connect(otherAccount).updatePQVerifier(newVerifierAddr))
            .to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");

        await expect(vault.updatePQVerifier(newVerifierAddr))
            .to.emit(vault, "PQVerifierUpdated")
            .withArgs(newVerifierAddr);
    });
  });

  describe("Withdrawal (Hybrid Mode)", function () {
    const depositAmount = ethers.parseEther("10.0");
    const withdrawAmount = ethers.parseEther("1.0");

    beforeEach(async function () {
      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), true);
      await vault.deposit({ value: depositAmount });
    });

    it("Should succeed with valid ECDSA and ML-DSA signatures", async function () {
      const recipient = otherAccount.address;
      const nonce = 0;

      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "address", "uint256", "address"],
        [owner.address, withdrawAmount, recipient, nonce, await vault.getAddress()]
      );

      const pqSignature = MLDSASigner.sign(messageHash, pqPrivateKey);
      const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

      await expect(vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, MLDSASigner.toHex(pqSignature)))
        .to.emit(vault, "Withdrawn")
        .withArgs(owner.address, recipient, withdrawAmount, nonce);

      const vaultDetails = await vault.getVault(owner.address);
      expect(vaultDetails.nonce).to.equal(1);
      expect(vaultDetails.balance).to.equal(depositAmount - withdrawAmount);
    });

    it("Should fail with invalid PQC signature", async function () {
      const recipient = otherAccount.address;
      const nonce = 0;
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "address", "uint256", "address"],
        [owner.address, withdrawAmount, recipient, nonce, await vault.getAddress()]
      );

      // Create an invalid signature (wrong length)
      const invalidPqSignature = new Uint8Array(100);
      const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

      await expect(vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, MLDSASigner.toHex(invalidPqSignature)))
        .to.be.revertedWith("Invalid PQC signature");
    });

    it("Should fail with invalid ECDSA signature", async function () {
      const recipient = otherAccount.address;
      const nonce = 0;
      const messageHash = ethers.solidityPackedKeccak256(
        ["address", "uint256", "address", "uint256", "address"],
        [owner.address, withdrawAmount, recipient, nonce, await vault.getAddress()]
      );

      const pqSignature = MLDSASigner.sign(messageHash, pqPrivateKey);
      const invalidEcdsaSignature = await otherAccount.signMessage(ethers.getBytes(messageHash));

      await expect(vault.withdraw(withdrawAmount, recipient, nonce, invalidEcdsaSignature, MLDSASigner.toHex(pqSignature)))
        .to.be.revertedWith("Invalid ECDSA signature");
    });

    it("Should fail if same nonce is used twice", async function () {
        const recipient = otherAccount.address;
        const nonce = 0;
        const messageHash = ethers.solidityPackedKeccak256(
          ["address", "uint256", "address", "uint256", "address"],
          [owner.address, withdrawAmount, recipient, nonce, await vault.getAddress()]
        );

        const pqSignature = MLDSASigner.sign(messageHash, pqPrivateKey);
        const ecdsaSignature = await owner.signMessage(ethers.getBytes(messageHash));

        await vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, MLDSASigner.toHex(pqSignature));

        // Try again with same nonce
        await expect(vault.withdraw(withdrawAmount, recipient, nonce, ecdsaSignature, MLDSASigner.toHex(pqSignature)))
          .to.be.revertedWith("Invalid nonce");
      });
  });
});
