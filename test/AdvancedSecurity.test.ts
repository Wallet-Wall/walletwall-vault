import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { WalletWallVault, MockMLDSAVerifier, WalletWallMultiSigVault } from "../typechain-types";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("Advanced Security (Phase 2)", function () {
  let vault: WalletWallVault;
  let multiSigVault: WalletWallMultiSigVault;
  let verifier: MockMLDSAVerifier;
  let owner: SignerWithAddress;
  let guardian1: SignerWithAddress;
  let guardian2: SignerWithAddress;
  let guardian3: SignerWithAddress;
  let other: SignerWithAddress;
  let newSigner: SignerWithAddress;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const NEW_PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));

  beforeEach(async function () {
    [owner, guardian1, guardian2, guardian3, other, newSigner] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
    multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());

    await vault.createVault(owner.address, PQ_KEY, 2); // Hybrid
  });

  describe("Guardian Recovery", function () {
    it("Should allow setting guardians", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      expect(await vault.vaultGuardians(owner.address, 0)).to.equal(guardian1.address);
    });

    it("Should initiate recovery (only by a guardian)", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);

      // Should fail if initiated by non-guardian
      await expect(vault.connect(other).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY))
        .to.be.revertedWithCustomError(vault, "NotAGuardian");

      // Should succeed if initiated by guardian
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      const request = await vault.recoveryRequests(owner.address);
      expect(request.newEcdsaSigner).to.equal(newSigner.address);
      expect(request.exists).to.be.true;
    });

    it("Should allow guardians to support recovery", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      await vault.connect(guardian1).supportRecovery(owner.address);
      let request = await vault.recoveryRequests(owner.address);
      expect(request.supportCount).to.equal(1);

      await vault.connect(guardian2).supportRecovery(owner.address);
      request = await vault.recoveryRequests(owner.address);
      expect(request.supportCount).to.equal(2);
    });

    it("Should execute recovery after delay and sufficient supports", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      await time.increase(7 * 24 * 60 * 60); // 7 days

      await vault.executeRecovery(owner.address);

      const vaultInfo = await vault.getVault(owner.address);
      expect(vaultInfo.ecdsaSigner).to.equal(newSigner.address);
      expect(vaultInfo.pqPublicKey).to.equal(NEW_PQ_KEY);
    });

    it("Should allow owner to cancel recovery", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.cancelRecovery();

      const request = await vault.recoveryRequests(owner.address);
      expect(request.exists).to.be.false;
    });
  });

  describe("Secure Credential Rotation", function () {
    it("Should rotate credentials with valid signatures", async function () {
      const nonce = 0;
      const deadline = (await time.latest()) + 3600;

      const domain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await vault.getAddress(),
      };

      const types = {
        RotateCredentials: [
          { name: "vaultOwner", type: "address" },
          { name: "newEcdsaSigner", type: "address" },
          { name: "newPQPublicKey", type: "bytes" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const request = {
        vaultOwner: owner.address,
        newEcdsaSigner: newSigner.address,
        newPQPublicKey: NEW_PQ_KEY,
        nonce: nonce,
        deadline: deadline,
      };

      const ecdsaSignature = await owner.signTypedData(domain, types, request);

      // Mock PQ signature (MockMLDSAVerifier just checks length and first byte)
      const pqSignature = ethers.hexlify(ethers.concat([
        "0x01", // non-zero first byte
        ethers.randomBytes(3308)
      ]));

      await vault.rotateCredentials(
        owner.address,
        newSigner.address,
        NEW_PQ_KEY,
        deadline,
        ecdsaSignature,
        pqSignature
      );

      const vaultInfo = await vault.getVault(owner.address);
      expect(vaultInfo.ecdsaSigner).to.equal(newSigner.address);
      expect(vaultInfo.pqPublicKey).to.equal(NEW_PQ_KEY);
    });
  });

  describe("Multi-Signature Vault", function () {
    it("Should create a multi-sig vault", async function () {
      const ecdsaSigners = [owner.address, guardian1.address];
      const pqKeys = [PQ_KEY, NEW_PQ_KEY];

      await multiSigVault.createVault(ecdsaSigners, 2, pqKeys, 2);
      const v = await multiSigVault.getVault(owner.address);
      expect(v.exists).to.be.true;
      expect(v.ecdsaThreshold).to.equal(2);
    });

    it("Should deposit and withdraw from multi-sig vault", async function () {
      const ecdsaSigners = [owner.address, guardian1.address].sort();
      const pqKeys = [PQ_KEY, NEW_PQ_KEY];

      // Re-create vault with sorted signers for easy recovery check
      const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
      multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());
      await multiSigVault.connect(owner).createVault(ecdsaSigners, 2, pqKeys, 2);

      await multiSigVault.deposit({ value: ethers.parseEther("1") });

      const nonce = 0;
      const deadline = (await time.latest()) + 3600;
      const amount = ethers.parseEther("0.5");
      const recipient = other.address;

      const domain = {
        name: "WalletWallMultiSigVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await multiSigVault.getAddress(),
      };

      const types = {
        MultiSigWithdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const request = {
        vaultOwner: owner.address,
        recipient: recipient,
        amount: amount,
        nonce: nonce,
        deadline: deadline,
      };

      // Sign with both ECDSA signers
      const sig1 = await owner.signTypedData(domain, types, request);
      const sig2 = await guardian1.signTypedData(domain, types, request);

      // Sort signatures based on signer address to match contract expectation
      const signers = [
        { addr: owner.address, sig: sig1 },
        { addr: guardian1.address, sig: sig2 }
      ].sort((a, b) => a.addr.localeCompare(b.addr));

      const ecdsaSignatures = signers.map(s => s.sig);

      const pqSignature1 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignature2 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignatures = [pqSignature1, pqSignature2];
      const pqKeyIndices = [0, 1];

      await multiSigVault.withdraw(request, ecdsaSignatures, pqSignatures, pqKeyIndices);

      expect(await ethers.provider.getBalance(recipient)).to.be.at.least(amount);
    });

    it("Should support p-of-q with indices", async function () {
      const ecdsaSigners = [owner.address];
      const pqKeys = [PQ_KEY, NEW_PQ_KEY, ethers.hexlify(ethers.randomBytes(1952))]; // 3 keys

      const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
      multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());
      await multiSigVault.connect(owner).createVault(ecdsaSigners, 1, pqKeys, 2); // 2 of 3 PQ

      await multiSigVault.deposit({ value: ethers.parseEther("1") });

      const deadline = (await time.latest()) + 3600;
      const request = {
        vaultOwner: owner.address,
        recipient: other.address,
        amount: ethers.parseEther("0.5"),
        nonce: 0,
        deadline: deadline,
      };

      const domain = {
        name: "WalletWallMultiSigVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await multiSigVault.getAddress(),
      };

      const types = {
        MultiSigWithdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const ecdsaSignature = await owner.signTypedData(domain, types, request);

      // Use keys 0 and 2
      const pqSignature1 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignature2 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await multiSigVault.withdraw(request, [ecdsaSignature], [pqSignature1, pqSignature2], [0, 2]);

      expect(await ethers.provider.getBalance(other.address)).to.be.at.least(ethers.parseEther("0.5"));
    });
  });
});
