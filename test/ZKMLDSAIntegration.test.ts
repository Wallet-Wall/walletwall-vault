import { expect } from "chai";
import { ethers } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";
import { ProverClient } from "../scripts/prover-client";

describe("ZKMLDSAVerifier Integration", function () {
  let vault: any;
  let zkVerifier: any;
  let owner: any;
  let recipient: any;

  const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("MOCK_VKEY"));

  let mockSp1Verifier: any;

  beforeEach(async function () {
    [owner, recipient] = await ethers.getSigners();

    // Deploy a mock SP1 Verifier
    const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
    mockSp1Verifier = await MockSP1Verifier.deploy();
    const sp1VerifierAddress = await mockSp1Verifier.getAddress();

    const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
    zkVerifier = await ZKMLDSAVerifier.deploy(sp1VerifierAddress, PROGRAM_VKEY);

    const WalletWallVault = await ethers.getContractFactory("WalletWallVault");
    vault = await WalletWallVault.deploy(await zkVerifier.getAddress());
  });

  it("should accept a withdrawal with a ZK proof in Hybrid mode", async function () {
    const amount = ethers.parseEther("1.0");

    // Create PQ material
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();

    // Create vault with owner's credentials
    await vault.createVault(owner.address, publicKey, 2); // 2 = Hybrid

    // Deposit funds
    await vault.deposit({ value: amount });

    const nonce = await vault.nonces(owner.address);
    const { latest } = await ethers.provider.getBlock("latest");
    const deadline = (latest?.timestamp ?? Math.floor(Date.now() / 1000)) + 3600;

    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };

    const types = {
      Withdrawal: [
        { name: "vaultOwner", type: "address" },
        { name: "recipient", type: "address" },
        { name: "amount", type: "uint256" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
        { name: "vaultMode", type: "uint8" },
      ],
    };

    const request = {
      vaultOwner: owner.address,
      recipient: recipient.address,
      amount: amount,
      nonce: nonce,
      deadline: deadline,
      vaultMode: 2, // Hybrid
    };

    const ecdsaSignature = await owner.signTypedData(domain, types, request);
    const digest = ethers.TypedDataEncoder.hash(domain, types, request);

    const pqSignature = MLDSASigner.sign(digest, privateKey);

    // Generate ZK proof payload
    const zkProofPayload = await ProverClient.generateProof(
      digest,
      publicKey,
      pqSignature,
      (await ethers.provider.getNetwork()).chainId,
      await zkVerifier.getAddress(),
    );

    // Execute withdrawal
    const tx = await vault.withdraw(request, ecdsaSignature, zkProofPayload);
    await expect(tx).to.emit(vault, "Withdrawn");

    const finalBalance = await ethers.provider.getBalance(recipient.address);
    expect(finalBalance).to.be.gt(amount);
  });

  it("should reject a withdrawal if the digest is tampered in the proof", async function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    await vault.createVault(owner.address, publicKey, 2);
    await vault.deposit({ value: ethers.parseEther("1.0") });

    const digest = ethers.keccak256(ethers.toUtf8Bytes("correct digest"));
    const tamperedDigest = ethers.keccak256(ethers.toUtf8Bytes("tampered digest"));

    const pqSignature = MLDSASigner.sign(digest, privateKey);
    const zkProofPayload = await ProverClient.generateProof(
      tamperedDigest, // Mismatch!
      publicKey,
      pqSignature,
      (await ethers.provider.getNetwork()).chainId,
      await zkVerifier.getAddress(),
    );

    const { latest } = await ethers.provider.getBlock("latest");
    const deadline = (latest?.timestamp ?? Math.floor(Date.now() / 1000)) + 3600;

    const request = {
      vaultOwner: owner.address,
      recipient: recipient.address,
      amount: ethers.parseEther("0.1"),
      nonce: 0,
      deadline: deadline,
      vaultMode: 2,
    };
    const ecdsaSignature = await owner.signTypedData(
      {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await vault.getAddress(),
      },
      {
        Withdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "vaultMode", type: "uint8" },
        ],
      },
      request,
    );

    await expect(vault.withdraw(request, ecdsaSignature, zkProofPayload)).to.be.revertedWithCustomError(
      vault,
      "InvalidPQSignature",
    );
  });

  it("should reject a withdrawal if the SP1 verifier fails", async function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    await vault.createVault(owner.address, publicKey, 2);
    await vault.deposit({ value: ethers.parseEther("1.0") });

    const digest = ethers.keccak256(ethers.toUtf8Bytes("some digest"));
    const pqSignature = MLDSASigner.sign(digest, privateKey);
    const zkProofPayload = await ProverClient.generateProof(
      digest,
      publicKey,
      pqSignature,
      (await ethers.provider.getNetwork()).chainId,
      await zkVerifier.getAddress(),
    );

    await mockSp1Verifier.setShouldSucceed(false);

    const { latest } = await ethers.provider.getBlock("latest");
    const deadline = (latest?.timestamp ?? Math.floor(Date.now() / 1000)) + 3600;

    const request = {
      vaultOwner: owner.address,
      recipient: recipient.address,
      amount: ethers.parseEther("0.1"),
      nonce: 0,
      deadline: deadline,
      vaultMode: 2,
    };
    const ecdsaSignature = await owner.signTypedData(
      {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await vault.getAddress(),
      },
      {
        Withdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "vaultMode", type: "uint8" },
        ],
      },
      request,
    );

    await expect(vault.withdraw(request, ecdsaSignature, zkProofPayload)).to.be.revertedWithCustomError(
      vault,
      "InvalidPQSignature",
    );
  });
});
