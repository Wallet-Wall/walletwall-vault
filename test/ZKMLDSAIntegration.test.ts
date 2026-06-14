import { time } from "@nomicfoundation/hardhat-network-helpers";
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

  async function encodeMockProof(
    digest: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
    verifierAddress = zkVerifier.getAddress(),
  ) {
    return ProverClient.encodeProof(
      digest,
      publicKey,
      signature,
      (await ethers.provider.getNetwork()).chainId,
      await verifierAddress,
      ethers.hexlify(ethers.randomBytes(128)),
    );
  }

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
    const deadline = (await time.latest()) + 3600;

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
    const zkProofPayload = await encodeMockProof(digest, publicKey, pqSignature);

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
    const zkProofPayload = await encodeMockProof(tamperedDigest, publicKey, pqSignature);

    const deadline = (await time.latest()) + 3600;

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
    const zkProofPayload = await encodeMockProof(digest, publicKey, pqSignature);

    await mockSp1Verifier.setShouldSucceed(false);

    const deadline = (await time.latest()) + 3600;

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

  it("rejects an EOA as the SP1 verifier", async function () {
    const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
    await expect(ZKMLDSAVerifier.deploy(owner.address, PROGRAM_VKEY)).to.be.revertedWithCustomError(
      ZKMLDSAVerifier,
      "InvalidSP1Verifier",
    );
  });

  it("rejects a zero program verification key", async function () {
    const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
    await expect(
      ZKMLDSAVerifier.deploy(await mockSp1Verifier.getAddress(), ethers.ZeroHash),
    ).to.be.revertedWithCustomError(ZKMLDSAVerifier, "InvalidProgramVKey");
  });

  it("rejects malformed proof encoder inputs", async function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    const digest = ethers.keccak256(ethers.toUtf8Bytes("digest"));
    const signature = MLDSASigner.sign(digest, privateKey);

    let error: unknown;
    try {
      await ProverClient.encodeProof(
        digest,
        publicKey,
        signature,
        (await ethers.provider.getNetwork()).chainId,
        await zkVerifier.getAddress(),
        "0x",
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.contain("proofBytes must be non-empty");
  });

  it("returns false for malformed ABI proof payloads", async function () {
    const { publicKey } = MLDSASigner.generateKeyPair();
    const digest = ethers.keccak256(ethers.toUtf8Bytes("digest"));

    expect(await zkVerifier.verify(digest, publicKey, "0x1234")).to.be.false;
    expect(await zkVerifier.verify(digest, publicKey, ethers.zeroPadValue("0x40", 64))).to.be.false;
  });
});
