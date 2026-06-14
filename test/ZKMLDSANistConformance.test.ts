import { expect } from "chai";
import { ethers } from "hardhat";
import { ProverClient } from "../scripts/prover-client";
import * as fs from "fs";
import * as path from "path";

describe("ZKMLDSAVerifier NIST ACVP Conformance", function () {
  let zkVerifier: any;
  let mockSp1Verifier: any;

  const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("MOCK_VKEY"));

  before(async function () {
    const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
    mockSp1Verifier = await MockSP1Verifier.deploy();
    const sp1VerifierAddress = await mockSp1Verifier.getAddress();

    const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
    zkVerifier = await ZKMLDSAVerifier.deploy(sp1VerifierAddress, PROGRAM_VKEY);
  });

  const fixturePath = path.resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

  it("should verify valid NIST ACVP vectors through the ZK verifier", async function () {
    const vec35 = fixture.vectors.find((v: any) => v.tcId === 35);

    const pk = ethers.getBytes("0x" + vec35.pk);
    const msg = ethers.getBytes("0x" + vec35.message);
    const sig = ethers.getBytes("0x" + vec35.signature);

    // NIST vector verification uses raw message.
    // In our ZK guest, we verify the signature over the withdrawal_digest.
    // So we treat msg as the digest.
    const digest = ethers.keccak256(msg);

    const zkProofPayload = await ProverClient.generateProof(
      digest,
      pk,
      sig,
      (await ethers.provider.getNetwork()).chainId,
      await zkVerifier.getAddress()
    );

    const isValid = await zkVerifier.verify(digest, pk, zkProofPayload);
    expect(isValid).to.be.true;
  });

  it("should reject tampered NIST ACVP vectors through the ZK verifier", async function () {
    const vec35 = fixture.vectors.find((v: any) => v.tcId === 35);
    const pk = ethers.getBytes("0x" + vec35.pk);
    const msg = ethers.getBytes("0x" + vec35.message);
    const sig = ethers.getBytes("0x" + vec35.signature);
    const digest = ethers.keccak256(msg);

    // Tamper with PK in the public inputs of the proof
    const tamperedPk = new Uint8Array(pk);
    tamperedPk[0] ^= 0xFF;

    const zkProofPayload = await ProverClient.generateProof(
      digest,
      tamperedPk,
      sig,
      (await ethers.provider.getNetwork()).chainId,
      await zkVerifier.getAddress()
    );

    // Should return false because committedPkHash != keccak256(realPublicKey)
    const isValid = await zkVerifier.verify(digest, pk, zkProofPayload);
    expect(isValid).to.be.false;
  });
});
