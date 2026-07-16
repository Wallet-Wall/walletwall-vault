import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import { ethers } from "./helpers/connection";

import {
  DEMO_WARNING,
  DEMO_WITHDRAWAL_DIGEST,
  FIXTURE_WITHDRAWAL_DIGEST,
  AttestationInput,
  createDemoMaterial,
  createFixtureMaterial,
  isFixtureMaterial,
  normalizeHex,
  parseAttestorArgs,
  readBytesInput,
  verifyAndSignAttestation,
  verifyMLDSA65,
} from "../scripts/lib/attestation";

describe("ML-DSA attestor helpers", function () {
  const fixturePath = resolve("test/fixtures/mldsa/library-generated/ml-dsa-65.json");
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
    message: string;
    publicKey: string;
    signature: string;
  };

  function fixtureBytes() {
    return {
      message: ethers.getBytes(fixture.message),
      publicKey: ethers.getBytes(fixture.publicKey),
      signature: ethers.getBytes(fixture.signature),
    };
  }

  it("verifies a valid ML-DSA-65 fixture", function () {
    const input = fixtureBytes();
    expect(verifyMLDSA65(input.publicKey, input.message, input.signature)).to.equal(true);
  });

  it("rejects an altered message", function () {
    const input = fixtureBytes();
    input.message[0] ^= 1;
    expect(verifyMLDSA65(input.publicKey, input.message, input.signature)).to.equal(false);
  });

  it("rejects an altered public key", function () {
    const input = fixtureBytes();
    input.publicKey[0] ^= 1;
    expect(verifyMLDSA65(input.publicKey, input.message, input.signature)).to.equal(false);
  });

  it("rejects an altered signature", function () {
    const input = fixtureBytes();
    input.signature[0] ^= 1;
    expect(verifyMLDSA65(input.publicKey, input.message, input.signature)).to.equal(false);
  });

  it("rejects missing and malformed CLI inputs", function () {
    expect(() => parseAttestorArgs(["verify", "--public-key"])).to.throw("Malformed argument");
    expect(() => readBytesInput(undefined, undefined, "public-key")).to.throw(
      "Provide exactly one of --public-key or --public-key-file",
    );
    expect(() => normalizeHex("not-hex", "public-key")).to.throw("0x-prefixed");
  });

  it("labels demo mode clearly", function () {
    expect(DEMO_WARNING).to.equal("DEMO ONLY — do not use generated/demo PQ material for real funds.");
  });

  it("refuses demo material in real mode", async function () {
    const [attestor] = await ethers.getSigners();
    const demo = createDemoMaterial();
    const verifierAddress = ethers.Wallet.createRandom().address;
    const input: AttestationInput = {
      withdrawalDigest: DEMO_WITHDRAWAL_DIGEST,
      publicKey: demo.publicKey,
      pqSignature: demo.signature,
      signedMessage: demo.message,
      verifierAddress,
      chainId: 31337n,
      deadline: 4_102_444_800n,
    };

    await expect(verifyAndSignAttestation(input, attestor)).to.be.rejectedWith(
      "Real verify mode refuses generated demo PQ material",
    );
  });

  it("refuses generated fixture material in real mode", async function () {
    const [attestor] = await ethers.getSigners();
    const fixture = createFixtureMaterial();
    const verifierAddress = ethers.Wallet.createRandom().address;
    const input: AttestationInput = {
      withdrawalDigest: FIXTURE_WITHDRAWAL_DIGEST,
      publicKey: fixture.publicKey,
      pqSignature: fixture.signature,
      signedMessage: fixture.message,
      verifierAddress,
      chainId: 31337n,
      deadline: 4_102_444_800n,
    };

    expect(isFixtureMaterial(fixture.publicKey, fixture.signature)).to.equal(true);
    await expect(verifyAndSignAttestation(input, attestor)).to.be.rejectedWith(
      "Real verify mode refuses generated fixture PQ material",
    );
  });

  it("signs verified material and produces an on-chain compatible payload", async function () {
    const [owner, attestor] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("AttestationPQCVerifier", owner);
    const verifier = await factory.deploy(attestor.address);
    await verifier.waitForDeployment();

    const material = fixtureBytes();
    const input: AttestationInput = {
      withdrawalDigest: fixture.message,
      publicKey: material.publicKey,
      pqSignature: material.signature,
      signedMessage: material.message,
      verifierAddress: await verifier.getAddress(),
      chainId: (await ethers.provider.getNetwork()).chainId,
      deadline: 4_102_444_800n,
    };
    // allowGeneratedMaterial=true: this test exercises payload construction
    // and on-chain compatibility with fixture material, not real-mode signing.
    const result = await verifyAndSignAttestation(input, attestor, true);
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes", "uint256", "bytes32", "bytes32"],
      result.verifierPayload,
    );

    expect(decoded[0]).to.equal(result.attestationSignature);
    expect(decoded[1]).to.equal(input.deadline);
    expect(decoded[2]).to.equal(result.publicKeyHash);
    expect(decoded[3]).to.equal(result.pqSignatureHash);
    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, result.verifierPayload)).to.equal(true);
  });
});
