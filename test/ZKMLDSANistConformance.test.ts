import { expect } from "chai";
import { ethers } from "./helpers/connection";
import * as fs from "node:fs";
import * as path from "node:path";
import { deployMockZkVerifier, encodeMockProof } from "./helpers/zkVerifierHelpers";

describe("ZKMLDSAVerifier public-input binding with NIST fixtures", function () {
  let zkVerifier: any;
  before(async function () {
    ({ zkVerifier } = await deployMockZkVerifier());
  });

  const fixturePath = path.resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

  function fixtureVector(tcId: number) {
    const vector = fixture.vectors.find((candidate: { tcId: number }) => candidate.tcId === tcId);
    return {
      digest: ethers.keccak256(ethers.getBytes("0x" + vector.message)),
      publicKey: ethers.getBytes("0x" + vector.pk),
      signature: ethers.getBytes("0x" + vector.signature),
    };
  }

  it("encodes fixture-shaped inputs for the mock SP1 boundary", async function () {
    const { digest, publicKey, signature } = fixtureVector(35);

    const zkProofPayload = await encodeMockProof(zkVerifier, digest, publicKey, signature);

    // MockSP1Verifier does not execute the Rust guest or establish NIST conformance.
    const isValid = await zkVerifier.verify(digest, publicKey, zkProofPayload);
    expect(isValid).to.be.true;
  });

  it("should reject tampered NIST ACVP vectors through the ZK verifier", async function () {
    const { digest, publicKey, signature } = fixtureVector(35);

    // Tamper with PK in the public inputs of the proof
    const tamperedPk = new Uint8Array(publicKey);
    tamperedPk[0] ^= 0xff;

    const zkProofPayload = await encodeMockProof(zkVerifier, digest, tamperedPk, signature);

    // Should return false because committedPkHash != keccak256(realPublicKey)
    const isValid = await zkVerifier.verify(digest, publicKey, zkProofPayload);
    expect(isValid).to.be.false;
  });
});
