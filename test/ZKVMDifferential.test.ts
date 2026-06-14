import { expect } from "chai";
import { MLDSASigner } from "../pqc/ml-dsa";

describe("ML-DSA fixture precheck", function () {
  it("verifies generated material with the TypeScript implementation", async function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    const digest = Buffer.alloc(32, 1); // 0x01...01
    const signature = MLDSASigner.sign(digest, privateKey);

    // Verify using TS implementation
    const isValidTS = MLDSASigner.verify(publicKey, digest, signature);
    expect(isValidTS).to.be.true;

    // This is not a differential zkVM test. Real differential coverage must compile
    // and execute the pinned Rust guest against the same vectors.
  });
});
