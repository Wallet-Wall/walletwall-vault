/**
 * Unit tests for the open PQ verifier module (src/verifier).
 *
 * These exercise the pure ML-DSA-65 boundary directly: deterministic structured
 * results, reason codes, and the guarantee that raw key/signature material never
 * appears in the result. The valid case uses the official NIST ACVP empty-context
 * vector (tcId 35) so the "valid" path is anchored to FIPS 204 conformance.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  verifyMLDSA65,
  verifyMLDSA65Detailed,
} from "../src/verifier/ml-dsa-65";
import { PQ_REASON, PQ_VERIFIER_SCHEMA_VERSION } from "../src/verifier/schema";

interface AcvpVector {
  tcId: number;
  pk: string;
  message: string;
  context: string;
  signature: string;
  testPassed: boolean;
}

const fixturePath = resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as { vectors: AcvpVector[] };

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

// tcId 35: valid ML-DSA-65 vector with an EMPTY context, directly exercisable
// through verifyMLDSA65 (which uses the external/pure interface, no context).
const vec35 = fixture.vectors.find((v) => v.tcId === 35);
if (!vec35) throw new Error("tcId 35 not found in NIST fixture");

function validInputs() {
  return {
    publicKey: hexToBytes(vec35!.pk),
    message: hexToBytes(vec35!.message),
    signature: hexToBytes(vec35!.signature),
  };
}

describe("Open PQ verifier module (ML-DSA-65 / FIPS 204)", function () {
  it("verifies a valid NIST ACVP empty-context vector", function () {
    const { publicKey, message, signature } = validInputs();
    const result = verifyMLDSA65Detailed(publicKey, message, signature);

    expect(result.result.verified).to.equal(true);
    expect(result.result.reason).to.equal(PQ_REASON.ML_DSA_65_VALID);
    expect(result.schemaVersion).to.equal(PQ_VERIFIER_SCHEMA_VERSION);
    expect(result.algorithm).to.equal("ML-DSA-65");
    expect(result.fips).to.equal("FIPS-204");
    expect(result.mode).to.equal("pure");
  });

  it("boolean wrapper agrees with the detailed result", function () {
    const { publicKey, message, signature } = validInputs();
    expect(verifyMLDSA65(publicKey, message, signature)).to.equal(true);
  });

  it("fails on an altered message", function () {
    const { publicKey, message, signature } = validInputs();
    message[0] ^= 0x01;
    const result = verifyMLDSA65Detailed(publicKey, message, signature);

    expect(result.result.verified).to.equal(false);
    expect(result.result.reason).to.equal(PQ_REASON.VERIFY_FAILED);
  });

  it("fails on an altered public key", function () {
    const { publicKey, message, signature } = validInputs();
    publicKey[0] ^= 0x01;
    const result = verifyMLDSA65Detailed(publicKey, message, signature);

    expect(result.result.verified).to.equal(false);
    // Length is unchanged, so this reaches cryptographic verification.
    expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(result.result.reason);
  });

  it("fails on an altered signature", function () {
    const { publicKey, message, signature } = validInputs();
    signature[0] ^= 0x01;
    const result = verifyMLDSA65Detailed(publicKey, message, signature);

    expect(result.result.verified).to.equal(false);
    expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(result.result.reason);
  });

  it("rejects a malformed public key length with the expected reason", function () {
    const { message, signature } = validInputs();
    const shortKey = new Uint8Array(10);
    const result = verifyMLDSA65Detailed(shortKey, message, signature);

    expect(result.result.verified).to.equal(false);
    expect(result.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
  });

  it("rejects a malformed signature length with the expected reason", function () {
    const { publicKey, message } = validInputs();
    const shortSig = new Uint8Array(10);
    const result = verifyMLDSA65Detailed(publicKey, message, shortSig);

    expect(result.result.verified).to.equal(false);
    expect(result.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
  });

  it("rejects an empty message with the expected reason", function () {
    const { publicKey, signature } = validInputs();
    const result = verifyMLDSA65Detailed(publicKey, new Uint8Array(0), signature);

    expect(result.result.verified).to.equal(false);
    expect(result.result.reason).to.equal(PQ_REASON.EMPTY_MESSAGE);
  });

  it("exposes the canonical ML-DSA-65 lengths", function () {
    expect(ML_DSA_65_PUBLIC_KEY_LENGTH).to.equal(1952);
    expect(ML_DSA_65_SIGNATURE_LENGTH).to.equal(3309);
  });

  it("produces a deterministic result for the same inputs", function () {
    const a = verifyMLDSA65Detailed(validInputs().publicKey, validInputs().message, validInputs().signature);
    const b = verifyMLDSA65Detailed(validInputs().publicKey, validInputs().message, validInputs().signature);
    expect(JSON.stringify(a)).to.equal(JSON.stringify(b));
  });

  it("never includes raw public key, signature, or message material in the result", function () {
    const { publicKey, message, signature } = validInputs();
    const result = verifyMLDSA65Detailed(publicKey, message, signature);
    const json = JSON.stringify(result);

    const pkHex = Buffer.from(publicKey).toString("hex");
    const sigHex = Buffer.from(signature).toString("hex");
    const msgHex = Buffer.from(message).toString("hex");

    expect(json).to.not.include(pkHex);
    expect(json).to.not.include(sigHex);
    if (msgHex.length > 0) expect(json).to.not.include(msgHex);
    // Hashes (not raw bytes) are present.
    expect(result.input.publicKeyHash).to.match(/^0x[0-9a-f]{64}$/);
    expect(result.input.signatureHash).to.match(/^0x[0-9a-f]{64}$/);
    expect(result.input.messageHash).to.match(/^0x[0-9a-f]{64}$/);
  });

  it("emits exactly the documented closed set of reason codes", function () {
    // This pins the failure-reason surface: if a new reason is added or one is
    // renamed without updating the schema/docs, this guard fails.
    const reasons = Object.values(PQ_REASON).sort();
    expect(reasons).to.deep.equal(
      [
        "EMPTY_MESSAGE",
        "INVALID_PUBLIC_KEY_LENGTH",
        "INVALID_SIGNATURE_LENGTH",
        "ML_DSA_65_VALID",
        "VERIFY_EXCEPTION",
        "VERIFY_FAILED",
      ].sort(),
    );
    // The key and value are identical for every reason (stable wire strings).
    for (const [key, value] of Object.entries(PQ_REASON)) {
      expect(key).to.equal(value);
    }
  });

  it("only ever reports a reason from the closed set, for arbitrary inputs", function () {
    const allowed = new Set<string>(Object.values(PQ_REASON));
    const lengths = [0, 1, 10, Number(ML_DSA_65_PUBLIC_KEY_LENGTH), Number(ML_DSA_65_SIGNATURE_LENGTH)];
    let seed = 1;
    const fill = (n: number) => {
      const a = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        // Deterministic pseudo-random so the test is reproducible.
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        a[i] = seed & 0xff;
      }
      return a;
    };

    for (const pkLen of lengths) {
      for (const sigLen of lengths) {
        for (const msgLen of [0, 5, 32]) {
          const result = verifyMLDSA65Detailed(fill(pkLen), fill(msgLen), fill(sigLen));
          expect(result.result.verified).to.equal(false);
          expect(allowed.has(result.result.reason), `unexpected reason ${result.result.reason}`).to.equal(true);
        }
      }
    }
  });

  it("reports stable length-failure reasons regardless of message content", function () {
    const goodMsg = validInputs().message;
    const shortKey = new Uint8Array(Number(ML_DSA_65_PUBLIC_KEY_LENGTH) - 1);
    const goodSig = validInputs().signature;
    expect(verifyMLDSA65Detailed(shortKey, goodMsg, goodSig).result.reason).to.equal(
      PQ_REASON.INVALID_PUBLIC_KEY_LENGTH,
    );

    const goodKey = validInputs().publicKey;
    const longSig = new Uint8Array(Number(ML_DSA_65_SIGNATURE_LENGTH) + 1);
    expect(verifyMLDSA65Detailed(goodKey, goodMsg, longSig).result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
  });
});
