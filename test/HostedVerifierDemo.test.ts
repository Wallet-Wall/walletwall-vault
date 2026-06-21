/**
 * Tests for the hosted PQ verifier DEMO/SPIKE handler
 * (scripts/lib/hosted-verifier-demo.ts).
 *
 * The handler is a pure, transport-agnostic request→response function. These
 * tests pin:
 *   - the happy path (valid + tampered → 200 with hashes-only evidence),
 *   - the malformed/oversized request paths (400 / 413),
 *   - determinism given an injected clock,
 *   - that no raw key/signature material ever appears in a response,
 *   - and — as a static guard — that the demo source never signs, never reads an
 *     attestor key or env, and never writes to a contract.
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { getBytes, hexlify } from "ethers";
import { expect } from "chai";

import { HOSTED_LIMITS, HOSTED_STATUS, handleHostedVerifyRequest } from "../scripts/lib/hosted-verifier-demo";
import { validateEvidence } from "../src/verifier/evidence";
import { PQ_REASON } from "../src/verifier/schema";

const FIXTURE_DIR = resolve("test/fixtures/mldsa/library-generated");
const readHex = (name: string): string => readFileSync(join(FIXTURE_DIR, name), "utf8").trim();

const message = readHex("message.hex");
const publicKey = readHex("public-key.hex");
const signature = readHex("signature.hex");
const NOW = "2026-01-01T00:00:00.000Z";

function validRequest() {
  return { message, publicKey, signature };
}

describe("Hosted PQ verifier demo handler (spike)", function () {
  it("returns 200 with valid, hashes-only evidence for a valid request", function () {
    const res = handleHostedVerifyRequest(validRequest(), { now: NOW });
    expect(res.status).to.equal(HOSTED_STATUS.OK);
    expect(res.ok).to.equal(true);
    expect(res.mode).to.equal("spike-non-production");
    expect(res.evidence).to.not.equal(undefined);
    expect(validateEvidence(res.evidence).valid).to.equal(true);
    expect(res.evidence!.verification.result.verified).to.equal(true);
    expect(res.evidence!.verification.result.reason).to.equal(PQ_REASON.ML_DSA_65_VALID);
  });

  it("treats a failed verification as a successful request (200, verified:false)", function () {
    const tampered = getBytes(signature);
    tampered[0] ^= 0x01;
    const res = handleHostedVerifyRequest({ message, publicKey, signature: hexlify(tampered) }, { now: NOW });
    expect(res.status).to.equal(HOSTED_STATUS.OK);
    expect(res.ok).to.equal(true);
    expect(res.evidence!.verification.result.verified).to.equal(false);
    expect(res.evidence!.verification.result.reason).to.equal(PQ_REASON.VERIFY_FAILED);
  });

  it("accepts an optional safe source reference", function () {
    const res = handleHostedVerifyRequest(
      { ...validRequest(), source: { type: "library-generated", reference: "library-generated/ml-dsa-65" } },
      { now: NOW },
    );
    expect(res.status).to.equal(HOSTED_STATUS.OK);
    expect(res.evidence!.source).to.deep.equal({ type: "library-generated", reference: "library-generated/ml-dsa-65" });
  });

  describe("malformed requests → 400", function () {
    it("a non-object request", function () {
      expect(handleHostedVerifyRequest(null).status).to.equal(HOSTED_STATUS.BAD_REQUEST);
      expect(handleHostedVerifyRequest("nope").status).to.equal(HOSTED_STATUS.BAD_REQUEST);
    });

    it("a missing field", function () {
      const res = handleHostedVerifyRequest({ message, publicKey });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
      expect(res.ok).to.equal(false);
    });

    it("an unexpected field", function () {
      const res = handleHostedVerifyRequest({ ...validRequest(), surprise: 1 });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
      expect(res.error!.message).to.match(/unexpected request field/);
    });

    it("a non-0x-prefixed value", function () {
      const res = handleHostedVerifyRequest({ ...validRequest(), message: "abcd" });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
    });

    it("odd-length hex", function () {
      const res = handleHostedVerifyRequest({ ...validRequest(), message: "0xabc" });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
      expect(res.error!.message).to.match(/even-length hex/);
    });

    it("non-hex characters", function () {
      const res = handleHostedVerifyRequest({ ...validRequest(), signature: "0xzzzz" });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
    });

    it("a bad source.type", function () {
      const res = handleHostedVerifyRequest({ ...validRequest(), source: { type: "from-the-web", reference: "x" } });
      expect(res.status).to.equal(HOSTED_STATUS.BAD_REQUEST);
    });
  });

  describe("oversized requests → 413", function () {
    it("an over-cap public key is rejected before verification", function () {
      const huge = "0x" + "ab".repeat(HOSTED_LIMITS.maxPublicKeyBytes + 1);
      const res = handleHostedVerifyRequest({ message, publicKey: huge, signature });
      expect(res.status).to.equal(HOSTED_STATUS.PAYLOAD_TOO_LARGE);
      expect(res.error!.code).to.equal("PAYLOAD_TOO_LARGE");
    });

    it("an over-cap signature is rejected before verification", function () {
      const huge = "0x" + "cd".repeat(HOSTED_LIMITS.maxSignatureBytes + 1);
      const res = handleHostedVerifyRequest({ message, publicKey, signature: huge });
      expect(res.status).to.equal(HOSTED_STATUS.PAYLOAD_TOO_LARGE);
    });
  });

  it("is deterministic for the same request and injected clock", function () {
    const a = handleHostedVerifyRequest(validRequest(), { now: NOW });
    const b = handleHostedVerifyRequest(validRequest(), { now: NOW });
    expect(JSON.stringify(a)).to.equal(JSON.stringify(b));
  });

  it("never returns raw key/signature/message material", function () {
    const res = handleHostedVerifyRequest(validRequest(), { now: NOW });
    const json = JSON.stringify(res);
    expect(json.toLowerCase()).to.not.include(publicKey.slice(2).toLowerCase());
    expect(json.toLowerCase()).to.not.include(signature.slice(2).toLowerCase());
    // No 0x hex run longer than a 32-byte hash anywhere in the response.
    expect(json).to.not.match(/0x[0-9a-fA-F]{65,}/);
  });

  it("static guard: the demo never signs, reads an attestor key/env, or writes a contract", function () {
    const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    for (const file of ["scripts/lib/hosted-verifier-demo.ts", "scripts/hosted-verifier-demo.ts"]) {
      const code = stripComments(readFileSync(resolve(file), "utf8"));
      expect(code, `${file} must not sign`).to.not.match(/\.sign\s*\(/);
      expect(code, `${file} must not EVM-sign`).to.not.match(/signMessage|signTypedData|_signTypedData/);
      expect(code, `${file} must not keygen`).to.not.match(/\bkeygen\s*\(/);
      expect(code, `${file} must not read process.env`).to.not.match(/process\.env/);
      expect(code, `${file} must not reference ATTESTOR_PRIVATE_KEY`).to.not.match(/ATTESTOR_PRIVATE_KEY/);
      expect(code, `${file} must not import hardhat`).to.not.match(/from\s+['"]hardhat['"]/);
      // No contract-write surface (signer/sendTransaction/contract method writes).
      expect(code, `${file} must not send transactions`).to.not.match(/sendTransaction|getSigner|new\s+Contract/);
    }
  });
});
