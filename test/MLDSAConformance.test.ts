/**
 * NIST ACVP conformance tests for ML-DSA-65 (FIPS 204).
 *
 * Vectors: usnistgov/ACVP-Server gen-val/json-files/ML-DSA-sigVer-FIPS204
 * vsId 42, group 3 (external interface, pure / no pre-hash).
 * 6-vector subset: 3 valid (testPassed: true) + 3 invalid (testPassed: false).
 *
 * These are official NIST ACVP vectors, not library-generated fixtures.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { expect } from "chai";

import { verifyMLDSA65 } from "../scripts/lib/attestation";

interface AcvpVector {
  tcId: number;
  pk: string;
  message: string;
  context: string;
  signature: string;
  testPassed: boolean;
}

interface AcvpFixture {
  source: string;
  official: boolean;
  algorithm: string;
  fips: string;
  signatureInterface: string;
  preHash: string;
  vectors: AcvpVector[];
}

const fixturePath = resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as AcvpFixture;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

describe("ML-DSA-65 NIST ACVP conformance (FIPS 204)", function () {
  before(function () {
    expect(fixture.official).to.equal(true, "fixture must be official NIST vectors");
    expect(fixture.algorithm).to.equal("ML-DSA-65");
    expect(fixture.signatureInterface).to.equal("external");
    expect(fixture.preHash).to.equal("pure");
  });

  describe("committed group-3 subset via ml_dsa65.verify (external, pure)", function () {
    for (const vec of fixture.vectors) {
      it(`tcId ${vec.tcId}: ${vec.testPassed ? "valid" : "invalid"} vector (context ${vec.context.length === 0 ? "empty" : `${vec.context.length / 2}B`})`, function () {
        const pk = hexToBytes(vec.pk);
        const msg = hexToBytes(vec.message);
        const sig = hexToBytes(vec.signature);
        const ctx = hexToBytes(vec.context);

        let result: boolean;
        try {
          result = ml_dsa65.verify(sig, msg, pk, { context: ctx });
        } catch {
          result = false;
        }
        expect(result).to.equal(vec.testPassed);
      });
    }
  });

  describe("verifyMLDSA65 wrapper with empty-context ACVP vector (tcId 35)", function () {
    const vec35 = fixture.vectors.find((v) => v.tcId === 35);

    before(function () {
      if (!vec35) throw new Error("tcId 35 not found in fixture");
      expect(vec35.testPassed).to.equal(true, "tcId 35 must be a valid vector");
      expect(vec35.context).to.equal("", "tcId 35 must have empty context");
    });

    it("valid NIST vector verifies through verifyMLDSA65", function () {
      const pk = hexToBytes(vec35!.pk);
      const msg = hexToBytes(vec35!.message);
      const sig = hexToBytes(vec35!.signature);
      expect(verifyMLDSA65(pk, msg, sig)).to.equal(true);
    });

    it("rejects altered message on NIST vector", function () {
      const pk = hexToBytes(vec35!.pk);
      const msg = hexToBytes(vec35!.message);
      const sig = hexToBytes(vec35!.signature);
      msg[0] ^= 0x01;
      expect(verifyMLDSA65(pk, msg, sig)).to.equal(false);
    });

    it("rejects altered public key on NIST vector", function () {
      const pk = hexToBytes(vec35!.pk);
      const msg = hexToBytes(vec35!.message);
      const sig = hexToBytes(vec35!.signature);
      pk[0] ^= 0x01;
      expect(verifyMLDSA65(pk, msg, sig)).to.equal(false);
    });

    it("rejects altered signature on NIST vector", function () {
      const pk = hexToBytes(vec35!.pk);
      const msg = hexToBytes(vec35!.message);
      const sig = hexToBytes(vec35!.signature);
      sig[0] ^= 0x01;
      expect(verifyMLDSA65(pk, msg, sig)).to.equal(false);
    });
  });
});
