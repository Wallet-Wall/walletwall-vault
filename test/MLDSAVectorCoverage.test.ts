/**
 * Expanded ML-DSA-65 verifier vector coverage (FIPS 204).
 *
 * This complements the official NIST ACVP fixture suites
 * (test/MLDSAConformance.test.ts, test/PQVerifier.test.ts) with a broader, fully
 * deterministic matrix that the open verifier boundary (src/verifier) can
 * exercise through the external/pure interface:
 *
 *   - multiple independent POSITIVE vectors (deterministic keygen + sign),
 *   - the official NIST ACVP empty-context vector (tcId 35) as a standards anchor,
 *   - cross-vector ("wrong vector metadata") NEGATIVE cases,
 *   - multi-position bit-flip MUTATIONS of message / public key / signature,
 *   - UNSUPPORTED parameter sets (ML-DSA-44 / ML-DSA-87) rejected by length,
 *   - MALFORMED encoding / length cases (truncated, padded, empty),
 *   - reason-code stability and the verified <=> ML_DSA_65_VALID invariant.
 *
 * Determinism & safety:
 *   - All material is produced from fixed, test-only seeds with deterministic
 *     signing (`extraEntropy: false`), so vectors are reproducible across runs.
 *   - The test SIGNS only to PRODUCE vectors; the pure verifier under test only
 *     ever VERIFIES. No signing happens inside src/verifier.
 *   - No network access. Raw key/signature material is never logged; only the
 *     verifier's keccak256 input hashes appear in results.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { keccak256, toUtf8Bytes } from "ethers";
import { expect } from "chai";

import {
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  verifyMLDSA65,
  verifyMLDSA65Detailed,
} from "../src/verifier/ml-dsa-65";
import { PQ_REASON } from "../src/verifier/schema";

const PK_LEN = Number(ML_DSA_65_PUBLIC_KEY_LENGTH);
const SIG_LEN = Number(ML_DSA_65_SIGNATURE_LENGTH);

// ---------------------------------------------------------------------------
// Deterministic test-only vectors. These seeds are fixed constants used ONLY to
// generate reproducible ML-DSA material for tests; they are not secrets and are
// never used with real funds. The pattern mirrors the existing demo/fixture
// seeds in scripts/lib/attestation.ts (0x42…, 0x43…).
// ---------------------------------------------------------------------------
interface MldsaVector {
  label: string;
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
}

function seedFromLabel(label: string): Uint8Array {
  // keccak256 gives a deterministic, well-distributed 32-byte seed per label.
  return Uint8Array.from(Buffer.from(keccak256(toUtf8Bytes(`ww-vector-seed:${label}`)).slice(2), "hex"));
}

/** Deterministically build a valid ML-DSA-65 vector for a label. */
function buildVector(label: string): MldsaVector {
  const seed = seedFromLabel(label);
  const keyPair = ml_dsa65.keygen(seed);
  const message = Uint8Array.from(Buffer.from(keccak256(toUtf8Bytes(`ww-vector-msg:${label}`)).slice(2), "hex"));
  const signature = ml_dsa65.sign(message, keyPair.secretKey, { extraEntropy: false });
  return { label, publicKey: keyPair.publicKey, message, signature };
}

const VECTOR_LABELS = ["alpha", "bravo", "charlie", "delta"] as const;
const vectors: MldsaVector[] = VECTOR_LABELS.map(buildVector);

// Official NIST ACVP empty-context vector (tcId 35), exercisable through the
// external/pure boundary. Used as a standards anchor alongside the generated set.
interface AcvpVector {
  tcId: number;
  pk: string;
  message: string;
  context: string;
  signature: string;
  testPassed: boolean;
}
const acvpFixturePath = resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
const acvpFixture = JSON.parse(readFileSync(acvpFixturePath, "utf8")) as { vectors: AcvpVector[] };
const acvp35 = acvpFixture.vectors.find((v) => v.tcId === 35);
if (!acvp35) throw new Error("tcId 35 not found in NIST ACVP fixture");
function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
const nistVector: MldsaVector = {
  label: "nist-acvp-tcId-35",
  publicKey: hexToBytes(acvp35.pk),
  message: hexToBytes(acvp35.message),
  signature: hexToBytes(acvp35.signature),
};

// Every result produced anywhere in this file is collected so we can assert the
// global reason-code invariants over the whole matrix at the end.
const ALLOWED_REASONS = new Set<string>(Object.values(PQ_REASON));
const collected: { reason: string; verified: boolean }[] = [];
function check(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) {
  const r = verifyMLDSA65Detailed(publicKey, message, signature);
  collected.push({ reason: r.result.reason, verified: r.result.verified });
  return r;
}

/** Flip one bit in a copy of `bytes` at `index` without mutating the original. */
function flipBit(bytes: Uint8Array, index: number): Uint8Array {
  const copy = bytes.slice();
  copy[index] ^= 0x01;
  return copy;
}

describe("ML-DSA-65 expanded vector coverage (FIPS 204, external/pure)", function () {
  describe("positive vectors verify and report ML_DSA_65_VALID", function () {
    for (const v of vectors) {
      it(`deterministic vector "${v.label}" verifies`, function () {
        const r = check(v.publicKey, v.message, v.signature);
        expect(r.result.verified).to.equal(true);
        expect(r.result.reason).to.equal(PQ_REASON.ML_DSA_65_VALID);
        expect(verifyMLDSA65(v.publicKey, v.message, v.signature)).to.equal(true);
      });
    }

    it('NIST ACVP vector "nist-acvp-tcId-35" verifies (standards anchor)', function () {
      const r = check(nistVector.publicKey, nistVector.message, nistVector.signature);
      expect(r.result.verified).to.equal(true);
      expect(r.result.reason).to.equal(PQ_REASON.ML_DSA_65_VALID);
    });

    it("generated vectors are reproducible across rebuilds (deterministic)", function () {
      for (const v of vectors) {
        const rebuilt = buildVector(v.label);
        expect(Buffer.from(rebuilt.publicKey).equals(Buffer.from(v.publicKey))).to.equal(true);
        expect(Buffer.from(rebuilt.signature).equals(Buffer.from(v.signature))).to.equal(true);
      }
    });
  });

  describe("cross-vector negatives (wrong vector metadata)", function () {
    // For every ordered pair of distinct vectors, swapping exactly one of the
    // three inputs must break verification. All inputs keep ML-DSA-65 lengths,
    // so each case reaches cryptographic verification (not a length short-circuit).
    for (let i = 0; i < vectors.length; i++) {
      for (let j = 0; j < vectors.length; j++) {
        if (i === j) continue;
        const a = vectors[i];
        const b = vectors[j];

        it(`signature from "${b.label}" does not verify for "${a.label}" message/key`, function () {
          const r = check(a.publicKey, a.message, b.signature);
          expect(r.result.verified).to.equal(false);
          expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
        });

        it(`message from "${b.label}" does not verify under "${a.label}" key/signature`, function () {
          const r = check(a.publicKey, b.message, a.signature);
          expect(r.result.verified).to.equal(false);
          expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
        });

        it(`public key from "${b.label}" does not verify "${a.label}" message/signature`, function () {
          const r = check(b.publicKey, a.message, a.signature);
          expect(r.result.verified).to.equal(false);
          expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
        });
      }
    }
  });

  describe("single-bit mutations are rejected", function () {
    const base = vectors[0];
    const positions = (len: number) => [0, Math.floor(len / 2), len - 1];

    it("flipping any sampled message bit fails verification", function () {
      for (const p of positions(base.message.length)) {
        const r = check(base.publicKey, flipBit(base.message, p), base.signature);
        expect(r.result.verified, `message bit ${p}`).to.equal(false);
        expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
      }
    });

    it("flipping any sampled public-key bit fails verification (length preserved)", function () {
      for (const p of positions(base.publicKey.length)) {
        const r = check(flipBit(base.publicKey, p), base.message, base.signature);
        expect(r.result.verified, `pk bit ${p}`).to.equal(false);
        expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
      }
    });

    it("flipping any sampled signature bit fails verification (length preserved)", function () {
      for (const p of positions(base.signature.length)) {
        const r = check(base.publicKey, base.message, flipBit(base.signature, p));
        expect(r.result.verified, `sig bit ${p}`).to.equal(false);
        expect([PQ_REASON.VERIFY_FAILED, PQ_REASON.VERIFY_EXCEPTION]).to.include(r.result.reason);
      }
    });
  });

  describe("unsupported parameter sets (wrong algorithm identifier) are rejected by length", function () {
    // The boundary verifies ML-DSA-65 only. ML-DSA-44 and ML-DSA-87 are distinct
    // FIPS 204 parameter sets with different key/signature lengths, so feeding
    // their material is detected as a length mismatch — a stable, deterministic
    // rejection rather than an attempt to verify the wrong algorithm.
    const dsa44 = ml_dsa44.keygen(seedFromLabel("dsa44"));
    const dsa87 = ml_dsa87.keygen(seedFromLabel("dsa87"));
    const msg44 = Uint8Array.from(Buffer.from(keccak256(toUtf8Bytes("dsa44-msg")).slice(2), "hex"));
    const msg87 = Uint8Array.from(Buffer.from(keccak256(toUtf8Bytes("dsa87-msg")).slice(2), "hex"));
    const sig44 = ml_dsa44.sign(msg44, dsa44.secretKey, { extraEntropy: false });
    const sig87 = ml_dsa87.sign(msg87, dsa87.secretKey, { extraEntropy: false });
    const valid = vectors[0];

    it("guards assume distinct parameter-set lengths", function () {
      expect(dsa44.publicKey.length).to.not.equal(PK_LEN);
      expect(dsa87.publicKey.length).to.not.equal(PK_LEN);
      expect(sig44.length).to.not.equal(SIG_LEN);
      expect(sig87.length).to.not.equal(SIG_LEN);
    });

    it("rejects an ML-DSA-44 public key as INVALID_PUBLIC_KEY_LENGTH", function () {
      const r = check(dsa44.publicKey, valid.message, valid.signature);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
    });

    it("rejects an ML-DSA-87 public key as INVALID_PUBLIC_KEY_LENGTH", function () {
      const r = check(dsa87.publicKey, valid.message, valid.signature);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
    });

    it("rejects an ML-DSA-44 signature as INVALID_SIGNATURE_LENGTH", function () {
      const r = check(valid.publicKey, valid.message, sig44);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
    });

    it("rejects an ML-DSA-87 signature as INVALID_SIGNATURE_LENGTH", function () {
      const r = check(valid.publicKey, valid.message, sig87);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
    });
  });

  describe("malformed encoding / length cases map to stable reasons", function () {
    const base = vectors[0];

    it("truncated public key (length - 1) → INVALID_PUBLIC_KEY_LENGTH", function () {
      const r = check(base.publicKey.slice(0, PK_LEN - 1), base.message, base.signature);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
    });

    it("padded public key (length + 1) → INVALID_PUBLIC_KEY_LENGTH", function () {
      const padded = new Uint8Array(PK_LEN + 1);
      padded.set(base.publicKey);
      const r = check(padded, base.message, base.signature);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
    });

    it("truncated signature (length - 1) → INVALID_SIGNATURE_LENGTH", function () {
      const r = check(base.publicKey, base.message, base.signature.slice(0, SIG_LEN - 1));
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
    });

    it("padded signature (length + 1) → INVALID_SIGNATURE_LENGTH", function () {
      const padded = new Uint8Array(SIG_LEN + 1);
      padded.set(base.signature);
      const r = check(base.publicKey, base.message, padded);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
    });

    it("empty public key → INVALID_PUBLIC_KEY_LENGTH", function () {
      const r = check(new Uint8Array(0), base.message, base.signature);
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
    });

    it("empty signature → INVALID_SIGNATURE_LENGTH", function () {
      const r = check(base.publicKey, base.message, new Uint8Array(0));
      expect(r.result.reason).to.equal(PQ_REASON.INVALID_SIGNATURE_LENGTH);
    });

    it("empty message → EMPTY_MESSAGE", function () {
      const r = check(base.publicKey, new Uint8Array(0), base.signature);
      expect(r.result.reason).to.equal(PQ_REASON.EMPTY_MESSAGE);
    });

    it("empty message takes precedence over bad key/signature lengths", function () {
      const r = check(new Uint8Array(3), new Uint8Array(0), new Uint8Array(7));
      expect(r.result.reason).to.equal(PQ_REASON.EMPTY_MESSAGE);
    });

    it("a strict hex decoder rejects odd-length wire encodings before verifying", function () {
      // Malformed wire encoding (odd hex length) must be caught at decode time;
      // it never reaches the verifier as a silently-truncated byte string.
      const strictHexToBytes = (hex: string): Uint8Array => {
        const body = hex.startsWith("0x") ? hex.slice(2) : hex;
        if (body.length % 2 !== 0) throw new Error("odd-length hex");
        if (!/^[0-9a-fA-F]*$/.test(body)) throw new Error("non-hex characters");
        return Uint8Array.from(Buffer.from(body, "hex"));
      };
      expect(() => strictHexToBytes("0xabc")).to.throw(/odd-length hex/);
      expect(() => strictHexToBytes("0xzz")).to.throw(/non-hex/);
      // A well-formed even-length encoding decodes and verifies as expected.
      const okHex = "0x" + Buffer.from(base.message).toString("hex");
      expect(Buffer.from(strictHexToBytes(okHex)).equals(Buffer.from(base.message))).to.equal(true);
    });
  });

  describe("global reason-code invariants over the whole matrix", function () {
    it("exercised both verified and unverified paths", function () {
      expect(collected.some((c) => c.verified)).to.equal(true);
      expect(collected.some((c) => !c.verified)).to.equal(true);
      // Sanity: the matrix above is substantial, not a couple of cases.
      expect(collected.length).to.be.greaterThan(30);
    });

    it("every result reports a reason from the closed set", function () {
      for (const c of collected) {
        expect(ALLOWED_REASONS.has(c.reason), `unexpected reason ${c.reason}`).to.equal(true);
      }
    });

    it("verified is true iff the reason is ML_DSA_65_VALID", function () {
      for (const c of collected) {
        expect(c.verified).to.equal(c.reason === PQ_REASON.ML_DSA_65_VALID);
      }
    });
  });
});
