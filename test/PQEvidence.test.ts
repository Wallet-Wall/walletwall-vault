/**
 * Tests for the PQ verifier evidence artifact (src/verifier/evidence.ts), its
 * committed examples, and the JSON Schema contract.
 *
 * Coverage:
 *   - buildEvidence wraps a deterministic result and never embeds raw material,
 *   - validateEvidence accepts valid + failure artifacts and rejects malformed
 *     ones (bad schema id, timestamp, hash, reason, verified/reason mismatch,
 *     unknown keys, bad source, embedded raw material),
 *   - the committed example files match what the generator builds (no drift),
 *   - the shipped JSON Schema stays in sync with the code's constants.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  PQ_EVIDENCE_SCHEMA_VERSION,
  PQ_EVIDENCE_SOURCE_TYPES,
  buildEvidence,
  isPQVerificationEvidence,
  validateEvidence,
} from "../src/verifier/evidence";
import { PQ_REASON } from "../src/verifier/schema";
import { getPQAlgorithmRecord } from "../src/standards/pq-algorithm-registry";
import {
  EXAMPLE_GENERATED_AT,
  FAILURE_EXAMPLE_PATH,
  VALID_EXAMPLE_PATH,
  buildFailureExample,
  buildValidExample,
} from "../scripts/generate-evidence-fixture";

const schemaPath = resolve("docs/schemas/pq-verifier-evidence.v1.schema.json");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("PQ verifier evidence artifact", function () {
  describe("buildEvidence", function () {
    it("wraps a deterministic result with an envelope and ISO timestamp", function () {
      const verification = buildValidExample().verification;
      const evidence = buildEvidence(verification);
      expect(evidence.schema).to.equal(PQ_EVIDENCE_SCHEMA_VERSION);
      expect(evidence.verification).to.deep.equal(verification);
      // Default generatedAt is a fresh, valid ISO instant and validates clean.
      expect(evidence.generatedAt).to.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/);
      expect(validateEvidence(evidence).valid).to.equal(true);
    });

    it("accepts a fixed Date or string for generatedAt", function () {
      const v = buildValidExample().verification;
      expect(buildEvidence(v, { generatedAt: "2026-01-01T00:00:00.000Z" }).generatedAt).to.equal(
        "2026-01-01T00:00:00.000Z",
      );
      expect(buildEvidence(v, { generatedAt: new Date(0) }).generatedAt).to.equal("1970-01-01T00:00:00.000Z");
    });

    it("refuses a source.reference that embeds raw key/signature material", function () {
      const v = buildValidExample().verification;
      const rawBlob = "0x" + "ab".repeat(100); // 200 hex chars >> a 64-char hash
      expect(() => buildEvidence(v, { source: { type: "operator-supplied", reference: rawBlob } })).to.throw(
        /raw key\/signature material/i,
      );
    });

    it("auto-populates standards from the canonical ML-DSA-65 registry record", function () {
      const v = buildValidExample().verification;
      const evidence = buildEvidence(v);
      const record = getPQAlgorithmRecord("ML-DSA");
      expect(evidence.standards).to.deep.equal({
        algorithm: "ML-DSA",
        parameterSet: "ML-DSA-65",
        standard: "FIPS 204",
        implementation: { ...record.implementation },
        verificationMode: "off-chain",
        conformanceStatus: record.conformanceStatus,
        certificationStatus: "not-validated",
        productionStatus: record.productionStatus,
      });
      expect(validateEvidence(evidence).valid).to.equal(true);
    });

    it("omits standards entirely when opts.standards is explicitly null (legacy-shape simulation)", function () {
      const v = buildValidExample().verification;
      const evidence = buildEvidence(v, { standards: null });
      expect(evidence.standards).to.equal(undefined);
      expect(validateEvidence(evidence).valid).to.equal(true);
    });
  });

  describe("validateEvidence — accepts", function () {
    it("the valid (verified true) example", function () {
      const res = validateEvidence(buildValidExample());
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("the failure (verified false) example", function () {
      const res = validateEvidence(buildFailureExample());
      expect(res.valid).to.equal(true);
      expect(buildFailureExample().verification.result.reason).to.equal(PQ_REASON.VERIFY_FAILED);
    });

    it("exposes a type guard", function () {
      expect(isPQVerificationEvidence(buildValidExample())).to.equal(true);
      expect(isPQVerificationEvidence({})).to.equal(false);
    });
  });

  describe("validateEvidence — rejects", function () {
    function freshValid() {
      // A clean, mutable deep copy of a valid artifact.
      return JSON.parse(JSON.stringify(buildValidExample()));
    }

    it("a non-object", function () {
      expect(validateEvidence(null).valid).to.equal(false);
      expect(validateEvidence("nope").valid).to.equal(false);
    });

    it("a wrong envelope schema id", function () {
      const e = freshValid();
      e.schema = "walletwall.pq-verifier-evidence.v2";
      expect(validateEvidence(e).valid).to.equal(false);
    });

    it("a malformed generatedAt", function () {
      const e = freshValid();
      e.generatedAt = "yesterday";
      expect(validateEvidence(e).valid).to.equal(false);
    });

    it("an unknown top-level key", function () {
      const e = freshValid();
      e.extra = "surprise";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected top-level key/i);
    });

    it("an unknown key nested under verification", function () {
      const e = freshValid();
      e.verification.injected = "surprise";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/verification has unexpected key/i);
    });

    it("an unknown key nested under verification.verifier", function () {
      const e = freshValid();
      e.verification.verifier.injected = "surprise";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/verification\.verifier has unexpected key/i);
    });

    it("an unknown key nested under verification.result", function () {
      const e = freshValid();
      e.verification.result.injected = "surprise";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/verification\.result has unexpected key/i);
    });

    it("a malformed input hash", function () {
      const e = freshValid();
      e.verification.input.publicKeyHash = "0x1234";
      expect(validateEvidence(e).valid).to.equal(false);
    });

    it("an unknown reason code", function () {
      const e = freshValid();
      e.verification.result.reason = "TOTALLY_MADE_UP";
      expect(validateEvidence(e).valid).to.equal(false);
    });

    it("a verified/reason mismatch", function () {
      const e = freshValid(); // verified true + ML_DSA_65_VALID
      e.verification.result.verified = false; // now inconsistent
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/iff reason is ML_DSA_65_VALID/);
    });

    it("a bad source.type", function () {
      const e = freshValid();
      e.source.type = "from-the-internet";
      expect(validateEvidence(e).valid).to.equal(false);
    });

    it("embedded raw key/signature material anywhere", function () {
      const e = freshValid();
      // Sneak a raw blob into the (otherwise free-text) source reference.
      e.source.reference = "see 0x" + "cd".repeat(80);
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/raw key\/signature material/i);
    });

    it("an invalid standards.algorithm value", function () {
      const e = freshValid();
      e.standards.algorithm = "RSA-4096";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/standards\.algorithm must be one of/i);
    });

    it("an invalid standards.certificationStatus value (rejected, not silently downgraded)", function () {
      const e = freshValid();
      e.standards.certificationStatus = "definitely-validated-trust-me";
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/standards\.certificationStatus must be one of/i);
    });

    it("an unknown key nested under standards", function () {
      const e = freshValid();
      e.standards.certified = true;
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/standards has unexpected key/i);
    });

    it("a malformed standards.implementation shape", function () {
      const e = freshValid();
      e.standards.implementation = { package: "@noble/post-quantum" }; // missing provider/version
      const res = validateEvidence(e);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/standards\.implementation must have exactly/i);
    });
  });

  describe("standards field — backward compatibility", function () {
    it("legacy evidence with no standards field at all is still valid (absence != a claim)", function () {
      const e = JSON.parse(JSON.stringify(buildValidExample()));
      delete e.standards;
      const res = validateEvidence(e);
      expect(res.valid).to.equal(true);
      expect(e.standards).to.equal(undefined);
    });
  });

  describe("committed examples (no drift)", function () {
    it("valid example file equals the freshly generated artifact", function () {
      expect(readJson(VALID_EXAMPLE_PATH)).to.deep.equal(buildValidExample());
    });

    it("failure example file equals the freshly generated artifact", function () {
      expect(readJson(FAILURE_EXAMPLE_PATH)).to.deep.equal(buildFailureExample());
    });

    it("both example files validate and carry no raw material", function () {
      for (const path of [VALID_EXAMPLE_PATH, FAILURE_EXAMPLE_PATH]) {
        const raw = readFileSync(path, "utf8");
        expect(validateEvidence(JSON.parse(raw)).valid).to.equal(true);
        expect(raw).to.not.match(/0x[0-9a-fA-F]{65,}/);
      }
    });

    it("examples are deterministic and pinned to the fixed generatedAt", function () {
      expect(buildValidExample().generatedAt).to.equal(EXAMPLE_GENERATED_AT);
      // Building twice yields byte-identical artifacts (only generatedAt could
      // vary at runtime, and it is fixed for the examples).
      expect(JSON.stringify(buildValidExample())).to.equal(JSON.stringify(buildValidExample()));
      expect(JSON.stringify(buildFailureExample())).to.equal(JSON.stringify(buildFailureExample()));
    });
  });

  describe("JSON Schema stays in sync with the code", function () {
    const schema = readJson(schemaPath) as Record<string, any>;

    it("envelope schema const matches PQ_EVIDENCE_SCHEMA_VERSION", function () {
      expect(schema.properties.schema.const).to.equal(PQ_EVIDENCE_SCHEMA_VERSION);
    });

    it("reason enum matches the verifier's closed reason set", function () {
      const schemaReasons = schema.properties.verification.properties.result.properties.reason.enum.slice().sort();
      expect(schemaReasons).to.deep.equal(Object.values(PQ_REASON).slice().sort());
    });

    it("source.type enum matches PQ_EVIDENCE_SOURCE_TYPES", function () {
      const schemaTypes = schema.properties.source.properties.type.enum.slice().sort();
      expect(schemaTypes).to.deep.equal([...PQ_EVIDENCE_SOURCE_TYPES].sort());
    });

    it("standards is declared optional (not in the top-level required list)", function () {
      expect(schema.required).to.not.include("standards");
      expect(schema.properties).to.have.property("standards");
    });

    it("standards.certificationStatus enum never asserts a bare 'validated' const default", function () {
      const certStatus = schema.properties.standards.properties.certificationStatus;
      expect(certStatus.enum).to.include("not-validated");
      expect(certStatus.const).to.equal(undefined); // must stay an open enum, not pinned true/validated
    });
  });
});
