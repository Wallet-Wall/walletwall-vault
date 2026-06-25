/**
 * Tests for the ML-DSA evidence artifact manifest: the builder/validator
 * (scripts/lib/ml-dsa-evidence-manifest.ts), the committed manifest at
 * evidence/ml-dsa/manifest.json, its on-disk source cross-checks, and the JSON
 * Schema contract.
 *
 * Coverage:
 *   - buildManifest assembles a valid envelope around derived entries,
 *   - validateManifest accepts the committed manifest and rejects malformed ones
 *     (bad schema/timestamp/hash/reason, accepted↔reason mismatch, under-marked
 *     boundary, missing limitation topic, unknown keys, overclaim language,
 *     embedded raw material, path traversal),
 *   - the committed manifest matches the generator (no drift) and its recorded
 *     hashes match the artifacts it indexes,
 *   - the shipped JSON Schema stays in sync with the code's constants.
 *
 * Pure, fast, static reads — no network, no contracts, no proving.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { keccak256, toUtf8Bytes } from "ethers";
import { expect } from "chai";

import {
  ML_DSA_BOUNDARY,
  ML_DSA_EVIDENCE_KINDS,
  ML_DSA_EVIDENCE_MANIFEST_SCHEMA,
  ML_DSA_EVIDENCE_SOURCE_TYPES,
  buildManifest,
  isMLDSAEvidenceManifest,
  validateManifest,
  type MLDSAEvidenceManifest,
} from "../scripts/lib/ml-dsa-evidence-manifest";
import { PQ_REASON } from "../src/verifier/schema";
import { MANIFEST_PATH, buildExampleManifest } from "../scripts/generate-mldsa-evidence-manifest";

const schemaPath = resolve("evidence/ml-dsa/schema/ml-dsa-evidence-manifest.v1.schema.json");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** A clean, mutable deep copy of the committed manifest. */
function freshValid(): MLDSAEvidenceManifest {
  return JSON.parse(JSON.stringify(buildExampleManifest()));
}

describe("ML-DSA evidence manifest", function () {
  describe("buildManifest / validateManifest — accepts", function () {
    it("the freshly built example manifest validates clean", function () {
      const res = validateManifest(buildExampleManifest());
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("exposes a type guard", function () {
      expect(isMLDSAEvidenceManifest(buildExampleManifest())).to.equal(true);
      expect(isMLDSAEvidenceManifest({})).to.equal(false);
    });

    it("does not flag honest negations in the limitations array", function () {
      // limitations legitimately say "no production custody" / "no mainnet …";
      // the overclaim guard must not false-flag those negations.
      const blob = buildExampleManifest().limitations.join(" ").toLowerCase();
      expect(blob).to.include("no mainnet");
      expect(blob).to.include("no production custody");
      expect(validateManifest(buildExampleManifest()).valid).to.equal(true);
    });

    it("indexes at least the two pq-verifier-evidence examples plus the library fixture", function () {
      const m = buildExampleManifest();
      const kinds = m.evidence.map((e) => e.kind);
      expect(kinds).to.include("pq-verifier-evidence");
      expect(kinds).to.include("test-vector");
      expect(m.evidence.length).to.be.greaterThanOrEqual(3);
    });
  });

  describe("validateManifest — rejects", function () {
    it("a non-object", function () {
      expect(validateManifest(null).valid).to.equal(false);
      expect(validateManifest([]).valid).to.equal(false);
    });

    it("a wrong schema id", function () {
      const m = freshValid();
      m.schema = "walletwall.ml-dsa-evidence-manifest.v2" as never;
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("a malformed generatedAt", function () {
      const m = freshValid();
      m.generatedAt = "soon";
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("an unknown top-level key", function () {
      const m = freshValid() as unknown as Record<string, unknown>;
      m.surprise = 1;
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected key in manifest/);
    });

    it("an unknown key nested under an evidence entry", function () {
      const m = freshValid();
      (m.evidence[0] as unknown as Record<string, unknown>).injected = "x";
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected key in evidence\[0\]/);
    });

    it("an unknown key nested under a result", function () {
      const m = freshValid();
      (m.evidence[0].result as unknown as Record<string, unknown>).injected = "x";
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("a malformed input hash", function () {
      const m = freshValid();
      m.evidence[0].publicKeyHash = "0x1234";
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("an unknown reason code", function () {
      const m = freshValid();
      m.evidence[0].result.reason = "MADE_UP" as never;
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("an accepted/reason mismatch", function () {
      const m = freshValid(); // accepted true + ML_DSA_65_VALID
      m.evidence[0].result.accepted = false;
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/iff reason is ML_DSA_65_VALID/);
    });

    it("a boundary that claims on-chain ML-DSA verification", function () {
      const m = freshValid();
      m.boundary = { ...ML_DSA_BOUNDARY, onChainMLDSAVerification: true } as never;
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/onChainMLDSAVerification must be false/);
    });

    it("a boundary that claims custody", function () {
      const m = freshValid();
      m.boundary = { ...ML_DSA_BOUNDARY, custody: true } as never;
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/custody must be false/);
    });

    it("a limitations list missing a required disclosure topic", function () {
      const m = freshValid();
      // Drop the 'mock' disclosure entirely.
      m.limitations = m.limitations.filter((l) => !/\bmock\b/i.test(l));
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/limitations must disclose: mock verifier/);
    });

    it("overclaim language on an asserted (non-limitations) field", function () {
      const m = freshValid();
      m.evidence[0].reference = "quantum-proof, production-ready, guaranteed";
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/overclaim language/);
    });

    it("embedded raw key/signature material anywhere", function () {
      const m = freshValid();
      m.evidence[0].reference = "see 0x" + "cd".repeat(80);
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/raw key\/signature material/);
    });

    it("an artifactPath with traversal", function () {
      const m = freshValid();
      m.evidence[0].artifactPath = "../../etc/passwd";
      const res = validateManifest(m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/repo-relative path without traversal/);
    });

    it("a bad sourceType", function () {
      const m = freshValid();
      m.evidence[0].sourceType = "from-the-internet" as never;
      expect(validateManifest(m).valid).to.equal(false);
    });

    it("an empty evidence array", function () {
      const m = freshValid();
      m.evidence = [];
      expect(validateManifest(m).valid).to.equal(false);
    });
  });

  describe("committed manifest (no drift, matches sources)", function () {
    it("the committed file equals the freshly generated manifest", function () {
      expect(readJson(MANIFEST_PATH)).to.deep.equal(buildExampleManifest());
    });

    it("the committed file validates and carries no raw material", function () {
      const raw = readFileSync(MANIFEST_PATH, "utf8");
      expect(validateManifest(JSON.parse(raw)).valid).to.equal(true);
      expect(raw).to.not.match(/0x[0-9a-fA-F]{65,}/);
    });

    it("every entry's artifactHash equals keccak256 of the referenced file", function () {
      const manifest = readJson(MANIFEST_PATH) as MLDSAEvidenceManifest;
      for (const entry of manifest.evidence) {
        const onDisk = keccak256(toUtf8Bytes(readFileSync(resolve(entry.artifactPath), "utf8")));
        expect(onDisk, `${entry.id} artifactHash`).to.equal(entry.artifactHash);
      }
    });

    it("pq-verifier-evidence entries mirror the referenced evidence artifact's input hashes", function () {
      const manifest = readJson(MANIFEST_PATH) as MLDSAEvidenceManifest;
      for (const entry of manifest.evidence.filter((e) => e.kind === "pq-verifier-evidence")) {
        const ev = readJson(resolve(entry.artifactPath)) as {
          verification: { input: { messageHash: string; publicKeyHash: string; signatureHash: string } };
        };
        expect(entry.messageHash).to.equal(ev.verification.input.messageHash);
        expect(entry.publicKeyHash).to.equal(ev.verification.input.publicKeyHash);
        expect(entry.signatureHash).to.equal(ev.verification.input.signatureHash);
      }
    });

    it("is deterministic (building twice is byte-identical)", function () {
      expect(JSON.stringify(buildExampleManifest())).to.equal(JSON.stringify(buildExampleManifest()));
      expect(buildExampleManifest().generatedAt).to.equal("2026-01-01T00:00:00.000Z");
    });
  });

  describe("JSON Schema stays in sync with the code", function () {
    const schema = readJson(schemaPath) as Record<string, any>;

    it("manifest schema const matches ML_DSA_EVIDENCE_MANIFEST_SCHEMA", function () {
      expect(schema.properties.schema.const).to.equal(ML_DSA_EVIDENCE_MANIFEST_SCHEMA);
    });

    it("entry.kind enum matches ML_DSA_EVIDENCE_KINDS", function () {
      const kinds = schema.properties.evidence.items.properties.kind.enum.slice().sort();
      expect(kinds).to.deep.equal([...ML_DSA_EVIDENCE_KINDS].sort());
    });

    it("entry.sourceType enum matches ML_DSA_EVIDENCE_SOURCE_TYPES", function () {
      const types = schema.properties.evidence.items.properties.sourceType.enum.slice().sort();
      expect(types).to.deep.equal([...ML_DSA_EVIDENCE_SOURCE_TYPES].sort());
    });

    it("entry.result.reason enum matches the verifier's closed reason set", function () {
      const reasons = schema.properties.evidence.items.properties.result.properties.reason.enum.slice().sort();
      expect(reasons).to.deep.equal(Object.values(PQ_REASON).slice().sort());
    });

    it("boundary consts match ML_DSA_BOUNDARY", function () {
      const b = schema.properties.boundary.properties;
      expect(b.verificationMode.const).to.equal(ML_DSA_BOUNDARY.verificationMode);
      expect(b.attestation.const).to.equal(ML_DSA_BOUNDARY.attestation);
      expect(b.onChainMLDSAVerification.const).to.equal(ML_DSA_BOUNDARY.onChainMLDSAVerification);
      expect(b.onChainVerifierIsMock.const).to.equal(ML_DSA_BOUNDARY.onChainVerifierIsMock);
      expect(b.custody.const).to.equal(ML_DSA_BOUNDARY.custody);
    });

    it("the committed manifest validates against the shipped JSON Schema's structural rules", function () {
      // A lightweight structural check (we don't pull a full JSON-Schema engine):
      // the committed manifest's top-level keys equal the schema's required set.
      const manifest = readJson(MANIFEST_PATH) as Record<string, unknown>;
      expect(Object.keys(manifest).sort()).to.deep.equal([...schema.required].sort());
    });
  });

  it("buildManifest stamps a fresh ISO timestamp by default", function () {
    const m = buildManifest([buildExampleManifest().evidence[0]]);
    expect(m.generatedAt).to.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/);
    expect(validateManifest(m).valid).to.equal(true);
  });
});
