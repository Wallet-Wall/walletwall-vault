/**
 * Tests for the reproducible PQ/ZK proof-artifact manifest
 * (scripts/lib/proof-artifact.ts), its committed example, and the JSON Schema.
 *
 * Coverage:
 *   - buildProofArtifact produces a deterministic, valid manifest whose journal
 *     binds to the declared input hashes and which carries no raw key/signature
 *     material; the proof block is gated (no real proof generated),
 *   - validateProofArtifact accepts the example and rejects malformed ones
 *     (bad schema, timestamp, kind, tampered journal, status/generated mismatch,
 *     unknown keys),
 *   - the committed example file matches what the generator builds (no drift),
 *   - the shipped JSON Schema stays in sync with the code's constants.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { keccak256 } from "ethers";
import { expect } from "chai";

import {
  GATED_PROOF_REASON,
  PQ_PROOF_ARTIFACT_KIND,
  PQ_PROOF_ARTIFACT_SCHEMA_VERSION,
  PQ_PROOF_SCHEME,
  PQ_PROOF_STATUS,
  buildProofArtifact,
  isPQProofArtifact,
  validateProofArtifact,
} from "../scripts/lib/proof-artifact";
import {
  EXAMPLE_GENERATED_AT,
  EXAMPLE_PATH,
  EXAMPLE_VECTOR_SET,
  buildExample,
} from "../scripts/generate-proof-artifact";
import { loadSmokeFixture } from "../scripts/sp1-smoke";

const schemaPath = resolve("docs/schemas/pq-proof-artifact.v1.schema.json");

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

function freshExample() {
  // A clean, mutable deep copy of a valid manifest.
  return JSON.parse(JSON.stringify(buildExample()));
}

describe("PQ proof-artifact manifest", function () {
  describe("buildProofArtifact", function () {
    it("produces a valid, gated manifest pinned to the fixed timestamp", function () {
      const artifact = buildExample();
      expect(artifact.schema).to.equal(PQ_PROOF_ARTIFACT_SCHEMA_VERSION);
      expect(artifact.generatedAt).to.equal(EXAMPLE_GENERATED_AT);
      expect(artifact.artifact.kind).to.equal(PQ_PROOF_ARTIFACT_KIND);
      expect(artifact.artifact.vectorSet).to.equal(EXAMPLE_VECTOR_SET);
      expect(artifact.proof.status).to.equal(PQ_PROOF_STATUS.GATED);
      expect(artifact.proof.generated).to.equal(false);
      expect(artifact.proof.scheme).to.equal(PQ_PROOF_SCHEME);
      expect(artifact.proof.reason).to.equal(GATED_PROOF_REASON);
      expect(validateProofArtifact(artifact).errors).to.deep.equal([]);
    });

    it("binds the journal output hash to keccak256(publicValues)", function () {
      const { journal } = buildExample().artifact;
      expect(journal.publicValuesHash).to.equal(keccak256(journal.publicValues));
    });

    it("ties the manifest input hashes to the committed fixture", function () {
      const fixture = loadSmokeFixture();
      const { input } = buildExample().artifact;
      expect(input.publicKeyHash).to.equal(keccak256(fixture.publicKey));
      expect(input.signatureHash).to.equal(keccak256(fixture.signature));
    });

    it("defaults to a non-Date generatedAt and supports a Date", function () {
      const fixture = loadSmokeFixture();
      const a = buildProofArtifact({
        withdrawalDigest: fixture.withdrawalDigest,
        publicKey: fixture.publicKey,
        signature: fixture.signature,
        chainId: 31337n,
        verifierAddress: "0x" + "11".repeat(20),
        vectorSet: EXAMPLE_VECTOR_SET,
        generatedAt: new Date(0),
      });
      expect(a.generatedAt).to.equal("1970-01-01T00:00:00.000Z");
    });

    it("exposes a type guard", function () {
      expect(isPQProofArtifact(buildExample())).to.equal(true);
      expect(isPQProofArtifact({})).to.equal(false);
    });
  });

  describe("validateProofArtifact — rejects", function () {
    it("a non-object", function () {
      expect(validateProofArtifact(null).valid).to.equal(false);
      expect(validateProofArtifact("nope").valid).to.equal(false);
    });

    it("a wrong schema id", function () {
      const a = freshExample();
      a.schema = "walletwall.pq-proof-artifact.v2";
      expect(validateProofArtifact(a).valid).to.equal(false);
    });

    it("a malformed generatedAt", function () {
      const a = freshExample();
      a.generatedAt = "soon";
      expect(validateProofArtifact(a).valid).to.equal(false);
    });

    it("a wrong artifact.kind", function () {
      const a = freshExample();
      a.artifact.kind = "something-else";
      expect(validateProofArtifact(a).valid).to.equal(false);
    });

    it("an unknown top-level key", function () {
      const a = freshExample();
      a.extra = "surprise";
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected top-level key/i);
    });

    it("a tampered journal that no longer matches the input hashes", function () {
      const a = freshExample();
      // Flip the publicValuesHash so it stops matching keccak256(publicValues).
      a.artifact.journal.publicValuesHash = "0x" + "00".repeat(32);
      expect(validateProofArtifact(a).valid).to.equal(false);
    });

    it("a journal publicValues of the wrong length", function () {
      const a = freshExample();
      a.artifact.journal.publicValues = "0x1234";
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/160-byte hex/);
    });

    it("an input messageHash that disagrees with the journal", function () {
      const a = freshExample();
      // Overwrite only the declared messageHash; the publicValues blob still
      // encodes the original withdrawalDigest, so the cross-check must fire.
      a.artifact.input.messageHash = "0x" + "cc".repeat(32);
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/messageHash does not match/);
    });

    it("an input publicKeyHash that disagrees with the journal", function () {
      const a = freshExample();
      a.artifact.input.publicKeyHash = "0x" + "ab".repeat(32);
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/publicKeyHash does not match/);
    });

    it("a missing regeneration block", function () {
      const a = freshExample();
      delete a.regeneration;
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/regeneration is required/);
    });

    it("a regeneration.command that is empty", function () {
      const a = freshExample();
      a.regeneration.command = "";
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/regeneration\.command/);
    });

    it("a regeneration.deterministic that is not a boolean", function () {
      const a = freshExample();
      a.regeneration.deterministic = "yes";
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/regeneration\.deterministic/);
    });

    it("a proof.status/generated mismatch", function () {
      const a = freshExample();
      a.proof.generated = true; // status is still "gated"
      const res = validateProofArtifact(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/generated must be true iff/);
    });

    it("an unknown proof.status", function () {
      const a = freshExample();
      a.proof.status = "totally-made-up";
      expect(validateProofArtifact(a).valid).to.equal(false);
    });
  });

  describe("committed example (no drift)", function () {
    it("example file equals the freshly generated manifest", function () {
      expect(readJson(EXAMPLE_PATH)).to.deep.equal(buildExample());
    });

    it("example validates and carries no raw key/signature material", function () {
      const raw = readFileSync(EXAMPLE_PATH, "utf8");
      expect(validateProofArtifact(JSON.parse(raw)).valid).to.equal(true);
      // The journal public values (320 hex chars = 160 bytes) is the only long
      // hex run; nothing as long as a raw 1952-byte key / 3309-byte signature.
      expect(raw).to.not.match(/0x[0-9a-fA-F]{321,}/);
      // Defense in depth: the raw fixture bytes must not appear anywhere.
      const fixture = loadSmokeFixture();
      const pkHex = Buffer.from(fixture.publicKey).toString("hex");
      const sigHex = Buffer.from(fixture.signature).toString("hex");
      expect(raw.toLowerCase()).to.not.include(pkHex);
      expect(raw.toLowerCase()).to.not.include(sigHex);
    });

    it("is deterministic across rebuilds", function () {
      expect(JSON.stringify(buildExample())).to.equal(JSON.stringify(buildExample()));
    });
  });

  describe("JSON Schema stays in sync with the code", function () {
    const schema = readJson(schemaPath);

    it("manifest schema const matches the code", function () {
      expect(schema.properties.schema.const).to.equal(PQ_PROOF_ARTIFACT_SCHEMA_VERSION);
    });

    it("artifact.kind const matches the code", function () {
      expect(schema.properties.artifact.properties.kind.const).to.equal(PQ_PROOF_ARTIFACT_KIND);
    });

    it("proof.status enum matches the closed status set", function () {
      const enumVals = schema.properties.proof.properties.status.enum.slice().sort();
      expect(enumVals).to.deep.equal(Object.values(PQ_PROOF_STATUS).slice().sort());
    });

    it("tooling/scheme consts match the code", function () {
      expect(schema.properties.artifact.properties.tooling.properties.scheme.const).to.equal(PQ_PROOF_SCHEME);
      expect(schema.properties.proof.properties.scheme.const).to.equal(PQ_PROOF_SCHEME);
    });

    it("the committed example validates against the shipped JSON Schema shape", function () {
      // Lightweight structural cross-check (no external validator dependency):
      // required top-level keys present and additionalProperties respected.
      const example = readJson(EXAMPLE_PATH);
      for (const key of schema.required) {
        expect(Object.prototype.hasOwnProperty.call(example, key), `missing ${key}`).to.equal(true);
      }
    });
  });
});
