/**
 * Tests for the SP1 ML-DSA-65 proof-input scaffold: the builder/validator/
 * alignment helpers (scripts/lib/sp1-proof-input.ts), the committed fixture at
 * zkvm/fixtures/mldsa65-withdrawal.inputs.json, and its alignment with the
 * committed ML-DSA evidence manifest.
 *
 * Pure, fast, static reads — no SP1 toolchain, no proving, no network. The heavy
 * host-execute / proving path stays out of CI (host-binary-gated / RUN_SP1_E2E=1).
 */
import { readFileSync } from "node:fs";

import { ethers } from "ethers";
import { expect } from "chai";

import {
  ALIGNED_MANIFEST_SCHEMA,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  SOURCE_EVIDENCE_ID,
  SP1_PROOF_INPUT_SCHEMA,
  buildProofInputs,
  expectedChainId,
  validateAlignment,
  validateProofInputs,
  type SP1ProofInputs,
} from "../scripts/lib/sp1-proof-input";
import { ML_DSA_EVIDENCE_MANIFEST_SCHEMA, type MLDSAEvidenceManifest } from "../scripts/lib/ml-dsa-evidence-manifest";
import { PROOF_INPUT_PATH, buildExampleProofInput } from "../scripts/generate-sp1-proof-input";
import { MANIFEST_PATH } from "../scripts/generate-mldsa-evidence-manifest";
import { buildSmokeInputs, computeExpectedPublicValues, loadSmokeFixture } from "../scripts/sp1-smoke";

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function freshInputs(): SP1ProofInputs {
  return JSON.parse(JSON.stringify(buildExampleProofInput()));
}

function committedManifest(): MLDSAEvidenceManifest {
  return readJson(MANIFEST_PATH) as MLDSAEvidenceManifest;
}

describe("SP1 ML-DSA-65 proof-input scaffold", function () {
  describe("buildProofInputs / validateProofInputs", function () {
    it("builds a flat host-shaped withdrawal input", function () {
      const inputs = buildProofInputs();
      expect(inputs.withdrawalDigest).to.match(/^0x[0-9a-fA-F]{64}$/);
      expect(ethers.dataLength(inputs.publicKey)).to.equal(ML_DSA_65_PUBLIC_KEY_BYTES);
      expect(ethers.dataLength(inputs.signature)).to.equal(ML_DSA_65_SIGNATURE_BYTES);
      expect(inputs.chainId).to.equal(expectedChainId());
      expect(ethers.isAddress(inputs.verifierAddress)).to.equal(true);
    });

    it("accepts the committed fixture", function () {
      const res = validateProofInputs(readJson(PROOF_INPUT_PATH));
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("rejects a non-object", function () {
      expect(validateProofInputs(null).valid).to.equal(false);
      expect(validateProofInputs([]).valid).to.equal(false);
    });

    it("rejects a wrong-length public key", function () {
      const i = freshInputs();
      i.publicKey = "0x1234";
      const res = validateProofInputs(i);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/publicKey must be 1952/);
    });

    it("rejects a wrong-length signature", function () {
      const i = freshInputs();
      i.signature = "0xabcd";
      expect(validateProofInputs(i).valid).to.equal(false);
    });

    it("rejects a mainnet chain id", function () {
      const i = freshInputs();
      i.chainId = 1;
      const res = validateProofInputs(i);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/mainnet chain ID/);
    });

    it("rejects an unknown key", function () {
      const i = freshInputs() as unknown as Record<string, unknown>;
      i.surprise = "x";
      const res = validateProofInputs(i);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected key in proof input/);
    });

    it("rejects a non-empty message (not the withdrawal path)", function () {
      const i = freshInputs() as unknown as Record<string, unknown>;
      i.message = "0xdeadbeef";
      const res = validateProofInputs(i);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/message must be empty/);
    });

    it("rejects a bad verifier address", function () {
      const i = freshInputs();
      i.verifierAddress = "not-an-address";
      expect(validateProofInputs(i).valid).to.equal(false);
    });
  });

  describe("validateAlignment with the ML-DSA evidence manifest", function () {
    it("accepts the committed fixture against the committed manifest", function () {
      const res = validateAlignment(buildExampleProofInput(), committedManifest());
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("rejects a fixture whose material no longer matches the manifest hashes", function () {
      const tampered = freshInputs();
      // Flip one signature byte → its keccak256 changes → alignment must fail.
      const sig = ethers.getBytes(tampered.signature);
      sig[0] ^= 0x01;
      tampered.signature = ethers.hexlify(sig);
      const res = validateAlignment(tampered, committedManifest());
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/signatureHash mismatch/);
    });

    it("rejects a manifest with the wrong schema version", function () {
      const m = committedManifest();
      m.schema = "walletwall.ml-dsa-evidence-manifest.v2" as never;
      const res = validateAlignment(buildExampleProofInput(), m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/not the aligned/);
    });

    it("rejects a manifest missing the source evidence entry", function () {
      const m = committedManifest();
      m.evidence = m.evidence.filter((e) => e.id !== SOURCE_EVIDENCE_ID);
      const res = validateAlignment(buildExampleProofInput(), m);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/no evidence entry/);
    });

    it("pins the aligned manifest schema to the manifest module's current constant", function () {
      // If the manifest schema id ever bumps, this fails and forces a conscious
      // update of the proof-input alignment rather than silent drift.
      expect(ALIGNED_MANIFEST_SCHEMA).to.equal(ML_DSA_EVIDENCE_MANIFEST_SCHEMA);
    });
  });

  describe("committed fixture (no drift, host- and proof-path consistent)", function () {
    it("equals the freshly generated input", function () {
      expect(readJson(PROOF_INPUT_PATH)).to.deep.equal(buildExampleProofInput());
    });

    it("is byte-identical to what the SP1 smoke lane feeds the guest", function () {
      // The committed proof input IS the smoke fixture input; running
      // `mldsa65-host execute` on it reproduces the tested smoke journal.
      expect(JSON.stringify(readJson(PROOF_INPUT_PATH))).to.equal(JSON.stringify(buildSmokeInputs()));
    });

    it("derives the same deterministic 160-byte SP1 journal as the smoke lane", function () {
      const inputs = readJson(PROOF_INPUT_PATH) as SP1ProofInputs;
      const journal = computeExpectedPublicValues(loadSmokeFixture());
      expect(ethers.dataLength(journal)).to.equal(160);
      // The journal commits keccak256(publicKey) and keccak256(signature); confirm
      // they match the committed input's raw material.
      const [, pkHash, sigHash] = new ethers.AbiCoder().decode(
        ["bytes32", "bytes32", "bytes32", "uint64", "address"],
        journal,
      );
      expect(pkHash).to.equal(ethers.keccak256(ethers.getBytes(inputs.publicKey)));
      expect(sigHash).to.equal(ethers.keccak256(ethers.getBytes(inputs.signature)));
    });

    it("aligns with the committed manifest on disk", function () {
      const res = validateAlignment(readJson(PROOF_INPUT_PATH) as SP1ProofInputs, committedManifest());
      expect(res.valid).to.equal(true);
    });

    it("exposes a stable proof-input schema id", function () {
      expect(SP1_PROOF_INPUT_SCHEMA).to.equal("walletwall.sp1-proof-input.v1");
    });
  });
});
