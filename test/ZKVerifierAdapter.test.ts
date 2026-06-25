/**
 * Tests for the ZK verifier adapter boundary: the builder/validator
 * (scripts/lib/zk-verifier-adapter.ts), the committed adapter at
 * evidence/zk/zk-verifier-adapter.json, its on-disk source cross-checks, and the
 * JSON Schema contract.
 *
 * Pure, fast, static reads — no SP1 toolchain, no proving, no network.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { ethers } from "ethers";
import { expect } from "chai";

import {
  ALIGNED_MANIFEST_SCHEMA,
  ALIGNED_PROOF_INPUT_SCHEMA,
  ZK_ADAPTER_ON_CHAIN_VERIFIER,
  ZK_VERIFIER_ADAPTER_SCHEMA,
  buildAdapter,
  isZKVerifierAdapter,
  validateAdapter,
  type ZKVerifierAdapter,
} from "../scripts/lib/zk-verifier-adapter";
import { ML_DSA_EVIDENCE_MANIFEST_SCHEMA } from "../scripts/lib/ml-dsa-evidence-manifest";
import { SP1_PROOF_INPUT_SCHEMA } from "../scripts/lib/sp1-proof-input";
import { PQ_PROOF_STATUS } from "../scripts/lib/proof-artifact";
import { ADAPTER_PATH, buildExampleAdapter } from "../scripts/generate-zk-verifier-adapter";

const schemaPath = resolve("evidence/zk/schema/zk-verifier-adapter.v1.schema.json");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function freshValid(): ZKVerifierAdapter {
  return JSON.parse(JSON.stringify(buildExampleAdapter()));
}

describe("ZK verifier adapter boundary", function () {
  describe("validateAdapter — accepts", function () {
    it("the freshly built adapter validates clean", function () {
      const res = validateAdapter(buildExampleAdapter());
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("exposes a type guard", function () {
      expect(isZKVerifierAdapter(buildExampleAdapter())).to.equal(true);
      expect(isZKVerifierAdapter({})).to.equal(false);
    });

    it("binds the proof input, journal, and evidence to the same material", function () {
      const a = buildExampleAdapter();
      // Journal decodes to the proof-input hashes (the core binding).
      const [digest, pkHash, sigHash] = new ethers.AbiCoder().decode(
        ["bytes32", "bytes32", "bytes32", "uint64", "address"],
        a.journal.publicValues,
      );
      expect(ethers.keccak256(digest)).to.equal(a.proofInput.messageHash);
      expect(pkHash).to.equal(a.proofInput.publicKeyHash);
      expect(sigHash).to.equal(a.proofInput.signatureHash);
    });
  });

  describe("validateAdapter — rejects", function () {
    it("a non-object", function () {
      expect(validateAdapter(null).valid).to.equal(false);
      expect(validateAdapter([]).valid).to.equal(false);
    });

    it("a wrong schema id", function () {
      const a = freshValid();
      a.schema = "walletwall.zk-verifier-adapter.v2" as never;
      expect(validateAdapter(a).valid).to.equal(false);
    });

    it("an unknown top-level key", function () {
      const a = freshValid() as unknown as Record<string, unknown>;
      a.surprise = 1;
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected key in adapter/);
    });

    it("an onChainVerifier that claims live on-chain verification", function () {
      const a = freshValid();
      a.onChainVerifier = { ...ZK_ADAPTER_ON_CHAIN_VERIFIER, onChainVerification: true } as never;
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/onChainVerification must be false/);
    });

    it("an onChainVerifier that claims a non-mock SP1 verifier", function () {
      const a = freshValid();
      a.onChainVerifier = { ...ZK_ADAPTER_ON_CHAIN_VERIFIER, sp1Verifier: "real" } as never;
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/sp1Verifier must be mock/);
    });

    it("a journal whose decoded pk hash disagrees with the proof input", function () {
      const a = freshValid();
      // Re-encode a journal with a tampered pk hash; everything else identical.
      const tamperedPk = "0x" + "ab".repeat(32);
      a.journal.publicValues = new ethers.AbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "uint64", "address"],
        [
          a.journal.publicValues.slice(0, 66),
          tamperedPk,
          "0x" + a.journal.publicValues.slice(2 + 128, 2 + 192),
          a.journal.chainId,
          a.journal.verifierAddress,
        ],
      );
      a.journal.publicValuesHash = ethers.keccak256(a.journal.publicValues);
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/journal publicKeyHash does not match proofInput/);
    });

    it("a journal publicValues of the wrong length", function () {
      const a = freshValid();
      a.journal.publicValues = "0x1234";
      a.journal.publicValuesHash = ethers.keccak256("0x1234");
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/160-byte hex/);
    });

    it("a publicValuesHash that is not keccak256(publicValues)", function () {
      const a = freshValid();
      a.journal.publicValuesHash = "0x" + "00".repeat(32);
      expect(validateAdapter(a).valid).to.equal(false);
    });

    it("a proof.status/generated mismatch", function () {
      const a = freshValid(); // gated + generated:false
      a.proof.generated = true;
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/generated must be true iff/);
    });

    it("a malformed proofInput hash", function () {
      const a = freshValid();
      a.proofInput.publicKeyHash = "0x1234";
      expect(validateAdapter(a).valid).to.equal(false);
    });

    it("a wrong evidence manifest schema", function () {
      const a = freshValid();
      a.evidence.manifestSchema = "walletwall.ml-dsa-evidence-manifest.v2" as never;
      expect(validateAdapter(a).valid).to.equal(false);
    });

    it("a limitations list missing a required disclosure topic", function () {
      const a = freshValid();
      a.limitations = a.limitations.filter((l) => !/\bmock\b/i.test(l));
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/limitations must disclose: mock/);
    });

    it("overclaim language on an asserted (non-limitations) field", function () {
      const a = freshValid();
      a.proof.reason = "production-ready, quantum-proof, guaranteed";
      const res = validateAdapter(a);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/overclaim language/);
    });

    it("a proofInput.path with traversal", function () {
      const a = freshValid();
      a.proofInput.path = "../../etc/passwd";
      expect(validateAdapter(a).valid).to.equal(false);
    });
  });

  describe("committed adapter (no drift, matches sources)", function () {
    it("the committed file equals the freshly generated adapter", function () {
      expect(readJson(ADAPTER_PATH)).to.deep.equal(buildExampleAdapter());
    });

    it("the committed file validates", function () {
      expect(validateAdapter(readJson(ADAPTER_PATH)).valid).to.equal(true);
    });

    it("the committed adapter's proofInput path points at the committed SP1 input", function () {
      const a = readJson(ADAPTER_PATH) as ZKVerifierAdapter;
      expect(a.proofInput.path).to.equal("zkvm/fixtures/mldsa65-withdrawal.inputs.json");
      // The referenced file exists and its material hashes match the adapter.
      const inputs = readJson(resolve(a.proofInput.path)) as { publicKey: string; signature: string };
      expect(ethers.keccak256(ethers.getBytes(inputs.publicKey))).to.equal(a.proofInput.publicKeyHash);
      expect(ethers.keccak256(ethers.getBytes(inputs.signature))).to.equal(a.proofInput.signatureHash);
    });

    it("the committed adapter's evidence entry exists in the manifest with matching hashes", function () {
      const a = readJson(ADAPTER_PATH) as ZKVerifierAdapter;
      const manifest = readJson(resolve(a.evidence.manifestPath)) as {
        evidence: { id: string; messageHash: string; publicKeyHash: string; signatureHash: string }[];
      };
      const entry = manifest.evidence.find((e) => e.id === a.evidence.evidenceId);
      expect(entry, "evidence entry present").to.not.equal(undefined);
      expect(entry!.publicKeyHash).to.equal(a.proofInput.publicKeyHash);
      expect(entry!.signatureHash).to.equal(a.proofInput.signatureHash);
      expect(entry!.messageHash).to.equal(a.proofInput.messageHash);
    });

    it("is deterministic across rebuilds", function () {
      expect(JSON.stringify(buildExampleAdapter())).to.equal(JSON.stringify(buildExampleAdapter()));
    });
  });

  describe("JSON Schema stays in sync with the code", function () {
    const schema = readJson(schemaPath) as Record<string, any>;

    it("adapter schema const matches ZK_VERIFIER_ADAPTER_SCHEMA", function () {
      expect(schema.properties.schema.const).to.equal(ZK_VERIFIER_ADAPTER_SCHEMA);
    });

    it("proofInput.schema const matches the aligned SP1 proof-input schema", function () {
      expect(schema.properties.proofInput.properties.schema.const).to.equal(ALIGNED_PROOF_INPUT_SCHEMA);
      expect(ALIGNED_PROOF_INPUT_SCHEMA).to.equal(SP1_PROOF_INPUT_SCHEMA);
    });

    it("evidence.manifestSchema const matches the aligned manifest schema", function () {
      expect(schema.properties.evidence.properties.manifestSchema.const).to.equal(ALIGNED_MANIFEST_SCHEMA);
      expect(ALIGNED_MANIFEST_SCHEMA).to.equal(ML_DSA_EVIDENCE_MANIFEST_SCHEMA);
    });

    it("proof.status enum matches the closed proof-status set", function () {
      const statuses = schema.properties.proof.properties.status.enum.slice().sort();
      expect(statuses).to.deep.equal(Object.values(PQ_PROOF_STATUS).slice().sort());
    });

    it("onChainVerifier consts match ZK_ADAPTER_ON_CHAIN_VERIFIER", function () {
      const p = schema.properties.onChainVerifier.properties;
      expect(p.sp1Verifier.const).to.equal(ZK_ADAPTER_ON_CHAIN_VERIFIER.sp1Verifier);
      expect(p.onChainVerification.const).to.equal(ZK_ADAPTER_ON_CHAIN_VERIFIER.onChainVerification);
      expect(p.custody.const).to.equal(ZK_ADAPTER_ON_CHAIN_VERIFIER.custody);
    });

    it("the committed adapter's top-level keys equal the schema's required set", function () {
      const adapter = readJson(ADAPTER_PATH) as Record<string, unknown>;
      expect(Object.keys(adapter).sort()).to.deep.equal([...schema.required].sort());
    });
  });

  it("buildAdapter stamps a fresh ISO timestamp and gated proof by default", function () {
    const src = buildExampleAdapter();
    const a = buildAdapter({ proofInput: src.proofInput, journal: src.journal, evidence: src.evidence });
    expect(a.generatedAt).to.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/);
    expect(a.proof.status).to.equal(PQ_PROOF_STATUS.GATED);
    expect(a.proof.generated).to.equal(false);
    expect(validateAdapter(a).valid).to.equal(true);
  });
});
