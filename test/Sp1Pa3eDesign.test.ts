/**
 * SP1-PA3E: the production-binding design manifest (scripts/lib/sp1-pa3e-design.ts) and the design document it
 * mirrors. The manifest is a design-time contract, not a measurement: the validator checks that it is internally
 * consistent (every threat names its binding or is marked unresolved, the public-values layout is contiguous and
 * sums to its length, every lifecycle transition names declared states, a revoked program authorizes nothing, the
 * recommended architecture carries no BLOCKING score, every failure fails closed, the PA3D residues are each
 * adjudicated) and that the document states every identifier the manifest declares, the final state and the
 * binding status. Design only: no Solidity, no proof, no chain. Research prototype. Not audited. Testnet/local only.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  DESIGN_DOC_REL,
  DESIGN_JSON_SCHEMA_REL,
  DESIGN_REL,
  DESIGN_SCHEMA,
  FINAL_STATES,
  LANE,
  PRODUCTION_SP1_BINDING,
  REQUIRED_RESIDUES,
  REQUIRED_THREATS,
  baselineErrors,
  designDocErrors,
  designErrors,
  hermeticClaims,
  type DesignManifest,
} from "../scripts/lib/sp1-pa3e-design";

const lf = (text: string) => text.replace(/\r\n/g, "\n");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const committed = (): DesignManifest => JSON.parse(lf(readFileSync(DESIGN_REL, "utf8")));
const doc = () => lf(readFileSync(DESIGN_DOC_REL, "utf8"));
const errorsOf = (edit: (m: DesignManifest) => void): string => {
  const m = committed();
  edit(m);
  return designErrors(m).join("\n");
};

describe("SP1-PA3E — the production-binding design manifest and document", function () {
  this.timeout(60_000);

  it("names the lane, the schema, the three final states and the binding status it can never raise", function () {
    expect(LANE).to.equal("SP1-PA3E");
    expect(DESIGN_SCHEMA).to.equal("walletwall.sp1-production-binding-design.v1");
    expect(DESIGN_REL).to.equal("evidence/zk/sp1-impl/pa3e-production-binding-design.json");
    expect(DESIGN_DOC_REL).to.equal("docs/SP1_Production_Binding_Design.md");
    expect([...FINAL_STATES]).to.deep.equal([
      "PA3E_PRODUCTION_BINDING_DESIGN_READY",
      "PA3E_DESIGN_BLOCKED",
      "PA3E_BLOCKED_ON_PA3D_MERGE",
    ]);
    expect(PRODUCTION_SP1_BINDING).to.equal("NOT_ESTABLISHED");
    expect(REQUIRED_THREATS.length).to.equal(20);
    expect(REQUIRED_RESIDUES).to.include("PA3D-F1");
    expect(REQUIRED_RESIDUES).to.include("PA3D-F4");
    expect(REQUIRED_RESIDUES.length).to.be.at.least(6);
  });

  describe("the committed manifest", function () {
    it("is internally consistent and in the ready state, with the binding not established", function () {
      const m = committed();
      expect(designErrors(m)).to.deep.equal([]);
      expect(m.schema).to.equal(DESIGN_SCHEMA);
      expect(m.state).to.equal("PA3E_PRODUCTION_BINDING_DESIGN_READY");
      expect(m.productionSp1Binding).to.equal("NOT_ESTABLISHED");
      expect(m.unresolved.filter((u) => u.blocking)).to.deep.equal([]);
    });

    it("carries the PA3D evidence forward without downgrading any fact", function () {
      const m = committed();
      const b = m.evidenceBaseline;
      expect(b.mainCommit).to.match(/^[0-9a-f]{40}$/);
      expect(b.mergeCommit.sha).to.equal(b.mainCommit);
      expect(b.mergeCommit.parents).to.have.length(2);
      expect(b.pa3dRecord.state).to.equal("PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED");
      const facts = b.carriedForward.join("\n");
      for (const must of [
        "one real v2 proof",
        "independently verified",
        "reproduced the expected public values",
        "determinism was NOT claimed",
        "attribution chain validated",
        "negative controls",
        "PARTIAL",
        "Docker Desktop",
        "shutdown defect",
        "chronyd",
        "Node dependency tree",
        "not yet wired into canonical CI",
      ]) {
        expect(facts, must).to.include(must);
      }
      // The committed PA3D record is the one the manifest names, by digest.
      const recordText = lf(readFileSync(b.pa3dRecord.path, "utf8"));
      expect(createHash("sha256").update(recordText).digest("hex")).to.equal(b.pa3dRecord.sha256);
      const record = JSON.parse(recordText);
      expect(record.state).to.equal(b.pa3dRecord.state);
      expect(b.proof.publicValuesSha256).to.equal(record.exercise.proof.publicValuesSha256);
      expect(b.proof.proofBytesSha256).to.equal(record.exercise.proof.proofBytesSha256);
      expect(b.program.programVKey).to.equal(record.statement.programVKey);
      expect(b.residue).to.deep.equal({
        unattributedEvents: record.exercise.record.assurance.unattributedEvents,
        unseenDestinations: record.exercise.record.assurance.unseenDestinations,
        otherNamespaceEgress: record.exercise.record.assurance.otherNamespaceEgress,
        unknownOutcomes: record.exercise.record.assurance.unknownOutcomes,
      });
    });

    it("classifies every candidate public input and binds the statement through the consumer's digest", function () {
      const m = committed();
      const names = m.statement.publicInputs.map((p) => p.name);
      for (const n of [
        "chainId",
        "vaultAddress",
        "policyEngine",
        "vaultOwner",
        "recipient",
        "asset",
        "amount",
        "nonce",
        "operationId",
        "policySnapshot",
        "deadline",
        "blockNumberOrHash",
        "programIdentity",
        "verifierVersion",
        "domainSeparator",
        "signatureHash",
        "verifierAddress",
      ]) {
        expect(names, n).to.include(n);
      }
      const by = Object.fromEntries(m.statement.publicInputs.map((p) => [p.name, p.classification]));
      expect(by.policySnapshot).to.equal("MUST_NOT_BIND");
      expect(by.policyEngine).to.equal("MUST_NOT_BIND");
      expect(by.blockNumberOrHash).to.equal("MUST_NOT_BIND");
      expect(by.chainId).to.equal("MUST_BIND");
      expect(by.nonce).to.equal("MUST_BIND");
      expect(by.recipient).to.equal("MUST_BIND");
      expect(by.amount).to.equal("MUST_BIND");
      expect(by.signatureHash).to.equal("MAY_BIND");
    });

    it("states twenty threats, each resolved by a named binding or marked partial or unresolved with its residual", function () {
      const m = committed();
      expect(m.threats.map((t) => t.id)).to.deep.equal([...REQUIRED_THREATS]);
      for (const t of m.threats) {
        if (t.status === "RESOLVED") expect(t.binding.length, t.id).to.be.greaterThan(10);
        else expect(t.residual.length, `${t.id} is ${t.status} without a residual`).to.be.greaterThan(10);
      }
      expect(
        m.threats.some((t) => t.status !== "RESOLVED"),
        "a threat model with nothing open overclaims",
      ).to.equal(true);
    });

    it("recommends one candidate the matrix does not block, and rejects the attestation path for production binding", function () {
      const m = committed();
      const ids = m.candidates.map((c) => c.id);
      expect(ids).to.include.members(["A", "B", "C"]);
      expect(ids).to.include(m.recommended.candidate);
      const scores = m.decisionMatrix.scores[m.recommended.candidate];
      expect(Object.values(scores)).to.not.include("BLOCKING");
      const attestation = m.candidates.find((c) => c.id === "C");
      expect(attestation?.verdict).to.equal("REJECTED");
      expect(Object.values(m.decisionMatrix.scores.C)).to.include("BLOCKING");
    });

    it("lays the public values out as 160 contiguous bytes of static words, and names the digest and proof constructions", function () {
      const m = committed();
      const e = m.encoding;
      expect(e.publicValues.totalBytes).to.equal(160);
      expect(e.publicValues.fields.map((f) => f.name)).to.deep.equal([
        "withdrawalDigest",
        "pkHash",
        "sigHash",
        "chainId",
        "verifierAddress",
      ]);
      expect(e.digest.scheme).to.include("EIP-712");
      expect(e.proofPayload.abi).to.include("bytes");
      expect(e.verifierBinding.publicValuesDigest).to.include("sha256");
    });

    it("gives every lifecycle state its powers, revokes everything at REVOKED, and names the on-chain evidence of every transition", function () {
      const m = committed();
      const states = Object.fromEntries(m.lifecycle.states.map((s) => [s.id, s]));
      for (const id of ["PROPOSED", "QUALIFIED", "ACTIVE", "DEPRECATED", "REVOKED"])
        expect(states[id], id).to.not.equal(undefined);
      expect(states.REVOKED.mayVerify).to.equal(false);
      expect(states.REVOKED.mayAuthorizeNew).to.equal(false);
      expect(states.REVOKED.mayAuthorizeExisting).to.equal(false);
      expect(states.DEPRECATED.mayAuthorizeNew).to.equal(false);
      expect(states.PROPOSED.mayAuthorizeNew).to.equal(false);
      expect(states.ACTIVE.mayAuthorizeNew).to.equal(true);
      for (const s of m.lifecycle.states) expect(s.historicalProofsAuditable, s.id).to.equal(true);
      for (const t of m.lifecycle.transitions) expect(t.evidence.length, `${t.from}->${t.to}`).to.be.greaterThan(10);
      expect(
        m.lifecycle.transitions.some((t) => t.from === "REVOKED"),
        "nothing leads back from REVOKED",
      ).to.equal(false);
    });

    it("adjudicates every PA3D residue into one of the four classes and never calls the exercise hermetic", function () {
      const m = committed();
      const ids = m.residues.map((r) => r.id);
      for (const r of REQUIRED_RESIDUES) expect(ids, r).to.include(r);
      for (const r of m.residues) {
        expect([
          "MUST_FIX_BEFORE_IMPLEMENTATION",
          "MUST_FIX_BEFORE_PRODUCTION",
          "ACCEPTABLE_WITH_DOCUMENTED_BOUNDARY",
          "IRRELEVANT_TO_PRODUCTION_BINDING",
        ]).to.include(r.disposition);
        expect(r.why.length, r.id).to.be.greaterThan(20);
      }
      expect(doc().toLowerCase()).to.not.include("fully hermetic");
    });

    it("has fail-closed semantics for every failure and invariants PB-1 to PB-10 and more, each with a tier and the threats it closes", function () {
      const m = committed();
      for (const f of m.failures) expect(["REVERT", "DENY_FALSE", "NO_STATE_CHANGE"], f.failure).to.include(f.outcome);
      const ids = m.invariants.map((i) => i.id);
      for (let n = 1; n <= 10; n++) expect(ids).to.include(`PB-${n}`);
      expect(ids.length).to.be.greaterThan(10);
      for (const i of m.invariants) {
        expect(["T0", "T1", "T2", "T3"], i.id).to.include(i.tier);
        for (const t of i.closes) expect(REQUIRED_THREATS, `${i.id} closes unknown ${t}`).to.include(t);
      }
    });

    it("has the shape its JSON schema names, closed to other fields", function () {
      const schema = JSON.parse(lf(readFileSync(DESIGN_JSON_SCHEMA_REL, "utf8"))) as {
        $id: string;
        required: string[];
        properties: Record<string, unknown>;
        additionalProperties: boolean;
      };
      expect(schema.$id).to.equal(DESIGN_SCHEMA);
      expect(schema.additionalProperties).to.equal(false);
      expect(Object.keys(committed()).sort()).to.deep.equal([...schema.required].sort());
      expect(Object.keys(schema.properties).sort()).to.deep.equal([...schema.required].sort());
    });
  });

  describe("the validator's refusals", function () {
    it("refuses a threat that is neither bound nor marked open, and an open threat without its residual", function () {
      expect(errorsOf((m) => ((m.threats[0] as { binding: string }).binding = ""))).to.include("THREAT_UNBOUND T01");
      expect(
        errorsOf((m) => {
          m.threats[1].status = "UNRESOLVED";
          m.threats[1].residual = "";
        }),
      ).to.include("THREAT_RESIDUAL_MISSING T02");
      expect(errorsOf((m) => ((m.threats[2] as { status: string }).status = "FINE"))).to.include("THREAT_STATUS T03");
    });

    it("refuses a public-values layout that is not contiguous or does not sum to its length", function () {
      expect(errorsOf((m) => (m.encoding.publicValues.totalBytes = 192))).to.include("ENCODING_LENGTH");
      expect(errorsOf((m) => (m.encoding.publicValues.fields[1].offset = 40))).to.include("ENCODING_GAP");
      expect(errorsOf((m) => (m.encoding.publicValues.fields[2].bytes = 16))).to.include("ENCODING_WORD");
    });

    it("refuses a lifecycle whose transition names an unknown state, whose REVOKED still authorizes, or that leads back from REVOKED", function () {
      expect(errorsOf((m) => (m.lifecycle.transitions[0].to = "ZOMBIE"))).to.include("LIFECYCLE_UNKNOWN_STATE");
      expect(
        errorsOf(
          (m) => ((m.lifecycle.states.find((s) => s.id === "REVOKED") as { mayVerify: boolean }).mayVerify = true),
        ),
      ).to.include("LIFECYCLE_REVOKED_POWER");
      expect(
        errorsOf((m) =>
          m.lifecycle.transitions.push({ from: "REVOKED", to: "ACTIVE", by: "x", evidence: "none at all here" }),
        ),
      ).to.include("LIFECYCLE_REVOKED_EXIT");
    });

    it("refuses a recommended architecture with a BLOCKING score, or one that is not a candidate", function () {
      expect(
        errorsOf(
          (m) => (m.decisionMatrix.scores[m.recommended.candidate][m.decisionMatrix.dimensions[0]] = "BLOCKING"),
        ),
      ).to.include("RECOMMENDED_BLOCKED");
      expect(errorsOf((m) => (m.recommended.candidate = "Z"))).to.include("RECOMMENDED_UNKNOWN");
      expect(
        errorsOf((m) => delete (m.decisionMatrix.scores.A as Record<string, unknown>)[m.decisionMatrix.dimensions[0]]),
      ).to.include("MATRIX_INCOMPLETE");
    });

    it("refuses a failure that does not fail closed, a residue outside the four classes, a missing residue, and an invariant closing an unknown threat", function () {
      expect(errorsOf((m) => ((m.failures[0] as { outcome: string }).outcome = "AUTHORIZE"))).to.include(
        "FAILURE_NOT_CLOSED",
      );
      expect(errorsOf((m) => ((m.residues[0] as { disposition: string }).disposition = "FINE"))).to.include(
        "RESIDUE_DISPOSITION",
      );
      expect(
        errorsOf((m) =>
          m.residues.splice(
            m.residues.findIndex((r) => r.id === "PA3D-F4"),
            1,
          ),
        ),
      ).to.include("RESIDUE_MISSING PA3D-F4");
      expect(errorsOf((m) => (m.invariants[0].closes as string[]).push("T99"))).to.include("INVARIANT_UNKNOWN_THREAT");
    });

    it("refuses the ready state while a blocking question is open, and any binding status but NOT_ESTABLISHED", function () {
      expect(
        errorsOf((m) =>
          m.unresolved.push({ id: "U-99", question: "a blocking question", blocking: true, owner: "owner" }),
        ),
      ).to.include("READY_WITH_BLOCKING_QUESTION");
      expect(
        errorsOf((m) => ((m as { productionSp1Binding: string }).productionSp1Binding = "ESTABLISHED")),
      ).to.include("PRODUCTION_SP1_BINDING");
      expect(errorsOf((m) => ((m as { state: string }).state = "DONE"))).to.include("STATE_UNKNOWN");
    });
  });

  describe("the design document", function () {
    it("states every identifier the manifest declares, the final state, the binding status and the baseline", function () {
      const m = committed();
      const text = doc();
      expect(designDocErrors(m, text)).to.deep.equal([]);
      expect(text.split("\n")[0]).to.include("SP1-PA3E");
      expect(text).to.include("`PRODUCTION_SP1_BINDING = NOT_ESTABLISHED`");
      expect(text).to.include(`State: \`${m.state}\``);
      expect(text).to.include(m.evidenceBaseline.mainCommit);
      for (const t of m.threats) expect(text, t.id).to.include(t.id);
      for (const i of m.invariants) expect(text, i.id).to.include(i.id);
      for (const r of m.residues) expect(text, r.id).to.include(r.id);
    });

    it("refuses a document that omits an identifier, the state or the binding status", function () {
      const m = committed();
      const text = doc();
      expect(designDocErrors(m, text.replaceAll("PB-5", "PB-X")).join("\n")).to.include("DOC_MISSING PB-5");
      expect(designDocErrors(m, text.replaceAll(`State: \`${m.state}\``, "State: `OTHER`")).join("\n")).to.include(
        "DOC_STATE",
      );
      expect(
        designDocErrors(
          m,
          text.replace(/PRODUCTION_SP1_BINDING = NOT_ESTABLISHED/g, "PRODUCTION_SP1_BINDING = ESTABLISHED"),
        ).join("\n"),
      ).to.include("DOC_BINDING");
    });

    it("refuses a document that names an identifier the manifest does not declare (the converse check)", function () {
      const m = committed();
      const text = doc();
      const errors = designDocErrors(
        m,
        `${text}\n\nThreat T21 and gate G-99 and invariant PB-99 are not in the manifest.\n`,
      ).join("\n");
      expect(errors).to.include("DOC_UNDECLARED T21");
      expect(errors).to.include("DOC_UNDECLARED G-99");
      expect(errors).to.include("DOC_UNDECLARED PB-99");
      expect(designDocErrors(m, `${text}\n\nResidue PA3D-F9 is adjudicated nowhere.\n`).join("\n")).to.include(
        "DOC_UNDECLARED PA3D-F9",
      );
    });

    it("refuses any artifact that calls PA3D hermetic, while negated uses pass", function () {
      const m = committed();
      const text = doc();
      expect(designDocErrors(m, `${text}\n\nThe proving run was hermetic.\n`).join("\n")).to.include("DOC_HERMETIC");
      expect(designDocErrors(m, `${text}\n\nThe proving run was fully hermetic.\n`).join("\n")).to.include(
        "DOC_HERMETIC",
      );
      expect(
        designDocErrors(m, `${text}\n\nThe proving run was not hermetic; no hermeticity is claimed.\n`),
      ).to.deep.equal([]);
      expect(hermeticClaims("PA3D is never called hermetic; nor hermetic at all")).to.deep.equal([]);
      expect(hermeticClaims("the exercise was hermetic")).to.have.length(1);
      expect(errorsOf((m2) => m2.nonGoals.push("the exercise was hermetic and sealed"))).to.include(
        "MANIFEST_HERMETIC",
      );
    });

    it("carries the repository's disclaimers (the docs sweep requires one wherever withdrawals are discussed)", function () {
      const text = doc().toLowerCase();
      expect(text).to.include("research prototype");
      expect(text).to.include("not audited");
      expect(text).to.include("do not use real funds");
      expect(text).to.include("not a mainnet write path");
    });
  });

  describe("the evidence baseline against the committed PA3D record and the package version", function () {
    const record = () => JSON.parse(lf(readFileSync(committed().evidenceBaseline.pa3dRecord.path, "utf8")));
    const version = () => (JSON.parse(lf(readFileSync("package.json", "utf8"))) as { version: string }).version;

    it("agrees with the record on state, binding, program, proof digests, selector, acceptance, determinism and residue counts", function () {
      expect(baselineErrors(committed(), record(), version())).to.deep.equal([]);
    });

    it("refuses a residue count, a proof digest or a determinism statement that differs from the record", function () {
      const m = committed();
      m.evidenceBaseline.residue.otherNamespaceEgress = 0;
      expect(baselineErrors(m, record(), version()).join("\n")).to.include("BASELINE_RESIDUE otherNamespaceEgress");
      const m2 = committed();
      m2.evidenceBaseline.proof.proofBytesSha256 = "0".repeat(64);
      expect(baselineErrors(m2, record(), version()).join("\n")).to.include("BASELINE_PROOF_BYTES_SHA256");
      const m3 = committed();
      (m3.evidenceBaseline.proof as { proofByteDeterminism: string }).proofByteDeterminism = "CLAIMED";
      expect(baselineErrors(m3, record(), version()).join("\n")).to.include("BASELINE_DETERMINISM");
    });

    it("refuses a package version that is not the baseline version or a later patch of it", function () {
      expect(baselineErrors(committed(), record(), "0.12.99").join("\n")).to.include("BASELINE_VERSION");
      expect(baselineErrors(committed(), record(), "0.14.0").join("\n")).to.include("BASELINE_VERSION");
      const m = committed();
      expect(baselineErrors(m, record(), m.evidenceBaseline.version)).to.deep.equal([]);
      const [maj, min, patch] = m.evidenceBaseline.version.split(".").map(Number);
      expect(baselineErrors(m, record(), `${maj}.${min}.${patch + 3}`)).to.deep.equal([]);
    });
  });
});
