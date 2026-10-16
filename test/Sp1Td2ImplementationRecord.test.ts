/**
 * The SP1-TD2 implementation record (evidence/zk/sp1-td2/implementation-record.json, scripts/lib/sp1-td2-record.ts):
 * it validates against SP1-TD1's receipt and the repository, and each rule refuses the departure it exists for —
 * re-deciding a frozen item, citing a test that does not exercise the proof, calling the multisig rotation
 * authority-neutral, recording the owner's decision on it (accepted, 2026-10-16) in any terms but the owner's,
 * admitting a consumer the decision does not admit, or unblocking real value.
 *
 * Pure, static reads — no network, no chain.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  NOT_WAIVED,
  TD1_RECEIPT_REL,
  TD2_RECORD_REL,
  admittedConsumers,
  effectiveHaltScope,
  validateCommittedTd2Record,
  validateTd2Record,
  type Td2RecordContext,
} from "../scripts/lib/sp1-td2-record";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const RECORD = JSON.parse(readFileSync(resolve(TD2_RECORD_REL), "utf8"));
const TD1_BYTES = readFileSync(resolve(TD1_RECEIPT_REL));
const readText = (rel: string): string | null => {
  try {
    return readFileSync(resolve(rel), "utf8");
  } catch {
    return null;
  }
};
const CTX: Td2RecordContext = { td1ReceiptBytes: TD1_BYTES, readText };

describe("SP1-TD2 implementation record", function () {
  it("the committed record validates against SP1-TD1's receipt and the repository", function () {
    expect(validateCommittedTd2Record()).to.deep.equal([]);
    expect(validateTd2Record(clone(RECORD), CTX)).to.deep.equal([]);
  });

  it("records both requirements built and tested, the owner's acceptance of the multisig rotation in the owner's terms, and real value blocked", function () {
    expect(RECORD.requirements.map((r: { id: string; status: string }) => `${r.id}: ${r.status}`)).to.deep.equal([
      "TD2-COMMON-VERIFIER-HALT: BUILT_AND_TESTED",
      "TD2-MULTISIG-ROTATION: BUILT_AND_TESTED",
    ]);
    const gate = RECORD.requirements[1];
    expect(gate.haltAdmission).to.equal("ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES");
    expect(gate.ownerDecision).to.include({
      decidedBy: "owner",
      date: "2026-10-16",
      TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION: "ACCEPTED",
      MULTISIG_ROTATION_AUTHORITY_CLASS: "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL",
      HALT_ADMISSION: "ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES",
    });
    expect(gate.ownerDecision.reasoning).to.have.length(7);
    expect(gate.ownerDecision.doesNotWaive).to.deep.equal(NOT_WAIVED);
    expect(gate.stopConditionEvaluation).to.equal("NOT_FOUND_UNACCEPTABLE_BY_TD2_ACCEPTED_BY_THE_OWNER");
    // The accounting the owner kept: new authority for an existing principal, widening, owner-only, 172,800 s.
    expect(RECORD.authorizationCut[2]).to.include({
      principal: "WALLETWALL_MULTISIG_VAULT_OWNER",
      classification: "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL",
      widensAuthorization: true,
      delaySeconds: 172800,
    });
    // SP1-TD1's scope is untouched; the effective one admits the multisig vault through its gate, and nothing else.
    expect(RECORD.haltScope.excludedUntilRecoverable.map((e: { consumer: string }) => e.consumer)).to.deep.equal([
      "WalletWallMultiSigVault",
    ]);
    expect(RECORD.effectiveHaltScope).to.deep.equal({
      applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
      excludedUntilRecoverable: [],
    });
    expect(RECORD.td1N12.answer).to.equal("BY_PROCESS_WITH_ON_CHAIN_IDENTITY_AND_PRINCIPAL_CHECKS");
    expect(RECORD.realValue.blocked).to.equal(true);
    expect(RECORD.realValue.blockers.join(" | ")).to.not.match(/decision on the multisig/);
  });

  describe("admission through a TD2 gate", function () {
    const frozen = JSON.parse(TD1_BYTES.toString("utf8")).decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope;
    const admitted = [{ consumer: "WalletWallMultiSigVault", gate: "TD2-MULTISIG-ROTATION" }];

    it("admits the consumer of a gate built, tested and accepted by the owner, and no one else", function () {
      expect(admittedConsumers(RECORD)).to.deep.equal(admitted);
      const departures: [string, (r: any) => void][] = [
        ["the gate not built", (r) => (r.requirements[1].status = "PARTIAL")],
        ["no consumer named", (r) => delete r.requirements[1].consumer],
        ["the admission pending", (r) => (r.requirements[1].haltAdmission = "OWNER_DECISION_PENDING")],
        ["the decision's admission otherwise", (r) => (r.requirements[1].ownerDecision.HALT_ADMISSION = "ACCEPTED")],
        [
          "the authorization cut not accepted",
          (r) => (r.requirements[1].ownerDecision.TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION = "REJECTED"),
        ],
        ["no owner decision", (r) => delete r.requirements[1].ownerDecision],
      ];
      for (const [label, depart] of departures) {
        const r = clone(RECORD);
        depart(r);
        expect(admittedConsumers(r), label).to.deep.equal([]);
      }
      for (const value of [null, {}, { requirements: "none" }]) expect(admittedConsumers(value)).to.deep.equal([]);
    });

    it("moves only the admitted exclusion into the scope, keeping SP1-TD1's scope otherwise", function () {
      expect(effectiveHaltScope(frozen, [])).to.deep.equal(frozen);
      expect(effectiveHaltScope(frozen, admitted)).to.deep.equal(RECORD.effectiveHaltScope);
      for (const other of [
        { consumer: "WalletWallMultiSigVault", gate: "TD2-COMMON-VERIFIER-HALT" },
        { consumer: "WalletWallVault", gate: "TD2-MULTISIG-ROTATION" },
      ]) {
        expect(effectiveHaltScope(frozen, [other]), JSON.stringify(other)).to.deep.equal(frozen);
      }
      // The scope it returns is a copy: SP1-TD1's is never edited in place.
      const copy = effectiveHaltScope(frozen, admitted);
      copy.applies.push("Elsewhere");
      expect(frozen.applies).to.not.include("Elsewhere");
    });
  });

  const cases: [string, (r: any) => void, RegExp][] = [
    ["another schema", (r) => (r.schema = "walletwall.sp1-td2-implementation-record.v0"), /schema must be/],
    ["another lane", (r) => (r.lane = "SP1-TD3"), /lane must be SP1-TD2/],
    ["a verdict that skips the owner", (r) => (r.verdict = "READY_FOR_REAL_VALUE"), /awaits the owner's review/],
    ["a rewritten TD1 receipt", (r) => (r.td1Receipt.sha256 = "0".repeat(64)), /never rewrites it/],
    [
      "another TD1 receipt path",
      (r) => (r.td1Receipt.path = "evidence/zk/sp1-p1/stop-receipt.json"),
      /td1Receipt must be/,
    ],
    ["a requirement dropped", (r) => r.requirements.pop(), /requirements must be SP1-TD1's/],
    ["requirements reordered", (r) => r.requirements.reverse(), /requirements must be SP1-TD1's/],
    ["a requirement not built", (r) => (r.requirements[0].status = "PARTIAL"), /status must be BUILT_AND_TESTED/],
    ["a frozen proof dropped", (r) => r.requirements[0].proofs.pop(), /proofs must be SP1-TD1's/],
    ["a proof renamed", (r) => (r.requirements[1].proofs[0].id = "ROTATION_WORKS"), /proofs must be SP1-TD1's/],
    ["an unknown enforcement", (r) => (r.requirements[0].proofs[0].enforcedBy = "HOPE"), /enforcedBy must be one of/],
    ["a proof without a test", (r) => (r.requirements[0].proofs[1].tests = []), /names no test/],
    [
      "a test file that does not exist",
      (r) => (r.requirements[0].proofs[1].tests = ["test/Nope.test.ts"]),
      /does not exist/,
    ],
    ["a path outside test/", (r) => (r.requirements[0].proofs[1].tests = ["package.json"]), /does not exist/],
    [
      "a test that does not name the proof",
      (r) => (r.requirements[0].proofs[0].tests = ["test/Sp1Td2VerifierBinding.test.ts"]),
      /does not name the proof/,
    ],
    [
      "a softened stop condition",
      (r) => (r.requirements[1].stopCondition.never = "NOTHING"),
      /stop condition must be SP1-TD1's/,
    ],
    // The owner's decision, closed: refused if reopened, reversed, relabelled, widened or left unattributed.
    [
      "the decision reopened as pending",
      (r) => (r.requirements[1].haltAdmission = "OWNER_DECISION_PENDING"),
      /HALT_ADMISSION = ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES/,
    ],
    [
      "the authorization cut rejected",
      (r) => (r.requirements[1].ownerDecision.TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION = "REJECTED"),
      /TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION = ACCEPTED/,
    ],
    [
      "the rotation relabelled authority-neutral in the decision",
      (r) => (r.requirements[1].ownerDecision.MULTISIG_ROTATION_AUTHORITY_CLASS = "AUTHORITY_NEUTRAL"),
      /stays NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL, never authority-neutral/,
    ],
    [
      "the rotation relabelled liveness-only",
      (r) => (r.requirements[1].ownerDecision.MULTISIG_ROTATION_AUTHORITY_CLASS = "LIVENESS_ONLY"),
      /never authority-neutral/,
    ],
    [
      "the rotation relabelled retained authority",
      (r) => (r.requirements[1].ownerDecision.MULTISIG_ROTATION_AUTHORITY_CLASS = "RETAINED"),
      /never authority-neutral/,
    ],
    [
      "the rotation relabelled no authority increase",
      (r) => (r.requirements[1].ownerDecision.MULTISIG_ROTATION_AUTHORITY_CLASS = "NO_AUTHORITY_INCREASE"),
      /never authority-neutral/,
    ],
    [
      "an admission without its binding gates",
      (r) => (r.requirements[1].ownerDecision.HALT_ADMISSION = "ACCEPTED"),
      /HALT_ADMISSION = ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES/,
    ],
    [
      "an admission that disagrees with the decision",
      (r) => (r.requirements[1].haltAdmission = "ADMITTED"),
      /HALT_ADMISSION = ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES/,
    ],
    [
      "a waived per-chain execution gate",
      (r) => r.requirements[1].ownerDecision.doesNotWaive.splice(4, 1),
      /waives none of TD1-N12, designation, code-hash, registry, per-chain execution, successor identity/,
    ],
    [
      "a waived designation gate",
      (r) => (r.requirements[1].ownerDecision.doesNotWaive = ["TD1-N12"]),
      /waives none of/,
    ],
    [
      "a decision not taken by the owner",
      (r) => (r.requirements[1].ownerDecision.decidedBy = "SP1-TD2"),
      /names who decided it and when/,
    ],
    [
      "an undated decision",
      (r) => (r.requirements[1].ownerDecision.date = "yesterday"),
      /names who decided it and when/,
    ],
    ["the decision dropped", (r) => delete r.requirements[1].ownerDecision, /names who decided it and when/],
    [
      "the owner's reasoning dropped",
      (r) => (r.requirements[1].ownerDecision.reasoning = []),
      /reasoning is recorded with the decision/,
    ],
    [
      "the evaluation left with the owner",
      (r) => (r.requirements[1].stopConditionEvaluation = "NOT_FOUND_UNACCEPTABLE_BY_TD2_OWNER_DECIDES"),
      /evaluation is NOT_FOUND_UNACCEPTABLE_BY_TD2_ACCEPTED_BY_THE_OWNER/,
    ],
    [
      "the multisig vault left outside the effective scope",
      (r) =>
        (r.effectiveHaltScope = JSON.parse(
          TD1_BYTES.toString("utf8"),
        ).decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope),
      /effectiveHaltScope must be SP1-TD1's scope with exactly the owner's admissions applied/,
    ],
    [
      "a consumer admitted without a decision",
      (r) => r.effectiveHaltScope.applies.push("SomeOtherVault"),
      /effectiveHaltScope must be/,
    ],
    ["the effective scope dropped", (r) => delete r.effectiveHaltScope, /effectiveHaltScope must be/],
    [
      "a shorter delay",
      (r) => (r.requirements[1].measured.minimumDelaySeconds = 86400),
      /delay must be at least 172800s/,
    ],
    [
      "an instant replacement",
      (r) => (r.requirements[1].measured.instantReplacement = true),
      /instantReplacement must be false/,
    ],
    [
      "a halt principal that rotates",
      (r) => (r.requirements[1].measured.invokableByHaltPrincipal = true),
      /invokableByHaltPrincipal must be false/,
    ],
    ["an unhalt", (r) => (r.requirements[1].measured.oldWrapperUnhalt = true), /oldWrapperUnhalt must be false/],
    [
      "target gating left unanswered",
      (r) => (r.requirements[1].measured.targetMustPassEvidenceGates = true),
      /evidence-gate requirement/,
    ],
    ["TD1-N12 unanswered", (r) => (r.td1N12.answer = "UNKNOWN"), /answer on chain or by process/],
    ["TD1-N12 answered by neither", (r) => (r.td1N12.answer = "BY_GUESSWORK"), /answer on chain or by process/],
    ["TD1-N12 without its split", (r) => delete r.td1N12.byProcess, /byProcess must be a list/],
    [
      "the multisig rotation called authority-neutral",
      (r) => (r.authorizationCut[2].classification = "AUTHORITY_NEUTRAL"),
      /never authority-neutral/,
    ],
    [
      "the multisig rotation said not to widen",
      (r) => (r.authorizationCut[2].widensAuthorization = false),
      /never authority-neutral/,
    ],
    ["the multisig rotation unaccounted", (r) => r.authorizationCut.splice(2, 1), /must be accounted/],
    [
      "a halt principal with another power",
      (r) => r.authorizationCut[0].capabilities.push("PQ_VERIFIER_ROTATION"),
      /HALT alone/,
    ],
    ["a halt principal that widens", (r) => (r.authorizationCut[0].widensAuthorization = true), /HALT alone/],
    ["a changed halt scope", (r) => r.haltScope.applies.push("WalletWallMultiSigVault"), /TD2 changes no scope/],
    ["real value unblocked", (r) => (r.realValue.blocked = false), /real value stays blocked/],
    ["real value without blockers", (r) => (r.realValue.blockers = []), /real value stays blocked/],
    ["the SP1-P1 supersession unrecorded", (r) => (r.supersedes = []), /superseded through its supersession record/],
  ];
  for (const [label, mutate, rule] of cases) {
    it(`refuses ${label}`, function () {
      const r = clone(RECORD);
      mutate(r);
      expect(validateTd2Record(r, CTX).join(" | ")).to.match(rule);
    });
  }

  it("refuses a record the SP1-P1 supersession does not name", function () {
    const ctx: Td2RecordContext = {
      td1ReceiptBytes: TD1_BYTES,
      readText: (rel) =>
        rel === "evidence/zk/sp1-p1/supersession.json"
          ? JSON.stringify({ supersededBy: [{ record: "evidence/zk/sp1-td1/decision-receipt.json" }] })
          : readText(rel),
    };
    expect(validateTd2Record(clone(RECORD), ctx).join(" | ")).to.match(/which names this record/);
  });

  it("refuses something that is not a record", function () {
    for (const value of [null, 42, "a record", true]) {
      expect(validateTd2Record(value, CTX), String(value)).to.deep.equal(["the record is not an object"]);
    }
  });
});
