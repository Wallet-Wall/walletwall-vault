/**
 * The SP1-TD2 implementation record (evidence/zk/sp1-td2/implementation-record.json, scripts/lib/sp1-td2-record.ts):
 * it validates against SP1-TD1's receipt and the repository, and each rule refuses the departure it exists for —
 * re-deciding a frozen item, citing a test that does not exercise the proof, calling the multisig rotation
 * authority-neutral, admitting the multisig vault without the owner, or unblocking real value.
 *
 * Pure, static reads — no network, no chain.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  TD1_RECEIPT_REL,
  TD2_RECORD_REL,
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

  it("records both requirements built and tested, the multisig vault's admission left to the owner, and real value blocked", function () {
    expect(RECORD.requirements.map((r: { id: string; status: string }) => `${r.id}: ${r.status}`)).to.deep.equal([
      "TD2-COMMON-VERIFIER-HALT: BUILT_AND_TESTED",
      "TD2-MULTISIG-ROTATION: BUILT_AND_TESTED",
    ]);
    expect(RECORD.requirements[1].haltAdmission).to.equal("OWNER_DECISION_PENDING");
    expect(RECORD.td1N12.answer).to.equal("BY_PROCESS_WITH_ON_CHAIN_IDENTITY_AND_PRINCIPAL_CHECKS");
    expect(RECORD.realValue.blocked).to.equal(true);
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
    [
      "the multisig admitted without the owner",
      (r) => (r.requirements[1].haltAdmission = "ADMITTED"),
      /owner's decision, still pending/,
    ],
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
