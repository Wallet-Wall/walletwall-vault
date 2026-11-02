/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE MATRIX CANNOT LIE QUIETLY. Admission must not be obtained by relabelling UNPROVEN as PASS, so this resolves
 * every reference a row makes: a named test must exist in the named file, a named property must be one the campaign
 * really checks, a named mutant must be in a real catalogue, and a row with a residual must name one whose pinning
 * tests exist under a clause of the closed policy. The registered criteria are compared with the commit that
 * registered them, and every invariant the normative documents name must be named by a criterion. The verdict is
 * computed, and asserted to be what the record says.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  DISCLOSED_NARROWINGS,
  HAZARD_COVERAGE,
  MATRIX,
  OWNER_DECISIONS,
  POLICY_CLAUSES,
  RESIDUALS,
  deriveAdmissionVerdict,
  type MatrixRow,
  type OwnerDecision,
} from "../generation-2/admission-matrix.js";
import { executionProblems, readRunRecord, type RunRecord } from "../generation-2/run-record.js";
import { G2_PROPERTIES } from "../generation-2/stateful/invariants.js";
import { G2_MUTATIONS } from "../generation-2/stateful/mutants.js";
import { GLOBAL_INVARIANTS } from "../stateful/invariants.js";
import { DECLARED_CUTS } from "../stateful/model.js";
import { MUTATIONS } from "../stateful/mutants.js";

const ROOT = "prototype/vnext-kernel";
const TESTS = path.join(ROOT, "test");
const CRITERIA = path.join(ROOT, "generation-2", "ADMISSION_CRITERIA.json");
const DOC = path.join(ROOT, "GEN2_ADMISSION.md");
const REGISTERED_AT = "dbe06a68";
const NORMATIVE = [
  "docs/Vault_vNext_Architecture.md",
  "docs/Vault_vNext_Hazard_Register.md",
  "docs/Vault_vNext_Recovery_Amendment.md",
  "docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md",
  path.join(ROOT, "KERNEL_ADMISSION.md"),
  path.join(ROOT, "AUTHORITY.md"),
];

interface Criterion {
  id: string;
  tier: string;
  source: string;
  measuredVariantA: string;
  addedAfterRegistration?: string;
}

interface Criteria {
  description: string;
  residualPolicy: string;
  classificationVocabulary: string[];
  criteria: Criterion[];
}

/** The two heavy suites live outside the prototype's test path: see generation-2/README.md. */
const HEAVY = path.join(ROOT, "generation-2", "test");
const readTest = (file: string): string => {
  const dir = fs.readdirSync(TESTS).includes(file) ? TESTS : HEAVY;
  return fs.readFileSync(path.join(dir, file), "utf8");
};

describe("Generation-2 admission — the matrix", function () {
  const criteria = JSON.parse(fs.readFileSync(CRITERIA, "utf8")) as Criteria;
  const properties = new Set<string>([
    ...G2_PROPERTIES.map((p) => p.name),
    ...GLOBAL_INVARIANTS.map((g) => g.name),
    ...Object.keys(DECLARED_CUTS).map((o) => "P-CUT/" + o),
    "G-RECOVERY-COMMITMENT-BINDS",
    "P-MODEL",
    "P-INCOMING-POSSESSION",
    "P-PLANE-SUBTRACTIVE",
    "P-VACUITY",
  ]);
  const mutants = new Set<string>([...G2_MUTATIONS.map((m) => m.id), ...MUTATIONS.map((m) => m.id)]);

  describe("the bar", function () {
    it("the registered rows, the description and the residual policy are what the registering commit says; anything later is appended and marked", function () {
      let registered: Criteria;
      try {
        registered = JSON.parse(
          execFileSync("git", ["show", `${REGISTERED_AT}:${CRITERIA.split(path.sep).join("/")}`], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
          }),
        ) as Criteria;
      } catch {
        this.skip();
        return;
      }
      expect(criteria.criteria.slice(0, registered.criteria.length)).to.deep.equal(registered.criteria);
      expect(criteria.description).to.equal(registered.description);
      expect(criteria.residualPolicy).to.equal(registered.residualPolicy);
      for (const c of criteria.criteria.slice(registered.criteria.length))
        expect(c.addedAfterRegistration, `${c.id} was appended, unmarked`).to.be.a("string");
    });

    it("every invariant the normative documents name is named by a criterion", function () {
      const named = JSON.stringify(criteria.criteria);
      const missing = new Set<string>();
      for (const doc of NORMATIVE) {
        for (const m of fs.readFileSync(doc, "utf8").matchAll(/\bI-[A-Z0-9][A-Z0-9-]+/g))
          if (!named.includes(m[0])) missing.add(m[0]);
      }
      expect([...missing].sort()).to.deep.equal([]);
    });

    it("every T0 and T1 hazard in the register is answered by a row that exists", function () {
      const register = fs.readFileSync("docs/Vault_vNext_Hazard_Register.md", "utf8").split(/\r?\n/);
      const hazards: string[] = [];
      for (let i = 0; i < register.length; i++) {
        const head = /^## (H-\d+) /.exec(register[i]!);
        if (head && /Tier T[01]\b/.test(register[i + 2] ?? "")) hazards.push(head[1]!);
      }
      expect(hazards.length, "the parse found the register").to.be.greaterThan(20);
      expect(Object.keys(HAZARD_COVERAGE).sort()).to.deep.equal([...hazards].sort());
      for (const [id, entry] of Object.entries(HAZARD_COVERAGE)) {
        for (const row of entry.rows) expect(MATRIX[row], `${id} names ${row}`).to.not.equal(undefined);
        expect(entry.note.length, id).to.be.greaterThan(10);
      }
    });

    it("every criterion has a row, and no row exists without a criterion", function () {
      expect(Object.keys(MATRIX).sort()).to.deep.equal(criteria.criteria.map((c) => c.id).sort());
    });
  });

  describe("the rows", function () {
    it("every classification is in the vocabulary", function () {
      for (const [id, row] of Object.entries(MATRIX))
        expect(criteria.classificationVocabulary, id).to.include(row.classification);
    });

    it("no row is still UNPROVEN, and only NOT_APPLICABLE may name no executable evidence", function () {
      for (const [id, row] of Object.entries(MATRIX)) {
        expect(row.classification, `${id} is still UNPROVEN`).to.not.equal("UNPROVEN");
        const e = row.evidence;
        const pointers =
          (e.tests?.length ?? 0) + (e.properties?.length ?? 0) + (e.mutants?.length ?? 0) + (e.receipts?.length ?? 0);
        if (row.classification === "NOT_APPLICABLE") expect(pointers, id).to.equal(0);
        else expect(e.tests?.length ?? 0, `${id} names no test`).to.be.greaterThan(0);
      }
    });

    it("a row FAIL on measured Variant A either names the admission delta that moved it, or still fails and names who decides", function () {
      const failedOnA = criteria.criteria
        .filter((c) => c.measuredVariantA === "FAIL")
        .map((c) => c.id)
        .sort();
      expect(failedOnA).to.deep.equal([
        "G2-SEM-KERNEL",
        "K-12-SCOPE",
        "K-12-TIME",
        "K-12-VETO",
        "K-13-DEAD-BINDING",
        "K-13-NONFUNGIBLE",
        "K-13-SETTLE",
        "K-6-ATTESTATION",
        "K-GENERATION",
        "K-RETIRE",
        "K-SECURITY-PROFILE",
      ]);
      const withDelta = Object.entries(MATRIX)
        .filter(([, r]) => r.admissionDelta !== undefined)
        .map(([id]) => id)
        .sort();
      expect(withDelta).to.deep.equal([
        "G2-SEM-KERNEL",
        "K-12-SCOPE",
        "K-12-TIME",
        "K-13-DEAD-BINDING",
        "K-13-SETTLE",
        "K-6-ATTESTATION",
        "K-GENERATION",
      ]);
      for (const id of withDelta) expect(MATRIX[id]!.classification, id).to.equal("PASS");
    });

    it("every row that fails names the decision that answers it, the decision blocks, and no other row names one", function () {
      const blocking = new Set(OWNER_DECISIONS.filter((d) => d.blocksAdmission).map((d) => d.id));
      const failing = Object.entries(MATRIX).filter(([, r]) => r.classification === "FAIL");
      expect(failing.map(([id]) => id).sort()).to.deep.equal([
        "K-12-VETO",
        "K-13",
        "K-13-NONFUNGIBLE",
        "K-7",
        "K-RETIRE",
        "K-SECURITY-PROFILE",
      ]);
      for (const [id, row] of failing)
        expect(blocking.has(row.blockedOnDecision ?? ""), `${id} names ${row.blockedOnDecision}`).to.equal(true);
      for (const [id, row] of Object.entries(MATRIX))
        if (row.classification !== "FAIL") expect(row.blockedOnDecision, id).to.equal(undefined);
      expect([...blocking].sort(), "and every blocking decision answers a row").to.deep.equal(
        [...new Set(failing.map(([, r]) => r.blockedOnDecision!))].sort(),
      );
    });

    it("every test a row names exists, by title, in the file it names", function () {
      for (const [id, row] of Object.entries(MATRIX)) {
        for (const [file, title] of row.evidence.tests ?? []) {
          expect(readTest(file).includes(title), `${id}: "${title}" is not in ${file}`).to.equal(true);
        }
      }
    });

    it("every property a row names is one the campaign really checks", function () {
      for (const [id, row] of Object.entries(MATRIX))
        for (const p of row.evidence.properties ?? []) expect(properties.has(p), `${id}: ${p}`).to.equal(true);
    });

    it("every mutant a row names is in a real catalogue", function () {
      for (const [id, row] of Object.entries(MATRIX))
        for (const m of row.evidence.mutants ?? []) expect(mutants.has(m), `${id}: ${m}`).to.equal(true);
    });
  });

  describe("the residuals", function () {
    it("the closed list is the policy's own words, verbatim", function () {
      for (const clause of POLICY_CLAUSES) expect(criteria.residualPolicy, clause).to.include(clause);
    });

    it("every residual stands under a clause of that list, is named by a row and is pinned by a test that exists", function () {
      const ids = new Set(RESIDUALS.map((r) => r.id));
      const used = new Set<string>();
      for (const [id, row] of Object.entries(MATRIX)) {
        const rs = row.residuals ?? [];
        expect(rs.length > 0, `${id}: PASS_WITH_DECLARED_RESIDUAL exactly when a residual is named`).to.equal(
          row.classification === "PASS_WITH_DECLARED_RESIDUAL",
        );
        for (const r of rs) {
          expect(ids.has(r), `${id}: ${r}`).to.equal(true);
          used.add(r);
        }
      }
      const clauses: readonly string[] = POLICY_CLAUSES;
      for (const r of RESIDUALS) {
        expect(used.has(r.id), `${r.id} is named by no row`).to.equal(true);
        expect(clauses.includes(r.policyClause), `${r.id} invents a clause: ${r.policyClause}`).to.equal(true);
        expect(r.pinnedBy.length, r.id).to.be.greaterThan(0);
        for (const [file, title] of r.pinnedBy)
          expect(readTest(file).includes(title), `${r.id}: "${title}" is not in ${file}`).to.equal(true);
      }
    });

    it("a T0 row carrying a residual says why the invariant itself still holds, and only such a row does", function () {
      const tier = new Map(criteria.criteria.map((c) => [c.id, c.tier]));
      for (const [id, row] of Object.entries(MATRIX)) {
        const needed = tier.get(id) === "T0" && row.classification === "PASS_WITH_DECLARED_RESIDUAL";
        if (needed)
          expect(row.whyTheT0Holds, `${id}: a T0 failing on a reachable state is not a residual`).to.be.a("string");
        else expect(row.whyTheT0Holds, id).to.equal(undefined);
      }
    });

    it("every disclosed narrowing is pinned by a test that exists, says what it is against, and no row rests on one", function () {
      const residualIds = new Set(RESIDUALS.map((r) => r.id));
      for (const n of DISCLOSED_NARROWINGS) {
        expect(residualIds.has(n.id), n.id).to.equal(false);
        expect(n.against.length, n.id).to.be.greaterThan(10);
        for (const [file, title] of n.pinnedBy)
          expect(readTest(file).includes(title), `${n.id}: "${title}" is not in ${file}`).to.equal(true);
        for (const [id, row] of Object.entries(MATRIX)) expect(row.residuals ?? [], id).to.not.include(n.id);
      }
    });

    it("every owner decision a residual names exists, and the table has the brief's six plus what this lane found", function () {
      const ids = new Set(OWNER_DECISIONS.map((d) => d.id));
      for (const r of RESIDUALS) if (r.ownerDecision) expect(ids.has(r.ownerDecision), r.id).to.equal(true);
      for (const id of [
        "10.1",
        "10.2",
        "10.3",
        "10.4",
        "10.5",
        "10.6",
        "OD-BINDING-LIFETIME",
        "OD-NONFUNGIBLE-EXIT",
        "OD-RECOVERY-LOCALITY",
        "OD-SECURITY-PROFILE",
        "OD-EGRESS-DELAY",
        "OD-DEAD-BINDING",
        "OD-ROOT",
      ])
        expect(ids.has(id), id).to.equal(true);
    });
  });

  describe("what ran", function () {
    const ran = readRunRecord();

    it("the record covers both catalogues, mutant for mutant, and the campaign's positive controls", function () {
      expect(ran.generation2Catalogue?.map((r) => r.id)).to.deep.equal(G2_MUTATIONS.map((m) => m.id));
      expect(ran.generation1Catalogue?.map((r) => r.id)).to.deep.equal(MUTATIONS.map((m) => m.id));
      expect(executionProblems(ran)).to.deep.equal([]);
    });

    it("each kill in the Generation-2 catalogue is by the property the catalogue names", function () {
      for (const m of G2_MUTATIONS)
        expect(ran.generation2Catalogue?.find((r) => r.id === m.id)?.property, m.id).to.equal(m.expectedProperty);
    });

    it("a record showing a violation, a failed control, a survivor or nothing at all stops the suites supporting admission", function () {
      const clean = (): RunRecord => JSON.parse(JSON.stringify(ran)) as RunRecord;
      const violated = clean();
      violated.campaign!.violations = 1;
      expect(executionProblems(violated).length).to.equal(1);
      const control = clean();
      control.campaign!.positiveControls = "1/2";
      expect(executionProblems(control).length).to.equal(1);
      const survivor = clean();
      survivor.generation2Catalogue![0]!.verdict = "SURVIVED";
      expect(executionProblems(survivor).length).to.equal(1);
      const nothing: RunRecord = { _note: "", campaign: null, generation2Catalogue: null, generation1Catalogue: null };
      expect(executionProblems(nothing).length).to.equal(3);
    });
  });

  describe("the verdict is derived, and can come out otherwise", function () {
    const pass: MatrixRow = { classification: "PASS", note: "", evidence: {} };
    const residual: MatrixRow = {
      classification: "PASS_WITH_DECLARED_RESIDUAL",
      note: "",
      evidence: {},
      residuals: ["R"],
    };
    const decision: OwnerDecision = {
      id: "x",
      decision: "",
      previousState: "",
      measurementEvidence: "",
      admissionEvidence: "",
      recommendation: "",
      ownerDecisionRequired: true,
      blocksAdmission: false,
    };
    const blocking: OwnerDecision = { ...decision, id: "y", blocksAdmission: true };

    it("all four verdicts are reachable from the same function", function () {
      expect(deriveAdmissionVerdict([pass], [decision], [])).to.equal("GEN2_ADMITTED");
      expect(deriveAdmissionVerdict([pass, residual], [decision], [])).to.equal(
        "GEN2_ADMITTED_WITH_DECLARED_RESIDUALS",
      );
      expect(deriveAdmissionVerdict([pass, { ...pass, classification: "FAIL" }], [decision], [])).to.equal(
        "GEN2_NOT_ADMITTED",
      );
      expect(deriveAdmissionVerdict([pass, { ...pass, classification: "UNPROVEN" }], [decision], [])).to.equal(
        "GEN2_NOT_ADMITTED",
      );
      expect(deriveAdmissionVerdict([pass, residual], [blocking], [])).to.equal("GEN2_ADMISSION_BLOCKED");
      expect(
        deriveAdmissionVerdict([pass, { ...pass, classification: "FAIL", blockedOnDecision: "y" }], [blocking], []),
      ).to.equal("GEN2_ADMISSION_BLOCKED");
    });

    it("a decision cannot excuse what it does not answer, and a row cannot excuse itself", function () {
      expect(
        deriveAdmissionVerdict([{ ...pass, classification: "FAIL", blockedOnDecision: "x" }], [decision, blocking], []),
        "that decision does not block",
      ).to.equal("GEN2_NOT_ADMITTED");
      expect(
        deriveAdmissionVerdict([{ ...pass, classification: "FAIL", blockedOnDecision: "nobody" }], [blocking], []),
        "no such decision",
      ).to.equal("GEN2_NOT_ADMITTED");
      expect(
        deriveAdmissionVerdict(
          [
            { ...pass, classification: "FAIL" },
            { ...pass, classification: "FAIL", blockedOnDecision: "y" },
          ],
          [blocking],
          [],
        ),
        "one unblocked FAIL settles it",
      ).to.equal("GEN2_NOT_ADMITTED");
    });

    it("suites that did not come out clean outweigh any row", function () {
      expect(deriveAdmissionVerdict([pass], [decision], ["a violation"])).to.equal("GEN2_NOT_ADMITTED");
      expect(deriveAdmissionVerdict([pass, residual], [blocking], ["a violation"])).to.equal("GEN2_NOT_ADMITTED");
    });

    it("on the real matrix it is GEN2_ADMISSION_BLOCKED, on the four decisions named", function () {
      expect(
        deriveAdmissionVerdict(Object.values(MATRIX), OWNER_DECISIONS, executionProblems(readRunRecord())),
      ).to.equal("GEN2_ADMISSION_BLOCKED");
      expect(
        OWNER_DECISIONS.filter((d) => d.blocksAdmission)
          .map((d) => d.id)
          .sort(),
      ).to.deep.equal(["OD-BINDING-LIFETIME", "OD-NONFUNGIBLE-EXIT", "OD-RECOVERY-LOCALITY", "OD-SECURITY-PROFILE"]);
    });

    it("IF amended text made every blocked row pass, nothing else in this matrix stands between these bytes and an admission with residuals. A hypothetical over the function: the amended rows are not written here", function () {
      const amended = Object.values(MATRIX).map((r) =>
        r.classification === "FAIL" ? { ...r, classification: "PASS" as const, blockedOnDecision: undefined } : r,
      );
      const answered = OWNER_DECISIONS.map((d) => ({ ...d, blocksAdmission: false }));
      expect(deriveAdmissionVerdict(amended, answered, [])).to.equal("GEN2_ADMITTED_WITH_DECLARED_RESIDUALS");
    });
  });

  describe("the admission document", function () {
    const doc = fs.readFileSync(DOC, "utf8");

    it("carries the fifteen sections the brief requires", function () {
      for (const heading of [
        "exact candidate identity",
        "Variant A decision",
        "asset-binding model",
        "authority census",
        "stateful authority result",
        "mutation adequacy",
        "ERC-20 semantic assumptions",
        "reentrancy result",
        "migration and egress result",
        "scanner and static-analysis result",
        "runtime and gas measurements",
        "provenance",
        "existing residual defects",
        "unresolved owner decisions",
        "what admission does NOT establish",
      ]) {
        expect(doc.toLowerCase().includes(heading.toLowerCase()), heading).to.equal(true);
      }
    });

    it("its verdict is the derived one, exactly one, states the two separate gates, and keeps the neutral legal gates", function () {
      const stated = /## Verdict\s+```text\s+(\S+)\s+```/.exec(doc.split("\r\n").join("\n"));
      expect(stated?.[1]).to.equal(
        deriveAdmissionVerdict(Object.values(MATRIX), OWNER_DECISIONS, executionProblems(readRunRecord())),
      );
      expect(doc).to.include("PRODUCTION_BASE_USDC = NOT_ADMITTED");
      expect(doc).to.include("MAINNET_REAL_FUNDS = NOT_APPROVED");
      expect(doc).to.include("NOT_APPROVED_FOR_MAINNET_REAL_FUNDS");
      for (const gate of [
        "LEGAL_REVIEW_REQUIRED",
        "SANCTIONS_CONTROL_REVIEW_REQUIRED",
        "PAYMENTS_PROVIDER_APPROVAL_REQUIRED_IF_APPLICABLE",
      ])
        expect(doc).to.include(gate);
    });

    it("every row, residual, narrowing and decision appears in it, and it names no real token address", function () {
      for (const id of Object.keys(MATRIX)) expect(doc.includes(id), id).to.equal(true);
      for (const r of RESIDUALS) expect(doc.includes(r.id), r.id).to.equal(true);
      for (const n of DISCLOSED_NARROWINGS) expect(doc.includes(n.id), n.id).to.equal(true);
      for (const d of OWNER_DECISIONS) expect(doc.includes(d.id), d.id).to.equal(true);
      expect(doc.match(/0x[0-9a-fA-F]{40}\b/g) ?? []).to.deep.equal([]);
    });

    it("the asset-admission checklist names every semantic the kernel cannot observe, and admits no token", function () {
      for (const item of [
        "Code identity",
        "Chain",
        "Proxy and upgrade structure",
        "Issuer controls",
        "Freeze and blocklist semantics",
        "Transfer semantics",
        "Decimals",
        "Balance behaviour",
        "Return and revert behaviour",
        "Fee behaviour",
        "Rebase behaviour",
        "Known callback behaviour",
        "Administrative upgrade risk",
      ]) {
        expect(doc.includes(item), item).to.equal(true);
      }
    });
  });
});
