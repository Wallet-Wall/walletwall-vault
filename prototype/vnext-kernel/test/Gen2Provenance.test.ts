/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * EVIDENCE CURRENCY: row PROVENANCE. A receipt names the commit it is about, never the commit containing it, and it
 * is current only while the inputs it measured are byte-equal. Ancestry and equal counts are worth nothing here:
 * this repository has already watched both hold across a drift that moved 21 of 33 findings. So each check compares
 * bytes or recomputes the claim. The Generation-1 subject is untouched: EvidenceSubjectProvenance.test.ts still
 * guards contracts/ and stateful/, and the last test here shows this lane did not move what it guards.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

import {
  ADMISSION_EVIDENCE_PATH,
  CRITERIA_PATH,
  GAS_RECORD_PATH,
  SCANNER_EVIDENCE_PATH,
  SIDE_RECEIPTS,
  STATEFUL_EVIDENCE_PATH,
  evidenceRoot,
  inputDigests,
  planned,
} from "../generation-2/generate-evidence.js";
import { CENSUS_PATH } from "../generation-2/authority/census.js";
import { candidateIdentity } from "../generation-2/identity.js";
import {
  DISCLOSED_NARROWINGS,
  MATRIX,
  OWNER_DECISIONS,
  RESIDUALS,
  deriveAdmissionVerdict,
} from "../generation-2/admission-matrix.js";
import { executionProblems, readRunRecord } from "../generation-2/run-record.js";
import { G2_MUTATIONS } from "../generation-2/stateful/mutants.js";
import { G2_PROFILES } from "../generation-2/stateful/profiles.js";
import { MUTATIONS } from "../stateful/mutants.js";

const RECEIPTS = [ADMISSION_EVIDENCE_PATH, STATEFUL_EVIDENCE_PATH, SCANNER_EVIDENCE_PATH, CENSUS_PATH];
const lf = (s: string): string => s.split("\r\n").join("\n");

interface AdmissionEvidence {
  evidenceSubject: { head: string; tree: string };
  subjectInputs: Record<string, string>;
  verdict: string;
  evidenceRoot: string;
  separately: Record<string, string>;
  neutralGates: string[];
  identity: unknown;
  gas: Record<string, number>;
  matrix: { id: string; measuredOnCandidate: string }[];
  matrixSummary: Record<string, number>;
  residuals: unknown[];
  disclosedNarrowings: unknown[];
  ownerDecisions: unknown[];
  executionProblems: string[];
}

interface StatefulEvidence {
  evidenceSubject: { head: string; tree: string };
  campaigns: { plannedCampaigns: number; plannedTransitions: number; profiles: unknown[] };
  executed: unknown;
  mutationAdequacy: {
    generation2: unknown[];
    generation1OnTheCandidate: unknown[];
    results: { generation2: unknown; generation1OnTheCandidate: unknown };
  };
}

const read = <T>(file: string): T => JSON.parse(lf(fs.readFileSync(file, "utf8"))) as T;

describe("Generation-2 admission — evidence currency and provenance", function () {
  this.timeout(180_000);

  describe("the receipts", function () {
    it("every receipt names one subject, a full commit and tree, and they all name the same one", function () {
      const subjects = RECEIPTS.map(
        (r) => read<{ evidenceSubject: { head: string; tree: string } }>(r).evidenceSubject,
      );
      for (const s of subjects) {
        expect(s.head).to.match(/^[0-9a-f]{40}$/);
        expect(s.tree).to.match(/^[0-9a-f]{40}$/);
      }
      expect(new Set(subjects.map((s) => s.head)).size).to.equal(1);
    });

    it("no receipt carries a timestamp, a machine path or a container", function () {
      for (const r of RECEIPTS) {
        const text = fs.readFileSync(r, "utf8");
        expect(text, r).to.not.match(/C:\\\\|\/mnt\/|\/home\/|\/root\/|filename_absolute/);
        expect(text, r).to.not.match(/"(generatedAt|timestamp|date|container|containerHead|builtAt)"\s*:/i);
        expect(text, r).to.not.match(/\b20\d\d-\d\d-\d\dT\d\d:/);
      }
    });

    it("the subject is really the commit whose tree it names, when this checkout can resolve it", function () {
      const { evidenceSubject: s } = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      let tree: string;
      try {
        tree = execFileSync("git", ["rev-parse", `${s.head}^{tree}`], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim();
      } catch {
        this.skip();
        return;
      }
      expect(tree).to.equal(s.tree);
    });
  });

  describe("currency is byte equality of what was measured", function () {
    it("every input the admission record digested is byte-equal to the tree, and none was added or removed", function () {
      const { subjectInputs } = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      expect(subjectInputs, "regenerate: commit, then generate-evidence.ts --subject <commit>").to.deep.equal(
        inputDigests(),
      );
    });

    it("the digests cover the candidate, the fixture, the harness and the matrix", function () {
      const { subjectInputs } = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      for (const part of [
        "contracts/VaultKernelGen2Prototype.sol",
        "contracts/VaultKernelGen2FactoryPrototype.sol",
        "contracts/Gen2TokenZoo.sol",
        "stateful/campaign.ts",
        "stateful/mutants.ts",
        "admission-matrix.ts",
        "authority/gen2-authority-manifest.json",
        "ADMISSION_CRITERIA.json",
        "scanner-run.json",
        "GEN2_RUN_RECORD.json",
        "test/Gen2StatefulCampaign.test.ts",
        "test/Gen2MutationAdequacy.test.ts",
      ]) {
        expect(
          Object.keys(subjectInputs).some((p) => p.endsWith(part)),
          part,
        ).to.equal(true);
      }
    });
  });

  describe("every claim recomputes", function () {
    it("the identity in the evidence is what the source compiles to, with the pinned compiler", function () {
      expect(read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH).identity).to.deep.equal(
        JSON.parse(JSON.stringify(candidateIdentity())),
      );
    });

    it("two identities from one tree are byte-identical: nothing in it reads the clock or the machine", function () {
      expect(JSON.stringify(candidateIdentity())).to.equal(JSON.stringify(candidateIdentity()));
    });

    it("the evidence root recomputes: a change to the identity, any input or any receipt moves it", function () {
      const e = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      const { root, members } = evidenceRoot(e.identity, e.subjectInputs, SIDE_RECEIPTS);
      expect(e.evidenceRoot).to.equal(root);
      expect(Object.keys(members).length, "identity + inputs + three receipts").to.equal(
        Object.keys(e.subjectInputs).length + 4,
      );
      const tampered = evidenceRoot(
        e.identity,
        { ...e.subjectInputs, [Object.keys(e.subjectInputs)[0]!]: "0".repeat(64) },
        SIDE_RECEIPTS,
      );
      expect(tampered.root, "the root has teeth").to.not.equal(root);
    });

    it("the verdict in the record is the one the matrix derives", function () {
      const e = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      expect(e.executionProblems).to.deep.equal(executionProblems(readRunRecord()));
      expect(e.verdict).to.equal(deriveAdmissionVerdict(Object.values(MATRIX), OWNER_DECISIONS, e.executionProblems));
      expect(e.separately).to.deep.equal({ PRODUCTION_BASE_USDC: "NOT_ADMITTED", MAINNET_REAL_FUNDS: "NOT_APPROVED" });
      expect(e.neutralGates).to.deep.equal([
        "LEGAL_REVIEW_REQUIRED",
        "SANCTIONS_CONTROL_REVIEW_REQUIRED",
        "PAYMENTS_PROVIDER_APPROVAL_REQUIRED_IF_APPLICABLE",
      ]);
    });

    it("the matrix in the record is the matrix, row for row", function () {
      const e = read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH);
      const criteria = read<{ criteria: { id: string }[] }>(CRITERIA_PATH).criteria;
      expect(e.matrix.map((r) => r.id)).to.deep.equal(criteria.map((c) => c.id));
      for (const r of e.matrix) expect(r.measuredOnCandidate, r.id).to.equal(MATRIX[r.id]!.classification);
      expect(e.residuals.length).to.equal(RESIDUALS.length);
      expect(e.disclosedNarrowings.length).to.equal(DISCLOSED_NARROWINGS.length);
      expect(e.ownerDecisions.length).to.equal(OWNER_DECISIONS.length);
    });

    it("the stateful receipt describes the matrix that runs, and reports what the committed record says happened", function () {
      const e = read<StatefulEvidence>(STATEFUL_EVIDENCE_PATH);
      const p = planned();
      expect(e.campaigns.plannedCampaigns).to.equal(p.campaigns);
      expect(e.campaigns.plannedTransitions).to.equal(p.transitions);
      const ran = readRunRecord();
      expect(e.executed).to.deep.equal(ran.campaign);
      expect(e.mutationAdequacy.results.generation2).to.deep.equal(ran.generation2Catalogue);
      expect(e.mutationAdequacy.results.generation1OnTheCandidate).to.deep.equal(ran.generation1Catalogue);
      expect(ran.campaign!.campaigns, "every planned campaign ran").to.equal(p.campaigns);
      expect(ran.campaign!.transitions, "every planned transition ran").to.equal(p.transitions);
      expect(e.campaigns.profiles.length).to.equal(G2_PROFILES.length);
      expect(e.mutationAdequacy.generation2.length).to.equal(G2_MUTATIONS.length);
      expect(e.mutationAdequacy.generation1OnTheCandidate.length).to.equal(MUTATIONS.length);
    });

    it("the gas in the record is the record the measurement suite asserts", function () {
      expect(read<AdmissionEvidence>(ADMISSION_EVIDENCE_PATH).gas).to.deep.equal(
        read<{ gas: Record<string, number> }>(GAS_RECORD_PATH).gas,
      );
    });
  });

  describe("this lane moved nothing it does not own", function () {
    it("Generation 1's evidence subject, the measured plane and the authority tooling are byte-identical to the base", function () {
      const base = "c9c13ea21566117421250ee216322594a5e05551";
      let changed: string;
      try {
        changed = execFileSync(
          "git",
          [
            "diff",
            "--name-only",
            base,
            "--",
            "prototype/vnext-kernel/contracts",
            "prototype/vnext-kernel/stateful",
            "prototype/vnext-kernel/erc20-spend-plane",
            "prototype/vnext-kernel/authority",
          ],
          { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
        ).trim();
      } catch {
        this.skip();
        return;
      }
      expect(changed).to.equal("");
    });
  });
});
