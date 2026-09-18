/**
 * GITHUB SARIF PROJECTION — presentation derived from the raw scan, never authority over it.
 *
 * `scanner-sarif-projection.ts` decides which Slither results GitHub code scanning shows. It must not
 * be able to hide a project-owned finding, invent one, merge two, or make the triage gate pass. This
 * suite proves each of those against the REAL frozen-source scan (17d55934, 295 results), stored as
 * a trimmed fixture whose fidelity is itself proven first: the test rebuilds Slither's SARIF from the
 * fixture byte-for-byte, and the UNMODIFIED triage validator accepts the fixture's raw scan with the
 * same census it gave the real one.
 *
 *   A. fixture fidelity           B. 295 -> 42 and the 42 <-> 42 triage bijection
 *   C. required mutations 1-12    D. further adversarial shapes
 *   E. CLI fail-closed behaviour  F. workflow wiring: only the projection reaches code scanning
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { indexFindings, isOwnFinding, semanticId, type SlitherFinding } from "../scanner-finding-identity.js";
import {
  PROJECTED_SARIF_PATH,
  RAW_SARIF_PATH,
  VERSION_LINT_DETECTORS,
  WORKFLOW_PATH,
  ProjectionError,
  assertProjectionIsSubset,
  assertTriageBijection,
  assertWorkflowSarifProjectionContract,
  classifyOwnership,
  loadTriageIdentities,
  main,
  parseRawSarif,
  projectSarif,
  type FailureCode,
  type Projection,
  type SarifLog,
  type SarifResult,
} from "../scanner-sarif-projection.js";
import { assertWorkflowMatchesPinnedConfig, assertWorkflowOutputContract } from "../scanner-workflow-config.js";

const DIR = path.join("prototype", "vnext-kernel");
const BASELINE = path.join(DIR, "test", "fixtures", "scanner", "projection-baseline.17d55934.json");
const TRIAGE = path.join(DIR, "slither-triage.json");
const RECEIPT = path.join(DIR, "SCANNER_EVIDENCE.json");

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- raw Slither JSON is mutated freely in these tests
type F = Record<string, any>;
interface PackedParent {
  type: string;
  name: string;
  parent?: PackedParent;
}
interface PackedElement {
  type: string;
  name: string;
  file: string;
  lines: string | number[];
  signature?: string;
  parent?: PackedParent;
}

// ------------------------------------------------------------------------------------------------
// Fixture expansion. A contiguous line array is stored as "first-last"; everything else verbatim.
// ------------------------------------------------------------------------------------------------
const unpackLines = (l: string | number[]): number[] => {
  if (Array.isArray(l)) return l;
  const [a, b] = l.split("-").map(Number);
  return Array.from({ length: b - a + 1 }, (_, i) => a + i);
};
const unpackParent = (p?: PackedParent): F | undefined =>
  p
    ? { type: p.type, name: p.name, ...(p.parent ? { type_specific_fields: { parent: unpackParent(p.parent) } } : {}) }
    : undefined;
const unpackElement = (e: PackedElement): F => ({
  type: e.type,
  name: e.name,
  source_mapping: { filename_relative: e.file, lines: unpackLines(e.lines) },
  ...(e.signature || e.parent
    ? {
        type_specific_fields: {
          ...(e.parent ? { parent: unpackParent(e.parent) } : {}),
          ...(e.signature ? { signature: e.signature } : {}),
        },
      }
    : {}),
});

const packed = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
const HEADER: SarifLog = packed.sarifHeader;
const EXPECTED = packed.provenance.expected;
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
/** A fresh copy of the 295 baseline findings, in Slither's emission order. */
const baseline = (): F[] =>
  (packed.order as number[]).map((i) => {
    const b = packed.bodies[i];
    return { ...clone(b), elements: b.elements.map(unpackElement) };
  });

const RULE_BY_CHECK = new Map<string, string>(HEADER.runs[0].tool.driver.rules.map((r) => [r.name, r.id]));
/** Slither's SARIF writer, as measured: result i is derived from JSON finding i, primary element only. */
const toResult = (f: F): SarifResult => {
  const sm = f.elements[0].source_mapping;
  return {
    ruleId: RULE_BY_CHECK.get(f.check) as string,
    message: { text: f.description, markdown: f.markdown },
    level: "warning",
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: sm.filename_relative },
          region: { startLine: sm.lines[0], endLine: sm.lines[sm.lines.length - 1] },
        },
      },
    ],
    partialFingerprints: { id: f.id },
  };
};
const scanText = (findings: F[]) => JSON.stringify({ success: true, error: null, results: { detectors: findings } });
const sarifText = (results: SarifResult[], header: SarifLog = HEADER) =>
  JSON.stringify({ ...header, runs: [{ ...header.runs[0], results }] }, null, 2);
const project = (findings: F[], results: SarifResult[] = findings.map(toResult)): Projection =>
  projectSarif(scanText(findings), sarifText(results));

function expectFailure(fn: () => unknown, code: FailureCode): ProjectionError {
  try {
    fn();
  } catch (e) {
    expect(e, `expected a ProjectionError ${code}, got ${String(e)}`).to.be.instanceOf(ProjectionError);
    expect((e as ProjectionError).code, (e as Error).message).to.equal(code);
    return e as ProjectionError;
  }
  expect.fail(`expected ${code}, but the projection succeeded`);
  throw new Error("unreachable");
}

const TRIAGE_IDS = loadTriageIdentities(fs.readFileSync(TRIAGE, "utf8"));
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const ownOf = (fs_: F[]) => fs_.filter((f) => isOwnFinding(f as SlitherFinding));
function groupsById(fs_: F[]): Map<string, F[]> {
  const m = new Map<string, F[]>();
  for (const f of ownOf(fs_)) {
    const k = semanticId(f as SlitherFinding);
    (m.get(k) || m.set(k, []).get(k)!).push(f);
  }
  return m;
}
const B = baseline();
const GROUPS = groupsById(B);
/** An own identity reported twice (a compilation-unit copy exists) and one reported once, with >= 2 elements. */
const DOUBLED = [...GROUPS.entries()].find(([, g]) => g.length === 2)![0];
const SINGLE = [...GROUPS.entries()].find(([, g]) => g.length === 1 && g[0].elements.length >= 2)![0];
const firstOf = (fs_: F[], id: string) =>
  fs_.findIndex((f) => isOwnFinding(f as SlitherFinding) && semanticId(f as SlitherFinding) === id);

/** Runs the UNMODIFIED triage gate (generate-scanner-evidence.ts --validate) exactly as CI does. */
function runValidator(findings: F[], extra: string[] = []): { status: number | null; out: string } {
  const receipt = JSON.parse(fs.readFileSync(RECEIPT, "utf8"));
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "proj-raw-")), "slither-raw.json");
  fs.writeFileSync(tmp, scanText(findings));
  const r = spawnSync(
    process.execPath,
    [
      path.join("node_modules", "tsx", "dist", "cli.mjs"),
      path.join(DIR, "generate-scanner-evidence.ts"),
      "--raw",
      tmp,
      "--source-subject",
      receipt.sourceSubject,
      "--triage-subject",
      receipt.triageSubject,
      "--validate",
      ...extra,
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}

describe("GitHub SARIF projection of the vNext Slither run", () => {
  describe("A. the frozen-source fixture is proven faithful, not assumed", () => {
    it("rebuilds Slither's own raw SARIF byte-for-byte (sha256 recorded from the real run)", () => {
      expect(sha256(sarifText(B.map(toResult)))).to.equal(packed.provenance.rawSarifSha256);
    });

    it("carries the real scan: 295 results, on the frozen source commit and contracts tree", () => {
      expect(B).to.have.length(EXPECTED.rawScanFindings);
      expect(packed.provenance.sourceCommit).to.equal("17d5593447d62ba6206642b716c73bd6ce25223f");
      expect(packed.provenance.contractsTree).to.equal("50b9484887c8399f843f3482d530a93eee008980");
    });

    it("the UNMODIFIED triage validator gives the fixture the same census it gave the real scan", function () {
      this.timeout(180_000);
      const r = runValidator(B);
      expect(r.status, r.out).to.equal(0);
      expect(r.out).to.contain("295 raw finding(s), 68 own-code raw row(s), 42 distinct own-code finding(s)");
      expect(r.out).to.contain("0 untriaged, 0 stale, 0 ambiguous");
    });
  });

  describe("B. 295 -> 42, and a bijection with the 42 triaged identities", () => {
    let P: Projection;
    before(() => {
      P = project(baseline());
    });

    it("counts: 295 raw = 68 own (42 distinct + 26 copies) + 222 dependency-only + 5 dependency-anchored version lints", () => {
      expect(P.counts).to.deep.equal(EXPECTED);
      expect(
        P.counts.ownInstances + P.counts.dependencyOnlyInstances + P.counts.mixedDependencyPrimaryExcludedInstances,
      ).to.equal(P.counts.rawSarifResults);
    });

    it("BIJECTION: every triaged identity projects to exactly one result, and nothing else is projected", () => {
      const b = assertTriageBijection(P.projected, TRIAGE_IDS);
      expect(b).to.deep.equal({ triageEntries: 42, projected: 42, matched: 42, missing: [], extra: [] });
      expect(new Set(P.projected.map((p) => p.semanticId)).size).to.equal(42);
      expect(P.log.runs[0].results).to.have.length(42);
    });

    it("the projected set is the triage machinery's own set, computed independently by indexFindings", () => {
      const { byId, ambiguities, ownRawCount } = indexFindings(B as SlitherFinding[], () => []);
      expect(ambiguities).to.deep.equal([]);
      expect(ownRawCount).to.equal(P.counts.ownInstances);
      expect([...byId.keys()].sort()).to.deep.equal(P.projected.map((p) => p.semanticId).sort());
    });

    it("ownership agrees with isOwnFinding on all 295, and no projected result is located in node_modules", () => {
      for (const f of B)
        expect(classifyOwnership(f as SlitherFinding) === "OWN").to.equal(isOwnFinding(f as SlitherFinding));
      for (const r of P.log.runs[0].results) {
        expect(r.locations[0].physicalLocation.artifactLocation.uri.split("/")).to.not.include("node_modules");
      }
    });

    it("EXACTLY TWO TRANSFORMATIONS: every other SARIF byte is carried, results are an in-order byte-identical subset", () => {
      const raw = parseRawSarif(sarifText(B.map(toResult)));
      expect(() => assertProjectionIsSubset(raw, P.log)).to.not.throw();
      expect({ ...P.log, runs: [{ ...P.log.runs[0], results: [] }] }).to.deep.equal(HEADER);
    });

    it("the 5 exclusions are exactly the dependency-anchored version lints, each referencing project pragmas only", () => {
      expect(P.excludedMixed).to.have.length(5);
      for (const x of P.excludedMixed) {
        expect(VERSION_LINT_DETECTORS).to.include(x.check);
        expect(x.primary.split("/")).to.include("node_modules");
        expect(x.projectElements.every((e) => e.type === "pragma")).to.equal(true);
      }
    });

    it("WHY semanticId ALONE CANNOT DEDUPE: six distinct OpenZeppelin mulDiv findings share one id (dropped here as dependency code)", () => {
      const byId = new Map<string, Set<string>>();
      for (const f of B.filter((x) => classifyOwnership(x as SlitherFinding) === "DEPENDENCY_ONLY")) {
        const k = semanticId(f as SlitherFinding);
        (byId.get(k) || byId.set(k, new Set()).get(k)!).add(JSON.stringify(f));
      }
      const collided = [...byId.values()].filter((s) => s.size > 1);
      expect(collided).to.have.length(1);
      expect([...collided[0]].map((s) => JSON.parse(s).check)).to.deep.equal(Array(6).fill("divide-before-multiply"));
    });

    it("is deterministic, and independent of Slither's emission order (which differs across machines)", () => {
      const again = project(baseline());
      expect(sarifText(again.log.runs[0].results)).to.equal(sarifText(P.log.runs[0].results));
      const shuffled = baseline().reverse();
      const S = project(shuffled);
      expect(S.projected.map((p) => p.semanticId).sort()).to.deep.equal(P.projected.map((p) => p.semanticId).sort());
      expect(S.counts).to.deep.equal(P.counts);
    });
  });

  describe("C. required mutations", () => {
    it("1. KILL: one own-code result deleted from the SARIF (raw finding still present) -> FAIL", () => {
      const fs_ = baseline();
      const results = fs_.map(toResult);
      results.splice(firstOf(fs_, SINGLE), 1);
      expectFailure(() => project(fs_, results), "UNREPRESENTABLE_FINDING");
      const results2 = fs_.map(toResult);
      results2.splice(firstOf(fs_, DOUBLED), 1);
      expectFailure(() => project(fs_, results2), "UNMAPPED_SARIF_RESULT");
    });

    it("1'. CONTROL: deleting one compilation-unit COPY from both outputs is not a lost finding", () => {
      const fs_ = baseline();
      fs_.splice(firstOf(fs_, DOUBLED), 1);
      const P = project(fs_);
      expect(P.counts.projectedResults).to.equal(42);
      expect(() => assertTriageBijection(P.projected, TRIAGE_IDS)).to.not.throw();
    });

    it("2. a dependency-only result deleted -> projection still valid", () => {
      const fs_ = baseline();
      fs_.splice(
        fs_.findIndex((f) => classifyOwnership(f as SlitherFinding) === "DEPENDENCY_ONLY"),
        1,
      );
      const P = project(fs_);
      expect(P.counts.dependencyOnlyInstances).to.equal(221);
      expect(P.counts.projectedResults).to.equal(42);
      expect(() => assertTriageBijection(P.projected, TRIAGE_IDS)).to.not.throw();
    });

    it("3. an exact own-code duplicate added -> still one projected identity", () => {
      const fs_ = baseline();
      fs_.push(clone(fs_[firstOf(fs_, SINGLE)]));
      const P = project(fs_);
      expect(P.counts.projectedResults).to.equal(42);
      expect(P.counts.ownCopiesCollapsed).to.equal(27);
      expect(P.projected.find((p) => p.semanticId === SINGLE)!.instances).to.equal(2);
    });

    it("4. a semantically distinct finding on the SAME line (different detector) -> both survive", () => {
      const fs_ = baseline();
      const f = fs_[firstOf(fs_, SINGLE)];
      const g = {
        ...clone(f),
        check: f.check === "timestamp" ? "incorrect-equality" : "timestamp",
        id: sha256("mutant-4"),
      };
      fs_.push(g);
      const P = project(fs_);
      expect(P.counts.projectedResults).to.equal(43);
      const same = P.projected.filter(
        (p) =>
          p.uri === toResult(f).locations[0].physicalLocation.artifactLocation.uri &&
          p.startLine === toResult(f).locations[0].physicalLocation.region.startLine,
      );
      expect(same.length).to.be.greaterThanOrEqual(2);
      expectFailure(() => assertTriageBijection(P.projected, TRIAGE_IDS), "TRIAGE_BIJECTION_FAILED");
    });

    it("5. same detector and path, different message -> both survive as distinct identities", () => {
      const fs_ = baseline();
      const f = fs_[firstOf(fs_, SINGLE)];
      const g: F = {
        ...clone(f),
        description: `${f.description} (mutant)`,
        markdown: `${f.markdown} (mutant)`,
        id: sha256("mutant-5"),
      };
      fs_.push(g);
      const P = project(fs_);
      expect(P.counts.projectedResults).to.equal(43);
      expect(P.projected.map((p) => p.semanticId)).to.include.members([SINGLE, semanticId(g as SlitherFinding)]);
    });

    it("6. a detector shared by dependency and project code -> the project findings survive, the dependency ones do not", () => {
      const P = project(baseline());
      const projectedIds = new Set(P.projected.map((p) => p.semanticId));
      const byCheck = (cls: string) =>
        new Set(B.filter((f) => classifyOwnership(f as SlitherFinding) === cls).map((f) => f.check));
      const shared = [...byCheck("OWN")].filter((c) => byCheck("DEPENDENCY_ONLY").has(c));
      expect(shared.length, "the frozen scan must exercise at least one shared detector").to.be.greaterThan(0);
      for (const c of shared) {
        for (const f of B.filter((x) => x.check === c)) {
          const own = classifyOwnership(f as SlitherFinding) === "OWN";
          expect(
            projectedIds.has(semanticId(f as SlitherFinding)),
            `${c} ${f.elements[0].source_mapping.filename_relative}`,
          ).to.equal(own);
        }
      }
    });

    it("7. KILL: malformed inputs -> FAIL", () => {
      const fs_ = baseline();
      const results = fs_.map(toResult);
      delete (results[0].message as F).text;
      expectFailure(() => project(fs_, results), "UNRECOGNIZED_SARIF_SHAPE");
      const fs2 = baseline();
      delete fs2[0].elements[0].source_mapping.filename_relative;
      expectFailure(() => projectSarif(scanText(fs2), sarifText(baseline().map(toResult))), "MALFORMED_RAW_SCAN");
      expectFailure(() => projectSarif("{not json", sarifText(B.map(toResult))), "MALFORMED_RAW_SCAN");
      expectFailure(() => projectSarif(scanText(B), "{not json"), "MALFORMED_SARIF");
      expectFailure(
        () => projectSarif(JSON.stringify({ success: false, error: "compile failed", results: {} }), sarifText([])),
        "MALFORMED_RAW_SCAN",
      );
      const results3 = baseline().map(toResult);
      results3[0].locations[0].physicalLocation.region.startLine = 0;
      expectFailure(() => project(baseline(), results3), "UNRECOGNIZED_SARIF_SHAPE");
    });

    it("8. KILL: ambiguous raw -> SARIF mapping (one SARIF signature, two different raw findings) -> FAIL", () => {
      const fs_ = baseline();
      const g = clone(fs_[firstOf(fs_, SINGLE)]);
      const last = g.elements[g.elements.length - 1].source_mapping;
      last.lines = last.lines.map((n: number) => n + 1000);
      fs_.push(g);
      expectFailure(() => project(fs_), "AMBIGUOUS_MAPPING");
    });

    it("9. KILL: an unexpected new result or log shape -> FAIL CLOSED", () => {
      const withExtra = (mut: (r: F) => void) => {
        const results = baseline().map(toResult);
        mut(results[3] as F);
        return () => project(baseline(), results);
      };
      expectFailure(
        withExtra((r) => (r.relatedLocations = [])),
        "UNRECOGNIZED_SARIF_SHAPE",
      );
      expectFailure(
        withExtra((r) => (r.fingerprints = { x: "y" })),
        "UNRECOGNIZED_SARIF_SHAPE",
      );
      expectFailure(
        withExtra((r) => r.locations.push(clone(r.locations[0]))),
        "UNRECOGNIZED_SARIF_SHAPE",
      );
      expectFailure(
        withExtra((r) => (r.level = "error")),
        "UNRECOGNIZED_SARIF_SHAPE",
      );
      const twoRuns = JSON.parse(sarifText(B.map(toResult)));
      twoRuns.runs.push(clone(twoRuns.runs[0]));
      expectFailure(() => projectSarif(scanText(B), JSON.stringify(twoRuns)), "UNRECOGNIZED_SARIF_SHAPE");
      const newRunKey = JSON.parse(sarifText(B.map(toResult)));
      newRunKey.runs[0].invocations = [];
      expectFailure(() => projectSarif(scanText(B), JSON.stringify(newRunKey)), "UNRECOGNIZED_SARIF_SHAPE");
      const v22 = JSON.parse(sarifText(B.map(toResult)));
      v22.version = "2.2.0";
      expectFailure(() => projectSarif(scanText(B), JSON.stringify(v22)), "UNRECOGNIZED_SARIF_SHAPE");
    });

    it("10. KILL: nothing but node_modules findings -> a zero own-code projection is rejected", () => {
      const fs_ = baseline().filter((f) => !isOwnFinding(f as SlitherFinding));
      expectFailure(() => project(fs_), "EMPTY_PROJECTION");
    });

    it("11. KILL: one of the current 42 triaged findings missing from the scan -> FAIL", () => {
      const fs_ = baseline().filter(
        (f) => !(isOwnFinding(f as SlitherFinding) && semanticId(f as SlitherFinding) === DOUBLED),
      );
      const P = project(fs_);
      expect(P.counts.projectedResults).to.equal(41);
      const e = expectFailure(() => assertTriageBijection(P.projected, TRIAGE_IDS), "TRIAGE_BIJECTION_FAILED");
      expect(e.message).to.contain(DOUBLED);
    });

    it("12. an untriaged project-owned finding: the projection refuses AND the existing triage gate still FAILS", function () {
      this.timeout(180_000);
      const fs_ = baseline();
      const f = fs_[firstOf(fs_, SINGLE)];
      fs_.push({
        ...clone(f),
        description: `${f.description} (untriaged mutant)`,
        markdown: `${f.markdown} (untriaged)`,
        id: sha256("mutant-12"),
      });
      const P = project(fs_);
      expectFailure(() => assertTriageBijection(P.projected, TRIAGE_IDS), "TRIAGE_BIJECTION_FAILED");
      const r = runValidator(fs_);
      expect(r.status, r.out).to.equal(1);
      expect(r.out).to.contain("have no triage entry");
    });

    it("12'. PROJECTION IS NEVER AUTHORITY: handing the validator a projected SARIF cannot turn it green", function () {
      this.timeout(180_000);
      const fs_ = baseline();
      const f = fs_[firstOf(fs_, SINGLE)];
      fs_.push({
        ...clone(f),
        description: `${f.description} (untriaged mutant)`,
        markdown: `${f.markdown} (untriaged)`,
        id: sha256("mutant-12b"),
      });
      const projected = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "proj-")), "projected.sarif");
      fs.writeFileSync(projected, sarifText(project(baseline()).log.runs[0].results));
      const r = runValidator(fs_, ["--sarif", projected]);
      expect(r.status, r.out).to.equal(1);
      expect(r.out).to.contain("have no triage entry");
      expect(fs.readFileSync(path.join(DIR, "generate-scanner-evidence.ts"), "utf8")).to.not.match(
        /args\.sarif|args\["sarif"\]/,
      );
    });
  });

  describe("D. further adversarial shapes", () => {
    it("KILL: two DISTINCT own findings sharing one semanticId (the mulDiv shape, in project code) never collapse", () => {
      const fs_ = baseline();
      const g = clone(fs_[firstOf(fs_, SINGLE)]);
      for (const e of g.elements) e.source_mapping.lines = e.source_mapping.lines.map((n: number) => n + 3);
      g.description = g.description.replace(/#(\d+)/g, (_m: string, n: string) => `#${Number(n) + 3}`);
      g.id = sha256("mutant-collapse");
      expect(semanticId(g as SlitherFinding)).to.equal(SINGLE);
      fs_.push(g);
      expectFailure(() => project(fs_), "DISTINCT_FINDINGS_WOULD_COLLAPSE");
    });

    it("KILL: a project-anchored finding that also references a dependency is never silently dropped", () => {
      const fs_ = baseline();
      fs_[firstOf(fs_, SINGLE)].elements.push({
        type: "function",
        name: "functionCall",
        source_mapping: {
          filename_relative: "node_modules/@openzeppelin/contracts/utils/Address.sol",
          lines: [60, 61],
        },
      });
      expectFailure(() => project(fs_), "PROJECT_FINDING_REFERENCES_DEPENDENCY");
    });

    it("KILL: a dependency-anchored finding that references project CODE (not a pragma) fails instead of being dropped", () => {
      const fs_ = baseline();
      const mixed = fs_.find((f) => classifyOwnership(f as SlitherFinding) === "MIXED_DEPENDENCY_PRIMARY")!;
      mixed.elements.find((e: F) => !e.source_mapping.filename_relative.split("/").includes("node_modules")).type =
        "function";
      expectFailure(() => project(fs_), "PROJECT_CODE_IN_DEPENDENCY_FINDING");
      const fs2 = baseline();
      const m2 = fs2.find((f) => classifyOwnership(f as SlitherFinding) === "MIXED_DEPENDENCY_PRIMARY")!;
      m2.check = "assembly";
      expectFailure(() => project(fs2), "PROJECT_CODE_IN_DEPENDENCY_FINDING");
    });

    it("KILL: a path the segment and substring dependency tests disagree on is refused", () => {
      const fs_ = baseline();
      fs_[firstOf(fs_, SINGLE)].elements[0].source_mapping.filename_relative =
        "prototype/vnext-kernel/contracts/my_node_modules_x/Y.sol";
      expectFailure(() => project(fs_), "DEPENDENCY_PREDICATE_DISAGREEMENT");
    });

    it("KILL: absolute or parent-relative paths are refused, never classified", () => {
      for (const bad of ["/root/repo/prototype/vnext-kernel/contracts/X.sol", "../contracts/X.sol", "C:/x/X.sol"]) {
        const fs_ = baseline();
        fs_[0].elements[0].source_mapping.filename_relative = bad;
        expectFailure(() => project(fs_), "MALFORMED_RAW_SCAN");
      }
    });

    it("KILL: a finding with no location (unrepresentable in SARIF, vacuously own) fails", () => {
      const fs_ = baseline();
      const results = fs_.map(toResult);
      fs_.push({ ...clone(fs_[0]), elements: [], id: sha256("no-location") });
      expectFailure(() => project(fs_, results), "UNREPRESENTABLE_FINDING");
    });

    it("KILL: a SARIF result with no raw finding, or an extra copy of one, fails", () => {
      const fs_ = baseline();
      const results = fs_.map(toResult);
      results.push(toResult({ ...clone(fs_[0]), id: sha256("orphan") }));
      expectFailure(() => project(fs_, results), "UNMAPPED_SARIF_RESULT");
      const r2 = baseline().map(toResult);
      r2.push(clone(r2[0]));
      expectFailure(() => project(baseline(), r2), "UNMAPPED_SARIF_RESULT");
    });

    it("KILL: two rules declared for one detector are refused (the signature carries the detector name)", () => {
      const header = clone(HEADER);
      const rule = clone(header.runs[0].tool.driver.rules[0]);
      rule.id = `9-9-${rule.name}`;
      header.runs[0].tool.driver.rules.push(rule);
      expectFailure(() => projectSarif(scanText(B), sarifText(B.map(toResult), header)), "UNRECOGNIZED_SARIF_SHAPE");
    });

    it("KILL: the subset guard rejects a changed header or a foreign result", () => {
      const raw = parseRawSarif(sarifText(B.map(toResult)));
      const P = project(baseline());
      const doctored = clone(P.log);
      doctored.runs[0].tool.driver.version = "9.9.9";
      expectFailure(() => assertProjectionIsSubset(raw, doctored), "PROJECTION_NOT_A_SUBSET");
      const foreign = clone(P.log);
      foreign.runs[0].results[0].message.text += " edited";
      expectFailure(() => assertProjectionIsSubset(raw, foreign), "PROJECTION_NOT_A_SUBSET");
    });

    it("KILL: a malformed triage file, or a projection naming one identity twice, is refused", () => {
      expectFailure(() => loadTriageIdentities("{}"), "MALFORMED_TRIAGE");
      expectFailure(() => loadTriageIdentities(JSON.stringify({ classifications: {} })), "MALFORMED_TRIAGE");
      expectFailure(
        () => loadTriageIdentities(JSON.stringify({ classifications: { "not-an-id": {} } })),
        "MALFORMED_TRIAGE",
      );
      const P = project(baseline());
      expectFailure(
        () => assertTriageBijection([...P.projected, P.projected[0]], TRIAGE_IDS),
        "TRIAGE_BIJECTION_FAILED",
      );
    });
  });

  describe("E. the CLI writes a projection only when every check passes", () => {
    const quiet = <T>(fn: () => T): T => {
      const [log, err] = [console.log, console.error];
      console.log = () => undefined;
      console.error = () => undefined;
      try {
        return fn();
      } finally {
        console.log = log;
        console.error = err;
      }
    };
    const inputs = (findings: F[]) => {
      const d = fs.mkdtempSync(path.join(os.tmpdir(), "proj-cli-"));
      fs.writeFileSync(path.join(d, "raw.sarif"), sarifText(findings.map(toResult)));
      fs.writeFileSync(path.join(d, "raw.json"), scanText(findings));
      return d;
    };
    const argv = (d: string) => [
      "--raw-sarif",
      path.join(d, "raw.sarif"),
      "--raw-scan",
      path.join(d, "raw.json"),
      "--triage",
      TRIAGE,
      "--out",
      path.join(d, "out.sarif"),
      "--report",
      path.join(d, "report.json"),
    ];

    it("success: 42 results written, report ok, and the output is itself a well-formed Slither SARIF", () => {
      const d = inputs(baseline());
      expect(quiet(() => main(argv(d)))).to.equal(0);
      const out = fs.readFileSync(path.join(d, "out.sarif"), "utf8");
      expect(parseRawSarif(out).runs[0].results).to.have.length(42);
      const report = JSON.parse(fs.readFileSync(path.join(d, "report.json"), "utf8"));
      expect(report.ok).to.equal(true);
      expect(report.counts).to.deep.equal(EXPECTED);
      expect(report.bijection.matched).to.equal(42);
    });

    it("failure: NO output file, and a report naming the failure", () => {
      const fs_ = baseline().filter(
        (f) => !(isOwnFinding(f as SlitherFinding) && semanticId(f as SlitherFinding) === DOUBLED),
      );
      const d = inputs(fs_);
      expect(quiet(() => main(argv(d)))).to.equal(1);
      expect(fs.existsSync(path.join(d, "out.sarif"))).to.equal(false);
      const report = JSON.parse(fs.readFileSync(path.join(d, "report.json"), "utf8"));
      expect(report.ok).to.equal(false);
      expect(report.failure.code).to.equal("TRIAGE_BIJECTION_FAILED");
    });

    it("refuses to run over a pre-existing output (exclusive create, no check-then-write race), leaving it untouched", () => {
      const d = inputs(baseline());
      fs.writeFileSync(path.join(d, "out.sarif"), "stale");
      expect(quiet(() => main(argv(d)))).to.equal(1);
      expect(fs.readFileSync(path.join(d, "out.sarif"), "utf8")).to.equal("stale");
      const report = JSON.parse(fs.readFileSync(path.join(d, "report.json"), "utf8"));
      expect(report.ok).to.equal(false);
      expect(report.failure.code).to.equal("PRE_EXISTING_OUTPUT");
    });
  });

  describe("F. workflow wiring: complete raw output preserved, only the validated projection reaches code scanning", () => {
    function workflowWith(replace: [string, string]): string {
      const original = fs.readFileSync(WORKFLOW_PATH, "utf8");
      expect(original, `mutation anchor absent: ${replace[0]}`).to.contain(replace[0]);
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wf-")), "workflow.yml");
      fs.writeFileSync(file, original.replace(replace[0], replace[1]));
      return file;
    }
    function workflowMovingStepBefore(step: string, before: string): string {
      const text = fs.readFileSync(WORKFLOW_PATH, "utf8");
      const lines = text.split("\n");
      const start = lines.findIndex((l) => l === `      - name: ${step}`);
      expect(start, step).to.be.greaterThan(-1);
      let end = start + 1;
      while (end < lines.length && !/^ {6}- name:/.test(lines[end]) && !/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[end]))
        end++;
      const block = lines.splice(start, end - start);
      const at = lines.findIndex((l) => l === `      - name: ${before}`);
      expect(at, before).to.be.greaterThan(-1);
      lines.splice(at, 0, ...block);
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wf-")), "workflow.yml");
      fs.writeFileSync(file, lines.join("\n"));
      return file;
    }

    it("the real workflow satisfies the projection contract, and still matches the pinned Slither semantics", () => {
      expect(() => assertWorkflowSarifProjectionContract()).to.not.throw();
      expect(() => assertWorkflowMatchesPinnedConfig()).to.not.throw();
      expect(() => assertWorkflowOutputContract()).to.not.throw();
    });

    it("KILL: upload-sarif pointed back at the raw SARIF", () => {
      const wf = workflowWith([`sarif_file: ${PROJECTED_SARIF_PATH}`, `sarif_file: ${RAW_SARIF_PATH}`]);
      expectFailure(() => assertWorkflowSarifProjectionContract(wf), "WORKFLOW_CONTRACT");
    });

    it("KILL: upload-sarif no longer conditioned on a successful projection", () => {
      const wf = workflowWith(["steps.sarif-projection.outcome == 'success'", "always()"]);
      expectFailure(() => assertWorkflowSarifProjectionContract(wf), "WORKFLOW_CONTRACT");
    });

    it("KILL: the raw SARIF artifact removed, or no longer under always()", () => {
      const gone = workflowWith([`          path: ${RAW_SARIF_PATH}\n`, "          path: elsewhere.sarif\n"]);
      expectFailure(() => assertWorkflowSarifProjectionContract(gone), "WORKFLOW_CONTRACT");
      const gated = workflowWith([
        `if: \${{ always() && hashFiles('${RAW_SARIF_PATH}') != '' }}`,
        `if: \${{ hashFiles('${RAW_SARIF_PATH}') != '' }}`,
      ]);
      expectFailure(() => assertWorkflowSarifProjectionContract(gated), "WORKFLOW_CONTRACT");
    });

    it("KILL: Slither's own SARIF output redirected onto the projection path (the raw would be overwritten)", () => {
      const wf = workflowWith([`          sarif: ${RAW_SARIF_PATH}`, `          sarif: ${PROJECTED_SARIF_PATH}`]);
      expectFailure(() => assertWorkflowSarifProjectionContract(wf), "WORKFLOW_CONTRACT");
    });

    it("KILL: the projection writing somewhere upload-sarif does not read", () => {
      const wf = workflowWith([`--out ${PROJECTED_SARIF_PATH}`, "--out elsewhere.sarif"]);
      expectFailure(() => assertWorkflowSarifProjectionContract(wf), "WORKFLOW_CONTRACT");
    });

    it("KILL: projecting before the triage gate, or preserving raw output only after it", () => {
      const early = workflowMovingStepBefore(
        "Project SARIF to distinct project-owned findings",
        "Validate scanner triage completeness",
      );
      expectFailure(() => assertWorkflowSarifProjectionContract(early), "WORKFLOW_CONTRACT");
      const late = workflowMovingStepBefore(
        "Upload raw Slither SARIF (complete, diagnostic)",
        "Verify publication container",
      );
      expectFailure(() => assertWorkflowSarifProjectionContract(late), "WORKFLOW_CONTRACT");
    });
  });
});
