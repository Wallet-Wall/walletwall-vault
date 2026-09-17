/**
 * Ruleset guard: every status context that main's ruleset requires must be reported for an ordinary pull request to
 * main by construction, never contingent on mutable repository configuration.
 *
 * GitHub meets a required status check only with a check run reported under that exact name for the head commit, and
 * the ruleset stores bare names: it cannot tell whether a workflow can still report one, or which job does. So:
 *
 * - No job-level `if:` over `vars.*`. An unset variable evaluates to '' in expressions, so the gate would depend on a
 *   repository setting that changes without a pull request, and a skipped job that keeps its name meets the
 *   requirement without running.
 * - No job-level `if:` at all on a matrix job. When it is false, GitHub skips the job before expanding the matrix and
 *   reports one check run under the raw template name: codeql.yml runs 29661190566 (pull_request) and 29661272395
 *   (push), from before CODEQL_ENABLED existed, each reported only `Analyze (${{ matrix.language }})`, skipped with 0
 *   steps, so the three required `Analyze (<language>)` names could never arrive and pull requests would wait forever.
 * - No pull_request trigger narrowed by paths, by branches that omit main, or by activity types: a workflow that does
 *   not run leaves its required checks pending.
 * - Exactly one job reporting each name. On the two heads above, CodeQL default setup (a different producer) reported
 *   the same three names, so a requirement can be met by a job other than the gate it names.
 *
 * Pure static read of comment-stripped workflow text, like test/CIValidatorCoverage.test.ts: no YAML parser
 * dependency, no network, no CI run. Shapes the reader does not model fail closed instead of passing.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const WORKFLOWS_DIR = resolve(".github/workflows");

/**
 * The status contexts that ruleset 21256062 ("Protect main — required assurance gates") requires on main. The ruleset
 * lives in GitHub, not in this tree, so it is mirrored by hand: the first nine are the contexts it required on
 * 2026-09-17, all from GitHub Actions (integration 15368). The relation-test context is listed ahead of the ruleset: a
 * context must be reportable before anything requires it. Update this list whenever the required checks change.
 */
const REQUIRED_CONTEXTS = [
  "check-version",
  "Build, lint & test",
  "Compile zkVM guest",
  "Validate SP1 host Cargo.lock",
  "Check evidence-validator crate (offline)",
  "Analyze Solidity",
  "Analyze (actions)",
  "Analyze (javascript-typescript)",
  "Analyze (rust)",
  "Native guest relation tests (no SP1 toolchain)",
];

/** GitHub's default pull_request activity types; a trigger that drops one stops re-running on some head updates. */
const DEFAULT_PULL_REQUEST_TYPES = ["opened", "synchronize", "reopened"];

interface Workflow {
  file: string;
  lines: string[];
}

interface Job {
  workflow: string;
  id: string;
  /** The job-level `if:` expression, or null when the job has none. */
  condition: string | null;
  matrix: boolean;
  needs: boolean;
}

/** Workflow text with full-line comments removed, as in the other workflow guards. */
const codeLines = (text: string): string[] => text.split(/\r?\n/).filter((line) => !/^\s*#/.test(line));
const indentOf = (line: string): number => line.length - line.trimStart().length;
const isKey = (line: string, key: string): boolean =>
  line.trimStart() === `${key}:` || line.trimStart().startsWith(`${key}: `);
const unquote = (text: string): string => text.trim().replace(/^(["'])(.*)\1$/, "$2");
/** The inline value after `key:`, unquoted; "" when the value is a nested block. */
const valueOf = (line: string): string => unquote(line.slice(line.indexOf(":") + 1));

/** Lines nested under the key at `lines[at]`: everything indented deeper (blank lines included) up to the next sibling. */
function childrenOf(lines: string[], at: number): string[] {
  const children: string[] = [];
  for (let i = at + 1; i < lines.length && (lines[i].trim() === "" || indentOf(lines[i]) > indentOf(lines[at])); i++) {
    children.push(lines[i]);
  }
  return children;
}

/** Indices of the shallowest non-blank lines: the keys of the mapping that `lines` holds. */
function topKeys(lines: string[]): number[] {
  const depth = Math.min(...lines.filter((line) => line.trim() !== "").map(indentOf));
  return lines.flatMap((line, i) => (line.trim() !== "" && indentOf(line) === depth ? [i] : []));
}

/** The items of a list given inline (`[a, b]`), as one scalar, or as `- item` lines under the key at `lines[at]`. */
function listAt(lines: string[], at: number): string[] {
  const inline = valueOf(lines[at]);
  if (inline === "") {
    return childrenOf(lines, at)
      .filter((line) => line.trim().startsWith("- "))
      .map((line) => unquote(line.trim().slice(2)));
  }
  return inline.startsWith("[") ? inline.slice(1, -1).split(",").map(unquote) : [inline];
}

/** Why the workflow might not run for some pull request to main; null when it runs for every one. */
function pullRequestGap(workflow: Workflow): string | null {
  const root = topKeys(workflow.lines).find((i) => isKey(workflow.lines[i], "on"));
  if (root === undefined || valueOf(workflow.lines[root]) !== "") return "no block-style on: (not modeled)";
  const triggers = childrenOf(workflow.lines, root);
  const pr = topKeys(triggers).find((i) => isKey(triggers[i], "pull_request"));
  if (pr === undefined) return "no pull_request trigger";
  if (valueOf(triggers[pr]) !== "") return "inline pull_request value (not modeled)";
  const filters = childrenOf(triggers, pr);
  for (const at of topKeys(filters)) {
    const key = filters[at].trim().split(":")[0];
    const values = listAt(filters, at);
    if (key === "branches") {
      if (!values.some((v) => ["main", "*", "**"].includes(v))) {
        return `pull_request branches [${values.join(", ")}] omit main`;
      }
    } else if (key === "types") {
      const missing = DEFAULT_PULL_REQUEST_TYPES.filter((t) => !values.includes(t));
      if (missing.length > 0) return `pull_request types omit ${missing.join(", ")}`;
    } else {
      return `pull_request is narrowed by ${key}`;
    }
  }
  return null;
}

/** A matrix given only as `include:` of flat mappings, one record per cell; null for any other form. */
function includeCells(strategy: string[], matrixAt: number): Record<string, string>[] | null {
  if (valueOf(strategy[matrixAt]) !== "") return null;
  const matrix = childrenOf(strategy, matrixAt);
  const keys = topKeys(matrix);
  if (keys.length !== 1 || !isKey(matrix[keys[0]], "include") || valueOf(matrix[keys[0]]) !== "") return null;
  const cells: Record<string, string>[] = [];
  for (const line of childrenOf(matrix, keys[0]).filter((l) => l.trim() !== "")) {
    let entry = line.trim();
    if (entry.startsWith("- ")) {
      cells.push({});
      entry = entry.slice(2);
    }
    const colon = entry.indexOf(":");
    if (cells.length === 0 || colon < 1) return null;
    cells[cells.length - 1][entry.slice(0, colon).trim()] = valueOf(entry);
  }
  return cells.length > 0 ? cells : null;
}

/** The check-run name GitHub reports for one matrix cell; null unless every expression is a known `matrix.<key>`. */
function renderMatrixName(name: string, cell: Record<string, string>): string | null {
  let unknown = !/\$\{\{\s*matrix\./.test(name);
  const rendered = name.replace(/\$\{\{\s*matrix\.([\w-]+)\s*\}\}/g, (_match, key: string) => {
    if (!Object.hasOwn(cell, key)) unknown = true;
    return cell[key] ?? "";
  });
  return unknown || rendered.includes("${{") ? null : rendered;
}

/** Every job in `workflows`, keyed by each check-run name it reports, plus the jobs whose names the reader cannot render. */
function inventory(workflows: Workflow[]): { reporters: Map<string, Job[]>; unmodeled: string[] } {
  const reporters = new Map<string, Job[]>();
  const unmodeled: string[] = [];
  const report = (name: string, job: Job) => reporters.set(name, [...(reporters.get(name) ?? []), job]);
  for (const workflow of workflows) {
    const root = topKeys(workflow.lines).find((i) => isKey(workflow.lines[i], "jobs"));
    if (root === undefined) {
      unmodeled.push(`${workflow.file}: no block-style jobs:`);
      continue;
    }
    const jobs = childrenOf(workflow.lines, root);
    for (const at of topKeys(jobs)) {
      const id = jobs[at].trim().split(":")[0];
      const body = childrenOf(jobs, at);
      const keyLine = (key: string) => topKeys(body).find((i) => isKey(body[i], key));
      const nameAt = keyLine("name");
      const ifAt = keyLine("if");
      const strategyAt = keyLine("strategy");
      const strategy = strategyAt === undefined ? [] : childrenOf(body, strategyAt);
      const matrixAt = topKeys(strategy).find((i) => isKey(strategy[i], "matrix"));
      const name = nameAt === undefined ? id : valueOf(body[nameAt]);
      const job: Job = {
        workflow: workflow.file,
        id,
        condition:
          ifAt === undefined
            ? null
            : [valueOf(body[ifAt]), ...childrenOf(body, ifAt).map((line) => line.trim())].join(" ").trim(),
        matrix: matrixAt !== undefined,
        needs: keyLine("needs") !== undefined,
      };
      if (matrixAt === undefined) {
        if (name.includes("${{")) unmodeled.push(`${workflow.file} job ${id}: expression in name`);
        else report(name, job);
        continue;
      }
      const cells = includeCells(strategy, matrixAt);
      if (cells === null) {
        unmodeled.push(`${workflow.file} job ${id}: matrix is not a plain include: list`);
        continue;
      }
      for (const cell of cells) {
        const rendered = renderMatrixName(name, cell);
        if (rendered === null)
          unmodeled.push(`${workflow.file} job ${id}: name does not render for ${JSON.stringify(cell)}`);
        else report(rendered, job);
      }
    }
  }
  return { reporters, unmodeled };
}

/** Why `job` might never report `context` on a pull request to main; empty when nothing can hold it back. */
function holdsBack(job: Job, context: string): string[] {
  const reasons: string[] = [];
  if (job.needs) reasons.push("needs: other jobs (dependency chains are not modeled by this guard)");
  if (job.condition !== null && /\bvars\s*[.[]/.test(job.condition)) {
    reasons.push(`job-level if: reads a repository variable (${job.condition})`);
  }
  if (job.condition !== null && job.matrix) {
    reasons.push(
      `job-level if: on a matrix job; when false the job is skipped unexpanded and "${context}" never arrives`,
    );
  }
  return reasons;
}

describe("Ruleset guard — required status contexts are reported for every pull request to main", function () {
  const workflows: Workflow[] = readdirSync(WORKFLOWS_DIR)
    .filter((file) => /\.ya?ml$/.test(file))
    .sort()
    .map((file) => ({ file, lines: codeLines(readFileSync(resolve(WORKFLOWS_DIR, file), "utf8")) }));
  const { reporters, unmodeled } = inventory(workflows);

  it("reads every workflow, and every job renders to concrete check-run names (unmodeled shapes fail closed)", function () {
    expect(workflows, `no workflows under ${WORKFLOWS_DIR}`).to.not.be.empty;
    expect(unmodeled).to.deep.equal([]);
  });

  for (const context of REQUIRED_CONTEXTS) {
    describe(`"${context}"`, function () {
      const reporter = (): Job => {
        const jobs = reporters.get(context) ?? [];
        expect(
          jobs.map((job) => `${job.workflow} job ${job.id}`),
          `jobs reporting "${context}"`,
        ).to.have.lengthOf(1);
        return jobs[0];
      };

      it("is reported by exactly one job under .github/workflows", function () {
        reporter();
      });

      it("is reported by a workflow that runs for every pull request to main", function () {
        const { workflow } = reporter();
        expect(pullRequestGap(workflows.find((w) => w.file === workflow)!), workflow).to.equal(null);
      });

      it("is not held back by a job-level if: or needs:", function () {
        const job = reporter();
        expect(holdsBack(job, context), `${job.workflow} job ${job.id}`).to.deep.equal([]);
      });
    });
  }

  describe("reader self-check on synthetic workflows (a parsing regression must not pass silently)", function () {
    const synthetic = (lines: string[]): Workflow => ({ file: "synthetic.yml", lines });
    const gated = synthetic([
      "on:",
      "  pull_request:",
      "jobs:",
      "  analyze:",
      "    name: Analyze (${{ matrix.language }})",
      "    if: ${{ vars.SCANNING_ENABLED == 'true' }}",
      "    strategy:",
      "      matrix:",
      "        include:",
      "          - language: rust",
      "            build-mode: none",
      "          - language: actions",
      "  check-version:",
      "    if: ${{ github.event.pull_request.user.login != 'dependabot[bot]' }}",
    ]);

    it("renders a matrix name per cell and names a job without name: by its id", function () {
      expect([...inventory([gated]).reporters.keys()]).to.deep.equal([
        "Analyze (rust)",
        "Analyze (actions)",
        "check-version",
      ]);
    });

    it("holds back a variable-gated matrix job for both reasons", function () {
      const [job] = inventory([gated]).reporters.get("Analyze (rust)")!;
      expect(holdsBack(job, "Analyze (rust)")).to.have.lengthOf(2);
    });

    it("sees, and allows, an event-only condition on a job without a matrix", function () {
      const [job] = inventory([gated]).reporters.get("check-version")!;
      expect(job.condition).to.not.equal(null);
      expect(holdsBack(job, "check-version")).to.deep.equal([]);
    });

    it("reports a pull_request trigger narrowed by paths or by branches that omit main", function () {
      expect(pullRequestGap(gated)).to.equal(null);
      expect(pullRequestGap(synthetic(["on:", "  pull_request:", "    paths:", "      - src/**"]))).to.match(/paths/);
      expect(pullRequestGap(synthetic(["on:", "  pull_request:", "    branches: [develop]"]))).to.match(/omit main/);
    });
  });
});
