/**
 * CI workflow guard: proves the normal PR CI build-test job in
 * .github/workflows/ci.yml actually runs the deployment-truth validators
 * (`npm run validate:deployments`, `npm run validate:reproducibility`) and the
 * EIP-170 runtime bytecode size gate (`npm run validate:bytecode-size`) — so a
 * future edit that drops or conditionally-skips one of these commands fails this
 * test, instead of silently shipping a CI run that no longer checks them.
 *
 * Pure, fast, static read of the workflow YAML as text — no network, no CI run.
 * Mirrors the workflow-guard pattern in
 * test/StaticHostedEvidencePublishWorkflow.test.ts (string/regex assertions on the
 * comment-stripped workflow text; no YAML parser dependency).
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const WORKFLOW_PATH = resolve(".github/workflows/ci.yml");

function read(path: string): string {
  return readFileSync(path, "utf8");
}

/** Slice out one top-level job's block (2-space-indented key) from comment-stripped YAML. */
function jobBlock(code: string, name: string): string {
  const lines = code.split("\n");
  const start = lines.findIndex((l) => l === `  ${name}:`);
  expect(start, `job "${name}:" not found in ${WORKFLOW_PATH}`).to.not.equal(-1);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^ {2}[A-Za-z][\w-]*:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

/** Slice out the single step block containing `commandSubstring`, for step-scoped assertions. */
function stepBlockContaining(job: string, commandSubstring: string): string {
  const lines = job.split("\n");
  const cmdLineIdx = lines.findIndex((l) => l.includes(commandSubstring));
  expect(cmdLineIdx, `command not found in job: ${commandSubstring}`).to.be.greaterThan(-1);
  let stepStart = cmdLineIdx;
  while (stepStart > 0 && !/^\s*- name:/.test(lines[stepStart])) stepStart--;
  let stepEnd = cmdLineIdx + 1;
  while (stepEnd < lines.length && !/^\s*- name:/.test(lines[stepEnd])) stepEnd++;
  return lines.slice(stepStart, stepEnd).join("\n");
}

describe("CI workflow — deployment-truth and bytecode-size gates run in normal PR CI", function () {
  const raw = read(WORKFLOW_PATH);
  // Strip comment lines so assertions inspect real YAML/step content, not prose.
  const code = raw
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");

  it("runs on every pull request, with no path filter that could narrow it away", function () {
    expect(code).to.match(/^on:\s*$/m);
    expect(code).to.match(/^\s+pull_request:\s*$/m);
    // A `pull_request:` trigger with a nested `paths:`/`paths-ignore:` filter can skip
    // the whole workflow for a PR that only touches (for example) deployments/ or
    // contracts/ — exactly the files these gates exist to check. None is present.
    expect(code).to.not.match(/paths(-ignore)?:/);
  });

  describe("build-test job (normal PR CI)", function () {
    const job = jobBlock(code, "build-test");

    it("runs npm run validate:deployments", function () {
      expect(job).to.include("npm run validate:deployments");
    });

    it("runs npm run validate:reproducibility", function () {
      expect(job).to.include("npm run validate:reproducibility");
    });

    it("runs npm run validate:bytecode-size", function () {
      expect(job).to.include("npm run validate:bytecode-size");
    });

    it("compiles before the bytecode-size gate (deployed bytecode must exist first)", function () {
      const compileIdx = job.indexOf("npm run compile");
      const sizeIdx = job.indexOf("npm run validate:bytecode-size");
      expect(compileIdx, "npm run compile step not found").to.be.greaterThan(-1);
      expect(sizeIdx, "npm run validate:bytecode-size step not found").to.be.greaterThan(-1);
      expect(compileIdx).to.be.lessThan(sizeIdx);
    });

    for (const cmd of [
      "npm run validate:deployments",
      "npm run validate:reproducibility",
      "npm run validate:bytecode-size",
    ]) {
      it(`"${cmd}" step is unconditional (no if:, no continue-on-error escape hatch)`, function () {
        const step = stepBlockContaining(job, cmd);
        expect(step).to.not.match(/if:\s*/);
        expect(step).to.not.match(/continue-on-error:\s*true/);
      });
    }
  });
});
