/**
 * CI workflow guard for the SP1 withdrawal-relation regression tests: .github/workflows/ci.yml must
 * keep running them, unconditionally.
 *
 * - The zkvm-relation-tests job runs the native relation tests (zkvm/relation-tests), locked and
 *   format-checked: the withdrawal program verifies exactly the digest it commits under the empty
 *   ML-DSA context, and the ACVP conformance program stays a separate program.
 * - The build-test job builds guest-native-execute and exports SP1_RELATION_EXECUTOR before the Hardhat
 *   suite and coverage run, so test/ZKMLDSAWithdrawalRelationConsumers.test.ts executes there (under
 *   CI it fails, rather than skips, without the executor).
 *
 * Pure static read of the workflow text with comment lines stripped, following
 * test/CIValidatorCoverage.test.ts. No network, no CI run.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const WORKFLOW_PATH = resolve(".github/workflows/ci.yml");

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

function expectUnconditional(block: string) {
  expect(block).to.not.match(/if:\s*/);
  expect(block).to.not.match(/continue-on-error:\s*true/);
}

describe("CI workflow — SP1 withdrawal-relation regression tests run in normal PR CI", function () {
  const code = readFileSync(WORKFLOW_PATH, "utf8")
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");

  describe("zkvm-relation-tests job", function () {
    const job = jobBlock(code, "zkvm-relation-tests");
    const TEST = "cargo test --locked --manifest-path zkvm/relation-tests/Cargo.toml";
    const FORMAT = "cargo fmt --check --all --manifest-path zkvm/relation-tests/Cargo.toml";

    it("runs the native relation tests against the committed lockfile", function () {
      expect(job).to.include(TEST);
    });

    it("checks the relation-test workspace's formatting, with rustfmt installed", function () {
      expect(job).to.include(FORMAT);
      expect(job).to.match(/rustup toolchain install stable[^\n]*--component rustfmt/);
    });

    it("the job and both steps are unconditional (no if:, no continue-on-error escape hatch)", function () {
      expectUnconditional(job.slice(0, job.indexOf("steps:")));
      expectUnconditional(stepBlockContaining(job, TEST));
      expectUnconditional(stepBlockContaining(job, FORMAT));
    });
  });

  describe("build-test job", function () {
    const job = jobBlock(code, "build-test");
    const BUILD = "cargo build --locked --manifest-path zkvm/relation-tests/Cargo.toml --bin guest-native-execute";
    const EXPORT =
      'echo "SP1_RELATION_EXECUTOR=$GITHUB_WORKSPACE/zkvm/relation-tests/target/debug/guest-native-execute" >> "$GITHUB_ENV"';

    it("builds guest-native-execute and exports SP1_RELATION_EXECUTOR in one unconditional step", function () {
      const step = stepBlockContaining(job, BUILD);
      expect(step).to.include(EXPORT);
      expectUnconditional(step);
    });

    it("builds the executor before the Hardhat suite and before coverage", function () {
      const buildIdx = job.indexOf(BUILD);
      const testIdx = job.indexOf("run: npm test");
      const coverageIdx = job.indexOf("run: npm run coverage");
      expect(buildIdx, "executor build step not found").to.be.greaterThan(-1);
      expect(testIdx, "npm test step not found").to.be.greaterThan(buildIdx);
      expect(coverageIdx, "coverage step not found").to.be.greaterThan(buildIdx);
    });
  });
});
