/**
 * The RustSec drift workflow (.github/workflows/rustsec-audit.yml) and the measurement it runs
 * (scripts/measure-sp1-host-advisories.ts): a networked, reporting-only job that must never block an unrelated merge,
 * never change a lockfile, never read an outage as clean, and measure with exactly the pinned cargo-audit.
 *
 * Static reads of the comment-stripped workflow and of the measurement script (which needs the network, so no test
 * runs it); no YAML parser, as in test/CIValidatorCoverage.test.ts.
 */
import { expect } from "chai";
import { readFileSync } from "node:fs";

import {
  ADVISORY_OBSERVATION_REL,
  CARGO_AUDIT_VERSION,
  preciseProbeCommand,
  updateProbeCommand,
} from "../scripts/lib/sp1-host-advisories";

const WORKFLOW = ".github/workflows/rustsec-audit.yml";
const stripComments = (text: string) =>
  text
    .split("\n")
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");
const code = stripComments(readFileSync(WORKFLOW, "utf8"));
const lines = code.split("\n");

/** The step whose `- name:` line contains `name`, up to the next step. */
function step(name: string): string {
  const start = lines.findIndex((l) => /^\s*- name:/.test(l) && l.includes(name));
  expect(start, `step "${name}" not found`).to.be.greaterThan(-1);
  let end = start + 1;
  while (end < lines.length && !/^\s*- name:/.test(lines[end])) end++;
  return lines.slice(start, end).join("\n");
}
const indexOfStep = (name: string) => lines.findIndex((l) => /^\s*- name:/.test(l) && l.includes(name));

const PATHS = [
  "zkvm/**/Cargo.toml",
  "zkvm/**/Cargo.lock",
  "evidence/zk/sp1-impl/host-lockfile-advisories.json",
  "evidence/zk/sp1-impl/observations/host-advisories-*.raw.json",
  "scripts/lib/sp1-host-advisories.ts",
  "scripts/measure-sp1-host-advisories.ts",
  "scripts/check-rustsec-drift.ts",
  ".github/workflows/rustsec-audit.yml",
];

function pathsUnder(trigger: string): string[] {
  const start = lines.findIndex((l) => l === `  ${trigger}:`);
  expect(start, `trigger ${trigger} not found`).to.be.greaterThan(-1);
  const out: string[] = [];
  let i = lines.indexOf("    paths:", start);
  expect(i, `${trigger} has no paths filter`).to.be.greaterThan(start);
  for (i++; i < lines.length && lines[i].startsWith("      - "); i++) out.push(lines[i].slice(8).replace(/^"|"$/g, ""));
  return out;
}

describe("RustSec drift workflow — triggers, token and actions", function () {
  it("runs weekly on a schedule, because RustSec changes while the repository does not", function () {
    const crons = [...code.matchAll(/^\s+- cron: "([^"]+)"$/gm)].map((m) => m[1]);
    expect(crons).to.have.length(1);
    const [min, hour, dom, month, dow] = crons[0].split(" ");
    expect([dom, month]).to.deep.equal(["*", "*"]);
    expect(dow).to.match(/^[0-6]$/);
    expect(Number(min)).to.be.within(0, 59);
    expect(Number(hour)).to.be.within(0, 23);
    expect(code).to.match(/^ {2}workflow_dispatch:\s*$/m);
  });

  it("runs on pull requests and main pushes only when a Rust manifest or lockfile, the record or its tooling changes", function () {
    expect(pathsUnder("pull_request")).to.deep.equal(PATHS);
    expect(pathsUnder("push")).to.deep.equal(PATHS);
    expect(code).to.match(/^ {2}push:\n {4}branches:\n {6}- main$/m);
  });

  it("holds a read-only token, and no job widens it", function () {
    expect(code).to.match(/^permissions:\n {2}contents: read$/m);
    expect(code.match(/permissions:/g)).to.have.length(1);
    expect(code).to.not.match(/:\s*write\b/);
  });

  it("uses only GitHub's own actions (no third-party action)", function () {
    const uses = [...code.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
    expect(uses.length).to.be.greaterThan(0);
    for (const u of uses) expect(u, u).to.match(/^actions\/(checkout|setup-node|upload-artifact)@v\d+$/);
  });

  it("has one plain job: no matrix, no job-level if, no continue-on-error", function () {
    expect(code).to.not.match(/strategy:|matrix:/);
    expect(code).to.not.match(/^ {4}if:/m);
    expect(code).to.not.match(/continue-on-error/);
  });
});

describe("RustSec drift workflow — measuring and reconciling", function () {
  it("installs exactly the pinned cargo-audit: the release the measurement refuses to run without", function () {
    expect(code).to.include(`CARGO_AUDIT_VERSION: "${CARGO_AUDIT_VERSION}"`);
    expect(step("pinned cargo-audit")).to.include(
      'cargo install cargo-audit --version "=${CARGO_AUDIT_VERSION}" --locked',
    );
    const obs = JSON.parse(readFileSync(ADVISORY_OBSERVATION_REL, "utf8")) as { tool: { cargoAudit: string } };
    expect(obs.tool.cargoAudit.endsWith(` ${CARGO_AUDIT_VERSION}`), obs.tool.cargoAudit).to.equal(true);
  });

  it("fetches the advisory database and the locked crates in their own steps, before measuring", function () {
    const db = step("Fetch the RustSec advisory database");
    expect(db).to.include('git clone --depth 1 https://github.com/rustsec/advisory-db.git "$RUNNER_TEMP/advisory-db"');
    expect(db).to.include("a failure here is not a finding");
    const crates = step("Fetch the locked crates");
    expect(crates).to.include('cargo fetch --locked --manifest-path "zkvm/$crate/Cargo.toml"');
    for (const c of ["host", "guest", "relation-tests", "evidence-validator"]) expect(crates).to.include(c);
    const measure = step("Measure");
    expect(measure).to.include('--db "$RUNNER_TEMP/advisory-db"');
    expect(measure).to.include('--out "$RUNNER_TEMP/rustsec-live.json"');
    expect(indexOfStep("Fetch the RustSec advisory database")).to.be.lessThan(indexOfStep("Measure"));
    expect(indexOfStep("Fetch the locked crates")).to.be.lessThan(indexOfStep("Measure"));
  });

  it("reconciles even after a failed measurement, so an outage is reported as AUDIT_UNAVAILABLE, never skipped", function () {
    const r = step("Reconcile");
    expect(r).to.include('npx tsx scripts/check-rustsec-drift.ts --live "$RUNNER_TEMP/rustsec-live.json"');
    expect(r).to.include("if: ${{ !cancelled() }}");
    expect(indexOfStep("Measure")).to.be.lessThan(indexOfStep("Reconcile"));
  });

  it("changes nothing: no commit, push or lockfile-writing cargo command", function () {
    expect(code).to.not.match(/git (commit|push|tag)|gh (pr|release)|cargo update|cargo generate-lockfile/);
    expect(updateProbeCommand("x@1.0.0")).to.include("--dry-run");
    expect(preciseProbeCommand("x@1.0.0", "1.0.1")).to.include("--dry-run");
  });

  it("is not a required status check, and the blocking CI never runs the networked audit", function () {
    const name = /^\s+name: (.+)$/m.exec(code.slice(code.indexOf("jobs:")))?.[1] as string;
    expect(name).to.include("not a required check");
    const ruleset = JSON.parse(readFileSync("evidence/zk/sp1-impl/observations/main-ruleset.raw.json", "utf8"));
    const required = ruleset.response.rules
      .filter((r: { type: string }) => r.type === "required_status_checks")
      .flatMap((r: { parameters: { required_status_checks: { context: string }[] } }) =>
        r.parameters.required_status_checks.map((c) => c.context),
      );
    expect(required.length).to.be.greaterThan(0);
    expect(required).to.not.include(name);
    const ci = stripComments(readFileSync(".github/workflows/ci.yml", "utf8"));
    expect(ci).to.not.match(/cargo audit|cargo-audit|rustsec-audit|measure-sp1-host-advisories|check-rustsec-drift/);
    expect(ci).to.include("npm run validate:sp1-host-advisories");
  });
});

describe("RustSec drift workflow — the measurement fails closed", function () {
  const script = readFileSync("scripts/measure-sp1-host-advisories.ts", "utf8");

  it("runs cargo audit against the named database only, without its own yanked check or fetch", function () {
    expect(script).to.include('["audit", "--json", "--no-yanked", "--no-fetch", "--db", db, "--file"');
  });

  it("refuses an advisory database checkout that is not exactly its commit", function () {
    expect(script).to.include('["-C", db, "status", "--porcelain", "--untracked-files=all"]');
    expect(script).to.include("is not a clean checkout of");
  });

  it("measures a git-archive copy of HEAD's zkvm/, refusing a working tree that differs", function () {
    expect(script).to.include('["archive", "--format=tar", "HEAD", "zkvm"]');
    expect(script).to.include('["status", "--porcelain", "--untracked-files=all", "--", "zkvm"]');
    expect(script).to.include("measure a committed tree");
  });

  it("reads yanked status from the crates.io index and fails when the index does not answer", function () {
    expect(script).to.include("yanked status unmeasured");
    expect(script).to.match(/AbortSignal\.timeout\(/);
  });

  it("refuses any cargo-audit but the pinned release", function () {
    expect(script).to.include("measure with cargo-audit ${CARGO_AUDIT_VERSION}");
  });
});
