#!/usr/bin/env node
// The two decisions of the SP1 canonical build workflow (.github/workflows/sp1-canonical-build.yml; the SP1
// implementation lane, review finding L-5; docs/SP1_Implementation_Pin_Designation_Registry.md). Dependency-free, so
// a job runs it right after checkout.
//
//   node scripts/sp1-canonical/ci-gate.mjs inputs    the paths whose change requires the rebuild, as JSON
//   node scripts/sp1-canonical/ci-gate.mjs match <path>...   which of the paths are inputs, as JSON
//   node scripts/sp1-canonical/ci-gate.mjs changed   from EVENT, BASE, HEAD: rebuild=true|false, to $GITHUB_OUTPUT
//   node scripts/sp1-canonical/ci-gate.mjs gate      from REBUILD, CHANGES, BUILD, RECOMPUTE, COMPARE: exit 0 or 1
//
// The workflow runs for every pull request, so its one gate can be required without leaving unrelated pull requests
// pending; the expensive jobs run only when an input changed. A decision that cannot be made (a diff that fails, a
// result that is not a known one) fails: it is never read as "nothing changed" or as a pass.
//
// Research prototype. Not audited. Testnet/local only. Do not use real funds.
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/**
 * What the canonical build reads: the subject, the designations and their evidence, SP1-TD1's procedure, this
 * driver, the workflow, every file the checker imports (test/Sp1ImplCanonicalBuildWorkflow.test.ts follows the
 * imports and fails on one missing here), the packages that run it, and every .gitattributes (git archive honours
 * export-ignore and export-subst). A pattern ending in a slash and two stars is everything under that directory; one
 * starting with two stars and a slash is a file of that name in any directory.
 */
export const INPUTS = [
  "zkvm/guest/**",
  "zkvm/host/**",
  "evidence/zk/sp1/designations/**",
  "evidence/zk/sp1/designation-evidence/**",
  "evidence/zk/sp1-td1/canonical-procedure/**",
  "scripts/sp1-canonical/**",
  "scripts/check-sp1-canonical-build.ts",
  "scripts/lib/reproducibility-evidence.ts",
  "scripts/lib/sp1-canonical-build.ts",
  "scripts/lib/sp1-designation.ts",
  "scripts/lib/sp1-p1-stop-receipt.ts",
  "scripts/lib/sp1-td1-decision.ts",
  "scripts/lib/sp1-wrapper-build.ts",
  ".github/workflows/sp1-canonical-build.yml",
  "package.json",
  "package-lock.json",
  "**/.gitattributes",
];

/** The changed paths that are inputs of the canonical build. */
export function inputsAmong(paths) {
  return paths.filter((path) =>
    INPUTS.some((p) =>
      p.startsWith("**/")
        ? path === p.slice(3) || path.endsWith(`/${p.slice(3)}`)
        : p.endsWith("/**")
          ? path.startsWith(p.slice(0, -2))
          : path === p,
    ),
  );
}

const COMMIT = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const NO_COMMIT = /^0+$/;

/** Whether the canonical build must run for this event: true unless a diff shows no input changed. */
function rebuildFor(env) {
  const event = env.EVENT ?? "";
  if (event !== "pull_request" && event !== "push") {
    return { rebuild: true, why: `event ${event || "(none)"}: the canonical build runs on demand` };
  }
  const base = env.BASE ?? "";
  const head = env.HEAD ?? "";
  if (event === "push" && NO_COMMIT.test(base) && COMMIT.test(head)) {
    return { rebuild: true, why: "a push with no previous commit to compare with" };
  }
  if (!COMMIT.test(base) || !COMMIT.test(head)) {
    throw new Error(`cannot decide: ${event} needs two commits to compare (base "${base}", head "${head}")`);
  }
  // No rename detection (a file moved out of an input is a deletion there) and NUL-separated names (never quoted).
  const changed = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", `${base}...${head}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  })
    .split("\0")
    .filter(Boolean);
  const inputs = inputsAmong(changed);
  return inputs.length > 0
    ? { rebuild: true, why: `inputs changed:\n  ${inputs.join("\n  ")}` }
    : { rebuild: false, why: `no input of the canonical build changed (${changed.length} files changed)` };
}

/** Why the workflow does not pass; empty when every job the change requires passed. */
export function gateProblems(env) {
  const result = (key) => env[key] ?? "";
  const named = (key) => result(key) || "no result";
  const problems = [];
  const rebuild = result("REBUILD");
  if (result("CHANGES") !== "success") problems.push(`the inputs decision did not succeed (${named("CHANGES")})`);
  if (rebuild !== "true" && rebuild !== "false") problems.push(`no rebuild decision (${rebuild || "none"})`);
  if (result("BUILD") !== "success") problems.push(`build: ${named("BUILD")}`);
  for (const [key, job] of [
    ["RECOMPUTE", "vkey-recompute"],
    ["COMPARE", "compare"],
  ]) {
    if (rebuild === "true" && result(key) !== "success") {
      problems.push(`${job}: ${named(key)}, but the rebuild was required`);
    } else if (rebuild === "false" && !["success", "skipped"].includes(result(key))) {
      problems.push(`${job}: ${named(key)}`);
    }
  }
  return problems;
}

function main(command) {
  if (command === "inputs") {
    process.stdout.write(`${JSON.stringify(INPUTS)}\n`);
    return 0;
  }
  if (command === "match") {
    process.stdout.write(`${JSON.stringify(inputsAmong(process.argv.slice(3)))}\n`);
    return 0;
  }
  if (command === "changed") {
    const { rebuild, why } = rebuildFor(process.env);
    console.log(`rebuild=${rebuild}: ${why}`);
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `rebuild=${rebuild}\n`);
    return 0;
  }
  if (command === "gate") {
    const problems = gateProblems(process.env);
    const seen = ["REBUILD", "CHANGES", "BUILD", "RECOMPUTE", "COMPARE"].map((k) => `${k}=${process.env[k] ?? ""}`);
    console.log(seen.join(" "));
    if (problems.length > 0) {
      console.error(`the SP1 canonical build gate fails:\n - ${problems.join("\n - ")}`);
      return 1;
    }
    console.log("the SP1 canonical build gate passes");
    return 0;
  }
  console.error("usage: ci-gate.mjs inputs | match <path>... | changed | gate");
  return 2;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv[2]);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
