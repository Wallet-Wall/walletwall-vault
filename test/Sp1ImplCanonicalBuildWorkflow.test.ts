/**
 * SP1 implementation lane: the canonical-build workflow and the CI checks (.github/workflows/sp1-canonical-build.yml,
 * scripts/sp1-canonical/ci-gate.mjs, .github/workflows/ci.yml). A static read of the comment-stripped workflow text,
 * like the repository's other workflow guards, plus the decision script run as the workflow runs it.
 *
 * Review finding L-5: a path-filtered workflow cannot be required (unrelated pull requests would wait for it), and a
 * required job downstream of a failed one is "skipped", which GitHub counts as passing. So the workflow runs for every
 * pull request, decides from the diff whether an input of the canonical build changed, runs the expensive jobs only
 * then (step conditions on the matrix job, never a job-level if:), and reports one gate that always runs and passes
 * only when every job the change requires passed. Requiring that gate is the owner's ruleset change.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, resolve } from "node:path";

import { expect } from "chai";
import { load } from "js-yaml";

const GATE_SCRIPT = "scripts/sp1-canonical/ci-gate.mjs";
const REBUILD = "needs.changes.outputs.rebuild == 'true'";

const code = (rel: string) =>
  readFileSync(resolve(rel), "utf8")
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
const jobBlock = (text: string, id: string) => {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l === `  ${id}:`);
  expect(start, `job ${id}`).to.not.equal(-1);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^ {2}[A-Za-z][\w-]*:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
};
/** The steps of a job block, each as its text from `- name:` to the next step. */
const stepsOf = (block: string) => block.split(/\n(?= {6}- name: )/).slice(1);

/** Runs the decision script as a workflow step would: `node scripts/sp1-canonical/ci-gate.mjs <command>`. */
function gateScript(command: string, env: Record<string, string>, cwd = ".") {
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(
      ([k]) =>
        !["GITHUB_OUTPUT", "EVENT", "BASE", "HEAD", "REBUILD", "CHANGES", "BUILD", "RECOMPUTE", "COMPARE"].includes(k),
    ),
  );
  return spawnSync(process.execPath, [resolve(GATE_SCRIPT), command], {
    cwd,
    env: { ...clean, ...env },
    encoding: "utf8",
  });
}

/** The relative imports of `entry`, followed through every file they name: what the checker runs. */
function importClosure(entry: string): string[] {
  const seen = new Set<string>();
  const todo = [entry];
  while (todo.length > 0) {
    const file = todo.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const m of readFileSync(resolve(file), "utf8").matchAll(
      /^\s*(?:import|export)\b[^;]*?\bfrom\s+"(\.{1,2}\/[^"]+)"/gms,
    )) {
      const target = posix.join(posix.dirname(file), m[1]);
      todo.push(target.endsWith(".ts") ? target : `${target}.ts`);
    }
  }
  return [...seen].sort();
}

describe("SP1 implementation lane — the canonical-build workflow and the CI checks", function () {
  this.timeout(60_000);
  const wf = code(".github/workflows/sp1-canonical-build.yml");
  const ci = code(".github/workflows/ci.yml");

  it("runs for every pull request, every push to main and on demand: no trigger is narrowed by paths", function () {
    expect(wf).to.match(/^on:\n {2}pull_request:\n {2}push:\n {4}branches:\n {6}- main\n {2}workflow_dispatch:$/m);
    expect(wf).to.not.match(/^ {4}paths:/m);
    expect(wf).to.match(/^permissions:\n {2}contents: read$/m);
    expect(wf).to.not.match(/secrets\./);
  });

  it("reports one gate that always runs and reads every job's result", function () {
    const gate = jobBlock(wf, "gate");
    expect(gate).to.match(/^ {4}name: SP1 canonical build gate$/m);
    expect(gate).to.match(/^ {4}needs: \[changes, build, vkey-recompute, compare\]$/m);
    expect(gate).to.match(/^ {4}if: always\(\)$/m);
    for (const [variable, expression] of [
      ["REBUILD", "needs.changes.outputs.rebuild"],
      ["CHANGES", "needs.changes.result"],
      ["BUILD", "needs.build.result"],
      ["RECOMPUTE", "needs.vkey-recompute.result"],
      ["COMPARE", "needs.compare.result"],
    ]) {
      expect(gate, variable).to.include(`${variable}: \${{ ${expression} }}`);
    }
    expect(gate).to.match(/run: node scripts\/sp1-canonical\/ci-gate\.mjs gate$/m);
    expect(wf.split("name: SP1 canonical build gate").length - 1, "one job reports the gate").to.equal(1);
  });

  it("the gate passes only when every job the change requires passed; skipped is no pass when the rebuild was required", function () {
    const passing = { CHANGES: "success", BUILD: "success", RECOMPUTE: "success", COMPARE: "success" };
    const runs: [string, Record<string, string>, number][] = [
      ["rebuild required, every job passed", { REBUILD: "true", ...passing }, 0],
      [
        "no input changed: the build steps skipped, the later jobs skipped",
        { REBUILD: "false", ...passing, RECOMPUTE: "skipped", COMPARE: "skipped" },
        0,
      ],
      ["rebuild required, a build failed", { REBUILD: "true", ...passing, BUILD: "failure" }, 1],
      [
        "rebuild required, the compare skipped (its needs failed)",
        { REBUILD: "true", ...passing, COMPARE: "skipped" },
        1,
      ],
      ["rebuild required, the recompute cancelled", { REBUILD: "true", ...passing, RECOMPUTE: "cancelled" }, 1],
      [
        "no input changed, but the build job failed",
        { REBUILD: "false", ...passing, BUILD: "failure", RECOMPUTE: "skipped", COMPARE: "skipped" },
        1,
      ],
      ["the inputs decision failed", { REBUILD: "", ...passing, CHANGES: "failure" }, 1],
      [
        "the inputs decision failed after it wrote one",
        { REBUILD: "false", ...passing, CHANGES: "failure", RECOMPUTE: "skipped", COMPARE: "skipped" },
        1,
      ],
      [
        "no input changed, but the compare ran and failed",
        { REBUILD: "false", ...passing, RECOMPUTE: "skipped", COMPARE: "failure" },
        1,
      ],
      ["no decision at all (an unknown value is no answer)", { REBUILD: "maybe", ...passing }, 1],
      ["no results at all", {}, 1],
    ];
    for (const [label, env, status] of runs) {
      const r = gateScript("gate", env);
      expect(r.status, `${label}: ${r.stdout}${r.stderr}`).to.equal(status);
    }
  });

  it("decides from the diff: every file the checker imports, the subject, the designations, their evidence, the procedure and the workflow are inputs", function () {
    const r = gateScript("inputs", {});
    expect(r.status, r.stderr).to.equal(0);
    expect(JSON.parse(r.stdout)).to.be.an("array").that.is.not.empty;
    // The script's own matcher decides, so this test cannot drift from it.
    const covered = (path: string) => {
      const m = spawnSync(process.execPath, [resolve(GATE_SCRIPT), "match", path], { encoding: "utf8" });
      expect(m.status, m.stderr).to.equal(0);
      return (JSON.parse(m.stdout) as string[]).includes(path);
    };
    const closure = importClosure("scripts/check-sp1-canonical-build.ts");
    expect(closure).to.include.members(["scripts/lib/sp1-canonical-build.ts", "scripts/lib/sp1-designation.ts"]);
    for (const file of closure) expect(covered(file), `${file} (the checker imports it)`).to.equal(true);
    for (const path of [
      // git archive honours export-ignore and export-subst wherever a .gitattributes says so (the re-review's A5).
      ".gitattributes",
      "zkvm/.gitattributes",
      "zkvm/guest/src/bin/withdrawal.rs",
      "zkvm/host/Cargo.lock",
      "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json",
      "evidence/zk/sp1/designation-evidence/mldsa65-withdrawal-d2.json",
      "evidence/zk/sp1-td1/canonical-procedure/host-build-in-container.sh",
      "scripts/sp1-canonical/canonical-build.sh",
      GATE_SCRIPT,
      ".github/workflows/sp1-canonical-build.yml",
      "package.json",
      "package-lock.json",
    ]) {
      expect(covered(path), path).to.equal(true);
    }
    for (const path of [
      "README.md",
      "docs/ZK_Prover_Runbook.md",
      "contracts/ZKMLDSAVerifier.sol",
      "scripts/lib/sp1-registry.ts",
    ]) {
      expect(covered(path), `${path} is no input`).to.equal(false);
    }
  });

  describe("the inputs decision, run on a repository", function () {
    let repo: string;
    let base: string;
    let subject: string;
    let docs: string;
    const git = (...args: string[]) =>
      execFileSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: repo, encoding: "utf8" }).trim();
    const commit = (rel: string, content: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), content);
      git("add", "-A");
      git("-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", rel);
      return git("rev-parse", "HEAD");
    };
    before(function () {
      repo = mkdtempSync(join(tmpdir(), "sp1-canonical-inputs-"));
      git("init", "-q", "-b", "main");
      base = commit("README.md", "base\n");
      subject = commit("zkvm/guest/src/bin/withdrawal.rs", "fn main() {}\n");
      docs = commit("docs/notes.md", "notes\n");
    });
    after(function () {
      rmSync(repo, { recursive: true, force: true });
    });
    const decide = (env: Record<string, string>) => {
      const out = join(repo, "..", `${Math.random().toString(16).slice(2)}.out`);
      writeFileSync(out, "");
      const r = gateScript("changed", { ...env, GITHUB_OUTPUT: out }, repo);
      const written = readFileSync(out, "utf8");
      rmSync(out, { force: true });
      return { status: r.status, output: written, log: `${r.stdout}${r.stderr}` };
    };

    it("a pull request that changes an input rebuilds; one that changes none skips", function () {
      expect(decide({ EVENT: "pull_request", BASE: base, HEAD: subject })).to.deep.include({
        status: 0,
        output: "rebuild=true\n",
      });
      expect(decide({ EVENT: "pull_request", BASE: subject, HEAD: docs })).to.deep.include({
        status: 0,
        output: "rebuild=false\n",
      });
      expect(decide({ EVENT: "push", BASE: base, HEAD: docs }).output, "a push carrying an input").to.equal(
        "rebuild=true\n",
      );
    });

    it("sees an input moved out of the subject, a name git would quote, and a .gitattributes (the re-review's A5)", function () {
      const before = commit("zkvm/guest/src/extra.rs", "// extra\n");
      git("mv", "zkvm/guest/src/extra.rs", "extra.rs");
      git("-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", "move out");
      const moved = git("rev-parse", "HEAD");
      expect(decide({ EVENT: "pull_request", BASE: before, HEAD: moved }).output, "moved out").to.equal(
        "rebuild=true\n",
      );
      const quoted = commit("zkvm/guest/src/ñ.rs", "// a name git quotes\n");
      expect(decide({ EVENT: "pull_request", BASE: moved, HEAD: quoted }).output, "a quoted name").to.equal(
        "rebuild=true\n",
      );
      const attributes = commit(".gitattributes", "zkvm/guest/src/extra.rs export-ignore\n");
      expect(decide({ EVENT: "pull_request", BASE: quoted, HEAD: attributes }).output, ".gitattributes").to.equal(
        "rebuild=true\n",
      );
    });

    it("on demand, and for a push with no base (a new branch), it rebuilds", function () {
      expect(decide({ EVENT: "workflow_dispatch", BASE: "", HEAD: "" }).output).to.equal("rebuild=true\n");
      expect(decide({ EVENT: "push", BASE: "0".repeat(40), HEAD: docs }).output).to.equal("rebuild=true\n");
    });

    it("a diff that cannot be made is no answer: the job fails, and writes no decision", function () {
      for (const env of [
        { EVENT: "pull_request", BASE: "1".repeat(40), HEAD: docs },
        { EVENT: "pull_request", BASE: "", HEAD: docs },
        { EVENT: "pull_request", BASE: "not-a-commit; rm -rf /", HEAD: docs },
      ]) {
        const r = decide(env);
        expect(r.status, JSON.stringify(env)).to.not.equal(0);
        expect(r.output, JSON.stringify(env)).to.equal("");
      }
    });
  });

  it("the expensive jobs run only when an input changed, through step conditions on the matrix job, never a job-level if:", function () {
    const changes = jobBlock(wf, "changes");
    expect(changes).to.match(/^ {6}rebuild: \$\{\{ steps\.decide\.outputs\.rebuild \}\}$/m);
    expect(changes).to.match(/fetch-depth: 0/);
    expect(changes).to.match(/id: decide/);
    expect(changes).to.include("EVENT: ${{ github.event_name }}");
    expect(changes).to.include("BASE: ${{ github.event.pull_request.base.sha || github.event.before }}");
    expect(changes).to.include("HEAD: ${{ github.event.pull_request.head.sha || github.sha }}");
    expect(changes).to.match(/run: node scripts\/sp1-canonical\/ci-gate\.mjs changed$/m);
    const build = jobBlock(wf, "build");
    expect(build).to.match(/^ {4}needs: changes$/m);
    // Nothing to rebuild needs neither pinned runner image: a retired label cannot fail every pull request (L4).
    expect(build).to.include(
      "runs-on: ${{ needs.changes.outputs.rebuild == 'true' && matrix.runner || 'ubuntu-latest' }}",
    );
    expect(build, "no job-level if: on the matrix job").to.not.match(/^ {4}if:/m);
    const steps = stepsOf(build);
    expect(steps).to.have.length.greaterThan(3);
    for (const step of steps) expect(step, step.split("\n")[0]).to.include(REBUILD);
    for (const id of ["vkey-recompute", "compare"]) {
      const job = jobBlock(wf, id);
      expect(job, id).to.match(new RegExp(`^ {4}if: ${REBUILD.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
      expect(job, id).to.match(/^ {4}needs: \[changes, /m);
    }
  });

  it("builds on two runners, in the vendor image the designation pins (never a tag in the workflow)", function () {
    const build = jobBlock(wf, "build");
    expect(build).to.match(/include:\n {10}- runner: ubuntu-24\.04\n {10}- runner: ubuntu-22\.04/);
    expect(build).to.match(
      /bash scripts\/sp1-canonical\/canonical-build\.sh "\$RUNNER_TEMP\/canonical" "github-\$\{\{ matrix\.runner \}\}"/,
    );
    expect(wf.includes("ghcr.io/succinctlabs/sp1"), "the workflow names no vendor image; the driver reads it").to.equal(
      false,
    );
    const driver = readFileSync(resolve("scripts/sp1-canonical/canonical-build.sh"), "utf8");
    expect(driver).to.match(/IMAGE="\$\(field procedure\.image\)"/);
    expect(driver).to.match(/case "\$IMAGE" in \*@sha256:\*\)/);
    expect(driver).to.match(/if \[ "\$ACTUAL_SHA" != "\$ENTRYPOINT_SHA" \]; then/);
    expect(driver).to.match(/lock-before\.txt[\s\S]*bash \/root\/host-build-in-container\.sh[\s\S]*lock-after\.txt/);
    expect(driver).to.match(/docker create --name "\$C" --platform linux\/amd64 -w \/root "\$IMAGE"/);
    const dockerRuns = driver.split("\n").filter((l) => /\bdocker (create|run)\b/.test(l));
    expect(dockerRuns).to.have.length(1);
    for (const line of dockerRuns) expect(line, "no bind mount or volume").to.not.match(/ -v | --volume| --mount/);
  });

  it("the driver records what ran, and fails when a build that exited 0 left an output missing (L-4)", function () {
    const driver = readFileSync(resolve("scripts/sp1-canonical/canonical-build.sh"), "utf8");
    expect(driver, "no output copy may fail silently").to.not.match(/\|\| true/);
    expect(driver).to.not.match(/2> \/dev\/null \|\|/);
    // What ran, measured by the driver itself: its own bytes, the designation file, the image, the entrypoint copy.
    for (const key of [
      "driver_sha256",
      "designation",
      "image",
      "entrypoint",
      "entrypoint_sha256",
      "started_utc",
      "finished_utc",
    ]) {
      expect(driver, key).to.match(new RegExp(`${key}=`));
    }
    expect(driver).to.match(/sha256sum "\$\{BASH_SOURCE\[0\]\}"/);
    // Every copy failure is collected; the container is always removed; a zero exit with an output missing fails.
    expect(driver).to.match(/\|\| MISSING="\$MISSING /);
    expect(driver).to.match(/docker rm "\$C" > \/dev\/null/);
    expect(driver).to.match(
      /if \[ "\$RC" -ne 0 \]; then[\s\S]*exit "\$RC"[\s\S]*if \[ -n "\$MISSING" \]; then[\s\S]*exit 5/,
    );
    expect(driver).to.match(/docker pull "\$IMAGE" > "\$OUT\/pull\.log" 2>&1 \|\| \{/);
  });

  it("recomputes the vkey on another runner from the ELFs alone, with the released cargo-prove verified by digest", function () {
    const recompute = jobBlock(wf, "vkey-recompute");
    expect(recompute).to.match(/needs: \[changes, build\]/);
    expect(recompute).to.match(
      /cargo_prove_v6\.3\.1_linux_amd64\.tar\.gz[\s\S]*echo "c9d6ee7667fa9e0a2302324a6bb0295c55f6acf0e17a242ad11ee45767bb08df {2}cargo-prove\.tar\.gz" \| sha256sum -c -/,
    );
    expect(recompute).to.match(/prove vkey --elf "\$elf"/);
    expect(recompute).to.not.match(/actions\/checkout/);
    // Every value is assigned before it is written, so set -e sees a failing command; a missing ELF fails the step.
    expect(
      recompute.split("\n").filter((l) => /echo "[^"]*\$\(/.test(l)),
      "no $(...) inside an echo",
    ).to.deep.equal([]);
    expect(recompute).to.match(/test -s "\$elf" \|\| \{/);
    expect(recompute).to.match(/for runner in ubuntu-24\.04 ubuntu-22\.04; do/);
  });

  it("fails unless both hosts and the recompute reproduce the designation", function () {
    const compare = jobBlock(wf, "compare");
    expect(compare).to.match(/needs: \[changes, build, vkey-recompute\]/);
    expect(compare).to.match(/npx tsx scripts\/check-sp1-canonical-build\.ts/);
    expect(compare.match(/--build github-ubuntu-2\d\.04=artifacts\/canonical-build-ubuntu-2\d\.04/g)).to.have.length(2);
    expect(compare.match(/--recompute artifacts\/vkey-recompute\//g)).to.have.length(2);
    expect(compare).to.match(/--min-hosts 2/);
    // The observation and its raw records, in the committed evidence's layout, uploaded whatever the verdict.
    expect(compare).to.match(/--records "\$RUNNER_TEMP\/canonical-rebuild-github"/);
    expect(compare).to.match(/name: canonical-rebuild-evidence/);
  });

  it("CI runs the cheap checks on every pull request: builds, designations (the subject tripwire), registry history, proving availability, the receipt, a locked guest", function () {
    const buildTest = jobBlock(ci, "build-test");
    for (const command of [
      "npm run validate:sp1-wrapper-build",
      "npm run validate:sp1-designation",
      "npm run validate:sp1-registry",
      "npm run validate:sp1-proving-availability",
      "npm run validate:sp1-impl-receipt",
    ]) {
      expect(buildTest, command).to.include(command);
    }
    expect(buildTest).to.match(/fetch-depth: 0/);
    expect(jobBlock(ci, "zkvm-guest")).to.match(/cargo check --locked --manifest-path zkvm\/guest\/Cargo\.toml/);
  });

  it("every workflow parses as YAML (a text read cannot see that GitHub would refuse the file)", function () {
    const dir = resolve(".github/workflows");
    const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));
    expect(files).to.include.members(["ci.yml", "sp1-canonical-build.yml"]);
    for (const f of files) {
      const doc = load(readFileSync(resolve(dir, f), "utf8")) as { jobs?: unknown };
      expect(doc?.jobs, f).to.be.an("object");
    }
  });
});
