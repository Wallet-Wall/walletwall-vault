/**
 * SP1 implementation lane: the canonical-build workflow and the CI checks (.github/workflows/sp1-canonical-build.yml,
 * .github/workflows/ci.yml). A static read of the comment-stripped workflow text, like the repository's other
 * workflow guards: what each job runs, what it is pinned to, and when it runs.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

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

describe("SP1 implementation lane — the canonical-build workflow and the CI checks", function () {
  const wf = code(".github/workflows/sp1-canonical-build.yml");
  const ci = code(".github/workflows/ci.yml");

  it("runs when the subject, a designation or the procedure changes, on main after such a merge, and on demand", function () {
    for (const path of [
      "zkvm/guest/**",
      "zkvm/host/**",
      "evidence/zk/sp1/designations/**",
      "evidence/zk/sp1-td1/canonical-procedure/**",
      "scripts/sp1-canonical/**",
      ".github/workflows/sp1-canonical-build.yml",
    ]) {
      expect(wf.split(`- "${path}"`).length - 1, path).to.equal(2);
    }
    expect(wf).to.match(/^ {2}pull_request:$/m);
    expect(wf).to.match(/^ {2}push:\n {4}branches:\n {6}- main$/m);
    expect(wf).to.match(/^ {2}workflow_dispatch:$/m);
    expect(wf).to.match(/^permissions:\n {2}contents: read$/m);
    expect(wf).to.not.match(/secrets\./);
  });

  it("builds on two runners, in the vendor image the designation pins (never a tag in the workflow)", function () {
    const build = jobBlock(wf, "build");
    expect(build).to.match(/include:\n {10}- runner: ubuntu-24\.04\n {10}- runner: ubuntu-22\.04/);
    expect(build).to.match(
      /bash scripts\/sp1-canonical\/canonical-build\.sh "\$RUNNER_TEMP\/canonical" "github-\$\{\{ matrix\.runner \}\}"/,
    );
    expect(wf).to.not.match(/ghcr\.io\/succinctlabs\/sp1/);
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

  it("recomputes the vkey on another runner from the ELFs alone, with the released cargo-prove verified by digest", function () {
    const recompute = jobBlock(wf, "vkey-recompute");
    expect(recompute).to.match(/needs: build/);
    expect(recompute).to.match(
      /cargo_prove_v6\.3\.1_linux_amd64\.tar\.gz[\s\S]*echo "c9d6ee7667fa9e0a2302324a6bb0295c55f6acf0e17a242ad11ee45767bb08df {2}cargo-prove\.tar\.gz" \| sha256sum -c -/,
    );
    expect(recompute).to.match(/prove vkey --elf "\$build\/elf\/\$p"/);
    expect(recompute).to.not.match(/actions\/checkout/);
  });

  it("fails unless both hosts and the recompute reproduce the designation", function () {
    const compare = jobBlock(wf, "compare");
    expect(compare).to.match(/needs: \[build, vkey-recompute\]/);
    expect(compare).to.match(/npx tsx scripts\/check-sp1-canonical-build\.ts/);
    expect(compare.match(/--build github-ubuntu-2\d\.04=artifacts\/canonical-build-ubuntu-2\d\.04/g)).to.have.length(2);
    expect(compare.match(/--recompute artifacts\/vkey-recompute\//g)).to.have.length(2);
    expect(compare).to.match(/--min-hosts 2/);
  });

  it("CI runs the cheap checks on every pull request: builds, designations (the subject tripwire), registry history, a locked guest", function () {
    const buildTest = jobBlock(ci, "build-test");
    for (const command of [
      "npm run validate:sp1-wrapper-build",
      "npm run validate:sp1-designation",
      "npm run validate:sp1-registry",
    ]) {
      expect(buildTest, command).to.include(command);
    }
    expect(buildTest).to.match(/fetch-depth: 0/);
    expect(jobBlock(ci, "zkvm-guest")).to.match(/cargo check --locked --manifest-path zkvm\/guest\/Cargo\.toml/);
  });
});
