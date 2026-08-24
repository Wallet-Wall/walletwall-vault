/**
 * Blocker A (source-commit -> build-capture binding) — behavioral tests
 * against the ACTUAL `capture-build` CLI entry point, using a real temporary
 * git repository. Before this fix, `capture-build` accepted an arbitrary
 * operator-supplied `--commit`/`--head-commit` label and recorded it
 * verbatim, with no check that the label matched where the build was
 * actually compiled — so a manifest and its evidence bundle could be edited
 * together and still "agree". These tests prove the closed behavior
 * directly: a mismatched label is rejected, a dirty tree is rejected, and a
 * correct capture succeeds and records the ACTUAL git-derived commit (not
 * the operator's label).
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect } from "chai";

import { captureBuild } from "../scripts/reproducibility-evidence";
import type { EvidenceBundle } from "../scripts/lib/reproducibility-evidence";

function git(args: string[], cwd: string): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

/**
 * A minimal, valid-shaped solc build-info: just enough for loadContractOutput
 * (compiler settings, one contract's deployedBytecode, output.sources for the
 * compiled-file list) — no real solc invocation involved.
 *
 * The git repo lives at `<dir>/repo` (the `--cwd` target); build-info.json and
 * evidence.json are written OUTSIDE it (directly under `dir`), deliberately
 * untracked, so a test can freely rewrite build-info.json without dirtying
 * the git tree it's supposed to be describing.
 */
function writeFixtureRepo(dir: string): { commit: string; repoDir: string; buildInfoPath: string; outPath: string } {
  const repoDir = join(dir, "repo");
  mkdirSync(repoDir, { recursive: true });
  git(["init", "--initial-branch=main"], repoDir);
  git(["config", "user.email", "test@example.com"], repoDir);
  git(["config", "user.name", "Test"], repoDir);
  mkdirSync(join(repoDir, "contracts"), { recursive: true });
  writeFileSync(
    join(repoDir, "contracts/Dummy.sol"),
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Dummy {}\n",
  );
  const buildInfo = {
    solcLongVersion: "0.8.24+commit.e11b9ed9",
    input: { settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun" } },
    output: {
      sources: { "contracts/Dummy.sol": {} },
      contracts: {
        "contracts/Dummy.sol": {
          Dummy: { evm: { deployedBytecode: { object: "6080604052", immutableReferences: {} } } },
        },
      },
    },
  };
  const buildInfoPath = join(dir, "build-info.json");
  writeFileSync(buildInfoPath, JSON.stringify(buildInfo));
  git(["add", "-A"], repoDir);
  git(["commit", "-m", "init"], repoDir);
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoDir, encoding: "utf8" }).trim();
  return { commit, repoDir, buildInfoPath, outPath: join(dir, "evidence.json") };
}

describe("capture-build — Blocker A: source-commit binding is verified, not asserted", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "repro-capture-build-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("RED (the gap this closes): a --commit label that does NOT match the actual checked-out HEAD is rejected, not silently recorded", () => {
    const { repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);
    const fabricatedCommit = "0".repeat(40); // definitely not the real HEAD

    expect(() =>
      captureBuild({
        subject: "Dummy",
        slot: "deployment-commit",
        cwd: repoDir,
        commit: fabricatedCommit,
        "source-file": "contracts/Dummy.sol",
        "contract-name": "Dummy",
        "build-info": buildInfoPath,
        out: outPath,
      }),
    ).to.throw(/does not match where it was actually compiled/);
  });

  it("GREEN: a --commit label matching the actual HEAD succeeds, and the evidence records the git-DERIVED commit", () => {
    const { commit, repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);

    captureBuild({
      subject: "Dummy",
      slot: "deployment-commit",
      cwd: repoDir,
      commit,
      "source-file": "contracts/Dummy.sol",
      "contract-name": "Dummy",
      "build-info": buildInfoPath,
      out: outPath,
    });

    const evidence = JSON.parse(readFileSync(outPath, "utf8")) as EvidenceBundle;
    expect(evidence.deploymentCommitBuild.commit).to.equal(commit);
    expect(evidence.deploymentCommitBuild.sourceDigests).to.have.property("contracts/Dummy.sol");
  });

  it("GREEN: omitting --commit entirely still binds to the actual git HEAD (no label to trust or distrust)", () => {
    const { commit, repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);

    captureBuild({
      subject: "Dummy",
      slot: "deployment-commit",
      cwd: repoDir,
      "source-file": "contracts/Dummy.sol",
      "contract-name": "Dummy",
      "build-info": buildInfoPath,
      out: outPath,
    });

    const evidence = JSON.parse(readFileSync(outPath, "utf8")) as EvidenceBundle;
    expect(evidence.deploymentCommitBuild.commit).to.equal(commit);
  });

  it("public-head slot: a --head-commit label that does not match actual HEAD is rejected the same way", () => {
    const { repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);
    expect(() =>
      captureBuild({
        subject: "Dummy",
        slot: "public-head",
        cwd: repoDir,
        "head-commit": "1".repeat(40),
        "source-file": "contracts/Dummy.sol",
        "contract-name": "Dummy",
        "build-info": buildInfoPath,
        out: outPath,
      }),
    ).to.throw(/does not match where it was actually compiled/);
  });

  it("a dirty tracked working tree is rejected — a build capture must come from a clean, committed state", () => {
    const { commit, repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);
    // Modify a TRACKED file without committing.
    writeFileSync(join(repoDir, "contracts/Dummy.sol"), "// modified, uncommitted\n");

    expect(() =>
      captureBuild({
        subject: "Dummy",
        slot: "deployment-commit",
        cwd: repoDir,
        commit,
        "source-file": "contracts/Dummy.sol",
        "contract-name": "Dummy",
        "build-info": buildInfoPath,
        out: outPath,
      }),
    ).to.throw(/not clean/);
  });

  it("a source file the build-info claims to have compiled, but which is missing from disk, is rejected", () => {
    const { commit, repoDir, buildInfoPath, outPath } = writeFixtureRepo(dir);
    const buildInfo = JSON.parse(readFileSync(buildInfoPath, "utf8"));
    buildInfo.output.sources["contracts/Missing.sol"] = {};
    writeFileSync(buildInfoPath, JSON.stringify(buildInfo));

    expect(() =>
      captureBuild({
        subject: "Dummy",
        slot: "deployment-commit",
        cwd: repoDir,
        commit,
        "source-file": "contracts/Dummy.sol",
        "contract-name": "Dummy",
        "build-info": buildInfoPath,
        out: outPath,
      }),
    ).to.throw(/does not exist on disk/);
  });
});
