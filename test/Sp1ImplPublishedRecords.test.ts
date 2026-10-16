/**
 * SP1 implementation lane: off a local chain the tooling acts only on the published records
 * (scripts/lib/sp1-published-records.ts; review findings L-1 and AUTH-4, and the re-review's A3 and A4).
 *
 * The cross-chain halt refusal is repository-published data, so it is only as fresh as the checkout that reads it: a
 * stale clone lacks a published WRAPPER_HALTED fact and would bind the halted identity on another chain, and a record
 * nobody merged (a successor, a fact, a build) is not published. Before anything binds, deploys or registers off a
 * local chain, the registry, the designations, their evidence bundles and the wrapper builds on disk must be, byte for
 * byte, what the canonical repository's main holds, fetched then from that repository itself (never whatever `origin`
 * names): every file on disk, ignored ones included, read as the tooling reads it, never through git's index. A fetch
 * that fails is no answer, and refuses. The registration script alone may append to the published registry, so that a
 * wrapper's registration and its halt can be published together.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { expect } from "chai";

import { PUBLISHED_RECORD_PATHS, PUBLISHED_SOURCE, publishedRecordsErrors } from "../scripts/lib/sp1-published-records";

const REGISTRY = "evidence/zk/sp1-td2/wrapper-registry.json";
const registry = (facts: unknown[]) =>
  `${JSON.stringify({ schema: "walletwall.sp1-wrapper-registry.v2", migratedFrom: { schema: "walletwall.sp1-wrapper-registry.v1", entries: 0 }, facts }, null, 2)}\n`;

describe("SP1 implementation lane — off a local chain, only the published records", function () {
  this.timeout(120_000);
  let root: string;
  let canonical: string;
  let work: string;
  const git = (cwd: string, ...args: string[]) =>
    execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const write = (dir: string, rel: string, content: string) => {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  };
  const commitAll = (dir: string, message: string) => {
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", message);
  };
  const identify = (dir: string) => {
    git(dir, "config", "user.email", "test@example.invalid");
    git(dir, "config", "user.name", "test");
    git(dir, "config", "core.autocrlf", "false");
  };
  const clone = (from: string, to: string) => {
    git(root, "clone", "-q", "-c", "core.autocrlf=false", from, to);
    identify(to);
  };
  /** Another writer publishes a change to the canonical main. */
  const publish = (rel: string, content: string) => {
    const other = join(root, `other-${Math.random().toString(16).slice(2)}`);
    clone(canonical, other);
    write(other, rel, content);
    commitAll(other, `publish ${rel}`);
    git(other, "push", "-q", "origin", "main");
    rmSync(other, { recursive: true, force: true });
  };
  const errors = (options: { registryMayExtend?: boolean } = {}) =>
    publishedRecordsErrors(work, { source: canonical, ...options }).join("\n");

  beforeEach(function () {
    root = mkdtempSync(join(tmpdir(), "sp1-published-"));
    canonical = join(root, "canonical.git");
    git(root, "init", "-q", "--bare", "-b", "main", canonical);
    const seed = join(root, "seed");
    clone(canonical, seed);
    write(seed, REGISTRY, registry([]));
    write(seed, "evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json", '{"id":"d1"}\n');
    write(seed, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", '{"id":"b1"}\n');
    write(seed, "README.md", "unrelated\n");
    commitAll(seed, "published records");
    git(seed, "push", "-q", "origin", "main");
    work = join(root, "work");
    clone(canonical, work);
  });
  afterEach(function () {
    rmSync(root, { recursive: true, force: true });
  });

  it("passes when the records on disk are the canonical main's, fetched now; unrelated files do not matter", function () {
    expect(errors()).to.equal("");
    write(work, "README.md", "edited\n");
    write(work, "notes.txt", "untracked\n");
    expect(errors()).to.equal("");
    expect(PUBLISHED_RECORD_PATHS).to.include.members([
      REGISTRY,
      "evidence/zk/sp1/designations",
      "evidence/zk/sp1/designation-evidence",
      "evidence/zk/sp1/wrapper-builds",
    ]);
    expect(PUBLISHED_SOURCE).to.equal("https://github.com/Wallet-Wall/walletwall-vault.git");
  });

  it("a stale checkout is refused: it lacks a fact published since (a halt on another chain)", function () {
    publish(REGISTRY, registry([{ seq: 1, kind: "a halt on another chain" }]));
    expect(errors()).to.match(/wrapper-registry\.json: not what .* main publishes/);
  });

  it("a stale fork as origin is refused: the records are compared with the canonical repository, never origin (A3)", function () {
    const fork = join(root, "fork.git");
    git(root, "clone", "-q", "--bare", canonical, fork);
    publish(REGISTRY, registry([{ seq: 1, kind: "a halt on another chain" }]));
    git(work, "remote", "set-url", "origin", fork);
    git(work, "fetch", "-q", "origin");
    expect(git(work, "diff", "--name-only", "origin/main", "--", REGISTRY), "origin agrees with the tree").to.equal("");
    expect(errors()).to.match(/wrapper-registry\.json: not what .* main publishes/);
  });

  it("a record nobody published is refused: a local fact, a local successor, an uncommitted edit", function () {
    write(work, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json", '{"id":"d2"}\n');
    expect(errors()).to.match(/mldsa65-withdrawal-d2\.json: not published/);
    commitAll(work, "a local successor");
    expect(errors()).to.match(/mldsa65-withdrawal-d2\.json: not published/);
    git(work, "reset", "-q", "--hard", "origin/main");
    write(work, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", '{"id":"b1","edited":true}\n');
    expect(errors()).to.match(/zkmldsa-verifier-b1\.json: not what .* main publishes/);
  });

  it("git's index cannot hide a record: ignored files, assume-unchanged and skip-worktree edits, a shadowing origin/main (A4)", function () {
    // An ignored, untracked successor: still a file the tooling reads.
    write(work, ".git/info/exclude", "evidence/zk/sp1/designations/*-d2.json\n");
    write(work, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json", '{"id":"d2"}\n');
    expect(errors()).to.match(/mldsa65-withdrawal-d2\.json: not published/);
    rmSync(join(work, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json"));
    // Edits git is told not to look at.
    for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
      git(work, "update-index", flag, REGISTRY);
      write(work, REGISTRY, registry([{ seq: 1, kind: "an unmerged fact" }]));
      expect(errors(), flag).to.match(/wrapper-registry\.json: not what .* main publishes/);
      git(work, "update-index", flag.replace("--", "--no-"), REGISTRY);
      git(work, "checkout", "--", REGISTRY);
    }
    // A local branch and a tag named origin/main that hold an unmerged record.
    git(work, "checkout", "-q", "-b", "origin/main");
    write(work, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b2.json", '{"id":"b2"}\n');
    commitAll(work, "an unmerged build");
    git(work, "tag", "origin/main");
    expect(errors()).to.match(/zkmldsa-verifier-b2\.json: not published/);
  });

  it("a record published but missing here is refused", function () {
    rmSync(join(work, "evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json"));
    expect(errors()).to.match(/mldsa65-withdrawal-d1\.json: published, but missing here/);
  });

  it("the registration script may append facts to the published registry, never drop or rewrite one", function () {
    const appended = registry([
      { seq: 1, kind: "WRAPPER_REGISTERED" },
      { seq: 2, kind: "WRAPPER_HALTED" },
    ]);
    write(work, REGISTRY, appended);
    expect(errors(), "every other tool: not the published registry").to.match(/wrapper-registry\.json: not what/);
    expect(errors({ registryMayExtend: true }), "the registration script").to.equal("");
    publish(REGISTRY, registry([{ seq: 1, kind: "WRAPPER_REGISTERED" }]));
    expect(errors({ registryMayExtend: true }), "extends what was published since").to.equal("");
    write(work, REGISTRY, registry([]));
    expect(errors({ registryMayExtend: true }), "drops a published fact").to.match(/wrapper-registry\.json: not what/);
    write(work, REGISTRY, appended);
    write(work, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", '{"id":"b1","edited":true}\n');
    expect(errors({ registryMayExtend: true }), "other records must still be the published ones").to.match(
      /zkmldsa-verifier-b1\.json: not what/,
    );
  });

  it("a fetch that fails is no answer: refused, never read as 'nothing new'", function () {
    expect(publishedRecordsErrors(work, { source: join(root, "no-such-repo.git") }).join("\n")).to.match(
      /could not be fetched/,
    );
    expect(publishedRecordsErrors(join(root, "not-a-repo-at-all"), { source: canonical }).join("\n")).to.match(
      /could not be fetched/,
    );
  });

  it("every script that binds, deploys or registers off a local chain checks the published records first, before any transaction", function () {
    for (const [script, acts] of [
      ["scripts/deploy.ts", "checkDeploymentBinding("],
      ["scripts/deploy-multisig.ts", "deployMultisigVault("],
      ["scripts/propose-verifier-update.ts", "checkRotationBinding("],
      ["scripts/deploy-zk-verifier.ts", "planWrapperDeployment("],
      ["scripts/register-sp1-wrapper.ts", "readRegistry("],
    ] as const) {
      const source = readFileSync(resolve(script), "utf8");
      const check = source.indexOf("assertPublishedSp1Records(");
      expect(check, `${script} checks the published records`).to.be.greaterThan(-1);
      expect(check, `${script} checks them before ${acts}`).to.be.lessThan(source.indexOf(acts));
      const firstDeploy = source.search(/\.deploy\(|sendTransaction\(/);
      if (firstDeploy !== -1) expect(check, `${script} checks them before any transaction`).to.be.lessThan(firstDeploy);
    }
    expect(readFileSync(resolve("scripts/register-sp1-wrapper.ts"), "utf8")).to.match(
      /assertPublishedSp1Records\(chainId, "\.", \{ registryMayExtend: true \}\)/,
    );
  });
});
