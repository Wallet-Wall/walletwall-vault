/**
 * SP1 implementation lane: off a local chain the tooling acts only on the published records
 * (scripts/lib/sp1-published-records.ts; review findings L-1 and AUTH-4).
 *
 * The cross-chain halt refusal is repository-published data, so it is only as fresh as the checkout that reads it: a
 * stale clone lacks a published WRAPPER_HALTED fact and would bind the halted identity on another chain, and a
 * record nobody merged (a successor, a fact, a build) is not published. Before anything binds, deploys or registers
 * off a local chain, the registry, the designations, their evidence bundles and the wrapper builds must be exactly
 * what origin/main holds, fetched then. A fetch that fails is no answer, and refuses.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { expect } from "chai";

import { PUBLISHED_RECORD_PATHS, publishedRecordsErrors } from "../scripts/lib/sp1-published-records";

describe("SP1 implementation lane — off a local chain, only the published records", function () {
  this.timeout(120_000);
  let root: string;
  let origin: string;
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

  beforeEach(function () {
    root = mkdtempSync(join(tmpdir(), "sp1-published-"));
    origin = join(root, "origin.git");
    git(root, "init", "-q", "--bare", "-b", "main", origin);
    const seed = join(root, "seed");
    git(root, "clone", "-q", "-c", "core.autocrlf=false", origin, seed);
    identify(seed);
    write(seed, "evidence/zk/sp1-td2/wrapper-registry.json", '{"facts":[]}\n');
    write(seed, "evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json", '{"id":"d1"}\n');
    write(seed, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", '{"id":"b1"}\n');
    write(seed, "README.md", "unrelated\n");
    commitAll(seed, "published records");
    git(seed, "push", "-q", "origin", "main");
    work = join(root, "work");
    git(root, "clone", "-q", "-c", "core.autocrlf=false", origin, work);
    identify(work);
  });
  afterEach(function () {
    rmSync(root, { recursive: true, force: true });
  });

  /** Another writer publishes a change to origin/main. */
  const publish = (rel: string, content: string) => {
    const other = join(root, "other");
    git(root, "clone", "-q", "-c", "core.autocrlf=false", origin, other);
    identify(other);
    write(other, rel, content);
    commitAll(other, `publish ${rel}`);
    git(other, "push", "-q", "origin", "main");
    rmSync(other, { recursive: true, force: true });
  };

  it("passes when the records are exactly origin/main's, fetched now; unrelated files do not matter", function () {
    expect(publishedRecordsErrors(work, { fetch: true })).to.deep.equal([]);
    write(work, "README.md", "edited\n");
    write(work, "notes.txt", "untracked\n");
    expect(publishedRecordsErrors(work, { fetch: true })).to.deep.equal([]);
    expect(PUBLISHED_RECORD_PATHS).to.include.members([
      "evidence/zk/sp1-td2/wrapper-registry.json",
      "evidence/zk/sp1/designations",
      "evidence/zk/sp1/designation-evidence",
      "evidence/zk/sp1/wrapper-builds",
    ]);
  });

  it("a stale checkout is refused: it lacks a fact published since (a halt on another chain)", function () {
    publish("evidence/zk/sp1-td2/wrapper-registry.json", '{"facts":["a halt on another chain"]}\n');
    expect(publishedRecordsErrors(work, { fetch: false }), "without fetching it cannot see").to.deep.equal([]);
    expect(publishedRecordsErrors(work, { fetch: true }).join("\n")).to.match(
      /wrapper-registry\.json.*not what origin\/main publishes/,
    );
  });

  it("a record nobody published is refused: a local fact, a local successor, an uncommitted edit", function () {
    write(work, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json", '{"id":"d2"}\n');
    expect(publishedRecordsErrors(work, { fetch: true }).join("\n")).to.match(
      /mldsa65-withdrawal-d2\.json.*not published/,
    );
    commitAll(work, "a local successor");
    expect(publishedRecordsErrors(work, { fetch: true }).join("\n")).to.match(
      /mldsa65-withdrawal-d2\.json.*not what origin\/main publishes/,
    );
    git(work, "reset", "-q", "--hard", "origin/main");
    write(work, "evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", '{"id":"b1","edited":true}\n');
    expect(publishedRecordsErrors(work, { fetch: true }).join("\n")).to.match(
      /zkmldsa-verifier-b1\.json.*not what origin\/main publishes/,
    );
  });

  it("a fetch that fails is no answer: refused, never read as 'nothing new'", function () {
    git(work, "remote", "set-url", "origin", join(root, "no-such-origin.git"));
    expect(publishedRecordsErrors(work, { fetch: true }).join("\n")).to.match(/could not be fetched/);
    expect(publishedRecordsErrors(join(root, "not-a-repo-at-all"), { fetch: true }).join("\n")).to.match(
      /could not be fetched|cannot compare/,
    );
  });

  it("every script that binds, deploys or registers off a local chain checks the published records first", function () {
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
    }
  });
});
