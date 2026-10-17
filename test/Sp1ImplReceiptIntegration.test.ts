/**
 * SP1 implementation receipt after its merge: the integration binding (scripts/lib/sp1-impl-receipt-integration.ts,
 * evidence/zk/sp1-impl/receipt-integration.json, docs/SP1_Impl_Receipt_Integration.md).
 *
 * Every case runs on a throwaway repository built here, so each topology is the one git really makes: a merge commit,
 * a squash, a rebase merge, a fast-forward, an octopus, a merge made from the lane's side, an evil merge, a lane that
 * was or was not brought up to date, main moving its contracts before the merge. Expected values are read from git
 * (rev-parse) or written here, never computed by the module under test.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { expect } from "chai";

import { IMPL_RECEIPT_REL, implReceiptErrors, readBoundReceiptInputs } from "../scripts/lib/sp1-impl-receipt";
import {
  IMPL_RECEIPT_INTEGRATION_REL,
  deriveReceiptIntegration,
  descendantDriftErrors,
  receiptIntegrationErrors,
  type ReceiptIntegration,
} from "../scripts/lib/sp1-impl-receipt-integration";

const RECEIPT = IMPL_RECEIPT_REL;
const VAULT = "contracts/WalletWallVault.sol";
const WRAPPER = "contracts/verifiers/ZKMLDSAVerifier.sol";
const PROBE = "contracts/mocks/ChainIdBindingProbe.sol";
const receiptText = (base: string) =>
  `${JSON.stringify({ schema: "walletwall.sp1-impl-receipt.v1", lane: "SP1-IMPL", baseCommit: base }, null, 2)}\n`;
const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

class Repo {
  readonly dir = mkdtempSync(join(tmpdir(), "sp1-receipt-integration-"));
  readonly ids: Record<string, string> = {};

  git(...args: string[]): string {
    const run = () =>
      execFileSync(
        "git",
        [
          "-c",
          "core.autocrlf=false",
          "-c",
          "commit.gpgsign=false",
          "-c",
          "user.email=t@example.invalid",
          "-c",
          "user.name=t",
          ...args,
        ],
        { cwd: this.dir, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
    // On Windows a scanner can hold a just-written object file for a moment, and git's rename into .git/objects then
    // fails with "Permission denied". That is the host, not the code under test: retry it, and only it, a few times.
    for (let attempt = 1; ; attempt++) {
      try {
        return run();
      } catch (error) {
        const stderr = String((error as { stderr?: unknown }).stderr ?? "");
        if (attempt === 5 || !/unable to write file \.git\/objects\/.*: Permission denied/.test(stderr)) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200 * attempt);
      }
    }
  }

  head(): string {
    return this.git("rev-parse", "HEAD");
  }

  /** Write (or, for null, delete) files in the working tree. */
  write(files: Record<string, string | null>): void {
    for (const [rel, text] of Object.entries(files)) {
      const path = join(this.dir, rel);
      if (text === null) {
        rmSync(path, { force: true });
      } else {
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, text);
      }
    }
  }

  commit(name: string, files: Record<string, string | null> = {}, message = name): string {
    this.write(files);
    this.git("add", "-A");
    this.git("commit", "-q", "--allow-empty", "-m", message);
    this.ids[name] = this.head();
    return this.ids[name];
  }

  /** origin/main, as a full clone that fetched main would name it. */
  publish(commit: string): void {
    this.git("update-ref", "refs/remotes/origin/main", commit);
  }

  tree(rev: string): string {
    return this.git("rev-parse", `${rev}^{tree}`);
  }

  object(rev: string, path: string): string {
    return this.git("rev-parse", `${rev}:${path}`);
  }

  remove(): void {
    rmSync(this.dir, { recursive: true, force: true });
  }
}

/** main m0 (vault, wrapper w0); the lane forks there: l1 changes the wrapper, adds the probe and writes the receipt
 *  (base m0), l2 adds a note. HEAD is left on main at m0. */
function laneWorld(repo: Repo): void {
  repo.git("init", "-q", "-b", "main");
  repo.commit("m0", { [VAULT]: "contract Vault {}\n", [WRAPPER]: "wrapper w0\n", "README.md": "readme\n" });
  repo.git("checkout", "-q", "-b", "lane");
  repo.commit("l1", { [WRAPPER]: "wrapper w1\n", [PROBE]: "probe\n", [RECEIPT]: receiptText(repo.ids.m0) });
  repo.commit("l2", { "docs/lane.md": "lane notes\n" });
  repo.git("checkout", "-q", "main");
}

/** Merge the lane into main with a merge commit, as GitHub's "Create a merge commit" does, and publish it. */
function mergeLane(repo: Repo, name = "I", branch = "lane"): string {
  repo.git("merge", "-q", "--no-ff", "-m", "Merge pull request #1 from lane", branch);
  repo.ids[name] = repo.head();
  repo.publish(repo.ids[name]);
  return repo.ids[name];
}

/**
 * A look-alike of the lane: the same messages and the same receipt over another wrapper, and a merge of it onto m0 made
 * the way the real one was (not published). What an attacker would like main to show instead of the real merge.
 */
function lookAlike(repo: Repo): { head: string; merge: string } {
  const back = repo.git("rev-parse", "--abbrev-ref", "HEAD");
  repo.git("checkout", "-q", "-b", "look-alike", repo.ids.m0);
  repo.commit(
    "x1",
    { [WRAPPER]: "wrapper w1, rewritten\n", [PROBE]: "probe\n", [RECEIPT]: receiptText(repo.ids.m0) },
    "l1",
  );
  const head = repo.commit("x2", { "docs/lane.md": "lane notes\n" }, "l2");
  const merge = repo.git(
    "commit-tree",
    repo.tree(head),
    "-p",
    repo.ids.m0,
    "-p",
    head,
    "-m",
    "Merge pull request #1 from lane",
  );
  repo.git("checkout", "-q", back === "HEAD" ? repo.ids.I : back);
  return { head, merge };
}

/** What the binding of a merge commit must say, written from git's own answers. */
function expectedBinding(
  repo: Repo,
  at: { base: string; writtenAt: string; reviewed: string; merge: string; firstParent: string },
): Omit<ReceiptIntegration, "note"> {
  return {
    schema: "walletwall.sp1-impl-receipt-integration.v1",
    historicalReceipt: {
      path: RECEIPT,
      sha256: sha256(receiptText(at.base)),
      lane: "SP1-IMPL",
      historicalLaneBase: at.base,
      writtenAt: at.writtenAt,
    },
    reviewedSubject: { commit: at.reviewed, tree: repo.tree(at.reviewed) },
    integratedSubject: {
      commit: at.merge,
      method: "MERGE_COMMIT",
      parents: [at.firstParent, at.reviewed],
      tree: repo.tree(at.merge),
    },
    descendantDriftBaseline: {
      commit: at.merge,
      subject: [
        { path: "contracts", type: "tree", id: repo.object(at.merge, "contracts") },
        { path: RECEIPT, type: "blob", id: repo.object(at.merge, RECEIPT) },
      ],
    },
  };
}

const withoutNote = (r: ReceiptIntegration) => {
  const { note, ...rest } = r;
  expect(note, "the record says what it is").to.match(/never rewritten/);
  expect(note, "and what it does not attest").to.match(/not who reviewed or merged it/);
  return rest;
};

describe("SP1 implementation receipt — the integration binding after the merge", function () {
  this.timeout(300_000);
  let repo: Repo;

  beforeEach(function () {
    repo = new Repo();
    laneWorld(repo);
  });
  afterEach(function () {
    repo.remove();
  });

  describe("the historical lane base, the reviewed subject and the integrated subject are kept apart", function () {
    it("derives the binding of a merge commit from git alone", function () {
      const merge = mergeLane(repo);
      expect(repo.tree(merge), "the premise: the merge carries the head's tree").to.equal(repo.tree(repo.ids.l2));
      expect(withoutNote(deriveReceiptIntegration(repo.dir, RECEIPT))).to.deep.equal(
        expectedBinding(repo, {
          base: repo.ids.m0,
          writtenAt: repo.ids.l1,
          reviewed: repo.ids.l2,
          merge,
          firstParent: repo.ids.m0,
        }),
      );
    });

    it("the committed record must be what git derives: a missing record, or any field edited, is refused", function () {
      mergeLane(repo);
      const derived = deriveReceiptIntegration(repo.dir, RECEIPT);
      const text = (r: unknown) => `${JSON.stringify(r, null, 2)}\n`;
      expect(receiptIntegrationErrors(repo.dir, RECEIPT).errors.join("\n")).to.match(/missing/);
      repo.write({ [IMPL_RECEIPT_INTEGRATION_REL]: text(derived) });
      const ok = receiptIntegrationErrors(repo.dir, RECEIPT);
      expect(ok.errors, "the positive control").to.deep.equal([]);
      expect(ok.record).to.deep.equal(derived);
      const edits: [string, (r: ReceiptIntegration) => void, string][] = [
        // The false STOP's base: the integration itself named as the lane's base.
        ["historicalLaneBase", (r) => (r.historicalReceipt.historicalLaneBase = repo.ids.I), "historicalReceipt"],
        ["sha256", (r) => (r.historicalReceipt.sha256 = sha256("another receipt\n")), "historicalReceipt"],
        ["reviewed head", (r) => (r.reviewedSubject.commit = repo.ids.l1), "reviewedSubject"],
        ["method", (r) => ((r.integratedSubject as { method: string }).method = "SQUASH"), "integratedSubject"],
        [
          "baseline",
          (r) => (r.descendantDriftBaseline.subject[0].id = repo.object(repo.ids.m0, "contracts")),
          "descendantDriftBaseline",
        ],
      ];
      for (const [what, edit, field] of edits) {
        const edited = structuredClone(derived);
        edit(edited);
        repo.write({ [IMPL_RECEIPT_INTEGRATION_REL]: text(edited) });
        const result = receiptIntegrationErrors(repo.dir, RECEIPT);
        expect(result.errors.join("\n"), what).to.match(new RegExp(`not what git derives \\(${field}\\)`));
        expect(result.record, what).to.equal(null);
      }
      repo.write({ [IMPL_RECEIPT_INTEGRATION_REL]: "not JSON\n" });
      expect(receiptIntegrationErrors(repo.dir, RECEIPT).errors.join("\n"), "not JSON: every field differs").to.match(
        /not what git derives \(schema, note, historicalReceipt, reviewedSubject, integratedSubject, descendantDriftBaseline\)/,
      );
      repo.write({ [IMPL_RECEIPT_INTEGRATION_REL]: null });
      mkdirSync(join(repo.dir, IMPL_RECEIPT_INTEGRATION_REL));
      const unreadable = receiptIntegrationErrors(repo.dir, RECEIPT);
      expect(unreadable.errors.join("\n"), "a record that cannot be read is no record").to.match(/cannot be read/);
      expect(unreadable.record).to.equal(null);
    });

    it("the writer is the lane's, as of the reviewed head: a descendant that rewrote and restored the receipt moves nothing", function () {
      mergeLane(repo);
      repo.commit("rewrite", { [RECEIPT]: receiptText(repo.ids.I) });
      repo.commit("restore", { [RECEIPT]: receiptText(repo.ids.m0) });
      repo.publish(repo.head());
      expect(repo.git("log", "-1", "--format=%H", "--", RECEIPT), "the premise: HEAD's last writer moved").to.equal(
        repo.ids.restore,
      );
      const binding = deriveReceiptIntegration(repo.dir, RECEIPT);
      expect(binding.historicalReceipt.writtenAt).to.equal(repo.ids.l1);
      expect(binding.integratedSubject.commit).to.equal(repo.ids.I);
      expect(descendantDriftErrors(repo.dir, binding.descendantDriftBaseline)).to.deep.equal([]);
    });

    it("a subject must hold what it protects: a history with no contracts/ binds nothing", function () {
      repo.remove();
      repo = new Repo();
      repo.git("init", "-q", "-b", "main");
      repo.commit("m0", { "README.md": "readme\n" });
      repo.git("checkout", "-q", "-b", "lane");
      repo.commit("l1", { [RECEIPT]: receiptText(repo.ids.m0) });
      repo.git("checkout", "-q", "main");
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(
        /carries no contracts: it cannot be a subject/,
      );
    });
  });

  describe("a descendant is judged against the integrated subject, never the historical lane base", function () {
    const baseline = () => deriveReceiptIntegration(repo.dir, RECEIPT).descendantDriftBaseline;

    it("main itself, an empty commit, a docs change, an app and test change, and a pull request's synthetic merge pass", function () {
      const merge = mergeLane(repo);
      const b = baseline();
      expect(descendantDriftErrors(repo.dir, b), "main at the merge").to.deep.equal([]);
      repo.commit("empty");
      expect(descendantDriftErrors(repo.dir, b), "one empty commit").to.deep.equal([]);
      repo.commit("docs", { "docs/notes.md": "notes\n", "README.md": "readme, edited\n" });
      expect(descendantDriftErrors(repo.dir, b), "docs only").to.deep.equal([]);
      repo.commit("app", { "src/app.ts": "export const x = 1;\n", "test/App.test.ts": "// test\n" });
      expect(descendantDriftErrors(repo.dir, b), "an unrelated app and test change").to.deep.equal([]);
      // A pull request off main: main moved on (docs, app), the PR head changed a test; CI checks out their merge,
      // whose first parent is main's tip and whose second is the PR head.
      repo.git("checkout", "-q", "-b", "pr", merge);
      const prHead = repo.commit("pr", { "test/Other.test.ts": "// other\n" });
      repo.git("checkout", "-q", "--detach", "main");
      repo.git("merge", "-q", "--no-ff", "-m", "Merge pr into main", prHead);
      expect(repo.git("rev-list", "--parents", "-n", "1", "HEAD").split(" "), "two parents, as CI's").to.deep.equal([
        repo.head(),
        repo.ids.app,
        prHead,
      ]);
      expect(descendantDriftErrors(repo.dir, b), "the synthetic merge").to.deep.equal([]);
      expect(
        deriveReceiptIntegration(repo.dir, RECEIPT).descendantDriftBaseline,
        "the baseline is unmoved",
      ).to.deep.equal(b);
    });

    it("one contract byte changed in HEAD is drift, whatever the commit says", function () {
      mergeLane(repo);
      const b = baseline();
      repo.commit("docs: typo", { [PROBE]: "probe \n" });
      const errors = descendantDriftErrors(repo.dir, b).join("\n");
      expect(errors).to.match(/HEAD changes contracts since the integrated subject/);
      expect(errors).to.match(/new evidence/);
    });

    it("the receipt rewritten in HEAD is drift: a historical receipt is never restamped", function () {
      const merge = mergeLane(repo);
      const b = baseline();
      repo.commit("regenerate", { [RECEIPT]: receiptText(merge) });
      expect(descendantDriftErrors(repo.dir, b).join("\n")).to.match(
        /HEAD changes evidence\/zk\/sp1-impl\/implementation-receipt\.json since the integrated subject/,
      );
    });

    it("the working tree is judged byte for byte: an edit, an untracked contract, a removal, an assume-unchanged file", function () {
      mergeLane(repo);
      const b = baseline();
      const cases: [string, () => void, () => void, string][] = [
        [
          "an uncommitted edit",
          () => repo.write({ [VAULT]: "contract Vault { }\n" }),
          () => repo.git("checkout", "--", VAULT),
          `${VAULT} (changed)`,
        ],
        [
          "an untracked contract",
          () => repo.write({ "contracts/Extra.sol": "contract Extra {}\n" }),
          () => repo.write({ "contracts/Extra.sol": null }),
          "contracts/Extra.sol (added)",
        ],
        [
          "a removed contract",
          () => repo.write({ [WRAPPER]: null }),
          () => repo.git("checkout", "--", WRAPPER),
          `${WRAPPER} (removed)`,
        ],
        [
          "an edit git's index is told to ignore",
          () => {
            repo.git("update-index", "--assume-unchanged", VAULT);
            repo.write({ [VAULT]: "contract Vault { /* hidden */ }\n" });
          },
          () => {
            repo.git("update-index", "--no-assume-unchanged", VAULT);
            repo.git("checkout", "--", VAULT);
          },
          `${VAULT} (changed)`,
        ],
        [
          "the receipt edited on disk",
          () => repo.write({ [RECEIPT]: receiptText("0".repeat(40)) }),
          () => repo.git("checkout", "--", RECEIPT),
          `${RECEIPT} (changed)`,
        ],
        [
          "a contract with CRLF line endings, as a core.autocrlf=true clone writes it",
          () => repo.write({ [VAULT]: "contract Vault {}\r\n" }),
          () => repo.git("checkout", "--", VAULT),
          `${VAULT} (changed: line endings only; check out with core.autocrlf=false)`,
        ],
        [
          "the receipt removed on disk",
          () => repo.write({ [RECEIPT]: null }),
          () => repo.git("checkout", "--", RECEIPT),
          `${RECEIPT} (removed, or unreadable)`,
        ],
      ];
      for (const [what, apply, undo, label] of cases) {
        apply();
        try {
          const errors = descendantDriftErrors(repo.dir, b).join("\n");
          expect(errors, what).to.match(/the working tree changes .* since the integrated subject/);
          expect(errors, `${what}: names the file and what happened to it`).to.include(label);
          expect(errors, `${what}: HEAD itself is unchanged`).to.not.match(/HEAD changes/);
        } finally {
          undo();
        }
        expect(descendantDriftErrors(repo.dir, b), `${what}: restored`).to.deep.equal([]);
      }
    });

    it("drift committed in HEAD is drift though the working tree was put back", function () {
      mergeLane(repo);
      const b = baseline();
      repo.commit("vault", { [VAULT]: "contract Vault { uint x; }\n" });
      repo.write({ [VAULT]: "contract Vault {}\n" });
      const errors = descendantDriftErrors(repo.dir, b).join("\n");
      expect(errors).to.match(/HEAD changes contracts since the integrated subject/);
      expect(errors, "the working tree is the integrated subject's").to.not.match(/the working tree changes/);
    });

    it("a commit that does not descend from the integration is refused, though it carries the same files", function () {
      mergeLane(repo);
      const b = baseline();
      repo.git("checkout", "-q", "-b", "elsewhere", repo.ids.l2);
      expect(descendantDriftErrors(repo.dir, b).join("\n")).to.match(/does not descend from the integrated subject/);
    });
  });

  describe("integration topologies: only a merge commit names the reviewed head", function () {
    it("a squash merge is refused: no parent names the reviewed head", function () {
      repo.git("merge", "-q", "--squash", "lane");
      const squash = repo.commit("Squash: the lane (#1)");
      repo.publish(squash);
      expect(repo.tree(squash), "the premise: the squash carries the head's tree").to.equal(repo.tree(repo.ids.l2));
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/single-parent commit/);
    });

    it("a rebase merge is refused: the lane's commits replayed on main name no reviewed head", function () {
      repo.git("cherry-pick", repo.ids.l1, repo.ids.l2);
      repo.publish(repo.head());
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/single-parent commit/);
    });

    it("a fast-forward is refused: the lane's own commits become main's first-parent history", function () {
      repo.publish(repo.ids.l2);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/single-parent commit/);
    });

    it("an octopus merge is refused", function () {
      repo.git("checkout", "-q", "-b", "other", repo.ids.m0);
      repo.commit("o1", { "docs/other.md": "other\n" });
      repo.git("checkout", "-q", "main");
      repo.git("merge", "-q", "--no-ff", "-m", "octopus", "lane", "other");
      repo.publish(repo.head());
      expect(repo.git("rev-list", "--parents", "-n", "1", "HEAD").split(" ")).to.have.length(4);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/3 parents/);
    });

    it("a merge made from the lane's side is refused: main's first parent then runs through the lane", function () {
      const swapped = repo.git(
        "commit-tree",
        repo.tree(repo.ids.l2),
        "-p",
        repo.ids.l2,
        "-p",
        repo.ids.m0,
        "-m",
        "Merge pull request #1 from lane",
      );
      repo.publish(swapped);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/single-parent commit/);
    });

    it("a merge carrying a protected change its reviewed head does not is refused", function () {
      repo.git("merge", "-q", "--no-ff", "--no-commit", "lane");
      repo.write({ [WRAPPER]: "wrapper w1, and something the review never saw\n" });
      repo.git("add", "-A");
      repo.git("commit", "-q", "-m", "Merge pull request #1 from lane");
      repo.publish(repo.head());
      expect(repo.git("rev-list", "--parents", "-n", "1", "HEAD").split(" "), "a merge commit").to.have.length(3);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/carries bytes its reviewed head .* does not/);
    });

    it("a merge carrying any other byte its reviewed head does not is refused too: the merge is the reviewed tree", function () {
      repo.git("merge", "-q", "--no-ff", "--no-commit", "lane");
      repo.write({ "docs/merge.md": "added by the merge\n" });
      repo.git("add", "-A");
      repo.git("commit", "-q", "-m", "Merge pull request #1 from lane");
      repo.publish(repo.head());
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/carries bytes its reviewed head .* does not/);
    });

    it("main moved without touching contracts and the lane was brought up to date: its merge commit binds", function () {
      repo.commit("m1", { "docs/main.md": "main notes\n" });
      repo.git("checkout", "-q", "lane");
      repo.git("merge", "-q", "--no-ff", "-m", "update the lane", "main");
      repo.ids.l3 = repo.head();
      repo.git("checkout", "-q", "main");
      const merge = mergeLane(repo);
      expect(withoutNote(deriveReceiptIntegration(repo.dir, RECEIPT))).to.deep.equal(
        expectedBinding(repo, {
          base: repo.ids.m0,
          writtenAt: repo.ids.l1,
          reviewed: repo.ids.l3,
          merge,
          firstParent: repo.ids.m1,
        }),
      );
    });

    it("a lane not brought up to date is refused: its merge commit carries main's bytes the reviewed head does not", function () {
      repo.commit("m1", { "docs/main.md": "main notes\n" });
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/carries bytes its reviewed head .* does not/);
    });

    it("main moved its contracts after the lane's base: the receipt would state its change set against a stale base", function () {
      repo.commit("m1", { [VAULT]: "contract Vault { uint b; }\n" });
      repo.git("checkout", "-q", "lane");
      repo.git("merge", "-q", "--no-ff", "-m", "update the lane", "main");
      repo.git("checkout", "-q", "main");
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(
        /main changed contracts between the lane's base .* and the merge's first parent/,
      );
    });

    it("a lane that merged main's contract change and reverted it is refused the same way (the re-review's A2)", function () {
      repo.commit("m1", { [VAULT]: "contract Vault { uint b; }\n" });
      repo.git("checkout", "-q", "lane");
      repo.git("merge", "-q", "--no-ff", "-m", "update the lane", "main");
      repo.commit("l4", { [VAULT]: "contract Vault {}\n" });
      repo.git("checkout", "-q", "main");
      const merge = mergeLane(repo);
      expect(repo.git("diff", "--name-only", repo.ids.l2, merge, "--", "contracts"), "the contracts are l2's").to.equal(
        "",
      );
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(
        /main changed contracts between the lane's base .* and the merge's first parent/,
      );
    });
  });

  describe("malicious ancestry", function () {
    it("the reviewed head is a parent, never a message: a look-alike history does not match the committed record", function () {
      mergeLane(repo);
      const record = `${JSON.stringify(deriveReceiptIntegration(repo.dir, RECEIPT), null, 2)}\n`;
      // The same messages and the same receipt over another wrapper, merged the same way onto a look-alike main.
      repo.git("checkout", "-q", "-b", "look-alike", repo.ids.m0);
      repo.commit(
        "x1",
        { [WRAPPER]: "wrapper w1, rewritten\n", [PROBE]: "probe\n", [RECEIPT]: receiptText(repo.ids.m0) },
        "l1",
      );
      const lookAlikeHead = repo.commit("x2", { "docs/lane.md": "lane notes\n" }, "l2");
      repo.git("checkout", "-q", "--detach", repo.ids.m0);
      repo.git("merge", "-q", "--no-ff", "-m", "Merge pull request #1 from lane", lookAlikeHead);
      repo.write({ [IMPL_RECEIPT_INTEGRATION_REL]: record });
      repo.publish(repo.ids.I);
      expect(receiptIntegrationErrors(repo.dir, RECEIPT).errors, "the positive control: the true main").to.deep.equal(
        [],
      );
      repo.publish(repo.head());
      expect(
        deriveReceiptIntegration(repo.dir, RECEIPT).reviewedSubject.commit,
        "git names the head by its parent",
      ).to.equal(lookAlikeHead);
      expect(receiptIntegrationErrors(repo.dir, RECEIPT).errors.join("\n")).to.match(/not what git derives/);
    });

    it("only refs/remotes/origin/main is main: a tag, a branch or a file named origin/main shadows nothing", function () {
      mergeLane(repo);
      const fake = lookAlike(repo);
      const gitDir = join(repo.dir, ".git");
      const shadows: [string, () => void, () => void][] = [
        ["a tag", () => repo.git("tag", "origin/main", fake.merge), () => repo.git("tag", "-d", "origin/main")],
        [
          "a branch",
          () => repo.git("branch", "origin/main", fake.merge),
          () => repo.git("branch", "-D", "origin/main"),
        ],
        [
          "a file in the git directory",
          () => {
            mkdirSync(join(gitDir, "origin"), { recursive: true });
            writeFileSync(join(gitDir, "origin/main"), `${fake.merge}\n`);
          },
          () => rmSync(join(gitDir, "origin"), { recursive: true, force: true }),
        ],
      ];
      for (const [what, shadow, undo] of shadows) {
        shadow();
        try {
          expect(repo.git("rev-parse", "origin/main"), `the premise: ${what} wins the short name`).to.equal(fake.merge);
          expect(deriveReceiptIntegration(repo.dir, RECEIPT).reviewedSubject.commit, what).to.equal(repo.ids.l2);
        } finally {
          undo();
        }
      }
    });

    it("grafts are not read: neither a grafts file nor GIT_GRAFT_FILE can reroute main through a look-alike merge", function () {
      mergeLane(repo);
      const fake = lookAlike(repo);
      const grafts = `${repo.ids.I} ${fake.merge}\n`;
      const file = join(repo.dir, ".git/info/grafts");
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, grafts);
      try {
        expect(repo.git("rev-parse", `${repo.ids.I}^1`), "the premise: git follows the grafts file").to.equal(
          fake.merge,
        );
        expect(deriveReceiptIntegration(repo.dir, RECEIPT).reviewedSubject.commit, "a grafts file").to.equal(
          repo.ids.l2,
        );
      } finally {
        rmSync(file, { force: true });
      }
      const elsewhere = join(repo.dir, "grafts-elsewhere");
      writeFileSync(elsewhere, grafts);
      const before = process.env.GIT_GRAFT_FILE;
      process.env.GIT_GRAFT_FILE = elsewhere;
      try {
        expect(repo.git("rev-parse", `${repo.ids.I}^1`), "the premise: git follows GIT_GRAFT_FILE").to.equal(
          fake.merge,
        );
        expect(deriveReceiptIntegration(repo.dir, RECEIPT).reviewedSubject.commit, "GIT_GRAFT_FILE").to.equal(
          repo.ids.l2,
        );
      } finally {
        if (before === undefined) delete process.env.GIT_GRAFT_FILE;
        else process.env.GIT_GRAFT_FILE = before;
      }
    });

    it("a replace ref cannot substitute another reviewed head: git's objects themselves are read", function () {
      const merge = mergeLane(repo);
      repo.git("checkout", "-q", "-b", "look-alike", repo.ids.m0);
      repo.commit(
        "x1",
        { [WRAPPER]: "wrapper w1, rewritten\n", [PROBE]: "probe\n", [RECEIPT]: receiptText(repo.ids.m0) },
        "l1",
      );
      const fakeHead = repo.commit("x2", { "docs/lane.md": "lane notes\n" }, "l2");
      const fake = repo.git(
        "commit-tree",
        repo.tree(fakeHead),
        "-p",
        repo.ids.m0,
        "-p",
        fakeHead,
        "-m",
        "Merge pull request #1 from lane",
      );
      repo.git("replace", merge, fake);
      expect(repo.git("rev-parse", `${merge}^2`), "the premise: git shows the look-alike head by default").to.equal(
        fakeHead,
      );
      expect(deriveReceiptIntegration(repo.dir, RECEIPT).reviewedSubject.commit).to.equal(repo.ids.l2);
    });

    it("cherry-picking the lane's authorized commit onto other contract bytes does not inherit the binding", function () {
      mergeLane(repo);
      const b = deriveReceiptIntegration(repo.dir, RECEIPT).descendantDriftBaseline;
      repo.commit("vault", { [VAULT]: "contract Vault { address owner2; }\n" });
      repo.git("cherry-pick", "--keep-redundant-commits", repo.ids.l1);
      expect(repo.git("log", "-1", "--format=%s"), "the authorized commit's message").to.equal("l1");
      expect(descendantDriftErrors(repo.dir, b).join("\n")).to.match(
        /HEAD changes contracts since the integrated subject/,
      );
    });

    it("a receipt and its record edited together stay refused: the record is derived from the reviewed head's bytes", function () {
      const merge = mergeLane(repo);
      const derived = deriveReceiptIntegration(repo.dir, RECEIPT);
      const forged = structuredClone(derived);
      forged.historicalReceipt.sha256 = sha256(receiptText(merge));
      forged.historicalReceipt.historicalLaneBase = merge;
      repo.commit("restamp", {
        [RECEIPT]: receiptText(merge),
        [IMPL_RECEIPT_INTEGRATION_REL]: `${JSON.stringify(forged, null, 2)}\n`,
      });
      expect(receiptIntegrationErrors(repo.dir, RECEIPT).errors.join("\n")).to.match(/not what git derives/);
      expect(descendantDriftErrors(repo.dir, derived.descendantDriftBaseline).join("\n")).to.match(
        /HEAD changes evidence\/zk\/sp1-impl\/implementation-receipt\.json/,
      );
    });

    it("a receipt removed and restored on main stays bound to its first merge, and the restored bytes are judged", function () {
      mergeLane(repo);
      const before = deriveReceiptIntegration(repo.dir, RECEIPT);
      repo.commit("drop", { [RECEIPT]: null });
      repo.commit("re-add", { [RECEIPT]: receiptText(repo.ids.m0) });
      repo.publish(repo.head());
      const after = deriveReceiptIntegration(repo.dir, RECEIPT);
      expect(after, "an append-only main cannot move its first merge").to.deep.equal(before);
      expect(descendantDriftErrors(repo.dir, after.descendantDriftBaseline), "the same bytes restored").to.deep.equal(
        [],
      );
      repo.commit("re-add other", { [RECEIPT]: receiptText(repo.ids.l2) });
      expect(descendantDriftErrors(repo.dir, after.descendantDriftBaseline).join("\n")).to.match(
        /HEAD changes evidence\/zk\/sp1-impl\/implementation-receipt\.json since the integrated subject/,
      );
    });
  });

  describe("fail closed", function () {
    it("without origin/main, or with an origin/main from before the merge, nothing is judged", function () {
      mergeLane(repo);
      repo.git("update-ref", "-d", "refs/remotes/origin/main");
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/origin\/main is not available/);
      repo.publish(repo.ids.m0);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/on no commit of origin\/main/);
    });

    it("a shallow clone fails closed", function () {
      mergeLane(repo);
      const clone = mkdtempSync(join(tmpdir(), "sp1-receipt-integration-shallow-"));
      try {
        execFileSync("git", ["clone", "-q", "--depth", "1", pathToFileURL(repo.dir).href, clone], { stdio: "pipe" });
        expect(() => deriveReceiptIntegration(clone, RECEIPT)).to.throw(/shallow/);
      } finally {
        rmSync(clone, { recursive: true, force: true });
      }
    });

    it("the historical receipt must name a full base commit: anything else is no commit of main", function () {
      repo.git("checkout", "-q", "lane");
      repo.commit("l3", { [RECEIPT]: receiptText(repo.ids.m0.slice(0, 12)) });
      repo.git("checkout", "-q", "main");
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/is no commit of origin\/main's first-parent/);
    });

    it("the historical base must be a commit of main's first-parent history, never a lane commit", function () {
      repo.git("checkout", "-q", "lane");
      repo.commit("l3", { [RECEIPT]: receiptText(repo.ids.l1) });
      repo.git("checkout", "-q", "main");
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/is no commit of origin\/main's first-parent/);
    });

    it("the historical base must be where the lane that wrote the receipt began", function () {
      // main m0 - m1 (docs); the lane forked at m0 but its receipt names m1, which it merged only afterwards.
      repo.commit("m1", { "docs/main.md": "main notes\n" });
      repo.git("checkout", "-q", "lane");
      repo.commit("l3", { [RECEIPT]: receiptText(repo.ids.m1) });
      repo.git("merge", "-q", "--no-ff", "-m", "update the lane", "main");
      repo.git("checkout", "-q", "main");
      mergeLane(repo);
      expect(() => deriveReceiptIntegration(repo.dir, RECEIPT)).to.throw(/did not begin at its base/);
    });
  });

  describe("the receipt's validator and generator reach it only through the binding", function () {
    const cli = (...args: string[]) =>
      spawnSync(
        process.execPath,
        ["--import", import.meta.resolve("tsx"), resolve("scripts/generate-sp1-impl-receipt.ts"), ...args],
        { cwd: repo.dir, encoding: "utf8" },
      );

    it("the validator refuses a tree without the binding, and one that drifted from it, before deriving anything", async function () {
      mergeLane(repo);
      let refusal = "";
      try {
        await readBoundReceiptInputs(repo.dir);
      } catch (error) {
        refusal = (error as Error).message;
      }
      expect(refusal).to.match(/receipt-integration\.json is missing/);
      expect((await implReceiptErrors(repo.dir)).join("\n")).to.match(/receipt-integration\.json is missing/);
      repo.write({
        [IMPL_RECEIPT_INTEGRATION_REL]: `${JSON.stringify(deriveReceiptIntegration(repo.dir, RECEIPT), null, 2)}\n`,
      });
      repo.commit("vault", { [VAULT]: "contract Vault { uint z; }\n" });
      expect((await implReceiptErrors(repo.dir)).join("\n")).to.match(
        /HEAD changes contracts since the integrated subject/,
      );
    });

    it("the CLI writes the binding git derives, and refuses to generate the receipt again on a descendant", function () {
      mergeLane(repo);
      repo.commit("empty");
      const written = cli("--integration");
      expect(written.status, written.stderr).to.equal(0);
      expect(readFileSync(join(repo.dir, IMPL_RECEIPT_INTEGRATION_REL), "utf8")).to.equal(
        `${JSON.stringify(deriveReceiptIntegration(repo.dir, RECEIPT), null, 2)}\n`,
      );
      // The false STOP came from exactly this: generating again, on a descendant, against the merge as the base.
      const regenerated = cli();
      expect(regenerated.status).to.equal(1);
      expect(regenerated.stderr).to.match(/already carries evidence\/zk\/sp1-impl\/implementation-receipt\.json/);
      expect(repo.git("status", "--porcelain", "--", RECEIPT), "the historical receipt is untouched").to.equal("");
    });

    it("the CLI's validation fails, with the binding's reason, where the binding does not hold", function () {
      mergeLane(repo);
      const run = cli("--validate");
      expect(run.status).to.equal(1);
      expect(run.stderr).to.match(/receipt-integration\.json is missing/);
    });
  });
});
