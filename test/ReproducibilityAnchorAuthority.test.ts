/**
 * Covered-content commitment is the freshness AUTHORITY; the capture's commit
 * SHA is a provenance hint that must never decide the verdict.
 *
 * THE DEFECT. `verifyPublicHeadCommitNotStale` compared recorded `sourceDigests`
 * against current HEAD's content — a comparison that needs no historical commit
 * at all — but kept "the capture commit's object is present locally" as a hard
 * PRECONDITION, returning `stale: null` otherwise. Under this repo's
 * squash-merge workflow that precondition is unsatisfiable by any honest
 * workflow: a capture must be taken on the PR branch (the content only exists
 * there), and squashing replaces those commits, so the anchor the capture just
 * created can never be retained by main. PR #164 followed the documented
 * recapture process exactly and produced three anchors — 7dfa6109, 5c62229b,
 * cb3ba5f2 — that main could not keep. Every subsequent CI run went red on
 * evidence that was, and remains, entirely valid: all three captures' digests
 * still match current HEAD byte for byte.
 *
 * WHAT AN ABSENT OBJECT ACTUALLY MEANS. Nothing specific. It may be a
 * squash-erased branch tip, a fabricated SHA, an object never fetched, or one
 * that has been garbage-collected. `fetch-depth: 0` gives complete history for
 * FETCHED REFS; it does not make every object that ever existed locally
 * available. Git cannot tell these apart, so this module does not pretend to:
 * the state is `anchor-unavailable`, never "squash-erased".
 *
 * THE AUTHORITY SPLIT.
 *
 *     covered source content at capture
 *             -> per-file digests
 *             -> canonical covered-content commitment      <- WHAT was captured
 *                          |
 *                       compare
 *                          |
 *     covered content at current HEAD (authenticated, always present)
 *                          |
 *                   freshness verdict
 *
 *     publicHeadCommit -> provenance hint only             <- WHERE it happened
 *       present    -> corroborate; a DISAGREEMENT is a hard failure
 *       absent     -> anchor-unavailable; verdict unaffected
 *
 * Shallowness is deliberately NOT coupled to freshness. "Stored covered-content
 * commitment equals current authenticated HEAD content" is computable in a
 * shallow checkout, because current HEAD is present by definition. Shallow
 * history matters for historical ancestry (verifyReportedCommitInPublicHistory,
 * the deployment-commit binding), which keeps its fail-closed behaviour.
 *
 * Every control runs against a REAL temporary git repository, and the
 * squash-erasure control performs a genuine `merge --squash` + branch delete +
 * `reflog expire` + `gc --prune=now` so the object is actually gone — not a
 * fabricated SHA standing in for one.
 *
 * Run:  npm test
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect } from "chai";
import { keccak256, toUtf8Bytes } from "ethers";

import {
  canonicalCoveredContentDigest,
  verifyCoveredContentAgainstHead,
} from "../scripts/lib/reproducibility-evidence";

const COVERED = "contracts/Covered.sol";
const OTHER = "contracts/Other.sol";
const ORIGINAL = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Covered { uint256 a; }\n";
const MUTATED = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Covered { uint256 b; }\n";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function write(repoDir: string, relPath: string, content: string): void {
  mkdirSync(join(repoDir, "contracts"), { recursive: true });
  writeFileSync(join(repoDir, relPath), content);
}

function commitAll(repoDir: string, message: string): string {
  git(["add", "-A"], repoDir);
  git(["commit", "-m", message], repoDir);
  return git(["rev-parse", "HEAD"], repoDir);
}

function initRepo(dir: string, name = "repo"): string {
  const repoDir = join(dir, name);
  mkdirSync(repoDir, { recursive: true });
  git(["init", "--initial-branch=main"], repoDir);
  git(["config", "user.email", "test@example.com"], repoDir);
  git(["config", "user.name", "Test"], repoDir);
  writeFileSync(join(repoDir, "README.md"), "base\n");
  commitAll(repoDir, "base");
  return repoDir;
}

function digestsFor(content: string, path = COVERED): Record<string, string> {
  return { [path]: keccak256(toUtf8Bytes(content)) };
}

function objectPresent(sha: string, repoDir: string): boolean {
  try {
    execFileSync("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: repoDir, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * The OLD rule, kept verbatim so each control can state whether it and the new
 * rule disagree on that fixture — the same technique
 * ReproducibilityStalenessContentAuthority.test.ts uses, so these are
 * discriminating regressions rather than vacuous restatements.
 *
 * The predecessor returned `stale: null` (inconclusive, which the manifest
 * checker treats as a hard error) whenever the anchor object was absent,
 * BEFORE looking at any content.
 */
function oldRuleWasInconclusive(anchorCommit: string, repoDir: string): boolean {
  return !objectPresent(anchorCommit, repoDir);
}

/**
 * A genuine squash merge that ERASES the branch commit: its tree lands on main
 * as a new single-parent commit, the branch ref is deleted, and the original
 * object is garbage-collected out of the object database.
 */
function squashMergeAndErase(repoDir: string, branch: string): void {
  git(["checkout", "main"], repoDir);
  git(["merge", "--squash", branch], repoDir);
  git(["commit", "-m", `squash ${branch}`], repoDir);
  git(["branch", "-D", branch], repoDir);
  git(["reflog", "expire", "--expire=now", "--all"], repoDir);
  git(["gc", "--prune=now", "--quiet"], repoDir);
}

describe("covered-content commitment is the freshness authority", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "repro-anchor-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  describe("canonicalCoveredContentDigest — a commitment to WHAT was captured", () => {
    it("is independent of key order", () => {
      const a = { "contracts/A.sol": keccak256(toUtf8Bytes("a")), "contracts/B.sol": keccak256(toUtf8Bytes("b")) };
      const b = { "contracts/B.sol": keccak256(toUtf8Bytes("b")), "contracts/A.sol": keccak256(toUtf8Bytes("a")) };
      expect(canonicalCoveredContentDigest(a)).to.equal(canonicalCoveredContentDigest(b));
    });

    it("changes when any covered file's content changes", () => {
      expect(canonicalCoveredContentDigest(digestsFor(ORIGINAL))).to.not.equal(
        canonicalCoveredContentDigest(digestsFor(MUTATED)),
      );
    });

    it("changes when a covered path is ADDED — the path SET is part of the commitment", () => {
      const one = digestsFor(ORIGINAL);
      const two = { ...one, ...digestsFor(ORIGINAL, OTHER) };
      expect(canonicalCoveredContentDigest(one)).to.not.equal(canonicalCoveredContentDigest(two));
    });

    it("changes when a covered path is RENAMED even if its content is identical", () => {
      expect(canonicalCoveredContentDigest(digestsFor(ORIGINAL, COVERED))).to.not.equal(
        canonicalCoveredContentDigest(digestsFor(ORIGINAL, OTHER)),
      );
    });

    it("is stable across separator style, so a Windows-shaped path cannot fork the commitment", () => {
      const posix = { "contracts/A.sol": keccak256(toUtf8Bytes("a")) };
      const win = { "contracts\\A.sol": keccak256(toUtf8Bytes("a")) };
      expect(canonicalCoveredContentDigest(posix)).to.equal(canonicalCoveredContentDigest(win));
    });
  });

  describe("CASE 1 — a real squash-erased anchor with identical content PASSES", () => {
    it("survives a genuine merge --squash + branch delete + gc that removes the object", () => {
      const repoDir = initRepo(dir);
      git(["checkout", "-b", "feature"], repoDir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "capture point on the PR branch");
      const captured = digestsFor(ORIGINAL);

      expect(objectPresent(captureCommit, repoDir), "precondition: object exists before squash").to.equal(true);
      squashMergeAndErase(repoDir, "feature");
      expect(objectPresent(captureCommit, repoDir), "the squash must genuinely erase the object").to.equal(false);

      // Discriminating: the old rule bailed out as inconclusive on this exact
      // fixture, which the manifest checker escalates to a hard error.
      expect(oldRuleWasInconclusive(captureCommit, repoDir), "old rule should have been inconclusive here").to.equal(
        true,
      );

      const result = verifyCoveredContentAgainstHead(captureCommit, captured, repoDir);
      expect(result.stale, result.error ?? "").to.equal(false);
      expect(result.anchor).to.equal("unavailable");
      // The commitment is what actually carries the proof, and both sides agree.
      expect(result.capturedContentDigest).to.equal(result.headContentDigest);
    });
  });

  describe("CASE 2 — a fabricated SHA gets anchor-unavailable, never 'verified'", () => {
    it("does not upgrade a missing anchor to corroborated provenance just because content matches", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      commitAll(repoDir, "add covered source");

      const fabricated = "e".repeat(40);
      const result = verifyCoveredContentAgainstHead(fabricated, digestsFor(ORIGINAL), repoDir);

      // Content is genuinely fresh, so the verdict is fresh...
      expect(result.stale).to.equal(false);
      // ...but nothing was corroborated, and the result must say so plainly.
      expect(result.anchor).to.equal("unavailable");
      expect(result.anchor).to.not.equal("verified");
    });

    it("is INDISTINGUISHABLE from the real squash-erased case, and says so rather than guessing", () => {
      // Git cannot tell an erased branch tip from a SHA that never existed. A
      // gate that claimed to know which one it was would be asserting something
      // it cannot observe.
      const repoDir = initRepo(dir);
      git(["checkout", "-b", "feature"], repoDir);
      write(repoDir, COVERED, ORIGINAL);
      const erased = commitAll(repoDir, "capture point");
      squashMergeAndErase(repoDir, "feature");

      const fromErased = verifyCoveredContentAgainstHead(erased, digestsFor(ORIGINAL), repoDir);
      const fromFabricated = verifyCoveredContentAgainstHead("e".repeat(40), digestsFor(ORIGINAL), repoDir);

      expect(fromErased.anchor).to.equal(fromFabricated.anchor);
      expect(fromErased.stale).to.equal(fromFabricated.stale);
      expect(fromErased.anchorDetail).to.not.match(/squash/i);
    });
  });

  describe("CASE 3 — HEAD content drift FAILS regardless of anchor availability", () => {
    it("fails with the anchor present", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");
      write(repoDir, COVERED, MUTATED);
      commitAll(repoDir, "change covered source after capture");

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), repoDir);
      expect(objectPresent(captureCommit, repoDir)).to.equal(true);
      expect(result.anchor).to.equal("verified");
      expect(result.stale).to.equal(true);
      expect(result.changedFiles.join(" ")).to.contain(COVERED);
    });

    it("fails just as hard with the anchor erased — a missing anchor is not a free pass", () => {
      const repoDir = initRepo(dir);
      git(["checkout", "-b", "feature"], repoDir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "capture point");
      squashMergeAndErase(repoDir, "feature");
      write(repoDir, COVERED, MUTATED);
      commitAll(repoDir, "change covered source after the squash");

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), repoDir);
      expect(result.anchor).to.equal("unavailable");
      expect(result.stale).to.equal(true);
    });

    it("fails when a covered file no longer exists at HEAD", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");
      rmSync(join(repoDir, COVERED));
      commitAll(repoDir, "delete covered source");

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), repoDir);
      expect(result.stale).to.equal(true);
      expect(result.headContentDigest).to.equal(null);
    });
  });

  describe("CASE 4 — an AVAILABLE anchor whose tree contradicts the stored digests fails hard", () => {
    it("reports contradicted, not verified, and never silently ignores the disagreement", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");

      // Digests that describe content the anchor commit never held. HEAD is then
      // made to match them, so the freshness comparison alone would say "fresh" —
      // only the anchor corroboration can catch that the label is a lie.
      write(repoDir, COVERED, MUTATED);
      commitAll(repoDir, "HEAD now holds the content the digests claim");

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(MUTATED), repoDir);
      expect(objectPresent(captureCommit, repoDir)).to.equal(true);
      expect(result.stale, "content genuinely does match HEAD").to.equal(false);
      expect(result.anchor).to.equal("contradicted");
      expect(result.anchorDetail).to.contain(COVERED);
    });

    it("also contradicts when a covered path did not exist at the anchor commit at all", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");
      write(repoDir, OTHER, ORIGINAL);
      commitAll(repoDir, "add a second file after the capture");

      const claimed = { ...digestsFor(ORIGINAL, COVERED), ...digestsFor(ORIGINAL, OTHER) };
      const result = verifyCoveredContentAgainstHead(captureCommit, claimed, repoDir);
      expect(result.stale).to.equal(false);
      expect(result.anchor).to.equal("contradicted");
      expect(result.anchorDetail).to.contain(OTHER);
    });
  });

  describe("shallow checkouts — decoupled from freshness, still fail-closed for ancestry", () => {
    function shallowClone(sourceRepo: string): string {
      const target = join(dir, "shallow");
      const url = `file:///${sourceRepo.replace(/\\/g, "/").replace(/^\//, "")}`;
      git(["clone", "--depth", "1", url, target], dir);
      return target;
    }

    it("computes a freshness verdict in a shallow clone — current HEAD is present by definition", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");
      const shallow = shallowClone(repoDir);
      expect(git(["rev-parse", "--is-shallow-repository"], shallow)).to.equal("true");

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), repoDir);
      expect(result.stale).to.equal(false);

      const shallowResult = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), shallow);
      expect(shallowResult.stale, shallowResult.error ?? "").to.equal(false);
    });

    it("still detects drift in a shallow clone", () => {
      const repoDir = initRepo(dir);
      write(repoDir, COVERED, ORIGINAL);
      const captureCommit = commitAll(repoDir, "add covered source");
      write(repoDir, COVERED, MUTATED);
      commitAll(repoDir, "drift");
      const shallow = shallowClone(repoDir);

      const result = verifyCoveredContentAgainstHead(captureCommit, digestsFor(ORIGINAL), shallow);
      expect(result.stale).to.equal(true);
    });
  });

  describe("genuinely uncomputable cases stay inconclusive", () => {
    it("a capture that bound NO files proves nothing about freshness", () => {
      const repoDir = initRepo(dir);
      const head = git(["rev-parse", "HEAD"], repoDir);
      const result = verifyCoveredContentAgainstHead(head, {}, repoDir);
      expect(result.stale).to.equal(null);
      expect(result.error).to.be.a("string");
    });

    it("an unresolvable HEAD is inconclusive, never a false 'fresh'", () => {
      const notARepo = join(dir, "not-a-repo");
      mkdirSync(notARepo, { recursive: true });
      const result = verifyCoveredContentAgainstHead("a".repeat(40), digestsFor(ORIGINAL), notARepo);
      expect(result.stale).to.equal(null);
    });
  });
});
