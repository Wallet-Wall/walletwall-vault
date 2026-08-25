/**
 * Staleness AUTHORITY: `verifyCoveredContentAgainstHead` must decide staleness from
 * source CONTENT, never from commit topology.
 *
 * The bug this closes: the function's own name and docstring claimed a
 * "SOURCE-CONTENT check", but it was implemented as
 * `git log <captureCommit>..HEAD -- <sourceFiles>` — i.e. it asked "did a later commit
 * TOUCH this path?", not "is HEAD's content different from what was captured?". Those
 * two questions diverge precisely under this repo's normal squash-merge workflow:
 * squash-merging a PR replaces its branch history with a NEW single-parent commit that
 * necessarily touches every covered path the PR edited, so evidence correctly captured
 * on the PR branch — with byte-identical resulting content — was reported stale the
 * instant it merged. PR #159 is the worked example: branch head 14fd579 was squashed
 * into 091c04c (single parent d96ad7d), invalidating evidence that PR had correctly
 * recaptured pre-merge and forcing a post-merge repair; PR #160 then inherited the same
 * red gate. The invariant enforced here instead:
 *
 *     public-head evidence is stale
 *     IFF current HEAD's covered source CONTENT != the content the evidence captured
 *
 * Every control below runs against a REAL temporary git repository (same approach as
 * ReproducibilityCaptureBuild.test.ts) so the topology being tested is genuine git
 * history, not a mock. The squash control additionally asserts, in-test, that the OLD
 * topology-based query WOULD have reported stale on the very same fixture — so it is a
 * discriminating regression test, not a vacuous one.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect } from "chai";
import { keccak256, toUtf8Bytes } from "ethers";

import { verifyCoveredContentAgainstHead } from "../scripts/lib/reproducibility-evidence";

const COVERED = "contracts/Covered.sol";
const ORIGINAL = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Covered { uint256 a; }\n";
const MUTATED = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Covered { uint256 b; }\n";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function writeCovered(repoDir: string, content: string): void {
  mkdirSync(join(repoDir, "contracts"), { recursive: true });
  writeFileSync(join(repoDir, COVERED), content);
}

function commitAll(repoDir: string, message: string): string {
  git(["add", "-A"], repoDir);
  git(["commit", "-m", message], repoDir);
  return git(["rev-parse", "HEAD"], repoDir);
}

/** A fresh repo with one base commit that does NOT yet contain the covered file. */
function initRepo(dir: string): string {
  const repoDir = join(dir, "repo");
  mkdirSync(repoDir, { recursive: true });
  git(["init", "--initial-branch=main"], repoDir);
  git(["config", "user.email", "test@example.com"], repoDir);
  git(["config", "user.name", "Test"], repoDir);
  writeFileSync(join(repoDir, "README.md"), "base\n");
  commitAll(repoDir, "base");
  return repoDir;
}

/** The digest map a capture would have recorded for `content`. */
function digestsFor(content: string): Record<string, string> {
  return { [COVERED]: keccak256(toUtf8Bytes(content)) };
}

/** The OLD, topology-based implementation, kept verbatim here purely so each control can
 *  assert whether it and the new content-based rule agree or disagree on that fixture. */
function oldTopologyStale(captureCommit: string, repoDir: string): boolean {
  const out = execFileSync("git", ["log", "--oneline", `${captureCommit}..HEAD`, "--", COVERED], {
    cwd: repoDir,
    encoding: "utf8",
  });
  return out.trim().length > 0;
}

describe("verifyCoveredContentAgainstHead — staleness is CONTENT, not commit topology", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "repro-staleness-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("CONTROL 1 (the regression this closes): same content + different commit topology (squash-merge) is NOT stale", () => {
    const repoDir = initRepo(dir);
    const base = git(["rev-parse", "HEAD"], repoDir);

    // Feature branch adds the covered file; evidence is captured HERE (pre-merge),
    // exactly as the repo's documented capture model prescribes.
    git(["checkout", "-b", "feature"], repoDir);
    writeCovered(repoDir, ORIGINAL);
    const branchHead = commitAll(repoDir, "feat: add covered source");
    const captured = digestsFor(ORIGINAL);

    // Squash-merge: a NEW single-parent commit on main carrying the branch's TREE but
    // none of its history — the branch commit is not an ancestor of the result.
    git(["checkout", "main"], repoDir);
    git(["merge", "--squash", "feature"], repoDir);
    const squashed = commitAll(repoDir, "feat: add covered source (#159)");
    expect(git(["rev-list", "--parents", "-n", "1", squashed], repoDir).split(" ")).to.have.lengthOf(2); // single parent
    expect(squashed).to.not.equal(branchHead);
    expect(git(["rev-list", "--parents", "-n", "1", squashed], repoDir).split(" ")[1]).to.equal(base);

    // The content is byte-identical across the squash...
    expect(git(["show", `HEAD:${COVERED}`], repoDir)).to.equal(git(["show", `${branchHead}:${COVERED}`], repoDir));

    // ...but the OLD topology query DOES report stale here — proving this control is
    // discriminating against the previous implementation rather than vacuous.
    expect(oldTopologyStale(branchHead, repoDir), "old topology check should have flagged this").to.equal(true);

    // The content-based authority correctly reports NOT stale.
    const result = verifyCoveredContentAgainstHead(branchHead, captured, repoDir);
    expect(result.stale, JSON.stringify(result.changedFiles)).to.equal(false);
    expect(result.changedFiles).to.deep.equal([]);
  });

  it("CONTROL 2: an actual covered-source mutation IS stale, and names the diverging file", () => {
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    const captureCommit = commitAll(repoDir, "add covered source");
    const captured = digestsFor(ORIGINAL);

    // A real edit to the covered source lands after capture.
    writeCovered(repoDir, MUTATED);
    commitAll(repoDir, "edit covered source");

    const result = verifyCoveredContentAgainstHead(captureCommit, captured, repoDir);
    expect(result.stale).to.equal(true);
    expect(result.changedFiles).to.have.lengthOf(1);
    expect(result.changedFiles[0]).to.contain(COVERED);
    expect(result.changedFiles[0]).to.contain(keccak256(toUtf8Bytes(MUTATED))); // actual HEAD content
    expect(result.changedFiles[0]).to.contain(keccak256(toUtf8Bytes(ORIGINAL))); // what was captured
  });

  it("CONTROL 3: a mutation followed by an exact revert is NOT stale (content is what matters, not that it churned)", () => {
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    const captureCommit = commitAll(repoDir, "add covered source");
    const captured = digestsFor(ORIGINAL);

    writeCovered(repoDir, MUTATED);
    commitAll(repoDir, "edit covered source");
    writeCovered(repoDir, ORIGINAL); // exact revert, two commits of churn in between
    commitAll(repoDir, "revert covered source");

    // Two later commits touched the path, so the old topology check would flag it...
    expect(oldTopologyStale(captureCommit, repoDir), "old topology check should have flagged this").to.equal(true);
    // ...but the content is identical to what was captured, so it is NOT stale.
    const result = verifyCoveredContentAgainstHead(captureCommit, captured, repoDir);
    expect(result.stale, JSON.stringify(result.changedFiles)).to.equal(false);
  });

  it("CONTROL 4: an unavailable capture commit yields anchor-unavailable — freshness still decided by content", () => {
    // DELIBERATE SEMANTIC CHANGE. This control previously required `stale: null`
    // whenever the capture commit's object was absent, on the reasoning that a
    // shallow checkout cannot authenticate the digests either. Two things were
    // conflated there. First, "object absent" does not mean "repo is shallow" —
    // it is equally an erased branch tip, a never-fetched object, or a collected
    // one, and git cannot tell them apart. Second, and decisively, the digests do
    // not need the historical commit to be authenticated: they are compared
    // against CURRENT HEAD's tree, which is real, present, and authenticated in
    // any checkout able to run this at all.
    //
    // Keeping the old coupling made a squash-merge workflow unserviceable: a
    // public-HEAD capture can only be taken on the PR branch, and squashing
    // erases that anchor, so correct evidence failed on every later run. The
    // absence is now REPORTED as lost provenance rather than converted into an
    // unprovable freshness verdict. See ReproducibilityAnchorAuthority.test.ts
    // for the full set, including a genuine merge --squash + gc erasure.
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    commitAll(repoDir, "add covered source");

    const fabricated = "e".repeat(40);
    const result = verifyCoveredContentAgainstHead(fabricated, digestsFor(ORIGINAL), repoDir);
    expect(result.stale).to.equal(false);
    expect(result.anchor).to.equal("unavailable");
    // Crucially NOT upgraded to corroborated provenance just because content matched.
    expect(result.anchor).to.not.equal("verified");
    expect(result.anchorDetail).to.be.a("string");
  });

  it("CONTROL 5: a wrong/tampered recorded source digest FAILS (stale), even with clean topology", () => {
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    const captureCommit = commitAll(repoDir, "add covered source");

    // Nothing has touched the path since capture, so the OLD topology check would have
    // passed this outright — a fabricated digest was simply never consulted.
    expect(oldTopologyStale(captureCommit, repoDir), "topology is clean on this fixture").to.equal(false);

    const tampered = { [COVERED]: keccak256(toUtf8Bytes("something the repo never contained")) };
    const result = verifyCoveredContentAgainstHead(captureCommit, tampered, repoDir);
    expect(result.stale).to.equal(true);
    expect(result.changedFiles[0]).to.contain(COVERED);
  });

  it("CONTROL 6: a covered file deleted or renamed since capture IS stale, not a silent pass", () => {
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    const captureCommit = commitAll(repoDir, "add covered source");
    const captured = digestsFor(ORIGINAL);

    git(["rm", COVERED], repoDir);
    commitAll(repoDir, "remove covered source");

    const result = verifyCoveredContentAgainstHead(captureCommit, captured, repoDir);
    expect(result.stale).to.equal(true);
    expect(result.changedFiles[0]).to.contain("no longer present at current HEAD");
  });

  it("CONTROL 7: an empty sourceDigests map is INCONCLUSIVE — a capture binding no files proves nothing", () => {
    const repoDir = initRepo(dir);
    writeCovered(repoDir, ORIGINAL);
    const captureCommit = commitAll(repoDir, "add covered source");

    const result = verifyCoveredContentAgainstHead(captureCommit, {}, repoDir);
    expect(result.stale).to.equal(null);
    expect(result.error).to.contain("no source files");
  });
});
