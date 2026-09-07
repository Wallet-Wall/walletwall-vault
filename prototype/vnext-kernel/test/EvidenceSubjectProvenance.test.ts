/**
 * EVIDENCE SUBJECT vs EVIDENCE CONTAINER — the provenance semantics, under test.
 *
 * WHAT WAS WRONG. `generate-stateful-evidence.ts` derived `receipt.head` / `receipt.tree` from
 * `git rev-parse HEAD`. `HEAD` is the CONTAINER — the commit that will hold the receipt — not the
 * SUBJECT the receipt is evidence about. The two coincide only when an operator runs the generator
 * on a clean checkout of the subject, and CI supplies no operator. For PR #194 that produced three
 * different heads for one body of evidence, the worst of them an ephemeral `refs/pull/194/merge`
 * id that exists in no clone and can never be checked out.
 *
 * WHY COUNT ASSERTIONS DID NOT CATCH IT. `StatefulAuthorityFuzz.test.ts` asserts campaign,
 * transition, profile, invariant and mutation COUNTS against the receipt. Every one of those was
 * green while the head was wrong, because none of them looks at provenance at all. Counts detect a
 * receipt describing the wrong MATRIX; nothing detected a receipt describing the wrong COMMIT.
 *
 * The first block below is the kill: it fails against the old semantics and passes against the new.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";

import {
  assertReceiptMatchesSubject,
  resolveEvidenceSubject,
  SUBJECT_HEAD_PATH,
  SUBJECT_TREE_PATH,
  type RevResolver,
} from "../evidence-subject.js";

const MEASUREMENTS_PATH = "prototype/vnext-kernel/MEASUREMENTS.json";
const RECEIPT_PATH = "prototype/vnext-kernel/STATEFUL_AUTHORITY_EVIDENCE.json";

/** Stand-in object ids. Distinct and well-formed, so only the LOGIC can decide between them. */
const SUBJECT_HEAD = "1111111111111111111111111111111111111111";
const SUBJECT_TREE = "2222222222222222222222222222222222222222";
const CONTAINER_HEAD = "3333333333333333333333333333333333333333";
const CONTAINER_TREE = "4444444444444444444444444444444444444444";

/**
 * A resolver that RECORDS every revision it is asked for.
 *
 * This is what makes the central claim observable rather than asserted. "The derivation does not
 * consult the container" is a statement about which revisions get resolved, so the test reads the
 * query log instead of grepping the source. It also answers `HEAD` with the CONTAINER — so a
 * regression that reintroduces container-stamping does not merely fail, it fails by returning
 * exactly the wrong, specific value.
 */
function recordingResolver(): { resolve: RevResolver; queries: string[] } {
  const queries: string[] = [];
  const resolve: RevResolver = (rev) => {
    queries.push(rev);
    if (rev === "HEAD" || rev === "HEAD^{commit}") return CONTAINER_HEAD;
    if (rev === "HEAD^{tree}") return CONTAINER_TREE;
    if (rev === SUBJECT_HEAD + "^{commit}") return SUBJECT_HEAD;
    if (rev === SUBJECT_HEAD + "^{tree}") return SUBJECT_TREE;
    throw new Error("unresolvable revision: " + rev);
  };
  return { resolve, queries };
}

const declaring = (head: unknown, tree: unknown) => ({ validation: { measuredAtHead: head, measuredAtTree: tree } });

describe("vNext Kernel — evidence subject provenance", function () {
  describe("the derivation names the SUBJECT and never the container", function () {
    it("returns the declared subject even when HEAD resolves to a different commit", function () {
      const { resolve } = recordingResolver();

      const subject = resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), resolve);

      // THE KILL. Under the old `rev-parse HEAD` semantics this returns CONTAINER_HEAD. The
      // resolver above answers `HEAD` with exactly that, so the bad implementation cannot pass by
      // coincidence — it produces the container id and this assertion names the difference.
      expect(subject.head, "provenance was taken from the container, not the declared subject").to.equal(
        SUBJECT_HEAD,
      );
      expect(subject.tree).to.equal(SUBJECT_TREE);
      expect(subject.head).to.not.equal(CONTAINER_HEAD);
      expect(subject.tree).to.not.equal(CONTAINER_TREE);
    });

    it("never asks git for HEAD at all", function () {
      const { resolve, queries } = recordingResolver();

      resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), resolve);

      // Stronger than checking the return value: the container is not merely unused, it is
      // UNREACHABLE from this code path. A derivation that cannot observe `HEAD` cannot be made to
      // depend on the trigger, the checkout mode or the working directory.
      const headQueries = queries.filter((q) => q.includes("HEAD"));
      expect(headQueries, "the derivation consulted HEAD, which is the container").to.deep.equal([]);
      expect(queries, "expected only subject-anchored revisions").to.deep.equal([
        SUBJECT_HEAD + "^{commit}",
        SUBJECT_HEAD + "^{tree}",
      ]);
    });

    it("is a pure function of the declaration — a different container cannot move it", function () {
      // Two resolvers disagreeing about HEAD, agreeing about the subject. Same answer both times.
      const alternate: RevResolver = (rev) => {
        if (rev === "HEAD" || rev === "HEAD^{commit}") return "9999999999999999999999999999999999999999";
        if (rev === SUBJECT_HEAD + "^{commit}") return SUBJECT_HEAD;
        if (rev === SUBJECT_HEAD + "^{tree}") return SUBJECT_TREE;
        throw new Error("unresolvable revision: " + rev);
      };
      const a = resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), recordingResolver().resolve);
      const b = resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), alternate);
      expect(a).to.deep.equal(b);
    });
  });

  describe("fail-closed: generation REFUSES rather than guessing", function () {
    it("refuses when no validation block declares a subject", function () {
      expect(() => resolveEvidenceSubject({}, recordingResolver().resolve)).to.throw(/EVIDENCE SUBJECT UNDECLARED/);
    });

    it("refuses when the subject head is missing", function () {
      expect(() => resolveEvidenceSubject(declaring(undefined, SUBJECT_TREE), recordingResolver().resolve)).to.throw(
        /EVIDENCE SUBJECT MALFORMED/,
      );
    });

    it("refuses an abbreviated object id", function () {
      expect(() => resolveEvidenceSubject(declaring("be1789f4", SUBJECT_TREE), recordingResolver().resolve)).to.throw(
        /EVIDENCE SUBJECT MALFORMED/,
      );
    });

    it("refuses a non-string subject", function () {
      expect(() => resolveEvidenceSubject(declaring(42, SUBJECT_TREE), recordingResolver().resolve)).to.throw(
        /EVIDENCE SUBJECT MALFORMED/,
      );
    });

    it("refuses when the subject commit does not exist, and says so rather than falling back", function () {
      const absent: RevResolver = () => {
        throw new Error("fatal: Not a valid object name");
      };
      // The message must point at the real cause. A shallow CI checkout does not contain the
      // subject, because the subject is an ANCESTOR of the container; the fix is fetch-depth, and
      // NEVER a fallback to HEAD.
      let thrown: unknown;
      try {
        resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), absent);
      } catch (e) {
        thrown = e;
      }
      expect(thrown, "an absent subject must throw, never fall back").to.be.instanceOf(Error);
      const message = (thrown as Error).message;
      expect(message).to.match(/EVIDENCE SUBJECT UNRESOLVABLE/);
      expect(message, "the message must name the real cause so CI is actionable").to.match(/fetch-depth/);
      expect(message, "the message must forbid the fallback explicitly").to.match(/NOT A REASON TO FALL BACK/);
    });

    it("refuses when the declared tree does not belong to the declared head", function () {
      const mismatched: RevResolver = (rev) => {
        if (rev === SUBJECT_HEAD + "^{commit}") return SUBJECT_HEAD;
        if (rev === SUBJECT_HEAD + "^{tree}") return "5555555555555555555555555555555555555555";
        throw new Error("unresolvable revision: " + rev);
      };
      expect(() => resolveEvidenceSubject(declaring(SUBJECT_HEAD, SUBJECT_TREE), mismatched)).to.throw(
        /EVIDENCE SUBJECT INCONSISTENT/,
      );
    });

    it("refuses a tree id pasted into the head field", function () {
      // `^{commit}` peels; a tree cannot be peeled to a commit, and real git exits non-zero. This
      // is why the check peels rather than merely testing existence.
      const peeling: RevResolver = (rev) => {
        if (rev === SUBJECT_TREE + "^{commit}") throw new Error("error: expected commit type, but dereferences to tree");
        throw new Error("unresolvable revision: " + rev);
      };
      expect(() => resolveEvidenceSubject(declaring(SUBJECT_TREE, SUBJECT_TREE), peeling)).to.throw(
        /EVIDENCE SUBJECT UNRESOLVABLE/,
      );
    });
  });

  describe("what was WRITTEN carries the subject", function () {
    it("accepts a receipt whose provenance matches", function () {
      expect(() =>
        assertReceiptMatchesSubject({ head: SUBJECT_HEAD, tree: SUBJECT_TREE }, { head: SUBJECT_HEAD, tree: SUBJECT_TREE }, "x.json"),
      ).to.not.throw();
    });

    it("rejects a receipt stamped with the container", function () {
      expect(() =>
        assertReceiptMatchesSubject(
          { head: CONTAINER_HEAD, tree: CONTAINER_TREE },
          { head: SUBJECT_HEAD, tree: SUBJECT_TREE },
          "x.json",
        ),
      ).to.throw(/RECEIPT PROVENANCE MISMATCH/);
    });
  });

  describe("the COMMITTED artifacts agree, against the real repository", function () {
    const git = (args: string[]) => execFileSync("git", args, { encoding: "utf8" }).trim();
    const measurements = JSON.parse(fs.readFileSync(MEASUREMENTS_PATH, "utf8"));
    const receipt = JSON.parse(fs.readFileSync(RECEIPT_PATH, "utf8"));

    it("resolves the declared subject against real git", function () {
      // Also the canary for a shallow clone: if CI ever loses `fetch-depth: 0`, this fails loudly
      // instead of self-skipping. A guard that quietly passes on a shallow checkout proves nothing.
      const subject = resolveEvidenceSubject(measurements);
      expect(subject.head).to.equal(measurements.validation.measuredAtHead);
      expect(git(["rev-parse", subject.head + "^{tree}"])).to.equal(subject.tree);
    });

    it("the committed receipt names the declared subject, not its own container", function () {
      const subject = resolveEvidenceSubject(measurements);
      expect(receipt.head, "receipt.head must equal " + SUBJECT_HEAD_PATH).to.equal(subject.head);
      expect(receipt.tree, "receipt.tree must equal " + SUBJECT_TREE_PATH).to.equal(subject.tree);
    });

    it("the receipt does NOT name the commit that contains it", function () {
      // Not a tautology. This is the property that was FALSE for every CI-generated artifact of
      // #194, and it is the whole point of separating subject from container.
      //
      // THE ORACLE IS READ RAW FROM JSON, NEVER THROUGH `resolveEvidenceSubject`. Deriving the
      // expected value from the function under test is how a mutation survives: a container-stamping
      // mutant would make declared == container and this check would pass VACUOUSLY. Measured, not
      // assumed — that mutant was executed and this assertion is what had to be hardened.
      const containerHead = git(["rev-parse", "HEAD"]);
      const declaredHead: string = measurements.validation.measuredAtHead;
      if (containerHead === declaredHead) {
        // Legitimate mid-lane state: the tree is a clean checkout of the subject itself, evidence
        // not yet committed. Nothing to discriminate here.
        return;
      }
      expect(receipt.head).to.not.equal(containerHead);
    });
  });

  describe("evidence CURRENCY — the subject still describes the code that publishes it", function () {
    /*
     * WITHOUT THIS, BYTE-IDENTITY IS CIRCULAR. Once the receipt derives its provenance from
     * MEASUREMENTS.json, regenerating and byte-comparing proves REPRODUCIBILITY and nothing else: a
     * receipt that faithfully describes a subject from ten commits ago reproduces perfectly. What
     * makes the evidence VALID for the tree publishing it is that the inputs it measured have not
     * moved between subject and container.
     *
     * Scoped to the paths the campaign actually measures rather than to the whole tree, so an
     * unrelated change elsewhere in the repository is not misreported as evidence staleness.
     *
     * THIS IS RED AT AN IMPLEMENTATION COMMIT, BY DESIGN, and that redness is correct: at that
     * commit the declared subject genuinely predates the code. It goes green at the evidence commit,
     * where MEASUREMENTS.json declares the new subject. That is the same two-commit protocol
     * `stateful/README.md` records for lane W2.
     */
    const EVIDENCE_INPUTS = ["prototype/vnext-kernel/contracts", "prototype/vnext-kernel/stateful"];

    it("the measured inputs are byte-identical between subject and container", function () {
      const git = (args: string[]) => execFileSync("git", args, { encoding: "utf8" }).trim();
      const measurements = JSON.parse(fs.readFileSync(MEASUREMENTS_PATH, "utf8"));
      // Raw from JSON, for the same anti-vacuity reason as above: routed through
      // `resolveEvidenceSubject`, a container-stamping mutant would compare HEAD against HEAD and
      // pass trivially.
      const declaredHead: string = measurements.validation.measuredAtHead;
      const containerHead = git(["rev-parse", "HEAD"]);

      const drifted = EVIDENCE_INPUTS.filter(
        (p) => git(["rev-parse", declaredHead + ":" + p]) !== git(["rev-parse", containerHead + ":" + p]),
      );

      expect(
        drifted,
        "these measured inputs changed between the declared evidence subject (" +
          declaredHead.slice(0, 8) +
          ") and the commit publishing the evidence (" +
          containerHead.slice(0, 8) +
          "). The receipt reproduces byte-identically but describes code that has since moved: " +
          "re-measure and re-declare " +
          SUBJECT_HEAD_PATH +
          ".",
      ).to.deep.equal([]);
    });
  });
});
