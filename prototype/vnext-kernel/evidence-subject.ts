/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * EVIDENCE SUBJECT vs EVIDENCE CONTAINER — the one distinction this module exists to enforce.
 *
 * A generated receipt is ABOUT a commit (its SUBJECT). It is committed IN a commit (its
 * CONTAINER). These are necessarily different objects, and the reason is SELF-REFERENCE rather
 * than ordering. A tree object is perfectly constructible before the commit that references it --
 * `git write-tree` does exactly that. The obstruction is that an artifact embedding the identity
 * of the tree CONTAINING it makes its own bytes part of the identity it is trying to state: change
 * the embedded value and the tree hash changes, which changes the value that should have been
 * embedded. Embedding the containing COMMIT id is worse still, since that id also depends on the
 * message, author and timestamps. So evidence names its SUBJECT -- a tree already fixed and
 * outside the artifact -- and the two-commit shape follows from the artifact's content.
 * That is why evidence lands in a second commit, and why `stateful/README.md` states the
 * repository convention as "a receipt identifies its SOURCE, never the commit that happens to
 * contain it."
 *
 * WHAT WENT WRONG, AND WHY A CONVENTION WAS NOT ENOUGH. The generators derived provenance from
 * `git rev-parse HEAD`, which is the CONTAINER, and therefore satisfied the convention only when
 * an operator happened to run them on a clean checkout of the subject. Nothing enforced that, and
 * CI supplies no such operator. For PR #194 the same evidence consequently exists under three
 * different heads:
 *
 *   committed in the PR      be1789f4...  the implementation subject   (correct)
 *   CI push-run artifact     87a3f056...  the container                (wrong)
 *   CI pull_request artifact 43426b22...  refs/pull/194/merge          (UNRESOLVABLE)
 *
 * The third is the decisive one. `43426b22...` is a SYNTHETIC GitHub PR merge commit: it is
 * trigger-dependent (the `pull_request` run has one, the `push` run of the same commit does not),
 * transient and non-canonical (GitHub recreates it as base or head move, and it is reachable from
 * no branch), and absent from an ordinary clone unless `refs/pull/N/merge` is fetched explicitly.
 * It is fetchable -- do not overstate this -- but it is NOT A DURABLE EVIDENCE SUBJECT. Provenance
 * that changes with which trigger fired is not provenance.
 *
 * THE FIX IS TO DERIVE, NOT TO STAMP. The subject is DECLARED once, in canonical measurements, and
 * every artifact derives from that declaration. `HEAD` is not consulted, so no trigger, checkout
 * mode or working directory can influence what a receipt claims to describe.
 */
import { execFileSync } from "node:child_process";

/** The commit an artifact is evidence ABOUT — never the commit that contains the artifact. */
export interface EvidenceSubject {
  head: string;
  tree: string;
}

/**
 * Resolves a git revision expression to an object id, exactly as `git rev-parse <rev>` does, and
 * THROWS when the revision does not resolve.
 *
 * Injectable on purpose. It is what makes "does this derivation consult HEAD?" a question a test
 * can answer by OBSERVATION — a fake resolver records every revision it is asked for — rather than
 * by reading the source and hoping.
 */
export type RevResolver = (rev: string) => string;

/**
 * The ONLY path in MEASUREMENTS.json that carries the evidence subject.
 *
 * BOUND TO A PATH, NEVER TO A NAME. `measuredAtHead` is not unique in that file:
 * `scannerCoverage.measuredAtHead` is a DIFFERENT and deliberately older anchor, because the
 * Slither counts describe an earlier head and that block says so. A name-based lookup would
 * silently pick up whichever one it met first.
 */
export const SUBJECT_HEAD_PATH = "validation.measuredAtHead";
export const SUBJECT_TREE_PATH = "validation.measuredAtTree";

/** Shape this module depends on. Deliberately minimal — everything else in the file is ignored. */
export interface SubjectBearingMeasurements {
  validation?: { measuredAtHead?: unknown; measuredAtTree?: unknown };
}

const OBJECT_ID = /^[0-9a-f]{40}$/;

/** The real resolver. Throws on an unresolvable revision, which is what fail-closed depends on. */
export const gitRevParse: RevResolver = (rev) =>
  execFileSync("git", ["rev-parse", rev], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/**
 * Derive the evidence subject from canonical measurements, FAIL-CLOSED at every step.
 *
 * Refuses rather than guesses. Each check below corresponds to a way the declaration can be wrong,
 * and in every case refusing to generate is strictly better than publishing a receipt whose
 * provenance is decorative.
 */
export function resolveEvidenceSubject(
  measurements: SubjectBearingMeasurements,
  resolveRev: RevResolver = gitRevParse,
): EvidenceSubject {
  const validation = measurements?.validation;
  if (validation === undefined || validation === null || typeof validation !== "object") {
    throw new Error(
      "EVIDENCE SUBJECT UNDECLARED: MEASUREMENTS.json has no `validation` block, so there is no " +
        "designated subject to generate against. Evidence is never generated against `HEAD`.",
    );
  }

  const head = validation.measuredAtHead;
  const tree = validation.measuredAtTree;

  for (const [label, value] of [
    [SUBJECT_HEAD_PATH, head],
    [SUBJECT_TREE_PATH, tree],
  ] as const) {
    if (typeof value !== "string" || !OBJECT_ID.test(value)) {
      throw new Error(
        "EVIDENCE SUBJECT MALFORMED: " +
          label +
          " must be a full 40-character lowercase git object id, got " +
          JSON.stringify(value) +
          ". An abbreviated or absent id cannot be verified against the repository.",
      );
    }
  }

  const declaredHead = head as string;
  const declaredTree = tree as string;

  // SUBJECT HEAD EXISTS, and is a COMMIT. `^{commit}` peels, so this also rejects a tree or blob
  // id pasted into the head field. Absent objects exit non-zero, which surfaces here as a throw.
  let resolvedHead: string;
  try {
    resolvedHead = resolveRev(declaredHead + "^{commit}");
  } catch (cause) {
    throw new Error(
      "EVIDENCE SUBJECT UNRESOLVABLE: " +
        SUBJECT_HEAD_PATH +
        " = " +
        declaredHead +
        " is not a commit in this repository. THIS IS NOT A REASON TO FALL BACK TO HEAD. If this " +
        "is CI, the checkout is almost certainly shallow: the subject is an ANCESTOR of the " +
        "container, so `actions/checkout` needs `fetch-depth: 0`. Generating against the container " +
        "instead is the exact defect this check exists to prevent.",
      { cause },
    );
  }
  if (resolvedHead !== declaredHead) {
    throw new Error(
      "EVIDENCE SUBJECT AMBIGUOUS: " + declaredHead + " peeled to " + resolvedHead + ", not itself.",
    );
  }

  // SUBJECT TREE MATCHES SUBJECT HEAD. The declared pair must be internally consistent; a tree
  // that belongs to a different commit means the declaration was edited by hand and got it wrong.
  const actualTree = resolveRev(declaredHead + "^{tree}");
  if (actualTree !== declaredTree) {
    throw new Error(
      "EVIDENCE SUBJECT INCONSISTENT: " +
        SUBJECT_HEAD_PATH +
        " = " +
        declaredHead +
        " has tree " +
        actualTree +
        ", but " +
        SUBJECT_TREE_PATH +
        " declares " +
        declaredTree +
        ". The declaration is self-contradictory; correct MEASUREMENTS.json rather than the receipt.",
    );
  }

  return { head: declaredHead, tree: declaredTree };
}

/**
 * Post-generation check: what was actually WRITTEN carries the subject.
 *
 * Separate from the derivation on purpose. The derivation proves the subject was computed
 * correctly; this proves it survived serialisation into the artifact a reader will actually open.
 */
export function assertReceiptMatchesSubject(
  receipt: { head?: unknown; tree?: unknown },
  subject: EvidenceSubject,
  artifactPath: string,
): void {
  if (receipt.head !== subject.head || receipt.tree !== subject.tree) {
    throw new Error(
      "RECEIPT PROVENANCE MISMATCH in " +
        artifactPath +
        ": wrote head=" +
        String(receipt.head) +
        " tree=" +
        String(receipt.tree) +
        " but the designated subject is head=" +
        subject.head +
        " tree=" +
        subject.tree +
        ".",
    );
  }
}
