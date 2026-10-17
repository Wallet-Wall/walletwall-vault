/**
 * The SP1 implementation receipt after its merge: the integration binding
 * (evidence/zk/sp1-impl/receipt-integration.json; docs/SP1_Impl_Receipt_Integration.md).
 *
 * The receipt (scripts/lib/sp1-impl-receipt.ts) is historical. Its lane derived it against the lane's base, and the
 * pull request was reviewed at its head; the merge moved those bytes into main without changing them. Three things are
 * kept apart, each read from git:
 *
 *   the historical lane base   the main commit the lane began from (the receipt's baseCommit), which the receipt states
 *                              its change set against; an immutable fact about the lane;
 *   the reviewed subject       the head the pull request merged: the merge commit's second parent;
 *   the integrated subject     the commit on main's first-parent history that introduced the receipt: a merge commit
 *                              that carries the reviewed tree byte for byte.
 *
 * A descendant (main after the merge, a branch, a pull request's synthetic merge) is judged against the integrated
 * subject: its contracts and the receipt itself must be that commit's, byte for byte, in HEAD and in the working tree.
 * A protected change after the merge needs new evidence, which no lane has produced, so it fails closed.
 *
 * Main's history locates the merge, and the merge's second parent names the head it merged; comparing the trees shows
 * the merge carries exactly that head's bytes. git shows a merge, not an approval (the measured ruleset requires none),
 * so the binding attests topology and bytes, not review. Main is read only as refs/remotes/origin/main, and git reads
 * the objects themselves (no replace ref, no graft). Nothing is trusted for being on main: a descendant is judged by
 * its bytes.
 *
 * Merge changes provenance location, not the set of bytes that were reviewed. A historical receipt is never rewritten
 * merely because its reviewed subject moved into main.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { diskFiles, gitBlobId } from "./append-only-history";

export const IMPL_RECEIPT_INTEGRATION_REL = "evidence/zk/sp1-impl/receipt-integration.json";
export const RECEIPT_INTEGRATION_SCHEMA = "walletwall.sp1-impl-receipt-integration.v1";
/**
 * Main, by its full name: a tag, a branch or a file named origin/main would win the short name (git resolves those
 * first), and actions/checkout fetches tags.
 */
export const MAIN_REF = "refs/remotes/origin/main";
/**
 * What the receipt states against its base (the contract sources changed since it, the journal the wrapper decoded
 * there) reads these bytes, so after the merge they are the integrated subject's. Every other fact the receipt states
 * is absolute (hashes, the compiled wrapper's AST, the zkvm subject's trees, the probes' outcomes), and its byte for
 * byte re-derivation already judges it on every descendant. These are sources: the wrapper's compiled code is pinned
 * by its build record, and no other contract's compiled code was ever bound by the receipt.
 */
export const PROTECTED_SUBJECT_PATHS = ["contracts"] as const;

const NOTE =
  "The SP1 implementation receipt after its merge: its historical lane base, the head its pull request merged (the " +
  "reviewed subject) and the merge commit that brought those bytes into main (the integrated subject), derived from " +
  "git by scripts/lib/sp1-impl-receipt-integration.ts and checked by npm run validate:sp1-impl-receipt. It attests " +
  "the merge's topology and bytes, not who reviewed or merged it: the receipt's OWNER_REVIEW_AND_MERGE stays as " +
  "published. A descendant is judged against the integrated subject; the historical receipt is never rewritten.";
const NEEDS_EVIDENCE =
  "a protected change after the merge needs new evidence (a later lane's record that supersedes this receipt), and " +
  "none exists, so the receipt fails closed; the historical receipt is never regenerated";

export interface SubjectObject {
  path: string;
  /** git's object type: a tree for a directory, a blob for a file. */
  type: string;
  id: string;
}

export interface ReceiptIntegration {
  schema: string;
  note: string;
  historicalReceipt: {
    path: string;
    /** sha256 of the receipt's bytes as the merge carries them (the reviewed head's, byte for byte). */
    sha256: string;
    lane: string;
    /** Where the lane began: the receipt's baseCommit, which it states its change set against. Never moved. */
    historicalLaneBase: string;
    /** The lane commit that last wrote the receipt, as of the reviewed head. */
    writtenAt: string;
  };
  /** The head the pull request merged: the merge commit's second parent. */
  reviewedSubject: { commit: string; tree: string };
  integratedSubject: { commit: string; method: "MERGE_COMMIT"; parents: [string, string]; tree: string };
  /** What every descendant must carry, byte for byte: the integrated subject's protected paths and the receipt. */
  descendantDriftBaseline: { commit: string; subject: SubjectObject[] };
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const lines = (text: string) => text.split("\n").filter(Boolean);
const messageOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** A graft file that does not exist: GIT_GRAFT_FILE replaces info/grafts, so git reads no graft at all. */
const NO_GRAFTS = join(tmpdir(), `sp1-receipt-no-grafts-${randomUUID()}`);

/**
 * git, reading the objects themselves: a replace ref (`git replace`) or a graft (info/grafts, GIT_GRAFT_FILE) would show
 * other parents or trees under the same ids, so neither is consulted.
 */
export function gitObjects(repoRoot: string, args: readonly string[], input?: string): Buffer {
  return execFileSync("git", ["--no-replace-objects", "-C", resolve(repoRoot), ...args], {
    env: { ...process.env, GIT_GRAFT_FILE: NO_GRAFTS },
    input,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
  });
}
const git = (repoRoot: string, args: string[], input?: string) => gitObjects(repoRoot, args, input).toString("utf8");

/** Whether `ancestor` is `descendant` or one of its ancestors; an object git cannot read shows nothing, so no. */
function descends(repoRoot: string, ancestor: string, descendant: string): boolean {
  try {
    git(repoRoot, ["merge-base", "--is-ancestor", ancestor, descendant]);
    return true;
  } catch {
    return false;
  }
}

/**
 * The object each `rev:path` names, by one batch read: null where nothing is there. Any other answer is kept as git
 * gave it, so it can only fail to equal an object it is compared with.
 */
function objectsAt(repoRoot: string, specs: readonly string[]): (SubjectObject | null)[] {
  const answers = lines(
    git(repoRoot, ["cat-file", "--batch-check=%(objecttype) %(objectname)"], specs.map((s) => `${s}\n`).join("")),
  );
  return specs.map((spec, k) => {
    if (answers[k] === `${spec} missing`) return null;
    const [type, id] = String(answers[k]).split(" ");
    return { path: spec.slice(spec.indexOf(":") + 1), type, id: String(id) };
  });
}

/**
 * origin/main's first-parent history, newest first, read whole: a shallow clone or no origin/main is refused (and
 * where git cannot run at all, its own error stands).
 */
function firstParentMainline(repoRoot: string): string[] {
  if (git(repoRoot, ["rev-parse", "--is-shallow-repository"]).trim() !== "false") {
    throw new Error(
      "a shallow clone cannot show where the receipt entered main: the full history is needed (fetch-depth 0), and " +
        "the receipt is not judged",
    );
  }
  try {
    return lines(git(repoRoot, ["rev-list", "--first-parent", MAIN_REF]));
  } catch {
    throw new Error(
      "origin/main is not available, with its history: the integration cannot be derived, and the receipt is not judged",
    );
  }
}

/** The protected paths at `commit`, each present: a subject missing what it protects is no subject. */
function protectedAt(repoRoot: string, commit: string, paths: readonly string[]): SubjectObject[] {
  return objectsAt(
    repoRoot,
    paths.map((p) => `${commit}:${p}`),
  ).map((o, k) => {
    if (o === null) throw new Error(`${commit} carries no ${paths[k]}: it cannot be a subject`);
    return o;
  });
}

/**
 * The binding of the receipt at `receiptRel` to the merge that brought it into main, from git alone; throws (fail
 * closed) with the reason when there is none to derive.
 *
 * The receipt is bound to where it first entered origin/main's first-parent history: an append-only main never moves
 * that commit, and a receipt removed and restored later is judged by its bytes, as every descendant is. That commit must
 * be a two-parent merge whose tree is its second parent's: a squash, a rebase merge or a fast-forward names no reviewed
 * head, and a merge that carries any byte its head does not carries something nobody reviewed. The receipt's own base
 * must be a main commit the lane that wrote it began from, and main's protected paths must not have moved between that
 * base and the merge's first parent: the receipt states its change set against the base, which would otherwise hide
 * main's change.
 */
export function deriveReceiptIntegration(repoRoot: string, receiptRel: string): ReceiptIntegration {
  const mainline = firstParentMainline(repoRoot);
  const present = objectsAt(
    repoRoot,
    mainline.map((c) => `${c}:${receiptRel}`),
  );
  const entered = mainline.filter(
    (_, k) => present[k] !== null && (k + 1 === mainline.length || present[k + 1] === null),
  );
  if (entered.length === 0) {
    throw new Error(
      `${receiptRel} is on no commit of origin/main's first-parent history: the receipt is not integrated, and is not ` +
        "judged (fetch origin/main)",
    );
  }
  const merge = entered[entered.length - 1];
  const parents = git(repoRoot, ["rev-list", "--parents", "-n", "1", merge]).trim().split(" ").slice(1);
  if (parents.length !== 2) {
    throw new Error(
      parents.length === 1
        ? `${receiptRel} entered main at ${merge}, a single-parent commit (a squash, a rebase merge or a ` +
            "fast-forward): no parent names the head the pull request merged, and content alone would bind main's " +
            "bytes to a commit nothing names as reviewed; this receipt is integrated by a merge commit only"
        : `${receiptRel} entered main at ${merge}, a commit with ${parents.length} parents: only a two-parent merge ` +
            "commit names one reviewed head",
    );
  }
  const [firstParent, reviewed] = parents;
  const [mergeTree, reviewedTree] = [merge, reviewed].map((c) => git(repoRoot, ["rev-parse", `${c}^{tree}`]).trim());
  if (mergeTree !== reviewedTree) {
    throw new Error(
      `the merge ${merge} carries bytes its reviewed head ${reviewed} does not (tree ${mergeTree}, not ` +
        `${reviewedTree}): an up-to-date pull request's merge commit carries its head's tree, and nothing else was ` +
        "reviewed",
    );
  }
  const bytes = gitObjects(repoRoot, ["cat-file", "blob", String(present[mainline.indexOf(merge)]?.id)]);
  let receipt: { lane?: unknown; baseCommit?: unknown } | null;
  try {
    receipt = JSON.parse(bytes.toString("utf8")) as { lane?: unknown; baseCommit?: unknown } | null;
  } catch {
    throw new Error(`${receiptRel} as the merge carries it is not JSON`);
  }
  // A full commit id is all mainline holds, so this also refuses a base that is no full commit id.
  const base = String(receipt?.baseCommit);
  if (!mainline.includes(base)) {
    throw new Error(
      `the historical lane base ${base} is no commit of origin/main's first-parent history: only a published main ` +
        "commit is a lane base",
    );
  }
  const writtenAt = git(repoRoot, ["log", "-1", "--format=%H", reviewed, "--", receiptRel]).trim();
  if (!descends(repoRoot, base, writtenAt)) {
    throw new Error(`the receipt was written at ${writtenAt}, in a lane that did not begin at its base ${base}`);
  }
  const atBase = protectedAt(repoRoot, base, PROTECTED_SUBJECT_PATHS);
  const moved = protectedAt(repoRoot, firstParent, PROTECTED_SUBJECT_PATHS)
    .filter((o, k) => o.id !== atBase[k].id)
    .map((o) => o.path);
  if (moved.length > 0) {
    throw new Error(
      `main changed ${moved.join(", ")} between the lane's base ${base} and the merge's first parent ` +
        `${firstParent}: the receipt states its change set against that base, which would hide main's change (the ` +
        "re-review's A2)",
    );
  }
  return {
    schema: RECEIPT_INTEGRATION_SCHEMA,
    note: NOTE,
    historicalReceipt: {
      path: receiptRel,
      sha256: sha256(bytes),
      lane: String(receipt?.lane),
      historicalLaneBase: base,
      writtenAt,
    },
    reviewedSubject: { commit: reviewed, tree: reviewedTree },
    integratedSubject: { commit: merge, method: "MERGE_COMMIT", parents: [firstParent, reviewed], tree: mergeTree },
    descendantDriftBaseline: {
      commit: merge,
      subject: protectedAt(repoRoot, merge, [...PROTECTED_SUBJECT_PATHS, receiptRel]),
    },
  };
}

export function serializeReceiptIntegration(r: ReceiptIntegration): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}

/**
 * Why the committed record at `recordRel` is not the binding git derives, and the binding when it is. The record is
 * never typed: each field is derived again and compared, byte for byte.
 */
export function receiptIntegrationErrors(
  repoRoot: string,
  receiptRel: string,
  recordRel = IMPL_RECEIPT_INTEGRATION_REL,
): { errors: string[]; record: ReceiptIntegration | null } {
  let text: string;
  try {
    text = readFileSync(resolve(repoRoot, recordRel), "utf8");
  } catch (error) {
    return {
      errors: [
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? `${recordRel} is missing: after its merge the receipt is judged only against its integrated subject ` +
            "(npx tsx scripts/generate-sp1-impl-receipt.ts --integration writes it from git)"
          : `${recordRel} cannot be read: ${messageOf(error)}`,
      ],
      record: null,
    };
  }
  let derived: ReceiptIntegration;
  try {
    derived = deriveReceiptIntegration(repoRoot, receiptRel);
  } catch (error) {
    return { errors: [messageOf(error)], record: null };
  }
  if (text === serializeReceiptIntegration(derived)) return { errors: [], record: derived };
  let committed: Record<string, unknown> = {};
  try {
    committed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // not JSON: every field differs
  }
  const differing = Object.keys(derived).filter(
    (k) => JSON.stringify(committed?.[k]) !== JSON.stringify((derived as unknown as Record<string, unknown>)[k]),
  );
  return {
    errors: [
      `${recordRel} is not what git derives (${differing.join(", ") || "formatting"}): the binding is never typed, ` +
        "and never written to fit a changed receipt",
    ],
    record: null,
  };
}

/** Each file under the tree `s` that the working tree removed, changed or added, read from disk byte for byte. */
function treeDrift(repoRoot: string, s: SubjectObject): string[] {
  const expected = new Map<string, string>();
  for (const entry of git(repoRoot, ["ls-tree", "-r", "-z", s.id]).split("\0").filter(Boolean)) {
    const tab = entry.indexOf("\t");
    expected.set(entry.slice(tab + 1), entry.slice(0, tab).split(" ")[2]);
  }
  const onDisk = diskFiles(resolve(repoRoot, s.path));
  const drift: string[] = [];
  for (const [path, id] of expected) {
    if (!onDisk.has(path)) drift.push(`${s.path}/${path} (removed)`);
    else if (onDisk.get(path) !== id)
      drift.push(`${s.path}/${path} (${changeOf(readFileSync(resolve(repoRoot, s.path, path)), id)})`);
  }
  for (const path of onDisk.keys()) if (!expected.has(path)) drift.push(`${s.path}/${path} (added)`);
  return drift.sort();
}

/**
 * How bytes that are not the blob `id` differ from it: only in CRLF line endings (what a core.autocrlf=true checkout
 * writes; still drift, and named so), or otherwise.
 */
function changeOf(bytes: Buffer, id: string): string {
  const lf = Buffer.from(bytes.toString("latin1").replaceAll("\r\n", "\n"), "latin1");
  return gitBlobId(lf) === id ? "changed: line endings only; check out with core.autocrlf=false" : "changed";
}

/** Whether the file `s` is on disk as the blob it names; a file that cannot be read is drift, never a pass. */
function blobDrift(repoRoot: string, s: SubjectObject): string[] {
  let bytes: Buffer;
  try {
    bytes = readFileSync(resolve(repoRoot, s.path));
  } catch {
    return [`${s.path} (removed, or unreadable)`];
  }
  return gitBlobId(bytes) === s.id ? [] : [`${s.path} (${changeOf(bytes, s.id)})`];
}

/**
 * Why HEAD and the working tree are not a descendant of the integrated subject that carries its protected subject:
 * empty when HEAD descends from it and every protected path is its object, byte for byte, committed and on disk.
 */
export function descendantDriftErrors(
  repoRoot: string,
  baseline: ReceiptIntegration["descendantDriftBaseline"],
): string[] {
  if (!descends(repoRoot, baseline.commit, "HEAD")) {
    return [
      `HEAD does not descend from the integrated subject ${baseline.commit}: the receipt is judged only on its ` +
        "descendants",
    ];
  }
  const errors: string[] = [];
  const atHead = objectsAt(
    repoRoot,
    baseline.subject.map((s) => `HEAD:${s.path}`),
  );
  baseline.subject.forEach((s, k) => {
    const now = atHead[k];
    if (now?.id !== s.id) {
      errors.push(
        `HEAD changes ${s.path} since the integrated subject ${baseline.commit} (${now === null ? "absent" : `${now.type} ${now.id}`}, ` +
          `not ${s.type} ${s.id}): ${NEEDS_EVIDENCE}`,
      );
    }
  });
  for (const s of baseline.subject) {
    const drift = s.type === "tree" ? treeDrift(repoRoot, s) : blobDrift(repoRoot, s);
    if (drift.length > 0) {
      errors.push(
        `the working tree changes ${s.path} since the integrated subject ${baseline.commit}: ${drift.join(", ")}; ` +
          NEEDS_EVIDENCE,
      );
    }
  }
  return errors;
}
