/**
 * Append-only proof from git history (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * A published record — the wrapper registry, the designations, their evidence bundles, the wrapper builds — may only
 * grow. "The JSON on disk looks right" proves nothing about that: a deleted fact, a rewritten field or a renumbered
 * list can all look right. What proves it is the history: every version that ever reached the published line must
 * extend the version before it.
 *
 * The check walks EVERY parent edge of EVERY commit reachable from HEAD (not `git log -- <path>`, whose history
 * simplification drops a merge that is identical to one parent and different from the other — exactly the shape of
 * a conflict resolved by dropping a fact), compares the record at the commit with the record at each parent, and
 * hands each changed pair to the record's own rule. The working tree is checked against HEAD the same way, so an
 * uncommitted rewrite fails too. A shallow clone cannot show the history, so it fails closed rather than pass.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

/** Given the older and newer content of a record (null: absent), every way the newer one fails to extend it. */
export type ExtensionRule = (older: string | null, newer: string | null) => string[];

const MAX_BUFFER = 512 * 1024 * 1024;

function git(repoRoot: string, args: string[], input?: string): string {
  return execFileSync("git", args, {
    cwd: resolve(repoRoot),
    encoding: "utf8",
    input,
    maxBuffer: MAX_BUFFER,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

/** Refuses to judge a history it cannot see. */
function historyUnavailable(repoRoot: string): string[] {
  let shallow: string;
  try {
    shallow = git(repoRoot, ["rev-parse", "--is-shallow-repository"]).trim();
  } catch {
    return ["the append-only check needs a git repository with its full history"];
  }
  return shallow === "true"
    ? ["the append-only check needs the full history: this clone is shallow (fetch with fetch-depth 0)"]
    : [];
}

/** Every commit reachable from HEAD with its parents. */
function commitsWithParents(repoRoot: string): { commit: string; parents: string[] }[] {
  return git(repoRoot, ["rev-list", "--parents", "HEAD"])
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [commit, ...parents] = line.trim().split(" ");
      return { commit, parents };
    });
}

/** The object id of `<commit>:<rel>` for each commit (null when the path is absent there), in one git call. */
function objectIds(repoRoot: string, commits: string[], rel: string): Map<string, string | null> {
  const unique = [...new Set(commits)];
  const out = git(
    repoRoot,
    ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
    unique.map((c) => `${c}:${rel}\n`).join(""),
  )
    .split("\n")
    .filter(Boolean);
  if (out.length !== unique.length) throw new Error(`git cat-file answered ${out.length} of ${unique.length} lookups`);
  const ids = new Map<string, string | null>();
  unique.forEach((c, i) => ids.set(c, out[i].endsWith(" missing") ? null : out[i].split(" ")[0]));
  return ids;
}

/**
 * Every parent edge where the object at `rel` differs: [commit, parent (null for a root), newer id, older id]. A commit
 * is compared with the parents that hold the record; where none does (a root, or a commit whose parents all predate
 * the record) it is an introduction, compared with nothing (older id null). A merge of a branch that predates the
 * record is therefore no introduction: it inherits the record from the parent that holds it.
 */
function changedEdges(repoRoot: string, rel: string): [string, string | null, string | null, string | null][] {
  const commits = commitsWithParents(repoRoot);
  const ids = objectIds(
    repoRoot,
    commits.flatMap((c) => [c.commit, ...c.parents]),
    rel,
  );
  const edges: [string, string | null, string | null, string | null][] = [];
  for (const { commit, parents } of commits) {
    const newer = ids.get(commit) ?? null;
    const holding = parents.filter((p) => (ids.get(p) ?? null) !== null);
    if (holding.length === 0) {
      if (newer !== null) edges.push([commit, parents[0] ?? null, newer, null]);
      continue;
    }
    for (const parent of holding) {
      const older = ids.get(parent) ?? null;
      if (older !== newer) edges.push([commit, parent, newer, older]);
    }
  }
  return edges;
}

const blob = (repoRoot: string, id: string | null) => (id === null ? null : git(repoRoot, ["cat-file", "blob", id]));
const at = (commit: string, parent: string | null) =>
  `commit ${commit.slice(0, 12)} (against ${parent === null ? "no parent" : `parent ${parent.slice(0, 12)}`})`;

/** Every way the history of the file `rel` is not an extension under `rule`; empty when it is append-only. */
export function fileHistoryErrors(repoRoot: string, rel: string, rule: ExtensionRule): string[] {
  const unavailable = historyUnavailable(repoRoot);
  if (unavailable.length > 0) return unavailable;
  const errors: string[] = [];
  for (const [commit, parent, newer, older] of changedEdges(repoRoot, rel)) {
    for (const e of rule(blob(repoRoot, older), blob(repoRoot, newer)))
      errors.push(`${rel} at ${at(commit, parent)}: ${e}`);
  }
  const path = resolve(repoRoot, rel);
  const head = blob(repoRoot, objectIds(repoRoot, ["HEAD"], rel).get("HEAD") ?? null);
  const disk = readIfPresent(path);
  if (head !== disk) for (const e of rule(head, disk)) errors.push(`${rel} in the working tree (against HEAD): ${e}`);
  return errors;
}

/** path → git blob id of every file under a tree object. */
function treeFiles(repoRoot: string, treeId: string | null): Map<string, string> {
  const files = new Map<string, string>();
  if (treeId === null) return files;
  for (const line of git(repoRoot, ["ls-tree", "-r", treeId]).split("\n").filter(Boolean)) {
    const [meta, path] = line.split("\t");
    files.set(path, meta.split(" ")[2]);
  }
  return files;
}

/** git's blob id of a file's bytes, so the working tree compares with the history exactly. */
export function gitBlobId(bytes: Buffer): string {
  return createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes]))
    .digest("hex");
}

/** A file's text, or null when nothing is there: one read, so no earlier check can go stale before it. */
function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

/**
 * The git blob id of every regular file under `root`, read entry by entry: the type is the directory entry's own, so
 * there is no separate check to go stale, and a link is never followed. Anything that is neither a regular file nor a
 * directory (a link above all) never matches a published record.
 */
export function diskFiles(root: string, prefix = ""): Map<string, string> {
  const files = new Map<string, string>();
  let entries: Dirent[];
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return files;
    throw error;
  }
  for (const entry of entries) {
    const full = join(root, entry.name);
    const rel = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) for (const [p, id] of diskFiles(full, rel)) files.set(p, id);
    else if (entry.isFile()) files.set(rel, gitBlobId(readFileSync(full)));
    else files.set(rel, "not a regular file");
  }
  return files;
}

function removedOrChanged(older: Map<string, string>, newer: Map<string, string>): string[] {
  const errors: string[] = [];
  for (const [path, id] of older) {
    if (!newer.has(path)) errors.push(`${path} was removed or renamed; a published record is never withdrawn`);
    else if (newer.get(path) !== id) errors.push(`${path} was changed; a published record is never edited`);
  }
  return errors;
}

/**
 * Every way the history of the directory `dirRel` removed or changed a file it had published; empty: it only grew.
 * With `include`, only the files whose paths (relative to the directory) it admits are held to that: a directory
 * shared with records of other kinds (SP1-PA3D0's proof-exercise observations beside re-measured observations).
 */
export function directoryHistoryErrors(
  repoRoot: string,
  dirRel: string,
  include: (path: string) => boolean = () => true,
): string[] {
  const unavailable = historyUnavailable(repoRoot);
  if (unavailable.length > 0) return unavailable;
  const only = (files: Map<string, string>) => new Map([...files].filter(([path]) => include(path)));
  const errors: string[] = [];
  for (const [commit, parent, newer, older] of changedEdges(repoRoot, dirRel)) {
    for (const e of removedOrChanged(only(treeFiles(repoRoot, older)), only(treeFiles(repoRoot, newer)))) {
      errors.push(`${dirRel} at ${at(commit, parent)}: ${e}`);
    }
  }
  const head = only(treeFiles(repoRoot, objectIds(repoRoot, ["HEAD"], dirRel).get("HEAD") ?? null));
  for (const e of removedOrChanged(head, only(diskFiles(resolve(repoRoot, dirRel))))) {
    errors.push(`${dirRel} in the working tree (against HEAD): ${e}`);
  }
  return errors;
}
