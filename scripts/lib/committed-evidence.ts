/**
 * Committed evidence: a record counts only as git commits it (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md).
 *
 * An uncommitted designation, availability record, archive record or acquisition observation is nobody's reviewed
 * claim, so every consumer that admits production evidence first asks git whether the paths are exactly what HEAD
 * commits. Shared by scripts/lib/sp1-circuit-tooling.ts and scripts/lib/sp1-circuit-acquisition.ts.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { spawnSync } from "node:child_process";

/**
 * Why `paths` (repository-relative) are not exactly what HEAD commits, or null: not a git checkout, a path git does
 * not track, or a path whose working-tree content differs from the index and HEAD (a modified, deleted or untracked
 * file under a directory path included).
 */
export function uncommittedEvidenceError(paths: readonly string[], repoRoot: string): string | null {
  const git = (...args: string[]) =>
    spawnSync("git", ["-C", repoRoot, "--no-optional-locks", ...args], { encoding: "utf8", shell: false });
  if (git("rev-parse", "--is-inside-work-tree").stdout.trim() !== "true") return "NOT_A_GIT_CHECKOUT";
  for (const p of paths) {
    if (git("ls-files", "--error-unmatch", "--", p).status !== 0) return `UNTRACKED ${p}`;
  }
  const status = git("status", "--porcelain", "--untracked-files=all", "--", ...paths);
  if (status.status !== 0) return "GIT_STATUS_FAILED";
  const first = status.stdout.split("\n").find((l) => l.trim() !== "");
  return first === undefined ? null : `UNCOMMITTED ${first.trim()}`;
}
