/**
 * Write-once creation of published records (designations, their evidence bundles, wrapper build records).
 *
 * A record is created once and never rewritten. Checking that it is absent and then writing it leaves a window in
 * which a file that appears is overwritten; here each file is opened with O_CREAT|O_EXCL ("wx"), so the refusal and
 * the creation are one operation. A set is all-or-nothing: on any failure the files this call created are removed
 * again, and a file that already exists is refused by name and left untouched.
 */
import { closeSync, openSync, rmSync, writeFileSync } from "node:fs";

/** Creates every `[path, data]` file, none of which may exist yet; `what` says why an existing one is refused. */
export function writeNewFiles(files: readonly (readonly [path: string, data: string])[], what: string): void {
  const created: string[] = [];
  try {
    for (const [path, data] of files) {
      const fd = openSync(path, "wx");
      created.push(path);
      try {
        writeFileSync(fd, data);
      } finally {
        closeSync(fd);
      }
    }
  } catch (error) {
    for (const path of created) rmSync(path, { force: true });
    const e = error as NodeJS.ErrnoException;
    if (e?.code === "EEXIST") throw new Error(`${e.path ?? "a file"} exists: ${what}`);
    throw error;
  }
}
