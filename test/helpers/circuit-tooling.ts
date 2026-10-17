/**
 * Shared helpers for the SP1-PA2A circuit-tooling suites: temporary directories that are removed even when a test
 * leaves a read-only installation behind, and the refusal a call meets.
 */
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CircuitToolingError } from "../../scripts/lib/sp1-circuit-archive";
import { makeWritable } from "../../scripts/lib/sp1-circuit-tooling";

export function tempDirs() {
  const made: string[] = [];
  return {
    make(prefix = "sp1-pa2a-"): string {
      const d = mkdtempSync(join(tmpdir(), prefix));
      made.push(d);
      return d;
    },
    cleanup(): void {
      for (const d of made.splice(0)) {
        makeWritable(d);
        rmSync(d, { recursive: true, force: true });
      }
    },
  };
}

/** "CODE (REASON)" of the refusal `f` meets, "NOT_REFUSED", or the unexpected error's message. */
export async function refusalOf(f: () => unknown): Promise<string> {
  try {
    await f();
    return "NOT_REFUSED";
  } catch (error) {
    if (error instanceof CircuitToolingError) return `${error.code} (${error.reason})`;
    return `UNEXPECTED: ${(error as Error)?.message ?? String(error)}`;
  }
}

/** Creates a symlink, or skips the test where the platform will not (Windows without the privilege). */
export function symlinkOrSkip(ctx: Mocha.Context, target: string, path: string, type?: "dir" | "file"): void {
  try {
    symlinkSync(target, path, type);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOSYS"].includes(String((error as NodeJS.ErrnoException).code))) ctx.skip();
    throw error;
  }
}
