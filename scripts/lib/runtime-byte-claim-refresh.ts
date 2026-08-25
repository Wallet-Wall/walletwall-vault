/**
 * Runtime-byte claim refresh — the deliberate-mutation half.
 *
 * A normal `npm run validate:runtime-byte-claims` is READ-ONLY. Refreshing is a
 * separate, explicit action (`--write`), mirroring how
 * scripts/reproducibility-evidence.ts already separates `check` from
 * `capture-build`. Evidence must never regenerate itself as a side effect of
 * being checked: a check that quietly rewrote the thing it was checking would
 * always pass and would prove nothing.
 *
 * Three rules keep the refresh honest, and each has its own test:
 *
 *   1. The only value it ever writes is the compiler's measurement. There is no
 *      way to pass a number in.
 *   2. It never touches an `observed-live` claim. Those record what a past
 *      deployment actually put on chain — WalletWallVault's live runtime is
 *      20,508 bytes while HEAD compiles to 22,701, and "fixing" the 20,508
 *      would be falsifying history, not refreshing evidence.
 *   3. It never edits an evidence bundle. A bundle's authority is the captured
 *      `deployedBytecodeObject` itself, so its length is not an independently
 *      editable field — changing it would forge solc output. A stale bundle is
 *      reported as unfixable, naming the real recapture command.
 *
 * Planning is pure (text in, edits out) so all of this is testable without
 * writing to disk; the CLI applies the plan.
 */
import type { ClaimSlot, RuntimeByteMeasurement } from "./runtime-byte-claims";
import { parseRuntimeByteTables, type ProseClaimSite } from "./runtime-byte-claim-sources";

export interface PlannedEdit {
  /** Repo-relative file. */
  file: string;
  /** 1-indexed line number. */
  line: number;
  before: string;
  after: string;
  description: string;
}

export interface RefreshPlan {
  edits: PlannedEdit[];
  /**
   * Disagreements a mechanical refresh must NOT resolve on its own, each with
   * the action a human has to take instead.
   */
  unfixable: string[];
}

export interface RefreshInput {
  /** Repo-relative path -> full file text. */
  files: Record<string, string>;
  sites: ProseClaimSite[];
  measurements: RuntimeByteMeasurement[];
}

const MANIFEST_FIELD_RE = /^(\s*"publicHeadRuntimeBytes"\s*:\s*)(\d+)(.*)$/;

/** Re-emit `value` using the same digit grouping the document already used. */
function formatLike(original: string, value: number): string {
  return original.includes(",") ? value.toLocaleString("en-US") : String(value);
}

function isEvidencePath(file: string): boolean {
  return file.replace(/\\/g, "/").includes("deployments/reproducibility/evidence/");
}

function isManifestPath(file: string): boolean {
  const p = file.replace(/\\/g, "/");
  return p.includes("deployments/reproducibility/") && !isEvidencePath(p) && p.endsWith(".json");
}

/**
 * Work out every edit needed to bring the tree's compiler-derived claims back
 * in line with the measurements, and everything that cannot honestly be fixed
 * that way.
 */
export function planRuntimeByteRefresh(input: RefreshInput): RefreshPlan {
  const edits: PlannedEdit[] = [];
  const unfixable: string[] = [];
  const measured = new Map(input.measurements.map((m) => [m.subject, m.runtimeBytes]));

  for (const [file, text] of Object.entries(input.files)) {
    const lines = text.split(/\r?\n/);

    if (isEvidencePath(file)) {
      let e: { subject?: string; publicHeadBuild?: { deployedBytecodeObject?: string } };
      try {
        e = JSON.parse(text);
      } catch {
        unfixable.push(`${file}: not valid JSON — cannot assess its public-HEAD build`);
        continue;
      }
      const object = e.publicHeadBuild?.deployedBytecodeObject;
      if (typeof e.subject !== "string" || typeof object !== "string") continue;
      const expected = measured.get(e.subject);
      if (expected === undefined) {
        unfixable.push(`${file}: subject "${e.subject}" has no compiler measurement bound to it`);
        continue;
      }
      const actual = (object.length - 2) / 2;
      if (actual !== expected) {
        unfixable.push(
          `${file}: publicHeadBuild holds ${actual} bytes of captured bytecode but the compiler now produces ` +
            `${expected} — a refresh cannot edit this, the bundle must be RECAPTURED:\n` +
            `      npx tsx scripts/reproducibility-evidence.ts capture-build --subject ${e.subject} ` +
            `--slot public-head --build-info artifacts/build-info/<hash>.output.json ... --out ${file}`,
        );
      }
      continue;
    }

    if (isManifestPath(file)) {
      const subject = /"subject"\s*:\s*"([^"]+)"/.exec(text)?.[1];
      if (!subject) {
        unfixable.push(`${file}: no subject — cannot attribute its runtime-byte claim`);
        continue;
      }
      const expected = measured.get(subject);
      if (expected === undefined) {
        unfixable.push(`${file}: subject "${subject}" has no compiler measurement bound to it`);
        continue;
      }
      lines.forEach((line, idx) => {
        const m = MANIFEST_FIELD_RE.exec(line);
        if (!m) return;
        if (Number(m[2]) === expected) return;
        edits.push({
          file,
          line: idx + 1,
          before: line,
          after: `${m[1]}${expected}${m[3]}`,
          description: `${subject} publicHeadRuntimeBytes ${m[2]} -> ${expected}`,
        });
      });
      // Fall through to the registered-site pass: a manifest states the size in
      // its narrative fields too, and refreshing only the machine-readable field
      // is precisely the partial fix that let the prose copies rot.
      edits.push(...planSiteEdits(file, lines, input.sites, measured, unfixable));
      continue;
    }

    // ── Markdown: structurally-parsed tables, then registered prose sites ────
    const tables = parseRuntimeByteTables(text, file);
    for (const d of tables.declarations) {
      if (d.slot !== "public-head") continue;
      const expected = measured.get(d.subject);
      if (expected === undefined) {
        unfixable.push(`${file}: table row for "${d.subject}" has no compiler measurement bound to it`);
        continue;
      }
      if (d.value === expected) continue;
      const lineNo = Number(d.location.split(":").pop());
      const before = lines[lineNo - 1];
      const after = before.replace(/`(\d[\d,]*)`/, (_full, digits: string) => `\`${formatLike(digits, expected)}\``);
      edits.push({
        file,
        line: lineNo,
        before,
        after,
        description: `${d.subject} table cell ${d.value} -> ${expected}`,
      });
    }

    edits.push(...planSiteEdits(file, lines, input.sites, measured, unfixable));
  }

  return { edits, unfixable };
}

/**
 * Rewrite every registered `public-head` prose site in one file. Shared by the
 * markdown and manifest paths so a narrative copy is refreshed wherever it
 * lives; `observed-live` sites are skipped, since the compiler cannot overrule
 * what a past deployment put on chain.
 */
function planSiteEdits(
  file: string,
  lines: string[],
  sites: ProseClaimSite[],
  measured: Map<string, number>,
  unfixable: string[],
): PlannedEdit[] {
  const edits: PlannedEdit[] = [];
  for (const site of sites) {
    if (site.file !== file) continue;
    if (site.slot !== "public-head") continue;
    const expected = measured.get(site.subject);
    if (expected === undefined) {
      unfixable.push(`${file}: registered site for "${site.subject}" has no compiler measurement bound to it`);
      continue;
    }
    lines.forEach((line, idx) => {
      const m = site.pattern.exec(line);
      if (!m) return;
      const current = Number(m[1].replace(/,/g, ""));
      if (current === expected) return;
      const replacement = formatLike(m[1], expected);
      // Replace the matched occurrence in place rather than the first number on
      // the line: JSON prose can state two sizes in one string, and rewriting
      // the wrong one would corrupt an observed-live fact.
      const after = line.slice(0, m.index) + m[0].replace(m[1], replacement) + line.slice(m.index + m[0].length);
      edits.push({
        file,
        line: idx + 1,
        before: line,
        after,
        description: `${site.subject} (${site.note}) ${m[1]} -> ${replacement}`,
      });
    });
  }
  return edits;
}

/** Apply a plan to file text held in memory. Returns the changed files only. */
export function applyRuntimeByteRefresh(files: Record<string, string>, edits: PlannedEdit[]): Record<string, string> {
  const byFile = new Map<string, PlannedEdit[]>();
  for (const e of edits) {
    const list = byFile.get(e.file);
    if (list) list.push(e);
    else byFile.set(e.file, [e]);
  }

  const out: Record<string, string> = {};
  for (const [file, fileEdits] of byFile) {
    const eol = files[file].includes("\r\n") ? "\r\n" : "\n";
    const lines = files[file].split(/\r?\n/);
    for (const e of fileEdits) {
      if (lines[e.line - 1] !== e.before) {
        throw new Error(`${file}:${e.line}: content changed since the plan was made — refusing to write`);
      }
      lines[e.line - 1] = e.after;
    }
    out[file] = lines.join(eol);
  }
  return out;
}

/** Slots a mechanical refresh is allowed to touch. Exported so the CLI can say so. */
export const REFRESHABLE_SLOTS: ClaimSlot[] = ["public-head"];
