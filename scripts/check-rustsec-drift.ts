/**
 * Compares a fresh RustSec measurement (scripts/measure-sp1-host-advisories.ts, run by the networked, reporting-only
 * workflow .github/workflows/rustsec-audit.yml) with the committed advisory record; see scripts/lib/sp1-host-advisories.ts.
 *
 *   npx tsx scripts/check-rustsec-drift.ts --live <observation.json>
 *
 * Exit codes keep the outcomes apart:
 *   0  MATCH                    every live finding is a recorded one, with the same advisory, graph and fix facts
 *   1  SECURITY_DRIFT           a new advisory, a changed one (kind, severity, ranges), another crate version or
 *                               lockfile, or a changed graph, feature, source or fix fact: reassess
 *   2  RECORD_CLEANUP_REQUIRED  only disappearances: RustSec no longer reports a recorded finding; remove it
 *   3  AUDIT_UNAVAILABLE        no usable live measurement (the advisory database, the index or a tool failed):
 *                               unmeasured, which is never read as clean
 *
 * It reads the checkout's lockfiles to hold the live findings to them, and appends a summary to $GITHUB_STEP_SUMMARY
 * when that is set. No network. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DRIFT_EXIT,
  HOST_ADVISORIES_REL,
  LOCKFILES,
  lockPathOf,
  rustsecDrift,
  type DriftReport,
  type HostAdvisoryRecord,
  type LockfileId,
} from "./lib/sp1-host-advisories";

function readText(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function report(r: DriftReport, live: string): string {
  const head = `RustSec drift: ${r.verdict} (exit ${DRIFT_EXIT[r.verdict]}); advisory-db ${r.database ?? "none"}; ${r.known} recorded finding(s) matched`;
  const rows = r.items.map((i) => `- ${i.type} ${i.lockfile ?? ""} ${i.key ?? ""}: ${i.detail}`.replace(/ {2,}/g, " "));
  return [head, `live observation: ${live}`, ...(rows.length > 0 ? rows : ["- no drift"])].join("\n");
}

function main(): number {
  const i = process.argv.indexOf("--live");
  const livePath = i === -1 ? null : process.argv[i + 1];
  if (!livePath) throw new Error("--live <observation.json> is required");
  const record = JSON.parse(readFileSync(resolve(HOST_ADVISORIES_REL), "utf8")) as HostAdvisoryRecord;
  const liveText = readText(resolve(livePath));
  let live: unknown = null;
  try {
    live = liveText === null ? null : JSON.parse(liveText);
  } catch {
    live = null;
  }
  const locks = Object.fromEntries(LOCKFILES.map((l) => [l.id, readText(resolve(lockPathOf(l)))])) as Record<
    LockfileId,
    string | null
  >;
  const r = rustsecDrift(record, live, locks);
  const text = report(r, livePath);
  console.log(text);
  for (const item of r.items) {
    const level = item.type === "DISAPPEARED" ? "warning" : "error";
    console.log(
      `::${level} title=RustSec ${item.type}::${item.lockfile ?? ""} ${item.key ?? ""} ${item.detail}`.trim(),
    );
  }
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) appendFileSync(summary, `### RustSec advisory drift\n\n\`\`\`\n${text}\n\`\`\`\n`);
  return DRIFT_EXIT[r.verdict];
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = DRIFT_EXIT.AUDIT_UNAVAILABLE;
}
