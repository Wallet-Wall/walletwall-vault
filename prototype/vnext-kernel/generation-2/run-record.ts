/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * WHAT THE HEAVY SUITES ACTUALLY DID, AS A COMMITTED RECORD. They take about nine minutes and live outside the
 * prototype's test path, so the verdict needs something to read that says how they came out. A campaign's decisions
 * are a function of (profile, seed, depth, label), so the record is exact: each heavy suite compares itself against
 * it and fails on any difference, and `deriveAdmissionVerdict` refuses to admit on a record that shows a violation or
 * a survivor. This does not prove a run happened, and nothing committed could: it makes a hand-edit fail the next
 * real run, and that run is by hand until a CI job exists for these suites.
 *
 * To re-record after a deliberate change to the harness or the candidate, run each suite once with
 * G2_WRITE_RUN_RECORD=1 and review the diff.
 */
import fs from "node:fs";

import { GEN2_ROOT } from "./compile.js";

export const RUN_RECORD_PATH = `${GEN2_ROOT}/GEN2_RUN_RECORD.json`;

export interface CampaignRunRecord {
  campaigns: number;
  transitions: number;
  successful: number;
  violations: number;
  positiveControls: string;
  outcomes: Record<string, number>;
  actions: Record<string, number>;
  reverts: Record<string, number>;
  seams: Record<string, number>;
  lifecycle: Record<string, number>;
  knownDefectHits: Record<string, number>;
}

export interface MutationRunRow {
  id: string;
  verdict: "KILLED" | "SURVIVED" | "INCONCLUSIVE";
  property: string | null;
  profile: string | null;
  seed: number | null;
  step: number | null;
  campaigns: number;
}

export interface RunRecord {
  _note: string;
  campaign: CampaignRunRecord | null;
  generation2Catalogue: MutationRunRow[] | null;
  generation1Catalogue: MutationRunRow[] | null;
}

const NOTE =
  "What the two heavy suites did on the candidate, exact, because a campaign is deterministic. Each suite fails on any difference from this record. Written with G2_WRITE_RUN_RECORD=1.";

const canonical = <T>(value: T): T =>
  JSON.parse(
    JSON.stringify(value, (_k, v) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)))
        : v,
    ),
  ) as T;

export function readRunRecord(): RunRecord {
  try {
    return JSON.parse(fs.readFileSync(RUN_RECORD_PATH, "utf8")) as RunRecord;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT")
      return { _note: NOTE, campaign: null, generation2Catalogue: null, generation1Catalogue: null };
    throw e;
  }
}

export const writingRunRecord = (): boolean => process.env.G2_WRITE_RUN_RECORD === "1";

export function writeRunSection(
  part: Partial<Pick<RunRecord, "campaign" | "generation2Catalogue" | "generation1Catalogue">>,
): void {
  const merged = { ...readRunRecord(), _note: NOTE, ...canonical(part) };
  fs.writeFileSync(RUN_RECORD_PATH, JSON.stringify(merged, null, 2) + "\n");
}

export { canonical as canonicalRunValue };

/** Why this record cannot support admission. Empty means the suites ran and came out clean. */
export function executionProblems(r: RunRecord): string[] {
  const problems: string[] = [];
  if (r.campaign === null) problems.push("the campaign has no record");
  else {
    if (r.campaign.violations !== 0) problems.push(`the campaign recorded ${r.campaign.violations} violation(s)`);
    const [passed, attempted] = r.campaign.positiveControls.split("/");
    if (passed !== attempted || Number(attempted) === 0)
      problems.push(`positive controls ${r.campaign.positiveControls}`);
  }
  for (const [name, rows] of [
    ["Generation-2", r.generation2Catalogue],
    ["Generation-1", r.generation1Catalogue],
  ] as const) {
    if (rows === null) problems.push(`the ${name} catalogue has no record`);
    else for (const row of rows.filter((x) => x.verdict !== "KILLED")) problems.push(`${row.id}: ${row.verdict}`);
  }
  return problems;
}
