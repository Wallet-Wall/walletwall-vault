/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * GITHUB CODE-SCANNING PROJECTION OF THE vNext SLITHER RUN. PRESENTATION, NEVER AUTHORITY.
 *
 * THE TWO-ARTIFACT MODEL. One pinned Slither execution writes two outputs, and they now go to two
 * different places for two different purposes:
 *
 *   Slither execution
 *     |
 *     +--> raw JSON  (prototype/vnext-kernel/slither-raw.json) --> triage + receipt gates (AUTHORITY)
 *     |
 *     +--> raw SARIF (slither-vnext-kernel-results.sarif) -------> workflow artifact, unmodified
 *                  |
 *                  +--> THIS projection (…results.github.sarif) --> upload-sarif (PRESENTATION)
 *
 * Nothing here feeds the evidence chain. `generate-scanner-evidence.ts` reads the raw JSON and has
 * no SARIF input at all, so no projection -- correct, wrong or absent -- can make its triage gate
 * pass. The Slither invocation, the raw JSON, the receipt and the triage are untouched by this file.
 *
 * WHY A PROJECTION EXISTS. crytic-compile 0.4.2's plain `solc` platform (forced for this prototype,
 * see the workflow) compiles every top-level .sol as its own unit, so a file reached by k entry
 * points is reported k times; and its `is_dependency()` is hard-coded `return False`, so
 * `--exclude-dependencies` cannot remove OpenZeppelin. GitHub turns each SARIF result into its own
 * alert and does NOT collapse byte-identical results. Measured on 17d55934: 295 raw results became
 * 295 open alerts, of which 222 are dependency-only and 165 are exact compilation-unit copies.
 *
 * EXACTLY TWO TRANSFORMATIONS, and every other byte of the SARIF is carried unchanged (asserted):
 *
 *   A. DROP DEPENDENCY-ONLY RESULTS. Ownership is decided from the RAW JSON, never from the SARIF
 *      location: SARIF carries only each result's PRIMARY location, so a SARIF-only rule could not
 *      see a finding's other elements. A finding is classified by EVERY element's
 *      `filename_relative` (path segment `node_modules` = dependency; the substring test
 *      `isOwnFinding` uses must agree on every path, or the run fails):
 *        OWN                       every element project-owned  -> PROJECTED (== isOwnFinding)
 *        DEPENDENCY_ONLY           every element in node_modules -> dropped
 *        MIXED_PROJECT_PRIMARY     project primary, a dependency element elsewhere -> FAIL. It
 *                                  involves project code so it must not disappear, and the governed
 *                                  triage scope (isOwnFinding) excludes it, so it could never be
 *                                  adjudicated either. A human must decide; the tool will not.
 *        MIXED_DEPENDENCY_PRIMARY  dependency primary (the report is ABOUT node_modules) with project
 *                                  elements -> dropped ONLY for the compilation-unit version lints
 *                                  (`pragma`, `solc-version`) and ONLY when every project element is
 *                                  a `pragma` directive; any other shape FAILS. Each exclusion is
 *                                  listed by name in the report, and the raw SARIF keeps it.
 *   B. COLLAPSE EXACT COPIES. Own findings are grouped by `semanticId`, the SAME identity the
 *      triage is keyed by (scanner-finding-identity.ts, reused, not re-derived). A group collapses
 *      to one result only when every member's raw JSON finding AND SARIF result are byte-identical.
 *      `semanticId` alone is NOT sufficient: it is line-free by design, and on 17d55934 six distinct
 *      `divide-before-multiply` findings in OpenZeppelin `Math.mulDiv` (the same Newton-step
 *      statement at six lines) share one id. The same shape in project code FAILS rather than
 *      merging two findings into one alert -- there is no "keep the first and hope".
 *
 * RAW -> SARIF MAPPING. Slither writes SARIF result i from JSON finding i (measured: the raw SARIF
 * is byte-identical to one rebuilt from the JSON, see the baseline fixture test). The mapping is
 * nevertheless not index-based: each side is reduced to the signature
 * [check, id, description, markdown, primary uri, first line, last line] and the two MULTISETS must
 * be equal, so a SARIF result with no raw finding, or a raw finding the SARIF does not represent,
 * fails. A signature whose raw findings disagree on anything is AMBIGUOUS and fails.
 *
 * FAIL-CLOSED CONTRACT. No output file is written on any failure, and the workflow uploads only
 * after this step succeeds: malformed raw JSON or SARIF; an unrecognised SARIF shape (exact key
 * sets, measured from the pinned Slither); an unmapped or unrepresented result; an ambiguous
 * mapping; a project finding that references a dependency; project code inside a dependency
 * finding; two distinct project findings that would collapse; a projected set that differs from
 * the isOwnFinding set; an empty projection; and a projected set that is not a BIJECTION with the
 * triage identities in slither-triage.json.
 *
 *   npx tsx prototype/vnext-kernel/scanner-sarif-projection.ts \
 *     --raw-sarif slither-vnext-kernel-results.sarif \
 *     --raw-scan prototype/vnext-kernel/slither-raw.json \
 *     --triage prototype/vnext-kernel/slither-triage.json \
 *     --out slither-vnext-kernel-results.github.sarif \
 *     --report slither-vnext-kernel-projection-report.json
 */
import { createHash } from "node:crypto";
import fs from "node:fs";

import { canonicalLocator, isOwnFinding, semanticId, type SlitherFinding } from "./scanner-finding-identity.js";

export const WORKFLOW_PATH = ".github/workflows/vnext-kernel-assurance.yml";
export const RAW_SARIF_PATH = "slither-vnext-kernel-results.sarif";
export const PROJECTED_SARIF_PATH = "slither-vnext-kernel-results.github.sarif";
export const RAW_SCAN_PATH = "prototype/vnext-kernel/slither-raw.json";
export const TRIAGE_PATH = "prototype/vnext-kernel/slither-triage.json";
export const PROJECTION_REPORT_PATH = "slither-vnext-kernel-projection-report.json";
export const SARIF_CATEGORY = "slither-vnext-kernel";
export const REPORT_SCHEMA = "vnext-kernel-sarif-projection-report.v1";

export const DEPENDENCY_SEGMENT = "node_modules";
/** The only detectors whose dependency-primary findings may carry project elements and be dropped. */
export const VERSION_LINT_DETECTORS: readonly string[] = Object.freeze(["pragma", "solc-version"]);

export type FailureCode =
  | "MALFORMED_RAW_SCAN"
  | "MALFORMED_SARIF"
  | "UNRECOGNIZED_SARIF_SHAPE"
  | "UNREPRESENTABLE_FINDING"
  | "UNMAPPED_SARIF_RESULT"
  | "AMBIGUOUS_MAPPING"
  | "DEPENDENCY_PREDICATE_DISAGREEMENT"
  | "PROJECT_FINDING_REFERENCES_DEPENDENCY"
  | "PROJECT_CODE_IN_DEPENDENCY_FINDING"
  | "DISTINCT_FINDINGS_WOULD_COLLAPSE"
  | "TRIAGE_SCOPE_DISAGREEMENT"
  | "EMPTY_PROJECTION"
  | "PROJECTION_NOT_A_SUBSET"
  | "MALFORMED_TRIAGE"
  | "TRIAGE_BIJECTION_FAILED"
  | "PRE_EXISTING_OUTPUT"
  | "WORKFLOW_CONTRACT";

export class ProjectionError extends Error {
  readonly code: FailureCode;
  constructor(code: FailureCode, message: string) {
    super(`[${code}] ${message}`);
    this.name = "ProjectionError";
    this.code = code;
  }
}

const fail = (code: FailureCode, message: string): never => {
  throw new ProjectionError(code, message);
};

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

// ---------------------------------------------------------------------------------------------
// Raw JSON (the authority for ownership and identity)
// ---------------------------------------------------------------------------------------------

export interface RawFinding extends SlitherFinding {
  id: string;
  markdown: string;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** A repo-relative POSIX path, or the run fails: an absolute or `..` path cannot be classified. */
function assertRepoRelative(p: string, where: string): void {
  const segs = p.split("/");
  if (
    p.length === 0 ||
    p.startsWith("/") ||
    p.includes("\\") ||
    /^[A-Za-z]:/.test(p) ||
    segs.some((s) => s === "" || s === "." || s === "..")
  ) {
    fail("MALFORMED_RAW_SCAN", `${where}: filename_relative "${p}" is not a repo-relative POSIX path`);
  }
}

/** Parses Slither's `--json` output. Extra fields are Slither's business; missing ones fail. */
export function parseRawScan(text: string): RawFinding[] {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return fail("MALFORMED_RAW_SCAN", `not JSON: ${(e as Error).message}`);
  }
  if (!isPlainObject(raw)) return fail("MALFORMED_RAW_SCAN", "top level is not an object");
  if (raw.success !== true || raw.error !== null) {
    return fail(
      "MALFORMED_RAW_SCAN",
      `Slither reported success=${String(raw.success)} error=${JSON.stringify(raw.error)}`,
    );
  }
  const detectors = isPlainObject(raw.results) ? raw.results.detectors : undefined;
  if (!Array.isArray(detectors)) return fail("MALFORMED_RAW_SCAN", "results.detectors is not an array");
  return detectors.map((f, i) => {
    const where = `raw finding #${i}`;
    if (!isPlainObject(f)) return fail("MALFORMED_RAW_SCAN", `${where} is not an object`);
    for (const k of ["check", "impact", "confidence", "description", "markdown", "id"]) {
      if (typeof f[k] !== "string" || (f[k] as string).length === 0) {
        fail("MALFORMED_RAW_SCAN", `${where}: "${k}" is missing or not a non-empty string`);
      }
    }
    const elements: unknown = f.elements;
    if (!Array.isArray(elements)) return fail("MALFORMED_RAW_SCAN", `${where}: elements is not an array`);
    // Slither's SARIF writer SKIPS a finding without elements ("Cannot generate Github security
    // alert for finding without location"), and isOwnFinding is vacuously TRUE for it -- so it
    // would be an own-code finding with no possible SARIF representation.
    if (elements.length === 0) {
      fail("UNREPRESENTABLE_FINDING", `${where} (${String(f.check)}) has no elements, so it has no SARIF location`);
    }
    elements.forEach((e: unknown, j: number) => {
      const w = `${where} element #${j}`;
      if (!isPlainObject(e) || typeof e.type !== "string") return fail("MALFORMED_RAW_SCAN", `${w} has no type`);
      const sm = e.source_mapping;
      if (!isPlainObject(sm) || typeof sm.filename_relative !== "string") {
        return fail("MALFORMED_RAW_SCAN", `${w} has no source_mapping.filename_relative`);
      }
      assertRepoRelative(sm.filename_relative, w);
      const lines = sm.lines;
      if (!Array.isArray(lines) || lines.length === 0 || !lines.every((n) => Number.isInteger(n) && n > 0)) {
        fail("MALFORMED_RAW_SCAN", `${w} source_mapping.lines is not a non-empty array of positive integers`);
      }
    });
    return f as unknown as RawFinding;
  });
}

// ---------------------------------------------------------------------------------------------
// Raw SARIF (strict: the exact shape the pinned Slither writes; anything else fails closed)
// ---------------------------------------------------------------------------------------------

export interface SarifResult {
  ruleId: string;
  message: { text: string; markdown: string };
  level: string;
  locations: Array<{
    physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; endLine: number } };
  }>;
  partialFingerprints: { id: string };
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: { name: string; informationUri: string; version: string; rules: Array<{ id: string; name: string }> };
    };
    results: SarifResult[];
  }>;
}

function exactKeys(v: unknown, keys: string[], where: string): Record<string, unknown> {
  if (!isPlainObject(v)) return fail("UNRECOGNIZED_SARIF_SHAPE", `${where} is not an object`);
  const got = Object.keys(v).sort();
  const want = [...keys].sort();
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    fail("UNRECOGNIZED_SARIF_SHAPE", `${where} has keys [${got.join(", ")}], expected exactly [${want.join(", ")}]`);
  }
  return v;
}

const RULE_ID = /^[0-9]-[0-9]-[a-z0-9-]+$/;
const positiveInt = (n: unknown) => Number.isInteger(n) && (n as number) > 0;

export function parseRawSarif(text: string): SarifLog {
  let log: unknown;
  try {
    log = JSON.parse(text);
  } catch (e) {
    return fail("MALFORMED_SARIF", `not JSON: ${(e as Error).message}`);
  }
  const top = exactKeys(log, ["$schema", "version", "runs"], "SARIF log");
  if (top.version !== "2.1.0") fail("UNRECOGNIZED_SARIF_SHAPE", `SARIF version ${String(top.version)}, expected 2.1.0`);
  if (!Array.isArray(top.runs) || top.runs.length !== 1)
    fail("UNRECOGNIZED_SARIF_SHAPE", "SARIF must carry exactly one run");
  const run = exactKeys((top.runs as unknown[])[0], ["tool", "results"], "run");
  const driver = exactKeys(
    exactKeys(run.tool, ["driver"], "run.tool").driver,
    ["name", "informationUri", "version", "rules"],
    "driver",
  );
  if (driver.name !== "Slither")
    fail("UNRECOGNIZED_SARIF_SHAPE", `driver.name is ${String(driver.name)}, expected Slither`);
  if (!Array.isArray(driver.rules)) fail("UNRECOGNIZED_SARIF_SHAPE", "driver.rules is not an array");
  // ONE rule per detector. The mapping signature carries the detector NAME; if two rule ids could
  // share a name, two copies with different ids would look identical to the signature.
  const ruleNameById = new Map<string, string>();
  const ruleNames = new Set<string>();
  (driver.rules as unknown[]).forEach((r, i) => {
    const rule = exactKeys(r, ["id", "name", "properties", "shortDescription", "help"], `rule #${i}`);
    if (typeof rule.id !== "string" || !RULE_ID.test(rule.id) || typeof rule.name !== "string") {
      fail("UNRECOGNIZED_SARIF_SHAPE", `rule #${i} has an unrecognised id/name`);
    }
    if (ruleNameById.has(rule.id as string))
      fail("UNRECOGNIZED_SARIF_SHAPE", `rule id ${String(rule.id)} is declared twice`);
    if (ruleNames.has(rule.name as string))
      fail("UNRECOGNIZED_SARIF_SHAPE", `detector ${String(rule.name)} is declared twice`);
    if ((rule.id as string).slice(4) !== rule.name)
      fail("UNRECOGNIZED_SARIF_SHAPE", `rule ${String(rule.id)} is named ${String(rule.name)}`);
    ruleNameById.set(rule.id as string, rule.name as string);
    ruleNames.add(rule.name as string);
  });
  if (!Array.isArray(run.results)) fail("UNRECOGNIZED_SARIF_SHAPE", "run.results is not an array");
  (run.results as unknown[]).forEach((r, i) => {
    const w = `SARIF result #${i}`;
    const res = exactKeys(r, ["ruleId", "message", "level", "locations", "partialFingerprints"], w);
    if (typeof res.ruleId !== "string" || !ruleNameById.has(res.ruleId))
      fail("UNRECOGNIZED_SARIF_SHAPE", `${w} ruleId is not a declared rule`);
    const msg = exactKeys(res.message, ["text", "markdown"], `${w}.message`);
    if (typeof msg.text !== "string" || typeof msg.markdown !== "string")
      fail("UNRECOGNIZED_SARIF_SHAPE", `${w}.message is not text+markdown strings`);
    if (res.level !== "warning") fail("UNRECOGNIZED_SARIF_SHAPE", `${w}.level is ${String(res.level)}`);
    if (!Array.isArray(res.locations) || res.locations.length !== 1)
      fail("UNRECOGNIZED_SARIF_SHAPE", `${w} must have exactly one location`);
    const loc = exactKeys((res.locations as unknown[])[0], ["physicalLocation"], `${w}.locations[0]`);
    const pl = exactKeys(loc.physicalLocation, ["artifactLocation", "region"], `${w}.physicalLocation`);
    const al = exactKeys(pl.artifactLocation, ["uri"], `${w}.artifactLocation`);
    const region = exactKeys(pl.region, ["startLine", "endLine"], `${w}.region`);
    if (typeof al.uri !== "string" || al.uri.length === 0) fail("UNRECOGNIZED_SARIF_SHAPE", `${w} uri is not a string`);
    if (
      !positiveInt(region.startLine) ||
      !positiveInt(region.endLine) ||
      (region.endLine as number) < (region.startLine as number)
    ) {
      fail("UNRECOGNIZED_SARIF_SHAPE", `${w} region is not a positive line range`);
    }
    const fp = exactKeys(res.partialFingerprints, ["id"], `${w}.partialFingerprints`);
    if (typeof fp.id !== "string" || fp.id.length === 0)
      fail("UNRECOGNIZED_SARIF_SHAPE", `${w} partialFingerprints.id is not a string`);
  });
  return log as SarifLog;
}

// ---------------------------------------------------------------------------------------------
// Mapping, ownership, identity
// ---------------------------------------------------------------------------------------------

const checkOfRuleId = (ruleId: string) => ruleId.slice(4);

/** What Slither's SARIF writer derives from a JSON finding: primary location only. */
export function findingSignature(f: RawFinding): string {
  const sm = f.elements[0].source_mapping as { filename_relative: string; lines: number[] };
  return JSON.stringify([
    f.check,
    f.id,
    f.description,
    f.markdown,
    sm.filename_relative,
    sm.lines[0],
    sm.lines[sm.lines.length - 1],
  ]);
}

export function resultSignature(r: SarifResult): string {
  const pl = r.locations[0].physicalLocation;
  return JSON.stringify([
    checkOfRuleId(r.ruleId),
    r.partialFingerprints.id,
    r.message.text,
    r.message.markdown,
    pl.artifactLocation.uri,
    pl.region.startLine,
    pl.region.endLine,
  ]);
}

/**
 * The dependency predicate, on ONE path. The segment test is the definition; the substring test is
 * the one `isOwnFinding` uses, and a path on which they disagree (`my_node_modules_x/…`) is a path
 * this projection cannot classify the way the triage machinery would, so it fails.
 */
export function isDependencyPath(p: string): boolean {
  const bySegment = p.split("/").includes(DEPENDENCY_SEGMENT);
  const bySubstring = p.includes(DEPENDENCY_SEGMENT);
  if (bySegment !== bySubstring) {
    fail("DEPENDENCY_PREDICATE_DISAGREEMENT", `"${p}": path-segment and substring dependency tests disagree`);
  }
  return bySegment;
}

export type Ownership = "OWN" | "DEPENDENCY_ONLY" | "MIXED_PROJECT_PRIMARY" | "MIXED_DEPENDENCY_PRIMARY";

const fileOf = (e: SlitherFinding["elements"][number]) => e.source_mapping?.filename_relative as string;

export function classifyOwnership(f: SlitherFinding): Ownership {
  const dep = f.elements.map((e) => isDependencyPath(fileOf(e)));
  if (!dep.some(Boolean)) return "OWN";
  if (dep.every(Boolean)) return "DEPENDENCY_ONLY";
  return dep[0] ? "MIXED_DEPENDENCY_PRIMARY" : "MIXED_PROJECT_PRIMARY";
}

export interface ProjectedIdentity {
  semanticId: string;
  ruleId: string;
  uri: string;
  startLine: number;
  endLine: number;
  locator: string;
  instances: number;
}

export interface ExcludedMixedFinding {
  check: string;
  primary: string;
  projectElements: Array<{ type: string; file: string; line: number }>;
  instances: number;
}

export interface ProjectionCounts {
  rawSarifResults: number;
  rawScanFindings: number;
  ownInstances: number;
  ownDistinct: number;
  ownCopiesCollapsed: number;
  dependencyOnlyInstances: number;
  mixedDependencyPrimaryExcludedInstances: number;
  projectedResults: number;
}

export interface Projection {
  log: SarifLog;
  counts: ProjectionCounts;
  projected: ProjectedIdentity[];
  excludedMixed: ExcludedMixedFinding[];
}

/**
 * Builds the GitHub projection from the two raw outputs of ONE Slither execution. Pure: reads no
 * files and no git, so the same inputs give the same answer anywhere. Throws ProjectionError.
 */
export function projectSarif(rawScanText: string, rawSarifText: string): Projection {
  const findings = parseRawScan(rawScanText);
  const log = parseRawSarif(rawSarifText);
  const results = log.runs[0].results;

  // 1. RAW <-> SARIF: equal multisets of signatures, and one meaning per signature.
  const bySig = new Map<string, RawFinding[]>();
  for (const f of findings) {
    const k = findingSignature(f);
    (bySig.get(k) || bySig.set(k, []).get(k)!).push(f);
  }
  const resultsBySig = new Map<string, SarifResult[]>();
  for (const r of results) {
    const k = resultSignature(r);
    (resultsBySig.get(k) || resultsBySig.set(k, []).get(k)!).push(r);
  }
  for (const [k, rs] of resultsBySig) {
    const have = bySig.get(k)?.length || 0;
    if (have === 0) fail("UNMAPPED_SARIF_RESULT", `a SARIF result has no raw finding: ${k.slice(0, 240)}`);
    if (have !== rs.length)
      fail("UNMAPPED_SARIF_RESULT", `${rs.length} SARIF result(s) but ${have} raw finding(s) for: ${k.slice(0, 240)}`);
    if (new Set(rs.map((r) => JSON.stringify(r))).size !== 1) {
      fail("AMBIGUOUS_MAPPING", `SARIF results sharing one signature differ: ${k.slice(0, 240)}`);
    }
  }
  for (const [k, fs_] of bySig) {
    if (!resultsBySig.has(k)) {
      fail(
        "UNREPRESENTABLE_FINDING",
        `${fs_.length} raw finding(s) (${classifyOwnership(fs_[0])}) are absent from the SARIF: ${k.slice(0, 240)}`,
      );
    }
    if (new Set(fs_.map((f) => JSON.stringify(f))).size !== 1) {
      fail(
        "AMBIGUOUS_MAPPING",
        `one SARIF signature maps to raw findings that differ: ${fs_.map(canonicalLocator).join(" | ")}`,
      );
    }
  }

  // 2. OWNERSHIP, cross-checked against the triage machinery's own predicate on every finding.
  const ownership = new Map<RawFinding, Ownership>();
  for (const f of findings) {
    const o = classifyOwnership(f);
    if ((o === "OWN") !== isOwnFinding(f)) {
      fail(
        "TRIAGE_SCOPE_DISAGREEMENT",
        `${f.check} at ${canonicalLocator(f)}: projection says ${o}, isOwnFinding says ${String(isOwnFinding(f))}`,
      );
    }
    if (o === "MIXED_PROJECT_PRIMARY") {
      fail(
        "PROJECT_FINDING_REFERENCES_DEPENDENCY",
        `${f.check} at ${canonicalLocator(f)} is anchored in project code but also references a dependency. It must not be ` +
          `dropped, and the governed triage scope (isOwnFinding) cannot adjudicate it; decide its scope explicitly.`,
      );
    }
    if (o === "MIXED_DEPENDENCY_PRIMARY") {
      const projectEls = f.elements.filter((e) => !isDependencyPath(fileOf(e)));
      if (!VERSION_LINT_DETECTORS.includes(f.check) || projectEls.some((e) => e.type !== "pragma")) {
        fail(
          "PROJECT_CODE_IN_DEPENDENCY_FINDING",
          `${f.check} at ${canonicalLocator(f)} is anchored in a dependency but references project ` +
            `${[...new Set(projectEls.map((e) => e.type))].join("/")} element(s); only version-lint pragma references may be dropped`,
        );
      }
    }
    ownership.set(f, o);
  }

  // 3. IDENTITY: collapse only exact copies, keyed by the triage's own semanticId.
  const ownGroups = new Map<string, RawFinding[]>();
  for (const f of findings) {
    if (ownership.get(f) !== "OWN") continue;
    const id = semanticId(f);
    (ownGroups.get(id) || ownGroups.set(id, []).get(id)!).push(f);
  }
  for (const [id, members] of ownGroups) {
    const jsonVariants = new Set(members.map((f) => JSON.stringify(f)));
    // EVERY result of EVERY member, not one representative per signature.
    const sarifVariants = new Set(
      members.flatMap((f) => resultsBySig.get(findingSignature(f))!.map((r) => JSON.stringify(r))),
    );
    if (jsonVariants.size !== 1 || sarifVariants.size !== 1) {
      fail(
        "DISTINCT_FINDINGS_WOULD_COLLAPSE",
        `semanticId ${id} covers ${jsonVariants.size} distinct raw finding(s) / ${sarifVariants.size} distinct SARIF ` +
          `result(s): ${[...new Set(members.map(canonicalLocator))].join(" | ")}`,
      );
    }
  }

  // 4. PROJECT in raw order, first occurrence of each identity; count what was dropped and why.
  const findingBySig = new Map<string, RawFinding>();
  for (const [k, fs_] of bySig) findingBySig.set(k, fs_[0]);
  const emitted = new Map<string, ProjectedIdentity>();
  const projectedResults: SarifResult[] = [];
  const excluded = new Map<string, ExcludedMixedFinding>();
  let dependencyOnly = 0;
  let mixedExcluded = 0;
  for (const r of results) {
    const f = findingBySig.get(resultSignature(r))!;
    const o = ownership.get(f)!;
    if (o === "DEPENDENCY_ONLY") {
      dependencyOnly++;
      continue;
    }
    if (o === "MIXED_DEPENDENCY_PRIMARY") {
      mixedExcluded++;
      const k = findingSignature(f);
      const pl = r.locations[0].physicalLocation;
      const prev = excluded.get(k);
      if (prev) prev.instances++;
      else {
        excluded.set(k, {
          check: f.check,
          primary: `${pl.artifactLocation.uri}:${pl.region.startLine}`,
          projectElements: f.elements
            .filter((e) => !isDependencyPath(fileOf(e)))
            .map((e) => ({ type: e.type as string, file: fileOf(e), line: (e.source_mapping!.lines as number[])[0] })),
          instances: 1,
        });
      }
      continue;
    }
    const id = semanticId(f);
    const seen = emitted.get(id);
    if (seen) {
      seen.instances++;
      continue;
    }
    const pl = r.locations[0].physicalLocation;
    emitted.set(id, {
      semanticId: id,
      ruleId: r.ruleId,
      uri: pl.artifactLocation.uri,
      startLine: pl.region.startLine,
      endLine: pl.region.endLine,
      locator: canonicalLocator(f),
      instances: 1,
    });
    projectedResults.push(r);
  }

  // 5. INDEPENDENT CROSS-CHECKS.
  const ownIds = new Set(findings.filter((f) => isOwnFinding(f)).map((f) => semanticId(f)));
  const projectedIds = [...emitted.keys()];
  if (projectedIds.length !== ownIds.size || projectedIds.some((id) => !ownIds.has(id))) {
    fail(
      "TRIAGE_SCOPE_DISAGREEMENT",
      `projected ${projectedIds.length} identities; the isOwnFinding set has ${ownIds.size}`,
    );
  }
  if (projectedResults.length === 0) {
    fail(
      "EMPTY_PROJECTION",
      "no project-owned finding would be uploaded; for this governed lane an empty projection is not credible",
    );
  }
  const projectedLog: SarifLog = { ...log, runs: [{ ...log.runs[0], results: projectedResults }] };
  assertProjectionIsSubset(log, projectedLog);

  const ownInstances = findings.filter((f) => ownership.get(f) === "OWN").length;
  return {
    log: projectedLog,
    counts: {
      rawSarifResults: results.length,
      rawScanFindings: findings.length,
      ownInstances,
      ownDistinct: emitted.size,
      ownCopiesCollapsed: ownInstances - emitted.size,
      dependencyOnlyInstances: dependencyOnly,
      mixedDependencyPrimaryExcludedInstances: mixedExcluded,
      projectedResults: projectedResults.length,
    },
    projected: [...emitted.values()],
    excludedMixed: [...excluded.values()],
  };
}

/**
 * The "exactly two transformations" guarantee, checked rather than assumed: every byte outside
 * `runs[0].results` is unchanged, and the projected results are an order-preserving subsequence of
 * the raw ones, each byte-identical to its original.
 */
export function assertProjectionIsSubset(raw: SarifLog, projected: SarifLog): void {
  const strip = (l: SarifLog) => JSON.stringify({ ...l, runs: [{ ...l.runs[0], results: [] }] });
  if (strip(raw) !== strip(projected)) fail("PROJECTION_NOT_A_SUBSET", "a field outside runs[0].results changed");
  const rawResults = raw.runs[0].results.map((r) => JSON.stringify(r));
  let cursor = 0;
  for (const r of projected.runs[0].results) {
    const s = JSON.stringify(r);
    while (cursor < rawResults.length && rawResults[cursor] !== s) cursor++;
    if (cursor === rawResults.length)
      fail("PROJECTION_NOT_A_SUBSET", "a projected result is not an in-order raw result");
    cursor++;
  }
}

// ---------------------------------------------------------------------------------------------
// Triage bijection
// ---------------------------------------------------------------------------------------------

export function loadTriageIdentities(text: string): Set<string> {
  let t: unknown;
  try {
    t = JSON.parse(text);
  } catch (e) {
    return fail("MALFORMED_TRIAGE", `not JSON: ${(e as Error).message}`);
  }
  const classifications = isPlainObject(t) ? t.classifications : undefined;
  if (!isPlainObject(classifications)) return fail("MALFORMED_TRIAGE", "classifications is not an object");
  const ids = Object.keys(classifications);
  if (ids.length === 0) fail("MALFORMED_TRIAGE", "the triage adjudicates nothing");
  for (const id of ids) if (!/^[0-9a-f]{64}$/.test(id)) fail("MALFORMED_TRIAGE", `"${id}" is not a semanticId`);
  return new Set(ids);
}

export interface Bijection {
  triageEntries: number;
  projected: number;
  matched: number;
  missing: string[];
  extra: string[];
}

/** Every triaged identity projects to exactly one result, and nothing else is projected. */
export function assertTriageBijection(projected: ProjectedIdentity[], triage: Set<string>): Bijection {
  const ids = projected.map((p) => p.semanticId);
  if (new Set(ids).size !== ids.length)
    fail("TRIAGE_BIJECTION_FAILED", "a semantic identity is projected more than once");
  const missing = [...triage].filter((id) => !ids.includes(id)).sort();
  const extra = ids.filter((id) => !triage.has(id)).sort();
  const b: Bijection = {
    triageEntries: triage.size,
    projected: ids.length,
    matched: ids.length - extra.length,
    missing,
    extra,
  };
  if (missing.length > 0 || extra.length > 0) {
    fail(
      "TRIAGE_BIJECTION_FAILED",
      `triage ${triage.size} <-> projected ${ids.length}: ${missing.length} triaged identit(ies) not projected ` +
        `[${missing.join(", ")}], ${extra.length} projected identit(ies) not triaged [${extra.join(", ")}]`,
    );
  }
  return b;
}

// ---------------------------------------------------------------------------------------------
// Workflow wiring contract: the projection, not the raw SARIF, is what reaches code scanning
// ---------------------------------------------------------------------------------------------

interface WorkflowStep {
  name: string;
  body: string;
  field: (key: string) => string | undefined;
}

function slitherJobSteps(text: string): WorkflowStep[] {
  const lines = text.split(/\r?\n/).filter((l) => !/^\s*#/.test(l));
  const start = lines.findIndex((l) => l === "  slither:");
  if (start < 0) fail("WORKFLOW_CONTRACT", `${WORKFLOW_PATH}: job "slither:" not found`);
  let end = lines.findIndex((l, i) => i > start && /^ {2}[A-Za-z0-9_-]+:\s*$/.test(l));
  if (end < 0) end = lines.length;
  const steps: WorkflowStep[] = [];
  let cur: string[] | null = null;
  const flush = () => {
    if (!cur) return;
    const stepLines = cur;
    const name = (stepLines[0].match(/^ {6}- name:\s*(.+)$/) as RegExpMatchArray)[1].trim();
    steps.push({
      name,
      body: stepLines.join("\n"),
      // First line whose key is exactly `key`. Plain string matching: no pattern is ever built
      // from a key or from workflow content.
      field: (key: string) => {
        for (const line of stepLines) {
          let t = line.trimStart();
          if (t.startsWith("- ")) t = t.slice(2);
          if (!t.startsWith(`${key}:`)) continue;
          const value = t.slice(key.length + 1).trim();
          if (value.length > 0) return value;
        }
        return undefined;
      },
    });
  };
  for (const l of lines.slice(start + 1, end)) {
    if (/^ {6}- name:/.test(l)) {
      flush();
      cur = [l];
    } else if (cur) cur.push(l);
  }
  flush();
  return steps;
}

/**
 * Throws unless the vNext Slither job preserves the complete raw output as artifacts BEFORE any
 * gate, validates triage and receipt against the RAW JSON, projects only after that, and hands
 * code scanning the projection -- and only a projection whose step succeeded.
 */
export function assertWorkflowSarifProjectionContract(path: string = WORKFLOW_PATH): void {
  const steps = slitherJobSteps(fs.readFileSync(path, "utf8"));
  const idx = (pred: (s: WorkflowStep) => boolean, what: string) => {
    const hits = steps.map((s, i) => (pred(s) ? i : -1)).filter((i) => i >= 0);
    if (hits.length !== 1)
      fail("WORKFLOW_CONTRACT", `${path}: expected exactly one ${what} in the slither job, found ${hits.length}`);
    return hits[0];
  };
  const slither = idx((s) => /crytic\/slither-action@/.test(s.field("uses") || ""), "Slither step");
  if (steps[slither].field("sarif") !== RAW_SARIF_PATH) {
    fail("WORKFLOW_CONTRACT", `${path}: Slither must write its SARIF to ${RAW_SARIF_PATH}`);
  }
  const rawJsonArtifact = idx(
    (s) => /actions\/upload-artifact@/.test(s.field("uses") || "") && s.field("path") === RAW_SCAN_PATH,
    "raw JSON artifact upload",
  );
  const rawSarifArtifact = idx(
    (s) => /actions\/upload-artifact@/.test(s.field("uses") || "") && s.field("path") === RAW_SARIF_PATH,
    "raw SARIF artifact upload",
  );
  for (const i of [rawJsonArtifact, rawSarifArtifact]) {
    if (!/always\(\)/.test(steps[i].field("if") || "")) {
      fail(
        "WORKFLOW_CONTRACT",
        `${path}: "${steps[i].name}" must run under always() so a failing gate cannot suppress it`,
      );
    }
  }
  const validate = idx(
    (s) => /generate-scanner-evidence\.ts/.test(s.body) && /--validate/.test(s.body),
    "triage validation step",
  );
  const receipt = idx(
    (s) => /generate-scanner-evidence\.ts/.test(s.body) && /--check/.test(s.body),
    "receipt byte-identity step",
  );
  const projection = idx((s) => /scanner-sarif-projection\.ts/.test(s.body), "SARIF projection step");
  const upload = idx((s) => /github\/codeql-action\/upload-sarif@/.test(s.field("uses") || ""), "upload-sarif step");

  const p = steps[projection];
  const projectionId = p.field("id");
  if (!projectionId) fail("WORKFLOW_CONTRACT", `${path}: the projection step needs an id`);
  for (const [flag, value] of [
    ["--raw-sarif", RAW_SARIF_PATH],
    ["--raw-scan", RAW_SCAN_PATH],
    ["--triage", TRIAGE_PATH],
    ["--out", PROJECTED_SARIF_PATH],
  ]) {
    // Token adjacency, not a pattern built from the value: `flag` immediately followed by `value`.
    const tokens = p.body.split(/\s+/);
    if (!tokens.some((t, i) => t === flag && tokens[i + 1] === value)) {
      fail("WORKFLOW_CONTRACT", `${path}: the projection step must pass ${flag} ${value}`);
    }
  }
  const u = steps[upload];
  if (u.field("sarif_file") !== PROJECTED_SARIF_PATH) {
    fail(
      "WORKFLOW_CONTRACT",
      `${path}: upload-sarif must receive ${PROJECTED_SARIF_PATH}, not ${String(u.field("sarif_file"))}`,
    );
  }
  if (u.field("category") !== SARIF_CATEGORY)
    fail("WORKFLOW_CONTRACT", `${path}: upload-sarif category must stay ${SARIF_CATEGORY}`);
  const uploadCondition = (u.field("if") || "").replace(/\s+/g, " ");
  if (!uploadCondition.includes(`steps.${String(projectionId)}.outcome == 'success'`)) {
    fail(
      "WORKFLOW_CONTRACT",
      `${path}: upload-sarif must be conditioned on steps.${String(projectionId)}.outcome == 'success'`,
    );
  }
  const order: Array<[number, number, string]> = [
    [slither, rawJsonArtifact, "Slither before the raw JSON artifact"],
    [rawJsonArtifact, validate, "raw JSON artifact before triage validation"],
    [rawSarifArtifact, validate, "raw SARIF artifact before triage validation"],
    [validate, projection, "triage validation before projection"],
    [receipt, projection, "receipt byte identity before projection"],
    [projection, upload, "projection before upload-sarif"],
  ];
  for (const [a, b, what] of order) if (!(a < b)) fail("WORKFLOW_CONTRACT", `${path}: ordering violated: ${what}`);
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith("--") || i + 1 >= argv.length) throw new Error(`unexpected argument ${tok}`);
    out[tok.slice(2)] = argv[++i];
  }
  return out;
}

export function main(argv: string[]): number {
  const args = parseArgs(argv);
  const rawSarifPath = args["raw-sarif"] ?? RAW_SARIF_PATH;
  const rawScanPath = args["raw-scan"] ?? RAW_SCAN_PATH;
  const triagePath = args["triage"] ?? TRIAGE_PATH;
  const outPath = args["out"] ?? PROJECTED_SARIF_PATH;
  const reportPath = args["report"];
  const report: Record<string, unknown> = { schema: REPORT_SCHEMA, ok: false };
  try {
    const rawSarifText = fs.readFileSync(rawSarifPath, "utf8");
    const rawScanText = fs.readFileSync(rawScanPath, "utf8");
    const triageText = fs.readFileSync(triagePath, "utf8");
    report.inputs = {
      rawSarif: { path: rawSarifPath, sha256: sha256(rawSarifText) },
      rawScan: { path: rawScanPath, sha256: sha256(rawScanText) },
      triage: { path: triagePath, sha256: sha256(triageText) },
    };
    const projection = projectSarif(rawScanText, rawSarifText);
    report.counts = projection.counts;
    report.projected = projection.projected;
    report.excludedMixed = projection.excludedMixed;
    const bijection = assertTriageBijection(projection.projected, loadTriageIdentities(triageText));
    report.bijection = bijection;
    // EXCLUSIVE CREATE ("wx"): refusing a pre-existing output is atomic with the write itself. A
    // separate existence check followed by a write is a check-then-use race (js/file-system-race).
    try {
      fs.writeFileSync(outPath, JSON.stringify(projection.log, null, 2), { flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        fail("PRE_EXISTING_OUTPUT", `${outPath} already exists; refusing to leave a stale projection uploadable`);
      }
      throw e;
    }
    report.ok = true;
    const c = projection.counts;
    console.log(
      `SARIF projection: ${c.rawSarifResults} raw result(s) = ${c.ownInstances} project-owned instance(s) ` +
        `(${c.ownDistinct} distinct + ${c.ownCopiesCollapsed} exact copies) + ${c.dependencyOnlyInstances} dependency-only + ` +
        `${c.mixedDependencyPrimaryExcludedInstances} dependency-anchored version lint(s). Uploading ${c.projectedResults}.`,
    );
    for (const x of projection.excludedMixed) {
      console.log(
        `  excluded ${x.check} anchored at ${x.primary}; project pragma(s): ${x.projectElements.map((e) => `${e.file}:${e.line}`).join(", ")}`,
      );
    }
    console.log(
      `Triage bijection: ${bijection.triageEntries} triaged <-> ${bijection.projected} projected, ${bijection.matched} matched. OK.`,
    );
    return 0;
  } catch (e) {
    const err = e as Error;
    report.failure = { code: e instanceof ProjectionError ? e.code : "UNEXPECTED", message: err.message };
    console.error(`SARIF projection FAILED; nothing will be uploaded. ${err.message}`);
    return 1;
  } finally {
    if (reportPath) fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  }
}

if (process.argv[1] && process.argv[1].endsWith("scanner-sarif-projection.ts")) {
  process.exit(main(process.argv.slice(2)));
}
