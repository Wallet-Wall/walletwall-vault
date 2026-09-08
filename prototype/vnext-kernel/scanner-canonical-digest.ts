/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * CANONICAL SCANNER-OUTPUT DIGESTS — a scanner-result identity that survives crossing machines.
 *
 * WHAT WENT WRONG. The receipt carried `rawOutputSha256`: sha256 of the whole Slither `--json`
 * file. That value is NOT a portable identity, and a receipt that must byte-reproduce cannot
 * contain one. It failed in CI at 0129e2ed while every security-relevant quantity agreed exactly
 * -- 217 raw, 54 own-code rows, 33 distinct, 0 untriaged, 0 stale, 0 ambiguous, 8/15/5/5:
 *
 *   local run  054135ac...
 *   CI run     47c5ed50...
 *
 * MEASURED, NOT ASSUMED. The CI output was uploaded as an artifact and diffed against the local
 * one. Two classes of difference, and only two:
 *
 *   1. RESULT ORDERING. `results.detectors` is emitted in a different order -- 144 of 217 array
 *      positions held a different finding. This is the dominant cause and it is invisible to any
 *      whole-file hash.
 *   2. WORKSPACE ROOT. `filename_absolute` embeds the checkout path (`/root/w2s/repo` locally,
 *      `/github/workspace` inside the action's container). `filename_relative` and
 *      `filename_short` are already repo-relative and were identical.
 *
 * Nothing else differed: after normalising the root and sorting, the two finding multisets are
 * byte-identical (0 only-local, 0 only-CI). Substituting the CI root into the local file did NOT
 * reproduce the CI hash, which is what ruled out "paths are the only cause" as a guess.
 *
 * WHAT THE DIGESTS DELIBERATELY EXCLUDE, each because it varies without the code varying:
 *   filename_absolute      the checkout root
 *   emission order         re-sorted before hashing
 *   start/length/columns   byte offsets; `lines` already carries the span, and offsets would make
 *                          the digest sensitive to line-ending normalisation
 *   filename_short         a duplicate of filename_relative
 *   JSON key order and whitespace   a canonical structure is built and serialized here
 *
 * WHAT THEY REMAIN SENSITIVE TO: detector, impact, confidence, the detector message, the
 * repository-relative file and line span of every element, and the element type/name/signature
 * and parent chain. A change to any of those changes the digest.
 */
import { createHash } from "node:crypto";
import {
  isOwnFinding,
  indexFindings,
  stripLineReferences,
  type FindingRow,
  type SlitherElement,
  type SlitherFinding,
  type SourceReader,
} from "./scanner-finding-identity.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** Element identity with every environment-dependent field removed. */
interface CanonicalElement {
  type: string;
  name: string;
  signature: string;
  file: string;
  lines: [number, number] | [];
  parent: string;
}

function parentChainOf(e: SlitherElement): string {
  const parts: string[] = [];
  let cur = e.type_specific_fields?.parent;
  let guard = 0;
  while (cur && guard++ < 8) {
    parts.push(`${cur.type}:${cur.name}:${cur.type_specific_fields?.signature ?? ""}`);
    cur = cur.type_specific_fields?.parent;
  }
  return parts.join(" < ");
}

function canonicalElement(e: SlitherElement): CanonicalElement {
  const sm = e.source_mapping || {};
  const lines = sm.lines || [];
  return {
    type: e.type ?? "",
    name: e.name ?? "",
    signature: e.type_specific_fields?.signature ?? "",
    file: sm.filename_relative ?? "",
    lines: lines.length ? [lines[0], lines[lines.length - 1]] : [],
    parent: parentChainOf(e),
  };
}

export interface CanonicalFinding {
  check: string;
  impact: string;
  confidence: string;
  message: string;
  elements: CanonicalElement[];
}

/**
 * One finding, reduced to what a scanner result MEANS.
 *
 * The message keeps its repository-relative citations but has line references normalised, because
 * the line span of every element is already carried structurally; keeping both would make the
 * digest count the same relocation twice without adding sensitivity.
 */
export function canonicalFinding(f: SlitherFinding): CanonicalFinding {
  const elements = f.elements.map(canonicalElement);
  // Elements are sorted so the scanner's own emission order inside a finding cannot move the digest.
  elements.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return {
    check: f.check,
    impact: f.impact,
    confidence: f.confidence,
    message: stripLineReferences(f.description).trim(),
    elements,
  };
}

/** Deterministic, order-independent digest over EVERY finding, dependencies included. */
export function canonicalAllFindingsSha256(findings: SlitherFinding[]): string {
  const rows = findings.map((f) => JSON.stringify(canonicalFinding(f)));
  rows.sort();
  return sha256(rows.join("\n"));
}

export interface OwnDigestEntry {
  semanticId: string;
  check: string;
  impact: string;
  confidence: string;
  narrow: string | null;
  broad: string | null;
  classification: string;
  locator: string;
}

/**
 * Digest over the 33 DISTINCT own-code findings, binding each to its adjudication.
 *
 * Separate from the all-findings digest on purpose. That one answers "did the scanner see the same
 * thing?"; this one answers "is the same set of own-code findings still classified the same way?".
 * A dependency-only change moves the first and not the second, and conflating them would make an
 * OpenZeppelin bump look like a change in this kernel's adjudicated state.
 */
export function canonicalDistinctOwnFindings(
  byId: Map<string, FindingRow>,
  classificationOf: (semanticId: string) => string,
): OwnDigestEntry[] {
  const entries: OwnDigestEntry[] = [...byId.values()].map((r) => ({
    semanticId: r.semanticId,
    check: r.check,
    impact: r.impact,
    confidence: r.confidence,
    narrow: r.narrow ?? null,
    broad: r.broad ?? null,
    classification: classificationOf(r.semanticId),
    locator: r.locator,
  }));
  entries.sort((a, b) => a.semanticId.localeCompare(b.semanticId));
  return entries;
}

export function canonicalDistinctOwnFindingsSha256(
  byId: Map<string, FindingRow>,
  classificationOf: (semanticId: string) => string,
): string {
  return sha256(canonicalDistinctOwnFindings(byId, classificationOf).map((e) => JSON.stringify(e)).join("\n"));
}

/** Convenience wrapper computing both digests from a raw detector array. */
export function canonicalDigests(
  detectors: SlitherFinding[],
  read: SourceReader,
  classificationOf: (semanticId: string) => string,
): { all: string; own: string; ownCount: number; allCount: number } {
  const { byId } = indexFindings(detectors, read);
  return {
    all: canonicalAllFindingsSha256(detectors),
    own: canonicalDistinctOwnFindingsSha256(byId, classificationOf),
    ownCount: byId.size,
    allCount: detectors.length,
  };
}

export { isOwnFinding };
