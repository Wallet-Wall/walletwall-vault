/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * STABLE SEMANTIC IDENTITY FOR SCANNER FINDINGS.
 *
 * WHY THIS EXISTS. The v1 triage key was
 * `<check>|<sorted filename:firstLine of every element>`. It is a LOCATOR: it names where a
 * finding was standing, not what it is. Two commits that only shift a function down the file
 * produce a completely different key for the identical finding, so the triage silently goes
 * stale and `--validate` reports untriaged findings that were adjudicated months earlier. That
 * is exactly what happened between c32e0d74 and aaa21d09: 33 findings, 0 added, 0 removed, and
 * 21 of 33 keys unmatched — purely because two edits moved code by +120 and +133 lines.
 *
 * THE FIX IS TO SEPARATE TWO QUESTIONS THAT THE v1 KEY CONFLATED:
 *
 *   IDENTITY    "is this the same finding?"      -> `semanticId`, carries NO line information
 *   CHANGE      "did what it describes change?"  -> `narrowFingerprint` / `broadFingerprint`
 *
 * Folding the source content into the identity would be worse than the v1 key, not better: every
 * comment edit inside a function would mint a new identity and orphan its own adjudication
 * history. So identity is deliberately insensitive to source content, and change is detected by
 * comparing fingerprints BETWEEN two runs of findings that already share an identity.
 *
 * NARROW vs BROAD, AND WHY BOTH. A finding's elements are a mixture of the CONSTRUCT Slither
 * actually flagged (`node` elements — the expression or statement) and the CONTEXT it sits in
 * (`function`, `contract`, `variable`). Hashing all of them together cannot distinguish "the
 * flagged expression changed" from "someone edited an unrelated line in the same function".
 * Only the first justifies saying the finding's semantics changed. So:
 *
 *   narrowFingerprint  -> `node` elements only. A difference PROVES the flagged construct moved
 *                         semantically. UNDEFINED when the finding has no node element.
 *   broadFingerprint   -> every element. A difference proves only that the surrounding source
 *                         changed, which REQUIRES RE-ADJUDICATION but proves nothing on its own.
 *
 * `narrowFingerprint` is UNDEFINED, never "the hash of nothing", for findings with no node
 * element (7 of the 33 in this corpus). A constant stand-in would compare equal forever and
 * silently assert "unchanged" for a class of findings this axis cannot see at all — a
 * classification asserting more than its trigger proves. Undefined forces the broad fallback,
 * whose strongest possible verdict is SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION.
 */
import { createHash } from "node:crypto";

export interface SlitherSourceMapping {
  filename_relative?: string;
  lines?: number[];
}
export interface SlitherElement {
  type?: string;
  name?: string;
  source_mapping?: SlitherSourceMapping;
  type_specific_fields?: { parent?: SlitherElement; signature?: string };
}
export interface SlitherFinding {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: SlitherElement[];
}

/** Reader for the source of a file at some revision. Injectable so tests need no git. */
export type SourceReader = (filenameRelative: string) => string[];

export const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");

/**
 * TRUE when every element of a finding lies in project-owned source.
 *
 * Unchanged from v1 on purpose: this predicate decides SCOPE, not identity, and re-deriving it
 * here would let the two drift apart.
 */
export function isOwnFinding(f: SlitherFinding): boolean {
  return f.elements.every((e) => {
    const fr = e.source_mapping?.filename_relative || "";
    return fr.length > 0 && !fr.includes("node_modules");
  });
}

/**
 * The v1 key, RETAINED AS A LOCATOR. Never an identity, never a match criterion — it is recorded
 * so a human can find the finding in a specific checkout and so historical keys stay resolvable.
 */
export function canonicalLocator(f: SlitherFinding): string {
  const locs = new Set<string>();
  for (const e of f.elements) {
    const fr = e.source_mapping?.filename_relative;
    if (fr) locs.add(`${fr}:${(e.source_mapping?.lines || [])[0]}`);
  }
  return `${f.check}|${[...locs].sort().join(",")}`;
}

/** `type:name` walked up the parent chain to the contract. Contains no line information. */
export function elementChain(e: SlitherElement): string {
  const parts: string[] = [];
  let cur: SlitherElement | undefined = e;
  let guard = 0;
  while (cur && guard++ < 8) {
    parts.push(`${cur.type}:${cur.name}`);
    cur = cur.type_specific_fields?.parent;
  }
  return parts.join(" < ");
}

/**
 * Replaces every `#123` / `#123-456` source citation in a detector message with a constant.
 *
 * Slither embeds line references directly in its prose. Left alone they would reintroduce exactly
 * the line dependence this module exists to remove.
 */
export function stripLineReferences(s: string): string {
  return (s || "").replace(/#[0-9]+(-[0-9]+)?/g, "#L");
}

interface IdentityElement {
  file: string;
  chain: string;
  signature: string;
}

/** The exact tuple hashed into `semanticId`. Exposed so a test can assert what is and is not in it. */
export function semanticIdParts(f: SlitherFinding): {
  detector: string;
  elements: IdentityElement[];
  message: string;
} {
  const elements: IdentityElement[] = f.elements.map((e) => ({
    file: e.source_mapping?.filename_relative || "",
    chain: elementChain(e),
    signature: e.type_specific_fields?.signature || "",
  }));
  // Sorted so Slither's element emission order cannot perturb identity.
  elements.sort((a, b) =>
    `${a.file}${a.chain}${a.signature}`.localeCompare(`${b.file}${b.chain}${b.signature}`),
  );
  return { detector: f.check, elements, message: stripLineReferences(f.description).trim() };
}

/** Line-independent identity of a finding. */
export function semanticId(f: SlitherFinding): string {
  return sha256Hex(JSON.stringify(semanticIdParts(f)));
}

/**
 * Strips comments and collapses whitespace, so a reflow or a comment rewrite is not mistaken for
 * a change in what the code does. Deliberately lexical: this is a change DETECTOR, not a parser,
 * and it is only ever used to compare one revision of a span against another.
 */
export function normaliseSolidity(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/[^\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function fingerprintOver(
  f: SlitherFinding,
  read: SourceReader,
  keep: (e: SlitherElement) => boolean,
): string | undefined {
  const kept = f.elements.filter(keep);
  if (kept.length === 0) return undefined;
  const parts = kept.map((e) => {
    const sm = e.source_mapping || {};
    const lines = sm.lines || [];
    const file = sm.filename_relative || "";
    const src = read(file);
    const body = lines.map((n) => src[n - 1] ?? "").join("\n");
    return `${file}|${elementChain(e)}|${normaliseSolidity(body)}`;
  });
  parts.sort();
  return sha256Hex(parts.join("\n--\n"));
}

/** `node` elements only — the constructs Slither actually flagged. UNDEFINED when there are none. */
export function narrowFingerprint(f: SlitherFinding, read: SourceReader): string | undefined {
  return fingerprintOver(f, read, (e) => e.type === "node");
}

/** Every element, context included. Always defined for a finding with at least one element. */
export function broadFingerprint(f: SlitherFinding, read: SourceReader): string | undefined {
  return fingerprintOver(f, read, () => true);
}

export type MatchClass =
  | "UNCHANGED"
  | "RELOCATED"
  | "SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION"
  | "SEMANTIC_CHANGE_PROVEN"
  | "ADDED"
  | "REMOVED";

export interface FindingRow {
  semanticId: string;
  locator: string;
  check: string;
  impact: string;
  confidence: string;
  description: string;
  narrow?: string;
  broad?: string;
  lineSpans: string[];
}

export function toRow(f: SlitherFinding, read: SourceReader): FindingRow {
  return {
    semanticId: semanticId(f),
    locator: canonicalLocator(f),
    check: f.check,
    impact: f.impact,
    confidence: f.confidence,
    description: f.description.trim(),
    narrow: narrowFingerprint(f, read),
    broad: broadFingerprint(f, read),
    lineSpans: f.elements.map((e) => {
      const sm = e.source_mapping || {};
      const l = sm.lines || [];
      return `${sm.filename_relative}:${l[0]}-${l[l.length - 1]}`;
    }),
  };
}

export interface Ambiguity {
  semanticId: string;
  reason: string;
  locators: string[];
}

export interface IndexResult {
  byId: Map<string, FindingRow>;
  ambiguities: Ambiguity[];
  ownRawCount: number;
}

/**
 * Collapses own-code findings to one row per `semanticId`.
 *
 * DUPLICATES ARE EXPECTED AND ARE NOT AMBIGUITY. crytic-compile's plain `solc` platform compiles
 * every top-level .sol under the target as an independent unit, so a file imported by another
 * entry point is analyzed once per entry point. Those duplicates agree on identity, locator and
 * both fingerprints — 54 own rows collapse to 33 ids that way. AMBIGUITY is the opposite case:
 * two findings claiming one identity while DISAGREEING about where they are or what they cover.
 * That is unresolvable, so it is reported and the caller must fail rather than pick one.
 */
export function indexFindings(findings: SlitherFinding[], read: SourceReader): IndexResult {
  const own = findings.filter(isOwnFinding);
  const byId = new Map<string, FindingRow>();
  const ambiguities: Ambiguity[] = [];
  for (const f of own) {
    const row = toRow(f, read);
    const prev = byId.get(row.semanticId);
    if (!prev) {
      byId.set(row.semanticId, row);
      continue;
    }
    if (prev.locator !== row.locator) {
      ambiguities.push({
        semanticId: row.semanticId,
        reason: "two findings share one semantic identity but sit at different locators",
        locators: [prev.locator, row.locator],
      });
    } else if (prev.narrow !== row.narrow || prev.broad !== row.broad) {
      ambiguities.push({
        semanticId: row.semanticId,
        reason: "two findings share one semantic identity and locator but differ in source fingerprint",
        locators: [prev.locator, row.locator],
      });
    }
  }
  return { byId, ambiguities, ownRawCount: own.length };
}

export interface MatchedFinding {
  semanticId: string;
  klass: MatchClass;
  current?: FindingRow;
  prior?: { locator: string; narrow?: string; broad?: string };
  lineDelta?: number[];
}

export interface PriorEntry {
  semanticId: string;
  locator: string;
  narrowFingerprint?: string;
  broadFingerprint?: string;
}

/**
 * Joins a prior adjudicated set against a current run on `semanticId`.
 *
 * Line deltas are computed as an OUTPUT for the record and are never a match criterion. A prior
 * entry that matches nothing is REMOVED and must be retired explicitly; it is never dropped.
 */
export function matchFindings(
  prior: PriorEntry[],
  current: Map<string, FindingRow>,
): MatchedFinding[] {
  const out: MatchedFinding[] = [];
  const priorById = new Map(prior.map((p) => [p.semanticId, p]));

  for (const [id, cur] of current) {
    const p = priorById.get(id);
    if (!p) {
      out.push({ semanticId: id, klass: "ADDED", current: cur });
      continue;
    }
    const priorInfo = { locator: p.locator, narrow: p.narrowFingerprint, broad: p.broadFingerprint };
    // A DEFINED narrow fingerprint that differs is the only evidence that proves the flagged
    // construct itself changed. Undefined on either side can never prove it.
    const narrowComparable = cur.narrow !== undefined && p.narrowFingerprint !== undefined;
    if (narrowComparable && cur.narrow !== p.narrowFingerprint) {
      out.push({ semanticId: id, klass: "SEMANTIC_CHANGE_PROVEN", current: cur, prior: priorInfo });
      continue;
    }
    if (cur.broad !== p.broadFingerprint) {
      out.push({
        semanticId: id,
        klass: "SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION",
        current: cur,
        prior: priorInfo,
      });
      continue;
    }
    out.push({
      semanticId: id,
      klass: cur.locator === p.locator ? "UNCHANGED" : "RELOCATED",
      current: cur,
      prior: priorInfo,
      lineDelta: cur.locator === p.locator ? undefined : locatorDelta(p.locator, cur.locator),
    });
  }

  for (const p of prior) {
    if (!current.has(p.semanticId)) {
      out.push({ semanticId: p.semanticId, klass: "REMOVED", prior: { locator: p.locator } });
    }
  }
  return out;
}

/**
 * Line deltas between two locators, RECORDED not used. Empty when the shapes differ.
 *
 * PAIRED NUMERICALLY WITHIN EACH FILE, never by the locator's own ordering. `canonicalLocator`
 * sorts its parts as STRINGS, so `…sol:983` sorts after `…sol:1001`; if those lines later become
 * 1116 and 1134 the string order flips and a positional subtraction pairs 1001 with 1116 and
 * reports a delta of 115 for a finding that moved uniformly by 133. Relocation preserves the order
 * of lines within a file, so numeric pairing per file is the correct correspondence.
 */
function locatorDelta(from: string, to: string): number[] {
  const byFile = (k: string): Map<string, number[]> => {
    const m = new Map<string, number[]>();
    for (const part of (k.split("|")[1] || "").split(",")) {
      const idx = part.lastIndexOf(":");
      if (idx < 0) continue;
      const file = part.slice(0, idx);
      const line = Number(part.slice(idx + 1));
      if (!Number.isFinite(line)) continue;
      m.set(file, [...(m.get(file) || []), line]);
    }
    for (const [file, lines] of m) m.set(file, lines.sort((x, y) => x - y));
    return m;
  };
  const a = byFile(from);
  const b = byFile(to);
  if (a.size !== b.size) return [];
  const out: number[] = [];
  for (const [file, aLines] of a) {
    const bLines = b.get(file);
    if (!bLines || bLines.length !== aLines.length) return [];
    for (let i = 0; i < aLines.length; i++) out.push(bLines[i] - aLines[i]);
  }
  return out;
}
