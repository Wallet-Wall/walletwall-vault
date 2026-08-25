/**
 * Runtime-byte claim collection — where the measurements and the declarations
 * actually come from.
 *
 * scripts/lib/runtime-byte-claims.ts decides; this module gathers. Split apart
 * because the decision logic must stay pure and directly unit-testable while
 * collection necessarily touches the filesystem.
 *
 * ── The authority ────────────────────────────────────────────────────────────
 * Measurements come from {measureRuntimeBytes} in scripts/validate-bytecode-size.ts —
 * the SAME primitive the EIP-170 ceiling gate resolves to. There is deliberately
 * no second bytecode parser in this repo: one artifact loader, one
 * {hexByteLength}, two consumers.
 *
 * ── The declarations ─────────────────────────────────────────────────────────
 * Three source kinds, all of which had drifted or could drift silently:
 *
 *   1. Reproducibility manifests (deployments/reproducibility/*.json).
 *      `publicHeadRuntimeBytes` is collected for EVERY manifest, not only the
 *      ones claiming `reproducible` — validate-reproducibility.ts nests its
 *      whole evidence replay inside `if (status === "reproducible")`, which is
 *      exactly why the remediation-gated WalletWallVault record could carry a
 *      stale number through two releases.
 *
 *   2. Evidence bundles (deployments/reproducibility/evidence/*.json).
 *      `publicHeadBuild.deployedBytecodeObject` is a checked-in COPY of solc
 *      output, read by the existing checker only for its `.length`. Binding it
 *      here is what kills the common-mode case: editing the manifest and the
 *      evidence together to the same wrong value used to pass every gate,
 *      because nothing compared either of them to a compiler. It also closes
 *      the toolchain-drift hole the staleness checker documents but does not
 *      cover — a solc/optimizer change alters the bytes with no source edit, so
 *      source-digest comparison cannot see it, but the compiler can.
 *
 *   3. Published prose (README.md, SECURITY.md, docs/Deployments.md). Four
 *      hand-maintained copies of the vault's size live here and no test read
 *      any of them.
 *
 * ── Completeness ─────────────────────────────────────────────────────────────
 * A registry of prose locators alone would only ever watch what someone
 * remembered to add, and the root cause of the defect is that someone forgot.
 * So {findUnregisteredProseClaims} sweeps every covered document for
 * byte-claim-shaped text and fails on any line no registered site (or parsed
 * table row) accounts for. Registered sites are LOCATORS only — the values
 * themselves are never hand-maintained here.
 *
 * ── Deliberately NOT bound ───────────────────────────────────────────────────
 * `reportedCommitRuntimeBytes` is the size recompiled from a pinned HISTORICAL
 * commit using ITS OWN lockfile and toolchain (Hardhat 2 / solc 0.8.24 for the
 * v0.4.24 records, versus today's Hardhat 3). Today's compiler has no standing
 * to adjudicate it, and forcing equality would be asserting something false.
 * It is already replayed against `deploymentCommitBuild` by
 * checkEvidenceAgainstManifest; that is the right authority for it.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import type { ClaimSlot, RuntimeByteDeclaration, RuntimeByteMeasurement } from "./runtime-byte-claims";
import { measureRuntimeBytes, TARGET_CONTRACTS, type ContractSizeTarget } from "../validate-bytecode-size";

/**
 * Reproducibility subjects that the EIP-170 target list does not already cover.
 * MockUSDC is a live Sepolia deployment with a published reproducibility record
 * but was absent from TARGET_CONTRACTS, so nothing measured it at all.
 */
export const ADDITIONAL_RUNTIME_BYTE_SUBJECTS: ContractSizeTarget[] = [
  {
    name: "MockUSDC",
    artifactRelPath: "mocks/MockUSDC.sol/MockUSDC.json",
    justification:
      "deployed on Sepolia (deployments/sepolia/stablecoin-vault-simulator.json) and carries a published " +
      "reproducibility record, so its runtime-byte claims must be checkable",
  },
];

/**
 * Every contract whose runtime size this repo may publish a claim about.
 * Spreads TARGET_CONTRACTS by reference so a shared contract can never acquire
 * two different artifact paths — see the "never diverges" test.
 */
export const RUNTIME_BYTE_SUBJECTS: ContractSizeTarget[] = [...TARGET_CONTRACTS, ...ADDITIONAL_RUNTIME_BYTE_SUBJECTS];

/** Documents that publish runtime-byte claims in prose and are swept for completeness. */
export const COVERED_PROSE_FILES = ["README.md", "SECURITY.md", "docs/Deployments.md"];

/**
 * What "a runtime-byte claim" looks like in MARKDOWN: a backticked number
 * immediately followed by `bytes`, or used as an `-byte` adjective. Every
 * runtime size in this repo's markdown is backticked, so the convention itself
 * does the discriminating and no magnitude threshold is needed — `569` is
 * caught as readily as `22,701`.
 */
export const MARKDOWN_BYTE_CLAIM = /`\d[\d,]*`(?:\s+bytes\b|-byte\b)/g;

/**
 * The same, for prose embedded in reproducibility-manifest JSON, where there is
 * no backtick convention to lean on. Discriminated by magnitude instead: a
 * runtime size is a whole-contract figure (EIP-170 caps it at 24,576 and every
 * subject with a published record compiles to at least 569 bytes), whereas the
 * byte counts these records legitimately carry in prose are solc CBOR
 * metadata-REGION accounting — "53 bytes total: a 2-byte length suffix plus a
 * 51-byte CBOR map", "32 bytes differ". Those size a sub-region of the
 * bytecode, not a contract, and are not the compiler's to adjudicate.
 *
 * KNOWN LIMIT: a runtime size below 1,000 bytes written into JSON prose would
 * not be swept. It would still be bound at the field level
 * (`publicHeadRuntimeBytes` is checked for every subject regardless of size),
 * and markdown — where the sub-1,000 claims actually live, e.g. MockMLDSAVerifier's
 * `569` — has no threshold at all.
 */
export const JSON_PROSE_BYTE_CLAIM = /\b(?:\d{1,3}(?:,\d{3})+|\d{4,})(?:\s+bytes\b|-byte\b)/g;

function byteClaimPatternFor(file: string): RegExp {
  return file.endsWith(".json") ? JSON_PROSE_BYTE_CLAIM : MARKDOWN_BYTE_CLAIM;
}

/** A markdown table column header that carries an on-chain (deployment) runtime size. */
const OBSERVED_LIVE_HEADER = /^(?:deployment\s+)?runtime bytes$/i;
/** A markdown table column header that carries the current public-HEAD compiled size. */
const PUBLIC_HEAD_HEADER = /^public[-\s]?head runtime bytes$/i;
const CONTRACT_HEADER = /^contract$/i;

export interface ProseClaimSite {
  /** Repo-relative file the claim lives in. Must be one of COVERED_PROSE_FILES. */
  file: string;
  subject: string;
  slot: ClaimSlot;
  /**
   * Must match exactly one LINE of the file; capture group 1 is the byte value.
   * A locator, never a value — the number itself is always the compiler's.
   */
  pattern: RegExp;
  /** Why this line carries this subject and slot. */
  note: string;
}

/**
 * Hand-registered prose locators. Only the LOCATION is maintained here; the
 * value is always compared against the compiler. Markdown tables that name
 * their own columns are parsed structurally instead (see parseRuntimeByteTables)
 * and need no entry.
 */
export const PROSE_CLAIM_SITES: ProseClaimSite[] = [
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /^\| Live Sepolia runtime observed \| `([\d,]+)` bytes \|$/,
    note: "active Sepolia deployment summary table, live-runtime row",
  },
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "public-head",
    pattern: /^\| Current public HEAD runtime \| `([\d,]+)` bytes \|$/,
    note: "active Sepolia deployment summary table, public-HEAD row",
  },
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /the observed live runtime is `([\d,]+)` bytes/,
    note: "read-only RPC confirmation paragraph",
  },
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "public-head",
    pattern: /public HEAD recompiles `WalletWallVault` to a `([\d,]+)`-byte$/,
    note: "deployment provenance paragraph, public-HEAD half",
  },
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /^runtime rather than the observed `([\d,]+)`-byte deployed runtime\.$/,
    note: "deployment provenance paragraph, observed half",
  },
  {
    file: "docs/Deployments.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /^`([\d,]+)`-byte runtime\), then set `reproducibilityStatus`/,
    note: "remediation runbook, path B",
  },
  {
    file: "README.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /Its observed runtime is `([\d,]+)` bytes, while current public HEAD$/,
    note: "deployment targets section, observed half",
  },
  {
    file: "README.md",
    subject: "WalletWallVault",
    slot: "public-head",
    pattern: /^recompiles to `([\d,]+)` bytes; exact deployment reproducibility/,
    note: "deployment targets section, public-HEAD half",
  },
  {
    file: "SECURITY.md",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /Its observed `([\d,]+)`-byte runtime is not reproducible from$/,
    note: "active Sepolia deployment paragraph, observed half",
  },
  {
    file: "SECURITY.md",
    subject: "WalletWallVault",
    slot: "public-head",
    pattern: /^current public HEAD, which recompiles to `([\d,]+)` bytes;/,
    note: "active Sepolia deployment paragraph, public-HEAD half",
  },
  // The manifest's own narrative fields. This record carries the number FOUR
  // times — the machine-readable field plus three sentences — and the sentences
  // are as public as the field. They are on one physical line each in the JSON,
  // and `rationale` states both sizes in a single string, which is why the
  // completeness sweep counts occurrences rather than lines.
  {
    file: "deployments/reproducibility/walletwall-vault-sepolia.json",
    subject: "WalletWallVault",
    slot: "public-head",
    pattern: /public HEAD recompiles WalletWallVault to a ([\d,]+)-byte runtime/,
    note: "remediation.rationale, public-HEAD half",
  },
  {
    file: "deployments/reproducibility/walletwall-vault-sepolia.json",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /runtime rather than the deployed ([\d,]+)-byte runtime/,
    note: "remediation.rationale, observed half",
  },
  {
    file: "deployments/reproducibility/walletwall-vault-sepolia.json",
    subject: "WalletWallVault",
    slot: "observed-live",
    pattern: /runtime bytecode keccak256 that reproduces the deployed ([\d,]+)-byte runtime/,
    note: "remediation.alternatePath",
  },
];

/** Parse a backticked, comma-grouped byte count. Returns null if the cell is not one. */
function parseByteCell(cell: string): number | null {
  const m = /^`(\d[\d,]*)`(?:\s+bytes)?$/.exec(cell.trim());
  if (!m) return null;
  const digits = m[1].replace(/,/g, "");
  const value = Number(digits);
  return Number.isInteger(value) ? value : null;
}

function splitRow(line: string): string[] {
  const cells = line.split("|").map((c) => c.trim());
  // "| a | b |" splits to ["", "a", "b", ""] — drop the outer empties.
  if (cells.length > 0 && cells[0] === "") cells.shift();
  if (cells.length > 0 && cells[cells.length - 1] === "") cells.pop();
  return cells;
}

function isSeparatorRow(line: string): boolean {
  return /^\|[\s|:-]+\|$/.test(line.trim());
}

export interface CollectionResult {
  declarations: RuntimeByteDeclaration[];
  errors: string[];
}

/**
 * Read runtime-byte claims out of any markdown table that NAMES a runtime-byte
 * column in its own header. Structural rather than hand-registered: the table
 * says which contract each row is about and which column holds the size, so a
 * new row is covered automatically and a new table is covered as soon as its
 * header uses a recognised column name.
 */
export function parseRuntimeByteTables(text: string, file: string): CollectionResult {
  const lines = text.split(/\r?\n/);
  const declarations: RuntimeByteDeclaration[] = [];
  const errors: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trimStart().startsWith("|")) continue;
    const header = splitRow(line);
    const byteCol = header.findIndex((h) => OBSERVED_LIVE_HEADER.test(h) || PUBLIC_HEAD_HEADER.test(h));
    if (byteCol === -1) continue;
    if (i + 1 >= lines.length || !isSeparatorRow(lines[i + 1])) continue;

    const slot: ClaimSlot = PUBLIC_HEAD_HEADER.test(header[byteCol]) ? "public-head" : "observed-live";
    const subjectCol = header.findIndex((h) => CONTRACT_HEADER.test(h));
    if (subjectCol === -1) {
      errors.push(
        `${file}:${i + 1}: table declares a "${header[byteCol]}" column but no "Contract" column — ` +
          `the runtime-byte claim cannot be attributed to a subject`,
      );
      continue;
    }

    for (let r = i + 2; r < lines.length; r++) {
      const row = lines[r];
      if (!row.trimStart().startsWith("|")) break;
      const cells = splitRow(row);
      if (cells.length <= Math.max(byteCol, subjectCol)) continue;
      const subject = cells[subjectCol].replace(/`/g, "").trim();
      const value = parseByteCell(cells[byteCol]);
      if (value === null) {
        errors.push(
          `${file}:${r + 1}: "${header[byteCol]}" cell for ${subject} is ${JSON.stringify(cells[byteCol])}, ` +
            `which is not a byte count`,
        );
        continue;
      }
      declarations.push({ location: `${file}:${r + 1}`, subject, slot, value });
    }
    i = i + 1;
  }

  return { declarations, errors };
}

/**
 * Resolve each registered prose site against the file's actual content.
 *
 * A site that matches no line fails: a locator whose sentence was reworded is
 * a guard that has silently stopped watching anything, which is strictly worse
 * than no guard because it still looks like coverage. A site matching several
 * lines fails for the mirror reason — an ambiguous locator proves nothing about
 * which claim was checked.
 */
export function extractProseDeclarations(text: string, file: string, sites: ProseClaimSite[]): CollectionResult {
  const lines = text.split(/\r?\n/);
  const declarations: RuntimeByteDeclaration[] = [];
  const errors: string[] = [];

  for (const site of sites) {
    if (site.file !== file) continue;
    const hits: Array<{ lineNo: number; raw: string }> = [];
    for (let i = 0; i < lines.length; i++) {
      const m = site.pattern.exec(lines[i]);
      if (m) hits.push({ lineNo: i + 1, raw: m[1] });
    }
    if (hits.length === 0) {
      errors.push(
        `${file}: registered runtime-byte claim site (${site.note}) matched no line — the text it watches was ` +
          `edited or moved; update the locator so the claim stays bound, do not delete the site`,
      );
      continue;
    }
    if (hits.length > 1) {
      errors.push(
        `${file}: registered runtime-byte claim site (${site.note}) matched ${hits.length} lines ` +
          `(${hits.map((h) => h.lineNo).join(", ")}) — an ambiguous locator cannot bind a specific claim`,
      );
      continue;
    }
    const value = Number(hits[0].raw.replace(/,/g, ""));
    declarations.push({
      location: `${file}:${hits[0].lineNo}`,
      subject: site.subject,
      slot: site.slot,
      value,
    });
  }

  return { declarations, errors };
}

/**
 * The completeness half. Every line in a covered document that LOOKS like a
 * runtime-byte claim must be accounted for — by a registered site or by a
 * structurally-parsed table row. Anything else is a published claim nothing
 * validates, which is precisely the state this gate exists to make unmergeable.
 */
export function findUnregisteredProseClaims(
  text: string,
  file: string,
  sites: ProseClaimSite[],
  coveredLocations: string[],
): string[] {
  const covered = new Set(coveredLocations);
  const applicable = sites.filter((s) => s.file === file);
  const pattern = byteClaimPatternFor(file);
  const errors: string[] = [];

  text.split(/\r?\n/).forEach((line, idx) => {
    // Count OCCURRENCES, not lines. JSON prose routinely puts several claims on
    // one physical line (walletwall-vault-sepolia.json's `rationale` states both
    // the public-HEAD and the observed-live size in a single string), so marking
    // the whole line "watched" as soon as one site matched would let every other
    // claim on it ride along unchecked.
    pattern.lastIndex = 0;
    const occurrences = line.match(pattern)?.length ?? 0;
    if (occurrences === 0) return;
    const watched = applicable.filter((s) => s.pattern.test(line)).length + (covered.has(`${file}:${idx + 1}`) ? 1 : 0);
    if (occurrences <= watched) return;
    errors.push(
      `${file}:${idx + 1}: ${occurrences - watched} unregistered runtime-byte claim(s) on this line ` +
        `(${occurrences} found, ${watched} bound) — ${JSON.stringify(line.trim().slice(0, 120))}. ` +
        `Every published byte count must be bound to a compiler measurement; add a PROSE_CLAIM_SITES entry ` +
        `(scripts/lib/runtime-byte-claim-sources.ts) naming its subject and slot.`,
    );
  });

  return errors;
}

const REPRO_SUBDIR = join("deployments", "reproducibility");

function listManifests(repoRoot: string): string[] {
  const dir = join(repoRoot, REPRO_SUBDIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(dir, f));
}

function listEvidenceBundles(repoRoot: string): string[] {
  const dir = join(repoRoot, REPRO_SUBDIR, "evidence");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(dir, f));
}

function toPosix(p: string): string {
  return p.split("\\").join("/");
}

export interface FullCollection {
  measurements: RuntimeByteMeasurement[];
  declarations: RuntimeByteDeclaration[];
  coverageRequired: string[];
  errors: string[];
}

/**
 * Gather every measurement and every declaration in the tree.
 *
 * `errors` here are COLLECTION failures (an artifact that will not load, a
 * locator that no longer matches, a published claim nothing watches) — distinct
 * from reconciliation failures, which are the reconciler's to report. Both are
 * fatal; separating them keeps "the guard is broken" legible from "the claim is
 * wrong".
 */
export function collectRuntimeByteClaims(repoRoot: string): FullCollection {
  const measurements: RuntimeByteMeasurement[] = [];
  const declarations: RuntimeByteDeclaration[] = [];
  const coverageRequired: string[] = [];
  const errors: string[] = [];

  for (const subject of RUNTIME_BYTE_SUBJECTS) {
    try {
      measurements.push({
        subject: subject.name,
        artifactRelPath: subject.artifactRelPath,
        runtimeBytes: measureRuntimeBytes(subject.artifactRelPath, subject.name),
      });
    } catch (err) {
      errors.push(`${subject.name}: ${(err as Error).message}`);
    }
  }

  // ── Reproducibility manifests — every record, not only "reproducible" ones ──
  for (const file of listManifests(repoRoot)) {
    const rel = toPosix(relative(repoRoot, file));
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    } catch (err) {
      errors.push(`${rel}: failed to parse: ${(err as Error).message}`);
      continue;
    }
    const subject = m["subject"];
    if (typeof subject !== "string" || subject.length === 0) {
      errors.push(`${rel}: no subject — a runtime-byte claim cannot be attributed`);
      continue;
    }
    coverageRequired.push(subject);
    const fields: Array<[string, ClaimSlot]> = [
      ["publicHeadRuntimeBytes", "public-head"],
      ["observedRuntimeBytes", "observed-live"],
    ];
    for (const [field, slot] of fields) {
      const value = m[field];
      if (value == null) continue;
      declarations.push({ location: `${rel}#${field}`, subject, slot, value: value as number });
    }

    // A manifest's NARRATIVE fields are as public as its machine-readable ones —
    // walletwall-vault-sepolia.json states the size three more times in
    // remediation.rationale and remediation.alternatePath, and those copies were
    // among the sites that had to be repaired by hand.
    const text = readFileSync(file, "utf8");
    const prose = extractProseDeclarations(text, rel, PROSE_CLAIM_SITES);
    errors.push(...prose.errors);
    declarations.push(...prose.declarations);
    errors.push(
      ...findUnregisteredProseClaims(
        text,
        rel,
        PROSE_CLAIM_SITES,
        prose.declarations.map((d) => d.location),
      ),
    );
  }

  // ── Evidence bundles — the checked-in copy of solc output ──────────────────
  for (const file of listEvidenceBundles(repoRoot)) {
    const rel = toPosix(relative(repoRoot, file));
    let e: { subject?: string; publicHeadBuild?: { deployedBytecodeObject?: string } };
    try {
      e = JSON.parse(readFileSync(file, "utf8"));
    } catch (err) {
      errors.push(`${rel}: failed to parse: ${(err as Error).message}`);
      continue;
    }
    const object = e.publicHeadBuild?.deployedBytecodeObject;
    if (typeof e.subject !== "string" || typeof object !== "string") continue;
    if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(object)) {
      errors.push(`${rel}#publicHeadBuild.deployedBytecodeObject: not a 0x-prefixed even-length hex string`);
      continue;
    }
    declarations.push({
      location: `${rel}#publicHeadBuild.deployedBytecodeObject`,
      subject: e.subject,
      slot: "public-head",
      value: (object.length - 2) / 2,
    });
  }

  // ── Published prose ────────────────────────────────────────────────────────
  for (const file of COVERED_PROSE_FILES) {
    const path = join(repoRoot, file);
    if (!existsSync(path)) {
      errors.push(`${file}: covered prose file is missing`);
      continue;
    }
    const text = readFileSync(path, "utf8");

    const tables = parseRuntimeByteTables(text, file);
    errors.push(...tables.errors);
    declarations.push(...tables.declarations);

    const prose = extractProseDeclarations(text, file, PROSE_CLAIM_SITES);
    errors.push(...prose.errors);
    declarations.push(...prose.declarations);

    errors.push(
      ...findUnregisteredProseClaims(text, file, PROSE_CLAIM_SITES, [
        ...tables.declarations.map((d) => d.location),
        ...prose.declarations.map((d) => d.location),
      ]),
    );
  }

  return { measurements, declarations, coverageRequired, errors };
}
