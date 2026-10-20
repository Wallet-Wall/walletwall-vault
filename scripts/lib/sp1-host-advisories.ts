/**
 * The zkvm/host RustSec advisory record (step 3 of the SP1 host-lockfile plan; docs/SP1_Host_Lockfile_Advisories.md).
 *
 * `cargo audit` reads a Cargo.lock, and a lockfile is not a build graph: it records every package some feature
 * combination could need, including optional crates that a weak dependency feature (`dep?/feature`) names while
 * nothing enables them. An advisory against a locked crate therefore says nothing yet about WalletWall. This module
 * turns what RustSec says into what was assessed and why, bound to the designated subject, and never calls a
 * dependency safe:
 *
 *   the OBSERVATION (scripts/measure-sp1-host-advisories.ts) records, for the four committed lockfiles, what cargo-audit
 *     reported against a named advisory-database commit (with --no-yanked), what the crates.io index says is yanked,
 *     what `cargo tree` says is compiled and which features are on, what `cargo update --dry-run` can reach, and what
 *     the pinned crates' own bytes contain (read from each .crate whose sha256 is the lockfile checksum);
 *   the CLAIMS below are the reviewed judgment: which measured evidence establishes which reachability for which
 *     advisory. A claim supports nothing unless every item it requires holds;
 *   the RECORD (evidence/zk/sp1-impl/host-lockfile-advisories.json) is derived from the observation, the claims and the
 *     repository, and validated by regenerating it byte for byte.
 *
 * Two verdicts, never one. ASSESSMENT_VALID says the record is what today's designated subject and evidence derive; it
 * never says a dependency is safe. The dependency status is derived on its own from the measured findings:
 * NOT_DEPENDENCY_SAFE while any RustSec vulnerability or unsoundness is locked, however it is classified. The owner
 * deferred every host lockfile change to the next program rebuild (HOST_LOCKFILE_REMEDIATION =
 * DEFER_TO_NEXT_PROGRAM_REBUILD), and nothing here patches anything.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DESIGNATIONS_DIR,
  latestDesignation,
  readDesignations,
  subjectFreshnessErrors,
  type ProgramDesignation,
} from "./sp1-designation";
import { exerciseRecordsIn } from "./sp1-proof-exercise";
import { PROVING_AVAILABILITY_REL, archiveRecordsIn } from "./sp1-proving-availability";

export const HOST_ADVISORIES_REL = "evidence/zk/sp1-impl/host-lockfile-advisories.json";
export const HOST_ADVISORIES_SCHEMA = "walletwall.sp1-host-lockfile-advisories.v1";
export const ADVISORY_OBSERVATION_REL =
  "evidence/zk/sp1-impl/observations/host-advisories-developer-workstation.raw.json";
export const ADVISORY_OBSERVATION_SCHEMA = "walletwall.rust-lockfile-advisories-observation.v1";
export const MEASURE_ADVISORIES_SCRIPT_REL = "scripts/measure-sp1-host-advisories.ts";
export const ADVISORIES_DOC_REL = "docs/SP1_Host_Lockfile_Advisories.md";
/** The cargo-audit release every measurement must use; the networked workflow installs exactly this one. */
export const CARGO_AUDIT_VERSION = "0.22.2";
export const CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";
export const SPARSE_INDEX_BASE = "https://index.crates.io/";
export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
const HOST_DIR = "zkvm/host";

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

// ---------------------------------------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------------------------------------

export type LockfileId = "host" | "guest" | "relation-tests" | "evidence-validator";
export type LockfileRole = "DESIGNATED_SUBJECT" | "CI_TEST_HARNESS" | "OFFLINE_TOOLING";
export interface LockfileSpec {
  id: LockfileId;
  dir: string;
  /** The crate at the root of `cargo tree` in that directory. */
  root: string;
  role: LockfileRole;
}
/** Every committed Rust lockfile; host first. The guest's is part of designation d1's subject, like the host tree. */
export const LOCKFILES: readonly LockfileSpec[] = [
  { id: "host", dir: "zkvm/host", root: "mldsa65-host", role: "DESIGNATED_SUBJECT" },
  { id: "guest", dir: "zkvm/guest", root: "mldsa65-guest", role: "DESIGNATED_SUBJECT" },
  { id: "relation-tests", dir: "zkvm/relation-tests", root: "mldsa65-relation-tests", role: "CI_TEST_HARNESS" },
  { id: "evidence-validator", dir: "zkvm/evidence-validator", root: "evidence-validator", role: "OFFLINE_TOOLING" },
];
export const lockPathOf = (l: LockfileSpec) => `${l.dir}/Cargo.lock`;

/** RustSec's kinds: a vulnerability, the informational unsound/unmaintained/notice warnings, and a yanked release. */
export const KINDS = ["vulnerability", "unsound", "yanked", "unmaintained", "notice"] as const;
export type Kind = (typeof KINDS)[number];

/**
 * How a finding meets WalletWall's path. NOT_COMPILED and NO_KNOWN_DEFECT are read from measurements alone; the other
 * three are judgments, and PRECONDITION_ABSENT / CONDITIONAL hold only while every item of evidence their claim
 * requires holds. UNASSESSED (no claim) and UNSUPPORTED (a claim whose evidence fails) are never valid in a record.
 */
export const REACHABILITY = [
  "NOT_COMPILED",
  "NO_KNOWN_DEFECT",
  "PRECONDITION_ABSENT",
  "CONDITIONAL",
  "REACHABLE",
] as const;
export type AssessedReachability = (typeof REACHABILITY)[number];
export type Reachability = AssessedReachability | "UNASSESSED" | "UNSUPPORTED";

export const BUCKETS = [
  "MUST_FIX_BEFORE_REAL_PROVING",
  "SHOULD_FIX_BEFORE_PRODUCTION",
  "NOT_REACHABLE_OR_UPSTREAM_ONLY",
] as const;
export type Bucket = (typeof BUCKETS)[number] | "UNASSESSED";

export type DependencyStatus = "NOT_DEPENDENCY_SAFE" | "DEPENDENCY_SAFE" | "UNKNOWN";
export type AssessmentStatus = "ASSESSMENT_VALID" | "REASSESSMENT_REQUIRED" | "RECORD_INVALID";

export const DISPOSITION_DEFERRED = "DEFERRED_TO_NEXT_PROGRAM_REBUILD";
const DISPOSITION_TEST_HARNESS = "UNCHANGED_TEST_HARNESS_NOT_SHIPPED";
const DISPOSITION_TOOLING = "UNCHANGED_OFFLINE_TOOLING";

/** The owner's decision this record serves; any other value is not a decision this repository has recorded. */
export const OWNER_DECISION = {
  HOST_LOCKFILE_REMEDIATION: "DEFER_TO_NEXT_PROGRAM_REBUILD",
  designation: "mldsa65-withdrawal-d1",
  decidedOn: "2026-10-16",
  scope:
    "zkvm/host/Cargo.lock under designation mldsa65-withdrawal-d1: no host dependency is updated and d1 is kept; the compatible dependency refresh waits for the next actual program rebuild",
  premise: { mustFixBeforeRealProving: 0 },
  source:
    "owner decision after the read-only zkvm/host RustSec assessment of 2026-10-16 (after PR #219): defer the host lockfile updates to the next program rebuild and keep d1 and the lockfile as they are",
} as const;

export interface Issue {
  code: string;
  /** stale: the subject or its evidence moved, reassess; invalid: the record or catalog is wrong as it stands. */
  class: "stale" | "invalid";
  message: string;
}
const stale = (code: string, message: string): Issue => ({ code, class: "stale", message });
const invalid = (code: string, message: string): Issue => ({ code, class: "invalid", message });

// ---------------------------------------------------------------------------------------------------------
// Parsing: Cargo.lock, a simple Cargo.toml, Rust comments, cargo outputs, versions
// ---------------------------------------------------------------------------------------------------------

export interface LockPackage {
  name: string;
  version: string;
  source: string | null;
  checksum: string | null;
  /** As Cargo writes them: "name", or "name version" when the lockfile pins more than one version of name. */
  dependencies: string[];
}

export function parseCargoLock(text: string): LockPackage[] {
  const out: LockPackage[] = [];
  for (const block of text.split(/^\[\[package\]\]\r?$/m).slice(1)) {
    const field = (k: string) => new RegExp(`^${k} = "([^"]*)"\\r?$`, "m").exec(block)?.[1] ?? null;
    const name = field("name");
    const version = field("version");
    if (!name || !version) throw new Error("a [[package]] of the lockfile has no name or version");
    const deps = /^dependencies = \[\r?\n([\s\S]*?)^\]\r?$/m.exec(block);
    const dependencies = deps ? [...deps[1].matchAll(/^ "([^"]+)",\r?$/gm)].map((m) => m[1]) : [];
    out.push({ name, version, source: field("source"), checksum: field("checksum"), dependencies });
  }
  if (out.length === 0) throw new Error("not a Cargo.lock: it has no [[package]]");
  return out;
}

export const specOf = (crate: string, version: string) => `${crate}@${version}`;
export const isPinned = (lock: readonly LockPackage[], crate: string, version: string) =>
  lock.some((p) => p.name === crate && p.version === version);
export const registryPackages = (lock: readonly LockPackage[]) => lock.filter((p) => p.source === CRATES_IO_SOURCE);

/** The single locked version of `crate`, or null when the lockfile pins none or several. */
export function onlyVersion(lock: readonly LockPackage[], crate: string): LockPackage | null {
  const found = lock.filter((p) => p.name === crate);
  return found.length === 1 ? found[0] : null;
}

/** The packages whose locked dependencies name `crate@version`, as name@version, sorted. */
export function directDependents(lock: readonly LockPackage[], crate: string, version: string): string[] {
  const versions = lock.filter((p) => p.name === crate).map((p) => p.version);
  return lock
    .filter((p) =>
      p.dependencies.some((d) => {
        const [n, v] = d.split(" ");
        return n === crate && (v === undefined ? versions.length === 1 && versions[0] === version : v === version);
      }),
    )
    .map((p) => specOf(p.name, p.version))
    .sort();
}

export type TomlValue = string | boolean | string[] | { [key: string]: string | boolean | string[] };
export interface SimpleManifest {
  /** Every table header in order, `[[bin]]` spelled with its brackets. */
  headers: string[];
  entries: Record<string, Record<string, TomlValue>>;
}

function splitTopLevel(s: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quoted = false;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === "\\") i++;
      else if (c === '"') quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
    else if (c === sep && depth === 0) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts.map((p) => p.trim()).filter((p) => p !== "");
}

function tomlScalar(raw: string): string | boolean | string[] {
  const s = raw.trim();
  const str = /^"((?:[^"\\]|\\.)*)"$/.exec(s);
  if (str) return str[1];
  if (s === "true" || s === "false") return s === "true";
  if (s.startsWith("[") && s.endsWith("]")) {
    return splitTopLevel(s.slice(1, -1), ",").map((item) => {
      const v = tomlScalar(item);
      if (typeof v !== "string") throw new Error(`an array value the assessment does not read: ${raw}`);
      return v;
    });
  }
  throw new Error(`a value the assessment does not read: ${raw}`);
}

/** The subset of TOML zkvm/host/Cargo.toml is written in; anything else is refused, never guessed at. */
export function parseSimpleManifest(text: string): SimpleManifest {
  const headers: string[] = [];
  const entries: Record<string, Record<string, TomlValue>> = {};
  let table = "";
  for (const rawLine of text.split(/\r?\n/)) {
    let line = "";
    let quoted = false;
    for (let i = 0; i < rawLine.length; i++) {
      const c = rawLine[i];
      if (quoted && c === "\\") {
        line += c + (rawLine[i + 1] ?? "");
        i++;
        continue;
      }
      if (c === '"') quoted = !quoted;
      if (c === "#" && !quoted) break;
      line += c;
    }
    line = line.trim();
    if (line === "") continue;
    const header = /^(\[\[?)([A-Za-z0-9_.-]+)(\]\]?)$/.exec(line);
    if (header) {
      if (header[1].length !== header[3].length) throw new Error(`a malformed table header: ${line}`);
      table = header[1] === "[[" ? `[[${header[2]}]]` : header[2];
      headers.push(table);
      entries[table] ??= {};
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+|"[^"]+")\s*=\s*(.+)$/.exec(line);
    if (!kv || table === "") throw new Error(`a line the assessment does not read: ${line}`);
    const key = kv[1].replace(/^"|"$/g, "");
    const value = kv[2].trim();
    let parsed: TomlValue;
    if (value.startsWith("{")) {
      if (!value.endsWith("}")) throw new Error(`an inline table spanning lines: ${line}`);
      const inline: { [key: string]: string | boolean | string[] } = {};
      for (const pair of splitTopLevel(value.slice(1, -1), ",")) {
        const m = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(pair);
        if (!m) throw new Error(`an inline table entry the assessment does not read: ${pair}`);
        inline[m[1]] = tomlScalar(m[2]);
      }
      parsed = inline;
    } else {
      if (value.startsWith("[") && !value.endsWith("]")) throw new Error(`an array spanning lines: ${line}`);
      parsed = tomlScalar(value);
    }
    if (key in entries[table]) throw new Error(`${key} is set twice in [${table}]`);
    entries[table][key] = parsed;
  }
  return { headers, entries };
}

/** Rust source with its line and (nested) block comments removed; string and char literals are kept intact. */
export function stripRustComments(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && n === "*") {
      let depth = 1;
      i += 2;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (src[i] === "*" && src[i + 1] === "/") {
          depth--;
          i += 2;
        } else i++;
      }
      continue;
    }
    const raw = c === "r" && !/[A-Za-z0-9_]/.test(src[i - 1] ?? "") ? /^r(#*)"/.exec(src.slice(i, i + 64)) : null;
    if (raw) {
      const close = `"${raw[1]}`;
      const end = src.indexOf(close, i + raw[0].length);
      const stop = end < 0 ? src.length : end + close.length;
      out += src.slice(i, stop);
      i = stop;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === "'") {
      const ch = /^'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|.)|[^\\'])'/.exec(src.slice(i, i + 16));
      if (ch) {
        out += ch[0];
        i += ch[0].length;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

export type TreeRole = "NOT_COMPILED" | "PROC_MACRO" | "PROC_MACRO_ONLY" | "LINKED";
export interface TreeFacts {
  compiled: boolean;
  /** PROC_MACRO_ONLY: every direct dependent is a proc-macro. LINKED is everything else, conservatively. */
  role: TreeRole;
  directDependents: string[];
  /** The first chain from the crate to the root, as `cargo tree -i` prints it first. */
  pathToRoot: string[];
}

/** The facts of an inverted, depth-prefixed `cargo tree` output; empty output means no build graph contains the crate. */
export function treeFactsOf(output: string, crate: string, version: string, root: string): TreeFacts {
  const lines = output.split(/\r?\n/).filter((l) => l.trim() !== "");
  if (lines.length === 0) return { compiled: false, role: "NOT_COMPILED", directDependents: [], pathToRoot: [] };
  const nodes = lines.map((l) => {
    const m = /^(\d+)([A-Za-z0-9_][A-Za-z0-9_-]*) v(\S+)(.*)$/.exec(l);
    if (!m) throw new Error(`not a depth-prefixed cargo tree line: ${l}`);
    return { depth: Number(m[1]), name: m[2], version: m[3], procMacro: /\(proc-macro\)/.test(m[4]) };
  });
  const head = nodes[0];
  if (head.depth !== 0 || head.name !== crate || head.version !== version) {
    throw new Error(`not the inverted tree of ${specOf(crate, version)}`);
  }
  const first = nodes.filter((n) => n.depth === 1);
  const role: TreeRole = head.procMacro
    ? "PROC_MACRO"
    : first.length > 0 && first.every((n) => n.procMacro)
      ? "PROC_MACRO_ONLY"
      : "LINKED";
  const pathToRoot = [specOf(head.name, head.version)];
  for (let i = 1; i < nodes.length && nodes[i].depth === i; i++) {
    pathToRoot.push(specOf(nodes[i].name, nodes[i].version));
    if (nodes[i].name === root) {
      return {
        compiled: true,
        role,
        directDependents: [...new Set(first.map((n) => specOf(n.name, n.version)))].sort(),
        pathToRoot,
      };
    }
  }
  throw new Error(`the first branch of ${specOf(crate, version)}'s tree does not reach ${root}`);
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The features of `crate@version` that an inverted, depth-prefixed `cargo tree -e features` output shows enabled. */
export function featuresOf(output: string, crate: string, version: string): string[] {
  const lines = output.split(/\r?\n/).filter((l) => l.trim() !== "");
  const head = `0${crate} v${version}`;
  if (lines[0] !== head && !lines[0]?.startsWith(`${head} `)) {
    throw new Error(`not the inverted feature tree of ${specOf(crate, version)}`);
  }
  const re = new RegExp(`^\\d+${escapeRe(crate)} feature "([^"]+)"`);
  return [...new Set(lines.flatMap((l) => re.exec(l)?.[1] ?? []))].sort();
}

/** The version `cargo update --dry-run -p crate@version` would move to (null: it stays). */
export function updateProbeOf(output: string, crate: string, version: string): { to: string | null } {
  if (/^error/m.test(output)) throw new Error(`the update probe of ${specOf(crate, version)} failed`);
  if (!output.includes("not updating lockfile due to dry run")) {
    throw new Error(`not a dry-run update probe of ${specOf(crate, version)}`);
  }
  const m = new RegExp(`^\\s*Updating ${escapeRe(crate)} v${escapeRe(version)} -> v(\\S+)\\s*$`, "m").exec(output);
  return { to: m?.[1] ?? null };
}

export type PreciseProbe = { blocked: true; requirement: string; requiredBy: string } | { blocked: false; to: string };

/** Whether `cargo update --dry-run -p crate@version --precise <v>` was refused by a dependent's requirement. */
export function preciseProbeOf(output: string, crate: string, version: string): PreciseProbe {
  const req = /failed to select a version for the requirement `([^`]+)`/.exec(output);
  const by = /required by package `([^`]+)`/.exec(output);
  if (req && by) return { blocked: true, requirement: req[1], requiredBy: by[1] };
  const up = new RegExp(`^\\s*Updating ${escapeRe(crate)} v${escapeRe(version)} -> v(\\S+)\\s*$`, "m").exec(output);
  if (up) return { blocked: false, to: up[1] };
  throw new Error(`the precise probe of ${specOf(crate, version)} neither updated nor named a blocking requirement`);
}

interface SemVer {
  major: number;
  minor: number;
  patch: number;
  pre: string[];
  parts: number;
}
function parseVersion(v: string): SemVer {
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(v.trim());
  if (!m) throw new Error(`not a version: ${v}`);
  return {
    major: Number(m[1]),
    minor: Number(m[2] ?? 0),
    patch: Number(m[3] ?? 0),
    pre: m[4] ? m[4].split(".") : [],
    parts: m[3] !== undefined ? 3 : m[2] !== undefined ? 2 : 1,
  };
}
export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a);
  const y = parseVersion(b);
  for (const k of ["major", "minor", "patch"] as const) if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  if (x.pre.length === 0 || y.pre.length === 0) return x.pre.length === y.pre.length ? 0 : x.pre.length === 0 ? 1 : -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined || q === undefined) return p === undefined ? -1 : 1;
    if (p === q) continue;
    const np = /^\d+$/.test(p);
    const nq = /^\d+$/.test(q);
    if (np && nq) return Number(p) < Number(q) ? -1 : 1;
    if (np !== nq) return np ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return 0;
}
function comparator(c: string): { op: string; bound: string } {
  const m = /^(>=|<=|>|<|=|\^|~)?\s*(\d[0-9A-Za-z.+-]*)$/.exec(c.trim());
  if (!m) throw new Error(`a version requirement this check does not read: ${c}`);
  return { op: m[1] ?? "^", bound: m[2] };
}
function upperOf(op: "^" | "~", bound: string): string {
  const v = parseVersion(bound);
  if (op === "~") return v.parts === 1 ? `${v.major + 1}.0.0` : `${v.major}.${v.minor + 1}.0`;
  if (v.major > 0 || v.parts === 1) return `${v.major + 1}.0.0`;
  if (v.minor > 0 || v.parts === 2) return `0.${v.minor + 1}.0`;
  return `0.0.${v.patch + 1}`;
}
/** Whether `version` meets a RustSec/Cargo requirement such as ">=0.4.16", "^0.9.1" or ">= 1.2, < 1.5". */
export function satisfies(version: string, requirement: string): boolean {
  return requirement.split(",").every((c) => {
    const { op, bound } = comparator(c);
    const cmp = compareVersions(version, bound);
    switch (op) {
      case ">=":
        return cmp >= 0;
      case ">":
        return cmp > 0;
      case "<=":
        return cmp <= 0;
      case "<":
        return cmp < 0;
      case "=":
        return cmp === 0;
      default:
        return cmp >= 0 && compareVersions(version, upperOf(op as "^" | "~", bound)) < 0;
    }
  });
}
/** The lowest version a patched-range list admits (its lower bounds), for a --precise probe. */
export function minimalPatchedVersion(patched: readonly string[]): string {
  const lows = patched.flatMap((r) =>
    r
      .split(",")
      .map(comparator)
      .filter((c) => c.op !== "<" && c.op !== "<=" && c.op !== ">")
      .map((c) => c.bound),
  );
  if (lows.length === 0) throw new Error(`no lower bound in the patched ranges ${JSON.stringify(patched)}`);
  return lows.sort(compareVersions)[0];
}

// ---------------------------------------------------------------------------------------------------------
// cargo-audit reports
// ---------------------------------------------------------------------------------------------------------

export interface AdvisoryProjection {
  title: string;
  date: string;
  categories: string[];
  cvss: string | null;
  informational: string | null;
  withdrawn: string | null;
  patched: string[];
  unaffected: string[];
  /** The affected functions RustSec lists, when it lists any. */
  functions: Record<string, string[]> | null;
  url: string | null;
}

export interface MeasuredFinding {
  lockfile: LockfileId;
  kind: Kind;
  id: string | null;
  crate: string;
  version: string;
  advisory: AdvisoryProjection | null;
}

/** The finding's identity within its lockfile: an advisory id names one crate, and a crate may be locked twice. */
export const keyOf = (f: { id: string | null; crate: string; version: string }) =>
  `${f.id ?? "yanked"} ${specOf(f.crate, f.version)}`;

const KIND_ORDER = new Map<string, number>(KINDS.map((k, i) => [k, i]));
function byFinding(a: MeasuredFinding, b: MeasuredFinding): number {
  return (
    (KIND_ORDER.get(a.kind) ?? 9) - (KIND_ORDER.get(b.kind) ?? 9) ||
    a.crate.localeCompare(b.crate) ||
    compareVersions(a.version, b.version) ||
    String(a.id).localeCompare(String(b.id))
  );
}

const strings = (x: unknown): string[] => (Array.isArray(x) ? x.map(String) : []);
const stringOrNull = (x: unknown): string | null => (typeof x === "string" ? x : null);

function projectAdvisory(item: Record<string, any>): AdvisoryProjection {
  const a = item.advisory as Record<string, any>;
  const fns = item.affected?.functions;
  const functions =
    fns && typeof fns === "object" && Object.keys(fns).length > 0
      ? Object.fromEntries(
          Object.keys(fns)
            .sort()
            .map((k) => [k, strings(fns[k])]),
        )
      : null;
  return {
    title: String(a.title),
    date: String(a.date),
    categories: strings(a.categories),
    cvss: stringOrNull(a.cvss),
    informational: stringOrNull(a.informational),
    withdrawn: stringOrNull(a.withdrawn),
    patched: strings(item.versions?.patched),
    unaffected: strings(item.versions?.unaffected),
    functions,
    url: stringOrNull(a.url),
  };
}

/**
 * The findings of one `cargo audit --json --no-yanked` report; anything not shaped like one is refused. With the
 * lockfile it audited (`lock`), the report is also held to that lockfile's packages; without it (a companion lockfile
 * that changed since), the report stands on its own and the networked check judges the new lockfile.
 */
export function auditFindingsOf(
  report: unknown,
  lockfile: LockfileId,
  lock: readonly LockPackage[] | null,
): MeasuredFinding[] {
  const fail = (what: string): never => {
    throw new Error(`the cargo-audit report for ${lockfile} ${what}`);
  };
  const r = report as Record<string, any> | null;
  if (!r || typeof r !== "object" || Array.isArray(r)) fail("is not an object");
  // With --no-fetch cargo-audit reports no commit (null); the observation names the checkout's commit instead.
  const db = (r as Record<string, any>).database;
  const commit = db?.["last-commit"];
  if (!(commit === null || /^[0-9a-f]{40}$/.test(String(commit))) || !Number.isInteger(db?.["advisory-count"])) {
    fail("has no advisory-database identity");
  }
  if (!(db["advisory-count"] > 0)) fail("was made against an empty advisory database");
  const rr = r as Record<string, any>;
  if (
    !Number.isInteger(rr.lockfile?.["dependency-count"]) ||
    (lock && rr.lockfile["dependency-count"] !== lock.length)
  ) {
    fail(`counts ${String(rr.lockfile?.["dependency-count"])} packages, while the lockfile pins ${lock?.length}`);
  }
  const v = rr.vulnerabilities;
  if (!Array.isArray(v?.list) || v.count !== v.list.length || v.found !== v.list.length > 0) {
    fail("has an inconsistent vulnerability list");
  }
  if (!rr.warnings || typeof rr.warnings !== "object" || Array.isArray(rr.warnings)) fail("has no warnings map");
  const out: MeasuredFinding[] = [];
  const add = (kind: Kind, item: Record<string, any>) => {
    const crate = item?.package?.name;
    const version = item?.package?.version;
    if (typeof crate !== "string" || typeof version !== "string") fail("names a finding without a package");
    if (lock && !isPinned(lock, crate, version))
      fail(`names ${specOf(crate, version)}, which the lockfile does not pin`);
    const id = item.advisory?.id;
    if (typeof id !== "string" || !/^RUSTSEC-\d{4}-\d{4}$/.test(id)) fail(`names ${crate} without a RustSec id`);
    if (item.advisory.package !== crate) fail(`attributes ${id} to ${crate}, but it is ${item.advisory.package}'s`);
    const informational = item.advisory.informational ?? null;
    if (
      (kind === "vulnerability") !== (informational === null) ||
      (kind !== "vulnerability" && informational !== kind)
    ) {
      fail(`lists ${id} as ${kind} while RustSec marks it ${String(informational)}`);
    }
    if (item.advisory.withdrawn) fail(`lists the withdrawn advisory ${id}`);
    out.push({ lockfile, kind, id, crate, version, advisory: projectAdvisory(item) });
  };
  for (const item of v.list) add("vulnerability", item);
  for (const [k, items] of Object.entries(rr.warnings as Record<string, unknown>)) {
    if (k === "yanked")
      fail("checked yanked crates: run cargo audit --no-yanked, yanked status is read from the index");
    if (!(k === "unsound" || k === "unmaintained" || k === "notice") || !Array.isArray(items)) {
      fail(`has an unknown warning kind ${k}`);
    }
    for (const item of items as Record<string, any>[]) {
      if (item?.kind !== k) fail(`files a ${String(item?.kind)} warning under ${k}`);
      add(k as Kind, item);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// The crates.io sparse index (yanked status)
// ---------------------------------------------------------------------------------------------------------

/** Where the sparse index keeps a crate's entries (https://doc.rust-lang.org/cargo/reference/registry-index.html). */
export function sparseIndexPath(name: string): string {
  const n = name.toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(n)) throw new Error(`not a crate name: ${name}`);
  if (n.length <= 2) return `${n.length}/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

/** A sparse-index file's versions of `name`: one JSON object per line, each with its checksum and yanked flag. */
export function indexEntriesOf(text: string, name: string): Map<string, { cksum: string; yanked: boolean }> {
  const out = new Map<string, { cksum: string; yanked: boolean }>();
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const e = JSON.parse(line) as Record<string, unknown>;
    if (String(e.name).toLowerCase() !== name.toLowerCase() || typeof e.vers !== "string") {
      throw new Error(`the index file of ${name} has an entry for ${String(e.name)}`);
    }
    if (typeof e.cksum !== "string" || !/^[0-9a-f]{64}$/.test(e.cksum) || typeof e.yanked !== "boolean") {
      throw new Error(`the index entry of ${specOf(name, e.vers)} has no checksum or yanked flag`);
    }
    out.set(e.vers, { cksum: e.cksum, yanked: e.yanked });
  }
  return out;
}

/** The locked packages the index marks yanked; a package the index does not list, or lists with another checksum, fails. */
export function yankedPackages(
  locked: readonly LockPackage[],
  index: ReadonlyMap<string, ReadonlyMap<string, { cksum: string; yanked: boolean }>>,
): { crate: string; version: string }[] {
  const out: { crate: string; version: string }[] = [];
  for (const p of registryPackages(locked)) {
    const entry = index.get(p.name)?.get(p.version);
    if (!entry)
      throw new Error(`the crates.io index does not list ${specOf(p.name, p.version)}: yanked status unmeasured`);
    if (entry.cksum !== p.checksum) {
      throw new Error(`the crates.io index lists ${specOf(p.name, p.version)} with another checksum than the lockfile`);
    }
    if (entry.yanked) out.push({ crate: p.name, version: p.version });
  }
  return out.sort((a, b) => specOf(a.crate, a.version).localeCompare(specOf(b.crate, b.version)));
}

/** Absolute temporary paths in a cargo output become repository-relative ones; any absolute path left fails. */
export function normalizeCargoOutput(text: string, root: string): string {
  let out = text.split("\r\n").join("\n");
  for (const v of new Set([root, root.split("\\").join("/"), root.split("/").join("\\")])) {
    out = out.split(`${v}\\`).join("").split(`${v}/`).join("");
  }
  out = out.replace(/\((zkvm[\\/][^()\n]*)\)/g, (_m, p: string) => `(${p.split("\\").join("/")})`);
  if (/[A-Za-z]:\\|\(\/(?:home|tmp|Users|runner|var)\//.test(out)) {
    throw new Error("a cargo output still names an absolute path after normalization");
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// The evidence catalog: assumptions over repository bytes, feature facts and source facts from the observation
// ---------------------------------------------------------------------------------------------------------

export interface AssumptionInput {
  hostManifestText: string | null;
  hostMainText: string | null;
  hostLock: readonly LockPackage[];
  provingAvailability: unknown;
  archiveRecords: readonly string[];
  /** The files under evidence/zk/sp1-impl/proof-exercises (SP1-PA3A); the availability record must account for them. */
  exerciseRecords: readonly string[];
}
export interface EvidenceResult {
  holds: boolean;
  observed: string;
}
export interface Assumption {
  id: string;
  statement: string;
  evaluate(input: AssumptionInput): EvidenceResult;
}

const HOST_DEPENDENCIES = ["anyhow", "hex", "serde", "serde_json", "sp1-sdk"];
const HOST_TABLES = ["package", "[[bin]]", "dependencies", "build-dependencies"];
/** Crates only sp1-sdk 6.3.1's `network` feature adds to a graph (its other network dependencies are locked anyway). */
export const NETWORK_ONLY_CRATES = [
  "alloy-signer",
  "alloy-signer-aws",
  "alloy-signer-local",
  "aws-config",
  "aws-sdk-kms",
  "backoff",
  "reqwest-middleware",
  "twirp",
  "zstd",
];

function manifestOf(input: AssumptionInput): SimpleManifest | string {
  if (input.hostManifestText === null) return "zkvm/host/Cargo.toml is missing";
  try {
    return parseSimpleManifest(input.hostManifestText);
  } catch (error) {
    return `zkvm/host/Cargo.toml is not in the form this assessment read: ${(error as Error).message}`;
  }
}
const absentCrates = (lock: readonly LockPackage[], names: readonly string[]): EvidenceResult => {
  const present = names.filter((n) => lock.some((p) => p.name === n));
  return {
    holds: present.length === 0,
    observed: present.length === 0 ? `none of ${names.join(", ")} is locked` : `locked: ${present.join(", ")}`,
  };
};

export const ASSUMPTIONS: readonly Assumption[] = [
  {
    id: "A_HOST_MANIFEST",
    statement:
      "zkvm/host/Cargo.toml has only [package], [[bin]], [dependencies] (sp1-sdk, serde, serde_json, hex, anyhow) and [build-dependencies] (sp1-build): no [features], [target.*], [patch], [replace], [workspace] or [profile] table",
    evaluate(input) {
      const m = manifestOf(input);
      if (typeof m === "string") return { holds: false, observed: m };
      const deps = Object.keys(m.entries.dependencies ?? {}).sort();
      const build = Object.keys(m.entries["build-dependencies"] ?? {}).sort();
      const holds =
        JSON.stringify(m.headers) === JSON.stringify(HOST_TABLES) &&
        JSON.stringify(deps) === JSON.stringify(HOST_DEPENDENCIES) &&
        JSON.stringify(build) === JSON.stringify(["sp1-build"]);
      return {
        holds,
        observed: `tables ${m.headers.join(", ")}; dependencies ${deps.join(", ")}; build-dependencies ${build.join(", ")}`,
      };
    },
  },
  {
    id: "A_SP1_SDK_FEATURES",
    statement:
      'sp1-sdk is required as "=6.3.1" with features ["blocking"] and its default features, and sp1-build as "=6.3.1": the network, cuda and native-gnark features are not requested',
    evaluate(input) {
      const m = manifestOf(input);
      if (typeof m === "string") return { holds: false, observed: m };
      const sdk = m.entries.dependencies?.["sp1-sdk"];
      const build = m.entries["build-dependencies"]?.["sp1-build"];
      const holds =
        typeof sdk === "object" &&
        !Array.isArray(sdk) &&
        JSON.stringify(Object.keys(sdk).sort()) === JSON.stringify(["features", "version"]) &&
        sdk.version === "=6.3.1" &&
        JSON.stringify(sdk.features) === JSON.stringify(["blocking"]) &&
        build === "=6.3.1";
      return { holds, observed: `sp1-sdk = ${JSON.stringify(sdk)}; sp1-build = ${JSON.stringify(build)}` };
    },
  },
  {
    id: "A_LOCK_NO_NETWORK_CRATES",
    statement: `zkvm/host/Cargo.lock pins none of the crates only sp1-sdk's network feature adds (${NETWORK_ONLY_CRATES.join(", ")})`,
    evaluate: (input) => absentCrates(input.hostLock, NETWORK_ONLY_CRATES),
  },
  {
    id: "A_LOCK_NO_CUDA",
    statement: "zkvm/host/Cargo.lock pins no sp1-cuda: the CUDA prover is not compiled",
    evaluate: (input) => absentCrates(input.hostLock, ["sp1-cuda"]),
  },
  {
    id: "A_LOCK_NO_AWS_LC",
    statement: "zkvm/host/Cargo.lock pins no aws-lc-rs or aws-lc-sys: ring is the only rustls crypto provider",
    evaluate: (input) => absentCrates(input.hostLock, ["aws-lc-rs", "aws-lc-sys"]),
  },
  {
    id: "A_LOCK_NO_BROTLI",
    statement: "zkvm/host/Cargo.lock pins no brotli or brotli-decompressor: rustls's brotli feature cannot be on",
    evaluate: (input) => absentCrates(input.hostLock, ["brotli", "brotli-decompressor"]),
  },
  {
    id: "A_LOCK_BACKTRACE_WITHOUT_RUZSTD",
    statement:
      "in zkvm/host/Cargo.lock object is ruzstd's only dependent: backtrace does not depend on it, so backtrace's own zstd path is off",
    evaluate(input) {
      // "backtrace does not depend on ruzstd" is implied: a backtrace that did would be one of ruzstd's dependents.
      const users = input.hostLock
        .filter((p) => p.name === "ruzstd")
        .flatMap((p) => directDependents(input.hostLock, p.name, p.version));
      return {
        holds: users.every((u) => u.startsWith("object@")),
        observed: `ruzstd's dependents: ${users.join(", ") || "none"}`,
      };
    },
  },
  {
    id: "A_HOST_SOURCE",
    statement:
      "zkvm/host/src/main.rs (comments stripped) proves only with .groth16() (once), never .plonk(), .compressed() or .core(), selects its prover with ProverClient::from_env(), and names no network or CUDA prover and no circuit install",
    evaluate(input) {
      if (input.hostMainText === null) return { holds: false, observed: "zkvm/host/src/main.rs is missing" };
      const code = stripRustComments(input.hostMainText);
      const groth16 = code.split(".groth16()").length - 1;
      const other = [...code.matchAll(/\.(plonk|compressed|core)\(\)/g)].map((m) => m[1]);
      const names = [...code.matchAll(/\b(network|Network|NETWORK|cuda|Cuda|CUDA|install_circuit_artifacts)\w*/g)].map(
        (m) => m[0],
      );
      const fromEnv = code.includes("ProverClient::from_env()");
      return {
        holds: groth16 === 1 && other.length === 0 && names.length === 0 && fromEnv,
        observed: `.groth16() ${groth16}x; other proof kinds: ${other.join(", ") || "none"}; network/cuda/install names: ${names.join(", ") || "none"}; ProverClient::from_env(): ${fromEnv ? "yes" : "no"}`,
      };
    },
  },
  {
    id: "A_NO_PROVING_WITHOUT_ARCHIVE",
    statement:
      "proving availability is OWNER_DOWNLOAD_REQUIRED (no WalletWall archive record, no local copy), ARCHIVED_VERIFIED_UNEXERCISED (exactly the one archive record the acquisition lane admitted, SP1-PA2B, and no proof-exercise record) or SELF_HOSTED_PATH_EXERCISED (that archive record plus proof-exercise records, each derived from a run through the archive-only gate, SP1-PA3A: every record on disk accepted and named by the availability record both as an accepted exercise and as a witness of the exercised path, and no other, SP1-PA3D0), never an unverified local copy where SP1 reads; the self-hosted path proves only from a verified archive through that gate, which never lets SP1 download the circuit, and it is exercised only as the committed proof-exercise records say",
    evaluate(input) {
      const pa = input.provingAvailability as Record<string, any> | null;
      const reqs: unknown[] = Array.isArray(pa?.selfHostedPath?.requirements) ? pa.selfHostedPath.requirements : [];
      const archiveOnly = reqs.some((r) => typeof r === "string" && r.startsWith("prove only from the archive"));
      const recorded = pa?.archives?.records;
      const onDisk = input.archiveRecords.length;
      const none = pa?.status === "OWNER_DOWNLOAD_REQUIRED" && recorded === 0 && onDisk === 0;
      const archived =
        pa?.status === "ARCHIVED_VERIFIED_UNEXERCISED" &&
        recorded === 1 &&
        onDisk === 1 &&
        input.archiveRecords[0] === pa?.archives?.accepted?.record;
      const exercisesRecorded = pa?.exercises?.records;
      // Every exercise record on disk, and the availability record's two accounts of them: the same paths, in the same
      // (path) order, or the account is not of these records.
      const exercisesOnDisk = [...input.exerciseRecords].sort();
      const sameAsOnDisk = (paths: unknown) =>
        Array.isArray(paths) && JSON.stringify(paths) === JSON.stringify(exercisesOnDisk);
      const acceptedExercises = Array.isArray(pa?.exercises?.accepted)
        ? pa.exercises.accepted.map((a: { record?: unknown } | null) => a?.record)
        : null;
      const exercised =
        pa?.status === "SELF_HOSTED_PATH_EXERCISED" &&
        recorded === 1 &&
        onDisk === 1 &&
        input.archiveRecords[0] === pa?.archives?.accepted?.record &&
        exercisesOnDisk.length > 0 &&
        exercisesRecorded === exercisesOnDisk.length &&
        sameAsOnDisk(acceptedExercises) &&
        sameAsOnDisk(pa?.selfHostedPath?.witnesses) &&
        pa?.selfHostedPath?.exercised === true;
      const unexercised =
        (none || archived) &&
        pa?.selfHostedPath?.exercised === false &&
        exercisesRecorded === 0 &&
        exercisesOnDisk.length === 0 &&
        pa?.exercises?.accepted === undefined &&
        pa?.selfHostedPath?.witnesses === undefined;
      const holds = (unexercised || exercised) && archiveOnly;
      return {
        holds,
        observed: `status ${String(pa?.status)}; archive records ${String(recorded)} recorded, ${onDisk} on disk${archived || exercised ? ` (the accepted ${String(pa?.archives?.accepted?.record)})` : ""}; proof-exercise records ${String(exercisesRecorded)} recorded, ${exercisesOnDisk.length} on disk${exercised ? ` (each accepted and a witness: ${exercisesOnDisk.join(", ")})` : ""}; self-hosted path exercised ${String(pa?.selfHostedPath?.exercised)}; proves only from an archive: ${archiveOnly ? "yes" : "no"}`,
      };
    },
  },
];

export interface FeatureFact {
  id: string;
  crate: string;
  present: readonly string[];
  absent: readonly string[];
  statement: string;
}
/** Read from `cargo tree -e features -i` in zkvm/host; each crate is the single version the lockfile pins. */
export const FEATURE_FACTS: readonly FeatureFact[] = [
  {
    id: "F_SP1_SDK_NO_NETWORK",
    crate: "sp1-sdk",
    present: ["blocking"],
    absent: ["cuda", "groth16-cuda", "native-gnark", "network", "reserved-capacity"],
    statement:
      "sp1-sdk is built with blocking and without network, cuda, groth16-cuda, native-gnark or reserved-capacity",
  },
  {
    id: "F_REQWEST_HTTP1_ONLY",
    crate: "reqwest",
    present: ["rustls-tls"],
    absent: ["http2", "http3"],
    statement: "reqwest is built with rustls and without http2 or http3: it speaks HTTP/1.1 only and never opens QUIC",
  },
  {
    id: "F_RUSTLS_NO_BROTLI",
    crate: "rustls",
    present: [],
    absent: ["brotli"],
    statement: "rustls is built without its brotli certificate-decompression feature",
  },
  {
    id: "F_RUSTLS_RING_ONLY",
    crate: "rustls",
    present: ["ring"],
    absent: ["aws-lc-rs", "aws_lc_rs", "fips", "prefer-post-quantum"],
    statement: "rustls is built with the ring provider only (no aws-lc-rs, fips or prefer-post-quantum)",
  },
  {
    id: "F_BACKTRACE_NO_RUZSTD",
    crate: "backtrace",
    present: [],
    absent: ["ruzstd"],
    statement: "backtrace is built without its ruzstd feature",
  },
];
export const FEATURE_CRATES = [...new Set(FEATURE_FACTS.map((f) => f.crate))].sort();

export interface MemberSelector {
  members?: readonly string[];
  prefix?: string;
  suffix?: string;
  exclude?: readonly string[];
}
export type Expectation =
  | { kind: "absent" }
  | { kind: "present" }
  | { kind: "count"; count: number }
  | { kind: "onlyIn"; members: readonly string[] };
export interface SourceFact {
  id: string;
  /** Each crate is the single version zkvm/host/Cargo.lock pins; its bytes are read from the .crate with that checksum. */
  crates: readonly string[];
  select: MemberSelector;
  pattern: string;
  flags: string;
  expect: Expectation;
  /** Each named crate's direct dependents must all be among `crates`: a claim about callers must cover every caller. */
  coversDependentsOf?: readonly string[];
  statement: string;
}

const RS: MemberSelector = { prefix: "src/", suffix: ".rs" };
export const SOURCE_FACTS: readonly SourceFact[] = [
  {
    id: "SF_SDK_NETWORK_MODULE_GATED",
    crates: ["sp1-sdk"],
    select: { members: ["src/lib.rs"] },
    pattern: String.raw`#\[cfg\(feature = "network"\)\]\s*pub mod network;`,
    flags: "",
    expect: { kind: "present" },
    statement: "sp1-sdk compiles its network module (its gRPC prover-network client) only with the network feature",
  },
  {
    id: "SF_SDK_GRPC_ONLY_IN_NETWORK_MODULE",
    crates: ["sp1-sdk"],
    select: { ...RS, exclude: ["src/network/"] },
    pattern: String.raw`\btonic::|ServiceClient|_service_client|connect_lazy|Endpoint::`,
    flags: "",
    expect: { kind: "absent" },
    statement: "outside its network module, sp1-sdk neither uses tonic nor constructs a gRPC client or endpoint",
  },
  {
    id: "SF_SDK_UNGATED_PROVERS",
    crates: ["sp1-sdk"],
    select: { members: ["src/blocking/env/mod.rs"] },
    pattern: String.raw`^\s*"(cpu|mock|light)" => Self::(Cpu|Mock|Light)\(`,
    flags: "m",
    expect: { kind: "count", count: 3 },
    statement: "SP1_PROVER selects cpu (the default), mock or light without any feature",
  },
  {
    id: "SF_SDK_NETWORK_PROVER_REFUSED",
    crates: ["sp1-sdk"],
    select: { members: ["src/blocking/env/mod.rs"] },
    pattern: String.raw`#\[cfg\(not\(feature = "network"\)\)\]\s*"network" => panic!`,
    flags: "",
    expect: { kind: "present" },
    statement: "SP1_PROVER=network panics when the network feature is off",
  },
  {
    id: "SF_SDK_CUDA_PROVER_REFUSED",
    crates: ["sp1-sdk"],
    select: { members: ["src/blocking/env/mod.rs"] },
    pattern: String.raw`#\[cfg\(not\(feature = "cuda"\)\)\]\s*"cuda" => panic!`,
    flags: "",
    expect: { kind: "present" },
    statement: "SP1_PROVER=cuda panics when the cuda feature is off",
  },
  {
    id: "SF_SDK_NEVER_INSTALLS_CIRCUITS",
    crates: ["sp1-sdk"],
    select: RS,
    pattern: String.raw`^[^\/\n]*\b(try_)?install_circuit_artifacts\(`,
    flags: "m",
    expect: { kind: "absent" },
    statement: "sp1-sdk never calls the circuit installer itself (it only re-exports it)",
  },
  {
    id: "SF_PROVER_NO_NETWORK_TRANSPORT",
    crates: ["sp1-prover", "sp1-prover-types"],
    select: RS,
    pattern: String.raw`tonic::transport|Server::builder|Endpoint::|connect_lazy|\.serve\(|TcpListener|UnixListener|TcpStream`,
    flags: "",
    expect: { kind: "absent" },
    coversDependentsOf: ["tonic"],
    statement:
      "neither tonic dependent (sp1-prover, sp1-prover-types) constructs a gRPC transport, server, listener or socket: sp1-prover uses tonic only for its Status and Code types, and its local workers talk over in-process channels",
  },
  {
    id: "SF_PROVER_HTTP_CLIENT_ONLY_IN_BUILD_RS",
    crates: ["sp1-prover"],
    select: RS,
    pattern: String.raw`\bClient::builder\(\)|\breqwest::(get|Client::new)\b`,
    flags: "",
    expect: { kind: "onlyIn", members: ["src/build.rs"] },
    statement: "sp1-prover builds its one HTTP client in src/build.rs (install_circuit_artifacts), nowhere else",
  },
  {
    id: "SF_PROVER_INSTALLS_ONLY_WHEN_ABSENT",
    crates: ["sp1-prover"],
    select: { members: ["src/build.rs"] },
    pattern: String.raw`pub async fn try_install_circuit_artifacts\(artifacts_type: &str\) -> Result<PathBuf> \{[\s\S]*?if build_dir\.exists\(\) \{[\s\S]*?\} else \{[\s\S]*?install_circuit_artifacts\(build_dir\.clone\(\), artifacts_type\)\.await\?;`,
    flags: "",
    expect: { kind: "present" },
    statement:
      "the circuit installer downloads only when the circuit directory is absent, and uses an existing one as it is",
  },
  {
    id: "SF_PROVER_INSTALL_ONLY_AT_WRAP",
    crates: ["sp1-prover"],
    select: RS,
    pattern: String.raw`\b(try_install_circuit_artifacts|try_build_groth16_artifacts_dir|try_build_plonk_artifacts_dir)\(`,
    flags: "",
    expect: { kind: "onlyIn", members: ["src/build.rs", "src/worker/prover/recursion.rs"] },
    statement:
      "the installer is reached only from the Groth16/PLONK wrap stage (src/worker/prover/recursion.rs); setup, vkey and execute never call it",
  },
  {
    id: "SF_NO_CUSTOM_SESSION_STORE",
    // quinn and quinn-proto are compiled into nothing (they are locked through reqwest's weak quinn?/ring feature);
    // they are read anyway, so the claim covers every locked dependent of rustls without an exemption.
    crates: ["hyper-rustls", "quinn", "quinn-proto", "reqwest", "tokio-rustls", "tonic"],
    select: RS,
    pattern: String.raw`ClientSessionStore`,
    flags: "",
    expect: { kind: "absent" },
    coversDependentsOf: ["rustls", "tokio-rustls"],
    statement:
      "no crate that configures rustls here implements or installs a ClientSessionStore: only rustls's built-in, redacting cache is used",
  },
  {
    id: "SF_RING_GROUPS_CLASSICAL",
    crates: ["rustls"],
    select: { members: ["src/crypto/ring/mod.rs"] },
    pattern: String.raw`pub static ALL_KX_GROUPS: &\[&dyn SupportedKxGroup\] =\s*&\[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1\];`,
    flags: "",
    expect: { kind: "present" },
    statement: "rustls's ring provider offers exactly X25519, P-256 and P-384",
  },
  {
    id: "SF_RING_NO_MLKEM",
    crates: ["rustls"],
    select: { prefix: "src/crypto/ring/", suffix: ".rs" },
    pattern: String.raw`mlkem|ml_kem|kyber`,
    flags: "i",
    expect: { kind: "absent" },
    statement: "rustls's ring provider implements no ML-KEM (no hybrid post-quantum group)",
  },
  {
    id: "SF_LRU_ONLY_IN_TWO_CACHES",
    crates: ["sp1-prover"],
    select: RS,
    pattern: String.raw`\bLruCache\b`,
    flags: "",
    expect: { kind: "onlyIn", members: ["src/shapes.rs", "src/worker/controller/mod.rs"] },
    coversDependentsOf: ["lru"],
    statement: "lru's only dependent, sp1-prover, uses LruCache in two places: the shape cache and the setup cache",
  },
  {
    id: "SF_PROVER_NO_ITER_MUT_OR_POP",
    crates: ["sp1-prover"],
    select: RS,
    pattern: String.raw`\.pop\(\s*&|\.pop_entry\(|\.pop_lru\(|\.iter_mut\(\)`,
    flags: "",
    expect: { kind: "absent" },
    statement: "sp1-prover never calls iter_mut, pop(&key), pop_entry or pop_lru",
  },
  {
    id: "SF_PROVER_NO_CATCH_UNWIND",
    crates: ["sp1-prover"],
    select: RS,
    pattern: String.raw`catch_unwind`,
    flags: "",
    expect: { kind: "absent" },
    statement: "sp1-prover never catches an unwinding panic",
  },
  {
    id: "SF_LRU_KEYS_WITHOUT_DROP",
    crates: ["sp1-prover", "sp1-prover-types"],
    select: RS,
    pattern: String.raw`impl(<[^>]*>)?\s+Drop\s+for\s+(SP1NormalizeInputShape|Artifact)\b`,
    flags: "",
    expect: { kind: "absent" },
    statement: "the cache keys (SP1NormalizeInputShape, Artifact) have no Drop impl that could panic",
  },
  {
    id: "SF_MEMMAP2_RANGE_FNS_UNUSED",
    crates: ["dynasmrt", "sp1-core-executor", "sp1-jit"],
    select: RS,
    pattern: String.raw`advise_range|flush_range|flush_async_range`,
    flags: "",
    expect: { kind: "absent" },
    coversDependentsOf: ["memmap2"],
    statement:
      "no dependent of memmap2 (dynasmrt, sp1-core-executor, sp1-jit) calls advise_range, unchecked_advise_range, flush_range or flush_async_range",
  },
  {
    id: "SF_EPOCH_POINTERS_NEVER_FORMATTED",
    crates: ["crossbeam", "crossbeam-deque", "slop-futures"],
    select: RS,
    pattern: String.raw`\{:#?p\}|fmt::Pointer`,
    flags: "",
    expect: { kind: "absent" },
    coversDependentsOf: ["crossbeam-epoch", "crossbeam"],
    statement:
      "no crate that can name crossbeam-epoch's Atomic or Shared (crossbeam-deque, crossbeam, and slop-futures through crossbeam) formats one as a pointer",
  },
  {
    id: "SF_OBJECT_RUZSTD_ONLY_IN_DECOMPRESS",
    crates: ["object"],
    select: RS,
    pattern: String.raw`\bruzstd::`,
    flags: "",
    expect: { kind: "onlyIn", members: ["src/read/mod.rs"] },
    coversDependentsOf: ["ruzstd"],
    statement:
      "object, ruzstd's only dependent, calls the decoder only in CompressedData::decompress (src/read/mod.rs)",
  },
  {
    id: "SF_OBJECT_DECOMPRESS_ONLY_VIA_UNCOMPRESSED_DATA",
    crates: ["object"],
    select: RS,
    pattern: String.raw`\.decompress\(\)`,
    flags: "",
    expect: { kind: "onlyIn", members: ["src/read/traits.rs", "src/read/xcoff/section.rs"] },
    statement: "object calls decompress() only from its uncompressed_data() implementations",
  },
  {
    id: "SF_OBJECT_DECOMPRESSION_UNUSED",
    crates: ["backtrace", "sp1-core-executor"],
    select: RS,
    pattern: String.raw`\buncompressed_data\b|\bcompressed_data\b|\bCompressedData\b`,
    flags: "",
    expect: { kind: "absent" },
    coversDependentsOf: ["object"],
    statement:
      "neither dependent of object (backtrace, sp1-core-executor) reaches object's section decompression: backtrace decompresses debug sections itself",
  },
  {
    id: "SF_EXECUTOR_WRITES_ELF_ONLY",
    crates: ["sp1-core-executor"],
    select: RS,
    pattern: String.raw`\bobject::(\{[^}]*\b(read|File|Object|ObjectSection)\b|read\b|File\b|Object\b)`,
    flags: "",
    expect: { kind: "absent" },
    statement: "sp1-core-executor uses object only to write ELF dumps (object::write), never to read one",
  },
];

export function memberSelected(select: MemberSelector, path: string): boolean {
  if (select.members) return select.members.includes(path);
  return (
    path.startsWith(select.prefix ?? "") &&
    path.endsWith(select.suffix ?? "") &&
    !(select.exclude ?? []).some((e) => path.startsWith(e))
  );
}
export function countMatches(fact: Pick<SourceFact, "pattern" | "flags">, text: string): number {
  const flags = fact.flags.includes("g") ? fact.flags : `${fact.flags}g`;
  return [...text.matchAll(new RegExp(fact.pattern, flags))].length;
}

// ---------------------------------------------------------------------------------------------------------
// The claims: the reviewed judgment, one per measured finding
// ---------------------------------------------------------------------------------------------------------

export interface Claim {
  lockfile: LockfileId;
  kind: Kind;
  id: string | null;
  crate: string;
  reachability: AssessedReachability;
  /** Evidence ids (assumptions, feature facts, source facts) that must all hold for the claim to support anything. */
  requires: readonly string[];
  precondition: string;
  exploit: string;
  rationale: string;
  /** For CONDITIONAL only: the path on which the code would run, and why the frozen configuration excludes it. */
  condition?: string;
}

const QUINN = {
  lockfile: "host",
  kind: "vulnerability",
  crate: "quinn-proto",
  reachability: "NOT_COMPILED",
  requires: ["F_REQWEST_HTTP1_ONLY"],
  precondition: "a QUIC connection (quinn) to a malicious peer",
  rationale:
    "cargo tree prints nothing for quinn-proto on any target: it is in Cargo.lock only because reqwest's rustls feature names quinn?/ring (a weak dependency feature), while reqwest's http3 feature, the only one that enables quinn, is off",
} as const;
const RUSTLS_DOWNLOAD =
  "rustls runs only inside SP1's own circuit download: release-mode install_circuit_artifacts at the Groth16/PLONK wrap stage, when the v6.1.0 circuit directory is absent (dev mode downloads with the aws CLI instead). The frozen proving configuration installs the circuit from a hash-verified WalletWall archive first, so that download never runs; until the archive path exists no proving run is authorized at all";

export const CLAIMS: readonly Claim[] = [
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0204",
    crate: "crossbeam-epoch",
    reachability: "PRECONDITION_ABSENT",
    requires: ["SF_EPOCH_POINTERS_NEVER_FORMATTED"],
    precondition:
      "formatting an Atomic or Shared that holds an invalid (e.g. null) pointer with its pointer formatting",
    exploit: "an invalid pointer dereference (undefined behaviour) inside the formatting impl",
    rationale:
      "crossbeam-epoch is linked through rayon's work-stealing deques, and no crate that can name its types formats one as a pointer",
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0258",
    crate: "h2",
    reachability: "PRECONDITION_ABSENT",
    requires: [
      "F_REQWEST_HTTP1_ONLY",
      "SF_PROVER_NO_NETWORK_TRANSPORT",
      "SF_SDK_GRPC_ONLY_IN_NETWORK_MODULE",
      "SF_SDK_NETWORK_MODULE_GATED",
      "F_SP1_SDK_NO_NETWORK",
      "A_SP1_SDK_FEATURES",
    ],
    precondition: "an HTTP/2 connection to a peer that sends empty DATA frames faster than the stream is drained",
    exploit: "unbounded memory growth, or a panic on length overflow (denial of service)",
    rationale:
      "h2 is linked through hyper (for reqwest and tonic), but no HTTP/2 connection is ever made: reqwest is built without http2 (HTTP/1.1 only), and no tonic transport is ever constructed, since sp1-prover uses tonic only for error types and sp1-sdk's gRPC client lives in its network module, which is not compiled",
  },
  {
    ...QUINN,
    id: "RUSTSEC-2026-0185",
    exploit: "memory exhaustion from unbounded out-of-order stream reassembly (remote peer)",
  },
  {
    ...QUINN,
    id: "RUSTSEC-2026-0338",
    exploit: "a panic from zero-length STREAM frames during unordered reads (remote peer)",
  },
  {
    ...QUINN,
    id: "RUSTSEC-2026-0339",
    exploit: "unbounded growth of pending connection-ID retirements (remote peer)",
  },
  {
    ...QUINN,
    id: "RUSTSEC-2026-0340",
    exploit: "a panic from a peer's minimum ACK delay when ACK_FREQUENCY sending is enabled",
  },
  {
    ...QUINN,
    id: "RUSTSEC-2026-0342",
    exploit: "zero-length DATAGRAM frames bypass the receive buffer limit (unbounded memory, remote peer)",
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0285",
    crate: "rustls",
    reachability: "CONDITIONAL",
    requires: [
      "SF_PROVER_HTTP_CLIENT_ONLY_IN_BUILD_RS",
      "SF_PROVER_INSTALLS_ONLY_WHEN_ABSENT",
      "SF_PROVER_INSTALL_ONLY_AT_WRAP",
      "SF_SDK_NEVER_INSTALLS_CIRCUITS",
      "SF_PROVER_NO_NETWORK_TRANSPORT",
      "F_SP1_SDK_NO_NETWORK",
      "A_HOST_SOURCE",
      "A_NO_PROVING_WITHOUT_ARCHIVE",
    ],
    precondition: "a TLS 1.3 server that sends handshake messages across a key change in one record",
    exploit:
      "rustls accepts such messages instead of aborting; the transcript stays authenticated, so the peer cannot alter or complete a handshake (low impact)",
    rationale:
      "rustls is compiled, and its one use is the HTTPS download of SP1's circuit artifacts; nothing else in the host opens a TLS connection",
    condition: RUSTLS_DOWNLOAD,
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0346",
    crate: "rustls",
    reachability: "PRECONDITION_ABSENT",
    requires: ["SF_NO_CUSTOM_SESSION_STORE"],
    precondition: "a custom ClientSessionStore that formats stored session values with Debug (for example into logs)",
    exploit: "disclosure of a TLS 1.2 master secret or TLS 1.3 resumption PSK to readers of those logs",
    rationale:
      "no crate that configures rustls here installs a session store of its own, and rustls's built-in cache redacts its Debug output",
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0348",
    crate: "rustls",
    reachability: "PRECONDITION_ABSENT",
    requires: ["F_RUSTLS_NO_BROTLI", "A_LOCK_NO_BROTLI"],
    precondition: "rustls's non-default brotli feature, connecting to a malicious server",
    exploit:
      "a five-byte header makes certificate decompression allocate up to 1 GiB before authentication (denial of service)",
    rationale: "rustls is built without brotli, and no brotli crate is in the lockfile",
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0349",
    crate: "rustls",
    reachability: "PRECONDITION_ABSENT",
    requires: ["SF_RING_GROUPS_CLASSICAL", "SF_RING_NO_MLKEM", "F_RUSTLS_RING_ONLY", "A_LOCK_NO_AWS_LC"],
    precondition:
      "a client that offers a hybrid post-quantum key-exchange group (X25519MLKEM768) and keeps sessions across connections to one server",
    exploit:
      "an unauthenticated ServerHello pins later handshakes to classical X25519 (loss of post-quantum confidentiality; no authentication bypass)",
    rationale:
      "the only rustls provider compiled here is ring, whose groups are X25519, P-256 and P-384: there is no hybrid group to downgrade from",
  },
  {
    lockfile: "host",
    kind: "vulnerability",
    id: "RUSTSEC-2026-0344",
    crate: "ruzstd",
    reachability: "PRECONDITION_ABSENT",
    requires: [
      "SF_OBJECT_RUZSTD_ONLY_IN_DECOMPRESS",
      "SF_OBJECT_DECOMPRESS_ONLY_VIA_UNCOMPRESSED_DATA",
      "SF_OBJECT_DECOMPRESSION_UNUSED",
      "SF_EXECUTOR_WRITES_ELF_ONLY",
      "F_BACKTRACE_NO_RUZSTD",
      "A_LOCK_BACKTRACE_WITHOUT_RUZSTD",
    ],
    precondition: "decoding attacker-controlled zstd input",
    exploit: "a crafted .zst under 128 KB allocates gigabytes (out-of-memory denial of service)",
    rationale:
      "ruzstd is compiled because sp1-core-executor enables object's default compression feature, but its decoder is reached only through object's section decompression, which no crate here calls: sp1-core-executor only writes ELF dumps, and backtrace decompresses debug sections itself, with its zstd path behind its own ruzstd feature, which is off",
  },
  {
    lockfile: "host",
    kind: "unsound",
    id: "RUSTSEC-2026-0002",
    crate: "lru",
    reachability: "PRECONDITION_ABSENT",
    requires: ["SF_LRU_ONLY_IN_TWO_CACHES", "SF_PROVER_NO_ITER_MUT_OR_POP"],
    precondition: "calling LruCache::iter_mut",
    exploit: "a Stacked Borrows violation in IterMut (undefined behaviour for code that iterates mutably)",
    rationale: "sp1-prover, lru's only dependent, keeps two caches and never calls iter_mut",
  },
  {
    lockfile: "host",
    kind: "unsound",
    id: "RUSTSEC-2026-0253",
    crate: "lru",
    reachability: "PRECONDITION_ABSENT",
    requires: [
      "SF_LRU_ONLY_IN_TWO_CACHES",
      "SF_PROVER_NO_ITER_MUT_OR_POP",
      "SF_PROVER_NO_CATCH_UNWIND",
      "SF_LRU_KEYS_WITHOUT_DROP",
    ],
    precondition: "LruCache::pop with a key whose Drop panics, the panic caught by catch_unwind",
    exploit: "a use-after-free or double free on a later eviction (memory corruption)",
    rationale:
      "sp1-prover never calls pop on its caches, never catches an unwind, and its cache keys have no Drop impl",
  },
  {
    lockfile: "host",
    kind: "unsound",
    id: "RUSTSEC-2026-0186",
    crate: "memmap2",
    reachability: "PRECONDITION_ABSENT",
    requires: ["SF_MEMMAP2_RANGE_FNS_UNUSED"],
    precondition:
      "calling advise_range, unchecked_advise_range, flush_range or flush_async_range with an out-of-bounds range",
    exploit:
      "an invalid pointer offset passed to madvise or msync (undefined behaviour; the pointer is not dereferenced)",
    rationale: "no dependent of memmap2 calls any of the affected functions",
  },
  {
    lockfile: "guest",
    kind: "unsound",
    id: "RUSTSEC-2026-0190",
    crate: "anyhow",
    reachability: "NOT_COMPILED",
    requires: [],
    precondition: "calling anyhow::Error::downcast_mut",
    exploit: "unsoundness in Error::downcast_mut",
    rationale:
      "cargo tree prints nothing for anyhow on any target: it is locked but compiled into neither guest program",
  },
  {
    lockfile: "relation-tests",
    kind: "unsound",
    id: "RUSTSEC-2026-0190",
    crate: "anyhow",
    reachability: "NOT_COMPILED",
    requires: [],
    precondition: "calling anyhow::Error::downcast_mut",
    exploit: "unsoundness in Error::downcast_mut",
    rationale:
      "cargo tree prints nothing for anyhow on any target: it is locked but not compiled into the test harness",
  },
];

const claimFor = (claims: readonly Claim[], f: MeasuredFinding) =>
  claims.find((c) => c.lockfile === f.lockfile && c.kind === f.kind && c.id === f.id && c.crate === f.crate);

/**
 * Static checks of a claim catalog: every claim must name evidence that exists, and a judgment must rest on measured
 * evidence. The production check always passes the reviewed CLAIMS; another list is how tests show what a regressed
 * catalog would do.
 */
export function catalogIssues(claims: readonly Claim[] = CLAIMS): Issue[] {
  const issues: Issue[] = [];
  const ids = new Set([
    ...ASSUMPTIONS.map((a) => a.id),
    ...FEATURE_FACTS.map((f) => f.id),
    ...SOURCE_FACTS.map((s) => s.id),
  ]);
  if (ids.size !== ASSUMPTIONS.length + FEATURE_FACTS.length + SOURCE_FACTS.length) {
    issues.push(invalid("CATALOG_INVALID", "two evidence items share an id"));
  }
  const seen = new Set<string>();
  for (const c of claims) {
    const who = `${c.lockfile} ${keyOf({ id: c.id, crate: c.crate, version: "*" })}`;
    const k = `${c.lockfile}|${c.kind}|${c.id}|${c.crate}`;
    if (seen.has(k)) issues.push(invalid("CATALOG_INVALID", `${who} has two claims`));
    seen.add(k);
    for (const r of c.requires) {
      if (!ids.has(r)) issues.push(invalid("CATALOG_INVALID", `${who}'s claim requires unknown evidence ${r}`));
    }
    const judged = c.reachability === "PRECONDITION_ABSENT" || c.reachability === "CONDITIONAL";
    const measuredSupport = c.requires.some((r) => r.startsWith("SF_") || r.startsWith("F_"));
    if (judged && !measuredSupport) {
      issues.push(
        invalid(
          "CATALOG_UNSUPPORTED_JUDGMENT",
          `${who} is claimed ${c.reachability} without any feature or source fact: an absent precondition must be measured`,
        ),
      );
    }
    if ((c.reachability === "CONDITIONAL") !== Boolean(c.condition)) {
      issues.push(invalid("CATALOG_INVALID", `${who}: a condition is stated exactly when the claim is CONDITIONAL`));
    }
    if (c.reachability === "NO_KNOWN_DEFECT" && (c.kind === "vulnerability" || c.kind === "unsound")) {
      issues.push(invalid("CATALOG_INVALID", `${who}: a ${c.kind} cannot be NO_KNOWN_DEFECT`));
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------------------------------------
// The observation
// ---------------------------------------------------------------------------------------------------------

export interface ObservedOutput {
  spec: string;
  command: string;
  output: string;
}
export interface ObservedPrecise extends ObservedOutput {
  version: string;
}
export interface ObservedLockfile {
  id: LockfileId;
  path: string;
  sha256: string;
  packages: number;
  registryPackages: number;
  audit: unknown;
  yanked: { crate: string; version: string }[];
  trees: ObservedOutput[];
  features: ObservedOutput[];
  updates: ObservedOutput[];
  precise: ObservedPrecise[];
}
export interface ObservedMember {
  path: string;
  sha256: string;
  matches: number;
}
export interface ObservedSourceCrate {
  crate: string;
  version: string;
  checksum: string;
  members: ObservedMember[];
}
export interface ObservedSourceFact {
  id: string;
  pattern: string;
  flags: string;
  crates: ObservedSourceCrate[];
}
export interface AdvisoryObservation {
  schema: string;
  measuredAtUtc: string;
  host: string;
  tool: { script: string; scriptSha256: string; cargo: string; cargoAudit: string };
  database: { lastCommit: string; lastUpdated: string; advisoryCount: number };
  index: { base: string; registryPackagesChecked: number };
  lockfiles: ObservedLockfile[];
  sourceFacts: ObservedSourceFact[];
}

/** A package spec or version that becomes one cargo argument: anything else (a space, a flag) is refused. */
function arg(value: string, what: "spec" | "version"): string {
  const ok =
    what === "spec" ? /^[A-Za-z0-9_][A-Za-z0-9_-]*@\d[0-9A-Za-z.+-]*$/.test(value) : /^\d[0-9A-Za-z.+-]*$/.test(value);
  if (!ok) throw new Error(`not a package ${what}: ${JSON.stringify(value)}`);
  return value;
}
export const treeCommand = (spec: string) =>
  `cargo tree --locked --offline --target all -e normal,build,dev --prefix depth -i ${arg(spec, "spec")}`;
export const featureTreeCommand = (spec: string) =>
  `cargo tree --locked --offline --target all -e features --prefix depth -i ${arg(spec, "spec")}`;
export const updateProbeCommand = (spec: string) => `cargo update --dry-run -p ${arg(spec, "spec")}`;
export const preciseProbeCommand = (spec: string, version: string) =>
  `cargo update --dry-run -p ${arg(spec, "spec")} --precise ${arg(version, "version")}`;

/** The measured findings of one observed lockfile: cargo-audit's, plus the index's yanked releases. */
export function measuredFindingsOf(lf: ObservedLockfile, lock: readonly LockPackage[] | null): MeasuredFinding[] {
  const out = auditFindingsOf(lf.audit, lf.id, lock);
  if (!Array.isArray(lf.yanked)) throw new Error(`the ${lf.id} observation has no yanked list`);
  for (const y of lf.yanked) {
    if (
      typeof y?.crate !== "string" ||
      typeof y?.version !== "string" ||
      (lock && !isPinned(lock, y.crate, y.version))
    ) {
      throw new Error(`the ${lf.id} observation reports ${specOf(y?.crate, y?.version)} yanked, which is not locked`);
    }
    out.push({ lockfile: lf.id, kind: "yanked", id: null, crate: y.crate, version: y.version, advisory: null });
  }
  const keys = out.map((f) => `${f.kind} ${keyOf(f)}`);
  const dup = keys.find((k, i) => keys.indexOf(k) !== i);
  if (dup) throw new Error(`the ${lf.id} observation reports ${dup} twice`);
  return out.sort(byFinding);
}

export const findingSpecs = (findings: readonly MeasuredFinding[]) =>
  [...new Set(findings.map((f) => specOf(f.crate, f.version)))].sort();

/** The precise probes a finding needs: when the compatible update reaches no patched version. */
export function precisePlan(
  findings: readonly MeasuredFinding[],
  updateOutput: (spec: string) => string,
): { spec: string; version: string }[] {
  const plan = new Map<string, { spec: string; version: string }>();
  for (const f of findings) {
    const patched = f.advisory?.patched ?? [];
    if (f.kind === "yanked" || patched.length === 0) continue;
    const spec = specOf(f.crate, f.version);
    const to = updateProbeOf(updateOutput(spec), f.crate, f.version).to;
    if (to !== null && patched.some((r) => satisfies(to, r))) continue;
    const version = minimalPatchedVersion(patched);
    plan.set(`${spec} ${version}`, { spec, version });
  }
  return [...plan.values()].sort((a, b) => `${a.spec} ${a.version}`.localeCompare(`${b.spec} ${b.version}`));
}

/** The other lockfile changes a dry-run update probe of `crate@version` reports (what the fix drags along). */
export function updateChangesOf(output: string, crate: string, version: string): string[] {
  const own = new RegExp(`^\\s*Updating ${escapeRe(crate)} v${escapeRe(version)} -> `);
  return output
    .split("\n")
    .filter((l) => /^\s*(Updating|Adding|Removing|Downgrading) [A-Za-z0-9_-]+ v/.test(l) && !own.test(l))
    .map((l) => l.trim());
}

export interface FixFacts {
  /** A semver-compatible release meets every dependent's requirement and is patched (for yanked: is not yanked). */
  lockfileOnly: boolean;
  compatibleVersion: string | null;
  /** The other lockfile changes that compatible update makes. */
  alsoChanges: string[];
  lowestPatched: string | null;
  upstreamBlocked: boolean;
  blockedBy: string | null;
  noPatchedRelease: boolean;
}
export function fixFactsOf(
  f: MeasuredFinding,
  update: string,
  precise: (spec: string, version: string) => string,
): FixFacts {
  const spec = specOf(f.crate, f.version);
  const to = updateProbeOf(update, f.crate, f.version).to;
  const none = { compatibleVersion: null, alsoChanges: [], upstreamBlocked: false, blockedBy: null };
  const reached = (v: string, changes: string[]) => ({ compatibleVersion: v, alsoChanges: changes });
  if (f.kind === "yanked") {
    return to === null
      ? {
          ...none,
          lockfileOnly: false,
          lowestPatched: null,
          upstreamBlocked: true,
          blockedBy: "no other semver-compatible release",
          noPatchedRelease: false,
        }
      : {
          ...none,
          ...reached(to, updateChangesOf(update, f.crate, f.version)),
          lockfileOnly: true,
          lowestPatched: null,
          noPatchedRelease: false,
        };
  }
  const patched = f.advisory?.patched ?? [];
  if (patched.length === 0) return { ...none, lockfileOnly: false, lowestPatched: null, noPatchedRelease: true };
  const lowestPatched = minimalPatchedVersion(patched);
  if (to !== null && patched.some((r) => satisfies(to, r))) {
    return {
      ...none,
      ...reached(to, updateChangesOf(update, f.crate, f.version)),
      lockfileOnly: true,
      lowestPatched,
      noPatchedRelease: false,
    };
  }
  const p = preciseProbeOf(precise(spec, lowestPatched), f.crate, f.version);
  if (p.blocked) {
    return {
      ...none,
      lockfileOnly: false,
      lowestPatched,
      upstreamBlocked: true,
      blockedBy: `${p.requiredBy} requires ${p.requirement}`,
      noPatchedRelease: false,
    };
  }
  return { ...none, ...reached(p.to, []), lockfileOnly: true, lowestPatched, noPatchedRelease: false };
}

const outputOf = (list: readonly ObservedOutput[], spec: string, what: string): string => {
  const hit = list.filter((t) => t?.spec === spec);
  if (hit.length !== 1) throw new Error(`the observation has ${hit.length} ${what} of ${spec}, not one`);
  return String(hit[0].output);
};

export interface SourceFactResult extends EvidenceResult {
  membersRead: number;
}
export function sourceFactResult(fact: SourceFact, observed: ObservedSourceFact): SourceFactResult {
  const crates = observed.crates;
  const membersRead = crates.reduce((n, c) => n + c.members.length, 0);
  const hits = crates.flatMap((c) => c.members.filter((m) => m.matches > 0).map((m) => ({ crate: c.crate, ...m })));
  const total = hits.reduce((n, m) => n + m.matches, 0);
  const vacuous = crates.some((c) => c.members.length === 0);
  let holds: boolean;
  switch (fact.expect.kind) {
    case "absent":
      holds = total === 0;
      break;
    case "present":
      holds = total >= 1;
      break;
    case "count":
      holds = total === fact.expect.count;
      break;
    default: {
      const only = fact.expect.members;
      holds = total >= 1 && hits.every((h) => only.includes(h.path));
    }
  }
  const where = hits.map((h) => `${h.crate}:${h.path} ${h.matches}x`).join(", ");
  const read = crates.map((c) => `${c.crate} ${c.version} (${c.members.length} files)`).join(", ");
  return {
    holds: holds && !vacuous,
    membersRead,
    observed: `${total} match${total === 1 ? "" : "es"}${where ? ` (${where})` : ""} in ${read}${vacuous ? "; a crate with no file read proves nothing" : ""}`,
  };
}

/** Every reason an observation is not one this repository can rely on, as of the given lockfiles. */
export function observationIssues(
  obs: AdvisoryObservation,
  ctx: { measureScriptSha256: string | null; locks: Record<LockfileId, string | null> },
): Issue[] {
  const issues: Issue[] = [];
  const bad = (message: string) => issues.push(invalid("OBSERVATION_MALFORMED", message));
  if (obs?.schema !== ADVISORY_OBSERVATION_SCHEMA) bad(`the schema must be ${ADVISORY_OBSERVATION_SCHEMA}`);
  if (obs?.tool?.script !== MEASURE_ADVISORIES_SCRIPT_REL || obs.tool.scriptSha256 !== ctx.measureScriptSha256) {
    issues.push(
      stale(
        "OBSERVATION_SCRIPT_CHANGED",
        `the observation was not made by ${MEASURE_ADVISORIES_SCRIPT_REL} as committed: re-measure`,
      ),
    );
  }
  if (!String(obs?.tool?.cargoAudit).includes(` ${CARGO_AUDIT_VERSION}`)) {
    bad(`the observation was not made with cargo-audit ${CARGO_AUDIT_VERSION}`);
  }
  const db = obs?.database;
  if (!/^[0-9a-f]{40}$/.test(String(db?.lastCommit)) || !(Number(db?.advisoryCount) > 0)) {
    bad("the observation names no advisory-database commit");
  }
  const lockfiles = Array.isArray(obs?.lockfiles) ? obs.lockfiles : [];
  if (lockfiles.map((l) => `${l?.id}:${l?.path}`).join() !== LOCKFILES.map((l) => `${l.id}:${lockPathOf(l)}`).join()) {
    bad(`the observation must measure ${LOCKFILES.map(lockPathOf).join(", ")}, in that order`);
    return issues;
  }
  let allCurrent = true;
  const union = new Set<string>();
  for (const lf of lockfiles) {
    const spec = LOCKFILES.find((l) => l.id === lf.id) as LockfileSpec;
    const current = ctx.locks[lf.id];
    const isCurrent = current !== null && sha256(current) === lf.sha256;
    if (!isCurrent) {
      allCurrent = false;
      if (spec.role === "DESIGNATED_SUBJECT") {
        issues.push(
          stale(
            "OBSERVATION_LOCKFILE_CHANGED",
            `${lf.path} is not the lockfile the observation measured (${lf.sha256}): its RustSec findings must be re-measured and reassessed`,
          ),
        );
      }
      continue; // a companion's changed lockfile is the networked check's to judge
    }
    let lock: LockPackage[];
    let findings: MeasuredFinding[];
    try {
      lock = parseCargoLock(current);
      findings = measuredFindingsOf(lf, lock);
    } catch (error) {
      bad((error as Error).message);
      continue;
    }
    for (const p of registryPackages(lock)) union.add(specOf(p.name, p.version));
    if (lf.packages !== lock.length || lf.registryPackages !== registryPackages(lock).length) {
      bad(`${lf.path}: the package counts are not the lockfile's`);
    }
    const auditDb = (lf.audit as Record<string, any>).database;
    const usedCommit = auditDb["last-commit"];
    if ((usedCommit !== null && usedCommit !== db?.lastCommit) || auditDb["advisory-count"] !== db?.advisoryCount) {
      bad(`${lf.path} was audited against another advisory database than the observation names`);
    }
    const specs = findingSpecs(findings);
    const check = (
      list: unknown,
      what: string,
      command: (s: string) => string,
      parse: (s: string, o: string) => void,
      want: string[],
    ) => {
      const entries = Array.isArray(list) ? (list as ObservedOutput[]) : [];
      if (entries.map((e) => e?.spec).join() !== want.join()) {
        bad(`${lf.path}: the ${what} must be exactly ${want.join(", ") || "none"}`);
        return;
      }
      for (const e of entries) {
        if (e.command !== command(e.spec)) bad(`${lf.path}: the ${what} of ${e.spec} was not \`${command(e.spec)}\``);
        try {
          parse(e.spec, String(e.output));
        } catch (error) {
          bad(`${lf.path}: ${(error as Error).message}`);
        }
      }
    };
    const crateOf = (s: string) => s.slice(0, s.lastIndexOf("@"));
    const versionOf = (s: string) => s.slice(s.lastIndexOf("@") + 1);
    check(lf.trees, "trees", treeCommand, (s, o) => treeFactsOf(o, crateOf(s), versionOf(s), spec.root), specs);
    check(lf.updates, "update probes", updateProbeCommand, (s, o) => updateProbeOf(o, crateOf(s), versionOf(s)), specs);
    const featureSpecs =
      lf.id === "host"
        ? FEATURE_CRATES.map((c) => {
            const p = onlyVersion(lock, c);
            return p ? specOf(p.name, p.version) : `${c}@?`;
          })
        : [];
    check(
      lf.features,
      "feature trees",
      featureTreeCommand,
      (s, o) => featuresOf(o, crateOf(s), versionOf(s)),
      featureSpecs,
    );
    let plan: { spec: string; version: string }[] = [];
    try {
      plan = precisePlan(findings, (s) => outputOf(lf.updates, s, "update probes"));
    } catch (error) {
      bad(`${lf.path}: ${(error as Error).message}`);
    }
    const precise = Array.isArray(lf.precise) ? lf.precise : [];
    if (precise.map((p) => `${p?.spec} ${p?.version}`).join() !== plan.map((p) => `${p.spec} ${p.version}`).join()) {
      bad(
        `${lf.path}: the precise probes must be exactly ${plan.map((p) => `${p.spec} at ${p.version}`).join(", ") || "none"}`,
      );
    } else {
      for (const p of precise) {
        if (p.command !== preciseProbeCommand(p.spec, p.version))
          bad(`${lf.path}: the precise probe of ${p.spec} was not its command`);
        try {
          preciseProbeOf(String(p.output), crateOf(p.spec), versionOf(p.spec));
        } catch (error) {
          bad(`${lf.path}: ${(error as Error).message}`);
        }
      }
    }
  }
  if (allCurrent && obs?.index?.registryPackagesChecked !== union.size) {
    bad(`the index check must cover the ${union.size} registry packages of the four lockfiles`);
  }
  if (obs?.index?.base !== SPARSE_INDEX_BASE) bad(`the yanked status must come from ${SPARSE_INDEX_BASE}`);
  const hostLockText = ctx.locks.host;
  if (hostLockText !== null && sha256(hostLockText) === lockfiles[0].sha256) {
    const hostLock = parseCargoLock(hostLockText);
    const facts = Array.isArray(obs?.sourceFacts) ? obs.sourceFacts : [];
    if (facts.map((f) => f?.id).join() !== SOURCE_FACTS.map((f) => f.id).join()) {
      issues.push(
        stale("OBSERVATION_CATALOG_CHANGED", "the observation's source facts are not the catalog's: re-measure"),
      );
    } else {
      SOURCE_FACTS.forEach((fact, i) => {
        const o = facts[i];
        if (o.pattern !== fact.pattern || o.flags !== fact.flags) {
          issues.push(
            stale(
              "OBSERVATION_CATALOG_CHANGED",
              `${fact.id}: the catalog's pattern changed since it was measured: re-measure`,
            ),
          );
          return;
        }
        if (!Array.isArray(o.crates) || o.crates.map((c) => c?.crate).join() !== fact.crates.join()) {
          bad(`${fact.id}: it must read ${fact.crates.join(", ")}`);
          return;
        }
        for (const c of o.crates) {
          const p = onlyVersion(hostLock, c.crate);
          if (!p || c.version !== p.version || c.checksum !== p.checksum) {
            bad(`${fact.id}: ${c.crate} ${c.version} is not the crate zkvm/host/Cargo.lock pins`);
          }
          if (!Array.isArray(c.members) || c.members.length === 0) {
            bad(`${fact.id}: no file of ${c.crate} was read, so the fact proves nothing`);
            continue;
          }
          for (const m of c.members) {
            if (
              !memberSelected(fact.select, m?.path) ||
              !/^[0-9a-f]{64}$/.test(String(m?.sha256)) ||
              !Number.isInteger(m?.matches) ||
              m.matches < 0
            ) {
              bad(`${fact.id}: ${c.crate} member ${String(m?.path)} is not one the fact reads, or is unmeasured`);
            }
          }
        }
      });
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------------------------------------
// The repository state and the record
// ---------------------------------------------------------------------------------------------------------

export interface FileDigest {
  path: string;
  sha256: string;
}
export interface AdvisoryState {
  observation: AdvisoryObservation | null;
  observationSha256: string | null;
  measureScriptSha256: string | null;
  recordText: string | null;
  /** The tracked files of zkvm/host, with the sha256 of their working-tree bytes. */
  hostFiles: FileDigest[];
  hostManifestText: string | null;
  hostMainText: string | null;
  headHostTree: string | null;
  locks: Record<LockfileId, string | null>;
  designations: { path: string; sha256: string; doc: ProgramDesignation }[];
  /** subjectFreshnessErrors of the latest designation: the zkvm subject at HEAD and on disk must be its. */
  designationFreshness: string[];
  td1Receipt: FileDigest | null;
  provingAvailability: { sha256: string; doc: unknown } | null;
  archiveRecords: string[];
  exerciseRecords: string[];
}

function readOrNull(path: string): Buffer | null {
  try {
    return readFileSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}
function git(repoRoot: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd: resolve(repoRoot), stdio: ["ignore", "pipe", "ignore"] }).toString("utf8");
  } catch {
    return null;
  }
}

/** Everything the record is derived from and checked against, read from the repository. */
export function advisoryStateFromRepo(repoRoot = "."): AdvisoryState {
  const at = (rel: string) => resolve(repoRoot, rel);
  const text = (rel: string) => readOrNull(at(rel))?.toString("utf8") ?? null;
  const obsBytes = readOrNull(at(ADVISORY_OBSERVATION_REL));
  const script = readOrNull(at(MEASURE_ADVISORIES_SCRIPT_REL));
  const listed = (git(repoRoot, ["ls-files", "-z", "--", HOST_DIR]) ?? "").split("\0").filter(Boolean).sort();
  const hostFiles = listed.map((path) => {
    const b = readOrNull(at(path));
    return { path, sha256: b === null ? "missing" : sha256(b) };
  });
  const designations = readDesignations(repoRoot).map((doc) => {
    const path = `${DESIGNATIONS_DIR}/${doc.id}.json`;
    return { path, sha256: sha256(readFileSync(at(path))), doc };
  });
  const latest = latestDesignation(designations.map((d) => d.doc));
  const td1 = readOrNull(at(TD1_RECEIPT_REL));
  const pa = readOrNull(at(PROVING_AVAILABILITY_REL));
  const locks = Object.fromEntries(LOCKFILES.map((l) => [l.id, text(lockPathOf(l))])) as Record<
    LockfileId,
    string | null
  >;
  return {
    observation: obsBytes === null ? null : (JSON.parse(obsBytes.toString("utf8")) as AdvisoryObservation),
    observationSha256: obsBytes === null ? null : sha256(obsBytes),
    measureScriptSha256: script === null ? null : sha256(script),
    recordText: text(HOST_ADVISORIES_REL),
    hostFiles,
    hostManifestText: text(`${HOST_DIR}/Cargo.toml`),
    hostMainText: text(`${HOST_DIR}/src/main.rs`),
    headHostTree: git(repoRoot, ["rev-parse", `HEAD:${HOST_DIR}`])?.trim() ?? null,
    locks,
    designations,
    designationFreshness: latest ? subjectFreshnessErrors(latest, repoRoot) : ["no designation exists"],
    td1Receipt: td1 === null ? null : { path: TD1_RECEIPT_REL, sha256: sha256(td1) },
    provingAvailability: pa === null ? null : { sha256: sha256(pa), doc: JSON.parse(pa.toString("utf8")) },
    archiveRecords: archiveRecordsIn(repoRoot),
    exerciseRecords: exerciseRecordsIn(repoRoot),
  };
}

export interface RecordFinding {
  key: string;
  id: string | null;
  kind: Kind;
  crate: string;
  version: string;
  advisory: AdvisoryProjection | null;
  compiled: boolean;
  dependency: { role: TreeRole; directDependents: string[]; pathToRoot: string[] };
  reachability: Reachability;
  reachableInFrozenProvingPath: boolean;
  precondition: string;
  exploit: string;
  rationale: string;
  condition: string | null;
  evidence: string[];
  fix: FixFacts;
  bucket: Bucket;
  disposition: string;
}
export interface RecordEvidence {
  id: string;
  kind: "assumption" | "feature" | "source";
  statement: string;
  holds: boolean;
  observed: string;
}
export interface CompanionRecord {
  id: LockfileId;
  path: string;
  role: LockfileRole;
  sha256: string;
  packages: number;
  vulnerabilities: number;
  warnings: number;
  disposition: string;
  findings: RecordFinding[];
}
export interface HostAdvisoryRecord {
  schema: string;
  note: string;
  ownerDecision: typeof OWNER_DECISION;
  subject: {
    designation: {
      id: string;
      sequence: number;
      path: string;
      sha256: string;
      zkvmHostTree: string;
      zkvmGuestTree: string;
      guestCargoLockSha256: string;
      elfSha256: string;
      programVKey: string;
      identity: string;
    };
    zkvmHostTree: string | null;
    files: FileDigest[];
    lockfile: { path: string; sha256: string; packages: number };
    boundEvidence: FileDigest[];
  };
  build: {
    sp1Requirements: Record<string, string>;
    sp1Locked: Record<string, string>;
    sp1SdkFeatures: string[];
    provers: { selectable: string[]; refused: string[] };
    hostCommands: string[];
    proofSystems: string[];
    circuit: {
      version: string | null;
      provingAvailability: string | null;
      walletWallArchives: number;
      walletWallProofExercises: number;
      sp1DownloadsWhenAbsent: boolean;
    };
  };
  assessment: {
    observation: { path: string; sha256: string | null; measuredAtUtc: string; host: string };
    tools: { cargo: string; cargoAudit: string };
    database: { lastCommit: string; lastUpdated: string; advisoryCount: number };
    yankedSource: string;
    counts: {
      findings: number;
      vulnerabilities: number;
      warnings: number;
      byKind: Record<Kind, number>;
      byBucket: Record<string, number>;
      compiled: number;
    };
    dependencyStatus: DependencyStatus;
    dependencyStatusMeaning: string;
  };
  buckets: Record<(typeof BUCKETS)[number], string[]>;
  findings: RecordFinding[];
  evidence: RecordEvidence[];
  remediation: {
    status: string;
    dependencyUpdatedByThisRecord: false;
    compatibleRefresh: { crate: string; from: string; to: string; findings: string[] }[];
    upstreamBlocked: { crate: string; version: string; blockedBy: string; findings: string[] }[];
    noPatchedRelease: { crate: string; version: string; findings: string[] }[];
    remainingAfterCompatibleRefresh: string[];
  };
  companionLockfiles: CompanionRecord[];
  reassessWhen: string[];
  nextProgramRebuild: string[];
}

export const REASSESS_WHEN = [
  "zkvm/host's tree changes at HEAD or on disk (Cargo.toml, Cargo.lock, build.rs or src/main.rs), including a dependabot bump",
  "a designation succeeds mldsa65-withdrawal-d1, or d1's bytes change (designations are immutable: supersede, never rewrite)",
  "an assumption stops holding: a new dependency, table or sp1-sdk feature (network, cuda, native-gnark), a network-only, aws-lc, brotli or cuda crate in the lockfile, another proof kind or prover in src/main.rs",
  "proving availability changes: a WalletWall circuit archive, a local copy, an exercised self-hosted path (the archive-only install changes which rustls path can run)",
  "the networked RustSec job reports drift: a new advisory, a changed one (kind, severity, ranges), a finding that disappeared, or a changed graph, feature, source or fix fact",
  "the measurement script, the evidence catalog or the claims change",
];
export const NEXT_PROGRAM_REBUILD = [
  "apply the compatible dependency refresh listed under remediation.compatibleRefresh (and any newer patched releases)",
  "re-audit every lockfile and re-measure this record's observation with the pinned cargo-audit",
  "publish a successor designation for the rebuilt program (a host-only change is refused as a same-identity successor: the rebuild itself must change the program's identity, or the owner decides the designation route)",
  "run the canonical two-host rebuild and record its procedure",
  "re-measure the ELF and PROGRAM_VKEY outside the build and compare them",
  "re-measure proving availability for the new lockfile and circuit",
];

const DEPENDENCY_STATUS_MEANING =
  "derived from the measured findings alone: NOT_DEPENDENCY_SAFE while any RustSec vulnerability or unsoundness is locked in zkvm/host/Cargo.lock, whatever its bucket. A valid assessment records what was assessed and why; it does not make a vulnerable dependency non-vulnerable.";
const NOTE =
  "What was assessed and why, for the zkvm/host RustSec findings of designation mldsa65-withdrawal-d1. Not a security waiver and not a fix: every finding below is still present in zkvm/host/Cargo.lock. Derived by scripts/generate-sp1-host-advisories.ts from the observation, the claims in scripts/lib/sp1-host-advisories.ts and the repository; never hand-edit it. See docs/SP1_Host_Lockfile_Advisories.md.";

/**
 * The bucket, derived and never typed. MUST_FIX: a vulnerability or unsoundness reachable on the frozen proving path.
 * SHOULD_FIX: compiled into a designated build and either reachable only on a path the frozen configuration excludes
 * (CONDITIONAL), or fixable by a lockfile-only update (a vulnerability, unsoundness or yanked release). Everything else
 * is NOT_REACHABLE_OR_UPSTREAM_ONLY: not compiled, a precondition measured absent with no compatible fix, an
 * unmaintained crate (no fix exists), or a lockfile that never ships (the CI test harness, offline tooling).
 */
export function bucketOf(
  f: Pick<RecordFinding, "kind" | "compiled" | "reachability" | "fix">,
  role: LockfileRole,
): Bucket {
  if (f.reachability === "UNASSESSED" || f.reachability === "UNSUPPORTED") return "UNASSESSED";
  if (role !== "DESIGNATED_SUBJECT") return "NOT_REACHABLE_OR_UPSTREAM_ONLY";
  if ((f.kind === "vulnerability" || f.kind === "unsound") && f.reachability === "REACHABLE") {
    return "MUST_FIX_BEFORE_REAL_PROVING";
  }
  const fixableKind = f.kind === "vulnerability" || f.kind === "unsound" || f.kind === "yanked";
  if (f.compiled && (f.reachability === "CONDITIONAL" || (fixableKind && f.fix.lockfileOnly))) {
    return "SHOULD_FIX_BEFORE_PRODUCTION";
  }
  return "NOT_REACHABLE_OR_UPSTREAM_ONLY";
}

export function dependencyStatusOf(findings: readonly { kind: Kind }[] | null): DependencyStatus {
  if (findings === null) return "UNKNOWN";
  return findings.some((f) => f.kind === "vulnerability" || f.kind === "unsound")
    ? "NOT_DEPENDENCY_SAFE"
    : "DEPENDENCY_SAFE";
}

/** The evidence results, by id, for the host observation; a fact that cannot be evaluated does not hold. */
export function evidenceResults(state: AdvisoryState, hostLock: readonly LockPackage[]): Map<string, RecordEvidence> {
  const out = new Map<string, RecordEvidence>();
  const input: AssumptionInput = {
    hostManifestText: state.hostManifestText,
    hostMainText: state.hostMainText,
    hostLock,
    provingAvailability: state.provingAvailability?.doc ?? null,
    archiveRecords: state.archiveRecords,
    exerciseRecords: state.exerciseRecords,
  };
  for (const a of ASSUMPTIONS) {
    const r = a.evaluate(input);
    out.set(a.id, { id: a.id, kind: "assumption", statement: a.statement, holds: r.holds, observed: r.observed });
  }
  const host = state.observation?.lockfiles?.[0];
  for (const f of FEATURE_FACTS) {
    let r: EvidenceResult;
    try {
      const p = onlyVersion(hostLock, f.crate);
      if (!p) throw new Error(`zkvm/host/Cargo.lock pins ${f.crate} at other than one version`);
      const features = featuresOf(
        outputOf(host?.features ?? [], specOf(p.name, p.version), "feature trees"),
        p.name,
        p.version,
      );
      const missing = f.present.filter((x) => !features.includes(x));
      const on = f.absent.filter((x) => features.includes(x));
      r = {
        holds: missing.length === 0 && on.length === 0,
        observed: `${p.name} ${p.version} features: ${features.join(", ") || "none"}${missing.length ? `; missing ${missing.join(", ")}` : ""}${on.length ? `; enabled ${on.join(", ")}` : ""}`,
      };
    } catch (error) {
      r = { holds: false, observed: (error as Error).message };
    }
    out.set(f.id, { id: f.id, kind: "feature", statement: f.statement, holds: r.holds, observed: r.observed });
  }
  for (const s of SOURCE_FACTS) {
    let r: EvidenceResult;
    try {
      const o = (state.observation?.sourceFacts ?? []).find((x) => x?.id === s.id);
      if (!o) throw new Error(`${s.id} was not measured`);
      r = sourceFactResult(s, o);
      for (const of of s.coversDependentsOf ?? []) {
        const p = onlyVersion(hostLock, of);
        const users = p
          ? directDependents(hostLock, p.name, p.version).map((u) => u.slice(0, u.lastIndexOf("@")))
          : [of];
        const missed = users.filter((u) => !s.crates.includes(u));
        if (missed.length > 0)
          r = { holds: false, observed: `${r.observed}; ${of}'s dependents ${missed.join(", ")} are not read` };
      }
    } catch (error) {
      r = { holds: false, observed: (error as Error).message };
    }
    out.set(s.id, { id: s.id, kind: "source", statement: s.statement, holds: r.holds, observed: r.observed });
  }
  return out;
}

function deriveFindings(
  lf: ObservedLockfile,
  lock: readonly LockPackage[] | null,
  where: LockfileSpec,
  evidence: ReadonlyMap<string, RecordEvidence>,
  disposition: string,
  claims: readonly Claim[],
): RecordFinding[] {
  return measuredFindingsOf(lf, lock).map((f) => {
    const spec = specOf(f.crate, f.version);
    const tree = treeFactsOf(outputOf(lf.trees, spec, "trees"), f.crate, f.version, where.root);
    const fix = fixFactsOf(f, outputOf(lf.updates, spec, "update probes"), (s, v) => {
      const hit = lf.precise.filter((p) => p.spec === s && p.version === v);
      if (hit.length !== 1) throw new Error(`the observation has no precise probe of ${s} at ${v}`);
      return hit[0].output;
    });
    const claim = claimFor(claims, f);
    const informational = f.kind === "yanked" || f.kind === "unmaintained" || f.kind === "notice";
    let reachability: Reachability;
    let evidenceIds: string[] = [];
    let precondition: string;
    let exploit: string;
    let rationale: string;
    let condition: string | null = null;
    const via =
      tree.role === "PROC_MACRO"
        ? `a procedural macro (it runs only while compiling), used via ${tree.pathToRoot.slice(1).join(" <- ")}`
        : tree.role === "PROC_MACRO_ONLY"
          ? `only by procedural macros (compile time only), via ${tree.pathToRoot.slice(1).join(" <- ")}`
          : `linked via ${tree.pathToRoot.slice(1).join(" <- ")}`;
    if (claim) {
      evidenceIds = [...claim.requires];
      precondition = claim.precondition;
      exploit = claim.exploit;
      rationale = claim.rationale;
      condition = claim.condition ?? null;
      const supported = claim.requires.every((id) => evidence.get(id)?.holds === true);
      const measuredOk =
        claim.reachability === "NOT_COMPILED"
          ? !tree.compiled
          : claim.reachability === "NO_KNOWN_DEFECT"
            ? tree.compiled && informational
            : tree.compiled;
      reachability = supported && measuredOk ? claim.reachability : "UNSUPPORTED";
    } else if (!tree.compiled) {
      reachability = "NOT_COMPILED";
      precondition = `${f.crate} compiled into a ${lf.id} build`;
      exploit = f.advisory ? f.advisory.title : `${f.crate} ${f.version} was yanked by its publisher`;
      rationale = `cargo tree prints nothing for ${spec} on any target: it is locked but compiled into no build`;
    } else if (informational) {
      reachability = "NO_KNOWN_DEFECT";
      precondition = "none: RustSec reports no vulnerability";
      exploit =
        f.kind === "yanked"
          ? `${f.crate} ${f.version} was yanked by its publisher; no advisory is attached`
          : `${f.advisory?.title ?? f.crate} (${f.kind}; informational)`;
      rationale = `${via}; ${f.kind === "yanked" ? "a yanked release carries no known defect, but a later release replaces it" : "an unmaintained crate gets no fixes, so a future advisory would be upstream-only"}`;
    } else {
      reachability = "UNASSESSED";
      precondition = "unassessed";
      exploit = f.advisory?.title ?? "unassessed";
      rationale = `no claim covers ${keyOf(f)}: a new or changed advisory needs a reviewed claim before the record is valid`;
    }
    const partial = { kind: f.kind, compiled: tree.compiled, reachability, fix };
    return {
      key: keyOf(f),
      id: f.id,
      kind: f.kind,
      crate: f.crate,
      version: f.version,
      advisory: f.advisory,
      compiled: tree.compiled,
      dependency: { role: tree.role, directDependents: tree.directDependents, pathToRoot: tree.pathToRoot },
      reachability,
      reachableInFrozenProvingPath: reachability === "REACHABLE",
      precondition,
      exploit,
      rationale,
      condition,
      evidence: evidenceIds,
      fix,
      bucket: bucketOf(partial, where.role),
      disposition,
    } satisfies RecordFinding;
  });
}

const countBy = <T extends string>(xs: readonly T[], keys: readonly T[]) =>
  Object.fromEntries(keys.map((k) => [k, xs.filter((x) => x === k).length])) as Record<T, number>;

/** The record the state derives under the reviewed claims; throws when the observation does not derive one. */
export function deriveHostAdvisoryRecord(state: AdvisoryState): HostAdvisoryRecord {
  return deriveRecordWith(state, CLAIMS);
}

/** The record the state derives under `claims` (tests pass a regressed catalog; production passes CLAIMS). */
export function deriveRecordWith(state: AdvisoryState, claims: readonly Claim[]): HostAdvisoryRecord {
  const obs = state.observation;
  if (!obs) throw new Error(`${ADVISORY_OBSERVATION_REL} is missing: measure it`);
  const hostText = state.locks.host;
  if (hostText === null) throw new Error("zkvm/host/Cargo.lock is missing");
  const hostLock = parseCargoLock(hostText);
  const evidence = evidenceResults(state, hostLock);
  const host = obs.lockfiles[0];
  const findings = deriveFindings(host, hostLock, LOCKFILES[0], evidence, DISPOSITION_DEFERRED, claims);
  const d1 = state.designations.find((d) => d.doc.id === OWNER_DECISION.designation);
  if (!d1) throw new Error(`designation ${OWNER_DECISION.designation} is missing`);
  const manifest = (() => {
    try {
      return parseSimpleManifest(state.hostManifestText ?? "");
    } catch {
      return null;
    }
  })();
  const req = (table: string, dep: string): string => {
    const v = manifest?.entries[table]?.[dep];
    return typeof v === "string" ? v : typeof v === "object" && !Array.isArray(v) ? String(v.version) : "unread";
  };
  const locked = (c: string) => onlyVersion(hostLock, c)?.version ?? "unread";
  const sdkSpec = specOf("sp1-sdk", locked("sp1-sdk"));
  const sdkFeatures = (() => {
    try {
      return featuresOf(outputOf(host.features, sdkSpec, "feature trees"), "sp1-sdk", locked("sp1-sdk"));
    } catch {
      return [];
    }
  })();
  const code = state.hostMainText === null ? "" : stripRustComments(state.hostMainText);
  const pa = state.provingAvailability?.doc as Record<string, any> | null | undefined;
  const ev = (id: string) => evidence.get(id)?.holds === true;
  const bucketKeys = (b: (typeof BUCKETS)[number]) => findings.filter((f) => f.bucket === b).map((f) => f.key);
  const groupBy = (xs: RecordFinding[], key: (f: RecordFinding) => string) => {
    const m = new Map<string, RecordFinding[]>();
    for (const x of xs) m.set(key(x), [...(m.get(key(x)) ?? []), x]);
    return [...m.values()];
  };
  const refresh = groupBy(
    findings.filter((f) => f.fix.lockfileOnly),
    (f) => specOf(f.crate, f.version),
  ).map((g) => ({
    crate: g[0].crate,
    from: g[0].version,
    to: g
      .map((f) => f.fix.compatibleVersion as string)
      .sort(compareVersions)
      .at(-1) as string,
    findings: g.map((f) => f.key),
  }));
  const companions: CompanionRecord[] = LOCKFILES.slice(1).map((spec, i) => {
    const lf = obs.lockfiles[i + 1];
    const text = state.locks[spec.id];
    const current = text !== null && sha256(text) === lf.sha256;
    const disposition =
      spec.role === "DESIGNATED_SUBJECT"
        ? DISPOSITION_DEFERRED
        : spec.role === "CI_TEST_HARNESS"
          ? DISPOSITION_TEST_HARNESS
          : DISPOSITION_TOOLING;
    // A companion lockfile that changed since the observation is the networked check's to judge: its findings stay the
    // measured ones (held to the lockfile only while it is the measured one), and a recorded finding that the new
    // lockfile no longer pins is reported by the verdict (COMPANION_FINDING_NOT_IN_LOCKFILE).
    const lock = current ? parseCargoLock(text as string) : null;
    const companionFindings = deriveFindings(lf, lock, spec, evidence, disposition, claims);
    return {
      id: spec.id,
      path: lockPathOf(spec),
      role: spec.role,
      sha256: lf.sha256,
      packages: lf.packages,
      vulnerabilities: companionFindings.filter((f) => f.kind === "vulnerability").length,
      warnings: companionFindings.filter((f) => f.kind !== "vulnerability").length,
      disposition,
      findings: companionFindings,
    };
  });
  return {
    schema: HOST_ADVISORIES_SCHEMA,
    note: NOTE,
    ownerDecision: OWNER_DECISION,
    subject: {
      designation: {
        id: d1.doc.id,
        sequence: d1.doc.sequence,
        path: d1.path,
        sha256: d1.sha256,
        zkvmHostTree: d1.doc.subject.zkvmHostTree,
        zkvmGuestTree: d1.doc.subject.zkvmGuestTree,
        guestCargoLockSha256: d1.doc.subject.guestCargoLockSha256,
        elfSha256: d1.doc.elf.sha256,
        programVKey: d1.doc.programVKey,
        identity: d1.doc.identity,
      },
      zkvmHostTree: state.headHostTree,
      files: state.hostFiles,
      lockfile: { path: "zkvm/host/Cargo.lock", sha256: sha256(hostText), packages: hostLock.length },
      boundEvidence: [
        ...(state.td1Receipt ? [state.td1Receipt] : []),
        ...(state.provingAvailability
          ? [{ path: PROVING_AVAILABILITY_REL, sha256: state.provingAvailability.sha256 }]
          : []),
      ],
    },
    build: {
      sp1Requirements: {
        "sp1-build": req("build-dependencies", "sp1-build"),
        "sp1-sdk": req("dependencies", "sp1-sdk"),
      },
      sp1Locked: Object.fromEntries(["sp1-build", "sp1-prover", "sp1-sdk"].map((c) => [c, locked(c)])),
      sp1SdkFeatures: sdkFeatures,
      provers: {
        selectable: ev("SF_SDK_UNGATED_PROVERS") ? ["cpu (default)", "light", "mock"] : [],
        refused: [
          ...(ev("SF_SDK_CUDA_PROVER_REFUSED") && ev("A_LOCK_NO_CUDA") ? ["cuda (panics: feature off)"] : []),
          ...(ev("SF_SDK_NETWORK_PROVER_REFUSED") && ev("F_SP1_SDK_NO_NETWORK")
            ? ["network (panics: feature off)"]
            : []),
        ],
      },
      hostCommands: [...code.matchAll(/^\s*"([a-z0-9-]+)" =>/gm)].map((m) => m[1]).sort(),
      proofSystems: (["groth16", "plonk", "compressed", "core"] as const).filter((k) => code.includes(`.${k}()`)),
      circuit: {
        version: typeof pa?.expectedArtifacts?.circuitVersion === "string" ? pa.expectedArtifacts.circuitVersion : null,
        provingAvailability: typeof pa?.status === "string" ? pa.status : null,
        walletWallArchives: state.archiveRecords.length,
        walletWallProofExercises: state.exerciseRecords.length,
        sp1DownloadsWhenAbsent: ev("SF_PROVER_INSTALLS_ONLY_WHEN_ABSENT"),
      },
    },
    assessment: {
      observation: {
        path: ADVISORY_OBSERVATION_REL,
        sha256: state.observationSha256,
        measuredAtUtc: obs.measuredAtUtc,
        host: obs.host,
      },
      tools: { cargo: obs.tool.cargo, cargoAudit: obs.tool.cargoAudit },
      database: obs.database,
      yankedSource: `${SPARSE_INDEX_BASE} (cargo audit ran with --no-yanked; an index that does not answer fails the measurement)`,
      counts: {
        findings: findings.length,
        vulnerabilities: findings.filter((f) => f.kind === "vulnerability").length,
        warnings: findings.filter((f) => f.kind !== "vulnerability").length,
        byKind: countBy(
          findings.map((f) => f.kind),
          KINDS,
        ),
        byBucket: countBy(
          findings.map((f) => f.bucket),
          [...BUCKETS, "UNASSESSED"] as Bucket[],
        ),
        compiled: findings.filter((f) => f.compiled).length,
      },
      dependencyStatus: dependencyStatusOf(findings),
      dependencyStatusMeaning: DEPENDENCY_STATUS_MEANING,
    },
    buckets: {
      MUST_FIX_BEFORE_REAL_PROVING: bucketKeys("MUST_FIX_BEFORE_REAL_PROVING"),
      SHOULD_FIX_BEFORE_PRODUCTION: bucketKeys("SHOULD_FIX_BEFORE_PRODUCTION"),
      NOT_REACHABLE_OR_UPSTREAM_ONLY: bucketKeys("NOT_REACHABLE_OR_UPSTREAM_ONLY"),
    },
    findings,
    evidence: [...evidence.values()],
    remediation: {
      status: DISPOSITION_DEFERRED,
      dependencyUpdatedByThisRecord: false,
      compatibleRefresh: refresh,
      upstreamBlocked: groupBy(
        findings.filter((f) => f.fix.upstreamBlocked),
        (f) => specOf(f.crate, f.version),
      ).map((g) => ({
        crate: g[0].crate,
        version: g[0].version,
        blockedBy: [...new Set(g.map((f) => f.fix.blockedBy as string))].join("; "),
        findings: g.map((f) => f.key),
      })),
      noPatchedRelease: groupBy(
        findings.filter((f) => f.fix.noPatchedRelease),
        (f) => specOf(f.crate, f.version),
      ).map((g) => ({ crate: g[0].crate, version: g[0].version, findings: g.map((f) => f.key) })),
      remainingAfterCompatibleRefresh: findings.filter((f) => !f.fix.lockfileOnly).map((f) => f.key),
    },
    companionLockfiles: companions,
    reassessWhen: REASSESS_WHEN,
    nextProgramRebuild: NEXT_PROGRAM_REBUILD,
  };
}

export function serializeHostAdvisoryRecord(record: HostAdvisoryRecord): string {
  return `${JSON.stringify(record, null, 2)}\n`;
}

// ---------------------------------------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------------------------------------

export interface Verdict {
  assessment: AssessmentStatus;
  dependencyStatus: DependencyStatus;
  issues: Issue[];
  derived: HostAdvisoryRecord | null;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function subjectIssues(state: AdvisoryState): Issue[] {
  const issues: Issue[] = [];
  const latest = latestDesignation(state.designations.map((d) => d.doc));
  if (!latest) return [stale("SUBJECT_NO_DESIGNATION", "no designation exists")];
  if (latest.id !== OWNER_DECISION.designation) {
    issues.push(
      stale(
        "SUBJECT_DESIGNATION_SUPERSEDED",
        `${latest.id} supersedes ${OWNER_DECISION.designation}, the designation the owner's deferral and this assessment were made for: reassess for ${latest.id}`,
      ),
    );
  }
  for (const e of state.designationFreshness) issues.push(stale("SUBJECT_STALE", e));
  const d1 = state.designations.find((d) => d.doc.id === OWNER_DECISION.designation);
  if (d1 && state.headHostTree !== d1.doc.subject.zkvmHostTree) {
    issues.push(
      stale(
        "SUBJECT_TREE_CHANGED",
        `HEAD:zkvm/host is ${String(state.headHostTree)}, not ${d1.doc.id}'s ${d1.doc.subject.zkvmHostTree}: the host subject moved`,
      ),
    );
  }
  return issues;
}

function recordIssues(committed: Record<string, any>, derived: HostAdvisoryRecord, state: AdvisoryState): Issue[] {
  const issues: Issue[] = [];
  if (committed.schema !== HOST_ADVISORIES_SCHEMA)
    issues.push(invalid("RECORD_MALFORMED", `the schema must be ${HOST_ADVISORIES_SCHEMA}`));
  const deferral =
    same(committed.ownerDecision, OWNER_DECISION) &&
    committed.remediation?.status === DISPOSITION_DEFERRED &&
    committed.remediation?.dependencyUpdatedByThisRecord === false;
  if (!deferral) {
    issues.push(
      invalid(
        "RECORD_DEFERRAL_REWRITTEN",
        "the record restates the owner's decision or the remediation status: HOST_LOCKFILE_REMEDIATION is DEFER_TO_NEXT_PROGRAM_REBUILD for d1, nothing is fixed until a successor designation, and only the owner changes that",
      ),
    );
  }
  if (!same(committed.subject?.designation, derived.subject.designation)) {
    issues.push(
      invalid(
        "RECORD_DESIGNATION_MISMATCH",
        `the record does not bind ${OWNER_DECISION.designation} as committed: designations are immutable (supersede, never rewrite), and the record may not restate one`,
      ),
    );
  }
  const boundNow = derived.subject.boundEvidence;
  if (!same(committed.subject?.boundEvidence, boundNow) && Array.isArray(committed.subject?.boundEvidence)) {
    issues.push(
      stale(
        "BOUND_EVIDENCE_CHANGED",
        `historical SP1 evidence the assessment read changed (${boundNow.map((b) => b.path).join(", ")}): such evidence is superseded, never restamped; reassess`,
      ),
    );
  }
  // Only a record that binds a subject can describe an earlier one; a record without that binding is malformed.
  if (!Array.isArray(committed.subject?.files) || typeof committed.subject?.zkvmHostTree !== "string") {
    issues.push(invalid("RECORD_MALFORMED", "the record binds no zkvm/host tree and file digests"));
  } else if (
    !same(committed.subject.files, derived.subject.files) ||
    committed.subject.zkvmHostTree !== derived.subject.zkvmHostTree
  ) {
    issues.push(stale("SUBJECT_FILE_CHANGED", "the record's zkvm/host tree or file digests are not today's: reassess"));
  }
  const want = new Map(derived.findings.map((f) => [f.key, f]));
  const got: Record<string, any>[] = Array.isArray(committed.findings) ? committed.findings : [];
  const keys = got.map((f) => String(f?.key));
  for (const k of keys.filter((k, i) => keys.indexOf(k) !== i)) {
    issues.push(invalid("RECORD_FINDING_DUPLICATE", `${k} appears twice`));
  }
  const hostLock = state.locks.host === null ? [] : parseCargoLock(state.locks.host);
  for (const f of got) {
    const d = want.get(String(f?.key));
    if (!isPinned(hostLock, f?.crate, f?.version)) {
      issues.push(
        invalid("RECORD_FINDING_NOT_IN_LOCKFILE", `${String(f?.key)}: ${specOf(f?.crate, f?.version)} is not locked`),
      );
    }
    if (!d) {
      issues.push(invalid("RECORD_FINDING_UNKNOWN", `${String(f?.key)} is not a measured finding`));
      continue;
    }
    if (f.kind !== d.kind || f.id !== d.id || f.crate !== d.crate || f.version !== d.version) {
      issues.push(invalid("RECORD_FINDING_NOT_DERIVED", `${d.key}: its identity is not the measured one`));
    }
    if (!same(f.advisory, d.advisory))
      issues.push(invalid("RECORD_ADVISORY_NOT_DERIVED", `${d.key}: the advisory is not RustSec's as measured`));
    if (f.compiled !== d.compiled || !same(f.dependency, d.dependency)) {
      issues.push(
        invalid("RECORD_GRAPH_NOT_DERIVED", `${d.key}: compiled/dependency are not what cargo tree measured`),
      );
    }
    if (f.reachability !== d.reachability) {
      issues.push(
        invalid(
          "RECORD_REACHABILITY_UNSUPPORTED",
          `${d.key}: ${String(f.reachability)} is not what the claim and its evidence support (${d.reachability})`,
        ),
      );
    }
    const judged = f.reachability === "PRECONDITION_ABSENT" || f.reachability === "CONDITIONAL";
    if (!same(f.evidence, d.evidence) || (judged && (!Array.isArray(f.evidence) || f.evidence.length === 0))) {
      issues.push(
        invalid("RECORD_EVIDENCE_MISSING", `${d.key}: the evidence must be exactly ${d.evidence.join(", ") || "none"}`),
      );
    }
    if (!same(f.fix, d.fix))
      issues.push(invalid("RECORD_FIX_NOT_DERIVED", `${d.key}: the fix facts are not the measured ones`));
    if (f.bucket !== d.bucket)
      issues.push(
        invalid("RECORD_BUCKET_NOT_DERIVED", `${d.key}: bucket ${String(f.bucket)} is not the derived ${d.bucket}`),
      );
    if (f.disposition !== DISPOSITION_DEFERRED) {
      issues.push(invalid("RECORD_DEFERRAL_REWRITTEN", `${d.key}: the disposition must stay ${DISPOSITION_DEFERRED}`));
    }
  }
  for (const k of want.keys()) {
    if (!keys.includes(k))
      issues.push(invalid("RECORD_FINDING_OMITTED", `${k} is measured but missing from the record`));
  }
  const companions: Record<string, any>[] = Array.isArray(committed.companionLockfiles)
    ? committed.companionLockfiles
    : [];
  for (const c of derived.companionLockfiles) {
    const got = companions.find((x) => x?.id === c.id);
    const gotKeys: string[] = Array.isArray(got?.findings)
      ? got.findings.map((f: { key: unknown }) => String(f?.key))
      : [];
    for (const f of c.findings) {
      if (!gotKeys.includes(f.key)) {
        issues.push(invalid("RECORD_FINDING_OMITTED", `${c.path}: ${f.key} is measured but missing from the record`));
      }
    }
    for (const k of gotKeys) {
      if (!c.findings.some((f) => f.key === k)) {
        issues.push(invalid("RECORD_FINDING_UNKNOWN", `${c.path}: ${k} is not a measured finding`));
      }
    }
  }
  if (committed.assessment?.dependencyStatus !== derived.assessment.dependencyStatus) {
    issues.push(
      invalid(
        "RECORD_DEPENDENCY_STATUS_NOT_DERIVED",
        `the dependency status must be ${derived.assessment.dependencyStatus}: a valid assessment never makes a locked vulnerability safe`,
      ),
    );
  }
  if (!same(committed.buckets, derived.buckets))
    issues.push(invalid("RECORD_BUCKET_NOT_DERIVED", "the bucket lists are not derived"));
  return issues;
}

/** The assessment status and, separately, the dependency status; never one standing in for the other. */
export function hostAdvisoryVerdict(state: AdvisoryState): Verdict {
  return evaluateHostAdvisories(state, CLAIMS);
}

/** The verdict under `claims` (tests pass a regressed catalog; the production check is hostAdvisoryVerdict). */
export function evaluateHostAdvisories(state: AdvisoryState, claims: readonly Claim[]): Verdict {
  const issues: Issue[] = [...catalogIssues(claims)];
  const obs = state.observation;
  if (!obs) {
    issues.push(invalid("OBSERVATION_MISSING", `${ADVISORY_OBSERVATION_REL} is missing: measure it`));
    return { assessment: "RECORD_INVALID", dependencyStatus: "UNKNOWN", issues, derived: null };
  }
  issues.push(...observationIssues(obs, { measureScriptSha256: state.measureScriptSha256, locks: state.locks }));
  issues.push(...subjectIssues(state));
  const usable = !issues.some((i) => i.code === "OBSERVATION_MALFORMED" || i.code === "OBSERVATION_LOCKFILE_CHANGED");
  let derived: HostAdvisoryRecord | null = null;
  let dependencyStatus: DependencyStatus = "UNKNOWN";
  if (usable) {
    try {
      derived = deriveRecordWith(state, claims);
    } catch (error) {
      issues.push(invalid("OBSERVATION_MALFORMED", (error as Error).message));
    }
  }
  if (derived) {
    dependencyStatus = derived.assessment.dependencyStatus;
    for (const e of derived.evidence) {
      if (!e.holds) {
        issues.push(
          e.kind === "assumption"
            ? stale(
                "ASSUMPTION_FAILED",
                `${e.id} no longer holds (${e.observed}): the claims that rest on it need reassessment`,
              )
            : stale("EVIDENCE_FAILED", `${e.id} no longer holds (${e.observed})`),
        );
      }
    }
    const all = [...derived.findings, ...derived.companionLockfiles.flatMap((c) => c.findings)];
    for (const f of all) {
      if (f.reachability === "UNASSESSED") issues.push(invalid("CLAIM_UNASSESSED", `${f.key}: ${f.rationale}`));
      if (f.reachability === "UNSUPPORTED") {
        issues.push(
          stale(
            "CLAIM_UNSUPPORTED",
            `${f.key}: its claim no longer rests on evidence that holds and measurements that agree`,
          ),
        );
      }
    }
    for (const c of claims) {
      const hit = (
        c.lockfile === "host"
          ? derived.findings
          : (derived.companionLockfiles.find((x) => x.id === c.lockfile)?.findings ?? [])
      ).some((f) => f.kind === c.kind && f.id === c.id && f.crate === c.crate);
      const companion = derived.companionLockfiles.find((x) => x.id === c.lockfile);
      const judged =
        c.lockfile === "host" ||
        (companion !== undefined && sha256(state.locks[c.lockfile] ?? "") === companion.sha256);
      if (!hit && judged) {
        issues.push(
          invalid(
            "CLAIM_WITHOUT_FINDING",
            `${c.lockfile} ${c.id ?? "yanked"} ${c.crate}: a claim for a finding RustSec no longer reports must be removed, not kept as an allowance`,
          ),
        );
      }
    }
    for (const c of derived.companionLockfiles) {
      const text = state.locks[c.id];
      if (text === null || sha256(text) === c.sha256) continue;
      const lock = parseCargoLock(text);
      for (const f of c.findings) {
        if (!isPinned(lock, f.crate, f.version)) {
          issues.push(
            stale(
              "COMPANION_FINDING_NOT_IN_LOCKFILE",
              `${c.path}: ${f.key} is recorded but ${specOf(f.crate, f.version)} is no longer locked`,
            ),
          );
        }
      }
    }
    const mustFix = derived.buckets.MUST_FIX_BEFORE_REAL_PROVING.length;
    if (mustFix !== OWNER_DECISION.premise.mustFixBeforeRealProving) {
      issues.push(
        invalid(
          "PREMISE_FAILED",
          `${mustFix} finding(s) are MUST_FIX_BEFORE_REAL_PROVING; the owner's deferral was decided for none: it needs the owner again`,
        ),
      );
    }
    if (state.recordText === null) {
      issues.push(invalid("RECORD_MISSING", `${HOST_ADVISORIES_REL} is missing: generate it`));
    } else {
      let committed: Record<string, any> | null = null;
      try {
        committed = JSON.parse(state.recordText) as Record<string, any>;
      } catch {
        issues.push(invalid("RECORD_MALFORMED", `${HOST_ADVISORIES_REL} is not JSON`));
      }
      if (committed) {
        issues.push(...recordIssues(committed, derived, state));
        if (state.recordText !== serializeHostAdvisoryRecord(derived)) {
          issues.push(
            invalid(
              "RECORD_DRIFT",
              `${HOST_ADVISORIES_REL} is not what the evidence derives: regenerate it (npm run sp1:host-advisories)`,
            ),
          );
        }
      }
    }
  }
  const assessment: AssessmentStatus = issues.some((i) => i.class === "stale")
    ? "REASSESSMENT_REQUIRED"
    : issues.length > 0
      ? "RECORD_INVALID"
      : "ASSESSMENT_VALID";
  return { assessment, dependencyStatus, issues, derived };
}

/** The summary lines of a record: the dependency status first, never the assessment alone. */
export function recordSummary(r: HostAdvisoryRecord): string[] {
  const c = r.assessment.counts;
  const k = c.byKind;
  return [
    `DEPENDENCY_STATUS: ${r.assessment.dependencyStatus}: zkvm/host/Cargo.lock locks ${k.vulnerability} RustSec vulnerabilities and ${k.unsound} unsound crates (+${k.yanked} yanked, ${k.unmaintained} unmaintained); ${r.remediation.status}, nothing is patched. A valid assessment is not a fix.`,
    `BUCKETS: MUST_FIX_BEFORE_REAL_PROVING ${r.buckets.MUST_FIX_BEFORE_REAL_PROVING.length} | SHOULD_FIX_BEFORE_PRODUCTION ${r.buckets.SHOULD_FIX_BEFORE_PRODUCTION.length} | NOT_REACHABLE_OR_UPSTREAM_ONLY ${r.buckets.NOT_REACHABLE_OR_UPSTREAM_ONLY.length} (${c.compiled} of ${c.findings} compiled)`,
    `COMPANIONS: ${r.companionLockfiles.map((x) => `${x.path} ${x.vulnerabilities} vulnerabilities, ${x.warnings} warnings`).join("; ")}`,
  ];
}

/**
 * What `npm run validate:sp1-host-advisories` prints and whether it passes: it passes on ASSESSMENT_VALID alone,
 * and every report, passing or not, names the dependency status, so a green check is never read as "fixed".
 */
export function validationReport(v: Verdict): { pass: boolean; lines: string[] } {
  if (v.assessment !== "ASSESSMENT_VALID" || v.derived === null) {
    return {
      pass: false,
      lines: [
        `${v.assessment} (dependency status ${v.dependencyStatus}):`,
        ...v.issues.map((i) => ` - [${i.code}] ${i.message}`),
      ],
    };
  }
  const r = v.derived;
  return {
    pass: true,
    lines: [
      `ASSESSMENT_VALID: ${HOST_ADVISORIES_REL} is what designation ${r.subject.designation.id}'s zkvm/host subject (HEAD tree ${r.subject.zkvmHostTree}), the observation (advisory-db ${r.assessment.database.lastCommit}) and the claims derive.`,
      ...recordSummary(r),
    ],
  };
}

// ---------------------------------------------------------------------------------------------------------
// Live drift: a fresh measurement against the committed record (the networked, reporting-only job)
// ---------------------------------------------------------------------------------------------------------

export type DriftVerdict = "MATCH" | "SECURITY_DRIFT" | "RECORD_CLEANUP_REQUIRED" | "AUDIT_UNAVAILABLE";
export type DriftType =
  | "NEW_FINDING"
  | "DISAPPEARED"
  | "KIND_CHANGED"
  | "VERSION_DRIFT"
  | "ADVISORY_CHANGED"
  | "LOCKFILE_DRIFT"
  | "GRAPH_DRIFT"
  | "FIX_DRIFT"
  | "EVIDENCE_DRIFT"
  | "UNAVAILABLE";
export interface DriftItem {
  type: DriftType;
  lockfile: LockfileId | null;
  key: string | null;
  detail: string;
}
export interface DriftReport {
  verdict: DriftVerdict;
  items: DriftItem[];
  known: number;
  database: string | null;
}
const RED: ReadonlySet<DriftType> = new Set([
  "NEW_FINDING",
  "KIND_CHANGED",
  "VERSION_DRIFT",
  "ADVISORY_CHANGED",
  "LOCKFILE_DRIFT",
  "GRAPH_DRIFT",
  "FIX_DRIFT",
  "EVIDENCE_DRIFT",
]);
export const DRIFT_EXIT: Readonly<Record<DriftVerdict, number>> = {
  MATCH: 0,
  SECURITY_DRIFT: 1,
  RECORD_CLEANUP_REQUIRED: 2,
  AUDIT_UNAVAILABLE: 3,
};

/**
 * A finding's fix availability as one state: fixFactsOf sets exactly one of lockfileOnly, upstreamBlocked and
 * noPatchedRelease, so comparing the three flags one by one would make each comparison redundant with the others.
 */
export function fixStateOf(fix: FixFacts): "LOCKFILE_ONLY" | "UPSTREAM_BLOCKED" | "NO_PATCHED_RELEASE" {
  const states = [
    fix.lockfileOnly && "LOCKFILE_ONLY",
    fix.upstreamBlocked && "UPSTREAM_BLOCKED",
    fix.noPatchedRelease && "NO_PATCHED_RELEASE",
  ].filter((s): s is "LOCKFILE_ONLY" | "UPSTREAM_BLOCKED" | "NO_PATCHED_RELEASE" => typeof s === "string");
  if (states.length !== 1) throw new Error(`fix facts in ${states.length} states at once: ${JSON.stringify(fix)}`);
  return states[0];
}

/** The advisory fields whose change can change a classification; a reworded description does not. */
const comparedAdvisory = (a: AdvisoryProjection | null) =>
  a && {
    title: a.title,
    categories: a.categories,
    cvss: a.cvss,
    informational: a.informational,
    withdrawn: a.withdrawn,
    patched: a.patched,
    unaffected: a.unaffected,
    functions: a.functions,
  };

/**
 * Compares a fresh measurement with the committed record. Exact identities only (lockfile, kind, advisory id, crate,
 * version): a known justification never covers another advisory, another crate version or another lockfile. A live
 * measurement that is not a valid observation is AUDIT_UNAVAILABLE, never MATCH: unmeasured is not clean. `locks` are
 * the lockfiles the live measurement read (the checkout's); each must be the one it names, and its findings are held to it.
 */
export function rustsecDrift(
  record: HostAdvisoryRecord,
  live: unknown,
  locks: Partial<Record<LockfileId, string | null>> = {},
): DriftReport {
  const items: DriftItem[] = [];
  const obs = live as AdvisoryObservation | null;
  const unavailable = (detail: string): DriftReport => ({
    verdict: "AUDIT_UNAVAILABLE",
    items: [{ type: "UNAVAILABLE", lockfile: null, key: null, detail }],
    known: 0,
    database: null,
  });
  if (!obs || obs.schema !== ADVISORY_OBSERVATION_SCHEMA || !Array.isArray(obs.lockfiles)) {
    return unavailable("no live observation: the measurement did not complete (network, index or tool failure)");
  }
  if (obs.lockfiles.map((l) => l?.id).join() !== LOCKFILES.map((l) => l.id).join()) {
    return unavailable("the live observation does not cover the four lockfiles");
  }
  if (!/^[0-9a-f]{40}$/.test(String(obs.database?.lastCommit)))
    return unavailable("the live observation names no advisory database");
  type Facts = { findings: RecordFinding[]; sha256: string };
  const liveFacts = new Map<LockfileId, Facts>();
  for (const [i, spec] of LOCKFILES.entries()) {
    const lf = obs.lockfiles[i];
    try {
      const text = locks[spec.id];
      if (typeof text === "string" && sha256(text) !== lf.sha256) {
        throw new Error(`it measured another ${lockPathOf(spec)} than the checkout's`);
      }
      // Reachability is not compared here (it needs the repository's assumptions); identities, advisory fields,
      // graph facts, fix facts and the re-measured evidence are.
      const findings = deriveFindings(
        lf,
        typeof text === "string" ? parseCargoLock(text) : null,
        spec,
        new Map(),
        "",
        CLAIMS,
      );
      liveFacts.set(spec.id, { findings, sha256: lf.sha256 });
    } catch (error) {
      return unavailable(`the live ${spec.id} measurement is unusable: ${(error as Error).message}`);
    }
  }
  const recorded = new Map<LockfileId, { findings: RecordFinding[]; sha256: string }>([
    ["host", { findings: record.findings, sha256: record.subject.lockfile.sha256 }],
    ...record.companionLockfiles.map((c) => [c.id, { findings: c.findings, sha256: c.sha256 }] as const),
  ]);
  let known = 0;
  for (const spec of LOCKFILES) {
    const want = recorded.get(spec.id) ?? { findings: [], sha256: "" };
    const got = liveFacts.get(spec.id) as Facts;
    if (want.sha256 !== got.sha256) {
      items.push({
        type: "LOCKFILE_DRIFT",
        lockfile: spec.id,
        key: null,
        detail: `${lockPathOf(spec)} is not the lockfile the record assessed`,
      });
    }
    const ident = (f: RecordFinding) => `${f.kind}|${f.id}|${f.crate}|${f.version}`;
    const liveByIdent = new Map(got.findings.map((f) => [ident(f), f]));
    const wantByIdent = new Map(want.findings.map((f) => [ident(f), f]));
    for (const f of want.findings) {
      const l = liveByIdent.get(ident(f));
      if (l) {
        known++;
        if (!same(comparedAdvisory(f.advisory), comparedAdvisory(l.advisory))) {
          items.push({
            type: "ADVISORY_CHANGED",
            lockfile: spec.id,
            key: f.key,
            detail:
              "RustSec changed a field that can change the classification (title, categories, cvss, informational, withdrawn, ranges or functions)",
          });
        }
        // The role carries `compiled` (NOT_COMPILED exactly when not compiled), so it is not compared again.
        if (
          f.dependency.role !== l.dependency.role ||
          !same(f.dependency.directDependents, l.dependency.directDependents)
        ) {
          items.push({
            type: "GRAPH_DRIFT",
            lockfile: spec.id,
            key: f.key,
            detail: `cargo tree now says compiled=${l.compiled}, role ${l.dependency.role}, dependents ${l.dependency.directDependents.join(", ") || "none"}`,
          });
        }
        if (fixStateOf(f.fix) !== fixStateOf(l.fix)) {
          items.push({
            type: "FIX_DRIFT",
            lockfile: spec.id,
            key: f.key,
            detail: `fix availability changed from ${fixStateOf(f.fix)} to ${fixStateOf(l.fix)}`,
          });
        }
        continue;
      }
      const sameAdvisory = got.findings.find((x) => x.id !== null && x.id === f.id && x.crate === f.crate);
      if (sameAdvisory && sameAdvisory.version === f.version) {
        items.push({
          type: "KIND_CHANGED",
          lockfile: spec.id,
          key: f.key,
          detail: `RustSec now files it as ${sameAdvisory.kind}, not ${f.kind}`,
        });
      } else if (sameAdvisory) {
        items.push({
          type: "VERSION_DRIFT",
          lockfile: spec.id,
          key: f.key,
          detail: `now reported against ${specOf(sameAdvisory.crate, sameAdvisory.version)}`,
        });
      } else {
        items.push({
          type: "DISAPPEARED",
          lockfile: spec.id,
          key: f.key,
          detail: "RustSec no longer reports it here: reassess and remove it from the record and the claims",
        });
      }
    }
    for (const l of got.findings) {
      if (wantByIdent.has(ident(l))) continue;
      const covered = want.findings.some((f) => f.id !== null && f.id === l.id && f.crate === l.crate);
      if (!covered)
        items.push({
          type: "NEW_FINDING",
          lockfile: spec.id,
          key: l.key,
          detail: `${l.kind}: ${l.advisory?.title ?? "yanked release"}; no assessment covers it`,
        });
    }
  }
  const liveEvidence = liveSourceAndFeatureResults(obs);
  for (const e of record.evidence.filter((x) => x.kind !== "assumption")) {
    const l = liveEvidence.get(e.id);
    if (!l || l.holds !== e.holds) {
      items.push({
        type: "EVIDENCE_DRIFT",
        lockfile: "host",
        key: e.id,
        detail: `re-measured: ${l?.observed ?? "not measured"}`,
      });
    }
  }
  const verdict: DriftVerdict = items.some((i) => RED.has(i.type))
    ? "SECURITY_DRIFT"
    : items.some((i) => i.type === "DISAPPEARED")
      ? "RECORD_CLEANUP_REQUIRED"
      : "MATCH";
  return { verdict, items, known, database: obs.database.lastCommit };
}

function liveSourceAndFeatureResults(obs: AdvisoryObservation): Map<string, EvidenceResult> {
  const out = new Map<string, EvidenceResult>();
  const host = obs.lockfiles[0];
  const trees = Array.isArray(host?.features) ? host.features : [];
  for (const f of FEATURE_FACTS) {
    try {
      const hit = trees.filter((t) => String(t?.spec).startsWith(`${f.crate}@`));
      if (hit.length !== 1) throw new Error(`${f.crate}'s feature tree was not measured once`);
      const version = hit[0].spec.slice(f.crate.length + 1);
      const features = featuresOf(String(hit[0].output), f.crate, version);
      out.set(f.id, {
        holds: f.present.every((x) => features.includes(x)) && f.absent.every((x) => !features.includes(x)),
        observed: `features ${features.join(", ")}`,
      });
    } catch (error) {
      out.set(f.id, { holds: false, observed: (error as Error).message });
    }
  }
  for (const s of SOURCE_FACTS) {
    const o = (obs.sourceFacts ?? []).find((x) => x?.id === s.id);
    if (o && o.pattern === s.pattern && o.flags === s.flags) out.set(s.id, sourceFactResult(s, o));
  }
  return out;
}
