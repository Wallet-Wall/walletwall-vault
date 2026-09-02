/**
 * vNext Kernel authority-path completeness checker (PHASE 4/12).
 *
 * FAILS CLOSED. Every branch below that cannot positively establish
 * completeness/correctness ends in a violation, never a silent pass. See
 * authority/README.md for the full design rationale, what is independently
 * DERIVED (the external surface, the gate/ordering trace) versus DECLARED
 * (outcome taxonomy, expected mechanism, expected cut, ordering
 * exceptions), and this checker's own known limitations.
 *
 * Run:
 *   npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
 *   npx tsx prototype/vnext-kernel/authority/check.ts
 *   npx tsx prototype/vnext-kernel/authority/check.ts --out prototype/vnext-kernel/AUTHORITY_CENSUS.json
 *
 * Exit code 0 only if every discovered state-changing function is
 * classified, every expected mechanism is observed with no order
 * violation, and no manifest entry is stale or malformed. Any other
 * outcome exits 1.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { type CompiledSources, loadCompiledSources } from "./ast.js";
import { type DiscoveredFunction, discoverSurface, traceDiscoveredFunction } from "./discover.js";
import { type GateMechanism, type GateTraceResult, resolvePrimitiveIds } from "./trace.js";

const ROOT = path.join("prototype", "vnext-kernel");
const AUTHORITY_DIR = path.join(ROOT, "authority");
const MANIFEST_PATH = path.join(AUTHORITY_DIR, "authority-manifest.json");
const BUILD_INFO_DIR = path.join(ROOT, "artifacts", "build-info");

const CONTRACTS = ["VaultKernelPrototype", "VaultKernelFactoryPrototype"] as const;
const KERNEL_CONTRACT = "VaultKernelPrototype";

const KNOWN_OUTCOMES = new Set([
  "ASSET_MOVEMENT",
  "CREDENTIAL_REPLACEMENT",
  "VERIFIER_REPLACEMENT",
  "POLICY_CHANGE",
  "GUARDIAN_CHANGE",
  "RECOVERY_START",
  "RECOVERY_CANCEL",
  "RECOVERY_COMPLETION",
  "MIGRATION",
  "CONTAINMENT_OR_SAFE_STATE_CHANGE",
  "COUNTERFACTUAL_IDENTITY_CREATION",
  "GENESIS_AUTHORITY_CREATION",
]);
const KNOWN_MECHANISMS = new Set<GateMechanism>(["HYBRID", "FLOOR_ONLY", "QUORUM", "POSSESSION_PROOF"]);

export interface ManifestEntry {
  signature: string;
  outcomes: string[];
  expectedMechanisms: GateMechanism[];
  expectedCut: string;
  orderingExceptionReason: string | null;
  justification: string;
}

export interface Manifest {
  entries: Record<string, ManifestEntry>;
}

type Verdict =
  | "PASS"
  | "PASS_WITH_DECLARED_EXCEPTION"
  | "UNCLASSIFIED_EXTERNAL_STATE_CHANGE"
  | "STALE_MANIFEST_ENTRY"
  | "MECHANISM_MISMATCH"
  | "ORDER_VIOLATION"
  | "UNRESOLVED_ORDERING_NO_EXCEPTION"
  | "MALFORMED_MANIFEST_ENTRY";

interface CensusRow {
  key: string;
  contract: string;
  signature: string;
  kind: string;
  visibility: string;
  stateMutability: string;
  isStateChanging: boolean;
  astId: number;
  observedMechanisms?: GateMechanism[];
  observedOrderOk?: boolean;
  observedUnresolved?: boolean;
  observedUnresolvedReasons?: string[];
  manifest?: ManifestEntry;
  verdict?: Verdict;
  reasons: string[];
}

function detectDuplicateKeys(rawText: string): string[] {
  // Cheap, source-bound hygiene check: JSON.parse silently keeps only the LAST of any
  // textually duplicated key, which would hide an intended distinct manifest entry.
  // Scans only the top-level "entries" object's direct keys (4-space indented,
  // matching this file's own formatting), not a general JSON parser.
  const entriesStart = rawText.indexOf('"entries"');
  if (entriesStart === -1) return [];
  const body = rawText.slice(entriesStart);
  const keyPattern = /^ {4}"([^"]+)":\s*\{/gm;
  const seen = new Map<string, number>();
  const dupes: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = keyPattern.exec(body))) {
    const key = m[1];
    seen.set(key, (seen.get(key) ?? 0) + 1);
    if (seen.get(key) === 2) dupes.push(key);
  }
  return dupes;
}

export function loadManifest(): Manifest {
  const rawText = fs.readFileSync(MANIFEST_PATH, "utf8");
  const dupes = detectDuplicateKeys(rawText);
  if (dupes.length > 0) {
    throw new Error(`duplicate manifest key(s), JSON.parse would silently drop all but the last: ${dupes.join(", ")}`);
  }
  return JSON.parse(rawText) as Manifest;
}

export function keyOf(fn: DiscoveredFunction): string {
  const tail = fn.kind === "function" ? fn.selector : fn.kind;
  return `${fn.contract}:${tail}`;
}

function validateManifestEntry(key: string, entry: ManifestEntry): string[] {
  const problems: string[] = [];
  if (!Array.isArray(entry.outcomes)) problems.push("outcomes is not an array");
  for (const o of entry.outcomes ?? []) if (!KNOWN_OUTCOMES.has(o)) problems.push(`unrecognized outcome "${o}"`);
  if (!Array.isArray(entry.expectedMechanisms)) problems.push("expectedMechanisms is not an array");
  for (const m of entry.expectedMechanisms ?? []) if (!KNOWN_MECHANISMS.has(m)) problems.push(`unrecognized mechanism "${m}"`);
  if (typeof entry.expectedCut !== "string" || entry.expectedCut.trim().length === 0) problems.push("missing expectedCut");
  if (typeof entry.justification !== "string" || entry.justification.trim().length === 0) problems.push("missing justification");
  return problems;
}

function evaluate(row: CensusRow, entry: ManifestEntry, trace: GateTraceResult): { verdict: Verdict; reasons: string[] } {
  const malformed = validateManifestEntry(row.key, entry);
  if (malformed.length > 0) return { verdict: "MALFORMED_MANIFEST_ENTRY", reasons: malformed };

  if (trace.mechanismsReachedAfterEffect.length > 0) {
    return {
      verdict: "ORDER_VIOLATION",
      reasons: [`mechanism(s) ${trace.mechanismsReachedAfterEffect.join(",")} only reached AFTER a state effect -- the gate does not actually precede the privileged action`],
    };
  }

  const observed = new Set(trace.mechanismsReached);
  const expected = new Set(entry.expectedMechanisms);
  const missing = [...expected].filter((m) => !observed.has(m));
  const extra = [...observed].filter((m) => !expected.has(m));
  if (missing.length > 0 || extra.length > 0) {
    const reasons: string[] = [];
    if (missing.length > 0) reasons.push(`expected mechanism(s) not observed before any effect: ${missing.join(",")}`);
    if (extra.length > 0) reasons.push(`observed mechanism(s) not declared in the manifest: ${extra.join(",")}`);
    return { verdict: "MECHANISM_MISMATCH", reasons };
  }

  if (trace.unresolved) {
    if (!entry.orderingExceptionReason || entry.orderingExceptionReason.trim().length === 0) {
      return {
        verdict: "UNRESOLVED_ORDERING_NO_EXCEPTION",
        reasons: [`static ordering analysis could not fully resolve this function and no orderingExceptionReason is declared: ${trace.unresolvedReasons.join("; ")}`],
      };
    }
    return { verdict: "PASS_WITH_DECLARED_EXCEPTION", reasons: [`unresolved statement(s) present, covered by declared exception: ${entry.orderingExceptionReason}`] };
  }

  return { verdict: "PASS", reasons: [] };
}

export interface CheckReport {
  schema: string;
  head: string;
  tree: string;
  compiler: { solcVersion: string; evmVersion: string };
  derivation: {
    externalSurface: "independently derived from compiled AST (solc standard-json), not from the manifest or from remembered names";
    gateOrderingTrace: "independently derived from the same AST -- gate primitive identification is by resolved declaration id, not name string; statement order is source order";
    outcomeTaxonomy: "declared -- see authority-manifest.json";
    expectedMechanismAndCut: "declared -- architecture citation + implementation cross-check, see authority-manifest.json's justification field per entry";
  };
  gatePrimitives: string[];
  contracts: string[];
  rows: CensusRow[];
  summary: {
    total: number;
    pass: number;
    passWithDeclaredException: number;
    failed: number;
    byVerdict: Record<string, number>;
  };
  manifestHash: string;
  checkerHash: string;
}

export interface RunCheckOptions {
  /** Defaults to loading prototype/vnext-kernel/artifacts/build-info from disk. Mutation tests supply an in-memory CompiledSources instead. */
  compiled?: CompiledSources;
  /** Defaults to authority-manifest.json from disk. Mutation tests supply an in-memory override, e.g. to simulate a manifest entry for a fixture-only function. */
  manifest?: Manifest;
  /** Skip git/hash bookkeeping (not meaningful for an in-memory mutation compile). */
  skipProvenance?: boolean;
}

export function runCheck(options: RunCheckOptions = {}): CheckReport {
  const compiled: CompiledSources = options.compiled ?? loadCompiledSources(BUILD_INFO_DIR);
  const kernelContractNode = (() => {
    for (const key of Object.keys(compiled.bySourceKey)) {
      const ast = compiled.bySourceKey[key].ast;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const hit = (ast.nodes as any[]).find((n) => n.nodeType === "ContractDefinition" && n.name === KERNEL_CONTRACT);
      if (hit) return hit;
    }
    throw new Error(`kernel contract "${KERNEL_CONTRACT}" not found in compiled output`);
  })();
  const primitives = resolvePrimitiveIds(kernelContractNode);
  const manifest = options.manifest ?? loadManifest();

  const rows: CensusRow[] = [];
  const usedManifestKeys = new Set<string>();

  for (const contractName of CONTRACTS) {
    const fns = discoverSurface(compiled, primitives, contractName);
    for (const fn of fns) {
      const key = keyOf(fn);
      const row: CensusRow = {
        key,
        contract: fn.contract,
        signature: fn.signature,
        kind: fn.kind,
        visibility: fn.visibility,
        stateMutability: fn.stateMutability,
        isStateChanging: fn.isStateChanging,
        astId: fn.astId,
        reasons: [],
      };
      if (!fn.isStateChanging) {
        rows.push(row); // recorded for completeness (PHASE 1's view/pure classification bucket), no manifest required
        continue;
      }

      const trace = traceDiscoveredFunction(compiled, primitives, fn);
      row.observedMechanisms = trace.mechanismsReached;
      row.observedOrderOk = trace.orderOk;
      row.observedUnresolved = trace.unresolved;
      row.observedUnresolvedReasons = trace.unresolvedReasons;

      const entry = manifest.entries[key];
      if (!entry) {
        row.verdict = "UNCLASSIFIED_EXTERNAL_STATE_CHANGE";
        row.reasons = [`no authority-manifest.json entry for key "${key}" -- a new or renamed externally reachable state-changing function must be classified before it can pass`];
        rows.push(row);
        continue;
      }
      usedManifestKeys.add(key);
      row.manifest = entry;
      const { verdict, reasons } = evaluate(row, entry, trace);
      row.verdict = verdict;
      row.reasons = reasons;
      rows.push(row);
    }
  }

  for (const key of Object.keys(manifest.entries)) {
    if (usedManifestKeys.has(key)) continue;
    rows.push({
      key,
      contract: key.split(":")[0],
      signature: manifest.entries[key].signature,
      kind: "function",
      visibility: "?",
      stateMutability: "?",
      isStateChanging: true,
      astId: -1,
      verdict: "STALE_MANIFEST_ENTRY",
      reasons: [`manifest entry "${key}" does not match any function discovered in the current compiled source -- it was removed, renamed, or the compile is stale`],
    });
  }

  const byVerdict: Record<string, number> = {};
  let pass = 0;
  let passWithException = 0;
  let failed = 0;
  const gatedRows = rows.filter((r) => r.isStateChanging || r.verdict === "STALE_MANIFEST_ENTRY");
  for (const r of gatedRows) {
    const v = r.verdict ?? "PASS";
    byVerdict[v] = (byVerdict[v] ?? 0) + 1;
    if (v === "PASS") pass++;
    else if (v === "PASS_WITH_DECLARED_EXCEPTION") passWithException++;
    else failed++;
  }

  const head = options.skipProvenance ? "" : execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const tree = options.skipProvenance ? "" : execFileSync("git", ["rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim();
  const manifestHash = options.skipProvenance ? "" : createHash("sha256").update(fs.readFileSync(MANIFEST_PATH)).digest("hex");
  const checkerHash = options.skipProvenance
    ? ""
    : createHash("sha256")
        .update(Buffer.concat(["ast.ts", "trace.ts", "discover.ts", "check.ts"].map((f) => fs.readFileSync(path.join(AUTHORITY_DIR, f)))))
        .digest("hex");

  return {
    schema: "vnext-kernel-authority-census.v1",
    head,
    tree,
    compiler: { solcVersion: "0.8.24", evmVersion: "cancun" },
    derivation: {
      externalSurface: "independently derived from compiled AST (solc standard-json), not from the manifest or from remembered names",
      gateOrderingTrace: "independently derived from the same AST -- gate primitive identification is by resolved declaration id, not name string; statement order is source order",
      outcomeTaxonomy: "declared -- see authority-manifest.json",
      expectedMechanismAndCut: "declared -- architecture citation + implementation cross-check, see authority-manifest.json's justification field per entry",
    },
    gatePrimitives: ["_authorise", "_floorAuthorises", "_requireQuorum", "_requireIncomingPossession"],
    contracts: [...CONTRACTS],
    rows,
    summary: { total: gatedRows.length, pass, passWithDeclaredException: passWithException, failed, byVerdict },
    manifestHash,
    checkerHash,
  };
}

function main(): void {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf("--out");
  const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

  const report = runCheck();

  console.log(`vNext Kernel authority completeness: ${report.summary.total} gated entries, ${report.summary.pass} PASS, ${report.summary.passWithDeclaredException} PASS_WITH_DECLARED_EXCEPTION, ${report.summary.failed} FAILED`);
  for (const row of report.rows) {
    if (!row.verdict || row.verdict === "PASS") continue;
    console.log(`  [${row.verdict}] ${row.key} ${row.signature}`);
    for (const reason of row.reasons) console.log(`      ${reason}`);
  }

  if (outPath) {
    fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`Wrote ${outPath}`);
  }

  if (report.summary.failed > 0) {
    console.error(`FAIL: ${report.summary.failed} authority completeness violation(s).`);
    process.exit(1);
  }
  console.log("PASS.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
