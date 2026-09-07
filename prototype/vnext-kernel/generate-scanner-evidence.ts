/**
 * SCANNER/ASSURANCE EVIDENCE RECEIPT for the vNext kernel prototype.
 *
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * Regenerates prototype/vnext-kernel/SCANNER_EVIDENCE.json from a raw Slither run, and validates
 * that every own-code finding is adjudicated in slither-triage.json.
 *
 *   npx tsx prototype/vnext-kernel/generate-scanner-evidence.ts \
 *     --raw <slither --json output> \
 *     --source-subject <commit whose contracts were analyzed> \
 *     --triage-subject <commit whose triage file was used> \
 *
 * The non-scanner figures (test counts, solhint totals) come from the COMMITTED
 * scanner-evidence-inputs.json rather than from flags, so a regeneration is reproducible from
 * committed state alone and the receipt can be byte-compared. Pass --check to regenerate and
 * compare instead of writing.
 *
 * The scan that produced <raw> must be the pinned one, which CI now emits in a SINGLE execution:
 *
 *   slither prototype/vnext-kernel/contracts \
 *     --compile-force-framework solc \
 *     --solc-remaps "@openzeppelin/=node_modules/@openzeppelin/" \
 *     --solc-args "--evm-version cancun --optimize --optimize-runs 200" \
 *     --exclude-dependencies --no-fail-pedantic \
 *     --sarif slither-vnext-kernel-results.sarif --json <raw>
 *
 * `--validate` needs only --raw, --source-subject and --triage-subject.
 *
 * THREE THINGS CHANGED IN THIS LANE, EACH FIXING A MEASURED DEFECT.
 *
 * 1. IDENTITY IS NO LONGER A LOCATOR. Findings are keyed by `semanticId`
 *    (scanner-finding-identity.ts), which contains no line information. The v1 key
 *    `<check>|<sorted filename:firstLine>` named where a finding stood, so two commits that only
 *    moved code re-keyed 21 of 33 adjudicated findings and made `--validate` report them as
 *    untriaged. The v1 keys are RETAINED per entry as locators and history; nothing is deleted.
 *
 * 2. PROVENANCE IS DECLARED, NEVER SNIFFED. `head`/`tree` used to come from `git rev-parse HEAD`,
 *    which is the CONTAINER, not the subject — the same defect evidence-subject.ts documents for
 *    the stateful receipt. Both subjects are now REQUIRED ARGUMENTS, and the receipt names:
 *      sourceSubject  the commit whose scanner-semantic inputs were analyzed
 *      triageSubject  the commit whose triage file adjudicated them
 *    It names NO container. The commit that publishes this file is established afterwards from
 *    git by verify-receipt-container.ts, because an artifact embedding its own container id makes
 *    its own bytes part of the id it is trying to state.
 *
 * 3. CURRENCY IS LICENSED BY BYTE EQUALITY, NOT BY COUNTS. Carrying a scanner result from one
 *    commit to another requires the scanner-input scope to be byte-equal (scanner-input-scope.ts).
 *    Between a46bc50c and aaa21d09 the raw count (217), own count (54), distinct count (33) and
 *    ancestry ALL held while the contracts tree changed and 21 findings moved. Counts and
 *    ancestry are not evidence of currency and are not consulted.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  FINGERPRINT_ALGORITHM,
  indexFindings,
  matchFindings,
  type PriorEntry,
  type SlitherFinding,
  type SourceReader,
} from "./scanner-finding-identity.js";
import { assertScopeEquality, type ScannerInputScope } from "./scanner-input-scope.js";
import { assertWorkflowMatchesPinnedConfig, assertWorkflowOutputContract } from "./scanner-workflow-config.js";

/**
 * Field names a receipt may never carry, because each would name its own publication container.
 *
 * Enforced by NAME as well as by value. `assertReceiptDoesNotNameContainer` catches an oid that
 * equals the container, but only a name rule stops a future field being ADDED that is intended to
 * hold it -- and only the value rule catches an oid smuggled into an innocuous field. Neither
 * check subsumes the other. `head`/`tree` are here because they are exactly what the v1 receipt
 * stamped from `git rev-parse HEAD`.
 */
export const FORBIDDEN_RECEIPT_FIELDS = [
  "container",
  "publicationContainer",
  "containerHead",
  "containerTree",
  "publishedIn",
  "head",
  "tree",
] as const;

/** Throws if any forbidden field name appears anywhere in the receipt object. */
export function assertNoContainerFields(value: unknown, path: string[] = []): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoContainerFields(v, [...path, String(i)]));
    return;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if ((FORBIDDEN_RECEIPT_FIELDS as readonly string[]).includes(k)) {
      throw new Error(
        `receipt field "${[...path, k].join(".")}" is forbidden: it names, or is shaped to name, the ` +
          `commit publishing the receipt. A receipt names its SOURCE and TRIAGE subjects only; the ` +
          `container is established afterwards from git by verify-receipt-container.ts.`,
      );
    }
    assertNoContainerFields(v, [...path, k]);
  }
}

export interface ScannerEvidenceInputs {
  prototypeTests: { passing: number; failing: number };
  productionNormal: { passing: number; failing: number; pending: number };
  productionCoverage: { passing: number; failing: number; pending: number; percent: number };
  solhint: { warnings: number; errors: number };
}

const ROOT = path.join("prototype", "vnext-kernel");
const TRIAGE_PATH = path.join(ROOT, "slither-triage.json");
const RECEIPT_PATH = path.join(ROOT, "SCANNER_EVIDENCE.json");
const INPUTS_PATH = path.join(ROOT, "scanner-evidence-inputs.json");
const SCHEMA = "vnext-kernel-scanner-evidence.v2";
const TRIAGE_SCHEMA = "vnext-kernel-slither-triage.v2";

export interface TriageEntry {
  classification: string;
  rationale: string;
  locators: { current: string; previous?: string[] };
  fingerprints: { narrow?: string; broad: string };
  provenance?: Record<string, unknown>;
}

function parseArgs(argv: string[]) {
  const out: Record<string, string[]> = {};
  let current: string | null = null;
  for (const tok of argv) {
    if (tok.startsWith("--")) {
      current = tok.slice(2);
      out[current] = [];
    } else if (current) {
      out[current].push(tok);
    }
  }
  return out;
}

function git(...args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}
function sha256File(filePath: string): string {
  return createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

/** Reads project source at a revision. Bound to the SOURCE SUBJECT, never to the working tree. */
function readerAt(rev: string): SourceReader {
  const cache = new Map<string, string[]>();
  return (rel: string) => {
    if (!cache.has(rel)) {
      let text = "";
      try {
        text = execFileSync("git", ["show", `${rev}:${rel}`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      } catch {
        text = "";
      }
      cache.set(rel, text.split(/\r?\n/));
    }
    return cache.get(rel)!;
  };
}

function readMeasurements() {
  const artDir = path.join(ROOT, "artifacts", ROOT, "contracts");
  const read = (file: string, name: string) => {
    const p = path.join(artDir, file, `${name}.json`);
    const a = JSON.parse(fs.readFileSync(p, "utf8"));
    const runtime = (a.deployedBytecode.length - 2) / 2;
    return { name, runtime, runtimeSha256: createHash("sha256").update(Buffer.from(a.deployedBytecode.slice(2), "hex")).digest("hex") };
  };
  return [
    read("VaultKernelPrototype.sol", "VaultKernelPrototype"),
    read("VaultKernelFactoryPrototype.sol", "VaultKernelFactoryPrototype"),
  ];
}

function requireArg(args: Record<string, string[]>, name: string): string {
  const v = args[name]?.[0];
  if (!v) throw new Error(`--${name} <rev> is required. See this file's header comment.`);
  return v;
}

/**
 * The on-disk triage must be exactly the one the declared triage subject contains.
 *
 * Without this the generator would adjudicate against whatever happens to be in the working tree
 * while the receipt claims a different commit's triage — a provenance lie of exactly the kind this
 * lane exists to remove. Compared by BYTES, not by mtime and not by ancestry.
 */
function assertTriageMatchesSubject(triageSubject: string): void {
  const declared = git("show", `${triageSubject}:${TRIAGE_PATH.split(path.sep).join("/")}`);
  const onDisk = fs.readFileSync(TRIAGE_PATH, "utf8");
  if (declared.trim() !== onDisk.trim()) {
    throw new Error(
      `${TRIAGE_PATH} on disk differs from its content at the declared triage subject ${triageSubject}; ` +
        `the receipt would claim an adjudication that was not the one applied`,
    );
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const rawPath = args.raw?.[0];
  if (!rawPath || !fs.existsSync(rawPath)) {
    throw new Error("--raw <path-to-slither---json-output> is required. See this file's header comment.");
  }
  const validateOnly = "validate" in args;
  const sourceSubject = requireArg(args, "source-subject");
  const triageSubject = requireArg(args, "triage-subject");

  const sourceHead = git("rev-parse", sourceSubject);
  const sourceTree = git("rev-parse", `${sourceSubject}^{tree}`);
  const triageHead = git("rev-parse", triageSubject);
  const triageTree = git("rev-parse", `${triageSubject}^{tree}`);

  assertTriageMatchesSubject(triageHead);

  // The hashed config must still describe what the workflow actually runs, or
  // scannerSemanticConfigSha256 attests to a configuration nothing executes.
  assertWorkflowMatchesPinnedConfig();
  assertWorkflowOutputContract();

  // THE ONLY CURRENCY LICENCE. Throws with the differing digest named.
  const scope: ScannerInputScope = assertScopeEquality(sourceHead, triageHead, ".");

  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
  const detectors: SlitherFinding[] = raw.results?.detectors ?? [];
  const { byId, ambiguities, ownRawCount } = indexFindings(detectors, readerAt(sourceHead));

  // AMBIGUITY IS FATAL, NOT A WARNING. Two findings claiming one identity while disagreeing about
  // where they are or what they cover cannot be adjudicated as one row, and picking either would
  // silently attach a rationale to something it was not written about.
  if (ambiguities.length > 0) {
    console.error(`${ambiguities.length} ambiguous finding identit${ambiguities.length === 1 ? "y" : "ies"}:`);
    for (const a of ambiguities) console.error(`  ${a.semanticId} ${a.reason}: ${a.locators.join(" | ")}`);
    process.exit(1);
  }

  const triageFile = JSON.parse(fs.readFileSync(TRIAGE_PATH, "utf8"));
  if (triageFile.$schema !== TRIAGE_SCHEMA) {
    throw new Error(`${TRIAGE_PATH} declares ${triageFile.$schema}; this generator requires ${TRIAGE_SCHEMA}`);
  }
  // The stored fingerprints are only comparable to freshly computed ones when both come from the
  // SAME normaliser. Without this, changing comment handling would silently reclassify every
  // finding as drifted -- or, worse, appear to agree by coincidence.
  if (triageFile.keyedAt?.fingerprintAlgorithm !== FINGERPRINT_ALGORITHM) {
    throw new Error(
      `${TRIAGE_PATH} stores ${FINGERPRINT_ALGORITHM === undefined ? "no" : ""}fingerprints computed by ` +
        `"${triageFile.keyedAt?.fingerprintAlgorithm}" but this generator computes "${FINGERPRINT_ALGORITHM}"; ` +
        `re-derive the stored fingerprints rather than comparing across algorithms`,
    );
  }
  const triage = triageFile.classifications as Record<string, TriageEntry>;

  const untriaged = [...byId.keys()].filter((k) => !(k in triage));
  const stale = Object.keys(triage).filter((k) => !byId.has(k));

  // Reported TOGETHER so one run shows the whole picture, then a single exit decides.
  if (untriaged.length > 0) {
    console.error(`${untriaged.length} Slither finding(s) on prototype/vnext-kernel code have no triage entry in ${TRIAGE_PATH}:`);
    for (const k of untriaged) {
      const r = byId.get(k)!;
      console.error(`  ${k}  ${r.check}  ${r.locator}`);
    }
  }
  // STALE IS FATAL TOO, WHICH IT WAS NOT BEFORE. A console.warn is exactly how 21 entries drifted
  // out of alignment unnoticed: nothing that only warns can hold a triage to its findings.
  if (stale.length > 0) {
    console.error(`${stale.length} triage entr${stale.length === 1 ? "y" : "ies"} in ${TRIAGE_PATH} match no current finding:`);
    for (const k of stale) console.error(`  ${k}  (${triage[k].classification}) last seen at ${triage[k].locators?.current}`);
  }
  if (untriaged.length > 0 || stale.length > 0) process.exit(1);

  // Fingerprint drift within a matched identity: the finding is the same, but the source it
  // describes moved or changed. RELOCATED is fine; a context change must be re-adjudicated.
  const prior: PriorEntry[] = Object.entries(triage).map(([semanticId, e]) => ({
    semanticId,
    locator: e.locators.current,
    narrowFingerprint: e.fingerprints.narrow,
    broadFingerprint: e.fingerprints.broad,
  }));
  const matched = matchFindings(prior, byId);
  const needsReadjudication = matched.filter(
    (m) => m.klass === "SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION" || m.klass === "SEMANTIC_CHANGE_PROVEN",
  );
  if (needsReadjudication.length > 0) {
    console.error(`${needsReadjudication.length} finding(s) whose source changed since their triage entry was written:`);
    for (const m of needsReadjudication) console.error(`  ${m.klass}  ${m.current!.check}  ${m.current!.locator}`);
    process.exit(1);
  }

  const byClassification: Record<string, number> = {};
  for (const k of byId.keys()) {
    const c = triage[k].classification;
    byClassification[c] = (byClassification[c] || 0) + 1;
  }

  const relocated = matched.filter((m) => m.klass === "RELOCATED").length;
  console.log(
    `${detectors.length} raw finding(s), ${ownRawCount} own-code raw row(s), ${byId.size} distinct own-code finding(s), ` +
      `${Object.entries(byClassification).map(([k, v]) => `${v} ${k}`).join(", ")}. ` +
      `${relocated} relocated since triage, 0 untriaged, 0 stale, 0 ambiguous.`,
  );

  if (validateOnly) {
    console.log("--validate: every own-code finding is adjudicated and every triage entry still matches. OK.");
    return;
  }

  const inputs = JSON.parse(fs.readFileSync(INPUTS_PATH, "utf8")) as ScannerEvidenceInputs;

  const receipt = {
    schema: SCHEMA,
    // NAMES ITS SUBJECTS, NEVER ITS CONTAINER. The commit that publishes this file is proven
    // afterwards by verify-receipt-container.ts from git ancestry and delta; see that module and
    // evidence-subject.ts for why an artifact cannot state the id of the commit holding it.
    sourceSubject: sourceHead,
    sourceTree,
    triageSubject: triageHead,
    triageTree,
    scannerInputScope: scope,
    provenanceNote:
      "sourceSubject is the commit whose scanner-semantic inputs were analyzed; triageSubject is the commit whose slither-triage.json adjudicated them. Currency between the two is licensed ONLY by scannerInputScope byte equality -- never by equal finding counts, equal raw hashes or ancestry, all three of which held across a drift that moved 21 of 33 findings. The publication container is deliberately unnamed: verify-receipt-container.ts establishes it from git afterwards.",
    compiler: {
      solcVersion: "0.8.24",
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      viaIR: false,
    },
    scanners: {
      slither: {
        version: "pinned via https://github.com/crytic/slither.git@ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad",
        action: "crytic/slither-action@b52cc1cbfee9ca3e8722dd5224299d16c9a6b80f",
        pathsAnalyzed: ["prototype/vnext-kernel/contracts"],
        platform: "solc (crytic-compile's hardhat platform cannot resolve this project's non-default sources path -- see the vNext Kernel workflow's Slither step comment)",
        rawOutputSha256: sha256File(rawPath),
        rawFindingCount: detectors.length,
        ownCodeRawRowCount: ownRawCount,
        distinctOwnCodeFindingCount: byId.size,
        duplicateRowsFromPerEntryRecompile: ownRawCount - byId.size,
        relocatedSinceTriage: relocated,
        untriaged: 0,
        stale: 0,
        ambiguous: 0,
        triagedByClassification: byClassification,
      },
      codeql: {
        solidityCoverage: "NONE -- GitHub CodeQL has no Solidity extractor. This is a permanent vendor limitation, not a configuration gap.",
        javascriptTypescriptCoverage: {
          pathsAnalyzed: ["prototype/vnext-kernel"],
          note: "Covers the prototype's own measurement/reproduction/test TOOLING (measure.ts, reproduce.ts, decompose.ts, deltas.ts, hardhat.config.ts, test/*.ts) via the javascript-typescript language, category /language:javascript-typescript/vnext-kernel. This is NOT Solidity security analysis.",
        },
      },
      solhint: {
        run: true,
        warnings: inputs.solhint.warnings,
        errors: inputs.solhint.errors,
      },
    },
    tests: {
      prototype: { passing: inputs.prototypeTests.passing, failing: inputs.prototypeTests.failing },
      productionNormal: {
        passing: inputs.productionNormal.passing,
        failing: inputs.productionNormal.failing,
        pending: inputs.productionNormal.pending,
      },
      productionCoverage: {
        passing: inputs.productionCoverage.passing,
        failing: inputs.productionCoverage.failing,
        pending: inputs.productionCoverage.pending,
        percent: inputs.productionCoverage.percent,
      },
    },
    bytecode: readMeasurements(),
    knownAnalysisAbsences: [
      "No third-party audit.",
      "No fuzzing campaign, no formal verification (T0/T1 invariants are argued and tested, not proven).",
      "GitHub CodeQL provides no Solidity semantic analysis of prototype/vnext-kernel/contracts (vendor limitation).",
      "Slither's own coverage is bounded by what its detectors can express -- see AUTHORITY.md section 7 for what this analysis does not establish, independent of any scanner.",
      "PQ verifier is structural/mock; no cryptographic claim about the PQ leg (AUTHORITY.md section 7.3).",
      "Guardian independence is assumed, not enforced on-chain (AUTHORITY.md section 7.4 / H-31).",
      "Semantic finding identity is derived from Slither's own element chain and message. A detector that reported the same construct under a different chain would present as ADDED plus REMOVED rather than as a change, which is the conservative direction but is not free of judgement.",
    ],
  };

  assertNoContainerFields(receipt);
  const serialized = `${JSON.stringify(receipt, null, 2)}\n`;

  // BYTE IDENTITY. Regeneration now depends only on committed inputs, the raw run and git, so CI
  // can rebuild the receipt and compare bytes. A hand-edit to ANY field -- including one that
  // leaves 217/54/33 and every triage entry valid -- no longer survives, because the compared
  // bytes are derived rather than read back from the file being checked.
  if ("check" in args) {
    const committed = fs.readFileSync(RECEIPT_PATH, "utf8");
    if (committed !== serialized) {
      const a = committed.split("\n");
      const b = serialized.split("\n");
      const firstDiff = a.findIndex((line, i) => line !== b[i]);
      console.error(`${RECEIPT_PATH} is not byte-identical to a regeneration from its declared subjects.`);
      console.error(`  committed bytes : ${committed.length}`);
      console.error(`  regenerated     : ${serialized.length}`);
      if (firstDiff >= 0) {
        console.error(`  first difference at line ${firstDiff + 1}:`);
        console.error(`    committed   : ${JSON.stringify(a[firstDiff])}`);
        console.error(`    regenerated : ${JSON.stringify(b[firstDiff])}`);
      }
      process.exit(1);
    }
    console.log(`--check: ${RECEIPT_PATH} is byte-identical to a regeneration from its declared subjects. OK.`);
    return;
  }

  fs.writeFileSync(RECEIPT_PATH, serialized);
  console.log(`Wrote ${RECEIPT_PATH}`);
}

// Only runs as a CLI. The module also EXPORTS its receipt rules so tests can exercise them
// directly; without this guard, importing it would regenerate evidence as a side effect.
if (process.argv[1] && process.argv[1].endsWith("generate-scanner-evidence.ts")) {
  main();
}
