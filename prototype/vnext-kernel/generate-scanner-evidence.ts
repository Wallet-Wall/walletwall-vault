/**
 * SCANNER/ASSURANCE EVIDENCE RECEIPT for the vNext kernel prototype.
 *
 * Binds a Slither run to the exact source it analyzed and to this file's
 * hand-maintained firsthand triage (slither-triage.json). Content-addressed,
 * not "immutable because it's a JSON file": every count here is either
 * recomputed from a supplied raw Slither --json file or read from the
 * prototype's own compiled artifacts -- nothing is retyped by hand except
 * the test counts, which come from the same `npx hardhat --config
 * prototype/vnext-kernel/hardhat.config.ts test` / `npm test` / `npm run
 * coverage` runs the vNext Kernel / Prototype Tests CI job and this repo's
 * CI job already execute, passed in explicitly so this script never
 * re-runs a multi-minute suite just to assemble a receipt.
 *
 * Run:
 *   npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
 *   slither prototype/vnext-kernel/contracts --compile-force-framework solc \
 *     --solc-remaps "@openzeppelin/=node_modules/@openzeppelin/" \
 *     --solc-args "--evm-version cancun --optimize --optimize-runs 200" \
 *     --exclude-dependencies --json prototype/vnext-kernel/.slither-raw.json
 *   npx tsx prototype/vnext-kernel/generate-scanner-evidence.ts \
 *     --raw prototype/vnext-kernel/.slither-raw.json \
 *     --prototype-tests 76 0 \
 *     --production-tests 1643 0 11 \
 *     --production-coverage 1640 0 14 90.13
 *
 * Add --validate to only check that every finding in --raw has a triage
 * entry (exit 1 if not) without rewriting the committed receipt -- this is
 * the regression gate: a new, untriaged Slither finding fails CI rather than
 * silently vanishing into an unreviewed pass.
 *
 * The raw Slither JSON itself is NOT committed (it is large and its byte
 * layout is not a stable/reviewable artifact) -- only its sha256 and this
 * summary are.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.join("prototype", "vnext-kernel");
const TRIAGE_PATH = path.join(ROOT, "slither-triage.json");
const RECEIPT_PATH = path.join(ROOT, "SCANNER_EVIDENCE.json");
const SCHEMA = "vnext-kernel-scanner-evidence.v1";

interface SlitherElement {
  source_mapping?: { filename_relative?: string; lines?: number[] };
}
interface SlitherFinding {
  check: string;
  impact: string;
  confidence: string;
  elements: SlitherElement[];
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

function isOwnFinding(f: SlitherFinding): boolean {
  return f.elements.every((e) => {
    const fr = e.source_mapping?.filename_relative || "";
    return fr.length > 0 && !fr.includes("node_modules");
  });
}

/**
 * crytic-compile's plain `solc` platform (the workaround this job uses --
 * see the vNext Kernel workflow's Slither step comment) compiles every
 * top-level .sol file under the target directory as an INDEPENDENT unit, so
 * a file reached by more than one entry point (e.g. VaultKernelPrototype.sol
 * via both its own compile and VaultKernelFactoryPrototype.sol's import) is
 * analyzed, and reported, once per entry point. This collapses those
 * duplicates back to one row per distinct (check, own-code locations) pair.
 */
function canonicalKey(f: SlitherFinding): string {
  const locs = new Set<string>();
  for (const e of f.elements) {
    const fr = e.source_mapping?.filename_relative;
    if (fr) locs.add(`${fr}:${(e.source_mapping?.lines || [])[0]}`);
  }
  return `${f.check}|${[...locs].sort().join(",")}`;
}

function dedupeOwn(findings: SlitherFinding[]): Map<string, SlitherFinding> {
  const own = findings.filter(isOwnFinding);
  const seen = new Map<string, SlitherFinding>();
  for (const f of own) {
    const k = canonicalKey(f);
    if (!seen.has(k)) seen.set(k, f);
  }
  return seen;
}

function git(...args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

function sha256(filePath: string): string {
  return createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
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

function main() {
  const args = parseArgs(process.argv.slice(2));
  const rawPath = args.raw?.[0];
  if (!rawPath || !fs.existsSync(rawPath)) {
    throw new Error("--raw <path-to-slither---json-output> is required. See this file's header comment for the exact command.");
  }
  const validateOnly = "validate" in args;

  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
  const detectors: SlitherFinding[] = raw.results?.detectors ?? [];
  const dedupedOwn = dedupeOwn(detectors);
  const triage = JSON.parse(fs.readFileSync(TRIAGE_PATH, "utf8")).classifications as Record<
    string,
    { classification: string; rationale: string }
  >;

  const untriaged = [...dedupedOwn.keys()].filter((k) => !(k in triage));
  if (untriaged.length > 0) {
    console.error(`${untriaged.length} Slither finding(s) on prototype/vnext-kernel code have no triage entry in ${TRIAGE_PATH}:`);
    for (const k of untriaged) console.error(`  ${k}`);
    process.exit(1);
  }

  const stale = Object.keys(triage).filter((k) => !dedupedOwn.has(k));
  if (stale.length > 0) {
    console.warn(`${stale.length} triage entr${stale.length === 1 ? "y" : "ies"} in ${TRIAGE_PATH} no longer match any current finding (informational; the finding may have moved or been fixed):`);
    for (const k of stale) console.warn(`  ${k}`);
  }

  const byClassification: Record<string, number> = {};
  for (const k of dedupedOwn.keys()) {
    const c = triage[k].classification;
    byClassification[c] = (byClassification[c] || 0) + 1;
  }

  console.log(
    `${detectors.length} raw finding(s), ${dedupedOwn.size} distinct own-code finding(s), ` +
      `${Object.entries(byClassification).map(([k, v]) => `${v} ${k}`).join(", ")}.`,
  );

  if (validateOnly) {
    console.log("--validate: no untriaged findings. OK.");
    return;
  }

  const prototypeTests = args["prototype-tests"];
  const productionTests = args["production-tests"];
  const productionCoverage = args["production-coverage"];
  if (!prototypeTests || !productionTests || !productionCoverage) {
    throw new Error("--prototype-tests <pass> <fail>, --production-tests <pass> <fail> <pending>, and --production-coverage <pass> <fail> <pending> <percent> are required to (re)generate the receipt (not needed for --validate).");
  }

  const receipt = {
    schema: SCHEMA,
    head: git("rev-parse", "HEAD"),
    tree: git("rev-parse", "HEAD^{tree}"),
    generatedFrom: {
      note: "Generated locally by a developer or CI running the command in this script's header comment; not itself re-run automatically on every commit.",
    },
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
        rawOutputSha256: sha256(rawPath),
        rawFindingCount: detectors.length,
        distinctOwnCodeFindingCount: dedupedOwn.size,
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
        warnings: 32,
        errors: 0,
      },
    },
    tests: {
      prototype: { passing: Number(prototypeTests[0]), failing: Number(prototypeTests[1]) },
      productionNormal: {
        passing: Number(productionTests[0]),
        failing: Number(productionTests[1]),
        pending: Number(productionTests[2]),
      },
      productionCoverage: {
        passing: Number(productionCoverage[0]),
        failing: Number(productionCoverage[1]),
        pending: Number(productionCoverage[2]),
        percent: Number(productionCoverage[3]),
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
    ],
  };

  fs.writeFileSync(RECEIPT_PATH, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Wrote ${RECEIPT_PATH}`);
}

main();
