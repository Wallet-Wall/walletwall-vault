/**
 * Runtime-byte claim gate — every published claim about a contract's RUNTIME
 * (deployed) bytecode size must equal the compiler's own measurement.
 *
 *     compiled runtime bytecode
 *             |
 *     authoritative measurement   (the SAME primitive the EIP-170 gate uses)
 *             |
 *     published evidence / manifest / prose
 *             |
 *     claim  !=  measurement   =>   this gate fails
 *
 * WHAT THIS CLOSES. `publicHeadRuntimeBytes` for WalletWallVault read 22,367 in
 * four places for two releases after the contract had already grown to 22,574.
 * Nothing failed: that record is `remediation-gated` and carries no
 * `evidenceFile`, and scripts/validate-reproducibility.ts nests its entire
 * evidence replay inside `if (status === "reproducible")`, so the number was
 * only ever type-checked as a non-negative integer. The three prose copies were
 * read by no test at all. This gate makes that state unmergeable.
 *
 * WHY IT DOES NOT COMPARE RECORDS TO EACH OTHER. The pre-existing
 * manifest/evidence cross-check compares `publicHeadRuntimeBytes` against a
 * checked-in COPY of solc output. Two artifacts agreeing is not independent
 * evidence when both descend from the same manual capture — edit them together
 * and every gate stays green. Here the authority is always a freshly compiled
 * artifact, so unanimous agreement among declarations still fails if the
 * compiler disagrees.
 *
 * This gate is post-compile: it reads already-compiled Hardhat artifacts under
 * artifacts/contracts/ and never invokes solc itself. The
 * `prevalidate:runtime-byte-claims` npm hook runs `hardhat compile` first,
 * matching validate:bytecode-size.
 *
 * Run:
 *   npm run validate:runtime-byte-claims             # read-only check
 *   npm run validate:runtime-byte-claims -- --write  # deliberate refresh
 *
 * A check NEVER writes. Refreshing is a separate, explicit action, the same way
 * `reproducibility-evidence.ts` separates `check` from `capture-build` — a
 * check that regenerated what it was checking would always pass and prove
 * nothing.
 *
 * Exit codes:
 *   0 — every published runtime-byte claim agrees with the compiler
 *   1 — a claim is stale, conflicting, malformed, unbound, or uncovered
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { applyRuntimeByteRefresh, planRuntimeByteRefresh } from "./lib/runtime-byte-claim-refresh";
import {
  COVERED_PROSE_FILES,
  collectRuntimeByteClaims,
  PROSE_CLAIM_SITES,
  RUNTIME_BYTE_SUBJECTS,
} from "./lib/runtime-byte-claim-sources";
import { reconcileRuntimeByteClaims } from "./lib/runtime-byte-claims";

const REPO_ROOT = join(import.meta.dirname, "..");

/** Every file a refresh may need to read or rewrite, as repo-relative paths. */
function refreshableFiles(): string[] {
  const reproDir = join(REPO_ROOT, "deployments", "reproducibility");
  const files: string[] = [...COVERED_PROSE_FILES];
  if (existsSync(reproDir)) {
    for (const f of readdirSync(reproDir)) {
      if (f.endsWith(".json")) files.push(`deployments/reproducibility/${f}`);
    }
    const evidenceDir = join(reproDir, "evidence");
    if (existsSync(evidenceDir)) {
      for (const f of readdirSync(evidenceDir)) {
        if (f.endsWith(".json")) files.push(`deployments/reproducibility/evidence/${f}`);
      }
    }
  }
  return files;
}

function readAll(paths: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of paths) out[p] = readFileSync(join(REPO_ROOT, p), "utf8");
  return out;
}

function check(): number {
  console.log("WalletWall Vault — runtime-byte claim gate");
  console.log("Authority: deployedBytecode length in the compiled Hardhat artifact (never another record)\n");

  const collected = collectRuntimeByteClaims(REPO_ROOT);

  for (const m of [...collected.measurements].sort((a, b) => b.runtimeBytes - a.runtimeBytes)) {
    console.log(`  measured  ${m.subject.padEnd(32)} ${String(m.runtimeBytes).padStart(6)} bytes`);
  }
  console.log(
    `\n${collected.measurements.length} contract(s) measured, ` +
      `${collected.declarations.length} published claim(s) checked across ` +
      `${collected.coverageRequired.length} reproducibility subject(s), ` +
      `${PROSE_CLAIM_SITES.length} registered prose site(s), ` +
      `${COVERED_PROSE_FILES.length} swept document(s).`,
  );

  const reconciled = reconcileRuntimeByteClaims({
    measurements: collected.measurements,
    declarations: collected.declarations,
    coverageRequired: collected.coverageRequired,
  });

  if (collected.errors.length > 0) {
    console.error("\nCOLLECTION FAILURES — the gate itself cannot see what it claims to watch:");
    for (const e of collected.errors) console.error(`  [error] ${e}`);
  }
  if (!reconciled.ok) {
    console.error("\nSTALE OR INCONSISTENT CLAIMS:");
    for (const e of reconciled.errors) console.error(`  [error] ${e}`);
  }

  if (collected.errors.length > 0 || !reconciled.ok) {
    console.error(
      "\nFAIL: a published runtime-byte claim does not match the compiler. Refresh the claims " +
        "(`npm run validate:runtime-byte-claims -- --write`), or recapture evidence where the message says so. " +
        "Do not adjust the gate.",
    );
    return 1;
  }

  console.log("\nPASS: every published runtime-byte claim matches the compiler measurement.");
  return 0;
}

function write(): number {
  console.log("WalletWall Vault — runtime-byte claim refresh (deliberate mutation)\n");

  const collected = collectRuntimeByteClaims(REPO_ROOT);
  if (collected.measurements.length !== RUNTIME_BYTE_SUBJECTS.length) {
    console.error("Refusing to refresh: not every subject could be measured. Run `npm run compile` first.");
    for (const e of collected.errors) console.error(`  [error] ${e}`);
    return 1;
  }

  const paths = refreshableFiles();
  const files = readAll(paths);
  const plan = planRuntimeByteRefresh({ files, sites: PROSE_CLAIM_SITES, measurements: collected.measurements });

  if (plan.edits.length === 0) {
    console.log("No compiler-derived claim needed refreshing.");
  } else {
    const updated = applyRuntimeByteRefresh(files, plan.edits);
    for (const [file, text] of Object.entries(updated)) {
      writeFileSync(join(REPO_ROOT, file), text, "utf8");
    }
    for (const e of plan.edits) console.log(`  ${e.file}:${e.line}  ${e.description}`);
    console.log(`\n${plan.edits.length} claim(s) refreshed across ${Object.keys(updated).length} file(s).`);
  }

  if (plan.unfixable.length > 0) {
    console.error("\nNOT REFRESHABLE — these need a human decision or a real recapture:");
    for (const u of plan.unfixable) console.error(`  [error] ${u}`);
    return 1;
  }

  console.log("\nRe-run `npm run validate:runtime-byte-claims` to confirm.");
  return 0;
}

function main(): void {
  process.exitCode = process.argv.includes("--write") ? write() : check();
}

if (process.argv[1]?.includes("validate-runtime-byte-claims")) {
  main();
}
