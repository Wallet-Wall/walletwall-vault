/**
 * SP1 pin-parity gate (CLI).
 *
 * Enforces the invariant stated in zkvm/host/Cargo.toml — sp1-zkvm (guest),
 * sp1-sdk and sp1-build (host) must name the SAME SP1 release, exact-pinned:
 * "If you bump one, bump all three together, then re-extract the program vKey."
 *
 * Deterministic and dependency-free: pure text inspection of two Cargo.toml
 * files. No SP1 toolchain, no cargo, no network, no Rust build — which is why it
 * can run in ordinary CI even though zkvm/host itself deliberately cannot.
 *
 * This proves the three DECLARED releases agree. It does NOT prove the declared
 * release builds or proves correctly; that stays a maintainer procedure
 * (docs/ZK_Prover_Runbook.md). See scripts/lib/sp1-pin-parity.ts.
 *
 * Exit codes:
 *   0 — all three pins present, exact, and equal
 *   1 — any pin missing, loosened to a range, or disagreeing
 *
 * Run: npm run validate:sp1-pin-parity
 */
import { join } from "node:path";

import { checkSp1PinParity, readSp1Manifests, SP1_PINNED_CRATES } from "./lib/sp1-pin-parity";

const REPO_ROOT = join(import.meta.dirname, "..");

function main(): void {
  console.log("WalletWall Vault — SP1 pin parity (guest sp1-zkvm == host sp1-sdk == host sp1-build)");

  const result = checkSp1PinParity(readSp1Manifests(REPO_ROOT));

  for (const pin of result.pins) {
    const shown = pin.spec === null ? "<not declared>" : `"${pin.spec}"`;
    console.log(`  ${pin.crate.padEnd(10)} ${shown.padEnd(12)} ${pin.manifest} [${pin.section}]`);
  }

  if (!result.ok) {
    console.error(`\n${result.errors.length} problem(s):`);
    for (const e of result.errors) console.error(`  - ${e}`);
    console.error(
      "\nFAIL: the SP1 pins are not a single exact release. This gate checks DECLARATIONS only — " +
        "after correcting them, a real SP1 upgrade still requires rebuilding the guest and re-extracting " +
        "the vKey per docs/ZK_Prover_Runbook.md.",
    );
    process.exitCode = 1;
    return;
  }

  const version = result.pins[0]?.version ?? "unknown";
  console.log(
    `\nPASS: all ${SP1_PINNED_CRATES.length} SP1 crates exact-pinned to ${version}. ` +
      "(Declaration parity only — not a proof that this release builds or proves correctly.)",
  );
}

main();
