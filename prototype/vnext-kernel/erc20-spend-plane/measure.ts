/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * Prints the compile-derived measurement of the admitted-asset ERC-20 spend-plane
 * candidates, and with `--write` records it in ERC20_SPEND_PLANE_MEASUREMENTS.json.
 * The `gas`, `verdict` and `recommendation` members of that file are NOT produced
 * here: gas is measured by the Hardhat suite (test/Erc20SpendPlane.test.ts) and the
 * verdict is the record's adjudication, so `--write` preserves them.
 *
 * Run:  npx tsx prototype/vnext-kernel/erc20-spend-plane/measure.ts
 *       npx tsx prototype/vnext-kernel/erc20-spend-plane/measure.ts --write
 *
 * Never run against a coverage-instrumented tree.
 */
import fs from "node:fs";

import { compileGen1Baseline, compilePlane, measurePlane, PLANE_RECORD_JSON } from "./compile.js";

const WARNING =
  "EXPERIMENTAL PROTOTYPE. NOT AUDITED. NOT PRODUCTION. NO DEPLOYMENT. Measurement candidates for a FUTURE kernel generation; the admitted asset in every test is a local mock, and nothing here authorises real value.";

function main(): void {
  const bytes = measurePlane(compilePlane(), compileGen1Baseline());
  if (!process.argv.includes("--write")) {
    console.log(JSON.stringify(bytes, null, 2));
    return;
  }
  const existing = fs.existsSync(PLANE_RECORD_JSON)
    ? (JSON.parse(fs.readFileSync(PLANE_RECORD_JSON, "utf8")) as Record<string, unknown>)
    : {};
  const record = {
    _WARNING: WARNING,
    _CUSTODY_DOC:
      "docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md sections 7.1, 7.2 and 10; record prototype/vnext-kernel/ERC20_SPEND_PLANE_MEASUREMENT.md",
    bytes,
    gas: existing.gas ?? null,
    verdict: existing.verdict ?? "MEASUREMENT_INCONCLUSIVE",
    recommendation: existing.recommendation ?? null,
  };
  fs.writeFileSync(PLANE_RECORD_JSON, JSON.stringify(record, null, 2) + "\n");
  console.log(`Wrote ${PLANE_RECORD_JSON}`);
  console.log(
    `variant A ${bytes.variants.A.runtimeBytes} B (headroom vs ceiling ${bytes.variants.A.headroomVsTargetCeiling}), ` +
      `variant B ${bytes.variants.B.runtimeBytes} B (headroom ${bytes.variants.B.headroomVsTargetCeiling}), ` +
      `factory ${bytes.factory.runtimeBytes} B, baseline kernel re-measured ${bytes.baseline.kernel.runtimeBytes} B (declared ${bytes.baseline.kernel.declaredRuntimeBytes})`,
  );
}

main();
