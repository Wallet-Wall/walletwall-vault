/**
 * Generate (and validate) the SP1-P1 assurance STOP receipt at evidence/zk/sp1-p1/stop-receipt.json.
 *
 * The receipt is derived from the committed raw observations (evidence/zk/sp1-p1/observations/) and the
 * repository's own bytes; see scripts/lib/sp1-p1-stop-receipt.ts. The observations themselves come from
 * measurements outside the repository (SP1 builds in three environments, read-only chain reads, solc
 * recompilation) and are never rewritten here.
 *
 * Usage:
 *   npm run sp1-p1:receipt            # (re)write the receipt; refuses stale sources or a changed premise
 *   npm run validate:sp1-p1-receipt   # validate the committed receipt, exit non-zero on any error
 *
 * No transactions, no deploys, no proving, no network.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  RECEIPT_REL,
  buildReceipt,
  checkInputsFresh,
  readObservationInputs,
  validateCommittedReceipt,
  validateReceiptRules,
} from "./lib/sp1-p1-stop-receipt";

export const RECEIPT_PATH = resolve(RECEIPT_REL);

function writeReceipt(): void {
  const inputs = readObservationInputs();
  const stale = checkInputsFresh(inputs);
  if (stale.length > 0) throw new Error(`refusing to generate the SP1-P1 receipt:\n - ${stale.join("\n - ")}`);
  const receipt = buildReceipt(inputs);
  const rules = validateReceiptRules(receipt);
  if (rules.length > 0) throw new Error(`generated receipt violates the lane rules:\n - ${rules.join("\n - ")}`);
  writeFileSync(RECEIPT_PATH, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Wrote ${RECEIPT_PATH}`);
}

function validateCommitted(): void {
  const committed = JSON.parse(readFileSync(RECEIPT_PATH, "utf8")) as unknown;
  const errors = validateCommittedReceipt(committed, readObservationInputs());
  if (errors.length > 0) throw new Error(`committed SP1-P1 receipt is invalid:\n - ${errors.join("\n - ")}`);
  console.log(`OK: ${RECEIPT_PATH} matches its observations, the subject sources and the lane rules (no drift).`);
}

if (process.argv[1]?.includes("generate-sp1-p1-stop-receipt")) {
  try {
    if (process.argv.includes("--validate")) validateCommitted();
    else writeReceipt();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
