/**
 * Generate (and validate) the SP1-TD1 decision receipt at evidence/zk/sp1-td1/decision-receipt.json.
 *
 * The receipt is derived from evidence/zk/sp1-td1/decision-inputs.json, the TD1 raw observations, the SP1-P1
 * observations and the zkvm sources on disk; see scripts/lib/sp1-td1-decision.ts. The observations come from
 * measurements outside the repository (read-only chain reads on four chains, registry reads, an SP1 build
 * probe) and are never rewritten here; the probe facts are re-executed by test/Sp1Td1TrustTargetProbes.test.ts.
 *
 * Usage:
 *   npm run sp1-td1:receipt            # (re)write the receipt; refuses stale evidence or a moved subject
 *   npm run validate:sp1-td1-receipt   # validate the committed receipt, exit non-zero on any error
 *
 * No transactions, no deploys, no proving, no network.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  TD1_RECEIPT_REL,
  buildDecisionReceipt,
  checkContextFresh,
  readDecisionContext,
  validateCommittedDecisionReceipt,
  validateDecisionRules,
} from "./lib/sp1-td1-decision";

export const TD1_RECEIPT_PATH = resolve(TD1_RECEIPT_REL);

function writeReceipt(): void {
  const ctx = readDecisionContext();
  const stale = checkContextFresh(ctx);
  if (stale.length > 0) throw new Error(`refusing to generate the SP1-TD1 receipt:\n - ${stale.join("\n - ")}`);
  const receipt = buildDecisionReceipt(ctx);
  const rules = validateDecisionRules(receipt);
  if (rules.length > 0) throw new Error(`generated receipt violates the lane rules:\n - ${rules.join("\n - ")}`);
  writeFileSync(TD1_RECEIPT_PATH, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`Wrote ${TD1_RECEIPT_PATH}`);
}

function validateCommitted(): void {
  const committed = JSON.parse(readFileSync(TD1_RECEIPT_PATH, "utf8")) as unknown;
  const errors = validateCommittedDecisionReceipt(committed, readDecisionContext());
  if (errors.length > 0) throw new Error(`committed SP1-TD1 receipt is invalid:\n - ${errors.join("\n - ")}`);
  console.log(
    `OK: ${TD1_RECEIPT_PATH} matches its inputs, observations, the zkvm subject and the lane rules (no drift).`,
  );
}

if (process.argv[1]?.includes("generate-sp1-td1-decision-receipt")) {
  try {
    if (process.argv.includes("--validate")) validateCommitted();
    else writeReceipt();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
