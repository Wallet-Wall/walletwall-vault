/**
 * Generate (and validate) the SP1 implementation lane's receipt, evidence/zk/sp1-impl/implementation-receipt.json;
 * see scripts/lib/sp1-impl-receipt.ts.
 *
 *   npm run sp1-impl:receipt                # derive and write it; the base is the merge base of HEAD and origin/main
 *                                           # (or -- --base <commit>)
 *   npm run validate:sp1-impl-receipt       # re-derive it from its committed base and compare, byte for byte
 *
 * Both compile first (npm pre-scripts). No network, no transactions. Research prototype. Not audited. Testnet/local
 * only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  IMPL_RECEIPT_REL,
  deriveImplReceipt,
  implReceiptErrors,
  readImplReceiptInputs,
  serializeImplReceipt,
} from "./lib/sp1-impl-receipt";

try {
  if (process.argv.includes("--validate")) {
    const errors = implReceiptErrors(".");
    if (errors.length > 0) throw new Error(`the implementation receipt is invalid:\n - ${errors.join("\n - ")}`);
    console.log(`OK: ${IMPL_RECEIPT_REL} is what the repository derives.`);
  } else {
    const at = process.argv.indexOf("--base");
    const base =
      at !== -1
        ? String(process.argv[at + 1])
        : execFileSync("git", ["merge-base", "HEAD", "origin/main"], { encoding: "utf8" }).trim();
    const receipt = deriveImplReceipt(readImplReceiptInputs(".", base));
    mkdirSync(dirname(resolve(IMPL_RECEIPT_REL)), { recursive: true });
    writeFileSync(resolve(IMPL_RECEIPT_REL), serializeImplReceipt(receipt));
    console.log(
      `${IMPL_RECEIPT_REL}: ${receipt.verdict}; PRODUCTION_SP1_BINDING_STATUS ${receipt.statuses.PRODUCTION_SP1_BINDING_STATUS.value}`,
    );
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
