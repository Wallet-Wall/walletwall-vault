/**
 * Generate (and validate) the SP1 implementation lane's receipt, evidence/zk/sp1-impl/implementation-receipt.json;
 * see scripts/lib/sp1-impl-receipt.ts.
 *
 *   npm run sp1-impl:receipt                # derive and write it; the base is the merge base of HEAD and origin/main
 *                                           # (or -- --base <commit>). Refused once the receipt is merged: a lane's base
 *                                           # precedes its receipt, and a historical receipt is never regenerated
 *   npm run validate:sp1-impl-receipt       # bind this tree to the receipt's integrated subject, then re-derive the
 *                                           # receipt from its historical base and compare, byte for byte
 *   npx tsx scripts/generate-sp1-impl-receipt.ts --integration
 *                                           # write evidence/zk/sp1-impl/receipt-integration.json, the binding derived
 *                                           # from git (scripts/lib/sp1-impl-receipt-integration.ts)
 *   npx tsx scripts/generate-sp1-impl-receipt.ts --supersession --lane <id> --record <path> --reason "<why>"
 *                                           # write evidence/zk/sp1-impl/receipt-supersession.json once a later lane's
 *                                           # record moved proving availability (SP1-PA2B): the receipt's bytes are
 *                                           # pinned, PROVING_AVAILABILITY is derived at the merge base of HEAD and
 *                                           # origin/main (where the receipt was last live), and the file is created
 *                                           # once; it is validated, never trusted, by validate:sp1-impl-receipt
 *
 * The first two compile first (npm pre-scripts). No network, no transactions. Research prototype. Not audited.
 * Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  IMPL_RECEIPT_REL,
  IMPL_SUPERSESSION_REL,
  IMPL_SUPERSESSION_SCHEMA,
  SUPERSEDABLE_STATUSES,
  deriveImplReceipt,
  implReceiptErrors,
  implSupersessionErrors,
  readImplReceiptInputs,
  serializeImplReceipt,
  type ImplSupersession,
} from "./lib/sp1-impl-receipt";
import { writeNewFiles } from "./lib/write-once";
import {
  IMPL_RECEIPT_INTEGRATION_REL,
  MAIN_REF,
  deriveReceiptIntegration,
  gitObjects,
  serializeReceiptIntegration,
} from "./lib/sp1-impl-receipt-integration";

async function main() {
  if (process.argv.includes("--validate")) {
    const errors = await implReceiptErrors(".");
    if (errors.length > 0) throw new Error(`the implementation receipt is invalid:\n - ${errors.join("\n - ")}`);
    console.log(`OK: ${IMPL_RECEIPT_REL} is what the repository derives, bound to its integrated subject.`);
  } else if (process.argv.includes("--supersession")) {
    const arg = (name: string) => {
      const i = process.argv.indexOf(name);
      const v = i === -1 ? undefined : process.argv[i + 1];
      if (!v) throw new Error(`${name} is required`);
      return v;
    };
    const receiptBytes = readFileSync(resolve(IMPL_RECEIPT_REL));
    const supersession: ImplSupersession = {
      schema: IMPL_SUPERSESSION_SCHEMA,
      receipt: IMPL_RECEIPT_REL,
      receiptSha256: createHash("sha256").update(receiptBytes).digest("hex"),
      historicalSubject: gitObjects(".", ["merge-base", "HEAD", MAIN_REF]).toString().trim(),
      supersedes: [...SUPERSEDABLE_STATUSES],
      supersededBy: [{ lane: arg("--lane"), record: arg("--record"), reason: arg("--reason") }],
    };
    const errors = implSupersessionErrors(supersession, receiptBytes, ".");
    if (errors.length > 0) throw new Error(`the supersession would not validate:\n - ${errors.join("\n - ")}`);
    writeNewFiles(
      [[resolve(IMPL_SUPERSESSION_REL), `${JSON.stringify(supersession, null, 2)}\n`]],
      "a supersession is never rewritten",
    );
    console.log(
      `${IMPL_SUPERSESSION_REL}: the receipt is superseded at ${supersession.historicalSubject} for ${supersession.supersedes.join(", ")}`,
    );
  } else if (process.argv.includes("--integration")) {
    const binding = deriveReceiptIntegration(".", IMPL_RECEIPT_REL);
    mkdirSync(dirname(resolve(IMPL_RECEIPT_INTEGRATION_REL)), { recursive: true });
    writeFileSync(resolve(IMPL_RECEIPT_INTEGRATION_REL), serializeReceiptIntegration(binding));
    console.log(
      `${IMPL_RECEIPT_INTEGRATION_REL}: reviewed head ${binding.reviewedSubject.commit}, integrated by ` +
        `${binding.integratedSubject.commit}, historical lane base ${binding.historicalReceipt.historicalLaneBase}`,
    );
  } else {
    const at = process.argv.indexOf("--base");
    const base =
      at !== -1 ? String(process.argv[at + 1]) : gitObjects(".", ["merge-base", "HEAD", MAIN_REF]).toString().trim();
    const receipt = deriveImplReceipt(await readImplReceiptInputs(".", base));
    mkdirSync(dirname(resolve(IMPL_RECEIPT_REL)), { recursive: true });
    writeFileSync(resolve(IMPL_RECEIPT_REL), serializeImplReceipt(receipt));
    console.log(
      `${IMPL_RECEIPT_REL}: ${receipt.verdict}; PRODUCTION_SP1_BINDING_STATUS ${receipt.statuses.PRODUCTION_SP1_BINDING_STATUS.value}`,
    );
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
