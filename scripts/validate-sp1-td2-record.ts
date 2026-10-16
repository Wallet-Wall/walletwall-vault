/**
 * Validate the SP1-TD2 implementation record (evidence/zk/sp1-td2/implementation-record.json) against the SP1-TD1
 * receipt and the repository; see scripts/lib/sp1-td2-record.ts.
 *
 * Usage:
 *   npm run validate:sp1-td2-record
 *
 * No transactions, no deploys, no network. Research prototype. Not audited. Testnet/local only.
 */
import { TD2_RECORD_REL, validateCommittedTd2Record } from "./lib/sp1-td2-record";

const errors = validateCommittedTd2Record();
if (errors.length > 0) {
  console.error(`the SP1-TD2 implementation record is invalid:\n - ${errors.join("\n - ")}`);
  process.exitCode = 1;
} else {
  console.log(`OK: ${TD2_RECORD_REL} matches SP1-TD1's frozen requirements and the repository.`);
}
