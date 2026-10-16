/**
 * Derive (and validate) evidence/zk/sp1-impl/proving-availability.json, SP1-TD1 finding TD1-N9's record, from the
 * measured observation (scripts/measure-sp1-proving-artifacts.ts), the designations and SP1-TD1's receipt; see
 * scripts/lib/sp1-proving-availability.ts.
 *
 *   npm run sp1:proving-availability            # write the record the evidence derives
 *   npm run validate:sp1-proving-availability   # check the observation and that the record is what it derives
 *
 * No network, no download. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  PROVING_AVAILABILITY_REL,
  provingAvailabilityErrors,
  provingAvailabilityFromRepo,
  serializeProvingAvailability,
} from "./lib/sp1-proving-availability";

try {
  if (process.argv.includes("--validate")) {
    const errors = provingAvailabilityErrors(".");
    if (errors.length > 0) throw new Error(`proving availability is invalid:\n - ${errors.join("\n - ")}`);
    console.log(
      `OK: ${PROVING_AVAILABILITY_REL} is what the evidence derives (${provingAvailabilityFromRepo(".").status}).`,
    );
  } else {
    const record = provingAvailabilityFromRepo(".");
    writeFileSync(resolve(PROVING_AVAILABILITY_REL), serializeProvingAvailability(record));
    console.log(`${PROVING_AVAILABILITY_REL}: ${record.status}`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
