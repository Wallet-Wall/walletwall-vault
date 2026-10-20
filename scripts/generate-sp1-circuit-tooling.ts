/**
 * Derive (and validate) evidence/zk/sp1-impl/circuit-tooling.json, SP1-PA2A's tooling contract, from designation d1,
 * the proving-availability record, the upstream observation (scripts/measure-sp1-circuit-upstream.ts), the gate's
 * rules and a self-test over the synthetic fixtures; see scripts/lib/sp1-circuit-tooling.ts.
 *
 *   npm run sp1:circuit-tooling              # write the record
 *   npm run validate:sp1-circuit-tooling     # check it is what the evidence and the self-test derive
 *
 * No network, no docker, no circuit archive, no SP1 toolchain: it runs in ordinary CI. It never changes
 * PROVING_AVAILABILITY. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { runScript } from "./lib/run-script";
import { TOOLING_REL, serializeTooling, toolingErrors, toolingRecordFromRepo } from "./lib/sp1-circuit-tooling";

runScript(async () => {
  if (process.argv.includes("--validate")) {
    const errors = await toolingErrors(".");
    if (errors.length > 0) throw new Error(`the circuit tooling is invalid:\n - ${errors.join("\n - ")}`);
    const r = (await toolingRecordFromRepo(".")) as { state: string; provingAvailability: { status: string } };
    console.log(`OK: ${TOOLING_REL} is what the evidence and the self-test derive (${r.state}).`);
    console.log(
      `PROVING_AVAILABILITY = ${r.provingAvailability.status} (${
        r.state === "SELF_HOSTED_PATH_EXERCISED"
          ? "an accepted archive record and exactly one accepted proof-exercise record: liveness on one host, never soundness or production readiness"
          : r.state === "ARCHIVED_VERIFIED_UNEXERCISED"
            ? "an accepted archive record; no proof has been made from it"
            : "no archive record: tooling is not an artifact"
      }).`,
    );
  } else {
    const record = await toolingRecordFromRepo(".");
    writeFileSync(resolve(TOOLING_REL), serializeTooling(record));
    console.log(`${TOOLING_REL}: ${String(record.state)}`);
  }
});
