/**
 * Derive (and validate) evidence/zk/sp1-impl/observer-qualification.json, SP1-PA3C-Q1's qualification record, from
 * the committed qualification observation(s), the committed observer and the committed self-test capture; see
 * scripts/lib/sp1-observer-qualification.ts.
 *
 *   npm run sp1:observer-qualification              # write the record
 *   npm run validate:sp1-observer-qualification     # check it is what the committed facts derive, here, now
 *
 * The validator derives the committed fixture on the machine it runs on and requires the record's host and container
 * derivations to equal it (so ordinary CI is a third environment), hashes every pinned component again, re-runs the
 * negative controls and recomputes the state. No network, no docker, no kernel, no SP1, no proof. It never changes
 * PROVING_AVAILABILITY or any SP1-PA3B evidence; PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED. Research prototype.
 * Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { runScript } from "./lib/run-script";
import {
  PRODUCTION_SP1_BINDING,
  QUALIFICATION_REL,
  qualificationErrors,
  qualificationRecordFrom,
  serializeQualification,
  validationContextFromRepo,
} from "./lib/sp1-observer-qualification";

runScript(async () => {
  const ctx = validationContextFromRepo(".");
  const record = qualificationRecordFrom(ctx);
  if (process.argv.includes("--validate")) {
    const committedText = readFileSync(resolve(QUALIFICATION_REL), "utf8").replace(/\r\n/g, "\n");
    const errors = qualificationErrors(JSON.parse(committedText), ctx);
    if (committedText !== serializeQualification(record)) errors.push("RECORD_BYTES_DIFFER: regenerate the record");
    if (errors.length > 0) throw new Error(`the observer qualification is invalid:\n - ${errors.join("\n - ")}`);
    console.log(
      `OK: ${QUALIFICATION_REL} is what the committed observation, fixture and observer derive (${record.state}).`,
    );
    console.log(
      `PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING} (${
        record.state === "OBSERVER_QUALIFIED_FOR_PA3D"
          ? "the observer path is qualified to carry the next controlled experiment, SP1-PA3D; this establishes no production binding"
          : record.state === "OBSERVER_QUALIFICATION_BLOCKED"
            ? `blocked: ${record.blockers.join("; ")}`
            : "the tooling is complete; no qualification observation is committed"
      }).`,
    );
  } else {
    writeFileSync(resolve(QUALIFICATION_REL), serializeQualification(record));
    console.log(
      `${QUALIFICATION_REL}: ${record.state}${record.blockers.length > 0 ? ` (${record.blockers.join("; ")})` : ""}`,
    );
  }
});
