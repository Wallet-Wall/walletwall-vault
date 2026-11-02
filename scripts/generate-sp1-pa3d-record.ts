/**
 * Derive (and validate) evidence/zk/sp1-impl/pa3d-exercise-record.json, SP1-PA3D's exercise record, from the committed
 * evidence alone; see scripts/lib/sp1-pa3d-record.ts.
 *
 *   npm run sp1:pa3d-record              # derive the record from the committed manifest, attestation, v2 exercise and
 *                                        # observer qualification, and create it (never overwritten)
 *   npm run validate:sp1-pa3d-record     # it is what the committed evidence derives, here, now
 *
 * The record is the attribution chain (each link a comparison of committed digests), the reproducibility statement,
 * the negative controls (the validator's re-run here, the verifier's executed by the test suite) and the state,
 * recomputed from facts. No proof, no network, no docker, no chain. It is a v2 proof exercise record, not a production
 * binding record: PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED. Research prototype. Not audited.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runScript } from "./lib/run-script";
import { PRODUCTION_SP1_BINDING } from "./lib/sp1-pa3d-exercise";
import {
  RECORD_REL,
  pa3dInputsFromRepo,
  pa3dRecordErrors,
  pa3dRecordFrom,
  serializePa3dRecord,
} from "./lib/sp1-pa3d-record";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));

runScript(async () => {
  const inputs = pa3dInputsFromRepo(REPO);
  if (process.argv.includes("--validate")) {
    const committedText = readFileSync(resolve(REPO, RECORD_REL), "utf8").replace(/\r\n/g, "\n");
    const committed: unknown = JSON.parse(committedText);
    const errors = pa3dRecordErrors(committed, inputs);
    if (errors.length === 0 && committedText !== serializePa3dRecord(pa3dRecordFrom(inputs))) {
      errors.push("RECORD_BYTES_DIFFER: the committed text is not the derivation's serialization; regenerate it");
    }
    if (errors.length > 0) throw new Error(`the PA3D exercise record is invalid:\n - ${errors.join("\n - ")}`);
    const r = pa3dRecordFrom(inputs);
    console.log(
      `OK: ${RECORD_REL} is what the committed evidence derives: ${r.state}; chain ${r.chain.links.filter((l) => l.holds).length}/${r.chain.links.length} links hold; ` +
        `statement ${r.reproducibility.statement}; ${r.negativeControls.filter((c) => c.outcome === "REFUSED").length} validator controls refused, ` +
        `${r.negativeControls.filter((c) => c.kind === "VERIFIER").length} verifier controls in the test suite.`,
    );
    console.log(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING} (${r.kind}).`);
    return;
  }
  const record = pa3dRecordFrom(inputs);
  writeNewFiles(
    [[resolve(REPO, RECORD_REL), serializePa3dRecord(record)]],
    "a PA3D exercise record is never overwritten",
  );
  console.log(
    `${RECORD_REL}: ${record.state}${record.blockers.length > 0 ? `\n - ${record.blockers.join("\n - ")}` : ""}`,
  );
  console.log(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING}.`);
});
