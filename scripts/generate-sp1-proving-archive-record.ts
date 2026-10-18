/**
 * SP1-PA2B: derive (and validate) the production archive record, evidence/zk/sp1-impl/proving-archives/<circuit
 * version>-groth16.json, from the committed acquisition and mirror observations (scripts/lib/sp1-circuit-acquisition.ts).
 *
 *   npm run sp1:proving-archive-record            # derive the record and create it (never overwritten)
 *   npm run validate:sp1-proving-archive-record   # the committed record is what the observations derive, accepted
 *                                                 # for d1, committed with its observations; or no record exists
 *
 * The anchor (designation d1) is read from the committed evidence of the checkout this script lives in, never the
 * working directory; the gnark image the record must name is the pinned prover's default, from the proving-artifacts
 * observation. No network, no download, no archive: the observations are the measurements. Research prototype.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACQUISITION_OBSERVATIONS_REL,
  acquisitionExpectations,
  archiveEvidenceState,
  deriveArchiveRecord,
  mirrorObservationsIn,
  productionArchiveEvidence,
  productionRecordRel,
  serializeJson,
} from "./lib/sp1-circuit-acquisition";
import { archiveRecordErrors } from "./lib/sp1-circuit-archive";
import { committedProductionAnchor } from "./lib/sp1-circuit-tooling";
import { PROVING_ARTIFACTS_OBSERVATION_REL } from "./lib/sp1-proving-availability";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));

runScript(async () => {
  const anchor = committedProductionAnchor(REPO);
  const artifacts = JSON.parse(readFileSync(resolve(REPO, PROVING_ARTIFACTS_OBSERVATION_REL), "utf8"));
  const input = { anchor, gnarkImage: String(artifacts?.source?.gnarkImage) };
  if (process.argv.includes("--validate")) {
    const e = productionArchiveEvidence(REPO, input);
    const state = archiveEvidenceState(e);
    if (state === "REFUSED") throw new Error(`the archive evidence is refused:\n - ${e.errors.join("\n - ")}`);
    console.log(
      state === "NO_RECORD"
        ? `OK: ${productionRecordRel(anchor)} does not exist; no archive is recorded (TOOLING_READY_NO_ARTIFACT).`
        : `OK: ${e.records[0]} is what ${e.observations.length} committed observations derive, accepted for ${anchor.designation}: ` +
            `${e.record?.archive.bytes} bytes, sha256 ${e.record?.archive.sha256}, ${e.record?.members.length} members, ` +
            `${e.record?.metadata.length} metadata entries, ${e.record?.acquisitions.length} hosts, ${e.record?.mirrors.length} mirrors, ` +
            `gnark ${e.record?.gnark.repository}@${e.record?.gnark.digest}.`,
    );
    return;
  }
  const expect = acquisitionExpectations(REPO, input);
  const read = (rel: string) => JSON.parse(readFileSync(resolve(REPO, rel), "utf8"));
  const record = deriveArchiveRecord(
    ACQUISITION_OBSERVATIONS_REL.map(read),
    mirrorObservationsIn(REPO).map(read),
    expect,
  );
  const refused = archiveRecordErrors(record, anchor);
  if (refused.length > 0) {
    throw new Error(
      `the derived record is refused:\n - ${refused.map((r) => `${r.reason}: ${r.detail}`).join("\n - ")}`,
    );
  }
  const rel = productionRecordRel(anchor);
  writeNewFiles([[resolve(REPO, rel), serializeJson(record)]], "a production record is never overwritten");
  console.log(
    `${rel}: ${record.archive.bytes} bytes, sha256 ${record.archive.sha256}, ${record.members.length} members, ${record.mirrors.length} mirrors.`,
  );
});
