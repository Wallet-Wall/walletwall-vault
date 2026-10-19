/**
 * SP1-PA3A: derive (and validate) the proof-exercise record, evidence/zk/sp1-impl/proof-exercises/<designation>.json,
 * from the committed run and verification observations of one real self-hosted proof exercise
 * (scripts/lib/sp1-proof-exercise.ts).
 *
 *   npm run sp1:proof-exercise-record            # derive the record and create it (never overwritten)
 *   npm run validate:sp1-proof-exercise-record   # the committed record is what the two committed observations
 *                                                # derive, accepted for d1 on the accepted archive record, committed
 *                                                # with them; or no record exists
 *
 * The anchor and the archive evidence are read from the committed evidence of the checkout this script lives in,
 * never the working directory; the observations must be committed before the record is derived, since the record
 * binds their committed bytes. No network, no docker, no proof: the observations are the measurements. SP1-PA3A
 * built this; the real repository holds no observation and derives no record. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { uncommittedEvidenceError } from "./lib/committed-evidence";
import { archiveEvidenceState, serializeJson } from "./lib/sp1-circuit-acquisition";
import { committedProductionAnchor, productionArchiveEvidenceOf } from "./lib/sp1-circuit-tooling";
import {
  OBSERVATIONS_DIR,
  ROTATION_DELAY_SECONDS,
  deriveExerciseRecord,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseObservationsIn,
  exerciseRecordRel,
  productionExerciseEvidence,
} from "./lib/sp1-proof-exercise";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");

runScript(async () => {
  const anchor = committedProductionAnchor(REPO);
  const archive = productionArchiveEvidenceOf(REPO);
  const archiveState = archiveEvidenceState(archive);
  const input = { anchor, archive };
  if (process.argv.includes("--validate")) {
    const e = productionExerciseEvidence(REPO, input);
    const state = exerciseEvidenceState(e);
    if (state === "REFUSED") throw new Error(`the proof-exercise evidence is refused:\n - ${e.errors.join("\n - ")}`);
    if (state === "NO_RECORD") {
      if (archiveState === "REFUSED") {
        throw new Error(
          `no proof-exercise record, and the archive evidence is refused:\n - ${archive.errors.join("\n - ")}`,
        );
      }
      const derived = archiveState === "ACCEPTED" ? "ARCHIVED_VERIFIED_UNEXERCISED" : "TOOLING_READY_NO_ARTIFACT";
      console.log(`OK: ${exerciseRecordRel(anchor)} does not exist; no proof-exercise record (${derived}).`);
      return;
    }
    const r = e.record;
    console.log(
      `OK: ${e.records[0]} is what ${e.observations.length} committed observations derive, accepted for ${anchor.designation} on ${r?.archiveRecord.path}: ` +
        `${r?.exercise.id} on ${r?.exercise.host}, ${r?.performance.wallClockSeconds} s (${r?.performance.withinRotationDelay ? "within" : "EXCEEDING"} the ${ROTATION_DELAY_SECONDS} s rotation delay), ` +
        `verifier ${r?.verification.acceptance} (${r?.verification.checks.length} check(s)), egress ${r?.egress.condition} (SELF_HOSTED_PATH_EXERCISED).`,
    );
    return;
  }
  if (archiveState !== "ACCEPTED") {
    throw new Error(`no accepted archive record (${archiveState}): nothing an exercise could have run from`);
  }
  const obs = exerciseObservationsIn(REPO);
  if (obs.run.length !== 1 || obs.verification.length !== 1 || obs.other.length > 0) {
    throw new Error(
      `${OBSERVATIONS_DIR} must hold exactly one run observation and exactly one verification observation (it holds ${obs.run.length} run, ${obs.verification.length} verification, ${obs.other.length} other)`,
    );
  }
  const dirty = uncommittedEvidenceError([...obs.run, ...obs.verification], REPO);
  if (dirty !== null)
    throw new Error(`the observations are not as committed (the record binds their committed bytes): ${dirty}`);
  const expect = exerciseExpectations(REPO, input);
  const runText = lf(readFileSync(resolve(REPO, obs.run[0]), "utf8"));
  const verification = JSON.parse(lf(readFileSync(resolve(REPO, obs.verification[0]), "utf8")));
  const record = deriveExerciseRecord(
    JSON.parse(runText),
    verification,
    { runSha256: sha256(runText), verificationPath: obs.verification[0], runPath: obs.run[0] },
    expect,
  );
  const rel = exerciseRecordRel(anchor);
  mkdirSync(dirname(resolve(REPO, rel)), { recursive: true });
  writeNewFiles([[resolve(REPO, rel), serializeJson(record)]], "a proof-exercise record is never overwritten");
  console.log(
    `${rel}: ${record.exercise.id} on ${record.exercise.host}, ${record.performance.wallClockSeconds} s (${record.performance.withinRotationDelay ? "within" : "EXCEEDING"} the ${ROTATION_DELAY_SECONDS} s rotation delay), verifier ${record.verification.acceptance}.`,
  );
});
