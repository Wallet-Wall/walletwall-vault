/**
 * SP1-PA3A: derive (and validate) a proof-exercise record under evidence/zk/sp1-impl/proof-exercises from the
 * committed run and verification observations of one real self-hosted proof exercise
 * (scripts/lib/sp1-proof-exercise.ts). SP1-PA3D0: the directory holds every exercise as history, SP1-PA3B's v1 record
 * in its slot (<designation>.json) and a v2 record beside it (<designation>.v2.<token>.json, its observations named
 * after the same token), so this derives the one exercise whose record is missing, never one that exists.
 *
 *   npm run sp1:proof-exercise-record            # derive the record of the one exercise without one, and create it
 *                                                # (never overwritten)
 *   npm run validate:sp1-proof-exercise-record   # every committed record is what its two committed observations
 *                                                # derive, accepted for d1 on the accepted archive record, committed
 *                                                # with them, and none was ever withdrawn; or no record exists
 *
 * The anchor and the archive evidence are read from the committed evidence of the checkout this script lives in,
 * never the working directory; the observations must be committed before the record is derived, since the record
 * binds their committed bytes. No network, no docker, no proof: the observations are the measurements. Research
 * prototype. Not audited.
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { archiveEvidenceState, serializeJson } from "./lib/sp1-circuit-acquisition";
import { committedProductionAnchor, productionArchiveEvidenceOf } from "./lib/sp1-circuit-tooling";
import {
  PROOF_EXERCISES_DIR,
  ROTATION_DELAY_SECONDS,
  derivePendingExerciseRecord,
  egressAssuranceOfRecord,
  exerciseEvidenceState,
  exerciseRecordRel,
  productionExerciseEvidence,
} from "./lib/sp1-proof-exercise";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));

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
    for (const { path, record: r, observations } of e.accepted) {
      const assurance = egressAssuranceOfRecord(r);
      console.log(
        `OK: ${path} is what ${observations.length} committed observations derive, accepted for ${anchor.designation} on ${r.archiveRecord.path}: ` +
          `${r.exercise.id} on ${r.exercise.host}, ${r.performance.wallClockSeconds} s (${r.performance.withinRotationDelay ? "within" : "EXCEEDING"} the ${ROTATION_DELAY_SECONDS} s rotation delay), ` +
          `verifier ${r.verification.acceptance} (${r.verification.checks.length} check(s)), egress ${r.egress.condition}; ` +
          `egress assurance ${assurance.level} (continuous observation ${assurance.continuousObservation}, process attribution ${assurance.processAttribution}).`,
      );
    }
    console.log(
      `SELF_HOSTED_PATH_EXERCISED: ${e.accepted.length} accepted proof-exercise record(s) in ${PROOF_EXERCISES_DIR}, one state; each keeps its own egress assurance.`,
    );
    return;
  }
  const { rel, record } = derivePendingExerciseRecord(REPO, input);
  mkdirSync(dirname(resolve(REPO, rel)), { recursive: true });
  writeNewFiles([[resolve(REPO, rel), serializeJson(record)]], "a proof-exercise record is never overwritten");
  console.log(
    `${rel}: ${record.exercise.id} on ${record.exercise.host}, ${record.performance.wallClockSeconds} s (${record.performance.withinRotationDelay ? "within" : "EXCEEDING"} the ${ROTATION_DELAY_SECONDS} s rotation delay), verifier ${record.verification.acceptance}, egress assurance ${egressAssuranceOfRecord(record).level}.`,
  );
});
