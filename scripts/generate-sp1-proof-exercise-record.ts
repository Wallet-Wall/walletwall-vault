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
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { uncommittedEvidenceError } from "./lib/committed-evidence";
import { archiveEvidenceState, serializeJson } from "./lib/sp1-circuit-acquisition";
import { committedProductionAnchor, productionArchiveEvidenceOf } from "./lib/sp1-circuit-tooling";
import {
  GENERATION_SCHEMAS,
  MAX_RECORDS,
  OBSERVATIONS_DIR,
  PROOF_EXERCISES_DIR,
  ROTATION_DELAY_SECONDS,
  attributedExerciseFiles,
  attributedExerciseRecordRel,
  deriveExerciseRecord,
  egressAssuranceOfRecord,
  exerciseDirectoryOf,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseRecordRel,
  exerciseRecordsIn,
  exerciseToken,
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
  if (archiveState !== "ACCEPTED") {
    throw new Error(`no accepted archive record (${archiveState}): nothing an exercise could have run from`);
  }
  const names = (rel: string) => {
    try {
      return readdirSync(resolve(REPO, rel));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  };
  const dir = exerciseDirectoryOf(names(PROOF_EXERCISES_DIR), names(OBSERVATIONS_DIR), anchor.designation);
  if (dir.errors.length > 0) {
    throw new Error(`the exercise directory is refused, so no record is derived:\n - ${dir.errors.join("\n - ")}`);
  }
  const pending = dir.groups.filter((g) => g.record === null);
  if (pending.length !== 1) {
    throw new Error(
      pending.length === 0
        ? `nothing to derive: every committed exercise in ${OBSERVATIONS_DIR} already has its record (${exerciseRecordsIn(REPO).join(", ") || "none"}); a record is never derived twice`
        : `${pending.length} exercises have no record (${pending.map((g) => g.token ?? "the v1 slot").join(", ")}): derive one at a time`,
    );
  }
  const g = pending[0];
  if (g.runs.length !== 1 || g.verifications.length !== 1) {
    throw new Error(
      `the exercise ${g.token ?? "of the v1 slot"} needs exactly one run observation and exactly one verification observation (it has ${g.runs.length} run, ${g.verifications.length} verification)`,
    );
  }
  const held = dir.groups.filter((x) => x.generation === g.generation && x.record !== null).length;
  if (held >= MAX_RECORDS[g.generation]) {
    throw new Error(
      `${PROOF_EXERCISES_DIR} already holds ${held} ${g.generation} record(s), the most the contract admits: a second needs it raised in its own lane`,
    );
  }
  const dirty = uncommittedEvidenceError([g.runs[0], g.verifications[0]], REPO);
  if (dirty !== null)
    throw new Error(`the observations are not as committed (the record binds their committed bytes): ${dirty}`);
  const runText = lf(readFileSync(resolve(REPO, g.runs[0]), "utf8"));
  const run = JSON.parse(runText);
  if (run?.schema !== GENERATION_SCHEMAS[g.generation].run) {
    throw new Error(
      `${g.runs[0]} holds ${String(run?.schema)}, but ${g.token === null ? "the v1 slot" : `exercise ${g.token}`} admits only a ${GENERATION_SCHEMAS[g.generation].run} run${run?.schema === GENERATION_SCHEMAS.v2.run && g.token === null ? `: a v2 exercise's files are named after its token (${attributedExerciseFiles(anchor, String(run?.host), runText).run})` : ""}`,
    );
  }
  if (g.token !== null && exerciseToken(runText) !== g.token) {
    throw new Error(
      `${g.runs[0]} is exercise ${exerciseToken(runText)}, not ${g.token}: name its files after it (${Object.values(
        attributedExerciseFiles(anchor, String(run?.host), runText),
      )
        .slice(1)
        .join(", ")})`,
    );
  }
  const verification = JSON.parse(lf(readFileSync(resolve(REPO, g.verifications[0]), "utf8")));
  const record = deriveExerciseRecord(
    run,
    verification,
    { runSha256: sha256(runText), verificationPath: g.verifications[0], runPath: g.runs[0] },
    exerciseExpectations(REPO, input),
  );
  const rel = g.token === null ? exerciseRecordRel(anchor) : attributedExerciseRecordRel(anchor, g.token);
  mkdirSync(dirname(resolve(REPO, rel)), { recursive: true });
  writeNewFiles([[resolve(REPO, rel), serializeJson(record)]], "a proof-exercise record is never overwritten");
  console.log(
    `${rel}: ${record.exercise.id} on ${record.exercise.host}, ${record.performance.wallClockSeconds} s (${record.performance.withinRotationDelay ? "within" : "EXCEEDING"} the ${ROTATION_DELAY_SECONDS} s rotation delay), verifier ${record.verification.acceptance}, egress assurance ${egressAssuranceOfRecord(record).level}.`,
  );
});
