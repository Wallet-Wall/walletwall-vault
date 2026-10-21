/**
 * SP1-PA3D0: the proof-exercise directory holds history, never ambiguity. SP1-PA3B's v1 record keeps its slot
 * (<designation>.json) beside a v2 record named after its own exercise (<designation>.v2.<token>.json, its two
 * observations named after the same token); every record is judged on its own and the directory as a whole; two
 * exercises are one state; each keeps its own egress assurance; and a record once committed is never withdrawn.
 *
 * The suite pins the names (pure), a synthetic repository holding a v1 exercise beside a v2 one (every refusal by its
 * reason, mixed accepted and refused records, the history), the derivation of the one record a committed exercise
 * lacks, a repository with this checkout's real history in which a synthetic v2 joins SP1-PA3B's real v1 (the
 * availability, tooling and advisory accounting), and the real checkout as merged. Nothing is proved: every v2 run
 * here is synthetic, bound to a deterministic observer capture. Research prototype. Not audited.
 */
import { assert, expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { productionRecordRel, serializeJson, type ArchiveEvidence } from "../scripts/lib/sp1-circuit-acquisition";
import { CANONICAL_REBUILD_OBSERVATION_REL } from "../scripts/lib/sp1-canonical-build";
import {
  committedProductionAnchor,
  productionArchiveEvidenceOf,
  toolingRecordFromRepo,
  toolingState,
} from "../scripts/lib/sp1-circuit-tooling";
import { DESIGNATIONS_DIR, readDesignations } from "../scripts/lib/sp1-designation";
import { EDGE_PROBES_ONLY, normalizeObserverRaw } from "../scripts/lib/sp1-egress-attribution";
import { ASSUMPTIONS, advisoryStateFromRepo } from "../scripts/lib/sp1-host-advisories";
import {
  ATTRIBUTED_RUN_SCRIPT_REL,
  EGRESS_CANARY_IPS,
  EXERCISE_RECORD_SCHEMA,
  EXERCISE_RECORD_SCHEMA_V2,
  MAX_RECORDS,
  OBSERVATIONS_DIR,
  PROOF_EXERCISES_DIR,
  PROOF_INPUT_FIXTURE_REL,
  REPOSITORY_ID,
  RUN_OBSERVATION_PREFIX,
  RUN_SCHEMA,
  RUN_SCHEMA_V2,
  RUN_SCRIPT_REL,
  VERIFICATION_OBSERVATION_PREFIX,
  VERIFICATION_SCRIPT_REL,
  attributedExerciseFiles,
  attributedExerciseRecordRel,
  deriveExerciseRecord,
  derivePendingExerciseRecord,
  egressAssuranceOfRecord,
  exerciseDirectoryOf,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseHistoryErrors,
  exerciseObservationsIn,
  exerciseRecordRel,
  exerciseRecordsIn,
  exerciseToken,
  observationSlotOf,
  productionExerciseEvidence,
  recordSlotOf,
  unrecordedExerciseErrors,
  type AcceptedExercise,
  type AttributedRunObservation,
  type EgressProbe,
  type ExerciseEvidence,
  type ExerciseExpectations,
  type ProofExerciseRecord,
  type RunObservation,
  type VerificationObservation,
} from "../scripts/lib/sp1-proof-exercise";
import {
  PROVING_ARTIFACTS_OBSERVATION_REL,
  PROVING_AVAILABILITY_REL,
  archiveEvidenceFromRepo,
  deriveProvingAvailability,
  exerciseEvidenceFromRepo,
  provingAvailabilityErrors,
  provingAvailabilityFromRepo,
  serializeProvingAvailability,
  type ProvingArtifactsObservation,
} from "../scripts/lib/sp1-proving-availability";
import { OBSERVER_SCRIPT_REL } from "../scripts/sp1-egress-observer";
import { tempDirs } from "./helpers/circuit-tooling";
import { BOOT_ID, HOST_EXE, standardRaw } from "./helpers/sp1EgressTrace";
import {
  ANCHOR,
  ARCHIVE_RECORD,
  ARCHIVE_RECORD_TEXT,
  EXPECTATIONS,
  HOST_BINARY_SHA,
  SOURCE_COMMIT,
  runObservation,
  verificationObservation,
} from "./helpers/sp1ProofExercise";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const D = ANCHOR.designation;
const T1 = "0123456789abcdef";
const T2 = "fedcba9876543210";
const HOST_A = "proving-host-a";
/** SP1-PA3B's merged evidence: the exact bytes (sha256 of the committed LF files) this lane must leave as they are. */
const PA3B = {
  record: "evidence/zk/sp1-impl/proof-exercises/mldsa65-withdrawal-d1.json",
  run: "evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json",
  verification: "evidence/zk/sp1-impl/observations/proof-exercise-verification-developer-workstation-wsl2.raw.json",
  sha256: {
    record: "fbcd5da3de334d971f9dae688148863bffd3bf3f1d610aec64fd00445014b131",
    run: "5cc66ed58a4a2cf8a9439737e3b6246b59710bab6f22357410def81e761db3ff",
    verification: "6057bf219e77c0303b0906364ccb9cb91e681e08410501220afce2427fe2b918",
  },
  exercise: "mldsa65-withdrawal-d1:5cc66ed58a4a2cf8",
};
const lfSha = (rel: string, root = ".") => sha256(readFileSync(join(root, rel), "utf8").replace(/\r\n/g, "\n"));

/** The run's probes for `x`'s targets (each refused the way the gate's probes are), at `atUtc`. */
function probesFor(x: ExerciseExpectations, atUtc: string): EgressProbe[] {
  return [
    ...[x.upstreamHost, x.registryHost].flatMap((h): EgressProbe[] => [
      { target: h, kind: "dns", atUtc, outcome: "REFUSED", error: "EAI_AGAIN" },
      { target: `${h}:443`, kind: "tcp", atUtc, outcome: "REFUSED", error: "ENETUNREACH" },
    ]),
    ...[...x.upstreamIps, ...EGRESS_CANARY_IPS].map((ip): EgressProbe => ({
      target: `${ip}:443`,
      kind: "tcp",
      atUtc,
      outcome: "REFUSED",
      error: "ENETUNREACH",
    })),
  ];
}

/**
 * A run observation of `generation` bound to `x` (its anchor, archive record, tools, host binary, input and probe
 * targets) at `commit` on `host`, with its own proof (`fill` makes the bytes; one proof is one exercise). A v2 run
 * carries the deterministic observer capture of those probes, that commit and that host.
 */
function boundRun(
  x: ExerciseExpectations,
  commit: string,
  generation: "v1" | "v2",
  opts: { host?: string; fill?: number } = {},
): RunObservation | AttributedRunObservation {
  const host = opts.host ?? HOST_A;
  const run = runObservation();
  const imageRef = `${x.archiveRecord.record.gnark.repository}@${x.archiveRecord.record.gnark.digest}`;
  run.host = host;
  run.anchor = structuredClone(x.anchor);
  run.source = { repository: REPOSITORY_ID, commit, zkvmHostTree: x.zkvmHostTree };
  run.archiveRecord = { path: x.archiveRecord.path, sha256: x.archiveRecord.sha256 };
  run.installedCircuit = { ...run.installedCircuit, circuitVersion: x.anchor.circuitVersion };
  run.installedCircuit.members = structuredClone(x.archiveRecord.record.members);
  run.hostExecutable.sha256 = String(x.hostBinarySha256);
  run.inputs.sha256 = String(x.proofInputSha256);
  run.tool.scriptSha256 = String(x.scripts.run);
  run.gnark = {
    repository: x.archiveRecord.record.gnark.repository,
    digest: x.archiveRecord.record.gnark.digest,
    imageRef,
    localRepoDigests: [imageRef],
  };
  run.prover.frozenEnv.SP1_GNARK_IMAGE = imageRef;
  run.egress.before = probesFor(x, "2026-11-01T09:59:50Z");
  run.egress.after = probesFor(x, "2026-11-01T11:59:50Z");
  const selector = x.anchor.verifyingKey.sha256.slice(2, 10);
  const proofBytes = Buffer.concat([Buffer.from(selector, "hex"), Buffer.alloc(352, opts.fill ?? 0xab)]);
  run.proof = {
    ...run.proof,
    vkey: x.anchor.programVKey,
    proofBytes: `0x${proofBytes.toString("hex")}`,
    selector: `0x${selector}`,
    proofBytesSha256: sha256(proofBytes),
  };
  run.platform = [`host=${host}`, "os=linux 6.8.0 x64", "node=v22.13.0"];
  if (generation === "v1") return run;
  const names = [x.upstreamHost, x.registryHost];
  const observer = normalizeObserverRaw(
    standardRaw(
      {
        commit,
        host,
        probes: { dns: names, tcpByName: names, tcpByAddress: [...x.upstreamIps, ...EGRESS_CANARY_IPS] },
      },
      { observerSha: String(x.scripts.observer) },
    ),
    HOST_EXE,
  );
  return {
    ...run,
    schema: RUN_SCHEMA_V2,
    tool: { script: ATTRIBUTED_RUN_SCRIPT_REL, scriptSha256: String(x.scripts.attributedRun) },
    egress: { ...run.egress, observer },
    platform: [...run.platform, `bootId=${BOOT_ID}`],
  };
}

/** The designated verifier's acceptance of `run`, committed at `runPath`, as the verification tool would record it. */
function boundVerification(
  x: ExerciseExpectations,
  run: RunObservation | AttributedRunObservation,
  runPath: string,
): VerificationObservation {
  const v = verificationObservation(run as RunObservation);
  v.host = run.host;
  v.run = { path: runPath, sha256: sha256(serializeJson(run)) };
  v.tool.scriptSha256 = String(x.scripts.verification);
  v.verifier = structuredClone(x.anchor.verifier);
  v.checks[0].runtimeCodeKeccak = x.anchor.verifier.runtimeCodeKeccak;
  return v;
}

interface Exercise {
  files: { run: string; verification: string; record: string };
  run: RunObservation | AttributedRunObservation;
  verification: VerificationObservation;
  record: ProofExerciseRecord;
}

/** One consistent exercise: v1 under the v1 slot's names, v2 under its token's; its record derived from the pair. */
function exerciseOf(
  x: ExerciseExpectations,
  commit: string,
  generation: "v1" | "v2",
  opts: { host?: string; fill?: number } = {},
): Exercise {
  const host = opts.host ?? HOST_A;
  const run = boundRun(x, commit, generation, { fill: opts.fill ?? (generation === "v1" ? 0xab : 0xcd), host });
  const text = serializeJson(run);
  const files =
    generation === "v1"
      ? {
          run: `${OBSERVATIONS_DIR}/${RUN_OBSERVATION_PREFIX}${host}.raw.json`,
          verification: `${OBSERVATIONS_DIR}/${VERIFICATION_OBSERVATION_PREFIX}${host}.raw.json`,
          record: exerciseRecordRel(x.anchor),
        }
      : (({ run: r, verification: v, record }) => ({ run: r, verification: v, record }))(
          attributedExerciseFiles(x.anchor, host, text),
        );
  const verification = boundVerification(x, run, files.run);
  const record = deriveExerciseRecord(
    run,
    verification,
    { runSha256: sha256(text), verificationPath: files.verification, runPath: files.run },
    x,
  );
  return { files, run, verification, record };
}

describe("SP1-PA3D0 — the proof-exercise directory holds history: SP1-PA3B's v1 beside a v2", function () {
  describe("the names (pure: the two listings alone, in any order)", function () {
    const run = (host: string, token?: string) =>
      `${RUN_OBSERVATION_PREFIX}${host}${token === undefined ? "" : `.${token}`}.raw.json`;
    const ver = (host: string, token?: string) =>
      `${VERIFICATION_OBSERVATION_PREFIX}${host}${token === undefined ? "" : `.${token}`}.raw.json`;

    it("admits exactly the v1 slot and v2 records named after a token, of the designation", function () {
      expect(recordSlotOf(`${D}.json`, D)).to.deep.equal({ generation: "v1", token: null });
      expect(recordSlotOf(`${D}.v2.${T1}.json`, D)).to.deep.equal({ generation: "v2", token: T1 });
      for (const name of [
        `${D}.v2.json`,
        `${D}.v2..json`,
        `${D}.v2.${T1.toUpperCase()}.json`,
        `${D}.v2.${T1.slice(1)}.json`,
        `${D}.v2.${T1}0.json`,
        `${D}.v2.${T1}.json.json`,
        `${D}.v3.${T1}.json`,
        `${D}.v1.json`,
        `${D}.v1.${T1}.json`,
        `${D}.json.bak`,
        `${D}.JSON`,
        `x${D}.json`,
        `${D}x.json`,
        `other-designation.json`,
        `other-designation.v2.${T1}.json`,
        // Another designation of the same length: only the prefix itself tells it apart.
        `x${D.slice(1)}.v2.${T1}.json`,
        `x${D.slice(1)}.json`,
        "README.md",
        "",
      ]) {
        expect(recordSlotOf(name, D), name).to.equal(null);
      }
      // The designation is the anchor's, read literally: the real one's slot is no slot of the synthetic one.
      expect(recordSlotOf("mldsa65-withdrawal-d1.json", D)).to.equal(null);
      expect(recordSlotOf("mldsa65-withdrawal-d1.json", "mldsa65-withdrawal-d1")).to.deep.equal({
        generation: "v1",
        token: null,
      });
    });

    it("reads an observation's kind, host label and token from its name, and nothing else", function () {
      expect(observationSlotOf(run(HOST_A))).to.deep.equal({ kind: "run", host: HOST_A, token: null });
      expect(observationSlotOf(ver(HOST_A, T1))).to.deep.equal({ kind: "verification", host: HOST_A, token: T1 });
      expect(observationSlotOf(run("developer-workstation-wsl2"))).to.deep.equal({
        kind: "run",
        host: "developer-workstation-wsl2",
        token: null,
      });
      // A label of sixteen hex digits is a host, not a token: a token always follows a dot.
      expect(observationSlotOf(run(T1))).to.deep.equal({ kind: "run", host: T1, token: null });
      for (const name of [
        run(""),
        run("Host-A"),
        run("-a"),
        run("a-"),
        run("a", T1.toUpperCase()),
        run("a", T1.slice(1)),
        run("a", `${T1}.${T2}`),
        `${RUN_OBSERVATION_PREFIX}a.b.raw.json`,
        `${RUN_OBSERVATION_PREFIX}a.raw.json.bak`,
        `${RUN_OBSERVATION_PREFIX}a.json`,
        "proof-exercise-notes.raw.json",
        "proof-exercise-runs-a.raw.json",
        `proof-exercise-verify-a.raw.json`,
      ]) {
        expect(observationSlotOf(name), name).to.equal(null);
      }
    });

    it("groups SP1-PA3B's names (no token) and a v2 exercise's (its token) apart, on the same host", function () {
      const dir = exerciseDirectoryOf(
        [`${D}.json`, `${D}.v2.${T1}.json`],
        [run(HOST_A), ver(HOST_A), run(HOST_A, T1), ver(HOST_A, T1), "circuit-acquisition-x.raw.json"],
        D,
      );
      expect(dir.errors).to.deep.equal([]);
      expect(dir.records).to.deep.equal([
        `${PROOF_EXERCISES_DIR}/${D}.json`,
        `${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.json`,
      ]);
      // Only proof-exercise observations are the directory's (the other observations are no one's here), by name.
      expect(dir.observations).to.deep.equal(
        [run(HOST_A, T1), run(HOST_A), ver(HOST_A, T1), ver(HOST_A)].map((n) => `${OBSERVATIONS_DIR}/${n}`),
      );
      expect(dir.groups).to.deep.equal([
        {
          token: null,
          generation: "v1",
          record: `${PROOF_EXERCISES_DIR}/${D}.json`,
          runs: [`${OBSERVATIONS_DIR}/${run(HOST_A)}`],
          verifications: [`${OBSERVATIONS_DIR}/${ver(HOST_A)}`],
        },
        {
          token: T1,
          generation: "v2",
          record: `${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.json`,
          runs: [`${OBSERVATIONS_DIR}/${run(HOST_A, T1)}`],
          verifications: [`${OBSERVATIONS_DIR}/${ver(HOST_A, T1)}`],
        },
      ]);
      expect(unrecordedExerciseErrors(dir)).to.deep.equal([]);
    });

    it("is the same whatever order either listing comes in (no listing order chooses anything)", function () {
      const records = [`${D}.v2.${T2}.json`, `${D}.json`, `${D}.v2.${T1}.json`, "stray.txt"];
      const observations = [run(HOST_A, T2), ver("b"), run(HOST_A), ver(HOST_A, T1), run("b", T1), ver(HOST_A, T2)];
      const once = exerciseDirectoryOf(records, observations, D);
      const rotate = <T>(xs: T[], n: number) => [...xs.slice(n), ...xs.slice(0, n)];
      for (const [r, o] of [
        [[...records].reverse(), [...observations].reverse()],
        [rotate(records, 1), rotate(observations, 2)],
        [rotate(records, 3), [...observations].sort()],
      ]) {
        expect(exerciseDirectoryOf(r, o, D)).to.deep.equal(once);
      }
      // The groups follow the tokens, the v1 slot first, which is the records' path order.
      expect(once.groups.map((g) => g.token)).to.deep.equal([null, T1, T2]);
      expect(once.groups.filter((g) => g.record !== null).map((g) => g.record)).to.deep.equal(
        [...once.records].filter((r) => !r.endsWith("stray.txt")),
      );
    });

    it("refuses every name the contract does not admit, never ignores it", function () {
      const dir = exerciseDirectoryOf(
        [`${D}.json`, "notes.txt", `other-designation.v2.${T1}.json`, `${D}.v2.${T1}.JSON`],
        [run(HOST_A), ver(HOST_A), "proof-exercise-notes.raw.json", `${RUN_OBSERVATION_PREFIX}A.raw.json`],
        D,
      );
      expect(dir.errors.join("\n")).to.include(`${PROOF_EXERCISES_DIR}/notes.txt is no proof-exercise record of ${D}`);
      expect(dir.errors.join("\n")).to.include(
        `${PROOF_EXERCISES_DIR}/other-designation.v2.${T1}.json is no proof-exercise record of ${D}`,
      );
      expect(dir.errors.join("\n")).to.include(`${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.JSON is no proof-exercise record`);
      expect(dir.errors.join("\n")).to.include(
        `${OBSERVATIONS_DIR}/proof-exercise-notes.raw.json, which is no proof-exercise observation`,
      );
      expect(dir.errors.join("\n")).to.include(`${OBSERVATIONS_DIR}/${RUN_OBSERVATION_PREFIX}A.raw.json, which is no`);
      expect(dir.errors).to.have.length(5);
    });

    it("needs exactly one run and one verification per record, and holds no generation over MAX_RECORDS", function () {
      expect(MAX_RECORDS).to.deep.equal({ v1: 1, v2: 1 });
      const short = exerciseDirectoryOf([`${D}.json`], [], D);
      expect(short.errors).to.deep.equal([
        `${PROOF_EXERCISES_DIR}/${D}.json needs exactly one run observation (${RUN_OBSERVATION_PREFIX}<host>.raw.json); ${OBSERVATIONS_DIR} holds 0`,
        `${PROOF_EXERCISES_DIR}/${D}.json needs exactly one verification observation (${VERIFICATION_OBSERVATION_PREFIX}<host>.raw.json); ${OBSERVATIONS_DIR} holds 0`,
      ]);
      // A second v1 run from another host: still one slot, now with two runs.
      const twoRuns = exerciseDirectoryOf([`${D}.json`], [run(HOST_A), run("b"), ver(HOST_A)], D);
      expect(twoRuns.errors).to.deep.equal([
        `${PROOF_EXERCISES_DIR}/${D}.json needs exactly one run observation (${RUN_OBSERVATION_PREFIX}<host>.raw.json); ${OBSERVATIONS_DIR} holds 2`,
      ]);
      const v2Short = exerciseDirectoryOf([`${D}.v2.${T1}.json`], [run(HOST_A, T1)], D);
      expect(v2Short.errors).to.deep.equal([
        `${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.json needs exactly one verification observation (${VERIFICATION_OBSERVATION_PREFIX}<host>.${T1}.raw.json); ${OBSERVATIONS_DIR} holds 0`,
      ]);
      // Two v2 records, each complete: over the contract's count, both named.
      const twoV2 = exerciseDirectoryOf(
        [`${D}.v2.${T2}.json`, `${D}.v2.${T1}.json`],
        [run(HOST_A, T1), ver(HOST_A, T1), run(HOST_A, T2), ver(HOST_A, T2)],
        D,
      );
      expect(twoV2.errors).to.deep.equal([
        `${PROOF_EXERCISES_DIR} holds 2 v2 records (${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.json, ${PROOF_EXERCISES_DIR}/${D}.v2.${T2}.json); the contract admits at most 1 per designation, and a second needs it raised in its own lane, never a record beside it`,
      ]);
      // The v1 slot and one v2 are within the count.
      expect(
        exerciseDirectoryOf([`${D}.json`, `${D}.v2.${T1}.json`], [run("x"), ver("x"), run("y", T1), ver("y", T1)], D)
          .errors,
      ).to.deep.equal([]);
    });

    it("leaves observations without a record as a group of no record, which unrecordedExerciseErrors refuses", function () {
      const dir = exerciseDirectoryOf([`${D}.json`], [run(HOST_A), ver(HOST_A), run(HOST_A, T1), ver(HOST_A, T1)], D);
      expect(dir.errors).to.deep.equal([]);
      expect(dir.groups.map((g) => [g.token, g.record])).to.deep.equal([
        [null, `${PROOF_EXERCISES_DIR}/${D}.json`],
        [T1, null],
      ]);
      expect(unrecordedExerciseErrors(dir)).to.deep.equal([
        `${OBSERVATIONS_DIR} holds the observations of exercise ${T1} (${OBSERVATIONS_DIR}/${run(HOST_A, T1)}, ${OBSERVATIONS_DIR}/${ver(HOST_A, T1)}) and no record of them: derive it (npm run sp1:proof-exercise-record) or remove them; evidence of an exercise is never left unaccounted`,
      ]);
      const v1Pending = exerciseDirectoryOf([`${D}.v2.${T1}.json`], [run(HOST_A), run(HOST_A, T1), ver(HOST_A, T1)], D);
      expect(unrecordedExerciseErrors(v1Pending).join("\n")).to.include("v1-slot observations");
      expect(unrecordedExerciseErrors(v1Pending)).to.have.length(1);
    });

    it("names an exercise by its token: the first 16 hex digits of its run file's sha256, LF or CRLF alike", function () {
      const text = serializeJson(runObservation());
      expect(exerciseToken(text)).to.equal(sha256(text).slice(0, 16));
      expect(exerciseToken(text.replace(/\n/g, "\r\n"))).to.equal(exerciseToken(text));
      const t = exerciseToken(text);
      expect(attributedExerciseFiles(ANCHOR, HOST_A, text)).to.deep.equal({
        token: t,
        run: `${OBSERVATIONS_DIR}/${RUN_OBSERVATION_PREFIX}${HOST_A}.${t}.raw.json`,
        verification: `${OBSERVATIONS_DIR}/${VERIFICATION_OBSERVATION_PREFIX}${HOST_A}.${t}.raw.json`,
        record: `${PROOF_EXERCISES_DIR}/${D}.v2.${t}.json`,
      });
      expect(attributedExerciseRecordRel(ANCHOR, T1)).to.equal(`${PROOF_EXERCISES_DIR}/${D}.v2.${T1}.json`);
      // The v1 slot's path is the one SP1-PA3B's record has always had.
      expect(exerciseRecordRel(ANCHOR)).to.equal(`${PROOF_EXERCISES_DIR}/${D}.json`);
      // The names the helpers make are the names the grammar reads back.
      const files = attributedExerciseFiles(ANCHOR, HOST_A, text);
      expect(recordSlotOf(basename(files.record), D)).to.deep.equal({ generation: "v2", token: t });
      expect(observationSlotOf(basename(files.run))).to.deep.equal({ kind: "run", host: HOST_A, token: t });
      expect(observationSlotOf(basename(files.verification))).to.deep.equal({
        kind: "verification",
        host: HOST_A,
        token: t,
      });
    });

    it("exerciseEvidenceState: ACCEPTED only when every record is accepted and nothing is refused", function () {
      const x = exerciseOf(EXPECTATIONS, SOURCE_COMMIT, "v1");
      const one = {
        path: x.files.record,
        generation: "v1" as const,
        record: x.record,
        observations: [x.files.run, x.files.verification] as [string, string],
      };
      const state = (e: ExerciseEvidence) => exerciseEvidenceState(e);
      expect(state({ records: [], accepted: [], observations: [], errors: [] })).to.equal("NO_RECORD");
      // No record left, but the history shows one withdrawn: never NO_RECORD.
      expect(state({ records: [], accepted: [], observations: [], errors: ["withdrawn"] })).to.equal("REFUSED");
      expect(state({ records: [one.path], accepted: [one], observations: [], errors: [] })).to.equal("ACCEPTED");
      expect(state({ records: [one.path], accepted: [one], observations: [], errors: ["x"] })).to.equal("REFUSED");
      // Two records, one accepted: the other is not history, it is a refusal (one good record never stands for it).
      expect(state({ records: [one.path, "b.json"], accepted: [one], observations: [], errors: [] })).to.equal(
        "REFUSED",
      );
      expect(state({ records: [one.path], accepted: [], observations: [], errors: [] })).to.equal("REFUSED");
    });
  });

  describe("a synthetic repository: a v1 exercise beside a v2 exercise", function () {
    const dirs = tempDirs();
    afterEach(() => dirs.cleanup());
    const git = (cwd: string, ...args: string[]) => {
      const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout.trim();
    };
    const write = (d: string, rel: string, text: string) => {
      mkdirSync(join(d, dirname(rel)), { recursive: true });
      writeFileSync(join(d, rel), text);
    };
    const commit = (d: string, message: string) => {
      git(d, "add", "-A");
      git(d, "commit", "-q", "--allow-empty", "-m", message);
      return git(d, "rev-parse", "HEAD");
    };
    const archive: ArchiveEvidence = {
      records: [productionRecordRel(ANCHOR)],
      record: ARCHIVE_RECORD,
      observations: [],
      errors: [],
    };
    const judge = (d: string, a: ArchiveEvidence = archive) =>
      productionExerciseEvidence(d, { anchor: ANCHOR, archive: a });
    /** Refused, with nothing accepted, every pattern among the reasons. */
    const refused = (d: string, ...patterns: (RegExp | string)[]) => {
      const e = judge(d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("REFUSED");
      expect(e.accepted).to.deep.equal([]);
      const text = e.errors.join("\n");
      for (const p of patterns) {
        if (typeof p === "string") expect(text).to.include(p);
        else expect(text).to.match(p);
      }
      return e;
    };
    const writeExercise = (d: string, e: Exercise, at: Exercise["files"] = e.files) => {
      write(d, at.run, serializeJson(e.run));
      write(d, at.verification, serializeJson(e.verification));
      write(d, at.record, serializeJson(e.record));
    };

    /** The archived state: the synthetic archive record, the four tools, the acquisitions, designation, canonical build. */
    function archivedRepo(): { d: string; base: string; x: ExerciseExpectations } {
      const d = dirs.make("sp1-pa3d0-");
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(d, "zkvm/host/src/main.rs", "fn main() {}\n");
      write(d, PROOF_INPUT_FIXTURE_REL, '{\n  "synthetic": "proof input fixture"\n}\n');
      write(d, RUN_SCRIPT_REL, "// synthetic v1 measurement tool\n");
      write(d, VERIFICATION_SCRIPT_REL, "// synthetic verification tool\n");
      write(d, ATTRIBUTED_RUN_SCRIPT_REL, "// synthetic attributed measurement tool\n");
      write(d, OBSERVER_SCRIPT_REL, "// synthetic observer\n");
      for (const host of ["developer-workstation", "github-hosted-runner"]) {
        write(
          d,
          `${OBSERVATIONS_DIR}/circuit-acquisition-${host}.raw.json`,
          serializeJson({ host, transfer: { remoteIp: "203.0.113.5" } }),
        );
      }
      commit(d, "the tools");
      const tree = git(d, "rev-parse", "HEAD:zkvm/host");
      write(
        d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1, subject: { zkvmHostTree: tree } }),
      );
      write(
        d,
        CANONICAL_REBUILD_OBSERVATION_REL,
        serializeJson({
          builds: [{ hostId: "x", subject: { zkvmHostTree: tree }, hostBinarySha256: HOST_BINARY_SHA }],
        }),
      );
      const base = commit(d, "archived state");
      return { d, base, x: exerciseExpectations(d, { anchor: ANCHOR, archive }) };
    }

    /** The archived state, then a v1 exercise (SP1-PA3B's shape) committed, then a v2 beside it (unless `v2: false`). */
    function coexisting(opts: { v1?: boolean; v2?: boolean } = {}) {
      const { d, base, x } = archivedRepo();
      const v1 = exerciseOf(x, base, "v1");
      const v2 = exerciseOf(x, base, "v2");
      if (opts.v1 !== false) {
        writeExercise(d, v1);
        commit(d, "the v1 exercise (SP1-PA3B's shape)");
      }
      if (opts.v2 !== false) {
        writeExercise(d, v2);
        commit(d, "a v2 exercise beside it");
      }
      return { d, base, x, v1, v2 };
    }

    it("is ACCEPTED: the v1 slot and the v2 record, each derived from its own observations, one state", function () {
      this.timeout(120_000);
      const { d, v1, v2 } = coexisting();
      const e = judge(d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(exerciseHistoryErrors(d, D)).to.deep.equal([]);
      expect(e.records).to.deep.equal([v1.files.record, v2.files.record]);
      expect(e.accepted.map((a) => [a.path, a.generation])).to.deep.equal([
        [v1.files.record, "v1"],
        [v2.files.record, "v2"],
      ]);
      expect(e.accepted.map((a) => a.observations)).to.deep.equal([
        [v1.files.run, v1.files.verification],
        [v2.files.run, v2.files.verification],
      ]);
      // Both bind the same designation, archive record and program; they are two exercises, not one twice.
      const [r1, r2] = e.accepted.map((a) => a.record);
      expect([r1.subject, r1.archiveRecord]).to.deep.equal([r2.subject, r2.archiveRecord]);
      expect(r1.exercise.id).to.not.equal(r2.exercise.id);
      expect(r1.proof.proofBytesSha256).to.not.equal(r2.proof.proofBytesSha256);
      expect([r1.schema, r2.schema]).to.deep.equal([EXERCISE_RECORD_SCHEMA, EXERCISE_RECORD_SCHEMA_V2]);
      // Each record is exactly what its own pair derives, byte for byte: neither is read through the other.
      expect(serializeJson(r1)).to.equal(readFileSync(join(d, v1.files.record), "utf8"));
      expect(serializeJson(r2)).to.equal(readFileSync(join(d, v2.files.record), "utf8"));
      // The same host label for both runs, distinct files: the v2's names carry its token.
      expect([v1.run.host, v2.run.host]).to.deep.equal([HOST_A, HOST_A]);
      expect(v2.files.run).to.equal(
        `${OBSERVATIONS_DIR}/${RUN_OBSERVATION_PREFIX}${HOST_A}.${exerciseToken(serializeJson(v2.run))}.raw.json`,
      );
      // Each keeps its own egress assurance: the v1 edge-probed only (nothing of the v2's reaches it), the v2 its own.
      expect(egressAssuranceOfRecord(r1)).to.deep.equal(EDGE_PROBES_ONLY);
      expect(Object.keys(r1.egress).sort()).to.deep.equal(["condition", "enforcement", "probes"]);
      expect(egressAssuranceOfRecord(r2).level).to.equal("CONTINUOUS_ATTRIBUTED");
      // Two exercises, one state: the same third state one exercise derives.
      expect(toolingState({ selfTestPassed: true, archive, exercise: e })).to.equal("SELF_HOSTED_PATH_EXERCISED");
    });

    it("each alone is ACCEPTED too (the v1 by itself, a v2 by itself), in either commit order", function () {
      this.timeout(120_000);
      for (const opts of [{ v2: false }, { v1: false }]) {
        const { d } = coexisting(opts);
        const e = judge(d);
        expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
        expect(e.accepted.map((a) => a.generation)).to.deep.equal([opts.v2 === false ? "v1" : "v2"]);
      }
      // The v2 committed first and the v1 after it: the same two records, the same verdict.
      const { d, base, x } = archivedRepo();
      writeExercise(d, exerciseOf(x, base, "v2"));
      commit(d, "the v2 first");
      writeExercise(d, exerciseOf(x, base, "v1"));
      commit(d, "the v1 after");
      expect(judge(d).accepted.map((a) => a.generation)).to.deep.equal(["v1", "v2"]);
    });

    it("a second v1 is refused: under another name, or as a second pair of v1-slot observations", function () {
      this.timeout(120_000);
      let r = coexisting();
      write(r.d, `${PROOF_EXERCISES_DIR}/${D}.v1.json`, readFileSync(join(r.d, r.v1.files.record), "utf8"));
      commit(r.d, "a second v1 record under another name");
      refused(r.d, `${PROOF_EXERCISES_DIR}/${D}.v1.json is no proof-exercise record of ${D}`);
      // A second v1 exercise from another host: its untokened files join the one v1 slot, which holds one exercise.
      r = coexisting();
      const other = exerciseOf(r.x, r.base, "v1", { host: "proving-host-b", fill: 0xef });
      write(r.d, other.files.run, serializeJson(other.run));
      write(r.d, other.files.verification, serializeJson(other.verification));
      commit(r.d, "a second v1 pair");
      refused(
        r.d,
        /needs exactly one run observation .*holds 2/,
        /needs exactly one verification observation .*holds 2/,
      );
    });

    it("a second v2 is refused: the contract admits one, and names both", function () {
      this.timeout(120_000);
      const r = coexisting();
      const second = exerciseOf(r.x, r.base, "v2", { fill: 0xef });
      writeExercise(r.d, second);
      commit(r.d, "a second v2");
      const names = [r.v2.files.record, second.files.record].sort();
      refused(r.d, `${PROOF_EXERCISES_DIR} holds 2 v2 records (${names.join(", ")}); the contract admits at most 1`);
    });

    it("one exercise under two names is refused: a copied record, copied observations, or v1 bytes under a v2 name", function () {
      this.timeout(120_000);
      // The v2 record's bytes under another token: that exercise has no observations, and two v2 records are one too many.
      let r = coexisting();
      write(r.d, attributedExerciseRecordRel(ANCHOR, T1), readFileSync(join(r.d, r.v2.files.record), "utf8"));
      commit(r.d, "the v2 record copied");
      refused(
        r.d,
        `${attributedExerciseRecordRel(ANCHOR, T1)} needs exactly one run observation`,
        "holds 2 v2 records",
      );
      // The v2 run copied under another host label, same token: two runs for one exercise.
      r = coexisting();
      const copy = r.v2.files.run.replace(`${HOST_A}.`, "proving-host-b.");
      write(r.d, copy, readFileSync(join(r.d, r.v2.files.run), "utf8"));
      commit(r.d, "the v2 run copied");
      refused(r.d, `${r.v2.files.record} needs exactly one run observation`);
      // SP1-PA3B's record bytes under a v2 name of its own token: a v2 name with no observations, and a v1 record.
      r = coexisting({ v2: false });
      const v1Token = exerciseToken(serializeJson(r.v1.run));
      write(r.d, attributedExerciseRecordRel(ANCHOR, v1Token), readFileSync(join(r.d, r.v1.files.record), "utf8"));
      commit(r.d, "the v1 record under a v2 name");
      refused(r.d, `${attributedExerciseRecordRel(ANCHOR, v1Token)} needs exactly one run observation`);
    });

    it("a v2 of another designation, PROGRAM_VKEY or archive is refused, and the v1 does not stand for it", function () {
      this.timeout(180_000);
      // Named for another designation: no record of this one's.
      let r = coexisting({ v2: false });
      const v2 = exerciseOf(r.x, r.base, "v2");
      writeExercise(r.d, v2, { ...v2.files, record: v2.files.record.replace(`/${D}.v2.`, "/other-designation.v2.") });
      commit(r.d, "a v2 named for another designation");
      refused(r.d, `other-designation.v2.`, "is no proof-exercise record of", `observations of exercise`);
      // A v2 whose run names another PROGRAM_VKEY or another archive record: refused by its own reasons, under its own
      // record's name (the files named after the edited run, as a consistent forger would name them).
      for (const [edit, reason] of [
        [
          (run: RunObservation) => (run.anchor = { ...run.anchor, programVKey: `0x${"11".repeat(32)}` }),
          "ANCHOR_MISMATCH",
        ],
        [(run: RunObservation) => (run.proof.vkey = `0x${"11".repeat(32)}`), "PROOF_MISMATCH"],
        [
          (run: RunObservation) => (run.archiveRecord = { ...run.archiveRecord, sha256: "00".repeat(32) }),
          "ARCHIVE_RECORD_MISMATCH",
        ],
      ] as const) {
        r = coexisting({ v2: false });
        const clean = exerciseOf(r.x, r.base, "v2");
        const forged = structuredClone(clean.run) as RunObservation;
        edit(forged);
        const at = attributedExerciseFiles(ANCHOR, HOST_A, serializeJson(forged));
        writeExercise(
          r.d,
          { ...clean, run: forged },
          { run: at.run, verification: at.verification, record: at.record },
        );
        commit(r.d, `a forged v2 (${reason})`);
        const e = refused(r.d, `${at.record}: ${reason}`);
        expect(
          e.errors.some((x) => x.startsWith(`${r.v1.files.record}:`)),
          "the v1 itself is fine",
        ).to.equal(false);
      }
    });

    it("schema and name must agree: a v2 in the v1 slot (the earlier layout) and a v1 under v2 names are refused", function () {
      this.timeout(120_000);
      // SP1-PA3C's earlier temporary layout: a v2 exercise under the v1 slot's names.
      let r = archivedRepo();
      const v2 = exerciseOf(r.x, r.base, "v2");
      const v1Names = exerciseOf(r.x, r.base, "v1").files;
      writeExercise(r.d, { ...v2, verification: boundVerification(r.x, v2.run, v1Names.run) }, v1Names);
      commit(r.d, "a v2 in the v1 slot");
      refused(
        r.d,
        `${v1Names.run} holds ${RUN_SCHEMA_V2}, but the v1 slot admits only a ${RUN_SCHEMA} run`,
        `${v1Names.record} holds ${EXERCISE_RECORD_SCHEMA_V2}, but its name is a v1 record's (${EXERCISE_RECORD_SCHEMA})`,
      );
      // A v1 exercise under the names of its token: a v2 name, a v1 run and a v1 record.
      r = archivedRepo();
      const v1 = exerciseOf(r.x, r.base, "v1");
      const at = attributedExerciseFiles(ANCHOR, HOST_A, serializeJson(v1.run));
      writeExercise(
        r.d,
        { ...v1, verification: boundVerification(r.x, v1.run, at.run) },
        { run: at.run, verification: at.verification, record: at.record },
      );
      commit(r.d, "a v1 under v2 names");
      refused(
        r.d,
        `${at.run} holds ${RUN_SCHEMA}, but exercise ${at.token} admits only a ${RUN_SCHEMA_V2} run`,
        `${at.record} holds ${EXERCISE_RECORD_SCHEMA}, but its name is a v2 record's (${EXERCISE_RECORD_SCHEMA_V2})`,
      );
    });

    it("an unknown schema, malformed JSON, an unknown file or a directory in the authoritative directory refuses it", function () {
      this.timeout(120_000);
      let r = coexisting();
      const rec = JSON.parse(readFileSync(join(r.d, r.v2.files.record), "utf8"));
      write(r.d, r.v2.files.record, serializeJson({ ...rec, schema: "walletwall.sp1-proof-exercise.v9" }));
      commit(r.d, "an unknown schema");
      refused(r.d, `${r.v2.files.record} holds walletwall.sp1-proof-exercise.v9, but its name is a v2 record's`);
      r = coexisting();
      write(r.d, r.v2.files.record, "{ not json\n");
      commit(r.d, "malformed");
      refused(r.d, `${r.v2.files.record} is not JSON`);
      r = coexisting();
      write(r.d, `${PROOF_EXERCISES_DIR}/README.md`, "notes\n");
      commit(r.d, "a stray file");
      refused(r.d, `${PROOF_EXERCISES_DIR}/README.md is no proof-exercise record of ${D}`);
      // A directory in the authoritative directory, even one named as a record (and its contents count for nothing).
      r = coexisting({ v2: false });
      write(r.d, `${PROOF_EXERCISES_DIR}/sub/${basename(r.v2.files.record)}`, serializeJson(r.v2.record));
      commit(r.d, "a subdirectory");
      refused(r.d, `${PROOF_EXERCISES_DIR}/sub is no proof-exercise record of ${D}`);
      r = coexisting({ v2: false });
      write(r.d, r.v2.files.run, serializeJson(r.v2.run));
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      write(r.d, `${r.v2.files.record}/x.json`, "{}\n");
      commit(r.d, "a directory named as the v2 record");
      refused(r.d, `${r.v2.files.record} is not a regular file directly in ${PROOF_EXERCISES_DIR}`);
      // An observation that is a directory: refused, never read.
      r = coexisting({ v2: false });
      write(r.d, `${r.v2.files.run}/x.json`, "{}\n");
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      write(r.d, r.v2.files.record, serializeJson(r.v2.record));
      commit(r.d, "a directory named as the v2 run");
      refused(r.d, `${r.v2.files.run} is not a regular file directly in ${OBSERVATIONS_DIR}`);
      // A stray proof-exercise name is no observation of any kind: listed as other, and refused by the judge.
      r = coexisting();
      write(r.d, `${OBSERVATIONS_DIR}/proof-exercise-notes.raw.json`, "{}\n");
      commit(r.d, "a stray observation name");
      expect(exerciseObservationsIn(r.d)).to.deep.equal({
        run: [r.v1.files.run, r.v2.files.run].sort(),
        verification: [r.v1.files.verification, r.v2.files.verification].sort(),
        other: [`${OBSERVATIONS_DIR}/proof-exercise-notes.raw.json`],
      });
      refused(r.d, "proof-exercise-notes.raw.json, which is no proof-exercise observation");
    });

    it("an exercise whose expectations the committed evidence cannot give is refused with that reason alone", function () {
      this.timeout(120_000);
      const r = coexisting();
      write(
        r.d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1 }),
      );
      commit(r.d, "a designation without its host tree");
      const e = judge(r.d);
      expect(exerciseEvidenceState(e)).to.equal("REFUSED");
      expect(e.accepted).to.deep.equal([]);
      expect(e.errors).to.deep.equal([`the designation ${ANCHOR.designation} names no zkvmHostTree`]);
    });

    it("a record outside the authoritative directory counts for nothing, neither as a record nor beside one", function () {
      this.timeout(120_000);
      const r = coexisting({ v2: false });
      // A complete v2 exercise, its record committed one directory up: the directory holds the v1 alone.
      write(r.d, `evidence/zk/sp1-impl/${basename(r.v2.files.record)}`, serializeJson(r.v2.record));
      write(r.d, `evidence/zk/sp1-impl/elsewhere/${basename(r.v2.files.record)}`, serializeJson(r.v2.record));
      commit(r.d, "records outside the directory");
      const e = judge(r.d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(e.accepted.map((a) => a.path)).to.deep.equal([r.v1.files.record]);
      expect(exerciseRecordsIn(r.d)).to.deep.equal([r.v1.files.record]);
    });

    it("a record or an observation that is a link is refused (POSIX)", function () {
      this.timeout(120_000);
      if (process.platform === "win32") this.skip();
      let r = coexisting({ v2: false });
      const target = join(r.d, "elsewhere.json");
      writeFileSync(target, serializeJson(r.v2.record));
      write(r.d, r.v2.files.run, serializeJson(r.v2.run));
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      symlinkSync(target, join(r.d, r.v2.files.record));
      commit(r.d, "a linked v2 record");
      refused(r.d, `${r.v2.files.record} is not a regular file directly in ${PROOF_EXERCISES_DIR}`);
      r = coexisting({ v2: false });
      const runTarget = join(r.d, "run.json");
      writeFileSync(runTarget, serializeJson(r.v2.run));
      symlinkSync(runTarget, join(r.d, r.v2.files.run));
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      write(r.d, r.v2.files.record, serializeJson(r.v2.record));
      commit(r.d, "a linked v2 run");
      refused(r.d, `${r.v2.files.run} is not a regular file directly in ${OBSERVATIONS_DIR}`);
    });

    it("a v2 exercise's observations without its record are refused (nothing is left unaccounted)", function () {
      this.timeout(120_000);
      const r = coexisting({ v2: false });
      write(r.d, r.v2.files.run, serializeJson(r.v2.run));
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      commit(r.d, "the v2 observations, no record yet");
      const token = exerciseToken(serializeJson(r.v2.run));
      refused(
        r.d,
        `the observations of exercise ${token} (${r.v2.files.run}, ${r.v2.files.verification}) and no record of them`,
      );
    });

    it("a refused v2 refuses the directory although the v1 is valid; a refused v1 although the v2 is; both, naming each", function () {
      this.timeout(180_000);
      // The v2's verification rejected the proof: the v2 is refused, and with it the directory, not the v1 alone kept.
      let r = coexisting({ v2: false });
      const rejected = structuredClone(r.v2);
      rejected.verification.acceptance = "REJECTED";
      writeExercise(r.d, rejected);
      commit(r.d, "a v2 the verifier rejected");
      let e = refused(r.d, `${r.v2.files.record}: VERIFIER_REJECTED`);
      expect(e.errors.every((x) => !x.startsWith(`${r.v1.files.record}:`))).to.equal(true);
      // The v1's run edited after its record was derived: the v1 is refused, the valid v2 does not stand for it.
      r = coexisting();
      const editedRun = JSON.parse(readFileSync(join(r.d, r.v1.files.run), "utf8"));
      editedRun.platform.push("edited after verification");
      write(r.d, r.v1.files.run, serializeJson(editedRun));
      commit(r.d, "the v1 run edited");
      e = refused(r.d, `${r.v1.files.record}: RUN_NOT_BOUND`);
      expect(e.errors.every((x) => !x.startsWith(`${r.v2.files.record}:`))).to.equal(true);
      // Both: each named by its own reason.
      write(r.d, r.v2.files.verification, serializeJson({ ...r.v2.verification, acceptance: "REJECTED" }));
      commit(r.d, "and the v2 rejected");
      refused(r.d, `${r.v1.files.record}: RUN_NOT_BOUND`, `${r.v2.files.record}: VERIFIER_REJECTED`);
    });

    it("one proof is one exercise: a v2 that records the v1's proof is refused", function () {
      this.timeout(120_000);
      const r = coexisting({ v2: false });
      const same = exerciseOf(r.x, r.base, "v2", { fill: 0xab });
      expect(same.record.proof.proofBytesSha256).to.equal(r.v1.record.proof.proofBytesSha256);
      writeExercise(r.d, same);
      commit(r.d, "a v2 of the v1's proof");
      refused(
        r.d,
        `${r.v1.files.record} and ${same.files.record} hold byte-identical proofs (proofBytesSha256 ${same.record.proof.proofBytesSha256}): one proof is one exercise, never two records`,
      );
      // Only accepted records count toward a duplicate: a refused v2 of the same proof is refused for its own reason.
      const again = coexisting({ v2: false });
      const rejected = exerciseOf(again.x, again.base, "v2", { fill: 0xab });
      rejected.verification.acceptance = "REJECTED";
      writeExercise(again.d, rejected);
      commit(again.d, "a rejected v2 of the v1's proof");
      const e = refused(again.d, `${rejected.files.record}: VERIFIER_REJECTED`);
      expect(e.errors.join("\n")).to.not.include("byte-identical proofs");
      // A v2 of that proof whose pair derives but whose committed record is not the derived one: refused only after
      // its derivation, and still never counted as a second exercise of the proof.
      const late = coexisting({ v2: false });
      const edited = exerciseOf(late.x, late.base, "v2", { fill: 0xab });
      writeExercise(late.d, { ...edited, record: { ...edited.record, establishes: "edited by hand" } });
      commit(late.d, "a v2 of the v1's proof, its record edited by hand");
      const l = refused(
        late.d,
        `${edited.files.record}: ${edited.files.record} is not the record the committed observations derive`,
      );
      expect(l.errors.join("\n")).to.not.include("byte-identical proofs");
    });

    it("a v2 named after another token than its run's bytes is refused (a name is a function of the bytes)", function () {
      this.timeout(120_000);
      const r = coexisting({ v2: false });
      const token = exerciseToken(serializeJson(r.v2.run));
      const wrong = {
        run: r.v2.files.run.replace(token, T1),
        verification: r.v2.files.verification.replace(token, T1),
        record: attributedExerciseRecordRel(ANCHOR, T1),
      };
      writeExercise(r.d, { ...r.v2, verification: boundVerification(r.x, r.v2.run, wrong.run) }, wrong);
      commit(r.d, "a v2 under another token");
      const e = refused(r.d, `${wrong.run} is exercise ${token} (the first 16 hex digits of its sha256), not ${T1}`);
      // The name is judged before the bytes: nothing else is said of that exercise until its name is its own.
      expect(e.errors.filter((x) => x.startsWith(`${wrong.record}:`))).to.deep.equal([
        `${wrong.record}: ${wrong.run} is exercise ${token} (the first 16 hex digits of its sha256), not ${T1}: an exercise's files are named after the exercise they hold`,
      ]);
    });

    it("history: SP1-PA3B's v1 withdrawn after the v2 is refused, committed or in the working tree, and so are both", function () {
      this.timeout(180_000);
      let r = coexisting();
      for (const rel of Object.values(r.v1.files)) rmSync(join(r.d, rel));
      commit(r.d, "the v1 withdrawn");
      // The v2 alone would be a valid directory; the history says the v1 was committed and is gone.
      const e = refused(
        r.d,
        `${PROOF_EXERCISES_DIR} at commit`,
        `${D}.json was removed or renamed; a published record is never withdrawn`,
      );
      expect(e.records).to.deep.equal([r.v2.files.record]);
      r = coexisting();
      rmSync(join(r.d, r.v1.files.record));
      refused(r.d, `${PROOF_EXERCISES_DIR} in the working tree (against HEAD): ${D}.json was removed or renamed`);
      // Every record withdrawn: no record left, still never NO_RECORD.
      r = coexisting();
      for (const rel of [...Object.values(r.v1.files), ...Object.values(r.v2.files)]) rmSync(join(r.d, rel));
      commit(r.d, "everything withdrawn");
      const none = judge(r.d);
      expect(none.records).to.deep.equal([]);
      expect(exerciseEvidenceState(none)).to.equal("REFUSED");
      expect(none.errors.join("\n")).to.include(`${D}.json was removed or renamed`);
      expect(none.errors.join("\n")).to.include(`${basename(r.v2.files.record)} was removed or renamed`);
    });

    it("history: a committed record edited and committed again is refused with its derivation's own reason (never restamped)", function () {
      this.timeout(120_000);
      const r = coexisting();
      const rec = JSON.parse(readFileSync(join(r.d, r.v1.files.record), "utf8"));
      rec.performance.wallClockSeconds = 1;
      write(r.d, r.v1.files.record, serializeJson(rec));
      commit(r.d, "the v1 record restamped");
      refused(
        r.d,
        `${D}.json was changed; a published record is never edited`,
        `${r.v1.files.record}: ${r.v1.files.record} is not the record the committed observations derive`,
      );
    });

    it("history: an exercise observation is never edited once committed, even into equal facts; other kinds are re-measured", function () {
      this.timeout(180_000);
      const r = coexisting();
      const ver = JSON.parse(readFileSync(join(r.d, r.v1.files.verification), "utf8"));
      write(r.d, r.v1.files.verification, `${JSON.stringify(ver, null, 4)}\n`);
      commit(r.d, "the v1 verification re-indented: the same facts, other bytes");
      // The derivation alone would accept it (the record holds the facts, not the bytes); the history does not.
      const e = refused(r.d, `${basename(r.v1.files.verification)} was changed; a published record is never edited`);
      expect(e.errors.every((x) => !x.startsWith(`${r.v1.files.record}:`))).to.equal(true);
      // An observation of another kind in the same directory is no exercise evidence: re-measuring it is no edit of one.
      const s = coexisting();
      write(s.d, `${OBSERVATIONS_DIR}/host-advisories-x.raw.json`, '{ "measured": 1 }\n');
      commit(s.d, "another kind of observation");
      write(s.d, `${OBSERVATIONS_DIR}/host-advisories-x.raw.json`, '{ "measured": 2 }\n');
      commit(s.d, "re-measured");
      const ok = judge(s.d);
      expect(exerciseEvidenceState(ok), ok.errors.join("\n")).to.equal("ACCEPTED");
      // ... and re-measured again in the working tree only: still none of the exercise's evidence.
      write(s.d, `${OBSERVATIONS_DIR}/host-advisories-x.raw.json`, '{ "measured": 3 }\n');
      const still = judge(s.d);
      expect(exerciseEvidenceState(still), still.errors.join("\n")).to.equal("ACCEPTED");
    });

    it("history: an attempt whose record was never committed may still be dropped, renamed or re-made", function () {
      this.timeout(240_000);
      // A rejected attempt, committed so it could be verified and judged, then dropped: the v1 stands alone again.
      let r = coexisting({ v2: false });
      const rejected = structuredClone(r.v2);
      rejected.verification.acceptance = "REJECTED";
      write(r.d, rejected.files.run, serializeJson(rejected.run));
      write(r.d, rejected.files.verification, serializeJson(rejected.verification));
      commit(r.d, "an attempt, its verification rejected");
      refused(r.d, "and no record of them");
      for (const rel of [rejected.files.run, rejected.files.verification]) rmSync(join(r.d, rel));
      commit(r.d, "the attempt dropped");
      let e = judge(r.d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(e.accepted.map((a) => a.path)).to.deep.equal([r.v1.files.record]);
      // Files committed under a mistyped token, then renamed after the run's own token, then derived: accepted.
      r = coexisting({ v2: false });
      const token = exerciseToken(serializeJson(r.v2.run));
      const wrong = {
        run: r.v2.files.run.replace(token, T1),
        verification: r.v2.files.verification.replace(token, T1),
      };
      write(r.d, wrong.run, serializeJson(r.v2.run));
      write(r.d, wrong.verification, serializeJson(boundVerification(r.x, r.v2.run, wrong.run)));
      commit(r.d, "an attempt under a mistyped token");
      for (const rel of [wrong.run, wrong.verification]) rmSync(join(r.d, rel));
      write(r.d, r.v2.files.run, serializeJson(r.v2.run));
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      commit(r.d, "renamed after the run's own token");
      const p = derivePendingExerciseRecord(r.d, { anchor: ANCHOR, archive });
      write(r.d, p.rel, serializeJson(p.record));
      commit(r.d, "its record derived");
      e = judge(r.d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(e.accepted.map((a) => a.path)).to.deep.equal([r.v1.files.record, r.v2.files.record]);
      // A verification re-made under the same name before the record exists is no edit of evidence ...
      r = coexisting({ v2: false });
      write(r.d, r.v2.files.run, serializeJson(r.v2.run));
      write(
        r.d,
        r.v2.files.verification,
        serializeJson({ ...r.v2.verification, measuredAtUtc: "2026-11-01T12:20:00Z" }),
      );
      commit(r.d, "a first verification");
      write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
      commit(r.d, "verified again, before any record");
      writeExercise(r.d, r.v2);
      commit(r.d, "the record");
      e = judge(r.d);
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      // ... and from the record on, the same rewrite is: the observations are as permanent as their record.
      write(
        r.d,
        r.v2.files.verification,
        serializeJson({ ...r.v2.verification, measuredAtUtc: "2026-11-01T12:20:00Z" }),
      );
      commit(r.d, "re-verified after the record");
      refused(r.d, `${basename(r.v2.files.verification)} was changed; a published record is never edited`);
    });

    it("a committed v2 freezes its tools: an edit refuses the directory, the v1 with it; only the old bytes restore it", function () {
      this.timeout(180_000);
      const r = coexisting();
      const tool = readFileSync(join(r.d, ATTRIBUTED_RUN_SCRIPT_REL), "utf8");
      write(r.d, ATTRIBUTED_RUN_SCRIPT_REL, `${tool}// a later edit\n`);
      commit(r.d, "the attributed tool edited after the v2 was committed");
      const e = refused(r.d, `${r.v2.files.record}: TOOL_NOT_BOUND`);
      expect(
        e.errors.some((x) => x.startsWith(`${r.v1.files.record}:`)),
        "the v1 itself is fine",
      ).to.equal(false);
      // Only the old bytes restore the directory.
      write(r.d, ATTRIBUTED_RUN_SCRIPT_REL, tool);
      commit(r.d, "the attributed tool restored");
      expect(judge(r.d).accepted.map((a) => a.path)).to.deep.equal([r.v1.files.record, r.v2.files.record]);
      // Withdrawing the stale v2 instead is refused: the history keeps it.
      write(r.d, ATTRIBUTED_RUN_SCRIPT_REL, `${tool}// a later edit\n`);
      for (const rel of Object.values(r.v2.files)) rmSync(join(r.d, rel));
      commit(r.d, "the v2 withdrawn instead");
      refused(r.d, `${basename(r.v2.files.record)} was removed or renamed; a published record is never withdrawn`);
    });

    it("a history git cannot show is refused, never read as clean: no repository, no commit, a shallow clone", function () {
      this.timeout(120_000);
      const bare = dirs.make("sp1-pa3d0-nogit-");
      expect(exerciseHistoryErrors(bare, D).join("\n")).to.match(/needs a git repository with its full history/);
      expect(exerciseEvidenceState(judge(bare))).to.equal("REFUSED");
      const empty = dirs.make("sp1-pa3d0-empty-");
      git(empty, "init", "-q");
      expect(exerciseHistoryErrors(empty, D).join("\n")).to.match(/cannot be read .*: no history is taken as clean/);
      const r = coexisting();
      const shallow = dirs.make("sp1-pa3d0-shallow-");
      git(shallow, "clone", "-q", "--depth", "1", pathToFileURL(r.d).href, ".");
      expect(exerciseHistoryErrors(shallow, D).join("\n")).to.match(/this clone is shallow/);
      expect(exerciseEvidenceState(judge(shallow))).to.equal("REFUSED");
    });

    describe("the one record a committed exercise lacks (derivePendingExerciseRecord, what sp1:proof-exercise-record writes)", function () {
      const pending = (d: string, a: ArchiveEvidence = archive) =>
        derivePendingExerciseRecord(d, { anchor: ANCHOR, archive: a });

      it("derives the v2's record beside the v1, which then accepts both; and the v1's beside nothing", function () {
        this.timeout(120_000);
        const r = coexisting({ v2: false });
        write(r.d, r.v2.files.run, serializeJson(r.v2.run));
        write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
        commit(r.d, "the v2 observations");
        const p = pending(r.d);
        expect(p.rel).to.equal(r.v2.files.record);
        expect(p.record).to.deep.equal(r.v2.record);
        write(r.d, p.rel, serializeJson(p.record));
        commit(r.d, "the v2 record derived");
        expect(judge(r.d).accepted.map((a) => a.path)).to.deep.equal([r.v1.files.record, r.v2.files.record]);
        const v1Only = archivedRepo();
        const v1 = exerciseOf(v1Only.x, v1Only.base, "v1");
        write(v1Only.d, v1.files.run, serializeJson(v1.run));
        write(v1Only.d, v1.files.verification, serializeJson(v1.verification));
        commit(v1Only.d, "the v1 observations");
        expect(pending(v1Only.d)).to.deep.equal({ rel: exerciseRecordRel(ANCHOR), record: v1.record });
      });

      it("refuses to derive anything twice, two at a time, past the count, uncommitted, mis-named or on a refused archive", function () {
        this.timeout(180_000);
        let r = coexisting();
        assert.throws(() => pending(r.d), /nothing to derive: every committed exercise .* already has its record/);
        // Two exercises without a record: one at a time.
        const two = archivedRepo();
        for (const g of ["v1", "v2"] as const) {
          const x = exerciseOf(two.x, two.base, g);
          write(two.d, x.files.run, serializeJson(x.run));
          write(two.d, x.files.verification, serializeJson(x.verification));
        }
        commit(two.d, "two pending");
        assert.throws(
          () => pending(two.d),
          /2 exercises have no record \(the v1 slot, [0-9a-f]{16}\): derive one at a time/,
        );
        // A second v2 pending beside the v1 and a v2 already recorded: past the contract's count.
        r = coexisting();
        const second = exerciseOf(r.x, r.base, "v2", { fill: 0xef });
        write(r.d, second.files.run, serializeJson(second.run));
        write(r.d, second.files.verification, serializeJson(second.verification));
        commit(r.d, "a second v2 pending");
        assert.throws(() => pending(r.d), /already holds 1 v2 record\(s\), the most the contract admits/);
        // Observations not committed; an exercise short of its verification.
        r = coexisting({ v2: false });
        write(r.d, r.v2.files.run, serializeJson(r.v2.run));
        write(r.d, r.v2.files.verification, serializeJson(r.v2.verification));
        assert.throws(() => pending(r.d), /not as committed .*UNTRACKED/);
        rmSync(join(r.d, r.v2.files.verification));
        assert.throws(
          () => pending(r.d),
          /needs exactly one run observation and exactly one verification observation \(it has 1 run, 0 verification\)/,
        );
        // A v2 run under the v1 slot's names (the v1 slot empty): named after its token instead.
        const slot = archivedRepo();
        const v2 = exerciseOf(slot.x, slot.base, "v2");
        const v1Names = exerciseOf(slot.x, slot.base, "v1").files;
        write(slot.d, v1Names.run, serializeJson(v2.run));
        write(slot.d, v1Names.verification, serializeJson(boundVerification(slot.x, v2.run, v1Names.run)));
        commit(slot.d, "a v2 in the v1 slot's names");
        assert.throws(
          () => pending(slot.d),
          new RegExp(
            `admits only a ${RUN_SCHEMA.replace(/\./g, "\\.")} run: a v2 exercise's files are named after its token \\(${v2.files.run.replace(/\./g, "\\.")}\\)`,
          ),
        );
        // A v2 under another token than its run's.
        r = coexisting({ v2: false });
        const token = exerciseToken(serializeJson(r.v2.run));
        write(r.d, r.v2.files.run.replace(token, T1), serializeJson(r.v2.run));
        write(r.d, r.v2.files.verification.replace(token, T1), serializeJson(r.v2.verification));
        commit(r.d, "a v2 under another token");
        assert.throws(() => pending(r.d), new RegExp(`is exercise ${token}, not ${T1}: name its files after it`));
        // A refused archive, even one whose record object is still there: nothing an exercise could have run from.
        assert.throws(
          () => pending(r.d, { ...archive, errors: ["MIRRORS_MISSING"] }),
          /no accepted archive record \(REFUSED\): nothing an exercise could have run from/,
        );
        // A directory the names refuse.
        r = coexisting();
        write(r.d, `${PROOF_EXERCISES_DIR}/README.md`, "x\n");
        commit(r.d, "a stray file");
        assert.throws(() => pending(r.d), /the exercise directory is refused, so no record is derived/);
      });
    });
  });

  describe("this checkout's real history, a synthetic v2 beside SP1-PA3B's real v1", function () {
    const dirs = tempDirs();
    afterEach(() => dirs.cleanup());
    const git = (cwd: string, ...args: string[]) => {
      const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout.trim();
    };
    const commitAll = (d: string, message: string) => {
      git(d, "add", "-A");
      git(d, "commit", "-q", "-m", message);
    };
    /**
     * A repository holding this checkout's HEAD and its whole history (so SP1-PA3B's source commit is in it), checked
     * out, then a synthetic v2 exercise bound to the real anchor, archive record, tools, host binary and probe targets,
     * run at that HEAD on SP1-PA3B's own host label, its three files committed; with `regenerate`, the availability
     * record then derived and committed.
     */
    /** A repository holding this checkout's HEAD and its whole history, checked out. */
    function realRepo() {
      const d = dirs.make("sp1-pa3d0-real-");
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      git(d, "fetch", "-q", resolve("."), "HEAD");
      git(d, "checkout", "-q", "--detach", "FETCH_HEAD");
      return d;
    }
    function realWithV2(regenerate = false) {
      const d = realRepo();
      const anchor = committedProductionAnchor(d);
      const archive = productionArchiveEvidenceOf(d);
      const x = exerciseExpectations(d, { anchor, archive });
      const v2 = exerciseOf(x, git(d, "rev-parse", "HEAD"), "v2", { host: "developer-workstation-wsl2" });
      for (const [rel, value] of [
        [v2.files.run, v2.run],
        [v2.files.verification, v2.verification],
        [v2.files.record, v2.record],
      ] as const) {
        writeFileSync(join(d, rel), serializeJson(value));
      }
      commitAll(d, "a synthetic v2 beside SP1-PA3B's v1");
      if (regenerate) {
        writeFileSync(join(d, PROVING_AVAILABILITY_REL), serializeProvingAvailability(provingAvailabilityFromRepo(d)));
        commitAll(d, "availability regenerated");
      }
      return { d, anchor, archive, x, v2 };
    }
    const noProvingWithoutArchive = ASSUMPTIONS.find(
      (a) => a.id === "A_NO_PROVING_WITHOUT_ARCHIVE",
    ) as (typeof ASSUMPTIONS)[number];
    // The assumption reads the availability record and the two listings only; the host fields stay unset, so a change
    // that made it read them fails here instead of passing on a stand-in.
    const evaluateFor = (d: string) => {
      const s = advisoryStateFromRepo(d);
      return noProvingWithoutArchive.evaluate({
        provingAvailability: s.provingAvailability?.doc ?? null,
        archiveRecords: s.archiveRecords,
        exerciseRecords: s.exerciseRecords,
      } as unknown as Parameters<(typeof ASSUMPTIONS)[number]["evaluate"]>[0]);
    };

    it("both accepted, one state: SP1-PA3B's bytes untouched and edge-probed only, the v2 its own assurance", function () {
      this.timeout(240_000);
      const { d, anchor, archive, v2 } = realWithV2();
      const e = productionExerciseEvidence(d, { anchor, archive });
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(exerciseHistoryErrors(d, anchor.designation)).to.deep.equal([]);
      expect(e.accepted.map((a) => a.path)).to.deep.equal([PA3B.record, v2.files.record]);
      expect(e.accepted[0].observations).to.deep.equal([PA3B.run, PA3B.verification]);
      expect([lfSha(PA3B.record, d), lfSha(PA3B.run, d), lfSha(PA3B.verification, d)]).to.deep.equal([
        PA3B.sha256.record,
        PA3B.sha256.run,
        PA3B.sha256.verification,
      ]);
      expect(e.accepted[0].record.exercise.id).to.equal(PA3B.exercise);
      expect(serializeJson(e.accepted[0].record)).to.equal(readFileSync(join(d, PA3B.record), "utf8"));
      expect(egressAssuranceOfRecord(e.accepted[0].record)).to.deep.equal(EDGE_PROBES_ONLY);
      expect(egressAssuranceOfRecord(e.accepted[1].record).level).to.equal("CONTINUOUS_ATTRIBUTED");
      // The same host label: SP1-PA3B's untokened names, the v2's tokened ones, no collision.
      expect(observationSlotOf(basename(v2.files.run))).to.deep.include({ host: "developer-workstation-wsl2" });
      expect(exerciseObservationsIn(d).run).to.deep.equal([PA3B.run, v2.files.run].sort());
      expect(toolingState({ selfTestPassed: true, archive, exercise: e })).to.equal("SELF_HOSTED_PATH_EXERCISED");
    });

    it("availability is stale until regenerated, then accounts for both, each with its own assurance", function () {
      this.timeout(240_000);
      const stale = realWithV2();
      expect(provingAvailabilityErrors(stale.d)).to.deep.equal([
        `${PROVING_AVAILABILITY_REL} is not what the evidence derives: regenerate it`,
      ]);
      const { d, v2 } = realWithV2(true);
      expect(provingAvailabilityErrors(d)).to.deep.equal([]);
      const pa = provingAvailabilityFromRepo(d);
      expect(pa.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(pa.exercises.records).to.equal(2);
      expect(pa.selfHostedPath).to.deep.include({ exercised: true, witnesses: [PA3B.record, v2.files.record] });
      expect(pa.selfHostedPath).to.not.have.property("record");
      expect(
        pa.exercises.accepted?.map((a) => [a.record, a.schema, a.lane, a.exercise, a.egressAssurance]),
      ).to.deep.equal([
        [PA3B.record, EXERCISE_RECORD_SCHEMA, "SP1-PA3B", PA3B.exercise, "EDGE_PROBES_ONLY"],
        [v2.files.record, EXERCISE_RECORD_SCHEMA_V2, "SP1-PA3D", v2.record.exercise.id, "CONTINUOUS_ATTRIBUTED"],
      ]);
      expect(pa.exercises.accepted?.[0].derivedFrom).to.deep.equal([PA3B.run, PA3B.verification]);
    });

    it("tooling derives the third state from both and refuses an availability record that omits either", async function () {
      this.timeout(420_000);
      const { d, v2 } = realWithV2(true);
      const tooling = (await toolingRecordFromRepo(d)) as {
        state: string;
        exercise: { state: string; records: { record: string; egressAssurance: string }[] };
      };
      expect(tooling.state).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(tooling.exercise.state).to.equal("ACCEPTED");
      expect(tooling.exercise.records.map((r) => [r.record, r.egressAssurance])).to.deep.equal([
        [PA3B.record, "EDGE_PROBES_ONLY"],
        [v2.files.record, "CONTINUOUS_ATTRIBUTED"],
      ]);
      // An availability record that names the v1 and omits the v2 (still the exercised status): tooling refuses it by
      // its own check, before any byte comparison, for either account.
      const pa = JSON.parse(readFileSync(join(d, PROVING_AVAILABILITY_REL), "utf8"));
      for (const [edit, what] of [
        [(p: any) => (p.exercises.accepted = p.exercises.accepted.slice(0, 1)), "accepted"],
        [(p: any) => (p.selfHostedPath.witnesses = p.selfHostedPath.witnesses.slice(1)), "witnesses"],
      ] as const) {
        const edited = structuredClone(pa);
        edit(edited);
        writeFileSync(join(d, PROVING_AVAILABILITY_REL), `${JSON.stringify(edited, null, 2)}\n`);
        commitAll(d, `availability omits an exercise (${what})`);
        let message = "";
        await toolingRecordFromRepo(d).catch((error: Error) => (message = error.message));
        expect(message).to.match(
          new RegExp(`proving availability names .* as ${what}, but the exercise evidence accepts`),
        );
      }
    });

    it("the advisory accounts for both, and for no other set", function () {
      this.timeout(240_000);
      const { d, v2 } = realWithV2(true);
      expect(advisoryStateFromRepo(d).exerciseRecords).to.deep.equal([PA3B.record, v2.files.record]);
      const holding = evaluateFor(d);
      expect(holding.holds, holding.observed).to.equal(true);
      expect(holding.observed).to.include(
        `proof-exercise records 2 recorded, 2 on disk (each accepted and a witness: ${PA3B.record}, ${v2.files.record})`,
      );
      // The committed availability accounting for the v1 alone while both are on disk: the assumption does not hold.
      const pa = JSON.parse(readFileSync(join(d, PROVING_AVAILABILITY_REL), "utf8"));
      pa.exercises.accepted = pa.exercises.accepted.slice(0, 1);
      pa.exercises.records = 1;
      pa.selfHostedPath.witnesses = [PA3B.record];
      writeFileSync(join(d, PROVING_AVAILABILITY_REL), `${JSON.stringify(pa, null, 2)}\n`);
      commitAll(d, "availability for the v1 alone");
      expect(evaluateFor(d).holds).to.equal(false);
    });

    it("SP1-PA3B's v1 withdrawn after the v2 is refused: established history never becomes 'only ever a v2'", function () {
      this.timeout(240_000);
      const { d, anchor, archive, v2 } = realWithV2();
      for (const rel of [PA3B.record, PA3B.run, PA3B.verification]) rmSync(join(d, rel));
      commitAll(d, "SP1-PA3B's exercise withdrawn");
      const e = productionExerciseEvidence(d, { anchor, archive });
      expect(e.records).to.deep.equal([v2.files.record]);
      expect(exerciseEvidenceState(e)).to.equal("REFUSED");
      expect(e.accepted).to.deep.equal([]);
      expect(e.errors.join("\n")).to.include(
        "mldsa65-withdrawal-d1.json was removed or renamed; a published record is never withdrawn",
      );
      // And renaming it into the v2's place is the same withdrawal.
      const again = realWithV2();
      renameSync(join(again.d, PA3B.record), join(again.d, PROOF_EXERCISES_DIR, "mldsa65-withdrawal-d1.v1.json"));
      commitAll(again.d, "SP1-PA3B's record renamed");
      const r = productionExerciseEvidence(again.d, { anchor: again.anchor, archive: again.archive });
      expect(exerciseEvidenceState(r)).to.equal("REFUSED");
      expect(r.errors.join("\n")).to.include("mldsa65-withdrawal-d1.json was removed or renamed");
      expect(r.errors.join("\n")).to.include("mldsa65-withdrawal-d1.v1.json is no proof-exercise record");
    });

    it("SP1-PA3B's exercise withdrawn together with the archive record is refused by availability too", function () {
      this.timeout(240_000);
      const d = realRepo();
      const archiveRecord = productionRecordRel(committedProductionAnchor(d));
      for (const rel of [archiveRecord, PA3B.record, PA3B.run, PA3B.verification]) rmSync(join(d, rel));
      commitAll(d, "the archive record and SP1-PA3B's exercise withdrawn together");
      // Without an accepted archive, the exercise evidence is still judged, its history with it: never "unexercised".
      assert.throws(
        () => provingAvailabilityFromRepo(d),
        /the proof-exercise evidence is refused without a record: .*mldsa65-withdrawal-d1\.json was removed or renamed/,
      );
      expect(provingAvailabilityErrors(d).join("\n")).to.match(/mldsa65-withdrawal-d1\.json was removed or renamed/);
    });

    it("SP1-PA3B's observations cannot be restamped, even into content-equivalent bytes", function () {
      this.timeout(240_000);
      const d = realRepo();
      const verification = JSON.parse(readFileSync(join(d, PA3B.verification), "utf8"));
      writeFileSync(join(d, PA3B.verification), `${JSON.stringify(verification, null, 4)}\n`);
      commitAll(d, "SP1-PA3B's verification observation re-indented: the same facts, other bytes");
      const e = productionExerciseEvidence(d, {
        anchor: committedProductionAnchor(d),
        archive: productionArchiveEvidenceOf(d),
      });
      expect(exerciseEvidenceState(e)).to.equal("REFUSED");
      expect(e.errors.join("\n")).to.include(
        `${basename(PA3B.verification)} was changed; a published record is never edited`,
      );
    });
  });

  describe("the real checkout, as merged", function () {
    it("holds SP1-PA3B's v1 byte for byte, its history append-only, and derives the third state from it alone", function () {
      this.timeout(120_000);
      expect([lfSha(PA3B.record), lfSha(PA3B.run), lfSha(PA3B.verification)]).to.deep.equal([
        PA3B.sha256.record,
        PA3B.sha256.run,
        PA3B.sha256.verification,
      ]);
      const anchor = committedProductionAnchor(".");
      const archive = productionArchiveEvidenceOf(".");
      expect(exerciseRecordRel(anchor)).to.equal(PA3B.record);
      expect(exerciseRecordsIn(".")).to.deep.equal([PA3B.record]);
      expect(exerciseObservationsIn(".")).to.deep.equal({
        run: [PA3B.run],
        verification: [PA3B.verification],
        other: [],
      });
      expect(exerciseHistoryErrors(".", anchor.designation)).to.deep.equal([]);
      const e = productionExerciseEvidence(".", { anchor, archive });
      expect(exerciseEvidenceState(e), e.errors.join("\n")).to.equal("ACCEPTED");
      expect(
        e.accepted.map((a) => [a.path, a.generation, a.record.lane, a.record.schema, a.record.exercise.id]),
      ).to.deep.equal([[PA3B.record, "v1", "SP1-PA3B", EXERCISE_RECORD_SCHEMA, PA3B.exercise]]);
      expect(e.accepted[0].record.derivedFrom).to.deep.equal([PA3B.run, PA3B.verification]);
      expect(egressAssuranceOfRecord(e.accepted[0].record)).to.deep.equal(EDGE_PROBES_ONLY);
      expect(toolingState({ selfTestPassed: true, archive, exercise: e })).to.equal("SELF_HOSTED_PATH_EXERCISED");
      const pa = JSON.parse(readFileSync(PROVING_AVAILABILITY_REL, "utf8"));
      expect(pa.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(pa.selfHostedPath.exercised).to.equal(true);
      expect(pa.selfHostedPath.witnesses).to.deep.equal([PA3B.record]);
      expect(pa.selfHostedPath).to.not.have.property("record");
      const receipt = JSON.parse(readFileSync("evidence/zk/sp1-impl/implementation-receipt.json", "utf8"));
      expect([receipt.statuses.PRODUCTION_SP1_BINDING_STATUS.value, receipt.productionBinding.status]).to.deep.equal([
        "NOT_ESTABLISHED",
        "NOT_ESTABLISHED",
      ]);
    });

    it("availability judges the exercise evidence even with no archive evidence beside it (SP1-PA3B's record then refuses)", function () {
      this.timeout(120_000);
      const obs = JSON.parse(readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL, "utf8")) as ProvingArtifactsObservation;
      const e = exerciseEvidenceFromRepo(".", obs, readDesignations("."), null);
      expect(e, "judged, never skipped").to.not.equal(null);
      expect(exerciseEvidenceState(e as ExerciseEvidence)).to.equal("REFUSED");
      expect((e as ExerciseEvidence).errors.join("\n")).to.include(
        "a proof-exercise record exists but the archive evidence is not accepted (NO_RECORD)",
      );
      expect(exerciseEvidenceFromRepo(".", obs, [], null), "no designation, nothing to judge").to.equal(null);
    });

    it("availability holds each accepted exercise to the accepted archive record and the designation, and states each", function () {
      this.timeout(120_000);
      const obsBytes = readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL);
      const obs = JSON.parse(obsBytes.toString("utf8")) as ProvingArtifactsObservation;
      const td1Bytes = readFileSync("evidence/zk/sp1-td1/decision-receipt.json");
      const designations = readDesignations(".");
      const archive = archiveEvidenceFromRepo(".", obs, designations) as ArchiveEvidence;
      const anchor = committedProductionAnchor(".");
      const real = productionExerciseEvidence(".", { anchor, archive });
      const v1 = real.accepted[0];
      // A second accepted exercise beside SP1-PA3B's, as the judge would hand it over: its own path and identity.
      const v2: AcceptedExercise = {
        ...structuredClone(v1),
        path: attributedExerciseRecordRel(anchor, T1),
        generation: "v2",
      };
      v2.record.exercise.id = `${anchor.designation}:${T1}`;
      const two: ExerciseEvidence = { ...real, records: [v1.path, v2.path], accepted: [v1, v2] };
      const base = {
        observation: obs,
        observationSha256: sha256(obsBytes),
        designations,
        td1Receipt: { sha256: sha256(td1Bytes), doc: JSON.parse(td1Bytes.toString("utf8")) },
        archiveRecords: archive.records,
        archive,
      };
      const pa = deriveProvingAvailability({ ...base, exerciseRecords: two.records, exercise: two });
      expect(pa.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(pa.selfHostedPath.witnesses).to.deep.equal([v1.path, v2.path]);
      expect(pa.exercises.accepted?.map((a) => [a.record, a.exercise])).to.deep.equal([
        [v1.path, PA3B.exercise],
        [v2.path, `${anchor.designation}:${T1}`],
      ]);
      const stated = pa.basis
        .filter((b) => b.startsWith("one real Groth16 proof"))
        .map((b) => /the record is (\S+)/.exec(b)?.[1]);
      expect(stated).to.deep.equal([v1.path, v2.path]);
      // The second bound to another designation, PROGRAM_VKEY or archive: refused by its path, beside a valid first.
      for (const edit of [
        (r: ProofExerciseRecord) => (r.subject.designation = "mldsa65-withdrawal-d9"),
        (r: ProofExerciseRecord) => (r.subject.programVKey = `0x${"00".repeat(32)}`),
        (r: ProofExerciseRecord) => (r.archiveRecord.archiveSha256 = "00".repeat(32)),
        (r: ProofExerciseRecord) => (r.archiveRecord.path = "evidence/zk/sp1-impl/proving-archives/other.json"),
      ]) {
        const broken = structuredClone(two);
        edit(broken.accepted[1].record);
        assert.throws(
          () => deriveProvingAvailability({ ...base, exerciseRecords: broken.records, exercise: broken }),
          new RegExp(`${v2.path.replace(/\./g, "\\.")} is not an exercise of the accepted archive record`),
        );
      }
    });
  });
});
