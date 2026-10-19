/**
 * SP1-PA3A: the proof-exercise evidence path (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md, "SP1-PA3A").
 *
 * A later, owner-authorized lane (SP1-PA3B) makes one real Groth16 proof through the archive-only gate and records
 * two observations: the measured run and the designated verifier's acceptance. The record is derived from them, and
 * the state SELF_HOSTED_PATH_EXERCISED from the record, never set. This suite pins every reason the observations
 * derive no record (a fail-closed matrix), that a consistent synthetic pair derives one in a temporary repository
 * (the transition is reachable), and that the real checkout has not reached it (no proof exists).
 *
 * Nothing here proves, pulls, downloads, deploys or writes to a chain. Research prototype. Not audited.
 */
import { expect } from "chai";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { serializeJson, type ArchiveEvidence } from "../scripts/lib/sp1-circuit-acquisition";
import { productionRecordRel } from "../scripts/lib/sp1-circuit-acquisition";
import { PROOF_INVALID } from "../scripts/lib/sp1-chain-execution";
import { SAFE_FILES, SYNTHETIC_ANCHOR, gz, safeTar, syntheticRecord } from "../scripts/lib/sp1-circuit-fixtures";
import {
  STATES,
  availabilityStatusesFor,
  productionAnchor,
  productionArchiveEvidenceOf,
  toolingState,
} from "../scripts/lib/sp1-circuit-tooling";
import { DESIGNATIONS_DIR, readDesignations } from "../scripts/lib/sp1-designation";
import {
  PROVING_ARTIFACTS_OBSERVATION_REL,
  archiveEvidenceFromRepo,
  deriveProvingAvailability,
  provingAvailabilityFromRepo,
  provingAvailabilityStatus,
  type ProvingArtifactsObservation,
} from "../scripts/lib/sp1-proving-availability";
import {
  EGRESS_DISABLED,
  EXERCISE_RECORD_SCHEMA,
  OBSERVATIONS_DIR,
  PROOF_EXERCISES_DIR,
  PROOF_INPUT_FIXTURE_REL,
  REPOSITORY_ID,
  ROTATION_DELAY_SECONDS,
  RUN_SCHEMA,
  RUN_SCRIPT_REL,
  VERIFICATION_SCHEMA,
  VERIFICATION_SCRIPT_REL,
  deriveExerciseRecord,
  exerciseErrors,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseObservationsIn,
  exerciseRecordRel,
  exerciseRecordsIn,
  productionExerciseEvidence,
  runObservationErrors,
  verificationObservationErrors,
  type EgressProbe,
  type ExerciseEvidence,
  type ExerciseExpectations,
  type RunObservation,
  type VerificationObservation,
} from "../scripts/lib/sp1-proof-exercise";
import { symlinkOrSkip, tempDirs } from "./helpers/circuit-tooling";
import {
  ANCHOR,
  ARCHIVE_RECORD,
  ARCHIVE_RECORD_TEXT,
  EXPECTATIONS,
  HOST_TREE,
  IMAGE_REF,
  INPUT_SHA,
  PROOF_BYTES,
  PUBLIC_VALUES,
  REGISTRY_HOST,
  RUN_REL,
  RUN_SCRIPT_SHA,
  SELECTOR,
  SOURCE_COMMIT,
  UPSTREAM_HOST,
  VERIFICATION_REL,
  probes,
  runObservation,
  runSha,
  verificationObservation,
} from "./helpers/sp1ProofExercise";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const hex = (b: Buffer) => `0x${b.toString("hex")}`;

/** The reasons (codes only) `mutate`d run observation is refused. */
function runRefusals(mutate: (o: RunObservation) => void, expect: ExerciseExpectations = EXPECTATIONS): string[] {
  const o = runObservation();
  mutate(o);
  return runObservationErrors(o, expect).map((r) => r.reason);
}

describe("SP1-PA3A — proof-exercise evidence", function () {
  it("names the constants the owner-facing facts bind to", function () {
    expect(ROTATION_DELAY_SECONDS).to.equal(2 * 24 * 3600);
    expect(PROOF_EXERCISES_DIR).to.equal("evidence/zk/sp1-impl/proof-exercises");
    expect(EXERCISE_RECORD_SCHEMA).to.equal("walletwall.sp1-proof-exercise.v1");
  });

  describe("the run observation", function () {
    it("accepts the synthetic observation", function () {
      expect(runRefusals(() => undefined)).to.deep.equal([]);
    });

    it("refuses another schema, a field the schema does not name, a missing field, and an unbound tool", function () {
      expect(runRefusals((o) => (o.schema = "walletwall.sp1-proof-exercise-run.v0"))).to.include("OBSERVATION_SCHEMA");
      expect(runRefusals((o) => ((o as unknown as Record<string, unknown>).verified = true))).to.include(
        "OBSERVATION_SHAPE",
      );
      expect(runRefusals((o) => delete (o as Partial<RunObservation>).egress)).to.include("OBSERVATION_SHAPE");
      expect(runRefusals((o) => (o.tool.scriptSha256 = "00".repeat(32)))).to.include("TOOL_NOT_BOUND");
      expect(runRefusals((o) => (o.tool.script = "scripts/other.ts"))).to.include("TOOL_NOT_BOUND");
      expect(runRefusals(() => undefined, { ...EXPECTATIONS, scripts: { run: null, verification: null } })).to.include(
        "TOOL_NOT_BOUND",
      );
    });

    it("binds the source: this repository, a commit, the designated host tree", function () {
      expect(runRefusals((o) => (o.source.repository = "Wallet-Wall/other"))).to.include("SOURCE_MISMATCH");
      expect(runRefusals((o) => (o.source.commit = "not-a-commit"))).to.include("SOURCE_MISMATCH");
      expect(runRefusals((o) => (o.source.zkvmHostTree = "b".repeat(40)))).to.include("HOST_IDENTITY_MISMATCH");
    });

    it("binds the anchor and the committed archive record, byte for byte", function () {
      expect(runRefusals((o) => (o.anchor.designation = "mldsa65-withdrawal-d2"))).to.include("ANCHOR_MISMATCH");
      expect(runRefusals((o) => (o.anchor.programVKey = `0x${"00".repeat(32)}`))).to.include("ANCHOR_MISMATCH");
      expect(runRefusals((o) => (o.archiveRecord.sha256 = "00".repeat(32)))).to.include("ARCHIVE_RECORD_MISMATCH");
      expect(runRefusals((o) => (o.archiveRecord.path = `${PROOF_EXERCISES_DIR}/x.json`))).to.include(
        "ARCHIVE_RECORD_MISMATCH",
      );
    });

    it("binds the installed circuit to exactly the record's members under the designated version", function () {
      expect(runRefusals((o) => (o.installedCircuit.members[0].sha256 = "00".repeat(32)))).to.include(
        "INSTALLED_CIRCUIT_MISMATCH",
      );
      expect(runRefusals((o) => o.installedCircuit.members.pop())).to.include("INSTALLED_CIRCUIT_MISMATCH");
      expect(runRefusals((o) => (o.installedCircuit.circuitVersion = "v6.0.0"))).to.include(
        "INSTALLED_CIRCUIT_MISMATCH",
      );
      expect(runRefusals((o) => (o.installedCircuit.root = "relative/root"))).to.include("INSTALLED_CIRCUIT_MISMATCH");
    });

    it("needs a measured host executable and the committed proof input", function () {
      expect(runRefusals((o) => (o.hostExecutable.sha256 = "nope"))).to.include("HOST_IDENTITY_MISMATCH");
      expect(runRefusals((o) => (o.hostExecutable.bytes = 0))).to.include("HOST_IDENTITY_MISMATCH");
      expect(runRefusals((o) => (o.inputs.sha256 = "00".repeat(32)))).to.include("PROOF_INPUT_MISMATCH");
      expect(runRefusals(() => undefined, { ...EXPECTATIONS, proofInputSha256: null })).to.include(
        "PROOF_INPUT_MISMATCH",
      );
    });

    it("needs the record's gnark image by digest, present in the local store", function () {
      expect(runRefusals((o) => (o.gnark.digest = `sha256:${"00".repeat(32)}`))).to.include("GNARK_IMAGE_MISMATCH");
      expect(runRefusals((o) => (o.gnark.repository = "ghcr.io/other/image"))).to.include("GNARK_IMAGE_MISMATCH");
      // A tag in place of the digest: never an identity.
      expect(
        runRefusals((o) => {
          o.gnark.imageRef = `${o.gnark.repository}:v6.1.0`;
          o.prover.frozenEnv.SP1_GNARK_IMAGE = o.gnark.imageRef;
        }),
      ).to.include("GNARK_IMAGE_MISMATCH");
      expect(runRefusals((o) => (o.gnark.localRepoDigests = []))).to.include("GNARK_IMAGE_MISMATCH");
    });

    it("needs the cpu prover with exactly the gate's frozen environment and no refused variable", function () {
      expect(runRefusals((o) => (o.prover.mode = "network" as never))).to.include("PROVER_MODE_MISMATCH");
      expect(runRefusals((o) => (o.prover.mode = "mock" as never))).to.include("PROVER_MODE_MISMATCH");
      expect(runRefusals((o) => (o.prover.frozenEnv.SP1_PROVER = "cuda"))).to.include("PROVER_MODE_MISMATCH");
      expect(runRefusals((o) => (o.prover.frozenEnv.SP1_GROTH16_CIRCUIT_PATH = "/elsewhere"))).to.include(
        "PROVER_ENV_MISMATCH",
      );
      expect(runRefusals((o) => delete o.prover.frozenEnv.DOCKER_CONTEXT)).to.include("PROVER_ENV_MISMATCH");
      expect(runRefusals((o) => (o.prover.frozenEnv.SP1_CIRCUIT_MODE = "dev"))).to.include("PROVER_ENV_MISMATCH");
      expect(runRefusals((o) => o.prover.passedThrough.push("NETWORK_PRIVATE_KEY"))).to.include("PROVER_ENV_MISMATCH");
      expect(runRefusals((o) => o.prover.dropped.push("SP1_CIRCUIT_MODE"))).to.include("PROVER_ENV_MISMATCH");
    });

    it("needs egress refused at every required target before and after the run, and nothing else", function () {
      expect(runRefusals((o) => (o.egress.condition = "EGRESS_ENABLED" as never))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.before[1].outcome = "CONNECTED"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].outcome = "RESOLVED"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].error = "EWHATEVER"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => o.egress.before.splice(0, 1))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after = []))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.enforcement = ""))).to.include("EGRESS_NOT_DISABLED");
      // Probes taken inside the run window attest nothing about its start or end.
      expect(runRefusals((o) => (o.egress.before[0].atUtc = "2026-11-01T10:00:01Z"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].atUtc = "2026-11-01T11:59:39Z"))).to.include("EGRESS_NOT_DISABLED");
    });

    it("needs a possible wall time: ordered stamps, positive seconds, the host run inside the gate run", function () {
      expect(runRefusals((o) => (o.timing.gateSeconds = 0))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.hostSeconds = -5))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.hostSeconds = o.timing.gateSeconds + 1))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.finishedAtUtc = "2026-11-01T09:00:00Z"))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.gateSeconds = 100))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.hostStartedAtUtc = "2026-11-01T09:00:00Z"))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.gateSeconds = 1.5 as never))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.measuredAtUtc = "2026-11-01T11:00:00Z"))).to.include("TIMING_IMPOSSIBLE");
    });

    it("needs a well-formed peak-memory measurement of the host process and the gnark containers", function () {
      expect(runRefusals((o) => (o.peakMemory.hostProcess.bytes = 0))).to.include("PEAK_MEMORY_MALFORMED");
      expect(runRefusals((o) => (o.peakMemory.hostProcess.bytes = -1))).to.include("PEAK_MEMORY_MALFORMED");
      expect(runRefusals((o) => (o.peakMemory.gnarkContainers.bytes = 1.5))).to.include("PEAK_MEMORY_MALFORMED");
      expect(runRefusals((o) => (o.peakMemory.gnarkContainers.samples = 0))).to.include("PEAK_MEMORY_MALFORMED");
      expect(runRefusals((o) => (o.peakMemory.gnarkContainers.intervalMs = 0))).to.include("PEAK_MEMORY_MALFORMED");
      expect(
        runRefusals((o) => delete (o.peakMemory as Partial<RunObservation["peakMemory"]>).gnarkContainers),
      ).to.include("OBSERVATION_SHAPE");
    });

    it("needs a proof naming the designated PROGRAM_VKEY under the designated key, with its digests", function () {
      expect(runRefusals((o) => (o.proof.vkey = `0x${"00".repeat(32)}`))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.proofBytes = `0x00000000${o.proof.proofBytes.slice(10)}`))).to.include(
        "PROOF_MISMATCH",
      );
      expect(runRefusals((o) => (o.proof.selector = "0x00000000"))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.proofBytesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValuesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValues = "0x"))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValues = "0xabc"))).to.include("PROOF_MISMATCH");
    });

    it("needs a host label, UTC stamps and identity lines", function () {
      expect(runRefusals((o) => (o.host = "Proving Host"))).to.include("OBSERVATION_FIELD");
      expect(runRefusals((o) => (o.measuredAtUtc = "yesterday"))).to.include("OBSERVATION_FIELD");
      expect(runRefusals((o) => (o.platform = []))).to.include("OBSERVATION_FIELD");
    });
  });

  describe("the verification observation", function () {
    /** The reasons the `mutate`d verification of the synthetic run is refused. */
    function refusals(
      mutate: (v: VerificationObservation, run: RunObservation) => void,
      expect: ExerciseExpectations = EXPECTATIONS,
    ): string[] {
      const run = runObservation();
      const v = verificationObservation(run);
      mutate(v, run);
      return verificationObservationErrors(v, { path: RUN_REL, sha256: runSha(run), observation: run }, expect).map(
        (r) => r.reason,
      );
    }

    it("accepts the synthetic verification of the synthetic run", function () {
      expect(refusals(() => undefined)).to.deep.equal([]);
    });

    it("refuses another schema, an unnamed field, an unbound tool, a bad host or stamp", function () {
      expect(refusals((v) => (v.schema = "walletwall.sp1-proof-exercise-verification.v0"))).to.include(
        "OBSERVATION_SCHEMA",
      );
      expect(refusals((v) => ((v as unknown as Record<string, unknown>).note = "fine"))).to.include(
        "OBSERVATION_SHAPE",
      );
      expect(refusals((v) => (v.tool.scriptSha256 = "00".repeat(32)))).to.include("TOOL_NOT_BOUND");
      expect(
        refusals(() => undefined, { ...EXPECTATIONS, scripts: { run: RUN_SCRIPT_SHA, verification: null } }),
      ).to.include("TOOL_NOT_BOUND");
      expect(refusals((v) => (v.host = "Host"))).to.include("OBSERVATION_FIELD");
      // Verified before the run was measured: not a verification of that run.
      expect(refusals((v) => (v.measuredAtUtc = "2026-11-01T12:00:00Z"))).to.include("OBSERVATION_FIELD");
    });

    it("binds the run observation's bytes and path, and the proof's identity", function () {
      // The run observation edited after the verification: its sha256 no longer binds.
      expect(refusals((v) => (v.run.sha256 = "00".repeat(32)))).to.include("RUN_NOT_BOUND");
      expect(refusals((v) => (v.run.path = RUN_REL.replace("host-a", "host-b")))).to.include("RUN_NOT_BOUND");
      expect(refusals((v) => (v.proof.proofBytesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(refusals((v) => (v.proof.publicValuesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(refusals((v) => (v.proof.vkey = `0x${"00".repeat(32)}`))).to.include("PROOF_MISMATCH");
    });

    it("needs the designated verifier: its identity, its runtime at the called address, the authenticated runtime once", function () {
      expect(refusals((v) => (v.verifier.runtimeCodeKeccak = `0x${"00".repeat(32)}`))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.verifier.verifierHash = `0x${"00".repeat(32)}`))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].runtimeCodeKeccak = `0x${"00".repeat(32)}`))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].mode = "DEPLOYED"))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks = []))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].address = "0x1234"))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].chainId = "mainnet"))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].mode = "SIMULATED" as never))).to.include("VERIFIER_MISMATCH");
      // A second, deployed check must carry the same runtime and the same verdicts.
      expect(
        refusals((v) => v.checks.push({ ...v.checks[0], chainId: "11155111", mode: "DEPLOYED", block: 12_000_000 })),
      ).to.deep.equal([]);
      expect(
        refusals((v) =>
          v.checks.push({
            ...v.checks[0],
            chainId: "11155111",
            mode: "DEPLOYED",
            block: 12_000_000,
            verdicts: { real: `revert ${PROOF_INVALID}`, tampered: `revert ${PROOF_INVALID}` },
          }),
        ),
      ).to.include("VERIFIER_REJECTED");
    });

    it("needs the verifier to accept the proof and refuse its tampered copy", function () {
      expect(refusals((v) => (v.checks[0].verdicts.real = `revert ${PROOF_INVALID}`))).to.include("VERIFIER_REJECTED");
      expect(refusals((v) => (v.checks[0].verdicts.real = "success 0x01"))).to.include("VERIFIER_REJECTED");
      expect(refusals((v) => (v.checks[0].verdicts.tampered = "success"))).to.include("VERIFIER_REJECTED");
      expect(refusals((v) => (v.checks[0].verdicts.tampered = "revert 0x"))).to.include("VERIFIER_REJECTED");
      expect(refusals((v) => (v.acceptance = "REJECTED"))).to.include("VERIFIER_REJECTED");
      expect(refusals((v) => (v.acceptance = "accepted" as never))).to.include("VERIFIER_REJECTED");
    });
  });

  describe("the derived record", function () {
    const bound = (run: RunObservation) => ({ runSha256: runSha(run), verificationPath: VERIFICATION_REL });

    it("is derived from the two observations, never written: every binding is carried", function () {
      const run = runObservation();
      const v = verificationObservation(run);
      expect(exerciseErrors(run, v, bound(run), EXPECTATIONS)).to.deep.equal([]);
      const r = deriveExerciseRecord(run, v, bound(run), EXPECTATIONS);
      expect(r.schema).to.equal(EXERCISE_RECORD_SCHEMA);
      expect(r.lane).to.equal("SP1-PA3B");
      expect(r.exercise).to.deep.equal({
        id: `${ANCHOR.designation}:${runSha(run).slice(0, 16)}`,
        host: "proving-host-a",
        performedAtUtc: "2026-11-01T10:00:00Z",
        verifiedAtUtc: "2026-11-01T12:30:00Z",
      });
      expect(r.subject).to.deep.equal({
        designation: ANCHOR.designation,
        circuitSystem: "groth16",
        circuitVersion: ANCHOR.circuitVersion,
        programVKey: ANCHOR.programVKey,
        verifier: ANCHOR.verifier,
        verifyingKey: { file: "groth16_vk.bin", ...ANCHOR.verifyingKey },
      });
      expect(r.archiveRecord).to.deep.equal({
        path: EXPECTATIONS.archiveRecord.path,
        sha256: EXPECTATIONS.archiveRecord.sha256,
        archiveFile: ARCHIVE_RECORD.archive.file,
        archiveBytes: ARCHIVE_RECORD.archive.bytes,
        archiveSha256: ARCHIVE_RECORD.archive.sha256,
        members: ARCHIVE_RECORD.members.length,
      });
      expect(r.installedCircuit).to.deep.equal({
        circuitVersion: ANCHOR.circuitVersion,
        membersSha256: sha256(serializeJson(ARCHIVE_RECORD.members)),
        verifiedBy: "the archive-only gate: re-hashed against the record before the host started and after it exited",
      });
      expect(r.host).to.deep.equal({
        executableSha256: run.hostExecutable.sha256,
        executableBytes: run.hostExecutable.bytes,
        sourceTree: HOST_TREE,
        sourceCommit: SOURCE_COMMIT,
        repository: REPOSITORY_ID,
      });
      expect(r.proofInput).to.deep.equal({
        fixture: "zkvm/fixtures/mldsa65-withdrawal.inputs.json",
        sha256: INPUT_SHA,
      });
      expect(r.gnark).to.deep.equal({
        repository: ARCHIVE_RECORD.gnark.repository,
        digest: ARCHIVE_RECORD.gnark.digest,
        imageRef: IMAGE_REF,
      });
      expect(r.prover).to.deep.equal({ mode: "cpu", frozenEnv: run.prover.frozenEnv, gate: "sp1:prove:archive-only" });
      expect(r.proof).to.deep.equal({
        vkey: ANCHOR.programVKey,
        selector: `0x${SELECTOR}`,
        publicValuesSha256: sha256(PUBLIC_VALUES),
        proofBytesSha256: sha256(PROOF_BYTES),
      });
      expect(r.verification).to.deep.equal({
        observation: { path: VERIFICATION_REL, host: "proving-host-a" },
        verifier: ANCHOR.verifier,
        checks: v.checks,
        acceptance: "ACCEPTED",
      });
      expect(r.performance).to.deep.equal({
        wallClockSeconds: 7180,
        hostSeconds: 4800,
        rotationDelaySeconds: ROTATION_DELAY_SECONDS,
        withinRotationDelay: true,
        rotationDelayFraction: 0.041551,
        peakMemory: run.peakMemory,
      });
      expect(r.egress).to.deep.equal({
        condition: EGRESS_DISABLED,
        enforcement: run.egress.enforcement,
        probes: {
          before: 4,
          after: 4,
          targets: [
            `dns:${UPSTREAM_HOST}`,
            `dns:${REGISTRY_HOST}`,
            `tcp:${UPSTREAM_HOST}:443`,
            `tcp:${REGISTRY_HOST}:443`,
          ].sort(),
        },
      });
      expect(r.derivedFrom).to.deep.equal([RUN_REL, VERIFICATION_REL]);
      expect(r.establishes).to.be.a("string").and.include("liveness");
      expect(r.doesNotEstablish).to.be.a("string").and.include("production readiness");
      expect(exerciseRecordRel(ANCHOR)).to.equal(`${PROOF_EXERCISES_DIR}/${ANCHOR.designation}.json`);
    });

    it("records a run longer than the rotation delay as such, never as availability", function () {
      const run = runObservation();
      run.timing = {
        startedAtUtc: "2026-11-01T00:00:00Z",
        finishedAtUtc: "2026-11-03T01:00:00Z",
        gateSeconds: 176_400,
        hostStartedAtUtc: "2026-11-01T00:10:00Z",
        hostFinishedAtUtc: "2026-11-03T00:50:00Z",
        hostSeconds: 175_200,
      };
      run.egress.before = probes("2026-10-31T23:59:00Z");
      run.egress.after = probes("2026-11-03T01:00:30Z");
      run.measuredAtUtc = "2026-11-03T01:01:00Z";
      const v = verificationObservation(run);
      v.measuredAtUtc = "2026-11-03T02:00:00Z";
      const r = deriveExerciseRecord(run, v, bound(run), EXPECTATIONS);
      expect(r.performance.withinRotationDelay).to.equal(false);
      expect(r.performance.rotationDelayFraction).to.equal(1.020833);
    });

    it("derives nothing from a refused pair, naming every reason", function () {
      const run = runObservation();
      const v = verificationObservation(run);
      run.proof.vkey = `0x${"00".repeat(32)}`;
      expect(exerciseErrors(run, v, bound(run), EXPECTATIONS).map((r) => r.reason)).to.include("PROOF_MISMATCH");
      assert.throws(() => deriveExerciseRecord(run, v, bound(run), EXPECTATIONS), /PROOF_MISMATCH/);
      // A verification of another run (the run edited after it was verified) derives nothing either.
      const run2 = runObservation();
      run2.platform.push("edited after verification");
      const v2 = verificationObservation(runObservation());
      const reasons = exerciseErrors(run2, v2, bound(run2), EXPECTATIONS).map((r) => r.reason);
      expect(reasons).to.include("RUN_NOT_BOUND");
      // Two partial records never combine: a verification whose proof digests are another run's.
      const v3 = verificationObservation(run2);
      v3.proof.proofBytesSha256 = "ff".repeat(32);
      expect(exerciseErrors(run2, v3, bound(run2), EXPECTATIONS).map((r) => r.reason)).to.include("PROOF_MISMATCH");
    });
  });

  describe("the committed evidence (a temporary repository)", function () {
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
    /** The accepted archive evidence the exercise is judged against (what the tooling record passes). */
    const archive: ArchiveEvidence = {
      records: [productionRecordRel(ANCHOR)],
      record: ARCHIVE_RECORD,
      observations: [],
      errors: [],
    };
    const RUN_FILE = `${OBSERVATIONS_DIR}/proof-exercise-run-proving-host-a.raw.json`;
    const VERIFICATION_FILE = `${OBSERVATIONS_DIR}/proof-exercise-verification-proving-host-a.raw.json`;

    interface Repo {
      dir: string;
      base: string;
      run: RunObservation;
      verification: VerificationObservation;
      expect: ExerciseExpectations;
    }
    /**
     * A repository at the archived state (the archive record, the designation, the proof-input fixture and the two
     * tools committed as the base), then the two observations of one exercise and the record derived from them.
     */
    function repo(
      opts: {
        observations?: boolean;
        record?: boolean;
        commit?: boolean;
        run?: (o: RunObservation) => void;
        verification?: (v: VerificationObservation) => void;
      } = {},
    ): Repo {
      const d = dirs.make("sp1-pa3a-");
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(
        d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1, subject: { zkvmHostTree: HOST_TREE } }),
      );
      write(d, PROOF_INPUT_FIXTURE_REL, '{\n  "synthetic": "proof input fixture"\n}\n');
      write(d, RUN_SCRIPT_REL, "// synthetic measurement tool\n");
      write(d, VERIFICATION_SCRIPT_REL, "// synthetic verification tool\n");
      const base = commit(d, "archived state");
      const expect = exerciseExpectations(d, { anchor: ANCHOR, archive });
      const bindTo = (run: RunObservation) => {
        const v = verificationObservation(run);
        v.run = { path: RUN_FILE, sha256: runSha(run) };
        v.tool.scriptSha256 = String(expect.scripts.verification);
        return v;
      };
      // The record is derived from the consistent pair; `opts.run` / `opts.verification` then edit what is written,
      // so a test can commit a record beside observations that no longer derive it.
      const clean = runObservation();
      clean.source.commit = base;
      clean.inputs.sha256 = String(expect.proofInputSha256);
      clean.tool.scriptSha256 = String(expect.scripts.run);
      const record = deriveExerciseRecord(
        clean,
        bindTo(clean),
        { runSha256: runSha(clean), verificationPath: VERIFICATION_FILE, runPath: RUN_FILE },
        expect,
      );
      const run = structuredClone(clean);
      opts.run?.(run);
      const verification = bindTo(run);
      opts.verification?.(verification);
      if (opts.observations !== false) {
        write(d, RUN_FILE, serializeJson(run));
        write(d, VERIFICATION_FILE, serializeJson(verification));
      }
      if (opts.record !== false) write(d, exerciseRecordRel(ANCHOR), serializeJson(record));
      if (opts.commit !== false) commit(d, "the exercise");
      return { dir: d, base, run, verification, expect };
    }
    const judge = (d: string, a: ArchiveEvidence = archive) =>
      productionExerciseEvidence(d, { anchor: ANCHOR, archive: a });
    const refused = (d: string, re: RegExp, a: ArchiveEvidence = archive) => {
      const e = judge(d, a);
      expect(exerciseEvidenceState(e), e.errors.join("; ")).to.equal("REFUSED");
      expect(e.record).to.equal(null);
      expect(e.errors.join("\n")).to.match(re);
    };

    it("reads the expectations from the committed evidence: the record's bytes, the host tree, the fixture, the tools", function () {
      this.timeout(60_000);
      const { expect: x } = repo({ observations: false, record: false });
      expect(x.archiveRecord).to.deep.equal({
        path: productionRecordRel(ANCHOR),
        sha256: sha256(ARCHIVE_RECORD_TEXT),
        record: ARCHIVE_RECORD,
      });
      expect(x.zkvmHostTree).to.equal(HOST_TREE);
      expect(x.proofInputSha256).to.equal(sha256('{\n  "synthetic": "proof input fixture"\n}\n'));
      expect(x.upstreamHost).to.equal(UPSTREAM_HOST);
      expect(x.registryHost).to.equal(REGISTRY_HOST);
      expect(x.scripts).to.deep.equal({
        run: sha256("// synthetic measurement tool\n"),
        verification: sha256("// synthetic verification tool\n"),
      });
      expect(x.repository).to.equal(REPOSITORY_ID);
      // An absent fixture or tool binds nothing (and so refuses every observation).
      const d = dirs.make("sp1-pa3a-bare-");
      git(d, "init", "-q");
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(
        d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1, subject: { zkvmHostTree: HOST_TREE } }),
      );
      const bare = exerciseExpectations(d, { anchor: ANCHOR, archive });
      expect(bare.proofInputSha256).to.equal(null);
      expect(bare.scripts).to.deep.equal({ run: null, verification: null });
    });

    it("is NO_RECORD while the exercise directory holds nothing, whatever observations exist", function () {
      this.timeout(60_000);
      for (const d of [repo({ record: false }), repo({ record: false, observations: false })]) {
        const e = judge(d.dir);
        expect(exerciseEvidenceState(e)).to.equal("NO_RECORD");
        expect(e).to.deep.include({ records: [], record: null, errors: [] });
      }
      expect(exerciseRecordsIn(repo({ record: false }).dir)).to.deep.equal([]);
    });

    it("is ACCEPTED only for the one record the committed observations derive, committed with them and the archive record", function () {
      this.timeout(60_000);
      const r = repo();
      const e = judge(r.dir);
      expect(exerciseEvidenceState(e), e.errors.join("; ")).to.equal("ACCEPTED");
      expect(e.records).to.deep.equal([exerciseRecordRel(ANCHOR)]);
      expect(e.observations).to.deep.equal([RUN_FILE, VERIFICATION_FILE]);
      expect(e.record?.proof.vkey).to.equal(ANCHOR.programVKey);
      expect(serializeJson(e.record)).to.equal(readFileSync(join(r.dir, exerciseRecordRel(ANCHOR)), "utf8"));
      expect(exerciseObservationsIn(r.dir)).to.deep.equal({
        run: [RUN_FILE],
        verification: [VERIFICATION_FILE],
        other: [],
      });
    });

    it("is REFUSED, never NO_RECORD, for uncommitted or edited evidence", function () {
      this.timeout(60_000);
      refused(repo({ commit: false }).dir, /not as committed: (NOT_A_GIT_CHECKOUT|UNTRACKED|UNCOMMITTED)/);
      // The record reformatted by hand: not the derived bytes.
      let r = repo();
      const rec = JSON.parse(readFileSync(join(r.dir, exerciseRecordRel(ANCHOR)), "utf8"));
      writeFileSync(join(r.dir, exerciseRecordRel(ANCHOR)), `${JSON.stringify(rec, null, 4)}\n`);
      commit(r.dir, "reformatted");
      refused(r.dir, /not the record the committed observations derive/);
      // A record field hand-set after derivation.
      r = repo();
      rec.performance.withinRotationDelay = true;
      rec.performance.wallClockSeconds = 1;
      writeFileSync(join(r.dir, exerciseRecordRel(ANCHOR)), serializeJson(rec));
      commit(r.dir, "edited");
      refused(r.dir, /not the record the committed observations derive/);
      // The run observation edited after it was verified: the verification no longer binds it.
      r = repo();
      const run = JSON.parse(readFileSync(join(r.dir, RUN_FILE), "utf8"));
      run.platform.push("edited after verification");
      writeFileSync(join(r.dir, RUN_FILE), serializeJson(run));
      commit(r.dir, "run edited");
      refused(r.dir, /RUN_NOT_BOUND/);
      // The run observation edited in the working tree only.
      r = repo();
      writeFileSync(join(r.dir, RUN_FILE), serializeJson(run));
      refused(r.dir, /RUN_NOT_BOUND|UNCOMMITTED/);
    });

    it("is REFUSED for a second record, a link, a duplicate or stray observation, or a missing one", function () {
      this.timeout(60_000);
      let r = repo();
      write(r.dir, `${PROOF_EXERCISES_DIR}/another.json`, "{}\n");
      commit(r.dir, "second");
      refused(r.dir, /must hold exactly/);
      r = repo();
      renameSync(join(r.dir, exerciseRecordRel(ANCHOR)), join(r.dir, PROOF_EXERCISES_DIR, "other-designation.json"));
      commit(r.dir, "renamed");
      refused(r.dir, /must hold exactly/);
      r = repo();
      const linked = join(r.dir, "elsewhere.json");
      renameSync(join(r.dir, exerciseRecordRel(ANCHOR)), linked);
      symlinkOrSkip(this, linked, join(r.dir, exerciseRecordRel(ANCHOR)), "file");
      commit(r.dir, "a link");
      refused(r.dir, /not a regular file/);
      r = repo();
      write(
        r.dir,
        `${OBSERVATIONS_DIR}/proof-exercise-run-proving-host-b.raw.json`,
        readFileSync(join(r.dir, RUN_FILE), "utf8"),
      );
      commit(r.dir, "a second run");
      refused(r.dir, /exactly one run observation/);
      r = repo();
      write(r.dir, `${OBSERVATIONS_DIR}/proof-exercise-notes.raw.json`, "{}\n");
      commit(r.dir, "a stray file");
      refused(r.dir, /proof-exercise-notes\.raw\.json/);
      r = repo();
      rmSync(join(r.dir, VERIFICATION_FILE));
      commit(r.dir, "no verification");
      refused(r.dir, /exactly one verification observation/);
      r = repo();
      rmSync(join(r.dir, RUN_FILE));
      commit(r.dir, "no run");
      refused(r.dir, /exactly one run observation/);
      // An observation whose file names another host than it claims.
      r = repo();
      renameSync(
        join(r.dir, VERIFICATION_FILE),
        join(r.dir, OBSERVATIONS_DIR, "proof-exercise-verification-other.raw.json"),
      );
      commit(r.dir, "relabeled");
      refused(r.dir, /claims host proving-host-a/);
    });

    it("is REFUSED when the archive evidence is gone, changed, or was never accepted", function () {
      this.timeout(60_000);
      const r = repo();
      refused(r.dir, /archive evidence is not accepted/, { records: [], record: null, observations: [], errors: [] });
      refused(r.dir, /archive evidence is not accepted/, { ...archive, record: null, errors: ["MIRRORS_MISSING"] });
      // The archive record's bytes changed after the exercise: the run no longer names the committed record.
      const edited = { ...ARCHIVE_RECORD, mirrors: [...ARCHIVE_RECORD.mirrors].reverse() };
      writeFileSync(join(r.dir, productionRecordRel(ANCHOR)), serializeJson(edited));
      commit(r.dir, "archive record changed");
      refused(r.dir, /ARCHIVE_RECORD_MISMATCH/, { ...archive, record: edited });
      // The archive record file removed while the exercise record stays.
      rmSync(join(r.dir, productionRecordRel(ANCHOR)));
      commit(r.dir, "archive record removed");
      refused(r.dir, /archive record .*is missing|ARCHIVE_RECORD_MISMATCH/);
    });

    it("is REFUSED for an exercise of another commit, another baseline or another designation", function () {
      this.timeout(60_000);
      // A commit this repository never had.
      refused(repo({ run: (o) => (o.source.commit = "d".repeat(40)) }).dir, /not in this repository's history/);
      // The run observation of another baseline (another archive record's sha256).
      refused(repo({ run: (o) => (o.archiveRecord.sha256 = "ee".repeat(32)) }).dir, /ARCHIVE_RECORD_MISMATCH/);
      // The designation's host tree moved on.
      const r = repo();
      write(
        r.dir,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1, subject: { zkvmHostTree: "b".repeat(40) } }),
      );
      commit(r.dir, "another host tree");
      refused(r.dir, /HOST_IDENTITY_MISMATCH/);
      // The proof-input fixture regenerated after the exercise.
      const r2 = repo();
      write(r2.dir, PROOF_INPUT_FIXTURE_REL, '{\n  "synthetic": "another input"\n}\n');
      commit(r2.dir, "another input");
      refused(r2.dir, /PROOF_INPUT_MISMATCH/);
      // The measurement tool edited after the run.
      const r3 = repo();
      write(r3.dir, RUN_SCRIPT_REL, "// synthetic measurement tool, edited\n");
      commit(r3.dir, "tool edited");
      refused(r3.dir, /TOOL_NOT_BOUND/);
    });

    it("is REFUSED when the verifier rejected, or a check ran another runtime", function () {
      this.timeout(60_000);
      refused(
        repo({ verification: (v) => (v.checks[0].verdicts.real = `revert ${PROOF_INVALID}`) }).dir,
        /VERIFIER_REJECTED/,
      );
      refused(repo({ verification: (v) => (v.acceptance = "REJECTED") }).dir, /VERIFIER_REJECTED/);
      refused(
        repo({ verification: (v) => (v.checks[0].runtimeCodeKeccak = `0x${"00".repeat(32)}`) }).dir,
        /VERIFIER_MISMATCH/,
      );
    });
  });

  describe("the state, derived from facts", function () {
    const NO_EXERCISE: ExerciseEvidence = { records: [], record: null, observations: [], errors: [] };
    const noArchive: ArchiveEvidence = { records: [], record: null, observations: [], errors: [] };
    const acceptedArchive: ArchiveEvidence = {
      records: [productionRecordRel(ANCHOR)],
      record: ARCHIVE_RECORD,
      observations: ["a.json", "b.json"],
      errors: [],
    };
    const syntheticExercise = (): ExerciseEvidence => {
      const run = runObservation();
      const v = verificationObservation(run);
      return {
        records: [exerciseRecordRel(ANCHOR)],
        record: deriveExerciseRecord(
          run,
          v,
          { runSha256: runSha(run), verificationPath: VERIFICATION_REL, runPath: RUN_REL },
          EXPECTATIONS,
        ),
        observations: [RUN_REL, VERIFICATION_REL],
        errors: [],
      };
    };
    const refusedExercise = (): ExerciseEvidence => ({
      ...syntheticExercise(),
      record: null,
      errors: ["VERIFIER_REJECTED: the proof was not accepted"],
    });

    it("toolingState: the third state only from an accepted exercise on an accepted archive; anything else derives none", function () {
      const x = syntheticExercise();
      expect(toolingState({ selfTestPassed: false, archive: acceptedArchive, exercise: x })).to.equal(
        "TOOLING_NOT_PRESENT",
      );
      expect(toolingState({ selfTestPassed: true, archive: noArchive, exercise: NO_EXERCISE })).to.equal(
        "TOOLING_READY_NO_ARTIFACT",
      );
      expect(toolingState({ selfTestPassed: true, archive: acceptedArchive, exercise: NO_EXERCISE })).to.equal(
        "ARCHIVED_VERIFIED_UNEXERCISED",
      );
      expect(toolingState({ selfTestPassed: true, archive: acceptedArchive, exercise: x })).to.equal(
        "SELF_HOSTED_PATH_EXERCISED",
      );
      assert.throws(
        () => toolingState({ selfTestPassed: true, archive: acceptedArchive, exercise: refusedExercise() }),
        /no state is derivable[\s\S]*VERIFIER_REJECTED/,
      );
      assert.throws(
        () => toolingState({ selfTestPassed: true, archive: noArchive, exercise: x }),
        /no state is derivable/,
      );
      assert.throws(
        () => toolingState({ selfTestPassed: true, archive: noArchive, exercise: refusedExercise() }),
        /no state is derivable/,
      );
      assert.throws(
        () =>
          toolingState({
            selfTestPassed: true,
            archive: { ...acceptedArchive, record: null, errors: ["MIRRORS_MISSING"] },
            exercise: x,
          }),
        /no state is derivable/,
      );
      // A record object with errors beside it is never accepted: the errors decide, not the presence of a record.
      assert.throws(
        () => toolingState({ selfTestPassed: true, archive: acceptedArchive, exercise: { ...x, errors: ["x"] } }),
        /no state is derivable/,
      );
      expect(availabilityStatusesFor("SELF_HOSTED_PATH_EXERCISED")).to.deep.equal(["SELF_HOSTED_PATH_EXERCISED"]);
      expect(availabilityStatusesFor("ARCHIVED_VERIFIED_UNEXERCISED")).to.deep.equal(["ARCHIVED_VERIFIED_UNEXERCISED"]);
      expect(STATES.find((s) => s.state === "SELF_HOSTED_PATH_EXERCISED")?.reachableInThisLane).to.equal(true);
    });

    it("provingAvailabilityStatus: SELF_HOSTED_PATH_EXERCISED only from accepted exercise evidence that judged exactly the records on disk", function () {
      const obs = JSON.parse(readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL, "utf8")) as ProvingArtifactsObservation;
      const x = syntheticExercise();
      const a = acceptedArchive;
      expect(provingAvailabilityStatus(obs, a.records, a, x.records, x)).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(provingAvailabilityStatus(obs, a.records, a, [], NO_EXERCISE)).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      expect(provingAvailabilityStatus(obs, a.records, a)).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      assert.throws(
        () => provingAvailabilityStatus(obs, a.records, a, x.records),
        /not an accepted proof-exercise record/,
      );
      assert.throws(
        () => provingAvailabilityStatus(obs, a.records, a, x.records, refusedExercise()),
        /VERIFIER_REJECTED/,
      );
      assert.throws(() => provingAvailabilityStatus(obs, a.records, a, [], x), /judged .* not no record/);
      assert.throws(
        () => provingAvailabilityStatus(obs, a.records, a, [], { ...NO_EXERCISE, errors: ["stray"] }),
        /refused without a record/,
      );
      // A proof-exercise record without an accepted archive record derives no status at all.
      assert.throws(() => provingAvailabilityStatus(obs, [], noArchive, x.records, x), /without an accepted archive/);
      assert.throws(() => provingAvailabilityStatus(obs, [], null, x.records), /without an accepted archive/);
    });

    it("deriveProvingAvailability: selfHostedPath.exercised follows the accepted exercise of the accepted record, never a setting", function () {
      const obsBytes = readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL);
      const obs = JSON.parse(obsBytes.toString("utf8")) as ProvingArtifactsObservation;
      const td1Bytes = readFileSync("evidence/zk/sp1-td1/decision-receipt.json");
      const designations = readDesignations(".");
      const archive = archiveEvidenceFromRepo(".", obs, designations) as ArchiveEvidence;
      expect(archive.record, "the real archive record is accepted today").to.not.equal(null);
      const base = {
        observation: obs,
        observationSha256: sha256(obsBytes),
        designations,
        td1Receipt: { sha256: sha256(td1Bytes), doc: JSON.parse(td1Bytes.toString("utf8")) },
        archiveRecords: archive.records,
        archive,
      };
      const unexercised = deriveProvingAvailability({ ...base, exerciseRecords: [], exercise: NO_EXERCISE });
      expect(unexercised.status).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      expect(unexercised.selfHostedPath.exercised).to.equal(false);
      expect(unexercised.exercises).to.deep.equal({ dir: PROOF_EXERCISES_DIR, records: 0 });
      // An exercise of another designation's circuit, even an accepted one, is not an exercise of this record.
      const x = syntheticExercise();
      assert.throws(
        () => deriveProvingAvailability({ ...base, exerciseRecords: x.records, exercise: x }),
        /not an exercise of the accepted archive record/,
      );
      const d1 = designations[designations.length - 1];
      const bound = structuredClone(x);
      bound.records = [`${PROOF_EXERCISES_DIR}/${d1.id}.json`];
      bound.record!.subject.designation = d1.id;
      bound.record!.subject.programVKey = d1.programVKey;
      bound.record!.archiveRecord.path = archive.records[0];
      bound.record!.archiveRecord.archiveSha256 = archive.record!.archive.sha256;
      bound.record!.archiveRecord.sha256 = sha256(readFileSync(archive.records[0], "utf8").replace(/\r\n/g, "\n"));
      const exercised = deriveProvingAvailability({ ...base, exerciseRecords: bound.records, exercise: bound });
      expect(exercised.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(exercised.selfHostedPath.exercised).to.equal(true);
      expect(exercised.selfHostedPath.record).to.equal(bound.records[0]);
      expect(exercised.exercises.accepted).to.deep.include({
        record: bound.records[0],
        derivedFrom: [RUN_REL, VERIFICATION_REL],
        host: "proving-host-a",
        wallClockSeconds: 7180,
        hostSeconds: 4800,
        rotationDelaySeconds: ROTATION_DELAY_SECONDS,
        withinRotationDelay: true,
      });
      expect(exercised.basis.join("\n")).to.include(`${ROTATION_DELAY_SECONDS}`);
      expect(exercised.ownerAction.join("\n")).to.include("production binding");
      expect(exercised.notEstablished.join("\n")).to.include("production readiness");
    });

    it("the real checkout has not reached the third state: no record, no exercise evidence, exercised false", function () {
      this.timeout(120_000);
      expect(exerciseRecordsIn(".")).to.deep.equal([]);
      expect(exerciseObservationsIn(".")).to.deep.equal({ run: [], verification: [], other: [] });
      const archive = productionArchiveEvidenceOf(".");
      const exercise = productionExerciseEvidence(".", { anchor: productionAnchor("."), archive });
      expect(exerciseEvidenceState(exercise)).to.equal("NO_RECORD");
      expect(exercise).to.deep.equal(NO_EXERCISE);
      expect(toolingState({ selfTestPassed: true, archive, exercise })).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      const pa = provingAvailabilityFromRepo(".");
      expect(pa.status).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      expect(pa.selfHostedPath.exercised).to.equal(false);
      expect(pa.selfHostedPath).to.not.have.property("record");
      expect(pa.exercises).to.deep.equal({ dir: PROOF_EXERCISES_DIR, records: 0 });
      // SP1-PA2C's evidence is not SP1-PA3's: the archive record is no run observation and no verification.
      const x = exerciseExpectations(".", { anchor: productionAnchor("."), archive });
      expect(runObservationErrors(archive.record, x).map((r) => r.reason)).to.include("OBSERVATION_SHAPE");
      expect(
        verificationObservationErrors(archive.record, { path: "", sha256: "", observation: runObservation() }, x).map(
          (r) => r.reason,
        ),
      ).to.include("OBSERVATION_SHAPE");
    });
  });
});
