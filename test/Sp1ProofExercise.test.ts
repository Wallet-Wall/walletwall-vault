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
import { cpSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { serializeJson, type ArchiveEvidence } from "../scripts/lib/sp1-circuit-acquisition";
import { productionRecordRel } from "../scripts/lib/sp1-circuit-acquisition";
import { CANONICAL_REBUILD_OBSERVATION_REL } from "../scripts/lib/sp1-canonical-build";
import { PROOF_INVALID } from "../scripts/lib/sp1-chain-execution";
import { SAFE_FILES, SYNTHETIC_ANCHOR, gz, safeTar, syntheticRecord } from "../scripts/lib/sp1-circuit-fixtures";
import {
  STATES,
  availabilityStatusesFor,
  productionAnchor,
  productionArchiveEvidenceOf,
  toolingRecordFromRepo,
  toolingState,
} from "../scripts/lib/sp1-circuit-tooling";
import { advisoryStateFromRepo } from "../scripts/lib/sp1-host-advisories";
import { DESIGNATIONS_DIR, readDesignations } from "../scripts/lib/sp1-designation";
import {
  PROVING_ARTIFACTS_OBSERVATION_REL,
  archiveEvidenceFromRepo,
  deriveProvingAvailability,
  provingAvailabilityFromRepo,
  provingAvailabilityStatus,
  serializeProvingAvailability,
  type ProvingArtifactsObservation,
} from "../scripts/lib/sp1-proving-availability";
import {
  EGRESS_CANARY_IPS,
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
  dockerContainerBytes,
  exerciseErrors,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseObservationsIn,
  exerciseRecordRel,
  exerciseRecordsIn,
  productionExerciseEvidence,
  egressTargets,
  fileIdentity,
  measuringSpawner,
  parseDockerMemUsage,
  parseVmHWM,
  probeEgress,
  runObservationErrors,
  sourceIdentity,
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
  HOST_BINARY_SHA,
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
  probeTargets,
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
      // An absent tool binds nothing, even to an observation that names no sha (null never equals null here).
      expect(
        runRefusals((o) => ((o.tool as unknown as Record<string, unknown>).scriptSha256 = null), {
          ...EXPECTATIONS,
          scripts: { run: null, verification: EXPECTATIONS.scripts.verification },
        }),
      ).to.include("TOOL_NOT_BOUND");
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
      // A well-formed sha256 that is not the canonical-build host binary's: another host build.
      expect(runRefusals((o) => (o.hostExecutable.sha256 = "55".repeat(32)))).to.include("HOST_IDENTITY_MISMATCH");
      expect(runRefusals(() => undefined, { ...EXPECTATIONS, hostBinarySha256: null })).to.include(
        "HOST_IDENTITY_MISMATCH",
      );
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
      expect(runRefusals((o) => (o.prover.passedThrough = [42] as never))).to.include("PROVER_ENV_MISMATCH");
      expect(runRefusals((o) => (o.prover.dropped = "SHELL" as never))).to.include("PROVER_ENV_MISMATCH");
      expect(runRefusals((o) => o.prover.passedThrough.push("not a name!"))).to.include("PROVER_ENV_MISMATCH");
      // A variable the gate never passes through cannot have reached the host.
      expect(runRefusals((o) => o.prover.passedThrough.push("SP1_WORKER_NUM_CORE_WORKERS"))).to.include(
        "PROVER_ENV_MISMATCH",
      );
    });

    it("needs egress refused at every required target before and after the run, and nothing else", function () {
      expect(runRefusals((o) => (o.egress.condition = "EGRESS_ENABLED" as never))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.before[1].outcome = "CONNECTED"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].outcome = "RESOLVED"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].error = "EWHATEVER"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => o.egress.before.splice(0, 1))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after = []))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.enforcement = ""))).to.include("EGRESS_NOT_DISABLED");
      // Not a list, or an entry that is no probe (another kind, no target, no stamp, a stray field): refused.
      expect(runRefusals((o) => (o.egress.before = "none" as never))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].kind = "udp" as never))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].target = ""))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].atUtc = "noon"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => ((o.egress.after[0] as unknown as Record<string, unknown>).note = "x"))).to.include(
        "EGRESS_NOT_DISABLED",
      );
      // A TCP probe at an address needs a refused CONNECTION: a resolver code there proves only that names do not
      // resolve, and a stub resolver answering NXDOMAIN would satisfy every by-name probe with egress open.
      expect(
        runRefusals((o) => {
          for (const p of [...o.egress.before, ...o.egress.after])
            if (p.target.startsWith("203.")) p.error = "EAI_AGAIN";
        }),
      ).to.include("EGRESS_NOT_DISABLED");
      expect(
        runRefusals((o) => {
          for (const p of [...o.egress.before, ...o.egress.after])
            if (p.target.startsWith("1.1.1.1")) p.error = "ENOTFOUND";
        }),
      ).to.include("EGRESS_NOT_DISABLED");
      // The address probes are required: the acquisitions' upstream address and both canaries.
      for (const ip of ["203.0.113.5", ...EGRESS_CANARY_IPS]) {
        expect(
          runRefusals((o) => {
            o.egress.before = o.egress.before.filter((p) => !p.target.startsWith(ip));
          }),
          ip,
        ).to.include("EGRESS_NOT_DISABLED");
      }
      // A resolver failing with a connection code is still a refusal (the resolver itself is unreachable).
      expect(runRefusals((o) => (o.egress.before[0].error = "ECONNREFUSED"))).to.deep.equal([]);
      // "Immediately before and after": a probe more than ten minutes from the run attests to another time.
      expect(runRefusals((o) => (o.egress.before[0].atUtc = "2026-11-01T09:49:59Z"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.after[0].atUtc = "2026-11-01T12:09:41Z"))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => (o.egress.before[0].atUtc = "2026-11-01T09:50:00Z"))).to.deep.equal([]);
      expect(runRefusals((o) => (o.egress.after[0].atUtc = "2026-11-01T12:09:40Z"))).to.deep.equal([]);
      // An EXTRA entry that is no probe, beside complete coverage: still refused (never skipped over).
      const stray = {
        target: "x.invalid",
        kind: "udp",
        atUtc: "2026-11-01T09:59:50Z",
        outcome: "REFUSED",
        error: "EPERM",
      };
      expect(runRefusals((o) => o.egress.before.push(stray as never))).to.include("EGRESS_NOT_DISABLED");
      expect(runRefusals((o) => o.egress.before.push({ ...stray, kind: "tcp", target: "" } as never))).to.include(
        "EGRESS_NOT_DISABLED",
      );
      expect(runRefusals((o) => o.egress.before.push({ ...stray, kind: "dns", atUtc: "x" } as never))).to.include(
        "EGRESS_NOT_DISABLED",
      );
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
      expect(runRefusals((o) => (o.timing.hostSeconds = 4800.5 as never))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.startedAtUtc = "2026-11-01 10:00:00"))).to.include("TIMING_IMPOSSIBLE");
      // The host window shifted before the gate began, its own seconds consistent: only the ordering refuses it.
      expect(
        runRefusals((o) => {
          o.timing.hostStartedAtUtc = "2026-11-01T09:50:00Z";
          o.timing.hostFinishedAtUtc = "2026-11-01T11:10:00Z";
        }),
      ).to.include("TIMING_IMPOSSIBLE");
      // Seconds that disagree with the stamps by more than the clock tolerance, host still shorter than the gate.
      expect(runRefusals((o) => (o.timing.gateSeconds = 7000))).to.include("TIMING_IMPOSSIBLE");
      expect(runRefusals((o) => (o.timing.hostSeconds = 4700))).to.include("TIMING_IMPOSSIBLE");
      // The host run equal to the gate run but longer in seconds: impossible even within the clock tolerance.
      expect(
        runRefusals((o) => {
          o.timing.hostStartedAtUtc = o.timing.startedAtUtc;
          o.timing.hostFinishedAtUtc = o.timing.finishedAtUtc;
          o.timing.hostSeconds = 7180;
          o.timing.gateSeconds = 7176;
        }),
      ).to.include("TIMING_IMPOSSIBLE");
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
      // The bytes under another selector with a consistent digest and the recorded selector unchanged.
      expect(
        runRefusals((o) => {
          const other = Buffer.concat([Buffer.from("00000000", "hex"), Buffer.alloc(352, 0xab)]);
          o.proof.proofBytes = `0x${other.toString("hex")}`;
          o.proof.proofBytesSha256 = sha256(other);
        }),
      ).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.proofBytesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValuesSha256 = "00".repeat(32)))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValues = "0x"))).to.include("PROOF_MISMATCH");
      expect(runRefusals((o) => (o.proof.publicValues = "0xabc"))).to.include("PROOF_MISMATCH");
      // Shape, not only the digest: empty public values or upper-case hex with a consistent digest are refused.
      expect(
        runRefusals((o) => {
          o.proof.publicValues = "0x";
          o.proof.publicValuesSha256 = sha256(Buffer.alloc(0));
        }),
      ).to.include("PROOF_MISMATCH");
      expect(
        runRefusals((o) => {
          const upper = Buffer.alloc(64, 0xab);
          o.proof.publicValues = `0x${upper.toString("hex").toUpperCase()}`;
          o.proof.publicValuesSha256 = sha256(upper);
        }),
      ).to.include("PROOF_MISMATCH");
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
      expect(refusals((v) => (v.tool.script = "scripts/other.ts"))).to.include("TOOL_NOT_BOUND");
      expect(refusals((v) => (v.measuredAtUtc = "2026-11-01 12:30:00"))).to.include("OBSERVATION_FIELD");
      expect(
        refusals(() => undefined, { ...EXPECTATIONS, scripts: { run: RUN_SCRIPT_SHA, verification: null } }),
      ).to.include("TOOL_NOT_BOUND");
      expect(
        refusals((v) => ((v.tool as unknown as Record<string, unknown>).scriptSha256 = null), {
          ...EXPECTATIONS,
          scripts: { run: RUN_SCRIPT_SHA, verification: null },
        }),
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
      expect(refusals((v) => (v.checks = "none" as never))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].block = -1))).to.include("VERIFIER_MISMATCH");
      expect(refusals((v) => (v.checks[0].block = 1.5))).to.include("VERIFIER_MISMATCH");
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
        executableSha256: HOST_BINARY_SHA,
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
        probes: { before: 7, after: 7, targets: probeTargets() },
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
      commit0: string;
      commit1: string;
      commit2: string;
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
      // A history whose commits each lack one fact the run's commit must hold: commit 0 an older host tree; commit 1
      // the designated host tree but another archive record; commit 2 the archive record but an older measurement
      // tool; then the base: the tool as committed, the designation naming the tree, the canonical host binary.
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(d, "zkvm/host/src/main.rs", "fn main() { /* v0 */ }\n");
      const commit0 = commit(d, "an older checkout");
      write(d, "zkvm/host/src/main.rs", "fn main() {}\n");
      write(
        d,
        productionRecordRel(ANCHOR),
        serializeJson({ ...ARCHIVE_RECORD, mirrors: [...ARCHIVE_RECORD.mirrors].reverse() }),
      );
      const commit1 = commit(d, "another archive record");
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(d, PROOF_INPUT_FIXTURE_REL, '{\n  "synthetic": "proof input fixture"\n}\n');
      write(d, RUN_SCRIPT_REL, "// synthetic measurement tool, first version\n");
      write(d, VERIFICATION_SCRIPT_REL, "// synthetic verification tool\n");
      const commit2 = commit(d, "the tools, first version");
      write(d, RUN_SCRIPT_REL, "// synthetic measurement tool\n");
      for (const [host, ip] of [
        ["developer-workstation", "203.0.113.5"],
        ["github-hosted-runner", "203.0.113.5"],
      ]) {
        write(
          d,
          `${OBSERVATIONS_DIR}/circuit-acquisition-${host}.raw.json`,
          serializeJson({ host, transfer: { remoteIp: ip } }),
        );
      }
      commit(d, "the designated host tree and the tools");
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
      const expect = exerciseExpectations(d, { anchor: ANCHOR, archive });
      void commit0;
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
      clean.source.zkvmHostTree = expect.zkvmHostTree;
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
      return { dir: d, base, commit0, commit1, commit2, run, verification, expect };
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
      expect(x.zkvmHostTree).to.match(/^[0-9a-f]{40}$/);
      expect(x.proofInputSha256).to.equal(sha256('{\n  "synthetic": "proof input fixture"\n}\n'));
      expect(x.upstreamHost).to.equal(UPSTREAM_HOST);
      expect(x.registryHost).to.equal(REGISTRY_HOST);
      expect(x.upstreamIps).to.deep.equal(["203.0.113.5"]);
      expect(x.hostBinarySha256).to.equal(HOST_BINARY_SHA);
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
      expect(bare.upstreamIps).to.deep.equal([]);
      expect(bare.hostBinarySha256).to.equal(null);
      expect(exerciseObservationsIn(d)).to.deep.equal({ run: [], verification: [], other: [] });
      expect(exerciseRecordsIn(d)).to.deep.equal([]);
      // No accepted archive record, no archive record file, no host tree in the designation: nothing to expect.
      assert.throws(
        () => exerciseExpectations(d, { anchor: ANCHOR, archive: { ...archive, record: null } }),
        /no accepted archive record/,
      );
      write(
        d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1 }),
      );
      assert.throws(() => exerciseExpectations(d, { anchor: ANCHOR, archive }), /names no zkvmHostTree/);
      rmSync(join(d, productionRecordRel(ANCHOR)));
      assert.throws(() => exerciseExpectations(d, { anchor: ANCHOR, archive }), /is missing/);
      // Two canonical builds for the designated tree naming different binaries bind nothing.
      const two = repo({ observations: false, record: false });
      write(
        two.dir,
        CANONICAL_REBUILD_OBSERVATION_REL,
        serializeJson({
          builds: [
            { hostId: "x", subject: { zkvmHostTree: two.expect.zkvmHostTree }, hostBinarySha256: HOST_BINARY_SHA },
            { hostId: "y", subject: { zkvmHostTree: two.expect.zkvmHostTree }, hostBinarySha256: "55".repeat(32) },
          ],
        }),
      );
      expect(exerciseExpectations(two.dir, { anchor: ANCHOR, archive }).hostBinarySha256).to.equal(null);
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

    it("is REFUSED for a record or an observation that is a link (POSIX)", function () {
      this.timeout(60_000);
      let r = repo();
      const linked = join(r.dir, "elsewhere.json");
      renameSync(join(r.dir, exerciseRecordRel(ANCHOR)), linked);
      symlinkOrSkip(this, linked, join(r.dir, exerciseRecordRel(ANCHOR)), "file");
      commit(r.dir, "a link");
      refused(r.dir, /not a regular file/);
      r = repo();
      const elsewhere = join(r.dir, "run-elsewhere.json");
      renameSync(join(r.dir, RUN_FILE), elsewhere);
      symlinkOrSkip(this, elsewhere, join(r.dir, RUN_FILE), "file");
      commit(r.dir, "a linked observation");
      refused(r.dir, /not a regular file/);
    });

    it("is REFUSED for an observation committed with CRLF line ends (the bound sha256 is of the committed bytes)", function () {
      this.timeout(60_000);
      const r = repo();
      writeFileSync(join(r.dir, RUN_FILE), readFileSync(join(r.dir, RUN_FILE), "utf8").replace(/\n/g, "\r\n"));
      commit(r.dir, "crlf");
      refused(r.dir, /CRLF/);
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
      // A commit in the history that does not hold the designated host tree (an older checkout, no tools).
      const older = repo();
      const o = JSON.parse(readFileSync(join(older.dir, RUN_FILE), "utf8"));
      o.source.commit = older.commit0;
      writeFileSync(join(older.dir, RUN_FILE), serializeJson(o));
      const v = JSON.parse(readFileSync(join(older.dir, VERIFICATION_FILE), "utf8"));
      v.run.sha256 = sha256(serializeJson(o));
      writeFileSync(join(older.dir, VERIFICATION_FILE), serializeJson(v));
      commit(older.dir, "another commit");
      refused(older.dir, /does not hold the designated host tree/);
      // A commit with the designated host tree but another archive record; one with the record but an older tool.
      for (const [pick, re] of [
        [(r: Repo) => r.commit1, /does not hold the archive record/],
        [(r: Repo) => r.commit2, /does not hold scripts\/measure-sp1-proof-exercise\.ts as committed/],
      ] as const) {
        const other = repo();
        const run2 = JSON.parse(readFileSync(join(other.dir, RUN_FILE), "utf8"));
        run2.source.commit = pick(other);
        writeFileSync(join(other.dir, RUN_FILE), serializeJson(run2));
        const ver2 = JSON.parse(readFileSync(join(other.dir, VERIFICATION_FILE), "utf8"));
        ver2.run.sha256 = sha256(serializeJson(run2));
        writeFileSync(join(other.dir, VERIFICATION_FILE), serializeJson(ver2));
        commit(other.dir, "another commit");
        refused(other.dir, re);
      }
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
      // Each binding alone: the bound record with one fact changed derives nothing.
      for (const [what, mutate] of [
        ["designation", (r: typeof bound) => (r.record!.subject.designation = "mldsa65-withdrawal-d9")],
        ["PROGRAM_VKEY", (r: typeof bound) => (r.record!.subject.programVKey = `0x${"00".repeat(32)}`)],
        ["archive path", (r: typeof bound) => (r.record!.archiveRecord.path = `${PROOF_EXERCISES_DIR}/other.json`)],
        ["archive sha256", (r: typeof bound) => (r.record!.archiveRecord.archiveSha256 = "00".repeat(32))],
      ] as const) {
        const broken = structuredClone(bound);
        mutate(broken);
        assert.throws(
          () => deriveProvingAvailability({ ...base, exerciseRecords: broken.records, exercise: broken }),
          /not an exercise of the accepted archive record/,
          what,
        );
      }
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

    it("the generators derive the third state on a copy of the real evidence plus a synthetic exercise (and nothing else does)", function () {
      this.timeout(300_000);
      const dirs2 = tempDirs();
      try {
        const d = dirs2.make("sp1-pa3a-real-");
        const git = (...args: string[]) => {
          const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: d, encoding: "utf8" });
          if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
          return r.stdout.trim();
        };
        git("init", "-q");
        git("config", "user.email", "test@example.invalid");
        git("config", "user.name", "test");
        git("config", "commit.gpgsign", "false");
        for (const p of ["evidence", "scripts", "test/fixtures", "zkvm/host", "zkvm/fixtures"]) {
          cpSync(resolve(p), join(d, p), { recursive: true });
        }
        // Since SP1-PA3B the real evidence holds a real exercise; the copy starts from the archived state (the real
        // exercise evidence removed), so the synthetic exercise alone makes the transition here.
        for (const rel of [...exerciseRecordsIn(d), ...Object.values(exerciseObservationsIn(d)).flat()]) {
          rmSync(join(d, rel));
        }
        git("add", "-A");
        git("commit", "-q", "-m", "the real evidence, copied");
        const anchor = productionAnchor(d);
        const archive = productionArchiveEvidenceOf(d);
        expect(archive.record, "the copied archive evidence is accepted").to.not.equal(null);
        const x = exerciseExpectations(d, { anchor, archive });
        expect(git("rev-parse", "HEAD:zkvm/host")).to.equal(x.zkvmHostTree);
        // The synthetic pair, bound to the copied evidence exactly as SP1-PA3B's tools would bind a real one.
        const run = runObservation();
        run.anchor = structuredClone(anchor);
        run.source = { repository: REPOSITORY_ID, commit: git("rev-parse", "HEAD"), zkvmHostTree: x.zkvmHostTree };
        run.archiveRecord = { path: x.archiveRecord.path, sha256: x.archiveRecord.sha256 };
        run.installedCircuit.members = structuredClone(x.archiveRecord.record.members);
        run.hostExecutable.sha256 = String(x.hostBinarySha256);
        run.inputs.sha256 = String(x.proofInputSha256);
        run.tool.scriptSha256 = String(x.scripts.run);
        const imageRef = `${x.archiveRecord.record.gnark.repository}@${x.archiveRecord.record.gnark.digest}`;
        run.gnark = {
          repository: x.archiveRecord.record.gnark.repository,
          digest: x.archiveRecord.record.gnark.digest,
          imageRef,
          localRepoDigests: [imageRef],
        };
        run.prover.frozenEnv.SP1_GNARK_IMAGE = imageRef;
        const probesAt = (atUtc: string) =>
          [
            ...[x.upstreamHost, x.registryHost].flatMap((h) => [
              { target: h, kind: "dns", atUtc, outcome: "REFUSED", error: "EAI_AGAIN" },
              { target: `${h}:443`, kind: "tcp", atUtc, outcome: "REFUSED", error: "ENETUNREACH" },
            ]),
            ...[...x.upstreamIps, ...EGRESS_CANARY_IPS].map((ip) => ({
              target: `${ip}:443`,
              kind: "tcp",
              atUtc,
              outcome: "REFUSED",
              error: "ENETUNREACH",
            })),
          ] as EgressProbe[];
        run.egress.before = probesAt("2026-11-01T09:59:50Z");
        run.egress.after = probesAt("2026-11-01T11:59:50Z");
        const selector = anchor.verifyingKey.sha256.slice(2, 10);
        const proofBytes = Buffer.concat([Buffer.from(selector, "hex"), Buffer.alloc(352, 0xab)]);
        run.proof = {
          vkey: anchor.programVKey,
          publicValues: run.proof.publicValues,
          proofBytes: `0x${proofBytes.toString("hex")}`,
          selector: `0x${selector}`,
          publicValuesSha256: run.proof.publicValuesSha256,
          proofBytesSha256: sha256(proofBytes),
        };
        const v = verificationObservation(run);
        v.run = { path: RUN_REL, sha256: runSha(run) };
        v.tool.scriptSha256 = String(x.scripts.verification);
        v.verifier = structuredClone(anchor.verifier);
        v.checks[0].runtimeCodeKeccak = anchor.verifier.runtimeCodeKeccak;
        writeFileSync(join(d, RUN_REL), serializeJson(run));
        writeFileSync(join(d, VERIFICATION_REL), serializeJson(v));
        git("add", "-A");
        git("commit", "-q", "-m", "the synthetic observations");
        const record = deriveExerciseRecord(
          run,
          v,
          { runSha256: runSha(run), verificationPath: VERIFICATION_REL, runPath: RUN_REL },
          x,
        );
        mkdirSync(join(d, PROOF_EXERCISES_DIR), { recursive: true });
        writeFileSync(join(d, exerciseRecordRel(anchor)), serializeJson(record));
        git("add", "-A");
        git("commit", "-q", "-m", "the derived record");
        const judged = productionExerciseEvidence(d, { anchor, archive });
        expect(exerciseEvidenceState(judged), judged.errors.join("; ")).to.equal("ACCEPTED");
        // The availability generator derives the third state from it, and only then the tooling generator.
        const pa = provingAvailabilityFromRepo(d);
        expect(pa.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
        expect(pa.selfHostedPath.exercised).to.equal(true);
        expect(pa.exercises.accepted?.record).to.equal(exerciseRecordRel(anchor));
        writeFileSync(join(d, "evidence/zk/sp1-impl/proving-availability.json"), serializeProvingAvailability(pa));
        git("add", "-A");
        git("commit", "-q", "-m", "availability regenerated");
        expect(advisoryStateFromRepo(d).exerciseRecords).to.deep.equal([exerciseRecordRel(anchor)]);
        return toolingRecordFromRepo(d).then((tooling) => {
          expect(tooling.state).to.equal("SELF_HOSTED_PATH_EXERCISED");
          expect((tooling.exercise as { state: string; record: string }).state).to.equal("ACCEPTED");
          expect((tooling.exercise as { state: string; record: string }).record).to.equal(exerciseRecordRel(anchor));
          expect((tooling.states as { reached: boolean }[]).map((s) => s.reached)).to.deep.equal([
            true,
            true,
            true,
            true,
          ]);
          expect(availabilityStatusesFor(tooling.state as "SELF_HOSTED_PATH_EXERCISED")).to.deep.equal([
            "SELF_HOSTED_PATH_EXERCISED",
          ]);
          dirs2.cleanup();
        });
      } catch (error) {
        dirs2.cleanup();
        throw error;
      }
    });

    it("the real checkout has reached the third state: exactly one record, derived from exactly one run and one verification observation, exercised true", function () {
      this.timeout(120_000);
      const anchor = productionAnchor(".");
      const archive = productionArchiveEvidenceOf(".");
      const records = exerciseRecordsIn(".");
      expect(records).to.deep.equal([exerciseRecordRel(anchor)]);
      const observations = exerciseObservationsIn(".");
      expect(observations.run).to.have.length(1);
      expect(observations.verification).to.have.length(1);
      expect(observations.other).to.deep.equal([]);
      const exercise = productionExerciseEvidence(".", { anchor, archive });
      expect(exercise.errors).to.deep.equal([]);
      expect(exerciseEvidenceState(exercise)).to.equal("ACCEPTED");
      expect(exercise.observations).to.deep.equal([...observations.run, ...observations.verification]);
      const committed = JSON.parse(readFileSync(records[0], "utf8"));
      expect(exercise.record).to.deep.equal(committed);
      expect(toolingState({ selfTestPassed: true, archive, exercise })).to.equal("SELF_HOSTED_PATH_EXERCISED");
      const pa = provingAvailabilityFromRepo(".");
      expect(pa.status).to.equal("SELF_HOSTED_PATH_EXERCISED");
      expect(pa.selfHostedPath.exercised).to.equal(true);
      expect(pa.selfHostedPath.record).to.equal(records[0]);
      expect(pa.exercises.records).to.equal(1);
      expect(pa.exercises.accepted?.record).to.equal(records[0]);
      // SP1-PA3B's record is bound to the real expectations: the canonical host binary for the designated host tree,
      // the committed proof input and archive record, the acquisitions' addresses; it was accepted by the designated
      // verifier with egress refused, within the rotation delay. SP1-PA2C's evidence is still not SP1-PA3's: the
      // archive record is no run observation and no verification.
      const x = exerciseExpectations(".", { anchor, archive });
      expect(x.upstreamIps).to.deep.equal(["3.5.90.58", "3.5.93.98"]);
      expect(x.hostBinarySha256).to.equal("fc8eff69e78e39c5c08bfa0eea2f402d5b67341eb27caae7fd34ff6b456abf1b");
      expect(x.zkvmHostTree).to.equal("30f72596c430974bf8113892bf41c26dce3629f3");
      expect(committed.host).to.deep.include({ executableSha256: x.hostBinarySha256, sourceTree: x.zkvmHostTree });
      expect(committed.proofInput.sha256).to.equal(x.proofInputSha256);
      expect(committed.archiveRecord.sha256).to.equal(x.archiveRecord.sha256);
      expect(committed.prover.mode).to.equal("cpu");
      expect(committed.verification.acceptance).to.equal("ACCEPTED");
      expect(committed.egress.condition).to.equal("EGRESS_DISABLED");
      expect(committed.performance.withinRotationDelay).to.equal(true);
      expect(runObservationErrors(archive.record, x).map((r) => r.reason)).to.include("OBSERVATION_SHAPE");
      expect(
        verificationObservationErrors(archive.record, { path: "", sha256: "", observation: runObservation() }, x).map(
          (r) => r.reason,
        ),
      ).to.include("OBSERVATION_SHAPE");
    });
  });

  describe("the measurement (SP1-PA3B's tool, exercised here with injected readers; nothing is proved)", function () {
    const dirs = tempDirs();
    afterEach(() => dirs.cleanup());
    const clockAt = (stamps: string[]) => () => stamps.shift() ?? "2026-11-01T23:59:59Z";

    it("parses the kernel's high-water mark and docker's memory usage, refusing what it cannot read", function () {
      expect(parseVmHWM("Name:\tmldsa65-host\nVmPeak:\t 1 kB\nVmHWM:\t  123456 kB\nVmRSS:\t 1 kB\n")).to.equal(
        123456 * 1024,
      );
      expect(parseVmHWM("Name:\tx\n")).to.equal(null);
      expect(parseVmHWM("VmHWM:\t  -5 kB\n")).to.equal(null);
      expect(parseDockerMemUsage("1.5GiB / 15.6GiB")).to.equal(Math.round(1.5 * 1024 ** 3));
      expect(parseDockerMemUsage("512MiB / 2GiB")).to.equal(512 * 1024 ** 2);
      expect(parseDockerMemUsage("900kB / 1GiB")).to.equal(900 * 1000);
      expect(parseDockerMemUsage("2.25TiB / 4TiB")).to.equal(Math.round(2.25 * 1024 ** 4));
      expect(parseDockerMemUsage("0B / 0B")).to.equal(0);
      expect(parseDockerMemUsage("garbage")).to.equal(null);
      expect(parseDockerMemUsage("")).to.equal(null);
    });

    it("sums the pinned image's containers from docker's answers, and reads nothing docker did not answer", function () {
      const answers = (
        ps: { status: number | null; stdout: string; error?: Error },
        stats: { status: number | null; stdout: string; error?: Error },
      ) => dockerContainerBytes("registry.invalid/x@sha256:00", {}, (args) => (args[0] === "ps" ? ps : stats));
      const ids = "abcdef0123456789\nfedcba9876543210\n";
      expect(answers({ status: 0, stdout: ids }, { status: 0, stdout: "1GiB / 4GiB\n512MiB / 4GiB\n" })()).to.equal(
        1024 ** 3 + 512 * 1024 ** 2,
      );
      expect(answers({ status: 1, stdout: "" }, { status: 0, stdout: "1GiB / 4GiB\n" })()).to.equal(null);
      expect(answers({ status: 0, stdout: "", error: new Error("no docker") }, { status: 0, stdout: "" })()).to.equal(
        null,
      );
      expect(answers({ status: 0, stdout: "\n" }, { status: 0, stdout: "1GiB / 4GiB\n" })()).to.equal(null);
      expect(answers({ status: 0, stdout: ids }, { status: 1, stdout: "" })()).to.equal(null);
      expect(answers({ status: 0, stdout: ids }, { status: 0, stdout: "", error: new Error("x") })()).to.equal(null);
      expect(answers({ status: 0, stdout: ids }, { status: 0, stdout: "garbage\n" })()).to.equal(null);
      expect(answers({ status: 0, stdout: ids }, { status: 0, stdout: "\n" })()).to.equal(null);
      // A failed command whose output still looks like an answer is no answer.
      expect(answers({ status: 1, stdout: ids }, { status: 0, stdout: "1GiB / 4GiB\n" })()).to.equal(null);
      expect(
        answers({ status: 0, stdout: ids, error: new Error("x") }, { status: 0, stdout: "1GiB / 4GiB\n" })(),
      ).to.equal(null);
      expect(answers({ status: 0, stdout: ids }, { status: 1, stdout: "1GiB / 4GiB\n" })()).to.equal(null);
      expect(
        answers({ status: 0, stdout: ids }, { status: 0, stdout: "1GiB / 4GiB\n", error: new Error("x") })(),
      ).to.equal(null);
    });

    it("measures a run: the host's wall time (rounded up), its peak RSS and the sampled container memory", async function () {
      this.timeout(30_000);
      let rss = 0;
      const container = [null, 5_000, 7_000, 6_000];
      let k = 0;
      const m = measuringSpawner({
        intervalMs: 20,
        hostRssBytes: () => (rss += 1_000),
        containerBytes: () => container[Math.min(k++, container.length - 1)],
        clock: clockAt(["2026-11-01T10:20:00Z", "2026-11-01T10:20:01Z"]),
      });
      const env: Record<string, string> = {};
      for (const name of ["PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME"]) {
        if (process.env[name]) env[name] = process.env[name] as string;
      }
      const plan = {
        executable: process.execPath,
        args: ["-e", 'setTimeout(() => { console.log(\'{"vkey":"0x01"}\') }, 300)'],
        env,
        dropped: [],
        circuitDir: "",
        imageRef: "registry.invalid/x@sha256:00",
        record: {} as never,
      };
      const r = await m.spawner(plan);
      expect(r.status).to.equal(0);
      expect(r.stdout).to.include('"vkey"');
      const got = m.measurement();
      expect(got).to.deep.include({
        hostStartedAtUtc: "2026-11-01T10:20:00Z",
        hostFinishedAtUtc: "2026-11-01T10:20:01Z",
        hostSeconds: 1,
        containerPeakBytes: 7_000,
        intervalMs: 20,
      });
      expect(got.hostPeakRssBytes).to.be.greaterThan(0);
      expect(got.containerSamples).to.be.at.least(1);
      // Before a run there is no measurement; after it the child's exit code is the gate's to judge, not this tool's.
      assert.throws(
        () => measuringSpawner({ intervalMs: 20, hostRssBytes: () => null, containerBytes: () => null }).measurement(),
        /no run/,
      );
      const failing = measuringSpawner({ intervalMs: 20, hostRssBytes: () => null, containerBytes: () => null });
      const f = await failing.spawner({ ...plan, args: ["-e", "process.exit(3)"] });
      expect(f.status).to.equal(3);
      expect(failing.measurement().containerSamples).to.equal(0);
      // A child flooding stdout is refused as the gate refuses it.
      const flooded = measuringSpawner({
        intervalMs: 20,
        hostRssBytes: () => null,
        containerBytes: () => null,
        maxStdout: 16,
      });
      await assert.rejects(
        flooded.spawner({ ...plan, args: ["-e", "console.log('x'.repeat(100))"] }),
        /PROOF_OUTPUT_REFUSED/,
      );
    });

    it("probes egress: a refusal is recorded with its code; a resolution or a connection is recorded as such", async function () {
      const clock = clockAt(["2026-11-01T09:59:50Z", "2026-11-01T09:59:51Z", "2026-11-01T09:59:52Z"]);
      const refusing = {
        lookup: async (host: string) => {
          if (host === "b.invalid") return;
          throw Object.assign(new Error("resolution refused"), { code: "EAI_AGAIN" });
        },
        connect: async () => {
          throw Object.assign(new Error("unreachable"), { code: "ENETUNREACH" });
        },
        clock,
      };
      const probes = await probeEgress(
        { dns: ["a.invalid", "b.invalid"], tcp: [{ host: "a.invalid", port: 443 }] },
        refusing,
      );
      expect(probes).to.deep.equal([
        { target: "a.invalid", kind: "dns", atUtc: "2026-11-01T09:59:50Z", outcome: "REFUSED", error: "EAI_AGAIN" },
        { target: "b.invalid", kind: "dns", atUtc: "2026-11-01T09:59:51Z", outcome: "RESOLVED", error: null },
        {
          target: "a.invalid:443",
          kind: "tcp",
          atUtc: "2026-11-01T09:59:52Z",
          outcome: "REFUSED",
          error: "ENETUNREACH",
        },
      ]);
      const open = await probeEgress(
        { dns: [], tcp: [{ host: "a.invalid", port: 443 }] },
        { lookup: async () => undefined, connect: async () => undefined, clock },
      );
      expect(open[0]).to.deep.include({ outcome: "CONNECTED", error: null });
      // An error without a code is recorded as UNKNOWN, which the validator refuses: egress was not shown refused.
      const unknown = await probeEgress(
        { dns: ["x.invalid"], tcp: [] },
        {
          lookup: async () => {
            throw new Error("?");
          },
          connect: async () => undefined,
          clock,
        },
      );
      expect(unknown[0]).to.deep.include({ outcome: "REFUSED", error: "UNKNOWN" });
      expect(egressTargets(EXPECTATIONS)).to.deep.equal({
        dns: [UPSTREAM_HOST, REGISTRY_HOST],
        tcp: [
          { host: UPSTREAM_HOST, port: 443 },
          { host: REGISTRY_HOST, port: 443 },
          { host: "203.0.113.5", port: 443 },
          { host: "1.1.1.1", port: 443 },
          { host: "8.8.8.8", port: 443 },
        ],
      });
    });

    it("identifies a file and the source checkout: sha256 and length; HEAD and the host tree; a dirty tree is seen", function () {
      this.timeout(60_000);
      const d = dirs.make("sp1-pa3a-src-");
      const git = (...args: string[]) => {
        const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: d, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
        return r.stdout.trim();
      };
      git("init", "-q");
      git("config", "user.email", "test@example.invalid");
      git("config", "user.name", "test");
      git("config", "commit.gpgsign", "false");
      mkdirSync(join(d, "zkvm", "host"), { recursive: true });
      writeFileSync(join(d, "zkvm", "host", "main.rs"), "fn main() {}\n");
      writeFileSync(join(d, "inputs.json"), "{}\n");
      git("add", "-A");
      git("commit", "-q", "-m", "base");
      expect(fileIdentity(join(d, "inputs.json"))).to.deep.equal({
        file: "inputs.json",
        bytes: 3,
        sha256: sha256("{}\n"),
      });
      expect(sourceIdentity(d)).to.deep.equal({
        repository: REPOSITORY_ID,
        commit: git("rev-parse", "HEAD"),
        zkvmHostTree: git("rev-parse", "HEAD:zkvm/host"),
        dirty: false,
      });
      writeFileSync(join(d, "zkvm", "host", "main.rs"), "fn main() { }\n");
      expect(sourceIdentity(d).dirty).to.equal(true);
      assert.throws(() => sourceIdentity(dirs.make("sp1-pa3a-nogit-")), /is not a git checkout/);
      // A checkout without the host source tree: the tree is not a tree of it (not an empty string).
      const nohost = dirs.make("sp1-pa3a-nohost-");
      const g2 = (...args: string[]) => {
        const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: nohost, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
        return r.stdout.trim();
      };
      g2("init", "-q");
      g2("config", "user.email", "test@example.invalid");
      g2("config", "user.name", "test");
      g2("config", "commit.gpgsign", "false");
      writeFileSync(join(nohost, "README.md"), "no host here\n");
      g2("add", "-A");
      g2("commit", "-q", "-m", "no host");
      assert.throws(() => sourceIdentity(nohost), /HEAD:zkvm\/host is not a tree/);
    });
  });

  describe("the commands (run from this checkout; nothing is proved, pulled or downloaded)", function () {
    const run = (script: string, ...args: string[]) =>
      spawnSync(process.execPath, [join("node_modules", "tsx", "dist", "cli.mjs"), script, ...args], {
        cwd: resolve("."),
        encoding: "utf8",
        env: { ...process.env, FORCE_COLOR: "0" },
        timeout: 120_000,
      });

    it("sp1:proof-exercise-record --validate: the committed record is what the committed observations derive (SELF_HOSTED_PATH_EXERCISED)", function () {
      this.timeout(120_000);
      const r = run("scripts/generate-sp1-proof-exercise-record.ts", "--validate");
      expect(r.status, r.stderr).to.equal(0);
      expect(r.stdout).to.include("OK:");
      expect(r.stdout).to.include(exerciseRecordsIn(".")[0]);
      expect(r.stdout).to.include("verifier ACCEPTED");
      expect(r.stdout).to.include("within the 172800 s rotation delay");
      expect(r.stdout).to.include("SELF_HOSTED_PATH_EXERCISED");
    });

    it("sp1:proof-exercise-record: never overwrites the committed record (the same observations derive it again, and it exists)", function () {
      this.timeout(120_000);
      const rel = exerciseRecordsIn(".")[0];
      const before = readFileSync(rel);
      const r = run("scripts/generate-sp1-proof-exercise-record.ts");
      expect(r.status).to.equal(1);
      expect(`${r.stdout}\n${r.stderr}`).to.match(/exists: a proof-exercise record is never overwritten/);
      expect(readFileSync(rel).equals(before)).to.equal(true);
      expect(exerciseRecordsIn(".")).to.deep.equal([rel]);
    });

    it("sp1:measure-proof-exercise refuses before any act: the arguments, then the host, then the record", function () {
      this.timeout(120_000);
      const committed = exerciseObservationsIn(".");
      const none = run("scripts/measure-sp1-proof-exercise.ts");
      expect(none.status).to.equal(1);
      expect(`${none.stdout}\n${none.stderr}`).to.include("--record is required");
      const absent = run(
        "scripts/measure-sp1-proof-exercise.ts",
        "--record",
        resolve("absent-record.json"),
        "--circuit-root",
        "/srv/absent",
        "--host",
        "/srv/absent/mldsa65-host",
        "--inputs",
        "/srv/absent/inputs.json",
        "--host-label",
        "proving-host-a",
        "--enforcement",
        "synthetic",
        "--out",
        resolve("absent-out.json"),
      );
      expect(absent.status).to.equal(1);
      expect(`${absent.stdout}\n${absent.stderr}`).to.match(
        /PROVE_HOST_UNSUPPORTED \(NOT_LINUX\)|RECORD_NOT_AUTHORITATIVE/,
      );
      // Nothing was written: the committed observations (SP1-PA3B's one pair) are exactly what is there.
      expect(exerciseObservationsIn(".")).to.deep.equal(committed);
    });
  });
});
