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
import { createHash } from "node:crypto";

import { serializeJson, type ArchiveEvidence } from "../scripts/lib/sp1-circuit-acquisition";
import { productionRecordRel } from "../scripts/lib/sp1-circuit-acquisition";
import { PROOF_INVALID } from "../scripts/lib/sp1-chain-execution";
import { SAFE_FILES, SYNTHETIC_ANCHOR, gz, safeTar, syntheticRecord } from "../scripts/lib/sp1-circuit-fixtures";
import {
  EGRESS_DISABLED,
  EXERCISE_RECORD_SCHEMA,
  PROOF_EXERCISES_DIR,
  REPOSITORY_ID,
  ROTATION_DELAY_SECONDS,
  RUN_SCHEMA,
  RUN_SCRIPT_REL,
  VERIFICATION_SCHEMA,
  VERIFICATION_SCRIPT_REL,
  deriveExerciseRecord,
  exerciseErrors,
  exerciseRecordRel,
  runObservationErrors,
  verificationObservationErrors,
  type EgressProbe,
  type ExerciseExpectations,
  type RunObservation,
  type VerificationObservation,
} from "../scripts/lib/sp1-proof-exercise";

const RUN_REL = "evidence/zk/sp1-impl/observations/proof-exercise-run-proving-host-a.raw.json";
const VERIFICATION_REL = "evidence/zk/sp1-impl/observations/proof-exercise-verification-proving-host-a.raw.json";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const hex = (b: Buffer) => `0x${b.toString("hex")}`;

// ---------------------------------------------------------------------------------------------------------------
// Synthetic evidence: an anchor that is no designation, the safe fixture archive's record, one run, one verification
// ---------------------------------------------------------------------------------------------------------------

const ANCHOR = SYNTHETIC_ANCHOR;
const ARCHIVE_GZ = gz(safeTar());
const ARCHIVE_RECORD = syntheticRecord(ARCHIVE_GZ, SAFE_FILES);
const ARCHIVE_RECORD_TEXT = serializeJson(ARCHIVE_RECORD);
const RUN_SCRIPT_SHA = "11".repeat(32);
const VERIFICATION_SCRIPT_SHA = "22".repeat(32);
const INPUT_SHA = "33".repeat(32);
const HOST_TREE = "a".repeat(40);
const SOURCE_COMMIT = "c".repeat(40);
const UPSTREAM_HOST = "example.invalid";
const REGISTRY_HOST = "registry.invalid";
const ROOT = "/srv/sp1/circuits";
const IMAGE_REF = `${ARCHIVE_RECORD.gnark.repository}@${ARCHIVE_RECORD.gnark.digest}`;
const SELECTOR = ANCHOR.verifyingKey.sha256.slice(2, 10);
const PROOF_BYTES = Buffer.concat([Buffer.from(SELECTOR, "hex"), Buffer.alloc(352, 0xab)]);
const PUBLIC_VALUES = Buffer.alloc(64, 0x01);

export const EXPECTATIONS: ExerciseExpectations = {
  anchor: ANCHOR,
  archiveRecord: {
    path: productionRecordRel(ANCHOR),
    sha256: sha256(ARCHIVE_RECORD_TEXT),
    record: ARCHIVE_RECORD,
  },
  zkvmHostTree: HOST_TREE,
  proofInputSha256: INPUT_SHA,
  upstreamHost: UPSTREAM_HOST,
  registryHost: REGISTRY_HOST,
  scripts: { run: RUN_SCRIPT_SHA, verification: VERIFICATION_SCRIPT_SHA },
  repository: REPOSITORY_ID,
};

function probes(atUtc: string): EgressProbe[] {
  const dns = (target: string): EgressProbe => ({ target, kind: "dns", atUtc, outcome: "REFUSED", error: "EAI_AGAIN" });
  const tcp = (target: string): EgressProbe => ({
    target,
    kind: "tcp",
    atUtc,
    outcome: "REFUSED",
    error: "ENETUNREACH",
  });
  return [dns(UPSTREAM_HOST), tcp(`${UPSTREAM_HOST}:443`), dns(REGISTRY_HOST), tcp(`${REGISTRY_HOST}:443`)];
}

export function runObservation(): RunObservation {
  return {
    schema: RUN_SCHEMA,
    host: "proving-host-a",
    measuredAtUtc: "2026-11-01T12:00:10Z",
    tool: { script: RUN_SCRIPT_REL, scriptSha256: RUN_SCRIPT_SHA },
    source: { repository: REPOSITORY_ID, commit: SOURCE_COMMIT, zkvmHostTree: HOST_TREE },
    anchor: structuredClone(ANCHOR),
    archiveRecord: { path: EXPECTATIONS.archiveRecord.path, sha256: EXPECTATIONS.archiveRecord.sha256 },
    installedCircuit: {
      root: ROOT,
      circuitVersion: ANCHOR.circuitVersion,
      members: structuredClone(ARCHIVE_RECORD.members),
    },
    hostExecutable: { file: "mldsa65-host", bytes: 12_345_678, sha256: "44".repeat(32) },
    inputs: { file: "mldsa65-withdrawal.inputs.json", bytes: 7_000, sha256: INPUT_SHA },
    gnark: {
      repository: ARCHIVE_RECORD.gnark.repository,
      digest: ARCHIVE_RECORD.gnark.digest,
      imageRef: IMAGE_REF,
      localRepoDigests: [IMAGE_REF],
    },
    prover: {
      mode: "cpu",
      frozenEnv: {
        SP1_PROVER: "cpu",
        SP1_GROTH16_CIRCUIT_PATH: ROOT,
        SP1_GNARK_IMAGE: IMAGE_REF,
        DOCKER_CONTEXT: "default",
      },
      passedThrough: ["HOME", "PATH"],
      dropped: ["SHELL"],
    },
    egress: {
      enforcement: "nftables: every outbound packet dropped except loopback, on the host and the docker bridge",
      before: probes("2026-11-01T09:59:50Z"),
      after: probes("2026-11-01T11:59:50Z"),
      condition: EGRESS_DISABLED,
    },
    timing: {
      startedAtUtc: "2026-11-01T10:00:00Z",
      finishedAtUtc: "2026-11-01T11:59:40Z",
      gateSeconds: 7180,
      hostStartedAtUtc: "2026-11-01T10:20:00Z",
      hostFinishedAtUtc: "2026-11-01T11:40:00Z",
      hostSeconds: 4800,
    },
    peakMemory: {
      hostProcess: { bytes: 3_000_000_000, method: "/proc/<pid>/status VmHWM, polled every 2000 ms" },
      gnarkContainers: {
        bytes: 20_000_000_000,
        samples: 2400,
        intervalMs: 2000,
        method: "docker stats --no-stream of containers whose ancestor is the pinned image, polled every 2000 ms",
      },
    },
    proof: {
      vkey: ANCHOR.programVKey,
      publicValues: hex(PUBLIC_VALUES),
      proofBytes: hex(PROOF_BYTES),
      selector: `0x${SELECTOR}`,
      publicValuesSha256: sha256(PUBLIC_VALUES),
      proofBytesSha256: sha256(PROOF_BYTES),
    },
    platform: ["host=proving-host-a", "os=linux 6.8.0 x64", "node=v22.13.0"],
  };
}

export function verificationObservation(run: RunObservation = runObservation()): VerificationObservation {
  return {
    schema: VERIFICATION_SCHEMA,
    host: "proving-host-a",
    measuredAtUtc: "2026-11-01T12:30:00Z",
    tool: { script: VERIFICATION_SCRIPT_REL, scriptSha256: VERIFICATION_SCRIPT_SHA },
    run: { path: "evidence/zk/sp1-impl/observations/proof-exercise-run-proving-host-a.raw.json", sha256: runSha(run) },
    proof: {
      vkey: run.proof.vkey,
      publicValuesSha256: run.proof.publicValuesSha256,
      proofBytesSha256: run.proof.proofBytesSha256,
    },
    verifier: structuredClone(ANCHOR.verifier),
    checks: [
      {
        chainId: "31337",
        address: `0x${"ab".repeat(20)}`,
        runtimeCodeKeccak: ANCHOR.verifier.runtimeCodeKeccak,
        mode: "AUTHENTICATED_RUNTIME_LOCAL",
        verdicts: { real: "success", tampered: `revert ${PROOF_INVALID}` },
        block: null,
      },
    ],
    acceptance: "ACCEPTED",
  };
}

export const runSha = (run: RunObservation) => sha256(serializeJson(run));

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
      expect(runRefusals((o) => ((o as Record<string, unknown>).verified = true))).to.include("OBSERVATION_SHAPE");
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
      expect(refusals((v) => ((v as Record<string, unknown>).note = "fine"))).to.include("OBSERVATION_SHAPE");
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
});
