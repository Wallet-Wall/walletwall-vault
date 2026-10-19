/**
 * SP1-PA3A test helper: synthetic proof-exercise evidence (an anchor that is no designation, the safe fixture
 * archive's record, one consistent run observation and its verification). Shared by test/Sp1ProofExercise.test.ts
 * (the validators, the derivation, the committed-evidence judge) and test/Sp1ProofExerciseVerifier.test.ts (the
 * designated runtime on a development chain). Nothing here is a proof: the proof bytes are a pattern under the
 * synthetic selector. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";

import { PROOF_INVALID } from "../../scripts/lib/sp1-chain-execution";
import { productionRecordRel, serializeJson } from "../../scripts/lib/sp1-circuit-acquisition";
import { SAFE_FILES, SYNTHETIC_ANCHOR, gz, safeTar, syntheticRecord } from "../../scripts/lib/sp1-circuit-fixtures";
import {
  EGRESS_DISABLED,
  REPOSITORY_ID,
  RUN_SCHEMA,
  RUN_SCRIPT_REL,
  VERIFICATION_SCHEMA,
  VERIFICATION_SCRIPT_REL,
  type EgressProbe,
  type ExerciseExpectations,
  type RunObservation,
  type VerificationObservation,
} from "../../scripts/lib/sp1-proof-exercise";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const hex = (b: Buffer) => `0x${b.toString("hex")}`;

export const RUN_REL = "evidence/zk/sp1-impl/observations/proof-exercise-run-proving-host-a.raw.json";
export const VERIFICATION_REL = "evidence/zk/sp1-impl/observations/proof-exercise-verification-proving-host-a.raw.json";

// ---------------------------------------------------------------------------------------------------------------
// Synthetic evidence: an anchor that is no designation, the safe fixture archive's record, one run, one verification
// ---------------------------------------------------------------------------------------------------------------

export const ANCHOR = SYNTHETIC_ANCHOR;
export const ARCHIVE_GZ = gz(safeTar());
export const ARCHIVE_RECORD = syntheticRecord(ARCHIVE_GZ, SAFE_FILES);
export const ARCHIVE_RECORD_TEXT = serializeJson(ARCHIVE_RECORD);
export const RUN_SCRIPT_SHA = "11".repeat(32);
export const VERIFICATION_SCRIPT_SHA = "22".repeat(32);
export const INPUT_SHA = "33".repeat(32);
export const HOST_TREE = "a".repeat(40);
export const SOURCE_COMMIT = "c".repeat(40);
export const UPSTREAM_HOST = "example.invalid";
export const REGISTRY_HOST = "registry.invalid";
export const ROOT = "/srv/sp1/circuits";
export const IMAGE_REF = `${ARCHIVE_RECORD.gnark.repository}@${ARCHIVE_RECORD.gnark.digest}`;
export const SELECTOR = ANCHOR.verifyingKey.sha256.slice(2, 10);
export const PROOF_BYTES = Buffer.concat([Buffer.from(SELECTOR, "hex"), Buffer.alloc(352, 0xab)]);
export const PUBLIC_VALUES = Buffer.alloc(64, 0x01);

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

export function probes(atUtc: string): EgressProbe[] {
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
