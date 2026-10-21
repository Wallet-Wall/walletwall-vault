/**
 * SP1-PA3A: the authoritative evidence of one real self-hosted proof exercise, and the state it derives
 * (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md, "SP1-PA3A").
 *
 * No proof is made here. A later, owner-authorized lane (SP1-PA3B) runs the UNCHANGED archive-only gate
 * (scripts/lib/sp1-prove-gate.ts) once, through scripts/measure-sp1-proof-exercise.ts, which measures the run (the
 * gate's wall time, the host process's peak RSS, the gnark containers' sampled memory, network egress probed refused
 * before and after, the exact executable, inputs, image and environment the host was given) and writes one RUN
 * observation; then scripts/verify-sp1-proof-exercise.ts submits the proof to the designated verifier (the
 * CREATE2-authenticated v6.1.0 runtime, whose code hash the designation pins) and writes one VERIFICATION observation
 * that binds the run observation's bytes. The record (walletwall.sp1-proof-exercise.v1) is DERIVED from the two
 * observations by `deriveExerciseRecord`, never written by hand; `exerciseErrors` names every reason they derive none;
 * and `productionExerciseEvidence` holds the committed record to the committed observations, byte for byte, with the
 * accepted archive record they ran from.
 *
 * SP1-PA3D0: the directory holds history, never ambiguity. SP1-PA3B's v1 record keeps its slot,
 * evidence/zk/sp1-impl/proof-exercises/<designation>.json, and its observations their names; a v2 exercise (SP1-PA3C's
 * attributed run) is recorded beside it as <designation>.v2.<token>.json, its two observations named after the same
 * token (exerciseToken: its run observation's digest, the one its exercise.id carries). Every record is judged on its
 * own and the directory as a whole (exerciseDirectoryOf, productionExerciseEvidence): one or more accepted records are
 * one state, any refused file refuses it, and a record once committed, with its observations from then on, is never
 * withdrawn or edited (exerciseHistoryErrors). Each record keeps its own egress assurance; a stronger one never rewrites
 * an older record's.
 *
 * Five facts, kept apart: artifact identity (the archive record, SP1-PA2B/C), proving execution (the run), verifier
 * acceptance (the verification), performance (wall time and memory against the 2-day rotation delay) and production
 * readiness (the implementation receipt's, never derived here). SELF_HOSTED_PATH_EXERCISED needs the first three and
 * records the fourth; it is liveness, never soundness, and never production readiness.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { connect, isIP } from "node:net";
import { basename, dirname, posix, resolve } from "node:path";

import { Interface, getBytes, hexlify, keccak256, type Provider, type Signer } from "ethers";

import { directoryHistoryErrors } from "./append-only-history";
import { uncommittedEvidenceError } from "./committed-evidence";
import { CANONICAL_REBUILD_OBSERVATION_REL } from "./sp1-canonical-build";
import { PROOF_INVALID, VERIFIER_BYTECODE_REL, verdictOf } from "./sp1-chain-execution";
import {
  ACQUISITION_OBSERVATIONS_REL,
  archiveEvidenceState,
  productionRecordRel,
  serializeJson,
  type ArchiveEvidence,
} from "./sp1-circuit-acquisition";
import {
  refuse,
  type ArchiveAnchor,
  type ArchiveMember,
  type ArchiveRecord,
  type Refusal,
} from "./sp1-circuit-archive";
import { readDesignations, type ProgramDesignation } from "./sp1-designation";
import { OBSERVER_SCRIPT_REL } from "../sp1-egress-observer";
import {
  EDGE_PROBES_ONLY,
  assuranceOf,
  observerEvidenceErrors,
  type EgressAssurance,
  type ObserverEvidence,
} from "./sp1-egress-attribution";
import {
  DOCKER_CONTEXT_FROZEN,
  FROZEN_ENV,
  LOCAL_PROVER,
  PASS_THROUGH_ENV,
  REFUSED_ENV,
  REFUSED_ENV_PREFIX,
  type ProvePlan,
  type SpawnResult,
  type Spawner,
} from "./sp1-prove-gate";

export const PROOF_EXERCISES_DIR = "evidence/zk/sp1-impl/proof-exercises";
export const EXERCISE_RECORD_SCHEMA = "walletwall.sp1-proof-exercise.v1";
export const RUN_SCHEMA = "walletwall.sp1-proof-exercise-run.v1";
/**
 * SP1-PA3C: a run observed continuously (scripts/sp1-egress-observer.ts) and attributed process by process
 * (scripts/lib/sp1-egress-attribution.ts). A v1 run is never read as one: it stays what it was, edge-probed only.
 */
export const RUN_SCHEMA_V2 = "walletwall.sp1-proof-exercise-run.v2";
export const EXERCISE_RECORD_SCHEMA_V2 = "walletwall.sp1-proof-exercise.v2";
export const ATTRIBUTED_RUN_SCRIPT_REL = "scripts/measure-sp1-attributed-proof-exercise.ts";
/** The lane expected to make the first attributed exercise (no v2 record exists; that lane confirms the name). */
export const ATTRIBUTED_EXERCISE_LANE = "SP1-PA3D";
export const VERIFICATION_SCHEMA = "walletwall.sp1-proof-exercise-verification.v1";
export const RUN_SCRIPT_REL = "scripts/measure-sp1-proof-exercise.ts";
export const VERIFICATION_SCRIPT_REL = "scripts/verify-sp1-proof-exercise.ts";
export const OBSERVATIONS_DIR = "evidence/zk/sp1-impl/observations";
export const EXERCISE_OBSERVATION_PREFIX = "proof-exercise-";
export const RUN_OBSERVATION_PREFIX = "proof-exercise-run-";
export const VERIFICATION_OBSERVATION_PREFIX = "proof-exercise-verification-";
/** The committed proof input the exercise must prove (scripts/generate-sp1-proof-input.ts). */
export const PROOF_INPUT_FIXTURE_REL = "zkvm/fixtures/mldsa65-withdrawal.inputs.json";
/** The repository every observation names; a record for another repository's evidence is no record here. */
export const REPOSITORY_ID = "Wallet-Wall/walletwall-vault";
/** PQ_VERIFIER_UPDATE_DELAY (contracts/WalletWallVault.sol): 2 days; a PqOnly user must prove within it. */
export const ROTATION_DELAY_SECONDS = 2 * 24 * 3600;
export const EGRESS_DISABLED = "EGRESS_DISABLED";
/** A refused CONNECTION: unreachable, rejected, timed out, or forbidden. What a probe at an address must end with. */
export const CONNECTION_REFUSAL_CODES: readonly string[] = [
  "ENETUNREACH",
  "EHOSTUNREACH",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EACCES",
  "EPERM",
];
/** A refused name resolution: what a probe by name may end with instead (a stub resolver answers this with egress
 * open, which is why the address probes below are required as well). */
export const RESOLUTION_REFUSAL_CODES: readonly string[] = ["EAI_AGAIN", "ENOTFOUND", "EAI_FAIL", "EAI_NONAME"];
export const EGRESS_REFUSAL_CODES: readonly string[] = [...CONNECTION_REFUSAL_CODES, ...RESOLUTION_REFUSAL_CODES];
/** Canary addresses (anycast resolvers, TCP 443): a refused connection to each shows egress blocked below name
 * resolution, which no resolver stub can imitate. */
export const EGRESS_CANARY_IPS: readonly string[] = ["1.1.1.1", "8.8.8.8"];
/** A probe attests to the run only near it: at most this long before it began or after it ended. */
export const PROBE_WINDOW_SECONDS = 600;
export const PROBE_PORT = 443;
export const LOCAL_RUNTIME = "AUTHENTICATED_RUNTIME_LOCAL";
export const DEPLOYED_RUNTIME = "DEPLOYED";
export const ACCEPTED = "ACCEPTED";
export const REJECTED = "REJECTED";
/**
 * The v1 slot of `anchor`'s designation: `<designation>.json`, the only name a v1 record may have. SP1-PA3B's record
 * holds it; SP1-PA3D0 keeps it where it is and adds the v2 records beside it, never in its place.
 */
export const exerciseRecordRel = (anchor: ArchiveAnchor) => `${PROOF_EXERCISES_DIR}/${anchor.designation}.json`;
/** A v2 record's path: `<designation>.v2.<token>.json`, named after its exercise (exerciseToken) (SP1-PA3D0). */
export const attributedExerciseRecordRel = (anchor: ArchiveAnchor, token: string) =>
  `${PROOF_EXERCISES_DIR}/${anchor.designation}.v2.${token}.json`;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HEX_BYTES = /^0x(?:[0-9a-f]{2})+$/;
/** The stamps of an observation are second-resolution wall clocks; monotonic seconds may differ from them this much. */
const CLOCK_TOLERANCE_SECONDS = 5;

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isText = (x: unknown): x is string => typeof x === "string" && x.length > 0;
const isPositiveInt = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) > 0;
const seconds = (utc: string) => Date.parse(utc) / 1000;
const byPath = <T extends { path: string }>(xs: readonly T[]) => [...xs].sort((a, b) => (a.path < b.path ? -1 : 1));

// ---------------------------------------------------------------------------------------------------------------
// The observations
// ---------------------------------------------------------------------------------------------------------------

export interface EgressProbe {
  /** `<host>` for a dns probe, `<host>:<port>` for a tcp probe. */
  target: string;
  kind: "dns" | "tcp";
  atUtc: string;
  outcome: "REFUSED" | "RESOLVED" | "CONNECTED";
  /** The error code a refused probe ended with; null when it resolved or connected. */
  error: string | null;
}

export interface RunObservation {
  schema: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
  /** The checkout the gate and this tool were run from: the repository, its HEAD, and the host source tree. */
  source: { repository: string; commit: string; zkvmHostTree: string };
  /** The committed production anchor the gate accepted the record for, from the checkout the tool lives in. */
  anchor: ArchiveAnchor;
  /** The committed archive record the gate ran from, by path and sha256 of its committed (LF) bytes. */
  archiveRecord: { path: string; sha256: string };
  /** What the gate verified under <root>/<circuit version>, re-hashed before and after the run. */
  installedCircuit: { root: string; circuitVersion: string; members: ArchiveMember[] };
  hostExecutable: { file: string; bytes: number; sha256: string };
  inputs: { file: string; bytes: number; sha256: string };
  gnark: { repository: string; digest: string; imageRef: string; localRepoDigests: string[] };
  prover: {
    mode: typeof LOCAL_PROVER;
    /** The four values the gate froze for the host; nothing else the caller set reached it. */
    frozenEnv: Record<string, string>;
    /** Names (never values) of the caller's variables the gate passed through, and of those it dropped. */
    passedThrough: string[];
    dropped: string[];
  };
  /** `condition` is what the tool observed (EGRESS_DISABLED only when every probe was refused); the validator requires it. */
  egress: { enforcement: string; before: EgressProbe[]; after: EgressProbe[]; condition: string };
  timing: {
    /** The gate run: the record check, the re-hash of the installation, the host, the re-hash again. */
    startedAtUtc: string;
    finishedAtUtc: string;
    gateSeconds: number;
    /** The host process alone (proving proper, the gnark container included). */
    hostStartedAtUtc: string;
    hostFinishedAtUtc: string;
    hostSeconds: number;
  };
  peakMemory: {
    hostProcess: { bytes: number; method: string };
    gnarkContainers: { bytes: number; samples: number; intervalMs: number; method: string };
  };
  proof: {
    vkey: string;
    publicValues: string;
    proofBytes: string;
    /** The proof's first four bytes: sha256(groth16_vk.bin)'s, the key it was made under. */
    selector: string;
    publicValuesSha256: string;
    proofBytesSha256: string;
  };
  platform: string[];
}

export interface VerificationCheck {
  chainId: string;
  address: string;
  /** keccak256 of the code at `address` when the call was made; must be the designation's. */
  runtimeCodeKeccak: string;
  mode: typeof LOCAL_RUNTIME | typeof DEPLOYED_RUNTIME;
  verdicts: { real: string; tampered: string };
  block: number | null;
}

export interface VerificationObservation {
  schema: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
  /** The run observation whose proof was verified, by path and sha256 of its committed (LF) bytes. */
  run: { path: string; sha256: string };
  proof: { vkey: string; publicValuesSha256: string; proofBytesSha256: string };
  verifier: ArchiveAnchor["verifier"];
  checks: VerificationCheck[];
  acceptance: typeof ACCEPTED | typeof REJECTED;
}

/** The fields an observation names, level by level: an unknown field is refused, not ignored. */
export const OBSERVATION_FIELDS = {
  run: [
    "schema",
    "host",
    "measuredAtUtc",
    "tool",
    "source",
    "anchor",
    "archiveRecord",
    "installedCircuit",
    "hostExecutable",
    "inputs",
    "gnark",
    "prover",
    "egress",
    "timing",
    "peakMemory",
    "proof",
    "platform",
  ],
  tool: ["script", "scriptSha256"],
  source: ["repository", "commit", "zkvmHostTree"],
  archiveRecord: ["path", "sha256"],
  installedCircuit: ["root", "circuitVersion", "members"],
  file: ["file", "bytes", "sha256"],
  gnark: ["repository", "digest", "imageRef", "localRepoDigests"],
  prover: ["mode", "frozenEnv", "passedThrough", "dropped"],
  egress: ["enforcement", "before", "after", "condition"],
  probe: ["target", "kind", "atUtc", "outcome", "error"],
  timing: ["startedAtUtc", "finishedAtUtc", "gateSeconds", "hostStartedAtUtc", "hostFinishedAtUtc", "hostSeconds"],
  peakMemory: ["hostProcess", "gnarkContainers"],
  hostProcess: ["bytes", "method"],
  gnarkContainers: ["bytes", "samples", "intervalMs", "method"],
  proof: ["vkey", "publicValues", "proofBytes", "selector", "publicValuesSha256", "proofBytesSha256"],
  verification: ["schema", "host", "measuredAtUtc", "tool", "run", "proof", "verifier", "checks", "acceptance"],
  verifier: ["version", "runtimeCodeKeccak", "verifierHash"],
  verificationProof: ["vkey", "publicValuesSha256", "proofBytesSha256"],
  check: ["chainId", "address", "runtimeCodeKeccak", "mode", "verdicts", "block"],
  verdicts: ["real", "tampered"],
} as const;

/** What the committed evidence expects of an exercise: the anchor, the accepted archive record, the bound inputs. */
export interface ExerciseExpectations {
  anchor: ArchiveAnchor;
  /** The accepted production archive record: its path, the sha256 of its committed bytes, and the record itself. */
  archiveRecord: { path: string; sha256: string; record: ArchiveRecord };
  /** The designated host source tree (the designation's subject.zkvmHostTree). */
  zkvmHostTree: string;
  /** sha256 of the committed proof-input fixture's LF bytes (null when absent: then nothing binds). */
  proofInputSha256: string | null;
  /** The hosts egress must have been refused to: the archive's upstream and the gnark image's registry. */
  upstreamHost: string;
  registryHost: string;
  /** The upstream addresses the committed acquisitions were served from: probed by address, beside the canaries. */
  upstreamIps: string[];
  /** The canonical-build host binary's sha256 for the designated host tree (null when the committed canonical
   * rebuild observation names none, or more than one: then no host executable binds). */
  hostBinarySha256: string | null;
  /** sha256 of the committed tools' LF bytes (null when a tool is absent: then nothing binds). A v2 run binds the
   * attributed measurement tool and the root observer instead of `run`. */
  scripts: { run: string | null; verification: string | null; attributedRun?: string | null; observer?: string | null };
  repository: string;
}

/** A shape check: `o` must name exactly `keys`; reports the extra and missing ones under `reason`. */
function exactly(
  o: unknown,
  keys: readonly string[],
  where: string,
  reason: string,
  no: (reason: string, detail: string) => void,
): o is Record<string, any> {
  if (!isObject(o)) {
    no(reason, `${where} is not an object`);
    return false;
  }
  const extra = Object.keys(o).filter((k) => !keys.includes(k));
  const missing = keys.filter((k) => !(k in o));
  if (extra.length > 0) no(reason, `${where} names ${extra.join(", ")}`);
  if (missing.length > 0) no(reason, `${where} lacks ${missing.join(", ")}`);
  return extra.length === 0 && missing.length === 0;
}

/** The probe targets an exercise must have been refused at: name resolution and TCP 443 for each host. */
export function requiredProbeTargets(
  expect: Pick<ExerciseExpectations, "upstreamHost" | "registryHost" | "upstreamIps">,
): string[] {
  return [
    ...[expect.upstreamHost, expect.registryHost].flatMap((h) => [`dns:${h}`, `tcp:${h}:${PROBE_PORT}`]),
    ...[...expect.upstreamIps, ...EGRESS_CANARY_IPS].map((ip) => `tcp:${ip}:${PROBE_PORT}`),
  ].sort();
}

/** The host a tcp probe target names (`<host>:<port>`). */
const probeHost = (target: string) => target.slice(0, target.lastIndexOf(":"));

function probeErrors(
  probes: unknown,
  where: string,
  expect: ExerciseExpectations,
  no: (reason: string, detail: string) => void,
): EgressProbe[] | null {
  if (!Array.isArray(probes) || probes.length === 0) {
    no("EGRESS_NOT_DISABLED", `${where} holds no probe`);
    return null;
  }
  const ok: EgressProbe[] = [];
  probes.forEach((p, i) => {
    if (!exactly(p, OBSERVATION_FIELDS.probe, `${where}[${i}]`, "EGRESS_NOT_DISABLED", no)) return;
    if ((p.kind !== "dns" && p.kind !== "tcp") || !isText(p.target) || !UTC.test(String(p.atUtc))) {
      no("EGRESS_NOT_DISABLED", `${where}[${i}] is not a probe`);
      return;
    }
    // A probe at an address must have had its CONNECTION refused; a resolver code there says only that names do
    // not resolve, which a stub resolver gives with egress open. A probe by name may fail either way.
    const atAddress = p.kind === "tcp" && isIP(probeHost(String(p.target))) !== 0;
    const allowed = atAddress ? CONNECTION_REFUSAL_CODES : EGRESS_REFUSAL_CODES;
    if (p.outcome !== "REFUSED" || !allowed.includes(String(p.error))) {
      no(
        "EGRESS_NOT_DISABLED",
        `${where}[${i}] ${p.kind} ${p.target}: ${String(p.outcome)} (${String(p.error)}); egress was not refused${atAddress ? " at the connection" : ""}`,
      );
      return;
    }
    ok.push(p as EgressProbe);
  });
  const covered = new Set(ok.map((p) => `${p.kind}:${p.target}`));
  const missing = requiredProbeTargets(expect).filter((t) => !covered.has(t));
  if (missing.length > 0) no("EGRESS_NOT_DISABLED", `${where} did not probe ${missing.join(", ")}`);
  return ok;
}

/** The gate's frozen environment for `root` and `imageRef`: what a run observation's prover.frozenEnv must be. */
export function expectedFrozenEnv(root: string, imageRef: string): Record<string, string> {
  return {
    SP1_PROVER: LOCAL_PROVER,
    SP1_GROTH16_CIRCUIT_PATH: root,
    SP1_GNARK_IMAGE: imageRef,
    DOCKER_CONTEXT: DOCKER_CONTEXT_FROZEN,
  };
}

const isRefusedName = (k: string) => {
  const K = k.toUpperCase();
  return REFUSED_ENV[K] !== undefined || K.startsWith(REFUSED_ENV_PREFIX);
};

/** Every reason `value` is not a run observation of one gate run for `expect`'s anchor and record; [] accepts it. */
export function runObservationErrors(value: unknown, expect: ExerciseExpectations): Refusal[] {
  const out: Refusal[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = "run";
  if (!exactly(value, OBSERVATION_FIELDS.run, where, "OBSERVATION_SHAPE", no)) return out;
  const o = value as RunObservation;
  if (o.schema !== RUN_SCHEMA) no("OBSERVATION_SCHEMA", `${where} must be ${RUN_SCHEMA}`);
  if (!HOST_LABEL.test(String(o.host))) no("OBSERVATION_FIELD", `${where}.host is not a host label`);
  if (!UTC.test(String(o.measuredAtUtc))) no("OBSERVATION_FIELD", `${where}.measuredAtUtc`);
  if (
    !exactly(o.tool, OBSERVATION_FIELDS.tool, `${where}.tool`, "OBSERVATION_SHAPE", no) ||
    o.tool.script !== RUN_SCRIPT_REL ||
    expect.scripts.run === null ||
    o.tool.scriptSha256 !== expect.scripts.run
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${RUN_SCRIPT_REL} as committed: re-measure`);
  }
  if (exactly(o.source, OBSERVATION_FIELDS.source, `${where}.source`, "OBSERVATION_SHAPE", no)) {
    if (o.source.repository !== expect.repository)
      no("SOURCE_MISMATCH", `${where}.source names ${String(o.source.repository)}, not ${expect.repository}`);
    if (!HEX40.test(String(o.source.commit))) no("SOURCE_MISMATCH", `${where}.source.commit is not a commit`);
    if (o.source.zkvmHostTree !== expect.zkvmHostTree) {
      no(
        "HOST_IDENTITY_MISMATCH",
        `${where}.source.zkvmHostTree ${String(o.source.zkvmHostTree)} is not the designated host tree ${expect.zkvmHostTree}`,
      );
    }
  }
  if (!same(o.anchor, expect.anchor))
    no("ANCHOR_MISMATCH", `${where} ran against another anchor than the designation's`);
  if (
    exactly(o.archiveRecord, OBSERVATION_FIELDS.archiveRecord, `${where}.archiveRecord`, "OBSERVATION_SHAPE", no) &&
    (o.archiveRecord.path !== expect.archiveRecord.path || o.archiveRecord.sha256 !== expect.archiveRecord.sha256)
  ) {
    no(
      "ARCHIVE_RECORD_MISMATCH",
      `${where} ran from ${String(o.archiveRecord.path)} (sha256 ${String(o.archiveRecord.sha256)}), not the committed ${expect.archiveRecord.path} (${expect.archiveRecord.sha256})`,
    );
  }
  const record = expect.archiveRecord.record;
  const ic = o.installedCircuit;
  if (exactly(ic, OBSERVATION_FIELDS.installedCircuit, `${where}.installedCircuit`, "OBSERVATION_SHAPE", no)) {
    if (!isText(ic.root) || !posix.isAbsolute(ic.root))
      no("INSTALLED_CIRCUIT_MISMATCH", `${where}.installedCircuit.root is not an absolute path`);
    if (ic.circuitVersion !== expect.anchor.circuitVersion)
      no(
        "INSTALLED_CIRCUIT_MISMATCH",
        `${where} installed ${String(ic.circuitVersion)}, not ${expect.anchor.circuitVersion}`,
      );
    const members = Array.isArray(ic.members)
      ? byPath(ic.members.map((m) => ({ path: m?.path, bytes: m?.bytes, sha256: m?.sha256 })))
      : null;
    if (members === null || !same(members, byPath(record.members))) {
      no("INSTALLED_CIRCUIT_MISMATCH", `${where}: the installation verified is not the record's members`);
    }
  }
  for (const [k, what] of [
    ["hostExecutable", "HOST_IDENTITY_MISMATCH"],
    ["inputs", "PROOF_INPUT_MISMATCH"],
  ] as const) {
    const f = o[k];
    if (
      !exactly(f, OBSERVATION_FIELDS.file, `${where}.${k}`, "OBSERVATION_SHAPE", no) ||
      !isText(f.file) ||
      !isPositiveInt(f.bytes) ||
      !HEX64.test(String(f.sha256))
    ) {
      no(what, `${where}.${k} is not a measured file, length and sha256`);
    }
  }
  if (
    isObject(o.hostExecutable) &&
    (expect.hostBinarySha256 === null || o.hostExecutable.sha256 !== expect.hostBinarySha256)
  ) {
    no(
      "HOST_IDENTITY_MISMATCH",
      `${where} ran a host executable with sha256 ${String(o.hostExecutable.sha256)}, not the canonical-build host binary for the designated host tree (${String(expect.hostBinarySha256)}): another host build`,
    );
  }
  if (isObject(o.inputs) && (expect.proofInputSha256 === null || o.inputs.sha256 !== expect.proofInputSha256)) {
    no(
      "PROOF_INPUT_MISMATCH",
      `${where} proved ${String(o.inputs.sha256)}, not the committed ${PROOF_INPUT_FIXTURE_REL} (${String(expect.proofInputSha256)})`,
    );
  }
  const g = o.gnark;
  const imageRef = `${record.gnark.repository}@${record.gnark.digest}`;
  if (exactly(g, OBSERVATION_FIELDS.gnark, `${where}.gnark`, "OBSERVATION_SHAPE", no)) {
    if (
      g.repository !== record.gnark.repository ||
      g.digest !== record.gnark.digest ||
      !DIGEST.test(String(g.digest)) ||
      g.imageRef !== imageRef
    ) {
      no("GNARK_IMAGE_MISMATCH", `${where} ran ${String(g.imageRef)}, not the record's ${imageRef} (by digest)`);
    }
    if (!Array.isArray(g.localRepoDigests) || !g.localRepoDigests.includes(imageRef)) {
      no("GNARK_IMAGE_MISMATCH", `${where}: the local store did not hold ${imageRef} by its digest`);
    }
  }
  const p = o.prover;
  if (exactly(p, OBSERVATION_FIELDS.prover, `${where}.prover`, "OBSERVATION_SHAPE", no)) {
    if (p.mode !== LOCAL_PROVER)
      no("PROVER_MODE_MISMATCH", `${where} proved in mode ${String(p.mode)}, not ${LOCAL_PROVER}`);
    const env = isObject(p.frozenEnv) ? p.frozenEnv : null;
    if (env?.SP1_PROVER !== LOCAL_PROVER)
      no("PROVER_MODE_MISMATCH", `${where}: SP1_PROVER was ${String(env?.SP1_PROVER)}, not ${LOCAL_PROVER}`);
    const want = expectedFrozenEnv(String(ic?.root), imageRef);
    if (
      env === null ||
      Object.keys(env).sort().join() !== [...FROZEN_ENV].sort().join() ||
      !same(Object.fromEntries(Object.entries(env).sort()), Object.fromEntries(Object.entries(want).sort()))
    ) {
      no("PROVER_ENV_MISMATCH", `${where}: the host's frozen environment is not the gate's`);
    }
    for (const [k, names] of [
      ["passedThrough", p.passedThrough],
      ["dropped", p.dropped],
    ] as const) {
      if (!Array.isArray(names) || !names.every((n) => typeof n === "string" && ENV_NAME.test(n))) {
        no("PROVER_ENV_MISMATCH", `${where}.prover.${k} is not a list of variable names`);
        continue;
      }
      const refused = names.filter(isRefusedName);
      if (refused.length > 0)
        no("PROVER_ENV_MISMATCH", `${where}: ${refused.join(", ")} was set; the gate refuses such a run`);
      if (k === "passedThrough" && names.some((n) => !PASS_THROUGH_ENV.includes(n.toUpperCase()))) {
        no("PROVER_ENV_MISMATCH", `${where}: a variable the gate never passes through reached the host`);
      }
    }
  }
  const e = o.egress;
  let before: EgressProbe[] | null = null;
  let after: EgressProbe[] | null = null;
  if (exactly(e, OBSERVATION_FIELDS.egress, `${where}.egress`, "OBSERVATION_SHAPE", no)) {
    if (e.condition !== EGRESS_DISABLED)
      no("EGRESS_NOT_DISABLED", `${where}.egress.condition is ${String(e.condition)}`);
    if (!isText(e.enforcement)) no("EGRESS_NOT_DISABLED", `${where}.egress.enforcement names no enforcement`);
    before = probeErrors(e.before, `${where}.egress.before`, expect, no);
    after = probeErrors(e.after, `${where}.egress.after`, expect, no);
  }
  const t = o.timing;
  if (exactly(t, OBSERVATION_FIELDS.timing, `${where}.timing`, "OBSERVATION_SHAPE", no)) {
    const stamps = [t.startedAtUtc, t.finishedAtUtc, t.hostStartedAtUtc, t.hostFinishedAtUtc].map(String);
    if (!stamps.every((s) => UTC.test(s)) || !isPositiveInt(t.gateSeconds) || !isPositiveInt(t.hostSeconds)) {
      no("TIMING_IMPOSSIBLE", `${where}.timing is not four UTC stamps and two positive whole seconds`);
    } else {
      const [s, f, hs, hf] = stamps.map(seconds);
      if (!(s < f && s <= hs && hs < hf && hf <= f))
        no("TIMING_IMPOSSIBLE", `${where}.timing: the host run is not inside the gate run`);
      if (t.hostSeconds > t.gateSeconds) no("TIMING_IMPOSSIBLE", `${where}.timing: the host ran longer than the gate`);
      if (Math.abs(f - s - t.gateSeconds) > CLOCK_TOLERANCE_SECONDS)
        no("TIMING_IMPOSSIBLE", `${where}.timing: gateSeconds ${t.gateSeconds} is not the stamps' ${f - s} s`);
      if (Math.abs(hf - hs - t.hostSeconds) > CLOCK_TOLERANCE_SECONDS)
        no("TIMING_IMPOSSIBLE", `${where}.timing: hostSeconds ${t.hostSeconds} is not the stamps' ${hf - hs} s`);
      if (UTC.test(String(o.measuredAtUtc)) && !(f <= seconds(o.measuredAtUtc)))
        no("TIMING_IMPOSSIBLE", `${where} was measured before the gate run ended`);
      for (const b of before ?? []) {
        const at = seconds(b.atUtc);
        if (!(at <= s && s - at <= PROBE_WINDOW_SECONDS)) {
          no(
            "EGRESS_NOT_DISABLED",
            `${where}: a "before" probe was not taken within ${PROBE_WINDOW_SECONDS} s before the run began`,
          );
        }
      }
      for (const a of after ?? []) {
        const at = seconds(a.atUtc);
        if (!(at >= f && at - f <= PROBE_WINDOW_SECONDS)) {
          no(
            "EGRESS_NOT_DISABLED",
            `${where}: an "after" probe was not taken within ${PROBE_WINDOW_SECONDS} s after the run ended`,
          );
        }
      }
    }
  }
  const m = o.peakMemory;
  if (exactly(m, OBSERVATION_FIELDS.peakMemory, `${where}.peakMemory`, "OBSERVATION_SHAPE", no)) {
    const h = m.hostProcess;
    if (
      !exactly(h, OBSERVATION_FIELDS.hostProcess, `${where}.peakMemory.hostProcess`, "OBSERVATION_SHAPE", no) ||
      !isPositiveInt(h.bytes) ||
      !isText(h.method)
    ) {
      no("PEAK_MEMORY_MALFORMED", `${where}.peakMemory.hostProcess is not a positive byte count with its method`);
    }
    const c = m.gnarkContainers;
    if (
      !exactly(c, OBSERVATION_FIELDS.gnarkContainers, `${where}.peakMemory.gnarkContainers`, "OBSERVATION_SHAPE", no) ||
      !isPositiveInt(c.bytes) ||
      !isPositiveInt(c.samples) ||
      !isPositiveInt(c.intervalMs) ||
      !isText(c.method)
    ) {
      no(
        "PEAK_MEMORY_MALFORMED",
        `${where}.peakMemory.gnarkContainers is not a sampled positive byte count (samples, interval, method)`,
      );
    }
  }
  const pr = o.proof;
  if (exactly(pr, OBSERVATION_FIELDS.proof, `${where}.proof`, "OBSERVATION_SHAPE", no)) {
    if (pr.vkey !== expect.anchor.programVKey)
      no("PROOF_MISMATCH", `${where}: the proof names vkey ${String(pr.vkey)}, not the designated PROGRAM_VKEY`);
    const pv = String(pr.publicValues);
    const pb = String(pr.proofBytes);
    if (!HEX_BYTES.test(pv) || !HEX_BYTES.test(pb) || pb.length < 10) {
      no("PROOF_MISMATCH", `${where}: publicValues and proofBytes must be hex bytes`);
    } else {
      const selector = expect.anchor.verifyingKey.sha256.slice(0, 10);
      if (pr.selector !== selector || !pb.startsWith(selector))
        no("PROOF_MISMATCH", `${where}: the proof was not made under the designated verifying key (selector)`);
      if (pr.publicValuesSha256 !== sha256(Buffer.from(pv.slice(2), "hex")))
        no("PROOF_MISMATCH", `${where}.proof.publicValuesSha256 is not the public values' sha256`);
      if (pr.proofBytesSha256 !== sha256(Buffer.from(pb.slice(2), "hex")))
        no("PROOF_MISMATCH", `${where}.proof.proofBytesSha256 is not the proof bytes' sha256`);
    }
  }
  if (!Array.isArray(o.platform) || o.platform.length === 0 || !o.platform.every(isText)) {
    no("OBSERVATION_FIELD", `${where}.platform names no host identity`);
  }
  return out;
}

/** A v2 run observation: the v1 fields, and in `egress` the observer's continuous evidence beside the edge probes. */
export interface AttributedRunObservation extends Omit<RunObservation, "egress"> {
  egress: RunObservation["egress"] & { observer: ObserverEvidence };
}

export const EGRESS_V2_FIELDS = ["enforcement", "before", "after", "condition", "observer"] as const;

/** Stands in for the v1 tool's digest while the v1 checks judge a v2 run's shared fields (never written anywhere). */
const PROJECTED_TOOL = "v2-projection";

/**
 * Every reason `value` is not a v2 run observation: every v1 rule on the fields v1 and v2 share (the same function,
 * on a projection that differs only in the schema, the tool and the egress keys), the attributed tool bound as
 * committed, and the observer's evidence judged by scripts/lib/sp1-egress-attribution.ts: coverage of the whole run,
 * continuity, every attempt attributed or named as not, the boundary's counters reconciled, the edge probes seen in
 * the trace, the capture bound to this run's commit, host label, boot and clock. [] accepts it.
 */
export function attributedRunObservationErrors(value: unknown, expect: ExerciseExpectations): Refusal[] {
  const out: Refusal[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = "run";
  if (!exactly(value, OBSERVATION_FIELDS.run, where, "OBSERVATION_SHAPE", no)) return out;
  const o = value as AttributedRunObservation;
  if (o.schema !== RUN_SCHEMA_V2) no("OBSERVATION_SCHEMA", `${where} must be ${RUN_SCHEMA_V2}`);
  if (
    !exactly(o.tool, OBSERVATION_FIELDS.tool, `${where}.tool`, "OBSERVATION_SHAPE", no) ||
    o.tool.script !== ATTRIBUTED_RUN_SCRIPT_REL ||
    (expect.scripts.attributedRun ?? null) === null ||
    o.tool.scriptSha256 !== expect.scripts.attributedRun
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${ATTRIBUTED_RUN_SCRIPT_REL} as committed: re-measure`);
  }
  if (!exactly(o.egress, EGRESS_V2_FIELDS, `${where}.egress`, "OBSERVATION_SHAPE", no)) return out;
  const { observer, ...edges } = o.egress;
  const projected = {
    ...o,
    schema: RUN_SCHEMA,
    tool: { script: RUN_SCRIPT_REL, scriptSha256: PROJECTED_TOOL },
    egress: edges,
  };
  out.push(...runObservationErrors(projected, { ...expect, scripts: { ...expect.scripts, run: PROJECTED_TOOL } }));
  out.push(...observerEvidenceErrors(observer, observerExpectationsOf(o, expect)).refusals);
  if (isObject(observer)) {
    const exe = observer.hostExecutable;
    if (isObject(exe) && isObject(o.hostExecutable) && basename(String(exe.path)) !== o.hostExecutable.file) {
      no(
        "HOST_IDENTITY_MISMATCH",
        `${where}: the observer followed ${String(exe.path)}, not the measured ${String(o.hostExecutable.file)}`,
      );
    }
    const lines = Array.isArray(o.platform) ? o.platform.map(String) : [];
    if (!lines.includes(`bootId=${String(observer.bootId)}`)) {
      no(
        "OBSERVER_NOT_THIS_RUN",
        `${where}.platform does not name the boot the observer watched: another host or another boot`,
      );
    }
  }
  return out;
}

/** The run observation a verification must bind: its committed path, the sha256 of its committed bytes, itself. */
export interface BoundRun {
  path: string;
  sha256: string;
  observation: RunObservation;
}

/** Every reason `value` is not the designated verifier's acceptance of `run`'s proof; [] accepts it. */
export function verificationObservationErrors(value: unknown, run: BoundRun, expect: ExerciseExpectations): Refusal[] {
  const out: Refusal[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = "verification";
  if (!exactly(value, OBSERVATION_FIELDS.verification, where, "OBSERVATION_SHAPE", no)) return out;
  const v = value as VerificationObservation;
  if (v.schema !== VERIFICATION_SCHEMA) no("OBSERVATION_SCHEMA", `${where} must be ${VERIFICATION_SCHEMA}`);
  if (!HOST_LABEL.test(String(v.host))) no("OBSERVATION_FIELD", `${where}.host is not a host label`);
  if (!UTC.test(String(v.measuredAtUtc))) no("OBSERVATION_FIELD", `${where}.measuredAtUtc`);
  else if (
    UTC.test(String(run.observation.measuredAtUtc)) &&
    !(seconds(run.observation.measuredAtUtc) <= seconds(v.measuredAtUtc))
  ) {
    no("OBSERVATION_FIELD", `${where} was made before the run it verifies was measured`);
  }
  if (
    !exactly(v.tool, OBSERVATION_FIELDS.tool, `${where}.tool`, "OBSERVATION_SHAPE", no) ||
    v.tool.script !== VERIFICATION_SCRIPT_REL ||
    expect.scripts.verification === null ||
    v.tool.scriptSha256 !== expect.scripts.verification
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${VERIFICATION_SCRIPT_REL} as committed: re-verify`);
  }
  if (
    exactly(v.run, OBSERVATION_FIELDS.archiveRecord, `${where}.run`, "OBSERVATION_SHAPE", no) &&
    (v.run.path !== run.path || v.run.sha256 !== run.sha256)
  ) {
    no(
      "RUN_NOT_BOUND",
      `${where} verified ${String(v.run.path)} (sha256 ${String(v.run.sha256)}), not the committed ${run.path} (${run.sha256}): the run observation changed after it was verified, or another run was verified`,
    );
  }
  const rp = run.observation.proof;
  if (
    exactly(v.proof, OBSERVATION_FIELDS.verificationProof, `${where}.proof`, "OBSERVATION_SHAPE", no) &&
    (v.proof.vkey !== rp?.vkey ||
      v.proof.publicValuesSha256 !== rp?.publicValuesSha256 ||
      v.proof.proofBytesSha256 !== rp?.proofBytesSha256)
  ) {
    no("PROOF_MISMATCH", `${where} verified another proof than the run observation holds`);
  }
  if (!same(v.verifier, expect.anchor.verifier)) {
    no("VERIFIER_MISMATCH", `${where} names another verifier than the designation's`);
  }
  const checks = Array.isArray(v.checks) ? v.checks : null;
  if (checks === null || checks.length === 0) {
    no("VERIFIER_MISMATCH", `${where} holds no check: the designated verifier was never asked`);
  } else {
    let local = 0;
    checks.forEach((c, i) => {
      const at = `${where}.checks[${i}]`;
      if (!exactly(c, OBSERVATION_FIELDS.check, at, "OBSERVATION_SHAPE", no)) return;
      if (!/^[0-9]+$/.test(String(c.chainId))) no("VERIFIER_MISMATCH", `${at}.chainId is not a chain id`);
      if (!ADDRESS.test(String(c.address))) no("VERIFIER_MISMATCH", `${at}.address is not an address`);
      if (c.runtimeCodeKeccak !== expect.anchor.verifier.runtimeCodeKeccak) {
        no(
          "VERIFIER_MISMATCH",
          `${at}: the code at ${String(c.address)} on chain ${String(c.chainId)} is ${String(c.runtimeCodeKeccak)}, not the designated verifier's ${expect.anchor.verifier.runtimeCodeKeccak}`,
        );
      }
      if (c.mode !== LOCAL_RUNTIME && c.mode !== DEPLOYED_RUNTIME)
        no("VERIFIER_MISMATCH", `${at}.mode ${String(c.mode)}`);
      if (c.mode === LOCAL_RUNTIME) local++;
      if (c.block !== null && !isPositiveInt(c.block)) no("VERIFIER_MISMATCH", `${at}.block`);
      if (!exactly(c.verdicts, OBSERVATION_FIELDS.verdicts, `${at}.verdicts`, "OBSERVATION_SHAPE", no)) return;
      if (c.verdicts.real !== "success") {
        no("VERIFIER_REJECTED", `${at}: the designated verifier answered ${String(c.verdicts.real)} to the proof`);
      }
      if (c.verdicts.tampered !== `revert ${PROOF_INVALID}`) {
        no(
          "VERIFIER_REJECTED",
          `${at}: the tampered copy was answered ${String(c.verdicts.tampered)}, not revert ${PROOF_INVALID}: not the designated verifier's behavior`,
        );
      }
    });
    if (local === 0) {
      no("VERIFIER_MISMATCH", `${where}: no check ran the CREATE2-authenticated runtime itself (${LOCAL_RUNTIME})`);
    }
  }
  if (v.acceptance !== ACCEPTED) {
    no("VERIFIER_REJECTED", `${where}.acceptance is ${String(v.acceptance)}: the proof was not accepted`);
  }
  return out;
}

/** What binds the pair: the run observation's committed bytes (and path, when known), where the verification is. */
export interface ExerciseBinding {
  runSha256: string;
  verificationPath: string;
  /** The run observation's committed path; when absent the verification's own claim is taken as the path. */
  runPath?: string;
}

/** Every reason `run` and `verification` do not derive one record for `expect`: the run first, then the acceptance. */
export function exerciseErrors(
  run: unknown,
  verification: unknown,
  binding: ExerciseBinding,
  expect: ExerciseExpectations,
): Refusal[] {
  const out = isAttributedRun(run) ? attributedRunObservationErrors(run, expect) : runObservationErrors(run, expect);
  if (out.length > 0) return out;
  const r = run as RunObservation;
  const claimed = isObject((verification as VerificationObservation)?.run)
    ? String((verification as VerificationObservation).run.path)
    : "";
  // Without a committed path the run's path is the verification's own claim and the sha256 of the committed bytes is
  // the authority; the judge (productionExerciseEvidence) passes the path of the file it read, so a relabeled run
  // observation is refused there.
  const runPath = binding.runPath ?? claimed;
  return verificationObservationErrors(
    verification,
    { path: runPath, sha256: binding.runSha256, observation: r },
    expect,
  );
}

export interface ProofExerciseRecord {
  schema: string;
  lane: string;
  exercise: { id: string; host: string; performedAtUtc: string; verifiedAtUtc: string };
  subject: {
    designation: string;
    circuitSystem: string;
    circuitVersion: string;
    programVKey: string;
    verifier: ArchiveAnchor["verifier"];
    verifyingKey: { file: string; sha256: string; bytes: number };
  };
  archiveRecord: {
    path: string;
    sha256: string;
    archiveFile: string;
    archiveBytes: number;
    archiveSha256: string;
    members: number;
  };
  installedCircuit: { circuitVersion: string; membersSha256: string; verifiedBy: string };
  host: {
    executableSha256: string;
    executableBytes: number;
    sourceTree: string;
    sourceCommit: string;
    repository: string;
  };
  proofInput: { fixture: string; sha256: string };
  gnark: { repository: string; digest: string; imageRef: string };
  prover: { mode: string; frozenEnv: Record<string, string>; gate: string };
  proof: { vkey: string; selector: string; publicValuesSha256: string; proofBytesSha256: string };
  verification: {
    observation: { path: string; host: string };
    verifier: ArchiveAnchor["verifier"];
    checks: VerificationCheck[];
    acceptance: string;
  };
  performance: {
    wallClockSeconds: number;
    hostSeconds: number;
    rotationDelaySeconds: number;
    withinRotationDelay: boolean;
    rotationDelayFraction: number;
    peakMemory: RunObservation["peakMemory"];
  };
  egress: {
    condition: string;
    enforcement: string;
    probes: { before: number; after: number; targets: string[] };
  };
  derivedFrom: string[];
  establishes: string;
  doesNotEstablish: string;
}

export const EXERCISE_LANE = "SP1-PA3B";
export const PROVE_GATE_COMMAND = "sp1:prove:archive-only";
const VERIFIED_BY = "the archive-only gate: re-hashed against the record before the host started and after it exited";

/** The record `run` and `verification` derive; throws naming every reason when they derive none. */
export function deriveExerciseRecord(
  run: unknown,
  verification: unknown,
  binding: ExerciseBinding,
  expect: ExerciseExpectations,
): ProofExerciseRecord {
  const errors = exerciseErrors(run, verification, binding, expect);
  if (errors.length > 0) {
    throw new Error(
      `the observations derive no proof-exercise record:\n - ${errors.map((e) => `${e.reason}: ${e.detail}`).join("\n - ")}`,
    );
  }
  const r = run as RunObservation;
  const v = verification as VerificationObservation;
  const a = expect.anchor;
  const record = expect.archiveRecord.record;
  const probes = [...r.egress.before, ...r.egress.after].map((p) => `${p.kind}:${p.target}`);
  const derived: ProofExerciseRecord = {
    schema: EXERCISE_RECORD_SCHEMA,
    lane: EXERCISE_LANE,
    exercise: {
      id: `${a.designation}:${binding.runSha256.slice(0, 16)}`,
      host: r.host,
      performedAtUtc: r.timing.startedAtUtc,
      verifiedAtUtc: v.measuredAtUtc,
    },
    subject: {
      designation: a.designation,
      circuitSystem: record.subject.circuitSystem,
      circuitVersion: a.circuitVersion,
      programVKey: a.programVKey,
      verifier: { ...a.verifier },
      verifyingKey: {
        file: record.subject.verifyingKey.file,
        sha256: a.verifyingKey.sha256,
        bytes: a.verifyingKey.bytes,
      },
    },
    archiveRecord: {
      path: expect.archiveRecord.path,
      sha256: expect.archiveRecord.sha256,
      archiveFile: record.archive.file,
      archiveBytes: record.archive.bytes,
      archiveSha256: record.archive.sha256,
      members: record.members.length,
    },
    installedCircuit: {
      circuitVersion: r.installedCircuit.circuitVersion,
      membersSha256: sha256(serializeJson(byPath(record.members))),
      verifiedBy: VERIFIED_BY,
    },
    host: {
      executableSha256: r.hostExecutable.sha256,
      executableBytes: r.hostExecutable.bytes,
      sourceTree: r.source.zkvmHostTree,
      sourceCommit: r.source.commit,
      repository: r.source.repository,
    },
    proofInput: { fixture: PROOF_INPUT_FIXTURE_REL, sha256: r.inputs.sha256 },
    gnark: { repository: r.gnark.repository, digest: r.gnark.digest, imageRef: r.gnark.imageRef },
    prover: { mode: r.prover.mode, frozenEnv: { ...r.prover.frozenEnv }, gate: PROVE_GATE_COMMAND },
    proof: {
      vkey: r.proof.vkey,
      selector: r.proof.selector,
      publicValuesSha256: r.proof.publicValuesSha256,
      proofBytesSha256: r.proof.proofBytesSha256,
    },
    verification: {
      observation: { path: binding.verificationPath, host: v.host },
      verifier: { ...v.verifier },
      checks: v.checks.map((c) => ({ ...c, verdicts: { ...c.verdicts } })),
      acceptance: v.acceptance,
    },
    performance: {
      wallClockSeconds: r.timing.gateSeconds,
      hostSeconds: r.timing.hostSeconds,
      rotationDelaySeconds: ROTATION_DELAY_SECONDS,
      withinRotationDelay: r.timing.gateSeconds <= ROTATION_DELAY_SECONDS,
      rotationDelayFraction: Math.round((r.timing.gateSeconds / ROTATION_DELAY_SECONDS) * 1e6) / 1e6,
      peakMemory: structuredClone(r.peakMemory),
    },
    egress: {
      condition: r.egress.condition,
      enforcement: r.egress.enforcement,
      probes: { before: r.egress.before.length, after: r.egress.after.length, targets: [...new Set(probes)].sort() },
    },
    derivedFrom: [v.run.path, binding.verificationPath],
    establishes:
      "one real Groth16 proof of the designated program was made on this host through the archive-only gate from the committed verified archive, with the digest-pinned gnark image, SP1_PROVER=cpu and network egress refused before and after the run, and the designated verifier (the CREATE2-authenticated v6.1.0 runtime) accepted it and refused its tampered copy; its wall time and peak memory are recorded against the 2-day rotation delay: liveness of the self-hosted path on this hardware, at this time",
    doesNotEstablish:
      "the provenance of the proving: the verifier proves the proof's validity under the designated key, never that it was made through the gate, with SP1_PROVER=cpu, with egress refused, by this host binary, in this time or with this memory; those facts are the operator's observation, bound as far as the repository can bind them (the proof's digests, the run's commit content, the canonical host binary, the committed input, the probes' shape and timing) and otherwise rest on the owner's review of the pull request that commits them; nor that the Groth16 trusted setup behind the key is sound (the verifier accepting a proof is compatibility, never soundness); nor that any other hardware proves within the rotation delay; nor that egress stayed refused between the two probes (an attestation of the enforcement, probed at the edges); nor that the archive, the mirrors or the image remain available; nor production readiness (the implementation receipt's PRODUCTION_SP1_BINDING)",
  };
  return isAttributedRun(run) ? attributedRecordOf(derived, run, expect) : derived;
}

/** Whether `run` claims the v2 form; anything else (a v1 run, or nothing readable) is judged as v1 always was. */
export const isAttributedRun = (run: unknown): run is AttributedRunObservation =>
  isObject(run) && run.schema === RUN_SCHEMA_V2;

/** A record an attributed run derives: the v1 record's facts plus the assurance the observer's evidence supports. */
export type AttributedProofExerciseRecord = ProofExerciseRecord & {
  egress: ProofExerciseRecord["egress"] & { assurance: EgressAssurance };
};

export const ATTRIBUTED_ESTABLISHES =
  "one real Groth16 proof of the designated program was made on this host through the archive-only gate from the committed verified archive, with the digest-pinned gnark image and SP1_PROVER=cpu, and the designated verifier (the CREATE2-authenticated v6.1.0 runtime) accepted it and refused its tampered copy; the operator's capture by the committed root observer (kernel probes on every UDP, raw, ping and packet-socket send, every AF_XDP socket's send and poll, every TCP connect, every netfilter drop and every transmit on a host device through the device layer, from before the first egress probe to after the last) covers the run by its own markers, heartbeats and ring-buffer statistics, attributes every attempt in that window to the process, container or kernel that made it or names it unattributed, counts every send whose destination it cannot read or trust (a packet, raw or AF_XDP socket's), shows no packet past the boundary among the sends whose destination it reads, and reconciles its refused packets with the declared boundary's counters as the observer read them; its wall time and peak memory are recorded against the 2-day rotation delay: liveness of the self-hosted path on this hardware, at this time, with the run's network activity as the operator's observer captured it";
export const ATTRIBUTED_DOES_NOT_ESTABLISH =
  "that the capture is complete or unedited: the raw trace, its facts and its manifest stay with the operator, every digest the repository holds is computed from them, and the reconciliation's counters were read into those same facts, so an operator (or any root process on the host, the proof's own tree among them through the Docker engine the gate needs) able to edit the capture before its normalization could remove an event, alter a packet header or rewrite a counter, or able to switch the probes off for the window, without any committed check noticing; continuous attribution adds what an honest observer saw, on the same operator trust as the edge probes, and is re-checkable only by someone given the raw directory, whose re-normalization must reproduce the committed digest; nor the provenance of the proving beyond what the repository binds (the operator's observation, bound by the proof's digests, the run's commit content, the canonical host binary, the committed input, the observer's configuration and the raw capture's digests); nor a channel outside the observed IP stack (WSL interop, the 9P file system, AF_VSOCK), a packet a TUN or TAP device injects (one root made), or a frame that leaves without the device transmit (PACKET_QDISC_BYPASS, an AF_XDP ring, an XDP program's redirect, netpoll: root, CAP_NET_RAW or CAP_NET_ADMIN in the host's namespace), seen at most as a send of unseen destination; nor where a packet, raw or AF_XDP socket's send went (counted as unseen, never read); nor the requester behind a daemon's attempt (an attempt dockerd or systemd-resolved makes on another process's behalf is the daemon's); nor the soundness of the Groth16 trusted setup behind the key; nor that any other hardware proves within the rotation delay; nor that the archive, the mirrors or the image remain available; nor production readiness (the implementation receipt's PRODUCTION_SP1_BINDING)";

/** The observer expectations of `run` (its probes, gate stamps, commit and host label) under `expect`. */
function observerExpectationsOf(run: AttributedRunObservation, expect: ExerciseExpectations) {
  return {
    observerScriptSha256: expect.scripts.observer ?? null,
    mode: "RUN" as const,
    probes: (["before", "after"] as const).flatMap((phase) =>
      (Array.isArray(run.egress?.[phase]) ? run.egress[phase] : []).map((p) => ({
        phase,
        kind: p.kind,
        target: p.target,
      })),
    ),
    gate: isObject(run.timing)
      ? { startedAtUtc: String(run.timing.startedAtUtc), finishedAtUtc: String(run.timing.finishedAtUtc) }
      : null,
    run: { commit: isObject(run.source) ? String(run.source.commit) : "", host: String(run.host) },
  };
}

function attributedRecordOf(
  derived: ProofExerciseRecord,
  run: AttributedRunObservation,
  expect: ExerciseExpectations,
): AttributedProofExerciseRecord {
  const judged = observerEvidenceErrors(run.egress.observer, observerExpectationsOf(run, expect));
  if (judged.attribution === null || judged.refusals.length > 0)
    throw new Error("the observer's evidence derives no assurance");
  return {
    ...derived,
    schema: EXERCISE_RECORD_SCHEMA_V2,
    lane: ATTRIBUTED_EXERCISE_LANE,
    egress: { ...derived.egress, assurance: assuranceOf(run.egress.observer, judged.attribution) },
    establishes: ATTRIBUTED_ESTABLISHES,
    doesNotEstablish: ATTRIBUTED_DOES_NOT_ESTABLISH,
  };
}

/**
 * The egress assurance an accepted record carries: a v1 record (SP1-PA3B's) was edge-probed only, so it carries
 * EDGE_PROBES_ONLY whatever else is known about its host; nothing measured later is read into it.
 */
export function egressAssuranceOfRecord(record: ProofExerciseRecord): EgressAssurance {
  if (record.schema === EXERCISE_RECORD_SCHEMA) return EDGE_PROBES_ONLY;
  const assurance = (record as AttributedProofExerciseRecord).egress?.assurance;
  if (record.schema !== EXERCISE_RECORD_SCHEMA_V2 || !isObject(assurance))
    throw new Error(`${String(record.schema)} carries no egress assurance`);
  return assurance;
}

// ---------------------------------------------------------------------------------------------------------------
// The committed evidence
// ---------------------------------------------------------------------------------------------------------------

/** Every file under PROOF_EXERCISES_DIR, repository-relative and sorted (as archiveRecordsIn lists records). */
export function exerciseRecordsIn(repoRoot = "."): string[] {
  const dir = resolve(repoRoot, PROOF_EXERCISES_DIR);
  return existsSync(dir)
    ? readdirSync(dir)
        .sort()
        .map((f) => `${PROOF_EXERCISES_DIR}/${f}`)
    : [];
}

/** The names under OBSERVATIONS_DIR that carry the proof-exercise prefix, sorted (none when the directory is absent). */
function exerciseObservationNamesIn(repoRoot: string): string[] {
  let names: string[];
  try {
    names = readdirSync(resolve(repoRoot, OBSERVATIONS_DIR));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  return names.filter((f) => f.startsWith(EXERCISE_OBSERVATION_PREFIX)).sort();
}

/** The committed proof-exercise observations by kind, as their names read (observationSlotOf); anything else under
 * the prefix is `other` (and refused). */
export function exerciseObservationsIn(repoRoot = "."): { run: string[]; verification: string[]; other: string[] } {
  const out = { run: [] as string[], verification: [] as string[], other: [] as string[] };
  for (const name of exerciseObservationNamesIn(repoRoot)) {
    const slot = observationSlotOf(name);
    (slot === null ? out.other : out[slot.kind]).push(`${OBSERVATIONS_DIR}/${name}`);
  }
  return out;
}

const lf = (text: string) => text.replace(/\r\n/g, "\n");
/** sha256 of a committed text file's LF bytes (what git commits and an LF checkout reads); null when absent. */
function fileSha(repoRoot: string, rel: string): string | null {
  const p = resolve(repoRoot, rel);
  return existsSync(p) ? sha256(lf(readFileSync(p, "utf8"))) : null;
}

// ---------------------------------------------------------------------------------------------------------------
// The exercise directory (SP1-PA3D0): history, never ambiguity. One designation's directory holds SP1-PA3B's v1
// record in the v1 slot and, beside it, v2 records each named after its own exercise; every record is judged on its
// own, every observation belongs to exactly one record, and no name, order, time or schema chooses an authority.
// ---------------------------------------------------------------------------------------------------------------

export type ExerciseGeneration = "v1" | "v2";
/** The schemas a generation's files hold: its record, and the run observation the record is derived from. */
export const GENERATION_SCHEMAS: Readonly<Record<ExerciseGeneration, { record: string; run: string }>> = {
  v1: { record: EXERCISE_RECORD_SCHEMA, run: RUN_SCHEMA },
  v2: { record: EXERCISE_RECORD_SCHEMA_V2, run: RUN_SCHEMA_V2 },
};
/**
 * How many records of each generation one designation's directory admits: v1, SP1-PA3B's slot (its single name makes
 * it one); v2, the one attributed exercise SP1-PA3D0 makes room for. Every v2 file already carries its exercise's
 * token, so a second v2 never needs a committed file renamed; but raising this number is not enough: every v2 record
 * is derived with ATTRIBUTED_EXERCISE_LANE, and a committed record is re-derived by the code of the day, so changing
 * that constant (or any v2 tool or text) re-derives the committed v2 differently and refuses the directory. A lane
 * that admits a second v2 first makes the lane a fact of each record.
 */
export const MAX_RECORDS: Readonly<Record<ExerciseGeneration, number>> = { v1: 1, v2: 1 };
const TOKEN = /^[0-9a-f]{16}$/;
/**
 * An exercise's token: the first 16 hex digits of the sha256 of its run observation's committed (LF) bytes, the
 * digest its record's exercise.id already carries (`<designation>:<token>`). A v2 exercise's three files are named
 * after it, so a file's name is a function of the exercise it holds: two names for one exercise cannot both be right.
 */
export const exerciseToken = (runText: string) => sha256(lf(runText)).slice(0, 16);

/** What a name under PROOF_EXERCISES_DIR is for `designation`: its v1 slot, a v2 record of one token, or nothing
 * (null): no other name is a record, whatever it holds. */
export function recordSlotOf(
  name: string,
  designation: string,
): { generation: ExerciseGeneration; token: string | null } | null {
  if (name === `${designation}.json`) return { generation: "v1", token: null };
  const prefix = `${designation}.v2.`;
  const token = name.startsWith(prefix) && name.endsWith(".json") ? name.slice(prefix.length, -".json".length) : "";
  return TOKEN.test(token) ? { generation: "v2", token } : null;
}

const OBSERVATION_NAME = new RegExp(
  `^${EXERCISE_OBSERVATION_PREFIX}(run|verification)-(${HOST_LABEL.source.slice(1, -1)})(?:\\.([0-9a-f]{16}))?\\.raw\\.json$`,
);
/** What a proof-exercise observation's name says: run or verification, the host label, and no token (the v1 slot's
 * names, SP1-PA3B's) or the token of the exercise it belongs to; null for any other name (refused). */
export function observationSlotOf(
  name: string,
): { kind: "run" | "verification"; host: string; token: string | null } | null {
  const m = OBSERVATION_NAME.exec(name);
  return m === null ? null : { kind: m[1] as "run" | "verification", host: m[2], token: m[3] ?? null };
}

/** The committed paths of a v2 exercise whose run observation is `runText`, run and verified on `host`. */
export function attributedExerciseFiles(anchor: ArchiveAnchor, host: string, runText: string) {
  const token = exerciseToken(runText);
  return {
    token,
    run: `${OBSERVATIONS_DIR}/${RUN_OBSERVATION_PREFIX}${host}.${token}.raw.json`,
    verification: `${OBSERVATIONS_DIR}/${VERIFICATION_OBSERVATION_PREFIX}${host}.${token}.raw.json`,
    record: attributedExerciseRecordRel(anchor, token),
  };
}

/** One exercise as the names describe it: its record (if the directory holds one) and its observations. */
export interface ExerciseGroup {
  /** null: the v1 slot (SP1-PA3B's names carry no token); else the token every file of the exercise is named after. */
  token: string | null;
  generation: ExerciseGeneration;
  /** The record's path; null when the directory holds no record of these observations. */
  record: string | null;
  runs: string[];
  verifications: string[];
}

export interface ExerciseDirectory {
  /** Every entry under PROOF_EXERCISES_DIR, repository-relative and sorted (the directory's membership). */
  records: string[];
  /** Every name under OBSERVATIONS_DIR with the proof-exercise prefix, repository-relative and sorted. */
  observations: string[];
  /** The exercises the names describe: the v1 slot first, then by token (never by any file's position or time). */
  groups: ExerciseGroup[];
  /** Every name the contract does not admit, every record short of an observation or with an extra one, every
   * generation over its count. */
  errors: string[];
}

/**
 * The exercise directory of `designation` as the names alone describe it: a pure function of the two listings, which
 * it sorts itself, so no listing order chooses anything. A record is named `<designation>.json` (the v1 slot) or
 * `<designation>.v2.<token>.json`; an observation `proof-exercise-<run|verification>-<host>.raw.json` (the v1 slot's)
 * or `proof-exercise-<run|verification>-<host>.<token>.raw.json`. Every other name is refused, never ignored; each
 * record needs exactly one run and one verification observation of its own; and no generation holds more records than
 * MAX_RECORDS. Observations without a record form a group with `record: null` (unrecordedExerciseErrors refuses it).
 */
export function exerciseDirectoryOf(
  recordNames: readonly string[],
  observationNames: readonly string[],
  designation: string,
): ExerciseDirectory {
  const errors: string[] = [];
  const byToken = new Map<string, ExerciseGroup>();
  const group = (token: string | null): ExerciseGroup => {
    const found = byToken.get(token ?? "");
    if (found !== undefined) return found;
    const created: ExerciseGroup = {
      token,
      generation: token === null ? "v1" : "v2",
      record: null,
      runs: [],
      verifications: [],
    };
    byToken.set(token ?? "", created);
    return created;
  };
  const records = [...recordNames].sort().map((name) => `${PROOF_EXERCISES_DIR}/${name}`);
  for (const rel of records) {
    const slot = recordSlotOf(rel.slice(PROOF_EXERCISES_DIR.length + 1), designation);
    if (slot === null) {
      errors.push(
        `${rel} is no proof-exercise record of ${designation}: ${PROOF_EXERCISES_DIR} admits only ${designation}.json (the v1 record) and ${designation}.v2.<token>.json (a v2 record, named after its exercise)`,
      );
    } else group(slot.token).record = rel;
  }
  const observations = observationNames
    .filter((name) => name.startsWith(EXERCISE_OBSERVATION_PREFIX))
    .sort()
    .map((name) => `${OBSERVATIONS_DIR}/${name}`);
  for (const rel of observations) {
    const slot = observationSlotOf(rel.slice(OBSERVATIONS_DIR.length + 1));
    if (slot === null) {
      errors.push(
        `${OBSERVATIONS_DIR} holds ${rel}, which is no proof-exercise observation (${RUN_OBSERVATION_PREFIX}<host>[.<token>].raw.json or ${VERIFICATION_OBSERVATION_PREFIX}<host>[.<token>].raw.json)`,
      );
    } else (slot.kind === "run" ? group(slot.token).runs : group(slot.token).verifications).push(rel);
  }
  const groups = [...byToken.values()].sort((a, b) => ((a.token ?? "") < (b.token ?? "") ? -1 : 1));
  for (const g of groups) {
    const suffix = g.token === null ? "" : `.${g.token}`;
    if (g.record === null) continue;
    if (g.runs.length !== 1) {
      errors.push(
        `${g.record} needs exactly one run observation (${RUN_OBSERVATION_PREFIX}<host>${suffix}.raw.json); ${OBSERVATIONS_DIR} holds ${g.runs.length}`,
      );
    }
    if (g.verifications.length !== 1) {
      errors.push(
        `${g.record} needs exactly one verification observation (${VERIFICATION_OBSERVATION_PREFIX}<host>${suffix}.raw.json); ${OBSERVATIONS_DIR} holds ${g.verifications.length}`,
      );
    }
  }
  for (const generation of ["v1", "v2"] as const) {
    const held = groups.filter((g) => g.generation === generation && g.record !== null).map((g) => g.record);
    if (held.length > MAX_RECORDS[generation]) {
      errors.push(
        `${PROOF_EXERCISES_DIR} holds ${held.length} ${generation} records (${held.join(", ")}); the contract admits at most ${MAX_RECORDS[generation]} per designation, and a second needs it raised in its own lane, never a record beside it`,
      );
    }
  }
  return { records, observations, groups, errors };
}

/**
 * The exercises `dir` holds observations of and no record of: each refused while the directory holds any record
 * (evidence of an exercise is never left unaccounted); the generator derives exactly such an exercise's record.
 */
export function unrecordedExerciseErrors(dir: ExerciseDirectory): string[] {
  return dir.groups
    .filter((g) => g.record === null)
    .map(
      (g) =>
        `${OBSERVATIONS_DIR} holds ${g.token === null ? "v1-slot observations" : `the observations of exercise ${g.token}`} (${[...g.runs, ...g.verifications].join(", ")}) and no record of them: derive it (npm run sp1:proof-exercise-record) or remove them; evidence of an exercise is never left unaccounted`,
    );
}

export interface ExerciseEvidenceInput {
  anchor: ArchiveAnchor;
  /** The judged archive evidence (scripts/lib/sp1-circuit-acquisition.ts): an exercise stands only on an accepted one. */
  archive: ArchiveEvidence;
}

/**
 * The expectations the committed evidence holds for an exercise of `input.anchor`'s designation: the accepted archive
 * record and the sha256 of its committed bytes, the designation's host source tree, the committed proof-input fixture,
 * the hosts egress must have been refused to (the archive's upstream, the image's registry), the committed tools.
 */
export function exerciseExpectations(repoRoot: string, input: ExerciseEvidenceInput): ExerciseExpectations {
  const record = input.archive.record;
  if (record === null) throw new Error("no accepted archive record: nothing an exercise could have run from");
  const path = productionRecordRel(input.anchor);
  const recordSha = fileSha(repoRoot, path);
  if (recordSha === null) throw new Error(`the archive record ${path} is missing`);
  const d = readDesignations(repoRoot).find((x) => x.id === input.anchor.designation);
  const tree = d?.subject?.zkvmHostTree;
  if (!isText(tree)) throw new Error(`the designation ${input.anchor.designation} names no zkvmHostTree`);
  let upstreamHost: string;
  try {
    upstreamHost = new URL(record.archive.sourceUrl).host.toLowerCase();
  } catch {
    throw new Error(`the archive record's sourceUrl ${String(record.archive.sourceUrl)} names no host`);
  }
  return {
    anchor: input.anchor,
    archiveRecord: { path, sha256: recordSha, record },
    zkvmHostTree: tree,
    proofInputSha256: fileSha(repoRoot, PROOF_INPUT_FIXTURE_REL),
    upstreamHost,
    registryHost: record.gnark.repository.split("/")[0],
    upstreamIps: upstreamAddresses(repoRoot),
    hostBinarySha256: canonicalHostBinarySha256(repoRoot, tree),
    scripts: {
      run: fileSha(repoRoot, RUN_SCRIPT_REL),
      verification: fileSha(repoRoot, VERIFICATION_SCRIPT_REL),
      ...v2Tools(repoRoot),
    },
    repository: REPOSITORY_ID,
  };
}

/** The v2 tools' digests, named only where they are committed (absent is unbound, as null is: a v2 run is refused). */
function v2Tools(repoRoot: string): { attributedRun?: string; observer?: string } {
  const attributedRun = fileSha(repoRoot, ATTRIBUTED_RUN_SCRIPT_REL);
  const observer = fileSha(repoRoot, OBSERVER_SCRIPT_REL);
  return { ...(attributedRun === null ? {} : { attributedRun }), ...(observer === null ? {} : { observer }) };
}

/** The addresses the committed acquisition observations were served from (transfer.remoteIp), unique and sorted. */
export function upstreamAddresses(repoRoot: string): string[] {
  const ips = new Set<string>();
  for (const rel of ACQUISITION_OBSERVATIONS_REL) {
    const p = resolve(repoRoot, rel);
    if (!existsSync(p)) continue;
    try {
      const ip = (JSON.parse(readFileSync(p, "utf8")) as { transfer?: { remoteIp?: unknown } })?.transfer?.remoteIp;
      if (typeof ip === "string" && isIP(ip) !== 0) ips.add(ip);
    } catch {
      // an unreadable observation binds no address; the archive evidence judges it elsewhere
    }
  }
  return [...ips].sort();
}

/**
 * The canonical-build host binary for `zkvmHostTree`: the committed canonical rebuild observation's
 * builds[].hostBinarySha256 whose subject names that tree. One distinct value binds; none, or several, binds nothing.
 */
export function canonicalHostBinarySha256(repoRoot: string, zkvmHostTree: string): string | null {
  const p = resolve(repoRoot, CANONICAL_REBUILD_OBSERVATION_REL);
  if (!existsSync(p)) return null;
  let builds: unknown[];
  try {
    const doc = JSON.parse(readFileSync(p, "utf8")) as { builds?: unknown };
    builds = Array.isArray(doc?.builds) ? doc.builds : [];
  } catch {
    return null;
  }
  const shas = new Set<string>();
  for (const b of builds) {
    const build = b as { subject?: { zkvmHostTree?: unknown }; hostBinarySha256?: unknown };
    if (build?.subject?.zkvmHostTree === zkvmHostTree && HEX64.test(String(build.hostBinarySha256))) {
      shas.add(String(build.hostBinarySha256));
    }
  }
  return shas.size === 1 ? [...shas][0] : null;
}

/** One accepted exercise: its record, derived from its own committed observations and equal to the committed file. */
export interface AcceptedExercise {
  /** The record's path: the v1 slot, or a v2 record named after its token. */
  path: string;
  generation: ExerciseGeneration;
  record: ProofExerciseRecord;
  /** Its run and its verification observation (the record's derivedFrom). */
  observations: [string, string];
}

export interface ExerciseEvidence {
  /** Every entry under PROOF_EXERCISES_DIR, as exerciseRecordsIn lists them (the directory's membership). */
  records: string[];
  /**
   * Every record, each accepted on its own, sorted by path, when the whole directory is accepted; empty whenever
   * anything is refused, so no consumer can take one exercise out of a refused directory. Never a "latest" or a
   * "winner": each exercise is history, and each carries its own assurance (egressAssuranceOfRecord).
   */
  accepted: AcceptedExercise[];
  /** Every proof-exercise observation under OBSERVATIONS_DIR (empty while there is no record: then none is judged). */
  observations: string[];
  errors: string[];
}

/** Whether `rel` is a regular file (not a link) directly in `dir` under `repoRoot`. */
function regularFileIn(repoRoot: string, rel: string, dir: string): boolean {
  const full = resolve(repoRoot, rel);
  try {
    return (
      lstatSync(full).isFile() && dirname(realpathSync(full)) === realpathSync(resolve(repoRoot, ...dir.split("/")))
    );
  } catch {
    return false;
  }
}

const gitOut = (repoRoot: string, args: string[]) =>
  spawnSync("git", ["-C", repoRoot, "--no-optional-locks", ...args], { encoding: "utf8", shell: false });

/**
 * Every reason `commit` (the run's source commit) does not hold what the run claims it ran from: the designated
 * host tree at zkvm/host, the archive record as committed (by the sha256 of its LF bytes), and the measurement tool
 * as committed. An ancestor commit from before the archive record or the tools is thereby refused.
 */
export function commitContentErrors(
  repoRoot: string,
  commit: string,
  expect: ExerciseExpectations,
  schema: string = RUN_SCHEMA,
): string[] {
  const errors: string[] = [];
  const tree = gitOut(repoRoot, ["rev-parse", `${commit}:${HOST_SOURCE_DIR}`]);
  const held = tree.status === 0 ? tree.stdout.trim() : null;
  if (held !== expect.zkvmHostTree) {
    errors.push(
      `the run's source commit ${commit} does not hold the designated host tree ${expect.zkvmHostTree} at ${HOST_SOURCE_DIR} (it holds ${held ?? "no such tree"})`,
    );
  }
  const blobSha = (rel: string): string | null => {
    const r = gitOut(repoRoot, ["show", `${commit}:${rel}`]);
    return r.status === 0 ? sha256(lf(r.stdout)) : null;
  };
  if (blobSha(expect.archiveRecord.path) !== expect.archiveRecord.sha256) {
    errors.push(
      `the run's source commit ${commit} does not hold the archive record ${expect.archiveRecord.path} as committed`,
    );
  }
  if (schema === RUN_SCHEMA_V2) {
    // An attributed run was made by the attributed tool under the root observer: both as committed, at its commit.
    for (const [rel, want] of [
      [ATTRIBUTED_RUN_SCRIPT_REL, expect.scripts.attributedRun ?? null],
      [OBSERVER_SCRIPT_REL, expect.scripts.observer ?? null],
    ] as const) {
      if (want === null || blobSha(rel) !== want)
        errors.push(`the run's source commit ${commit} does not hold ${rel} as committed`);
    }
  } else if (expect.scripts.run === null || blobSha(RUN_SCRIPT_REL) !== expect.scripts.run) {
    errors.push(`the run's source commit ${commit} does not hold ${RUN_SCRIPT_REL} as committed`);
  }
  return errors;
}

/** Every file of `rels` whose committed (index) bytes carry CRLF: the bound sha256 is of LF bytes, so a CRLF commit
 * would read as committed while hashing differently; observations and records are LF. */
export function crlfCommittedErrors(repoRoot: string, rels: readonly string[]): string[] {
  const r = gitOut(repoRoot, ["ls-files", "--eol", "--", ...rels]);
  if (r.status !== 0) return [`git ls-files --eol failed in ${repoRoot}`];
  return r.stdout
    .split(/\r?\n/)
    .filter((line) => /^i\/(crlf|mixed)\b/.test(line))
    .map((line) => `${line.split("\t").pop()} is committed with CRLF line ends; observations and records are LF`);
}

/** Whether `commit` is in `repoRoot`'s history (HEAD or an ancestor of it). */
function inHistory(repoRoot: string, commit: string): boolean {
  if (!HEX40.test(commit)) return false;
  const r = spawnSync("git", ["-C", repoRoot, "--no-optional-locks", "merge-base", "--is-ancestor", commit, "HEAD"], {
    encoding: "utf8",
    shell: false,
  });
  return r.status === 0;
}

/**
 * Every way the exercise directory's history withdrew or edited a record it had committed, or the observation
 * directory's the observation of a committed record (SP1-PA3D0): exercises are history, so a newer one never replaces
 * an older one, and a record stays, byte for byte, in every later commit and in the working tree from the commit that
 * holds it, as do its observations from the first commit that holds the record (scripts/lib/append-only-history.ts,
 * every parent edge of every commit). An attempt whose record was never committed (a rejected proof, a refused
 * capture, a mistyped token) may still be dropped. A history git cannot show (no repository, a shallow clone, no
 * commit) is refused, never read as clean.
 */
export function exerciseHistoryErrors(repoRoot: string, designation: string): string[] {
  const walk = (dirRel: string, include?: (path: string, commit: string) => boolean): string[] => {
    try {
      return directoryHistoryErrors(repoRoot, dirRel, include);
    } catch (error) {
      return [
        `the history of ${dirRel} cannot be read (${String((error as Error).message).split("\n")[0]}): no history is taken as clean`,
      ];
    }
  };
  return [...walk(PROOF_EXERCISES_DIR), ...walk(OBSERVATIONS_DIR, recordedObservationAt(repoRoot, designation))];
}

/**
 * Whether a file of OBSERVATIONS_DIR is, in `commit`'s tree, evidence of a committed record: a proof-exercise
 * observation whose exercise's record (the v1 slot for its untokened names, `<designation>.v2.<token>.json` for its
 * token's) the records directory holds in that tree. Each commit's records are listed once; a listing git cannot give
 * throws, and the history is then refused, never read as holding nothing.
 */
function recordedObservationAt(repoRoot: string, designation: string): (path: string, commit: string) => boolean {
  const listed = new Map<string, Set<string>>();
  const recordsAt = (commit: string): Set<string> => {
    const known = listed.get(commit);
    if (known !== undefined) return known;
    const r = gitOut(repoRoot, ["ls-tree", "--name-only", "-z", commit, "--", `${PROOF_EXERCISES_DIR}/`]);
    if (r.status !== 0) throw new Error(`git ls-tree ${commit} -- ${PROOF_EXERCISES_DIR}/ failed: ${r.stderr.trim()}`);
    const names = new Set(
      r.stdout
        .split("\0")
        .filter(Boolean)
        .map((rel) => rel.slice(PROOF_EXERCISES_DIR.length + 1)),
    );
    listed.set(commit, names);
    return names;
  };
  return (path, commit) => {
    const slot = observationSlotOf(path);
    if (slot === null) return false;
    return recordsAt(commit).has(slot.token === null ? `${designation}.json` : `${designation}.v2.${slot.token}.json`);
  };
}

/**
 * Every way `accepted` holds byte-identical proofs: two records of one proof are one exercise described twice. Only
 * identical bytes are seen: a Groth16 proof re-encoded into other valid bytes (negating its A and B points, say) is not,
 * and an exercise's provenance rests on its observations and the owner's review, as it always has.
 */
function duplicateProofErrors(accepted: readonly AcceptedExercise[]): string[] {
  const byProof = new Map<string, string[]>();
  for (const a of accepted) {
    const sha = a.record.proof.proofBytesSha256;
    byProof.set(sha, [...(byProof.get(sha) ?? []), a.path]);
  }
  return [...byProof]
    .filter(([, paths]) => paths.length > 1)
    .map(
      ([sha, paths]) =>
        `${paths.join(" and ")} hold byte-identical proofs (proofBytesSha256 ${sha}): one proof is one exercise, never two records`,
    );
}

/**
 * One exercise of the directory judged on its own: its record is what its own run and verification observations
 * derive for the accepted archive record, of the generation its name says (the v1 slot holds a v1 run's record, a v2
 * name a v2 run's, with the run's own token), with the run's source commit in this repository's history and holding
 * what the run ran from. Every reason it is not; nothing about any other exercise.
 */
function judgeExercise(
  repoRoot: string,
  g: ExerciseGroup & { record: string },
  expect: ExerciseExpectations,
): { accepted: AcceptedExercise | null; errors: string[] } {
  const errors: string[] = [];
  const [runRel, verificationRel] = [g.runs[0], g.verifications[0]];
  const readJson = (rel: string): { text: string; value: any } => {
    const text = lf(readFileSync(resolve(repoRoot, rel), "utf8"));
    try {
      return { text, value: JSON.parse(text) };
    } catch {
      errors.push(`${rel} is not JSON`);
      return { text, value: null };
    }
  };
  const record = readJson(g.record);
  const run = readJson(runRel);
  const verification = readJson(verificationRel);
  for (const [rel, value] of [
    [runRel, run.value],
    [verificationRel, verification.value],
  ] as const) {
    const named = observationSlotOf(rel.slice(OBSERVATIONS_DIR.length + 1))?.host;
    if (value !== null && value?.host !== named) errors.push(`${rel} claims host ${String(value?.host)}, not ${named}`);
  }
  const want = GENERATION_SCHEMAS[g.generation];
  const slot = g.token === null ? "the v1 slot" : `exercise ${g.token}`;
  if (record.value !== null && record.value?.schema !== want.record) {
    errors.push(
      `${g.record} holds ${String(record.value?.schema)}, but its name is a ${g.generation} record's (${want.record})`,
    );
  }
  if (run.value !== null && run.value?.schema !== want.run) {
    errors.push(`${runRel} holds ${String(run.value?.schema)}, but ${slot} admits only a ${want.run} run`);
  }
  if (g.token !== null && exerciseToken(run.text) !== g.token) {
    errors.push(
      `${runRel} is exercise ${exerciseToken(run.text)} (the first 16 hex digits of its sha256), not ${g.token}: an exercise's files are named after the exercise they hold`,
    );
  }
  if (errors.length > 0) return { accepted: null, errors };
  const binding: ExerciseBinding = {
    runSha256: sha256(run.text),
    verificationPath: verificationRel,
    runPath: runRel,
  };
  const agreement = exerciseErrors(run.value, verification.value, binding, expect);
  if (agreement.length > 0) return { accepted: null, errors: agreement.map((e) => `${e.reason}: ${e.detail}`) };
  const derived = deriveExerciseRecord(run.value, verification.value, binding, expect);
  if (record.text !== serializeJson(derived)) {
    errors.push(
      `${g.record} is not the record the committed observations derive: regenerate it (npm run sp1:proof-exercise-record)`,
    );
  }
  const commit = (run.value as RunObservation).source.commit;
  if (!inHistory(repoRoot, commit)) {
    errors.push(`the run's source commit ${commit} is not in this repository's history`);
  } else {
    errors.push(...commitContentErrors(repoRoot, commit, expect, want.run));
  }
  return {
    accepted:
      errors.length === 0
        ? { path: g.record, generation: g.generation, record: derived, observations: [runRel, verificationRel] }
        : null,
    errors,
  };
}

/**
 * What the repository holds under PROOF_EXERCISES_DIR, judged (SP1-PA3D0): no record (the state before SP1-PA3B: its
 * observations are then not judged), or one or more records, each accepted on its own: the v1 slot and up to
 * MAX_RECORDS v2 records, each byte for byte what its own committed run and verification observations derive for the
 * accepted archive record, of the generation its name says, with its run's source commit in this repository's
 * history, every observation belonging to exactly one record, no proof recorded twice, every file exactly as HEAD
 * commits it, and no record the directory's history committed ever withdrawn or edited. Anything else (a name the
 * contract does not admit, a link, an exercise short of an observation or with an extra one, observations without a
 * record, a hand-edited or uncommitted record, an exercise of another baseline, a record while the archive evidence
 * is not accepted, a withdrawn record) refuses the whole directory with every reason: one good record never stands
 * for a refused one, and the state never depends on which file a listing returns first.
 */
export function productionExerciseEvidence(repoRoot: string, input: ExerciseEvidenceInput): ExerciseEvidence {
  // The history is judged beside everything else, never instead of it: a withdrawn or edited record is reported with
  // whatever else the directory holds, and refuses it even when nothing is left in it.
  const history = exerciseHistoryErrors(repoRoot, input.anchor.designation);
  const records = exerciseRecordsIn(repoRoot);
  const refused = (observations: string[], errors: string[]): ExerciseEvidence => ({
    records,
    accepted: [],
    observations,
    errors: [...history, ...errors],
  });
  if (records.length === 0) return refused([], []);
  const dir = exerciseDirectoryOf(
    records.map((rel) => rel.slice(PROOF_EXERCISES_DIR.length + 1)),
    exerciseObservationNamesIn(repoRoot),
    input.anchor.designation,
  );
  const errors = [...dir.errors, ...unrecordedExerciseErrors(dir)];
  for (const rel of dir.records) {
    if (!regularFileIn(repoRoot, rel, PROOF_EXERCISES_DIR)) {
      errors.push(`${rel} is not a regular file directly in ${PROOF_EXERCISES_DIR}`);
    }
  }
  for (const rel of dir.observations) {
    if (!regularFileIn(repoRoot, rel, OBSERVATIONS_DIR)) {
      errors.push(`${rel} is not a regular file directly in ${OBSERVATIONS_DIR}`);
    }
  }
  const archiveState = archiveEvidenceState(input.archive);
  if (archiveState !== "ACCEPTED" || input.archive.record === null) {
    errors.push(
      `a proof-exercise record exists but the archive evidence is not accepted (${archiveState}${input.archive.errors.length > 0 ? `: ${input.archive.errors.join("; ")}` : ""}): no exercise stands without the archive it ran from`,
    );
  }
  const archivePath = productionRecordRel(input.anchor);
  if (!existsSync(resolve(repoRoot, archivePath))) errors.push(`the archive record ${archivePath} is missing`);
  if (errors.length > 0) return refused(dir.observations, errors);
  let expect: ExerciseExpectations;
  try {
    expect = exerciseExpectations(repoRoot, input);
  } catch (error) {
    return refused(dir.observations, [(error as Error).message]);
  }
  const accepted: AcceptedExercise[] = [];
  for (const g of dir.groups) {
    const judged = judgeExercise(repoRoot, g as ExerciseGroup & { record: string }, expect);
    errors.push(...judged.errors.map((e) => `${g.record}: ${e}`));
    if (judged.accepted !== null) accepted.push(judged.accepted);
  }
  errors.push(...duplicateProofErrors(accepted));
  const files = [...dir.records, ...dir.observations];
  errors.push(...crlfCommittedErrors(repoRoot, files));
  const dirty = uncommittedEvidenceError([...files, archivePath], repoRoot);
  if (dirty !== null) errors.push(`the proof-exercise evidence is not as committed: ${dirty}`);
  return errors.length === 0 && history.length === 0
    ? { records, accepted, observations: dir.observations, errors: [] }
    : refused(dir.observations, errors);
}

/**
 * The record of the one exercise whose observations are committed and whose record is not, and where it goes (the v1
 * slot for the v1 slot's observations, `<designation>.v2.<token>.json` for a v2 exercise's): what
 * `npm run sp1:proof-exercise-record` writes, write-once. Throws naming why there is none: a directory the names
 * refuse, no exercise without its record (a record is never derived twice) or more than one (one at a time), an
 * exercise short of an observation, a generation already at MAX_RECORDS, observations not as committed, a run of
 * another generation than its names say, or files named after another exercise than the run they hold.
 */
export function derivePendingExerciseRecord(
  repoRoot: string,
  input: ExerciseEvidenceInput,
): { rel: string; record: ProofExerciseRecord } {
  const archiveState = archiveEvidenceState(input.archive);
  if (archiveState !== "ACCEPTED") {
    throw new Error(`no accepted archive record (${archiveState}): nothing an exercise could have run from`);
  }
  const records = exerciseRecordsIn(repoRoot);
  const dir = exerciseDirectoryOf(
    records.map((rel) => rel.slice(PROOF_EXERCISES_DIR.length + 1)),
    exerciseObservationNamesIn(repoRoot),
    input.anchor.designation,
  );
  if (dir.errors.length > 0) {
    throw new Error(`the exercise directory is refused, so no record is derived:\n - ${dir.errors.join("\n - ")}`);
  }
  const pending = dir.groups.filter((g) => g.record === null);
  if (pending.length !== 1) {
    throw new Error(
      pending.length === 0
        ? `nothing to derive: every committed exercise in ${OBSERVATIONS_DIR} already has its record (${records.join(", ") || "none"}); a record is never derived twice`
        : `${pending.length} exercises have no record (${pending.map((g) => g.token ?? "the v1 slot").join(", ")}): derive one at a time`,
    );
  }
  const g = pending[0];
  const what = g.token === null ? "the v1 slot" : `exercise ${g.token}`;
  if (g.runs.length !== 1 || g.verifications.length !== 1) {
    throw new Error(
      `${what} needs exactly one run observation and exactly one verification observation (it has ${g.runs.length} run, ${g.verifications.length} verification)`,
    );
  }
  const held = dir.groups.filter((x) => x.generation === g.generation && x.record !== null).length;
  if (held >= MAX_RECORDS[g.generation]) {
    throw new Error(
      `${PROOF_EXERCISES_DIR} already holds ${held} ${g.generation} record(s), the most the contract admits: a second needs it raised in its own lane`,
    );
  }
  const dirty = uncommittedEvidenceError([g.runs[0], g.verifications[0]], repoRoot);
  if (dirty !== null) {
    throw new Error(`the observations are not as committed (the record binds their committed bytes): ${dirty}`);
  }
  const runText = lf(readFileSync(resolve(repoRoot, g.runs[0]), "utf8"));
  const run = JSON.parse(runText);
  const want = GENERATION_SCHEMAS[g.generation].run;
  if (run?.schema !== want) {
    const named =
      run?.schema === RUN_SCHEMA_V2 && g.token === null
        ? `: a v2 exercise's files are named after its token (${attributedExerciseFiles(input.anchor, String(run?.host), runText).run})`
        : "";
    throw new Error(`${g.runs[0]} holds ${String(run?.schema)}, but ${what} admits only a ${want} run${named}`);
  }
  if (g.token !== null && exerciseToken(runText) !== g.token) {
    const right = attributedExerciseFiles(input.anchor, String(run?.host), runText);
    throw new Error(
      `${g.runs[0]} is exercise ${right.token}, not ${g.token}: name its files after it (${right.run}, ${right.verification}, ${right.record})`,
    );
  }
  const verification = JSON.parse(lf(readFileSync(resolve(repoRoot, g.verifications[0]), "utf8")));
  const record = deriveExerciseRecord(
    run,
    verification,
    { runSha256: sha256(runText), verificationPath: g.verifications[0], runPath: g.runs[0] },
    exerciseExpectations(repoRoot, input),
  );
  return {
    rel: g.token === null ? exerciseRecordRel(input.anchor) : attributedExerciseRecordRel(input.anchor, g.token),
    record,
  };
}

/**
 * The state the exercise evidence is in, as the tooling record names it: NO_RECORD (nothing, and no history
 * withdrawn), ACCEPTED (every record accepted, one or many: two exercises are still one state) or REFUSED.
 */
export function exerciseEvidenceState(e: ExerciseEvidence): "NO_RECORD" | "ACCEPTED" | "REFUSED" {
  if (e.records.length === 0) return e.errors.length === 0 ? "NO_RECORD" : "REFUSED";
  return e.errors.length === 0 && e.accepted.length === e.records.length ? "ACCEPTED" : "REFUSED";
}

// ---------------------------------------------------------------------------------------------------------------
// Measurement: what SP1-PA3B's tool records of the run. Pure where it can be (the parsers, the classification),
// injectable where it reads the host (the readers, the probes, the clock), so the suite exercises every branch here
// while the real readers run only on the proving host. Nothing here proves.
// ---------------------------------------------------------------------------------------------------------------

/** VmHWM from /proc/<pid>/status: the process's peak resident set, in bytes; null when absent or not a count. */
export function parseVmHWM(statusText: string): number | null {
  const m = /^VmHWM:\s*(\d+)\s*kB\s*$/m.exec(statusText);
  if (!m) return null;
  const kb = Number(m[1]);
  return Number.isSafeInteger(kb) && kb >= 0 ? kb * 1024 : null;
}

const MEMORY_UNITS: Readonly<Record<string, number>> = {
  B: 1,
  kB: 1e3,
  KB: 1e3,
  MB: 1e6,
  GB: 1e9,
  TB: 1e12,
  KiB: 1024,
  MiB: 1024 ** 2,
  GiB: 1024 ** 3,
  TiB: 1024 ** 4,
};

/** The usage half of docker stats' MemUsage ("1.5GiB / 15.6GiB"), in bytes; null when it does not read. */
export function parseDockerMemUsage(memUsage: string): number | null {
  const m = /^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*\/\s*[0-9]/.exec(memUsage);
  if (!m) return null;
  const unit = MEMORY_UNITS[m[2]];
  return unit === undefined ? null : Math.round(Number(m[1]) * unit);
}

/** The peak RSS of a process on Linux (/proc/<pid>/status VmHWM); null elsewhere or when the process is gone. */
export const linuxHostRssBytes = (pid: number): number | null => {
  try {
    return parseVmHWM(readFileSync(`/proc/${pid}/status`, "utf8"));
  } catch {
    return null;
  }
};

/**
 * The summed memory usage of the running containers whose ancestor is `imageRef`, by `docker ps` then `docker stats
 * --no-stream` (offline, read-only); null when docker does not answer or no such container runs.
 */
export type DockerRunner = (args: string[]) => { error?: Error; status: number | null; stdout: string };
export const dockerRunner =
  (env: NodeJS.ProcessEnv): DockerRunner =>
  (args) =>
    spawnSync("docker", args, { env, encoding: "utf8", shell: false, timeout: 30_000, windowsHide: true });
export const dockerContainerBytes =
  (imageRef: string, env: NodeJS.ProcessEnv, run: DockerRunner = dockerRunner(env)): (() => number | null) =>
  () => {
    const ps = run(["ps", "--no-trunc", "--filter", `ancestor=${imageRef}`, "--format", "{{.ID}}"]);
    if (ps.error || ps.status !== 0) return null;
    const ids = ps.stdout.split(/\r?\n/).filter((l) => /^[0-9a-f]{12,64}$/.test(l));
    if (ids.length === 0) return null;
    const stats = run(["stats", "--no-stream", "--format", "{{.MemUsage}}", ...ids]);
    if (stats.error || stats.status !== 0) return null;
    const figures = stats.stdout
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "")
      .map(parseDockerMemUsage);
    if (figures.length === 0 || figures.some((f) => f === null)) return null;
    return (figures as number[]).reduce((a, b) => a + b, 0);
  };

/** A UTC stamp at second resolution, as every observation records time. */
export const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
/** The gate's own cap on the host's stdout (scripts/lib/sp1-prove-gate.ts MAX_STDOUT), mirrored. */
export const MAX_STDOUT = 64 * 1024 * 1024;

export interface MeasurementDeps {
  intervalMs: number;
  hostRssBytes: (pid: number) => number | null;
  containerBytes: () => number | null;
  clock?: () => string;
  maxStdout?: number;
  /** Told the host's process once it is spawned (SP1-PA3C's attributed tool kills it if the observer fails). */
  onChild?: (child: ChildProcess) => void;
}

export interface RunMeasurement {
  hostStartedAtUtc: string;
  hostFinishedAtUtc: string;
  /** Whole seconds, rounded up, from the monotonic clock. */
  hostSeconds: number;
  hostPeakRssBytes: number | null;
  containerPeakBytes: number | null;
  containerSamples: number;
  intervalMs: number;
}

/**
 * A Spawner for runArchiveOnlyProve with the gate's semantics (no shell, exactly the plan's environment, stdout
 * captured under the gate's cap, stderr through) that also measures the host: its wall time on the monotonic clock,
 * its peak RSS and the containers' sampled memory at `intervalMs`. The host's exit code is returned for the gate to
 * judge, never judged here.
 */
export function measuringSpawner(deps: MeasurementDeps): { spawner: Spawner; measurement(): RunMeasurement } {
  let done: RunMeasurement | null = null;
  const clock = deps.clock ?? utcNow;
  const maxStdout = deps.maxStdout ?? MAX_STDOUT;
  const spawner: Spawner = (plan: ProvePlan) =>
    new Promise<SpawnResult>((resolve, reject) => {
      const startedAt = clock();
      const t0 = process.hrtime.bigint();
      const child = spawn(plan.executable, plan.args, {
        env: plan.env,
        shell: false,
        stdio: ["ignore", "pipe", "inherit"],
        windowsHide: true,
      });
      deps.onChild?.(child);
      let hostPeak: number | null = null;
      let containerPeak: number | null = null;
      let samples = 0;
      const sample = () => {
        if (child.pid !== undefined) {
          const h = deps.hostRssBytes(child.pid);
          if (h !== null && (hostPeak === null || h > hostPeak)) hostPeak = h;
        }
        const c = deps.containerBytes();
        if (c !== null) {
          samples++;
          if (containerPeak === null || c > containerPeak) containerPeak = c;
        }
      };
      const timer = setInterval(sample, deps.intervalMs);
      const chunks: Buffer[] = [];
      let size = 0;
      child.stdout.on("data", (c: Buffer) => {
        size += c.length;
        if (size > maxStdout) child.kill();
        else chunks.push(c);
      });
      child.on("error", (error) => {
        clearInterval(timer);
        reject(error);
      });
      child.on("close", (status, signal) => {
        clearInterval(timer);
        sample();
        const ns = process.hrtime.bigint() - t0;
        done = {
          hostStartedAtUtc: startedAt,
          hostFinishedAtUtc: clock(),
          hostSeconds: Number((ns + 999_999_999n) / 1_000_000_000n),
          hostPeakRssBytes: hostPeak,
          containerPeakBytes: containerPeak,
          containerSamples: samples,
          intervalMs: deps.intervalMs,
        };
        if (size > maxStdout) {
          reject(refuse("PROOF_OUTPUT_REFUSED", "OUTPUT_TOO_LARGE", `more than ${maxStdout} bytes on stdout`));
        } else {
          resolve({ status, signal, stdout: Buffer.concat(chunks).toString("utf8") });
        }
      });
    });
  return {
    spawner,
    measurement: () => {
      if (done === null) throw new Error("no run has been measured");
      return { ...done };
    },
  };
}

export interface ProbeTargets {
  dns: string[];
  tcp: { host: string; port: number }[];
}
export interface ProbeDeps {
  lookup: (host: string) => Promise<void>;
  connect: (host: string, port: number) => Promise<void>;
  clock?: () => string;
}

/** The targets an exercise must probe: the archive's upstream host and the image registry, by name and TCP 443. */
export function egressTargets(
  expect: Pick<ExerciseExpectations, "upstreamHost" | "registryHost" | "upstreamIps">,
): ProbeTargets {
  const hosts = [expect.upstreamHost, expect.registryHost];
  return {
    dns: [...hosts],
    tcp: [...hosts, ...expect.upstreamIps, ...EGRESS_CANARY_IPS].map((host) => ({ host, port: PROBE_PORT })),
  };
}

const errorCode = (error: unknown) => {
  const code = (error as NodeJS.ErrnoException)?.code;
  return typeof code === "string" && code.length > 0 ? code : "UNKNOWN";
};

/** Probes each target once, in order; a refusal keeps its error code (UNKNOWN when there is none). */
export async function probeEgress(targets: ProbeTargets, deps: ProbeDeps): Promise<EgressProbe[]> {
  const clock = deps.clock ?? utcNow;
  const out: EgressProbe[] = [];
  for (const host of targets.dns) {
    const atUtc = clock();
    try {
      await deps.lookup(host);
      out.push({ target: host, kind: "dns", atUtc, outcome: "RESOLVED", error: null });
    } catch (error) {
      out.push({ target: host, kind: "dns", atUtc, outcome: "REFUSED", error: errorCode(error) });
    }
  }
  for (const { host, port } of targets.tcp) {
    const atUtc = clock();
    const target = `${host}:${port}`;
    try {
      await deps.connect(host, port);
      out.push({ target, kind: "tcp", atUtc, outcome: "CONNECTED", error: null });
    } catch (error) {
      out.push({ target, kind: "tcp", atUtc, outcome: "REFUSED", error: errorCode(error) });
    }
  }
  return out;
}

/** The real probes: the system resolver, and a TCP connect that is torn down as soon as it is answered. */
export const networkProbeDeps = (timeoutMs = 10_000): ProbeDeps => ({
  lookup: (host) => lookup(host).then(() => undefined),
  connect: (host, port) =>
    new Promise<void>((resolve, reject) => {
      const socket = connect({ host, port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(Object.assign(new Error(`${host}:${port} timed out`), { code: "ETIMEDOUT" }));
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        socket.destroy();
        resolve();
      });
      socket.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
    }),
});

/** A file's identity as the observations record it: its name, length and sha256. */
export function fileIdentity(path: string): { file: string; bytes: number; sha256: string } {
  const bytes = readFileSync(path);
  return { file: basename(path), bytes: bytes.length, sha256: sha256(bytes) };
}

export const HOST_SOURCE_DIR = "zkvm/host";

/** The checkout the tool runs from: this repository, its HEAD, the host source tree, and whether the tree is dirty. */
export function sourceIdentity(repoRoot: string): {
  repository: string;
  commit: string;
  zkvmHostTree: string;
  dirty: boolean;
} {
  const git = (...args: string[]) =>
    spawnSync("git", ["-C", repoRoot, "--no-optional-locks", ...args], { encoding: "utf8", shell: false });
  if (git("rev-parse", "--is-inside-work-tree").stdout.trim() !== "true") {
    throw new Error(`${repoRoot} is not a git checkout`);
  }
  const commit = git("rev-parse", "HEAD").stdout.trim();
  const tree = git("rev-parse", `HEAD:${HOST_SOURCE_DIR}`);
  if (tree.status !== 0 || !HEX40.test(tree.stdout.trim())) {
    throw new Error(`HEAD:${HOST_SOURCE_DIR} is not a tree of ${repoRoot}`);
  }
  const status = git("status", "--porcelain", "--untracked-files=all");
  if (status.status !== 0) throw new Error(`git status failed in ${repoRoot}`);
  return {
    repository: REPOSITORY_ID,
    commit,
    zkvmHostTree: tree.stdout.trim(),
    dirty: status.stdout.trim() !== "",
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The designated verifier path: the CREATE2-authenticated runtime, asked by eth_call (SP1-PA3B's verification tool
// and the suite that re-executes a committed proof)
// ---------------------------------------------------------------------------------------------------------------

const VERIFY_PROOF = new Interface(["function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes)"]);
const HEX_DATA = /^0x(?:[0-9a-fA-F]{2})+$/;

/** The same tampering SP1-TD1's chain-execution check applies: the last public-value bit flipped. */
function flipLastBit(hex: string): string {
  const b = getBytes(hex);
  if (b.length === 0) throw new Error("no public values to tamper with");
  b[b.length - 1] ^= 1;
  return hexlify(b);
}

/**
 * The designated verifier's initcode as SP1-TD1 recorded it (evidence/zk/sp1-td1/observations/deployment-bytecode
 * .raw.json), accepted only as its keccak is the designation's CREATE2-authenticated initcodeKeccak.
 */
export function authenticatedInitcode(repoRoot: string, designation: ProgramDesignation): string {
  const doc = JSON.parse(readFileSync(resolve(repoRoot, VERIFIER_BYTECODE_REL), "utf8"));
  const initcode: unknown = doc?.deployments?.[designation.verifier.version]?.initcode;
  const c2 = designation.verifier.create2;
  if (
    typeof initcode !== "string" ||
    !HEX_DATA.test(initcode) ||
    c2?.authenticated !== true ||
    keccak256(initcode) !== c2.initcodeKeccak
  ) {
    throw new Error(
      `${VERIFIER_BYTECODE_REL} does not hold ${designation.id}'s verifier ${designation.verifier.version} as designated: not the CREATE2-authenticated initcode`,
    );
  }
  return initcode;
}

/** Deploys `initcode` (no constructor arguments) from `signer` and returns the address it got. */
export async function deployRuntime(signer: Signer, initcode: string): Promise<string> {
  const receipt = await (await signer.sendTransaction({ data: initcode })).wait();
  if (!receipt?.contractAddress) throw new Error("the runtime did not deploy");
  return receipt.contractAddress;
}

export interface VerifyInput {
  address: string;
  programVKey: string;
  publicValues: string;
  proofBytes: string;
  mode: VerificationCheck["mode"];
}

/**
 * Asks the verifier at `address` on `provider`'s chain: the proof as given, then its tampered copy. The code hash at
 * the address is measured and recorded (the validator holds it to the designation's); the verdicts are the chain's
 * answers, never judged here. An RPC that does not answer throws (no verdict is no evidence).
 */
export async function verifyWithRuntime(provider: Provider, input: VerifyInput): Promise<VerificationCheck> {
  const code = await provider.getCode(input.address);
  if (code === "0x") throw new Error(`${input.address} holds no code`);
  const chainId = (await provider.getNetwork()).chainId.toString();
  const block = await provider.getBlockNumber();
  const call = (publicValues: string) => ({
    to: input.address,
    data: VERIFY_PROOF.encodeFunctionData("verifyProof", [input.programVKey, publicValues, input.proofBytes]),
  });
  const real = await verdictOf(provider, call(input.publicValues));
  const tampered = await verdictOf(provider, call(flipLastBit(input.publicValues)));
  return {
    chainId,
    address: input.address,
    runtimeCodeKeccak: keccak256(code),
    mode: input.mode,
    verdicts: { real, tampered },
    block,
  };
}

/** Whether `checks` are the designated verifier's acceptance: every check accepted and refused the tampered copy, at least one of them the authenticated runtime itself. */
export function checksAccept(checks: readonly VerificationCheck[]): boolean {
  return (
    checks.length > 0 &&
    checks.every((c) => c.verdicts.real === "success" && c.verdicts.tampered === `revert ${PROOF_INVALID}`) &&
    checks.some((c) => c.mode === LOCAL_RUNTIME)
  );
}

/** The verification observation for `checks` of `run`'s proof; `acceptance` is computed from the checks, never set. */
export function verificationObservationFor(input: {
  host: string;
  scriptSha256: string;
  run: BoundRun;
  verifier: ArchiveAnchor["verifier"];
  checks: readonly VerificationCheck[];
  clock?: () => string;
}): VerificationObservation {
  const proof = input.run.observation.proof;
  return {
    schema: VERIFICATION_SCHEMA,
    host: input.host,
    measuredAtUtc: (input.clock ?? utcNow)(),
    tool: { script: VERIFICATION_SCRIPT_REL, scriptSha256: input.scriptSha256 },
    run: { path: input.run.path, sha256: input.run.sha256 },
    proof: {
      vkey: proof.vkey,
      publicValuesSha256: proof.publicValuesSha256,
      proofBytesSha256: proof.proofBytesSha256,
    },
    verifier: { ...input.verifier },
    checks: input.checks.map((c) => ({ ...c, verdicts: { ...c.verdicts } })),
    acceptance: checksAccept(input.checks) ? ACCEPTED : REJECTED,
  };
}

/** sha256 of a tool's own LF bytes: how an observation names the script that made it. */
export const scriptSha256Of = (fileUrl: string) => sha256(lf(readFileSync(new URL(fileUrl), "utf8")));

export { serializeJson, type ArchiveEvidence };
