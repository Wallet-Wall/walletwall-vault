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
 * Five facts, kept apart: artifact identity (the archive record, SP1-PA2B/C), proving execution (the run), verifier
 * acceptance (the verification), performance (wall time and memory against the 2-day rotation delay) and production
 * readiness (the implementation receipt's, never derived here). SELF_HOSTED_PATH_EXERCISED needs the first three and
 * records the fourth; it is liveness, never soundness, and never production readiness.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { posix, resolve } from "node:path";

import { PROOF_INVALID } from "./sp1-chain-execution";
import { serializeJson, type ArchiveEvidence } from "./sp1-circuit-acquisition";
import { type ArchiveAnchor, type ArchiveMember, type ArchiveRecord, type Refusal } from "./sp1-circuit-archive";
import {
  DOCKER_CONTEXT_FROZEN,
  FROZEN_ENV,
  LOCAL_PROVER,
  PASS_THROUGH_ENV,
  REFUSED_ENV,
  REFUSED_ENV_PREFIX,
} from "./sp1-prove-gate";

export const PROOF_EXERCISES_DIR = "evidence/zk/sp1-impl/proof-exercises";
export const EXERCISE_RECORD_SCHEMA = "walletwall.sp1-proof-exercise.v1";
export const RUN_SCHEMA = "walletwall.sp1-proof-exercise-run.v1";
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
/** The errors a refused probe may end with: unreachable, rejected, timed out, or a name that does not resolve. */
export const EGRESS_REFUSAL_CODES: readonly string[] = [
  "ENETUNREACH",
  "EHOSTUNREACH",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EACCES",
  "EPERM",
  "EAI_AGAIN",
  "ENOTFOUND",
  "EAI_FAIL",
  "EAI_NONAME",
];
export const PROBE_PORT = 443;
export const LOCAL_RUNTIME = "AUTHENTICATED_RUNTIME_LOCAL";
export const DEPLOYED_RUNTIME = "DEPLOYED";
export const ACCEPTED = "ACCEPTED";
export const REJECTED = "REJECTED";
/** The record's path for `anchor`'s designation: one file, named after the designation. */
export const exerciseRecordRel = (anchor: ArchiveAnchor) => `${PROOF_EXERCISES_DIR}/${anchor.designation}.json`;

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
  egress: { enforcement: string; before: EgressProbe[]; after: EgressProbe[]; condition: typeof EGRESS_DISABLED };
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
  /** sha256 of the committed tools' LF bytes (null when a tool is absent: then nothing binds). */
  scripts: { run: string | null; verification: string | null };
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
export function requiredProbeTargets(expect: Pick<ExerciseExpectations, "upstreamHost" | "registryHost">): string[] {
  return [expect.upstreamHost, expect.registryHost].flatMap((h) => [`dns:${h}`, `tcp:${h}:${PROBE_PORT}`]).sort();
}

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
    if (p.outcome !== "REFUSED" || !EGRESS_REFUSAL_CODES.includes(String(p.error))) {
      no(
        "EGRESS_NOT_DISABLED",
        `${where}[${i}] ${p.kind} ${p.target}: ${String(p.outcome)} (${String(p.error)}); egress was not refused`,
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
      for (const b of before ?? [])
        if (!(seconds(b.atUtc) <= s))
          no("EGRESS_NOT_DISABLED", `${where}: a "before" probe was taken after the run began`);
      for (const a of after ?? [])
        if (!(seconds(a.atUtc) >= f))
          no("EGRESS_NOT_DISABLED", `${where}: an "after" probe was taken before the run ended`);
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

export { serializeJson, type ArchiveEvidence };
