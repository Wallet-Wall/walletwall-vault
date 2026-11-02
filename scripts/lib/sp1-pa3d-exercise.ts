/**
 * SP1-PA3D: one real v2 attributed proof, authorized by the owner, made in the observer environment SP1-PA3C-Q1
 * qualified, independently verified, and bound to its source by a chain of committed records.
 *
 * This library holds the lane's derivations, each a pure function of committed facts (a measurement never grades
 * itself):
 *
 *   - the exercise manifest (evidence/zk/sp1-impl/pa3d-exercise-manifest.json), authored BEFORE the proof: the proof
 *     statement (program, ELF, inputs, expected public values), the circuit and verifier identities, the prover's
 *     implementation and toolchain, the environment and the observer qualification it stands on, the tools the run's
 *     checkout must hold unchanged, the acquisition gate over every artifact the proof needs (nothing may be acquired),
 *     and the operator's authorization marker. Everything but the operator's inputs (source commit, host label,
 *     environment words, start stamp, authorization words) is derived from the checkout, and the validator re-derives
 *     it from those inputs and compares every leaf.
 *
 * No proof, no network, no docker and no kernel are touched here. PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED
 * whatever any record says. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { CANONICAL_REBUILD_OBSERVATION_REL } from "./sp1-canonical-build";
import { productionRecordRel, serializeJson } from "./sp1-circuit-acquisition";
import type { ArchiveAnchor, ArchiveMember, ArchiveRecord } from "./sp1-circuit-archive";
import { committedProductionAnchor } from "./sp1-circuit-tooling";
import { DESIGNATIONS_DIR } from "./sp1-designation";
import { QUALIFICATION_REL, leafDifferences, type ComponentClass } from "./sp1-observer-qualification";
import {
  ATTRIBUTED_RUN_SCRIPT_REL,
  OBSERVATIONS_DIR,
  PROOF_EXERCISES_DIR,
  PROOF_INPUT_FIXTURE_REL,
  VERIFICATION_SCRIPT_REL,
} from "./sp1-proof-exercise";
import { FROZEN_ENV, LOCAL_PROVER } from "./sp1-prove-gate";
import { OBSERVER_SCRIPT_REL } from "../sp1-egress-observer";

export const LANE = "SP1-PA3D";
export const PREVIOUS_LANE = "SP1-PA3C-Q1";
export const NEXT_LANE = "SP1-PA3E";
export const REPOSITORY_ID = "Wallet-Wall/walletwall-vault";
/** Repeated by every tool of this lane: a proof exercise establishes no production binding. */
export const PRODUCTION_SP1_BINDING = "NOT_ESTABLISHED";

export const MANIFEST_SCHEMA = "walletwall.sp1-pa3d-exercise-manifest.v1";
export const MANIFEST_REL = "evidence/zk/sp1-impl/pa3d-exercise-manifest.json";
export const MANIFEST_JSON_SCHEMA_REL = "evidence/zk/schema/sp1-pa3d-exercise-manifest.v1.schema.json";

/** The canonical build's environment log, where the toolchain that built the host binary printed its versions. */
export const TOOLCHAIN_ENV_REL =
  "evidence/zk/sp1-impl/observations/canonical-rebuild-developer-workstation/builds/developer-workstation/host/env.txt";
export const HOST_LOCKFILE_REL = "zkvm/host/Cargo.lock";
export const GUEST_MANIFEST_REL = "zkvm/guest/Cargo.toml";
/** SP1-PA3B's run: the public values the same program commits to on the same inputs (statement reproducibility). */
export const EXPECTED_PUBLIC_VALUES_SOURCE_REL =
  "evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json";

/** The repository files the run executes or reads; the run's checkout must hold each as the authoring checkout does. */
export const RUN_TOOLS: readonly string[] = [
  ATTRIBUTED_RUN_SCRIPT_REL,
  OBSERVER_SCRIPT_REL,
  VERIFICATION_SCRIPT_REL,
  "scripts/sp1-prove-archive-only.ts",
  "scripts/generate-sp1-proof-exercise-record.ts",
  "scripts/lib/sp1-prove-gate.ts",
  "scripts/lib/sp1-proof-exercise.ts",
  "scripts/lib/sp1-egress-attribution.ts",
  "scripts/lib/sp1-circuit-install.ts",
  "scripts/lib/sp1-circuit-acquisition.ts",
  "scripts/lib/sp1-circuit-archive.ts",
  PROOF_INPUT_FIXTURE_REL,
];

/** The owner's words on what this lane may not do, repeated in the manifest beside the authorization. */
export const NOT_AUTHORIZED: readonly string[] = [
  "repeated proving experiments without need",
  "production proving",
  "proof generation against arbitrary external inputs",
  "unrelated circuit acquisition",
  "contract changes",
  "cloud proving spend",
  "third-party hosted proving",
  "publishing private host metadata",
];

export const FINAL_STATES = [
  "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED",
  "PA3D_PROOF_GENERATED_VERIFICATION_BLOCKED",
  "PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE",
  "PA3D_PREPROOF_ENVIRONMENT_REFUSED",
  "PA3D_PROVING_FAILED",
] as const;
export type FinalState = (typeof FINAL_STATES)[number];

/** The classes an artifact may have for the proof to proceed: pinned by the repository or a digest, or a host fact. */
export const ACQUISITION_PASSING_CLASSES: readonly ComponentClass[] = [
  "repository-pinned",
  "digest-pinned",
  "version-pinned",
  "host-dependent",
];

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENVIRONMENT_KIND = /^[a-z0-9][a-z0-9.-]{0,63}$/;

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isText = (x: unknown): x is string => typeof x === "string" && x.length > 0;

// ---------------------------------------------------------------------------------------------------------------
// Parsers of committed text
// ---------------------------------------------------------------------------------------------------------------

/** rustc and cargo as `rustc -vV` / `cargo -vV` print their first line in the canonical build's environment log. */
export function toolchainOf(envText: string): { rustc: string; cargo: string } | null {
  const rustc = /^rustc (\S+ \([0-9a-f]+ \d{4}-\d{2}-\d{2}\))$/m.exec(lf(envText));
  const cargo = /^cargo (\S+ \([0-9a-f]+ \d{4}-\d{2}-\d{2}\))$/m.exec(lf(envText));
  return rustc && cargo ? { rustc: rustc[1], cargo: cargo[1] } : null;
}

/** The sp1-sdk release the host lockfile resolves and the sp1-zkvm release the guest manifest pins (`=` dropped). */
export function sp1VersionsOf(
  hostLockText: string,
  guestManifestText: string,
): { sdk: string | null; zkvm: string | null } {
  const sdk = /^name = "sp1-sdk"\nversion = "([^"\n]+)"/m.exec(lf(hostLockText));
  const zkvm = /^sp1-zkvm\s*=\s*(?:"=?([^"\n]+)"|\{[^}\n]*\bversion\s*=\s*"=?([^"\n]+)")/m.exec(lf(guestManifestText));
  return { sdk: sdk ? sdk[1] : null, zkvm: zkvm ? (zkvm[1] ?? zkvm[2] ?? null) : null };
}

// ---------------------------------------------------------------------------------------------------------------
// The acquisition gate (Phase 2)
// ---------------------------------------------------------------------------------------------------------------

export interface Artifact {
  name: string;
  class: ComponentClass;
  /** What pins it: a digest, a repository path's digest, or how a host fact is recorded. */
  identity: string;
  /** The committed record that pins it, or the observation that records it. */
  pinnedBy: string;
  /** Nothing may be acquired for this proof: every artifact is already here, or is a fact of the host. */
  acquisition: "NONE";
  /** How its identity is checked before (or by) the proof. */
  verifiedBy: string;
}

export interface AcquisitionGate {
  verdict: "PASSED" | "BLOCKED";
  blockers: string[];
}

/**
 * PASSED only when at least one artifact is classified, every one is pinned (repository, digest, version) or a
 * recorded host fact, and none would have to be acquired: a mutable, network-dependent or unknown artifact blocks, as
 * does any acquisition, whatever its class (PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE).
 */
export function acquisitionGateOf(artifacts: readonly Artifact[]): AcquisitionGate {
  const blockers: string[] = [];
  if (artifacts.length === 0) blockers.push("no artifact is classified: nothing is known to be pinned");
  for (const a of artifacts) {
    if (!ACQUISITION_PASSING_CLASSES.includes(a.class)) {
      blockers.push(`${a.name}: class ${a.class} is neither pinned nor a recorded host fact`);
    }
    if (a.acquisition !== "NONE") {
      blockers.push(`${a.name}: acquisition ${String(a.acquisition)} (nothing may be acquired for this proof)`);
    }
  }
  return { verdict: blockers.length === 0 ? "PASSED" : "BLOCKED", blockers };
}

// ---------------------------------------------------------------------------------------------------------------
// The manifest (Phase 1)
// ---------------------------------------------------------------------------------------------------------------

/** What the operator states and nothing derives: the manifest's only inputs, read back from a committed manifest. */
export interface ManifestInputs {
  /** The commit the proof is made from: a clean checkout of it holds every RUN_TOOLS file as this checkout does. */
  sourceCommit: string;
  hostLabel: string;
  environment: { kind: string; description: string };
  startedAtUtc: string;
  authorization: { by: "OWNER"; proofs: 1; words: string; recordedAtUtc: string };
}

export interface Manifest {
  schema: typeof MANIFEST_SCHEMA;
  lane: typeof LANE;
  repository: string;
  productionSp1Binding: string;
  authorization: ManifestInputs["authorization"] & { notAuthorized: string[] };
  startedAtUtc: string;
  source: { commit: string; parents: string[]; version: string };
  statement: {
    text: string;
    designation: string;
    program: string;
    programVKey: string;
    guestElf: { sha256: string; bytes: number };
    zkvmGuestTree: string;
    zkvmHostTree: string;
    inputs: { path: string; bytes: number; sha256: string };
    expectedPublicValues: { hex: string; sha256: string; source: { path: string; sha256: string } };
  };
  circuit: {
    version: string;
    archiveRecord: { path: string; sha256: string };
    archive: { file: string; bytes: number; sha256: string; sourceUrl: string; sourceUrlRole: string };
    members: ArchiveMember[];
    gnark: { repository: string; digest: string; imageRef: string };
    verifier: { version: string; address: string; verifierHash: string; selector: string; runtimeCodeKeccak: string };
  };
  prover: {
    implementation: string;
    mode: string;
    proofSystem: "groth16";
    hostBinary: { file: string; sha256: string; pinnedBy: string };
    sp1: { sdk: string; zkvm: string };
    rust: { rustc: string; cargo: string; source: string };
    buildImage: { reference: string; platform: string };
    frozenEnv: string[];
  };
  environment: {
    hostLabel: string;
    kind: string;
    description: string;
    qualification: {
      lane: string;
      path: string;
      sha256: string;
      state: string;
      qualifiedAtUtc: string;
      observerScriptSha256: string;
    };
  };
  tools: { path: string; sha256: string }[];
  plan: {
    proofs: 1;
    gate: string;
    measurement: string;
    observer: { script: string; mode: "run"; boundary: "COMPLETE_EGRESS_BOUNDARY" };
    outputs: { token: string; runObservation: string; verificationObservation: string; record: string };
    verification: { tool: string; where: string; recordTool: string };
  };
  artifacts: Artifact[];
  acquisitionGate: AcquisitionGate;
  derivedFrom: { path: string; sha256: string }[];
}

const MANIFEST_KEYS: readonly (keyof Manifest)[] = [
  "schema",
  "lane",
  "repository",
  "productionSp1Binding",
  "authorization",
  "startedAtUtc",
  "source",
  "statement",
  "circuit",
  "prover",
  "environment",
  "tools",
  "plan",
  "artifacts",
  "acquisitionGate",
  "derivedFrom",
];

/** The checkout a manifest is derived from or validated against; every read goes through it (tests replace files). */
export interface ManifestContext {
  headCommit: string;
  anchor: ArchiveAnchor;
  /** A file of the checkout by its posix-relative path, or null when it is not there. */
  readFile: (rel: string) => Buffer | null;
  /** The blob at `commit:rel`, or null when that commit holds no such file. */
  blobAt: (commit: string, rel: string) => Buffer | null;
  /** The parents of `commit`, or null when it is not a commit of this repository. */
  parentsOf: (commit: string) => string[] | null;
  isAncestorOfHead: (commit: string) => boolean;
}

const GIT_MAX_BUFFER = 256 * 1024 * 1024;

export function manifestContextFromRepo(repoRoot: string): ManifestContext {
  const git = (args: string[]) =>
    spawnSync("git", ["-C", repoRoot, "--no-optional-locks", ...args], { shell: false, maxBuffer: GIT_MAX_BUFFER });
  const head = git(["rev-parse", "HEAD"]);
  if (head.status !== 0) throw new Error(`${repoRoot} is not a git checkout`);
  return {
    headCommit: head.stdout.toString("utf8").trim(),
    anchor: committedProductionAnchor(repoRoot),
    readFile: (rel) => {
      try {
        return readFileSync(join(repoRoot, ...rel.split("/")));
      } catch {
        return null;
      }
    },
    blobAt: (commit, rel) => {
      if (!HEX40.test(commit)) return null;
      const r = git(["cat-file", "blob", `${commit}:${rel}`]);
      return r.status === 0 ? r.stdout : null;
    },
    parentsOf: (commit) => {
      if (!HEX40.test(commit)) return null;
      const r = git(["rev-list", "--parents", "-n", "1", commit]);
      if (r.status !== 0) return null;
      const [self, ...parents] = r.stdout.toString("utf8").trim().split(/\s+/);
      return self === commit ? parents : null;
    },
    isAncestorOfHead: (commit) =>
      HEX40.test(commit) && git(["merge-base", "--is-ancestor", commit, "HEAD"]).status === 0,
  };
}

/** The operator inputs of a committed manifest, or null when it does not carry them in shape. */
export function manifestInputsOf(value: unknown): ManifestInputs | null {
  if (!isObject(value)) return null;
  const { source, environment, authorization, startedAtUtc } = value;
  if (!isObject(source) || !isObject(environment) || !isObject(authorization)) return null;
  if (typeof source.commit !== "string" || typeof environment.hostLabel !== "string") return null;
  if (typeof environment.kind !== "string" || typeof environment.description !== "string") return null;
  if (typeof startedAtUtc !== "string" || typeof authorization.words !== "string") return null;
  if (typeof authorization.recordedAtUtc !== "string") return null;
  return {
    sourceCommit: source.commit,
    hostLabel: environment.hostLabel,
    environment: { kind: environment.kind, description: environment.description },
    startedAtUtc,
    authorization: {
      by: authorization.by,
      proofs: authorization.proofs,
      words: authorization.words,
      recordedAtUtc: authorization.recordedAtUtc,
    },
  };
}

/** What is wrong with the operator's inputs by their form alone. */
export function inputErrors(inputs: ManifestInputs): string[] {
  const errors: string[] = [];
  if (!HEX40.test(inputs.sourceCommit)) errors.push("SOURCE_COMMIT_FORM: the source commit is a full 40-digit sha");
  if (!HOST_LABEL.test(inputs.hostLabel)) errors.push("HOST_LABEL_INVALID: lowercase letters, digits and hyphens");
  if (!ENVIRONMENT_KIND.test(inputs.environment.kind)) errors.push("ENVIRONMENT_KIND_INVALID");
  if (!isText(inputs.environment.description)) errors.push("ENVIRONMENT_DESCRIPTION_EMPTY");
  if (!UTC.test(inputs.startedAtUtc)) errors.push("STARTED_AT_INVALID: a second-resolution UTC stamp");
  const a = inputs.authorization;
  if (a.by !== "OWNER") errors.push("AUTHORIZATION_BY: only the owner authorizes a proof");
  if (a.proofs !== 1) errors.push("AUTHORIZATION_PROOFS: exactly one proof is authorized");
  if (!isText(a.words)) errors.push("AUTHORIZATION_WORDS_EMPTY: the authorization is quoted, never implied");
  if (!UTC.test(a.recordedAtUtc)) errors.push("AUTHORIZATION_RECORDED_AT_INVALID");
  return errors;
}

/**
 * Derives the manifest from the checkout and the operator's inputs, or throws naming the fact that is missing or
 * wrong: the source commit (unknown, not an ancestor, without a package.json), the observer qualification (not
 * OBSERVER_QUALIFIED_FOR_PA3D for this lane), a run tool the source commit does not hold as this checkout does
 * (TOOL_DRIFT), an unreadable toolchain or SP1 pin, a host binary the canonical rebuild does not bind.
 */
export function manifestFrom(ctx: ManifestContext, inputs: ManifestInputs): Manifest {
  const bad = inputErrors(inputs);
  if (bad.length > 0) throw new Error(bad.join("; "));
  const read = new Map<string, Buffer>();
  const file = (rel: string): Buffer => {
    const b = ctx.readFile(rel);
    if (b === null) throw new Error(`${rel} is missing from the checkout`);
    read.set(rel, b);
    return b;
  };
  const text = (rel: string) => lf(file(rel).toString("utf8"));
  const json = (rel: string): any => {
    try {
      return JSON.parse(text(rel));
    } catch (error) {
      throw new Error(`${rel} is not JSON: ${(error as Error).message}`);
    }
  };

  // The source commit: a commit of this repository the checkout descends from, with its version.
  const parents = ctx.parentsOf(inputs.sourceCommit);
  if (parents === null)
    throw new Error(`SOURCE_COMMIT_UNKNOWN: ${inputs.sourceCommit} is not a commit of this repository`);
  if (!ctx.isAncestorOfHead(inputs.sourceCommit)) {
    throw new Error(`SOURCE_COMMIT_NOT_ANCESTOR: the checkout does not descend from ${inputs.sourceCommit}`);
  }
  const pkgBlob = ctx.blobAt(inputs.sourceCommit, "package.json");
  if (pkgBlob === null) throw new Error("SOURCE_COMMIT_NO_PACKAGE: the source commit holds no package.json");
  const version: unknown = JSON.parse(lf(pkgBlob.toString("utf8"))).version;
  if (!isText(version)) throw new Error("SOURCE_COMMIT_NO_VERSION: the source commit's package.json names no version");

  // The run tools: the source commit holds each exactly as this checkout does.
  const tools = RUN_TOOLS.map((rel) => {
    const here = ctx.readFile(rel);
    if (here === null) throw new Error(`TOOL_DRIFT: ${rel} is missing from the checkout`);
    read.set(rel, here);
    const there = ctx.blobAt(inputs.sourceCommit, rel);
    if (there === null) throw new Error(`TOOL_DRIFT: ${rel} is not in the source commit ${inputs.sourceCommit}`);
    const hereSha = sha256(lf(here.toString("utf8")));
    const thereSha = sha256(lf(there.toString("utf8")));
    if (hereSha !== thereSha) {
      throw new Error(
        `TOOL_DRIFT: ${rel} differs between the checkout (${hereSha}) and the source commit (${thereSha})`,
      );
    }
    return { path: rel, sha256: hereSha };
  });

  // The designation and the archive record: the program, its ELF, the circuit, the verifier.
  const designationRel = `${DESIGNATIONS_DIR}/${ctx.anchor.designation}.json`;
  const d = json(designationRel);
  if (d?.id !== ctx.anchor.designation || d?.programVKey !== ctx.anchor.programVKey) {
    throw new Error(`${designationRel} does not describe the anchor ${ctx.anchor.designation}`);
  }
  for (const [k, v] of [
    ["program", d.program],
    ["elf.sha256", d.elf?.sha256],
    ["subject.zkvmGuestTree", d.subject?.zkvmGuestTree],
    ["subject.zkvmHostTree", d.subject?.zkvmHostTree],
    ["verifier.address", d.verifier?.address],
    ["procedure.image", d.procedure?.image],
    ["procedure.platform", d.procedure?.platform],
  ]) {
    if (!isText(v)) throw new Error(`${designationRel} names no ${k}`);
  }
  if (!Number.isSafeInteger(d.elf?.bytes) || d.elf.bytes <= 0) throw new Error(`${designationRel} names no elf.bytes`);
  const archiveRel = productionRecordRel(ctx.anchor);
  const archive = json(archiveRel) as ArchiveRecord;
  if (archive?.subject?.circuitVersion !== ctx.anchor.circuitVersion || !Array.isArray(archive.members)) {
    throw new Error(`${archiveRel} is not the archive record of ${ctx.anchor.circuitVersion}`);
  }
  const verifierHash = ctx.anchor.verifier.verifierHash;

  // The expected public values: what the same program committed to on the same inputs in SP1-PA3B's run.
  const v1 = json(EXPECTED_PUBLIC_VALUES_SOURCE_REL);
  const pvHex: unknown = v1?.proof?.publicValues;
  if (typeof pvHex !== "string" || !/^0x(?:[0-9a-f]{2})+$/.test(pvHex)) {
    throw new Error(`${EXPECTED_PUBLIC_VALUES_SOURCE_REL} holds no public values`);
  }
  const inputsBytes = Buffer.from(text(PROOF_INPUT_FIXTURE_REL));

  // The observer qualification: this lane runs only in the qualified environment.
  const q = json(QUALIFICATION_REL);
  if (q?.state !== "OBSERVER_QUALIFIED_FOR_PA3D" || q?.next?.lane !== LANE || q?.lane !== PREVIOUS_LANE) {
    throw new Error(
      `OBSERVER_NOT_QUALIFIED: ${QUALIFICATION_REL} is ${String(q?.state)} for ${String(q?.next?.lane)}; this lane needs OBSERVER_QUALIFIED_FOR_PA3D for ${LANE}`,
    );
  }
  if (!UTC.test(String(q.qualifiedAtUtc)) || !HEX64.test(String(q.source?.observerScriptSha256))) {
    throw new Error(`${QUALIFICATION_REL} names no qualification stamp or observer digest`);
  }

  // The prover: the canonical host binary, the SP1 release, the toolchain that built it.
  const toolchain = toolchainOf(text(TOOLCHAIN_ENV_REL));
  if (toolchain === null)
    throw new Error(`TOOLCHAIN_UNREADABLE: ${TOOLCHAIN_ENV_REL} prints no rustc and cargo versions`);
  const sp1 = sp1VersionsOf(text(HOST_LOCKFILE_REL), text(GUEST_MANIFEST_REL));
  if (sp1.sdk === null || sp1.zkvm === null) throw new Error("SP1_PIN_UNREADABLE: no sp1-sdk or sp1-zkvm pin");
  const hostBinarySha256 = canonicalHostBinaryOf(json(CANONICAL_REBUILD_OBSERVATION_REL), d.subject.zkvmHostTree);
  if (hostBinarySha256 === null) {
    throw new Error(
      `HOST_BINARY_UNBOUND: ${CANONICAL_REBUILD_OBSERVATION_REL} binds no one host binary to ${d.subject.zkvmHostTree}`,
    );
  }

  const pvSha = sha256(Buffer.from(pvHex.slice(2), "hex"));
  const inputsIdentity = { path: PROOF_INPUT_FIXTURE_REL, bytes: inputsBytes.length, sha256: sha256(inputsBytes) };
  const statement: Manifest["statement"] = {
    text:
      `The SP1 guest program ${d.program} (ELF sha256 ${d.elf.sha256}, ${d.elf.bytes} bytes; guest tree ${d.subject.zkvmGuestTree}), ` +
      `executed by the canonical-build host binary (sha256 ${hostBinarySha256}; host tree ${d.subject.zkvmHostTree}) on the committed ` +
      `input fixture ${PROOF_INPUT_FIXTURE_REL} (sha256 ${inputsIdentity.sha256}), commits to the public values whose sha256 is ${pvSha} ` +
      `(the values SP1-PA3B's run recorded for the same program and inputs). One Groth16 proof of that execution, made by the local ` +
      `${LOCAL_PROVER} prover from the archive-only circuit ${ctx.anchor.circuitVersion} (archive sha256 ${archive.archive.sha256}), ` +
      `is to verify under PROGRAM_VKEY ${ctx.anchor.programVKey} on the designated verifier ${ctx.anchor.verifier.version} ` +
      `(verifierHash ${verifierHash}). It is an exercise of the self-hosted path and establishes no production binding: ` +
      `PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING}.`,
    designation: d.id,
    program: d.program,
    programVKey: d.programVKey,
    guestElf: { sha256: d.elf.sha256, bytes: d.elf.bytes },
    zkvmGuestTree: d.subject.zkvmGuestTree,
    zkvmHostTree: d.subject.zkvmHostTree,
    inputs: inputsIdentity,
    expectedPublicValues: {
      hex: pvHex,
      sha256: pvSha,
      source: { path: EXPECTED_PUBLIC_VALUES_SOURCE_REL, sha256: sha256(text(EXPECTED_PUBLIC_VALUES_SOURCE_REL)) },
    },
  };
  const circuit: Manifest["circuit"] = {
    version: ctx.anchor.circuitVersion,
    archiveRecord: { path: archiveRel, sha256: sha256(text(archiveRel)) },
    archive: {
      file: archive.archive.file,
      bytes: archive.archive.bytes,
      sha256: archive.archive.sha256,
      sourceUrl: archive.archive.sourceUrl,
      sourceUrlRole: archive.archive.sourceUrlRole,
    },
    members: archive.members.map((m) => ({ path: m.path, bytes: m.bytes, sha256: m.sha256 })),
    gnark: {
      repository: archive.gnark.repository,
      digest: archive.gnark.digest,
      imageRef: `${archive.gnark.repository}@${archive.gnark.digest}`,
    },
    verifier: {
      version: ctx.anchor.verifier.version,
      address: d.verifier.address,
      verifierHash,
      selector: verifierHash.slice(0, 10),
      runtimeCodeKeccak: ctx.anchor.verifier.runtimeCodeKeccak,
    },
  };
  const prover: Manifest["prover"] = {
    implementation:
      "zkvm/host (the sp1-sdk blocking client, Groth16 through the pinned gnark image), run as the canonical-build host binary mldsa65-host under the archive-only prove gate",
    mode: LOCAL_PROVER,
    proofSystem: "groth16",
    hostBinary: { file: "mldsa65-host", sha256: hostBinarySha256, pinnedBy: CANONICAL_REBUILD_OBSERVATION_REL },
    sp1: { sdk: sp1.sdk, zkvm: sp1.zkvm },
    rust: { ...toolchain, source: TOOLCHAIN_ENV_REL },
    buildImage: { reference: d.procedure.image, platform: d.procedure.platform },
    frozenEnv: [...FROZEN_ENV],
  };
  const qualificationText = text(QUALIFICATION_REL);
  const environment: Manifest["environment"] = {
    hostLabel: inputs.hostLabel,
    kind: inputs.environment.kind,
    description: inputs.environment.description,
    qualification: {
      lane: PREVIOUS_LANE,
      path: QUALIFICATION_REL,
      sha256: sha256(qualificationText),
      state: q.state,
      qualifiedAtUtc: q.qualifiedAtUtc,
      observerScriptSha256: q.source.observerScriptSha256,
    },
  };
  const plan: Manifest["plan"] = {
    proofs: 1,
    gate: "sp1:prove:archive-only",
    measurement: ATTRIBUTED_RUN_SCRIPT_REL,
    observer: { script: OBSERVER_SCRIPT_REL, mode: "run", boundary: "COMPLETE_EGRESS_BOUNDARY" },
    outputs: {
      token: "the first 16 hexadecimal digits of the sha256 of the run observation's committed (LF) bytes",
      runObservation: `${OBSERVATIONS_DIR}/proof-exercise-run-${inputs.hostLabel}.<token>.raw.json`,
      verificationObservation: `${OBSERVATIONS_DIR}/proof-exercise-verification-${inputs.hostLabel}.<token>.raw.json`,
      record: `${PROOF_EXERCISES_DIR}/${ctx.anchor.designation}.v2.<token>.json`,
    },
    verification: {
      tool: VERIFICATION_SCRIPT_REL,
      where:
        "the proving host, from a clean checkout at the commit that holds the committed run observation, after the egress boundary is removed",
      recordTool: "scripts/generate-sp1-proof-exercise-record.ts",
    },
  };
  const artifacts = artifactsOf({ statement, circuit, prover, environment, tools });
  const derivedFrom = [...read.keys()]
    .sort()
    .map((path) => ({ path, sha256: sha256(lf((read.get(path) as Buffer).toString("utf8"))) }));
  return {
    schema: MANIFEST_SCHEMA,
    lane: LANE,
    repository: REPOSITORY_ID,
    productionSp1Binding: PRODUCTION_SP1_BINDING,
    authorization: { ...inputs.authorization, notAuthorized: [...NOT_AUTHORIZED] },
    startedAtUtc: inputs.startedAtUtc,
    source: { commit: inputs.sourceCommit, parents, version },
    statement,
    circuit,
    prover,
    environment,
    tools,
    plan,
    artifacts,
    acquisitionGate: acquisitionGateOf(artifacts),
    derivedFrom,
  };
}

/** The canonical rebuild's one host binary for `zkvmHostTree` (as scripts/lib/sp1-proof-exercise.ts binds it). */
function canonicalHostBinaryOf(observation: any, zkvmHostTree: string): string | null {
  const builds: unknown[] = Array.isArray(observation?.builds) ? observation.builds : [];
  const shas = new Set<string>();
  for (const b of builds as { subject?: { zkvmHostTree?: unknown }; hostBinarySha256?: unknown }[]) {
    if (b?.subject?.zkvmHostTree === zkvmHostTree && HEX64.test(String(b.hostBinarySha256))) {
      shas.add(String(b.hostBinarySha256));
    }
  }
  return shas.size === 1 ? [...shas][0] : null;
}

/** Every artifact the proof needs, classified; nothing is acquired for it. */
function artifactsOf(m: Pick<Manifest, "statement" | "circuit" | "prover" | "environment" | "tools">): Artifact[] {
  const pinned = (name: string, path: string, sha: string, verifiedBy: string): Artifact => ({
    name,
    class: "repository-pinned",
    identity: `sha256:${sha}`,
    pinnedBy: path,
    acquisition: "NONE",
    verifiedBy,
  });
  const hostFact = (name: string, verifiedBy: string): Artifact => ({
    name,
    class: "host-dependent",
    identity: "a fact of the proving host, recorded, not pinned",
    pinnedBy: "the run observation's platform lines and the pre-proof attestation",
    acquisition: "NONE",
    verifiedBy,
  });
  return [
    {
      name: `guest ELF (${m.statement.program}), embedded in the host binary`,
      class: "digest-pinned",
      identity: `sha256:${m.statement.guestElf.sha256}`,
      pinnedBy: `${DESIGNATIONS_DIR}/${m.statement.designation}.json`,
      acquisition: "NONE",
      verifiedBy:
        "the designation's elf.sha256 equals the canonical rebuild's; the host binary that embeds it is hashed before the proof and recorded by the run",
    },
    {
      name: `host binary ${m.prover.hostBinary.file} (canonical build)`,
      class: "digest-pinned",
      identity: `sha256:${m.prover.hostBinary.sha256}`,
      pinnedBy: m.prover.hostBinary.pinnedBy,
      acquisition: "NONE",
      verifiedBy:
        "the pre-proof attestation hashes the operator-local copy against this digest; the run observation records hostExecutable.sha256 and the record validator binds it to the canonical rebuild",
    },
    {
      name: `Groth16 circuit ${m.circuit.version} (${m.circuit.members.length} members, installed archive-only)`,
      class: "digest-pinned",
      identity: `archive sha256:${m.circuit.archive.sha256}`,
      pinnedBy: m.circuit.archiveRecord.path,
      acquisition: "NONE",
      verifiedBy:
        "the prove gate verifies every installed member's bytes against the archive record before and after the proof and refuses any other entry under the circuit root",
    },
    {
      name: `gnark prover image ${m.circuit.gnark.repository}`,
      class: "digest-pinned",
      identity: m.circuit.gnark.digest,
      pinnedBy: m.circuit.archiveRecord.path,
      acquisition: "NONE",
      verifiedBy:
        "SP1_GNARK_IMAGE is frozen to the digest reference; the image is present locally before the proof (docker image inspect) and no pull can succeed under the egress boundary",
    },
    {
      name: `SP1 build image (built the host binary)`,
      class: "digest-pinned",
      identity: m.prover.buildImage.reference,
      pinnedBy: `${DESIGNATIONS_DIR}/${m.statement.designation}.json`,
      acquisition: "NONE",
      verifiedBy: "not used by the proof; it is the provenance of the host binary (the canonical rebuild observation)",
    },
    pinned(
      "proof inputs fixture",
      m.statement.inputs.path,
      m.statement.inputs.sha256,
      "the run observation records inputs.sha256; the record validator binds it to the committed fixture",
    ),
    ...m.tools.map((t) =>
      pinned(
        `run tool ${t.path}`,
        t.path,
        t.sha256,
        "held byte-identical by the source commit and this checkout (TOOL_DRIFT otherwise); the run observation records the tool digests it ran",
      ),
    ),
    pinned(
      "observer qualification record",
      m.environment.qualification.path,
      m.environment.qualification.sha256,
      "OBSERVER_QUALIFIED_FOR_PA3D for this lane, re-derived by its own validator before the proof",
    ),
    pinned(
      "archive record",
      m.circuit.archiveRecord.path,
      m.circuit.archiveRecord.sha256,
      "the run observation records archiveRecord.sha256; the record validator binds it to the committed record",
    ),
    hostFact(
      "Linux kernel (WSL2 virtual machine)",
      "recorded (release, boot id) by the pre-proof attestation and the run observation; the egress observer's kprobes are attached to it",
    ),
    hostFact(
      "Docker Engine (the distribution's own, unix socket)",
      "recorded (version, endpoint, context) by the pre-proof attestation and the run observation; DOCKER_CONTEXT is frozen",
    ),
    hostFact("node runtime", "recorded (version) by the pre-proof attestation and the run observation"),
    hostFact(
      "nftables (the complete egress boundary)",
      "the rules text and counters are recorded by the observer's raw evidence; the boundary is derived from the rules, not asserted",
    ),
  ];
}

export const serializeManifest = (m: Manifest) => serializeJson(m);

/**
 * What is wrong with a committed manifest: its shape, its constants, its operator inputs by form, and every leaf that
 * differs from what the checkout derives from those inputs now (TOOL_DRIFT, a changed qualification, a changed record
 * all surface here, since the derivation fails or differs).
 */
export function manifestErrors(value: unknown, ctx: ManifestContext): string[] {
  if (!isObject(value)) return ["NOT_AN_OBJECT: a manifest is a JSON object"];
  const errors: string[] = [];
  const keys = new Set(Object.keys(value));
  for (const k of MANIFEST_KEYS) if (!keys.has(k)) errors.push(`MISSING_FIELD ${k}`);
  for (const k of keys) if (!(MANIFEST_KEYS as readonly string[]).includes(k)) errors.push(`UNKNOWN_FIELD ${k}`);
  if (value.schema !== MANIFEST_SCHEMA) errors.push(`SCHEMA: ${String(value.schema)} is not ${MANIFEST_SCHEMA}`);
  if (value.lane !== LANE) errors.push(`LANE: ${String(value.lane)} is not ${LANE}`);
  if (value.repository !== REPOSITORY_ID)
    errors.push(`REPOSITORY: ${String(value.repository)} is not ${REPOSITORY_ID}`);
  if (value.productionSp1Binding !== PRODUCTION_SP1_BINDING) {
    errors.push(`PRODUCTION_SP1_BINDING: ${String(value.productionSp1Binding)} is not ${PRODUCTION_SP1_BINDING}`);
  }
  const inputs = manifestInputsOf(value);
  if (inputs === null)
    return [...errors, "INPUTS_UNREADABLE: the manifest does not carry its operator inputs in shape"];
  errors.push(...inputErrors(inputs));
  if (
    errors.some(
      (e) =>
        e.startsWith("SOURCE_COMMIT_FORM") ||
        e.startsWith("AUTHORIZATION") ||
        e.startsWith("STARTED_AT") ||
        e.startsWith("HOST_LABEL") ||
        e.startsWith("ENVIRONMENT"),
    )
  ) {
    return errors;
  }
  let derived: Manifest;
  try {
    derived = manifestFrom(ctx, inputs);
  } catch (error) {
    return [...errors, `DERIVATION_FAILED: ${(error as Error).message}`];
  }
  for (const d of leafDifferences(value, derived)) {
    errors.push(`LEAF_DIFFERS ${d.path}: committed ${JSON.stringify(d.a)}, derived ${JSON.stringify(d.b)}`);
  }
  if (derived.acquisitionGate.verdict !== "PASSED") {
    errors.push(`ACQUISITION_GATE_BLOCKED: ${derived.acquisitionGate.blockers.join("; ")}`);
  }
  return errors;
}
