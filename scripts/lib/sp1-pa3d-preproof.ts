/**
 * SP1-PA3D, Phase 3: the pre-proof environment attestation. On the proving host, before the one authorized proof,
 * scripts/sp1-pa3d-preproof.ts records FACTS (the committed manifest's validity and digest, the lane checkout and the
 * proving checkout, the installed circuit as the gate's own check sees it, the host binary, the gnark image's local
 * digests, the observer qualification re-derived on that host, the platform) and the VERDICT is a pure function of
 * those facts and the manifest: PA3D_PREPROOF_ENVIRONMENT_VALID, or PA3D_PREPROOF_ENVIRONMENT_REFUSED with every
 * refusal named. No proof is made after a refusal. The validator recomputes the verdict from the recorded facts and
 * the committed manifest (a measurement never grades itself); it cannot re-check the host, only that the host's
 * recorded facts carry the verdict they say. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";

import { serializeJson } from "./sp1-circuit-acquisition";
import type { ArchiveMember } from "./sp1-circuit-archive";
import { LANE, MANIFEST_REL, manifestErrors, type Manifest, type ManifestContext } from "./sp1-pa3d-exercise";
import { OBSERVATIONS_DIR } from "./sp1-proof-exercise";

export const PREPROOF_SCHEMA = "walletwall.sp1-pa3d-preproof-attestation.v1";
export const PREPROOF_OBSERVATION_PREFIX = "pa3d-preproof-";
export const preproofObservationRel = (host: string) =>
  `${OBSERVATIONS_DIR}/${PREPROOF_OBSERVATION_PREFIX}${host}.raw.json`;
/** SP1-PA3B's run peaked at ~22 GiB in the host process and ~18 GiB in the gnark containers: the host needs the room. */
export const MIN_RAM_KIB = 16 * 1024 * 1024;
export const MIN_RAM_PLUS_SWAP_KIB = 40 * 1024 * 1024;
export const PREPROOF_VERDICTS = ["PA3D_PREPROOF_ENVIRONMENT_VALID", "PA3D_PREPROOF_ENVIRONMENT_REFUSED"] as const;
export type PreproofVerdict = (typeof PREPROOF_VERDICTS)[number];

const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const byPath = <T extends { path: string }>(xs: readonly T[]) => [...xs].sort((a, b) => (a.path < b.path ? -1 : 1));
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export interface PreproofFacts {
  schema: typeof PREPROOF_SCHEMA;
  lane: typeof LANE;
  host: string;
  measuredAtUtc: string;
  /** The committed manifest as the lane checkout holds it, validated there. */
  manifest: { path: string; sha256: string; errors: string[] };
  /** The checkout the tool runs from (it holds the manifest). */
  laneCheckout: { commit: string; dirty: boolean };
  /** The checkout the proof runs from: a clean checkout of the manifest's source commit holding the run tools. */
  provingCheckout: { path: string; commit: string; dirty: boolean; tools: { path: string; sha256: string | null }[] };
  /** The installed circuit as scripts/lib/sp1-circuit-install.ts verifies it (the gate's own check), or its refusal. */
  circuit: { root: string; members: ArchiveMember[] | null; error: string | null };
  hostBinary: { path: string; bytes: number | null; sha256: string | null };
  gnark: { imageRef: string; localRepoDigests: string[] | null; error: string | null };
  /** The observer qualification record re-derived on this host by its own validator. */
  qualification: { path: string; sha256: string; errors: string[] };
  platform: {
    os: string;
    kernel: string;
    machine: string;
    bootId: string;
    distro: string;
    memTotalKiB: number;
    swapTotalKiB: number;
    node: string;
    docker: string | null;
    user: string;
    uid: number;
  };
}

export type PreproofObservation = PreproofFacts & { verdict: PreproofVerdict; refusals: string[] };

const OBSERVATION_KEYS: readonly (keyof PreproofObservation)[] = [
  "schema",
  "lane",
  "host",
  "measuredAtUtc",
  "manifest",
  "laneCheckout",
  "provingCheckout",
  "circuit",
  "hostBinary",
  "gnark",
  "qualification",
  "platform",
  "verdict",
  "refusals",
];

/** What the committed manifest expects of the proving host. */
export interface PreproofExpectations {
  manifestSha256: string;
  hostLabel: string;
  sourceCommit: string;
  tools: { path: string; sha256: string }[];
  members: ArchiveMember[];
  hostBinarySha256: string;
  gnarkImageRef: string;
  qualificationSha256: string;
}

export function preproofExpectationsOf(manifest: Manifest, manifestText: string): PreproofExpectations {
  return {
    manifestSha256: sha256(manifestText.replace(/\r\n/g, "\n")),
    hostLabel: manifest.environment.hostLabel,
    sourceCommit: manifest.source.commit,
    tools: manifest.tools.map((t) => ({ path: t.path, sha256: t.sha256 })),
    members: manifest.circuit.members.map((m) => ({ path: m.path, bytes: m.bytes, sha256: m.sha256 })),
    hostBinarySha256: manifest.prover.hostBinary.sha256,
    gnarkImageRef: manifest.circuit.gnark.imageRef,
    qualificationSha256: manifest.environment.qualification.sha256,
  };
}

/** The verdict the facts carry against the manifest's expectations: every refusal, never only the first. */
export function preproofVerdictOf(
  facts: PreproofFacts,
  expected: PreproofExpectations,
): { verdict: PreproofVerdict; refusals: string[] } {
  const r: string[] = [];
  if (facts.manifest.errors.length > 0) r.push(`MANIFEST_INVALID: ${facts.manifest.errors.join("; ")}`);
  if (facts.manifest.sha256 !== expected.manifestSha256) {
    r.push(
      `MANIFEST_DIFFERS: the host read ${facts.manifest.sha256}, the committed manifest is ${expected.manifestSha256}`,
    );
  }
  if (facts.host !== expected.hostLabel)
    r.push(`HOST_LABEL_DIFFERS: ${facts.host} is not the manifest's ${expected.hostLabel}`);
  if (facts.laneCheckout.dirty) r.push("LANE_CHECKOUT_DIRTY: the checkout holding the manifest is not as committed");
  if (facts.provingCheckout.commit !== expected.sourceCommit) {
    r.push(`PROVING_CHECKOUT_NOT_AT_SOURCE: ${facts.provingCheckout.commit} is not ${expected.sourceCommit}`);
  }
  if (facts.provingCheckout.dirty) r.push("PROVING_CHECKOUT_DIRTY: the proof must run from a clean checkout");
  if (!same(byPath(facts.provingCheckout.tools), byPath(expected.tools))) {
    const have = new Map(facts.provingCheckout.tools.map((t) => [t.path, t.sha256]));
    const want = new Map(expected.tools.map((t) => [t.path, t.sha256]));
    const drifted = [...new Set([...have.keys(), ...want.keys()])].filter((p) => have.get(p) !== want.get(p)).sort();
    r.push(`PROVING_CHECKOUT_TOOL_DRIFT: ${drifted.join(", ")}`);
  }
  if (facts.circuit.error !== null || facts.circuit.members === null) {
    r.push(`CIRCUIT_NOT_VERIFIED: ${facts.circuit.error ?? "no members were verified"}`);
  } else if (!same(byPath(facts.circuit.members), byPath(expected.members))) {
    r.push("CIRCUIT_MEMBERS_DIFFER: the installed members are not the archive record's");
  }
  if (facts.hostBinary.sha256 !== expected.hostBinarySha256) {
    r.push(
      `HOST_BINARY_DIFFERS: ${facts.hostBinary.sha256 ?? "unreadable"} is not the canonical build's ${expected.hostBinarySha256}`,
    );
  }
  if (
    facts.gnark.error !== null ||
    facts.gnark.localRepoDigests === null ||
    !facts.gnark.localRepoDigests.includes(expected.gnarkImageRef)
  ) {
    r.push(
      `GNARK_IMAGE_ABSENT: ${expected.gnarkImageRef} is not in the local docker store by digest${facts.gnark.error ? ` (${facts.gnark.error})` : ""}`,
    );
  }
  if (facts.qualification.errors.length > 0) {
    r.push(`OBSERVER_QUALIFICATION_INVALID: ${facts.qualification.errors.join("; ")}`);
  }
  if (facts.qualification.sha256 !== expected.qualificationSha256) {
    r.push(
      `OBSERVER_QUALIFICATION_DIFFERS: ${facts.qualification.sha256} is not the manifest's ${expected.qualificationSha256}`,
    );
  }
  if (facts.platform.os !== "linux") r.push(`NOT_LINUX: ${facts.platform.os}`);
  if (facts.platform.uid === 0) r.push("RUNS_AS_ROOT: the prover is an unprivileged user; only the observer is root");
  if (facts.platform.docker === null) r.push("DOCKER_UNAVAILABLE: the gnark prover runs in a local container");
  if (
    facts.platform.memTotalKiB < MIN_RAM_KIB ||
    facts.platform.memTotalKiB + facts.platform.swapTotalKiB < MIN_RAM_PLUS_SWAP_KIB
  ) {
    r.push(
      `MEMORY_INSUFFICIENT: ${facts.platform.memTotalKiB} KiB RAM + ${facts.platform.swapTotalKiB} KiB swap (needs ${MIN_RAM_KIB} RAM and ${MIN_RAM_PLUS_SWAP_KIB} together)`,
    );
  }
  return {
    verdict: r.length === 0 ? "PA3D_PREPROOF_ENVIRONMENT_VALID" : "PA3D_PREPROOF_ENVIRONMENT_REFUSED",
    refusals: r,
  };
}

export const serializePreproof = (o: PreproofObservation) => serializeJson(o);

/**
 * What is wrong with a committed attestation: its shape, its constants, and a recorded verdict or refusal list that is
 * not what its own facts and the committed manifest derive.
 */
export function preproofErrors(value: unknown, ctx: ManifestContext): string[] {
  if (!isObject(value)) return ["NOT_AN_OBJECT: an attestation is a JSON object"];
  const errors: string[] = [];
  const keys = new Set(Object.keys(value));
  for (const k of OBSERVATION_KEYS) if (!keys.has(k)) errors.push(`MISSING_FIELD ${k}`);
  for (const k of keys) if (!(OBSERVATION_KEYS as readonly string[]).includes(k)) errors.push(`UNKNOWN_FIELD ${k}`);
  if (value.schema !== PREPROOF_SCHEMA) errors.push(`SCHEMA: ${String(value.schema)} is not ${PREPROOF_SCHEMA}`);
  if (value.lane !== LANE) errors.push(`LANE: ${String(value.lane)} is not ${LANE}`);
  if (!UTC.test(String(value.measuredAtUtc))) errors.push("MEASURED_AT_INVALID: a second-resolution UTC stamp");
  if (!PREPROOF_VERDICTS.includes(value.verdict)) errors.push(`VERDICT_UNKNOWN: ${String(value.verdict)}`);
  if (!Array.isArray(value.refusals) || !value.refusals.every((x: unknown) => typeof x === "string")) {
    errors.push("REFUSALS_INVALID: a list of strings");
  }
  if (value.manifest?.path !== MANIFEST_REL)
    errors.push(`MANIFEST_PATH: ${String(value.manifest?.path)} is not ${MANIFEST_REL}`);
  const manifestBytes = ctx.readFile(MANIFEST_REL);
  if (manifestBytes === null) return [...errors, `MANIFEST_MISSING: ${MANIFEST_REL}`];
  const manifestText = manifestBytes.toString("utf8").replace(/\r\n/g, "\n");
  let manifest: Manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch (error) {
    return [...errors, `MANIFEST_UNREADABLE: ${(error as Error).message}`];
  }
  const manifestBad = manifestErrors(manifest, ctx);
  if (manifestBad.length > 0) return [...errors, ...manifestBad.map((e) => `MANIFEST_INVALID: ${e}`)];
  if (errors.length > 0) return errors;
  let derived: { verdict: PreproofVerdict; refusals: string[] };
  try {
    derived = preproofVerdictOf(value as PreproofFacts, preproofExpectationsOf(manifest, manifestText));
  } catch (error) {
    return [`FACTS_UNREADABLE: ${(error as Error).message}`];
  }
  if (derived.verdict !== value.verdict) {
    errors.push(`VERDICT_DIFFERS: recorded ${String(value.verdict)}, the facts derive ${derived.verdict}`);
  }
  if (!same(derived.refusals, value.refusals)) {
    errors.push(
      `REFUSALS_DIFFER: recorded ${JSON.stringify(value.refusals)}, the facts derive ${JSON.stringify(derived.refusals)}`,
    );
  }
  return errors;
}
