/**
 * SP1 program designations (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD1 froze the designation contract:
 *
 *   zkvm subject → canonical procedure (vendor image by digest) → ELF sha256 → vkey (recomputed outside the build)
 *   → designation file → compile-time constant
 *
 * A designation is one immutable file per program identity in evidence/zk/sp1/designations/. It binds the subject
 * (zkvm guest and host trees, the per-file manifest digest, the guest lockfile), the canonical procedure (image by
 * digest, its manifest and config digests, the exact in-container entrypoint and driver by sha256, the SP1 pins, the
 * guest-lock policy), the ELF and its vkey, the hosts that reproduced them, the outside vkey recompute, the SP1
 * verifier the program's proofs are checked by (version, address, runtime code hash, VERIFIER_HASH, VK_ROOT, CREATE2
 * authentication, the chains it was measured on and executed on) and the IDENTITY the consumers compare on chain:
 * keccak256(abi.encode(the verifier's runtime code hash, PROGRAM_VKEY)) — an address never enters it.
 *
 * The first designation is DERIVED from SP1-TD1's evidence by SP1-TD1's own derivations, as of the subject that
 * evidence measured, and validated by regenerating it. Nothing here is typed: a human pasting matching constants in
 * two files is not evidence. A designation records which program and verifier these are; it never establishes that
 * they are sound (`soundness` is always NOT_ESTABLISHED_BY_DESIGNATION).
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, keccak256 } from "ethers";

import { sourceManifestDigest, workingTreeSourceManifest } from "./sp1-p1-stop-receipt";
import {
  deriveDesignation,
  deriveProgramIdentity,
  deriveTrustTargetIdentity,
  readDecisionContext,
  type DecisionContext,
} from "./sp1-td1-decision";
import { readWrapperBuilds, type WrapperBuild } from "./sp1-wrapper-build";

export const DESIGNATIONS_DIR = "evidence/zk/sp1/designations";
/** Each successor's evidence bundle, committed beside it and named after the designation it produced. */
export const DESIGNATION_EVIDENCE_DIR = "evidence/zk/sp1/designation-evidence";
export const DESIGNATION_EVIDENCE_SCHEMA = "walletwall.sp1-designation-evidence.v1";
export const DESIGNATION_SCHEMA = "walletwall.sp1-program-designation.v1";
export const WITHDRAWAL_PROGRAM = "mldsa65-withdrawal";
export const SOUNDNESS_NOT_ESTABLISHED = "NOT_ESTABLISHED_BY_DESIGNATION";
/** The canonical workflow refuses a build that changes the guest lockfile (SP1-TD1 finding TD1-N7). */
export const GUEST_LOCK_POLICY = "UNCHANGED_BY_THE_BUILD";
const GUEST_LOCK_PATH = "zkvm/guest/Cargo.lock";
const VENDOR_PROCEDURE = "vendor-image-host-flow";

export interface FileDigest {
  path: string;
  sha256: string;
}

export interface ProgramDesignation {
  schema: string;
  id: string;
  sequence: number;
  program: string;
  /** The designation this one succeeds; null for the first. */
  predecessor: { id: string; identity: string } | null;
  /** Why it succeeds its predecessor; null for the first. */
  succession: { reason: string } | null;
  subject: {
    zkvmGuestTree: string;
    zkvmHostTree: string;
    sourceManifestSha256: string;
    guestCargoLockSha256: string;
  };
  procedure: {
    id: string;
    image: string;
    platform: string;
    linuxAmd64Manifest: string;
    config: string;
    entrypoint: FileDigest;
    driver: FileDigest;
    sp1: Record<string, string>;
    target: string;
    guestLock: string;
  };
  elf: { sha256: string; bytes: number };
  programVKey: string;
  vkeyRecomputed: { tool: string; agreeing: number; conflicting: number; distinctComputations: number };
  hosts: string[];
  verifier: {
    version: string;
    address: string;
    runtimeCodeKeccak: string;
    verifierHash: string;
    vkRoot: string;
    create2: { deploymentTx: string; salt: string; initcodeKeccak: string; address: string; authenticated: boolean };
    measuredChains: { chainId: string; block: number; codeKeccak: string; providersAgree: boolean }[];
    chainExecution: { chainId: string; block: number; providersAgree: boolean; verdictsAsExpected: boolean }[];
    chainCallsBound: boolean;
    canaryHasPositiveControl: boolean;
    realProofOnPinnedKey: { transaction: string; programVKey: string };
  };
  identity: string;
  /** What it was derived from: SP1-TD1's decision evidence (the first) or a committed evidence bundle (successors). */
  evidence: { kind: string; decisionInputsDigest?: string; bundleDigest?: string; files: FileDigest[] };
  soundness: string;
  doNotPin: { program: string; elfSha256: string | null; vkey: string | null }[];
}

/** One host's run of the canonical procedure, as its observation recorded it. */
export interface EvidenceBuild {
  hostId: string;
  image: string;
  guestLockBefore: string;
  guestLockAfter: string;
  programs: Record<string, { elfSha256: string; elfBytes: number; vkey: string }>;
}

/**
 * The evidence a successor designation is derived from: the same contract the first designation met. The verifier is
 * either an earlier designation's (`sameAs`, a new program build on the same SP1 verifier) or a full verifier record.
 */
export interface DesignationEvidenceBundle {
  schema: string;
  program: string;
  subject: { zkvmGuestTree: string; zkvmHostTree: string; sourceManifest: FileDigest[] };
  procedure: ProgramDesignation["procedure"];
  builds: EvidenceBuild[];
  vkeyRecompute: {
    tool: string;
    toolSha256: string;
    ranOn: string;
    results: { program: string; elfSha256: string; vkey: string }[];
  };
  verifier: { sameAs: string } | ProgramDesignation["verifier"];
  /** The designation it succeeds and why: authored inputs, bound by the bundle's digest like the rest. */
  succession: { predecessor: string; reason: string };
}

const abi = AbiCoder.defaultAbiCoder();
const sha256Hex = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const isWord = (x: unknown) => typeof x === "string" && /^0x[0-9a-f]{64}$/.test(x);
const isHex64 = (x: unknown) => typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const isTree = (x: unknown) => typeof x === "string" && /^[0-9a-f]{40}$/.test(x);
const uniq = <T>(xs: T[]) => [...new Set(xs)];

/** A subject as subjects are compared: its two trees, and its source manifest's digest. */
interface SubjectKey {
  guest: unknown;
  host: unknown;
  manifest: unknown;
}
const subjectKey = (s: ProgramDesignation["subject"] | undefined): SubjectKey => ({
  guest: s?.zkvmGuestTree,
  host: s?.zkvmHostTree,
  manifest: s?.sourceManifestSha256,
});
/** The same zkvm sources: both trees, or the manifest of the sources on disk. */
const sameSubject = (a: SubjectKey, b: SubjectKey) =>
  (typeof a.guest === "string" && a.guest === b.guest && a.host === b.host) ||
  (typeof a.manifest === "string" && a.manifest === b.manifest);
/** SP1 pins as releases compare: sorted by crate, values trimmed (key order and padding are not another release). */
const canonicalPins = (sp1: Record<string, string> | undefined) =>
  JSON.stringify(
    Object.entries(sp1 ?? {})
      .map(([k, v]) => [k.trim(), String(v).trim()])
      .sort(([a], [b]) => a.localeCompare(b)),
  );
/** JSON with every object's keys sorted, so key order never makes two equal records differ. */
const canonicalJson = (x: unknown): string =>
  JSON.stringify(x, (_k, v) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)))
      : v,
  );

/** The designation with the highest sequence: the one whose subject CI holds HEAD to. */
export function latestDesignation(set: readonly ProgramDesignation[]): ProgramDesignation | undefined {
  return [...set].sort((a, b) => a.sequence - b.sequence).at(-1);
}

/** The identity the consumers store and compare on chain (VerifierRotationGuard.identityOf). */
export function identityOf(runtimeCodeKeccak: string, programVKey: string): string {
  return keccak256(abi.encode(["bytes32", "bytes32"], [runtimeCodeKeccak, programVKey]));
}

/** A designation as committed: fixed key order, trailing newline. */
export function serializeDesignation(d: ProgramDesignation): string {
  return `${JSON.stringify(d, null, 2)}\n`;
}

// ---------------------------------------------------------------------------------------------------------
// The first designation: SP1-TD1's evidence, derived as of the subject it measured
// ---------------------------------------------------------------------------------------------------------

/**
 * SP1-TD1's context as of the subject its evidence measured: the per-file manifest every vendor-image build recorded
 * and the trees SP1-TD1 recorded, instead of today's working tree. A designation is immutable, so it may not depend on
 * the tree it is validated in; whether today's tree is still its subject is a separate check (subjectFreshnessErrors).
 */
function asOfMeasuredSubject(ctx: DecisionContext): DecisionContext {
  const vendor = ctx.sp1p1Identity.environments.filter((e) => e.procedure === VENDOR_PROCEDURE && e.sourceManifest);
  const manifests = uniq(vendor.map((e) => sourceManifestDigest(e.sourceManifest as FileDigest[])));
  if (manifests.length !== 1) {
    throw new Error(
      `SP1-TD1's evidence does not designate ${WITHDRAWAL_PROGRAM}: the vendor-image builds recorded ${manifests.length} subjects`,
    );
  }
  return {
    ...ctx,
    workingTreeManifest: (vendor[0].sourceManifest as FileDigest[]).map((e) => ({ ...e })),
    gitTrees: { guest: ctx.inputs.subject.zkvmGuestTree, host: ctx.inputs.subject.zkvmHostTree },
  };
}

/** The first designation of mldsa65-withdrawal, derived from SP1-TD1's evidence; throws when the evidence does not designate it. */
export function deriveInitialDesignation(ctx: DecisionContext): ProgramDesignation {
  const m = asOfMeasuredSubject(ctx);
  const tt = deriveTrustTargetIdentity(m);
  const pid = deriveProgramIdentity(m);
  const dz = deriveDesignation(m, pid);
  const problems: string[] = [];
  if (!tt.established) problems.push(`the trust target is not established (${tt.failures.join("; ")})`);
  if (pid.decision !== "PINNED_VENDOR_BUILD") problems.push(`the program identity decision is ${pid.decision}`);
  if (pid.contradictions.length > 0) problems.push(`contradicting identity evidence: ${pid.contradictions.join("; ")}`);
  if (!pid.vendorImage.indexDigestVerified) problems.push("the vendor image index is not verified against its digest");
  if (dz.status !== "DESIGNATED") problems.push(`the vkey is not designated (${dz.reason})`);
  const missing = Object.entries(m.fileHashes).filter(([, h]) => !isHex64(h));
  if (missing.length > 0) problems.push(`evidence files are missing: ${missing.map(([p]) => p).join(", ")}`);
  if (problems.length > 0) {
    throw new Error(`SP1-TD1's evidence does not designate ${WITHDRAWAL_PROGRAM}:\n - ${problems.join("\n - ")}`);
  }
  const sel = m.inputs.programIdentitySelection.canonicalProcedure;
  const lock = m.workingTreeManifest.find((e) => e.path === GUEST_LOCK_PATH);
  if (!lock)
    throw new Error(`SP1-TD1's evidence does not designate ${WITHDRAWAL_PROGRAM}: no ${GUEST_LOCK_PATH} measured`);
  const xc = dz.crossCheck;
  const programVKey = dz.vkey as string;
  const runtimeCodeKeccak = tt.codeKeccak as string;
  return {
    schema: DESIGNATION_SCHEMA,
    id: `${WITHDRAWAL_PROGRAM}-d1`,
    sequence: 1,
    program: WITHDRAWAL_PROGRAM,
    predecessor: null,
    succession: null,
    subject: {
      zkvmGuestTree: dz.zkvmGuestTree,
      zkvmHostTree: dz.zkvmHostTree,
      sourceManifestSha256: sourceManifestDigest(m.workingTreeManifest),
      guestCargoLockSha256: lock.sha256,
    },
    procedure: {
      id: sel.id,
      image: sel.image,
      platform: sel.platform,
      linuxAmd64Manifest: pid.vendorImage.linuxAmd64Manifest as string,
      config: pid.vendorImage.config as string,
      entrypoint: { path: sel.entrypoint, sha256: m.fileHashes[sel.entrypoint] },
      driver: { path: sel.driver, sha256: m.fileHashes[sel.driver] },
      sp1: { ...sel.sp1 },
      target: sel.target,
      guestLock: GUEST_LOCK_POLICY,
    },
    elf: { sha256: dz.elfSha256 as string, bytes: dz.elfBytes as number },
    programVKey,
    vkeyRecomputed: {
      tool: String(xc.tool),
      agreeing: xc.agreeing,
      conflicting: xc.conflicting,
      distinctComputations: xc.distinctComputations,
    },
    hosts: [...dz.independentHosts].sort(),
    verifier: {
      version: tt.version,
      address: tt.verifier,
      runtimeCodeKeccak,
      verifierHash: tt.verifierHash as string,
      vkRoot: tt.vkRoot as string,
      create2: {
        deploymentTx: tt.create2.tx,
        salt: tt.create2.salt,
        initcodeKeccak: tt.create2.initcodeKeccak,
        address: tt.create2.derived,
        authenticated: tt.create2.authenticated,
      },
      measuredChains: tt.chains.map((c) => ({
        chainId: c.chainId,
        block: c.block,
        codeKeccak: c.codeKeccak as string,
        providersAgree: c.providersAgree,
      })),
      chainExecution: tt.chainExecution.map((c) => ({ ...c })),
      chainCallsBound: tt.chainCallsBound,
      canaryHasPositiveControl: tt.canaryHasPositiveControl,
      realProofOnPinnedKey: {
        transaction: tt.realProofOnPinnedKey.transaction,
        programVKey: tt.realProofOnPinnedKey.programVKey,
      },
    },
    identity: identityOf(runtimeCodeKeccak, programVKey),
    evidence: {
      kind: "SP1-TD1 decision evidence",
      decisionInputsDigest: sha256Hex(JSON.stringify(m.inputs)),
      files: Object.entries(m.fileHashes)
        .map(([path, sha256]) => ({ path, sha256 }))
        .sort((a, b) => a.path.localeCompare(b.path)),
    },
    soundness: SOUNDNESS_NOT_ESTABLISHED,
    doNotPin: dz.doNotPin.map((x) => ({ ...x })),
  };
}

/** The committed first designation against the derivation from SP1-TD1's evidence. */
export function initialDesignationDriftErrors(set: readonly ProgramDesignation[], ctx: DecisionContext): string[] {
  if (set.length === 0) return [`no designation is recorded in ${DESIGNATIONS_DIR}`];
  let derived: ProgramDesignation;
  try {
    derived = deriveInitialDesignation(ctx);
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
  return serializeDesignation(set[0]) === serializeDesignation(derived)
    ? []
    : [`${set[0].id} is not what SP1-TD1's evidence derives: a designation is generated from evidence, never edited`];
}

// ---------------------------------------------------------------------------------------------------------
// Successors: a new, independently established identity, from an evidence bundle
// ---------------------------------------------------------------------------------------------------------

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
type ProgramOutput = EvidenceBuild["programs"][string];

/**
 * The next designation, derived from `bundle` and appended after `set`; throws with every way the bundle falls short
 * of the evidence contract or would alias an earlier identity. Nothing in `set` is changed.
 */
export function deriveSuccessorDesignation(
  bundle: DesignationEvidenceBundle,
  set: readonly ProgramDesignation[],
): ProgramDesignation {
  const problems: string[] = [];
  const first = set[0];
  if (!first) problems.push("a successor needs a first designation to succeed");
  if (bundle?.schema !== DESIGNATION_EVIDENCE_SCHEMA) {
    problems.push(`the bundle's schema must be ${DESIGNATION_EVIDENCE_SCHEMA}`);
  }
  if (bundle !== null && typeof bundle === "object" && "soundness" in bundle) {
    problems.push("an evidence bundle carries no soundness claim (provenance is not soundness)");
  }
  if (bundle?.program !== WITHDRAWAL_PROGRAM) problems.push(`the program must be ${WITHDRAWAL_PROGRAM}`);

  // The canonical procedure is the first designation's, field for field (its image pinned by digest, its platform,
  // manifest, config, entrypoint, driver, SP1 pins, target and guest lock policy): another one is another decision.
  const procedure = bundle?.procedure;
  if (first && JSON.stringify(procedure) !== JSON.stringify(first.procedure)) {
    problems.push(
      `the procedure must be the first designation's (${first.procedure.id}, ${first.procedure.image}) field for ` +
        "field: another procedure needs its own decision",
    );
  }

  // The subject, and every host's build of it.
  const manifest = Array.isArray(bundle?.subject?.sourceManifest) ? bundle.subject.sourceManifest : [];
  const lock = manifest.find((e) => e.path === GUEST_LOCK_PATH);
  if (!isTree(bundle?.subject?.zkvmGuestTree) || !isTree(bundle?.subject?.zkvmHostTree) || !lock) {
    problems.push(`the subject needs both trees and a manifest that includes ${GUEST_LOCK_PATH}`);
  }
  if (manifest.some((e) => !isHex64(e?.sha256))) problems.push("every subject file needs its sha256");
  // Under the same procedure an earlier subject builds that designation's ELF: a bundle naming it can only alias that
  // identity or contradict its measured build, so a successor is a new subject (a program rebuild).
  const claimed: SubjectKey = {
    guest: bundle?.subject?.zkvmGuestTree,
    host: bundle?.subject?.zkvmHostTree,
    manifest: sourceManifestDigest(manifest),
  };
  const earlier = set.find((d) => sameSubject(subjectKey(d.subject), claimed));
  if (earlier) {
    problems.push(
      `the subject is ${earlier.id}'s: under the same procedure it builds ${earlier.id}'s ELF, so a successor needs a ` +
        "new subject (a program rebuild)",
    );
  }
  const builds = Array.isArray(bundle?.builds) ? bundle.builds : [];
  if (builds.length < 2 || uniq(builds.map((b) => b?.hostId)).length !== builds.length) {
    problems.push("the ELF and vkey must be reproduced on two hosts, each once");
  }
  for (const b of builds) {
    if (b?.image !== procedure?.image)
      problems.push(`the build on ${String(b?.hostId)} did not run the procedure's image`);
    if (!lock || b?.guestLockBefore !== lock.sha256 || b?.guestLockAfter !== lock.sha256) {
      problems.push(
        `the build on ${String(b?.hostId)}: the guest lockfile must be the subject's before and after the build (${GUEST_LOCK_POLICY})`,
      );
    }
  }
  const outputs = builds.map((b) => b?.programs?.[WITHDRAWAL_PROGRAM] ?? null);
  const w: ProgramOutput | null = outputs[0] ?? null;
  if (w === null || uniq(outputs.map((o) => JSON.stringify(o))).length !== 1) {
    problems.push("the hosts must agree on the withdrawal ELF, its size and its vkey");
  } else if (!isHex64(w.elfSha256) || !isWord(w.vkey) || !(Number.isInteger(w.elfBytes) && w.elfBytes > 0)) {
    problems.push("the withdrawal ELF needs its sha256 and size, and its vkey a 32-byte word");
  }

  // The vkey, recomputed from the ELF outside every build, by a tool named by its digest.
  if (!isHex64(bundle?.vkeyRecompute?.toolSha256)) {
    problems.push("the outside recompute must name its tool's sha256 (the binary that recomputed the vkey)");
  }
  const results = (bundle?.vkeyRecompute?.results ?? []).filter(
    (r) => r?.program === WITHDRAWAL_PROGRAM && r.elfSha256 === w?.elfSha256,
  );
  const agreeing = results.filter((r) => r.vkey === w?.vkey).length;
  if (results.length > agreeing) problems.push("one ELF maps to two vkeys (PROGRAM_IDENTITY_CONTRADICTION)");
  else if (agreeing < 1) problems.push("the vkey must be recomputed outside the build from the ELF it designates");

  // The verifier: an earlier designation's, or a full record (which needs its own per-chain evidence).
  let verifier: ProgramDesignation["verifier"] | null = null;
  const v = bundle?.verifier as Record<string, unknown> | undefined;
  if (v && typeof v.sameAs === "string") {
    const reference = set.find((d) => d.id === v.sameAs);
    if (!reference) problems.push(`the verifier reference ${v.sameAs} names no designation`);
    else verifier = clone(reference.verifier);
  } else if (v && isWord(v.runtimeCodeKeccak)) {
    verifier = clone(v) as unknown as ProgramDesignation["verifier"];
    problems.push(
      "a new SP1 verifier cannot be designated by this tooling: it needs its own trust-target derivation, as SP1-TD1's " +
        "for v6.1.0 (a real proof on it, its CREATE2-authenticated initcode, per-chain execution evidence)",
    );
  } else {
    problems.push("the bundle names no SP1 verifier");
  }

  // The identity: never one an earlier designation has, whatever the address.
  const identity =
    verifier !== null && w !== null && isWord(w.vkey) ? identityOf(verifier.runtimeCodeKeccak, w.vkey) : null;
  const aliased = identity === null ? undefined : set.find((d) => d.identity === identity);
  if (aliased) {
    problems.push(
      `identity ${identity} is already designated by ${aliased.id}: a successor must be a distinct verifier/program identity`,
    );
  }
  const choice = bundle?.succession;
  const predecessor = set.find((d) => d.id === choice?.predecessor);
  if (!predecessor) problems.push(`the predecessor ${String(choice?.predecessor)} is no designation`);
  if (typeof choice?.reason !== "string" || choice.reason.trim().length === 0) {
    problems.push("the succession needs a reason");
  }
  if (
    problems.length > 0 ||
    predecessor === undefined ||
    w === null ||
    verifier === null ||
    identity === null ||
    !lock ||
    choice === undefined
  ) {
    throw new Error(`the evidence bundle does not designate a successor:\n - ${problems.join("\n - ")}`);
  }

  const acvp = builds.map((b) => b.programs?.["mldsa65-acvp"] ?? null);
  const acvpAgreed = acvp[0] !== null && uniq(acvp.map((o) => JSON.stringify(o))).length === 1;
  const sequence = set.length + 1;
  return {
    schema: DESIGNATION_SCHEMA,
    id: `${WITHDRAWAL_PROGRAM}-d${sequence}`,
    sequence,
    program: WITHDRAWAL_PROGRAM,
    predecessor: { id: predecessor.id, identity: predecessor.identity },
    succession: { reason: choice.reason },
    subject: {
      zkvmGuestTree: bundle.subject.zkvmGuestTree,
      zkvmHostTree: bundle.subject.zkvmHostTree,
      sourceManifestSha256: sourceManifestDigest(manifest),
      guestCargoLockSha256: lock.sha256,
    },
    procedure: clone(procedure),
    elf: { sha256: w.elfSha256, bytes: w.elfBytes },
    programVKey: w.vkey,
    // One bundle carries one recompute (one tool, one run): its results agree, or the bundle was refused above.
    vkeyRecomputed: {
      tool: bundle.vkeyRecompute.tool,
      agreeing,
      conflicting: results.length - agreeing,
      distinctComputations: 1,
    },
    hosts: builds.map((b) => b.hostId).sort(),
    verifier,
    identity,
    evidence: { kind: "SP1 designation evidence bundle", bundleDigest: sha256Hex(JSON.stringify(bundle)), files: [] },
    soundness: SOUNDNESS_NOT_ESTABLISHED,
    doNotPin: [
      {
        program: "mldsa65-acvp",
        elfSha256: acvpAgreed ? (acvp[0] as ProgramOutput).elfSha256 : null,
        vkey: acvpAgreed ? (acvp[0] as ProgramOutput).vkey : null,
      },
    ],
  };
}

/**
 * Each successor in `set` against the derivation from its own committed bundle (`bundles`, by designation id); the
 * bundle holds every input, the predecessor and the reason included, so a successor is generated, never edited.
 */
export function successorDriftErrors(
  set: readonly ProgramDesignation[],
  bundles: Record<string, DesignationEvidenceBundle | undefined>,
): string[] {
  const errors: string[] = [];
  set.forEach((d, i) => {
    if (i === 0) return;
    const bundle = bundles[d.id];
    if (bundle === undefined) {
      errors.push(`${d.id}: its evidence bundle ${DESIGNATION_EVIDENCE_DIR}/${d.id}.json is missing`);
      return;
    }
    if (sha256Hex(JSON.stringify(bundle)) !== d.evidence?.bundleDigest) {
      errors.push(`${d.id}: the committed evidence bundle is not the one it was derived from`);
      return;
    }
    try {
      const derived = deriveSuccessorDesignation(bundle, set.slice(0, i));
      if (serializeDesignation(derived) !== serializeDesignation(d)) {
        errors.push(`${d.id} is not what its evidence bundle derives: a designation is generated, never edited`);
      }
    } catch (error) {
      errors.push(`${d.id}: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return errors;
}

// ---------------------------------------------------------------------------------------------------------
// Rules over the set
// ---------------------------------------------------------------------------------------------------------

/** Every way a designation set (in sequence order) is malformed or contradicts itself; empty: valid. */
export function designationSetErrors(set: readonly ProgramDesignation[]): string[] {
  const errors: string[] = [];
  const identities = new Map<string, string>();
  set.forEach((d, i) => {
    const at = `designation ${String(d?.id)}`;
    if (d?.schema !== DESIGNATION_SCHEMA) errors.push(`${at}: schema must be ${DESIGNATION_SCHEMA}`);
    if (d?.program !== WITHDRAWAL_PROGRAM) errors.push(`${at}: program must be ${WITHDRAWAL_PROGRAM}`);
    if (d?.sequence !== i + 1) errors.push(`${at}: sequence must be ${i + 1} (numbered from 1, in order)`);
    if (d?.id !== `${d?.program}-d${d?.sequence}`) errors.push(`${at}: id must be <program>-d<sequence>`);
    if (d?.soundness !== SOUNDNESS_NOT_ESTABLISHED) {
      errors.push(`${at}: soundness must be ${SOUNDNESS_NOT_ESTABLISHED} (provenance is not soundness)`);
    }
    if (!isWord(d?.programVKey) || !isWord(d?.verifier?.runtimeCodeKeccak)) {
      errors.push(`${at}: programVKey and verifier.runtimeCodeKeccak must be 32-byte words`);
    } else if (d.identity !== identityOf(d.verifier.runtimeCodeKeccak, d.programVKey)) {
      errors.push(`${at}: identity must be keccak256(abi.encode(verifier runtime code hash, PROGRAM_VKEY))`);
    }
    if (!/@sha256:[0-9a-f]{64}$/.test(String(d?.procedure?.image))) {
      errors.push(`${at}: the procedure's image must be pinned by digest, never a mutable tag`);
    }
    if (d?.procedure?.guestLock !== GUEST_LOCK_POLICY)
      errors.push(`${at}: the guest lock policy must be ${GUEST_LOCK_POLICY}`);
    const s = d?.subject;
    if (
      !isTree(s?.zkvmGuestTree) ||
      !isTree(s?.zkvmHostTree) ||
      !isHex64(s?.sourceManifestSha256) ||
      !isHex64(s?.guestCargoLockSha256)
    ) {
      errors.push(`${at}: the subject needs both trees, the manifest digest and the guest lockfile digest`);
    }
    if (!isHex64(d?.elf?.sha256) || !(Number.isInteger(d?.elf?.bytes) && d.elf.bytes > 0)) {
      errors.push(`${at}: the ELF needs its sha256 and size`);
    }
    if (uniq(d?.hosts ?? []).length < 2) errors.push(`${at}: the ELF and vkey must be reproduced on two hosts`);
    if (!(d?.vkeyRecomputed?.agreeing >= 1) || d?.vkeyRecomputed?.conflicting !== 0) {
      errors.push(`${at}: the vkey must be recomputed outside the build, with no conflicting result`);
    }
    if (i === 0) {
      if (d?.predecessor !== null || d?.succession !== null)
        errors.push(`${at}: the first designation has no predecessor`);
    } else {
      const earlier = set.slice(0, i).find((e) => e.id === d?.predecessor?.id);
      if (!earlier || d?.predecessor?.identity !== earlier.identity) {
        errors.push(`${at}: its predecessor must be an earlier designation, named with that designation's identity`);
      }
      if (typeof d?.succession?.reason !== "string" || d.succession.reason.trim().length === 0) {
        errors.push(`${at}: a successor states the reason it succeeds its predecessor`);
      }
    }
    const prior = identities.get(d?.identity);
    if (prior !== undefined) errors.push(`${at}: identity ${d.identity} is already designated by ${prior}`);
    else identities.set(d?.identity, d?.id);
  });
  // One ELF built with the same SP1 release can have one vkey only, however the release's pins are spelled.
  for (const a of set) {
    for (const b of set) {
      if (
        a !== b &&
        a.elf?.sha256 === b.elf?.sha256 &&
        canonicalPins(a.procedure?.sp1) === canonicalPins(b.procedure?.sp1)
      ) {
        if (a.programVKey !== b.programVKey && a.sequence < b.sequence) {
          errors.push(`designations ${a.id} and ${b.id}: one ELF maps to two vkeys (PROGRAM_IDENTITY_CONTRADICTION)`);
        }
      }
    }
  }
  // One subject under one procedure is one build: designating it twice can only alias or contradict.
  set.forEach((a, i) => {
    for (const b of set.slice(i + 1)) {
      if (
        sameSubject(subjectKey(a.subject), subjectKey(b.subject)) &&
        canonicalJson(a.procedure) === canonicalJson(b.procedure)
      ) {
        errors.push(
          `designations ${a.id} and ${b.id} share a subject under one procedure: one build, two designations`,
        );
      }
    }
  });
  return errors;
}

/** The designations a compiled wrapper build can be bound to: its pinned verifier is theirs. */
export function compatibleDesignations(build: WrapperBuild, set: readonly ProgramDesignation[]): ProgramDesignation[] {
  return set.filter(
    (d) =>
      d.verifier.runtimeCodeKeccak === build.pins.sp1VerifierCodehash &&
      d.verifier.verifierHash === build.pins.sp1VerifierHash &&
      d.verifier.vkRoot === build.pins.vkRoot &&
      d.verifier.version === build.pins.version,
  );
}

// ---------------------------------------------------------------------------------------------------------
// The repository
// ---------------------------------------------------------------------------------------------------------

function headTree(repoRoot: string, rel: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", `HEAD:${rel}`], {
      cwd: resolve(repoRoot),
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString("utf8")
      .trim();
  } catch {
    return null;
  }
}

/** Whether the zkvm subject at HEAD and on disk is `d`'s; a change needs a new designation (the stale-vkey tripwire). */
export function subjectFreshnessErrors(d: ProgramDesignation, repoRoot = "."): string[] {
  const errors: string[] = [];
  const need = `a zkvm change needs a new designation`;
  const guest = headTree(repoRoot, "zkvm/guest");
  const host = headTree(repoRoot, "zkvm/host");
  if (guest !== d.subject.zkvmGuestTree) {
    errors.push(`stale: HEAD:zkvm/guest is ${String(guest)}, not ${d.id}'s ${d.subject.zkvmGuestTree}; ${need}`);
  }
  if (host !== d.subject.zkvmHostTree) {
    errors.push(`stale: HEAD:zkvm/host is ${String(host)}, not ${d.id}'s ${d.subject.zkvmHostTree}; ${need}`);
  }
  const onDisk = sourceManifestDigest(workingTreeSourceManifest(repoRoot));
  if (onDisk !== d.subject.sourceManifestSha256) {
    errors.push(`stale: the zkvm guest/host sources on disk (${onDisk}) are not ${d.id}'s subject; ${need}`);
  }
  const lockPath = resolve(repoRoot, GUEST_LOCK_PATH);
  const lock = existsSync(lockPath) ? sha256Hex(readFileSync(lockPath)) : "missing";
  if (lock !== d.subject.guestCargoLockSha256) {
    errors.push(
      `stale: ${GUEST_LOCK_PATH} on disk is ${lock}, not ${d.id}'s ${d.subject.guestCargoLockSha256}; ${need}`,
    );
  }
  return errors;
}

/** The committed designations, in sequence order; a file must be named after the id it holds. */
export function readDesignations(repoRoot = "."): ProgramDesignation[] {
  const dir = resolve(repoRoot, DESIGNATIONS_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((file) => {
      const d = JSON.parse(readFileSync(resolve(dir, file), "utf8")) as ProgramDesignation;
      if (`${d.id}.json` !== file) throw new Error(`${DESIGNATIONS_DIR}/${file} holds ${String(d.id)}`);
      return d;
    })
    .sort((a, b) => a.sequence - b.sequence);
}

/** The committed evidence bundle of each successor, by designation id (missing ones are absent). */
export function readDesignationBundles(
  repoRoot: string,
  set: readonly ProgramDesignation[],
): Record<string, DesignationEvidenceBundle | undefined> {
  const out: Record<string, DesignationEvidenceBundle | undefined> = {};
  for (const d of set.slice(1)) {
    const path = resolve(repoRoot, DESIGNATION_EVIDENCE_DIR, `${d.id}.json`);
    out[d.id] = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as DesignationEvidenceBundle) : undefined;
  }
  return out;
}

/** The full check of the committed designations in this repository. */
export function validateDesignationsInRepo(repoRoot = "."): string[] {
  const set = readDesignations(repoRoot);
  const errors = [
    ...designationSetErrors(set),
    ...initialDesignationDriftErrors(set, readDecisionContext(repoRoot)),
    ...successorDriftErrors(set, readDesignationBundles(repoRoot, set)),
  ];
  if (set.length > 0) errors.push(...subjectFreshnessErrors(set[set.length - 1], repoRoot));
  const builds = readWrapperBuilds(repoRoot);
  if (builds.length > 0 && compatibleDesignations(builds[builds.length - 1], set).length === 0) {
    errors.push("verifier drift: the compiled wrapper's pinned SP1 verifier is no designation's verifier");
  }
  return errors;
}
