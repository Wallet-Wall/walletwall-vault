/**
 * The canonical build, checked against the designation (the SP1 implementation lane;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * scripts/sp1-canonical/canonical-build.sh runs SP1-TD1's canonical procedure (PINNED_VENDOR_BUILD: the repository's
 * host flow in a fresh container of the vendor image pinned by digest, SP1-TD1's preserved entrypoint unchanged) and
 * records what it produced; the vkey is then recomputed from each ELF outside every build, with Succinct's released
 * cargo-prove. This module collects those records into an observation and compares it with the designation:
 *
 *   PROGRAM_IDENTITY_DRIFT — the ELF, its size, the in-build vkey, the outside recompute (one ELF, two vkeys, or no
 *     recompute at all), or the ACVP program differ, or two hosts disagree. Rebuilding the frozen subject must
 *     reproduce the designation; otherwise the lane STOPs.
 *   PROCEDURE_DRIFT — the build failed, or ran another image (a mutable tag), another platform, another entrypoint,
 *     another subject, or the guest lockfile was not the subject's before and after the build (TD1-N7).
 *   INSUFFICIENT_HOSTS — fewer distinct hosts than required (the release rebuild requires two).
 *
 * Common mode, stated rather than hidden: every host runs the same vendor image, toolchain, source archive and
 * entrypoint, fetches the same locked crates, and is operated the same way; the outside recompute runs the same
 * upstream prover library (a different binary distribution, not an independent implementation). Two hosts agreeing
 * shows the procedure is deterministic on that platform; it cannot show the image or the prover is right.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { sourceManifestDigest } from "./sp1-p1-stop-receipt";
import type { FileDigest, ProgramDesignation } from "./sp1-designation";

export const CANONICAL_BUILD_SCHEMA = "walletwall.sp1-canonical-build.v1";
export const CANONICAL_REBUILD_OBSERVATION_REL =
  "evidence/zk/sp1-impl/observations/canonical-rebuild-developer-workstation.raw.json";
const WITHDRAWAL = "mldsa65-withdrawal";
const ACVP = "mldsa65-acvp";

export interface ProgramOutput {
  elfSha256: string;
  elfBytes: number;
  vkey: string;
}

export interface CanonicalBuild {
  hostId: string;
  hostIdentity: string;
  image: { reference: string; id: string; repoDigests: string[]; platform: string };
  subject: {
    head: string;
    zkvmGuestTree: string;
    zkvmHostTree: string;
    guestLockAtHead: string;
    sourceManifest: FileDigest[];
  };
  entrypoint: FileDigest;
  containerExit: number;
  buildSeconds: number | null;
  guestLockBefore: string;
  guestLockAfter: string;
  programs: Record<string, ProgramOutput>;
  hostBinarySha256: string | null;
}

export interface VkeyRecompute {
  tool: string;
  toolSha256: string;
  ranOn: string;
  results: { program: string; elfSha256: string; vkey: string }[];
}

export interface CanonicalBuildObservation {
  schema: string;
  measuredAtUtc: string;
  designation: string;
  builds: CanonicalBuild[];
  vkeyRecompute: VkeyRecompute;
  commonMode: string[];
}

export type CanonicalBuildVerdict = "REPRODUCED" | "PROGRAM_IDENTITY_DRIFT" | "PROCEDURE_DRIFT" | "INSUFFICIENT_HOSTS";

const sha256File = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const text = (dir: string, rel: string) => (existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8") : "");
const firstToken = (s: string) => s.trim().split(/\s+/)[0] ?? "";

/** One host's build, from the driver's output directory (scripts/sp1-canonical/canonical-build.sh). */
export function collectBuild(
  dir: string,
  hostId: string,
  procedure: { image: string; entrypoint: FileDigest },
): CanonicalBuild {
  const [head = "", guestTree = "", hostTree = ""] = text(dir, "src/git-ids.txt").trim().split(/\r?\n/);
  const imageLine = text(dir, "image.txt").trim();
  const firstSpace = imageLine.indexOf(" ");
  const lastSpace = imageLine.lastIndexOf(" ");
  let repoDigests: string[] = [];
  try {
    repoDigests = JSON.parse(imageLine.slice(firstSpace + 1, lastSpace)) as string[];
  } catch {
    repoDigests = [];
  }
  const sizes = Object.fromEntries(
    text(dir, "host/elf-size.txt")
      .trim()
      .split(/\r?\n/)
      .filter(Boolean)
      .map((l) => [l.split(/\s+/)[0], Number(l.split(/\s+/)[1])]),
  );
  const shas = Object.fromEntries(
    text(dir, "host/elf-sha256.txt")
      .trim()
      .split(/\r?\n/)
      .filter(Boolean)
      .map((l) => [l.split(/\s+/)[1], l.split(/\s+/)[0]]),
  );
  const vkeyOf = (rel: string) => {
    try {
      return String(JSON.parse(text(dir, rel)).vkey);
    } catch {
      return "";
    }
  };
  const exit = /container_exit=(\d+)/.exec(text(dir, "host/run.log"));
  const seconds = /build_seconds=(\d+)/.exec(text(dir, "host/env.txt"));
  const entrypoint = join(dir, "src/entrypoint.sh");
  return {
    hostId,
    hostIdentity: text(dir, "host-identity.txt").trim(),
    image: {
      reference: procedure.image,
      id: firstToken(imageLine),
      repoDigests,
      platform: imageLine.slice(lastSpace + 1),
    },
    subject: {
      head,
      zkvmGuestTree: guestTree,
      zkvmHostTree: hostTree,
      guestLockAtHead: firstToken(text(dir, "src/guest-lock-at-head.txt")),
      sourceManifest: text(dir, "host/source-sha256.txt")
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .map((l) => ({ path: l.split(/\s+/)[1], sha256: l.split(/\s+/)[0] })),
    },
    entrypoint: {
      path: procedure.entrypoint.path,
      sha256: existsSync(entrypoint) ? sha256File(entrypoint) : "missing",
    },
    containerExit: exit ? Number(exit[1]) : -1,
    buildSeconds: seconds ? Number(seconds[1]) : null,
    guestLockBefore: firstToken(text(dir, "host/lock-before.txt")),
    guestLockAfter: firstToken(text(dir, "host/lock-after.txt")),
    programs: {
      [WITHDRAWAL]: {
        elfSha256: shas[WITHDRAWAL] ?? "",
        elfBytes: sizes[WITHDRAWAL] ?? 0,
        vkey: vkeyOf("host/vkey.stdout"),
      },
      [ACVP]: { elfSha256: shas[ACVP] ?? "", elfBytes: sizes[ACVP] ?? 0, vkey: vkeyOf("host/acvp-vkey.stdout") },
    },
    hostBinarySha256: firstToken(text(dir, "host/host-bin-sha256.txt")) || null,
  };
}

/** The outside recompute's key=value record (one line per fact); a program whose output names no key has no result. */
export function parseVkeyRecompute(record: string): VkeyRecompute {
  const fields = new Map<string, string>();
  for (const line of record.split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at > 0) fields.set(line.slice(0, at), line.slice(at + 1).trim());
  }
  const results: VkeyRecompute["results"] = [];
  for (const program of [WITHDRAWAL, ACVP]) {
    const elfSha256 = fields.get(`elf_${program}_sha256`);
    const vkey = /0x[0-9a-f]{64}/.exec(fields.get(`vkey_output_${program}`) ?? "")?.[0];
    if (elfSha256 && vkey) results.push({ program, elfSha256, vkey });
  }
  return {
    tool: fields.get("tool_version") ?? "",
    toolSha256: fields.get("tool_sha256") ?? "",
    ranOn: fields.get("ran_on") ?? "",
    results,
  };
}

type Kind = "IDENTITY" | "PROCEDURE" | "HOSTS";

function classified(obs: CanonicalBuildObservation, d: ProgramDesignation, minimumHosts: number): [Kind, string][] {
  const out: [Kind, string][] = [];
  if (obs?.schema !== CANONICAL_BUILD_SCHEMA)
    out.push(["PROCEDURE", `the observation's schema must be ${CANONICAL_BUILD_SCHEMA}`]);
  if (obs?.designation !== d.id) out.push(["PROCEDURE", `the observation is not of designation ${d.id}`]);
  const builds = Array.isArray(obs?.builds) ? obs.builds : [];
  const hosts = new Set(builds.map((b) => b.hostId));
  if (builds.length < minimumHosts || hosts.size < minimumHosts) {
    out.push(["HOSTS", `the rebuild needs ${minimumHosts} distinct hosts, it has ${hosts.size}`]);
  }
  const lock = d.subject.guestCargoLockSha256;
  for (const b of builds) {
    const at = `the build on ${b.hostId}`;
    if (b.containerExit !== 0) out.push(["PROCEDURE", `${at} exited ${b.containerExit}`]);
    if (b.image?.reference !== d.procedure.image || !(b.image?.repoDigests ?? []).includes(d.procedure.image)) {
      out.push(["PROCEDURE", `${at} did not run the image pinned by digest (${d.procedure.image})`]);
    }
    if (b.image?.platform !== d.procedure.platform)
      out.push(["PROCEDURE", `${at} ran on platform ${b.image?.platform}`]);
    if (b.entrypoint?.sha256 !== d.procedure.entrypoint.sha256) {
      out.push(["PROCEDURE", `${at} ran another entrypoint (${b.entrypoint?.sha256})`]);
    }
    if (
      b.subject?.zkvmGuestTree !== d.subject.zkvmGuestTree ||
      b.subject?.zkvmHostTree !== d.subject.zkvmHostTree ||
      sourceManifestDigest(b.subject?.sourceManifest ?? []) !== d.subject.sourceManifestSha256
    ) {
      out.push(["PROCEDURE", `${at} built another subject than ${d.id}'s`]);
    }
    if (b.subject?.guestLockAtHead !== lock || b.guestLockBefore !== lock || b.guestLockAfter !== lock) {
      out.push(["PROCEDURE", `${at}: the guest lockfile must be the subject's (${lock}) before and after the build`]);
    }
    const w = b.programs?.[WITHDRAWAL];
    if (w?.elfSha256 !== d.elf.sha256 || w?.elfBytes !== d.elf.bytes) {
      out.push([
        "IDENTITY",
        `${at} produced ELF ${w?.elfSha256} (${w?.elfBytes} B), not ${d.elf.sha256} (${d.elf.bytes} B)`,
      ]);
    }
    if (w?.vkey !== d.programVKey)
      out.push(["IDENTITY", `${at}: its in-build vkey ${w?.vkey} is not ${d.programVKey}`]);
    const acvp = b.programs?.[ACVP];
    const pinNever = d.doNotPin.find((x) => x.program === ACVP);
    if (pinNever?.elfSha256 && (acvp?.elfSha256 !== pinNever.elfSha256 || acvp?.vkey !== pinNever.vkey)) {
      out.push(["IDENTITY", `${at}: the ACVP program is not the one the designation records`]);
    }
  }
  const outputs = new Set(builds.map((b) => JSON.stringify(b.programs?.[WITHDRAWAL] ?? null)));
  if (outputs.size > 1) out.push(["IDENTITY", "the hosts disagree on the withdrawal ELF or vkey"]);
  const results = (obs?.vkeyRecompute?.results ?? []).filter(
    (r) => r.program === WITHDRAWAL && r.elfSha256 === d.elf.sha256,
  );
  const agreeing = results.filter((r) => r.vkey === d.programVKey).length;
  if (results.length > agreeing)
    out.push(["IDENTITY", "one ELF maps to two vkeys in the outside recompute (PROGRAM_IDENTITY_CONTRADICTION)"]);
  else if (agreeing < 1)
    out.push(["IDENTITY", "the vkey was not recomputed outside the build from the designated ELF"]);
  return out;
}

/** Every way the observation departs from the designation; empty when it reproduces it on enough hosts. */
export function canonicalBuildErrors(
  obs: CanonicalBuildObservation,
  d: ProgramDesignation,
  options: { minimumHosts: number },
): string[] {
  return classified(obs, d, options.minimumHosts).map(([, message]) => message);
}

/** The verdict: identity drift outranks procedure drift, which outranks too few hosts. */
export function canonicalBuildVerdict(
  obs: CanonicalBuildObservation,
  d: ProgramDesignation,
  options: { minimumHosts: number },
): CanonicalBuildVerdict {
  const kinds = new Set(classified(obs, d, options.minimumHosts).map(([kind]) => kind));
  if (kinds.has("IDENTITY")) return "PROGRAM_IDENTITY_DRIFT";
  if (kinds.has("PROCEDURE")) return "PROCEDURE_DRIFT";
  if (kinds.has("HOSTS")) return "INSUFFICIENT_HOSTS";
  return "REPRODUCED";
}

/** What every host has in common, recorded with each observation. */
export const COMMON_MODE = [
  "every host runs the same vendor image (by digest), toolchain, source archive (git archive of one commit) and entrypoint",
  "every host fetches the same locked crate set from crates.io",
  "the outside recompute runs Succinct's released cargo-prove: another binary distribution of the same sp1-prover library, not an independent implementation",
  "hosts agreeing shows the procedure is deterministic on linux/amd64; it cannot show that the image or the prover is right",
];
