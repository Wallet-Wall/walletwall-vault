/**
 * The canonical build, checked against the designation (the SP1 implementation lane;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * scripts/sp1-canonical/canonical-build.sh runs SP1-TD1's canonical procedure (PINNED_VENDOR_BUILD: the repository's
 * host flow in a fresh container of the vendor image pinned by digest, SP1-TD1's preserved entrypoint unchanged) and
 * records what ran and what it produced; the vkey is then recomputed from each ELF outside every build, with Succinct's
 * released cargo-prove. This module derives an observation from those records and compares it with the designation:
 *
 *   PROGRAM_IDENTITY_DRIFT — a completed build's ELF, its size, its in-build vkey or its ACVP program differ, two
 *     hosts disagree, or the outside recompute gives one ELF two vkeys. Rebuilding the frozen subject must reproduce
 *     the designation; otherwise the lane STOPs.
 *   PROCEDURE_DRIFT — a build recorded another image (a mutable tag), platform, entrypoint, subject, driver or
 *     designation, its record names another host, or the guest lockfile was not the subject's before and after the
 *     build (TD1-N7).
 *   INCOMPLETE — a record is absent: a build that failed (its container exited non-zero), an output never copied, an
 *     image never pulled, a recompute that never ran. A liveness failure (review finding L-4): nothing is judged from
 *     it, and it is never read as drift.
 *   INSUFFICIENT_HOSTS — fewer distinct machines than required (the release rebuild requires two). Hosts are told
 *     apart by what each recorded about itself, not by the label it was given (F3).
 *
 * An absent record is INCOMPLETE; a present record that differs is drift. Identity outranks procedure, which outranks
 * an incomplete build, which outranks too few hosts.
 *
 * Committed evidence (F3): the observation sits next to the raw records it is derived from (recordsDirOf), names the
 * driver and the checker that made it by sha256, and canonicalRebuildEvidenceErrors re-derives it from those records
 * with this tree's checker and requires both tools to be this tree's. A local observation is still self-attested: the
 * records are what the driver wrote on one machine. A CI observation carries the run id in each host identity, and its
 * artifacts can be compared with GitHub's copy of that run.
 *
 * Common mode, stated rather than hidden: every host runs the same vendor image, toolchain, source archive and
 * entrypoint, fetches the same locked crates, and is operated the same way; the outside recompute runs the same
 * upstream prover library (a different binary distribution, not an independent implementation). Two hosts agreeing
 * shows the procedure is deterministic on that platform; it cannot show the image or the prover is right.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

import { sourceManifestDigest } from "./sp1-p1-stop-receipt";
import type { FileDigest, ProgramDesignation } from "./sp1-designation";

export const CANONICAL_BUILD_SCHEMA = "walletwall.sp1-canonical-build.v2";
export const CANONICAL_REBUILD_OBSERVATION_REL =
  "evidence/zk/sp1-impl/observations/canonical-rebuild-developer-workstation.raw.json";
/** The driver that runs the build and writes the records, and the checker that derives the observation from them. */
export const CANONICAL_DRIVER_REL = "scripts/sp1-canonical/canonical-build.sh";
export const CANONICAL_CHECKER_RELS = ["scripts/check-sp1-canonical-build.ts", "scripts/lib/sp1-canonical-build.ts"];
/** The files of a build's directory the observation is derived from: the evidence (ELFs and the archive are not). */
export const CANONICAL_BUILD_RECORDS = [
  "driver.txt",
  "host-identity.txt",
  "docker-info.txt",
  "image.txt",
  "src/git-ids.txt",
  "src/guest-lock-at-head.txt",
  "host/run.log",
  "host/env.txt",
  "host/elf-sha256.txt",
  "host/elf-size.txt",
  "host/vkey.stdout",
  "host/acvp-vkey.stdout",
  "host/lock-before.txt",
  "host/lock-after.txt",
  "host/host-bin-sha256.txt",
  "host/source-sha256.txt",
];
const WITHDRAWAL = "mldsa65-withdrawal";
const ACVP = "mldsa65-acvp";

export interface ProgramOutput {
  elfSha256: string;
  elfBytes: number;
  vkey: string;
}

export interface ToolDigest {
  script: string;
  scriptSha256: string;
}

export interface CanonicalBuild {
  hostId: string;
  /** What the driver recorded about the machine, first line `host_id=<hostId>`. */
  hostIdentity: string;
  dockerInfo: string;
  /** What ran, as the driver recorded it: its own sha256, the designation file, its start and finish. */
  driver: { scriptSha256: string; designation: string; startedUtc: string; finishedUtc: string };
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
  tools: { driver: ToolDigest; checker: ToolDigest[] };
  builds: CanonicalBuild[];
  vkeyRecompute: VkeyRecompute;
  commonMode: string[];
}

export type CanonicalBuildVerdict =
  "REPRODUCED" | "PROGRAM_IDENTITY_DRIFT" | "PROCEDURE_DRIFT" | "INCOMPLETE" | "INSUFFICIENT_HOSTS";

const sha256File = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const text = (dir: string, rel: string) =>
  existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8").replace(/\r\n/g, "\n") : "";
const lines = (s: string) => s.trim().split("\n").filter(Boolean);
const firstToken = (s: string) => s.trim().split(/\s+/)[0] ?? "";
const isHex64 = (s: unknown): s is string => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const isVkey = (s: unknown): s is string => typeof s === "string" && /^0x[0-9a-f]{64}$/.test(s);
const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** A key=value record (one fact per line; the first `=` splits). */
function keyValues(record: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const line of record.split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at > 0) fields.set(line.slice(0, at), line.slice(at + 1).trim());
  }
  return fields;
}

/** One host's build, from the driver's output directory: every value as recorded, "" (or -1, 0) where none is. */
export function collectBuild(dir: string, hostId: string): CanonicalBuild {
  const driver = keyValues(text(dir, "driver.txt"));
  const [head = "", guestTree = "", hostTree = ""] = lines(text(dir, "src/git-ids.txt"));
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
    lines(text(dir, "host/elf-size.txt")).map((l) => [l.split(/\s+/)[0], Number(l.split(/\s+/)[1])]),
  );
  const shas = Object.fromEntries(
    lines(text(dir, "host/elf-sha256.txt")).map((l) => [l.split(/\s+/)[1], l.split(/\s+/)[0]]),
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
  const program = (name: string, vkeyRel: string): ProgramOutput => ({
    elfSha256: shas[name] ?? "",
    elfBytes: sizes[name] ?? 0,
    vkey: vkeyOf(vkeyRel),
  });
  return {
    hostId,
    hostIdentity: text(dir, "host-identity.txt").trim(),
    dockerInfo: text(dir, "docker-info.txt").trim(),
    driver: {
      scriptSha256: driver.get("driver_sha256") ?? "",
      designation: driver.get("designation") ?? "",
      startedUtc: driver.get("started_utc") ?? "",
      finishedUtc: driver.get("finished_utc") ?? "",
    },
    image: {
      reference: driver.get("image") ?? "",
      id: firstToken(imageLine),
      repoDigests,
      platform: lastSpace > 0 ? imageLine.slice(lastSpace + 1) : "",
    },
    subject: {
      head,
      zkvmGuestTree: guestTree,
      zkvmHostTree: hostTree,
      guestLockAtHead: firstToken(text(dir, "src/guest-lock-at-head.txt")),
      sourceManifest: lines(text(dir, "host/source-sha256.txt")).map((l) => ({
        path: l.split(/\s+/)[1],
        sha256: l.split(/\s+/)[0],
      })),
    },
    entrypoint: { path: driver.get("entrypoint") ?? "", sha256: driver.get("entrypoint_sha256") ?? "" },
    containerExit: exit ? Number(exit[1]) : -1,
    buildSeconds: seconds ? Number(seconds[1]) : null,
    guestLockBefore: firstToken(text(dir, "host/lock-before.txt")),
    guestLockAfter: firstToken(text(dir, "host/lock-after.txt")),
    programs: { [WITHDRAWAL]: program(WITHDRAWAL, "host/vkey.stdout"), [ACVP]: program(ACVP, "host/acvp-vkey.stdout") },
    hostBinarySha256: firstToken(text(dir, "host/host-bin-sha256.txt")) || null,
  };
}

/** The outside recompute's key=value record (one line per fact); a program whose output names no key has no result. */
export function parseVkeyRecompute(record: string): VkeyRecompute {
  const fields = keyValues(record);
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

/** The driver and the checker of this tree, by sha256. */
export function canonicalToolDigests(repoRoot = "."): CanonicalBuildObservation["tools"] {
  const digest = (script: string): ToolDigest => ({ script, scriptSha256: sha256File(resolve(repoRoot, script)) });
  return { driver: digest(CANONICAL_DRIVER_REL), checker: CANONICAL_CHECKER_RELS.map(digest) };
}

const byResult = (a: VkeyRecompute["results"][number], b: VkeyRecompute["results"][number]) =>
  `${a.program} ${a.elfSha256} ${a.vkey}`.localeCompare(`${b.program} ${b.elfSha256} ${b.vkey}`);

/** The observation, from the collected builds and the recompute records: a function of them and the tools alone. */
export function deriveCanonicalObservation(input: {
  designation: string;
  builds: CanonicalBuild[];
  recomputes: VkeyRecompute[];
  tools: CanonicalBuildObservation["tools"];
}): CanonicalBuildObservation {
  if (input.recomputes.length === 0) {
    throw new Error("a recompute record is required: the vkey is recomputed outside the build");
  }
  const ran = new Set(input.recomputes.map((r) => JSON.stringify([r.tool, r.toolSha256, r.ranOn])));
  if (ran.size !== 1) {
    throw new Error(
      "the outside recomputes ran different tools or on different machines: record them as separate observations",
    );
  }
  const finished = input.builds
    .map((b) => b.driver.finishedUtc)
    .filter(Boolean)
    .sort();
  const [{ tool, toolSha256, ranOn }] = input.recomputes;
  return {
    schema: CANONICAL_BUILD_SCHEMA,
    measuredAtUtc: finished[finished.length - 1] ?? "",
    designation: input.designation,
    tools: input.tools,
    builds: input.builds,
    vkeyRecompute: { tool, toolSha256, ranOn, results: input.recomputes.flatMap((r) => r.results).sort(byResult) },
    commonMode: [...COMMON_MODE],
  };
}

/** Where an observation's raw records are: next to it, its path without `.raw.json`. */
export const recordsDirOf = (observationRel: string) => observationRel.replace(/\.raw\.json$/, "");

/**
 * Copies each build's records (CANONICAL_BUILD_RECORDS, those that exist) to `<dir>/builds/<host-id>/`, and each
 * recompute record to `<dir>/vkey-recompute/<its file name>`: the committed evidence's layout.
 */
export function writeCanonicalRecords(
  dir: string,
  builds: { hostId: string; dir: string }[],
  recomputeFiles: string[],
): void {
  for (const b of builds) {
    for (const rel of CANONICAL_BUILD_RECORDS) {
      const from = join(b.dir, rel);
      if (!existsSync(from)) continue;
      const to = join(dir, "builds", b.hostId, rel);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(from, to);
    }
  }
  for (const file of recomputeFiles) {
    mkdirSync(join(dir, "vkey-recompute"), { recursive: true });
    copyFileSync(file, join(dir, "vkey-recompute", basename(file)));
  }
}

const filesUnder = (dir: string): string[] =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });

/** A stable serialization (sorted keys), so two equal observations compare equal whatever their key order. */
const stable = (x: unknown): string =>
  Array.isArray(x)
    ? `[${x.map(stable).join(",")}]`
    : x !== null && typeof x === "object"
      ? `{${Object.keys(x)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${stable((x as Record<string, unknown>)[k])}`)
          .join(",")}}`
      : JSON.stringify(x);

/**
 * Every way the committed observation is not what this tree's checker derives from the committed raw records, or
 * names a driver or checker that is not this tree's (F3). Empty when it is: the observation then says what the
 * records say, and nothing more (the records themselves are what the driver wrote on the machine that ran it).
 */
export function canonicalRebuildEvidenceErrors(
  repoRoot = ".",
  observationRel = CANONICAL_REBUILD_OBSERVATION_REL,
): string[] {
  const path = resolve(repoRoot, observationRel);
  if (!existsSync(path)) return [`no observation at ${observationRel}`];
  let committed: CanonicalBuildObservation;
  let tools: CanonicalBuildObservation["tools"];
  try {
    committed = JSON.parse(readFileSync(path, "utf8")) as CanonicalBuildObservation;
    tools = canonicalToolDigests(repoRoot);
  } catch (error) {
    return [`cannot read ${observationRel} or this tree's canonical-build tools: ${message(error)}`];
  }
  const errors: string[] = [];
  const named = committed?.tools;
  if (named?.driver?.script !== tools.driver.script || named?.driver?.scriptSha256 !== tools.driver.scriptSha256) {
    errors.push(
      `the driver ${tools.driver.script} the observation names (sha256 ${String(named?.driver?.scriptSha256)}) is ` +
        `not this tree's (${tools.driver.scriptSha256}): re-run the canonical build`,
    );
  }
  for (const t of tools.checker) {
    const n = (Array.isArray(named?.checker) ? named.checker : []).find((x) => x?.script === t.script);
    if (n?.scriptSha256 !== t.scriptSha256) {
      errors.push(
        `the checker ${t.script} the observation names (sha256 ${String(n?.scriptSha256)}) is not this tree's ` +
          `(${t.scriptSha256}): re-derive the observation from its raw records`,
      );
    }
  }
  const recordsRel = recordsDirOf(observationRel);
  const records = resolve(repoRoot, recordsRel);
  if (!existsSync(join(records, "builds")) || !existsSync(join(records, "vkey-recompute"))) {
    errors.push(
      `the raw records of ${observationRel} are missing (${recordsRel}/builds, ${recordsRel}/vkey-recompute)`,
    );
    return errors;
  }
  const hostIds = (Array.isArray(committed?.builds) ? committed.builds : []).map((b) => String(b?.hostId));
  const hostDirs = readdirSync(join(records, "builds")).sort();
  if (stable([...hostIds].sort()) !== stable(hostDirs)) {
    errors.push(`the raw records hold the builds of [${hostDirs.join(", ")}], the observation [${hostIds.join(", ")}]`);
  }
  for (const file of filesUnder(join(records, "builds"))) {
    const rel = relative(join(records, "builds"), file).replace(/\\/g, "/").split("/").slice(1).join("/");
    if (!CANONICAL_BUILD_RECORDS.includes(rel)) {
      errors.push(`${relative(resolve(repoRoot), file).replace(/\\/g, "/")} is no record the driver writes`);
    }
  }
  const recomputeFiles = readdirSync(join(records, "vkey-recompute"))
    .filter((f) => f.endsWith(".txt"))
    .sort()
    .map((f) => join(records, "vkey-recompute", f));
  try {
    const derived = deriveCanonicalObservation({
      designation: String(committed?.designation),
      builds: hostIds.map((hostId) => collectBuild(join(records, "builds", hostId), hostId)),
      recomputes: recomputeFiles.map((f) => parseVkeyRecompute(readFileSync(f, "utf8"))),
      tools,
    });
    if (stable(derived) !== stable(committed)) {
      errors.push(
        `${observationRel} is not what this tree's checker derives from the committed raw records (${recordsRel}): ` +
          "re-derive it (scripts/check-sp1-canonical-build.ts --records)",
      );
    }
  } catch (error) {
    errors.push(
      `${observationRel} cannot be re-derived from the committed raw records (${recordsRel}): ${message(error)}`,
    );
  }
  return errors;
}

type Kind = "IDENTITY" | "PROCEDURE" | "INCOMPLETE" | "HOSTS";

/**
 * What a host's driver measured about its machine: its kernel, its CPU and its Docker engine. Never the label it was
 * given (host_id) or what it read from its environment (runner=, run=): one machine run twice, under any names, is one
 * host (the re-review's A1). Empty when it measured nothing.
 */
const machineOf = (b: CanonicalBuild): string => {
  const measured = String(b?.hostIdentity ?? "")
    .split("\n")
    .slice(1)
    .filter((line) => line.trim() !== "" && !/^(runner|run)=/.test(line));
  const docker = String(b?.dockerInfo ?? "").trim();
  return measured.length === 0 && docker === "" ? "" : JSON.stringify([...measured, docker]);
};

function classified(obs: CanonicalBuildObservation, d: ProgramDesignation, minimumHosts: number): [Kind, string][] {
  const out: [Kind, string][] = [];
  const push = (kind: Kind, why: string) => out.push([kind, why]);
  if (obs?.schema !== CANONICAL_BUILD_SCHEMA)
    push("PROCEDURE", `the observation's schema must be ${CANONICAL_BUILD_SCHEMA}`);
  if (obs?.designation !== d.id) push("PROCEDURE", `the observation is not of designation ${d.id}`);
  const driver = obs?.tools?.driver?.scriptSha256;
  if (!isHex64(driver)) push("PROCEDURE", "the observation names no driver (tools.driver)");
  const builds = Array.isArray(obs?.builds) ? obs.builds : [];
  const machines = new Set(builds.map(machineOf).filter((m) => m !== ""));
  if (!(builds.length >= minimumHosts && machines.size >= minimumHosts)) {
    push("HOSTS", `the rebuild needs ${minimumHosts} distinct hosts, it has ${machines.size}`);
  }
  const lock = d.subject.guestCargoLockSha256;
  const acvpPin = d.doNotPin.find((x) => x.program === ACVP);
  for (const b of builds) {
    const at = `the build on ${b?.hostId}`;
    const named = String(b?.hostIdentity ?? "").split("\n")[0];
    if (!b?.hostIdentity) push("INCOMPLETE", `${at} recorded no host identity`);
    else if (machineOf(b) === "") push("INCOMPLETE", `${at} recorded no machine (kernel, CPU, Docker engine)`);
    else if (named !== `host_id=${b.hostId}`) push("PROCEDURE", `the build record of ${b.hostId} names ${named}`);
    if (!isHex64(b?.driver?.scriptSha256)) push("INCOMPLETE", `${at} recorded no driver digest`);
    else if (isHex64(driver) && b.driver.scriptSha256 !== driver) {
      push("PROCEDURE", `${at} ran another driver (${b.driver.scriptSha256}) than the observation names (${driver})`);
    }
    if (!b?.driver?.designation) push("INCOMPLETE", `${at} recorded no designation`);
    else if (b.driver.designation.split(/[\\/]/).pop() !== `${d.id}.json`) {
      push("PROCEDURE", `${at} ran under designation ${b.driver.designation}, not ${d.id}`);
    }
    const image = b?.image;
    if (!image?.id || !image?.reference || !image?.platform) {
      push("INCOMPLETE", `${at} recorded no image (the reference it ran, its id and its platform)`);
    } else {
      if (image.reference !== d.procedure.image || !(image.repoDigests ?? []).includes(d.procedure.image)) {
        push("PROCEDURE", `${at} did not run the image pinned by digest (${d.procedure.image})`);
      }
      if (image.platform !== d.procedure.platform) push("PROCEDURE", `${at} ran on platform ${image.platform}`);
    }
    if (!isHex64(b?.entrypoint?.sha256)) push("INCOMPLETE", `${at} recorded no entrypoint digest`);
    else if (b.entrypoint.sha256 !== d.procedure.entrypoint.sha256) {
      push("PROCEDURE", `${at} ran another entrypoint (${b.entrypoint.sha256})`);
    }
    const s = b?.subject;
    if (!s?.zkvmGuestTree || !s?.zkvmHostTree || !(Array.isArray(s?.sourceManifest) && s.sourceManifest.length > 0)) {
      push("INCOMPLETE", `${at} recorded no subject (its trees and its source manifest)`);
    } else if (
      s.zkvmGuestTree !== d.subject.zkvmGuestTree ||
      s.zkvmHostTree !== d.subject.zkvmHostTree ||
      sourceManifestDigest(s.sourceManifest) !== d.subject.sourceManifestSha256
    ) {
      push("PROCEDURE", `${at} built another subject than ${d.id}'s`);
    }
    const locks = [s?.guestLockAtHead, b?.guestLockBefore, b?.guestLockAfter];
    if (!locks.every(isHex64)) push("INCOMPLETE", `${at} recorded no guest lockfile digest at HEAD, before and after`);
    else if (locks.some((x) => x !== lock)) {
      push("PROCEDURE", `${at}: the guest lockfile must be the subject's (${lock}) before and after the build`);
    }
    // Nothing is judged from the outputs of a build that did not complete.
    if (b?.containerExit !== 0) {
      push(
        "INCOMPLETE",
        b?.containerExit === -1
          ? `${at} did not complete (no container exit recorded)`
          : `${at} did not complete (container exit ${b?.containerExit})`,
      );
      continue;
    }
    const w = b.programs?.[WITHDRAWAL];
    if (!isHex64(w?.elfSha256) || !(Number(w?.elfBytes) > 0)) push("INCOMPLETE", `${at} recorded no withdrawal ELF`);
    else if (w.elfSha256 !== d.elf.sha256 || w.elfBytes !== d.elf.bytes) {
      push("IDENTITY", `${at} produced ELF ${w.elfSha256} (${w.elfBytes} B), not ${d.elf.sha256} (${d.elf.bytes} B)`);
    }
    if (!isVkey(w?.vkey)) push("INCOMPLETE", `${at} recorded no in-build vkey`);
    else if (w.vkey !== d.programVKey) push("IDENTITY", `${at}: its in-build vkey ${w.vkey} is not ${d.programVKey}`);
    if (acvpPin?.elfSha256) {
      const a = b.programs?.[ACVP];
      if (!isHex64(a?.elfSha256) || !isVkey(a?.vkey)) push("INCOMPLETE", `${at} recorded no ACVP output`);
      else if (a.elfSha256 !== acvpPin.elfSha256 || a.vkey !== acvpPin.vkey) {
        push("IDENTITY", `${at}: the ACVP program is not the one the designation records`);
      }
    }
  }
  const outputs = new Set(
    builds
      .filter((b) => b?.containerExit === 0 && isHex64(b.programs?.[WITHDRAWAL]?.elfSha256))
      .map((b) => {
        const w = b.programs[WITHDRAWAL];
        return `${w.elfSha256} ${w.elfBytes} ${w.vkey}`;
      }),
  );
  if (outputs.size > 1) push("IDENTITY", "the hosts disagree on the withdrawal ELF or vkey");
  const recompute = obs?.vkeyRecompute;
  // A recompute is of these builds' ELFs: one of an ELF no completed build produced is another procedure's (L2).
  for (const program of [WITHDRAWAL, ACVP]) {
    const built = new Set(
      builds
        .filter((b) => b?.containerExit === 0)
        .map((b) => b.programs?.[program]?.elfSha256)
        .filter(isHex64),
    );
    if (built.size === 0) continue;
    for (const r of Array.isArray(recompute?.results) ? recompute.results : []) {
      if (r?.program === program && isHex64(r.elfSha256) && !built.has(r.elfSha256)) {
        push("PROCEDURE", `the outside recompute ran on ELF ${r.elfSha256}, which no build produced`);
      }
    }
  }
  if (!isHex64(recompute?.toolSha256)) push("INCOMPLETE", "the outside recompute names no tool digest");
  const results = (Array.isArray(recompute?.results) ? recompute.results : []).filter(
    (r) => r?.program === WITHDRAWAL && r.elfSha256 === d.elf.sha256 && isVkey(r.vkey),
  );
  const agreeing = results.filter((r) => r.vkey === d.programVKey).length;
  if (results.length > agreeing) {
    push("IDENTITY", "one ELF maps to two vkeys in the outside recompute (PROGRAM_IDENTITY_CONTRADICTION)");
  } else if (agreeing < 1) {
    push("INCOMPLETE", "the vkey was not recomputed outside the build from the designated ELF");
  }
  return out;
}

/** Every way the observation departs from the designation; empty when it reproduces it on enough hosts. */
export function canonicalBuildErrors(
  obs: CanonicalBuildObservation,
  d: ProgramDesignation,
  options: { minimumHosts: number },
): string[] {
  return classified(obs, d, options.minimumHosts).map(([, why]) => why);
}

/** The verdict: identity drift outranks procedure drift, which outranks an incomplete build, then too few hosts. */
export function canonicalBuildVerdict(
  obs: CanonicalBuildObservation,
  d: ProgramDesignation,
  options: { minimumHosts: number },
): CanonicalBuildVerdict {
  const kinds = new Set(classified(obs, d, options.minimumHosts).map(([kind]) => kind));
  if (kinds.has("IDENTITY")) return "PROGRAM_IDENTITY_DRIFT";
  if (kinds.has("PROCEDURE")) return "PROCEDURE_DRIFT";
  if (kinds.has("INCOMPLETE")) return "INCOMPLETE";
  if (kinds.has("HOSTS")) return "INSUFFICIENT_HOSTS";
  return "REPRODUCED";
}

/**
 * How many times the designated ELF was given another vkey: by a completed build, or by the outside recompute. A
 * vkey that is absent, or left by a build that did not complete, is no conflicting vkey (L-4).
 */
export function conflictingVkeyCount(obs: CanonicalBuildObservation, d: ProgramDesignation): number {
  const other = (p: { elfSha256?: string; vkey?: string } | undefined) =>
    p?.elfSha256 === d.elf.sha256 && isVkey(p.vkey) && p.vkey !== d.programVKey;
  const results = Array.isArray(obs?.vkeyRecompute?.results) ? obs.vkeyRecompute.results : [];
  const builds = Array.isArray(obs?.builds) ? obs.builds : [];
  return (
    results.filter(other).length +
    builds.filter((b) => b?.containerExit === 0 && Object.values(b.programs ?? {}).some(other)).length
  );
}

/** What every host has in common, recorded with each observation. */
export const COMMON_MODE = [
  "every host runs the same vendor image (by digest), toolchain, source archive (git archive of one commit) and entrypoint",
  "every host fetches the same locked crate set from crates.io",
  "the outside recompute runs Succinct's released cargo-prove: another binary distribution of the same sp1-prover library, not an independent implementation",
  "hosts agreeing shows the procedure is deterministic on linux/amd64; it cannot show that the image or the prover is right",
];
