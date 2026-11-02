/**
 * SP1-PA3C-Q1: observer qualification before SP1-PA3D (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md,
 * "SP1-PA3C-Q1"). No proof is made, downloaded or pretended here; nothing about SP1-PA3B's evidence changes; and
 * PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED whatever this lane concludes. The question is narrower: is the egress
 * observer's path (scripts/sp1-egress-observer.ts capturing, scripts/lib/sp1-egress-attribution.ts deriving) stable,
 * reproducible, isolated and inspectable enough to carry the next controlled experiment?
 *
 * Two layers, kept apart as the observer keeps them:
 *  - the kernel capture is host-bound (root, tracefs, nftables): it can only be soaked where it runs, and every capture
 *    is its own (nonce, boot, pids, stamps). A soak asks whether what the evidence model says must be stable is stable
 *    across many captures, and records what varies by name instead of normalizing it away. Two soaks are told apart by
 *    their boundary: the self-test table (TEST-NET-1 and the resolvers refused, nothing else: the integration test's,
 *    under which another process's real egress rightly reads as a leak) and the complete egress boundary (everything
 *    but the host itself refused and counted: the one SP1-PA3B ran under and SP1-PA3D will);
 *  - the derivation is pure: the same raw bytes and the same host-executable identity must give the same normalized
 *    evidence and the same judgement anywhere Node runs. The reconciliation asks for byte equality of every derived
 *    field between the proving host and a clean container, and classes only environment identity as expected to differ.
 *
 * Everything the record states is recomputed by its validator from the committed observation, the committed fixture and
 * the committed observer: a measurement never grades itself. Research prototype. Not audited.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  OBSERVER_MECHANISM,
  OBSERVER_SCRIPT_REL,
  SELF_TEST_WORKLOAD_REL,
  canonicalJson,
  sha256Hex,
} from "../sp1-egress-observer";
import {
  assuranceOf,
  normalizeObserverRaw,
  observerEvidenceErrors,
  reconcile,
  type Attribution,
  type HostExecutable,
  type ObserverEvidence,
  type ObserverExpectations,
  type RawEvidence,
  type Refusal,
} from "./sp1-egress-attribution";

export const LANE = "SP1-PA3C-Q1";
export const NEXT_LANE = "SP1-PA3D";
export const REPOSITORY_ID = "Wallet-Wall/walletwall-vault";
/** Whatever this lane concludes, no production SP1 binding exists; the record carries this literally. */
export const PRODUCTION_SP1_BINDING = "NOT_ESTABLISHED";
export const QUALIFICATION_SCHEMA = "walletwall.sp1-observer-qualification.v1";
export const OBSERVATION_SCHEMA = "walletwall.sp1-observer-qualification-observation.v1";
export const DERIVATION_SCHEMA = "walletwall.sp1-observer-derivation.v1";
export const SOAK_SCHEMA = "walletwall.sp1-observer-soak.v1";
export const QUALIFICATION_REL = "evidence/zk/sp1-impl/observer-qualification.json";
export const QUALIFICATION_JSON_SCHEMA_REL = "evidence/zk/schema/sp1-observer-qualification.v1.schema.json";
export const OBSERVATIONS_DIR_REL = "evidence/zk/sp1-impl/observations";
export const OBSERVATION_PREFIX = "observer-qualification-";
export const FIXTURE_DIR_REL = "test/fixtures/sp1-egress-observer/selftest-capture";
/** The stand-in host the committed self-test capture's workload executed, as stat named it on that host. */
export const FIXTURE_HOST_EXECUTABLE: HostExecutable = {
  path: "/opt/node/node-v24.16.0-linux-x64/bin/node",
  dev: "8:48",
  ino: 1021,
};
export const SELF_TEST_RUN = { commit: "0".repeat(40), host: "self-test" };
export const SELF_TEST_PROBES: ObserverExpectations["probes"] = [
  { phase: "before", kind: "tcp", target: "192.0.2.10:443" },
  { phase: "after", kind: "tcp", target: "192.0.2.10:443" },
];
/** The observer's raw directory holds exactly these (sorted). */
export const RAW_FILES = ["facts.json", "manifest.json", "trace.txt"] as const;
export const STATES = [
  "OBSERVER_QUALIFIED_FOR_PA3D",
  "OBSERVER_QUALIFICATION_BLOCKED",
  "OBSERVER_TOOLING_READY_VALIDATION_PENDING",
] as const;
export type QualificationState = (typeof STATES)[number];
export const MIN_SOAK_ITERATIONS = 10;
/** The two boundaries a soak may run under; only the complete one is the boundary SP1-PA3D runs under. */
export const SOAK_BOUNDARIES = ["SELF_TEST_TABLE", "COMPLETE_EGRESS_BOUNDARY"] as const;
export type SoakBoundary = (typeof SOAK_BOUNDARIES)[number];

/**
 * Which boundary a soak ran under, from the rules its runner installed (a label is never trusted): the self-test
 * table refuses TEST-NET-1 (twice: TCP with a reset, the rest) and nothing else; the complete boundary accepts the
 * host's own addresses and refuses and counts everything else at the output hook and drops every forwarded packet.
 */
export function boundaryOfRules(rules: string): SoakBoundary {
  const selfTest =
    rules.includes("ip daddr 192.0.2.0/24 meta l4proto tcp counter reject with tcp reset") &&
    rules.includes("ip daddr 192.0.2.0/24 counter reject") &&
    !rules.includes("fib daddr type local accept") &&
    !rules.includes("hook forward");
  const complete =
    rules.includes("fib daddr type local accept") &&
    rules.includes("meta l4proto tcp counter reject with tcp reset") &&
    rules.includes("meta l4proto udp counter reject") &&
    /\n\s+counter reject with icmpx admin-prohibited\n/.test(rules) &&
    rules.includes("hook forward") &&
    /\n\s+counter drop\n/.test(rules) &&
    !rules.includes("192.0.2.0/24");
  if (selfTest && !complete) return "SELF_TEST_TABLE";
  if (complete && !selfTest) return "COMPLETE_EGRESS_BOUNDARY";
  throw new Error("the table's rules are neither the self-test table nor the complete egress boundary");
}
export const CLI_SCRIPT_REL = "scripts/sp1-observer-qualification.ts";
export const SOAK_SCRIPT_REL = "scripts/sp1-observer-soak.ts";
export const GENERATOR_REL = "scripts/generate-sp1-observer-qualification.ts";
export const CONTAINER_SCRIPT_REL = "scripts/sp1-observer-qualification/container-derive.sh";
export const LOADER_REL = "scripts/sp1-observer-qualification/node-ts-loader.mjs";
export const HOOK_REL = "scripts/sp1-observer-qualification/node-ts-resolve-hook.mjs";
/** Every repository-controlled byte the observer path and this qualification execute or read: pinned by sha256. */
export const REPOSITORY_PINNED_COMPONENTS: readonly string[] = [
  OBSERVER_SCRIPT_REL,
  "scripts/lib/sp1-egress-attribution.ts",
  SELF_TEST_WORKLOAD_REL,
  `${FIXTURE_DIR_REL}/trace.txt`,
  `${FIXTURE_DIR_REL}/facts.json`,
  `${FIXTURE_DIR_REL}/manifest.json`,
  "scripts/lib/sp1-observer-qualification.ts",
  CLI_SCRIPT_REL,
  SOAK_SCRIPT_REL,
  GENERATOR_REL,
  CONTAINER_SCRIPT_REL,
  LOADER_REL,
  HOOK_REL,
  QUALIFICATION_JSON_SCHEMA_REL,
];
export const COMPONENT_CLASSES = [
  "repository-pinned",
  "digest-pinned",
  "version-pinned",
  "host-dependent",
  "network-dependent",
  "mutable-external-dependency",
  "unknown-unverified",
] as const;
export type ComponentClass = (typeof COMPONENT_CLASSES)[number];

export interface SoakVariation {
  name: string;
  env: Record<string, string>;
  umask: number | null;
  /** Where the observer is started from: the checkout, or another directory (it must not matter). */
  cwd: "repo" | "/" | "/tmp";
}
/** The soak's iterations, in order (scripts/sp1-observer-soak.ts applies the same list; a test holds them equal). */
export const SOAK_VARIATIONS: readonly SoakVariation[] = [
  { name: "plain", env: {}, umask: null, cwd: "repo" },
  { name: "plain", env: {}, umask: null, cwd: "repo" },
  { name: "plain", env: {}, umask: null, cwd: "repo" },
  { name: "plain", env: {}, umask: null, cwd: "repo" },
  { name: "tz", env: { TZ: "Asia/Tokyo" }, umask: null, cwd: "repo" },
  { name: "locale", env: { LANG: "C", LC_ALL: "C" }, umask: null, cwd: "repo" },
  { name: "home", env: { HOME: "/nonexistent" }, umask: null, cwd: "repo" },
  { name: "umask-077", env: {}, umask: 0o077, cwd: "repo" },
  { name: "cwd-root", env: {}, umask: null, cwd: "/" },
  { name: "cwd-tmp", env: {}, umask: null, cwd: "/tmp" },
  { name: "plain", env: {}, umask: null, cwd: "repo" },
  { name: "plain", env: {}, umask: null, cwd: "repo" },
];

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const digestOf = (value: unknown) => sha256Hex(canonicalJson(value));

// ---------------------------------------------------------------------------------------------------------------
// One capture, derived: the normalized evidence, its judgement, and what of it must be stable
// ---------------------------------------------------------------------------------------------------------------

export function selfTestExpectations(committedObserverSha256: string): ObserverExpectations {
  return {
    observerScriptSha256: committedObserverSha256,
    mode: "SELF_TEST",
    probes: SELF_TEST_PROBES,
    gate: null,
    run: SELF_TEST_RUN,
  };
}

export interface AttemptProjection {
  scope: string;
  kind: "send" | "connect";
  probe: string;
  dest: string | null;
  outcome: string;
  qname: string | null;
  phase: string;
}

/** What the derivation establishes of one capture (facts and judgements; nothing here is asserted by the capture). */
export interface Judgement {
  refusals: Refusal[];
  assurance: ReturnType<typeof assuranceOf>;
  reconciliation: ReturnType<typeof reconcile>;
  /** [observer, tool, proof root] thread groups; null where not identified. */
  lineage: (number | null)[];
  /** The attempts of the observer's own scopes (the tool, the stand-in host): what the self-test must show. */
  ownAttempts: AttemptProjection[];
  /** Attempts by other processes on the host meanwhile (noise of a shared host, attributed but not the workload's). */
  otherScopeAttempts: number;
  ownRefusedPackets: number;
  unattributedDrops: number;
  dropClasses: Record<string, number>;
  heartbeats: number;
  leaks: number;
  /** Each leak by the scope of the attempt that made it ("FRAME" for a frame on an uplink no attempt is joined to). */
  leaksByScope: Record<string, number>;
  lostLines: number;
  statsLoss: number;
  events: number;
}

/**
 * The fields of a capture the evidence model requires to be the same across captures of one observer on one host:
 * the observer's own behaviour. The verdict (refusals, leaks) is judged beside it, per boundary, by the soak summary.
 */
export interface StableProjection {
  observer: { script: string; scriptSha256: string; mechanism: string; mode: string };
  kernelRelease: string;
  probeTemplate: string[];
  filtersTemplate: { nfdrop: string; xmit: string };
  configTemplate: { clock: string; bufferKb: number; overwrite: number; recordTgid: number; heartbeatMs: number };
  host: {
    nfDropReason: number;
    interfaceNames: string[];
    uplinkNames: string[];
    resolvers: string[];
    wslInterop: string;
  };
  table: string;
  boundaryRules: { chain: string; hook: string | null; verdict: string; expr: string }[];
  boundaryRulesStable: boolean;
  rawFiles: string[];
  lostLines: number;
  statsClean: boolean;
  lineageResolved: boolean;
  ownAttempts: AttemptProjection[];
  ownRefusedPackets: number;
  unattributedDrops: number;
  reconciliationOk: boolean;
  assurance: {
    enforcement: string;
    edgeProbes: string;
    continuousObservation: string;
    unattributedEvents: number | null;
  };
}

export interface DerivationOutput {
  normalizedSha256: string | null;
  configSha256: string | null;
  nonce: string | null;
  bootId: string | null;
  kernelRelease: string | null;
  refusals: Refusal[];
  judgement: Judgement | null;
  judgementSha256: string | null;
  stableProjection: StableProjection | null;
  stableProjectionSha256: string | null;
}

const OWN_SCOPES: readonly string[] = ["TOOL", "PROOF", "PROOF_CONTAINER"];

function rawRefusalReason(message: string): string {
  if (/manifest/.test(message)) return "RAW_NOT_BOUND";
  if (/observer failed/.test(message)) return "OBSERVER_FAILED";
  return "RAW_MALFORMED";
}

export function judgementOf(o: ObserverEvidence, a: Attribution, refusals: Refusal[]): Judgement {
  const counted = a.attempts.filter((x) => !x.delegated);
  const dropClasses: Record<string, number> = {};
  for (const d of a.drops) dropClasses[d.class] = (dropClasses[d.class] ?? 0) + 1;
  const leaksByScope: Record<string, number> = {};
  for (const l of a.leaks) {
    const scope = a.attempts.find((x) => x.i === l.i)?.scope ?? "FRAME";
    leaksByScope[scope] = (leaksByScope[scope] ?? 0) + 1;
  }
  return {
    refusals,
    assurance: assuranceOf(o, a),
    reconciliation: reconcile(a.drops, a.markers, o.boundary),
    lineage: [a.lineage.observerTgid, a.lineage.toolTgid, a.lineage.proofRoot],
    ownAttempts: counted
      .filter((x) => OWN_SCOPES.includes(x.scope))
      .map((x) => ({
        scope: x.scope,
        kind: x.kind,
        probe: x.probe,
        dest: x.dest === null ? null : `${x.dest.addr}:${x.dest.port ?? "-"}`,
        outcome: x.outcome,
        qname: x.dns?.qname ?? null,
        phase: x.phase,
      })),
    otherScopeAttempts: counted.filter((x) => !OWN_SCOPES.includes(x.scope)).length,
    ownRefusedPackets: a.drops.filter((d) => d.attempt !== null && OWN_SCOPES.includes(d.attempt.scope)).length,
    unattributedDrops: a.drops.filter((d) => d.class === "UNATTRIBUTED").length,
    dropClasses,
    heartbeats: a.heartbeats,
    leaks: a.leaks.length,
    leaksByScope,
    lostLines: o.lostLines,
    statsLoss: o.stats.reduce((s, c) => s + c.overrun + c.commitOverrun + c.droppedEvents, 0),
    events: o.events.length,
  };
}

export function stableProjectionOf(o: ObserverEvidence, j: Judgement): StableProjection {
  const nameOf = (ifindex: number) => o.host.interfaces.find((i) => i.ifindex === ifindex)?.name ?? String(ifindex);
  const identity = (rules: ObserverEvidence["boundary"][number]["rules"]) =>
    rules.map((r) => ({ chain: r.chain, hook: r.hook, verdict: r.verdict, expr: r.expr }));
  const snapshots = [...o.boundary].sort((x, y) => x.n - y.n);
  const first = identity(snapshots[0]?.rules ?? []);
  return {
    observer: { script: o.tool.script, scriptSha256: o.tool.scriptSha256, mechanism: o.mechanism, mode: o.mode },
    kernelRelease: o.kernelRelease,
    probeTemplate: o.config.probes.map((line) => line.split(`sp1obs_${o.nonce}/`).join("sp1obs_<nonce>/")),
    filtersTemplate: {
      nfdrop: o.config.filters.nfdrop,
      xmit: o.config.filters.xmit.split(String(o.host.netns)).join("<hostNetns>"),
    },
    configTemplate: {
      clock: o.config.clock,
      bufferKb: o.config.bufferKb,
      overwrite: o.config.overwrite,
      recordTgid: o.config.recordTgid,
      heartbeatMs: o.config.heartbeatMs,
    },
    host: {
      nfDropReason: o.host.nfDropReason,
      interfaceNames: o.host.interfaces.map((i) => i.name),
      uplinkNames: o.host.uplinks.map(nameOf),
      resolvers: o.host.resolvers,
      wslInterop: o.host.wslInterop,
    },
    table: o.table,
    boundaryRules: first,
    boundaryRulesStable: snapshots.length === 2 && canonicalJson(first) === canonicalJson(identity(snapshots[1].rules)),
    rawFiles: o.raw.files.map((f) => f.name).sort(),
    lostLines: o.lostLines,
    statsClean:
      o.stats.length > 0 && o.stats.every((s) => s.overrun === 0 && s.commitOverrun === 0 && s.droppedEvents === 0),
    lineageResolved: j.lineage.every((x) => x !== null),
    ownAttempts: j.ownAttempts,
    ownRefusedPackets: j.ownRefusedPackets,
    unattributedDrops: j.unattributedDrops,
    reconciliationOk: j.reconciliation.ok,
    assurance: {
      enforcement: j.assurance.enforcement,
      edgeProbes: j.assurance.edgeProbes,
      continuousObservation: j.assurance.continuousObservation,
      unattributedEvents: j.assurance.unattributedEvents,
    },
  };
}

/**
 * The derivation of one raw capture, deterministic in its three inputs: the raw bytes, the stand-in host's identity
 * and the committed observer's digest (what the capture must have been made by). A capture that does not read derives
 * nothing but the reason.
 */
export function deriveQualification(
  raw: RawEvidence,
  hostExecutable: HostExecutable,
  committedObserverSha256: string,
): DerivationOutput {
  const none: DerivationOutput = {
    normalizedSha256: null,
    configSha256: null,
    nonce: null,
    bootId: null,
    kernelRelease: null,
    refusals: [],
    judgement: null,
    judgementSha256: null,
    stableProjection: null,
    stableProjectionSha256: null,
  };
  let o: ObserverEvidence;
  try {
    o = normalizeObserverRaw(raw, hostExecutable);
  } catch (error) {
    const detail = (error as Error).message;
    return { ...none, refusals: [{ reason: rawRefusalReason(detail), detail }] };
  }
  const judged = observerEvidenceErrors(o, selfTestExpectations(committedObserverSha256));
  const judgement = judged.attribution === null ? null : judgementOf(o, judged.attribution, judged.refusals);
  const projection = judgement === null ? null : stableProjectionOf(o, judgement);
  return {
    normalizedSha256: o.normalizedSha256,
    configSha256: o.configSha256,
    nonce: o.nonce,
    bootId: o.bootId,
    kernelRelease: o.kernelRelease,
    refusals: judged.refusals,
    judgement,
    judgementSha256: judgement === null ? null : digestOf(judgement),
    stableProjection: projection,
    stableProjectionSha256: projection === null ? null : digestOf(projection),
  };
}

export interface RawDirIo {
  list: (dir: string) => string[];
  read: (name: string) => string;
}

/** The observer's raw directory: exactly its three files, read as latin1 (anything else is a mutation, refused). */
export function readRawDir(
  dir: string,
  io: RawDirIo = { list: (d) => readdirSync(d), read: (name) => readFileSync(join(dir, name), "latin1") },
): RawEvidence {
  const entries = [...io.list(dir)].sort();
  const extra = entries.filter((e) => !(RAW_FILES as readonly string[]).includes(e));
  if (extra.length > 0) throw new Error(`RAW_DIR_UNEXPECTED_FILE: ${dir} holds ${extra.join(", ")}`);
  const missing = RAW_FILES.filter((f) => !entries.includes(f));
  if (missing.length > 0) throw new Error(`RAW_DIR_INCOMPLETE: ${dir} lacks ${missing.join(", ")}`);
  return { trace: io.read("trace.txt"), facts: io.read("facts.json"), manifest: io.read("manifest.json") };
}

// ---------------------------------------------------------------------------------------------------------------
// Where a derivation ran, and of what
// ---------------------------------------------------------------------------------------------------------------

export interface ContainerIdentity {
  image: { reference: string; digest: string; id: string; nodeVersion: string; registryVerification: string };
  /** The exact `docker run` argv (options, image, command). */
  runOptions: string[];
  /** Read inside the container by the derivation itself. */
  facts: {
    uid: number;
    gid: number;
    networkInterfaces: string[];
    capEff: string;
    noNewPrivs: number;
    rootMount: string;
    env: string[];
  };
}

export interface EnvironmentIdentity {
  kind: "HOST" | "CONTAINER";
  label: string;
  platform: string;
  release: string;
  arch: string;
  node: string;
  typescriptExecution: "tsx" | "node-type-stripping";
  sourceCommit: string;
  container?: ContainerIdentity;
}

export interface InputIdentity {
  raw: { manifestSha256: string; files: { name: string; bytes: number; sha256: string }[] };
  hostExecutable: HostExecutable;
  observerScriptSha256: string;
  mode: "SELF_TEST";
}

export interface Derivation {
  schema: typeof DERIVATION_SCHEMA;
  environment: EnvironmentIdentity;
  input: InputIdentity;
  output: DerivationOutput;
}

export function inputIdentityOf(raw: RawEvidence, hostExecutable: HostExecutable, committed: string): InputIdentity {
  const manifest = JSON.parse(raw.manifest) as { files?: { name: string; bytes: number; sha256: string }[] };
  return {
    raw: {
      manifestSha256: sha256Hex(Buffer.from(raw.manifest, "latin1")),
      files: Array.isArray(manifest.files) ? manifest.files : [],
    },
    hostExecutable,
    observerScriptSha256: committed,
    mode: "SELF_TEST",
  };
}

/** The `docker run` options that take a value (so the image is the first token that is none of these). */
const VALUE_OPTIONS = new Set([
  "--network",
  "--net",
  "--cap-drop",
  "--cap-add",
  "--security-opt",
  "--user",
  "-u",
  "--pids-limit",
  "--memory",
  "-m",
  "--memory-swap",
  "--cpus",
  "-v",
  "--volume",
  "--mount",
  "--tmpfs",
  "--name",
  "--env",
  "-e",
  "--env-file",
  "--workdir",
  "-w",
  "--entrypoint",
  "--label",
  "-l",
  "--hostname",
  "-h",
  "--platform",
  "--add-host",
  "--dns",
  "--device",
  "--ulimit",
  "--log-driver",
  "--log-opt",
  "--stop-timeout",
  "--shm-size",
  "--ipc",
  "--pid",
  "--uts",
  "--userns",
  "--cgroupns",
  "--cgroup-parent",
  "--runtime",
  "--gpus",
  "--group-add",
  "--sysctl",
  "--storage-opt",
  "--volumes-from",
  "--link",
  "--expose",
  "-p",
  "--publish",
  "--restart",
  "--cidfile",
  "--domainname",
  "--isolation",
  "--mac-address",
  "--memory-reservation",
  "--oom-score-adj",
  "--annotation",
  "--attach",
  "-a",
  "--cpu-period",
  "--cpu-quota",
  "--cpu-shares",
  "-c",
  "--cpuset-cpus",
  "--cpuset-mems",
  "--device-cgroup-rule",
  "--dns-option",
  "--dns-search",
  "--ip",
  "--ip6",
  "--network-alias",
  "--pull",
  "--detach-keys",
  "--blkio-weight",
  "--kernel-memory",
]);

interface DockerRun {
  flags: string[];
  pairs: [string, string][];
  image: string | null;
  command: string[];
  error: string | null;
}

/** A `docker run` argv read as docker reads it: options (with or without `=`), then the image, then the command. */
export function parseDockerRun(argv: readonly string[]): DockerRun {
  const tokens = argv.flatMap((t) =>
    t.startsWith("--") && t.includes("=") ? [t.slice(0, t.indexOf("=")), t.slice(t.indexOf("=") + 1)] : [t],
  );
  const run = tokens.indexOf("run");
  if (tokens[0] !== "docker" || run !== 1) {
    return { flags: [], pairs: [], image: null, command: [], error: "not a docker run command" };
  }
  const flags: string[] = [];
  const pairs: [string, string][] = [];
  let i = 2;
  while (i < tokens.length && tokens[i].startsWith("-")) {
    if (VALUE_OPTIONS.has(tokens[i])) {
      pairs.push([tokens[i], tokens[i + 1] ?? ""]);
      i += 2;
    } else {
      flags.push(tokens[i]);
      i += 1;
    }
  }
  return { flags, pairs, image: tokens[i] ?? null, command: tokens.slice(i + 1), error: null };
}

/** Every reason an environment identity is incomplete, unprovenanced, or (a container's) not the hardened one. */
export function environmentErrors(env: EnvironmentIdentity): string[] {
  const errors: string[] = [];
  const e = env as unknown as Record<string, unknown>;
  for (const field of ["kind", "label", "platform", "release", "arch", "node", "typescriptExecution", "sourceCommit"]) {
    if (typeof e[field] !== "string" || e[field] === "") errors.push(`ENVIRONMENT_INCOMPLETE: ${field} is missing`);
  }
  if (typeof e.kind === "string" && e.kind !== "HOST" && e.kind !== "CONTAINER")
    errors.push(`ENVIRONMENT_INCOMPLETE: kind ${String(e.kind)} is neither HOST nor CONTAINER`);
  if (typeof e.node === "string" && !/^v\d+\.\d+\.\d+/.test(e.node))
    errors.push(`PROVENANCE_INVALID: node ${e.node} is not a version`);
  if (typeof e.typescriptExecution === "string" && !["tsx", "node-type-stripping"].includes(e.typescriptExecution))
    errors.push(`ENVIRONMENT_INCOMPLETE: typescriptExecution ${e.typescriptExecution} is unknown`);
  if (typeof e.sourceCommit === "string" && !HEX40.test(e.sourceCommit))
    errors.push(`PROVENANCE_INVALID: sourceCommit ${e.sourceCommit} is not a commit`);
  if (env.kind !== "CONTAINER") {
    if (env.container !== undefined) errors.push("ENVIRONMENT_INCOMPLETE: a host identity carries a container");
    return errors;
  }
  const c = env.container;
  if (c === undefined || typeof c !== "object") {
    errors.push("ENVIRONMENT_INCOMPLETE: container is missing");
    return errors;
  }
  const image = (c.image ?? {}) as Record<string, unknown>;
  for (const field of ["reference", "digest", "id", "nodeVersion", "registryVerification"]) {
    if (typeof image[field] !== "string" || image[field] === "")
      errors.push(`ENVIRONMENT_INCOMPLETE: image.${field} is missing`);
  }
  if (typeof image.digest === "string" && !DIGEST.test(image.digest))
    errors.push(`PROVENANCE_INVALID: image.digest ${image.digest} is not sha256:<64 hex>`);
  if (typeof image.id === "string" && !DIGEST.test(image.id))
    errors.push(`PROVENANCE_INVALID: image.id ${image.id} is not sha256:<64 hex>`);
  if (!Array.isArray(c.runOptions) || !c.runOptions.every((t) => typeof t === "string")) {
    errors.push("ENVIRONMENT_INCOMPLETE: runOptions is not the docker run argv");
  } else {
    const run = parseDockerRun(c.runOptions);
    if (run.error !== null) errors.push(`CONTAINER_NOT_HARDENED: ${run.error}`);
    const values = (opt: string[]) => run.pairs.filter(([k]) => opt.includes(k)).map(([, v]) => v);
    const networks = values(["--network", "--net"]);
    if (!networks.includes("none")) errors.push("CONTAINER_NOT_HARDENED: --network none is missing");
    if (networks.includes("host") || run.flags.includes("--net=host"))
      errors.push("CONTAINER_NOT_HARDENED: host networking");
    if (!run.flags.includes("--read-only")) errors.push("CONTAINER_NOT_HARDENED: --read-only is missing");
    if (!values(["--cap-drop"]).includes("ALL")) errors.push("CONTAINER_NOT_HARDENED: --cap-drop ALL is missing");
    if (!values(["--security-opt"]).some((v) => /^no-new-privileges(:true)?$/.test(v)))
      errors.push("CONTAINER_NOT_HARDENED: --security-opt no-new-privileges is missing");
    if (!values(["--user", "-u"]).some((v) => /^[1-9]\d*:[1-9]\d*$/.test(v)))
      errors.push("CONTAINER_NOT_HARDENED: --user <non-root uid>:<gid> is missing");
    if (!values(["--pids-limit"]).some((v) => /^[1-9]\d*$/.test(v)))
      errors.push("CONTAINER_NOT_HARDENED: --pids-limit is missing");
    if (run.flags.includes("--privileged") || c.runOptions.includes("--privileged"))
      errors.push("CONTAINER_NOT_HARDENED: --privileged");
    if (c.runOptions.some((t) => t.includes("docker.sock")))
      errors.push("CONTAINER_NOT_HARDENED: docker.sock is mounted");
    if (run.pairs.some(([k]) => ["--env", "-e", "--env-file"].includes(k)))
      errors.push("CONTAINER_NOT_HARDENED: environment variables are passed in");
    for (const v of values(["-v", "--volume"])) {
      const [src, dst, opts] = v.split(":");
      // A home directory itself, or a dotfile store under one (.ssh, .docker, .aws, .npmrc ...), never enters the
      // container; a plain working directory under a home may (the operator's source export, inputs and outputs).
      const home = /^(?:\/(?:home\/[^/]+|root)|\/mnt\/[a-z]\/Users\/[^/]+)(?=\/|$)/.exec(src ?? "");
      if (home !== null) {
        const below = (src ?? "")
          .slice(home[0].length)
          .split("/")
          .filter((s) => s !== "");
        if (below.length === 0 || below.some((s) => s.startsWith(".")))
          errors.push(`CONTAINER_NOT_HARDENED: a home directory or a dotfile store under it is mounted (${src})`);
      }
      if (dst !== "/out" && !(opts ?? "").split(",").includes("ro"))
        errors.push(`CONTAINER_NOT_HARDENED: ${dst ?? src} is writable`);
    }
    for (const m of values(["--mount"])) {
      const kv = Object.fromEntries(m.split(",").map((p) => p.split("=") as [string, string]));
      const dst = kv.dst ?? kv.destination ?? kv.target ?? "?";
      if (dst !== "/out" && !("readonly" in kv || "ro" in kv))
        errors.push(`CONTAINER_NOT_HARDENED: ${dst} is writable`);
    }
    if (run.image === null || !/@sha256:[0-9a-f]{64}$/.test(run.image))
      errors.push("PROVENANCE_INVALID: the image is not run by digest");
    else if (typeof image.digest === "string" && DIGEST.test(image.digest) && !run.image.endsWith(image.digest))
      errors.push(`PROVENANCE_INVALID: the image run (${run.image}) is not image.digest`);
  }
  const f = (c.facts ?? {}) as Partial<ContainerIdentity["facts"]>;
  if (f.uid === 0) errors.push("CONTAINER_NOT_HARDENED: ran as root");
  if (!Number.isSafeInteger(f.uid) || !Number.isSafeInteger(f.gid))
    errors.push("ENVIRONMENT_INCOMPLETE: facts.uid/gid are missing");
  if (!Array.isArray(f.networkInterfaces)) errors.push("ENVIRONMENT_INCOMPLETE: facts.networkInterfaces is missing");
  else if (canonicalJson([...f.networkInterfaces].sort()) !== canonicalJson(["lo"]))
    errors.push(`CONTAINER_NOT_HARDENED: network interfaces ${f.networkInterfaces.join(", ")}`);
  if (f.capEff !== "0000000000000000")
    errors.push(`CONTAINER_NOT_HARDENED: effective capabilities ${String(f.capEff ?? "unknown")}`);
  if (f.noNewPrivs !== 1) errors.push("CONTAINER_NOT_HARDENED: no_new_privs is not set");
  if (f.rootMount !== "ro") errors.push("CONTAINER_NOT_HARDENED: the root filesystem is writable");
  if (!Array.isArray(f.env)) errors.push("ENVIRONMENT_INCOMPLETE: facts.env is missing");
  return errors;
}

// ---------------------------------------------------------------------------------------------------------------
// Two derivations compared, and many captures summarized
// ---------------------------------------------------------------------------------------------------------------

export interface LeafDifference {
  path: string;
  a: unknown;
  b: unknown;
}

/** Every leaf where two JSON values differ, by path; arrays by index and length, objects by the union of their keys. */
export function leafDifferences(a: unknown, b: unknown, prefix = ""): LeafDifference[] {
  const at = (k: string | number) => (prefix === "" ? String(k) : `${prefix}.${k}`);
  if (Array.isArray(a) && Array.isArray(b)) {
    const out: LeafDifference[] = [];
    for (let i = 0; i < Math.min(a.length, b.length); i++) out.push(...leafDifferences(a[i], b[i], at(i)));
    if (a.length !== b.length) out.push({ path: at("length"), a: a.length, b: b.length });
    return out;
  }
  const isObj = (x: unknown) => typeof x === "object" && x !== null && !Array.isArray(x);
  if (isObj(a) && isObj(b)) {
    const keys = [...new Set([...Object.keys(a as object), ...Object.keys(b as object)])].sort();
    return keys.flatMap((k) =>
      leafDifferences((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], at(k)),
    );
  }
  return canonicalJson(a) === canonicalJson(b) ? [] : [{ path: prefix, a, b }];
}

export type DifferenceClass =
  | "EXPECTED_ENVIRONMENT_IDENTITY"
  | "SOURCE_IDENTITY_MISMATCH"
  | "INPUT_IDENTITY_MISMATCH"
  | "SECURITY_RELEVANT_MISMATCH";

export interface DerivationReconciliation {
  result: "HOST_CONTAINER_OBSERVER_AGREEMENT" | "HOST_CONTAINER_OBSERVER_DISAGREEMENT";
  differences: (LeafDifference & { class: DifferenceClass })[];
}

/**
 * Two derivations of one capture reconciled field by field: the inputs and every derived field must be equal; only the
 * environment's identity may differ, and its source commit never. Equal exit codes mean nothing here.
 */
export function reconcileDerivations(a: Derivation, b: Derivation): DerivationReconciliation {
  const differences = leafDifferences(a, b).map((d) => {
    const cls: DifferenceClass =
      d.path === "environment.sourceCommit"
        ? "SOURCE_IDENTITY_MISMATCH"
        : d.path.startsWith("environment.")
          ? "EXPECTED_ENVIRONMENT_IDENTITY"
          : d.path.startsWith("input.")
            ? "INPUT_IDENTITY_MISMATCH"
            : "SECURITY_RELEVANT_MISMATCH";
    return { ...d, class: cls };
  });
  const agree = differences.every((d) => d.class === "EXPECTED_ENVIRONMENT_IDENTITY");
  return {
    result: agree ? "HOST_CONTAINER_OBSERVER_AGREEMENT" : "HOST_CONTAINER_OBSERVER_DISAGREEMENT",
    differences,
  };
}

export interface SoakIteration {
  n: number;
  variation: string;
  startedAtUtc: string;
  seconds: number;
  exit: number;
  rawDir: string;
  rawEntries: string[];
  factsSummary: { failures: number; heartbeats: number; probeMisses: number; leftoverLines: number; cleanup: number };
  after: { probesLeft: number; instancesLeft: number };
  host: Derivation;
  container: Derivation;
}

export interface Soak {
  id: string;
  boundary: SoakBoundary;
  startedAtUtc: string;
  finishedAtUtc: string;
  table: { family: string; name: string; rulesSha256: string; rules: string };
  iterations: SoakIteration[];
}

export interface SoakSummary {
  boundary: SoakBoundary;
  iterations: number;
  exitZero: number;
  refusalFree: number;
  clean: number;
  distinctCaptures: number;
  distinctProjections: number;
  agreeing: number;
  variations: string[];
  refusalReasons: Record<string, number>;
  /** Iterations refused only as EGRESS_LEAKED by attempts outside the workload's scopes (another process's egress). */
  thirdPartyLeakIterations: number[];
  stable: boolean;
  /** Stable in every respect but third-party leaks: meaningful under the self-test table alone, which refuses no real egress. */
  stableExceptThirdPartyLeaks: boolean;
  unstableBecause: string[];
}

/** What many captures of one observer on one host establish together; every reason they establish less, by name. */
export function soakSummaryOf(iterations: readonly SoakIteration[], boundary: SoakBoundary): SoakSummary {
  const because: string[] = [];
  let exitZero = 0;
  let refusalFree = 0;
  let clean = 0;
  let agreeing = 0;
  const captures = new Map<string, number[]>();
  const projections = new Set<string>();
  const refusalReasons: Record<string, number> = {};
  const thirdParty: number[] = [];
  const first = iterations[0]?.host.output.stableProjectionSha256 ?? null;
  for (const it of iterations) {
    if (it.exit === 0) exitZero++;
    else because.push(`iteration ${it.n} exited ${it.exit}`);
    const refusals = [...it.host.output.refusals, ...it.container.output.refusals];
    const reasons = [...new Set(refusals.map((r) => r.reason))].sort();
    for (const r of reasons) refusalReasons[r] = (refusalReasons[r] ?? 0) + 1;
    if (refusals.length === 0) refusalFree++;
    else {
      const j = it.host.output.judgement;
      const scopes = j === null ? [] : Object.keys(j.leaksByScope).sort();
      const onlyLeaks = reasons.length === 1 && reasons[0] === "EGRESS_LEAKED";
      const ownIntact = j !== null && j.ownAttempts.length > 0 && j.ownAttempts.every((x) => x.outcome === "REFUSED");
      const noOwnLeak = scopes.length > 0 && scopes.every((s) => !OWN_SCOPES.includes(s));
      if (onlyLeaks && ownIntact && noOwnLeak) {
        thirdParty.push(it.n);
        because.push(
          `iteration ${it.n} refused: EGRESS_LEAKED by another process (scope ${scopes.join(", ")}): the workload's own attempts were all refused`,
        );
      } else because.push(`iteration ${it.n} refused: ${reasons.join(", ")}`);
    }
    const entriesOk = canonicalJson([...it.rawEntries].sort()) === canonicalJson(RAW_FILES);
    const isClean =
      it.after.probesLeft === 0 &&
      it.after.instancesLeft === 0 &&
      entriesOk &&
      it.factsSummary.failures === 0 &&
      it.factsSummary.cleanup === 0;
    if (isClean) clean++;
    else if (!entriesOk) because.push(`iteration ${it.n} raw directory holds ${it.rawEntries.join(", ")}`);
    else if (it.factsSummary.failures > 0 || it.factsSummary.cleanup > 0)
      because.push(
        `iteration ${it.n} observer recorded ${it.factsSummary.failures} failures, ${it.factsSummary.cleanup} cleanup leftovers`,
      );
    else
      because.push(
        `iteration ${it.n} left ${it.after.probesLeft} probes and ${it.after.instancesLeft} instances behind`,
      );
    const r = reconcileDerivations(it.host, it.container);
    if (r.result === "HOST_CONTAINER_OBSERVER_AGREEMENT") agreeing++;
    else {
      const paths = r.differences.filter((d) => d.class !== "EXPECTED_ENVIRONMENT_IDENTITY").map((d) => d.path);
      because.push(`iteration ${it.n}: host and container disagree (${paths.join(", ")})`);
    }
    const digest = it.host.output.normalizedSha256;
    if (digest !== null) captures.set(digest, [...(captures.get(digest) ?? []), it.n]);
    const p = it.host.output.stableProjectionSha256;
    if (p !== null) projections.add(p);
    if (p !== first) because.push(`iteration ${it.n} projects differently from iteration 1`);
  }
  for (const [digest, ns] of captures) {
    if (ns.length > 1) because.push(`iterations ${ns.join(" and ")} hold one capture (${digest.slice(0, 16)})`);
  }
  const n = iterations.length;
  const otherwiseStable =
    n > 0 &&
    exitZero === n &&
    clean === n &&
    agreeing === n &&
    captures.size === n &&
    projections.size === 1 &&
    first !== null;
  return {
    boundary,
    iterations: n,
    exitZero,
    refusalFree,
    clean,
    distinctCaptures: captures.size,
    distinctProjections: projections.size,
    agreeing,
    variations: [...new Set(iterations.map((i) => i.variation))],
    refusalReasons,
    thirdPartyLeakIterations: thirdParty,
    stable: otherwiseStable && refusalFree === n,
    stableExceptThirdPartyLeaks: otherwiseStable && refusalFree + thirdParty.length === n,
    unstableBecause: because,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Negative controls: the harness must be seen to refuse
// ---------------------------------------------------------------------------------------------------------------

export interface NegativeContext {
  raw: RawEvidence;
  hostExecutable: HostExecutable;
  committedObserverSha256: string;
  host: Derivation;
  container: Derivation;
}

export interface NegativeControl {
  id: string;
  name: string;
  /** The reason the control must be refused for ("NONE" for the positive control, which must not be refused). */
  intendedReason: string;
  run: (ctx: NegativeContext) => string[];
}

export interface NegativeControlResult {
  id: string;
  name: string;
  intendedReason: string;
  observedReasons: string[];
  ok: boolean;
}

const codeOf = (message: string) => message.split(":")[0];
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const mismatchClasses = (r: DerivationReconciliation) => [
  ...new Set(r.differences.filter((d) => d.class !== "EXPECTED_ENVIRONMENT_IDENTITY").map((d) => d.class)),
];

/** The trace with its STOP marker line removed and the manifest re-bound to the new bytes (a forger who rebinds). */
function rebound(raw: RawEvidence): RawEvidence {
  const lines = raw.trace.split("\n");
  const trace = lines.filter((l) => !/tracing_mark_write: SP1OBS [0-9a-f]{16} \d+ STOP\b/.test(l)).join("\n");
  const manifest = JSON.parse(raw.manifest) as { files: { name: string; bytes: number; sha256: string }[] };
  const bytes = Buffer.from(trace, "latin1");
  manifest.files = manifest.files.map((f) =>
    f.name === "trace.txt" ? { ...f, bytes: bytes.length, sha256: sha256Hex(bytes) } : f,
  );
  return { ...raw, trace, manifest: `${JSON.stringify(manifest, null, 2)}\n` };
}

export const NEGATIVE_CONTROLS: readonly NegativeControl[] = [
  {
    id: "P0",
    name: "positive control: the unmodified capture derives, agrees between host and container, and is refusal-free",
    intendedReason: "NONE",
    run: (ctx) => [
      ...deriveQualification(ctx.raw, ctx.hostExecutable, ctx.committedObserverSha256).refusals.map((r) => r.reason),
      ...mismatchClasses(reconcileDerivations(ctx.host, ctx.container)),
    ],
  },
  {
    id: "NC1",
    name: "modified observer input: one byte of the raw trace changed",
    intendedReason: "RAW_NOT_BOUND",
    run: (ctx) => {
      const trace = ctx.raw.trace.replace("READY mode=", "REAdY mode=");
      return deriveQualification({ ...ctx.raw, trace }, ctx.hostExecutable, ctx.committedObserverSha256).refusals.map(
        (r) => r.reason,
      );
    },
  },
  {
    id: "NC2",
    name: "modified expected digest: the host derivation's recorded normalized digest is not what the bytes derive",
    intendedReason: "EXPECTED_DIGEST_MISMATCH",
    run: (ctx) => {
      const host = clone(ctx.host);
      host.output.normalizedSha256 = sha256Hex("another expected digest");
      return derivationErrors(host, deriveQualification(ctx.raw, ctx.hostExecutable, ctx.committedObserverSha256)).map(
        codeOf,
      );
    },
  },
  {
    id: "NC3",
    name: "altered evidence payload: one normalized event edited after normalization",
    intendedReason: "NORMALIZED_NOT_BOUND",
    run: (ctx) => {
      const o = clone(normalizeObserverRaw(ctx.raw, ctx.hostExecutable));
      const connect = o.events.find((e) => e.k === "connect" && e.dest !== null) as
        Extract<ObserverEvidence["events"][number], { k: "connect" }> | undefined;
      if (connect?.dest) connect.dest.port = (connect.dest.port ?? 0) + 1;
      return observerEvidenceErrors(o, selfTestExpectations(ctx.committedObserverSha256)).refusals.map((r) => r.reason);
    },
  },
  {
    id: "NC4",
    name: "stale evidence reused against a new source identity: the committed observer is another",
    intendedReason: "TOOL_NOT_BOUND",
    run: (ctx) =>
      deriveQualification(ctx.raw, ctx.hostExecutable, sha256Hex("the observer after a change")).refusals.map(
        (r) => r.reason,
      ),
  },
  {
    id: "NC5",
    name: "intentionally mismatched host/container record: the container's normalized digest differs",
    intendedReason: "SECURITY_RELEVANT_MISMATCH",
    run: (ctx) => {
      const container = clone(ctx.container);
      container.output.normalizedSha256 = sha256Hex("a container that derived otherwise");
      return mismatchClasses(reconcileDerivations(ctx.host, container));
    },
  },
  {
    id: "NC6",
    name: "unexpected file mutation: a fourth file appears in the raw directory",
    intendedReason: "RAW_DIR_UNEXPECTED_FILE",
    run: () => {
      try {
        readRawDir("/raw", { list: () => [...RAW_FILES, "notes.txt"], read: () => "" });
        return [];
      } catch (error) {
        return [codeOf((error as Error).message)];
      }
    },
  },
  {
    id: "NC7",
    name: "missing required tool/version: an environment identity without its Node.js version",
    intendedReason: "ENVIRONMENT_INCOMPLETE",
    run: (ctx) => {
      const env = clone(ctx.host.environment) as Partial<EnvironmentIdentity>;
      delete env.node;
      return environmentErrors(env as EnvironmentIdentity).map(codeOf);
    },
  },
  {
    id: "NC8",
    name: "invalid or absent provenance field: a container image named by a mutable tag, not a digest",
    intendedReason: "PROVENANCE_INVALID",
    run: (ctx) => {
      const env = clone(ctx.container.environment);
      if (env.container) env.container.image.digest = "latest";
      return environmentErrors(env).map(codeOf);
    },
  },
  {
    id: "NC9",
    name: "input modified and manifest re-bound: the STOP marker removed, the manifest rewritten to the new bytes",
    intendedReason: "OBSERVER_COVERAGE",
    run: (ctx) =>
      deriveQualification(rebound(ctx.raw), ctx.hostExecutable, ctx.committedObserverSha256).refusals.map(
        (r) => r.reason,
      ),
  },
];

/** A recorded derivation against a fresh one of the same inputs: its digest and every other derived field. */
export function derivationErrors(recorded: Derivation, fresh: DerivationOutput): string[] {
  const errors: string[] = [];
  if (recorded.output.normalizedSha256 !== fresh.normalizedSha256)
    errors.push("EXPECTED_DIGEST_MISMATCH: the recorded normalized digest is not what the bytes derive");
  for (const d of leafDifferences(recorded.output, fresh)) {
    if (d.path !== "normalizedSha256") errors.push(`OUTPUT_MISMATCH: output.${d.path}`);
  }
  return errors;
}

export function runNegativeControls(ctx: NegativeContext): NegativeControlResult[] {
  return NEGATIVE_CONTROLS.map((c) => {
    let observed: string[];
    try {
      observed = [...new Set(c.run(ctx))].sort();
    } catch (error) {
      observed = [`THREW: ${(error as Error).message.slice(0, 80)}`];
    }
    const ok = c.intendedReason === "NONE" ? observed.length === 0 : observed.includes(c.intendedReason);
    return { id: c.id, name: c.name, intendedReason: c.intendedReason, observedReasons: observed, ok };
  });
}

// ---------------------------------------------------------------------------------------------------------------
// The state, from facts alone
// ---------------------------------------------------------------------------------------------------------------

export interface SoakFacts {
  id: string;
  boundary: SoakBoundary;
  iterations: number;
  stable: boolean;
  stableExceptThirdPartyLeaks: boolean;
  unstableBecause: string[];
}

export interface StateFacts {
  observed: boolean;
  soaks: SoakFacts[];
  fixtureAgreement: boolean;
  negativeControls: { id: string; ok: boolean }[];
  positiveControl: boolean;
  environmentErrors: string[];
  blockingFindings: string[];
}

/**
 * The state the facts derive. A soak under the complete egress boundary (SP1-PA3D's) must exist and be stable in every
 * respect; a soak under the self-test table may be unstable only by another process's egress, which that table does not
 * refuse and the derivation rightly calls a leak.
 */
export function qualificationStateOf(facts: StateFacts): { state: QualificationState; blockers: string[] } {
  if (!facts.observed) return { state: "OBSERVER_TOOLING_READY_VALIDATION_PENDING", blockers: [] };
  const blockers: string[] = [];
  if (!facts.soaks.some((s) => s.boundary === "COMPLETE_EGRESS_BOUNDARY"))
    blockers.push("SOAK_MISSING: no soak ran under the complete egress boundary (the one SP1-PA3D runs under)");
  for (const s of facts.soaks) {
    const where = `${s.id}, ${s.boundary === "COMPLETE_EGRESS_BOUNDARY" ? "complete boundary" : "self-test table"}`;
    if (s.iterations < MIN_SOAK_ITERATIONS)
      blockers.push(`SOAK_TOO_SHORT (${where}): ${s.iterations} iterations, at least ${MIN_SOAK_ITERATIONS} needed`);
    const ok = s.boundary === "COMPLETE_EGRESS_BOUNDARY" ? s.stable : s.stable || s.stableExceptThirdPartyLeaks;
    if (!ok) blockers.push(`SOAK_UNSTABLE (${where}): ${s.unstableBecause.join("; ")}`);
  }
  if (!facts.fixtureAgreement)
    blockers.push("HOST_CONTAINER_DISAGREEMENT: the fixture's host and container derivations differ");
  if (facts.negativeControls.length === 0) blockers.push("NEGATIVE_CONTROLS_MISSING: no negative control ran");
  for (const c of facts.negativeControls) if (!c.ok && c.id !== "P0") blockers.push(`NEGATIVE_CONTROL_FAILED: ${c.id}`);
  if (!facts.positiveControl) blockers.push("POSITIVE_CONTROL_FAILED: the unmodified capture was refused");
  blockers.push(...facts.environmentErrors);
  for (const id of facts.blockingFindings) blockers.push(`SECURITY_FINDING_BLOCKING: ${id}`);
  return { state: blockers.length > 0 ? "OBSERVER_QUALIFICATION_BLOCKED" : "OBSERVER_QUALIFIED_FOR_PA3D", blockers };
}

// ---------------------------------------------------------------------------------------------------------------
// The observation (measured on the proving host) and the record derived from it
// ---------------------------------------------------------------------------------------------------------------

export interface QualificationObservation {
  schema: typeof OBSERVATION_SCHEMA;
  lane: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
  source: { commit: string; observerScriptSha256: string };
  hostFacts: {
    kernelRelease: string;
    bootId: string;
    node: { execPath: string; version: string; sha256: string };
    nft: string;
    docker: string;
  };
  fixture: { host: Derivation; container: Derivation };
  soaks: Soak[];
  negativeControls: NegativeControlResult[];
}

export interface SecurityFinding {
  id: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH";
  blocking: boolean;
  finding: string;
  disposition: string;
  carriedForwardFrom: string | null;
  evidence: string | null;
}

/** The adversarial review of the environment (Phase 6), stated once; measured evidence is attached by the record. */
export const SECURITY_FINDINGS: readonly Omit<SecurityFinding, "evidence">[] = [
  {
    id: "Q1-SF1",
    severity: "LOW",
    blocking: false,
    finding:
      "The container's base image was not pulled by this lane: it was already in the proving host's native engine (moved there by docker save/load in SP1-PA3B). Its identity is its content digest; its registry provenance rests on a read-only manifest lookup by that digest (nothing downloaded).",
    disposition:
      "ACCEPTED_WITH_EVIDENCE: the digest is pinned in the record; the lookup's answer is recorded beside it",
    carriedForwardFrom: null,
  },
  {
    id: "Q1-SF2",
    severity: "INFO",
    blocking: false,
    finding:
      "The host derivation runs TypeScript through tsx from node_modules, installed from the npm registry by npm ci; the registry is a network dependency of the host path (integrity-pinned by package-lock.json). The container path has none: Node strips the types itself and a repository-owned hook resolves the two extensionless imports.",
    disposition: "ACCEPTED: two independent TypeScript execution paths agreeing is part of the evidence",
    carriedForwardFrom: null,
  },
  {
    id: "Q1-SF3",
    severity: "LOW",
    blocking: false,
    finding:
      "The repository's deployer Dockerfile names its base image by tag (node:<version>-bookworm-slim, not a digest) and installs apt packages unpinned; docker-compose files reference walletwall-vault:latest. None of these is in the observer path; they are the Sepolia deployer's.",
    disposition:
      "REPORTED: out of this lane's scope (no production tooling changed); an owner decision for the deployer",
    carriedForwardFrom: null,
  },
  {
    id: "Q1-SF4",
    severity: "INFO",
    blocking: false,
    finding:
      "Raw captures hold host identity (addresses, boot id, exec paths, pids). The soaks' raw directories stay operator-local (root:prover-group, 0750) as SP1-PA3C's evidence model requires; only their digests and derivations are committed. The committed fixture remains the one privacy-reviewed capture.",
    disposition: "ACCEPTED: retained OPERATOR_LOCAL",
    carriedForwardFrom: "SP1-PA3C",
  },
  {
    id: "Q1-SF5",
    severity: "MEDIUM",
    blocking: false,
    finding:
      "RustSec: zkvm/host/Cargo.lock still locks webpki-roots 1.0.7 (RUSTSEC-2026-0381) and rustls-webpki 0.103.13 (RUSTSEC-2026-0382), assessed CONDITIONAL / SHOULD_FIX_BEFORE_PRODUCTION in #233 (MUST_FIX 0). This lane compiles nothing with cargo, runs no SP1 host and opens no TLS connection: the exposure is unchanged, so the classification is carried forward, neither raised nor suppressed.",
    disposition: "CARRIED_FORWARD: owner decision HOST_LOCKFILE_REMEDIATION = DEFER_TO_NEXT_PROGRAM_REBUILD stands",
    carriedForwardFrom: "#233",
  },
  {
    id: "Q1-SF6",
    severity: "MEDIUM",
    blocking: false,
    finding:
      "The capture layer cannot be containerized without privileges: tracefs, kprobes and nftables act on the one shared WSL2 kernel, so the observer runs as root on the proving host and only the derivation is reproduced in the clean container. A hostile root on that host could edit a capture before it is derived (SP1-PA3C's trust statement). This qualification does not change that; it makes the derivation of whatever was captured reproducible anywhere.",
    disposition: "STATED: the host trust boundary is the proving host's root, as before",
    carriedForwardFrom: "SP1-PA3C",
  },
  {
    id: "Q1-SF7",
    severity: "MEDIUM",
    blocking: false,
    finding:
      "The proving user is in the docker group of the native engine, which is root-equivalent on the proving host (SP1-PA3C disclosed it); the container self-test is started by that user. Docker Desktop's own engine was stopped throughout and was not started or reset.",
    disposition: "CARRIED_FORWARD: the proving host's design, disclosed in SP1-PA3B and SP1-PA3C",
    carriedForwardFrom: "SP1-PA3C",
  },
  {
    id: "Q1-SF8",
    severity: "LOW",
    blocking: false,
    finding:
      "The proving host is not quiet: its own daemons egress during observation windows. Under the self-test table (TEST-NET-1 and the resolvers refused, nothing else) one soak iteration saw the host's chronyd send one NTP datagram to a public time server inside the window, and the derivation refused that capture as EGRESS_LEAKED, as it must under a table that refuses no real egress; the workload's own attempts were refused and reconciled as in every other iteration. Under the complete egress boundary (SP1-PA3B's, which SP1-PA3D runs under) the same traffic is refused, counted and attributed to another scope, never a leak.",
    disposition:
      "ACCEPTED_AS_MEASURED: the observer detected and attributed it; a SP1-PA3D run should expect refused attempts of other scopes (quieting chronyd first is an owner choice, not a requirement)",
    carriedForwardFrom: null,
  },
];

export interface Component {
  component: string;
  class: ComponentClass;
  path?: string;
  sha256?: string | null;
  identity?: string;
  note?: string;
}

export interface RecordSoak {
  id: string;
  boundary: SoakBoundary;
  host: string;
  startedAtUtc: string;
  finishedAtUtc: string;
  table: Soak["table"];
  iterations: {
    n: number;
    variation: string;
    exit: number;
    normalizedSha256: string | null;
    stableProjectionSha256: string | null;
    judgementSha256: string | null;
    refusals: string[];
    otherScopeAttempts: number | null;
    reconciliation: DerivationReconciliation["result"];
  }[];
  summary: SoakSummary;
}

export interface QualificationRecord {
  schema: typeof QUALIFICATION_SCHEMA;
  lane: string;
  repository: string;
  productionSp1Binding: string;
  state: QualificationState;
  blockers: string[];
  next: { lane: string; what: string; authorization: "OWNER"; started: false } | null;
  qualifiedAtUtc: string | null;
  source: { commit: string | null; observerScriptSha256: string };
  observer: { script: string; scriptSha256: string; mechanism: string; workload: string };
  components: Component[];
  fixture: {
    dir: string;
    hostExecutable: HostExecutable;
    host: Derivation;
    container: Derivation;
    reconciliation: DerivationReconciliation;
  } | null;
  soaks: RecordSoak[];
  container: ContainerIdentity | null;
  environments: EnvironmentIdentity[];
  negativeControls: NegativeControlResult[];
  securityFindings: SecurityFinding[];
  networkDependencies: { phase: string; dependency: string; verification: string }[];
  hostDependencies: string[];
  derivedFrom: { path: string; sha256: string }[];
}

export interface ValidationContext {
  /** A repository file's bytes by its posix-relative path, or null when it is not there. */
  readFile: (rel: string) => Buffer | null;
  committedObserverSha256: string;
  /** The committed fixture derived here, now (what the record's fixture derivations must equal). */
  fixtureDerivation: DerivationOutput;
  observations: { path: string; observation: QualificationObservation }[];
}

const nameOfComponent = (path: string) =>
  path === OBSERVER_SCRIPT_REL
    ? "root egress observer"
    : path === "scripts/lib/sp1-egress-attribution.ts"
      ? "attribution derivation (normalize, judge)"
      : path === SELF_TEST_WORKLOAD_REL
        ? "self-test workload"
        : path.startsWith(FIXTURE_DIR_REL)
          ? "committed self-test capture (fixture)"
          : path === CLI_SCRIPT_REL
            ? "qualification CLI (derive, reconcile, controls, assemble)"
            : path === SOAK_SCRIPT_REL
              ? "root soak runner"
              : path === GENERATOR_REL
                ? "record generator and validator CLI"
                : path === CONTAINER_SCRIPT_REL
                  ? "clean container runner"
                  : path === LOADER_REL || path === HOOK_REL
                    ? "zero-dependency TypeScript loader (container)"
                    : path === QUALIFICATION_JSON_SCHEMA_REL
                      ? "record JSON schema"
                      : "qualification library";

function componentsOf(ctx: ValidationContext, o: QualificationObservation | null): Component[] {
  const pinned: Component[] = REPOSITORY_PINNED_COMPONENTS.map((path) => {
    const bytes = ctx.readFile(path);
    return {
      component: nameOfComponent(path),
      class: "repository-pinned",
      path,
      sha256: bytes === null ? null : sha256Hex(lf(bytes.toString("utf8"))),
    };
  });
  if (o === null) return pinned;
  const c = o.fixture.container.environment.container;
  const image = c?.image;
  const verified = /HTTP 200/.test(image?.registryVerification ?? "");
  return [
    ...pinned,
    {
      component: "container base image (Node.js)",
      class: image === undefined ? "unknown-unverified" : verified ? "digest-pinned" : "unknown-unverified",
      identity: image === undefined ? "none" : `${image.reference}@${image.digest}`,
      note: image?.registryVerification ?? "no registry verification",
    },
    {
      component: "container Node.js",
      class: "version-pinned",
      identity: `${o.fixture.container.environment.node} (${image?.nodeVersion ?? "?"}, from the image)`,
    },
    {
      component: "host Node.js (runs the observer as root, the workload as the user, the host derivation)",
      class: "version-pinned",
      identity: `${o.hostFacts.node.execPath} ${o.hostFacts.node.version} sha256 ${o.hostFacts.node.sha256}`,
    },
    { component: "nftables (the boundary tables)", class: "version-pinned", identity: o.hostFacts.nft },
    { component: "Docker engine (container path only)", class: "version-pinned", identity: o.hostFacts.docker },
    {
      component: "Linux kernel: tracefs, kprobes with BTF arguments, netfilter drop reasons",
      class: "host-dependent",
      identity: o.hostFacts.kernelRelease,
    },
    {
      component: "proving host (root for the observer; WSL2 shared network namespace)",
      class: "host-dependent",
      identity: `${o.host}, boot ${o.hostFacts.bootId}`,
    },
    {
      component: "host binaries the observer runs: setpriv, ip, getent, cat, nft",
      class: "host-dependent",
      identity: "distribution packages; versions recorded only for nft",
    },
    {
      component: "stand-in host executable identity (device:inode of the workload's node)",
      class: "host-dependent",
      identity: `${o.fixture.host.input.hostExecutable.path} ${o.fixture.host.input.hostExecutable.dev}:${o.fixture.host.input.hostExecutable.ino} (fixture)`,
    },
    {
      component: "npm registry (tsx and the suite, for the host derivation and the tests)",
      class: "network-dependent",
      identity: "package-lock.json integrity hashes; no runtime fetch",
    },
    {
      component: "Docker Hub (read-only manifest lookup of the pinned digest)",
      class: "network-dependent",
      identity: image?.registryVerification ?? "not looked up",
    },
    {
      component: "raw soak captures",
      class: "host-dependent",
      identity: "retained OPERATOR_LOCAL on the proving host; digests and derivations committed",
    },
  ];
}

function factsOf(record: {
  observed: boolean;
  soaks: RecordSoak[];
  fixture: QualificationRecord["fixture"];
  negativeControls: NegativeControlResult[];
  environments: EnvironmentIdentity[];
  securityFindings: SecurityFinding[];
}): StateFacts {
  return {
    observed: record.observed,
    soaks: record.soaks.map((s) => ({
      id: s.id,
      boundary: s.boundary,
      iterations: s.summary.iterations,
      stable: s.summary.stable,
      stableExceptThirdPartyLeaks: s.summary.stableExceptThirdPartyLeaks,
      unstableBecause: s.summary.unstableBecause,
    })),
    fixtureAgreement: record.fixture?.reconciliation.result === "HOST_CONTAINER_OBSERVER_AGREEMENT",
    negativeControls: record.negativeControls.map((c) => ({ id: c.id, ok: c.ok })),
    positiveControl: record.negativeControls.find((c) => c.id === "P0")?.ok ?? false,
    environmentErrors: record.environments.flatMap((e) =>
      environmentErrors(e).map((x) => `${e.kind === "CONTAINER" ? "" : "HOST_"}${x}`),
    ),
    blockingFindings: record.securityFindings.filter((f) => f.blocking).map((f) => f.id),
  };
}

function recordSoaksOf(o: QualificationObservation): RecordSoak[] {
  return o.soaks.map((s) => ({
    id: s.id,
    boundary: s.boundary,
    host: o.host,
    startedAtUtc: s.startedAtUtc,
    finishedAtUtc: s.finishedAtUtc,
    table: s.table,
    iterations: s.iterations.map((it) => ({
      n: it.n,
      variation: it.variation,
      exit: it.exit,
      normalizedSha256: it.host.output.normalizedSha256,
      stableProjectionSha256: it.host.output.stableProjectionSha256,
      judgementSha256: it.host.output.judgementSha256,
      refusals: [...new Set([...it.host.output.refusals, ...it.container.output.refusals].map((r) => r.reason))].sort(),
      otherScopeAttempts: it.host.output.judgement?.otherScopeAttempts ?? null,
      reconciliation: reconcileDerivations(it.host, it.container).result,
    })),
    summary: soakSummaryOf(s.iterations, s.boundary),
  }));
}

/** The record, a pure function of the committed observation(s), the committed observer and the pinned components. */
export function qualificationRecordFrom(ctx: ValidationContext): QualificationRecord {
  const first = ctx.observations[0] ?? null;
  const o = first?.observation ?? null;
  const soaks = o === null ? [] : recordSoaksOf(o);
  const selfTestSoaks = soaks.filter((s) => s.boundary === "SELF_TEST_TABLE");
  const findings: SecurityFinding[] = SECURITY_FINDINGS.map((f) => ({
    ...f,
    evidence:
      f.id === "Q1-SF1"
        ? (o?.fixture.container.environment.container?.image.registryVerification ?? null)
        : f.id === "Q1-SF2"
          ? o === null
            ? null
            : `host ${o.fixture.host.environment.typescriptExecution}, container ${o.fixture.container.environment.typescriptExecution}`
          : f.id === "Q1-SF7"
            ? o === null
              ? null
              : `docker ${o.hostFacts.docker} on ${o.host}`
            : f.id === "Q1-SF8"
              ? selfTestSoaks.length === 0
                ? null
                : selfTestSoaks
                    .map(
                      (s) =>
                        `soak ${s.id}: iterations ${s.summary.thirdPartyLeakIterations.join(", ") || "none"} refused as EGRESS_LEAKED by another process; ${s.summary.refusalFree}/${s.summary.iterations} refusal-free`,
                    )
                    .join("; ")
              : null,
  }));
  const fixture =
    o === null
      ? null
      : {
          dir: FIXTURE_DIR_REL,
          hostExecutable: o.fixture.host.input.hostExecutable,
          host: o.fixture.host,
          container: o.fixture.container,
          reconciliation: reconcileDerivations(o.fixture.host, o.fixture.container),
        };
  const environments = o === null ? [] : [o.fixture.host.environment, o.fixture.container.environment];
  const negativeControls = o === null ? [] : o.negativeControls;
  const { state, blockers } = qualificationStateOf(
    factsOf({ observed: o !== null, soaks, fixture, negativeControls, environments, securityFindings: findings }),
  );
  const containerEnv = o?.fixture.container.environment.container ?? null;
  return {
    schema: QUALIFICATION_SCHEMA,
    lane: LANE,
    repository: REPOSITORY_ID,
    productionSp1Binding: PRODUCTION_SP1_BINDING,
    state,
    blockers,
    next:
      state === "OBSERVER_QUALIFIED_FOR_PA3D"
        ? {
            lane: NEXT_LANE,
            what: "owner-authorized v2 attributed proof exercise under the observer",
            authorization: "OWNER",
            started: false,
          }
        : null,
    qualifiedAtUtc: o?.measuredAtUtc ?? null,
    source: { commit: o?.source.commit ?? null, observerScriptSha256: ctx.committedObserverSha256 },
    observer: {
      script: OBSERVER_SCRIPT_REL,
      scriptSha256: ctx.committedObserverSha256,
      mechanism: OBSERVER_MECHANISM,
      workload: SELF_TEST_WORKLOAD_REL,
    },
    components: componentsOf(ctx, o),
    fixture,
    soaks,
    container: containerEnv,
    environments,
    negativeControls,
    securityFindings: findings,
    networkDependencies: [
      {
        phase: "HOST_DERIVATION_AND_TESTS",
        dependency: "registry.npmjs.org (npm ci: tsx and the test suite)",
        verification: "package-lock.json integrity hashes",
      },
      {
        phase: "CONTAINER_IMAGE_PROVENANCE",
        dependency: "registry-1.docker.io, one read-only manifest request by digest (no pull, nothing downloaded)",
        verification: containerEnv?.image.registryVerification ?? "not performed",
      },
      {
        phase: "CONTAINER_DERIVATION",
        dependency: "none (--network none)",
        verification:
          containerEnv === null
            ? "not run"
            : `interfaces seen inside: ${containerEnv.facts.networkInterfaces.join(", ")}`,
      },
      {
        phase: "SOAKS",
        dependency:
          "none: the workload names only TEST-NET-1 destinations, refused by every table; under the complete boundary nothing on the host leaves the VM",
        verification:
          soaks.length === 0
            ? "not run"
            : soaks
                .map((s) => `${s.id} (${s.boundary}): ${s.summary.refusalFree}/${s.summary.iterations} refusal-free`)
                .join("; "),
      },
    ],
    hostDependencies: [
      "a Linux kernel with tracefs at /sys/kernel/tracing, kprobes with BTF arguments and the kfree_skb drop-reason format (the proving host's WSL2 kernel)",
      "root on that host for the observer and the soak runner (tracefs control, nftables, setpriv)",
      "nft, setpriv, ip, getent and cat on the host's PATH /usr/sbin:/usr/bin:/sbin:/bin",
      "an unprivileged user who can read the checkout (the workload and the host derivation run as it)",
      "a Node.js able to run the observer and the workload (the host's node; its device:inode is the stand-in host's identity)",
      "a Docker engine on the same host for the container path (the native engine; Docker Desktop stayed stopped)",
      "the complete egress boundary is VM-wide while it stands (every WSL2 distribution and Docker Desktop share the network namespace)",
    ],
    derivedFrom: ctx.observations.map((x) => {
      const bytes = ctx.readFile(x.path);
      return { path: x.path, sha256: bytes === null ? "missing" : sha256Hex(bytes) };
    }),
  };
}

/** Sorted keys, two-space indentation, LF, one final newline: the one serialization of a record. */
export function serializeQualification(record: QualificationRecord): string {
  return `${JSON.stringify(JSON.parse(canonicalJson(record)), null, 2)}\n`;
}

const FORBIDDEN_KEYS = /^(proof|proofBytes|publicValues|vkey|programVKey|selector)$/;

function proofShapedKeys(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) return value.flatMap((v, i) => proofShapedKeys(v, `${prefix}${i}.`));
  if (typeof value !== "object" || value === null) return [];
  return Object.entries(value).flatMap(([k, v]) => [
    ...(FORBIDDEN_KEYS.test(k) ? [`${prefix}${k}`] : []),
    ...proofShapedKeys(v, `${prefix}${k}.`),
  ]);
}

function sectionCode(path: string): string {
  if (/^soaks\.\d+\.summary/.test(path)) return "SOAK_SUMMARY_MISMATCH";
  if (path.startsWith("negativeControls")) return "NEGATIVE_CONTROLS_MISMATCH";
  if (path.startsWith("fixture.host.output") || path.startsWith("fixture.container.output"))
    return "FIXTURE_DIGEST_MISMATCH";
  if (path.startsWith("components")) return "COMPONENT_MISMATCH";
  if (path === "state" || path.startsWith("blockers") || path.startsWith("next")) return "STATE_MISMATCH";
  return "RECORD_MISMATCH";
}

/**
 * Every reason `value` is not the qualification record the committed facts derive; [] accepts it. Nothing in the
 * record is trusted: it is regenerated from the observation and compared, the fixture is derived again here and
 * compared, the pinned components are hashed again, the negative controls are run again, and the state is recomputed.
 */
export function qualificationErrors(value: unknown, ctx: ValidationContext): string[] {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return ["SHAPE: the record is not an object"];
  const r = value as Partial<QualificationRecord> & Record<string, unknown>;
  if (r.schema !== QUALIFICATION_SCHEMA) errors.push(`SHAPE: schema is ${String(r.schema)}`);
  if (r.lane !== LANE) errors.push(`SHAPE: lane is ${String(r.lane)}`);
  if (r.repository !== REPOSITORY_ID) errors.push(`SHAPE: repository is ${String(r.repository)}`);
  if (r.productionSp1Binding !== PRODUCTION_SP1_BINDING)
    errors.push(`SHAPE: productionSp1Binding is ${String(r.productionSp1Binding)}, not ${PRODUCTION_SP1_BINDING}`);
  if (!(STATES as readonly string[]).includes(String(r.state)))
    errors.push(`SHAPE: state ${String(r.state)} is unknown`);
  for (const k of proofShapedKeys(value)) errors.push(`NO_PROOF_ARTIFACT: ${k} is a proof-shaped field`);
  const expected = qualificationRecordFrom(ctx);
  for (const d of leafDifferences(expected, value)) errors.push(`${sectionCode(d.path)}: ${d.path}`);
  if (
    r.observer?.scriptSha256 !== ctx.committedObserverSha256 ||
    r.source?.observerScriptSha256 !== ctx.committedObserverSha256
  )
    errors.push("OBSERVER_CHANGED: re-qualify (the committed observer is not the one this record qualifies)");
  if (Array.isArray(r.components)) {
    for (const c of r.components) {
      if (c.class !== "repository-pinned" || typeof c.path !== "string") continue;
      const bytes = ctx.readFile(c.path);
      const now = bytes === null ? null : sha256Hex(lf(bytes.toString("utf8")));
      if (now !== c.sha256) errors.push(`COMPONENT_CHANGED: ${c.path} is not the bytes the record pins`);
    }
  }
  if (r.fixture && typeof r.fixture === "object") {
    for (const side of ["host", "container"] as const) {
      const output = r.fixture[side]?.output;
      for (const d of leafDifferences(ctx.fixtureDerivation, output)) {
        errors.push(`FIXTURE_DIGEST_MISMATCH: ${side} output.${d.path} is not what this machine derives`);
      }
    }
  }
  const o = ctx.observations[0]?.observation;
  if (o !== undefined) {
    const raw = fixtureRawFrom(ctx.readFile);
    if (raw === null) errors.push("FIXTURE_MISSING: the committed self-test capture is not there");
    else {
      const rerun = runNegativeControls({
        raw,
        hostExecutable: o.fixture.host.input.hostExecutable,
        committedObserverSha256: ctx.committedObserverSha256,
        host: o.fixture.host,
        container: o.fixture.container,
      });
      if (canonicalJson(rerun) !== canonicalJson(r.negativeControls))
        errors.push(
          `NEGATIVE_CONTROLS_MISMATCH: re-running the controls gives ${rerun.filter((c) => c.ok).length}/${rerun.length} ok, not what the record holds`,
        );
    }
    const derived = qualificationStateOf(
      factsOf({
        observed: true,
        soaks: expected.soaks,
        fixture: expected.fixture,
        negativeControls: o.negativeControls,
        environments: expected.environments,
        securityFindings: expected.securityFindings,
      }),
    );
    if (derived.state !== r.state)
      errors.push(`STATE_MISMATCH: the facts derive ${derived.state}, the record says ${String(r.state)}`);
  } else if (r.state !== "OBSERVER_TOOLING_READY_VALIDATION_PENDING") {
    errors.push(
      `STATE_MISMATCH: the facts derive OBSERVER_TOOLING_READY_VALIDATION_PENDING, the record says ${String(r.state)}`,
    );
  }
  // A soak's boundary is a fact of the rules it ran under, re-derived here from the committed rules text.
  for (const s of expected.soaks) {
    let derivedBoundary: SoakBoundary | null = null;
    try {
      derivedBoundary = boundaryOfRules(s.table.rules);
    } catch (error) {
      errors.push(`SOAK_BOUNDARY_MISMATCH: soak ${s.id}: ${(error as Error).message}`);
    }
    if (derivedBoundary !== null && derivedBoundary !== s.boundary)
      errors.push(
        `SOAK_BOUNDARY_MISMATCH: soak ${s.id} is labelled ${s.boundary} but its rules are the ${derivedBoundary}`,
      );
    if (sha256Hex(s.table.rules) !== s.table.rulesSha256)
      errors.push(`SOAK_BOUNDARY_MISMATCH: soak ${s.id}'s rules are not the bytes rulesSha256 names`);
  }
  if (Array.isArray(r.environments)) {
    for (const e of r.environments as EnvironmentIdentity[])
      errors.push(...environmentErrors(e).map((x) => `ENVIRONMENT: ${x}`));
  }
  if (Array.isArray(r.derivedFrom)) {
    for (const d of r.derivedFrom) {
      const bytes = ctx.readFile(d.path);
      if (bytes === null || sha256Hex(bytes) !== d.sha256) errors.push(`DERIVED_FROM_MISMATCH: ${d.path}`);
    }
  }
  return [...new Set(errors)];
}

/** The validation context of a checkout: its files, its committed observer, the fixture derived now, its observations. */
export function validationContextFromRepo(repoRoot: string): ValidationContext {
  const readFile = (rel: string): Buffer | null => {
    try {
      return readFileSync(join(repoRoot, ...rel.split("/")));
    } catch {
      return null;
    }
  };
  const observerBytes = readFile(OBSERVER_SCRIPT_REL);
  if (observerBytes === null) throw new Error(`${OBSERVER_SCRIPT_REL} is missing: not a checkout`);
  const committedObserverSha256 = sha256Hex(lf(observerBytes.toString("utf8")));
  const raw = fixtureRawFrom(readFile);
  if (raw === null) throw new Error(`${FIXTURE_DIR_REL} is incomplete: the committed self-test capture is needed`);
  const dir = join(repoRoot, ...OBSERVATIONS_DIR_REL.split("/"));
  const names = readdirSync(dir)
    .filter((n) => n.startsWith(OBSERVATION_PREFIX) && n.endsWith(".raw.json"))
    .sort();
  return {
    readFile,
    committedObserverSha256,
    fixtureDerivation: deriveQualification(raw, FIXTURE_HOST_EXECUTABLE, committedObserverSha256),
    observations: names.map((n) => {
      const path = `${OBSERVATIONS_DIR_REL}/${n}`;
      const observation = JSON.parse(lf((readFile(path) as Buffer).toString("utf8"))) as QualificationObservation;
      if (observation.schema !== OBSERVATION_SCHEMA) throw new Error(`${path} is not a qualification observation`);
      return { path, observation };
    }),
  };
}

/** The committed fixture, read through `readFile` (LF-normalized as the kernel wrote it: a CRLF checkout reads back). */
export function fixtureRawFrom(readFile: ValidationContext["readFile"]): RawEvidence | null {
  const read = (name: string) => {
    const bytes = readFile(`${FIXTURE_DIR_REL}/${name}`);
    return bytes === null ? null : lf(bytes.toString("latin1"));
  };
  const trace = read("trace.txt");
  const facts = read("facts.json");
  const manifest = read("manifest.json");
  if (trace === null || facts === null || manifest === null) return null;
  return { trace, facts, manifest };
}
