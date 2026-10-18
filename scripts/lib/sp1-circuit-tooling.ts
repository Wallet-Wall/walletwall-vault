/**
 * SP1-PA2A: the circuit-tooling contract (evidence/zk/sp1-impl/circuit-tooling.json) and what it is derived from.
 *
 *   the production anchor: designation d1 (PROGRAM_VKEY, verifier, VERIFIER_HASH) and the proving-availability
 *     record's groth16_vk.bin length; a record serves d1's circuit only if its subject is exactly this;
 *   the upstream observation (scripts/measure-sp1-circuit-upstream.ts): what the pinned SP1 crates do with the
 *     circuit directory, the gnark image and the prover mode, and every environment variable they read, measured
 *     from the .crate bytes zkvm/host/Cargo.lock pins;
 *   the gate's own rules (sp1-circuit-archive.ts, sp1-circuit-install.ts, sp1-prove-gate.ts), checked against that
 *     observation: every variable that selects the circuit, the prover or the gnark image is frozen or refused;
 *   a self-test over the synthetic fixtures (test/fixtures/sp1-proving-archives): the safe archive inspects, installs
 *     and passes the gate with a stub image store; every hostile archive meets its refusal; the production anchor
 *     refuses every fixture; and no production archive record exists.
 *
 * The state is TOOLING_READY_NO_ARTIFACT. It never moves PROVING_AVAILABILITY, which stays OWNER_DOWNLOAD_REQUIRED:
 * tooling is not an artifact, and an artifact is not proving. Research prototype. Not audited. Testnet/local only.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { gunzipSync } from "node:zlib";

import {
  APPLEDOUBLE_BODIES,
  APPLEDOUBLE_PATHS,
  ARCHIVE_RECORD_SCHEMA,
  CircuitToolingError,
  IGNORED_APPLEDOUBLE_METADATA,
  IGNORED_PROVENANCE_METADATA,
  MIN_ACQUISITIONS,
  MIN_MIRRORS,
  PROVENANCE_ENTRIES,
  PROVENANCE_ONLY,
  PROVENANCE_PAX_KEY,
  PROVENANCE_VALUE,
  REFUSAL_CODES,
  REQUIRED_MEMBERS,
  VK_FILE,
  archiveRecordErrors,
  inspectArchive,
  refuse,
  type ArchiveAnchor,
  type ArchiveRecord,
} from "./sp1-circuit-archive";
import { CENSUS_SCHEMA, type Census } from "./sp1-circuit-archive-census";
import {
  SAFE_ARCHIVE_REL,
  SAFE_FILES,
  SAFE_RECORD_REL,
  SYNTHETIC_ANCHOR,
  SYNTHETIC_ANCHOR_REL,
  UPSTREAM_SHAPED_FILES,
  appleDoubleMetadata,
  gz,
  hostileCases,
  safeTar,
  syntheticRecord,
  tarBytes,
  upstreamShapedEntries,
} from "./sp1-circuit-fixtures";
import { installCircuitArchive, verifyInstalledCircuit } from "./sp1-circuit-install";
import { DESIGNATIONS_DIR, designationSetErrors, latestDesignation, readDesignations } from "./sp1-designation";
import {
  FROZEN_ENV,
  LOCAL_PROVER,
  PASS_THROUGH_ENV,
  REFUSED_ENV,
  REFUSED_ENV_PREFIX,
  prepareArchiveOnlyProve,
  type LocalImageDigests,
} from "./sp1-prove-gate";
import {
  HOST_LOCK_REL,
  PROVING_ARCHIVES_DIR,
  PROVING_AVAILABILITY_REL,
  archiveRecordsIn,
  lockedCrates,
  readTarMembers,
  type LockedCrate,
} from "./sp1-proving-availability";

export const TOOLING_REL = "evidence/zk/sp1-impl/circuit-tooling.json";
export const TOOLING_SCHEMA = "walletwall.sp1-circuit-tooling.v1";
export const ARCHIVE_JSON_SCHEMA_REL = "evidence/zk/schema/sp1-proving-archive.v2.schema.json";
export const UPSTREAM_OBSERVATION_REL =
  "evidence/zk/sp1-impl/observations/circuit-upstream-developer-workstation.raw.json";
export const UPSTREAM_SCHEMA = "walletwall.sp1-circuit-upstream.v1";
export const UPSTREAM_SCRIPT_REL = "scripts/measure-sp1-circuit-upstream.ts";
/** Variables the pinned SP1 reads that the gate passes through anyway, each reviewed: HOME only locates ~/.sp1, which
 * the frozen SP1_GROTH16_CIRCUIT_PATH replaces. */
export const REVIEWED_PASS_THROUGH: readonly string[] = ["HOME"];
/** Library sources that read the environment by a non-literal name, each reviewed: sp1-build's local build command
 * forwards the build environment to cargo; it runs in zkvm/host/build.rs (the ELF build), never in a proving run. */
export const REVIEWED_NON_LITERAL_READS: readonly string[] = ["sp1-build/src/command/local.rs"];
/**
 * The census of the upstream v6.1.0 archive (scripts/sp1-circuit-archive-census.ts output, verbatim) on each host that
 * acquired it: the developer workstation, and a GitHub-hosted runner (a re-acquisition of host B's bytes, whose first
 * copy its ephemeral runner deleted after measuring it). The AppleDouble and provenance policies are derived from them.
 */
export const CENSUS_OBSERVATIONS_REL: readonly string[] = [
  "evidence/zk/sp1-impl/observations/circuit-archive-census-developer-workstation.raw.json",
  "evidence/zk/sp1-impl/observations/circuit-archive-census-github-hosted-runner.raw.json",
];

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

export const STATES = [
  {
    state: "TOOLING_NOT_PRESENT",
    meaning: "no WalletWall archive inspection, installer or prove gate exists (main before SP1-PA2A)",
    reachableInThisLane: true,
  },
  {
    state: "TOOLING_READY_NO_ARTIFACT",
    meaning:
      "the inspection, installer and archive-only prove gate exist and pass their self-test, and no WalletWall archive record exists",
    reachableInThisLane: true,
  },
  {
    state: "ARCHIVED_VERIFIED_UNEXERCISED",
    meaning:
      "an owner-authorized acquisition produced an accepted record (two agreeing hosts, two WalletWall mirrors, the gnark image by digest); no proof has been made from it",
    reachableInThisLane: false,
  },
  {
    state: "SELF_HOSTED_PATH_EXERCISED",
    meaning:
      "a real Groth16 proof was made through this gate from the archive, egress off, and accepted by the designated verifier",
    reachableInThisLane: false,
  },
] as const;
export type ToolingState = (typeof STATES)[number]["state"];

// ---------------------------------------------------------------------------------------------------------------
// The production anchor and the authoritative record location
// ---------------------------------------------------------------------------------------------------------------

/** What a production archive must serve: designation d1's circuit, from committed evidence only. */
export function productionAnchor(repoRoot = "."): ArchiveAnchor {
  const set = readDesignations(repoRoot);
  const malformed = designationSetErrors(set);
  if (malformed.length > 0) throw new Error(`the designations are not a valid set: ${malformed.join("; ")}`);
  const d = latestDesignation(set);
  const pa = JSON.parse(readFileSync(resolve(repoRoot, PROVING_AVAILABILITY_REL), "utf8"));
  const vk = (pa?.expectedArtifacts?.members ?? []).find((m: { file?: string }) => m?.file === VK_FILE);
  if (
    !d ||
    !Array.isArray(pa?.designations) ||
    !pa.designations.includes(d.id) ||
    pa.expectedArtifacts?.circuitVersion !== d.verifier.version ||
    vk?.sha256 !== d.verifier.verifierHash ||
    !Number.isSafeInteger(vk?.bytes)
  ) {
    throw new Error(`${PROVING_AVAILABILITY_REL} and the latest designation do not name one circuit and verifying key`);
  }
  return {
    designation: d.id,
    circuitVersion: d.verifier.version,
    programVKey: d.programVKey,
    verifier: {
      version: d.verifier.version,
      runtimeCodeKeccak: d.verifier.runtimeCodeKeccak,
      verifierHash: d.verifier.verifierHash,
    },
    verifyingKey: { sha256: d.verifier.verifierHash, bytes: vk.bytes },
  };
}

/** Why `recordPath` is not a production record (a regular .json file directly in PROVING_ARCHIVES_DIR), or null. */
export function authoritativeRecordError(recordPath: string, repoRoot = "."): string | null {
  let real: string;
  try {
    if (!lstatSync(recordPath).isFile()) return "NOT_A_FILE";
    real = realpathSync(recordPath);
  } catch {
    return "ABSENT";
  }
  const dir = join(realpathSync(resolve(repoRoot)), ...PROVING_ARCHIVES_DIR.split("/"));
  if (dirname(real) !== dir) return "OUTSIDE_PROVING_ARCHIVES";
  if (!real.endsWith(".json")) return "NOT_JSON";
  return null;
}

/** The evidence the production anchor is read from; it counts only as committed. */
export const ANCHOR_EVIDENCE: readonly string[] = [DESIGNATIONS_DIR, PROVING_AVAILABILITY_REL];

/**
 * Why `paths` (repository-relative) are not exactly what HEAD commits, or null. Git is the evidence's anchor: an
 * uncommitted designation, availability record or archive record is nobody's reviewed claim.
 */
export function uncommittedEvidenceError(paths: readonly string[], repoRoot: string): string | null {
  const git = (...args: string[]) =>
    spawnSync("git", ["-C", repoRoot, "--no-optional-locks", ...args], { encoding: "utf8", shell: false });
  if (git("rev-parse", "--is-inside-work-tree").stdout.trim() !== "true") return "NOT_A_GIT_CHECKOUT";
  for (const p of paths) {
    if (git("ls-files", "--error-unmatch", "--", p).status !== 0) return `UNTRACKED ${p}`;
  }
  const status = git("status", "--porcelain", "--untracked-files=all", "--", ...paths);
  if (status.status !== 0) return "GIT_STATUS_FAILED";
  const first = status.stdout.split("\n").find((l) => l.trim() !== "");
  return first === undefined ? null : `UNCOMMITTED ${first.trim()}`;
}

/** The production anchor from `repoRoot`'s committed evidence (the CLIs pass the checkout they live in, never cwd). */
export function committedProductionAnchor(repoRoot: string): ArchiveAnchor {
  const bad = uncommittedEvidenceError(ANCHOR_EVIDENCE, repoRoot);
  if (bad)
    throw refuse("EVIDENCE_NOT_COMMITTED", bad.split(" ")[0], `the anchor's evidence is not as committed: ${bad}`);
  return productionAnchor(repoRoot);
}

/** The production record at `recordPath`: in PROVING_ARCHIVES_DIR, and exactly as committed. */
export function committedProductionRecord(recordPath: string, repoRoot: string): unknown {
  const bad = authoritativeRecordError(recordPath, repoRoot);
  if (bad) throw refuse("RECORD_NOT_AUTHORITATIVE", bad, `${recordPath} is not a production archive record`);
  const rel = relative(realpathSync(repoRoot), realpathSync(recordPath)).split(sep).join("/");
  const dirty = uncommittedEvidenceError([rel], repoRoot);
  if (dirty) throw refuse("RECORD_NOT_AUTHORITATIVE", dirty.split(" ")[0], `${rel} is not as committed: ${dirty}`);
  return JSON.parse(readFileSync(recordPath, "utf8"));
}

// ---------------------------------------------------------------------------------------------------------------
// The upstream observation
// ---------------------------------------------------------------------------------------------------------------

export interface UpstreamFacts {
  circuitVersion: string;
  groth16Dir: { env: string; valueUsedVerbatim: boolean; joinsVersion: boolean; fallback: string };
  install: { onlyWhenAbsent: boolean; verifiesDigest: boolean; extractFlags: string; url: string };
  circuitMode: { env: string; devValue: string };
  prover: { env: string; default: string; modes: string[] };
  gnark: { env: string; defaultImage: string; dockerRunArgs: string[]; pullFlag: boolean; mountSpec: string };
}

export interface UpstreamObservation {
  schema: string;
  measuredAtUtc: string;
  host: string;
  tool: { script: string; scriptSha256: string };
  lockfile: { path: string; sha256: string };
  crates: { name: string; version: string; checksum: string; rustSources: number }[];
  /** Every variable a pinned crate reads by literal name in its library sources, and which crates read it. */
  environment: Record<string, string[]>;
  /** Reads whose name is not a literal (they are listed for review; none may be in src/). */
  nonLiteralEnvironmentReads: string[];
  facts: UpstreamFacts;
}

/** The crates the observation measures: every sp1-* and slop-* registry crate the host lockfile pins. */
export function upstreamCrates(lockText: string): LockedCrate[] {
  const out: LockedCrate[] = [];
  for (const [name, c] of lockedCrates(lockText)) {
    if (!/^(sp1|slop)-/.test(name)) continue;
    if (c === null) throw new Error(`${HOST_LOCK_REL} pins more than one version of ${name}`);
    out.push(c);
  }
  return out.sort((a, b) => (a.name < b.name ? -1 : 1));
}

const noLonger = (what: string) => new Error(`the pinned SP1 source no longer reads as SP1-PA2A read it: ${what}`);
function must(text: string, re: RegExp, what: string): RegExpExecArray {
  const m = re.exec(text);
  if (!m) throw noLonger(what);
  return m;
}
function body(text: string, signature: string): string {
  const start = text.indexOf(signature);
  const end = start < 0 ? -1 : text.indexOf("\n}", start);
  if (end < 0) throw noLonger(signature);
  return text.slice(start, end);
}

/** The facts the gate depends on, read from the pinned sources (each regex is the lane's reading, re-checked). */
export function readUpstreamFacts(src: (crate: string, member: string) => string): UpstreamFacts {
  const version = src("sp1-prover", "SP1_CIRCUIT_VERSION").trim();
  const build = src("sp1-prover", "src/build.rs");
  const dir = body(build, "pub fn groth16_circuit_artifacts_dir()");
  const dirEnv = must(dir, /match std::env::var\("([A-Z0-9_]+)"\) \{\s*Ok\(path\) => PathBuf::from\(path\),/, "dir")[1];
  const fallback = must(dir, /home_dir\.join\("\.sp1"\)\.join\("([^"]+)"\)/, "the fallback directory")[1];
  const install = body(build, "pub async fn install_circuit_artifacts(");
  const download = body(build, "pub async fn download_file(");
  const mode = body(build, "pub(crate) fn use_development_mode()");
  const modeEnv = must(
    mode,
    /std::env::var\("([A-Z0-9_]+)"\)\.unwrap_or\("release"\.to_string\(\)\) == "([a-z]+)"/,
    "mode",
  );
  const env = src("sp1-sdk", "src/blocking/env/mod.rs");
  const selector = body(env, "pub fn from_env_with_opts_and_machine(");
  const proverEnv = must(
    selector,
    /let prover = match std::env::var\("([A-Z0-9_]+)"\) \{\s*Ok\(prover\) => prover,\s*Err\(_\) => "([a-z]+)"\.to_string\(\),/,
    "the prover selector",
  );
  const match = must(selector, /match prover\.as_str\(\) \{([\s\S]*?)_ => unreachable!\(\),/, "the prover modes")[1];
  const arms = [...match.matchAll(/^\s*"([a-z]+)" =>/gm)].map((m) => m[1]);
  const docker = src("sp1-recursion-gnark-ffi", "src/ffi/docker.rs");
  const image = must(
    docker,
    /std::env::var\("([A-Z0-9_]+)"\)\s*\.unwrap_or_else\(\|_\| format!\("([^"]+)"\)\)/,
    "the image",
  );
  const run = body(docker, "fn call_docker(");
  const runArgs = must(run, /cmd\.args\(\[("[^\]]+")\]\);/, "the docker run arguments")[1];
  const mount = must(run, /cmd\.arg\("-v"\)\.arg\(format!\("([^"]+)"\)\);/, "the mount")[1];
  return {
    circuitVersion: version,
    groth16Dir: {
      env: dirEnv,
      valueUsedVerbatim: true,
      joinsVersion: /Ok\(base_path\.join\(SP1_CIRCUIT_VERSION\)\)/.test(dir),
      fallback: `~/.sp1/${fallback}`,
    },
    install: {
      onlyWhenAbsent: /if build_dir\.exists\(\) \{[\s\S]*?\} else \{[\s\S]*?install_circuit_artifacts\(/.test(
        body(build, "pub async fn try_install_circuit_artifacts("),
      ),
      verifiesDigest: /sha2|sha256|checksum|digest|verify/i.test(install + download),
      extractFlags: must(install, /Command::new\("tar"\)\.args\(\["(-[A-Za-z]+)"/, "the extraction")[1],
      url: must(build, /CIRCUIT_ARTIFACTS_URL_BASE: &str = "(https:\/\/[^"]+)"/, "the URL base")[1],
    },
    circuitMode: { env: modeEnv[1], devValue: modeEnv[2] },
    prover: { env: proverEnv[1], default: proverEnv[2], modes: [...new Set(arms)].sort() },
    gnark: {
      env: image[1],
      defaultImage: image[2].replace("{SP1_CIRCUIT_VERSION}", version),
      dockerRunArgs: [...runArgs.matchAll(/"([^"]+)"/g)].map((m) => m[1]),
      pullFlag: /--pull/.test(docker),
      mountSpec: mount,
    },
  };
}

/** The literal environment reads in a crate's library sources (`src/**.rs`), and any non-literal ones. */
export function environmentReads(crate: string, files: ReadonlyMap<string, string>) {
  const names = new Set<string>();
  const nonLiteral: string[] = [];
  for (const [path, text] of files) {
    for (const m of text.matchAll(/env::var(?:_os)?\(\s*"([A-Za-z0-9_]+)"/g)) names.add(m[1]);
    text.split("\n").forEach((line, i) => {
      if (/env::var(?:_os)?\(\s*[^"\s)]/.test(line) || /env::vars(?:_os)?\(\)/.test(line)) {
        nonLiteral.push(`${crate}/${path}:${i + 1}`);
      }
    });
  }
  return { names: [...names].sort(), nonLiteral };
}

/** The cached .crate of `c` under CARGO_HOME; every cached copy must be the bytes the lockfile pins. */
function cachedCrateBytes(cargoHome: string, c: LockedCrate): Buffer {
  const cache = join(cargoHome, "registry", "cache");
  const copies = existsSync(cache)
    ? readdirSync(cache)
        .sort()
        .map((index) => join(cache, index, `${c.name}-${c.version}.crate`))
        .filter((f) => existsSync(f))
    : [];
  if (copies.length === 0) throw new Error(`${c.name} ${c.version} is not in the cargo cache at ${cache}`);
  for (const f of copies) {
    if (sha256(readFileSync(f)) !== c.checksum) throw new Error(`${f} is not the crate ${HOST_LOCK_REL} pins`);
  }
  return readFileSync(copies[0]);
}

/** Measures, read-only and offline, the pinned crates' circuit, prover and gnark behavior and environment reads. */
export function measureUpstream(input: {
  repoRoot: string;
  cargoHome: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
}): UpstreamObservation {
  const lock = readFileSync(resolve(input.repoRoot, HOST_LOCK_REL));
  const environment: Record<string, string[]> = {};
  const nonLiteral: string[] = [];
  const sources = new Map<string, Map<string, Buffer>>();
  const crates = upstreamCrates(lock.toString("utf8")).map((c) => {
    const members = readTarMembers(cachedCrateBytes(input.cargoHome, c));
    const root = `${c.name}-${c.version}/`;
    sources.set(c.name, new Map([...members].map(([p, b]) => [p.slice(root.length), b])));
    const rust = new Map(
      [...members]
        .filter(([p]) => p.startsWith(`${root}src/`) && p.endsWith(".rs"))
        .map(([p, b]) => [p.slice(root.length), b.toString("utf8")]),
    );
    const reads = environmentReads(c.name, rust);
    for (const name of reads.names) (environment[name] ??= []).push(c.name);
    nonLiteral.push(...reads.nonLiteral);
    return { name: c.name, version: c.version, checksum: c.checksum, rustSources: rust.size };
  });
  const src = (crate: string, member: string) => {
    const b = sources.get(crate)?.get(member);
    if (!b) throw noLonger(`${crate} has no ${member}`);
    return b.toString("utf8");
  };
  return {
    schema: UPSTREAM_SCHEMA,
    measuredAtUtc: input.measuredAtUtc,
    host: input.host,
    tool: input.tool,
    lockfile: { path: HOST_LOCK_REL, sha256: sha256(lock) },
    crates,
    environment: Object.fromEntries(Object.entries(environment).sort(([a], [b]) => (a < b ? -1 : 1))),
    nonLiteralEnvironmentReads: nonLiteral.sort(),
    facts: readUpstreamFacts(src),
  };
}

/** Every reason a committed upstream observation is not bound to this repository's host lockfile and script. */
export function upstreamObservationErrors(obs: UpstreamObservation, repoRoot = "."): string[] {
  const errors: string[] = [];
  if (obs?.schema !== UPSTREAM_SCHEMA) errors.push(`the upstream observation's schema must be ${UPSTREAM_SCHEMA}`);
  const script = resolve(repoRoot, UPSTREAM_SCRIPT_REL);
  if (
    obs?.tool?.script !== UPSTREAM_SCRIPT_REL ||
    !existsSync(script) ||
    obs.tool.scriptSha256 !== sha256(readFileSync(script))
  ) {
    errors.push(`the upstream observation was not made by ${UPSTREAM_SCRIPT_REL} as committed: re-measure`);
  }
  const lock = readFileSync(resolve(repoRoot, HOST_LOCK_REL));
  if (obs?.lockfile?.path !== HOST_LOCK_REL || obs.lockfile.sha256 !== sha256(lock)) {
    errors.push(`the upstream observation measured another ${HOST_LOCK_REL}: re-measure`);
  }
  const want = upstreamCrates(lock.toString("utf8")).map((c) => `${c.name} ${c.version} ${c.checksum}`);
  const got = (Array.isArray(obs?.crates) ? obs.crates : []).map((c) => `${c?.name} ${c?.version} ${c?.checksum}`);
  if (want.join() !== got.join())
    errors.push("the upstream observation does not measure exactly the pinned sp1/slop crates");
  if (!obs?.environment || typeof obs.environment !== "object") errors.push("the environment census is missing");
  const reads = Array.isArray(obs?.nonLiteralEnvironmentReads) ? obs.nonLiteralEnvironmentReads : null;
  const unreviewed = reads?.filter((r) => !REVIEWED_NON_LITERAL_READS.some((p) => String(r).startsWith(`${p}:`)));
  if (!reads || (unreviewed ?? []).length > 0) {
    errors.push(
      `a pinned crate reads the environment by a non-literal name (${(unreviewed ?? []).join(", ")}): review it`,
    );
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------------------------
// The gate's environment classes, checked against the census
// ---------------------------------------------------------------------------------------------------------------

export type EnvClass = "FROZEN" | "REFUSED" | "PASSED" | "DROPPED";

/** How the gate treats a variable a caller sets: the same rules buildProverEnv applies. */
export function envClass(name: string): EnvClass {
  const K = name.toUpperCase();
  if ((FROZEN_ENV as readonly string[]).includes(K)) return "FROZEN";
  if (REFUSED_ENV[K] !== undefined || K.startsWith(REFUSED_ENV_PREFIX)) return "REFUSED";
  if (PASS_THROUGH_ENV.includes(K)) return "PASSED";
  return "DROPPED";
}

/** Every way the gate's rules do not cover what the pinned SP1 reads. */
export function gateCoverageErrors(
  facts: UpstreamFacts,
  environment: Record<string, string[]>,
  anchor: ArchiveAnchor,
): string[] {
  const errors: string[] = [];
  if (facts.circuitVersion !== anchor.circuitVersion) {
    errors.push(`the pinned prover's circuit ${facts.circuitVersion} is not the designated ${anchor.circuitVersion}`);
  }
  const bound: [string, EnvClass, string][] = [
    [facts.groth16Dir.env, "FROZEN", "the circuit directory"],
    [facts.gnark.env, "FROZEN", "the gnark image"],
    [facts.prover.env, "FROZEN", "the prover mode"],
    [facts.circuitMode.env, "REFUSED", "the development circuit mode"],
  ];
  for (const [name, want, what] of bound) {
    if (envClass(name) !== want)
      errors.push(`${what} is selected by ${name}, which the gate does not ${want === "FROZEN" ? "freeze" : "refuse"}`);
  }
  if (!facts.prover.modes.includes(LOCAL_PROVER)) errors.push(`the pinned prover has no ${LOCAL_PROVER} mode`);
  if (!facts.groth16Dir.joinsVersion) errors.push("the pinned prover no longer reads <root>/<circuit version>");
  for (const name of Object.keys(environment)) {
    if (envClass(name) === "PASSED" && !REVIEWED_PASS_THROUGH.includes(name)) {
      errors.push(`the gate passes ${name} through, and the pinned SP1 reads it: review it`);
    }
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------------------------
// The metadata policies, checked against the census they are derived from
// ---------------------------------------------------------------------------------------------------------------

/** A census entry's path as the parser names it, one leading "./" dropped: the upstream root, "./", is "". Any other
 * spelling of an entry names no characterized one, and is refused. */
const censusPath = (p: string) => (p.startsWith("./") ? p.slice(2) : p);

/**
 * Every way the AppleDouble and provenance constants are not exactly what `census` observed: the bodies, the
 * namespace, each entry's companion, type and PAX header, and the provenance value and the entries carrying it.
 */
export function censusPolicyErrors(census: Census): string[] {
  const errors: string[] = [];
  if (census?.schema !== CENSUS_SCHEMA) return [`a census must be ${CENSUS_SCHEMA}`];
  const key = (b: { bytes: number; sha256: string }) => `${b.bytes}:${b.sha256}`;
  const observed = [...new Set(census.appleDouble.map((r) => key({ bytes: r.size, sha256: r.sha256 })))].sort();
  if (observed.join() !== APPLEDOUBLE_BODIES.map(key).sort().join()) {
    errors.push(`APPLEDOUBLE_BODIES is not exactly the bodies the census observed (${observed.join(", ")})`);
  }
  const paths = census.appleDouble.map((r) => r.path).sort();
  if (paths.join() !== [...APPLEDOUBLE_PATHS].sort().join()) {
    errors.push(`APPLEDOUBLE_PATHS is not exactly the AppleDouble entries the census observed (${paths.join(", ")})`);
  }
  for (const r of census.appleDouble) {
    const clashes = [
      ...r.sameAsOther,
      ...r.caseFoldSameAsOther,
      ...r.windowsNameSameAsOther,
      ...r.parentOfOther,
      ...r.otherIsParent,
    ];
    if (r.typeflag !== "0") errors.push(`the census's ${r.path} is not a regular file`);
    if (!r.companionFollows) errors.push(`the census's ${r.path} is not followed by the entry it describes`);
    if (clashes.length > 0) errors.push(`the census's ${r.path} collides with ${clashes.join(", ")}`);
    if (census.entries[r.index]?.pax.length !== 0) errors.push(`the census's ${r.path} has a PAX header`);
  }
  const carrying = census.entries.flatMap((e) => {
    const p = e.typeflag === "x" || e.typeflag === "g" ? undefined : e.pax.find((x) => x.key === PROVENANCE_PAX_KEY);
    return p ? [{ e, p }] : [];
  });
  const kindOf = (typeflag: string) => (typeflag === "5" ? "directory" : "file");
  const got = carrying.map(({ e }) => `${censusPath(e.path)}:${kindOf(e.typeflag)}`).sort();
  if (
    got.join() !==
    PROVENANCE_ENTRIES.map((e) => `${e.path}:${e.kind}`)
      .sort()
      .join()
  ) {
    errors.push(`PROVENANCE_ENTRIES is not exactly the entries the census observed carrying ${PROVENANCE_PAX_KEY}`);
  }
  for (const { e, p } of carrying) {
    if (p.valueBytes !== PROVENANCE_VALUE.length || p.valueSha256 !== sha256(PROVENANCE_VALUE)) {
      errors.push(`the census's ${e.path} carries another ${PROVENANCE_PAX_KEY} value than PROVENANCE_VALUE`);
    }
  }
  return errors;
}

/** The census tool's output for `census`, byte for byte: what each observation file holds. */
export const serializeCensus = (census: unknown) => `${JSON.stringify(census, null, 2)}\n`;

/**
 * The committed census observations: each exactly the census tool's output (line ends aside, so an autocrlf checkout
 * still reads as committed, and a reformatted copy does not), all one census, and the policies derived from it.
 */
export function censusObservationErrors(repoRoot = "."): string[] {
  const texts = CENSUS_OBSERVATIONS_REL.map((rel) => {
    const path = resolve(repoRoot, rel);
    return existsSync(path) ? readFileSync(path, "utf8").replace(/\r\n/g, "\n") : `absent ${rel}`;
  });
  if (texts.some((t) => t !== texts[0])) return ["the census observations are not one census"];
  const census = JSON.parse(texts[0]);
  if (serializeCensus(census) !== texts[0]) return ["the census observations are not the census tool's output"];
  return censusPolicyErrors(census as Census);
}

// ---------------------------------------------------------------------------------------------------------------
// The self-test
// ---------------------------------------------------------------------------------------------------------------

export interface SelfTestCase {
  id: string;
  title: string;
  refusal: string;
}

export interface SelfTest {
  fixtures: { path: string; sha256: string }[];
  safe: string[];
  hostile: SelfTestCase[];
  gate: SelfTestCase[];
  productionAnchorRefusesFixtures: string[];
  productionArchiveRecords: number;
}

const refusalOf = (e: unknown) =>
  e instanceof CircuitToolingError ? `${e.code} (${e.reason})` : `UNEXPECTED: ${(e as Error)?.message ?? e}`;

async function refusalOfAsync(f: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await f();
    return "NOT_REFUSED";
  } catch (error) {
    return refusalOf(error);
  }
}

/** Makes a tree this process created writable again (an installation is read-only), never through a link. */
export function makeWritable(dir: string): void {
  if (!existsSync(dir)) return;
  chmodSync(dir, 0o700);
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) makeWritable(full);
    else if (e.isFile()) chmodSync(full, 0o600);
  }
}

/** The tooling's self-test over the committed synthetic fixtures. Throws on the first expectation it does not meet. */
export async function runSelfTest(repoRoot = "."): Promise<SelfTest> {
  const read = (rel: string) => readFileSync(resolve(repoRoot, rel));
  const archive = read(SAFE_ARCHIVE_REL);
  const recordBytes = read(SAFE_RECORD_REL);
  const anchorBytes = read(SYNTHETIC_ANCHOR_REL);
  const fail = (what: string) => {
    throw new Error(`the circuit tooling self-test failed: ${what}`);
  };
  if (!gunzipSync(archive).equals(safeTar())) fail(`${SAFE_ARCHIVE_REL} is not the safe synthetic tree`);
  const record = JSON.parse(recordBytes.toString("utf8")) as ArchiveRecord;
  if (JSON.stringify(record) !== JSON.stringify(syntheticRecord(archive, SAFE_FILES))) {
    fail(`${SAFE_RECORD_REL} is not the synthetic record of ${SAFE_ARCHIVE_REL}`);
  }
  if (JSON.stringify(JSON.parse(anchorBytes.toString("utf8")).anchor) !== JSON.stringify(SYNTHETIC_ANCHOR)) {
    fail(`${SYNTHETIC_ANCHOR_REL} is not the synthetic anchor`);
  }
  const anchor = SYNTHETIC_ANCHOR;
  const work = mkdtempSync(join(tmpdir(), "sp1-circuit-selftest-"));
  try {
    const archivePath = join(work, "synthetic-safe.tar.gz");
    writeFileSync(archivePath, archive);
    const safe: string[] = [];
    const inspected = await inspectArchive(archivePath, { anchor, record });
    safe.push(`inspected against its record: ${inspected.members.length} members, sha256 ${inspected.archive.sha256}`);
    const root = join(work, "circuits");
    mkdirSync(root);
    const installed = await installCircuitArchive({ archivePath, record, anchor, destinationRoot: root });
    safe.push(`installed and re-verified at <root>/${relative(root, installed.circuitDir).split(sep).join("/")}`);
    const again = await refusalOfAsync(() =>
      installCircuitArchive({ archivePath, record, anchor, destinationRoot: root }),
    );
    if (again !== "INSTALL_TARGET_EXISTS (EXISTS)") fail(`a second installation was not refused (${again})`);
    safe.push(`a second installation is refused: ${again}`);
    const upArchive = gz(tarBytes(upstreamShapedEntries()));
    const upRecord = syntheticRecord(
      upArchive,
      UPSTREAM_SHAPED_FILES,
      anchor,
      appleDoubleMetadata(UPSTREAM_SHAPED_FILES),
    );
    const upPath = join(work, "synthetic-upstream-shaped.tar.gz");
    writeFileSync(upPath, upArchive);
    const up = await inspectArchive(upPath, { anchor, record: upRecord });
    safe.push(
      `the upstream-shaped archive inspected against its record: ${up.members.length} members; ${up.metadata.length} AppleDouble entries and ${up.provenance.length} provenance records ignored`,
    );
    const upRoot = join(work, "circuits-upstream-shaped");
    mkdirSync(upRoot);
    const upInstalled = await installCircuitArchive({
      archivePath: upPath,
      record: upRecord,
      anchor,
      destinationRoot: upRoot,
    });
    const installedNames = readdirSync(upInstalled.circuitDir).sort();
    if (
      installedNames.join() !==
      UPSTREAM_SHAPED_FILES.map(([p]) => p)
        .sort()
        .join()
    ) {
      fail(`the upstream-shaped installation holds ${installedNames.join(", ")}`);
    }
    safe.push(`installed it: the tree holds its ${installedNames.length} members only, no AppleDouble file`);
    const host = join(work, "host");
    const inputs = join(work, "inputs.json");
    writeFileSync(host, "synthetic host: never run");
    writeFileSync(inputs, "{}");
    const imageRef = `${record.gnark.repository}@${record.gnark.digest}`;
    const present: LocalImageDigests = (ref) => (ref === imageRef ? [imageRef] : null);
    const input = (env: Record<string, string>, over: Partial<{ root: string }> = {}) => ({
      record,
      anchor,
      circuitRoot: over.root ?? root,
      hostExecutable: host,
      inputsPath: inputs,
      callerEnv: env,
    });
    const plan = prepareArchiveOnlyProve(input({ PATH: "/usr/bin", SP1_WORKER_NUM_CORE_WORKERS: "2" }), present);
    const keys = Object.keys(plan.env).sort().join(",");
    if (
      keys !== "DOCKER_CONTEXT,PATH,SP1_GNARK_IMAGE,SP1_GROTH16_CIRCUIT_PATH,SP1_PROVER" ||
      plan.env.SP1_GNARK_IMAGE !== imageRef
    ) {
      fail(`the gate built another environment (${keys})`);
    }
    safe.push(`the gate passes with the image present by digest; the child gets only ${keys}`);

    const hostile: SelfTestCase[] = [];
    for (const c of hostileCases()) {
      const p = join(work, `${c.id}.tar.gz`);
      writeFileSync(p, c.archive);
      const auto = syntheticRecord(c.archive, SAFE_FILES);
      const rec = c.record === undefined ? undefined : c.record === "auto" ? auto : c.record(auto);
      const got = await refusalOfAsync(() => inspectArchive(p, { anchor, record: rec, limits: c.limits }));
      if (got !== `${c.expect.code} (${c.expect.reason})`) fail(`${c.id} (${c.title}): ${got}`);
      hostile.push({ id: c.id, title: c.title, refusal: got });
    }

    const gate: SelfTestCase[] = [];
    const expectGate = async (id: string, title: string, want: string, f: () => unknown) => {
      const got = await refusalOfAsync(f);
      if (got !== want) fail(`gate ${id} (${title}): ${got}`);
      gate.push({ id, title, refusal: got });
    };
    await expectGate("G01", "SP1_CIRCUIT_MODE=dev", "ENV_REFUSED (CIRCUIT_MODE)", () =>
      prepareArchiveOnlyProve(input({ SP1_CIRCUIT_MODE: "dev" }), present),
    );
    await expectGate("G02", "a prover-network key", "ENV_REFUSED (PROVER_NETWORK)", () =>
      prepareArchiveOnlyProve(input({ NETWORK_PRIVATE_KEY: "synthetic" }), present),
    );
    await expectGate("G03", "SP1_PROVER=network", "ENV_REFUSED (PROVER_MODE)", () =>
      prepareArchiveOnlyProve(input({ SP1_PROVER: "network" }), present),
    );
    await expectGate("G04", "a tag-only SP1_GNARK_IMAGE", "GNARK_IMAGE_NOT_PINNED (NO_DIGEST)", () =>
      prepareArchiveOnlyProve(input({ SP1_GNARK_IMAGE: `${record.gnark.repository}:v6.1.0` }), present),
    );
    await expectGate("G05", "the image not in the local store", "GNARK_IMAGE_NOT_LOCAL (ABSENT)", () =>
      prepareArchiveOnlyProve(input({}), () => null),
    );
    await expectGate(
      "G06",
      "SP1_GROTH16_CIRCUIT_PATH at a missing directory",
      "CIRCUIT_ARCHIVE_NOT_INSTALLED (ROOT_ABSENT)",
      () =>
        prepareArchiveOnlyProve(
          input({ SP1_GROTH16_CIRCUIT_PATH: join(work, "absent") }, { root: join(work, "absent") }),
          present,
        ),
    );
    const pk = join(installed.circuitDir, "groth16_pk.bin");
    chmodSync(pk, 0o600);
    writeFileSync(pk, Buffer.alloc(3000));
    await expectGate("G07", "a member changed after installation", "CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)", () =>
      prepareArchiveOnlyProve(input({}), present),
    );

    const production = archiveRecordErrors(record, productionAnchor(repoRoot)).map((e) => e.reason);
    if (!production.includes("SUBJECT_MISMATCH") || !production.includes("VK_MISMATCH")) {
      fail(`the production anchor does not refuse the synthetic record (${production.join(", ")})`);
    }
    const records = archiveRecordsIn(repoRoot).length;
    if (records !== 0) fail(`${PROVING_ARCHIVES_DIR} holds ${records} records; no lane has admitted any`);
    return {
      fixtures: [SYNTHETIC_ANCHOR_REL, SAFE_ARCHIVE_REL, SAFE_RECORD_REL].map((p) => ({
        path: p,
        sha256: sha256(read(p)),
      })),
      safe,
      hostile,
      gate,
      productionAnchorRefusesFixtures: [...new Set(production)].sort(),
      productionArchiveRecords: records,
    };
  } finally {
    makeWritable(work);
    rmSync(work, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The tooling record
// ---------------------------------------------------------------------------------------------------------------

export function toolingState(input: { productionArchiveRecords: number; selfTestPassed: boolean }): ToolingState {
  if (!input.selfTestPassed) return "TOOLING_NOT_PRESENT";
  if (input.productionArchiveRecords > 0) {
    throw new Error(
      "an archive record exists: ARCHIVED_VERIFIED_UNEXERCISED is not reachable before an acquisition lane admits it",
    );
  }
  return "TOOLING_READY_NO_ARTIFACT";
}

export const RESIDUALS: readonly string[] = [
  "the root's owner (the operator's own user) or the superuser can undo the run's lock and rewrite or replace proving inputs, the host binary included, during the run; the after-run re-hash and identity comparison detect a change that persists, not one reverted in between",
  "the gnark container is started by SP1 with a read-write bind mount of the circuit directory (docker run -v <dir>:/circuit, no :ro) and runs as root inside it, so the pinned image could write there; the after-run re-hash and identity comparison detect, not prevent, that",
  "docker run has no --pull=never: if the digest-pinned image is removed between the gate's check and SP1's docker run, docker pulls it again, by digest (the same bytes, but a network fetch)",
  "a local DOCKER_HOST socket that forwards to another machine's daemon would mount that machine's directory; the gate refuses every non-local endpoint and any context but default, not a forwarded socket",
  "the host binary is not bound: one built for another circuit version cannot create its directory under the locked root (POSIX) and fails instead of downloading, but on a host where the lock does not hold (root, Windows) the gate refuses to run at all",
  "the gate is not the only way to run the host: running mldsa65-host directly still lets SP1 download the circuit, so the stronger claim (WalletWall proving never exercises the downloader) needs the exercised-proof lane, which should also run the host with network egress blocked",
  "on POSIX, an empty directory created by another process in the instant between the installer's last existence check and its rename is replaced by the rename (rename(2) semantics; Node exposes no RENAME_NOREPLACE); it held nothing, so nothing is overwritten",
  "a flooding host is killed, not its docker child or container; a run has no overall time limit (proofs take hours)",
  "the upstream observation is bound to the lockfile and its script in CI but re-read only where the pinned crates are cached (npm run sp1:measure-circuit-upstream -- --check); the gate's own rules are constants, so a forged observation can hide a future SP1 change, never widen the gate",
  "the record's acquisitions, mirrors and gnark observation are recorded assertions: the validator checks their form and agreement, not that two hosts or two mirrors exist; that is the acquisition lane's evidence to produce",
  "installation authenticates bytes when it runs; read-only permissions are a liveness hardening, never the authority",
  "the AppleDouble and provenance policies are the census of one archive, v6.1.0-groth16.tar.gz: another circuit version, or this one packed another way, needs its own two-host census and a reviewed amendment, never a widening of these constants",
  "extended-attribute PAX records other than the binary provenance one keep PA2A's inert-metadata rule: LIBARCHIVE.xattr.* and SCHILY.xattr.* records with UTF-8 values (the provenance record's base64 twin LIBARCHIVE.xattr.com.apple.provenance included) are accepted on any entry and never applied; the installer applies no extended attribute, so they change nothing installed",
  "an AppleDouble entry's header encoding (ustar or GNU, a NUL typeflag, a base-256 size, a linkname beside a regular file) is held only to the parser's general rules; its path, body, position and PAX-lessness are what the policy binds, and a record pins the exact entries",
];

export const NOT_ESTABLISHED: readonly string[] = [
  "an accepted record of v6.1.0-groth16.tar.gz: its bytes were acquired on two hosts and every entry censused (the observations above), but no record exists, and passing the amended inspector on both copies is the acquisition lane's evidence, not this one's",
  "the gnark image's digest: no committed observation, and the image is never pulled here",
  "two independent acquisitions, two WalletWall mirrors, and a record in evidence/zk/sp1-impl/proving-archives",
  "that the self-hosted path proves at all, or within the rotation delay",
  "the Groth16 trusted setup behind the v6.1.0 key: groth16_vk.bin's hash is an integrity and compatibility check, never evidence that the setup is sound",
];

/** The tooling record the committed evidence and the self-test derive. */
export async function toolingRecordFromRepo(repoRoot = "."): Promise<Record<string, unknown>> {
  const at = (rel: string) => resolve(repoRoot, rel);
  const anchor = productionAnchor(repoRoot);
  const obsBytes = readFileSync(at(UPSTREAM_OBSERVATION_REL));
  const obs = JSON.parse(obsBytes.toString("utf8")) as UpstreamObservation;
  const obsErrors = upstreamObservationErrors(obs, repoRoot);
  if (obsErrors.length > 0) throw new Error(obsErrors.join("; "));
  const coverage = gateCoverageErrors(obs.facts, obs.environment, anchor);
  if (coverage.length > 0) throw new Error(coverage.join("; "));
  const censusErrors = censusObservationErrors(repoRoot);
  if (censusErrors.length > 0) throw new Error(censusErrors.join("; "));
  const censusBytes = readFileSync(at(CENSUS_OBSERVATIONS_REL[0]), "utf8");
  const census = JSON.parse(censusBytes) as Census;
  const paBytes = readFileSync(at(PROVING_AVAILABILITY_REL));
  const pa = JSON.parse(paBytes.toString("utf8"));
  if (pa.status !== "OWNER_DOWNLOAD_REQUIRED") {
    throw new Error(
      `proving availability is ${String(pa.status)}: this lane leaves it OWNER_DOWNLOAD_REQUIRED, and a change needs its own lane`,
    );
  }
  const selfTest = await runSelfTest(repoRoot);
  const state = toolingState({ productionArchiveRecords: selfTest.productionArchiveRecords, selfTestPassed: true });
  const f = obs.facts;
  return {
    schema: TOOLING_SCHEMA,
    lane: "SP1-PA2A",
    amendment:
      "AppleDouble metadata and binary provenance: closed policies derived from the two-host census of the upstream archive; ignored, never installed",
    state,
    states: STATES,
    provingAvailability: {
      path: PROVING_AVAILABILITY_REL,
      sha256: sha256(paBytes),
      status: pa.status,
      unchangedByThisTooling: true,
    },
    anchor,
    archiveRecord: {
      schema: ARCHIVE_RECORD_SCHEMA,
      jsonSchema: { path: ARCHIVE_JSON_SCHEMA_REL, sha256: sha256(readFileSync(at(ARCHIVE_JSON_SCHEMA_REL))) },
      authoritativeDir: PROVING_ARCHIVES_DIR,
      productionRecords: selfTest.productionArchiveRecords,
      requiredMembers: REQUIRED_MEMBERS,
      minAcquisitions: MIN_ACQUISITIONS,
      minMirrors: MIN_MIRRORS,
      sourceUrlAndTag: PROVENANCE_ONLY,
      ignoredMetadata: {
        appleDouble: {
          disposition: IGNORED_APPLEDOUBLE_METADATA,
          rule: `a path with any "._" component is never a member; it is ignored only as one of these paths ("._." describing the root directory, "._<name>" the regular file <name>), a regular file with no PAX header, one of these bodies, immediately followed by the entry it describes; never extracted, never installed; recorded in the record's metadata`,
          paths: APPLEDOUBLE_PATHS,
          bodies: APPLEDOUBLE_BODIES,
        },
        provenance: {
          disposition: IGNORED_PROVENANCE_METADATA,
          key: PROVENANCE_PAX_KEY,
          value: {
            hex: PROVENANCE_VALUE.toString("hex"),
            bytes: PROVENANCE_VALUE.length,
            sha256: sha256(PROVENANCE_VALUE),
          },
          entries: PROVENANCE_ENTRIES.map((e) => ({ path: e.path || ".", kind: e.kind })),
          rule: "the key's raw value must be exactly this value (never decoded, interpreted or applied), on these entries only (by path and kind), at most once each, and on all of them once on any; every other PAX key and value stays strict UTF-8",
        },
        derivedFrom: {
          observations: CENSUS_OBSERVATIONS_REL.map((path) => ({ path, sha256: sha256(serializeCensus(census)) })),
          archive: census.archive,
          tarEntries: census.tar.entries,
          appleDoubleEntries: census.appleDouble.map((r) => r.path),
        },
      },
    },
    upstream: {
      observation: { path: UPSTREAM_OBSERVATION_REL, sha256: sha256(obsBytes), measuredAtUtc: obs.measuredAtUtc },
      crates: obs.crates.length,
      censusScope:
        "literal environment reads in the src/ of every sp1-* and slop-* crate the host lockfile pins; other crates' reads (dirs, reqwest, tracing) are outside it and reach the host only through the pass-through list",
      reviewedNonLiteralReads: obs.nonLiteralEnvironmentReads,
      readings: [
        `circuit ${f.circuitVersion}: $${f.groth16Dir.env}/${f.circuitVersion} when set (the value used verbatim: empty or relative resolves against SP1's working directory), else ${f.groth16Dir.fallback}/${f.circuitVersion}`,
        `the circuit is downloaded from ${f.install.url} only when that directory is absent; ${f.install.verifiesDigest ? "a digest is checked" : "no digest is checked"}; extraction is tar ${f.install.extractFlags}`,
        `$${f.circuitMode.env}=${f.circuitMode.devValue} selects development artifacts from another source`,
        `$${f.prover.env} selects the prover (${f.prover.modes.join(", ")}), ${f.prover.default} when unset`,
        `the gnark prover runs as docker ${f.gnark.dockerRunArgs.join(" ")} -v ${f.gnark.mountSpec} <image>, the image $${f.gnark.env} or ${f.gnark.defaultImage} (a mutable tag)${f.gnark.pullFlag ? "" : "; no --pull flag, so an absent image is pulled"}`,
      ],
      environment: Object.entries(obs.environment)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([name, readBy]) => ({ name, readBy, gate: envClass(name) })),
    },
    gate: {
      order: [
        "the record is a production record, exactly as committed, accepted for the designation read from the committed evidence of the checkout the command lives in",
        "the circuit root is absolute, normalized, not a UNC share and mount-safe",
        "the caller's environment: frozen values identical or absent, refused variables absent, docker only on a local socket",
        "the host executable and the inputs are regular files",
        "the gnark image is in the local docker store by its digest (offline inspection, never a pull)",
        "<root> holds only <circuit version>, which is re-hashed and must be exactly the record's members, each file with one link",
        "POSIX, unprivileged user: <root>'s path is changeable only by its owner, and <root> is locked read-only for the run",
        "under the lock: the installation is re-hashed again and its identity (inodes, links, times) taken; then the host is spawned (no shell, the constructed environment only)",
        "after it exits, whether or not it succeeded, and before the lock is released: the same bytes at the same identity; then exit 0, and a proof naming the designated PROGRAM_VKEY with its verifying key's selector",
      ],
      frozen: {
        SP1_PROVER: LOCAL_PROVER,
        SP1_GROTH16_CIRCUIT_PATH: "<the verified circuit root>",
        SP1_GNARK_IMAGE: "<repository>@sha256:<the record's digest>",
        DOCKER_CONTEXT: "default",
      },
      refused: Object.keys(REFUSED_ENV).sort(),
      refusedPrefix: REFUSED_ENV_PREFIX,
      passThrough: PASS_THROUGH_ENV,
      refusals: REFUSAL_CODES,
    },
    selfTest,
    residuals: RESIDUALS,
    notEstablished: NOT_ESTABLISHED,
    next: "SP1-PA2B resumes only after this amendment merges and both independently acquired copies pass the merged inspector unchanged: then the gnark image by digest, WalletWall mirroring and the record; still not a proof lane",
  };
}

export const serializeTooling = (record: Record<string, unknown>) => `${JSON.stringify(record, null, 2)}\n`;

/** Every reason the committed tooling record is not what the evidence and the self-test derive. */
export async function toolingErrors(repoRoot = "."): Promise<string[]> {
  let expected: string;
  try {
    expected = serializeTooling(await toolingRecordFromRepo(repoRoot));
  } catch (error) {
    return [(error as Error).message];
  }
  const path = resolve(repoRoot, TOOLING_REL);
  if (!existsSync(path) || readFileSync(path, "utf8") !== expected) {
    return [`${TOOLING_REL} is not what the evidence and the self-test derive: regenerate it`];
  }
  return [];
}
