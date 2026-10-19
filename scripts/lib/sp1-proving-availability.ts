/**
 * Proving availability (SP1-TD1 finding TD1-N9; the SP1 implementation lane,
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * The pqVerifier rotation's 2-day delay protects a PqOnly user only while they can prove, and a Groth16 proof for
 * circuit v6.1.0 needs Succinct's v6.1.0 circuit artifacts (or Succinct's prover network). Upstream hosting them today
 * is not availability. This module records what can be established without downloading them, and derives the status
 * from measurements:
 *
 *   from the crates zkvm/host/Cargo.lock pins (each .crate's sha256 must be the lockfile's checksum, and members are
 *     read from those bytes, never from an unpacked source tree): the circuit version, the expected groth16_vk.bin
 *     (sp1-verifier's embedded key, whose sha256 is the designated VERIFIER_HASH), where the pinned prover fetches the
 *     artifacts, how it installs them and which files Groth16 proving reads;
 *   on the proving host: whether the artifacts and the gnark image are present, and which gnark backend the host's
 *     dependency graph selects;
 *   in the repository: WalletWall archive records (none; any is refused until a lane defines and validates them).
 *
 *   OWNER_DOWNLOAD_REQUIRED — no archive and no local copy: obtaining the artifacts needs a download this lane is not
 *     authorized to make.
 *   LOCAL_COPY_NOT_ARCHIVED — a local copy exists, but WalletWall has neither archived nor verified it.
 *
 * Neither is availability, which needs a verified archive and an exercised self-hosted proving path (a later,
 * owner-authorized lane). The artifacts' integrity is never soundness: the designated verifier refuses a proof made
 * under any other key or circuit, so what they decide is whether a user can prove at all.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { gunzipSync } from "node:zlib";

import {
  anchorFromDesignation,
  archiveEvidenceState,
  productionArchiveEvidence,
  type ArchiveEvidence,
} from "./sp1-circuit-acquisition";
import { PROVING_ARCHIVES_DIR, archiveRecordsIn } from "./sp1-circuit-archive";
import { latestDesignation, readDesignations, type ProgramDesignation } from "./sp1-designation";
import {
  PROOF_EXERCISES_DIR,
  ROTATION_DELAY_SECONDS,
  exerciseEvidenceState,
  exerciseRecordsIn,
  productionExerciseEvidence,
  type ExerciseEvidence,
  type ProofExerciseRecord,
} from "./sp1-proof-exercise";

/** The authoritative record directory and its listing live with the record (scripts/lib/sp1-circuit-archive.ts). */
export { PROVING_ARCHIVES_DIR, archiveRecordsIn };

export const PROVING_AVAILABILITY_REL = "evidence/zk/sp1-impl/proving-availability.json";
export const PROVING_AVAILABILITY_SCHEMA = "walletwall.sp1-proving-availability.v1";
export const PROVING_ARTIFACTS_OBSERVATION_REL =
  "evidence/zk/sp1-impl/observations/proving-artifacts-developer-workstation.raw.json";
export const PROVING_ARTIFACTS_SCHEMA = "walletwall.sp1-proving-artifacts.v1";
export const HOST_LOCK_REL = "zkvm/host/Cargo.lock";
export const MEASURE_SCRIPT_REL = "scripts/measure-sp1-proving-artifacts.ts";
export const GNARK_TREE_COMMAND = "cargo tree --offline --locked -e features -i sp1-recursion-gnark-ffi";
const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
const VK_MEMBER = "vk-artifacts/groth16_vk.bin";

/** The members read from each crate the host lockfile pins. */
export const MEASURED_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  "sp1-prover": ["SP1_CIRCUIT_VERSION", "src/build.rs"],
  "sp1-recursion-gnark-ffi": [
    "assets/SP1_CIRCUIT_VERSION",
    "src/ffi/docker.rs",
    "src/groth16_bn254.rs",
    "go/sp1/sp1.go",
    "go/sp1/prove_groth16.go",
  ],
  "sp1-verifier": [VK_MEMBER],
};

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

/** The regular files of a gzip'd tar (a .crate), by path. A corrupt, truncated or ambiguous archive is refused. */
export function readTarMembers(gz: Uint8Array): Map<string, Buffer> {
  const tar = gunzipSync(gz);
  const members = new Map<string, Buffer>();
  let pendingName: string | null = null;
  for (let at = 0; at + 512 <= tar.length;) {
    const h = tar.subarray(at, at + 512);
    if (h.every((b) => b === 0)) return members;
    const text = (from: number, len: number) =>
      h
        .subarray(from, from + len)
        .toString("latin1")
        .split("\0")[0];
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
    if (parseInt(text(148, 8).trim(), 8) !== sum) throw new Error(`tar header at byte ${at}: checksum mismatch`);
    if (h[124] & 0x80) throw new Error(`tar header at byte ${at}: a base-256 size is not read`);
    const size = parseInt(text(124, 12).trim() || "0", 8);
    const start = at + 512;
    if (start + size > tar.length) throw new Error(`tar member at byte ${at}: truncated`);
    const data = tar.subarray(start, start + size);
    at = start + Math.ceil(size / 512) * 512;
    const type = String.fromCharCode(h[156]);
    if (type === "L") {
      pendingName = data.toString("utf8").split("\0")[0];
      continue;
    }
    if (type === "x") {
      pendingName = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(data.toString("utf8"))?.[1] ?? pendingName;
      continue;
    }
    // POSIX ustar splits long names into prefix/name; the GNU header uses those bytes for other fields.
    const posix = text(257, 6) === "ustar" && text(263, 2) === "00";
    const prefix = posix ? text(345, 155) : "";
    const name = pendingName ?? (prefix ? `${prefix}/${text(0, 100)}` : text(0, 100));
    pendingName = null;
    if (type !== "0" && type !== "\0") continue;
    if (members.has(name)) throw new Error(`tar member ${name} appears twice`);
    members.set(name, Buffer.from(data));
  }
  throw new Error("the tar archive ends without its end-of-archive block");
}

export interface LockedCrate {
  name: string;
  version: string;
  checksum: string;
}

/** The registry crates a Cargo.lock pins, by name; null for a name locked at more than one version. */
export function lockedCrates(lockText: string): Map<string, LockedCrate | null> {
  const out = new Map<string, LockedCrate | null>();
  for (const block of lockText.split(/^\[\[package\]\]\r?$/m).slice(1)) {
    const field = (k: string) => new RegExp(`^${k} = "([^"]*)"\\r?$`, "m").exec(block)?.[1];
    const [name, version, checksum] = [field("name"), field("version"), field("checksum")];
    if (!name || !version || !checksum) continue; // path and git dependencies carry no registry checksum
    out.set(name, out.has(name) ? null : { name, version, checksum });
  }
  return out;
}

/** The cached .crate of `c`; every cached copy must be the bytes the lockfile pins. */
function cachedCrate(cargoHome: string, c: LockedCrate): { file: string; bytes: Buffer } {
  const cache = join(cargoHome, "registry", "cache");
  const found = existsSync(cache)
    ? readdirSync(cache)
        .sort()
        .map((index) => join(cache, index, `${c.name}-${c.version}.crate`))
        .filter((f) => existsSync(f))
    : [];
  if (found.length === 0) throw new Error(`${c.name} ${c.version} is not in the cargo cache at ${cache}`);
  for (const file of found) {
    const digest = sha256(readFileSync(file));
    if (digest !== c.checksum) {
      throw new Error(`${file} is not the crate ${HOST_LOCK_REL} pins (sha256 ${digest}, locked ${c.checksum})`);
    }
  }
  return { file: found[0], bytes: readFileSync(found[0]) };
}

/** What the lane read in the pinned prover's source, re-read from the measured bytes on every measurement. */
export interface SourceReading {
  circuitVersion: string;
  artifactUrl: string;
  groth16DirEnv: string;
  groth16DefaultDir: string;
  circuitModeEnv: string;
  extractFlags: string;
  reusesExistingDir: boolean;
  downloadVerifiesHash: boolean;
  gnarkImageEnv: string;
  gnarkImage: string;
  groth16ProveReads: string[];
  groth16VkFile: string;
  groth16Vk: { sha256: string; bytes: number };
}

const noLonger = (what: string) =>
  new Error(`the pinned prover's source no longer reads as this lane read it: ${what}`);
function matchOf(text: string, re: RegExp, what: string): RegExpExecArray {
  const m = re.exec(text);
  if (!m) throw noLonger(what);
  return m;
}
/** A top-level Rust or Go function, from its signature to the first closing brace at column 0. */
function fnBody(text: string, signature: string): string {
  const start = text.indexOf(signature);
  const end = start < 0 ? -1 : text.indexOf("\n}", start);
  if (end < 0) throw noLonger(signature);
  return text.slice(start, end);
}

function readSource(read: (crate: string, member: string) => Buffer): SourceReading {
  const str = (crate: string, member: string) => read(crate, member).toString("utf8");
  const proverVersion = str("sp1-prover", "SP1_CIRCUIT_VERSION");
  const gnarkVersion = str("sp1-recursion-gnark-ffi", "assets/SP1_CIRCUIT_VERSION");
  if (!/^v\d+\.\d+\.\d+$/.test(proverVersion) || proverVersion !== gnarkVersion) {
    throw new Error(
      `the circuit version is not one: sp1-prover names ${JSON.stringify(proverVersion)}, sp1-recursion-gnark-ffi ${JSON.stringify(gnarkVersion)}`,
    );
  }
  const v = proverVersion;
  const build = str("sp1-prover", "src/build.rs");
  const base = matchOf(build, /pub const CIRCUIT_ARTIFACTS_URL_BASE: &str = "(https:\/\/[^"]+)";/, "the URL base")[1];
  const install = fnBody(build, "pub async fn install_circuit_artifacts(");
  matchOf(
    install,
    /format!\(\s*"\{CIRCUIT_ARTIFACTS_URL_BASE\}\/\{SP1_CIRCUIT_VERSION\}-\{artifacts_type\}\.tar\.gz"\s*\)/,
    "the download URL",
  );
  const download = fnBody(build, "pub async fn download_file(");
  const dir = fnBody(build, "pub fn groth16_circuit_artifacts_dir()");
  const groth16DirEnv = matchOf(dir, /std::env::var\("([A-Z0-9_]+)"\)/, "the artifacts directory variable")[1];
  const sub = matchOf(dir, /home_dir\.join\("\.sp1"\)\.join\("([^"]+)"\)/, "the default artifacts directory")[1];
  matchOf(dir, /Ok\(base_path\.join\(SP1_CIRCUIT_VERSION\)\)/, "the versioned artifacts directory");
  const mode = fnBody(build, "fn use_development_mode()");
  const circuitModeEnv = matchOf(
    mode,
    /std::env::var\("([A-Z0-9_]+)"\)\.unwrap_or\("release"\.to_string\(\)\) == "dev"/,
    "the development-mode variable",
  )[1];
  const docker = str("sp1-recursion-gnark-ffi", "src/ffi/docker.rs");
  const image = matchOf(
    docker,
    /std::env::var\("([A-Z0-9_]+)"\)\s*\.unwrap_or_else\(\|_\| format!\("([^"]+)"\)\)/,
    "the gnark image",
  );
  const vkFile = matchOf(
    str("sp1-recursion-gnark-ffi", "src/groth16_bn254.rs"),
    /fn get_vkey_hash\(build_dir: &Path\) -> \[u8; 32\] \{\s*let vkey_path = build_dir\.join\("([^"]+)"\);\s*let vk_bin_bytes = std::fs::read\(vkey_path\)\.unwrap\(\);\s*Sha256::digest\(vk_bin_bytes\)\.into\(\)/,
    "the vkey hash",
  )[1];
  const goNames = new Map(
    [...str("sp1-recursion-gnark-ffi", "go/sp1/sp1.go").matchAll(/^var (\w+) string = "([^"]+)"/gm)].map((m) => [
      m[1],
      m[2],
    ]),
  );
  const prove = fnBody(str("sp1-recursion-gnark-ffi", "go/sp1/prove_groth16.go"), "func ProveGroth16(");
  const reads = [...prove.matchAll(/dataDir\s*\+\s*"\/"\s*\+\s*(\w+)/g)].map((m) => {
    const file = goNames.get(m[1]);
    if (!file) throw noLonger(`the Groth16 prover's file ${m[1]}`);
    return file;
  });
  if (reads.length === 0) throw noLonger("the files Groth16 proving reads");
  const vk = read("sp1-verifier", VK_MEMBER);
  return {
    circuitVersion: v,
    artifactUrl: `${base}/${v}-groth16.tar.gz`,
    groth16DirEnv,
    groth16DefaultDir: `~/.sp1/${sub}/${v}`,
    circuitModeEnv,
    extractFlags: matchOf(install, /Command::new\("tar"\)\s*\.args\(\["(-[A-Za-z]+)"/, "the extraction")[1],
    reusesExistingDir: /if build_dir\.exists\(\)/.test(fnBody(build, "pub async fn try_install_circuit_artifacts(")),
    downloadVerifiesHash: /sha2|sha256|checksum|digest|verify/i.test(install + download),
    gnarkImageEnv: image[1],
    gnarkImage: image[2].replace("{SP1_CIRCUIT_VERSION}", v),
    groth16ProveReads: [...new Set(reads)].sort(),
    groth16VkFile: vkFile,
    groth16Vk: { sha256: sha256(vk), bytes: vk.length },
  };
}

/** The sp1-recursion-gnark-ffi features enabled in the host's graph, from `cargo tree -e features -i` output. */
export function gnarkFeaturesOf(treeOutput: string, version: string): string[] {
  const lines = treeOutput.split(/\r?\n/);
  if (lines[0]?.trim() !== `sp1-recursion-gnark-ffi v${version}`) {
    throw new Error(`not the inverted feature tree of sp1-recursion-gnark-ffi ${version} (${GNARK_TREE_COMMAND})`);
  }
  const features = lines.flatMap((l) => /sp1-recursion-gnark-ffi feature "([^"]+)"/.exec(l)?.[1] ?? []);
  return [...new Set(features)].sort();
}
const backendOf = (features: readonly string[]) => (features.includes("native") ? "native" : "docker");

export interface MeasuredCrate {
  name: string;
  version: string;
  lockChecksum: string;
  crateSha256: string;
  cacheFile: string;
  members: Record<string, { sha256: string; bytes: number }>;
}

export interface ProvingArtifactsObservation {
  schema: string;
  measuredAtUtc: string;
  host: string;
  tool: { script: string; scriptSha256: string };
  lockfile: { path: string; sha256: string };
  crates: MeasuredCrate[];
  source: SourceReading;
  gnark: {
    command: string;
    output: string;
    outputSha256: string;
    features: string[];
    backend: "docker" | "native";
    localImages: string[];
  };
  local: {
    circuitsRoot: string;
    circuitsRootPresent: boolean;
    circuitsRootEntries: string[];
    groth16Dir: string;
    groth16DirPresent: boolean;
  };
}

export interface MeasureInput {
  repoRoot: string;
  /** The proving host's CARGO_HOME. */
  cargoHome: string;
  /** The proving host's home directory. */
  home: string;
  hostId: string;
  cargoTree: { command: string; output: string };
  /** The proving host's local images of an image repository; must throw when it cannot tell. */
  localImages: (repository: string) => string[];
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
}

/** Measures, read-only, what can be established about proving availability without the artifacts. */
export function measureProvingArtifacts(input: MeasureInput): ProvingArtifactsObservation {
  const lockBytes = readFileSync(resolve(input.repoRoot, HOST_LOCK_REL));
  const locked = lockedCrates(lockBytes.toString("utf8"));
  const read = new Map<string, Buffer>();
  const crates: MeasuredCrate[] = [];
  for (const [name, wanted] of Object.entries(MEASURED_MEMBERS)) {
    const lock = locked.get(name);
    if (!lock) throw new Error(`${HOST_LOCK_REL} pins ${lock === null ? "more than one version of" : "no"} ${name}`);
    const { file, bytes } = cachedCrate(input.cargoHome, lock);
    const tar = readTarMembers(bytes);
    const members: MeasuredCrate["members"] = {};
    for (const member of wanted) {
      const b = tar.get(`${name}-${lock.version}/${member}`);
      if (!b) throw new Error(`${name} ${lock.version} has no ${member}`);
      members[member] = { sha256: sha256(b), bytes: b.length };
      read.set(`${name}/${member}`, b);
    }
    crates.push({
      name,
      version: lock.version,
      lockChecksum: lock.checksum,
      crateSha256: sha256(bytes),
      cacheFile: relative(input.cargoHome, file).split(sep).join("/"),
      members,
    });
  }
  const source = readSource((crate, member) => read.get(`${crate}/${member}`) as Buffer);
  const features = gnarkFeaturesOf(
    input.cargoTree.output,
    (locked.get("sp1-recursion-gnark-ffi") as LockedCrate).version,
  );
  const root = join(input.home, ".sp1", "circuits");
  const rootPresent = existsSync(root);
  return {
    schema: PROVING_ARTIFACTS_SCHEMA,
    measuredAtUtc: input.measuredAtUtc,
    host: input.hostId,
    tool: input.tool,
    lockfile: { path: HOST_LOCK_REL, sha256: sha256(lockBytes) },
    crates,
    source,
    gnark: {
      command: input.cargoTree.command,
      output: input.cargoTree.output,
      outputSha256: sha256(input.cargoTree.output),
      features,
      backend: backendOf(features),
      localImages: input.localImages(source.gnarkImage.replace(/:[^:/]+$/, "")),
    },
    local: {
      circuitsRoot: "~/.sp1/circuits",
      circuitsRootPresent: rootPresent,
      circuitsRootEntries: rootPresent ? readdirSync(root).sort() : [],
      groth16Dir: source.groth16DefaultDir,
      groth16DirPresent: existsSync(join(root, "groth16", source.circuitVersion)),
    },
  };
}

/** What a committed observation must satisfy; what it measured on the host cannot be re-read here, only bound. */
export function provingArtifactsObservationErrors(
  obs: ProvingArtifactsObservation,
  designations: readonly ProgramDesignation[],
  repoRoot = ".",
): string[] {
  const errors: string[] = [];
  if (obs?.schema !== PROVING_ARTIFACTS_SCHEMA)
    errors.push(`the observation's schema must be ${PROVING_ARTIFACTS_SCHEMA}`);
  const script = resolve(repoRoot, MEASURE_SCRIPT_REL);
  if (
    obs?.tool?.script !== MEASURE_SCRIPT_REL ||
    !existsSync(script) ||
    obs.tool.scriptSha256 !== sha256(readFileSync(script))
  ) {
    errors.push(`the observation was not made by ${MEASURE_SCRIPT_REL} as committed: re-measure`);
  }
  const lockBytes = readFileSync(resolve(repoRoot, HOST_LOCK_REL));
  if (obs?.lockfile?.path !== HOST_LOCK_REL || obs.lockfile.sha256 !== sha256(lockBytes)) {
    errors.push(`the observation measured another ${HOST_LOCK_REL}: re-measure`);
  }
  const locked = lockedCrates(lockBytes.toString("utf8"));
  const names = Object.keys(MEASURED_MEMBERS);
  const crates = Array.isArray(obs?.crates) ? obs.crates : [];
  if (crates.map((c) => c?.name).join() !== names.join())
    errors.push(`the observation must measure ${names.join(", ")}`);
  for (const c of crates) {
    const lock = locked.get(c?.name);
    if (!lock || c.version !== lock.version || c.lockChecksum !== lock.checksum || c.crateSha256 !== lock.checksum) {
      errors.push(`${c?.name}: the measured crate is not the one the lockfile pins`);
    }
    for (const member of MEASURED_MEMBERS[c?.name] ?? []) {
      const m = c?.members?.[member];
      if (!/^[0-9a-f]{64}$/.test(String(m?.sha256)) || !(Number(m?.bytes) > 0)) {
        errors.push(`${c?.name}: ${member} is not measured`);
      }
    }
  }
  const s = obs?.source;
  const vkMember = crates.find((c) => c?.name === "sp1-verifier")?.members?.[VK_MEMBER];
  if (!vkMember || s?.groth16Vk?.sha256 !== vkMember.sha256 || s?.groth16Vk?.bytes !== vkMember.bytes) {
    errors.push(`the expected groth16_vk.bin is not sp1-verifier's measured ${VK_MEMBER}`);
  }
  for (const d of designations) {
    if (`0x${s?.groth16Vk?.sha256}` !== d.verifier.verifierHash) {
      errors.push(
        `groth16_vk.bin's sha256 0x${s?.groth16Vk?.sha256} is not ${d.id}'s VERIFIER_HASH ${d.verifier.verifierHash}: the artifacts would serve another verifier`,
      );
    }
    if (s?.circuitVersion !== d.verifier.version) {
      errors.push(
        `the pinned prover's circuit version ${s?.circuitVersion} is not ${d.id}'s verifier ${d.verifier.version}`,
      );
    }
  }
  const shape =
    typeof s?.artifactUrl === "string" &&
    s.artifactUrl.startsWith("https://") &&
    s.artifactUrl.endsWith(`/${s.circuitVersion}-groth16.tar.gz`) &&
    s.groth16DefaultDir === `~/.sp1/circuits/groth16/${s.circuitVersion}` &&
    [s.groth16DirEnv, s.circuitModeEnv, s.gnarkImageEnv, s.gnarkImage, s.extractFlags, s.groth16VkFile].every(
      (x) => typeof x === "string" && x.length > 0,
    ) &&
    typeof s.reusesExistingDir === "boolean" &&
    typeof s.downloadVerifiesHash === "boolean" &&
    Array.isArray(s.groth16ProveReads) &&
    s.groth16ProveReads.length > 0;
  if (!shape) errors.push("the source reading is incomplete");
  const g = obs?.gnark;
  let features: string[] | null = null;
  try {
    features = gnarkFeaturesOf(
      String(g?.output),
      String(crates.find((c) => c?.name === "sp1-recursion-gnark-ffi")?.version),
    );
  } catch {
    features = null;
  }
  if (
    features === null ||
    g?.command !== GNARK_TREE_COMMAND ||
    g.outputSha256 !== sha256(String(g.output)) ||
    JSON.stringify(g.features) !== JSON.stringify(features) ||
    g.backend !== backendOf(features) ||
    !Array.isArray(g.localImages)
  ) {
    errors.push("the gnark feature tree does not re-read as recorded");
  }
  const l = obs?.local;
  if (
    typeof l?.circuitsRootPresent !== "boolean" ||
    typeof l.groth16DirPresent !== "boolean" ||
    !Array.isArray(l.circuitsRootEntries) ||
    (l.groth16DirPresent && !l.circuitsRootPresent) ||
    (!l.circuitsRootPresent && l.circuitsRootEntries.length > 0) ||
    l.circuitsRoot !== "~/.sp1/circuits" ||
    l.groth16Dir !== s?.groth16DefaultDir
  ) {
    errors.push("the local install is not measured");
  }
  return errors;
}

/**
 * The vocabulary is the circuit tooling's four-state model (scripts/lib/sp1-circuit-tooling.ts STATES), as far as
 * proving availability can go without a proof: OWNER_DOWNLOAD_REQUIRED and LOCAL_COPY_NOT_ARCHIVED name the states
 * before an archive exists (no WalletWall archive record; nothing, or an unverified local copy); SP1-PA2B's
 * ARCHIVED_VERIFIED_UNEXERCISED names the state after one is admitted (an accepted record: two agreeing hosts, the
 * inspected members, two WalletWall mirrors, the gnark image by digest), with the self-hosted proving path still
 * unexercised. None is availability: SELF_HOSTED_PATH_EXERCISED is a later, owner-authorized lane's, and even that is
 * liveness, never soundness.
 */
export type ProvingAvailability =
  | "OWNER_DOWNLOAD_REQUIRED"
  | "LOCAL_COPY_NOT_ARCHIVED"
  | "ARCHIVED_VERIFIED_UNEXERCISED"
  | "SELF_HOSTED_PATH_EXERCISED";

/**
 * The status, from the measured host, the archive evidence and the proof-exercise evidence (SP1-PA3A). A record
 * counts only as its evidence accepted it (the committed observations derive it, it is accepted for the designation,
 * it is committed); any file under PROVING_ARCHIVES_DIR or PROOF_EXERCISES_DIR that is not that accepted record stops
 * the derivation instead of being read as absent, and a proof-exercise record without an accepted archive derives
 * nothing. SELF_HOSTED_PATH_EXERCISED is liveness on one host at one time, never soundness, never production readiness.
 */
export function provingAvailabilityStatus(
  obs: ProvingArtifactsObservation,
  archiveRecords: readonly string[],
  archive: ArchiveEvidence | null = null,
  exerciseRecords: readonly string[] = [],
  exercise: ExerciseEvidence | null = null,
): ProvingAvailability {
  if (archive !== null && JSON.stringify(archive.records) !== JSON.stringify(archiveRecords)) {
    throw new Error(
      `the archive evidence judged ${archive.records.join(", ") || "no record"}, not ${archiveRecords.join(", ") || "no record"}`,
    );
  }
  if (exercise !== null && JSON.stringify(exercise.records) !== JSON.stringify(exerciseRecords)) {
    throw new Error(
      `the proof-exercise evidence judged ${exercise.records.join(", ") || "no record"}, not ${exerciseRecords.join(", ") || "no record"}`,
    );
  }
  if (archiveRecords.length > 0) {
    if (archive === null || archiveEvidenceState(archive) !== "ACCEPTED" || archive.record === null) {
      throw new Error(
        `${archiveRecords.join(", ")}: not an accepted production archive record (${archive === null ? "no archive evidence was judged" : archive.errors.join("; ")}); a record counts only as the committed acquisition observations derive it`,
      );
    }
    if (exerciseRecords.length > 0) {
      if (exercise === null || exerciseEvidenceState(exercise) !== "ACCEPTED" || exercise.record === null) {
        throw new Error(
          `${exerciseRecords.join(", ")}: not an accepted proof-exercise record (${exercise === null ? "no proof-exercise evidence was judged" : exercise.errors.join("; ")}); a record counts only as the committed run and verification observations derive it`,
        );
      }
      return "SELF_HOSTED_PATH_EXERCISED";
    }
    if (exercise !== null && exerciseEvidenceState(exercise) !== "NO_RECORD") {
      throw new Error(`the proof-exercise evidence is refused without a record: ${exercise.errors.join("; ")}`);
    }
    return "ARCHIVED_VERIFIED_UNEXERCISED";
  }
  if (exerciseRecords.length > 0) {
    throw new Error(
      `${exerciseRecords.join(", ")}: a proof-exercise record without an accepted archive record derives no status`,
    );
  }
  if (archive !== null && archiveEvidenceState(archive) !== "NO_RECORD") {
    throw new Error(`the archive evidence is refused without a record: ${archive.errors.join("; ")}`);
  }
  if (exercise !== null && exerciseEvidenceState(exercise) !== "NO_RECORD") {
    throw new Error(`the proof-exercise evidence is refused without a record: ${exercise.errors.join("; ")}`);
  }
  return obs.local.groth16DirPresent ? "LOCAL_COPY_NOT_ARCHIVED" : "OWNER_DOWNLOAD_REQUIRED";
}

interface Td1Finding {
  id: string;
  title: string;
  disposition: string;
  plan: string;
}

export interface ProvingAvailabilityRecord {
  schema: string;
  finding: Td1Finding & { receipt: { path: string; sha256: string }; dependency: string };
  status: ProvingAvailability;
  basis: string[];
  designations: string[];
  expectedArtifacts: {
    circuitVersion: string;
    upstreamUrl: string;
    tarball: { file: string; sha256: string | null; size: string; status: string };
    members: {
      file: string;
      sha256: string | null;
      bytes?: number;
      knownFrom?: string;
      status?: string;
      role: string;
    }[];
    gnark: {
      backend: string;
      features: string[];
      image: string;
      imageOverrideEnv: string;
      imageDigest: string | null;
      status: string;
    };
  };
  pinnedProver: string[];
  local: ProvingArtifactsObservation["local"] & { host: string; gnarkImages: string[] };
  archives: {
    dir: string;
    records: number;
    /** The accepted record and what it establishes, once SP1-PA2B admits one; absent before. */
    accepted?: {
      record: string;
      derivedFrom: string[];
      hosts: string[];
      mirrors: string[];
      members: number;
      ignoredMetadata: number;
      gnarkDigest: string;
    };
  };
  exercises: {
    dir: string;
    records: number;
    /** The accepted proof-exercise record and what it establishes, once SP1-PA3B admits one; absent before. */
    accepted?: {
      record: string;
      derivedFrom: string[];
      host: string;
      performedAtUtc: string;
      verifiedAtUtc: string;
      wallClockSeconds: number;
      hostSeconds: number;
      rotationDelaySeconds: number;
      withinRotationDelay: boolean;
      peakMemory: { hostProcessBytes: number; gnarkContainersBytes: number };
      verifier: { runtimeCodeKeccak: string; checks: number };
      egress: string;
    };
  };
  /** `exercised` and `record` follow the accepted proof-exercise record (SP1-PA3A); they are never set by hand. */
  selfHostedPath: { exercised: boolean; requirements: string[]; record?: string };
  ownerAction: string[];
  notEstablished: string[];
  observation: { path: string; sha256: string };
}

export function deriveProvingAvailability(input: {
  observation: ProvingArtifactsObservation;
  observationSha256: string;
  designations: readonly ProgramDesignation[];
  td1Receipt: { sha256: string; doc: { findings: Td1Finding[]; offChainLivenessDependencies: string[] } };
  archiveRecords: readonly string[];
  /** The judged archive evidence (scripts/lib/sp1-circuit-acquisition.ts); null only for a repository that holds none. */
  archive: ArchiveEvidence | null;
  exerciseRecords: readonly string[];
  /** The judged proof-exercise evidence (scripts/lib/sp1-proof-exercise.ts); null while no archive is accepted. */
  exercise: ExerciseEvidence | null;
}): ProvingAvailabilityRecord {
  const obs = input.observation;
  const s = obs.source;
  const v = s.circuitVersion;
  const finding = input.td1Receipt.doc.findings.find((f) => f.id === "TD1-N9");
  const dependency = input.td1Receipt.doc.offChainLivenessDependencies.find((d) => /circuit artifacts/.test(d));
  const size = dependency === undefined ? undefined : /about ([\d.]+ [KMGT]B)/.exec(dependency)?.[1];
  if (!finding || !dependency || !size) throw new Error("SP1-TD1's receipt no longer states TD1-N9 and its dependency");
  const status = provingAvailabilityStatus(
    obs,
    input.archiveRecords,
    input.archive,
    input.exerciseRecords,
    input.exercise,
  );
  const inArchivedState = status === "ARCHIVED_VERIFIED_UNEXERCISED" || status === "SELF_HOSTED_PATH_EXERCISED";
  const record = inArchivedState ? (input.archive as ArchiveEvidence).record : null;
  const exercised: ProofExerciseRecord | null =
    status === "SELF_HOSTED_PATH_EXERCISED" ? (input.exercise as ExerciseEvidence).record : null;
  // The exercise record the judge accepted must be an exercise of THIS accepted archive record for THIS designation:
  // the judge bound the record's bytes; here the facts the record names are held to the facts beside it.
  const latest = latestDesignation(input.designations);
  if (
    exercised !== null &&
    (record === null ||
      !latest ||
      exercised.subject.designation !== latest.id ||
      exercised.subject.programVKey !== latest.programVKey ||
      exercised.archiveRecord.path !== input.archiveRecords[0] ||
      exercised.archiveRecord.archiveSha256 !== record.archive.sha256)
  ) {
    throw new Error(
      `${input.exerciseRecords[0]} is not an exercise of the accepted archive record ${input.archiveRecords[0]} for ${String(latest?.id)}`,
    );
  }
  const verifierCrate = obs.crates.find((c) => c.name === "sp1-verifier") as MeasuredCrate;
  const tarball = s.artifactUrl.slice(s.artifactUrl.lastIndexOf("/") + 1);
  const upstream = new URL(s.artifactUrl).host;
  const vkHash = `0x${s.groth16Vk.sha256}`;
  const docker = obs.gnark.backend === "docker";
  const repository = s.gnarkImage.replace(/:[^:/]+$/, "");
  const verifierCrateName = `sp1-verifier ${verifierCrate.version}`;
  const memberOf = (file: string) => record?.members.find((m) => m.path === file) ?? null;
  const archived = (file: string) => {
    const m = memberOf(file);
    return m === null
      ? { sha256: null, status: "UNKNOWN_UNTIL_ARCHIVED" }
      : { sha256: m.sha256, bytes: m.bytes, status: "ARCHIVED_VERIFIED" };
  };
  return {
    schema: PROVING_AVAILABILITY_SCHEMA,
    finding: {
      id: finding.id,
      receipt: { path: TD1_RECEIPT_REL, sha256: input.td1Receipt.sha256 },
      title: finding.title,
      disposition: finding.disposition,
      plan: finding.plan,
      dependency,
    },
    status,
    basis: [
      obs.local.groth16DirPresent
        ? `a copy is present on ${obs.host} at ${obs.local.groth16Dir}, but WalletWall has neither archived nor verified it`
        : `the circuit ${v} Groth16 artifacts are absent on ${obs.host}: ${obs.local.groth16Dir} does not exist${obs.local.circuitsRootPresent ? "" : `, nor does ${obs.local.circuitsRoot}`}`,
      ...(record === null
        ? [`no WalletWall archive of them is recorded (${PROVING_ARCHIVES_DIR} holds no record)`]
        : [
            `WalletWall archived ${record.archive.file}: ${record.archive.bytes} bytes, sha256 ${record.archive.sha256}, acquired independently on ${record.acquisitions.map((a) => a.host).join(" and ")} (both measured the same bytes), inspected member by member by the SP1-PA2A tooling (${record.members.length} members; ${record.metadata.length} AppleDouble entries ignored), mirrored at ${record.mirrors.length} WalletWall-controlled locations each recorded with that sha256, with the gnark image pinned by digest ${record.gnark.digest}; the record is ${input.archiveRecords[0]}, derived from the committed acquisition observations`,
            ...(exercised === null
              ? [
                  "an archive is not an exercised proving path: no proof has been made from it, and archiving establishes availability of the bytes, never that the Groth16 trusted setup behind the key is sound",
                ]
              : [
                  `one real Groth16 proof of the designated program was made on ${exercised.exercise.host} through the archive-only gate from that archive, with SP1_PROVER=cpu, the digest-pinned image ${exercised.gnark.imageRef} and network egress refused before and after the run, and the designated verifier accepted it and refused its tampered copy (${exercised.verification.checks.length} check(s) of the v6.1.0 runtime at code hash ${exercised.verification.verifier.runtimeCodeKeccak}); the gate run took ${exercised.performance.wallClockSeconds} s against the ${ROTATION_DELAY_SECONDS} s rotation delay (${exercised.performance.withinRotationDelay ? "within it" : "EXCEEDING it"}, ${exercised.performance.rotationDelayFraction} of it), with peak memory ${exercised.performance.peakMemory.hostProcess.bytes} bytes (host process) and ${exercised.performance.peakMemory.gnarkContainers.bytes} bytes (gnark containers, sampled); the record is ${input.exerciseRecords[0]}, derived from the committed run and verification observations`,
                  "an exercised path is liveness on one host at one time: it establishes neither that the Groth16 trusted setup behind the key is sound nor production readiness",
                ]),
          ]),
      ...(status === "OWNER_DOWNLOAD_REQUIRED"
        ? [
            `obtaining them needs the download of ${tarball} (about ${size}, per SP1-TD1), which this lane is not authorized to make`,
          ]
        : []),
      `upstream (${upstream}) hosting them is not availability: it can stop, and nothing here relies on what it serves`,
      `known offline: their ${s.groth16VkFile} must have sha256 ${vkHash} (${s.groth16Vk.bytes} bytes), the key ${verifierCrateName} embeds; that crate is the one ${HOST_LOCK_REL} pins, and the hash is the designated VERIFIER_HASH`,
    ],
    designations: input.designations.map((d) => d.id),
    expectedArtifacts: {
      circuitVersion: v,
      upstreamUrl: s.artifactUrl,
      tarball:
        record === null
          ? {
              file: tarball,
              sha256: null,
              size: `about ${size} (SP1-TD1; not measured here)`,
              status: "UNKNOWN_UNTIL_ARCHIVED",
            }
          : {
              file: record.archive.file,
              sha256: record.archive.sha256,
              size: `${record.archive.bytes} bytes (measured on ${record.acquisitions.length} hosts)`,
              status: "ARCHIVED_VERIFIED",
            },
      members: [
        {
          file: s.groth16VkFile,
          sha256: vkHash,
          bytes: s.groth16Vk.bytes,
          knownFrom: `${verifierCrateName} ${VK_MEMBER} (crate sha256 ${verifierCrate.crateSha256}, the ${HOST_LOCK_REL} checksum)`,
          ...(record === null ? {} : { status: "ARCHIVED_VERIFIED" }),
          role: "the verifying key: a proof's selector and vkey hash are its sha256, so a proof made under any other key is refused by the designated verifier",
        },
        ...s.groth16ProveReads.map((file) => ({
          file,
          ...archived(file),
          role: "read by Groth16 proving: any other file yields proofs the designated verifier refuses (liveness, never soundness)",
        })),
      ],
      gnark: {
        backend: obs.gnark.backend,
        features: obs.gnark.features,
        image: docker ? s.gnarkImage : "(none: the gnark prover is compiled into the host)",
        imageOverrideEnv: s.gnarkImageEnv,
        imageDigest: record === null ? null : record.gnark.digest,
        status: record === null ? "UNKNOWN_UNTIL_ARCHIVED" : "DIGEST_RECORDED_NOT_PULLED",
      },
    },
    pinnedProver: [
      `uses $${s.groth16DirEnv}/${v} when set, else ${s.groth16DefaultDir}`,
      `${s.reusesExistingDir ? "uses an existing directory as it is" : "re-checks an existing directory"}, and downloads ${s.artifactUrl} only when the directory is absent`,
      `${s.downloadVerifiesHash ? "checks a digest of the download" : "checks no digest of the download"}, and extracts it with tar ${s.extractFlags}${s.extractFlags.includes("P") ? " (absolute member names are kept)" : ""}`,
      `$${s.circuitModeEnv}=dev switches to development artifacts from another source`,
      `Groth16 proving reads ${s.groth16ProveReads.join(", ")}; the proof's vkey hash is the sha256 of ${s.groth16VkFile}`,
      docker
        ? `the host's dependency graph leaves sp1-recursion-gnark-ffi's native feature off, so the gnark prover runs in docker: ${s.gnarkImage} (a tag, mutable) unless $${s.gnarkImageEnv} names another image`
        : "the host's dependency graph enables sp1-recursion-gnark-ffi's native feature: the gnark prover is compiled into the host",
    ],
    local: { host: obs.host, ...obs.local, gnarkImages: obs.gnark.localImages },
    archives:
      record === null
        ? { dir: PROVING_ARCHIVES_DIR, records: input.archiveRecords.length }
        : {
            dir: PROVING_ARCHIVES_DIR,
            records: input.archiveRecords.length,
            accepted: {
              record: input.archiveRecords[0],
              derivedFrom: (input.archive as ArchiveEvidence).observations,
              hosts: record.acquisitions.map((a) => a.host),
              mirrors: record.mirrors.map((m) => m.location),
              members: record.members.length,
              ignoredMetadata: record.metadata.length,
              gnarkDigest: record.gnark.digest,
            },
          },
    exercises:
      exercised === null
        ? { dir: PROOF_EXERCISES_DIR, records: input.exerciseRecords.length }
        : {
            dir: PROOF_EXERCISES_DIR,
            records: input.exerciseRecords.length,
            accepted: {
              record: input.exerciseRecords[0],
              derivedFrom: (input.exercise as ExerciseEvidence).observations,
              host: exercised.exercise.host,
              performedAtUtc: exercised.exercise.performedAtUtc,
              verifiedAtUtc: exercised.exercise.verifiedAtUtc,
              wallClockSeconds: exercised.performance.wallClockSeconds,
              hostSeconds: exercised.performance.hostSeconds,
              rotationDelaySeconds: exercised.performance.rotationDelaySeconds,
              withinRotationDelay: exercised.performance.withinRotationDelay,
              peakMemory: {
                hostProcessBytes: exercised.performance.peakMemory.hostProcess.bytes,
                gnarkContainersBytes: exercised.performance.peakMemory.gnarkContainers.bytes,
              },
              verifier: {
                runtimeCodeKeccak: exercised.verification.verifier.runtimeCodeKeccak,
                checks: exercised.verification.checks.length,
              },
              egress: exercised.egress.condition,
            },
          },
    selfHostedPath: {
      exercised: exercised !== null,
      ...(exercised === null ? {} : { record: input.exerciseRecords[0] }),
      requirements: [
        `archive ${tarball} once, from an owner-authorized download, with its sha256 and every member's sha256 and size; upstream hosting is no archive`,
        `accept it only if its ${s.groth16VkFile} has sha256 ${vkHash} and is byte-identical to ${verifierCrateName}'s ${VK_MEMBER}; the other members are checked by proving, never trusted`,
        "mirror the verified archive to at least two WalletWall-controlled locations, each recorded with the tarball's sha256",
        docker
          ? `pin the gnark prover by digest: set $${s.gnarkImageEnv} to ${repository}@sha256:<digest> and archive that image, since ${s.gnarkImage} is a mutable tag`
          : "pin the native gnark build: its Go toolchain and module digests",
        `prove only from the archive: place the verified members at $${s.groth16DirEnv}/${v} (the pinned prover then downloads nothing), keep $${s.circuitModeEnv} unset, and check every member's sha256 before each proving session (the prover checks none)`,
        `exercise it: one Groth16 proof of the designated program made with network egress off (no prover network, no ${upstream}), accepted by the designated verifier on every supported chain (the per-chain check with that proof), with its peak memory and wall time recorded against the 2-day rotation delay`,
      ],
    },
    ownerAction:
      record === null
        ? [
            `authorize the download of ${tarball} (about ${size})${docker ? " and of the gnark image by digest" : ""}; this lane downloaded nothing`,
            "name the two archive locations WalletWall controls",
            "authorize the self-hosted proving run: a real proof, which this lane did not generate",
          ]
        : exercised === null
          ? [
              "authorize the self-hosted proving run (SP1-PA3B): install from the committed verified archive only, with the digest-pinned gnark image, network egress off, one real Groth16 proof of the designated program through the archive-only gate under measurement (sp1:measure-proof-exercise), verified through the designated verifier path (sp1:verify-proof-exercise), peak memory and wall time recorded against the 2-day rotation delay, the two observations committed and the record derived (sp1:proof-exercise-record); only then SELF_HOSTED_PATH_EXERCISED, from facts",
            ]
          : [
              "production binding (the implementation receipt's PRODUCTION_SP1_BINDING) is a later, owner-authorized lane: an exercised path is liveness on one host at one time, never production readiness",
            ],
    notEstablished:
      exercised !== null
        ? [
            "the provenance of the proving beyond what the repository binds (the proof's digests, the run's commit content, the canonical host binary, the committed input, the probes' shape and timing): the designated verifier accepts a valid proof whoever made it, however it was made; the rest is the operator's observation under the owner's review",
            `that any other hardware proves within the ${ROTATION_DELAY_SECONDS} s rotation delay: one measured run on one host (a run over the delay is still an exercised path, recorded as EXCEEDING, never a timely one)`,
            "that egress stayed refused between the two probes, or that the proving host's enforcement reached every container",
            "that the mirrors keep serving the archive, or that the image stays in the registry: the exercise used them once",
            `the Groth16 trusted setup behind the ${v} key: a proof the designated verifier accepts is compatibility with the key, never soundness`,
            "production readiness: the implementation receipt's PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED until its own lane",
          ]
        : record === null
          ? [
              `the tarball's sha256 and the digests of ${s.groth16ProveReads.join(", ")} (never downloaded)`,
              ...(docker ? ["the gnark image's digest"] : []),
              "that the self-hosted path proves at all, on what hardware, and within the 2-day rotation delay",
              "that upstream keeps hosting the artifacts",
              `the Groth16 trusted setup behind the ${v} key: an upstream assumption the designated verifier inherits, which archiving does not change`,
            ]
          : [
              "that the self-hosted path proves at all, on what hardware, and within the 2-day rotation delay: no proof has been made from the archive",
              "that the mirrors keep serving the archive: each was re-read byte for byte when its observation was made, and the record is that assertion, never a continuous check",
              "that the mirrors are independent of each other beyond what their locations and controller state",
              ...(docker
                ? [
                    "that the digest-pinned gnark image is archived under WalletWall's control: the record pins its identity (the registry's index digest and the linux/amd64 manifest), not a copy of its bytes",
                  ]
                : []),
              `the Groth16 trusted setup behind the ${v} key: an upstream assumption the designated verifier inherits, which archiving does not change; the verifying-key equality is integrity and compatibility, never soundness`,
            ],
    observation: { path: PROVING_ARTIFACTS_OBSERVATION_REL, sha256: input.observationSha256 },
  };
}

export function serializeProvingAvailability(record: ProvingAvailabilityRecord): string {
  return `${JSON.stringify(record, null, 2)}\n`;
}

/**
 * The archive evidence of `repoRoot`, judged for the latest designation's circuit and the pinned prover's gnark
 * image (both read from the committed evidence, never from a record): what provingAvailabilityStatus counts.
 */
export function archiveEvidenceFromRepo(
  repoRoot: string,
  observation: ProvingArtifactsObservation,
  designations: readonly ProgramDesignation[],
): ArchiveEvidence | null {
  const d = latestDesignation(designations);
  if (!d) return null;
  return productionArchiveEvidence(repoRoot, {
    anchor: anchorFromDesignation(d, observation.source.groth16Vk.bytes),
    gnarkImage: observation.source.gnarkImage,
  });
}

/**
 * The proof-exercise evidence of `repoRoot`, judged against the accepted archive evidence (SP1-PA3A); null while no
 * archive record is accepted (then any exercise record is refused by the status derivation, never judged on its own).
 */
export function exerciseEvidenceFromRepo(
  repoRoot: string,
  observation: ProvingArtifactsObservation,
  designations: readonly ProgramDesignation[],
  archive: ArchiveEvidence | null,
): ExerciseEvidence | null {
  const d = latestDesignation(designations);
  if (!d || archive === null || archive.record === null) return null;
  return productionExerciseEvidence(repoRoot, {
    anchor: anchorFromDesignation(d, observation.source.groth16Vk.bytes),
    archive,
  });
}

/** The record the committed evidence derives (throws when the evidence does not derive one). */
export function provingAvailabilityFromRepo(repoRoot = "."): ProvingAvailabilityRecord {
  const obsBytes = readFileSync(resolve(repoRoot, PROVING_ARTIFACTS_OBSERVATION_REL));
  const td1Bytes = readFileSync(resolve(repoRoot, TD1_RECEIPT_REL));
  const observation = JSON.parse(obsBytes.toString("utf8")) as ProvingArtifactsObservation;
  const designations = readDesignations(repoRoot);
  const archive = archiveEvidenceFromRepo(repoRoot, observation, designations);
  return deriveProvingAvailability({
    observation,
    observationSha256: sha256(obsBytes),
    designations,
    td1Receipt: { sha256: sha256(td1Bytes), doc: JSON.parse(td1Bytes.toString("utf8")) },
    archiveRecords: archiveRecordsIn(repoRoot),
    archive,
    exerciseRecords: exerciseRecordsIn(repoRoot),
    exercise: exerciseEvidenceFromRepo(repoRoot, observation, designations, archive),
  });
}

/** Every reason the committed proving-availability record is not what the committed evidence derives. */
export function provingAvailabilityErrors(repoRoot = "."): string[] {
  const obsPath = resolve(repoRoot, PROVING_ARTIFACTS_OBSERVATION_REL);
  if (!existsSync(obsPath)) return [`${PROVING_ARTIFACTS_OBSERVATION_REL} is missing: measure it`];
  const obs = JSON.parse(readFileSync(obsPath, "utf8")) as ProvingArtifactsObservation;
  const errors = provingArtifactsObservationErrors(obs, readDesignations(repoRoot), repoRoot);
  if (errors.length > 0) return errors;
  let expected: string;
  try {
    expected = serializeProvingAvailability(provingAvailabilityFromRepo(repoRoot));
  } catch (error) {
    return [(error as Error).message];
  }
  const recordPath = resolve(repoRoot, PROVING_AVAILABILITY_REL);
  if (!existsSync(recordPath) || readFileSync(recordPath, "utf8") !== expected) {
    errors.push(`${PROVING_AVAILABILITY_REL} is not what the evidence derives: regenerate it`);
  }
  return errors;
}
