/**
 * SP1-PA2A: the archive-only gate in front of the host's local Groth16 prove path (`mldsa65-host prove <inputs>`).
 *
 * The pinned prover downloads the circuit itself whenever $SP1_GROTH16_CIRCUIT_PATH/v6.1.0 is absent, and pulls its
 * gnark image by a mutable tag unless $SP1_GNARK_IMAGE names another. This gate never lets either happen through it:
 * it refuses to start the host unless, at that moment,
 *
 *   - the archive record is accepted for the designation (scripts/lib/sp1-circuit-archive.ts);
 *   - the caller's environment selects nothing the gate does not freeze: no prover network, no other prover mode, no
 *     development circuit, no other circuit root or gnark image, no remote docker endpoint (the gnark container must
 *     mount the verified directory of this host);
 *   - the gnark image is named by digest and that exact digest is in the local docker store (inspected offline; the
 *     gate never pulls);
 *   - <root> holds <circuit version> and nothing else, and that directory is, byte for byte, the record's members,
 *     re-hashed now (installation alone authenticates nothing later);
 *   - on a POSIX host, run by an unprivileged user, <root> sits on a path only its owner can change, and is locked
 *     read-only for the whole run: the host cannot create a directory for another circuit version (a host built
 *     against another SP1 would read <root>/<its version>, find it absent and download), and nothing short of the
 *     owner or root can move the verified directory away for SP1 to fetch a fresh copy.
 *
 * The child gets a constructed environment: the frozen SP1_PROVER=cpu, SP1_GROTH16_CIRCUIT_PATH, SP1_GNARK_IMAGE and
 * DOCKER_CONTEXT=default, plus a short list of process basics; nothing else the caller set reaches it. Whatever the
 * host does, the installation is then re-hashed and its identity (inodes, links, times) compared with the one taken
 * under the lock, and a proof must name the designated PROGRAM_VKEY and carry its verifying key's selector.
 *
 * Residual, not eliminated here: the owner or root, who can undo the lock, rewriting proving inputs during the run;
 * the image removed so docker pulls it again (by digest). Research prototype. Not audited.
 */
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, lstatSync, realpathSync, type Stats } from "node:fs";
import { isAbsolute, join, posix, win32 } from "node:path";

import {
  acceptedRecord,
  imageRefError,
  refuse,
  type ArchiveAnchor,
  type ArchiveRecord,
  type CircuitToolingError,
} from "./sp1-circuit-archive";
import { installationIdentity, verifyInstalledCircuit, walkTree } from "./sp1-circuit-install";

export const LOCAL_PROVER = "cpu";
export const DOCKER_CONTEXT_FROZEN = "default";
/** What the gate sets in the child's environment; a caller value must be identical or is refused. */
export const FROZEN_ENV = ["SP1_PROVER", "SP1_GROTH16_CIRCUIT_PATH", "SP1_GNARK_IMAGE", "DOCKER_CONTEXT"] as const;
/** Variables the pinned SP1 reads that select another circuit, prover, verification or network: refused when set. */
export const REFUSED_ENV: Readonly<Record<string, string>> = {
  SP1_CIRCUIT_MODE: "CIRCUIT_MODE",
  SP1_PLONK_CIRCUIT_PATH: "ALTERNATE_CIRCUIT_PATH",
  WITHOUT_VK_VERIFICATION: "VK_VERIFICATION_OFF",
  SKIP_SIMULATION: "PROVER_NETWORK",
};
/** Every NETWORK_* variable (NETWORK_PRIVATE_KEY, NETWORK_RPC_URL, ...) is the prover network's. */
export const REFUSED_ENV_PREFIX = "NETWORK_";
/** Process basics passed through when the caller sets them. DOCKER_HOST only as a local socket (checked below). */
export const PASS_THROUGH_ENV: readonly string[] = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TMPDIR",
  "TMP",
  "TEMP",
  "SYSTEMROOT",
  "WINDIR",
  "PATHEXT",
  "USERPROFILE",
  "XDG_RUNTIME_DIR",
  "DOCKER_HOST",
  "DOCKER_CONFIG",
  "RUST_LOG",
  "RUST_BACKTRACE",
];
/** A docker endpoint on this machine: an absolute unix socket, or a local named pipe (never \\<server>\pipe\...). */
const LOCAL_DOCKER_HOST = { posix: /^unix:\/\/\/./, win32: /^npipe:\/\/\/\/\.\/pipe\/[^/\\]+$/ } as const;

export interface ProverEnv {
  env: Record<string, string>;
  /** Names (never values) of the caller's variables that were not passed on. */
  dropped: string[];
}

/** The child's environment, from the caller's and the frozen values; a security-bearing caller value is refused. */
export function buildProverEnv(
  caller: Readonly<Record<string, string | undefined>>,
  frozen: { circuitRoot: string; imageRef: string },
  platform: NodeJS.Platform = process.platform,
): ProverEnv {
  const env: Record<string, string> = {};
  const dropped: string[] = [];
  const passName = (k: string) => (platform === "win32" ? k.toUpperCase() : k);
  for (const [k, v] of Object.entries(caller)) {
    if (v === undefined) continue;
    const K = k.toUpperCase();
    if (K === "SP1_PROVER") {
      if (v !== LOCAL_PROVER) throw refuse("ENV_REFUSED", "PROVER_MODE", `${k} must be ${LOCAL_PROVER}, or unset`);
    } else if (K === "SP1_GROTH16_CIRCUIT_PATH") {
      if (v !== frozen.circuitRoot)
        throw refuse("ENV_REFUSED", "CIRCUIT_PATH_CONFLICT", `${k} is not the verified root`);
    } else if (K === "SP1_GNARK_IMAGE") {
      const bad = imageRefError(v);
      if (bad) throw refuse("GNARK_IMAGE_NOT_PINNED", bad, `${k} must name the image by digest`);
      if (v !== frozen.imageRef) throw refuse("GNARK_IMAGE_CONFLICT", "OTHER_DIGEST", `${k} is not the record's image`);
    } else if (K === "DOCKER_CONTEXT") {
      if (v !== DOCKER_CONTEXT_FROZEN)
        throw refuse("ENV_REFUSED", "DOCKER_CONTEXT", `${k} must be ${DOCKER_CONTEXT_FROZEN}`);
    } else if (K === "DOCKER_HOST") {
      if (!LOCAL_DOCKER_HOST[platform === "win32" ? "win32" : "posix"].test(v))
        throw refuse("ENV_REFUSED", "DOCKER_ENDPOINT_NOT_LOCAL", `${k} is not a local socket`);
    } else if (REFUSED_ENV[K] !== undefined) {
      throw refuse("ENV_REFUSED", REFUSED_ENV[K], `${k} is set`);
    } else if (K.startsWith(REFUSED_ENV_PREFIX)) {
      throw refuse("ENV_REFUSED", "PROVER_NETWORK", `${k} is set`);
    }
    if (PASS_THROUGH_ENV.includes(passName(k))) env[k] = v;
    else if (!(FROZEN_ENV as readonly string[]).includes(K)) dropped.push(k);
  }
  env.SP1_PROVER = LOCAL_PROVER;
  env.SP1_GROTH16_CIRCUIT_PATH = frozen.circuitRoot;
  env.SP1_GNARK_IMAGE = frozen.imageRef;
  env.DOCKER_CONTEXT = DOCKER_CONTEXT_FROZEN;
  return { env, dropped: dropped.sort() };
}

/**
 * The circuit root SP1 will be given: absolute, already normalized (SP1 uses it verbatim; an empty or relative value
 * would resolve against its working directory), and safe inside docker's `-v <src>:<dest>` mount spec.
 */
export function circuitRootError(root: string, platform: NodeJS.Platform = process.platform): string | null {
  const p = platform === "win32" ? win32 : posix;
  // A share other machines can write between the check and the use is never the verified tree.
  if (platform === "win32" && /^[\\/]{2}/.test(root)) return "UNC_PATH";
  if (!p.isAbsolute(root)) return "RELATIVE";
  if (p.resolve(root) !== root) return "NOT_NORMALIZED";
  const colon = platform === "win32" ? root.indexOf(":", 2) : root.indexOf(":");
  if (colon >= 0 || root.includes(",")) return "MOUNT_UNSAFE_PATH";
  return null;
}

function regularFile(path: string, what: string): void {
  if (!isAbsolute(path)) throw refuse("PROVE_INPUT_INVALID", "RELATIVE", `${what} ${path} is not absolute`);
  let st: Stats;
  try {
    st = lstatSync(path);
  } catch (error) {
    throw refuse("PROVE_INPUT_INVALID", "ABSENT", `${what} ${path}: ${(error as Error).message}`);
  }
  if (!st.isFile()) throw refuse("PROVE_INPUT_INVALID", "NOT_A_FILE", `${what} ${path} is not a regular file`);
}

/**
 * Why `root` is not a path only `uid` (and the superuser) can change, StrictModes-style, or null (POSIX): no link on
 * the way, the root `uid`'s and writable by nobody else, and every ancestor `uid`'s or the superuser's and writable
 * by no one else unless sticky (so no other user can rename the root, or an ancestor, out from under the run).
 */
export function securePathError(root: string, uid: number): string | null {
  let real: string;
  try {
    real = realpathSync(root);
  } catch {
    return "ABSENT";
  }
  if (real !== root) return "LINKED_PATH";
  for (let p = root; ; p = posix.dirname(p)) {
    const st = lstatSync(p);
    if (p === root ? st.uid !== uid : st.uid !== uid && st.uid !== 0)
      return p === root ? "NOT_OWNED" : "FOREIGN_ANCESTOR";
    if ((st.mode & 0o022) !== 0 && (p === root || (st.mode & 0o1000) === 0)) {
      return p === root ? "WRITABLE_BY_OTHERS" : "WRITABLE_ANCESTOR";
    }
    if (p === "/") return null;
  }
}

/** Holds the circuit root unchangeable for a run; `release` restores it. */
export type RootGuard = (circuitRoot: string, circuitDir: string) => { release(): void };

/**
 * The production guard (POSIX, unprivileged): the root's path is secure, the installation is its owner's and writable
 * by nobody else, and the root is made read-only until `release`, so the host can neither add a directory for another
 * circuit version nor move the verified one away. Permissions bind nothing for root, so root is refused, and Windows,
 * whose directory permissions this does not manage, is refused.
 */
export const posixRootGuard: RootGuard = (root, circuitDir) => {
  if (process.platform === "win32") {
    throw refuse(
      "PROVE_HOST_UNSUPPORTED",
      "WINDOWS",
      "proving through the gate needs a POSIX host whose circuit root can be locked",
    );
  }
  const uid = process.getuid?.() ?? -1;
  if (uid === 0)
    throw refuse(
      "PROVE_HOST_UNSUPPORTED",
      "RUNS_AS_ROOT",
      "permissions bind nothing for root: run as an unprivileged user",
    );
  const bad = securePathError(root, uid);
  if (bad) throw refuse("CIRCUIT_ROOT_INVALID", bad, `${root} is not a path only its owner can change`);
  const { files, directories } = walkTree(circuitDir, "CIRCUIT_INTEGRITY_FAILED");
  for (const p of [circuitDir, ...[...directories, ...files].map((rel) => join(circuitDir, ...rel.split("/")))]) {
    const st = lstatSync(p);
    if (st.uid !== uid || (st.mode & 0o022) !== 0) {
      throw refuse("CIRCUIT_ROOT_INVALID", "WRITABLE_BY_OTHERS", `${p} is not ${uid}'s alone`);
    }
  }
  const mode = lstatSync(root).mode & 0o7777;
  chmodSync(root, mode & ~0o222);
  return { release: () => chmodSync(root, mode) };
};

/** The local image's repo digests for `ref` (offline: `docker image inspect`); null when docker has no such image. */
export type LocalImageDigests = (ref: string, env: Record<string, string>) => string[] | null;

export const dockerImageDigests: LocalImageDigests = (ref, env) => {
  const r = spawnSync("docker", ["image", "inspect", "--format", "{{json .RepoDigests}}", ref], {
    env,
    encoding: "utf8",
    shell: false,
    timeout: 60_000,
    windowsHide: true,
  });
  if (r.error) throw new Error(`docker did not run: ${r.error.message}`);
  if (r.status !== 0) {
    if (/no such (image|object)/i.test(r.stderr)) return null;
    throw new Error(`docker did not answer: ${r.stderr.trim()}`);
  }
  const digests: unknown = JSON.parse(r.stdout.trim());
  if (!Array.isArray(digests) || !digests.every((d) => typeof d === "string")) {
    throw new Error("docker answered something other than a list of repo digests");
  }
  return digests;
};

export interface ProveGateInput {
  record: unknown;
  anchor: ArchiveAnchor;
  circuitRoot: string;
  hostExecutable: string;
  inputsPath: string;
  callerEnv: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
}

export interface ProvePlan {
  executable: string;
  args: string[];
  env: Record<string, string>;
  dropped: string[];
  circuitDir: string;
  imageRef: string;
  record: ArchiveRecord;
}

/** Every check, in order, the last one the full re-hash; returns what to spawn, or throws before anything runs. */
export function prepareArchiveOnlyProve(input: ProveGateInput, images: LocalImageDigests): ProvePlan {
  const record = acceptedRecord(input.record, input.anchor);
  const imageRef = `${record.gnark.repository}@${record.gnark.digest}`;
  const rootBad = circuitRootError(input.circuitRoot, input.platform);
  if (rootBad) throw refuse("CIRCUIT_ROOT_INVALID", rootBad, `${input.circuitRoot}`);
  const { env, dropped } = buildProverEnv(
    input.callerEnv,
    { circuitRoot: input.circuitRoot, imageRef },
    input.platform,
  );
  regularFile(input.hostExecutable, "the host executable");
  regularFile(input.inputsPath, "the inputs file");
  let digests: string[] | null;
  try {
    digests = images(imageRef, env);
  } catch (error) {
    throw refuse("GNARK_IMAGE_NOT_LOCAL", "UNVERIFIABLE", `${imageRef}: ${(error as Error).message}`);
  }
  if (digests === null) throw refuse("GNARK_IMAGE_NOT_LOCAL", "ABSENT", `${imageRef} is not in the local docker store`);
  if (!digests.includes(imageRef)) {
    throw refuse("GNARK_IMAGE_NOT_LOCAL", "DIGEST_NOT_LOCAL", `the local image is not ${imageRef}`);
  }
  const { circuitDir } = verifyInstalledCircuit(input.circuitRoot, record, input.anchor);
  return {
    executable: input.hostExecutable,
    args: ["prove", input.inputsPath],
    env,
    dropped,
    circuitDir,
    imageRef,
    record,
  };
}

export interface SpawnResult {
  status: number | null;
  signal: string | null;
  stdout: string;
}
export type Spawner = (plan: ProvePlan) => Promise<SpawnResult>;

const MAX_STDOUT = 64 * 1024 * 1024;

/** Runs the host without a shell, with exactly the plan's environment; stdout is captured, stderr passes through. */
export const spawnHost: Spawner = (plan) =>
  new Promise((done, fail) => {
    const child = spawn(plan.executable, plan.args, {
      env: plan.env,
      shell: false,
      stdio: ["ignore", "pipe", "inherit"],
      windowsHide: true,
    });
    const chunks: Buffer[] = [];
    let size = 0;
    child.stdout.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_STDOUT) child.kill();
      else chunks.push(c);
    });
    child.on("error", fail);
    child.on("close", (status, signal) =>
      size > MAX_STDOUT
        ? fail(refuse("PROOF_OUTPUT_REFUSED", "OUTPUT_TOO_LARGE", `more than ${MAX_STDOUT} bytes on stdout`))
        : done({ status, signal, stdout: Buffer.concat(chunks).toString("utf8") }),
    );
  });

export interface ProofOutput {
  vkey: string;
  publicValues: string;
  proofBytes: string;
}

/** The host's proof JSON (its last stdout line), which must name the designated PROGRAM_VKEY. */
export function proofOutput(stdout: string, anchor: ArchiveAnchor): ProofOutput {
  const line =
    stdout
      .split(/\r?\n/)
      .filter((l) => l.trim() !== "")
      .pop() ?? "";
  let out: Record<string, unknown>;
  try {
    out = JSON.parse(line);
  } catch {
    throw refuse("PROOF_OUTPUT_REFUSED", "NOT_JSON", "the host's last stdout line is not JSON");
  }
  if (out?.vkey !== anchor.programVKey) {
    throw refuse("PROOF_OUTPUT_REFUSED", "VKEY_MISMATCH", `the proof names vkey ${String(out?.vkey)}`);
  }
  if (!/^0x(?:[0-9a-f]{2})*$/.test(String(out.publicValues)) || !/^0x(?:[0-9a-f]{2})+$/.test(String(out.proofBytes))) {
    throw refuse("PROOF_OUTPUT_REFUSED", "SHAPE", "publicValues and proofBytes must be hex");
  }
  // SP1's Groth16 proof bytes open with the first four bytes of sha256(groth16_vk.bin): the key it was made under.
  if (String(out.proofBytes).slice(2, 10) !== anchor.verifyingKey.sha256.slice(2, 10)) {
    throw refuse(
      "PROOF_OUTPUT_REFUSED",
      "SELECTOR_MISMATCH",
      "the proof was not made under the designated verifying key",
    );
  }
  return { vkey: out.vkey as string, publicValues: out.publicValues as string, proofBytes: out.proofBytes as string };
}

/**
 * The gate, the host run and the after-run checks. Nothing is spawned unless prepareArchiveOnlyProve returned and the
 * root is locked; under the lock the installation is verified again and its identity taken; whatever the host does,
 * failure included, the installation must afterwards be the same bytes at the same inodes, before the lock is released.
 */
export async function runArchiveOnlyProve(
  input: ProveGateInput,
  deps: { images: LocalImageDigests; spawn: Spawner; guard?: RootGuard },
): Promise<{ plan: ProvePlan; output: ProofOutput }> {
  const plan = prepareArchiveOnlyProve(input, deps.images);
  const lock = (deps.guard ?? posixRootGuard)(input.circuitRoot, plan.circuitDir);
  let result: SpawnResult | null = null;
  let failure: unknown = null;
  try {
    verifyInstalledCircuit(input.circuitRoot, plan.record, input.anchor);
    const before = installationIdentity(input.circuitRoot, plan.circuitDir).join("\n");
    try {
      result = await deps.spawn(plan);
    } catch (error) {
      failure = error;
    }
    try {
      verifyInstalledCircuit(input.circuitRoot, plan.record, input.anchor);
      if (installationIdentity(input.circuitRoot, plan.circuitDir).join("\n") !== before) {
        throw refuse("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE", "REPLACED", "the same bytes now sit at other inodes");
      }
    } catch (error) {
      const e = error as CircuitToolingError;
      if (e.code === "CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE") throw e;
      throw refuse("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE", e.reason ?? "UNEXPECTED", e.message);
    }
  } finally {
    lock.release();
  }
  if (failure !== null) {
    if ((failure as { code?: string })?.code === "PROOF_OUTPUT_REFUSED") throw failure;
    throw refuse("PROVER_SPAWN_FAILED", "SPAWN", (failure as Error).message);
  }
  const done = result as SpawnResult;
  if (done.status !== 0) {
    throw refuse("PROVER_FAILED", "EXIT", `the host exited ${String(done.status)} (signal ${String(done.signal)})`);
  }
  return { plan, output: proofOutput(done.stdout, input.anchor) };
}
