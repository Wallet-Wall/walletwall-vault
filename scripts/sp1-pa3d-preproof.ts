/**
 * SP1-PA3D, Phase 3: the pre-proof environment attestation, run on the proving host as the unprivileged prover BEFORE
 * the one authorized proof (see scripts/lib/sp1-pa3d-preproof.ts):
 *
 *   npx tsx scripts/sp1-pa3d-preproof.ts --proving-checkout <clean checkout of the manifest's source commit> \
 *     --circuit-root <absolute dir> --host <absolute path of the host binary> --host-label <label> --out <new file>
 *
 * It records facts and derives the verdict from them and the committed manifest: PA3D_PREPROOF_ENVIRONMENT_VALID
 * (exit 0) or PA3D_PREPROOF_ENVIRONMENT_REFUSED (exit 1, every refusal named). The observation is written either way
 * (never over an existing file): a refusal is evidence too, and no proof is made after one. It runs from the lane
 * checkout (which holds the manifest), re-derives the observer qualification there, verifies the installed circuit
 * with the gate's own check, hashes the host binary, asks the local docker store for the gnark image by digest, and
 * reads the platform. Nothing is pulled, downloaded or changed. Research prototype. Not audited.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { machine, platform, release, userInfo } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runScript } from "./lib/run-script";
import type { ArchiveRecord } from "./lib/sp1-circuit-archive";
import { verifyInstalledCircuit } from "./lib/sp1-circuit-install";
import { qualificationErrors, validationContextFromRepo } from "./lib/sp1-observer-qualification";
import {
  MANIFEST_REL,
  PRODUCTION_SP1_BINDING,
  manifestContextFromRepo,
  manifestErrors,
  type Manifest,
} from "./lib/sp1-pa3d-exercise";
import {
  PREPROOF_SCHEMA,
  preproofExpectationsOf,
  preproofVerdictOf,
  serializePreproof,
  type PreproofFacts,
  type PreproofObservation,
} from "./lib/sp1-pa3d-preproof";
import { utcNow } from "./lib/sp1-proof-exercise";
import { DOCKER_CONTEXT_FROZEN, PASS_THROUGH_ENV, dockerImageDigests } from "./lib/sp1-prove-gate";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");

function arg(name: string): string {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${name} <value> is required`);
  return value;
}

const git = (cwd: string, ...args: string[]) =>
  spawnSync("git", ["-C", cwd, "--no-optional-locks", ...args], {
    encoding: "utf8",
    shell: false,
    maxBuffer: 64 * 1024 * 1024,
  });

function checkoutOf(dir: string): { commit: string; dirty: boolean } {
  const head = git(dir, "rev-parse", "HEAD");
  if (head.status !== 0) throw new Error(`${dir} is not a git checkout`);
  const status = git(dir, "status", "--porcelain", "--untracked-files=all");
  if (status.status !== 0) throw new Error(`git status failed in ${dir}`);
  return { commit: head.stdout.trim(), dirty: status.stdout.trim() !== "" };
}

function meminfo(): { memTotalKiB: number; swapTotalKiB: number } {
  const text = readFileSync("/proc/meminfo", "utf8");
  const kib = (key: string) =>
    Number(/^(\S+):\s+(\d+) kB/m.exec(text.split("\n").find((l) => l.startsWith(`${key}:`)) ?? "")?.[2] ?? NaN);
  return { memTotalKiB: kib("MemTotal"), swapTotalKiB: kib("SwapTotal") };
}

function dockerVersion(env: Record<string, string>): string | null {
  const r = spawnSync("docker", ["version", "--format", "{{.Server.Version}} api={{.Server.APIVersion}}"], {
    env,
    encoding: "utf8",
    shell: false,
    timeout: 60_000,
  });
  if (r.error || r.status !== 0) return null;
  return `${r.stdout.trim()} endpoint=${env.DOCKER_HOST ?? "unix:///var/run/docker.sock"} context=${env.DOCKER_CONTEXT}`;
}

runScript(async () => {
  const provingCheckout = arg("--proving-checkout");
  const circuitRoot = arg("--circuit-root");
  const hostBinary = arg("--host");
  const hostLabel = arg("--host-label");
  const out = arg("--out");
  for (const [name, p] of [
    ["--proving-checkout", provingCheckout],
    ["--circuit-root", circuitRoot],
    ["--host", hostBinary],
  ]) {
    if (!isAbsolute(p)) throw new Error(`${name} must be an absolute path`);
  }
  const ctx = manifestContextFromRepo(REPO);
  const manifestText = lf(readFileSync(resolve(REPO, MANIFEST_REL), "utf8"));
  const manifest = JSON.parse(manifestText) as Manifest;
  const env: Record<string, string> = { DOCKER_CONTEXT: DOCKER_CONTEXT_FROZEN };
  for (const k of PASS_THROUGH_ENV) if (process.env[k] !== undefined) env[k] = process.env[k] as string;

  let circuit: PreproofFacts["circuit"] = { root: circuitRoot, members: null, error: null };
  try {
    const record = JSON.parse(
      lf(readFileSync(resolve(REPO, manifest.circuit.archiveRecord.path), "utf8")),
    ) as ArchiveRecord;
    const { members } = verifyInstalledCircuit(circuitRoot, record, ctx.anchor);
    circuit = {
      root: circuitRoot,
      members: members.map((m) => ({ path: m.path, bytes: m.bytes, sha256: m.sha256 })),
      error: null,
    };
  } catch (error) {
    circuit = { root: circuitRoot, members: null, error: (error as Error).message.split("\n")[0] };
  }
  let binary: PreproofFacts["hostBinary"] = { path: hostBinary, bytes: null, sha256: null };
  try {
    const bytes = readFileSync(hostBinary);
    if (!statSync(hostBinary).isFile()) throw new Error("not a regular file");
    binary = { path: hostBinary, bytes: bytes.length, sha256: sha256(bytes) };
  } catch {
    binary = { path: hostBinary, bytes: null, sha256: null };
  }
  let gnark: PreproofFacts["gnark"] = {
    imageRef: manifest.circuit.gnark.imageRef,
    localRepoDigests: null,
    error: null,
  };
  try {
    gnark = { ...gnark, localRepoDigests: dockerImageDigests(manifest.circuit.gnark.imageRef, env) };
  } catch (error) {
    gnark = { ...gnark, error: (error as Error).message.split("\n")[0] };
  }
  const qualificationText = lf(readFileSync(resolve(REPO, manifest.environment.qualification.path), "utf8"));
  let qualificationBad: string[];
  try {
    qualificationBad = qualificationErrors(JSON.parse(qualificationText), validationContextFromRepo(REPO));
  } catch (error) {
    qualificationBad = [`the qualification could not be re-derived here: ${(error as Error).message.split("\n")[0]}`];
  }
  const osRelease = (() => {
    try {
      return /^PRETTY_NAME="?([^"\n]+)"?$/m.exec(readFileSync("/etc/os-release", "utf8"))?.[1] ?? "unknown";
    } catch {
      return "unknown";
    }
  })();
  const bootId = (() => {
    try {
      return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    } catch {
      return "unknown";
    }
  })();
  const mem = platform() === "linux" ? meminfo() : { memTotalKiB: 0, swapTotalKiB: 0 };
  const facts: PreproofFacts = {
    schema: PREPROOF_SCHEMA,
    lane: "SP1-PA3D",
    host: hostLabel,
    measuredAtUtc: utcNow(),
    manifest: { path: MANIFEST_REL, sha256: sha256(manifestText), errors: manifestErrors(manifest, ctx) },
    laneCheckout: checkoutOf(REPO),
    provingCheckout: {
      path: provingCheckout,
      ...checkoutOf(provingCheckout),
      tools: manifest.tools.map((t) => {
        try {
          return {
            path: t.path,
            sha256: sha256(lf(readFileSync(join(provingCheckout, ...t.path.split("/")), "utf8"))),
          };
        } catch {
          return { path: t.path, sha256: null };
        }
      }),
    },
    circuit,
    hostBinary: binary,
    gnark,
    qualification: {
      path: manifest.environment.qualification.path,
      sha256: sha256(qualificationText),
      errors: qualificationBad,
    },
    platform: {
      os: platform(),
      kernel: release(),
      machine: machine(),
      bootId,
      distro: osRelease,
      ...mem,
      node: process.version,
      docker: dockerVersion(env),
      user: userInfo().username,
      uid: process.getuid?.() ?? -1,
    },
  };
  const verdict = preproofVerdictOf(facts, preproofExpectationsOf(manifest, manifestText));
  const observation: PreproofObservation = { ...facts, ...verdict };
  writeNewFiles([[resolve(out), serializePreproof(observation)]], "a pre-proof attestation is never overwritten");
  console.log(
    `${out}: ${verdict.verdict}${verdict.refusals.length > 0 ? `\n - ${verdict.refusals.join("\n - ")}` : ""}`,
  );
  console.log(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING}.`);
  if (verdict.verdict !== "PA3D_PREPROOF_ENVIRONMENT_VALID") process.exitCode = 1;
});
