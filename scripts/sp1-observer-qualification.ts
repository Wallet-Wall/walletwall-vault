/**
 * SP1-PA3C-Q1: the qualification CLI (scripts/lib/sp1-observer-qualification.ts does the deciding). It runs as the
 * unprivileged user on the proving host (through tsx) and, byte for byte the same file, inside the clean container
 * (through Node's own type stripping and scripts/sp1-observer-qualification/node-ts-loader.mjs): Node built-ins and
 * the repository's own libraries only, nothing from node_modules.
 *
 *   host-executable --path <node binary> --out <json>              the stand-in host's identity, as stat names it here
 *   derive (--raw <dir> --host-executable <json> | --fixture) --execution tsx|node-type-stripping --out <json>
 *          [--environment-file <json>] [--label <label>] [--source-commit <40 hex>]
 *   registry-check --image <repository@sha256:digest> --out <json> one read-only manifest request (the only network act)
 *   negative-controls --fixture-host <json> --fixture-container <json> --out <json>
 *   assemble --label <host> --soak <soak.json> --fixture-host <json> --fixture-container <json>
 *            --host-dir <dir> --container-dir <dir> --negative <json> --out <json>
 *   reconcile <a.json> <b.json>
 *
 * Every output is written once (never over a file). No proof, no download, no image pull. Research prototype. Not audited.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, statSync, writeSync } from "node:fs";
import { networkInterfaces, release } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { userDev, type HostExecutable } from "./lib/sp1-egress-attribution";
import {
  CLI_SCRIPT_REL,
  DERIVATION_SCHEMA,
  FIXTURE_HOST_EXECUTABLE,
  LANE,
  OBSERVATION_SCHEMA,
  deriveQualification,
  fixtureRawFrom,
  inputIdentityOf,
  readRawDir,
  reconcileDerivations,
  runNegativeControls,
  type ContainerIdentity,
  type Derivation,
  type EnvironmentIdentity,
  type NegativeControlResult,
  type QualificationObservation,
  type SoakIteration,
} from "./lib/sp1-observer-qualification";
import { OBSERVER_SCRIPT_REL } from "./sp1-egress-observer";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const say = (text: string) => process.stderr.write(`${text}\n`);
const HEX40 = /^[0-9a-f]{40}$/;

function arg(argv: string[], name: string, required = true): string | undefined {
  const i = argv.indexOf(name);
  const value = i === -1 ? undefined : argv[i + 1];
  if (required && (value === undefined || value.startsWith("--"))) throw new Error(`${name} is required`);
  return value;
}

/** Writes `text` to a file that must not exist yet. */
function writeNew(path: string, text: string): void {
  const fd = openSync(path, "wx");
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

const readJson = <T>(path: string): T => JSON.parse(lf(readFileSync(path, "utf8"))) as T;
const readRepo = (rel: string): Buffer | null => {
  try {
    return readFileSync(join(REPO, ...rel.split("/")));
  } catch {
    return null;
  }
};
const committedObserver = () => sha256(lf((readRepo(OBSERVER_SCRIPT_REL) as Buffer).toString("utf8")));

function gitHead(): string {
  const git = (...a: string[]) =>
    spawnSync("git", ["-C", REPO, "--no-optional-locks", ...a], { encoding: "utf8", shell: false });
  const head = git("rev-parse", "HEAD");
  if (head.status !== 0 || !HEX40.test(head.stdout.trim()))
    throw new Error(`${REPO} is not a git checkout: pass --source-commit`);
  const status = git("status", "--porcelain", "--untracked-files=all");
  if (status.status !== 0) throw new Error("git status failed");
  if (status.stdout.trim() !== "")
    throw new Error("the checkout is not clean: a derivation names its HEAD, so commit or discard first");
  return head.stdout.trim();
}

/** What the derivation can read of its own container from inside (facts, not the host's claims). */
function containerFacts(): ContainerIdentity["facts"] {
  const status = existsSync("/proc/self/status") ? readFileSync("/proc/self/status", "utf8") : "";
  const field = (name: string) =>
    /^(?:\S+)$/.exec((new RegExp(`^${name}:\\s*(\\S+)`, "m").exec(status) ?? [])[1] ?? "")?.[0] ?? "unknown";
  const mounts = existsSync("/proc/self/mounts") ? readFileSync("/proc/self/mounts", "utf8") : "";
  const root = mounts.split("\n").find((l) => l.split(" ")[1] === "/");
  const rootMount = root === undefined ? "unknown" : (root.split(" ")[3] ?? "").split(",")[0];
  return {
    uid: process.getuid?.() ?? -1,
    gid: process.getgid?.() ?? -1,
    networkInterfaces: Object.keys(networkInterfaces()).sort(),
    capEff: field("CapEff"),
    noNewPrivs: Number(field("NoNewPrivs")),
    rootMount,
    env: Object.keys(process.env).sort(),
  };
}

function environmentOf(argv: string[]): EnvironmentIdentity {
  const file = arg(argv, "--environment-file", false);
  const execution = arg(argv, "--execution") as EnvironmentIdentity["typescriptExecution"];
  if (execution !== "tsx" && execution !== "node-type-stripping")
    throw new Error("--execution is tsx or node-type-stripping");
  const given =
    file === undefined
      ? null
      : readJson<{ image: ContainerIdentity["image"]; runOptions: string[]; sourceCommit: string; label?: string }>(
          file,
        );
  const sourceCommit = arg(argv, "--source-commit", false) ?? given?.sourceCommit ?? gitHead();
  if (!HEX40.test(sourceCommit)) throw new Error(`the source commit ${sourceCommit} is not 40 hex digits`);
  const base: EnvironmentIdentity = {
    kind: given === null ? "HOST" : "CONTAINER",
    label: arg(argv, "--label", false) ?? given?.label ?? (given === null ? "host" : "clean-container"),
    platform: process.platform,
    release: release(),
    arch: process.arch,
    node: process.version,
    typescriptExecution: execution,
    sourceCommit,
  };
  if (given === null) return base;
  return { ...base, container: { image: given.image, runOptions: given.runOptions, facts: containerFacts() } };
}

function derive(argv: string[]): void {
  const out = arg(argv, "--out") as string;
  const committed = committedObserver();
  let raw;
  let hostExecutable: HostExecutable;
  if (argv.includes("--fixture")) {
    const fixture = fixtureRawFrom(readRepo);
    if (fixture === null) throw new Error("the committed self-test capture is missing");
    raw = fixture;
    hostExecutable = FIXTURE_HOST_EXECUTABLE;
  } else {
    const dir = arg(argv, "--raw") as string;
    if (!isAbsolute(dir)) throw new Error("--raw must be an absolute path");
    raw = readRawDir(dir);
    hostExecutable = readJson<HostExecutable>(arg(argv, "--host-executable") as string);
    if (
      typeof hostExecutable.path !== "string" ||
      typeof hostExecutable.dev !== "string" ||
      !Number.isSafeInteger(hostExecutable.ino)
    )
      throw new Error("--host-executable must hold {path, dev, ino}");
  }
  const derivation: Derivation = {
    schema: DERIVATION_SCHEMA,
    environment: environmentOf(argv),
    input: inputIdentityOf(raw, hostExecutable, committed),
    output: deriveQualification(raw, hostExecutable, committed),
  };
  writeNew(out, `${JSON.stringify(derivation, null, 2)}\n`);
  const o = derivation.output;
  say(
    `${out}: ${derivation.environment.kind} ${derivation.environment.label} (${derivation.environment.typescriptExecution}, node ${process.version}): normalized ${o.normalizedSha256 ?? "none"}, projection ${o.stableProjectionSha256?.slice(0, 16) ?? "none"}, refusals ${o.refusals.map((r) => r.reason).join(",") || "none"}`,
  );
}

function hostExecutable(argv: string[]): void {
  const path = arg(argv, "--path") as string;
  const out = arg(argv, "--out") as string;
  if (!isAbsolute(path)) throw new Error("--path must be absolute (the path the workload executes)");
  const s = statSync(path, { bigint: true });
  const id: HostExecutable = { path, dev: userDev(s.dev), ino: Number(s.ino) };
  writeNew(out, `${JSON.stringify(id, null, 2)}\n`);
  say(`${out}: ${id.path} ${id.dev}:${id.ino}`);
}

/** One read-only manifest request by digest: proves the registry serves exactly these bytes; pulls nothing. */
async function registryCheck(argv: string[]): Promise<void> {
  const image = arg(argv, "--image") as string;
  const out = arg(argv, "--out") as string;
  const m = /^([a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})$/.exec(image);
  if (!m) throw new Error("--image must be <repository>@sha256:<digest>");
  const repository = m[1].includes("/") ? m[1] : `library/${m[1]}`;
  const digest = m[2];
  const tokenResponse = await fetch(
    `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repository}:pull`,
  );
  const token = ((await tokenResponse.json()) as { token?: string }).token;
  if (typeof token !== "string") throw new Error(`no anonymous pull token (${tokenResponse.status})`);
  const response = await fetch(`https://registry-1.docker.io/v2/${repository}/manifests/${digest}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:
        "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json",
    },
  });
  const body = Buffer.from(await response.arrayBuffer());
  const bodySha256 = sha256(body);
  const matches = response.status === 200 && `sha256:${bodySha256}` === digest;
  const text = `docker.io/${repository} manifest by digest: HTTP ${response.status}, body sha256 ${matches ? "==" : "!="} digest (read-only; nothing pulled)`;
  writeNew(
    out,
    `${JSON.stringify({ image, repository, digest, http: response.status, contentType: response.headers.get("content-type"), bodySha256, matches, registryVerification: text, checkedAtUtc: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") }, null, 2)}\n`,
  );
  say(`${out}: ${text}`);
}

function negativeControls(argv: string[]): void {
  const host = readJson<Derivation>(arg(argv, "--fixture-host") as string);
  const container = readJson<Derivation>(arg(argv, "--fixture-container") as string);
  const out = arg(argv, "--out") as string;
  const raw = fixtureRawFrom(readRepo);
  if (raw === null) throw new Error("the committed self-test capture is missing");
  const results = runNegativeControls({
    raw,
    hostExecutable: host.input.hostExecutable,
    committedObserverSha256: committedObserver(),
    host,
    container,
  });
  writeNew(out, `${JSON.stringify(results, null, 2)}\n`);
  say(`${out}: ${results.filter((r) => r.ok).length}/${results.length} controls behaved as intended`);
}

interface SoakFile {
  schema: string;
  startedAtUtc: string;
  finishedAtUtc: string;
  kernelRelease: string;
  bootId: string;
  node: { execPath: string; version: string; sha256: string };
  nft: string;
  docker: string;
  table: { family: string; name: string; rulesSha256: string };
  iterations: {
    n: number;
    variation: string;
    startedAtUtc: string;
    seconds: number;
    exit: number;
    rawDir: string;
    rawEntries: string[];
    factsSummary: SoakIteration["factsSummary"];
    after: SoakIteration["after"];
  }[];
}

function assemble(argv: string[]): void {
  const label = arg(argv, "--label") as string;
  const soak = readJson<SoakFile>(arg(argv, "--soak") as string);
  if (soak.schema !== "walletwall.sp1-observer-soak.v1") throw new Error("--soak is not a soak record");
  const fixtureHost = readJson<Derivation>(arg(argv, "--fixture-host") as string);
  const fixtureContainer = readJson<Derivation>(arg(argv, "--fixture-container") as string);
  const hostDir = arg(argv, "--host-dir") as string;
  const containerDir = arg(argv, "--container-dir") as string;
  const negative = readJson<NegativeControlResult[]>(arg(argv, "--negative") as string);
  const out = arg(argv, "--out") as string;
  const commit = fixtureHost.environment.sourceCommit;
  const iterations: SoakIteration[] = soak.iterations.map((it) => {
    const host = readJson<Derivation>(join(hostDir, `derivation-raw-${it.n}.json`));
    const container = readJson<Derivation>(join(containerDir, `derivation-raw-${it.n}.json`));
    for (const d of [host, container]) {
      if (d.environment.sourceCommit !== commit)
        throw new Error(`iteration ${it.n}: a derivation names another commit`);
    }
    return {
      n: it.n,
      variation: it.variation,
      startedAtUtc: it.startedAtUtc,
      seconds: it.seconds,
      exit: it.exit,
      rawDir: it.rawDir,
      rawEntries: it.rawEntries,
      factsSummary: it.factsSummary,
      after: it.after,
      host,
      container,
    };
  });
  if (fixtureContainer.environment.sourceCommit !== commit) throw new Error("the fixture derivations name two commits");
  const observation: QualificationObservation = {
    schema: OBSERVATION_SCHEMA,
    lane: LANE,
    host: label,
    measuredAtUtc: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    tool: { script: CLI_SCRIPT_REL, scriptSha256: sha256(lf(readFileSync(fileURLToPath(import.meta.url), "utf8"))) },
    source: { commit, observerScriptSha256: committedObserver() },
    hostFacts: {
      kernelRelease: soak.kernelRelease,
      bootId: soak.bootId,
      node: soak.node,
      nft: soak.nft,
      docker: soak.docker,
      table: { family: soak.table.family, name: soak.table.name, rulesSha256: soak.table.rulesSha256 },
    },
    fixture: { host: fixtureHost, container: fixtureContainer },
    soak: { startedAtUtc: soak.startedAtUtc, finishedAtUtc: soak.finishedAtUtc, iterations },
    negativeControls: negative,
  };
  writeNew(out, `${JSON.stringify(observation, null, 2)}\n`);
  say(`${out}: ${iterations.length} soak iterations, ${negative.length} controls, commit ${commit}`);
}

function reconcileFiles(argv: string[]): number {
  const [a, b] = argv.filter((x) => !x.startsWith("--"));
  const r = reconcileDerivations(readJson<Derivation>(resolve(a)), readJson<Derivation>(resolve(b)));
  say(r.result);
  for (const d of r.differences) say(`  ${d.class} ${d.path}: ${JSON.stringify(d.a)} | ${JSON.stringify(d.b)}`);
  return r.result === "HOST_CONTAINER_OBSERVER_AGREEMENT" ? 0 : 1;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "host-executable":
      hostExecutable(rest);
      return 0;
    case "derive":
      derive(rest);
      return 0;
    case "registry-check":
      await registryCheck(rest);
      return 0;
    case "negative-controls":
      negativeControls(rest);
      return 0;
    case "assemble":
      assemble(rest);
      return 0;
    case "reconcile":
      return reconcileFiles(rest);
    default:
      throw new Error(
        "usage: sp1-observer-qualification.ts host-executable|derive|registry-check|negative-controls|assemble|reconcile ...",
      );
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    console.error((error as Error).message);
    process.exitCode = 2;
  },
);
