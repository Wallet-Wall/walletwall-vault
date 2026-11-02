/**
 * SP1-PA3C-Q1: the root soak runner. It exercises the committed observer's `self-test` (never `run`: no proof-exercise
 * tool, no proof, no SP1) many times on the proving host and records, per iteration, only what a comparison needs:
 * the variation applied, the exit code, how long it took, the raw directory and its entries, the observer's own
 * summary (failures, heartbeats, misses, leftovers, cleanup) and what, if anything, it left in the kernel. The
 * derivation of each capture is not done here: it runs afterwards, as the unprivileged user, through
 * scripts/sp1-observer-qualification.ts, on the host and in the clean container.
 *
 *   node <root-owned copy>/sp1-observer-soak.ts --as <user> --repo <checkout> --observer <root-owned observer copy> \
 *     --out-dir <new directory under a root-owned parent> [--iterations 12] [--table sp1obs_q1] \
 *     [--boundary self-test-table|complete] [--id A]
 *
 * As root it creates one private nft table (the self-test table: the host's resolvers and TEST-NET-1 refused at the
 * output hook, every refusal counted, as the integration test does; or the complete egress boundary of SP1-PA3B's
 * shape, which refuses and counts everything but the host itself, VM-wide), runs the iterations, deletes the table,
 * and writes soak.json. Node
 * built-ins only (root never executes code from node_modules); the variation list is the library's, repeated here
 * verbatim (a test holds them equal). Linux only. Research prototype. Not audited.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SOAK_SCHEMA = "walletwall.sp1-observer-soak.v1";
const PATH = "/usr/sbin:/usr/bin:/sbin:/bin";
const TRACEFS = "/sys/kernel/tracing";
const RAW_FILES = ["facts.json", "manifest.json", "trace.txt"];
interface Variation {
  name: string;
  env: Record<string, string>;
  umask: number | null;
  cwd: "repo" | "/" | "/tmp";
}
/** Verbatim SOAK_VARIATIONS of scripts/lib/sp1-observer-qualification.ts. */
const VARIATIONS: readonly Variation[] = [
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

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

function argValue(argv: string[], name: string, fallback?: string): string {
  const i = argv.indexOf(name);
  const value = i === -1 ? fallback : argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${name} is required`);
  return value;
}

function run(cmd: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(cmd, args, { encoding: "utf8", shell: false, timeout: 60_000, env: { PATH } });
  if (r.error) throw r.error;
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Every path from `file` up to `/` must be root-owned and writable by no one else (the observer's own rule). */
function rootOwnedPathErrors(file: string): string[] {
  const errors: string[] = [];
  for (let p = resolve(file); ; p = dirname(p)) {
    const s = lstatSync(p);
    if (s.uid !== 0) errors.push(`${p} is owned by uid ${s.uid}, not root`);
    if ((s.mode & 0o022) !== 0) errors.push(`${p} is writable by group or others`);
    if (dirname(p) === p) break;
  }
  return errors;
}

const kprobesLeft = () =>
  readFileSync(join(TRACEFS, "kprobe_events"), "utf8")
    .split("\n")
    .filter((l) => /^[pr]\d*:sp1obs_/.test(l)).length;
const instancesLeft = () => readdirSync(join(TRACEFS, "instances")).filter((n) => n.startsWith("sp1obs_")).length;

function main(argv: string[]): number {
  if (process.platform !== "linux") throw new Error("NOT_LINUX: the observer needs tracefs");
  if (process.getuid?.() !== 0) throw new Error("NOT_ROOT: the observer and nft need root");
  const self = fileURLToPath(import.meta.url);
  const selfErrors = rootOwnedPathErrors(self);
  if (selfErrors.length > 0) throw new Error(`SOAK_PATH_NOT_ROOT_OWNED: ${selfErrors.join("; ")}`);
  // Every argument that reaches a command or a path is checked by form first: an account name, plain absolute paths.
  const user = argValue(argv, "--as");
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(user)) throw new Error("--as must be a plain account name");
  const plainPath = (name: string) => {
    const value = argValue(argv, name);
    if (!/^\/[A-Za-z0-9._/-]+$/.test(value)) throw new Error(`${name} must be an absolute path of plain characters`);
    return value;
  };
  const repo = realpathSync(plainPath("--repo"));
  const observer = realpathSync(plainPath("--observer"));
  const outDir = resolve(plainPath("--out-dir"));
  const iterations = Number(argValue(argv, "--iterations", "12"));
  const table = argValue(argv, "--table", "sp1obs_q1");
  const boundaryArg = argValue(argv, "--boundary", "self-test-table");
  const id = argValue(argv, "--id", "A");
  if (boundaryArg !== "self-test-table" && boundaryArg !== "complete")
    throw new Error("--boundary is self-test-table or complete");
  if (!/^[A-Z][A-Za-z0-9]{0,15}$/.test(id)) throw new Error("--id is a short capitalized name (A, B, ...)");
  const boundary = boundaryArg === "complete" ? "COMPLETE_EGRESS_BOUNDARY" : "SELF_TEST_TABLE";
  if (!Number.isSafeInteger(iterations) || iterations < 1) throw new Error("--iterations must be a positive integer");
  if (!/^[A-Za-z0-9_]{1,64}$/.test(table)) throw new Error("--table must be a plain name");
  const observerErrors = rootOwnedPathErrors(observer);
  if (observerErrors.length > 0) throw new Error(`OBSERVER_PATH_NOT_ROOT_OWNED: ${observerErrors.join("; ")}`);
  if (existsSync(outDir)) throw new Error(`${outDir} exists: the soak writes a new directory`);
  const parentErrors = rootOwnedPathErrors(dirname(outDir));
  if (parentErrors.length > 0) throw new Error(`OUT_DIR_PARENT_NOT_ROOT_OWNED: ${parentErrors.join("; ")}`);
  for (const f of [
    join(repo, "test/fixtures/sp1-egress-observer/workload.mjs"),
    join(repo, "scripts/sp1-egress-observer.ts"),
  ]) {
    if (!existsSync(f)) throw new Error(`${f} is missing: --repo is not a checkout`);
  }
  const committedObserver = sha256(
    readFileSync(join(repo, "scripts/sp1-egress-observer.ts"), "utf8").replace(/\r\n/g, "\n"),
  );
  const copyObserver = sha256(readFileSync(observer, "utf8").replace(/\r\n/g, "\n"));
  if (committedObserver !== copyObserver)
    throw new Error("OBSERVER_COPY_DIFFERS: the root-owned observer copy is not the checkout's observer");
  // The soak's own records (the rules, soak.json) are root's and the user's group's, like the observer's raw files:
  // host facts for the operator, not for every local account.
  const userGid = Number(run("getent", ["passwd", user]).stdout.trim().split(":")[3]);
  if (!Number.isSafeInteger(userGid)) throw new Error(`--as ${user}: not an account`);
  mkdirSync(outDir, { mode: 0o755 });
  chmodSync(outDir, 0o755);

  // The boundary: the host's resolvers and TEST-NET-1 refused at the output hook, every refusal counted.
  const resolvers = (existsSync("/etc/resolv.conf") ? readFileSync("/etc/resolv.conf", "utf8") : "")
    .split(/\r?\n/)
    .map((l) => /^\s*nameserver\s+(\S+)\s*$/.exec(l)?.[1])
    .filter((x): x is string => typeof x === "string" && isIP(x) !== 0)
    .map((r) => `    ${isIP(r) === 6 ? "ip6" : "ip"} daddr ${r} counter reject\n`)
    .join("");
  // SELF_TEST_TABLE: the integration test's (TEST-NET-1 and the resolvers refused, nothing else: another process's
  // real egress passes and rightly reads as a leak). COMPLETE_EGRESS_BOUNDARY: SP1-PA3B's shape, the one SP1-PA3D runs
  // under: the resolvers refused first (they live on lo), the host's own addresses accepted (so its RST/ICMP answers
  // are not swallowed), everything else refused and counted at the output hook, every forwarded packet dropped and
  // counted. It is VM-wide while it stands.
  const rules =
    boundary === "SELF_TEST_TABLE"
      ? `table inet ${table} {\n  chain output {\n    type filter hook output priority -10; policy accept;\n${resolvers}    ip daddr 192.0.2.0/24 meta l4proto tcp counter reject with tcp reset\n    ip daddr 192.0.2.0/24 counter reject\n  }\n}\n`
      : `table inet ${table} {\n  chain output {\n    type filter hook output priority -10; policy accept;\n${resolvers}    fib daddr type local accept\n    meta l4proto tcp counter reject with tcp reset\n    meta l4proto udp counter reject with icmpx port-unreachable\n    counter reject with icmpx admin-prohibited\n  }\n  chain forward {\n    type filter hook forward priority -10; policy drop;\n    counter drop\n  }\n}\n`;
  const rulesPath = join(outDir, "table.nft");
  writeFileSync(rulesPath, rules, { mode: 0o640 });
  chownSync(rulesPath, 0, userGid);
  chmodSync(rulesPath, 0o640);
  const nodeBinary = readFileSync(process.execPath);
  const soak: Record<string, unknown> = {
    schema: SOAK_SCHEMA,
    id,
    boundary,
    host: process.env.SP1_SOAK_HOST_LABEL ?? "proving-host",
    startedAtUtc: utcNow(),
    finishedAtUtc: null,
    kernelRelease: readFileSync("/proc/sys/kernel/osrelease", "utf8").trim(),
    bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    uptimeSecondsAtStart: Number(readFileSync("/proc/uptime", "utf8").split(" ")[0]),
    repo,
    observer: { path: observer, sha256: copyObserver },
    workloadSha256: sha256(
      readFileSync(join(repo, "test/fixtures/sp1-egress-observer/workload.mjs"), "utf8").replace(/\r\n/g, "\n"),
    ),
    node: { execPath: realpathSync(process.execPath), version: process.version, sha256: sha256(nodeBinary) },
    nft: run("nft", ["--version"]).stdout.trim(),
    setpriv: run("sh", ["-c", "command -v setpriv"]).stdout.trim(),
    docker: (() => {
      try {
        return run("docker", ["version", "--format", "{{.Server.Version}}"]).stdout.trim();
      } catch {
        return "absent";
      }
    })(),
    user,
    table: { family: "inet", name: table, rulesSha256: sha256(rules), rules },
    before: { probesLeft: kprobesLeft(), instancesLeft: instancesLeft() },
    iterations: [] as unknown[],
  };
  const list = soak.iterations as Record<string, unknown>[];
  let status = 0;
  const made = run("nft", ["-f", rulesPath]);
  if (made.status !== 0) throw new Error(`could not create ${table}: ${made.stderr}`);
  try {
    for (let k = 1; k <= iterations; k++) {
      const v = VARIATIONS[(k - 1) % VARIATIONS.length];
      const rawDir = join(outDir, `raw-${k}`);
      const startedAtUtc = utcNow();
      const t0 = process.hrtime.bigint();
      const before = process.umask();
      if (v.umask !== null) process.umask(v.umask);
      let r: ReturnType<typeof spawnSync>;
      try {
        r = spawnSync(
          process.execPath,
          [observer, "self-test", "--as", user, "--repo", repo, "--table", "inet", table, "--raw-dir", rawDir],
          {
            cwd: v.cwd === "repo" ? repo : v.cwd,
            env: { PATH, ...v.env },
            encoding: "utf8",
            timeout: 180_000,
            shell: false,
          },
        );
      } finally {
        process.umask(before);
      }
      const seconds = Number((process.hrtime.bigint() - t0) / 1_000_000_000n);
      const stderr = String(r.stderr ?? "");
      const lines = stderr.split("\n").filter((l) => /^(probe (before|after)|host udp|raw evidence|observer:)/.test(l));
      let rawEntries: string[] = [];
      let factsSummary: Record<string, unknown> = {
        failures: null,
        heartbeats: null,
        probeMisses: null,
        leftoverLines: null,
        cleanup: null,
      };
      let manifestSha256: string | null = null;
      try {
        rawEntries = readdirSync(rawDir).sort();
        if (rawEntries.includes("facts.json")) {
          const f = JSON.parse(readFileSync(join(rawDir, "facts.json"), "utf8")) as Record<string, unknown>;
          factsSummary = {
            failures: Array.isArray(f.failures) ? f.failures.length : null,
            heartbeats: f.heartbeats ?? null,
            probeMisses: f.probeMisses ?? null,
            leftoverLines: f.leftoverLines ?? null,
            cleanup: Array.isArray(f.cleanup) ? f.cleanup.length : null,
          };
        }
        if (rawEntries.includes("manifest.json")) manifestSha256 = sha256(readFileSync(join(rawDir, "manifest.json")));
      } catch (error) {
        lines.push(`soak: raw directory unreadable: ${(error as Error).message}`);
      }
      const exit = r.status ?? (r.signal ? 128 : 1);
      const after = { probesLeft: kprobesLeft(), instancesLeft: instancesLeft() };
      const entriesOk = rawEntries.join(",") === RAW_FILES.join(",");
      if (exit !== 0 || after.probesLeft !== 0 || after.instancesLeft !== 0 || !entriesOk) status = 1;
      list.push({
        n: k,
        variation: v.name,
        applied: {
          env: v.env,
          umask: v.umask === null ? null : v.umask.toString(8),
          cwd: v.cwd === "repo" ? repo : v.cwd,
        },
        startedAtUtc,
        seconds,
        exit,
        signal: r.signal ?? null,
        rawDir,
        rawEntries,
        manifestSha256,
        factsSummary,
        after,
        stderrLines: lines,
      });
      process.stderr.write(
        `soak ${k}/${iterations} ${v.name}: exit ${exit}, ${seconds} s, ${rawEntries.length} files, probes left ${after.probesLeft}\n`,
      );
      if (after.probesLeft !== 0 || after.instancesLeft !== 0) {
        process.stderr.write(
          "soak: the kernel holds an observer's leftovers; stopping (the next precheck would refuse)\n",
        );
        break;
      }
    }
  } finally {
    const deleted = run("nft", ["delete", "table", "inet", table]);
    soak.tableDeleted = deleted.status === 0;
    soak.finishedAtUtc = utcNow();
    soak.after = { probesLeft: kprobesLeft(), instancesLeft: instancesLeft() };
    writeFileSync(join(outDir, "soak.json"), `${JSON.stringify(soak, null, 2)}\n`, { mode: 0o640 });
    chownSync(join(outDir, "soak.json"), 0, userGid);
    chmodSync(join(outDir, "soak.json"), 0o640);
    process.stderr.write(
      `${join(outDir, "soak.json")}: ${list.length} iterations, table deleted ${String(soak.tableDeleted)}\n`,
    );
  }
  return status;
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error((error as Error).message);
    process.exitCode = 2;
  }
}
