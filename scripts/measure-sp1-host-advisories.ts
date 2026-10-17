/**
 * Measures, read-only, what RustSec, the crates.io index, cargo and the pinned crates' own bytes say about the four
 * committed Rust lockfiles (scripts/lib/sp1-host-advisories.ts; docs/SP1_Host_Lockfile_Advisories.md), and writes
 * the observation.
 *
 *   npx tsx scripts/measure-sp1-host-advisories.ts --db <advisory-db checkout> [--host <id>] [--out <file>]
 *                                                  [--cargo-home <dir>]
 *
 *   --db          a checkout of https://github.com/rustsec/advisory-db; cargo audit runs with --no-fetch against it, so
 *                 the database is exactly that commit and fetching it is a separate, earlier step
 *   --host        the measuring host's id (default developer-workstation)
 *   --out         where to write (default evidence/zk/sp1-impl/observations/host-advisories-<host>.raw.json)
 *   --cargo-home  the CARGO_HOME whose registry cache holds the locked crates (default $CARGO_HOME, else ~/.cargo)
 *
 * It measures HEAD's zkvm/ tree, exported with `git archive` into a temporary directory, so cargo never runs in the
 * repository and no lockfile is ever written; a working tree whose zkvm/ differs from HEAD is refused. cargo audit
 * runs with --no-yanked, and yanked status is read from the crates.io sparse index instead, so that an index that does
 * not answer fails the measurement rather than silently dropping yanked findings (unmeasured is not clean). The
 * dry-run update probes read cargo's index too. Research prototype. Not audited. Testnet/local only.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gzipSync } from "node:zlib";

import {
  ADVISORY_OBSERVATION_SCHEMA,
  CARGO_AUDIT_VERSION,
  FEATURE_CRATES,
  LOCKFILES,
  MEASURE_ADVISORIES_SCRIPT_REL,
  SOURCE_FACTS,
  SPARSE_INDEX_BASE,
  countMatches,
  featureTreeCommand,
  findingSpecs,
  indexEntriesOf,
  lockPathOf,
  measuredFindingsOf,
  memberSelected,
  normalizeCargoOutput,
  onlyVersion,
  parseCargoLock,
  preciseProbeCommand,
  precisePlan,
  registryPackages,
  sparseIndexPath,
  specOf,
  treeCommand,
  updateProbeCommand,
  yankedPackages,
  type AdvisoryObservation,
  type LockPackage,
  type ObservedLockfile,
  type ObservedSourceFact,
} from "./lib/sp1-host-advisories";
import { readTarMembers } from "./lib/sp1-proving-availability";

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? fallback : process.argv[i + 1];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function run(cmd: string, args: string[], cwd: string, accept: readonly number[] = [0]) {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  if (r.error || r.status === null || !accept.includes(r.status)) {
    throw new Error(
      `\`${cmd} ${args.join(" ")}\` failed (${r.error?.message ?? `exit ${r.status}`}): ${String(r.stderr).trim().slice(-2000)}`,
    );
  }
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
const argv = (command: string) => command.split(" ").slice(1);

/** HEAD's zkvm/ tree, written into `dir` from `git archive`; the working tree must be HEAD's. */
function exportZkvm(dir: string): void {
  const dirty = run("git", ["status", "--porcelain", "--untracked-files=all", "--", "zkvm"], ".").stdout.trim();
  if (dirty !== "") throw new Error(`zkvm/ differs from HEAD; measure a committed tree:\n${dirty}`);
  const r = spawnSync("git", ["archive", "--format=tar", "HEAD", "zkvm"], { maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git archive failed: ${String(r.stderr)}`);
  for (const [path, bytes] of readTarMembers(gzipSync(r.stdout))) {
    // A member must stay inside zkvm/ on every platform: no "..", and no backslash (a separator on Windows).
    if (!path.startsWith("zkvm/") || path.includes("\\") || path.split("/").includes("..")) {
      throw new Error(`git archive member ${JSON.stringify(path)} is not a path under zkvm/`);
    }
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), bytes);
  }
}

/** The .crate of `p` from the registry cache; every cached copy must be the bytes the lockfile pins. */
function crateBytes(cargoHome: string, p: LockPackage): Buffer {
  const cache = join(cargoHome, "registry", "cache");
  const found: Buffer[] = [];
  for (const index of readdirSync(cache, { withFileTypes: true })) {
    if (!index.isDirectory()) continue;
    try {
      found.push(readFileSync(join(cache, index.name, `${p.name}-${p.version}.crate`)));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (found.length === 0)
    throw new Error(`${specOf(p.name, p.version)} is not in the cargo cache at ${cache}: cargo fetch first`);
  for (const b of found) {
    if (sha256(b) !== p.checksum)
      throw new Error(`a cached ${specOf(p.name, p.version)} is not the crate the lockfile pins`);
  }
  return found[0];
}

async function indexFile(name: string): Promise<string> {
  const url = `${SPARSE_INDEX_BASE}${sparseIndexPath(name)}`;
  let last = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, {
        headers: {
          "User-Agent": "walletwall-vault RustSec advisory measurement (github.com/Wallet-Wall/walletwall-vault)",
        },
        signal: AbortSignal.timeout(30_000),
      });
      if (res.ok) return await res.text();
      last = `HTTP ${res.status}`;
      if (res.status === 404) break;
    } catch (error) {
      last = (error as Error).message;
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
  throw new Error(`the crates.io index did not answer for ${name} (${last}): yanked status unmeasured`);
}

async function main() {
  const db = resolve(arg("--db"));
  const host = arg("--host", "developer-workstation");
  const out = resolve(arg("--out", `evidence/zk/sp1-impl/observations/host-advisories-${host}.raw.json`));
  const cargoHome = resolve(arg("--cargo-home", process.env.CARGO_HOME ?? join(homedir(), ".cargo")));

  const cargoAudit = run("cargo", ["audit", "--version"], ".").stdout.trim();
  if (!cargoAudit.endsWith(` ${CARGO_AUDIT_VERSION}`)) {
    throw new Error(`measure with cargo-audit ${CARGO_AUDIT_VERSION}, not "${cargoAudit}"`);
  }
  const cargo = run("cargo", ["--version"], ".").stdout.trim();
  // With --no-fetch cargo-audit reads the database from disk and reports no commit, so the commit is git's, and only
  // a clean checkout is that commit's content (a fetched-into checkout can keep renamed advisories as untracked files).
  const dbCommit = run("git", ["-C", db, "rev-parse", "HEAD"], ".").stdout.trim();
  const dbUpdated = run("git", ["-C", db, "log", "-1", "--format=%cI"], ".").stdout.trim();
  const dbDirty = run("git", ["-C", db, "status", "--porcelain", "--untracked-files=all"], ".").stdout.trim();
  if (dbDirty !== "") throw new Error(`the advisory database at ${db} is not a clean checkout of ${dbCommit}`);

  const root = mkdtempSync(join(tmpdir(), "wv-advisories-"));
  try {
    exportZkvm(root);
    const crateDir = (dir: string) => join(root, ...dir.split("/"));
    const locks = LOCKFILES.map((l) => {
      const text = readFileSync(join(crateDir(l.dir), "Cargo.lock"), "utf8");
      return { spec: l, text, lock: parseCargoLock(text) };
    });

    // Yanked status: one index file per crate name, every locked registry package checked against it.
    const names = [...new Set(locks.flatMap((l) => registryPackages(l.lock).map((p) => p.name)))].sort();
    const index = new Map<string, Map<string, { cksum: string; yanked: boolean }>>();
    for (let i = 0; i < names.length; i += 16) {
      const batch = names.slice(i, i + 16);
      const files = await Promise.all(batch.map(indexFile));
      batch.forEach((n, j) => index.set(n, indexEntriesOf(files[j], n)));
    }
    const checked = new Set(locks.flatMap((l) => registryPackages(l.lock).map((p) => specOf(p.name, p.version))));

    const lockfiles: ObservedLockfile[] = locks.map(({ spec, text, lock }) => {
      const cwd = crateDir(spec.dir);
      const audit = JSON.parse(
        run(
          "cargo",
          ["audit", "--json", "--no-yanked", "--no-fetch", "--db", db, "--file", join(cwd, "Cargo.lock")],
          cwd,
          [0, 1],
        ).stdout,
      ) as Record<string, any>;
      const used = audit?.database?.["last-commit"];
      if (used !== null && used !== dbCommit) {
        throw new Error(`cargo audit used advisory-db ${String(used)}, not --db's ${dbCommit}`);
      }
      const lf: ObservedLockfile = {
        id: spec.id,
        path: lockPathOf(spec),
        sha256: sha256(text),
        packages: lock.length,
        registryPackages: registryPackages(lock).length,
        audit,
        yanked: yankedPackages(lock, index),
        trees: [],
        features: [],
        updates: [],
        precise: [],
      };
      const findings = measuredFindingsOf(lf, lock);
      const capture = (command: string, accept: readonly number[] = [0], both = false) => {
        const r = run("cargo", argv(command), cwd, accept);
        return normalizeCargoOutput(both ? `${r.stderr}${r.stdout}` : r.stdout, root);
      };
      for (const s of findingSpecs(findings)) {
        lf.trees.push({ spec: s, command: treeCommand(s), output: capture(treeCommand(s)) });
        lf.updates.push({ spec: s, command: updateProbeCommand(s), output: capture(updateProbeCommand(s), [0], true) });
      }
      if (spec.id === "host") {
        for (const c of FEATURE_CRATES) {
          const p = onlyVersion(lock, c);
          if (!p) throw new Error(`zkvm/host/Cargo.lock pins ${c} at other than one version`);
          const s = specOf(p.name, p.version);
          lf.features.push({ spec: s, command: featureTreeCommand(s), output: capture(featureTreeCommand(s)) });
        }
      }
      const updates = new Map(lf.updates.map((u) => [u.spec, u.output]));
      for (const p of precisePlan(findings, (s) => updates.get(s) as string)) {
        const command = preciseProbeCommand(p.spec, p.version);
        lf.precise.push({ ...p, command, output: capture(command, [0, 101], true) });
      }
      return lf;
    });

    // Source facts: each crate's own bytes, from the .crate whose sha256 is the host lockfile's checksum.
    const hostLock = locks[0].lock;
    const sourceFacts: ObservedSourceFact[] = SOURCE_FACTS.map((fact) => ({
      id: fact.id,
      pattern: fact.pattern,
      flags: fact.flags,
      crates: fact.crates.map((name) => {
        const p = onlyVersion(hostLock, name);
        if (!p || !p.checksum) throw new Error(`${fact.id}: zkvm/host/Cargo.lock does not pin ${name} once`);
        const prefix = `${p.name}-${p.version}/`;
        const members = [...readTarMembers(crateBytes(cargoHome, p))]
          .filter(([path]) => path.startsWith(prefix) && memberSelected(fact.select, path.slice(prefix.length)))
          .map(([path, bytes]) => ({
            path: path.slice(prefix.length),
            sha256: sha256(bytes),
            matches: countMatches(fact, bytes.toString("utf8")),
          }))
          .sort((a, b) => a.path.localeCompare(b.path));
        return { crate: p.name, version: p.version, checksum: p.checksum, members };
      }),
    }));

    const hostDb = (lockfiles[0].audit as Record<string, any>).database;
    const observation: AdvisoryObservation = {
      schema: ADVISORY_OBSERVATION_SCHEMA,
      measuredAtUtc: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      host,
      tool: {
        script: MEASURE_ADVISORIES_SCRIPT_REL,
        scriptSha256: sha256(readFileSync(resolve(MEASURE_ADVISORIES_SCRIPT_REL))),
        cargo,
        cargoAudit,
      },
      database: { lastCommit: dbCommit, lastUpdated: dbUpdated, advisoryCount: hostDb["advisory-count"] },
      index: { base: SPARSE_INDEX_BASE, registryPackagesChecked: checked.size },
      lockfiles,
      sourceFacts,
    };
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify(observation, null, 2)}\n`);
    const summary = lockfiles.map((l) => {
      const f = measuredFindingsOf(l, null);
      return `${l.id}: ${f.filter((x) => x.kind === "vulnerability").length} vulnerabilities, ${f.filter((x) => x.kind !== "vulnerability").length} warnings`;
    });
    console.log(`${out}\n  advisory-db ${dbCommit}; ${summary.join("; ")}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
