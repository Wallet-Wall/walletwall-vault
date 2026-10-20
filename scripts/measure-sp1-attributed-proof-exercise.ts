/**
 * SP1-PA3C: the measurement of a FUTURE proof exercise under continuous egress attribution. SP1-PA3C runs no proof;
 * an owner-authorized lane does, and only through the root observer, which is the only thing that may start this tool:
 *
 *   node <root-owned copy>/sp1-egress-observer.ts run --as <user> --repo <this checkout> --table <family> <name> \
 *     --raw-dir <new directory> -- --record <record.json> --circuit-root <absolute dir> --host <absolute path> \
 *     --inputs <absolute path> --host-label <label> --enforcement "<statement>" --out <new file> \
 *     [--proof-out <new file>] [--interval-ms 2000] [--platform-file <file of identity lines>]
 *
 * It does everything scripts/measure-sp1-proof-exercise.ts does (that tool stays byte-identical: SP1-PA3B's run
 * observation binds it) and, around it: refuses unless its stdin opens with a READY for this boot in run mode (a check
 * of form: anything could write that line, and what binds the evidence is the observer's markers, which only root
 * writes, never this check); asks the
 * observer to mark HELLO (this checkout's commit and the host label) and every phase before acting on it, so each
 * marker precedes the act in the trace; registers each gnark container it samples (the observer resolves and marks the
 * container's network namespace); and after the after-probes asks the observer to stop, reads the raw evidence the
 * observer's manifest binds, normalizes it (scripts/lib/sp1-egress-attribution.ts) and writes ONE v2 run observation
 * (walletwall.sp1-proof-exercise-run.v2, never overwritten). If the observer fails or goes away, the host is killed and
 * no observation is written. Its stdout is the control channel: everything it reports goes to stderr. It asserts
 * nothing; the validators decide. Never pulls an image or downloads anything. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { platform, release, arch } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import type { ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";

import { archiveEvidenceState } from "./lib/sp1-circuit-acquisition";
import { refuse } from "./lib/sp1-circuit-archive";
import {
  committedProductionAnchor,
  committedProductionRecord,
  productionArchiveEvidenceOf,
} from "./lib/sp1-circuit-tooling";
import { ObserverClient, normalizeObserverRaw, userDev, type HostExecutable } from "./lib/sp1-egress-attribution";
import {
  ATTRIBUTED_RUN_SCRIPT_REL,
  EGRESS_DISABLED,
  RUN_SCHEMA_V2,
  dockerContainerBytes,
  dockerRunner,
  egressTargets,
  exerciseExpectations,
  fileIdentity,
  linuxHostRssBytes,
  measuringSpawner,
  networkProbeDeps,
  probeEgress,
  scriptSha256Of,
  serializeJson,
  sourceIdentity,
  utcNow,
  type AttributedRunObservation,
} from "./lib/sp1-proof-exercise";
import { FROZEN_ENV, dockerImageDigests, runArchiveOnlyProve, type Spawner } from "./lib/sp1-prove-gate";
import { RAW_FACTS_FILE, RAW_MANIFEST_FILE, RAW_TRACE_FILE } from "./sp1-egress-observer";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const say = (text: string) => process.stderr.write(`${text}\n`);

function arg(name: string, required = true): string | undefined {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (required && (value === undefined || value.startsWith("--"))) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const recordPath = arg("--record") as string;
  const circuitRoot = arg("--circuit-root") as string;
  const hostExecutable = arg("--host") as string;
  const inputsPath = arg("--inputs") as string;
  const hostLabel = arg("--host-label") as string;
  const enforcement = arg("--enforcement") as string;
  const out = arg("--out") as string;
  const proofOut = arg("--proof-out", false);
  const intervalMs = Number(arg("--interval-ms", false) ?? "2000");
  const platformFile = arg("--platform-file", false);
  if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) throw new Error("--interval-ms must be a positive integer");
  // The observer reads an exec's path from its first 128 bytes and names the proof's root only by the whole path, so
  // a path it could not read whole (or would read as other bytes) is refused here, before any act, not after a proof.
  if (!isAbsolute(hostExecutable) || !/^\/[\x21-\x7e]{1,126}$/.test(hostExecutable)) {
    throw new Error(
      "--host must be an absolute path of at most 127 printable ASCII bytes, no space: the observer follows its exec by that path",
    );
  }
  if (process.platform !== "linux") {
    throw refuse(
      "PROVE_HOST_UNSUPPORTED",
      "NOT_LINUX",
      "the attributed measurement needs a Linux host and its observer",
    );
  }
  // The observer started this process, on this boot, in RUN mode; nothing happens before it says so.
  if (process.stdin.isTTY)
    throw new Error("not started by the egress observer: stdin is a terminal (see scripts/sp1-egress-observer.ts run)");
  const client = new ObserverClient(process.stdin, (line) => void process.stdout.write(`${line}\n`));
  const ready = await client.ready();
  const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  if (ready.mode !== "RUN" || ready.bootId !== bootId) {
    throw new Error(
      `the observer is not observing this run (mode ${ready.mode}, boot ${ready.bootId}, this boot ${bootId})`,
    );
  }
  let host: ChildProcess | null = null;
  client.onFail((reason) => {
    say(`the observer failed (${reason}): the run is abandoned and no observation is written`);
    host?.kill("SIGKILL");
  });
  const abort = async (code: string, error: unknown): Promise<never> => {
    try {
      await client.request("ABORT", code);
    } catch {
      // the observer may already be gone; nothing is written either way
    }
    throw error;
  };

  let record: unknown;
  let anchor: ReturnType<typeof committedProductionAnchor>;
  let expect: ReturnType<typeof exerciseExpectations>;
  let source: ReturnType<typeof sourceIdentity>;
  try {
    record = committedProductionRecord(recordPath, REPO);
    anchor = committedProductionAnchor(REPO);
    const archive = productionArchiveEvidenceOf(REPO);
    if (archiveEvidenceState(archive) !== "ACCEPTED") {
      throw new Error(`the archive evidence is not accepted (${archive.errors.join("; ")}): nothing to exercise`);
    }
    expect = exerciseExpectations(REPO, { anchor, archive });
    source = sourceIdentity(REPO);
    if (source.dirty)
      throw new Error("the checkout is not clean: the observation names its HEAD, so commit or discard first");
  } catch (error) {
    return abort("PRECONDITION", error);
  }
  const recordRel = relative(realpathSync(REPO), realpathSync(recordPath)).split(sep).join("/");
  const recordSha256 = sha256(lf(readFileSync(recordPath, "utf8")));
  const gnark = (record as { gnark: { repository: string; digest: string } }).gnark;
  const imageRef = `${gnark.repository}@${gnark.digest}`;
  const targets = egressTargets(expect);
  const probes = networkProbeDeps();
  const exeStat = statSync(hostExecutable, { bigint: true });
  const followed: HostExecutable = { path: hostExecutable, dev: userDev(exeStat.dev), ino: Number(exeStat.ino) };

  await client.request("HELLO", source.commit, hostLabel);
  await client.request("PHASE", "PROBES_BEFORE_BEGIN");
  const before = await probeEgress(targets, probes);
  await client.request("PHASE", "PROBES_BEFORE_END");
  const hostFile = fileIdentity(hostExecutable);
  const inputsFile = fileIdentity(inputsPath);

  // Every gnark container the sampler sees is registered once; the observer marks its namespace (it can read it).
  const docker = dockerRunner(process.env);
  const registered = new Set<string>();
  const sampleBytes = dockerContainerBytes(imageRef, process.env, docker);
  const containerBytes = () => {
    const ps = docker(["ps", "--no-trunc", "--filter", `ancestor=${imageRef}`, "--format", "{{.ID}}"]);
    if (!ps.error && ps.status === 0) {
      for (const id of ps.stdout.split(/\r?\n/).filter((l) => /^[0-9a-f]{64}$/.test(l) && !registered.has(l))) {
        const pid = docker(["inspect", "--format", "{{.State.Pid}}", id]).stdout.trim();
        if (!/^[1-9]\d*$/.test(pid)) continue;
        registered.add(id);
        client.request("CONTAINER", id, pid).catch((e) => client.fail(`CONTAINER_NOT_MARKED: ${(e as Error).message}`));
      }
    }
    return sampleBytes();
  };
  const measured = measuringSpawner({
    intervalMs,
    hostRssBytes: linuxHostRssBytes,
    containerBytes,
    onChild: (child) => {
      host = child;
      if (client.failure !== null) child.kill("SIGKILL");
    },
  });
  const spawner: Spawner = async (plan) => {
    await client.request("PHASE", "HOST_SPAWN");
    try {
      return await measured.spawner(plan);
    } finally {
      host = null;
      await client.request("PHASE", "HOST_EXIT");
    }
  };
  await client.request("PHASE", "GATE_BEGIN");
  const startedAtUtc = utcNow();
  const t0 = process.hrtime.bigint();
  const { plan, output } = await runArchiveOnlyProve(
    { record: record as never, anchor, circuitRoot, hostExecutable, inputsPath, callerEnv: process.env },
    { images: dockerImageDigests, spawn: spawner },
  );
  const gateSeconds = Number((process.hrtime.bigint() - t0 + 999_999_999n) / 1_000_000_000n);
  const finishedAtUtc = utcNow();
  await client.request("PHASE", "GATE_END");
  await client.request("PHASE", "PROBES_AFTER_BEGIN");
  const after = await probeEgress(targets, probes);
  await client.request("PHASE", "PROBES_AFTER_END");
  const stopped = await client.stop();

  // The raw evidence, exactly as the observer's manifest binds it, normalized deterministically.
  const read = (name: string) => readFileSync(join(stopped.rawDir, name), "latin1");
  const manifest = read(RAW_MANIFEST_FILE);
  if (sha256(Buffer.from(manifest, "latin1")) !== stopped.manifestSha256) {
    throw new Error(
      "the raw manifest is not the one the observer named: the raw evidence changed after the observer stopped",
    );
  }
  const observer = normalizeObserverRaw(
    { trace: read(RAW_TRACE_FILE), facts: read(RAW_FACTS_FILE), manifest },
    followed,
  );
  const m = measured.measurement();
  const localRepoDigests = dockerImageDigests(plan.imageRef, plan.env) ?? [];
  const frozen = new Set<string>(FROZEN_ENV);
  const allRefused = [...before, ...after].every((p) => p.outcome === "REFUSED");
  const publicValues = Buffer.from(output.publicValues.slice(2), "hex");
  const proofBytes = Buffer.from(output.proofBytes.slice(2), "hex");
  const observation: AttributedRunObservation = {
    schema: RUN_SCHEMA_V2,
    host: hostLabel,
    measuredAtUtc: utcNow(),
    tool: { script: ATTRIBUTED_RUN_SCRIPT_REL, scriptSha256: scriptSha256Of(import.meta.url) },
    source: { repository: source.repository, commit: source.commit, zkvmHostTree: source.zkvmHostTree },
    anchor,
    archiveRecord: { path: recordRel, sha256: recordSha256 },
    installedCircuit: {
      root: circuitRoot,
      circuitVersion: anchor.circuitVersion,
      members: plan.record.members.map((x) => ({ path: x.path, bytes: x.bytes, sha256: x.sha256 })),
    },
    hostExecutable: hostFile,
    inputs: inputsFile,
    gnark: {
      repository: plan.record.gnark.repository,
      digest: plan.record.gnark.digest,
      imageRef: plan.imageRef,
      localRepoDigests,
    },
    prover: {
      mode: plan.env.SP1_PROVER as "cpu",
      frozenEnv: Object.fromEntries(Object.entries(plan.env).filter(([k]) => frozen.has(k))),
      passedThrough: Object.keys(plan.env)
        .filter((k) => !frozen.has(k))
        .sort(),
      dropped: plan.dropped,
    },
    egress: { enforcement, before, after, condition: allRefused ? EGRESS_DISABLED : "EGRESS_NOT_REFUSED", observer },
    timing: {
      startedAtUtc,
      finishedAtUtc,
      gateSeconds,
      hostStartedAtUtc: m.hostStartedAtUtc,
      hostFinishedAtUtc: m.hostFinishedAtUtc,
      hostSeconds: m.hostSeconds,
    },
    peakMemory: {
      hostProcess: {
        bytes: m.hostPeakRssBytes ?? 0,
        method: `/proc/<pid>/status VmHWM of the host process, polled every ${intervalMs} ms and at exit (the kernel's high-water mark)`,
      },
      gnarkContainers: {
        bytes: m.containerPeakBytes ?? 0,
        samples: m.containerSamples,
        intervalMs,
        method: `docker stats --no-stream MemUsage of the running containers whose ancestor is ${imageRef}, summed, polled every ${intervalMs} ms (a sampled lower bound of the peak)`,
      },
    },
    proof: {
      vkey: output.vkey,
      publicValues: output.publicValues,
      proofBytes: output.proofBytes,
      selector: output.proofBytes.slice(0, 10),
      publicValuesSha256: sha256(publicValues),
      proofBytesSha256: sha256(proofBytes),
    },
    platform: [
      `host=${hostLabel}`,
      `os=${platform()} ${release()} ${arch()}`,
      `node=${process.version}`,
      `bootId=${bootId}`,
      ...(platformFile
        ? readFileSync(platformFile, "utf8")
            .split(/\r?\n/)
            .filter((l) => l.trim() !== "")
        : []),
    ],
  };
  const files: [string, string][] = [[out, serializeJson(observation)]];
  if (proofOut) files.push([proofOut, `${JSON.stringify(output, null, 2)}\n`]);
  writeNewFiles(files, "an observation is never overwritten");
  say(
    `${out}: gate ${gateSeconds} s (host ${m.hostSeconds} s), egress ${observation.egress.condition}, ${observer.events.length} observed events (raw evidence ${stopped.rawDir}, manifest ${stopped.manifestSha256}); the proof names ${output.vkey}. Commit this observation, then verify it (npm run sp1:verify-proof-exercise).`,
  );
});
