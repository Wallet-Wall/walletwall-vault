/**
 * SP1-PA3B's measurement of the one real self-hosted proof exercise (built by SP1-PA3A, which ran no proof).
 *
 *   npm run sp1:measure-proof-exercise -- --record <record.json> --circuit-root <absolute dir> \
 *     --host <absolute path to the built mldsa65-host> --inputs <absolute path to inputs.json> \
 *     --host-label <label> --enforcement "<how egress is disabled on this host>" --out <new file> \
 *     [--proof-out <new file>] [--interval-ms 2000] [--platform-file <file of identity lines>]
 *
 * Linux only (the gate locks the circuit root on POSIX; /proc gives the host's peak RSS). It refuses before any act
 * unless the record is a production record exactly as committed and the checkout is clean; then it probes egress
 * (name resolution and TCP 443 at the archive's upstream host and the image registry), runs the UNCHANGED archive-only
 * gate (scripts/lib/sp1-prove-gate.ts runArchiveOnlyProve, every check of sp1:prove:archive-only) through a spawner
 * that measures the host's wall time, its peak RSS and the gnark containers' sampled memory, probes egress again, and
 * writes ONE run observation (never overwritten). It asserts nothing: the record is derived later from this
 * observation and the designated verifier's (scripts/verify-sp1-proof-exercise.ts), and the validators decide.
 * Never pulls an image or downloads anything. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { platform, release, arch } from "node:os";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { archiveEvidenceState } from "./lib/sp1-circuit-acquisition";
import { refuse } from "./lib/sp1-circuit-archive";
import {
  committedProductionAnchor,
  committedProductionRecord,
  productionArchiveEvidenceOf,
} from "./lib/sp1-circuit-tooling";
import {
  EGRESS_DISABLED,
  RUN_SCHEMA,
  RUN_SCRIPT_REL,
  dockerContainerBytes,
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
  type RunObservation,
} from "./lib/sp1-proof-exercise";
import { FROZEN_ENV, dockerImageDigests, runArchiveOnlyProve } from "./lib/sp1-prove-gate";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");

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
  if (process.platform !== "linux") {
    throw refuse(
      "PROVE_HOST_UNSUPPORTED",
      "NOT_LINUX",
      "the measurement needs a Linux host: /proc for the host's peak RSS, and the gate's POSIX lock",
    );
  }
  const record = committedProductionRecord(recordPath, REPO);
  const anchor = committedProductionAnchor(REPO);
  const archive = productionArchiveEvidenceOf(REPO);
  if (archiveEvidenceState(archive) !== "ACCEPTED") {
    throw new Error(`the archive evidence is not accepted (${archive.errors.join("; ")}): nothing to exercise`);
  }
  const expect = exerciseExpectations(REPO, { anchor, archive });
  const source = sourceIdentity(REPO);
  if (source.dirty)
    throw new Error("the checkout is not clean: the observation names its HEAD, so commit or discard first");
  const recordRel = relative(realpathSync(REPO), realpathSync(recordPath)).split(sep).join("/");
  const recordSha256 = sha256(lf(readFileSync(recordPath, "utf8")));
  const imageRef = `${(record as { gnark: { repository: string; digest: string } }).gnark.repository}@${(record as { gnark: { digest: string } }).gnark.digest}`;
  const targets = egressTargets(expect);
  const probes = networkProbeDeps();

  const before = await probeEgress(targets, probes);
  const hostFile = fileIdentity(hostExecutable);
  const inputsFile = fileIdentity(inputsPath);
  const measured = measuringSpawner({
    intervalMs,
    hostRssBytes: linuxHostRssBytes,
    containerBytes: dockerContainerBytes(imageRef, process.env),
  });
  const startedAtUtc = utcNow();
  const t0 = process.hrtime.bigint();
  const { plan, output } = await runArchiveOnlyProve(
    { record, anchor, circuitRoot, hostExecutable, inputsPath, callerEnv: process.env },
    { images: dockerImageDigests, spawn: measured.spawner },
  );
  const gateSeconds = Number((process.hrtime.bigint() - t0 + 999_999_999n) / 1_000_000_000n);
  const finishedAtUtc = utcNow();
  const after = await probeEgress(targets, probes);
  const m = measured.measurement();
  const localRepoDigests = dockerImageDigests(plan.imageRef, plan.env) ?? [];
  const frozen = new Set<string>(FROZEN_ENV);
  const allRefused = [...before, ...after].every((p) => p.outcome === "REFUSED");
  const publicValues = Buffer.from(output.publicValues.slice(2), "hex");
  const proofBytes = Buffer.from(output.proofBytes.slice(2), "hex");
  const observation: RunObservation = {
    schema: RUN_SCHEMA,
    host: hostLabel,
    measuredAtUtc: utcNow(),
    tool: { script: RUN_SCRIPT_REL, scriptSha256: scriptSha256Of(import.meta.url) },
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
    egress: { enforcement, before, after, condition: allRefused ? EGRESS_DISABLED : "EGRESS_NOT_REFUSED" },
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
  console.log(
    `${out}: gate ${gateSeconds} s (host ${m.hostSeconds} s), host peak RSS ${m.hostPeakRssBytes ?? "unmeasured"} B, containers ${m.containerPeakBytes ?? "unmeasured"} B over ${m.containerSamples} samples, egress ${observation.egress.condition}; the proof names ${output.vkey}. Commit this observation, then verify it (npm run sp1:verify-proof-exercise).`,
  );
});
