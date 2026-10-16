/**
 * Compare canonical builds with the designation (scripts/lib/sp1-canonical-build.ts); used by
 * .github/workflows/sp1-canonical-build.yml and to record a local rebuild.
 *
 * Usage:
 *   npx tsx scripts/check-sp1-canonical-build.ts --build <host-id>=<driver-output-dir> [--build ...]
 *     --recompute <outside-recompute-record> --min-hosts <n> [--designation <id>] [--write <observation.json>]
 *
 * Exits non-zero unless the verdict is REPRODUCED. Reads files only; no network, no transactions.
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  CANONICAL_BUILD_SCHEMA,
  COMMON_MODE,
  canonicalBuildErrors,
  canonicalBuildVerdict,
  collectBuild,
  parseVkeyRecompute,
  type CanonicalBuildObservation,
} from "./lib/sp1-canonical-build";
import { latestDesignation, readDesignations } from "./lib/sp1-designation";

function args(name: string): string[] {
  const out: string[] = [];
  process.argv.forEach((a, i) => {
    if (a === name && process.argv[i + 1] !== undefined) out.push(process.argv[i + 1]);
  });
  return out;
}

try {
  const designations = readDesignations();
  const wanted = args("--designation")[0] ?? latestDesignation(designations)?.id;
  const d = designations.find((x) => x.id === wanted);
  if (!d) throw new Error(`no designation ${String(wanted)}`);
  const builds = args("--build").map((spec) => {
    const at = spec.indexOf("=");
    if (at <= 0) throw new Error(`--build takes <host-id>=<dir>, not ${spec}`);
    return collectBuild(resolve(spec.slice(at + 1)), spec.slice(0, at), d.procedure);
  });
  const records = args("--recompute").map((file) => parseVkeyRecompute(readFileSync(resolve(file), "utf8")));
  if (records.length === 0) {
    throw new Error("--recompute <record> is required: the vkey is recomputed outside the build");
  }
  if (new Set(records.map((r) => r.toolSha256)).size !== 1) {
    throw new Error("the outside recomputes ran different cargo-prove binaries: record them as separate observations");
  }
  const minimumHosts = Number(args("--min-hosts")[0] ?? "2");
  const observation: CanonicalBuildObservation = {
    schema: CANONICAL_BUILD_SCHEMA,
    measuredAtUtc: new Date().toISOString(),
    designation: d.id,
    builds,
    vkeyRecompute: { ...records[0], results: records.flatMap((r) => r.results) },
    commonMode: COMMON_MODE,
  };
  const out = args("--write")[0];
  if (out !== undefined) {
    mkdirSync(dirname(resolve(out)), { recursive: true });
    writeFileSync(resolve(out), `${JSON.stringify(observation, null, 2)}\n`);
    console.log(`wrote ${out}`);
  }
  const verdict = canonicalBuildVerdict(observation, d, { minimumHosts });
  const errors = canonicalBuildErrors(observation, d, { minimumHosts });
  console.log(`CANONICAL_BUILD_STATUS=${verdict} (${builds.map((b) => b.hostId).join(", ")}; designation ${d.id})`);
  if (verdict !== "REPRODUCED") {
    throw new Error(`${verdict === "PROGRAM_IDENTITY_DRIFT" ? "STOP: " : ""}${verdict}:\n - ${errors.join("\n - ")}`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
