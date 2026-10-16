/**
 * Compare canonical builds with the designation (scripts/lib/sp1-canonical-build.ts); used by
 * .github/workflows/sp1-canonical-build.yml and to record a local rebuild.
 *
 * Usage:
 *   npx tsx scripts/check-sp1-canonical-build.ts --build <host-id>=<driver-output-dir> [--build ...]
 *     --recompute <outside-recompute-record> [--recompute ...] --min-hosts <n> [--designation <id>]
 *     [--records <dir>]
 *
 * The observation is derived from the driver's records and the recompute records alone, and names this tree's driver
 * and checker by sha256. --records writes it as <dir>.raw.json, with the records it was derived from under <dir>/
 * (builds/<host-id>/, vkey-recompute/): the committed evidence's layout, which canonicalRebuildEvidenceErrors
 * re-derives. Exits non-zero unless the verdict is REPRODUCED (after writing, so a failure keeps its evidence). Reads
 * files only; no network, no transactions.
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";

import {
  canonicalBuildErrors,
  canonicalBuildVerdict,
  canonicalToolDigests,
  collectBuild,
  deriveCanonicalObservation,
  parseVkeyRecompute,
  writeCanonicalRecords,
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
  const minimumHosts = Number(args("--min-hosts")[0] ?? "2");
  if (!Number.isInteger(minimumHosts) || minimumHosts < 1) {
    throw new Error(`--min-hosts takes a positive integer, not ${args("--min-hosts")[0]}`);
  }
  const builds = args("--build").map((spec) => {
    const at = spec.indexOf("=");
    if (at <= 0) throw new Error(`--build takes <host-id>=<dir>, not ${spec}`);
    return { hostId: spec.slice(0, at), dir: resolve(spec.slice(at + 1)) };
  });
  const recomputeFiles = args("--recompute")
    .map((file) => resolve(file))
    .sort((a, b) => basename(a).localeCompare(basename(b)));
  const observation = deriveCanonicalObservation({
    designation: d.id,
    builds: builds.map((b) => collectBuild(b.dir, b.hostId)),
    recomputes: recomputeFiles.map((file) => parseVkeyRecompute(readFileSync(file, "utf8"))),
    tools: canonicalToolDigests("."),
  });
  const records = args("--records")[0];
  if (records !== undefined) {
    const dir = resolve(records);
    writeCanonicalRecords(dir, builds, recomputeFiles);
    mkdirSync(dirname(dir), { recursive: true });
    writeFileSync(`${dir}.raw.json`, `${JSON.stringify(observation, null, 2)}\n`);
    console.log(`wrote ${records}.raw.json, derived from the records under ${records}/`);
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
