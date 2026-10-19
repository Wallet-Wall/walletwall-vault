/**
 * SP1-PA2B: measures one host's acquired copy of SP1's Groth16 circuit archive and writes the host's acquisition
 * observation (scripts/lib/sp1-circuit-acquisition.ts). The copy was acquired by other means (curl); this tool never
 * downloads it, never extracts it and never runs SP1.
 *
 *   npx tsx scripts/measure-sp1-circuit-acquisition.ts --archive <file.tar.gz> --host <label> \
 *     --transfer <curl -w json> --headers <curl -D file> --started-at <UTC> --finished-at <UTC> \
 *     --digest <tool>=<sha256 | @file> [--digest ...] --gnark-image <registry/repository:tag> \
 *     [--gnark-raw-index <file>] (--platform <line> | --platform-file <file>) ... --out <new file> \
 *     [--census-out <new file>]
 *
 * It inspects the copy with the merged PA2A inspector in measuring mode (every entry rule, the required members,
 * designation d1's verifying key; the anchor read from the committed evidence of the checkout this script lives in),
 * runs the read-only census and records its sha256, records the transfer's provenance (URL, status, window, response
 * headers) and the host's independent digests of the same bytes, and resolves the gnark image tag to its immutable
 * digest from the registry (manifests only, never a pull). A copy the inspector refuses is recorded as refused and the
 * tool exits 1. The observation is created once (never overwritten). Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import { fileURLToPath } from "node:url";

import { CircuitToolingError, inspectArchive } from "./lib/sp1-circuit-archive";
import { censusArchive } from "./lib/sp1-circuit-archive-census";
import {
  ACQUISITION_SCHEMA,
  ACQUISITION_SCRIPT_REL,
  resolveImageTag,
  serializeJson,
  type AcquisitionObservation,
  type TransferProvenance,
} from "./lib/sp1-circuit-acquisition";
import { committedProductionAnchor } from "./lib/sp1-circuit-tooling";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

function args(name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === name) {
      const v = process.argv[i + 1];
      if (v === undefined || v.startsWith("--")) throw new Error(`${name} needs a value`);
      out.push(v);
    }
  }
  return out;
}
function arg(name: string, required = true): string | undefined {
  const all = args(name);
  if (all.length > 1) throw new Error(`${name} given more than once`);
  if (required && all.length === 0) throw new Error(`${name} is required`);
  return all[0];
}

/** `tool=<64 hex>` or `tool=@file` (the first 64-hex token of the file). */
function digestArg(spec: string): { tool: string; sha256: string } {
  const eq = spec.indexOf("=");
  if (eq <= 0) throw new Error(`--digest ${spec}: expected <tool>=<sha256 | @file>`);
  const tool = spec.slice(0, eq);
  const value = spec.slice(eq + 1);
  const text = value.startsWith("@") ? readFileSync(value.slice(1), "utf8") : value;
  const hex = /\b([0-9a-f]{64})\b/i.exec(text)?.[1]?.toLowerCase();
  if (!hex) throw new Error(`--digest ${spec}: no sha256 found`);
  return { tool, sha256: hex };
}

/** curl -D output: the LAST status line's headers (redirects write several blocks). */
function responseHeaders(text: string): TransferProvenance["responseHeaders"] {
  const blocks = text
    .replace(/\r/g, "")
    .split(/\n(?=HTTP\/)/)
    .filter((b) => b.trim() !== "");
  const last = blocks[blocks.length - 1] ?? "";
  const get = (name: string): string | null => {
    const m = new RegExp(`^${name}:[ \\t]*(.*)$`, "im").exec(last);
    return m ? m[1].trim() : null;
  };
  const length = get("Content-Length");
  return {
    lastModified: get("Last-Modified"),
    etag: get("ETag"),
    contentLength: length === null ? null : Number(length),
    server: get("Server"),
  };
}

runScript(async () => {
  const archivePath = arg("--archive") as string;
  const host = arg("--host") as string;
  const transfer = JSON.parse(readFileSync(arg("--transfer") as string, "utf8")) as Record<string, unknown>;
  const headers = readFileSync(arg("--headers") as string, "utf8");
  const digests = args("--digest").map(digestArg);
  const image = arg("--gnark-image") as string;
  const rawIndex = arg("--gnark-raw-index", false);
  const platformLines = [
    ...args("--platform"),
    ...args("--platform-file").flatMap((f) =>
      readFileSync(f, "utf8")
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l !== ""),
    ),
  ];
  if (platformLines.length === 0)
    platformLines.push(`os=${platform()} ${release()} ${arch()}`, `node=${process.version}`);
  const out = arg("--out") as string;
  const file = archivePath.split(/[\\/]/).pop() as string;

  const anchor = committedProductionAnchor(REPO);
  const provenance: TransferProvenance = {
    sourceUrl: String(arg("--source-url", false) ?? transfer.url_effective),
    urlEffective: String(transfer.url_effective),
    httpCode: Number(transfer.http_code),
    remoteIp: String(transfer.remote_ip),
    timeTotalSeconds: Number(transfer.time_total),
    startedAtUtc: arg("--started-at") as string,
    finishedAtUtc: arg("--finished-at") as string,
    responseHeaders: responseHeaders(headers),
  };

  let inspection: AcquisitionObservation["inspection"] | null = null;
  let archive: AcquisitionObservation["archive"] | null = null;
  let refusal: string | null = null;
  try {
    const i = await inspectArchive(archivePath, { anchor });
    archive = { file, bytes: i.archive.bytes, sha256: i.archive.sha256 };
    inspection = { members: i.members, directories: i.directories, metadata: i.metadata, provenance: i.provenance };
  } catch (error) {
    if (!(error instanceof CircuitToolingError)) throw error;
    refusal = `${error.code} (${error.reason}): ${error.message}`;
  }
  const census = await censusArchive(archivePath);
  if (archive === null) archive = { file, bytes: census.archive.bytes, sha256: census.archive.sha256 };
  const censusOut = arg("--census-out", false);
  if (censusOut) writeNewFiles([[censusOut, serializeJson(census)]], "a census is never overwritten");
  const gnarkAt = utcNow();
  const gnark = await resolveImageTag(image);
  const observation = {
    schema: ACQUISITION_SCHEMA,
    host,
    measuredAtUtc: utcNow(),
    tool: { script: ACQUISITION_SCRIPT_REL, scriptSha256: sha256(readFileSync(fileURLToPath(import.meta.url))) },
    anchor,
    archive,
    transfer: provenance,
    independentDigests: digests,
    inspection,
    ...(refusal === null ? {} : { refusal }),
    census: {
      schema: census.schema,
      sha256: sha256(serializeJson(census)),
      entries: census.tar.entries,
      decompressedBytes: census.tar.decompressedBytes,
      appleDoubleEntries: census.appleDouble.length,
    },
    gnark: {
      ...gnark,
      crossCheck:
        rawIndex === undefined
          ? null
          : { tool: "docker buildx imagetools inspect --raw", indexSha256: sha256(readFileSync(rawIndex)) },
      observedAtUtc: gnarkAt,
    },
    platform: platformLines,
  };
  writeNewFiles([[out, serializeJson(observation)]], "an observation is never overwritten");
  console.log(
    `${out}: ${host} measured ${archive.bytes} bytes, sha256 ${archive.sha256}; ` +
      (inspection === null
        ? `the inspector REFUSED the copy: ${refusal}`
        : `${inspection.members.length} members, ${inspection.metadata.length} AppleDouble entries and ${inspection.provenance.length} provenance records ignored`) +
      `; census ${observation.census.sha256}; ${image} -> ${gnark.index.digest}`,
  );
  if (refusal !== null) process.exitCode = 1;
});
