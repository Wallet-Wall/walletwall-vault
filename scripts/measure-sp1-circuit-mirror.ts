/**
 * SP1-PA2B: re-reads one WalletWall-controlled mirror of the circuit archive byte for byte and writes a mirror
 * observation (scripts/lib/sp1-circuit-acquisition.ts). A mirror counts only when the bytes it serves are exactly the
 * canonical archive; this tool measures that once, at the time it runs. It is not continuous availability.
 *
 *   npx tsx scripts/measure-sp1-circuit-mirror.ts --location <as the record names it> --url <https URL to read> \
 *     [--auth-env <NAME of an environment variable holding a bearer token>] --control "<who controls it>" \
 *     --host <label> --expect-bytes <N> --expect-sha256 <hex> --out <new file>
 *
 * The URL's query string (a signed URL's signature) and any token are never recorded: only the host and path. The
 * bytes are hashed as they stream and never written to disk. The observation is created once. Research prototype.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { AGREES } from "./lib/sp1-circuit-archive";
import { MIRROR_SCHEMA, MIRROR_SCRIPT_REL, serializeJson, type MirrorObservation } from "./lib/sp1-circuit-acquisition";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

function arg(name: string, required = true): string | undefined {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (required && (value === undefined || value.startsWith("--"))) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const location = arg("--location") as string;
  const url = new URL(arg("--url") as string);
  if (url.protocol !== "https:") throw new Error("--url must be https");
  const authEnv = arg("--auth-env", false);
  const control = arg("--control") as string;
  const host = arg("--host") as string;
  const expected = { bytes: Number(arg("--expect-bytes")), sha256: String(arg("--expect-sha256")).toLowerCase() };
  if (!Number.isSafeInteger(expected.bytes) || expected.bytes <= 0 || !/^[0-9a-f]{64}$/.test(expected.sha256)) {
    throw new Error("--expect-bytes and --expect-sha256 must be the canonical archive's length and sha256");
  }
  const out = arg("--out") as string;
  const headers: Record<string, string> = {};
  if (authEnv) {
    const token = process.env[authEnv];
    if (!token) throw new Error(`${authEnv} is not set`);
    headers.Authorization = `Bearer ${token}`;
  }
  const startedAtUtc = utcNow();
  const r = await fetch(url, { headers, redirect: "error" });
  const hash = createHash("sha256");
  let bytes = 0;
  if (r.body) {
    for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
      hash.update(chunk);
      bytes += chunk.length;
    }
  }
  const finishedAtUtc = utcNow();
  const digest = hash.digest("hex");
  const length = r.headers.get("content-length");
  const agrees = r.status === 200 && bytes === expected.bytes && digest === expected.sha256;
  const observation: MirrorObservation = {
    schema: MIRROR_SCHEMA,
    host,
    measuredAtUtc: utcNow(),
    tool: { script: MIRROR_SCRIPT_REL, scriptSha256: sha256(readFileSync(fileURLToPath(import.meta.url))) },
    location,
    control,
    fetch: {
      urlHost: url.host,
      urlPath: url.pathname,
      httpCode: r.status,
      startedAtUtc,
      finishedAtUtc,
      responseHeaders: {
        lastModified: r.headers.get("last-modified"),
        etag: r.headers.get("etag"),
        contentLength: length === null ? null : Number(length),
      },
    },
    bytes,
    sha256: digest,
    expected,
    agreement: agrees ? AGREES : "DISAGREES",
  };
  writeNewFiles([[out, serializeJson(observation)]], "an observation is never overwritten");
  console.log(`${out}: ${location} served ${bytes} bytes, sha256 ${digest}: ${observation.agreement}`);
  if (!agrees) process.exitCode = 1;
});
