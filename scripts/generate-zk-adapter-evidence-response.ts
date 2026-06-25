/**
 * Generate (and validate) the committed ZK adapter evidence endpoint example.
 *
 * The example at evidence/zk/zk-adapter-evidence-response.example.json is the
 * deterministic 200 success response a hosted, READ-ONLY ZK-adapter evidence
 * endpoint would return: the committed ZK verifier adapter boundary
 * (evidence/zk/zk-verifier-adapter.json) wrapped with `servedAt` + a strong
 * `etag` (keccak256 of the adapter) so the private app can cache and
 * conditionally re-fetch.
 *
 * Every field except the fixed `servedAt` is a pure function of the committed
 * adapter, so regenerating yields a byte-identical example.
 * `test/ZKAdapterEvidenceEndpoint.test.ts` re-derives this and asserts the
 * committed file matches, so it can never silently drift.
 *
 * Usage:
 *   npm run zk:adapter:response   # (re)write the committed example response
 *   npm run validate:zk-response  # validate the committed example, exit non-zero if invalid
 *
 * No server, no network listener, no transactions, no deploys, no proving.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { type ZKVerifierAdapter } from "./lib/zk-verifier-adapter";
import {
  buildAdapterEvidenceResponse,
  computeAdapterETag,
  handleAdapterEvidenceRequest,
  validateAdapterEvidenceResponse,
  type ZKAdapterEvidenceResponse,
} from "./lib/zk-adapter-endpoint";

/** Fixed instant so the committed example is deterministic. */
export const EXAMPLE_SERVED_AT = "2026-01-01T00:00:00.000Z";

export const RESPONSE_DIR = resolve("evidence/zk");
export const RESPONSE_PATH = resolve(RESPONSE_DIR, "zk-adapter-evidence-response.example.json");

/** Repo-relative path to the committed adapter this endpoint serves. */
const ADAPTER_REL = "evidence/zk/zk-verifier-adapter.json";

/** Load the committed ZK verifier adapter boundary. */
export function loadCommittedAdapter(): ZKVerifierAdapter {
  return JSON.parse(readFileSync(resolve(ADAPTER_REL), "utf8")) as ZKVerifierAdapter;
}

/** Build the committed example response deterministically. */
export function buildExampleResponse(): ZKAdapterEvidenceResponse {
  return buildAdapterEvidenceResponse(loadCommittedAdapter(), {
    servedAt: EXAMPLE_SERVED_AT,
    command: "npm run zk:adapter:response",
  });
}

function writeResponse(): void {
  mkdirSync(RESPONSE_DIR, { recursive: true });
  writeFileSync(RESPONSE_PATH, `${JSON.stringify(buildExampleResponse(), null, 2)}\n`);
  console.log(`Wrote ${RESPONSE_PATH}`);
}

function validateCommitted(): void {
  const onDisk = JSON.parse(readFileSync(RESPONSE_PATH, "utf8")) as ZKAdapterEvidenceResponse;

  const { valid, errors } = validateAdapterEvidenceResponse(onDisk);
  if (!valid) {
    throw new Error(`committed ZK adapter evidence response is invalid:\n - ${errors.join("\n - ")}`);
  }

  // The served adapter must equal the committed adapter on disk (the response can
  // never serve a stale or divergent adapter), and the etag must match it.
  const committedAdapter = loadCommittedAdapter();
  if (JSON.stringify(onDisk.adapter) !== JSON.stringify(committedAdapter)) {
    throw new Error("committed response serves an adapter that differs from evidence/zk/zk-verifier-adapter.json");
  }
  if (onDisk.etag !== computeAdapterETag(committedAdapter)) {
    throw new Error("committed response etag does not match the committed adapter");
  }

  // A conditional GET with the current etag must produce 304 (caching contract).
  const conditional = handleAdapterEvidenceRequest({ method: "GET", ifNoneMatch: onDisk.etag }, committedAdapter, {
    now: EXAMPLE_SERVED_AT,
  });
  if (conditional.status !== 304) {
    throw new Error(`conditional GET with the current etag must return 304, got ${conditional.status}`);
  }

  // Drift check: the committed file must equal a freshly built example.
  if (JSON.stringify(onDisk) !== JSON.stringify(buildExampleResponse())) {
    throw new Error(
      "committed ZK adapter evidence response has drifted from the generator; run `npm run zk:adapter:response`",
    );
  }

  console.log(
    `OK: ${RESPONSE_PATH} is valid, serves the committed adapter (etag matches, 304 works), and matches the generator (no drift).`,
  );
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeResponse();
  }
}

if (process.argv[1]?.includes("generate-zk-adapter-evidence-response")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
