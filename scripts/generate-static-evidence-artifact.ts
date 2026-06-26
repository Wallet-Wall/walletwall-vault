/**
 * Generate (and validate) the committed Option A static hosted evidence artifact.
 *
 * Option A (see docs/Hosted_Evidence_Endpoint_Target_Decision.md) serves the
 * pre-committed `walletwall.zk-adapter-evidence-response.v1` example
 * (evidence/zk/zk-adapter-evidence-response.example.json) byte-for-byte from a
 * stable, versioned static path. This script materializes that static artifact at
 * the versioned path evidence/zk/hosted/v1/zk-adapter-evidence-response.json and
 * proves, offline, that it is a faithful, valid, ETag-correct copy served from a
 * versioned path.
 *
 * It PUBLISHES NOTHING. It writes only a committed local file. There is no server,
 * no network listener, no GitHub Pages deploy, no CDN upload, no transaction, no
 * deploy, no proving, no chain call, and no secret/credential/key access. Going
 * live remains gated behind the security-review gate in the target-decision doc.
 *
 * Usage:
 *   npm run static:artifact          # (re)write the committed static artifact
 *   npm run validate:static-artifact # validate the committed artifact; exit non-zero if invalid
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  computeAdapterETag,
  validateAdapterEvidenceResponse,
  type ZKAdapterEvidenceResponse,
} from "./lib/zk-adapter-endpoint";
import { RESPONSE_PATH, buildExampleResponse } from "./generate-zk-adapter-evidence-response";

/** Versioned static-hosting path component (Option A control: versioned path). */
export const STATIC_VERSION = "v1";

/** Repo-relative path of the committed static hosted evidence artifact. */
export const STATIC_ARTIFACT_REL = `evidence/zk/hosted/${STATIC_VERSION}/zk-adapter-evidence-response.json`;
export const STATIC_ARTIFACT_PATH = resolve(STATIC_ARTIFACT_REL);

/**
 * The committed canonical example whose bytes a static host would serve verbatim.
 * Owned by the TypeScript `zk:adapter:response` generator / `validate:zk-response`.
 */
export const CANONICAL_PATH = RESPONSE_PATH;

function readRaw(path: string): string {
  return readFileSync(path, "utf8");
}

/** The exact bytes a static host would serve: the canonical example, verbatim. */
export function buildStaticArtifactBytes(): string {
  return readRaw(CANONICAL_PATH);
}

function writeArtifact(): void {
  mkdirSync(dirname(STATIC_ARTIFACT_PATH), { recursive: true });
  writeFileSync(STATIC_ARTIFACT_PATH, buildStaticArtifactBytes());
  console.log(`Wrote ${STATIC_ARTIFACT_PATH}`);
}

function validateCommitted(): void {
  const staticRaw = readRaw(STATIC_ARTIFACT_PATH);
  const canonicalRaw = readRaw(CANONICAL_PATH);

  // Control — exact artifact: the static artifact must be byte-for-byte the
  // committed canonical example. The static host serves the committed file as-is;
  // it must never serve a divergent or stale copy.
  if (staticRaw !== canonicalRaw) {
    throw new Error(
      `static hosted artifact has drifted from the canonical example; run \`npm run static:artifact\` ` +
        `(${STATIC_ARTIFACT_REL} must be byte-for-byte ${CANONICAL_PATH})`,
    );
  }

  const onDisk = JSON.parse(staticRaw) as ZKAdapterEvidenceResponse;

  // The static artifact must itself be a valid zk-adapter-evidence-response.v1
  // (shape, embedded-adapter validity, limitations coverage, no overclaim, etc.).
  const { valid, errors } = validateAdapterEvidenceResponse(onDisk);
  if (!valid) {
    throw new Error(`static hosted evidence artifact is invalid:\n - ${errors.join("\n - ")}`);
  }

  // Control — ETag provenance: the etag must be keccak256 of the served adapter.
  if (onDisk.etag !== computeAdapterETag(onDisk.adapter)) {
    throw new Error("static hosted artifact etag is not keccak256 of its served adapter");
  }

  // Control — versioned path: the published path must carry a version segment so a
  // stale consumer can detect version drift.
  if (!/(^|\/)v\d+\//.test(STATIC_ARTIFACT_REL)) {
    throw new Error(`static hosted artifact path must include a version segment: ${STATIC_ARTIFACT_REL}`);
  }

  // Drift: cross-check against the canonical generator-of-record, so the static
  // artifact can never silently diverge from what `zk:adapter:response` produces.
  if (JSON.stringify(onDisk) !== JSON.stringify(buildExampleResponse())) {
    throw new Error(
      "static hosted artifact does not match the canonical generator; run `npm run zk:adapter:response` then `npm run static:artifact`",
    );
  }

  console.log(
    `OK: ${STATIC_ARTIFACT_PATH} is byte-identical to the canonical example, is a valid ` +
      `zk-adapter-evidence-response.v1, its etag is keccak256 of its adapter, and it is served from a ` +
      `versioned path. Publishes nothing (no server, no network, no deploy).`,
  );
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeArtifact();
  }
}

if (process.argv[1]?.includes("generate-static-evidence-artifact")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
