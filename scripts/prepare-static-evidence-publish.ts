/**
 * Prepare the Option A static hosted evidence artifact for a reviewed static publish.
 *
 * This stages — into a controlled, gitignored directory — ONLY the single committed
 * static artifact that a host may serve under Option A
 * (docs/Static_Hosted_Evidence_Publishing_Controls.md). It is the
 * copy-only-the-validated-checked-in-bytes step the publishing controls require: the
 * publish step has no authority to regenerate, edit, or "fix" the artifact, so this
 * script never generates evidence — it copies the checked-in file verbatim and then
 * verifies the staged bytes are byte-for-byte the checked-in bytes.
 *
 * It is OFFLINE and DETERMINISTIC. It performs:
 *   - no HTTP fetch, no network, no RPC, no chain call,
 *   - no contract call, no toolchain, no SP1, no proof generation,
 *   - no secret, credential, key, or environment-variable read,
 *   - no wallet/user-data inference.
 *
 * It PUBLISHES NOTHING by itself. A host only ever serves these bytes through the
 * gated, manual `publish-static-evidence` workflow, and only after the security review
 * named in the target decision. This script just assembles the exact files that
 * workflow uploads, so the staging tree can only ever contain the one approved file.
 *
 * Usage:
 *   npm run static:publish:prepare   # stage the one approved artifact + verify; exit non-zero on any drift/extra file
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

import { STATIC_ARTIFACT_PATH, STATIC_ARTIFACT_REL } from "./generate-static-evidence-artifact";

/** Controlled, gitignored staging root the publish workflow uploads from. */
export const STAGING_DIR_REL = "dist/hosted-evidence";
export const STAGING_DIR_PATH = resolve(STAGING_DIR_REL);

/**
 * The staged artifact mirrors the repo path under the staging root, so the served
 * URL path mirrors the committed path (`…/evidence/zk/hosted/v1/…`).
 */
export const STAGED_ARTIFACT_REL = `${STAGING_DIR_REL}/${STATIC_ARTIFACT_REL}`;

function readRaw(path: string): string {
  return readFileSync(path, "utf8");
}

/** Recursively list files under `dir`, as POSIX-style paths relative to `dir`. */
export function listStagedFiles(dir: string): string[] {
  const out: string[] = [];
  function walk(current: string): void {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const abs = join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else out.push(relative(dir, abs).split(sep).join("/"));
    }
  }
  try {
    walk(dir);
  } catch {
    // Absent dir => empty staging tree.
  }
  return out.sort();
}

/**
 * Stage ONLY the checked-in static artifact into `targetDir` (default the publish
 * staging dir). Removes any prior staging tree first so the result can only ever
 * contain the one approved file, then copies the checked-in bytes verbatim to the
 * versioned mirror path. Returns the staged file list (relative to `targetDir`).
 */
export function buildPublishStaging(targetDir: string = STAGING_DIR_PATH): {
  stagingDir: string;
  stagedArtifactPath: string;
  files: string[];
} {
  const sourceBytes = readRaw(STATIC_ARTIFACT_PATH);
  // Clean slate: the staged tree must contain nothing but the approved artifact.
  rmSync(targetDir, { recursive: true, force: true });
  const stagedArtifactPath = resolve(targetDir, STATIC_ARTIFACT_REL);
  mkdirSync(dirname(stagedArtifactPath), { recursive: true });
  writeFileSync(stagedArtifactPath, sourceBytes);
  return { stagingDir: targetDir, stagedArtifactPath, files: listStagedFiles(targetDir) };
}

/**
 * Verify the staged tree is exactly the approved artifact, byte-for-byte. Throws if
 * the staged tree is missing the artifact, carries any extra file, or has drifted from
 * the checked-in bytes. A publish may copy these bytes; it may never regenerate them.
 */
export function verifyPublishStaging(targetDir: string = STAGING_DIR_PATH): void {
  const files = listStagedFiles(targetDir);
  if (files.length !== 1 || files[0] !== STATIC_ARTIFACT_REL) {
    throw new Error(
      `staging tree must contain exactly the approved artifact (${STATIC_ARTIFACT_REL}); found: ${JSON.stringify(files)}`,
    );
  }
  const stagedBytes = readRaw(resolve(targetDir, STATIC_ARTIFACT_REL));
  if (stagedBytes !== readRaw(STATIC_ARTIFACT_PATH)) {
    throw new Error(
      `staged artifact differs from the checked-in artifact (${STATIC_ARTIFACT_REL}); refusing to stage for publish`,
    );
  }
}

function main(): void {
  const { stagingDir, files } = buildPublishStaging();
  verifyPublishStaging(stagingDir);
  console.log(
    `Staged ${files.length} file(s) under ${STAGING_DIR_REL}:\n` +
      files.map((f) => `  - ${f}`).join("\n") +
      `\nStaged artifact is byte-for-byte the checked-in ${STATIC_ARTIFACT_REL}. ` +
      `Offline only — no network, no RPC, no chain call, no toolchain, no secret. ` +
      `Publishes nothing by itself; bytes are served only via the gated manual workflow.`,
  );
}

if (process.argv[1]?.includes("prepare-static-evidence-publish")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
