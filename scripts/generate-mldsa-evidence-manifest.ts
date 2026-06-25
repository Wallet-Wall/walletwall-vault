/**
 * Generate (and validate) the committed ML-DSA evidence artifact manifest.
 *
 * The manifest at evidence/ml-dsa/manifest.json is a deterministic INDEX over the
 * repository's committed ML-DSA evidence artifacts — the two
 * `walletwall.pq-verifier-evidence.v1` examples and the deterministic
 * library-generated ML-DSA-65 fixture — recording, for each, the keccak256 input
 * hashes, the off-chain verification result, and an integrity hash of the
 * referenced file, plus the overall evidence boundary and limitations.
 *
 * Every field except the fixed `generatedAt` is a pure function of committed
 * bytes, so regenerating yields a byte-identical manifest.
 * `test/MLDSAEvidenceManifest.test.ts` re-derives this and asserts the committed
 * file matches, so the manifest can never silently drift from its sources.
 *
 * Usage:
 *   npm run evidence:manifest        # (re)write the committed manifest
 *   npm run validate:evidence        # validate the committed manifest, exit non-zero if invalid
 *
 * No toolchain, no network, no proving, no transactions.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { getBytes, keccak256, toUtf8Bytes } from "ethers";

import { verifyMLDSA65Detailed } from "../src/verifier/ml-dsa-65";
import { PQ_REASON, PQ_VERIFIER_ALGORITHM, PQ_VERIFIER_MODE } from "../src/verifier/schema";
import type { PQReason } from "../src/verifier/schema";
import {
  buildManifest,
  validateManifest,
  type MLDSAEvidenceEntry,
  type MLDSAEvidenceManifest,
} from "./lib/ml-dsa-evidence-manifest";

/** Fixed instant so the committed manifest is deterministic. */
export const EXAMPLE_GENERATED_AT = "2026-01-01T00:00:00.000Z";

export const MANIFEST_DIR = resolve("evidence/ml-dsa");
export const MANIFEST_PATH = resolve(MANIFEST_DIR, "manifest.json");

/** Repo-relative paths to the committed source artifacts the manifest indexes. */
const VALID_EVIDENCE_PATH = "docs/schemas/examples/pq-verifier-evidence.valid.json";
const FAILURE_EVIDENCE_PATH = "docs/schemas/examples/pq-verifier-evidence.failure.json";
const LIBRARY_FIXTURE_PATH = "test/fixtures/mldsa/library-generated/ml-dsa-65.json";

/** keccak256 of a committed file's exact bytes (its integrity hash). */
function fileHash(relPath: string): string {
  return keccak256(toUtf8Bytes(readFileSync(resolve(relPath), "utf8")));
}

/** Read a committed pq-verifier-evidence example into a manifest entry. */
function entryFromPqEvidence(id: string, relPath: string): MLDSAEvidenceEntry {
  const ev = JSON.parse(readFileSync(resolve(relPath), "utf8")) as {
    verification: {
      input: { messageHash: string; publicKeyHash: string; signatureHash: string };
      result: { verified: boolean; reason: PQReason };
    };
    source: { type: MLDSAEvidenceEntry["sourceType"]; reference: string };
  };
  return {
    id,
    kind: "pq-verifier-evidence",
    sourceType: ev.source.type,
    reference: ev.source.reference,
    parameterSet: PQ_VERIFIER_ALGORITHM,
    verifierMode: PQ_VERIFIER_MODE,
    messageHash: ev.verification.input.messageHash,
    publicKeyHash: ev.verification.input.publicKeyHash,
    signatureHash: ev.verification.input.signatureHash,
    result: { accepted: ev.verification.result.verified, reason: ev.verification.result.reason },
    artifactPath: relPath,
    artifactHash: fileHash(relPath),
  };
}

/** Derive a manifest entry from the deterministic library-generated ML-DSA-65 fixture. */
function entryFromLibraryFixture(): MLDSAEvidenceEntry {
  const fixture = JSON.parse(readFileSync(resolve(LIBRARY_FIXTURE_PATH), "utf8")) as {
    source: string;
    algorithm: string;
    message: string;
    publicKey: string;
    signature: string;
    publicKeyHash: string;
    signatureHash: string;
  };
  const message = getBytes(fixture.message);
  const publicKey = getBytes(fixture.publicKey);
  const signature = getBytes(fixture.signature);
  const verification = verifyMLDSA65Detailed(publicKey, message, signature);

  return {
    id: "library-generated-ml-dsa-65",
    kind: "test-vector",
    sourceType: "library-generated",
    reference: `${fixture.source} ${fixture.algorithm} (deterministic seed; the SP1 proof-input source)`,
    parameterSet: PQ_VERIFIER_ALGORITHM,
    verifierMode: PQ_VERIFIER_MODE,
    messageHash: keccak256(message),
    publicKeyHash: verification.input.publicKeyHash,
    signatureHash: verification.input.signatureHash,
    result: { accepted: verification.result.verified, reason: verification.result.reason },
    artifactPath: LIBRARY_FIXTURE_PATH,
    artifactHash: fileHash(LIBRARY_FIXTURE_PATH),
  };
}

/** Build the committed manifest deterministically from the committed sources. */
export function buildExampleManifest(): MLDSAEvidenceManifest {
  const entries: MLDSAEvidenceEntry[] = [
    entryFromPqEvidence("nist-acvp-ml-dsa-65-sigver-tcid35-valid", VALID_EVIDENCE_PATH),
    entryFromPqEvidence("nist-acvp-ml-dsa-65-sigver-tcid35-failure", FAILURE_EVIDENCE_PATH),
    entryFromLibraryFixture(),
  ];
  return buildManifest(entries, { generatedAt: EXAMPLE_GENERATED_AT, command: "npm run evidence:manifest" });
}

function writeManifest(): void {
  mkdirSync(MANIFEST_DIR, { recursive: true });
  writeFileSync(MANIFEST_PATH, `${JSON.stringify(buildExampleManifest(), null, 2)}\n`);
  console.log(`Wrote ${MANIFEST_PATH}`);
}

/**
 * Independent on-disk cross-check: every entry's recorded artifactHash must equal
 * the keccak256 of the file it points at, and pq-verifier-evidence entries must
 * carry the same input hashes the referenced evidence artifact carries. This
 * catches a hand-edited committed manifest even if the generator is never re-run.
 */
function crossCheckAgainstSources(manifest: MLDSAEvidenceManifest): string[] {
  const errors: string[] = [];
  for (const entry of manifest.evidence) {
    let onDiskHash: string;
    try {
      onDiskHash = fileHash(entry.artifactPath);
    } catch {
      errors.push(`${entry.id}: referenced artifact ${entry.artifactPath} could not be read`);
      continue;
    }
    if (onDiskHash !== entry.artifactHash) {
      errors.push(`${entry.id}: artifactHash does not match keccak256(${entry.artifactPath})`);
    }
    if (entry.kind === "pq-verifier-evidence") {
      const ev = JSON.parse(readFileSync(resolve(entry.artifactPath), "utf8")) as {
        verification: { input: { messageHash: string; publicKeyHash: string; signatureHash: string } };
      };
      const i = ev.verification.input;
      if (i.messageHash !== entry.messageHash)
        errors.push(`${entry.id}: messageHash drifted from ${entry.artifactPath}`);
      if (i.publicKeyHash !== entry.publicKeyHash)
        errors.push(`${entry.id}: publicKeyHash drifted from ${entry.artifactPath}`);
      if (i.signatureHash !== entry.signatureHash)
        errors.push(`${entry.id}: signatureHash drifted from ${entry.artifactPath}`);
    }
  }
  return errors;
}

function validateCommitted(): void {
  const onDisk = JSON.parse(readFileSync(MANIFEST_PATH, "utf8")) as MLDSAEvidenceManifest;

  const { valid, errors } = validateManifest(onDisk);
  if (!valid) {
    throw new Error(`committed ML-DSA evidence manifest is invalid:\n - ${errors.join("\n - ")}`);
  }

  const crossErrors = crossCheckAgainstSources(onDisk);
  if (crossErrors.length > 0) {
    throw new Error(`committed ML-DSA evidence manifest does not match its sources:\n - ${crossErrors.join("\n - ")}`);
  }

  // Drift check: the committed file must equal a freshly built manifest.
  const fresh = JSON.stringify(buildExampleManifest());
  if (JSON.stringify(onDisk) !== fresh) {
    throw new Error(
      "committed ML-DSA evidence manifest has drifted from the generator; run `npm run evidence:manifest`",
    );
  }

  console.log(`OK: ${MANIFEST_PATH} is valid, matches its sources, and matches the generator (no drift).`);
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeManifest();
  }
}

// Re-exported so tests can assert the committed result code paths.
export { validateManifest, PQ_REASON };

if (process.argv[1]?.includes("generate-mldsa-evidence-manifest")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
