/**
 * Generate the committed PQ verifier evidence example artifacts.
 *
 * Produces one verified (true) and one failure (verified:false) example from the
 * official NIST ACVP ML-DSA-65 sigVer vector (tcId 35), wrapped in the stable
 * `walletwall.pq-verifier-evidence.v1` envelope with a FIXED timestamp so the
 * output is reproducible. `test/PQEvidence.test.ts` re-derives these and asserts
 * the committed files match, so the examples can never silently drift.
 *
 * Run: npm run evidence:fixtures
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

// Imported extensionless (CommonJS ts-node), matching scripts/pq-verifier-cli.ts.
// The verifier modules' intra-package imports use the .ts extension; entry
// scripts that consume them do not.
import { verifyMLDSA65Detailed } from "../src/verifier/ml-dsa-65";
import { buildEvidence } from "../src/verifier/evidence";

/** Fixed instant so the committed examples are deterministic. */
export const EXAMPLE_GENERATED_AT = "2026-01-01T00:00:00.000Z";

interface AcvpVector {
  tcId: number;
  pk: string;
  message: string;
  signature: string;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

const fixturePath = resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as { vectors: AcvpVector[] };
const vec = fixture.vectors.find((v) => v.tcId === 35);
if (!vec) throw new Error("tcId 35 not found in NIST fixture");

const publicKey = hexToBytes(vec.pk);
const message = hexToBytes(vec.message);
const signature = hexToBytes(vec.signature);

/** Valid example: the unmodified NIST ACVP vector verifies. */
export function buildValidExample() {
  return buildEvidence(verifyMLDSA65Detailed(publicKey, message, signature), {
    generatedAt: EXAMPLE_GENERATED_AT,
    source: { type: "nist-acvp", reference: "NIST ACVP ML-DSA-65 sigVer tcId 35 (FIPS 204, external/pure)" },
  });
}

/** Failure example: a single tampered signature byte yields VERIFY_FAILED. */
export function buildFailureExample() {
  const tampered = signature.slice();
  tampered[0] ^= 0x01;
  return buildEvidence(verifyMLDSA65Detailed(publicKey, message, tampered), {
    generatedAt: EXAMPLE_GENERATED_AT,
    source: {
      type: "nist-acvp",
      reference: "NIST ACVP ML-DSA-65 sigVer tcId 35 with one tampered signature byte",
    },
  });
}

export const EXAMPLE_DIR = resolve("docs/schemas/examples");
export const VALID_EXAMPLE_PATH = resolve(EXAMPLE_DIR, "pq-verifier-evidence.valid.json");
export const FAILURE_EXAMPLE_PATH = resolve(EXAMPLE_DIR, "pq-verifier-evidence.failure.json");

function main(): void {
  mkdirSync(EXAMPLE_DIR, { recursive: true });
  writeFileSync(VALID_EXAMPLE_PATH, `${JSON.stringify(buildValidExample(), null, 2)}\n`);
  writeFileSync(FAILURE_EXAMPLE_PATH, `${JSON.stringify(buildFailureExample(), null, 2)}\n`);
  console.log(`Wrote ${VALID_EXAMPLE_PATH}`);
  console.log(`Wrote ${FAILURE_EXAMPLE_PATH}`);
}

if (process.argv[1]?.includes("generate-evidence-fixture")) {
  main();
}
