/**
 * Generate (and validate) the committed reproducible PQ/ZK proof-artifact example.
 *
 * Produces one deterministic `walletwall.pq-proof-artifact.v1` manifest from the
 * committed library-generated ML-DSA-65 fixture, with a FIXED timestamp so the
 * output is byte-reproducible. `test/PQProofArtifact.test.ts` re-derives this and
 * asserts the committed file matches, so the example can never silently drift.
 *
 * The manifest pins the deterministic SP1 journal only; it does NOT contain a
 * real Groth16 proof (the `proof` block is reported as gated). No toolchain is
 * required.
 *
 * Usage:
 *   npm run proof:artifact            # (re)write the committed example
 *   npm run proof:artifact:validate   # validate the committed example, exit non-zero if invalid
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { buildProofArtifact, validateProofArtifact } from "./lib/proof-artifact";
import { loadSmokeFixture, SMOKE_CHAIN_ID, SMOKE_VERIFIER_ADDRESS } from "./sp1-smoke";

/** Fixed instant so the committed example is deterministic. */
export const EXAMPLE_GENERATED_AT = "2026-01-01T00:00:00.000Z";

/** Vector-set identifier for the committed library-generated fixture. */
export const EXAMPLE_VECTOR_SET = "library-generated/ml-dsa-65";

export const EXAMPLE_DIR = resolve("docs/schemas/examples");
export const EXAMPLE_PATH = resolve(EXAMPLE_DIR, "pq-proof-artifact.v1.json");

/** Build the committed example manifest deterministically. */
export function buildExample() {
  const fixture = loadSmokeFixture();
  return buildProofArtifact({
    withdrawalDigest: fixture.withdrawalDigest,
    publicKey: fixture.publicKey,
    signature: fixture.signature,
    chainId: SMOKE_CHAIN_ID,
    verifierAddress: SMOKE_VERIFIER_ADDRESS,
    vectorSet: EXAMPLE_VECTOR_SET,
    generatedAt: EXAMPLE_GENERATED_AT,
    command: "npm run proof:artifact",
  });
}

function writeExample(): void {
  mkdirSync(EXAMPLE_DIR, { recursive: true });
  writeFileSync(EXAMPLE_PATH, `${JSON.stringify(buildExample(), null, 2)}\n`);
  console.log(`Wrote ${EXAMPLE_PATH}`);
}

function validateCommitted(): void {
  const onDisk = JSON.parse(readFileSync(EXAMPLE_PATH, "utf8"));
  const { valid, errors } = validateProofArtifact(onDisk);
  if (!valid) {
    throw new Error(`committed proof artifact is invalid:\n - ${errors.join("\n - ")}`);
  }
  // Drift check: the committed file must equal a freshly built example.
  const fresh = JSON.stringify(buildExample());
  if (JSON.stringify(onDisk) !== fresh) {
    throw new Error("committed proof artifact has drifted from the generator; run `npm run proof:artifact`");
  }
  console.log(`OK: ${EXAMPLE_PATH} is valid and matches the generator (no drift).`);
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeExample();
  }
}

if (process.argv[1]?.includes("generate-proof-artifact")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
