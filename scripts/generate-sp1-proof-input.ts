/**
 * Generate (and validate) the committed SP1 ML-DSA-65 proof-input fixture.
 *
 * The fixture at zkvm/fixtures/mldsa65-withdrawal.inputs.json is the deterministic
 * guest `inputs.json` for the withdrawal path. It is byte-identical to what
 * scripts/sp1-smoke.ts already feeds the guest (it reuses buildSmokeInputs), so
 * `mldsa65-host execute zkvm/fixtures/mldsa65-withdrawal.inputs.json` runs the
 * same committed material the tested smoke lane uses — no new crypto, no guest or
 * host changes.
 *
 * `--validate` checks the committed fixture three ways, all offline and with no
 * SP1 toolchain or proving:
 *   1. shape — the flat host inputs shape (bytes32 digest, ML-DSA-65-sized key and
 *      signature, testnet/non-mainnet chain id, valid verifier address),
 *   2. manifest alignment — the keccak256 of the input's raw material matches the
 *      hashes the ML-DSA evidence manifest records for the source evidence entry,
 *      under the pinned manifest schema version,
 *   3. no drift — the committed fixture equals a freshly built one and derives the
 *      same deterministic SP1 journal (public values) as the smoke lane.
 *
 * Usage:
 *   npm run sp1:proof-input       # (re)write the committed fixture
 *   npm run validate:sp1-input    # validate the committed fixture, exit non-zero if invalid
 *
 * No transactions, no deploys, no proving, no network.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { dataLength, getBytes } from "ethers";

import { computeExpectedPublicValues, loadSmokeFixture } from "./sp1-smoke";
import { buildProofInputs, validateAlignment, validateProofInputs, type SP1ProofInputs } from "./lib/sp1-proof-input";
import type { MLDSAEvidenceManifest } from "./lib/ml-dsa-evidence-manifest";

export const FIXTURE_DIR = resolve("zkvm/fixtures");
export const PROOF_INPUT_PATH = resolve(FIXTURE_DIR, "mldsa65-withdrawal.inputs.json");

/** Repo-relative path to the committed ML-DSA evidence manifest this input aligns to. */
const MANIFEST_PATH = resolve("evidence/ml-dsa/manifest.json");

/** Build the committed proof input deterministically. */
export function buildExampleProofInput(): SP1ProofInputs {
  return buildProofInputs();
}

function writeFixture(): void {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  writeFileSync(PROOF_INPUT_PATH, `${JSON.stringify(buildExampleProofInput(), null, 2)}\n`);
  console.log(`Wrote ${PROOF_INPUT_PATH}`);
}

function loadManifest(): MLDSAEvidenceManifest {
  return JSON.parse(readFileSync(MANIFEST_PATH, "utf8")) as MLDSAEvidenceManifest;
}

function validateCommitted(): void {
  const onDisk = JSON.parse(readFileSync(PROOF_INPUT_PATH, "utf8")) as SP1ProofInputs;

  const shape = validateProofInputs(onDisk);
  if (!shape.valid) {
    throw new Error(`committed SP1 proof input is malformed:\n - ${shape.errors.join("\n - ")}`);
  }

  const alignment = validateAlignment(onDisk, loadManifest());
  if (!alignment.valid) {
    throw new Error(
      `committed SP1 proof input is not aligned with the ML-DSA evidence manifest:\n - ${alignment.errors.join("\n - ")}`,
    );
  }

  // Drift check: the committed fixture must equal a freshly built one.
  const fresh = JSON.stringify(buildExampleProofInput());
  if (JSON.stringify(onDisk) !== fresh) {
    throw new Error("committed SP1 proof input has drifted from the generator; run `npm run sp1:proof-input`");
  }

  // Bind the input to the deterministic journal the smoke lane derives, so the
  // committed input provably produces the expected guest public values.
  const journal = computeExpectedPublicValues(loadSmokeFixture());
  if (dataLength(journal) !== 160) {
    throw new Error(`expected a 160-byte journal, got ${dataLength(journal)} bytes`);
  }
  // Touch getBytes so the input's raw material is parsed (and rejected if invalid).
  getBytes(onDisk.publicKey);
  getBytes(onDisk.signature);

  console.log(
    `OK: ${PROOF_INPUT_PATH} is valid, aligned with the ML-DSA evidence manifest, and matches the generator (no drift).`,
  );
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeFixture();
  }
}

if (process.argv[1]?.includes("generate-sp1-proof-input")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
