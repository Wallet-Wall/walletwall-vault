/**
 * Generate (and validate) the committed ZK verifier adapter boundary.
 *
 * The adapter at evidence/zk/zk-verifier-adapter.json ties together the SP1 proof
 * input (zkvm/fixtures/mldsa65-withdrawal.inputs.json), the deterministic SP1
 * guest journal (public values), the gated proof slot, and the ML-DSA evidence
 * manifest (evidence/ml-dsa/manifest.json) — all describing the same
 * library-generated ML-DSA-65 material — plus the on-chain verifier role.
 *
 * Every field except the fixed `generatedAt` is a pure function of committed
 * bytes, so regenerating yields a byte-identical adapter.
 * `test/ZKVerifierAdapter.test.ts` re-derives this and asserts the committed file
 * matches, so it can never silently drift.
 *
 * Usage:
 *   npm run zk:adapter            # (re)write the committed adapter
 *   npm run validate:zk-adapter   # validate the committed adapter, exit non-zero if invalid
 *
 * No transactions, no deploys, no proving, no network.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { getBytes, keccak256 } from "ethers";

import { SMOKE_CHAIN_ID, SMOKE_VERIFIER_ADDRESS, computeExpectedPublicValues, loadSmokeFixture } from "./sp1-smoke";
import { SOURCE_EVIDENCE_ID, SP1_PROOF_INPUT_SCHEMA, buildProofInputs } from "./lib/sp1-proof-input";
import { ML_DSA_EVIDENCE_MANIFEST_SCHEMA, type MLDSAEvidenceManifest } from "./lib/ml-dsa-evidence-manifest";
import { buildAdapter, validateAdapter, type ZKVerifierAdapter } from "./lib/zk-verifier-adapter";

/** Fixed instant so the committed adapter is deterministic. */
export const EXAMPLE_GENERATED_AT = "2026-01-01T00:00:00.000Z";

export const ADAPTER_DIR = resolve("evidence/zk");
export const ADAPTER_PATH = resolve(ADAPTER_DIR, "zk-verifier-adapter.json");

const PROOF_INPUT_REL = "zkvm/fixtures/mldsa65-withdrawal.inputs.json";
const MANIFEST_REL = "evidence/ml-dsa/manifest.json";

/** Build the committed adapter deterministically from the committed sources. */
export function buildExampleAdapter(): ZKVerifierAdapter {
  const inputs = buildProofInputs();
  const fixture = loadSmokeFixture();
  const publicValues = computeExpectedPublicValues(fixture);

  return buildAdapter({
    proofInput: {
      schema: SP1_PROOF_INPUT_SCHEMA,
      path: PROOF_INPUT_REL,
      messageHash: keccak256(getBytes(inputs.withdrawalDigest)),
      publicKeyHash: keccak256(getBytes(inputs.publicKey)),
      signatureHash: keccak256(getBytes(inputs.signature)),
    },
    journal: {
      publicValues,
      publicValuesHash: keccak256(publicValues),
      chainId: Number(SMOKE_CHAIN_ID),
      verifierAddress: SMOKE_VERIFIER_ADDRESS,
    },
    evidence: {
      manifestSchema: ML_DSA_EVIDENCE_MANIFEST_SCHEMA,
      manifestPath: MANIFEST_REL,
      evidenceId: SOURCE_EVIDENCE_ID,
    },
    generatedAt: EXAMPLE_GENERATED_AT,
    command: "npm run zk:adapter",
  });
}

function writeAdapter(): void {
  mkdirSync(ADAPTER_DIR, { recursive: true });
  writeFileSync(ADAPTER_PATH, `${JSON.stringify(buildExampleAdapter(), null, 2)}\n`);
  console.log(`Wrote ${ADAPTER_PATH}`);
}

function loadManifest(): MLDSAEvidenceManifest {
  return JSON.parse(readFileSync(resolve(MANIFEST_REL), "utf8")) as MLDSAEvidenceManifest;
}

/**
 * Independent on-disk cross-check: the adapter's proof-input hashes must match the
 * ML-DSA evidence manifest's source entry, and the named evidence entry must
 * exist. This catches a hand-edited committed adapter even if the generator is
 * never re-run.
 */
function crossCheckAgainstSources(adapter: ZKVerifierAdapter): string[] {
  const errors: string[] = [];
  const manifest = loadManifest();

  if (manifest.schema !== adapter.evidence.manifestSchema) {
    errors.push(
      `manifest schema ${manifest.schema} != adapter.evidence.manifestSchema ${adapter.evidence.manifestSchema}`,
    );
  }
  const entry = manifest.evidence.find((e) => e.id === adapter.evidence.evidenceId);
  if (!entry) {
    errors.push(`manifest has no evidence entry "${adapter.evidence.evidenceId}"`);
    return errors;
  }
  if (entry.messageHash !== adapter.proofInput.messageHash)
    errors.push("proofInput.messageHash drifted from the manifest entry");
  if (entry.publicKeyHash !== adapter.proofInput.publicKeyHash)
    errors.push("proofInput.publicKeyHash drifted from the manifest entry");
  if (entry.signatureHash !== adapter.proofInput.signatureHash)
    errors.push("proofInput.signatureHash drifted from the manifest entry");
  return errors;
}

function validateCommitted(): void {
  const onDisk = JSON.parse(readFileSync(ADAPTER_PATH, "utf8")) as ZKVerifierAdapter;

  const { valid, errors } = validateAdapter(onDisk);
  if (!valid) {
    throw new Error(`committed ZK verifier adapter is invalid:\n - ${errors.join("\n - ")}`);
  }

  const crossErrors = crossCheckAgainstSources(onDisk);
  if (crossErrors.length > 0) {
    throw new Error(`committed ZK verifier adapter does not match its sources:\n - ${crossErrors.join("\n - ")}`);
  }

  const fresh = JSON.stringify(buildExampleAdapter());
  if (JSON.stringify(onDisk) !== fresh) {
    throw new Error("committed ZK verifier adapter has drifted from the generator; run `npm run zk:adapter`");
  }

  console.log(
    `OK: ${ADAPTER_PATH} is valid, aligned with the proof input + ML-DSA evidence manifest, and matches the generator (no drift).`,
  );
}

function main(): void {
  if (process.argv.includes("--validate")) {
    validateCommitted();
  } else {
    writeAdapter();
  }
}

if (process.argv[1]?.includes("generate-zk-verifier-adapter")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
