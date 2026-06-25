/**
 * SP1 ML-DSA-65 proof-input scaffold (builder + validator + manifest alignment).
 *
 * This is an INPUT-CONTRACT scaffold, not a proof system. It produces and
 * validates the deterministic guest `inputs.json` the SP1 ML-DSA-65 guest
 * consumes for the withdrawal path (`mldsa65-host execute <inputs.json>`), and it
 * binds that input to the ML-DSA evidence manifest
 * (`walletwall.ml-dsa-evidence-manifest.v1`) so the proof-input path and the
 * evidence path can never silently diverge.
 *
 * The committed fixture is byte-identical to what `scripts/sp1-smoke.ts` already
 * feeds the guest (it reuses {@link buildSmokeInputs}), so this PR adds a
 * committed, drift-checked, manifest-aligned input WITHOUT changing the guest,
 * the host, or the smoke lane. The Rust guest/host already parse this exact flat
 * shape; nothing in the heavy SP1 toolchain is added or required.
 *
 * What it is / is NOT:
 *   - It IS a deterministic proof INPUT and an alignment check between that input
 *     and the ML-DSA evidence manifest. The input carries the raw ML-DSA-65
 *     public key and signature because the guest needs them to verify.
 *   - It is NOT a proof. No proving happens here. It does NOT prove production
 *     custody security, does NOT perform on-chain PQ verification, and is NOT
 *     audited. Mainnet stays gated by audit, funding, and operational controls.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { dataLength, getBytes, isAddress, isHexString, keccak256 } from "ethers";

import { ML_DSA_EVIDENCE_MANIFEST_SCHEMA } from "./ml-dsa-evidence-manifest";
import type { MLDSAEvidenceManifest } from "./ml-dsa-evidence-manifest";
import { SMOKE_CHAIN_ID, buildSmokeInputs } from "../sp1-smoke";

/** Stable identifier for this proof-input scaffold's shape. */
export const SP1_PROOF_INPUT_SCHEMA = "walletwall.sp1-proof-input.v1";

/**
 * The ML-DSA evidence manifest schema this proof input is aligned to. Pinned as a
 * literal AND asserted equal to {@link ML_DSA_EVIDENCE_MANIFEST_SCHEMA} by a test,
 * so a manifest schema bump forces a conscious update here rather than silent
 * drift.
 */
export const ALIGNED_MANIFEST_SCHEMA = "walletwall.ml-dsa-evidence-manifest.v1";

/** The manifest evidence entry this proof input mirrors (the SP1 proof-input source). */
export const SOURCE_EVIDENCE_ID = "library-generated-ml-dsa-65";

/** ML-DSA-65 (FIPS 204) encoded byte lengths, enforced on the proof input. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;

/** Known mainnet chain IDs that must never appear in a testnet-only proof input. */
const FORBIDDEN_CHAIN_IDS = new Set([1, 8453, 137, 10, 42161, 56, 43114]);

/**
 * The flat guest `inputs.json` shape consumed by `mldsa65-host execute`. Mirrors
 * the Rust `InputsFile` in zkvm/host/src/main.rs. `message`/`context` are empty
 * for the withdrawal path (the 32-byte digest is itself the signed message).
 */
export interface SP1ProofInputs {
  withdrawalDigest: string;
  publicKey: string;
  signature: string;
  chainId: number;
  verifierAddress: string;
}

/**
 * Build the deterministic withdrawal-path proof input. Reuses the SP1 smoke
 * fixture builder so the committed input is byte-identical to what the tested
 * smoke lane feeds the guest.
 */
export function buildProofInputs(): SP1ProofInputs {
  return buildSmokeInputs();
}

export interface ProofInputValidation {
  valid: boolean;
  errors: string[];
}

const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;
const ALLOWED_KEYS = new Set([
  "withdrawalDigest",
  "publicKey",
  "signature",
  "chainId",
  "verifierAddress",
  "message",
  "context",
]);
const REQUIRED_KEYS = ["withdrawalDigest", "publicKey", "signature", "chainId", "verifierAddress"] as const;

/**
 * Validate the proof input's SHAPE (pure; no manifest, no filesystem).
 *
 * Checks the flat host shape: a bytes32 withdrawal digest, an ML-DSA-65-sized
 * public key and signature, a uint64 testnet (non-mainnet) chain id, a valid
 * verifier address, and — for the withdrawal path — empty/omitted message and
 * context. Unknown keys are rejected.
 */
export function validateProofInputs(value: unknown): ProofInputValidation {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, errors: ["proof input must be an object"] };
  }
  const v = value as Record<string, unknown>;

  for (const k of Object.keys(v)) {
    if (!ALLOWED_KEYS.has(k)) errors.push(`unexpected key in proof input: ${k}`);
  }
  for (const k of REQUIRED_KEYS) {
    if (!(k in v)) errors.push(`proof input is missing required key: ${k}`);
  }

  if (typeof v.withdrawalDigest !== "string" || !BYTES32_RE.test(v.withdrawalDigest)) {
    errors.push("withdrawalDigest must be a 0x bytes32 hex value");
  }
  if (
    typeof v.publicKey !== "string" ||
    !isHexString(v.publicKey) ||
    dataLength(v.publicKey) !== ML_DSA_65_PUBLIC_KEY_BYTES
  ) {
    errors.push(`publicKey must be ${ML_DSA_65_PUBLIC_KEY_BYTES}-byte ML-DSA-65 hex`);
  }
  if (
    typeof v.signature !== "string" ||
    !isHexString(v.signature) ||
    dataLength(v.signature) !== ML_DSA_65_SIGNATURE_BYTES
  ) {
    errors.push(`signature must be ${ML_DSA_65_SIGNATURE_BYTES}-byte ML-DSA-65 hex`);
  }
  if (typeof v.chainId !== "number" || !Number.isSafeInteger(v.chainId) || v.chainId < 0) {
    errors.push("chainId must be a non-negative integer");
  } else if (FORBIDDEN_CHAIN_IDS.has(v.chainId)) {
    errors.push(`chainId ${v.chainId} is a mainnet chain ID — proof input is testnet/local only`);
  }
  if (typeof v.verifierAddress !== "string" || !isAddress(v.verifierAddress)) {
    errors.push("verifierAddress must be a valid EVM address");
  }
  // Withdrawal path: message/context, if present, must be empty.
  for (const k of ["message", "context"] as const) {
    if (k in v && v[k] !== "" && v[k] !== "0x") {
      errors.push(`${k} must be empty for the withdrawal path`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate that a proof input stays ALIGNED with the ML-DSA evidence manifest:
 * the manifest is the pinned schema version, it carries the source evidence
 * entry, and the keccak256 of the proof input's raw material matches that entry's
 * recorded hashes. This is the bridge that keeps the proof-input path and the
 * read-only evidence path describing the same ML-DSA material.
 */
export function validateAlignment(inputs: SP1ProofInputs, manifest: MLDSAEvidenceManifest): ProofInputValidation {
  const errors: string[] = [];

  if (manifest.schema !== ALIGNED_MANIFEST_SCHEMA) {
    errors.push(`manifest schema ${manifest.schema} is not the aligned ${ALIGNED_MANIFEST_SCHEMA}`);
    return { valid: false, errors };
  }

  const entry = manifest.evidence.find((e) => e.id === SOURCE_EVIDENCE_ID);
  if (!entry) {
    errors.push(`manifest has no evidence entry "${SOURCE_EVIDENCE_ID}" to align with`);
    return { valid: false, errors };
  }

  if (entry.parameterSet !== "ML-DSA-65") errors.push(`source entry parameterSet must be ML-DSA-65`);

  const checks: [string, string, string][] = [
    ["messageHash", keccak256(getBytes(inputs.withdrawalDigest)), entry.messageHash],
    ["publicKeyHash", keccak256(getBytes(inputs.publicKey)), entry.publicKeyHash],
    ["signatureHash", keccak256(getBytes(inputs.signature)), entry.signatureHash],
  ];
  for (const [name, derived, recorded] of checks) {
    if (derived !== recorded) {
      errors.push(`${name} mismatch: proof input derives ${derived} but manifest records ${recorded}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Sanity guard: the smoke fixture's local chain id is the expected non-mainnet one. */
export function expectedChainId(): number {
  return Number(SMOKE_CHAIN_ID);
}
