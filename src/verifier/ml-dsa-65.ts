/**
 * Open PQ verifier — pure ML-DSA-65 (FIPS 204) signature verification.
 *
 * This is the open, independently hostable verification boundary. It answers
 * exactly one question and returns a deterministic structured result:
 *
 *   "Did this ML-DSA-65 signature verify for this message and public key?"
 *
 * Guarantees of this module:
 *   - uses @noble/post-quantum ML-DSA-65 verification (FIPS 204, external/pure)
 *   - validates public key length, signature length, and non-empty message
 *   - returns a deterministic {@link PQVerificationResult} with a reason code
 *   - hashes all inputs with keccak256 and never returns raw key/signature bytes
 *   - NEVER signs anything
 *   - NEVER reads or requires ATTESTOR_PRIVATE_KEY
 *   - NEVER constructs an EIP-712 attestation
 *   - NEVER depends on the Hardhat runtime
 *
 * The optional attestation layer (scripts/lib/attestation.ts) may consume the
 * boolean outcome of this module to sign a trusted EIP-712 attestation, but that
 * path is separate, trusted, and is NOT a ZK proof or on-chain ML-DSA check.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import type { PQVerificationResult } from "./schema";
// Type-only re-export (erased at runtime) so consumers can import the result
// type from this module entry point alongside the verify functions.
export type { PQVerificationResult, PQReason } from "./schema";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { PQ_REASON } from "./schema.ts";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { buildResult, hashInput } from "./result.ts";

/** ML-DSA-65 public key length in bytes (FIPS 204, category 3). */
export const ML_DSA_65_PUBLIC_KEY_LENGTH = ml_dsa65.lengths.publicKey;
/** ML-DSA-65 signature length in bytes (FIPS 204, category 3). */
export const ML_DSA_65_SIGNATURE_LENGTH = ml_dsa65.lengths.signature;

/**
 * Pure ML-DSA-65 verification returning a deterministic structured result.
 *
 * Reason precedence is fixed (empty message → public-key length → signature
 * length → cryptographic verification) so the same inputs always yield the same
 * result. Input hashes are always populated; raw bytes are never included.
 */
export function verifyMLDSA65Detailed(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): PQVerificationResult {
  const input = {
    messageHash: hashInput(message),
    publicKeyHash: hashInput(publicKey),
    signatureHash: hashInput(signature),
  };

  if (message.length === 0) {
    return buildResult(input, false, PQ_REASON.EMPTY_MESSAGE);
  }
  if (publicKey.length !== ML_DSA_65_PUBLIC_KEY_LENGTH) {
    return buildResult(input, false, PQ_REASON.INVALID_PUBLIC_KEY_LENGTH);
  }
  if (signature.length !== ML_DSA_65_SIGNATURE_LENGTH) {
    return buildResult(input, false, PQ_REASON.INVALID_SIGNATURE_LENGTH);
  }

  try {
    const verified = ml_dsa65.verify(signature, message, publicKey);
    return buildResult(input, verified, verified ? PQ_REASON.ML_DSA_65_VALID : PQ_REASON.VERIFY_FAILED);
  } catch {
    return buildResult(input, false, PQ_REASON.VERIFY_EXCEPTION);
  }
}

/**
 * Boolean convenience wrapper preserving the historical helper signature used by
 * the attestation layer and conformance tests. Equivalent to
 * `verifyMLDSA65Detailed(...).result.verified`.
 */
export function verifyMLDSA65(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return verifyMLDSA65Detailed(publicKey, message, signature).result.verified;
}
