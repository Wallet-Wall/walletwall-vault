/**
 * Open PQ verifier — result schema and reason codes.
 *
 * This file is the stable, dependency-free contract for the open ML-DSA-65
 * verifier boundary. It defines the structured result shape and the closed set
 * of reason codes the verifier may emit. It deliberately has NO relative
 * imports and NO runtime dependencies so it stays a self-contained leaf module
 * that can be vendored or re-hosted independently.
 *
 * The open verifier answers exactly one question:
 *   "Did this ML-DSA-65 signature verify for this message and public key?"
 *
 * It never signs anything, never reads an EVM private key, and never constructs
 * an EIP-712 attestation. See docs/Open_PQ_Verifier.md and
 * docs/Verifier_Result_Schema.md.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */

/** Stable schema identifier. Bump only on a breaking result-shape change. */
export const PQ_VERIFIER_SCHEMA_VERSION = "walletwall.pq-verifier.v1";

/** Human/machine name of this verifier implementation. */
export const PQ_VERIFIER_NAME = "walletwall-vault-pq-verifier";

/**
 * Version of the open verifier module itself.
 *
 * This is intentionally a local constant, NOT the repository's package.json
 * version. The verifier boundary is meant to be independently hostable and its
 * reported version tracks the verifier contract/behavior, not the surrounding
 * vault release. Keeping it local also makes {@link PQVerificationResult}
 * deterministic for the same inputs regardless of repo version bumps.
 */
export const PQ_VERIFIER_VERSION = "0.1.0";

/** Algorithm and standard this verifier checks. */
export const PQ_VERIFIER_ALGORITHM = "ML-DSA-65";
export const PQ_VERIFIER_FIPS = "FIPS-204";

/** This module performs pure verification only — no signing, no custody. */
export const PQ_VERIFIER_MODE = "pure";

/**
 * Closed set of reason codes. Exactly one is reported per verification.
 *
 * - ML_DSA_65_VALID         signature verified for the message and public key
 * - EMPTY_MESSAGE           the message had zero bytes
 * - INVALID_PUBLIC_KEY_LENGTH  public key was not the ML-DSA-65 length
 * - INVALID_SIGNATURE_LENGTH   signature was not the ML-DSA-65 length
 * - VERIFY_FAILED           well-formed inputs but the signature did not verify
 * - VERIFY_EXCEPTION        the underlying verifier threw while checking
 */
export const PQ_REASON = {
  ML_DSA_65_VALID: "ML_DSA_65_VALID",
  EMPTY_MESSAGE: "EMPTY_MESSAGE",
  INVALID_PUBLIC_KEY_LENGTH: "INVALID_PUBLIC_KEY_LENGTH",
  INVALID_SIGNATURE_LENGTH: "INVALID_SIGNATURE_LENGTH",
  VERIFY_FAILED: "VERIFY_FAILED",
  VERIFY_EXCEPTION: "VERIFY_EXCEPTION",
} as const;

export type PQReason = (typeof PQ_REASON)[keyof typeof PQ_REASON];

/**
 * Static verifier metadata shared by every result. Bundled as a single constant
 * so consumers (and the result builder) import one name rather than many. The
 * `as const` keeps the literal types required by {@link PQVerificationResult}.
 */
export const PQ_VERIFIER_METADATA = {
  schemaVersion: PQ_VERIFIER_SCHEMA_VERSION,
  verifier: {
    name: PQ_VERIFIER_NAME,
    version: PQ_VERIFIER_VERSION,
  },
  algorithm: PQ_VERIFIER_ALGORITHM,
  fips: PQ_VERIFIER_FIPS,
  mode: PQ_VERIFIER_MODE,
} as const;

/**
 * Deterministic, structured verification result.
 *
 * `input` carries only keccak256 hashes of the message, public key, and
 * signature — never the raw bytes. This keeps the result safe to log and serve
 * while still letting auditors and operators reproduce and cross-check the
 * exact inputs that were verified.
 */
export interface PQVerificationResult {
  schemaVersion: typeof PQ_VERIFIER_SCHEMA_VERSION;
  verifier: {
    name: typeof PQ_VERIFIER_NAME;
    version: string;
  };
  algorithm: typeof PQ_VERIFIER_ALGORITHM;
  fips: typeof PQ_VERIFIER_FIPS;
  mode: typeof PQ_VERIFIER_MODE;
  input: {
    messageHash: string;
    publicKeyHash: string;
    signatureHash: string;
  };
  result: {
    verified: boolean;
    reason: PQReason;
  };
}
