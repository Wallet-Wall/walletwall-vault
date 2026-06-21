/**
 * Open PQ verifier — result construction helpers.
 *
 * Assembles the deterministic {@link PQVerificationResult} from input hashes and
 * a verification outcome. Inputs are reduced to keccak256 hashes so that raw key
 * and signature material never enters the result object.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { keccak256 } from "ethers";

import type { PQReason, PQVerificationResult } from "./schema";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { PQ_VERIFIER_METADATA } from "./schema.ts";

/** keccak256 of raw bytes. Hashing never reveals the underlying material. */
export function hashInput(data: Uint8Array): string {
  return keccak256(data);
}

/** Build the structured, deterministic verification result. */
export function buildResult(
  input: { messageHash: string; publicKeyHash: string; signatureHash: string },
  verified: boolean,
  reason: PQReason,
): PQVerificationResult {
  return {
    ...PQ_VERIFIER_METADATA,
    input: {
      messageHash: input.messageHash,
      publicKeyHash: input.publicKeyHash,
      signatureHash: input.signatureHash,
    },
    result: {
      verified,
      reason,
    },
  };
}
