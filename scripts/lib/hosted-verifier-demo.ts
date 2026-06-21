/**
 * Hosted PQ verifier — DEMO / SPIKE ONLY (transport-agnostic request handler).
 *
 * ⚠️ This is a non-production SPIKE. It is a pure, in-process request→response
 * function that demonstrates the boundary a hosted open-verifier endpoint WOULD
 * expose. It deliberately ships NO server, NO network listener, NO secrets, and
 * NO deployed-service requirement. It is here to evaluate the shape and threat
 * model of a future hosted verifier, not to run one.
 *
 * What it does:
 *   - accepts a deterministic JSON-shaped request `{ message, publicKey,
 *     signature, source? }` with `0x`-prefixed, even-length hex inputs,
 *   - strictly decodes and size-bounds the inputs (DoS guard),
 *   - runs the pure open verifier (verifyMLDSA65Detailed) and wraps the result
 *     in the stable `walletwall.pq-verifier-evidence.v1` envelope (hashes only),
 *   - returns a deterministic response with an HTTP-like status code.
 *
 * What it must NEVER do (and does not):
 *   - read any environment variable or ATTESTOR_PRIVATE_KEY,
 *   - sign anything (no ML-DSA signing, no EIP-712, no EVM signing),
 *   - write to any contract or chain,
 *   - custody funds,
 *   - return raw key/signature/message bytes (only keccak256 hashes appear).
 *
 * A failed *verification* is still a successful *request* (status 200, evidence
 * with `verified: false`). Only a malformed or oversized request is 400/413.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { isHexString, getBytes } from "ethers";

import type { PQVerificationEvidence, PQEvidenceSource } from "../../src/verifier/evidence";
import { buildEvidence, PQ_EVIDENCE_SOURCE_TYPES } from "../../src/verifier/evidence";
import { verifyMLDSA65Detailed } from "../../src/verifier/ml-dsa-65";

/** Demo identifier surfaced in responses so callers can never mistake it for prod. */
export const HOSTED_DEMO_NAME = "walletwall-hosted-pq-verifier-demo";
export const HOSTED_DEMO_MODE = "spike-non-production";

/**
 * Per-field byte caps. These bound memory/CPU per request (a DoS guard) while
 * still leaving near-miss length errors to the verifier's reason codes. They are
 * generously above the ML-DSA-65 sizes (pk 1952 B, sig 3309 B); absurd inputs
 * are rejected with 413 before any verification work.
 */
export const HOSTED_LIMITS = {
  maxMessageBytes: 4096,
  maxPublicKeyBytes: 4096,
  maxSignatureBytes: 8192,
} as const;

/** HTTP-like status codes the demo handler reports. */
export const HOSTED_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  PAYLOAD_TOO_LARGE: 413,
} as const;
export type HostedStatus = (typeof HOSTED_STATUS)[keyof typeof HOSTED_STATUS];

export interface HostedVerifyRequest {
  message: string;
  publicKey: string;
  signature: string;
  source?: PQEvidenceSource;
}

export interface HostedVerifyError {
  code: "BAD_REQUEST" | "PAYLOAD_TOO_LARGE";
  message: string;
}

export interface HostedVerifyResponse {
  service: typeof HOSTED_DEMO_NAME;
  mode: typeof HOSTED_DEMO_MODE;
  status: HostedStatus;
  ok: boolean;
  evidence?: PQVerificationEvidence;
  error?: HostedVerifyError;
}

function badRequest(message: string): HostedVerifyResponse {
  return baseResponse(HOSTED_STATUS.BAD_REQUEST, false, {
    error: { code: "BAD_REQUEST", message },
  });
}

function tooLarge(message: string): HostedVerifyResponse {
  return baseResponse(HOSTED_STATUS.PAYLOAD_TOO_LARGE, false, {
    error: { code: "PAYLOAD_TOO_LARGE", message },
  });
}

function baseResponse(
  status: HostedStatus,
  ok: boolean,
  extra: Partial<Pick<HostedVerifyResponse, "evidence" | "error">>,
): HostedVerifyResponse {
  return { service: HOSTED_DEMO_NAME, mode: HOSTED_DEMO_MODE, status, ok, ...extra };
}

/**
 * Strictly decode a `0x`-prefixed, even-length hex field and enforce its byte
 * cap. Returns the bytes, a `tooLarge` flag, or null for malformed encoding.
 * The field name is used only for error text — raw bytes are never echoed.
 */
function decodeHexField(
  value: unknown,
  name: string,
  maxBytes: number,
): { bytes: Uint8Array } | { tooLarge: true } | { bad: string } {
  if (typeof value !== "string") return { bad: `${name} must be a 0x-prefixed hex string` };
  // Reject before allocating: hex string of N chars decodes to (N-2)/2 bytes.
  if (!value.startsWith("0x")) return { bad: `${name} must be 0x-prefixed` };
  const body = value.slice(2);
  if (body.length % 2 !== 0) return { bad: `${name} must be even-length hex` };
  if (!/^[0-9a-fA-F]*$/.test(body)) return { bad: `${name} must be hex characters only` };
  if (body.length / 2 > maxBytes) return { tooLarge: true };
  if (!isHexString(value)) return { bad: `${name} must be valid hex` };
  return { bytes: getBytes(value) };
}

/** Validate an optional, safe provenance reference (no raw material allowed). */
function validateSource(source: unknown): { source?: PQEvidenceSource } | { bad: string } {
  if (source === undefined) return {};
  if (typeof source !== "object" || source === null) return { bad: "source must be an object" };
  const s = source as Record<string, unknown>;
  if (typeof s.type !== "string" || !PQ_EVIDENCE_SOURCE_TYPES.includes(s.type as PQEvidenceSource["type"])) {
    return { bad: `source.type must be one of ${PQ_EVIDENCE_SOURCE_TYPES.join(", ")}` };
  }
  if (typeof s.reference !== "string" || s.reference.length === 0) {
    return { bad: "source.reference must be a non-empty string" };
  }
  return { source: { type: s.type as PQEvidenceSource["type"], reference: s.reference } };
}

/**
 * Handle one hosted-verify request. Pure and deterministic given the request and
 * an injected clock (`opts.now`); the only non-deterministic field is the
 * evidence timestamp, which a caller may pin for reproducible demos/tests.
 */
export function handleHostedVerifyRequest(request: unknown, opts: { now?: string | Date } = {}): HostedVerifyResponse {
  if (typeof request !== "object" || request === null) {
    return badRequest("request must be a JSON object");
  }
  const r = request as Record<string, unknown>;

  const allowed = new Set(["message", "publicKey", "signature", "source"]);
  for (const key of Object.keys(r)) {
    if (!allowed.has(key)) return badRequest(`unexpected request field: ${key}`);
  }

  const message = decodeHexField(r.message, "message", HOSTED_LIMITS.maxMessageBytes);
  if ("tooLarge" in message) return tooLarge(`message exceeds ${HOSTED_LIMITS.maxMessageBytes} bytes`);
  if ("bad" in message) return badRequest(message.bad);

  const publicKey = decodeHexField(r.publicKey, "publicKey", HOSTED_LIMITS.maxPublicKeyBytes);
  if ("tooLarge" in publicKey) return tooLarge(`publicKey exceeds ${HOSTED_LIMITS.maxPublicKeyBytes} bytes`);
  if ("bad" in publicKey) return badRequest(publicKey.bad);

  const signature = decodeHexField(r.signature, "signature", HOSTED_LIMITS.maxSignatureBytes);
  if ("tooLarge" in signature) return tooLarge(`signature exceeds ${HOSTED_LIMITS.maxSignatureBytes} bytes`);
  if ("bad" in signature) return badRequest(signature.bad);

  const source = validateSource(r.source);
  if ("bad" in source) return badRequest(source.bad);

  // Pure verification + evidence envelope (hashes only). No signing, no keys.
  const verification = verifyMLDSA65Detailed(publicKey.bytes, message.bytes, signature.bytes);
  const evidence = buildEvidence(verification, { generatedAt: opts.now, source: source.source });

  return baseResponse(HOSTED_STATUS.OK, true, { evidence });
}
