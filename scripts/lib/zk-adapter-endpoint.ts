/**
 * Hosted ZK adapter evidence endpoint — DEMO / SPIKE ONLY (transport-agnostic).
 *
 * ⚠️ This is a non-production SPIKE. It is a pure, in-process request→response
 * function that demonstrates the boundary a hosted, READ-ONLY ZK-adapter evidence
 * endpoint WOULD expose. It ships NO server, NO network listener, NO secrets, and
 * NO deployed-service requirement. Mirrors scripts/lib/hosted-verifier-demo.ts.
 *
 * What it does:
 *   - serves the committed ZK verifier adapter boundary
 *     (`walletwall.zk-verifier-adapter.v1`) as read-only evidence,
 *   - wraps it with `servedAt` + a strong `etag` (keccak256 content hash of the
 *     adapter) so the private app can cache and conditionally re-fetch,
 *   - answers a conditional GET: `ifNoneMatch === etag` → 304 Not Modified
 *     (no body); a non-GET method → 405; an unknown field → 400.
 *
 * What it must NEVER do (and does not):
 *   - perform any vault write, transaction, deploy, or on-chain call,
 *   - sign anything or read any private key / environment variable,
 *   - custody funds,
 *   - serve anything but read-only evidence (hashes + the 160-byte journal only).
 *
 * The served adapter is NOT a proof, NOT production ZK verification, and NOT
 * on-chain ML-DSA verification (the active on-chain SP1 verifier is a mock; heavy
 * proving stays gated). Mainnet stays gated by audit, funding, and operational
 * controls.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { keccak256, toUtf8Bytes } from "ethers";

import { validateAdapter, type ZKVerifierAdapter } from "./zk-verifier-adapter";

/** Stable success-response schema identifier. */
export const ZK_ADAPTER_RESPONSE_SCHEMA = "walletwall.zk-adapter-evidence-response.v1";

/** Demo identifiers surfaced in every response so callers can never mistake it for prod. */
export const ZK_ENDPOINT_SERVICE = "walletwall-zk-adapter-evidence-demo";
export const ZK_ENDPOINT_MODE = "spike-non-production";
export const ZK_ENDPOINT_CONTENT_TYPE = "application/json";

/** HTTP-like status codes the demo handler reports. */
export const ZK_ENDPOINT_STATUS = {
  OK: 200,
  NOT_MODIFIED: 304,
  BAD_REQUEST: 400,
  METHOD_NOT_ALLOWED: 405,
} as const;
export type ZKEndpointStatus = (typeof ZK_ENDPOINT_STATUS)[keyof typeof ZK_ENDPOINT_STATUS];

/** Canonical, honest limitations for the hosted endpoint. */
export const ZK_ENDPOINT_LIMITATIONS: readonly string[] = [
  "Spike / non-production — this is a transport-agnostic demo handler; it ships no server, no listener, and no deployed-service requirement.",
  "Read-only — the endpoint serves evidence only; it performs no vault write, transaction, deploy, or on-chain call.",
  "Served evidence is gated and off-chain — the adapter carries no real proof and does not perform on-chain ML-DSA verification (the active on-chain SP1 verifier is a mock).",
  "Research prototype — not audited.",
  "Testnet / reference path only — no mainnet deployment and no production custody.",
  "No real funds — every served artifact is deterministic test/fixture material.",
];

export interface ZKAdapterEvidenceResponse {
  schema: typeof ZK_ADAPTER_RESPONSE_SCHEMA;
  service: typeof ZK_ENDPOINT_SERVICE;
  mode: typeof ZK_ENDPOINT_MODE;
  status: typeof ZK_ENDPOINT_STATUS.OK;
  ok: true;
  contentType: typeof ZK_ENDPOINT_CONTENT_TYPE;
  /** ISO-8601 UTC instant; the only non-deterministic field. */
  servedAt: string;
  /** Strong ETag: keccak256 of the canonical adapter JSON. */
  etag: string;
  adapter: ZKVerifierAdapter;
  limitations: string[];
  regeneration: { command: string; deterministic: boolean };
}

export interface ZKEndpointConditionalResponse {
  service: typeof ZK_ENDPOINT_SERVICE;
  mode: typeof ZK_ENDPOINT_MODE;
  status: typeof ZK_ENDPOINT_STATUS.NOT_MODIFIED;
  ok: true;
  servedAt: string;
  etag: string;
}

export interface ZKEndpointErrorResponse {
  service: typeof ZK_ENDPOINT_SERVICE;
  mode: typeof ZK_ENDPOINT_MODE;
  status: typeof ZK_ENDPOINT_STATUS.BAD_REQUEST | typeof ZK_ENDPOINT_STATUS.METHOD_NOT_ALLOWED;
  ok: false;
  servedAt: string;
  error: { code: "BAD_REQUEST" | "METHOD_NOT_ALLOWED"; message: string };
}

export type ZKEndpointResponse = ZKAdapterEvidenceResponse | ZKEndpointConditionalResponse | ZKEndpointErrorResponse;

/** Strong ETag over the canonical (compact, parsed) adapter JSON — formatting-independent. */
export function computeAdapterETag(adapter: ZKVerifierAdapter): string {
  return keccak256(toUtf8Bytes(JSON.stringify(adapter)));
}

function isoNow(now?: string | Date): string {
  return now instanceof Date ? now.toISOString() : (now ?? new Date().toISOString());
}

/** Build the canonical 200 success response that serves the adapter as read-only evidence. */
export function buildAdapterEvidenceResponse(
  adapter: ZKVerifierAdapter,
  opts: { servedAt?: string | Date; command?: string } = {},
): ZKAdapterEvidenceResponse {
  return {
    schema: ZK_ADAPTER_RESPONSE_SCHEMA,
    service: ZK_ENDPOINT_SERVICE,
    mode: ZK_ENDPOINT_MODE,
    status: ZK_ENDPOINT_STATUS.OK,
    ok: true,
    contentType: ZK_ENDPOINT_CONTENT_TYPE,
    servedAt: isoNow(opts.servedAt),
    etag: computeAdapterETag(adapter),
    adapter,
    limitations: [...ZK_ENDPOINT_LIMITATIONS],
    regeneration: { command: opts.command ?? "npm run zk:adapter:response", deterministic: true },
  };
}

export interface ZKEndpointRequest {
  method?: string;
  ifNoneMatch?: string;
}

/**
 * Handle one read-only adapter-evidence request. Pure and deterministic given the
 * request, the served adapter, and an injected clock (`opts.now`).
 *
 *   - non-GET method                         → 405 Method Not Allowed
 *   - unknown request field                  → 400 Bad Request
 *   - ifNoneMatch === current etag           → 304 Not Modified (no body)
 *   - otherwise                              → 200 with the adapter evidence
 */
export function handleAdapterEvidenceRequest(
  request: unknown,
  adapter: ZKVerifierAdapter,
  opts: { now?: string | Date } = {},
): ZKEndpointResponse {
  const servedAt = isoNow(opts.now);

  if (typeof request !== "object" || request === null || Array.isArray(request)) {
    return errorResponse("BAD_REQUEST", "request must be a JSON object", servedAt);
  }
  const r = request as Record<string, unknown>;

  const allowed = new Set(["method", "ifNoneMatch"]);
  for (const key of Object.keys(r)) {
    if (!allowed.has(key)) return errorResponse("BAD_REQUEST", `unexpected request field: ${key}`, servedAt);
  }

  const method = r.method ?? "GET";
  if (typeof method !== "string") return errorResponse("BAD_REQUEST", "method must be a string", servedAt);
  if (method.toUpperCase() !== "GET") {
    return errorResponse(
      "METHOD_NOT_ALLOWED",
      `method ${method} not allowed; this endpoint is read-only (GET)`,
      servedAt,
    );
  }
  if (r.ifNoneMatch !== undefined && typeof r.ifNoneMatch !== "string") {
    return errorResponse("BAD_REQUEST", "ifNoneMatch must be a string", servedAt);
  }

  const etag = computeAdapterETag(adapter);
  if (typeof r.ifNoneMatch === "string" && r.ifNoneMatch === etag) {
    return {
      service: ZK_ENDPOINT_SERVICE,
      mode: ZK_ENDPOINT_MODE,
      status: ZK_ENDPOINT_STATUS.NOT_MODIFIED,
      ok: true,
      servedAt,
      etag,
    };
  }

  return buildAdapterEvidenceResponse(adapter, { servedAt });
}

function errorResponse(
  code: "BAD_REQUEST" | "METHOD_NOT_ALLOWED",
  message: string,
  servedAt: string,
): ZKEndpointErrorResponse {
  return {
    service: ZK_ENDPOINT_SERVICE,
    mode: ZK_ENDPOINT_MODE,
    status: ZK_ENDPOINT_STATUS[code],
    ok: false,
    servedAt,
    error: { code, message },
  };
}

export interface ResponseValidation {
  valid: boolean;
  errors: string[];
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const HASH_RE = /^0x[0-9a-f]{64}$/;
const OVERCLAIM_RE =
  /\b(mainnet-ready|production custody|production-ready|quantum-proof|quantum proof|quantum-safe|guaranteed|insured|real yield|\bapy\b)/i;

const TOP_KEYS = [
  "schema",
  "service",
  "mode",
  "status",
  "ok",
  "contentType",
  "servedAt",
  "etag",
  "adapter",
  "limitations",
  "regeneration",
];
const REGEN_KEYS = ["command", "deterministic"];

const REQUIRED_LIMITATION_TOPICS: { label: string; re: RegExp }[] = [
  { label: "spike / non-production", re: /spike|non-production/ },
  { label: "read-only", re: /read-only/ },
  { label: "gated / off-chain served evidence", re: /gated|off-chain/ },
  { label: "not audited", re: /not audited/ },
  { label: "testnet / reference path only", re: /testnet/ },
  { label: "no real funds", re: /no real funds/ },
];

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}
function rejectUnknownKeys(obj: unknown, allowed: readonly string[], path: string, errors: string[]): void {
  if (typeof obj !== "object" || obj === null) return;
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) errors.push(`unexpected key in ${path}: ${k}`);
  }
}

/**
 * Strictly validate the canonical 200 success response (pure; no filesystem).
 *
 * Verifies the served-evidence shape, that the `etag` is keccak256 of the embedded
 * adapter, that the embedded adapter itself is valid (reuses validateAdapter),
 * limitation coverage, and the absence of overclaim language on asserted surfaces.
 */
export function validateAdapterEvidenceResponse(value: unknown): ResponseValidation {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, errors: ["response must be an object"] };
  }
  const a = value as Record<string, unknown>;
  rejectUnknownKeys(a, TOP_KEYS, "response", errors);

  if (a.schema !== ZK_ADAPTER_RESPONSE_SCHEMA) errors.push(`schema must be ${ZK_ADAPTER_RESPONSE_SCHEMA}`);
  if (a.service !== ZK_ENDPOINT_SERVICE) errors.push(`service must be ${ZK_ENDPOINT_SERVICE}`);
  if (a.mode !== ZK_ENDPOINT_MODE) errors.push(`mode must be ${ZK_ENDPOINT_MODE}`);
  if (a.status !== ZK_ENDPOINT_STATUS.OK) errors.push("status must be 200");
  if (a.ok !== true) errors.push("ok must be true");
  if (a.contentType !== ZK_ENDPOINT_CONTENT_TYPE) errors.push(`contentType must be ${ZK_ENDPOINT_CONTENT_TYPE}`);
  if (typeof a.servedAt !== "string" || !ISO_RE.test(a.servedAt) || Number.isNaN(Date.parse(a.servedAt))) {
    errors.push("servedAt must be an ISO-8601 UTC timestamp");
  }

  // The embedded adapter must itself be a valid ZK verifier adapter boundary.
  const adapterValidation = validateAdapter(a.adapter);
  if (!adapterValidation.valid) {
    for (const e of adapterValidation.errors) errors.push(`adapter.${e}`);
  }

  // etag must be the keccak256 content hash of the embedded adapter.
  if (typeof a.etag !== "string" || !HASH_RE.test(a.etag)) {
    errors.push("etag must be a 0x keccak256 hash");
  } else if (adapterValidation.valid && a.etag !== computeAdapterETag(a.adapter as ZKVerifierAdapter)) {
    errors.push("etag must be keccak256 of the served adapter");
  }

  const limitations = a.limitations;
  if (!Array.isArray(limitations) || limitations.length === 0) {
    errors.push("limitations must be a non-empty array of strings");
  } else if (!limitations.every((l) => isNonEmptyString(l))) {
    errors.push("limitations[] must each be a non-empty string");
  } else {
    const blob = limitations.join(" ").toLowerCase();
    for (const topic of REQUIRED_LIMITATION_TOPICS) {
      if (!topic.re.test(blob)) errors.push(`limitations must disclose: ${topic.label}`);
    }
  }

  const regen = a.regeneration as Record<string, unknown> | undefined;
  if (!regen || typeof regen !== "object") {
    errors.push("regeneration must be an object");
  } else {
    rejectUnknownKeys(regen, REGEN_KEYS, "regeneration", errors);
    if (!isNonEmptyString(regen.command)) errors.push("regeneration.command must be a non-empty string");
    if (regen.deterministic !== true) errors.push("regeneration.deterministic must be true");
  }

  // No overclaim language on the endpoint's own asserted surfaces. The embedded
  // `adapter` (already validated, and whose limitations negate these terms) and
  // the response `limitations` are excluded to avoid false-flagging negations.
  const assertedSurface = JSON.stringify({ ...a, adapter: undefined, limitations: undefined });
  if (OVERCLAIM_RE.test(assertedSurface)) {
    errors.push("response must not contain production/mainnet/custody/quantum-proof/yield overclaim language");
  }

  return { valid: errors.length === 0, errors };
}

/** Type-guard form of {@link validateAdapterEvidenceResponse}. */
export function isZKAdapterEvidenceResponse(value: unknown): value is ZKAdapterEvidenceResponse {
  return validateAdapterEvidenceResponse(value).valid;
}
