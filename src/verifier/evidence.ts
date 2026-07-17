/**
 * Open PQ verifier — app-consumable evidence artifact.
 *
 * The pure verifier ({@link verifyMLDSA65Detailed}) returns a deterministic
 * {@link PQVerificationResult} that carries only keccak256 hashes of the inputs.
 * This module wraps that result in a stable, timestamped *evidence envelope* the
 * private WalletWall app (or any third party) can store and display read-only,
 * plus a dependency-free validator so consumers can reject anything malformed or
 * carrying raw key material.
 *
 * Design:
 *   - The deterministic verification result is nested verbatim under
 *     `verification`. The envelope adds `generatedAt` (the single
 *     non-deterministic field), an optional safe `source` reference, and an
 *     optional `standards` snapshot from the canonical PQ algorithm registry
 *     (src/standards/pq-algorithm-registry.ts) recording conformance,
 *     certification, and production-readiness status. Absence of `standards`
 *     (e.g. on legacy evidence) must never be read as a positive claim.
 *   - The envelope NEVER contains raw message, public-key, or signature bytes —
 *     only the hashes already present in the inner result. {@link buildEvidence}
 *     and {@link validateEvidence} both defend against accidentally embedding raw
 *     material (any hex run longer than a 32-byte hash is rejected).
 *   - This is verification evidence only. It is NOT a signature, NOT an
 *     attestation, NOT a ZK proof, and NOT on-chain verification. It does not
 *     custody funds.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import type { PQReason, PQVerificationResult } from "./schema";
// Namespace import of the dependency-free schema leaf; mirrors result.ts.
// @ts-expect-error ts-node ESM requires the explicit extension.
import * as schema from "./schema.ts";

import type {
  PQAlgorithmId,
  PQAlgorithmRecord,
  PQCertificationStatus,
  PQConformanceStatus,
  PQImplementationRef,
  PQProductionStatus,
  PQStandard,
  PQVerificationMode,
} from "../standards/pq-algorithm-registry";
// Namespace import of the dependency-free standards registry; mirrors the
// schema import above (ts-node ESM requires the explicit extension).
// @ts-expect-error ts-node ESM requires the explicit extension.
import * as standards from "../standards/pq-algorithm-registry.ts";

const {
  PQ_REASON,
  PQ_VERIFIER_ALGORITHM,
  PQ_VERIFIER_FIPS,
  PQ_VERIFIER_MODE,
  PQ_VERIFIER_NAME,
  PQ_VERIFIER_SCHEMA_VERSION,
} = schema;

const {
  PQ_ALGORITHM_IDS,
  PQ_STANDARDS,
  PQ_VERIFICATION_MODES,
  PQ_CONFORMANCE_STATUSES,
  PQ_CERTIFICATION_STATUSES,
  PQ_PRODUCTION_STATUSES,
  getPQAlgorithmRecord,
} = standards;

/** Stable evidence-envelope schema identifier. Bump only on a breaking change. */
export const PQ_EVIDENCE_SCHEMA_VERSION = "walletwall.pq-verifier-evidence.v1";

/** Closed set of source-reference kinds that are safe to embed. */
export const PQ_EVIDENCE_SOURCE_TYPES = ["nist-acvp", "library-generated", "operator-supplied"] as const;
export type PQEvidenceSourceType = (typeof PQ_EVIDENCE_SOURCE_TYPES)[number];

/**
 * Optional, safe provenance reference for the verified material. `reference` is a
 * short human-readable label (e.g. "NIST ACVP ML-DSA-65 sigVer tcId 35"); it must
 * not embed raw key/signature material.
 */
export interface PQEvidenceSource {
  type: PQEvidenceSourceType;
  reference: string;
}

/**
 * Standards-alignment snapshot, taken at evidence-generation time, of this
 * algorithm's canonical registry entry
 * (src/standards/pq-algorithm-registry.ts). Optional and purely additive.
 *
 * Absence must be read as "no standards metadata available" — a consumer
 * must never infer validation, certification, or production readiness from
 * a missing `standards` block. See {@link toEvidenceStandardsMetadata}.
 */
export interface PQEvidenceStandardsMetadata {
  algorithm: PQAlgorithmId;
  parameterSet: string | null;
  standard: PQStandard;
  implementation: PQImplementationRef;
  verificationMode: PQVerificationMode;
  conformanceStatus: PQConformanceStatus;
  certificationStatus: PQCertificationStatus;
  productionStatus: PQProductionStatus;
}

/**
 * Stable, app-consumable evidence artifact.
 *
 * `verification` is the deterministic inner result (its own
 * `walletwall.pq-verifier.v1` schema). `generatedAt` is an ISO-8601 UTC instant
 * and is the only non-deterministic field. `source` is optional provenance.
 * `standards` is an optional standards-alignment snapshot (see
 * {@link PQEvidenceStandardsMetadata}); legacy evidence generated before this
 * field existed simply omits it.
 */
export interface PQVerificationEvidence {
  schema: typeof PQ_EVIDENCE_SCHEMA_VERSION;
  generatedAt: string;
  verification: PQVerificationResult;
  source?: PQEvidenceSource;
  standards?: PQEvidenceStandardsMetadata;
}

/**
 * Project a canonical registry record into the narrower per-evidence
 * standards-metadata shape, for a given verification mode.
 */
export function toEvidenceStandardsMetadata(
  record: PQAlgorithmRecord,
  verificationMode: PQVerificationMode,
): PQEvidenceStandardsMetadata {
  return {
    algorithm: record.algorithm,
    parameterSet: record.parameterSet,
    standard: record.standard,
    implementation: { ...record.implementation },
    verificationMode,
    conformanceStatus: record.conformanceStatus,
    certificationStatus: record.certificationStatus,
    productionStatus: record.productionStatus,
  };
}

/** Result of {@link validateEvidence}. */
export interface EvidenceValidation {
  valid: boolean;
  errors: string[];
}

const HASH_RE = /^0x[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
// Any 0x hex run longer than a 32-byte (64 nibble) hash would mean raw key or
// signature material slipped in. The envelope must only ever carry hashes.
const RAW_MATERIAL_RE = /0x[0-9a-fA-F]{65,}/;

const ALLOWED_REASONS = new Set<string>(Object.values(PQ_REASON));

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === "string" && ISO_RE.test(value) && !Number.isNaN(Date.parse(value));
}

/**
 * Build an evidence envelope around a verification result.
 *
 * @param verification deterministic result from {@link verifyMLDSA65Detailed}.
 * @param opts.generatedAt fixed timestamp (Date or ISO string); defaults to now.
 *   Pass a fixed value to produce deterministic fixtures/examples.
 * @param opts.source optional safe provenance reference.
 * @param opts.standards standards-alignment snapshot; defaults to the
 *   canonical ML-DSA-65 registry record (this verifier's only algorithm) at
 *   `verificationMode: "off-chain"`. Pass `null` to omit the field entirely
 *   (e.g. to reproduce pre-standards-metadata legacy evidence in a fixture).
 * @throws if `source.reference` would embed raw key/signature material.
 */
export function buildEvidence(
  verification: PQVerificationResult,
  opts: {
    generatedAt?: string | Date;
    source?: PQEvidenceSource;
    standards?: PQEvidenceStandardsMetadata | null;
  } = {},
): PQVerificationEvidence {
  const generatedAt =
    opts.generatedAt instanceof Date ? opts.generatedAt.toISOString() : (opts.generatedAt ?? new Date().toISOString());

  const evidence: PQVerificationEvidence = {
    schema: PQ_EVIDENCE_SCHEMA_VERSION,
    generatedAt,
    verification,
  };
  if (opts.source) {
    if (RAW_MATERIAL_RE.test(opts.source.reference)) {
      throw new Error("source.reference must not embed raw key/signature material");
    }
    evidence.source = { type: opts.source.type, reference: opts.source.reference };
  }
  if (opts.standards !== null) {
    evidence.standards = opts.standards ?? toEvidenceStandardsMetadata(getPQAlgorithmRecord("ML-DSA"), "off-chain");
  }
  return evidence;
}

/** Validate the nested deterministic verification result. Pushes into `errors`. */
function validateVerification(v: unknown, errors: string[]): void {
  if (typeof v !== "object" || v === null) {
    errors.push("verification must be an object");
    return;
  }
  const r = v as Record<string, unknown>;

  // Reject unknown keys at the verification level. The JSON Schema declares
  // additionalProperties:false at every object level; this authoritative TS
  // validator must match it (mirrors the proof-artifact validator's stance).
  const allowedVerificationKeys = new Set([
    "schemaVersion",
    "verifier",
    "algorithm",
    "fips",
    "mode",
    "input",
    "result",
  ]);
  for (const k of Object.keys(r)) {
    if (!allowedVerificationKeys.has(k)) errors.push(`verification has unexpected key: ${k}`);
  }

  if (r.schemaVersion !== PQ_VERIFIER_SCHEMA_VERSION) {
    errors.push(`verification.schemaVersion must be ${PQ_VERIFIER_SCHEMA_VERSION}`);
  }
  const verifier = r.verifier as Record<string, unknown> | undefined;
  if (!verifier || verifier.name !== PQ_VERIFIER_NAME || typeof verifier.version !== "string") {
    errors.push("verification.verifier must be { name, version:string }");
  }
  if (verifier && typeof verifier === "object") {
    for (const k of Object.keys(verifier)) {
      if (k !== "name" && k !== "version") errors.push(`verification.verifier has unexpected key: ${k}`);
    }
  }
  if (r.algorithm !== PQ_VERIFIER_ALGORITHM) errors.push(`verification.algorithm must be ${PQ_VERIFIER_ALGORITHM}`);
  if (r.fips !== PQ_VERIFIER_FIPS) errors.push(`verification.fips must be ${PQ_VERIFIER_FIPS}`);
  if (r.mode !== PQ_VERIFIER_MODE) errors.push(`verification.mode must be ${PQ_VERIFIER_MODE}`);

  const input = r.input as Record<string, unknown> | undefined;
  if (!input) {
    errors.push("verification.input is required");
  } else {
    const inputKeys = Object.keys(input).sort();
    if (inputKeys.join(",") !== "messageHash,publicKeyHash,signatureHash") {
      errors.push("verification.input must have exactly messageHash, publicKeyHash, signatureHash");
    }
    for (const k of ["messageHash", "publicKeyHash", "signatureHash"] as const) {
      if (typeof input[k] !== "string" || !HASH_RE.test(input[k] as string)) {
        errors.push(`verification.input.${k} must be a 0x keccak256 hash`);
      }
    }
  }

  const result = r.result as Record<string, unknown> | undefined;
  if (!result || typeof result.verified !== "boolean" || typeof result.reason !== "string") {
    errors.push("verification.result must be { verified:boolean, reason:string }");
    return;
  }
  for (const k of Object.keys(result)) {
    if (k !== "verified" && k !== "reason") errors.push(`verification.result has unexpected key: ${k}`);
  }
  if (!ALLOWED_REASONS.has(result.reason)) {
    errors.push(`verification.result.reason must be one of ${[...ALLOWED_REASONS].join(", ")}`);
  }
  // verified <=> ML_DSA_65_VALID. Any other pairing is internally inconsistent.
  const isValidReason = result.reason === PQ_REASON.ML_DSA_65_VALID;
  if (result.verified !== isValidReason) {
    errors.push("verification.result.verified must be true iff reason is ML_DSA_65_VALID");
  }
}

/**
 * Validate an optional `standards` block. Unlike `source` (also optional),
 * a *present but malformed* `standards` block is always an error — it must
 * never be silently downgraded into an implicit "no metadata" pass, since
 * that would let a caller ship a broken/spoofed standards claim that reads
 * as absent rather than rejected.
 */
function validateStandardsMetadata(v: unknown, errors: string[]): void {
  if (typeof v !== "object" || v === null) {
    errors.push("standards must be an object when present");
    return;
  }
  const s = v as Record<string, unknown>;

  const allowedStandardsKeys = new Set([
    "algorithm",
    "parameterSet",
    "standard",
    "implementation",
    "verificationMode",
    "conformanceStatus",
    "certificationStatus",
    "productionStatus",
  ]);
  for (const k of Object.keys(s)) {
    if (!allowedStandardsKeys.has(k)) errors.push(`standards has unexpected key: ${k}`);
  }

  if (!(PQ_ALGORITHM_IDS as readonly string[]).includes(s.algorithm as string)) {
    errors.push(`standards.algorithm must be one of ${PQ_ALGORITHM_IDS.join(", ")}`);
  }
  if (s.parameterSet !== null && typeof s.parameterSet !== "string") {
    errors.push("standards.parameterSet must be a string or null");
  }
  if (!(PQ_STANDARDS as readonly string[]).includes(s.standard as string)) {
    errors.push(`standards.standard must be one of ${PQ_STANDARDS.join(", ")}`);
  }
  if (!(PQ_VERIFICATION_MODES as readonly string[]).includes(s.verificationMode as string)) {
    errors.push(`standards.verificationMode must be one of ${PQ_VERIFICATION_MODES.join(", ")}`);
  }
  if (!(PQ_CONFORMANCE_STATUSES as readonly string[]).includes(s.conformanceStatus as string)) {
    errors.push(`standards.conformanceStatus must be one of ${PQ_CONFORMANCE_STATUSES.join(", ")}`);
  }
  if (!(PQ_CERTIFICATION_STATUSES as readonly string[]).includes(s.certificationStatus as string)) {
    errors.push(`standards.certificationStatus must be one of ${PQ_CERTIFICATION_STATUSES.join(", ")}`);
  }
  if (!(PQ_PRODUCTION_STATUSES as readonly string[]).includes(s.productionStatus as string)) {
    errors.push(`standards.productionStatus must be one of ${PQ_PRODUCTION_STATUSES.join(", ")}`);
  }

  const impl = s.implementation as Record<string, unknown> | undefined;
  if (typeof impl !== "object" || impl === null) {
    errors.push("standards.implementation must be an object");
  } else {
    const implKeys = Object.keys(impl).sort();
    if (implKeys.join(",") !== "package,provider,version") {
      errors.push("standards.implementation must have exactly { provider, package, version }");
    }
    for (const k of ["provider", "package", "version"] as const) {
      if (impl[k] !== null && typeof impl[k] !== "string") {
        errors.push(`standards.implementation.${k} must be a string or null`);
      }
    }
  }
}

/**
 * Validate an evidence artifact against the stable schema.
 *
 * Strict: rejects unknown top-level keys, malformed hashes, unknown reason codes,
 * an inconsistent verified/reason pairing, a bad timestamp, and — as defense in
 * depth — any embedded raw key/signature material.
 */
export function validateEvidence(value: unknown): EvidenceValidation {
  const errors: string[] = [];

  if (typeof value !== "object" || value === null) {
    return { valid: false, errors: ["evidence must be an object"] };
  }
  const e = value as Record<string, unknown>;

  const topKeys = Object.keys(e).sort();
  const allowedTop = new Set(["schema", "generatedAt", "verification", "source", "standards"]);
  for (const k of topKeys) {
    if (!allowedTop.has(k)) errors.push(`unexpected top-level key: ${k}`);
  }

  if (e.schema !== PQ_EVIDENCE_SCHEMA_VERSION) errors.push(`schema must be ${PQ_EVIDENCE_SCHEMA_VERSION}`);
  if (!isIsoTimestamp(e.generatedAt)) errors.push("generatedAt must be an ISO-8601 UTC timestamp");

  validateVerification(e.verification, errors);

  if (e.source !== undefined) {
    const s = e.source as Record<string, unknown>;
    const sourceKeys = Object.keys(s).sort();
    if (sourceKeys.join(",") !== "reference,type") {
      errors.push("source must have exactly { type, reference }");
    }
    if (typeof s.type !== "string" || !PQ_EVIDENCE_SOURCE_TYPES.includes(s.type as PQEvidenceSourceType)) {
      errors.push(`source.type must be one of ${PQ_EVIDENCE_SOURCE_TYPES.join(", ")}`);
    }
    if (typeof s.reference !== "string" || s.reference.length === 0) {
      errors.push("source.reference must be a non-empty string");
    }
  }

  // `standards` is optional (legacy evidence omits it entirely — that is
  // valid), but if present it must be well-formed; a malformed block is
  // always rejected, never silently treated as absent.
  if (e.standards !== undefined) {
    validateStandardsMetadata(e.standards, errors);
  }

  // Defense in depth: no raw key/signature material anywhere in the artifact.
  if (RAW_MATERIAL_RE.test(JSON.stringify(value))) {
    errors.push("artifact must not contain raw key/signature material (hex longer than a 32-byte hash)");
  }

  return { valid: errors.length === 0, errors };
}

/** Type guard form of {@link validateEvidence}. */
export function isPQVerificationEvidence(value: unknown): value is PQVerificationEvidence {
  return validateEvidence(value).valid;
}

export type { PQReason };
