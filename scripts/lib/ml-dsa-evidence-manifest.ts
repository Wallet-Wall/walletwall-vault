/**
 * ML-DSA evidence artifact manifest (builder + pure validator).
 *
 * This module produces and validates a deterministic, machine-checkable
 * *manifest* that records the current ML-DSA / post-quantum EVIDENCE BOUNDARY of
 * this repository in one app-consumable place. It is an INDEX over the
 * already-committed, drift-checked ML-DSA evidence artifacts (the
 * `walletwall.pq-verifier-evidence.v1` examples and the deterministic
 * library-generated ML-DSA-65 fixture), recording for each one:
 *
 *   - its fixture identity and provenance (NIST ACVP / library-generated),
 *   - the ML-DSA-65 (FIPS 204) parameter set it exercises,
 *   - keccak256 hashes of the message, public key, and signature (never the raw
 *     bytes),
 *   - the off-chain verification result (accepted / rejected + reason code),
 *   - the integrity hash (keccak256) of the referenced artifact file.
 *
 * On top of the per-entry index it records the boundary the whole evidence set
 * lives within — off-chain verification, a trusted-attestor on-chain path, a
 * mock on-chain verifier, and no custody — plus an explicit limitations list.
 *
 * What it is / is NOT:
 *   - It IS read-only evidence the private WalletWall app may reference and
 *     display. It captures HASHES and boundary facts only.
 *   - It is NOT a signature, NOT an attestation, NOT a ZK proof, and NOT
 *     on-chain ML-DSA verification. It makes no production-custody, mainnet, or
 *     "quantum-proof" claim. The evidence is off-chain and the active on-chain
 *     verifier is a mock.
 *
 * The manifest is the INPUT CONTRACT a follow-up Rust/SP1 proof-input scaffold
 * can consume or mirror. `validateManifest` is pure (no filesystem): it checks
 * shape, boundary marking, limitations coverage, internal consistency, the
 * absence of overclaim language, and that no raw key/signature material is
 * embedded. The generator
 * ({@link ../generate-mldsa-evidence-manifest}) adds the on-disk drift and
 * artifact-integrity cross-checks.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import {
  PQ_REASON,
  PQ_VERIFIER_ALGORITHM,
  PQ_VERIFIER_FIPS,
  PQ_VERIFIER_MODE,
  PQ_VERIFIER_NAME,
} from "../../src/verifier/schema";
import type { PQReason } from "../../src/verifier/schema";

/** Stable manifest schema identifier. Bump only on a breaking shape change. */
export const ML_DSA_EVIDENCE_MANIFEST_SCHEMA = "walletwall.ml-dsa-evidence-manifest.v1";

/** Single artifact type this module emits. */
export const ML_DSA_EVIDENCE_ARTIFACT_TYPE = "ml-dsa-evidence-manifest";

/** Kinds of ML-DSA evidence an entry may reference. */
export const ML_DSA_EVIDENCE_KINDS = ["pq-verifier-evidence", "test-vector"] as const;
export type MLDSAEvidenceKind = (typeof ML_DSA_EVIDENCE_KINDS)[number];

/** Provenance kinds, mirroring the PQ verifier evidence envelope's source types. */
export const ML_DSA_EVIDENCE_SOURCE_TYPES = ["nist-acvp", "library-generated", "operator-supplied"] as const;
export type MLDSAEvidenceSourceType = (typeof ML_DSA_EVIDENCE_SOURCE_TYPES)[number];

/** Closed boundary vocabulary. These mark, machine-checkably, where the evidence lives. */
export const ML_DSA_BOUNDARY = {
  /** ML-DSA verification happens off-chain (the open pure verifier), never on-chain. */
  verificationMode: "off-chain",
  /** The non-mock on-chain path trusts an authorized EIP-712 attestor; it does not run ML-DSA. */
  attestation: "trusted-attestor",
  /** No native or ZK on-chain ML-DSA verification exists. */
  onChainMLDSAVerification: false,
  /** The active testnet on-chain verifier is a mock (no real ML-DSA verification). */
  onChainVerifierIsMock: true,
  /** This repository does not custody funds. */
  custody: false,
} as const;

/**
 * Canonical, honest limitations for the ML-DSA evidence boundary. Every required
 * disclosure topic the validator enforces is present here.
 */
export const ML_DSA_EVIDENCE_LIMITATIONS: readonly string[] = [
  "Off-chain post-quantum verification only — ML-DSA-65 signatures are verified off-chain by the open pure verifier, not on-chain.",
  "Trusted-attestor boundary — the non-mock AttestationPQCVerifier trusts an authorized EIP-712 attestor and does not execute ML-DSA on-chain.",
  "Mock verifier limitations — the active testnet on-chain verifier is a mock that performs no real ML-DSA verification.",
  "Research prototype — not audited.",
  "Testnet / reference path only — no mainnet deployment and no production custody.",
  "No real funds — every referenced artifact is deterministic test/fixture material.",
];

/** Static algorithm + verifier metadata every manifest carries. */
export const ML_DSA_EVIDENCE_ALGORITHM = {
  parameterSet: PQ_VERIFIER_ALGORITHM,
  fips: PQ_VERIFIER_FIPS,
} as const;

export const ML_DSA_EVIDENCE_VERIFIER = {
  name: PQ_VERIFIER_NAME,
  // The open verifier reports its own contract version (see src/verifier/schema.ts);
  // it is intentionally decoupled from the repository's package.json version.
  version: "0.1.0",
  mode: PQ_VERIFIER_MODE,
} as const;

export interface MLDSAEvidenceResult {
  /** True iff the off-chain verifier accepted the signature. */
  accepted: boolean;
  /** Closed reason code from the open verifier. */
  reason: PQReason;
}

export interface MLDSAEvidenceEntry {
  /** Stable, human-readable identifier for this evidence entry. */
  id: string;
  kind: MLDSAEvidenceKind;
  sourceType: MLDSAEvidenceSourceType;
  /** Short provenance label (no raw key/signature material). */
  reference: string;
  parameterSet: typeof PQ_VERIFIER_ALGORITHM;
  /** Mode of the off-chain verifier that produced the result (always pure here). */
  verifierMode: typeof PQ_VERIFIER_MODE;
  /** keccak256 of the message bytes. */
  messageHash: string;
  /** keccak256 of the public-key bytes (the public-key fingerprint). */
  publicKeyHash: string;
  /** keccak256 of the signature bytes (the signature / test-vector digest). */
  signatureHash: string;
  result: MLDSAEvidenceResult;
  /** Repo-relative path to the referenced evidence artifact file. */
  artifactPath: string;
  /** keccak256 of the referenced artifact file's bytes (integrity hash). */
  artifactHash: string;
}

export interface MLDSAEvidenceManifest {
  schema: typeof ML_DSA_EVIDENCE_MANIFEST_SCHEMA;
  artifactType: typeof ML_DSA_EVIDENCE_ARTIFACT_TYPE;
  /** ISO-8601 UTC instant; the only non-deterministic field. */
  generatedAt: string;
  algorithm: typeof ML_DSA_EVIDENCE_ALGORITHM;
  verifier: typeof ML_DSA_EVIDENCE_VERIFIER;
  boundary: typeof ML_DSA_BOUNDARY;
  evidence: MLDSAEvidenceEntry[];
  limitations: string[];
  regeneration: {
    command: string;
    deterministic: boolean;
  };
}

export interface BuildManifestOptions {
  generatedAt?: string | Date;
  command?: string;
}

/**
 * Assemble the manifest envelope around already-derived evidence entries.
 *
 * Pure: it copies in the canonical algorithm/verifier/boundary/limitations
 * constants and the supplied entries. All non-trivial derivation (reading the
 * committed artifacts, hashing them, running the verifier) happens in the
 * generator so this stays a deterministic, side-effect-free assembler.
 */
export function buildManifest(entries: MLDSAEvidenceEntry[], opts: BuildManifestOptions = {}): MLDSAEvidenceManifest {
  const generatedAt =
    opts.generatedAt instanceof Date ? opts.generatedAt.toISOString() : (opts.generatedAt ?? new Date().toISOString());

  return {
    schema: ML_DSA_EVIDENCE_MANIFEST_SCHEMA,
    artifactType: ML_DSA_EVIDENCE_ARTIFACT_TYPE,
    generatedAt,
    algorithm: ML_DSA_EVIDENCE_ALGORITHM,
    verifier: ML_DSA_EVIDENCE_VERIFIER,
    boundary: ML_DSA_BOUNDARY,
    evidence: entries,
    limitations: [...ML_DSA_EVIDENCE_LIMITATIONS],
    regeneration: {
      command: opts.command ?? "npm run evidence:manifest",
      deterministic: true,
    },
  };
}

export interface ManifestValidation {
  valid: boolean;
  errors: string[];
}

const HASH_RE = /^0x[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
// Any 0x hex run longer than a 32-byte (64 nibble) hash would mean raw key or
// signature material slipped in. The manifest must only ever carry hashes.
const RAW_MATERIAL_RE = /0x[0-9a-fA-F]{65,}/;

const KINDS = new Set<string>(ML_DSA_EVIDENCE_KINDS);
const SOURCE_TYPES = new Set<string>(ML_DSA_EVIDENCE_SOURCE_TYPES);
const ALLOWED_REASONS = new Set<string>(Object.values(PQ_REASON));

/**
 * Overclaim guard. These phrases must never appear anywhere in the manifest. The
 * list is deliberately specific (not bare "audited" / "yield" / "secure") so it
 * never false-flags the repository's honest negations ("not audited",
 * "no real yield"). Each disclosure topic is enforced positively via
 * {@link ML_DSA_EVIDENCE_LIMITATIONS} coverage instead.
 */
const OVERCLAIM_RE =
  /\b(mainnet-ready|production custody|production-ready|quantum-proof|quantum proof|quantum-safe|guaranteed|insured|real yield|\bapy\b)/i;

/** Topics every manifest's limitations must collectively disclose. */
const REQUIRED_LIMITATION_TOPICS: { label: string; re: RegExp }[] = [
  { label: "off-chain verification", re: /off-chain/ },
  { label: "trusted-attestor boundary", re: /trusted.?attestor/ },
  { label: "mock verifier", re: /\bmock\b/ },
  { label: "not audited", re: /not audited/ },
  { label: "testnet / reference path only", re: /testnet/ },
  { label: "no real funds", re: /no real funds/ },
];

function isHash(v: unknown): v is string {
  return typeof v === "string" && HASH_RE.test(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

/** Push an error for every own key of `obj` not in `allowed`. No-ops for non-objects. */
function rejectUnknownKeys(obj: unknown, allowed: readonly string[], path: string, errors: string[]): void {
  if (typeof obj !== "object" || obj === null) return;
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) errors.push(`unexpected key in ${path}: ${k}`);
  }
}

const TOP_KEYS = [
  "schema",
  "artifactType",
  "generatedAt",
  "algorithm",
  "verifier",
  "boundary",
  "evidence",
  "limitations",
  "regeneration",
];
const ALGORITHM_KEYS = ["parameterSet", "fips"];
const VERIFIER_KEYS = ["name", "version", "mode"];
const BOUNDARY_KEYS = [
  "verificationMode",
  "attestation",
  "onChainMLDSAVerification",
  "onChainVerifierIsMock",
  "custody",
];
const ENTRY_KEYS = [
  "id",
  "kind",
  "sourceType",
  "reference",
  "parameterSet",
  "verifierMode",
  "messageHash",
  "publicKeyHash",
  "signatureHash",
  "result",
  "artifactPath",
  "artifactHash",
];
const RESULT_KEYS = ["accepted", "reason"];
const REGEN_KEYS = ["command", "deterministic"];

/** Validate a single evidence entry into `errors`. */
function validateEntry(value: unknown, index: number, errors: string[]): void {
  const where = `evidence[${index}]`;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    errors.push(`${where} must be an object`);
    return;
  }
  const e = value as Record<string, unknown>;
  rejectUnknownKeys(e, ENTRY_KEYS, where, errors);

  if (!isNonEmptyString(e.id)) errors.push(`${where}.id must be a non-empty string`);
  if (typeof e.kind !== "string" || !KINDS.has(e.kind)) {
    errors.push(`${where}.kind must be one of ${[...KINDS].join(", ")}`);
  }
  if (typeof e.sourceType !== "string" || !SOURCE_TYPES.has(e.sourceType)) {
    errors.push(`${where}.sourceType must be one of ${[...SOURCE_TYPES].join(", ")}`);
  }
  if (!isNonEmptyString(e.reference)) errors.push(`${where}.reference must be a non-empty string`);
  if (e.parameterSet !== PQ_VERIFIER_ALGORITHM) errors.push(`${where}.parameterSet must be ${PQ_VERIFIER_ALGORITHM}`);
  if (e.verifierMode !== PQ_VERIFIER_MODE) errors.push(`${where}.verifierMode must be ${PQ_VERIFIER_MODE}`);

  for (const k of ["messageHash", "publicKeyHash", "signatureHash", "artifactHash"] as const) {
    if (!isHash(e[k])) errors.push(`${where}.${k} must be a 0x keccak256 hash`);
  }

  if (!isNonEmptyString(e.artifactPath)) {
    errors.push(`${where}.artifactPath must be a non-empty string`);
  } else {
    const p = e.artifactPath as string;
    // App-referenceable, repo-relative path only. No absolute paths or traversal.
    if (p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p) || p.includes("..")) {
      errors.push(`${where}.artifactPath must be a repo-relative path without traversal`);
    }
  }

  const result = e.result as Record<string, unknown> | undefined;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    errors.push(`${where}.result must be an object { accepted, reason }`);
    return;
  }
  rejectUnknownKeys(result, RESULT_KEYS, `${where}.result`, errors);
  if (typeof result.accepted !== "boolean") errors.push(`${where}.result.accepted must be a boolean`);
  if (typeof result.reason !== "string" || !ALLOWED_REASONS.has(result.reason)) {
    errors.push(`${where}.result.reason must be one of ${[...ALLOWED_REASONS].join(", ")}`);
  }
  // accepted <=> ML_DSA_65_VALID. Any other pairing is internally inconsistent.
  if (typeof result.accepted === "boolean" && typeof result.reason === "string") {
    const shouldAccept = result.reason === PQ_REASON.ML_DSA_65_VALID;
    if (result.accepted !== shouldAccept) {
      errors.push(`${where}.result.accepted must be true iff reason is ML_DSA_65_VALID`);
    }
  }
}

/**
 * Strictly validate an ML-DSA evidence manifest (pure; no filesystem).
 *
 * Rejects unknown keys at every object level, malformed hashes/timestamps, a
 * missing or under-marked boundary, missing limitation topics, an inconsistent
 * accepted/reason pairing, overclaim language, and any embedded raw
 * key/signature material.
 */
export function validateManifest(value: unknown): ManifestValidation {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, errors: ["manifest must be an object"] };
  }
  const m = value as Record<string, unknown>;
  rejectUnknownKeys(m, TOP_KEYS, "manifest", errors);

  if (m.schema !== ML_DSA_EVIDENCE_MANIFEST_SCHEMA) errors.push(`schema must be ${ML_DSA_EVIDENCE_MANIFEST_SCHEMA}`);
  if (m.artifactType !== ML_DSA_EVIDENCE_ARTIFACT_TYPE) {
    errors.push(`artifactType must be ${ML_DSA_EVIDENCE_ARTIFACT_TYPE}`);
  }
  if (typeof m.generatedAt !== "string" || !ISO_RE.test(m.generatedAt) || Number.isNaN(Date.parse(m.generatedAt))) {
    errors.push("generatedAt must be an ISO-8601 UTC timestamp");
  }

  const algorithm = m.algorithm as Record<string, unknown> | undefined;
  if (!algorithm || typeof algorithm !== "object") {
    errors.push("algorithm must be an object");
  } else {
    rejectUnknownKeys(algorithm, ALGORITHM_KEYS, "algorithm", errors);
    if (algorithm.parameterSet !== PQ_VERIFIER_ALGORITHM)
      errors.push(`algorithm.parameterSet must be ${PQ_VERIFIER_ALGORITHM}`);
    if (algorithm.fips !== PQ_VERIFIER_FIPS) errors.push(`algorithm.fips must be ${PQ_VERIFIER_FIPS}`);
  }

  const verifier = m.verifier as Record<string, unknown> | undefined;
  if (!verifier || typeof verifier !== "object") {
    errors.push("verifier must be an object");
  } else {
    rejectUnknownKeys(verifier, VERIFIER_KEYS, "verifier", errors);
    if (verifier.name !== PQ_VERIFIER_NAME) errors.push(`verifier.name must be ${PQ_VERIFIER_NAME}`);
    if (!isNonEmptyString(verifier.version)) errors.push("verifier.version must be a non-empty string");
    if (verifier.mode !== PQ_VERIFIER_MODE) errors.push(`verifier.mode must be ${PQ_VERIFIER_MODE}`);
  }

  // Boundary must be present AND clearly marked: off-chain, trusted-attestor,
  // no on-chain ML-DSA verification, mock on-chain verifier, no custody.
  const boundary = m.boundary as Record<string, unknown> | undefined;
  if (!boundary || typeof boundary !== "object") {
    errors.push("boundary must be an object");
  } else {
    rejectUnknownKeys(boundary, BOUNDARY_KEYS, "boundary", errors);
    if (boundary.verificationMode !== ML_DSA_BOUNDARY.verificationMode) {
      errors.push(`boundary.verificationMode must be "${ML_DSA_BOUNDARY.verificationMode}"`);
    }
    if (boundary.attestation !== ML_DSA_BOUNDARY.attestation) {
      errors.push(`boundary.attestation must be "${ML_DSA_BOUNDARY.attestation}"`);
    }
    if (boundary.onChainMLDSAVerification !== false) {
      errors.push("boundary.onChainMLDSAVerification must be false (no on-chain ML-DSA verification)");
    }
    if (boundary.onChainVerifierIsMock !== true) {
      errors.push("boundary.onChainVerifierIsMock must be true (active on-chain verifier is a mock)");
    }
    if (boundary.custody !== false) {
      errors.push("boundary.custody must be false (no custody)");
    }
  }

  const evidence = m.evidence;
  if (!Array.isArray(evidence) || evidence.length === 0) {
    errors.push("evidence must be a non-empty array");
  } else {
    evidence.forEach((entry, i) => validateEntry(entry, i, errors));
  }

  const limitations = m.limitations;
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

  const regen = m.regeneration as Record<string, unknown> | undefined;
  if (!regen || typeof regen !== "object") {
    errors.push("regeneration must be an object");
  } else {
    rejectUnknownKeys(regen, REGEN_KEYS, "regeneration", errors);
    if (!isNonEmptyString(regen.command)) errors.push("regeneration.command must be a non-empty string");
    if (regen.deterministic !== true) errors.push("regeneration.deterministic must be true");
  }

  // No overclaim language on the asserted surfaces. The `limitations` array is
  // excluded because its entire job is to NEGATE these very terms ("no production
  // custody", "no mainnet deployment"); a substring denylist would false-flag
  // those honest negations. Limitation coverage is enforced positively above via
  // REQUIRED_LIMITATION_TOPICS, mirroring the repo's disclaimer-presence style.
  const assertedSurface = JSON.stringify({ ...m, limitations: undefined });
  if (OVERCLAIM_RE.test(assertedSurface)) {
    errors.push("manifest must not contain production/mainnet/custody/quantum-proof/yield overclaim language");
  }
  // Defense in depth: no raw key/signature material anywhere (including limitations).
  if (RAW_MATERIAL_RE.test(JSON.stringify(value))) {
    errors.push("manifest must not contain raw key/signature material (hex longer than a 32-byte hash)");
  }

  return { valid: errors.length === 0, errors };
}

/** Type-guard form of {@link validateManifest}. */
export function isMLDSAEvidenceManifest(value: unknown): value is MLDSAEvidenceManifest {
  return validateManifest(value).valid;
}

export type { PQReason };
