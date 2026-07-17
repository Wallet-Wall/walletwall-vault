/**
 * Canonical NIST PQC (post-quantum cryptography) algorithm standards registry.
 *
 * Single source of truth for which FIPS 203/204/205 algorithms this repository
 * implements, at what conformance / certification / production maturity, and
 * with what library. This module is purely descriptive metadata.
 *
 * It does NOT select, dispatch, or perform verification, and adding a record
 * here does NOT make an algorithm usable — the verifier boundary
 * (src/verifier/*) remains intentionally hardcoded to ML-DSA-65 (tracked
 * separately as future off-chain crypto-agility work; out of scope here).
 *
 * Reading rules for every field below:
 *   - `implementationStatus: "not-implemented"` must never be read as a
 *     negative signal — ML-KEM and SLH-DSA are out of scope by design (see
 *     docs/security/pqc-standards-alignment-audit.md §10).
 *   - `certificationStatus`/`productionStatus` on the ML-DSA-65 record must
 *     never be read as a positive validation claim. Nothing in this registry
 *     is FIPS/CMVP validated, and absence of a `validated` status must never
 *     be silently upgraded into one downstream.
 *
 * Research prototype. Not audited. Testnet/local only.
 */

export const PQ_ALGORITHM_IDS = ["ML-DSA", "ML-KEM", "SLH-DSA"] as const;
export type PQAlgorithmId = (typeof PQ_ALGORITHM_IDS)[number];

export const PQ_STANDARDS = ["FIPS 203", "FIPS 204", "FIPS 205"] as const;
export type PQStandard = (typeof PQ_STANDARDS)[number];

export const PQ_PURPOSES = ["signature", "key-establishment"] as const;
export type PQPurpose = (typeof PQ_PURPOSES)[number];

export const PQ_IMPLEMENTATION_STATUSES = ["implemented", "experimental", "planned", "not-implemented"] as const;
export type PQImplementationStatus = (typeof PQ_IMPLEMENTATION_STATUSES)[number];

/**
 * Modes in which *some* form of verification exists for an algorithm in this
 * system. Presence in a record's `verificationModes` is not a claim that the
 * mode is cryptographically real or production-grade — `mock` and `zk-proof`
 * (an un-deployed scaffold) are deliberately included as distinct, honestly
 * labeled entries rather than omitted or conflated with `off-chain`. See
 * docs/ZK_PQ_Status_Matrix.md for the per-mode capability matrix.
 */
export const PQ_VERIFICATION_MODES = ["local", "off-chain", "attested", "zk-proof", "mock"] as const;
export type PQVerificationMode = (typeof PQ_VERIFICATION_MODES)[number];

export const PQ_CONFORMANCE_STATUSES = ["not-tested", "vectors-tested", "acvp-evidence", "unknown"] as const;
export type PQConformanceStatus = (typeof PQ_CONFORMANCE_STATUSES)[number];

export const PQ_CERTIFICATION_STATUSES = ["not-validated", "validation-pending", "validated"] as const;
export type PQCertificationStatus = (typeof PQ_CERTIFICATION_STATUSES)[number];

export const PQ_PRODUCTION_STATUSES = ["research-only", "prototype", "production-candidate", "production"] as const;
export type PQProductionStatus = (typeof PQ_PRODUCTION_STATUSES)[number];

export interface PQImplementationRef {
  provider: string | null;
  package: string | null;
  version: string | null;
}

export interface PQAlgorithmRecord {
  algorithm: PQAlgorithmId;
  parameterSet: string | null;
  standard: PQStandard;
  purpose: PQPurpose;
  implementation: PQImplementationRef;
  implementationStatus: PQImplementationStatus;
  verificationModes: readonly PQVerificationMode[];
  conformanceStatus: PQConformanceStatus;
  certificationStatus: PQCertificationStatus;
  productionStatus: PQProductionStatus;
}

/**
 * ML-DSA-65 (FIPS 204, = CRYSTALS-Dilithium3, NIST security category 3).
 * The only PQ signature path implemented in this repository.
 *
 * - Off-chain, pure verification: src/verifier/ml-dsa-65.ts (real crypto).
 * - Mock on-chain verifier (active on Sepolia): contracts/MockMLDSAVerifier.sol.
 * - Trusted-attestor on-chain path: contracts/verifiers/AttestationPQCVerifier.sol
 *   (EIP-712 attestation, not ML-DSA verification on-chain).
 * - ZK on-chain path: contracts/verifiers/ZKMLDSAVerifier.sol — un-deployed
 *   SP1 forwarder scaffold, mock-backed in tests.
 * - Conformance: 6 of the 15 NIST ACVP sigVer group-3 vectors are committed
 *   and exercised (3 valid + 3 invalid) — see
 *   test/fixtures/mldsa/nist-cavp/README.md. The upstream library is
 *   independently ACVP-tested; this repository's own committed/exercised
 *   surface is the 6-vector subset, not the full 15-vector group.
 */
const ML_DSA_65: PQAlgorithmRecord = Object.freeze({
  algorithm: "ML-DSA",
  parameterSet: "ML-DSA-65",
  standard: "FIPS 204",
  purpose: "signature",
  implementation: Object.freeze({
    provider: "noble-cryptography (Paul Miller)",
    package: "@noble/post-quantum",
    version: "0.6.1",
  }),
  implementationStatus: "implemented",
  verificationModes: Object.freeze(["off-chain", "mock", "attested", "zk-proof"]),
  conformanceStatus: "vectors-tested",
  certificationStatus: "not-validated",
  productionStatus: "prototype",
}) as PQAlgorithmRecord;

/**
 * ML-KEM (FIPS 203). Not implemented anywhere in this repository, the
 * embedded private-app research copy, or the private app runtime. Out of
 * scope for the withdrawal-signature use case (see audit §10).
 */
const ML_KEM_NOT_IMPLEMENTED: PQAlgorithmRecord = Object.freeze({
  algorithm: "ML-KEM",
  parameterSet: null,
  standard: "FIPS 203",
  purpose: "key-establishment",
  implementation: Object.freeze({ provider: null, package: null, version: null }),
  implementationStatus: "not-implemented",
  verificationModes: Object.freeze([]),
  conformanceStatus: "not-tested",
  certificationStatus: "not-validated",
  productionStatus: "research-only",
}) as PQAlgorithmRecord;

/**
 * SLH-DSA / SPHINCS+ (FIPS 205). Not implemented anywhere in this
 * repository, the embedded private-app research copy, or the private app
 * runtime. Referenced only as roadmap/notional-mode text (see audit §10).
 */
const SLH_DSA_NOT_IMPLEMENTED: PQAlgorithmRecord = Object.freeze({
  algorithm: "SLH-DSA",
  parameterSet: null,
  standard: "FIPS 205",
  purpose: "signature",
  implementation: Object.freeze({ provider: null, package: null, version: null }),
  implementationStatus: "not-implemented",
  verificationModes: Object.freeze([]),
  conformanceStatus: "not-tested",
  certificationStatus: "not-validated",
  productionStatus: "research-only",
}) as PQAlgorithmRecord;

/** Canonical registry, keyed by algorithm id. The single source of truth. */
export const PQ_ALGORITHM_REGISTRY: Readonly<Record<PQAlgorithmId, PQAlgorithmRecord>> = Object.freeze({
  "ML-DSA": ML_DSA_65,
  "ML-KEM": ML_KEM_NOT_IMPLEMENTED,
  "SLH-DSA": SLH_DSA_NOT_IMPLEMENTED,
});

/** Look up the canonical record for a registry algorithm id. */
export function getPQAlgorithmRecord(id: PQAlgorithmId): PQAlgorithmRecord {
  return PQ_ALGORITHM_REGISTRY[id];
}

/** True only for algorithms with `implementationStatus === "implemented"`. */
export function isPQAlgorithmImplemented(id: PQAlgorithmId): boolean {
  return PQ_ALGORITHM_REGISTRY[id].implementationStatus === "implemented";
}

// ---------------------------------------------------------------------------
// Derived standards-alignment status (for UI / evidence reporting)
// ---------------------------------------------------------------------------
//
// Deliberately factual and per-standard, NOT a percentage or aggregate score.
// Implementation, evidence availability, and formal validation are three
// independent axes; collapsing them into one number would itself be a
// readiness overclaim.

export interface PQStandardAlignment {
  algorithm: PQAlgorithmId;
  parameterSet: string | null;
  standard: PQStandard;
  implemented: boolean;
  evidenceAvailable: boolean;
  validated: boolean;
}

export interface PQStandardsAlignmentStatus {
  signatureStandard: PQStandardAlignment;
  keyEstablishmentStandard: PQStandardAlignment;
  alternateSignatureStandard: PQStandardAlignment;
}

function toAlignment(record: PQAlgorithmRecord): PQStandardAlignment {
  return Object.freeze({
    algorithm: record.algorithm,
    parameterSet: record.parameterSet,
    standard: record.standard,
    implemented: record.implementationStatus === "implemented",
    evidenceAvailable: record.conformanceStatus === "vectors-tested" || record.conformanceStatus === "acvp-evidence",
    validated: record.certificationStatus === "validated",
  });
}

/**
 * Derived, UI-safe summary of standards alignment across the three audited
 * standards. `validated` is `true` only for `certificationStatus ===
 * "validated"` — today that is `false` for every record, by design.
 */
export function getPQStandardsAlignmentStatus(): PQStandardsAlignmentStatus {
  return Object.freeze({
    signatureStandard: toAlignment(PQ_ALGORITHM_REGISTRY["ML-DSA"]),
    keyEstablishmentStandard: toAlignment(PQ_ALGORITHM_REGISTRY["ML-KEM"]),
    alternateSignatureStandard: toAlignment(PQ_ALGORITHM_REGISTRY["SLH-DSA"]),
  });
}
