/**
 * ZK verifier adapter boundary (builder + pure validator).
 *
 * This module defines a single, read-only boundary object that ties together the
 * three deterministic ML-DSA-65 artifacts this repository already ships, so the
 * private WalletWall app (or any third party) can see — in one place, fully
 * cross-checked — how they relate:
 *
 *   - the SP1 proof INPUT      (walletwall.sp1-proof-input.v1; zkvm/fixtures/...),
 *   - the SP1 guest JOURNAL    (the 160-byte public values the guest commits and
 *                               the on-chain verifier decodes),
 *   - the (gated) PROOF slot   (no real Groth16 bytes in CI; status "gated"),
 *   - the read-only EVIDENCE   (walletwall.ml-dsa-evidence-manifest.v1).
 *
 * It also records the on-chain verifier's ROLE: the `ZKMLDSAVerifier`
 * (`IPQCVerifier`) contract is the trustless target, but the active testnet
 * deployment wires it to a MOCK SP1 verifier and no production on-chain ML-DSA
 * verification is live.
 *
 * What it is / is NOT:
 *   - It IS an interface/boundary descriptor + an alignment check. It carries
 *     keccak256 hashes plus the 160-byte journal (itself only hashes + chainId +
 *     address) — never raw key, signature, or message bytes.
 *   - It is NOT a proof, NOT production ZK verification, NOT on-chain ML-DSA
 *     verification, and NOT a production-custody or mainnet-ready claim. Heavy
 *     proving stays gated behind RUN_SP1_E2E=1; the active on-chain SP1 verifier
 *     is a mock. Mainnet stays gated by audit, funding, and operational controls.
 *
 * `validateAdapter` is pure (no filesystem): it checks shape, the gated proof
 * invariant, the boundary marking, limitation coverage, overclaim language, and —
 * the core defense — that the embedded journal decodes to exactly the hashes the
 * proof-input section declares (proving the whole object describes one ML-DSA
 * material set and carries hashes only). The generator
 * ({@link ../generate-zk-verifier-adapter}) adds the on-disk source cross-checks.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { AbiCoder, dataLength, getBytes, isAddress, isHexString, keccak256 } from "ethers";

import {
  GATED_PROOF_REASON,
  PQ_PROOF_PROVER,
  PQ_PROOF_SCHEME,
  PQ_PROOF_STATUS,
  type PQProofStatus,
} from "./proof-artifact";
import { ML_DSA_EVIDENCE_MANIFEST_SCHEMA } from "./ml-dsa-evidence-manifest";
import { SP1_PROOF_INPUT_SCHEMA } from "./sp1-proof-input";

/** Stable adapter-boundary schema identifier. Bump only on a breaking shape change. */
export const ZK_VERIFIER_ADAPTER_SCHEMA = "walletwall.zk-verifier-adapter.v1";

/** Single artifact type this module emits. */
export const ZK_VERIFIER_ADAPTER_ARTIFACT_TYPE = "zk-verifier-adapter-boundary";

/** The aligned upstream contract schema versions (pinned; asserted by tests). */
export const ALIGNED_MANIFEST_SCHEMA = "walletwall.ml-dsa-evidence-manifest.v1";
export const ALIGNED_PROOF_INPUT_SCHEMA = "walletwall.sp1-proof-input.v1";

/** ML-DSA-65 (FIPS 204). */
export const ZK_ADAPTER_ALGORITHM = { parameterSet: "ML-DSA-65", fips: "FIPS-204" } as const;

/**
 * The on-chain verifier role this boundary describes. The ZKMLDSAVerifier is the
 * trustless target, but the active testnet SP1 verifier is a mock and no
 * production on-chain ML-DSA verification is live.
 */
export const ZK_ADAPTER_ON_CHAIN_VERIFIER = {
  interface: "IPQCVerifier",
  contract: "ZKMLDSAVerifier",
  algorithmId: "ZK-ML-DSA-65",
  /** The active testnet SP1 verifier is a mock; "real" only with a deployed SP1 verifier. */
  sp1Verifier: "mock",
  /** No production / live on-chain ML-DSA verification. */
  onChainVerification: false,
  /** This boundary does not custody funds. */
  custody: false,
} as const;

/** Canonical, honest limitations. Every required disclosure topic is present here. */
export const ZK_ADAPTER_LIMITATIONS: readonly string[] = [
  "No proof — no real Groth16 proof bytes are present; heavy SP1 proving stays gated behind RUN_SP1_E2E=1 and an external prover.",
  "Off-chain only — ML-DSA-65 is verified off-chain; this boundary does not perform on-chain ML-DSA verification.",
  "Mock on-chain verifier — the active testnet SP1 verifier is a mock, so the ZKMLDSAVerifier path is not a live trustless check.",
  "Trusted-attestor boundary — the non-mock production path today is the trusted EIP-712 attestor, not a ZK proof.",
  "Research prototype — not audited.",
  "Testnet / reference path only — no mainnet deployment and no production custody.",
  "No real funds — every referenced artifact is deterministic test/fixture material.",
];

export interface ZKAdapterProofInput {
  schema: typeof ALIGNED_PROOF_INPUT_SCHEMA;
  path: string;
  messageHash: string;
  publicKeyHash: string;
  signatureHash: string;
}

export interface ZKAdapterJournal {
  /** ABI-encoded SP1 public values (the guest journal), 160 bytes. */
  publicValues: string;
  /** keccak256 of `publicValues`. */
  publicValuesHash: string;
  chainId: number;
  verifierAddress: string;
}

export interface ZKAdapterProof {
  status: PQProofStatus;
  scheme: typeof PQ_PROOF_SCHEME;
  prover: typeof PQ_PROOF_PROVER;
  generated: boolean;
  reason: string;
}

export interface ZKAdapterEvidence {
  manifestSchema: typeof ALIGNED_MANIFEST_SCHEMA;
  manifestPath: string;
  evidenceId: string;
}

export interface ZKVerifierAdapter {
  schema: typeof ZK_VERIFIER_ADAPTER_SCHEMA;
  artifactType: typeof ZK_VERIFIER_ADAPTER_ARTIFACT_TYPE;
  /** ISO-8601 UTC instant; the only non-deterministic field. */
  generatedAt: string;
  algorithm: typeof ZK_ADAPTER_ALGORITHM;
  onChainVerifier: typeof ZK_ADAPTER_ON_CHAIN_VERIFIER;
  proofInput: ZKAdapterProofInput;
  journal: ZKAdapterJournal;
  proof: ZKAdapterProof;
  evidence: ZKAdapterEvidence;
  limitations: string[];
  regeneration: { command: string; deterministic: boolean };
}

export interface BuildAdapterInput {
  proofInput: ZKAdapterProofInput;
  journal: ZKAdapterJournal;
  evidence: ZKAdapterEvidence;
  proof?: ZKAdapterProof;
  generatedAt?: string | Date;
  command?: string;
}

/** Assemble the adapter boundary. Pure: canonical constants + supplied bindings. */
export function buildAdapter(input: BuildAdapterInput): ZKVerifierAdapter {
  const generatedAt =
    input.generatedAt instanceof Date
      ? input.generatedAt.toISOString()
      : (input.generatedAt ?? new Date().toISOString());

  const proof: ZKAdapterProof = input.proof ?? {
    status: PQ_PROOF_STATUS.GATED,
    scheme: PQ_PROOF_SCHEME,
    prover: PQ_PROOF_PROVER,
    generated: false,
    reason: GATED_PROOF_REASON,
  };

  return {
    schema: ZK_VERIFIER_ADAPTER_SCHEMA,
    artifactType: ZK_VERIFIER_ADAPTER_ARTIFACT_TYPE,
    generatedAt,
    algorithm: ZK_ADAPTER_ALGORITHM,
    onChainVerifier: ZK_ADAPTER_ON_CHAIN_VERIFIER,
    proofInput: input.proofInput,
    journal: input.journal,
    proof,
    evidence: input.evidence,
    limitations: [...ZK_ADAPTER_LIMITATIONS],
    regeneration: { command: input.command ?? "npm run zk:adapter", deterministic: true },
  };
}

export interface AdapterValidation {
  valid: boolean;
  errors: string[];
}

const HASH_RE = /^0x[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const PROOF_STATUSES = new Set<string>(Object.values(PQ_PROOF_STATUS));

const OVERCLAIM_RE =
  /\b(mainnet-ready|production custody|production-ready|quantum-proof|quantum proof|quantum-safe|guaranteed|insured|real yield|\bapy\b)/i;

const REQUIRED_LIMITATION_TOPICS: { label: string; re: RegExp }[] = [
  { label: "no proof / gated proving", re: /no proof|gated/ },
  { label: "off-chain only", re: /off-chain/ },
  { label: "mock on-chain verifier", re: /\bmock\b/ },
  { label: "not audited", re: /not audited/ },
  { label: "testnet / reference path only", re: /testnet/ },
  { label: "no real funds", re: /no real funds/ },
];

const TOP_KEYS = [
  "schema",
  "artifactType",
  "generatedAt",
  "algorithm",
  "onChainVerifier",
  "proofInput",
  "journal",
  "proof",
  "evidence",
  "limitations",
  "regeneration",
];
const ALGORITHM_KEYS = ["parameterSet", "fips"];
const ON_CHAIN_KEYS = ["interface", "contract", "algorithmId", "sp1Verifier", "onChainVerification", "custody"];
const PROOF_INPUT_KEYS = ["schema", "path", "messageHash", "publicKeyHash", "signatureHash"];
const JOURNAL_KEYS = ["publicValues", "publicValuesHash", "chainId", "verifierAddress"];
const PROOF_KEYS = ["status", "scheme", "prover", "generated", "reason"];
const EVIDENCE_KEYS = ["manifestSchema", "manifestPath", "evidenceId"];
const REGEN_KEYS = ["command", "deterministic"];

function isHash(v: unknown): v is string {
  return typeof v === "string" && HASH_RE.test(v);
}
function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}
function rejectUnknownKeys(obj: unknown, allowed: readonly string[], path: string, errors: string[]): void {
  if (typeof obj !== "object" || obj === null) return;
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) errors.push(`unexpected key in ${path}: ${k}`);
  }
}
function isRelativeNoTraversal(p: unknown): boolean {
  return typeof p === "string" && p.length > 0 && !p.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(p) && !p.includes("..");
}

/**
 * Validate that the journal decodes to exactly the proof-input hashes. This is
 * the core binding: it proves the journal carries only hashes (no raw key/sig)
 * and that the journal and the proof input describe the same ML-DSA material.
 */
function validateJournalBinding(
  journal: Record<string, unknown>,
  proofInput: Record<string, unknown> | undefined,
  errors: string[],
): void {
  const pv = journal.publicValues;
  if (typeof pv !== "string" || !isHexString(pv) || dataLength(pv) !== 160) {
    errors.push("journal.publicValues must be 160-byte hex");
    return;
  }
  if (!isHash(journal.publicValuesHash) || journal.publicValuesHash !== keccak256(pv)) {
    errors.push("journal.publicValuesHash must be keccak256(publicValues)");
  }
  if (typeof journal.chainId !== "number" || !Number.isSafeInteger(journal.chainId) || journal.chainId < 0) {
    errors.push("journal.chainId must be a non-negative integer");
  }
  if (typeof journal.verifierAddress !== "string" || !isAddress(journal.verifierAddress)) {
    errors.push("journal.verifierAddress must be a valid EVM address");
  }
  try {
    const [digest, pkHash, sigHash, chainId, verifier] = new AbiCoder().decode(
      ["bytes32", "bytes32", "bytes32", "uint64", "address"],
      pv,
    );
    if (proofInput && isHash(proofInput.messageHash) && keccak256(digest) !== proofInput.messageHash) {
      errors.push("journal digest does not hash to proofInput.messageHash");
    }
    if (proofInput && isHash(proofInput.publicKeyHash) && pkHash.toLowerCase() !== proofInput.publicKeyHash) {
      errors.push("journal publicKeyHash does not match proofInput.publicKeyHash");
    }
    if (proofInput && isHash(proofInput.signatureHash) && sigHash.toLowerCase() !== proofInput.signatureHash) {
      errors.push("journal signatureHash does not match proofInput.signatureHash");
    }
    if (typeof journal.chainId === "number" && Number(chainId) !== journal.chainId) {
      errors.push("journal chainId does not match the decoded public values");
    }
    if (
      typeof journal.verifierAddress === "string" &&
      verifier.toLowerCase() !== journal.verifierAddress.toLowerCase()
    ) {
      errors.push("journal verifierAddress does not match the decoded public values");
    }
  } catch {
    errors.push("journal.publicValues failed to decode as (bytes32,bytes32,bytes32,uint64,address)");
  }
}

/** Strictly validate a ZK verifier adapter boundary (pure; no filesystem). */
export function validateAdapter(value: unknown): AdapterValidation {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, errors: ["adapter must be an object"] };
  }
  const a = value as Record<string, unknown>;
  rejectUnknownKeys(a, TOP_KEYS, "adapter", errors);

  if (a.schema !== ZK_VERIFIER_ADAPTER_SCHEMA) errors.push(`schema must be ${ZK_VERIFIER_ADAPTER_SCHEMA}`);
  if (a.artifactType !== ZK_VERIFIER_ADAPTER_ARTIFACT_TYPE)
    errors.push(`artifactType must be ${ZK_VERIFIER_ADAPTER_ARTIFACT_TYPE}`);
  if (typeof a.generatedAt !== "string" || !ISO_RE.test(a.generatedAt) || Number.isNaN(Date.parse(a.generatedAt))) {
    errors.push("generatedAt must be an ISO-8601 UTC timestamp");
  }

  const algorithm = a.algorithm as Record<string, unknown> | undefined;
  if (!algorithm || typeof algorithm !== "object") {
    errors.push("algorithm must be an object");
  } else {
    rejectUnknownKeys(algorithm, ALGORITHM_KEYS, "algorithm", errors);
    if (algorithm.parameterSet !== "ML-DSA-65") errors.push("algorithm.parameterSet must be ML-DSA-65");
    if (algorithm.fips !== "FIPS-204") errors.push("algorithm.fips must be FIPS-204");
  }

  // On-chain verifier role must be present AND honestly marked.
  const ocv = a.onChainVerifier as Record<string, unknown> | undefined;
  if (!ocv || typeof ocv !== "object") {
    errors.push("onChainVerifier must be an object");
  } else {
    rejectUnknownKeys(ocv, ON_CHAIN_KEYS, "onChainVerifier", errors);
    if (ocv.interface !== ZK_ADAPTER_ON_CHAIN_VERIFIER.interface)
      errors.push("onChainVerifier.interface must be IPQCVerifier");
    if (ocv.contract !== ZK_ADAPTER_ON_CHAIN_VERIFIER.contract)
      errors.push("onChainVerifier.contract must be ZKMLDSAVerifier");
    if (ocv.algorithmId !== ZK_ADAPTER_ON_CHAIN_VERIFIER.algorithmId)
      errors.push("onChainVerifier.algorithmId must be ZK-ML-DSA-65");
    if (ocv.sp1Verifier !== "mock")
      errors.push("onChainVerifier.sp1Verifier must be mock (active testnet verifier is a mock)");
    if (ocv.onChainVerification !== false) errors.push("onChainVerifier.onChainVerification must be false");
    if (ocv.custody !== false) errors.push("onChainVerifier.custody must be false");
  }

  const proofInput = a.proofInput as Record<string, unknown> | undefined;
  if (!proofInput || typeof proofInput !== "object") {
    errors.push("proofInput must be an object");
  } else {
    rejectUnknownKeys(proofInput, PROOF_INPUT_KEYS, "proofInput", errors);
    if (proofInput.schema !== ALIGNED_PROOF_INPUT_SCHEMA)
      errors.push(`proofInput.schema must be ${ALIGNED_PROOF_INPUT_SCHEMA}`);
    if (!isRelativeNoTraversal(proofInput.path))
      errors.push("proofInput.path must be a repo-relative path without traversal");
    for (const k of ["messageHash", "publicKeyHash", "signatureHash"] as const) {
      if (!isHash(proofInput[k])) errors.push(`proofInput.${k} must be a 0x keccak256 hash`);
    }
  }

  const journal = a.journal as Record<string, unknown> | undefined;
  if (!journal || typeof journal !== "object") {
    errors.push("journal must be an object");
  } else {
    rejectUnknownKeys(journal, JOURNAL_KEYS, "journal", errors);
    validateJournalBinding(journal, proofInput, errors);
  }

  // Proof block: gated unless real bytes are present; generated iff status generated.
  const proof = a.proof as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== "object") {
    errors.push("proof must be an object");
  } else {
    rejectUnknownKeys(proof, PROOF_KEYS, "proof", errors);
    if (typeof proof.status !== "string" || !PROOF_STATUSES.has(proof.status)) {
      errors.push(`proof.status must be one of ${[...PROOF_STATUSES].join(", ")}`);
    }
    if (proof.scheme !== PQ_PROOF_SCHEME) errors.push(`proof.scheme must be ${PQ_PROOF_SCHEME}`);
    if (proof.prover !== PQ_PROOF_PROVER) errors.push(`proof.prover must be ${PQ_PROOF_PROVER}`);
    if (typeof proof.generated !== "boolean") errors.push("proof.generated must be a boolean");
    if (!isNonEmptyString(proof.reason)) errors.push("proof.reason must be a non-empty string");
    if (typeof proof.generated === "boolean" && typeof proof.status === "string") {
      const shouldBeGenerated = proof.status === PQ_PROOF_STATUS.GENERATED;
      if (proof.generated !== shouldBeGenerated)
        errors.push('proof.generated must be true iff proof.status is "generated"');
    }
  }

  const evidence = a.evidence as Record<string, unknown> | undefined;
  if (!evidence || typeof evidence !== "object") {
    errors.push("evidence must be an object");
  } else {
    rejectUnknownKeys(evidence, EVIDENCE_KEYS, "evidence", errors);
    if (evidence.manifestSchema !== ALIGNED_MANIFEST_SCHEMA)
      errors.push(`evidence.manifestSchema must be ${ALIGNED_MANIFEST_SCHEMA}`);
    if (!isRelativeNoTraversal(evidence.manifestPath))
      errors.push("evidence.manifestPath must be a repo-relative path without traversal");
    if (!isNonEmptyString(evidence.evidenceId)) errors.push("evidence.evidenceId must be a non-empty string");
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

  // No overclaim language on asserted surfaces (limitations excluded; they negate
  // these very terms — coverage is enforced positively above).
  const assertedSurface = JSON.stringify({ ...a, limitations: undefined });
  if (OVERCLAIM_RE.test(assertedSurface)) {
    errors.push("adapter must not contain production/mainnet/custody/quantum-proof/yield overclaim language");
  }

  return { valid: errors.length === 0, errors };
}

/** Type-guard form of {@link validateAdapter}. */
export function isZKVerifierAdapter(value: unknown): value is ZKVerifierAdapter {
  return validateAdapter(value).valid;
}
