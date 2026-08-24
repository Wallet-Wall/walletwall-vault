/**
 * Validates deployment *reproducibility* manifests in deployments/reproducibility/.
 *
 * These manifests record, in a machine-checkable form, whether a public test
 * deployment can be reproduced from public repository sources — and, when it
 * cannot, the committed remediation path. They are deliberately separate from
 * the simulator deployment records validated by `validate:deployments`.
 *
 * The central rule is an HONESTY CROSS-CHECK: a manifest may only declare
 * `reproducibilityStatus: "reproducible"` when its own recorded facts support
 * that claim (the reported source commit is in public history, an artifact
 * manifest with a source tag + bytecode hash is present, and the observed
 * runtime bytes match reportedCommitRuntimeBytes — bytes recompiled from the
 * deployment commit itself). Otherwise the manifest MUST carry a concrete
 * remediation plan. This makes it impossible to silently mark a deployment
 * "reproducible" while the facts say otherwise.
 *
 * When a manifest names an `evidenceFile` (deployments/reproducibility/evidence/*.json —
 * raw captured live/build bytecode plus solc's own immutableReferences), this validator
 * goes further: it does not just format-check the manifest's artifactManifest fields, it
 * deterministically RE-DERIVES them from that evidence (scripts/lib/reproducibility-evidence.ts:
 * decodes the solc CBOR metadata boundary from the bytecode itself, computes the normalized
 * executable-code comparison and hash, and re-derives every immutable's expected value from
 * public inputs) and fails if the manifest's recorded value disagrees with the recomputation.
 * A manifest's `executableBytecodeMatch`, `metadataHashMatch`, `metadataTrailerBytesExcluded`,
 * `bytecodeHash`, and `immutableValuesIndependentlyVerified` are therefore never their own
 * authority when evidence is present — they are replayed, not asserted.
 *
 * Run:  npm run validate:reproducibility
 *
 * Exit codes:
 *   0 — all manifests valid (or none found, which is acceptable)
 *   1 — one or more manifests failed validation
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, relative } from "path";

import { checkEvidenceAgainstManifest, type EvidenceBundle } from "./lib/reproducibility-evidence";

const REPO_ROOT = join(import.meta.dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");
const EXCLUDED_DIRS = new Set(["schema", "evidence"]);

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const TXHASH_RE = /^0x[0-9a-fA-F]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const BYTECODE_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const ALLOWED_ENVIRONMENTS = ["local", "sepolia", "base-sepolia"] as const;
const ALLOWED_STATUSES = ["reproducible", "pending-source-alignment", "remediation-gated", "deprecated"] as const;
const ALLOWED_REMEDIATION_PATHS = ["redeploy-from-public-head", "publish-source-tag-and-manifest"] as const;
// Known mainnet chain IDs that must never appear in a testnet-only record.
const FORBIDDEN_CHAIN_IDS = new Set([1, 8453, 137, 10, 42161, 56, 43114]);

interface ValidationResult {
  file: string;
  errors: string[];
}

function collectManifests(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      if (!EXCLUDED_DIRS.has(entry)) files.push(...collectManifests(fullPath));
    } else if (entry.endsWith(".json")) {
      files.push(fullPath);
    }
  }
  return files;
}

function isNonEmptyString(v: unknown, min = 1): boolean {
  return typeof v === "string" && v.trim().length >= min;
}

function validateManifest(filePath: string, raw: unknown): ValidationResult {
  const rel = relative(REPO_ROOT, filePath);
  const errors: string[] = [];

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { file: rel, errors: ["Root value must be a JSON object"] };
  }
  const rec = raw as Record<string, unknown>;

  if (rec["version"] !== "1") {
    errors.push(`version: must be "1" (got ${JSON.stringify(rec["version"])})`);
  }
  if (!isNonEmptyString(rec["subject"])) {
    errors.push("subject: must be a non-empty string (the deployed contract name)");
  }
  if (!ALLOWED_ENVIRONMENTS.includes(rec["environment"] as never)) {
    errors.push(
      `environment: must be one of ${ALLOWED_ENVIRONMENTS.join(", ")} (got ${JSON.stringify(rec["environment"])})`,
    );
  }
  const chainId = rec["chainId"];
  if (typeof chainId !== "number" || !Number.isInteger(chainId) || chainId <= 0) {
    errors.push(`chainId: must be a positive integer (got ${JSON.stringify(chainId)})`);
  } else if (FORBIDDEN_CHAIN_IDS.has(chainId)) {
    errors.push(`chainId: ${chainId} is a mainnet chain ID — must never appear in a record`);
  }

  if (typeof rec["deployedAddress"] !== "string" || !ADDRESS_RE.test(rec["deployedAddress"])) {
    errors.push("deployedAddress: must be a 0x-prefixed 40-hex-character address");
  }
  if (
    rec["deploymentTx"] != null &&
    (typeof rec["deploymentTx"] !== "string" || !TXHASH_RE.test(rec["deploymentTx"]))
  ) {
    errors.push("deploymentTx: must be a 0x-prefixed 64-hex-character tx hash or null");
  }
  if (
    rec["reportedSourceCommit"] != null &&
    (typeof rec["reportedSourceCommit"] !== "string" || !COMMIT_RE.test(rec["reportedSourceCommit"]))
  ) {
    errors.push("reportedSourceCommit: must be a 40-char lowercase hex SHA or null");
  }
  if (typeof rec["reportedSourceCommitInPublicHistory"] !== "boolean") {
    errors.push("reportedSourceCommitInPublicHistory: must be a boolean");
  }
  for (const f of ["observedRuntimeBytes", "reportedCommitRuntimeBytes", "publicHeadRuntimeBytes"]) {
    const v = rec[f];
    if (v != null && (typeof v !== "number" || !Number.isInteger(v) || v < 0)) {
      errors.push(`${f}: must be a non-negative integer or null (got ${JSON.stringify(v)})`);
    }
  }
  if (rec["evidenceFile"] != null && !isNonEmptyString(rec["evidenceFile"])) {
    errors.push("evidenceFile: must be a non-empty string path or null");
  }
  if (!ALLOWED_STATUSES.includes(rec["reproducibilityStatus"] as never)) {
    errors.push(
      `reproducibilityStatus: must be one of ${ALLOWED_STATUSES.join(", ")} (got ${JSON.stringify(rec["reproducibilityStatus"])})`,
    );
  }
  if (!isNonEmptyString(rec["lastChecked"]) || !DATE_RE.test(rec["lastChecked"] as string)) {
    errors.push("lastChecked: must be a YYYY-MM-DD date string");
  }

  // disclosures — must always be present and substantive.
  const disclosures = rec["disclosures"];
  if (!Array.isArray(disclosures) || disclosures.length === 0) {
    errors.push("disclosures: must be a non-empty array of disclosure strings");
  } else if (!disclosures.every((d) => isNonEmptyString(d, 10))) {
    errors.push("disclosures[]: each entry must be a string of at least 10 characters");
  } else {
    const blob = disclosures.join(" ").toLowerCase();
    if (!/testnet|research prototype|not audited|no real funds/.test(blob)) {
      errors.push(
        "disclosures: at least one must disclose testnet-only / research-prototype / not-audited / no-real-funds status",
      );
    }
  }

  // ── HONESTY CROSS-CHECK ─────────────────────────────────────────────────────
  const status = rec["reproducibilityStatus"];
  const observed = rec["observedRuntimeBytes"];
  // reportedCommitRuntimeBytes (bytes recompiled from reportedSourceCommit, using ITS OWN
  // toolchain) is the decisive figure for "reproducible from the deployment commit".
  // publicHeadRuntimeBytes (bytes recompiled from today's public HEAD, a separate capture)
  // is a distinct, informational claim — the two toolchains can differ, so equality with
  // publicHeadRuntimeBytes is never itself required for "reproducible".
  const reportedCommitBytes = rec["reportedCommitRuntimeBytes"];
  const bytecodeMatches =
    typeof observed === "number" && typeof reportedCommitBytes === "number" ? observed === reportedCommitBytes : null;

  if (status === "reproducible") {
    // The record's own facts must support the claim.
    if (rec["reportedSourceCommitInPublicHistory"] !== true) {
      errors.push('reproducibilityStatus "reproducible" requires reportedSourceCommitInPublicHistory: true');
    }
    if (bytecodeMatches === false) {
      errors.push(
        'reproducibilityStatus "reproducible" requires observedRuntimeBytes to match reportedCommitRuntimeBytes (bytes recompiled from the reported deployment commit) — publicHeadRuntimeBytes is a separate, non-gating claim',
      );
    } else if (reportedCommitBytes == null) {
      errors.push(
        'reproducibilityStatus "reproducible" requires reportedCommitRuntimeBytes to be recorded (bytes recompiled from the deployment commit itself, not just publicHeadRuntimeBytes)',
      );
    }

    // ── EVIDENCE-BASED REPLAY ─────────────────────────────────────────────────
    // If this manifest points at a committed evidence bundle, every fact above is not
    // merely format-checked: it is deterministically RE-DERIVED from that evidence and
    // must agree, or this manifest fails validation. No field is its own authority.
    const evidenceFile = rec["evidenceFile"];
    if (isNonEmptyString(evidenceFile)) {
      const evidencePath = join(REPO_ROOT, evidenceFile as string);
      if (!existsSync(evidencePath)) {
        errors.push(`evidenceFile: ${evidenceFile} does not exist`);
      } else {
        try {
          const evidence = JSON.parse(readFileSync(evidencePath, "utf8")) as EvidenceBundle;
          const check = checkEvidenceAgainstManifest(evidence, rec);
          for (const e of check.errors) errors.push(`[evidence replay] ${e}`);
        } catch (err) {
          errors.push(`evidenceFile: failed to load/replay ${evidenceFile}: ${(err as Error).message}`);
        }
      }
    }

    const manifest = rec["artifactManifest"];
    const m = manifest as Record<string, unknown> | null;
    if (!m || typeof m !== "object" || Array.isArray(m)) {
      errors.push(
        'reproducibilityStatus "reproducible" requires an artifactManifest object (sourceTag + bytecodeHash)',
      );
    } else {
      if (!isNonEmptyString(m["sourceTag"]))
        errors.push("artifactManifest.sourceTag: must be a non-empty string when reproducible");
      if (typeof m["bytecodeHash"] !== "string" || !BYTECODE_HASH_RE.test(m["bytecodeHash"] as string)) {
        errors.push("artifactManifest.bytecodeHash: must be a 0x-prefixed 32-byte hash when reproducible");
      }

      // A manifest may legitimately claim "reproducible" while explicitly excluding the
      // non-executed solc build-metadata hash (it is known to vary by build environment
      // even for byte-identical source). That narrower claim must be impossible to state
      // without also disclosing exactly what is excluded and proving the executable code
      // itself still matches exactly.
      if (m["metadataHashMatch"] === false) {
        if (m["executableBytecodeMatch"] !== true) {
          errors.push(
            'artifactManifest.metadataHashMatch: false requires artifactManifest.executableBytecodeMatch: true — a "reproducible" claim cannot exclude the metadata hash unless the executable code is independently confirmed to still match exactly',
          );
        }
        const excluded = m["metadataTrailerBytesExcluded"];
        if (typeof excluded !== "number" || !Number.isInteger(excluded) || excluded < 0 || excluded > 128) {
          errors.push(
            "artifactManifest.metadataTrailerBytesExcluded: required (a small non-negative integer, ≤128) when metadataHashMatch is false, so the excluded region cannot silently grow to cover real logic",
          );
        }
        const disclosureBlob = ((rec["disclosures"] as string[] | undefined) ?? []).join(" ").toLowerCase();
        if (!/metadata|cbor/.test(disclosureBlob)) {
          errors.push(
            "disclosures: metadataHashMatch: false requires at least one disclosure mentioning the excluded metadata/CBOR hash",
          );
        }
      }
    }
  } else {
    // Not reproducible → a concrete remediation plan is mandatory.
    const remediation = rec["remediation"] as Record<string, unknown> | undefined;
    if (!remediation || typeof remediation !== "object" || Array.isArray(remediation)) {
      errors.push(`reproducibilityStatus "${String(status)}" requires a remediation object with a concrete plan`);
    } else {
      if (!ALLOWED_REMEDIATION_PATHS.includes(remediation["chosenPath"] as never)) {
        errors.push(`remediation.chosenPath: must be one of ${ALLOWED_REMEDIATION_PATHS.join(", ")}`);
      }
      const steps = remediation["steps"];
      if (!Array.isArray(steps) || steps.length === 0 || !steps.every((s) => isNonEmptyString(s, 10))) {
        errors.push("remediation.steps: must be a non-empty array of step strings (each ≥ 10 chars)");
      }
      if (!isNonEmptyString(remediation["recordToUpdate"])) {
        errors.push("remediation.recordToUpdate: must name the record/doc updated once remediation completes");
      }
    }
  }

  return { file: rel, errors };
}

function main(): void {
  console.log("WalletWall Vault — deployment reproducibility validator");
  console.log(`Scanning: ${relative(REPO_ROOT, REPRO_DIR)}  (excluding: schema/, evidence/)\n`);

  const files = collectManifests(REPRO_DIR);
  if (files.length === 0) {
    console.log("No reproducibility manifests found — acceptable (none recorded yet).");
    process.exit(0);
  }

  let failCount = 0;
  let passCount = 0;
  for (const file of files) {
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch (err) {
      console.error(`FAIL  ${relative(REPO_ROOT, file)}`);
      console.error(`  [parse error] ${(err as Error).message}`);
      failCount++;
      continue;
    }
    const result = validateManifest(file, raw);
    if (result.errors.length > 0) {
      console.error(`FAIL  ${result.file}`);
      for (const e of result.errors) console.error(`  [error] ${e}`);
      failCount++;
    } else {
      console.log(`PASS  ${result.file}`);
      passCount++;
    }
  }

  console.log(`\n${passCount} passed, ${failCount} failed (${files.length} total)`);
  if (failCount > 0) process.exit(1);
}

main();
