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
 * manifest with a source tag + bytecode hash is present, and the observed and
 * public-HEAD runtime byte counts match). Otherwise the manifest MUST carry a
 * concrete remediation plan. This makes it impossible to silently mark a
 * deployment "reproducible" while the facts say otherwise.
 *
 * Run:  npm run validate:reproducibility
 *
 * Exit codes:
 *   0 — all manifests valid (or none found, which is acceptable)
 *   1 — one or more manifests failed validation
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, relative } from "path";

const REPO_ROOT = join(__dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");
const EXCLUDED_DIRS = new Set(["schema"]);

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
  for (const f of ["observedRuntimeBytes", "publicHeadRuntimeBytes"]) {
    const v = rec[f];
    if (v != null && (typeof v !== "number" || !Number.isInteger(v) || v < 0)) {
      errors.push(`${f}: must be a non-negative integer or null (got ${JSON.stringify(v)})`);
    }
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
  const publicHead = rec["publicHeadRuntimeBytes"];
  const bytecodeMatches =
    typeof observed === "number" && typeof publicHead === "number" ? observed === publicHead : null;

  if (status === "reproducible") {
    // The record's own facts must support the claim.
    if (rec["reportedSourceCommitInPublicHistory"] !== true) {
      errors.push('reproducibilityStatus "reproducible" requires reportedSourceCommitInPublicHistory: true');
    }
    if (bytecodeMatches === false) {
      errors.push('reproducibilityStatus "reproducible" requires observed and public-HEAD runtime bytes to match');
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
  console.log(`Scanning: ${relative(REPO_ROOT, REPRO_DIR)}  (excluding: schema/)\n`);

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
