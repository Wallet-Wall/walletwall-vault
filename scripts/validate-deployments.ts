/**
 * Validates deployment metadata files in deployments/ against the schema rules
 * defined in deployments/schema/simulator-deployment.schema.json.
 *
 * Files under deployments/schema/ and deployments/examples/ are excluded —
 * only live deployment records are validated.
 *
 * Run:  npm run validate:deployments
 *
 * Exit codes:
 *   0 — all records valid (or no records found, which is expected pre-deployment)
 *   1 — one or more records failed validation
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, relative, sep } from "path";

const REPO_ROOT = join(import.meta.dirname, "..");
const DEPLOYMENTS_DIR = join(REPO_ROOT, "deployments");
// "reproducibility" holds reproducibility manifests validated separately by
// scripts/validate-reproducibility.ts; they have a different shape.
const EXCLUDED_DIRS = new Set(["schema", "examples", "reproducibility"]);

const ALLOWED_ENVIRONMENTS = ["local", "sepolia", "base-sepolia"] as const;
const ALLOWED_TOKEN_MODES = ["mock", "external-test-token"] as const;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

type NullableString = string | null;
type NullableNumber = number | null;

interface DeploymentRecord {
  version: string;
  environment: string;
  chainId: number;
  networkName: string;
  tokenMode: string;
  tokenAddress: NullableString;
  tokenSymbol: NullableString;
  tokenDecimals: NullableNumber;
  stablecoinVaultSimulatorAddress: NullableString;
  verifierAddress: NullableString;
  policyEngineAddress: NullableString;
  timelockAddress: NullableString;
  recoveryAddress: NullableString;
  deploymentCommit: NullableString;
  packageVersion: string;
  deployedAt: NullableString;
  docsUrl: NullableString;
  warnings: string[];
}

interface ValidationResult {
  file: string;
  errors: string[];
  warnings: string[];
}

function collectJsonFiles(dir: string, excludeDirs: Set<string>): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      if (!excludeDirs.has(entry)) {
        files.push(...collectJsonFiles(fullPath, excludeDirs));
      }
    } else if (entry.endsWith(".json")) {
      files.push(fullPath);
    }
  }
  return files;
}

function validateAddress(value: unknown, fieldName: string, errors: string[]): void {
  if (value !== null && value !== undefined) {
    if (typeof value !== "string" || !ADDRESS_RE.test(value)) {
      errors.push(
        `${fieldName}: must be a 0x-prefixed 40-hex-character address or null (got ${JSON.stringify(value)})`,
      );
    }
  }
}

function validateRecord(filePath: string, raw: unknown): ValidationResult {
  const rel = relative(REPO_ROOT, filePath);
  const errors: string[] = [];
  const warns: string[] = [];

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { file: rel, errors: ["Root value must be a JSON object"], warnings: [] };
  }

  const rec = raw as Record<string, unknown>;

  // version
  if (rec["version"] !== "1") {
    errors.push(`version: must be "1" (got ${JSON.stringify(rec["version"])})`);
  }

  // environment
  if (!ALLOWED_ENVIRONMENTS.includes(rec["environment"] as never)) {
    errors.push(
      `environment: must be one of ${ALLOWED_ENVIRONMENTS.join(", ")} (got ${JSON.stringify(rec["environment"])})`,
    );
  }

  // chainId
  if (typeof rec["chainId"] !== "number" || !Number.isInteger(rec["chainId"]) || rec["chainId"] <= 0) {
    errors.push(`chainId: must be a positive integer (got ${JSON.stringify(rec["chainId"])})`);
  }

  // networkName
  if (typeof rec["networkName"] !== "string" || rec["networkName"].trim() === "") {
    errors.push(`networkName: must be a non-empty string`);
  }

  // tokenMode
  if (!ALLOWED_TOKEN_MODES.includes(rec["tokenMode"] as never)) {
    errors.push(
      `tokenMode: must be one of ${ALLOWED_TOKEN_MODES.join(", ")} (got ${JSON.stringify(rec["tokenMode"])})`,
    );
  }

  // packageVersion
  if (typeof rec["packageVersion"] !== "string" || !SEMVER_RE.test(rec["packageVersion"])) {
    errors.push(`packageVersion: must be a semver string (got ${JSON.stringify(rec["packageVersion"])})`);
  }

  // warnings
  if (!Array.isArray(rec["warnings"]) || (rec["warnings"] as unknown[]).length === 0) {
    errors.push(`warnings: must be a non-empty array of disclosure strings`);
  } else {
    for (const w of rec["warnings"] as unknown[]) {
      if (typeof w !== "string" || w.length < 10) {
        errors.push(`warnings[]: each entry must be a string of at least 10 characters`);
        break;
      }
    }
  }

  // address fields
  validateAddress(rec["tokenAddress"], "tokenAddress", errors);
  validateAddress(rec["stablecoinVaultSimulatorAddress"], "stablecoinVaultSimulatorAddress", errors);
  validateAddress(rec["verifierAddress"], "verifierAddress", errors);
  validateAddress(rec["policyEngineAddress"], "policyEngineAddress", errors);
  validateAddress(rec["timelockAddress"], "timelockAddress", errors);
  validateAddress(rec["recoveryAddress"], "recoveryAddress", errors);

  // deploymentCommit
  if (rec["deploymentCommit"] !== null && rec["deploymentCommit"] !== undefined) {
    if (typeof rec["deploymentCommit"] !== "string" || !COMMIT_RE.test(rec["deploymentCommit"])) {
      errors.push(
        `deploymentCommit: must be a 40-character lowercase hex SHA or null (got ${JSON.stringify(rec["deploymentCommit"])})`,
      );
    }
  }

  // deployedAt
  if (rec["deployedAt"] !== null && rec["deployedAt"] !== undefined) {
    if (typeof rec["deployedAt"] !== "string" || !ISO_DATE_RE.test(rec["deployedAt"])) {
      errors.push(
        `deployedAt: must be an ISO 8601 date-time string or null (got ${JSON.stringify(rec["deployedAt"])})`,
      );
    }
  }

  // Cross-field: if environment is not local and addresses are null, warn
  const env = rec["environment"];
  if (env !== "local") {
    const addressFields: Array<[string, unknown]> = [
      ["stablecoinVaultSimulatorAddress", rec["stablecoinVaultSimulatorAddress"]],
      ["verifierAddress", rec["verifierAddress"]],
      ["tokenAddress", rec["tokenAddress"]],
    ];
    for (const [field, val] of addressFields) {
      if (val === null || val === undefined) {
        warns.push(`${field} is null — ensure this file is only committed after a real ${env} deployment`);
      }
    }
    if (!rec["deploymentCommit"]) {
      warns.push(`deploymentCommit is null — populate from the confirmed deployment commit`);
    }
    if (!rec["deployedAt"]) {
      warns.push(`deployedAt is null — populate with the deployment transaction timestamp`);
    }
  }

  return { file: rel, errors, warnings: warns };
}

function main(): void {
  console.log("WalletWall Vault — deployment metadata validator");
  console.log(`Scanning: ${relative(REPO_ROOT, DEPLOYMENTS_DIR)}${sep}  (excluding: schema/, examples/)\n`);

  const files = collectJsonFiles(DEPLOYMENTS_DIR, EXCLUDED_DIRS);

  if (files.length === 0) {
    console.log("No deployment records found — this is expected before any deployment is performed.");
    console.log("Add a record to deployments/ (not examples/) after a real on-chain deployment.");
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

    const result = validateRecord(file, raw);

    if (result.errors.length > 0) {
      console.error(`FAIL  ${result.file}`);
      for (const e of result.errors) console.error(`  [error]   ${e}`);
      for (const w of result.warnings) console.warn(`  [warning] ${w}`);
      failCount++;
    } else {
      console.log(`PASS  ${result.file}`);
      for (const w of result.warnings) console.warn(`  [warning] ${w}`);
      passCount++;
    }
  }

  console.log(`\n${passCount} passed, ${failCount} failed (${files.length} total)`);
  if (failCount > 0) process.exit(1);
}

main();
