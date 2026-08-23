/**
 * EIP-170 runtime (deployed) bytecode size gate.
 *
 * EIP-170 (https://eips.ethereum.org/EIPS/eip-170) caps a contract's RUNTIME
 * bytecode — the code actually stored on-chain and executed on every call — at
 * 24,576 bytes. CREATE/CREATE2 deployment reverts above that; it is a protocol
 * constant, not a policy knob. CREATION bytecode (constructor logic + init code,
 * `bytecode` in a Hardhat artifact) is not gated by EIP-170 and is not measured
 * here except for the informational report — only `deployedBytecode` (the runtime
 * code, what remains on-chain after construction) is checked against the limit.
 *
 * This gate is post-compile: it reads already-compiled Hardhat artifacts under
 * artifacts/contracts/ and never invokes solc itself. Run `npm run compile` first
 * (the `prevalidate:bytecode-size` npm hook does this automatically).
 *
 * Run:  npm run validate:bytecode-size
 *
 * Exit codes:
 *   0 — every measured contract's runtime bytecode is within the EIP-170 ceiling
 *   1 — one or more contracts exceed the 24,576-byte runtime bytecode ceiling
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const REPO_ROOT = join(import.meta.dirname, "..");
const ARTIFACTS_DIR = join(REPO_ROOT, "artifacts", "contracts");

/**
 * EIP-170's runtime bytecode ceiling, in bytes. A protocol constant — never tune
 * this to "fix" a failing gate; reduce the contract instead.
 */
export const EIP170_RUNTIME_LIMIT_BYTES = 24576;

/**
 * Conservative, non-failing early-warning threshold: 90% of the hard ceiling
 * (22,118 bytes), leaving roughly 2.4 KB of headroom. This exists so a routine
 * future change (a new modifier, event, or require string) that pushes a
 * contract from "comfortable" to "one PR away from a hard EIP-170 failure" is
 * visible in CI output before it becomes an emergency — it never fails the build.
 */
export const WARN_RATIO = 0.9;
export const WARN_THRESHOLD_BYTES = Math.floor(EIP170_RUNTIME_LIMIT_BYTES * WARN_RATIO);

export interface ContractSizeTarget {
  /** Human-readable contract name, as reported. */
  name: string;
  /** Artifact path relative to artifacts/contracts/. */
  artifactRelPath: string;
  /** Why this contract is in scope for the gate. */
  justification: string;
}

export const TARGET_CONTRACTS: ContractSizeTarget[] = [
  {
    name: "WalletWallVault",
    artifactRelPath: "WalletWallVault.sol/WalletWallVault.json",
    justification: "primary hybrid ECDSA+PQ withdrawal-authorization vault",
  },
  {
    name: "StablecoinVaultSimulator",
    artifactRelPath: "StablecoinVaultSimulator.sol/StablecoinVaultSimulator.json",
    justification: "deployed stablecoin vault simulator (see deployments/sepolia/)",
  },
  {
    name: "WalletWallMultiSigVault",
    artifactRelPath: "WalletWallMultiSigVault.sol/WalletWallMultiSigVault.json",
    justification: "multisig vault variant",
  },
  {
    name: "MockMLDSAVerifier",
    artifactRelPath: "MockMLDSAVerifier.sol/MockMLDSAVerifier.json",
    justification:
      "the concrete IPQCVerifier actually deployed on Sepolia today " +
      "(deployments/sepolia/stablecoin-vault-simulator.json)",
  },
  {
    name: "AttestationPQCVerifier",
    artifactRelPath: "verifiers/AttestationPQCVerifier.sol/AttestationPQCVerifier.json",
    justification: "concrete IPQCVerifier trusted-attestation implementation",
  },
  {
    name: "ImmutableAttestationPQCVerifier",
    artifactRelPath: "verifiers/ImmutableAttestationPQCVerifier.sol/ImmutableAttestationPQCVerifier.json",
    justification:
      "concrete IPQCVerifier trusted-attestation implementation with a constructor-fixed, " +
      "non-rotatable attestor and no admin surface; recommended near-term deployment choice " +
      "over AttestationPQCVerifier (see docs/Attestation_Governance_Hardening.md), not yet " +
      "deployed to any network",
  },
  {
    name: "ZKMLDSAVerifier",
    artifactRelPath: "verifiers/ZKMLDSAVerifier.sol/ZKMLDSAVerifier.json",
    justification:
      "concrete IPQCVerifier ZK/SP1-backed implementation (prototype, not yet deployed; " +
      "see docs/ZK_PQ_Status_Matrix.md)",
  },
];

interface HardhatArtifact {
  contractName: string;
  /** CREATION bytecode (constructor + init code) — NOT gated by this check. */
  bytecode: string;
  /** RUNTIME (deployed) bytecode — what EIP-170 measures and what this gate checks. */
  deployedBytecode: string;
}

/** Number of bytes encoded by a "0x..."-prefixed hex string (e.g. deployedBytecode). */
export function hexByteLength(hex: string): number {
  if (typeof hex !== "string" || !hex.startsWith("0x")) {
    throw new Error(`expected a 0x-prefixed hex string, got ${JSON.stringify(hex)}`);
  }
  const body = hex.slice(2);
  if (body.length % 2 !== 0) {
    throw new Error(`hex string has an odd number of nibbles: ${JSON.stringify(hex)}`);
  }
  return body.length / 2;
}

export interface SizeReport {
  name: string;
  /** RUNTIME (deployed) bytecode size — the only field EIP-170 gates. */
  runtimeBytes: number;
  /** CREATION bytecode size — informational only, never compared to the limit. */
  creationBytes: number;
  limitBytes: number;
  headroomBytes: number;
  overLimit: boolean;
  nearLimit: boolean;
}

/**
 * Pure evaluation over already-extracted byte counts — no I/O, so the hard-fail /
 * warn boundaries are directly unit-testable without touching the filesystem.
 */
export function evaluateSize(name: string, runtimeBytes: number, creationBytes: number): SizeReport {
  return {
    name,
    runtimeBytes,
    creationBytes,
    limitBytes: EIP170_RUNTIME_LIMIT_BYTES,
    headroomBytes: EIP170_RUNTIME_LIMIT_BYTES - runtimeBytes,
    overLimit: runtimeBytes > EIP170_RUNTIME_LIMIT_BYTES,
    nearLimit: runtimeBytes >= WARN_THRESHOLD_BYTES && runtimeBytes <= EIP170_RUNTIME_LIMIT_BYTES,
  };
}

/**
 * Evaluate a Hardhat artifact. Reads `deployedBytecode` for the gated runtime size
 * and `bytecode` (creation code) only for the informational report — creation
 * bytecode is never compared against the EIP-170 limit.
 */
export function evaluateArtifact(name: string, artifact: HardhatArtifact): SizeReport {
  const runtimeBytes = hexByteLength(artifact.deployedBytecode);
  const creationBytes = hexByteLength(artifact.bytecode);
  return evaluateSize(name, runtimeBytes, creationBytes);
}

function loadArtifact(target: ContractSizeTarget): HardhatArtifact {
  const path = join(ARTIFACTS_DIR, target.artifactRelPath);
  if (!existsSync(path)) {
    throw new Error(
      `${path} does not exist — run \`npm run compile\` before validate:bytecode-size (target: ${target.name})`,
    );
  }
  return JSON.parse(readFileSync(path, "utf8")) as HardhatArtifact;
}

export function collectReports(targets: ContractSizeTarget[] = TARGET_CONTRACTS): SizeReport[] {
  return targets.map((t) => evaluateArtifact(t.name, loadArtifact(t)));
}

function formatReport(r: SizeReport): string {
  const pct = ((r.runtimeBytes / r.limitBytes) * 100).toFixed(1);
  const tag = r.overLimit ? "FAIL" : r.nearLimit ? "WARN" : "PASS";
  return (
    `${tag}  ${r.name}\n` +
    `      runtime bytecode:  ${r.runtimeBytes} bytes (${pct}% of ${r.limitBytes})\n` +
    `      creation bytecode: ${r.creationBytes} bytes (not gated; informational only)\n` +
    `      headroom:          ${r.headroomBytes} bytes`
  );
}

function main(): void {
  console.log("WalletWall Vault — EIP-170 runtime bytecode size gate");
  console.log(`Hard limit: ${EIP170_RUNTIME_LIMIT_BYTES} bytes (EIP-170, runtime/deployed bytecode only)`);
  console.log(`Warning threshold: ${WARN_THRESHOLD_BYTES} bytes (${WARN_RATIO * 100}% of hard limit, non-failing)\n`);

  const reports = collectReports();
  for (const r of reports) {
    console.log(formatReport(r));
  }

  const failing = reports.filter((r) => r.overLimit);
  const warning = reports.filter((r) => r.nearLimit && !r.overLimit);

  console.log(
    `\n${reports.length} contract(s) measured, ${failing.length} over the EIP-170 ceiling, ` +
      `${warning.length} within the non-failing warning band.`,
  );

  if (failing.length > 0) {
    console.error(
      `\nFAIL: ${failing.map((r) => r.name).join(", ")} exceed the EIP-170 ${EIP170_RUNTIME_LIMIT_BYTES}-byte ` +
        `runtime bytecode ceiling. This is a hard protocol limit — CREATE/CREATE2 deployment reverts above it. ` +
        `Reduce contract size; do not change this gate.`,
    );
    process.exitCode = 1;
  }
}

if (process.argv[1]?.includes("validate-bytecode-size")) {
  main();
}
