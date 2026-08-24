/**
 * Operator CLI for reproducibility evidence bundles
 * (deployments/reproducibility/evidence/*.json).
 *
 * This is the CAPTURE side of the capture/check split: it performs the two
 * genuine external measurements a reproducibility manifest depends on —
 * reading live on-chain bytecode, and recording a solc build already
 * compiled locally — and writes them into a committed evidence bundle with
 * provenance. It does NOT compute any derived verdict (match/hash/verified
 * booleans); that is scripts/lib/reproducibility-evidence.ts's job, run
 * automatically by `npm run validate:reproducibility` (the CHECK side).
 *
 * `capture-build` cannot check out an arbitrary historical commit for you —
 * compiling "from the deployment commit" requires actually being in a
 * worktree pinned to that commit with its own lockfile installed (see
 * docs/Deployments.md's Reproducibility section for the exact steps). This
 * CLI only records the build-info Hardhat already produced once you've done
 * that, together with which commit it represents.
 *
 * Usage:
 *   # 1. Read live on-chain bytecode (network read only, writes nothing else):
 *   npx tsx scripts/reproducibility-evidence.ts capture-live \
 *     --subject StablecoinVaultSimulator --address 0x32f4... \
 *     --chain-id 11155111 --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
 *     --out deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # 2. From a worktree pinned to the deployment commit, after `npm ci` + `npx hardhat compile`:
 *   npx tsx scripts/reproducibility-evidence.ts capture-build \
 *     --subject StablecoinVaultSimulator --slot deployment-commit \
 *     --commit 35c25fa294bebea44b3089aa2435a190a5adf3fb --source-tag v0.4.24 \
 *     --source-file contracts/StablecoinVaultSimulator.sol --contract-name StablecoinVaultSimulator \
 *     --build-info artifacts/build-info/<hash>.json \
 *     --out deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # 3. Same, from a worktree at current public HEAD:
 *   npx tsx scripts/reproducibility-evidence.ts capture-build \
 *     --subject StablecoinVaultSimulator --slot public-head \
 *     --head-commit <exact SHA compiled> \
 *     --source-file contracts/StablecoinVaultSimulator.sol --contract-name StablecoinVaultSimulator \
 *     --build-info artifacts/build-info/<hash>.output.json \
 *     --out deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # Replay every manifest's claims against its committed evidence, offline:
 *   npx tsx scripts/reproducibility-evidence.ts check
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "fs";
import { join, relative } from "path";

import {
  checkEvidenceAgainstManifest,
  type BuildCapture,
  type CompilerSettings,
  type EvidenceBundle,
} from "./lib/reproducibility-evidence";

const REPO_ROOT = join(import.meta.dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");

function parseFlags(args: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = args[i + 1];
      if (value === undefined || value.startsWith("--")) throw new Error(`--${key} requires a value`);
      flags[key] = value;
      i++;
    }
  }
  return flags;
}

function requireFlag(flags: Record<string, string>, name: string): string {
  const value = flags[name];
  if (!value) throw new Error(`Missing required flag: --${name}`);
  return value;
}

function loadOrInitEvidence(outPath: string, subject: string): EvidenceBundle {
  if (existsSync(outPath)) {
    const existing = JSON.parse(readFileSync(outPath, "utf8")) as EvidenceBundle;
    if (existing.subject !== subject) {
      throw new Error(`${outPath} already holds evidence for subject "${existing.subject}", not "${subject}"`);
    }
    return existing;
  }
  return {
    $schema: "./schema/evidence.schema.json",
    version: "1",
    subject,
  } as EvidenceBundle;
}

function writeEvidence(outPath: string, evidence: EvidenceBundle): void {
  writeFileSync(outPath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(`Wrote ${relative(REPO_ROOT, outPath)}`);
}

// ── capture-live ────────────────────────────────────────────────────────────

async function captureLive(flags: Record<string, string>): Promise<void> {
  const subject = requireFlag(flags, "subject");
  const address = requireFlag(flags, "address");
  const chainId = Number(requireFlag(flags, "chain-id"));
  const rpcUrl = requireFlag(flags, "rpc-url");
  const blockTag = flags["block-tag"] ?? "latest";
  const outPath = requireFlag(flags, "out");

  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, blockTag] }),
  });
  const body = (await response.json()) as { result?: string; error?: unknown };
  if (body.error || !body.result) {
    throw new Error(`eth_getCode failed: ${JSON.stringify(body.error ?? body)}`);
  }

  const chainIdResponse = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
  });
  const chainIdBody = (await chainIdResponse.json()) as { result?: string };
  const observedChainId = chainIdBody.result ? parseInt(chainIdBody.result, 16) : null;
  if (observedChainId !== chainId) {
    throw new Error(`RPC reports chainId ${observedChainId}, but --chain-id was ${chainId} — refusing to capture`);
  }

  const evidence = loadOrInitEvidence(outPath, subject);
  evidence.liveRuntime = {
    address,
    chainId,
    rpcUrl,
    rpcMethod: "eth_getCode",
    blockTag,
    capturedAt: new Date().toISOString(),
    runtimeBytecode: body.result,
  };
  writeEvidence(outPath, evidence);
}

// ── capture-build ───────────────────────────────────────────────────────────

function compilerSettingsFromInput(input: {
  solcLongVersion: string;
  settings: { optimizer: { enabled: boolean; runs: number }; evmVersion: string };
}): CompilerSettings {
  return {
    solcLongVersion: input.solcLongVersion,
    optimizerEnabled: input.settings.optimizer.enabled,
    optimizerRuns: input.settings.optimizer.runs,
    evmVersion: input.settings.evmVersion,
  };
}

/** Hardhat 2 (single build-info file) and Hardhat 3 (split input/.output.json) both produce
 * the same solc standard-json `output.contracts[file][name]` shape once loaded; this only
 * needs to find the right one, given either a single file or split input+output pair. */
function loadContractOutput(
  buildInfoPath: string,
  sourceFile: string,
  contractName: string,
): { compiler: CompilerSettings; deployedBytecode: { object: string; immutableReferences?: Record<string, unknown> } } {
  const raw = JSON.parse(readFileSync(buildInfoPath, "utf8"));
  if (raw.output?.contracts) {
    // Hardhat 2 single-file build-info, or a Hardhat 3 .output.json passed alongside its own input.
    const settings = raw.input?.settings ?? raw.settings;
    const solcLongVersion = raw.solcLongVersion;
    // Hardhat 3 namespaces source keys under "project/"; try both.
    const candidates = [sourceFile, `project/${sourceFile}`];
    for (const key of candidates) {
      const contract = raw.output.contracts[key]?.[contractName];
      if (contract) {
        return {
          compiler:
            solcLongVersion && settings
              ? compilerSettingsFromInput({ solcLongVersion, settings })
              : (raw._compiler as CompilerSettings),
          deployedBytecode: contract.evm.deployedBytecode,
        };
      }
    }
    throw new Error(
      `Contract ${contractName} not found in ${sourceFile} or project/${sourceFile} within ${buildInfoPath}`,
    );
  }
  throw new Error(`${buildInfoPath} does not look like a solc build-info/output file (no output.contracts)`);
}

function captureBuild(flags: Record<string, string>): void {
  const subject = requireFlag(flags, "subject");
  const slot = requireFlag(flags, "slot");
  if (slot !== "deployment-commit" && slot !== "public-head") {
    throw new Error('--slot must be "deployment-commit" or "public-head"');
  }
  const sourceFile = requireFlag(flags, "source-file");
  const contractName = requireFlag(flags, "contract-name");
  const buildInfoPath = requireFlag(flags, "build-info");
  const outPath = requireFlag(flags, "out");

  const { compiler, deployedBytecode } = loadContractOutput(buildInfoPath, sourceFile, contractName);
  const capture: BuildCapture = {
    compiler,
    sourceFile,
    contractName,
    deployedBytecodeObject: deployedBytecode.object.startsWith("0x")
      ? deployedBytecode.object
      : "0x" + deployedBytecode.object,
    immutableReferences: (deployedBytecode.immutableReferences as BuildCapture["immutableReferences"]) ?? {},
  };

  const evidence = loadOrInitEvidence(outPath, subject);
  if (slot === "deployment-commit") {
    evidence.deploymentCommitBuild = {
      ...capture,
      commit: requireFlag(flags, "commit"),
      sourceTag: flags["source-tag"] ?? null,
    };
  } else {
    evidence.publicHeadBuild = {
      ...capture,
      headCommit: requireFlag(flags, "head-commit"),
      capturedAt: new Date().toISOString(),
    };
  }
  writeEvidence(outPath, evidence);
}

// ── check ────────────────────────────────────────────────────────────────────

function findManifestForEvidence(evidencePath: string): string | null {
  const slug = evidencePath.split(/[\\/]/).pop()!;
  const manifestPath = join(REPRO_DIR, slug);
  return existsSync(manifestPath) ? manifestPath : null;
}

function check(flags: Record<string, string>): void {
  const files = flags["file"]
    ? [join(REPO_ROOT, flags["file"])]
    : existsSync(join(REPRO_DIR, "evidence"))
      ? listJsonFiles(join(REPRO_DIR, "evidence"))
      : [];

  if (files.length === 0) {
    console.log("No evidence bundles found.");
    return;
  }

  let failCount = 0;
  for (const evidencePath of files) {
    const manifestPath = findManifestForEvidence(evidencePath);
    if (!manifestPath) {
      console.error(`FAIL  ${relative(REPO_ROOT, evidencePath)} — no matching manifest found`);
      failCount++;
      continue;
    }
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8")) as EvidenceBundle;
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    const result = checkEvidenceAgainstManifest(evidence, manifest);
    if (result.ok) {
      console.log(`PASS  ${relative(REPO_ROOT, manifestPath)}`);
    } else {
      console.error(`FAIL  ${relative(REPO_ROOT, manifestPath)}`);
      for (const e of result.errors) console.error(`  [error] ${e}`);
      failCount++;
    }
  }
  if (failCount > 0) process.exitCode = 1;
}

function listJsonFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(dir, f));
}

// ── entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const flags = parseFlags(rest);
  switch (command) {
    case "capture-live":
      await captureLive(flags);
      break;
    case "capture-build":
      captureBuild(flags);
      break;
    case "check":
      check(flags);
      break;
    default:
      console.error("Usage: reproducibility-evidence.ts <capture-live|capture-build|check> [--flags]");
      process.exitCode = 1;
  }
}

if (process.argv[1]?.includes("reproducibility-evidence")) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
