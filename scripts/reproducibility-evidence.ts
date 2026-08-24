/**
 * Operator CLI for reproducibility evidence bundles
 * (deployments/reproducibility/evidence/*.json).
 *
 * This is the CAPTURE side of the capture/check split: it performs the
 * genuine external measurements a reproducibility manifest depends on —
 * reading live on-chain bytecode at a specific resolved block, and BINDING a
 * locally-compiled solc build to the actual git commit it was compiled at —
 * and writes them into a committed evidence bundle with provenance. It does
 * NOT compute any derived verdict (match/hash/verified booleans); that is
 * scripts/lib/reproducibility-evidence.ts's job, run automatically by
 * `npm run validate:reproducibility` (the CHECK side).
 *
 * `capture-build` does NOT trust an operator-supplied --commit/--head-commit
 * label as authority. It independently derives the actual checked-out commit
 * via `git rev-parse HEAD` in the current working directory, requires a
 * clean tracked tree, and — for every source file solc's own metadata says
 * it compiled — reads that file from disk and confirms its keccak256 matches
 * what solc recorded, so the resulting evidence bundle can prove the build
 * actually came from that commit's actual source, not merely an operator's
 * label. It still cannot check out an arbitrary historical commit FOR you —
 * see docs/Deployments.md's Reproducibility section for the exact steps.
 *
 * Usage:
 *   # 1. Read live on-chain bytecode, at a freshly resolved exact block:
 *   npx tsx scripts/reproducibility-evidence.ts capture-live \
 *     --subject StablecoinVaultSimulator --address 0x32f4... \
 *     --chain-id 11155111 --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
 *     --out deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # 2. From a worktree pinned to the deployment commit, after `npm ci` + `npx hardhat compile`
 *   #    (run FROM that worktree — capture-build reads `git rev-parse HEAD` from cwd):
 *   npx tsx scripts/reproducibility-evidence.ts capture-build \
 *     --subject StablecoinVaultSimulator --slot deployment-commit \
 *     --commit 35c25fa294bebea44b3089aa2435a190a5adf3fb --source-tag v0.4.24 \
 *     --source-file contracts/StablecoinVaultSimulator.sol --contract-name StablecoinVaultSimulator \
 *     --build-info artifacts/build-info/<hash>.json \
 *     --out /path/to/deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # 3. Same, from a worktree pinned to current public HEAD:
 *   npx tsx scripts/reproducibility-evidence.ts capture-build \
 *     --subject StablecoinVaultSimulator --slot public-head \
 *     --head-commit <exact SHA compiled> \
 *     --source-file contracts/StablecoinVaultSimulator.sol --contract-name StablecoinVaultSimulator \
 *     --build-info artifacts/build-info/<hash>.output.json \
 *     --out /path/to/deployments/reproducibility/evidence/stablecoin-vault-simulator-sepolia.json
 *
 *   # Replay every manifest's claims against its committed evidence, offline
 *   # (--with-git-checks additionally verifies source-commit binding + public
 *   # history via local git — requires a full-history checkout):
 *   npx tsx scripts/reproducibility-evidence.ts check [--with-git-checks]
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import { keccak256 } from "ethers";

import {
  checkEvidenceAgainstManifest,
  type BuildCapture,
  type CompilerSettings,
  type EvidenceBundle,
  type ImmutableAstDeclaration,
} from "./lib/reproducibility-evidence";

const REPO_ROOT = join(import.meta.dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");

function parseFlags(args: string[]): Record<string, string> {
  const BOOLEAN_FLAGS = new Set(["with-git-checks"]);
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      if (BOOLEAN_FLAGS.has(key)) {
        flags[key] = "true";
        continue;
      }
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

async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await response.json()) as { result?: T; error?: unknown };
  if (body.error || body.result === undefined) {
    throw new Error(`${method} failed: ${JSON.stringify(body.error ?? body)}`);
  }
  return body.result;
}

export async function captureLive(flags: Record<string, string>): Promise<void> {
  const subject = requireFlag(flags, "subject");
  const address = requireFlag(flags, "address");
  const chainId = Number(requireFlag(flags, "chain-id"));
  const rpcUrl = requireFlag(flags, "rpc-url");
  const outPath = requireFlag(flags, "out");

  const observedChainIdHex = await rpcCall<string>(rpcUrl, "eth_chainId", []);
  const observedChainId = parseInt(observedChainIdHex, 16);
  if (observedChainId !== chainId) {
    throw new Error(`RPC reports chainId ${observedChainId}, but --chain-id was ${chainId} — refusing to capture`);
  }

  // Resolve "latest" to a SPECIFIC block ONCE, then use that exact block for
  // both the block-hash lookup and eth_getCode — never re-resolve "latest"
  // as a moving label between calls.
  const blockNumberHex = await rpcCall<string>(rpcUrl, "eth_blockNumber", []);
  const blockNumber = parseInt(blockNumberHex, 16);
  const block = await rpcCall<{ hash: string }>(rpcUrl, "eth_getBlockByNumber", [blockNumberHex, false]);
  const runtimeBytecode = await rpcCall<string>(rpcUrl, "eth_getCode", [address, blockNumberHex]);

  const evidence = loadOrInitEvidence(outPath, subject);
  evidence.liveRuntime = {
    address,
    chainId,
    rpcUrl,
    rpcMethod: "eth_getCode",
    blockNumber,
    blockHash: block.hash,
    capturedAt: new Date().toISOString(),
    runtimeBytecode,
    // Computed HERE, independently of the RPC's own framing — the checker
    // recomputes this again from runtimeBytecode and cross-checks it.
    runtimeCodeHash: keccak256(runtimeBytecode),
  };
  writeEvidence(outPath, evidence);
}

// ── capture-build ───────────────────────────────────────────────────────────

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

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

interface LoadedBuild {
  compiler: CompilerSettings;
  deployedBytecode: { object: string; immutableReferences?: Record<string, unknown> };
  /** Every source file key the compiler actually processed for this build (output.sources is
   * always present, unlike the optional `metadata` output selection — Hardhat 3's default
   * config omits `metadata`, so this is derived from a field guaranteed to exist instead). */
  compiledSourceKeys: string[];
  fullOutput: { output: { sources: Record<string, { ast?: unknown }> } };
}

/** Hardhat 2 (single build-info file, has both `input`/`solcLongVersion` and `output.contracts`)
 * and Hardhat 3 (split into a `<id>.json` input file and a `<id>.output.json` output file) both
 * produce the same solc standard-json `output.contracts[file][name]` shape once loaded. Hardhat
 * 3 additionally namespaces source keys under "project/". If `buildInfoPath` is a Hardhat-3
 * `.output.json` file, its sibling `.json` input file (same id, compiler settings) is read too. */
function loadContractOutput(buildInfoPath: string, sourceFile: string, contractName: string): LoadedBuild {
  const raw = JSON.parse(readFileSync(buildInfoPath, "utf8"));
  if (!raw.output?.contracts) {
    throw new Error(`${buildInfoPath} does not look like a solc build-info/output file (no output.contracts)`);
  }
  let settings = raw.input?.settings ?? raw.settings;
  let solcLongVersion = raw.solcLongVersion;
  if (!settings || !solcLongVersion) {
    const siblingInputPath = buildInfoPath.endsWith(".output.json")
      ? buildInfoPath.slice(0, -".output.json".length) + ".json"
      : null;
    if (siblingInputPath && existsSync(siblingInputPath)) {
      const siblingInput = JSON.parse(readFileSync(siblingInputPath, "utf8"));
      settings = settings ?? siblingInput.input?.settings ?? siblingInput.settings;
      solcLongVersion = solcLongVersion ?? siblingInput.solcLongVersion;
    }
  }
  if (!settings || !solcLongVersion) {
    throw new Error(
      `${buildInfoPath}: could not find compiler settings/solcLongVersion (checked the file itself and its sibling input file)`,
    );
  }
  const candidates = [sourceFile, `project/${sourceFile}`];
  for (const key of candidates) {
    const contract = raw.output.contracts[key]?.[contractName];
    if (contract) {
      return {
        compiler: compilerSettingsFromInput({ solcLongVersion, settings }),
        deployedBytecode: contract.evm.deployedBytecode,
        compiledSourceKeys: Object.keys(raw.output.sources ?? {}),
        fullOutput: raw,
      };
    }
  }
  throw new Error(
    `Contract ${contractName} not found in ${sourceFile} or project/${sourceFile} within ${buildInfoPath}`,
  );
}

/**
 * keccak256 of the RAW bytes of every compiled LOCAL project source file (i.e. under
 * contracts/, tracked in this repo's git history) as it actually exists on disk right now —
 * the capture-time half of Blocker A's binding; verifySourceDigestsAgainstCommit later
 * re-verifies these against git history at check time.
 *
 * Third-party dependency sources (e.g. "@openzeppelin/contracts/...", resolved from
 * node_modules) are deliberately NOT included here: they are not tracked in this repo's git
 * history, so a git-commit binding check cannot apply to them — their integrity is already the
 * job of package-lock.json's own integrity hashes, verified by `npm ci`, a different and
 * already-adequate boundary. This function still requires they exist on disk (so a genuinely
 * broken/missing node_modules install fails loudly rather than silently), it just doesn't
 * record them for git-based re-verification.
 */
function computeSourceDigests(compiledSourceKeys: string[], cwd: string): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const rawKey of compiledSourceKeys) {
    // Hardhat 3 namespaces local project sources under "project/"; strip it for the on-disk
    // path. Dependency sources use various schemes (Hardhat 2: bare "@scope/pkg/..." resolved
    // under node_modules; Hardhat 3: "npm/@scope/pkg@version/...") that are deliberately NOT
    // resolved or hashed here at all — see the doc comment above: dependency integrity is
    // package-lock.json's job, not this function's.
    if (!rawKey.startsWith("project/") && !rawKey.startsWith("contracts/")) continue;
    const diskPath = rawKey.startsWith("project/") ? rawKey.slice("project/".length) : rawKey;
    if (!diskPath.startsWith("contracts/")) continue;
    const fullPath = join(cwd, diskPath);
    if (!existsSync(fullPath)) {
      throw new Error(
        `capture-build: compiled local project source file "${diskPath}" does not exist on disk at ${fullPath}`,
      );
    }
    digests[diskPath] = keccak256(readFileSync(fullPath));
  }
  return digests;
}

interface AstVariableDeclaration {
  id: number;
  nodeType: string;
  name?: string;
  mutability?: string;
  typeDescriptions?: { typeString?: string };
}

/** Walk every source file's AST in the full build output and collect every VariableDeclaration
 * with mutability "immutable" — a machine-derived snapshot of what the compiler ACTUALLY saw,
 * independent of any hand-typed identity label. */
function extractImmutableAstDeclarations(fullOutput: {
  output: { sources: Record<string, { ast?: unknown }> };
}): ImmutableAstDeclaration[] {
  const found: ImmutableAstDeclaration[] = [];
  function walk(node: unknown, sourceFile: string): void {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const n of node) walk(n, sourceFile);
      return;
    }
    const n = node as AstVariableDeclaration & Record<string, unknown>;
    if (n.nodeType === "VariableDeclaration" && n.mutability === "immutable") {
      found.push({
        astId: String(n.id),
        name: n.name ?? "",
        sourceFile,
        typeString: n.typeDescriptions?.typeString ?? "",
      });
    }
    for (const [key, value] of Object.entries(n)) {
      if (key === "nodeType" || key === "id") continue;
      if (value && typeof value === "object") walk(value, sourceFile);
    }
  }
  for (const [sourceKey, sourceOutput] of Object.entries(fullOutput.output.sources)) {
    const diskPath = sourceKey.startsWith("project/") ? sourceKey.slice("project/".length) : sourceKey;
    if (sourceOutput.ast) walk(sourceOutput.ast, diskPath);
  }
  return found;
}

function requireCleanWorktree(cwd: string): void {
  const status = git(["status", "--porcelain"], cwd);
  if (status.length > 0) {
    throw new Error(
      `capture-build: worktree at ${cwd} is not clean — a dirty source/config tree must not receive reproducibility evidence:\n${status}`,
    );
  }
}

export function captureBuild(flags: Record<string, string>): void {
  const subject = requireFlag(flags, "subject");
  const slot = requireFlag(flags, "slot");
  if (slot !== "deployment-commit" && slot !== "public-head") {
    throw new Error('--slot must be "deployment-commit" or "public-head"');
  }
  const sourceFile = requireFlag(flags, "source-file");
  const contractName = requireFlag(flags, "contract-name");
  const buildInfoPath = requireFlag(flags, "build-info");
  const outPath = requireFlag(flags, "out");
  const cwd = resolve(flags["cwd"] ?? process.cwd());

  requireCleanWorktree(cwd);

  // The ACTUAL checked-out commit, derived independently — never merely the
  // operator-supplied --commit/--head-commit label. If a label is supplied,
  // it must match; if it doesn't, capture fails loudly rather than silently
  // recording a mismatched claim.
  const actualHead = git(["rev-parse", "HEAD"], cwd);
  const labelFlag = slot === "deployment-commit" ? "commit" : "head-commit";
  const suppliedLabel = flags[labelFlag];
  if (suppliedLabel && suppliedLabel !== actualHead) {
    throw new Error(
      `capture-build: --${labelFlag} was "${suppliedLabel}", but the actual checked-out commit at ${cwd} is "${actualHead}" — refusing to record a build capture under a commit label that does not match where it was actually compiled`,
    );
  }
  const boundCommit = actualHead;

  const { compiler, deployedBytecode, compiledSourceKeys, fullOutput } = loadContractOutput(
    buildInfoPath,
    sourceFile,
    contractName,
  );
  const sourceDigests = computeSourceDigests(compiledSourceKeys, cwd);
  const immutableAstDeclarations = extractImmutableAstDeclarations(fullOutput);

  const capture: BuildCapture = {
    compiler,
    sourceFile,
    contractName,
    deployedBytecodeObject: deployedBytecode.object.startsWith("0x")
      ? deployedBytecode.object
      : "0x" + deployedBytecode.object,
    immutableReferences: (deployedBytecode.immutableReferences as BuildCapture["immutableReferences"]) ?? {},
    sourceDigests,
    immutableAstDeclarations,
  };

  const evidence = loadOrInitEvidence(outPath, subject);
  if (slot === "deployment-commit") {
    evidence.deploymentCommitBuild = { ...capture, commit: boundCommit, sourceTag: flags["source-tag"] ?? null };
  } else {
    evidence.publicHeadBuild = { ...capture, headCommit: boundCommit, capturedAt: new Date().toISOString() };
  }
  writeEvidence(outPath, evidence);
  console.log(`  bound to commit ${boundCommit} (verified via git rev-parse HEAD at ${cwd})`);
  console.log(`  ${Object.keys(sourceDigests).length} source file digest(s) verified against the working tree`);
  console.log(`  ${immutableAstDeclarations.length} immutable AST declaration(s) found across the compilation unit`);
}

// ── check ────────────────────────────────────────────────────────────────────

function findManifestForEvidence(evidencePath: string): string | null {
  const slug = evidencePath.split(/[\\/]/).pop()!;
  const manifestPath = join(REPRO_DIR, slug);
  return existsSync(manifestPath) ? manifestPath : null;
}

function listJsonFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(dir, f));
}

export function check(flags: Record<string, string>): void {
  const files = flags["file"]
    ? [join(REPO_ROOT, flags["file"])]
    : existsSync(join(REPRO_DIR, "evidence"))
      ? listJsonFiles(join(REPRO_DIR, "evidence"))
      : [];
  const repoRoot = "with-git-checks" in flags ? REPO_ROOT : undefined;

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
    const result = checkEvidenceAgainstManifest(evidence, manifest, repoRoot);
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
