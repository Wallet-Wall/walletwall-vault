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

import { keccak256, toUtf8Bytes } from "ethers";

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

interface CompilerInput {
  language: string;
  sources: Record<string, { content?: string; urls?: string[] }>;
  settings: { optimizer: { enabled: boolean; runs: number }; evmVersion: string };
}

interface LoadedBuild {
  compiler: CompilerSettings;
  deployedBytecode: { object: string; immutableReferences?: Record<string, unknown> };
  /** The ACTUAL solc standard-json input this output was produced from — the compiler's own
   * record of what it was asked to compile, including literal source content, not merely a
   * disk snapshot taken separately at capture time. See loadCompilerInputFor. */
  compilerInput: CompilerInput;
  compilerInputHash: string;
  fullOutput: { output: { sources: Record<string, { ast?: unknown }> } };
}

/**
 * Load the solc standard-json INPUT that actually produced a given build-info's OUTPUT,
 * proving the pairing rather than assuming it from filenames.
 *
 * Hardhat 2 emits one build-info file containing both `input` and `output` together — no
 * pairing ambiguity is possible. Hardhat 3 splits them into a `<id>.json` input file and a
 * sibling `<id>.output.json` output file; BOTH carry the SAME `id` (Hardhat's own internal
 * pairing key, not a filename convention). This function requires that `id` to be present on
 * both sides and to match before trusting the pair — "same directory, plausible filename" is
 * explicitly NOT accepted as proof they belong together.
 */
function loadCompilerInputFor(buildInfoPath: string, raw: Record<string, unknown>): CompilerInput {
  if (raw["input"]) {
    return raw["input"] as CompilerInput; // Hardhat 2: input and output are the same file.
  }
  const siblingInputPath = buildInfoPath.endsWith(".output.json")
    ? buildInfoPath.slice(0, -".output.json".length) + ".json"
    : null;
  if (!siblingInputPath || !existsSync(siblingInputPath)) {
    throw new Error(
      `${buildInfoPath}: has no "input" field and no sibling "<id>.json" input file was found — cannot bind this output to a compiler input`,
    );
  }
  const siblingInput = JSON.parse(readFileSync(siblingInputPath, "utf8")) as Record<string, unknown>;
  const outputId = raw["id"];
  const inputId = siblingInput["id"];
  if (outputId === undefined || inputId === undefined) {
    throw new Error(
      `capture-build: cannot verify the input/output pairing for ${buildInfoPath} — missing "id" field on the output file, the sibling input file (${siblingInputPath}), or both. Refusing to accept a sibling file merely because its filename fits the convention.`,
    );
  }
  if (outputId !== inputId) {
    throw new Error(
      `capture-build: output file id "${String(outputId)}" (${buildInfoPath}) does not match sibling input file id "${String(inputId)}" (${siblingInputPath}) — these are not actually the same compilation and cannot be bound together`,
    );
  }
  if (!siblingInput["input"]) {
    throw new Error(`${siblingInputPath}: has a matching id but no "input" field — not a valid solc input file`);
  }
  return siblingInput["input"] as CompilerInput;
}

/** Deterministic JSON serialization (recursively sorted object keys) so compilerInputHash does
 * not depend on incidental key-insertion order. */
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalStringify).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
}

/** Hardhat 2 (single build-info file, has both `input`/`solcLongVersion` and `output.contracts`)
 * and Hardhat 3 (split into a `<id>.json` input file and a `<id>.output.json` output file) both
 * produce the same solc standard-json `output.contracts[file][name]` shape once loaded. Hardhat
 * 3 additionally namespaces source keys under "project/". */
function loadContractOutput(buildInfoPath: string, sourceFile: string, contractName: string): LoadedBuild {
  const raw = JSON.parse(readFileSync(buildInfoPath, "utf8")) as Record<string, unknown>;
  const output = raw["output"] as { contracts?: Record<string, Record<string, unknown>> } | undefined;
  if (!output?.contracts) {
    throw new Error(`${buildInfoPath} does not look like a solc build-info/output file (no output.contracts)`);
  }
  const compilerInput = loadCompilerInputFor(buildInfoPath, raw);
  const solcLongVersion = (raw["solcLongVersion"] as string | undefined) ?? "unknown";
  const compilerInputHash = keccak256(toUtf8Bytes(canonicalStringify(compilerInput)));

  const candidates = [sourceFile, `project/${sourceFile}`];
  for (const key of candidates) {
    const contract = output.contracts[key]?.[contractName] as
      { evm: { deployedBytecode: LoadedBuild["deployedBytecode"] } } | undefined;
    if (contract) {
      return {
        compiler: compilerSettingsFromInput({ solcLongVersion, settings: compilerInput.settings }),
        deployedBytecode: contract.evm.deployedBytecode,
        compilerInput,
        compilerInputHash,
        fullOutput: raw as LoadedBuild["fullOutput"],
      };
    }
  }
  throw new Error(
    `Contract ${contractName} not found in ${sourceFile} or project/${sourceFile} within ${buildInfoPath}`,
  );
}

/**
 * keccak256 of the LITERAL source content solc's own compiler input recorded for every
 * compiled LOCAL project source file (i.e. under contracts/, tracked in this repo's git
 * history) — NOT a separately-taken disk snapshot. This is what closes the full chain: the
 * content hashed here is proven (by construction — it's the compiler's own recorded input) to
 * be exactly what produced deployedBytecodeObject, so comparing it against
 * `git show <commit>:<path>` (verifySourceDigestsAgainstCommit, at check time) proves the
 * OUTPUT — not merely a disk snapshot taken separately — came from that commit's real content.
 *
 * Third-party dependency sources (e.g. "@openzeppelin/contracts/...") are deliberately NOT
 * included: they are not tracked in this repo's git history, so a git-commit binding check
 * cannot apply to them — package-lock.json's own integrity hashes (enforced by `npm ci`)
 * already cover that boundary. They ARE still folded into compilerInputHash (see
 * loadContractOutput), which hashes the ENTIRE compiler input — sources, settings, and
 * language — so the complete compilation input is frozen and auditable even where git is not
 * the authority for a given source.
 */
function deriveSourceDigestsFromCompilerInput(compilerInput: CompilerInput): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const [rawKey, entry] of Object.entries(compilerInput.sources)) {
    const diskPath = rawKey.startsWith("project/") ? rawKey.slice("project/".length) : rawKey;
    if (!diskPath.startsWith("contracts/")) continue;
    if (typeof entry.content !== "string") {
      throw new Error(
        `capture-build: compiler input for local source "${diskPath}" has no embedded literal content (got a URL reference instead) — cannot bind it to git without the actual compiled text`,
      );
    }
    digests[diskPath] = keccak256(toUtf8Bytes(entry.content));
  }
  return digests;
}

/**
 * Sanity check (not itself part of the committed evidence): confirms the files currently on
 * disk in this worktree still match what the compiler input says it compiled, catching operator
 * error (e.g. editing a file after compiling, before running capture-build) as an immediate,
 * loud failure rather than silently recording a mismatch between output and disk state.
 */
function verifyDigestsMatchWorkingTree(sourceDigests: Record<string, string>, cwd: string): void {
  for (const [diskPath, expectedDigest] of Object.entries(sourceDigests)) {
    const fullPath = join(cwd, diskPath);
    if (!existsSync(fullPath)) {
      throw new Error(`capture-build: "${diskPath}" is in the compiler input but missing from disk at ${fullPath}`);
    }
    const actual = keccak256(readFileSync(fullPath));
    if (actual.toLowerCase() !== expectedDigest.toLowerCase()) {
      throw new Error(
        `capture-build: "${diskPath}" on disk (keccak256 ${actual}) no longer matches the compiler input that produced this build-info (${expectedDigest}) — the working tree has drifted since compilation; recompile before capturing`,
      );
    }
  }
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

  const { compiler, deployedBytecode, compilerInput, compilerInputHash, fullOutput } = loadContractOutput(
    buildInfoPath,
    sourceFile,
    contractName,
  );
  // The chain this closes: git commit -> (proven identical to) compiler input content ->
  // (proven, by construction — it's the SAME object) compiler output/deployedBytecode.
  const sourceDigests = deriveSourceDigestsFromCompilerInput(compilerInput);
  verifyDigestsMatchWorkingTree(sourceDigests, cwd);
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
    compilerInputHash,
  };

  const evidence = loadOrInitEvidence(outPath, subject);
  if (slot === "deployment-commit") {
    evidence.deploymentCommitBuild = { ...capture, commit: boundCommit, sourceTag: flags["source-tag"] ?? null };
  } else {
    evidence.publicHeadBuild = { ...capture, headCommit: boundCommit, capturedAt: new Date().toISOString() };
  }
  writeEvidence(outPath, evidence);
  console.log(`  bound to commit ${boundCommit} (verified via git rev-parse HEAD at ${cwd})`);
  console.log(`  compilerInputHash ${compilerInputHash}`);
  console.log(
    `  ${Object.keys(sourceDigests).length} source file digest(s) derived from the compiler's own input and confirmed to still match the working tree`,
  );
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
