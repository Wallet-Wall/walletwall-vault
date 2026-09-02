/**
 * Compiles the kernel/factory sources with one or more files textually
 * overridden, entirely in memory -- never writes to the real
 * prototype/vnext-kernel/contracts/ tree. Used ONLY by
 * test/AuthorityCompletenessMutations.test.ts to prove check.ts actually
 * detects the historical and adversarial bypass classes (PHASES 7-9, 15),
 * never by check.ts itself.
 *
 * Drives the same PINNED solc binary reproduce.ts uses, directly via
 * --standard-json (no Hardhat), so a mutation compiles in milliseconds
 * without touching prototype/vnext-kernel/artifacts/ or its cache.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildCompiledSources, type CompiledSources } from "./ast.js";

const SOLC_VERSION = "0.8.24";
const ROOT = path.join("prototype", "vnext-kernel");
const SRC = path.join(ROOT, "contracts");

const KERNEL_FILES = ["VaultKernelPrototype.sol", "VaultKernelFactoryPrototype.sol", "PrototypeMocks.sol", "interfaces/IKernelPlanes.sol"];

// Duplicated from reproduce.ts deliberately (see that file's own comment on the same
// functions): this module must stay compilable and runnable standalone by the mutation
// test suite without depending on reproduce.ts's CLI-oriented `main()`/export surface.
function compilerCachePlatform(): string {
  switch (os.platform()) {
    case "win32":
      return "windows-amd64";
    case "linux":
      return os.arch() === "arm64" ? "linux-arm64" : "linux-amd64";
    case "darwin":
      return "macosx-amd64";
    default:
      throw new Error(`no native solc cache layout known for platform ${os.platform()}/${os.arch()}`);
  }
}

function hardhatCacheRoot(): string {
  const home = os.homedir();
  switch (os.platform()) {
    case "win32":
      return path.join(process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local"), "hardhat-nodejs", "Cache");
    case "darwin":
      return path.join(home, "Library", "Caches", "hardhat-nodejs");
    case "linux":
      return path.join(process.env.XDG_CACHE_HOME ?? path.join(home, ".cache"), "hardhat-nodejs");
    default:
      throw new Error(`no known hardhat cache directory convention for platform ${os.platform()}`);
  }
}

function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) throw new Error(`pinned solc ${SOLC_VERSION} not found in ${base}`);
  return path.join(base, hit);
}

export interface MutationCompileResult {
  readonly ok: true;
  readonly compiled: CompiledSources;
}
export interface MutationCompileFailure {
  readonly ok: false;
  readonly errors: string[];
}

/**
 * @param overrides map of filename (relative to prototype/vnext-kernel/contracts/,
 *   e.g. "VaultKernelPrototype.sol") to REPLACEMENT source text. Files not listed are
 *   read unmodified from disk. Never writes anything to disk itself.
 */
export function compileMutatedKernel(overrides: Readonly<Record<string, string>>): MutationCompileResult | MutationCompileFailure {
  const solc = solcPath();
  const sources: Record<string, { content: string }> = {};
  for (const relFile of KERNEL_FILES) {
    const key = path.posix.join("contracts", relFile.split(path.sep).join("/"));
    const content = overrides[relFile] ?? fs.readFileSync(path.join(SRC, relFile), "utf8");
    sources[key] = { content };
  }

  const input = {
    language: "Solidity",
    sources,
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
      outputSelection: { "*": { "": ["ast"] } },
    },
  };

  const raw = execFileSync(solc, ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 256 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw);
  const fatal: string[] = (parsed.errors ?? []).filter((e: { severity: string }) => e.severity === "error").map((e: { formattedMessage: string }) => e.formattedMessage);
  if (fatal.length > 0) return { ok: false, errors: fatal };

  return { ok: true, compiled: buildCompiledSources(parsed.sources) };
}

/**
 * Replaces `oldSnippet` with `newSnippet` ONLY within the named function's own
 * body (found by brace-matching from `function <name>(` or `modifier <name>(`),
 * so a mutation targeting e.g. rotateCredential cannot accidentally also mutate
 * execute/setVerifier/setPolicy, which share several identical call sites. Throws
 * if the function or the snippet (exactly once) cannot be found -- a silently
 * no-op mutation would be worse than a loud one.
 */
export function replaceWithinFunction(source: string, functionName: string, oldSnippet: string, newSnippet: string): string {
  const marker = new RegExp(`\\b(function|modifier)\\s+${functionName}\\s*\\(`);
  const startMatch = marker.exec(source);
  if (!startMatch) throw new Error(`could not find function/modifier "${functionName}" in source`);
  const openBraceIdx = source.indexOf("{", startMatch.index);
  if (openBraceIdx === -1) throw new Error(`could not find opening brace for "${functionName}"`);
  let depth = 0;
  let endBraceIdx = -1;
  for (let i = openBraceIdx; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) {
        endBraceIdx = i;
        break;
      }
    }
  }
  if (endBraceIdx === -1) throw new Error(`could not find matching closing brace for "${functionName}"`);

  const before = source.slice(0, openBraceIdx);
  const body = source.slice(openBraceIdx, endBraceIdx + 1);
  const after = source.slice(endBraceIdx + 1);

  const occurrences = body.split(oldSnippet).length - 1;
  if (occurrences !== 1) {
    throw new Error(`expected exactly 1 occurrence of the target snippet inside "${functionName}", found ${occurrences}`);
  }
  return before + body.replace(oldSnippet, newSnippet) + after;
}

/** Inserts `newCode` immediately before the named function/modifier's own definition (for adding a new function/modifier alongside an existing one, at a stable location). */
export function insertBeforeFunction(source: string, anchorFunctionName: string, newCode: string): string {
  const marker = new RegExp(`\\n(\\s*)(function|modifier)\\s+${anchorFunctionName}\\s*\\(`);
  const m = marker.exec(source);
  if (!m) throw new Error(`could not find anchor function/modifier "${anchorFunctionName}"`);
  return source.slice(0, m.index) + "\n" + newCode + source.slice(m.index);
}

export { KERNEL_FILES, SRC };
