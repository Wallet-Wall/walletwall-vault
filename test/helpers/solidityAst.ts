import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * Loads the solc-emitted AST already produced by the normal Hardhat compile —
 * no parser dependency. `hardhat compile` writes one or more
 * `artifacts/build-info/*.output.json` files (Hardhat's incremental compiler
 * can split sources across several such files — observed directly: adding two
 * new fixture contracts here produced a second build-info file alongside the
 * original one covering the other ~24 sources), each holding the full solc
 * standard-JSON output, including `output.sources[<path>].ast` (a `SourceUnit`
 * AST node) for every compiled file. This module is the single place that
 * knows how to find a given source file's AST across however many build-info
 * files exist.
 */

const REPO_ROOT = join(import.meta.dirname, "..", "..");
const BUILD_INFO_DIR = join(REPO_ROOT, "artifacts", "build-info");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AstNode = Record<string, any>;

interface BuildInfoFile {
  output?: { sources?: Record<string, { ast?: AstNode }> };
}

/**
 * The solc `SourceUnit` AST for `repoRelativePath` (e.g.
 * `"contracts/WalletWallVault.sol"`), found by scanning every build-info file
 * for a source key ending in that path (Hardhat 3 keys sources like
 * `"project/contracts/Foo.sol"` — matched by suffix so this survives that
 * prefix changing).
 *
 * Hardhat's incremental compiler does not delete a superseded build-info file
 * when a later compile only re-runs a subset of sources — a STALE file
 * matching this path can coexist with a fresh one (observed directly: editing
 * one fixture contract left both the old and new build-info files on disk,
 * each containing a same-path `ast` entry with a DIFFERENT function set).
 * Collecting every match and keeping the one from the most-recently-written
 * build-info file (`mtimeMs`) is what makes this deterministic; returning the
 * first directory-iteration hit silently picked the stale one in practice.
 */
export function loadSourceAst(repoRelativePath: string): AstNode {
  if (!existsSync(BUILD_INFO_DIR)) {
    throw new Error(`${BUILD_INFO_DIR} does not exist — run \`npm run compile\` first`);
  }
  const normalized = repoRelativePath.replace(/\\/g, "/");
  let best: { ast: AstNode; mtimeMs: number } | undefined;
  for (const file of readdirSync(BUILD_INFO_DIR)) {
    if (!file.endsWith(".output.json")) continue;
    const fullPath = join(BUILD_INFO_DIR, file);
    const data = JSON.parse(readFileSync(fullPath, "utf8")) as BuildInfoFile;
    const sources = data.output?.sources ?? {};
    for (const key of Object.keys(sources)) {
      if (key !== normalized && !key.endsWith("/" + normalized)) continue;
      const ast = sources[key].ast;
      if (!ast) continue;
      const mtimeMs = statSync(fullPath).mtimeMs;
      if (!best || mtimeMs > best.mtimeMs) best = { ast, mtimeMs };
    }
  }
  if (!best) {
    throw new Error(
      `no compiled AST found for "${repoRelativePath}" in any artifacts/build-info/*.output.json — run \`npm run compile\``,
    );
  }
  return best.ast;
}

/** Depth-first visit of every descendant AST node (skips `src`/`documentation` — never structural). */
export function walkAst(node: unknown, visit: (n: AstNode) => void): void {
  if (!node || typeof node !== "object") return;
  const n = node as AstNode;
  if (typeof n.nodeType === "string") visit(n);
  for (const key of Object.keys(n)) {
    if (key === "src" || key === "documentation") continue;
    const v = n[key];
    if (Array.isArray(v)) {
      for (const item of v) walkAst(item, visit);
    } else if (v && typeof v === "object") {
      walkAst(v, visit);
    }
  }
}

/** The `ContractDefinition` node named `contractName`, declared directly in `sourceUnitAst` (not an import). */
export function findContract(sourceUnitAst: AstNode, contractName: string): AstNode {
  const found = ((sourceUnitAst.nodes as AstNode[]) ?? []).find(
    (n) => n.nodeType === "ContractDefinition" && n.name === contractName,
  );
  if (!found) throw new Error(`contract "${contractName}" not found in source unit`);
  return found;
}

/**
 * Every function directly declared in `contractAst` (not inherited), as
 * `{name, node}` pairs. The constructor (if any) is reported with
 * `name: "constructor"` so callers can treat it uniformly.
 */
export function listFunctionDefinitions(contractAst: AstNode): { name: string; node: AstNode }[] {
  const out: { name: string; node: AstNode }[] = [];
  for (const node of (contractAst.nodes as AstNode[]) ?? []) {
    if (node.nodeType !== "FunctionDefinition") continue;
    out.push({ name: node.kind === "constructor" ? "constructor" : (node.name as string), node });
  }
  return out;
}

/** One function (or `"constructor"`) declared directly in `contractAst`, by name. */
export function findFunctionDefinition(contractAst: AstNode, functionName: string): AstNode {
  const found = listFunctionDefinitions(contractAst).find((f) => f.name === functionName);
  if (!found) throw new Error(`function "${functionName}" not found in contract "${contractAst.name}"`);
  return found.node;
}

/** The AST `id` of the state variable `variableName` declared directly in `contractAst`. */
export function findStateVariableId(contractAst: AstNode, variableName: string): number {
  const found = ((contractAst.nodes as AstNode[]) ?? []).find(
    (n) => n.nodeType === "VariableDeclaration" && n.stateVariable && n.name === variableName,
  );
  if (!found) throw new Error(`state variable "${variableName}" not found in contract "${contractAst.name}"`);
  return found.id as number;
}
