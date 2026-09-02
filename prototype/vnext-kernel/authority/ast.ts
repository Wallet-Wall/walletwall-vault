/**
 * Minimal Solidity solc-standard-JSON AST loader and cross-file declaration
 * resolver, shared by discover.ts and trace.ts. Deliberately does NOT
 * special-case Hardhat 3's "project/..."/"npm/..." build-info source-key
 * scheme (see the vNext Kernel Slither workflow's own comment on that) --
 * this module never needs to turn a key back into a real file path, only
 * to read the AST payload each key already carries.
 */
import fs from "node:fs";
import path from "node:path";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AstNode = any;

export interface CompiledSources {
  readonly bySourceKey: Record<string, { ast: AstNode }>;
  /** Every AST node with an `id`, indexed for cross-file referencedDeclaration lookups. */
  readonly declById: Map<number, AstNode>;
}

function indexNode(node: AstNode, declById: Map<number, AstNode>): void {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) indexNode(item, declById);
    return;
  }
  if (typeof node.id === "number" && typeof node.nodeType === "string") {
    declById.set(node.id, node);
  }
  for (const key of Object.keys(node)) {
    if (key === "src" || key === "nameLocation") continue;
    const value = node[key];
    if (value !== null && typeof value === "object") indexNode(value, declById);
  }
}

/** Builds the cross-file declaration index shared by loadCompiledSources (Hardhat build-info) and the mutation harness (direct solc --standard-json output) -- same shape (`{ [sourceKey]: { ast } }`), different producer. */
export function buildCompiledSources(sources: Record<string, { ast: AstNode }>): CompiledSources {
  const declById = new Map<number, AstNode>();
  for (const key of Object.keys(sources)) {
    const ast = sources[key]?.ast;
    if (!ast) throw new Error(`source "${key}" has no AST -- was it compiled with ast in outputSelection?`);
    indexNode(ast, declById);
  }
  return { bySourceKey: sources, declById };
}

/**
 * Loads every source unit's AST from the ONE Hardhat build-info pair in
 * `buildInfoDir` (this prototype's isolated Hardhat config always produces
 * exactly one -- see hardhat.config.ts -- so "more than one" is treated as
 * an analysis failure rather than picked arbitrarily; a project with
 * multiple compiler runs would need this generalised, not silently
 * guessed).
 */
export function loadCompiledSources(buildInfoDir: string): CompiledSources {
  if (!fs.existsSync(buildInfoDir)) {
    throw new Error(`${buildInfoDir} does not exist -- run the prototype Hardhat compile first.`);
  }
  const outputFiles = fs.readdirSync(buildInfoDir).filter((f) => f.endsWith(".output.json"));
  if (outputFiles.length !== 1) {
    throw new Error(
      `expected exactly one *.output.json in ${buildInfoDir}, found ${outputFiles.length} (${outputFiles.join(", ")}). Run \`npx hardhat --config prototype/vnext-kernel/hardhat.config.ts clean\` then recompile.`,
    );
  }
  const parsed = JSON.parse(fs.readFileSync(path.join(buildInfoDir, outputFiles[0]), "utf8"));
  const sources = parsed.output?.sources;
  if (!sources || typeof sources !== "object") {
    throw new Error(`${outputFiles[0]} has no output.sources -- unexpected build-info shape.`);
  }
  return buildCompiledSources(sources);
}

export function findContract(compiled: CompiledSources, contractName: string): AstNode {
  for (const key of Object.keys(compiled.bySourceKey)) {
    const ast = compiled.bySourceKey[key].ast;
    const hit = (ast.nodes as AstNode[]).find((n) => n.nodeType === "ContractDefinition" && n.name === contractName);
    if (hit) return hit;
  }
  throw new Error(`contract "${contractName}" not found in any compiled source unit`);
}

export function resolveDeclaration(compiled: CompiledSources, declarationId: number | undefined): AstNode | undefined {
  if (declarationId === undefined || declarationId < 0) return undefined; // negative ids are solc built-ins (e.g. abi, block)
  return compiled.declById.get(declarationId);
}

export function canonicalSignature(fn: AstNode): string {
  const types = (fn.parameters?.parameters ?? []).map((p: AstNode) => p.typeDescriptions?.typeString ?? "?");
  return `${fn.name}(${types.join(",")})`;
}
