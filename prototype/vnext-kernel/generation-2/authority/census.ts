/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * THE GENERATION-2 AUTHORITY CENSUS.
 *
 * Two layers, because they answer different questions and neither may stand in for the other.
 *
 *   1. THE REAL CHECKER, UNCHANGED. `authority/check.ts` runs on the candidate compiled under the two
 *      contract names it is hard-coded to (an in-memory rename; nothing on disk moves), against the
 *      Generation-2 manifest. Editing the checker to take contract names would move its own hash and
 *      turn the Generation-1 census stale for no gain, so it is driven as it stands.
 *
 *   2. A DERIVED COMPARISON WITH GENERATION 1, read from the two compiled ASTs: per function, what it
 *      writes, what it calls out to and whether its body is the same, and across the contract, who
 *      can hold authority. The verdict NO_NEW_PRIVILEGED_PRINCIPAL is COMPUTED from those facts by
 *      `deriveVerdict`. It is never declared: test/Gen2AuthorityCensus.test.ts runs mutants that add a
 *      principal, and requires the same code to answer differently.
 *
 * A new ERC-20 external call is a new EFFECT SURFACE even though it is not a new human principal, and
 * this census models it as one: `effectSurface` lists every external edge, and `newEdges` is what moved.
 *
 * Run: npx tsx prototype/vnext-kernel/generation-2/authority/census.ts [--out <path>] [--check]
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  type AstNode,
  buildCompiledSources,
  findContract,
  resolveDeclaration,
  type CompiledSources,
} from "../../authority/ast.js";
import { loadManifest, runCheck, type Manifest, type ManifestEntry } from "../../authority/check.js";
import { compileGen1Baseline, GEN1_FACTORY, GEN1_KERNEL, solcPath } from "../../erc20-spend-plane/compile.js";
import { compileGen2, GEN2_FACTORY, GEN2_KERNEL, GEN2_ROOT } from "../compile.js";
import { execFileSync } from "node:child_process";

export const MANIFEST_PATH = `${GEN2_ROOT}/authority/gen2-authority-manifest.json`;
export const CENSUS_PATH = "prototype/vnext-kernel/GEN2_AUTHORITY_CENSUS.json";

const RENAMES: Readonly<Record<string, string>> = { [GEN2_FACTORY]: GEN1_FACTORY, [GEN2_KERNEL]: GEN1_KERNEL };
const toGen1Key = (key: string): string => key.replace(GEN2_FACTORY, GEN1_FACTORY).replace(GEN2_KERNEL, GEN1_KERNEL);
const toGen2Name = (name: string): string => name.replace(GEN1_FACTORY, GEN2_FACTORY).replace(GEN1_KERNEL, GEN2_KERNEL);

export interface Gen2ManifestEntry extends ManifestEntry {
  callerDiscretion: string;
}

export interface Gen2Manifest {
  entries: Record<string, Gen2ManifestEntry>;
}

export function loadGen2Manifest(): Gen2Manifest {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8")) as Gen2Manifest;
}

/** The manifest under the names the checker is hard-coded to. */
export function checkerManifest(manifest: Gen2Manifest): Manifest {
  const entries: Manifest["entries"] = {};
  for (const [key, entry] of Object.entries(manifest.entries)) entries[toGen1Key(key)] = entry;
  return { entries };
}

/** The AST of one candidate compilation, under the Generation-1 names, with the zoo and the root present and ignored. */
export function compiledForChecker(overrides?: Readonly<Record<string, string>>): CompiledSources {
  const c = compileGen2({ renames: RENAMES, ast: true, overrides });
  if (!c.asts) throw new Error("ast output was not produced");
  return buildCompiledSources(c.asts as Record<string, { ast: unknown }>);
}

/** The Generation-1 kernel and factory, through the same solc path, with ASTs. */
export function gen1Ast(): CompiledSources {
  const baseline = compileGen1Baseline();
  const input = {
    language: "Solidity",
    sources: Object.fromEntries(Object.entries(baseline.sources).map(([k, content]) => [k, { content }])),
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
      outputSelection: { "*": { "": ["ast"] } },
    },
  };
  const raw = execFileSync(solcPath(), ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 512 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as { sources: Record<string, { ast: unknown }> };
  return buildCompiledSources(parsed.sources);
}

// =====================================================================
// AST facts
// =====================================================================

function walk(node: AstNode, visit: (n: AstNode) => void): void {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  if (typeof node.nodeType === "string") visit(node);
  for (const key of Object.keys(node)) {
    if (key === "src" || key === "nameLocation" || key === "documentation" || key === "typeDescriptions") continue;
    const value = node[key];
    if (value !== null && typeof value === "object") walk(value, visit);
  }
}

/** Keys that carry AST ids, positions or comments, none of which is the function's meaning. */
const STRIPPED = new Set([
  "id",
  "src",
  "nameLocation",
  "scope",
  "referencedDeclaration",
  "overloadedDeclarations",
  "typeDescriptions",
  "documentation",
  "argumentTypes",
  "declarations",
  "nativeSrc",
  "functionSelector",
  "baseFunctions",
  "externalReferences",
  "contractScope",
  "constant",
  "mutability",
  "memberLocation",
  "nameLocations",
  "assignments",
  "commonType",
  "functionReturnParameters",
]);

function normalise(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(normalise);
  if (node !== null && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(node as Record<string, unknown>).sort()) {
      if (STRIPPED.has(key)) continue;
      out[key] = normalise((node as Record<string, unknown>)[key]);
    }
    return out;
  }
  return node;
}

export const bodyDigest = (fn: AstNode): string =>
  createHash("sha256")
    .update(
      JSON.stringify(normalise({ body: fn.body, parameters: fn.parameters, returnParameters: fn.returnParameters })),
    )
    .digest("hex");

export interface FunctionFacts {
  readonly name: string;
  readonly signature: string;
  readonly selector: string;
  readonly visibility: string;
  readonly stateMutability: string;
  readonly kind: string;
  readonly bodyDigest: string;
  readonly writes: string[];
  readonly externalCalls: string[];
  readonly referencesCloneArgs: boolean;
}

function isStateVar(compiled: CompiledSources, id: number | undefined): AstNode | undefined {
  const decl = resolveDeclaration(compiled, id);
  return decl?.nodeType === "VariableDeclaration" && decl.stateVariable === true ? decl : undefined;
}

function writtenStateRoot(compiled: CompiledSources, expr: AstNode | undefined): string | undefined {
  if (!expr) return undefined;
  if (expr.nodeType === "Identifier") return isStateVar(compiled, expr.referencedDeclaration)?.name;
  if (expr.nodeType === "IndexAccess") return writtenStateRoot(compiled, expr.baseExpression);
  if (expr.nodeType === "MemberAccess") return writtenStateRoot(compiled, expr.expression);
  return undefined;
}

const YUL_EXTERNAL = new Set(["call", "staticcall", "delegatecall", "callcode", "create", "create2", "selfdestruct"]);

/** What one function does, following internal and library calls transitively. Stops at contract boundaries. */
function factsOf(compiled: CompiledSources, fn: AstNode): { writes: Set<string>; calls: Set<string>; args: boolean } {
  const writes = new Set<string>();
  const calls = new Set<string>();
  let args = false;
  const seen = new Set<number>();

  const describeLowLevel = (call: AstNode): string => {
    const member = call.expression.memberName as string;
    const target = call.expression.expression;
    let who = "?";
    if (target.nodeType === "Identifier") who = target.name as string;
    else if (target.nodeType === "MemberAccess") who = `${target.expression?.name ?? "?"}.${target.memberName}`;
    else if (target.nodeType === "FunctionCall") who = `${target.expression?.name ?? "payable"}(...)`;
    const selector = (call.arguments ?? [])
      .flatMap((a: AstNode) => (a.nodeType === "FunctionCall" ? (a.arguments ?? []) : []))
      .map((a: AstNode) => a.value ?? a.hexValue)
      .find((v: unknown) => typeof v === "string" && /^0x[0-9a-f]{8}$/i.test(v as string));
    const value = call.expression.nodeType === "FunctionCallOptions";
    return `lowlevel.${member}:${who}${selector ? ":" + selector : ""}${value ? ":value" : ""}`;
  };

  const visitFn = (f: AstNode): void => {
    if (!f?.body || seen.has(f.id)) return;
    seen.add(f.id);
    walk(f.body, (n) => {
      if (n.nodeType === "Assignment") {
        const root = writtenStateRoot(compiled, n.leftHandSide);
        if (root) writes.add(root);
      }
      if (n.nodeType === "UnaryOperation" && (n.operator === "++" || n.operator === "--" || n.operator === "delete")) {
        const root = writtenStateRoot(compiled, n.subExpression);
        if (root) writes.add(root);
      }
      if (n.nodeType === "YulFunctionCall") {
        const name = n.functionName?.name as string;
        if (name === "sstore") writes.add("<yul sstore>");
        if (YUL_EXTERNAL.has(name)) calls.add(`yul.${name}:${f.name}`);
        if (name === "extcodecopy") args = true;
      }
      if (n.nodeType === "FunctionCall") {
        let e = n.expression;
        const withOptions = e?.nodeType === "FunctionCallOptions";
        if (withOptions) e = e.expression;
        if (
          e?.nodeType === "MemberAccess" &&
          ["call", "staticcall", "delegatecall", "callcode"].includes(e.memberName)
        ) {
          const base = e.expression;
          const typeString = base?.typeDescriptions?.typeString as string | undefined;
          if (typeString?.startsWith("address")) {
            calls.add(
              describeLowLevel({ ...n, expression: withOptions ? { ...e, nodeType: "FunctionCallOptions" } : e }),
            );
            return;
          }
        }
        if (e?.nodeType === "Identifier" && e.name === "ecrecover") calls.add("precompile.ecrecover");
        const callee =
          e?.referencedDeclaration !== undefined ? resolveDeclaration(compiled, e.referencedDeclaration) : undefined;
        if (callee?.nodeType === "FunctionDefinition") {
          const owner = resolveDeclaration(compiled, callee.scope);
          if (
            e.nodeType === "MemberAccess" &&
            owner?.nodeType === "ContractDefinition" &&
            owner.contractKind !== "library" &&
            e.expression?.typeDescriptions?.typeString?.startsWith("contract")
          ) {
            calls.add(`interface.${owner.name}.${callee.name}`);
            return;
          }
          visitFn(callee);
        }
      }
      // A public state variable read through a modifier-free getter writes nothing; nothing to follow.
    });
  };
  visitFn(fn);
  return { writes, calls, args };
}

export function functionFacts(compiled: CompiledSources, contractName: string): FunctionFacts[] {
  const contract = findContract(compiled, contractName);
  const out: FunctionFacts[] = [];
  for (const node of contract.nodes as AstNode[]) {
    if (node.nodeType !== "FunctionDefinition") continue;
    const f = factsOf(compiled, node);
    const paramTypes = (node.parameters?.parameters ?? []).map((p: AstNode) => p.typeDescriptions?.typeString ?? "?");
    out.push({
      name: node.name || node.kind,
      signature: `${node.name || node.kind}(${paramTypes.join(",")})`
        .split(GEN1_KERNEL + ".")
        .join("")
        .replace(/struct /g, ""),
      selector: node.functionSelector ?? "",
      visibility: node.visibility,
      stateMutability: node.stateMutability,
      kind: node.kind,
      bodyDigest: bodyDigest(node),
      writes: [...f.writes].sort(),
      externalCalls: [...f.calls].sort(),
      referencesCloneArgs: f.args,
    });
  }
  return out;
}

/** Every syntactic use of an identity the kernel could key authority on. */
export function callerIdentityUses(compiled: CompiledSources, contractName: string): string[] {
  const found: string[] = [];
  walk(findContract(compiled, contractName), (n) => {
    if (
      n.nodeType === "MemberAccess" &&
      n.expression?.nodeType === "Identifier" &&
      n.expression.name === "msg" &&
      n.memberName === "sender"
    )
      found.push("msg.sender");
    if (
      n.nodeType === "MemberAccess" &&
      n.expression?.nodeType === "Identifier" &&
      n.expression.name === "tx" &&
      n.memberName === "origin"
    )
      found.push("tx.origin");
    if (n.nodeType === "Identifier" && n.name === "_msgSender") found.push("_msgSender");
  });
  return found.sort();
}

export interface StateVar {
  readonly name: string;
  readonly type: string;
  readonly mutability: string;
  readonly visibility: string;
}

export function stateVariables(compiled: CompiledSources, contractName: string): StateVar[] {
  const contract = findContract(compiled, contractName);
  return (contract.nodes as AstNode[])
    .filter((n) => n.nodeType === "VariableDeclaration" && n.stateVariable === true)
    .map((n) => ({
      name: n.name as string,
      type: (n.typeDescriptions?.typeString as string)
        .split(GEN1_KERNEL + ".")
        .join("")
        .split("contract ")
        .join(""),
      mutability: n.mutability as string,
      visibility: n.visibility as string,
    }));
}

/** A storage variable holding an address names a principal or a plane. Comparing the set is what exposes a new one. */
export const addressHolders = (vars: readonly StateVar[]): string[] =>
  vars
    .filter((v) => v.mutability === "mutable" && /address/.test(v.type))
    .map((v) => v.name)
    .sort();

// =====================================================================
// The derived verdict
// =====================================================================

export interface ComparisonRow {
  readonly selector: string;
  readonly signatureGen1: string | null;
  readonly signatureGen2: string | null;
  readonly mechanismsGen1: string[];
  readonly mechanismsGen2: string[];
  readonly verdictGen2: string;
  readonly expectedCut: string;
  readonly permissionless: boolean;
  readonly callerDiscretion: string;
  readonly bodyIdenticalToGen1: boolean;
  readonly stateEffectsGen1: string[];
  readonly stateEffectsGen2: string[];
  readonly externalCallsGen1: string[];
  readonly externalCallsGen2: string[];
}

export interface CensusVerdictInputs {
  readonly checkerFailed: number;
  readonly callerIdentity: string[];
  readonly factoryCallerIdentity: string[];
  readonly addedAddressHolders: string[];
  readonly addedStateVariables: string[];
  readonly changedMechanisms: string[];
  readonly addedStateChangingSelectors: string[];
  readonly removedStateChangingSelectors: string[];
  readonly changedStateEffects: string[];
  readonly factoryStateChangingFunctions: string[];
  readonly factoryMutableStorage: string[];
  readonly newEdges: { added: string[]; removed: string[] };
  readonly unexpectedNewEdges: string[];
}

/**
 * The edges Generation 2 is SUPPOSED to add: one fixed-selector transfer and the balance read, both on
 * the asset the clone's own code names. Declared here because an expectation must come from outside
 * the thing it judges; an edge not listed is a finding, whatever the checker says about gates.
 */
export const EXPECTED_NEW_EDGES = new Set([
  "execute -> lowlevel.call:asset:0xa9059cbb",
  "execute -> lowlevel.staticcall:asset:0x70a08231",
]);

export type CensusVerdict = "NO_NEW_PRIVILEGED_PRINCIPAL" | "NEW_AUTHORITY_SURFACE_REQUIRES_REVIEW";

export function deriveVerdict(i: CensusVerdictInputs): { verdict: CensusVerdict; reasons: string[] } {
  const reasons: string[] = [];
  if (i.checkerFailed > 0) reasons.push(`the authority checker reported ${i.checkerFailed} failure(s)`);
  if (i.callerIdentity.length > 0) reasons.push(`the kernel keys on caller identity: ${i.callerIdentity.join(", ")}`);
  if (i.factoryCallerIdentity.length > 0)
    reasons.push(`the factory keys on caller identity: ${i.factoryCallerIdentity.join(", ")}`);
  if (i.addedAddressHolders.length > 0)
    reasons.push(`new storage word(s) holding an address: ${i.addedAddressHolders.join(", ")}`);
  if (i.addedStateVariables.length > 0) reasons.push(`new state variable(s): ${i.addedStateVariables.join(", ")}`);
  if (i.changedMechanisms.length > 0) reasons.push(`mechanism changed on: ${i.changedMechanisms.join(", ")}`);
  if (i.addedStateChangingSelectors.length > 0)
    reasons.push(`new state-changing selector(s): ${i.addedStateChangingSelectors.join(", ")}`);
  if (i.removedStateChangingSelectors.length > 0)
    reasons.push(`removed state-changing selector(s): ${i.removedStateChangingSelectors.join(", ")}`);
  if (i.changedStateEffects.length > 0) reasons.push(`state effects changed on: ${i.changedStateEffects.join(", ")}`);
  if (i.factoryStateChangingFunctions.join() !== "deployVault")
    reasons.push(`factory state-changing surface: ${i.factoryStateChangingFunctions.join(", ")}`);
  if (i.factoryMutableStorage.length > 0)
    reasons.push(`factory mutable storage: ${i.factoryMutableStorage.join(", ")}`);
  if (i.unexpectedNewEdges.length > 0) reasons.push(`unexpected external edge(s): ${i.unexpectedNewEdges.join(", ")}`);
  return {
    verdict: reasons.length === 0 ? "NO_NEW_PRIVILEGED_PRINCIPAL" : "NEW_AUTHORITY_SURFACE_REQUIRES_REVIEW",
    reasons,
  };
}

const edgesOf = (rows: readonly FunctionFacts[]): Set<string> => {
  const edges = new Set<string>();
  for (const r of rows) {
    if (r.visibility !== "external" && r.visibility !== "public" && r.kind !== "receive" && r.kind !== "constructor")
      continue;
    for (const c of r.externalCalls) edges.add(`${r.name} -> ${c}`);
  }
  return edges;
};

export interface Gen2Census {
  schema: string;
  question: string;
  subjectInputs: {
    candidateKernelSourceSha256: string;
    candidateFactorySourceSha256: string;
    manifestSha256: string;
    checkerSha256: string;
  };
  checker: {
    tool: string;
    how: string;
    summary: ReturnType<typeof runCheck>["summary"];
    rows: {
      key: string;
      signature: string;
      verdict: string | undefined;
      observedMechanisms: string[] | undefined;
      observedUnresolved: boolean | undefined;
      reasons: string[];
    }[];
  };
  comparisonWithGeneration1: ComparisonRow[];
  viewSurface: { addedViews: string[]; removedViews: string[] };
  principals: {
    addressHoldersGen1: string[];
    addressHoldersGen2: string[];
    callerIdentityUsesKernel: string[];
    callerIdentityUsesFactory: string[];
    factoryImmutables: string[];
    assetBinding: string;
    relayer: string;
    walletWall: string;
  };
  effectSurface: {
    edgesGen2: string[];
    newEdges: { added: string[]; removed: string[] };
    expectedNewEdges: string[];
    modelled: string;
  };
  bodyIdentity: {
    identicalToGen1: string[];
    differentFromGen1: string[];
    addedInGen2: string[];
    removedFromGen1: string[];
  };
  derivedVerdict: { verdict: CensusVerdict; reasons: string[] };
  doesNotEstablish: string[];
}

const sha256File = (p: string): string => createHash("sha256").update(fs.readFileSync(p)).digest("hex");

export interface CensusOptions {
  /** Replacement text for candidate files, keyed relative to the candidate's contracts dir: how a mutant is judged. */
  readonly overrides?: Readonly<Record<string, string>>;
}

export function runGen2Census(options: CensusOptions = {}): Gen2Census {
  const manifest = loadGen2Manifest();
  const compiled = compiledForChecker(options.overrides);
  const report = runCheck({ compiled, manifest: checkerManifest(manifest), skipProvenance: true });

  const gen1 = gen1Ast();
  const gen1Report = runCheck({ compiled: gen1, manifest: loadManifest(), skipProvenance: true });

  const factsG2 = functionFacts(compiled, GEN1_KERNEL);
  const factsG1 = functionFacts(gen1, GEN1_KERNEL);
  const factoryFactsG2 = functionFacts(compiled, GEN1_FACTORY);
  const bySelector = (rows: readonly FunctionFacts[]): Map<string, FunctionFacts> =>
    new Map(rows.map((r) => [r.selector !== "" ? r.selector : r.kind, r]));
  const g1 = bySelector(factsG1);
  const g2 = bySelector(factsG2);

  const isChanging = (r: FunctionFacts): boolean =>
    r.stateMutability === "nonpayable" || r.stateMutability === "payable";
  const externally = (r: FunctionFacts): boolean =>
    r.visibility === "external" || r.visibility === "public" || r.kind === "receive" || r.kind === "constructor";

  const changingG1 = factsG1.filter((r) => externally(r) && isChanging(r));
  const changingG2 = factsG2.filter((r) => externally(r) && isChanging(r));
  const keyOf = (r: FunctionFacts): string => (r.selector !== "" ? r.selector : r.kind);

  const reportRow = (rep: typeof report, contract: string, key: string) =>
    rep.rows.find((x) => x.key === `${contract}:${key}`);

  const comparison: ComparisonRow[] = [...new Set([...changingG1.map(keyOf), ...changingG2.map(keyOf)])]
    .sort()
    .map((key) => {
      const a = g1.get(key);
      const b = g2.get(key);
      const rowG2 = reportRow(report, GEN1_KERNEL, key);
      const rowG1 = reportRow(gen1Report, GEN1_KERNEL, key);
      const entry = manifest.entries[`${GEN2_KERNEL}:${key}`];
      return {
        selector: key,
        signatureGen1: a?.signature ?? null,
        signatureGen2: b?.signature ?? null,
        mechanismsGen1: rowG1?.observedMechanisms ?? [],
        mechanismsGen2: rowG2?.observedMechanisms ?? [],
        verdictGen2: rowG2?.verdict ?? "MISSING",
        expectedCut: entry?.expectedCut ?? "MISSING",
        permissionless: (rowG2?.observedMechanisms ?? []).length === 0,
        callerDiscretion: entry?.callerDiscretion ?? "MISSING",
        bodyIdenticalToGen1: a !== undefined && b !== undefined && a.bodyDigest === b.bodyDigest,
        stateEffectsGen1: a?.writes ?? [],
        stateEffectsGen2: b?.writes ?? [],
        externalCallsGen1: a?.externalCalls ?? [],
        externalCallsGen2: b?.externalCalls ?? [],
      };
    });

  const edgesG2 = edgesOf(factsG2);
  const edgesG1 = edgesOf(factsG1);
  const added = [...edgesG2].filter((e) => !edgesG1.has(e)).sort();
  const removed = [...edgesG1].filter((e) => !edgesG2.has(e)).sort();

  const varsG1 = stateVariables(gen1, GEN1_KERNEL);
  const varsG2 = stateVariables(compiled, GEN1_KERNEL);
  const holdersG1 = addressHolders(varsG1);
  const holdersG2 = addressHolders(varsG2);
  const factoryVars = stateVariables(compiled, GEN1_FACTORY);

  const viewNames = (rows: readonly FunctionFacts[]): Set<string> =>
    new Set(rows.filter((r) => externally(r) && !isChanging(r)).map((r) => r.signature));
  const viewsG1 = viewNames(factsG1);
  const viewsG2 = viewNames(factsG2);

  const allBodiesG1 = new Map(factsG1.map((r) => [r.signature, r.bodyDigest]));
  const allBodiesG2 = new Map(factsG2.map((r) => [r.signature.replace("address payable", "address"), r.bodyDigest]));
  const normalisedG1 = new Map([...allBodiesG1].map(([k, v]) => [k.replace("address payable", "address"), v]));

  const verdictInputs: CensusVerdictInputs = {
    checkerFailed: report.summary.failed,
    callerIdentity: callerIdentityUses(compiled, GEN1_KERNEL),
    factoryCallerIdentity: callerIdentityUses(compiled, GEN1_FACTORY),
    addedAddressHolders: holdersG2.filter((h) => !holdersG1.includes(h)),
    addedStateVariables: varsG2
      .filter((v) => v.mutability === "mutable" && !varsG1.some((x) => x.name === v.name))
      .map((v) => v.name),
    changedMechanisms: comparison
      .filter((r) => JSON.stringify(r.mechanismsGen1) !== JSON.stringify(r.mechanismsGen2))
      .map((r) => r.signatureGen2 ?? r.selector),
    addedStateChangingSelectors: changingG2.filter((r) => !g1.has(keyOf(r))).map((r) => r.signature),
    removedStateChangingSelectors: changingG1.filter((r) => !g2.has(keyOf(r))).map((r) => r.signature),
    changedStateEffects: comparison
      .filter((r) => JSON.stringify(r.stateEffectsGen1) !== JSON.stringify(r.stateEffectsGen2))
      .map((r) => r.signatureGen2 ?? r.selector),
    factoryStateChangingFunctions: factoryFactsG2
      .filter((r) => r.kind === "function" && externally(r) && isChanging(r))
      .map((r) => r.name),
    factoryMutableStorage: factoryVars.filter((v) => v.mutability === "mutable").map((v) => v.name),
    newEdges: { added, removed },
    unexpectedNewEdges: added.filter((e) => !EXPECTED_NEW_EDGES.has(e)),
  };

  return {
    schema: "vnext-kernel-gen2-authority-census.v1",
    question:
      "Does the Generation-2 candidate add a privileged principal or an unmodelled authority edge relative to Generation 1?",
    subjectInputs: {
      candidateKernelSourceSha256: sha256File(path.join(GEN2_ROOT, "contracts", "VaultKernelGen2Prototype.sol")),
      candidateFactorySourceSha256: sha256File(
        path.join(GEN2_ROOT, "contracts", "VaultKernelGen2FactoryPrototype.sol"),
      ),
      manifestSha256: sha256File(MANIFEST_PATH),
      checkerSha256: createHash("sha256")
        .update(
          Buffer.concat(
            ["ast.ts", "trace.ts", "discover.ts", "check.ts"].map((f) =>
              fs.readFileSync(path.join("prototype", "vnext-kernel", "authority", f)),
            ),
          ),
        )
        .digest("hex"),
    },
    checker: {
      tool: "prototype/vnext-kernel/authority/check.ts, unchanged",
      how: "runCheck on the candidate compiled under the two contract names the checker is hard-coded to (in-memory rename), against generation-2/authority/gen2-authority-manifest.json",
      summary: report.summary,
      rows: report.rows
        .filter((r) => r.isStateChanging || r.verdict === "STALE_MANIFEST_ENTRY")
        .map((r) => ({
          key: toGen2Name(r.key),
          signature: r.signature,
          verdict: r.verdict,
          observedMechanisms: r.observedMechanisms,
          observedUnresolved: r.observedUnresolved,
          reasons: r.reasons,
        })),
    },
    comparisonWithGeneration1: comparison,
    viewSurface: {
      addedViews: [...viewsG2].filter((v) => !viewsG1.has(v)).sort(),
      removedViews: [...viewsG1].filter((v) => !viewsG2.has(v)).sort(),
    },
    principals: {
      addressHoldersGen1: holdersG1,
      addressHoldersGen2: holdersG2,
      callerIdentityUsesKernel: verdictInputs.callerIdentity,
      callerIdentityUsesFactory: verdictInputs.factoryCallerIdentity,
      factoryImmutables: factoryVars
        .filter((v) => v.mutability === "immutable")
        .map((v) => v.name)
        .sort(),
      assetBinding:
        "bytes 28..48 of the clone's immutable args, read by `_admittedAsset` through Clones.fetchCloneArgs: code, not storage. No storage variable holds the asset, on the kernel or the factory.",
      relayer:
        "NOT A PRINCIPAL. The kernel and factory reference no caller identity (derived above); a relayer can choose whether and when to submit, and any change to a signed field invalidates the signature.",
      walletWall:
        "NOT A PRINCIPAL. No storage word, immutable or args field names WalletWall. Choosing the factory's asset at construction is the generation publisher's one-shot act, spent before any vault exists, and its residual is discovery (H-32), checkable offline from each clone's own code.",
    },
    effectSurface: {
      edgesGen2: [...edgesG2].sort(),
      newEdges: { added, removed },
      expectedNewEdges: [...EXPECTED_NEW_EDGES].sort(),
      modelled:
        "The ERC-20 call is a NEW EFFECT SURFACE with no new principal behind it: `execute` now hands control to the admitted asset, which can run code, and can observe and re-enter the kernel. It is treated as adversarial in test/Gen2Reentrancy.test.ts and in the campaign's reentrancy profile, its ordering is mutated by M-G2-6, and what it can still lie about is the asset boundary in GEN2_ADMISSION.md. The native value edge to the recipient is removed from `execute` and remains only in `egress`.",
    },
    bodyIdentity: {
      identicalToGen1: [...allBodiesG2]
        .filter(([k, v]) => normalisedG1.get(k) === v)
        .map(([k]) => k)
        .sort(),
      differentFromGen1: [...allBodiesG2]
        .filter(([k, v]) => normalisedG1.has(k) && normalisedG1.get(k) !== v)
        .map(([k]) => k)
        .sort(),
      addedInGen2: [...allBodiesG2.keys()].filter((k) => !normalisedG1.has(k)).sort(),
      removedFromGen1: [...normalisedG1.keys()].filter((k) => !allBodiesG2.has(k)).sort(),
    },
    derivedVerdict: deriveVerdict(verdictInputs),
    doesNotEstablish: [
      "That a cut is the right cut: expectedCut is declared and checked for consistency, and the campaign tests it over histories.",
      "That the token is honest. The asset can lie about its own ledger; that is the asset boundary, not a kernel fact.",
      "Anything about a deployed factory: which asset, root and implementation a factory binds is a deployment fact, checkable offline.",
    ],
  };
}

function main(): void {
  const census = runGen2Census();
  console.log(
    `Generation-2 authority census: ${census.checker.summary.total} gated entries, ${census.checker.summary.pass} PASS, ${census.checker.summary.passWithDeclaredException} PASS_WITH_DECLARED_EXCEPTION, ${census.checker.summary.failed} FAILED; derived verdict ${census.derivedVerdict.verdict}`,
  );
  for (const r of census.derivedVerdict.reasons) console.log("  " + r);
  const text = JSON.stringify(census, null, 2) + "\n";
  if (process.argv.includes("--check")) {
    const committed = fs.readFileSync(CENSUS_PATH, "utf8");
    if (committed !== text) {
      console.error(`FAIL: ${CENSUS_PATH} is stale: regenerate it with --out on a clean tree.`);
      process.exit(1);
    }
    console.log(`${CENSUS_PATH} is byte-identical to a fresh run.`);
    return;
  }
  const outIdx = process.argv.indexOf("--out");
  if (outIdx >= 0) {
    fs.writeFileSync(process.argv[outIdx + 1] ?? CENSUS_PATH, text);
    console.log(`Wrote ${process.argv[outIdx + 1] ?? CENSUS_PATH}`);
  }
  if (census.checker.summary.failed > 0 || census.derivedVerdict.verdict !== "NO_NEW_PRIVILEGED_PRINCIPAL")
    process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
