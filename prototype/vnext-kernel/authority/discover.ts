/**
 * AST-derived external state-changing surface discovery (PHASE 5).
 *
 * Independently derived from compiled truth: walks the ContractDefinition's
 * own `nodes` (Solidity has no reflection API, so "what functions exist" is
 * answered by reading the same AST solc produced, not by grep or by
 * remembering names). Deliberately excludes PrototypeMocks.sol -- those are
 * test-only adversaries/controls never deployed as part of the measured
 * kernel (see prototype/vnext-kernel/contracts/PrototypeMocks.sol's own
 * header, and measure.ts, which never measures them either) -- and any
 * inherited surface (mechanically verified below: both contracts have
 * `baseContracts: []`, so there is none to miss).
 */
import { type AstNode, type CompiledSources, canonicalSignature } from "./ast.js";
import { type GateMechanism, resolvePrimitiveIds, traceFunction, GATE_PRIMITIVES } from "./trace.js";

export interface ModifierGateInfo {
  readonly name: string;
  readonly gateMechanismsBeforePlaceholder: GateMechanism[];
  readonly gateMechanismsAfterPlaceholder: GateMechanism[]; // PHASE 15: "modifier performs authorization after body"
}

export interface DiscoveredFunction {
  readonly contract: string;
  readonly name: string;
  readonly signature: string;
  readonly selector: string;
  readonly visibility: string;
  readonly stateMutability: string;
  readonly isStateChanging: boolean; // nonpayable or payable, and not the constructor/receive/fallback
  readonly kind: "constructor" | "receive" | "fallback" | "function";
  readonly modifiers: ModifierGateInfo[];
  readonly astId: number;
}

function resolveModifierGate(compiled: CompiledSources, primitives: ReturnType<typeof resolvePrimitiveIds>, modDef: AstNode): ModifierGateInfo {
  const before: GateMechanism[] = [];
  const after: GateMechanism[] = [];
  let sawPlaceholder = false;

  function walk(stmts: AstNode[]): void {
    for (const s of stmts) {
      if (s.nodeType === "Block" || s.nodeType === "UncheckedBlock") {
        walk(s.statements ?? []);
        continue;
      }
      if (s.nodeType === "PlaceholderStatement") {
        sawPlaceholder = true;
        continue;
      }
      // Reuse traceFunction's single-statement classification by wrapping this one
      // statement as a pseudo function body -- simplest way to not duplicate the
      // classifier. Cheap: modifiers are tiny.
      const trace = traceFunction(compiled, primitives, { body: { statements: [s] } }, []);
      for (const st of trace.statements) {
        if (st.kind === "GATE" && st.mechanism) (sawPlaceholder ? after : before).push(st.mechanism);
      }
    }
  }
  walk(modDef.body?.statements ?? []);
  return { name: modDef.name, gateMechanismsBeforePlaceholder: [...new Set(before)], gateMechanismsAfterPlaceholder: [...new Set(after)] };
}

function findContractNode(compiled: CompiledSources, contractName: string): AstNode {
  for (const key of Object.keys(compiled.bySourceKey)) {
    const ast = compiled.bySourceKey[key].ast;
    const hit = (ast.nodes as AstNode[]).find((n) => n.nodeType === "ContractDefinition" && n.name === contractName);
    if (hit) return hit;
  }
  throw new Error(`contract "${contractName}" not found`);
}

export function discoverSurface(compiled: CompiledSources, primitives: ReturnType<typeof resolvePrimitiveIds>, contractName: string): DiscoveredFunction[] {
  const contract = findContractNode(compiled, contractName);

  if ((contract.baseContracts ?? []).length > 0) {
    throw new Error(
      `${contractName} now inherits from ${contract.baseContracts.length} base contract(s) -- authority/discover.ts's "no inherited surface to miss" assumption no longer holds and must be extended deliberately before this checker can be trusted again.`,
    );
  }

  const out: DiscoveredFunction[] = [];

  for (const node of contract.nodes as AstNode[]) {
    if (node.nodeType !== "FunctionDefinition") continue;
    const kind: DiscoveredFunction["kind"] =
      node.kind === "constructor" ? "constructor" : node.kind === "receive" ? "receive" : node.kind === "fallback" ? "fallback" : "function";
    const isExternallyReachable = node.visibility === "external" || node.visibility === "public" || kind !== "function";
    if (!isExternallyReachable) continue; // internal/private helpers are not part of the external surface

    const isStateChanging = node.stateMutability === "nonpayable" || node.stateMutability === "payable";

    const modifiers: ModifierGateInfo[] = (node.modifiers ?? []).map((m: AstNode) => {
      const modDef = compiled.declById.get(m.modifierName?.referencedDeclaration ?? -1);
      if (!modDef) throw new Error(`could not resolve modifier "${m.modifierName?.name}" applied to ${node.name || kind}`);
      return resolveModifierGate(compiled, primitives, modDef);
    });

    out.push({
      contract: contractName,
      name: node.name || kind,
      signature: node.name ? canonicalSignature(node) : `${kind}()`,
      selector: node.functionSelector ?? "",
      visibility: node.visibility,
      stateMutability: node.stateMutability,
      isStateChanging,
      kind,
      modifiers,
      astId: node.id,
    });
  }
  return out;
}

export function traceDiscoveredFunction(compiled: CompiledSources, primitives: ReturnType<typeof resolvePrimitiveIds>, discovered: DiscoveredFunction) {
  const fnNode = compiled.declById.get(discovered.astId);
  if (!fnNode) throw new Error(`could not re-resolve AST node ${discovered.astId} for ${discovered.signature}`);
  const modifierGateMechanisms = discovered.modifiers.flatMap((m) => m.gateMechanismsBeforePlaceholder);
  return traceFunction(compiled, primitives, fnNode, modifierGateMechanisms);
}

export { GATE_PRIMITIVES };
