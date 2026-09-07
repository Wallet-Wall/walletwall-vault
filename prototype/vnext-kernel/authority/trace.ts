/**
 * Statement-level classifier + gate-reachability tracer.
 *
 * GROUND TRUTH, not a heuristic: Solidity's compiler enforces that a `view`
 * function cannot write state, emit, or make a non-static external call, and
 * that a `pure` function cannot even read state. So "is this internal call
 * safe (no privileged effect can occur inside it)" is answered by the
 * callee's OWN declared `stateMutability` -- solc already proved it, this
 * module just reads the proof back out of the AST. The only thing this
 * module adds is: (a) recognising the four named authority PRIMITIVES by
 * resolved AST declaration id (never by name string alone, so a same-named
 * shadow cannot spoof one), and (b) determining STATEMENT ORDER within a
 * function body, which solc's type system says nothing about.
 *
 * See authority/README.md for the full design rationale and its declared
 * limitations (a semantically-inlined equivalent of a gate check, not
 * routed through a named primitive at all, cannot be detected here by
 * construction -- see PHASE 15 in the PR description for how that gap is
 * covered instead).
 */
import { type AstNode, type CompiledSources, canonicalSignature, resolveDeclaration } from "./ast.js";

export const GATE_PRIMITIVES = ["_authorise", "_floorAuthorises", "_requireQuorum", "_requireIncomingPossession"] as const;
export type GateMechanism = "HYBRID" | "FLOOR_ONLY" | "QUORUM" | "POSSESSION_PROOF";

const PRIMITIVE_TO_MECHANISM: Record<string, GateMechanism> = {
  _authorise: "HYBRID",
  _floorAuthorises: "FLOOR_ONLY",
  _requireQuorum: "QUORUM",
  _requireIncomingPossession: "POSSESSION_PROOF",
};

export type StatementKind = "SAFE" | "GATE" | "EFFECT" | "UNRESOLVED";

export interface ClassifiedStatement {
  readonly kind: StatementKind;
  readonly nodeType: string;
  readonly detail: string;
  readonly mechanism?: GateMechanism;
  readonly via?: string; // the (possibly wrapper) function name the gate was found through
}

export interface GateTraceResult {
  readonly statements: ClassifiedStatement[];
  readonly mechanismsReached: GateMechanism[]; // in the order first satisfied, before the first EFFECT
  readonly mechanismsReachedAfterEffect: GateMechanism[]; // satisfied, but too late -- ordering violation
  readonly orderOk: boolean;
  readonly unresolved: boolean;
  readonly unresolvedReasons: string[];
}

interface PrimitiveIds {
  readonly idToMechanism: Map<number, GateMechanism>;
}

/**
 * Resolves the gate primitives' AST declaration ids ONCE, from the contract
 * that actually defines them (the kernel). `internal` visibility means no
 * OTHER contract (e.g. the factory) can ever call them directly regardless
 * of import/reference -- Solidity does not allow it -- so this is
 * deliberately not re-resolved per analysed contract: every contract's
 * trace uses this SAME id set, and a contract that structurally cannot
 * reach any of these ids (the factory) will correctly show zero gates
 * found, not an error.
 */
export function resolvePrimitiveIds(kernelContract: AstNode): PrimitiveIds {
  const idToMechanism = new Map<number, GateMechanism>();
  for (const node of kernelContract.nodes as AstNode[]) {
    if (node.nodeType === "FunctionDefinition" && (GATE_PRIMITIVES as readonly string[]).includes(node.name)) {
      idToMechanism.set(node.id, PRIMITIVE_TO_MECHANISM[node.name]);
    }
  }
  if (idToMechanism.size !== GATE_PRIMITIVES.length) {
    throw new Error(
      `expected to resolve all ${GATE_PRIMITIVES.length} gate primitives (${GATE_PRIMITIVES.join(", ")}) in ${kernelContract.name}, found ${idToMechanism.size}. A primitive was renamed or removed -- update authority/trace.ts's GATE_PRIMITIVES deliberately, this must not pass silently.`,
    );
  }
  return { idToMechanism };
}

/** Finds the outermost FunctionCall node(s) an expression directly performs, without descending into their arguments (a call used only as an argument value has no ordering effect of its own here -- its own mutability already bounds what it can do, checked separately when THAT statement is a bare ExpressionStatement of the same call). */
function topLevelCalls(expr: AstNode | undefined): AstNode[] {
  if (!expr) return [];
  switch (expr.nodeType) {
    case "FunctionCall":
      return [expr];
    case "Assignment":
      return topLevelCalls(expr.rightHandSide);
    case "TupleExpression":
      return (expr.components ?? []).flatMap((c: AstNode) => topLevelCalls(c));
    default:
      return [];
  }
}

function calleeDeclaration(compiled: CompiledSources, call: AstNode): AstNode | undefined {
  const target = call.expression;
  if (target.nodeType === "Identifier" || target.nodeType === "MemberAccess") {
    return resolveDeclaration(compiled, target.referencedDeclaration);
  }
  return undefined;
}

/**
 * Does `fn` (a view/pure internal function, or the top-level call site
 * itself) reach a gate primitive through its own top-level statements,
 * recursing through further view/pure calls? Stops the instant it hits a
 * primitive by id -- never looks inside a primitive's own body, so
 * `_authorise` calling `_floorAuthorises` internally is never misread as
 * the CALLER having satisfied FLOOR_ONLY on its own.
 */
function findGateTransitively(
  compiled: CompiledSources,
  primitives: PrimitiveIds,
  fn: AstNode,
  seen: Set<number>,
): { mechanism: GateMechanism; via: string } | undefined {
  if (seen.has(fn.id)) return undefined; // cycle guard
  seen.add(fn.id);
  if (!fn.body) return undefined; // no implementation to inspect (interface/abstract)
  for (const stmt of flattenBlock(fn.body.statements ?? [])) {
    if (stmt.raw === undefined) continue;
    for (const call of statementFunctionCalls(stmt.raw)) {
      const callee = calleeDeclaration(compiled, call);
      if (!callee) continue;
      const primitiveMechanism = primitives.idToMechanism.get(callee.id);
      if (primitiveMechanism) return { mechanism: primitiveMechanism, via: fn.name };
      if (callee.nodeType === "FunctionDefinition" && (callee.stateMutability === "view" || callee.stateMutability === "pure")) {
        const found = findGateTransitively(compiled, primitives, callee, seen);
        if (found) return found;
      }
    }
  }
  return undefined;
}

/** All FunctionCall nodes a single flattened statement's own expression performs at top level (see topLevelCalls). */
function statementFunctionCalls(raw: AstNode): AstNode[] {
  if (raw.nodeType === "ExpressionStatement") return topLevelCalls(raw.expression);
  if (raw.nodeType === "VariableDeclarationStatement") return topLevelCalls(raw.initialValue);
  // `return <expr>;` -- needed so a one-line `internal view returns (bool)` wrapper
  // around a gate primitive (`return _floorAuthorises(d, s);`) is still followed by
  // findGateTransitively's recursion; without this case such a wrapper's call is
  // invisible and the gate looks unreached. Deliberately NOT a bare `topLevelCallsDeep`
  // on arbitrary expressions -- kept to the same "assignment/tuple RHS" shape
  // topLevelCalls already understands, plus this one additional statement kind.
  if (raw.nodeType === "Return") return topLevelCalls(raw.expression);
  return [];
}

interface FlatStatement {
  readonly raw: AstNode | undefined;
  readonly kind: "guard-if" | "plain";
  readonly nodeType: string;
}

/**
 * Recursively flattens `Block`/`UncheckedBlock` wrappers (pure lexical
 * scoping in this codebase -- see bindMigration's stack-depth-motivated
 * `{ ... }` and setGuardians'/cancelRecovery's `unchecked { ... }`, neither
 * of which branches control flow) into one sequential list, and recognises
 * the single `if (!X) revert ...;` / `if (X) revert ...;` guard idiom used
 * throughout this kernel as an unconditional check at that point in
 * sequence (either it holds, or the function terminates). Any OTHER
 * IfStatement shape (an else branch, or a true-body that does not consist
 * solely of a revert) is not modelled -- it is surfaced by the caller as
 * UNRESOLVED rather than guessed at, per this repo's fail-closed rule.
 */
function flattenBlock(statements: AstNode[]): FlatStatement[] {
  const out: FlatStatement[] = [];
  for (const s of statements) {
    if (s.nodeType === "Block" || s.nodeType === "UncheckedBlock") {
      out.push(...flattenBlock(s.statements ?? []));
    } else if (s.nodeType === "IfStatement" && isGuardRevertPattern(s)) {
      out.push({ raw: s, kind: "guard-if", nodeType: "IfStatement(guard)" });
    } else {
      out.push({ raw: s, kind: "plain", nodeType: s.nodeType });
    }
  }
  return out;
}

function isGuardRevertPattern(ifStmt: AstNode): boolean {
  if (ifStmt.falseBody) return false; // has an else -- not the simple guard idiom
  const body = ifStmt.trueBody;
  const stmts: AstNode[] = body.nodeType === "Block" ? (body.statements ?? []) : [body];
  return stmts.length === 1 && stmts[0].nodeType === "RevertStatement";
}

/** The condition of a guard-if, as its own pseudo-statement (so a gate call inside `if (!_authorise-like(...))` -- which this codebase does not do, `_authorise` itself reverts rather than returning bool, but `_floorAuthorises`/`_requireQuorum`... `_requireQuorum` also reverts internally, only `_floorAuthorises` returns bool -- is still discoverable). */
function conditionCalls(ifStmt: AstNode): AstNode[] {
  return topLevelCallsDeep(ifStmt.condition);
}

/** Like topLevelCalls, but also descends through unary `!` and binary boolean operators, since guard conditions are boolean expressions built from those, not just a bare call or assignment. */
function topLevelCallsDeep(expr: AstNode | undefined): AstNode[] {
  if (!expr) return [];
  switch (expr.nodeType) {
    case "FunctionCall":
      return [expr];
    case "UnaryOperation":
      return topLevelCallsDeep(expr.subExpression);
    case "BinaryOperation":
      return [...topLevelCallsDeep(expr.leftExpression), ...topLevelCallsDeep(expr.rightExpression)];
    case "TupleExpression":
      return (expr.components ?? []).flatMap((c: AstNode) => topLevelCallsDeep(c));
    default:
      return [];
  }
}

function isStateVariableTarget(compiled: CompiledSources, expr: AstNode | undefined): boolean {
  if (!expr) return false;
  if (expr.nodeType === "Identifier") {
    const decl = resolveDeclaration(compiled, expr.referencedDeclaration);
    return decl?.nodeType === "VariableDeclaration" && decl.stateVariable === true;
  }
  // IndexAccess (mapping[k] = ...) and MemberAccess (struct.field = ...) both ultimately
  // point back at a base expression; walk to it.
  if (expr.nodeType === "IndexAccess") return isStateVariableTarget(compiled, expr.baseExpression);
  if (expr.nodeType === "MemberAccess") return isStateVariableTarget(compiled, expr.expression);
  if (expr.nodeType === "TupleExpression") return (expr.components ?? []).some((c: AstNode) => isStateVariableTarget(compiled, c));
  return false;
}

function classifyPlain(compiled: CompiledSources, primitives: PrimitiveIds, raw: AstNode): ClassifiedStatement {
  const nodeType = raw.nodeType as string;

  if (nodeType === "RevertStatement" || nodeType === "Break" || nodeType === "Continue") {
    // Terminal/no-expression statements: RevertStatement rolls back anything its own
    // error-argument expressions might do, so it is safe regardless of their content.
    return { kind: "SAFE", nodeType, detail: nodeType };
  }
  // `Return` is NOT unconditionally safe: `return _someNonViewCall();` executes that
  // call (and any side effect it has) before returning, so it falls through to the
  // same call-classification path as every other statement kind below.
  if (nodeType === "EmitStatement") {
    return { kind: "EFFECT", nodeType, detail: "emit" };
  }
  if (nodeType === "ForStatement" || nodeType === "WhileStatement" || nodeType === "DoWhileStatement") {
    return { kind: "UNRESOLVED", nodeType, detail: "loop construct is not analysed for ordering" };
  }
  if (nodeType === "IfStatement") {
    return { kind: "UNRESOLVED", nodeType, detail: "IfStatement is not the recognised single-revert guard idiom (has an else, or a non-revert-only true body)" };
  }
  if (nodeType === "TryStatement") {
    return { kind: "UNRESOLVED", nodeType, detail: "try/catch is not analysed" };
  }
  if (nodeType === "InlineAssembly") {
    return { kind: "UNRESOLVED", nodeType, detail: "inline assembly is not analysed -- see authority/README.md's declared limitation" };
  }

  if (nodeType === "ExpressionStatement" && raw.expression?.nodeType === "Assignment") {
    if (isStateVariableTarget(compiled, raw.expression.leftHandSide)) {
      // Still classify any call on the right-hand side too: a state write whose
      // value comes from an unresolved/unsafe call is EFFECT either way, but a
      // gate call on the RHS of an assignment (not this codebase's pattern, but
      // conceivable) should still register as reached.
      const calls = topLevelCalls(raw.expression.rightHandSide);
      for (const call of calls) {
        const gate = classifyCallAsGate(compiled, primitives, call);
        if (gate) return { kind: "GATE", nodeType, detail: `assignment RHS reaches ${gate.mechanism} via ${gate.via}`, mechanism: gate.mechanism, via: gate.via };
      }
      return { kind: "EFFECT", nodeType, detail: "assignment to state variable" };
    }
  }

  const calls = statementFunctionCalls(raw);
  if (calls.length === 0) {
    // A bare local computation / VariableDeclarationStatement with no call, or an
    // expression statement we don't specifically recognise but that performs no
    // call at all -- cannot write state without one, so it is safe.
    if (nodeType === "ExpressionStatement" || nodeType === "VariableDeclarationStatement" || nodeType === "Return") {
      return { kind: "SAFE", nodeType, detail: "no function call" };
    }
    return { kind: "UNRESOLVED", nodeType, detail: `unrecognised statement kind with no function call: ${nodeType}` };
  }

  // One or more calls at top level (this codebase never has more than one, but tuple
  // destructuring could). Any single non-safe call makes the whole statement EFFECT
  // (or GATE if one of them IS the gate and none of the others are unsafe); any
  // unresolved call makes the whole statement UNRESOLVED (fail closed).
  let sawGate: { mechanism: GateMechanism; via: string } | undefined;
  let sawEffect = false;
  let sawUnresolved: string | undefined;
  for (const call of calls) {
    const gate = classifyCallAsGate(compiled, primitives, call);
    if (gate) {
      sawGate = gate;
      continue;
    }
    const callee = calleeDeclaration(compiled, call);
    if (!callee) {
      // Unresolvable target: a low-level call (`.call`, `.staticcall`, `.delegatecall`),
      // an external contract call through an interface variable, or anything else
      // whose declaration this module cannot look up. Treated as EFFECT (the
      // conservative, fail-closed direction: an unresolved external call could do
      // anything, including move value), never silently SAFE.
      sawEffect = true;
      continue;
    }
    if (callee.nodeType !== "FunctionDefinition") {
      sawUnresolved = `call target resolved to non-function ${callee.nodeType}`;
      continue;
    }
    if (callee.stateMutability === "view" || callee.stateMutability === "pure") {
      // Already proven safe by the compiler UNLESS it transitively reaches a gate,
      // which classifyCallAsGate (above) already checked and would have returned.
      continue;
    }
    sawEffect = true;
  }
  if (sawUnresolved) return { kind: "UNRESOLVED", nodeType, detail: sawUnresolved };
  if (sawGate && !sawEffect) return { kind: "GATE", nodeType, detail: `reaches ${sawGate.mechanism} via ${sawGate.via}`, mechanism: sawGate.mechanism, via: sawGate.via };
  if (sawEffect) return { kind: "EFFECT", nodeType, detail: "non-view/pure or unresolved call" };
  return { kind: "SAFE", nodeType, detail: "only safe (view/pure, non-gate) calls" };
}

function classifyCallAsGate(compiled: CompiledSources, primitives: PrimitiveIds, call: AstNode): { mechanism: GateMechanism; via: string } | undefined {
  const callee = calleeDeclaration(compiled, call);
  if (!callee) return undefined;
  const direct = primitives.idToMechanism.get(callee.id);
  if (direct) return { mechanism: direct, via: callee.name };
  if (callee.nodeType === "FunctionDefinition" && (callee.stateMutability === "view" || callee.stateMutability === "pure")) {
    return findGateTransitively(compiled, primitives, callee, new Set());
  }
  return undefined;
}

/**
 * Traces one externally reachable function's body (and, if `modifiers` are
 * supplied and resolved, their pre-`_;` code -- see modifierGatesBeforeBody
 * in discover.ts) for gate/effect ordering.
 */
export function traceFunction(compiled: CompiledSources, primitives: PrimitiveIds, fn: AstNode, modifierGateMechanisms: GateMechanism[]): GateTraceResult {
  const statements: ClassifiedStatement[] = modifierGateMechanisms.map((m) => ({
    kind: "GATE" as const,
    nodeType: "ModifierPreCondition",
    detail: `reaches ${m} via an applied modifier's pre-\`_;\` code`,
    mechanism: m,
  }));

  if (!fn.body) {
    return {
      statements,
      mechanismsReached: [...new Set(modifierGateMechanisms)],
      mechanismsReachedAfterEffect: [],
      orderOk: true,
      unresolved: false,
      unresolvedReasons: [],
    };
  }

  for (const flat of flattenBlock(fn.body.statements ?? [])) {
    if (flat.kind === "guard-if") {
      const ifStmt = flat.raw as AstNode;
      const calls = conditionCalls(ifStmt);
      let gate: { mechanism: GateMechanism; via: string } | undefined;
      let unresolved: string | undefined;
      for (const call of calls) {
        const g = classifyCallAsGate(compiled, primitives, call);
        if (g) {
          gate = g;
          break;
        }
        const callee = calleeDeclaration(compiled, call);
        if (callee && callee.nodeType === "FunctionDefinition" && callee.stateMutability !== "view" && callee.stateMutability !== "pure") {
          unresolved = `guard condition calls a non-view/pure function "${callee.name}" -- cannot treat as a side-effect-free guard`;
        }
      }
      if (unresolved) {
        statements.push({ kind: "UNRESOLVED", nodeType: "IfStatement(guard)", detail: unresolved });
      } else if (gate) {
        statements.push({ kind: "GATE", nodeType: "IfStatement(guard)", detail: `guard reaches ${gate.mechanism} via ${gate.via}`, mechanism: gate.mechanism, via: gate.via });
      } else {
        statements.push({ kind: "SAFE", nodeType: "IfStatement(guard)", detail: "validity guard, no gate reached" });
      }
      continue;
    }
    statements.push(classifyPlain(compiled, primitives, flat.raw as AstNode));
  }

  const unresolvedReasons = statements.filter((s) => s.kind === "UNRESOLVED").map((s) => s.detail);
  const firstEffectIndex = statements.findIndex((s) => s.kind === "EFFECT");
  const mechanismsReached: GateMechanism[] = [];
  const mechanismsReachedAfterEffect: GateMechanism[] = [];
  statements.forEach((s, i) => {
    if (s.kind !== "GATE" || !s.mechanism) return;
    if (firstEffectIndex === -1 || i < firstEffectIndex) mechanismsReached.push(s.mechanism);
    else mechanismsReachedAfterEffect.push(s.mechanism);
  });

  return {
    statements,
    mechanismsReached: [...new Set(mechanismsReached)],
    mechanismsReachedAfterEffect: [...new Set(mechanismsReachedAfterEffect)],
    orderOk: mechanismsReachedAfterEffect.length === 0,
    unresolved: unresolvedReasons.length > 0,
    unresolvedReasons,
  };
}

export { canonicalSignature };
