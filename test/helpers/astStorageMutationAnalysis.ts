import { AstNode, findContract, findStateVariableId, listFunctionDefinitions, walkAst } from "./solidityAst";

function resolveIndexAccessRootId(expr: AstNode | undefined | null): number | undefined {
  let cur: AstNode | undefined | null = expr;
  while (cur && cur.nodeType === "IndexAccess") {
    cur = cur.baseExpression as AstNode | undefined;
  }
  return cur && cur.nodeType === "Identifier" ? (cur.referencedDeclaration as number | undefined) : undefined;
}

function targetsTrackedId(expr: AstNode | undefined | null, targetIds: Set<number>): boolean {
  if (!expr) return false;
  if (expr.nodeType === "Identifier" && targetIds.has(expr.referencedDeclaration as number)) return true;
  const root = resolveIndexAccessRootId(expr);
  return root !== undefined && targetIds.has(root);
}

/**
 * Local storage-reference variables in `functionBody` whose initializer
 * resolves — through zero or more `IndexAccess` hops, or through an already-
 * discovered alias — back to `mappingId`. Iterated to a fixed point so a
 * multi-hop chain (`X storage a = vaultGuardians[k]; Y storage b = a;`) is
 * tracked fully, not just one hop. Returns alias ids only (never `mappingId`
 * itself).
 */
function discoverAliasIds(functionBody: AstNode, mappingId: number): Set<number> {
  const known = new Set<number>([mappingId]);
  let changed = true;
  while (changed) {
    changed = false;
    walkAst(functionBody, (node) => {
      if (node.nodeType !== "VariableDeclarationStatement") return;
      const initialValue = node.initialValue as AstNode | undefined;
      if (!initialValue) return;
      const rootId =
        initialValue.nodeType === "Identifier"
          ? (initialValue.referencedDeclaration as number | undefined)
          : resolveIndexAccessRootId(initialValue);
      if (rootId === undefined || !known.has(rootId)) return;
      for (const decl of (node.declarations as (AstNode | null)[]) ?? []) {
        if (decl && decl.storageLocation === "storage" && !known.has(decl.id as number)) {
          known.add(decl.id as number);
          changed = true;
        }
      }
    });
  }
  known.delete(mappingId);
  return known;
}

/**
 * True if `functionBody` mutates the state variable identified by `mappingId` —
 * directly, via `delete`, via `.push`/`.pop`, or through any local storage
 * alias (including a transitive alias chain, see {discoverAliasIds}).
 *
 * `=` is structurally an `Assignment` node and `==` a `BinaryOperation` node —
 * the AST disambiguates them by construction, unlike a text search.
 *
 * Known, disclosed limitation: does not follow a mapping/array member passed
 * as a `storage` PARAMETER into another internal function, nor a
 * struct-field-nested storage alias (`SomeStruct storage s = ...; s.arr.push(x)`)
 * — neither production contract does this to `vaultGuardians` today, and
 * `vaultGuardians` is not itself struct-nested.
 */
function bodyMutatesMapping(functionBody: AstNode, mappingId: number): boolean {
  const targetIds = new Set<number>([mappingId, ...discoverAliasIds(functionBody, mappingId)]);

  let found = false;
  walkAst(functionBody, (node) => {
    if (found) return;
    if (node.nodeType === "Assignment" && node.operator === "=") {
      if (targetsTrackedId(node.leftHandSide as AstNode, targetIds)) found = true;
      return;
    }
    if (node.nodeType === "UnaryOperation" && node.operator === "delete") {
      if (targetsTrackedId(node.subExpression as AstNode, targetIds)) found = true;
      return;
    }
    if (node.nodeType === "FunctionCall" && node.kind === "functionCall") {
      let callee = node.expression as AstNode;
      if (callee.nodeType === "FunctionCallOptions") callee = callee.expression as AstNode;
      if (callee.nodeType === "MemberAccess" && (callee.memberName === "push" || callee.memberName === "pop")) {
        if (targetsTrackedId(callee.expression as AstNode, targetIds)) found = true;
      }
    }
  });
  return found;
}

/**
 * Every function (constructor included, reported as `"constructor"`) declared
 * directly in contract `contractName` whose body mutates the state variable
 * `mappingName` — the AST-backed, alias-aware replacement for the old regex
 * check. See docs/Guardian_Authority_Design.md §9.1 L-I / §14.2 regression #2.
 */
export function functionsThatMutateStorageMapping(
  sourceUnitAst: AstNode,
  contractName: string,
  mappingName: string,
): string[] {
  const contractAst = findContract(sourceUnitAst, contractName);
  const mappingId = findStateVariableId(contractAst, mappingName);
  const writers: string[] = [];
  for (const { name, node } of listFunctionDefinitions(contractAst)) {
    if (!node.body) continue; // no body => cannot mutate anything (abstract/interface)
    if (bodyMutatesMapping(node.body as AstNode, mappingId)) writers.push(name);
  }
  return writers;
}
