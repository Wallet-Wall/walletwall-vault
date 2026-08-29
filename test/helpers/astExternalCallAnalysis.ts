import { AstNode, walkAst } from "./solidityAst";

export interface ExternalCallFinding {
  memberName?: string;
  receiverTypeString: string;
  calleeTypeString?: string;
  reason: string;
}

const LOW_LEVEL_CALL_MEMBERS = new Set(["call", "delegatecall", "staticcall", "send", "transfer"]);

function typeString(node: AstNode | undefined | null): string {
  const ts = node?.typeDescriptions?.typeString;
  return typeof ts === "string" ? ts : "";
}

/**
 * Finds every external-contract call, low-level call, or external member call
 * reachable from `functionBody` (a solc AST function `body` node) — the AST-backed
 * replacement for the old finite-marker-list check. See
 * docs/Guardian_Authority_Design.md §9.1 L-I.
 *
 * Classification is by AST shape and solc's own resolved type information, never
 * by identifier name, so it survives renaming a dependency and catches a newly
 * introduced one:
 *
 *  - A `FunctionCall` whose callee is a plain `Identifier` is an internal
 *    reference (a function/error/struct/event in the same scope, or a revert) —
 *    never flagged.
 *  - A `FunctionCall` whose callee is a `MemberAccess` on a receiver typed
 *    `"contract ..."` IS flagged (this covers other-contract calls and a
 *    same-contract `this.foo()`, which also dispatches via CALL). A `using X for
 *    Y` library call (e.g. `digest.recover(sig)`) is NOT flagged: its receiver is
 *    the value type `Y` (e.g. `"bytes32"`), never `"contract ..."` — confirmed
 *    against the real compiled AST of `_authorizeRotation`.
 *  - A `MemberAccess` named call/delegatecall/staticcall/send/transfer on a
 *    receiver typed `address`/`address payable` is a low-level call. When it
 *    carries `{value: ...}`/`{gas: ...}` (e.g. `target.call{value: x}(data)`),
 *    solc wraps it in an extra `FunctionCallOptions` node, unwrapped here.
 *
 * Known, disclosed limitation: a direct `Library.externalFunc()` call (calling a
 * library's own `external`/`public` function WITHOUT `using X for Y`, a real but
 * rare DELEGATECALL form) is not specially classified — its receiver's
 * typeString is `"type(library Library)"`, not `"contract ..."`. Neither
 * production contract uses that call form anywhere, and it is not among the
 * mutation shapes this task enumerates; see the test file's adversarial-review
 * notes.
 */
export function findExternalCallFindings(functionBody: AstNode): ExternalCallFinding[] {
  const findings: ExternalCallFinding[] = [];
  walkAst(functionBody, (node) => {
    if (node.nodeType !== "FunctionCall" || node.kind !== "functionCall") return;

    let callee = node.expression as AstNode;
    if (callee.nodeType === "FunctionCallOptions") {
      callee = callee.expression as AstNode;
    }
    if (callee.nodeType !== "MemberAccess") return; // Identifier => internal; never flagged

    const receiver = callee.expression as AstNode | undefined;
    const receiverType = typeString(receiver);
    const memberName = callee.memberName as string | undefined;

    if (memberName && LOW_LEVEL_CALL_MEMBERS.has(memberName) && /^address\b/.test(receiverType)) {
      findings.push({
        memberName,
        receiverTypeString: receiverType,
        reason: `low-level .${memberName} on an address-typed receiver`,
      });
      return;
    }
    if (receiverType.startsWith("contract ")) {
      findings.push({
        memberName,
        receiverTypeString: receiverType,
        calleeTypeString: typeString(callee),
        reason: `member call on a contract/interface-typed receiver (${receiverType})`,
      });
    }
  });
  return findings;
}
