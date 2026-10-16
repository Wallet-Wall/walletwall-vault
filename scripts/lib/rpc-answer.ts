/**
 * What a failed eth_call means (SP1-TD2 review findings R2-2 and R3-1; shared by the binding gate and the SP1
 * implementation lane's per-chain execution check).
 *
 * Only the chain's own answer — the call ran and reverted, or ran out of gas — is an answer. A rate limit, a timeout, a
 * refused connection or a node that lost the state is NOT an answer, and no rule may read it as one: an off-chain gate
 * that took "the call failed" for "the call reverted" fails OPEN on a rate-limited RPC (the halt of a registered
 * wrapper would disappear; a missing verdict would read as a refusal).
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { isHexString } from "ethers";

const EXECUTION_FAILURE =
  /revert|out of gas|gas required exceeds|invalid opcode|invalid jump|stack (?:under|over)flow|vm execution error/i;

/** A node's own JSON-RPC error that says the call ran and failed: EIP-1474 code 3, or a server error saying so. */
function nodeReportsExecutionFailure(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  if (code === 3) return true;
  return (
    (code === -32000 || code === -32015 || code === -32603) &&
    typeof message === "string" &&
    EXECUTION_FAILURE.test(message)
  );
}

/**
 * Whether a failed eth_call is the chain's answer — the call ran and reverted or ran out of gas, which the guard
 * reads as "no answer" — rather than the RPC failing to answer (a rate limit, a timeout, a refused connection).
 * EIP-1474 code 3 is a revert; a node reports running out of gas (and some clients a revert without data) as a
 * server error whose message says so. Ethers' own JSON-RPC providers turn every failed eth_call into
 * CALL_EXCEPTION, keeping the node's error in `info.error`: that error decides, and without it only a call that
 * came back with revert data is an answer (the review's R3-1). Anything else is not an answer.
 */
export function isExecutionFailure(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const e = error as { code?: unknown; info?: { error?: unknown } | null; data?: unknown };
  if (e.code === "CALL_EXCEPTION") {
    if (e.info?.error !== undefined) return nodeReportsExecutionFailure(e.info.error);
    return typeof e.data === "string" && isHexString(e.data);
  }
  return nodeReportsExecutionFailure(error);
}

/** The revert data a failed call carried (EDR, ethers and plain JSON-RPC all put it in `data`), or null. */
export function revertDataOf(error: unknown): string | null {
  if (error === null || typeof error !== "object") return null;
  const e = error as { data?: unknown; info?: { error?: { data?: unknown } } | null };
  if (typeof e.data === "string" && isHexString(e.data)) return e.data.toLowerCase();
  const nested = e.info?.error?.data;
  return typeof nested === "string" && isHexString(nested) ? nested.toLowerCase() : null;
}
