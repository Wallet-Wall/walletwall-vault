/**
 * Main's history protection, measured (the SP1 implementation lane; review finding AUTH-3;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * The append-only proof of the registry, the designations, their evidence and the wrapper builds walks the history it
 * is given (scripts/lib/append-only-history.ts). A rewrite of main itself, by a force push or a deletion, would hand it
 * a history without the rewritten facts, and it could not tell. What forbids that is main's ruleset (non_fast_forward
 * and deletion, with nobody able to bypass them), which lives in GitHub, not in this tree. So it is measured:
 * scripts/measure-main-ruleset.ts records the ruleset as GitHub reports it (a read-only GET), and the receipt states
 * what the record shows. It is one measurement at one time: whoever administers the repository can change the ruleset
 * afterwards, and only the next measurement would show it.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const MAIN_RULESET_ID = 21256062;
export const MAIN_RULESET_REPOSITORY = "Wallet-Wall/walletwall-vault";
export const MAIN_RULESET_REQUEST = `GET /repos/${MAIN_RULESET_REPOSITORY}/rulesets/${MAIN_RULESET_ID}`;
export const MAIN_RULESET_OBSERVATION_REL = "evidence/zk/sp1-impl/observations/main-ruleset.raw.json";
export const MAIN_RULESET_SCHEMA = "walletwall.github-ruleset-observation.v1";
const MAIN = "refs/heads/main";

/** The ruleset as GitHub's REST API returns it (the fields read here; the record keeps the whole response). */
export interface GithubRuleset {
  id: number;
  target: string;
  enforcement: string;
  conditions: { ref_name: { include: string[]; exclude: string[] } };
  rules: { type: string; parameters?: unknown }[];
  bypass_actors: unknown[];
  current_user_can_bypass?: string;
  [field: string]: unknown;
}

export interface RulesetObservation {
  schema: string;
  observedAtUtc: string;
  request: string;
  tool: string;
  response: GithubRuleset;
}

/** Why the record is no observation of main's ruleset; empty when it is one. */
export function rulesetObservationErrors(obs: RulesetObservation): string[] {
  const errors: string[] = [];
  if (obs?.schema !== MAIN_RULESET_SCHEMA) errors.push(`the observation's schema must be ${MAIN_RULESET_SCHEMA}`);
  if (obs?.request !== MAIN_RULESET_REQUEST) errors.push(`the observation's request must be ${MAIN_RULESET_REQUEST}`);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(String(obs?.observedAtUtc))) errors.push("the observation names no observedAtUtc");
  if (obs?.response?.id !== MAIN_RULESET_ID) errors.push(`the response is not ruleset ${MAIN_RULESET_ID}`);
  if (!Array.isArray(obs?.response?.rules)) errors.push("the response lists no rules");
  if (!Array.isArray(obs?.response?.bypass_actors)) errors.push("the response lists no bypass actors");
  if (!Array.isArray(obs?.response?.conditions?.ref_name?.include)) errors.push("the response names no branches");
  return errors;
}

/** Every way, per the observation, that main's history could be rewritten or deleted; empty when none. */
export function historyProtectionGaps(obs: RulesetObservation): string[] {
  const r = obs?.response;
  const gaps: string[] = [];
  if (r?.enforcement !== "active") gaps.push(`the ruleset is ${String(r?.enforcement)}, not active`);
  if (r?.target !== "branch") gaps.push(`the ruleset targets ${String(r?.target)}, not a branch`);
  const include = r?.conditions?.ref_name?.include ?? [];
  const exclude = r?.conditions?.ref_name?.exclude ?? [];
  if (![MAIN, "~DEFAULT_BRANCH", "~ALL"].some((ref) => include.includes(ref))) {
    gaps.push(`the ruleset does not cover ${MAIN} (it includes ${include.join(", ") || "nothing"})`);
  }
  if ([MAIN, "~DEFAULT_BRANCH", "~ALL"].some((ref) => exclude.includes(ref))) gaps.push(`the ruleset excludes ${MAIN}`);
  const rules = new Set((r?.rules ?? []).map((x) => x?.type));
  if (!rules.has("non_fast_forward")) gaps.push("force pushes to main are not refused (no non_fast_forward rule)");
  if (!rules.has("deletion")) gaps.push("main can be deleted (no deletion rule)");
  const bypass = Array.isArray(r?.bypass_actors) ? r.bypass_actors.length : -1;
  if (bypass !== 0) gaps.push(`${bypass === -1 ? "unknown" : bypass} actor(s) can bypass the ruleset`);
  if (r?.current_user_can_bypass !== "never") {
    gaps.push(`the measuring account can bypass the ruleset (${String(r?.current_user_can_bypass)})`);
  }
  return gaps;
}

/** The committed observation, or null when there is none. */
export function readRulesetObservation(repoRoot = "."): RulesetObservation | null {
  const path = resolve(repoRoot, MAIN_RULESET_OBSERVATION_REL);
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as RulesetObservation) : null;
}
