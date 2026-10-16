/**
 * Records main's ruleset as GitHub reports it (scripts/lib/main-ruleset.ts; review finding AUTH-3): one read-only GET
 * through the GitHub CLI, written to evidence/zk/sp1-impl/observations/main-ruleset.raw.json with the time it was made.
 *
 *   npx tsx scripts/measure-main-ruleset.ts      (needs an authenticated gh; changes nothing on GitHub)
 *
 * Not run in CI. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  MAIN_RULESET_ID,
  MAIN_RULESET_OBSERVATION_REL,
  MAIN_RULESET_REPOSITORY,
  MAIN_RULESET_REQUEST,
  MAIN_RULESET_SCHEMA,
  historyProtectionGaps,
  rulesetObservationErrors,
  type GithubRuleset,
  type RulesetObservation,
} from "./lib/main-ruleset";

try {
  const response = JSON.parse(
    execFileSync("gh", ["api", "-X", "GET", `repos/${MAIN_RULESET_REPOSITORY}/rulesets/${MAIN_RULESET_ID}`], {
      encoding: "utf8",
    }),
  ) as GithubRuleset;
  const observation: RulesetObservation = {
    schema: MAIN_RULESET_SCHEMA,
    observedAtUtc: new Date().toISOString(),
    request: MAIN_RULESET_REQUEST,
    tool: "scripts/measure-main-ruleset.ts (gh api, a read-only GET)",
    response,
  };
  const errors = rulesetObservationErrors(observation);
  if (errors.length > 0) throw new Error(`not an observation of main's ruleset:\n - ${errors.join("\n - ")}`);
  mkdirSync(dirname(resolve(MAIN_RULESET_OBSERVATION_REL)), { recursive: true });
  writeFileSync(resolve(MAIN_RULESET_OBSERVATION_REL), `${JSON.stringify(observation, null, 2)}\n`);
  const gaps = historyProtectionGaps(observation);
  console.log(
    `wrote ${MAIN_RULESET_OBSERVATION_REL}: ${gaps.length === 0 ? "main can be neither force-pushed nor deleted, and nobody bypasses that" : `GAPS:\n - ${gaps.join("\n - ")}`}`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
