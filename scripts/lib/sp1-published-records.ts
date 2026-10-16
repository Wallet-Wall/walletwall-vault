/**
 * Off a local chain the SP1 tooling acts only on the published records (the SP1 implementation lane; review findings
 * L-1 and AUTH-4; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * The cross-chain refusal of a halted identity is repository-published data (scripts/lib/sp1-registry.ts), so it is
 * only as fresh as the checkout that reads it: a stale clone lacks a published WRAPPER_HALTED fact and would bind the
 * halted identity on another chain, and a record nobody merged (a successor, a fact, a build) is not published. Before
 * anything binds, deploys or registers off a local chain, the registry, the designations, their evidence bundles and
 * the wrapper builds must be exactly what origin/main holds, fetched then, and they must validate. A fetch that fails
 * is no answer: refused.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { DESIGNATIONS_DIR, DESIGNATION_EVIDENCE_DIR, validateDesignationsInRepo } from "./sp1-designation";
import { REGISTRY_REL, validateRegistryInRepo } from "./sp1-registry";
import { WRAPPER_BUILDS_DIR } from "./sp1-wrapper-build";
import { LOCAL_CHAIN_IDS } from "./verifier-binding";

/** Where the records are published: what the binding, deployment and registration tooling read off a local chain. */
export const PUBLISHED_REF = "origin/main";
export const PUBLISHED_RECORD_PATHS = [REGISTRY_REL, DESIGNATIONS_DIR, DESIGNATION_EVIDENCE_DIR, WRAPPER_BUILDS_DIR];

const firstLine = (error: unknown) =>
  String((error as { stderr?: unknown })?.stderr || (error as Error)?.message || error)
    .trim()
    .split("\n")[0];

/** Every way the records at `repoRoot` are not the published ones (after fetching origin main, when `fetch`). */
export function publishedRecordsErrors(repoRoot: string, options: { fetch: boolean }): string[] {
  const git = (args: string[]) =>
    execFileSync("git", ["-C", resolve(repoRoot), ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (options.fetch) {
    try {
      git(["fetch", "--quiet", "origin", "main"]);
    } catch (error) {
      return [
        `the published records could not be fetched (git fetch origin main: ${firstLine(error)}): off a local chain ` +
          "nothing binds, deploys or registers on records that may be stale",
      ];
    }
  }
  let changed: string[];
  let untracked: string[];
  try {
    changed = git(["diff", "--name-only", PUBLISHED_REF, "--", ...PUBLISHED_RECORD_PATHS])
      .split("\n")
      .filter(Boolean);
    untracked = git(["ls-files", "--others", "--exclude-standard", "--", ...PUBLISHED_RECORD_PATHS])
      .split("\n")
      .filter(Boolean);
  } catch (error) {
    return [`cannot compare the records with ${PUBLISHED_REF} (${firstLine(error)})`];
  }
  return [
    ...changed.map((path) => `${path}: not what ${PUBLISHED_REF} publishes`),
    ...untracked.map((path) => `${path}: not published (an untracked record)`),
  ];
}

/** Returns on a local chain; elsewhere throws unless the records are the published ones and they validate. */
export function assertPublishedSp1Records(chainId: bigint, repoRoot = "."): void {
  if ((LOCAL_CHAIN_IDS as readonly bigint[]).includes(chainId)) return;
  const errors = publishedRecordsErrors(repoRoot, { fetch: true });
  if (errors.length === 0) errors.push(...validateDesignationsInRepo(repoRoot), ...validateRegistryInRepo(repoRoot));
  if (errors.length > 0) {
    throw new Error(
      `refusing on chain ${chainId}: off a local chain the SP1 records must be the published ones (${PUBLISHED_REF}) ` +
        `and valid:\n - ${errors.join("\n - ")}`,
    );
  }
}
