/**
 * Off a local chain the SP1 tooling acts only on the published records (the SP1 implementation lane; review findings
 * L-1 and AUTH-4, and the re-review's A3 and A4; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * The cross-chain refusal of a halted identity is repository-published data (scripts/lib/sp1-registry.ts), so it is
 * only as fresh as the checkout that reads it: a stale clone lacks a published WRAPPER_HALTED fact and would bind the
 * halted identity on another chain, and a record nobody merged (a successor, a fact, a build) is not published. Before
 * anything binds, deploys or registers off a local chain, the registry, the designations, their evidence bundles and
 * the wrapper builds on disk must be, byte for byte, what the canonical repository's main holds, fetched then from
 * that repository itself into a private ref (never whatever `origin` names, a fork included). The comparison reads
 * every file on disk, ignored ones included, as the tooling reads it, never through git's index (assume-unchanged or
 * skip-worktree hide nothing), and a ref named origin/main shadows nothing. A fetch that fails is no answer: refused.
 * The registration script alone may hold facts appended to the published registry (registryMayExtend), so that a
 * wrapper's registration and its halt can be published in one pull request.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { DESIGNATIONS_DIR, DESIGNATION_EVIDENCE_DIR, validateDesignationsInRepo } from "./sp1-designation";
import { REGISTRY_REL, registryExtensionErrors, validateRegistryInRepo } from "./sp1-registry";
import { WRAPPER_BUILDS_DIR } from "./sp1-wrapper-build";
import { LOCAL_CHAIN_IDS } from "./verifier-binding";

/** Where the records are published: the canonical repository's main, fetched by URL. */
export const PUBLISHED_SOURCE = "https://github.com/Wallet-Wall/walletwall-vault.git";
export const PUBLISHED_BRANCH = "main";
/** The private ref the published main is fetched into (it never names or moves a branch). */
const PUBLISHED_REF = "refs/sp1-published/main";
export const PUBLISHED_RECORD_PATHS = [REGISTRY_REL, DESIGNATIONS_DIR, DESIGNATION_EVIDENCE_DIR, WRAPPER_BUILDS_DIR];

const firstLine = (error: unknown) =>
  String((error as { stderr?: unknown })?.stderr || (error as Error)?.message || error)
    .trim()
    .split("\n")[0];
const lf = (text: string) => text.replace(/\r\n/g, "\n");

/** Every file under `rel` on disk, as a repository-relative posix path; links are refused, not followed. */
function filesOnDisk(repoRoot: string, rel: string, links: string[]): string[] {
  const path = resolve(repoRoot, rel);
  if (!existsSync(path)) return [];
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) {
    links.push(rel);
    return [];
  }
  if (!stat.isDirectory()) return [rel];
  return readdirSync(path)
    .sort()
    .flatMap((name) => filesOnDisk(repoRoot, `${rel}/${name}`, links));
}

/**
 * Every way the records at `repoRoot` are not the published ones, after fetching `source`'s main; empty when they are.
 * With `registryMayExtend`, the registry may append facts to the published one (it may never drop or rewrite one).
 */
export function publishedRecordsErrors(
  repoRoot: string,
  options: { source?: string; registryMayExtend?: boolean } = {},
): string[] {
  const source = options.source ?? PUBLISHED_SOURCE;
  const where = `${source} ${PUBLISHED_BRANCH}`;
  const git = (args: string[]) =>
    execFileSync("git", ["-C", resolve(repoRoot), ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 64 * 1024 * 1024,
    });
  let published: string[];
  try {
    git(["fetch", "--quiet", "--no-tags", source, `+refs/heads/${PUBLISHED_BRANCH}:${PUBLISHED_REF}`]);
    published = git(["ls-tree", "-r", "--name-only", PUBLISHED_REF, "--", ...PUBLISHED_RECORD_PATHS])
      .split("\n")
      .filter(Boolean);
  } catch (error) {
    return [
      `the published records could not be fetched from ${where} (${firstLine(error)}): off a local chain nothing ` +
        "binds, deploys or registers on records that may be stale",
    ];
  }
  const links: string[] = [];
  const onDisk = PUBLISHED_RECORD_PATHS.flatMap((rel) => filesOnDisk(repoRoot, rel, links));
  const errors = links.map((rel) => `${rel}: a link, not a record`);
  for (const path of onDisk) {
    if (!published.includes(path)) errors.push(`${path}: not published (${where} does not hold it)`);
  }
  for (const path of published) {
    if (!onDisk.includes(path)) {
      errors.push(`${path}: published, but missing here`);
      continue;
    }
    const theirs = lf(git(["cat-file", "blob", `${PUBLISHED_REF}:${path}`]));
    const ours = lf(readFileSync(resolve(repoRoot, path), "utf8"));
    if (ours === theirs) continue;
    if (options.registryMayExtend && path === REGISTRY_REL && registryExtensionErrors(theirs, ours).length === 0) {
      continue;
    }
    errors.push(`${path}: not what ${where} publishes`);
  }
  return errors;
}

/**
 * Returns on a local chain; elsewhere throws unless the records are the published ones (fetched now from the canonical
 * repository) and they validate, content and history.
 */
export function assertPublishedSp1Records(
  chainId: bigint,
  repoRoot = ".",
  options: { source?: string; registryMayExtend?: boolean } = {},
): void {
  if ((LOCAL_CHAIN_IDS as readonly bigint[]).includes(chainId)) return;
  const errors = publishedRecordsErrors(repoRoot, options);
  if (errors.length === 0) errors.push(...validateDesignationsInRepo(repoRoot), ...validateRegistryInRepo(repoRoot));
  if (errors.length > 0) {
    throw new Error(
      `refusing on chain ${chainId}: off a local chain the SP1 records must be the published ones ` +
        `(${options.source ?? PUBLISHED_SOURCE} ${PUBLISHED_BRANCH}) and valid:\n - ${errors.join("\n - ")}`,
    );
  }
}
