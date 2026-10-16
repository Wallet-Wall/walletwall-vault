/**
 * Validate the WalletWall SP1 wrapper registry and the published SP1 records; see scripts/lib/sp1-registry.ts and
 * scripts/lib/append-only-history.ts.
 *
 * Usage:
 *   npm run validate:sp1-registry
 *
 * Checks the registry's facts against the recorded wrapper builds and designations, and walks the git history of
 * the registry, the designations, their evidence bundles and the wrapper builds: anything but an append fails. Needs
 * the full history (CI checks out with fetch-depth 0); a shallow clone fails closed. No transactions, no network.
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { REGISTRY_REL, readRegistry, validateRegistryInRepo } from "./lib/sp1-registry";

const errors = validateRegistryInRepo();
if (errors.length > 0) {
  console.error(`the SP1 wrapper registry or a published SP1 record is invalid:\n - ${errors.join("\n - ")}`);
  process.exitCode = 1;
} else {
  console.log(
    `OK: ${REGISTRY_REL} (${readRegistry().facts.length} facts) matches the recorded builds and designations, and ` +
      `the registry, designations, evidence bundles and wrapper builds have only ever been appended to.`,
  );
}
