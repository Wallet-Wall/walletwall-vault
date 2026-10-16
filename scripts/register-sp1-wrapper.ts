import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { network } from "hardhat";

import { runScript } from "./lib/run-script";
import { readDesignations, validateDesignationsInRepo } from "./lib/sp1-designation";
import { REGISTRY_REL, readRegistry, validateRegistryInRepo } from "./lib/sp1-registry";
import { haltFact, registrationFact } from "./lib/sp1-registration";
import { readWrapperBuilds } from "./lib/sp1-wrapper-build";
import { LOCAL_CHAIN_IDS } from "./lib/verifier-binding";

/**
 * Appends a fact to the WalletWall SP1 wrapper registry (evidence/zk/sp1-td2/wrapper-registry.json), measured from the
 * chain (scripts/lib/sp1-registration.ts). It sends no transaction; it writes the registry file, which a pull request
 * then publishes (CI keeps it append-only).
 *
 *   WRAPPER_ADDRESS=0x.. DEPLOYMENT_TX=0x.. [REPLACES=0x..] npx hardhat run --network <net> scripts/register-sp1-wrapper.ts
 *   WRAPPER_ADDRESS=0x.. HALT_TX=0x.. HALT_REASON=<reason>  npx hardhat run --network <net> scripts/register-sp1-wrapper.ts
 *
 * A halt is published for every chain: once recorded, the binding gate refuses the wrapper's identity everywhere.
 * Local chains are refused (the registry records public deployments). Research prototype. Not audited.
 */
async function main() {
  const { ethers } = await network.create();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if ((LOCAL_CHAIN_IDS as readonly bigint[]).includes(chainId)) {
    throw new Error(`chain ${chainId} is local: the registry records public deployments only`);
  }
  const published = [...validateDesignationsInRepo(), ...validateRegistryInRepo()];
  if (published.length > 0) throw new Error(`the published SP1 records are invalid:\n - ${published.join("\n - ")}`);
  const registry = readRegistry();
  const builds = readWrapperBuilds();
  const wrapper = process.env.WRAPPER_ADDRESS;
  if (!wrapper) throw new Error("WRAPPER_ADDRESS is required");
  const fact = process.env.HALT_TX
    ? await haltFact(ethers.provider, {
        wrapper,
        haltTx: process.env.HALT_TX,
        reason: String(process.env.HALT_REASON),
        registry,
        builds,
      })
    : await registrationFact(ethers.provider, {
        wrapper,
        deploymentTx: String(process.env.DEPLOYMENT_TX),
        designations: readDesignations(),
        builds,
        registry,
        replaces: process.env.REPLACES ?? null,
      });
  writeFileSync(
    resolve(REGISTRY_REL),
    `${JSON.stringify({ ...registry, facts: [...registry.facts, fact] }, null, 2)}\n`,
  );
  console.log(
    `appended fact #${fact.seq} (${fact.kind}) for ${fact.address} on chain ${fact.chainId} to ${REGISTRY_REL}`,
  );
}

runScript(main);
