import { network } from "hardhat";

import { assertDeployableChain } from "./lib/deployment-guards";
import { runScript } from "./lib/run-script";
import type { DevProvider } from "./lib/sp1-chain-execution";
import { readDesignations, validateDesignationsInRepo } from "./lib/sp1-designation";
import { readRegistry, validateRegistryInRepo } from "./lib/sp1-registry";
import { currentBuildErrors, readWrapperBuilds } from "./lib/sp1-wrapper-build";
import {
  deployPlannedWrapper,
  planWrapperDeployment,
  preDeploymentChecks,
  readBackErrors,
} from "./lib/zk-verifier-deployment";

/**
 * Deploys a ZKMLDSAVerifier wrapper with designation-only inputs (the SP1 implementation lane;
 * docs/SP1_Implementation_Pin_Designation_Registry.md, scripts/lib/zk-verifier-deployment.ts).
 *
 * Off a local chain the SP1 verifier, its runtime code hash and PROGRAM_VKEY come only from an accepted designation
 * (evidence/zk/sp1/designations/; SP1_DESIGNATION_ID selects one when several are accepted), the wrapper only from the
 * latest recorded build, and the one-way halt's principal from HALT_PRINCIPAL_ADDRESS (halt-only; threshold or multisig
 * control preferred; never the deployer). SP1_VERIFIER_ADDRESS, PROGRAM_VKEY and ALLOW_MOCK_SP1 are refused there.
 * Before deploying it validates the designations and the registry (content and append-only history), measures the
 * designated verifier's code and the per-chain execution verdicts on the target chain, and runs the canary's positive
 * control on the in-process EVM; after deploying it reads the wrapper back. Mainnets are refused.
 *
 * A local chain (31337/1337) deploys the designated verifier's real bytes; with ALLOW_MOCK_SP1=true it then puts an
 * always-accepting mock behind the genuine wrapper — TEST ONLY, refused by the binding gate off a local chain.
 * The new wrapper is not registered here: record it with scripts/register-sp1-wrapper.ts, from chain reads.
 */
async function main() {
  const connection = await network.create();
  const { ethers } = connection;
  const [deployer, localHaltPrincipal] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  assertDeployableChain(connection.networkName, chainId);

  const builds = readWrapperBuilds();
  const plan = planWrapperDeployment({
    chainId,
    env: process.env,
    deployer: deployer.address,
    localHaltPrincipal: localHaltPrincipal?.address,
    designations: readDesignations(),
    builds,
    currentBuildErrors: currentBuildErrors(),
    registry: readRegistry(),
  });
  console.log(`Deploying ZKMLDSAVerifier (${plan.mode}) on chain ${chainId} with account ${deployer.address}`);

  if (plan.mode !== "LOCAL_TEST_MOCK") {
    const published = [...validateDesignationsInRepo(), ...validateRegistryInRepo()];
    if (published.length > 0)
      throw new Error(`refusing to deploy: the published SP1 records are invalid:\n - ${published.join("\n - ")}`);
  }
  let deployable = plan;
  if (plan.mode === "DESIGNATED") {
    const local = await network.create("default");
    const report = await preDeploymentChecks(ethers.provider, plan, local.ethers.provider as unknown as DevProvider);
    console.log(
      `SP1 verifier ${plan.sp1Verifier}: code ${report.codeKeccak}; verdicts ${JSON.stringify(report.verdicts)}`,
    );
  }
  const deployed = await deployPlannedWrapper(ethers, deployer, deployable);
  deployable = deployed.plan;
  if (plan.mode === "LOCAL_DESIGNATED") {
    const report = await preDeploymentChecks(ethers.provider, deployable, ethers.provider as unknown as DevProvider);
    console.log(`local SP1 verifier ${deployable.sp1Verifier}: verdicts ${JSON.stringify(report.verdicts)}`);
  }
  const mismatches = await readBackErrors(ethers.provider, deployed.wrapper, deployable, builds);
  if (mismatches.length > 0)
    throw new Error(`the deployed wrapper is not the planned one:\n - ${mismatches.join("\n - ")}`);

  console.log("ZKMLDSAVerifier deployed to:", deployed.wrapper);
  console.log("Wrapper build:", deployable.build.id);
  console.log("SP1 verifier:", deployable.sp1Verifier);
  console.log("Program vKey:", deployable.programVKey, deployable.designation ? `(${deployable.designation.id})` : "");
  console.log("Halt principal:", deployable.haltPrincipal);
  if (plan.mode === "LOCAL_TEST_MOCK") {
    console.warn(
      "TEST ONLY: an always-accepting MockSP1Verifier now runs behind this wrapper; it verifies nothing real.",
    );
  } else {
    console.log("Next: record it in the registry with scripts/register-sp1-wrapper.ts (chain reads, no transaction).");
  }
  if ((await ethers.provider.getCode(deployable.haltPrincipal)) === "0x") {
    console.warn(
      "Note: the halt principal is an externally owned account (one key). The frozen design prefers threshold or multisig control.",
    );
  }
}

runScript(main);
