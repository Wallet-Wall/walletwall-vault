import { network } from "hardhat";

import { assertDeployableChain, deployMultisigVault } from "./lib/deployment-guards";

/**
 * Deploys WalletWallMultiSigVault (research prototype).
 *
 * ⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY. Do not use real funds.
 *
 * SP1-TD2: the multisig vault waits outside the verifier halt's scope until the owner admits it (its gate,
 * TD2-MULTISIG-ROTATION, is built and tested; its authorization cut awaits the owner's review). Until then it is
 * bound to no part of the SP1 path, so the binding gate (scripts/lib/verifier-binding.ts) refuses a ZKMLDSAVerifier
 * here — haltable or not. Without PQC_VERIFIER_ADDRESS the script deploys the MOCK verifier, which performs no real
 * cryptographic verification. The logic lives in scripts/lib/deployment-guards.ts, where the tests run it.
 */
async function main() {
  const connection = await network.create();
  const { ethers } = connection;
  assertDeployableChain(connection.networkName, (await ethers.provider.getNetwork()).chainId);

  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const [localSigner] = await ethers.getSigners();
  const deployer = deployerKey ? new ethers.Wallet(deployerKey, ethers.provider) : localSigner;
  if (!deployer) throw new Error("No deployer signer is configured");
  console.warn("\n⚠️  Prototype only. Not audited. Do not use real funds.\n");
  console.log(`Network: ${connection.networkName}`);
  console.log(`Deployer: ${await deployer.getAddress()}`);

  const { vault, verifierAddress, deployedMockVerifier } = await deployMultisigVault(ethers, deployer, {
    pqcVerifierAddress: process.env.PQC_VERIFIER_ADDRESS,
    allowMockSp1: process.env.ALLOW_MOCK_SP1 === "true",
  });
  console.log(`${deployedMockVerifier ? "MockMLDSAVerifier (MOCK)" : "PQ verifier"}: ${verifierAddress}`);
  console.log(`WalletWallMultiSigVault deployed to: ${await vault.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
