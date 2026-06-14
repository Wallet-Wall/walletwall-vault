import { ethers, network } from "hardhat";

/**
 * Deploys the WalletWall Vault research prototype.
 *
 * ⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY.
 *     The deployed PQ verifier is {MockMLDSAVerifier} and performs NO real
 *     cryptographic verification. Do not use with real funds.
 */
async function main() {
  console.warn(
    "\n⚠️  Prototype only. Not audited. Do not use real funds. " +
      "The PQ verifier deployed here is a MOCK (no real cryptographic verification).\n",
  );
  console.log(`Network: ${network.name}`);
  console.log("Deploying contracts...");

  // Deploy the mock PQ verifier (test/demo only).
  const MockMLDSAVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
  const pqVerifier = await MockMLDSAVerifier.deploy();
  await pqVerifier.waitForDeployment();
  const pqVerifierAddress = await pqVerifier.getAddress();
  console.log(`MockMLDSAVerifier (MOCK) deployed to: ${pqVerifierAddress}`);

  // Deploy the vault, wired to the PQ verifier trust boundary.
  const WalletWallVault = await ethers.getContractFactory("WalletWallVault");
  const vault = await WalletWallVault.deploy(pqVerifierAddress);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log(`WalletWallVault deployed to: ${vaultAddress}`);

  console.log("Deployment complete!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
