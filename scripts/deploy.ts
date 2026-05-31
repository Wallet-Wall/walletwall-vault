import { ethers } from "hardhat";

async function main() {
  console.log("Deploying contracts...");

  // Deploy SignatureVerifier
  const SignatureVerifier = await ethers.getContractFactory("SignatureVerifier");
  const verifier = await SignatureVerifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log(`SignatureVerifier deployed to: ${verifierAddress}`);

  // Deploy WalletWallVault
  const WalletWallVault = await ethers.getContractFactory("WalletWallVault");
  const vault = await WalletWallVault.deploy(verifierAddress);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log(`WalletWallVault deployed to: ${vaultAddress}`);

  console.log("Deployment complete!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
