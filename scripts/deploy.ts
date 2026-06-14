import { ethers, network } from "hardhat";

const ALLOWED_NETWORKS = new Set(["hardhat", "localhost", "sepolia", "base-sepolia"]);

/**
 * Deploys the WalletWall Vault research prototype.
 *
 * ⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY.
 *     The deployed PQ verifier is {MockMLDSAVerifier} and performs NO real
 *     cryptographic verification. Do not use with real funds.
 */
async function main() {
  if (!ALLOWED_NETWORKS.has(network.name)) {
    throw new Error(`Refusing to deploy to unsupported network: ${network.name}`);
  }

  console.warn(
    "\n⚠️  Prototype only. Not audited. Do not use real funds. " +
      "The PQ verifier deployed here is a MOCK (no real cryptographic verification).\n",
  );
  console.log(`Network: ${network.name}`);
  console.log("Deploying contracts...");

  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const [localSigner] = await ethers.getSigners();
  const deployer = deployerKey ? new ethers.Wallet(deployerKey, ethers.provider) : localSigner;
  if (!deployer) {
    throw new Error("No deployer signer is configured");
  }
  console.log(`Deployer: ${await deployer.getAddress()}`);

  // Deploy the mock PQ verifier (test/demo only), or reuse a prior partial deployment.
  let pqVerifierAddress = process.env.PQC_VERIFIER_ADDRESS;
  if (pqVerifierAddress) {
    if (!ethers.isAddress(pqVerifierAddress)) {
      throw new Error("PQC_VERIFIER_ADDRESS is not a valid address");
    }
    const code = await ethers.provider.getCode(pqVerifierAddress);
    if (code === "0x") {
      throw new Error("PQC_VERIFIER_ADDRESS has no deployed contract code");
    }
    try {
      const verifier = await ethers.getContractAt("IPQCVerifier", pqVerifierAddress, deployer);
      await verifier.algorithmId();
    } catch {
      throw new Error("PQC_VERIFIER_ADDRESS does not implement IPQCVerifier");
    }
    console.log(`Reusing PQ verifier at: ${pqVerifierAddress}`);
  } else {
    const MockMLDSAVerifier = await ethers.getContractFactory("MockMLDSAVerifier", deployer);
    const pqVerifier = await MockMLDSAVerifier.deploy();
    await pqVerifier.waitForDeployment();
    pqVerifierAddress = await pqVerifier.getAddress();
    console.log(`MockMLDSAVerifier (MOCK) deployed to: ${pqVerifierAddress}`);
  }

  // Deploy the vault, wired to the PQ verifier trust boundary.
  const WalletWallVault = await ethers.getContractFactory("WalletWallVault", deployer);
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
