import { network } from "hardhat";

const ALLOWED_NETWORKS = new Set(["default", "hardhat", "localhost", "sepolia", "base-sepolia"]);

// Expected chain ID for each supported Hardhat network. Used to detect a
// misconfigured RPC URL (e.g. one that actually points at a mainnet) BEFORE any
// gas is spent. A mismatch is a hard failure. Kept identical to
// scripts/deploy-simulator.ts for consistency.
const EXPECTED_CHAIN_ID: Record<string, bigint> = {
  default: 31337n,
  hardhat: 31337n,
  localhost: 31337n,
  sepolia: 11155111n,
  "base-sepolia": 84532n,
};

// Well-known mainnet chain IDs that must NEVER be a deployment target here.
// Kept identical to scripts/deploy-simulator.ts for consistency.
const FORBIDDEN_MAINNET_CHAIN_IDS = new Map<bigint, string>([
  [1n, "Ethereum mainnet"],
  [8453n, "Base mainnet"],
  [137n, "Polygon mainnet"],
  [10n, "Optimism mainnet"],
  [42161n, "Arbitrum One mainnet"],
  [56n, "BNB Smart Chain mainnet"],
  [43114n, "Avalanche C-Chain mainnet"],
]);

/**
 * Deploys the WalletWall Vault research prototype.
 *
 * ⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY.
 *     The deployed PQ verifier is {MockMLDSAVerifier} and performs NO real
 *     cryptographic verification. Do not use with real funds.
 */
async function main() {
  const connection = await network.connect();
  const { ethers } = connection;

  if (!ALLOWED_NETWORKS.has(connection.networkName)) {
    throw new Error(`Refusing to deploy to unsupported network: ${connection.networkName}`);
  }

  // A network-NAME allowlist alone is not enough: `--network sepolia` pointed at
  // a mainnet RPC URL would still deploy the vault to mainnet. Verify the LIVE
  // chain ID reported by the RPC BEFORE any deploy transaction. This mirrors the
  // guard in scripts/deploy-simulator.ts.
  const liveChainId = (await ethers.provider.getNetwork()).chainId;

  const forbidden = FORBIDDEN_MAINNET_CHAIN_IDS.get(liveChainId);
  if (forbidden) {
    throw new Error(
      `REFUSING TO DEPLOY: the RPC for network "${connection.networkName}" reports chain ID ` +
        `${liveChainId} (${forbidden}). This is a MAINNET. The WalletWall Vault ` +
        `prototype is testnet/local only and must never touch mainnet. Aborting before ` +
        `any transaction. Check your *_RPC_URL environment variable.`,
    );
  }

  const expectedChainId = EXPECTED_CHAIN_ID[connection.networkName];
  if (liveChainId !== expectedChainId) {
    throw new Error(
      `Chain ID mismatch for network "${connection.networkName}": expected ${expectedChainId} but the ` +
        `RPC reports ${liveChainId}. Aborting before any transaction — verify your RPC URL ` +
        `points at the correct ${connection.networkName} endpoint.`,
    );
  }

  console.warn(
    "\n⚠️  Prototype only. Not audited. Do not use real funds. " +
      "The PQ verifier deployed here is a MOCK (no real cryptographic verification).\n",
  );
  console.log(`Network: ${connection.networkName}`);
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
