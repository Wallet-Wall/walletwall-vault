import { network } from "hardhat";

import { checkDeploymentBinding } from "./lib/verifier-binding";

const ALLOWED_NETWORKS = new Set(["default", "hardhat", "localhost", "sepolia", "base-sepolia"]);

// Expected chain ID for each supported Hardhat network; kept identical to scripts/deploy.ts.
const EXPECTED_CHAIN_ID: Record<string, bigint> = {
  default: 31337n,
  hardhat: 31337n,
  localhost: 31337n,
  sepolia: 11155111n,
  "base-sepolia": 84532n,
};

// Well-known mainnet chain IDs that must NEVER be a deployment target here; kept identical to scripts/deploy.ts.
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
 * Deploys WalletWallMultiSigVault (research prototype).
 *
 * ⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY. Do not use real funds.
 *
 * SP1-TD2: the multisig vault waits outside the verifier halt's scope until the owner admits it (its gate,
 * TD2-MULTISIG-ROTATION, is built and tested; its authorization cut awaits the owner's review). Until then it is
 * bound to no part of the SP1 path, so the binding gate (scripts/lib/verifier-binding.ts) refuses a ZKMLDSAVerifier
 * here — haltable or not. Without PQC_VERIFIER_ADDRESS the script deploys the MOCK verifier, which performs no real
 * cryptographic verification.
 */
async function main() {
  const connection = await network.create();
  const { ethers } = connection;

  if (!ALLOWED_NETWORKS.has(connection.networkName)) {
    throw new Error(`Refusing to deploy to unsupported network: ${connection.networkName}`);
  }
  const liveChainId = (await ethers.provider.getNetwork()).chainId;
  const forbidden = FORBIDDEN_MAINNET_CHAIN_IDS.get(liveChainId);
  if (forbidden) {
    throw new Error(
      `REFUSING TO DEPLOY: the RPC for network "${connection.networkName}" reports chain ID ${liveChainId} ` +
        `(${forbidden}). This is a MAINNET; the prototype is testnet/local only. Aborting before any transaction.`,
    );
  }
  if (liveChainId !== EXPECTED_CHAIN_ID[connection.networkName]) {
    throw new Error(
      `Chain ID mismatch for network "${connection.networkName}": expected ` +
        `${EXPECTED_CHAIN_ID[connection.networkName]} but the RPC reports ${liveChainId}. Aborting before any transaction.`,
    );
  }

  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const [localSigner] = await ethers.getSigners();
  const deployer = deployerKey ? new ethers.Wallet(deployerKey, ethers.provider) : localSigner;
  if (!deployer) throw new Error("No deployer signer is configured");
  console.warn("\n⚠️  Prototype only. Not audited. Do not use real funds.\n");
  console.log(`Network: ${connection.networkName}`);
  console.log(`Deployer: ${await deployer.getAddress()}`);

  let pqVerifierAddress = process.env.PQC_VERIFIER_ADDRESS;
  if (pqVerifierAddress) {
    if (!ethers.isAddress(pqVerifierAddress)) throw new Error("PQC_VERIFIER_ADDRESS is not a valid address");
    console.log(`Reusing PQ verifier at: ${pqVerifierAddress}`);
  } else {
    const mock = await (await ethers.getContractFactory("MockMLDSAVerifier", deployer)).deploy();
    await mock.waitForDeployment();
    pqVerifierAddress = await mock.getAddress();
    console.log(`MockMLDSAVerifier (MOCK) deployed to: ${pqVerifierAddress}`);
  }

  await checkDeploymentBinding(
    ethers.provider,
    "WalletWallMultiSigVault",
    pqVerifierAddress,
    await deployer.getAddress(),
    {
      allowMockSp1: process.env.ALLOW_MOCK_SP1 === "true",
    },
  );

  const vault = await (await ethers.getContractFactory("WalletWallMultiSigVault", deployer)).deploy(pqVerifierAddress);
  await vault.waitForDeployment();
  console.log(`WalletWallMultiSigVault deployed to: ${await vault.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
