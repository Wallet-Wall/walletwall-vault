import { network } from "hardhat";
import { execSync } from "child_process";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";

/**
 * Deploy-only script for the WalletWall Stablecoin Vault Simulator stack.
 *
 * ⚠️  TESTNET / LOCAL ONLY. RESEARCH PROTOTYPE. NOT AUDITED. NO REAL VALUE.
 *     Deploys MockUSDC (mUSDC — freely mintable, no monetary value), the
 *     MockMLDSAVerifier (structural-only PQ gate, NO real cryptographic
 *     verification), and StablecoinVaultSimulator wired to both.
 *
 * What this script does NOT do (by design):
 *   - It performs NO approve, deposit, withdraw, faucet, vault-creation, or any
 *     other demo/state transaction. It deploys contracts and stops. For an
 *     end-to-end LOCAL walkthrough use `npm run demo:simulator` instead.
 *   - It never reads, prints, or persists your private key. The deployer key is
 *     supplied only through the DEPLOYER_PRIVATE_KEY environment variable
 *     (typically via an uncommitted .env file) and is consumed by Hardhat.
 *
 * Networks:
 *   - Local:   `npx hardhat run scripts/deploy-simulator.ts` (in-memory hardhat)
 *              or `--network localhost` against a running node.
 *   - Sepolia: `npm run deploy:simulator:sepolia`
 *              (requires a FUNDED throwaway DEPLOYER_PRIVATE_KEY with Sepolia
 *               test ETH; never a wallet that controls real funds).
 *
 * Output:
 *   - Prints schema-shaped deployment metadata to stdout by default.
 *   - Writes the metadata to a file ONLY if DEPLOYMENT_METADATA_OUT is set, e.g.
 *       DEPLOYMENT_METADATA_OUT=deployments/sepolia/stablecoin-vault-simulator.json \
 *         npm run deploy:simulator:sepolia
 *     Inspect the file, then run `npm run validate:deployments` before committing.
 */

// Hardhat network name -> deployment-metadata `environment` enum value.
const NETWORK_ENVIRONMENT: Record<string, "local" | "sepolia" | "base-sepolia"> = {
  default: "local",
  hardhat: "local",
  localhost: "local",
  sepolia: "sepolia",
  "base-sepolia": "base-sepolia",
};

// Expected chain ID for each supported Hardhat network. Used to detect a
// misconfigured RPC URL (e.g. one that actually points at a mainnet) BEFORE any
// gas is spent. A mismatch is a hard failure.
const EXPECTED_CHAIN_ID: Record<string, bigint> = {
  default: 31337n,
  hardhat: 31337n,
  localhost: 31337n,
  sepolia: 11155111n,
  "base-sepolia": 84532n,
};

// Well-known mainnet chain IDs that must NEVER be a deployment target here.
const FORBIDDEN_MAINNET_CHAIN_IDS = new Map<bigint, string>([
  [1n, "Ethereum mainnet"],
  [8453n, "Base mainnet"],
  [137n, "Polygon mainnet"],
  [10n, "Optimism mainnet"],
  [42161n, "Arbitrum One mainnet"],
  [56n, "BNB Smart Chain mainnet"],
  [43114n, "Avalanche C-Chain mainnet"],
]);

const REPO_ROOT = join(import.meta.dirname, "..");

const DISCLAIMER =
  "TESTNET — RESEARCH PROTOTYPE, NO REAL VALUE. Not audited. " +
  "MockUSDC (mUSDC) has no monetary value. PQ verifier is a MOCK (no real cryptographic verification).";

function banner(title: string): void {
  console.log("\n" + "─".repeat(72));
  console.log(title);
  console.log("─".repeat(72));
}

function readPackageVersion(): string {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")) as { version?: string };
  if (typeof pkg.version !== "string") {
    throw new Error("Could not read version from package.json");
  }
  return pkg.version;
}

function readDeploymentCommit(): string | null {
  try {
    const sha = execSync("git rev-parse HEAD", {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    return /^[0-9a-f]{40}$/.test(sha) ? sha : null;
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  const connection = await network.connect();
  const { ethers } = connection;

  const networkName = connection.networkName;
  const environment = NETWORK_ENVIRONMENT[networkName];

  // --- Hard network gate (refuse unsupported networks and mainnet) ---
  if (!environment) {
    throw new Error(
      `Refusing to deploy on unsupported network "${networkName}". ` +
        `Supported: ${Object.keys(NETWORK_ENVIRONMENT).join(", ")}. ` +
        `This simulator is testnet/local only — there is no mainnet deployment path.`,
    );
  }

  const liveChainId = (await ethers.provider.getNetwork()).chainId;

  const forbidden = FORBIDDEN_MAINNET_CHAIN_IDS.get(liveChainId);
  if (forbidden) {
    throw new Error(
      `REFUSING TO DEPLOY: the RPC for network "${networkName}" reports chain ID ` +
        `${liveChainId} (${forbidden}). This is a MAINNET. The Stablecoin Vault ` +
        `Simulator is testnet/local only and must never touch mainnet. Aborting before ` +
        `any transaction. Check your *_RPC_URL environment variable.`,
    );
  }

  const expectedChainId = EXPECTED_CHAIN_ID[networkName];
  if (liveChainId !== expectedChainId) {
    throw new Error(
      `Chain ID mismatch for network "${networkName}": expected ${expectedChainId} but the ` +
        `RPC reports ${liveChainId}. Aborting before any transaction — verify your RPC URL ` +
        `points at the correct ${networkName} endpoint.`,
    );
  }

  // --- Resolve deployer (never logs the key itself) ---
  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  const [localSigner] = await ethers.getSigners();
  const deployer = deployerKey ? new ethers.Wallet(deployerKey, ethers.provider) : localSigner;
  if (!deployer) {
    throw new Error(
      `No deployer available for network "${networkName}". Set DEPLOYER_PRIVATE_KEY in your ` +
        `.env to a FUNDED throwaway testnet key (Sepolia test ETH only — never a wallet that ` +
        `controls real funds).`,
    );
  }
  const deployerAddress = await deployer.getAddress();

  banner("⚠️  " + DISCLAIMER);
  console.log(`Network:    ${networkName}`);
  console.log(`Chain ID:   ${liveChainId}`);
  console.log(`Deployer:   ${deployerAddress}`);

  // Pre-flight balance check so we fail clearly instead of mid-deploy on a
  // non-local network with an unfunded deployer.
  if (environment !== "local") {
    const balance = await ethers.provider.getBalance(deployerAddress);
    console.log(`Balance:    ${ethers.formatEther(balance)} test ETH`);
    if (balance === 0n) {
      throw new Error(
        `Deployer ${deployerAddress} has 0 test ETH on ${networkName}. Fund it with a small ` +
          `amount of ${networkName} test ETH from a faucet before deploying. Aborting before any ` +
          `transaction.`,
      );
    }
  }

  // --- 1. MockUSDC (test token, no monetary value) ---
  banner("1. Deploy MockUSDC (mUSDC — test token, no monetary value)");
  const mockUSDC = await (await ethers.getContractFactory("MockUSDC", deployer)).deploy();
  await mockUSDC.waitForDeployment();
  const tokenAddress = await mockUSDC.getAddress();
  const tokenSymbol = await mockUSDC.symbol();
  const tokenDecimals = Number(await mockUSDC.decimals());
  console.log(`MockUSDC:   ${tokenAddress}  (${tokenSymbol}, ${tokenDecimals} decimals)`);

  // --- 2. MockMLDSAVerifier (MOCK PQ gate — no real crypto) ---
  banner("2. Deploy MockMLDSAVerifier (MOCK — structural only, no real crypto)");
  const verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", deployer)).deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log(`Verifier:   ${verifierAddress}  (algorithmId = MOCK-ML-DSA-65)`);

  // --- 3. StablecoinVaultSimulator(token, verifier) ---
  // Policy engine, timelock, and guardian recovery are NOT separate deployed
  // contracts: the policy engine is optional and wired post-deploy through the
  // governance-delayed proposePolicyEngine flow, the large-tx/governance delay
  // is an in-contract constant, and recovery guardians are configured per-vault
  // by vault owners. They therefore remain null in the deployment metadata.
  banner("3. Deploy StablecoinVaultSimulator(token, verifier)");
  const sim = await (
    await ethers.getContractFactory("StablecoinVaultSimulator", deployer)
  ).deploy(tokenAddress, verifierAddress);
  await sim.waitForDeployment();
  const simulatorAddress = await sim.getAddress();
  console.log(`Simulator:  ${simulatorAddress}`);

  // --- Confirmation timestamp from the simulator deployment block ---
  const deployTx = sim.deploymentTransaction();
  let deployedAt = new Date().toISOString();
  if (deployTx) {
    const receipt = await deployTx.wait();
    if (receipt) {
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      if (block) {
        deployedAt = new Date(Number(block.timestamp) * 1000).toISOString();
      }
    }
  }

  // --- Assemble schema-shaped metadata ---
  const metadata = {
    $schema: "../schema/simulator-deployment.schema.json",
    version: "1",
    environment,
    chainId: Number(liveChainId),
    networkName,
    tokenMode: "mock",
    tokenAddress,
    tokenSymbol,
    tokenDecimals,
    stablecoinVaultSimulatorAddress: simulatorAddress,
    verifierAddress,
    policyEngineAddress: null,
    timelockAddress: null,
    recoveryAddress: null,
    deploymentCommit: readDeploymentCommit(),
    packageVersion: readPackageVersion(),
    deployedAt,
    docsUrl:
      "https://github.com/Wallet-Wall/walletwall-vault/blob/main/docs/specs/testnet-stablecoin-vault-simulator.md",
    warnings: [
      "RESEARCH PROTOTYPE. Not audited. Testnet / local only. Never use real funds.",
      "MockUSDC (mUSDC) has no monetary value. There is no purchase path, no custody, and no yield.",
      "PQ gate uses MockMLDSAVerifier — structural checks only, with no real on-chain ML-DSA cryptographic verification.",
      "No yield, interest, APY, APR, returns, rewards, payout, or profit of any kind.",
      "No mainnet deployment exists or is planned for this contract.",
      "The WalletWall app may read this metadata read-only. Its presence does not indicate the simulator is deployed, reachable, ready for transactions, or holding any custody — always perform on-chain checks before any write interaction.",
    ],
  };

  const json = JSON.stringify(metadata, null, 2);

  banner("Deployment metadata (schema v1)");
  console.log(json);

  const outPath = process.env.DEPLOYMENT_METADATA_OUT;
  if (outPath) {
    const resolved = join(REPO_ROOT, outPath);
    mkdirSync(dirname(resolved), { recursive: true });
    writeFileSync(resolved, json + "\n");
    banner("Metadata written");
    console.log(`Wrote: ${outPath}`);
    console.log("Next: inspect the file, then run `npm run validate:deployments` before committing.");
  } else {
    banner("Metadata NOT written to a file");
    console.log(
      "Set DEPLOYMENT_METADATA_OUT=<path> to persist (e.g. deployments/sepolia/stablecoin-vault-simulator.json).",
    );
  }

  banner("✅  Deploy-only run complete — " + DISCLAIMER);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
