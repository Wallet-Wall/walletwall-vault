/**
 * SP1-TD2 deployment helpers shared by scripts/deploy-multisig.ts and scripts/deploy-zk-verifier.ts, kept here so
 * the tests exercise the code the scripts run (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { getAddress, isAddress, ZeroAddress, type Signer } from "ethers";

import { checkDeploymentBinding } from "./verifier-binding";

/** Expected chain ID per supported Hardhat network; kept identical to scripts/deploy.ts. */
export const EXPECTED_CHAIN_ID: Record<string, bigint> = {
  default: 31337n,
  hardhat: 31337n,
  localhost: 31337n,
  sepolia: 11155111n,
  "base-sepolia": 84532n,
};

/** Well-known mainnet chain IDs that must never be a deployment target; kept identical to scripts/deploy.ts. */
export const FORBIDDEN_MAINNET_CHAIN_IDS = new Map<bigint, string>([
  [1n, "Ethereum mainnet"],
  [8453n, "Base mainnet"],
  [137n, "Polygon mainnet"],
  [10n, "Optimism mainnet"],
  [42161n, "Arbitrum One mainnet"],
  [56n, "BNB Smart Chain mainnet"],
  [43114n, "Avalanche C-Chain mainnet"],
]);

/** Refuses an unsupported network, any mainnet, and an RPC whose chain ID is not the network's. */
export function assertDeployableChain(networkName: string, liveChainId: bigint): void {
  const expected = EXPECTED_CHAIN_ID[networkName];
  if (expected === undefined) throw new Error(`Refusing to deploy to unsupported network: ${networkName}`);
  const mainnet = FORBIDDEN_MAINNET_CHAIN_IDS.get(liveChainId);
  if (mainnet !== undefined) {
    throw new Error(
      `REFUSING TO DEPLOY: the RPC for network "${networkName}" reports chain ID ${liveChainId} (${mainnet}). ` +
        `This is a MAINNET; the prototype is testnet/local only. Aborting before any transaction.`,
    );
  }
  if (liveChainId !== expected) {
    throw new Error(
      `Chain ID mismatch for network "${networkName}": expected ${expected} but the RPC reports ${liveChainId}. ` +
        `Aborting before any transaction.`,
    );
  }
}

/**
 * The wrapper's halt principal: HALT_PRINCIPAL_ADDRESS, required on every non-local chain. A local chain defaults to
 * `localDefault` (the second local account), so the deployer, who usually deploys the vault too, is not the halt
 * principal — which the consumers would refuse on chain anyway.
 */
export function resolveHaltPrincipal(
  envValue: string | undefined,
  isLocalChain: boolean,
  localDefault?: string,
): string {
  let principal = envValue;
  if (!principal) {
    if (!isLocalChain || !localDefault) {
      throw new Error(
        "HALT_PRINCIPAL_ADDRESS is required: the wrapper's one-way halt needs its halt-only principal (a local chain defaults to the second local account).",
      );
    }
    principal = localDefault;
  }
  if (!isAddress(principal) || getAddress(principal) === ZeroAddress) {
    throw new Error("HALT_PRINCIPAL_ADDRESS must be a non-zero address");
  }
  return getAddress(principal);
}

/** The subset of Hardhat's `ethers` the deployment needs. */
export interface DeployEthers {
  provider: Parameters<typeof checkDeploymentBinding>[0];
  getContractFactory: (name: string, signer: Signer) => Promise<{ deploy: (...args: unknown[]) => Promise<any> }>;
}

/**
 * Deploys WalletWallMultiSigVault bound to `pqcVerifierAddress` (or to a fresh MOCK verifier when none is given),
 * after the binding gate: while the halt's scope excludes the multisig vault, no SP1-path verifier passes. The gate
 * runs before the vault is deployed, and before any transaction when the operator names the verifier, so a refused
 * verifier gets nothing deployed.
 */
export async function deployMultisigVault(
  ethers: DeployEthers,
  deployer: Signer,
  options: { pqcVerifierAddress?: string; allowMockSp1: boolean },
): Promise<{ vault: any; verifierAddress: string; deployedMockVerifier: boolean }> {
  let verifierAddress = options.pqcVerifierAddress;
  let deployedMockVerifier = false;
  if (verifierAddress) {
    if (!isAddress(verifierAddress)) throw new Error("PQC_VERIFIER_ADDRESS is not a valid address");
  } else {
    const mock = await (await ethers.getContractFactory("MockMLDSAVerifier", deployer)).deploy();
    await mock.waitForDeployment();
    verifierAddress = (await mock.getAddress()) as string;
    deployedMockVerifier = true;
  }
  await checkDeploymentBinding(
    ethers.provider,
    "WalletWallMultiSigVault",
    verifierAddress,
    await deployer.getAddress(),
    {
      allowMockSp1: options.allowMockSp1,
    },
  );
  const vault = await (await ethers.getContractFactory("WalletWallMultiSigVault", deployer)).deploy(verifierAddress);
  await vault.waitForDeployment();
  return { vault, verifierAddress, deployedMockVerifier };
}
