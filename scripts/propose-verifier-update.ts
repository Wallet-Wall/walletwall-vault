import { network } from "hardhat";
import { runScript } from "./lib/run-script";
import { assertPublishedSp1Records } from "./lib/sp1-published-records";
import { checkRotationBinding } from "./lib/verifier-binding";

/**
 * Proposes a timelocked pqVerifier rotation on a WalletWall consumer (WalletWallVault, StablecoinVaultSimulator or
 * WalletWallMultiSigVault, identified by its EIP-712 domain). The proposal applies after 172,800 s.
 *
 * SP1-TD2: the target goes through the binding gate first (scripts/lib/verifier-binding.ts). On any non-local
 * chain a ZK target must be an ACTIVE, haltable wrapper whose SP1 verifier code hash and PROGRAM_VKEY are the
 * SP1-TD1 designations, must not carry a halted identity, and must not be haltable by the proposer; a consumer
 * the halt's scope excludes is refused any SP1 target. ALLOW_MOCK_SP1=true relaxes only the designation check,
 * only on a local chain.
 */
async function main() {
  const { ethers } = await network.create();

  const vaultAddress = process.env.VAULT_ADDRESS;
  const newVerifierAddress = process.env.NEW_VERIFIER_ADDRESS;

  if (!vaultAddress || !newVerifierAddress) {
    throw new Error("VAULT_ADDRESS and NEW_VERIFIER_ADDRESS are required");
  }
  if (!ethers.isAddress(vaultAddress) || !ethers.isAddress(newVerifierAddress)) {
    throw new Error("VAULT_ADDRESS and NEW_VERIFIER_ADDRESS must be valid addresses");
  }

  const [vaultCode, verifierCode] = await Promise.all([
    ethers.provider.getCode(vaultAddress),
    ethers.provider.getCode(newVerifierAddress),
  ]);
  if (vaultCode === "0x") {
    throw new Error("VAULT_ADDRESS must reference a deployed contract");
  }
  if (verifierCode === "0x") {
    throw new Error("NEW_VERIFIER_ADDRESS must reference a deployed contract");
  }

  const verifier = await ethers.getContractAt("IPQCVerifier", newVerifierAddress);
  const algorithmId = await verifier.algorithmId();
  if (algorithmId !== ethers.keccak256(ethers.toUtf8Bytes("ZK-ML-DSA-65"))) {
    throw new Error("NEW_VERIFIER_ADDRESS does not report the ZK-ML-DSA-65 algorithm ID");
  }

  const [proposer] = await ethers.getSigners();
  // Off a local chain the binding gate reads only the published SP1 records, fetched now.
  assertPublishedSp1Records((await ethers.provider.getNetwork()).chainId);
  const { consumer } = await checkRotationBinding(
    ethers.provider,
    vaultAddress,
    newVerifierAddress,
    await proposer.getAddress(),
    { allowMockSp1: process.env.ALLOW_MOCK_SP1 === "true" },
  );

  // The three consumers share the rotation ABI; WalletWallVault's binding serves for each.
  const vault = await ethers.getContractAt("WalletWallVault", vaultAddress);
  console.log(`Proposing new PQ verifier ${newVerifierAddress} for ${consumer} ${vaultAddress}...`);
  const tx = await vault.proposePQVerifier(newVerifierAddress);
  await tx.wait();

  const validAfter = await vault.pendingPQVerifierValidAfter();
  console.log("Proposal successful. Can be applied after:", new Date(Number(validAfter) * 1000).toLocaleString());
}

runScript(main);
