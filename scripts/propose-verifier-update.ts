import { network } from "hardhat";
import { runScript } from "./lib/run-script";

async function main() {
  const { ethers } = await network.connect();

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

  const vault = await ethers.getContractAt("WalletWallVault", vaultAddress);
  const verifier = await ethers.getContractAt("IPQCVerifier", newVerifierAddress);
  const algorithmId = await verifier.algorithmId();
  if (algorithmId !== ethers.keccak256(ethers.toUtf8Bytes("ZK-ML-DSA-65"))) {
    throw new Error("NEW_VERIFIER_ADDRESS does not report the ZK-ML-DSA-65 algorithm ID");
  }

  console.log(`Proposing new PQ verifier ${newVerifierAddress} for vault ${vaultAddress}...`);
  const tx = await vault.proposePQVerifier(newVerifierAddress);
  await tx.wait();

  const validAfter = await vault.pendingPQVerifierValidAfter();
  console.log("Proposal successful. Can be applied after:", new Date(Number(validAfter) * 1000).toLocaleString());
}

runScript(main);
