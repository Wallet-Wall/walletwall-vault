import { ethers } from "hardhat";

async function main() {
  const vaultAddress = process.env.VAULT_ADDRESS;
  const newVerifierAddress = process.env.NEW_VERIFIER_ADDRESS;

  if (!vaultAddress || !newVerifierAddress) {
    console.error("Please set VAULT_ADDRESS and NEW_VERIFIER_ADDRESS");
    process.exit(1);
  }

  const vault = await ethers.getContractAt("WalletWallVault", vaultAddress);

  console.log(`Proposing new PQ verifier ${newVerifierAddress} for vault ${vaultAddress}...`);
  const tx = await vault.proposePQVerifier(newVerifierAddress);
  await tx.wait();

  const validAfter = await vault.pendingPQVerifierValidAfter();
  console.log("Proposal successful. Can be applied after:", new Date(Number(validAfter) * 1000).toLocaleString());
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
