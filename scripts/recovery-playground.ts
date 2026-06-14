import { ethers } from "hardhat";

/**
 * Local simulation of the Guardian Recovery flow for WalletWall Vault.
 * This script demonstrates setting guardians, initiating a recovery request,
 * supporting it, fast-forwarding time by the required 7 days, and executing it.
 *
 * Run with:  npx hardhat run scripts/recovery-playground.ts
 */
async function main() {
  console.log("\n==================================================");
  console.log("WalletWall Vault Guardian Recovery Simulation");
  console.log("==================================================\n");

  const [owner, guardian1, guardian2, newSigner] = await ethers.getSigners();

  // 1. Deploy verifier and vault
  console.log("1. Deploying verifier and vault...");
  const verifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
  await verifier.waitForDeployment();
  const vault = await (await ethers.getContractFactory("WalletWallVault")).deploy(await verifier.getAddress());
  await vault.waitForDeployment();
  console.log(`Vault deployed at: ${await vault.getAddress()}`);

  // 2. Create owner's vault
  console.log("2. Creating owner's vault in Hybrid mode...");
  const mockPqKey = ethers.hexlify(ethers.randomBytes(1952));
  await (await vault.createVault(owner.address, mockPqKey, 2)).wait();
  let vaultOwnerInfo = await vault.getVault(owner.address);
  console.log(`Original ECDSA Signer: ${vaultOwnerInfo.ecdsaSigner}`);

  // 3. Set guardians
  console.log("3. Registering guardians...");
  await (await vault.setGuardians([guardian1.address, guardian2.address])).wait();
  console.log("Guardians registered successfully.");

  // 4. Initiate recovery
  console.log("4. Guardian 1 initiating recovery for lost credentials...");
  const newPqKey = ethers.hexlify(ethers.randomBytes(1952));
  await (await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPqKey)).wait();
  const recoveryReq = await vault.recoveryRequests(owner.address);
  console.log(`Recovery initiated. Earliest execution timestamp: ${recoveryReq.executeAfter}`);

  // Guardian 1 supports the request
  console.log("Guardian 1 supporting the recovery request...");
  await (await vault.connect(guardian1).supportRecovery(owner.address)).wait();

  // 5. Support recovery
  console.log("5. Guardian 2 supporting the recovery request...");
  await (await vault.connect(guardian2).supportRecovery(owner.address)).wait();
  const updatedReq = await vault.recoveryRequests(owner.address);
  console.log(`Recovery support count: ${updatedReq.supportCount} (Threshold required: 2)`);

  // 6. Fast-forward time
  console.log("6. Fast-forwarding local blockchain time by 7 days...");
  await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60]);
  await ethers.provider.send("evm_mine", []);

  // 7. Execute recovery
  console.log("7. Executing recovery...");
  await (await vault.executeRecovery(owner.address)).wait();

  const finalVaultState = await vault.getVault(owner.address);
  console.log("\n==================================================");
  console.log("Recovery completed successfully!");
  console.log(`New ECDSA Signer: ${finalVaultState.ecdsaSigner}`);
  console.log("==================================================\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
