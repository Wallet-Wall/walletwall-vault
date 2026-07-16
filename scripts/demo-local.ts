import { network } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";

/**
 * Local/testnet demo of the WalletWall Vault hybrid withdrawal flow.
 *
 * ⚠️  Prototype only. Not audited. Do not use real funds.
 *     The PQ verifier used here is a MOCK (no real cryptographic verification).
 *
 * Run with:  npm run demo            (Hardhat in-memory network)
 *        or:  npx hardhat run scripts/demo-local.ts --network localhost
 */

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

const DISCLAIMER = "Prototype only. Not audited. Do not use real funds. Current PQ verifier may be mock/placeholder.";

function banner(title: string) {
  console.log("\n" + "─".repeat(72));
  console.log(title);
  console.log("─".repeat(72));
}

async function main() {
  const connection = await network.create();
  const { ethers } = connection;

  // "default" is Hardhat 3's built-in in-memory (EDR-simulated) network, the
  // equivalent of Hardhat 2's in-memory "hardhat" network used by `npm run demo`.
  if (
    connection.networkName !== "default" &&
    connection.networkName !== "hardhat" &&
    connection.networkName !== "localhost"
  ) {
    throw new Error(
      `Refusing to run the demo on network "${connection.networkName}". ` +
        "This demo is local/testnet only — use the Hardhat or localhost network.",
    );
  }

  banner("⚠️  " + DISCLAIMER);
  console.log(`Network: ${connection.networkName}`);

  const [owner, recipient] = await ethers.getSigners();

  // --- Deploy mock verifier + vault ---
  banner("1. Deploy (mock PQ verifier + vault)");
  const mockVerifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
  await mockVerifier.waitForDeployment();
  const vault = await (await ethers.getContractFactory("WalletWallVault")).deploy(await mockVerifier.getAddress());
  await vault.waitForDeployment();
  console.log(`MockMLDSAVerifier (MOCK): ${await mockVerifier.getAddress()}`);
  console.log(`WalletWallVault:          ${await vault.getAddress()}`);
  console.log(`PQ algorithmId:           ${await mockVerifier.algorithmId()} (MOCK — no real crypto)`);

  // --- Generate PQ keys + create a hybrid vault ---
  banner("2. Create a Hybrid vault");
  const pqKeys = MLDSASigner.generateKeyPair();
  await (await vault.createVault(owner.address, MLDSASigner.toHex(pqKeys.publicKey), VaultMode.Hybrid)).wait();
  console.log(`Owner:        ${owner.address}`);
  console.log(`Mode:         Hybrid (requires ECDSA + PQ)`);
  console.log(`PQ pubkey:    ${MLDSASigner.toHex(pqKeys.publicKey).slice(0, 26)}… (${pqKeys.publicKey.length} bytes)`);

  // --- Deposit test ETH ---
  banner("3. Deposit test ETH");
  const depositAmount = ethers.parseEther("5.0");
  await (await vault.deposit({ value: depositAmount })).wait();
  console.log(`Deposited:    ${ethers.formatEther(depositAmount)} test ETH`);
  console.log(`Vault balance:${ethers.formatEther((await vault.getVault(owner.address)).balance)} ETH`);

  // --- Build the EIP-712 withdrawal request ---
  banner("4. Build EIP-712 withdrawal request");
  const { chainId } = await ethers.provider.getNetwork();
  const domain = {
    name: "WalletWallVault",
    version: "1",
    chainId,
    verifyingContract: await vault.getAddress(),
  };
  const types = {
    Withdrawal: [
      { name: "vaultOwner", type: "address" },
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "vaultMode", type: "uint8" },
    ],
  };
  const nonce = await vault.nonces(owner.address);
  const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
  const request = {
    vaultOwner: owner.address,
    recipient: recipient.address,
    amount: ethers.parseEther("1.0"),
    nonce,
    deadline,
    vaultMode: VaultMode.Hybrid,
  };
  console.log(`Recipient:    ${request.recipient}`);
  console.log(`Amount:       ${ethers.formatEther(request.amount)} ETH`);
  console.log(`Nonce:        ${nonce}`);
  console.log(`Deadline:     ${deadline} (${new Date(deadline * 1000).toISOString()})`);

  // --- Sign classical (ECDSA) authorization ---
  banner("5. Sign classical (ECDSA) authorization");
  const ecdsaSignature = await owner.signTypedData(domain, types, request);
  const digest = ethers.TypedDataEncoder.hash(domain, types, request);
  console.log(`EIP-712 digest:   ${digest}`);
  console.log(`ECDSA signature:  ${ecdsaSignature.slice(0, 26)}…`);

  // --- Attach mock/PQ authorization ---
  banner("6. Attach mock / PQ authorization");
  const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, pqKeys.privateKey));
  console.log(`PQ signature:     ${pqSignature.slice(0, 26)}… (${(pqSignature.length - 2) / 2} bytes)`);
  console.log("⚠️  PQ signature is checked by a MOCK verifier — no real cryptographic guarantee.");

  // --- Submit the withdrawal ---
  banner("7. Submit withdrawal");
  const tx = await vault.withdraw(request, ecdsaSignature, pqSignature);
  const receipt = await tx.wait();
  console.log(`Tx hash:      ${receipt!.hash}`);

  // --- Show event log + post-state ---
  banner("8. Event log + post-state");
  for (const log of receipt!.logs) {
    try {
      const parsed = vault.interface.parseLog(log);
      if (parsed) console.log(`Event: ${parsed.name}(${parsed.args.map((a) => a.toString()).join(", ")})`);
    } catch {
      /* non-vault log */
    }
  }
  const after = await vault.getVault(owner.address);
  console.log(`New nonce:       ${after.nonce}`);
  console.log(`Vault balance:   ${ethers.formatEther(after.balance)} ETH`);
  console.log(`Recipient bal:   ${ethers.formatEther(await ethers.provider.getBalance(recipient.address))} ETH`);

  banner("✅  Demo complete — " + DISCLAIMER);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
