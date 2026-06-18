import { ethers, network } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";

/**
 * Local/testnet demo of the WalletWall Stablecoin Vault Simulator.
 *
 * ⚠️  TESTNET / LOCAL DEMO ONLY. NOT AUDITED. NO MONETARY VALUE.
 *     The mock USDC token (mUSDC) has no value. The PQ verifier used here
 *     is a MOCK (no real on-chain cryptographic verification).
 *     DO NOT use real USDC or any real-value token with this simulator.
 *
 * Run with:  npm run demo:simulator            (Hardhat in-memory network)
 *        or:  npx hardhat run scripts/demo-simulator.ts --network localhost
 *
 * Sepolia / Base Sepolia (testnet gas only, no real value):
 *     npx hardhat run scripts/demo-simulator.ts --network sepolia
 *     npx hardhat run scripts/demo-simulator.ts --network base-sepolia
 */

const ALLOWED_NETWORKS = ["hardhat", "localhost", "sepolia", "base-sepolia"];

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

const DISCLAIMER =
  "TESTNET — RESEARCH PROTOTYPE, NO REAL VALUE. " +
  "Not audited. Mock USDC has no monetary value. PQ verifier may be mock/placeholder.";

function banner(title: string) {
  console.log("\n" + "─".repeat(72));
  console.log(title);
  console.log("─".repeat(72));
}

async function main() {
  if (!ALLOWED_NETWORKS.includes(network.name)) {
    throw new Error(
      `Refusing to deploy on network "${network.name}". ` +
        `Simulator is testnet/local only. Allowed: ${ALLOWED_NETWORKS.join(", ")}`,
    );
  }

  banner("⚠️  " + DISCLAIMER);
  console.log(`Network: ${network.name}`);

  const [owner, recipient] = await ethers.getSigners();

  // --- Deploy MockUSDC ---
  banner("1. Deploy MockUSDC (test token, no value)");
  const mockUSDC = await (await ethers.getContractFactory("MockUSDC")).deploy();
  await mockUSDC.waitForDeployment();
  console.log(`MockUSDC (mUSDC):  ${await mockUSDC.getAddress()}`);
  console.log(`Decimals:          ${await mockUSDC.decimals()} (matches real USDC)`);
  console.log(`Name:              ${await mockUSDC.name()}`);

  // --- Deploy mock PQ verifier ---
  banner("2. Deploy MockMLDSAVerifier (MOCK — no real crypto)");
  const mockVerifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
  await mockVerifier.waitForDeployment();
  console.log(`MockMLDSAVerifier: ${await mockVerifier.getAddress()}`);
  console.log(`PQ algorithmId:    ${await mockVerifier.algorithmId()} (MOCK — no real crypto)`);

  // --- Deploy StablecoinVaultSimulator ---
  banner("3. Deploy StablecoinVaultSimulator");
  const sim = await (
    await ethers.getContractFactory("StablecoinVaultSimulator")
  ).deploy(await mockUSDC.getAddress(), await mockVerifier.getAddress());
  await sim.waitForDeployment();
  console.log(`StablecoinVaultSimulator: ${await sim.getAddress()}`);
  console.log(`Token (immutable):        ${await sim.token()}`);

  // --- Mint test tokens from faucet ---
  banner("4. Mint mUSDC from the faucet (no real value)");
  await (await mockUSDC.connect(owner).faucet()).wait();
  const faucetBalance = await mockUSDC.balanceOf(owner.address);
  console.log(`Minted (faucet):   ${ethers.formatUnits(faucetBalance, 6)} mUSDC to ${owner.address}`);

  // --- Also mint a larger amount via mint() ---
  const mintAmount = 500n * 1_000_000n; // 500 mUSDC
  await (await mockUSDC.connect(owner).mint(owner.address, mintAmount)).wait();
  const totalBalance = await mockUSDC.balanceOf(owner.address);
  console.log(`Minted (mint):     500 mUSDC — total: ${ethers.formatUnits(totalBalance, 6)} mUSDC`);

  // --- Generate PQ keys + create a Hybrid vault ---
  banner("5. Create a Hybrid vault");
  const pqKeys = MLDSASigner.generateKeyPair();
  await (
    await sim.connect(owner).createVault(owner.address, MLDSASigner.toHex(pqKeys.publicKey), VaultMode.Hybrid)
  ).wait();
  console.log(`Owner:   ${owner.address}`);
  console.log(`Mode:    Hybrid (requires ECDSA + PQ attestation)`);
  console.log(`PQ key:  ${MLDSASigner.toHex(pqKeys.publicKey).slice(0, 26)}… (${pqKeys.publicKey.length} bytes)`);

  // --- Deposit via approve + deposit ---
  banner("6. Deposit mUSDC (approve + deposit)");
  const depositAmount = 100n * 1_000_000n; // 100 mUSDC
  await (await mockUSDC.connect(owner).approve(await sim.getAddress(), depositAmount)).wait();
  await (await sim.connect(owner).deposit(depositAmount)).wait();
  console.log(`Approved:          ${ethers.formatUnits(depositAmount, 6)} mUSDC`);
  console.log(`Deposited:         ${ethers.formatUnits(depositAmount, 6)} mUSDC`);
  console.log(`Vault balance:     ${ethers.formatUnits((await sim.getVault(owner.address)).balance, 6)} mUSDC`);
  console.log(`Contract holds:    ${ethers.formatUnits(await mockUSDC.balanceOf(await sim.getAddress()), 6)} mUSDC`);

  // --- Verify: direct transfer does NOT credit the vault ---
  banner("7. Direct transfer — should NOT credit vault accounting");
  const directAmount = 10n * 1_000_000n;
  await (await mockUSDC.connect(owner).transfer(await sim.getAddress(), directAmount)).wait();
  console.log(`Transferred directly: ${ethers.formatUnits(directAmount, 6)} mUSDC to vault address`);
  console.log(
    `Vault record:         ${ethers.formatUnits((await sim.getVault(owner.address)).balance, 6)} mUSDC (unchanged — direct transfer not credited)`,
  );
  console.log(`Contract holds:       ${ethers.formatUnits(await mockUSDC.balanceOf(await sim.getAddress()), 6)} mUSDC`);

  // --- Build EIP-712 withdrawal request ---
  banner("8. Build EIP-712 withdrawal request");
  const { chainId } = await ethers.provider.getNetwork();
  const domain = {
    name: "WalletWallStablecoinVault",
    version: "1",
    chainId,
    verifyingContract: await sim.getAddress(),
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
  const nonce = await sim.nonces(owner.address);
  const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
  const withdrawAmount = 50n * 1_000_000n; // 50 mUSDC
  const request = {
    vaultOwner: owner.address,
    recipient: recipient.address,
    amount: withdrawAmount,
    nonce,
    deadline,
    vaultMode: VaultMode.Hybrid,
  };
  console.log(`Recipient:  ${request.recipient}`);
  console.log(`Amount:     ${ethers.formatUnits(request.amount, 6)} mUSDC (no monetary value)`);
  console.log(`Nonce:      ${nonce}`);
  console.log(`Deadline:   ${deadline} (${new Date(deadline * 1000).toISOString()})`);

  // --- Sign ECDSA ---
  banner("9. Sign classical (ECDSA) authorization");
  const ecdsaSignature = await owner.signTypedData(domain, types, request);
  const digest = ethers.TypedDataEncoder.hash(domain, types, request);
  console.log(`EIP-712 digest:    ${digest}`);
  console.log(`ECDSA signature:   ${ecdsaSignature.slice(0, 26)}…`);

  // --- Attach mock PQ authorization ---
  banner("10. Attach mock PQ authorization");
  const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, pqKeys.privateKey));
  console.log(`PQ signature:   ${pqSignature.slice(0, 26)}… (${(pqSignature.length - 2) / 2} bytes)`);
  console.log("⚠️  PQ signature is checked by a MOCK verifier — no real on-chain cryptographic guarantee.");

  // --- Submit withdrawal ---
  banner("11. Submit withdrawal");
  const tx = await sim.withdraw(request, ecdsaSignature, pqSignature);
  const receipt = await tx.wait();
  console.log(`Tx hash:   ${receipt!.hash}`);

  // --- Event log + post-state ---
  banner("12. Event log + post-state");
  for (const log of receipt!.logs) {
    try {
      const parsed = sim.interface.parseLog(log);
      if (parsed) console.log(`Event: ${parsed.name}(${parsed.args.map((a) => a.toString()).join(", ")})`);
    } catch {
      /* non-simulator log */
    }
  }
  const after = await sim.getVault(owner.address);
  console.log(`New nonce:          ${after.nonce}`);
  console.log(`Vault balance:      ${ethers.formatUnits(after.balance, 6)} mUSDC`);
  console.log(
    `Recipient mUSDC:    ${ethers.formatUnits(await mockUSDC.balanceOf(recipient.address), 6)} mUSDC (no value)`,
  );

  banner("✅  Demo complete — " + DISCLAIMER);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
