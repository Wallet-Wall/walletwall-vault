# Local Playground Guide

This guide describes how to run the WalletWall Vault prototype locally and experiment with its core features. Since this is a smart contract prototype, you can play around with it using the interactive console, modifying test scripts, or simulating recovery scenarios.

> ⚠️ **Research prototype. Not audited. Not production custody. Do not use real funds.**
> See [SECURITY.md](../SECURITY.md) and [Security_Assumptions.md](Security_Assumptions.md) for full context.

---

## Prerequisites

Before starting, make sure you have installed all dependencies and compiled the contracts:

```bash
# Install packages
npm install

# Clean & Compile
npm run clean
npm run compile
```

---

## Option 1: Interactive Hardhat Console

The interactive Hardhat console allows you to deploy contracts and execute functions line-by-line using `ethers.js` in your terminal.

1. **Start a persistent local blockchain node** in your first terminal window:
   ```bash
   npx hardhat node
   ```

2. **Open the interactive console** in a second terminal window:
   ```bash
   npx hardhat console --network localhost
   ```

3. **Copy-paste the following JavaScript snippet** into the console to deploy and interact:
   ```javascript
   // 1. Get the local test accounts
   const [owner, recipient, guardian] = await ethers.getSigners();

   // 2. Deploy the Mock PQC Verifier
   const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
   const verifier = await MockVerifier.deploy();
   await verifier.waitForDeployment();
   console.log("Mock Verifier deployed at:", await verifier.getAddress());

   // 3. Deploy the main Vault
   const Vault = await ethers.getContractFactory("WalletWallVault");
   const vault = await Vault.deploy(await verifier.getAddress());
   await vault.waitForDeployment();
   console.log("Vault deployed at:", await vault.getAddress());

   // 4. Register a vault in Hybrid mode (mode 2) with a mock 1952-byte PQ public key
   const mockPqKey = ethers.hexlify(ethers.randomBytes(1952));
   const tx = await vault.createVault(owner.address, mockPqKey, 2);
   await tx.wait();
   console.log("Vault created successfully for owner:", owner.address);

   // 5. Deposit test ETH
   await vault.deposit({ value: ethers.parseEther("10.0") });
   const vaultInfo = await vault.getVault(owner.address);
   console.log("Vault ETH Balance:", ethers.formatEther(vaultInfo.balance));
   ```

At this point, you can interact with the `vault` variable directly. For instance:
* Check the current nonce: `await vault.nonces(owner.address)`
* Pause the vault: `await vault.pause()`
* Set guardians: `await vault.setGuardians([guardian.address])`

---

## Option 2: Modify the Local Demo to Trigger Security Failures

You can play around with the contract logic and security rules by altering [scripts/demo-local.ts](../scripts/demo-local.ts) and running the local demo.

Run the default demo using:
```bash
npm run demo
```

To experiment with failures, open `scripts/demo-local.ts` and apply the following modifications:

### Test Replay Protection
In the withdrawal execution area, try executing the withdrawal twice using the same signature parameters:
```typescript
// First submission (succeeds)
await vault.withdraw(request, ecdsaSignature, pqSignature);

// Replay submission (reverts with InvalidNonce)
await vault.withdraw(request, ecdsaSignature, pqSignature); 
```

### Test Tamper Protection
Modify the recipient or the withdrawal amount after generating the EIP-712 signature:
```typescript
const ecdsaSignature = await owner.signTypedData(domain, types, request);

// Tamper with the recipient address
request.recipient = "0x0000000000000000000000000000000000000000";

// Reverts with InvalidEcdsaSignature because signature digest no longer matches
await vault.withdraw(request, ecdsaSignature, pqSignature);
```

### Test Expired Deadlines
Alter the deadline value in the withdrawal request to be in the past:
```typescript
const request = {
  ...
  deadline: Math.floor(Date.now() / 1000) - 10, // expired 10 seconds ago
  ...
};
```
*Result: Reverts with `DeadlineExpired`.*

---

## Option 3: Run the Guardian Recovery Script

If a user loses their ECDSA key or PQ key, the vault enables a guardian-supported credential rotation. You can run this scenario programmatically.

1. Create a script called `scripts/recovery-playground.ts`:
   ```typescript
   import { ethers } from "hardhat";

   async function main() {
     const [owner, guardian1, guardian2, newSigner] = await ethers.getSigners();

     // Deploy verifier & vault
     const verifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
     const vault = await (await ethers.getContractFactory("WalletWallVault")).deploy(await verifier.getAddress());

     // Create owner vault
     const mockPqKey = ethers.hexlify(ethers.randomBytes(1952));
     await vault.createVault(owner.address, mockPqKey, 2);

     // Set guardians
     console.log("Setting guardians...");
     await vault.setGuardians([guardian1.address, guardian2.address]);

     // Initiate recovery (simulate losing keys, guardian1 starts it)
     console.log("Guardian 1 initiating recovery...");
     const newPqKey = ethers.hexlify(ethers.randomBytes(1952));
     await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPqKey);

     // Guardian 1 supports recovery
     console.log("Guardian 1 supporting recovery...");
     await vault.connect(guardian1).supportRecovery(owner.address);

     // Guardian 2 supports recovery to reach threshold (N/2 + 1 = 2)
     console.log("Guardian 2 supporting recovery...");
     await vault.connect(guardian2).supportRecovery(owner.address);

     // Simulate time travel (recovery requires a 7-day delay)
     console.log("Fast-forwarding blockchain time by 7 days...");
     await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60]);
     await ethers.provider.send("evm_mine", []);

     // Execute recovery
     console.log("Executing recovery...");
     await vault.executeRecovery(owner.address);

     const updatedVault = await vault.getVault(owner.address);
     console.log("Recovery completed successfully!");
     console.log("New ECDSA signer:", updatedVault.ecdsaSigner);
   }

   main().catch(console.error);
   ```

2. Run the script:
   ```bash
   npx hardhat run scripts/recovery-playground.ts
   ```
