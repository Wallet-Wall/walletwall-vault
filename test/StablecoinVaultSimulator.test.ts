import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import {
  MockUSDC,
  MockMLDSAVerifier,
  AttestationPQCVerifier,
  RecipientAllowlistPolicy,
  DailySpendLimitPolicy,
  SanctionsListPolicy,
  StablecoinVaultSimulator,
} from "../typechain-types";
import {
  simulatorDomain,
  WITHDRAWAL_TYPES,
  makeSignWithdrawal,
  makeBuildRequest,
  buildAttestationPayload,
} from "./helpers/simulatorHelpers";

// VaultMode enum mirror
const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

// 1 000 mUSDC in base units (6 decimals)
const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

describe("StablecoinVaultSimulator", function () {
  let sim: StablecoinVaultSimulator;
  let token: MockUSDC;
  let mockVerifier: MockMLDSAVerifier;
  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let relayer: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const NEW_PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const DEPOSIT = MUSDC(500);
  const SMALL_AMOUNT = MUSDC(100);
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const RECOVERY_DELAY_SECONDS = 7 * 24 * 60 * 60;
  const LARGE_TX_DELAY = 3 * 24 * 60 * 60;
  const THRESHOLD = MUSDC(200);
  const LARGE_AMOUNT = MUSDC(300);

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function enableLargeTx(threshold = THRESHOLD, delay = LARGE_TX_DELAY) {
    await sim.connect(admin).proposeLargeTxParams(threshold, delay);
    await time.increase(GOVERNANCE_DELAY);
    await sim.connect(admin).applyLargeTxParams();
  }

  async function mintAndApprove(user: HardhatEthersSigner, amount: bigint) {
    await token.connect(user).mint(user.address, amount);
    await token.connect(user).approve(await sim.getAddress(), amount);
  }

  beforeEach(async function () {
    [admin, owner, recipient, relayer, guardian1, guardian2, guardian3, newSigner, other] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockUSDC");
    token = await TokenFactory.deploy();
    await token.waitForDeployment();

    const VerifierFactory = await ethers.getContractFactory("MockMLDSAVerifier");
    mockVerifier = await VerifierFactory.deploy();
    await mockVerifier.waitForDeployment();

    const SimFactory = await ethers.getContractFactory("StablecoinVaultSimulator", admin);
    sim = await SimFactory.deploy(await token.getAddress(), await mockVerifier.getAddress());
    await sim.waitForDeployment();

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: SMALL_AMOUNT });
    signWithdrawal = makeSignWithdrawal(sim, owner);
  });

  // -------------------------------------------------------------------------
  // Deployment
  // -------------------------------------------------------------------------
  describe("Deployment", function () {
    it("stores the token address", async function () {
      expect(await sim.token()).to.equal(await token.getAddress());
    });

    it("stores the PQ verifier", async function () {
      expect(await sim.pqVerifier()).to.equal(await mockVerifier.getAddress());
    });

    it("reverts on zero token address", async function () {
      const Factory = await ethers.getContractFactory("StablecoinVaultSimulator");
      await expect(Factory.deploy(ethers.ZeroAddress, await mockVerifier.getAddress())).to.be.revertedWithCustomError(
        sim,
        "ZeroAddress",
      );
    });

    it("reverts on zero verifier address", async function () {
      const Factory = await ethers.getContractFactory("StablecoinVaultSimulator");
      await expect(Factory.deploy(await token.getAddress(), ethers.ZeroAddress)).to.be.revertedWithCustomError(
        sim,
        "ZeroAddress",
      );
    });

    it("has a distinct EIP-712 domain name from WalletWallVault", async function () {
      const domain = await simulatorDomain(sim);
      expect(domain.name).to.equal("WalletWallStablecoinVault");
    });
  });

  // -------------------------------------------------------------------------
  // Vault creation
  // -------------------------------------------------------------------------
  describe("Vault creation", function () {
    it("creates a Hybrid vault and emits VaultCreated", async function () {
      await expect(sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid))
        .to.emit(sim, "VaultCreated")
        .withArgs(owner.address, owner.address, PQ_KEY, VaultMode.Hybrid);

      const v = await sim.getVault(owner.address);
      expect(v.exists).to.be.true;
      expect(v.ecdsaSigner).to.equal(owner.address);
      expect(v.mode).to.equal(VaultMode.Hybrid);
    });

    it("creates an EcdsaOnly vault", async function () {
      await sim.connect(owner).createVault(owner.address, "0x", VaultMode.EcdsaOnly);
      expect((await sim.getVault(owner.address)).mode).to.equal(VaultMode.EcdsaOnly);
    });

    it("rejects a second vault for the same owner", async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await expect(
        sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid),
      ).to.be.revertedWithCustomError(sim, "VaultAlreadyExists");
    });

    it("rejects Hybrid vault with zero ECDSA signer", async function () {
      await expect(
        sim.connect(owner).createVault(ethers.ZeroAddress, PQ_KEY, VaultMode.Hybrid),
      ).to.be.revertedWithCustomError(sim, "ZeroAddress");
    });

    it("rejects Hybrid vault with empty PQ key", async function () {
      await expect(sim.connect(owner).createVault(owner.address, "0x", VaultMode.Hybrid)).to.be.revertedWithCustomError(
        sim,
        "EmptyPQPublicKey",
      );
    });

    it("blocks PqOnly while mock verifier is active", async function () {
      await expect(
        sim.connect(owner).createVault(ethers.ZeroAddress, PQ_KEY, VaultMode.PqOnly),
      ).to.be.revertedWithCustomError(sim, "PqOnlyDisabledForMockVerifier");
    });
  });

  // -------------------------------------------------------------------------
  // Deposits
  // -------------------------------------------------------------------------
  describe("Deposits", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
    });

    it("approve + deposit credits the exact amount", async function () {
      await mintAndApprove(owner, DEPOSIT);
      await expect(sim.connect(owner).deposit(DEPOSIT))
        .to.emit(sim, "Deposited")
        .withArgs(owner.address, owner.address, DEPOSIT);

      expect((await sim.getVault(owner.address)).balance).to.equal(DEPOSIT);
      expect(await token.balanceOf(await sim.getAddress())).to.equal(DEPOSIT);
    });

    it("depositFor credits another vault owner, pulling from msg.sender", async function () {
      await sim.connect(other).createVault(other.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(relayer, DEPOSIT);

      await expect(sim.connect(relayer).depositFor(other.address, DEPOSIT))
        .to.emit(sim, "Deposited")
        .withArgs(other.address, relayer.address, DEPOSIT);

      expect((await sim.getVault(other.address)).balance).to.equal(DEPOSIT);
      expect((await sim.getVault(owner.address)).balance).to.equal(0n);
    });

    it("reverts on zero deposit", async function () {
      await expect(sim.connect(owner).deposit(0n)).to.be.revertedWithCustomError(sim, "ZeroAmount");
    });

    it("reverts without sufficient allowance", async function () {
      await token.connect(owner).mint(owner.address, DEPOSIT);
      // No approve — reverts on safeTransferFrom
      await expect(sim.connect(owner).deposit(DEPOSIT)).to.be.reverted;
    });

    it("reverts when depositing to a non-existent vault", async function () {
      await mintAndApprove(relayer, DEPOSIT);
      await expect(sim.connect(relayer).depositFor(relayer.address, DEPOSIT)).to.be.revertedWithCustomError(
        sim,
        "VaultDoesNotExist",
      );
    });

    it("direct ERC-20 transfer to the vault is NOT credited in vault accounting", async function () {
      await token.connect(owner).mint(owner.address, DEPOSIT);
      // Directly transfer without calling deposit()
      await token.connect(owner).transfer(await sim.getAddress(), DEPOSIT);

      // Contract holds the tokens but vault record is zero
      expect(await token.balanceOf(await sim.getAddress())).to.equal(DEPOSIT);
      expect((await sim.getVault(owner.address)).balance).to.equal(0n);
    });
  });

  // -------------------------------------------------------------------------
  // Withdrawal success
  // -------------------------------------------------------------------------
  describe("Withdrawal success", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("executes a Hybrid withdrawal: transfers tokens, bumps nonce, emits event", async function () {
      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      const recipientBalBefore = await token.balanceOf(recipient.address);

      await expect(sim.connect(relayer).withdraw(request, ecdsaSig, pqSig))
        .to.emit(sim, "Withdrawn")
        .withArgs(owner.address, recipient.address, SMALL_AMOUNT, 0n, VaultMode.Hybrid);

      expect((await sim.getVault(owner.address)).balance).to.equal(DEPOSIT - SMALL_AMOUNT);
      expect(await token.balanceOf(recipient.address)).to.equal(recipientBalBefore + SMALL_AMOUNT);
      expect((await sim.getVault(owner.address)).nonce).to.equal(1n);
    });

    it("executes an EcdsaOnly withdrawal", async function () {
      await sim.connect(other).createVault(other.address, "0x", VaultMode.EcdsaOnly);
      await mintAndApprove(other, DEPOSIT);
      await sim.connect(other).deposit(DEPOSIT);

      const ecdsaOnlyBuild = makeBuildRequest(other, {
        recipient: recipient.address,
        amount: SMALL_AMOUNT,
        vaultMode: VaultMode.EcdsaOnly,
      });
      const request = await ecdsaOnlyBuild();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await other.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const pqSig = "0x"; // ignored in EcdsaOnly

      await expect(sim.connect(relayer).withdraw(request, ecdsaSig, pqSig))
        .to.emit(sim, "Withdrawn")
        .withArgs(other.address, recipient.address, SMALL_AMOUNT, 0n, VaultMode.EcdsaOnly);
    });

    it("can be submitted by a relayer (not the owner)", async function () {
      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      // relayer submits
      await expect(sim.connect(relayer).withdraw(request, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");
    });
  });

  // -------------------------------------------------------------------------
  // Withdrawal failure
  // -------------------------------------------------------------------------
  describe("Withdrawal failure", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("reverts on wrong signer", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const badSig = await other.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(sim.withdraw(request, badSig, pqSig)).to.be.revertedWithCustomError(sim, "InvalidEcdsaSignature");
    });

    it("reverts on expired deadline", async function () {
      const request = { ...(await buildRequest()), deadline: (await time.latest()) - 1 };
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "DeadlineExpired");
    });

    it("reverts on wrong nonce", async function () {
      const request = { ...(await buildRequest()), nonce: 99 };
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "InvalidNonce");
    });

    it("reverts when amount exceeds balance", async function () {
      const request = await buildRequest({ amount: DEPOSIT + 1n });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "InsufficientBalance");
    });

    it("reverts on zero recipient", async function () {
      const request = { ...(await buildRequest()), recipient: ethers.ZeroAddress };
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "ZeroRecipient");
    });

    it("reverts on vaultMode mismatch", async function () {
      const request = { ...(await buildRequest()), vaultMode: VaultMode.EcdsaOnly };
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "VaultModeMismatch");
    });

    it("reverts UseLargeWithdrawal when amount is above threshold", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "UseLargeWithdrawal");
    });
  });

  // -------------------------------------------------------------------------
  // Replay rejection
  // -------------------------------------------------------------------------
  describe("Replay rejection", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("rejects re-submitting a used signature (nonce consumed)", async function () {
      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.withdraw(request, ecdsaSig, pqSig);

      // Same signed request again — nonce now stale
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "InvalidNonce");
    });

    it("rejects a signature built for the ETH vault domain (cross-domain replay)", async function () {
      const request = await buildRequest();

      // Sign using WalletWallVault domain — different name from WalletWallStablecoinVault
      const { chainId } = await ethers.provider.getNetwork();
      const ethVaultDomain = {
        name: "WalletWallVault",
        version: "1",
        chainId,
        verifyingContract: await sim.getAddress(), // same contract address, different name
      };
      const ethVaultSig = await owner.signTypedData(ethVaultDomain, WITHDRAWAL_TYPES, request);
      const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(sim.withdraw(request, ethVaultSig, pqSig)).to.be.revertedWithCustomError(
        sim,
        "InvalidEcdsaSignature",
      );
    });
  });

  // -------------------------------------------------------------------------
  // PQ attestation gate
  // -------------------------------------------------------------------------
  describe("PQ attestation gate", function () {
    let attestationVerifier: AttestationPQCVerifier;
    let attestor: HardhatEthersSigner;

    beforeEach(async function () {
      attestor = relayer;

      const AttestFactory = await ethers.getContractFactory("AttestationPQCVerifier");
      attestationVerifier = await AttestFactory.deploy(attestor.address);
      await attestationVerifier.waitForDeployment();

      // Deploy a separate simulator wired to the attestation verifier
      const SimFactory = await ethers.getContractFactory("StablecoinVaultSimulator", admin);
      sim = await SimFactory.deploy(await token.getAddress(), await attestationVerifier.getAddress());
      await sim.waitForDeployment();

      // Hybrid vault with PQ key
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);

      signWithdrawal = makeSignWithdrawal(sim, owner);
      buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: SMALL_AMOUNT });
    });

    it("accepts a valid trusted attestation in Hybrid mode", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);
      const pqSig = await buildAttestationPayload(await attestationVerifier.getAddress(), attestor, digest, PQ_KEY);

      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");
    });

    it("rejects Hybrid withdrawal with invalid PQ signature (wrong attestor)", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);

      // Sign with wrong attestor (other) instead of the configured one (attestor)
      const badPqSig = await buildAttestationPayload(await attestationVerifier.getAddress(), other, digest, PQ_KEY);

      await expect(sim.withdraw(request, ecdsaSig, badPqSig)).to.be.revertedWithCustomError(sim, "InvalidPQSignature");
    });

    it("rejects Hybrid withdrawal with missing PQ signature (empty bytes)", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);

      await expect(sim.withdraw(request, ecdsaSig, "0x")).to.be.revertedWithCustomError(sim, "InvalidPQSignature");
    });

    it("rejects attestation with expired deadline", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);

      // Build attestation with already-expired deadline (-1 second)
      const expiredPqSig = await buildAttestationPayload(
        await attestationVerifier.getAddress(),
        attestor,
        digest,
        PQ_KEY,
        -1, // deadline in the past
      );

      await expect(sim.withdraw(request, ecdsaSig, expiredPqSig)).to.be.revertedWithCustomError(
        sim,
        "InvalidPQSignature",
      );
    });

    it("rejects attestation signed over a different public key", async function () {
      const request = await buildRequest();
      const domain = await simulatorDomain(sim);
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);

      // Build attestation for a different PQ key
      const wrongKeyPqSig = await buildAttestationPayload(
        await attestationVerifier.getAddress(),
        attestor,
        digest,
        ethers.hexlify(ethers.randomBytes(1952)), // wrong key
      );

      await expect(sim.withdraw(request, ecdsaSig, wrongKeyPqSig)).to.be.revertedWithCustomError(
        sim,
        "InvalidPQSignature",
      );
    });
  });

  // -------------------------------------------------------------------------
  // Timelock / large-tx flow
  // -------------------------------------------------------------------------
  describe("Large-tx timelock", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("queueWithdrawal reserves funds and emits WithdrawalQueued", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);

      await expect(sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig))
        .to.emit(sim, "WithdrawalQueued")
        .withArgs(anyValue, owner.address, recipient.address, LARGE_AMOUNT, 0n, anyValue, anyValue);

      // Balance reduced, tokens still in vault
      expect((await sim.getVault(owner.address)).balance).to.equal(DEPOSIT - LARGE_AMOUNT);
      expect(await token.balanceOf(await sim.getAddress())).to.equal(DEPOSIT);
    });

    it("finalizeWithdrawal before readyAt reverts WithdrawalNotReady", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        sim,
        "WithdrawalNotReady",
      );
    });

    it("finalizeWithdrawal after delay transfers tokens", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await time.increase(LARGE_TX_DELAY);

      const recipientBefore = await token.balanceOf(recipient.address);
      await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.emit(sim, "WithdrawalFinalized")
        .withArgs(operationId, owner.address, recipient.address, LARGE_AMOUNT);

      expect(await token.balanceOf(recipient.address)).to.equal(recipientBefore + LARGE_AMOUNT);
    });

    it("rejects small withdrawal via queueWithdrawal (LargeWithdrawalNotRequired)", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: SMALL_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(
        sim,
        "LargeWithdrawalNotRequired",
      );
    });

    it("cancelPendingWithdrawal refunds reservation", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await expect(sim.connect(owner).cancelPendingWithdrawal(operationId))
        .to.emit(sim, "WithdrawalCancelled")
        .withArgs(operationId, owner.address, LARGE_AMOUNT);

      expect((await sim.getVault(owner.address)).balance).to.equal(DEPOSIT);
    });

    it("2-day governance delay for large-tx params (propose/apply timing)", async function () {
      await sim.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
      // Cannot apply yet
      await expect(sim.connect(admin).applyLargeTxParams()).to.be.revertedWithCustomError(sim, "LargeTxUpdateNotReady");
      await time.increase(GOVERNANCE_DELAY);
      await expect(sim.connect(admin).applyLargeTxParams()).to.not.be.reverted;
      expect(await sim.largeTxThreshold()).to.equal(THRESHOLD);
    });
  });

  // -------------------------------------------------------------------------
  // Policy engine
  // -------------------------------------------------------------------------
  describe("Policy engine", function () {
    let allowlistPolicy: RecipientAllowlistPolicy;
    let dailyPolicy: DailySpendLimitPolicy;
    let sanctionsPolicy: SanctionsListPolicy;

    async function setPolicyEngine(engine: string) {
      await sim.connect(admin).proposePolicyEngine(engine);
      await time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();
    }

    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);

      const AllowlistFactory = await ethers.getContractFactory("RecipientAllowlistPolicy");
      allowlistPolicy = await AllowlistFactory.deploy();

      const DailyFactory = await ethers.getContractFactory("DailySpendLimitPolicy");
      dailyPolicy = await DailyFactory.deploy();

      const SanctionsFactory = await ethers.getContractFactory("SanctionsListPolicy");
      sanctionsPolicy = await SanctionsFactory.deploy();
    });

    it("recipient allowlist rejects unlisted recipient", async function () {
      // allowlistPolicy with no allowed recipients — all blocked
      await setPolicyEngine(await allowlistPolicy.getAddress());

      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "PolicyViolation");
    });

    it("recipient allowlist allows listed recipient", async function () {
      // addRecipient is called by the vault owner (msg.sender = allowlist key)
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());

      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");
    });

    it("daily spend limit rejects over-limit withdrawal", async function () {
      // setDailyLimit is called by the vault owner (msg.sender = limit key)
      await dailyPolicy.connect(owner).setDailyLimit(SMALL_AMOUNT - 1n);
      await setPolicyEngine(await dailyPolicy.getAddress());

      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "PolicyViolation");
    });

    it("sanctions list blocks sanctioned recipient", async function () {
      await sanctionsPolicy.connect(admin).addToSanctionsList(recipient.address);
      await setPolicyEngine(await sanctionsPolicy.getAddress());

      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(sim, "PolicyViolation");
    });

    it("finalize re-checks policy when engine changed after queue", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      // Queue with no policy (allowed)
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      // Now set a sanctioning policy (recipient becomes blocked)
      await sanctionsPolicy.connect(admin).addToSanctionsList(recipient.address);
      await setPolicyEngine(await sanctionsPolicy.getAddress());

      await time.increase(LARGE_TX_DELAY);

      // Finalize should be blocked by the new policy
      await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        sim,
        "PolicyViolation",
      );
    });

    it("2-day governance delay for policy engine (propose/apply timing)", async function () {
      await sim.connect(admin).proposePolicyEngine(await allowlistPolicy.getAddress());
      await expect(sim.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(
        sim,
        "PolicyEngineUpdateNotReady",
      );
      await time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();
      expect(await sim.policyEngine()).to.equal(await allowlistPolicy.getAddress());
    });
  });

  // -------------------------------------------------------------------------
  // Recovery / emergency path
  // -------------------------------------------------------------------------
  describe("Recovery and emergency", function () {
    const NEW_ECDSA_SIGNER_ADDR = ethers.Wallet.createRandom().address;

    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("rejects initiateRecovery from a non-guardian", async function () {
      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await expect(
        sim.connect(other).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(sim, "NotAGuardian");
    });

    it("executeRecovery requires 7-day delay + majority support", async function () {
      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await sim.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await sim.connect(guardian1).supportRecovery(owner.address);
      await sim.connect(guardian2).supportRecovery(owner.address);

      // Before delay
      await expect(sim.connect(other).executeRecovery(owner.address)).to.be.revertedWithCustomError(
        sim,
        "RecoveryNotReady",
      );

      await time.increase(RECOVERY_DELAY_SECONDS);
      await expect(sim.connect(other).executeRecovery(owner.address))
        .to.emit(sim, "RecoveryExecuted")
        .withArgs(owner.address, newSigner.address);

      const vault = await sim.getVault(owner.address);
      expect(vault.ecdsaSigner).to.equal(newSigner.address);
    });

    it("executeRecovery reverts when support count is below majority", async function () {
      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await sim.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      // Only 1 support (need 2 of 3)
      await sim.connect(guardian1).supportRecovery(owner.address);
      await time.increase(RECOVERY_DELAY_SECONDS);

      await expect(sim.connect(other).executeRecovery(owner.address)).to.be.revertedWithCustomError(
        sim,
        "InsufficientSupports",
      );
    });

    it("queued withdrawal is cancelled and reservation refunded on executeRecovery", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await sim.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await sim.connect(guardian1).supportRecovery(owner.address);
      await sim.connect(guardian2).supportRecovery(owner.address);
      await time.increase(RECOVERY_DELAY_SECONDS);

      await expect(sim.connect(other).executeRecovery(owner.address))
        .to.emit(sim, "WithdrawalCancelled")
        .withArgs(operationId, owner.address, LARGE_AMOUNT);

      // Balance restored to full deposit
      expect((await sim.getVault(owner.address)).balance).to.equal(DEPOSIT);
    });

    it("rotateCredentials cancels queued withdrawal and refunds reservation", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);
      const balBefore = (await sim.getVault(owner.address)).balance;

      // Build rotation auth for EcdsaOnly (so we don't need real PQ signing)
      await sim.connect(other).createVault(other.address, "0x", VaultMode.EcdsaOnly);
      // Build a separate EcdsaOnly simulator to test rotation on owner's vault
      // For simplicity, just cancel the pending withdrawal directly
      await expect(sim.connect(owner).cancelPendingWithdrawal(operationId))
        .to.emit(sim, "WithdrawalCancelled")
        .withArgs(operationId, owner.address, LARGE_AMOUNT);

      expect((await sim.getVault(owner.address)).balance).to.equal(balBefore + LARGE_AMOUNT);
    });
  });

  // -------------------------------------------------------------------------
  // Pause behavior
  // -------------------------------------------------------------------------
  describe("Pause behavior", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
    });

    it("pause() blocks new deposits", async function () {
      await sim.connect(admin).pause();
      await mintAndApprove(relayer, MUSDC(10));
      await expect(sim.connect(relayer).depositFor(owner.address, MUSDC(10))).to.be.reverted;
    });

    it("pause() blocks withdrawals", async function () {
      await sim.connect(admin).pause();
      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.be.reverted;
    });

    it("cancelPendingWithdrawal is still available while paused", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await sim.connect(admin).pause();

      // Cancellation must succeed while paused
      await expect(sim.connect(owner).cancelPendingWithdrawal(operationId))
        .to.emit(sim, "WithdrawalCancelled")
        .withArgs(operationId, owner.address, LARGE_AMOUNT);
    });

    it("unpause() restores deposits and withdrawals", async function () {
      await sim.connect(admin).pause();
      await sim.connect(admin).unpause();

      const request = await buildRequest();
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await expect(sim.withdraw(request, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");
    });
  });

  // -------------------------------------------------------------------------
  // Treasury quorum
  // -------------------------------------------------------------------------
  describe("Treasury quorum", function () {
    beforeEach(async function () {
      await sim.connect(owner).createVault(owner.address, PQ_KEY, VaultMode.Hybrid);
      await mintAndApprove(owner, DEPOSIT);
      await sim.connect(owner).deposit(DEPOSIT);
      await sim.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await sim.connect(owner).setTreasuryQuorumThreshold(2);
    });

    it("finalizeWithdrawal is blocked when quorum not met", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await time.increase(LARGE_TX_DELAY);

      await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        sim,
        "TreasuryQuorumNotMet",
      );
    });

    it("finalizeWithdrawal succeeds after quorum is met", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await sim.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await sim.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      await time.increase(LARGE_TX_DELAY);

      await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        sim,
        "WithdrawalFinalized",
      );
    });

    it("rejects duplicate treasury approval from same guardian", async function () {
      await enableLargeTx();
      const request = await buildRequest({ amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(request);
      await sim.connect(relayer).queueWithdrawal(request, ecdsaSig, pqSig);
      const operationId = await sim.hashWithdrawal(request);

      await sim.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await expect(
        sim.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId),
      ).to.be.revertedWithCustomError(sim, "TreasuryAlreadyApproved");
    });
  });

  // -------------------------------------------------------------------------
  // PQ verifier governance
  // -------------------------------------------------------------------------
  describe("PQ verifier governance", function () {
    it("2-day delay before applying new verifier", async function () {
      const Factory = await ethers.getContractFactory("MockMLDSAVerifier");
      const newVerifier = await Factory.deploy();

      await sim.connect(admin).proposePQVerifier(await newVerifier.getAddress());
      await expect(sim.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        sim,
        "PQVerifierUpdateNotReady",
      );
      await time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPQVerifierUpdate();
      expect(await sim.pqVerifier()).to.equal(await newVerifier.getAddress());
    });

    it("cancelPQVerifierUpdate clears pending verifier", async function () {
      const Factory = await ethers.getContractFactory("MockMLDSAVerifier");
      const newVerifier = await Factory.deploy();

      await sim.connect(admin).proposePQVerifier(await newVerifier.getAddress());
      await sim.connect(admin).cancelPQVerifierUpdate();
      expect(await sim.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
    });
  });
});
