import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import {
  WalletWallVault,
  MockMLDSAVerifier,
  DailySpendLimitPolicy,
  RecipientAllowlistPolicy,
} from "../typechain-types";
import { makeSignWithdrawal, makeBuildRequest } from "./helpers/vaultHelpers";

describe("Policy Engine", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let dailyPolicy: DailySpendLimitPolicy;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let owner: SignerWithAddress;
  let recipient: SignerWithAddress;
  let other: SignerWithAddress;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function withdraw(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    const request = await buildRequest(overrides);
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    return vault.withdraw(request, ecdsaSig, pqSig);
  }

  async function setPolicyEngine(engineAddress: string) {
    await vault.proposePolicyEngine(engineAddress);
    await time.increase(GOVERNANCE_DELAY);
    await vault.applyPolicyEngine();
  }

  beforeEach(async function () {
    [owner, recipient, other] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const DailyPolicy = await ethers.getContractFactory("DailySpendLimitPolicy");
    dailyPolicy = await DailyPolicy.deploy();

    const AllowlistPolicy = await ethers.getContractFactory("RecipientAllowlistPolicy");
    allowlistPolicy = await AllowlistPolicy.deploy();

    buildRequest = makeBuildRequest(owner, {
      recipient: recipient.address,
      amount: ethers.parseEther("0.5"),
    });
    signWithdrawal = makeSignWithdrawal(vault, owner);

    await vault.createVault(owner.address, PQ_KEY, 2);
    await vault.deposit({ value: ethers.parseEther("5") });
  });

  describe("Governance", function () {
    it("no policy by default — withdrawals pass through", async function () {
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("proposePolicyEngine reverts before delay", async function () {
      await vault.proposePolicyEngine(await dailyPolicy.getAddress());
      await expect(vault.applyPolicyEngine()).to.be.revertedWithCustomError(vault, "PolicyEngineUpdateNotReady");
    });

    it("cancelPolicyEngine clears pending proposal", async function () {
      await vault.proposePolicyEngine(await dailyPolicy.getAddress());
      await vault.cancelPolicyEngine();
      await expect(vault.applyPolicyEngine()).to.be.revertedWithCustomError(vault, "NoPendingPolicyEngine");
    });

    it("applyPolicyEngine sets the engine after delay and emits event", async function () {
      const addr = await dailyPolicy.getAddress();
      await vault.proposePolicyEngine(addr);
      await time.increase(GOVERNANCE_DELAY);
      await expect(vault.applyPolicyEngine()).to.emit(vault, "PolicyEngineUpdated").withArgs(ethers.ZeroAddress, addr);
      expect(await vault.policyEngine()).to.equal(addr);
    });

    it("proposePolicyEngine(address(0)) disables the engine", async function () {
      await setPolicyEngine(await dailyPolicy.getAddress());
      await setPolicyEngine(ethers.ZeroAddress);
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("non-owner cannot propose or apply", async function () {
      await expect(
        vault.connect(other).proposePolicyEngine(await dailyPolicy.getAddress()),
      ).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
    });
  });

  describe("DailySpendLimitPolicy", function () {
    beforeEach(async function () {
      await setPolicyEngine(await dailyPolicy.getAddress());
    });

    it("no limit set (0) — all withdrawals pass", async function () {
      await expect(withdraw({ amount: ethers.parseEther("4") })).to.emit(vault, "Withdrawn");
    });

    it("within limit — withdrawal succeeds", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await expect(withdraw({ amount: ethers.parseEther("0.5") })).to.emit(vault, "Withdrawn");
    });

    it("over limit — withdrawal reverts with PolicyViolation", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await expect(withdraw({ amount: ethers.parseEther("1.5") }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("cumulative spend tracked across withdrawals in same window", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await withdraw({ amount: ethers.parseEther("0.6") });
      await expect(withdraw({ amount: ethers.parseEther("0.5"), nonce: 1 }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("window resets after 24h — full limit available again", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await withdraw({ amount: ethers.parseEther("0.9") });

      await time.increase(24 * 60 * 60);

      await expect(withdraw({ amount: ethers.parseEther("0.9"), nonce: 1 })).to.emit(vault, "Withdrawn");
    });

    it("remainingAllowance reflects spend correctly", async function () {
      const limit = ethers.parseEther("1");
      await dailyPolicy.connect(owner).setDailyLimit(limit);
      const spent = ethers.parseEther("0.4");
      await withdraw({ amount: spent });

      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(limit - spent);
    });

    it("remainingAllowance returns max uint256 when no limit set", async function () {
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(ethers.MaxUint256);
    });

    it("different vault owners have independent limits", async function () {
      const otherVaultOwner = other;
      await vault.connect(otherVaultOwner).createVault(otherVaultOwner.address, PQ_KEY, 2);

      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("0.3"));

      await expect(withdraw({ amount: ethers.parseEther("0.5") })).to.be.revertedWithCustomError(
        vault,
        "PolicyViolation",
      );

      expect(await dailyPolicy.remainingAllowance(otherVaultOwner.address)).to.equal(ethers.MaxUint256);
    });
  });

  describe("RecipientAllowlistPolicy", function () {
    beforeEach(async function () {
      await setPolicyEngine(await allowlistPolicy.getAddress());
    });

    it("empty allowlist blocks all recipients", async function () {
      await expect(withdraw())
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("allowlisted recipient passes", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("non-allowlisted recipient is blocked", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await expect(withdraw({ recipient: other.address }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("removing a recipient re-blocks them", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      await expect(withdraw()).to.be.revertedWithCustomError(vault, "PolicyViolation");
    });

    it("address(0) in allowlist disables the restriction entirely", async function () {
      await allowlistPolicy.connect(owner).addRecipient(ethers.ZeroAddress);
      await expect(withdraw({ recipient: other.address })).to.emit(vault, "Withdrawn");
    });

    it("different vault owners have independent allowlists", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);

      const otherOwner = other;
      await vault.connect(otherOwner).createVault(otherOwner.address, PQ_KEY, 2);
      expect(await allowlistPolicy.allowlist(otherOwner.address, recipient.address)).to.be.false;
    });
  });
});
