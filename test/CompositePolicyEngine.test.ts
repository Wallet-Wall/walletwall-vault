import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { networkHelpers } from "./helpers/connection";
import {
  WalletWallVault,
  MockMLDSAVerifier,
  CompositePolicyEngine,
  DailySpendLimitPolicy,
  RecipientAllowlistPolicy,
  SanctionsListPolicy,
} from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

describe("CompositePolicyEngine", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let composite: CompositePolicyEngine;
  let dailyPolicy: DailySpendLimitPolicy;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let sanctionsPolicy: SanctionsListPolicy;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let sanctioned: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const LARGE_TX_DELAY = 1 * 24 * 60 * 60;
  const DEPOSIT = ethers.parseEther("10");
  const THRESHOLD = ethers.parseEther("3");
  const LARGE_AMOUNT = ethers.parseEther("4");
  const SMALL_AMOUNT = ethers.parseEther("0.5");
  const DAILY_LIMIT = ethers.parseEther("2");

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function setPolicyEngine(engine: string) {
    await vault.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();
  }

  async function enableLargeTx() {
    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
  }

  async function withdraw(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    const req = await buildRequest(overrides);
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    return vault.connect(other).withdraw(req, ecdsaSig, pqSig);
  }

  beforeEach(async function () {
    [admin, owner, recipient, sanctioned, other] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier", admin);
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());

    const Composite = await ethers.getContractFactory("CompositePolicyEngine", admin);
    composite = await Composite.deploy();

    const DailyPolicy = await ethers.getContractFactory("DailySpendLimitPolicy", admin);
    dailyPolicy = await DailyPolicy.deploy();

    const AllowlistPolicy = await ethers.getContractFactory("RecipientAllowlistPolicy", admin);
    allowlistPolicy = await AllowlistPolicy.deploy();

    const SanctionsPolicy = await ethers.getContractFactory("SanctionsListPolicy", admin);
    sanctionsPolicy = await SanctionsPolicy.deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: SMALL_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // ---------------------------------------------------------------------------
  // Module management
  // ---------------------------------------------------------------------------

  describe("Module management", function () {
    it("starts with an empty module list", async function () {
      expect(await composite.moduleCount()).to.equal(0);
      expect(await composite.getModules()).to.deep.equal([]);
    });

    it("addModule registers a deployed contract", async function () {
      await expect(composite.addModule(await dailyPolicy.getAddress()))
        .to.emit(composite, "ModuleAdded")
        .withArgs(await dailyPolicy.getAddress(), 1);
      expect(await composite.moduleCount()).to.equal(1);
    });

    it("addModule rejects zero address", async function () {
      await expect(composite.addModule(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        composite,
        "ZeroModuleAddress",
      );
    });

    it("addModule rejects address with no deployed code (EOA)", async function () {
      await expect(composite.addModule(other.address)).to.be.revertedWithCustomError(composite, "NoCode");
    });

    it("addModule rejects address with no deployed code (random)", async function () {
      const noCode = ethers.Wallet.createRandom().address;
      await expect(composite.addModule(noCode)).to.be.revertedWithCustomError(composite, "NoCode");
    });

    it("addModule rejects duplicate module", async function () {
      await composite.addModule(await dailyPolicy.getAddress());
      await expect(composite.addModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "DuplicateModule",
      );
    });

    it("non-owner cannot addModule", async function () {
      await expect(composite.connect(other).addModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "OwnableUnauthorizedAccount",
      );
    });

    it("removeModule removes an existing module and emits event", async function () {
      await composite.addModule(await dailyPolicy.getAddress());
      await expect(composite.removeModule(await dailyPolicy.getAddress()))
        .to.emit(composite, "ModuleRemoved")
        .withArgs(await dailyPolicy.getAddress(), 0);
      expect(await composite.moduleCount()).to.equal(0);
    });

    it("removeModule reverts for unknown module", async function () {
      await expect(composite.removeModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleNotFound",
      );
    });

    it("can re-add a module after removal", async function () {
      await composite.addModule(await dailyPolicy.getAddress());
      await composite.removeModule(await dailyPolicy.getAddress());
      await expect(composite.addModule(await dailyPolicy.getAddress())).to.not.revert(ethers);
    });

    it("rejects adding the composite itself as a module (direct self-recursion)", async function () {
      await expect(composite.addModule(await composite.getAddress())).to.be.revertedWithCustomError(
        composite,
        "SelfModule",
      );
    });

    it("enforces the MAX_MODULES hard cap", async function () {
      const max = await composite.MAX_MODULES();
      expect(max).to.equal(16n);
      const Filler = await ethers.getContractFactory("LegacyCheckOnlyPolicyMock", admin);
      for (let i = 0n; i < max; i++) {
        const filler = await Filler.deploy();
        await composite.addModule(await filler.getAddress());
      }
      expect(await composite.moduleCount()).to.equal(max);
      const oneTooMany = await Filler.deploy();
      await expect(composite.addModule(await oneTooMany.getAddress()))
        .to.be.revertedWithCustomError(composite, "TooManyModules")
        .withArgs(max, max);
    });
  });

  // ---------------------------------------------------------------------------
  // Composite check — all three policies simultaneously
  // ---------------------------------------------------------------------------

  describe("Composite policy enforcement", function () {
    beforeEach(async function () {
      // Wire up all three modules
      await composite.addModule(await dailyPolicy.getAddress());
      await composite.addModule(await allowlistPolicy.getAddress());
      await composite.addModule(await sanctionsPolicy.getAddress());

      // Configure policies for owner's vault
      await dailyPolicy.connect(owner).setDailyLimit(DAILY_LIMIT);
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      // No sanctioned addresses by default

      // Wire composite into vault
      await setPolicyEngine(await composite.getAddress());
    });

    it("daily limit + allowlist + sanctions all pass for a valid withdrawal", async function () {
      await expect(withdraw({ amount: ethers.parseEther("1") })).to.emit(vault, "Withdrawn");
    });

    it("sanctioned recipient is blocked even though allowlisted", async function () {
      await allowlistPolicy.connect(owner).addRecipient(sanctioned.address);
      await sanctionsPolicy.addToSanctionsList(sanctioned.address);
      await expect(withdraw({ recipient: sanctioned.address }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("non-allowlisted recipient is blocked", async function () {
      // recipient is allowlisted; other is not
      await expect(withdraw({ recipient: other.address }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("daily limit exceeded is blocked", async function () {
      await expect(withdraw({ amount: ethers.parseEther("2.5") }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("sanctions check blocks before allowlist check within the same module set", async function () {
      // With modules added in order [daily, allowlist, sanctions], sanctions runs last.
      // Sanction recipient AND remove from allowlist — first failure wins.
      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      // allowlist check runs first and blocks with its own message
      await expect(withdraw())
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("empty composite module list is permissive", async function () {
      // Deploy a fresh composite with no modules
      const Composite = await ethers.getContractFactory("CompositePolicyEngine", admin);
      const emptyComposite = await Composite.deploy();
      await setPolicyEngine(await emptyComposite.getAddress());
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });
  });

  // ---------------------------------------------------------------------------
  // Finalization policy revalidation
  // ---------------------------------------------------------------------------

  describe("Finalization policy revalidation", function () {
    it("a denying engine installed after queueing blocks finalization", async function () {
      // Enable large-tx timelock so we can queue
      await enableLargeTx();

      // Queue withdrawal with NO policy engine active
      const buildLarge = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
      const req = await buildLarge();
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
      const operationId = await vault.hashWithdrawal(req);

      // Admin sets a new composite engine that sanctions the recipient
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress()); // 2-day governance delay already consumed
      await sanctionsPolicy.addToSanctionsList(recipient.address);

      // Pass the large-tx timelock
      await networkHelpers.time.increase(LARGE_TX_DELAY);

      // Finalization revalidates the CURRENT engine (queued with none), which
      // rejects the recipient — so settlement is blocked.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("finalization revalidates an unchanged engine against current state and passes while it still permits", async function () {
      // Composite with an allowlist module that admits the recipient; engine unchanged
      // between queue and finalize. Finalization re-validates the composite (read-only
      // fan-out over the CURRENT module set); since the allowlist still permits, the
      // withdrawal settles. The restrictive-drift counterparts (module added, module
      // state turned denying) live in test/PolicyFinalizationAuthority.test.ts P2.
      const Composite2 = await ethers.getContractFactory("CompositePolicyEngine", admin);
      const composite2 = await Composite2.deploy();
      await composite2.addModule(await allowlistPolicy.getAddress());
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await composite2.getAddress());

      await enableLargeTx();

      const buildLarge2 = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
      const req2 = await buildLarge2();
      const { ecdsaSig, pqSig } = await signWithdrawal(req2);
      await vault.connect(other).queueWithdrawal(req2, ecdsaSig, pqSig);
      const operationId2 = await vault.hashWithdrawal(req2);

      await networkHelpers.time.increase(LARGE_TX_DELAY);

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId2)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });
});
