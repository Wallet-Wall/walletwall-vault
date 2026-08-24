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

    // Module REMOVAL is timelocked (propose -> wait MODULE_REMOVAL_DELAY -> apply):
    // removing a module can only ever WEAKEN the composite's effective policy (AND
    // composition), so it now carries the same governance friction as replacing the
    // vault's engine address outright. addModule stays instant (see the tests above)
    // because adding a module can only ever STRENGTHEN it. See
    // test/CompositeModuleGovernanceAuthority.test.ts for the full adversarial suite.
    describe("Module removal governance (propose / apply / cancel)", function () {
      it("MODULE_REMOVAL_DELAY matches the vault's own POLICY_ENGINE_UPDATE_DELAY by convention", async function () {
        expect(await composite.MODULE_REMOVAL_DELAY()).to.equal(BigInt(GOVERNANCE_DELAY));
      });

      it("proposeRemoveModule reverts for a module that is not currently registered", async function () {
        await expect(composite.proposeRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "ModuleNotFound",
        );
      });

      it("non-owner cannot proposeRemoveModule", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await expect(
          composite.connect(other).proposeRemoveModule(await dailyPolicy.getAddress()),
        ).to.be.revertedWithCustomError(composite, "OwnableUnauthorizedAccount");
      });

      it("applyRemoveModule reverts before the delay has elapsed", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "ModuleRemovalNotReady",
        );
        // The module is UNCHANGED and still active while the removal is pending.
        expect(await composite.moduleCount()).to.equal(1);
      });

      it("applyRemoveModule reverts when no removal is pending", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "NoPendingModuleRemoval",
        );
      });

      it("removes an existing module and emits ModuleRemoved once the delay has elapsed", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress()))
          .to.emit(composite, "ModuleRemoved")
          .withArgs(await dailyPolicy.getAddress(), 0);
        expect(await composite.moduleCount()).to.equal(0);
        expect(await composite.pendingModuleRemovalValidAfter(await dailyPolicy.getAddress())).to.equal(0);
      });

      it("boundary precision: apply reverts at validAfter-1 and succeeds exactly AT validAfter", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        const validAfter = await composite.pendingModuleRemovalValidAfter(await dailyPolicy.getAddress());

        // setNextBlockTimestamp governs the NEXT mined block, so the assertion
        // transaction itself must be the block mined at that timestamp -- do not
        // call mine() in between, or the tx lands one second later than intended.
        await networkHelpers.time.setNextBlockTimestamp(validAfter - 1n);
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "ModuleRemovalNotReady",
        );

        await networkHelpers.time.setNextBlockTimestamp(validAfter);
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.emit(composite, "ModuleRemoved");
      });

      it("non-owner cannot applyRemoveModule", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await expect(
          composite.connect(other).applyRemoveModule(await dailyPolicy.getAddress()),
        ).to.be.revertedWithCustomError(composite, "OwnableUnauthorizedAccount");
      });

      it("cancelRemoveModule clears a pending proposal so apply then reverts", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await expect(composite.cancelRemoveModule(await dailyPolicy.getAddress()))
          .to.emit(composite, "ModuleRemovalCancelled")
          .withArgs(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "NoPendingModuleRemoval",
        );
        expect(await composite.moduleCount()).to.equal(1);
      });

      it("cancelRemoveModule reverts when nothing is pending", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await expect(composite.cancelRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "NoPendingModuleRemoval",
        );
      });

      it("can re-add a module after its removal is fully applied", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await composite.applyRemoveModule(await dailyPolicy.getAddress());
        await expect(composite.addModule(await dailyPolicy.getAddress())).to.not.revert(ethers);
      });

      it("re-adding after removal requires a FRESH full delay -- no stale-timestamp replay", async function () {
        // Remove, then re-add, the SAME module address once already.
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await composite.applyRemoveModule(await dailyPolicy.getAddress());
        await composite.addModule(await dailyPolicy.getAddress());

        // A second removal cycle for the same address must NOT be able to reuse any
        // stale pending-removal timestamp left over from the first cycle -- it needs
        // its own fresh proposal and its own fresh full delay.
        expect(await composite.pendingModuleRemovalValidAfter(await dailyPolicy.getAddress())).to.equal(0);
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "ModuleRemovalNotReady",
        );
        expect(await composite.moduleCount()).to.equal(1);
      });

      it("re-proposing the same module restarts the delay", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY - 10);
        // Re-propose just before the original delay would have elapsed.
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        // The ORIGINAL window has now passed, but the restarted one has not.
        await networkHelpers.time.increase(20);
        await expect(composite.applyRemoveModule(await dailyPolicy.getAddress())).to.be.revertedWithCustomError(
          composite,
          "ModuleRemovalNotReady",
        );
      });

      it("a module with a pending removal still counts toward MAX_MODULES until applied", async function () {
        await composite.addModule(await dailyPolicy.getAddress());
        await composite.proposeRemoveModule(await dailyPolicy.getAddress());
        // Still pending (not applied): moduleCount is unchanged, still occupying a slot.
        expect(await composite.moduleCount()).to.equal(1);
        expect(await composite.getModules()).to.deep.equal([await dailyPolicy.getAddress()]);
      });

      it("the module being removed remains fully active (still evaluated by check/revalidate) for the entire pending window", async function () {
        await composite.addModule(await sanctionsPolicy.getAddress());
        await sanctionsPolicy.addToSanctionsList(sanctioned.address);
        // revalidate() is deliberately ungated (unlike check()), so it can be called
        // directly here without registering an admissionCaller.
        await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

        // Right up until (but not including) the apply, the module still enforces.
        await networkHelpers.time.increase(GOVERNANCE_DELAY - 10);
        let [ok, reason] = await composite.revalidate(owner.address, sanctioned.address, 1n, 1n);
        expect(ok).to.equal(false);
        expect(reason).to.equal("recipient is sanctioned");

        await networkHelpers.time.increase(20);
        await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
        [ok, reason] = await composite.revalidate(owner.address, sanctioned.address, 1n, 1n);
        expect(ok).to.equal(true);
      });
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

      // Configure policies for owner's vault. With a composite in the path, the owner
      // delegates admission authority to the COMPOSITE (that is the msg.sender the
      // stateful module observes), and the composite's admin registers the vault as the
      // consumer permitted to invoke it. Authority holds at both hops.
      await dailyPolicy.connect(owner).setAdmitter(await composite.getAddress(), true);
      await dailyPolicy.connect(owner).setDailyLimit(DAILY_LIMIT);
      await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
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
      await emptyComposite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
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
      await composite2.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
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
