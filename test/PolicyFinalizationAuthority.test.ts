import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  WalletWallVault,
  MockMLDSAVerifier,
  CompositePolicyEngine,
  DailySpendLimitPolicy,
  RecipientAllowlistPolicy,
  SanctionsListPolicy,
} from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

/**
 * Adversarial CHARACTERIZATION of the delayed-withdrawal / mutable-policy authority model.
 *
 * These tests do NOT assert a desired architecture. They pin the ACTUAL semantics of
 * `WalletWallVault` on the current branch so the authority model can be reasoned about
 * with evidence rather than from the docstrings.
 *
 * Each assertion tagged `VULNERABILITY` records behavior that the docs claim is prevented
 * but that the code permits. When the authority model is fixed, those assertions are the
 * ones expected to flip (revert instead of succeed); the `CONTROL` assertions prove the
 * underlying policy engines themselves are wired correctly, isolating the defect to the
 * finalization gate rather than the policies.
 *
 * Reference (current code, contracts/WalletWallVault.sol:813-823):
 *
 *     address currentEngine = address(policyEngine);
 *     if (currentEngine != address(0) && currentEngine != pending.policyEngineAtQueue) {
 *         (bool ok, string memory why) = policyEngine.check(...);
 *         if (!ok) revert PolicyViolation(why);
 *     }
 *
 * The re-check fires ONLY when the engine ADDRESS differs from the one captured at queue
 * time. Same-address internal mutation (sanctions add, allowlist remove, composite module
 * add) is therefore never re-consulted at finalization.
 *
 * Contradicted docs:
 *   - docs/Phase_3_Status.md:39 — claims this "prevents stale-policy bypasses
 *     (e.g. recipient added to sanctions list after queuing)". That exact example is P1 below.
 *   - docs/Security_Assumptions.md:261-263 — "re-checks policy only if the active engine
 *     address changed ... This closes stale-engine bypasses". Only engine REPLACEMENT is closed.
 */
describe("Policy finalization authority (adversarial characterization)", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let composite: CompositePolicyEngine;
  let dailyPolicy: DailySpendLimitPolicy;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let sanctionsPolicy: SanctionsListPolicy;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const NEW_PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const LARGE_TX_DELAY = 1 * 24 * 60 * 60;
  const RECOVERY_DELAY = 7 * 24 * 60 * 60;
  const DEPOSIT = ethers.parseEther("20");
  const THRESHOLD = ethers.parseEther("1");
  const LARGE_AMOUNT = ethers.parseEther("2");

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

  // Queues the standard LARGE_AMOUNT withdrawal to `recipient` from `owner`'s vault.
  async function queueLarge(to = recipient.address, amount = LARGE_AMOUNT) {
    const req = await buildRequest({ recipient: to, amount });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
    return { req, operationId: await vault.hashWithdrawal(req) };
  }

  beforeEach(async function () {
    [admin, owner, recipient, other, guardian1, guardian2, guardian3] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    composite = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
    dailyPolicy = await (await ethers.getContractFactory("DailySpendLimitPolicy", admin)).deploy();
    allowlistPolicy = await (await ethers.getContractFactory("RecipientAllowlistPolicy", admin)).deploy();
    sanctionsPolicy = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // =========================================================================
  // P1 — SAME sanctions engine mutates after queue (address unchanged)
  // =========================================================================
  describe("P1 — same-address SanctionsListPolicy mutates after queue", function () {
    it("CONTROL: the immediate-withdrawal path DOES honor the sanctions engine", async function () {
      // Proves the SanctionsListPolicy is correctly wired; only the finalize gate is in question.
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      const req = await buildRequest({ recipient: recipient.address, amount: ethers.parseEther("0.5") });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await expect(vault.connect(other).withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("VULNERABILITY: finalize succeeds for a recipient sanctioned AFTER queue (same engine address)", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();

      // Recipient is clean at queue time → passes the queue-time policy check.
      const { operationId } = await queueLarge();

      // Same engine address; only its internal state mutates.
      const engineAtQueue = (await vault.pendingWithdrawals(owner.address)).policyEngineAtQueue;
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      expect(await sanctionsPolicy.isSanctioned(recipient.address)).to.equal(true);
      expect(await vault.policyEngine()).to.equal(engineAtQueue); // address unchanged

      await networkHelpers.time.increase(LARGE_TX_DELAY);

      // docs/Phase_3_Status.md:39 claims THIS is prevented. It is not.
      // VULNERABILITY: a now-sanctioned recipient is paid out.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P2 — SAME composite engine mutates after queue (module added)
  // =========================================================================
  describe("P2 — same-address CompositePolicyEngine gains a denying module after queue", function () {
    it("VULNERABILITY: finalize succeeds after a denying sanctions module is added to the composite", async function () {
      // Composite permits at queue time (allowlist admits the recipient).
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await composite.addModule(await allowlistPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();
      const engineAtQueue = (await vault.pendingWithdrawals(owner.address)).policyEngineAtQueue;

      // Add a module that denies the recipient; composite ADDRESS is unchanged.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await composite.addModule(await sanctionsPolicy.getAddress());
      expect(await vault.policyEngine()).to.equal(engineAtQueue);

      // CONTROL: the composite now denies on a fresh evaluation.
      const [ok, why] = await composite.check.staticCall(
        owner.address,
        recipient.address,
        LARGE_AMOUNT,
        DEPOSIT,
      );
      expect(ok).to.equal(false);
      expect(why).to.equal("recipient is sanctioned");

      await networkHelpers.time.increase(LARGE_TX_DELAY);

      // VULNERABILITY: composition now denies, but finalize does not re-consult it.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });

    it("VULNERABILITY: finalize succeeds after the permitting module is REMOVED from the composite", async function () {
      // Composite permits at queue time via allowlist; empty composite is permissive too,
      // so removing the module leaves an all-permitting engine — this variant instead
      // removes allowlist and relies on the default-deny of an EMPTY allowlist re-add.
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await composite.addModule(await allowlistPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      // Remove the recipient from the allowlist module (module stays in the composite).
      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      const [ok] = await composite.check.staticCall(owner.address, recipient.address, LARGE_AMOUNT, DEPOSIT);
      expect(ok).to.equal(false); // composite now denies

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P3 — allowlist mutation after queue (address unchanged)
  // =========================================================================
  describe("P3 — same-address RecipientAllowlistPolicy revokes permission after queue", function () {
    it("VULNERABILITY: finalize succeeds after the recipient is removed from the allowlist", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      const [ok] = await allowlistPolicy.check.staticCall(owner.address, recipient.address, LARGE_AMOUNT, DEPOSIT);
      expect(ok).to.equal(false); // policy now denies this recipient

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P4 — DailySpendLimitPolicy statefulness: why "just re-run at finalize" is wrong
  // =========================================================================
  describe("P4 — DailySpendLimitPolicy records spend at queue time (stateful admission)", function () {
    it("check() MUTATES the window at queue time: remaining allowance drops immediately", async function () {
      const LIMIT = ethers.parseEther("10");
      const AMOUNT = ethers.parseEther("3");
      await dailyPolicy.connect(owner).setDailyLimit(LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());
      await enableLargeTx();

      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT);

      await queueLarge(recipient.address, AMOUNT);

      // Spend is recorded at QUEUE time, not finalize — proves admission is stateful.
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - AMOUNT);
    });

    it("a naive re-run of check() at finalize would DOUBLE-COUNT the same withdrawal", async function () {
      const LIMIT = ethers.parseEther("10");
      const AMOUNT = ethers.parseEther("3");
      await dailyPolicy.connect(owner).setDailyLimit(LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());
      await enableLargeTx();

      await queueLarge(recipient.address, AMOUNT);
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - AMOUNT); // 7

      // Simulate what "just re-run policy at finalization" would do: call check() again
      // for the SAME logical withdrawal. It records a SECOND time.
      await dailyPolicy.check(owner.address, recipient.address, AMOUNT, DEPOSIT);

      // The one 3-ETH withdrawal has now consumed 6 ETH of the 10-ETH allowance.
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - AMOUNT - AMOUNT); // 4
    });

    it("a naive re-run can also WRONGLY REJECT an already-authorized withdrawal near the limit", async function () {
      const LIMIT = ethers.parseEther("5");
      const AMOUNT = ethers.parseEther("3");
      await dailyPolicy.connect(owner).setDailyLimit(LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());
      await enableLargeTx();

      await queueLarge(recipient.address, AMOUNT); // records 3 of 5; remaining 2

      // Re-running the same 3-ETH check would see spent(3)+amount(3)=6 > 5 and deny —
      // even though this withdrawal was legitimately admitted. staticCall to avoid mutating.
      const [ok, why] = await dailyPolicy.check.staticCall(owner.address, recipient.address, AMOUNT, DEPOSIT);
      expect(ok).to.equal(false);
      expect(why).to.equal("daily limit exceeded");
    });
  });

  // =========================================================================
  // P5 — engine ADDRESS replacement: the ONE path where re-check fires
  // =========================================================================
  describe("P5 — engine address replacement re-check (documented, working path)", function () {
    it("SAFE: finalize BLOCKS when the engine is replaced by one that denies the recipient", async function () {
      await enableLargeTx();
      // Queue with NO engine → policyEngineAtQueue == address(0).
      const { operationId } = await queueLarge();

      // Replace with a sanctions engine that denies the recipient (address changes 0x0 -> engine).
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(await sanctionsPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("SAFE: finalize SUCCEEDS when the replacement engine permits the recipient", async function () {
      await enableLargeTx();
      const { operationId } = await queueLarge();

      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P6 — engine disabled (set to address(0)) after queue
  // =========================================================================
  describe("P6 — disabling the engine after queue skips the finalize re-check entirely", function () {
    it("VULNERABILITY: disabling the engine (→ address(0)) after queue means NO policy at finalize", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      // Sanction the recipient AND disable the engine. `currentEngine == address(0)` makes the
      // finalize re-check short-circuit before it can observe the address change.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(ethers.ZeroAddress);
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      // VULNERABILITY: a policy applied at queue time, the recipient is now sanctioned,
      // yet finalize applies no policy at all.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P7 — cancellation paths must not retain policy/quorum authority
  // =========================================================================
  describe("P7 — cancellation clears reserved authority", function () {
    it("cancelPendingWithdrawal refunds, clears treasury approvals, and forbids finalize", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();

      const { operationId } = await queueLarge();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(2);

      const balBefore = (await vault.getVault(owner.address)).balance;
      await expect(vault.connect(owner).cancelPendingWithdrawal(operationId)).to.emit(vault, "WithdrawalCancelled");

      // Reservation refunded.
      expect((await vault.getVault(owner.address)).balance).to.equal(balBefore + LARGE_AMOUNT);
      // Treasury authority cleared — the approvals cannot linger for reuse.
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(0);
      expect(await vault.treasuryApprovals(operationId, guardian1.address)).to.equal(false);
      // Cancelled op cannot be finalized.
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(
        vault.connect(owner).finalizeWithdrawal(owner.address, operationId),
      ).to.be.revertedWithCustomError(vault, "NoPendingWithdrawal");
    });

    it("a re-queued withdrawal after cancellation does NOT inherit the old op's guardian approvals", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();

      // Queue op #1 (nonce 0), gather 2 approvals, cancel it.
      const first = await queueLarge();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, first.operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, first.operationId);
      await vault.connect(owner).cancelPendingWithdrawal(first.operationId);

      // Re-queue (nonce is now 1) → different operationId.
      const req2 = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT, nonce: 1 });
      const { ecdsaSig, pqSig } = await signWithdrawal(req2);
      await vault.connect(other).queueWithdrawal(req2, ecdsaSig, pqSig);
      const op2 = await vault.hashWithdrawal(req2);
      expect(op2).to.not.equal(first.operationId);

      // The new op starts with zero approvals; quorum is not met by the old approvals.
      expect(await vault.treasuryApprovalCount(op2)).to.equal(0);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, op2))
        .to.be.revertedWithCustomError(vault, "TreasuryQuorumNotMet")
        .withArgs(2, 0);
    });

    it("executeRecovery cancels a pending withdrawal and refunds its reservation", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await enableLargeTx();

      const { operationId } = await queueLarge();
      const balAfterQueue = (await vault.getVault(owner.address)).balance;

      await vault.connect(guardian1).initiateRecovery(owner.address, other.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(RECOVERY_DELAY);

      await expect(vault.connect(guardian1).executeRecovery(owner.address))
        .to.emit(vault, "WithdrawalCancelled")
        .withArgs(operationId, owner.address, LARGE_AMOUNT);

      // Pending gone, reservation refunded.
      expect((await vault.pendingWithdrawals(owner.address)).exists).to.equal(false);
      expect((await vault.getVault(owner.address)).balance).to.equal(balAfterQueue + LARGE_AMOUNT);
    });
  });
});
