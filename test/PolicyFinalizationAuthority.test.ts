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
 * Regression suite for the delayed-withdrawal / mutable-policy AUTHORITY MODEL.
 *
 * Background: `finalizeWithdrawal` formerly re-checked policy only when the engine
 * ADDRESS changed since queue, so same-address internal mutation (a recipient
 * sanctioned or de-allowlisted after queueing, a denying module added to a
 * composite) was never re-consulted — a stale-policy bypass. These tests began
 * life as characterization of that bug (PR #152); they now pin the FIXED model:
 *
 *   - admission (`check`, may mutate) is split from finalization revalidation
 *     (`revalidate`, view / STATICCALL, never re-books);
 *   - finalization ALWAYS revalidates — no address-drift gate — against the
 *     QUEUE-TIME engine (a sticky floor that survives replacement/disable) AND
 *     the current engine (once, if the same address);
 *   - restrictive drift blocks, permissive drift is honored, and stateful
 *     admission accounting (DailySpendLimitPolicy) is booked exactly once at queue.
 *
 * Contradicted-then-corrected docs: docs/Phase_3_Status.md and
 * docs/Security_Assumptions.md (updated in this PR to describe the new model).
 */
describe("Policy finalization authority (regression)", function () {
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
    // A composite relays admissions only from registered consumers, so wiring one into
    // the vault means registering the vault on it. Idempotent, and a no-op for the
    // single-module engines.
    if (engine === (await composite.getAddress())) {
      await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
    }
    await vault.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();
  }

  /// Delegates admission authority for `owner` to the vault, then arms `limit`.
  async function armDailyLimit(limit: bigint) {
    await dailyPolicy.connect(owner).setAdmitter(await vault.getAddress(), true);
    await dailyPolicy.connect(owner).setDailyLimit(limit);
  }

  async function enableLargeTx(delay = LARGE_TX_DELAY) {
    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, delay);
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
    it("CONTROL: the immediate-withdrawal path honors the sanctions engine", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      const req = await buildRequest({ recipient: recipient.address, amount: ethers.parseEther("0.5") });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await expect(vault.connect(other).withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("finalize REVERTS for a recipient sanctioned AFTER queue (same engine address)", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();

      // Recipient is clean at queue time → passes the queue-time admission check.
      const { operationId } = await queueLarge();

      // Same engine address; only its internal state mutates.
      const engineAtQueue = (await vault.pendingWithdrawals(owner.address)).policyEngineAtQueue;
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      expect(await vault.policyEngine()).to.equal(engineAtQueue); // address unchanged

      await networkHelpers.time.increase(LARGE_TX_DELAY);

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Fail-closed but not fund-trapping: the owner can cancel and recover the reservation.
      const balBefore = (await vault.getVault(owner.address)).balance;
      await vault.connect(owner).cancelPendingWithdrawal(operationId);
      expect((await vault.getVault(owner.address)).balance).to.equal(balBefore + LARGE_AMOUNT);
    });
  });

  // =========================================================================
  // P2 — SAME composite engine's module set / module state mutates after queue
  // =========================================================================
  describe("P2 — same-address CompositePolicyEngine turns denying after queue", function () {
    it("finalize REVERTS after a denying sanctions module is ADDED to the composite", async function () {
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

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("finalize REVERTS after a retained composite module's internal state turns denying", async function () {
      // The composite KEEPS its allowlist module throughout; only the module's internal
      // state mutates (the recipient's allowlist entry is revoked after queue). Removing
      // the module itself would not deny — an empty composite is permissive — so the
      // mutation under test is module-internal, behind an unchanged composite address.
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await composite.addModule(await allowlistPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      await allowlistPolicy.connect(owner).removeRecipient(recipient.address); // module retained
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("finalize SUCCEEDS when the composite still permits at settlement", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await composite.addModule(await allowlistPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P3 — allowlist revocation after queue (address unchanged)
  // =========================================================================
  describe("P3 — same-address RecipientAllowlistPolicy revokes permission after queue", function () {
    it("finalize REVERTS after the recipient is removed from the allowlist", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("finalize SUCCEEDS when a revoked recipient is re-added before settlement (permissive drift honored)", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      // Revoke, then restore before finalize. Revalidation reflects CURRENT state, so a
      // restriction that no longer holds must not fail the withdrawal.
      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P4 — DailySpendLimitPolicy: booked once at admission, never re-booked
  // =========================================================================
  describe("P4 — DailySpendLimitPolicy settles at admission, not finalization", function () {
    // These two tests use a one-hour large-tx delay so the policy's 24h window does
    // NOT roll between queue and finalize — keeping the allowance figures comparable.
    const SHORT_DELAY = 3600;

    it("spend is booked once at queue and finalization does not book it again", async function () {
      const LIMIT = ethers.parseEther("10");
      const AMOUNT = ethers.parseEther("3");
      await armDailyLimit(LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());
      await enableLargeTx(SHORT_DELAY);

      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT);

      const { operationId } = await queueLarge(recipient.address, AMOUNT);
      // Booked at QUEUE time.
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - AMOUNT);

      await networkHelpers.time.increase(SHORT_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );

      // Finalization did NOT re-book: allowance is unchanged by settlement (no double-count).
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - AMOUNT);
    });

    it("a withdrawal admitted exactly at the limit still finalizes (not wrongly rejected)", async function () {
      const LIMIT = ethers.parseEther("3");
      const AMOUNT = ethers.parseEther("3"); // consumes the entire allowance at admission
      await armDailyLimit(LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());
      await enableLargeTx(SHORT_DELAY);

      const { operationId } = await queueLarge(recipient.address, AMOUNT);
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(0n); // fully consumed

      // A naive finalize re-run would see spent(3)+amount(3) > limit(3) and wrongly deny.
      // The split model does not re-run admission, so settlement succeeds.
      await networkHelpers.time.increase(SHORT_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(0n);
    });
  });

  // =========================================================================
  // P5 — engine ADDRESS replacement (sticky queue-time floor + current engine)
  // =========================================================================
  describe("P5 — engine replacement respects both queue-time and current engines", function () {
    it("replacement with a RESTRICTIVE engine blocks (queue had no engine)", async function () {
      await enableLargeTx();
      const { operationId } = await queueLarge(); // policyEngineAtQueue == address(0)

      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(await sanctionsPolicy.getAddress()); // 0x0 -> engine

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("replacement with a PERMISSIVE engine still respects the queue-time engine (sticky floor)", async function () {
      // Queue under a sanctions engine while the recipient is clean (admitted).
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();
      const { operationId } = await queueLarge();

      // The queue-time engine now sanctions the recipient; then governance replaces the
      // active engine with a permissive allowlist that admits the recipient.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      // The current (permissive) engine would pass, but the sticky queue-time engine denies.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("replacement with a permissive engine SUCCEEDS when the queue-time engine also still permits", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();
      const { operationId } = await queueLarge(); // clean under sanctions engine

      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress()); // both engines permit

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });

    it("a denying CURRENT engine blocks even when the (non-zero) queue-time engine permits", async function () {
      // Both engines non-zero and distinct: queue-time allowlist permits, the
      // replacement sanctions engine denies — the current engine's denial must
      // not be discarded just because the queue-time engine passed.
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await setPolicyEngine(await allowlistPolicy.getAddress());
      await enableLargeTx();
      const { operationId } = await queueLarge();

      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(await sanctionsPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("drift onto a STATEFUL current engine settles without booking (revalidate is not admission)", async function () {
      // Queue with NO engine, then install DailySpendLimitPolicy with a limit far
      // BELOW the pending amount as the current engine. The pending withdrawal was
      // never admitted by (or booked into) that engine; its revalidate must neither
      // apply admission semantics (which would wrongly deny) nor book anything.
      await enableLargeTx();
      const { operationId } = await queueLarge(); // policyEngineAtQueue == address(0)

      await armDailyLimit(ethers.parseEther("0.1")); // << LARGE_AMOUNT
      await setPolicyEngine(await dailyPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
      // Nothing was booked into the window by settlement.
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(ethers.parseEther("0.1"));
    });
  });

  // =========================================================================
  // P6 — disabling the current engine (→ address(0)) after queue
  // =========================================================================
  describe("P6 — disabling the current engine does not erase queue-time restrictions", function () {
    it("finalize REVERTS: queue-time engine still denies after the current engine is disabled", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge();

      // Sanction the recipient in the queue-time engine, then disable the active engine.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(ethers.ZeroAddress);
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      // address(0) current engine must NOT mean "skip policy": the sticky floor still applies.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("finalize SUCCEEDS when the disabled engine's queue-time state still permits", async function () {
      await setPolicyEngine(await sanctionsPolicy.getAddress());
      await enableLargeTx();
      const { operationId } = await queueLarge(); // clean

      await setPolicyEngine(ethers.ZeroAddress); // disabled; recipient never sanctioned
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // Deduplication — a single engine on both sides is revalidated exactly once
  // =========================================================================
  describe("Deduplication of the two-engine revalidation", function () {
    // Deploys a fresh single-owner vault and measures finalize gas in one of three
    // configurations: no engine at all, a single heavy engine on BOTH sides (shared
    // address), or two distinct heavy engines (queue-time + replacement).
    async function measureFinalizeGas(mode: "none" | "shared" | "distinct"): Promise<bigint> {
      const v = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());

      await v.connect(owner).createVault(owner.address, PQ_KEY, 2);
      await v.connect(owner).deposit({ value: DEPOSIT });

      if (mode !== "none") {
        const heavyA = await (await ethers.getContractFactory("HeavyRevalidatePolicyMock", admin)).deploy();
        await v.connect(admin).proposePolicyEngine(await heavyA.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await v.connect(admin).applyPolicyEngine();
      }
      await v.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await v.connect(admin).applyLargeTxParams();

      const build = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
      const sign = makeSignWithdrawal(v, owner);
      const req = await build();
      const { ecdsaSig, pqSig } = await sign(req);
      await v.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
      const operationId = await v.hashWithdrawal(req);

      if (mode === "distinct") {
        const heavyB = await (await ethers.getContractFactory("HeavyRevalidatePolicyMock", admin)).deploy();
        await v.connect(admin).proposePolicyEngine(await heavyB.getAddress());
        await networkHelpers.time.increase(GOVERNANCE_DELAY);
        await v.connect(admin).applyPolicyEngine();
      }

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      const tx = await v.connect(owner).finalizeWithdrawal(owner.address, operationId);
      const receipt = await tx.wait();
      return receipt!.gasUsed;
    }

    it("evaluates a shared queue/current engine exactly once (gas evidence)", async function () {
      // Independently estimate the cost of ONE heavy revalidation (call overhead
      // included) so the assertions below are absolute, not self-referential.
      const heavy = await (await ethers.getContractFactory("HeavyRevalidatePolicyMock", admin)).deploy();
      const oneHeavy = await heavy.revalidate.estimateGas(owner.address, recipient.address, LARGE_AMOUNT, DEPOSIT);

      const gasNone = await measureFinalizeGas("none"); // 0 heavy evals
      const gasShared = await measureFinalizeGas("shared"); // must be exactly 1
      const gasDistinct = await measureFinalizeGas("distinct"); // must be exactly 2

      const sharedCost = gasShared - gasNone;
      // At least one heavy evaluation ran…
      expect(sharedCost).to.be.greaterThan(oneHeavy / 2n);
      // …and fewer than two (kills any double-evaluation of the shared engine).
      expect(sharedCost).to.be.lessThan((oneHeavy * 8n) / 5n);
      // The distinct configuration runs exactly one more evaluation than shared.
      const extra = gasDistinct - gasShared;
      expect(extra).to.be.greaterThan(oneHeavy / 2n);
      expect(extra).to.be.lessThan((oneHeavy * 8n) / 5n);
    });
  });

  // =========================================================================
  // Fail-closed — revalidation must never silently grant settlement
  // =========================================================================
  describe("Fail-closed revalidation", function () {
    async function queueUnderMockEngine(engineAddr: string) {
      await setPolicyEngine(engineAddr);
      await enableLargeTx();
      const { operationId } = await queueLarge();
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      return operationId;
    }

    it("a revalidate() that attempts an SSTORE reverts finalization and books nothing (STATICCALL)", async function () {
      const mock = await (await ethers.getContractFactory("MutatingRevalidatePolicyMock", admin)).deploy();
      const operationId = await queueUnderMockEngine(await mock.getAddress());

      // Admission (a normal CALL) recorded a write; revalidation (a STATICCALL) must not.
      expect(await mock.checkCalls()).to.equal(1n);

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(await mock.getAddress());

      // The write inside revalidate() was rolled back by the static-call revert.
      expect(await mock.revalidateCalls()).to.equal(0n);
    });

    it("a reverting revalidate() fails finalization closed", async function () {
      const mock = await (await ethers.getContractFactory("RevertingRevalidatePolicyMock", admin)).deploy();
      const operationId = await queueUnderMockEngine(await mock.getAddress());
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(await mock.getAddress());
    });

    it("an engine that does not implement revalidate() (check-only) fails closed", async function () {
      const mock = await (await ethers.getContractFactory("LegacyCheckOnlyPolicyMock", admin)).deploy();
      const operationId = await queueUnderMockEngine(await mock.getAddress());
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(await mock.getAddress());
    });

    it("an engine returning malformed (undecodable) data fails closed", async function () {
      const mock = await (await ethers.getContractFactory("MalformedReturnPolicyMock", admin)).deploy();
      const operationId = await queueUnderMockEngine(await mock.getAddress());
      // Return-data decode failures are raised in the CALLER and are not catchable by
      // try/catch (Solidity semantics), so this surfaces as a raw revert rather than
      // PolicyEngineUnavailable — still fail-closed, which is the property under test.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.revert(ethers);
    });

    it("a composite containing a check-only module fails finalization closed (propagated)", async function () {
      // Admission works (composite.check fans out to the legacy module's check), but
      // revalidation cannot: the module lacks revalidate, the composite's view fan-out
      // reverts, and the vault converts that to PolicyEngineUnavailable(composite).
      const legacy = await (await ethers.getContractFactory("LegacyCheckOnlyPolicyMock", admin)).deploy();
      await composite.addModule(await legacy.getAddress());
      const operationId = await queueUnderMockEngine(await composite.getAddress());
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(await composite.getAddress());
    });

    it("a CURRENT engine that has become code-less fails closed", async function () {
      // Queue under a real engine, then point the active engine at a code-less address (an EOA).
      await setPolicyEngine(await allowlistPolicy.getAddress());
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await enableLargeTx();
      const { operationId } = await queueLarge();

      await setPolicyEngine(other.address); // EOA: code.length == 0
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(other.address);
    });
  });

  // =========================================================================
  // Balance semantic — revalidate receives the pre-deduction balance, like check
  // =========================================================================
  describe("vaultBalance semantic parity between check and revalidate", function () {
    it("finalization reconstructs the pre-deduction balance (current + reserved), matching admission", async function () {
      // The mock admits only when vaultBalance == DEPOSIT (the balance BEFORE the
      // withdrawal's deduction). If finalization passed the post-reservation balance
      // (the old bug), revalidate would see DEPOSIT - LARGE_AMOUNT and revert.
      const mock = await (
        await ethers.getContractFactory("BalanceAssertingPolicyMock", admin)
      ).deploy(DEPOSIT, LARGE_AMOUNT);

      await setPolicyEngine(await mock.getAddress());
      await enableLargeTx();
      const { operationId } = await queueLarge(); // admission sees DEPOSIT and passes

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // P7 — cancellation / recovery must not retain policy or quorum authority
  // =========================================================================
  describe("P7 — cancellation and recovery clear reserved authority", function () {
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

      expect((await vault.getVault(owner.address)).balance).to.equal(balBefore + LARGE_AMOUNT);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(0);
      expect(await vault.treasuryApprovals(operationId, guardian1.address)).to.equal(false);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        vault,
        "NoPendingWithdrawal",
      );
    });

    it("a re-queued withdrawal after cancellation does NOT inherit the old op's guardian approvals", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();

      const first = await queueLarge();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, first.operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, first.operationId);
      await vault.connect(owner).cancelPendingWithdrawal(first.operationId);

      const req2 = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT, nonce: 1 });
      const { ecdsaSig, pqSig } = await signWithdrawal(req2);
      await vault.connect(other).queueWithdrawal(req2, ecdsaSig, pqSig);
      const op2 = await vault.hashWithdrawal(req2);
      expect(op2).to.not.equal(first.operationId);

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

      expect((await vault.pendingWithdrawals(owner.address)).exists).to.equal(false);
      expect((await vault.getVault(owner.address)).balance).to.equal(balAfterQueue + LARGE_AMOUNT);
    });
  });
});
