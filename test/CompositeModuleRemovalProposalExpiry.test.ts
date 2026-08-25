import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier, CompositePolicyEngine, SanctionsListPolicy } from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

/**
 * Regression suite for the EXPIRY of CompositePolicyEngine module-removal
 * proposals.
 *
 * PR #160 gated module removal behind `MODULE_REMOVAL_DELAY` (2 days) and
 * documented the resulting invariant as a FRICTION floor — the composite's own
 * NatSpec states a module "cannot be evicted with less friction than an
 * engine-address swap would cost", and
 * test/CompositeModuleGovernanceAuthority.test.ts pins removal as needing "the
 * SAME 2-day delay that swap requires".
 *
 * That invariant did not hold, because `pendingModuleRemovalValidAfter` had no
 * upper bound: once a proposal matured it stayed exercisable FOREVER. A
 * composite owner could therefore PRE-ARM a removal — propose it at a quiet
 * moment when nothing is queued and no observer has reason to react, let the
 * two days elapse without applying, and bank an instantly-exercisable eviction
 * indefinitely. At the moment the module actually stood between the owner and a
 * settlement, `applyRemoveModule` cost ZERO additional delay.
 *
 * That is precisely where the vault's sticky floor does NOT help. Per PR #152,
 * `finalizeWithdrawal` binds the queue-time engine ADDRESS, so swapping the
 * vault's active engine can never retroactively free an already-queued
 * withdrawal. But `revalidate()` always reads the composite's LIVE module
 * roster, so evicting a module from the composite that IS the sticky-floor
 * engine does change that withdrawal's outcome. The 2-day removal delay was the
 * only friction standing in front of that path, and pre-arming reduced it to
 * nothing.
 *
 * FIXED MODEL (this suite pins it): a matured removal proposal stays applicable
 * only for `MODULE_REMOVAL_GRACE_PERIOD`, after which it expires and must be
 * re-proposed — paying the full delay again. The security property this buys is
 * bounded-warning: any removal that can be executed right now was publicly
 * announced (via `ModuleRemovalProposed`) within the last
 * DELAY + GRACE window, so an observer monitoring that event has a guaranteed
 * finite horizon rather than needing perfect recall of every proposal ever made.
 *
 * The delay/grace pairing mirrors Compound's Timelock (2-day delay, 14-day
 * GRACE_PERIOD), which exists for exactly this reason.
 *
 * Expiry deliberately does NOT remove the composite owner's ability to
 * legitimately retire a module — section "legitimate removals still work"
 * proves the honest path is unchanged.
 */
describe("CompositePolicyEngine module-removal proposal expiry", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let composite: CompositePolicyEngine;
  let sanctionsPolicy: SanctionsListPolicy;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60; // vault POLICY_ENGINE_UPDATE_DELAY
  const MODULE_REMOVAL_DELAY = 2 * 24 * 60 * 60; // CompositePolicyEngine.MODULE_REMOVAL_DELAY
  const MODULE_REMOVAL_GRACE_PERIOD = 14 * 24 * 60 * 60; // CompositePolicyEngine.MODULE_REMOVAL_GRACE_PERIOD
  const LARGE_TX_DELAY = 1 * 24 * 60 * 60;
  const DEPOSIT = ethers.parseEther("10");
  const THRESHOLD = ethers.parseEther("3");
  const LARGE_AMOUNT = ethers.parseEther("4");
  const SMALL_AMOUNT = ethers.parseEther("0.5");

  /** A long, quiet interval between pre-arming a removal and exercising it. */
  const LONG_DORMANCY = 365 * 24 * 60 * 60;

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

  async function queueLarge(nonce: number, overrides: { amount?: bigint; recipient?: string } = {}) {
    const req = await buildRequest({ nonce, amount: LARGE_AMOUNT, ...overrides });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
    return { req, operationId: await vault.hashWithdrawal(req) };
  }

  beforeEach(async function () {
    [admin, owner, recipient, other] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    composite = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
    sanctionsPolicy = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: SMALL_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // =========================================================================
  // A — the banked-proposal defect, at the unit level.
  // =========================================================================
  describe("A — a matured proposal cannot be banked indefinitely", function () {
    it("MODULE_REMOVAL_GRACE_PERIOD is exposed and is a bounded, non-zero window", async function () {
      const grace = await composite.MODULE_REMOVAL_GRACE_PERIOD();
      expect(grace).to.equal(BigInt(MODULE_REMOVAL_GRACE_PERIOD));
      expect(grace).to.be.greaterThan(0n);
    });

    it("a removal proposal that matured long ago has EXPIRED and can no longer be applied", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());

      // Pre-arm at a quiet moment: nothing is queued, nothing is denied, and
      // this call is indistinguishable from routine policy maintenance.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

      // Let it mature and then sit dormant for a long time without applying.
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY + LONG_DORMANCY);

      // The banked proposal must NOT still be exercisable.
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleRemovalExpired",
      );

      // ...and the module is still fully enforcing.
      expect(await composite.moduleCount()).to.equal(1n);
    });

    it("expiry is enforced at the exact grace boundary, not merely 'eventually'", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

      const validAfter = await composite.pendingModuleRemovalValidAfter(await sanctionsPolicy.getAddress());
      const lastValidSecond = validAfter + BigInt(MODULE_REMOVAL_GRACE_PERIOD);

      // One second past the grace window: refused.
      await networkHelpers.time.setNextBlockTimestamp(lastValidSecond + 1n);
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleRemovalExpired",
      );
    });

    it("the final second of the grace window is still applicable (the window is inclusive)", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

      const validAfter = await composite.pendingModuleRemovalValidAfter(await sanctionsPolicy.getAddress());
      const lastValidSecond = validAfter + BigInt(MODULE_REMOVAL_GRACE_PERIOD);

      await networkHelpers.time.setNextBlockTimestamp(lastValidSecond);
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.emit(composite, "ModuleRemoved");
      expect(await composite.moduleCount()).to.equal(0n);
    });

    it("an expired proposal must be re-proposed AND pay a fresh full delay -- it does not become instantly applicable", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY + MODULE_REMOVAL_GRACE_PERIOD + 1);

      // Re-proposing is allowed...
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      // ...but buys no head start from the expired proposal.
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleRemovalNotReady",
      );

      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.emit(composite, "ModuleRemoved");
    });

    it("an expired proposal can still be explicitly cancelled, clearing the stale pending record", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY + MODULE_REMOVAL_GRACE_PERIOD + 1);

      await expect(composite.cancelRemoveModule(await sanctionsPolicy.getAddress())).to.emit(
        composite,
        "ModuleRemovalCancelled",
      );
      expect(await composite.pendingModuleRemovalValidAfter(await sanctionsPolicy.getAddress())).to.equal(0n);
    });
  });

  // =========================================================================
  // B — end-to-end: the banked proposal cannot free a blocked queued withdrawal.
  // =========================================================================
  describe("B — a banked removal cannot retroactively free a blocked queued withdrawal", function () {
    it("pre-arming a removal long in advance does not let the owner evict a denying module the instant it blocks finalization", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      // PRE-ARM, long before any withdrawal exists.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY + LONG_DORMANCY);

      // Only now does the owner queue a withdrawal; the recipient is clean, so
      // admission passes with the sanctions module fully active.
      const { operationId } = await queueLarge(0);
      await networkHelpers.time.increase(LARGE_TX_DELAY);

      // The recipient becomes sanctioned; revalidation correctly blocks.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // The banked eviction must NOT be exercisable now.
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleRemovalExpired",
      );

      // ...so the withdrawal is still blocked.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("evicting the denying module still costs a FULL fresh removal delay once the need has arisen", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY + LONG_DORMANCY);

      const { operationId } = await queueLarge(0);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await sanctionsPolicy.addToSanctionsList(recipient.address);

      // Re-propose now that the need is public. The module keeps enforcing for
      // the whole fresh window -- this is the reaction window the timelock is
      // supposed to guarantee, and pre-arming must not be able to skip it.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY - 60);
      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.be.revertedWithCustomError(
        composite,
        "ModuleRemovalNotReady",
      );
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });
  });

  // =========================================================================
  // C — the honest path is unchanged (expiry must not break legitimate removal).
  // =========================================================================
  describe("C — legitimate removals still work", function () {
    it("a removal applied promptly after its delay elapses still succeeds", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);

      await expect(composite.applyRemoveModule(await sanctionsPolicy.getAddress())).to.emit(composite, "ModuleRemoved");
      expect(await composite.moduleCount()).to.equal(0n);
    });

    it("a fully-governed removal still eventually settles a queued withdrawal it was blocking", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge(0);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await sanctionsPolicy.addToSanctionsList(recipient.address);

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Propose AFTER the need arose, wait the full delay, apply inside grace.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });
});
