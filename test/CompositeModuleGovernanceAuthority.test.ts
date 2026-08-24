import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  WalletWallVault,
  MockMLDSAVerifier,
  CompositePolicyEngine,
  RecipientAllowlistPolicy,
  SanctionsListPolicy,
} from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

/**
 * Regression suite for the module-mutation AUTHORITY/GOVERNANCE model of
 * CompositePolicyEngine.
 *
 * Both WalletWallVault and StablecoinVaultSimulator require a 2-day
 * `POLICY_ENGINE_UPDATE_DELAY` (propose -> wait -> apply) to replace the
 * vault's policy-engine ADDRESS. `CompositePolicyEngine.addModule` /
 * `removeModule` formerly took effect IMMEDIATELY (onlyOwner, no proposal,
 * no delay), and an empty module list is permissive — so a composite owner
 * could instantly evict a denying module (or empty the set entirely), for
 * zero governance friction, weakening both future admissions AND an
 * already-queued withdrawal wired to that composite (since
 * `finalizeWithdrawal`'s `revalidate()` always reads the composite's LIVE
 * module roster — see PR #152). This was strictly worse than what an
 * engine-address swap alone could do: the vault's sticky floor binds the
 * queue-time engine ADDRESS, so swapping the vault's ACTIVE engine can never
 * retroactively free a withdrawal queued under a different, still-sticky
 * engine — but mutating the LIVE roster of that SAME sticky-floor composite
 * could, because there is no per-withdrawal snapshot of the roster.
 *
 * FIXED MODEL (this suite pins it): module composition is AND-semantics, so
 * `addModule` can only ever shrink-or-preserve the composite's accepted set
 * (monotonic strengthening) and stays instant — gating it would cost urgent-
 * response liveness for no security benefit. Removal is the only direction
 * that can weaken the effective policy, so it now goes through
 * `proposeRemoveModule` / `applyRemoveModule` behind `MODULE_REMOVAL_DELAY`
 * (2 days, matching the vault's own `POLICY_ENGINE_UPDATE_DELAY` by
 * convention). The module being removed stays fully active — evaluated by
 * both `check()` and `revalidate()` — for the entire pending window.
 *
 * IMPORTANT — friction-equivalent, NOT settlement-outcome-equivalent for
 * already-queued withdrawals. Module removal now costs a composite owner
 * the same DELAY a vault owner would pay to swap the vault's engine address
 * — that is a statement about governance FRICTION for future admissions.
 * It is NOT a guarantee that the two mechanisms settle an already-queued
 * withdrawal identically: an engine-address swap can never retroactively
 * free a withdrawal queued under a DIFFERENT (still sticky-floor) engine,
 * but a matured-and-applied module removal on a composite that IS the
 * sticky-floor engine legitimately CAN, because the floor binds the
 * queue-time engine ADDRESS, not a snapshot of that engine's module roster.
 * Sections A-D below characterize this; the "Control A/B" section pins the
 * distinction explicitly, side by side, against the same conceptual setup.
 *
 * Sections A-D below map 1:1 onto the four characterization scenarios this
 * suite began life pinning as vulnerable: immediate weakening, last-module
 * removal, queued-withdrawal retroactivity, and owner authority
 * equivalence (for future admissions — see the note above and Control A/B).
 * Every assertion that used to observe the vulnerable outcome is flipped in
 * place here — no tests were deleted, only their expectations inverted once
 * the fix landed, mirroring how PolicyFinalizationAuthority.test.ts's P1-P7
 * were flipped for PR #152. The unit-level propose/apply/cancel mechanics
 * (delays, membership guards, stale-timestamp-on-reuse, MAX_MODULES
 * interaction) are covered in test/CompositePolicyEngine.test.ts; this file
 * proves the mechanism closes the invariant end-to-end through a live vault.
 */
describe("CompositePolicyEngine module-mutation governance authority", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let composite: CompositePolicyEngine;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let sanctionsPolicy: SanctionsListPolicy;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60; // vault POLICY_ENGINE_UPDATE_DELAY
  const MODULE_REMOVAL_DELAY = 2 * 24 * 60 * 60; // CompositePolicyEngine.MODULE_REMOVAL_DELAY
  const LARGE_TX_DELAY = 1 * 24 * 60 * 60; // deliberately SHORTER than MODULE_REMOVAL_DELAY
  const DEPOSIT = ethers.parseEther("10");
  const THRESHOLD = ethers.parseEther("3");
  const LARGE_AMOUNT = ethers.parseEther("4");
  const SMALL_AMOUNT = ethers.parseEther("0.5");

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

  async function directWithdraw(nonce: number, overrides: { amount?: bigint; recipient?: string } = {}) {
    const req = await buildRequest({ nonce, ...overrides });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    return vault.connect(other).withdraw(req, ecdsaSig, pqSig);
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
    allowlistPolicy = await (await ethers.getContractFactory("RecipientAllowlistPolicy", admin)).deploy();
    sanctionsPolicy = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
    await allowlistPolicy.connect(owner).addRecipient(recipient.address);

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: SMALL_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // =========================================================================
  // A — removal now requires the same governance friction an engine-address
  //     swap would need; proposing alone changes nothing until applied.
  // =========================================================================
  describe("A — module removal no longer weakens admission until its own delay is paid", function () {
    it("proposing removal changes nothing; only apply, after the delay, un-blocks the recipient", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      // Wiring the composite in as the active engine consumes the vault's OWN
      // 2-day delay exactly once, up front — a one-time setup cost, not part
      // of the removal governance under test below.
      await setPolicyEngine(await composite.getAddress());
      const engineAddress = await vault.policyEngine();

      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Proposing removal is onlyOwner and synchronous, but the module stays
      // fully active until MODULE_REMOVAL_DELAY elapses AND apply is called.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Still blocked right up until the delay has fully elapsed.
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY - 10);
      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Only once the FULL delay has elapsed AND applyRemoveModule is called
      // does the same recipient become admittable for this FUTURE (non-queued)
      // withdrawal -- matching the friction an engine-address swap would need
      // for a future admission. The vault's policyEngine ADDRESS never changed
      // throughout: this is friction-equivalence for future admissions, achieved
      // through the composite's own governance rather than the vault's -- NOT a
      // claim about already-queued withdrawals (see Control A/B below).
      await networkHelpers.time.increase(20);
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await vault.policyEngine()).to.equal(engineAddress);
      await expect(directWithdraw(0)).to.emit(vault, "Withdrawn");
    });
  });

  // =========================================================================
  // B — last-module removal: reaching an empty (permissive) composite from a
  //     non-empty enforcing one now costs the same governance friction.
  // =========================================================================
  describe("B — collapsing to a permissive empty composite is now governed", function () {
    it("admission: the last module keeps enforcing until its removal is fully applied", async function () {
      await composite.addModule(await sanctionsPolicy.getAddress());
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(await composite.getAddress());

      expect(await composite.moduleCount()).to.equal(1n);
      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      // Still one active module, still denying -- proposing is not removing.
      expect(await composite.moduleCount()).to.equal(1n);
      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await composite.moduleCount()).to.equal(0n);
      // Reaching empty was itself governed -- exactly the invariant required.
      await expect(directWithdraw(0)).to.emit(vault, "Withdrawn");
    });

    it("finalization: a removal proposed after queueing has NOT applied by the (shorter) large-tx delay, so the withdrawal still finalizes blocked -- and only settles once the removal itself is later fully applied", async function () {
      // Recipient is allowlisted (permitted) but the sanctions module is what
      // would deny it. Queue while sanctions is the ONLY module and the
      // recipient is clean, then sanction the recipient and PROPOSE removing
      // the sanctions module before finalize.
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge(0);

      await sanctionsPolicy.addToSanctionsList(recipient.address); // would now deny...
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress()); // ...proposing removal does not evict it yet

      // LARGE_TX_DELAY (1 day) is deliberately shorter than MODULE_REMOVAL_DELAY
      // (2 days): by the time this withdrawal is ready to finalize, the removal
      // proposal has NOT matured, so the module is still fully active.
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      expect(await composite.moduleCount()).to.equal(1n); // still present -- not yet applied
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // The finalize attempt reverted, so the withdrawal is still queued. Once
      // the module-removal delay has ALSO fully elapsed and the removal is
      // actually applied, the (now fully-governed) removal does eventually let
      // the withdrawal settle -- proving the fix gates the TIMING, not the
      // ability to ever legitimately remove a module.
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY - LARGE_TX_DELAY);
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await composite.moduleCount()).to.equal(0n);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // =========================================================================
  // C — queued-withdrawal retroactivity: mutate the module set between queue
  //     and finalize and characterize BOTH directions.
  // =========================================================================
  describe("C — queued-withdrawal retroactivity under module mutation", function () {
    it("strengthening: adding a denying module before finalize still blocks a withdrawal that was clean at queue time (unaffected by this fix)", async function () {
      // No modules at queue time -- admission is permissive.
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge(0);

      // Sanction the recipient, then INSTANTLY add the sanctions module.
      // addModule is deliberately left ungated by this fix: it can only ever
      // strengthen the composite's effective policy (AND composition), so
      // urgent strengthening stays free and instant.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await composite.addModule(await sanctionsPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("weakening: a module whose continued presence would deny finalization stays enforced -- proposing its removal does not evict it before the (shorter) large-tx delay elapses", async function () {
      // Both modules present and passing at queue time.
      await composite.addModule(await allowlistPolicy.getAddress());
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();

      const { operationId } = await queueLarge(0);

      // Recipient becomes sanctioned after queueing -- if the sanctions module
      // stays present at finalize, revalidate() observes this live and blocks
      // (exactly as PolicyFinalizationAuthority.test.ts's P2 "retained module"
      // case proves). The composite owner PROPOSES evicting the denying
      // module, but proposing alone does not remove it.
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      // FIXED: the module-removal delay (2 days) has not elapsed by the time
      // the (1-day) large-tx delay has, so the sanctions module is still fully
      // active and finalization is still correctly blocked -- the module whose
      // continued presence would deny this settlement was NOT evicted in time.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });
  });

  // =========================================================================
  // D — authority equivalence for FUTURE admissions only: emptying the module
  //     set now costs the same governance friction as an engine swap for a
  //     fresh, non-queued withdrawal. This is NOT a claim about already-queued
  //     withdrawals -- see Control A/B below for that distinction.
  // =========================================================================
  describe("D — composite owner authority now costs the same friction as an engine swap (future admissions)", function () {
    it("emptying the module set reaches the same FUTURE-ADMISSION outcome as swapping to a permissive engine, and now needs the SAME 2-day delay that swap requires", async function () {
      // NOTE: this test uses directWithdraw() throughout -- a fresh, non-queued
      // withdrawal -- so "reaches the same outcome" here is scoped to FUTURE
      // admissions only. It says nothing about an already-queued withdrawal;
      // see "Control A/B" below for why that case is NOT outcome-equivalent.
      await composite.addModule(await allowlistPolicy.getAddress());
      await composite.addModule(await sanctionsPolicy.getAddress());
      await sanctionsPolicy.addToSanctionsList(recipient.address);
      await setPolicyEngine(await composite.getAddress());
      const engineAddress = await vault.policyEngine();

      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Contrast path: actually swapping the vault's engine to something
      // permissive (e.g. address(0)) is gated -- proposing it does not make it
      // effective yet.
      await vault.connect(admin).proposePolicyEngine(ethers.ZeroAddress);
      await expect(vault.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(
        vault,
        "PolicyEngineUpdateNotReady",
      );
      await vault.connect(admin).cancelPolicyEngine();

      // The composite owner PROPOSES emptying the module set instead -- but,
      // unlike before this fix, proposing alone changes nothing: the recipient
      // is still blocked with zero elapsed time.
      await composite.proposeRemoveModule(await allowlistPolicy.getAddress());
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());
      expect(await composite.moduleCount()).to.equal(2n);
      await expect(directWithdraw(0))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Only after paying the SAME governance delay the engine-swap contrast
      // path above required (and actually applying) does module removal reach
      // that FUTURE-ADMISSION outcome. The two paths are friction-equivalent
      // (same delay) for this future admission -- that says nothing about an
      // already-queued withdrawal, which is where the two paths diverge (see
      // "Control A/B" below).
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);
      await composite.applyRemoveModule(await allowlistPolicy.getAddress());
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await composite.moduleCount()).to.equal(0n);

      expect(await vault.policyEngine()).to.equal(engineAddress);
      await expect(directWithdraw(0)).to.emit(vault, "Withdrawn");
    });
  });

  // =========================================================================
  // Control A/B — side-by-side proof that the ADDRESS-level sticky floor
  // (PR #152) and the composite's MODULE-ROSTER content are two different
  // things, pinned against the same conceptual setup (a composite with a
  // sanctions module, queued while clean, sanctioned after queue):
  //
  //   address-level sticky floor  !=  module-roster snapshot
  //
  // Control A: an engine-ADDRESS swap (even after its own full governance
  // delay) cannot erase the queue-time composite's sticky floor -- the
  // ORIGINAL composite is still consulted, and its sanctions module is still
  // live on it, so finalization still reverts.
  //
  // Control B: a matured, explicitly-APPLIED module removal on that SAME
  // queue-time composite (its address never changes) DOES change the
  // outcome, because revalidate() always reads the live roster -- there is
  // no per-withdrawal snapshot of it. This is intentional module-roster
  // mutability after a governed delay, not "the same outcome as an engine
  // swap" and not an erosion of the sticky floor: the floor still binds the
  // queue-time engine ADDRESS in both controls -- only the LIVE state read
  // through that address differs.
  // =========================================================================
  describe("Control A/B — address-level sticky floor vs. module-roster snapshot", function () {
    it("Control A: an engine-address swap to a permissive engine, even after its full delay, cannot erase the queue-time composite's sticky floor", async function () {
      // Wire a CompositePolicyEngine with a sanctions module into the vault.
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();
      const queueTimeEngine = await vault.policyEngine();

      // Queue a withdrawal while the recipient is clean.
      const { operationId } = await queueLarge(0);

      // Sanction the recipient after queue.
      await sanctionsPolicy.addToSanctionsList(recipient.address);

      // Propose and apply a vault ENGINE-ADDRESS swap to address(0) after the
      // full POLICY_ENGINE_UPDATE_DELAY -- the vault's CURRENT engine is now
      // permissive (disabled), but the composite itself is untouched: its
      // sanctions module is still registered and still sanctions the recipient.
      await vault.connect(admin).proposePolicyEngine(ethers.ZeroAddress);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyPolicyEngine();
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      expect(await composite.moduleCount()).to.equal(1n); // composite's roster untouched

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      // Finalization still reverts: policyEngineAtQueue is the ORIGINAL
      // composite (queueTimeEngine), which is still consulted as the sticky
      // floor regardless of what the vault's CURRENT engine now is, and that
      // composite's sanctions module is still present and live.
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
      expect(queueTimeEngine).to.equal(await composite.getAddress()); // sanity: floor IS this composite
    });

    it("Control B: a matured, explicitly-applied module removal on that SAME queue-time composite legitimately changes the outcome -- the address never changed, only the live roster did", async function () {
      // Identical conceptual setup to Control A: fresh fixture (beforeEach),
      // same composite + sanctions module, same queue-while-clean-then-sanction
      // sequence -- only the mutation path differs (module removal, not an
      // engine-address swap).
      await composite.addModule(await sanctionsPolicy.getAddress());
      await setPolicyEngine(await composite.getAddress());
      await enableLargeTx();
      const queueTimeEngine = await vault.policyEngine();

      const { operationId } = await queueLarge(0);
      await sanctionsPolicy.addToSanctionsList(recipient.address);

      // Propose removal of the sanctions module.
      await composite.proposeRemoveModule(await sanctionsPolicy.getAddress());

      // Before MODULE_REMOVAL_DELAY matures, finalization must still revert --
      // proposing does not remove, so the roster is unchanged so far.
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // After the full delay and an explicit applyRemoveModule, finalization
      // MAY succeed -- the queue-time engine ADDRESS is UNCHANGED throughout
      // (unlike Control A's engine swap), but its LIVE roster has been
      // legitimately weakened via governed removal.
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY - LARGE_TX_DELAY);
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await vault.policyEngine()).to.equal(queueTimeEngine); // ADDRESS never changed
      expect(await composite.moduleCount()).to.equal(0n); // but the LIVE roster did

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );

      // The explicit assertion this pair exists to pin: the sticky floor
      // (queue-time ENGINE ADDRESS, unchanged in Control B) is not the same
      // guarantee as a module-roster SNAPSHOT (which does not exist) --
      // address-level sticky floor != module-roster snapshot. Control A shows
      // the address-level floor holding firm against an engine swap; this test
      // shows the SAME address's live roster is not floor-protected against a
      // governed removal.
      expect(queueTimeEngine).to.equal(await composite.getAddress());
    });
  });
});
