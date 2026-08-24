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
 * could instantly evict a denying module (or empty the set entirely) and
 * reach, in one transaction and zero elapsed delay, the same practical
 * outcome a full engine-address swap would need the vault's governance
 * delay to reach.
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
 * Sections A-D below map 1:1 onto the four characterization scenarios this
 * suite began life pinning as vulnerable: immediate weakening, last-module
 * removal, queued-withdrawal retroactivity, and owner authority
 * equivalence. Every assertion that used to observe the vulnerable outcome
 * is flipped in place here — no tests were deleted, only their
 * expectations inverted once the fix landed, mirroring how
 * PolicyFinalizationAuthority.test.ts's P1-P7 were flipped for PR #152.
 * The unit-level propose/apply/cancel mechanics (delays, membership guards,
 * stale-timestamp-on-reuse, MAX_MODULES interaction) are covered in
 * test/CompositePolicyEngine.test.ts; this file proves the mechanism closes
 * the invariant end-to-end through a live vault.
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
      // does the same recipient become admittable -- matching the friction an
      // engine-address swap would need. The vault's policyEngine ADDRESS never
      // changed throughout: this is authority-equivalent friction, achieved
      // through the composite's own governance rather than the vault's.
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
  // D — authority equivalence: reaching the same outcome as an engine swap by
  //     emptying the module set now costs the same governance friction.
  // =========================================================================
  describe("D — composite owner authority now costs the same friction as an engine swap", function () {
    it("emptying the module set reaches the same outcome as swapping to a permissive engine, and now needs the SAME 2-day delay that swap requires", async function () {
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
      // that outcome -- the two paths are now friction-equivalent, not just
      // outcome-equivalent.
      await networkHelpers.time.increase(MODULE_REMOVAL_DELAY);
      await composite.applyRemoveModule(await allowlistPolicy.getAddress());
      await composite.applyRemoveModule(await sanctionsPolicy.getAddress());
      expect(await composite.moduleCount()).to.equal(0n);

      expect(await vault.policyEngine()).to.equal(engineAddress);
      await expect(directWithdraw(0)).to.emit(vault, "Withdrawn");
    });
  });
});
