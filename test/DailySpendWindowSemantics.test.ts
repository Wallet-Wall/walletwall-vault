import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  WalletWallVault,
  StablecoinVaultSimulator,
  MockUSDC,
  MockMLDSAVerifier,
  DailySpendLimitPolicy,
  CompositePolicyEngine,
} from "../typechain-types";
import { WITHDRAWAL_TYPES } from "./helpers/vaultHelpers";
import { NATIVE_ASSET } from "./helpers/policySubject";

/**
 * DailySpendLimitPolicy time and scope semantics.
 *
 * Originally an INVESTIGATION suite: it made the then-current behaviour undeniable so
 * a semantics decision could be made from evidence rather than from NatSpec prose.
 * The two questions it asked have now been answered differently:
 *
 *   TIME  — is the window rolling (any 24h interval capped) or tumbling (a fixed
 *           window that zeroes on the first call after expiry)?
 *           NOW ROLLING. PART 1 previously characterized a TUMBLING window and pinned
 *           the `2 * limit` boundary burst as a reachable fact; those two burst cases
 *           are now INVERTED and assert the burst is refused. They are kept in place,
 *           rather than replaced with fresh happy-path tests, precisely so the closure
 *           is visible as a diff against the construction that used to succeed.
 *
 *           HISTORICAL, NOT CURRENT: every mention of `windowStart`, `windowSpent`, a
 *           tumbling reset or a `2 * limit` ceiling in this file describes behaviour
 *           that NO LONGER EXISTS. The live invariant is a true trailing-24h cap; its
 *           adversarial matrix is test/DailySpendRollingWindow.test.ts, which is the
 *           authority on rolling semantics. This file remains the authority on the
 *           SCOPE half — that PART 2 still passes unchanged is the evidence that
 *           rolling accounting did not weaken subject isolation.
 *
 *   SCOPE — is spend accounting isolated per vault contract and per asset, or only per
 *           owner address?
 *           NOW ISOLATED. PART 2 previously characterized a COLLAPSE — one accumulator
 *           shared across vault contracts, one scalar shared across incommensurable
 *           denominations, one bucket shared by every consumer behind a composite — and
 *           now asserts that collapse's absence. The TENANT ISOLATION case is the
 *           control: it did not change, and proves these tests can still observe a
 *           shared bucket where one legitimately exists.
 *
 * Cross-boundary propagation (what the vaults mint, what the composite relays, what a
 * spoofing caller can reach) is covered by test/PolicySubjectPropagation.test.ts.
 */
describe("DailySpendLimitPolicy — window and scope semantics (investigation)", function () {
  const WINDOW = 24 * 60 * 60;
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;

  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let admin: HardhatEthersSigner;

  let verifier: MockMLDSAVerifier;
  let policy: DailySpendLimitPolicy;

  // ---------------------------------------------------------------------
  // Local request builders — the shared helpers derive `deadline` from
  // time.latest(), which is unusable here because these tests deliberately
  // jump the clock across a 24h boundary before submitting.
  // ---------------------------------------------------------------------
  async function ethDomain(vault: WalletWallVault) {
    return {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };
  }

  async function tokenDomain(sim: StablecoinVaultSimulator) {
    return {
      name: "WalletWallStablecoinVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await sim.getAddress(),
    };
  }

  function request(vaultOwner: string, to: string, amount: bigint, nonce: number, deadline: number) {
    return { vaultOwner, recipient: to, amount, nonce, deadline, vaultMode: HYBRID };
  }

  async function signEth(vault: WalletWallVault, signer: HardhatEthersSigner, req: object) {
    const ecdsaSig = await signer.signTypedData(await ethDomain(vault), WITHDRAWAL_TYPES, req);
    const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { ecdsaSig, pqSig };
  }

  async function signToken(sim: StablecoinVaultSimulator, signer: HardhatEthersSigner, req: object) {
    const ecdsaSig = await signer.signTypedData(await tokenDomain(sim), WITHDRAWAL_TYPES, req);
    const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { ecdsaSig, pqSig };
  }

  /** Submits an ETH withdrawal in a block whose timestamp is exactly `at`. */
  async function withdrawAt(
    vault: WalletWallVault,
    signer: HardhatEthersSigner,
    amount: bigint,
    nonce: number,
    at: number,
  ) {
    const req = request(signer.address, recipient.address, amount, nonce, at + 3600);
    const { ecdsaSig, pqSig } = await signEth(vault, signer, req);
    await networkHelpers.time.setNextBlockTimestamp(at);
    return vault.withdraw(req, ecdsaSig, pqSig);
  }

  async function deployEthVault(): Promise<WalletWallVault> {
    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    const v = await Vault.deploy(await verifier.getAddress());
    await v.waitForDeployment();
    return v;
  }

  async function installEngine(vault: WalletWallVault, engine: string) {
    await vault.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();
  }

  async function installEngineSim(sim: StablecoinVaultSimulator, engine: string) {
    await sim.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await sim.connect(admin).applyPolicyEngine();
  }

  // ---------------------------------------------------------------------
  // Subject-scoped configuration and reads.
  //
  // Every bucket is (consumer, owner, asset). These helpers take the consumer
  // as a contract handle so a test can never silently read one subject while
  // arming another — the mistake that a bare owner-keyed API made easy.
  // ---------------------------------------------------------------------
  interface HasAddress {
    getAddress(): Promise<string>;
  }

  /** Delegates `admitterContract` (default: the consumer itself) and arms `limit`. */
  async function armFor(
    signer: HardhatEthersSigner,
    consumer: HasAddress,
    limit: bigint,
    asset: string = NATIVE_ASSET,
    admitterContract?: HasAddress,
  ) {
    const consumerAddress = await consumer.getAddress();
    const delegate = admitterContract ? await admitterContract.getAddress() : consumerAddress;
    await policy.connect(signer).setAdmitter(consumerAddress, asset, delegate, true);
    await policy.connect(signer).setDailyLimit(consumerAddress, asset, limit);
  }

  /** Remaining allowance for the (consumer, owner, asset) bucket. */
  async function allowanceFor(consumer: HasAddress, owner_: string, asset: string = NATIVE_ASSET) {
    return policy.remainingAllowance(await consumer.getAddress(), owner_, asset);
  }

  beforeEach(async function () {
    [admin, owner, recipient] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Bridge = await ethers.getContractFactory("PolicyControlBridge");
    const bridge = await Bridge.deploy(admin.address);
    await bridge.waitForDeployment();

    const Policy = await ethers.getContractFactory("DailySpendLimitPolicy");
    policy = await Policy.deploy(await bridge.getAddress());
    await policy.waitForDeployment();
  });

  // =====================================================================
  // PART 1 — TIME SEMANTICS
  // =====================================================================
  describe("TIME: the window is a rolling per-spend ledger, not a tumbling reset", function () {
    const LIMIT = ethers.parseEther("1");
    let vault: WalletWallVault;

    beforeEach(async function () {
      vault = await deployEthVault();
      await installEngine(vault, await policy.getAddress());
      await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("20") });
      await armFor(owner, vault, LIMIT);
    });

    it("BOUNDARY: a full-limit spend leaves nothing at t0 + WINDOW - 1 (one second before it expires)", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // One second BEFORE expiry: still the same window, allowance exhausted.
      const justBefore = t0 + WINDOW - 1;
      const req = request(owner.address, recipient.address, 1n, 1, justBefore + 3600);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(justBefore);
      await expect(vault.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("BOUNDARY: a spend expires at EXACTLY t0 + WINDOW (comparison is >=)", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // Exactly AT expiry: the full limit is available again.
      await expect(withdrawAt(vault, owner, LIMIT, 1, t0 + WINDOW)).to.emit(vault, "Withdrawn");
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);
    });

    it("BOUNDARY: remainingAllowance agrees with check() on both sides of the boundary", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);

      // Mine a block exactly one second before expiry and read the view there.
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // Mine a block exactly at expiry; the view reports a full fresh limit
      // even though no reset has been written to storage yet.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);
    });

    it("MAXIMUM BURST REFUSED: the old 2*LIMIT - 1 construction is denied at the boundary", async function () {
      // INVERTED. On the tumbling implementation every step below was admitted and this
      // test asserted a 1.99x burst across a ONE-SECOND interval. The construction is
      // replayed verbatim; only the expected outcome of the final step changed.
      const t0 = (await networkHelpers.time.latest()) + 10;

      // Anchor with the smallest spend the vault will accept (withdraw() rejects
      // amount == 0 with ZeroAmount). Under a rolling ledger this is no longer an
      // "anchor" at all — it is simply a 1-wei entry that expires at t0 + WINDOW.
      await withdrawAt(vault, owner, 1n, 0, t0);

      // Fill to the brim one second before that entry ages out.
      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(vault, owner, LIMIT - 1n, 1, tEnd)).to.emit(vault, "Withdrawn");
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // One second later, ONLY the 1-wei entry has expired. The tumbling window handed
      // back the entire limit here; the rolling ledger hands back exactly one wei.
      const tReset = t0 + WINDOW;
      await expect(withdrawAt(vault, owner, LIMIT, 2, tReset))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      await networkHelpers.time.increaseTo(tReset);
      expect(await allowanceFor(vault, owner.address)).to.equal(1n);

      // The most that can be admitted in that trailing 24h is LIMIT, reached exactly.
      await expect(withdrawAt(vault, owner, 1n, 2, tReset + 1)).to.emit(vault, "Withdrawn");
      const consumer = await vault.getAddress();
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);
    });

    it("MAXIMUM BURST REFUSED: a zero-amount check no longer buys a free anchor", async function () {
      // INVERTED. The exact-2x figure required a zero-amount check to move `windowStart`
      // at no allowance cost. A rolling ledger books amounts rather than anchors, so a
      // zero amount is a true no-op and the construction loses its free step.
      await policy.connect(owner).setAdmitter(await vault.getAddress(), NATIVE_ASSET, owner.address, true);

      const consumer = await vault.getAddress();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await networkHelpers.time.setNextBlockTimestamp(t0);
      await policy
        .connect(owner)
        .check({ consumer, owner: owner.address, asset: NATIVE_ASSET }, recipient.address, 0n, 0n);

      // It changed nothing: no allowance consumed, and — the part that used to matter —
      // no ledger entry created, so nothing exists to expire at t0 + WINDOW.
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);

      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(vault, owner, LIMIT, 0, tEnd)).to.emit(vault, "Withdrawn");
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // The second full limit, which used to complete an exact 2x, is refused.
      await expect(withdrawAt(vault, owner, LIMIT, 1, t0 + WINDOW))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      // It only becomes admissible a full WINDOW after the spend it follows.
      await expect(withdrawAt(vault, owner, LIMIT, 1, tEnd + WINDOW)).to.emit(vault, "Withdrawn");
    });

    it("CADENCE: full-limit spends are admissible exactly WINDOW apart, and never sooner", async function () {
      // RETAINED, REINTERPRETED. On the tumbling implementation this was the proof that
      // the burst ceiling was 2x and not 3x. Every step still passes, but it no longer
      // demonstrates a ceiling ABOVE the limit: spends exactly WINDOW apart never share
      // a trailing 24h interval, so the total inside any such interval is exactly LIMIT.
      // It now reads as the cadence a fully-spending subject may sustain.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);

      const secondAnchor = t0 + WINDOW;
      await expect(withdrawAt(vault, owner, LIMIT, 1, secondAnchor)).to.emit(vault, "Withdrawn");
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      // Denied one second in, and still denied at the LAST instant before the
      // third window may open. Nothing in between reopens it.
      for (const t of [secondAnchor + 1, secondAnchor + WINDOW - 1]) {
        const req = request(owner.address, recipient.address, 1n, 2, t + 3600);
        const sigs = await signEth(vault, owner, req);
        await networkHelpers.time.setNextBlockTimestamp(t);
        await expect(vault.withdraw(req, sigs.ecdsaSig, sigs.pqSig))
          .to.be.revertedWithCustomError(vault, "PolicyViolation")
          .withArgs("daily limit exceeded");
      }

      // And admitted at EXACTLY secondAnchor + WINDOW -- the earliest third reset.
      await expect(withdrawAt(vault, owner, LIMIT, 2, secondAnchor + WINDOW)).to.emit(vault, "Withdrawn");

      // That instant is a full WINDOW after the second window opened, so the 24h
      // interval that held windows N and N+1 cannot also hold N+2.
      expect(secondAnchor + WINDOW - secondAnchor).to.equal(WINDOW);
      expect(secondAnchor + WINDOW).to.be.greaterThan(t0 + WINDOW + (WINDOW - 1));
    });

    it("NO CALENDAR: expiry is measured from each spend, not from a fixed calendar boundary", async function () {
      // There is no shared anchor to drift: each entry expires a WINDOW after ITSELF,
      // wherever in the day it happened to fall.
      const t0 = (await networkHelpers.time.latest()) + 1000;
      await withdrawAt(vault, owner, ethers.parseEther("0.1"), 0, t0);

      const windowStartProbe = await allowanceFor(vault, owner.address);
      expect(windowStartProbe).to.equal(LIMIT - ethers.parseEther("0.1"));

      // Still the same window one second before expiry.
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT - ethers.parseEther("0.1"));

      // Fresh window from the instant of expiry, wherever t0 happened to fall.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);
    });

    it("ARMING IS NOT A SPEND: arming a limit puts nothing on the ledger; only a spend does", async function () {
      // Arming writes `limit` and nothing else, so an idle subject accumulates no
      // history however long it waits. Under the tumbling model this mattered because
      // whoever made the first spend CHOSE where the shared 24h boundary fell; now
      // there is no shared boundary to choose, and this asserts only that configuration
      // alone never consumes allowance.
      const armedAt = await networkHelpers.time.latest();
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);

      // Sit idle for most of a day. No window has started, so nothing expires.
      await networkHelpers.time.increaseTo(armedAt + WINDOW * 3);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);

      // The first spend lands here, three days after arming, and expires a WINDOW later.
      const anchor = armedAt + WINDOW * 3 + 10;
      await withdrawAt(vault, owner, LIMIT, 0, anchor);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);

      await networkHelpers.time.increaseTo(anchor + WINDOW - 1);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);
      await networkHelpers.time.increaseTo(anchor + WINDOW);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);
    });

    it("DENIED ATTEMPTS BOOK NOTHING: a refused request leaves the ledger untouched", async function () {
      // Expiry is computed into locals and only persisted on the admit path, so a
      // denied request writes no entry and advances no index. Under the tumbling model
      // this is what held the burst to 2x; under the rolling ledger it is what stops a
      // stream of over-limit attempts from planting history or consuming capacity.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);

      // After expiry, attempt more than a full limit — the reset is computed but the
      // request is denied, so nothing is written.
      const afterExpiry = t0 + WINDOW;
      const tooBig = request(owner.address, recipient.address, LIMIT * 2n, 1, afterExpiry + 3600);
      const sigs = await signEth(vault, owner, tooBig);
      await networkHelpers.time.setNextBlockTimestamp(afterExpiry);
      await expect(vault.withdraw(tooBig, sigs.ecdsaSig, sigs.pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      // Nothing was booked at afterExpiry: the next ADMITTED spend is the only thing
      // that creates an entry, and that entry runs a full WINDOW from its own instant.
      const admitAt = afterExpiry + 500;
      await expect(withdrawAt(vault, owner, LIMIT, 1, admitAt)).to.emit(vault, "Withdrawn");
      await networkHelpers.time.increaseTo(admitAt + WINDOW - 1);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);
      await networkHelpers.time.increaseTo(admitAt + WINDOW);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT);
    });

    it("QUEUED PATH: spend books at queue time and a cancellation does NOT return the allowance", async function () {
      const threshold = ethers.parseEther("0.2");
      await vault.connect(admin).proposeLargeTxParams(threshold, 3 * 24 * 60 * 60);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyLargeTxParams();

      const amount = ethers.parseEther("0.9");
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const req = request(owner.address, recipient.address, amount, 0, deadline);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await vault.queueWithdrawal(req, ecdsaSig, pqSig);

      // Booked at QUEUE time, before any settlement.
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT - amount);

      // Cancelling refunds the vault balance but not the daily allowance.
      const pending = await vault.pendingWithdrawals(owner.address);
      const balanceBefore = (await vault.getVault(owner.address)).balance;
      await vault.connect(owner).cancelPendingWithdrawal(pending.operationId);
      expect((await vault.getVault(owner.address)).balance).to.equal(balanceBefore + amount);
      expect(await allowanceFor(vault, owner.address)).to.equal(LIMIT - amount);
    });

    it("NO RAW/EFFECTIVE SPLIT: rollingSpent and remainingAllowance always agree", async function () {
      // INVERTED. This test used to pin a DISAGREEMENT: `windowSpent` was a raw
      // accumulator that did not decay, so for up to a full day it reported a tenant
      // exhausted while `remainingAllowance` reported them free. That split was a real
      // trap for anyone computing headroom as `limit - windowSpent`, and the getters
      // that created it are gone. Both survivors now compute expiry through the SAME
      // routine the admission path uses, so the two can no longer drift apart.
      const consumer = await vault.getAddress();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);

      const agree = async () => {
        const spent = await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET);
        const remaining = await allowanceFor(vault, owner.address);
        expect(spent + remaining).to.equal(LIMIT);
        return { spent, remaining };
      };

      expect((await agree()).spent).to.equal(LIMIT);

      // Step past the boundary WITHOUT spending anything. No transaction runs, so raw
      // storage cannot have changed — yet both views decay together, because both are
      // evaluated against the calling block's timestamp rather than read from a field.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect((await agree()).spent).to.equal(0n);

      // And they stay in agreement across a partial spend.
      await withdrawAt(vault, owner, LIMIT / 4n, 1, t0 + WINDOW + 5);
      const after = await agree();
      expect(after.spent).to.equal(LIMIT / 4n);
      expect(after.remaining).to.equal(LIMIT - LIMIT / 4n);
    });
  });

  // =====================================================================
  // PART 2 — SCOPE SEMANTICS
  // =====================================================================
  describe("SCOPE: accounting is keyed by the full (consumer, owner, asset) subject", function () {
    // INVERTED BY THE POLICY-SUBJECT PROPAGATION CHANGE.
    //
    // Every test in this block previously asserted a COLLAPSE: one accumulator shared
    // across vault contracts, one scalar shared across incommensurable denominations,
    // one bucket shared by every consumer behind a composite. Those were faithful
    // characterizations of owner-only keying. They now assert the collapse's absence.
    //
    // The one test that did NOT change is TENANT ISOLATION: owner-keying was always
    // correct for the tenant dimension, and it remains the control proving these tests
    // can still observe a shared bucket when one legitimately exists.

    it("STATE MODEL: one policy instance holds independent state per consumer", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const a = await vaultA.getAddress();
      const b = await vaultB.getAddress();

      await armFor(owner, vaultA, ethers.parseEther("1"));
      await armFor(owner, vaultB, ethers.parseEther("7"));

      // Two limits, two delegation lists, two counters — for ONE owner.
      expect(await policy.dailyLimit(a, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("1"));
      expect(await policy.dailyLimit(b, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("7"));
      expect(await policy.admitter(a, owner.address, NATIVE_ASSET, a)).to.equal(true);
      expect(await policy.admitter(b, owner.address, NATIVE_ASSET, b)).to.equal(true);
      // A delegation for one consumer confers nothing for the other.
      expect(await policy.admitter(a, owner.address, NATIVE_ASSET, b)).to.equal(false);
      expect(await policy.admitterCount(a, owner.address, NATIVE_ASSET)).to.equal(1n);
      expect(await policy.admitterCount(b, owner.address, NATIVE_ASSET)).to.equal(1n);
    });

    it("CROSS-VAULT: two separately-authorized vault contracts hold INDEPENDENT accumulators", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      await armFor(owner, vaultA, ethers.parseEther("1"));
      await armFor(owner, vaultB, ethers.parseEther("1"));

      // Vault A consumes its OWN whole allowance.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("1"), 0, t0);
      expect(await allowanceFor(vaultA, owner.address)).to.equal(0n);

      // Vault B is untouched and still admits — the previous behaviour denied here.
      expect(await allowanceFor(vaultB, owner.address)).to.equal(ethers.parseEther("1"));
      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultB, owner, req);
      await expect(vaultB.withdraw(req, ecdsaSig, pqSig)).to.emit(vaultB, "Withdrawn");
      expect(await allowanceFor(vaultB, owner.address)).to.equal(ethers.parseEther("0.5"));
      // …and spending in B did not refund or disturb A.
      expect(await allowanceFor(vaultA, owner.address)).to.equal(0n);
    });

    it("CROSS-VAULT (reversed): independence holds in the opposite order", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await armFor(owner, vaultA, ethers.parseEther("1"));
      await armFor(owner, vaultB, ethers.parseEther("1"));

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultB, owner, ethers.parseEther("1"), 0, t0);
      expect(await allowanceFor(vaultB, owner.address)).to.equal(0n);
      expect(await allowanceFor(vaultA, owner.address)).to.equal(ethers.parseEther("1"));

      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultA, owner, req);
      await expect(vaultA.withdraw(req, ecdsaSig, pqSig)).to.emit(vaultA, "Withdrawn");
    });

    it("CROSS-VAULT EXPIRY: a spend in one vault does not put anything on the other's ledger", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await armFor(owner, vaultA, ethers.parseEther("1"));
      await armFor(owner, vaultB, ethers.parseEther("1"));

      const a = await vaultA.getAddress();
      const b = await vaultB.getAddress();

      // Vault A books a half-limit entry at t0 on ITS ledger.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("0.5"), 0, t0);
      expect(await policy.oldestActiveEntry(a, owner.address, NATIVE_ASSET)).to.deep.equal([
        BigInt(t0),
        ethers.parseEther("0.5"),
      ]);
      // Vault B's ledger is still empty — A's spend put nothing on it.
      expect(await policy.activeEntryCount(b, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await allowanceFor(vaultB, owner.address)).to.equal(ethers.parseEther("1"));

      // Vault B books its OWN entry later, against its own full limit.
      await withdrawAt(vaultB, owner, ethers.parseEther("1"), 0, t0 + 5);
      expect(await policy.oldestActiveEntry(b, owner.address, NATIVE_ASSET)).to.deep.equal([
        BigInt(t0 + 5),
        ethers.parseEther("1"),
      ]);
      expect(await allowanceFor(vaultB, owner.address)).to.equal(0n);
      expect(await allowanceFor(vaultA, owner.address)).to.equal(ethers.parseEther("0.5"));

      // Each entry expires on its OWN clock, five seconds apart.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowanceFor(vaultA, owner.address)).to.equal(ethers.parseEther("1")); // A rolled
      expect(await allowanceFor(vaultB, owner.address)).to.equal(0n); // B has not
      await networkHelpers.time.increaseTo(t0 + 5 + WINDOW);
      expect(await allowanceFor(vaultB, owner.address)).to.equal(ethers.parseEther("1"));
    });

    it("CROSS-ASSET: wei and 6-decimal token base units never share a scalar", async function () {
      // One owner, two vault contracts denominated in different assets, one policy.
      const ethVault = await deployEthVault();

      const Token = await ethers.getContractFactory("MockUSDC");
      const token: MockUSDC = await Token.deploy();
      await token.waitForDeployment();

      const Sim = await ethers.getContractFactory("StablecoinVaultSimulator", admin);
      const sim: StablecoinVaultSimulator = await Sim.deploy(await token.getAddress(), await verifier.getAddress());
      await sim.waitForDeployment();

      const engine = await policy.getAddress();
      await installEngine(ethVault, engine);
      await installEngineSim(sim, engine);

      await ethVault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await sim.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);

      const deposit = 500_000_000n; // 500 mUSDC at 6 decimals
      await token.connect(owner).mint(owner.address, deposit);
      await token.connect(owner).approve(await sim.getAddress(), deposit);
      await sim.connect(owner).deposit(deposit);

      const tokenAddress = await token.getAddress();
      // Each limit is now expressed in ITS OWN denomination and cannot be mistaken for
      // the other: "1 ETH per day" and "200 mUSDC per day" are separate buckets.
      const ethLimit = ethers.parseEther("1");
      const usdcLimit = 200_000_000n;
      await armFor(owner, ethVault, ethLimit);
      await armFor(owner, sim, usdcLimit, tokenAddress);

      // Withdraw 100 mUSDC (1e8 base units) from the stablecoin vault.
      const usdcAmount = 100_000_000n;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const req = request(owner.address, recipient.address, usdcAmount, 0, deadline);
      const { ecdsaSig, pqSig } = await signToken(sim, owner, req);
      await expect(sim.withdraw(req, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");

      // Token units were debited from the TOKEN bucket only…
      expect(await allowanceFor(sim, owner.address, tokenAddress)).to.equal(usdcLimit - usdcAmount);
      // …and the wei-denominated bucket is untouched. Previously 1e8 base units were
      // subtracted from a 1e18 wei allowance directly.
      expect(await allowanceFor(ethVault, owner.address)).to.equal(ethLimit);
    });

    it("CROSS-ASSET (reversed): a token-scaled limit cannot deny trivial ETH spends", async function () {
      const ethVault = await deployEthVault();
      await installEngine(ethVault, await policy.getAddress());
      await ethVault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      const Token = await ethers.getContractFactory("MockUSDC");
      const token: MockUSDC = await Token.deploy();
      await token.waitForDeployment();
      const Sim = await ethers.getContractFactory("StablecoinVaultSimulator", admin);
      const sim: StablecoinVaultSimulator = await Sim.deploy(await token.getAddress(), await verifier.getAddress());
      await sim.waitForDeployment();

      // An owner reasoning in stablecoin base units sets "1000 mUSDC per day" — on the
      // TOKEN subject, where that number means what they think it means.
      await armFor(owner, sim, 1_000_000_000n, await token.getAddress());
      // The ETH subject is separately armed at a sane wei figure.
      await armFor(owner, ethVault, ethers.parseEther("1"));

      // 2 gwei of ETH is now trivially admitted; previously the token-scaled number was
      // read as wei (1 gwei) and denied it.
      const twoGwei = 2_000_000_000n;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const req = request(owner.address, recipient.address, twoGwei, 0, deadline);
      const { ecdsaSig, pqSig } = await signEth(ethVault, owner, req);
      await expect(ethVault.withdraw(req, ecdsaSig, pqSig)).to.emit(ethVault, "Withdrawn");
    });

    it("ETH vs ERC-20: address(0) and a token address are structurally distinct keys", async function () {
      const Token = await ethers.getContractFactory("MockUSDC");
      const token: MockUSDC = await Token.deploy();
      await token.waitForDeployment();
      const tokenAddress = await token.getAddress();

      const vault = await deployEthVault();
      const consumer = await vault.getAddress();

      expect(await policy.subjectKey({ consumer, owner: owner.address, asset: NATIVE_ASSET })).to.not.equal(
        await policy.subjectKey({ consumer, owner: owner.address, asset: tokenAddress }),
      );

      // And they behave as distinct buckets, not merely as distinct hashes.
      await armFor(owner, vault, ethers.parseEther("1"));
      await armFor(owner, vault, 500_000n, tokenAddress);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("1"));
      expect(await policy.dailyLimit(consumer, owner.address, tokenAddress)).to.equal(500_000n);
    });

    it("SAME CONSUMER + OWNER, DIFFERENT ASSET: independent buckets on ONE consumer", async function () {
      // Both production consumers are single-asset, so a multi-asset consumer is built
      // here on purpose — the subject is designed for one, and the dimension must be
      // exercised rather than assumed. FakeVaultMock mints `consumer: address(this)`
      // exactly as a real vault does, and lets the asset vary per call.
      const Token = await ethers.getContractFactory("MockUSDC");
      const tokenA: MockUSDC = await Token.deploy();
      const tokenB: MockUSDC = await Token.deploy();
      await tokenA.waitForDeployment();
      await tokenB.waitForDeployment();
      const assetA = await tokenA.getAddress();
      const assetB = await tokenB.getAddress();

      const Fake = await ethers.getContractFactory("FakeVaultMock", admin);
      const multiAsset = await Fake.deploy(await policy.getAddress());
      await multiAsset.waitForDeployment();
      const consumer = await multiAsset.getAddress();

      // One consumer, one owner, two assets — each armed and delegated separately.
      await policy.connect(owner).setAdmitter(consumer, assetA, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, assetA, 1_000n);
      await policy.connect(owner).setAdmitter(consumer, assetB, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, assetB, 1_000n);

      // Exhaust asset A entirely through the consumer's own admission path.
      await multiAsset.admit(owner.address, assetA, recipient.address, 1_000n, 0n);
      expect(await policy.remainingAllowance(consumer, owner.address, assetA)).to.equal(0n);
      // Asset B is untouched, on the very same consumer and owner.
      expect(await policy.remainingAllowance(consumer, owner.address, assetB)).to.equal(1_000n);

      // And B still admits.
      await multiAsset.admit(owner.address, assetB, recipient.address, 1_000n, 0n);
      expect(await policy.remainingAllowance(consumer, owner.address, assetB)).to.equal(0n);
    });

    it("NO NORMALIZATION: the amount reaching the policy is the raw request amount", async function () {
      // Proves the value is passed through untouched — no decimals lookup,
      // no oracle, no quote conversion anywhere on the path.
      const ethVault = await deployEthVault();
      await installEngine(ethVault, await policy.getAddress());
      await ethVault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await armFor(owner, ethVault, ethers.parseEther("1"));

      const odd = 123_456_789n; // an amount no scaling factor would preserve
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(ethVault, owner, odd, 0, t0);
      expect(await allowanceFor(ethVault, owner.address)).to.equal(ethers.parseEther("1") - odd);
    });

    it("COMPOSITE AMPLIFICATION: one shared composite serves several consumers WITHOUT merging them", async function () {
      // THE #170 WORKAROUND, RETIRED. The previous release documented that a
      // CompositePolicyEngine must never be shared across consumers, because the
      // module saw only the owner and every vault behind the composite drew on one
      // bucket. This test asserted that merge. It now asserts separation: the subject
      // survives the composite, so sharing is mechanically safe.
      const Composite = await ethers.getContractFactory("CompositePolicyEngine", admin);
      const composite: CompositePolicyEngine = await Composite.deploy();
      await composite.waitForDeployment();
      await composite.connect(admin).addModule(await policy.getAddress());

      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await composite.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      // The COMPOSITE owner registers both consumers.
      await composite.connect(admin).setAdmissionCaller(await vaultA.getAddress(), true);
      await composite.connect(admin).setAdmissionCaller(await vaultB.getAddress(), true);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      // The tenant delegates to the COMPOSITE — separately for each consumer's subject,
      // because authority is per subject even when the delegate is the same contract.
      await armFor(owner, vaultA, ethers.parseEther("1"), NATIVE_ASSET, composite);
      await armFor(owner, vaultB, ethers.parseEther("1"), NATIVE_ASSET, composite);

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("1"), 0, t0);
      expect(await allowanceFor(vaultA, owner.address)).to.equal(0n);

      // Through the SAME composite, vault B still has its own full allowance.
      expect(await allowanceFor(vaultB, owner.address)).to.equal(ethers.parseEther("1"));
      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultB, owner, req);
      await expect(vaultB.withdraw(req, ecdsaSig, pqSig)).to.emit(vaultB, "Withdrawn");
    });

    it("TENANT ISOLATION HOLDS: two owners inside one vault contract never share a bucket", async function () {
      // The control case, UNCHANGED by this PR. Owner keying was always correct for the
      // multi-tenant dimension; the consumer and asset dimensions are what were missing.
      // It also proves these tests can still observe a shared bucket where one exists.
      const [, , , second] = await ethers.getSigners();
      const vault = await deployEthVault();
      await installEngine(vault, await policy.getAddress());

      await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vault.connect(second).createVault(second.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      await armFor(owner, vault, ethers.parseEther("1"));
      await armFor(second, vault, ethers.parseEther("1"));

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, ethers.parseEther("1"), 0, t0);
      expect(await allowanceFor(vault, owner.address)).to.equal(0n);
      expect(await allowanceFor(vault, second.address)).to.equal(ethers.parseEther("1"));

      const req = request(second.address, recipient.address, ethers.parseEther("1"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vault, second, req);
      await expect(vault.withdraw(req, ecdsaSig, pqSig)).to.emit(vault, "Withdrawn");
    });
  });
});
