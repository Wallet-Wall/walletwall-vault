import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier, DailySpendLimitPolicy } from "../typechain-types";
import { WITHDRAWAL_TYPES } from "./helpers/vaultHelpers";
import { NATIVE_ASSET } from "./helpers/policySubject";

/**
 * DailySpendLimitPolicy — TRUE ROLLING 24-HOUR ENFORCEMENT.
 *
 * test/DailySpendWindowSemantics.test.ts is the historical record: it characterized the
 * TUMBLING window and pinned the `2 * limit` boundary burst as a fact. This suite is the
 * adversarial matrix for the ledger that REPLACED it, and it exists to establish the
 * invariant itself rather than to exercise implementation lines:
 *
 *   For subject S and instant T:
 *     sum{ a : (t, a) admitted for S, t > T - WINDOW } <= limit(S)
 *
 * BOUNDARY CONVENTION. A spend booked at `t` is counted while `block.timestamp < t +
 * WINDOW` and expires at EXACTLY `t + WINDOW`. The active set is the half-open interval
 * `(T - WINDOW, T]`. Every assertion below is written against that convention, so an
 * off-by-one in either direction breaks a test rather than silently widening the cap.
 */
describe("DailySpendLimitPolicy — true rolling 24h enforcement", function () {
  const WINDOW = 24 * 60 * 60;
  const HOUR = 60 * 60;
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;
  const LIMIT = ethers.parseEther("1");

  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let admin: HardhatEthersSigner;

  let verifier: MockMLDSAVerifier;
  let policy: DailySpendLimitPolicy;
  let vault: WalletWallVault;

  async function ethDomain(v: WalletWallVault) {
    return {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await v.getAddress(),
    };
  }

  function request(vaultOwner: string, to: string, amount: bigint, nonce: number, deadline: number) {
    return { vaultOwner, recipient: to, amount, nonce, deadline, vaultMode: HYBRID };
  }

  async function signEth(v: WalletWallVault, signer: HardhatEthersSigner, req: object) {
    const ecdsaSig = await signer.signTypedData(await ethDomain(v), WITHDRAWAL_TYPES, req);
    const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { ecdsaSig, pqSig };
  }

  /** Submits an ETH withdrawal in a block whose timestamp is exactly `at`. */
  async function withdrawAt(signer: HardhatEthersSigner, amount: bigint, nonce: number, at: number) {
    const req = request(signer.address, recipient.address, amount, nonce, at + HOUR);
    const { ecdsaSig, pqSig } = await signEth(vault, signer, req);
    await networkHelpers.time.setNextBlockTimestamp(at);
    return vault.withdraw(req, ecdsaSig, pqSig);
  }

  /** Remaining rolling allowance for the (vault, owner, ETH) bucket. */
  async function allowance() {
    return policy.remainingAllowance(await vault.getAddress(), owner.address, NATIVE_ASSET);
  }

  async function rollingSpent() {
    return policy.rollingSpent(await vault.getAddress(), owner.address, NATIVE_ASSET);
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

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());
    await vault.waitForDeployment();

    await vault.connect(admin).proposePolicyEngine(await policy.getAddress());
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("50") });

    const consumer = await vault.getAddress();
    await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
    await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);
  });

  // =====================================================================
  // PART A — THE ROLLING INVARIANT
  // =====================================================================
  describe("A — allowance decays per spend, not per window", function () {
    it("A1 PARTIAL EXPIRY: allowance returns incrementally as individual spends age out", async function () {
      // THE test that separates rolling from tumbling. Under the old model, the instant
      // the anchor expired the WHOLE accumulator reset to `limit`. Under a rolling
      // ledger each spend carries its own expiry, so headroom returns in the same
      // increments it was consumed — and at the exact instants those spends age out.
      const t0 = (await networkHelpers.time.latest()) + 10;
      const first = ethers.parseEther("0.3");
      const second = ethers.parseEther("0.4");

      await withdrawAt(owner, first, 0, t0);
      expect(await allowance()).to.equal(LIMIT - first);

      await withdrawAt(owner, second, 1, t0 + 6 * HOUR);
      expect(await allowance()).to.equal(LIMIT - first - second);

      // t0 + 23h: both spends are still inside the trailing window.
      await networkHelpers.time.increaseTo(t0 + 23 * HOUR);
      expect(await allowance()).to.equal(LIMIT - first - second);

      // t0 + WINDOW: the FIRST spend expires — and ONLY it. A tumbling window would
      // report the full LIMIT here; a rolling one still withholds `second`.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowance()).to.equal(LIMIT - second);
      expect(await rollingSpent()).to.equal(second);

      // t0 + 6h + WINDOW: the second expires and the ledger is empty.
      await networkHelpers.time.increaseTo(t0 + 6 * HOUR + WINDOW);
      expect(await allowance()).to.equal(LIMIT);
      expect(await rollingSpent()).to.equal(0n);
    });

    it("A2 OLD 2x EXPLOIT CLOSED: `limit - 1` before the boundary then `limit` after is DENIED", async function () {
      // The exact construction pinned as reachable in DailySpendWindowSemantics.test.ts
      // ("MAXIMUM BURST: 2*LIMIT - 1 wei is admitted across a 1-second interval"),
      // re-run against the rolling ledger. Only the 1-wei anchor ages out at the
      // boundary, so only 1 wei of headroom returns.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, 1n, 0, t0);

      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(owner, LIMIT - 1n, 1, tEnd)).to.emit(vault, "Withdrawn");
      expect(await allowance()).to.equal(0n);

      // One second later the anchor — and nothing else — expires.
      const tReset = t0 + WINDOW;
      await expect(withdrawAt(owner, LIMIT, 2, tReset))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      // Exactly the 1 wei that aged out is available, and not one wei more.
      await networkHelpers.time.increaseTo(tReset);
      expect(await allowance()).to.equal(1n);
      await expect(withdrawAt(owner, 2n, 2, tReset + 1))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
      await expect(withdrawAt(owner, 1n, 2, tReset + 2)).to.emit(vault, "Withdrawn");

      // Trailing 24h ending at tReset + 2 holds (LIMIT - 1) + 1 == LIMIT. At the cap,
      // never above it.
      expect(await rollingSpent()).to.equal(LIMIT);
      expect(await allowance()).to.equal(0n);
    });

    it("A3 ZERO-AMOUNT ANCHOR CLOSED: a zero-amount check books nothing and anchors nothing", async function () {
      // The old exact-2x construction needed a free anchor: a zero-amount check that
      // moved `windowStart` without consuming allowance. A rolling ledger books
      // amounts, not anchors, so a zero amount is a genuine no-op — it must not
      // create an entry, must not consume ring capacity, and must not shift any expiry.
      const consumer = await vault.getAddress();
      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, owner.address, true);

      const t0 = (await networkHelpers.time.latest()) + 10;
      await networkHelpers.time.setNextBlockTimestamp(t0);
      await policy
        .connect(owner)
        .check({ consumer, owner: owner.address, asset: NATIVE_ASSET }, recipient.address, 0n, 0n);

      expect(await allowance()).to.equal(LIMIT);
      expect(await rollingSpent()).to.equal(0n);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);

      // The full-limit spend one second before the OLD boundary is admitted…
      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(owner, LIMIT, 0, tEnd)).to.emit(vault, "Withdrawn");

      // …and the second full limit at the old reset instant is now refused, because
      // the zero-amount call left nothing to expire.
      await expect(withdrawAt(owner, LIMIT, 1, t0 + WINDOW))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("A4 REPEATED CROSSING: STAGGERED spends make the trailing total a staircase, never a reset", async function () {
      // Deliberately staggered by half a window, because evenly-spaced full-limit
      // spends do NOT discriminate: under BOTH models a spend exactly WINDOW after the
      // last one is admissible, so a test built that way passes on the defective
      // contract and detects nothing. Splitting the limit across two half-window
      // offsets forces the two models apart at the FIRST boundary — a tumbling window
      // hands back the whole limit there, a rolling one hands back exactly the half
      // that aged out.
      const HALF = LIMIT / 2n;
      const t0 = (await networkHelpers.time.latest()) + 10;
      let nonce = 0;

      await withdrawAt(owner, HALF, nonce++, t0);
      await withdrawAt(owner, HALF, nonce++, t0 + 12 * HOUR);
      expect(await allowance()).to.equal(0n);

      // First boundary: only the t0 half has aged out. A tumbling window would admit a
      // full LIMIT here — that is the reset this whole change removes.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowance()).to.equal(HALF);
      await expect(withdrawAt(owner, LIMIT, nonce, t0 + WINDOW + 1))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
      await expect(withdrawAt(owner, HALF, nonce++, t0 + WINDOW + 2)).to.emit(vault, "Withdrawn");
      expect(await allowance()).to.equal(0n);

      // Second boundary, half a window later: the t0 + 12h half ages out and exactly
      // that much returns — the staircase continues rather than resetting.
      await networkHelpers.time.increaseTo(t0 + 12 * HOUR + WINDOW);
      expect(await allowance()).to.equal(HALF);
      await expect(withdrawAt(owner, HALF, nonce++, t0 + 12 * HOUR + WINDOW + 1)).to.emit(vault, "Withdrawn");
      expect(await allowance()).to.equal(0n);

      // Third boundary: the t0 + WINDOW + 2 half ages out on its own schedule.
      await networkHelpers.time.increaseTo(t0 + WINDOW + 2 + WINDOW);
      expect(await allowance()).to.equal(HALF);
      expect(await rollingSpent()).to.equal(HALF);
    });
  });

  // =====================================================================
  // PART B — THE EXACT BOUNDARY INSTANT
  // =====================================================================
  describe("B — boundary convention: live while now < at + WINDOW", function () {
    it("B1: an entry is still counted at at + WINDOW - 1, and expires at EXACTLY at + WINDOW", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);

      // The three instants that matter, walked in order. One second before expiry the
      // entry is fully counted; AT expiry it is fully gone; a second later nothing has
      // changed again (an entry expires once, not progressively).
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await rollingSpent()).to.equal(LIMIT);
      expect(await allowance()).to.equal(0n);

      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await rollingSpent()).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);

      await networkHelpers.time.increaseTo(t0 + WINDOW + 1);
      expect(await rollingSpent()).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);
    });

    it("B2: a spend at at + WINDOW - 1 carries its OWN expiry, not the previous entry's", async function () {
      // The defect a naive port would reintroduce: letting a later spend inherit the
      // window of an earlier one. Each entry must expire a full WINDOW after ITSELF.
      const t0 = (await networkHelpers.time.latest()) + 10;
      const half = LIMIT / 2n;

      await withdrawAt(owner, half, 0, t0);
      const late = t0 + WINDOW - 1;
      await withdrawAt(owner, half, 1, late);
      expect(await rollingSpent()).to.equal(LIMIT);

      // First expires on schedule; the second must survive almost a whole further day.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await rollingSpent()).to.equal(half);

      await networkHelpers.time.increaseTo(late + WINDOW - 1);
      expect(await rollingSpent()).to.equal(half);
      await networkHelpers.time.increaseTo(late + WINDOW);
      expect(await rollingSpent()).to.equal(0n);
    });

    it("B3: oldestActiveEntry names the instant allowance next returns, and how much", async function () {
      const consumer = await vault.getAddress();
      const t0 = (await networkHelpers.time.latest()) + 10;
      const first = ethers.parseEther("0.25");

      expect(await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET)).to.deep.equal([0n, 0n]);

      await withdrawAt(owner, first, 0, t0);
      await withdrawAt(owner, ethers.parseEther("0.5"), 1, t0 + HOUR);

      const [at, amount] = await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET);
      expect(at).to.equal(BigInt(t0));
      expect(amount).to.equal(first);

      // Its promise is executable: exactly `amount` returns at exactly `at + WINDOW`.
      const before = await allowance();
      await networkHelpers.time.increaseTo(Number(at) + WINDOW);
      expect(await allowance()).to.equal(before + first);
    });
  });

  // =====================================================================
  // PART C — SEVERAL ADMISSIONS IN ONE BLOCK
  // =====================================================================
  describe("C — same-timestamp admissions", function () {
    it("C1: admissions sharing a block coalesce into ONE entry when representable, and total exactly", async function () {
      const Batch = await ethers.getContractFactory("DailySpendBatchAdmitterMock");
      const batch = await Batch.deploy(await policy.getAddress());
      await batch.waitForDeployment();
      const consumer = await batch.getAddress();

      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      const parts = [ethers.parseEther("0.1"), ethers.parseEther("0.2"), ethers.parseEther("0.3")];
      await batch.admitBatch(owner.address, NATIVE_ASSET, parts);

      // Asked three separate times, the ledger arrives at the same total as one spend…
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("0.6"));
      // …and holds it in a SINGLE slot, because the three share an expiry instant and
      // their combined amount is representable. D2d covers the case where it is not:
      // coalescing is declined and a second entry is appended at the same instant, so
      // the cap counts ENTRIES rather than distinct seconds.
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
    });

    it("C2: a coalesced entry expires as one, at a single instant", async function () {
      const Batch = await ethers.getContractFactory("DailySpendBatchAdmitterMock");
      const batch = await Batch.deploy(await policy.getAddress());
      await batch.waitForDeployment();
      const consumer = await batch.getAddress();

      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      const at = (await networkHelpers.time.latest()) + 10;
      await networkHelpers.time.setNextBlockTimestamp(at);
      await batch.admitBatch(owner.address, NATIVE_ASSET, [ethers.parseEther("0.4"), ethers.parseEther("0.4")]);

      await networkHelpers.time.increaseTo(at + WINDOW - 1);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("0.8"));
      await networkHelpers.time.increaseTo(at + WINDOW);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("C3: the limit binds ACROSS a same-block batch, not per sub-call", async function () {
      const Batch = await ethers.getContractFactory("DailySpendBatchAdmitterMock");
      const batch = await Batch.deploy(await policy.getAddress());
      await batch.waitForDeployment();
      const consumer = await batch.getAddress();

      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      // Three-quarters twice inside one block: the second must be refused. A policy that
      // evaluated each call against a stale pre-batch total would admit both.
      const threeQuarters = (LIMIT * 3n) / 4n;
      await expect(batch.admitBatch(owner.address, NATIVE_ASSET, [threeQuarters, threeQuarters]))
        .to.emit(batch, "Admission")
        .withArgs(1, false, "daily limit exceeded");

      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(threeQuarters);
    });
  });

  // =====================================================================
  // PART D — LEDGER CAPACITY AND BOUNDED WORK
  // =====================================================================
  describe("D — bounded ledger capacity", function () {
    it("D1: MAX_ACTIVE_ENTRIES entries fit; the next spend needing a new one is refused", async function () {
      const consumer = await vault.getAddress();
      const cap = Number(await policy.MAX_ACTIVE_ENTRIES());
      const each = LIMIT / BigInt(cap * 2); // half the limit across a full ledger

      const t0 = (await networkHelpers.time.latest()) + 10;
      for (let i = 0; i < cap; i++) {
        await withdrawAt(owner, each, i, t0 + i);
      }
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(BigInt(cap));

      // Allowance remains — this is a CAPACITY refusal, not a limit refusal, and the
      // reason string has to say so or an operator cannot tell them apart. Note what
      // this pins about the getters: remainingAllowance() reports a POSITIVE figure at
      // the same instant check() refuses. The two are not in conflict; they answer
      // different questions, and only activeEntryCount() answers the capacity one.
      expect(await allowance()).to.equal(LIMIT / 2n);
      await expect(withdrawAt(owner, each, cap, t0 + cap))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily spend ledger full");
    });

    it("D2: the capacity refusal is SELF-HEALING — a slot frees the instant the oldest expires", async function () {
      // The property that keeps a full ledger from being a brick. If capacity denial
      // were permanent this design would be unacceptable regardless of its exactness.
      const consumer = await vault.getAddress();
      const cap = Number(await policy.MAX_ACTIVE_ENTRIES());
      const each = LIMIT / BigInt(cap * 2);

      const t0 = (await networkHelpers.time.latest()) + 10;
      for (let i = 0; i < cap; i++) {
        await withdrawAt(owner, each, i, t0 + i);
      }
      await expect(withdrawAt(owner, each, cap, t0 + cap))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily spend ledger full");

      // At exactly t0 + WINDOW the first entry ages out and its slot is reusable.
      await expect(withdrawAt(owner, each, cap, t0 + WINDOW)).to.emit(vault, "Withdrawn");
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(BigInt(cap));
    });

    it("D3: at capacity a spend in the SAME second as the newest is still admitted", async function () {
      // Coalescing is attempted before capacity is consulted, so a full ledger never
      // refuses a spend it could absorb into the entry it already holds for that second.
      const consumer = await vault.getAddress();
      const cap = Number(await policy.MAX_ACTIVE_ENTRIES());
      const each = LIMIT / BigInt(cap * 4);

      // Deploy and delegate BEFORE the loop: each of those is its own block, so doing
      // them afterwards would advance the chain past the second the batch must land in.
      const Batch = await ethers.getContractFactory("DailySpendBatchAdmitterMock");
      const batch = await Batch.deploy(await policy.getAddress());
      await batch.waitForDeployment();
      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, await batch.getAddress(), true);

      const t0 = (await networkHelpers.time.latest()) + 10;
      for (let i = 0; i < cap - 1; i++) {
        await withdrawAt(owner, each, i, t0 + i);
      }
      const lastSecond = t0 + cap - 1;

      // Two admissions in ONE block: the first fills the final slot, the second must
      // coalesce into it rather than be refused for capacity.
      await networkHelpers.time.setNextBlockTimestamp(lastSecond);
      await expect(batch.admitBatchAs(consumer, owner.address, NATIVE_ASSET, [each, each])).to.not.revert(ethers);

      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(BigInt(cap));
      expect(await rollingSpent()).to.equal(each * BigInt(cap + 1));
    });

    it("D4: a full ledger expiring at once is pruned in ONE admission, within a normal gas budget", async function () {
      // The worst case the structure can require: MAX_ACTIVE_ENTRIES entries all aged
      // out, cleared by a single check(). Bounded by a CONSTANT — it does not grow with
      // lifetime withdrawal count, which is the property that makes the ledger safe.
      const consumer = await vault.getAddress();
      const cap = Number(await policy.MAX_ACTIVE_ENTRIES());
      const each = LIMIT / BigInt(cap * 2);

      const t0 = (await networkHelpers.time.latest()) + 10;
      for (let i = 0; i < cap; i++) {
        await withdrawAt(owner, each, i, t0 + i);
      }
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(BigInt(cap));

      // Jump past every entry's expiry, then spend once: this single call prunes all of
      // them. It must succeed, and its gas is the worst-case admission figure reported
      // in the PR.
      const tx = await withdrawAt(owner, each, cap, t0 + cap + WINDOW);
      const receipt = await tx.wait();
      expect(receipt).to.not.equal(null);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
      expect(await rollingSpent()).to.equal(each);
    });
  });

  // =====================================================================
  // PART D2 — ARITHMETIC EDGES NEAR type(uint256).max
  // =====================================================================
  describe("D2 — the bookable-amount ceiling denies cleanly, never panics", function () {
    // A ledger entry packs (uint64 timestamp, uint192 amount) into one slot, so an
    // amount above type(uint192).max cannot be represented. The failure mode chosen for
    // that is a DENIAL. The alternative — capping `limit` instead — is not available:
    // test/DailySpendAdmissionAuthority.test.ts B5 pins that an owner reaching for
    // "effectively unlimited" may still set type(uint256).max.
    let consumer: string;
    // A DISTINCT asset from the outer beforeEach's MAX_ASSET, so this subject is
    // genuinely fresh (limit defaults to 0) rather than already armed at LIMIT. Under
    // v0.13.0's policy-control authority, LIMIT -> MaxUint256 would be a RAISE — a
    // weakening, delayed rather than immediate — which is not what this block tests;
    // 0 -> MaxUint256 (arming from unrestricted) stays immediate, preserving this
    // block's actual intent: that MaxUint256 is settable as a limit at all.
    const MAX_ASSET = ethers.Wallet.createRandom().address;
    const subj = () => ({ consumer, owner: owner.address, asset: MAX_ASSET });

    beforeEach(async function () {
      consumer = await vault.getAddress();
      await policy.connect(owner).setAdmitter(consumer, MAX_ASSET, owner.address, true);
      await policy.connect(owner).setDailyLimit(consumer, MAX_ASSET, ethers.MaxUint256);
    });

    it("D2a: an armed limit of type(uint256).max is still settable", async function () {
      expect(await policy.dailyLimit(consumer, owner.address, MAX_ASSET)).to.equal(ethers.MaxUint256);
    });

    it("D2b: amount == type(uint256).max is DENIED with its own reason, not a panic", async function () {
      // Under the previous accumulator this construction reached a checked add and could
      // produce Panic(0x11) rather than a decision. A caller must be able to tell "I was
      // refused" from "the contract broke".
      const [allowed, reason] = await policy
        .connect(owner)
        .check.staticCall(subj(), recipient.address, ethers.MaxUint256, 0n);
      expect(allowed).to.equal(false);
      expect(reason).to.equal("amount exceeds bookable range");

      await expect(policy.connect(owner).check(subj(), recipient.address, ethers.MaxUint256, 0n)).to.not.revert(ethers);
      expect(await policy.activeEntryCount(consumer, owner.address, MAX_ASSET)).to.equal(0n);
      expect(await policy.rollingSpent(consumer, owner.address, MAX_ASSET)).to.equal(0n);
    });

    it("D2c: exactly MAX_BOOKABLE_AMOUNT is admitted and booked as one entry", async function () {
      // The boundary is inclusive on the admitted side, so the denial in D2b is about
      // representability and nothing else.
      const max = await policy.MAX_BOOKABLE_AMOUNT();
      const [allowed] = await policy.connect(owner).check.staticCall(subj(), recipient.address, max, 0n);
      expect(allowed).to.equal(true);

      await policy.connect(owner).check(subj(), recipient.address, max, 0n);
      expect(await policy.rollingSpent(consumer, owner.address, MAX_ASSET)).to.equal(max);
      expect(await policy.activeEntryCount(consumer, owner.address, MAX_ASSET)).to.equal(1n);
    });

    it("D2d: a second MAX_BOOKABLE_AMOUNT in the SAME second appends rather than overflowing", async function () {
      // Coalescing would overflow uint192 here, so it must be declined in favour of a
      // fresh entry. Both are still exact: two entries at the same instant expire
      // together, so the trailing total is the same either way.
      const Batch = await ethers.getContractFactory("DailySpendBatchAdmitterMock");
      const batch = await Batch.deploy(await policy.getAddress());
      await batch.waitForDeployment();
      await policy.connect(owner).setAdmitter(consumer, MAX_ASSET, await batch.getAddress(), true);

      const max = await policy.MAX_BOOKABLE_AMOUNT();
      const at = (await networkHelpers.time.latest()) + 10;
      await networkHelpers.time.setNextBlockTimestamp(at);
      await batch.admitBatchAs(consumer, owner.address, MAX_ASSET, [max, max]);

      expect(await policy.activeEntryCount(consumer, owner.address, MAX_ASSET)).to.equal(2n);
      expect(await policy.rollingSpent(consumer, owner.address, MAX_ASSET)).to.equal(max * 2n);

      // They still expire as one instant, together.
      await networkHelpers.time.increaseTo(at + WINDOW - 1);
      expect(await policy.rollingSpent(consumer, owner.address, MAX_ASSET)).to.equal(max * 2n);
      await networkHelpers.time.increaseTo(at + WINDOW);
      expect(await policy.rollingSpent(consumer, owner.address, MAX_ASSET)).to.equal(0n);
    });
  });

  // =====================================================================
  // PART E — LIMIT CHANGES MUST NOT REWRITE HISTORY
  // =====================================================================
  describe("E — raising, lowering, disarming and re-arming", function () {
    const consumerOf = async () => vault.getAddress();

    it("E1: raising the limit is a WEAKENING under v0.13.0 — delayed, not immediate — and never touches the ledger", async function () {
      // Historical note: prior to the policy-control authority lane (PR #171/#172),
      // setDailyLimit applied every value immediately. Raising a limit is now
      // deliberately delayed (POLICY_CONTROL_DELAY, 2 days — longer than WINDOW, so by
      // the time a raise matures the triggering spend has already aged out on its own
      // clock regardless) — this is the feature the lane exists to add, not a
      // regression. See docs/Policy_Control_Authority_Design.md §3.
      const POLICY_CONTROL_DELAY = 2 * 24 * 60 * 60;
      const consumer = await consumerOf();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);
      expect(await allowance()).to.equal(0n);

      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT * 3n);
      // Not yet applied — no immediate headroom, and proposing touched no ledger state.
      expect(await allowance()).to.equal(0n);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await rollingSpent()).to.equal(LIMIT);

      // POLICY_CONTROL_DELAY (2 days) exceeds WINDOW (24h), so by maturity the original
      // spend has already aged out on ITS OWN schedule — proving that fact, and that
      // applying the raise does not additionally touch the ledger beyond ordinary expiry.
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      expect(await rollingSpent()).to.equal(0n);
      await policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 3n);
      expect(await allowance()).to.equal(LIMIT * 3n);
      expect(await rollingSpent()).to.equal(0n);
    });

    it("E2: lowering the limit below trailing spend reports zero and denies, never reverts", async function () {
      const consumer = await consumerOf();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);

      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 4n);
      // Floored at zero rather than underflowing.
      expect(await allowance()).to.equal(0n);
      expect(await rollingSpent()).to.equal(LIMIT);

      await expect(withdrawAt(owner, 1n, 1, t0 + HOUR))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      // And it recovers on the ledger's schedule, not the setter's.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowance()).to.equal(LIMIT / 4n);
    });

    it("E3 ADVERSARIAL: a disarm/re-arm cycle does NOT reset rolling history", async function () {
      // The obvious way to make this contract wrong: treat setDailyLimit as a lifecycle
      // event and clear the ledger with it. Then `setDailyLimit(0)` followed by
      // `setDailyLimit(L)` would be a one-transaction allowance refill, defeating the
      // cap entirely for anyone who can call the setter.
      const consumer = await consumerOf();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);
      expect(await allowance()).to.equal(0n);

      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      // History survived the round trip untouched.
      expect(await rollingSpent()).to.equal(LIMIT);
      expect(await allowance()).to.equal(0n);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
      await expect(withdrawAt(owner, 1n, 1, t0 + HOUR))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");

      // It still expires when it always would have, not a window after re-arming.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await allowance()).to.equal(LIMIT);
    });

    it("E4: setDailyLimit touches the ledger in no way at all", async function () {
      // Under v0.13.0 only one weakening may be pending at a time (WeakeningAlreadyPending),
      // so this walks STRENGTHENING values only (each applies immediately, no pending
      // created) plus ONE weakening proposal — still enough to prove the claim: neither
      // an immediate strengthen nor a delayed-proposal creation ever touches the ledger.
      const consumer = await consumerOf();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, ethers.parseEther("0.4"), 0, t0);

      const beforeCount = await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET);
      const beforeSpent = await rollingSpent();
      const beforeOldest = await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET);

      // Strengthening values (n -> smaller, all immediate — no pending collision).
      for (const l of [LIMIT / 2n, LIMIT / 4n]) {
        await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, l);
        expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(beforeCount);
        expect(await rollingSpent()).to.equal(beforeSpent);
        expect(await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET)).to.deep.equal(beforeOldest);
      }

      // One weakening proposal (creates a PENDING record, distinct from the ledger).
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(beforeCount);
      expect(await rollingSpent()).to.equal(beforeSpent);
      expect(await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET)).to.deep.equal(beforeOldest);
    });
  });

  // =====================================================================
  // PART F — ADMISSION EXACTLY ONCE ACROSS THE QUEUED PATH
  // =====================================================================
  describe("F — queued withdrawals book once", function () {
    const THRESHOLD = ethers.parseEther("0.2");
    // Deliberately SHORTER than WINDOW, so a queued entry is still live at settlement
    // and "did finalization book again?" is actually observable. F4 covers the opposite
    // configuration, where the delay outlives the window.
    const DELAY = 2 * 60 * 60;

    beforeEach(async function () {
      await vault.connect(admin).proposeLargeTxParams(THRESHOLD, DELAY);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyLargeTxParams();
    });

    it("F1: queueing books ONE entry and finalization books none", async function () {
      // `revalidate()` is view, so it structurally cannot book — but the entry COUNT is
      // the assertion that matters for a ledger: a second entry would both double-spend
      // the allowance and consume a capacity slot.
      const consumer = await vault.getAddress();
      const amount = ethers.parseEther("0.9");
      const deadline = (await networkHelpers.time.latest()) + HOUR;
      const req = request(owner.address, recipient.address, amount, 0, deadline);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);

      await vault.queueWithdrawal(req, ecdsaSig, pqSig);
      expect(await rollingSpent()).to.equal(amount);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);

      const pending = await vault.pendingWithdrawals(owner.address);
      await networkHelpers.time.increase(DELAY + 1);
      await vault.connect(owner).finalizeWithdrawal(owner.address, pending.operationId);

      // Settlement moved money but not the ledger.
      expect(await rollingSpent()).to.equal(amount);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
    });

    it("F2: the queued entry expires from its QUEUE instant, not its finalize instant", async function () {
      // A rolling-specific question the tumbling model could not even pose. Booking at
      // queue time and expiring from finalize time would hold allowance hostage for the
      // whole large-tx delay ON TOP of the window.
      const amount = ethers.parseEther("0.9");
      const queuedAt = (await networkHelpers.time.latest()) + 10;
      const req = request(owner.address, recipient.address, amount, 0, queuedAt + HOUR);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(queuedAt);
      await vault.queueWithdrawal(req, ecdsaSig, pqSig);

      const pending = await vault.pendingWithdrawals(owner.address);
      await networkHelpers.time.increase(DELAY + 1);
      await vault.connect(owner).finalizeWithdrawal(owner.address, pending.operationId);

      // Finalization happened days later, yet the entry ages out on the QUEUE clock.
      await networkHelpers.time.increaseTo(queuedAt + WINDOW - 1);
      expect(await rollingSpent()).to.equal(amount);
      await networkHelpers.time.increaseTo(queuedAt + WINDOW);
      expect(await rollingSpent()).to.equal(0n);
    });

    it("F3: cancellation does NOT return allowance, and does not disturb the ledger", async function () {
      // PRESERVED SEMANTIC, restated for the ledger. The pre-existing contract is that
      // cancelling refunds the vault balance but not the daily allowance; changing that
      // would make cancel-and-requeue a way to spend without ever consuming the cap.
      const consumer = await vault.getAddress();
      const amount = ethers.parseEther("0.9");
      const queuedAt = (await networkHelpers.time.latest()) + 10;
      const req = request(owner.address, recipient.address, amount, 0, queuedAt + HOUR);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(queuedAt);
      await vault.queueWithdrawal(req, ecdsaSig, pqSig);

      const pending = await vault.pendingWithdrawals(owner.address);
      const balanceBefore = (await vault.getVault(owner.address)).balance;
      await vault.connect(owner).cancelPendingWithdrawal(pending.operationId);

      expect((await vault.getVault(owner.address)).balance).to.equal(balanceBefore + amount);
      expect(await rollingSpent()).to.equal(amount);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
      expect(await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET)).to.deep.equal([
        BigInt(queuedAt),
        amount,
      ]);

      // Re-queueing the same value is refused: the cancelled spend still occupies the
      // allowance until it ages out on its original schedule.
      const again = request(owner.address, recipient.address, amount, 1, queuedAt + HOUR);
      const sigs = await signEth(vault, owner, again);
      await expect(vault.queueWithdrawal(again, sigs.ecdsaSig, sigs.pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("F4 SCOPE: the cap governs ADMISSION, so a delay longer than WINDOW outlives its entry", async function () {
      // Named rather than hidden. `IPolicyEngine` defines check() as admission and
      // revalidate() as a non-mutating settlement test, so a queued spend consumes
      // allowance from the instant it is ADMITTED and releases it a WINDOW later —
      // even if the large-transaction delay means it has not settled yet.
      //
      // This does NOT let settled outflow exceed the cap. Settlement time is admission
      // time plus a per-withdrawal delay fixed at queue time, so admissions spaced at
      // least WINDOW apart settle at least WINDOW apart too; the spacing is shifted,
      // not compressed. It is recorded because it is the kind of thing an operator
      // reading "24-hour spend cap" would otherwise assume applies to payouts.
      const consumer = await vault.getAddress();
      const longDelay = WINDOW + HOUR;
      await vault.connect(admin).proposeLargeTxParams(THRESHOLD, longDelay);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyLargeTxParams();

      const amount = ethers.parseEther("0.9");
      const queuedAt = (await networkHelpers.time.latest()) + 10;
      const req = request(owner.address, recipient.address, amount, 0, queuedAt + HOUR);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(queuedAt);
      await vault.queueWithdrawal(req, ecdsaSig, pqSig);
      expect(await rollingSpent()).to.equal(amount);

      // The entry ages out while the withdrawal is still pending settlement.
      await networkHelpers.time.increaseTo(queuedAt + WINDOW);
      expect(await rollingSpent()).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);
      expect((await vault.pendingWithdrawals(owner.address)).exists).to.equal(true);

      // Settling it afterwards still books nothing.
      const pending = await vault.pendingWithdrawals(owner.address);
      await networkHelpers.time.increaseTo(queuedAt + longDelay + 1);
      await vault.connect(owner).finalizeWithdrawal(owner.address, pending.operationId);
      expect(await rollingSpent()).to.equal(0n);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });
  });

  // =====================================================================
  // PART G — ATOMICITY AND AUTHORITY
  // =====================================================================
  describe("G — revert atomicity and storage griefing", function () {
    it("G1: an outer transfer failure AFTER admission rolls the ledger back", async function () {
      // check() books before the vault performs its transfer, so a failed transfer must
      // unwind the booking with everything else. Anything less would let a griefer burn
      // a victim's allowance with withdrawals that never pay out.
      const consumer = await vault.getAddress();
      const Reject = await ethers.getContractFactory("RejectEther");
      const rejector = await Reject.deploy();
      await rejector.waitForDeployment();

      const amount = ethers.parseEther("0.5");
      const deadline = (await networkHelpers.time.latest()) + HOUR;
      const req = request(owner.address, await rejector.getAddress(), amount, 0, deadline);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);

      await expect(vault.withdraw(req, ecdsaSig, pqSig)).to.be.revertedWithCustomError(vault, "TransferFailed");

      expect(await rollingSpent()).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("G2: an unauthorized EOA cannot append an entry or consume ledger capacity", async function () {
      // The authority gate sits BEFORE the first ledger read, so a refused caller
      // reaches no state at all. Under a ring buffer this matters more than it did
      // under an accumulator: appending is now a way to consume a scarce slot, not just
      // to inflate a number.
      const consumer = await vault.getAddress();
      const subject = { consumer, owner: owner.address, asset: NATIVE_ASSET };

      for (let i = 0; i < 5; i++) {
        await expect(policy.connect(recipient).check(subject, recipient.address, 1n, 0n))
          .to.be.revertedWithCustomError(policy, "UnauthorizedAdmitter")
          .withArgs(recipient.address, consumer, owner.address, NATIVE_ASSET);
      }

      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await rollingSpent()).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);
    });

    it("G3: an unauthorized CONTRACT cannot plant history by naming the real vault", async function () {
      const consumer = await vault.getAddress();
      const Fake = await ethers.getContractFactory("FakeVaultMock");
      const fake = await Fake.deploy(await policy.getAddress());
      await fake.waitForDeployment();

      await expect(
        fake.admitAs(consumer, owner.address, NATIVE_ASSET, recipient.address, LIMIT, 0n),
      ).to.be.revertedWithCustomError(policy, "UnauthorizedAdmitter");

      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await allowance()).to.equal(LIMIT);
    });

    it("G4: a denied over-limit request writes nothing — no entry, no pruning, no index move", async function () {
      const consumer = await vault.getAddress();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, ethers.parseEther("0.6"), 0, t0);

      const before = await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET);
      for (let i = 0; i < 3; i++) {
        await expect(withdrawAt(owner, ethers.parseEther("0.9"), 1, t0 + 10 + i))
          .to.be.revertedWithCustomError(vault, "PolicyViolation")
          .withArgs("daily limit exceeded");
      }

      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(1n);
      expect(await policy.oldestActiveEntry(consumer, owner.address, NATIVE_ASSET)).to.deep.equal(before);
      expect(await rollingSpent()).to.equal(ethers.parseEther("0.6"));
    });
  });

  // =====================================================================
  // PART H — SUBJECT ISOLATION SURVIVES ROLLING ACCOUNTING
  // =====================================================================
  describe("H — the #171 subject isolation is not weakened", function () {
    it("H1: two consumers keep independent ledgers AND independent expiry clocks", async function () {
      const Vault = await ethers.getContractFactory("WalletWallVault", admin);
      const vaultB = await Vault.deploy(await verifier.getAddress());
      await vaultB.waitForDeployment();
      await vaultB.connect(admin).proposePolicyEngine(await policy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vaultB.connect(admin).applyPolicyEngine();
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      const b = await vaultB.getAddress();
      await policy.connect(owner).setAdmitter(b, NATIVE_ASSET, b, true);
      await policy.connect(owner).setDailyLimit(b, NATIVE_ASSET, LIMIT);

      const a = await vault.getAddress();
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);

      // A is exhausted; B is untouched and its ledger is empty.
      expect(await policy.remainingAllowance(a, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await policy.remainingAllowance(b, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await policy.activeEntryCount(b, owner.address, NATIVE_ASSET)).to.equal(0n);

      // B spends five seconds later; the two expire five seconds apart, each on its own.
      const reqB = request(owner.address, recipient.address, LIMIT, 0, t0 + HOUR);
      const sigsB = await signEth(vaultB as unknown as WalletWallVault, owner, reqB);
      await networkHelpers.time.setNextBlockTimestamp(t0 + 5);
      await vaultB.withdraw(reqB, sigsB.ecdsaSig, sigsB.pqSig);

      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await policy.remainingAllowance(a, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await policy.remainingAllowance(b, owner.address, NATIVE_ASSET)).to.equal(0n);
      await networkHelpers.time.increaseTo(t0 + 5 + WINDOW);
      expect(await policy.remainingAllowance(b, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("H2: a second tenant in the SAME vault has a wholly separate ledger", async function () {
      const consumer = await vault.getAddress();
      const other = admin;
      await vault.connect(other).createVault(other.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(other).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(other).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(owner, LIMIT, 0, t0);

      expect(await policy.remainingAllowance(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await policy.remainingAllowance(consumer, other.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await policy.activeEntryCount(consumer, other.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("H3: one subject filling its LEDGER does not consume another subject's capacity", async function () {
      // Capacity is per subject, like every other field in SpendState. A shared ring
      // would turn one busy tenant into a denial-of-service on every other tenant of
      // the same vault — a new cross-subject coupling of exactly the kind #171 removed.
      const consumer = await vault.getAddress();
      const cap = Number(await policy.MAX_ACTIVE_ENTRIES());
      const other = admin;
      await vault.connect(other).createVault(other.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(other).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(other).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);

      const each = LIMIT / BigInt(cap * 2);
      const t0 = (await networkHelpers.time.latest()) + 10;
      for (let i = 0; i < cap; i++) {
        await withdrawAt(owner, each, i, t0 + i);
      }
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(BigInt(cap));

      // The other tenant's ledger is still empty and their spend is admitted normally.
      expect(await policy.activeEntryCount(consumer, other.address, NATIVE_ASSET)).to.equal(0n);
      const reqO = request(other.address, recipient.address, each, 0, t0 + cap + HOUR);
      const sigsO = await signEth(vault, other, reqO);
      await networkHelpers.time.setNextBlockTimestamp(t0 + cap);
      await expect(vault.withdraw(reqO, sigsO.ecdsaSig, sigsO.pqSig)).to.emit(vault, "Withdrawn");
    });
  });
});
