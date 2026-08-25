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

/**
 * INVESTIGATION TESTS — DailySpendLimitPolicy time and scope semantics.
 *
 * These tests change NO production behaviour. They exist to make the CURRENT
 * behaviour of DailySpendLimitPolicy undeniable, so a semantics decision can be
 * made from evidence rather than from NatSpec prose.
 *
 * Two independent questions:
 *   TIME  — is the window rolling (any 24h interval capped) or tumbling (a fixed
 *           window that zeroes on the first call after expiry)?
 *   SCOPE — is spend accounting isolated per vault contract and per asset, or
 *           only per owner address?
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

  beforeEach(async function () {
    [admin, owner, recipient] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Policy = await ethers.getContractFactory("DailySpendLimitPolicy");
    policy = await Policy.deploy();
    await policy.waitForDeployment();
  });

  // =====================================================================
  // PART 1 — TIME SEMANTICS
  // =====================================================================
  describe("TIME: the window is tumbling (reset-on-first-call), not rolling", function () {
    const LIMIT = ethers.parseEther("1");
    let vault: WalletWallVault;

    beforeEach(async function () {
      vault = await deployEthVault();
      await installEngine(vault, await policy.getAddress());
      await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("20") });
      await policy.connect(owner).setAdmitter(await vault.getAddress(), true);
      await policy.connect(owner).setDailyLimit(LIMIT);
    });

    it("BOUNDARY: window is exhausted at windowStart + WINDOW - 1 (one second before expiry)", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // One second BEFORE expiry: still the same window, allowance exhausted.
      const justBefore = t0 + WINDOW - 1;
      const req = request(owner.address, recipient.address, 1n, 1, justBefore + 3600);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(justBefore);
      await expect(vault.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("BOUNDARY: the window resets at EXACTLY windowStart + WINDOW (comparison is >=)", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // Exactly AT expiry: the full limit is available again.
      await expect(withdrawAt(vault, owner, LIMIT, 1, t0 + WINDOW)).to.emit(vault, "Withdrawn");
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);
    });

    it("BOUNDARY: remainingAllowance agrees with check() on both sides of the boundary", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);

      // Mine a block exactly one second before expiry and read the view there.
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // Mine a block exactly at expiry; the view reports a full fresh limit
      // even though no reset has been written to storage yet.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);
    });

    it("MAXIMUM BURST: 2*LIMIT - 1 wei is admitted across a 1-second interval", async function () {
      const t0 = (await networkHelpers.time.latest()) + 10;

      // Anchor the window with the smallest spend the vault will accept
      // (withdraw() rejects amount == 0 with ZeroAmount).
      await withdrawAt(vault, owner, 1n, 0, t0);

      // Fill window N to the brim, one second before it expires.
      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(vault, owner, LIMIT - 1n, 1, tEnd)).to.emit(vault, "Withdrawn");
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // One second later the window has expired: the full limit is available.
      const tReset = t0 + WINDOW;
      await expect(withdrawAt(vault, owner, LIMIT, 2, tReset)).to.emit(vault, "Withdrawn");

      const burst = LIMIT - 1n + LIMIT;
      const elapsed = tReset - tEnd;
      expect(burst).to.equal(2n * LIMIT - 1n);
      expect(elapsed).to.equal(1);

      // The trailing 24h interval ending at tReset is [t0 + 1, t0 + WINDOW].
      // It contains the tEnd spend and the tReset spend, and excludes the
      // 1-wei anchor at t0 — so a genuine rolling cap of LIMIT is violated
      // by very nearly a factor of two.
      expect(burst).to.be.greaterThan(LIMIT);
      expect((burst * 100n) / LIMIT).to.equal(199n); // 1.99x, i.e. 2x minus one wei
    });

    it("MAXIMUM BURST: exactly 2*LIMIT when the window is anchored by a zero-amount check", async function () {
      // The vault path cannot send amount 0, but a self-delegated subject can
      // call the policy directly. A zero-amount check still writes _windowStart,
      // so it anchors a window at no allowance cost.
      await policy.connect(owner).setAdmitter(owner.address, true);

      const t0 = (await networkHelpers.time.latest()) + 10;
      await networkHelpers.time.setNextBlockTimestamp(t0);
      await policy.connect(owner).check(owner.address, recipient.address, 0n, 0n);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);

      const tEnd = t0 + WINDOW - 1;
      await expect(withdrawAt(vault, owner, LIMIT, 0, tEnd)).to.emit(vault, "Withdrawn");
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      const tReset = t0 + WINDOW;
      await expect(withdrawAt(vault, owner, LIMIT, 1, tReset)).to.emit(vault, "Withdrawn");

      // 2x the nominal limit, in a one-second wall-clock interval.
      expect(2n * LIMIT).to.equal(ethers.parseEther("2"));
      expect(tReset - tEnd).to.equal(1);
    });

    it("NO ROLLING GUARANTEE: a third window cannot be reached inside the same 24h interval", async function () {
      // Establishes the exact reachable bound: 2x, not 3x. Window N+2 cannot
      // start earlier than t0 + 2*WINDOW, which is outside the 24h interval
      // that already contains windows N and N+1.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, LIMIT, 0, t0);
      await expect(withdrawAt(vault, owner, LIMIT, 1, t0 + WINDOW)).to.emit(vault, "Withdrawn");

      // The latest instant still inside the 24h interval that began at t0 + 1.
      const stillSameRollingInterval = t0 + WINDOW + (WINDOW - 1) - (WINDOW - 1);
      expect(stillSameRollingInterval).to.equal(t0 + WINDOW);

      // One second after the second window opened, no further reset is available.
      const req = request(owner.address, recipient.address, 1n, 2, t0 + WINDOW + 3601);
      const { ecdsaSig, pqSig } = await signEth(vault, owner, req);
      await networkHelpers.time.setNextBlockTimestamp(t0 + WINDOW + 1);
      await expect(vault.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("ANCHOR DRIFT: the window anchors on the first ADMITTED spend, not on a fixed calendar boundary", async function () {
      // A denied check does not persist a reset, so the anchor is attacker-chosen.
      const t0 = (await networkHelpers.time.latest()) + 1000;
      await withdrawAt(vault, owner, ethers.parseEther("0.1"), 0, t0);

      const windowStartProbe = await policy.remainingAllowance(owner.address);
      expect(windowStartProbe).to.equal(LIMIT - ethers.parseEther("0.1"));

      // Still the same window one second before expiry.
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT - ethers.parseEther("0.1"));

      // Fresh window from the instant of expiry, wherever t0 happened to fall.
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);
    });

    it("ANCHOR IS SPEND-CHOSEN: arming a limit does not start a window; the first admitted spend does", async function () {
      // _windowStart is 0 until the first admitted check, and 0 + WINDOW is in the
      // distant past, so the first spend always resets. Whoever controls the first
      // spend therefore chooses where the 24h boundary falls — the boundary is not
      // fixed by the configuration, and not by any calendar.
      const armedAt = await networkHelpers.time.latest();
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);

      // Sit idle for most of a day. No window has started, so nothing expires.
      await networkHelpers.time.increaseTo(armedAt + WINDOW * 3);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);

      // The spend anchors the window here, three days after arming.
      const anchor = armedAt + WINDOW * 3 + 10;
      await withdrawAt(vault, owner, LIMIT, 0, anchor);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      await networkHelpers.time.increaseTo(anchor + WINDOW - 1);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);
      await networkHelpers.time.increaseTo(anchor + WINDOW);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);
    });

    it("DENIED ATTEMPTS DO NOT RE-ANCHOR: windows stay at least WINDOW apart", async function () {
      // The reset is computed into locals and only persisted on the admit path, so a
      // denial after expiry leaves _windowStart untouched. This is what makes the
      // reachable bound EXACTLY 2x rather than unbounded: successive window anchors
      // can never be closer together than WINDOW.
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

      // The anchor did not move to afterExpiry: a later admitted spend re-anchors
      // there instead, and its own window runs a full WINDOW from that point.
      const admitAt = afterExpiry + 500;
      await expect(withdrawAt(vault, owner, LIMIT, 1, admitAt)).to.emit(vault, "Withdrawn");
      await networkHelpers.time.increaseTo(admitAt + WINDOW - 1);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);
      await networkHelpers.time.increaseTo(admitAt + WINDOW);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT);
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
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT - amount);

      // Cancelling refunds the vault balance but not the daily allowance.
      const pending = await vault.pendingWithdrawals(owner.address);
      const balanceBefore = (await vault.getVault(owner.address)).balance;
      await vault.connect(owner).cancelPendingWithdrawal(pending.operationId);
      expect((await vault.getVault(owner.address)).balance).to.equal(balanceBefore + amount);
      expect(await policy.remainingAllowance(owner.address)).to.equal(LIMIT - amount);
    });
  });

  // =====================================================================
  // PART 2 — SCOPE SEMANTICS
  // =====================================================================
  describe("SCOPE: accounting is keyed by owner address only — no vault and no asset dimension", function () {
    it("STATE MODEL: nothing binds a policy instance to one vault contract", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();

      await policy.connect(owner).setAdmitter(await vaultA.getAddress(), true);
      await policy.connect(owner).setAdmitter(await vaultB.getAddress(), true);

      // Both delegations coexist; the policy has no notion of "my vault".
      expect(await policy.admitter(owner.address, await vaultA.getAddress())).to.equal(true);
      expect(await policy.admitter(owner.address, await vaultB.getAddress())).to.equal(true);
      expect(await policy.admitterCount(owner.address)).to.equal(2n);

      // There is exactly one limit and one allowance per owner, not per vault.
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      expect(await policy.dailyLimit(owner.address)).to.equal(ethers.parseEther("1"));
    });

    it("CROSS-VAULT: two separately-authorized vault contracts share ONE accumulator", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      await policy.connect(owner).setAdmitter(await vaultA.getAddress(), true);
      await policy.connect(owner).setAdmitter(await vaultB.getAddress(), true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));

      // Vault A consumes the whole allowance.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("1"), 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // Vault B — a different contract, with its own funded balance and its own
      // nonce — is now denied. Neither vault spent anything from the other.
      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultB, owner, req);
      await expect(vaultB.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vaultB, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("CROSS-VAULT (reversed): the same denial occurs in the opposite order", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(owner).setAdmitter(await vaultA.getAddress(), true);
      await policy.connect(owner).setAdmitter(await vaultB.getAddress(), true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultB, owner, ethers.parseEther("1"), 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultA, owner, req);
      await expect(vaultA.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vaultA, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("CROSS-VAULT WINDOW: a spend in one vault moves the window anchor for the other", async function () {
      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await policy.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(owner).setAdmitter(await vaultA.getAddress(), true);
      await policy.connect(owner).setAdmitter(await vaultB.getAddress(), true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));

      // Vault A anchors the window at t0 and spends half.
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("0.5"), 0, t0);

      // Vault B sees vault A's residue, not a fresh limit.
      expect(await policy.remainingAllowance(owner.address)).to.equal(ethers.parseEther("0.5"));
      await expect(withdrawAt(vaultB, owner, ethers.parseEther("0.5"), 0, t0 + 5)).to.emit(vaultB, "Withdrawn");
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      // And vault B's window expires on vault A's clock.
      await networkHelpers.time.increaseTo(t0 + WINDOW - 1);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);
      await networkHelpers.time.increaseTo(t0 + WINDOW);
      expect(await policy.remainingAllowance(owner.address)).to.equal(ethers.parseEther("1"));
    });

    it("CROSS-ASSET: wei and 6-decimal token base units accumulate in the same scalar", async function () {
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

      await policy.connect(owner).setAdmitter(await ethVault.getAddress(), true);
      await policy.connect(owner).setAdmitter(await sim.getAddress(), true);

      // The owner's stated intent: "at most 1 ETH per day". The limit is a bare
      // uint256 with no asset tag, so it is simultaneously the stablecoin limit.
      const limit = ethers.parseEther("1");
      await policy.connect(owner).setDailyLimit(limit);

      // Withdraw 100 mUSDC (1e8 base units) from the stablecoin vault.
      const usdcAmount = 100_000_000n;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const req = request(owner.address, recipient.address, usdcAmount, 0, deadline);
      const { ecdsaSig, pqSig } = await signToken(sim, owner, req);
      await expect(sim.withdraw(req, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");

      // 1e8 token base units were subtracted from a 1e18 wei allowance directly.
      expect(await policy.remainingAllowance(owner.address)).to.equal(limit - usdcAmount);

      // The 100 mUSDC withdrawal consumed one ten-billionth of the "1 ETH" limit:
      // the stablecoin leg is effectively unlimited under an ETH-scaled limit.
      const consumedPpb = (usdcAmount * 1_000_000_000n) / limit;
      expect(consumedPpb).to.equal(0n);
    });

    it("CROSS-ASSET (reversed): an ETH-scaled limit set for token units denies trivial ETH spends", async function () {
      const ethVault = await deployEthVault();
      await installEngine(ethVault, await policy.getAddress());
      await ethVault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(owner).setAdmitter(await ethVault.getAddress(), true);

      // An owner reasoning in stablecoin base units sets "1000 mUSDC per day".
      const limit = 1_000_000_000n; // 1000 * 1e6
      await policy.connect(owner).setDailyLimit(limit);

      // The same number read as wei is 1 gwei — so 2 gwei of ETH is refused.
      const twoGwei = 2_000_000_000n;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const req = request(owner.address, recipient.address, twoGwei, 0, deadline);
      const { ecdsaSig, pqSig } = await signEth(ethVault, owner, req);
      await expect(ethVault.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(ethVault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("NO NORMALIZATION: the amount reaching the policy is the raw request amount", async function () {
      // Proves the value is passed through untouched — no decimals lookup,
      // no oracle, no quote conversion anywhere on the path.
      const ethVault = await deployEthVault();
      await installEngine(ethVault, await policy.getAddress());
      await ethVault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await policy.connect(owner).setAdmitter(await ethVault.getAddress(), true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));

      const odd = 123_456_789n; // an amount no scaling factor would preserve
      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(ethVault, owner, odd, 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(ethers.parseEther("1") - odd);
    });

    it("COMPOSITE: one composite relays vaultOwner verbatim and can serve several consumers", async function () {
      const Composite = await ethers.getContractFactory("CompositePolicyEngine", admin);
      const composite: CompositePolicyEngine = await Composite.deploy();
      await composite.waitForDeployment();
      await composite.connect(admin).addModule(await policy.getAddress());

      const vaultA = await deployEthVault();
      const vaultB = await deployEthVault();
      const engine = await composite.getAddress();
      await installEngine(vaultA, engine);
      await installEngine(vaultB, engine);

      // The COMPOSITE owner registers both consumers; the subject delegates once.
      await composite.connect(admin).setAdmissionCaller(await vaultA.getAddress(), true);
      await composite.connect(admin).setAdmissionCaller(await vaultB.getAddress(), true);
      expect(await composite.admissionCaller(await vaultA.getAddress())).to.equal(true);
      expect(await composite.admissionCaller(await vaultB.getAddress())).to.equal(true);

      await vaultA.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      // A SINGLE delegation — to the composite — now covers both vaults.
      await policy.connect(owner).setAdmitter(engine, true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      expect(await policy.admitterCount(owner.address)).to.equal(1n);

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vaultA, owner, ethers.parseEther("1"), 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);

      const req = request(owner.address, recipient.address, ethers.parseEther("0.5"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vaultB, owner, req);
      await expect(vaultB.withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vaultB, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("TENANT ISOLATION HOLDS: two owners inside one vault contract never share a bucket", async function () {
      // The control case. Subject keying by owner address is correct for the
      // multi-tenant dimension; only the vault-contract and asset dimensions
      // are missing.
      const [, , , second] = await ethers.getSigners();
      const vault = await deployEthVault();
      await installEngine(vault, await policy.getAddress());

      await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });
      await vault.connect(second).createVault(second.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

      await policy.connect(owner).setAdmitter(await vault.getAddress(), true);
      await policy.connect(second).setAdmitter(await vault.getAddress(), true);
      await policy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await policy.connect(second).setDailyLimit(ethers.parseEther("1"));

      const t0 = (await networkHelpers.time.latest()) + 10;
      await withdrawAt(vault, owner, ethers.parseEther("1"), 0, t0);
      expect(await policy.remainingAllowance(owner.address)).to.equal(0n);
      expect(await policy.remainingAllowance(second.address)).to.equal(ethers.parseEther("1"));

      const req = request(second.address, recipient.address, ethers.parseEther("1"), 0, t0 + 3600);
      const { ecdsaSig, pqSig } = await signEth(vault, second, req);
      await expect(vault.withdraw(req, ecdsaSig, pqSig)).to.emit(vault, "Withdrawn");
    });
  });
});
