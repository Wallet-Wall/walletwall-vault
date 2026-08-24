import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  MockUSDC,
  MockMLDSAVerifier,
  RecipientAllowlistPolicy,
  DailySpendLimitPolicy,
  SanctionsListPolicy,
  StablecoinVaultSimulator,
} from "../typechain-types";
import { makeSignWithdrawal, makeBuildRequest } from "./helpers/simulatorHelpers";

/**
 * Parity REGRESSION: StablecoinVaultSimulator (the ERC-20 sibling) applies the same
 * finalization authority model as WalletWallVault — read-only revalidation of BOTH
 * the queue-time engine (sticky floor) and the current engine, with no address-drift
 * gate. These tests began life as characterization of the shared stale-policy bypass
 * (PR #152) and now pin the fix on the simulator side. The full P1–P7 matrix lives in
 * test/PolicyFinalizationAuthority.test.ts; this file proves ERC-20 parity.
 */
const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

describe("Simulator policy finalization authority (parity regression)", function () {
  let sim: StablecoinVaultSimulator;
  let token: MockUSDC;
  let verifier: MockMLDSAVerifier;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let dailyPolicy: DailySpendLimitPolicy;
  let sanctionsPolicy: SanctionsListPolicy;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const LARGE_TX_DELAY = 3 * 24 * 60 * 60;
  const DEPOSIT = MUSDC(500);
  const THRESHOLD = MUSDC(100);
  const LARGE_AMOUNT = MUSDC(300);

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function setPolicyEngine(engine: string) {
    await sim.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await sim.connect(admin).applyPolicyEngine();
  }

  async function enableLargeTx(delay = LARGE_TX_DELAY) {
    await sim.connect(admin).proposeLargeTxParams(THRESHOLD, delay);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await sim.connect(admin).applyLargeTxParams();
  }

  async function queueLarge(amount = LARGE_AMOUNT) {
    const req = await buildRequest({ recipient: recipient.address, amount });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    await sim.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
    return { req, operationId: await sim.hashWithdrawal(req) };
  }

  beforeEach(async function () {
    [admin, owner, recipient, other] = await ethers.getSigners();

    token = await (await ethers.getContractFactory("MockUSDC")).deploy();
    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
    sim = await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await verifier.getAddress());
    allowlistPolicy = await (await ethers.getContractFactory("RecipientAllowlistPolicy", admin)).deploy();
    dailyPolicy = await (await ethers.getContractFactory("DailySpendLimitPolicy", admin)).deploy();
    sanctionsPolicy = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();

    await sim.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await token.connect(owner).mint(owner.address, DEPOSIT);
    await token.connect(owner).approve(await sim.getAddress(), DEPOSIT);
    await sim.connect(owner).deposit(DEPOSIT);

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
    signWithdrawal = makeSignWithdrawal(sim, owner);
  });

  it("finalize REVERTS for a recipient sanctioned AFTER queue (same engine address)", async function () {
    await setPolicyEngine(await sanctionsPolicy.getAddress());
    await enableLargeTx();

    const { operationId } = await queueLarge();
    const engineAtQueue = (await sim.pendingWithdrawals(owner.address)).policyEngineAtQueue;

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    expect(await sim.policyEngine()).to.equal(engineAtQueue); // address unchanged

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient is sanctioned");
  });

  it("finalize REVERTS for a recipient removed from the allowlist AFTER queue", async function () {
    await allowlistPolicy.connect(owner).addRecipient(recipient.address);
    await setPolicyEngine(await allowlistPolicy.getAddress());
    await enableLargeTx();

    const { operationId } = await queueLarge();
    await allowlistPolicy.connect(owner).removeRecipient(recipient.address);

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient not on allowlist");
  });

  it("finalize BLOCKS when the engine ADDRESS is replaced by a denying one", async function () {
    await enableLargeTx();
    const { operationId } = await queueLarge(); // policyEngineAtQueue == address(0)

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    await setPolicyEngine(await sanctionsPolicy.getAddress()); // 0x0 -> engine

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient is sanctioned");
  });

  it("disabling the current engine does not erase queue-time restrictions (sticky floor)", async function () {
    await setPolicyEngine(await sanctionsPolicy.getAddress());
    await enableLargeTx();
    const { operationId } = await queueLarge(); // clean at admission

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    await setPolicyEngine(ethers.ZeroAddress); // disabled
    expect(await sim.policyEngine()).to.equal(ethers.ZeroAddress);

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient is sanctioned");
  });

  it("daily spend is booked once at queue and finalization does not book it again", async function () {
    // One-hour large-tx delay so the policy's 24h window does not roll before finalize.
    const SHORT_DELAY = 3600;
    const LIMIT = MUSDC(400);
    await dailyPolicy.connect(owner).setDailyLimit(LIMIT);
    await setPolicyEngine(await dailyPolicy.getAddress());
    await enableLargeTx(SHORT_DELAY);

    expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT);
    const { operationId } = await queueLarge(MUSDC(300));
    expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - MUSDC(300));

    await networkHelpers.time.increase(SHORT_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(sim, "WithdrawalFinalized");
    // Settlement did not re-book (no double-count).
    expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - MUSDC(300));
  });

  it("revalidate receives the pre-deduction balance and true amount (parity with the ETH vault)", async function () {
    // Mock admits only when vaultBalance == DEPOSIT (the balance before this
    // withdrawal's deduction) AND amount == LARGE_AMOUNT. The old code passed the
    // post-reservation balance at finalization, which would make this revalidation fail.
    const mock = await (
      await ethers.getContractFactory("BalanceAssertingPolicyMock", admin)
    ).deploy(DEPOSIT, LARGE_AMOUNT);
    await setPolicyEngine(await mock.getAddress());
    await enableLargeTx();
    const { operationId } = await queueLarge();

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(sim, "WithdrawalFinalized");
  });

  it("a denying CURRENT engine blocks even when the (non-zero) queue-time engine permits", async function () {
    await allowlistPolicy.connect(owner).addRecipient(recipient.address);
    await setPolicyEngine(await allowlistPolicy.getAddress());
    await enableLargeTx();
    const { operationId } = await queueLarge();

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    await setPolicyEngine(await sanctionsPolicy.getAddress()); // both engines non-zero, distinct

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient is sanctioned");
  });

  it("a code-less CURRENT engine fails finalization closed (parity)", async function () {
    await allowlistPolicy.connect(owner).addRecipient(recipient.address);
    await setPolicyEngine(await allowlistPolicy.getAddress());
    await enableLargeTx();
    const { operationId } = await queueLarge();

    await setPolicyEngine(other.address); // EOA: code.length == 0
    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyEngineUnavailable")
      .withArgs(other.address);
  });

  it("a revalidate() that attempts a state write fails finalization closed (STATICCALL parity)", async function () {
    const mock = await (await ethers.getContractFactory("MutatingRevalidatePolicyMock", admin)).deploy();
    await setPolicyEngine(await mock.getAddress());
    await enableLargeTx();
    const { operationId } = await queueLarge();
    expect(await mock.checkCalls()).to.equal(1n); // admission wrote normally

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyEngineUnavailable")
      .withArgs(await mock.getAddress());
    expect(await mock.revalidateCalls()).to.equal(0n);
  });
});
