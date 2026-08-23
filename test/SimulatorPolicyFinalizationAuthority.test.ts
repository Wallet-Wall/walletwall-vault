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
 * Parity CHARACTERIZATION: the stale-policy finalization gap is IDENTICAL in
 * StablecoinVaultSimulator (ERC-20 sibling of WalletWallVault). Same code shape at
 * contracts/StablecoinVaultSimulator.sol:712-721 — the finalize re-check fires only when
 * the engine ADDRESS changed since queue, so same-address internal mutation is never
 * re-consulted. See test/PolicyFinalizationAuthority.test.ts for the ETH-vault analysis.
 *
 * These pin ACTUAL current behavior; `VULNERABILITY`-tagged assertions are expected to
 * flip when the authority model is corrected. Kept intentionally small — the ETH-vault
 * suite carries the full P1–P7 matrix; this file only proves the ERC-20 twin is affected.
 */
const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

describe("Simulator policy finalization authority (parity characterization)", function () {
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

  async function enableLargeTx() {
    await sim.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
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
    sim = await (await ethers.getContractFactory("StablecoinVaultSimulator", admin)).deploy(
      await token.getAddress(),
      await verifier.getAddress(),
    );
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

  it("VULNERABILITY: finalize pays a recipient sanctioned AFTER queue (same engine address)", async function () {
    await setPolicyEngine(await sanctionsPolicy.getAddress());
    await enableLargeTx();

    const { operationId } = await queueLarge();
    const engineAtQueue = (await sim.pendingWithdrawals(owner.address)).policyEngineAtQueue;

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    expect(await sim.policyEngine()).to.equal(engineAtQueue); // address unchanged

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
      sim,
      "WithdrawalFinalized",
    );
  });

  it("VULNERABILITY: finalize pays a recipient removed from the allowlist AFTER queue", async function () {
    await allowlistPolicy.connect(owner).addRecipient(recipient.address);
    await setPolicyEngine(await allowlistPolicy.getAddress());
    await enableLargeTx();

    const { operationId } = await queueLarge();
    await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
    const [ok] = await allowlistPolicy.check.staticCall(owner.address, recipient.address, LARGE_AMOUNT, DEPOSIT);
    expect(ok).to.equal(false);

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
      sim,
      "WithdrawalFinalized",
    );
  });

  it("SAFE (control): finalize BLOCKS when the engine ADDRESS is replaced by a denying one", async function () {
    await enableLargeTx();
    const { operationId } = await queueLarge();

    await sanctionsPolicy.addToSanctionsList(recipient.address);
    await setPolicyEngine(await sanctionsPolicy.getAddress()); // address 0x0 -> engine

    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await expect(sim.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(sim, "PolicyViolation")
      .withArgs("recipient is sanctioned");
  });

  it("DailySpendLimitPolicy records spend at queue time in the simulator too", async function () {
    const LIMIT = MUSDC(400);
    await dailyPolicy.connect(owner).setDailyLimit(LIMIT);
    await setPolicyEngine(await dailyPolicy.getAddress());
    await enableLargeTx();

    expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT);
    await queueLarge(MUSDC(300));
    expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(LIMIT - MUSDC(300));
  });
});
