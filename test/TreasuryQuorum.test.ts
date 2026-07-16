import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { networkHelpers } from "./helpers/connection";
import { WalletWallVault, MockMLDSAVerifier } from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

describe("Treasury withdrawal quorum", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let owner2: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const DEPOSIT = ethers.parseEther("10");
  const THRESHOLD = ethers.parseEther("1"); // large-tx threshold
  const LARGE_AMOUNT = ethers.parseEther("2");
  const LARGE_TX_DELAY = 2 * 24 * 60 * 60;
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function enableLargeTx(threshold = THRESHOLD, delay = LARGE_TX_DELAY) {
    await vault.connect(admin).proposeLargeTxParams(threshold, delay);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
  }

  async function queueLargeWithdrawal(nonce = 0) {
    const req = await buildRequest({ nonce });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
    const operationId = await vault.hashWithdrawal(req);
    return { req, operationId };
  }

  beforeEach(async function () {
    [admin, owner, owner2, recipient, other, guardian1, guardian2, guardian3] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier", admin);
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // ---------------------------------------------------------------------------
  // setTreasuryQuorumThreshold
  // ---------------------------------------------------------------------------

  describe("setTreasuryQuorumThreshold", function () {
    it("quorum threshold update is vault-owner controlled", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await expect(vault.connect(owner).setTreasuryQuorumThreshold(2))
        .to.emit(vault, "TreasuryQuorumThresholdSet")
        .withArgs(owner.address, 2);
      expect(await vault.treasuryQuorumThreshold(owner.address)).to.equal(2);
    });

    it("non-vault-owner cannot set threshold for another vault", async function () {
      // other has no vault — should revert with VaultDoesNotExist
      await expect(vault.connect(other).setTreasuryQuorumThreshold(1)).to.be.revertedWithCustomError(
        vault,
        "VaultDoesNotExist",
      );
    });

    it("threshold of 0 disables treasury quorum", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await vault.connect(owner).setTreasuryQuorumThreshold(0);
      expect(await vault.treasuryQuorumThreshold(owner.address)).to.equal(0);
    });

    it("threshold exceeding guardian count is rejected", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await expect(vault.connect(owner).setTreasuryQuorumThreshold(3)).to.be.revertedWithCustomError(
        vault,
        "TooManyGuardians",
      );
    });

    it("threshold > 0 with no guardians set is rejected", async function () {
      await expect(vault.connect(owner).setTreasuryQuorumThreshold(1)).to.be.revertedWithCustomError(
        vault,
        "InvalidGuardianSet",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Core quorum gating on finalizeWithdrawal
  // ---------------------------------------------------------------------------

  describe("Quorum gating", function () {
    beforeEach(async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();
    });

    it("large withdrawal cannot finalize without required quorum", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "TreasuryQuorumNotMet")
        .withArgs(2, 0);
    });

    it("large withdrawal cannot finalize with insufficient quorum (1 of 2 required)", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "TreasuryQuorumNotMet")
        .withArgs(2, 1);
    });

    it("large withdrawal can finalize after timelock + quorum", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.emit(vault, "WithdrawalFinalized")
        .withArgs(operationId, owner.address, recipient.address, LARGE_AMOUNT);
    });

    it("finalization is blocked before timelock even with full quorum", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      // Do NOT advance time past the delay
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        vault,
        "WithdrawalNotReady",
      );
    });

    it("large withdrawal with quorum disabled (threshold=0) finalizes without approvals", async function () {
      await vault.connect(owner).setTreasuryQuorumThreshold(0);
      const { operationId } = await queueLargeWithdrawal();
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // approveTreasuryWithdrawal
  // ---------------------------------------------------------------------------

  describe("approveTreasuryWithdrawal", function () {
    beforeEach(async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();
    });

    it("emits TreasuryWithdrawalApproved with incrementing count", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await expect(vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId))
        .to.emit(vault, "TreasuryWithdrawalApproved")
        .withArgs(operationId, guardian1.address, 1);
      await expect(vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId))
        .to.emit(vault, "TreasuryWithdrawalApproved")
        .withArgs(operationId, guardian2.address, 2);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(2);
    });

    it("duplicate approval is rejected", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await expect(
        vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId),
      ).to.be.revertedWithCustomError(vault, "TreasuryAlreadyApproved");
    });

    it("removed guardian cannot approve after setGuardians", async function () {
      const { operationId } = await queueLargeWithdrawal();
      // guardian3 is in the original set but is removed here
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await expect(
        vault.connect(guardian3).approveTreasuryWithdrawal(owner.address, operationId),
      ).to.be.revertedWithCustomError(vault, "NotAGuardian");
    });

    it("non-guardian cannot approve", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await expect(
        vault.connect(other).approveTreasuryWithdrawal(owner.address, operationId),
      ).to.be.revertedWithCustomError(vault, "NotAGuardian");
    });

    it("reverts when there is no pending withdrawal", async function () {
      const fakeOpId = ethers.keccak256(ethers.toUtf8Bytes("fake"));
      await expect(
        vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, fakeOpId),
      ).to.be.revertedWithCustomError(vault, "NoPendingWithdrawal");
    });

    it("reverts with mismatched operationId", async function () {
      const { operationId } = await queueLargeWithdrawal();
      const wrongId = ethers.keccak256(ethers.toUtf8Bytes("wrong"));
      await expect(
        vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, wrongId),
      ).to.be.revertedWithCustomError(vault, "PendingWithdrawalMismatch");
    });
  });

  // ---------------------------------------------------------------------------
  // Approval state isolation across queued withdrawals
  // ---------------------------------------------------------------------------

  describe("Approval state isolation", function () {
    beforeEach(async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();
    });

    it("approval state cannot be reused across different queued withdrawals", async function () {
      // Withdrawal A: nonce 0
      const { operationId: opA } = await queueLargeWithdrawal(0);
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, opA);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, opA);
      expect(await vault.treasuryApprovalCount(opA)).to.equal(2);

      // Cancel withdrawal A — clears approvals for opA
      await vault.connect(owner).cancelPendingWithdrawal(opA);
      expect(await vault.treasuryApprovalCount(opA)).to.equal(0);

      // Withdrawal B: nonce 1 — different operationId
      const { operationId: opB } = await queueLargeWithdrawal(1);
      expect(opB).to.not.equal(opA);
      expect(await vault.treasuryApprovalCount(opB)).to.equal(0);

      // Finalization of B without fresh approvals must fail
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, opB))
        .to.be.revertedWithCustomError(vault, "TreasuryQuorumNotMet")
        .withArgs(2, 0);

      // Get fresh approvals for B → succeeds
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, opB);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, opB);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, opB)).to.emit(vault, "WithdrawalFinalized");
    });

    it("canceled queued withdrawal cannot execute even after quorum was met", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(2);

      // Cancel the withdrawal
      await vault.connect(owner).cancelPendingWithdrawal(operationId);

      // Even though quorum was met before cancellation, finalization is impossible
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
        vault,
        "NoPendingWithdrawal",
      );
    });

    it("setGuardians clears treasury approvals so re-approval with new set is required", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      await vault.connect(guardian2).approveTreasuryWithdrawal(owner.address, operationId);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(2);

      // Change guardian set — approvals for pending withdrawal must be cleared
      await vault.connect(owner).setGuardians([guardian1.address, guardian3.address]);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(0);

      // Trying to finalize without fresh approvals should fail
      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "TreasuryQuorumNotMet")
        .withArgs(2, 0);
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction with credential rotation and recovery
  // ---------------------------------------------------------------------------

  describe("Credential rotation / recovery interaction", function () {
    beforeEach(async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(owner).setTreasuryQuorumThreshold(2);
      await enableLargeTx();
    });

    it("executing recovery cancels pending withdrawal and clears its treasury approvals", async function () {
      const { operationId } = await queueLargeWithdrawal();
      await vault.connect(guardian1).approveTreasuryWithdrawal(owner.address, operationId);
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(1);

      // Initiate and complete guardian recovery (requires majority: 2 of 3)
      const newKey = ethers.hexlify(ethers.randomBytes(1952));
      await vault.connect(guardian1).initiateRecovery(owner.address, other.address, newKey);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60); // RECOVERY_DELAY
      await vault.connect(guardian1).executeRecovery(owner.address);

      // Treasury approvals for the cancelled withdrawal should be cleared
      expect(await vault.treasuryApprovalCount(operationId)).to.equal(0);
    });
  });
});
