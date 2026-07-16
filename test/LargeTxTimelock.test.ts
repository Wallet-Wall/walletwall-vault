import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { anyValue } from "@nomicfoundation/hardhat-ethers-chai-matchers/withArgs";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { MockMLDSAVerifier, RecipientAllowlistPolicy, WalletWallVault } from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

describe("Large transaction timelock", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let owner2: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const NEW_PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const DEPOSIT = ethers.parseEther("5");
  const THRESHOLD = ethers.parseEther("1");
  const LARGE_AMOUNT = ethers.parseEther("2");
  const SMALL_AMOUNT = ethers.parseEther("0.5");
  const LARGE_TX_DELAY = 3 * 24 * 60 * 60;
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const RECOVERY_DELAY = 7 * 24 * 60 * 60;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function enableLargeTx(threshold = THRESHOLD, delay = LARGE_TX_DELAY) {
    await vault.connect(admin).proposeLargeTxParams(threshold, delay);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
  }

  async function queueLargeWithdrawal() {
    const request = await buildRequest();
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    await vault.connect(other).queueWithdrawal(request, ecdsaSig, pqSig);
    return { request, operationId: await vault.hashWithdrawal(request) };
  }

  beforeEach(async function () {
    [admin, owner, owner2, recipient, other, guardian1, guardian2, guardian3, newSigner] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier", admin);
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());

    const AllowlistPolicy = await ethers.getContractFactory("RecipientAllowlistPolicy", admin);
    allowlistPolicy = await AllowlistPolicy.deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, {
      recipient: recipient.address,
      amount: LARGE_AMOUNT,
    });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  it("keeps below-threshold withdrawals on the existing immediate path", async function () {
    await enableLargeTx();
    const request = await buildRequest({ amount: SMALL_AMOUNT });
    const { ecdsaSig, pqSig } = await signWithdrawal(request);

    await expect(vault.connect(other).withdraw(request, ecdsaSig, pqSig))
      .to.emit(vault, "Withdrawn")
      .withArgs(owner.address, recipient.address, SMALL_AMOUNT, 0, 2);
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT - SMALL_AMOUNT);
  });

  it("treats an amount exactly equal to the threshold as an immediate withdrawal", async function () {
    await enableLargeTx();
    const request = await buildRequest({ amount: THRESHOLD });
    const { ecdsaSig, pqSig } = await signWithdrawal(request);

    await expect(vault.withdraw(request, ecdsaSig, pqSig)).to.emit(vault, "Withdrawn");
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT - THRESHOLD);
  });

  it("blocks immediate withdrawal above the configured threshold", async function () {
    await enableLargeTx();
    const request = await buildRequest();
    const { ecdsaSig, pqSig } = await signWithdrawal(request);

    await expect(vault.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(vault, "UseLargeWithdrawal");
  });

  it("records owner, operation identity, amount, nonce, and timing when queued", async function () {
    await enableLargeTx();
    const request = await buildRequest();
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    const operationId = await vault.hashWithdrawal(request);

    await expect(vault.connect(other).queueWithdrawal(request, ecdsaSig, pqSig))
      .to.emit(vault, "WithdrawalQueued")
      .withArgs(operationId, owner.address, recipient.address, LARGE_AMOUNT, 0, anyValue, anyValue);

    const pending = await vault.pendingWithdrawals(owner.address);
    expect(pending.owner).to.equal(owner.address);
    expect(pending.recipient).to.equal(recipient.address);
    expect(pending.amount).to.equal(LARGE_AMOUNT);
    expect(pending.nonce).to.equal(0);
    expect(pending.operationId).to.equal(operationId);
    expect(pending.readyAt - pending.queuedAt).to.equal(LARGE_TX_DELAY);
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT - LARGE_AMOUNT);
    expect(await vault.nonces(owner.address)).to.equal(1);
  });

  it("rejects queueing while disabled, below threshold, or with another request pending", async function () {
    let request = await buildRequest();
    let signatures = await signWithdrawal(request);
    await expect(vault.queueWithdrawal(request, signatures.ecdsaSig, signatures.pqSig)).to.be.revertedWithCustomError(
      vault,
      "LargeTxTimelockDisabled",
    );

    await enableLargeTx();
    request = await buildRequest({ amount: SMALL_AMOUNT });
    signatures = await signWithdrawal(request);
    await expect(vault.queueWithdrawal(request, signatures.ecdsaSig, signatures.pqSig)).to.be.revertedWithCustomError(
      vault,
      "LargeWithdrawalNotRequired",
    );

    await queueLargeWithdrawal();
    request = await buildRequest({ nonce: 1 });
    signatures = await signWithdrawal(request);
    await expect(vault.queueWithdrawal(request, signatures.ecdsaSig, signatures.pqSig)).to.be.revertedWithCustomError(
      vault,
      "PendingWithdrawalExists",
    );
  });

  it("rejects finalization before the configured delay", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();
    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, ethers.ZeroHash))
      .to.be.revertedWithCustomError(vault, "PendingWithdrawalMismatch")
      .withArgs(operationId, ethers.ZeroHash);
    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
      vault,
      "WithdrawalNotReady",
    );
  });

  it("finalizes after the delay and cannot finalize twice", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();
    await networkHelpers.time.increase(LARGE_TX_DELAY);

    const recipientBalance = await ethers.provider.getBalance(recipient.address);
    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
      .to.emit(vault, "WithdrawalFinalized")
      .withArgs(operationId, owner.address, recipient.address, LARGE_AMOUNT);
    expect(await ethers.provider.getBalance(recipient.address)).to.equal(recipientBalance + LARGE_AMOUNT);

    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
      vault,
      "NoPendingWithdrawal",
    );
  });

  it("cancels a pending withdrawal and releases the reserved balance", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();

    await expect(vault.connect(owner).cancelPendingWithdrawal(operationId))
      .to.emit(vault, "WithdrawalCancelled")
      .withArgs(operationId, owner.address, LARGE_AMOUNT);
    expect((await vault.pendingWithdrawals(owner.address)).exists).to.be.false;
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT);
    expect(await vault.nonces(owner.address)).to.equal(1);

    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
      vault,
      "NoPendingWithdrawal",
    );
  });

  it("binds operation IDs to the vault owner", async function () {
    await enableLargeTx();
    await vault.connect(owner2).createVault(owner2.address, PQ_KEY, 2);
    await vault.connect(owner2).deposit({ value: DEPOSIT });

    const deadline = (await networkHelpers.time.latest()) + 3600;
    const request1 = {
      vaultOwner: owner.address,
      recipient: recipient.address,
      amount: LARGE_AMOUNT,
      nonce: 0,
      deadline,
      vaultMode: 2,
    };
    const request2 = { ...request1, vaultOwner: owner2.address };
    const signatures1 = await signWithdrawal(request1);
    const signatures2 = await makeSignWithdrawal(vault, owner2)(request2);
    const operationId1 = await vault.hashWithdrawal(request1);
    const operationId2 = await vault.hashWithdrawal(request2);

    expect(operationId1).to.not.equal(operationId2);
    await vault.queueWithdrawal(request1, signatures1.ecdsaSig, signatures1.pqSig);
    await vault.queueWithdrawal(request2, signatures2.ecdsaSig, signatures2.pqSig);
    await networkHelpers.time.increase(LARGE_TX_DELAY);

    await expect(vault.connect(owner).finalizeWithdrawal(owner2.address, operationId2))
      .to.be.revertedWithCustomError(vault, "NotPendingWithdrawalOwner")
      .withArgs(owner2.address, owner.address);
    await expect(vault.connect(owner2).finalizeWithdrawal(owner2.address, operationId1))
      .to.be.revertedWithCustomError(vault, "PendingWithdrawalMismatch")
      .withArgs(operationId2, operationId1);
  });

  it("does not let another owner finalize or cancel the pending withdrawal", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();
    await networkHelpers.time.increase(LARGE_TX_DELAY);

    await expect(vault.connect(other).finalizeWithdrawal(owner.address, operationId))
      .to.be.revertedWithCustomError(vault, "NotPendingWithdrawalOwner")
      .withArgs(owner.address, other.address);
    await expect(vault.connect(other).cancelPendingWithdrawal(operationId)).to.be.revertedWithCustomError(
      vault,
      "NoPendingWithdrawal",
    );
    expect((await vault.pendingWithdrawals(owner.address)).exists).to.be.true;
  });

  it("blocks queue and finalize while paused but permits cancellation", async function () {
    await enableLargeTx();
    const request = await buildRequest();
    const signatures = await signWithdrawal(request);
    await vault.connect(admin).pause();

    await expect(vault.queueWithdrawal(request, signatures.ecdsaSig, signatures.pqSig)).to.be.revertedWithCustomError(
      vault,
      "EnforcedPause",
    );

    await vault.connect(admin).unpause();
    const { operationId } = await queueLargeWithdrawal();
    await networkHelpers.time.increase(LARGE_TX_DELAY);
    await vault.connect(admin).pause();

    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.be.revertedWithCustomError(
      vault,
      "EnforcedPause",
    );
    await expect(vault.connect(owner).cancelPendingWithdrawal(operationId)).to.emit(vault, "WithdrawalCancelled");
  });

  it("enforces the active policy engine before queueing", async function () {
    await enableLargeTx();
    await vault.connect(admin).proposePolicyEngine(await allowlistPolicy.getAddress());
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();

    const request = await buildRequest();
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    await expect(vault.queueWithdrawal(request, ecdsaSig, pqSig))
      .to.be.revertedWithCustomError(vault, "PolicyViolation")
      .withArgs("recipient not on allowlist");

    expect((await vault.pendingWithdrawals(owner.address)).exists).to.be.false;
    expect(await vault.nonces(owner.address)).to.equal(0);
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT);
  });

  it("cancels and refunds a pending withdrawal when recovery executes", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();
    const staleRequest = {
      ...(await buildRequest({ amount: SMALL_AMOUNT, nonce: 1 })),
      deadline: (await networkHelpers.time.latest()) + RECOVERY_DELAY + 3600,
    };
    const staleSignatures = await signWithdrawal(staleRequest);

    await vault.connect(owner).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
    await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
    await vault.connect(guardian1).supportRecovery(owner.address);
    await vault.connect(guardian2).supportRecovery(owner.address);
    await networkHelpers.time.increase(RECOVERY_DELAY);

    await expect(vault.executeRecovery(owner.address))
      .to.emit(vault, "WithdrawalCancelled")
      .withArgs(operationId, owner.address, LARGE_AMOUNT)
      .and.to.emit(vault, "RecoveryExecuted")
      .withArgs(owner.address, newSigner.address);

    expect((await vault.pendingWithdrawals(owner.address)).exists).to.be.false;
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT);
    expect(await vault.nonces(owner.address)).to.equal(2);

    await expect(
      vault.withdraw(staleRequest, staleSignatures.ecdsaSig, staleSignatures.pqSig),
    ).to.be.revertedWithCustomError(vault, "InvalidNonce");

    const oldSignerRequest = {
      ...(await buildRequest({ amount: SMALL_AMOUNT, nonce: 2 })),
      deadline: (await networkHelpers.time.latest()) + 3600,
    };
    const oldSignerSignatures = await signWithdrawal(oldSignerRequest);
    await expect(
      vault.withdraw(oldSignerRequest, oldSignerSignatures.ecdsaSig, oldSignerSignatures.pqSig),
    ).to.be.revertedWithCustomError(vault, "InvalidEcdsaSignature");
  });

  it("cancels and refunds a pending withdrawal when credentials rotate", async function () {
    await enableLargeTx();
    const { operationId } = await queueLargeWithdrawal();
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT - LARGE_AMOUNT);

    // Build a rotation authorized by the current keys (owner) with new-key proofs.
    const ROTATION_TYPES = {
      RotateCredentials: [
        { name: "vaultOwner", type: "address" },
        { name: "newEcdsaSigner", type: "address" },
        { name: "newPQPublicKey", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };
    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };
    const deadline = (await networkHelpers.time.latest()) + 3600;
    const request = {
      vaultOwner: owner.address,
      newEcdsaSigner: newSigner.address,
      newPQPublicKey: NEW_PQ_KEY,
      nonce: Number(await vault.nonces(owner.address)),
      deadline,
    };
    const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    const auth = {
      currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
      currentPqSignature: blob(),
      newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, request),
      newPqSignature: blob(),
    };

    await expect(vault.rotateCredentials(owner.address, newSigner.address, NEW_PQ_KEY, deadline, auth))
      .to.emit(vault, "WithdrawalCancelled")
      .withArgs(operationId, owner.address, LARGE_AMOUNT)
      .and.to.emit(vault, "CredentialsRotated")
      .withArgs(owner.address, newSigner.address);

    // Queue is cleared and the reserved amount is returned to the vault balance.
    expect((await vault.pendingWithdrawals(owner.address)).exists).to.be.false;
    expect((await vault.getVault(owner.address)).balance).to.equal(DEPOSIT);
  });

  it("proposes and applies large-transaction parameters after the governance delay", async function () {
    await expect(vault.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY))
      .to.emit(vault, "LargeTxParamsProposed")
      .withArgs(THRESHOLD, LARGE_TX_DELAY, anyValue);

    await expect(vault.connect(admin).applyLargeTxParams()).to.be.revertedWithCustomError(
      vault,
      "LargeTxUpdateNotReady",
    );
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await expect(vault.connect(admin).applyLargeTxParams())
      .to.emit(vault, "LargeTxParamsApplied")
      .withArgs(THRESHOLD, LARGE_TX_DELAY);
    expect(await vault.largeTxThreshold()).to.equal(THRESHOLD);
    expect(await vault.largeTxDelay()).to.equal(LARGE_TX_DELAY);
  });

  it("cancels pending parameter updates and supports disabling the feature", async function () {
    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
    await expect(vault.connect(admin).cancelLargeTxParams())
      .to.emit(vault, "LargeTxParamsCancelled")
      .withArgs(THRESHOLD, LARGE_TX_DELAY);
    await expect(vault.connect(admin).applyLargeTxParams()).to.be.revertedWithCustomError(
      vault,
      "NoPendingLargeTxUpdate",
    );

    await vault.connect(admin).proposeLargeTxParams(0, 0);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
    expect(await vault.largeTxThreshold()).to.equal(0);
    expect(await vault.largeTxDelay()).to.equal(0);
  });

  it("rejects invalid parameters and non-admin governance calls", async function () {
    await expect(vault.connect(admin).proposeLargeTxParams(THRESHOLD, 0)).to.be.revertedWithCustomError(
      vault,
      "ZeroDelay",
    );
    await expect(vault.connect(owner).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY))
      .to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount")
      .withArgs(owner.address);

    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await expect(vault.connect(owner).applyLargeTxParams())
      .to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount")
      .withArgs(owner.address);
    await expect(vault.connect(owner).cancelLargeTxParams())
      .to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount")
      .withArgs(owner.address);
  });
});
