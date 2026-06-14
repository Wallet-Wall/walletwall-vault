import { expect } from "chai";
import { ethers } from "hardhat";
import { MLDSASigner } from "../pqc/ml-dsa";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { WalletWallVault, MockMLDSAVerifier } from "../typechain-types";
import { WITHDRAWAL_TYPES } from "./helpers/vaultHelpers";

// VaultMode enum mirror (see WalletWallVault.sol)
const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

interface WithdrawalRequest {
  vaultOwner: string;
  recipient: string;
  amount: bigint;
  nonce: bigint | number;
  deadline: bigint | number;
  vaultMode: number;
}

describe("WalletWallVault", function () {
  let vault: WalletWallVault;
  let mockVerifier: MockMLDSAVerifier;
  let owner: HardhatEthersSigner;
  let otherAccount: HardhatEthersSigner;
  let relayer: HardhatEthersSigner;

  let pqPublicKey: Uint8Array;
  let pqPrivateKey: Uint8Array;

  const FUTURE_DEADLINE = 9_999_999_999; // year 2286, comfortably in the future

  async function buildDomain(target: WalletWallVault) {
    const { chainId } = await ethers.provider.getNetwork();
    return {
      name: "WalletWallVault",
      version: "1",
      chainId,
      verifyingContract: await target.getAddress(),
    };
  }

  // Produces a fully-signed (ECDSA + PQ) authorization for `request`.
  async function signWithdrawal(
    target: WalletWallVault,
    request: WithdrawalRequest,
    ecdsaSigner: HardhatEthersSigner,
    pqKey: Uint8Array,
  ) {
    const domain = await buildDomain(target);
    const ecdsaSignature = await ecdsaSigner.signTypedData(domain, WITHDRAWAL_TYPES, request);
    const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);
    const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, pqKey));
    return { ecdsaSignature, pqSignature, digest };
  }

  beforeEach(async function () {
    [owner, otherAccount, relayer] = await ethers.getSigners();

    const MockMLDSAVerifierFactory = await ethers.getContractFactory("MockMLDSAVerifier");
    mockVerifier = await MockMLDSAVerifierFactory.deploy();
    await mockVerifier.waitForDeployment();

    const WalletWallVaultFactory = await ethers.getContractFactory("WalletWallVault");
    vault = await WalletWallVaultFactory.deploy(await mockVerifier.getAddress());
    await vault.waitForDeployment();

    const keyPair = MLDSASigner.generateKeyPair();
    pqPublicKey = keyPair.publicKey;
    pqPrivateKey = keyPair.privateKey;
  });

  describe("Deployment", function () {
    it("Should reject a zero-address PQ verifier", async function () {
      const factory = await ethers.getContractFactory("WalletWallVault");
      await expect(factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });
  });

  describe("Vault Creation", function () {
    it("Should create a hybrid vault and emit VaultCreated", async function () {
      const pqHex = MLDSASigner.toHex(pqPublicKey);
      await expect(vault.createVault(owner.address, pqHex, VaultMode.Hybrid))
        .to.emit(vault, "VaultCreated")
        .withArgs(owner.address, owner.address, pqHex, VaultMode.Hybrid);

      const details = await vault.getVault(owner.address);
      expect(details.ecdsaSigner).to.equal(owner.address);
      expect(details.pqPublicKey).to.equal(pqHex);
      expect(details.mode).to.equal(VaultMode.Hybrid);
      expect(details.exists).to.be.true;
    });

    it("Should reject a second vault for the same owner", async function () {
      const pqHex = MLDSASigner.toHex(pqPublicKey);
      await vault.createVault(owner.address, pqHex, VaultMode.Hybrid);
      await expect(vault.createVault(owner.address, pqHex, VaultMode.Hybrid)).to.be.revertedWithCustomError(
        vault,
        "VaultAlreadyExists",
      );
    });

    it("Should reject a hybrid vault with a zero ECDSA signer", async function () {
      await expect(
        vault.createVault(ethers.ZeroAddress, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid),
      ).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });

    it("Should reject a hybrid vault with an empty PQ public key", async function () {
      await expect(vault.createVault(owner.address, "0x", VaultMode.Hybrid)).to.be.revertedWithCustomError(
        vault,
        "EmptyPQPublicKey",
      );
    });
  });

  describe("Deposits", function () {
    beforeEach(async function () {
      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
    });

    it("Should credit deposit() to the caller's vault", async function () {
      const amount = ethers.parseEther("1.0");
      await expect(vault.deposit({ value: amount }))
        .to.emit(vault, "Deposited")
        .withArgs(owner.address, owner.address, amount);
      expect((await vault.getVault(owner.address)).balance).to.equal(amount);
    });

    it("Should credit depositFor() to the intended owner, not the sender", async function () {
      const amount = ethers.parseEther("2.0");
      await expect(vault.connect(relayer).depositFor(owner.address, { value: amount }))
        .to.emit(vault, "Deposited")
        .withArgs(owner.address, relayer.address, amount);
      expect((await vault.getVault(owner.address)).balance).to.equal(amount);
    });

    it("Should reject a zero-value deposit", async function () {
      await expect(vault.deposit({ value: 0 })).to.be.revertedWithCustomError(vault, "ZeroAmount");
    });

    it("Should reject deposits to a non-existent vault", async function () {
      await expect(
        vault.connect(otherAccount).deposit({ value: ethers.parseEther("1.0") }),
      ).to.be.revertedWithCustomError(vault, "VaultDoesNotExist");
    });
  });

  describe("Hybrid Withdrawals", function () {
    const depositAmount = ethers.parseEther("10.0");
    const withdrawAmount = ethers.parseEther("1.0");

    beforeEach(async function () {
      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      await vault.deposit({ value: depositAmount });
    });

    function baseRequest(overrides: Partial<WithdrawalRequest> = {}): WithdrawalRequest {
      return {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: withdrawAmount,
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.Hybrid,
        ...overrides,
      };
    }

    it("Should succeed with valid ECDSA + ML-DSA signatures (relayer-submitted)", async function () {
      const request = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);

      await expect(vault.connect(relayer).withdraw(request, ecdsaSignature, pqSignature))
        .to.emit(vault, "Withdrawn")
        .withArgs(owner.address, otherAccount.address, withdrawAmount, 0, VaultMode.Hybrid);

      const details = await vault.getVault(owner.address);
      expect(details.nonce).to.equal(1);
      expect(details.balance).to.equal(depositAmount - withdrawAmount);
    });

    it("Should fail when the ECDSA signature is from the wrong signer", async function () {
      const request = baseRequest();
      // otherAccount signs instead of the registered owner signer.
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, otherAccount, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InvalidEcdsaSignature",
      );
    });

    it("Should fail when the recipient is tampered after signing", async function () {
      const signed = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, signed, owner, pqPrivateKey);
      const tampered = baseRequest({ recipient: relayer.address });
      await expect(vault.withdraw(tampered, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InvalidEcdsaSignature",
      );
    });

    it("Should fail when the amount is tampered after signing", async function () {
      const signed = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, signed, owner, pqPrivateKey);
      const tampered = baseRequest({ amount: ethers.parseEther("2.0") });
      await expect(vault.withdraw(tampered, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InvalidEcdsaSignature",
      );
    });

    it("Should fail when the vault owner is tampered after signing", async function () {
      // otherAccount also has a hybrid vault with the same nonce/mode.
      await vault
        .connect(otherAccount)
        .createVault(otherAccount.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      await vault.connect(otherAccount).deposit({ value: depositAmount });

      const signed = baseRequest(); // signed for owner's vault
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, signed, owner, pqPrivateKey);
      const tampered = baseRequest({ vaultOwner: otherAccount.address });
      await expect(vault.withdraw(tampered, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InvalidEcdsaSignature",
      );
    });

    it("Should fail on replay with the same nonce", async function () {
      const request = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await vault.withdraw(request, ecdsaSignature, pqSignature);

      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InvalidNonce",
      );
    });

    it("Should fail when the deadline has expired", async function () {
      const latest = await ethers.provider.getBlock("latest");
      const request = baseRequest({ deadline: latest!.timestamp - 1 });
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "DeadlineExpired",
      );
    });

    it("Should reject a zero amount", async function () {
      const request = baseRequest({ amount: 0n });
      await expect(vault.withdraw(request, "0x", "0x")).to.be.revertedWithCustomError(vault, "ZeroAmount");
    });

    it("Should reject a zero recipient", async function () {
      const request = baseRequest({ recipient: ethers.ZeroAddress });
      await expect(vault.withdraw(request, "0x", "0x")).to.be.revertedWithCustomError(vault, "ZeroRecipient");
    });

    it("Should reject when the vault balance is insufficient", async function () {
      const request = baseRequest({ amount: ethers.parseEther("100.0") });
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "InsufficientBalance",
      );
    });

    it("Should reject when the requested mode does not match the vault mode", async function () {
      const request = baseRequest({ vaultMode: VaultMode.PqOnly });
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "VaultModeMismatch",
      );
    });

    it("Should fail to withdraw while paused", async function () {
      await vault.pause();
      const request = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "EnforcedPause",
      );

      // Unpausing restores functionality.
      await vault.unpause();
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.emit(vault, "Withdrawn");
    });

    it("Should not let forced ETH (selfdestruct) corrupt internal accounting", async function () {
      const vaultAddress = await vault.getAddress();
      const forced = ethers.parseEther("5.0");

      // Force ETH into the vault, bypassing deposit().
      const ForceSend = await ethers.getContractFactory("ForceSend");
      await (await ForceSend.deploy(vaultAddress, { value: forced })).waitForDeployment();

      // Raw balance grew, but accounted vault balance did not.
      expect(await ethers.provider.getBalance(vaultAddress)).to.equal(depositAmount + forced);
      expect((await vault.getVault(owner.address)).balance).to.equal(depositAmount);

      // A normal withdrawal still only debits accounted balance.
      const request = baseRequest();
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await vault.withdraw(request, ecdsaSignature, pqSignature);
      expect((await vault.getVault(owner.address)).balance).to.equal(depositAmount - withdrawAmount);
    });
  });

  describe("Verifier trust boundary", function () {
    it("Should block withdrawal when the PQ verifier returns false", async function () {
      const AlwaysFalse = await ethers.getContractFactory("AlwaysFalsePQCVerifier");
      const falseVerifier = await AlwaysFalse.deploy();
      await falseVerifier.waitForDeployment();

      const factory = await ethers.getContractFactory("WalletWallVault");
      const failingVault = await factory.deploy(await falseVerifier.getAddress());
      await failingVault.waitForDeployment();

      await failingVault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      await failingVault.deposit({ value: ethers.parseEther("3.0") });

      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: ethers.parseEther("1.0"),
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.Hybrid,
      };
      const { ecdsaSignature, pqSignature } = await signWithdrawal(failingVault, request, owner, pqPrivateKey);
      await expect(failingVault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        failingVault,
        "InvalidPQSignature",
      );
    });
  });

  describe("Admin controls (Ownable2Step)", function () {
    async function deployNewVerifier() {
      const NewVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
      const newVerifier = await NewVerifier.deploy();
      await newVerifier.waitForDeployment();
      return newVerifier;
    }

    it("Should prevent a non-owner from proposing a PQ verifier", async function () {
      const newVerifier = await deployNewVerifier();
      await expect(
        vault.connect(otherAccount).proposePQVerifier(await newVerifier.getAddress()),
      ).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
    });

    it("Should let the owner propose a PQ verifier and emit the event", async function () {
      const newVerifier = await deployNewVerifier();
      const oldAddr = await mockVerifier.getAddress();
      const newAddr = await newVerifier.getAddress();

      await expect(vault.proposePQVerifier(newAddr))
        .to.emit(vault, "PQVerifierUpdateProposed")
        .withArgs(oldAddr, newAddr, anyValue);

      expect(await vault.pendingPQVerifier()).to.equal(newAddr);
      expect(await vault.pendingPQVerifierValidAfter()).to.be.greaterThan(await time.latest());
      expect(await vault.pqVerifier()).to.equal(oldAddr);
    });

    it("Should reject a zero-address verifier proposal", async function () {
      await expect(vault.proposePQVerifier(ethers.ZeroAddress)).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });

    it("Should prevent a non-owner from cancelling a PQ verifier update", async function () {
      const newVerifier = await deployNewVerifier();
      await vault.proposePQVerifier(await newVerifier.getAddress());

      await expect(vault.connect(otherAccount).cancelPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
    });

    it("Should let the owner cancel a pending PQ verifier update", async function () {
      const newVerifier = await deployNewVerifier();
      const newAddr = await newVerifier.getAddress();
      await vault.proposePQVerifier(newAddr);

      await expect(vault.cancelPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdateCancelled").withArgs(newAddr);

      expect(await vault.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
      expect(await vault.pendingPQVerifierValidAfter()).to.equal(0);
    });

    it("Should not apply a cancelled PQ verifier update later", async function () {
      const newVerifier = await deployNewVerifier();
      await vault.proposePQVerifier(await newVerifier.getAddress());
      const validAfter = await vault.pendingPQVerifierValidAfter();
      await vault.cancelPQVerifierUpdate();

      await time.increaseTo(validAfter);
      await expect(vault.applyPQVerifierUpdate()).to.be.revertedWithCustomError(vault, "NoPendingPQVerifier");
      expect(await vault.pqVerifier()).to.equal(await mockVerifier.getAddress());
    });

    it("Should reject cancellation when no verifier update is pending", async function () {
      await expect(vault.cancelPQVerifierUpdate()).to.be.revertedWithCustomError(vault, "NoPendingPQVerifier");
    });

    it("Should not apply a verifier before the delay", async function () {
      const newVerifier = await deployNewVerifier();
      await vault.proposePQVerifier(await newVerifier.getAddress());

      const validAfter = await vault.pendingPQVerifierValidAfter();
      await expect(vault.applyPQVerifierUpdate())
        .to.be.revertedWithCustomError(vault, "PQVerifierUpdateNotReady")
        .withArgs(validAfter, anyValue);
    });

    it("Should apply a verifier after the delay and emit the event", async function () {
      const newVerifier = await deployNewVerifier();
      const oldAddr = await mockVerifier.getAddress();
      const newAddr = await newVerifier.getAddress();
      await vault.proposePQVerifier(newAddr);

      await time.increaseTo(await vault.pendingPQVerifierValidAfter());

      await expect(vault.applyPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdated").withArgs(oldAddr, newAddr);
      expect(await vault.pqVerifier()).to.equal(newAddr);
      expect(await vault.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
      expect(await vault.pendingPQVerifierValidAfter()).to.equal(0);
    });

    it("Should keep existing withdrawal behavior while a verifier update is pending", async function () {
      const falseVerifier = await (await ethers.getContractFactory("AlwaysFalsePQCVerifier")).deploy();
      await falseVerifier.waitForDeployment();

      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      await vault.deposit({ value: ethers.parseEther("2.0") });
      await vault.proposePQVerifier(await falseVerifier.getAddress());

      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: ethers.parseEther("1.0"),
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.Hybrid,
      };
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);

      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.emit(vault, "Withdrawn");
      expect(await vault.pqVerifier()).to.equal(await mockVerifier.getAddress());
    });

    it("Should use two-step ownership transfer", async function () {
      await vault.transferOwnership(otherAccount.address);
      // Ownership does not change until accepted.
      expect(await vault.owner()).to.equal(owner.address);
      expect(await vault.pendingOwner()).to.equal(otherAccount.address);

      await vault.connect(otherAccount).acceptOwnership();
      expect(await vault.owner()).to.equal(otherAccount.address);
    });
  });

  describe("Vault modes", function () {
    const depositAmount = ethers.parseEther("5.0");
    const withdrawAmount = ethers.parseEther("1.0");

    it("EcdsaOnly: succeeds with only an ECDSA signature", async function () {
      await vault.createVault(owner.address, "0x", VaultMode.EcdsaOnly);
      await vault.deposit({ value: depositAmount });

      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: withdrawAmount,
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.EcdsaOnly,
      };
      const domain = await buildDomain(vault);
      const ecdsaSignature = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);

      // No PQ signature needed.
      await expect(vault.withdraw(request, ecdsaSignature, "0x")).to.emit(vault, "Withdrawn");
      expect((await vault.getVault(owner.address)).balance).to.equal(depositAmount - withdrawAmount);
    });

    it("PqOnly: reverts at creation while the verifier is the mock", async function () {
      // The default vault uses MockMLDSAVerifier, so PqOnly must be blocked.
      await expect(
        vault.createVault(ethers.ZeroAddress, MLDSASigner.toHex(pqPublicKey), VaultMode.PqOnly),
      ).to.be.revertedWithCustomError(vault, "PqOnlyDisabledForMockVerifier");
    });

    it("PqOnly: succeeds with only a PQ signature against a non-mock verifier", async function () {
      // Deploy a vault wired to a non-mock verifier so PqOnly is permitted.
      const realVerifier = await (await ethers.getContractFactory("AlwaysTruePQCVerifier")).deploy();
      await realVerifier.waitForDeployment();
      const pqVault = await (
        await ethers.getContractFactory("WalletWallVault")
      ).deploy(await realVerifier.getAddress());
      await pqVault.waitForDeployment();

      await pqVault.createVault(ethers.ZeroAddress, MLDSASigner.toHex(pqPublicKey), VaultMode.PqOnly);
      await pqVault.deposit({ value: depositAmount });

      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: withdrawAmount,
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.PqOnly,
      };
      const domain = await buildDomain(pqVault);
      const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);
      const pqSignature = MLDSASigner.toHex(MLDSASigner.sign(digest, pqPrivateKey));

      // No ECDSA signature needed.
      await expect(pqVault.withdraw(request, "0x", pqSignature)).to.emit(pqVault, "Withdrawn");
      expect((await pqVault.getVault(owner.address)).balance).to.equal(depositAmount - withdrawAmount);
    });

    it("EcdsaOnly and Hybrid still work with the mock verifier", async function () {
      // EcdsaOnly creation succeeds against the mock (covered above); confirm Hybrid too.
      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      expect((await vault.getVault(owner.address)).mode).to.equal(VaultMode.Hybrid);
    });

    it("Reverts with TransferFailed when the recipient rejects ETH", async function () {
      const RejectEther = await ethers.getContractFactory("RejectEther");
      const rejecter = await RejectEther.deploy();
      await rejecter.waitForDeployment();

      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      await vault.deposit({ value: depositAmount });

      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: await rejecter.getAddress(),
        amount: withdrawAmount,
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.Hybrid,
      };
      const { ecdsaSignature, pqSignature } = await signWithdrawal(vault, request, owner, pqPrivateKey);
      await expect(vault.withdraw(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        vault,
        "TransferFailed",
      );
    });
  });

  describe("Credential rotation (PR D)", function () {
    const ROTATION_TYPES = {
      RotateCredentials: [
        { name: "vaultOwner", type: "address" },
        { name: "newEcdsaSigner", type: "address" },
        { name: "newPQPublicKey", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };

    // Builds the four-signature RotationAuth tuple for a rotation. ECDSA proofs are real
    // (recover); PQ proofs are well-formed ML-DSA-shaped blobs (the mock verifier checks
    // shape only). Pass a falsy private key / string signer to leave a proof unsigned so
    // negative cases can exercise the missing/invalid paths.
    async function signRotation(
      target: WalletWallVault,
      ownerAccount: HardhatEthersSigner,
      newEcdsaSigner: HardhatEthersSigner | string,
      newPQPublicKey: string,
      opts: {
        currentSigner?: HardhatEthersSigner;
        currentPqPriv?: Uint8Array;
        newPqPriv?: Uint8Array;
        deadline?: number;
        nonce?: bigint | number;
      } = {},
    ) {
      const domain = await buildDomain(target);
      const deadline = opts.deadline ?? (await time.latest()) + 3600;
      const nonce = opts.nonce ?? (await target.nonces(ownerAccount.address));
      const request = {
        vaultOwner: ownerAccount.address,
        newEcdsaSigner: typeof newEcdsaSigner === "string" ? newEcdsaSigner : newEcdsaSigner.address,
        newPQPublicKey,
        nonce,
        deadline,
      };
      const digest = ethers.TypedDataEncoder.hash(domain, ROTATION_TYPES, request);
      const currentSigner = opts.currentSigner ?? ownerAccount;
      const currentEcdsaSignature = await currentSigner.signTypedData(domain, ROTATION_TYPES, request);
      const newEcdsaSignature =
        typeof newEcdsaSigner === "string" ? "0x" : await newEcdsaSigner.signTypedData(domain, ROTATION_TYPES, request);
      const currentPqSignature = opts.currentPqPriv
        ? MLDSASigner.toHex(MLDSASigner.sign(digest, opts.currentPqPriv))
        : "0x";
      const newPqSignature = opts.newPqPriv ? MLDSASigner.toHex(MLDSASigner.sign(digest, opts.newPqPriv)) : "0x";
      return {
        deadline,
        digest,
        auth: { currentEcdsaSignature, currentPqSignature, newEcdsaSignature, newPqSignature },
      };
    }

    describe("legacy direct functions are tombstoned", function () {
      it("updateEcdsaSigner reverts with UseRotateCredentials", async function () {
        await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
        await expect(vault.updateEcdsaSigner(relayer.address)).to.be.revertedWithCustomError(
          vault,
          "UseRotateCredentials",
        );
        // State is untouched: the original signer is still in place.
        expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(owner.address);
      });

      it("updatePQPublicKey reverts with UseRotateCredentials", async function () {
        await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
        const newKey = MLDSASigner.toHex(MLDSASigner.generateKeyPair().publicKey);
        await expect(vault.updatePQPublicKey(newKey)).to.be.revertedWithCustomError(vault, "UseRotateCredentials");
        expect((await vault.getVault(owner.address)).pqPublicKey).to.equal(MLDSASigner.toHex(pqPublicKey));
      });

      it("tombstones revert even with no vault (no state dependence)", async function () {
        await expect(vault.connect(otherAccount).updateEcdsaSigner(otherAccount.address)).to.be.revertedWithCustomError(
          vault,
          "UseRotateCredentials",
        );
      });
    });

    describe("Hybrid rotation (current ECDSA + current PQ + new ECDSA + new PQ)", function () {
      let newPq: ReturnType<typeof MLDSASigner.generateKeyPair>;

      beforeEach(async function () {
        await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
        newPq = MLDSASigner.generateKeyPair();
      });

      it("rotates with all four valid proofs and increments the nonce", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });

        await expect(vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth))
          .to.emit(vault, "CredentialsRotated")
          .withArgs(owner.address, relayer.address);

        const info = await vault.getVault(owner.address);
        expect(info.ecdsaSigner).to.equal(relayer.address);
        expect(info.pqPublicKey).to.equal(newKey);
        expect(info.nonce).to.equal(1);
      });

      it("reverts when the current ECDSA proof is from the wrong signer", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentSigner: otherAccount, // not the current signer
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidRotationSignature");
      });

      it("reverts when the new-signer proof is empty (current keys alone do not suffice)", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        // Strip the new-signer proof; an empty signature is rejected by ECDSA.recover.
        auth.newEcdsaSignature = "0x";
        await expect(vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth)).to.be.reverted;
      });

      it("reverts when the new ECDSA proof is a valid signature from the wrong account", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        // Same digest (newEcdsaSigner = relayer), but the proof is signed by otherAccount.
        const domain = await buildDomain(vault);
        const req = {
          vaultOwner: owner.address,
          newEcdsaSigner: relayer.address,
          newPQPublicKey: newKey,
          nonce: 0,
          deadline,
        };
        auth.newEcdsaSignature = await otherAccount.signTypedData(domain, ROTATION_TYPES, req);
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidNewEcdsaProof");
      });

      it("reverts when the current PQ proof is malformed", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        auth.currentPqSignature = "0x"; // wrong length -> mock verify returns false
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidPQSignature");
      });

      it("reverts when the new PQ proof-of-possession is malformed", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        auth.newPqSignature = "0x"; // wrong length -> mock verify returns false
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidNewPQProof");
      });

      it("rejects a rotation that would brick the vault (empty new PQ key)", async function () {
        const { deadline, auth } = await signRotation(vault, owner, relayer, "0x", {
          currentPqPriv: pqPrivateKey,
        });
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, "0x", deadline, auth),
        ).to.be.revertedWithCustomError(vault, "EmptyPQPublicKey");
      });

      it("reverts on an expired deadline", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const past = (await time.latest()) - 1;
        const { auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
          deadline: past,
        });
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, past, auth),
        ).to.be.revertedWithCustomError(vault, "DeadlineExpired");
      });

      it("cannot be replayed once the nonce has advanced", async function () {
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        await vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth);
        // The signed digest bound nonce 0; the vault is now at nonce 1.
        await expect(
          vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidRotationSignature");
      });

      it("invalidates a withdrawal signed before the rotation", async function () {
        await vault.deposit({ value: ethers.parseEther("1") });
        const stale: WithdrawalRequest = {
          vaultOwner: owner.address,
          recipient: otherAccount.address,
          amount: ethers.parseEther("0.1"),
          nonce: 0,
          deadline: FUTURE_DEADLINE,
          vaultMode: VaultMode.Hybrid,
        };
        const staleSig = await signWithdrawal(vault, stale, owner, pqPrivateKey);

        const newKey = MLDSASigner.toHex(newPq.publicKey);
        const { deadline, auth } = await signRotation(vault, owner, relayer, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        await vault.rotateCredentials(owner.address, relayer.address, newKey, deadline, auth);

        await expect(
          vault.withdraw(stale, staleSig.ecdsaSignature, staleSig.pqSignature),
        ).to.be.revertedWithCustomError(vault, "InvalidNonce");
      });
    });

    describe("EcdsaOnly rotation (current ECDSA + new ECDSA proof)", function () {
      beforeEach(async function () {
        await vault.connect(otherAccount).createVault(otherAccount.address, "0x", VaultMode.EcdsaOnly);
      });

      it("rotates with both ECDSA proofs and ignores PQ", async function () {
        const { deadline, auth } = await signRotation(vault, otherAccount, relayer, "0x", {
          currentSigner: otherAccount,
        });
        await expect(vault.rotateCredentials(otherAccount.address, relayer.address, "0x", deadline, auth)).to.emit(
          vault,
          "CredentialsRotated",
        );
        expect((await vault.getVault(otherAccount.address)).ecdsaSigner).to.equal(relayer.address);
      });

      it("reverts when the new ECDSA proof is from the wrong account", async function () {
        const { deadline, auth } = await signRotation(vault, otherAccount, relayer, "0x", {
          currentSigner: otherAccount,
        });
        // Valid-length signature, but signed by owner instead of the incoming signer (relayer).
        const domain = await buildDomain(vault);
        const req = {
          vaultOwner: otherAccount.address,
          newEcdsaSigner: relayer.address,
          newPQPublicKey: "0x",
          nonce: 0,
          deadline,
        };
        auth.newEcdsaSignature = await owner.signTypedData(domain, ROTATION_TYPES, req);
        await expect(
          vault.rotateCredentials(otherAccount.address, relayer.address, "0x", deadline, auth),
        ).to.be.revertedWithCustomError(vault, "InvalidNewEcdsaProof");
      });

      it("rejects rotating the signer to the zero address", async function () {
        const { deadline, auth } = await signRotation(vault, otherAccount, ethers.ZeroAddress, "0x", {
          currentSigner: otherAccount,
        });
        await expect(
          vault.rotateCredentials(otherAccount.address, ethers.ZeroAddress, "0x", deadline, auth),
        ).to.be.revertedWithCustomError(vault, "ZeroAddress");
      });
    });

    describe("PqOnly rotation (current PQ + new PQ proof)", function () {
      it("rotates with both PQ proofs against a non-mock verifier", async function () {
        // PqOnly is blocked for the mock verifier, so use AlwaysTruePQCVerifier.
        const realVerifier = await (await ethers.getContractFactory("AlwaysTruePQCVerifier")).deploy();
        const pqVault = await (
          await ethers.getContractFactory("WalletWallVault")
        ).deploy(await realVerifier.getAddress());
        const oldKey = MLDSASigner.toHex(pqPublicKey);
        const newPq = MLDSASigner.generateKeyPair();
        const newKey = MLDSASigner.toHex(newPq.publicKey);
        await pqVault.createVault(ethers.ZeroAddress, oldKey, VaultMode.PqOnly);

        const { deadline, auth } = await signRotation(pqVault, owner, ethers.ZeroAddress, newKey, {
          currentPqPriv: pqPrivateKey,
          newPqPriv: newPq.privateKey,
        });
        await expect(pqVault.rotateCredentials(owner.address, ethers.ZeroAddress, newKey, deadline, auth)).to.emit(
          pqVault,
          "CredentialsRotated",
        );
        const info = await pqVault.getVault(owner.address);
        expect(info.pqPublicKey).to.equal(newKey);
        expect(info.nonce).to.equal(1);
      });
    });
  });

  describe("EIP-712 helpers", function () {
    it("hashWithdrawal matches the off-chain typed-data digest", async function () {
      await vault.createVault(owner.address, MLDSASigner.toHex(pqPublicKey), VaultMode.Hybrid);
      const request: WithdrawalRequest = {
        vaultOwner: owner.address,
        recipient: otherAccount.address,
        amount: ethers.parseEther("1.0"),
        nonce: 0,
        deadline: FUTURE_DEADLINE,
        vaultMode: VaultMode.Hybrid,
      };
      const domain = await buildDomain(vault);
      const offChain = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);
      expect(await vault.hashWithdrawal(request)).to.equal(offChain);
    });
  });

  describe("Mock verifier (TEST-ONLY behavior)", function () {
    it("Should expose a clearly mock-tagged algorithm id", async function () {
      expect(await mockVerifier.algorithmId()).to.equal(ethers.keccak256(ethers.toUtf8Bytes("MOCK-ML-DSA-65")));
    });

    it("Documents that the mock is structural-only and NOT real verification", async function () {
      // A well-formed but cryptographically meaningless blob of the right length
      // passes the mock — proving it provides no real security and must never be
      // used with real funds.
      const digest = ethers.keccak256(ethers.toUtf8Bytes("anything"));
      const fakeKey = "0x" + "ab".repeat(1952);
      const fakeSig = "0x" + "cd".repeat(3309);
      expect(await mockVerifier.verify(digest, fakeKey, fakeSig)).to.equal(true);

      // Wrong lengths are rejected (structural check only).
      expect(await mockVerifier.verify(digest, "0x1234", fakeSig)).to.equal(false);
    });
  });
});
