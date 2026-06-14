import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { WalletWallVault, MockMLDSAVerifier, SanctionsListPolicy } from "../typechain-types";
import { makeSignWithdrawal, makeBuildRequest } from "./helpers/vaultHelpers";

describe("SanctionsListPolicy", function () {
  let vault: WalletWallVault;
  let sanctions: SanctionsListPolicy;
  let owner: SignerWithAddress;
  let admin: SignerWithAddress;
  let recipient: SignerWithAddress;
  let other: SignerWithAddress;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function activateSanctions() {
    await vault.proposePolicyEngine(await sanctions.getAddress());
    await time.increase(GOVERNANCE_DELAY);
    await vault.applyPolicyEngine();
  }

  async function withdraw(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    const request = await buildRequest(overrides);
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    return vault.withdraw(request, ecdsaSig, pqSig);
  }

  beforeEach(async function () {
    [owner, admin, recipient, other] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    const verifier = (await MockVerifier.deploy()) as MockMLDSAVerifier;

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const Sanctions = await ethers.getContractFactory("SanctionsListPolicy");
    sanctions = await Sanctions.deploy();

    buildRequest = makeBuildRequest(owner, {
      recipient: recipient.address,
      amount: ethers.parseEther("0.5"),
    });
    signWithdrawal = makeSignWithdrawal(vault, owner);

    await vault.createVault(owner.address, PQ_KEY, 2);
    await vault.deposit({ value: ethers.parseEther("5") });
  });

  describe("Access control", function () {
    it("deployer is the owner", async function () {
      expect(await sanctions.owner()).to.equal(owner.address);
    });

    it("non-owner cannot add to sanctions list", async function () {
      await expect(sanctions.connect(other).addToSanctionsList(recipient.address)).to.be.revertedWithCustomError(
        sanctions,
        "OwnableUnauthorizedAccount",
      );
    });

    it("non-owner cannot remove from sanctions list", async function () {
      await sanctions.addToSanctionsList(recipient.address);
      await expect(sanctions.connect(other).removeFromSanctionsList(recipient.address)).to.be.revertedWithCustomError(
        sanctions,
        "OwnableUnauthorizedAccount",
      );
    });

    it("non-owner cannot batch add", async function () {
      await expect(sanctions.connect(other).addBatchToSanctionsList([recipient.address])).to.be.revertedWithCustomError(
        sanctions,
        "OwnableUnauthorizedAccount",
      );
    });

    it("uses Ownable2Step — pending owner must accept before taking control", async function () {
      await sanctions.transferOwnership(admin.address);
      expect(await sanctions.owner()).to.equal(owner.address);
      await sanctions.connect(admin).acceptOwnership();
      expect(await sanctions.owner()).to.equal(admin.address);
    });
  });

  describe("List management", function () {
    it("isSanctioned returns false by default", async function () {
      expect(await sanctions.isSanctioned(recipient.address)).to.be.false;
    });

    it("addToSanctionsList marks address as sanctioned and emits event", async function () {
      await expect(sanctions.addToSanctionsList(recipient.address))
        .to.emit(sanctions, "AddressAdded")
        .withArgs(recipient.address);
      expect(await sanctions.isSanctioned(recipient.address)).to.be.true;
    });

    it("removeFromSanctionsList clears the flag and emits event", async function () {
      await sanctions.addToSanctionsList(recipient.address);
      await expect(sanctions.removeFromSanctionsList(recipient.address))
        .to.emit(sanctions, "AddressRemoved")
        .withArgs(recipient.address);
      expect(await sanctions.isSanctioned(recipient.address)).to.be.false;
    });

    it("addBatchToSanctionsList sanctions multiple addresses", async function () {
      const targets = [recipient.address, other.address];
      await sanctions.addBatchToSanctionsList(targets);
      expect(await sanctions.isSanctioned(recipient.address)).to.be.true;
      expect(await sanctions.isSanctioned(other.address)).to.be.true;
    });

    it("addBatchToSanctionsList emits AddressAdded for each entry", async function () {
      const tx = await sanctions.addBatchToSanctionsList([recipient.address, other.address]);
      await expect(tx).to.emit(sanctions, "AddressAdded").withArgs(recipient.address);
      await expect(tx).to.emit(sanctions, "AddressAdded").withArgs(other.address);
    });
  });

  describe("Withdrawal enforcement", function () {
    beforeEach(async function () {
      await activateSanctions();
    });

    it("allows withdrawal to a non-sanctioned recipient", async function () {
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("blocks withdrawal to a sanctioned recipient", async function () {
      await sanctions.addToSanctionsList(recipient.address);
      await expect(withdraw())
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("allows withdrawal after recipient is removed from list", async function () {
      await sanctions.addToSanctionsList(recipient.address);
      await sanctions.removeFromSanctionsList(recipient.address);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("blocks withdrawal to any sanctioned address in a batch", async function () {
      await sanctions.addBatchToSanctionsList([other.address, recipient.address]);
      await expect(withdraw())
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");
    });

    it("does not block the vault owner — only recipient is screened", async function () {
      await sanctions.addToSanctionsList(owner.address);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });
  });
});
