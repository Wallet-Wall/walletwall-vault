import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { networkHelpers } from "./helpers/connection";
import {
  WalletWallVault,
  MockMLDSAVerifier,
  DailySpendLimitPolicy,
  RecipientAllowlistPolicy,
} from "../typechain-types";
import { makeSignWithdrawal, makeBuildRequest } from "./helpers/vaultHelpers";

describe("Policy Engine", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let dailyPolicy: DailySpendLimitPolicy;
  let allowlistPolicy: RecipientAllowlistPolicy;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function withdraw(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    const request = await buildRequest(overrides);
    const { ecdsaSig, pqSig } = await signWithdrawal(request);
    return vault.withdraw(request, ecdsaSig, pqSig);
  }

  async function setPolicyEngine(engineAddress: string) {
    await vault.proposePolicyEngine(engineAddress);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.applyPolicyEngine();
  }

  beforeEach(async function () {
    [owner, recipient, other] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const DailyPolicy = await ethers.getContractFactory("DailySpendLimitPolicy");
    dailyPolicy = await DailyPolicy.deploy();

    const AllowlistPolicy = await ethers.getContractFactory("RecipientAllowlistPolicy");
    allowlistPolicy = await AllowlistPolicy.deploy();

    buildRequest = makeBuildRequest(owner, {
      recipient: recipient.address,
      amount: ethers.parseEther("0.5"),
    });
    signWithdrawal = makeSignWithdrawal(vault, owner);

    await vault.createVault(owner.address, PQ_KEY, 2);
    await vault.deposit({ value: ethers.parseEther("5") });
  });

  describe("Governance", function () {
    it("no policy by default — withdrawals pass through", async function () {
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("proposePolicyEngine reverts before delay", async function () {
      await vault.proposePolicyEngine(await dailyPolicy.getAddress());
      await expect(vault.applyPolicyEngine()).to.be.revertedWithCustomError(vault, "PolicyEngineUpdateNotReady");
    });

    it("cancelPolicyEngine clears pending proposal", async function () {
      await vault.proposePolicyEngine(await dailyPolicy.getAddress());
      await vault.cancelPolicyEngine();
      await expect(vault.applyPolicyEngine()).to.be.revertedWithCustomError(vault, "NoPendingPolicyEngine");
    });

    it("applyPolicyEngine sets the engine after delay and emits event", async function () {
      const addr = await dailyPolicy.getAddress();
      await vault.proposePolicyEngine(addr);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(vault.applyPolicyEngine()).to.emit(vault, "PolicyEngineUpdated").withArgs(ethers.ZeroAddress, addr);
      expect(await vault.policyEngine()).to.equal(addr);
    });

    it("proposePolicyEngine(address(0)) disables the engine", async function () {
      await setPolicyEngine(await dailyPolicy.getAddress());
      await setPolicyEngine(ethers.ZeroAddress);
      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("non-owner cannot propose or apply", async function () {
      await expect(
        vault.connect(other).proposePolicyEngine(await dailyPolicy.getAddress()),
      ).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
    });
  });

  describe("DailySpendLimitPolicy", function () {
    beforeEach(async function () {
      await setPolicyEngine(await dailyPolicy.getAddress());
      // Arming a limit requires the owner to first delegate admission authority to the
      // contract that will book against them — here, the vault itself.
      await dailyPolicy.connect(owner).setAdmitter(await vault.getAddress(), true);
    });

    it("no limit set (0) — all withdrawals pass", async function () {
      await expect(withdraw({ amount: ethers.parseEther("4") })).to.emit(vault, "Withdrawn");
    });

    it("within limit — withdrawal succeeds", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await expect(withdraw({ amount: ethers.parseEther("0.5") })).to.emit(vault, "Withdrawn");
    });

    it("over limit — withdrawal reverts with PolicyViolation", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await expect(withdraw({ amount: ethers.parseEther("1.5") }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("cumulative spend tracked across withdrawals in same window", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await withdraw({ amount: ethers.parseEther("0.6") });
      await expect(withdraw({ amount: ethers.parseEther("0.5"), nonce: 1 }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("window resets after 24h — full limit available again", async function () {
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      await withdraw({ amount: ethers.parseEther("0.9") });

      await networkHelpers.time.increase(24 * 60 * 60);

      await expect(withdraw({ amount: ethers.parseEther("0.9"), nonce: 1 })).to.emit(vault, "Withdrawn");
    });

    it("remainingAllowance reflects spend correctly", async function () {
      const limit = ethers.parseEther("1");
      await dailyPolicy.connect(owner).setDailyLimit(limit);
      const spent = ethers.parseEther("0.4");
      await withdraw({ amount: spent });

      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(limit - spent);
    });

    it("remainingAllowance returns max uint256 when no limit set", async function () {
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(ethers.MaxUint256);
    });

    it("different vault owners have independent limits", async function () {
      const otherVaultOwner = other;
      await vault.connect(otherVaultOwner).createVault(otherVaultOwner.address, PQ_KEY, 2);

      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("0.3"));

      await expect(withdraw({ amount: ethers.parseEther("0.5") })).to.be.revertedWithCustomError(
        vault,
        "PolicyViolation",
      );

      expect(await dailyPolicy.remainingAllowance(otherVaultOwner.address)).to.equal(ethers.MaxUint256);
    });
  });

  describe("RecipientAllowlistPolicy", function () {
    beforeEach(async function () {
      await setPolicyEngine(await allowlistPolicy.getAddress());
    });

    it("empty allowlist blocks all recipients", async function () {
      await expect(withdraw())
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("allowlisted recipient passes", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await expect(withdraw()).to.emit(vault, "Withdrawn");
    });

    it("non-allowlisted recipient is blocked", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await expect(withdraw({ recipient: other.address }))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient not on allowlist");
    });

    it("removing a recipient re-blocks them", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await allowlistPolicy.connect(owner).removeRecipient(recipient.address);
      await expect(withdraw()).to.be.revertedWithCustomError(vault, "PolicyViolation");
    });

    it("address(0) in allowlist disables the restriction entirely", async function () {
      await allowlistPolicy.connect(owner).addRecipient(ethers.ZeroAddress);
      await expect(withdraw({ recipient: other.address })).to.emit(vault, "Withdrawn");
    });

    it("different vault owners have independent allowlists", async function () {
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);

      const otherOwner = other;
      await vault.connect(otherOwner).createVault(otherOwner.address, PQ_KEY, 2);
      expect(await allowlistPolicy.allowlist(otherOwner.address, recipient.address)).to.be.false;
    });
  });

  describe("Credential rotation interaction", function () {
    it("preserves daily-spend policy counters across a credential rotation", async function () {
      await setPolicyEngine(await dailyPolicy.getAddress());
      await dailyPolicy.connect(owner).setAdmitter(await vault.getAddress(), true);
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));

      // Consume 0.6 of the 1.0 daily allowance (nonce 0 -> 1).
      await withdraw({ amount: ethers.parseEther("0.6") });
      const before = await dailyPolicy.remainingAllowance(owner.address);
      expect(before).to.equal(ethers.parseEther("0.4"));

      // Rotate credentials. Policy state is keyed by the vault owner address, which a
      // rotation does not change, so the counter must be untouched (no reset, no bypass).
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
      const newKey = ethers.hexlify(ethers.randomBytes(1952));
      const request = {
        vaultOwner: owner.address,
        newEcdsaSigner: other.address,
        newPQPublicKey: newKey,
        nonce: Number(await vault.nonces(owner.address)),
        deadline,
      };
      const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const auth = {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
        currentPqSignature: blob(),
        newEcdsaSignature: await other.signTypedData(domain, ROTATION_TYPES, request),
        newPqSignature: blob(),
      };
      await vault.rotateCredentials(owner.address, other.address, newKey, deadline, auth);

      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(before);
    });
  });

  // ---------------------------------------------------------------------------
  // revalidate() unit semantics (engines called directly, no vault involved)
  // ---------------------------------------------------------------------------
  describe("revalidate() unit semantics", function () {
    const AMOUNT = ethers.parseEther("1");
    const BALANCE = ethers.parseEther("5");

    it("stateless policies answer identically via check and revalidate (allowlist)", async function () {
      // Denying state.
      let viaCheck = await allowlistPolicy.check.staticCall(owner.address, recipient.address, AMOUNT, BALANCE);
      let viaReval = await allowlistPolicy.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(viaReval).to.deep.equal(viaCheck);
      expect(viaReval[0]).to.equal(false);

      // Permitting state.
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      viaCheck = await allowlistPolicy.check.staticCall(owner.address, recipient.address, AMOUNT, BALANCE);
      viaReval = await allowlistPolicy.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(viaReval).to.deep.equal(viaCheck);
      expect(viaReval[0]).to.equal(true);
    });

    it("stateless policies answer identically via check and revalidate (sanctions)", async function () {
      const sanctions = await (await ethers.getContractFactory("SanctionsListPolicy")).deploy();

      let viaCheck = await sanctions.check.staticCall(owner.address, recipient.address, AMOUNT, BALANCE);
      let viaReval = await sanctions.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(viaReval).to.deep.equal(viaCheck);
      expect(viaReval[0]).to.equal(true);

      await sanctions.addToSanctionsList(recipient.address);
      viaCheck = await sanctions.check.staticCall(owner.address, recipient.address, AMOUNT, BALANCE);
      viaReval = await sanctions.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(viaReval).to.deep.equal(viaCheck);
      expect(viaReval[0]).to.equal(false);
    });

    it("daily-limit revalidate is a pure allow that never books, even over the limit", async function () {
      // No vault involved here, so the owner self-delegates — the standalone case.
      await dailyPolicy.connect(owner).setAdmitter(owner.address, true);
      await dailyPolicy.connect(owner).setDailyLimit(ethers.parseEther("1"));
      const before = await dailyPolicy.remainingAllowance(owner.address);

      // Even an amount far above the limit is not this method's concern: the window
      // settles at admission (check). revalidate() books nothing and rejects nothing.
      const [ok, reason] = await dailyPolicy.revalidate(
        owner.address,
        recipient.address,
        ethers.parseEther("100"),
        BALANCE,
      );
      expect(ok).to.equal(true);
      expect(reason).to.equal("");
      expect(await dailyPolicy.remainingAllowance(owner.address)).to.equal(before);
    });

    it("composite revalidate fans out over current modules and propagates the first denial", async function () {
      const composite = await (await ethers.getContractFactory("CompositePolicyEngine")).deploy();
      const sanctions = await (await ethers.getContractFactory("SanctionsListPolicy")).deploy();
      await composite.addModule(await allowlistPolicy.getAddress());
      await composite.addModule(await sanctions.getAddress());

      // allowlist denies (empty) → its reason surfaces first.
      let [ok, reason] = await composite.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(ok).to.equal(false);
      expect(reason).to.equal("recipient not on allowlist");

      // Allowlist satisfied, sanctions denies → sanctions reason surfaces.
      await allowlistPolicy.connect(owner).addRecipient(recipient.address);
      await sanctions.addToSanctionsList(recipient.address);
      [ok, reason] = await composite.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(ok).to.equal(false);
      expect(reason).to.equal("recipient is sanctioned");

      // All modules permit → allowed.
      await sanctions.removeFromSanctionsList(recipient.address);
      [ok, reason] = await composite.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(ok).to.equal(true);
      expect(reason).to.equal("");
    });

    it("an empty composite is permissive via revalidate, mirroring check", async function () {
      const composite = await (await ethers.getContractFactory("CompositePolicyEngine")).deploy();
      const [ok] = await composite.revalidate(owner.address, recipient.address, AMOUNT, BALANCE);
      expect(ok).to.equal(true);
    });

    it("a composite containing a check-only (legacy) module reverts on revalidate — fail-closed", async function () {
      const composite = await (await ethers.getContractFactory("CompositePolicyEngine")).deploy();
      const legacy = await (await ethers.getContractFactory("LegacyCheckOnlyPolicyMock")).deploy();
      await composite.addModule(await legacy.getAddress());
      await expect(composite.revalidate(owner.address, recipient.address, AMOUNT, BALANCE)).to.revert(ethers);
    });
  });
});
