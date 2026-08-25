import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, StablecoinVaultSimulator, MockUSDC } from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";

/**
 * Regression suite for the EXPIRY of vault governance proposals.
 *
 * Both vaults gate their trust-boundary swaps behind a two-day propose/apply
 * delay (`PQ_VERIFIER_UPDATE_DELAY`, `POLICY_ENGINE_UPDATE_DELAY`,
 * `LARGE_TX_PARAMS_UPDATE_DELAY`). None of those matured proposals expired, so
 * the delay bought a reaction window only when the proposal was made AFTER the
 * need for it arose. A matured proposal could be PRE-ARMED at a quiet moment,
 * banked indefinitely, and then exercised instantly — costing zero delay and
 * giving zero fresh notice at the moment it mattered.
 *
 * THE PQ VERIFIER IS THE SEVERE CASE. `pqVerifier` is contract-level, not
 * per-vault, so one swap changes the authorization authority for EVERY vault at
 * once. In `VaultMode.PqOnly` (`needEcdsa == false`) the live verifier is the
 * SOLE authorization gate — there is no classical fallback and, unlike the
 * policy engine, no queue-time sticky floor pinning the verifier a withdrawal
 * was admitted under. It also gates {rotateCredentials}, so a forging verifier
 * enables credential takeover, not just a single withdrawal. Worse, the
 * `PqOnlyDisabledForMockVerifier` guard runs only at vault CREATION, so a
 * banked swap can retroactively restore the exact configuration that guard
 * exists to prevent, for vaults that already exist.
 *
 * Demonstrated before the fix: a proposal pre-armed a year in advance replaced
 * the verifier instantly, and a withdrawal that the active verifier had just
 * REJECTED became authorized with no intervening notice.
 *
 * FIXED MODEL (this suite pins it): a matured proposal stays applicable only
 * for `GOVERNANCE_GRACE_PERIOD`, after which it expires and must be re-proposed
 * — paying the full delay again. The property restored is bounded warning: any
 * governance action executable right now was announced by its proposal event
 * within the last DELAY + GRACE window.
 */
describe("Vault governance proposal expiry", function () {
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const DELAY = 2 * 24 * 60 * 60; // all three vault governance delays are 2 days
  const GRACE = 14 * 24 * 60 * 60; // GOVERNANCE_GRACE_PERIOD
  const LONG_DORMANCY = 365 * 24 * 60 * 60;
  const DEPOSIT = ethers.parseEther("10");
  const AMOUNT = ethers.parseEther("1");

  let admin: HardhatEthersSigner, owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner, other: HardhatEthersSigner;

  beforeEach(async function () {
    [admin, owner, recipient, other] = await ethers.getSigners();
  });

  async function deployVault(verifierName = "MockMLDSAVerifier") {
    const verifier = await (await ethers.getContractFactory(verifierName, admin)).deploy();
    const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    return { vault: vault as WalletWallVault, verifier };
  }

  async function deploySimulator() {
    const verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    const token = (await (await ethers.getContractFactory("MockUSDC", admin)).deploy()) as MockUSDC;
    const sim = (await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await verifier.getAddress())) as StablecoinVaultSimulator;
    return { sim, token, verifier };
  }

  // =========================================================================
  // A — the severe case: PQ verifier, the sole PqOnly authorization authority.
  // =========================================================================
  describe("A — PQ verifier (sole PqOnly authorization authority)", function () {
    it("GOVERNANCE_GRACE_PERIOD is exposed and bounded on both vaults", async function () {
      const { vault } = await deployVault();
      const { sim } = await deploySimulator();
      expect(await vault.GOVERNANCE_GRACE_PERIOD()).to.equal(BigInt(GRACE));
      expect(await sim.GOVERNANCE_GRACE_PERIOD()).to.equal(BigInt(GRACE));
    });

    it("a banked PQ-verifier proposal EXPIRES and cannot be exercised", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);

      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "ProposalExpired",
      );
    });

    it("END-TO-END: a banked swap cannot instantly authorize a PqOnly withdrawal the active verifier rejects", async function () {
      const rejecting = await (await ethers.getContractFactory("AlwaysFalsePQCVerifier", admin)).deploy();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();
      const vault = (await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await rejecting.getAddress())) as WalletWallVault;

      // PqOnly: needEcdsa is false, so the live verifier is the ONLY gate.
      await vault.connect(owner).createVault(owner.address, PQ_KEY, 1);
      await vault.connect(owner).deposit({ value: DEPOSIT });

      const build = makeBuildRequest(owner, { recipient: recipient.address, amount: AMOUNT, vaultMode: 1 });
      const req = await build({ nonce: 0 });
      const { ecdsaSig, pqSig } = await makeSignWithdrawal(vault, owner)(req);
      await expect(vault.connect(other).withdraw(req, ecdsaSig, pqSig)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );

      // Pre-armed a year earlier, then exercised at the moment of need.
      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "ProposalExpired",
      );

      // The authority is unchanged, so the withdrawal is still unauthorized.
      expect(await vault.pqVerifier()).to.equal(await rejecting.getAddress());
      const req2 = await build({ nonce: 0 });
      const sig2 = await makeSignWithdrawal(vault, owner)(req2);
      await expect(vault.connect(other).withdraw(req2, sig2.ecdsaSig, sig2.pqSig)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );
    });

    it("the simulator's PQ-verifier proposal expires too", async function () {
      const { sim } = await deploySimulator();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await sim.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(sim.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(sim, "ProposalExpired");
    });
  });

  // =========================================================================
  // B — the same bound on every other governance pair, both vaults.
  // =========================================================================
  describe("B — policy engine and large-tx params", function () {
    it("a banked policy-engine proposal expires (WalletWallVault)", async function () {
      const { vault } = await deployVault();
      const engine = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();

      await vault.connect(admin).proposePolicyEngine(await engine.getAddress());
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(vault.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(vault, "ProposalExpired");
    });

    it("a banked policy-engine proposal expires (StablecoinVaultSimulator)", async function () {
      const { sim } = await deploySimulator();
      const engine = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();

      await sim.connect(admin).proposePolicyEngine(await engine.getAddress());
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(sim.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(sim, "ProposalExpired");
    });

    it("a banked large-tx-params proposal expires (WalletWallVault)", async function () {
      const { vault } = await deployVault();
      await vault.connect(admin).proposeLargeTxParams(ethers.parseEther("3"), 24 * 60 * 60);
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(vault.connect(admin).applyLargeTxParams()).to.be.revertedWithCustomError(vault, "ProposalExpired");
    });

    it("a banked large-tx-params proposal expires (StablecoinVaultSimulator)", async function () {
      const { sim } = await deploySimulator();
      await sim.connect(admin).proposeLargeTxParams(3_000_000n, 24 * 60 * 60);
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(sim.connect(admin).applyLargeTxParams()).to.be.revertedWithCustomError(sim, "ProposalExpired");
    });

    it("a banked policy-engine DISABLE (address(0)) also expires -- disabling is a weakening too", async function () {
      const { vault } = await deployVault();
      await vault.connect(admin).proposePolicyEngine(ethers.ZeroAddress);
      await networkHelpers.time.increase(DELAY + LONG_DORMANCY);
      await expect(vault.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(vault, "ProposalExpired");
    });
  });

  // =========================================================================
  // C — boundary behaviour and recovery from expiry.
  // =========================================================================
  describe("C — grace boundary and re-proposal", function () {
    it("the final second of the grace window is still applicable", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();
      await vault.connect(admin).proposePQVerifier(await forging.getAddress());

      const validAfter = await vault.pendingPQVerifierValidAfter();
      await networkHelpers.time.setNextBlockTimestamp(validAfter + BigInt(GRACE));
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdated");
    });

    it("one second past the grace window is refused", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();
      await vault.connect(admin).proposePQVerifier(await forging.getAddress());

      const validAfter = await vault.pendingPQVerifierValidAfter();
      await networkHelpers.time.setNextBlockTimestamp(validAfter + BigInt(GRACE) + 1n);
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "ProposalExpired",
      );
    });

    it("an expired proposal must be re-proposed AND pay a fresh full delay", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY + GRACE + 1);

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "PQVerifierUpdateNotReady",
      );

      await networkHelpers.time.increase(DELAY);
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdated");
    });

    it("an expired proposal is still explicitly cancellable, clearing the stale pending record", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY + GRACE + 1);

      await expect(vault.connect(admin).cancelPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdateCancelled");
      expect(await vault.pendingPQVerifierValidAfter()).to.equal(0n);
    });

    it("a rejected expired apply leaves the ACTIVE authority and the pending proposal untouched", async function () {
      const { vault, verifier } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      const validAfter = await vault.pendingPQVerifierValidAfter();
      await networkHelpers.time.increase(DELAY + GRACE + 1);

      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "ProposalExpired",
      );
      expect(await vault.pqVerifier()).to.equal(await verifier.getAddress());
      expect(await vault.pendingPQVerifier()).to.equal(await forging.getAddress());
      expect(await vault.pendingPQVerifierValidAfter()).to.equal(validAfter);
    });
  });

  // =========================================================================
  // D — the honest path is unchanged.
  // =========================================================================
  describe("D — legitimate governance still works", function () {
    it("a PQ-verifier update applied promptly after its delay still succeeds", async function () {
      const { vault } = await deployVault();
      const forging = await (await ethers.getContractFactory("AlwaysTruePQCVerifier", admin)).deploy();

      await vault.connect(admin).proposePQVerifier(await forging.getAddress());
      await networkHelpers.time.increase(DELAY);
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.emit(vault, "PQVerifierUpdated");
      expect(await vault.pqVerifier()).to.equal(await forging.getAddress());
    });

    it("a policy-engine update applied promptly after its delay still succeeds", async function () {
      const { vault } = await deployVault();
      const engine = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();

      await vault.connect(admin).proposePolicyEngine(await engine.getAddress());
      await networkHelpers.time.increase(DELAY);
      await expect(vault.connect(admin).applyPolicyEngine()).to.emit(vault, "PolicyEngineUpdated");
    });

    it("a large-tx-params update applied promptly after its delay still succeeds", async function () {
      const { vault } = await deployVault();
      await vault.connect(admin).proposeLargeTxParams(ethers.parseEther("3"), 24 * 60 * 60);
      await networkHelpers.time.increase(DELAY);
      await expect(vault.connect(admin).applyLargeTxParams()).to.emit(vault, "LargeTxParamsApplied");
    });
  });
});
