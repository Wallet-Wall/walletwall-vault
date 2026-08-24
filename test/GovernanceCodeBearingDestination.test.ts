import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  WalletWallVault,
  StablecoinVaultSimulator,
  MockMLDSAVerifier,
  MockUSDC,
  SanctionsListPolicy,
  RecipientAllowlistPolicy,
} from "../typechain-types";

/**
 * Governance destinations must be structurally executable at BOTH proposal time
 * AND apply time.
 *
 * Background: `proposePQVerifier` / `applyPQVerifierUpdate` (WalletWallVault) and
 * `proposePolicyEngine` / `applyPolicyEngine` (WalletWallVault, StablecoinVaultSimulator)
 * accepted any nonzero address as a governance destination — including an EOA, or a
 * contract that later loses its code before the governance delay elapses and the
 * proposal is applied. A governance delay separates proposal from execution; proposal-time
 * validation alone is not a permanent guarantee, because the destination can go code-less
 * during the delay window. These tests began life as characterization of that gap and now
 * pin the fix: a code-less destination is rejected at BOTH proposal and apply time, a
 * rejected apply leaves active state unchanged and pending state intact/cancellable, and
 * `address(0)` remains a valid policy-engine disable value throughout.
 *
 * `.code.length > 0` proves only that the destination is code-bearing at that instant — it
 * does not prove interface conformance, behavioral correctness, immutability of code, or
 * future availability. See docs/Security_Assumptions.md.
 */
describe("Governance destinations must be code-bearing (security)", function () {
  let vault: WalletWallVault;
  let sim: StablecoinVaultSimulator;
  let token: MockUSDC;
  let verifier: MockMLDSAVerifier;
  let verifier2: MockMLDSAVerifier;
  let sanctionsPolicy: SanctionsListPolicy;
  let allowlistPolicy: RecipientAllowlistPolicy;

  let admin: HardhatEthersSigner;
  let nonOwner: HardhatEthersSigner;
  let eoa: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;

  beforeEach(async function () {
    [admin, nonOwner, eoa] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    verifier2 = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    token = await (await ethers.getContractFactory("MockUSDC", admin)).deploy();
    sanctionsPolicy = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();
    allowlistPolicy = await (await ethers.getContractFactory("RecipientAllowlistPolicy", admin)).deploy();

    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    sim = await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await verifier.getAddress());
  });

  /// Wipes the code at `address` in place, leaving balance/storage untouched — simulates a
  /// governance destination that had code at propose time but is code-less by apply time.
  /// Real SELFDESTRUCT cannot manufacture this across two separate transactions under this
  /// repo's configured Cancun EVM target (EIP-6780 only clears code within the CREATING
  /// transaction), so this uses the Hardhat Network `hardhat_setCode` test RPC instead —
  /// a test-harness technique, not a change to production encapsulation.
  async function wipeCode(address: string) {
    await ethers.provider.send("hardhat_setCode", [address, "0x"]);
  }

  // =========================================================================
  // PQ verifier governance — WalletWallVault
  // =========================================================================
  describe("WalletWallVault — PQ verifier governance", function () {
    it("1. rejects a nonzero EOA proposed as PQ verifier", async function () {
      await expect(vault.connect(admin).proposePQVerifier(eoa.address))
        .to.be.revertedWithCustomError(vault, "NoCode")
        .withArgs(eoa.address);
    });

    it("2. apply rejects a pending PQ verifier that lost its code before the delay matured", async function () {
      const target = await verifier2.getAddress();
      await vault.connect(admin).proposePQVerifier(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(vault.connect(admin).applyPQVerifierUpdate())
        .to.be.revertedWithCustomError(vault, "NoCode")
        .withArgs(target);
    });

    it("3. a failed apply leaves the active PQ verifier unchanged", async function () {
      const target = await verifier2.getAddress();
      await vault.connect(admin).proposePQVerifier(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.revert(ethers);

      expect(await vault.pqVerifier()).to.equal(await verifier.getAddress());
    });

    it("4. a failed apply leaves the pending PQ verifier proposal intact and cancellable", async function () {
      const target = await verifier2.getAddress();
      await vault.connect(admin).proposePQVerifier(target);
      const validAfter = await vault.pendingPQVerifierValidAfter();
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.revert(ethers);

      expect(await vault.pendingPQVerifier()).to.equal(target);
      expect(await vault.pendingPQVerifierValidAfter()).to.equal(validAfter);

      await expect(vault.connect(admin).cancelPQVerifierUpdate())
        .to.emit(vault, "PQVerifierUpdateCancelled")
        .withArgs(target);
    });

    it("5. a valid PQ verifier contract still applies successfully after the full delay", async function () {
      const target = await verifier2.getAddress();
      await vault.connect(admin).proposePQVerifier(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);

      await expect(vault.connect(admin).applyPQVerifierUpdate())
        .to.emit(vault, "PQVerifierUpdated")
        .withArgs(await verifier.getAddress(), target);

      expect(await vault.pqVerifier()).to.equal(target);
      expect(await vault.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
    });
  });

  // =========================================================================
  // Policy engine governance — WalletWallVault
  // =========================================================================
  describe("WalletWallVault — policy engine governance", function () {
    it("6. rejects a nonzero EOA proposed as policy engine", async function () {
      await expect(vault.connect(admin).proposePolicyEngine(eoa.address))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(eoa.address);
    });

    it("7. apply rejects a pending policy engine that lost its code before the delay matured", async function () {
      const target = await sanctionsPolicy.getAddress();
      await vault.connect(admin).proposePolicyEngine(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(vault.connect(admin).applyPolicyEngine())
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(target);
    });

    it("8. a failed apply leaves active and pending policy-engine state unchanged", async function () {
      const target = await sanctionsPolicy.getAddress();
      await vault.connect(admin).proposePolicyEngine(target);
      const validAfter = await vault.pendingPolicyEngineValidAfter();
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(vault.connect(admin).applyPolicyEngine()).to.revert(ethers);

      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
      expect(await vault.pendingPolicyEngine()).to.equal(target);
      expect(await vault.pendingPolicyEngineValidAfter()).to.equal(validAfter);

      await expect(vault.connect(admin).cancelPolicyEngine())
        .to.emit(vault, "PolicyEngineUpdateCancelled")
        .withArgs(target);
    });

    it("9. proposePolicyEngine(address(0)) still disables the policy engine after the full delay", async function () {
      await vault.connect(admin).proposePolicyEngine(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyPolicyEngine();
      expect(await vault.policyEngine()).to.equal(await sanctionsPolicy.getAddress());

      await expect(vault.connect(admin).proposePolicyEngine(ethers.ZeroAddress)).to.not.revert(ethers);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);

      await expect(vault.connect(admin).applyPolicyEngine())
        .to.emit(vault, "PolicyEngineUpdated")
        .withArgs(await sanctionsPolicy.getAddress(), ethers.ZeroAddress);

      expect(await vault.policyEngine()).to.equal(ethers.ZeroAddress);
    });

    it("10. a real policy engine contract still proposes, waits, and applies normally", async function () {
      const target = await allowlistPolicy.getAddress();
      await vault.connect(admin).proposePolicyEngine(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);

      await expect(vault.connect(admin).applyPolicyEngine())
        .to.emit(vault, "PolicyEngineUpdated")
        .withArgs(ethers.ZeroAddress, target);

      expect(await vault.policyEngine()).to.equal(target);
    });
  });

  // =========================================================================
  // Policy engine governance — StablecoinVaultSimulator (mirrors the vault)
  // =========================================================================
  describe("StablecoinVaultSimulator — policy engine governance", function () {
    it("11. rejects a nonzero EOA proposed as policy engine", async function () {
      await expect(sim.connect(admin).proposePolicyEngine(eoa.address))
        .to.be.revertedWithCustomError(sim, "PolicyEngineUnavailable")
        .withArgs(eoa.address);
    });

    it("12. apply rejects a pending policy engine that lost its code before the delay matured", async function () {
      const target = await sanctionsPolicy.getAddress();
      await sim.connect(admin).proposePolicyEngine(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(sim.connect(admin).applyPolicyEngine())
        .to.be.revertedWithCustomError(sim, "PolicyEngineUnavailable")
        .withArgs(target);
    });

    it("13. a failed apply leaves active and pending policy-engine state unchanged", async function () {
      const target = await sanctionsPolicy.getAddress();
      await sim.connect(admin).proposePolicyEngine(target);
      const validAfter = await sim.pendingPolicyEngineValidAfter();
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await wipeCode(target);

      await expect(sim.connect(admin).applyPolicyEngine()).to.revert(ethers);

      expect(await sim.policyEngine()).to.equal(ethers.ZeroAddress);
      expect(await sim.pendingPolicyEngine()).to.equal(target);
      expect(await sim.pendingPolicyEngineValidAfter()).to.equal(validAfter);

      await expect(sim.connect(admin).cancelPolicyEngine())
        .to.emit(sim, "PolicyEngineUpdateCancelled")
        .withArgs(target);
    });

    it("14. proposePolicyEngine(address(0)) still disables the policy engine after the full delay", async function () {
      await sim.connect(admin).proposePolicyEngine(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();
      expect(await sim.policyEngine()).to.equal(await sanctionsPolicy.getAddress());

      await expect(sim.connect(admin).proposePolicyEngine(ethers.ZeroAddress)).to.not.revert(ethers);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);

      await expect(sim.connect(admin).applyPolicyEngine())
        .to.emit(sim, "PolicyEngineUpdated")
        .withArgs(await sanctionsPolicy.getAddress(), ethers.ZeroAddress);

      expect(await sim.policyEngine()).to.equal(ethers.ZeroAddress);
    });

    it("15. a real policy engine contract still proposes, waits, and applies normally", async function () {
      const target = await allowlistPolicy.getAddress();
      await sim.connect(admin).proposePolicyEngine(target);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);

      await expect(sim.connect(admin).applyPolicyEngine())
        .to.emit(sim, "PolicyEngineUpdated")
        .withArgs(ethers.ZeroAddress, target);

      expect(await sim.policyEngine()).to.equal(target);
    });
  });

  // =========================================================================
  // 16. Non-owner governance behavior remains unchanged
  // =========================================================================
  describe("16. non-owner governance behavior remains unchanged", function () {
    it("WalletWallVault PQ verifier propose/apply stay owner-gated", async function () {
      await expect(
        vault.connect(nonOwner).proposePQVerifier(await verifier2.getAddress()),
      ).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");

      await vault.connect(admin).proposePQVerifier(await verifier2.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(vault.connect(nonOwner).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
    });

    it("WalletWallVault policy engine propose/apply stay owner-gated", async function () {
      await expect(
        vault.connect(nonOwner).proposePolicyEngine(await sanctionsPolicy.getAddress()),
      ).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");

      await vault.connect(admin).proposePolicyEngine(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(vault.connect(nonOwner).applyPolicyEngine()).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
    });

    it("StablecoinVaultSimulator policy engine propose/apply stay owner-gated", async function () {
      await expect(
        sim.connect(nonOwner).proposePolicyEngine(await sanctionsPolicy.getAddress()),
      ).to.be.revertedWithCustomError(sim, "OwnableUnauthorizedAccount");

      await sim.connect(admin).proposePolicyEngine(await sanctionsPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(sim.connect(nonOwner).applyPolicyEngine()).to.be.revertedWithCustomError(
        sim,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  // =========================================================================
  // 17. Delay-boundary behavior remains unchanged
  // =========================================================================
  describe("17. delay-boundary behavior remains unchanged", function () {
    it("PQ verifier apply still reverts before the delay matures, still succeeds once it has", async function () {
      const target = await verifier2.getAddress();
      await vault.connect(admin).proposePQVerifier(target);

      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "PQVerifierUpdateNotReady",
      );

      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(vault.connect(admin).applyPQVerifierUpdate()).to.not.revert(ethers);
      expect(await vault.pqVerifier()).to.equal(target);
    });

    it("policy engine apply still reverts before the delay matures, still succeeds once it has", async function () {
      const target = await sanctionsPolicy.getAddress();
      await vault.connect(admin).proposePolicyEngine(target);

      await expect(vault.connect(admin).applyPolicyEngine()).to.be.revertedWithCustomError(
        vault,
        "PolicyEngineUpdateNotReady",
      );

      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(vault.connect(admin).applyPolicyEngine()).to.not.revert(ethers);
      expect(await vault.policyEngine()).to.equal(target);
    });
  });
});
