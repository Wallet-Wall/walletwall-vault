/**
 * H-22 — accounted ETH ingress must be refused while the vault is paused.
 *
 * THE DEFECT THIS PINS
 * --------------------
 * `pause()` freezes every payout path of `WalletWallVault`: `withdraw`, `queueWithdrawal`,
 * `finalizeWithdrawal`, `rotateCredentials`, `initiateRecovery` and `executeRecovery` are all
 * `whenNotPaused`, and so is `createVault`, whose `msg.value` is credited to the new vault.
 * `deposit()` and `depositFor()` were not. A paused vault therefore kept booking deposits into a
 * ledger it could not pay out of, deepening any concurrent freeze for every tenant. The sibling
 * `StablecoinVaultSimulator` gates both of its deposit paths, so two contracts implementing the
 * same semantics answered the same question differently (docs/Vault_vNext_Hazard_Register.md,
 * H-22 and H-16).
 *
 * WHAT THIS SUITE PROVES, AND WHAT IT DOES NOT
 * --------------------------------------------
 * It proves that while paused neither explicit deposit path books anything, that the refusal is
 * suspensive (the same call credits once unpaused), that third-party funding still credits the
 * named vault rather than the funder, and that both siblings now give the same answer on both
 * deposit paths.
 *
 * It does NOT claim that a paused vault receives no ETH. Forced ETH (a `selfdestruct`
 * beneficiary, a block's fee recipient) reaches an address without calling any function, so no
 * modifier can refuse it; it is pinned below as still arriving and still uncredited. The change
 * adds no principal and no authority: `pause()` keeps its existing owner and its existing,
 * unbounded duration (H-12). It has no bearing on migration asset-planting (H-28), which never
 * traverses a deposit function.
 */

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import type { MockUSDC, StablecoinVaultSimulator, WalletWallVault } from "../typechain-types";

const HYBRID = 2;

describe("H-22: accounted ETH ingress is refused while paused", function () {
  let admin: HardhatEthersSigner;
  let tenant: HardhatEthersSigner;
  let funder: HardhatEthersSigner;

  let vault: WalletWallVault;
  let sim: StablecoinVaultSimulator;
  let token: MockUSDC;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));

  beforeEach(async function () {
    [admin, tenant, funder] = await ethers.getSigners();

    const verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    token = await (await ethers.getContractFactory("MockUSDC", admin)).deploy();
    sim = await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await verifier.getAddress());

    // One existing tenant vault on each contract, created while unpaused and holding nothing,
    // so every balance asserted below is attributable to the step under test.
    await vault.connect(tenant).createVault(tenant.address, PQ_KEY, HYBRID);
    await sim.connect(tenant).createVault(tenant.address, PQ_KEY, HYBRID);
  });

  it("deposit(): refused while paused with nothing booked, and credits again once unpaused", async function () {
    const vaultAddress = await vault.getAddress();
    await vault.connect(admin).pause();

    await expect(vault.connect(tenant).deposit({ value: 1_000n })).to.be.revertedWithCustomError(
      vault,
      "EnforcedPause",
    );
    expect((await vault.getVault(tenant.address)).balance, "a paused vault booked a deposit").to.equal(0n);
    expect(await ethers.provider.getBalance(vaultAddress)).to.equal(0n);

    await vault.connect(admin).unpause();

    await expect(vault.connect(tenant).deposit({ value: 1_000n }))
      .to.emit(vault, "Deposited")
      .withArgs(tenant.address, tenant.address, 1_000n);
    expect((await vault.getVault(tenant.address)).balance).to.equal(1_000n);
    expect(await ethers.provider.getBalance(vaultAddress)).to.equal(1_000n);
  });

  it("depositFor(): a third-party funder is refused while paused, and once unpaused credits the named vault, not the funder", async function () {
    await vault.connect(admin).pause();

    await expect(vault.connect(funder).depositFor(tenant.address, { value: 2_000n })).to.be.revertedWithCustomError(
      vault,
      "EnforcedPause",
    );
    expect((await vault.getVault(tenant.address)).balance, "a paused vault booked a third-party deposit").to.equal(0n);

    await vault.connect(admin).unpause();

    await expect(vault.connect(funder).depositFor(tenant.address, { value: 2_000n }))
      .to.emit(vault, "Deposited")
      .withArgs(tenant.address, funder.address, 2_000n);
    expect((await vault.getVault(tenant.address)).balance).to.equal(2_000n);
    // The funder needs no vault of its own, and none was created or credited.
    expect((await vault.getVault(funder.address)).exists).to.equal(false);
  });

  it("parity: both siblings give the same answer on both deposit paths, paused and unpaused", async function () {
    const simAddress = await sim.getAddress();
    await token.mint(tenant.address, 10_000n);
    await token.mint(funder.address, 10_000n);
    await token.connect(tenant).approve(simAddress, 10_000n);
    await token.connect(funder).approve(simAddress, 10_000n);

    const paths = [
      {
        name: "deposit",
        onVault: () => vault.connect(tenant).deposit({ value: 100n }),
        onSim: () => sim.connect(tenant).deposit(100n),
      },
      {
        name: "depositFor",
        onVault: () => vault.connect(funder).depositFor(tenant.address, { value: 100n }),
        onSim: () => sim.connect(funder).depositFor(tenant.address, 100n),
      },
    ];

    await vault.connect(admin).pause();
    await sim.connect(admin).pause();
    for (const path of paths) {
      await expect(path.onVault(), `WalletWallVault.${path.name} while paused`).to.be.revertedWithCustomError(
        vault,
        "EnforcedPause",
      );
      await expect(path.onSim(), `StablecoinVaultSimulator.${path.name} while paused`).to.be.revertedWithCustomError(
        sim,
        "EnforcedPause",
      );
    }

    await vault.connect(admin).unpause();
    await sim.connect(admin).unpause();
    for (const path of paths) {
      await expect(path.onVault(), `WalletWallVault.${path.name} while unpaused`).to.emit(vault, "Deposited");
      await expect(path.onSim(), `StablecoinVaultSimulator.${path.name} while unpaused`).to.emit(sim, "Deposited");
    }

    expect((await vault.getVault(tenant.address)).balance).to.equal(200n);
    expect((await sim.getVault(tenant.address)).balance).to.equal(200n);
  });

  it("createVault(): an opening deposit, the third accounted ingress, is refused while paused as well", async function () {
    await vault.connect(admin).pause();

    await expect(
      vault.connect(funder).createVault(funder.address, PQ_KEY, HYBRID, { value: 3_000n }),
    ).to.be.revertedWithCustomError(vault, "EnforcedPause");
    expect((await vault.getVault(funder.address)).exists).to.equal(false);
    expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(0n);
  });

  describe("boundaries this change does not move", function () {
    it("forced ETH still reaches a paused vault and is never credited: no modifier can refuse it", async function () {
      const vaultAddress = await vault.getAddress();
      await vault.connect(admin).pause();

      const ForceSend = await ethers.getContractFactory("ForceSend", funder);
      await (await ForceSend.deploy(vaultAddress, { value: 5_000n })).waitForDeployment();

      expect(await ethers.provider.getBalance(vaultAddress), "forced ETH arrives regardless of pause").to.equal(5_000n);
      expect((await vault.getVault(tenant.address)).balance, "forced ETH is never booked").to.equal(0n);
    });

    it("a plain ETH transfer is refused whether paused or not: the contract has no receive() or fallback()", async function () {
      const to = await vault.getAddress();

      await expect(funder.sendTransaction({ to, value: 1n })).to.revert(ethers);
      await vault.connect(admin).pause();
      await expect(funder.sendTransaction({ to, value: 1n })).to.revert(ethers);

      expect(await ethers.provider.getBalance(to)).to.equal(0n);
    });
  });
});
