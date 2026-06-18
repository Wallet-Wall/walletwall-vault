import { expect } from "chai";
import { ethers } from "hardhat";
import { MockUSDC } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("MockUSDC", function () {
  let token: MockUSDC;
  let owner: HardhatEthersSigner;
  let user: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  beforeEach(async function () {
    [owner, user, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MockUSDC");
    token = await Factory.deploy();
    await token.waitForDeployment();
  });

  describe("Metadata", function () {
    it("has 6 decimals", async function () {
      expect(await token.decimals()).to.equal(6);
    });

    it("has expected name and symbol", async function () {
      expect(await token.name()).to.equal("WalletWall Mock USD");
      expect(await token.symbol()).to.equal("mUSDC");
    });

    it("starts with zero total supply", async function () {
      expect(await token.totalSupply()).to.equal(0n);
    });
  });

  describe("faucet()", function () {
    it("mints 1 000 mUSDC to the caller", async function () {
      const FAUCET_AMOUNT = 1_000n * 1_000_000n; // 1 000 * 1e6
      await token.connect(user).faucet();
      expect(await token.balanceOf(user.address)).to.equal(FAUCET_AMOUNT);
    });

    it("can be called by anyone, multiple times", async function () {
      await token.connect(user).faucet();
      await token.connect(user).faucet();
      await token.connect(other).faucet();
      expect(await token.balanceOf(user.address)).to.equal(2_000n * 1_000_000n);
      expect(await token.balanceOf(other.address)).to.equal(1_000n * 1_000_000n);
    });
  });

  describe("mint(address, uint256)", function () {
    it("mints the requested amount to the target address", async function () {
      const amount = 500_000n * 1_000_000n; // 500 000 mUSDC
      await token.connect(user).mint(other.address, amount);
      expect(await token.balanceOf(other.address)).to.equal(amount);
    });

    it("is permissionless — any address can call it", async function () {
      const amount = 1_000n * 1_000_000n;
      await token.connect(other).mint(user.address, amount);
      expect(await token.balanceOf(user.address)).to.equal(amount);
    });

    it("mints exactly MAX_MINT_PER_CALL without reverting", async function () {
      const cap = await token.MAX_MINT_PER_CALL();
      await expect(token.mint(user.address, cap)).to.not.be.reverted;
      expect(await token.balanceOf(user.address)).to.equal(cap);
    });

    it("reverts when amount exceeds MAX_MINT_PER_CALL", async function () {
      const cap = await token.MAX_MINT_PER_CALL();
      await expect(token.mint(user.address, cap + 1n)).to.be.revertedWithCustomError(token, "MintExceedsPerCallCap");
    });

    it("emits a Transfer event from address(0)", async function () {
      const amount = 100n * 1_000_000n;
      await expect(token.mint(user.address, amount))
        .to.emit(token, "Transfer")
        .withArgs(ethers.ZeroAddress, user.address, amount);
    });
  });

  describe("ERC-20 transfers", function () {
    it("allows standard transfer between accounts", async function () {
      const amount = 100n * 1_000_000n;
      await token.connect(user).faucet();
      await token.connect(user).transfer(other.address, amount);
      expect(await token.balanceOf(other.address)).to.equal(amount);
    });

    it("reverts on transfer with insufficient balance", async function () {
      await expect(token.connect(user).transfer(other.address, 1n)).to.be.reverted;
    });
  });
});
