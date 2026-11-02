/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * THE ADMITTED-ASSET ERC-20 SPEND PLANE, UNDER ATTACK. This suite exercises the two
 * Generation-2 candidate kernels (`erc20-spend-plane/contracts/`) against the
 * security properties the lane brief names —
 *
 *   ERC20-1   relayer gains no authority
 *   ERC20-2   asset cannot be caller-selected
 *   ERC20-3   cross-asset replay fails
 *   ERC20-4   nonce replay fails
 *   ERC20-5   failed transfer is atomic
 *   ERC20-6   direct transfer does not corrupt spendability
 *   ERC20-7   migration recipient remains fixed
 *   ERC20-8   migration asset remains fixed
 *   ERC20-9   arbitrary caller may execute a valid authorised action
 *   ERC20-10  WalletWall owns no new on-chain capability
 *
 * — plus the zero-amount, codeless-asset, hook-bearing-asset and issuer-upgraded-
 * asset cases, both genesis variants, and a local comparative GAS table.
 *
 * THE VACUITY RULE, inherited from KernelPrototype.test.ts: every attack is paired
 * with a POSITIVE CONTROL — the identical call with the one adversarial input
 * corrected — asserted in the same test, so a refusal is attributable to the
 * invariant and not to a broken fixture.
 *
 * The admitted asset is ALWAYS a local mock. Nothing here deploys to any network,
 * names a production asset, or authorises real value. Gas figures are LOCAL
 * COMPARATIVE measurements on the Hardhat network and are not cost claims.
 */
import { expect } from "chai";
import fs from "node:fs";

import { ethers } from "./connection.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  KERNEL_GENERATION_2,
  UNIT,
  ZERO,
  addrOf,
  advanceTime,
  balanceOf,
  bindDestination,
  currentNonce,
  deployArtifact,
  deployErc20World,
  deployUnit,
  gasOf,
  keyOf,
  migrationSnapshot,
  packedArgs,
  planeUnit,
  pqKeyBytes,
  proposeRecovery,
  sendSpend,
  setPolicy,
  setVerifier,
  sign,
  spendDigest,
  type Erc20World,
} from "./erc20-spend-plane-world.js";
import { digestOf, migrationParams, spendParams } from "../stateful/world.js";
import { PLANE_RECORD_JSON } from "../erc20-spend-plane/compile.js";

const AMOUNT = 250n * UNIT;
const PROBE_GAS = 400_000n;

/** The Generation-1 kernel's state-changing surface, read from the Hardhat artifact: the yardstick for ERC20-10. */
async function gen1StateChangingNames(): Promise<string[]> {
  const iface = (await ethers.getContractFactory("VaultKernelPrototype")).interface;
  return iface.fragments
    .filter((f) => f.type === "function" && !["view", "pure"].includes((f as ethers.FunctionFragment).stateMutability))
    .map((f) => (f as ethers.FunctionFragment).name)
    .sort();
}

const stateChangingNames = (iface: ethers.Interface): string[] =>
  iface.fragments
    .filter((f) => f.type === "function" && !["view", "pure"].includes((f as ethers.FunctionFragment).stateMutability))
    .map((f) => (f as ethers.FunctionFragment).name)
    .sort();

describe("ERC-20 spend plane — invariants under attack", function () {
  this.timeout(300_000);

  // =====================================================================
  describe("code identity — the asset is a fact of the clone's own code (ERC20-2, custody doc section 7.1)", function () {
    it("admittedAsset() reads the factory's asset back from the clone's immutable args, which sit in the clone's CODE", async function () {
      const w = await deployErc20World({ label: "identity" });
      expect(await w.vault.admittedAsset()).to.equal(w.tokenAddress);
      expect(await w.factory.admittedAsset()).to.equal(w.tokenAddress);
      const args = (await w.vault.genesisCommitments()) as string;
      expect(args).to.equal(packedArgs(KERNEL_GENERATION_2, w.authorityAddress, w.tokenAddress));
      expect(await w.vault.kernelGeneration()).to.equal(KERNEL_GENERATION_2);
      // 45-byte EIP-1167 template + 48 bytes of args, and the args are the tail of the runtime code.
      const code = await ethers.provider.getCode(w.vaultAddress);
      expect(ethers.dataLength(code)).to.equal(93);
      expect(code.toLowerCase().endsWith(args.slice(2).toLowerCase())).to.equal(true);
    });

    it("a clone carrying DIFFERENT asset args has different code, a different address and reports that asset", async function () {
      const w = await deployErc20World({ label: "identity-args" });
      const other = await deployUnit(planeUnit("VanillaToken"), w.deployer);
      const Raw = await deployArtifact("RawCloner", w.deployer);
      const args = packedArgs(KERNEL_GENERATION_2, w.authorityAddress, other.address);
      await (await Raw.contract.cloneWithArgs(w.implementation, args, ethers.id("other-asset"))).wait();
      const clone = new ethers.Contract(
        (await Raw.contract.lastClone()) as string,
        w.kernelAbi as ethers.InterfaceAbi,
        w.deployer,
      );
      expect(await clone.admittedAsset()).to.equal(other.address);
      expect(await ethers.provider.getCode(await clone.getAddress())).to.not.equal(
        await ethers.provider.getCode(w.vaultAddress),
      );
      // FAIL CLOSED: a clone whose args carry NO asset reads address(0).
      await (
        await Raw.contract.cloneWithArgs(
          w.implementation,
          ethers.solidityPacked(["uint64", "address"], [2, w.authorityAddress]),
          ethers.id("no-asset"),
        )
      ).wait();
      const assetless = new ethers.Contract(
        (await Raw.contract.lastClone()) as string,
        w.kernelAbi as ethers.InterfaceAbi,
        w.deployer,
      );
      expect(await assetless.admittedAsset()).to.equal(ZERO);
    });

    it("execute takes NO asset parameter and there is no execute(address,bytes): the caller cannot select what moves", async function () {
      const w = await deployErc20World({ label: "identity-abi" });
      const executes = w.vault.interface.fragments
        .filter((f) => f.type === "function" && (f as ethers.FunctionFragment).name === "execute")
        .map((f) => (f as ethers.FunctionFragment).format("sighash"));
      expect(executes).to.deep.equal(["execute(address,uint256,uint256,uint64,bytes,bytes,bytes)"]);
      const inputs = w.vault.interface.getFunction("execute")!.inputs.map((i) => i.name);
      expect(inputs).to.deep.equal(["recipient", "amount", "nonce", "deadline", "ecdsaSig", "pqSig", "pqKey"]);
    });

    it("the factory refuses a zero or codeless asset, so a dead generation cannot be published", async function () {
      const w = await deployErc20World({ label: "identity-factory" });
      const unit = planeUnit("VaultKernelErc20FactoryPrototype");
      const F = new ethers.ContractFactory(unit.abi as ethers.InterfaceAbi, unit.bytecode, w.deployer);
      await expect(
        F.deploy(w.implementation, KERNEL_GENERATION_2, w.authorityAddress, ZERO),
      ).to.be.revertedWithCustomError(w.factory, "ZeroAddress");
      await expect(
        F.deploy(w.implementation, KERNEL_GENERATION_2, w.authorityAddress, w.recipient),
      ).to.be.revertedWithCustomError(w.factory, "NoCode");
      // Control: a code-bearing asset is accepted.
      const ok = await F.deploy(w.implementation, KERNEL_GENERATION_2, w.authorityAddress, w.tokenAddress);
      await ok.waitForDeployment();
      expect(await (ok as unknown as ethers.Contract).admittedAsset()).to.equal(w.tokenAddress);
    });
  });

  // =====================================================================
  describe("the spend plane — authority (ERC20-1, ERC20-3, ERC20-4)", function () {
    it("POSITIVE CONTROL — a credential-signed spend RELAYED by a stranger moves exactly the amount and consumes one nonce", async function () {
      const w = await deployErc20World({ label: "spend-control" });
      const vaultBefore = await balanceOf(w.token, w.vaultAddress);
      const recipientBefore = await balanceOf(w.token, w.recipient);
      const relayerBefore = await balanceOf(w.token, await w.outsider.getAddress());
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT, from: w.outsider }))
        .to.emit(w.vault, "Executed")
        .withArgs(w.recipient, AMOUNT, 0n);
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(vaultBefore - AMOUNT);
      expect(await balanceOf(w.token, w.recipient)).to.equal(recipientBefore + AMOUNT);
      expect(await balanceOf(w.token, await w.outsider.getAddress())).to.equal(relayerBefore);
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
    });

    it("ERC20-1 — the relayer gains NO authority: its own signature is refused, and it cannot redirect or resize a signed spend", async function () {
      const w = await deployErc20World({ label: "erc20-1" });
      const outsiderKey = keyOf("erc20-1-outsider");
      await expect(
        sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: outsiderKey, from: w.outsider }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // Signed for the recipient, submitted for the relayer: the params hash is in the digest.
      const relayer = await w.outsider.getAddress();
      const signedForRecipient = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 0n });
      await expect(
        sendSpend(w, { to: relayer, amount: AMOUNT, nonce: 0n, from: w.outsider, digestOverride: signedForRecipient }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        sendSpend(w, {
          to: w.recipient,
          amount: AMOUNT * 2n,
          nonce: 0n,
          from: w.outsider,
          digestOverride: signedForRecipient,
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // Control: the untouched payload, relayed by the same stranger, lands.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, from: w.outsider })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
      expect(await balanceOf(w.token, relayer)).to.equal(0n);
    });

    it("ERC20-3 — a signature for the vault of asset A does not move asset B: two vaults with IDENTICAL genesis and different assets", async function () {
      const w1 = await deployErc20World({ label: "erc20-3" });
      // Same label => same keys, same roster, same salt; same verifier, root and implementation reused. ONLY the asset differs.
      const w2 = await deployErc20World({
        label: "erc20-3",
        reuse: {
          verifierAddress: w1.verifierAddress,
          authorityAddress: w1.authorityAddress,
          implementation: w1.implementation,
        },
      });
      expect(w2.genesis).to.deep.equal(w1.genesis);
      expect(w2.salt).to.equal(w1.salt);
      expect(w2.tokenAddress).to.not.equal(w1.tokenAddress);
      // The clone's args differ, so its initcode differs, so CREATE2 lands elsewhere — the asset is in the identity.
      expect(w2.vaultAddress).to.not.equal(w1.vaultAddress);
      expect(await w1.factory.predictVault(w1.salt, w1.genesis)).to.not.equal(
        await w2.factory.predictVault(w2.salt, w2.genesis),
      );

      // A spend signed for vault 1 (asset A) replayed at vault 2 (asset B): the domain binds the vault address.
      const forVault1 = spendDigest(w1, { to: w1.recipient, amount: AMOUNT, nonce: 0n });
      await expect(
        sendSpend(w2, { to: w2.recipient, amount: AMOUNT, nonce: 0n, digestOverride: forVault1 }),
      ).to.be.revertedWithCustomError(w2.vault, "BadSignature");
      expect(await balanceOf(w2.token, w2.recipient)).to.equal(0n);
      // Control: the same signature at the vault it was made for.
      await (await sendSpend(w1, { to: w1.recipient, amount: AMOUNT, nonce: 0n, digestOverride: forVault1 })).wait();
      expect(await balanceOf(w1.token, w1.recipient)).to.equal(AMOUNT);
    });

    it("ERC20-4 — the same authorised payload cannot be replayed; the next nonce is a fresh authorisation", async function () {
      const w = await deployErc20World({ label: "erc20-4" });
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, from: w.outsider })).wait();
      await expect(
        sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, from: w.outsider }),
      ).to.be.revertedWithCustomError(w.vault, "BadNonce");
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
      // Control: nonce 1, freshly signed.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 1n, from: w.outsider })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(2n * AMOUNT);
    });

    it("a deadline in the past is refused and burns nothing", async function () {
      const w = await deployErc20World({ label: "deadline" });
      await expect(
        sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, deadline: 1n }),
      ).to.be.revertedWithCustomError(w.vault, "Expired");
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n })).wait();
    });

    it("the HYBRID floor is unchanged by the plane: a hybrid vault still demands the PQ conjunct on every spend", async function () {
      const w = await deployErc20World({ label: "hybrid", floor: "hybrid" });
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT })).to.be.revertedWithCustomError(
        w.vault,
        "BadSignature",
      );
      await (
        await sendSpend(w, {
          to: w.recipient,
          amount: AMOUNT,
          pq: { sig: ethers.hexlify(new Uint8Array(65)), key: pqKeyBytes(w.pqKey) },
        })
      ).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
    });

    it("the policy plane is still consulted, still subtractive, still after the nonce", async function () {
      const w = await deployErc20World({ label: "policy" });
      const deny = await deployArtifact("ConfigurablePolicy", w.deployer, false);
      await (await setPolicy(w, deny.address)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT })).to.be.revertedWithCustomError(
        w.vault,
        "PolicyDenied",
      );
      const allow = await deployArtifact("ConfigurablePolicy", w.deployer, true);
      await (await setPolicy(w, allow.address)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
    });
  });

  // =====================================================================
  describe("the spend plane — settlement (ERC20-5, ERC20-6)", function () {
    it("ERC20-5 — an issuer-blocklisted recipient makes the whole spend revert: no nonce, no event, no balance change; unblocking lands the SAME payload", async function () {
      const w = await deployErc20World({ label: "erc20-5" });
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("VanillaToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await token.setBlocklisted(w.recipient, true)).wait();
      const before = await balanceOf(w.token, w.vaultAddress);
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(before);
      // The issuer lifts the flag; the identical authorisation now settles — no WalletWall act in between.
      await (await token.setBlocklisted(w.recipient, false)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
      // And a blocklisted VAULT cannot spend at all — the issuer's lever reaches the clone, as section 7.1 states.
      await (await token.setBlocklisted(w.vaultAddress, true)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 1n })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
    });

    it("ERC20-5 — a token that returns TRUE without moving balance is refused: the observed-balance rule, not the boolean, judges settlement", async function () {
      const w = await deployErc20World({ label: "lying", token: "LyingToken" });
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
      // Control: the same world's rule accepts a vanilla asset (a second factory over the same implementation).
      const v = await deployErc20World({
        label: "lying",
        reuse: {
          verifierAddress: w.verifierAddress,
          authorityAddress: w.authorityAddress,
          implementation: w.implementation,
        },
      });
      await (await sendSpend(v, { to: v.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(v.token, v.recipient)).to.equal(AMOUNT);
    });

    it("ERC20-6 — a DIRECT token transfer (no deposit entrypoint exists) is spendable, and so is a rebase the vault never saw", async function () {
      const w = await deployErc20World({ label: "erc20-6", token: "RebasingToken", mintToVault: 0n });
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("RebasingToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      // A third party simply transfers to the vault's address.
      await (await token.mint(await w.outsider.getAddress(), 1_000n * UNIT)).wait();
      await (await (token.connect(w.outsider) as ethers.Contract).transfer(w.vaultAddress, 600n * UNIT)).wait();
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(600n * UNIT);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
      // A rebase doubles every balance with no transaction to the vault: the vault's spendable balance IS the token's.
      await (await token.rebase(2_000_000_000_000_000_000n)).wait();
      const doubled = (600n * UNIT - AMOUNT) * 2n;
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(doubled);
      // At index 2 a transfer of 250 units moves 125 shares = exactly 250 units: settles.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(doubled - AMOUNT);
      // An index that makes the token round short of the amount is refused — the rule is EXACT.
      await (await token.rebase(1_500_000_000_000_000_000n)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: 100n })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
      // A rebase INSIDE the transfer (the sender's decrease is not the amount) is refused too.
      await (await token.rebase(1_000_000_000_000_000_000n)).wait();
      await (await token.armRebaseOnTransfer(1_100_000_000_000_000_000n)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
    });

    it("a ZERO-amount spend is admitted: it moves nothing and consumes the nonce (the credential's way to retire an outstanding signature)", async function () {
      const w = await deployErc20World({ label: "zero" });
      const before = await balanceOf(w.token, w.vaultAddress);
      await expect(sendSpend(w, { to: w.recipient, amount: 0n, nonce: 0n }))
        .to.emit(w.vault, "Executed")
        .withArgs(w.recipient, 0n, 0n);
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(before);
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
      // A signature outstanding for nonce 0 is now dead.
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n })).to.be.revertedWithCustomError(
        w.vault,
        "BadNonce",
      );
      // The asset still judges a zero transfer: a blocklisted recipient refuses even zero.
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("VanillaToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await token.setBlocklisted(w.recipient, true)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: 0n, nonce: 1n })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
    });

    it("a CODELESS asset: the factory refuses it (above); a raw clone naming one can never settle a non-zero spend, and a zero spend is vacuous", async function () {
      const w = await deployErc20World({ label: "codeless" });
      const Raw = await deployArtifact("RawCloner", w.deployer);
      const eoa = w.recipient; // an account with no code
      await (
        await Raw.contract.cloneWithArgs(
          w.implementation,
          packedArgs(KERNEL_GENERATION_2, w.authorityAddress, eoa),
          ethers.id("codeless"),
        )
      ).wait();
      const clone = new ethers.Contract(
        (await Raw.contract.lastClone()) as string,
        w.kernelAbi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await clone.initialize(w.genesis, "0x")).wait();
      const cloneAddress = await clone.getAddress();
      const digest = (amount: bigint, nonce: bigint) =>
        spendDigest(w, { to: w.recipient, amount, nonce, vault: cloneAddress });
      await expect(
        clone.execute(w.recipient, AMOUNT, 0, FAR_DEADLINE, sign(w.credKey, digest(AMOUNT, 0n)), "0x", "0x"),
      ).to.be.revertedWithCustomError(clone, "TransferFailed");
      // RECORDED, NOT HIDDEN: with amount 0 the balance reads 0 before and after, so the exact rule is satisfied vacuously.
      await (await clone.execute(w.recipient, 0, 0, FAR_DEADLINE, sign(w.credKey, digest(0n, 0n)), "0x", "0x")).wait();
      expect(await clone.nonces(DOMAIN.SPEND)).to.equal(1n);
    });

    it("a HOOK-BEARING asset cannot re-enter to replay: the nonce is consumed before the transfer, and a second valid spend inside the first breaks the outer exact delta, reverting both", async function () {
      const w = await deployErc20World({ label: "reentrant", token: "ReentrantToken" });
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("ReentrantToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      // Control FIRST, on the unarmed hook.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 0n })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);

      // Attack 1: the hook replays the SAME payload (nonce 1) from inside the transfer for nonce 1.
      const d1 = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 1n });
      const replay = w.vault.interface.encodeFunctionData("execute", [
        w.recipient,
        AMOUNT,
        1n,
        FAR_DEADLINE,
        sign(w.credKey, d1),
        "0x",
        "0x",
      ]);
      await (await token.arm(w.vaultAddress, replay)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 1n })).wait();
      expect(await token.reentered()).to.equal(true);
      expect(await token.reentrySucceeded()).to.equal(false);
      expect(((await token.reentryReturn()) as string).slice(0, 10)).to.equal(
        w.vault.interface.getError("BadNonce")!.selector,
      );
      expect(await balanceOf(w.token, w.recipient)).to.equal(2n * AMOUNT);

      // Attack 2: the hook carries a VALID second authorisation (nonce 3) inside the spend for nonce 2.
      const d3 = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 3n });
      const inner = w.vault.interface.encodeFunctionData("execute", [
        w.recipient,
        AMOUNT,
        3n,
        FAR_DEADLINE,
        sign(w.credKey, d3),
        "0x",
        "0x",
      ]);
      await (await token.arm(w.vaultAddress, inner)).wait();
      await expect(
        sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 2n, gasLimit: PROBE_GAS }),
      ).to.be.revertedWithCustomError(w.vault, "TransferFailed");
      // Everything the inner spend did was reverted with the outer: balances and nonce untouched.
      expect(await balanceOf(w.token, w.recipient)).to.equal(2n * AMOUNT);
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(2n);
    });

    it("an ISSUER-UPGRADED asset: the address is pinned, the behaviour is the issuer's; a lying upgrade is refused, an honest one settles", async function () {
      const [deployer] = await ethers.getSigners();
      const honest = await deployUnit(planeUnit("VanillaToken"), deployer!);
      const lying = await deployUnit(planeUnit("LyingToken"), deployer!);
      const proxy = await deployUnit(planeUnit("SwappableTokenProxy"), deployer!, honest.address);
      const w = await deployErc20World({ label: "proxy", tokenAddress: proxy.address });
      expect(await w.vault.admittedAsset()).to.equal(proxy.address);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
      // The issuer swaps the logic. Same address, different truth: the kernel cannot see the swap and must not need to.
      await (await proxy.contract.setImplementation(lying.address)).wait();
      await expect(sendSpend(w, { to: w.recipient, amount: AMOUNT })).to.be.revertedWithCustomError(
        w.vault,
        "TransferFailed",
      );
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
      await (await proxy.contract.setImplementation(honest.address)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(w.token, w.recipient)).to.equal(2n * AMOUNT);
    });

    it("native value is NOT spendable through the plane: unsolicited ETH stays until egress, and the token leaves only by execute", async function () {
      const w = await deployErc20World({ label: "eth", fundEth: ethers.parseEther("1") });
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("1"));
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      // The spend moved tokens, not ether.
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("1"));
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
    });
  });

  // =====================================================================
  describe("genesis — the two variants the custody adjudication asked to measure (section 7.2, section 10 item 6)", function () {
    it("variant A REFUSES a null verifier at genesis even on an ECDSA-only floor; variant B ADMITS it there and only there", async function () {
      const a = await deployErc20World({ label: "genesis-a" });
      await expect(
        a.factory.deployVault(ethers.id("null-a"), { ...a.genesis, verifier: ZERO }, "0x"),
      ).to.be.revertedWithCustomError(a.vault, "ZeroAddress");
      const b = await deployErc20World({ label: "genesis-b", variant: "B", verifier: "none" });
      expect(await b.vault.pqVerifier()).to.equal(ZERO);
      expect(await b.vault.ecdsaSigner()).to.equal(addrOf(b.credKey));
      // The verifier-less vault spends on the ECDSA floor exactly like variant A.
      await (await sendSpend(b, { to: b.recipient, amount: AMOUNT, from: b.outsider })).wait();
      expect(await balanceOf(b.token, b.recipient)).to.equal(AMOUNT);
      // But NOT with a mandatory PQ conjunct: a null verifier under requirePq is still refused by B.
      const withPq = { ...b.genesis, floor: { ...HONEST_FLOOR }, pqKeyHash: ethers.keccak256(pqKeyBytes(b.pqKey)) };
      await expect(
        b.factory.deployVault(ethers.id("null-b-pq"), withPq, pqKeyBytes(b.pqKey)),
      ).to.be.revertedWithCustomError(b.vault, "ZeroAddress");
      // And a NON-null candidate is still checked: a code-bearing stranger with no provenance is refused by the real root.
    });

    it("variant B: a vault born verifier-less must NAME an admissible verifier to arm the PQ conjunct or to recover", async function () {
      const b = await deployErc20World({ label: "genesis-b-arm", variant: "B", verifier: "none", commitPqKey: true });
      const admissible = (await deployArtifact("ConfigurableVerifier", b.deployer, 0)).address;
      // Arming with null: refused before any nonce is consumed.
      await expect(setVerifier(b, ZERO, { ...HONEST_FLOOR })).to.be.revertedWithCustomError(b.vault, "ZeroAddress");
      // Recovery naming null: refused.
      await expect(
        proposeRecovery(b, addrOf(keyOf("new-signer")), ethers.ZeroHash, ZERO),
      ).to.be.revertedWithCustomError(b.vault, "ZeroAddress");
      // Controls: naming an admissible verifier succeeds on both edges.
      await (await proposeRecovery(b, addrOf(keyOf("new-signer")), ethers.ZeroHash, admissible)).wait();
      await (await setVerifier(b, admissible, { ...HONEST_FLOOR }, { sig: "0x", key: pqKeyBytes(b.pqKey) })).wait();
      expect(await b.vault.pqVerifier()).to.equal(admissible);
      expect(((await b.vault.securityFloor()) as unknown[])[0]).to.equal(true);
    });

    it("variant A with the REAL Generation-1 root: creating an ECDSA-only vault needs an admissible verifier, which a STRANGER creates permissionlessly", async function () {
      // The helper's gen1root mode has the OUTSIDER call deployVerifier(attestor) on the root.
      const w = await deployErc20World({ label: "genesis-root", authority: "gen1root" });
      expect(await w.vault.pqVerifier()).to.equal(w.verifierAddress);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      // A code-bearing contract the root did NOT create is refused at genesis: provenance, not mere code.
      const stranger = await deployArtifact("DestinationStub", w.deployer);
      await expect(
        w.factory.deployVault(ethers.id("stranger"), { ...w.genesis, verifier: stranger.address }, "0x"),
      ).to.be.revertedWithCustomError(w.vault, "InadmissibleVerifier");
    });
  });

  // =====================================================================
  describe("migration — permissionless executor, fixed destination, fixed disposition (ERC20-7, ERC20-8, ERC20-9)", function () {
    it("ERC20-7/9 — any stranger executes egress; the admitted asset goes IN FULL to the bound destination and nowhere else", async function () {
      const w = await deployErc20World({ label: "mig-7" });
      await (await bindDestination(w)).wait();
      expect(await w.vault.safeState()).to.equal(3n); // MIGRATION_ONLY
      const held = await balanceOf(w.token, w.vaultAddress);
      // There is no recipient parameter to redirect.
      expect(w.vault.interface.getFunction("egress")!.inputs.map((i) => i.name)).to.deep.equal(["asset"]);
      await expect((w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress))
        .to.emit(w.vault, "Egressed")
        .withArgs(w.tokenAddress, w.destination, held);
      expect(await balanceOf(w.token, w.destination)).to.equal(held);
      expect(await balanceOf(w.token, w.vaultAddress)).to.equal(0n);
      expect(await balanceOf(w.token, await w.outsider.getAddress())).to.equal(0n);
      // Spending authority is WITHDRAWN once bound: the plane answers only to egress now.
      await expect(sendSpend(w, { to: w.recipient, amount: 1n })).to.be.revertedWithCustomError(w.vault, "BadState");
    });

    it("ERC20-8 — the caller chooses WHICH holding to sweep, never WHERE: an unsolicited token and native value also go to the destination; the plane cannot be pointed at another token", async function () {
      const w = await deployErc20World({ label: "mig-8", fundEth: ethers.parseEther("2") });
      const other = await deployUnit(planeUnit("VanillaToken"), w.deployer);
      await (await other.contract.mint(w.vaultAddress, 77n)).wait();
      // Before binding: execute moves ONLY the admitted asset; the other token is not reachable by any spend.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await balanceOf(other.contract, w.vaultAddress)).to.equal(77n);
      await (await bindDestination(w)).wait();
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(other.address)).wait();
      expect(await balanceOf(other.contract, w.destination)).to.equal(77n);
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(w.destination)).to.equal(ethers.parseEther("2"));
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress)).wait();
      expect(await balanceOf(w.token, w.destination)).to.equal(1_000n * UNIT - AMOUNT);
    });

    it("a FAILED egress mutates no migration state and does not veto the admitted asset's egress", async function () {
      const w = await deployErc20World({ label: "mig-atomic" });
      const lying = await deployUnit(planeUnit("LyingToken"), w.deployer);
      await (await lying.contract.mint(w.vaultAddress, 5n)).wait();
      await (await bindDestination(w)).wait();
      const before = await migrationSnapshot(w);
      await expect(w.vault.egress(lying.address)).to.be.revertedWithCustomError(w.vault, "TransferFailed");
      expect(await migrationSnapshot(w)).to.deep.equal(before);
      // Independence: the admitted asset still leaves.
      await (await w.vault.egress(w.tokenAddress)).wait();
      expect(await balanceOf(w.token, w.destination)).to.equal(1_000n * UNIT);
    });

    it("a completed migration cannot be replayed into a second movement or a second destination", async function () {
      const w = await deployErc20World({ label: "mig-replay" });
      await (await bindDestination(w)).wait();
      await (await w.vault.egress(w.tokenAddress)).wait();
      // A second egress moves NOTHING and says so.
      await expect(w.vault.egress(w.tokenAddress))
        .to.emit(w.vault, "Egressed")
        .withArgs(w.tokenAddress, w.destination, 0n);
      // A second binding — even to the same destination, even by the same principals — is refused.
      await expect(bindDestination(w)).to.be.revertedWithCustomError(w.vault, "AlreadyBound");
      // Tokens arriving AFTER the first egress still leave to the same destination, forever (I-EGRESS-RETRY-PERPETUAL).
      await (await w.token.mint(w.vaultAddress, 9n)).wait();
      await advanceTime(8 * DAY);
      await (await (w.vault.connect(w.outsider) as ethers.Contract).retire()).wait();
      expect(await w.vault.safeState()).to.equal(4n); // RETIRED
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress)).wait();
      expect(await balanceOf(w.token, w.destination)).to.equal(1_000n * UNIT + 9n);
    });

    it("a stranger cannot bind a destination of their own: binding needs the quorum AND the credential", async function () {
      const w = await deployErc20World({ label: "mig-stranger" });
      const nonce = await currentNonce(w, DOMAIN.MIGRATION);
      const evil = await w.outsider.getAddress();
      const evilHash = ethers.keccak256(await ethers.provider.getCode(w.destination));
      const params = migrationParams(w.destination, evilHash, 3n);
      const digest = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GENERATION_2,
        actionType: ACTION.BIND_MIGRATION,
        authorityGeneration: 1n,
        params,
        domain: DOMAIN.MIGRATION,
        nonce,
        deadline: FAR_DEADLINE,
      });
      const evilKey = keyOf("mig-stranger-evil");
      // Quorum right, credential wrong.
      await expect(
        w.vault.bindMigration(
          { vault: w.destination, codeHash: evilHash, generation: 3 },
          {
            members: w.guardians,
            isContract: w.guardianIsContract,
            attestingIndices: [0, 1],
            attestations: [sign(w.gKeys[0]!, digest), sign(w.gKeys[1]!, digest)],
          },
          nonce,
          FAR_DEADLINE,
          sign(evilKey, digest),
        ),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // Credential right, quorum forged.
      await expect(
        w.vault.bindMigration(
          { vault: w.destination, codeHash: evilHash, generation: 3 },
          {
            members: w.guardians,
            isContract: w.guardianIsContract,
            attestingIndices: [0, 1],
            attestations: [sign(evilKey, digest), sign(evilKey, digest)],
          },
          nonce,
          FAR_DEADLINE,
          sign(w.credKey, digest),
        ),
      ).to.be.revertedWithCustomError(w.vault, "QuorumNotMet");
      void evil;
      // Control: both principals.
      await (await bindDestination(w)).wait();
      expect(((await w.vault.migration()) as unknown[])[4]).to.equal(true);
    });
  });

  // =====================================================================
  describe("ERC20-10 — WalletWall owns no new on-chain capability", function () {
    it("the candidate kernel's state-changing surface is Generation 1's, name for name; the factory's is deployVault alone", async function () {
      const gen1 = await gen1StateChangingNames();
      for (const variant of ["A", "B"] as const) {
        const w = await deployErc20World({ label: `erc20-10-${variant}`, variant });
        expect(stateChangingNames(w.vault.interface)).to.deep.equal(gen1);
        expect(stateChangingNames(w.factory.interface)).to.deep.equal(["deployVault"]);
        const allNames = w.vault.interface.fragments
          .filter((f) => f.type === "function")
          .map((f) => (f as ethers.FunctionFragment).name);
        expect(
          allNames.filter((n) =>
            /owner|admin|pause|upgrade|setAsset|setAdmittedAsset|register|freeze|blocklist/i.test(n),
          ),
        ).to.deep.equal([]);
      }
    });

    it("the factory holds NO authority over a clone it produced: no setter exists, and its immutables are fixed at construction", async function () {
      const w = await deployErc20World({ label: "erc20-10-factory" });
      const names = w.factory.interface.fragments
        .filter((f) => f.type === "function")
        .map((f) => (f as ethers.FunctionFragment).name)
        .sort();
      expect(names).to.deep.equal([
        "admittedAsset",
        "deployVault",
        "generation",
        "implementation",
        "predictVault",
        "verifierAuthority",
      ]);
      expect(await w.factory.implementation()).to.equal(w.implementation);
      expect(await w.factory.generation()).to.equal(KERNEL_GENERATION_2);
      expect(await w.factory.verifierAuthority()).to.equal(w.authorityAddress);
    });
  });

  // =====================================================================
  describe("gas — LOCAL comparative measurements, recorded in ERC20_SPEND_PLANE_MEASUREMENTS.json (not cost claims)", function () {
    const OFFSET = 16;
    const measured: Record<string, number> = {};
    let accounts: ethers.Signer[];

    before(async function () {
      accounts = await ethers.getSigners();
      expect(accounts.length, "the gas probes need isolated accounts 16..18").to.be.greaterThan(OFFSET + 2);
    });

    interface Gen1World {
      vault: ethers.Contract;
      vaultAddress: string;
      credKey: ethers.SigningKey;
      gKeys: ethers.SigningKey[];
      guardians: string[];
      chainId: bigint;
      deployGas: { implementation: bigint; factory: bigint; vault: bigint };
    }

    /** The Generation-1 kernel from the Hardhat artifact, on the same isolated accounts, for the native-ETH baseline. */
    async function gen1World(label: string): Promise<Gen1World> {
      const deployer = accounts[OFFSET]!;
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const verifier = await deployArtifact("ConfigurableVerifier", deployer, 0);
      const impl = await deployArtifact("VaultKernelPrototype", deployer);
      const ungated = await deployArtifact("UngatedVerifierAuthority", deployer);
      const factory = await deployArtifact("VaultKernelFactoryPrototype", deployer, impl.address, 1, ungated.address);
      const credKey = keyOf(label + "-cred");
      const gKeys = [0, 1, 2]
        .map((i) => keyOf(label + "-guardian-" + i))
        .sort((x, y) => (BigInt(addrOf(x)) < BigInt(addrOf(y)) ? -1 : 1));
      const guardians = gKeys.map(addrOf);
      const genesis = {
        signer: addrOf(credKey),
        pqKeyHash: ethers.ZeroHash,
        verifier: verifier.address,
        threshold: 2,
        guardians,
        guardianIsContract: [false, false, false],
        floor: { ...ECDSA_ONLY_FLOOR },
      };
      const salt = ethers.id(label + "-vault");
      const vaultAddress = (await factory.contract.predictVault(salt, genesis)) as string;
      const receipt = await (await factory.contract.deployVault(salt, genesis, "0x")).wait();
      const vault = await ethers.getContractAt("VaultKernelPrototype", vaultAddress, deployer);
      await (await deployer.sendTransaction({ to: vaultAddress, value: ethers.parseEther("10") })).wait();
      return {
        vault: vault as unknown as ethers.Contract,
        vaultAddress,
        credKey,
        gKeys,
        guardians,
        chainId,
        deployGas: { implementation: impl.gasUsed, factory: factory.gasUsed, vault: receipt!.gasUsed },
      };
    }

    function gen1SpendDigest(g: Gen1World, to: string, amount: bigint, nonce: bigint): string {
      return digestOf({
        chainId: g.chainId,
        vault: g.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.SPEND,
        authorityGeneration: 1n,
        params: spendParams(to, amount),
        domain: DOMAIN.SPEND,
        nonce,
        deadline: FAR_DEADLINE,
      });
    }

    it("measures the probes", async function () {
      const relayer = accounts[OFFSET + 1]!;
      const recipient = await accounts[OFFSET + 2]!.getAddress();

      // ---- ERC-20 plane, variant A --------------------------------------------------------------------
      const a = await deployErc20World({ label: "gas-a", signerOffset: OFFSET });
      measured.deployImplementationVariantA = Number(a.deployGas.implementation);
      measured.deployFactoryErc20 = Number(a.deployGas.factory);
      measured.deployVaultErc20Factory = Number(a.deployGas.vault);
      const spendA = await gasOf(() => sendSpend(a, { to: recipient, amount: AMOUNT, from: relayer }));
      expect(spendA.ok).to.equal(true);
      measured.erc20SpendVanillaRelayed = Number(spendA.gasUsed);
      const badSig = await gasOf(() =>
        sendSpend(a, {
          to: recipient,
          amount: AMOUNT,
          signer: keyOf("gas-attacker"),
          from: relayer,
          gasLimit: PROBE_GAS,
        }),
      );
      expect(badSig.ok).to.equal(false);
      measured.erc20SpendRefusedBadSignature = Number(badSig.gasUsed);
      const tokenA = new ethers.Contract(
        a.tokenAddress,
        planeUnit("VanillaToken").abi as ethers.InterfaceAbi,
        a.deployer,
      );
      await (await tokenA.setBlocklisted(recipient, true)).wait();
      const blocked = await gasOf(() =>
        sendSpend(a, { to: recipient, amount: AMOUNT, from: relayer, gasLimit: PROBE_GAS }),
      );
      expect(blocked.ok).to.equal(false);
      measured.erc20SpendRefusedBlocklistedRecipient = Number(blocked.gasUsed);
      await (await tokenA.setBlocklisted(recipient, false)).wait();
      await (await bindDestination(a)).wait();
      const egressA = await gasOf(() => (a.vault.connect(relayer) as ethers.Contract).egress(a.tokenAddress));
      expect(egressA.ok).to.equal(true);
      measured.erc20EgressAdmittedAsset = Number(egressA.gasUsed);

      // ---- ERC-20 plane, variant B (null verifier) ----------------------------------------------------
      const b = await deployErc20World({ label: "gas-b", variant: "B", verifier: "none", signerOffset: OFFSET });
      measured.deployImplementationVariantB = Number(b.deployGas.implementation);
      const spendB = await gasOf(() => sendSpend(b, { to: recipient, amount: AMOUNT, from: relayer }));
      expect(spendB.ok).to.equal(true);
      measured.erc20SpendVariantBRelayed = Number(spendB.gasUsed);

      // ---- lying asset: refused by the observed-balance rule ----------------------------------------
      const lying = await deployErc20World({ label: "gas-lying", token: "LyingToken", signerOffset: OFFSET });
      const refusedLying = await gasOf(() =>
        sendSpend(lying, { to: recipient, amount: AMOUNT, from: relayer, gasLimit: PROBE_GAS }),
      );
      expect(refusedLying.ok).to.equal(false);
      measured.erc20SpendRefusedLyingToken = Number(refusedLying.gasUsed);

      // ---- Generation-1 native-ETH baseline ---------------------------------------------------------
      const g = await gen1World("gas-gen1");
      measured.deployImplementationGen1 = Number(g.deployGas.implementation);
      measured.deployFactoryGen1 = Number(g.deployGas.factory);
      measured.deployVaultGen1Factory = Number(g.deployGas.vault);
      const ethAmount = ethers.parseEther("1");
      const ethSpend = await gasOf(() =>
        (g.vault.connect(relayer) as ethers.Contract).execute(
          recipient,
          ethAmount,
          0,
          FAR_DEADLINE,
          sign(g.credKey, gen1SpendDigest(g, recipient, ethAmount, 0n)),
          "0x",
          "0x",
        ),
      );
      expect(ethSpend.ok).to.equal(true);
      measured.ethSpendGen1Baseline = Number(ethSpend.gasUsed);
      const ethBadSig = await gasOf(() =>
        (g.vault.connect(relayer) as ethers.Contract).execute(
          recipient,
          ethAmount,
          1,
          FAR_DEADLINE,
          sign(keyOf("gas-attacker"), gen1SpendDigest(g, recipient, ethAmount, 1n)),
          "0x",
          "0x",
          { gasLimit: PROBE_GAS },
        ),
      );
      expect(ethBadSig.ok).to.equal(false);
      measured.ethSpendGen1RefusedBadSignature = Number(ethBadSig.gasUsed);
      // Gen-1 egress of native value, after a quorum-and-credential binding to a stub.
      const dest = await deployArtifact("DestinationStub", accounts[OFFSET]!);
      const destHash = ethers.keccak256(await ethers.provider.getCode(dest.address));
      const bindDigest = digestOf({
        chainId: g.chainId,
        vault: g.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.BIND_MIGRATION,
        authorityGeneration: 1n,
        params: migrationParams(dest.address, destHash, 2n),
        domain: DOMAIN.MIGRATION,
        nonce: 0n,
        deadline: FAR_DEADLINE,
      });
      await (
        await g.vault.bindMigration(
          { vault: dest.address, codeHash: destHash, generation: 2 },
          {
            members: g.guardians,
            isContract: [false, false, false],
            attestingIndices: [0, 1],
            attestations: [sign(g.gKeys[0]!, bindDigest), sign(g.gKeys[1]!, bindDigest)],
          },
          0,
          FAR_DEADLINE,
          sign(g.credKey, bindDigest),
        )
      ).wait();
      const ethEgress = await gasOf(() => (g.vault.connect(relayer) as ethers.Contract).egress(ZERO));
      expect(ethEgress.ok).to.equal(true);
      measured.ethEgressGen1Baseline = Number(ethEgress.gasUsed);

      console.log("      ERC-20 spend plane gas probes (local, comparative):");
      console.log(JSON.stringify(measured, null, 2).replace(/^/gm, "      "));
    });

    it("the recorded gas block equals this run's probes exactly (re-record with the printed table when a candidate changes)", function () {
      const record = JSON.parse(fs.readFileSync(PLANE_RECORD_JSON, "utf8")) as { gas: Record<string, unknown> | null };
      expect(
        record.gas,
        "ERC20_SPEND_PLANE_MEASUREMENTS.json has no gas block yet -- copy the printed table into it",
      ).to.not.equal(null);
      const recorded = { ...record.gas } as Record<string, unknown>;
      delete recorded._note;
      expect(recorded).to.deep.equal(measured);
    });

    it("the ERC-20 spend is dearer than the native-ETH spend by the asset's two balance reads and its transfer, and nothing else", function () {
      expect(measured.erc20SpendVanillaRelayed).to.be.greaterThan(measured.ethSpendGen1Baseline!);
      // A refused authorisation costs the same order on both kernels: the floor is unchanged.
      expect(
        Math.abs(measured.erc20SpendRefusedBadSignature! - measured.ethSpendGen1RefusedBadSignature!),
      ).to.be.lessThan(2_000);
      // The null-verifier variant spends for the same price: the genesis difference is not on the spend path.
      expect(Math.abs(measured.erc20SpendVariantBRelayed! - measured.erc20SpendVanillaRelayed!)).to.be.lessThan(500);
    });
  });
});
