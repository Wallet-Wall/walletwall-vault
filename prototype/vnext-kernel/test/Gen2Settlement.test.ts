/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * WHAT THE KERNEL CAN OBSERVE, AND WHAT ONLY ASSET ADMISSION CAN GUARANTEE. Rows K-1, K-2, K-13-SETTLE,
 * G2-SEM-KERNEL, G2-SEM-BOUNDARY and G2-NO-ALLOWANCE. The oracle is the token's REAL ledger. The two tests
 * labelled ASSET BOUNDARY assert that the kernel settles something economically wrong, on purpose:
 *
 *     kernel-level settlement proof != complete token-economic semantics proof
 *
 * Each such behaviour appears on the asset-admission checklist in GEN2_ADMISSION.md, whose completeness
 * test/Gen2AdmissionMatrix.test.ts enforces. Nothing here names or models a real token.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";
import { GEN2_KERNEL, gen2Unit } from "../generation-2/compile.js";
import {
  DEFAULT_MINT,
  DOMAIN,
  UNIT,
  assetBalance,
  currentNonce,
  deployArtifact,
  deployGen2World,
  refusal,
  sendSpend,
  setMode,
  zoo,
  type Gen2World,
  type ModeName,
} from "../generation-2/world.js";

const PROBE_GAS = 800_000n;
const AMOUNT = 250n * UNIT;
const FEE = (AMOUNT * 100n) / 10_000n;

const world = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, ecdsaOnlyFloor: true, ...more });

async function executedAmounts(w: Gen2World, blockHash: string): Promise<bigint[]> {
  const logs = await ethers.provider.getLogs({ address: w.vaultAddress, blockHash });
  const out: bigint[] = [];
  for (const log of logs) {
    const parsed = w.vault.interface.parseLog(log);
    if (parsed?.name === "Executed") out.push(parsed.args[1] as bigint);
  }
  return out;
}

describe("Generation-2 admission — settlement: the kernel's observation and the asset boundary", function () {
  this.timeout(180_000);

  const REFUSED: readonly ModeName[] = [
    "RETURN_FALSE_NO_MOVE",
    "RETURN_TRUE_NO_MOVE",
    "SHORT_PAY",
    "SENDER_FEE",
    "DUST_SHORT",
    "REVERTS",
    "QUERY_REVERTS_AFTER_TRANSFER",
    "QUERY_SHORT_AFTER_TRANSFER",
  ];

  describe("G2-SEM-KERNEL: settled means the OBSERVED balance fell by exactly the signed amount", function () {
    for (const mode of REFUSED) {
      it(`${mode}: refused as TransferFailed, atomically, and the signature stays unspent`, async function () {
        const w = await world("settle-" + mode);
        await setMode(w, mode);
        expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
          "TransferFailed",
        );
        expect(await currentNonce(w, DOMAIN.SPEND), "a refused act consumes nothing").to.equal(0n);
        expect(await assetBalance(w, w.vaultAddress), "the ledger is untouched").to.equal(DEFAULT_MINT);
        expect(await assetBalance(w, w.recipient)).to.equal(0n);
        // POSITIVE CONTROL: the same world, an honest token: the kernel was not simply refusing everything.
        await setMode(w, "VANILLA");
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
      });
    }

    it("the boolean is trusted in NEITHER direction: a token returning nothing, or false while moving, settles on the observed delta", async function () {
      for (const mode of ["NO_RETURN", "RETURN_FALSE_BUT_MOVES"] as const) {
        const w = await world("settle-bool-" + mode);
        await setMode(w, mode);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
        expect(await assetBalance(w, w.vaultAddress), mode).to.equal(DEFAULT_MINT - AMOUNT);
        expect(await assetBalance(w, w.recipient), mode).to.equal(AMOUNT);
      }
    });

    it("a zero-amount spend needs a transfer that COMPLETED: settled over an honest token, refused over one that reverts", async function () {
      const w = await world("settle-zero");
      await (await sendSpend(w, { to: w.recipient, amount: 0n })).wait();
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
      await setMode(w, "REVERTS");
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: 0n, gasLimit: PROBE_GAS }))).to.equal(
        "TransferFailed",
      );
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
    });

    it("a spend the vault cannot cover is refused and the signature survives to settle once the vault is funded", async function () {
      const w = await world("settle-short", { mintToVault: 0n });
      const nonce = await currentNonce(w, DOMAIN.SPEND);
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce, gasLimit: PROBE_GAS })),
      ).to.equal("TransferFailed");
      await (await zoo(w).mint(w.vaultAddress, AMOUNT)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("a spend to the vault itself observes no decrease and is refused", async function () {
      const w = await world("settle-self");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.vaultAddress, amount: AMOUNT, gasLimit: PROBE_GAS })),
      ).to.equal("TransferFailed");
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
    });

    it("a blocklisted recipient refuses the spend; the issuer lifting it lets the SAME signature settle: a refusal spends nothing", async function () {
      const w = await world("settle-freeze");
      const nonce = await currentNonce(w, DOMAIN.SPEND);
      await (await zoo(w).setBlocklisted(w.recipient, true)).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce, gasLimit: PROBE_GAS })),
      ).to.equal("TransferFailed");
      await (await zoo(w).setBlocklisted(w.recipient, false)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the Executed event appears only in a settled spend: a refusal publishes nothing", async function () {
      const w = await world("settle-event");
      const receipt = await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await executedAmounts(w, receipt!.blockHash)).to.deep.equal([AMOUNT]);
      await setMode(w, "RETURN_TRUE_NO_MOVE");
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
        "TransferFailed",
      );
      const latest = await ethers.provider.getBlock("latest");
      expect(await executedAmounts(w, latest!.hash!)).to.deep.equal([]);
    });
  });

  describe("ASSET BOUNDARY: what no sender can observe. Asset admission must close these, the kernel cannot", function () {
    it("ASSET BOUNDARY: a recipient-side fee settles: the vault's balance fell by exactly the amount, and the recipient got less", async function () {
      const w = await world("boundary-fee");
      await setMode(w, "RECIPIENT_FEE");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await assetBalance(w, w.vaultAddress), "exactly what the kernel can see").to.equal(DEFAULT_MINT - AMOUNT);
      expect(await assetBalance(w, w.recipient), "what it cannot").to.equal(AMOUNT - FEE);
      expect(await zoo(w).sink()).to.equal(FEE);
    });

    it("ASSET BOUNDARY: a balanceOf that lies by exactly the expected debit settles with NOTHING moved and the nonce burned", async function () {
      const w = await world("boundary-lie");
      await setMode(w, "QUERY_LIES_EXACT_DEBIT");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await currentNonce(w, DOMAIN.SPEND), "the kernel believes it settled").to.equal(1n);
      expect(await assetBalance(w, w.vaultAddress), "the real ledger disagrees").to.equal(DEFAULT_MINT);
      expect(await assetBalance(w, w.recipient)).to.equal(0n);
    });

    it("ASSET BOUNDARY: the token can debit the clone with no kernel act at all: an issuer's seizure, which the kernel neither authorised nor can stop", async function () {
      const w = await world("asset-seize");
      const nonces = await Promise.all([0, 1, 2, 3].map((d) => w.vault.nonces(d)));
      await (await zoo(w).rebaseAccount(w.vaultAddress, DEFAULT_MINT / 4n)).wait();
      expect(await assetBalance(w, w.vaultAddress), "gone, and no key was involved").to.equal(DEFAULT_MINT / 4n);
      expect(await Promise.all([0, 1, 2, 3].map((d) => w.vault.nonces(d))), "no signed act consumed").to.deep.equal(
        nonces,
      );
      await (await sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT / 4n })).wait();
      expect(await assetBalance(w, w.vaultAddress), "the rest stays the credential's").to.equal(0n);
    });

    it("a rebase moves the balance with no transfer at all: nothing is reported, nothing desynchronises, the new balance is what is spendable", async function () {
      const w = await world("boundary-rebase");
      await (await zoo(w).rebaseAccount(w.vaultAddress, DEFAULT_MINT / 2n)).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT, gasLimit: PROBE_GAS })),
      ).to.equal("TransferFailed");
      await (await sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT / 2n })).wait();
      expect(await assetBalance(w, w.vaultAddress)).to.equal(0n);
    });
  });

  describe("K-1: custody is the token's own ledger: no pool, no second number", function () {
    it("no storage word holds a balance, so a direct transfer has nothing to desynchronise and is immediately spendable", async function () {
      const w = await world("k1");
      const words = async (): Promise<string[]> =>
        Promise.all(Array.from({ length: 24 }, (_, slot) => ethers.provider.getStorage(w.vaultAddress, slot)));
      const before = await words();
      await (await zoo(w).mint(w.vaultAddress, 500n * UNIT)).wait();
      await (await zoo(w).mint(w.vaultAddress, 7n)).wait();
      expect(await words(), "a credit touches no kernel storage").to.deep.equal(before);
      await (await sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT + 500n * UNIT + 7n })).wait();
      expect(await assetBalance(w, w.vaultAddress)).to.equal(0n);
    });

    it("K-2: the kernel's only external call shapes are named in the census, and there is no generic execute(address,bytes)", function () {
      const abi = gen2Unit(GEN2_KERNEL).abi as { type: string; name?: string; inputs?: { type: string }[] }[];
      const withDynamicTarget = abi.filter((f) => f.type === "function" && f.name === "execute");
      expect(withDynamicTarget.length).to.equal(1);
      expect(withDynamicTarget[0]!.inputs!.map((i) => i.type)).to.deep.equal([
        "address",
        "uint256",
        "uint256",
        "uint64",
        "bytes",
        "bytes",
        "bytes",
      ]);
      const payable = abi.filter(
        (f) => f.type === "function" && (f as { stateMutability?: string }).stateMutability === "payable",
      );
      expect(payable, "no payable entrypoint: a spend cannot carry value").to.deep.equal([]);
      const genericCallShape = (f: { type: string; name?: string }): boolean => {
        if (f.type !== "function") return false;
        const name = (f.name ?? "").toLowerCase();
        return (
          name.includes("delegate") || name.includes("multicall") || name.includes("batch") || name.endsWith("call")
        );
      };
      for (const name of ["delegateTo", "multicallAll", "batchSpend", "staticCall"]) {
        expect(genericCallShape({ type: "function", name }), `the filter catches ${name}`).to.equal(true);
      }
      expect(genericCallShape({ type: "function", name: "callback" }), "call counts only as a suffix").to.equal(false);
      expect(abi.filter(genericCallShape)).to.deep.equal([]);
    });

    it("a spend moves no native value: the vault's ether is reachable only by egress", async function () {
      const w = await world("k2-native", { fundEth: ethers.parseEther("1") });
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("1"));
    });
  });

  describe("G2-NO-ALLOWANCE: the vault can grant no allowance and answers no ERC-1271 query", function () {
    const SELECTORS = {
      isValidSignature: "0x1626ba7e",
      approve: "0x095ea7b3",
      increaseAllowance: "0x39509351",
      permit: "0xd505accf",
    };

    it("the runtime contains no approve call and no 1271 entrypoint, and the kernel has no function with either selector", async function () {
      const unit = gen2Unit(GEN2_KERNEL);
      expect(Object.values(unit.methodIdentifiers)).to.not.include(SELECTORS.isValidSignature.slice(2));
      expect(Object.values(unit.methodIdentifiers)).to.not.include(SELECTORS.approve.slice(2));
      const runtime = unit.deployedBytecode.toLowerCase();
      expect(
        runtime.includes(SELECTORS.approve.slice(2)),
        "the four bytes of approve appear nowhere in the runtime",
      ).to.equal(false);
      expect(runtime.includes(SELECTORS.increaseAllowance.slice(2))).to.equal(false);
      expect(runtime.includes("a9059cbb"), "POSITIVE CONTROL: the same search does find transfer").to.equal(true);
      expect(runtime.includes("70a08231"), "and balanceOf").to.equal(true);
      const w = await world("noallow-sel");
      let refused = false;
      try {
        await ethers.provider.call({ to: w.vaultAddress, data: SELECTORS.isValidSignature + "00".repeat(96) });
      } catch {
        refused = true;
      }
      expect(refused, "the vault does not answer isValidSignature").to.equal(true);
    });

    it("a token's permit and signature-transfer paths cannot debit the vault, even signed by the credential itself; a contract that DOES answer 1271 can be debited", async function () {
      const w = await world("noallow", { tokenUnit: gen2Unit("Gen2SignatureDebitToken") });
      const token = new ethers.Contract(
        w.token,
        gen2Unit("Gen2SignatureDebitToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      const digest = ethers.id("any-digest");
      const signature = w.credKey.sign(digest).serialized;
      const attacker = await w.outsider.getAddress();

      const fails = async (run: () => Promise<{ wait: () => Promise<unknown> }>): Promise<boolean> => {
        try {
          await (await run()).wait();
          return false;
        } catch {
          return true;
        }
      };
      expect(
        await fails(() =>
          token
            .getFunction("permit")
            .send(w.vaultAddress, attacker, DEFAULT_MINT, digest, signature, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(true);
      expect(
        await fails(() =>
          token
            .getFunction("transferWithAuthorization")
            .send(w.vaultAddress, attacker, DEFAULT_MINT, digest, signature, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(true);
      expect(
        await fails(() =>
          (token.connect(w.outsider) as ethers.Contract)
            .getFunction("transferFrom")
            .send(w.vaultAddress, attacker, 1n, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(true);
      expect(await token.allowance(w.vaultAddress, attacker)).to.equal(0n);
      expect(await token.balanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);

      // POSITIVE CONTROL: the adversary is real. A contract answering 1271 IS debited through the same path.
      const wallet = await deployArtifact("GoodContractGuardian", w.deployer);
      await (await token.mint(wallet.address, 5n)).wait();
      await (
        await token.getFunction("transferWithAuthorization").send(wallet.address, attacker, 5n, digest, signature)
      ).wait();
      expect(await token.balanceOf(attacker)).to.equal(5n);
    });

    it("spending this token still works: the only path off the vault is the one the kernel makes", async function () {
      const w = await world("noallow-ok", { tokenUnit: gen2Unit("Gen2SignatureDebitToken") });
      const token = new ethers.Contract(
        w.token,
        gen2Unit("Gen2SignatureDebitToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await token.balanceOf(w.recipient)).to.equal(AMOUNT);
    });
  });
});
