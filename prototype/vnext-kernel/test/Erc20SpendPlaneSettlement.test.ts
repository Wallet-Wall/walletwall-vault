/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * THE ACCOUNTING QUESTION, SETTLED BY EXECUTION. The custody adjudication prefers
 * observed-balance settlement for the admitted-asset plane because direct ERC-20
 * transfers bypass any explicit deposit method. This suite runs an adversarial
 * token zoo against the three candidate accounting rules as MODEL contracts —
 *
 *   A  internal ledger        recordedBalance -= amount; token.transfer(...)
 *   B  direct balance + boolean trust   (SafeERC20 semantics)
 *   C  observed-balance delta (the kernel's rule)
 *
 * — and against the candidate KERNEL itself, so the preference is proved or
 * refuted per adversary rather than argued. A rule REFUSES an adversary when
 * `spend` reverts; it is FOOLED when `spend` succeeds while the recipient did not
 * receive exactly what the rule reported settled (or the sender lost more).
 *
 * Every adversary row is paired with the vanilla control on the same rule.
 */
import { expect } from "chai";

import {
  DOMAIN,
  UNIT,
  balanceOf,
  currentNonce,
  deployErc20World,
  deployUnit,
  planeUnit,
  sendSpend,
} from "./erc20-spend-plane-world.js";
import { ethers } from "./connection.js";

const AMOUNT = 250n * UNIT;
const FUNDING = 1_000n * UNIT;

type Outcome =
  "REFUSED" | "SETTLED_EXACTLY" | "FOOLED_SHORT_RECIPIENT" | "FOOLED_SENDER_OVERDEBIT" | "FOOLED_NOTHING_MOVED";

interface Zoo {
  readonly name: string;
  /** How a vanilla-trusting rule is fooled, if it is. */
  readonly truth: string;
  readonly prepare?: (token: ethers.Contract) => Promise<void>;
}

const ZOO: Zoo[] = [
  { name: "VanillaToken", truth: "moves exactly amount, returns true (the control)" },
  { name: "FalseReturningToken", truth: "returns false, moves nothing" },
  { name: "LyingToken", truth: "returns true, moves nothing" },
  { name: "ShortPayToken", truth: "moves amount/2, returns true" },
  { name: "SenderFeeToken", truth: "sender debited amount + 1%, recipient receives amount" },
  { name: "RecipientFeeToken", truth: "sender debited amount, recipient receives amount - 1%" },
  { name: "NoReturnToken", truth: "moves exactly amount, returns NOTHING" },
  {
    name: "RebasingToken",
    truth: "index 1.5e18: transfer rounds shares down, settles 1 unit short",
    prepare: async (t) => {
      await (await t.rebase(1_500_000_000_000_000_000n)).wait();
    },
  },
];

async function deployToken(name: string): Promise<ethers.Contract> {
  const [deployer] = await ethers.getSigners();
  return (await deployUnit(planeUnit(name), deployer!)).contract;
}

async function deployModel(name: string): Promise<ethers.Contract> {
  const [deployer] = await ethers.getSigners();
  return (await deployUnit(planeUnit(name), deployer!)).contract;
}

/** Classifies what REALLY happened from the balances alone, independent of what the rule reported. */
async function classify(
  token: ethers.Contract,
  holder: string,
  recipient: string,
  before: { holder: bigint; recipient: bigint },
  spendOk: boolean,
): Promise<Outcome> {
  if (!spendOk) return "REFUSED";
  const after = { holder: await balanceOf(token, holder), recipient: await balanceOf(token, recipient) };
  const sent = before.holder - after.holder;
  const received = after.recipient - before.recipient;
  if (sent === AMOUNT && received === AMOUNT) return "SETTLED_EXACTLY";
  if (sent === 0n && received === 0n) return "FOOLED_NOTHING_MOVED";
  if (sent > AMOUNT) return "FOOLED_SENDER_OVERDEBIT";
  return "FOOLED_SHORT_RECIPIENT";
}

async function runModel(modelName: string, zoo: Zoo, recipient: string): Promise<Outcome> {
  const token = await deployToken(zoo.name);
  const model = await deployModel(modelName);
  const holder = await model.getAddress();
  await (await token.mint(holder, FUNDING)).wait();
  if (zoo.prepare) await zoo.prepare(token);
  if (modelName === "LedgerSettlementModel") await (await model.credit(FUNDING)).wait();
  const before = { holder: await balanceOf(token, holder), recipient: await balanceOf(token, recipient) };
  let ok = true;
  try {
    await (await model.spend(await token.getAddress(), recipient, AMOUNT)).wait();
  } catch {
    ok = false;
  }
  return classify(token, holder, recipient, before, ok);
}

describe("ERC-20 spend plane — settlement rules against the adversarial token zoo", function () {
  this.timeout(240_000);

  const results: Record<string, Record<string, Outcome>> = {};
  let recipient: string;

  before(async function () {
    recipient = (await ethers.getSigners())[2]!.address;
  });

  for (const model of [
    "LedgerSettlementModel",
    "ReturnValueSettlementModel",
    "ObservedDeltaSettlementModel",
  ] as const) {
    describe(`model ${model}`, function () {
      for (const zoo of ZOO) {
        it(`${zoo.name}: ${zoo.truth}`, async function () {
          const outcome = await runModel(model, zoo, recipient);
          (results[model] ??= {})[zoo.name] = outcome;
          // The vanilla control must settle on EVERY rule, or the rule is broken rather than strict.
          if (zoo.name === "VanillaToken" || zoo.name === "NoReturnToken") {
            expect(outcome).to.equal("SETTLED_EXACTLY");
          }
        });
      }
    });
  }

  describe("the verdicts, read off the balances", function () {
    it("model A (ledger) and model B (boolean trust) are FOOLED by the lying, short-pay, sender-fee and rebasing tokens", function () {
      for (const model of ["LedgerSettlementModel", "ReturnValueSettlementModel"]) {
        const r = results[model]!;
        expect(r.LyingToken, model).to.equal("FOOLED_NOTHING_MOVED");
        expect(r.ShortPayToken, model).to.equal("FOOLED_SHORT_RECIPIENT");
        expect(r.SenderFeeToken, model).to.equal("FOOLED_SENDER_OVERDEBIT");
        expect(r.RebasingToken, model).to.equal("FOOLED_SHORT_RECIPIENT");
        // The boolean DOES catch the honest refusal: returning false is refused by both.
        expect(r.FalseReturningToken, model).to.equal("REFUSED");
      }
    });

    it("model C (observed delta) REFUSES every one of them and settles the two honest shapes", function () {
      const r = results.ObservedDeltaSettlementModel!;
      expect(r.VanillaToken).to.equal("SETTLED_EXACTLY");
      expect(r.NoReturnToken).to.equal("SETTLED_EXACTLY");
      expect(r.FalseReturningToken).to.equal("REFUSED");
      expect(r.LyingToken).to.equal("REFUSED");
      expect(r.ShortPayToken).to.equal("REFUSED");
      expect(r.SenderFeeToken).to.equal("REFUSED");
      expect(r.RebasingToken).to.equal("REFUSED");
    });

    it("the one adversary NO sender-side rule can see: a fee taken from the RECIPIENT's leg settles on every model", function () {
      // Recorded as a KNOWN UNSUPPORTED BEHAVIOUR, not hidden: the sender's balance is the only ledger the vault owns,
      // and it tells the truth about the sender. A recipient-leg fee is the asset's semantics, admissible only if the
      // admitted asset is known not to have one — which is a property of the ASSET admitted, not of the kernel.
      for (const model of Object.keys(results)) {
        expect(results[model]!.RecipientFeeToken, model).to.equal("FOOLED_SHORT_RECIPIENT");
      }
    });
  });

  describe("the KERNEL implements model C — the same zoo, through execute", function () {
    for (const zoo of ZOO) {
      it(`${zoo.name}: kernel outcome equals model C's`, async function () {
        const w = await deployErc20World({ label: `settle-${zoo.name}`, token: zoo.name, mintToVault: FUNDING });
        if (zoo.prepare)
          await zoo.prepare(
            new ethers.Contract(w.tokenAddress, planeUnit(zoo.name).abi as ethers.InterfaceAbi, w.deployer),
          );
        const before = {
          holder: await balanceOf(w.token, w.vaultAddress),
          recipient: await balanceOf(w.token, w.recipient),
        };
        const nonceBefore = await currentNonce(w, DOMAIN.SPEND);
        let ok = true;
        try {
          await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, from: w.outsider, gasLimit: 400_000n })).wait();
        } catch {
          ok = false;
        }
        const outcome = await classify(w.token, w.vaultAddress, w.recipient, before, ok);
        expect(outcome).to.equal(results.ObservedDeltaSettlementModel![zoo.name]);
        // ATOMICITY: a refused spend consumes no nonce; an accepted one consumes exactly one.
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(ok ? nonceBefore + 1n : nonceBefore);
      });
    }
  });
});
