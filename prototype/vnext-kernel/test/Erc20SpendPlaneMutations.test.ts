/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * MUTATION ADEQUACY FOR THE SETTLEMENT RULE. Every attack in Erc20SpendPlane.test.ts
 * is paired with a positive control, which proves the seam was REACHED. This suite
 * proves the assertions have TEETH: each mutant below is a real, compiled, deployed
 * weakening of variant A's `execute` — applied to an in-memory copy of the source,
 * never to the tracked file — and each is KILLED by a NAMED observation that the
 * real kernel passes and the mutant fails. A mutant that no observation can kill
 * would mean the suite is not measuring the rule it claims to measure.
 *
 * Mutants are first shown to be LIVE (the vanilla positive control still settles
 * on them), so a kill is never a compile or setup failure in disguise.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";

import { replaceWithinFunction } from "../authority/mutation-harness.js";
import { compilePlane, PLANE_CONTRACTS, VARIANT_A, type CompiledUnit } from "../erc20-spend-plane/compile.js";
import { ethers } from "./connection.js";
import {
  DOMAIN,
  FAR_DEADLINE,
  UNIT,
  balanceOf,
  currentNonce,
  deployErc20World,
  planeUnit,
  sendSpend,
  sign,
  spendDigest,
} from "./erc20-spend-plane-world.js";

const AMOUNT = 250n * UNIT;
const SOURCE = path.join(PLANE_CONTRACTS, "VaultKernelErc20Prototype.sol");

const CALL = "(bool ok, ) = asset.call(abi.encodeWithSelector(0xa9059cbb, recipient, amount));";
const CALL_CHECK = "if (!ok) revert TransferFailed();";
const BEFORE = "uint256 before = _balanceOf(asset);";
const REMAINING = "uint256 remaining = _balanceOf(asset);";
const DELTA = "if (remaining > before || before - remaining != amount) revert TransferFailed();";
const CONSUME = "_consume(DOMAIN_SPEND, nonce, deadline);";

interface Mutant {
  readonly id: string;
  readonly weakening: string;
  readonly apply: (source: string) => string;
}

const MUTANTS: Mutant[] = [
  {
    id: "M-E1 boolean trust",
    weakening: "settlement judged on the token's returned boolean (SafeERC20), the observed balance never read",
    apply: (s) => {
      let out = replaceWithinFunction(s, "execute", BEFORE, "");
      out = replaceWithinFunction(
        out,
        "execute",
        CALL + "\n        " + CALL_CHECK,
        "(bool ok, bytes memory data) = asset.call(abi.encodeWithSelector(0xa9059cbb, recipient, amount));\n" +
          "        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();",
      );
      out = replaceWithinFunction(out, "execute", REMAINING, "");
      return replaceWithinFunction(out, "execute", DELTA, "");
    },
  },
  {
    id: "M-E2 any decrease",
    weakening: "egress's full-balance rule applied to a sized spend: ANY decrease settles, not exactly `amount`",
    apply: (s) => replaceWithinFunction(s, "execute", DELTA, "if (remaining >= before) revert TransferFailed();"),
  },
  {
    id: "M-E3 nonce after settlement",
    weakening: "the spend nonce is consumed AFTER the asset call instead of before it",
    apply: (s) => {
      const out = replaceWithinFunction(s, "execute", CONSUME, "");
      return replaceWithinFunction(out, "execute", DELTA, DELTA + "\n        " + CONSUME);
    },
  },
  {
    id: "M-E4 call failure ignored",
    weakening: "a reverting asset call is not refused on its own; only the delta rule remains",
    apply: (s) => replaceWithinFunction(s, "execute", CALL_CHECK, ""),
  },
];

function compileMutant(m: Mutant): CompiledUnit {
  const original = fs.readFileSync(SOURCE, "utf8");
  const mutated = m.apply(original);
  expect(mutated, `${m.id}: the mutation changed nothing`).to.not.equal(original);
  const compiled = compilePlane({ overrides: { "VaultKernelErc20Prototype.sol": mutated } });
  const unit = compiled.units.get(VARIANT_A);
  if (!unit) throw new Error(`${m.id}: mutant did not compile to ${VARIANT_A}`);
  return unit;
}

/** `true` when the spend settled, `false` when the kernel refused it. */
async function spendSettles(
  w: Awaited<ReturnType<typeof deployErc20World>>,
  amount: bigint,
  gasLimit = 400_000n,
): Promise<boolean> {
  try {
    await (await sendSpend(w, { to: w.recipient, amount, gasLimit })).wait();
    return true;
  } catch {
    return false;
  }
}

describe("ERC-20 spend plane — mutation adequacy of the settlement rule", function () {
  this.timeout(300_000);

  const compiled = new Map<string, CompiledUnit>();

  before(function () {
    for (const m of MUTANTS) compiled.set(m.id, compileMutant(m));
  });

  it("every mutant is LIVE: the vanilla positive control still settles on each weakened kernel", async function () {
    for (const m of MUTANTS) {
      const w = await deployErc20World({ label: `live-${m.id}`, implOverride: compiled.get(m.id) });
      expect(await spendSettles(w, AMOUNT), `${m.id} is dead: the vanilla control does not settle`).to.equal(true);
      expect(await balanceOf(w.token, w.recipient)).to.equal(AMOUNT);
    }
  });

  it("M-E1 boolean trust is KILLED by the lying token: the real kernel refuses it, the mutant settles nothing and says it did", async function () {
    const real = await deployErc20World({ label: "e1-real", token: "LyingToken" });
    const mutant = await deployErc20World({
      label: "e1-mutant",
      token: "LyingToken",
      implOverride: compiled.get("M-E1 boolean trust"),
    });
    expect(await spendSettles(real, AMOUNT)).to.equal(false);
    expect(await spendSettles(mutant, AMOUNT)).to.equal(true);
    // The observation that kills: a spend "settled" with nobody paid and nobody debited.
    expect(await balanceOf(mutant.token, mutant.recipient)).to.equal(0n);
    expect(await balanceOf(mutant.token, mutant.vaultAddress)).to.equal(1_000n * UNIT);
    expect(await currentNonce(mutant, DOMAIN.SPEND)).to.equal(1n);
  });

  it("M-E2 any decrease is KILLED by the short-pay token (half settles) and the sender-fee token (over-debit): exactness is load-bearing", async function () {
    for (const token of ["ShortPayToken", "SenderFeeToken"]) {
      const real = await deployErc20World({ label: `e2-real-${token}`, token });
      const mutant = await deployErc20World({
        label: `e2-mutant-${token}`,
        token,
        implOverride: compiled.get("M-E2 any decrease"),
      });
      expect(await spendSettles(real, AMOUNT), `${token}: real kernel`).to.equal(false);
      expect(await spendSettles(mutant, AMOUNT), `${token}: mutant`).to.equal(true);
      const debited = 1_000n * UNIT - (await balanceOf(mutant.token, mutant.vaultAddress));
      expect(debited, `${token}: the mutant published amount ${AMOUNT} while the vault lost ${debited}`).to.not.equal(
        AMOUNT,
      );
    }
  });

  it("M-E3 nonce after settlement is KILLED by a hook that reads the nonce during the transfer: the real kernel has already advanced it", async function () {
    const probe = (w: Awaited<ReturnType<typeof deployErc20World>>) =>
      w.vault.interface.encodeFunctionData("nonces", [DOMAIN.SPEND]);
    const real = await deployErc20World({ label: "e3-real", token: "ReentrantToken" });
    const mutant = await deployErc20World({
      label: "e3-mutant",
      token: "ReentrantToken",
      implOverride: compiled.get("M-E3 nonce after settlement"),
    });
    for (const [label, w, expectedDuringTransfer] of [
      ["real", real, 1n],
      ["mutant", mutant, 0n],
    ] as const) {
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("ReentrantToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await token.arm(w.vaultAddress, probe(w))).wait();
      expect(await spendSettles(w, AMOUNT), `${label}: the probing spend itself settles`).to.equal(true);
      expect(await token.reentrySucceeded(), `${label}: the nonce read succeeded`).to.equal(true);
      const observed = ethers.AbiCoder.defaultAbiCoder().decode(
        ["uint256"],
        (await token.reentryReturn()) as string,
      )[0] as bigint;
      expect(observed, `${label}: nonce observed by the asset mid-transfer`).to.equal(expectedDuringTransfer);
    }
    // And the consequence the ordering exists to prevent: on the mutant a same-payload replay from inside the hook is
    // NOT refused as BadNonce (it fails only later, on the outer delta), so the replay guard no longer stands alone.
    const digest = spendDigest(mutant, { to: mutant.recipient, amount: AMOUNT, nonce: 1n });
    const replay = mutant.vault.interface.encodeFunctionData("execute", [
      mutant.recipient,
      AMOUNT,
      1n,
      FAR_DEADLINE,
      sign(mutant.credKey, digest),
      "0x",
      "0x",
    ]);
    const token = new ethers.Contract(
      mutant.tokenAddress,
      planeUnit("ReentrantToken").abi as ethers.InterfaceAbi,
      mutant.deployer,
    );
    await (await token.arm(mutant.vaultAddress, replay)).wait();
    expect(await spendSettles(mutant, AMOUNT)).to.equal(false);
    // Whereas the real kernel, armed the same way, settles the outer spend and records the inner replay as refused.
    const realToken = new ethers.Contract(
      real.tokenAddress,
      planeUnit("ReentrantToken").abi as ethers.InterfaceAbi,
      real.deployer,
    );
    const realDigest = spendDigest(real, { to: real.recipient, amount: AMOUNT, nonce: 1n });
    await (
      await realToken.arm(
        real.vaultAddress,
        real.vault.interface.encodeFunctionData("execute", [
          real.recipient,
          AMOUNT,
          1n,
          FAR_DEADLINE,
          sign(real.credKey, realDigest),
          "0x",
          "0x",
        ]),
      )
    ).wait();
    expect(await spendSettles(real, AMOUNT)).to.equal(true);
    expect(await realToken.reentrySucceeded()).to.equal(false);
  });

  it("M-E4 call failure ignored is KILLED by a reverting zero-amount transfer: the real kernel refuses a failed call even when nothing was to move", async function () {
    const real = await deployErc20World({ label: "e4-real" });
    const mutant = await deployErc20World({
      label: "e4-mutant",
      implOverride: compiled.get("M-E4 call failure ignored"),
    });
    for (const w of [real, mutant]) {
      const token = new ethers.Contract(
        w.tokenAddress,
        planeUnit("VanillaToken").abi as ethers.InterfaceAbi,
        w.deployer,
      );
      await (await token.setBlocklisted(w.recipient, true)).wait();
    }
    // Non-zero: both refuse (the delta rule catches the mutant too) — the control that shows the mutant is subtle.
    expect(await spendSettles(real, AMOUNT)).to.equal(false);
    expect(await spendSettles(mutant, AMOUNT)).to.equal(false);
    // Zero: the real kernel refuses the REVERTING call; the mutant publishes Executed(recipient, 0) for a call the asset rejected.
    expect(await spendSettles(real, 0n)).to.equal(false);
    expect(await spendSettles(mutant, 0n)).to.equal(true);
    expect(await currentNonce(mutant, DOMAIN.SPEND)).to.equal(1n);
  });
});
