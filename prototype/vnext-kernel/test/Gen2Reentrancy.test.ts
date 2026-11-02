/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE EXTERNAL-CALL BOUNDARY: row G2-REENTRANCY, and PLANE-ISOLATION. Generation 2 hands control to a token
 * inside the spend path, so this asks what that token can do with it. The kernel has no reentrancy guard and
 * this suite is why it needs none: the nonce is consumed before the plane and the token run, the balance is
 * snapshotted after the plane and read again after the token, and everything nested is an ordinary call that
 * must clear its own authority. So a hook can only sequence acts someone authorised, and the claim tested is
 * SERIAL EQUIVALENCE: every outcome is one some ordering of authorised acts could produce, or the whole call
 * reverts. A guard would be an architectural delta to measure, and nothing here earns one.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";
import { gen2Unit } from "../generation-2/compile.js";
import {
  ACTION,
  DEFAULT_MINT,
  DOMAIN,
  FAR_DEADLINE,
  UNIT,
  addrOf,
  advanceTime,
  assetBalance,
  bindCalldata,
  containmentCalldata,
  currentNonce,
  deployGen2World,
  deployUnit,
  guardianDigest,
  keyOf,
  quorum,
  recoverParams,
  recoveryCalldata,
  refusal,
  rotateCalldata,
  send,
  sendSpend,
  setGuardiansCalldata,
  setMode,
  setPolicyCalldata,
  spendCalldata,
  zoo,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 2_000_000n;
const AMOUNT = 250n * UNIT;
const POSITIONS = [
  ["before the debit", false],
  ["after the debit", true],
] as const;

const world = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, ecdsaOnlyFloor: true, ...more });

async function arm(w: Gen2World, payload: string, afterDebit: boolean, target?: string): Promise<void> {
  await (await zoo(w).armHook(target ?? w.vaultAddress, payload, afterDebit)).wait();
}

/** A spend for `nonce`, signed by `signer`, as bytes a hook can carry. */
function signedSpend(w: Gen2World, to: string, amount: bigint, nonce: bigint, signer?: ethers.SigningKey): string {
  return spendCalldata(w, { to, amount, nonce, credentialGeneration: 1n, signer });
}

async function kernelWords(w: Gen2World): Promise<string[]> {
  const raw = await Promise.all(
    Array.from({ length: 24 }, (_, slot) => ethers.provider.getStorage(w.vaultAddress, slot)),
  );
  const nonces = await Promise.all([0, 1, 2, 3].map((d) => w.vault.nonces(d)));
  return [...raw, ...nonces.map(String)];
}

describe("Generation-2 admission — the reentrant token, with no guard", function () {
  this.timeout(180_000);

  for (const [position, afterDebit] of POSITIONS) {
    describe(`hook ${position}`, function () {
      it("cannot double-spend: a second VALID spend at nonce + 1 breaks the outer exact delta and the whole call reverts", async function () {
        const w = await world(`re-double-${afterDebit}`);
        await arm(w, signedSpend(w, w.recipient, UNIT, 1n), afterDebit);
        const before = await kernelWords(w);
        expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
          "TransferFailed",
        );
        expect(await kernelWords(w), "nonce included: nothing is left behind").to.deep.equal(before);
        expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
        expect(await assetBalance(w, w.recipient)).to.equal(0n);
      });

      it("cannot replay: the same calldata from inside the transfer dies on the nonce the outer call already consumed", async function () {
        const w = await world(`re-replay-${afterDebit}`);
        const data = signedSpend(w, w.recipient, AMOUNT, 0n);
        await arm(w, data, afterDebit);
        await (await send(w, data, w.outsider, PROBE_GAS)).wait();
        const token = zoo(w);
        expect(await token.hookFired(), "POSITIVE CONTROL: the hook really ran").to.equal(true);
        expect(await token.hookSucceeded(), "the nested replay was refused").to.equal(false);
        expect(w.vault.interface.parseError((await token.hookReturn()) as string)?.name).to.equal("BadNonce");
        expect(await assetBalance(w, w.recipient), "paid once").to.equal(AMOUNT);
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
      });

      it("finds the nonce already consumed: the token itself reads it through the vault's own getter", async function () {
        const w = await world(`re-nonce-${afterDebit}`);
        await arm(w, w.vault.interface.encodeFunctionData("nonces", [DOMAIN.SPEND]), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        const [seen] = ethers.AbiCoder.defaultAbiCoder().decode(
          ["uint256"],
          (await zoo(w).hookReturn()) as string,
        ) as unknown as [bigint];
        expect(seen).to.equal(1n);
      });

      it("a hostile hook signed by nobody is refused inside and the honest spend it sits in still settles exactly", async function () {
        const w = await world(`re-hostile-${afterDebit}`);
        await arm(w, signedSpend(w, w.recipient, UNIT, 1n, keyOf("re-hostile-signer")), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(false);
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(1n);
      });

      it("serial equivalence: an authorised zero-value spend nested at nonce + 1 settles, and the result is spend-then-spend", async function () {
        const w = await world(`re-serial-${afterDebit}`);
        await arm(w, signedSpend(w, w.recipient, 0n, 1n), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(true);
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(2n);
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
      });

      it("failure is atomic: an authorised containment that SUCCEEDED inside a refused spend is rolled back with it", async function () {
        const w = await world(`re-atomic-${afterDebit}`);
        await arm(w, await containmentCalldata(w), afterDebit);
        await setMode(w, "RETURN_TRUE_NO_MOVE");
        const before = await kernelWords(w);
        expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
          "TransferFailed",
        );
        expect(await kernelWords(w)).to.deep.equal(before);
        expect(await w.vault.safeState()).to.equal(0n);
        expect(await zoo(w).hookFired(), "the token's own record rolled back too").to.equal(false);
      });

      it("cannot escape a safe state: a containment entered from the hook stops the next spend, which is spend-then-contain", async function () {
        const w = await world(`re-contain-${afterDebit}`);
        await arm(w, await containmentCalldata(w), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(true);
        expect(await w.vault.effectiveSafeState()).to.equal(1n);
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
        expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
          "BadState",
        );
      });

      it("a rotation from the hook is spend-then-rotate: the outer spend settles under the key that signed it, and the next spend needs the new one; a stranger's is refused", async function () {
        const w = await world(`re-rotate-${afterDebit}`);
        const newCred = keyOf(`re-rotate-new-${afterDebit}`);
        await arm(w, await rotateCalldata(w, newCred, null), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(true);
        expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
        expect(
          await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
          "the old key",
        ).to.equal("BadSignature");
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred })).wait();

        const hostile = await world(`re-rotate-hostile-${afterDebit}`);
        await arm(
          hostile,
          await rotateCalldata(hostile, keyOf("re-rotate-stranger"), null, {
            credential: keyOf("re-rotate-not-the-credential"),
          }),
          afterDebit,
        );
        await (await sendSpend(hostile, { to: hostile.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(hostile).hookSucceeded()).to.equal(false);
        expect(await hostile.vault.ecdsaSigner()).to.equal(addrOf(hostile.credKey));
      });

      it("a roster change from the hook is spend-then-replace: the outer spend settles, the old quorum is spent, and a sub-quorum's is refused", async function () {
        const w = await world(`re-roster-${afterDebit}`);
        const replacement = [0, 1, 2]
          .map((i) => keyOf(`re-roster-${afterDebit}-${i}`))
          .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
        await arm(w, await setGuardiansCalldata(w, 2n, replacement.map(addrOf), [false, false, false]), afterDebit);
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(true);
        expect(await w.vault.guardianGeneration()).to.equal(2n);
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
        expect(
          await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS)),
          "the old roster",
        ).to.equal("BadRoster");

        const hostile = await world(`re-roster-hostile-${afterDebit}`);
        await arm(
          hostile,
          await setGuardiansCalldata(hostile, 2n, replacement.map(addrOf), [false, false, false], (digest) =>
            quorum(hostile, digest, [0]),
          ),
          afterDebit,
        );
        await (await sendSpend(hostile, { to: hostile.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(hostile).hookSucceeded()).to.equal(false);
        expect(await hostile.vault.guardianGeneration()).to.equal(1n);
      });

      it("a recovery begun from the hook is spend-then-initiate: its clock is the mined block's, and without a quorum it is refused", async function () {
        const w = await world(`re-recover-${afterDebit}`);
        await arm(
          w,
          await recoveryCalldata(w, addrOf(keyOf("re-recover-new")), ethers.ZeroHash, w.verifiers.honest),
          afterDebit,
        );
        const receipt = await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(w).hookSucceeded()).to.equal(true);
        const mined = BigInt((await ethers.provider.getBlock(receipt!.blockNumber))!.timestamp);
        expect((await w.vault.recovery()).executableAt, "executable a full delay after the mined block").to.equal(
          mined + (await w.vault.RECOVERY_DELAY()),
        );
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);

        const hostile = await world(`re-recover-hostile-${afterDebit}`);
        const nonce = await currentNonce(hostile, DOMAIN.GUARDIAN);
        const digest = await guardianDigest(
          hostile,
          ACTION.RECOVER,
          recoverParams(addrOf(keyOf("re-recover-new")), ethers.ZeroHash, hostile.verifiers.honest),
          DOMAIN.GUARDIAN,
          nonce,
        );
        const belowQuorum = hostile.vault.interface.encodeFunctionData("initiateRecovery", [
          addrOf(keyOf("re-recover-new")),
          ethers.ZeroHash,
          hostile.verifiers.honest,
          quorum(hostile, digest, [0]),
          nonce,
          FAR_DEADLINE,
        ]);
        await arm(hostile, belowQuorum, afterDebit);
        await (await sendSpend(hostile, { to: hostile.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(hostile).hookSucceeded()).to.equal(false);
        expect((await hostile.vault.recovery()).active, "no request").to.equal(false);
      });

      it("cannot alter the migration disposition: an authorised bind from the hook fixes the signed destination; unauthorised it is refused", async function () {
        const honest = await world(`re-bind-${afterDebit}`);
        await arm(honest, await bindCalldata(honest), afterDebit);
        await (await sendSpend(honest, { to: honest.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(honest).hookSucceeded()).to.equal(true);
        const binding = await honest.vault.migration();
        expect(binding[0]).to.equal(honest.destination);
        expect(
          await refusal(honest, () => sendSpend(honest, { to: honest.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
          "the state it entered still refuses a spend",
        ).to.equal("BadState");
        expect(
          await refusal(honest, () =>
            honest.vault.connect(honest.outsider).getFunction("egress").send(honest.token, { gasLimit: PROBE_GAS }),
          ),
          "and the delay still applies",
        ).to.equal("TooEarly");

        const hostile = await world(`re-bind-hostile-${afterDebit}`);
        await arm(
          hostile,
          await bindCalldata(hostile, {
            destination: keyOfAddress("re-bind-elsewhere"),
            credential: keyOf("re-bind-not-the-credential"),
          }),
          afterDebit,
        );
        await (await sendSpend(hostile, { to: hostile.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
        expect(await zoo(hostile).hookSucceeded()).to.equal(false);
        expect((await hostile.vault.migration())[4], "no binding").to.equal(false);
      });
    });
  }

  describe("the settlement observation cannot be manipulated into accepting unauthorised value movement", function () {
    it("a token crediting the vault during its own transfer makes the observed decrease wrong, and the spend is refused", async function () {
      const w = await world("re-credit");
      const mint = new ethers.Interface(["function mint(address,uint256)"]).encodeFunctionData("mint", [
        w.vaultAddress,
        UNIT,
      ]);
      await arm(w, mint, true, w.token);
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
        "TransferFailed",
      );
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("a rebase of the vault during the transfer is an over- or under-debit like any other", async function () {
      const w = await world("re-rebase");
      const rebase = new ethers.Interface(["function rebaseAccount(address,uint256)"]).encodeFunctionData(
        "rebaseAccount",
        [w.vaultAddress, DEFAULT_MINT / 2n],
      );
      await arm(w, rebase, true, w.token);
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
        "TransferFailed",
      );
    });

    it("the hook has no other route to the vault's holdings: nested egress of another holding is NotBound", async function () {
      const w = await world("re-other");
      await (await w.other.mint(w.vaultAddress, UNIT)).wait();
      await arm(w, w.vault.interface.encodeFunctionData("egress", [w.otherToken]), true);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
      const token = zoo(w);
      expect(await token.hookSucceeded()).to.equal(false);
      expect(w.vault.interface.parseError((await token.hookReturn()) as string)?.name).to.equal("NotBound");
      expect(await w.other.realBalanceOf(w.vaultAddress)).to.equal(UNIT);
    });
  });

  describe("egress under a hook: a stranger's call, so the disposition is what must hold", function () {
    async function boundAndOpen(label: string): Promise<Gen2World> {
      const w = await world(label);
      await (await send(w, await bindCalldata(w))).wait();
      await advanceTime(7 * 86400 + 1);
      return w;
    }

    it("a nested egress before the debit leaves the outer transfer unable to pay and the whole call reverts: nothing moved, retry stays open", async function () {
      const w = await boundAndOpen("re-eg-before");
      await arm(w, w.vault.interface.encodeFunctionData("egress", [w.token]), false);
      expect(
        await refusal(w, () =>
          w.vault.connect(w.outsider).getFunction("egress").send(w.token, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("TransferFailed");
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      await (await zoo(w).disarmHook()).wait();
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("a nested egress after the debit finds nothing left: everything is at the destination, and the events sum to what moved", async function () {
      const w = await boundAndOpen("re-eg-after");
      await arm(w, w.vault.interface.encodeFunctionData("egress", [w.token]), true);
      const receipt = await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
      const moved = (receipt!.logs as ethers.Log[])
        .map((l) => {
          try {
            return w.vault.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .filter((p) => p?.name === "Egressed")
        .map((p) => p!.args[2] as bigint);
      expect(moved.reduce((a, b) => a + b, 0n)).to.equal(DEFAULT_MINT);
    });

    it("a replayable spend from a hook during an egress is refused by the state: the binding already closed the spend path", async function () {
      const w = await boundAndOpen("re-eg-spend");
      await arm(w, signedSpend(w, w.recipient, UNIT, 0n), true);
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      const token = zoo(w);
      expect(await token.hookSucceeded()).to.equal(false);
      expect(w.vault.interface.parseError((await token.hookReturn()) as string)?.name).to.equal("BadState");
      expect(await assetBalance(w, w.recipient)).to.equal(0n);
    });
  });

  describe("PLANE-ISOLATION: a plane may only refuse, and it runs before the settlement snapshot", function () {
    async function withProbingPlane(label: string): Promise<{ w: Gen2World; plane: ethers.Contract }> {
      const w = await world(label);
      const plane = await deployUnit(gen2Unit("Gen2ProbingPolicy"), w.deployer);
      await (await send(w, await setPolicyCalldata(w, plane.address))).wait();
      return { w, plane: plane.contract };
    }

    it("a plane replaying the spend it is admitting dies on the nonce, and the spend settles", async function () {
      const { w, plane } = await withProbingPlane("pl-replay");
      const data = signedSpend(w, w.recipient, AMOUNT, 0n);
      await (await plane.arm(w.vaultAddress, data, true)).wait();
      await (await send(w, data, w.outsider, PROBE_GAS)).wait();
      expect(await plane.fired(), "POSITIVE CONTROL: the plane really ran").to.equal(true);
      expect(await plane.succeeded()).to.equal(false);
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("a plane nesting an authorised spend cannot touch the observation: both settle exactly, because the snapshot comes after it", async function () {
      const { w, plane } = await withProbingPlane("pl-nested");
      await (await plane.arm(w.vaultAddress, signedSpend(w, w.recipient, UNIT, 1n), true)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
      expect(await plane.succeeded()).to.equal(true);
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT + UNIT);
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(2n);
    });

    it("a plane nesting a quorum-signed containment is spend-then-contain too, with a vanilla token: the spend settles while contained", async function () {
      const { w, plane } = await withProbingPlane("pl-contain");
      await (await plane.arm(w.vaultAddress, await containmentCalldata(w), true)).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
      expect(await plane.succeeded()).to.equal(true);
      expect(await w.vault.effectiveSafeState()).to.equal(1n);
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("a plane's refusal reverts the spend and everything the plane nested, and consumes nothing", async function () {
      const { w, plane } = await withProbingPlane("pl-deny");
      await (await plane.arm(w.vaultAddress, signedSpend(w, w.recipient, UNIT, 1n), false)).wait();
      const nonce = await currentNonce(w, DOMAIN.SPEND);
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce, gasLimit: PROBE_GAS })),
      ).to.equal("PolicyDenied");
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(nonce);
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("a plane that always allows grants nothing: a stranger's signature is refused before it is ever asked", async function () {
      const w = await world("pl-grant");
      await (await send(w, await setPolicyCalldata(w, w.policies.allow))).wait();
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: keyOf("pl-grant-stranger"),
            from: w.outsider,
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
    });

    it("no plane is consulted on the way out: a denying plane does not stop a bound vault's egress", async function () {
      const w = await world("pl-exit");
      await (await send(w, await setPolicyCalldata(w, w.policies.deny))).wait();
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS }))).to.equal(
        "PolicyDenied",
      );
      await (await send(w, await bindCalldata(w))).wait();
      await advanceTime(7 * 86400 + 1);
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });
});

function keyOfAddress(label: string): string {
  return ethers.computeAddress(keyOf(label));
}
