/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * BYTES AND GAS OF THE ADMISSION CANDIDATE: row RUNTIME-CEILING. PR #237's figures were for a kernel this
 * lane changed, so nothing here re-uses them: the candidate is measured fresh, and every delta from what was
 * measured is published, so an admission fix cannot hide behind the old number.
 *
 * Gas is on the local Hardhat network, isolated accounts 16..18, so every address and calldata byte is
 * independent of the rest of the suite. Not a cost claim for any network, and never converted to a currency.
 */
import { expect } from "chai";
import fs from "node:fs";
import { ethers } from "./connection.js";
import { candidateIdentity } from "../generation-2/identity.js";
import { RAW_STORAGE_WORDS } from "../generation-2/stateful/invariants.js";
import {
  PLANE_RECORD_JSON,
  STOP_CONDITION_HEADROOM,
  TARGET_KERNEL_CEILING,
  compileGen1Baseline,
  compilePlane,
  GEN1_KERNEL,
  VARIANT_A,
  byteLength,
} from "../erc20-spend-plane/compile.js";
import { planeUnit } from "./erc20-spend-plane-world.js";
import { GEN2_KERNEL, gen2Unit } from "../generation-2/compile.js";
import {
  BIND_DELAY_SECONDS,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  addrOf,
  advanceTime,
  bindDestination,
  deployGen2World,
  executeRecoveryCalldata,
  keyOf,
  pqHash,
  proposeRecovery,
  refusal,
  send,
  sendSpend,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 1_500_000n;
const AMOUNT = 250n * UNIT;
/** Accounts 13..15: used by nothing else in the suite, so every address and calldata byte here is independent of test order. */
const OFFSET = 13;
const GAS_RECORD = "prototype/vnext-kernel/generation-2/GEN2_GAS_RECORD.json";

const gasOf = async (tx: { wait: () => Promise<{ gasUsed: bigint } | null> }): Promise<bigint> =>
  (await tx.wait())!.gasUsed;

async function refusedGas(w: Gen2World, send_: () => Promise<{ hash: string }>): Promise<bigint> {
  let hash = "";
  const name = await refusal(w, async () => {
    const tx = await send_();
    hash = tx.hash;
    return tx as unknown as { wait: () => Promise<unknown> };
  });
  expect(name, "this probe is a refusal").to.not.equal(null);
  if (hash !== "") return (await ethers.provider.getTransactionReceipt(hash))!.gasUsed;
  const latest = await ethers.provider.getBlock("latest", true);
  const last = latest!.prefetchedTransactions.at(-1)!;
  return (await ethers.provider.getTransactionReceipt(last.hash))!.gasUsed;
}

describe("Generation-2 admission — bytes and gas of the candidate", function () {
  this.timeout(300_000);

  const identity = candidateIdentity();
  const m = identity.measurement;
  const plane = compilePlane();
  const gen1 = compileGen1Baseline();

  describe("runtime budget", function () {
    it("prints every figure the brief asks for", function () {
      console.log(
        "\n  CANDIDATE BYTES\n" +
          JSON.stringify(
            {
              finalRuntime: m.runtimeBytes,
              initcode: m.initcodeBytes,
              deltaFromMeasuredVariantA: m.deltaFromMeasuredVariantA,
              deltaFromGeneration1: m.deltaFromGeneration1,
              headroomToEip170: m.headroomToEip170,
              headroomToTargetKernelCeiling: m.headroomToTargetKernelCeiling,
              headroomAboveStopLine: m.headroomAboveStopLine,
              factoryRuntime: m.factoryRuntimeBytes,
              factoryInitcode: m.factoryInitcodeBytes,
              cloneRuntime: m.cloneRuntimeBytes,
            },
            null,
            2,
          ).replace(/^/gm, "  "),
      );
    });

    it("the candidate clears TARGET_KERNEL_CEILING with the 600 B stop condition intact", function () {
      expect(m.runtimeBytes).to.be.lessThanOrEqual(TARGET_KERNEL_CEILING - STOP_CONDITION_HEADROOM);
      expect(m.headroomAboveStopLine).to.be.greaterThan(0);
    });

    it("the delta from measured Variant A is computed from the record #237 committed, not from a figure copied here", function () {
      const record = JSON.parse(fs.readFileSync(PLANE_RECORD_JSON, "utf8")) as {
        bytes: { variants: { A: { runtimeBytes: number; initcodeBytes: number } } };
      };
      expect(record.bytes.variants.A.runtimeBytes).to.equal(18_572);
      expect(m.runtimeBytes - record.bytes.variants.A.runtimeBytes).to.equal(m.deltaFromMeasuredVariantA);
      expect(m.initcodeBytes - record.bytes.variants.A.initcodeBytes).to.equal(m.initcodeDeltaFromMeasuredVariantA);
    });

    it("the admission changed the candidate: a zero delta would mean this lane measured the wrong bytes", function () {
      expect(m.deltaFromMeasuredVariantA).to.not.equal(0);
      expect(byteLength(plane.units.get(VARIANT_A)!.deployedBytecode)).to.equal(18_572);
    });

    it("zero immutable slots on the kernel; four on the factory; a 93-byte clone", function () {
      expect((identity.kernel as { immutableSlots: number }).immutableSlots).to.equal(0);
      expect((identity.factory as { immutableSlots: number }).immutableSlots).to.equal(4);
      expect(m.cloneRuntimeBytes).to.equal(93);
    });

    it("storage is Generation 1's layout, and the snapshot's raw-word range covers all of it", function () {
      const layout = (u: { storage: { slot: string; offset: number; label: string; type: string }[] }): unknown =>
        u.storage.map((s) => [
          s.slot,
          s.offset,
          s.label,
          s.type.split("VaultKernelGen2Prototype").join("VaultKernelPrototype"),
        ]);
      expect(layout(gen2Unit(GEN2_KERNEL))).to.deep.equal(layout(gen1.units.get(GEN1_KERNEL)!));
      expect(m.storageEntries).to.equal(17);
      expect(m.storageSlots).to.equal(11);
      const top = Math.max(...gen2Unit(GEN2_KERNEL).storage.map((s) => Number(s.slot)));
      expect(top + 8, "structs extend past their first slot").to.be.lessThan(RAW_STORAGE_WORDS);
    });

    it("the state-changing selector set is exactly Generation 1's; the additions are views", function () {
      const changing = (abi: readonly unknown[]): string[] =>
        (abi as { type?: string; name?: string; stateMutability?: string }[])
          .filter((f) => f.type === "function" && f.stateMutability !== "view" && f.stateMutability !== "pure")
          .map((f) => f.name!)
          .sort();
      expect(changing(gen2Unit(GEN2_KERNEL).abi)).to.deep.equal(changing(gen1.units.get(GEN1_KERNEL)!.abi));
      expect(m.stateChangingSelectors).to.equal(14);
      expect(gen2Unit(GEN2_KERNEL).methodIdentifiers["admittedAsset()"]).to.be.a("string");
    });
  });

  describe("gas, deterministic and local", function () {
    const table: Record<string, number> = {};

    /** #237's plain fixture, so the kernel is what these figures measure. The zoo's bookkeeping writes alone cost more than the spend. */
    const fresh = (
      label: string,
      token: string = "VanillaToken",
      more: Partial<Parameters<typeof deployGen2World>[0]> = {},
    ): Promise<Gen2World> =>
      deployGen2World({ label, ecdsaOnlyFloor: true, signerOffset: OFFSET, tokenUnit: planeUnit(token), ...more });

    it("measures the required paths, and they equal the committed record exactly", async function () {
      const w = await fresh("gas-g2");
      table.deployImplementation = Number(w.deployGas.implementation);
      table.deployFactory = Number(w.deployGas.factory);
      table.deployVault = Number(w.deployGas.vault);
      table.spendAuthorised = Number(
        await gasOf(await sendSpend(w, { to: w.recipient, amount: AMOUNT, from: w.outsider })),
      );
      table.spendRefusedBadSignature = Number(
        await refusedGas(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: keyOf("gas-g2-stranger"),
            from: w.outsider,
            gasLimit: PROBE_GAS,
          }),
        ),
      );

      const blocked = new ethers.Contract(w.token, planeUnit("VanillaToken").abi as ethers.InterfaceAbi, w.deployer);
      await (await blocked.setBlocklisted(w.recipient, true)).wait();
      table.spendRefusedTransferFailure = Number(
        await refusedGas(w, () =>
          sendSpend(w, { to: w.recipient, amount: AMOUNT, from: w.outsider, gasLimit: PROBE_GAS }),
        ),
      );
      await (await blocked.setBlocklisted(w.recipient, false)).wait();

      const lying = await fresh("gas-g2-lying", "LyingToken");
      table.spendRefusedLyingToken = Number(
        await refusedGas(lying, () =>
          sendSpend(lying, { to: lying.recipient, amount: AMOUNT, from: lying.outsider, gasLimit: PROBE_GAS }),
        ),
      );

      const bound = await fresh("gas-g2-egress");
      await (await bindDestination(bound)).wait();
      await advanceTime(BIND_DELAY_SECONDS + 1);
      table.migrationEgress = Number(
        await gasOf(await bound.vault.connect(bound.outsider).getFunction("egress").send(bound.token)),
      );

      const recovered = await fresh("gas-g2-recovery");
      const newCred = keyOf("gas-g2-recovery-cred");
      const newPq = keyOf("gas-g2-recovery-pq");
      await (await proposeRecovery(recovered, addrOf(newCred), pqHash(newPq), recovered.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (
        await send(recovered, await executeRecoveryCalldata(recovered, newCred, newPq, recovered.verifiers.honest))
      ).wait();
      table.spendAfterRecovery = Number(
        await gasOf(
          await sendSpend(recovered, {
            to: recovered.recipient,
            amount: AMOUNT,
            signer: newCred,
            from: recovered.outsider,
          }),
        ),
      );

      console.log(
        "\n  CANDIDATE GAS (local Hardhat network; not a cost claim). Re-record in " +
          GAS_RECORD +
          "\n" +
          JSON.stringify(table, null, 2).replace(/^/gm, "  "),
      );
      const recorded = JSON.parse(fs.readFileSync(GAS_RECORD, "utf8")) as { gas: Record<string, number> };
      expect(table).to.deep.equal(recorded.gas);
    });

    it("the same paths as #237 measured, and what the admission delta cost on each", function () {
      const record = JSON.parse(fs.readFileSync(PLANE_RECORD_JSON, "utf8")) as { gas: Record<string, number> };
      const delta = {
        spendAuthorised: table.spendAuthorised! - record.gas.erc20SpendVanillaRelayed!,
        spendRefusedBadSignature: table.spendRefusedBadSignature! - record.gas.erc20SpendRefusedBadSignature!,
        spendRefusedTransferFailure:
          table.spendRefusedTransferFailure! - record.gas.erc20SpendRefusedBlocklistedRecipient!,
        spendRefusedLyingToken: table.spendRefusedLyingToken! - record.gas.erc20SpendRefusedLyingToken!,
        migrationEgress: table.migrationEgress! - record.gas.erc20EgressAdmittedAsset!,
        deployImplementation: table.deployImplementation! - record.gas.deployImplementationVariantA!,
      };
      console.log("\n  GAS DELTA FROM MEASURED VARIANT A\n" + JSON.stringify(delta, null, 2).replace(/^/gm, "  "));
      // The candidate adds a length check on each balance read and one comparison on egress: small, and never a saving on a settled spend.
      expect(Math.abs(delta.spendAuthorised), "a spend costs what it cost").to.be.lessThan(1_000);
      expect(Math.abs(delta.spendRefusedBadSignature), "a refused signature never reaches the token").to.be.lessThan(
        1_000,
      );
      expect(Math.abs(delta.migrationEgress), "the delay check is one comparison").to.be.lessThan(1_000);
    });
  });
});
