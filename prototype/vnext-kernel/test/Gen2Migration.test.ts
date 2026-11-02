/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * MIGRATION BINDING AND EGRESS: rows K-12, K-12-SCOPE, K-12-TIME, K-12-CLOCK, K-13 and K-13-DEAD-BINDING. What no
 * kernel here does and the architecture requires is measured on every kernel in test/Gen2AdmissionFindings.test.ts:
 * F-VETO, F-FREEZE and F-NONFUNGIBLE stay open, as owner decisions. What this file asserts as a limit, it asserts as one.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";
import { GENERATION_2, GEN2_KERNEL, compileMutatedKernel, gen2Unit } from "../generation-2/compile.js";
import type { CompiledUnit } from "../erc20-spend-plane/compile.js";
import {
  ACTION,
  BIND_DELAY_SECONDS,
  DEFAULT_MINT,
  DESTINATION_GENERATION,
  DOMAIN,
  FAR_DEADLINE,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  ZERO,
  addrOf,
  advanceTime,
  assetBalance,
  bindCalldata,
  bindDestination,
  bindingParams,
  containmentCalldata,
  currentNonce,
  deployGen2World,
  deployUnit,
  digestOf,
  executeRecoveryCalldata,
  guardianDigest,
  keyOf,
  pqHash,
  proposeRecovery,
  quorum,
  recoveryCalldata,
  refusal,
  rotateCalldata,
  send,
  sendSpend,
  setMode,
  setPolicyCalldata,
  sign,
  zoo,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 1_500_000n;
const WEEK = 7 * 86400;

const world = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, ecdsaOnlyFloor: true, ...more });

const egress = (
  w: Gen2World,
  asset: string,
  gasLimit: bigint = PROBE_GAS,
): Promise<ethers.ContractTransactionResponse> =>
  w.vault.connect(w.outsider).getFunction("egress").send(asset, { gasLimit });

async function minedAt(tx: { wait: () => Promise<ethers.TransactionReceipt | null> }): Promise<number> {
  const receipt = await tx.wait();
  return (await ethers.provider.getBlock(receipt!.blockNumber))!.timestamp;
}

async function setNextTimestamp(ts: number): Promise<void> {
  await ethers.provider.send("evm_setNextBlockTimestamp", [ts]);
}

/** A uint64 of the kernel's storage, located through the compiler's own layout. */
async function storedWord(w: Gen2World, label: string): Promise<bigint> {
  const entry = gen2Unit(GEN2_KERNEL).storage.find((s) => s.label === label);
  if (entry === undefined) throw new Error("no such storage word: " + label);
  const raw = BigInt(await ethers.provider.getStorage(w.vaultAddress, BigInt(entry.slot)));
  return (raw >> BigInt(entry.offset * 8)) & ((1n << 64n) - 1n);
}

/**
 * A destination at a CREATE2 address this helper controls, bound and destroyed in one transaction: since
 * EIP-6780 the only way left for bound code to vanish.
 */
async function bindThenDestroy(
  w: Gen2World,
  label: string,
): Promise<{ helper: ethers.Contract; salt: string; destination: string }> {
  const helper = await deployUnit(gen2Unit("Gen2BindThenDestroy"), w.deployer);
  const ephemeral = gen2Unit("Gen2EphemeralDestination");
  const salt = ethers.id(label);
  const destination = ethers.getCreate2Address(helper.address, salt, ethers.keccak256(ephemeral.bytecode));
  const data = await bindCalldata(w, { destination, codeHash: ethers.keccak256(ephemeral.deployedBytecode) });
  await (await helper.contract.run(salt, w.vaultAddress, data)).wait();
  return { helper: helper.contract, salt, destination };
}

describe("Generation-2 admission — migration binding and egress", function () {
  this.timeout(180_000);

  describe("K-12: a binding needs the quorum AND the credential, fixes the destination, and is one-way", function () {
    it("the credential alone is refused, the quorum alone is refused, both succeed", async function () {
      const w = await world("k12");
      const nonce = await currentNonce(w, DOMAIN.MIGRATION);
      const digest = await guardianDigest(
        w,
        ACTION.BIND_MIGRATION,
        await bindingParams(w, w.destination, w.destinationCodeHash, DESTINATION_GENERATION),
        DOMAIN.MIGRATION,
        nonce,
      );
      const dest = [w.destination, w.destinationCodeHash, DESTINATION_GENERATION];
      const belowQuorum = w.vault.interface.encodeFunctionData("bindMigration", [
        dest,
        quorum(w, digest, [0]),
        nonce,
        FAR_DEADLINE,
        sign(w.credKey, digest),
      ]);
      expect(
        await refusal(w, () => send(w, belowQuorum, undefined, PROBE_GAS)),
        "one guardian plus the credential",
      ).to.equal("QuorumNotMet");
      const wrongCredential = w.vault.interface.encodeFunctionData("bindMigration", [
        dest,
        quorum(w, digest),
        nonce,
        FAR_DEADLINE,
        sign(keyOf("k12-not-credential"), digest),
      ]);
      expect(
        await refusal(w, () => send(w, wrongCredential, undefined, PROBE_GAS)),
        "the quorum without the credential",
      ).to.equal("BadSignature");
      await (
        await send(
          w,
          w.vault.interface.encodeFunctionData("bindMigration", [
            dest,
            quorum(w, digest),
            nonce,
            FAR_DEADLINE,
            sign(w.credKey, digest),
          ]),
        )
      ).wait();
      expect((await w.vault.migration())[4]).to.equal(true);
    });

    it("a binding cannot be rebound by anyone, replayed, or aimed at a zero destination", async function () {
      const w = await world("k12b");
      expect(
        await refusal(w, async () => send(w, await bindCalldata(w, { destination: ZERO }), undefined, PROBE_GAS)),
      ).to.equal("DestinationMismatch");
      expect(
        await refusal(w, async () =>
          send(w, await bindCalldata(w, { codeHash: ethers.ZeroHash }), undefined, PROBE_GAS),
        ),
      ).to.equal("DestinationMismatch");
      const data = await bindCalldata(w);
      await (await send(w, data)).wait();
      expect(await refusal(w, () => send(w, data, w.outsider, PROBE_GAS)), "a replay").to.equal("AlreadyBound");
      expect(
        await refusal(w, async () => send(w, await bindCalldata(w), undefined, PROBE_GAS)),
        "a fresh, fully-authorised rebind",
      ).to.equal("AlreadyBound");
    });

    it("a binding names no amount and no asset set: what arrives afterwards goes to the same destination", async function () {
      const w = await world("k12c");
      await (await bindDestination(w)).wait();
      await advanceTime(WEEK + 1);
      await (await egress(w, w.token)).wait();
      await (await zoo(w).mint(w.vaultAddress, 77n * UNIT)).wait();
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT + 77n * UNIT);
    });

    it("a destination's generation is signed, and otherwise a label: the kernel checks its address and code hash, and nothing else about it", async function () {
      const w = await world("k12-gen");
      const nonce = await currentNonce(w, DOMAIN.MIGRATION);
      const digest = await guardianDigest(
        w,
        ACTION.BIND_MIGRATION,
        await bindingParams(w, w.destination, w.destinationCodeHash, 9_999n),
        DOMAIN.MIGRATION,
        nonce,
      );
      await (
        await send(
          w,
          w.vault.interface.encodeFunctionData("bindMigration", [
            [w.destination, w.destinationCodeHash, 9_999n],
            quorum(w, digest),
            nonce,
            FAR_DEADLINE,
            sign(w.credKey, digest),
          ]),
        )
      ).wait();
      expect((await w.vault.migration())[2]).to.equal(9_999n);
      await advanceTime(WEEK + 1);
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("a destination must have code to be bound: a counterfactual address is refused, and the same signed call succeeds once the code is there", async function () {
      const w = await world("k12-counterfactual");
      const helper = await deployUnit(gen2Unit("Gen2BindThenDestroy"), w.deployer);
      const ephemeral = gen2Unit("Gen2EphemeralDestination");
      const salt = ethers.id("k12-counterfactual");
      const destination = ethers.getCreate2Address(helper.address, salt, ethers.keccak256(ephemeral.bytecode));
      const data = await bindCalldata(w, { destination, codeHash: ethers.keccak256(ephemeral.deployedBytecode) });
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("DestinationMismatch");
      await (await helper.contract.redeploy(salt)).wait();
      await (await send(w, data)).wait();
      expect((await w.vault.migration())[0]).to.equal(destination);
    });

    it("I-MIGRATION-CLOCK-NEUTRAL: a binding made while contained moves no clock word, and containment cannot start once bound", async function () {
      const w = await world("k12-clock");
      await (await send(w, await containmentCalldata(w))).wait();
      // Read from storage: the budget's getters are functions of the block's timestamp, and would move on their own.
      const clocks = (): Promise<bigint[]> =>
        Promise.all(
          ["containedUntil", "_previousContainmentStart", "_earlierContainmentStart"].map((label) =>
            storedWord(w, label),
          ),
        );
      const before = await clocks();
      const boundAt = await minedAt(await bindDestination(w));
      expect(await clocks()).to.deep.equal(before);
      // Its own clock runs from the mined binding, and neither shortens nor waits for anything else's.
      expect(await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS))).to.equal(
        "BadState",
      );
      await setNextTimestamp(boundAt + WEEK);
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("a LIVE recovery blocks binding; an EXPIRED one blocks nothing", async function () {
      const w = await world("k12d");
      await (await proposeRecovery(w, addrOf(keyOf("k12d-new")), ethers.ZeroHash, w.verifiers.honest)).wait();
      expect(await refusal(w, async () => send(w, await bindCalldata(w), undefined, PROBE_GAS))).to.equal("NoRecovery");
      await advanceTime(WEEK + 14 * 86400 + 1);
      await (await bindDestination(w)).wait();
      expect((await w.vault.migration())[4]).to.equal(true);
    });
  });

  describe("K-12-SCOPE: a binding commits to what it was signed under (H-10, architecture 13.1 Phase 1)", function () {
    it("a binding signed before a credential rotation, even back to the same key, is refused afterwards", async function () {
      const w = await world("scope-cred");
      const data = await bindCalldata(w);
      const away = keyOf("scope-cred-away");
      await (await send(w, await rotateCalldata(w, away, null))).wait();
      await (await send(w, await rotateCalldata(w, w.credKey, null, { credential: away }))).wait();
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("QuorumNotMet");
      await (await bindDestination(w)).wait();
    });

    it("a binding signed before a policy change is refused afterwards", async function () {
      const w = await world("scope-policy");
      const data = await bindCalldata(w);
      await (await send(w, await setPolicyCalldata(w, w.policies.allow))).wait();
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("QuorumNotMet");
      await (await bindDestination(w)).wait();
    });

    it("a binding signed in one safe state is refused in another: signed NORMAL, refused contained; signed contained, it binds", async function () {
      const w = await world("scope-state");
      const data = await bindCalldata(w);
      await (await send(w, await containmentCalldata(w))).wait();
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("QuorumNotMet");
      await (await bindDestination(w)).wait();
      expect(await w.vault.safeState()).to.equal(3n);
    });

    it("the deadline it signs is the signature's: past it the binding is refused, and it says nothing about how long the binding lasts (K-12-VETO)", async function () {
      const w = await world("scope-deadline");
      const nonce = await currentNonce(w, DOMAIN.MIGRATION);
      const params = await bindingParams(w, w.destination, w.destinationCodeHash, DESTINATION_GENERATION);
      const deadline = BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 60n;
      const generation = (await w.vault.guardianGeneration()) as bigint;
      const digest = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: GENERATION_2,
        actionType: ACTION.BIND_MIGRATION,
        authorityGeneration: generation,
        params,
        domain: DOMAIN.MIGRATION,
        nonce,
        deadline,
      });
      const data = w.vault.interface.encodeFunctionData("bindMigration", [
        [w.destination, w.destinationCodeHash, DESTINATION_GENERATION],
        quorum(w, digest),
        nonce,
        deadline,
        sign(w.credKey, digest),
      ]);
      await advanceTime(61);
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("Expired");
    });
  });

  describe("K-12-TIME: I-MIGRATION-SUBORDINATE-TO-RECOVERY. A migration takes at least as long as a recovery, for every coalition", function () {
    it("the two delays are the same constant, read from the kernel itself", async function () {
      const w = await world("t0");
      expect(await w.vault.BIND_DELAY()).to.equal(BigInt(BIND_DELAY_SECONDS));
      expect(await w.vault.RECOVERY_DELAY()).to.equal(BigInt(RECOVERY_DELAY_SECONDS));
      expect(await w.vault.BIND_DELAY()).to.be.greaterThanOrEqual(await w.vault.RECOVERY_DELAY());
    });

    for (const [label, ecdsaOnlyFloor] of [
      ["armed", false],
      ["dormant", true],
    ] as const) {
      it(`${label} floor: every holding is refused until exactly bind + 7 d, and leaves at that exact second, measured from the mined bind block`, async function () {
        const w = await deployGen2World({ label: "t-" + label, ecdsaOnlyFloor, fundEth: ethers.parseEther("1") });
        const boundAt = await minedAt(await bindDestination(w));
        expect(await refusal(w, () => egress(w, w.token)), "the very next block").to.equal("TooEarly");
        expect(await refusal(w, () => egress(w, ZERO)), "native too").to.equal("TooEarly");
        expect(await refusal(w, () => egress(w, w.otherToken)), "any holding").to.equal("TooEarly");
        await setNextTimestamp(boundAt + WEEK - 1);
        expect(await refusal(w, () => egress(w, w.token)), "one second early").to.equal("TooEarly");
        await setNextTimestamp(boundAt + WEEK);
        await (await egress(w, w.token)).wait();
        expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
      });
    }

    it("ARMED FLOOR, THE COALITION THE DEFECT CONCERNED: {k guardians, ECDSA, no PQ key} takes as long to migrate as to recover", async function () {
      const migrate = await deployGen2World({ label: "t-coal-m" });
      const boundAt = await minedAt(await bindDestination(migrate));
      await setNextTimestamp(boundAt + WEEK);
      const migrated = await minedAt(await egress(migrate, migrate.token));

      const recover = await deployGen2World({ label: "t-coal-r" });
      const newCred = keyOf("t-coal-cred");
      const newPq = keyOf("t-coal-pq");
      const proposedAt = await minedAt(
        await proposeRecovery(recover, addrOf(newCred), pqHash(newPq), recover.verifiers.honest),
      );
      const executable = (await recover.vault.recovery())[3] as bigint;
      await setNextTimestamp(Number(executable));
      const recovered = await minedAt(
        await send(recover, await executeRecoveryCalldata(recover, newCred, newPq, recover.verifiers.honest)),
      );
      expect(migrated - boundAt).to.be.greaterThanOrEqual(recovered - proposedAt);
    });

    it("OWNER-REVIEWABLE: the delay buys time and visibility only: during the window no principal can stop the egress", async function () {
      const w = await world("t-window");
      await (await bindDestination(w)).wait();
      // Everything a defender might reach for, each refused at the state gate.
      expect(
        await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS)),
        "containment",
      ).to.equal("BadState");
      expect(
        await refusal(w, async () =>
          send(
            w,
            await recoveryCalldata(w, addrOf(keyOf("t-window-new")), ethers.ZeroHash, w.verifiers.honest),
            undefined,
            PROBE_GAS,
          ),
        ),
        "a recovery",
      ).to.equal("BadState");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "the credential moving funds first",
      ).to.equal("BadState");
      expect(await refusal(w, async () => send(w, await bindCalldata(w), undefined, PROBE_GAS)), "a rebind").to.equal(
        "AlreadyBound",
      );
      await advanceTime(WEEK + 1);
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("retire waits for the same instant, and gates nothing: egress does not depend on it", async function () {
      const w = await world("t-retire");
      const boundAt = await minedAt(await bindDestination(w));
      expect(
        await refusal(w, () => w.vault.connect(w.outsider).getFunction("retire").send({ gasLimit: PROBE_GAS })),
      ).to.equal("TooEarly");
      await setNextTimestamp(boundAt + WEEK);
      await (await w.vault.connect(w.outsider).getFunction("retire")()).wait();
      expect(await w.vault.safeState()).to.equal(4n);
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });

  describe("K-13: permissionless, with no discretion", function () {
    async function open(label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> {
      const w = await world(label, more);
      await (await bindDestination(w)).wait();
      await advanceTime(WEEK + 1);
      return w;
    }

    it("a stranger's call moves the full balance to the binding's destination, whatever it appends to the calldata", async function () {
      const w = await open("k13");
      const hostile = addrOf(keyOf("k13-hostile"));
      const data =
        w.vault.interface.encodeFunctionData("egress", [w.token]) + hostile.slice(2).toLowerCase() + "deadbeef";
      await (await send(w, data, w.outsider)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
      expect(await assetBalance(w, hostile)).to.equal(0n);
    });

    it("I-EGRESS-INDEPENDENCE and I-MIGRATION-NONTRAP(a): hostile holdings fail alone and veto nothing", async function () {
      // A return bomb's first word decodes as a zero balance, so its egress moves nothing and claims nothing.
      for (const [hostility, expected] of [
        [1, "TransferFailed"],
        [2, null],
      ] as const) {
        const w = await open("k13-host-" + hostility, { fundEth: ethers.parseEther("1") });
        await (await w.other.mint(w.vaultAddress, UNIT)).wait();
        await (await w.other.setHostility(hostility)).wait();
        expect(await refusal(w, () => egress(w, w.otherToken)), "hostility " + hostility).to.equal(expected);
        expect(await w.other.realBalanceOf(w.vaultAddress), "either way the hostile holding stays").to.equal(UNIT);
        await (await egress(w, w.token)).wait();
        await (await egress(w, ZERO)).wait();
        expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
        expect(await ethers.provider.getBalance(w.destination)).to.equal(ethers.parseEther("1"));
      }
    });

    it("I-EGRESS-RETRY-PERPETUAL: it never closes, including from RETIRED, and a failed attempt costs nothing", async function () {
      const w = await open("k13-retry");
      await setMode(w, "REVERTS");
      expect(await refusal(w, () => egress(w, w.token))).to.equal("TransferFailed");
      await setMode(w, "VANILLA");
      await (await w.vault.connect(w.outsider).getFunction("retire")()).wait();
      await (await egress(w, w.token)).wait();
      await (await zoo(w).mint(w.vaultAddress, UNIT)).wait();
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT + UNIT);
      // Nothing to move still succeeds: a zero egress is not an error.
      await (await egress(w, w.token)).wait();
    });

    it("I-NO-FALSE-SETTLEMENT on the way out: a token that moves nothing, or fails its query, publishes no movement", async function () {
      for (const mode of [
        "RETURN_TRUE_NO_MOVE",
        "QUERY_REVERTS_AFTER_TRANSFER",
        "QUERY_SHORT_AFTER_TRANSFER",
        "RETURN_FALSE_NO_MOVE",
      ] as const) {
        const w = await open("k13-false-" + mode);
        await setMode(w, mode);
        expect(await refusal(w, () => egress(w, w.token)), mode).to.equal("TransferFailed");
        expect(await assetBalance(w, w.vaultAddress), mode).to.equal(DEFAULT_MINT);
      }
    });

    it("K-13-DEAD-BINDING: a hash the destination does not have is refused at binding, consuming nothing, so egress is never left waiting on it", async function () {
      const w = await world("k13-hash");
      expect(
        await refusal(w, () => bindDestination(w, { codeHash: ethers.id("not-the-code"), gasLimit: PROBE_GAS })),
      ).to.equal("DestinationMismatch");
      expect(await currentNonce(w, DOMAIN.MIGRATION)).to.equal(0n);
      expect((await w.vault.migration())[4]).to.equal(false);
      expect(await w.vault.safeState()).to.equal(0n);
    });

    describe("the check at execution stays, because code can still vanish in the transaction that created it", function () {
      let withoutRecheck: CompiledUnit;
      let withoutCodeCheck: CompiledUnit;

      // Compiled up front: execFileSync blocks the event loop, and doing that with an in-process EVM request in flight deadlocks.
      before(function () {
        const drop = (source: string, check: string, replacement: string): string => {
          if (source.split(check).length !== 2) throw new Error("stale anchor: " + check);
          return source.replace(check, replacement);
        };
        withoutRecheck = compileMutatedKernel((s) =>
          drop(s, "if (b.destinationVault.codehash != b.destinationVaultCodeHash) revert DestinationMismatch();", ""),
        );
        withoutCodeCheck = compileMutatedKernel((s) => drop(s, "destination.vault.code.length == 0 || ", ""));
      });

      it("MUTANT: with the no-code check removed, a funded empty address binds, and the deployment that follows it is refused for good", async function () {
        const w = await world("k13-funded-mutant", { implOverride: withoutCodeCheck });
        const helper = await deployUnit(gen2Unit("Gen2BindThenDestroy"), w.deployer);
        const salt = ethers.id("k13-funded-mutant");
        const destination = ethers.getCreate2Address(
          helper.address,
          salt,
          ethers.keccak256(gen2Unit("Gen2EphemeralDestination").bytecode),
        );
        await (await w.deployer.sendTransaction({ to: destination, value: 1n })).wait();
        await (
          await bindDestination(w, {
            destination,
            codeHash: ethers.keccak256(await ethers.provider.getCode(destination)),
          })
        ).wait();
        await (await helper.contract.redeploy(salt)).wait();
        await advanceTime(WEEK + 1);
        expect(await refusal(w, () => egress(w, w.token))).to.equal("DestinationMismatch");
        expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      });

      it("a destination that lost its code after binding is refused, and re-creating the same code at the same address restores the exit, where the creator can", async function () {
        const w = await world("k13-gone");
        const { helper, salt, destination } = await bindThenDestroy(w, "k13-gone");
        expect(await ethers.provider.getCode(destination), "EIP-6780 removed it").to.equal("0x");
        expect((await w.vault.migration())[4]).to.equal(true);
        await advanceTime(WEEK + 1);
        expect(await refusal(w, () => egress(w, w.token))).to.equal("DestinationMismatch");
        expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
        await (await helper.redeploy(salt)).wait();
        await (await egress(w, w.token)).wait();
        expect(await assetBalance(w, destination)).to.equal(DEFAULT_MINT);
      });

      it("MUTANT: with the re-check removed, the same sequence pays an address with no code at all, so the re-check is what refuses it", async function () {
        const w = await world("k13-gone-mutant", { implOverride: withoutRecheck });
        const { destination } = await bindThenDestroy(w, "k13-gone-mutant");
        await advanceTime(WEEK + 1);
        await (await egress(w, w.token)).wait();
        expect(await ethers.provider.getCode(destination)).to.equal("0x");
        expect(await assetBalance(w, destination)).to.equal(DEFAULT_MINT);
      });
    });

    it("OWNER DECISION OD-NONFUNGIBLE-EXIT: a holding with no transfer(address,uint256) is refused rather than moved: an ERC-721 cannot leave through this kernel", async function () {
      const w = await open("k13-nft");
      const nft = await deployUnit(gen2Unit("Gen2NonFungibleHolding"), w.deployer);
      await (await nft.contract.mintTo(w.vaultAddress)).wait();
      expect(await refusal(w, () => egress(w, nft.address))).to.equal("TransferFailed");
      expect(await nft.contract.balanceOf(w.vaultAddress)).to.equal(1n);
      // It vetoes nothing else.
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("a codeless address is not a holding: the query returns no data, and the strict read refuses it", async function () {
      const w = await open("k13-codeless");
      expect(await refusal(w, () => egress(w, addrOf(keyOf("k13-nobody"))))).to.equal("TransferFailed");
    });

    it("a token blocklisting the SOURCE stops its egress until lifted: a denial by the issuer, undone by the issuer", async function () {
      const w = await open("k13-source");
      await (await zoo(w).setBlocklisted(w.vaultAddress, true)).wait();
      expect(await refusal(w, () => egress(w, w.token))).to.equal("TransferFailed");
      await (await zoo(w).setBlocklisted(w.vaultAddress, false)).wait();
      await (await egress(w, w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });
});
