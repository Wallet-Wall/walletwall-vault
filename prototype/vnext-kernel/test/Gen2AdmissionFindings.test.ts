/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE FINDINGS OF THE ADMISSION LANE, MEASURED ON BOTH SIDES. Each test runs ONE adversarial sequence
 * against the kernel PR #237 measured (variant A), and where the code is shared against the
 * Generation-1 kernel, and then against the admission candidate. A finding asserted only on the fixed
 * kernel would prove nothing about whether the defect ever existed; a fix asserted only by reading the
 * diff would prove nothing about whether it closes the sequence.
 *
 * These are not regressions of the measured kernel: `erc20-spend-plane/` stays exactly as measured,
 * so the defect stays reproducible, permanently, beside the kernel that does not have it.
 */
import { expect } from "chai";

import { ethers } from "./connection.js";
import {
  DESTINATION_GENERATION as PLANE_DESTINATION_GENERATION,
  bindDestination as planeBind,
  currentNonce as planeNonce,
  deployErc20World,
  guardianDigest as planeGuardianDigest,
  proposeRecovery as planeProposeRecovery,
  quorum as planeQuorum,
  sendSpend as planeSpend,
  type Erc20World,
} from "./erc20-spend-plane-world.js";
import { deployWorld, migrationParams as gen1MigrationParams, type World } from "../stateful/world.js";
import {
  ACTION,
  BIND_DELAY_SECONDS,
  DEFAULT_MINT,
  DESTINATION_GENERATION,
  DOMAIN,
  FAR_DEADLINE,
  MODE,
  UNIT,
  ZERO,
  addrOf,
  advanceTime,
  assetBalance,
  bindCalldata,
  bindDestination,
  containmentCalldata,
  currentNonce,
  deployGen2World,
  deployUnit,
  digestOf,
  guardianDigest,
  keyOf,
  recoveryCalldata,
  refusal,
  rotateCalldata,
  send,
  sendSpend,
  setGuardiansCalldata,
  setMode,
  settles,
  sign,
  spendParams,
  zoo,
  type Gen2World,
  type ModeName,
} from "../generation-2/world.js";
import { gen2Unit } from "../generation-2/compile.js";

const PROBE_GAS = 600_000n;
const TEN_YEARS = 10 * 365 * 86400;
const WRONG_HASH = ethers.id("not the destination's code");

/** A measured-variant-A world whose admitted asset is the zoo token, so both arms face the same adversary. */
async function measuredWorld(
  label: string,
  mode?: ModeName,
  floor: "ecdsaOnly" | "hybrid" = "ecdsaOnly",
): Promise<{ w: Erc20World; token: ethers.Contract }> {
  const signers = await ethers.getSigners();
  const deployed = await deployUnit(gen2Unit("Gen2ZooToken"), signers[0]!);
  const w = await deployErc20World({ label, tokenAddress: deployed.address, mintToVault: 0n, floor });
  await (await deployed.contract.mint(w.vaultAddress, DEFAULT_MINT)).wait();
  if (mode !== undefined) await (await deployed.contract.setMode(MODE[mode])).wait();
  return { w, token: deployed.contract };
}

async function egressEventAmount(vault: ethers.Contract, receipt: ethers.TransactionReceipt): Promise<bigint> {
  for (const log of receipt.logs) {
    try {
      const parsed = vault.interface.parseLog(log);
      if (parsed?.name === "Egressed") return parsed.args[2] as bigint;
    } catch {
      /* a token's own log */
    }
  }
  throw new Error("no Egressed event");
}

/** A Generation-1 binding of the world's destination, fully authorised, naming whatever code hash it is told to. */
async function bindGen1(w: World, codeHash: string, destination: string = w.destination): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint;
  const guardianGeneration = (await w.vault.guardianGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: guardianGeneration,
    params: gen1MigrationParams(destination, codeHash, 2n),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.bindMigration(
      [destination, codeHash, 2n],
      {
        members: w.guardians,
        isContract: w.guardianIsContract,
        attestingIndices: [0, 1],
        attestations: [sign(w.gKeys[0]!, digest), sign(w.gKeys[1]!, digest)],
      },
      nonce,
      FAR_DEADLINE,
      sign(w.credKey, digest),
    )
  ).wait();
}

/** The calldata for a fully-authorised binding on measured Variant A, whatever it is told to name. */
async function measuredBindCalldata(
  w: Erc20World,
  codeHash: string,
  destination: string = w.destination,
): Promise<string> {
  const nonce = await planeNonce(w, DOMAIN.MIGRATION);
  const digest = await planeGuardianDigest(
    w,
    ACTION.BIND_MIGRATION,
    gen1MigrationParams(destination, codeHash, PLANE_DESTINATION_GENERATION),
    DOMAIN.MIGRATION,
    nonce,
  );
  return w.vault.interface.encodeFunctionData("bindMigration", [
    [destination, codeHash, PLANE_DESTINATION_GENERATION],
    planeQuorum(w, digest),
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, digest),
  ]);
}

async function bindMeasured(w: Erc20World, codeHash: string, destination: string = w.destination): Promise<void> {
  const data = await measuredBindCalldata(w, codeHash, destination);
  await (await w.deployer.sendTransaction({ to: w.vaultAddress, data })).wait();
}

/** A destination fixture of this tree, for the measured kernels, whose worlds bind a plain stub. */
async function switchableDestination(
  signer: ethers.Signer,
): Promise<{ contract: ethers.Contract; address: string; codeHash: string }> {
  const d = await deployUnit(gen2Unit("Gen2SwitchableDestination"), signer);
  return {
    contract: d.contract,
    address: d.address,
    codeHash: ethers.keccak256(await ethers.provider.getCode(d.address)),
  };
}

/** The Egressed amount in a receipt, or null. */
function published(vault: ethers.Contract, receipt: ethers.TransactionReceipt): bigint | null {
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== String(vault.target).toLowerCase()) continue;
    const parsed = vault.interface.parseLog(log);
    if (parsed?.name === "Egressed") return parsed.args[2] as bigint;
  }
  return null;
}

/**
 * A roster with one guardian contract in it, and a containment that needs that guardian's answer to reach quorum.
 * The measured kernel takes the same calls: the digest differs only in what the world names, and it has the same generation.
 */
async function containmentWithDirtyGuardian(w: Gen2World, label: string): Promise<string | null> {
  const dirty = await deployUnit(gen2Unit("Gen2DirtyMagicGuardian"), w.deployer);
  const eoas = [keyOf(label + "-a"), keyOf(label + "-b")];
  const seats = [dirty.address, addrOf(eoas[0]!), addrOf(eoas[1]!)].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  const isContract = seats.map((s) => s === dirty.address);
  await (await send(w, await setGuardiansCalldata(w, 2n, seats, isContract))).wait();
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const digest = await guardianDigest(w, ACTION.RECOVER, ethers.id("CONTAIN"), DOMAIN.GUARDIAN, nonce);
  const dirtyAt = isContract.indexOf(true);
  const eoaAt = seats.findIndex((s) => s === addrOf(eoas[0]!));
  const indices = [dirtyAt, eoaAt].sort((a, b) => a - b);
  const proof = {
    members: seats,
    isContract,
    attestingIndices: indices,
    attestations: indices.map((i) => (i === dirtyAt ? "0x" : sign(eoas[0]!, digest))),
  };
  return refusal(w, () =>
    send(
      w,
      w.vault.interface.encodeFunctionData("enterContainment", [proof, nonce, FAR_DEADLINE]),
      undefined,
      PROBE_GAS,
    ),
  );
}

describe("Generation-2 admission — findings, measured on the measured kernel and on the candidate", function () {
  this.timeout(180_000);

  describe("F-SETTLE: a failed balance query was read as an OBSERVED ZERO (I-NO-FALSE-SETTLEMENT, T1)", function () {
    for (const mode of ["QUERY_REVERTS_AFTER_TRANSFER", "QUERY_SHORT_AFTER_TRANSFER"] as const) {
      it(`MEASURED VARIANT A settles a full-balance spend that moved NOTHING (${mode}), with the nonce consumed`, async function () {
        const { w, token } = await measuredWorld("f-settle-a-" + mode, mode);
        await (await planeSpend(w, { to: w.recipient, amount: DEFAULT_MINT, gasLimit: PROBE_GAS })).wait();
        expect(await planeNonce(w, DOMAIN.SPEND), "the signature was spent").to.equal(1n);
        expect(await token.realBalanceOf(w.vaultAddress), "nothing left the vault").to.equal(DEFAULT_MINT);
        expect(await token.realBalanceOf(w.recipient), "nobody was paid").to.equal(0n);
      });

      it(`THE CANDIDATE refuses the same sequence (${mode}) and consumes nothing; a partial spend was refused on both`, async function () {
        const w = await deployGen2World({ label: "f-settle-c-" + mode, ecdsaOnlyFloor: true });
        await setMode(w, mode);
        expect(
          await refusal(w, () => sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT, gasLimit: PROBE_GAS })),
        ).to.equal("TransferFailed");
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
        expect(
          await refusal(w, () => sendSpend(w, { to: w.recipient, amount: 250n * UNIT, gasLimit: PROBE_GAS })),
        ).to.equal("TransferFailed");
        expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
        // POSITIVE CONTROL: the same world, the same full-balance spend, an honest token.
        await setMode(w, "VANILLA");
        await (await sendSpend(w, { to: w.recipient, amount: DEFAULT_MINT, gasLimit: PROBE_GAS })).wait();
        expect(await assetBalance(w, w.vaultAddress)).to.equal(0n);
        expect(await assetBalance(w, w.recipient)).to.equal(DEFAULT_MINT);
      });
    }

    it("MEASURED VARIANT A's egress PUBLISHES the whole balance as moved when nothing moved", async function () {
      const { w, token } = await measuredWorld("f-settle-eg-a", "QUERY_REVERTS_AFTER_TRANSFER");
      await (await planeBind(w)).wait();
      const receipt = await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress)).wait();
      expect(await egressEventAmount(w.vault, receipt)).to.equal(DEFAULT_MINT);
      expect(await token.realBalanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);
      expect(PLANE_DESTINATION_GENERATION).to.equal(DESTINATION_GENERATION);
    });

    it("GENERATION 1's egress carries the same read: the shared code publishes the same false movement (recorded, not changed)", async function () {
      const w = await deployWorld({ label: "f-settle-eg-g1" });
      const signers = await ethers.getSigners();
      const hostile = await deployUnit(gen2Unit("Gen2ZooToken"), signers[0]!);
      await (await hostile.contract.mint(w.vaultAddress, DEFAULT_MINT)).wait();
      await (await hostile.contract.setMode(MODE.QUERY_REVERTS_AFTER_TRANSFER)).wait();
      await bindGen1(w, w.destinationCodeHash);
      const receipt = await (await w.vault.egress(hostile.address)).wait();
      expect(await egressEventAmount(w.vault, receipt!)).to.equal(DEFAULT_MINT);
      expect(await hostile.contract.realBalanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("MEASURED VARIANT A and GENERATION 1 publish native value as moved because the call returned, with a destination that handed it straight back", async function () {
      const signers = await ethers.getSigners();
      const { w } = await measuredWorld("f-settle-native-a");
      await (await signers[0]!.sendTransaction({ to: w.vaultAddress, value: ethers.parseEther("1") })).wait();
      const bouncing = await switchableDestination(signers[0]!);
      await (await bouncing.contract.setMode(1)).wait();
      await bindMeasured(w, bouncing.codeHash, bouncing.address);
      const receipt = await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(ZERO)).wait();
      expect(published(w.vault, receipt), "published as moved").to.equal(ethers.parseEther("1"));
      expect(await ethers.provider.getBalance(w.vaultAddress), "and still there").to.equal(ethers.parseEther("1"));

      const g1 = await deployWorld({ label: "f-settle-native-g1" });
      const held = await ethers.provider.getBalance(g1.vaultAddress);
      await bindGen1(g1, bouncing.codeHash, bouncing.address);
      const r1 = await (await g1.vault.egress(ZERO)).wait();
      expect(published(g1.vault, r1!)).to.equal(held);
      expect(await ethers.provider.getBalance(g1.vaultAddress)).to.equal(held);
    });

    it("THE CANDIDATE refuses a native egress that lost nothing, publishes only what left when part comes back, and the holding leaves once the destination keeps it", async function () {
      const w = await deployGen2World({
        label: "f-settle-native-c",
        ecdsaOnlyFloor: true,
        fundEth: ethers.parseEther("1"),
      });
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      const asOutsider = w.vault.connect(w.outsider) as ethers.Contract;
      await (await w.destinationFixture.setMode(1)).wait();
      expect(await refusal(w, () => asOutsider.egress(ZERO, { gasLimit: PROBE_GAS })), "all of it came back").to.equal(
        "TransferFailed",
      );
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("1"));
      await (await w.destinationFixture.setMode(2)).wait();
      const half = await (await asOutsider.egress(ZERO)).wait();
      expect(published(w.vault, half), "half of it came back").to.equal(ethers.parseEther("0.5"));
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("0.5"));
      await (await w.destinationFixture.setMode(0)).wait();
      await (await asOutsider.egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(w.destination)).to.equal(ethers.parseEther("1"));
    });

    it("THE CANDIDATE's egress refuses it, and a read that fails BEFORE any call refuses too, confined to that one holding", async function () {
      const w = await deployGen2World({ label: "f-settle-eg-c", ecdsaOnlyFloor: true });
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      await setMode(w, "QUERY_REVERTS_AFTER_TRANSFER");
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("TransferFailed");
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      // Codeless address: its query "succeeds" with no data. Measured kernel: moved 0, success. Candidate: refused.
      const stranger = keyOf("f-settle-codeless");
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(addrOf(stranger), { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("TransferFailed");
      // POSITIVE CONTROL: an honest query, and the holding leaves in full.
      await setMode(w, "VANILLA");
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });

  describe("F-TIME: migration completed in the bind block (I-MIGRATION-SUBORDINATE-TO-RECOVERY, T0)", function () {
    /** The coalition the invariant is about on an ARMED floor: k guardians and the ECDSA key, and NOT the PQ key. */
    async function hybridSpendIsDeniedToCoalition(
      w: Erc20World | Gen2World,
      spend: () => Promise<{ wait: () => Promise<unknown> }>,
    ): Promise<void> {
      void w;
      expect(await settles(spend), "without the PQ factor the coalition cannot simply spend").to.equal(false);
    }

    it("MEASURED VARIANT A: {k guardians, ECDSA, no PQ key} drains an armed vault in ONE BLOCK AFTER binding, with no delay at all", async function () {
      const { w, token } = await measuredWorld("f-time-a", undefined, "hybrid");
      await hybridSpendIsDeniedToCoalition(w, () =>
        planeSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS }),
      );
      const bound = await (await planeBind(w)).wait();
      const boundAt = BigInt((await ethers.provider.getBlock(bound!.blockNumber))!.timestamp);
      const egressed = await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress)).wait();
      const movedAt = BigInt((await ethers.provider.getBlock(egressed!.blockNumber))!.timestamp);
      expect(await token.realBalanceOf(w.destination)).to.equal(DEFAULT_MINT);
      expect(movedAt - boundAt, "the whole balance left within seconds of the binding").to.be.lessThan(60n);
      // retire() is what BIND_DELAY actually gates, and it gates nothing the binding had not already opened.
      expect(
        await settles(() => (w.vault.connect(w.outsider) as ethers.Contract).retire({ gasLimit: PROBE_GAS })),
      ).to.equal(false);
    });

    it("GENERATION 1 does the same with native value: the shape is inherited, not introduced by the plane", async function () {
      const w = await deployWorld({ label: "f-time-g1" });
      await bindGen1(w, w.destinationCodeHash);
      const before = await ethers.provider.getBalance(w.destination);
      await (await w.vault.egress(ZERO)).wait();
      expect((await ethers.provider.getBalance(w.destination)) - before).to.equal(ethers.parseEther("10"));
    });

    it("THE CANDIDATE: refused one second before boundAt + BIND_DELAY, settled at that instant, and the delay equals the recovery delay", async function () {
      const w = await deployGen2World({ label: "f-time-c" });
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "PQ factor still mandatory",
      ).to.equal("BadSignature");
      const bound = await (await bindDestination(w)).wait();
      const boundAt = (await ethers.provider.getBlock(bound!.blockNumber))!.timestamp;
      expect(await w.vault.BIND_DELAY()).to.equal(await w.vault.RECOVERY_DELAY());
      const asOutsider = w.vault.connect(w.outsider) as ethers.Contract;
      await ethers.provider.send("evm_setNextBlockTimestamp", [boundAt + BIND_DELAY_SECONDS - 1]);
      expect(await refusal(w, () => asOutsider.egress(w.token, { gasLimit: PROBE_GAS })), "one second early").to.equal(
        "TooEarly",
      );
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      // The instant the delay ends: permissionless, no further authority, full balance, bound recipient.
      await ethers.provider.send("evm_setNextBlockTimestamp", [boundAt + BIND_DELAY_SECONDS]);
      await (await asOutsider.egress(w.token, { gasLimit: PROBE_GAS })).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("THE CANDIDATE, on an ECDSA-only floor: the delay costs the honest migration time and removes nothing, since the credential already spends", async function () {
      const w = await deployGen2World({ label: "f-time-floor", ecdsaOnlyFloor: true });
      await (await sendSpend(w, { to: w.recipient, amount: UNIT })).wait();
      await (await bindDestination(w)).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "spending stops at the binding",
      ).to.equal("BadState");
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token, { gasLimit: PROBE_GAS }),
        ),
        "egress waits",
      ).to.equal("TooEarly");
      await advanceTime(BIND_DELAY_SECONDS);
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT - UNIT);
    });
  });

  describe("F-DEAD-BINDING: a binding egress could never honour was accepted, and then nothing could undo it (I-MIGRATION-NONTRAP, T0)", function () {
    it("MEASURED VARIANT A: one wrong hash signed at k+1 and the vault is shut for good: egress, spending, a recovery and a rebind all refused, ten years on", async function () {
      const { w, token } = await measuredWorld("f-dead-a");
      await bindMeasured(w, WRONG_HASH);
      await advanceTime(TEN_YEARS);
      expect(
        await settles(() =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress, { gasLimit: PROBE_GAS }),
        ),
        "egress",
      ).to.equal(false);
      expect(
        await settles(() => planeSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "spending",
      ).to.equal(false);
      expect(
        await settles(() =>
          planeProposeRecovery(w, addrOf(keyOf("f-dead-a-new")), ethers.ZeroHash, w.verifierAddress, PROBE_GAS),
        ),
        "a recovery",
      ).to.equal(false);
      expect(await settles(() => planeBind(w)), "a rebind to the right hash").to.equal(false);
      expect(await token.realBalanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("GENERATION 1: the same shape on native value (recorded, not changed): the check 13.5 presumes was never at binding on either", async function () {
      const w = await deployWorld({ label: "f-dead-g1" });
      await bindGen1(w, WRONG_HASH);
      await advanceTime(TEN_YEARS);
      const held = await ethers.provider.getBalance(w.vaultAddress);
      expect(held).to.be.greaterThan(0n);
      expect(await settles(() => w.vault.egress(ZERO, { gasLimit: PROBE_GAS }))).to.equal(false);
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(held);
    });

    it("THE CANDIDATE refuses it at binding: nothing consumed, nothing flipped, the vault still spends, and the right binding then works", async function () {
      const w = await deployGen2World({ label: "f-dead-c", ecdsaOnlyFloor: true });
      expect(await refusal(w, () => bindDestination(w, { codeHash: WRONG_HASH, gasLimit: PROBE_GAS }))).to.equal(
        "DestinationMismatch",
      );
      expect(await currentNonce(w, DOMAIN.MIGRATION)).to.equal(0n);
      expect((await w.vault.migration())[4]).to.equal(false);
      expect(await w.vault.safeState()).to.equal(0n);
      await (await sendSpend(w, { to: w.recipient, amount: UNIT })).wait();
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT - UNIT);
    });
  });

  describe("F-DEAD-BINDING, the two other roads to the same place", function () {
    it("MEASURED VARIANT A: a vault bound to itself passes the hash, and its balance can never fall: egress refused and spending refused for good", async function () {
      const { w, token } = await measuredWorld("f-self-a");
      await bindMeasured(w, ethers.keccak256(await ethers.provider.getCode(w.vaultAddress)), w.vaultAddress);
      await advanceTime(TEN_YEARS);
      expect(
        await settles(() =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(false);
      expect(await settles(() => planeSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS }))).to.equal(
        false,
      );
      expect(await token.realBalanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("MEASURED VARIANT A: an empty address anyone funded has a hash to name; bind to it, deploy to it, and that hash is gone for good", async function () {
      const signers = await ethers.getSigners();
      const { w, token } = await measuredWorld("f-funded-a");
      const helper = await deployUnit(gen2Unit("Gen2BindThenDestroy"), signers[0]!);
      const salt = ethers.id("f-funded-a");
      const destination = ethers.getCreate2Address(
        helper.address,
        salt,
        ethers.keccak256(gen2Unit("Gen2EphemeralDestination").bytecode),
      );
      await (await signers[0]!.sendTransaction({ to: destination, value: 1n })).wait();
      await bindMeasured(w, ethers.keccak256(await ethers.provider.getCode(destination)), destination);
      await (await helper.contract.redeploy(salt)).wait();
      await advanceTime(TEN_YEARS);
      expect(
        await settles(() =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.tokenAddress, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(false);
      expect(await settles(() => planeSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS }))).to.equal(
        false,
      );
      expect(await token.realBalanceOf(w.vaultAddress)).to.equal(DEFAULT_MINT);
    });

    it("THE CANDIDATE refuses both at binding, consuming nothing and flipping nothing, and an address with no code at all", async function () {
      const w = await deployGen2World({ label: "f-roads-c", ecdsaOnlyFloor: true });
      const selfHash = ethers.keccak256(await ethers.provider.getCode(w.vaultAddress));
      expect(
        await refusal(w, () =>
          bindDestination(w, { destination: w.vaultAddress, codeHash: selfHash, gasLimit: PROBE_GAS }),
        ),
        "the vault itself",
      ).to.equal("DestinationMismatch");
      const funded = addrOf(keyOf("f-roads-funded"));
      await (await w.deployer.sendTransaction({ to: funded, value: 1n })).wait();
      const emptyHash = ethers.keccak256(await ethers.provider.getCode(funded));
      expect(
        await refusal(w, () => bindDestination(w, { destination: funded, codeHash: emptyHash, gasLimit: PROBE_GAS })),
        "funded, no code",
      ).to.equal("DestinationMismatch");
      const empty = addrOf(keyOf("f-roads-empty"));
      expect(
        await refusal(w, () => bindDestination(w, { destination: empty, codeHash: emptyHash, gasLimit: PROBE_GAS })),
        "nothing there at all",
      ).to.equal("DestinationMismatch");
      expect(await currentNonce(w, DOMAIN.MIGRATION)).to.equal(0n);
      expect(await w.vault.safeState()).to.equal(0n);
      await (await sendSpend(w, { to: w.recipient, amount: UNIT })).wait();
    });
  });

  describe("F-BINDING-SCOPE: a binding's signatures outlived what they were given under (H-10, I-GENERATION-MONOTONE)", function () {
    it("MEASURED VARIANT A: signed, then the credential rotates away and back, and the plane changes: the old signatures still bind", async function () {
      const { w } = await measuredWorld("f-scope-a");
      const asWorld = w as unknown as Gen2World;
      const data = await measuredBindCalldata(w, w.destinationCodeHash);
      const away = keyOf("f-scope-a-away");
      await (await send(asWorld, await rotateCalldata(asWorld, away, null))).wait();
      await (await send(asWorld, await rotateCalldata(asWorld, w.credKey, null, { credential: away }))).wait();
      expect(await w.vault.credentialGeneration()).to.equal(3n);
      await (await w.deployer.sendTransaction({ to: w.vaultAddress, data })).wait();
      expect((await w.vault.migration())[4], "a credential leg from two generations ago").to.equal(true);
    });

    it("THE CANDIDATE: the same sequence is refused, and a binding signed at the live generation succeeds", async function () {
      const w = await deployGen2World({ label: "f-scope-c", ecdsaOnlyFloor: true });
      const data = await bindCalldata(w);
      const away = keyOf("f-scope-c-away");
      await (await send(w, await rotateCalldata(w, away, null))).wait();
      await (await send(w, await rotateCalldata(w, w.credKey, null, { credential: away }))).wait();
      expect(await w.vault.credentialGeneration()).to.equal(3n);
      expect(await refusal(w, () => send(w, data, undefined, PROBE_GAS))).to.equal("QuorumNotMet");
      await (await bindDestination(w)).wait();
      expect((await w.vault.migration())[4]).to.equal(true);
    });
  });

  describe("F-ATTESTATION: an ERC-1271 answer counted on its first four bytes (I-ATTESTATION-IS-AFFIRMATIVE, T1)", function () {
    it("MEASURED VARIANT A: magic in the first four bytes and something else in the word reaches quorum", async function () {
      const { w } = await measuredWorld("f-attest-a");
      expect(await containmentWithDirtyGuardian(w as unknown as Gen2World, "f-attest-a")).to.equal(null);
      expect(await w.vault.effectiveSafeState()).to.equal(1n);
    });

    it("THE CANDIDATE counts no such answer: the word must be the magic value", async function () {
      const w = await deployGen2World({ label: "f-attest-c", ecdsaOnlyFloor: true });
      expect(await containmentWithDirtyGuardian(w, "f-attest-c")).to.equal("QuorumNotMet");
      expect(await w.vault.effectiveSafeState()).to.equal(0n);
    });
  });

  describe("F-VETO: a binding never lifts (I-VETO-BOUND, T0). NOT CLOSED BY THIS LANE: owner decision OD-BINDING-LIFETIME", function () {
    it("THE CANDIDATE: the destination frozen, ten years pass and the vault is still MIGRATION_ONLY: nothing lifts it with no principal acting, and no principal can", async function () {
      const w = await deployGen2World({ label: "f-veto-c", ecdsaOnlyFloor: true });
      await (await bindDestination(w)).wait();
      await (await zoo(w).setBlocklisted(w.destination, true)).wait();
      await advanceTime(TEN_YEARS);
      expect(await w.vault.safeState(), "MIGRATION_ONLY, with no deadline to read").to.equal(3n);
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token, { gasLimit: PROBE_GAS }),
        ),
        "egress",
      ).to.equal("TransferFailed");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "spending",
      ).to.equal("BadState");
      expect(
        await refusal(w, async () => send(w, await rotateCalldata(w, keyOf("f-veto-new"), null), undefined, PROBE_GAS)),
        "a rotation",
      ).to.equal("BadState");
      expect(
        await refusal(w, async () =>
          send(
            w,
            await recoveryCalldata(w, addrOf(keyOf("f-veto-new")), ethers.ZeroHash, w.verifiers.honest),
            undefined,
            PROBE_GAS,
          ),
        ),
        "a recovery",
      ).to.equal("BadState");
      expect(
        await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS)),
        "containment",
      ).to.equal("BadState");
      expect(await refusal(w, () => bindDestination(w, { gasLimit: PROBE_GAS })), "a rebind").to.equal("AlreadyBound");
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      // The only act that helps is the issuer's. That is a denial with no bound, which is what the invariant forbids.
      await (await zoo(w).setBlocklisted(w.destination, false)).wait();
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("MEASURED VARIANT A and GENERATION 1 carry the same shape: the admission deltas neither introduced this nor closed it", async function () {
      const { w, token } = await measuredWorld("f-veto-a");
      await bindMeasured(w, w.destinationCodeHash);
      await (await token.setBlocklisted(w.destination, true)).wait();
      await advanceTime(TEN_YEARS);
      expect(await w.vault.safeState()).to.equal(3n);
      expect(await settles(() => planeSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS }))).to.equal(
        false,
      );
      expect(
        await settles(() =>
          planeProposeRecovery(w, addrOf(keyOf("f-veto-a-new")), ethers.ZeroHash, w.verifierAddress, PROBE_GAS),
        ),
      ).to.equal(false);

      const g1 = await deployWorld({ label: "f-veto-g1" });
      await bindGen1(g1, g1.destinationCodeHash);
      await advanceTime(TEN_YEARS);
      expect(await g1.vault.safeState()).to.equal(3n);
      const nonce = (await g1.vault.nonces(DOMAIN.SPEND)) as bigint;
      const digest = digestOf({
        chainId: g1.chainId,
        vault: g1.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.SPEND,
        authorityGeneration: (await g1.vault.credentialGeneration()) as bigint,
        params: spendParams(g1.recipient, 1n),
        domain: DOMAIN.SPEND,
        nonce,
        deadline: FAR_DEADLINE,
      });
      const spend = g1.vault.interface.encodeFunctionData("execute", [
        g1.recipient,
        1n,
        nonce,
        FAR_DEADLINE,
        sign(g1.credKey, digest),
        "0x",
        "0x",
      ]);
      expect(
        await settles(() => g1.deployer.sendTransaction({ to: g1.vaultAddress, data: spend, gasLimit: PROBE_GAS })),
        "nothing lifted, so spending is still refused",
      ).to.equal(false);
    });

    it("A destination that refuses native value keeps that holding in the vault with no bound on the wait, and the admitted asset still leaves", async function () {
      const w = await deployGen2World({
        label: "f-veto-refuse",
        ecdsaOnlyFloor: true,
        fundEth: ethers.parseEther("1"),
      });
      await (await bindDestination(w)).wait();
      await (await w.destinationFixture.setMode(3)).wait();
      await advanceTime(TEN_YEARS);
      const asOutsider = w.vault.connect(w.outsider) as ethers.Contract;
      expect(await refusal(w, () => asOutsider.egress(ZERO, { gasLimit: PROBE_GAS }))).to.equal("TransferFailed");
      expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(ethers.parseEther("1"));
      await (await asOutsider.egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("WHAT THE DELAY COST: a wrapper on measured Variant A binds and egresses atomically, so a block already on the destination reverts both and traps nothing; on the candidate that is impossible", async function () {
      const signers = await ethers.getSigners();
      const migrator = await deployUnit(gen2Unit("Gen2AtomicMigrator"), signers[0]!);

      const { w: measured, token } = await measuredWorld("f-cost-a");
      const nonce = await planeNonce(measured, DOMAIN.MIGRATION);
      const digest = await planeGuardianDigest(
        measured,
        ACTION.BIND_MIGRATION,
        gen1MigrationParams(measured.destination, measured.destinationCodeHash, PLANE_DESTINATION_GENERATION),
        DOMAIN.MIGRATION,
        nonce,
      );
      const bindData = measured.vault.interface.encodeFunctionData("bindMigration", [
        [measured.destination, measured.destinationCodeHash, PLANE_DESTINATION_GENERATION],
        planeQuorum(measured, digest),
        nonce,
        FAR_DEADLINE,
        sign(measured.credKey, digest),
      ]);
      const egressData = measured.vault.interface.encodeFunctionData("egress", [measured.tokenAddress]);
      await (await token.setBlocklisted(measured.destination, true)).wait();
      expect(
        await settles(() =>
          migrator.contract.run(measured.vaultAddress, bindData, egressData, { gasLimit: 2_000_000n }),
        ),
        "a blocked destination reverts both",
      ).to.equal(false);
      expect(await measured.vault.safeState(), "and the vault is exactly where it was").to.equal(0n);
      await (await token.setBlocklisted(measured.destination, false)).wait();
      await (await migrator.contract.run(measured.vaultAddress, bindData, egressData)).wait();
      expect(await token.realBalanceOf(measured.destination)).to.equal(DEFAULT_MINT);

      const w = await deployGen2World({ label: "f-cost-c", ecdsaOnlyFloor: true });
      const candidateEgress = w.vault.interface.encodeFunctionData("egress", [w.token]);
      expect(
        await refusal(w, async () =>
          migrator.contract.run(w.vaultAddress, await bindCalldata(w), candidateEgress, { gasLimit: 2_000_000n }),
        ),
        "the delay refuses the second half, so a binding is always exposed for seven days",
      ).to.equal("TooEarly");
    });
  });

  describe("F-NONFUNGIBLE: a holding with no transfer(address,uint256) cannot leave (I-MIGRATION-NONTRAP, T0). NOT CLOSED BY THIS LANE: owner decision OD-NONFUNGIBLE-EXIT", function () {
    it("MEASURED VARIANT A, GENERATION 1 and THE CANDIDATE alike: its egress is refused, it stays where it is, and it vetoes nothing else", async function () {
      const signers = await ethers.getSigners();
      const nft = await deployUnit(gen2Unit("Gen2NonFungibleHolding"), signers[0]!);

      const { w: measured, token } = await measuredWorld("f-nft-a");
      await (await nft.contract.mintTo(measured.vaultAddress)).wait();
      await bindMeasured(measured, measured.destinationCodeHash);
      expect(
        await settles(() =>
          (measured.vault.connect(measured.outsider) as ethers.Contract).egress(nft.address, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal(false);
      expect(await nft.contract.balanceOf(measured.vaultAddress)).to.equal(1n);
      await (await (measured.vault.connect(measured.outsider) as ethers.Contract).egress(measured.tokenAddress)).wait();
      expect(await token.realBalanceOf(measured.destination)).to.equal(DEFAULT_MINT);

      const g1 = await deployWorld({ label: "f-nft-g1" });
      await (await nft.contract.mintTo(g1.vaultAddress)).wait();
      await bindGen1(g1, g1.destinationCodeHash);
      expect(await settles(() => g1.vault.egress(nft.address, { gasLimit: PROBE_GAS }))).to.equal(false);
      expect(await nft.contract.balanceOf(g1.vaultAddress)).to.equal(1n);

      const w = await deployGen2World({ label: "f-nft-c", ecdsaOnlyFloor: true });
      await (await nft.contract.mintTo(w.vaultAddress)).wait();
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(nft.address, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("TransferFailed");
      expect(await nft.contract.balanceOf(w.vaultAddress)).to.equal(1n);
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });

  describe("F-FREEZE: the issuer blocklists the BOUND DESTINATION. Architecture 13.0 names this as the trap and 13.4 keeps only the SOURCE case, so it is row K-13, owner decision OD-BINDING-LIFETIME", function () {
    it("MEASURED VARIANT A and THE CANDIDATE alike: egress refused, spending refused, no rebind; lifting the blocklist restores egress", async function () {
      const { w: measured, token } = await measuredWorld("f-freeze-a");
      await (await planeBind(measured)).wait();
      await (await token.setBlocklisted(measured.destination, true)).wait();
      expect(
        await settles(() =>
          (measured.vault.connect(measured.outsider) as ethers.Contract).egress(measured.tokenAddress, {
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal(false);
      expect(
        await settles(() => planeSpend(measured, { to: measured.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
      ).to.equal(false);

      const w = await deployGen2World({ label: "f-freeze-c", ecdsaOnlyFloor: true });
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      await (await zoo(w).setBlocklisted(w.destination, true)).wait();
      const asOutsider = w.vault.connect(w.outsider) as ethers.Contract;
      expect(
        await refusal(w, () => asOutsider.egress(w.token, { gasLimit: PROBE_GAS })),
        "the asset cannot reach the destination",
      ).to.equal("TransferFailed");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS })),
        "MIGRATION_ONLY refuses spending",
      ).to.equal("BadState");
      expect(await refusal(w, () => bindDestination(w, { gasLimit: PROBE_GAS })), "the binding is one-shot").to.equal(
        "AlreadyBound",
      );
      // It is a DENIAL held by the issuer, never a loss, and no other holding is touched by it.
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
      await (await zoo(w).setBlocklisted(w.destination, false)).wait();
      await (await asOutsider.egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });

    it("the issuer blocklisting the SOURCE (the clone itself) is the case the architecture already declares: spend and egress both refuse until lifted", async function () {
      const w = await deployGen2World({ label: "f-freeze-src", ecdsaOnlyFloor: true });
      await (await zoo(w).setBlocklisted(w.vaultAddress, true)).wait();
      expect(await refusal(w, () => sendSpend(w, { to: w.recipient, amount: UNIT, gasLimit: PROBE_GAS }))).to.equal(
        "TransferFailed",
      );
      expect(await currentNonce(w, DOMAIN.SPEND), "a refusal consumes nothing").to.equal(0n);
      await (await bindDestination(w)).wait();
      await advanceTime(BIND_DELAY_SECONDS);
      expect(
        await refusal(w, () =>
          (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("TransferFailed");
      await (await zoo(w).setBlocklisted(w.vaultAddress, false)).wait();
      await (await (w.vault.connect(w.outsider) as ethers.Contract).egress(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });
});
