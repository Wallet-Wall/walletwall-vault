/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE DEFECT LEDGER, CARRIED. Row DEFECT-CARRY. Generation 2 does not erase what stateful/defects.ts records,
 * so each open entry is re-executed on the candidate and its answer is pinned, not asserted in prose:
 *
 *     SD-4    sustained   PRESERVED. Not worsened. Not reachable through an ERC-20 path except as a carrier
 *                         for the same credential signature. Its exit still works, and now ends in a spend.
 *     SD-8    sustained   PRESERVED. Not worsened: the asset stays reachable by recovery and by migration.
 *     SD-11A  conditional PRESERVED remediation under the same condition: the factory must bind the real root.
 *     SD-11B  conditional PRESERVED remediation under the same condition.
 *
 * Nothing in this ledger is accidentally fixed. What THIS lane found is in test/Gen2AdmissionFindings.test.ts,
 * each on the kernels it applies to: some fixed on the candidate and open on Generation 1, some open on all of them.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";
import { GEN2_KERNEL, GEN2_VERIFIER_CLASS, gen2Unit } from "../generation-2/compile.js";
import { REMEDIATED_DEFECTS, SUSTAINED_DEFECTS } from "../stateful/defects.js";
import {
  ECDSA_ONLY_FLOOR,
  DEFAULT_MINT,
  HONEST_FLOOR,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  addrOf,
  advanceTime,
  assetBalance,
  bindDestination,
  cancelByQuorumCalldata,
  deployGen2World,
  deployUnit,
  executeRecoveryCalldata,
  keyOf,
  pqHash,
  pqKeyBytes,
  pqLegOf,
  proposeRecovery,
  recoveryCalldata,
  refusal,
  send,
  sendArmedSpend,
  sendSpend,
  setVerifierCalldata,
  sign,
  spendDigest,
  zoo,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 1_500_000n;
const AMOUNT = 250n * UNIT;

async function declareArmed(w: Gen2World): Promise<string> {
  return setVerifierCalldata(
    w,
    w.verifiers.honest,
    { ...HONEST_FLOOR },
    { pq: { sig: "0x", key: pqKeyBytes(w.pqKey) } },
  );
}

async function noPqExecution(w: Gen2World, newCred: ethers.SigningKey): Promise<string> {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  return w.vault.interface.encodeFunctionData("executeRecovery", [
    {
      newSigner: addrOf(newCred),
      newPqKeyHash: ethers.ZeroHash,
      newPqKey: "0x",
      newEcdsaPop: sign(newCred, pop),
      newPqPop: "0x",
    },
  ]);
}

describe("Generation-2 admission — the defect ledger, carried", function () {
  this.timeout(180_000);

  it("the ledger this suite answers is the ledger: two sustained, and SD-11A and SD-11B conditional", function () {
    expect(SUSTAINED_DEFECTS.map((d) => d.id.split("-").slice(0, 2).join("-")).sort()).to.deep.equal(["SD-4", "SD-8"]);
    const conditional = REMEDIATED_DEFECTS.filter((d) => d.condition !== undefined).map((d) =>
      d.id.split("-").slice(0, 2).join("-"),
    );
    expect(conditional.sort()).to.deep.equal(["SD-11A", "SD-11B"]);
  });

  describe("SD-4: the ECDSA-only declaration destroys an approved recovery at cut 1", function () {
    async function approvedOnDormant(label: string): Promise<{ w: Gen2World; newCred: ethers.SigningKey }> {
      const w = await deployGen2World({ label, ecdsaOnlyFloor: true, commitPqKey: true });
      const newCred = keyOf(label + "-cred");
      await (await proposeRecovery(w, addrOf(newCred), ethers.ZeroHash, w.verifiers.honest)).wait();
      return { w, newCred };
    }

    it("PRESERVED: the declaration is still admitted with a live approved request, no challenge is consumed, and the request can no longer execute", async function () {
      const { w, newCred } = await approvedOnDormant("sd4");
      await (await send(w, await declareArmed(w))).wait();
      expect((await w.vault.securityFloor())[0]).to.equal(true);
      const r = await w.vault.recovery();
      expect(r[6], "uncounted").to.equal(0n);
      expect(r[7], "stranded active").to.equal(true);
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      expect(await refusal(w, async () => send(w, await noPqExecution(w, newCred), undefined, PROBE_GAS))).to.equal(
        "BadSignature",
      );
    });

    it("POSITIVE CONTROL: without the declaration the same request executes", async function () {
      const { w, newCred } = await approvedOnDormant("sd4-ctl");
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await noPqExecution(w, newCred))).wait();
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    });

    it("NOT WORSENED: the architecture-native exit still repairs it, quorum cancel then a correctly-shaped recovery, and the new credential spends the ERC-20", async function () {
      const { w } = await approvedOnDormant("sd4-exit");
      await (await send(w, await declareArmed(w))).wait();
      await (await send(w, await cancelByQuorumCalldata(w))).wait();
      const newCred = keyOf("sd4-exit-cred2");
      const newPq = keyOf("sd4-exit-pq2");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("NOT REACHABLE THROUGH THE ASSET: a token can carry the credential's signed declaration from a hook, and cannot make one", async function () {
      const carried = await approvedOnDormant("sd4-hook");
      await (await zoo(carried.w).armHook(carried.w.vaultAddress, await declareArmed(carried.w), true)).wait();
      await (await sendSpend(carried.w, { to: carried.w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
      expect(await zoo(carried.w).hookSucceeded(), "the same authority, carried").to.equal(true);
      expect((await carried.w.vault.securityFloor())[0]).to.equal(true);

      const forged = await approvedOnDormant("sd4-forged");
      const stranger = await setVerifierCalldata(
        forged.w,
        forged.w.verifiers.honest,
        { ...HONEST_FLOOR },
        { credential: keyOf("sd4-stranger"), pq: { sig: "0x", key: pqKeyBytes(forged.w.pqKey) } },
      );
      await (await zoo(forged.w).armHook(forged.w.vaultAddress, stranger, true)).wait();
      await (await sendSpend(forged.w, { to: forged.w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })).wait();
      expect(await zoo(forged.w).hookSucceeded(), "with no signature it is refused inside").to.equal(false);
      expect((await forged.w.vault.securityFloor())[0]).to.equal(false);
    });

    it("the campaign still sees it: generation-2/test/Gen2StatefulCampaign.test.ts requires G-DECLARATION-SUBORDINATE-TO-RECOVERY to keep firing", function () {
      const sd4 = SUSTAINED_DEFECTS.find((d) => d.id.startsWith("SD-4"))!;
      expect(sd4.property).to.equal("G-DECLARATION-SUBORDINATE-TO-RECOVERY");
    });
  });

  describe("SD-8: an exhibited preimage proves no key is well-formed", function () {
    async function badKeyVault(label: string): Promise<{ w: Gen2World; vault: ethers.Contract; address: string }> {
      const w = await deployGen2World({ label, authority: "root", ecdsaOnlyFloor: true });
      const genesis = { ...w.genesis, pqKeyHash: ethers.keccak256("0x"), floor: { ...HONEST_FLOOR } };
      const address = (await w.factory.predictVault(w.salt, genesis)) as string;
      await (await w.factory.deployVault(w.salt, genesis, "0x")).wait();
      await (await zoo(w).mint(address, DEFAULT_MINT)).wait();
      return {
        w,
        vault: new ethers.Contract(address, gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi, w.deployer),
        address,
      };
    }

    it("PRESERVED: a deliberately empty key commits, arms and then refuses every spend: a self-inflicted, cut-0 outcome", async function () {
      const { w, vault, address } = await badKeyVault("sd8");
      expect(await vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0x"));
      expect((await vault.securityFloor())[0]).to.equal(true);
      const asThis = { ...w, vault, vaultAddress: address } as Gen2World;
      // An honest attestor signs nothing for an empty key, so the statement offered is nobody's; the ECDSA factor is real.
      const digest = spendDigest(asThis, { to: w.recipient, amount: AMOUNT, nonce: 0n });
      const nobody = pqLegOf(
        { ...w, attestors: { [w.verifiers.honest.toLowerCase()]: keyOf("sd8-not-the-attestor") } },
        digest,
        w.verifiers.honest,
        w.pqKey,
      );
      expect(
        await refusal(w, () =>
          sendSpend(asThis, {
            to: w.recipient,
            amount: AMOUNT,
            pq: { sig: nobody.sig, key: "0x" },
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("VerifierDenied");
      expect(
        await refusal(w, () =>
          sendSpend(asThis, { to: w.recipient, amount: AMOUNT, pq: { sig: "0x", key: "0x" }, gasLimit: PROBE_GAS }),
        ),
        "no statement at all",
      ).to.equal("VerifierDenied");
      expect(await assetBalance(w, address), "no asset moved").to.equal(DEFAULT_MINT);
    });

    it("NOT WORSENED, AND THE ASSET IS NOT TRAPPED: the guardian recovery installs real material, and a binding needs no PQ leg at all", async function () {
      const { w, vault, address } = await badKeyVault("sd8-exit");
      expect(await vault.admittedAsset()).to.equal(w.token);
      const asThis = { ...w, vault, vaultAddress: address } as Gen2World;
      const newCred = keyOf("sd8-exit-cred");
      const newPq = keyOf("sd8-exit-pq");
      const verifier = w.verifiers.honest;
      await (await send(asThis, await recoveryCalldata(asThis, addrOf(newCred), pqHash(newPq), verifier))).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(asThis, await executeRecoveryCalldata(asThis, newCred, newPq, verifier))).wait();
      await (await sendArmedSpend(asThis, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the migration exit from the same dead state", async function () {
      const { w, vault, address } = await badKeyVault("sd8-mig");
      const asThis = { ...w, vault, vaultAddress: address } as Gen2World;
      await (await bindDestination(asThis)).wait();
      await advanceTime(7 * 86400 + 1);
      await (await (vault.connect(w.outsider) as ethers.Contract).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
    });
  });

  describe("SD-11A and SD-11B: the verifier-admission remediation, under its stated condition", function () {
    it("PRESERVED UNDER THE REAL ROOT: an arbitrary verifier and a byte-identical copy outside the root are refused at setVerifier and at recovery", async function () {
      const w = await deployGen2World({ label: "sd11", authority: "root", ecdsaOnlyFloor: true });
      const attestor = addrOf(w.attestors[w.verifiers.honest.toLowerCase()]!);
      const copy = await deployUnit(gen2Unit(GEN2_VERIFIER_CLASS), w.deployer, attestor);
      for (const hostile of [w.verifiers.alwaysTrue, w.verifiers.alwaysFalse, copy.address]) {
        expect(
          await refusal(w, async () =>
            send(w, await setVerifierCalldata(w, hostile, { ...ECDSA_ONLY_FLOOR }), undefined, PROBE_GAS),
          ),
        ).to.equal("InadmissibleVerifier");
        expect(
          await refusal(w, async () =>
            send(
              w,
              await recoveryCalldata(w, addrOf(keyOf("sd11-new")), ethers.ZeroHash, hostile),
              undefined,
              PROBE_GAS,
            ),
          ),
        ).to.equal("InadmissibleVerifier");
      }
    });

    it("THE CONDITION, STATED BY EXECUTION: the same kernel bytes bound to a fixture root admit what that root approves. Which root is a generation-publisher fact (H-32)", async function () {
      const w = await deployGen2World({ label: "sd11-cond", authority: "ungated", ecdsaOnlyFloor: true });
      const real = await deployGen2World({ label: "sd11-cond-real", authority: "root", ecdsaOnlyFloor: true });
      await (await send(w, await setVerifierCalldata(w, w.verifiers.alwaysTrue, { ...ECDSA_ONLY_FLOOR }))).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.alwaysTrue);
      // Offline-checkable from each clone's own code: bytes 8..28 of the args name the root.
      const rootOf = async (x: Gen2World): Promise<string> =>
        ethers.getAddress(
          ethers.hexlify(ethers.getBytes(await ethers.provider.getCode(x.vaultAddress)).slice(45 + 8, 45 + 28)),
        );
      expect(await rootOf(w)).to.equal(w.authorityAddress);
      expect(await rootOf(real)).to.equal(real.authorityAddress);
      expect(await rootOf(w)).to.not.equal(await rootOf(real));
    });

    it("the armed spend under the real root still needs the admitted class's real relation", async function () {
      const w = await deployGen2World({ label: "sd11-rel", authority: "root" });
      const digestSpend = async (): Promise<void> => {
        await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      };
      await digestSpend();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });
  });
});
