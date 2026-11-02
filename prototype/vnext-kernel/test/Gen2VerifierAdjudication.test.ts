/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE VARIANT A VERIFIER DECISION, ADJUDICATED (custody section 10, item 6). Variant A requires an
 * admissible verifier at genesis even while requirePq is false. PR #237 measured that this is smaller; it
 * did not prove it is safe. Rows G2-VERIFIER-1..8 and K-14, each executed rather than argued. The real
 * provenance root is bound wherever a claim is about admission; the ungated fixture appears only where a
 * mock verifier must be installable to attack the conjunct, and each such test says so.
 *
 * Variant B stays the comparator: test at the end.
 */
import { expect } from "chai";
import fs from "node:fs";
import { ethers } from "./connection.js";
import {
  GEN2_KERNEL,
  GEN2_ROOT_CONTRACT,
  GEN2_VERIFIER_CLASS,
  GENERATION_2,
  gen2Unit,
} from "../generation-2/compile.js";
import { VARIANT_A, VARIANT_B } from "../erc20-spend-plane/compile.js";
import { deployErc20World, planeUnit } from "./erc20-spend-plane-world.js";
import {
  DEFAULT_MINT,
  ECDSA_ONLY_FLOOR,
  HONEST_FLOOR,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  ZERO,
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
  rotateCalldata,
  send,
  sendArmedSpend,
  sendSpend,
  setPolicyCalldata,
  setVerifierCalldata,
  sign,
  spendDigest,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 1_000_000n;
const AMOUNT = 250n * UNIT;

const rootWorld = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, authority: "root", ecdsaOnlyFloor: true, ...more });

/** An ECDSA-only recovery execution: no PQ material anywhere, so no attestor could have been asked. */
async function dormantExecuteRecovery(w: Gen2World, newCred: ethers.SigningKey): Promise<string> {
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

const nameMatches = (abi: readonly unknown[], pattern: RegExp): string[] =>
  (abi as { type: string; name?: string }[])
    .filter((f) => f.type === "function" && pattern.test(f.name ?? ""))
    .map((f) => f.name!);

describe("Generation-2 admission — the Variant A verifier decision", function () {
  this.timeout(180_000);

  describe("G2-VERIFIER-1: verifier presence creates no WalletWall authority root", function () {
    it("neither the root nor the class exposes an owner, an admin, a pause, an upgrade or a setter, and neither names a vault", function () {
      const forbidden = /owner|admin|pause|upgrade|set[A-Z]|grant|revoke|rotate|withdraw|sweep|vault/i;
      expect(nameMatches(gen2Unit(GEN2_ROOT_CONTRACT).abi, forbidden)).to.deep.equal([]);
      expect(nameMatches(gen2Unit(GEN2_VERIFIER_CLASS).abi, forbidden)).to.deep.equal([]);
      const cls = gen2Unit(GEN2_VERIFIER_CLASS);
      expect(
        cls.storage.map((slot) => slot.label),
        "OpenZeppelin's EIP-712 fallback strings, set by the constructor if at all",
      ).to.deep.equal(["_nameFallback", "_versionFallback"]);
      const writers = (cls.abi as { type: string; stateMutability?: string; name?: string }[]).filter(
        (f) => f.type === "function" && f.stateMutability !== "view" && f.stateMutability !== "pure",
      );
      expect(
        writers.map((f) => f.name),
        "the class has no function that can write them",
      ).to.deep.equal([]);
    });

    it("the attestor key behind the vault's verifier authorises nothing on a dormant floor: used as a credential it is refused", async function () {
      const w = await rootWorld("v1");
      const attestor = w.attestors[w.verifiers.honest.toLowerCase()]!;
      expect(
        await refusal(w, () =>
          sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: attestor, from: w.outsider, gasLimit: PROBE_GAS }),
        ),
      ).to.equal("BadSignature");
      // POSITIVE CONTROL: the credential itself spends.
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("whoever created the verifier gets nothing from having created it", async function () {
      const w = await rootWorld("v1b");
      const hostile = keyOf("v1b-creator-as-credential");
      expect(
        await refusal(w, () =>
          sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: hostile, from: w.outsider, gasLimit: PROBE_GAS }),
        ),
      ).to.equal("BadSignature");
    });
  });

  describe("G2-VERIFIER-2: verifier authority cannot move assets while requirePq == false; it is not even consulted", function () {
    for (const verifier of ["reverting", "alwaysFalse"] as const) {
      it(`FIXTURE ROOT: a spend settles on an ECDSA-only floor with a ${verifier} verifier installed, which it could not if the verifier were called`, async function () {
        const w = await deployGen2World({ label: "v2-" + verifier, ecdsaOnlyFloor: true, verifier });
        await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
        expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
      });
    }

    it("FIXTURE ROOT: an always-true verifier gives an attacker with no ECDSA key nothing on a dormant floor", async function () {
      const w = await deployGen2World({ label: "v2t", ecdsaOnlyFloor: true, verifier: "alwaysTrue" });
      const hostile = keyOf("v2t-attacker");
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: hostile,
            from: w.outsider,
            pq: { sig: "0x01", key: "0x01" },
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT);
    });
  });

  describe("G2-VERIFIER-3 and G2-VERIFIER-8: no infrastructure and no attestor is a liveness dependency on the dormant floor", function () {
    it("REAL ROOT: spend, policy, verifier change, rotation, recovery and migration all complete with NO attestor statement anywhere, and no PQ material at all", async function () {
      // The vault is born with a root-created verifier whose attestor is a key this test never uses.
      const w = await rootWorld("v3");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      await (await send(w, await setPolicyCalldata(w, ZERO))).wait();
      await (await send(w, await setVerifierCalldata(w, w.verifiers.honestB, { ...ECDSA_ONLY_FLOOR }))).wait();

      const rotated = keyOf("v3-rotated");
      await (await send(w, await rotateCalldata(w, rotated, null))).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: rotated })).wait();

      const recovered = keyOf("v3-recovered");
      await (await proposeRecovery(w, addrOf(recovered), ethers.ZeroHash, w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await dormantExecuteRecovery(w, recovered))).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: recovered })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(3n * AMOUNT);

      await (await bindDestination(w, { credential: recovered })).wait();
      await advanceTime(7 * 86400 + 1);
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT - 3n * AMOUNT);
    });

    it("REAL ROOT: a vault can be created without WalletWall: a stranger creates the verifier and a stranger deploys the vault", async function () {
      const w = await rootWorld("v3b");
      const signers = await ethers.getSigners();
      const stranger = signers[9]!;
      const root = w.root!.connect(stranger) as ethers.Contract;
      const attestor = addrOf(keyOf("v3b-stranger-attestor"));
      const verifier = (await root.deployVerifier.staticCall(attestor)) as string;
      await (await root.deployVerifier(attestor)).wait();
      const genesis = { ...w.genesis, verifier };
      const predicted = (await w.factory.predictVault(w.salt, genesis)) as string;
      await (await (w.factory.connect(stranger) as ethers.Contract).deployVault(w.salt, genesis, "0x")).wait();
      const vault = new ethers.Contract(predicted, gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi, stranger);
      expect(await vault.pqVerifier()).to.equal(verifier);
      expect(await vault.kernelGeneration()).to.equal(GENERATION_2);
    });
  });

  describe("G2-VERIFIER-4: the verifier can be created permissionlessly, and creation grants no privilege", function () {
    it("the outsider created every verifier in a root world, and the root records only what it created: a byte-identical copy outside it is refused", async function () {
      const w = await rootWorld("v4");
      expect(await w.root!.isAdmissibleVerifier(w.verifiers.honest)).to.equal(true);
      const attestor = addrOf(w.attestors[w.verifiers.honest.toLowerCase()]!);
      const copy = await deployUnit(gen2Unit(GEN2_VERIFIER_CLASS), w.deployer, attestor);
      expect(await w.root!.isAdmissibleVerifier(copy.address)).to.equal(false);
      expect(
        await refusal(w, async () =>
          send(w, await setVerifierCalldata(w, copy.address, { ...ECDSA_ONLY_FLOOR }), undefined, PROBE_GAS),
        ),
      ).to.equal("InadmissibleVerifier");
    });

    it("the class's attestor is immutable: its code carries it, and a fresh deployment for another attestor is another address", async function () {
      const w = await rootWorld("v4b");
      const attestor = addrOf(w.attestors[w.verifiers.honest.toLowerCase()]!);
      expect(
        (await ethers.provider.getCode(w.verifiers.honest)).toLowerCase().includes(attestor.slice(2).toLowerCase()),
      ).to.equal(true);
      expect(w.verifiers.honest).to.not.equal(w.verifiers.honestB);
    });
  });

  describe("G2-VERIFIER-5 and K-14: later verifier transitions satisfy the existing cuts and provenance, at all three edges", function () {
    it("REAL ROOT: a mock verifier is refused at genesis, at setVerifier and at initiateRecovery; a root-created one is admitted at each", async function () {
      const w = await rootWorld("v5");
      const mock = w.verifiers.alwaysTrue;

      // Edge 1: genesis, through the real factory: the kernel validates its own genesis.
      let genesisRefused = "";
      try {
        await (
          await w.factory
            .getFunction("deployVault")
            .send(ethers.id("v5-hostile"), { ...w.genesis, verifier: mock }, "0x", { gasLimit: 3_000_000n })
        ).wait();
      } catch (e) {
        const data = /return data: (0x[0-9a-fA-F]*)/.exec(String(e));
        genesisRefused = data ? (w.vault.interface.parseError(data[1]!)?.name ?? "UNKNOWN") : String(e).slice(0, 120);
      }
      expect(genesisRefused).to.equal("InadmissibleVerifier");

      // Edge 2.
      expect(
        await refusal(w, async () =>
          send(w, await setVerifierCalldata(w, mock, { ...ECDSA_ONLY_FLOOR }), undefined, PROBE_GAS),
        ),
      ).to.equal("InadmissibleVerifier");
      await (await send(w, await setVerifierCalldata(w, w.verifiers.honestB, { ...ECDSA_ONLY_FLOOR }))).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.honestB);

      // Edge 3, and the positive control for edge 3.
      const next = keyOf("v5-next");
      expect(
        await refusal(w, async () =>
          send(w, await recoveryCalldata(w, addrOf(next), ethers.ZeroHash, mock), undefined, PROBE_GAS),
        ),
      ).to.equal("InadmissibleVerifier");
      await (await proposeRecovery(w, addrOf(next), ethers.ZeroHash, w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await dormantExecuteRecovery(w, next))).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.honest);
    });

    it("REAL ROOT, ARMED: one root cannot change the verifier: the ECDSA key alone is refused, both factors succeed", async function () {
      const w = await deployGen2World({ label: "v5b", authority: "root" });
      expect(
        await refusal(w, async () =>
          send(w, await setVerifierCalldata(w, w.verifiers.honestB, { ...HONEST_FLOOR }), undefined, PROBE_GAS),
        ),
        "no key at all",
      ).to.equal("BadSignature");
      // The key is public, so holding it proves nothing: without the attestor's statement the verifier refuses.
      const publicKeyOnly = { sig: "0x", key: pqKeyBytes(w.pqKey) };
      expect(
        await refusal(w, async () =>
          send(
            w,
            await setVerifierCalldata(w, w.verifiers.honestB, { ...HONEST_FLOOR }, { pq: publicKeyOnly }),
            undefined,
            PROBE_GAS,
          ),
        ),
        "the public key alone",
      ).to.equal("VerifierDenied");
      const pq = (digest: string): { sig: string; key: string } => pqLegOf(w, digest, w.verifiers.honest, w.pqKey);
      await (
        await send(w, await setVerifierCalldata(w, w.verifiers.honestB, { ...HONEST_FLOOR }, { pqFor: pq }))
      ).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.honestB);
    });

    it("requirePq is one-way: a downgrade is refused with both factors present", async function () {
      const w = await deployGen2World({ label: "v5c", authority: "root" });
      const pq = (digest: string): { sig: string; key: string } => pqLegOf(w, digest, w.verifiers.honest, w.pqKey);
      expect(
        await refusal(w, async () =>
          send(
            w,
            await setVerifierCalldata(w, w.verifiers.honest, { ...ECDSA_ONLY_FLOOR }, { pqFor: pq }),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("Downgrade");
    });

    it("arming needs the exact preimage of the committed key, and is refused on a vault that committed none", async function () {
      const committed = await rootWorld("v5d", { commitPqKey: true });
      const wrong = { sig: "0x", key: pqKeyBytes(keyOf("v5d-wrong")) };
      expect(
        await refusal(committed, async () =>
          send(
            committed,
            await setVerifierCalldata(committed, committed.verifiers.honest, { ...HONEST_FLOOR }, { pq: wrong }),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("BadSignature");
      await (
        await send(
          committed,
          await setVerifierCalldata(
            committed,
            committed.verifiers.honest,
            { ...HONEST_FLOOR },
            { pq: { sig: "0x", key: pqKeyBytes(committed.pqKey) } },
          ),
        )
      ).wait();
      expect((await committed.vault.securityFloor())[0]).to.equal(true);

      const none = await rootWorld("v5e");
      expect(
        await refusal(none, async () =>
          send(
            none,
            await setVerifierCalldata(
              none,
              none.verifiers.honest,
              { ...HONEST_FLOOR },
              { pq: { sig: "0x", key: "0x" } },
            ),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("BadSignature");
    });
  });

  describe("G2-VERIFIER-6: a malicious or always-true verifier stays bounded by the existing authority model", function () {
    it("REAL ROOT, ARMED: a verifier under an attacker's own attestor IS admissible, needs both factors to install, and then voids only the PQ factor: the ECDSA floor still decides", async function () {
      const w = await deployGen2World({ label: "v6-attestor", authority: "root" });
      const attacker = keyOf("v6-attestor-attacker");
      const asStranger = w.root!.connect(w.outsider) as ethers.Contract;
      const created = (await asStranger.deployVerifier.staticCall(addrOf(attacker))) as string;
      await (await asStranger.deployVerifier(addrOf(attacker))).wait();
      const noFactor = await setVerifierCalldata(w, created, HONEST_FLOOR, {
        pq: { sig: "0x", key: pqKeyBytes(w.pqKey) },
      });
      expect(
        await refusal(w, () => send(w, noFactor, undefined, PROBE_GAS)),
        "the ECDSA key alone does not install it",
      ).to.equal("VerifierDenied");
      const both = await setVerifierCalldata(w, created, HONEST_FLOOR, {
        pqFor: (digest) => pqLegOf(w, digest, w.verifiers.honest, w.pqKey),
      });
      await (await send(w, both)).wait();
      const hostile: Gen2World = { ...w, attestors: { ...w.attestors, [created.toLowerCase()]: attacker } };
      const digest = spendDigest(w, {
        to: w.recipient,
        amount: AMOUNT,
        nonce: 0n,
        credentialGeneration: (await w.vault.credentialGeneration()) as bigint,
      });
      const statement = pqLegOf(hostile, digest, created, w.pqKey);
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: keyOf("v6-attestor-no-key"),
            from: w.outsider,
            pq: statement,
            gasLimit: PROBE_GAS,
          }),
        ),
        "the attestor alone",
      ).to.equal("BadSignature");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, pq: statement })).wait();
      expect(
        await assetBalance(w, w.recipient),
        "what the holder of the ECDSA key can now do with no PQ key: the declared degradation",
      ).to.equal(AMOUNT);
    });

    it("REAL ROOT: a bare always-true contract cannot be installed at all", async function () {
      const w = await deployGen2World({ label: "v6", authority: "root" });
      const pq = (digest: string): { sig: string; key: string } => pqLegOf(w, digest, w.verifiers.honest, w.pqKey);
      expect(
        await refusal(w, async () =>
          send(
            w,
            await setVerifierCalldata(w, w.verifiers.alwaysTrue, { ...HONEST_FLOOR }, { pqFor: pq }),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("InadmissibleVerifier");
    });

    it("FIXTURE ROOT, ARMED: installed anyway, it voids only the PQ factor: the ECDSA floor still decides, and no one without that key can spend", async function () {
      const w = await deployGen2World({ label: "v6b", verifier: "alwaysTrue" });
      const hostile = keyOf("v6b-attacker");
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: hostile,
            from: w.outsider,
            pq: { sig: "0x01", key: pqKeyBytes(w.pqKey) },
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
      // The declared degradation: the factor is void, so the ECDSA holder alone suffices (AUTHORITY.md's byzantine row).
      await (
        await sendSpend(w, { to: w.recipient, amount: AMOUNT, pq: { sig: "0x01", key: pqKeyBytes(w.pqKey) } })
      ).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("FIXTURE ROOT, ARMED: it cannot reach the asset any other way: egress stays unbound without the quorum and the credential", async function () {
      const w = await deployGen2World({ label: "v6c", verifier: "alwaysTrue" });
      expect(
        await refusal(w, () =>
          w.vault.connect(w.outsider).getFunction("egress").send(w.token, { gasLimit: PROBE_GAS }),
        ),
      ).to.equal("NotBound");
    });
  });

  describe("G2-VERIFIER-7: verifier loss cannot trap permitted migration or egress", function () {
    it("FIXTURE ROOT, ARMED, VERIFIER DOWN: spending stops, a binding by quorum and ECDSA does not, and the egress moves everything", async function () {
      const w = await deployGen2World({ label: "v7", verifier: "reverting", fundEth: ethers.parseEther("1") });
      const digest = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 0n });
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            pq: { sig: sign(w.pqKey, digest), key: pqKeyBytes(w.pqKey) },
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("verifier down");
      await (await bindDestination(w)).wait();
      await advanceTime(7 * 86400 + 1);
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      await (await w.vault.connect(w.outsider).getFunction("egress")(ZERO)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT);
      expect(await ethers.provider.getBalance(w.destination)).to.equal(ethers.parseEther("1"));
    });

    it("FIXTURE ROOT, ARMED, VERIFIER DOWN: the guardian recovery escapes to a live verifier, and the new credential spends the asset (I-NO-CIRCULAR-ESCAPE)", async function () {
      const w = await deployGen2World({ label: "v7b", verifier: "reverting" });
      const newCred = keyOf("v7b-cred");
      const newPq = keyOf("v7b-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.honest);
      await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("REAL ROOT, ARMED, ATTESTOR GONE: the same two exits work, so no particular attestor is a hard dependency, and spending is what an armed floor stakes on one", async function () {
      const w = await deployGen2World({ label: "v8", authority: "root" });
      // Nobody can attest for the installed verifier any more: every statement below is by someone else.
      const digest = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 0n });
      const forged = pqLegOf(
        { ...w, attestors: { [w.verifiers.honest.toLowerCase()]: keyOf("v8-not-the-attestor") } },
        digest,
        w.verifiers.honest,
        w.pqKey,
      );
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, pq: forged, gasLimit: PROBE_GAS })),
      ).to.equal("VerifierDenied");
      const newCred = keyOf("v8-cred");
      const newPq = keyOf("v8-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honestB)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honestB))).wait();
      await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("REAL ROOT, ARMED: a compromised attestor alone moves nothing: the ECDSA floor is the kernel's own test", async function () {
      const w = await deployGen2World({ label: "v8b", authority: "root" });
      const attacker = keyOf("v8b-attacker");
      const digest = spendDigest(w, { to: w.recipient, amount: AMOUNT, nonce: 0n });
      const statement = pqLegOf(w, digest, w.verifiers.honest, w.pqKey);
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: attacker,
            from: w.outsider,
            pq: statement,
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
    });
  });

  describe("K-7, MEASURED: recovery consults two things I-RECOVERY-LOCALITY-V2's closed list does not name. OWNER DECISION OD-RECOVERY-LOCALITY", function () {
    it("CONSULT 1, REAL ROOT, EVERY FLOOR: initiation asks the provenance root, which can only refuse; the cure is permissionless, so the refusal is never the last word", async function () {
      const w = await rootWorld("k7-root");
      const newCred = keyOf("k7-root-cred");
      expect(
        await refusal(w, () => proposeRecovery(w, addrOf(newCred), ethers.ZeroHash, w.verifiers.alwaysTrue, PROBE_GAS)),
        "a mock is refused here, before any gate",
      ).to.equal("InadmissibleVerifier");
      const attestor = addrOf(keyOf("k7-root-attestor"));
      const asStranger = w.root!.connect(w.outsider) as ethers.Contract;
      const created = (await asStranger.deployVerifier.staticCall(attestor)) as string;
      await (await asStranger.deployVerifier(attestor)).wait();
      await (await proposeRecovery(w, addrOf(newCred), ethers.ZeroHash, created)).wait();
      expect((await w.vault.recovery())[2]).to.equal(created);
    });

    it("CONSULT 2, FIXTURE ROOT, ARMED: execution asks the verifier the quorum proposed, so a dead proposal stops THAT request, and the quorum's next proposal escapes", async function () {
      const w = await deployGen2World({ label: "k7-proposed" });
      const newCred = keyOf("k7-proposed-cred");
      const newPq = keyOf("k7-proposed-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.alwaysFalse)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      expect(
        await refusal(w, async () =>
          send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.alwaysFalse), undefined, PROBE_GAS),
        ),
        "the plane the recovery named refuses it",
      ).to.equal("BadSignature");
      await (await send(w, await cancelByQuorumCalldata(w))).wait();
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("WHAT THE WORDS ARE FOR STILL HOLDS: armed, real root, the recovering party runs its own attestor, with no other party's infrastructure anywhere, and completes", async function () {
      const w = await deployGen2World({ label: "k7-self", authority: "root" });
      const attestor = keyOf("k7-self-attestor");
      const asStranger = w.root!.connect(w.outsider) as ethers.Contract;
      const created = (await asStranger.deployVerifier.staticCall(addrOf(attestor))) as string;
      await (await asStranger.deployVerifier(addrOf(attestor))).wait();
      const ownWorld: Gen2World = { ...w, attestors: { ...w.attestors, [created.toLowerCase()]: attestor } };
      const newCred = keyOf("k7-self-cred");
      const newPq = keyOf("k7-self-pq");
      await (await proposeRecovery(ownWorld, addrOf(newCred), pqHash(newPq), created)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(ownWorld, await executeRecoveryCalldata(ownWorld, newCred, newPq, created))).wait();
      expect(await w.vault.pqVerifier()).to.equal(created);
      await (await sendArmedSpend(ownWorld, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the same two consults are on the kernel's own record, and neither is on the invariant's list", function () {
      const locality = fs
        .readFileSync("docs/Vault_vNext_Architecture.md", "utf8")
        .split("I-RECOVERY-LOCALITY-V2 (T1)")[1]!
        .split("that constituency")[0]!;
      expect(locality).to.include("guardian principals named in the vault's own committed constituency");
      expect(locality.toLowerCase()).to.not.include("verifier");
      const inventory = fs.readFileSync("prototype/vnext-kernel/AUTHORITY.md", "utf8");
      expect(inventory).to.include("`IKernelVerifierAuthority.isAdmissibleVerifier`");
      expect(inventory).to.include("`view` STATICCALL at `initialize`, `setVerifier` and `initiateRecovery` only");
    });
  });

  describe("Variant B, the comparator: nothing here overturns the measurement", function () {
    it("the candidate refuses address(0) at genesis; Variant B admits it, and is larger by the amount #237 measured", async function () {
      const w = await rootWorld("vb-a");
      let refused = "";
      try {
        await (
          await w.factory
            .getFunction("deployVault")
            .send(ethers.id("vb-a-null"), { ...w.genesis, verifier: ZERO }, "0x", { gasLimit: 3_000_000n })
        ).wait();
      } catch (e) {
        const data = /return data: (0x[0-9a-fA-F]*)/.exec(String(e));
        refused = data ? (w.vault.interface.parseError(data[1]!)?.name ?? "UNKNOWN") : String(e).slice(0, 120);
      }
      expect(refused).to.equal("ZeroAddress");

      const b = await deployErc20World({ label: "vb-b", variant: "B", verifier: "none" });
      expect(await b.vault.pqVerifier(), "the verifier-less state later transitions would have to understand").to.equal(
        ZERO,
      );
      const size = (name: string): number => ethers.getBytes(planeUnit(name).deployedBytecode).length;
      expect(size(VARIANT_B) - size(VARIANT_A)).to.equal(57);
    });
  });
});
