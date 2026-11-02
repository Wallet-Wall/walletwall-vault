/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE KERNEL ROWS, EXECUTED ON THE CANDIDATE: K-3 to K-11, K-15 and AUTH-SATISFIABILITY. Forty-two function
 * bodies are AST-identical to Generation 1 (GEN2_AUTHORITY_CENSUS.json), which is why these rows are worth
 * re-running rather than assuming: this suite is what would notice if identity of source had not meant
 * identity of behaviour under the new clone args, generation number and asset. It is deliberately not a
 * copy of Generation 1's suites: each row gets its positive control and its adversary, on a vault that
 * holds an ERC-20, and the stateful campaign composes them over histories.
 */
import { expect } from "chai";
import fs from "node:fs";
import { ethers } from "./connection.js";
import {
  ACTION,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  DEFAULT_MINT,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  ZERO,
  addrOf,
  advanceTime,
  assetBalance,
  bindDestination,
  cancelByQuorumCalldata,
  cancelCalldata,
  containmentCalldata,
  currentNonce,
  deployArtifact,
  deployGen2World,
  deployUnit,
  digestOf,
  executeRecoveryCalldata,
  guardianDigest,
  keyOf,
  pqHash,
  pqKeyBytes,
  pqLegOf,
  proposeRecovery,
  quorum,
  refusal,
  rotateCalldata,
  send,
  sendArmedSpend,
  sendSpend,
  setGuardiansCalldata,
  setMode,
  setPolicyCalldata,
  setVerifierCalldata,
  sign,
  type Gen2World,
  type QuorumProof,
} from "../generation-2/world.js";
import { GENERATION_2, gen2Unit } from "../generation-2/compile.js";

const PROBE_GAS = 1_500_000n;
const AMOUNT = 250n * UNIT;
const EPISODE = 3 * 86400;
const WINDOW = 30 * 86400;

const world = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, ecdsaOnlyFloor: true, ...more });

const expectSettled = async (w: Gen2World, tx: Promise<{ wait: () => Promise<unknown> }>): Promise<void> => {
  await (await tx).wait();
};

async function recoverTo(w: Gen2World, newCred: ethers.SigningKey, newPq: ethers.SigningKey): Promise<void> {
  await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
  await advanceTime(RECOVERY_DELAY_SECONDS + 1);
  await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
}

describe("Generation-2 admission — kernel rows, executed on the candidate", function () {
  this.timeout(180_000);

  describe("K-3: replay state", function () {
    it("four separate domains: each act moves its own nonce and no other", async function () {
      const w = await world("k3");
      const all = async (): Promise<bigint[]> =>
        Promise.all(
          [DOMAIN.SPEND, DOMAIN.CREDENTIAL, DOMAIN.GUARDIAN, DOMAIN.MIGRATION].map((d) => currentNonce(w, d)),
        );
      expect(await all()).to.deep.equal([0n, 0n, 0n, 0n]);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await all()).to.deep.equal([1n, 0n, 0n, 0n]);
      await (await send(w, await setPolicyCalldata(w, ZERO))).wait();
      expect(await all()).to.deep.equal([1n, 1n, 0n, 0n]);
      await (await send(w, await containmentCalldata(w))).wait();
      expect(await all()).to.deep.equal([1n, 1n, 1n, 0n]);
      await advanceTime(EPISODE + 1);
      await (await bindDestination(w)).wait();
      expect(await all()).to.deep.equal([1n, 1n, 1n, 1n]);
    });

    it("a wrong nonce and a passed deadline are refused and consume nothing", async function () {
      const w = await world("k3b");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, nonce: 7n, gasLimit: PROBE_GAS })),
      ).to.equal("BadNonce");
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, deadline: 1n, gasLimit: PROBE_GAS })),
      ).to.equal("Expired");
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
    });

    it("a spent signature is dead, whoever resubmits it, at any later time", async function () {
      const w = await world("k3c");
      const tx = await sendSpend(w, { to: w.recipient, amount: AMOUNT });
      await tx.wait();
      await advanceTime(40 * 86400);
      expect(
        await refusal(w, () => w.outsider.sendTransaction({ to: w.vaultAddress, data: tx.data, gasLimit: PROBE_GAS })),
      ).to.equal("BadNonce");
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });
  });

  describe("I-GENERATION-MONOTONE: a signature is good for one generation of what signed it", function () {
    it("the current key under a past credential generation is refused, and the current roster under a past guardian generation; each passes under the live one. A binding's two legs: K-12-SCOPE", async function () {
      const w = await world("generation");
      const newCred = keyOf("generation-cred");
      await (await send(w, await rotateCalldata(w, newCred, null))).wait();
      expect(await w.vault.credentialGeneration()).to.equal(2n);
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: newCred,
            credentialGeneration: 1n,
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred })).wait();

      const keys = [0, 1, 2]
        .map((i) => keyOf("generation-g" + i))
        .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
      const members = keys.map(addrOf);
      const isContract = [false, false, false];
      await (await send(w, await setGuardiansCalldata(w, 2n, members, isContract))).wait();
      expect(await w.vault.guardianGeneration()).to.equal(2n);
      const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
      const proof = (digest: string): QuorumProof => ({
        members,
        isContract,
        attestingIndices: [0, 1],
        attestations: [sign(keys[0]!, digest), sign(keys[1]!, digest)],
      });
      const stale = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: GENERATION_2,
        actionType: ACTION.RECOVER,
        authorityGeneration: 1n,
        params: ethers.id("CONTAIN"),
        domain: DOMAIN.GUARDIAN,
        nonce,
        deadline: FAR_DEADLINE,
      });
      expect(
        await refusal(w, () =>
          send(
            w,
            w.vault.interface.encodeFunctionData("enterContainment", [proof(stale), nonce, FAR_DEADLINE]),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("QuorumNotMet");
      const live = await guardianDigest(w, ACTION.RECOVER, ethers.id("CONTAIN"), DOMAIN.GUARDIAN, nonce);
      await (
        await send(w, w.vault.interface.encodeFunctionData("enterContainment", [proof(live), nonce, FAR_DEADLINE]))
      ).wait();
      expect(await w.vault.effectiveSafeState()).to.equal(1n);
    });
  });

  describe("K-4: credential commitment and incoming possession", function () {
    it("a rotation proves possession of the INCOMING credential: the outgoing key's proof is refused, then the real one installs and spends", async function () {
      const w = await world("k4");
      const incoming = keyOf("k4-in");
      expect(
        await refusal(w, async () =>
          send(w, await rotateCalldata(w, incoming, null, { popSigner: w.credKey }), undefined, PROBE_GAS),
        ),
      ).to.equal("BadSignature");
      await (await send(w, await rotateCalldata(w, incoming, null))).wait();
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(incoming));
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: incoming })).wait();
      expect(
        await refusal(w, () =>
          sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: w.credKey, gasLimit: PROBE_GAS }),
        ),
        "the old key is dead",
      ).to.equal("BadSignature");
    });

    it("a non-zero commitment needs its preimage even on a dormant floor (I-COMMITMENT-EXHIBITED-AT-ADMISSION)", async function () {
      const w = await world("k4b");
      const incoming = keyOf("k4b-in");
      const newPq = keyOf("k4b-pq");
      const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
      const pop = (await w.vault.credentialPossessionDigest(addrOf(incoming), pqHash(newPq))) as string;
      const digest = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: GENERATION_2,
        actionType: ACTION.ROTATE,
        authorityGeneration: 1n,
        params: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(incoming), pqHash(newPq)]),
        ),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });
      const data = (key: string): string =>
        w.vault.interface.encodeFunctionData("rotateCredential", [
          {
            newSigner: addrOf(incoming),
            newPqKeyHash: pqHash(newPq),
            newPqKey: key,
            newEcdsaPop: sign(incoming, pop),
            newPqPop: "0x",
          },
          nonce,
          FAR_DEADLINE,
          sign(w.credKey, digest),
          "0x",
          "0x",
        ]);
      expect(await refusal(w, () => send(w, data(pqKeyBytes(keyOf("k4b-wrong"))), undefined, PROBE_GAS))).to.equal(
        "BadSignature",
      );
      await (await send(w, data(pqKeyBytes(newPq)))).wait();
      expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(newPq));
    });
  });

  describe("K-5: the ECDSA possession floor", function () {
    it("with every plane removed and an always-true verifier installed, the kernel's own ecrecover still decides", async function () {
      const w = await deployGen2World({ label: "k5", verifier: "alwaysTrue" });
      expect(await w.vault.policyEngine()).to.equal(ZERO);
      const stranger = keyOf("k5-stranger");
      const pq = { sig: "0x01", key: pqKeyBytes(w.pqKey) };
      expect(
        await refusal(w, () =>
          sendSpend(w, {
            to: w.recipient,
            amount: AMOUNT,
            signer: stranger,
            from: w.outsider,
            pq,
            gasLimit: PROBE_GAS,
          }),
        ),
      ).to.equal("BadSignature");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, pq })).wait();
    });

    it("rotation, verifier and policy changes each contain the same floor", async function () {
      const w = await world("k5b");
      const stranger = keyOf("k5b-stranger");
      expect(
        await refusal(w, async () =>
          send(w, await rotateCalldata(w, keyOf("k5b-in"), null, { credential: stranger }), undefined, PROBE_GAS),
        ),
      ).to.equal("BadSignature");
      expect(
        await refusal(w, async () =>
          send(
            w,
            await setVerifierCalldata(w, w.verifiers.honestB, { ...ECDSA_ONLY_FLOOR }, { credential: stranger }),
            undefined,
            PROBE_GAS,
          ),
        ),
      ).to.equal("BadSignature");
      expect(
        await refusal(w, async () =>
          send(w, await setPolicyCalldata(w, w.policies.deny, stranger), undefined, PROBE_GAS),
        ),
      ).to.equal("BadSignature");
    });
  });

  describe("K-6: guardian authority", function () {
    const sorted = (keys: ethers.SigningKey[]): ethers.SigningKey[] =>
      [...keys].sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));

    it("the roster arrives as untrusted calldata: a forged roster, a sub-quorum and an unordered index are each refused", async function () {
      const w = await world("k6");
      const members = sorted([0, 1, 2].map((i) => keyOf("k6-g" + i))).map(addrOf);
      const flags = [false, false, false];
      const forged = sorted([0, 1, 2].map((i) => keyOf("k6-forged" + i)));
      const forgedProof = (digest: string): QuorumProof => ({
        members: forged.map(addrOf),
        isContract: flags,
        attestingIndices: [0, 1],
        attestations: [sign(forged[0]!, digest), sign(forged[1]!, digest)],
      });
      expect(
        await refusal(w, async () =>
          send(w, await setGuardiansCalldata(w, 2n, members, flags, forgedProof), undefined, PROBE_GAS),
        ),
        "a roster the kernel never committed",
      ).to.equal("BadRoster");
      expect(
        await refusal(w, async () =>
          send(w, await setGuardiansCalldata(w, 2n, members, flags, (d) => quorum(w, d, [0])), undefined, PROBE_GAS),
        ),
        "one guardian",
      ).to.equal("QuorumNotMet");
      expect(
        await refusal(w, async () =>
          send(w, await setGuardiansCalldata(w, 2n, members, flags, (d) => quorum(w, d, [1, 0])), undefined, PROBE_GAS),
        ),
        "indices out of order",
      ).to.equal("NotOrdered");
      expect(
        await refusal(w, async () =>
          send(w, await setGuardiansCalldata(w, 2n, members, flags, (d) => quorum(w, d, [1, 1])), undefined, PROBE_GAS),
        ),
        "one seat twice",
      ).to.equal("NotOrdered");
      await (await send(w, await setGuardiansCalldata(w, 2n, members, flags))).wait();
      expect(await w.vault.guardianGeneration()).to.equal(2n);
    });

    it("a roster with one principal in two seats cannot be committed (I-QUORUM-PRINCIPAL-DISTINCTNESS)", async function () {
      const w = await world("k6b");
      const a = addrOf(keyOf("k6b-a"));
      expect(
        await refusal(w, async () =>
          send(w, await setGuardiansCalldata(w, 2n, [a, a, a], [false, false, false]), undefined, PROBE_GAS),
        ),
      ).to.equal("NotOrdered");
    });

    for (const [name, mock] of [
      ["reverting", "RevertingGuardian"],
      ["gas-burning", "GasBurningGuardian"],
      ["wrong-answer", "WrongAnswerGuardian"],
      ["huge-return", "HugeReturnGuardian"],
      ["dirty-magic", "Gen2DirtyMagicGuardian"],
    ] as const) {
      it(`a ${name} ERC-1271 guardian changes nothing for the others (I-GUARDIAN-FAULT-ISOLATION)`, async function () {
        const w = await world("k6-" + name);
        const bad =
          mock === "Gen2DirtyMagicGuardian"
            ? await deployUnit(gen2Unit(mock), w.deployer)
            : await deployArtifact(mock, w.deployer);
        const eoas = sorted([keyOf(`k6-${name}-a`), keyOf(`k6-${name}-b`)]);
        const seats = [addrOf(eoas[0]!), addrOf(eoas[1]!), bad.address].map((a) => a.toLowerCase());
        const order = [...seats.keys()].sort((x, y) => (BigInt(seats[x]!) < BigInt(seats[y]!) ? -1 : 1));
        const members = order.map((i) => ethers.getAddress(seats[i]!));
        const isContract = order.map((i) => i === 2);
        await (await send(w, await setGuardiansCalldata(w, 2n, members, isContract))).wait();

        const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
        const digest = await guardianDigest(w, ACTION.RECOVER, ethers.id("CONTAIN"), DOMAIN.GUARDIAN, nonce);
        const eoaIndices = members.map((m, i) => (isContract[i] ? -1 : i)).filter((i) => i >= 0);
        const keyAt = (i: number): ethers.SigningKey => eoas.find((k) => addrOf(k) === members[i])!;
        const honest: QuorumProof = {
          members,
          isContract,
          attestingIndices: eoaIndices,
          attestations: eoaIndices.map((i) => sign(keyAt(i), digest)),
        };
        const badIndex = isContract.indexOf(true);
        const withBad = [badIndex, eoaIndices[0]!].sort((a, b) => a - b);
        const faulty: QuorumProof = {
          members,
          isContract,
          attestingIndices: withBad,
          attestations: withBad.map((i) => (i === badIndex ? "0x" : sign(keyAt(i), digest))),
        };
        expect(
          await refusal(w, () =>
            send(
              w,
              w.vault.interface.encodeFunctionData("enterContainment", [faulty, nonce, FAR_DEADLINE]),
              undefined,
              3_000_000n,
            ),
          ),
          "its vote does not count",
        ).to.equal("QuorumNotMet");
        await (
          await send(
            w,
            w.vault.interface.encodeFunctionData("enterContainment", [honest, nonce, FAR_DEADLINE]),
            undefined,
            3_000_000n,
          )
        ).wait();
        expect(await w.vault.effectiveSafeState()).to.equal(1n);
      });
    }
  });

  describe("K-7 and K-8: recovery state and execution", function () {
    it("recovery never consults the asset: it completes with the token down, and the new credential spends once the token is back", async function () {
      const w = await world("k7");
      await setMode(w, "REVERTS");
      const newCred = keyOf("k7-cred");
      const newPq = keyOf("k7-pq");
      await recoverTo(w, newCred, newPq);
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, gasLimit: PROBE_GAS })),
      ).to.equal("TransferFailed");
      await setMode(w, "VANILLA");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the window is half-open: refused before executableAt, executable at it, dead at expiresAt with nothing else having happened", async function () {
      const w = await world("k7b");
      const newCred = keyOf("k7b-cred");
      const newPq = keyOf("k7b-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      const r = await w.vault.recovery();
      const executableAt = Number(r[3]);
      const expiresAt = Number(r[4]);
      expect(
        await refusal(w, async () =>
          send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest), undefined, PROBE_GAS),
        ),
      ).to.equal("TooEarly");
      await ethers.provider.send("evm_setNextBlockTimestamp", [expiresAt]);
      expect(
        await refusal(w, async () =>
          send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest), undefined, PROBE_GAS),
        ),
        "at expiresAt",
      ).to.equal("Expired");
      expect(executableAt).to.be.lessThan(expiresAt);

      const on = await world("k7c");
      const c2 = keyOf("k7c-cred");
      const p2 = keyOf("k7c-pq");
      await (await proposeRecovery(on, addrOf(c2), pqHash(p2), on.verifiers.honest)).wait();
      const data = await executeRecoveryCalldata(on, c2, p2, on.verifiers.honest);
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number((await on.vault.recovery())[3])]);
      await (await send(on, data)).wait();
      expect(await on.vault.ecdsaSigner()).to.equal(addrOf(c2));
    });

    it("I-APPROVED-REQUEST-PRESERVATION: a guardian-set replacement does not clear an approved request", async function () {
      const w = await world("k8");
      const newCred = keyOf("k8-cred");
      const newPq = keyOf("k8-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      const replacement = [0, 1, 2]
        .map((i) => keyOf("k8-g" + i))
        .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
      await (await send(w, await setGuardiansCalldata(w, 2n, replacement.map(addrOf), [false, false, false]))).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    });
  });

  describe("K-9: cancellation and the challenge epoch", function () {
    it("the credential's veto is capped and the epoch does not refund; the quorum's cancellation still works; a successful recovery resets it", async function () {
      const w = await world("k9");
      const next = keyOf("k9-cred");
      const nextPq = keyOf("k9-pq");
      const propose = async (): Promise<void> => {
        await (await proposeRecovery(w, addrOf(next), pqHash(nextPq), w.verifiers.honest)).wait();
      };
      await propose();
      await (await send(w, await cancelCalldata(w))).wait();
      await propose();
      await (await send(w, await cancelCalldata(w))).wait();
      await propose();
      expect(
        await refusal(w, async () => send(w, await cancelCalldata(w), undefined, PROBE_GAS)),
        "the third is refused",
      ).to.equal("ChallengeExhausted");
      await (await send(w, await cancelByQuorumCalldata(w))).wait();
      expect((await w.vault.recovery())[7], "mechanism B cleared it").to.equal(false);
      expect((await w.vault.recovery())[6], "mechanism B does not refund mechanism A").to.equal(2n);
      await propose();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, next, nextPq, w.verifiers.honest))).wait();
      expect((await w.vault.recovery())[6], "only a successful recovery resets the epoch").to.equal(0n);
    });

    it("a stranger can cancel nothing, on either mechanism", async function () {
      const w = await world("k9b");
      await (await proposeRecovery(w, addrOf(keyOf("k9b-new")), ethers.ZeroHash, w.verifiers.honest)).wait();
      expect(
        await refusal(w, async () => send(w, await cancelCalldata(w, keyOf("k9b-stranger")), w.outsider, PROBE_GAS)),
      ).to.equal("BadSignature");
      const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
      const digest = await guardianDigest(
        w,
        ACTION.RECOVER,
        ethers.id("QUORUM_CANCEL_RECOVERY"),
        DOMAIN.GUARDIAN,
        nonce,
      );
      expect(
        await refusal(w, () =>
          send(
            w,
            w.vault.interface.encodeFunctionData("cancelRecoveryByQuorum", [
              quorum(w, digest, [0]),
              nonce,
              FAR_DEADLINE,
            ]),
            w.outsider,
            PROBE_GAS,
          ),
        ),
      ).to.equal("QuorumNotMet");
    });
  });

  describe("K-10: the safe-state machine, with an asset in it", function () {
    it("spending is NORMAL only: refused CONTAINED, MIGRATION_ONLY and RETIRED; the exit is open from RETIRED", async function () {
      const w = await world("k10");
      await (await send(w, await containmentCalldata(w))).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
        "CONTAINED",
      ).to.equal("BadState");
      await advanceTime(EPISODE + 1);
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      await (await bindDestination(w)).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
        "MIGRATION_ONLY",
      ).to.equal("BadState");
      await advanceTime(7 * 86400 + 1);
      await (await w.vault.connect(w.outsider).getFunction("retire")()).wait();
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
        "RETIRED",
      ).to.equal("BadState");
      await (await w.vault.connect(w.outsider).getFunction("egress")(w.token)).wait();
      expect(await assetBalance(w, w.destination)).to.equal(DEFAULT_MINT - AMOUNT);
    });

    it("recovery stays live in CONTAINED: containment cannot stop the remedy", async function () {
      const w = await world("k10b");
      await (await send(w, await containmentCalldata(w))).wait();
      const newCred = keyOf("k10b-cred");
      const newPq = keyOf("k10b-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      expect((await w.vault.recovery())[7]).to.equal(true);
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    });
  });

  describe("K-11: emergency transitions", function () {
    it("containment self-expires on the wall clock with no principal acting, and the next block can spend", async function () {
      const w = await world("k11");
      await (await send(w, await containmentCalldata(w))).wait();
      const until = Number(await w.vault.containedUntil());
      await ethers.provider.send("evm_setNextBlockTimestamp", [until - 1]);
      expect(
        await refusal(w, () => sendSpend(w, { to: w.recipient, amount: AMOUNT, gasLimit: PROBE_GAS })),
        "one second before",
      ).to.equal("BadState");
      await ethers.provider.send("evm_setNextBlockTimestamp", [until]);
      await expectSettled(w, sendSpend(w, { to: w.recipient, amount: AMOUNT }));
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the historical straddle stops at the declared 6 days: late in one window, at the rollover, and right after is refused (the SD-2 shape)", async function () {
      const w = await world("k11-straddle");
      await (await send(w, await containmentCalldata(w))).wait();
      const firstStart = Number(await w.vault.containedUntil()) - EPISODE;
      await ethers.provider.send("evm_setNextBlockTimestamp", [firstStart + 27 * 86400]);
      await (await send(w, await containmentCalldata(w))).wait();
      const secondStart = firstStart + 27 * 86400;
      await ethers.provider.send("evm_setNextBlockTimestamp", [firstStart + WINDOW]);
      await (await send(w, await containmentCalldata(w))).wait();
      // A fourth here would hold 9 contiguous days in one window, which is exactly what a tumbling counter allowed.
      const attempt = await containmentCalldata(w);
      await ethers.provider.send("evm_setNextBlockTimestamp", [firstStart + WINDOW + EPISODE]);
      expect(await refusal(w, () => send(w, attempt, undefined, PROBE_GAS))).to.equal("ContainmentBudget");
      // Legal exactly one window after the second-most-recent start, and no earlier.
      const later = await containmentCalldata(w);
      await ethers.provider.send("evm_setNextBlockTimestamp", [secondStart + WINDOW - 1]);
      expect(await refusal(w, () => send(w, later, undefined, PROBE_GAS))).to.equal("ContainmentBudget");
      await ethers.provider.send("evm_setNextBlockTimestamp", [secondStart + WINDOW]);
      await (await send(w, later)).wait();
      expect(await w.vault.effectiveSafeState()).to.equal(1n);
    });

    it("re-entry cannot extend it, and a third episode inside the window is refused until the second-most-recent start is exactly one window old", async function () {
      const w = await world("k11b");
      await (await send(w, await containmentCalldata(w))).wait();
      const firstUntil = await w.vault.containedUntil();
      expect(
        await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS)),
        "re-entry",
      ).to.equal("BadState");
      expect(await w.vault.containedUntil(), "not extended").to.equal(firstUntil);
      const firstStart = Number(firstUntil) - EPISODE;

      await advanceTime(EPISODE + 1);
      await (await send(w, await containmentCalldata(w))).wait();
      await advanceTime(EPISODE + 1);
      expect(
        await refusal(w, async () => send(w, await containmentCalldata(w), undefined, PROBE_GAS)),
        "a third",
      ).to.equal("ContainmentBudget");
      const data = await containmentCalldata(w);
      await ethers.provider.send("evm_setNextBlockTimestamp", [firstStart + WINDOW]);
      await (await send(w, data)).wait();
      expect(await w.vault.effectiveSafeState()).to.equal(1n);
    });
  });

  describe("K-SECURITY-PROFILE: section 12's strength policy is not here, and the row says so", function () {
    it("the floor is four flat fields, the construct section 12 withdrew: no scheme, family, root tag or anchor, and the level authorises nothing", async function () {
      const w = await world("profile");
      const fields = (w.vault.interface.getFunction("securityFloor")!.outputs ?? []).map(
        (o: { name: string }) => o.name,
      );
      expect(fields).to.deep.equal(["requirePq", "pqParamLevel", "pqPublicKeyLength", "pqSignatureLength"]);
      const names = w.vault.interface.fragments
        .filter((f: { type: string }) => f.type === "function")
        .map((f: { type: string }) => (f as unknown as { name: string }).name);
      for (const missing of ["schemeId", "family", "rootTag", "anchored", "verifierGeneration", "securityProfile"])
        expect(names, missing).to.not.include(missing);
      const admission = fs.readFileSync("prototype/vnext-kernel/KERNEL_ADMISSION.md", "utf8");
      expect(admission, "the disposition this generation inherits").to.include(
        "SECURITY_PROFILE_DISPOSITION = DEFERRED_TO_FUTURE_GENERATION",
      );
    });
  });

  describe("K-15 and AUTH-SATISFIABILITY: the floor", function () {
    it("I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE: moving the metadata fields cannot move an approved recovery", async function () {
      const w = await deployGen2World({ label: "k15" });
      const newCred = keyOf("k15-cred");
      const newPq = keyOf("k15-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      const moved = {
        ...HONEST_FLOOR,
        pqParamLevel: HONEST_FLOOR.pqParamLevel + 1,
        pqPublicKeyLength: 4242,
        pqSignatureLength: 4343,
      };
      await (
        await send(
          w,
          await setVerifierCalldata(w, w.verifiers.honest, moved, {
            pqFor: (d) => pqLegOf(w, d, w.verifiers.honest, w.pqKey),
          }),
        )
      ).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      await (await sendArmedSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred, pqKey: newPq })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("no vault is born with a mandatory conjunct nothing can satisfy: an armed genesis with no commitment, or a commitment with no preimage, is refused", async function () {
      const w = await world("sat");
      const refusedGenesis = async (genesis: unknown, witness: string): Promise<string> => {
        try {
          await (
            await w.factory
              .getFunction("deployVault")
              .send(ethers.id("sat-" + witness.length + JSON.stringify(genesis).length), genesis, witness, {
                gasLimit: 3_000_000n,
              })
          ).wait();
          return "DEPLOYED";
        } catch (e) {
          const data = /return data: (0x[0-9a-fA-F]*)/.exec(String(e));
          return data ? (w.vault.interface.parseError(data[1]!)?.name ?? "UNKNOWN") : String(e).slice(0, 120);
        }
      };
      expect(
        await refusedGenesis({ ...w.genesis, floor: { ...HONEST_FLOOR }, pqKeyHash: ethers.ZeroHash }, "0x"),
      ).to.equal("BadSignature");
      expect(
        await refusedGenesis({ ...w.genesis, pqKeyHash: pqHash(keyOf("sat-pq")) }, pqKeyBytes(keyOf("sat-wrong"))),
      ).to.equal("BadSignature");
      expect(
        await refusedGenesis({ ...w.genesis, pqKeyHash: pqHash(keyOf("sat-pq")) }, pqKeyBytes(keyOf("sat-pq"))),
        "POSITIVE CONTROL",
      ).to.equal("DEPLOYED");
    });
  });
});
