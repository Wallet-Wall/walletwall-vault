/**
 * EXPERIMENTAL PROTOTYPE — SD-1 REMEDIATION REGRESSION SUITE.
 *
 * SD-1 was `setVerifier` writing `SecurityFloor.pqPublicKeyLength` /
 * `pqSignatureLength` freely while `_requireIncomingPossession` measured an
 * already-quorum-approved recovery against those fields LIVE. The credential
 * principal therefore held a veto over guardian recovery that the modelled
 * challenge counter never saw.
 *
 * THE INVARIANT THIS FILE PINS — `I-FLOOR-SHAPE-IMMUTABLE`:
 *
 *   for every accepted setVerifier transition s -> s':
 *     s.securityFloor.requirePq
 *       ==> s'.pqPublicKeyLength == s.pqPublicKeyLength
 *        /\ s'.pqSignatureLength == s.pqSignatureLength
 *
 * `initialize` and `setVerifier` are the ONLY writers of `securityFloor`, so
 * once a PQ conjunct is mandatory the two STRUCTURAL fields are constants for
 * the life of the vault. The remedy is therefore not "count the veto" and not
 * "snapshot the floor" — both of which merely relocate credential-movable state
 * — but REMOVE that state from the satisfiability condition. `pqParamLevel`
 * stays a free ratchet because neither `_authorise` nor
 * `_requireIncomingPossession` ever reads it.
 *
 * WHY NOT A COUNTER, AND WHY NOT A SNAPSHOT — the reasons are asserted below,
 * not merely claimed. `challengesUsed` bounds `cancelRecovery` because a
 * cancellation is REVERSIBLE by the defender: the quorum re-initiates and the
 * state returns. A floor write is not reversible by any defender — no guardian
 * path writes `securityFloor`, and `executeRecovery` never touches it — so a
 * counter bounds only how many times an attacker re-chooses which permanent
 * state to inflict. A snapshot fails for the mirror-image reason: `_authorise`
 * reads the SAME live slot, so a poisoned floor stays absorbing and the
 * recovered credential could never spend. R5 and R9 pin both halves.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  floorTuple,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;

/** The floor as the kernel currently holds it. */
async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/**
 * Submits a setVerifier as the credential principal. Returns the unawaited
 * promise so a caller may assert either a revert or a successful mine.
 */
async function setVerifierTx(
  w: World,
  verifier: string,
  floor: Floor,
  opts: { cred?: ethers.SigningKey; pq?: ethers.SigningKey | null; pqSigOverride?: string } = {},
): Promise<ethers.ContractTransactionResponse> {
  const cred = opts.cred ?? w.credKey;
  const pq = opts.pq === undefined ? w.pqKey : opts.pq;
  const current = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.setVerifier(
    verifier,
    floorTuple(floor),
    nonce,
    FAR_DEADLINE,
    sign(cred, d),
    current.requirePq && pq ? (opts.pqSigOverride ?? sign(pq, d)) : "0x",
    current.requirePq && pq ? pqKeyBytes(pq) : "0x",
  );
}

/** A k-of-n honest quorum initiates a recovery to `spareCred[i]` / `sparePq[i]`. */
async function initiate(
  w: World,
  i = 0,
  verifier?: string,
  pqHashOverride?: string,
): Promise<{ cred: ethers.SigningKey; pq: ethers.SigningKey; verifier: string }> {
  const cred = w.spareCred[i]!;
  const pq = w.sparePq[i]!;
  const v = verifier ?? w.verifiers.honest;
  const keyHash = pqHashOverride ?? pqHash(pq);
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER,
    authorityGeneration: gGen,
    params: recoverParams(addrOf(cred), keyHash, v),
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.initiateRecovery(
      addrOf(cred),
      keyHash,
      v,
      {
        members: w.guardians,
        isContract: w.guardianIsContract,
        attestingIndices: [0, 1],
        attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      },
      nonce,
      FAR_DEADLINE,
    )
  ).wait();
  return { cred, pq, verifier: v };
}

/** The CredentialChange a matured recovery expects, signed by the INCOMING material. */
async function recoveryChange(
  w: World,
  cred: ethers.SigningKey,
  pq: ethers.SigningKey,
): Promise<Record<string, string>> {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  return {
    newSigner: addrOf(cred),
    newPqKeyHash: pqHash(pq),
    newPqKey: pqKeyBytes(pq),
    newEcdsaPop: sign(cred, pop),
    newPqPop: sign(pq, pop),
  };
}

/** Positional indices into the public `recovery()` tuple. */
const RECOVERY_FIELD = { CHALLENGES: 6, ACTIVE: 7 } as const;

async function challengesUsed(w: World): Promise<number> {
  return Number((await w.vault.recovery())[RECOVERY_FIELD.CHALLENGES]);
}

async function recoveryActive(w: World): Promise<boolean> {
  return (await w.vault.recovery())[RECOVERY_FIELD.ACTIVE] as boolean;
}

/**
 * Executes a matured recovery and asserts the STATE TRANSITION, never merely the
 * absence of a revert. `_requireIncomingPossession` reverts `BadSignature` from
 * three different branches, so a revert-selector assertion cannot tell a fixed
 * kernel from a broken one — only the observed install can.
 */
async function expectRecoveryExecutes(
  w: World,
  cred: ethers.SigningKey,
  pq: ethers.SigningKey,
  note: string,
): Promise<void> {
  const genBefore = (await w.vault.credentialGeneration()) as bigint;
  await (await w.vault.executeRecovery(await recoveryChange(w, cred, pq))).wait();
  expect(await w.vault.ecdsaSigner(), note + " — the proposed signer must be installed").to.equal(addrOf(cred));
  expect(await w.vault.pqPublicKeyHash(), note + " — the proposed PQ commitment must be installed").to.equal(
    pqHash(pq),
  );
  expect((await w.vault.credentialGeneration()) as bigint, note + " — the generation must advance").to.equal(
    genBefore + 1n,
  );
  expect(await recoveryActive(w), note + " — the request must be consumed").to.equal(false);
}

describe("vNext kernel — SD-1 REMEDIATION: I-FLOOR-SHAPE-IMMUTABLE", function () {
  this.timeout(600_000);

  // =====================================================================
  // R1 — the exact sustained attack
  // =====================================================================
  describe("R1 — the sustained SD-1 counterexample is dead", function () {
    it("the exact SD-1 attack is REFUSED AT THE WRITE, and the vetoed recovery then executes", async function () {
      const w = await deployWorld({ label: "sd1-r1", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      expect(await recoveryActive(w)).to.equal(true);
      expect(await challengesUsed(w)).to.equal(0);

      const before = await liveFloor(w);
      expect(before.pqSignatureLength, "the honest floor declares a 65-byte signature").to.equal(65);

      // The SD-1 move, verbatim: requirePq held, pqParamLevel held, ONE length changed.
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 }),
        "the poisoning transition must be refused",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");

      expect(await liveFloor(w), "the floor must be byte-identical after the refusal").to.deep.equal(before);

      // AND THE POINT: the recovery the attack existed to veto now completes.
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R1");
      expect(await challengesUsed(w), "no challenge was consumed, because there was never a veto").to.equal(0);
    });

    it("the attack is refused BEFORE any recovery exists too — poisoning is prevented, not merely deferred", async function () {
      const w = await deployWorld({ label: "sd1-r1b", verifier: "honest" });
      const before = await liveFloor(w);
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...before, pqPublicKeyLength: 1 }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      expect(await liveFloor(w)).to.deep.equal(before);

      // A quorum proposing AFTER the attempted poisoning is unaffected. This is
      // the schedule a request-snapshot design cannot close, because a snapshot
      // faithfully records an already-poisoned floor.
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R1b");
    });
  });

  // =====================================================================
  // R2 / R3 — no uncounted veto at any point in the request's life
  // =====================================================================
  describe("R2/R3 — no uncounted veto after authorization, at any schedule point", function () {
    const MUTATIONS: { name: string; label: string; mutate: (f: Floor) => Floor }[] = [
      { name: "pqSignatureLength shrunk", label: "sigdown", mutate: (f) => ({ ...f, pqSignatureLength: 64 }) },
      { name: "pqSignatureLength grown", label: "sigup", mutate: (f) => ({ ...f, pqSignatureLength: 66 }) },
      { name: "pqPublicKeyLength shrunk", label: "keydown", mutate: (f) => ({ ...f, pqPublicKeyLength: 31 }) },
      { name: "pqPublicKeyLength grown", label: "keyup", mutate: (f) => ({ ...f, pqPublicKeyLength: 33 }) },
      {
        name: "both lengths changed",
        label: "both",
        mutate: (f) => ({ ...f, pqPublicKeyLength: 1, pqSignatureLength: 1 }),
      },
      {
        name: "both lengths changed WITH a pqParamLevel increase — the ledger's own fix sketch, which is not a fix",
        label: "levelcoupled",
        mutate: (f) => ({ ...f, pqParamLevel: f.pqParamLevel + 1, pqPublicKeyLength: 1, pqSignatureLength: 1 }),
      },
      {
        name: "lengths changed to a plausible-looking larger PQ shape",
        label: "plausible",
        mutate: (f) => ({ ...f, pqParamLevel: f.pqParamLevel + 2, pqPublicKeyLength: 1952, pqSignatureLength: 3309 }),
      },
    ];

    for (const m of MUTATIONS) {
      it("R2 — after quorum approval: " + m.name + " is refused and the recovery still executes", async function () {
        const w = await deployWorld({ label: "sd1-r2-" + m.label, verifier: "honest" });
        const { cred, pq } = await initiate(w);
        const before = await liveFloor(w);

        await expect(setVerifierTx(w, w.verifiers.honest, m.mutate(before))).to.be.revertedWithCustomError(
          w.vault,
          "Downgrade",
        );
        expect(await liveFloor(w)).to.deep.equal(before);
        expect(await challengesUsed(w)).to.equal(0);

        await networkHelpers.time.increase(7 * DAY + 1);
        await expectRecoveryExecutes(w, cred, pq, "R2/" + m.label);
      });
    }

    it("R3 — after MATURATION, inside the executable window, every mutation is still refused", async function () {
      const w = await deployWorld({ label: "sd1-r3", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const before = await liveFloor(w);
      for (const m of MUTATIONS) {
        await expect(
          setVerifierTx(w, w.verifiers.honest, m.mutate(before)),
          m.name + " must be refused after maturation",
        ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      }
      expect(await liveFloor(w)).to.deep.equal(before);
      expect(await challengesUsed(w)).to.equal(0);
      await expectRecoveryExecutes(w, cred, pq, "R3");
    });

    it("R2b — repetition buys nothing, and the challenge budget is never touched", async function () {
      const w = await deployWorld({ label: "sd1-r2b", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const before = await liveFloor(w);
      for (let i = 0; i < 5; i++) {
        await expect(
          setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 - i }),
        ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      }
      expect(await liveFloor(w)).to.deep.equal(before);
      expect(await challengesUsed(w), "a refused transition consumes no challenge").to.equal(0);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R2b");
    });
  });

  // =====================================================================
  // R4 — legitimate floor evolution is NOT frozen
  // =====================================================================
  describe("R4 — legitimate strengthening still works", function () {
    it("a pqParamLevel increase with the shape HELD is accepted, with and without a pending recovery", async function () {
      const w = await deployWorld({ label: "sd1-r4a", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel + 1 })).wait();
      expect((await liveFloor(w)).pqParamLevel).to.equal(f0.pqParamLevel + 1);

      const { cred, pq } = await initiate(w);
      const f1 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f1, pqParamLevel: f1.pqParamLevel + 7 })).wait();
      expect((await liveFloor(w)).pqParamLevel, "the ratchet is free even mid-recovery").to.equal(f1.pqParamLevel + 7);
      expect(await challengesUsed(w), "a legitimate strengthening costs no challenge").to.equal(0);
      expect(await recoveryActive(w), "and does not destroy the approved request").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R4a");
    });

    it("replacing the VERIFIER with the shape held is accepted, and I-NO-SILENT-DOWNGRADE still discriminates its own clauses", async function () {
      const w = await deployWorld({ label: "sd1-r4b", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.alwaysTrue, f0)).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.alwaysTrue);

      // requirePq true -> false is refused even when the SHAPE IS HELD CONSTANT,
      // so the freeze has not absorbed the clause that forbids it.
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...f0, requirePq: false }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      // ...and a level DECREASE is refused with the shape held, likewise.
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel - 1 }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    });

    it("an ECDSA-ONLY vault may still raise requirePq — the freeze is guarded on the CURRENT floor", async function () {
      // The key is committed at genesis, so raising requirePq lands in a
      // SATISFIABLE state rather than in SD-3's bricked one. SD-3 is a separate
      // sustained defect and is deliberately not exercised here.
      const w = await deployWorld({
        label: "sd1-r4c",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const f0 = await liveFloor(w);
      expect(f0.requirePq).to.equal(false);
      expect(f0.pqPublicKeyLength).to.equal(0);
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 3,
          pqPublicKeyLength: 32,
          pqSignatureLength: 65,
        })
      ).wait();
      const f1 = await liveFloor(w);
      expect(f1.requirePq).to.equal(true);
      expect(f1.pqSignatureLength).to.equal(65);
      // ...and from that moment the shape is frozen.
      await expect(setVerifierTx(w, w.verifiers.honest, { ...f1, pqSignatureLength: 64 })).to.be.revertedWithCustomError(
        w.vault,
        "Downgrade",
      );
    });
  });

  // =====================================================================
  // R5 — the remedy still works end to end
  // =====================================================================
  describe("R5 — legitimate guardian recovery matures, executes, and leaves authority USABLE", function () {
    it("POSITIVE CONTROL — recovery completes and the recovered credential can spend", async function () {
      const w = await deployWorld({ label: "sd1-r5", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await expect(w.vault.executeRecovery(await recoveryChange(w, cred, pq))).to.be.revertedWithCustomError(
        w.vault,
        "TooEarly",
      );
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R5");

      // A recovery that installs a credential the LIVE floor cannot use is a
      // hollow remedy. The freeze is what makes this hold: the shape the quorum
      // proposed against is the shape the kernel still enforces afterwards.
      const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND,
        authorityGeneration: gen,
        params: spendParams(w.recipient, ethers.parseEther("1")),
        domain: DOMAIN.SPEND,
        nonce,
        deadline: FAR_DEADLINE,
      });
      const balBefore = await ethers.provider.getBalance(w.recipient);
      await (
        await w.vault.execute(
          w.recipient,
          ethers.parseEther("1"),
          nonce,
          FAR_DEADLINE,
          sign(cred, d),
          sign(pq, d),
          pqKeyBytes(pq),
        )
      ).wait();
      expect(await ethers.provider.getBalance(w.recipient)).to.equal(balBefore + ethers.parseEther("1"));
    });
  });

  // =====================================================================
  // R6 — possession is still real
  // =====================================================================
  describe("R6 — incoming possession remains required and verified", function () {
    it("a recovery whose incoming ECDSA possession proof is not held is still refused", async function () {
      const w = await deployWorld({ label: "sd1-r6a", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: pqHash(pq),
          newPqKey: pqKeyBytes(pq),
          // signed by the OUTGOING credential, which does not hold the incoming one
          newEcdsaPop: sign(w.credKey, pop),
          newPqPop: sign(pq, pop),
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await recoveryActive(w)).to.equal(true);
      await expectRecoveryExecutes(w, cred, pq, "R6a");
    });

    it("a recovery whose incoming PQ possession proof is not held is still refused BY THE VERIFIER", async function () {
      const w = await deployWorld({ label: "sd1-r6b", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: pqHash(pq),
          newPqKey: pqKeyBytes(pq),
          newEcdsaPop: sign(cred, pop),
          // a well-formed 65-byte signature by the WRONG key: it passes every
          // structural check and dies at the verifier, which is the point.
          newPqPop: sign(w.pqKey, pop),
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expectRecoveryExecutes(w, cred, pq, "R6b");
    });

    it("the structural length filter still rejects a wrong-shaped proof — it is now a CONSTANT, not removed", async function () {
      const w = await deployWorld({ label: "sd1-r6c", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: pqHash(pq),
          newPqKey: pqKeyBytes(pq),
          newEcdsaPop: sign(cred, pop),
          newPqPop: ethers.hexlify(new Uint8Array(64)),
        }),
        "a 64-byte PoP must still fail the kernel's own length comparison",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expectRecoveryExecutes(w, cred, pq, "R6c");
    });
  });

  // =====================================================================
  // R7 — replay, generation and digest binding are unchanged
  // =====================================================================
  describe("R7 — replay and generation binding unchanged", function () {
    it("the PoP digest is still NOT movable by the outgoing credential (#178 lesson preserved)", async function () {
      const w = await deployWorld({ label: "sd1-r7a", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const armed = (await w.vault.recoveryPossessionDigest()) as string;

      // Everything the outgoing credential can still do to the floor, done.
      const f = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.alwaysTrue, { ...f, pqParamLevel: f.pqParamLevel + 1 })).wait();
      expect(await w.vault.recoveryPossessionDigest(), "a floor ratchet must not move the PoP digest").to.equal(armed);

      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R7a");
    });

    it("a stale guardian generation still invalidates an approved request", async function () {
      const w = await deployWorld({ label: "sd1-r7b", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const newCommitment = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint64", "address[]", "bool[]"],
          [3n, w.guardians, w.guardianIsContract],
        ),
      );
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_GUARDIANS,
        authorityGeneration: gGen,
        params: newCommitment,
        domain: DOMAIN.GUARDIAN,
        nonce,
        deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.setGuardians(
          3n,
          w.guardians,
          w.guardianIsContract,
          {
            members: w.guardians,
            isContract: w.guardianIsContract,
            attestingIndices: [0, 1],
            attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
          },
          nonce,
          FAR_DEADLINE,
        )
      ).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await expect(w.vault.executeRecovery(await recoveryChange(w, cred, pq))).to.be.revertedWithCustomError(
        w.vault,
        "BadRoster",
      );
    });

    it("a consumed recovery cannot be replayed", async function () {
      const w = await deployWorld({ label: "sd1-r7c", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const change = await recoveryChange(w, cred, pq);
      await (await w.vault.executeRecovery(change)).wait();
      await expect(w.vault.executeRecovery(change)).to.be.revertedWithCustomError(w.vault, "NoRecovery");
    });
  });

  // =====================================================================
  // R8 — the challenge mechanism is exactly as it was
  // =====================================================================
  describe("R8 — challenge accounting unchanged", function () {
    it("two cancellations exhaust the budget, the third is refused, and a floor mutation is not an alternative currency", async function () {
      const w = await deployWorld({ label: "sd1-r8", verifier: "honest" });
      const cancel = async (): Promise<ethers.ContractTransactionResponse> => {
        const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
        const gen = (await w.vault.credentialGeneration()) as bigint;
        const d = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: KERNEL_GEN,
          actionType: ACTION.RECOVER,
          authorityGeneration: gen,
          params: ethers.id("CANCEL"),
          domain: DOMAIN.CREDENTIAL,
          nonce,
          deadline: FAR_DEADLINE,
        });
        return w.vault.cancelRecovery(nonce, FAR_DEADLINE, sign(w.credKey, d));
      };

      for (let i = 0; i < 2; i++) {
        await initiate(w);
        await (await cancel()).wait();
        expect(await challengesUsed(w)).to.equal(i + 1);
      }
      const { cred, pq } = await initiate(w);
      await expect(cancel()).to.be.revertedWithCustomError(w.vault, "ChallengeExhausted");

      const f = await liveFloor(w);
      await expect(setVerifierTx(w, w.verifiers.honest, { ...f, pqSignatureLength: 64 })).to.be.revertedWithCustomError(
        w.vault,
        "Downgrade",
      );
      expect(await challengesUsed(w), "the refusal must not touch the counter").to.equal(2);

      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R8");
    });
  });

  // =====================================================================
  // R9 — no cut moved
  // =====================================================================
  describe("R9 — authority cuts are preserved", function () {
    it("the floor still has NO guardian-reachable writer, and setVerifier is still HYBRID", async function () {
      const w = await deployWorld({ label: "sd1-r9a", verifier: "honest" });
      const f = await liveFloor(w);
      // ONE root (ECDSA alone) cannot move the verifier or the floor.
      await expect(
        setVerifierTx(w, w.verifiers.alwaysTrue, { ...f, pqParamLevel: f.pqParamLevel + 1 }, { pq: null }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // A guardian quorum recovering does not gain the floor either.
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R9a");
      expect(await liveFloor(w), "executeRecovery must not write the floor").to.deep.equal(f);
    });

    it("a stranger holding NO root can still do nothing", async function () {
      const w = await deployWorld({ label: "sd1-r9b", verifier: "honest" });
      const f = await liveFloor(w);
      await expect(
        setVerifierTx(w, w.verifiers.alwaysTrue, f, { cred: w.spareCred[2]!, pq: w.sparePq[2]! }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    });
  });

  // =====================================================================
  // PHASE 5 — adversarial permutations against the remediation itself
  // =====================================================================
  describe("ADVERSARIAL — attempts to reconstruct the veto through another route", function () {
    it("a verifier swap mid-recovery cannot veto: recovery verifies against the PROPOSED verifier", async function () {
      const w = await deployWorld({ label: "sd1-advA", verifier: "honest" });
      const { cred, pq } = await initiate(w, 0, w.verifiers.honest);
      const f = await liveFloor(w);
      // Install a verifier that refuses everything. The recovery does not consult it.
      await (await setVerifierTx(w, w.verifiers.alwaysFalse, f)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "advA");
    });

    it("a REVERTING verifier installed mid-recovery cannot veto either", async function () {
      const w = await deployWorld({ label: "sd1-advA2", verifier: "honest" });
      const { cred, pq } = await initiate(w, 0, w.verifiers.honest);
      const f = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.reverting, f)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "advA2");
    });

    it("a credential ROTATION mid-recovery cannot veto", async function () {
      const w = await deployWorld({ label: "sd1-advB", verifier: "honest" });
      const { cred, pq } = await initiate(w, 0);
      const nCred = w.spareCred[2]!;
      const nPq = w.sparePq[2]!;
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GEN,
        actionType: ACTION.ROTATE,
        authorityGeneration: gen,
        params: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(nCred), pqHash(nPq)]),
        ),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });
      const pop = (await w.vault.credentialPossessionDigest(addrOf(nCred), pqHash(nPq))) as string;
      await (
        await w.vault.rotateCredential(
          {
            newSigner: addrOf(nCred),
            newPqKeyHash: pqHash(nPq),
            newPqKey: pqKeyBytes(nPq),
            newEcdsaPop: sign(nCred, pop),
            newPqPop: sign(nPq, pop),
          },
          nonce,
          FAR_DEADLINE,
          sign(w.credKey, d),
          sign(w.pqKey, d),
          pqKeyBytes(w.pqKey),
        )
      ).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "advB");
    });

    it("strengthen -> propose -> strengthen -> execute holds across the whole schedule", async function () {
      const w = await deployWorld({ label: "sd1-advC", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel + 1 })).wait();
      const { cred, pq } = await initiate(w);
      const f1 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f1, pqParamLevel: f1.pqParamLevel + 1 })).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const f2 = await liveFloor(w);
      await expect(setVerifierTx(w, w.verifiers.honest, { ...f2, pqPublicKeyLength: 33 })).to.be.revertedWithCustomError(
        w.vault,
        "Downgrade",
      );
      await expectRecoveryExecutes(w, cred, pq, "advC");
    });

    it("BOUNDARY — the declared shape is magnitude-bounded, so no floor can demand calldata no block can carry", async function () {
      const w = await deployWorld({
        label: "sd1-advD",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // On an ECDSA-only vault the shape is still unset, so this is the one
      // transition that may declare it. It must be bounded.
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 4_294_967_295,
          pqSignatureLength: 65,
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 32,
          pqSignatureLength: 65_536,
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // The bound admits every NIST PQC shape, SPHINCS+-256f's 49,856-byte
      // signature included, so it costs no real configuration.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 64,
          pqSignatureLength: 49_856,
        })
      ).wait();
      expect((await liveFloor(w)).pqSignatureLength).to.equal(49_856);
    });

    it("BOUNDARY — the bound itself is EXACT: MAX_PQ_LENGTH is admitted and MAX_PQ_LENGTH + 1 is not", async function () {
      // Without this, a `>` -> `>=` off-by-one on the comparison would survive
      // every other check in the repository.
      const max = Number(await (await deployWorld({ label: "sd1-advD2-probe" })).vault.MAX_PQ_LENGTH());
      expect(max).to.equal(65_535);

      const accept = await deployWorld({
        label: "sd1-advD2a",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (
        await setVerifierTx(accept, accept.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: max,
          pqSignatureLength: max,
        })
      ).wait();
      expect((await liveFloor(accept)).pqSignatureLength, "exactly MAX_PQ_LENGTH must be ADMITTED").to.equal(max);

      const refuse = await deployWorld({
        label: "sd1-advD2b",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        setVerifierTx(refuse, refuse.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: max + 1,
          pqSignatureLength: 65,
        }),
        "MAX_PQ_LENGTH + 1 must be REFUSED",
      ).to.be.revertedWithCustomError(refuse.vault, "BadSignature");
    });

    it("a zero-length shape with a mandatory PQ conjunct is still refused, and a non-zero one is not", async function () {
      const w = await deployWorld({
        label: "sd1-advE",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 0,
          pqSignatureLength: 65,
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 32,
          pqSignatureLength: 0,
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // POSITIVE CONTROL — otherwise the two refusals above could be produced by
      // a kernel that refuses every floor, and would prove nothing.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 32,
          pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq).to.equal(true);
    });

    it("GENESIS — the magnitude bound also binds `initialize`, so an unsatisfiable vault cannot be born", async function () {
      // `_requireSaneFloor` is called from BOTH writers. The freeze makes the
      // genesis shape permanent, so a vault born with an unsatisfiable shape
      // would be permanently unusable — the bound must therefore refuse it at
      // birth, not only at setVerifier.
      const w = await deployWorld({ label: "sd1-advG", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      const genesis = (floor: Floor): Record<string, unknown> => ({
        signer: addrOf(w.credKey),
        pqKeyHash: pqHash(w.pqKey),
        verifier: w.verifiers.honest,
        threshold: w.threshold,
        guardians: w.guardians,
        guardianIsContract: w.guardianIsContract,
        floor: floorTuple(floor),
      });
      await expect(
        factory.deployVault(ethers.id("sd1-advG-over"), genesis({
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 65_536,
          pqSignatureLength: 65,
        })),
        "genesis must refuse a shape beyond MAX_PQ_LENGTH",
      ).to.revert(ethers);
      // POSITIVE CONTROL — the same genesis at the bound is admitted, so the
      // refusal above is the bound and not a blanket refusal to deploy.
      await (
        await factory.deployVault(ethers.id("sd1-advG-ok"), genesis({
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 65_535,
          pqSignatureLength: 65,
        }))
      ).wait();
    });

    it("a duplicate guardian attestation still cannot reach quorum", async function () {
      const w = await deployWorld({ label: "sd1-advF", verifier: "honest" });
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GEN,
        actionType: ACTION.RECOVER,
        authorityGeneration: gGen,
        params: recoverParams(addrOf(w.spareCred[0]!), pqHash(w.sparePq[0]!), w.verifiers.honest),
        domain: DOMAIN.GUARDIAN,
        nonce,
        deadline: FAR_DEADLINE,
      });
      await expect(
        w.vault.initiateRecovery(
          addrOf(w.spareCred[0]!),
          pqHash(w.sparePq[0]!),
          w.verifiers.honest,
          {
            members: w.guardians,
            isContract: w.guardianIsContract,
            attestingIndices: [0, 0],
            attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[0]!, d)],
          },
          nonce,
          FAR_DEADLINE,
        ),
      ).to.be.revertedWithCustomError(w.vault, "NotOrdered");
    });
  });

  // =====================================================================
  // THE DECLARED RESIDUAL — stated as an executed test, not as prose
  // =====================================================================
  describe("RESIDUAL — the ECDSA-only-genesis arming move, bounded and self-healing", function () {
    it("SD-4: on an ECDSA-only vault the requirePq false->true edge still invalidates ONE approved request, uncounted — and the quorum self-heals at k", async function () {
      // A LEGAL genesis nothing in this repository could previously build: no
      // mandatory PQ conjunct, but a PQ key ALREADY COMMITTED. `initialize`
      // refuses only requirePq WITH a zero commitment, so this is reachable.
      const w = await deployWorld({
        label: "sd1-residual",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      expect((await liveFloor(w)).requirePq).to.equal(false);
      expect(await w.vault.pqPublicKeyHash()).to.not.equal(ethers.ZeroHash);

      // The quorum approves a recovery whose PROPOSED verifier is the honest,
      // 32/65-bound one — the shape the vault has always published.
      const { cred, pq } = await initiate(w, 0, w.verifiers.honest);
      expect(await challengesUsed(w)).to.equal(0);

      // THE ARMING MOVE, at ONE root: `_authorise` degenerates to the ECDSA
      // conjunct on this vault, so no PQ factor is needed to make it. It declares
      // a 64-byte signature shape and installs a verifier that will accept one,
      // so the attacker keeps its own authority while the pending recovery —
      // measured against the honest verifier it named — dies.
      await (
        await setVerifierTx(
          w,
          w.verifiers.alwaysTrue,
          { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 },
          { pq: null },
        )
      ).wait();

      await networkHelpers.time.increase(7 * DAY + 1);
      await expect(
        w.vault.executeRecovery(await recoveryChange(w, cred, pq)),
        "RESIDUAL: the approved request is now unsatisfiable",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await challengesUsed(w), "RESIDUAL: and no challenge was consumed").to.equal(0);

      // THE BOUND, which is why this is a bounded defect and not a veto: the
      // shape is FROZEN from this moment, so the move is ONE-SHOT. The attacker
      // still holds its root and can still authorise — it simply cannot move the
      // shape a second time.
      const f = await liveFloor(w);
      await expect(
        setVerifierTx(
          w,
          w.verifiers.alwaysTrue,
          { ...f, pqSignatureLength: 63 },
          // 64 arbitrary bytes: the shape the attacker itself declared, waved
          // through by the always-true verifier it itself installed. The
          // attacker still holds full authority here — only the SHAPE is stuck.
          { pq: w.pqKey, pqSigOverride: ethers.hexlify(new Uint8Array(64).fill(3)) },
        ),
        "the arming move is one-shot: the shape is frozen immediately afterwards",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");

      // AND THE ESCAPE: the quorum re-proposes against the now-immovable shape
      // and completes at k. One uncounted move costs the quorum one
      // re-initiation, never the remedy.
      const re = await initiate(w, 1, w.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(re.cred),
          newPqKeyHash: pqHash(re.pq),
          newPqKey: pqKeyBytes(re.pq),
          newEcdsaPop: sign(re.cred, pop),
          // 64 bytes, matching the frozen shape; the proposed verifier accepts it.
          newPqPop: ethers.hexlify(new Uint8Array(64).fill(9)),
        })
      ).wait();
      expect(await w.vault.ecdsaSigner(), "the quorum escapes at k").to.equal(addrOf(re.cred));
    });
  });
});
