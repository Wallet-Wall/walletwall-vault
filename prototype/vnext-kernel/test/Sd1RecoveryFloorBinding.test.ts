/**
 * EXPERIMENTAL PROTOTYPE — SD-1's SECURITY GOAL, CARRIED FORWARD BY SD5-I.
 *
 * THE HISTORICAL RECORD, PRESERVED BECAUSE IT WAS CORRECT FOR ITS LANE.
 *
 * SD-1 was `setVerifier` writing `SecurityFloor.pqPublicKeyLength` /
 * `pqSignatureLength` freely while `_requireIncomingPossession` measured an
 * already-quorum-approved recovery against those fields LIVE. The credential
 * principal therefore held a veto over guardian recovery that the modelled
 * challenge counter never saw. SD-1's goal was stated then and is unchanged
 * now: NO CREDENTIAL-WRITABLE STATE MAY SIT IN AN APPROVED RECOVERY'S
 * SATISFIABILITY CONDITION.
 *
 * SD-1 reached that goal by making the state UNMOVABLE — `I-FLOOR-SHAPE-IMMUTABLE`,
 * a freeze on the two lengths once a PQ conjunct was mandatory. That remedy was
 * correct for SD-1's lane and this file pinned it. SD-5 then measured its cost:
 * the shape chosen once became permanent against EVERY principal, a guardian
 * quorum included, on HONEST vaults as much as captured ones
 * (PERMANENT_PQ_AGILITY_LOSS).
 *
 * WHAT THIS FILE PINS NOW — `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`:
 *
 *   for an APPROVED recovery request r, and for any `setVerifier` transition
 *   s -> s' that holds `requirePq` constant:
 *     executable(r, s') == executable(r, s)
 *   however s' differs from s in `pqPublicKeyLength`, `pqSignatureLength` or
 *   `pqParamLevel`.
 *
 * SD5-I reaches SD-1's goal by making that state UNREAD rather than unmovable,
 * which is strictly stronger — an unmovable field is still IN the satisfiability
 * condition, merely pinned — and which imposes no agility loss on honest vaults.
 * `I-FLOOR-SHAPE-IMMUTABLE` is therefore RETIRED, not weakened: with no
 * authoritative shape it has no operand left to constrain.
 *
 * THE CLASSIFICATION OF THE THREE FIELDS (SD5-A1R, verbatim). They are
 * SIGNED_METADATA + IDENTITY_BOUND_METADATA +
 * NON_AUTHORITATIVE_SECURITY_METADATA + ABI_COMPATIBILITY, and explicitly NOT
 * AUTHORIZATION_INPUT, NOT RECOVERY_SATISFIABILITY_INPUT, NOT
 * CRYPTOGRAPHIC_STRENGTH. The removed length gates were SHAPE-SCOPED: they
 * constrained an encoding's width and never the strength of the relation behind
 * it. No test in this file may reintroduce a length gate, a minimum length or an
 * exact-tuple allowlist as an expectation — a minimum was measured and REJECTED,
 * because "S = MIN + 1" defeats it.
 *
 * `requirePq` IS EXPLICITLY OUTSIDE THIS INVARIANT. It remains monotone
 * (`I-NO-SILENT-DOWNGRADE-G1`) and its false -> true declaring edge still
 * strands one approved ECDSA-only recovery, uncounted. That is SD-4, it is still
 * SUSTAINED, and the RESIDUAL block below asserts it as an executed test with a
 * control that attributes the strand to `requirePq` and to nothing else.
 *
 * WHY NOT A COUNTER, AND WHY NOT A SNAPSHOT — the SD-1-era reasoning is retained
 * because it still rules both out. `challengesUsed` bounds `cancelRecovery`
 * because a cancellation is REVERSIBLE by the defender; a floor write is not, so
 * a counter would bound only how many times an attacker re-chooses which
 * permanent state to inflict. A snapshot fails for the mirror-image reason:
 * `_authorise` reads the same live slot, so a poisoned floor stays absorbing.
 * Removing the read closes both at once, and R5 and R9 pin both halves.
 *
 * ATTRIBUTION, WHICH THIS FILE IS STRICT ABOUT. The kernel has three distinct
 * refusals on these paths and they must never be conflated:
 *   `Downgrade`      — `_requireNoDowngrade`, i.e. the requirePq conjunct;
 *   `BadSignature`   — a KERNEL leg: ECDSA recovery, the committed-key preimage,
 *                      or — on the possession path only — the verifier's own
 *                      refusal, which `_requireIncomingPossession` reports as
 *                      `BadSignature`;
 *   `VerifierDenied` — `_authorise`'s verifier refusal, reported distinctly.
 * A probe that dies at an earlier guard than its author believed proves nothing,
 * so every refusal below asserts its SPECIFIC error and, where the error alone
 * cannot attribute the cause, carries a second arm that removes the suspected
 * cause and observes the outcome flip.
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

/** The largest value the `uint32` length fields can hold. Nothing reads them. */
const UINT32_MAX = 4_294_967_295;

/**
 * A byte string of exactly `n` bytes. Still needed: the surviving half of
 * `I-COMMITMENT-EXHIBITED-AT-ADMISSION` requires genesis to exhibit a PREIMAGE
 * of the committed hash. It no longer needs to be exhibited AT A DECLARED
 * LENGTH — that conjunct went with the field's authority — which is precisely
 * what the genesis test below now measures.
 */
const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) {
    out += ethers.id(`${tag}-${i}`).slice(2);
    i += 1;
  }
  return "0x" + out.slice(0, n * 2);
};

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
    // The `pqKey` slot carries a SECOND role on the `requirePq` false -> true
    // edge: it is the exhibit for the declaration. SD5-I narrowed that exhibit to
    // its surviving half — the exact PREIMAGE of the committed `pqPublicKeyHash`
    // — and removed its length conjunct. It is the vault's committed PUBLIC key,
    // so supplying it grants authority to nobody, but omitting it makes every
    // legitimate declaration revert. Pinned in Sd34DeclarationInvariants.test.ts
    // and, for the surviving preimage half, in ADVERSARIAL/advE below.
    current.requirePq || floor.requirePq ? pqKeyBytes(pq ?? w.pqKey) : "0x",
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
 * several different branches, so a revert-selector assertion cannot tell a fixed
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

/**
 * A spend by the CURRENTLY INSTALLED credential, asserted by the balance delta.
 *
 * This is what stops "the recovery executed" from being a hollow result: a
 * kernel that installs a credential the live floor cannot use has moved the harm
 * rather than removed it.
 */
async function expectSpendWorks(
  w: World,
  cred: ethers.SigningKey,
  pq: ethers.SigningKey,
  note: string,
): Promise<void> {
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
  expect(
    await ethers.provider.getBalance(w.recipient),
    note + " — the installed credential must be able to spend",
  ).to.equal(balBefore + ethers.parseEther("1"));
}

describe("vNext kernel — SD-1's GOAL: I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE", function () {
  this.timeout(600_000);

  // =====================================================================
  // R1 — the exact SD-1 move, now admitted and consumed by nothing
  // =====================================================================
  describe("R1 — the sustained SD-1 counterexample is dead, by a different mechanism", function () {
    it("the exact SD-1 write is ADMITTED, and the recovery it existed to veto executes anyway", async function () {
      const w = await deployWorld({ label: "sd1-r1", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      expect(await recoveryActive(w)).to.equal(true);
      expect(await challengesUsed(w)).to.equal(0);

      const before = await liveFloor(w);
      expect(before.pqSignatureLength, "the honest floor records a 65-byte signature").to.equal(65);

      // The SD-1 move, verbatim: requirePq HELD, pqParamLevel HELD, ONE length
      // changed. Under SD-1's freeze this reverted `Downgrade`. It is now
      // ADMITTED — the write lands, and that is the amendment working rather than
      // a regression, because the field it writes has no reader on any
      // authorization, possession or satisfiability path.
      await (await setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 })).wait();
      const after = await liveFloor(w);
      expect(after.pqSignatureLength, "the SD-1 write LANDS — it is no longer refused").to.equal(64);
      expect(
        after.requirePq,
        "requirePq is held CONSTANT across the arm, so any delta is attributable to the metadata alone",
      ).to.equal(before.requirePq);

      // AND THE POINT: the recovery the SD-1 attack existed to veto completes,
      // measured on the INSTALL rather than on the absence of a revert.
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R1");
      expect(await challengesUsed(w), "no challenge was consumed, because there was never a veto").to.equal(0);
      await expectSpendWorks(w, cred, pq, "R1");
    });

    it("the same holds when the write lands BEFORE any request exists — the metadata is not absorbing", async function () {
      const w = await deployWorld({ label: "sd1-r1b", verifier: "honest" });
      const before = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 })).wait();
      const mid = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...mid, pqPublicKeyLength: 1 })).wait();
      expect(await liveFloor(w), "both writes land exactly as submitted").to.deep.equal({
        ...before,
        pqSignatureLength: 64,
        pqPublicKeyLength: 1,
      });

      // A quorum proposing AFTER the writes is unaffected. This is the schedule a
      // request-snapshot design could never close, because a snapshot faithfully
      // records an already-written floor; removing the READ closes every schedule
      // at once.
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R1b");
      await expectSpendWorks(w, cred, pq, "R1b");
    });
  });

  // =====================================================================
  // R2 / R3 — metadata independence at every schedule point
  // =====================================================================
  describe("R2/R3 — an APPROVED recovery is metadata-independent at every schedule point", function () {
    /**
     * Every mutation holds `requirePq` CONSTANT and moves only the three
     * NON_AUTHORITATIVE_SECURITY_METADATA fields, so an observed delta in
     * executability would be attributable to those fields and to nothing else.
     */
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
        name: "pqParamLevel LOWERED — the retired ratchet",
        label: "leveldown",
        mutate: (f) => ({ ...f, pqParamLevel: f.pqParamLevel - 1 }),
      },
      {
        name: "both lengths changed WITH a pqParamLevel increase — the SD-1 ledger's own fix sketch, which was never a fix",
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
      it("R2 — after quorum approval: " + m.name + " is ADMITTED and the recovery still executes", async function () {
        const w = await deployWorld({ label: "sd1-r2-" + m.label, verifier: "honest" });
        const { cred, pq } = await initiate(w);
        const before = await liveFloor(w);
        const target = m.mutate(before);
        expect(target.requirePq, "the mutation must hold requirePq constant").to.equal(before.requirePq);

        await (await setVerifierTx(w, w.verifiers.honest, target)).wait();
        expect(await liveFloor(w), "the write must land exactly as submitted").to.deep.equal(target);
        expect(await challengesUsed(w), "and must consume no challenge").to.equal(0);
        expect(await recoveryActive(w), "and must not destroy the approved request").to.equal(true);

        await networkHelpers.time.increase(7 * DAY + 1);
        await expectRecoveryExecutes(w, cred, pq, "R2/" + m.label);
        await expectSpendWorks(w, cred, pq, "R2/" + m.label);
      });
    }

    it("R3 — after MATURATION, inside the executable window, every mutation is still inert", async function () {
      const w = await deployWorld({ label: "sd1-r3", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      await networkHelpers.time.increase(7 * DAY + 1);
      const before = await liveFloor(w);
      for (const m of MUTATIONS) {
        const target = m.mutate(before);
        await (await setVerifierTx(w, w.verifiers.honest, target)).wait();
        expect(await liveFloor(w), m.name + " must land after maturation").to.deep.equal(target);
        expect(await recoveryActive(w), m.name + " must leave the matured request alive").to.equal(true);
      }
      expect(await challengesUsed(w)).to.equal(0);
      await expectRecoveryExecutes(w, cred, pq, "R3");
    });

    it("R2b — repeated metadata churn buys nothing, and the challenge budget is never touched", async function () {
      const w = await deployWorld({ label: "sd1-r2b", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const before = await liveFloor(w);
      for (let i = 0; i < 5; i++) {
        await (await setVerifierTx(w, w.verifiers.honest, { ...before, pqSignatureLength: 64 - i })).wait();
        expect((await liveFloor(w)).pqSignatureLength).to.equal(64 - i);
      }
      expect(await challengesUsed(w), "an ADMITTED metadata write is not a challenge").to.equal(0);
      expect(await recoveryActive(w)).to.equal(true);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R2b");
    });
  });

  // =====================================================================
  // R4 — what the floor may still do, and the ONE clause that still refuses
  // =====================================================================
  describe("R4 — floor evolution, and the surviving Downgrade clause", function () {
    it("a pqParamLevel increase is accepted, with and without a pending recovery", async function () {
      const w = await deployWorld({ label: "sd1-r4a", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel + 1 })).wait();
      expect((await liveFloor(w)).pqParamLevel).to.equal(f0.pqParamLevel + 1);

      const { cred, pq } = await initiate(w);
      const f1 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f1, pqParamLevel: f1.pqParamLevel + 7 })).wait();
      expect((await liveFloor(w)).pqParamLevel, "the level is writable mid-recovery").to.equal(f1.pqParamLevel + 7);
      expect(await challengesUsed(w), "and costs no challenge").to.equal(0);
      expect(await recoveryActive(w), "and does not destroy the approved request").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R4a");
    });

    it("requirePq true -> false is STILL refused; the pqParamLevel ratchet is RETIRED", async function () {
      const w = await deployWorld({ label: "sd1-r4b", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.alwaysTrue, f0)).wait();
      expect(await w.vault.pqVerifier()).to.equal(w.verifiers.alwaysTrue);

      // THE SURVIVING LEG of `I-NO-SILENT-DOWNGRADE`, now `-G1`: a mandatory PQ
      // conjunct may not be silently disabled. It is the ONLY clause left, and it
      // is asserted here so `Downgrade` is proven REACHABLE — without which the
      // admissions below could be produced by a kernel that refuses nothing.
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...f0, requirePq: false }),
        "requirePq true -> false must still revert Downgrade",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");

      // RETIRED: a pqParamLevel DECREASE was `Downgrade` and is now ADMITTED.
      // Architecture section 12 withdrew the flat strength scalar this field
      // instantiates, so ratcheting it asserted an ordering the kernel cannot
      // justify — the LABEL of an upgrade without its SUBSTANCE.
      await (await setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel - 1 })).wait();
      expect((await liveFloor(w)).pqParamLevel, "the level moved DOWN").to.equal(f0.pqParamLevel - 1);

      // ...and the surviving clause is undisturbed by having moved the level.
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...(await liveFloor(w)), requirePq: false }),
        "the requirePq clause still refuses from the lowered floor",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    });

    it("an ECDSA-ONLY vault may raise requirePq, and the shape it declares is NOT frozen afterwards", async function () {
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

      // RETIRED: the declaration used to freeze the shape from this moment on. It
      // no longer does, and the vault stays usable across the change.
      await (await setVerifierTx(w, w.verifiers.honest, { ...f1, pqSignatureLength: 64 })).wait();
      expect((await liveFloor(w)).pqSignatureLength, "the declared shape is not frozen").to.equal(64);
      expect((await liveFloor(w)).requirePq, "but requirePq is latched ON").to.equal(true);
      await expect(
        setVerifierTx(w, w.verifiers.honest, { ...(await liveFloor(w)), requirePq: false }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      await expectSpendWorks(w, w.credKey, w.pqKey, "R4c");
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
      // hollow remedy. Under SD-1 the freeze is what made this hold; under SD5-I
      // it holds because `_authorise` does not consult the shape fields at all.
      await expectSpendWorks(w, cred, pq, "R5");
    });
  });

  // =====================================================================
  // R6 — possession is still real, and each refusal is ATTRIBUTED
  // =====================================================================
  describe("R6 — incoming possession remains required, verified, and correctly attributed", function () {
    it("a recovery whose incoming ECDSA possession proof is not held is still refused BY THE KERNEL", async function () {
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

    it("a wrong-KEY PQ possession proof is refused BY THE VERIFIER — proven by flipping the verifier, not by the selector", async function () {
      // ARM 1 — honest verifier. `_requireIncomingPossession` reports a verifier
      // refusal as `BadSignature`, the SAME selector its own kernel legs use, so
      // the selector alone cannot attribute this. Arm 2 supplies the attribution.
      const w = await deployWorld({ label: "sd1-r6b", verifier: "honest" });
      const { cred, pq } = await initiate(w, 0, w.verifiers.honest);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: pqHash(pq),
          newPqKey: pqKeyBytes(pq),
          newEcdsaPop: sign(cred, pop),
          // a well-formed 65-byte signature by the WRONG key: it satisfies every
          // KERNEL leg — cross-check, ECDSA PoP, committed-key preimage — so the
          // only guard left to kill it is the verifier.
          newPqPop: sign(w.pqKey, pop),
        }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expectRecoveryExecutes(w, cred, pq, "R6b/honest");

      // ARM 2 — the SAME material against a verifier that accepts everything. It
      // EXECUTES, which proves arm 1 died at the verifier and not at an earlier
      // kernel guard.
      const w2 = await deployWorld({ label: "sd1-r6b2", verifier: "honest" });
      const r2 = await initiate(w2, 0, w2.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop2 = (await w2.vault.recoveryPossessionDigest()) as string;
      await (
        await w2.vault.executeRecovery({
          newSigner: addrOf(r2.cred),
          newPqKeyHash: pqHash(r2.pq),
          newPqKey: pqKeyBytes(r2.pq),
          newEcdsaPop: sign(r2.cred, pop2),
          newPqPop: sign(w2.pqKey, pop2),
        })
      ).wait();
      expect(await w2.vault.ecdsaSigner(), "arm 2 must EXECUTE, attributing arm 1's refusal to the verifier").to.equal(
        addrOf(r2.cred),
      );
    });

    it("a wrong-LENGTH PQ possession proof is refused BY THE VERIFIER ONLY — the kernel imposes no length gate", async function () {
      // INVERTED BY SD5-I. This probe formerly asserted that the KERNEL's own
      // length comparison rejected a 64-byte PoP. That comparison is REMOVED, so
      // the assertion's operand is gone; what replaces it is the measurement of
      // WHO refuses now. Scheme-specific structural validity is the verifier's
      // duty — FIPS 204 3.6.2 binds an ML-DSA IMPLEMENTATION to return false on
      // wrong-length inputs and places no duty on a scheme-agnostic caller — and
      // `EcdsaBackedVerifier` discharges it for this harness's stand-in scheme.
      //
      // NOTE, because this file must not overclaim: a verifier returning false on
      // a wrong length does NOT establish that it exposes only one accepting
      // relation. A conforming strong leg can coexist with a forgeable second
      // leg; that is residual SD-11 and is out of scope here.
      const w = await deployWorld({ label: "sd1-r6c", verifier: "honest" });
      const { cred, pq } = await initiate(w, 0, w.verifiers.honest);
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
        "a 64-byte PoP must still be refused when an honest verifier is bound",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expectRecoveryExecutes(w, cred, pq, "R6c/honest");

      // ARM 2 — the identical 64-byte PoP against an always-true verifier
      // EXECUTES. That is the measurement: no kernel-side length gate survives,
      // and the refusal in arm 1 was the verifier's alone.
      const w2 = await deployWorld({ label: "sd1-r6c2", verifier: "honest" });
      const r2 = await initiate(w2, 0, w2.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop2 = (await w2.vault.recoveryPossessionDigest()) as string;
      await (
        await w2.vault.executeRecovery({
          newSigner: addrOf(r2.cred),
          newPqKeyHash: pqHash(r2.pq),
          newPqKey: pqKeyBytes(r2.pq),
          newEcdsaPop: sign(r2.cred, pop2),
          newPqPop: ethers.hexlify(new Uint8Array(64)),
        })
      ).wait();
      expect(await w2.vault.ecdsaSigner(), "the kernel itself measures no PoP length").to.equal(addrOf(r2.cred));

      // ...and the KERNEL's own leg on that same path is still live: a `newPqKey`
      // that is not the committed preimage is refused even by the always-true
      // verifier, so arm 2 is not "the kernel checks nothing".
      const w3 = await deployWorld({ label: "sd1-r6c3", verifier: "honest" });
      const r3 = await initiate(w3, 0, w3.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop3 = (await w3.vault.recoveryPossessionDigest()) as string;
      await expect(
        w3.vault.executeRecovery({
          newSigner: addrOf(r3.cred),
          newPqKeyHash: pqHash(r3.pq),
          newPqKey: pqKeyBytes(w3.sparePq[1]!),
          newEcdsaPop: sign(r3.cred, pop3),
          newPqPop: ethers.hexlify(new Uint8Array(64)),
        }),
        "the committed-key preimage is a KERNEL leg and survives an always-true verifier",
      ).to.be.revertedWithCustomError(w3.vault, "BadSignature");
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

      // Everything the outgoing credential can still do to the floor, done: all
      // three metadata fields moved at once, requirePq held.
      const f = await liveFloor(w);
      await (
        await setVerifierTx(w, w.verifiers.alwaysTrue, {
          ...f,
          pqParamLevel: f.pqParamLevel + 1,
          pqPublicKeyLength: 1,
          pqSignatureLength: 1,
        })
      ).wait();
      expect(await w.vault.recoveryPossessionDigest(), "a floor write must not move the PoP digest").to.equal(armed);

      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R7a");
    });

    it("a guardian-set change does NOT invalidate an approved request (SD-10 corrected); the possession digest is unmoved by it", async function () {
      // INVERTED BY LANE SD10-I. This R7 probe asserted `BadRoster` — it pinned
      // what the kernel did, and what the kernel did was SD-10. Its place in the
      // R7 series is "the armed possession digest is not moved by things that
      // happen around it", and that claim is UNCHANGED and now carries further:
      // the digest binds `boundGuardianGeneration`, which stays pinned at the
      // approving generation, so the roster change moves neither the digest nor
      // the request's executability.
      const w = await deployWorld({ label: "sd1-r7b", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const armed = (await w.vault.recoveryPossessionDigest()) as string;
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
      expect((await w.vault.guardianGeneration()) as bigint, "the generation advanced").to.equal(gGen + 1n);
      expect(await w.vault.recoveryPossessionDigest(), "a roster change must not move the PoP digest").to.equal(armed);
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "R7b");
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
    it("two cancellations exhaust the budget, the third is refused, and metadata is not an alternative currency", async function () {
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

      // The budget is now exhausted, so metadata is the only lever the credential
      // has left. It is ADMITTED — and it is neither a challenge nor a veto.
      const f = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f, pqSignatureLength: 64 })).wait();
      expect((await liveFloor(w)).pqSignatureLength).to.equal(64);
      expect(await challengesUsed(w), "an admitted metadata write must not touch the counter").to.equal(2);

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

      // ONE root (ECDSA alone) cannot move the verifier or the floor. THE
      // ATTRIBUTION CHANGED AND IS ASSERTED RATHER THAN ASSUMED: this probe used
      // to die at the kernel's `pqSig.length` comparison (`BadSignature`). That
      // gate is removed, so an empty PQ signature now reaches the verifier and is
      // refused there — `_authorise` reports that as `VerifierDenied`, a
      // DIFFERENT selector. The cut is unmoved; the guard enforcing it is not the
      // same one, and asserting the old selector would be exactly the
      // "the probe died at a different guard than you think" error.
      await expect(
        setVerifierTx(w, w.verifiers.alwaysTrue, { ...f, pqParamLevel: f.pqParamLevel + 1 }, { pq: null }),
        "ECDSA alone is refused, now by the verifier plane",
      ).to.be.revertedWithCustomError(w.vault, "VerifierDenied");

      // ...and the KERNEL's own leg on the same path is still live and reports
      // `BadSignature`: an exhibited key that is not the committed preimage never
      // reaches the verifier at all. Both legs, both selectors, both proven.
      await expect(
        setVerifierTx(w, w.verifiers.alwaysTrue, { ...f, pqParamLevel: f.pqParamLevel + 1 }, { pq: w.sparePq[1]! }),
        "a non-preimage key is refused by the kernel, before the verifier",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      expect(await liveFloor(w), "neither refusal wrote the floor").to.deep.equal(f);

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

    it("strengthen -> propose -> churn metadata -> execute holds across the whole schedule", async function () {
      const w = await deployWorld({ label: "sd1-advC", verifier: "honest" });
      const f0 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f0, pqParamLevel: f0.pqParamLevel + 1 })).wait();
      const { cred, pq } = await initiate(w);
      const f1 = await liveFloor(w);
      await (await setVerifierTx(w, w.verifiers.honest, { ...f1, pqParamLevel: f1.pqParamLevel + 1 })).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const f2 = await liveFloor(w);
      // Formerly `Downgrade`; now ADMITTED, inside the executable window.
      await (await setVerifierTx(w, w.verifiers.honest, { ...f2, pqPublicKeyLength: 33 })).wait();
      expect((await liveFloor(w)).pqPublicKeyLength).to.equal(33);
      await expectRecoveryExecutes(w, cred, pq, "advC");
    });

    it("BOUNDARY — an ABSURD declared shape is admitted and demands nothing: no calldata, no veto, no strand", async function () {
      // INVERTED BY SD5-I. This slot formerly asserted a magnitude bound
      // (`MAX_PQ_LENGTH`) whose stated purpose was "no floor may demand calldata
      // no block can carry". Nothing demands that calldata any more, because
      // nothing reads the fields, so the bound's operand is gone and asserting it
      // would be asserting nothing. What replaces it is the sharper measurement:
      // the fields may name `type(uint32).max` and not one byte is asked for.
      //
      // NO MINIMUM AND NO ALLOWLIST IS REINTRODUCED HERE, deliberately: a minimum
      // was measured and REJECTED, because a caller choosing S = MIN + 1 defeats
      // it while looking compliant.
      const w = await deployWorld({ label: "sd1-advD", verifier: "honest" });
      const { cred, pq } = await initiate(w);
      const f = await liveFloor(w);
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          ...f,
          pqPublicKeyLength: UINT32_MAX,
          pqSignatureLength: UINT32_MAX,
        })
      ).wait();
      const after = await liveFloor(w);
      expect(after.pqPublicKeyLength, "an absurd shape is ADMITTED").to.equal(UINT32_MAX);
      expect(after.pqSignatureLength).to.equal(UINT32_MAX);
      expect(after.requirePq, "requirePq held constant across the arm").to.equal(f.requirePq);

      // `MAX_PQ_LENGTH` remains on the ABI — ABI_COMPATIBILITY, part of the
      // byte-identical selector surface SD5-A1R measured — and it now has NO
      // READER. The write above is the proof: a floor above the constant landed.
      // It must never again be documented as preventing unsatisfiable floors.
      expect(Number(await w.vault.MAX_PQ_LENGTH()), "the constant is retained for ABI compatibility only").to.equal(
        65_535,
      );

      // The approved recovery executes with a 32-byte key and a 65-byte PoP,
      // against a floor naming four billion of each.
      await networkHelpers.time.increase(7 * DAY + 1);
      await expectRecoveryExecutes(w, cred, pq, "advD");
      await expectSpendWorks(w, cred, pq, "advD");
    });

    it("the declaring edge still demands the COMMITTED PREIMAGE, and a zero-length shape no longer means anything", async function () {
      // NARROWED BY SD5-I. `I-DECLARATION-EXHIBITED` had two conjuncts on the
      // `requirePq` false -> true edge. The LENGTH conjunct went with the field's
      // authority; the PREIMAGE conjunct SURVIVES and is the one asserted here.
      // The old zero-shape refusals rested on `_requireSaneFloor`, which is now
      // vacuous — there is no shape left to render unsatisfiable.
      const w = await deployWorld({
        label: "sd1-advE",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      expect((await liveFloor(w)).requirePq).to.equal(false);

      // SURVIVING LEG: a declaration exhibiting a key that is NOT a preimage of
      // the committed `pqPublicKeyHash` is refused. Note the discrimination: this
      // edge takes no PQ signature (the CURRENT floor requires none), so the ONLY
      // difference from the accepted call below is the exhibited key.
      await expect(
        setVerifierTx(
          w,
          w.verifiers.honest,
          { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
          { pq: w.sparePq[0]! },
        ),
        "a declaration must exhibit the COMMITTED preimage",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the refused declaration latched nothing").to.equal(false);

      // INVERTED: with the correct preimage, a ZERO-length shape is ADMITTED.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true,
          pqParamLevel: 0,
          pqPublicKeyLength: 0,
          pqSignatureLength: 0,
        })
      ).wait();
      expect(await liveFloor(w), "a zero shape is now an ordinary metadata value").to.deep.equal({
        requirePq: true,
        pqParamLevel: 0,
        pqPublicKeyLength: 0,
        pqSignatureLength: 0,
      });

      // POSITIVE CONTROL — a vault declaring a zero shape is NOT bricked, which is
      // exactly the claim `_requireSaneFloor` existed to protect and which is now
      // discharged by the field having no reader.
      await expectSpendWorks(w, w.credKey, w.pqKey, "advE");
    });

    it("GENESIS — `initialize` admits any declared shape; its surviving conjunct is the PREIMAGE", async function () {
      // INVERTED BY SD5-I. `_requireSaneFloor` runs on both writers and is now
      // vacuous, and the genesis key-LENGTH conjunct is removed, so a vault may be
      // born declaring any shape. That is safe for the same reason the transition
      // is: nothing reads it. What genesis still enforces — and what makes the
      // kernel's later keccak measurement an INDUCTIVE invariant rather than an
      // assumption — is that a PREIMAGE of the committed hash was exhibited at
      // admission.
      const w = await deployWorld({ label: "sd1-advG", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      const key = bytesOfLength(32, "sd1-advG-key");
      const genesis = (floor: Floor, keyHash: string): Record<string, unknown> => ({
        signer: addrOf(w.credKey),
        pqKeyHash: keyHash,
        verifier: w.verifiers.honest,
        threshold: w.threshold,
        guardians: w.guardians,
        guardianIsContract: w.guardianIsContract,
        floor: floorTuple(floor),
      });

      // ADMITTED: a declared shape far beyond the retained `MAX_PQ_LENGTH`, and a
      // 32-byte exhibit that matches NONE of it. The two are unrelated now.
      await (
        await factory.deployVault(
          ethers.id("sd1-advG-huge"),
          genesis(
            { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 65_536, pqSignatureLength: UINT32_MAX },
            ethers.keccak256(key),
          ),
          key,
        )
      ).wait();

      // SURVIVING LEG: a witness that is not a preimage of the committed hash is
      // refused at birth. Same floor, same commitment — only the exhibit differs.
      await expect(
        factory.deployVault(
          ethers.id("sd1-advG-badwitness"),
          genesis(
            { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
            ethers.keccak256(key),
          ),
          bytesOfLength(32, "sd1-advG-other"),
        ),
        "genesis must refuse a witness that is not the committed preimage",
      ).to.revert(ethers);

      // POSITIVE CONTROL — the SAME floor with the CORRECT exhibit is admitted, so
      // the refusal above is the preimage conjunct and not a blanket refusal.
      await (
        await factory.deployVault(
          ethers.id("sd1-advG-ok"),
          genesis(
            { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
            ethers.keccak256(key),
          ),
          key,
        )
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
  // THE DECLARED RESIDUAL — STILL OPEN, AND NARROWED TO ITS TRUE OPERAND
  // =====================================================================
  describe("RESIDUAL — SD-4, declared by this lane and STILL SUSTAINED", function () {
    /**
     * SD-4: on a vault born ECDSA-only, the `requirePq` false -> true edge can
     * invalidate ONE approved recovery, uncounted, at cut 1.
     *
     * A later lane closed SD-3 on the same edge and then tried to close this one
     * too, with an interlock refusing the declaration while a live request
     * exists. That interlock was built, measured and REMOVED: the declaration is
     * ONE-SHOT and no guardian path can write `securityFloor`, so refusing it
     * hands the quorum a renewable veto over a capability it cannot itself
     * exercise. SD-4 therefore remains SUSTAINED.
     *
     * WHAT SD5-I CHANGED HERE, AND WHAT IT DID NOT. The old exhibit took its
     * strand in `pqSignatureLength` — it declared a 64-byte signature shape
     * against a 65-byte PoP. That exhibit is CLOSED: the length is not read. The
     * residual survives on its true operand, `requirePq` itself: a recovery
     * proposing an ECDSA-ONLY replacement (`proposedPqKeyHash == 0`) is
     * admissible while the conjunct is dormant and becomes unsatisfiable the
     * moment it is armed, since no preimage hashes to `bytes32(0)`.
     *
     * `requirePq` is EXPLICITLY OUTSIDE
     * `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` — not as an exception
     * carved into that invariant, but because it is a different field with a
     * different classification. The CONTROL below holds the three metadata
     * fields IDENTICAL across both arms and varies only `requirePq`, so the
     * strand is attributed to `requirePq` alone and cannot be misread as a
     * metadata effect.
     */
    it("SD-4 — SUSTAINED: arming requirePq still destroys an approved ECDSA-only recovery, uncounted", async function () {
      const w = await deployWorld({
        label: "sd1-residual",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      expect((await liveFloor(w)).requirePq).to.equal(false);
      expect(await w.vault.pqPublicKeyHash()).to.not.equal(ethers.ZeroHash);

      // The quorum approves an ECDSA-ONLY replacement credential.
      const { cred } = await initiate(w, 0, w.verifiers.honest, ethers.ZeroHash);
      expect(await challengesUsed(w)).to.equal(0);

      // A declaration the vault's OWN committed key satisfies exactly.
      await (
        await setVerifierTx(w, w.verifiers.alwaysTrue, {
          requirePq: true,
          pqParamLevel: 1,
          pqPublicKeyLength: 32,
          pqSignatureLength: 64,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "SUSTAINED: the declaration succeeds").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: ethers.ZeroHash,
          newPqKey: "0x",
          newEcdsaPop: sign(cred, pop),
          newPqPop: "0x",
        }),
        "SUSTAINED (SD-4): the approved recovery is now unexecutable",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await challengesUsed(w), "SUSTAINED: and no challenge was consumed").to.equal(0);
      expect(await recoveryActive(w), "the request is stranded, not consumed").to.equal(true);
    });

    it("CONTROL — the SAME metadata with requirePq HELD FALSE strands nothing", async function () {
      const w = await deployWorld({
        label: "sd1-residual-control",
        verifier: "honest",
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const { cred } = await initiate(w, 0, w.verifiers.honest, ethers.ZeroHash);

      // Byte-for-byte the metadata of the arm above; only `requirePq` differs.
      await (
        await setVerifierTx(w, w.verifiers.alwaysTrue, {
          requirePq: false,
          pqParamLevel: 1,
          pqPublicKeyLength: 32,
          pqSignatureLength: 64,
        })
      ).wait();
      expect(await liveFloor(w)).to.deep.equal({
        requirePq: false,
        pqParamLevel: 1,
        pqPublicKeyLength: 32,
        pqSignatureLength: 64,
      });

      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      const genBefore = (await w.vault.credentialGeneration()) as bigint;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(cred),
          newPqKeyHash: ethers.ZeroHash,
          newPqKey: "0x",
          newEcdsaPop: sign(cred, pop),
          newPqPop: "0x",
        })
      ).wait();
      expect(await w.vault.ecdsaSigner(), "the recovery EXECUTES").to.equal(addrOf(cred));
      expect((await w.vault.credentialGeneration()) as bigint).to.equal(genBefore + 1n);
      expect(await recoveryActive(w)).to.equal(false);
    });
  });
});
