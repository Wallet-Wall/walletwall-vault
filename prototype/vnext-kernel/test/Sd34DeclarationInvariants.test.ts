/**
 * EXPERIMENTAL PROTOTYPE — SD-3 REMEDIATION REGRESSION SUITE.
 *
 * ONE INVARIANT OVER ONE TRANSITION, and the proof that a SECOND was needed and
 * could not be had. SD-3 and SD-4 are both the `requirePq`
 * false -> true edge in `setVerifier` — the single moment in a vault's life at
 * which the PQ authentication shape is declared. They are nonetheless
 * INDEPENDENT, and neither implies the other:
 *
 *   I-DECLARATION-EXHIBITED  (closes SD-3) — NARROWED BY SD5-I
 *     For every accepted setVerifier transition s -> s' with
 *     !s.requirePq && s'.requirePq, the call must exhibit a byte string K with
 *     keccak256(K) == s.pqPublicKeyHash.
 *     Equivalently: the kernel's own spending conjunct is satisfiable by
 *     material actually produced on chain, not merely non-zero.
 *
 *     THE INVARIANT HAD TWO LEGS AND NOW HAS ONE. The second conjunct,
 *     |K| == s'.pqPublicKeyLength, is REMOVED together with the field's
 *     authority. Under the E-PRIME amendment `pqPublicKeyLength`,
 *     `pqSignatureLength` and `pqParamLevel` are SIGNED_METADATA +
 *     IDENTITY_BOUND_METADATA + NON_AUTHORITATIVE_SECURITY_METADATA +
 *     ABI_COMPATIBILITY, and explicitly NOT AUTHORIZATION_INPUT, NOT
 *     RECOVERY_SATISFIABILITY_INPUT, NOT CRYPTOGRAPHIC_STRENGTH. No
 *     authorization, possession or recovery-satisfiability path reads them, so a
 *     conjunct over them asserts nothing; it is DELETED here rather than left
 *     vacuously green while appearing to measure something.
 *
 *     THE NARROWING COSTS THIS FILE NOTHING IT EVER HELD. The removed leg was
 *     SHAPE-SCOPED. SD-5 Form B reproduced against an HONEST incumbent key AT
 *     THE CORRECT KEY LENGTH, taking its vacuity entirely in
 *     `pqSignatureLength`, so the length leg never bound the reachable capture
 *     in the first place. What the exhibit proves is UNCHANGED and deliberately
 *     narrow: a preimage of the committed hash was known at declaration. It has
 *     never proven possession of a signing capability, and SD-8 is untouched in
 *     both directions.
 *
 * SD-4 IS NOT CLOSED, and that is a decision rather than an omission. The
 * exhibit binds `pqPublicKeyHash`; SD-4 is about `recovery.proposedPqKeyHash` —
 * different variables, chosen by different principals — and in the SD-4
 * counterexample the declared key length MATCHES the incumbent exactly, so the
 * exhibit passed on both of its former conjuncts and passes on the single
 * surviving one, while the quorum's proposal still dies. No exhibit-shaped fix
 * could ever have closed it.
 *
 * The obvious second clause — refuse the declaration while a live approved
 * recovery exists — was implemented, measured and REMOVED. The declaration is
 * ONE-SHOT and no guardian path can ever write `securityFloor`, so that refusal
 * hands the quorum a renewable, uncounted veto over a capability it cannot
 * itself exercise, pinning an ECDSA-only vault at asset-control cut 1 forever.
 * Trading a bounded one-shot credential harm for an unbounded guardian one is
 * not a remediation. SD-4 therefore stays SUSTAINED, with its analysis and the
 * only sound design recorded in `stateful/defects.ts`, and — for the first time
 * — with a CAMPAIGN PROPERTY (`G-DECLARATION-SUBORDINATE-TO-RECOVERY`) that
 * observes it across 224 campaigns instead of a narrative argument.
 *
 * THE EXHIBIT IS A SATISFIABILITY WITNESS, NOT AN AUTHORITY GATE. `pqKey` is a
 * PUBLIC key and is deliberately not covered by the action digest, so a relayer
 * rewriting it can only make the call REVERT — never make it accept a
 * configuration the signer did not authorise. The edge's cut is 1 before and 1
 * after; nothing here should be read as raising it.
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
const HYBRID = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/** `setVerifier` as the credential principal, with full control of the exhibited key. */
async function arm(
  w: World,
  floor: Floor,
  opts: { verifier?: string; cred?: ethers.SigningKey; pqKey?: string; pqSig?: string } = {},
): Promise<ethers.ContractTransactionResponse> {
  const verifier = opts.verifier ?? w.verifiers.honest;
  const cred = opts.cred ?? w.credKey;
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
    opts.pqSig ?? (current.requirePq ? sign(w.pqKey, d) : "0x"),
    // The exhibit. Defaults to the vault's own committed key, which is the
    // honest operator's case; every attack below overrides it.
    opts.pqKey ?? pqKeyBytes(w.pqKey),
  );
}

async function initiate(w: World, i: number, verifier: string, pqKeyHash: string): Promise<ethers.SigningKey> {
  const cred = w.spareCred[i]!;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER, authorityGeneration: gGen,
    params: recoverParams(addrOf(cred), pqKeyHash, verifier),
    domain: DOMAIN.GUARDIAN, nonce, deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.initiateRecovery(addrOf(cred), pqKeyHash, verifier, {
      members: w.guardians, isContract: w.guardianIsContract,
      attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
    }, nonce, FAR_DEADLINE)
  ).wait();
  return cred;
}

/** Rotates the credential, which on an ECDSA-only vault also installs any PQ commitment. */
async function rotateTo(w: World, cred: ethers.SigningKey, pqKeyHash: string, pqKey: string): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.ROTATE, authorityGeneration: gen,
    params: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(cred), pqKeyHash]),
    ),
    domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
  });
  const pop = (await w.vault.credentialPossessionDigest(addrOf(cred), pqKeyHash)) as string;
  await (
    await w.vault.rotateCredential(
      { newSigner: addrOf(cred), newPqKeyHash: pqKeyHash, newPqKey: pqKey, newEcdsaPop: sign(cred, pop), newPqPop: "0x" },
      nonce, FAR_DEADLINE, sign(w.credKey, d), "0x", "0x",
    )
  ).wait();
}

const keyOfLength = (n: number, fill: number): string => ethers.hexlify(new Uint8Array(n).fill(fill));
const RECOVERY = { CHALLENGES: 6, ACTIVE: 7 } as const;

/** Spends 1 ETH under the given material, proving the vault is genuinely usable. */
async function expectSpends(w: World, cred: ethers.SigningKey, pq: ethers.SigningKey, note: string): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SPEND, authorityGeneration: gen,
    params: spendParams(w.recipient, ethers.parseEther("1")),
    domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
  });
  const before = await ethers.provider.getBalance(w.recipient);
  await (
    await w.vault.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE,
      sign(cred, d), sign(pq, d), pqKeyBytes(pq))
  ).wait();
  expect(await ethers.provider.getBalance(w.recipient), note).to.equal(before + ethers.parseEther("1"));
}

describe("vNext kernel — SD-3 REMEDIATION: I-DECLARATION-EXHIBITED", function () {
  this.timeout(600_000);

  // =====================================================================
  // I-DECLARATION-EXHIBITED
  // =====================================================================
  describe("I-DECLARATION-EXHIBITED — a declaration must be satisfiable by the committed material", function () {
    it("SD-3 FORM 1 — arming against a ZERO commitment is refused", async function () {
      const w = await deployWorld({ label: "d-e1", verifier: "honest", ecdsaOnlyFloor: true });
      expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
      await expect(arm(w, HYBRID, { pqKey: pqKeyBytes(w.pqKey) })).to.be.revertedWithCustomError(
        w.vault, "BadSignature",
      );
      await expect(arm(w, HYBRID, { pqKey: "0x" })).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the floor did not move").to.equal(false);
    });

    it("SD-3 FORM 2 (NARROWED) — a key that is not the committed preimage is refused at ANY declared length", async function () {
      // NARROWED, not weakened. This `it` formerly asserted a SHAPE refusal and a
      // PREIMAGE refusal in one breath. Only the preimage leg survives SD5-I, and
      // it carries the invariant's whole content. To keep the surviving leg
      // MEASURED rather than incidentally green, the declared length is varied
      // ACROSS the two probes: the refusal must not depend on it.
      const w = await deployWorld({
        label: "d-e2", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // A perfectly good NON-ZERO commitment whose preimage is 32 bytes.
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 33 }, { pqKey: keyOfLength(33, 1) }),
        "a 33-byte stranger key does not hash to the committed key's hash",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 32 }, { pqKey: keyOfLength(33, 1) }),
        "and declaring the 'right' length rescues it no better — the hash is what binds",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("SD5-I INVERSION — a declared pqPublicKeyLength that contradicts the exhibit is ACCEPTED, and the armed vault spends", async function () {
      // INVERTED. Before SD5-I this exact call reverted `BadSignature`, because
      // `_authorise`/the declaring edge compared |pqKey| against the declared
      // number. That comparison is gone with the field's authority, so the
      // NEW behaviour is what must now be pinned — and pinning it as an
      // acceptance plus a working spend is what proves the field is not read,
      // rather than assuming it.
      //
      // TWO-ARM NOTE: the sharpest form of this is a BASE-vs-IMPLEMENTED
      // discrimination against the pre-SD5-I kernel. This is a TRACKED test and
      // the BASE artefact lives only in the UNTRACKED sd5-scratch/, so the
      // two-arm version belongs in a follow-up PERMANENT harness. What is
      // asserted here needs no BASE arm: acceptance plus a completed spend at a
      // declared length the exhibited key does not have.
      const w = await deployWorld({
        label: "d-e2b", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const committed = pqKeyBytes(w.pqKey);
      expect(ethers.dataLength(committed), "the committed preimage really is 32 bytes").to.equal(32);
      await (await arm(w, { ...HYBRID, pqPublicKeyLength: 33 }, { pqKey: committed })).wait();
      const f = await liveFloor(w);
      expect(f.requirePq, "the declaration landed").to.equal(true);
      expect(f.pqPublicKeyLength, "and the contradictory number was recorded verbatim").to.equal(33);
      // NON_AUTHORITATIVE_SECURITY_METADATA, demonstrated rather than asserted:
      // authorization consumes the exhibited bytes and the verifier's own
      // structural duty, never this number.
      await expectSpends(w, w.credKey, w.pqKey, "the 33-declaring vault spends with the 32-byte key");
    });

    it("a wrong key of the RIGHT length is refused — the exhibit binds the hash, not just the shape", async function () {
      const w = await deployWorld({
        label: "d-e3", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, HYBRID, { pqKey: keyOfLength(32, 0xee) }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    });

    it("POSITIVE CONTROL — the honest declaration succeeds and the armed vault spends", async function () {
      const w = await deployWorld({
        label: "d-e4", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (await arm(w, { ...HYBRID, pqParamLevel: 3 })).wait();
      const f = await liveFloor(w);
      expect(f.requirePq).to.equal(true);
      expect(f.pqPublicKeyLength).to.equal(32);
      await expectSpends(w, w.credKey, w.pqKey, "the armed vault is genuinely usable");
    });

    it("NARROWED — an EMPTY exhibit still cannot satisfy a NON-EMPTY commitment", async function () {
      // NARROWED, AND RE-ATTRIBUTED. The former rationale here was an ORDERING
      // claim: `_requireSaneFloor` ran first and forbade a zero length, so
      // `pqKey` could never be empty by the time the exhibit was reached. That
      // guard is VACUOUS after SD5-I, so the ordering argument has no operand and
      // is deleted. The refusal below survives on the PREIMAGE conjunct alone,
      // which is a strictly different — and honestly narrower — reason.
      //
      // RESIDUAL, RECORDED NOT HIDDEN: the vacuous guard no longer refuses a
      // vault whose commitment IS keccak256(""). That case is now admitted at
      // declaration and is measured in the inversion test below.
      const w = await deployWorld({
        label: "d-e5", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 0 }, { pqKey: "0x" }),
        "keccak256('') is not this vault's committed hash",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the floor did not move").to.equal(false);
    });

    it("SD5-I INVERSION — a zero pqSignatureLength declaration is ACCEPTED, and the vault spends anyway", async function () {
      // INVERTED. This call used to revert `BadSignature` via `_requireSaneFloor`.
      // `pqSignatureLength` is NON_AUTHORITATIVE_SECURITY_METADATA: no
      // authorization, possession or recovery-satisfiability path reads it, and
      // the completed spend below is the measurement of that, not a restatement.
      // This is also the field SD-5 Form B took its vacuity in.
      const w = await deployWorld({
        label: "d-e5b", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (await arm(w, { ...HYBRID, pqSignatureLength: 0 }, { pqKey: pqKeyBytes(w.pqKey) })).wait();
      const f = await liveFloor(w);
      expect(f.requirePq).to.equal(true);
      expect(f.pqSignatureLength, "recorded verbatim, consumed by nothing").to.equal(0);
      await expectSpends(w, w.credKey, w.pqKey, "a 65-byte PQ signature lands under a declared length of 0");
    });

    it("SD5-I RESIDUAL — an EMPTY commitment may now be declared, and the refusal MOVES to the verifier", async function () {
      // INVERTED, and deliberately uncomfortable. The retired `_requireSaneFloor`
      // was the only thing standing between a keccak256("") commitment and an
      // armed floor; the preimage conjunct is satisfied by pqKey = "0x" because
      // that IS the preimage. Leaving the old title ("the trap stays closed")
      // over a narrowed body would have quietly dropped a claim that has in fact
      // inverted, so the new behaviour is pinned here instead.
      //
      // ATTRIBUTION IS THE POINT. The kernel no longer refuses; the VERIFIER
      // does, at spend time, discharging the structural duty SD5-A1R assigns to
      // it. The assertion therefore names `VerifierDenied` SPECIFICALLY — a probe
      // dying at `BadSignature` would mean the kernel had refused and this test
      // would be measuring something else entirely.
      const w = await deployWorld({ label: "d-e5c", verifier: "honest", ecdsaOnlyFloor: true });
      const nCred = w.spareCred[0]!;
      const emptyHash = ethers.keccak256("0x");
      await rotateTo(w, nCred, emptyHash, "0x");
      expect(await w.vault.pqPublicKeyHash(), "the empty commitment is installed").to.equal(emptyHash);
      await (
        await arm(w, { ...HYBRID, pqPublicKeyLength: 0 }, { cred: nCred, pqKey: "0x" })
      ).wait();
      expect((await liveFloor(w)).requirePq, "the declaration is ADMITTED after SD5-I").to.equal(true);
      // And the consequence lands on the verifier plane, not the kernel.
      const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND, authorityGeneration: gen,
        params: spendParams(w.recipient, ethers.parseEther("1")),
        domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
      });
      await expect(
        w.vault.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE, sign(nCred, d), "0x", "0x"),
        "the kernel's own binding is satisfied; the honest verifier refuses the empty key",
      ).to.be.revertedWithCustomError(w.vault, "VerifierDenied");
      // NOT A BRICK, and not to be reported as one: `executeRecovery` reaches
      // `_requireIncomingPossession`'s armed branch, which binds the QUORUM's
      // proposed hash and never this floor's metadata — that is exactly
      // `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`.
    });

    it("LIVENESS — a zero-commitment vault adopts PQ in TWO transactions: commit, then declare", async function () {
      // This is a deliberate consequence, not an accident: you cannot require a
      // factor you have never committed. Both principals retain the path
      // independently, so neither can strand the other.
      const w = await deployWorld({ label: "d-e6", verifier: "honest", ecdsaOnlyFloor: true });
      await expect(arm(w, HYBRID), "one transaction is no longer enough").to.be.revertedWithCustomError(
        w.vault, "BadSignature",
      );
      const nCred = w.spareCred[0]!;
      const nPq = w.sparePq[0]!;
      await rotateTo(w, nCred, pqHash(nPq), pqKeyBytes(nPq));
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: gen,
        params: setVerifierParams(w.verifiers.honest, HYBRID),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.setVerifier(
          w.verifiers.honest, floorTuple(HYBRID), nonce, FAR_DEADLINE,
          sign(nCred, d), "0x", pqKeyBytes(nPq),
        )
      ).wait();
      expect((await liveFloor(w)).requirePq, "two transactions are enough").to.equal(true);
      await expectSpends(w, nCred, nPq, "and the adopted configuration works");
    });

    it("a PQ-ENABLED genesis: true -> true moves the metadata FREELY now, and only requirePq is still guarded", async function () {
      const w = await deployWorld({ label: "d-e7", verifier: "honest" });
      const f = await liveFloor(w);
      // INVERTED. `I-FLOOR-SHAPE-IMMUTABLE` is RETIRED — not weakened, and not
      // replaced by a looser bound. With no authoritative shape it has no
      // operand, and its successor is
      // `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`: for an APPROVED
      // recovery, moving these three fields cannot change its executability.
      // A move the two-length FREEZE used to refuse with `Downgrade` is
      // ACCEPTED here, and the asked-for value is what gets recorded.
      await (await arm(w, { ...f, pqParamLevel: f.pqParamLevel + 2, pqSignatureLength: 64 })).wait();
      let live = await liveFloor(w);
      expect(live.pqSignatureLength, "the two-length freeze is gone").to.equal(64);
      expect(live.pqParamLevel).to.equal(f.pqParamLevel + 2);
      // INVERTED. The `pqParamLevel` RATCHET is removed as well, so the level
      // moves DOWN as readily as up. Keeping only the upward probe would leave a
      // test that passes while measuring no ratchet at all — precisely the
      // vacuously-green shape this lane is forbidden to ship.
      await (await arm(w, { ...f, pqParamLevel: 1, pqSignatureLength: 64 })).wait();
      live = await liveFloor(w);
      expect(live.pqParamLevel, "removed, not merely loosened").to.equal(1);
      // POSITIVE CONTROL across both moves: the vault is still genuinely usable,
      // which is what makes the three fields' non-authority a measurement.
      await expectSpends(w, w.credKey, w.pqKey, "metadata moves do not disturb spending");
      // SURVIVING LEG, kept. `I-NO-SILENT-DOWNGRADE-G1` retains exactly one
      // clause: requirePq true -> false. Attribution is asserted SPECIFICALLY —
      // `Downgrade` from `_requireNoDowngrade`, not a `BadSignature` from an
      // earlier guard that would prove nothing about the downgrade rule.
      await expect(
        arm(w, { ...f, requirePq: false, pqSignatureLength: 64 }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
      expect((await liveFloor(w)).requirePq, "the conjunct is still mandatory").to.equal(true);
    });
  });

  // =====================================================================
  // SD-4 IS NOT CLOSED HERE — the interlock that would have closed it was built,
  // measured and REMOVED. Refusing a ONE-SHOT transition while a live approved
  // recovery exists hands the guardian quorum a renewable, uncounted veto over a
  // capability no guardian path can itself exercise, which pins an ECDSA-only
  // vault at asset-control cut 1 forever. That trade is not a remediation, and
  // the reasoning is recorded in stateful/defects.ts SD-4 so the next lane does
  // not rebuild it. SD-4 REMAINS SUSTAINED and is reproduced, still asserting the
  // defective behaviour, in test/Sd34AuthenticationSatisfiability.test.ts.
  //
  // WHAT THIS FILE DOES PROVE about the two defects being independent is kept
  // below: the exhibit passes on its SURVIVING conjunct in the SD-4
  // counterexample — as it passed on both while there were two, the declared key
  // length there MATCHING the incumbent exactly — so no exhibit-shaped fix could
  // ever have closed it, before SD5-I or after.
  // =====================================================================

  // =====================================================================
  // CUT PRESERVATION
  // =====================================================================
  describe("no cut moved", function () {
    it("the edge's cut is unchanged at ONE — the exhibit is a public witness, not a second factor", async function () {
      const w = await deployWorld({
        label: "d-c1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // No PQ SIGNATURE is supplied — only the public key bytes — and the
      // declaration still succeeds. Anyone reading "exhibit the committed key"
      // as a cut increase would be wrong.
      await (await arm(w, HYBRID, { pqSig: "0x" })).wait();
      expect((await liveFloor(w)).requirePq).to.equal(true);
    });

    it("a stranger still cannot arm, and a wrong credential signature still fails first", async function () {
      const w = await deployWorld({
        label: "d-c2", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, HYBRID, { cred: w.spareCred[2]! }),
        "authority is still checked before satisfiability",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("guardian recovery remains the escape, and still installs a working credential", async function () {
      const w = await deployWorld({
        label: "d-c3", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (await arm(w, HYBRID)).wait();
      const newPq = w.sparePq[0]!;
      const newCred = await initiate(w, 0, w.verifiers.honest, pqHash(newPq));
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
          newEcdsaPop: sign(newCred, pop), newPqPop: sign(newPq, pop),
        })
      ).wait();
      await expectSpends(w, newCred, newPq, "the recovered credential spends");
    });
  });
});
