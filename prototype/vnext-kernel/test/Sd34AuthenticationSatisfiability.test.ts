/**
 * EXPERIMENTAL PROTOTYPE — THE `requirePq` false -> true EDGE, BEFORE AND AFTER.
 *
 * SD-3 and SD-4 were recorded separately, but they are ONE TRANSITION: the
 * single moment in a vault's life at which the PQ authentication shape is
 * declared. They differ only in which committed authentication commitment the
 * declaration breaks:
 *
 *   SD-3  breaks `pqPublicKeyHash`            — the SPENDING commitment
 *   SD-4  breaks `recovery.proposedPqKeyHash` — an APPROVED RECOVERY's commitment
 *
 * They are nonetheless INDEPENDENT. The two commitments are different variables
 * chosen by different principals, and only the first is exhibitable by the
 * principal making the transition — which is why the prior lane's hypothesis
 * that closing SD-4 "necessarily intersects" SD-3 is REFUTED below rather than
 * inherited. Two clauses were needed, and each is discriminated by its own tests
 * in `Sd34DeclarationInvariants.test.ts`.
 *
 * WHY THE EDGE IS THE ONLY MOMENT — AND WHAT SD5-I CHANGED ABOUT THAT.
 * `securityFloor` has exactly two writers, `initialize` and `setVerifier`, and
 * `requirePq` is monotone, so the ARMING moment still happens at most once.
 * `I-FLOOR-SHAPE-IMMUTABLE` used to add a far stronger claim on top of that —
 * that the two structural length fields FROZE the instant `requirePq` held. That
 * invariant is RETIRED by SD5-I, which removed the two-length freeze and the
 * `pqParamLevel` ratchet together with every reader of those three fields. They
 * are now
 *
 *     SIGNED_METADATA + IDENTITY_BOUND_METADATA +
 *     NON_AUTHORITATIVE_SECURITY_METADATA + ABI_COMPATIBILITY
 *
 * and explicitly NOT `AUTHORIZATION_INPUT`, NOT
 * `RECOVERY_SATISFIABILITY_INPUT`, NOT `CRYPTOGRAPHIC_STRENGTH`. Nothing in
 * authorization, incoming possession, recovery satisfiability or downgrade reads
 * them. The removed gates were SHAPE-SCOPED: they compared declared lengths, and
 * a caller who pads to the declared length was never refused by them.
 *
 * `I-FLOOR-SHAPE-IMMUTABLE`'s replacement is
 * `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`: for an APPROVED recovery,
 * changing `pqPublicKeyLength`, `pqSignatureLength` or `pqParamLevel` cannot
 * change whether it executes. `requirePq` is EXPLICITLY OUTSIDE that invariant
 * and remains the SD-4 residual — which is why SD-4 below is NARROWED to that one
 * route and is NOT marked remediated.
 *
 * NO LENGTH GATE MAY EVER COME BACK, here or in the kernel — not a minimum, not
 * an exact-tuple allowlist. A minimum was measured and REJECTED: "S = MIN + 1"
 * defeats it.
 *
 * THIS FILE IS THE EVIDENCE LEDGER FOR THAT EDGE. The sequences below are the
 * ones that SUSTAINED SD-3, SD-4 and SD-5 at `ec5adce9`, kept with their verdicts
 * moved rather than deleted — deleting them would erase the proof that the
 * interlock in `stateful/defects.ts` worked. SD-5 in particular is kept in its
 * ORIGINAL shape: the capture sequence still runs to the same state, and what
 * changed is that the state is now ESCAPABLE. Where a guard lost one of two legs,
 * the surviving leg is asserted alongside the inverted one, so a green result
 * cannot be produced by the guard having disappeared altogether.
 *
 * TWO LEDGER CLAIMS WERE TESTED AND BOTH WERE WRONG:
 *   1. SD-3's title said "PERMANENTLY bricking spending at cut 1". Its own
 *      `notAnEscalationBecause` said "escapable at k", and that field was right.
 *   2. SD-3's `minimalFixSketch` proposed a ZERO-HASH check only. A NON-ZERO
 *      commitment reaches the identical dead state by declaring a shape no
 *      preimage of it has, so the recorded sketch would have shipped a fix that
 *      left the defect open.
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
 * `setVerifier` as the credential principal.
 *
 * On a vault whose CURRENT floor has `requirePq == false`, `_authorise` returns
 * before the PQ leg, so this is a ONE-ROOT call: no PQ signature is supplied and
 * none is consulted. The `pqKey` argument is nonetheless meaningful there — it
 * is `I-DECLARATION-EXHIBITED`'s satisfiability witness, a PUBLIC value that
 * grants authority to nobody — and it defaults to the vault's committed key so
 * the honest path is the default and every attack has to opt out explicitly.
 */
async function setVerifierTx(
  w: World,
  verifier: string,
  floor: Floor,
  opts: { cred?: ethers.SigningKey; pqSig?: string; pqKey?: string } = {},
): Promise<ethers.ContractTransactionResponse> {
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

const keyOfLength = (n: number, fill: number): string => ethers.hexlify(new Uint8Array(n).fill(fill));
const RECOVERY = { CHALLENGES: 6, ACTIVE: 7 } as const;

describe("vNext kernel — the requirePq false -> true edge (SD-3, SD-5, SD-6, SD-7 remediated; SD-4 NARROWED and sustained)", function () {
  this.timeout(600_000);

  // =====================================================================
  // SD-3 — REMEDIATED
  // =====================================================================
  describe("SD-3 — REMEDIATED: a declaration must be satisfiable by the committed material", function () {
    it("SD-3 FORM 1 — the sustained sequence, verdict moved: arming against a ZERO commitment is now REFUSED", async function () {
      const w = await deployWorld({ label: "sd3-cut", verifier: "honest", ecdsaOnlyFloor: true });
      expect(await w.vault.pqPublicKeyHash(), "born with no PQ commitment").to.equal(ethers.ZeroHash);
      expect((await liveFloor(w)).requirePq).to.equal(false);

      // At ec5adce9 this call SUCCEEDED at one root, and every credential action
      // was dead afterwards because `keccak256(pqKey) == 0` has no preimage.
      await expect(
        setVerifierTx(
          w, w.verifiers.honest,
          { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
        ),
        "REMEDIATED: nothing hashes to the zero commitment, so the declaration cannot be witnessed",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the floor never moved").to.equal(false);
    });

    it("SD-3 FORM 1' — the state is now UNREACHABLE, which is what makes the old escape moot", async function () {
      // The recorded severity dispute is settled by construction rather than by
      // argument: the ledger title said "permanently bricking" and its own
      // `notAnEscalationBecause` said "escapable at k". The field was right —
      // and the state it described can no longer be entered at all.
      const w = await deployWorld({ label: "sd3-sev", verifier: "honest", ecdsaOnlyFloor: true });
      for (const shape of [32, 1, 65_535]) {
        await expect(
          setVerifierTx(w, w.verifiers.honest, {
            requirePq: true, pqParamLevel: 1, pqPublicKeyLength: shape, pqSignatureLength: 65,
          }),
          "no declared shape can be witnessed against a zero commitment",
        ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      }
      expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("SD-3 FORM 2 — the form the ledger's OWN fix sketch would have missed is refused too", async function () {
      // `minimalFixSketch` proposed `if (floor.requirePq && pqPublicKeyHash == 0)
      // revert`, which closes the zero case only. The harm was never "the hash is
      // zero" — it was "the declared requirements are unsatisfiable by the
      // committed material", which a NON-ZERO commitment reaches just as well.
      const w = await deployWorld({
        label: "sd3-gen", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      expect(await w.vault.pqPublicKeyHash(), "a perfectly good NON-ZERO commitment").to.not.equal(ethers.ZeroHash);
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 33, pqSignatureLength: 65,
        }, { pqKey: keyOfLength(33, 1) }),
        "REMEDIATED: a 33-byte witness does not hash to a 32-byte key's commitment",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });
  });

  // =====================================================================
  // SD-4 — NARROWED BY SD5-I, AND STILL SUSTAINED. (This banner once read
  // "REMEDIATED", contradicting the describe below it, the kernel, and
  // stateful/defects.ts. The interlock that would have closed SD-4 was built,
  // measured and REMOVED.)
  //
  // SD-4 had TWO routes into the same harm — a declaration destroying an
  // already-approved recovery. SD5-I closes exactly one of them:
  //
  //   SHAPE route     — CLOSED by `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`.
  //                     The declared lengths are no longer read by
  //                     `_requireIncomingPossession`, so they can no longer
  //                     change whether an approved recovery executes.
  //   requirePq route — SURVIVES, untouched and deliberately outside that
  //                     invariant. `requirePq` is the one field that is still
  //                     security authority.
  //
  // SD-4 IS THEREFORE NARROWED, NOT REMEDIATED, and it is not marked so here.
  // =====================================================================
  describe("SD-4 — NARROWED, still SUSTAINED: the declaration front-runs an approved remedy through `requirePq` alone", function () {
    it("SD-4 SHAPE ROUTE — CLOSED: the identical sequence now lets the approved 48-byte recovery EXECUTE", async function () {
      const w = await deployWorld({
        label: "sd4-cut", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // THE SEQUENCE IS THE ONE THAT SUSTAINED SD-4 AT `ec5adce9`, UNCHANGED.
      // An honest k = 2 quorum approves a recovery to a 48-byte PQ key. Nothing
      // about the proposal is malformed; the quorum picks hash and verifier.
      const proposedKey = keyOfLength(48, 0xab);
      const proposedHash = ethers.keccak256(proposedKey);
      const newCred = await initiate(w, 0, w.verifiers.alwaysTrue, proposedHash);
      expect((await w.vault.recovery())[RECOVERY.ACTIVE]).to.equal(true);
      // The declaration itself is UNCHANGED by SD5-I and still succeeds: one root
      // declares a 32-byte shape while the quorum's approved material is 48 bytes,
      // and `I-DECLARATION-EXHIBITED`'s surviving PREIMAGE conjunct is satisfied
      // by the vault's own committed key.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "the declaration still succeeds").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      // VERDICT INVERTED. At `ec5adce9` this call reverted `BadSignature` on a
      // pure integer comparison — the approved key's 48 against the declared 32 —
      // and the quorum's remedy was destroyed uncounted. That comparison was
      // SHAPE-SCOPED and is removed with the field's authority, so the remedy now
      // completes.
      //
      // ATTRIBUTION: the recovery carries `alwaysTrue` as its incoming verifier,
      // so nothing on this path can be a VERIFIER refusal, and the possession
      // helper reports a verifier refusal as `BadSignature` — the same error the
      // removed length gate raised. Pinning the verifier to `alwaysTrue` is what
      // makes the outcome attributable to the KERNEL declining to read the
      // declared lengths and to nothing else.
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: proposedHash, newPqKey: proposedKey,
          newEcdsaPop: sign(newCred, pop), newPqPop: keyOfLength(65, 1),
        })
      ).wait();
      expect(await w.vault.ecdsaSigner(), "the quorum's remedy completed").to.equal(addrOf(newCred));
      expect(await w.vault.pqPublicKeyHash(), "against the 48-byte material it approved").to.equal(proposedHash);
      // THE ACCEPTED CONSEQUENCE, STATED RATHER THAN GLOSSED: the floor still
      // advertises a 32-byte key while a 48-byte one is committed. The metadata
      // no longer describes the installed material and must never be published as
      // evidence about it.
      expect((await liveFloor(w)).pqPublicKeyLength, "and the metadata no longer describes it").to.equal(32);

      // The request was CONSUMED by execution, not stranded: `executeRecovery`'s
      // whole-struct delete is the challenge epoch's one reset boundary.
      const rec = await w.vault.recovery();
      expect(rec[RECOVERY.ACTIVE], "consumed by execution, not left dead-active").to.equal(false);
      expect(Number(rec[RECOVERY.CHALLENGES]), "and the epoch reset at the authority transition").to.equal(0);
    });

    it("SD-4 SHAPE ROUTE — the SURVIVING leg still bites: material that is not the approved PREIMAGE is refused", async function () {
      // WITHOUT THIS, THE TEST ABOVE IS NOT EVIDENCE. "The approved recovery now
      // executes" is equally consistent with the length gate having been removed
      // and with `_requireIncomingPossession` having lost its possession check
      // altogether. This discriminates the two: the same world, the same
      // declaration, the same `alwaysTrue` incoming verifier — and material whose
      // keccak does NOT equal the quorum-approved commitment is still refused.
      const w = await deployWorld({
        label: "sd4-preimage", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const proposedHash = ethers.keccak256(keyOfLength(48, 0xab));
      const newCred = await initiate(w, 0, w.verifiers.alwaysTrue, proposedHash);
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          // The struct still NAMES the approved commitment, so the cross-check
          // passes and the ECDSA possession proof is valid — the refusal below
          // cannot be either of those earlier guards.
          newSigner: addrOf(newCred), newPqKeyHash: proposedHash, newPqKey: keyOfLength(48, 0xac),
          newEcdsaPop: sign(newCred, pop), newPqPop: keyOfLength(65, 1),
        }),
        "SURVIVING LEG: the kernel's own binding to the exact committed bytes",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await w.vault.recovery())[RECOVERY.ACTIVE], "and the approved request is untouched").to.equal(true);
    });

    it("SD-4 requirePq ROUTE — SUSTAINED: the flip still kills an approved zero-commitment recovery, uncounted", async function () {
      const w = await deployWorld({
        label: "sd4-req", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // An honest k = 2 quorum approves an ECDSA-ONLY remedy. `bytes32(0)` is
      // this kernel's representation of "no PQ credential" and is a legitimate
      // proposal on an ECDSA-only vault — it is the natural remedy for a
      // compromised signer where no PQ material is in play.
      const newCred = await initiate(w, 0, w.verifiers.alwaysTrue, ethers.ZeroHash);
      expect((await w.vault.recovery())[RECOVERY.ACTIVE]).to.equal(true);
      // The credential then flips `requirePq`. This is NOT metadata: `requirePq`
      // is the one floor field that is still security authority, and it is
      // EXPLICITLY outside `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`. No
      // exception clause smuggles it back in, and none may be added.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "the declaration succeeded").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      // ATTRIBUTION: the incoming verifier is `alwaysTrue`, the struct names the
      // approved signer and commitment, and the ECDSA possession proof is valid —
      // so this is neither a verifier refusal, nor the cross-check, nor the ECDSA
      // leg. It is `keccak256(newPqKey) != bytes32(0)`, which no preimage can
      // satisfy, reached only because `requirePq` now holds.
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: ethers.ZeroHash, newPqKey: "0x",
          newEcdsaPop: sign(newCred, pop), newPqPop: "0x",
        }),
        "SUSTAINED (SD-4): the approved remedy is unexecutable",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      // THE POINT, UNCHANGED BY SD5-I: the destruction is UNACCOUNTED.
      // `challengesUsed` — the only mechanism AUTHORITY.md cites for bounding a
      // credential-held veto — never engages, and the request is left stranded
      // ACTIVE.
      const rec = await w.vault.recovery();
      expect(rec[RECOVERY.ACTIVE], "the request is still active and still dead").to.equal(true);
      expect(Number(rec[RECOVERY.CHALLENGES]), "SUSTAINED: challengesUsed is STILL 0").to.equal(0);

      // POSITIVE CONTROL — the IDENTICAL approved remedy, on an identical vault,
      // where the credential does NOT flip `requirePq`, EXECUTES. Without this the
      // revert above would be equally consistent with a zero commitment being
      // independently inadmissible at `executeRecovery`. It is not: the flip is
      // the whole cause.
      const pc = await deployWorld({
        label: "sd4-req-pc", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const pcCred = await initiate(pc, 0, pc.verifiers.alwaysTrue, ethers.ZeroHash);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pcPop = (await pc.vault.recoveryPossessionDigest()) as string;
      await (
        await pc.vault.executeRecovery({
          newSigner: addrOf(pcCred), newPqKeyHash: ethers.ZeroHash, newPqKey: "0x",
          newEcdsaPop: sign(pcCred, pcPop), newPqPop: "0x",
        })
      ).wait();
      expect(await pc.vault.ecdsaSigner(), "the same remedy completes without the flip").to.equal(addrOf(pcCred));
    });

    it("SD-4 — the EXHIBIT is not an interlock, which is why the requirePq route is still open", async function () {
      // The prior lane hypothesised that exhibiting the committed key closes SD-4.
      // It does not, and this is the proof: `I-DECLARATION-EXHIBITED` binds
      // `pqPublicKeyHash` and says NOTHING about `recovery.proposedPqKeyHash`, so
      // a declaration is admitted while a quorum-approved request naming entirely
      // different material is live. SD-3 concerns `pqPublicKeyHash`; SD-4 concerns
      // `recovery.proposedPqKeyHash`. Different variables, chosen by different
      // principals — which is why two clauses were needed and why closing one
      // never closed the other.
      //
      // NARROWED BY SD5-I: the exhibit's LENGTH conjunct is gone, so the declared
      // key length no longer has to match the incumbent for the declaration to be
      // admitted. The surviving PREIMAGE conjunct is what is satisfied here, and
      // it is the weaker of the two against this defect — it always was.
      const w = await deployWorld({
        label: "sd4-indep", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await initiate(w, 0, w.verifiers.alwaysTrue, ethers.keccak256(keyOfLength(48, 0xcd)));
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "the witness is valid, so the declaration proceeds").to.equal(true);
    });
  });

  // =====================================================================
  // SD-5 — REMEDIATED BY SD5-I; SD-6 — REMEDIATED. Both reproduced rather than
  // argued.
  //
  // WHAT SD-5 WAS: the declaring edge chose the two structural lengths ONCE, and
  // `I-FLOOR-SHAPE-IMMUTABLE` then froze them for the life of the vault against
  // EVERY principal — a k = 2 guardian quorum included. A captured vault could be
  // pinned at an advertised-maximal, one-byte-signature shape forever, and the
  // same permanence reached HONEST vaults with no attacker at all: an ML-DSA-44
  // vault could never move to ML-DSA-87. That is PERMANENT_PQ_AGILITY_LOSS.
  //
  // WHAT CLOSED IT: E-PRIME. The invariant is RETIRED, not weakened — it has no
  // operand left. The state is made UNREAD instead of UNMOVABLE, so the three
  // metadata fields have no reader in authorization, incoming possession,
  // recovery satisfiability or downgrade, and the SD-1 move they were introduced
  // to block is now admitted while the approved recovery still completes.
  //
  // NOT CLOSED BY A MINIMUM, AND NEVER TO BE: a minimum length was measured and
  // REJECTED, because "S = MIN + 1" defeats it. Neither this file nor the kernel
  // may reintroduce a length gate, a minimum, or an exact-tuple allowlist.
  // =====================================================================
  describe("SD-5 — REMEDIATED: the declaration is no longer one-shot, and a captured shape is escapable", function () {
    it("VERDICT MOVED — the same capture runs, then a k = 2 quorum recovers to GENUINE material and the vault spends on a real second factor", async function () {
      const w = await deployWorld({
        label: "sd5-perm", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // ---- PHASE 1: THE CAPTURE, UNCHANGED ------------------------------
      // Still admitted, and SD5-I did not try to prevent it. Maximal advertised
      // strength on a one-byte factor is a legal declaration, pointed at an
      // always-true verifier. Historically the exhibit's LENGTH conjunct forced
      // the attacker to reuse the incumbent's 32-byte key shape and take the
      // vacuity in `pqSignatureLength`; that conjunct is gone, so the 32 below is
      // sequence fidelity rather than a constraint. What the declaration proves is
      // unchanged and narrow: a preimage of the committed hash was exhibited.
      await (
        await setVerifierTx(w, w.verifiers.alwaysTrue, {
          requirePq: true, pqParamLevel: 65535, pqPublicKeyLength: 32, pqSignatureLength: 1,
        })
      ).wait();
      const f = await liveFloor(w);
      expect(f.pqParamLevel, "advertises maximal strength...").to.equal(65535);
      expect(f.pqSignatureLength, "...backed by a one-byte signature").to.equal(1);

      // ---- PHASE 2: THE REMEDY THAT USED TO BE IMPOSSIBLE ----------------
      // VERDICT MOVED. A k = 2 quorum recovers to GENUINE material — a fresh
      // credential, a fresh PQ keypair, and the HONEST verifier as the incoming
      // one — proving possession with a REAL 65-byte second-factor signature.
      //
      // At `ec5adce9` this exact call reverted: `_requireIncomingPossession`
      // measured the 65-byte possession proof against the captured
      // `pqSignatureLength == 1` LIVE, so the only material that could be
      // recovered to was material the capture had already made useless. The
      // quorum's own remedy was hostage to the credential's one-shot choice.
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
      expect(await w.vault.ecdsaSigner(), "the quorum owns the vault now").to.equal(addrOf(newCred));
      expect(await w.vault.pqPublicKeyHash(), "on GENUINE PQ material of its own choosing").to.equal(pqHash(newPq));
      expect(await w.vault.pqVerifier(), "and the always-true verifier is gone").to.equal(w.verifiers.honest);
      // The captured metadata is INHERITED, exactly as it always was. That is not
      // the harm any more; the harm was that it could never be undone.
      expect((await liveFloor(w)).pqSignatureLength, "the shape still survives the remedy").to.equal(1);

      // ---- PHASE 3: THE REPAIR THAT USED TO REVERT `Downgrade` -----------
      // The RECOVERED credential — full authority, installed by k guardians —
      // restores a truthful floor. Two of the three fields move in the direction
      // the retired invariants forbade: `pqSignatureLength` 1 -> 65 was the
      // two-length FREEZE, and `pqParamLevel` 65535 -> 3 is a DECREASE the
      // withdrawn ratchet refused. The ratchet went because a flat scalar asserts
      // a total order across families that does not exist, so ratcheting it was
      // the LABEL of an upgrade without its substance.
      //
      // This call also carries a real second-factor signature against the honest
      // verifier, so its success is itself evidence that the recovered vault has a
      // working second factor and not merely a rewritten label.
      const repaired = { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65 };
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: gen,
        params: setVerifierParams(w.verifiers.honest, repaired),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.setVerifier(
          w.verifiers.honest, floorTuple(repaired), nonce, FAR_DEADLINE,
          sign(newCred, d), sign(newPq, d), pqKeyBytes(newPq),
        )
      ).wait();
      expect(await liveFloor(w), "REMEDIATED (SD-5): the shape is repairable").to.deep.equal(repaired);

      // ---- PHASE 4: THE SURVIVING LEG OF `_requireNoDowngrade` -----------
      // WITHOUT THIS, PHASE 3 IS NOT EVIDENCE. "The repair succeeds" is equally
      // consistent with the two removals and with `_requireNoDowngrade` having
      // been deleted outright. `I-NO-SILENT-DOWNGRADE-G1` is the narrowest TRUE
      // form and it still bites: a mandatory PQ conjunct may not be disabled.
      // `_authorise` passes on this call — same credential, same real PQ
      // signature — so the revert is the downgrade guard and not an earlier one.
      const off = { ...repaired, requirePq: false };
      const nonce2 = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen2 = (await w.vault.credentialGeneration()) as bigint;
      const d2 = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: gen2,
        params: setVerifierParams(w.verifiers.honest, off),
        domain: DOMAIN.CREDENTIAL, nonce: nonce2, deadline: FAR_DEADLINE,
      });
      await expect(
        w.vault.setVerifier(
          w.verifiers.honest, floorTuple(off), nonce2, FAR_DEADLINE,
          sign(newCred, d2), sign(newPq, d2), pqKeyBytes(newPq),
        ),
        "SURVIVING LEG: requirePq true -> false is still refused",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");

      // ---- PHASE 5: THE SECOND FACTOR IS REAL, AND ATTRIBUTED ------------
      // Three arms over the SAME spend digest, separating the three refusals this
      // repository has previously confused. Each negative arm reverts before
      // `_consume`, so the nonce is still live for the positive arm.
      const sNonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
      const sGen = (await w.vault.credentialGeneration()) as bigint;
      const amount = ethers.parseEther("1");
      const sd = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND, authorityGeneration: sGen,
        params: spendParams(w.recipient, amount),
        domain: DOMAIN.SPEND, nonce: sNonce, deadline: FAR_DEADLINE,
      });
      // (a) VERIFIER refusal: the committed key is exhibited correctly, so the
      //     kernel's own binding passes, and the honest verifier rejects a
      //     signature from a keypair the caller does not hold.
      await expect(
        w.vault.execute(w.recipient, amount, sNonce, FAR_DEADLINE,
          sign(newCred, sd), sign(w.pqKey, sd), pqKeyBytes(newPq)),
        "the second factor genuinely requires material the caller lacks",
      ).to.be.revertedWithCustomError(w.vault, "VerifierDenied");
      // (b) KERNEL refusal: a real signature over the right digest, but by the
      //     wrong key, so the exhibited bytes are not the committed ones. This
      //     dies at the keccak binding BEFORE any verifier is consulted.
      await expect(
        w.vault.execute(w.recipient, amount, sNonce, FAR_DEADLINE,
          sign(newCred, sd), sign(w.pqKey, sd), pqKeyBytes(w.pqKey)),
        "and the kernel's own binding is a separate, earlier refusal",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      // (c) POSITIVE ARM: both factors, and the vault spends.
      const before = await ethers.provider.getBalance(w.recipient);
      await (
        await w.vault.execute(w.recipient, amount, sNonce, FAR_DEADLINE,
          sign(newCred, sd), sign(newPq, sd), pqKeyBytes(newPq))
      ).wait();
      expect(await ethers.provider.getBalance(w.recipient), "the recovered vault is genuinely usable")
        .to.equal(before + amount);
    });

    it("the cut on an ECDSA-only vault is ONE, which AUTHORITY.md's asset-control row does not caveat", async function () {
      const w = await deployWorld({
        label: "sd5-cut1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // No PQ SIGNATURE at all. The witness is a public value, so supplying it
      // proves nothing about a second factor: the cut is 1 before and after.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        }, { pqSig: "0x" })
      ).wait();
      expect((await liveFloor(w)).requirePq, "one root moved the security floor").to.equal(true);
    });
  });

  describe("SD-7 — REMEDIATED, NARROWED by SD5-I: the GENESIS twin is reached by the admission invariant's PREIMAGE half", function () {
    it("VERDICT MOVED, then NARROWED — a genesis whose commitment has no exhibited preimage is REFUSED; the LENGTH leg is gone", async function () {
      // SUSTAINING CLAIM (parent): `initialize`'s only material check was a
      // ZERO-ness test, and `_requireIncomingPossession` has exactly two call
      // sites — neither of them `initialize` — so there was no genesis
      // possession proof of any kind, and both SD-3/SD-4 clauses live in
      // `setVerifier` and never run here.
      //
      // VERDICT MOVED by `I-COMMITMENT-EXHIBITED-AT-ADMISSION`, which adds the
      // base case directly to `initialize`. That invariant had TWO conjuncts: a
      // non-zero commitment must exhibit its PREIMAGE, and where `requirePq`
      // holds that preimage must carry the declared key LENGTH.
      //
      // SD5-I NARROWS IT TO THE FIRST. The length conjunct is removed with the
      // field's authority, so this test now pins the SURVIVING leg and RECORDS
      // the removed one rather than leaving a vacuously green assertion behind.
      const w = await deployWorld({ label: "sd7-genesis", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelPrototype", w.vaultAddress, w.deployer);
      const fac = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      const salt = ethers.id("sd7-genesis-twin");
      const genesis = {
        signer: addrOf(w.credKey),
        pqKeyHash: ethers.keccak256(keyOfLength(32, 0x5a)),
        verifier: w.verifiers.honest,
        threshold: w.threshold,
        guardians: w.guardians,
        guardianIsContract: w.guardianIsContract,
        floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 }),
      };
      // SURVIVING LEG — the deployment reverts because the exhibit does not hash
      // to the commitment the same genesis carries, so the unattested twin is
      // never born. This is what makes the kernel's later keccak measurements an
      // INDUCTIVE invariant rather than an assumption about genesis. It proves
      // knowledge of a preimage and deliberately nothing more — not that the bytes
      // are a well-formed key of any scheme.
      await expect(
        fac.deployVault(salt, genesis, keyOfLength(32, 0x5b)),
        "REMEDIATED (SD-7): a commitment with no exhibited preimage is refused at birth",
      ).to.be.revertedWithCustomError(factory, "BadSignature");

      // POSITIVE CONTROL — the SAME genesis, differing ONLY in the exhibit,
      // deploys. So the refusal above is the missing preimage and not a blanket
      // refusal to deploy a PQ vault.
      const okAddr: string = await fac.predictVault(salt, genesis);
      await (await fac.deployVault(salt, genesis, keyOfLength(32, 0x5a))).wait();
      const twin = await ethers.getContractAt("VaultKernelPrototype", okAddr, w.deployer);
      expect(Number((await twin.securityFloor())[2])).to.equal(32);

      // REMOVED LEG, RECORDED. The original SD-7 reproduction — a 48-byte key
      // committed against a floor declaring 32, exhibited CORRECTLY — is now
      // ADMITTED. The old refusal was SHAPE-SCOPED: it compared two declared
      // numbers, and a deployer who padded to the declared length was never
      // refused by it. `pqPublicKeyLength` is NON_AUTHORITATIVE_SECURITY_METADATA
      // and no longer describes the committed material; that consequence is
      // stated here rather than glossed, and the floor value below must never be
      // published as evidence about the key behind the commitment.
      const lengthContradicting = { ...genesis, pqKeyHash: ethers.keccak256(keyOfLength(48, 0x5a)) };
      const bornAddr: string = await fac.predictVault(salt, lengthContradicting);
      await (await fac.deployVault(salt, lengthContradicting, keyOfLength(48, 0x5a))).wait();
      const born = await ethers.getContractAt("VaultKernelPrototype", bornAddr, w.deployer);
      expect(await born.pqPublicKeyHash(), "a 48-byte commitment, exhibited and admitted")
        .to.equal(lengthContradicting.pqKeyHash);
      expect(Number((await born.securityFloor())[2]), "under metadata that still reads 32 and binds nothing")
        .to.equal(32);
    });
  });

  describe("SD-6 — REMEDIATED: an unattested commitment install is now refused", function () {
    it("VERDICT MOVED — rotateCredential REFUSES a pqPublicKeyHash with no exhibited preimage", async function () {
      // SUSTAINING CLAIM (parent): `_requireIncomingPossession` returned at
      // `if (!floor.requirePq) return;` BEFORE the keccak cross-check, so the
      // incoming commitment was accepted unattested — and the declaring edge is
      // what makes it live, so the exhibit's strength against a determined
      // adversary was bounded by THIS defect rather than by its own logic.
      //
      // VERDICT MOVED by `I-COMMITMENT-EXHIBITED-AT-ADMISSION`, dormant half:
      // a non-zero incoming commitment must exhibit its preimage even while
      // nothing reads it. Deliberately NO length comparison on this path — see
      // the kernel comment for why reading the unvalidated dormant lengths here
      // would hand the credential a permanent veto over guardian recovery.
      const w = await deployWorld({
        label: "sd6-unattested", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const nCred = w.spareCred[2]!;
      const fabricated = ethers.keccak256(keyOfLength(7, 0x77)); // a key nobody holds
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.ROTATE, authorityGeneration: gen,
        params: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(nCred), fabricated]),
        ),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      const pop = (await w.vault.credentialPossessionDigest(addrOf(nCred), fabricated)) as string;
      const before = await w.vault.pqPublicKeyHash();
      await expect(
        w.vault.rotateCredential(
          {
            newSigner: addrOf(nCred), newPqKeyHash: fabricated,
            newPqKey: "0x", newEcdsaPop: sign(nCred, pop), newPqPop: "0x",
          },
          nonce, FAR_DEADLINE, sign(w.credKey, d), "0x", "0x",
        ),
        "REMEDIATED (SD-6): an unattested commitment is refused",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await w.vault.pqPublicKeyHash(), "storage untouched").to.equal(before);

      // POSITIVE CONTROL — exhibiting the 7-byte preimage installs it. The
      // invariant is about ATTESTATION, not about shape: a 7-byte "key" is still
      // admissible while dormant, which is why the SD-6 lane left SD-5 standing.
      // SD-5 was closed later, by SD5-I, and this path is unaffected in either
      // direction because it never read a length to begin with — that absence was
      // the design, and SD5-I generalised it to the armed path.
      await (
        await w.vault.rotateCredential(
          {
            newSigner: addrOf(nCred), newPqKeyHash: fabricated,
            newPqKey: keyOfLength(7, 0x77), newEcdsaPop: sign(nCred, pop), newPqPop: "0x",
          },
          nonce, FAR_DEADLINE, sign(w.credKey, d), "0x", "0x",
        )
      ).wait();
      expect(await w.vault.pqPublicKeyHash()).to.equal(fabricated);
    });
  });

  // =====================================================================
  // POSITIVE CONTROLS — so a blanket revert can never be mistaken for a fix
  // =====================================================================
  describe("POSITIVE CONTROLS", function () {
    it("a legitimate declaration, witnessed by the committed key, works and the vault still spends", async function () {
      const w = await deployWorld({
        label: "sd34-pc1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq).to.equal(true);

      const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const sd = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND, authorityGeneration: gen,
        params: spendParams(w.recipient, ethers.parseEther("1")),
        domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
      });
      const before = await ethers.provider.getBalance(w.recipient);
      await (
        await w.vault.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE,
          sign(w.credKey, sd), sign(w.pqKey, sd), pqKeyBytes(w.pqKey))
      ).wait();
      expect(await ethers.provider.getBalance(w.recipient), "the armed vault is genuinely usable")
        .to.equal(before + ethers.parseEther("1"));
    });

    it("a PQ-ENABLED genesis is unaffected: the edge does not exist there, and recovery still executes", async function () {
      const w = await deployWorld({ label: "sd34-pc2", verifier: "honest" });
      expect((await liveFloor(w)).requirePq, "born requiring PQ").to.equal(true);
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
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    });

    it("genesis still refuses the unsatisfiable configuration it always refused", async function () {
      const w = await deployWorld({ label: "sd34-pc3", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      await expect(
        factory.deployVault(ethers.id("sd34-pc3-bad"), {
          signer: addrOf(w.credKey),
          pqKeyHash: ethers.ZeroHash,
          verifier: w.verifiers.honest,
          threshold: w.threshold,
          guardians: w.guardians,
          guardianIsContract: w.guardianIsContract,
          floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 }),
        }, "0x"),
      ).to.revert(ethers);
    });
  });
});
