/**
 * EXPERIMENTAL PROTOTYPE — WHAT SD-4's OWN CAMPAIGN PROPERTY ACTUALLY MEASURES.
 *
 * This file changes no design and proposes none. It measures the ORACLE, on the
 * UNMODIFIED kernel, because every candidate in this lane is judged against it
 * and a proxy that over-fires would make an unharmful candidate look guilty and
 * a harmful one look no worse.
 *
 * `G-DECLARATION-SUBORDINATE-TO-RECOVERY` (stateful/invariants.ts) is stated as:
 *
 *   "an accepted configuration transition may not silently REDUCE THE
 *    SATISFIABILITY of a recovery the guardians have ALREADY approved"
 *
 * but its predicate is:
 *
 *   wasLive(prev.recovery) && !prev.floor.requirePq && now.floor.requirePq
 *
 * Nothing in that expression can see whether satisfiability was reduced. It
 * fires on the declaring edge and on nothing else, so an approved request that
 * survives the edge and executes normally is counted identically to one the edge
 * destroys.
 *
 * That is demonstrated below in both directions, with the SAME property, on the
 * SAME kernel, and it means the campaign's `knownDefectHits` entry for SD-4
 * counts TRANSITIONS, not HARMS. The property's own comment anticipates the
 * looser direction — "a kernel that refused MORE transitions than this still
 * passes" — but not this one, where the kernel refuses nothing and no harm
 * occurs either.
 *
 * SD5-I RE-ANCHORING. Before E-PRIME, this file's harmful arm was a length
 * mismatch: the declaring edge chose `pqPublicKeyLength`, and an approved
 * recovery whose committed preimage had a different length could no longer be
 * delivered. That gate is GONE — `pqPublicKeyLength`, `pqSignatureLength` and
 * `pqParamLevel` are SIGNED_METADATA + IDENTITY_BOUND_METADATA +
 * NON_AUTHORITATIVE_SECURITY_METADATA + ABI_COMPATIBILITY, and explicitly NOT
 * AUTHORIZATION_INPUT, NOT RECOVERY_SATISFIABILITY_INPUT, NOT
 * CRYPTOGRAPHIC_STRENGTH. Under `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`
 * none of the three can change whether an approved recovery executes, so the
 * SHAPE-SCOPED harm the old arm exercised is no longer reachable and is pinned
 * below in its INVERTED form instead.
 *
 * What survives is the SD-4 residual, which is `requirePq` itself and nothing
 * else: `requirePq` is EXPLICITLY OUTSIDE that invariant. Arming the conjunct
 * adds a whole authentication requirement to a request approved without one, and
 * an approved recovery carrying NO PQ commitment then cannot be delivered at all.
 * That is the harmful arm now, and it is a strictly narrower harm than the one
 * the property has always fired on — which is exactly the file's thesis.
 *
 * WHY THIS MATTERS TO THE ADJUDICATION, concretely: a repair that preserves a
 * deliverable episode across the edge is the correct behaviour and is also what
 * the kernel already does in every case below except one — yet this property
 * reports a violation for all of them. Adopting ANY candidate therefore requires
 * restating the property in terms of the request's continued executability, or
 * the lane will keep scoring a fix as if it were the defect.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { checkGlobals, snapshot } from "../stateful/invariants.js";
import { R, bytesOfLength, declare, pqPub, pqPubHash, proposeStd, spend } from "./sd4-harness.js";
import { DAY, addrOf, deployWorld, keyOf, pqKeyBytes, sign, type Floor } from "../stateful/world.js";

const ARMED: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
/** The same floor with the ONE authoritative field disarmed. */
const DISARMED: Floor = { requirePq: false, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
const PROPERTY = "G-DECLARATION-SUBORDINATE-TO-RECOVERY";

const sd4World = (label: string) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });

describe("SD-4 — the campaign property counts TRANSITIONS, not HARMS", () => {
  it("HARMFUL edge — the property fires and the approved recovery really does die", async function () {
    this.timeout(240_000);
    const nominee = keyOf("prop-harm-nominee");

    // THE SURVIVING SD-4 RESIDUAL, and the whole of it. The quorum of an
    // ECDSA-only vault approves an ECDSA-only credential: `proposedPqKeyHash` is
    // the kernel's own representation of "no PQ credential". The declaring edge
    // then arms `requirePq`, which is the ONE field
    // `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` deliberately does not
    // cover, and the armed branch of `_requireIncomingPossession` demands a
    // preimage of a commitment that does not exist.
    //
    // ATTRIBUTION. The INCOMING verifier is `alwaysTrue`, and it is the verifier
    // `executeRecovery` consults, so a verifier can neither cause nor colour the
    // refusal below: `VerifierDenied` is unreachable on this path and the only
    // principal left able to refuse is the kernel.
    const w = await sd4World("prop-harm");
    await proposeStd(w, w.vault, addrOf(nominee), ethers.ZeroHash, w.verifiers.alwaysTrue);
    const prev = await snapshot(w);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const now = await snapshot(w);

    const fired = checkGlobals(now, prev, w).map((v) => v.name);
    expect(fired, "the property fires").to.include(PROPERTY);

    await networkHelpers.time.increase(7 * DAY + 1);
    // The request is still ACTIVE and the window is open, so nothing below can
    // die at maturity, at expiry or at the `active` flag — the three guards that
    // stand in front of the possession check.
    expect((await w.vault.recovery())[R.ACTIVE], "the request is still live at the probe").to.equal(true);

    // WHICH `BadSignature`. `_requireIncomingPossession` can raise that one error
    // from four places, so the two conjuncts that run BEFORE the armed branch are
    // discharged here, mirrored off chain exactly as the kernel computes them.
    // What is left for the revert below is the armed conjunct and nothing else.
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    const request = await w.vault.recovery();
    expect(
      [request[R.SIGNER], request[R.PQ_KEY_HASH]],
      "the supplied change is the one the kernel expects",
    ).to.deep.equal([addrOf(nominee), ethers.ZeroHash]);
    expect(
      ethers.recoverAddress(pop, sign(nominee, pop)),
      "the incoming ECDSA possession leg is satisfied",
    ).to.equal(addrOf(nominee));

    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.ZeroHash,
        newPqKey: "0x",
        newEcdsaPop: sign(nominee, pop),
        newPqPop: "0x",
      }),
      "and the harm is real — the kernel itself refuses the approved request",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // POSITIVE CONTROL. The IDENTICAL request, at the IDENTICAL point in its
    // window, in a world that took no declaring edge. It executes. Without this
    // arm the revert above would be equally consistent with material the kernel
    // would have refused anyway, and the harm would be asserted rather than
    // measured.
    const control = await sd4World("prop-harm-control");
    const controlNominee = keyOf("prop-harm-control-nominee");
    await proposeStd(control, control.vault, addrOf(controlNominee), ethers.ZeroHash, control.verifiers.alwaysTrue);
    await networkHelpers.time.increase(7 * DAY + 1);
    const controlPop = (await control.vault.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await control.vault.executeRecovery({
            newSigner: addrOf(controlNominee),
            newPqKeyHash: ethers.ZeroHash,
            newPqKey: "0x",
            newEcdsaPop: sign(controlNominee, controlPop),
            newPqPop: "0x",
          })
        ).wait()
      )?.status,
      "the same request executes when the edge is not taken — the edge is the cause",
    ).to.equal(1);

    // AND THE HARM IS UNRECOVERABLE, which is why it is the residual and not a
    // nuisance. Disarming `requirePq` is the one move that would restore the
    // request, and it is refused with `Downgrade` — a DIFFERENT error from the
    // one above, so this probe demonstrably reaches `_requireNoDowngrade` rather
    // than dying at `_authorise`. The PQ conjunct is armed now, so the call
    // carries a real second factor.
    await expect(
      declare(w, w.vault, w.credKey, w.verifiers.honest, DISARMED, pqKeyBytes(w.pqKey), w.pqKey),
      "and nothing can undo it",
    ).to.be.revertedWithCustomError(w.vault, "Downgrade");
  });

  it("SHAPE-SCOPED edge — the property fires, and the approved recovery executes anyway", async function () {
    this.timeout(120_000);
    // THE INVERTED ARM. This is the construction that used to be the harmful
    // one: the approved commitment's preimage is 48 bytes, while the floor the
    // edge declares records `pqPublicKeyLength = 32` and `pqSignatureLength = 65`
    // and the delivered PoP is neither. Before E-PRIME the kernel measured that
    // SHAPE-SCOPED disagreement LIVE against an already-approved request and the
    // request died. It is pinned here in its new direction, and pinning it is the
    // point: this is `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` observed
    // on the exact input that once violated it, not inferred from the diff.
    //
    // NOTHING HERE ASSERTS A LENGTH RULE IN EITHER DIRECTION. The material is
    // shape-disagreeing so that a surviving reader of the three fields would
    // still be caught; no minimum, maximum or admissible tuple is claimed.
    const w = await sd4World("prop-shape");
    const nominee = keyOf("prop-shape-nominee");
    const key48 = bytesOfLength(48, "prop-shape-key");

    // `alwaysTrue` is again the INCOMING verifier, so the success below is
    // attributable to the kernel accepting: a verifier cannot be the reason a
    // refusal is absent when it was never asked to refuse.
    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue);
    const prev = await snapshot(w);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const now = await snapshot(w);

    expect(checkGlobals(now, prev, w).map((v) => v.name), "the property fires").to.include(PROPERTY);
    // The declared metadata really is on the floor and really does disagree with
    // the material — the arm would be vacuous if the edge had recorded nothing.
    const floor = await w.vault.securityFloor();
    expect([Number(floor[2]), Number(floor[3])], "the edge recorded a disagreeing shape").to.deep.equal([32, 65]);

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await w.vault.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: ethers.keccak256(key48),
            newPqKey: key48,
            newEcdsaPop: sign(nominee, pop),
            newPqPop: bytesOfLength(97, "prop-shape-sig"),
          })
        ).wait()
      )?.status,
      "the three metadata fields cannot change whether an approved recovery executes",
    ).to.equal(1);
  });

  it("HARMLESS edge — the SAME property fires, yet the approved recovery survives and SPENDS", async function () {
    this.timeout(120_000);
    const w = await sd4World("prop-harmless");
    const nominee = keyOf("prop-harmless-nominee");
    const nomineePq = keyOf("prop-harmless-pq");

    // The quorum proposes a PQ credential, so the conjunct the edge arms is one
    // the approved request can actually satisfy.
    await proposeStd(w, w.vault, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    const prev = await snapshot(w);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const now = await snapshot(w);

    const fired = checkGlobals(now, prev, w).map((v) => v.name);
    expect(fired, "the property fires IDENTICALLY").to.include(PROPERTY);

    // ...and the request it claims was harmed is still live, still executable,
    // and produces a credential that moves value. The verifier here is HONEST,
    // so the possession proof is a real one and the success is not a fixture.
    expect((await w.vault.recovery())[R.ACTIVE]).to.equal(true);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await w.vault.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sign(nomineePq, pop),
          })
        ).wait()
      )?.status,
      "no satisfiability was reduced by the transition the property flagged",
    ).to.equal(1);

    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, w.vault, nominee, nomineePq, pqPub(nomineePq))).wait();
    expect(await ethers.provider.getBalance(w.recipient)).to.equal(before + 1n);
  });

  it("THE PREDICATE IS BLIND BY CONSTRUCTION — its inputs cannot distinguish the two runs", async function () {
    this.timeout(120_000);
    // Stated from the snapshot fields the check actually reads, so the claim is
    // about the oracle's INPUTS rather than about an observed coincidence. Run A
    // is the harmful residual above; run B is the harmless one.
    const harmful = await sd4World("prop-blind-a");
    await proposeStd(
      harmful,
      harmful.vault,
      addrOf(keyOf("prop-blind-a-nominee")),
      ethers.ZeroHash,
      harmful.verifiers.alwaysTrue,
    );
    const prevA = await snapshot(harmful);
    await (
      await declare(harmful, harmful.vault, harmful.credKey, harmful.verifiers.honest, ARMED, pqKeyBytes(harmful.pqKey))
    ).wait();
    const nowA = await snapshot(harmful);

    const harmless = await sd4World("prop-blind-b");
    await proposeStd(
      harmless,
      harmless.vault,
      addrOf(keyOf("prop-blind-b-nominee")),
      pqPubHash(keyOf("prop-blind-b-pq")),
      harmless.verifiers.honest,
    );
    const prevB = await snapshot(harmless);
    await (
      await declare(
        harmless,
        harmless.vault,
        harmless.credKey,
        harmless.verifiers.honest,
        ARMED,
        pqKeyBytes(harmless.pqKey),
      )
    ).wait();
    const nowB = await snapshot(harmless);

    // The three values the predicate consumes are equal across the two runs.
    expect(prevA.recovery.active).to.equal(prevB.recovery.active);
    expect(prevA.floor.requirePq).to.equal(prevB.floor.requirePq);
    expect(nowA.floor.requirePq).to.equal(nowB.floor.requirePq);
    // The value that DOES differ is the one the oracle never reads: whether the
    // approved request carries a PQ commitment at all. It is on chain, in the
    // request the predicate already holds, and the predicate still does not
    // consult it.
    expect(prevA.recovery.proposedPqKeyHash).to.equal(ethers.ZeroHash);
    expect(prevB.recovery.proposedPqKeyHash).to.not.equal(ethers.ZeroHash);

    expect(checkGlobals(nowA, prevA, harmful).map((v) => v.name)).to.include(PROPERTY);
    expect(checkGlobals(nowB, prevB, harmless).map((v) => v.name)).to.include(PROPERTY);
  });
});
