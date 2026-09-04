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
 * fires on the declaring edge and on nothing else, so a SHAPE-COMPATIBLE
 * approved request — one that survives the edge and executes normally — is
 * counted identically to one the edge destroys.
 *
 * That is demonstrated below in both directions, with the SAME property, on the
 * SAME kernel, and it means the campaign's `knownDefectHits` entry for SD-4
 * counts TRANSITIONS, not HARMS. The property's own comment anticipates the
 * looser direction — "a kernel that refused MORE transitions than this still
 * passes" — but not this one, where the kernel refuses nothing and no harm
 * occurs either.
 *
 * WHY THIS MATTERS TO THE ADJUDICATION, concretely: H-PRECISE preserves a
 * compatible episode across the edge, which is the correct behaviour and is also
 * exactly what the unmodified kernel already does — yet this property reports a
 * violation for both. Adopting ANY candidate therefore requires restating the
 * property in terms of the request's continued executability, or the lane will
 * keep scoring a fix as if it were the defect.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { checkGlobals, snapshot } from "../stateful/invariants.js";
import { R, bytesOfLength, declare, pqPub, pqPubHash, proposeStd, spend } from "./sd4-harness.js";
import { DAY, addrOf, deployWorld, keyOf, pqKeyBytes, sign, type Floor } from "../stateful/world.js";

const ARMED: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
const PROPERTY = "G-DECLARATION-SUBORDINATE-TO-RECOVERY";

const sd4World = (label: string) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });

describe("SD-4 — the campaign property counts TRANSITIONS, not HARMS", () => {
  it("HARMFUL edge — the property fires and the approved recovery really does die", async function () {
    this.timeout(120_000);
    const w = await sd4World("prop-harm");
    const nominee = keyOf("prop-harm-nominee");
    const key48 = bytesOfLength(48, "prop-harm-key");

    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue);
    const prev = await snapshot(w);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const now = await snapshot(w);

    const fired = checkGlobals(now, prev, w).map((v) => v.name);
    expect(fired, "the property fires").to.include(PROPERTY);

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(key48),
        newPqKey: key48,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(65, "prop-harm-sig"),
      }),
      "and the harm is real",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });

  it("HARMLESS edge — the SAME property fires, yet the approved recovery survives and SPENDS", async function () {
    this.timeout(120_000);
    const w = await sd4World("prop-harmless");
    const nominee = keyOf("prop-harmless-nominee");
    const nomineePq = keyOf("prop-harmless-pq");

    // The quorum happens to propose material of the shape that will be declared.
    // Nothing in the kernel arranged this; the quorum simply guessed right.
    await proposeStd(w, w.vault, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    const prev = await snapshot(w);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const now = await snapshot(w);

    const fired = checkGlobals(now, prev, w).map((v) => v.name);
    expect(fired, "the property fires IDENTICALLY").to.include(PROPERTY);

    // ...and the request it claims was harmed is still live, still executable,
    // and produces a credential that moves value.
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
    // about the oracle's INPUTS rather than about an observed coincidence.
    const harmful = await sd4World("prop-blind-a");
    await proposeStd(
      harmful,
      harmful.vault,
      addrOf(keyOf("prop-blind-a-nominee")),
      ethers.keccak256(bytesOfLength(48, "prop-blind-a-key")),
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
    // The value that DOES differ is the one the oracle never reads: the length
    // of the preimage behind the approved commitment, which is not on chain.
    expect(prevA.recovery.proposedPqKeyHash).to.not.equal(prevB.recovery.proposedPqKeyHash);

    expect(checkGlobals(nowA, prevA, harmful).map((v) => v.name)).to.include(PROPERTY);
    expect(checkGlobals(nowB, prevB, harmless).map((v) => v.name)).to.include(PROPERTY);
  });
});
