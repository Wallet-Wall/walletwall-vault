/**
 * EXPERIMENTAL PROTOTYPE — CANDIDATE H, ADJUDICATED AT ITS BOUNDARY.
 *
 * #188 dismisses metering in one sentence: "a counter has teeth only through its
 * REFUSAL, and refusing a ONE-SHOT transition is permanent deprivation, so
 * metering moves the irreversibility from the attacker to the defender."
 *
 * That sentence is TRUE of exactly one of the five boundary semantics, and the
 * generalisation to "metering fails" does not follow. H1, H2 and H4 never refuse
 * anything, so nothing is ever permanently deprived; their teeth come from the
 * FUTURE refusal of `cancelRecovery` once the budget is spent. The whole
 * question is therefore what happens at
 *
 *     recovery.active == true && challengesUsed == CHALLENGE_LIMIT
 *
 * and each answer is built and driven separately below.
 *
 * A separate defect in H1..H4, which #188 never had to consider because it never
 * built them: they OVER-APPROXIMATE. The kernel holds a HASH of the proposed key
 * and cannot know its length, so every declaring edge destroys the pending
 * request — INCLUDING edges that would not have harmed it. That is a liveness
 * regression against the unmodified kernel, which lets a shape-compatible
 * recovery survive. H-PRECISE removes it.
 *
 * ---------------------------------------------------------------------------
 * SUPERSEDED — EVERY VARIANT BELOW IS KILLED IN `Sd4RedTeamRound2.test.ts`.
 *
 * The assertions here all hold and all still run; what they do NOT establish is
 * that any H variant is a remedy. Round 2 executes four kills the boundary
 * analysis below never reached:
 *
 *   1. THE METER IS ORDERABLE AWAY. The credential chooses WHEN to declare.
 *      Cancelling twice and declaring LAST spends the budget and lands the free
 *      third denial — SD-4's 21 days, unchanged. "H1 restores the published
 *      bound" holds only against an adversary that volunteers to go first.
 *   2. H1 DRIVES `challengesUsed` TO 3 AND BREAKS `G-CHALLENGE-CAP`, a property
 *      this repository publishes and checks.
 *   3. `recovery.active` IS NEVER CLEARED ON EXPIRY, so every H variant meters a
 *      CORPSE, and H3 latches shut permanently with ZERO compromised roots.
 *   4. H-PRECISE'S COMPATIBILITY PREDICATE IS UNSOUND. Equal lengths do not
 *      imply survival: the pinned verifier must also ACCEPT the shape. A
 *      declaration can pass the predicate, be metered nothing, and destroy the
 *      episode anyway.
 * ---------------------------------------------------------------------------
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  buildCandidateH1,
  buildCandidateH2,
  buildCandidateH3,
  buildCandidateH4,
  buildCandidateHPrecise,
  buildCandidateHPreciseStrict,
} from "./sd4-candidate-kernels.js";
import {
  R,
  at,
  bytesOfLength,
  cancel,
  declare,
  liveFloor,
  pqPub,
  pqPubHash,
  proposeHPrecise,
  proposeStd,
  spend,
} from "./sd4-harness.js";
import { DAY, addrOf, deployWorld, keyOf, pqKeyBytes, sign, type Floor } from "../stateful/world.js";

const ARMED: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

const sd4World = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

type Kernel = { abi: unknown[]; bytecode: string };
let H1: Kernel;
let H2: Kernel;
let H3: Kernel;
let H4: Kernel;
let HP: Kernel;
let HPS: Kernel;

before(function () {
  this.timeout(600_000);
  H1 = buildCandidateH1();
  H2 = buildCandidateH2();
  H3 = buildCandidateH3();
  H4 = buildCandidateH4();
  HP = buildCandidateHPrecise();
  HPS = buildCandidateHPreciseStrict();
});

describe("SD-4 candidate H — the declaring edge as a metered cancellation", () => {
  it("BASELINE — today the declaration is FREE and leaves the request STRANDED ACTIVE", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-base");
    await proposeStd(
      w,
      w.vault,
      addrOf(keyOf("ch-base-nominee")),
      ethers.keccak256(bytesOfLength(48, "ch-base-key")),
      w.verifiers.honest,
    );
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const r = await w.vault.recovery();
    expect(r[R.CHALLENGES], "nothing was accounted").to.equal(0n);
    expect(r[R.ACTIVE], "and a dead request reads as live").to.equal(true);
  });

  it("H1 — the declaration is METERED and the request is coherently closed", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h1", H1);
    const v = at(w, H1);
    await proposeStd(
      w,
      v,
      addrOf(keyOf("ch-h1-nominee")),
      ethers.keccak256(bytesOfLength(48, "ch-h1-key")),
      w.verifiers.honest,
    );
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();

    const r = await v.recovery();
    expect(r[R.CHALLENGES], "the destruction consumed the SAME budget a cancellation consumes").to.equal(1n);
    expect(r[R.ACTIVE], "and the request is closed rather than stranded").to.equal(false);
  });

  it("H1 restores the published bound ONLY IF THE CREDENTIAL DECLARES FIRST — two denials, not three", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h1-bound", H1);
    const v = at(w, H1);
    const nominee = keyOf("ch-h1-bound-nominee");
    const nomineePq = keyOf("ch-h1-bound-pq");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);

    await propose();
    // Denial 1: the declaring edge, now counted.
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(1n);

    await propose();
    // Denial 2: an ordinary cancellation. The budget is now spent.
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);

    await propose();
    await expect(cancel(w, v, w.credKey), "the credential has no denial left").to.be.revertedWithCustomError(
      v,
      "ChallengeExhausted",
    );

    // ...and the remedy then completes at the declared shape.
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sign(nomineePq, pop),
          })
        ).wait()
      )?.status,
      "two denials, then the quorum wins",
    ).to.equal(1);
  });

  it("H1 AT THE BOUNDARY — the counter exceeds the cap by exactly one, and never again", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h1-boundary", H1);
    const v = at(w, H1);
    const nominee = keyOf("ch-h1-boundary-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "ch-h1b-key")), w.verifiers.honest);

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES], "budget fully spent").to.equal(2n);

    await propose();
    // H1 NEVER REFUSES. The declaring edge is one-shot and monotone, so the
    // overshoot is bounded at exactly one — today's worst case, not worse.
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    expect((await v.recovery())[R.CHALLENGES], "three denials, honestly recorded").to.equal(3n);

    await propose();
    await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");

    // THE OVERSHOOT IS BOUNDED BECAUSE THE EDGE IS ONE-SHOT, and that is
    // executed rather than asserted: a LATER, fully valid `setVerifier` is a
    // true -> true transition, so the metering clause (guarded on
    // `!securityFloor.requirePq`) does not fire and the live request survives.
    const stronger: Floor = { requirePq: true, pqParamLevel: 2, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const active = await v.recovery();
    expect(active[R.ACTIVE], "a fresh request is live").to.equal(true);
    await (await declare(w, v, w.credKey, w.verifiers.honest, stronger, pqKeyBytes(w.pqKey), w.pqKey)).wait();
    const after = await v.recovery();
    expect(after[R.ACTIVE], "a non-declaring setVerifier destroys nothing").to.equal(true);
    expect(after[R.CHALLENGES], "and meters nothing").to.equal(3n);
  });

  it("H2 — coherent state but NO accounting: the denial stays free", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h2", H2);
    const v = at(w, H2);
    await proposeStd(
      w,
      v,
      addrOf(keyOf("ch-h2-nominee")),
      ethers.keccak256(bytesOfLength(48, "ch-h2-key")),
      w.verifiers.honest,
    );
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const r = await v.recovery();
    expect(r[R.ACTIVE], "closed").to.equal(false);
    expect(r[R.CHALLENGES], "but unaccounted — H2 fixes coherence and not the bound").to.equal(0n);
  });

  it("H3 — the refusal is REACHABLE and it is a real deprivation", async function () {
    this.timeout(180_000);
    const w = await sd4World("ch-h3", H3);
    const v = at(w, H3);
    const nominee = keyOf("ch-h3-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "ch-h3-key")), w.verifiers.honest);

    // The trap is SELF-INFLICTED: only the credential's own cancellations raise
    // the counter, and no guardian path can. That is worth establishing, because
    // it is the half of #188's argument that is right for the wrong reason.
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);

    // ...but the OTHER half of the precondition, `recovery.active`, is
    // guardian-controlled and renewable, and `initiateRecovery` has no
    // `!recovery.active` guard. So the quorum alone decides how long the
    // credential stays unable to arm PQ.
    for (let i = 0; i < 3; i++) {
      await propose();
      await expect(
        declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey)),
        `declaration refused, round ${i}`,
      ).to.be.revertedWithCustomError(v, "ChallengeExhausted");
      await networkHelpers.time.increase(6 * DAY);
    }
    expect((await liveFloor(v)).requirePq, "the vault is pinned ECDSA-only for as long as the quorum wishes").to.equal(
      false,
    );
  });

  it("H3 — with an UNSPENT budget the same declaration is admitted, so the refusal is not the edge itself", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h3-open", H3);
    const v = at(w, H3);
    await proposeStd(
      w,
      v,
      addrOf(keyOf("ch-h3-open-nominee")),
      ethers.keccak256(bytesOfLength(48, "ch-h3-open-key")),
      w.verifiers.honest,
    );
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    expect((await liveFloor(v)).requirePq).to.equal(true);
    expect((await v.recovery())[R.CHALLENGES]).to.equal(1n);
  });

  it("H4 — the counter SATURATES, so the ledger under-reports a denial that happened", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-h4", H4);
    const v = at(w, H4);
    const nominee = keyOf("ch-h4-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "ch-h4-key")), w.verifiers.honest);

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();

    expect((await v.recovery())[R.ACTIVE], "a third denial DID occur").to.equal(false);
    expect(
      (await v.recovery())[R.CHALLENGES],
      "yet the counter still reads two — an observability defect, not a bound",
    ).to.equal(2n);
  });

  // ===================================================================
  // H-PRECISE — the family #188's dichotomy has no name for
  // ===================================================================

  it("H-PRECISE — a COMPATIBLE declaration leaves the episode untouched and it still executes", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-hp-compat", HP);
    const v = at(w, HP);
    const nominee = keyOf("ch-hp-compat-nominee");
    const nomineePq = keyOf("ch-hp-compat-pq");

    // The quorum DECLARES the shape it is proposing for. That declaration is a
    // COMPATIBILITY statement; it is never used as an authentication predicate.
    await proposeHPrecise(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest, 32, 65);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();

    const r = await v.recovery();
    expect(r[R.ACTIVE], "a harmless declaration destroys nothing").to.equal(true);
    expect(r[R.CHALLENGES], "and costs the credential nothing").to.equal(0n);

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sign(nomineePq, pop),
          })
        ).wait()
      )?.status,
      "the ORIGINAL episode completes across the declaring edge",
    ).to.equal(1);

    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, v, nominee, nomineePq, pqPub(nomineePq))).wait();
    expect(await ethers.provider.getBalance(w.recipient), "and the vault is ALIVE").to.equal(before + 1n);
  });

  it("H-PRECISE vs H1 — the same compatible episode, killed by H1 and preserved by H-PRECISE", async function () {
    this.timeout(180_000);
    const nominee = keyOf("ch-cmp-nominee");
    const nomineePq = keyOf("ch-cmp-pq");

    const a = await sd4World("ch-cmp-h1", H1);
    const va = at(a, H1);
    await proposeStd(a, va, addrOf(nominee), pqPubHash(nomineePq), a.verifiers.honest);
    await (await declare(a, va, a.credKey, a.verifiers.honest, ARMED, pqKeyBytes(a.pqKey))).wait();
    expect((await va.recovery())[R.ACTIVE], "H1 over-approximates and kills a survivable episode").to.equal(false);

    const b = await sd4World("ch-cmp-hp", HP);
    const vb = at(b, HP);
    await proposeHPrecise(b, vb, addrOf(nominee), pqPubHash(nomineePq), b.verifiers.honest, 32, 65);
    await (await declare(b, vb, b.credKey, b.verifiers.honest, ARMED, pqKeyBytes(b.pqKey))).wait();
    expect((await vb.recovery())[R.ACTIVE], "H-PRECISE keeps it").to.equal(true);
  });

  it("H-PRECISE — an INCOMPATIBLE declaration is metered, and the quorum re-proposes at the shape", async function () {
    this.timeout(120_000);
    const w = await sd4World("ch-hp-incompat", HP);
    const v = at(w, HP);
    const nominee = keyOf("ch-hp-incompat-nominee");
    const nomineePq = keyOf("ch-hp-incompat-pq");

    await proposeHPrecise(
      w,
      v,
      addrOf(nominee),
      ethers.keccak256(bytesOfLength(48, "ch-hp-key")),
      w.verifiers.honest,
      48,
      65,
    );
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const r = await v.recovery();
    expect(r[R.ACTIVE], "destroyed, because it genuinely could not survive").to.equal(false);
    expect(r[R.CHALLENGES], "and the destruction is now on the credential's tab").to.equal(1n);

    await proposeHPrecise(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest, 32, 65);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sign(nomineePq, pop),
          })
        ).wait()
      )?.status,
    ).to.equal(1);
  });

  it("H-PRECISE IS NOT DESIGN A — the request's lengths are read by NOTHING on the execution path", async function () {
    this.timeout(120_000);
    // Design A's brick comes from using the request's lengths AS the
    // authentication predicate, so the installed commitment may disagree with
    // the frozen floor. Here the possession check still measures the LIVE floor,
    // so a request whose declared shape disagrees with the floor cannot install
    // at all — it reverts, exactly as the unmodified kernel does, and no dead
    // credential is ever written.
    const w = await sd4World("ch-hp-nota", HP);
    const v = at(w, HP);
    const nominee = keyOf("ch-hp-nota-nominee");
    const key48 = bytesOfLength(48, "ch-hp-nota-key");

    // Arm FIRST, so no declaring edge can fire, then propose a mismatched shape.
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await proposeHPrecise(w, v, addrOf(nominee), ethers.keccak256(key48), w.verifiers.honest, 48, 65);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(key48),
        newPqKey: key48,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(65, "ch-hp-nota-sig"),
      }),
      "the LIVE floor is still the predicate, so no unsatisfiable credential can be installed",
    ).to.be.revertedWithCustomError(v, "BadSignature");
    expect(await v.ecdsaSigner(), "and the incumbent credential is untouched").to.equal(addrOf(w.credKey));
    expect((await v.recovery())[R.ACTIVE], "the request is still live, not silently consumed").to.equal(true);
  });

  it("H-PRECISE NEVER REFUSES — at the exhausted boundary the declaration still succeeds", async function () {
    this.timeout(180_000);
    const w = await sd4World("ch-hp-boundary", HP);
    const v = at(w, HP);
    const nominee = keyOf("ch-hp-boundary-nominee");
    const propose = () =>
      proposeHPrecise(
        w,
        v,
        addrOf(nominee),
        ethers.keccak256(bytesOfLength(48, "ch-hp-b-key")),
        w.verifiers.honest,
        48,
        65,
      );

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);

    await propose();
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    expect((await liveFloor(v)).requirePq, "no principal is ever permanently deprived of arming PQ").to.equal(true);
    expect((await v.recovery())[R.CHALLENGES], "and the overshoot is bounded at exactly one").to.equal(3n);
  });

  it("H-PRECISE-STRICT REPRODUCES #188's OBJECTION — the refusal becomes a quorum-held block", async function () {
    this.timeout(180_000);
    const w = await sd4World("ch-hps", HPS);
    const v = at(w, HPS);
    const nominee = keyOf("ch-hps-nominee");
    const propose = () =>
      proposeHPrecise(
        w,
        v,
        addrOf(nominee),
        ethers.keccak256(bytesOfLength(48, "ch-hps-key")),
        w.verifiers.honest,
        48,
        65,
      );

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await expect(
      declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey)),
      "the strict boundary is the one semantics #188's sentence actually reaches",
    ).to.be.revertedWithCustomError(v, "ChallengeExhausted");
  });

  it("NO H VARIANT WRITES securityFloor OUTSIDE setVerifier's own assignment", async function () {
    this.timeout(180_000);
    // I-FLOOR-SHAPE-IMMUTABLE is untouched by the whole family: the metering
    // clause reads `recovery` and writes `recovery`, never the floor.
    for (const [name, kernel] of [
      ["H1", H1],
      ["H-PRECISE", HP],
    ] as [string, Kernel][]) {
      const w = await sd4World(`ch-floor-${name}`, kernel);
      const v = at(w, kernel);
      await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
      const armed = await liveFloor(v);
      expect(armed.pqPublicKeyLength, name).to.equal(32);
      const stronger: Floor = { requirePq: true, pqParamLevel: 9, pqPublicKeyLength: 64, pqSignatureLength: 65 };
      await expect(
        declare(w, v, w.credKey, w.verifiers.honest, stronger, pqKeyBytes(w.pqKey), w.pqKey),
        `${name}: the shape is still frozen`,
      ).to.be.revertedWithCustomError(v, "Downgrade");
    }
  });
});
