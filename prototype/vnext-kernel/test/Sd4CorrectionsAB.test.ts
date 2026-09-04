/**
 * EXPERIMENTAL PROTOTYPE — TWO CLAIMS IN #188, CORRECTED EXECUTABLY.
 *
 * Neither correction weakens a security conclusion. Both narrow an OVERSTATED
 * one, which is the difference between an evidence file and an argument.
 *
 * CLAIM A — "jointly unsatisfiable".
 * `Sd4SnapshotAdjudication.test.ts` shows that a KNOWN 48-byte preimage fails a
 * 32-byte length test, and that ONE tested 32-byte value does not hash to that
 * commitment, and concludes "no 32-byte string hashes to a 48-byte key's
 * commitment". The first half is a proof. The second is a single sample, and no
 * number of samples is a proof. The accurate statement is:
 *
 *     Exhibiting a 32-byte X with keccak256(X) == keccak256(K48) for the known
 *     48-byte K48 is a SECOND-PREIMAGE problem on Keccak-256, restricted to a
 *     length class. It is computationally infeasible under the second-preimage
 *     resistance of Keccak-256, at a work factor of about 2^256 evaluations.
 *
 * SECOND-preimage rather than preimage matters and is not pedantry: the 48-byte
 * witness is public in the calldata of the very transaction under attack, so the
 * attacker is never in the harder position of not knowing one. The conclusion —
 * that the state design A creates is unusable — is UNCHANGED and is if anything
 * better supported, because a computational-infeasibility statement survives
 * scrutiny that an unproven absolute claim does not.
 *
 * CLAIM B — "bricks the vault".
 * The design-A end state is NOT permanently unrecoverable. `executeRecovery`
 * stays guardian-reachable, and under design A it measures against the REQUEST's
 * shape — so a second guardian recovery at the frozen floor's shape installs a
 * usable credential and the vault lives. The right name is a STRANDED CREDENTIAL
 * REQUIRING ANOTHER RECOVERY, and the fair comparison is a timeline, not the
 * word "bricked". That timeline is driven below, and it does NOT favour the
 * unmodified kernel in SD-4's own threat model.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { buildDesignAReplica } from "./sd4-candidate-kernels.js";
import {
  R,
  abi,
  at,
  bytesOfLength,
  declare,
  guardianDigest,
  liveFloor,
  quorum,
  spend,
} from "./sd4-harness.js";
import { DAY, FAR_DEADLINE, addrOf, deployWorld, keyOf, pqKeyBytes, sign, type Floor } from "../stateful/world.js";

const ARMED32: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

/**
 * A 65-byte second-factor signature. The ALWAYS-TRUE verifier accepts any bytes,
 * but the KERNEL checks the length itself before ever consulting it, so a spend
 * still needs a correctly-shaped blob. Using a real key makes that explicit.
 */
const PQ_BLOB = keyOf("corrections-pq-blob");

const sd4World = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

let A: { abi: unknown[]; bytecode: string };

before(function () {
  this.timeout(300_000);
  A = buildDesignAReplica();
});

/** `initiateRecovery` on design A's signature. */
async function proposeA(
  w: Awaited<ReturnType<typeof sd4World>>,
  v: ethers.Contract,
  signer: string,
  hash: string,
  verifier: string,
  keyLen: number,
  sigLen: number,
): Promise<void> {
  const params = ethers.keccak256(
    abi.encode(
      ["address", "bytes32", "address", "uint32", "uint32"],
      [signer, hash, verifier, keyLen, sigLen],
    ),
  );
  const { digest, nonce } = await guardianDigest(w, v, params);
  await (
    await v.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE, keyLen, sigLen)
  ).wait();
}

describe("SD-4 — correcting two overstated claims in #188", () => {
  it("CLAIM A — the unsatisfiability is COMPUTATIONAL, and 50,000 more samples still do not prove it", function () {
    this.timeout(300_000);
    const k48 = bytesOfLength(48, "correction-a-key");
    const target = ethers.keccak256(k48);

    // The half that IS a proof: the known witness is the wrong length, and
    // length is a pure integer comparison the kernel performs itself.
    expect(ethers.dataLength(k48), "the exhibited preimage is 48 bytes").to.equal(48);
    expect(ethers.dataLength(k48)).to.not.equal(32);

    // The half that is NOT a proof, enlarged from one sample to fifty thousand
    // so the epistemic point is impossible to miss: this is evidence of
    // infeasibility, never a demonstration of impossibility. The search space is
    // 2^256; 50,000 is 2^15.6 of it, which is indistinguishable from zero
    // coverage. The security conclusion rests on Keccak-256's SECOND-preimage
    // resistance — second, not first, because k48 is public.
    let collisions = 0;
    for (let i = 0; i < 50_000; i++) {
      if (ethers.keccak256(ethers.id(`correction-a-probe-${i}`)) === target) collisions++;
    }
    expect(collisions, "no 32-byte second preimage found, as expected").to.equal(0);

    // And the property is a fact about the INSTANCE, not about design A: when
    // the request's shape and the floor's shape agree there is nothing
    // unsatisfiable about the state at all. That is checked on chain below.
  });

  it("CLAIM A — with AGREEING shapes design A installs a perfectly usable credential", async function () {
    this.timeout(120_000);
    const w = await sd4World("corr-a-agree", A);
    const v = at(w, A);
    const nominee = keyOf("corr-a-agree-nominee");
    const key32 = bytesOfLength(32, "corr-a-agree-key");

    await proposeA(w, v, addrOf(nominee), ethers.keccak256(key32), w.verifiers.alwaysTrue, 32, 65);
    await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(key32),
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(65, "corr-a-agree-sig"),
      })
    ).wait();

    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, v, nominee, PQ_BLOB, key32)).wait();
    expect(
      await ethers.provider.getBalance(w.recipient),
      "design A's failure is CONDITIONAL on shape disagreement, not intrinsic",
    ).to.equal(before + 1n);
  });

  it("CLAIM B — #188's own two observations about design A REPRODUCE", async function () {
    this.timeout(120_000);
    const w = await sd4World("corr-b-repro", A);
    const v = at(w, A);
    const nominee = keyOf("corr-b-repro-nominee");
    const key48 = bytesOfLength(48, "corr-b-repro-key");

    await proposeA(w, v, addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue, 48, 65);
    await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: ethers.keccak256(key48),
            newPqKey: key48,
            newEcdsaPop: sign(nominee, pop),
            newPqPop: bytesOfLength(65, "corr-b-repro-sig"),
          })
        ).wait()
      )?.status,
      "(1) design A closes SD-4",
    ).to.equal(1);

    await expect(
      // A correctly-SHAPED second factor is supplied, so the refusal is about
      // the key/commitment disagreement and not merely a missing signature.
      spend(w, v, nominee, PQ_BLOB, key48),
      "(2) and the installed credential cannot spend",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });

  it("CLAIM B — the state is AUTHORIZATION-DEAD, not permanently unrecoverable", async function () {
    this.timeout(180_000);
    const w = await sd4World("corr-b-alive", A);
    const v = at(w, A);
    const dead = keyOf("corr-b-alive-dead");
    const key48 = bytesOfLength(48, "corr-b-alive-key48");

    await proposeA(w, v, addrOf(dead), ethers.keccak256(key48), w.verifiers.alwaysTrue, 48, 65);
    await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    let pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(dead),
        newPqKeyHash: ethers.keccak256(key48),
        newPqKey: key48,
        newEcdsaPop: sign(dead, pop),
        newPqPop: bytesOfLength(65, "corr-b-alive-sig"),
      })
    ).wait();
    expect(await v.ecdsaSigner(), "the stranded credential is installed").to.equal(addrOf(dead));
    const frozen = await liveFloor(v);
    expect(frozen.pqPublicKeyLength, "under a floor frozen at 32").to.equal(32);

    // THE CORRECTION. `executeRecovery` never consults `_authorise`, so the
    // guardian remedy is untouched by the credential being unusable. A second
    // recovery, proposed at the shape the floor actually has, installs material
    // the vault can authorise.
    const alive = keyOf("corr-b-alive-alive");
    const key32 = bytesOfLength(32, "corr-b-alive-key32");
    await proposeA(w, v, addrOf(alive), ethers.keccak256(key32), w.verifiers.alwaysTrue, 32, 65);
    await networkHelpers.time.increase(7 * DAY + 1);
    pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(alive),
        newPqKeyHash: ethers.keccak256(key32),
        newPqKey: key32,
        newEcdsaPop: sign(alive, pop),
        newPqPop: bytesOfLength(65, "corr-b-alive-sig2"),
      })
    ).wait();

    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, v, alive, PQ_BLOB, key32)).wait();
    expect(
      await ethers.provider.getBalance(w.recipient),
      "one further guardian recovery revives it: STRANDED, not bricked",
    ).to.equal(before + 1n);
    expect((await liveFloor(v)), "and no floor field ever moved").to.deep.equal(frozen);
  });

  it("CLAIM B — the fair timeline: in SD-4's OWN threat model the unmodified kernel is not better", async function () {
    this.timeout(240_000);
    // SD-4's adversary is the OUTGOING CREDENTIAL at cut 1 on an ECDSA-only
    // vault. It arms the PQ conjunct to destroy the remedy, and it chooses the
    // verifier in the same act — so it picks one that keeps ITS own spending
    // alive. What matters during the extra cycle is therefore not "is the vault
    // usable" but "WHO can move the money".
    const nominee = keyOf("corr-b-time-nominee");
    const key48 = bytesOfLength(48, "corr-b-time-key");

    // ---- UNMODIFIED KERNEL ---------------------------------------------
    {
      const w = await sd4World("corr-b-time-real");
      await (
        await w.vault.initiateRecovery(
          addrOf(nominee),
          ethers.keccak256(key48),
          w.verifiers.alwaysTrue,
          quorum(
            w,
            (
              await guardianDigest(
                w,
                w.vault,
                ethers.keccak256(
                  abi.encode(
                    ["address", "bytes32", "address"],
                    [addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue],
                  ),
                ),
              )
            ).digest,
          ),
          (await w.vault.nonces(2)) as bigint,
          FAR_DEADLINE,
        )
      ).wait();
      await (await declare(w, w.vault, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: ethers.keccak256(key48),
          newPqKey: key48,
          newEcdsaPop: sign(nominee, pop),
          newPqPop: bytesOfLength(65, "corr-b-time-sig"),
        }),
        "the remedy dies",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      // AND THE ADVERSARY KEEPS SPENDING throughout the extra cycle.
      const before = await ethers.provider.getBalance(w.recipient);
      await (
        await spend(w, w.vault, w.credKey, w.pqKey, pqKeyBytes(w.pqKey), 3n)
      ).wait();
      expect(
        await ethers.provider.getBalance(w.recipient),
        "the compromised credential retains asset control for the whole extra delay",
      ).to.equal(before + 3n);
    }

    // ---- DESIGN A -------------------------------------------------------
    {
      const w = await sd4World("corr-b-time-a", A);
      const v = at(w, A);
      await proposeA(w, v, addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue, 48, 65);
      await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await v.recoveryPossessionDigest()) as string;
      await (
        await v.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: ethers.keccak256(key48),
          newPqKey: key48,
          newEcdsaPop: sign(nominee, pop),
          newPqPop: bytesOfLength(65, "corr-b-time-sig-a"),
        })
      ).wait();

      // The adversary is EVICTED at the original maturity. The vault is frozen
      // for one further cycle, and the compromised principal can move nothing.
      await expect(
        spend(w, v, w.credKey, w.pqKey, pqKeyBytes(w.pqKey), 3n),
        "the compromised credential has lost asset control",
      ).to.be.revertedWithCustomError(v, "BadSignature");
      expect(await v.ecdsaSigner()).to.equal(addrOf(nominee));
    }

    // CONCLUSION, stated as a trade rather than a ranking: design A converts
    // "the attacker keeps spending for another cycle" into "nobody spends for
    // another cycle". #188's "strictly worse than today" does not hold in the
    // threat model SD-4 itself describes. Design A remains rejected — it costs a
    // credential generation, produces a state no observer can distinguish from
    // success, and drives a commitment past the shape agreement
    // I-DECLARATION-EXHIBITED exists to enforce — but it is rejected for those
    // reasons, not for permanence.
  });

  it("CLAIM B — enumerating what the stranded state can and cannot still do", async function () {
    this.timeout(180_000);
    const w = await sd4World("corr-b-enum", A);
    const v = at(w, A);
    const dead = keyOf("corr-b-enum-dead");
    const key48 = bytesOfLength(48, "corr-b-enum-key");

    await proposeA(w, v, addrOf(dead), ethers.keccak256(key48), w.verifiers.alwaysTrue, 48, 65);
    await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(dead),
        newPqKeyHash: ethers.keccak256(key48),
        newPqKey: key48,
        newEcdsaPop: sign(dead, pop),
        newPqPop: bytesOfLength(65, "corr-b-enum-sig"),
      })
    ).wait();

    // CREDENTIAL PATHS — all dead, because every one calls `_authorise`.
    await expect(spend(w, v, dead, PQ_BLOB, key48), "execute").to.be.revertedWithCustomError(v, "BadSignature");
    await expect(
      declare(w, v, dead, w.verifiers.alwaysTrue, ARMED32, key48),
      "setVerifier",
    ).to.be.revertedWithCustomError(v, "BadSignature");

    // GUARDIAN PATHS — all alive, because none of them calls `_authorise`.
    const survivor = keyOf("corr-b-enum-survivor");
    const key32 = bytesOfLength(32, "corr-b-enum-key32");
    await proposeA(w, v, addrOf(survivor), ethers.keccak256(key32), w.verifiers.alwaysTrue, 32, 65);
    expect((await v.recovery())[R.ACTIVE], "initiateRecovery is reachable").to.equal(true);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop2 = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(survivor),
            newPqKeyHash: ethers.keccak256(key32),
            newPqKey: key32,
            newEcdsaPop: sign(survivor, pop2),
            newPqPop: bytesOfLength(65, "corr-b-enum-sig2"),
          })
        ).wait()
      )?.status,
      "executeRecovery is reachable, and it is the escape",
    ).to.equal(1);
  });
});
