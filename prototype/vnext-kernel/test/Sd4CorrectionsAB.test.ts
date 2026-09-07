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
 *
 * SD5-I NOTE, APPENDED NOT REWRITTEN. Everything above was written against the
 * PRE-AMENDMENT kernel, and design A's own behaviour is unaffected by the
 * amendment — the replica is compiled from its own pinned source, so CLAIM A and
 * the design-A observations below stand exactly as measured.
 *
 * What DID change is the kernel arm of the fair-timeline comparison. E-PRIME
 * removes the pqKey/pqSig LENGTH equalities from `_authorise` and
 * `_requireIncomingPossession`, the genesis and declaring-edge length conjuncts,
 * and the `pqParamLevel` ratchet together with the two-length freeze. The
 * approved recovery that the arming used to kill now COMPLETES, so the assertion
 * that "the remedy dies" is RESTATED to pin the new outcome instead of being
 * left asserting a behaviour the kernel no longer has.
 *
 * SD-4 is NARROWED, not closed. The declaring edge still strands an approved
 * recovery whose commitment is `bytes32(0)`, and that residual gets its own
 * two-arm test below so the narrowing cannot be mistaken for a closure.
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
  proposeStd,
  quorum,
  quorumCancelStd,
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

  it("CLAIM B — the fair timeline, RESTATED for E-PRIME: the amended kernel's remedy SURVIVES the arming", async function () {
    this.timeout(240_000);
    // SD-4's adversary is the OUTGOING CREDENTIAL at cut 1 on an ECDSA-only
    // vault. It arms the PQ conjunct to destroy the remedy, and it chooses the
    // verifier in the same act — so it picks one that keeps ITS own spending
    // alive. What matters during the extra cycle is therefore not "is the vault
    // usable" but "WHO can move the money".
    //
    // SD5-I INVERTS THE FIRST ARM. Before the amendment the kernel measured the
    // approved recovery's key against the LIVE floor's `pqPublicKeyLength`, so
    // arming at a disagreeing shape killed the remedy and the whole timeline
    // collapsed into "who suffers the extra cycle". The assertion is RESTATED
    // rather than deleted, because the operand did not merely vanish — the
    // OUTCOME changed, and the new outcome is what must now be pinned. Under
    // E-PRIME the three legacy fields are SIGNED_METADATA +
    // IDENTITY_BOUND_METADATA + NON_AUTHORITATIVE_SECURITY_METADATA +
    // ABI_COMPATIBILITY, and explicitly NOT AUTHORIZATION_INPUT, NOT
    // RECOVERY_SATISFIABILITY_INPUT and NOT CRYPTOGRAPHIC_STRENGTH. The barrier
    // the adversary used to raise here was SHAPE-SCOPED: it discriminated on an
    // encoded length and on nothing else.
    const nominee = keyOf("corr-b-time-nominee");
    const key48 = bytesOfLength(48, "corr-b-time-key");

    // ---- THE AMENDED KERNEL --------------------------------------------
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
      // The SAME arming move the adversary made before: `requirePq` false -> true
      // at a 32-byte declared shape, against a 48-byte approved proposal.
      await (await declare(w, w.vault, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
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
              newPqPop: bytesOfLength(65, "corr-b-time-sig"),
            })
          ).wait()
        )?.status,
        "THE REMEDY SURVIVES: the arming no longer kills the approved recovery",
      ).to.equal(1);

      // The shape DISAGREEMENT is still there and is still observable — it is
      // simply no longer consulted. The declared metadata says 32; the installed
      // credential is 48 bytes. That divergence is exactly what
      // NON_AUTHORITATIVE_SECURITY_METADATA means, and it is asserted rather
      // than assumed so a future kernel restoring the comparison fails HERE.
      expect(ethers.dataLength(key48), "the installed key is 48 bytes").to.equal(48);
      const floor = await liveFloor(w.vault);
      expect(floor.pqPublicKeyLength, "while the floor still declares 32").to.equal(32);
      expect(floor.requirePq, "and the conjunct is genuinely armed, not quietly dropped").to.equal(true);

      // POSITIVE CONTROL, and the reason the arm above is not merely "the
      // transaction did not revert": the recovered principal can actually MOVE
      // MONEY under the armed floor. A credential that installs and cannot spend
      // is the stranded state design A produces, and this is what separates the
      // two outcomes.
      const before = await ethers.provider.getBalance(w.recipient);
      await (await spend(w, w.vault, nominee, PQ_BLOB, key48)).wait();
      expect(
        await ethers.provider.getBalance(w.recipient),
        "and the recovered credential is USABLE under the armed floor",
      ).to.equal(before + 1n);

      // AND THE ADVERSARY IS EVICTED AT THE ORIGINAL MATURITY. This refusal is
      // an AUTHORIZATION refusal inside `_authorise`: the outgoing key is no
      // longer `ecdsaSigner`, so `_floorAuthorises` reverts `BadSignature`
      // before the verifier is ever consulted. It is NOT `VerifierDenied` — the
      // always-true verifier denies nothing — and it is NOT a
      // recovery-satisfiability effect, because no request is live. Naming the
      // specific error is what stops this probe passing for the wrong reason at
      // an earlier guard.
      await expect(
        spend(w, w.vault, w.credKey, w.pqKey, pqKeyBytes(w.pqKey), 3n),
        "the compromised credential has lost asset control",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await w.vault.ecdsaSigner(), "the nominee holds the vault").to.equal(addrOf(nominee));
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

      // The adversary is evicted at the original maturity here too — but design
      // A pays for it with a vault frozen for one further cycle, because the
      // credential it installed can authorise nothing.
      await expect(
        spend(w, v, w.credKey, w.pqKey, pqKeyBytes(w.pqKey), 3n),
        "the compromised credential has lost asset control",
      ).to.be.revertedWithCustomError(v, "BadSignature");
      expect(await v.ecdsaSigner()).to.equal(addrOf(nominee));
    }

    // CONCLUSION, RESTATED. #188's "strictly worse than today" never held in
    // SD-4's own threat model, and that finding stands unchanged. But the trade
    // it argued over — "the attacker keeps spending for another cycle" versus
    // "nobody spends for another cycle" — is no longer a trade this kernel has
    // to make. E-PRIME evicts the adversary at the ORIGINAL maturity AND leaves
    // the recovered credential usable, which dominates both arms above. Design
    // A remains rejected, and now for one fewer reason: it still costs a
    // credential generation and still produces a state no observer can
    // distinguish from success, but the harm it traded against has been removed
    // at the source instead of exchanged for a different one.
  });

  it("CLAIM B — SD-4 is NARROWED, NOT CLOSED: the requirePq / zero-hash residual survives E-PRIME", async function () {
    this.timeout(240_000);
    // `I-FLOOR-SHAPE-IMMUTABLE` is RETIRED. Its replacement is
    // `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`: for an APPROVED
    // recovery, changing `pqPublicKeyLength`, `pqSignatureLength` or
    // `pqParamLevel` cannot change its executability. `requirePq` is EXPLICITLY
    // OUTSIDE that invariant — not as an exception carved into it, but as a
    // separately recorded residual. This test is what keeps that residual
    // visible, so the amendment above cannot be read as a closure of SD-4.
    //
    // THE RESIDUAL, exactly: an approved recovery whose `proposedPqKeyHash` is
    // `bytes32(0)` — a guardian recovery to an ECDSA-only credential — is still
    // stranded by the declaring edge, because `keccak256` of ANY preimage, the
    // empty string included, is never zero. No length participates, and none is
    // reintroduced here.
    const nominee = keyOf("corr-b-resid-nominee");

    // ---- POSITIVE CONTROL: the identical recovery, WITHOUT the arming -------
    // Without this arm the revert below would prove only that the fixture was
    // broken. The two arms differ in exactly one fact: the `setVerifier` call.
    {
      const w = await sd4World("corr-b-resid-control");
      await proposeStd(w, w.vault, addrOf(nominee), ethers.ZeroHash, w.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      expect(
        (
          await (
            await w.vault.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: ethers.ZeroHash,
              newPqKey: "0x",
              newEcdsaPop: sign(nominee, pop),
              newPqPop: "0x",
            })
          ).wait()
        )?.status,
        "an approved zero-commitment recovery executes on a DORMANT floor",
      ).to.equal(1);
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(nominee));
      expect(await w.vault.pqPublicKeyHash(), "installed with no PQ credential").to.equal(ethers.ZeroHash);
    }

    // ---- THE RESIDUAL: the same recovery, with the arming -------------------
    {
      const w = await sd4World("corr-b-resid-armed");
      await proposeStd(w, w.vault, addrOf(nominee), ethers.ZeroHash, w.verifiers.alwaysTrue);
      // The ONE differing fact.
      await (await declare(w, w.vault, w.credKey, w.verifiers.alwaysTrue, ARMED32, pqKeyBytes(w.pqKey))).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      // ATTRIBUTION. This is `_requireIncomingPossession` refusing the incoming
      // material against a ZERO expectation — a recovery-satisfiability refusal,
      // reached only after the signer cross-check and the ECDSA
      // proof-of-possession have both already PASSED. The control arm above
      // drives those same two legs to completion on identical material, so this
      // probe cannot be dying at an earlier guard.
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: ethers.ZeroHash,
          newPqKey: "0x",
          newEcdsaPop: sign(nominee, pop),
          newPqPop: "0x",
        }),
        "SD-4 SURVIVES: the declaring edge still strands a zero-commitment recovery",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect(await w.vault.ecdsaSigner(), "and the compromised credential keeps the vault").to.equal(
        addrOf(w.credKey),
      );

      // No preimage rescues it, and that is the point: the obstacle is not a
      // shape a caller can meet, so no supplied blob — not the empty string, not
      // the incumbent key — changes the outcome. This is why the residual is
      // about `requirePq` and the zero commitment, and not about any length.
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: ethers.ZeroHash,
          newPqKey: pqKeyBytes(w.pqKey),
          newEcdsaPop: sign(nominee, pop),
          newPqPop: bytesOfLength(65, "corr-b-resid-sig"),
        }),
        "keccak256 of any preimage is never zero",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      // SAME-WORLD DISCRIMINATOR, the sharpest form of the attribution. The
      // signer cross-check and the ECDSA proof-of-possession legs are driven to
      // completion in THIS world, under THIS armed floor, with THIS nominee: the
      // quorum cancels, re-proposes the same nominee at a NON-ZERO commitment,
      // and the recovery executes. Only the commitment changed, so the strand
      // above is attributable to the zero commitment alone — not to the arming
      // in general, and not to any length, since the key installed here is 48
      // bytes against a floor that still declares 32.
      await (await quorumCancelStd(w, w.vault)).wait();
      const key48 = bytesOfLength(48, "corr-b-resid-key48");
      await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key48), w.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop2 = (await w.vault.recoveryPossessionDigest()) as string;
      expect(
        (
          await (
            await w.vault.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: ethers.keccak256(key48),
              newPqKey: key48,
              newEcdsaPop: sign(nominee, pop2),
              newPqPop: bytesOfLength(65, "corr-b-resid-sig2"),
            })
          ).wait()
        )?.status,
        "a NON-ZERO commitment executes under the identical armed floor",
      ).to.equal(1);
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(nominee));
      expect(
        (await liveFloor(w.vault)).pqPublicKeyLength,
        "and the floor still declares 32 while a 48-byte key is installed",
      ).to.equal(32);
    }
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
