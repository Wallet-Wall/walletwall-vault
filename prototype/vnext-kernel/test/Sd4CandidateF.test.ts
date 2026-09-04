/**
 * EXPERIMENTAL PROTOTYPE — CANDIDATE F, ADJUDICATED.
 *
 * F asks whether the guardian quorum must name the exact `proposedPqKeyHash`
 * before any PQ shape exists. The observation motivating it is correct and is
 * PROVEN here rather than assumed: `executeRecovery` already refuses to install
 * anything without an ECDSA possession proof from `proposedSigner`, so the
 * nominee is ALREADY a mandatory participant and letting it choose its own
 * second factor introduces no new principal and no new liveness dependency.
 *
 * F clears SD-4's COMMITMENT axis without writing `securityFloor` and without
 * handing the quorum the shape, so it escapes #188's A/E dichotomy structurally.
 * The question is what it costs, and the cost is measured here at the sharpest
 * point available: a compromise set of ONE root that the unmodified kernel
 * refuses and F admits.
 *
 * ---------------------------------------------------------------------------
 * SCOPE CORRECTION — READ `Sd4RedTeamRound2.test.ts` ALONGSIDE THIS FILE.
 *
 * An earlier revision of this header claimed F closes SD-4 "in both of its
 * published forms". It does not. The FORM 2 test below reaches its result under
 * the ALWAYS-TRUE verifier, which accepts any signature length; with a verifier
 * that performs a real check, `floor.pqSignatureLength` is chosen by the
 * CREDENTIAL at t1 while `r.proposedVerifier` was pinned by the QUORUM at t0,
 * and no late-bound commitment can reconcile them. F IS INERT ON THAT AXIS, and
 * it is executed in round 2. F is killed on the cut below regardless, so this
 * correction narrows a claim rather than changing the verdict — but a green test
 * whose greenness depends on a shape-agnostic stub is exactly the kind of
 * evidence this lane exists to refuse.
 * ---------------------------------------------------------------------------
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { buildCandidateF, buildCandidateFScoped } from "./sd4-candidate-kernels.js";
import {
  R,
  at,
  bytesOfLength,
  cancel,
  declare,
  liveFloor,
  pqPub,
  pqPubHash,
  proposeF,
  proposeStd,
  spend,
} from "./sd4-harness.js";
import { DAY, addrOf, deployWorld, keyOf, pqKeyBytes, sign, type Floor } from "../stateful/world.js";

const ARMED: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

/** The SD-4 fixture: born ECDSA-only WITH a committed key, so the declaring edge is reachable. */
const sd4World = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

/** A vault whose floor mandates PQ from birth — where the published cut is min(2, k). */
const hybridWorld = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, implOverride: impl });

let F: { abi: unknown[]; bytecode: string };
let FS: { abi: unknown[]; bytecode: string };

before(function () {
  this.timeout(300_000);
  F = buildCandidateF();
  FS = buildCandidateFScoped();
});

describe("SD-4 candidate F — nominee-late-bound PQ credential", () => {
  it("RED — on the UNMODIFIED kernel the approved recovery dies across the declaring edge", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-red");
    const nominee = keyOf("cf-red-nominee");
    const nomineePq = keyOf("cf-red-nominee-pq");

    // The quorum proposes while no shape exists. It picks a 48-byte key because
    // nothing in the vault's state tells it any other length will ever matter.
    const proposedKey = bytesOfLength(48, "cf-red-key");
    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(proposedKey), w.verifiers.honest);

    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(proposedKey),
        newPqKey: proposedKey,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(nomineePq, pop),
      }),
      "SD-4 reproduced firsthand on my own fixture",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    expect((await w.vault.recovery())[R.ACTIVE], "and the request is left stranded ACTIVE").to.equal(true);
  });

  it("GREEN — candidate F completes the SAME episode and the recovered credential SPENDS", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-green", F);
    const v = at(w, F);
    const nominee = keyOf("cf-green-nominee");
    const nomineePq = keyOf("cf-green-nominee-pq");

    // The quorum authorises WHO and WHICH ORACLE. It names no commitment,
    // because at S0 there is no shape a commitment could be chosen against.
    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    // The nominee generates PQ material AT THE DECLARED SHAPE and binds it with
    // its own ECDSA possession proof. The honest verifier performs a real
    // recovery against the exhibited key, so this is possession, not a mock.
    const hash = pqPubHash(nomineePq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    const receipt = await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(nomineePq, pop),
      })
    ).wait();
    expect(receipt?.status, "SD-4 closed: the approved episode survives the declaration").to.equal(1);
    expect(await v.ecdsaSigner()).to.equal(addrOf(nominee));
    expect(await v.pqPublicKeyHash()).to.equal(hash);

    // FOLLOW THE ACCEPTED TRANSITION THROUGH TO AN ASSET MOVEMENT. A recovery
    // that "succeeds" into a credential that cannot spend is design A, and this
    // assertion is what distinguishes F from it.
    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, v, nominee, nomineePq, pqPub(nomineePq))).wait();
    expect(await ethers.provider.getBalance(w.recipient)).to.equal(before + 1n);
  });

  it("GREEN (ONLY UNDER A SHAPE-AGNOSTIC VERIFIER) — F clears SD-4 FORM 2", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-form2", F);
    const v = at(w, F);
    const nominee = keyOf("cf-form2-nominee");

    await proposeF(w, v, addrOf(nominee), w.verifiers.alwaysTrue);
    // A 96-byte signature shape: under the unmodified kernel any PoP prepared
    // before this declaration is the wrong length forever.
    const shape: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 96 };
    await (await declare(w, v, w.credKey, w.verifiers.alwaysTrue, shape, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const key = bytesOfLength(32, "cf-form2-key");
    const hash = ethers.keccak256(key);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: hash,
            newPqKey: key,
            newEcdsaPop: sign(nominee, pop),
            newPqPop: bytesOfLength(96, "cf-form2-sig"),
          })
        ).wait()
      )?.status,
      "the nominee simply produces material at the shape that now exists",
    ).to.equal(1);
  });

  it("F NEVER WRITES securityFloor — I-FLOOR-SHAPE-IMMUTABLE survives the whole episode", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-floor", F);
    const v = at(w, F);
    const nominee = keyOf("cf-floor-nominee");
    const nomineePq = keyOf("cf-floor-nominee-pq");

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    const armed = await liveFloor(v);
    await networkHelpers.time.increase(7 * DAY + 1);

    const hash = pqPubHash(nomineePq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(nomineePq, pop),
      })
    ).wait();

    expect(await liveFloor(v), "the floor is byte-identical across the remedy").to.deep.equal(armed);
    // Design E's regression, checked negatively: no guardian path moved a shape.
    expect(armed.pqPublicKeyLength).to.equal(32);
    expect(armed.pqSignatureLength).to.equal(65);
  });

  it("F is NOT strawmanned — a relayer cannot substitute the late-bound PQ material", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-sub", F);
    const v = at(w, F);
    const nominee = keyOf("cf-sub-nominee");
    const nomineePq = keyOf("cf-sub-nominee-pq");
    const relayerPq = keyOf("cf-sub-relayer-pq");

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    // The nominee's honest possession proof, for ITS OWN commitment.
    const honestHash = pqPubHash(nomineePq);
    const honestPop = (await v.recoveryPossessionDigest(honestHash)) as string;
    const honestEcdsaPop = sign(nominee, honestPop);

    // A relayer swaps every PQ field for material it holds and keeps the
    // nominee's ECDSA proof. The PoP digest COVERS the late-bound hash, so the
    // recovered address is no longer the nominee.
    const evilHash = pqPubHash(relayerPq);
    const evilPop = (await v.recoveryPossessionDigest(evilHash)) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: evilHash,
        newPqKey: pqPub(relayerPq),
        newEcdsaPop: honestEcdsaPop,
        newPqPop: sign(relayerPq, evilPop),
      }),
      "substitution is refused because the digest binds the late-bound hash",
    ).to.be.revertedWithCustomError(v, "BadSignature");

    // POSITIVE CONTROL: the same transaction with the nominee's own material works.
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: honestHash,
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: honestEcdsaPop,
            newPqPop: sign(nomineePq, honestPop),
          })
        ).wait()
      )?.status,
    ).to.equal(1);
  });

  it("F's possession proof does not replay ACROSS EPISODES — executableAt still binds", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-replay", F);
    const v = at(w, F);
    const nominee = keyOf("cf-replay-nominee");
    const nomineePq = keyOf("cf-replay-nominee-pq");
    const hash = pqPubHash(nomineePq);

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    const episode1Pop = (await v.recoveryPossessionDigest(hash)) as string;
    const staleEcdsaPop = sign(nominee, episode1Pop);
    const staleFirstEpisode = (await v.recovery())[R.EXECUTABLE_AT] as bigint;

    // The credential cancels; the quorum re-proposes the identical parameters at
    // a LATER timestamp, so only `executableAt` differs between the episodes.
    await (await cancel(w, v, w.credKey)).wait();
    await networkHelpers.time.increase(3 * DAY);
    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    expect((await v.recovery())[R.EXECUTABLE_AT], "a genuinely different episode").to.not.equal(staleFirstEpisode);

    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: staleEcdsaPop,
        newPqPop: sign(nomineePq, episode1Pop),
      }),
      "the first episode's proof is worthless in the second",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });

  it("F's possession proof does not replay ACROSS VAULTS", async function () {
    this.timeout(180_000);
    const a = await sd4World("cf-vaultA", F);
    const b = await sd4World("cf-vaultB", F);
    const va = at(a, F);
    const vb = at(b, F);
    // ONE nominee identity, nominated at BOTH vaults. Only address(this) differs.
    const nominee = keyOf("cf-cross-nominee");
    const nomineePq = keyOf("cf-cross-nominee-pq");
    const hash = pqPubHash(nomineePq);

    await proposeF(a, va, addrOf(nominee), a.verifiers.honest);
    await proposeF(b, vb, addrOf(nominee), b.verifiers.honest);
    const popA = (await va.recoveryPossessionDigest(hash)) as string;
    const popB = (await vb.recoveryPossessionDigest(hash)) as string;
    expect(popA, "the two vaults produce different possession digests").to.not.equal(popB);

    await (await declare(b, vb, b.credKey, b.verifiers.honest, ARMED, pqKeyBytes(b.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      vb.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, popA),
        newPqPop: sign(nomineePq, popA),
      }),
      "vault A's proof is refused at vault B",
    ).to.be.revertedWithCustomError(vb, "BadSignature");
  });

  it("F ADDS NO LIVENESS DEPENDENCY — the unmodified kernel already needs the nominee's ECDSA proof", async function () {
    this.timeout(120_000);
    const w = await sd4World("cf-liveness");
    const nominee = keyOf("cf-liveness-nominee");
    const impostor = keyOf("cf-liveness-impostor");
    const key = bytesOfLength(48, "cf-liveness-key");

    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key), w.verifiers.alwaysTrue);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;

    // Without the NOMINEE's own signature the matured recovery cannot complete,
    // on the kernel as it stands today. A malicious nominee can therefore
    // already stall its own recovery, and F changes nothing about that.
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(key),
        newPqKey: key,
        newEcdsaPop: sign(impostor, pop),
        newPqPop: bytesOfLength(65, "cf-liveness-sig"),
      }),
      "the nominee is ALREADY a mandatory participant",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });

  // ===================================================================
  // THE KILL
  // ===================================================================

  it("KILL — F lowers 'Unauthorized asset control' from min(2,k) to 1 on a PQ-mandating vault", async function () {
    this.timeout(180_000);
    // The compromise set is ONE root: the incoming credential's ECDSA key.
    // The guardians are HONEST throughout — they perform exactly the remedy the
    // design intends. No declaring edge is involved: this vault mandates PQ from
    // birth, so AUTHORITY.md section 3 publishes min(2, k) = 2 for it.
    const nominee = keyOf("cf-kill-nominee");
    const nomineePq = keyOf("cf-kill-nominee-pq"); // NOT compromised.
    const attackerPq = keyOf("cf-kill-attacker-pq"); // Minted by the attacker.

    // ---- CONTROL: the unmodified kernel refuses -----------------------
    {
      const w = await hybridWorld("cf-kill-control");
      await proposeStd(w, w.vault, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;

      // (a) the attacker's own PQ material is not the commitment the quorum named
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: pqPubHash(attackerPq),
          newPqKey: pqPub(attackerPq),
          newEcdsaPop: sign(nominee, pop),
          newPqPop: sign(attackerPq, pop),
        }),
        "the guardian-named commitment binds",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      // (b) the guardian-named PUBLIC key is public, but the attacker cannot sign for it
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: pqPubHash(nomineePq),
          newPqKey: pqPub(nomineePq),
          newEcdsaPop: sign(nominee, pop),
          newPqPop: sign(attackerPq, pop),
        }),
        "possession of the PQ PRIVATE key is genuinely required",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    }

    // ---- CANDIDATE F: the same compromise set succeeds -----------------
    {
      const w = await hybridWorld("cf-kill-f", F);
      const v = at(w, F);
      await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
      await networkHelpers.time.increase(7 * DAY + 1);

      const hash = pqPubHash(attackerPq);
      const pop = (await v.recoveryPossessionDigest(hash)) as string;
      expect(
        (
          await (
            await v.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: hash,
              newPqKey: pqPub(attackerPq),
              newEcdsaPop: sign(nominee, pop), // the ONE compromised root
              newPqPop: sign(attackerPq, pop), // a factor the attacker MINTED
            })
          ).wait()
        )?.status,
        "F admits a credential whose second factor the attacker chose",
      ).to.equal(1);

      // And it reaches ASSETS, which is what makes this a cut and not a nuisance.
      const before = await ethers.provider.getBalance(w.recipient);
      await (await spend(w, v, nominee, attackerPq, pqPub(attackerPq))).wait();
      expect(
        await ethers.provider.getBalance(w.recipient),
        "one compromised root moved value out of a vault whose published cut is 2",
      ).to.equal(before + 1n);
    }
  });

  // ===================================================================
  // F-SCOPED — the narrowing, and what it does and does not save
  // ===================================================================

  it("F-SCOPED closes SD-4 in the declaring window", async function () {
    this.timeout(120_000);
    const w = await sd4World("cfs-green", FS);
    const v = at(w, FS);
    const nominee = keyOf("cfs-green-nominee");
    const nomineePq = keyOf("cfs-green-nominee-pq");

    // The quorum still names a commitment; it is simply the wrong LENGTH once
    // the shape appears, which is SD-4 exactly.
    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "cfs-green-key")), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const hash = pqPubHash(nomineePq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: hash,
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sign(nomineePq, pop),
          })
        ).wait()
      )?.status,
    ).to.equal(1);
    expect(await v.ecdsaSigner()).to.equal(addrOf(nominee));
  });

  it("F-SCOPED DEFENDS the kill on a PQ-mandating vault — the guardian commitment still binds", async function () {
    this.timeout(120_000);
    const w = await hybridWorld("cfs-defend", FS);
    const v = at(w, FS);
    const nominee = keyOf("cfs-defend-nominee");
    const nomineePq = keyOf("cfs-defend-nominee-pq");
    const attackerPq = keyOf("cfs-defend-attacker-pq");

    await proposeStd(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);

    const hash = pqPubHash(attackerPq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(attackerPq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(attackerPq, pop),
      }),
      "pqRequiredAtApproval was TRUE, so late binding is unavailable",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });

  it("F-SCOPED RESIDUE — inside the declaring window one compromised root still takes the vault", async function () {
    this.timeout(120_000);
    // Every principal here is HONEST except the nominee's ECDSA key: the quorum
    // performs the intended remedy, and the credential performs a legitimate,
    // exhibited declaration. The narrowing does not remove the reduction; it
    // only shrinks the state in which it is reachable.
    const w = await sd4World("cfs-residue", FS);
    const v = at(w, FS);
    const nominee = keyOf("cfs-residue-nominee");
    const nomineePq = keyOf("cfs-residue-nominee-pq");
    const attackerPq = keyOf("cfs-residue-attacker-pq");

    await proposeStd(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const hash = pqPubHash(attackerPq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(attackerPq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(attackerPq, pop),
      })
    ).wait();

    const before = await ethers.provider.getBalance(w.recipient);
    await (await spend(w, v, nominee, attackerPq, pqPub(attackerPq))).wait();
    expect(await ethers.provider.getBalance(w.recipient), "the residue reaches assets too").to.equal(before + 1n);
  });

  it("F does NOT rescue SD-5 — a vacuous declared shape still denies the remedy", async function () {
    this.timeout(120_000);
    // SD-4 and SD-5 are different defects and F closes only one. A credential
    // that declares a structurally vacuous shape still destroys the remedy,
    // because no key of that shape satisfies an honest verifier. Stating this
    // bounds F's claim instead of over-reading it.
    const w = await sd4World("cf-sd5", F);
    const v = at(w, F);
    const nominee = keyOf("cf-sd5-nominee");

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    // The exhibit must be a preimage of the committed key at the declared
    // length, so a 1-byte KEY shape is unreachable here; the SIGNATURE shape is
    // bound by nothing at all, which is exactly SD-5's stronger half.
    const vacuous: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 1 };
    await (await declare(w, v, w.credKey, w.verifiers.honest, vacuous, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const pqk = keyOf("cf-sd5-pq");
    const hash = pqPubHash(pqk);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(pqk),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(1, "cf-sd5-sig"),
      }),
      "the honest verifier cannot accept a one-byte signature",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });
});
