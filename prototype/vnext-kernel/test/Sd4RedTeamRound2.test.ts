/**
 * EXPERIMENTAL PROTOTYPE — SD-4 CANDIDATES UNDER ADVERSARIAL REVIEW, ROUND 2.
 *
 * Round 1 built candidates F, G and H and drove the SD-4 counterexample through
 * each. An independent adversarial pass then attacked all three, and it landed
 * hits that round 1 had not tested. This file executes those hits rather than
 * quoting them, and it revises two of round 1's own conclusions.
 *
 * WHAT THE ADVERSARIAL PASS FOUND THAT ROUND 1 MISSED:
 *
 *  1. SD-4 HAS TWO SATISFIABILITY AXES, NOT ONE. The recovery must satisfy both
 *     `floor.pqPublicKeyLength` and `floor.pqSignatureLength`, and the second is
 *     checked against `IKernelPQVerifier(r.proposedVerifier)` — a SHAPE-SPECIFIC
 *     oracle the QUORUM pinned at t0. Amending only the commitment repairs only
 *     the commitment. Round 1's F and G tests used an always-true verifier on the
 *     signature branch, which hid this completely. Both candidates are INERT
 *     against the signature axis, and that is executed below.
 *
 *  2. `recovery.active` IS NEVER CLEARED ON EXPIRY. `expiresAt` is read in
 *     exactly one place — `executeRecovery`'s `if (block.timestamp > r.expiresAt)
 *     revert Expired();` — and no writer clears the flag. So a long-dead request
 *     reads as live forever, and every candidate H triggers on that corpse.
 *
 *  3. THE METER IS ORDERABLE AWAY. Candidate H charges the declaring edge, but
 *     the credential chooses WHEN to declare. Declaring LAST leaves the meter
 *     inert and reproduces SD-4's three denials exactly. Round 1's H1 test drove
 *     the favourable order and drew a conclusion the adversary simply refuses to
 *     cooperate with.
 *
 * The repair that follows from (1) is G-PRIME: ratify the commitment AND the
 * verifier as one quorum act, because they are one decision. It is built,
 * attacked, and shown to close BOTH axes with a verifier that performs a REAL
 * possession check — not an always-true stub, which would make the result
 * indistinguishable from collapsing the PQ conjunct.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  VERIFIER_32_64_SOURCE,
  buildCandidateF,
  buildCandidateG,
  buildCandidateGPrime,
  buildCandidateGPrimeNotice,
  buildCandidateH1,
  buildCandidateH3,
  buildCandidateHPrecise,
  compileAuxContract,
} from "./sd4-candidate-kernels.js";
import { checkGlobals, snapshot } from "../stateful/invariants.js";
import {
  R,
  abi,
  at,
  bytesOfLength,
  cancel,
  declare,
  guardianDigest,
  pqPub,
  pqPubHash,
  proposeF,
  proposeHPrecise,
  proposeStd,
  quorum,
  spend,
} from "./sd4-harness.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  migrationParams,
  pqKeyBytes,
  sign,
  type Floor,
  type World,
} from "../stateful/world.js";

/** 32-byte key, 64-BYTE signature: a legitimate scheme shape the fixture verifier cannot accept. */
const SHAPE_32_64: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
const RATIFY_TAG = ethers.id("RATIFY_RECOVERY_COMMITMENT");

const sd4World = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

/** The 65-byte ECDSA encoding with the recovery byte dropped. A REAL possession proof at 64 bytes. */
const sig64 = (k: ethers.SigningKey, digest: string): string => ethers.dataSlice(sign(k, digest), 0, 64);

type Kernel = { abi: unknown[]; bytecode: string };
let F: Kernel;
let G: Kernel;
let GP: Kernel;
let GPN: Kernel;
let H1: Kernel;
let H3: Kernel;
let HP: Kernel;
let V64: Kernel;

before(function () {
  this.timeout(600_000);
  F = buildCandidateF();
  G = buildCandidateG();
  GP = buildCandidateGPrime();
  GPN = buildCandidateGPrimeNotice();
  H1 = buildCandidateH1();
  H3 = buildCandidateH3();
  HP = buildCandidateHPrecise();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

/** G-PRIME's ratification: commitment AND verifier, as one quorum act. */
async function ratifyPrime(
  w: World,
  v: ethers.Contract,
  hash: string,
  verifier: string,
): Promise<ethers.ContractTransactionResponse> {
  const r = await v.recovery();
  const params = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "address", "uint64"],
      [RATIFY_TAG, hash, verifier, r[R.SIGNER] as string, r[R.EXECUTABLE_AT] as bigint],
    ),
  );
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.ratifyRecoveryCommitment(hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE);
}

/** Plain G's ratification: commitment only. */
async function ratifyG(w: World, v: ethers.Contract, hash: string): Promise<ethers.ContractTransactionResponse> {
  const r = await v.recovery();
  const params = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "address", "uint64"],
      [RATIFY_TAG, hash, r[R.SIGNER] as string, r[R.VERIFIER] as string, r[R.EXECUTABLE_AT] as bigint],
    ),
  );
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.ratifyRecoveryCommitment(hash, quorum(w, digest), nonce, FAR_DEADLINE);
}

async function bindMigration(w: World, v: ethers.Contract): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: migrationParams(w.destination, w.destinationCodeHash, 1n),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.bindMigration(
    { vault: w.destination, codeHash: w.destinationCodeHash, generation: 1n },
    quorum(w, d),
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, d),
  );
}

describe("SD-4 round 2 — base-kernel facts the adversarial pass established", () => {
  it("`recovery.active` is NEVER cleared on expiry — a dead request reads as live forever", async function () {
    this.timeout(120_000);
    const w = await sd4World("r2-corpse");
    await proposeStd(
      w,
      w.vault,
      addrOf(keyOf("r2-corpse-nominee")),
      ethers.keccak256(bytesOfLength(48, "r2-corpse-key")),
      w.verifiers.honest,
    );
    const expires = (await w.vault.recovery())[R.EXPIRES_AT] as bigint;

    await networkHelpers.time.increase(7 * DAY + 14 * DAY + 100);
    const nowTs = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
    expect(nowTs, "the episode is past its expiry").to.be.greaterThan(expires);
    expect((await w.vault.recovery())[R.ACTIVE], "yet the flag still reads TRUE").to.equal(true);

    // The consequence that matters: every candidate H triggers on this flag, and
    // `bindMigration` is blocked by it, both with no live remedy behind it.
    await expect(bindMigration(w, w.vault), "migration is blocked by a corpse").to.be.revertedWithCustomError(
      w.vault,
      "NoRecovery",
    );
  });
});

describe("SD-4 round 2 — the SIGNATURE-LENGTH axis kills F and plain G", () => {
  it("F is INERT against the signature axis when the quorum pinned a real verifier", async function () {
    this.timeout(120_000);
    // Round 1's FORM 2 test used the ALWAYS-TRUE verifier, which accepts any
    // length and therefore hid this entirely. With a verifier that performs a
    // real check, the credential's free choice of `pqSignatureLength` destroys
    // the request no matter who binds the commitment.
    const w = await sd4World("r2-f-sig", F);
    const v = at(w, F);
    const nominee = keyOf("r2-f-sig-nominee");
    const nomineePq = keyOf("r2-f-sig-pq");

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    await networkHelpers.time.increase(7 * DAY + 1);

    const hash = pqPubHash(nomineePq);
    const pop = (await v.recoveryPossessionDigest(hash)) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(nomineePq, pop),
      }),
      "the nominee's key is free, but the SHAPE its proof must have is not",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });

  it("PLAIN G is INERT against the same axis — ratification cannot move the pinned verifier", async function () {
    this.timeout(120_000);
    const w = await sd4World("r2-g-sig", G);
    const v = at(w, G);
    const nominee = keyOf("r2-g-sig-nominee");
    const nomineePq = keyOf("r2-g-sig-pq");

    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2-g-sig-key")), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();

    // The quorum ratifies a commitment of exactly the declared KEY shape.
    await (await ratifyG(w, v, pqPubHash(nomineePq))).wait();
    expect((await v.recovery())[R.PQ_KEY_HASH], "the commitment is amended").to.equal(pqPubHash(nomineePq));

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: pqPubHash(nomineePq),
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(nomineePq, pop),
      }),
      "G repaired the commitment and the ORACLE is still wrong: SD-4 survives round 1's fix",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });
});

describe("SD-4 round 2 — G-PRIME closes BOTH axes without collapsing the PQ conjunct", () => {
  it("the 32/64 verifier is a REAL possession check, not an always-true stub", async function () {
    this.timeout(120_000);
    const w = await sd4World("r2-v64-control", GP);
    const addr = await deployV64(w);
    const c = new ethers.Contract(addr, V64.abi as ethers.InterfaceAbi, w.deployer);
    const k = keyOf("r2-v64-key");
    const other = keyOf("r2-v64-other");
    const d = ethers.id("r2-v64-digest");

    expect(await c.verify(d, pqPub(k), sig64(k, d)), "the holder's proof verifies").to.equal(true);
    expect(await c.verify(d, pqPub(k), sig64(other, d)), "another key's proof does NOT").to.equal(false);
    expect(await c.verify(d, pqPub(k), sign(k, d)), "and the 65-byte shape is refused").to.equal(false);
  });

  it("GREEN — G-PRIME repairs the signature axis and the recovered credential SPENDS", async function () {
    this.timeout(180_000);
    const w = await sd4World("r2-gp-green", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const nominee = keyOf("r2-gp-green-nominee");
    const nomineePq = keyOf("r2-gp-green-pq");

    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2-gp-key")), w.verifiers.honest);
    const t0 = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    await networkHelpers.time.increase(6 * DAY);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();

    // ONE quorum act amends the commitment AND the oracle that must accept it.
    await (await ratifyPrime(w, v, pqPubHash(nomineePq), v64)).wait();
    expect((await v.recovery())[R.EXECUTABLE_AT], "and the clock did not move").to.equal(t0);

    await networkHelpers.time.increase(1 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sig64(nomineePq, pop),
          })
        ).wait()
      )?.status,
      "SD-4 closed on BOTH axes at the ORIGINAL maturity",
    ).to.equal(1);

    // The second factor is REAL: the vault now spends only with a genuine
    // 64-byte possession proof, checked by a verifier that refuses impostors.
    const before = await ethers.provider.getBalance(w.recipient);
    const nonce = (await v.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await v.credentialGeneration()) as bigint;
    const sd = digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: 1n,
      actionType: ACTION.SPEND,
      authorityGeneration: credGen,
      params: ethers.keccak256(abi.encode(["address", "uint256"], [w.recipient, 1n])),
      domain: DOMAIN.SPEND,
      nonce,
      deadline: FAR_DEADLINE,
    });
    await expect(
      v.execute(
        w.recipient,
        1n,
        nonce,
        FAR_DEADLINE,
        sign(nominee, sd),
        sig64(keyOf("r2-gp-impostor"), sd),
        pqPub(nomineePq),
      ),
      "an impostor second factor is refused",
    ).to.be.revertedWithCustomError(v, "VerifierDenied");
    await (
      await v.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(nominee, sd), sig64(nomineePq, sd), pqPub(nomineePq))
    ).wait();
    expect(await ethers.provider.getBalance(w.recipient)).to.equal(before + 1n);
  });

  it("G-PRIME does NOT inherit F's kill — one compromised nominee root cannot late-bind", async function () {
    this.timeout(120_000);
    const w = await deployWorld({ label: "r2-gp-kill", implOverride: GP });
    const v = at(w, GP);
    const nominee = keyOf("r2-gp-kill-nominee");
    const nomineePq = keyOf("r2-gp-kill-pq");
    const attackerPq = keyOf("r2-gp-kill-attacker");

    await proposeStd(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: pqPubHash(attackerPq),
        newPqKey: pqPub(attackerPq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(attackerPq, pop),
      }),
      "amendment authority stayed with the QUORUM",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });

  it("G-PRIME grants NO new end state — the same credential AND verifier are reachable today", async function () {
    this.timeout(180_000);
    const w = await sd4World("r2-gp-endstate");
    const v64 = await deployV64(w);
    const nominee = keyOf("r2-gp-endstate-nominee");
    const nomineePq = keyOf("r2-gp-endstate-pq");

    await proposeStd(
      w,
      w.vault,
      addrOf(nominee),
      ethers.keccak256(bytesOfLength(48, "r2-gp-es-key")),
      w.verifiers.honest,
    );
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    // On the UNMODIFIED kernel the quorum reaches the identical end state by
    // re-initiating with the new commitment AND the new verifier — at the cost
    // of a whole fresh delay. That cost is the ONLY thing G-PRIME removes.
    await proposeStd(w, w.vault, addrOf(nominee), pqPubHash(nomineePq), v64);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: pqPubHash(nomineePq),
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(nomineePq, pop),
      })
    ).wait();
    expect(await w.vault.ecdsaSigner()).to.equal(addrOf(nominee));
    expect(await w.vault.pqVerifier(), "verifier and commitment both quorum-chosen, today").to.equal(v64);
  });

  it("G-PRIME's ZERO-NOTICE cost, disclosed and then removed by the NOTICE variant", async function () {
    this.timeout(180_000);
    // The adversarial pass is right that ratification AFTER maturity composes
    // with execution, leaving the credential no interval to object to the
    // amended value. It is a NOTICE loss on a value the quorum already controls
    // outright, not a cut change — but it is removable for one comparison.
    {
      const w = await sd4World("r2-gp-zero", GP);
      const v = at(w, GP);
      const v64 = await deployV64(w);
      const nominee = keyOf("r2-gp-zero-nominee");
      const nomineePq = keyOf("r2-gp-zero-pq");
      await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2z-key")), w.verifiers.honest);
      await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await ratifyPrime(w, v, pqPubHash(nomineePq), v64)).wait();
      const pop = (await v.recoveryPossessionDigest()) as string;
      expect(
        (
          await (
            await v.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: pqPubHash(nomineePq),
              newPqKey: pqPub(nomineePq),
              newEcdsaPop: sign(nominee, pop),
              newPqPop: sig64(nomineePq, pop),
            })
          ).wait()
        )?.status,
        "amended AFTER maturity, executed immediately: zero notice",
      ).to.equal(1);
    }
    {
      const w = await sd4World("r2-gpn-zero", GPN);
      const v = at(w, GPN);
      const v64 = await deployV64(w);
      await proposeStd(
        w,
        v,
        addrOf(keyOf("r2-gpn-nominee")),
        ethers.keccak256(bytesOfLength(48, "r2zn-key")),
        w.verifiers.honest,
      );
      await networkHelpers.time.increase(7 * DAY + 1);
      await expect(
        ratifyPrime(w, v, pqPubHash(keyOf("r2-gpn-pq")), v64),
        "the NOTICE variant refuses to amend a matured episode",
      ).to.be.revertedWithCustomError(v, "TooEarly");
    }
  });

  it("G-PRIME-NOTICE still closes SD-4 — the repair lives inside the delay window", async function () {
    this.timeout(180_000);
    const w = await sd4World("r2-gpn-green", GPN);
    const v = at(w, GPN);
    const v64 = await deployV64(w);
    const nominee = keyOf("r2-gpn-green-nominee");
    const nomineePq = keyOf("r2-gpn-green-pq");

    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2gn-key")), w.verifiers.honest);
    const t0 = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    await networkHelpers.time.increase(3 * DAY);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    await (await ratifyPrime(w, v, pqPubHash(nomineePq), v64)).wait();
    expect((await v.recovery())[R.EXECUTABLE_AT]).to.equal(t0);

    await networkHelpers.time.increase(4 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop),
            newPqPop: sig64(nomineePq, pop),
          })
        ).wait()
      )?.status,
    ).to.equal(1);
  });
});

describe("SD-4 round 2 — candidate H, attacked at the order the adversary chooses", () => {
  it("THE METER IS ORDERABLE AWAY — declaring LAST reproduces SD-4's three denials exactly", async function () {
    this.timeout(180_000);
    // Round 1 concluded H1 "restores the published bound in the typical case".
    // The adversary does not run the typical case. Cancelling twice first and
    // declaring last spends the whole budget AND lands the free third denial —
    // the identical 21 days SD-4 costs today.
    const w = await sd4World("r2-h1-order", H1);
    const v = at(w, H1);
    const nominee = keyOf("r2-h1-order-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2h1-key")), w.verifiers.honest);

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();

    expect((await v.recovery())[R.CHALLENGES], "THREE denials, the meter having gated nothing").to.equal(3n);
    expect((await v.recovery())[R.ACTIVE], "the third episode is dead too").to.equal(false);
  });

  it("H1 BREAKS the repository's own G-CHALLENGE-CAP property", async function () {
    this.timeout(180_000);
    const w = await sd4World("r2-h1-cap", H1);
    const v = at(w, H1);
    const nominee = keyOf("r2-h1-cap-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2cap-key")), w.verifiers.honest);

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();

    // The oracle reads the standard ABI, and the recovery tuple's layout is
    // unchanged by H1, so the published property can be evaluated directly.
    const now = await snapshot(w);
    const fired = checkGlobals(now, null, w).map((x) => x.name);
    expect(fired, "H1 drives challengesUsed to 3 against a published cap of 2").to.include("G-CHALLENGE-CAP");
  });

  it("H METERS A CORPSE — an EXPIRED request still costs the credential a challenge", async function () {
    this.timeout(180_000);
    const w = await sd4World("r2-h1-corpse", H1);
    const v = at(w, H1);
    await proposeStd(
      w,
      v,
      addrOf(keyOf("r2-corpse2-nominee")),
      ethers.keccak256(bytesOfLength(48, "r2corpse-key")),
      w.verifiers.honest,
    );
    // Let the episode die of old age. No principal acts.
    await networkHelpers.time.increase(7 * DAY + 14 * DAY + 100);
    expect((await v.recovery())[R.ACTIVE], "still reads live").to.equal(true);

    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    expect(
      (await v.recovery())[R.CHALLENGES],
      "the credential is charged for destroying something that was already dead",
    ).to.equal(1n);
  });

  it("H3 LATCHES AT CUT ZERO — an expired corpse plus a spent budget denies the declaration forever", async function () {
    this.timeout(240_000);
    const w = await sd4World("r2-h3-latch", H3);
    const v = at(w, H3);
    const nominee = keyOf("r2-h3-latch-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "r2h3-key")), w.verifiers.honest);

    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    await propose();
    // Every principal now walks away. Nothing is compromised; nobody acts.
    await networkHelpers.time.increase(7 * DAY + 14 * DAY + 100);

    for (let i = 0; i < 3; i++) {
      await expect(
        declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey)),
        `refused at round ${i}, with zero compromised roots and no adversary present`,
      ).to.be.revertedWithCustomError(v, "ChallengeExhausted");
      await networkHelpers.time.increase(30 * DAY);
    }
  });

  it("H1 GIVES THE CREDENTIAL A THIRD CLEAR of recovery.active, unlocking bindMigration", async function () {
    this.timeout(240_000);
    // `I-MIGRATION-SUBORDINATE-TO-RECOVERY` blocks binding while a request is
    // live, and `cancelRecovery` is capped so the credential runs out of ways to
    // clear it. H1's declaring edge is a THIRD clear, available exactly when the
    // cap has bitten. Migration still needs the quorum's half, so no section 3
    // row moves — but the guard is weaker than the kernel's own comment claims.
    const nominee = keyOf("r2-mig-nominee");
    const key = ethers.keccak256(bytesOfLength(48, "r2mig-key"));

    // CONTROL — the unmodified kernel refuses.
    {
      const w = await sd4World("r2-mig-control");
      const propose = () => proposeStd(w, w.vault, addrOf(nominee), key, w.verifiers.honest);
      await propose();
      await (await cancel(w, w.vault, w.credKey)).wait();
      await propose();
      await (await cancel(w, w.vault, w.credKey)).wait();
      await propose();
      await expect(cancel(w, w.vault, w.credKey)).to.be.revertedWithCustomError(w.vault, "ChallengeExhausted");
      await expect(bindMigration(w, w.vault), "the block holds").to.be.revertedWithCustomError(
        w.vault,
        "NoRecovery",
      );
    }

    // H1 — the declaration clears it.
    {
      const w = await sd4World("r2-mig-h1", H1);
      const v = at(w, H1);
      const propose = () => proposeStd(w, v, addrOf(nominee), key, w.verifiers.honest);
      await propose();
      await (await cancel(w, v, w.credKey)).wait();
      await propose();
      await (await cancel(w, v, w.credKey)).wait();
      await propose();
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
      await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
      expect((await v.recovery())[R.ACTIVE]).to.equal(false);
      expect(
        (await (await bindMigration(w, v)).wait())?.status,
        "binding now succeeds where the unmodified kernel refuses",
      ).to.equal(1);
    }
  });

  it("H-PRECISE's COMPATIBILITY PREDICATE IS UNSOUND — equal lengths do not imply survival", async function () {
    this.timeout(180_000);
    // H-PRECISE spares a declaration whose declared lengths equal the request's.
    // Equality of lengths is not satisfiability: the pinned verifier must also
    // ACCEPT that shape. Here the request declares 32/64 and the floor is armed
    // at 32/64 — the predicate says "harmless", nothing is metered, and the
    // episode is dead anyway because the quorum pinned a 32/65 verifier.
    const w = await sd4World("r2-hp-unsound", HP);
    const v = at(w, HP);
    const nominee = keyOf("r2-hp-unsound-nominee");
    const nomineePq = keyOf("r2-hp-unsound-pq");

    await proposeHPrecise(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest, 32, 64);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();

    const r = await v.recovery();
    expect(r[R.ACTIVE], "the predicate judged the declaration harmless").to.equal(true);
    expect(r[R.CHALLENGES], "so nothing was metered").to.equal(0n);

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: pqPubHash(nomineePq),
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(nomineePq, pop),
      }),
      "and the episode is dead regardless: a FREE, UNMETERED destruction",
    ).to.be.revertedWithCustomError(v, "BadSignature");
  });
});

describe("SD-4 round 2 — what the built F does that its specification did not", () => {
  it("the BUILT F still enforces the dormant exhibit, so I-COMMITMENT-EXHIBITED-AT-ADMISSION holds", async function () {
    this.timeout(120_000);
    // The adversarial pass reported that F, as written in prose, drops the
    // `bytes32(0)`-guarded dormant clause on the recovery path. The BUILT F
    // passes `expectedPqKeyHash = c.newPqKeyHash`, so that clause fires and
    // demands a preimage. This is the difference between reviewing a design and
    // reviewing an artifact, and it is worth one test.
    const w = await sd4World("r2-f-exhibit", F);
    const v = at(w, F);
    const nominee = keyOf("r2-f-exhibit-nominee");

    await proposeF(w, v, addrOf(nominee), w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);
    // Dormant floor: no PQ conjunct is mandatory. A NON-ZERO commitment with no
    // matching preimage must still be refused.
    const bogus = ethers.id("a-commitment-with-no-exhibited-preimage");
    const pop = (await v.recoveryPossessionDigest(bogus)) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: bogus,
        newPqKey: bytesOfLength(32, "r2-f-exhibit-wrong"),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: "0x",
      }),
      "an unattested commitment is refused on the dormant path",
    ).to.be.revertedWithCustomError(v, "BadSignature");

    // POSITIVE CONTROL: with the preimage exhibited, the same call succeeds.
    const key = bytesOfLength(32, "r2-f-exhibit-right");
    const hash = ethers.keccak256(key);
    const pop2 = (await v.recoveryPossessionDigest(hash)) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: hash,
            newPqKey: key,
            newEcdsaPop: sign(nominee, pop2),
            newPqPop: "0x",
          })
        ).wait()
      )?.status,
    ).to.equal(1);
  });
});
