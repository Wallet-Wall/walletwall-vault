/**
 * EXPERIMENTAL PROTOTYPE — LANE W: RECOVERY LIFECYCLE SEMANTIC FREEZE.
 *
 * Everything here measures the FROZEN CANDIDATE against the extremes it must
 * beat. No production Solidity is touched; both kernels are compiled in memory.
 *
 * Boundary derived rather than guessed, and the two artifacts DISAGREE:
 *   kernel  VaultKernelPrototype.sol:1228  `now >  expiresAt` -> Expired
 *           => live while `now <= expiresAt`  (live AT the boundary)
 *   model   vaultVNextModel.ts:1031, :1040  `clock >= expiresAt` -> dead
 *           => dead AT the boundary
 * The architecture specifies neither. The frozen statement adopts the KERNEL
 * boundary, matching "has not passed its authorized expiry", and the divergence
 * is recorded for reconciliation rather than silently resolved.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  VERIFIER_32_64_SOURCE,
  buildLaneWNeverReset,
  buildLaneWResetting,
  compileAuxContract,
} from "./sd4-candidate-kernels.js";
import { R, abi, at, cancel, declare, guardianDigest, quorum } from "./sd4-harness.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  pqKeyBytes,
  sign,
  type Floor,
  type World,
} from "../stateful/world.js";

const QCANCEL_TAG = ethers.id("QUORUM_CANCEL_RECOVERY");
const KEY32 = (tag: string) => abi.encode(["address"], [addrOf(keyOf(tag))]);

type Kernel = { abi: unknown[]; bytecode: string };
const K: Record<string, Kernel> = {};
let V64: Kernel;

before(function () {
  this.timeout(900_000);
  K.reset = buildLaneWResetting();
  K.never = buildLaneWNeverReset();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

async function propose(w: World, v: ethers.Contract, signer: string, hash: string, verifier: string) {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, hash, verifier]));
  const { digest, nonce } = await guardianDigest(w, v, params);
  await (await v.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

async function quorumCancel(w: World, v: ethers.Contract) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE);
}

/** An in-place rotation: same signer, same commitment, no new material. */
async function rotateInPlace(w: World, v: ethers.Contract) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.credentialGeneration()) as bigint;
  const hash = (await v.pqPublicKeyHash()) as string;
  const signer = addrOf(w.credKey);
  const pop = (await v.credentialPossessionDigest(signer, hash)) as string;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.ROTATE,
    authorityGeneration: gen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [signer, hash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.rotateCredential(
    {
      newSigner: signer,
      newPqKeyHash: hash,
      newPqKey: pqKeyBytes(w.pqKey),
      newEcdsaPop: sign(w.credKey, pop),
      newPqPop: sign(w.pqKey, pop),
    },
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, d),
    sign(w.pqKey, d),
    pqKeyBytes(w.pqKey),
  );
}

/** Drive a full recovery to a NEW credential and return that credential's keys. */
async function recoverTo(w: World, v: ethers.Contract, tag: string) {
  const nominee = keyOf(`${tag}-signer`);
  const pqNominee = keyOf(`${tag}-pq`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  const hash = ethers.keccak256(key32);
  await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
  await networkHelpers.time.increase(7 * DAY + 1);
  const pop = (await v.recoveryPossessionDigest()) as string;
  await (
    await v.executeRecovery({
      newSigner: addrOf(nominee),
      newPqKeyHash: hash,
      newPqKey: key32,
      newEcdsaPop: sign(nominee, pop),
      newPqPop: sign(pqNominee, pop),
    })
  ).wait();
  return { nominee, pqNominee };
}

async function exhaust(w: World, v: ethers.Contract, credKey: ethers.SigningKey, tag: string) {
  const nominee = addrOf(keyOf(`${tag}-nom`));
  const hash = ethers.keccak256(KEY32(`${tag}-pq`));
  for (let i = 0; i < 2; i++) {
    await propose(w, v, nominee, hash, w.verifiers.honest);
    await (await cancel(w, v, credKey)).wait();
  }
}

describe("SD-4 lane W — recovery lifecycle semantic freeze", () => {
  // ===================================================================
  // B — the challenge epoch
  // ===================================================================

  it("B1 GENERATION-KEY SELF-REFUND — preserved: the epoch must not follow credentialGeneration", async function () {
    this.timeout(300_000);
    // The V2 result, restated against the FROZEN candidate: with the epoch in
    // standalone storage and only ONE reset site, an ordinary in-place rotation
    // no longer refunds anything. `_installCredential` still bumps the
    // generation on both paths (:800 rotate, :1242 recovery) — the frozen design
    // simply stops using the generation as the epoch key.
    const w = await deployWorld({ label: "w-b1", implOverride: K.reset });
    const v = at(w, K.reset);
    await exhaust(w, v, w.credKey, "w-b1");
    expect(await v.recoveryChallengesUsed(), "exhausted").to.equal(2n);

    const genBefore = (await v.credentialGeneration()) as bigint;
    await (await rotateInPlace(w, v)).wait();
    expect((await v.credentialGeneration()) as bigint, "rotation still bumps it").to.be.greaterThan(genBefore);
    expect(await v.recoveryChallengesUsed(), "but the epoch did not follow").to.equal(2n);

    await propose(w, v, addrOf(keyOf("w-b1-nom")), ethers.keccak256(KEY32("w-b1-pq")), w.verifiers.honest);
    await expect(cancel(w, v, w.credKey), "still exhausted after rotation").to.be.revertedWithCustomError(
      v,
      "ChallengeExhausted",
    );
  });

  it("B2 NEVER-RESET DEGENERATION — a legitimate history silently deletes the D1 defence", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "w-b2", implOverride: K.never });
    const v = at(w, K.never);

    // A legitimate history: the credential exercises its full bounded defence.
    await exhaust(w, v, w.credKey, "w-b2");
    expect(await v.recoveryChallengesUsed()).to.equal(2n);

    // A legitimate guardian recovery then completes, installing NEW material.
    const fresh = await recoverTo(w, v, "w-b2-new");
    expect(await v.ecdsaSigner(), "new credential installed").to.equal(addrOf(fresh.nominee));
    expect(await v.credentialGeneration(), "authority transition happened").to.equal(2n);

    // THE DEGENERATION. The new credential — a different principal, holding
    // material the old one never had — inherits ZERO challenge capacity.
    expect(await v.recoveryChallengesUsed(), "budget never returns").to.equal(2n);
    await propose(w, v, addrOf(keyOf("w-b2-third")), ethers.keccak256(KEY32("w-b2-third-pq")), w.verifiers.honest);
    await expect(
      cancel(w, v, fresh.nominee),
      "the new holder has no bounded defence at all",
    ).to.be.revertedWithCustomError(v, "ChallengeExhausted");

    // This does not lose assets. What it deletes is the §22 D1 / H-15 defence —
    // "a finite, non-zero k costs the attacker k x recoveryDelay" — for every
    // credential after the first, permanently, with no event marking the loss.
  });

  it("B3 RESET-ON-SUCCESS — no principal can manufacture budget, across six transitions", async function () {
    this.timeout(900_000);
    const w = await deployWorld({ label: "w-b3", implOverride: K.reset });
    const v = at(w, K.reset);

    // (i) ordinary rotation BEFORE recovery — no refund.
    await exhaust(w, v, w.credKey, "w-b3");
    await (await rotateInPlace(w, v)).wait();
    expect(await v.recoveryChallengesUsed(), "rotation before: no refund").to.equal(2n);

    // (ii) cancellation immediately before recovery — no refund.
    await propose(w, v, addrOf(keyOf("w-b3-a")), ethers.keccak256(KEY32("w-b3-a-pq")), w.verifiers.honest);
    await (await quorumCancel(w, v)).wait();
    expect(await v.recoveryChallengesUsed(), "quorum cancel: no refund").to.equal(2n);

    // (iii) expiry immediately before a later recovery — no refund.
    await propose(w, v, addrOf(keyOf("w-b3-b")), ethers.keccak256(KEY32("w-b3-b-pq")), w.verifiers.honest);
    const exp = (await v.recovery())[R.EXPIRES_AT] as bigint;
    await networkHelpers.time.increaseTo(Number(exp) + 1);
    expect(await v.effectiveLiveRecovery(), "expired without any principal acting").to.equal(false);
    expect(await v.recoveryChallengesUsed(), "expiry: no refund").to.equal(2n);

    // (iv) recovery to genuinely NEW material — the one reset site fires.
    const fresh = await recoverTo(w, v, "w-b3-new");
    expect(await v.recoveryChallengesUsed(), "authority transition resets the epoch").to.equal(0n);
    expect(await v.ecdsaSigner()).to.equal(addrOf(fresh.nominee));

    // (v) ordinary rotation AFTER recovery — still no refund path.
    await propose(w, v, addrOf(keyOf("w-b3-c")), ethers.keccak256(KEY32("w-b3-c-pq")), w.verifiers.honest);
    await (await cancel(w, v, fresh.nominee)).wait();
    expect(await v.recoveryChallengesUsed(), "new holder spent one").to.equal(1n);

    // (vi) recovery REINSTALLING IDENTICAL material still resets — because the
    // boundary is the AUTHORITY TRANSITION, not byte equality of the payload.
    const nominee = fresh.nominee;
    const pqNominee = fresh.pqNominee;
    const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
    const hash = ethers.keccak256(key32);
    await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(pqNominee, pop),
      })
    ).wait();
    expect(await v.recoveryChallengesUsed(), "identical material, same reset").to.equal(0n);

    // AND THE MANUFACTURE QUESTION: every reset requires a completed guardian
    // recovery, which requires the quorum. No credential-only path exists, and
    // the credential cannot initiate.
    expect(
      w.vault.interface.getFunction("initiateRecovery")?.inputs.some((i) => i.name === "proof"),
      "initiation is quorum-gated, so the credential cannot self-trigger a reset",
    ).to.equal(true);
  });

  // ===================================================================
  // D, E and F were REMOVED in Lane W1R. They measured effective expiry,
  // overwrite and the SD-4 remedy on the SUPERSEDED closed boundary
  // (live at expiresAt). Sd4LaneW1.test.ts re-establishes every one of those
  // claims on the reconciled half-open boundary and asserts strictly more —
  // mined-timestamp probes at expiresAt-1 / expiresAt / expiresAt+1 and the
  // two-path remedy across seven timings. B1–B3 above are boundary-independent
  // and remain the sole executable witness for the never-reset degeneration.
  // ===================================================================
});
