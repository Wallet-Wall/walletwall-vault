/**
 * EXPERIMENTAL PROTOTYPE — TWO PREMISES OF #186/#188's REJECTION ARGUMENT,
 * TESTED RATHER THAN INHERITED.
 *
 * The argument that removed the SD-4 interlock, quoted from `setVerifier`'s own
 * comment at `c67d1439`, is:
 *
 *   "because the declaration is ONE-SHOT and no guardian path can ever write
 *    `securityFloor`, that refusal hands the quorum a renewable, uncounted veto
 *    over a capability IT CANNOT ITSELF EXERCISE"
 *
 * Both halves of the premise are TRUE of the source — `securityFloor` has
 * exactly two writers and neither is quorum-reachable, and `initiateRecovery`
 * carries no `!recovery.active` guard. What does not follow is the word the
 * conclusion turns on. "Cannot exercise" is silently used as "cannot obstruct",
 * and this file shows the second is false: the guardian quorum ALREADY holds a
 * budgeted obstruction over the declaring edge, today, with no candidate
 * applied. `setVerifier` opens with `_requireNormal()`, and `enterContainment`
 * is quorum-gated and leaves NORMAL — while `_requireRecoveryOpen` keeps
 * `initiateRecovery` available throughout.
 *
 * The second premise audited here is the candidate specification's own framing —
 * mine, not #188's — that the declaring edge "chooses BOTH structural lengths
 * freely". Only `pqSignatureLength` is free. `I-DECLARATION-EXHIBITED` pins
 * `pqPublicKeyLength` to the length of an exhibited preimage of the LIVE
 * commitment, so moving the key length requires a preparatory
 * `rotateCredential` on the dormant path. That asymmetry is why the signature
 * axis is the one that survives every candidate, and it is established here.
 *
 * NEITHER RESULT RESCUES THE INTERLOCK. A budgeted three-day obstruction is not
 * an unbounded one, and the interlock's own harm is unchanged. What they correct
 * is the CATEGORICAL form of the published argument — "a capability it cannot
 * itself exercise" reads as though the quorum had no purchase on the declaring
 * edge at all, and it has one.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { R, at, bytesOfLength, declare, liveFloor, proposeStd, quorum, quorumCancelStd } from "./sd4-harness.js";
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

const ARMED: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

const sd4World = (label: string) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });

async function enterContainment(w: World): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: (await w.vault.guardianGeneration()) as bigint,
    params: ethers.id("CONTAIN"),
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.enterContainment(quorum(w, d), nonce, FAR_DEADLINE);
}

/** A dormant-path rotation: ECDSA-only authority, an exhibited preimage of ANY length. */
async function rotateDormant(
  w: World,
  newPqKey: string,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const signer = addrOf(w.credKey);
  const hash = ethers.keccak256(newPqKey);
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.ROTATE,
    authorityGeneration: credGen,
    params: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [signer, hash]),
    ),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const pop = (await w.vault.credentialPossessionDigest(signer, hash)) as string;
  return w.vault.rotateCredential(
    {
      newSigner: signer,
      newPqKeyHash: hash,
      newPqKey,
      newEcdsaPop: sign(w.credKey, pop),
      newPqPop: "0x",
    },
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, d),
    "0x",
    "0x",
  );
}

describe("SD-4 round 3 — auditing the premises the rejection argument rests on", () => {
  it("THE QUORUM ALREADY OBSTRUCTS THE DECLARING EDGE — containment blocks setVerifier today", async function () {
    this.timeout(180_000);
    const w = await sd4World("r3-contain");
    await proposeStd(
      w,
      w.vault,
      addrOf(keyOf("r3-contain-nominee")),
      ethers.keccak256(bytesOfLength(48, "r3-contain-key")),
      w.verifiers.honest,
    );

    // k guardians alone enter containment. No credential participation.
    await (await enterContainment(w)).wait();
    expect(await w.vault.effectiveSafeState(), "CONTAINED").to.equal(1n);

    // `setVerifier` opens with `_requireNormal()`, so the declaring edge is shut.
    await expect(
      declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey)),
      "the quorum obstructs the floor write it supposedly has no purchase on",
    ).to.be.revertedWithCustomError(w.vault, "BadState");

    // ...and `initiateRecovery` stays open the whole time, because
    // `_requireRecoveryOpen` admits CONTAINED. W2 SUPERSESSION: the W2 kernel
    // refuses to overwrite the LIVE request staged above, so the quorum takes
    // its own exit first — which is itself gated by `_requireRecoveryOpen` and
    // therefore also proves that gate admits CONTAINED — and then re-proposes.
    await (await quorumCancelStd(w, w.vault)).wait();
    await proposeStd(
      w,
      w.vault,
      addrOf(keyOf("r3-contain-nominee2")),
      ethers.keccak256(bytesOfLength(48, "r3-contain-key2")),
      w.verifiers.honest,
    );
    expect((await w.vault.recovery())[R.ACTIVE]).to.equal(true);

    // THE OBSTRUCTION IS BUDGETED, and that is the half of the published
    // argument that IS right: containment self-expires on wall clock, and
    // CONTAINMENT_BUDGET (6d) < CONTAINMENT_WINDOW (30d) bounds the duty cycle.
    // So this is a bounded obstruction, not the unbounded one an interlock would
    // create — the correction is to the word "cannot exercise", not to the
    // interlock's verdict.
    await networkHelpers.time.increase(3 * DAY + 1);
    expect(await w.vault.effectiveSafeState(), "self-expired to NORMAL").to.equal(0n);
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, ARMED, pqKeyBytes(w.pqKey))).wait();
    expect((await liveFloor(w.vault)).requirePq).to.equal(true);
  });

  it("ONLY pqSignatureLength IS FREE AT THE DECLARING EDGE — the key length is pinned by the exhibit", async function () {
    this.timeout(180_000);
    const w = await sd4World("r3-asym");

    // The vault's live commitment is a 32-byte key, so a declaration at any
    // OTHER key length cannot exhibit a preimage and is refused...
    for (const badLen of [16, 48, 64]) {
      const shape: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: badLen, pqSignatureLength: 65 };
      await expect(
        declare(w, w.vault, w.credKey, w.verifiers.honest, shape, bytesOfLength(badLen, `r3-asym-${badLen}`)),
        `I-DECLARATION-EXHIBITED pins the key length at ${badLen}`,
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    }

    // ...while the SIGNATURE length is bound by nothing at all. Every value
    // below is accepted on a fresh vault with the identical commitment.
    for (const sigLen of [1, 33, 96, 4096]) {
      const fresh = await sd4World(`r3-asym-sig-${sigLen}`);
      const shape: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: sigLen };
      await (await declare(fresh, fresh.vault, fresh.credKey, fresh.verifiers.honest, shape, pqKeyBytes(fresh.pqKey))).wait();
      expect(
        (await liveFloor(fresh.vault)).pqSignatureLength,
        `no commitment anywhere binds a signature length of ${sigLen}`,
      ).to.equal(sigLen);
    }
  });

  it("THE KEY LENGTH IS MOVABLE, but only via a preparatory dormant ROTATION at cut 1", async function () {
    this.timeout(180_000);
    const w = await sd4World("r3-rotate");
    await proposeStd(
      w,
      w.vault,
      addrOf(keyOf("r3-rotate-nominee")),
      ethers.keccak256(bytesOfLength(32, "r3-rotate-approved")),
      w.verifiers.honest,
    );

    // The dormant path imposes a preimage but NO length, so the credential moves
    // the commitment to a 64-byte value using the ECDSA conjunct alone...
    const key64 = bytesOfLength(64, "r3-rotate-key64");
    await (await rotateDormant(w, key64)).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(key64));

    // ...and the declaring edge can now pin a 64-byte key shape, exhibiting it.
    const shape: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 64, pqSignatureLength: 65 };
    await (await declare(w, w.vault, w.credKey, w.verifiers.honest, shape, key64)).wait();
    expect((await liveFloor(w.vault)).pqPublicKeyLength).to.equal(64);

    // The quorum's 32-byte approved commitment is now unsatisfiable on the key
    // axis — SD-4, reached through two cut-1 transitions instead of one.
    await networkHelpers.time.increase(7 * DAY + 1);
    const nominee = keyOf("r3-rotate-nominee");
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(bytesOfLength(32, "r3-rotate-approved")),
        newPqKey: bytesOfLength(32, "r3-rotate-approved"),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(65, "r3-rotate-sig"),
      }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });
});
