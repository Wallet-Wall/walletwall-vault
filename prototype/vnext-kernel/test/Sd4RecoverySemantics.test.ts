/**
 * EXPERIMENTAL PROTOTYPE — SD-4, REPRODUCED AT THE PREDICATE.
 *
 * SD-4 is usually stated as "the declaration destroys an approved recovery".
 * That is the SYMPTOM. This file establishes the MECHANISM, because the
 * remediation hypothesis stands or falls on which read actually changed:
 *
 *   `executeRecovery` -> `_requireIncomingPossession` reads `securityFloor`
 *   LIVE and measures the quorum's already-approved request against
 *   `floor.pqPublicKeyLength` / `floor.pqSignatureLength`.
 *
 * THE STRUCTURAL FACT THAT BOUNDS THE WHOLE PROBLEM, and that every candidate
 * design must be judged against:
 *
 *   `requirePq` is MONOTONE (`_requireNoDowngrade` refuses true -> false) and
 *   `I-FLOOR-SHAPE-IMMUTABLE` freezes BOTH lengths the instant `requirePq`
 *   holds. So the live lengths are mutable in EXACTLY ONE window in a vault's
 *   life — while `requirePq` is false — and they change EXACTLY ONCE, at the
 *   declaring edge.
 *
 * That is the entire SD-4 surface. It is not a general "execution reads mutable
 * state" problem; it is one transition, once, on one vault class.
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
  keyOf,
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
const abi = ethers.AbiCoder.defaultAbiCoder();

/** Index of `active` / `challengesUsed` in the public `recovery()` tuple. */
const R_CHALLENGES = 6;
const R_ACTIVE = 7;

const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) out += ethers.id(`${tag}-${i++}`).slice(2);
  return "0x" + out.slice(0, n * 2);
};

async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/** Guardian quorum proposes a recovery. Returns nothing; the request is on chain. */
async function propose(
  w: World,
  newCred: ethers.SigningKey,
  pqKeyHash: string,
  verifier: string,
): Promise<void> {
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER,
    authorityGeneration: gGen,
    params: recoverParams(addrOf(newCred), pqKeyHash, verifier),
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.initiateRecovery(addrOf(newCred), pqKeyHash, verifier, {
      members: w.guardians,
      isContract: w.guardianIsContract,
      attestingIndices: [0, 1],
      attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
    }, nonce, FAR_DEADLINE)
  ).wait();
}

/** The credential principal declares the PQ floor — the `requirePq` false -> true edge. */
async function declare(w: World, floor: Floor, pqKey: string): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(w.verifiers.honest, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.setVerifier(
      w.verifiers.honest, floorTuple(floor), nonce, FAR_DEADLINE,
      sign(w.credKey, d), "0x", pqKey,
    )
  ).wait();
}

/** Attempt the matured recovery with the quorum's proposed material. */
async function execute(
  w: World,
  newCred: ethers.SigningKey,
  pqKeyHash: string,
  pqKey: string,
  pqSig: string,
): Promise<ethers.ContractTransactionResponse> {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  return w.vault.executeRecovery({
    newSigner: addrOf(newCred),
    newPqKeyHash: pqKeyHash,
    newPqKey: pqKey,
    newEcdsaPop: sign(newCred, pop),
    newPqPop: pqSig,
  });
}

describe("SD-4 — the live read that destroys an approved recovery", () => {
  it("THE STRUCTURAL BOUND: the floor lengths are mutable in exactly ONE window", async () => {
    const w = await deployWorld({
      label: "sd4-window", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    // S0 — dormant. Both lengths are ZERO and unvalidated.
    expect(await liveFloor(w)).to.deep.equal({
      requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0,
    });

    await declare(w, { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      pqKeyBytes(w.pqKey));

    // S1 — armed. Both lengths are now FROZEN: I-FLOOR-SHAPE-IMMUTABLE.
    const f1 = await liveFloor(w);
    expect(f1.pqPublicKeyLength).to.equal(32);
    expect(f1.pqSignatureLength).to.equal(65);

    // Any further move of either length is refused, in both directions, forever.
    for (const shape of [
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 64, pqSignatureLength: 65 },
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 128 },
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 16, pqSignatureLength: 65 },
    ]) {
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const credGen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: credGen,
        params: setVerifierParams(w.verifiers.honest, shape),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      await expect(
        w.vault.setVerifier(w.verifiers.honest, floorTuple(shape), nonce, FAR_DEADLINE,
          sign(w.credKey, d), sign(w.pqKey, d), pqKeyBytes(w.pqKey)),
        "the shape is frozen once requirePq holds",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    }
  });

  it("SD-4 FORM 1 — approved recovery dies on the KEY length; the predicate is the live floor", async () => {
    const w = await deployWorld({
      label: "sd4-form1", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const newCred = keyOf("sd4-form1-cred");
    // The quorum proposes a 48-byte PQ key. Nothing about the proposal is
    // malformed: at S0 no shape exists, so no shape can contradict it.
    const proposedKey = bytesOfLength(48, "sd4-form1-key");
    const proposedHash = ethers.keccak256(proposedKey);

    await propose(w, newCred, proposedHash, w.verifiers.alwaysTrue);
    expect((await w.vault.recovery())[R_ACTIVE], "approved and staged").to.equal(true);
    const challengesAtProposal = Number((await w.vault.recovery())[R_CHALLENGES]);

    // S0 -> S1. A legitimate declaration by the credential principal, exhibiting
    // the vault's OWN committed key, so I-DECLARATION-EXHIBITED is satisfied.
    await declare(w, { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      pqKeyBytes(w.pqKey));

    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      execute(w, newCred, proposedHash, proposedKey, bytesOfLength(65, "sd4-form1-sig")),
      "SD-4: the approved request is now unexecutable",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // Q8/Q9 — no new guardian approval occurred, and nothing was accounted.
    expect(Number((await w.vault.recovery())[R_CHALLENGES]), "challengesUsed unchanged")
      .to.equal(challengesAtProposal);
    expect((await w.vault.recovery())[R_ACTIVE], "and the request is left STRANDED ACTIVE")
      .to.equal(true);
  });

  it("SD-4 FORM 2 — the same request dies on the SIGNATURE length, a different conjunct", async () => {
    const w = await deployWorld({
      label: "sd4-form2", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const newCred = keyOf("sd4-form2-cred");
    // This time the proposed KEY length matches what will be declared, so only
    // the SIGNATURE length can be the cause. Any fix constraining one length
    // alone closes neither form reliably.
    const proposedKey = pqKeyBytes(keyOf("sd4-form2-pq"));
    const proposedHash = ethers.keccak256(proposedKey);
    expect(ethers.dataLength(proposedKey), "32 bytes, matching the shape to be declared").to.equal(32);

    await propose(w, newCred, proposedHash, w.verifiers.alwaysTrue);
    await declare(w, { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      pqKeyBytes(w.pqKey));
    await networkHelpers.time.increase(7 * DAY + 1);

    // A 64-byte PoP: legal at S0 where no signature shape existed, refused at S1.
    await expect(
      execute(w, newCred, proposedHash, proposedKey, bytesOfLength(64, "sd4-form2-sig")),
      "SD-4 form 2: the signature length is the killing conjunct",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });

  it("THE PREDICATE WAS NEVER IN THE AUTHORITY STATEMENT — proven from the digest preimage", async () => {
    // What the guardians signed is `keccak256(abi.encode(signer, pqKeyHash,
    // verifier))`. No length, no floor, no shape. So the value that decided
    // executability at S1 is one the quorum never saw and never authorised.
    const w = await deployWorld({ label: "sd4-digest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });
    const newCred = keyOf("sd4-digest-cred");
    const hash = pqHash(keyOf("sd4-digest-pq"));

    const viaHelper = recoverParams(addrOf(newCred), hash, w.verifiers.honest);
    const byHand = ethers.keccak256(
      abi.encode(["address", "bytes32", "address"], [addrOf(newCred), hash, w.verifiers.honest]),
    );
    expect(viaHelper, "the authority statement is exactly (signer, pqKeyHash, verifier)").to.equal(byHand);

    // And it is INSENSITIVE to the shape: two different floors produce the same
    // guardian digest, so no guardian signature can distinguish them.
    const shapeA = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const shapeB = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 48, pqSignatureLength: 96 };
    expect(setVerifierParams(w.verifiers.honest, shapeA)).to.not.equal(setVerifierParams(w.verifiers.honest, shapeB));
    expect(viaHelper, "yet the RECOVERY statement contains neither").to.equal(byHand);
  });

  it("POSITIVE CONTROL — without the declaration the identical recovery executes and spends", async () => {
    const w = await deployWorld({
      label: "sd4-control", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const newCred = keyOf("sd4-control-cred");
    const proposedKey = bytesOfLength(48, "sd4-control-key");
    const proposedHash = ethers.keccak256(proposedKey);

    await propose(w, newCred, proposedHash, w.verifiers.alwaysTrue);
    await networkHelpers.time.increase(7 * DAY + 1);
    expect(
      (await (await execute(w, newCred, proposedHash, proposedKey, bytesOfLength(65, "sd4-control-sig"))).wait())?.status,
      "the SAME request, minus the declaration, executes",
    ).to.equal(1);
    expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));

    // ...and the recovered credential can move value, so the control is real.
    const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await w.vault.credentialGeneration()) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SPEND, authorityGeneration: credGen,
      params: spendParams(w.recipient, 1n), domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
    });
    expect(
      (await (await w.vault.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(newCred, d), "0x", "0x")).wait())?.status,
    ).to.equal(1);
  });
});
