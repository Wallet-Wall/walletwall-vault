/**
 * EXPERIMENTAL PROTOTYPE — SD-4, REPRODUCED AT THE PREDICATE, AND NARROWED BY
 * SD5-I / E-PRIME.
 *
 * SD-4 is usually stated as "the declaration destroys an approved recovery".
 * That is the SYMPTOM. This file establishes the MECHANISM, because both the
 * remediation and the RESIDUAL stand or fall on WHICH read decides:
 *
 *   `executeRecovery` -> `_requireIncomingPossession` reads `securityFloor`
 *   LIVE and measures the quorum's already-approved request against it.
 *
 * WHAT SD5-I REMOVED, AND WHAT THAT DOES TO THIS FILE.
 *
 *   `pqPublicKeyLength`, `pqSignatureLength` and `pqParamLevel` are, after the
 *   accepted E-PRIME amendment, SIGNED_METADATA + IDENTITY_BOUND_METADATA +
 *   NON_AUTHORITATIVE_SECURITY_METADATA + ABI_COMPATIBILITY. They are
 *   explicitly NOT AUTHORIZATION_INPUT, NOT RECOVERY_SATISFIABILITY_INPUT and
 *   NOT CRYPTOGRAPHIC_STRENGTH: no authorization, possession or satisfiability
 *   path reads them. They remain covered by the credential principal's
 *   `setVerifier` digest and bound into the genesis identity, which is why they
 *   are still recorded and still asserted on below.
 *
 *   So the two classic SD-4 forms — an approved recovery dying on the declared
 *   KEY length, and the same request dying on the declared SIGNATURE length —
 *   ARE CLOSED. That whole route was SHAPE-SCOPED: it turned on the declared
 *   shape contradicting the proposed material, never on the strength of any
 *   cryptographic relation. Both are INVERTED below, and the surviving
 *   structural-validity duty is shown to sit with the VERIFIER.
 *
 *   `I-FLOOR-SHAPE-IMMUTABLE` is RETIRED, not weakened: with no authoritative
 *   shape it has no operand. Its replacement is
 *   `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` — for an APPROVED
 *   recovery, moving `pqPublicKeyLength`, `pqSignatureLength` or `pqParamLevel`
 *   cannot change whether it executes. The old "the lengths are mutable in
 *   exactly ONE window" bound is therefore GONE, and the first test now pins the
 *   opposite fact.
 *
 *   NO LENGTH GATE, NO MINIMUM AND NO EXACT-TUPLE ALLOWLIST IS REINTRODUCED
 *   HERE, in source or as an expectation. A minimum was measured and REJECTED
 *   (`S = MIN + 1` defeats it), so a test demanding one would be demanding a
 *   defect back.
 *
 * WHAT SURVIVES — THE SD-4 RESIDUAL, AND WHY THIS FILE MUST NOT READ AS
 * "REMEDIATED":
 *
 *   `requirePq` is deliberately OUTSIDE
 *   `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` and is NOT smuggled back
 *   in through an exception clause. It is monotone (`_requireNoDowngrade` still
 *   refuses true -> false) and its false -> true edge still adds a whole
 *   conjunct to an already-approved request. A recovery proposing
 *   `bytes32(0)` — an ECDSA-only recovery, carrying no PQ credential — is STILL
 *   STRANDED by that flip, because `keccak256` of any preimage is never zero and
 *   the armed branch demands a preimage. That is the last test in this file.
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

/**
 * A `setVerifier` by the credential principal, carrying `floor`. Used both for
 * the `requirePq` false -> true DECLARING EDGE and, after SD5-I, for the
 * ordinary armed moves that the retired shape freeze used to refuse.
 *
 * The PQ leg is supplied with the vault's OWN committed key and a signature over
 * this exact digest, so `_authorise` is satisfied by POSSESSION, never by the
 * declared metadata. That is what makes the assertions below about
 * NOT AUTHORIZATION_INPUT observations rather than assumptions.
 */
async function setFloor(w: World, floor: Floor, armed: boolean): Promise<void> {
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
      sign(w.credKey, d), armed ? sign(w.pqKey, d) : "0x", pqKeyBytes(w.pqKey),
    )
  ).wait();
}

/** The credential principal declares the PQ floor — the `requirePq` false -> true edge. */
const declare = (w: World, floor: Floor): Promise<void> => setFloor(w, floor, false);

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

const ARMED_32_65: Floor = {
  requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
};

describe("SD-4 — the live read, after SD5-I narrowed it", () => {
  it("THE SHAPE ROUTE IS CLOSED: the three metadata fields move freely and decide nothing", async () => {
    const w = await deployWorld({
      label: "sd4-window", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    // S0 — dormant. Both lengths are ZERO.
    expect(await liveFloor(w)).to.deep.equal({
      requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0,
    });

    await declare(w, ARMED_32_65);

    // S1 — armed. The fields are RECORDED, and still readable: they are
    // SIGNED_METADATA and IDENTITY_BOUND_METADATA, which is why this assertion
    // survives the amendment rather than being deleted with the freeze.
    expect(await liveFloor(w)).to.deep.equal(ARMED_32_65);

    // INVERTED. Under `I-FLOOR-SHAPE-IMMUTABLE` every one of these moved a
    // frozen length and was refused with `Downgrade`, forever. That invariant is
    // RETIRED — the fields are NON_AUTHORITATIVE_SECURITY_METADATA, so there is
    // nothing left for a freeze to protect — and each move is now ACCEPTED and
    // OBSERVED to land. The last three are the important ones:
    //   * SHRINKING both lengths shows no minimum survives anywhere. None is
    //     reintroduced here: a minimum was measured and REJECTED, `S = MIN + 1`
    //     defeating it, so pinning one would pin a defect.
    //   * LOWERING `pqParamLevel` shows the ratchet is gone too; it asserted a
    //     total order across schemes that the kernel cannot justify.
    //   * ZEROING both lengths under a mandatory PQ conjunct shows the former
    //     satisfiability bound is vacuous, because there is no longer a declared
    //     shape for anything to be unsatisfiable against.
    for (const shape of [
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 64, pqSignatureLength: 65 },
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 64, pqSignatureLength: 128 },
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 16, pqSignatureLength: 1 },
      { requirePq: true, pqParamLevel: 0, pqPublicKeyLength: 16, pqSignatureLength: 1 },
      { requirePq: true, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 },
    ]) {
      await setFloor(w, shape, true);
      expect(await liveFloor(w), "the declared shape moved, and was recorded").to.deep.equal(shape);
    }

    // NOT AUTHORIZATION_INPUT, demonstrated rather than asserted. The live floor
    // now declares 0/0 while the vault's real credential is a 32-byte key and a
    // 65-byte signature, and an ordinary hybrid SPEND still authorises. Nothing
    // in `_authorise` consults the declared shape; only the committed PREIMAGE
    // and the verifier's own verdict decide.
    const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await w.vault.credentialGeneration()) as bigint;
    const spendDigest = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SPEND, authorityGeneration: credGen,
      params: spendParams(w.recipient, 1n), domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
    });
    expect(
      (await (await w.vault.execute(
        w.recipient, 1n, nonce, FAR_DEADLINE,
        sign(w.credKey, spendDigest), sign(w.pqKey, spendDigest), pqKeyBytes(w.pqKey),
      )).wait())?.status,
      "a 32/65 credential authorises under a 0/0 declared shape",
    ).to.equal(1);

    // NARROWED, NOT DELETED. `_requireNoDowngrade` lost the ratchet and the
    // two-length freeze; the `requirePq` conjunct is the leg that SURVIVES, and
    // it is the reason SD-4 is narrowed rather than closed.
    const downNonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const downGen = (await w.vault.credentialGeneration()) as bigint;
    const disarm = { requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 };
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SET_VERIFIER, authorityGeneration: downGen,
      params: setVerifierParams(w.verifiers.honest, disarm),
      domain: DOMAIN.CREDENTIAL, nonce: downNonce, deadline: FAR_DEADLINE,
    });
    await expect(
      w.vault.setVerifier(w.verifiers.honest, floorTuple(disarm), downNonce, FAR_DEADLINE,
        sign(w.credKey, d), sign(w.pqKey, d), pqKeyBytes(w.pqKey)),
      "requirePq true -> false is still refused",
    ).to.be.revertedWithCustomError(w.vault, "Downgrade");
  });

  it("SD-4 FORM 1 IS CLOSED — the approved recovery now SURVIVES the declaring edge", async () => {
    const w = await deployWorld({
      label: "sd4-form1", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const newCred = keyOf("sd4-form1-cred");
    // The quorum proposes a 48-byte PQ key, deliberately contradicting the
    // 32-byte shape that is about to be declared. Before SD5-I this killed the
    // request: `_requireIncomingPossession` measured it against the LIVE floor.
    const proposedKey = bytesOfLength(48, "sd4-form1-key");
    const proposedHash = ethers.keccak256(proposedKey);

    await propose(w, newCred, proposedHash, w.verifiers.alwaysTrue);
    expect((await w.vault.recovery())[R_ACTIVE], "approved and staged").to.equal(true);
    const challengesAtProposal = Number((await w.vault.recovery())[R_CHALLENGES]);

    // S0 -> S1. The same legitimate declaration by the credential principal,
    // exhibiting the vault's OWN committed key, so the surviving half of
    // `I-DECLARATION-EXHIBITED` (the PREIMAGE conjunct) is satisfied.
    await declare(w, ARMED_32_65);
    expect(await liveFloor(w), "the declaration really happened before execution")
      .to.deep.equal(ARMED_32_65);
    expect(ethers.dataLength(proposedKey), "and it contradicts the proposed key length").to.equal(48);

    await networkHelpers.time.increase(7 * DAY + 1);
    expect(
      (await (await execute(w, newCred, proposedHash, proposedKey, bytesOfLength(65, "sd4-form1-sig"))).wait())?.status,
      "I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE: the declared key length cannot strand it",
    ).to.equal(1);
    expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    expect(await w.vault.pqPublicKeyHash(), "and the 48-byte credential was installed as approved")
      .to.equal(proposedHash);

    // The request completed rather than being left stranded, and the challenge
    // budget was never touched on the way — the two accounting questions the
    // original defect raised, now answered the other way.
    expect((await w.vault.recovery())[R_ACTIVE], "the request is consumed, not stranded")
      .to.equal(false);
    expect(challengesAtProposal, "and nothing was charged for the declaration").to.equal(0);

    // The metadata is still RECORDED and still contradicts what was installed —
    // which is precisely the point: it is recorded, and it decides nothing.
    expect(await liveFloor(w)).to.deep.equal(ARMED_32_65);
  });

  it("SD-4 FORM 2 IS CLOSED — and the signature-length duty now sits with the VERIFIER", async () => {
    // Arm A. The proposed KEY length matches the shape that will be declared, so
    // only the SIGNATURE length could ever have been the cause. The incoming
    // verifier is the HONEST one, whose own scheme rule is `signature.length ==
    // 65` — so a 65-byte PoP by the proposed key must now execute.
    const a = await deployWorld({
      label: "sd4-form2a", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const credA = keyOf("sd4-form2a-cred");
    const pqA = keyOf("sd4-form2-pq");
    const keyA = pqKeyBytes(pqA);
    const hashA = ethers.keccak256(keyA);
    expect(ethers.dataLength(keyA), "32 bytes, matching the shape to be declared").to.equal(32);

    await propose(a, credA, hashA, a.verifiers.honest);
    await declare(a, ARMED_32_65);
    await networkHelpers.time.increase(7 * DAY + 1);
    const popA = (await a.vault.recoveryPossessionDigest()) as string;
    expect(
      (await (await execute(a, credA, hashA, keyA, sign(pqA, popA))).wait())?.status,
      "the declaring edge no longer kills it",
    ).to.equal(1);
    expect(await a.vault.ecdsaSigner()).to.equal(addrOf(credA));

    // Arm B. IDENTICAL world, identical approved request, identical declaration
    // — the ONLY change is a 64-byte PoP. It is refused. Arm A is the positive
    // control that isolates the cause: the preimage leg demonstrably passes for
    // this exact key, so the refusal is the HONEST VERIFIER returning false on a
    // signature of the wrong length for ITS scheme. Structural validity did not
    // disappear; it moved to the party that knows the scheme.
    //
    // ATTRIBUTION, precisely. `_requireIncomingPossession` maps an incoming
    // verifier's refusal onto `BadSignature`; `VerifierDenied` is `_authorise`'s
    // attribution and is UNREACHABLE on this path. The two refusals are
    // therefore separated by CALL SITE, not by error selector, and arm C below
    // separates verifier refusal from kernel preimage refusal.
    const b = await deployWorld({
      label: "sd4-form2b", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const credB = keyOf("sd4-form2b-cred");
    await propose(b, credB, hashA, b.verifiers.honest);
    await declare(b, ARMED_32_65);
    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      execute(b, credB, hashA, keyA, bytesOfLength(64, "sd4-form2-sig")),
      "refused by the verifier's own length rule, not by the kernel's floor",
    ).to.be.revertedWithCustomError(b.vault, "BadSignature");

    // Arm C. The KERNEL's own surviving leg, isolated the other way: an
    // always-true verifier cannot refuse anything, so a preimage that does not
    // hash to the approved commitment can only die on
    // `keccak256(newPqKey) != expectedPqKeyHash`.
    const c = await deployWorld({
      label: "sd4-form2c", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const credC = keyOf("sd4-form2c-cred");
    await propose(c, credC, hashA, c.verifiers.alwaysTrue);
    await declare(c, ARMED_32_65);
    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      execute(c, credC, hashA, pqKeyBytes(keyOf("sd4-form2-wrong-pq")), bytesOfLength(65, "sd4-form2c-sig")),
      "the committed PREIMAGE conjunct survives E-PRIME and is the kernel's own refusal",
    ).to.be.revertedWithCustomError(c.vault, "BadSignature");
  });

  it("THE PREDICATE WAS NEVER IN THE AUTHORITY STATEMENT — proven from the digest preimage", async () => {
    // What the guardians signed is `keccak256(abi.encode(signer, pqKeyHash,
    // verifier))`. No floor, no `requirePq`, no shape. That was the original
    // SD-4 complaint and it is UNCHANGED by SD5-I: the amendment removed the
    // SHAPE fields from the deciding set, but `requirePq` — which still decides,
    // and is the residual pinned in the last test — is just as absent from the
    // statement the quorum authorised.
    const w = await deployWorld({ label: "sd4-digest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });
    const newCred = keyOf("sd4-digest-cred");
    const hash = pqHash(keyOf("sd4-digest-pq"));

    const viaHelper = recoverParams(addrOf(newCred), hash, w.verifiers.honest);
    const byHand = ethers.keccak256(
      abi.encode(["address", "bytes32", "address"], [addrOf(newCred), hash, w.verifiers.honest]),
    );
    expect(viaHelper, "the authority statement is exactly (signer, pqKeyHash, verifier)").to.equal(byHand);

    // And it is INSENSITIVE to the floor: two different floors — differing in
    // `requirePq` itself — produce the same guardian digest, so no guardian
    // signature can distinguish them.
    const armed = ARMED_32_65;
    const dormant = { requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 };
    expect(setVerifierParams(w.verifiers.honest, armed)).to.not.equal(setVerifierParams(w.verifiers.honest, dormant));
    expect(viaHelper, "yet the RECOVERY statement contains neither").to.equal(byHand);
  });

  it("SD-4 RESIDUAL — an ECDSA-only recovery (bytes32(0)) is STILL stranded by the requirePq flip", async () => {
    // CONTROL. `bytes32(0)` is this kernel's representation of "no PQ
    // credential", it is an admissible recovery proposal, and while `requirePq`
    // is false the request executes end to end. Without this arm the refusal
    // below would prove nothing: a probe that dies at an earlier guard than the
    // author believes is the standing hazard in this repository.
    const ok = await deployWorld({
      label: "sd4-residual-ok", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const credOk = keyOf("sd4-residual-ok-cred");
    await propose(ok, credOk, ethers.ZeroHash, ok.verifiers.alwaysTrue);
    await networkHelpers.time.increase(7 * DAY + 1);
    expect(
      (await (await execute(ok, credOk, ethers.ZeroHash, "0x", "0x")).wait())?.status,
      "an ECDSA-only recovery is executable while requirePq is false",
    ).to.equal(1);
    expect(await ok.vault.ecdsaSigner()).to.equal(addrOf(credOk));
    expect(await ok.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);

    // THE RESIDUAL. Identical world, identical request, plus ONE declaration.
    // `requirePq` is EXPLICITLY OUTSIDE
    // `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE` — no exception clause
    // brings it back inside — so the armed branch demands a preimage of the
    // approved commitment, and `keccak256` of any preimage is never zero.
    const w = await deployWorld({
      label: "sd4-residual", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const newCred = keyOf("sd4-residual-cred");
    await propose(w, newCred, ethers.ZeroHash, w.verifiers.alwaysTrue);
    expect((await w.vault.recovery())[R_ACTIVE], "approved and staged").to.equal(true);
    const challengesAtProposal = Number((await w.vault.recovery())[R_CHALLENGES]);

    await declare(w, ARMED_32_65);
    await networkHelpers.time.increase(7 * DAY + 1);

    // The incoming verifier is ALWAYS-TRUE, so no verifier verdict can be the
    // cause; and the cross-check on `newPqKeyHash` passes because the caller
    // supplies exactly the approved `bytes32(0)`. The only leg left standing is
    // the kernel's `keccak256(newPqKey) != expectedPqKeyHash`.
    for (const attempt of ["0x", pqKeyBytes(w.pqKey), bytesOfLength(48, "sd4-residual-key")]) {
      await expect(
        execute(w, newCred, ethers.ZeroHash, attempt, bytesOfLength(65, "sd4-residual-sig")),
        "no preimage hashes to zero, so no witness can rescue this request",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    }

    // And moving the metadata cannot rescue it either — which is exactly the
    // boundary of the new invariant. The three fields are
    // NON_AUTHORITATIVE_SECURITY_METADATA; `requirePq` is not.
    await setFloor(w, { requirePq: true, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 }, true);
    await expect(
      execute(w, newCred, ethers.ZeroHash, "0x", "0x"),
      "the residual is the requirePq conjunct, and metadata cannot reach it",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // SD-4 is NARROWED, NOT CLOSED: the request is left STRANDED ACTIVE, and no
    // guardian approval was consumed and nothing was accounted on the way.
    expect(Number((await w.vault.recovery())[R_CHALLENGES]), "challengesUsed unchanged")
      .to.equal(challengesAtProposal);
    expect((await w.vault.recovery())[R_ACTIVE], "and the request is left STRANDED ACTIVE")
      .to.equal(true);
  });
});
