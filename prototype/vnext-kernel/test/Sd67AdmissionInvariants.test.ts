/**
 * EXPERIMENTAL PROTOTYPE — SD-6 / SD-7 REMEDIATION REGRESSION SUITE.
 *
 * ONE INVARIANT OVER THE WHOLE COMMITMENT INGRESS SURFACE.
 *
 *   I-COMMITMENT-EXHIBITED-AT-ADMISSION   (NARROWED BY SD5-I)
 *     Every accepted transition that writes a NON-ZERO value to
 *     `pqPublicKeyHash` must exhibit a byte string K with
 *     keccak256(K) == the value being written. That is the WHOLE of the
 *     admission obligation: the exhibit binds the PREIMAGE and nothing else.
 *     The pre-existing proofs of possession apply unchanged and are SEPARATE
 *     conjuncts, not part of the exhibit: the ECDSA one is recovered by the
 *     kernel, and the PQ one on the armed path is decided by the verifier.
 *
 * There are exactly three such transitions — `initialize`, `rotateCredential`
 * and `executeRecovery` — because `pqPublicKeyHash` has exactly two write sites
 * (`initialize`, `_installCredential`) and `_installCredential` has exactly two
 * callers. The invariant is stated over the WRITE, not over any one function,
 * which is why it lands in one shared helper plus genesis rather than in three
 * places.
 *
 * WHY THERE IS NO LENGTH CONJUNCT ANYWHERE, AS OF SD5-I.
 * The mission hypothesis was "a preimage consistent with the commitment AND all
 * structural parameters that will later govern its use". The second half is
 * withdrawn, because those parameters govern nothing. Under the accepted
 * E-PRIME amendment `pqPublicKeyLength`, `pqSignatureLength` and `pqParamLevel`
 * are SIGNED_METADATA + IDENTITY_BOUND_METADATA +
 * NON_AUTHORITATIVE_SECURITY_METADATA + ABI_COMPATIBILITY. They are explicitly
 * NOT AUTHORIZATION_INPUT, NOT RECOVERY_SATISFIABILITY_INPUT and NOT
 * CRYPTOGRAPHIC_STRENGTH: no authorization, incoming-possession, recovery
 * satisfiability or downgrade path reads them.
 *
 * The genesis conjunct that used to compare the exhibit's length against the
 * declared shape was SHAPE-SCOPED — it constrained the exhibit's shape, never
 * its cryptographic content — and it is removed. It had always been conditional
 * for a structural reason worth preserving: on an ECDSA-only vault no shape
 * exists yet, `pqPublicKeyLength` is 0, and comparing against it would make
 * every PQ commitment unadmittable, bricking PQ adoption for the entire class.
 * SD-5 then measured that the ARMED branch carried the same defect in a slower
 * form, so SD5-I generalises the dormant branch's design to every branch.
 * SD-3's `I-DECLARATION-EXHIBITED` narrows identically on the declaring edge:
 * its PREIMAGE conjunct survives, its key-LENGTH conjunct does not.
 *
 * A MINIMUM LENGTH IS NOT THE MISSING PIECE. A minimum was measured and
 * REJECTED — "S = MIN + 1" defeats it — so no test here may pin a minimum, a
 * length gate or an exact-tuple allowlist, in either direction.
 *
 * ZERO IS NOT A COMMITMENT. `bytes32(0)` is the kernel's representation of
 * "this vault has no PQ credential", and it remains admissible wherever the
 * floor does not mandate PQ. That is what preserves the legitimate cold-ceremony
 * deployment: deploy with no commitment, run the key ceremony off-chain, then
 * rotate the real commitment in once you actually hold the key.
 *
 * WHAT THIS DOES NOT CLOSE — AND MUST NOT BE READ AS CLOSING. Admission proves
 * ONE thing: a preimage of the committed hash was known to the caller at the
 * moment of the write. Three distinct properties are kept strictly separate,
 * and no assertion in this file may let the narrowed invariant claim the second
 * or the third:
 *   1. PREIMAGE EXISTENCE                — what an exhibit proves.
 *   2. CRYPTOGRAPHIC WELL-FORMEDNESS     — that the bytes are a valid key of
 *                                          some scheme. NOT proven here; the
 *                                          genesis edge consults no verifier at
 *                                          all, deliberately, because the
 *                                          deployer chooses the verifier in the
 *                                          same transaction.
 *   3. PRIVATE-KEY POSSESSION            — SD-8. NOT proven here, and untouched
 *                                          by SD5-I in either direction.
 *
 * `I-FLOOR-SHAPE-IMMUTABLE` is RETIRED. Its replacement is
 * `I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE`: for an APPROVED recovery,
 * changing `pqPublicKeyLength`, `pqSignatureLength` or `pqParamLevel` cannot
 * change its executability. `requirePq` is EXPLICITLY OUTSIDE that invariant and
 * remains the SD-4 declaring-edge residual — it is not an exception clause to be
 * smuggled back in.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { quorumCancelStd } from "./sd4-harness.js";
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
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;
const abi = ethers.AbiCoder.defaultAbiCoder();
const HYBRID = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

/**
 * THE IDENTITY-PRESERVATION CONSTANT, captured from the PARENT build before a
 * single byte of this remediation existed.
 *
 * The genesis exhibit is a WITNESS, not authority, so it must not enter the
 * identity commitment: it is a parameter of `initialize` and `deployVault`, and
 * deliberately NOT a member of `GenesisConfig`.
 *
 * WHAT THIS CONSTANT PROVES, EXACTLY: that the CONFIGURATION -> SALT function is
 * unchanged. It does NOT prove that any deployed address is unchanged, and an
 * earlier draft of this comment said it did. A clone's address is
 * `CREATE2(factory, salt, keccak256(initcode))` and the ERC-1167 initcode embeds
 * the IMPLEMENTATION address, so every clone address moves whenever the kernel
 * bytecode moves — which it does here, and in every other remediation in this
 * stack. `predictVault` is deliberately called nowhere in this test, because it
 * could not assert what the pin is for.
 */
const PARENT_GENESIS_SALT = "0xd3dd812d29d708ba4000d06e2e43fa7358917df3e3d26f14c874b6bee63956e2";

const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) {
    out += ethers.id(`${tag}-${i}`).slice(2);
    i += 1;
  }
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

interface RotateOpts {
  newCred: ethers.SigningKey;
  newPqKeyHash: string;
  newPqKey?: string;
  newPqPop?: string;
  cred?: ethers.SigningKey;
  popKey?: ethers.SigningKey;
  pqOfCaller?: ethers.SigningKey;
}

async function rotate(w: World, o: RotateOpts): Promise<ethers.ContractTransactionResponse> {
  const floor = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const pop = (await w.vault.credentialPossessionDigest(addrOf(o.newCred), o.newPqKeyHash)) as string;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.ROTATE,
    authorityGeneration: credGen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(o.newCred), o.newPqKeyHash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const callerPq = o.pqOfCaller ?? w.pqKey;
  return w.vault.rotateCredential(
    {
      newSigner: addrOf(o.newCred),
      newPqKeyHash: o.newPqKeyHash,
      newPqKey: o.newPqKey ?? "0x",
      newEcdsaPop: sign(o.popKey ?? o.newCred, pop),
      newPqPop: o.newPqPop ?? (floor.requirePq ? sign(o.newCred, pop) : "0x"),
    },
    nonce,
    FAR_DEADLINE,
    sign(o.cred ?? w.credKey, digest),
    floor.requirePq ? sign(callerPq, digest) : "0x",
    floor.requirePq ? pqKeyBytes(callerPq) : "0x",
  );
}

/** Deploy at an arbitrary genesis, now supplying the witness separately. */
async function deployGenesis(
  w: World,
  over: Record<string, unknown>,
  salt: string,
  pqKey: string,
): Promise<{ ok: true; vault: ethers.Contract } | { ok: false; error: string }> {
  const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
  const genesis = {
    signer: addrOf(w.credKey),
    pqKeyHash: pqHash(w.pqKey),
    verifier: w.verifiers.honest,
    threshold: w.threshold,
    guardians: w.guardians,
    guardianIsContract: w.guardianIsContract,
    floor: floorTuple(HYBRID),
    ...over,
  };
  try {
    const predicted: string = await factory.predictVault(salt, genesis);
    await (await factory.deployVault(salt, genesis, pqKey)).wait();
    return { ok: true, vault: await ethers.getContractAt("VaultKernelPrototype", predicted, w.deployer) };
  } catch (e) {
    return { ok: false, error: String((e as Error).message ?? e) };
  }
}

// =======================================================================
// SD-6 — rotation and recovery
// =======================================================================
describe("I-COMMITMENT-EXHIBITED-AT-ADMISSION — rotation (SD-6)", () => {
  it("REFUSES an arbitrary unattested non-zero commitment while requirePq is false", async () => {
    const w = await deployWorld({ label: "adm-rot-refuse", ecdsaOnlyFloor: true });
    const target = keyOf("adm-rot-refuse-target");
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: ethers.id("no preimage"), newPqKey: "0x" }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    expect(await w.vault.pqPublicKeyHash(), "storage untouched").to.equal(ethers.ZeroHash);
  });

  it("REFUSES an INCORRECT preimage, and a correct preimage of a DIFFERENT key", async () => {
    const w = await deployWorld({ label: "adm-rot-wrong", ecdsaOnlyFloor: true });
    const target = keyOf("adm-rot-wrong-target");
    const other = keyOf("adm-rot-wrong-other");
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(other) }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: bytesOfLength(7, "junk") }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });

  it("POSITIVE CONTROL: the correct preimage is accepted, and repeated rotations still work", async () => {
    const w = await deployWorld({ label: "adm-rot-ok", ecdsaOnlyFloor: true });
    const k1 = keyOf("adm-rot-ok-1");
    const k2 = keyOf("adm-rot-ok-2");
    await (await rotate(w, { newCred: k1, newPqKeyHash: pqHash(k1), newPqKey: pqKeyBytes(k1) })).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(k1));
    await (await rotate(w, { cred: k1, newCred: k2, newPqKeyHash: pqHash(k2), newPqKey: pqKeyBytes(k2) })).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(k2));
    expect((await w.vault.credentialGeneration()) as bigint).to.equal(3n);
  });

  it("LIVENESS: a purely ECDSA rotation stays possible — zero is not a commitment", async () => {
    const w = await deployWorld({ label: "adm-rot-ecdsa", ecdsaOnlyFloor: true });
    const target = keyOf("adm-rot-ecdsa-target");
    await (await rotate(w, { newCred: target, newPqKeyHash: ethers.ZeroHash, newPqKey: "0x" })).wait();
    expect(await w.vault.ecdsaSigner()).to.equal(addrOf(target));
    expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
  });

  it("LIVENESS: a dormant commitment can be CLEARED, so an ECDSA holder is never stranded by one", async () => {
    // The one behaviour change an operator can feel: with a non-zero dormant
    // commitment installed, a rotation must now either re-exhibit that key or
    // clear the commitment. Clearing is always available to the ECDSA principal
    // and takes nothing away, because no path reads a dormant commitment.
    const w = await deployWorld({ label: "adm-rot-clear", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true });
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(w.pqKey));
    const target = keyOf("adm-rot-clear-target");
    await (await rotate(w, { newCred: target, newPqKeyHash: ethers.ZeroHash, newPqKey: "0x" })).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
  });

  it("the requirePq-TRUE path NARROWS to preimage and PoP — the kernel's length leg is gone", async () => {
    // NARROWED BY SD5-I. This assertion had two legs on the armed path; the
    // key-LENGTH leg was removed and the PREIMAGE leg survives, so the title and
    // the attributions below are restated to claim only what still runs.
    const w = await deployWorld({ label: "adm-rot-hybrid" });
    const target = keyOf("adm-rot-hybrid-target");
    // POSITIVE CONTROL first.
    await (
      await rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target) })
    ).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(target));

    // A 33-byte exhibit of a 32-byte commitment is still refused — but by the
    // PREIMAGE leg, which is the only leg left that could catch it.
    // keccak256(junk33) != pqHash(t2), and that comparison runs before the
    // verifier is ever reached.
    const w2 = await deployWorld({ label: "adm-rot-hybrid-2" });
    const t2 = keyOf("adm-rot-hybrid-2-target");
    await expect(
      rotate(w2, { newCred: t2, newPqKeyHash: pqHash(t2), newPqKey: bytesOfLength(33, "long") }),
    ).to.be.revertedWithCustomError(w2.vault, "BadSignature");

    // ATTRIBUTION, by discrimination rather than by assertion. Take a 33-byte
    // key that DOES exhibit its own commitment, so the preimage leg passes and
    // only the verifier conjunct is left standing. Change NOTHING but the
    // verifier between the two arms.
    const key33 = bytesOfLength(33, "adm-rot-hybrid-33");
    const hash33 = ethers.keccak256(key33);

    // Arm A — honest verifier. Refused. `EcdsaBackedVerifier` returns false for
    // any public key that is not exactly 32 bytes, so this is that VERIFIER's
    // own well-formedness refusal. It is not evidence of a surviving kernel
    // length gate, and arm B is what settles that.
    const w3 = await deployWorld({ label: "adm-rot-hybrid-33-honest" });
    const t3 = keyOf("adm-rot-hybrid-33-honest-target");
    await expect(
      rotate(w3, { newCred: t3, newPqKeyHash: hash33, newPqKey: key33 }),
    ).to.be.revertedWithCustomError(w3.vault, "BadSignature");

    // Arm B — an accepting verifier, same kernel, same inputs. ADMITTED. The
    // kernel therefore holds no length gate on this edge: the refusal in arm A
    // was located entirely in the verifier.
    const w4 = await deployWorld({ label: "adm-rot-hybrid-33-open", verifier: "alwaysTrue" });
    const t4 = keyOf("adm-rot-hybrid-33-open-target");
    await (await rotate(w4, { newCred: t4, newPqKeyHash: hash33, newPqKey: key33 })).wait();
    expect(
      await w4.vault.pqPublicKeyHash(),
      "a 33-byte credential installs under a floor declaring 32 — shape is not authority",
    ).to.equal(hash33);
  });

  it("GUARDIAN RECOVERY is bound by the same invariant, and still succeeds when exhibited", async () => {
    const w = await deployWorld({ label: "adm-rec", ecdsaOnlyFloor: true });
    const fresh = keyOf("adm-rec-fresh");
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [addrOf(fresh), pqHash(fresh), w.verifiers.honest]),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(fresh), pqHash(fresh), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;

    // Unexhibited: refused, even though the QUORUM approved this hash.
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: "0x",
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // Exhibited: accepted. The remedy path is preserved.
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: pqKeyBytes(fresh),
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      })
    ).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(fresh));
    expect(await w.vault.ecdsaSigner()).to.equal(addrOf(fresh));
  });

  it("NO LOCKOUT: a quorum that proposed a key nobody holds simply RE-PROPOSES", async () => {
    // THE DISQUALIFYING QUESTION, answered by execution. The new clause makes
    // executeRecovery refuse a commitment the incoming holder cannot exhibit.
    // If that refusal were terminal it would be a permanent denial of the
    // remedy — the failure that sank the SD-4 interlock. It is not. W2
    // SUPERSESSION: this comment used to read "`initiateRecovery` has no
    // `!recovery.active` guard, so the quorum stages a fresh request over the
    // dead one". Since Lane W2 a live request is never overwritten; the quorum
    // instead takes its own exit (`cancelRecoveryByQuorum`, K-9 mechanism B) and
    // then stages the fresh request — two explicit acts, same remedy, and the
    // credential still cannot prevent it: `cancelRecovery` is capped at
    // CHALLENGE_LIMIT and the quorum's exit consumes nothing from it.
    const w = await deployWorld({ label: "adm-no-lockout", ecdsaOnlyFloor: true });
    const fresh = keyOf("adm-no-lockout-fresh");
    const unheld = ethers.id("a commitment the incoming holder cannot exhibit");

    const propose = async (hash: string): Promise<void> => {
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.RECOVER, authorityGeneration: gGen,
        params: ethers.keccak256(
          abi.encode(["address", "bytes32", "address"], [addrOf(fresh), hash, w.verifiers.honest]),
        ),
        domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.initiateRecovery(addrOf(fresh), hash, w.verifiers.honest, {
          members: w.guardians, isContract: w.guardianIsContract,
          attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
        }, gNonce, FAR_DEADLINE)
      ).wait();
    };

    await propose(unheld);
    await networkHelpers.time.increase(7 * DAY + 1);
    let pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: unheld, newPqKey: "0x",
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      }),
      "the unexhibitable proposal is refused",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // Clear the dead request through the quorum's own exit, then RE-PROPOSE with
    // material the quorum and the incoming holder actually have.
    await (await quorumCancelStd(w, w.vault)).wait();
    await propose(pqHash(fresh));
    await networkHelpers.time.increase(7 * DAY + 1);
    pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: pqKeyBytes(fresh),
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      })
    ).wait();
    expect(await w.vault.ecdsaSigner(), "the remedy completes — no lockout").to.equal(addrOf(fresh));
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(fresh));
  });

  it("the UNATTESTED plant is refused; the EXHIBITED one is not — admission binds attestation, not shape", async () => {
    const w = await deployWorld({ label: "adm-chain", ecdsaOnlyFloor: true });
    const target = keyOf("adm-chain-target");
    // The SD-5 composition needed a one-byte commitment planted here. Refused.
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: ethers.keccak256("0xaa"), newPqKey: "0x" }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    // Exhibiting it is still possible — the invariant is about ATTESTATION, not
    // about shape, and after SD5-I no edge anywhere reads a shape. What an
    // exhibit proves stays narrow: a preimage was known. SD-8 is untouched.
    await (await rotate(w, { newCred: target, newPqKeyHash: ethers.keccak256("0xaa"), newPqKey: "0xaa" })).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0xaa"));
  });
});

// =======================================================================
// SD-7 — genesis
// =======================================================================
describe("I-COMMITMENT-EXHIBITED-AT-ADMISSION — genesis (SD-7)", () => {
  it("THE SALT IS UNCHANGED: the witness is not part of the identity commitment", async () => {
    const w = await deployWorld({ label: "adm-salt" });
    const g = {
      signer: "0x1111111111111111111111111111111111111111",
      pqKeyHash: ethers.id("canonical-pq-commitment"),
      verifier: "0x2222222222222222222222222222222222222222",
      threshold: 2,
      guardians: [
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0x5555555555555555555555555555555555555555",
      ],
      guardianIsContract: [false, false, false],
      floor: [true, 1, 32, 65],
    };
    expect(
      await w.vault.genesisSalt(ethers.id("canonical-user-salt"), g),
      "adding the exhibit must not change the configuration -> salt map",
    ).to.equal(PARENT_GENESIS_SALT);
  });

  it("REFUSES a PQ-mandatory genesis whose commitment has no exhibited preimage", async () => {
    const w = await deployWorld({ label: "adm-gen-nopre" });
    const r = await deployGenesis(w, { pqKeyHash: ethers.id("no preimage") }, ethers.id("adm-gen-nopre-salt"), "0x");
    expect(r.ok, "SD-7 refused").to.equal(false);
  });

  it("ADMITS a genesis whose exhibit does not match its own declared shape — length is not admission authority", async () => {
    // INVERTED BY SD5-I. This case used to be REFUSED by the genesis key-LENGTH
    // conjunct, which was SHAPE-SCOPED. That conjunct is removed, so a 48-byte
    // exhibit under a floor declaring 32 is now ADMITTED: the commitment is
    // bound to its PREIMAGE and to nothing else.
    //
    // TWO ARMS, so this pins the narrowing rather than merely observing that
    // something got easier. Arm A exhibits the true preimage and is ADMITTED.
    // Arm B changes ONLY the committed hash, keeping the identical 48-byte
    // exhibit, and is still REFUSED — with the kernel's own `BadSignature`, so
    // the refusal is attributed to the surviving preimage leg and not to some
    // earlier guard. The surviving leg is therefore doing real work, and arm A's
    // acceptance is not the vacuous acceptance of a check that no longer runs.
    //
    // Arm A proves PREIMAGE EXISTENCE only. It does NOT claim the 48 bytes are a
    // well-formed key of any scheme, and it does NOT claim possession of a
    // private key — the honest verifier is never consulted on this edge.
    const w = await deployWorld({ label: "adm-gen-mismatch" });
    const key48 = bytesOfLength(48, "adm-gen-48");
    const other48 = bytesOfLength(48, "adm-gen-48-other");

    const admitted = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(key48) }, ethers.id("adm-gen-mm-salt"), key48,
    );
    expect(admitted.ok, "a 48-byte exhibit under a floor declaring 32 is ADMITTED").to.equal(true);
    if (!admitted.ok) return;
    expect(
      await admitted.vault.pqPublicKeyHash(),
      "the commitment stored is exactly the one exhibited",
    ).to.equal(ethers.keccak256(key48));
    // The three fields are RETAINED verbatim — de-authorised, not deleted — and
    // still readable at the unchanged `securityFloor()` return shape.
    const floor = await admitted.vault.securityFloor();
    expect(
      [floor[0] as boolean, Number(floor[1]), Number(floor[2]), Number(floor[3])],
      "the declared metadata is stored as declared, and simply governs nothing",
    ).to.deep.equal([
      HYBRID.requirePq,
      HYBRID.pqParamLevel,
      HYBRID.pqPublicKeyLength,
      HYBRID.pqSignatureLength,
    ]);

    // ARM B — the discriminating control. Identical exhibit, different commitment.
    const refused = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(other48) }, ethers.id("adm-gen-mm-salt-b"), key48,
    );
    expect(refused.ok, "a 48-byte exhibit of the WRONG commitment is still refused").to.equal(false);
    if (refused.ok) return;
    expect(refused.error, "and it is the KERNEL refusing, at the preimage leg").to.include("BadSignature");
  });

  it("REFUSES a PQ-mandatory genesis with a zero commitment (the pre-existing check survives)", async () => {
    const w = await deployWorld({ label: "adm-gen-zero" });
    const r = await deployGenesis(w, { pqKeyHash: ethers.ZeroHash }, ethers.id("adm-gen-zero-salt"), "0x");
    expect(r.ok).to.equal(false);
  });

  it("REFUSES a DORMANT genesis carrying an unattested latent commitment", async () => {
    const w = await deployWorld({ label: "adm-gen-latent" });
    const r = await deployGenesis(
      w,
      { pqKeyHash: ethers.id("latent"), floor: floorTuple({ requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 }) },
      ethers.id("adm-gen-latent-salt"),
      "0x",
    );
    expect(r.ok, "a latent commitment is still a commitment").to.equal(false);
  });

  it("POSITIVE CONTROL: a legitimate PQ-mandatory genesis deploys, and the vault spends", async () => {
    const w = await deployWorld({ label: "adm-gen-ok" });
    const key = keyOf("adm-gen-ok-key");
    const r = await deployGenesis(
      w, { pqKeyHash: pqHash(key) }, ethers.id("adm-gen-ok-salt"), pqKeyBytes(key),
    );
    expect(r.ok).to.equal(true);
    if (!r.ok) return;
    await w.deployer.sendTransaction({ to: await r.vault.getAddress(), value: ethers.parseEther("1") });
    const nonce = (await r.vault.nonces(DOMAIN.SPEND)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: await r.vault.getAddress(), kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SPEND, authorityGeneration: 1n,
      params: spendParams(w.recipient, 1n), domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
    });
    expect(
      (await (await r.vault.execute(w.recipient, 1n, nonce, FAR_DEADLINE,
        sign(w.credKey, d), sign(key, d), pqKeyBytes(key))).wait())?.status,
    ).to.equal(1);
  });

  it("POSITIVE CONTROL: the cold-ceremony deployment is preserved — zero commitment, then rotate in", async () => {
    const w = await deployWorld({ label: "adm-gen-cold" });
    const r = await deployGenesis(
      w,
      { pqKeyHash: ethers.ZeroHash, floor: floorTuple({ requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 }) },
      ethers.id("adm-gen-cold-salt"),
      "0x",
    );
    expect(r.ok, "deploy without holding any PQ key").to.equal(true);
    if (!r.ok) return;
    expect(await r.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
  });

  it("POSITIVE CONTROL: a 65,535-byte exhibit still deploys — MAX_PQ_LENGTH has no reader", async () => {
    const w = await deployWorld({ label: "adm-gen-max" });
    const big = bytesOfLength(65535, "adm-gen-max-key");
    const r = await deployGenesis(
      w,
      {
        pqKeyHash: ethers.keccak256(big),
        floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 65535, pqSignatureLength: 65535 }),
      },
      ethers.id("adm-gen-max-salt"),
      big,
    );
    expect(
      r.ok,
      "the exhibit is not a bound in either direction; MAX_PQ_LENGTH is retained for ABI only",
    ).to.equal(true);
  });

  it("a shape declaring 1 and 1 is admissible at genesis — the declared shape is not authority", async () => {
    // Stated as a test so the boundary of the remediation is executable rather
    // than merely asserted in prose. Exhibiting a one-byte key proves that a
    // one-byte preimage was known — not that it is a well-formed key, and not
    // that anyone holds a corresponding private key. Nothing about admission
    // constrains the shape, and after SD5-I nothing downstream reads it either:
    // the declared lengths and param level are NON_AUTHORITATIVE_SECURITY_METADATA,
    // so a "small" declaration is a metadata fact, not a weakened gate.
    const w = await deployWorld({ label: "adm-gen-vacuous" });
    const r = await deployGenesis(
      w,
      {
        pqKeyHash: ethers.keccak256("0xaa"),
        floor: floorTuple({ requirePq: true, pqParamLevel: 65535, pqPublicKeyLength: 1, pqSignatureLength: 1 }),
      },
      ethers.id("adm-gen-vacuous-salt"),
      "0xaa",
    );
    expect(r.ok, "admission constrains the preimage and nothing else").to.equal(true);
  });
});
