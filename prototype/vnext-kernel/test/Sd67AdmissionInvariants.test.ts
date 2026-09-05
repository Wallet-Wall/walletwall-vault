/**
 * EXPERIMENTAL PROTOTYPE — SD-6 / SD-7 REMEDIATION REGRESSION SUITE.
 *
 * ONE INVARIANT OVER THE WHOLE COMMITMENT INGRESS SURFACE.
 *
 *   I-COMMITMENT-EXHIBITED-AT-ADMISSION
 *     Every accepted transition that writes a NON-ZERO value to
 *     `pqPublicKeyHash` must exhibit a byte string K with
 *     keccak256(K) == the value being written. Where the floor governing that
 *     write already mandates PQ, K must additionally carry the declared key
 *     length, and the pre-existing proof-of-possession applies unchanged.
 *
 * There are exactly three such transitions — `initialize`, `rotateCredential`
 * and `executeRecovery` — because `pqPublicKeyHash` has exactly two write sites
 * (`initialize`, `_installCredential`) and `_installCredential` has exactly two
 * callers. The invariant is stated over the WRITE, not over any one function,
 * which is why it lands in one shared helper plus genesis rather than in three
 * places.
 *
 * WHY THE LENGTH CONJUNCT IS CONDITIONAL, AND WHY THAT IS NOT A COMPROMISE.
 * The mission hypothesis was "a preimage consistent with the commitment AND all
 * structural parameters that will later govern its use". The second half is not
 * evaluable at admission time in the dormant case: on an ECDSA-only vault no
 * shape exists yet, `pqPublicKeyLength` is 0, and comparing against it would
 * make every PQ commitment unadmittable — bricking PQ adoption for the entire
 * class. The parameters are therefore bound at the moment they EXIST, which is
 * the declaring edge, and that is precisely SD-3's `I-DECLARATION-EXHIBITED`.
 * The two invariants are complementary, not redundant; the mutants in
 * `stateful/mutants.ts` prove neither subsumes the other.
 *
 * ZERO IS NOT A COMMITMENT. `bytes32(0)` is the kernel's representation of
 * "this vault has no PQ credential", and it remains admissible wherever the
 * floor does not mandate PQ. That is what preserves the legitimate cold-ceremony
 * deployment: deploy with no commitment, run the key ceremony off-chain, then
 * rotate the real commitment in once you actually hold the key.
 *
 * WHAT THIS DOES NOT CLOSE. SD-5 is untouched and is not closeable by an
 * exhibit: exhibiting a one-byte key proves possession of a one-byte key. The
 * key-length and signature-length axes are bound by no commitment anywhere in
 * the kernel, and `_requireSaneFloor` bounds them only against 0 and
 * MAX_PQ_LENGTH. That is a MIN_PQ_LENGTH question, not an admission question.
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

  it("the requirePq-TRUE path is unchanged: length, preimage and PoP all still bind", async () => {
    const w = await deployWorld({ label: "adm-rot-hybrid" });
    const target = keyOf("adm-rot-hybrid-target");
    // POSITIVE CONTROL first.
    await (
      await rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target) })
    ).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(target));

    // Wrong length is still refused, on a fresh world.
    const w2 = await deployWorld({ label: "adm-rot-hybrid-2" });
    const t2 = keyOf("adm-rot-hybrid-2-target");
    await expect(
      rotate(w2, { newCred: t2, newPqKeyHash: pqHash(t2), newPqKey: bytesOfLength(33, "long") }),
    ).to.be.revertedWithCustomError(w2.vault, "BadSignature");
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

  it("the UNATTESTED plant is refused; the EXHIBITED one is not — SD-5 is untouched", async () => {
    const w = await deployWorld({ label: "adm-chain", ecdsaOnlyFloor: true });
    const target = keyOf("adm-chain-target");
    // The SD-5 composition needed a one-byte commitment planted here. Refused.
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: ethers.keccak256("0xaa"), newPqKey: "0x" }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    // Exhibiting it is still possible — the invariant is about ATTESTATION, not
    // about shape. SD-5 remains open and is not an admission question.
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

  it("REFUSES a PQ-mandatory genesis whose exhibit is the WRONG LENGTH for its own floor", async () => {
    const w = await deployWorld({ label: "adm-gen-mismatch" });
    const key48 = bytesOfLength(48, "adm-gen-48");
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(key48) }, ethers.id("adm-gen-mm-salt"), key48,
    );
    expect(r.ok, "48-byte key under a 32-byte declared shape is refused").to.equal(false);
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

  it("POSITIVE CONTROL: the MAXIMUM legal shape is still deployable when genuinely exhibited", async () => {
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
    expect(r.ok, "MAX_PQ_LENGTH remains reachable — the exhibit is not a new bound").to.equal(true);
  });

  it("SD-7 x SD-5: a vacuous shape is STILL admissible at genesis — this fix does not close SD-5", async () => {
    // Stated as a test so the boundary of the remediation is executable rather
    // than merely asserted in prose. Exhibiting a one-byte key proves possession
    // of a one-byte key; nothing about admission constrains the shape.
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
    expect(r.ok, "SD-5 is untouched and remains SUSTAINED").to.equal(true);
  });
});
