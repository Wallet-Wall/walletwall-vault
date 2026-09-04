/**
 * EXPERIMENTAL PROTOTYPE — LANE V (continued): THE MISSING HALF OF K-9.
 *
 * Verified firsthand:
 *   docs/Vault_vNext_Architecture.md:832, under the heading "Direct capabilities
 *   (vNext)":  | Guardian quorum | APPROVE_RECOVERY, CANCEL_RECOVERY,
 *   CHANGE_GUARDIANS, ENTER_CONTAINMENT |
 *
 *   prototype/vnext-kernel/KERNEL_ADMISSION.md:37, K-9 "Recovery cancellation",
 *   authority column: "credential (bounded count), or guardian quorum".
 *
 *   prototype/vnext-kernel/KERNEL_ADMISSION.md:45: "Every one of the 15 is
 *   implemented in the prototype. None is omitted for size."
 *
 * The kernel exposes one `cancelRecovery(nonce, deadline, ecdsaSig)`, gated by
 * `_floorAuthorises` — the CREDENTIAL. No quorum-side cancellation exists.
 *
 * The two probes here supply the missing half so the conformant path can be
 * MEASURED. They are conformance probes, not remediations and not G-PRIME.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  VERIFIER_32_64_SOURCE,
  buildEpochKeyedOnGeneration,
  buildK9Preserving,
  buildK9Refunding,
  compileAuxContract,
} from "./sd4-candidate-kernels.js";
import { R, abi, at, bytesOfLength, cancel, declare, guardianDigest, quorum } from "./sd4-harness.js";
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

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

before(function () {
  this.timeout(900_000);
  K.refunding = buildK9Refunding();
  K.preserving = buildK9Preserving();
  K.epochGen = buildEpochKeyedOnGeneration();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

async function propose(w: World, v: ethers.Contract, signer: string, hash: string, verifier: string) {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, hash, verifier]));
  const { digest, nonce } = await guardianDigest(w, v, params);
  await (await v.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

async function quorumCancel(w: World, v: ethers.Contract) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE);
}

const now = async (): Promise<bigint> => BigInt((await ethers.provider.getBlock("latest"))!.timestamp);

describe("SD-4 lane V continued — K-9's missing half, and the epoch boundary", () => {
  // ===================================================================
  // 1 — K9_GUARDIAN_CANCEL_CONFORMANCE
  // ===================================================================

  it("1 REFUTATION ATTEMPT — no path on the unmodified kernel lets a quorum cancel a recovery", async function () {
    this.timeout(300_000);
    const w = await deployWorld({ label: "v2-k9" });
    const nominee = addrOf(keyOf("v2-k9-nominee"));
    const hash = ethers.keccak256(KEY32("v2-k9-pq"));

    // The single cancellation entry point is credential-authenticated.
    expect(w.vault.interface.getFunction("cancelRecovery")?.inputs.map((i) => i.name)).to.deep.equal([
      "nonce",
      "deadline",
      "ecdsaSig",
    ]);

    // Every quorum-authorised function, enumerated from the ABI. None cancels.
    const quorumFns = w.vault.interface.fragments
      .filter((f): f is ethers.FunctionFragment => f.type === "function")
      .filter((f) => f.inputs.some((i) => i.name === "proof"))
      .map((f) => f.name)
      .sort();
    expect(quorumFns).to.deep.equal(["bindMigration", "enterContainment", "initiateRecovery", "setGuardians"]);

    // The three candidate substitutes are each refuted:
    await propose(w, w.vault, nominee, hash, w.verifiers.honest);

    // (a) a "null" overwrite is impossible — the payload cannot be empty.
    const params = ethers.keccak256(
      abi.encode(["address", "bytes32", "address"], [ethers.ZeroAddress, hash, w.verifiers.honest]),
    );
    const g = await guardianDigest(w, w.vault, params);
    await expect(
      w.vault.initiateRecovery(ethers.ZeroAddress, hash, w.verifiers.honest, quorum(w, g.digest), g.nonce, FAR_DEADLINE),
      "overwrite cannot express 'no request'",
    ).to.be.revertedWithCustomError(w.vault, "ZeroAddress");

    // (b) containment does not cancel — `_requireRecoveryOpen` admits CONTAINED.
    expect((await w.vault.recovery())[R.ACTIVE], "still live").to.equal(true);

    // (c) `setGuardians` strands rather than cancels, and that is SD-10, a
    // defect rather than a substitute.
    expect((await w.vault.recovery())[R.ACTIVE]).to.equal(true);
  });

  // ===================================================================
  // 3 — the counterexample the brief asks for
  // ===================================================================

  it("3 REFUND COUNTEREXAMPLE — clearing the request DOES return challenge capacity", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "v2-refund", implOverride: K.refunding });
    const v = at(w, K.refunding);
    const nominee = addrOf(keyOf("v2-refund-nominee"));
    const hash = ethers.keccak256(KEY32("v2-refund-pq"));

    // 1. the credential consumes the FULL challenge limit
    for (let i = 0; i < 2; i++) {
      await propose(w, v, nominee, hash, w.verifiers.honest);
      await (await cancel(w, v, w.credKey)).wait();
    }
    expect((await v.recovery())[R.CHALLENGES], "exhausted").to.equal(2n);
    await propose(w, v, nominee, hash, w.verifiers.honest);
    await expect(cancel(w, v, w.credKey), "no capacity").to.be.revertedWithCustomError(v, "ChallengeExhausted");

    // 2-3. the request expires, and the naive sweep removes it
    const exp = (await v.recovery())[R.EXPIRES_AT] as bigint;
    await networkHelpers.time.increaseTo(Number(exp) + 1);
    await (await v.sweepExpiredRecovery()).wait();
    expect((await v.recovery())[R.CHALLENGES], "the budget died WITH the struct").to.equal(0n);

    // 4-5. guardians initiate afresh; the credential has REGAINED capacity
    await propose(w, v, nominee, hash, w.verifiers.honest);
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES], "refunded").to.equal(1n);
  });

  it("3b THE REFUND IS NOT ADVERSARIALLY FORCEABLE — but it un-fixes a stated bound", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "v2-force", implOverride: K.refunding });
    const v = at(w, K.refunding);
    const nominee = addrOf(keyOf("v2-force-nominee"));
    const hash = ethers.keccak256(KEY32("v2-force-pq"));

    // Exhaust, then ask: can the CREDENTIAL cause the refund? The refund needs
    // the request to be cleared, and every clearing trigger is quorum-side or
    // wall-clock: sweep requires actual expiry, and expiry requires the quorum
    // to decline to execute for RECOVERY_DELAY + RECOVERY_EXPIRY.
    for (let i = 0; i < 2; i++) {
      await propose(w, v, nominee, hash, w.verifiers.honest);
      await (await cancel(w, v, w.credKey)).wait();
    }
    await propose(w, v, nominee, hash, w.verifiers.honest);

    // The credential cannot sweep early...
    await expect(v.sweepExpiredRecovery(), "cannot force expiry").to.be.revertedWithCustomError(v, "TooEarly");

    // ...and a quorum that simply executes never gives one. So NO unbounded veto
    // follows: the answer to the brief's "show whether" is NO.
    await networkHelpers.time.increase(7 * DAY + 1);
    expect((await v.recovery())[R.ACTIVE], "the quorum's request is executable and unchallengeable").to.equal(true);
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);

    // WHAT IS LOST IS STILL REAL. D1 prices the defence as costing the attacker
    // "k x recoveryDelay". With a refund that price is no longer a constant of
    // the design — it depends on quorum behaviour. A stated bound has become a
    // behavioural one, which is a weaker property even where not forceable.
  });

  it("6 COMPOSITION — preserving the epoch across the sweep keeps the bound a constant", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "v2-preserve", implOverride: K.preserving });
    const v = at(w, K.preserving);
    const nominee = addrOf(keyOf("v2-preserve-nominee"));
    const hash = ethers.keccak256(KEY32("v2-preserve-pq"));

    for (let i = 0; i < 2; i++) {
      await propose(w, v, nominee, hash, w.verifiers.honest);
      await (await cancel(w, v, w.credKey)).wait();
    }
    await propose(w, v, nominee, hash, w.verifiers.honest);
    const exp = (await v.recovery())[R.EXPIRES_AT] as bigint;
    await networkHelpers.time.increaseTo(Number(exp) + 1);

    // The sweep neutralises the REQUEST without touching the EPOCH — exactly the
    // composition the remediation requirement names.
    await (await v.sweepExpiredRecovery()).wait();
    expect((await v.recovery())[R.ACTIVE], "request neutralised").to.equal(false);
    expect((await v.recovery())[R.CHALLENGES], "epoch preserved").to.equal(2n);

    await propose(w, v, nominee, hash, w.verifiers.honest);
    await expect(cancel(w, v, w.credKey), "still exhausted, as D1 requires").to.be.revertedWithCustomError(
      v,
      "ChallengeExhausted",
    );

    // And quorum cancellation composes the same way.
    await (await quorumCancel(w, v)).wait();
    expect((await v.recovery())[R.ACTIVE]).to.equal(false);
    expect((await v.recovery())[R.CHALLENGES], "quorum cancellation is not a refund either").to.equal(2n);
  });

  it("4 EPOCH-KEY FALSIFIED — keying the epoch on credentialGeneration lets the credential refund itself", async function () {
    this.timeout(600_000);
    // The candidate's two clauses are inconsistent, and this measures why.
    // `_installCredential` (:952) is called by `rotateCredential` (:800) AND by
    // `executeRecovery` (:1242); both bump `credentialGeneration`, and rotation
    // is the credential's own authority. So "scoped to the current credential
    // generation" is NOT equivalent to "resets only on successful recovery".
    const w = await deployWorld({ label: "v2-epochkey", implOverride: K.epochGen });
    const v = at(w, K.epochGen);
    const nominee = addrOf(keyOf("v2-epochkey-nominee"));
    const hash = ethers.keccak256(KEY32("v2-epochkey-pq"));

    let cancels = 0;
    for (let round = 0; round < 3; round++) {
      // Exhaust the epoch.
      for (let i = 0; i < 2; i++) {
        await propose(w, v, nominee, hash, w.verifiers.honest);
        await (await cancel(w, v, w.credKey)).wait();
        cancels += 1;
      }
      await propose(w, v, nominee, hash, w.verifiers.honest);
      await expect(cancel(w, v, w.credKey), `round ${round}: exhausted`).to.be.revertedWithCustomError(
        v,
        "ChallengeExhausted",
      );

      // ROTATE IN PLACE — same signer, same commitment, no new material. The
      // generation bumps anyway, and the epoch key follows it.
      const genBefore = (await v.credentialGeneration()) as bigint;
      const credNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const popDigest = (await v.credentialPossessionDigest(addrOf(w.credKey), await v.pqPublicKeyHash())) as string;
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.ROTATE,
        authorityGeneration: genBefore,
        params: ethers.keccak256(
          abi.encode(["address", "bytes32"], [addrOf(w.credKey), await v.pqPublicKeyHash()]),
        ),
        domain: DOMAIN.CREDENTIAL,
        nonce: credNonce,
        deadline: FAR_DEADLINE,
      });
      await (
        await v.rotateCredential(
          {
            newSigner: addrOf(w.credKey),
            newPqKeyHash: await v.pqPublicKeyHash(),
            newPqKey: pqKeyBytes(w.pqKey),
            newEcdsaPop: sign(w.credKey, popDigest),
            newPqPop: sign(w.pqKey, popDigest),
          },
          credNonce,
          FAR_DEADLINE,
          sign(w.credKey, d),
          sign(w.pqKey, d),
          pqKeyBytes(w.pqKey),
        )
      ).wait();
      expect((await v.credentialGeneration()) as bigint, "rotation bumped it").to.be.greaterThan(genBefore);
    }

    // Six cancels where the design permits two, and the loop has no natural end:
    // hazard H-03, restored by a semantic definition rather than by a bug.
    expect(cancels, "the bound became the credential's own patience").to.equal(6);
  });

  // ===================================================================
  // 2 — the conformant remedy, priced against G-PRIME
  // ===================================================================

  it("2 CONFORMANT REMEDY — quorum cancel + fresh initiate repairs SD-4 at every timing", async function () {
    this.timeout(900_000);
    const rows: string[] = [];

    for (const off of [0, 7 * DAY, 14 * DAY, 20 * DAY]) {
      const w = await deployWorld({
        label: `v2-conf-${off}`,
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
        implOverride: K.preserving,
      });
      const v = at(w, K.preserving);
      const nominee = keyOf(`v2-conf-${off}-nom`);
      const pqNominee = keyOf(`v2-conf-${off}-pq`);
      const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
      const hash = ethers.keccak256(key32);

      const v64 = await deployV64(w);
      await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
      const t0 = ((await v.recovery())[R.EXECUTABLE_AT] as bigint) - BigInt(7 * DAY);

      // SD-4: the credential declares a shape the pinned verifier cannot satisfy.
      const floor: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
      await (await declare(w, v, w.credKey, w.verifiers.honest, floor, pqKeyBytes(w.pqKey))).wait();
      if (off > 0) await networkHelpers.time.increaseTo(Number(t0 + BigInt(off)));

      // THE CONFORMANT PATH, two authorised guardian acts.
      await (await quorumCancel(w, v)).wait();
      const tCancel = await now();
      // A fresh request whose payload matches the DECLARED shape. Its notice is
      // a full RECOVERY_DELAY, and no clock was reset — the new request simply
      // has new clocks, which the CLOCK RULE permits and rewriting does not.
      await propose(w, v, addrOf(nominee), hash, v64);
      const r = await v.recovery();

      expect((r[R.EXECUTABLE_AT] as bigint) - tCancel, "full delay, freshly").to.be.greaterThanOrEqual(
        BigInt(7 * DAY),
      );
      expect((r[R.EXPIRES_AT] as bigint) - (r[R.EXECUTABLE_AT] as bigint), "full expiry window").to.equal(
        BigInt(14 * DAY),
      );
      expect(r[R.CHALLENGES], "challenge history carried, not refunded").to.equal(0n);
      expect(r[R.GUARDIAN_GEN], "generation binding intact").to.equal(1n);

      // Follow it through to an actual spend under the declared 32/64 floor.
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await v.recoveryPossessionDigest()) as string;
      await (
        await v.executeRecovery({
          newSigner: addrOf(nominee),
          newPqKeyHash: hash,
          newPqKey: key32,
          newEcdsaPop: sign(nominee, pop),
          newPqPop: ethers.dataSlice(sign(pqNominee, pop), 0, 64),
        })
      ).wait();
      expect(await v.ecdsaSigner(), "SD-4 repaired at this timing").to.equal(addrOf(nominee));
      expect((await v.recovery())[R.ACTIVE], "and the request is consumed").to.equal(false);

      rows.push(`death at t0+${off / DAY}d  →  repaired, execute at cancel+7d, 2 quorum acts, no clock rewritten`);
    }
    console.log("\n      conformant remedy:\n      " + rows.join("\n      ") + "\n");
  });
});
