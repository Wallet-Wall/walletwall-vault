/**
 * EXPERIMENTAL PROTOTYPE — G-PRIME UNDER THE FULL BATTERY.
 *
 * G-PRIME is the only candidate still standing after round 2, so it gets the
 * hostile treatment the others got, plus the one attack that killed design E:
 * does letting the quorum amend the VERIFIER move AUTHORITY.md section 3's
 * "Silent crypto downgrade" row from `unreachable` to `k`?
 *
 * The answer is no, and the reason is not an argument about intent. It is that
 * `initiateRecovery` ALREADY takes `proposedVerifier` as a quorum-authorised
 * parameter and `executeRecovery` ALREADY assigns `pqVerifier = r.proposedVerifier`.
 * k guardians can therefore install any verifier they like TODAY, on the
 * unmodified kernel, with no candidate applied — which is executed below before
 * anything is claimed about G-PRIME. What G-PRIME changes is the PRICE of that
 * choice (one more quorum act instead of a fresh seven-day delay), never the
 * reachability of the state.
 *
 * That is the same shape of argument design E FAILED: design E moved
 * `securityFloor.pqPublicKeyLength` and `pqSignatureLength`, which
 * `I-FLOOR-SHAPE-IMMUTABLE` freezes against EVERY principal and which no
 * guardian path can otherwise write. G-PRIME writes neither, and that is
 * asserted here rather than assumed.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { VERIFIER_32_64_SOURCE, buildCandidateGPrime, compileAuxContract } from "./sd4-candidate-kernels.js";
import {
  R,
  abi,
  at,
  bytesOfLength,
  cancel,
  declare,
  guardianDigest,
  liveFloor,
  pqPub,
  pqPubHash,
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
  pqKeyBytes,
  sign,
  type Floor,
  type World,
} from "../stateful/world.js";

const SHAPE_32_64: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
const RATIFY_TAG = ethers.id("RATIFY_RECOVERY_COMMITMENT");
const sig64 = (k: ethers.SigningKey, digest: string): string => ethers.dataSlice(sign(k, digest), 0, 64);

const sd4World = (label: string, impl?: { abi: unknown[]; bytecode: string }) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

type Kernel = { abi: unknown[]; bytecode: string };
let GP: Kernel;
let V64: Kernel;

before(function () {
  this.timeout(600_000);
  GP = buildCandidateGPrime();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

function ratifyParams(hash: string, verifier: string, signer: string, executableAt: bigint): string {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "address", "uint64"],
      [RATIFY_TAG, hash, verifier, signer, executableAt],
    ),
  );
}

async function ratify(
  w: World,
  v: ethers.Contract,
  hash: string,
  verifier: string,
): Promise<ethers.ContractTransactionResponse> {
  const r = await v.recovery();
  const { digest, nonce } = await guardianDigest(
    w,
    v,
    ratifyParams(hash, verifier, r[R.SIGNER] as string, r[R.EXECUTABLE_AT] as bigint),
  );
  return v.ratifyRecoveryCommitment(hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE);
}

describe("SD-4 candidate G-PRIME — the surviving architecture, attacked", () => {
  it("THE VERIFIER AUTHORITY G-PRIME USES ALREADY EXISTS — k guardians install any verifier TODAY", async function () {
    this.timeout(180_000);
    // UNMODIFIED KERNEL. Two guardians alone, no credential participation, no
    // candidate applied: propose a recovery naming the ALWAYS-TRUE verifier and
    // execute it. `executeRecovery` assigns `pqVerifier = r.proposedVerifier`.
    // The quorum's authority over the vault's verifier is therefore not
    // something G-PRIME creates; it is the kernel's existing design, and
    // AUTHORITY.md says so: "The escape from a dead verifier is the GUARDIAN
    // quorum, not one factor."
    const w = await deployWorld({ label: "gp-verifier-today" });
    const nominee = keyOf("gp-verifier-today-nominee");
    const key32 = bytesOfLength(32, "gp-verifier-today-key");

    expect(await w.vault.pqVerifier(), "born under the honest verifier").to.equal(w.verifiers.honest);
    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key32), w.verifiers.alwaysTrue);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: ethers.keccak256(key32),
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: bytesOfLength(65, "gp-verifier-today-sig"),
      })
    ).wait();
    expect(
      await w.vault.pqVerifier(),
      "k guardians alone replaced the verifier on the UNMODIFIED kernel",
    ).to.equal(w.verifiers.alwaysTrue);
    // The floor is untouched throughout — which is the point: the verifier and
    // the floor are different authority objects, and only the floor is frozen.
    const f = await liveFloor(w.vault);
    expect(f.pqPublicKeyLength).to.equal(32);
    expect(f.pqSignatureLength).to.equal(65);
  });

  it("G-PRIME NEVER WRITES securityFloor — the field design E moved is untouched", async function () {
    this.timeout(180_000);
    const w = await sd4World("gp-floor", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const nominee = keyOf("gp-floor-nominee");
    const nomineePq = keyOf("gp-floor-pq");

    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "gp-floor-key")), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    const armed = await liveFloor(v);
    await (await ratify(w, v, pqPubHash(nomineePq), v64)).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: pqPubHash(nomineePq),
        newPqKey: pqPub(nomineePq),
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(nomineePq, pop),
      })
    ).wait();
    expect(await liveFloor(v), "byte-identical across ratification AND execution").to.deep.equal(armed);
    expect(armed.pqSignatureLength, "the credential's declared shape stands").to.equal(64);
  });

  it("G-PRIME cannot move the SIGNER, and the signer is not a parameter", async function () {
    this.timeout(120_000);
    const w = await sd4World("gp-signer", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const original = addrOf(keyOf("gp-signer-nominee"));

    await proposeStd(w, v, original, ethers.keccak256(bytesOfLength(48, "gp-signer-key")), w.verifiers.honest);
    await (await ratify(w, v, pqPubHash(keyOf("gp-signer-pq")), v64)).wait();
    expect((await v.recovery())[R.SIGNER], "unchanged, structurally").to.equal(original);

    const frag = new ethers.Interface(GP.abi as ethers.InterfaceAbi).getFunction("ratifyRecoveryCommitment");
    expect(
      frag?.inputs.map((i) => i.name),
      "no calldata shape can carry a signer",
    ).to.deep.equal(["newPqKeyHash", "newVerifier", "proof", "nonce", "deadline"]);
  });

  it("G-PRIME's attestation does not replay into a DIFFERENT episode", async function () {
    this.timeout(120_000);
    const w = await sd4World("gp-replay", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const nominee = keyOf("gp-replay-nominee");
    const evil = pqPubHash(keyOf("gp-replay-evil"));

    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "gp-replay-key")), w.verifiers.honest);
    const at1 = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    const stale = await guardianDigest(w, v, ratifyParams(evil, v64, addrOf(nominee), at1));
    const staleProof = quorum(w, stale.digest);

    await (await cancel(w, v, w.credKey)).wait();
    await networkHelpers.time.increase(2 * DAY);
    await proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "gp-replay-key")), w.verifiers.honest);
    expect((await v.recovery())[R.EXECUTABLE_AT]).to.not.equal(at1);

    const n = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
    await expect(
      v.ratifyRecoveryCommitment(evil, v64, staleProof, n, FAR_DEADLINE),
      "consent for episode 1 is worthless in episode 2",
    ).to.be.revertedWithCustomError(v, "QuorumNotMet");
  });

  it("G-PRIME refuses a stale guardian generation, an expired episode, and a cancelled one", async function () {
    this.timeout(240_000);
    const v64Src = VERIFIER_32_64_SOURCE;
    void v64Src;

    // (a) stale generation
    {
      const w = await sd4World("gp-gen", GP);
      const v = at(w, GP);
      const v64 = await deployV64(w);
      await proposeStd(
        w,
        v,
        addrOf(keyOf("gp-gen-nominee")),
        ethers.keccak256(bytesOfLength(48, "gp-gen-key")),
        w.verifiers.honest,
      );
      const commitment = ethers.keccak256(
        abi.encode(["uint64", "address[]", "bool[]"], [2n, w.guardians, w.guardianIsContract]),
      );
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.SET_GUARDIANS,
        authorityGeneration: (await v.guardianGeneration()) as bigint,
        params: commitment,
        domain: DOMAIN.GUARDIAN,
        nonce: gNonce,
        deadline: FAR_DEADLINE,
      });
      await (await v.setGuardians(2n, w.guardians, w.guardianIsContract, quorum(w, d), gNonce, FAR_DEADLINE)).wait();
      await expect(ratify(w, v, pqPubHash(keyOf("gp-gen-pq")), v64)).to.be.revertedWithCustomError(v, "BadRoster");
    }

    // (b) expired episode
    {
      const w = await sd4World("gp-expiry", GP);
      const v = at(w, GP);
      const v64 = await deployV64(w);
      await proposeStd(
        w,
        v,
        addrOf(keyOf("gp-expiry-nominee")),
        ethers.keccak256(bytesOfLength(48, "gp-expiry-key")),
        w.verifiers.honest,
      );
      await networkHelpers.time.increase(7 * DAY + 14 * DAY + 10);
      await expect(ratify(w, v, pqPubHash(keyOf("gp-expiry-pq")), v64)).to.be.revertedWithCustomError(v, "Expired");
    }

    // (c) cancelled episode
    {
      const w = await sd4World("gp-cancelled", GP);
      const v = at(w, GP);
      const v64 = await deployV64(w);
      await proposeStd(
        w,
        v,
        addrOf(keyOf("gp-cancelled-nominee")),
        ethers.keccak256(bytesOfLength(48, "gp-cancelled-key")),
        w.verifiers.honest,
      );
      await (await cancel(w, v, w.credKey)).wait();
      await expect(ratify(w, v, pqPubHash(keyOf("gp-cancelled-pq")), v64)).to.be.revertedWithCustomError(
        v,
        "NoRecovery",
      );
    }
  });

  it("G-PRIME refuses a zero or CODELESS verifier, matching every other verifier ingress", async function () {
    this.timeout(120_000);
    const w = await sd4World("gp-codeless", GP);
    const v = at(w, GP);
    await proposeStd(
      w,
      v,
      addrOf(keyOf("gp-codeless-nominee")),
      ethers.keccak256(bytesOfLength(48, "gp-codeless-key")),
      w.verifiers.honest,
    );
    const hash = pqPubHash(keyOf("gp-codeless-pq"));
    await expect(ratify(w, v, hash, ethers.ZeroAddress)).to.be.revertedWithCustomError(v, "ZeroAddress");
    await expect(
      ratify(w, v, hash, "0x00000000000000000000000000000000DeaDBeef"),
      "a non-zero address with no code would STATICCALL into nothing",
    ).to.be.revertedWithCustomError(v, "ZeroAddress");
  });

  it("G-PRIME leaves the credential's bounded veto and both timers exactly as it found them", async function () {
    this.timeout(180_000);
    const w = await sd4World("gp-veto", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const nominee = keyOf("gp-veto-nominee");
    const propose = () =>
      proposeStd(w, v, addrOf(nominee), ethers.keccak256(bytesOfLength(48, "gp-veto-key")), w.verifiers.honest);

    await propose();
    const t0 = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    const x0 = (await v.recovery())[R.EXPIRES_AT] as bigint;
    for (let i = 0; i < 3; i++) {
      await networkHelpers.time.increase(6 * 60 * 60);
      await (await ratify(w, v, pqPubHash(keyOf(`gp-veto-pq-${i}`)), v64)).wait();
      const r = await v.recovery();
      expect(r[R.EXECUTABLE_AT], `round ${i}: executableAt`).to.equal(t0);
      expect(r[R.EXPIRES_AT], `round ${i}: expiresAt`).to.equal(x0);
      expect(r[R.CHALLENGES], `round ${i}: challengesUsed`).to.equal(0n);
    }

    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(1n);
    await propose();
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);
    await propose();
    await expect(cancel(w, v, w.credKey), "still capped at two").to.be.revertedWithCustomError(
      v,
      "ChallengeExhausted",
    );
  });

  it("G-PRIME AND SD-5 — the vacuous shape is survivable only by a QUORUM-CHOSEN vacuous verifier, today and under G-PRIME alike", async function () {
    this.timeout(240_000);
    // SD-5 lets a cut-1 credential pin a shape no real scheme fits. G-PRIME does
    // not close that — nothing in this lane does — and the honest statement is
    // that the quorum's only escape is a verifier permissive enough to accept
    // the vacuous shape, which collapses the PQ conjunct. That is TRUE OF THE
    // UNMODIFIED KERNEL TOO, because `proposedVerifier` is already the quorum's
    // choice at initiation. G-PRIME changes the price, not the menu.
    const vacuous: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 1 };
    const nominee = keyOf("gp-sd5-nominee");
    const key32 = bytesOfLength(32, "gp-sd5-key");

    // UNMODIFIED: the quorum re-proposes with a permissive verifier and wins.
    {
      const w = await sd4World("gp-sd5-today");
      await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key32), w.verifiers.honest);
      await (await declare(w, w.vault, w.credKey, w.verifiers.honest, vacuous, pqKeyBytes(w.pqKey))).wait();
      await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key32), w.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      expect(
        (
          await (
            await w.vault.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: ethers.keccak256(key32),
              newPqKey: key32,
              newEcdsaPop: sign(nominee, pop),
              newPqPop: bytesOfLength(1, "gp-sd5-sig"),
            })
          ).wait()
        )?.status,
        "a fresh delay buys the quorum a permissive verifier — TODAY",
      ).to.equal(1);
    }

    // G-PRIME: the same end state, at the original clock.
    {
      const w = await sd4World("gp-sd5-gp", GP);
      const v = at(w, GP);
      await proposeStd(w, v, addrOf(nominee), ethers.keccak256(key32), w.verifiers.honest);
      const t0 = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
      await networkHelpers.time.increase(5 * DAY);
      await (await declare(w, v, w.credKey, w.verifiers.honest, vacuous, pqKeyBytes(w.pqKey))).wait();
      await (await ratify(w, v, ethers.keccak256(key32), w.verifiers.alwaysTrue)).wait();
      expect((await v.recovery())[R.EXECUTABLE_AT]).to.equal(t0);
      await networkHelpers.time.increase(2 * DAY + 1);
      const pop = (await v.recoveryPossessionDigest()) as string;
      expect(
        (
          await (
            await v.executeRecovery({
              newSigner: addrOf(nominee),
              newPqKeyHash: ethers.keccak256(key32),
              newPqKey: key32,
              newEcdsaPop: sign(nominee, pop),
              newPqPop: bytesOfLength(1, "gp-sd5-sig2"),
            })
          ).wait()
        )?.status,
        "same end state, same menu, at the ORIGINAL clock",
      ).to.equal(1);
    }
  });

  it("G-PRIME's only new guardian power is a DENIAL the quorum already holds, and it self-heals", async function () {
    this.timeout(180_000);
    const w = await sd4World("gp-denial", GP);
    const v = at(w, GP);
    const v64 = await deployV64(w);
    const nominee = keyOf("gp-denial-nominee");
    const nomineePq = keyOf("gp-denial-pq");

    await proposeStd(w, v, addrOf(nominee), pqPubHash(nomineePq), w.verifiers.honest);
    await (await declare(w, v, w.credKey, w.verifiers.honest, SHAPE_32_64, pqKeyBytes(w.pqKey))).wait();
    // A hostile quorum aims the episode at material nobody holds.
    await (await ratify(w, v, ethers.id("held-by-nobody"), v64)).wait();
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
    ).to.be.revertedWithCustomError(v, "BadSignature");

    // The same quorum heals it without touching the clock. Under the unmodified
    // kernel the equivalent aim-change costs a fresh seven days, so the denial
    // surface does not grow — the REPAIR surface does.
    await (await ratify(w, v, pqPubHash(nomineePq), v64)).wait();
    const pop2 = (await v.recoveryPossessionDigest()) as string;
    expect(
      (
        await (
          await v.executeRecovery({
            newSigner: addrOf(nominee),
            newPqKeyHash: pqPubHash(nomineePq),
            newPqKey: pqPub(nomineePq),
            newEcdsaPop: sign(nominee, pop2),
            newPqPop: sig64(nomineePq, pop2),
          })
        ).wait()
      )?.status,
    ).to.equal(1);
    const before = await ethers.provider.getBalance(w.recipient);
    const nonce = (await v.nonces(DOMAIN.SPEND)) as bigint;
    const sd = digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: 1n,
      actionType: ACTION.SPEND,
      authorityGeneration: (await v.credentialGeneration()) as bigint,
      params: ethers.keccak256(abi.encode(["address", "uint256"], [w.recipient, 1n])),
      domain: DOMAIN.SPEND,
      nonce,
      deadline: FAR_DEADLINE,
    });
    await (
      await v.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(nominee, sd), sig64(nomineePq, sd), pqPub(nomineePq))
    ).wait();
    expect(await ethers.provider.getBalance(w.recipient)).to.equal(before + 1n);
  });
});
