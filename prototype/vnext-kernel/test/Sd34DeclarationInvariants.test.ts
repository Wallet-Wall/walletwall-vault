/**
 * EXPERIMENTAL PROTOTYPE — SD-3 REMEDIATION REGRESSION SUITE.
 *
 * ONE INVARIANT OVER ONE TRANSITION, and the proof that a SECOND was needed and
 * could not be had. SD-3 and SD-4 are both the `requirePq`
 * false -> true edge in `setVerifier` — the single moment in a vault's life at
 * which the PQ authentication shape is declared. They are nonetheless
 * INDEPENDENT, and neither implies the other:
 *
 *   I-DECLARATION-EXHIBITED  (closes SD-3)
 *     For every accepted setVerifier transition s -> s' with
 *     !s.requirePq && s'.requirePq, the call must exhibit a byte string K with
 *     |K| == s'.pqPublicKeyLength and keccak256(K) == s.pqPublicKeyHash.
 *     Equivalently: the kernel's own spending conjunct is satisfiable by
 *     material actually produced on chain, not merely non-zero.
 *
 * SD-4 IS NOT CLOSED, and that is a decision rather than an omission. The
 * exhibit binds `pqPublicKeyHash`; SD-4 is about `recovery.proposedPqKeyHash` —
 * different variables, chosen by different principals — and in the SD-4
 * counterexample the declared key length MATCHES the incumbent exactly, so the
 * exhibit passes on BOTH conjuncts and the quorum's proposal still dies. No
 * exhibit-shaped fix could ever have closed it.
 *
 * The obvious second clause — refuse the declaration while a live approved
 * recovery exists — was implemented, measured and REMOVED. The declaration is
 * ONE-SHOT and no guardian path can ever write `securityFloor`, so that refusal
 * hands the quorum a renewable, uncounted veto over a capability it cannot
 * itself exercise, pinning an ECDSA-only vault at asset-control cut 1 forever.
 * Trading a bounded one-shot credential harm for an unbounded guardian one is
 * not a remediation. SD-4 therefore stays SUSTAINED, with its analysis and the
 * only sound design recorded in `stateful/defects.ts`, and — for the first time
 * — with a CAMPAIGN PROPERTY (`G-DECLARATION-SUBORDINATE-TO-RECOVERY`) that
 * observes it across 224 campaigns instead of a narrative argument.
 *
 * THE EXHIBIT IS A SATISFIABILITY WITNESS, NOT AN AUTHORITY GATE. `pqKey` is a
 * PUBLIC key and is deliberately not covered by the action digest, so a relayer
 * rewriting it can only make the call REVERT — never make it accept a
 * configuration the signer did not authorise. The edge's cut is 1 before and 1
 * after; nothing here should be read as raising it.
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
const HYBRID = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };

async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/** `setVerifier` as the credential principal, with full control of the exhibited key. */
async function arm(
  w: World,
  floor: Floor,
  opts: { verifier?: string; cred?: ethers.SigningKey; pqKey?: string; pqSig?: string } = {},
): Promise<ethers.ContractTransactionResponse> {
  const verifier = opts.verifier ?? w.verifiers.honest;
  const cred = opts.cred ?? w.credKey;
  const current = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.setVerifier(
    verifier,
    floorTuple(floor),
    nonce,
    FAR_DEADLINE,
    sign(cred, d),
    opts.pqSig ?? (current.requirePq ? sign(w.pqKey, d) : "0x"),
    // The exhibit. Defaults to the vault's own committed key, which is the
    // honest operator's case; every attack below overrides it.
    opts.pqKey ?? pqKeyBytes(w.pqKey),
  );
}

async function initiate(w: World, i: number, verifier: string, pqKeyHash: string): Promise<ethers.SigningKey> {
  const cred = w.spareCred[i]!;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER, authorityGeneration: gGen,
    params: recoverParams(addrOf(cred), pqKeyHash, verifier),
    domain: DOMAIN.GUARDIAN, nonce, deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.initiateRecovery(addrOf(cred), pqKeyHash, verifier, {
      members: w.guardians, isContract: w.guardianIsContract,
      attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
    }, nonce, FAR_DEADLINE)
  ).wait();
  return cred;
}

/** Rotates the credential, which on an ECDSA-only vault also installs any PQ commitment. */
async function rotateTo(w: World, cred: ethers.SigningKey, pqKeyHash: string, pqKey: string): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.ROTATE, authorityGeneration: gen,
    params: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(cred), pqKeyHash]),
    ),
    domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
  });
  const pop = (await w.vault.credentialPossessionDigest(addrOf(cred), pqKeyHash)) as string;
  await (
    await w.vault.rotateCredential(
      { newSigner: addrOf(cred), newPqKeyHash: pqKeyHash, newPqKey: pqKey, newEcdsaPop: sign(cred, pop), newPqPop: "0x" },
      nonce, FAR_DEADLINE, sign(w.credKey, d), "0x", "0x",
    )
  ).wait();
}

const keyOfLength = (n: number, fill: number): string => ethers.hexlify(new Uint8Array(n).fill(fill));
const RECOVERY = { CHALLENGES: 6, ACTIVE: 7 } as const;

/** Spends 1 ETH under the given material, proving the vault is genuinely usable. */
async function expectSpends(w: World, cred: ethers.SigningKey, pq: ethers.SigningKey, note: string): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SPEND, authorityGeneration: gen,
    params: spendParams(w.recipient, ethers.parseEther("1")),
    domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
  });
  const before = await ethers.provider.getBalance(w.recipient);
  await (
    await w.vault.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE,
      sign(cred, d), sign(pq, d), pqKeyBytes(pq))
  ).wait();
  expect(await ethers.provider.getBalance(w.recipient), note).to.equal(before + ethers.parseEther("1"));
}

describe("vNext kernel — SD-3 REMEDIATION: I-DECLARATION-EXHIBITED", function () {
  this.timeout(600_000);

  // =====================================================================
  // I-DECLARATION-EXHIBITED
  // =====================================================================
  describe("I-DECLARATION-EXHIBITED — a declaration must be satisfiable by the committed material", function () {
    it("SD-3 FORM 1 — arming against a ZERO commitment is refused", async function () {
      const w = await deployWorld({ label: "d-e1", verifier: "honest", ecdsaOnlyFloor: true });
      expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
      await expect(arm(w, HYBRID, { pqKey: pqKeyBytes(w.pqKey) })).to.be.revertedWithCustomError(
        w.vault, "BadSignature",
      );
      await expect(arm(w, HYBRID, { pqKey: "0x" })).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the floor did not move").to.equal(false);
    });

    it("SD-3 FORM 2 — arming with a shape the committed key cannot meet is refused (the ledger's own sketch misses this)", async function () {
      const w = await deployWorld({
        label: "d-e2", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // A perfectly good NON-ZERO commitment whose preimage is 32 bytes.
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 33 }, { pqKey: keyOfLength(33, 1) }),
        "a 33-byte key does not hash to the 32-byte key's commitment",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 33 }, { pqKey: pqKeyBytes(w.pqKey) }),
        "and the real key is not 33 bytes",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("a wrong key of the RIGHT length is refused — the exhibit binds the hash, not just the shape", async function () {
      const w = await deployWorld({
        label: "d-e3", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, HYBRID, { pqKey: keyOfLength(32, 0xee) }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    });

    it("POSITIVE CONTROL — the honest declaration succeeds and the armed vault spends", async function () {
      const w = await deployWorld({
        label: "d-e4", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (await arm(w, { ...HYBRID, pqParamLevel: 3 })).wait();
      const f = await liveFloor(w);
      expect(f.requirePq).to.equal(true);
      expect(f.pqPublicKeyLength).to.equal(32);
      await expectSpends(w, w.credKey, w.pqKey, "the armed vault is genuinely usable");
    });

    it("the ZERO-LENGTH trap stays closed: an empty exhibit cannot satisfy an empty declaration", async function () {
      // `_requireSaneFloor` runs FIRST and forbids a zero length, so `pqKey`
      // can never be empty at the exhibit. Were the order reversed, a vault
      // that had committed keccak256("") could be armed with pqKey = "".
      const w = await deployWorld({
        label: "d-e5", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, { ...HYBRID, pqPublicKeyLength: 0 }, { pqKey: "0x" }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      await expect(
        arm(w, { ...HYBRID, pqSignatureLength: 0 }, { pqKey: pqKeyBytes(w.pqKey) }),
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    });

    it("LIVENESS — a zero-commitment vault adopts PQ in TWO transactions: commit, then declare", async function () {
      // This is a deliberate consequence, not an accident: you cannot require a
      // factor you have never committed. Both principals retain the path
      // independently, so neither can strand the other.
      const w = await deployWorld({ label: "d-e6", verifier: "honest", ecdsaOnlyFloor: true });
      await expect(arm(w, HYBRID), "one transaction is no longer enough").to.be.revertedWithCustomError(
        w.vault, "BadSignature",
      );
      const nCred = w.spareCred[0]!;
      const nPq = w.sparePq[0]!;
      await rotateTo(w, nCred, pqHash(nPq), pqKeyBytes(nPq));
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: gen,
        params: setVerifierParams(w.verifiers.honest, HYBRID),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.setVerifier(
          w.verifiers.honest, floorTuple(HYBRID), nonce, FAR_DEADLINE,
          sign(nCred, d), "0x", pqKeyBytes(nPq),
        )
      ).wait();
      expect((await liveFloor(w)).requirePq, "two transactions are enough").to.equal(true);
      await expectSpends(w, nCred, nPq, "and the adopted configuration works");
    });

    it("a PQ-ENABLED genesis is untouched: true -> true transitions behave exactly as before", async function () {
      const w = await deployWorld({ label: "d-e7", verifier: "honest" });
      const f = await liveFloor(w);
      // A level ratchet with the shape held is still accepted...
      await (await arm(w, { ...f, pqParamLevel: f.pqParamLevel + 1 })).wait();
      expect((await liveFloor(w)).pqParamLevel).to.equal(f.pqParamLevel + 1);
      // ...and I-FLOOR-SHAPE-IMMUTABLE still refuses a shape move.
      await expect(
        arm(w, { ...f, pqParamLevel: f.pqParamLevel + 2, pqSignatureLength: 64 }),
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    });
  });

  // =====================================================================
  // SD-4 IS NOT CLOSED HERE — the interlock that would have closed it was built,
  // measured and REMOVED. Refusing a ONE-SHOT transition while a live approved
  // recovery exists hands the guardian quorum a renewable, uncounted veto over a
  // capability no guardian path can itself exercise, which pins an ECDSA-only
  // vault at asset-control cut 1 forever. That trade is not a remediation, and
  // the reasoning is recorded in stateful/defects.ts SD-4 so the next lane does
  // not rebuild it. SD-4 REMAINS SUSTAINED and is reproduced, still asserting the
  // defective behaviour, in test/Sd34AuthenticationSatisfiability.test.ts.
  //
  // WHAT THIS FILE DOES PROVE about the two defects being independent is kept
  // below: the exhibit passes on BOTH conjuncts in the SD-4 counterexample, so
  // no exhibit-shaped fix could ever have closed it.
  // =====================================================================

  // =====================================================================
  // CUT PRESERVATION
  // =====================================================================
  describe("no cut moved", function () {
    it("the edge's cut is unchanged at ONE — the exhibit is a public witness, not a second factor", async function () {
      const w = await deployWorld({
        label: "d-c1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // No PQ SIGNATURE is supplied — only the public key bytes — and the
      // declaration still succeeds. Anyone reading "exhibit the committed key"
      // as a cut increase would be wrong.
      await (await arm(w, HYBRID, { pqSig: "0x" })).wait();
      expect((await liveFloor(w)).requirePq).to.equal(true);
    });

    it("a stranger still cannot arm, and a wrong credential signature still fails first", async function () {
      const w = await deployWorld({
        label: "d-c2", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await expect(
        arm(w, HYBRID, { cred: w.spareCred[2]! }),
        "authority is still checked before satisfiability",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("guardian recovery remains the escape, and still installs a working credential", async function () {
      const w = await deployWorld({
        label: "d-c3", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (await arm(w, HYBRID)).wait();
      const newPq = w.sparePq[0]!;
      const newCred = await initiate(w, 0, w.verifiers.honest, pqHash(newPq));
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
          newEcdsaPop: sign(newCred, pop), newPqPop: sign(newPq, pop),
        })
      ).wait();
      await expectSpends(w, newCred, newPq, "the recovered credential spends");
    });
  });
});
