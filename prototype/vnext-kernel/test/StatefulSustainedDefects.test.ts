/**
 * EXPERIMENTAL PROTOTYPE — SUSTAINED COMPOSITION DEFECTS, REPRODUCED.
 *
 * Three defects found by the stateful campaign and then reproduced FIRSTHAND
 * against the compiled kernel. This PR changes ZERO bytes of Solidity, so each
 * one is recorded here as a deterministic, permanently-executed reproduction
 * rather than fixed in passing. `stateful/defects.ts` carries the full analysis,
 * the contradicted published claim, the root cause, and a minimal fix sketch.
 *
 * THESE TESTS ASSERT THE DEFECTIVE BEHAVIOUR ON PURPOSE.
 * ------------------------------------------------------
 * That is the point. Each one is written so that IF A FIX LANDS IT FAILS, which
 * is what forces the fixer to update this file, `stateful/defects.ts` and
 * AUTHORITY.md together. A defect that can be quietly fixed while a security
 * table still says it is unreachable is how a stale table is born; a defect that
 * is quietly SUPPRESSED is worse. Neither happens here.
 *
 * NONE OF THE THREE IS AN UNAUTHORIZED ASSET OR CONTROL ESCALATION. All three
 * are DENIAL / LIVENESS or state-incoherence outcomes. No declared cut for
 * asset control, credential replacement, verifier replacement, guardian
 * transition or migration is reduced by any of them. That bound is asserted
 * below, not merely asserted in prose.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
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
import { SUSTAINED_DEFECTS } from "../stateful/defects.js";

const DAY = 24 * 60 * 60;

/** Signs and submits a setVerifier with an arbitrary floor, as the credential holder. */
async function setVerifierAs(
  w: World,
  verifier: string,
  floor: Floor,
  credKey: ethers.SigningKey,
  pqKey: ethers.SigningKey | null,
): Promise<void> {
  const current = await w.vault.securityFloor();
  const requirePqNow = current[0] as boolean;
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.setVerifier(
      verifier,
      [floor.requirePq, floor.pqParamLevel, floor.pqPublicKeyLength, floor.pqSignatureLength],
      nonce,
      FAR_DEADLINE,
      sign(credKey, d),
      requirePqNow && pqKey ? sign(pqKey, d) : "0x",
      requirePqNow && pqKey ? pqKeyBytes(pqKey) : "0x",
    )
  ).wait();
}

describe("vNext kernel — SUSTAINED COMPOSITION DEFECTS (reproduced, NOT fixed here)", function () {
  this.timeout(600_000);

  it("the ledger is complete and every entry is classified as denial or incoherence, never escalation", function () {
    expect(SUSTAINED_DEFECTS.length).to.equal(3);
    for (const d of SUSTAINED_DEFECTS) {
      expect(d.classification, d.id).to.be.oneOf(["LIVENESS_DENIAL", "STATE_INCOHERENCE"]);
      expect(d.contradicts.length, d.id + " must name the published claim it falsifies").to.be.greaterThan(40);
      expect(d.rootCause.length, d.id + " must name the source construct").to.be.greaterThan(40);
      expect(d.minimalFixSketch.length, d.id + " must carry a minimal fix sketch").to.be.greaterThan(30);
    }
  });

  // =====================================================================
  it("SD-1 — floor-length poisoning gives the credential an UNCOUNTED, repeatable veto over guardian recovery", async function () {
    const w = await deployWorld({ label: "sd1", verifier: "honest" });

    // 1. An HONEST guardian quorum (k = 2 distinct principals) approves a recovery.
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const newCred = w.spareCred[0]!;
    const newPq = w.sparePq[0]!;
    const rd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: recoverParams(addrOf(newCred), pqHash(newPq), w.verifiers.honest),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(newCred), pqHash(newPq), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, rd), sign(w.gKeys[1]!, rd)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.recovery())[7], "recovery must be active").to.equal(true);
    expect(Number((await w.vault.recovery())[6]), "challenge budget untouched").to.equal(0);

    // 2. The COMPROMISED credential (2 roots — the declared asset cut, so it has
    //    gained nothing it did not already have) changes ONLY the signature LENGTH.
    //    requirePq stays true and pqParamLevel does not decrease, so
    //    _requireNoDowngrade — which compares only those two fields — permits it.
    const before = await w.vault.securityFloor();
    await setVerifierAs(
      w, w.verifiers.honest,
      { requirePq: true, pqParamLevel: Number(before[1]), pqPublicKeyLength: 32, pqSignatureLength: 64 },
      w.credKey, w.pqKey,
    );
    const after = await w.vault.securityFloor();
    expect(Number(before[3]), "the honest floor declares a 65-byte signature").to.equal(65);
    expect(Number(after[3]), "SUSTAINED: the length was changed with no downgrade check").to.equal(64);

    // 3. THE VETO. Both branches of the incoming-possession check are now closed.
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    const change = (pqPop: string): Record<string, string> => ({
      newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
      newEcdsaPop: sign(newCred, pop), newPqPop: pqPop,
    });
    // A REAL 65-byte proof now fails the LENGTH check against the poisoned floor.
    await expect(w.vault.executeRecovery(change(sign(newPq, pop))))
      .to.be.revertedWithCustomError(w.vault, "BadSignature");
    // A 64-byte proof passes the length check and fails the VERIFIER, which is
    // length-bound like every real PQ scheme at a fixed parameter level.
    await expect(w.vault.executeRecovery(change(ethers.hexlify(new Uint8Array(64)))))
      .to.be.revertedWithCustomError(w.vault, "BadSignature");

    // 4. THE POINT: the challenge budget — the ONLY mechanism AUTHORITY.md cites
    //    for "permanent recovery veto: unreachable" — was never touched, so the
    //    veto is repeatable without limit.
    const rec = await w.vault.recovery();
    expect(rec[7], "the request is still active and still unexecutable").to.equal(true);
    expect(Number(rec[6]), "SUSTAINED: challengesUsed is STILL 0 — CHALLENGE_LIMIT never engages").to.equal(0);

    // 5. AND THE BOUND ON THE CLAIM: no guardian was compromised, and the
    //    guardian roster is untouched, so no authority CUT moved.
    expect(await w.vault.guardianCommitment()).to.equal(
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint64", "address[]", "bool[]"], [w.threshold, w.guardians, w.guardianIsContract],
        ),
      ),
    );
    expect(Number(await w.vault.guardianThreshold()), "the guardian cut k is unchanged").to.equal(2);
  });

  // =====================================================================
  it("SD-2 — the containment budget window is TUMBLING: k guardians hold 9 CONTIGUOUS contained days from a declared 6", async function () {
    const w = await deployWorld({ label: "sd2", verifier: "honest" });
    const now = async (): Promise<number> => Number((await ethers.provider.getBlock("latest"))!.timestamp);
    const contain = async (): Promise<boolean> => {
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const n = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
        actionType: ACTION.RECOVER, authorityGeneration: gGen, params: ethers.id("CONTAIN"),
        domain: DOMAIN.GUARDIAN, nonce: n, deadline: FAR_DEADLINE,
      });
      try {
        await (
          await w.vault.enterContainment({
            members: w.guardians, isContract: w.guardianIsContract,
            attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
          }, n, FAR_DEADLINE)
        ).wait();
        return true;
      } catch { return false; }
    };
    const advanceTo = async (t: number): Promise<void> => {
      const d = t - (await now());
      if (d > 0) await networkHelpers.time.increase(d);
    };

    // THE STRADDLE. Two containments at the END of an epoch, two more immediately
    // after the rollover. Each epoch's own accounting stays within CONTAINMENT_BUDGET;
    // the DENIAL is contiguous across the boundary.
    expect(await contain(), "containment #1").to.equal(true);
    const W = Number(await w.vault.containmentWindowStart());

    await advanceTo(W + 27 * DAY);
    expect(await contain(), "containment #2 at +27d, still inside the first epoch").to.equal(true);
    expect(Number(await w.vault.containmentUsedInWindow()), "epoch 1 is now at the full budget").to.equal(6 * DAY);
    const contiguousFrom = Number(await w.vault.containedUntil()) - 3 * DAY;

    const containedUntilEpoch1 = Number(await w.vault.containedUntil());
    await advanceTo(W + 30 * DAY);
    const enteredAt3 = (await now()) + 1;
    expect(await contain(), "containment #3 — the rollover resets the ORIGIN to now").to.equal(true);
    expect(
      enteredAt3 <= containedUntilEpoch1 + 1,
      "the third containment must begin with NO GAP, or the denial is not contiguous",
    ).to.equal(true);
    expect(
      Number(await w.vault.containmentWindowStart()) >= W + 30 * DAY,
      "the origin JUMPED to now rather than sliding — this is a TUMBLING epoch",
    ).to.equal(true);
    expect(Number(await w.vault.containmentUsedInWindow()), "and the budget reset to zero, then took 3d").to.equal(3 * DAY);

    await advanceTo(W + 33 * DAY);
    expect(await contain(), "containment #4").to.equal(true);
    const contiguousTo = Number(await w.vault.containedUntil());

    const contiguousDays = (contiguousTo - contiguousFrom) / DAY;
    console.log("      measured contiguous denial: " + contiguousDays.toFixed(4) + " days (declared budget 6.00)");
    expect(
      contiguousDays > 6,
      "SUSTAINED: contiguous denial (" + contiguousDays.toFixed(4) + "d) exceeds the declared 6-day budget",
    ).to.equal(true);
    expect(Math.round(contiguousDays), "the straddle yields 3 x CONTAINMENT_MAX contiguous").to.equal(9);

    // THE BOUND ON THE CLAIM: containment withdraws SPENDING and never RECOVERY,
    // so the remedy stays reachable throughout — this is denial, not capture.
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const n = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const rd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: recoverParams(addrOf(w.spareCred[0]!), pqHash(w.sparePq[0]!), w.verifiers.honest),
      domain: DOMAIN.GUARDIAN, nonce: n, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(w.spareCred[0]!), pqHash(w.sparePq[0]!), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, rd), sign(w.gKeys[1]!, rd)],
      }, n, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.recovery())[7], "recovery remains OPEN while contained").to.equal(true);
  });

  // =====================================================================
  it("SD-3 — setVerifier raises requirePq against a ZERO key commitment, the exact state initialize refuses", async function () {
    // A vault BORN with an ECDSA-only floor — a configuration initialize permits,
    // and the only one from which requirePq can legally go false -> true.
    const w = await deployWorld({ label: "sd3", verifier: "honest", ecdsaOnlyFloor: true });
    expect(await w.vault.pqPublicKeyHash(), "no PQ key is committed").to.equal(ethers.ZeroHash);
    expect((await w.vault.securityFloor())[0], "and no PQ conjunct is demanded").to.equal(false);

    // GENESIS REFUSES THIS EXACT COMBINATION — the positive control that proves
    // the kernel knows the state is invalid.
    const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
    await expect(
      factory.deployVault(ethers.id("sd3-genesis-control"), {
        signer: addrOf(w.credKey), pqKeyHash: ethers.ZeroHash, verifier: w.verifiers.honest,
        threshold: 2, guardians: w.guardians, guardianIsContract: w.guardianIsContract,
        floor: { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      }),
      "initialize must refuse requirePq with a zero key commitment",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // THE TRANSITION DOES NOT. One root — the sole ECDSA credential of an
    // ECDSA-only vault, where _authorise IS the ECDSA conjunct alone.
    await setVerifierAs(
      w, w.verifiers.honest,
      { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      w.credKey, null,
    );
    expect((await w.vault.securityFloor())[0], "SUSTAINED: the conjunct is now mandatory").to.equal(true);
    expect(await w.vault.pqPublicKeyHash(), "against a commitment no preimage can satisfy").to.equal(ethers.ZeroHash);

    // AND SPENDING IS NOW UNSATISFIABLE: _authorise requires keccak256(pqKey) == 0.
    const sNonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await w.vault.credentialGeneration()) as bigint;
    const amount = ethers.parseEther("1");
    const sd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.SPEND, authorityGeneration: credGen,
      params: spendParams(w.recipient, amount),
      domain: DOMAIN.SPEND, nonce: sNonce, deadline: FAR_DEADLINE,
    });
    await expect(
      w.vault.execute(w.recipient, amount, sNonce, FAR_DEADLINE, sign(w.credKey, sd),
        ethers.hexlify(new Uint8Array(65)), ethers.hexlify(new Uint8Array(32))),
      "SUSTAINED: the vault is now permanently unspendable by its own credential",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // THE BOUND ON THE CLAIM: guardian recovery still escapes it, because
    // executeRecovery installs a FRESH key commitment of the guardians' choosing.
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const newCred = w.spareCred[0]!;
    const newPq = w.sparePq[0]!;
    const rd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: recoverParams(addrOf(newCred), pqHash(newPq), w.verifiers.honest),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(newCred), pqHash(newPq), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, rd), sign(w.gKeys[1]!, rd)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
        newEcdsaPop: sign(newCred, pop), newPqPop: sign(newPq, pop),
      })
    ).wait();
    expect(await w.vault.pqPublicKeyHash(), "the guardian quorum repaired the commitment").to.equal(pqHash(newPq));

    // END-TO-END (R6): the recovered authority is USABLE, proven by a real balance change.
    const balBefore = await ethers.provider.getBalance(w.vaultAddress);
    const n2 = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const cg2 = (await w.vault.credentialGeneration()) as bigint;
    const sd2 = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.SPEND, authorityGeneration: cg2,
      params: spendParams(w.recipient, amount), domain: DOMAIN.SPEND, nonce: n2, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.execute(w.recipient, amount, n2, FAR_DEADLINE,
        sign(newCred, sd2), sign(newPq, sd2), pqKeyBytes(newPq))
    ).wait();
    expect(await ethers.provider.getBalance(w.vaultAddress)).to.equal(balBefore - amount);
  });

  // =====================================================================
  it("prints the sustained-defect ledger", function () {
    console.log("\n  SUSTAINED COMPOSITION DEFECTS (zero Solidity changed in this PR)");
    for (const d of SUSTAINED_DEFECTS) {
      console.log("\n  " + d.id + "  [" + d.classification + "]  roots: " + d.rootsRequired.split("—")[0]!.trim());
      console.log("    " + d.title);
      console.log("    contradicts : " + d.contradicts.slice(0, 150) + "...");
      console.log("    minimal fix : " + d.minimalFixSketch.slice(0, 130) + "...");
    }
    console.log("");
  });
});
