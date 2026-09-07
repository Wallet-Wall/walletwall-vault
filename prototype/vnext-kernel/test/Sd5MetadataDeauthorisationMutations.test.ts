/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE — LANE SD5-I.
 *
 * THE DE-AUTHORISATION, GUARDED. SD5-I removed six clauses; a removal is only
 * assured if REINSERTING each one is DETECTED. Every mutant below puts a removed
 * clause back and is killed by a NARROW observation — one that no unrelated
 * revert could produce — because a mutant killed by an incidental failure proves
 * nothing about the clause it names.
 *
 * TWO OF THESE GUARD THE OPPOSITE DIRECTION, and they are the load-bearing pair.
 * M-SD5-COMMITMENT-BYPASS and M-SD5-PQ-DISABLE delete things SD5-I did NOT touch.
 * Without them a suite could pass with the lengths removed AND the commitment
 * removed, and the whole de-authorisation argument — "the exact committed key
 * bytes are the binding that survives" — would be unfalsifiable rather than
 * proven. See stateful/mutants.ts for why M17 and M18 were RETIRED here rather
 * than kept: their invariant no longer exists, so they restore nothing.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION, DOMAIN, FAR_DEADLINE, addrOf, deployWorld, digestOf, floorTuple,
  pqHash, pqKeyBytes, setVerifierParams, sign, spendParams, type Floor, type World,
} from "../stateful/world.js";
import { proposeStd } from "./sd4-harness.js";
import { compileDeployable, type DeployableMutant } from "../stateful/mutants.js";
import { replaceWithinFunction } from "../authority/mutation-harness.js";
import * as fs from "node:fs";
import * as path from "node:path";

const KERNEL_GEN = 1n;
const DAY = 24 * 60 * 60;
const ONE = "0x01";
const ONE_HASH = ethers.keccak256(ONE);
const ARMED: Floor = { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65 };

function kernelSource(): string {
  return fs.readFileSync(
    path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "VaultKernelPrototype.sol"),
    "utf8",
  );
}

/** The clauses SD5-I removed, reinserted verbatim. */
const MUTANTS: { id: string; why: string; apply: (s: string) => string }[] = [
  {
    id: "M-SD5-LENGTH-AUTH-RESTORED",
    why: "puts the structural length equality back into _authorise",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_authorise",
        "        if (keccak256(pqKey) != pqPublicKeyHash) revert BadSignature();",
        "        if (pqKey.length != floor.pqPublicKeyLength || pqSig.length != floor.pqSignatureLength) {\n" +
          "            revert BadSignature();\n" +
          "        }\n" +
          "        if (keccak256(pqKey) != pqPublicKeyHash) revert BadSignature();",
      ),
  },
  {
    id: "M-SD5-INCOMING-LENGTH-RESTORED",
    why: "puts the structural length equality back into _requireIncomingPossession",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireIncomingPossession",
        "        if (keccak256(c.newPqKey) != expectedPqKeyHash) revert BadSignature();",
        "        if (c.newPqKey.length != floor.pqPublicKeyLength || c.newPqPop.length != floor.pqSignatureLength) {\n" +
          "            revert BadSignature();\n" +
          "        }\n" +
          "        if (keccak256(c.newPqKey) != expectedPqKeyHash) revert BadSignature();",
      ),
  },
  {
    id: "M-SD5-PARAMLEVEL-RATCHET-RESTORED",
    why: "puts the withdrawn flat-scalar ratchet back into _requireNoDowngrade",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireNoDowngrade",
        "        if (current.requirePq && !next.requirePq) revert Downgrade();",
        "        if (current.requirePq && !next.requirePq) revert Downgrade();\n" +
          "        if (next.pqParamLevel < current.pqParamLevel) revert Downgrade();",
      ),
  },
  {
    id: "M-SD5-PQ-DISABLE",
    why: "DELETES the one clause SD5-I kept — a mandatory PQ conjunct becomes silently disableable",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireNoDowngrade",
        "        if (current.requirePq && !next.requirePq) revert Downgrade();",
        "",
      ),
  },
  {
    id: "M-SD5-COMMITMENT-BYPASS",
    why: "DELETES the surviving commitment check in _authorise — the binding the whole de-authorisation argument rests on",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_authorise",
        "        if (keccak256(pqKey) != pqPublicKeyHash) revert BadSignature();",
        "",
      ),
  },
];

const built = new Map<string, DeployableMutant>();

before(function () {
  this.timeout(900_000);
  for (const m of MUTANTS) {
    // replaceWithinFunction throws when the anchor is not found EXACTLY once, so
    // a mutant that silently became a no-op fails loudly here rather than scoring
    // as a survivor. That is the same discipline StatefulMutationAdequacy applies.
    const out = compileDeployable({ "VaultKernelPrototype.sol": m.apply(kernelSource()) });
    if (!out.ok) throw new Error(m.id + " failed to compile:\n" + out.errors.join("\n"));
    built.set(m.id, out.kernel);
  }
});

const armedAlwaysTrue = async (label: string, impl?: DeployableMutant) => {
  const w = await deployWorld({ label, verifier: "alwaysTrue", ...(impl ? { implOverride: impl } : {}) });
  return w;
};

async function spendTx(w: World, pqKey: string, pqSig: string) {
  const amount = ethers.parseEther("1");
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SPEND, authorityGeneration: gen, params: spendParams(w.recipient, amount),
    domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
  });
  return w.vault.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(w.credKey, d), pqSig, pqKey);
}

async function setVerifierTx(w: World, verifier: string, floor: Floor) {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER, authorityGeneration: gen,
    params: setVerifierParams(verifier, floor), domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
  });
  return w.vault.setVerifier(verifier, floorTuple(floor), nonce, FAR_DEADLINE,
    sign(w.credKey, d), sign(w.pqKey, d), pqKeyBytes(w.pqKey));
}

describe("vNext kernel — SD5-I: the metadata de-authorisation, guarded by reinsertion", function () {
  this.timeout(900_000);

  it("every SD5-I mutant applies and compiles", function () {
    expect(built.size, "a stale anchor would score as a survivor while testing nothing").to.equal(MUTANTS.length);
  });

  it("M-SD5-LENGTH-AUTH-RESTORED — killed: a 1-byte key and 1-byte signature must SPEND under a permissive verifier", async function () {
    // NARROW BY CONSTRUCTION: the verifier is held constant (alwaysTrue) across
    // both arms, so only a KERNEL-side length gate can explain a revert.
    const live = await armedAlwaysTrue("sd5m-len-live");
    // Commit a 1-byte key on the live kernel by arming from dormant would need a
    // declaring edge; instead use the world's own committed key at its own length
    // and a SHORT signature, which the removed gate is exactly what refused.
    await (await spendTx(live, pqKeyBytes(live.pqKey), ONE)).wait();

    const mut = await armedAlwaysTrue("sd5m-len-mut", built.get("M-SD5-LENGTH-AUTH-RESTORED"));
    await expect(
      spendTx(mut, pqKeyBytes(mut.pqKey), ONE),
      "the mutant reintroduces the kernel-side length gate",
    ).to.be.revertedWithCustomError(mut.vault, "BadSignature");
  });

  it("M-SD5-INCOMING-LENGTH-RESTORED — killed: a matured recovery with a 1-byte PoP must COMPLETE", async function () {
    const run = async (label: string, impl?: DeployableMutant) => {
      const w = await deployWorld({ label, verifier: "alwaysTrue", ...(impl ? { implOverride: impl } : {}) });
      const nc = w.spareCred[0]!, np = w.sparePq[0]!;
      await proposeStd(w, w.vault, addrOf(nc), pqHash(np), w.verifiers.alwaysTrue);
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      return { w, nc, tx: w.vault.executeRecovery({
        newSigner: addrOf(nc), newPqKeyHash: pqHash(np), newPqKey: pqKeyBytes(np),
        newEcdsaPop: sign(nc, pop), newPqPop: ONE,
      }) };
    };
    const live = await run("sd5m-inc-live");
    await (await live.tx).wait();
    expect(await live.w.vault.ecdsaSigner(), "live kernel completes").to.equal(addrOf(live.nc));

    const mut = await run("sd5m-inc-mut", built.get("M-SD5-INCOMING-LENGTH-RESTORED"));
    await expect(mut.tx, "the mutant reintroduces the incoming length gate").to.be.revert(ethers);
  });

  it("M-SD5-PARAMLEVEL-RATCHET-RESTORED — killed: LOWERING pqParamLevel must SUCCEED and the getter must read it", async function () {
    const live = await armedAlwaysTrue("sd5m-lvl-live");
    await (await setVerifierTx(live, live.verifiers.alwaysTrue, { ...ARMED, pqParamLevel: 9 })).wait();
    await (await setVerifierTx(live, live.verifiers.alwaysTrue, { ...ARMED, pqParamLevel: 2 })).wait();
    expect(Number((await live.vault.securityFloor())[1]), "the withdrawn scalar is freely writable").to.equal(2);

    const mut = await armedAlwaysTrue("sd5m-lvl-mut", built.get("M-SD5-PARAMLEVEL-RATCHET-RESTORED"));
    await (await setVerifierTx(mut, mut.verifiers.alwaysTrue, { ...ARMED, pqParamLevel: 9 })).wait();
    await expect(
      setVerifierTx(mut, mut.verifiers.alwaysTrue, { ...ARMED, pqParamLevel: 2 }),
      "the mutant reintroduces the ratchet",
    ).to.be.revertedWithCustomError(mut.vault, "Downgrade");
  });

  it("M-SD5-PQ-DISABLE — killed: requirePq true -> false must still REVERT, with a positive control", async function () {
    const off: Floor = { ...ARMED, requirePq: false };
    const live = await armedAlwaysTrue("sd5m-off-live");
    await expect(
      setVerifierTx(live, live.verifiers.alwaysTrue, off),
      "I-NO-SILENT-DOWNGRADE-G1 is the one clause SD5-I kept",
    ).to.be.revertedWithCustomError(live.vault, "Downgrade");
    // POSITIVE CONTROL, same kernel: a requirePq-PRESERVING write succeeds, so the
    // refusal above is the requirePq clause and not a dead setVerifier path.
    await (await setVerifierTx(live, live.verifiers.alwaysTrue, { ...ARMED, pqParamLevel: 7 })).wait();

    const mut = await armedAlwaysTrue("sd5m-off-mut", built.get("M-SD5-PQ-DISABLE"));
    await (await setVerifierTx(mut, mut.verifiers.alwaysTrue, off)).wait();
    expect((await mut.vault.securityFloor())[0], "the mutant silently disables the PQ conjunct").to.equal(false);
  });

  it("M-SD5-COMMITMENT-BYPASS — killed: noise of ANY length must be REFUSED; this is the control for the whole amendment", async function () {
    // Under alwaysTrue the verifier refuses nothing, so the ONLY thing that can
    // refuse is the kernel's committed-key binding. If this ever passes on the
    // live kernel, the de-authorisation has removed one check too many.
    const live = await armedAlwaysTrue("sd5m-commit-live");
    const noise = "0x" + "ab".repeat(32);
    await expect(
      spendTx(live, noise, ONE),
      "the exact committed key bytes are the binding that survives SD5-I",
    ).to.be.revertedWithCustomError(live.vault, "BadSignature");
    // POSITIVE CONTROL: the committed key, same verifier, same short signature.
    await (await spendTx(live, pqKeyBytes(live.pqKey), ONE)).wait();

    const mut = await armedAlwaysTrue("sd5m-commit-mut", built.get("M-SD5-COMMITMENT-BYPASS"));
    await (await spendTx(mut, noise, ONE)).wait();
    // The mutant moves value on unrelated bytes — the failure mode the surviving
    // check exists to prevent, and the reason removing the LENGTH gate is safe
    // only while this one stands.
    expect(await mut.vault.ecdsaSigner(), "mutant accepted noise as the PQ key").to.equal(addrOf(mut.credKey));
  });
});
