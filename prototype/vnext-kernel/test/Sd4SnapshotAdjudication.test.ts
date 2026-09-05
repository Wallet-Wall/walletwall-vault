/**
 * EXPERIMENTAL PROTOTYPE — ADJUDICATION OF THE SD-4 SNAPSHOT HYPOTHESIS.
 *
 * The brief's leading architecture is: bind the proposed credential's
 * authentication SHAPE into the recovery request at approval time, and have
 * `executeRecovery` measure against that instead of the live floor. It also
 * says: try to kill it first.
 *
 * This file kills it, executably. Design A is COMPILED IN MEMORY — the two
 * length fields added to `RecoveryRequest`, bound into the guardian digest,
 * threaded into `_requireIncomingPossession`, with `rotateCredential` still
 * passing the live floor — and pointed at the exact SD-4 counterexample.
 *
 * IT CLOSES SD-4 AND OPENS SOMETHING WORSE.
 *
 * The decisive fact is one the brief does not state and that no amount of
 * snapshotting can change: `I-FLOOR-SHAPE-IMMUTABLE` FREEZES both floor lengths
 * the instant `requirePq` holds, so the live shape is not "unrelated mutable
 * state" at all — it is the vault's PERMANENT, GLOBAL authentication policy, and
 * the ONLY window in which it can disagree with a pending request is the
 * one-shot declaring edge. A recovery that installs a commitment of a DIFFERENT
 * shape therefore installs a credential the vault's own frozen policy can never
 * authorise: `_authorise` demands `|pqKey| == floor.pqPublicKeyLength` AND
 * `keccak256(pqKey) == pqPublicKeyHash`, and after design A those two are
 * jointly unsatisfiable. The remedy appears to succeed and the vault is dead.
 *
 * That is strictly worse than SD-4. Today the quorum sees a REVERT and
 * re-proposes at the right shape, costing one cycle. Under design A the quorum
 * sees SUCCESS, burns its request, installs a dead credential, and only then
 * discovers it must recover again. Design A also drives a commitment past the
 * shape agreement that `I-DECLARATION-EXHIBITED` (SD-3) and
 * `I-COMMITMENT-EXHIBITED-AT-ADMISSION` (SD-6/SD-7) exist to enforce — which the
 * brief forbids weakening.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { compileDeployable } from "../stateful/mutants.js";
import { replaceWithinFunction } from "../authority/mutation-harness.js";
import { quorumCancelStd } from "./sd4-harness.js";
import * as fs from "node:fs";
import * as path from "node:path";
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
  pqKeyBytes,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;
const abi = ethers.AbiCoder.defaultAbiCoder();
// W2 SUPERSESSION (implementation status only): designs A and E were adjudicated
// as textual deltas over the kernel at c67d1439. Lane W2 changed that kernel, so
// the deltas are built over the byte-exact pinned copy of the pre-W2 source (see
// the pinning note in sd4-candidate-kernels.ts); the adjudication itself is
// unchanged. The one test below that measures the REAL kernel is marked in place.
const SRC = path.join(
  process.cwd(),
  "prototype",
  "vnext-kernel",
  "test",
  "fixtures",
  "VaultKernelPrototype.pre-w2.e6964aeb.sol",
);

const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) out += ethers.id(`${tag}-${i++}`).slice(2);
  return "0x" + out.slice(0, n * 2);
};

/**
 * DESIGN A, built faithfully rather than strawmanned:
 *   1. `RecoveryRequest` gains `proposedPqKeyLength` / `proposedPqSigLength`;
 *   2. `initiateRecovery` takes them, BINDS them into the guardian digest
 *      (so the quorum authorises the shape) and stores them;
 *   3. `_requireIncomingPossession` takes the two lengths as parameters;
 *   4. `rotateCredential` passes the LIVE floor's lengths — unchanged behaviour;
 *   5. `executeRecovery` passes the REQUEST's lengths — the whole point.
 */
function designASource(): string {
  let s = fs.readFileSync(SRC, "utf8");

  // (1) struct
  s = s.replace(
    `        uint32 challengesUsed;
        bool active;
    }`,
    `        uint32 challengesUsed;
        bool active;
        uint32 proposedPqKeyLength;
        uint32 proposedPqSigLength;
    }`,
  );

  // (3) helper signature + the two live reads it must stop making
  s = s.replace(
    `        address verifierToUse,
        CredentialChange calldata c
    ) internal view {`,
    `        address verifierToUse,
        CredentialChange calldata c,
        uint32 expectedKeyLen,
        uint32 expectedSigLen
    ) internal view {`,
  );
  s = replaceWithinFunction(
    s,
    "_requireIncomingPossession",
    `if (c.newPqKey.length != floor.pqPublicKeyLength || c.newPqPop.length != floor.pqSignatureLength) {`,
    `if (c.newPqKey.length != expectedKeyLen || c.newPqPop.length != expectedSigLen) {`,
  );

  // (4) rotation keeps live semantics
  s = replaceWithinFunction(
    s,
    "rotateCredential",
    `            pqVerifier,
            c
        );`,
    `            pqVerifier,
            c,
            securityFloor.pqPublicKeyLength,
            securityFloor.pqSignatureLength
        );`,
  );

  // (5) recovery uses the request-bound shape
  s = replaceWithinFunction(
    s,
    "executeRecovery",
    `            r.proposedVerifier,
            c
        );`,
    `            r.proposedVerifier,
            c,
            r.proposedPqKeyLength,
            r.proposedPqSigLength
        );`,
  );

  // (2) initiateRecovery: params, digest binding, storage
  // Signature edits sit OUTSIDE the brace-matched body, so they are whole-file
  // replacements against a string unique to this function.
  const initSig = `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {`;
  if (!s.includes(initSig)) throw new Error("initiateRecovery signature anchor not found");
  s = s.replace(
    initSig,
    `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline,
        uint32 proposedPqKeyLength,
        uint32 proposedPqSigLength
    ) external {`,
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    `keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),`,
    `keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier, proposedPqKeyLength, proposedPqSigLength)),`,
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    `            challengesUsed: recovery.challengesUsed,
            active: true`,
    `            challengesUsed: recovery.challengesUsed,
            active: true,
            proposedPqKeyLength: proposedPqKeyLength,
            proposedPqSigLength: proposedPqSigLength`,
  );

  return s;
}

function buildDesignA(): { abi: unknown[]; bytecode: string } {
  const out = compileDeployable({ "VaultKernelPrototype.sol": designASource() });
  if (!out.ok) throw new Error("design A failed to compile:\n" + out.errors.join("\n"));
  return out.kernel;
}

/**
 * DESIGN E — the ONLY family that can actually PRESERVE the remedy rather than
 * merely relocating its failure: let a completed guardian recovery RE-DECLARE
 * the floor shape to that of the material it just proved possession of. Design A
 * plus two floor writes in `executeRecovery`.
 *
 * `stateful/defects.ts` already records this as SD-5's not-applied fix, on the
 * ground that it "moves AUTHORITY.md's Silent crypto downgrade row from
 * unreachable to k". This builds it so that claim is executed rather than cited.
 */
function buildDesignE(): { abi: unknown[]; bytecode: string } {
  let s = designASource();
  s = replaceWithinFunction(
    s,
    "executeRecovery",
    `        _installCredential(r.proposedSigner, r.proposedPqKeyHash);`,
    `        _installCredential(r.proposedSigner, r.proposedPqKeyHash);
        securityFloor.pqPublicKeyLength = r.proposedPqKeyLength;
        securityFloor.pqSignatureLength = r.proposedPqSigLength;`,
  );
  const out = compileDeployable({ "VaultKernelPrototype.sol": s });
  if (!out.ok) throw new Error("design E failed to compile:\n" + out.errors.join("\n"));
  return out.kernel;
}

describe("SD-4 — adjudicating the snapshot hypothesis against the real counterexample", () => {
  it("DESIGN A CLOSES SD-4 — the approved recovery now executes across the declaring edge", async function () {
    this.timeout(180_000);
    const kernel = buildDesignA();
    const w = await deployWorld({
      label: "sd4-designA-closes", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      implOverride: kernel,
    });
    const vault = new ethers.Contract(w.vaultAddress, kernel.abi as ethers.InterfaceAbi, w.deployer);

    const newCred = keyOf("sd4-designA-cred");
    const proposedKey = bytesOfLength(48, "sd4-designA-key");
    const proposedHash = ethers.keccak256(proposedKey);
    const KEYLEN = 48;
    const SIGLEN = 65;

    // Quorum approves the shape as well as the credential.
    const gNonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(
          ["address", "bytes32", "address", "uint32", "uint32"],
          [addrOf(newCred), proposedHash, w.verifiers.alwaysTrue, KEYLEN, SIGLEN],
        ),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.initiateRecovery(addrOf(newCred), proposedHash, w.verifiers.alwaysTrue, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE, KEYLEN, SIGLEN)
    ).wait();

    // The credential declares a 32-byte shape — the exact SD-4 counterexample.
    const armed: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const cNonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const cd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SET_VERIFIER, authorityGeneration: 1n,
      params: setVerifierParams(w.verifiers.honest, armed),
      domain: DOMAIN.CREDENTIAL, nonce: cNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.setVerifier(w.verifiers.honest, floorTuple(armed), cNonce, FAR_DEADLINE,
        sign(w.credKey, cd), "0x", pqKeyBytes(w.pqKey))
    ).wait();

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await vault.recoveryPossessionDigest()) as string;
    const receipt = await (
      await vault.executeRecovery({
        newSigner: addrOf(newCred), newPqKeyHash: proposedHash, newPqKey: proposedKey,
        newEcdsaPop: sign(newCred, pop), newPqPop: bytesOfLength(65, "sd4-designA-sig"),
      })
    ).wait();
    expect(receipt?.status, "SD-4 is closed: the approved recovery survives the declaration").to.equal(1);
    expect(await vault.ecdsaSigner()).to.equal(addrOf(newCred));
  });

  it("AND IT BRICKS THE VAULT — the installed credential can never satisfy the frozen floor", async function () {
    this.timeout(180_000);
    const kernel = buildDesignA();
    const w = await deployWorld({
      label: "sd4-designA-bricks", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      implOverride: kernel,
    });
    const vault = new ethers.Contract(w.vaultAddress, kernel.abi as ethers.InterfaceAbi, w.deployer);

    const newCred = keyOf("sd4-brick-cred");
    const proposedKey = bytesOfLength(48, "sd4-brick-key");
    const proposedHash = ethers.keccak256(proposedKey);

    const gNonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(
          ["address", "bytes32", "address", "uint32", "uint32"],
          [addrOf(newCred), proposedHash, w.verifiers.alwaysTrue, 48, 65],
        ),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.initiateRecovery(addrOf(newCred), proposedHash, w.verifiers.alwaysTrue, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE, 48, 65)
    ).wait();

    const armed: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const cNonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const cd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SET_VERIFIER, authorityGeneration: 1n,
      params: setVerifierParams(w.verifiers.honest, armed),
      domain: DOMAIN.CREDENTIAL, nonce: cNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.setVerifier(w.verifiers.honest, floorTuple(armed), cNonce, FAR_DEADLINE,
        sign(w.credKey, cd), "0x", pqKeyBytes(w.pqKey))
    ).wait();

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await vault.recoveryPossessionDigest()) as string;
    await (
      await vault.executeRecovery({
        newSigner: addrOf(newCred), newPqKeyHash: proposedHash, newPqKey: proposedKey,
        newEcdsaPop: sign(newCred, pop), newPqPop: bytesOfLength(65, "sd4-brick-sig"),
      })
    ).wait();

    // THE STATE DESIGN A CREATES: a 48-byte-key commitment under a FROZEN
    // 32-byte floor. `_authorise` demands |pqKey| == 32 AND
    // keccak256(pqKey) == hash-of-a-48-byte-key. Jointly unsatisfiable.
    const floor = await vault.securityFloor();
    expect(Number(floor[2]), "floor still demands 32").to.equal(32);
    expect(await vault.pqPublicKeyHash(), "but the commitment is of a 48-byte key").to.equal(proposedHash);

    const nonce = (await vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await vault.credentialGeneration()) as bigint;
    const sd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SPEND, authorityGeneration: credGen,
      params: spendParams(w.recipient, 1n), domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
    });
    // The honest 48-byte preimage: right hash, WRONG length.
    await expect(
      vault.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(newCred, sd),
        bytesOfLength(65, "sd4-brick-spend"), proposedKey),
      "the recovered credential cannot spend: length refused",
    ).to.be.revertedWithCustomError(vault, "BadSignature");
    // Any 32-byte string: right length, WRONG hash.
    await expect(
      vault.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(newCred, sd),
        bytesOfLength(65, "sd4-brick-spend"), bytesOfLength(32, "sd4-brick-any32")),
      "and no 32-byte string hashes to a 48-byte key's commitment",
    ).to.be.revertedWithCustomError(vault, "BadSignature");
  });

  it("DESIGN E PRESERVES THE REMEDY AND LOWERS A PUBLISHED CUT — k guardians alone reach a vacuous PQ floor", async function () {
    this.timeout(180_000);
    // Design E is the only family that can keep the quorum's proposal alive AND
    // leave the vault usable, because it lets the recovery move the shape to
    // match the material it just proved. The price is the whole reason
    // `I-FLOOR-SHAPE-IMMUTABLE` exists: the floor becomes guardian-writable.
    const kernel = buildDesignE();
    const w = await deployWorld({
      label: "sd4-designE", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      implOverride: kernel,
    });
    const vault = new ethers.Contract(w.vaultAddress, kernel.abi as ethers.InterfaceAbi, w.deployer);

    // The vault is honestly armed at a real 32/65 shape by its credential.
    const armed: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const cNonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const cd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SET_VERIFIER, authorityGeneration: 1n,
      params: setVerifierParams(w.verifiers.alwaysTrue, armed),
      domain: DOMAIN.CREDENTIAL, nonce: cNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.setVerifier(w.verifiers.alwaysTrue, floorTuple(armed), cNonce, FAR_DEADLINE,
        sign(w.credKey, cd), "0x", pqKeyBytes(w.pqKey))
    ).wait();
    expect(Number((await vault.securityFloor())[2]), "a real 32-byte PQ shape").to.equal(32);

    // Now k = 2 guardians alone propose a recovery whose declared shape is
    // structurally vacuous. No credential participation anywhere.
    const newCred = keyOf("sd4-designE-cred");
    const oneByte = "0xaa";
    const hash = ethers.keccak256(oneByte);
    const gNonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(
          ["address", "bytes32", "address", "uint32", "uint32"],
          [addrOf(newCred), hash, w.verifiers.alwaysTrue, 1, 1],
        ),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await vault.initiateRecovery(addrOf(newCred), hash, w.verifiers.alwaysTrue, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE, 1, 1)
    ).wait();

    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await vault.recoveryPossessionDigest()) as string;
    await (
      await vault.executeRecovery({
        newSigner: addrOf(newCred), newPqKeyHash: hash, newPqKey: oneByte,
        newEcdsaPop: sign(newCred, pop), newPqPop: "0xbb",
      })
    ).wait();

    const after = await vault.securityFloor();
    expect(Number(after[2]), "the PQ key shape is now ONE BYTE").to.equal(1);
    expect(Number(after[3]), "and the signature shape is ONE BYTE").to.equal(1);
    // AUTHORITY.md section 3 publishes "Silent crypto downgrade | unreachable".
    // Design E makes it reachable at k, by guardians alone, with no credential
    // involvement and no transition the document calls out. That is a CUT
    // REGRESSION, and it is why this family stays rejected.
  });

  it("THE REAL KERNEL IS STRICTLY BETTER HERE — the quorum learns immediately and re-proposes", async function () {
    this.timeout(180_000);
    // The same episode on the UNMODIFIED kernel: the recovery reverts, the
    // request is still there, and a re-proposal at the declared shape completes.
    // Cost is one extra cycle — the same cost design A pays, except design A
    // also spends a credential generation and leaves the vault dead in between.
    // W2 SUPERSESSION: this test runs on the REAL kernel, which since Lane W2
    // refuses to overwrite a live request. The quorum therefore takes its own
    // exit (K-9 mechanism B) before re-proposing — the architecture-native
    // two-path remedy of the Recovery Amendment section 4. Still one extra
    // cycle, now made of two explicit quorum acts instead of a silent overwrite.
    const w = await deployWorld({
      label: "sd4-realkernel-repropose", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const bad = keyOf("sd4-rk-bad");
    const badKey = bytesOfLength(48, "sd4-rk-badkey");

    const propose = async (cred: ethers.SigningKey, hash: string): Promise<void> => {
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const n = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.RECOVER, authorityGeneration: gGen,
        params: ethers.keccak256(
          abi.encode(["address", "bytes32", "address"], [addrOf(cred), hash, w.verifiers.alwaysTrue]),
        ),
        domain: DOMAIN.GUARDIAN, nonce: n, deadline: FAR_DEADLINE,
      });
      await (
        await w.vault.initiateRecovery(addrOf(cred), hash, w.verifiers.alwaysTrue, {
          members: w.guardians, isContract: w.guardianIsContract,
          attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
        }, n, FAR_DEADLINE)
      ).wait();
    };

    await propose(bad, ethers.keccak256(badKey));
    const armed: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 };
    const cNonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const cd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SET_VERIFIER, authorityGeneration: 1n,
      params: setVerifierParams(w.verifiers.honest, armed),
      domain: DOMAIN.CREDENTIAL, nonce: cNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.setVerifier(w.verifiers.honest, floorTuple(armed), cNonce, FAR_DEADLINE,
        sign(w.credKey, cd), "0x", pqKeyBytes(w.pqKey))
    ).wait();

    // Re-propose at the shape the vault now permanently has — after the quorum
    // clears the request the declaration stranded (W2: live overwrite is refused).
    await (await quorumCancelStd(w, w.vault)).wait();
    const good = keyOf("sd4-rk-good");
    const goodKey = pqKeyBytes(good);
    expect(ethers.dataLength(goodKey)).to.equal(32);
    await propose(good, ethers.keccak256(goodKey));
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    expect(
      (await (await w.vault.executeRecovery({
        newSigner: addrOf(good), newPqKeyHash: ethers.keccak256(goodKey), newPqKey: goodKey,
        newEcdsaPop: sign(good, pop), newPqPop: sign(good, pop),
      })).wait())?.status,
      "the remedy completes at the correct shape, and the vault is ALIVE",
    ).to.equal(1);
  });
});
