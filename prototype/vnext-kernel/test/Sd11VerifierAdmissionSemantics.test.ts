/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SD-11A / SD-11B — VERIFIER ADMISSION AND VERIFIER SEMANTIC INTEGRITY.
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * The ledger records two residuals against the verifier boundary and, at the
 * head this lane measured, NEITHER had a tracked deterministic reproduction:
 *
 *   SD-11A  the kernel cannot establish that an admitted verifier exposes only
 *           ONE accepting relation. Its `reproducedBy` names an UNTRACKED lane
 *           scratch file and says so: "Promoting one is owed by the lane that
 *           acts on SD-11A."
 *   SD-11B  whether an ALREADY-ADMITTED verifier can change its accepting
 *           relation in place was recorded as NOT EXCLUDED and NOT MEASURED,
 *           with `rootsRequired` UNKNOWN.
 *
 * This file discharges both obligations by EXECUTION rather than by prose.
 *
 * THE EVIDENCE LABELS, AND WHY THEY ARE REPEATED AT EVERY ASSERTION
 * ----------------------------------------------------------------
 * SD5-A1R had to withdraw a published claim because `setCode` was read as
 * deployment reachability. That correction is inherited here as a rule:
 *
 *   REACHABLE            a named principal calls a real function on a really
 *                        deployed contract and the system moves.
 *   REPRESENTABLE        the interface admits the shape. NOTHING is claimed
 *                        about any deployed or intended verifier exposing it.
 *   CONSTRUCTED_CONTROL  built only to test whether a PROPOSED CONTROL detects a
 *                        mechanism. Never evidence that a repository verifier
 *                        has that mechanism.
 *
 * NO `setCode`, NO `setStorageAt`, NO `setBalance` ANYWHERE. Section F asserts
 * that mechanically against this file's own bytes, so a later edit cannot
 * quietly downgrade a reachability claim into a representability one.
 *
 * SD-11B IS MEASURED AGAINST THE REAL PRODUCTION CONTRACTS. Section C deploys
 * `contracts/verifiers/AttestationPQCVerifier.sol` and
 * `ImmutableAttestationPQCVerifier.sol` compiled FROM THEIR OWN SOURCE FILES by
 * the pinned solc (see sd11-verifier-compile.ts for why this reads them rather
 * than copying them, and why nothing is added to the scanner-scoped
 * `prototype/vnext-kernel/contracts` tree).
 *
 * WHAT THIS FILE DOES NOT CLAIM
 * -----------------------------
 * Section B builds a dual-relation verifier. That is REPRESENTABLE plus
 * ADMISSIBLE, and it is NOT a claim that any production candidate exposes two
 * relations — none examined by this lane does. The four propositions SD-11A
 * spans are kept apart, in the suite's own names:
 *   (1) the interface can represent multiple accepting relations;
 *   (2) a specific production candidate exposes multiple accepting relations;
 *   (3) an attacker can cause such a verifier to be ADMITTED;
 *   (4) a cut is actually reduced in a reachable state.
 * This file measures (1), (3) and (4). It asserts NOTHING for (2).
 */
import { expect } from "chai";
import fs from "node:fs";
import { ethers } from "./connection.js";
import { compileSources, productionSource, type Deployable } from "./sd11-verifier-compile.js";
import { DESTRUCTIBLE_VERIFIER, DUAL_RELATION_VERIFIER, VERIFIER_PROXY } from "./sd11-verifier-sources.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  digestOf,
  keyOf,
  pqKeyBytes,
  pqHash,
  sign,
  spendParams,
  setVerifierParams,
  type Floor,
} from "../stateful/world.js";

const abi = ethers.AbiCoder.defaultAbiCoder();

/** ML-DSA-65 shapes, used so the committed material and declared floor look like the intended scheme. */
const ML_DSA_65_PUBLIC_KEY_LENGTH = 1952;
const ML_DSA_65_SIGNATURE_LENGTH = 3309;

const ATTESTED_ALGORITHM_ID = ethers.id("ATTESTED-ML-DSA-65");
const EIP712_DOMAIN_TYPEHASH = ethers.id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
);
const ATTESTATION_TYPEHASH = ethers.id(
  "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)",
);

const PQ_FLOOR: Floor = {
  requirePq: true,
  pqParamLevel: 3,
  pqPublicKeyLength: ML_DSA_65_PUBLIC_KEY_LENGTH,
  pqSignatureLength: ML_DSA_65_SIGNATURE_LENGTH,
};

/** The EcdsaBackedVerifier shape the rest of the suite uses: a 32-byte key, a 65-byte signature. */
const ECDSA_BACKED_FLOOR: Floor = {
  requirePq: true,
  pqParamLevel: 3,
  pqPublicKeyLength: 32,
  pqSignatureLength: 65,
};

const floorTupleOf = (f: Floor): [boolean, number, number, number] => [
  f.requirePq,
  f.pqParamLevel,
  f.pqPublicKeyLength,
  f.pqSignatureLength,
];

let FIXTURES: Map<string, Deployable>;

function fixture(name: string): Deployable {
  const unit = FIXTURES.get(name);
  if (unit === undefined) throw new Error("fixture not compiled: " + name);
  return unit;
}

async function deployFixture(name: string, args: unknown[] = []): Promise<ethers.Contract> {
  const [deployer] = await ethers.getSigners();
  const unit = fixture(name);
  const factory = new ethers.ContractFactory(unit.abi as ethers.InterfaceAbi, unit.bytecode, deployer);
  const c = await factory.deploy(...args);
  await c.waitForDeployment();
  return c as unknown as ethers.Contract;
}

/**
 * The error name of a reverted call, OBSERVED rather than asserted on the way to it.
 *
 * Two failure modes have to be handled or a refusal probe can pass vacuously:
 * ethers rejects at `estimateGas` (the common path, and the one that decodes the
 * custom error), but a call sent with an explicit gas limit RESOLVES and only
 * reveals the revert when the receipt is awaited. Returning "NO_REVERT" for the
 * second case would score a refusal that never happened, so both are awaited.
 */
async function revertNameOf(p: Promise<unknown>): Promise<string> {
  try {
    const sent = (await p) as { wait?: () => Promise<unknown> } | null;
    if (sent !== null && typeof sent === "object" && typeof sent.wait === "function") await sent.wait();
    return "NO_REVERT";
  } catch (e) {
    const err = e as { revert?: { name?: string }; shortMessage?: string; message?: string };
    return err.revert?.name ?? err.shortMessage ?? err.message ?? "UNKNOWN";
  }
}

/**
 * Deterministic filler bytes.
 *
 * A tracked reproduction may not depend on `randomBytes`: a run that passes for
 * one draw and not another is not a reproduction. This expands a fixed label by
 * iterated keccak, so the same label always yields the same key material.
 */
function deterministicBytes(label: string, length: number): string {
  let out = "0x";
  let block = ethers.id(label);
  while (ethers.dataLength(out) < length) {
    out = ethers.concat([out, block]);
    block = ethers.keccak256(block);
  }
  return ethers.dataSlice(out, 0, length);
}

interface Vault {
  readonly vault: ethers.Contract;
  readonly address: string;
  readonly chainId: bigint;
  readonly credKey: ethers.SigningKey;
  readonly verifier: string;
}

/**
 * Deploys impl + factory + ONE vault whose genesis verifier is `verifierAddress`.
 *
 * Built locally rather than through `stateful/world.ts::deployWorld` because the
 * campaign's world admits only its four fixed verifier kinds, and the whole
 * question here is what happens with a verifier it has never seen. Nothing in
 * the shared harness is modified.
 */
async function deployVaultWith(
  label: string,
  verifierAddress: string,
  floor: Floor,
  pqKeyHex: string,
): Promise<Vault> {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;

  const credKey = keyOf(label + "-cred");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));

  const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
  const impl = await Impl.deploy();
  await impl.waitForDeployment();
  // THE UNGATED FIXTURE AUTHORITY, deliberately. This file reproduces what an admission rule of
  // `code.length != 0` allows, and that rule is exactly what the fixture reinstates. The SAME
  // artifacts are REFUSED under the Generation-1 root in Sd11VerifierAdmissionProvenance.test.ts,
  // which is how closure is shown at admission without neutralising a single hostile fixture here.
  const Ungated = await ethers.getContractFactory("UngatedVerifierAuthority", deployer);
  const ungated = await Ungated.deploy();
  await ungated.waitForDeployment();
  const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
  const factory = await Factory.deploy(await impl.getAddress(), 1, await ungated.getAddress());
  await factory.waitForDeployment();

  const genesis = {
    signer: addrOf(credKey),
    pqKeyHash: ethers.keccak256(pqKeyHex),
    verifier: verifierAddress,
    threshold: 2,
    guardians: gKeys.map(addrOf),
    guardianIsContract: [false, false, false],
    floor: floorTupleOf(floor),
  };

  const salt = ethers.id(label + "-vault");
  const address: string = await factory.predictVault(salt, genesis);
  await (await factory.deployVault(salt, genesis, pqKeyHex)).wait();
  const vault = (await ethers.getContractAt("VaultKernelPrototype", address, deployer)) as unknown as ethers.Contract;
  await deployer.sendTransaction({ to: address, value: ethers.parseEther("10") });

  return { vault, address, chainId, credKey, verifier: verifierAddress };
}

/** The exact SPEND digest the kernel will build, mirrored independently of the kernel. */
async function spendDigest(v: Vault, to: string, amount: bigint): Promise<{ digest: string; nonce: bigint }> {
  const nonce = (await v.vault.nonces(DOMAIN.SPEND)) as bigint;
  const credGen = (await v.vault.credentialGeneration()) as bigint;
  return {
    nonce,
    digest: digestOf({
      chainId: v.chainId,
      vault: v.address,
      kernelGeneration: 1n,
      actionType: ACTION.SPEND,
      authorityGeneration: credGen,
      params: spendParams(to, amount),
      domain: DOMAIN.SPEND,
      nonce,
      deadline: FAR_DEADLINE,
    }),
  };
}

/**
 * Builds an `AttestationPQCVerifier` payload for `digest`, signed by `attestorKey`.
 *
 * Computed here from the typehashes rather than read back from the contract: an
 * oracle derived from the implementation under test proves only that the
 * implementation agrees with itself.
 */
function attestationPayload(
  attestorKey: ethers.SigningKey,
  verifierAddress: string,
  chainId: bigint,
  digest: string,
  publicKeyHex: string,
  deadline: bigint,
): string {
  const publicKeyHash = ethers.keccak256(publicKeyHex);
  const pqSignatureHash = ethers.id("any-ml-dsa-signature-the-attestor-claims-to-have-checked");

  const domainSeparator = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [EIP712_DOMAIN_TYPEHASH, ethers.id("AttestationPQCVerifier"), ethers.id("1"), chainId, verifierAddress],
    ),
  );
  const structHash = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256", "uint256"],
      [
        ATTESTATION_TYPEHASH,
        digest,
        publicKeyHash,
        pqSignatureHash,
        ATTESTED_ALGORITHM_ID,
        verifierAddress,
        chainId,
        deadline,
      ],
    ),
  );
  const attestationDigest = ethers.keccak256(ethers.concat(["0x1901", domainSeparator, structHash]));
  const attestationSignature = sign(attestorKey, attestationDigest);

  return abi.encode(
    ["bytes", "uint256", "bytes32", "bytes32"],
    [attestationSignature, deadline, publicKeyHash, pqSignatureHash],
  );
}

/** The forgeable WEAK witness of the dual-relation verifier: computable from PUBLIC data alone. */
function weakWitness(digest: string, publicKeyHex: string): string {
  const tag = ethers.solidityPackedKeccak256(["bytes32", "bytes"], [digest, publicKeyHex]);
  // 65 bytes — the SAME shape as the strong relation, so no length gate could separate them (M6).
  return ethers.concat([ethers.dataSlice(tag, 0, 2), ethers.zeroPadValue("0x00", 63)]);
}

describe("SD-11A / SD-11B — verifier admission and post-admission semantic integrity", function () {
  this.timeout(600_000);

  const VERDICTS: string[] = [];

  before(function () {
    const mutable = productionSource("contracts/verifiers/AttestationPQCVerifier.sol");
    const immutableAttestation = productionSource("contracts/verifiers/ImmutableAttestationPQCVerifier.sol");
    FIXTURES = compileSources({
      [mutable.key]: mutable.content,
      [immutableAttestation.key]: immutableAttestation.content,
      "sd11/DualRelationVerifier.sol": DUAL_RELATION_VERIFIER,
      "sd11/VerifierProxy.sol": VERIFIER_PROXY,
      "sd11/Destructible.sol": DESTRUCTIBLE_VERIFIER,
    });
  });

  after(function () {
    console.log("\n  SD-11 measured verdicts:");
    for (const line of VERDICTS) console.log("    " + line);
    console.log("");
  });

  // =====================================================================
  // A — D1 STRUCTURE. What the kernel actually binds at admission.
  // =====================================================================

  describe("A. the admission constraint, measured rather than read", function () {
    it("A1 the kernel admits ANY address with code — including a contract that is not a verifier at all", async function () {
      const pq = keyOf("sd11-a1-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-a1", await honestVerifier(), ECDSA_BACKED_FLOOR, key);

      // A contract with code whose ABI has no `verify` at all.
      const Stub = await ethers.getContractFactory("DestinationStub");
      const stub = await Stub.deploy();
      await stub.waitForDeployment();
      const stubAddress = await stub.getAddress();
      expect(await ethers.provider.getCode(stubAddress)).to.not.equal("0x");

      const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const credGen = (await v.vault.credentialGeneration()) as bigint;
      const digest = digestOf({
        chainId: v.chainId,
        vault: v.address,
        kernelGeneration: 1n,
        actionType: ACTION.SET_VERIFIER,
        authorityGeneration: credGen,
        params: setVerifierParams(stubAddress, ECDSA_BACKED_FLOOR),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });

      // ADMISSION SUCCEEDS. The only constraint is `code.length != 0`.
      await (
        await v.vault.setVerifier(
          stubAddress,
          floorTupleOf(ECDSA_BACKED_FLOOR),
          nonce,
          FAR_DEADLINE,
          sign(v.credKey, digest),
          sign(pq, digest),
          key,
        )
      ).wait();
      expect(await v.vault.pqVerifier()).to.equal(stubAddress);

      VERDICTS.push("A1 ADMISSION_CONSTRAINT = code.length != 0 only — a non-verifier contract is admitted");
    });

    it("A2 a codeless address is the ONLY thing refused, and the refusal is not semantic", async function () {
      const pq = keyOf("sd11-a2-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-a2", await honestVerifier(), ECDSA_BACKED_FLOOR, key);

      const codeless = "0x00000000000000000000000000000000DeaDBeef";
      const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const credGen = (await v.vault.credentialGeneration()) as bigint;
      const digest = digestOf({
        chainId: v.chainId,
        vault: v.address,
        kernelGeneration: 1n,
        actionType: ACTION.SET_VERIFIER,
        authorityGeneration: credGen,
        params: setVerifierParams(codeless, ECDSA_BACKED_FLOOR),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });

      const name = await revertNameOf(
        v.vault.setVerifier(
          codeless,
          floorTupleOf(ECDSA_BACKED_FLOOR),
          nonce,
          FAR_DEADLINE,
          sign(v.credKey, digest),
          sign(pq, digest),
          key,
          { gasLimit: 2_000_000 },
        ),
      );
      expect(name).to.contain("ZeroAddress");
    });

    it("A3 the kernel pins a CODEHASH for a migration destination and NONE for a verifier", async function () {
      // The mechanism exists in this very contract and is deliberately not
      // applied to the verifier — the contrast SD-11B's rootCause names, here
      // asserted against the compiled ABI instead of quoted from the source.
      const artifact = await ethers.getContractFactory("VaultKernelPrototype");
      const names = artifact.interface.fragments
        .filter((f): f is ethers.FunctionFragment => f.type === "function")
        .map((f) => f.name);

      expect(names, "migration binding is exposed").to.include("migration");
      expect(names, "the verifier is exposed as a bare address").to.include("pqVerifier");

      const migration = artifact.interface.getFunction("migration")!;
      const migrationOutputs = migration.outputs.map((o) => o.name);
      expect(migrationOutputs, "the migration binding carries a codehash").to.include("destinationVaultCodeHash");

      const pqVerifier = artifact.interface.getFunction("pqVerifier")!;
      expect(pqVerifier.outputs.length).to.equal(1);
      expect(pqVerifier.outputs[0]!.type, "the verifier is stored as an address and nothing else").to.equal("address");

      VERDICTS.push("A3 VERIFIER_IDENTITY_STORED = address only; migration pins destinationVaultCodeHash");
    });
  });

  // =====================================================================
  // B — SD-11A. Relation multiplicity behind one admitted address.
  // =====================================================================

  describe("B. SD-11A — one address, two accepting relations (no setCode)", function () {
    it("B1 REPRESENTABLE — a really deployed verifier accepts a STRONG and a forgeable WEAK witness, and refuses a wrong one", async function () {
      const pq = keyOf("sd11-b1-pq");
      const key = pqKeyBytes(pq);
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const digest = ethers.id("sd11-b1-digest");

      const strong = sign(pq, digest);
      const weak = weakWitness(digest, key);

      expect(await dual.verify(digest, key, strong), "STRONG accepted").to.equal(true);
      expect(await dual.verify(digest, key, weak), "WEAK accepted").to.equal(true);

      // VACUITY GUARD: the weak relation is not "accept everything".
      const wrong = ethers.concat([ethers.dataSlice(ethers.id("not-the-tag"), 0, 2), ethers.zeroPadValue("0x00", 63)]);
      expect(await dual.verify(digest, key, wrong), "a wrong witness is REFUSED").to.equal(false);

      // The weak witness is NOT a signature by the PQ key: possession is not involved.
      expect(ethers.recoverAddress(digest, strong)).to.equal(addrOf(pq));
      expect(weak).to.not.equal(strong);

      // M6: the weak witness sits at the DECLARED signature length, so a
      // structural length gate could never have separated the two relations.
      expect(ethers.dataLength(weak)).to.equal(ECDSA_BACKED_FLOOR.pqSignatureLength);

      VERDICTS.push("B1 RELATION_MULTIPLICITY = REPRESENTABLE; weak leg at the DECLARED shape (M6)");
    });

    it("B2/B3/B4 REACHABLE — admitted at cut 2, then an ECDSA-ONLY holder spends through the weak relation", async function () {
      const pq = keyOf("sd11-b2-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-b2", await honestVerifier(), ECDSA_BACKED_FLOOR, key);
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const dualAddress = await dual.getAddress();

      // ADMISSION at cut 2: the credential holds BOTH factors and signs a full
      // HYBRID setVerifier. This is an authorised act by a named principal.
      const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const credGen = (await v.vault.credentialGeneration()) as bigint;
      const admitDigest = digestOf({
        chainId: v.chainId,
        vault: v.address,
        kernelGeneration: 1n,
        actionType: ACTION.SET_VERIFIER,
        authorityGeneration: credGen,
        params: setVerifierParams(dualAddress, ECDSA_BACKED_FLOOR),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });
      await (
        await v.vault.setVerifier(
          dualAddress,
          floorTupleOf(ECDSA_BACKED_FLOOR),
          nonce,
          FAR_DEADLINE,
          sign(v.credKey, admitDigest),
          sign(pq, admitDigest),
          key,
        )
      ).wait();
      expect(await v.vault.pqVerifier()).to.equal(dualAddress);

      // THE CUT CONSEQUENCE. From here the PQ key is never used again.
      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const before = await ethers.provider.getBalance(recipient);

      const { digest, nonce: spendNonce } = await spendDigest(v, recipient, amount);
      const forged = weakWitness(digest, key);
      const receipt = await (
        await v.vault.execute(recipient, amount, spendNonce, FAR_DEADLINE, sign(v.credKey, digest), forged, key)
      ).wait();

      expect(await ethers.provider.getBalance(recipient)).to.equal(before + amount);

      // B4 INDISTINGUISHABILITY. The kernel's whole observation of the verifier
      // is one bool. Nothing it emits or stores says WHICH relation answered.
      const executed = receipt!.logs
        .filter((l) => l.address === v.address)
        .map((l) => v.vault.interface.parseLog({ topics: [...l.topics], data: l.data }))
        .filter((p) => p !== null);
      expect(executed.map((p) => p!.name), "the kernel emits its ordinary spend event").to.deep.equal(["Executed"]);

      const verifyFn = (fixture("Sd11DualRelationVerifier").abi as { name?: string; outputs?: unknown[] }[]).find(
        (e) => e.name === "verify",
      )!;
      expect((verifyFn.outputs as { type: string }[]).map((o) => o.type), "a bare bool is the entire answer").to.deep.equal(
        ["bool"],
      );

      VERDICTS.push("B2 ADMISSION_AT_CUT_2 = REACHABLE (real HYBRID setVerifier)");
      VERDICTS.push("B3 ASSET_MOVEMENT_VIA_WEAK_RELATION = REACHABLE at cut 1 (ECDSA root alone)");
      VERDICTS.push("B4 KERNEL_CAN_DISTINGUISH_RELATIONS = NO (verify returns a bare bool)");
    });

    it("B5 the weak relation also carries a CREDENTIAL REPLACEMENT, so the 2 -> 1 is not spend-only", async function () {
      const pq = keyOf("sd11-b5-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-b5", await honestVerifier(), ECDSA_BACKED_FLOOR, key);
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const dualAddress = await dual.getAddress();

      const admitNonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const credGen = (await v.vault.credentialGeneration()) as bigint;
      const admitDigest = digestOf({
        chainId: v.chainId,
        vault: v.address,
        kernelGeneration: 1n,
        actionType: ACTION.SET_VERIFIER,
        authorityGeneration: credGen,
        params: setVerifierParams(dualAddress, ECDSA_BACKED_FLOOR),
        domain: DOMAIN.CREDENTIAL,
        nonce: admitNonce,
        deadline: FAR_DEADLINE,
      });
      await (
        await v.vault.setVerifier(
          dualAddress,
          floorTupleOf(ECDSA_BACKED_FLOOR),
          admitNonce,
          FAR_DEADLINE,
          sign(v.credKey, admitDigest),
          sign(pq, admitDigest),
          key,
        )
      ).wait();

      // The attacker holds the ECDSA credential and material of its OWN choosing.
      const newCred = keyOf("sd11-b5-attacker-cred");
      const newPq = keyOf("sd11-b5-attacker-pq");
      const newKey = pqKeyBytes(newPq);
      const newPqHash = pqHash(newPq);

      const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await v.vault.credentialGeneration()) as bigint;
      const rotateDigest = digestOf({
        chainId: v.chainId,
        vault: v.address,
        kernelGeneration: 1n,
        actionType: ACTION.ROTATE,
        authorityGeneration: gen,
        params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(newCred), newPqHash])),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });

      const popDigest = (await v.vault.credentialPossessionDigest(addrOf(newCred), newPqHash)) as string;
      const change = {
        newSigner: addrOf(newCred),
        newPqKeyHash: newPqHash,
        newPqKey: newKey,
        newEcdsaPop: sign(newCred, popDigest),
        // The INCOMING possession proof is forged through the same weak relation.
        newPqPop: weakWitness(popDigest, newKey),
      };

      await (
        await v.vault.rotateCredential(
          change,
          nonce,
          FAR_DEADLINE,
          sign(v.credKey, rotateDigest),
          weakWitness(rotateDigest, key),
          key,
        )
      ).wait();

      expect(await v.vault.ecdsaSigner()).to.equal(addrOf(newCred));
      expect(await v.vault.pqPublicKeyHash()).to.equal(newPqHash);

      VERDICTS.push("B5 CREDENTIAL_REPLACEMENT_VIA_WEAK_RELATION = REACHABLE at cut 1");
    });

    it("B6 ATTRIBUTION — the identical forged witness is REFUSED by the honest single-relation verifier", async function () {
      // Without this the success above could be a kernel weakness rather than a
      // property of the admitted verifier. The positive control fixes the cause.
      const pq = keyOf("sd11-b6-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-b6", await honestVerifier(), ECDSA_BACKED_FLOOR, key);

      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const { digest, nonce } = await spendDigest(v, recipient, amount);

      const name = await revertNameOf(
        v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), weakWitness(digest, key), key, {
          gasLimit: 2_000_000,
        }),
      );
      expect(name).to.contain("VerifierDenied");

      // POSITIVE CONTROL: the honest witness still spends on the same vault.
      const before = await ethers.provider.getBalance(recipient);
      await (
        await v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), sign(pq, digest), key)
      ).wait();
      expect(await ethers.provider.getBalance(recipient)).to.equal(before + amount);

      VERDICTS.push("B6 ATTRIBUTION = the weak leg is the verifier's, not the kernel's");
    });
  });

  // =====================================================================
  // C — SD-11B, against the REAL production verifiers.
  // =====================================================================

  describe("C. SD-11B — post-admission relation change at a stable address (REAL contracts)", function () {
    it("C1 the structural premise this measurement depends on, asserted rather than assumed", async function () {
      const mutableFns = (fixture("AttestationPQCVerifier").abi as { type?: string; name?: string }[])
        .filter((e) => e.type === "function")
        .map((e) => e.name);
      const immutableFns = (fixture("ImmutableAttestationPQCVerifier").abi as { type?: string; name?: string }[])
        .filter((e) => e.type === "function")
        .map((e) => e.name);

      expect(mutableFns, "the mutable variant exposes in-place attestor rotation").to.include("updateAttestor");
      expect(immutableFns, "the immutable variant exposes none").to.not.include("updateAttestor");
      expect(immutableFns, "and no ownership surface at all").to.not.include("owner");

      VERDICTS.push("C1 AttestationPQCVerifier = MUTABLE authority; ImmutableAttestationPQCVerifier = no mutator");
    });

    it("C2..C6 REACHABLE — the verifier owner moves the accepting relation with NO kernel action, NO address change and NO codehash change", async function () {
      const attestorA = keyOf("sd11-c-attestor-A");
      const attestorB = keyOf("sd11-c-attestor-B");
      const pqPublicKey = deterministicBytes("sd11-c-ml-dsa-65-public-key", ML_DSA_65_PUBLIC_KEY_LENGTH);

      // A. ADMITTED — the real production verifier, really deployed.
      const verifier = await deployFixture("AttestationPQCVerifier", [addrOf(attestorA)]);
      const verifierAddress = await verifier.getAddress();
      const v = await deployVaultWith("sd11-c", verifierAddress, PQ_FLOOR, pqPublicKey);

      // B. THE KERNEL-VISIBLE IDENTITY, recorded before anything moves.
      const addressBefore = (await v.vault.pqVerifier()) as string;
      const codehashBefore = ethers.keccak256(await ethers.provider.getCode(verifierAddress));
      expect(addressBefore).to.equal(verifierAddress);

      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const { digest, nonce } = await spendDigest(v, recipient, amount);
      const deadline = FAR_DEADLINE;

      // C(before). A spend attested by B is REFUSED: B is not the attestor.
      const payloadFromB = attestationPayload(attestorB, verifierAddress, v.chainId, digest, pqPublicKey, deadline);
      const refused = await revertNameOf(
        v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), payloadFromB, pqPublicKey, {
          gasLimit: 3_000_000,
        }),
      );
      expect(refused, "the relation refuses B before the rotation").to.contain("VerifierDenied");
      expect(await v.vault.nonces(DOMAIN.SPEND), "a refused spend consumes nothing").to.equal(nonce);

      // D. THE MUTATION — one call, by the VERIFIER's owner. No kernel interaction.
      const rotation = await (await verifier.updateAttestor(addrOf(attestorB))).wait();
      const kernelLogs = rotation!.logs.filter((l) => l.address === v.address);
      expect(kernelLogs, "the kernel emits NOTHING when the relation moves").to.deep.equal([]);

      expect(await v.vault.pqVerifier(), "the kernel-visible address is unchanged").to.equal(addressBefore);
      const codehashAfter = ethers.keccak256(await ethers.provider.getCode(verifierAddress));
      expect(codehashAfter, "the runtime bytecode is unchanged, bit for bit").to.equal(codehashBefore);
      expect(await v.vault.pqPublicKeyHash(), "the committed key is unchanged").to.equal(
        ethers.keccak256(pqPublicKey),
      );
      expect(await v.vault.credentialGeneration(), "no credential transition occurred").to.equal(1n);

      // E. THE KERNEL NOW ACTS ON THE CHANGED RELATION. Same call, same bytes.
      const before = await ethers.provider.getBalance(recipient);
      await (
        await v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), payloadFromB, pqPublicKey)
      ).wait();
      expect(await ethers.provider.getBalance(recipient), "value moved on the NEW relation").to.equal(before + amount);

      // C6 BOTH DIRECTIONS. The relation MOVED; it did not merely widen.
      const next = await spendDigest(v, recipient, amount);
      const payloadFromA = attestationPayload(attestorA, verifierAddress, v.chainId, next.digest, pqPublicKey, deadline);
      const nowRefused = await revertNameOf(
        v.vault.execute(
          recipient,
          amount,
          next.nonce,
          FAR_DEADLINE,
          sign(v.credKey, next.digest),
          payloadFromA,
          pqPublicKey,
          { gasLimit: 3_000_000 },
        ),
      );
      expect(nowRefused, "the previously-accepted attestor is now refused").to.contain("VerifierDenied");

      VERDICTS.push("C2-C5 SD-11B = REACHABLE on AttestationPQCVerifier (owner-controlled attestor rotation)");
      VERDICTS.push("C4 EXTCODEHASH_PIN_WOULD_DETECT_IT = NO — runtime bytecode is bit-identical across the change");
      VERDICTS.push("C6 RELATION_MOVED_BOTH_WAYS = YES (A accepted->refused, B refused->accepted)");
    });

    it("C7 POSITIVE CONTROL — the immutable variant has no such path, so the class is not universal", async function () {
      const attestorA = keyOf("sd11-c7-attestor-A");
      const attestorB = keyOf("sd11-c7-attestor-B");
      const pqPublicKey = deterministicBytes("sd11-c7-ml-dsa-65-public-key", ML_DSA_65_PUBLIC_KEY_LENGTH);

      const verifier = await deployFixture("ImmutableAttestationPQCVerifier", [addrOf(attestorA)]);
      const verifierAddress = await verifier.getAddress();
      const v = await deployVaultWith("sd11-c7", verifierAddress, PQ_FLOOR, pqPublicKey);

      // There is no rotation function to call — the technique the production
      // suite already uses for this contract (test/ImmutableAttestationPQCVerifier.test.ts).
      expect((verifier as unknown as Record<string, unknown>).updateAttestor).to.equal(undefined);

      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const { digest, nonce } = await spendDigest(v, recipient, amount);

      const payloadFromB = attestationPayload(attestorB, verifierAddress, v.chainId, digest, pqPublicKey, FAR_DEADLINE);
      const refused = await revertNameOf(
        v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), payloadFromB, pqPublicKey, {
          gasLimit: 3_000_000,
        }),
      );
      expect(refused).to.contain("VerifierDenied");

      // POSITIVE CONTROL: the fixed attestor still authorises, so the refusal
      // above is the relation refusing B rather than a broken fixture.
      const payloadFromA = attestationPayload(attestorA, verifierAddress, v.chainId, digest, pqPublicKey, FAR_DEADLINE);
      const before = await ethers.provider.getBalance(recipient);
      await (
        await v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), payloadFromA, pqPublicKey)
      ).wait();
      expect(await ethers.provider.getBalance(recipient)).to.equal(before + amount);

      VERDICTS.push("C7 ImmutableAttestationPQCVerifier = IMMUTABLE_BY_CONSTRUCTION (no mutator, positive control passes)");
    });
  });

  // =====================================================================
  // G — VACUITY GUARDS. Every "unchanged" above is only a measurement if the
  //     instrument that produced it was capable of reporting "changed".
  // =====================================================================

  describe("G. vacuity guards — the instruments must be able to disagree", function () {
    it("G1 the codehash instrument DISCRIMINATES — two different contracts do not share a codehash", async function () {
      // Without this, "the codehash is unchanged" in C4 and D1 could be an
      // instrument that returns the same value for everything.
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const honest = await honestVerifier();
      const a = ethers.keccak256(await ethers.provider.getCode(await dual.getAddress()));
      const b = ethers.keccak256(await ethers.provider.getCode(honest));
      expect(a).to.not.equal(b);
    });

    it("G2 WHERE THE ATTESTOR AUTHORITY LIVES decides what a code-identity control can bind", async function () {
      // This is the fact the candidate-control matrix turns on, so it is measured
      // rather than inferred from the word "immutable" in a declaration.
      const attestor = keyOf("sd11-g2-attestor");
      const target = addrOf(attestor);

      const mutable = await deployFixture("AttestationPQCVerifier", [target]);
      const immutableV = await deployFixture("ImmutableAttestationPQCVerifier", [target]);
      const mutableAddress = await mutable.getAddress();
      const immutableAddress = await immutableV.getAddress();

      const mutableCode = await ethers.provider.getCode(mutableAddress);
      const immutableCode = await ethers.provider.getCode(immutableAddress);

      const codeHolds = (code: string, addr: string) => code.toLowerCase().includes(addr.toLowerCase().slice(2));
      const storageHolds = async (addr: string, needle: string): Promise<boolean> => {
        const want = needle.toLowerCase().slice(2);
        for (let slot = 0; slot < 12; slot++) {
          const word = await ethers.provider.getStorage(addr, slot);
          if (word.toLowerCase().endsWith(want)) return true;
        }
        return false;
      };

      // MUTABLE: the authority is STORAGE, so it is outside BOTH the address and
      // the runtime code — which is exactly why C4's codehash never moved.
      expect(await storageHolds(mutableAddress, target), "mutable attestor is in storage").to.equal(true);
      expect(codeHolds(mutableCode, target), "mutable attestor is NOT in runtime code").to.equal(false);

      // IMMUTABLE: the authority is baked into the runtime code, so it is inside
      // code identity, and changing it necessarily means a new deployment — a new
      // address, which the kernel's existing address identity already sees.
      expect(codeHolds(immutableCode, target), "immutable attestor IS in runtime code").to.equal(true);
      expect(await storageHolds(immutableAddress, target), "immutable attestor is not in storage").to.equal(false);

      VERDICTS.push("G2 ATTESTOR_AUTHORITY_LOCATION = STORAGE (mutable, outside code identity) vs CODE (immutable)");
    });

    it("G3 the vault-log instrument DISCRIMINATES — it can see a kernel event when one is emitted", async function () {
      // Without this, "the kernel emitted NOTHING when the relation moved" could
      // be a filter that never matches anything.
      const pq = keyOf("sd11-g3-pq");
      const key = pqKeyBytes(pq);
      const v = await deployVaultWith("sd11-g3", await honestVerifier(), ECDSA_BACKED_FLOOR, key);

      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const { digest, nonce } = await spendDigest(v, recipient, amount);
      const receipt = await (
        await v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), sign(pq, digest), key)
      ).wait();

      expect(receipt!.logs.filter((l) => l.address === v.address).length).to.be.greaterThan(0);
    });
  });

  // =====================================================================
  // D — candidate control B, attacked with its own named mechanism.
  // =====================================================================

  describe("D. CONSTRUCTED_CONTROL — does an EXTCODEHASH pin close the delegatecall route?", function () {
    it("D1 a proxy's codehash is stable while its implementation pointer moves", async function () {
      const pq = keyOf("sd11-d1-pq");
      const key = pqKeyBytes(pq);

      const strict = await deployFixture("Sd11StrictImpl");
      const permissive = await deployFixture("Sd11PermissiveImpl");
      const proxy = await deployFixture("Sd11ProxyOwner", [await strict.getAddress()]);
      const proxyAddress = await proxy.getAddress();

      const v = await deployVaultWith("sd11-d1", proxyAddress, ECDSA_BACKED_FLOOR, key);
      const codehashBefore = ethers.keccak256(await ethers.provider.getCode(proxyAddress));

      const recipient = ethers.Wallet.createRandom().address;
      const amount = ethers.parseEther("1");
      const { digest, nonce } = await spendDigest(v, recipient, amount);
      const junk = ethers.zeroPadValue("0x01", 65);

      const refused = await revertNameOf(
        v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), junk, key, {
          gasLimit: 2_000_000,
        }),
      );
      expect(refused, "the strict implementation refuses").to.contain("VerifierDenied");

      await (await proxy.setImplementation(await permissive.getAddress())).wait();

      const codehashAfter = ethers.keccak256(await ethers.provider.getCode(proxyAddress));
      expect(codehashAfter, "the ADMITTED address's codehash never moved").to.equal(codehashBefore);
      expect(await v.vault.pqVerifier()).to.equal(proxyAddress);

      const before = await ethers.provider.getBalance(recipient);
      await (
        await v.vault.execute(recipient, amount, nonce, FAR_DEADLINE, sign(v.credKey, digest), junk, key)
      ).wait();
      expect(await ethers.provider.getBalance(recipient)).to.equal(before + amount);

      VERDICTS.push("D1 EXTCODEHASH_PIN_CLOSES_DELEGATECALL = NO (CONSTRUCTED_CONTROL, not a repository verifier)");
    });
  });

  // =====================================================================
  // E — the metamorphic class, on the pinned EVM rather than from memory.
  // =====================================================================

  describe("E. the mechanism a codehash pin WOULD address, measured", function () {
    it("E1 under the pinned cancun EVM, SELFDESTRUCT does not remove the code of an account that outlived its creation transaction", async function () {
      const [funder] = await ethers.getSigners();
      const victim = await deployFixture("Sd11Destructible");
      const address = await victim.getAddress();
      const codeBefore = await ethers.provider.getCode(address);
      expect(codeBefore).to.not.equal("0x");

      // VACUITY GUARD: fund it, so the sweep proves SELFDESTRUCT really executed.
      // Without this, E1 would assert only that `destroy()` did not revert, and a
      // no-op body would score as evidence about EIP-6780.
      await (await funder.sendTransaction({ to: address, value: 1n })).wait();
      expect(await ethers.provider.getBalance(address)).to.equal(1n);

      // A LATER transaction than the creation one — the EIP-6780 condition.
      await (await victim.destroy()).wait();

      expect(await ethers.provider.getBalance(address), "SELFDESTRUCT executed: the balance was swept").to.equal(0n);
      const codeAfter = await ethers.provider.getCode(address);
      expect(codeAfter, "EIP-6780: code survives selfdestruct outside the creation transaction").to.equal(codeBefore);

      VERDICTS.push(
        "E1 METAMORPHIC_REPLACEMENT_OF_AN_ADMITTED_VERIFIER = NOT REACHABLE by later-transaction selfdestruct (cancun)",
      );
      VERDICTS.push("E1 RESIDUAL = the same-transaction create+admit+destruct composition is NOT MEASURED here");
    });
  });

  // =====================================================================
  // F — the guard that keeps the labels honest.
  // =====================================================================

  describe("F. evidence discipline, enforced mechanically", function () {
    it("F1 this reproduction uses no harness superpower", async function () {
      const sources = [
        "prototype/vnext-kernel/test/Sd11VerifierAdmissionSemantics.test.ts",
        "prototype/vnext-kernel/test/sd11-verifier-compile.ts",
        "prototype/vnext-kernel/test/sd11-verifier-sources.ts",
      ];
      for (const file of sources) {
        const text = fs.readFileSync(file, "utf8");
        for (const forbidden of ["hardhat_setCode", "setStorageAt", "setBalance", "impersonateAccount"]) {
          // The literal appears in this list itself, so the check looks for a CALL.
          expect(text.includes(forbidden + "("), file + " must not call " + forbidden).to.equal(false);
        }
      }
    });
  });
});

/** The honest single-relation second factor the rest of the suite uses. */
async function honestVerifier(): Promise<string> {
  const [deployer] = await ethers.getSigners();
  const V = await ethers.getContractFactory("EcdsaBackedVerifier", deployer);
  const v = await V.deploy();
  await v.waitForDeployment();
  return v.getAddress();
}
