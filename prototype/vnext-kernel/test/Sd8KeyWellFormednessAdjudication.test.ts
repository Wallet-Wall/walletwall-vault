/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SD-8 ADJUDICATION — KEY WELL-FORMEDNESS AT EVERY CREDENTIAL-INSTALLATION EDGE, MEASURED.
 *
 * THE QUESTION
 * ------------
 * Genesis proves knowledge of a preimage of the PQ credential commitment
 * (`I-COMMITMENT-EXHIBITED-AT-ADMISSION`). Does it ALSO establish that the exhibited
 * preimage is a valid, well-formed public key for the admitted Generation-1 verifier
 * relation? The ledger's SD-8 entry says no. This file does not trust that wording: it
 * measures the admission chain layer by layer, on a vault bound to the Generation-1 root
 * (SD-11 is FROZEN INPUT here — every verifier below is root-created, and provenance is
 * never the variable), against the REAL admitted class and the REAL attestor tooling.
 *
 * FIVE PROPERTIES, KEPT APART — collapsing them is how a defect gets over- or under-read:
 *   P1 KNOWLEDGE OF BYTES      the caller can produce the bytes.
 *   P2 PREIMAGE CONSISTENCY    keccak256(bytes) == the committed hash. THE KERNEL'S ONLY CHECK.
 *   P3 VERIFIER ACCEPTANCE     `ImmutableAttestationPQCVerifier.verify` returns true: an EIP-712
 *                              statement by the attestor that binds keccak256(bytes) and NOTHING
 *                              ELSE about the bytes (§A2 measures it).
 *   P4 KEY WELL-FORMEDNESS     the bytes decode as an ML-DSA-65 public key (FIPS 204). For
 *                              ML-DSA-65 this is EXACTLY `length == 1952`: every 1952-byte string
 *                              decodes (§A4). The only layer in this repository that checks it is
 *                              the attestor's OFF-CHAIN verifier, `src/verifier/ml-dsa-65.ts`,
 *                              which is imported and measured here rather than paraphrased.
 *   P5 PROOF OF POSSESSION     a signature under the key verifies. Only the attestor's off-chain
 *                              ML-DSA verification sees this; the chain sees the attestor's word.
 *
 * EVIDENCE LABELS (inherited from lane SD-11)
 *   REACHABLE            a named principal calls a real function on a really deployed contract.
 *   CONSTRUCTED_CONTROL  built only to measure what a layer checks. The BLIND attestor below is
 *                        one: an attestor key that signs whatever it is handed. It is NOT a claim
 *                        that the production attestor tooling is blind — that tooling is the
 *                        HONEST attestor here, and it is the real `verifyMLDSA65Detailed`.
 * NO `setCode`, NO `setStorageAt`: every artifact is created by an ordinary transaction (§F).
 *
 * WHAT THIS FILE DOES NOT CLAIM
 *   - That an arbitrary 1952-byte string has NO secret key. Deciding that is the MLWE problem.
 *     What is established is narrower and mechanical: it is length-valid, it decodes, and the
 *     signature the requester presented does not verify under it.
 *   - Anything about verifier provenance (frozen, see above) or about the attestor's honesty as
 *     a trust assumption (that is the Generation-1 trust model, stated in the class's own NatSpec).
 *   - Anything about a fix. §E measures what candidate controls WOULD discriminate, from data
 *     already produced in this file. No kernel is mutated and no candidate is implemented.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ethers, networkHelpers } from "./connection.js";
import {
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  verifyMLDSA65Detailed,
} from "../../../src/verifier/ml-dsa-65.js";
import { compileMutatedKernel } from "../authority/mutation-harness.js";
import { findContract, loadCompiledSources, type AstNode, type CompiledSources } from "../authority/ast.js";
import {
  ACTION,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  addrOf,
  digestOf,
  floorTuple,
  keyOf,
  recoverParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
} from "../stateful/world.js";

const abi = ethers.AbiCoder.defaultAbiCoder();
const DAY = 24 * 60 * 60;
const ADMITTED = "ADMITTED";
/** What an honest attestor hands back when it refuses: nothing. The chain sees an empty payload. */
const NO_ATTESTATION = "0x";

/** ML-DSA-65 shapes. NON_AUTHORITATIVE_SECURITY_METADATA since SD5-I; declared so the vault looks like the intended scheme. */
const FLOOR_ML_DSA_65: Floor = { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 1952, pqSignatureLength: 3309 };

const ATTESTED_ALGORITHM_ID = ethers.id("ATTESTED-ML-DSA-65");
const EIP712_DOMAIN_TYPEHASH = ethers.id("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
const ATTESTATION_TYPEHASH = ethers.id(
  "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)",
);

const ARTIFACTS = path.join("prototype", "vnext-kernel", "artifacts", "prototype", "vnext-kernel", "contracts");
const BUILD_INFO = path.join("prototype", "vnext-kernel", "artifacts", "build-info");
const GEN1_CLASS_COPY = "prototype/vnext-kernel/contracts/verifiers/ImmutableAttestationPQCVerifier.sol";
const GEN1_CLASS_ORIGINAL = "contracts/verifiers/ImmutableAttestationPQCVerifier.sol";
const THIS_FILE = "prototype/vnext-kernel/test/Sd8KeyWellFormednessAdjudication.test.ts";

const sha256File = (p: string): string => createHash("sha256").update(fs.readFileSync(p)).digest("hex");

/** Deterministic filler: a tracked reproduction may not depend on a random draw. */
function deterministicBytes(label: string, length: number): string {
  if (length === 0) return "0x";
  let out = "0x";
  let block = ethers.id(label);
  while (ethers.dataLength(out) < length) {
    out = ethers.concat([out, block]);
    block = ethers.keccak256(block);
  }
  return ethers.dataSlice(out, 0, length);
}

// =====================================================================
// KEY MATERIAL — one REAL ML-DSA-65 keypair (positive control) and eight constructions.
// =====================================================================

/** A real FIPS 204 keypair from a fixed seed, so the positive control is reproducible byte for byte. */
const REAL = ml_dsa65.keygen(ethers.getBytes(ethers.id("sd8-real-ml-dsa-65-key-seed")));
const REAL_PK = ethers.hexlify(REAL.publicKey);
const realSign = (digest: string): string =>
  ethers.hexlify(ml_dsa65.sign(ethers.getBytes(digest), REAL.secretKey, { extraEntropy: false }));

/** A second real keypair, so rotation and recovery have an honest INCOMING positive control. */
const REAL2 = ml_dsa65.keygen(ethers.getBytes(ethers.id("sd8-second-real-ml-dsa-65-key-seed")));
const REAL2_PK = ethers.hexlify(REAL2.publicKey);
const real2Sign = (digest: string): string =>
  ethers.hexlify(ml_dsa65.sign(ethers.getBytes(digest), REAL2.secretKey, { extraEntropy: false }));

/**
 * The signature a requester PRESENTS beside a malformed key. It carries the exact ML-DSA-65
 * signature length, so the attestor's refusal is attributable to the KEY and never to the
 * signature's shape (the off-chain verifier's reason precedence is message, key length,
 * signature length, then the cryptographic check).
 */
const CLAIMED_SIG = deterministicBytes("sd8-claimed-ml-dsa-65-signature", ML_DSA_65_SIGNATURE_LENGTH);

interface Construction {
  readonly id: string;
  readonly bytes: string;
  readonly note: string;
}

/** Eight byte strings that are NOT established ML-DSA-65 public keys, chosen to discriminate the layers. */
const CONSTRUCTIONS: readonly Construction[] = [
  { id: "K0-empty", bytes: "0x", note: "0 bytes — the minimum; keccak256 of the empty string is a legal non-zero commitment" },
  { id: "K1-one-byte", bytes: "0x01", note: "1 byte" },
  { id: "K32-harness-shape", bytes: deterministicBytes("sd8-k32", 32), note: "32 bytes — the shape every other suite's EcdsaBackedVerifier uses" },
  { id: "K1951-short", bytes: deterministicBytes("sd8-k1951", 1951), note: "one byte short of ML-DSA-65" },
  { id: "K1953-long", bytes: deterministicBytes("sd8-k1953", 1953), note: "one byte over ML-DSA-65" },
  { id: "K1952-arbitrary", bytes: deterministicBytes("sd8-k1952", 1952), note: "1952 arbitrary bytes — length-valid, decodes, no known secret key" },
  { id: "K1952-all-zero", bytes: "0x" + "00".repeat(1952), note: "1952 zero bytes — length-valid, decodes" },
  { id: "K1952-all-ones", bytes: "0x" + "ff".repeat(1952), note: "1952 0xff bytes — length-valid, decodes" },
];

// =====================================================================
// THE ATTESTOR — measured twice: HONEST (the real off-chain tooling) and BLIND (a constructed control).
// =====================================================================

/**
 * An `ImmutableAttestationPQCVerifier` payload for `digest`, signed by `attestor`, naming
 * `verifierAddress`. Computed from the typehashes rather than read back from the contract, so the
 * oracle is independent of the implementation it judges.
 */
function attestationPayload(
  attestor: ethers.SigningKey,
  verifierAddress: string,
  chainId: bigint,
  digest: string,
  publicKey: string,
  pqSignatureHash: string,
): string {
  const publicKeyHash = ethers.keccak256(publicKey);
  const domain = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [EIP712_DOMAIN_TYPEHASH, ethers.id("AttestationPQCVerifier"), ethers.id("1"), chainId, verifierAddress],
    ),
  );
  const struct = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256", "uint256"],
      [ATTESTATION_TYPEHASH, digest, publicKeyHash, pqSignatureHash, ATTESTED_ALGORITHM_ID, verifierAddress, chainId, FAR_DEADLINE],
    ),
  );
  const attestation = sign(attestor, ethers.keccak256(ethers.concat(["0x1901", domain, struct])));
  return abi.encode(["bytes", "uint256", "bytes32", "bytes32"], [attestation, FAR_DEADLINE, publicKeyHash, pqSignatureHash]);
}

/** CONSTRUCTED_CONTROL — signs whatever it is handed. Measures what the CHAIN checks about the key: nothing but its hash. */
function blindAttest(attestor: ethers.SigningKey, verifier: string, chainId: bigint, digest: string, publicKey: string): string {
  return attestationPayload(attestor, verifier, chainId, digest, publicKey, ethers.id("blind-attestor-checked-nothing"));
}

interface AttestorVerdict {
  readonly payload: string;
  readonly reason: string;
  readonly verified: boolean;
}

/**
 * The HONEST attestor: the repository's own `verifyMLDSA65Detailed` decides, exactly as
 * `scripts/lib/attestation.ts#verifyAndSignAttestation` does before it signs. Refusal yields NO
 * payload, which is what a caller who cannot obtain an attestation is left to submit.
 */
function honestAttest(
  attestor: ethers.SigningKey,
  verifier: string,
  chainId: bigint,
  digest: string,
  publicKey: string,
  mlDsaSignature: string,
): AttestorVerdict {
  const v = verifyMLDSA65Detailed(ethers.getBytes(publicKey), ethers.getBytes(digest), ethers.getBytes(mlDsaSignature));
  if (!v.result.verified) return { payload: NO_ATTESTATION, reason: v.result.reason, verified: false };
  return {
    payload: attestationPayload(attestor, verifier, chainId, digest, publicKey, ethers.keccak256(mlDsaSignature)),
    reason: v.result.reason,
    verified: true,
  };
}

// =====================================================================
// ERROR ATTRIBUTION — the kernel error a refusal carried, OBSERVED.
// =====================================================================

let KERNEL_IFACE: ethers.Interface;

function errorNameOf(e: unknown): string {
  const err = e as {
    revert?: { name?: string } | null;
    data?: unknown;
    error?: { data?: unknown };
    info?: { error?: { data?: unknown } };
    shortMessage?: string;
    message?: string;
  };
  if (err.revert?.name) return err.revert.name;
  for (const data of [err.data, err.error?.data, err.info?.error?.data]) {
    if (typeof data === "string" && data.length >= 10) {
      try {
        const parsed = KERNEL_IFACE.parseError(data);
        if (parsed) return parsed.name;
      } catch {
        // not a kernel error; fall through to the raw selector
      }
      return "UNDECODED:" + data.slice(0, 10);
    }
  }
  return "REVERTED:" + (err.shortMessage ?? err.message ?? "unknown");
}

/** "ADMITTED" if the call lands (receipt awaited), otherwise the observed refusal. */
async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    const sent = (await p) as { wait?: () => Promise<unknown> } | null;
    if (sent !== null && typeof sent === "object" && typeof sent.wait === "function") await sent.wait();
    return ADMITTED;
  } catch (e) {
    return errorNameOf(e);
  }
}

// =====================================================================
// THE WORLD — one Generation-1 root, one root-created verifier, one factory bound to the root.
// =====================================================================

interface Base {
  readonly label: string;
  readonly chainId: bigint;
  readonly deployer: ethers.Signer;
  readonly root: ethers.Contract;
  readonly factory: ethers.Contract;
  /** The root-created Generation-1 verifier every vault below is born under. */
  readonly verifier: string;
  /** Its sole configuration: the attestor. Held by the harness so it can act honestly OR blindly. */
  readonly attestor: ethers.SigningKey;
  readonly recipient: string;
}

interface Genesis {
  signer: string;
  pqKeyHash: string;
  verifier: string;
  threshold: number;
  guardians: string[];
  guardianIsContract: boolean[];
  floor: [boolean, number, number, number];
}

interface Vault {
  readonly vault: ethers.Contract;
  readonly address: string;
  readonly credKey: ethers.SigningKey;
  readonly gKeys: ethers.SigningKey[];
  readonly genesis: Genesis;
  readonly salt: string;
  /** null = no PQ credential committed (bytes32(0)). */
  readonly committedKey: string | null;
  readonly armed: boolean;
}

async function deployBase(label: string): Promise<Base> {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const Root = await ethers.getContractFactory("ImmutableAttestationVerifierFactoryPrototype", deployer);
  const root = (await Root.deploy()) as unknown as ethers.Contract;
  await root.waitForDeployment();
  const attestor = keyOf(label + "-attestor");
  const verifier = (await root.deployVerifier.staticCall(addrOf(attestor))) as string;
  await (await root.deployVerifier(addrOf(attestor))).wait();
  const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
  const impl = await Impl.deploy();
  await impl.waitForDeployment();
  const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
  const factory = (await Factory.deploy(await impl.getAddress(), 1, await root.getAddress())) as unknown as ethers.Contract;
  await factory.waitForDeployment();
  return { label, chainId, deployer, root, factory, verifier, attestor, recipient: addrOf(keyOf(label + "-recipient")) };
}

function genesisFor(base: Base, label: string, armed: boolean, committedKey: string | null): Omit<Vault, "vault" | "address"> {
  const credKey = keyOf(label + "-cred");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  const genesis: Genesis = {
    signer: addrOf(credKey),
    pqKeyHash: committedKey === null ? ethers.ZeroHash : ethers.keccak256(committedKey),
    verifier: base.verifier,
    threshold: 2,
    guardians: gKeys.map(addrOf),
    guardianIsContract: [false, false, false],
    floor: floorTuple(armed ? FLOOR_ML_DSA_65 : ECDSA_ONLY_FLOOR),
  };
  return { credKey, gKeys, genesis, salt: ethers.id(label + "-vault"), committedKey, armed };
}

/** REACHABLE: `deployVault` through the factory, witness = the committed bytes (or nothing). */
async function deployGenesis(
  base: Base,
  label: string,
  armed: boolean,
  committedKey: string | null,
  witnessOverride?: string,
): Promise<{ result: string; vault?: Vault }> {
  const g = genesisFor(base, label, armed, committedKey);
  const witness = witnessOverride ?? committedKey ?? "0x";
  const address = (await base.factory.predictVault(g.salt, g.genesis)) as string;
  const result = await outcome(base.factory.deployVault(g.salt, g.genesis, witness));
  if (result !== ADMITTED) return { result };
  const vault = (await ethers.getContractAt("VaultKernelPrototype", address, base.deployer)) as unknown as ethers.Contract;
  await (await base.deployer.sendTransaction({ to: address, value: ethers.parseEther("10") })).wait();
  return { result, vault: { ...g, vault, address } };
}

// =====================================================================
// TRANSACTIONS — every digest mirrored independently of the kernel.
// =====================================================================

const kernelDigest = (base: Base, v: Vault, actionType: string, authorityGeneration: bigint, params: string, domain: number, nonce: bigint): string =>
  digestOf({ chainId: base.chainId, vault: v.address, kernelGeneration: 1n, actionType, authorityGeneration, params, domain, nonce, deadline: FAR_DEADLINE });

const quorum = (v: Vault, d: string) => ({
  members: v.genesis.guardians,
  isContract: v.genesis.guardianIsContract,
  attestingIndices: [0, 1],
  attestations: [sign(v.gKeys[0]!, d), sign(v.gKeys[1]!, d)],
});

/** The outgoing authorisation's PQ leg: a payload for the action digest, or nothing on a dormant floor. */
type PqLeg = (digest: string) => string;
const NO_PQ_LEG: PqLeg = () => "0x";

async function spendTx(base: Base, v: Vault, cred: ethers.SigningKey, pqLeg: PqLeg, pqKey: string) {
  const amount = ethers.parseEther("1");
  const nonce = (await v.vault.nonces(DOMAIN.SPEND)) as bigint;
  const gen = (await v.vault.credentialGeneration()) as bigint;
  const d = kernelDigest(base, v, ACTION.SPEND, gen, spendParams(base.recipient, amount), DOMAIN.SPEND, nonce);
  return v.vault.execute(base.recipient, amount, nonce, FAR_DEADLINE, sign(cred, d), pqLeg(d), pqKey);
}

interface Rotation {
  cred: ethers.SigningKey;
  outPqLeg: PqLeg;
  outPqKey: string;
  newCred: ethers.SigningKey;
  newPq: string;
  newPqPop: (popDigest: string) => string;
}

async function rotateTx(base: Base, v: Vault, r: Rotation) {
  const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.vault.credentialGeneration()) as bigint;
  const newHash = ethers.keccak256(r.newPq);
  const params = ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(r.newCred), newHash]));
  const d = kernelDigest(base, v, ACTION.ROTATE, gen, params, DOMAIN.CREDENTIAL, nonce);
  const pop = (await v.vault.credentialPossessionDigest(addrOf(r.newCred), newHash)) as string;
  const change = {
    newSigner: addrOf(r.newCred),
    newPqKeyHash: newHash,
    newPqKey: r.newPq,
    newEcdsaPop: sign(r.newCred, pop),
    newPqPop: r.newPqPop(pop),
  };
  return v.vault.rotateCredential(change, nonce, FAR_DEADLINE, sign(r.cred, d), r.outPqLeg(d), r.outPqKey);
}

/** `setVerifier` with a floor: on the dormant->armed edge `exhibit` must be the committed preimage. */
async function setVerifierTx(base: Base, v: Vault, cred: ethers.SigningKey, outPqLeg: PqLeg, outPqKey: string, floor: Floor, exhibit: string) {
  const nonce = (await v.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.vault.credentialGeneration()) as bigint;
  const d = kernelDigest(base, v, ACTION.SET_VERIFIER, gen, setVerifierParams(base.verifier, floor), DOMAIN.CREDENTIAL, nonce);
  return v.vault.setVerifier(base.verifier, floorTuple(floor), nonce, FAR_DEADLINE, sign(cred, d), outPqLeg(d), exhibit);
}

async function initiateTx(base: Base, v: Vault, newCred: ethers.SigningKey, newPq: string) {
  const newHash = ethers.keccak256(newPq);
  const gGen = (await v.vault.guardianGeneration()) as bigint;
  const nonce = (await v.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = kernelDigest(base, v, ACTION.RECOVER, gGen, recoverParams(addrOf(newCred), newHash, base.verifier), DOMAIN.GUARDIAN, nonce);
  return v.vault.initiateRecovery(addrOf(newCred), newHash, base.verifier, quorum(v, d), nonce, FAR_DEADLINE);
}

/** Permissionless completion; `pqPop` supplies the INCOMING possession witness for the proposed verifier. */
async function executeRecoveryTx(v: Vault, newCred: ethers.SigningKey, newPq: string, pqPop: (popDigest: string) => string) {
  const pop = (await v.vault.recoveryPossessionDigest()) as string;
  return v.vault.executeRecovery({
    newSigner: addrOf(newCred),
    newPqKeyHash: ethers.keccak256(newPq),
    newPqKey: newPq,
    newEcdsaPop: sign(newCred, pop),
    newPqPop: pqPop(pop),
  });
}

/** An honest PQ leg over `key` using a real signer; refusal yields NO_ATTESTATION. */
const honestLeg =
  (base: Base, key: string, mlSign: (digest: string) => string): PqLeg =>
  (d) =>
    honestAttest(base.attestor, base.verifier, base.chainId, d, key, mlSign(d)).payload;
/** An honest PQ leg for material the requester cannot sign: it presents CLAIMED_SIG and is refused. */
const honestLegUnsignable = (base: Base, key: string): PqLeg => honestLeg(base, key, () => CLAIMED_SIG);
const blindLeg =
  (base: Base, key: string): PqLeg =>
  (d) =>
    blindAttest(base.attestor, base.verifier, base.chainId, d, key);

// =====================================================================
// AST CENSUS — every read of key bytes, from the compiler's own AST, never from text.
// =====================================================================

type Visitor = (node: AstNode, parent: AstNode | null) => void;

function visit(node: AstNode, f: Visitor, parent: AstNode | null = null): void {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const x of node) visit(x, f, parent);
    return;
  }
  const isNode = typeof node.nodeType === "string";
  if (isNode) f(node, parent);
  for (const [k, v] of Object.entries(node)) if (k !== "src" && v !== null && typeof v === "object") visit(v, f, isNode ? node : parent);
}

const exprText = (e: AstNode): string =>
  e?.nodeType === "Identifier" ? e.name : e?.nodeType === "MemberAccess" ? exprText(e.expression) + "." + e.memberName : String(e?.nodeType);

interface KeyReadCensus {
  /** keccak256(<key>) — P2. */
  preimage: string[];
  /** <verifier>.verify(_, <key>, _) — P3. */
  verifier: string[];
  /** <key> forwarded verbatim to an internal helper. */
  forward: string[];
  /** <key>.length — the one read a structural check would need. */
  length: string[];
  /** anything else. */
  other: string[];
  /** Identifier or member named `algorithmId`. */
  algorithmId: number;
  /** MemberAccess of the two declared floor lengths. */
  declaredLengthReads: string[];
}

/** Which expressions denote PQ public-key BYTES in the kernel: the `pqKey` parameters and `CredentialChange.newPqKey`. */
const isKeyRead = (n: AstNode): boolean =>
  (n.nodeType === "Identifier" && n.name === "pqKey") || (n.nodeType === "MemberAccess" && n.memberName === "newPqKey");

function keyReadCensus(contract: AstNode): KeyReadCensus {
  const census: KeyReadCensus = { preimage: [], verifier: [], forward: [], length: [], other: [], algorithmId: 0, declaredLengthReads: [] };
  for (const fn of (contract.nodes as AstNode[]).filter((n) => n.nodeType === "FunctionDefinition")) {
    const name: string = fn.name || fn.kind;
    visit(fn.body, (n, parent) => {
      if (n.nodeType === "MemberAccess" && n.memberName === "length" && isKeyRead(n.expression)) census.length.push(name + ":" + exprText(n));
      if (n.nodeType === "MemberAccess" && (n.memberName === "pqPublicKeyLength" || n.memberName === "pqSignatureLength")) {
        census.declaredLengthReads.push(name + ":" + exprText(n));
      }
      if ((n.nodeType === "Identifier" && n.name === "algorithmId") || (n.nodeType === "MemberAccess" && n.memberName === "algorithmId")) census.algorithmId += 1;
      if (!isKeyRead(n)) return;
      // A MemberAccess `.length` on a key read is classified above; the key read itself is then the
      // MemberAccess's child, whose parent is that MemberAccess — record it as `length`, not `other`.
      if (parent?.nodeType === "MemberAccess" && parent.memberName === "length") return;
      const site = name + ":" + exprText(n);
      if (parent?.nodeType === "FunctionCall") {
        const callee = parent.expression;
        if (callee?.nodeType === "Identifier" && callee.name === "keccak256") return void census.preimage.push(site);
        if (callee?.nodeType === "MemberAccess" && callee.memberName === "verify") return void census.verifier.push(site);
        if (callee?.nodeType === "Identifier" && String(callee.name).startsWith("_")) return void census.forward.push(site + "->" + callee.name);
      }
      census.other.push(site + " under " + String(parent?.nodeType));
    });
  }
  return census;
}

// =====================================================================
// THE VERDICT TABLE — one row per construction, printed at the end for the record.
// =====================================================================

interface Row {
  id: string;
  length: number;
  lengthValid: boolean;
  attestorReason: string;
  genesis: string;
  honestSpend: string;
  blindSpend: string;
}
const ROWS: Row[] = [];

describe("SD-8 ADJUDICATION — does genesis establish key well-formedness for the admitted Generation-1 relation?", function () {
  this.timeout(600_000);

  before(async function () {
    KERNEL_IFACE = (await ethers.getContractFactory("VaultKernelPrototype")).interface;
  });

  after(function () {
    // The record. Every row was produced by a REACHABLE transaction against a root-created verifier.
    console.table(ROWS);
  });

  // ===================================================================
  describe("A. D1 — the admission chain, re-derived from the compiler's AST", function () {
    let kernelCensus: KeyReadCensus;
    let built: CompiledSources;

    before(function () {
      const out = compileMutatedKernel({});
      if (!out.ok) throw new Error("kernel AST compile failed:" + out.errors.join(";"));
      kernelCensus = keyReadCensus(findContract(out.compiled, "VaultKernelPrototype"));
      built = loadCompiledSources(BUILD_INFO);
    });

    it("A1 every read of PQ key bytes in the kernel is a keccak256 preimage, a verifier argument, or a verbatim forward — never a length, never a structure", function () {
      // P2 — the five preimage sites: initialize, _authorise, _requireIncomingPossession (dormant and armed), setVerifier's declaring edge.
      expect(kernelCensus.preimage, "keccak256(<key>) sites").to.have.lengthOf(5);
      expect(kernelCensus.preimage.map((s) => s.split(":")[0]).sort()).to.deep.equal(
        ["_authorise", "_requireIncomingPossession", "_requireIncomingPossession", "initialize", "setVerifier"].sort(),
      );
      // P3 — the two verifier sites: _authorise (outgoing) and _requireIncomingPossession (incoming, armed only).
      expect(kernelCensus.verifier, "verify(_, <key>, _) sites").to.have.lengthOf(2);
      expect(kernelCensus.verifier.map((s) => s.split(":")[0]).sort()).to.deep.equal(["_authorise", "_requireIncomingPossession"]);
      // Forwards: the four external entry points that hand pqKey to _authorise.
      expect(kernelCensus.forward.map((s) => s.split(":")[0]).sort(), "verbatim forwards").to.deep.equal(
        ["execute", "rotateCredential", "setPolicy", "setVerifier"].sort(),
      );
      // P4 — NOT PRESENT: no `.length` on any key expression, anywhere in the kernel.
      expect(kernelCensus.length, "structural reads of key bytes").to.deep.equal([]);
      expect(kernelCensus.other, "unclassified key reads").to.deep.equal([]);
    });

    it("A2 the kernel never asks the verifier which scheme it implements, and never consults the declared key length", function () {
      expect(kernelCensus.algorithmId, "algorithmId is on IPQCVerifier and the kernel never calls it").to.equal(0);
      // E-PRIME (SD5-I): `pqPublicKeyLength` and `pqSignatureLength` are NON_AUTHORITATIVE_SECURITY_METADATA.
      // Measured: not one MemberAccess of either field in any kernel function. They are copied as a struct and never read.
      expect(kernelCensus.declaredLengthReads, "reads of the declared lengths").to.deep.equal([]);
    });

    it("A3 the admitted Generation-1 class reads `publicKey` exactly once — as a keccak256 argument — and exposes no key-validation entry point", function () {
      const cls = findContract(built, "ImmutableAttestationPQCVerifier");
      const verifyFn = (cls.nodes as AstNode[]).find((n) => n.nodeType === "FunctionDefinition" && n.name === "verify");
      expect(verifyFn, "verify exists").to.not.equal(undefined);
      const reads: string[] = [];
      const lengthReads: string[] = [];
      visit(verifyFn.body, (n, parent) => {
        if (n.nodeType === "MemberAccess" && n.memberName === "length" && n.expression?.nodeType === "Identifier" && n.expression.name === "publicKey") {
          lengthReads.push(exprText(n));
        }
        if (n.nodeType === "Identifier" && n.name === "publicKey") {
          if (parent?.nodeType === "MemberAccess" && parent.memberName === "length") return;
          const callee = parent?.nodeType === "FunctionCall" ? parent.expression : undefined;
          reads.push(callee?.nodeType === "Identifier" ? callee.name : "under " + String(parent?.nodeType));
        }
      });
      // P3 IS P2 SEEN FROM THE VERIFIER: the class binds keccak256(publicKey) to the attestor's statement and nothing else.
      expect(reads, "every read of publicKey in verify").to.deep.equal(["keccak256"]);
      expect(lengthReads, "publicKey.length reads").to.deep.equal([]);
      // The class copy IS the production class (SD-11 CLASS ASSURANCE), so this is a statement about production too.
      expect(sha256File(GEN1_CLASS_COPY), "byte-identical to the production class").to.equal(sha256File(GEN1_CLASS_ORIGINAL));
      // And the ABI carries no entry a kernel could call to ask "is this a key": only the IPQCVerifier surface plus EIP-712 metadata.
      const artifact = JSON.parse(fs.readFileSync(path.join(ARTIFACTS, "verifiers", "ImmutableAttestationPQCVerifier.sol", "ImmutableAttestationPQCVerifier.json"), "utf8"));
      const fns = (artifact.abi as { type: string; name?: string }[]).filter((e) => e.type === "function").map((e) => e.name).sort();
      expect(fns).to.deep.equal(["ATTESTED_ML_DSA_65_ALGORITHM_ID", "algorithmId", "attestor", "eip712Domain", "verify"]);
    });

    it("A4 for ML-DSA-65, key WELL-FORMEDNESS is exactly `length == 1952`: wrong lengths are refused on input, every 1952-byte string decodes", function () {
      expect(ML_DSA_65_PUBLIC_KEY_LENGTH).to.equal(1952);
      expect(ML_DSA_65_SIGNATURE_LENGTH).to.equal(3309);
      const msg = ethers.getBytes(ethers.id("sd8-a4-message"));
      const sig = ml_dsa65.sign(msg, REAL.secretKey, { extraEntropy: false });
      expect(ml_dsa65.verify(sig, msg, REAL.publicKey), "positive control: the real key verifies its own signature").to.equal(true);
      // Wrong length: the library refuses the KEY before any cryptography — that is the whole of FIPS 204 well-formedness it enforces.
      for (const k of CONSTRUCTIONS.filter((c) => ethers.dataLength(c.bytes) !== 1952)) {
        expect(() => ml_dsa65.verify(sig, msg, ethers.getBytes(k.bytes)), k.id + " must be refused on length").to.throw(/length/);
      }
      // Right length: EVERY such string decodes as a public key (t1 is packed in 10-bit fields and every 10-bit value is in range),
      // so the library reaches the cryptographic check and answers false. There is no "encoding-invalid" 1952-byte key.
      for (const k of CONSTRUCTIONS.filter((c) => ethers.dataLength(c.bytes) === 1952)) {
        expect(ml_dsa65.verify(sig, msg, ethers.getBytes(k.bytes)), k.id + " decodes and fails verification").to.equal(false);
      }
    });
  });

  // ===================================================================
  describe("B. D2 — deterministic reproductions at GENESIS, against the real admitted class", function () {
    let base: Base;
    before(async function () {
      base = await deployBase("sd8-b");
    });

    it("B0 POSITIVE CONTROL: a real ML-DSA-65 key is admitted, the honest attestor attests, the vault spends", async function () {
      const g = await deployGenesis(base, "sd8-b-real", true, REAL_PK);
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(REAL_PK));
      const before = await ethers.provider.getBalance(base.recipient);
      expect(await outcome(spendTx(base, v, v.credKey, honestLeg(base, REAL_PK, realSign), REAL_PK))).to.equal(ADMITTED);
      expect((await ethers.provider.getBalance(base.recipient)) - before).to.equal(ethers.parseEther("1"));
      ROWS.push({ id: "REAL-ml-dsa-65", length: 1952, lengthValid: true, attestorReason: "ML_DSA_65_VALID", genesis: ADMITTED, honestSpend: ADMITTED, blindSpend: ADMITTED });
    });

    it("B1 NEGATIVE CONTROL: the preimage leg is live — a non-empty commitment with no witness is refused with BadSignature", async function () {
      // So every ADMITTED below is attributable to a consistent exhibit, never to a missing check.
      const r = await deployGenesis(base, "sd8-b-nowitness", true, CONSTRUCTIONS[5]!.bytes, "0x");
      expect(r.result).to.equal("BadSignature");
    });

    for (const k of CONSTRUCTIONS) {
      it(`B2 ${k.id} (${k.note}): ADMITTED at genesis; the honest attestor refuses it; a blind attestation makes the chain accept it`, async function () {
        const length = ethers.dataLength(k.bytes);
        // (i) GENESIS — REACHABLE. requirePq = true, declared shape 1952/3309, commitment = keccak256(K), witness = K.
        const g = await deployGenesis(base, "sd8-b-" + k.id, true, k.bytes);
        expect(g.result, "the kernel's preimage check is satisfied by any bytes that hash to the commitment").to.equal(ADMITTED);
        const v = g.vault!;
        expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(k.bytes));
        const floor = await v.vault.securityFloor();
        expect(floor[0], "the PQ conjunct is MANDATORY from birth").to.equal(true);
        expect(Number(floor[2]), "the declared length is recorded as signed metadata").to.equal(1952);

        // (ii) THE HONEST ATTESTOR — the real off-chain verifier decides, and refuses.
        const amount = ethers.parseEther("1");
        const nonce = (await v.vault.nonces(DOMAIN.SPEND)) as bigint;
        const d = kernelDigest(base, v, ACTION.SPEND, 1n, spendParams(base.recipient, amount), DOMAIN.SPEND, nonce);
        const verdict = honestAttest(base.attestor, base.verifier, base.chainId, d, k.bytes, CLAIMED_SIG);
        expect(verdict.verified).to.equal(false);
        if (length !== 1952) expect(verdict.reason, "refused on the KEY's length, before any cryptography").to.equal("INVALID_PUBLIC_KEY_LENGTH");
        else expect(verdict.reason, "length-valid: refused only by the cryptographic relation").to.be.oneOf(["VERIFY_FAILED", "VERIFY_EXCEPTION"]);
        // With no attestation to present, the spend dies at the verifier — not at the kernel, whose preimage check PASSES.
        const honestSpend = await outcome(spendTx(base, v, v.credKey, () => verdict.payload, k.bytes));
        expect(honestSpend, "born unable to authorise").to.equal("VerifierDenied");

        // (iii) THE BLIND ATTESTOR — CONSTRUCTED_CONTROL. Same bytes, same vault, same digest; only the attestor's conduct differs.
        const before = await ethers.provider.getBalance(base.recipient);
        const blindSpend = await outcome(spendTx(base, v, v.credKey, blindLeg(base, k.bytes), k.bytes));
        expect(blindSpend, "the on-chain relation binds keccak256(publicKey) and NOTHING ELSE about the bytes").to.equal(ADMITTED);
        expect((await ethers.provider.getBalance(base.recipient)) - before).to.equal(amount);

        ROWS.push({ id: k.id, length, lengthValid: length === 1952, attestorReason: verdict.reason, genesis: g.result, honestSpend, blindSpend });
      });
    }

    it("B3 the EMPTY key is the degenerate case: an omitted witness and an exhibited empty key are the same calldata, so the exhibit requirement is vacuous for it", async function () {
      // keccak256("") is a fixed, well-known, non-zero value. A deployer who commits it "exhibits" it by passing no bytes at all.
      const empty = ethers.keccak256("0x");
      expect(empty).to.not.equal(ethers.ZeroHash);
      const r = await deployGenesis(base, "sd8-b-empty-omitted", true, "0x", "0x");
      expect(r.result, "no witness supplied, and the kernel is satisfied").to.equal(ADMITTED);
      expect(await r.vault!.vault.pqPublicKeyHash()).to.equal(empty);
    });
  });

  // ===================================================================
  describe("C. D3 — consequence: what actually fails, and for whom", function () {
    let base: Base;
    let dead: Vault; // the K0-empty vault: armed, committed to keccak256("")
    before(async function () {
      base = await deployBase("sd8-c");
      const g = await deployGenesis(base, "sd8-c-dead", true, "0x");
      expect(g.result).to.equal(ADMITTED);
      dead = g.vault!;
    });

    it("C1 NO DOWNGRADE: the ECDSA factor alone cannot spend — the PQ conjunct is required and unsatisfiable, so the vault is DEAD, not weakened", async function () {
      expect(await outcome(spendTx(base, dead, dead.credKey, NO_PQ_LEG, "0x"))).to.equal("VerifierDenied");
      expect(await outcome(spendTx(base, dead, dead.credKey, honestLegUnsignable(base, "0x"), "0x"))).to.equal("VerifierDenied");
    });

    it("C2 NO CREDENTIAL REPAIR: rotation and setVerifier are HYBRID-authorised, so the dead conjunct blocks the credential from fixing its own vault", async function () {
      const target = keyOf("sd8-c2-target");
      expect(
        await outcome(rotateTx(base, dead, { cred: dead.credKey, outPqLeg: honestLegUnsignable(base, "0x"), outPqKey: "0x", newCred: target, newPq: REAL_PK, newPqPop: (pop) => honestAttest(base.attestor, base.verifier, base.chainId, pop, REAL_PK, realSign(pop)).payload })),
        "the OUTGOING authorisation fails first",
      ).to.equal("VerifierDenied");
      expect(await outcome(setVerifierTx(base, dead, dead.credKey, honestLegUnsignable(base, "0x"), "0x", FLOOR_ML_DSA_65, "0x"))).to.equal("VerifierDenied");
      expect(await dead.vault.pqPublicKeyHash(), "nothing moved").to.equal(ethers.keccak256("0x"));
    });

    it("C3 NO ATTACKER AUTHORITY: the commitment is inside the CREATE2 salt, so malformed material cannot be placed in anyone else's vault at genesis", async function () {
      const honest = genesisFor(base, "sd8-c3", true, REAL_PK);
      const honestAddress = (await base.factory.predictVault(honest.salt, honest.genesis)) as string;
      const seen = new Set<string>([honestAddress]);
      for (const k of CONSTRUCTIONS) {
        const g = genesisFor(base, "sd8-c3", true, k.bytes); // SAME label, SAME salt, SAME signer and roster — only the commitment differs
        const a = (await base.factory.predictVault(g.salt, g.genesis)) as string;
        expect(a, k.id + " lands at a different address from the honest configuration").to.not.equal(honestAddress);
        expect(seen.has(a), k.id + " is distinct from every other construction").to.equal(false);
        seen.add(a);
      }
    });

    it("C4 ESCAPABLE AT k: a guardian quorum recovers the dead vault to a real key, the honest attestor attests the incoming possession proof, and the vault spends", async function () {
      const fresh = keyOf("sd8-c4-fresh");
      expect(await outcome(initiateTx(base, dead, fresh, REAL_PK))).to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      const honestPop = (pop: string) => honestAttest(base.attestor, base.verifier, base.chainId, pop, REAL_PK, realSign(pop)).payload;
      expect(await outcome(executeRecoveryTx(dead, fresh, REAL_PK, honestPop))).to.equal(ADMITTED);
      expect(await dead.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(REAL_PK));
      expect(await dead.vault.ecdsaSigner()).to.equal(addrOf(fresh));
      expect(await outcome(spendTx(base, dead, fresh, honestLeg(base, REAL_PK, realSign), REAL_PK)), "alive again").to.equal(ADMITTED);
    });

    it("C5 STATE INCOHERENCE, documentary only: the floor records 1952 while the committed preimage is 0 bytes, and nothing reads the recorded value", async function () {
      const g = await deployGenesis(base, "sd8-c5", true, "0x");
      const floor = await g.vault!.vault.securityFloor();
      expect(Number(floor[2])).to.equal(1952);
      expect(ethers.dataLength("0x")).to.equal(0);
      // §A2 established that no kernel function reads pqPublicKeyLength: the contradiction is in signed metadata that E-PRIME
      // de-authorised. It misleads an observer; it changes no authorisation, possession or recovery outcome.
    });
  });

  // ===================================================================
  describe("D. D4 — the same question at every credential-installation edge", function () {
    it("D1 rotateCredential, ARMED floor — the incoming key is judged by the attestor's OFF-CHAIN check: honest refuses malformed and admits real; blind admits malformed", async function () {
      const base = await deployBase("sd8-d1");
      const g = await deployGenesis(base, "sd8-d1", true, REAL_PK);
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      const out = honestLeg(base, REAL_PK, realSign);
      const target = keyOf("sd8-d1-target");

      for (const k of [CONSTRUCTIONS[0]!, CONSTRUCTIONS[5]!]) {
        const r = await outcome(rotateTx(base, v, { cred: v.credKey, outPqLeg: out, outPqKey: REAL_PK, newCred: target, newPq: k.bytes, newPqPop: (pop) => honestAttest(base.attestor, base.verifier, base.chainId, pop, k.bytes, CLAIMED_SIG).payload }));
        expect(r, k.id + " incoming, honest attestor: refused by the incoming possession proof").to.equal("BadSignature");
        expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(REAL_PK));
      }
      // Positive control: a second REAL key rotates in under the honest attestor.
      const target2 = keyOf("sd8-d1-target2");
      expect(
        await outcome(rotateTx(base, v, { cred: v.credKey, outPqLeg: out, outPqKey: REAL_PK, newCred: target2, newPq: REAL2_PK, newPqPop: (pop) => honestAttest(base.attestor, base.verifier, base.chainId, pop, REAL2_PK, real2Sign(pop)).payload })),
      ).to.equal(ADMITTED);
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256(REAL2_PK));

      // CONSTRUCTED_CONTROL: the blind attestor. Same edge, same bytes: the EMPTY key is installed and ARMED.
      const out2 = honestLeg(base, REAL2_PK, real2Sign);
      const target3 = keyOf("sd8-d1-target3");
      expect(
        await outcome(rotateTx(base, v, { cred: target2, outPqLeg: out2, outPqKey: REAL2_PK, newCred: target3, newPq: "0x", newPqPop: (pop) => blindAttest(base.attestor, base.verifier, base.chainId, pop, "0x") })),
        "the chain cannot tell a blind attestation from an honest one",
      ).to.equal(ADMITTED);
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0x"));
      expect(await outcome(spendTx(base, v, target3, honestLegUnsignable(base, "0x"), "0x")), "and the vault is now dead under an honest attestor").to.equal("VerifierDenied");
    });

    it("D2 rotateCredential, DORMANT floor — no verifier is consulted at all: the empty key installs on a preimage alone", async function () {
      const base = await deployBase("sd8-d2");
      const g = await deployGenesis(base, "sd8-d2", false, null);
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      const target = keyOf("sd8-d2-target");
      expect(
        await outcome(rotateTx(base, v, { cred: v.credKey, outPqLeg: NO_PQ_LEG, outPqKey: "0x", newCred: target, newPq: "0x", newPqPop: () => "0x" })),
        "newPqPop is EMPTY and the install lands: the verifier was never asked",
      ).to.equal(ADMITTED);
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0x"));
      expect((await v.vault.securityFloor())[0], "still dormant").to.equal(false);
      // The credential can still repair it while dormant (clear-then-rotate is the recorded escape).
      const target2 = keyOf("sd8-d2-target2");
      expect(await outcome(rotateTx(base, v, { cred: target, outPqLeg: NO_PQ_LEG, outPqKey: "0x", newCred: target2, newPq: REAL_PK, newPqPop: () => "0x" }))).to.equal(ADMITTED);
    });

    it("D3 the ARMING edge (setVerifier false -> true) is a FOURTH site: a dormant empty commitment becomes MANDATORY on a preimage alone, with no verifier call", async function () {
      const base = await deployBase("sd8-d3");
      const g = await deployGenesis(base, "sd8-d3", false, "0x"); // born dormant, already committed to keccak256("")
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      expect(await outcome(spendTx(base, v, v.credKey, NO_PQ_LEG, "0x")), "ECDSA-only spending works while dormant").to.equal(ADMITTED);
      expect(
        await outcome(setVerifierTx(base, v, v.credKey, NO_PQ_LEG, "0x", FLOOR_ML_DSA_65, "0x")),
        "the declaring edge exhibits the preimage and asks the verifier nothing",
      ).to.equal(ADMITTED);
      expect((await v.vault.securityFloor())[0]).to.equal(true);
      expect(await outcome(spendTx(base, v, v.credKey, honestLegUnsignable(base, "0x"), "0x")), "now dead").to.equal("VerifierDenied");
      expect(await outcome(spendTx(base, v, v.credKey, NO_PQ_LEG, "0x")), "and not downgradable back").to.equal("VerifierDenied");
    });

    it("D4 executeRecovery, ARMED floor — one approved request, two attestor conducts: honest refuses the empty key, blind installs it", async function () {
      const base = await deployBase("sd8-d4");
      const g = await deployGenesis(base, "sd8-d4", true, REAL_PK);
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      const fresh = keyOf("sd8-d4-fresh");
      expect(await outcome(initiateTx(base, v, fresh, "0x")), "the quorum may PROPOSE any commitment; the kernel checks nothing about it here").to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(
        await outcome(executeRecoveryTx(v, fresh, "0x", (pop) => honestAttest(base.attestor, base.verifier, base.chainId, pop, "0x", CLAIMED_SIG).payload)),
        "honest attestor: the incoming possession proof cannot be obtained",
      ).to.equal("BadSignature");
      expect((await v.vault.recovery())[7], "the request is still live — a refused completion consumes nothing").to.equal(true);
      expect(await outcome(executeRecoveryTx(v, fresh, "0x", (pop) => blindAttest(base.attestor, base.verifier, base.chainId, pop, "0x"))), "blind attestor: installed").to.equal(ADMITTED);
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0x"));
      expect(await v.vault.ecdsaSigner()).to.equal(addrOf(fresh));
    });

    it("D5 executeRecovery, DORMANT floor — the empty key installs on a preimage alone, exactly as at genesis", async function () {
      const base = await deployBase("sd8-d5");
      const g = await deployGenesis(base, "sd8-d5", false, null);
      expect(g.result).to.equal(ADMITTED);
      const v = g.vault!;
      const fresh = keyOf("sd8-d5-fresh");
      expect(await outcome(initiateTx(base, v, fresh, "0x"))).to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await outcome(executeRecoveryTx(v, fresh, "0x", () => "0x")), "newPqPop EMPTY: no verifier consulted").to.equal(ADMITTED);
      expect(await v.vault.pqPublicKeyHash()).to.equal(ethers.keccak256("0x"));
    });
  });

  // ===================================================================
  describe("E. D5 — what each candidate control WOULD discriminate, measured from the rows above (no kernel mutated)", function () {
    it("E1 a FIXED length gate (1952) proves P4 and only P4: it refuses five of eight constructions and admits three that are exactly as dead", function () {
      const malformed = ROWS.filter((r) => r.id !== "REAL-ml-dsa-65");
      expect(malformed, "rows are present").to.have.lengthOf(CONSTRUCTIONS.length);
      const refusedByGate = malformed.filter((r) => !r.lengthValid);
      const admittedByGate = malformed.filter((r) => r.lengthValid);
      expect(refusedByGate.map((r) => r.id).sort()).to.deep.equal(["K0-empty", "K1-one-byte", "K1951-short", "K1953-long", "K32-harness-shape"].sort());
      expect(admittedByGate.map((r) => r.id).sort()).to.deep.equal(["K1952-all-ones", "K1952-all-zero", "K1952-arbitrary"].sort());
      for (const r of admittedByGate) expect(r.honestSpend, r.id + " passes the gate and is still born dead").to.equal("VerifierDenied");
      // And the gate binds the kernel to ONE scheme: every other suite's honest verifier commits 32-byte keys.
      expect(HONEST_FLOOR.pqPublicKeyLength).to.equal(32);
    });

    it("E2 VERIFIER-CLASS-SUPPLIED validation does not exist on the admitted class, and adding it changes the byte-identical production class (SD-11 CLASS ASSURANCE re-established)", function () {
      // Measured in A3: the ABI is exactly {ATTESTED_ML_DSA_65_ALGORITHM_ID, algorithmId, attestor, eip712Domain, verify},
      // and the copy's sha256 equals the production file's. Any new entry point moves both.
      expect(sha256File(GEN1_CLASS_COPY)).to.equal(sha256File(GEN1_CLASS_ORIGINAL));
    });

    it("E3 a GENESIS possession proof against the admitted relation is self-certification: the deployer chooses the attestor, so an empty key passes it", async function () {
      const base = await deployBase("sd8-e3"); // `base.attestor` IS the deployer's choice — the salt of the root-created verifier.
      const verifier = (await ethers.getContractAt("ImmutableAttestationPQCVerifier", base.verifier)) as unknown as ethers.Contract;
      const signer = addrOf(keyOf("sd8-e3-signer"));
      // The digest a genesis PoP would bind (the kernel's own possession digest shape, with the vault address unknown before deployment —
      // the point is unaffected by which digest is used, because the attestor signs whatever digest it is handed).
      const popDigest = ethers.keccak256(abi.encode(["bytes32", "address", "bytes32"], [ethers.id("INCOMING_CREDENTIAL_POSSESSION"), signer, ethers.keccak256("0x")]));
      expect(await verifier.verify(popDigest, "0x", blindAttest(base.attestor, base.verifier, base.chainId, popDigest, "0x")), "deployer-chosen attestor: the empty key 'proves possession'").to.equal(true);
      expect(await verifier.verify(popDigest, "0x", honestAttest(base.attestor, base.verifier, base.chainId, popDigest, "0x", CLAIMED_SIG).payload), "honest attestor: refused").to.equal(false);
      // And the control's price: with NO attestation the relation answers false, so genesis would become impossible while the attestor is unavailable.
      expect(await verifier.verify(popDigest, REAL_PK, NO_ATTESTATION), "attestor liveness becomes a genesis dependency").to.equal(false);
    });
  });

  // ===================================================================
  describe("F. evidence discipline, enforced mechanically", function () {
    it("F1 this reproduction uses no harness superpower", function () {
      const text = fs.readFileSync(THIS_FILE, "utf8");
      for (const forbidden of ["hardhat_setCode", "setStorageAt", "setBalance", "impersonateAccount"]) {
        // The literal appears in this list itself, so the check looks for a CALL.
        expect(text.includes(forbidden + "("), THIS_FILE + " must not call " + forbidden).to.equal(false);
      }
    });
  });
});
