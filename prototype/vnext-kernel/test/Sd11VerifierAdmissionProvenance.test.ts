/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SD-11 CLOSURE — `G-VERIFIER-ADMISSION-PROVENANCE`.
 *
 * THE INVARIANT
 * -------------
 * A verifier may become ACTIVE only if
 *   (1) it belongs to a Generation-1-approved implementation class;
 *   (2) its accepting-relation configuration is immutable after deployment;
 *   (3) that fact is mechanically attributable rather than documentary;
 *   (4) every path that can change the active verifier applies the same check.
 *
 * THE MECHANISM UNDER TEST — provenance by construction, not approval by an administrator
 * ------------------------------------------------------------------------------------
 *   - `ImmutableAttestationVerifierFactoryPrototype` can create exactly ONE class,
 *     `ImmutableAttestationPQCVerifier` (a byte-identical copy of the repository's
 *     contracts/verifiers/ImmutableAttestationPQCVerifier.sol), and records
 *     `isAdmissibleVerifier[v] = true` in the same function that creates `v`. It has no
 *     owner, no setter and no other writer.
 *   - `VaultKernelFactoryPrototype` binds that root ONCE, at its own construction, and copies
 *     it into every clone's immutable args beside the generation.
 *   - the kernel reads the root out of its OWN runtime code and consults it at `initialize`,
 *     `setVerifier` and `initiateRecovery` — the three sites whose values can later be
 *     written to `pqVerifier`.
 *
 * EVIDENCE LABELS (inherited from lane SD-11, and repeated where they matter)
 *   REACHABLE            a named principal calls a real function on a really deployed contract.
 *   CONSTRUCTED_CONTROL  built only to test whether the CONTROL detects a mechanism.
 *   COUNTERFEIT          built to impersonate provenance; never evidence about a repository verifier.
 * NO `setCode`, NO `setStorageAt`: every artifact below is created by an ordinary transaction.
 *
 * WHAT THIS FILE DOES NOT CLAIM
 *   - That an admissible verifier's ATTESTOR is trustworthy. Which attestor a vault trusts is
 *     still an authorised admission decision (genesis cut 0, setVerifier cut 2, recovery cut k);
 *     Generation 1 guarantees only that the decision cannot be revised later without a new,
 *     kernel-visible admission.
 *   - Anything about key well-formedness or proof of possession (SD-8 is untouched).
 *   - Anything about the ZK/SP1 path, which Generation 1 does not admit.
 *
 * WRITTEN RED FIRST, against the unchanged kernel.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ethers, networkHelpers } from "./connection.js";
import { compileSources, productionSource, type Deployable } from "./sd11-verifier-compile.js";
import { DESTRUCTIBLE_VERIFIER, DUAL_RELATION_VERIFIER, VERIFIER_PROXY } from "./sd11-verifier-sources.js";
import { compileDeployable, type DeployableMutant } from "../stateful/mutants.js";
import { compileMutatedKernel, replaceWithinFunction } from "../authority/mutation-harness.js";
import { findContract, type AstNode, type CompiledSources } from "../authority/ast.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  digestOf,
  floorTuple,
  keyOf,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
} from "../stateful/world.js";

const abi = ethers.AbiCoder.defaultAbiCoder();
const DAY = 24 * 60 * 60;
const ZERO = "0x0000000000000000000000000000000000000000";
const ADMITTED = "ADMITTED";

/** ML-DSA-65 shapes. Non-authoritative metadata since SD5-I; used so the vault looks like the intended scheme. */
const FLOOR: Floor = { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 1952, pqSignatureLength: 3309 };

const ATTESTED_ALGORITHM_ID = ethers.id("ATTESTED-ML-DSA-65");
const EIP712_DOMAIN_TYPEHASH = ethers.id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
);
const ATTESTATION_TYPEHASH = ethers.id(
  "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)",
);

const ARTIFACTS = path.join("prototype", "vnext-kernel", "artifacts", "prototype", "vnext-kernel", "contracts");
const GEN1_CLASS_COPY = "prototype/vnext-kernel/contracts/verifiers/ImmutableAttestationPQCVerifier.sol";
const GEN1_CLASS_ORIGINAL = "contracts/verifiers/ImmutableAttestationPQCVerifier.sol";
const GEN1_INTERFACE_COPY = "prototype/vnext-kernel/contracts/IPQCVerifier.sol";
const GEN1_INTERFACE_ORIGINAL = "contracts/IPQCVerifier.sol";
const GEN1_ROOT_SOURCE = "prototype/vnext-kernel/contracts/ImmutableAttestationVerifierFactoryPrototype.sol";

/**
 * COUNTERFEIT (M5-B). Claims Generation-1 membership IN THE ROOT'S OWN ABI, reports the admitted
 * class's algorithm id and exposes an attestor getter — every self-description a naive admission
 * rule could consult. It accepts everything.
 */
const SELF_ASSERTED_VERIFIER = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sd11SelfAssertedVerifier {
    bytes32 public constant ATTESTED_ML_DSA_65_ALGORITHM_ID = keccak256("ATTESTED-ML-DSA-65");
    address public immutable attestor;

    constructor(address attestor_) {
        attestor = attestor_;
    }

    function algorithmId() external pure returns (bytes32) {
        return ATTESTED_ML_DSA_65_ALGORITHM_ID;
    }

    function isAdmissibleVerifier(address) external pure returns (bool) {
        return true;
    }

    function verify(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
`;

/**
 * COUNTERFEIT (M5-C). The Generation-1 root's ABI and event, byte for byte, creating the
 * dual-relation verifier instead of the admitted class and "approving" what it creates.
 */
const COUNTERFEIT_ROOT = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "sd11/DualRelationVerifier.sol";

contract Sd11CounterfeitVerifierFactory {
    mapping(address => bool) public isAdmissibleVerifier;

    event VerifierDeployed(address indexed verifier, address indexed attestor);

    function deployVerifier(address attestor) external returns (address verifier) {
        verifier = address(new Sd11DualRelationVerifier());
        isAdmissibleVerifier[verifier] = true;
        emit VerifierDeployed(verifier, attestor);
    }
}
`;

const sha256File = (p: string): string => createHash("sha256").update(fs.readFileSync(p)).digest("hex");

/** Deterministic filler: a tracked reproduction may not depend on a random draw. */
function deterministicBytes(label: string, length: number): string {
  let out = "0x";
  let block = ethers.id(label);
  while (ethers.dataLength(out) < length) {
    out = ethers.concat([out, block]);
    block = ethers.keccak256(block);
  }
  return ethers.dataSlice(out, 0, length);
}

/**
 * An `ImmutableAttestationPQCVerifier` payload for `digest`, signed by `attestor`, naming
 * `verifierAddress`. Computed from the typehashes rather than read back from the contract, so the
 * oracle is independent of the implementation it judges.
 */
function attest(
  attestor: ethers.SigningKey,
  verifierAddress: string,
  chainId: bigint,
  digest: string,
  publicKey: string,
): string {
  const publicKeyHash = ethers.keccak256(publicKey);
  const pqSignatureHash = ethers.id("the-ml-dsa-signature-the-attestor-checked");
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

/** The dual-relation fixture's forgeable WEAK witness: computable from public data alone. */
function weakWitness(digest: string, publicKey: string): string {
  const tag = ethers.solidityPackedKeccak256(["bytes32", "bytes"], [digest, publicKey]);
  return ethers.concat([ethers.dataSlice(tag, 0, 2), ethers.zeroPadValue("0x00", 63)]);
}

let KERNEL_IFACE: ethers.Interface;

/**
 * The kernel error a refusal carried, OBSERVED. A factory-routed genesis bubbles the kernel's
 * revert through an ABI that does not declare it, so the raw data is decoded against the kernel
 * interface rather than trusted to arrive pre-parsed.
 */
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

/** Strips the trailing CBOR metadata, which is data rather than code. */
function stripMetadata(runtimeHex: string): Buffer {
  const b = Buffer.from(runtimeHex.slice(2), "hex");
  if (b.length < 2) return b;
  const metaLen = b.readUInt16BE(b.length - 2);
  return metaLen + 2 <= b.length ? b.subarray(0, b.length - 2 - metaLen) : b;
}

interface OpcodeCensus {
  SSTORE: number;
  SLOAD: number;
  CALL: number;
  CALLCODE: number;
  DELEGATECALL: number;
  STATICCALL: number;
  CREATE: number;
  CREATE2: number;
  SELFDESTRUCT: number;
}

/**
 * A LINEAR SWEEP of executable positions — the decoding the EVM itself uses for JUMPDEST
 * analysis, so any instruction that can ever execute is counted and PUSH data never is.
 * Absence of an opcode here is therefore absence of the capability, not an inference.
 */
function opcodeCensus(runtimeHex: string): OpcodeCensus {
  const code = stripMetadata(runtimeHex);
  const c: Record<number, number> = {};
  for (let i = 0; i < code.length; i++) {
    const op = code[i]!;
    c[op] = (c[op] ?? 0) + 1;
    if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
  }
  const n = (op: number) => c[op] ?? 0;
  return {
    SSTORE: n(0x55),
    SLOAD: n(0x54),
    CALL: n(0xf1),
    CALLCODE: n(0xf2),
    DELEGATECALL: n(0xf4),
    STATICCALL: n(0xfa),
    CREATE: n(0xf0),
    CREATE2: n(0xf5),
    SELFDESTRUCT: n(0xff),
  };
}

/** Zeroes every immutable range the compiler reported, so per-instance values drop out of a code comparison. */
function maskImmutables(runtimeHex: string, refs: Record<string, { start: number; length: number }[]>): string {
  const b = Buffer.from(runtimeHex.slice(2), "hex");
  for (const ranges of Object.values(refs)) for (const r of ranges) b.fill(0, r.start, r.start + r.length);
  return "0x" + b.toString("hex");
}

function readArtifact(file: string, name: string): { abi: unknown[]; bytecode: string; deployedBytecode: string; immutableReferences?: Record<string, { start: number; length: number }[]> } {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACTS, file, name + ".json"), "utf8"));
}

/** Initcode that returns `runtimeHex` VERBATIM — an ordinary deployment of code copied from elsewhere. */
function verbatimInitcode(runtimeHex: string): string {
  const len = ethers.dataLength(runtimeHex);
  const l = ethers.toBeHex(len, 2).slice(2);
  // PUSH2 len  PUSH1 0x0e  PUSH1 0  CODECOPY  PUSH2 len  PUSH1 0  RETURN  <runtime>
  return "0x61" + l + "600e6000396" + "1" + l + "6000f3" + runtimeHex.slice(2);
}

// =====================================================================
// THE WRITE CENSUS — path completeness from the compiler's own AST, never from text.
// =====================================================================

interface KernelWriteCensus {
  pqVerifierWriters: { fn: string; value: string; src: number }[];
  recoveryStructWriters: { fn: string; proposedVerifier: string; src: number }[];
  recoveryMemberWriters: { fn: string; member: string }[];
  recoveryDeleters: string[];
  admissionChecks: { fn: string; argument: string; src: number }[];
  assemblyStorageWriters: string[];
  executeRecoveryReadsRecovery: boolean;
}

const exprText = (e: AstNode): string =>
  e?.nodeType === "Identifier" ? e.name : e?.nodeType === "MemberAccess" ? exprText(e.expression) + "." + e.memberName : String(e?.nodeType);
const srcStart = (n: AstNode): number => Number(String(n.src).split(":")[0]);

function visit(node: AstNode, f: (n: AstNode) => void): void {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const x of node) visit(x, f);
    return;
  }
  if (typeof node.nodeType === "string") f(node);
  for (const [k, v] of Object.entries(node)) if (k !== "src" && v !== null && typeof v === "object") visit(v, f);
}

function kernelWriteCensus(overrides: Readonly<Record<string, string>> = {}): KernelWriteCensus {
  const out = compileMutatedKernel(overrides);
  if (!out.ok) throw new Error("kernel AST compile failed:\n" + out.errors.join("\n"));
  const compiled: CompiledSources = out.compiled;
  const kernel = findContract(compiled, "VaultKernelPrototype");
  const stateVar = (name: string): number =>
    (kernel.nodes as AstNode[]).find((n) => n.nodeType === "VariableDeclaration" && n.stateVariable && n.name === name)!.id;
  const PQ_VERIFIER = stateVar("pqVerifier");
  const RECOVERY = stateVar("recovery");

  const census: KernelWriteCensus = {
    pqVerifierWriters: [],
    recoveryStructWriters: [],
    recoveryMemberWriters: [],
    recoveryDeleters: [],
    admissionChecks: [],
    assemblyStorageWriters: [],
    executeRecoveryReadsRecovery: false,
  };
  for (const fn of (kernel.nodes as AstNode[]).filter((n) => n.nodeType === "FunctionDefinition" || n.nodeType === "ModifierDefinition")) {
    const name: string = fn.name || fn.kind;
    visit(fn.body, (n) => {
      if (n.nodeType === "Assignment") {
        const lhs = n.leftHandSide;
        if (lhs.nodeType === "Identifier" && lhs.referencedDeclaration === PQ_VERIFIER) {
          census.pqVerifierWriters.push({ fn: name, value: exprText(n.rightHandSide), src: srcStart(n) });
        }
        if (lhs.nodeType === "Identifier" && lhs.referencedDeclaration === RECOVERY) {
          const rhs = n.rightHandSide;
          const idx = (rhs.names ?? []).indexOf("proposedVerifier");
          census.recoveryStructWriters.push({ fn: name, proposedVerifier: idx >= 0 ? exprText(rhs.arguments[idx]) : "UNKNOWN", src: srcStart(n) });
        }
        if (lhs.nodeType === "MemberAccess" && lhs.expression?.referencedDeclaration === RECOVERY) {
          census.recoveryMemberWriters.push({ fn: name, member: lhs.memberName });
        }
      }
      if (n.nodeType === "UnaryOperation" && n.operator === "delete" && n.subExpression?.referencedDeclaration === RECOVERY) {
        census.recoveryDeleters.push(name);
      }
      if (n.nodeType === "FunctionCall" && n.expression?.nodeType === "Identifier" && n.expression.name === "_requireAdmissibleVerifier") {
        census.admissionChecks.push({ fn: name, argument: exprText(n.arguments[0]), src: srcStart(n) });
      }
      if (n.nodeType === "InlineAssembly" && JSON.stringify(n.AST ?? {}).includes('"name":"sstore"')) {
        census.assemblyStorageWriters.push(name);
      }
      if (
        name === "executeRecovery" &&
        n.nodeType === "VariableDeclarationStatement" &&
        n.declarations?.[0]?.name === "r" &&
        n.initialValue?.referencedDeclaration === RECOVERY
      ) {
        census.executeRecoveryReadsRecovery = true;
      }
    });
  }
  return census;
}

// =====================================================================
// THE WORLD — one Generation-1 root, one kernel factory bound to an authority, one vault.
// =====================================================================

interface Genesis {
  signer: string;
  pqKeyHash: string;
  verifier: string;
  threshold: number;
  guardians: string[];
  guardianIsContract: boolean[];
  floor: [boolean, number, number, number];
}

interface Gen1World {
  readonly label: string;
  readonly chainId: bigint;
  readonly deployer: ethers.Signer;
  /** This world's Generation-1 verifier provenance root. */
  readonly root: ethers.Contract;
  /** The authority the KERNEL FACTORY binds — the root, unless a test deliberately overrides it. */
  readonly authority: string;
  readonly implAddress: string;
  readonly factory: ethers.Contract;
  readonly vault: ethers.Contract;
  readonly vaultAddress: string;
  readonly credKey: ethers.SigningKey;
  readonly pqPublicKey: string;
  /** Attests for the genesis verifier. */
  readonly attestor: ethers.SigningKey;
  readonly verifier: string;
  readonly gKeys: ethers.SigningKey[];
  readonly genesis: Genesis;
  readonly recipient: string;
}

interface WorldOptions {
  /** "root" (default) binds this world's own root; "ungated" binds the pre-lane fixture; an address binds that. */
  authority?: "root" | "ungated" | string;
  genesisVerifier?: string;
  impl?: DeployableMutant;
  rootOverride?: Deployable;
}

async function deployContract(unit: { abi: unknown[]; bytecode: string }, args: unknown[] = []): Promise<ethers.Contract> {
  const [deployer] = await ethers.getSigners();
  const factory = new ethers.ContractFactory(unit.abi as ethers.InterfaceAbi, unit.bytecode, deployer);
  const c = await factory.deploy(...args);
  await c.waitForDeployment();
  return c as unknown as ethers.Contract;
}

async function deployRoot(override?: Deployable): Promise<ethers.Contract> {
  if (override !== undefined) return deployContract(override);
  const F = await ethers.getContractFactory("ImmutableAttestationVerifierFactoryPrototype");
  const f = await F.deploy();
  await f.waitForDeployment();
  return f as unknown as ethers.Contract;
}

/** A verifier created BY a root — the only kind of provenance Generation 1 recognises. */
async function rootVerifier(root: ethers.Contract, attestor: ethers.SigningKey): Promise<string> {
  const who = addrOf(attestor);
  const created = (await root.deployVerifier.staticCall(who)) as string;
  await (await root.deployVerifier(who)).wait();
  return created;
}

async function deployUngated(): Promise<string> {
  const F = await ethers.getContractFactory("UngatedVerifierAuthority");
  const f = await F.deploy();
  await f.waitForDeployment();
  return f.getAddress();
}

async function gen1World(label: string, opts: WorldOptions = {}): Promise<Gen1World> {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const root = await deployRoot(opts.rootOverride);
  const authority =
    opts.authority === undefined || opts.authority === "root"
      ? await root.getAddress()
      : opts.authority === "ungated"
        ? await deployUngated()
        : opts.authority;

  const credKey = keyOf(label + "-cred");
  const attestor = keyOf(label + "-attestor");
  const pqPublicKey = deterministicBytes(label + "-ml-dsa-65-public-key", FLOOR.pqPublicKeyLength);
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  const verifier = opts.genesisVerifier ?? (await rootVerifier(root, attestor));

  const Impl = opts.impl
    ? new ethers.ContractFactory(opts.impl.abi as ethers.InterfaceAbi, opts.impl.bytecode, deployer)
    : await ethers.getContractFactory("VaultKernelPrototype", deployer);
  const impl = await Impl.deploy();
  await impl.waitForDeployment();
  const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
  const factory = (await Factory.deploy(await impl.getAddress(), 1, authority)) as unknown as ethers.Contract;
  await factory.waitForDeployment();

  const genesis: Genesis = {
    signer: addrOf(credKey),
    pqKeyHash: ethers.keccak256(pqPublicKey),
    verifier,
    threshold: 2,
    guardians: gKeys.map(addrOf),
    guardianIsContract: [false, false, false],
    floor: floorTuple(FLOOR),
  };
  const salt = ethers.id(label + "-vault");
  const vaultAddress = (await factory.predictVault(salt, genesis)) as string;
  await (await factory.deployVault(salt, genesis, pqPublicKey)).wait();
  const vault = (await ethers.getContractAt("VaultKernelPrototype", vaultAddress, deployer)) as unknown as ethers.Contract;
  await (await deployer.sendTransaction({ to: vaultAddress, value: ethers.parseEther("10") })).wait();

  return {
    label,
    chainId,
    deployer,
    root,
    authority,
    implAddress: await impl.getAddress(),
    factory,
    vault,
    vaultAddress,
    credKey,
    pqPublicKey,
    attestor,
    verifier,
    gKeys,
    genesis,
    recipient: addrOf(keyOf(label + "-recipient")),
  };
}

// =====================================================================
// TRANSACTIONS — every digest mirrored independently of the kernel.
// =====================================================================

const kernelDigest = (w: Gen1World, actionType: string, authorityGeneration: bigint, params: string, domain: number, nonce: bigint): string =>
  digestOf({ chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n, actionType, authorityGeneration, params, domain, nonce, deadline: FAR_DEADLINE });

const quorum = (w: Gen1World, d: string) => ({
  members: w.genesis.guardians,
  isContract: w.genesis.guardianIsContract,
  attestingIndices: [0, 1],
  attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
});

async function spendAs(w: Gen1World, cred: ethers.SigningKey, pqPublicKey: string, attestor: ethers.SigningKey, verifier: string) {
  const amount = ethers.parseEther("1");
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = kernelDigest(w, ACTION.SPEND, gen, spendParams(w.recipient, amount), DOMAIN.SPEND, nonce);
  return w.vault.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(cred, d), attest(attestor, verifier, w.chainId, d, pqPublicKey), pqPublicKey);
}

/** A fully HYBRID-authorised setVerifier: the credential signs, the CURRENT verifier's attestor attests. */
async function setVerifierTx(w: Gen1World, next: string, attestor: ethers.SigningKey, current: string) {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = kernelDigest(w, ACTION.SET_VERIFIER, gen, setVerifierParams(next, FLOOR), DOMAIN.CREDENTIAL, nonce);
  return w.vault.setVerifier(next, floorTuple(FLOOR), nonce, FAR_DEADLINE, sign(w.credKey, d), attest(attestor, current, w.chainId, d, w.pqPublicKey), w.pqPublicKey);
}

async function setPolicyTx(w: Gen1World, policy: string) {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const d = kernelDigest(w, ACTION.SET_POLICY, gen, setPolicyParams(policy), DOMAIN.CREDENTIAL, nonce);
  return w.vault.setPolicy(policy, nonce, FAR_DEADLINE, sign(w.credKey, d), attest(w.attestor, w.verifier, w.chainId, d, w.pqPublicKey), w.pqPublicKey);
}

async function rotateTx(w: Gen1World, newCred: ethers.SigningKey, newPq: string) {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await w.vault.credentialGeneration()) as bigint;
  const newHash = ethers.keccak256(newPq);
  const params = ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(newCred), newHash]));
  const d = kernelDigest(w, ACTION.ROTATE, gen, params, DOMAIN.CREDENTIAL, nonce);
  const pop = (await w.vault.credentialPossessionDigest(addrOf(newCred), newHash)) as string;
  const change = {
    newSigner: addrOf(newCred),
    newPqKeyHash: newHash,
    newPqKey: newPq,
    newEcdsaPop: sign(newCred, pop),
    newPqPop: attest(w.attestor, w.verifier, w.chainId, pop, newPq),
  };
  return w.vault.rotateCredential(change, nonce, FAR_DEADLINE, sign(w.credKey, d), attest(w.attestor, w.verifier, w.chainId, d, w.pqPublicKey), w.pqPublicKey);
}

async function guardianAct(w: Gen1World, params: string): Promise<{ d: string; nonce: bigint }> {
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  return { d: kernelDigest(w, ACTION.RECOVER, gGen, params, DOMAIN.GUARDIAN, nonce), nonce };
}

async function initiateTx(w: Gen1World, newCred: ethers.SigningKey, newPq: string, proposedVerifier: string) {
  const newHash = ethers.keccak256(newPq);
  const { d, nonce } = await guardianAct(w, recoverParams(addrOf(newCred), newHash, proposedVerifier));
  return w.vault.initiateRecovery(addrOf(newCred), newHash, proposedVerifier, quorum(w, d), nonce, FAR_DEADLINE);
}

async function quorumCancelTx(w: Gen1World) {
  const { d, nonce } = await guardianAct(w, ethers.id("QUORUM_CANCEL_RECOVERY"));
  return w.vault.cancelRecoveryByQuorum(quorum(w, d), nonce, FAR_DEADLINE);
}

async function containTx(w: Gen1World) {
  const { d, nonce } = await guardianAct(w, ethers.id("CONTAIN"));
  return w.vault.enterContainment(quorum(w, d), nonce, FAR_DEADLINE);
}

/** Permissionless completion; `pqPop` supplies the INCOMING possession witness for the proposed verifier. */
async function executeRecoveryTx(w: Gen1World, newCred: ethers.SigningKey, newPq: string, pqPop: (popDigest: string) => string) {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  return w.vault.executeRecovery({
    newSigner: addrOf(newCred),
    newPqKeyHash: ethers.keccak256(newPq),
    newPqKey: newPq,
    newEcdsaPop: sign(newCred, pop),
    newPqPop: pqPop(pop),
  });
}

const VERDICTS: string[] = [];

/**
 * One artifact, the three admission edges, each refusal paired with a positive control on the
 * SAME vault under the SAME authorisation shape — so the only variable that can explain a
 * refusal is the artifact's provenance.
 */
async function expectRefusedAtEveryEdge(label: string, artifact: string): Promise<void> {
  const w = await gen1World(label);
  const legitB = await rootVerifier(w.root, keyOf(label + "-attestor-B"));

  // EDGE 1 — GENESIS (`initialize`, reached through the factory).
  expect(
    await outcome(w.factory.deployVault(ethers.id(label + "-hostile-genesis"), { ...w.genesis, verifier: artifact }, w.pqPublicKey)),
    "GENESIS must refuse the artifact",
  ).to.equal("InadmissibleVerifier");
  expect(
    await outcome(w.factory.deployVault(ethers.id(label + "-legit-genesis"), { ...w.genesis, verifier: legitB }, w.pqPublicKey)),
    "GENESIS positive control: a root-created verifier is admitted",
  ).to.equal(ADMITTED);

  // EDGE 2 — setVerifier, FULLY authorised, so provenance is the only thing left to refuse on.
  expect(await outcome(setVerifierTx(w, artifact, w.attestor, w.verifier)), "setVerifier must refuse the artifact").to.equal(
    "InadmissibleVerifier",
  );
  expect(await w.vault.pqVerifier(), "the active verifier did not move").to.equal(w.verifier);

  // EDGE 3 — recovery, with an honest quorum.
  const newCred = keyOf(label + "-new-cred");
  const newPq = deterministicBytes(label + "-new-pq", FLOOR.pqPublicKeyLength);
  expect(await outcome(initiateTx(w, newCred, newPq, artifact)), "initiateRecovery must refuse the artifact").to.equal(
    "InadmissibleVerifier",
  );
  expect((await w.vault.recovery())[7], "no request exists that executeRecovery could later install").to.equal(false);

  // POSITIVE CONTROLS on the same vault.
  expect(await outcome(initiateTx(w, newCred, newPq, legitB)), "recovery positive control").to.equal(ADMITTED);
  expect(await outcome(setVerifierTx(w, legitB, w.attestor, w.verifier)), "setVerifier positive control").to.equal(ADMITTED);
  expect(await w.vault.pqVerifier()).to.equal(legitB);

  VERDICTS.push(label + ": GENESIS refused, SET_VERIFIER refused, RECOVERY refused (all three controls admitted)");
}

describe("SD-11 closure — G-VERIFIER-ADMISSION-PROVENANCE (M1-M7)", function () {
  this.timeout(900_000);

  let FIX: Map<string, Deployable>;
  const fixture = (name: string): Deployable => {
    const unit = FIX.get(name);
    if (unit === undefined) throw new Error("fixture not compiled: " + name);
    return unit;
  };
  const deployFixture = (name: string, args: unknown[] = []) => deployContract(fixture(name), args);

  before(async function () {
    KERNEL_IFACE = (await ethers.getContractFactory("VaultKernelPrototype")).interface;
    const mutable = productionSource("contracts/verifiers/AttestationPQCVerifier.sol");
    FIX = compileSources({
      [mutable.key]: mutable.content,
      "sd11/DualRelationVerifier.sol": DUAL_RELATION_VERIFIER,
      "sd11/VerifierProxy.sol": VERIFIER_PROXY,
      "sd11/Destructible.sol": DESTRUCTIBLE_VERIFIER,
      "sd11/SelfAssertedVerifier.sol": SELF_ASSERTED_VERIFIER,
      "sd11/CounterfeitVerifierFactory.sol": COUNTERFEIT_ROOT,
    });
  });

  after(function () {
    console.log("\n  G-VERIFIER-ADMISSION-PROVENANCE measured verdicts:");
    for (const line of VERDICTS) console.log("    " + line);
    console.log("");
  });

  // =====================================================================
  // M1 — arbitrary code with no provenance.
  // =====================================================================
  describe("M1 — a contract with code and no verifier provenance", function () {
    it("M1 REFUSED at genesis, setVerifier and recovery — though it has code, which is all the old rule asked for", async function () {
      const Stub = await ethers.getContractFactory("DestinationStub");
      const stub = await Stub.deploy();
      await stub.waitForDeployment();
      const address = await stub.getAddress();
      expect(await ethers.provider.getCode(address), "the artifact has code").to.not.equal("0x");
      await expectRefusedAtEveryEdge("sd11p-m1", address);
    });

    it("M1 PREVIOUS BEHAVIOUR, pinned: bound to the ungated fixture (the pre-lane rule) the same artifact is ADMITTED", async function () {
      const w = await gen1World("sd11p-m1-previous", { authority: "ungated" });
      const Stub = await ethers.getContractFactory("DestinationStub");
      const stub = await Stub.deploy();
      await stub.waitForDeployment();
      expect(await outcome(setVerifierTx(w, await stub.getAddress(), w.attestor, w.verifier))).to.equal(ADMITTED);
      expect(await w.vault.pqVerifier()).to.equal(await stub.getAddress());
      VERDICTS.push("M1 previous behaviour (ungated fixture = the code-length rule): a non-verifier contract is ADMITTED");
    });
  });

  // =====================================================================
  // M2 — SD-11A's dual-relation verifier.
  // =====================================================================
  describe("M2 — the SD-11A dual-relation verifier", function () {
    it("M2 REFUSED at every edge although it has code, the verifier ABI and a working strong relation — and it stays hostile", async function () {
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const address = await dual.getAddress();

      // The three facts that do NOT make an artifact admissible.
      expect(await ethers.provider.getCode(address), "(i) it has code").to.not.equal("0x");
      const verifyFn = (
        fixture("Sd11DualRelationVerifier").abi as { type?: string; name?: string; inputs?: { type: string }[]; outputs?: { type: string }[] }[]
      ).find((e) => e.type === "function" && e.name === "verify")!;
      expect(verifyFn.inputs!.map((i) => i.type), "(ii) it satisfies the kernel's verifier ABI").to.deep.equal(["bytes32", "bytes", "bytes"]);
      expect(verifyFn.outputs!.map((o) => o.type)).to.deep.equal(["bool"]);
      const pq = keyOf("sd11p-m2-pq");
      const key = pqKeyBytes(pq);
      const d = ethers.id("sd11p-m2-digest");
      expect(await dual.verify(d, key, sign(pq, d)), "(iii) its STRONG relation works").to.equal(true);
      expect(await dual.verify(d, key, weakWitness(d, key)), "and its WEAK relation accepts").to.equal(true);

      await expectRefusedAtEveryEdge("sd11p-m2", address);

      // NOT NEUTRALISED: the refusal is at admission; the fixture's hostile semantics are intact.
      expect(await dual.verify(d, key, weakWitness(d, key)), "the forgeable relation is still there").to.equal(true);
      VERDICTS.push("M2 dual-relation verifier: weak leg still accepts; Generation 1 refuses it at all three edges");
    });
  });

  // =====================================================================
  // M3 — SD-11B's reachable mechanism, on the REAL production contract.
  // =====================================================================
  describe("M3 — the REAL mutable AttestationPQCVerifier (SD-11B)", function () {
    it("M3 REFUSED at every edge, and NOT repaired: its owner still moves the attestor afterwards", async function () {
      const mutable = await deployFixture("AttestationPQCVerifier", [addrOf(keyOf("sd11p-m3-attestor-A"))]);
      const address = await mutable.getAddress();
      expect((fixture("AttestationPQCVerifier").abi as { name?: string }[]).map((e) => e.name), "the mutator exists").to.include(
        "updateAttestor",
      );

      await expectRefusedAtEveryEdge("sd11p-m3", address);

      const attestorB = keyOf("sd11p-m3-attestor-B");
      await (await mutable.updateAttestor(addrOf(attestorB))).wait();
      expect(await mutable.attestor(), "SD-11B's mechanism is untouched: the relation still moves in place").to.equal(addrOf(attestorB));
      VERDICTS.push("M3 AttestationPQCVerifier: still MUTABLE (updateAttestor works); Generation 1 refuses it at all three edges");
    });

    it("M3 the refusal is PROVENANCE, not attestor identity: naming the vault's OWN attestor, and accepting its statement today, does not admit it", async function () {
      const w = await gen1World("sd11p-m3-same-attestor");
      const mutable = await deployFixture("AttestationPQCVerifier", [addrOf(w.attestor)]);
      const address = await mutable.getAddress();
      const d = ethers.id("sd11p-m3-probe");
      expect(
        await mutable.verify(d, w.pqPublicKey, attest(w.attestor, address, w.chainId, d, w.pqPublicKey)),
        "functionally equivalent to the admitted verifier RIGHT NOW",
      ).to.equal(true);
      expect(await outcome(setVerifierTx(w, address, w.attestor, w.verifier))).to.equal("InadmissibleVerifier");
      expect(await w.root.isAdmissibleVerifier(address), "the root never created it").to.equal(false);
      expect(await w.root.isAdmissibleVerifier(w.verifier), "control: the root recognises its own creation").to.equal(true);
    });
  });

  // =====================================================================
  // M4 — the Generation-1 class: admissible, and immutable once admitted.
  // =====================================================================
  describe("M4 — the Generation-1 ImmutableAttestationPQCVerifier", function () {
    it("M4 ADMITTED at genesis, setVerifier and recovery — and each admission is LIVE end to end", async function () {
      const w = await gen1World("sd11p-m4-edges");
      expect(await w.vault.pqVerifier()).to.equal(w.verifier);
      expect(await outcome(spendAs(w, w.credKey, w.pqPublicKey, w.attestor, w.verifier)), "GENESIS verifier authorises").to.equal(ADMITTED);

      // setVerifier -> B: B's statements authorise, A's no longer do.
      const attestorB = keyOf("sd11p-m4-attestor-B");
      const vB = await rootVerifier(w.root, attestorB);
      expect(await outcome(setVerifierTx(w, vB, w.attestor, w.verifier))).to.equal(ADMITTED);
      expect(await w.vault.pqVerifier()).to.equal(vB);
      expect(await outcome(spendAs(w, w.credKey, w.pqPublicKey, attestorB, vB))).to.equal(ADMITTED);
      expect(await outcome(spendAs(w, w.credKey, w.pqPublicKey, w.attestor, vB)), "the previous attestor is refused").to.equal("VerifierDenied");

      // recovery -> C: initiated by the quorum, matured, completed with a C-attested possession proof.
      const attestorC = keyOf("sd11p-m4-attestor-C");
      const vC = await rootVerifier(w.root, attestorC);
      const newCred = keyOf("sd11p-m4-new-cred");
      const newPq = deterministicBytes("sd11p-m4-new-pq", FLOOR.pqPublicKeyLength);
      expect(await outcome(initiateTx(w, newCred, newPq, vC))).to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await outcome(executeRecoveryTx(w, newCred, newPq, (pop) => attest(attestorC, vC, w.chainId, pop, newPq)))).to.equal(ADMITTED);
      expect(await w.vault.pqVerifier()).to.equal(vC);
      expect(await outcome(spendAs(w, newCred, newPq, attestorC, vC)), "the recovered credential spends under C").to.equal(ADMITTED);
      VERDICTS.push("M4 Gen-1 ImmutableAttestationPQCVerifier: ADMITTED at genesis, setVerifier and recovery, each live end to end");
    });

    it("M4 NO SUPPORTED OPERATION moves the admitted relation while the active verifier keeps its identity", async function () {
      const w = await gen1World("sd11p-m4-immutable");
      const verifier = await ethers.getContractAt("ImmutableAttestationPQCVerifier", w.verifier);
      const attestorB = keyOf("sd11p-m4-immutable-B");
      type AbiEntry = { type: string; name?: string; stateMutability?: string };

      // (1) ABI — no entry point of the class can write.
      const classAbi = readArtifact("verifiers/ImmutableAttestationPQCVerifier.sol", "ImmutableAttestationPQCVerifier").abi as AbiEntry[];
      const functions = classAbi.filter((e) => e.type === "function");
      expect(functions.length, "non-empty ABI, so the next check is not vacuous").to.be.greaterThan(0);
      expect(
        functions.filter((f) => f.stateMutability !== "view" && f.stateMutability !== "pure").map((f) => f.name),
        "no writing entry point",
      ).to.deep.equal([]);
      expect(classAbi.some((e) => e.type === "fallback" || e.type === "receive"), "no fallback or receive").to.equal(false);

      // (2) BYTECODE — no instruction that can write storage, borrow code, call out with effects, create or destroy.
      const census = opcodeCensus(await ethers.provider.getCode(w.verifier));
      const { SSTORE, DELEGATECALL, CALLCODE, CALL, CREATE, CREATE2, SELFDESTRUCT } = census;
      expect({ SSTORE, DELEGATECALL, CALLCODE, CALL, CREATE, CREATE2, SELFDESTRUCT }).to.deep.equal({
        SSTORE: 0,
        DELEGATECALL: 0,
        CALLCODE: 0,
        CALL: 0,
        CREATE: 0,
        CREATE2: 0,
        SELFDESTRUCT: 0,
      });
      // One READ-ONLY call remains. Its target is stack-supplied (DUP6 GAS STATICCALL), so the bytecode does not name
      // it; the SOURCE attributes it to ECDSA.tryRecover's ecrecover precompile. SOURCE-ATTRIBUTED, not bytecode-proven.
      expect(census.STATICCALL).to.equal(1);

      // (3) THE INSTRUMENT DISCRIMINATES — each mutability class is reported where it exists (CONSTRUCTED_CONTROL).
      const mutable = await deployFixture("AttestationPQCVerifier", [addrOf(w.attestor)]);
      expect(opcodeCensus(await ethers.provider.getCode(await mutable.getAddress())).SSTORE, "mutable attestor => SSTORE").to.be.greaterThan(0);
      const strict = await deployFixture("Sd11StrictImpl");
      const proxy = await deployFixture("Sd11ProxyOwner", [await strict.getAddress()]);
      expect(opcodeCensus(await ethers.provider.getCode(await proxy.getAddress())).DELEGATECALL, "proxy => DELEGATECALL").to.be.greaterThan(0);
      const destructible = await deployFixture("Sd11Destructible");
      expect(
        opcodeCensus(await ethers.provider.getCode(await destructible.getAddress())).SELFDESTRUCT,
        "destructible => SELFDESTRUCT",
      ).to.be.greaterThan(0);

      // (4) THE ROOT HOLDS NO POWER OVER WHAT IT CREATED — one writing function, and it only creates.
      const rootAbi = readArtifact("ImmutableAttestationVerifierFactoryPrototype.sol", "ImmutableAttestationVerifierFactoryPrototype").abi as AbiEntry[];
      expect(
        rootAbi.filter((e) => e.type === "function" && e.stateMutability !== "view" && e.stateMutability !== "pure").map((e) => e.name),
      ).to.deep.equal(["deployVerifier"]);
      expect(rootAbi.some((e) => e.type === "fallback" || e.type === "receive")).to.equal(false);

      // (5) BEHAVIOUR — identity and relation, before and after every other operation the system offers.
      const d = ethers.id("sd11p-m4-relation-probe");
      const probe = async () => ({
        active: (await w.vault.pqVerifier()) as string,
        codehash: ethers.keccak256(await ethers.provider.getCode(w.verifier)),
        attestor: (await verifier.attestor()) as string,
        acceptsA: (await verifier.verify(d, w.pqPublicKey, attest(w.attestor, w.verifier, w.chainId, d, w.pqPublicKey))) as boolean,
        acceptsB: (await verifier.verify(d, w.pqPublicKey, attest(attestorB, w.verifier, w.chainId, d, w.pqPublicKey))) as boolean,
      });
      const before = await probe();
      expect(before.acceptsA, "probe control: A accepted").to.equal(true);
      expect(before.acceptsB, "probe control: B refused").to.equal(false);

      await rootVerifier(w.root, attestorB);
      expect(await outcome(w.root.deployVerifier(addrOf(w.attestor))), "the root cannot re-create at an occupied address").to.not.equal(ADMITTED);
      expect(await outcome(spendAs(w, w.credKey, w.pqPublicKey, w.attestor, w.verifier))).to.equal(ADMITTED);
      expect(await outcome(setPolicyTx(w, ZERO))).to.equal(ADMITTED);
      const nextCred = keyOf("sd11p-m4-immutable-next-cred");
      const nextPq = deterministicBytes("sd11p-m4-immutable-next-pq", FLOOR.pqPublicKeyLength);
      expect(await outcome(rotateTx(w, nextCred, nextPq))).to.equal(ADMITTED);
      expect(await outcome(containTx(w))).to.equal(ADMITTED);

      expect(await probe(), "identity AND relation unchanged across every non-admission operation").to.deep.equal(before);
      VERDICTS.push(
        "M4 admitted verifier: no writing ABI; SSTORE/DELEGATECALL/CALLCODE/CALL/CREATE/CREATE2/SELFDESTRUCT all 0; relation + identity unchanged across root and kernel operations",
      );
    });

    it("M4 EXACT CLASS: what the root creates is the repository's ImmutableAttestationPQCVerifier — source and executable code", async function () {
      // SOURCE — the prototype copies are the production files, byte for byte.
      expect(sha256File(GEN1_CLASS_COPY), "class source byte-identical to production").to.equal(sha256File(GEN1_CLASS_ORIGINAL));
      expect(sha256File(GEN1_INTERFACE_COPY), "interface source byte-identical to production").to.equal(sha256File(GEN1_INTERFACE_ORIGINAL));

      // EXECUTABLE — a root-created instance, immutables masked and metadata stripped, equals the PRODUCTION source
      // compiled at its REAL path by the pinned compiler. Metadata differs only because the source path does.
      const w = await gen1World("sd11p-m4-exact");
      const artifact = readArtifact("verifiers/ImmutableAttestationPQCVerifier.sol", "ImmutableAttestationPQCVerifier");
      expect(Object.keys(artifact.immutableReferences ?? {}).length, "the class carries immutables, so the mask does work").to.be.greaterThan(0);
      const deployed = maskImmutables(await ethers.provider.getCode(w.verifier), artifact.immutableReferences ?? {});
      const production = productionSource(GEN1_CLASS_ORIGINAL);
      const compiled = compileSources({ [production.key]: production.content }).get("ImmutableAttestationPQCVerifier")!;
      expect(stripMetadata(deployed).equals(stripMetadata(compiled.deployedBytecode)), "executable code identical to production").to.equal(true);

      // VACUITY GUARD — the comparison can fail: the mutable class does not match.
      expect(stripMetadata(deployed).equals(stripMetadata(fixture("AttestationPQCVerifier").deployedBytecode))).to.equal(false);
    });
  });

  // =====================================================================
  // M5 — counterfeit provenance. Every identity below is self-asserted or copied.
  // =====================================================================
  describe("M5 — counterfeit provenance", function () {
    it("M5-A the SAME EXTCODEHASH as an admitted verifier, deployed by an ordinary transaction outside the root, is refused", async function () {
      const w = await gen1World("sd11p-m5a-source");
      const runtime = await ethers.provider.getCode(w.verifier);
      const receipt = await (await w.deployer.sendTransaction({ data: verbatimInitcode(runtime) })).wait();
      const counterfeit = receipt!.contractAddress!;
      expect(ethers.keccak256(await ethers.provider.getCode(counterfeit)), "EXTCODEHASH identical, bit for bit").to.equal(ethers.keccak256(runtime));
      const c = await ethers.getContractAt("ImmutableAttestationPQCVerifier", counterfeit);
      expect(await c.attestor(), "identical immutable configuration").to.equal(addrOf(w.attestor));
      const d = ethers.id("sd11p-m5a-probe");
      expect(await c.verify(d, w.pqPublicKey, attest(w.attestor, counterfeit, w.chainId, d, w.pqPublicKey)), "a WORKING member of the class").to.equal(
        true,
      );
      expect(await w.root.isAdmissibleVerifier(counterfeit), "never created by the root").to.equal(false);
      expect(await w.root.isAdmissibleVerifier(w.verifier), "control").to.equal(true);
      // Same vault, same authorisation: only provenance differs between the two addresses.
      expect(await outcome(setVerifierTx(w, counterfeit, w.attestor, w.verifier))).to.equal("InadmissibleVerifier");

      await expectRefusedAtEveryEdge("sd11p-m5a", counterfeit);
      VERDICTS.push("M5-A identical EXTCODEHASH + identical configuration + working relation, no root provenance: REFUSED (a codehash pin would admit it)");
    });

    it("M5-B a verifier that SELF-ASSERTS Generation-1 membership in the root's own ABI is refused", async function () {
      const self = await deployFixture("Sd11SelfAssertedVerifier", [addrOf(keyOf("sd11p-m5b-attestor"))]);
      const address = await self.getAddress();
      expect(await self.isAdmissibleVerifier(address), "it claims admissibility").to.equal(true);
      expect(await self.algorithmId(), "it reports the admitted class's algorithm id").to.equal(ATTESTED_ALGORITHM_ID);

      await expectRefusedAtEveryEdge("sd11p-m5b", address);
      VERDICTS.push("M5-B self-asserted membership (isAdmissibleVerifier() = true, matching algorithmId, attestor getter): REFUSED");
    });

    it("M5-C a COUNTERFEIT ROOT with the real root's exact ABI approves nothing for a Generation-1 vault", async function () {
      const w = await gen1World("sd11p-m5c");
      const fake = await deployFixture("Sd11CounterfeitVerifierFactory");
      const approved = (await fake.deployVerifier.staticCall(addrOf(w.attestor))) as string;
      await (await fake.deployVerifier(addrOf(w.attestor))).wait();
      expect(await fake.isAdmissibleVerifier(approved), "the counterfeit approves its own creation").to.equal(true);

      const signatures = (unitAbi: unknown[]) =>
        new ethers.Interface(unitAbi as ethers.InterfaceAbi).fragments
          .filter((f) => f.type === "function" || f.type === "event")
          .map((f) => (f as ethers.FunctionFragment).format("sighash"))
          .sort();
      const realAbi = readArtifact("ImmutableAttestationVerifierFactoryPrototype.sol", "ImmutableAttestationVerifierFactoryPrototype").abi;
      expect(signatures(fixture("Sd11CounterfeitVerifierFactory").abi), "ABI and event parity with the real root").to.deep.equal(signatures(realAbi));

      expect(await outcome(setVerifierTx(w, approved, w.attestor, w.verifier))).to.equal("InadmissibleVerifier");
      const newPq = deterministicBytes("sd11p-m5c-new-pq", FLOOR.pqPublicKeyLength);
      expect(await outcome(initiateTx(w, keyOf("sd11p-m5c-new-cred"), newPq, approved))).to.equal("InadmissibleVerifier");

      // THE ROOT IS READ FROM THE VAULT'S OWN CODE — and it is the real one.
      const args = (await w.vault.genesisCommitments()) as string;
      expect(ethers.dataLength(args), "generation || root").to.equal(28);
      expect(ethers.dataSlice(args, 0, 8)).to.equal("0x0000000000000001");
      expect(ethers.getAddress(ethers.dataSlice(args, 8, 28))).to.equal(await w.root.getAddress());

      // WHERE a counterfeit root could matter at all: a clone created against it, which is a DIFFERENT identity.
      const Raw = await ethers.getContractFactory("RawCloner");
      const raw = await Raw.deploy();
      await raw.waitForDeployment();
      const salt = ethers.id("sd11p-m5c-identity");
      const argsFor = (root: string) => ethers.solidityPacked(["uint64", "address"], [1, root]);
      const realClone = await raw.cloneWithArgs.staticCall(w.implAddress, argsFor(await w.root.getAddress()), salt);
      const fakeClone = await raw.cloneWithArgs.staticCall(w.implAddress, argsFor(await fake.getAddress()), salt);
      expect(fakeClone, "same implementation, same creator, same salt: the ROOT alone moves the address").to.not.equal(realClone);
      VERDICTS.push("M5-C counterfeit root with identical ABI: its approvals REFUSED; a vault's root lives in its code and is part of its address");
    });

    it("M5-D the binding cannot move: no admission transition rewrites the clone's code, so each check reads the root bound at creation", async function () {
      const w = await gen1World("sd11p-m5d");
      const vaultCode = async () => ethers.keccak256(await ethers.provider.getCode(w.vaultAddress));
      const codeBefore = await vaultCode();
      const argsBefore = (await w.vault.genesisCommitments()) as string;
      expect(await w.factory.verifierAuthority(), "the factory's one-shot binding").to.equal(await w.root.getAddress());
      const factoryAbi = readArtifact("VaultKernelFactoryPrototype.sol", "VaultKernelFactoryPrototype").abi as { type: string; name?: string; stateMutability?: string }[];
      expect(
        factoryAbi.filter((e) => e.type === "function" && e.stateMutability !== "view" && e.stateMutability !== "pure").map((e) => e.name),
        "the factory has no setter",
      ).to.deep.equal(["deployVault"]);

      const attestorB = keyOf("sd11p-m5d-B");
      const vB = await rootVerifier(w.root, attestorB);
      expect(await outcome(setVerifierTx(w, vB, w.attestor, w.verifier))).to.equal(ADMITTED);
      const attestorC = keyOf("sd11p-m5d-C");
      const vC = await rootVerifier(w.root, attestorC);
      const newCred = keyOf("sd11p-m5d-new-cred");
      const newPq = deterministicBytes("sd11p-m5d-new-pq", FLOOR.pqPublicKeyLength);
      expect(await outcome(initiateTx(w, newCred, newPq, vC))).to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await outcome(executeRecoveryTx(w, newCred, newPq, (pop) => attest(attestorC, vC, w.chainId, pop, newPq)))).to.equal(ADMITTED);

      expect(await vaultCode(), "the vault's runtime code — and the root inside it — is unchanged").to.equal(codeBefore);
      expect(await w.vault.genesisCommitments()).to.equal(argsBefore);
    });

    it("M5-E with NO root bound a clone admits nothing (fail closed); bound to the root, initialize itself enforces it — no factory involved", async function () {
      const w = await gen1World("sd11p-m5e");
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const legit = await rootVerifier(w.root, keyOf("sd11p-m5e-legit"));
      const Raw = await ethers.getContractFactory("RawCloner");
      const raw = await Raw.deploy();
      await raw.waitForDeployment();

      // (a) NO ROOT: even a root-created verifier is refused — the kernel never defaults to admitting.
      await (await raw.cloneOnly(w.implAddress, ethers.id("sd11p-m5e-bare"))).wait();
      const bare = await ethers.getContractAt("VaultKernelPrototype", await raw.lastClone());
      expect(await outcome(bare.initialize({ ...w.genesis, verifier: legit }, w.pqPublicKey)), "fail closed").to.not.equal(ADMITTED);
      expect(await bare.ecdsaSigner(), "and nothing was initialised").to.equal(ZERO);

      // (b) ROOT BOUND, NO FACTORY: initialize refuses the hostile artifact and admits the legit one on the SAME clone.
      await (await raw.cloneWithArgs(w.implAddress, ethers.solidityPacked(["uint64", "address"], [1, await w.root.getAddress()]), ethers.id("sd11p-m5e-bound"))).wait();
      const bound = await ethers.getContractAt("VaultKernelPrototype", await raw.lastClone());
      expect(
        await outcome(bound.initialize({ ...w.genesis, verifier: await dual.getAddress() }, w.pqPublicKey)),
        "the KERNEL enforces, not the factory",
      ).to.equal("InadmissibleVerifier");
      expect(await outcome(bound.initialize({ ...w.genesis, verifier: legit }, w.pqPublicKey)), "positive control on the same clone").to.equal(ADMITTED);
      expect(await bound.pqVerifier()).to.equal(legit);
      VERDICTS.push("M5-E no root bound: FAIL CLOSED; a factory-free clone bound to the root is enforced by initialize itself");
    });
  });

  // =====================================================================
  // M6 — every path that can change the active verifier applies the same check.
  // =====================================================================
  describe("M6 — admission-path completeness", function () {
    it("M6 AST CENSUS: pqVerifier has exactly three writers, each writing the very value an admission check examined; no alternate writer exists", function () {
      const c = kernelWriteCensus();
      expect(c.pqVerifierWriters.map((x) => x.fn + " <- " + x.value).sort(), "writers of the active verifier").to.deep.equal([
        "executeRecovery <- r.proposedVerifier",
        "initialize <- g.verifier",
        "setVerifier <- verifier",
      ]);
      expect(c.executeRecoveryReadsRecovery, "executeRecovery installs the STORED request").to.equal(true);
      expect(c.recoveryStructWriters.map((x) => x.fn + " <- " + x.proposedVerifier), "the one writer of a proposal").to.deep.equal([
        "initiateRecovery <- proposedVerifier",
      ]);
      expect(c.recoveryMemberWriters.filter((x) => x.member === "proposedVerifier"), "no field-level writer").to.deep.equal([]);
      expect(c.recoveryDeleters, "the only other whole-struct write zeroes it").to.deep.equal(["executeRecovery"]);
      expect(c.assemblyStorageWriters, "no inline assembly writes storage").to.deep.equal([]);

      expect(c.admissionChecks.map((x) => x.fn + "(" + x.argument + ")").sort(), "one check per edge, on the written value").to.deep.equal([
        "initialize(g.verifier)",
        "initiateRecovery(proposedVerifier)",
        "setVerifier(verifier)",
      ]);
      const check = (fn: string) => c.admissionChecks.find((x) => x.fn === fn)!.src;
      expect(check("initialize"), "checked before written").to.be.lessThan(c.pqVerifierWriters.find((x) => x.fn === "initialize")!.src);
      expect(check("setVerifier"), "checked before written").to.be.lessThan(c.pqVerifierWriters.find((x) => x.fn === "setVerifier")!.src);
      expect(check("initiateRecovery"), "checked before proposed").to.be.lessThan(c.recoveryStructWriters[0]!.src);
      VERDICTS.push(
        "M6 census: pqVerifier writers = {initialize, setVerifier, executeRecovery}; proposal writer = {initiateRecovery}; each check is on the written value, before the write",
      );
    });

    it("M6 RECOVERY ADOPTION: a pending proposal cannot be swapped — every route to a new proposedVerifier re-enters the check", async function () {
      const w = await gen1World("sd11p-m6-adoption");
      const attestorC = keyOf("sd11p-m6-C");
      const vC = await rootVerifier(w.root, attestorC);
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const newCred = keyOf("sd11p-m6-new-cred");
      const newPq = deterministicBytes("sd11p-m6-new-pq", FLOOR.pqPublicKeyLength);

      expect(await outcome(initiateTx(w, newCred, newPq, vC))).to.equal(ADMITTED);
      expect(await outcome(initiateTx(w, newCred, newPq, await dual.getAddress())), "a LIVE request is never replaced").to.equal("BadState");
      expect(await outcome(quorumCancelTx(w))).to.equal(ADMITTED);
      expect(await outcome(initiateTx(w, newCred, newPq, await dual.getAddress())), "a FRESH proposal is checked again").to.equal(
        "InadmissibleVerifier",
      );
      expect(await outcome(initiateTx(w, newCred, newPq, vC)), "positive control").to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await outcome(executeRecoveryTx(w, newCred, newPq, (pop) => attest(attestorC, vC, w.chainId, pop, newPq)))).to.equal(ADMITTED);
      expect(await w.vault.pqVerifier()).to.equal(vC);
    });

    it("M6 the UNGATED fixture is the pre-lane rule at all three edges — which is exactly why no Generation-1 factory binds it", async function () {
      const dual = await deployFixture("Sd11DualRelationVerifier");
      const w = await gen1World("sd11p-m6-ungated", { authority: "ungated" });
      const hostile = await dual.getAddress();
      expect(await outcome(w.factory.deployVault(ethers.id("sd11p-m6-ungated-genesis"), { ...w.genesis, verifier: hostile }, w.pqPublicKey))).to.equal(
        ADMITTED,
      );
      const newPq = deterministicBytes("sd11p-m6-ungated-new-pq", FLOOR.pqPublicKeyLength);
      expect(await outcome(initiateTx(w, keyOf("sd11p-m6-ungated-new-cred"), newPq, hostile))).to.equal(ADMITTED);
      expect(await outcome(setVerifierTx(w, hostile, w.attestor, w.verifier))).to.equal(ADMITTED);
      VERDICTS.push("M6 ungated fixture: admits a hostile verifier at genesis, recovery and setVerifier (the pre-lane rule, for legacy suites only)");
    });
  });

  // =====================================================================
  // M7 — mutation guards. A green security assertion proves nothing until removing the property
  // it names turns it red. Kill credit requires OBSERVING the hostile verifier become active.
  // =====================================================================
  describe("M7 — mutation guards", function () {
    const KERNEL_PATH = path.join("prototype", "vnext-kernel", "contracts", "VaultKernelPrototype.sol");
    const kernelSource = (): string => fs.readFileSync(KERNEL_PATH, "utf8");
    const replaceOnce = (source: string, oldText: string, newText: string): string => {
      const n = source.split(oldText).length - 1;
      if (n !== 1) throw new Error("expected exactly one occurrence of the anchor, found " + n);
      return source.replace(oldText, newText);
    };

    const KERNEL_MUTANTS: { id: string; apply: (s: string) => string }[] = [
      {
        id: "M7-K1-initialize-unchecked",
        apply: (s) => replaceWithinFunction(s, "initialize", "        _requireAdmissibleVerifier(g.verifier);\n", ""),
      },
      {
        id: "M7-K2-setVerifier-unchecked",
        apply: (s) => replaceWithinFunction(s, "setVerifier", "        _requireAdmissibleVerifier(verifier);\n", ""),
      },
      {
        id: "M7-K3-initiateRecovery-unchecked",
        apply: (s) => replaceWithinFunction(s, "initiateRecovery", "        _requireAdmissibleVerifier(proposedVerifier);\n", ""),
      },
      {
        // SELF-ASSERTION: the kernel asks the CANDIDATE whether it is admissible instead of the bound root.
        id: "M7-K4-provenance-self-asserted",
        apply: (s) =>
          replaceWithinFunction(s, "_requireAdmissibleVerifier", "IKernelVerifierAuthority(_verifierAuthority())", "IKernelVerifierAuthority(verifier)"),
      },
      {
        // FAIL-OPEN: a clone with no bound root skips the check instead of refusing.
        id: "M7-K5-unbound-root-fails-open",
        apply: (s) =>
          replaceWithinFunction(
            s,
            "_requireAdmissibleVerifier",
            "        if (!IKernelVerifierAuthority(_verifierAuthority()).isAdmissibleVerifier(verifier)) revert InadmissibleVerifier();",
            "        address authority = _verifierAuthority();\n" +
              "        if (authority != address(0) && !IKernelVerifierAuthority(authority).isAdmissibleVerifier(verifier)) {\n" +
              "            revert InadmissibleVerifier();\n" +
              "        }",
          ),
      },
    ];

    const ROOT_MUTANTS: { id: string; apply: (s: string) => string }[] = [
      {
        // The root ALSO approves the address it was handed, so any caller can approve any contract.
        id: "M7-A1-root-also-approves-its-input",
        apply: (s) =>
          replaceWithinFunction(
            s,
            "deployVerifier",
            "isAdmissibleVerifier[verifier] = true;",
            "isAdmissibleVerifier[verifier] = true;\n        isAdmissibleVerifier[attestor] = true;",
          ),
      },
      {
        // The root gains a second, open writer — the "curator" shape, with no curator even needed.
        id: "M7-A2-root-gains-an-open-writer",
        apply: (s) =>
          replaceOnce(
            s,
            "    event VerifierDeployed(address indexed verifier, address indexed attestor);\n",
            "    event VerifierDeployed(address indexed verifier, address indexed attestor);\n\n" +
              "    function register(address candidate) external {\n" +
              "        isAdmissibleVerifier[candidate] = true;\n" +
              "    }\n",
          ),
      },
    ];

    const kernels = new Map<string, DeployableMutant>();
    const roots = new Map<string, Deployable>();
    const kernelMutant = (id: string): DeployableMutant => kernels.get(id)!;
    const kernelMutantSource = (id: string): string => KERNEL_MUTANTS.find((m) => m.id === id)!.apply(kernelSource());

    before(function () {
      this.timeout(900_000);
      for (const m of KERNEL_MUTANTS) {
        // replaceWithinFunction throws unless the anchor occurs EXACTLY once: a mutant that silently became a
        // no-op fails loudly here instead of scoring as a survivor.
        const out = compileDeployable({ "VaultKernelPrototype.sol": m.apply(kernelSource()) });
        if (!out.ok) throw new Error(m.id + " failed to compile:\n" + out.errors.join("\n"));
        kernels.set(m.id, out.kernel);
      }
      const rootSource = fs.readFileSync(GEN1_ROOT_SOURCE, "utf8");
      for (const m of ROOT_MUTANTS) {
        const unit = compileSources({ [GEN1_ROOT_SOURCE]: m.apply(rootSource) }).get("ImmutableAttestationVerifierFactoryPrototype");
        if (unit === undefined) throw new Error(m.id + " produced no root artifact");
        roots.set(m.id, unit);
      }
    });

    it("every M7 mutant applies exactly once and compiles", function () {
      expect(kernels.size).to.equal(KERNEL_MUTANTS.length);
      expect(roots.size).to.equal(ROOT_MUTANTS.length);
    });

    it("M7-K1 initialize UNCHECKED — killed: a dual-relation verifier becomes a genesis verifier", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const live = await gen1World("sd11p-m7-k1-live");
      expect(await outcome(live.factory.deployVault(ethers.id("m7k1"), { ...live.genesis, verifier: hostile }, live.pqPublicKey)), "live refuses").to.equal(
        "InadmissibleVerifier",
      );

      // The mutant world's OWN genesis is legit and succeeded: the mutant is a working kernel (vacuity guard).
      const mut = await gen1World("sd11p-m7-k1-mutant", { impl: kernelMutant("M7-K1-initialize-unchecked") });
      const g = { ...mut.genesis, verifier: hostile };
      const predicted = (await mut.factory.predictVault(ethers.id("m7k1"), g)) as string;
      expect(await outcome(mut.factory.deployVault(ethers.id("m7k1"), g, mut.pqPublicKey))).to.equal(ADMITTED);
      expect(await (await ethers.getContractAt("VaultKernelPrototype", predicted)).pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
      expect(kernelWriteCensus({ "VaultKernelPrototype.sol": kernelMutantSource("M7-K1-initialize-unchecked") }).admissionChecks.map((x) => x.fn), "the census sees it too").to.not.include("initialize");
    });

    it("M7-K2 setVerifier UNCHECKED — killed: the dual-relation verifier is admitted and the ECDSA root ALONE moves value (SD-11A returns)", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const live = await gen1World("sd11p-m7-k2-live");
      expect(await outcome(setVerifierTx(live, hostile, live.attestor, live.verifier)), "live refuses").to.equal("InadmissibleVerifier");

      const mut = await gen1World("sd11p-m7-k2-mutant", { impl: kernelMutant("M7-K2-setVerifier-unchecked") });
      expect(await outcome(setVerifierTx(mut, hostile, mut.attestor, mut.verifier))).to.equal(ADMITTED);
      expect(await mut.vault.pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
      const amount = ethers.parseEther("1");
      const nonce = (await mut.vault.nonces(DOMAIN.SPEND)) as bigint;
      const d = kernelDigest(mut, ACTION.SPEND, (await mut.vault.credentialGeneration()) as bigint, spendParams(mut.recipient, amount), DOMAIN.SPEND, nonce);
      const before = await ethers.provider.getBalance(mut.recipient);
      await (await mut.vault.execute(mut.recipient, amount, nonce, FAR_DEADLINE, sign(mut.credKey, d), weakWitness(d, mut.pqPublicKey), mut.pqPublicKey)).wait();
      expect(await ethers.provider.getBalance(mut.recipient), "the forged witness spends — the cut reduction is back").to.equal(before + amount);
      expect(kernelWriteCensus({ "VaultKernelPrototype.sol": kernelMutantSource("M7-K2-setVerifier-unchecked") }).admissionChecks.map((x) => x.fn)).to.not.include("setVerifier");
    });

    it("M7-K3 initiateRecovery UNCHECKED — killed: a quorum proposal installs the dual-relation verifier at execution", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const newCred = keyOf("sd11p-m7-k3-new-cred");
      const newPq = deterministicBytes("sd11p-m7-k3-new-pq", FLOOR.pqPublicKeyLength);
      const live = await gen1World("sd11p-m7-k3-live");
      expect(await outcome(initiateTx(live, newCred, newPq, hostile)), "live refuses").to.equal("InadmissibleVerifier");

      const mut = await gen1World("sd11p-m7-k3-mutant", { impl: kernelMutant("M7-K3-initiateRecovery-unchecked") });
      expect(await outcome(initiateTx(mut, newCred, newPq, hostile))).to.equal(ADMITTED);
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await outcome(executeRecoveryTx(mut, newCred, newPq, (pop) => weakWitness(pop, newPq)))).to.equal(ADMITTED);
      expect(await mut.vault.pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
      expect(kernelWriteCensus({ "VaultKernelPrototype.sol": kernelMutantSource("M7-K3-initiateRecovery-unchecked") }).admissionChecks.map((x) => x.fn)).to.not.include("initiateRecovery");
    });

    it("M7-K4 provenance SELF-ASSERTED — killed: a verifier that answers for itself becomes a genesis verifier", async function () {
      const self = await (await deployFixture("Sd11SelfAssertedVerifier", [addrOf(keyOf("sd11p-m7-k4-attestor"))])).getAddress();
      const live = await gen1World("sd11p-m7-k4-live");
      expect(await outcome(live.factory.deployVault(ethers.id("m7k4"), { ...live.genesis, verifier: self }, live.pqPublicKey)), "live refuses").to.equal(
        "InadmissibleVerifier",
      );

      // This mutant cannot admit a root-created verifier (the class does not answer the question), so the world is
      // BORN under the counterfeit — and being born is the kill.
      const mut = await gen1World("sd11p-m7-k4-mutant", { impl: kernelMutant("M7-K4-provenance-self-asserted"), genesisVerifier: self });
      expect(await mut.vault.pqVerifier(), "KILL: the self-asserting counterfeit is ACTIVE").to.equal(self);
    });

    it("M7-K5 unbound root FAILS OPEN — killed: a clone with no root admits the dual-relation verifier", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const template = await gen1World("sd11p-m7-k5-template");
      const Raw = await ethers.getContractFactory("RawCloner");
      const raw = await Raw.deploy();
      await raw.waitForDeployment();

      await (await raw.cloneOnly(template.implAddress, ethers.id("m7k5-live"))).wait();
      const liveClone = await ethers.getContractAt("VaultKernelPrototype", await raw.lastClone());
      expect(await outcome(liveClone.initialize({ ...template.genesis, verifier: hostile }, template.pqPublicKey)), "live fails closed").to.not.equal(ADMITTED);

      const mutImpl = await deployContract(kernelMutant("M7-K5-unbound-root-fails-open"));
      await (await raw.cloneOnly(await mutImpl.getAddress(), ethers.id("m7k5-mutant"))).wait();
      const mutClone = await ethers.getContractAt("VaultKernelPrototype", await raw.lastClone());
      expect(await outcome(mutClone.initialize({ ...template.genesis, verifier: hostile }, template.pqPublicKey))).to.equal(ADMITTED);
      expect(await mutClone.pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
    });

    it("M7-A1 root ALSO APPROVES ITS INPUT — killed: any caller approves any contract, and a vault bound to that root admits it", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const live = await gen1World("sd11p-m7-a1-live");
      await (await live.root.deployVerifier(hostile)).wait();
      expect(await live.root.isAdmissibleVerifier(hostile), "the live root approves only what it created").to.equal(false);
      expect(await outcome(setVerifierTx(live, hostile, live.attestor, live.verifier)), "live refuses").to.equal("InadmissibleVerifier");

      const mut = await gen1World("sd11p-m7-a1-mutant", { rootOverride: roots.get("M7-A1-root-also-approves-its-input") });
      await (await mut.root.deployVerifier(hostile)).wait();
      expect(await outcome(setVerifierTx(mut, hostile, mut.attestor, mut.verifier))).to.equal(ADMITTED);
      expect(await mut.vault.pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
    });

    it("M7-A2 root GAINS AN OPEN WRITER — killed: register(hostile) and a vault bound to that root admits it", async function () {
      const hostile = await (await deployFixture("Sd11DualRelationVerifier")).getAddress();
      const live = await gen1World("sd11p-m7-a2-live");
      expect((live.root as unknown as Record<string, unknown>).register, "the live root has no second writer").to.equal(undefined);
      expect(await outcome(setVerifierTx(live, hostile, live.attestor, live.verifier)), "live refuses").to.equal("InadmissibleVerifier");

      const mut = await gen1World("sd11p-m7-a2-mutant", { rootOverride: roots.get("M7-A2-root-gains-an-open-writer") });
      await (await mut.root.register(hostile)).wait();
      expect(await outcome(setVerifierTx(mut, hostile, mut.attestor, mut.verifier))).to.equal(ADMITTED);
      expect(await mut.vault.pqVerifier(), "KILL: the hostile verifier is ACTIVE").to.equal(hostile);
    });
  });
});
