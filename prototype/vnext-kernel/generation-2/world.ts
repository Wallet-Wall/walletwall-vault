/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * The fixture every Generation-2 suite and the stateful campaign drive. It mirrors every digest and
 * reads nothing back from the kernel to decide what to sign (stateful/world.ts gives the reason: a
 * harness that asks the contract what to sign cannot detect a contract that signs the wrong thing).
 *
 * The admitted asset is ALWAYS a local mock. Nothing here names, models or touches a production token,
 * network or address.
 */
import { ethers } from "../test/connection.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  ZERO,
  addrOf,
  digestOf,
  keyOf,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
} from "../stateful/world.js";
import type { CompiledUnit } from "../erc20-spend-plane/compile.js";
import { GENERATION_2, GEN2_FACTORY, GEN2_KERNEL, gen2Unit } from "./compile.js";

export {
  ACTION,
  DAY,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  ZERO,
  addrOf,
  digestOf,
  keyOf,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
};
export type { Floor };

/** Six-decimal units: the shape of the asset class, with no real token named. */
export const UNIT = 1_000_000n;
export const DEFAULT_MINT = 1_000n * UNIT;
export const DESTINATION_GENERATION = 3n;
export const BIND_DELAY_SECONDS = 7 * DAY;
export const RECOVERY_DELAY_SECONDS = 7 * DAY;

/** Gen2ZooToken.Mode, by ordinal. */
export const MODE = {
  VANILLA: 0,
  RETURN_FALSE_NO_MOVE: 1,
  RETURN_TRUE_NO_MOVE: 2,
  SHORT_PAY: 3,
  SENDER_FEE: 4,
  RECIPIENT_FEE: 5,
  DUST_SHORT: 6,
  REVERTS: 7,
  NO_RETURN: 8,
  RETURN_FALSE_BUT_MOVES: 9,
  QUERY_REVERTS_AFTER_TRANSFER: 10,
  QUERY_SHORT_AFTER_TRANSFER: 11,
  QUERY_LIES_EXACT_DEBIT: 12,
} as const;
export type ModeName = keyof typeof MODE;

export interface Deployed {
  readonly contract: ethers.Contract;
  readonly address: string;
  readonly gasUsed: bigint;
}

/** Deploys a compiled unit by an ORDINARY transaction (never setCode). */
export async function deployUnit(unit: CompiledUnit, signer: ethers.Signer, ...args: unknown[]): Promise<Deployed> {
  const factory = new ethers.ContractFactory(unit.abi as ethers.InterfaceAbi, unit.bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  const receipt = await contract.deploymentTransaction()!.wait();
  return {
    contract: contract as unknown as ethers.Contract,
    address: await contract.getAddress(),
    gasUsed: receipt!.gasUsed,
  };
}

/** Deploys a Generation-1 prototype mock from its Hardhat artifact. */
export async function deployArtifact(name: string, signer: ethers.Signer, ...args: unknown[]): Promise<Deployed> {
  const factory = await ethers.getContractFactory(name, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  const receipt = await contract.deploymentTransaction()!.wait();
  return {
    contract: contract as unknown as ethers.Contract,
    address: await contract.getAddress(),
    gasUsed: receipt!.gasUsed,
  };
}

export type VerifierKindG2 = "honest" | "honestB" | "alwaysTrue" | "alwaysFalse" | "reverting";
export type PolicyKindG2 = "none" | "allow" | "deny" | "stateful" | "codeless";

export interface Gen2WorldOptions {
  /** Seed for every key and salt, so a campaign seed plus a label reproduces the world. */
  readonly label: string;
  /**
   * `ungated`: the factory binds UngatedVerifierAuthority, so the mock verifiers stay admissible and the
   * PQ conjunct can be attacked directly. NOT a Generation-2 configuration, and a campaign under it has
   * no power over provenance. `root`: the factory binds the real root, every verifier is a root-created
   * ImmutableAttestationPQCVerifier, and the mocks are the refused adversaries.
   */
  readonly authority?: "ungated" | "root";
  /** Which verifier the vault is born under. */
  readonly verifier?: VerifierKindG2;
  /** Born under an ECDSA-only floor, the custody adjudication's v1 recommendation. */
  readonly ecdsaOnlyFloor?: boolean;
  /** With `ecdsaOnlyFloor`, commit a PQ key anyway: the arming edge is reachable only then. */
  readonly commitPqKey?: boolean;
  readonly mintToVault?: bigint;
  readonly fundEth?: bigint;
  /** Index of the first Hardhat account used (deployer, outsider, recipient are consecutive). */
  readonly signerOffset?: number;
  /** A MUTATED kernel to deploy instead of the candidate. ABI-compatible with the candidate. */
  readonly implOverride?: CompiledUnit;
  /** A MUTATED factory to deploy instead of the candidate's. */
  readonly factoryOverride?: CompiledUnit;
  /** Deploys the same genesis under a second factory bound to a second asset (cross-asset replay). */
  readonly sibling?: boolean;
  /** Use a different admitted asset contract than the zoo token. */
  readonly tokenUnit?: CompiledUnit;
  /**
   * The verifying contract the harness signs for. Only a mutant that changes the domain separator sets
   * it: a mutant whose honest signatures all fail is dead, and a dead mutant proves nothing.
   */
  readonly signingDomainVault?: string;
  /** The recipient honest spend digests name. Only a mutant that stops binding the recipient sets it. */
  readonly signedSpendRecipient?: string;
}

export interface Gen2World {
  readonly opts: {
    label: string;
    verifier: VerifierKindG2;
    ecdsaOnlyFloor: boolean;
    authority: "ungated" | "root";
    commitPqKeyOnEcdsaOnlyFloor: boolean;
  };
  readonly chainId: bigint;
  readonly deployer: ethers.Signer;
  readonly outsider: ethers.Signer;
  readonly recipient: string;
  readonly credKey: ethers.SigningKey;
  readonly pqKey: ethers.SigningKey;
  /** Guardian principals in the STRICTLY ASCENDING order the kernel demands. */
  readonly gKeys: ethers.SigningKey[];
  readonly guardians: string[];
  readonly guardianIsContract: boolean[];
  readonly threshold: bigint;
  readonly spareCred: ethers.SigningKey[];
  readonly sparePq: ethers.SigningKey[];
  readonly implAddress: string;
  readonly factory: ethers.Contract;
  readonly factoryAddress: string;
  readonly vault: ethers.Contract;
  readonly vaultAddress: string;
  /** The address the harness's digests name as verifying contract: the vault, except under a domain mutant. */
  readonly signingDomainVault: string;
  readonly signedSpendRecipient: string | null;
  readonly genesis: Genesis;
  readonly salt: string;
  /** The admitted asset. */
  readonly token: string;
  readonly asset: ethers.Contract;
  /** A second holding nobody admitted. */
  readonly otherToken: string;
  readonly other: ethers.Contract;
  readonly authorityAddress: string;
  /** Present only when the world binds the real root. */
  readonly root: ethers.Contract | null;
  /** Attestor key behind each root-created verifier; empty for an ungated world. */
  readonly attestors: Record<string, ethers.SigningKey>;
  readonly verifiers: Record<VerifierKindG2, string>;
  readonly policies: Record<Exclude<PolicyKindG2, "none">, string>;
  readonly destination: string;
  /** The same contract, for its behaviour lever: Gen2SwitchableDestination. */
  readonly destinationFixture: ethers.Contract;
  readonly destinationCodeHash: string;
  readonly deployGas: { readonly implementation: bigint; readonly factory: bigint; readonly vault: bigint };
  /** Same genesis, second factory, second asset. Present only with `sibling`. */
  readonly sibling: {
    vault: ethers.Contract;
    vaultAddress: string;
    asset: ethers.Contract;
    token: string;
    factoryAddress: string;
  } | null;
}

export interface Genesis {
  signer: string;
  pqKeyHash: string;
  verifier: string;
  threshold: number;
  guardians: string[];
  guardianIsContract: boolean[];
  floor: Floor;
}

/** Deploys a complete Generation-2 world. Every key derives from `label`, so the roster order is reproducible. */
export async function deployGen2World(options: Gen2WorldOptions): Promise<Gen2World> {
  const authorityKind = options.authority ?? "ungated";
  const verifierKind = options.verifier ?? "honest";
  const signers = await ethers.getSigners();
  const offset = options.signerOffset ?? 0;
  const deployer = signers[offset]!;
  const outsider = signers[offset + 1]!;
  const recipient = signers[offset + 2]!.address;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const label = options.label;

  const credKey = keyOf(label + "-cred");
  const pqKey = keyOf(label + "-pq");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  const guardians = gKeys.map(addrOf);
  const guardianIsContract = [false, false, false];
  const threshold = 2n;

  // ---- mock verifiers: admissible only under the ungated fixture, refused adversaries under the root ----
  const mock = async (mode: number): Promise<string> =>
    (await deployArtifact("ConfigurableVerifier", deployer, mode)).address;
  const alwaysTrue = await mock(0);
  const alwaysFalse = await mock(1);
  const reverting = await mock(2);

  let authorityAddress: string;
  let root: ethers.Contract | null = null;
  const attestors: Record<string, ethers.SigningKey> = {};
  let honest: string;
  let honestB: string;
  if (authorityKind === "root") {
    const r = await deployUnit(gen2Unit("ImmutableAttestationVerifierFactoryPrototype"), deployer);
    root = r.contract;
    authorityAddress = r.address;
    // PERMISSIONLESS: the outsider creates both, which is the point of G2-VERIFIER-4.
    const asOutsider = r.contract.connect(outsider) as ethers.Contract;
    const make = async (attestor: ethers.SigningKey): Promise<string> => {
      const at = addrOf(attestor);
      const predicted = (await asOutsider.deployVerifier.staticCall(at)) as string;
      await (await asOutsider.deployVerifier(at)).wait();
      return predicted;
    };
    const attestorA = keyOf(label + "-attestor-a");
    const attestorB = keyOf(label + "-attestor-b");
    honest = await make(attestorA);
    honestB = await make(attestorB);
    attestors[honest.toLowerCase()] = attestorA;
    attestors[honestB.toLowerCase()] = attestorB;
  } else {
    authorityAddress = (await deployArtifact("UngatedVerifierAuthority", deployer)).address;
    honest = (await deployArtifact("EcdsaBackedVerifier", deployer)).address;
    honestB = (await deployArtifact("EcdsaBackedVerifier", deployer)).address;
  }
  const verifiers: Record<VerifierKindG2, string> = { honest, honestB, alwaysTrue, alwaysFalse, reverting };

  const Policy = await ethers.getContractFactory("ConfigurablePolicy", deployer);
  const allow = await Policy.deploy(true);
  await allow.waitForDeployment();
  const deny = await Policy.deploy(false);
  await deny.waitForDeployment();
  const Stateful = await ethers.getContractFactory("StatefulPolicy", deployer);
  const stateful = await Stateful.deploy(600n * UNIT);
  await stateful.waitForDeployment();

  // ---- the admitted asset and the holding nobody admitted: LOCAL MOCKS, always ----
  const tokenUnit = options.tokenUnit ?? gen2Unit("Gen2ZooToken");
  const asset = await deployUnit(tokenUnit, deployer);
  const other = await deployUnit(gen2Unit("Gen2UnsolicitedToken"), deployer);

  const kernelUnit = gen2Unit(GEN2_KERNEL);
  const impl = await deployUnit(options.implOverride ?? kernelUnit, deployer);
  const factoryUnit = options.factoryOverride ?? gen2Unit(GEN2_FACTORY);
  const factory = await deployUnit(factoryUnit, deployer, impl.address, GENERATION_2, authorityAddress, asset.address);

  const ecdsaOnly = options.ecdsaOnlyFloor === true;
  const commitPq = !ecdsaOnly || options.commitPqKey === true;
  const genesis: Genesis = {
    signer: addrOf(credKey),
    pqKeyHash: commitPq ? pqHash(pqKey) : ethers.ZeroHash,
    verifier: verifiers[verifierKind],
    threshold: Number(threshold),
    guardians,
    guardianIsContract,
    floor: ecdsaOnly ? { ...ECDSA_ONLY_FLOOR } : { ...HONEST_FLOOR },
  };
  const salt = ethers.id(label + "-vault");
  const vaultAddress = (await factory.contract.predictVault(salt, genesis)) as string;
  const witness = commitPq ? pqKeyBytes(pqKey) : "0x";
  const deployReceipt = await (await factory.contract.deployVault(salt, genesis, witness)).wait();
  const vault = new ethers.Contract(
    vaultAddress,
    (options.implOverride ?? kernelUnit).abi as ethers.InterfaceAbi,
    deployer,
  );

  const mint = options.mintToVault ?? DEFAULT_MINT;
  if (mint > 0n) await (await asset.contract.mint(vaultAddress, mint)).wait();
  if ((options.fundEth ?? 0n) > 0n)
    await (await deployer.sendTransaction({ to: vaultAddress, value: options.fundEth })).wait();

  const dest = await deployUnit(gen2Unit("Gen2SwitchableDestination"), deployer);

  let sibling: Gen2World["sibling"] = null;
  if (options.sibling) {
    const asset2 = await deployUnit(gen2Unit("Gen2ZooToken"), deployer);
    const factory2 = await deployUnit(
      factoryUnit,
      deployer,
      impl.address,
      GENERATION_2,
      authorityAddress,
      asset2.address,
    );
    const siblingAddress = (await factory2.contract.predictVault(salt, genesis)) as string;
    await (await factory2.contract.deployVault(salt, genesis, witness)).wait();
    const siblingVault = new ethers.Contract(
      siblingAddress,
      (options.implOverride ?? kernelUnit).abi as ethers.InterfaceAbi,
      deployer,
    );
    await (await asset2.contract.mint(siblingAddress, DEFAULT_MINT)).wait();
    sibling = {
      vault: siblingVault,
      vaultAddress: siblingAddress,
      asset: asset2.contract,
      token: asset2.address,
      factoryAddress: factory2.address,
    };
  }

  return {
    opts: {
      label,
      verifier: verifierKind,
      ecdsaOnlyFloor: ecdsaOnly,
      authority: authorityKind,
      commitPqKeyOnEcdsaOnlyFloor: options.commitPqKey === true,
    },
    chainId,
    deployer,
    outsider,
    recipient,
    credKey,
    pqKey,
    gKeys,
    guardians,
    guardianIsContract,
    threshold,
    spareCred: [0, 1, 2].map((i) => keyOf(label + "-spare-cred-" + i)),
    sparePq: [0, 1, 2].map((i) => keyOf(label + "-spare-pq-" + i)),
    implAddress: impl.address,
    factory: factory.contract,
    factoryAddress: factory.address,
    vault,
    vaultAddress,
    signingDomainVault: options.signingDomainVault ?? vaultAddress,
    signedSpendRecipient: options.signedSpendRecipient ?? null,
    genesis,
    salt,
    token: asset.address,
    asset: asset.contract,
    otherToken: other.address,
    other: other.contract,
    authorityAddress,
    root,
    attestors,
    verifiers,
    policies: {
      allow: await allow.getAddress(),
      deny: await deny.getAddress(),
      stateful: await stateful.getAddress(),
      codeless: "0x00000000000000000000000000000000DeaDBeef",
    },
    destination: dest.address,
    destinationFixture: dest.contract,
    destinationCodeHash: ethers.keccak256(await ethers.provider.getCode(dest.address)),
    deployGas: { implementation: impl.gasUsed, factory: factory.gasUsed, vault: deployReceipt!.gasUsed },
    sibling,
  };
}

// =====================================================================
// Attestations: the admitted class's relation, computed from the typehashes rather than read back.
// =====================================================================

const abi = ethers.AbiCoder.defaultAbiCoder();
const EIP712_DOMAIN_TYPEHASH = ethers.id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
);
const ATTESTATION_TYPEHASH = ethers.id(
  "PQCAttestation(bytes32 withdrawalDigest,bytes32 publicKeyHash,bytes32 pqSignatureHash,bytes32 algorithmId,address verifier,uint256 chainId,uint256 deadline)",
);
const ALGORITHM_ID = ethers.id("ATTESTED-ML-DSA-65");

/** The attestor's statement for the root-created class, as the opaque `pqSig` the kernel forwards. */
export function attest(
  attestor: ethers.SigningKey,
  verifier: string,
  chainId: bigint,
  digest: string,
  publicKey: string,
): string {
  const deadline = FAR_DEADLINE;
  const publicKeyHash = ethers.keccak256(publicKey);
  const pqSignatureHash = ethers.id("the-ml-dsa-signature-the-attestor-checked");
  const domain = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [EIP712_DOMAIN_TYPEHASH, ethers.id("AttestationPQCVerifier"), ethers.id("1"), chainId, verifier],
    ),
  );
  const structHash = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256", "uint256"],
      [ATTESTATION_TYPEHASH, digest, publicKeyHash, pqSignatureHash, ALGORITHM_ID, verifier, chainId, deadline],
    ),
  );
  const attestationDigest = ethers.keccak256(ethers.concat(["0x1901", domain, structHash]));
  return abi.encode(
    ["bytes", "uint256", "bytes32", "bytes32"],
    [sign(attestor, attestationDigest), deadline, publicKeyHash, pqSignatureHash],
  );
}

// =====================================================================
// Digests and calls, mirrored, never read back
// =====================================================================

export interface SpendArgs {
  readonly to: string;
  readonly amount: bigint;
  readonly nonce?: bigint;
  readonly deadline?: bigint;
  readonly signer?: ethers.SigningKey;
  readonly from?: ethers.Signer;
  readonly pq?: { readonly sig: string; readonly key: string };
  readonly gasLimit?: bigint;
  readonly credentialGeneration?: bigint;
  /** Sign for THIS vault address instead (cross-vault and cross-asset probes). */
  readonly signForVault?: string;
}

export const currentNonce = async (w: Gen2World, domain: number): Promise<bigint> =>
  (await w.vault.nonces(domain)) as bigint;

export function spendDigest(
  w: Gen2World,
  p: { to: string; amount: bigint; nonce: bigint; deadline?: bigint; credentialGeneration?: bigint; vault?: string },
): string {
  return digestOf({
    chainId: w.chainId,
    vault: p.vault ?? w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType: ACTION.SPEND,
    authorityGeneration: p.credentialGeneration ?? 1n,
    params: spendParams(p.to, p.amount),
    domain: DOMAIN.SPEND,
    nonce: p.nonce,
    deadline: p.deadline ?? FAR_DEADLINE,
  });
}

export function spendCalldata(w: Gen2World, a: SpendArgs & { nonce: bigint }): string {
  const deadline = a.deadline ?? FAR_DEADLINE;
  const digest = spendDigest(w, {
    to: a.to,
    amount: a.amount,
    nonce: a.nonce,
    deadline,
    credentialGeneration: a.credentialGeneration,
    vault: a.signForVault,
  });
  return w.vault.interface.encodeFunctionData("execute", [
    a.to,
    a.amount,
    a.nonce,
    deadline,
    sign(a.signer ?? w.credKey, digest),
    a.pq?.sig ?? "0x",
    a.pq?.key ?? "0x",
  ]);
}

/** Builds, signs and SENDS a spend. An explicit gas limit is REQUIRED for a probe expected to revert. */
export async function sendSpend(w: Gen2World, a: SpendArgs): Promise<ethers.ContractTransactionResponse> {
  const nonce = a.nonce ?? (await currentNonce(w, DOMAIN.SPEND));
  const credentialGeneration = a.credentialGeneration ?? ((await w.vault.credentialGeneration()) as bigint);
  const data = spendCalldata(w, { ...a, nonce, credentialGeneration });
  const signer = a.from ?? w.deployer;
  return signer.sendTransaction({
    to: w.vaultAddress,
    data,
    ...(a.gasLimit !== undefined ? { gasLimit: a.gasLimit } : {}),
  });
}

/** `true` when the transaction settled, `false` when it was refused and mined at status 0. */
export async function settles(send: () => Promise<{ wait: () => Promise<unknown> }>): Promise<boolean> {
  try {
    await (await send()).wait();
    return true;
  } catch {
    return false;
  }
}

export interface QuorumProof {
  members: string[];
  isContract: boolean[];
  attestingIndices: number[];
  attestations: string[];
}

export function quorum(w: Gen2World, digest: string, indices: number[] = [0, 1]): QuorumProof {
  return {
    members: w.guardians,
    isContract: w.guardianIsContract,
    attestingIndices: indices,
    attestations: indices.map((i) => sign(w.gKeys[i]!, digest)),
  };
}

export async function guardianDigest(
  w: Gen2World,
  actionType: string,
  params: string,
  domain: number,
  nonce: bigint,
): Promise<string> {
  const guardianGeneration = (await w.vault.guardianGeneration()) as bigint;
  return digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType,
    authorityGeneration: guardianGeneration,
    params,
    domain,
    nonce,
    deadline: FAR_DEADLINE,
  });
}

/** What a binding's digest commits to: the destination, and the source's credential, plane and safe state as they stand now. */
export async function bindingParams(
  w: Gen2World,
  destination: string,
  codeHash: string,
  generation: bigint,
): Promise<string> {
  const [credentialGeneration, policy, state] = await Promise.all([
    w.vault.credentialGeneration(),
    w.vault.policyEngine(),
    w.vault.effectiveSafeState(),
  ]);
  return ethers.keccak256(
    abi.encode(
      ["address", "bytes32", "uint64", "uint64", "address", "uint8"],
      [destination, codeHash, generation, credentialGeneration, policy, state],
    ),
  );
}

export async function bindCalldata(
  w: Gen2World,
  opts: { destination?: string; codeHash?: string; credential?: ethers.SigningKey } = {},
): Promise<string> {
  const destination = opts.destination ?? w.destination;
  const codeHash = opts.codeHash ?? w.destinationCodeHash;
  const nonce = await currentNonce(w, DOMAIN.MIGRATION);
  const digest = await guardianDigest(
    w,
    ACTION.BIND_MIGRATION,
    await bindingParams(w, destination, codeHash, DESTINATION_GENERATION),
    DOMAIN.MIGRATION,
    nonce,
  );
  return w.vault.interface.encodeFunctionData("bindMigration", [
    [destination, codeHash, DESTINATION_GENERATION],
    quorum(w, digest),
    nonce,
    FAR_DEADLINE,
    sign(opts.credential ?? w.credKey, digest),
  ]);
}

/** Binds the world's destination: guardian quorum AND the credential's ECDSA leg, section 22 D2. */
export async function bindDestination(
  w: Gen2World,
  opts: { destination?: string; codeHash?: string; credential?: ethers.SigningKey; gasLimit?: bigint } = {},
): Promise<ethers.TransactionResponse> {
  const data = await bindCalldata(w, opts);
  return w.deployer.sendTransaction({
    to: w.vaultAddress,
    data,
    ...(opts.gasLimit !== undefined ? { gasLimit: opts.gasLimit } : {}),
  });
}

export async function recoveryCalldata(
  w: Gen2World,
  proposedSigner: string,
  proposedPqKeyHash: string,
  verifier: string,
): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const digest = await guardianDigest(
    w,
    ACTION.RECOVER,
    recoverParams(proposedSigner, proposedPqKeyHash, verifier),
    DOMAIN.GUARDIAN,
    nonce,
  );
  return w.vault.interface.encodeFunctionData("initiateRecovery", [
    proposedSigner,
    proposedPqKeyHash,
    verifier,
    quorum(w, digest),
    nonce,
    FAR_DEADLINE,
  ]);
}

export async function proposeRecovery(
  w: Gen2World,
  proposedSigner: string,
  proposedPqKeyHash: string,
  verifier: string,
  gasLimit?: bigint,
): Promise<ethers.TransactionResponse> {
  const data = await recoveryCalldata(w, proposedSigner, proposedPqKeyHash, verifier);
  return w.deployer.sendTransaction({ to: w.vaultAddress, data, ...(gasLimit !== undefined ? { gasLimit } : {}) });
}

/** A complete incoming-possession bundle for `executeRecovery`, proven against the proposed verifier. */
export async function executeRecoveryCalldata(
  w: Gen2World,
  newCred: ethers.SigningKey,
  newPq: ethers.SigningKey,
  verifier: string,
): Promise<string> {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  const attestor = w.attestors[verifier.toLowerCase()];
  const newPqKey = pqKeyBytes(newPq);
  const newPqPop = attestor ? attest(attestor, verifier, w.chainId, pop, newPqKey) : sign(newPq, pop);
  return w.vault.interface.encodeFunctionData("executeRecovery", [
    { newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey, newEcdsaPop: sign(newCred, pop), newPqPop },
  ]);
}

export async function setVerifierCalldata(
  w: Gen2World,
  verifier: string,
  floor: Floor,
  opts: {
    credential?: ethers.SigningKey;
    pq?: { sig: string; key: string };
    pqFor?: (digest: string) => { sig: string; key: string };
  } = {},
): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credentialGeneration,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const pq = opts.pqFor ? opts.pqFor(digest) : opts.pq;
  return w.vault.interface.encodeFunctionData("setVerifier", [
    verifier,
    floor,
    nonce,
    FAR_DEADLINE,
    sign(opts.credential ?? w.credKey, digest),
    pq?.sig ?? "0x",
    pq?.key ?? "0x",
  ]);
}

export async function setPolicyCalldata(w: Gen2World, policy: string, credential?: ethers.SigningKey): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType: ACTION.SET_POLICY,
    authorityGeneration: credentialGeneration,
    params: setPolicyParams(policy),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.interface.encodeFunctionData("setPolicy", [
    policy,
    nonce,
    FAR_DEADLINE,
    sign(credential ?? w.credKey, digest),
    "0x",
    "0x",
  ]);
}

export async function containmentCalldata(w: Gen2World): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const digest = await guardianDigest(w, ACTION.RECOVER, ethers.id("CONTAIN"), DOMAIN.GUARDIAN, nonce);
  return w.vault.interface.encodeFunctionData("enterContainment", [quorum(w, digest), nonce, FAR_DEADLINE]);
}

/** The PQ leg for `digest`: an attestor's statement under the root's class, a second ECDSA key under the fixture. */
export function pqLegOf(
  w: Gen2World,
  digest: string,
  verifier: string,
  key: ethers.SigningKey,
): { sig: string; key: string } {
  const attestor = w.attestors[verifier.toLowerCase()];
  const bytes = pqKeyBytes(key);
  return { sig: attestor ? attest(attestor, verifier, w.chainId, digest, bytes) : sign(key, digest), key: bytes };
}

/** A spend on an armed floor: both factors, the second from `pqKey` under the vault's live verifier. */
export async function sendArmedSpend(
  w: Gen2World,
  a: SpendArgs & { pqKey?: ethers.SigningKey },
): Promise<ethers.TransactionResponse> {
  const nonce = a.nonce ?? (await currentNonce(w, DOMAIN.SPEND));
  const credentialGeneration = a.credentialGeneration ?? ((await w.vault.credentialGeneration()) as bigint);
  const digest = spendDigest(w, { to: a.to, amount: a.amount, nonce, deadline: a.deadline, credentialGeneration });
  const verifier = (await w.vault.pqVerifier()) as string;
  return sendSpend(w, { ...a, nonce, credentialGeneration, pq: pqLegOf(w, digest, verifier, a.pqKey ?? w.pqKey) });
}

/** A rotation with incoming possession proven by the incoming keys, unless a caller overrides a leg. */
export async function rotateCalldata(
  w: Gen2World,
  newCred: ethers.SigningKey,
  newPq: ethers.SigningKey | null,
  opts: { credential?: ethers.SigningKey; popSigner?: ethers.SigningKey; pq?: { sig: string; key: string } } = {},
): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const newPqKeyHash = newPq ? pqHash(newPq) : ethers.ZeroHash;
  const pop = (await w.vault.credentialPossessionDigest(addrOf(newCred), newPqKeyHash)) as string;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType: ACTION.ROTATE,
    authorityGeneration: credentialGeneration,
    params: ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(newCred), newPqKeyHash]),
    ),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const verifier = (await w.vault.pqVerifier()) as string;
  const change = {
    newSigner: addrOf(newCred),
    newPqKeyHash,
    newPqKey: newPq ? pqKeyBytes(newPq) : "0x",
    newEcdsaPop: sign(opts.popSigner ?? newCred, pop),
    newPqPop: newPq ? pqLegOf(w, pop, verifier, newPq).sig : "0x",
  };
  return w.vault.interface.encodeFunctionData("rotateCredential", [
    change,
    nonce,
    FAR_DEADLINE,
    sign(opts.credential ?? w.credKey, digest),
    opts.pq?.sig ?? "0x",
    opts.pq?.key ?? "0x",
  ]);
}

export async function cancelCalldata(w: Gen2World, credential?: ethers.SigningKey): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: GENERATION_2,
    actionType: ACTION.RECOVER,
    authorityGeneration: credentialGeneration,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.interface.encodeFunctionData("cancelRecovery", [
    nonce,
    FAR_DEADLINE,
    sign(credential ?? w.credKey, digest),
  ]);
}

export async function cancelByQuorumCalldata(w: Gen2World): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const digest = await guardianDigest(w, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"), DOMAIN.GUARDIAN, nonce);
  return w.vault.interface.encodeFunctionData("cancelRecoveryByQuorum", [quorum(w, digest), nonce, FAR_DEADLINE]);
}

/** A roster replacement signed by the world's GENESIS roster; a later transition supplies its own proof. */
export async function setGuardiansCalldata(
  w: Gen2World,
  threshold: bigint,
  members: string[],
  isContract: boolean[],
  proof?: (digest: string) => QuorumProof,
): Promise<string> {
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const params = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["uint64", "address[]", "bool[]"], [threshold, members, isContract]),
  );
  const digest = await guardianDigest(w, ACTION.SET_GUARDIANS, params, DOMAIN.GUARDIAN, nonce);
  return w.vault.interface.encodeFunctionData("setGuardians", [
    threshold,
    members,
    isContract,
    proof ? proof(digest) : quorum(w, digest),
    nonce,
    FAR_DEADLINE,
  ]);
}

export async function advanceTime(seconds: number): Promise<void> {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

export const send = (
  w: Gen2World,
  data: string,
  from?: ethers.Signer,
  gasLimit?: bigint,
): Promise<ethers.TransactionResponse> =>
  (from ?? w.deployer).sendTransaction({ to: w.vaultAddress, data, ...(gasLimit !== undefined ? { gasLimit } : {}) });

/** Packed immutable args the Generation-2 factory writes, mirrored for assertions. */
export const packedArgs = (generation: bigint, authority: string, asset: string): string =>
  ethers.solidityPacked(["uint64", "address", "address"], [generation, authority, asset]);

/** A contract handle on the ZOO's full ABI for the world's asset. */
export const zoo = (w: Gen2World, runner?: ethers.ContractRunner): ethers.Contract =>
  new ethers.Contract(w.token, gen2Unit("Gen2ZooToken").abi as ethers.InterfaceAbi, runner ?? w.deployer);

export const setMode = async (w: Gen2World, mode: ModeName): Promise<void> => {
  await (await zoo(w).setMode(MODE[mode])).wait();
};

export const assetBalance = async (w: Gen2World, account: string): Promise<bigint> =>
  (await zoo(w).realBalanceOf(account)) as bigint;

/**
 * The name of the error a refused transaction died with, decoded through the kernel's own ABI. The
 * candidate is compiled outside Hardhat's artifacts, so the runtime reports its custom errors only as
 * raw return data. A refusal with no name is a harness question, not a kernel answer, which is why
 * attack tests assert this instead of a bare "it reverted": a probe can die at an EARLIER guard than
 * the one it claims to reach.
 */
export function revertNameOf(iface: ethers.Interface, e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  const named = /custom error '([A-Za-z0-9_]+)/.exec(message) ?? /reverted with reason string '([^']*)'/.exec(message);
  if (named) return named[1]!;
  const data = /return data: (0x[0-9a-fA-F]*)/.exec(message);
  if (data) {
    if (data[1] === "0x") return "EMPTY_REVERT";
    const parsed = iface.parseError(data[1]!);
    if (parsed) return parsed.name;
    return "UNKNOWN_ERROR:" + data[1];
  }
  if (/out of gas/i.test(message)) return "OUT_OF_GAS";
  return message.slice(0, 160).replace(/\s+/g, " ");
}

/** Sends, and returns null when it settled or the decoded name of the error when it was refused. */
export async function refusal(
  w: Gen2World,
  send_: () => Promise<{ wait: () => Promise<unknown> }>,
): Promise<string | null> {
  try {
    await (await send_()).wait();
    return null;
  } catch (e) {
    return revertNameOf(w.vault.interface, e);
  }
}
