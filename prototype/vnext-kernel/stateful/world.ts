/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * The WORLD: principal identities, authority roots, and the deployed fixture the
 * stateful campaign drives.
 *
 * PRINCIPALS, ROOTS, ADDRESSES AND SEATS ARE FOUR DIFFERENT THINGS, and this
 * lane keeps them apart on purpose (mission PHASE 3):
 *
 *   ADDRESS   — an EVM account. Says nothing about who controls it.
 *   ROOT      — an independent authority factor: the ECDSA credential, the PQ
 *               credential, or one guardian principal. Compromising a root is
 *               the unit the minimum-cut table counts.
 *   PRINCIPAL — a guardian ROSTER MEMBER. Because the kernel demands a strictly
 *               ascending roster, one address is exactly one principal; two
 *               signatures from one address are ONE principal, never two.
 *   SEAT      — an index into the roster. Seats are NOT principals: the whole
 *               point of finding B was that counting seats let one principal
 *               reach a threshold of two.
 *
 * `Actor.roots` below is the harness's own record of WHICH ROOTS A CALLER
 * HOLDS. It is declared by the campaign, never read from the chain. That is
 * what makes the oracle independent: the model knows how many roots the caller
 * really has, and the kernel is judged on whether it agreed.
 *
 * H-31 (several distinct addresses behind ONE off-chain custodian) is OUTSIDE
 * this boundary and stays outside it. This lane counts on-chain principals; it
 * does not and cannot observe off-chain custody, and it invents no identity
 * system to pretend otherwise.
 */
import { ethers } from "../test/connection.js";

export const DAY = 24 * 60 * 60;
export const ZERO = "0x0000000000000000000000000000000000000000";
export const FAR_DEADLINE = BigInt(2 ** 40);

const abi = ethers.AbiCoder.defaultAbiCoder();

export const ACTION = {
  SPEND: ethers.id("SPEND"),
  ROTATE: ethers.id("ROTATE_CREDENTIAL"),
  SET_VERIFIER: ethers.id("SET_VERIFIER"),
  SET_POLICY: ethers.id("SET_POLICY"),
  SET_GUARDIANS: ethers.id("SET_GUARDIANS"),
  RECOVER: ethers.id("RECOVER"),
  BIND_MIGRATION: ethers.id("BIND_MIGRATION"),
} as const;

export const DOMAIN = { SPEND: 0, CREDENTIAL: 1, GUARDIAN: 2, MIGRATION: 3 } as const;

/**
 * The honest second factor's declared shape. `EcdsaBackedVerifier` stands in for
 * a real PQ scheme with a SECOND, INDEPENDENT ECDSA keypair, so "the attacker
 * does not hold the PQ root" is a real cryptographic fact in this harness and
 * not a mock that waves everything through. A 32-byte key, a 65-byte signature.
 */
export const HONEST_FLOOR = {
  requirePq: true,
  pqParamLevel: 3,
  pqPublicKeyLength: 32,
  pqSignatureLength: 65,
} as const;

export interface Floor {
  requirePq: boolean;
  pqParamLevel: number;
  pqPublicKeyLength: number;
  pqSignatureLength: number;
}

export const floorTuple = (f: Floor): [boolean, number, number, number] => [
  f.requirePq,
  f.pqParamLevel,
  f.pqPublicKeyLength,
  f.pqSignatureLength,
];

// =====================================================================
// Digest mirror — every field the kernel binds, mirrored exactly.
// =====================================================================

export interface DigestParts {
  chainId: bigint;
  vault: string;
  kernelGeneration: bigint;
  actionType: string;
  authorityGeneration: bigint;
  params: string;
  domain: number;
  nonce: bigint;
  deadline: bigint;
}

export function domainSeparator(chainId: bigint, vault: string): string {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        ethers.id("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        ethers.id("WalletWallVaultKernel"),
        ethers.id("0-prototype"),
        chainId,
        vault,
      ],
    ),
  );
}

export function digestOf(p: DigestParts): string {
  const structHash = ethers.keccak256(
    abi.encode(
      ["bytes32", "uint64", "uint64", "bytes32", "uint8", "uint256", "uint64"],
      [p.actionType, p.kernelGeneration, p.authorityGeneration, p.params, p.domain, p.nonce, p.deadline],
    ),
  );
  return ethers.keccak256(ethers.concat(["0x1901", domainSeparator(p.chainId, p.vault), structHash]));
}

export const sign = (k: ethers.SigningKey, digest: string): string => ethers.Signature.from(k.sign(digest)).serialized;
export const keyOf = (label: string): ethers.SigningKey => new ethers.SigningKey(ethers.id(label));
export const addrOf = (k: ethers.SigningKey): string => ethers.computeAddress(k.publicKey);
/** The honest verifier's "public key": the second keypair's address, 32 bytes. */
export const pqKeyBytes = (k: ethers.SigningKey): string => abi.encode(["address"], [addrOf(k)]);
export const pqHash = (k: ethers.SigningKey): string => ethers.keccak256(pqKeyBytes(k));

export const spendParams = (to: string, amount: bigint): string =>
  ethers.keccak256(abi.encode(["address", "uint256"], [to, amount]));

export const setVerifierParams = (verifier: string, floor: Floor): string =>
  ethers.keccak256(abi.encode(["address", "tuple(bool,uint16,uint32,uint32)"], [verifier, floorTuple(floor)]));

export const setPolicyParams = (policy: string): string => ethers.keccak256(abi.encode(["address"], [policy]));

export const rosterCommitment = (threshold: bigint, members: string[], isContract: boolean[]): string =>
  ethers.keccak256(abi.encode(["uint64", "address[]", "bool[]"], [threshold, members, isContract]));

export const recoverParams = (signer: string, pqKeyHash: string, verifier: string): string =>
  ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, pqKeyHash, verifier]));

export const migrationParams = (vault: string, codeHash: string, generation: bigint): string =>
  ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [vault, codeHash, generation]));

// =====================================================================
// Roots and actors
// =====================================================================

export const ROOTS = ["CRED_ECDSA", "CRED_PQ", "GUARDIAN_0", "GUARDIAN_1", "GUARDIAN_2"] as const;
export type Root = (typeof ROOTS)[number];

export const GUARDIAN_ROOTS: readonly Root[] = ["GUARDIAN_0", "GUARDIAN_1", "GUARDIAN_2"];

/**
 * A caller of a generated action, described by the KEY MATERIAL IT HOLDS rather
 * than by a fixed list of roots.
 *
 * This distinction is the whole point. If an actor were pinned to a static root
 * set, an honest recovery that rotates the credential to fresh material would
 * leave the model still believing the attacker holds the credential root — and
 * the campaign would then either raise false violations or, far worse, credit
 * the attacker with authority it lost and never notice a real one. Holding is
 * therefore recomputed at every step from WHICH KEY IS CURRENTLY INSTALLED
 * (tracked by the harness's own bookkeeping, never read back from the kernel).
 *
 * `ownedLabels` are the harness's key labels — see `keyOf`. An actor holds the
 * ECDSA credential root exactly when the key currently installed as
 * `ecdsaSigner` is one whose label it owns.
 *
 * The fully-honest actor owns every label and exists as the POSITIVE CONTROL:
 * without it, a campaign in which every attack reverts scores as "the invariant
 * held" while proving only that the fixture was broken.
 */
/**
 * The material an actor holds, named by ROLE rather than by concrete key label.
 *
 * THIS INDIRECTION IS NOT COSMETIC. Every campaign deploys its own world under
 * its own label, so the concrete key labels are `<worldLabel>-cred`,
 * `<worldLabel>-guardian-0` and so on. An earlier version of this file declared
 * actors with labels hard-coded to one world's name; in every other campaign
 * those labels matched NOTHING, so each "attacker" silently held zero roots and
 * signed everything with decoys. The campaign still looked healthy — full action
 * coverage, all positive controls passing — while the adversary was inert, and
 * the P-CUT properties could not fire because no attack ever cleared a gate.
 *
 * It was the MUTATION ADEQUACY suite that exposed it: thirteen deliberately
 * weakened kernels survived. Roles are resolved against the actual world at
 * campaign construction (`materialiseActor`), so an actor cannot be mis-bound
 * to a world it is not running in.
 */
export const ROLES = ["cred", "pq", "guardian-0", "guardian-1", "guardian-2"] as const;
export type Role = (typeof ROLES)[number];

/** Held by the fully-honest positive control: every key, in every world. */
export const ALL_MATERIAL = "*";

export interface Actor {
  readonly name: string;
  /** ROLES held. Resolved to concrete key labels by `materialiseActor`. */
  readonly ownedRoles: ReadonlySet<string>;
  /** Concrete key labels, filled in once the world is known. Empty until then. */
  readonly ownedLabels: ReadonlySet<string>;
  /** Which EOA sends the transaction. Authority comes from signatures, not from msg.sender. */
  readonly sendsAs: "deployer" | "outsider";
}

export const makeActor = (
  name: string,
  ownedRoles: readonly string[],
  sendsAs: Actor["sendsAs"] = "outsider",
): Actor => ({ name, ownedRoles: new Set(ownedRoles), ownedLabels: new Set(), sendsAs });

/** Binds an actor's ROLES to the concrete key labels of THIS world. */
export function materialiseActor(actor: Actor, worldLabel: string): Actor {
  if (actor.ownedRoles.has(ALL_MATERIAL)) {
    return { ...actor, ownedLabels: new Set([ALL_MATERIAL]) };
  }
  const labels = new Set<string>();
  for (const role of actor.ownedRoles) labels.add(worldLabel + "-" + role);
  return { ...actor, ownedLabels: labels };
}

/** Guardian ROOT name for a roster seat index. Seats and roots are 1:1 here BY CONSTRUCTION. */
export const seatRoot = (seat: number): Root => GUARDIAN_ROOTS[seat] ?? "GUARDIAN_0";

// =====================================================================
// The deployed world
// =====================================================================

export type VerifierKind = "honest" | "alwaysTrue" | "alwaysFalse" | "reverting";
export type PolicyKind = "none" | "allow" | "deny" | "stateful" | "codeless";

export interface WorldOptions {
  /** Which verifier the vault is born under. */
  verifier: VerifierKind;
  /** `k = floor(n/2) + 1` for the declared cuts; n = 3 gives k = 2. */
  threshold: number;
  /** Label seed, so two worlds in one run never share keys or a salt. */
  label: string;
  /** Initial funding, in wei. */
  funding: bigint;
  /** Born under ECDSA_ONLY_FLOOR rather than HONEST_FLOOR. See that constant. */
  ecdsaOnlyFloor: boolean;
  /**
   * With `ecdsaOnlyFloor`, commit a PQ key ANYWAY. `initialize` refuses only
   * `requirePq` WITH a zero commitment, so a floor that mandates nothing while a
   * key is ALREADY COMMITTED is a legal genesis nothing else in this repository
   * could build. It is the only configuration in which the `requirePq`
   * false -> true edge is reachable WITHOUT also being SD-3, which is what makes
   * the SD-1 remediation's declared residual testable in isolation. Defaults to
   * false, so no existing world changes shape.
   */
  commitPqKeyOnEcdsaOnlyFloor?: boolean;
  /**
   * A MUTATED kernel implementation, compiled in memory, to deploy instead of
   * the real artifact. Used ONLY by the mutation-adequacy suite: it is what lets
   * the SAME campaign machinery be pointed at a deliberately weakened kernel, so
   * "the properties have teeth" is demonstrated rather than asserted. Never
   * writes to contracts/ and never touches the real artifacts.
   */
  implOverride?: { abi: unknown[]; bytecode: string };
}

/**
 * An ECDSA-ONLY genesis floor. `initialize` permits it (it only refuses
 * `requirePq` WITH a zero key commitment), so it is a legal configuration of
 * this kernel and the campaign must cover it. It is also the only way to reach
 * a `requirePq: false -> true` transition at all, because `_requireNoDowngrade`
 * makes the reverse direction unrepresentable.
 */
export const ECDSA_ONLY_FLOOR = {
  requirePq: false,
  pqParamLevel: 0,
  pqPublicKeyLength: 0,
  pqSignatureLength: 0,
} as const;

export const DEFAULT_WORLD: WorldOptions = {
  verifier: "honest",
  threshold: 2,
  label: "stateful",
  funding: ethers.parseEther("10"),
  ecdsaOnlyFloor: false,
};

async function deployVerifier(kind: VerifierKind, deployer: ethers.Signer): Promise<string> {
  if (kind === "honest") {
    const V = await ethers.getContractFactory("EcdsaBackedVerifier", deployer);
    const v = await V.deploy();
    await v.waitForDeployment();
    return v.getAddress();
  }
  const mode = kind === "alwaysTrue" ? 0 : kind === "alwaysFalse" ? 1 : 2;
  const V = await ethers.getContractFactory("ConfigurableVerifier", deployer);
  const v = await V.deploy(mode);
  await v.waitForDeployment();
  return v.getAddress();
}

export interface World {
  readonly opts: WorldOptions;
  readonly chainId: bigint;
  readonly deployer: ethers.Signer;
  readonly outsider: ethers.Signer;
  readonly recipient: string;
  readonly credKey: ethers.SigningKey;
  readonly pqKey: ethers.SigningKey;
  /** Guardian principals, in the STRICTLY ASCENDING order the kernel demands. */
  readonly gKeys: ethers.SigningKey[];
  readonly guardians: string[];
  readonly guardianIsContract: boolean[];
  readonly threshold: bigint;
  readonly implAddress: string;
  readonly factoryAddress: string;
  readonly vaultAddress: string;
  readonly vault: ethers.Contract;
  /** Spare credential material the campaign can rotate/recover TO. */
  readonly spareCred: ethers.SigningKey[];
  readonly sparePq: ethers.SigningKey[];
  readonly verifiers: Record<VerifierKind, string>;
  readonly policies: Record<Exclude<PolicyKind, "none">, string>;
  readonly destination: string;
  readonly destinationCodeHash: string;
  readonly token: string;
}

/**
 * Deploys one complete world. Every key is derived from `label`, so a campaign
 * seed plus a label reproduces the identical world — addresses included, which
 * matters because the roster's canonical ORDER depends on the addresses.
 */
export async function deployWorld(partial: Partial<WorldOptions> = {}): Promise<World> {
  const opts: WorldOptions = { ...DEFAULT_WORLD, ...partial };
  const signers = await ethers.getSigners();
  const deployer = signers[0]!;
  const outsider = signers[1]!;
  const recipient = signers[2]!.address;
  const chainId = (await ethers.provider.getNetwork()).chainId;

  const credKey = keyOf(opts.label + "-cred");
  const pqKey = keyOf(opts.label + "-pq");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(opts.label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  const guardians = gKeys.map(addrOf);
  const guardianIsContract = [false, false, false];

  const verifiers: Record<VerifierKind, string> = {
    honest: await deployVerifier("honest", deployer),
    alwaysTrue: await deployVerifier("alwaysTrue", deployer),
    alwaysFalse: await deployVerifier("alwaysFalse", deployer),
    reverting: await deployVerifier("reverting", deployer),
  };

  const Policy = await ethers.getContractFactory("ConfigurablePolicy", deployer);
  const allow = await Policy.deploy(true);
  await allow.waitForDeployment();
  const deny = await Policy.deploy(false);
  await deny.waitForDeployment();
  const Stateful = await ethers.getContractFactory("StatefulPolicy", deployer);
  const stateful = await Stateful.deploy(ethers.parseEther("3"));
  await stateful.waitForDeployment();

  const Impl = opts.implOverride
    ? new ethers.ContractFactory(opts.implOverride.abi as ethers.InterfaceAbi, opts.implOverride.bytecode, deployer)
    : await ethers.getContractFactory("VaultKernelPrototype", deployer);
  const impl = await Impl.deploy();
  await impl.waitForDeployment();
  const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
  const factory = await Factory.deploy(await impl.getAddress(), 1);
  await factory.waitForDeployment();

  const Dest = await ethers.getContractFactory("DestinationStub", deployer);
  const dest = await Dest.deploy();
  await dest.waitForDeployment();
  const destination = await dest.getAddress();

  const Token = await ethers.getContractFactory("TestToken", deployer);
  const token = await Token.deploy(false);
  await token.waitForDeployment();

  const genesis = {
    signer: addrOf(credKey),
    // A vault with no mandatory PQ conjunct commits to no PQ key either; that is
    // the configuration initialize accepts (it refuses only requirePq WITH a
    // zero commitment), and it is what makes requirePq false -> true reachable.
    pqKeyHash: opts.ecdsaOnlyFloor && opts.commitPqKeyOnEcdsaOnlyFloor !== true ? ethers.ZeroHash : pqHash(pqKey),
    verifier: verifiers[opts.verifier],
    threshold: opts.threshold,
    guardians,
    guardianIsContract,
    floor: opts.ecdsaOnlyFloor ? ECDSA_ONLY_FLOOR : HONEST_FLOOR,
  };

  const salt = ethers.id(opts.label + "-vault");
  const vaultAddress: string = await factory.predictVault(salt, genesis);
  // The genesis witness for `I-COMMITMENT-EXHIBITED-AT-ADMISSION`. Every world
  // this factory builds commits either nothing or `pqHash(pqKey)`, so the
  // exhibit is always available and no world changes shape. `predictVault` is
  // called with the UNCHANGED argument list on purpose: the witness is not part
  // of the salt, and this line is where that would break if it ever became so.
  const genesisWitness = genesis.pqKeyHash === ethers.ZeroHash ? "0x" : pqKeyBytes(pqKey);
  await (await factory.deployVault(salt, genesis, genesisWitness)).wait();
  const vault = await ethers.getContractAt("VaultKernelPrototype", vaultAddress, deployer);
  if (opts.funding > 0n) await deployer.sendTransaction({ to: vaultAddress, value: opts.funding });
  await (await token.mint(vaultAddress, ethers.parseEther("5"))).wait();

  return {
    opts,
    chainId,
    deployer,
    outsider,
    recipient,
    credKey,
    pqKey,
    gKeys,
    guardians,
    guardianIsContract,
    threshold: BigInt(opts.threshold),
    implAddress: await impl.getAddress(),
    factoryAddress: await factory.getAddress(),
    vaultAddress,
    vault,
    spareCred: [0, 1, 2].map((i) => keyOf(opts.label + "-spare-cred-" + i)),
    sparePq: [0, 1, 2].map((i) => keyOf(opts.label + "-spare-pq-" + i)),
    verifiers,
    policies: {
      allow: await allow.getAddress(),
      deny: await deny.getAddress(),
      stateful: await stateful.getAddress(),
      // A NON-ZERO address with NO CODE. Included deliberately: `setPolicy` has
      // no code-length check, unlike `setVerifier`, so this is a REACHABLE
      // configuration and the campaign must find out what it actually does.
      codeless: "0x00000000000000000000000000000000DeaDBeef",
    },
    destination,
    destinationCodeHash: ethers.keccak256(await ethers.provider.getCode(destination)),
    token: await token.getAddress(),
  };
}
