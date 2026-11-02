/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * Fixture and digest helpers for the admitted-asset ERC-20 spend-plane MEASUREMENT
 * suites (test/Erc20SpendPlane*.test.ts). The candidates are compiled ONCE per
 * process through `erc20-spend-plane/compile.ts` (pinned solc, never Hardhat's
 * artifacts) and deployed from their creation bytecode by ordinary transactions.
 * Every digest here mirrors the kernel's EXACTLY and reads nothing back from the
 * kernel to decide what to sign, for the reason stateful/world.ts gives: a harness
 * that asks the contract what to sign cannot detect a contract that signs the
 * wrong thing.
 *
 * The admitted asset is ALWAYS a local mock. Nothing here names, models or touches
 * a production token, network or address.
 */
import { ethers } from "./connection.js";
import {
  compilePlane,
  PLANE_FACTORY,
  VARIANT_A,
  VARIANT_B,
  type Compiled,
  type CompiledUnit,
} from "../erc20-spend-plane/compile.js";
import {
  ACTION,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  HONEST_FLOOR,
  ZERO,
  addrOf,
  digestOf,
  keyOf,
  migrationParams,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
} from "../stateful/world.js";

export { ACTION, DOMAIN, FAR_DEADLINE, ZERO, ECDSA_ONLY_FLOOR, HONEST_FLOOR, addrOf, keyOf, sign, pqKeyBytes, pqHash };

/** The candidate generation's number: Generation 1 is the measured kernel on main. */
export const KERNEL_GENERATION_2 = 2n;
/** An arbitrary later generation a migration binding may name. */
export const DESTINATION_GENERATION = 3n;
/** Six-decimal units, the shape of the stablecoin this lane deliberately does not name. */
export const UNIT = 1_000_000n;
export const DEFAULT_MINT = 1_000n * UNIT;

let cached: Compiled | undefined;

/** The candidates, compiled once per process. */
export function plane(): Compiled {
  if (!cached) cached = compilePlane();
  return cached;
}

export function planeUnit(name: string): CompiledUnit {
  const unit = plane().units.get(name);
  if (!unit) throw new Error(`compiled plane has no contract named ${name}`);
  return unit;
}

export interface Deployed {
  readonly contract: ethers.Contract;
  readonly address: string;
  readonly gasUsed: bigint;
}

/** Deploys a compiled unit by an ORDINARY transaction (never setCode), returning its deployment gas. */
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

/** Deploys one of the Generation-1 PROTOTYPE MOCKS from the Hardhat artifact (they are not re-compiled here). */
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

export type Variant = "A" | "B";

export interface Erc20WorldOptions {
  /** Seed for every key and salt, so two worlds in one run never share identities. */
  readonly label: string;
  /** Which kernel candidate the factory binds. Default A. */
  readonly variant?: Variant;
  /** The genesis floor. Default `ecdsaOnly`, the custody adjudication's v1 recommendation (section 7.2). */
  readonly floor?: "ecdsaOnly" | "hybrid";
  /** Commit a PQ key even on an ECDSA-only floor (legal genesis; makes the arming edge reachable). */
  readonly commitPqKey?: boolean;
  /** `configurable` = ConfigurableVerifier ALWAYS_TRUE; `none` = address(0), legal only for variant B on an ECDSA-only floor. */
  readonly verifier?: "configurable" | "none";
  /** Which provenance root the factory binds. Default the UNGATED fixture rule (the mock verifiers stay admissible). */
  readonly authority?: "ungated" | "gen1root";
  /** Mock token contract name from Erc20PlaneMocks.sol. Default VanillaToken. */
  readonly token?: string;
  readonly tokenArgs?: readonly unknown[];
  /** Use an already-deployed asset instead of deploying `token`. */
  readonly tokenAddress?: string;
  /** Minted to the vault by a plain `mint` — a direct credit, no deposit entrypoint exists. Default 1,000 units. */
  readonly mintToVault?: bigint;
  /** Unsolicited native value, in wei. Default 0. */
  readonly fundEth?: bigint;
  /**
   * Index of the first Hardhat account to use (deployer, outsider and recipient are consecutive).
   * The gas probes use a high offset so their deployer's nonce — and therefore every address and
   * every calldata byte — is independent of whatever other suites deployed earlier in the process.
   */
  readonly signerOffset?: number;
  /** Reuse already-deployed pieces, so two worlds can differ in EXACTLY one thing. */
  readonly reuse?: {
    readonly verifierAddress?: string;
    readonly authorityAddress?: string;
    readonly implementation?: string;
  };
  /**
   * A MUTATED kernel (compiled in memory by the mutation suite) to deploy instead of the candidate.
   * Its ABI is variant A's, so every helper here keeps working against it.
   */
  readonly implOverride?: CompiledUnit;
}

export interface Erc20World {
  readonly opts: Required<Pick<Erc20WorldOptions, "label" | "variant" | "floor" | "verifier" | "authority" | "token">>;
  readonly chainId: bigint;
  readonly deployer: ethers.Signer;
  /** A stranger: relayer, attacker and permissionless executor in one. */
  readonly outsider: ethers.Signer;
  readonly recipient: string;
  readonly credKey: ethers.SigningKey;
  readonly pqKey: ethers.SigningKey;
  /** Guardian principals in the STRICTLY ASCENDING order the kernel demands. */
  readonly gKeys: ethers.SigningKey[];
  readonly guardians: string[];
  readonly guardianIsContract: boolean[];
  readonly threshold: bigint;
  readonly floor: Floor;
  readonly implementation: string;
  readonly factory: ethers.Contract;
  readonly factoryAddress: string;
  readonly kernelAbi: unknown[];
  readonly vault: ethers.Contract;
  readonly vaultAddress: string;
  readonly token: ethers.Contract;
  readonly tokenAddress: string;
  readonly verifierAddress: string;
  readonly authorityAddress: string;
  readonly destination: string;
  readonly destinationCodeHash: string;
  readonly genesis: Genesis;
  readonly salt: string;
  readonly deployGas: { readonly implementation: bigint; readonly factory: bigint; readonly vault: bigint };
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

const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address,uint256) returns (bool)",
  "function mint(address,uint256)",
];

/** Deploys a complete world: mocks, asset, candidate implementation, factory and one initialised vault. */
export async function deployErc20World(options: Erc20WorldOptions): Promise<Erc20World> {
  const opts = {
    variant: "A" as Variant,
    floor: "ecdsaOnly" as const,
    verifier: "configurable" as const,
    authority: "ungated" as const,
    token: "VanillaToken",
    ...options,
  };
  const signers = await ethers.getSigners();
  const offset = opts.signerOffset ?? 0;
  const deployer = signers[offset]!;
  const outsider = signers[offset + 1]!;
  const recipient = signers[offset + 2]!.address;
  const chainId = (await ethers.provider.getNetwork()).chainId;

  const credKey = keyOf(opts.label + "-cred");
  const pqKey = keyOf(opts.label + "-pq");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(opts.label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  const guardians = gKeys.map(addrOf);
  const guardianIsContract = [false, false, false];
  const threshold = 2n;

  // The provenance root the factory binds.
  let authorityAddress: string;
  let verifierAddress = ZERO;
  if (opts.reuse?.authorityAddress !== undefined) {
    authorityAddress = opts.reuse.authorityAddress;
    verifierAddress = opts.reuse.verifierAddress ?? ZERO;
  } else if (opts.authority === "gen1root") {
    const root = await deployArtifact("ImmutableAttestationVerifierFactoryPrototype", deployer);
    authorityAddress = root.address;
    if (opts.verifier === "configurable") {
      // Created BY the root — the only provenance Generation 1 recognises. Permissionless: the OUTSIDER creates it.
      const rootAsOutsider = root.contract.connect(outsider) as ethers.Contract;
      const attestor = await deployer.getAddress();
      verifierAddress = (await rootAsOutsider.deployVerifier.staticCall(attestor)) as string;
      await (await rootAsOutsider.deployVerifier(attestor)).wait();
    }
  } else {
    authorityAddress = (await deployArtifact("UngatedVerifierAuthority", deployer)).address;
    if (opts.verifier === "configurable") {
      verifierAddress = (await deployArtifact("ConfigurableVerifier", deployer, 0)).address; // ALWAYS_TRUE
    }
  }

  // The admitted asset: a LOCAL MOCK, always.
  let tokenAddress: string;
  if (opts.tokenAddress !== undefined) {
    tokenAddress = opts.tokenAddress;
  } else {
    tokenAddress = (await deployUnit(planeUnit(opts.token), deployer, ...(opts.tokenArgs ?? []))).address;
  }
  const token = new ethers.Contract(tokenAddress, ERC20_ABI, deployer);

  const kernelUnit = planeUnit(opts.variant === "A" ? VARIANT_A : VARIANT_B);
  const impl =
    opts.reuse?.implementation !== undefined
      ? { address: opts.reuse.implementation, gasUsed: 0n }
      : await deployUnit(opts.implOverride ?? kernelUnit, deployer);
  const factory = await deployUnit(
    planeUnit(PLANE_FACTORY),
    deployer,
    impl.address,
    KERNEL_GENERATION_2,
    authorityAddress,
    tokenAddress,
  );

  const hybrid = opts.floor === "hybrid";
  const commitPq = hybrid || opts.commitPqKey === true;
  const floor: Floor = hybrid ? { ...HONEST_FLOOR } : { ...ECDSA_ONLY_FLOOR };
  const genesis: Genesis = {
    signer: addrOf(credKey),
    pqKeyHash: commitPq ? pqHash(pqKey) : ethers.ZeroHash,
    verifier: verifierAddress,
    threshold: Number(threshold),
    guardians,
    guardianIsContract,
    floor,
  };
  const salt = ethers.id(opts.label + "-vault");
  const vaultAddress = (await factory.contract.predictVault(salt, genesis)) as string;
  const witness = commitPq ? pqKeyBytes(pqKey) : "0x";
  const deployReceipt = await (await factory.contract.deployVault(salt, genesis, witness)).wait();
  const vault = new ethers.Contract(vaultAddress, kernelUnit.abi as ethers.InterfaceAbi, deployer);

  const mint = opts.mintToVault ?? DEFAULT_MINT;
  if (mint > 0n) await (await token.mint(vaultAddress, mint)).wait();
  if ((opts.fundEth ?? 0n) > 0n)
    await (await deployer.sendTransaction({ to: vaultAddress, value: opts.fundEth })).wait();

  const dest = await deployArtifact("DestinationStub", deployer);

  return {
    opts: {
      label: opts.label,
      variant: opts.variant,
      floor: opts.floor,
      verifier: opts.verifier,
      authority: opts.authority,
      token: opts.token,
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
    floor,
    implementation: impl.address,
    factory: factory.contract,
    factoryAddress: factory.address,
    kernelAbi: kernelUnit.abi,
    vault,
    vaultAddress,
    token,
    tokenAddress,
    verifierAddress,
    authorityAddress,
    destination: dest.address,
    destinationCodeHash: ethers.keccak256(await ethers.provider.getCode(dest.address)),
    genesis,
    salt,
    deployGas: { implementation: impl.gasUsed, factory: factory.gasUsed, vault: deployReceipt!.gasUsed },
  };
}

// =====================================================================
// Digests — mirrored, never read back
// =====================================================================

export interface SpendDigestParts {
  readonly to: string;
  readonly amount: bigint;
  readonly nonce: bigint;
  readonly deadline?: bigint;
  readonly credentialGeneration?: bigint;
  readonly vault?: string;
  readonly chainId?: bigint;
  readonly kernelGeneration?: bigint;
}

export function spendDigest(w: Erc20World, p: SpendDigestParts): string {
  return digestOf({
    chainId: p.chainId ?? w.chainId,
    vault: p.vault ?? w.vaultAddress,
    kernelGeneration: p.kernelGeneration ?? KERNEL_GENERATION_2,
    actionType: ACTION.SPEND,
    authorityGeneration: p.credentialGeneration ?? 1n,
    params: spendParams(p.to, p.amount),
    domain: DOMAIN.SPEND,
    nonce: p.nonce,
    deadline: p.deadline ?? FAR_DEADLINE,
  });
}

export interface SpendArgs {
  readonly to: string;
  readonly amount: bigint;
  /** Defaults to the vault's CURRENT spend nonce (read for convenience; the digest is still mirrored). */
  readonly nonce?: bigint;
  readonly deadline?: bigint;
  /** Who signs. Defaults to the credential. */
  readonly signer?: ethers.SigningKey;
  /** Who SUBMITS. Defaults to the deployer; the outsider is the relayer. */
  readonly from?: ethers.Signer;
  /** PQ leg, for hybrid worlds. */
  readonly pq?: { readonly sig: string; readonly key: string };
  /** Explicit gas limit, REQUIRED for a probe expected to revert (ethers' estimation would refuse to send it). */
  readonly gasLimit?: bigint;
  /** Sign THIS digest instead of the mirrored one (for cross-vault and cross-asset replay probes). */
  readonly digestOverride?: string;
}

export async function currentNonce(w: Erc20World, domain: number): Promise<bigint> {
  return (await w.vault.nonces(domain)) as bigint;
}

/** Builds, signs and SENDS a spend. Returns the transaction promise so chai's revert matchers can judge it. */
export async function sendSpend(w: Erc20World, a: SpendArgs): Promise<ethers.ContractTransactionResponse> {
  const nonce = a.nonce ?? (await currentNonce(w, DOMAIN.SPEND));
  const deadline = a.deadline ?? FAR_DEADLINE;
  const digest = a.digestOverride ?? spendDigest(w, { to: a.to, amount: a.amount, nonce, deadline });
  const ecdsaSig = sign(a.signer ?? w.credKey, digest);
  const vault = (a.from ? w.vault.connect(a.from) : w.vault) as ethers.Contract;
  const overrides = a.gasLimit !== undefined ? { gasLimit: a.gasLimit } : {};
  return vault.execute(a.to, a.amount, nonce, deadline, ecdsaSig, a.pq?.sig ?? "0x", a.pq?.key ?? "0x", overrides);
}

export interface QuorumProof {
  members: string[];
  isContract: boolean[];
  attestingIndices: number[];
  attestations: string[];
}

/** A k-of-n quorum proof over the world's roster, seats 0 and 1 by default. */
export function quorum(w: Erc20World, digest: string, indices: number[] = [0, 1]): QuorumProof {
  return {
    members: w.guardians,
    isContract: w.guardianIsContract,
    attestingIndices: indices,
    attestations: indices.map((i) => sign(w.gKeys[i]!, digest)),
  };
}

export async function guardianDigest(
  w: Erc20World,
  actionType: string,
  params: string,
  domain: number,
  nonce: bigint,
): Promise<string> {
  const guardianGeneration = (await w.vault.guardianGeneration()) as bigint;
  return digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GENERATION_2,
    actionType,
    authorityGeneration: guardianGeneration,
    params,
    domain,
    nonce,
    deadline: FAR_DEADLINE,
  });
}

/** Binds the world's destination: guardian quorum AND the credential, as section 22 D2 requires. */
export async function bindDestination(w: Erc20World): Promise<ethers.ContractTransactionResponse> {
  const nonce = await currentNonce(w, DOMAIN.MIGRATION);
  const params = migrationParams(w.destination, w.destinationCodeHash, DESTINATION_GENERATION);
  const digest = await guardianDigest(w, ACTION.BIND_MIGRATION, params, DOMAIN.MIGRATION, nonce);
  return w.vault.bindMigration(
    { vault: w.destination, codeHash: w.destinationCodeHash, generation: DESTINATION_GENERATION },
    quorum(w, digest),
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, digest),
  );
}

/** A quorum-approved recovery proposal naming `verifier`, from the current roster. */
export async function proposeRecovery(
  w: Erc20World,
  proposedSigner: string,
  proposedPqKeyHash: string,
  verifier: string,
  gasLimit?: bigint,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
  const digest = await guardianDigest(
    w,
    ACTION.RECOVER,
    recoverParams(proposedSigner, proposedPqKeyHash, verifier),
    DOMAIN.GUARDIAN,
    nonce,
  );
  const overrides = gasLimit !== undefined ? { gasLimit } : {};
  return w.vault.initiateRecovery(
    proposedSigner,
    proposedPqKeyHash,
    verifier,
    quorum(w, digest),
    nonce,
    FAR_DEADLINE,
    overrides,
  );
}

/** `setVerifier`, hybrid-authorised by the credential (and the PQ leg when the current floor requires it). */
export async function setVerifier(
  w: Erc20World,
  verifier: string,
  floor: Floor,
  pq?: { readonly sig: string; readonly key: string },
  gasLimit?: bigint,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GENERATION_2,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credentialGeneration,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const overrides = gasLimit !== undefined ? { gasLimit } : {};
  return w.vault.setVerifier(
    verifier,
    floor,
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, digest),
    pq?.sig ?? "0x",
    pq?.key ?? "0x",
    overrides,
  );
}

/** `setPolicy`, credential-authorised (ECDSA-only worlds). */
export async function setPolicy(w: Erc20World, policy: string): Promise<ethers.ContractTransactionResponse> {
  const nonce = await currentNonce(w, DOMAIN.CREDENTIAL);
  const credentialGeneration = (await w.vault.credentialGeneration()) as bigint;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GENERATION_2,
    actionType: ACTION.SET_POLICY,
    authorityGeneration: credentialGeneration,
    params: setPolicyParams(policy),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.setPolicy(policy, nonce, FAR_DEADLINE, sign(w.credKey, digest), "0x", "0x");
}

// =====================================================================
// Observation helpers
// =====================================================================

export interface GasProbe {
  readonly ok: boolean;
  readonly gasUsed: bigint;
}

/**
 * Sends a transaction and reports the gas it burnt whether it succeeded or REVERTED. A refused
 * transaction is still mined (status 0) when it carries an explicit gas limit; ethers' estimation
 * would otherwise refuse to send it and no block would exist to read (the SD-2 suite's lesson).
 */
export async function gasOf(send: () => Promise<ethers.ContractTransactionResponse>): Promise<GasProbe> {
  try {
    const tx = await send();
    const receipt = await tx.wait();
    return { ok: true, gasUsed: receipt!.gasUsed };
  } catch {
    const block = await ethers.provider.getBlock("latest");
    const hash = block?.transactions[0];
    const receipt = hash ? await ethers.provider.getTransactionReceipt(hash) : null;
    if (!receipt || receipt.status !== 0) {
      throw new Error("the refused probe was NOT mined: pass an explicit gasLimit so a block exists to read");
    }
    return { ok: false, gasUsed: receipt.gasUsed };
  }
}

export const balanceOf = async (token: ethers.Contract, account: string): Promise<bigint> =>
  (await token.balanceOf(account)) as bigint;

export interface MigrationSnapshot {
  readonly destinationVault: string;
  readonly destinationVaultCodeHash: string;
  readonly destinationGeneration: bigint;
  readonly boundAt: bigint;
  readonly bound: boolean;
  readonly safeState: bigint;
  readonly migrationNonce: bigint;
}

/** Every kernel word a failed egress could conceivably disturb. */
export async function migrationSnapshot(w: Erc20World): Promise<MigrationSnapshot> {
  const m = await w.vault.migration();
  return {
    destinationVault: m[0] as string,
    destinationVaultCodeHash: m[1] as string,
    destinationGeneration: m[2] as bigint,
    boundAt: m[3] as bigint,
    bound: m[4] as boolean,
    safeState: (await w.vault.safeState()) as bigint,
    migrationNonce: await currentNonce(w, DOMAIN.MIGRATION),
  };
}

/** Packed immutable args the Generation-2 factory writes, mirrored for assertions and raw clones. */
export const packedArgs = (generation: bigint, authority: string, asset: string): string =>
  ethers.solidityPacked(["uint64", "address", "address"], [generation, authority, asset]);

export const DAY = 24 * 60 * 60;
export async function advanceTime(seconds: number): Promise<void> {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}
