/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE GENERATION-2 OBSERVATIONS AND PROPERTIES.
 *
 * Generation 1's GLOBAL_INVARIANTS are run UNCHANGED on the Generation-2 snapshot, which has their
 * shape; `snapshotG2` feeds them. They are imported, not copied, so an edit there reaches both.
 *
 * THE ADDED PROPERTIES ARE ABOUT THE ASSET, AND THEIR ORACLE IS THE TOKEN'S REAL LEDGER. The kernel
 * reads `balanceOf`; the snapshot reads `realBalanceOf`, the fixture's own ground truth. In the lying
 * modes the two disagree on purpose, so a property here cannot agree with the kernel by construction.
 * Each is one direction only: IF a protected thing happened THEN its authority must have been present.
 * None mirrors a precondition, and a refusal is never judged here: liveness is the positive controls.
 */
import { ethers } from "../../test/connection.js";
import { GENERATION_2 } from "../compile.js";
import { pqHash, zoo, type Gen2World, type ModeName } from "../world.js";
import type { KernelSnapshot } from "../../stateful/invariants.js";

export interface SnapshotG2 extends KernelSnapshot {
  admittedAssetRead: string;
  vaultCode: string;
  otherTokenBalance: bigint;
  recipientAsset: bigint;
  destinationAsset: bigint;
  outsiderAsset: bigint;
  deployerAsset: bigint;
  sink: bigint;
  totalSupply: bigint;
  siblingAsset: bigint | null;
  siblingSpendNonce: bigint | null;
  destinationNative: bigint;
  destinationOther: bigint;
  /** The vault's raw storage words. Storage cannot move with the clock; four of the views above can. */
  rawStorage: string[];
  blockNumber: number;
  /** Transfers the token completed, counted by the token. A reverted call rolls its count back. */
  transferCalls: bigint;
}

/** Past the last non-mapping slot of the layout; test/Gen2Measurement.test.ts pins the layout it covers. */
export const RAW_STORAGE_WORDS = 24;

const ZERO_HASH = "0x" + "0".repeat(64);
const attestableCache = new Map<string, ReadonlySet<string>>();

function attestable(w: Gen2World): ReadonlySet<string> {
  const hit = attestableCache.get(w.opts.label);
  if (hit !== undefined) return hit;
  const set = new Set<string>([ZERO_HASH]);
  for (const k of [w.pqKey, ...w.sparePq]) set.add(pqHash(k).toLowerCase());
  attestableCache.set(w.opts.label, set);
  return set;
}

export async function snapshotG2(w: Gen2World): Promise<SnapshotG2> {
  const v = w.vault;
  const token = zoo(w);
  const [
    safeStateStored,
    safeStateEffective,
    containedUntil,
    containmentWindowStart,
    containmentUsedInWindow,
    ecdsaSigner,
    pqPublicKeyHash,
    credentialGeneration,
    floorRaw,
    pqVerifier,
    policyEngine,
    guardianCommitment,
    guardianThreshold,
    guardianGeneration,
    recoveryRaw,
    migrationRaw,
    admittedAssetRead,
  ] = await Promise.all([
    v.safeState(),
    v.effectiveSafeState(),
    v.containedUntil(),
    v.containmentWindowStart(),
    v.containmentUsedInWindow(),
    v.ecdsaSigner(),
    v.pqPublicKeyHash(),
    v.credentialGeneration(),
    v.securityFloor(),
    v.pqVerifier(),
    v.policyEngine(),
    v.guardianCommitment(),
    v.guardianThreshold(),
    v.guardianGeneration(),
    v.recovery(),
    v.migration(),
    v.admittedAsset(),
  ]);
  const [n0, n1, n2, n3, code, vaultCode, block] = await Promise.all([
    v.nonces(0),
    v.nonces(1),
    v.nonces(2),
    v.nonces(3),
    ethers.provider.getCode(pqVerifier as string),
    ethers.provider.getCode(w.vaultAddress),
    ethers.provider.getBlock("latest"),
  ]);
  const transferCalls = (await token.transferCalls()) as bigint;
  const rawStorage = await Promise.all(
    Array.from({ length: RAW_STORAGE_WORDS }, (_, slot) => ethers.provider.getStorage(w.vaultAddress, slot)),
  );
  const [
    tokenBalance,
    recipientAsset,
    destinationAsset,
    outsiderAsset,
    deployerAsset,
    sink,
    totalSupply,
    nativeBalance,
    destinationNative,
    otherTokenBalance,
    destinationOther,
  ] = await Promise.all([
    token.realBalanceOf(w.vaultAddress),
    token.realBalanceOf(w.recipient),
    token.realBalanceOf(w.destination),
    token.realBalanceOf(await w.outsider.getAddress()),
    token.realBalanceOf(await w.deployer.getAddress()),
    token.sink(),
    token.totalSupply(),
    ethers.provider.getBalance(w.vaultAddress),
    ethers.provider.getBalance(w.destination),
    w.other.realBalanceOf(w.vaultAddress),
    w.other.realBalanceOf(w.destination),
  ]);
  let siblingAsset: bigint | null = null;
  let siblingSpendNonce: bigint | null = null;
  if (w.sibling !== null) {
    siblingAsset = (await w.sibling.asset.realBalanceOf(w.sibling.vaultAddress)) as bigint;
    siblingSpendNonce = (await w.sibling.vault.nonces(0)) as bigint;
  }
  const nowTs = BigInt((block as { timestamp?: number } | null)?.timestamp ?? 0);
  return {
    safeStateStored: Number(safeStateStored),
    safeStateEffective: Number(safeStateEffective),
    containedUntil: containedUntil as bigint,
    containmentWindowStart: containmentWindowStart as bigint,
    containmentUsedInWindow: containmentUsedInWindow as bigint,
    ecdsaSigner: ecdsaSigner as string,
    pqPublicKeyHash: pqPublicKeyHash as string,
    commitmentAttestable: attestable(w).has(String(pqPublicKeyHash).toLowerCase()),
    credentialGeneration: credentialGeneration as bigint,
    floor: {
      requirePq: floorRaw[0] as boolean,
      pqParamLevel: floorRaw[1] as bigint,
      pqPublicKeyLength: floorRaw[2] as bigint,
      pqSignatureLength: floorRaw[3] as bigint,
    },
    pqVerifier: pqVerifier as string,
    pqVerifierHasCode: code !== "0x",
    policyEngine: policyEngine as string,
    guardianCommitment: guardianCommitment as string,
    guardianThreshold: guardianThreshold as bigint,
    guardianGeneration: guardianGeneration as bigint,
    nonces: [n0 as bigint, n1 as bigint, n2 as bigint, n3 as bigint],
    recovery: {
      proposedSigner: recoveryRaw[0] as string,
      proposedPqKeyHash: recoveryRaw[1] as string,
      proposedVerifier: recoveryRaw[2] as string,
      executableAt: recoveryRaw[3] as bigint,
      expiresAt: recoveryRaw[4] as bigint,
      boundGuardianGeneration: recoveryRaw[5] as bigint,
      challengesUsed: recoveryRaw[6] as bigint,
      active: recoveryRaw[7] as boolean,
    },
    migration: {
      destinationVault: migrationRaw[0] as string,
      destinationVaultCodeHash: migrationRaw[1] as string,
      destinationGeneration: migrationRaw[2] as bigint,
      boundAt: migrationRaw[3] as bigint,
      bound: migrationRaw[4] as boolean,
    },
    nativeBalance: nativeBalance as bigint,
    tokenBalance: tokenBalance as bigint,
    blockTimestamp: nowTs,
    recoveryEffectivelyLive: (recoveryRaw[7] as boolean) && nowTs < (recoveryRaw[4] as bigint),
    admittedAssetRead: admittedAssetRead as string,
    vaultCode: vaultCode,
    otherTokenBalance: otherTokenBalance as bigint,
    recipientAsset: recipientAsset as bigint,
    destinationAsset: destinationAsset as bigint,
    outsiderAsset: outsiderAsset as bigint,
    deployerAsset: deployerAsset as bigint,
    sink: sink as bigint,
    totalSupply: totalSupply as bigint,
    siblingAsset,
    siblingSpendNonce,
    destinationNative: destinationNative as bigint,
    destinationOther: destinationOther as bigint,
    rawStorage,
    blockNumber: (block as { number?: number } | null)?.number ?? 0,
    transferCalls,
  };
}

/**
 * Everything a kernel transition can write: the raw storage words, the one mapping's four domains, and
 * the code. NOT the views: `containmentWindowStart`, `containmentUsedInWindow`, `effectiveSafeState` and
 * the derived recovery liveness all read the clock, and every refusal here is really MINED, so the clock
 * moves across it. Generation 1's digest includes them and never trips, because its refused calls die in
 * gas estimation and mine no block: see "Evidence-quality findings" in GEN2_ADMISSION.md.
 */
export function kernelDigest(s: SnapshotG2): string {
  return ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify([s.rawStorage, s.nonces.map(String), s.vaultCode])));
}

/** G-RECOVERY-COMMITMENT-BINDS with the generation the candidate actually runs under. */
export async function checkRecoveryCommitmentG2(w: Gen2World, s: SnapshotG2): Promise<string | null> {
  if (!s.recovery.active) return null;
  const actual = (await w.vault.recoveryPossessionDigest()) as string;
  const expected = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "uint64", "address", "bytes32", "address", "uint64", "uint64"],
      [
        ethers.id("INCOMING_CREDENTIAL_POSSESSION"),
        w.chainId,
        w.vaultAddress,
        GENERATION_2,
        s.recovery.proposedSigner,
        s.recovery.proposedPqKeyHash,
        s.recovery.proposedVerifier,
        s.recovery.boundGuardianGeneration,
        s.recovery.executableAt,
      ],
    ),
  );
  return actual === expected
    ? null
    : "the recovery possession digest does not bind the complete approved configuration";
}

/**
 * THE ASSET MODES IN WHICH THE TOKEN MISREPRESENTS ITSELF TO A SENDER. In these the kernel-level
 * settlement rule cannot tell, by construction: this is the asset boundary, stated as code. Spends
 * settled here are counted as `assetBoundaryObserved` and pinned deterministically in
 * test/Gen2Settlement.test.ts; they are excluded from the debit oracle because the oracle would
 * otherwise report a property of the token as a defect of the kernel.
 */
export const LYING_TO_THE_SENDER: ReadonlySet<ModeName> = new Set(["QUERY_LIES_EXACT_DEBIT"]);
/** The mode whose harm is on the RECIPIENT's leg, which a sender cannot observe. Boundary too. */
export const RECIPIENT_LEG_ONLY: ReadonlySet<ModeName> = new Set(["RECIPIENT_FEE"]);

export const G2_PROPERTIES: readonly { name: string; statement: string }[] = [
  {
    name: "P-ASSET-CODE-IDENTITY",
    statement:
      "admittedAsset() and the vault's own code never change across any history, and the code's tail is generation || verifierAuthority || admitted asset: no principal can move the asset in place and the asset is the vault's identity (G2-ASSET-1,5,6,8,9).",
  },
  {
    name: "P-SETTLEMENT-EXACT",
    statement:
      "A spend that SUCCEEDED debited the vault's REAL balance by exactly the signed amount (G2-SEM-KERNEL, K-13-SETTLE). Excludes only the declared lying-to-the-sender mode.",
  },
  {
    name: "P-SPEND-COMPLETED-TRANSFER",
    statement:
      "A spend that SUCCEEDED is backed by a token transfer that itself completed, counted by the token: a zero-amount spend cannot settle over a reverted call.",
  },
  {
    name: "P-SPEND-PAYS-RECIPIENT",
    statement:
      "A successful spend credited the signed recipient by exactly the signed amount, except the declared recipient-leg mode.",
  },
  {
    name: "P-SPEND-TOUCHES-ONLY-ASSET",
    statement:
      "A successful spend moves neither native value nor any other holding, whatever a relayer appended to the calldata (G2-ASSET-3,4).",
  },
  {
    name: "P-CONSERVATION",
    statement:
      "Every unit of the admitted asset is at an account the harness tracks or in the token's own sink: value cannot reach an address nobody authorised.",
  },
  {
    name: "P-CROSS-ASSET",
    statement:
      "The vault of the other asset, same genesis and same credential, loses nothing and burns no nonce from anything done here, and a signature made for it never settles here (G2-ASSET-9,10).",
  },
  {
    name: "P-UNAUTHORISED-INPUT-NEVER-SETTLES",
    statement:
      "A relayed spend whose signed recipient or amount the harness rewrote never settles: a relayer chooses whether and when, and nothing else (G2-ASSET-4).",
  },
  {
    name: "P-NO-REPLAY",
    statement: "A nonce-bearing call that already succeeded never succeeds a second time, whoever resubmits it.",
  },
  {
    name: "P-NONCE-SPENT-BEFORE-TOKEN-RUNS",
    statement:
      "When the token gets control during a spend, the spend nonce it sits inside is already consumed, read by the token itself through the vault's own getter (G2-REENTRANCY).",
  },
  {
    name: "P-REENTRY-NO-REPLAY",
    statement: "A same-payload replay fired from inside the token's transfer never succeeds (G2-REENTRANCY).",
  },
  {
    name: "P-NONCE-ON-SPEND",
    statement:
      "A successful spend consumed at least one spend nonce: no settlement without its authorisation being spent.",
  },
  {
    name: "P-EGRESS-RECIPIENT",
    statement:
      "An egress credits exactly the bound destination with what the vault lost, except the declared recipient-leg mode (I-EGRESS-RECIPIENT-FIXED).",
  },
  {
    name: "P-EGRESS-PUBLISHES-THE-TRUTH",
    statement:
      "The amount an egress publishes is what the vault's REAL balance lost, except the declared lying-to-the-sender mode (I-NO-FALSE-SETTLEMENT).",
  },
  {
    name: "P-MIGRATION-TIME",
    statement:
      "After a binding, no holding leaves before the binding's own instant plus 7 days, measured on the harness's clock from the mined bind block (I-MIGRATION-SUBORDINATE-TO-RECOVERY).",
  },
  {
    name: "P-EXIT-REACHABLE",
    statement:
      "Whatever history ended in a binding, once the delay has passed and the token behaves, a stranger's egress of each class moves the vault's full balance of it to the destination, whichever egress was attempted first (I-EXIT-REACHABILITY, I-MIGRATION-NONTRAP, I-EGRESS-INDEPENDENCE). Liveness: judged at the end of a history, never per step.",
  },
  {
    name: "P-BALANCE-SPENDABLE",
    statement:
      "Whatever history ended in NORMAL with a behaving token and a plane that admits, the current credential can spend the vault's whole real balance, direct credits and rebases included: there is no ledger to desynchronise. Liveness, judged at the end of a history.",
  },
  {
    name: "P-VERIFIER-PROVENANCE",
    statement:
      "Under the real root, the active verifier and any proposed verifier are always among those the harness saw the root create (G-VERIFIER-ADMISSION-PROVENANCE). Zero power under the ungated fixture, so asserted only under the root.",
  },
];
