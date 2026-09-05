/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * Shared plumbing for the SD-4 candidate adjudication. Every helper here mirrors
 * a kernel digest EXACTLY; none of them reads a value back out of the kernel to
 * decide what to sign, because a harness that asks the contract what to sign
 * cannot detect a contract that signs the wrong thing.
 */
import { ethers } from "./connection.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  digestOf,
  floorTuple,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

export const KERNEL_GEN = 1n;
export const abi = ethers.AbiCoder.defaultAbiCoder();

/** A deterministic byte string of an exact length. */
export const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) out += ethers.id(`${tag}-${i++}`).slice(2);
  return "0x" + out.slice(0, n * 2);
};

/** Index positions in the public `recovery()` tuple of the UNMODIFIED kernel. */
export const R = {
  SIGNER: 0,
  PQ_KEY_HASH: 1,
  VERIFIER: 2,
  EXECUTABLE_AT: 3,
  EXPIRES_AT: 4,
  GUARDIAN_GEN: 5,
  CHALLENGES: 6,
  ACTIVE: 7,
} as const;

/** Binds a candidate kernel's ABI to the world's already-deployed vault clone. */
export const at = (w: World, kernel: { abi: unknown[] }): ethers.Contract =>
  new ethers.Contract(w.vaultAddress, kernel.abi as ethers.InterfaceAbi, w.deployer);

export interface FloorTuple {
  requirePq: boolean;
  pqParamLevel: number;
  pqPublicKeyLength: number;
  pqSignatureLength: number;
}

export async function liveFloor(vault: ethers.Contract): Promise<FloorTuple> {
  const f = await vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/** Quorum attestations over an arbitrary guardian digest, from seats 0 and 1. */
export const quorum = (w: World, digest: string) => ({
  members: w.guardians,
  isContract: w.guardianIsContract,
  attestingIndices: [0, 1],
  attestations: [sign(w.gKeys[0]!, digest), sign(w.gKeys[1]!, digest)],
});

/** The guardian digest for an action with a given params hash. */
export async function guardianDigest(
  w: World,
  vault: ethers.Contract,
  params: string,
): Promise<{ digest: string; nonce: bigint }> {
  const gGen = (await vault.guardianGeneration()) as bigint;
  const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  return {
    nonce,
    digest: digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER,
      authorityGeneration: gGen,
      params,
      domain: DOMAIN.GUARDIAN,
      nonce,
      deadline: FAR_DEADLINE,
    }),
  };
}

/** `initiateRecovery` on the UNMODIFIED kernel's signature. */
export async function proposeStd(
  w: World,
  vault: ethers.Contract,
  signer: string,
  pqKeyHash: string,
  verifier: string,
): Promise<void> {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, pqKeyHash, verifier]));
  const { digest, nonce } = await guardianDigest(w, vault, params);
  await (await vault.initiateRecovery(signer, pqKeyHash, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

/** `initiateRecovery` on candidate F's signature: NO commitment in the statement. */
export async function proposeF(
  w: World,
  vault: ethers.Contract,
  signer: string,
  verifier: string,
): Promise<void> {
  const params = ethers.keccak256(abi.encode(["address", "address"], [signer, verifier]));
  const { digest, nonce } = await guardianDigest(w, vault, params);
  await (await vault.initiateRecovery(signer, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

/** `initiateRecovery` on H-PRECISE's signature: the shape is a COMPATIBILITY declaration. */
export async function proposeHPrecise(
  w: World,
  vault: ethers.Contract,
  signer: string,
  pqKeyHash: string,
  verifier: string,
  keyLen: number,
  sigLen: number,
): Promise<void> {
  const params = ethers.keccak256(
    abi.encode(
      ["address", "bytes32", "address", "uint32", "uint32"],
      [signer, pqKeyHash, verifier, keyLen, sigLen],
    ),
  );
  const { digest, nonce } = await guardianDigest(w, vault, params);
  await (
    await vault.initiateRecovery(signer, pqKeyHash, verifier, quorum(w, digest), nonce, FAR_DEADLINE, keyLen, sigLen)
  ).wait();
}

/**
 * The credential principal arms the PQ conjunct.
 *
 * `pqExhibit` must be a preimage of the vault's CURRENT `pqPublicKeyHash` at the
 * declared key length — `I-DECLARATION-EXHIBITED`. The outgoing floor does not
 * mandate PQ, so `_authorise` returns before the PQ leg and an empty `pqSig` is
 * correct rather than lazy.
 */
export async function declare(
  w: World,
  vault: ethers.Contract,
  credKey: ethers.SigningKey,
  verifier: string,
  floor: Floor,
  pqExhibit: string,
  /**
   * The PQ signer, for the case this call is NOT a declaring edge. Once
   * `requirePq` already holds, `_authorise` runs the full hybrid check first, so
   * a true -> true `setVerifier` needs a real second-factor signature. Passing
   * null is correct ONLY while the outgoing floor is dormant.
   */
  pqSigner: ethers.SigningKey | null = null,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const pqSig = pqSigner === null ? "0x" : sign(pqSigner, d);
  return vault.setVerifier(verifier, floorTuple(floor), nonce, FAR_DEADLINE, sign(credKey, d), pqSig, pqExhibit);
}

/** The credential principal cancels a pending recovery (bounded by CHALLENGE_LIMIT). */
export async function cancel(
  w: World,
  vault: ethers.Contract,
  credKey: ethers.SigningKey,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER,
    authorityGeneration: credGen,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return vault.cancelRecovery(nonce, FAR_DEADLINE, sign(credKey, d));
}

/**
 * K-9 mechanism B (Lane W2): the guardian quorum cancels the effectively-live
 * request, at the CURRENT guardian nonce and generation. Mirrors the kernel's
 * `cancelRecoveryByQuorum` digest exactly: `ACTION_RECOVER`, guardianGeneration,
 * params `keccak256("QUORUM_CANCEL_RECOVERY")`, `DOMAIN_GUARDIAN`.
 *
 * Only meaningful against the REAL artifact (or a candidate that carries the
 * function); the pinned pre-W2 kernel has no such selector by construction.
 */
export const QCANCEL_TAG = ethers.id("QUORUM_CANCEL_RECOVERY");
export async function quorumCancelStd(w: World, vault: ethers.Contract): Promise<ethers.ContractTransactionResponse> {
  const { digest, nonce } = await guardianDigest(w, vault, QCANCEL_TAG);
  return vault.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE);
}

/**
 * A spend under the CURRENT floor, following an accepted transition through to
 * an actual asset movement. `pqSigner` is ignored when the floor is dormant.
 */
export async function spend(
  w: World,
  vault: ethers.Contract,
  signerKey: ethers.SigningKey,
  pqSigner: ethers.SigningKey | null,
  pqKeyBytesValue: string,
  amount = 1n,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await vault.nonces(DOMAIN.SPEND)) as bigint;
  const credGen = (await vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SPEND,
    authorityGeneration: credGen,
    params: spendParams(w.recipient, amount),
    domain: DOMAIN.SPEND,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const pqSig = pqSigner === null ? "0x" : sign(pqSigner, d);
  return vault.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(signerKey, d), pqSig, pqKeyBytesValue);
}

/** An ECDSA key's 32-byte "PQ public key" in the EcdsaBackedVerifier's encoding. */
export const pqPub = (k: ethers.SigningKey): string => abi.encode(["address"], [addrOf(k)]);
export const pqPubHash = (k: ethers.SigningKey): string => ethers.keccak256(pqPub(k));
