import { ethers } from "./connection";
import { networkHelpers } from "./connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { StablecoinVaultSimulator } from "../../typechain-types";

export const WITHDRAWAL_TYPES = {
  Withdrawal: [
    { name: "vaultOwner", type: "address" },
    { name: "recipient", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "vaultMode", type: "uint8" },
  ],
};

/** EIP-712 domain for the stablecoin simulator — distinct from "WalletWallVault". */
export async function simulatorDomain(vault: StablecoinVaultSimulator) {
  return {
    name: "WalletWallStablecoinVault",
    version: "1",
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await vault.getAddress(),
  };
}

export async function signWithdrawalRequest(
  vault: StablecoinVaultSimulator,
  signer: HardhatEthersSigner,
  request: object,
) {
  const domain = await simulatorDomain(vault);
  return {
    digest: ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request),
    ecdsaSignature: await signer.signTypedData(domain, WITHDRAWAL_TYPES, request),
  };
}

/** Returns a sign function that produces ECDSA + mock-PQ signatures for the simulator. */
export function makeSignWithdrawal(vault: StablecoinVaultSimulator, signer: HardhatEthersSigner) {
  return async function signWithdrawal(request: object) {
    const domain = await simulatorDomain(vault);
    const ecdsaSig = await signer.signTypedData(domain, WITHDRAWAL_TYPES, request);
    const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { ecdsaSig, pqSig };
  };
}

export function makeBuildRequest(
  owner: HardhatEthersSigner,
  defaults: { recipient: string; amount: bigint; vaultMode?: number },
) {
  return async function buildRequest(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    return {
      vaultOwner: owner.address,
      recipient: overrides.recipient ?? defaults.recipient,
      amount: overrides.amount ?? defaults.amount,
      nonce: overrides.nonce ?? 0,
      deadline: (await networkHelpers.time.latest()) + 3600,
      vaultMode: defaults.vaultMode ?? 2,
    };
  };
}

/** Build an AttestationPQCVerifier payload for a given withdrawal digest. */
export async function buildAttestationPayload(
  verifierAddress: string,
  attestorSigner: HardhatEthersSigner,
  withdrawalDigest: string,
  publicKey: string,
  deadlineOffset = 3600,
) {
  const ALGORITHM_ID = ethers.keccak256(ethers.toUtf8Bytes("ATTESTED-ML-DSA-65"));
  const ATTESTATION_TYPES = {
    PQCAttestation: [
      { name: "withdrawalDigest", type: "bytes32" },
      { name: "publicKeyHash", type: "bytes32" },
      { name: "pqSignatureHash", type: "bytes32" },
      { name: "algorithmId", type: "bytes32" },
      { name: "verifier", type: "address" },
      { name: "chainId", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  const { chainId } = await ethers.provider.getNetwork();
  const publicKeyHash = ethers.keccak256(publicKey);
  const pqSignatureHash = ethers.keccak256(ethers.randomBytes(3309));
  const deadline = BigInt((await networkHelpers.time.latest()) + deadlineOffset);

  const domain = {
    name: "AttestationPQCVerifier",
    version: "1",
    chainId,
    verifyingContract: verifierAddress,
  };
  const attestation = {
    withdrawalDigest,
    publicKeyHash,
    pqSignatureHash,
    algorithmId: ALGORITHM_ID,
    verifier: verifierAddress,
    chainId,
    deadline,
  };
  const attestationSignature = await attestorSigner.signTypedData(domain, ATTESTATION_TYPES, attestation);

  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "uint256", "bytes32", "bytes32"],
    [attestationSignature, deadline, publicKeyHash, pqSignatureHash],
  );
}
