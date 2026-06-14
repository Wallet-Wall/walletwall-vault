import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { WalletWallVault } from "../../typechain-types";

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

export async function withdrawalDomain(vault: WalletWallVault) {
  return {
    name: "WalletWallVault",
    version: "1",
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await vault.getAddress(),
  };
}

export async function signWithdrawalRequest(vault: WalletWallVault, signer: SignerWithAddress, request: object) {
  const domain = await withdrawalDomain(vault);
  return {
    digest: ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request),
    ecdsaSignature: await signer.signTypedData(domain, WITHDRAWAL_TYPES, request),
  };
}

export function makeSignWithdrawal(vault: WalletWallVault, signer: SignerWithAddress) {
  return async function signWithdrawal(request: object) {
    const domain = await withdrawalDomain(vault);
    const ecdsaSig = await signer.signTypedData(domain, WITHDRAWAL_TYPES, request);
    const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { ecdsaSig, pqSig };
  };
}

export function makeBuildRequest(
  owner: SignerWithAddress,
  defaults: { recipient: string; amount: bigint; vaultMode?: number },
) {
  return async function buildRequest(overrides: { amount?: bigint; nonce?: number; recipient?: string } = {}) {
    return {
      vaultOwner: owner.address,
      recipient: overrides.recipient ?? defaults.recipient,
      amount: overrides.amount ?? defaults.amount,
      nonce: overrides.nonce ?? 0,
      deadline: (await time.latest()) + 3600,
      vaultMode: defaults.vaultMode ?? 2,
    };
  };
}
