import { ethers } from "./connection";

/**
 * Helpers for constructing {PolicySubject} values in tests.
 *
 * The production subject is always MINTED BY A VAULT from its own trusted state, so
 * tests that want the honest subject should derive it from the vault itself
 * ({ethSubject} / {tokenSubject}) rather than hand-assembling one. Hand-assembly is
 * reserved for the adversarial cases, where naming a consumer the caller is not is
 * exactly the thing under test — {spoofedSubject} exists to make those call sites
 * read as deliberate rather than as a mistake.
 */

/** The canonical native-ETH asset identifier. Not a placeholder — address(0) IS the asset. */
export const NATIVE_ASSET = ethers.ZeroAddress;

export interface PolicySubjectValue {
  consumer: string;
  owner: string;
  asset: string;
}

/** Minimal shape shared by every contract wrapper we need an address from. */
interface HasAddress {
  getAddress(): Promise<string>;
}

/** The subject a native-ETH vault (WalletWallVault) mints for `owner`. */
export async function ethSubject(vault: HasAddress, owner: string): Promise<PolicySubjectValue> {
  return { consumer: await vault.getAddress(), owner, asset: NATIVE_ASSET };
}

/** The subject an ERC-20 vault (StablecoinVaultSimulator) mints for `owner`. */
export async function tokenSubject(vault: HasAddress, owner: string, token: HasAddress): Promise<PolicySubjectValue> {
  return { consumer: await vault.getAddress(), owner, asset: await token.getAddress() };
}

/**
 * An arbitrary, deliberately unauthenticated subject.
 *
 * Every use of this is an attack step: it names a `consumer` the caller is not, or an
 * `asset` the caller does not custody. Nothing that must succeed should be built with
 * it.
 */
export function spoofedSubject(consumer: string, owner: string, asset: string): PolicySubjectValue {
  return { consumer, owner, asset };
}
