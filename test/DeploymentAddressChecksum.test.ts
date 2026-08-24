/**
 * EIP-55 checksum enforcement for deployment metadata addresses
 * (scripts/validate-deployments.ts).
 *
 * Background: deployments/sepolia/stablecoin-vault-simulator.json once carried
 * a `tokenAddress` with one mis-cased hex digit
 * (0x8ffc8cE04789e9a7b53685a2d78CDa54E6Faac15 — 'c' where EIP-55 requires 'C').
 * The underlying 20-byte address was correct; only the checksum casing was
 * wrong. `validateAddress()`'s old shape check (`/^0x[0-9a-fA-F]{40}$/`) is
 * case-insensitive by construction, so this exact defect passed the canonical
 * deployment validator undetected.
 *
 * These tests pin the strengthened invariant directly against the repository's
 * own `validateAddress()` — not a standalone `ethers.getAddress()` call — so a
 * future regression of the validator itself (not just the data) is caught:
 *
 *   - RED:      the known-bad mis-cased address must fail validation.
 *   - GREEN:    the corrected EIP-55 address must pass validation.
 *   - MUTATION: `ADDRESS_RE` alone (the pre-#156 validator's entire address
 *     check) accepts the mis-cased address — proving that a regression back to
 *     shape-only checking would flip the RED case's assertion from failing
 *     (error present) to passing incorrectly, i.e. the RED test above is a
 *     kill test for that exact mutant.
 *
 * Pure, fast, static checks — no network, no contracts, no filesystem scan.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect } from "chai";

import { ADDRESS_RE, validateAddress } from "../scripts/validate-deployments";

const REPO_ROOT = join(import.meta.dirname, "..");
const SEPOLIA_RECORD = join(REPO_ROOT, "deployments", "sepolia", "stablecoin-vault-simulator.json");

// The exact defect this suite guards against.
const OLD_MISCASED_ADDRESS = "0x8ffc8cE04789e9a7b53685a2d78CDa54E6Faac15";
const CORRECT_CHECKSUMMED_ADDRESS = "0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac15";

function errorsFor(value: unknown): string[] {
  const errors: string[] = [];
  validateAddress(value, "tokenAddress", errors);
  return errors;
}

describe("Deployment address EIP-55 checksum enforcement", () => {
  it("RED: rejects the known-bad mis-cased MockUSDC address", () => {
    const errors = errorsFor(OLD_MISCASED_ADDRESS);
    expect(errors).to.have.lengthOf(1);
    expect(errors[0]).to.match(/EIP-55 checksum/);
  });

  it("GREEN: accepts the corrected EIP-55 checksummed address", () => {
    expect(errorsFor(CORRECT_CHECKSUMMED_ADDRESS)).to.deep.equal([]);
  });

  it("MUTATION: shape-only ADDRESS_RE alone would have accepted the bad address", () => {
    // This is exactly what the validator checked before #156 — proving that
    // reverting validateAddress() to only this regex resurrects the bug the
    // RED test above catches.
    expect(ADDRESS_RE.test(OLD_MISCASED_ADDRESS)).to.equal(true);
  });

  it("rejects a malformed address (wrong length)", () => {
    const errors = errorsFor("0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac1");
    expect(errors).to.have.lengthOf(1);
    expect(errors[0]).to.match(/must be a 0x-prefixed 40-hex-character address/);
  });

  it("rejects a malformed address (non-hex character)", () => {
    const errors = errorsFor("0xZZfc8CE04789e9a7b53685a2d78CDa54E6Faac15");
    expect(errors).to.have.lengthOf(1);
    expect(errors[0]).to.match(/must be a 0x-prefixed 40-hex-character address/);
  });

  it("rejects an all-lowercase address (valid hex, but not the canonical checksum casing)", () => {
    const errors = errorsFor(CORRECT_CHECKSUMMED_ADDRESS.toLowerCase());
    expect(errors).to.have.lengthOf(1);
    expect(errors[0]).to.match(/EIP-55 checksum/);
  });

  it("accepts null and undefined (address not yet deployed)", () => {
    expect(errorsFor(null)).to.deep.equal([]);
    expect(errorsFor(undefined)).to.deep.equal([]);
  });

  it("the committed Sepolia record's tokenAddress passes validation today", () => {
    const record = JSON.parse(readFileSync(SEPOLIA_RECORD, "utf8")) as Record<string, unknown>;
    expect(errorsFor(record["tokenAddress"])).to.deep.equal([]);
  });
});
