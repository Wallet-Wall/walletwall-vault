/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE CANDIDATE IS MEASURED VARIANT A PLUS THE DECLARED ADMISSION DELTA, AND NOTHING ELSE. Row PROVENANCE. The
 * candidate lives in its own tree so #237's record stays what it measured, which means its relation to what was
 * measured has to be enforced rather than remembered: this suite applies the declared edits to Variant A's
 * statements and requires the candidate's statements to be that sequence exactly, so an edit that is not listed,
 * a moved statement, or a change to Variant A fails here. It compares statements because comments are the other
 * half of the delta: those that made false claims were corrected, and they are named in GEN2_ADMISSION.md.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";

import { GEN2_CONTRACTS, VARIANT_A_SOURCE } from "../generation-2/compile.js";

const VARIANT_A_FACTORY = "prototype/vnext-kernel/erc20-spend-plane/contracts/VaultKernelErc20FactoryPrototype.sol";

const lf = (s: string): string => s.split("\r\n").join("\n");
const read = (p: string): string => lf(fs.readFileSync(p, "utf8"));

const CANDIDATE = path.join(GEN2_CONTRACTS, "VaultKernelGen2Prototype.sol");
const CANDIDATE_INTERFACE = path.join(GEN2_CONTRACTS, "interfaces", "IKernelPlanes.sol");
const VARIANT_A_INTERFACE = "prototype/vnext-kernel/erc20-spend-plane/contracts/interfaces/IKernelPlanes.sol";

/** Only the executable statements of the delta, read out of both sides with comments stripped. */
function code(source: string): string[] {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((l) => l.replace(/\/\/.*$/, "").trim())
    .filter((l) => l !== "");
}

/** One statement, by its only occurrence: a declared edit whose anchor moved or doubled must not apply quietly. */
function only(lines: string[], statement: string): number {
  const at = lines.indexOf(statement);
  if (at < 0 || lines.lastIndexOf(statement) !== at) throw new Error("not exactly one occurrence: " + statement);
  return at;
}

describe("Generation-2 admission — the candidate's derivation from measured Variant A", function () {
  it("with comments stripped, the candidate differs from Variant A in exactly the declared statements", function () {
    const declared = code(read(VARIANT_A_SOURCE));
    declared[only(declared, "contract VaultKernelErc20Prototype {")] = "contract VaultKernelGen2Prototype {";
    declared[only(declared, "if (!ok || data.length < 32) return 0;")] =
      "if (!ok || data.length < 32) revert TransferFailed();";
    declared.splice(
      only(declared, "if (!b.bound) revert NotBound();") + 1,
      0,
      "if (block.timestamp < b.boundAt + BIND_DELAY) revert TooEarly();",
    );
    declared.splice(
      only(
        declared,
        "if (destination.vault == address(0) || destination.codeHash == bytes32(0)) revert DestinationMismatch();",
      ) + 1,
      0,
      "if (destination.vault.code.length == 0 || destination.vault == address(this)) revert DestinationMismatch();",
      "if (destination.vault.codehash != destination.codeHash) revert DestinationMismatch();",
    );
    declared[
      only(declared, "keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation)),")
    ] =
      "keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation, credentialGeneration, policyEngine, _effectiveState())),";
    declared.splice(
      only(declared, "moved = address(this).balance;"),
      5,
      "uint256 before = address(this).balance;",
      "if (before != 0) {",
      '(bool ok, ) = payable(b.destinationVault).call{value: before}("");',
      "if (!ok) revert TransferFailed();",
      "uint256 remaining = address(this).balance;",
      "if (remaining >= before) revert TransferFailed();",
      "moved = before - remaining;",
      "}",
    );
    declared[only(declared, "return ok && bytes4(answer) == ERC1271_MAGIC;")] =
      "return ok && answer == bytes32(ERC1271_MAGIC);";
    expect(code(read(CANDIDATE))).to.deep.equal(declared);
  });

  it("with comments stripped, the candidate's factory differs from Variant A's in its own name and the kernel's alone", function () {
    const declared = code(read(VARIANT_A_FACTORY)).map((l) =>
      l
        .replace("VaultKernelErc20FactoryPrototype", "VaultKernelGen2FactoryPrototype")
        .replace(/VaultKernelErc20Prototype/g, "VaultKernelGen2Prototype"),
    );
    expect(code(read(path.join(GEN2_CONTRACTS, "VaultKernelGen2FactoryPrototype.sol")))).to.deep.equal(declared);
  });

  it("the interface is a byte-identical copy of what #237 measured", function () {
    expect(read(CANDIDATE_INTERFACE)).to.equal(read(VARIANT_A_INTERFACE));
  });

  it("the source of the candidate carries the NOT PRODUCTION label, and no network address", function () {
    for (const file of [
      CANDIDATE,
      path.join(GEN2_CONTRACTS, "VaultKernelGen2FactoryPrototype.sol"),
      path.join(GEN2_CONTRACTS, "Gen2TokenZoo.sol"),
    ]) {
      const text = read(file);
      expect(text, file).to.match(/NOT PRODUCTION/);
      const literals = text.match(/0x[0-9a-fA-F]{40}\b/g) ?? [];
      expect(literals, `${file} hard-codes an address`).to.deep.equal([]);
    }
  });

  it("the tree contains the candidate, its factory, the interface and the fixture, and nothing else", function () {
    const list = (dir: string): string[] =>
      fs
        .readdirSync(dir, { withFileTypes: true })
        .flatMap((e) => (e.isDirectory() ? list(path.join(dir, e.name)) : [path.join(dir, e.name)]));
    const files = list(GEN2_CONTRACTS)
      .map((f) => path.relative(GEN2_CONTRACTS, f).split(path.sep).join("/"))
      .sort();
    expect(files).to.deep.equal([
      "Gen2TokenZoo.sol",
      "VaultKernelGen2FactoryPrototype.sol",
      "VaultKernelGen2Prototype.sol",
      "interfaces/IKernelPlanes.sol",
    ]);
  });
});
