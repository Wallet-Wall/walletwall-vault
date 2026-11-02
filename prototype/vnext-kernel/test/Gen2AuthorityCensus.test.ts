/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE AUTHORITY CENSUS HAS TEETH: rows AUTH-COMPLETENESS and K-2. NO_NEW_PRIVILEGED_PRINCIPAL is computed by
 * `deriveVerdict` from facts read out of two ASTs, and it would be worthless if it could not answer anything
 * else, so each mutant below adds a principal or an authority edge and the same code must change its answer.
 * The Generation-1 census is unaffected: authority/ is not edited, and it runs here unchanged.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";

import { replaceWithinFunction } from "../authority/mutation-harness.js";
import {
  CENSUS_PATH,
  EXPECTED_NEW_EDGES,
  deriveVerdict,
  runGen2Census,
  type Gen2Census,
} from "../generation-2/authority/census.js";
import { GEN2_CONTRACTS } from "../generation-2/compile.js";

const KERNEL_FILE = "VaultKernelGen2Prototype.sol";
const FACTORY_FILE = "VaultKernelGen2FactoryPrototype.sol";

describe("Generation-2 admission — the authority census", function () {
  this.timeout(600_000);

  const kernel = fs.readFileSync(path.join(GEN2_CONTRACTS, KERNEL_FILE), "utf8");
  const factory = fs.readFileSync(path.join(GEN2_CONTRACTS, FACTORY_FILE), "utf8");
  let census: Gen2Census;

  before(function () {
    census = runGen2Census();
  });

  it("the real checker classifies every state-changing function, under a Generation-2 manifest, with nothing failed", function () {
    expect(census.checker.summary.failed).to.equal(0);
    expect(census.checker.summary.total).to.equal(18);
    expect(census.checker.summary.pass + census.checker.summary.passWithDeclaredException).to.equal(18);
  });

  it("derived verdict: NO_NEW_PRIVILEGED_PRINCIPAL, with no reason recorded against it", function () {
    expect(census.derivedVerdict.verdict).to.equal("NO_NEW_PRIVILEGED_PRINCIPAL");
    expect(census.derivedVerdict.reasons).to.deep.equal([]);
  });

  it("the comparison covers everything the brief names: selectors, authorisation paths, roots, state effects, discretion, permissionless paths, mutable principals, new edges", function () {
    expect(census.comparisonWithGeneration1.length).to.equal(16);
    for (const row of census.comparisonWithGeneration1) {
      expect(row.callerDiscretion, row.selector).to.not.equal("MISSING");
      expect(row.expectedCut, row.selector).to.not.equal("MISSING");
      expect(row.verdictGen2, row.selector).to.not.equal("MISSING");
      expect(row.mechanismsGen2, `${row.selector}: same authorisation path as Generation 1`).to.deep.equal(
        row.mechanismsGen1,
      );
      expect(row.stateEffectsGen2, `${row.selector}: same state effects as Generation 1`).to.deep.equal(
        row.stateEffectsGen1,
      );
    }
    expect(census.principals.addressHoldersGen2).to.deep.equal(census.principals.addressHoldersGen1);
    expect(census.principals.callerIdentityUsesKernel).to.deep.equal([]);
    expect(census.principals.callerIdentityUsesFactory).to.deep.equal([]);
  });

  it("the ERC-20 call is modelled as what it is: a new effect surface, on execute only, and the native edge left execute", function () {
    expect(census.effectSurface.newEdges.added.sort()).to.deep.equal([...EXPECTED_NEW_EDGES].sort());
    expect(census.effectSurface.newEdges.removed).to.deep.equal(["execute -> lowlevel.call:recipient:value"]);
  });

  it("only bindMigration, egress and execute changed among state-changing functions, with _balanceOf and the guardian's answer underneath them: the admission delta is what it says", function () {
    const differs = census.comparisonWithGeneration1
      .filter((r) => !r.bodyIdenticalToGen1)
      .map((r) => r.signatureGen2!.split("(")[0])
      .sort();
    expect(differs).to.deep.equal(["bindMigration", "egress", "execute"]);
    expect(census.bodyIdentity.differentFromGen1.map((s) => s.split("(")[0]).sort()).to.deep.equal([
      "_attests",
      "_balanceOf",
      "bindMigration",
      "egress",
      "execute",
    ]);
    expect(census.bodyIdentity.addedInGen2.map((s) => s.split("(")[0]).sort()).to.deep.equal([
      "_admittedAsset",
      "admittedAsset",
    ]);
    expect(census.bodyIdentity.removedFromGen1).to.deep.equal([]);
    expect(census.viewSurface.addedViews).to.deep.equal(["admittedAsset()"]);
    expect(census.viewSurface.removedViews).to.deep.equal([]);
  });

  it("the committed census is this census, byte for byte", function () {
    let committed = "";
    try {
      committed = fs.readFileSync(CENSUS_PATH, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT")
        throw new Error(`${CENSUS_PATH} is missing: npx tsx prototype/vnext-kernel/generation-2/generate-evidence.ts`);
      throw e;
    }
    const norm = (s: string): string => s.split("\r\n").join("\n");
    const expected = JSON.parse(norm(committed)) as Gen2Census;
    // The hashes are over LF-normalised bytes in the receipt; a CRLF checkout must not read as stale.
    expect(expected.comparisonWithGeneration1).to.deep.equal(census.comparisonWithGeneration1);
    expect(expected.derivedVerdict).to.deep.equal(census.derivedVerdict);
    expect(expected.effectSurface).to.deep.equal(census.effectSurface);
    expect(expected.bodyIdentity).to.deep.equal(census.bodyIdentity);
  });

  describe("the verdict has teeth: each mutant must change its answer", function () {
    const stillClean = (c: Gen2Census): boolean => c.derivedVerdict.verdict === "NO_NEW_PRIVILEGED_PRINCIPAL";

    const CASES: { id: string; apply: () => Record<string, string>; reason: RegExp }[] = [
      {
        id: "M-G2-10: msg.sender gains privilege in _authorise",
        apply: () => ({
          [KERNEL_FILE]: replaceWithinFunction(
            kernel,
            "_authorise",
            "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
            "if (msg.sender == address(0x1234)) return;\n        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
          ),
        }),
        reason: /caller identity/,
      },
      {
        id: "a new storage word holding an address",
        apply: () => ({
          [KERNEL_FILE]: kernel.replace(
            "function _balanceOf(address asset) internal view returns (uint256) {",
            "address public relayerRoot;\n\n    function _balanceOf(address asset) internal view returns (uint256) {",
          ),
        }),
        reason: /new storage word/,
      },
      {
        id: "a new state-changing selector",
        apply: () => ({
          [KERNEL_FILE]: kernel.replace(
            "function _balanceOf(address asset) internal view returns (uint256) {",
            "function poke() external {\n        credentialGeneration += 1;\n    }\n\n    function _balanceOf(address asset) internal view returns (uint256) {",
          ),
        }),
        reason: /./,
      },
      {
        id: "an unexpected external edge: execute approves as well as transfers",
        apply: () => ({
          [KERNEL_FILE]: replaceWithinFunction(
            kernel,
            "execute",
            "uint256 remaining = _balanceOf(asset);",
            "(bool approved, ) = recipient.call(abi.encodeWithSelector(0x095ea7b3, recipient, amount));\n        approved;\n        uint256 remaining = _balanceOf(asset);",
          ),
        }),
        reason: /unexpected external edge/,
      },
      {
        id: "a factory with a setter",
        apply: () => ({
          [FACTORY_FILE]: factory.replace(
            "/// @notice The counterfactual address for a genesis configuration.",
            "address public owner;\n\n    function setOwner(address o) external {\n        owner = o;\n    }\n\n    /// @notice The counterfactual address for a genesis configuration.",
          ),
        }),
        reason: /factory/,
      },
    ];

    for (const c of CASES) {
      it(c.id, function () {
        const mutated = runGen2Census({ overrides: c.apply() });
        expect(stillClean(mutated), "the census did not notice").to.equal(false);
        expect(mutated.derivedVerdict.reasons.join(" | ")).to.match(c.reason);
      });
    }

    it("deriveVerdict itself: an empty reason list is the only way to the clean verdict", function () {
      const clean = {
        checkerFailed: 0,
        callerIdentity: [],
        factoryCallerIdentity: [],
        addedAddressHolders: [],
        addedStateVariables: [],
        changedMechanisms: [],
        addedStateChangingSelectors: [],
        removedStateChangingSelectors: [],
        changedStateEffects: [],
        factoryStateChangingFunctions: ["deployVault"],
        factoryMutableStorage: [],
        newEdges: { added: [], removed: [] },
        unexpectedNewEdges: [],
      };
      expect(deriveVerdict(clean).verdict).to.equal("NO_NEW_PRIVILEGED_PRINCIPAL");
      expect(deriveVerdict({ ...clean, checkerFailed: 1 }).verdict).to.equal("NEW_AUTHORITY_SURFACE_REQUIRES_REVIEW");
    });
  });
});
