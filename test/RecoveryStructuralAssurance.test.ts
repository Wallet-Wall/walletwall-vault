import { expect } from "chai";
import { findExternalCallFindings } from "./helpers/astExternalCallAnalysis";
import { functionsThatMutateStorageMapping } from "./helpers/astStorageMutationAnalysis";
import { findContract, findFunctionDefinition, loadSourceAst } from "./helpers/solidityAst";
import { extractFunctionBody, readContractSource, stripComments } from "./helpers/solidityStructure";

// Structural assurance pinned to FUNCTION NAMES, not line numbers — a future edit
// that reorders or reformats the file cannot silently defeat these checks, but an
// edit that adds a new external call, a new guardian-write path, or a new
// rotation->recovery coupling will. See docs/Guardian_Authority_Design.md §9.1
// L-I, §14.2 regression #2, and §10.1 item 3.
//
// AST-backed, not regex-backed: an earlier version of this file searched function
// bodies for a finite marker list (`"pqVerifier"`, `".call("`, ...) and matched
// `vaultGuardians[...] =` textually. Both were false proof — a differently-named
// external dependency, or a mutation through a local storage alias
// (`address[] storage gs = vaultGuardians[o]; gs.push(x);`), would pass either
// check unnoticed. This file now reads the solc AST that `hardhat compile`
// already emits into artifacts/build-info/*.output.json (see
// test/helpers/solidityAst.ts) and classifies every call by its resolved TYPE,
// not by name, and tracks storage aliases through the AST rather than text.

const CONTRACTS = [
  { name: "WalletWallVault", path: "contracts/WalletWallVault.sol" },
  { name: "StablecoinVaultSimulator", path: "contracts/StablecoinVaultSimulator.sol" },
];

const RECOVERY_ENTRY_POINTS = ["initiateRecovery", "supportRecovery", "executeRecovery", "cancelRecovery"];

describe("Recovery structural assurance (L-I)", function () {
  describe("real contracts", function () {
    for (const { name, path } of CONTRACTS) {
      describe(name, function () {
        const sourceUnitAst = loadSourceAst(path);
        const contractAst = findContract(sourceUnitAst, name);

        for (const fn of RECOVERY_ENTRY_POINTS) {
          it(`${fn} makes no external call (AST-verified)`, function () {
            const fnAst = findFunctionDefinition(contractAst, fn);
            const findings = findExternalCallFindings(fnAst.body);
            expect(findings, `${fn}: ${JSON.stringify(findings)}`).to.deep.equal([]);
          });
        }

        it("only setGuardians writes vaultGuardians (credential authority cannot gain guardian writes)", function () {
          const writers = functionsThatMutateStorageMapping(sourceUnitAst, name, "vaultGuardians");
          expect(writers).to.deep.equal(["setGuardians"]);
        });
      });
    }
  });

  // ---------------------------------------------------------------------------
  // Mutation controls: each fixture below is a minimal, independently compiled
  // contract (contracts/mocks/AssuranceCallMutants.sol,
  // contracts/mocks/AssuranceGuardianWriteMutants.sol — never the production
  // contracts) reproducing one evasion of the OLD regex/marker check. Every one
  // of these MUST be caught by the AST-backed checkers above, or the checkers
  // are not proving what the real-contract tests above claim.
  // ---------------------------------------------------------------------------

  describe("mutation controls — external-call classifier", function () {
    const callMutantsAst = loadSourceAst("contracts/mocks/AssuranceCallMutants.sol");

    it("M1 arbitrary typed external call is FLAGGED", function () {
      const fn = findFunctionDefinition(findContract(callMutantsAst, "M1ArbitraryExternalCall"), "executeRecovery");
      const findings = findExternalCallFindings(fn.body);
      expect(findings).to.have.length.greaterThan(0);
      expect(findings[0].receiverTypeString).to.match(/^contract /);
    });

    it("M2 renamed external dependency (not pqVerifier/policyEngine) is FLAGGED", function () {
      const fn = findFunctionDefinition(
        findContract(callMutantsAst, "M2RenamedExternalDependency"),
        "initiateRecovery",
      );
      const findings = findExternalCallFindings(fn.body);
      expect(findings).to.have.length.greaterThan(0);
      expect(findings[0].receiverTypeString).to.match(/^contract /);
    });

    it("M3 plain low-level .call is FLAGGED", function () {
      const fn = findFunctionDefinition(findContract(callMutantsAst, "M3LowLevelCall"), "executeRecovery");
      const findings = findExternalCallFindings(fn.body);
      expect(findings).to.have.length.greaterThan(0);
      expect(findings[0].memberName).to.equal("call");
    });

    it("M4 every other low-level call form (staticcall/delegatecall/send/transfer) is FLAGGED", function () {
      const contractAst = findContract(callMutantsAst, "M4OtherLowLevelCallForms");
      const expected: Record<string, string> = {
        viaStaticcall: "staticcall",
        viaDelegatecall: "delegatecall",
        viaSend: "send",
        viaTransfer: "transfer",
      };
      for (const [fnName, member] of Object.entries(expected)) {
        const fn = findFunctionDefinition(contractAst, fnName);
        const findings = findExternalCallFindings(fn.body);
        expect(findings, fnName).to.have.length.greaterThan(0);
        expect(findings[0].memberName, fnName).to.equal(member);
      }
    });

    it("M5 inline interface cast immediately invoked is FLAGGED", function () {
      const fn = findFunctionDefinition(findContract(callMutantsAst, "M5InlineInterfaceCast"), "executeRecovery");
      const findings = findExternalCallFindings(fn.body);
      expect(findings).to.have.length.greaterThan(0);
      expect(findings[0].receiverTypeString).to.match(/^contract /);
    });

    it("M8 control: an internal helper call PASSES (checker isn't rejecting every FunctionCall)", function () {
      const fn = findFunctionDefinition(findContract(callMutantsAst, "M8InternalHelperControl"), "executeRecovery");
      const findings = findExternalCallFindings(fn.body);
      expect(findings).to.deep.equal([]);
    });
  });

  describe("mutation controls — guardian-write allowlist", function () {
    const writeMutantsAst = loadSourceAst("contracts/mocks/AssuranceGuardianWriteMutants.sol");

    it("M6 direct writes bypassing setGuardians are FLAGGED (assignment, delete, and direct non-alias push)", function () {
      const writers = functionsThatMutateStorageMapping(writeMutantsAst, "M6DirectGuardianWrite", "vaultGuardians");
      expect(writers).to.have.members(["setGuardians", "evilDirectWrite", "evilDelete", "evilDirectPush"]);
      expect(writers).to.have.length(4);
    });

    it("M7 a mutation through a local storage alias (gs.push) is FLAGGED", function () {
      const writers = functionsThatMutateStorageMapping(writeMutantsAst, "M7AliasGuardianWrite", "vaultGuardians");
      expect(writers).to.have.members(["setGuardians", "evilAliasPush"]);
      expect(writers).to.have.length(2);
    });
  });

  describe("H3 structural pin: rotateCredentials / _authorizeRotation never reference recoveryRequests", function () {
    // This is a genuinely lexical claim, not a call-graph claim — design doc
    // §10.1 item 3's literal ask ("no call that writes recoveryRequests") is
    // satisfied here by the STRONGER and simpler fact that this repo's rotation
    // code never even reads recoveryRequests, so asserting the identifier is
    // absent from the body text is exact, not an approximation, and does not
    // need AST/alias analysis to be true. Left as a source-text check
    // deliberately (see Step 8 disposition in the accompanying report).
    for (const { name, path } of CONTRACTS) {
      it(`${name}: rotateCredentials and _authorizeRotation never reference recoveryRequests`, function () {
        const source = stripComments(readContractSource(path));
        for (const fn of ["rotateCredentials", "_authorizeRotation"]) {
          const body = extractFunctionBody(source, fn);
          expect(body, `${fn} body must not reference recoveryRequests`).to.not.match(/\brecoveryRequests\b/);
        }
      });
    }
  });
});
