import { expect } from "chai";
import {
  extractFunctionBody,
  functionsThatMutateArrayMapping,
  readContractSource,
  stripComments,
} from "./helpers/solidityStructure";

// Structural assurance pinned to FUNCTION NAMES, not line numbers — a future edit
// that reorders or reformats the file cannot silently defeat these checks, but an
// edit that adds a new external call, a new guardian-write path, or a new
// rotation->recovery coupling will. See docs/Guardian_Authority_Design.md §9.1
// L-I, §14.2 regression #2, and §10.1 item 3.

const CONTRACTS = [
  { name: "WalletWallVault", path: "contracts/WalletWallVault.sol" },
  { name: "StablecoinVaultSimulator", path: "contracts/StablecoinVaultSimulator.sol" },
];

// The only two external-contract-typed trust boundaries this recovery path could
// possibly reach through, plus the low-level call primitive and inline interface
// casts, so a future edit can't route around the named state variables.
const EXTERNAL_CALL_MARKERS = ["pqVerifier", "policyEngine", "IPolicyEngine(", "IPQCVerifier(", ".call(", ".call{"];

const RECOVERY_ENTRY_POINTS = ["initiateRecovery", "supportRecovery", "executeRecovery", "cancelRecovery"];

describe("Recovery structural assurance (L-I)", function () {
  for (const { name, path } of CONTRACTS) {
    describe(name, function () {
      const source = stripComments(readContractSource(path));

      for (const fn of RECOVERY_ENTRY_POINTS) {
        it(`${fn} makes no external call`, function () {
          const body = extractFunctionBody(source, fn);
          for (const marker of EXTERNAL_CALL_MARKERS) {
            expect(body, `${fn} body must not reference "${marker}"`).to.not.include(marker);
          }
        });
      }

      it("only setGuardians writes vaultGuardians (credential authority cannot gain guardian writes)", function () {
        const writers = functionsThatMutateArrayMapping(readContractSource(path), "vaultGuardians");
        expect(writers).to.deep.equal(["setGuardians"]);
      });

      it("rotateCredentials and _authorizeRotation never reference recoveryRequests", function () {
        // Design doc §10.1 item 3: a structural guard that a future "fix" cannot
        // reintroduce cancel-on-rotation without this test catching it. Stronger
        // than the design doc's literal "no call that writes recoveryRequests" —
        // this repo's rotation code never even READS recoveryRequests, so asserting
        // the identifier is absent is sufficient and does not depend on resolving
        // storage-pointer aliases.
        for (const fn of ["rotateCredentials", "_authorizeRotation"]) {
          const body = extractFunctionBody(source, fn);
          expect(body, `${fn} body must not reference recoveryRequests`).to.not.match(/\brecoveryRequests\b/);
        }
      });
    });
  }
});
