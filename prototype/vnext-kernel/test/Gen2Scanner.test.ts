/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * THE SCANNER BOUNDARY: row SCANNER-BOUNDARY. A scanner result is current only while its inputs are byte-equal,
 * so a change to the candidate fails here until Slither is re-run. Every exception must carry its whole
 * justification, and its dynamic property and mutant must be real names in real catalogues. The prohibited-pattern
 * checks are the part that needs no external tool, so they run on the candidate's real bytes on every run.
 */
import { expect } from "chai";
import fs from "node:fs";

import { GEN2_FACTORY, GEN2_KERNEL, gen2Unit } from "../generation-2/compile.js";
import {
  ADJUDICATIONS,
  SCANNER_RUN_PATH,
  SCANNER_TARGET,
  analyzedSources,
  type ScannerRun,
} from "../generation-2/scanner.js";
import { G2_PROPERTIES } from "../generation-2/stateful/invariants.js";
import { G2_MUTATIONS } from "../generation-2/stateful/mutants.js";
import { GLOBAL_INVARIANTS } from "../stateful/invariants.js";
import { MUTATIONS } from "../stateful/mutants.js";
import { DECLARED_CUTS } from "../stateful/model.js";

const FORBIDDEN_OPCODES: Readonly<Record<string, number>> = {
  DELEGATECALL: 0xf4,
  CALLCODE: 0xf2,
  CREATE: 0xf0,
  CREATE2: 0xf5,
  SELFDESTRUCT: 0xff,
};

const TERMINATORS: ReadonlySet<number> = new Set([0x00, 0x56, 0xf3, 0xfd, 0xfe, 0xff]);
const JUMPDEST = 0x5b;

/**
 * A linear sweep that skips what cannot execute. Stepping over PUSH data is not enough: the compiler places a
 * 32-byte constant after the kernel's last INVALID, and one of its bytes is 0xf5, which a naive sweep reads as
 * CREATE2 (Generation 1 carries the same word). After a terminator, nothing runs until the next JUMPDEST.
 */
function opcodeCensus(bytecode: string): Record<string, number> {
  const code = Buffer.from(bytecode.replace(/^0x/, ""), "hex");
  const counts: Record<string, number> = Object.fromEntries(Object.keys(FORBIDDEN_OPCODES).map((k) => [k, 0]));
  const metadataLength = code.readUInt16BE(code.length - 2) + 2;
  const end = code.length - metadataLength;
  let dead = false;
  for (let i = 0; i < end; i++) {
    const op = code[i]!;
    if (dead) {
      if (op === JUMPDEST) dead = false;
      continue;
    }
    if (op >= 0x60 && op <= 0x7f) {
      i += op - 0x5f;
      continue;
    }
    for (const [name, value] of Object.entries(FORBIDDEN_OPCODES)) if (op === value) counts[name]!++;
    if (TERMINATORS.has(op)) dead = true;
  }
  return counts;
}

describe("Generation-2 admission — the scanner boundary", function () {
  this.timeout(120_000);

  const run = JSON.parse(fs.readFileSync(SCANNER_RUN_PATH, "utf8")) as ScannerRun;
  const properties = new Set<string>([
    ...G2_PROPERTIES.map((p) => p.name),
    ...GLOBAL_INVARIANTS.map((g) => g.name),
    ...Object.keys(DECLARED_CUTS).map((o) => "P-CUT/" + o),
    "P-MODEL",
    "P-INCOMING-POSSESSION",
    "P-PLANE-SUBTRACTIVE",
    "P-ATOMICITY",
  ]);
  const mutants = new Set<string>([...G2_MUTATIONS.map((m) => m.id), ...MUTATIONS.map((m) => m.id)]);

  describe("Slither ran on the candidate itself, and its result is current", function () {
    it("the target is the candidate's tree, and no Generation-1 result is carried", function () {
      expect(run.tool.target).to.equal(SCANNER_TARGET);
      expect(run.tool.slitherCommit).to.equal("ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad");
      expect(run.analyzedSources.every((s) => s.path.startsWith(SCANNER_TARGET))).to.equal(true);
    });

    it("every analysed source is byte-equal to what was scanned", function () {
      expect(
        run.analyzedSources,
        "the candidate changed after Slither ran: re-run it and regenerate generation-2/scanner-run.json",
      ).to.deep.equal(analyzedSources());
    });

    it("the record carries no machine path", function () {
      const text = fs.readFileSync(SCANNER_RUN_PATH, "utf8");
      expect(text).to.not.match(/\/root\/|\/mnt\/|C:\\\\|\/home\/|filename_absolute/);
    });
  });

  describe("adjudication", function () {
    it("every finding on the candidate's kernel and factory is PASS_WITH_DECLARED_EXCEPTION with its whole justification", function () {
      const candidate = run.distinctOwnFindings.filter((r) => r.classification !== "TEST_FIXTURE_BY_DESIGN");
      expect(candidate.length).to.equal(run.kernelAndFactoryFindings);
      expect(candidate.length).to.be.greaterThan(0);
      for (const r of candidate) {
        expect(r.classification, r.key).to.equal("PASS_WITH_DECLARED_EXCEPTION");
        expect(r.sourceLocation.length, r.key).to.be.greaterThan(0);
        const a = ADJUDICATIONS[r.key];
        expect(a, r.key).to.not.equal(undefined);
        expect(a!.rationale.length, r.key).to.be.greaterThan(20);
        expect(a!.whyStaticAnalysisCannotResolve, r.key).to.be.a("string");
        expect(
          properties.has(a!.dynamicProperty!),
          `${r.key} names ${a!.dynamicProperty}, which no campaign checks`,
        ).to.equal(true);
        expect(mutants.has(a!.mutant!), `${r.key} names ${a!.mutant}, which no catalogue has`).to.equal(true);
      }
    });

    it("no adjudication is left over from a finding that no longer exists", function () {
      const live = new Set(run.distinctOwnFindings.map((r) => r.key));
      expect(Object.keys(ADJUDICATIONS).filter((k) => !live.has(k))).to.deep.equal([]);
    });

    it("the fixture's rows are only in the fixture", function () {
      for (const r of run.distinctOwnFindings.filter((x) => x.classification === "TEST_FIXTURE_BY_DESIGN")) {
        expect(
          r.sourceLocation.every((s) => s.includes("Gen2TokenZoo.sol")),
          r.key,
        ).to.equal(true);
      }
    });
  });

  describe("prohibited patterns, on the candidate's real bytes and AST", function () {
    it("the opcode sweep: no DELEGATECALL, CALLCODE, CREATE, CREATE2 or SELFDESTRUCT anywhere in the kernel's executable code", function () {
      expect(opcodeCensus(gen2Unit(GEN2_KERNEL).deployedBytecode)).to.deep.equal({
        DELEGATECALL: 0,
        CALLCODE: 0,
        CREATE: 0,
        CREATE2: 0,
        SELFDESTRUCT: 0,
      });
    });

    it("the sweep has teeth: the factory's CREATE2 and the standard clone's DELEGATECALL are both seen", function () {
      expect(
        opcodeCensus(gen2Unit(GEN2_FACTORY).deployedBytecode).CREATE2,
        "the factory really does CREATE2",
      ).to.be.greaterThan(0);
      const clone = "0x363d3d373d3d3d363d73" + "11".repeat(20) + "5af43d82803e903d91602b57fd5bf3" + "0002";
      const census = opcodeCensus(clone);
      expect(census.DELEGATECALL, "a clone really does DELEGATECALL").to.equal(1);
    });

    it("the source names no caller identity, no owner, no pause, and no upgrade path", function () {
      const source = fs
        .readFileSync(`${SCANNER_TARGET}/VaultKernelGen2Prototype.sol`, "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      for (const pattern of [
        /\bmsg\.sender\b/,
        /\btx\.origin\b/,
        /\bonlyOwner\b/,
        /\bowner\b/,
        /\bdelegatecall\b/,
        /\bselfdestruct\b/,
        /\bupgradeTo\b/,
        /\bpause\b/,
      ]) {
        expect(pattern.test(source), String(pattern)).to.equal(false);
      }
    });

    it("no function selector on the kernel can move an allowance or an arbitrary payload", function () {
      const names = Object.keys(gen2Unit(GEN2_KERNEL).methodIdentifiers);
      expect(names.filter((n) => /approve|permit|multicall|delegate|isValidSignature|onERC/i.test(n))).to.deep.equal(
        [],
      );
    });
  });
});
