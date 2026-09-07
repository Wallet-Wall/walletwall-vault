/**
 * SCANNER ENFORCEMENT — the gaps that were still open after semantic identity landed.
 *
 * Identity stopped a moved finding from losing its adjudication. It did not stop any of these:
 *
 *   A. The hashed scanner config was TRANSCRIBED from the workflow, so the two could drift and
 *      `scannerSemanticConfigSha256` would keep attesting to a configuration nothing runs.
 *   B. `SCANNER_EVIDENCE.json` was hand-editable. Every field outside the triage census could be
 *      changed with 217/54/33 and all 33 entries still valid, and nothing compared bytes.
 *   C. `normaliseSolidity` stripped comments with regexes, which cannot tell a comment marker from
 *      the same characters inside a STRING LITERAL. A URL, revert string or ABI signature
 *      containing a double slash had everything after it erased, so two revisions differing only
 *      there fingerprinted identically and a real change reported UNCHANGED.
 *   D. Nothing enforced that a receipt may not name its own publication container by FIELD NAME,
 *      only by value.
 *
 * Each block below fails against the state before this lane and passes after. The workflow-drift
 * block mutates a real copy of the workflow per semantic field rather than asserting on a summary,
 * because a verifier that reads the wrong text agrees just as confidently as one that reads the
 * right text -- which is exactly what happened on the first attempt here: the extractor matched
 * `--compile-force-framework solc,` and ``fail-on: none` `` out of the workflow's own PROSE, and
 * reported agreement it had never established.
 */
import { expect } from "chai";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { normaliseSolidity, FINGERPRINT_ALGORITHM } from "../scanner-finding-identity.js";
import {
  assertWorkflowMatchesPinnedConfig,
  assertWorkflowOutputContract,
  readWorkflowScannerConfig,
  WORKFLOW_PATH,
  WORKFLOW_UNPINNED,
} from "../scanner-workflow-config.js";
import { assertNoContainerFields, FORBIDDEN_RECEIPT_FIELDS } from "../generate-scanner-evidence.js";
import { PINNED_SEMANTIC_CONFIG } from "../scanner-input-scope.js";

const TRIAGE_PATH = path.join("prototype", "vnext-kernel", "slither-triage.json");

/** Writes a mutated copy of the workflow to a temp file, so the real one is never touched. */
function workflowWith(replace: [string, string]): string {
  const original = fs.readFileSync(WORKFLOW_PATH, "utf8");
  const [from, to] = replace;
  expect(original, `mutation anchor absent: ${from}`).to.contain(from);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "wf-")), "workflow.yml");
  fs.writeFileSync(file, original.replace(from, to));
  return file;
}

describe("scanner enforcement", () => {
  describe("A. the hashed config must describe what the workflow runs", () => {
    it("agrees with the real workflow across every comparable field", () => {
      const result = assertWorkflowMatchesPinnedConfig();
      expect(result.equal).to.equal(true);
      expect(result.checked).to.have.members([
        "slitherCommit", "solc", "evmVersion", "optimizer.enabled", "optimizer.runs",
        "remaps", "target", "compileFramework", "dependencyPolicy",
      ]);
    });

    it("reads CONFIGURATION, not the workflow's own prose about it", () => {
      // The workflow comments quote these flags verbatim. Extracting from raw text captured
      // "solc," and "none`" from those comments -- the first version of this verifier compared
      // documentation to the constant and called it agreement.
      const w = readWorkflowScannerConfig();
      expect(w.compileFramework, "captured from a comment if this has a trailing comma").to.equal("solc");
      expect(w.failOn, "captured from a comment if this has a backtick").to.equal("none");
    });

    /*
     * Each entry carries the message it is EXPECTED to be caught by. Two distinct mechanisms are
     * legitimate: a value that differs from the constant is caught by the comparison, while a
     * value the extractor can no longer locate at all is caught by its fail-closed anchor guard --
     * the stronger of the two, since it refuses to compare rather than comparing a default.
     * Asserting one blanket message would have hidden which mechanism actually fired.
     */
    const SEMANTIC_MUTATIONS: Array<[string, [string, string], RegExp]> = [
      ["slither commit", ["slither-version: ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad", "slither-version: aaaabbbbccccddddeeeeffff00001111222233334"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["solc", ['solc-version: "0.8.24"', 'solc-version: "0.8.26"'], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["evm version", ["--evm-version cancun", "--evm-version shanghai"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["optimizer runs", ["--optimize-runs 200", "--optimize-runs 999"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["optimizer enabled", ["--optimize --optimize-runs 200", "--optimize-runs 200"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["remap", ['--solc-remaps "@openzeppelin/=node_modules/@openzeppelin/"', '--solc-remaps "@oz/=node_modules/@openzeppelin/"'], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["target", ["          target: prototype/vnext-kernel/contracts", "          target: contracts"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["compile framework", ["            --compile-force-framework solc", "            --compile-force-framework hardhat"], /no longer matches PINNED_SEMANTIC_CONFIG/],
      ["dependency policy", ["            --exclude-dependencies", "            --include-dependencies"], /--exclude-dependencies is absent/],
    ];

    for (const [name, mutation, expected] of SEMANTIC_MUTATIONS) {
      it(`KILL: detects a changed ${name} while PINNED_SEMANTIC_CONFIG stays untouched`, () => {
        expect(() => assertWorkflowMatchesPinnedConfig(workflowWith(mutation))).to.throw(expected);
      });
    }

    it("fails closed when an anchor cannot be found at all", () => {
      expect(() => readWorkflowScannerConfig(workflowWith(["          solc-version: \"0.8.24\"", ""]))).to.throw(
        /could not locate solc-version/,
      );
    });

    it("states what the workflow does NOT pin, rather than implying full coverage", () => {
      expect(Object.keys(WORKFLOW_UNPINNED)).to.deep.equal(["crypticCompile"]);
      expect(PINNED_SEMANTIC_CONFIG.crypticCompile, "still hashed — it does affect results").to.be.a("string");
    });

    it("KILL: refuses if the workflow stops emitting raw JSON, drops SARIF, or starts gating", () => {
      expect(() => assertWorkflowOutputContract(workflowWith(["            --json prototype/vnext-kernel/slither-raw.json\n", ""]))).to.throw(/--json is gone/);
      expect(() => assertWorkflowOutputContract(workflowWith(["          sarif: slither-vnext-kernel-results.sarif", "          # removed"]))).to.throw(/SARIF output is gone/);
      expect(() => assertWorkflowOutputContract(workflowWith(["          fail-on: none", "          fail-on: high"]))).to.throw(/fail-on is "high"/);
    });

    it("POSITIVE CONTROL: an unrelated workflow edit does not trip either check", () => {
      const benign = workflowWith(["    timeout-minutes: 30", "    timeout-minutes: 31"]);
      expect(() => assertWorkflowMatchesPinnedConfig(benign)).to.not.throw();
      expect(() => assertWorkflowOutputContract(benign)).to.not.throw();
    });
  });

  describe("C. the fingerprint normaliser must not erase string contents", () => {
    const changed = (a: string, b: string) => normaliseSolidity(a) !== normaliseSolidity(b);

    it("KILL: a change inside a URL string is visible", () => {
      expect(changed('string constant X = "https://example.com/a";', 'string constant X = "https://example.com/b";')).to.equal(true);
    });
    it("KILL: a change after a double slash inside a string is visible", () => {
      expect(changed('revert("literal // not comment A");', 'revert("literal // not comment B");')).to.equal(true);
    });
    it("KILL: a change inside a slash-star sequence within a string is visible", () => {
      expect(changed('revert("literal /* not comment A */");', 'revert("literal /* not comment B */");')).to.equal(true);
    });
    it("KILL: single-quoted literals are protected too", () => {
      expect(changed("emit E('a//b');", "emit E('a//c');")).to.equal(true);
    });
    it("KILL: an escaped quote does not end the literal early", () => {
      expect(changed('revert("say \\" // x A");', 'revert("say \\" // x B");')).to.equal(true);
    });

    it("POSITIVE CONTROL: real comments are still stripped", () => {
      expect(normaliseSolidity("x = 1; // note A")).to.equal(normaliseSolidity("x = 1;   /* note B */"));
      expect(normaliseSolidity("x = 1;")).to.equal("x = 1;");
    });

    it("NO-OP CONTROL: whitespace reflow alone is not a change", () => {
      expect(normaliseSolidity("if (a > b) {\n  c();\n}")).to.equal(normaliseSolidity("if  (a > b)  { c(); }"));
    });

    it("the triage records the algorithm its stored fingerprints came from", () => {
      const triage = JSON.parse(fs.readFileSync(TRIAGE_PATH, "utf8"));
      expect(triage.keyedAt.fingerprintAlgorithm).to.equal(FINGERPRINT_ALGORITHM);
    });
  });

  describe("D. a receipt may not carry a container-shaped field", () => {
    it("KILL: rejects each forbidden field name", () => {
      for (const field of FORBIDDEN_RECEIPT_FIELDS) {
        expect(() => assertNoContainerFields({ [field]: "x" }), field).to.throw(/is forbidden/);
      }
    });
    it("KILL: rejects one nested anywhere in the object", () => {
      expect(() => assertNoContainerFields({ a: { b: [{ containerHead: "x" }] } })).to.throw(/a\.b\.0\.containerHead/);
    });
    it("KILL: rejects the v1 head/tree stamping shape specifically", () => {
      expect(() => assertNoContainerFields({ head: "abc", tree: "def" })).to.throw(/is forbidden/);
    });
    it("POSITIVE CONTROL: the real receipt's declared subjects are allowed", () => {
      expect(() =>
        assertNoContainerFields({
          sourceSubject: "a".repeat(40), sourceTree: "b".repeat(40),
          triageSubject: "c".repeat(40), triageTree: "d".repeat(40),
        }),
      ).to.not.throw();
    });
    it("the committed receipt carries none of them", () => {
      const receipt = JSON.parse(fs.readFileSync(path.join("prototype", "vnext-kernel", "SCANNER_EVIDENCE.json"), "utf8"));
      expect(() => assertNoContainerFields(receipt)).to.not.throw();
    });
  });
});
