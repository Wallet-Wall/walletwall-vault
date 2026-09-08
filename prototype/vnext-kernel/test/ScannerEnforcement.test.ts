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

import {
  normaliseSolidity,
  FINGERPRINT_ALGORITHM,
  indexFindings,
  type SlitherFinding,
  type SourceReader,
} from "../scanner-finding-identity.js";
import {
  assertWorkflowMatchesPinnedConfig,
  assertWorkflowOutputContract,
  readWorkflowScannerConfig,
  WORKFLOW_PATH,
  WORKFLOW_UNPINNED,
  assertScannerRequirementsPinned,
  assertWorkflowUsesRequirements,
} from "../scanner-workflow-config.js";
import {
  assertNoContainerFields,
  readScannerEvidenceInputs,
  FORBIDDEN_RECEIPT_FIELDS,
  RECEIPT_SCHEMA,
  OUT_OF_DOMAIN_RECEIPT_FIELDS,
  assertReceiptDomain,
} from "../generate-scanner-evidence.js";
import { PINNED_SEMANTIC_CONFIG } from "../scanner-input-scope.js";
import {
  canonicalAllFindingsSha256,
  canonicalDistinctOwnFindingsSha256,
} from "../scanner-canonical-digest.js";

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

    it("leaves NO semantic field merely documented as unpinned", () => {
      // This assertion used to read `deep.equal(["crypticCompile"])` and passed while that
      // dependency was resolved from a RANGE. Documenting a gap is not closing it: the observed
      // 0.4.2 was a resolution, and nothing stopped the next install taking 0.4.3. It is now
      // pinned exactly in scanner-requirements.txt, so the list is empty and must stay empty.
      expect(Object.keys(WORKFLOW_UNPINNED)).to.deep.equal([]);
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

/**
 * CANONICAL SCANNER-OUTPUT DIGESTS and the EXACT crytic-compile pin.
 *
 * WHAT WENT WRONG. The receipt carried `rawOutputSha256` -- sha256 of the whole Slither --json
 * file -- and the byte-identity check failed in CI at 0129e2ed while every security-relevant
 * quantity agreed exactly: 217 raw, 54 own rows, 33 distinct, 0 untriaged/stale/ambiguous,
 * 8/15/5/5. Local 054135ac, CI 47c5ed50.
 *
 * The CI output was uploaded as an artifact and diffed. Two causes, both invisible to a whole-file
 * hash: RESULT ORDERING (144 of 217 array positions held a different finding) and the WORKSPACE
 * ROOT inside `filename_absolute`. Nothing else differed -- normalising the root and sorting made
 * the two multisets byte-identical, 0 only-local and 0 only-CI. Substituting the CI root into the
 * local file did NOT reproduce the CI hash, which is what ruled out "paths are the only cause"
 * rather than assuming it.
 *
 * The fixtures below are MINIMIZED EXCERPTS selected and derived from the historical real local
 * and CI outputs -- not the full outputs themselves. The full pair was 10,324,917 bytes, 91% of
 * this stack's entire insertion count, mostly parent-chain line arrays the digest never reads. The
 * excerpts preserve every discriminator, proven by running this exact matrix against both pairs and
 * comparing verdicts; their historical sha256s are recorded in SCANNER_IDENTITY_CORRECTION_RECORD
 * section 13. Replacing them reduces the CURRENT TREE and future checkout/diff footprint; it does
 * NOT remove the historical blobs from git history, and no rewrite is attempted.
 */
describe("canonical scanner-output digests", () => {
  const RAW_LOCAL = path.join("prototype", "vnext-kernel", "test", "fixtures", "scanner", "raw-findings.local.json");
  const RAW_CI = path.join("prototype", "vnext-kernel", "test", "fixtures", "scanner", "raw-findings.ci.json");
  const load = (p: string): SlitherFinding[] => JSON.parse(fs.readFileSync(p, "utf8")).detectors;
  const BASE = () => canonicalAllFindingsSha256(load(RAW_LOCAL));

  it("the excerpts still differ in the real measured environment dimensions", () => {
    const a = fs.readFileSync(RAW_LOCAL, "utf8");
    const b = fs.readFileSync(RAW_CI, "utf8");
    expect(a, "excerpts must differ, or every control below is vacuous").to.not.equal(b);
    // dimension 1: workspace root
    expect(a).to.contain("/root/w2s/repo");
    expect(b).to.contain("/github/workspace");
    // dimension 2: result order -- the dominant cause, and the one a whole-file hash cannot see
    const order = (t: string) => JSON.parse(t).detectors.map((f: { check: string }) => f.check).join(",");
    expect(order(a), "the CI excerpt must preserve a real order difference").to.not.equal(order(b));
    // and they are excerpts, not the historical full outputs
    expect(JSON.parse(a).detectors.length).to.be.lessThan(217);
  });

  it("CONTROL: a different absolute workspace prefix does not move the digest", () => {
    expect(canonicalAllFindingsSha256(load(RAW_CI))).to.equal(BASE());
  });

  it("CONTROL: a different result order does not move the digest", () => {
    expect(canonicalAllFindingsSha256([...load(RAW_LOCAL)].reverse())).to.equal(BASE());
  });

  it("CONTROL: different key order and whitespace do not move the digest", () => {
    const findings = load(RAW_LOCAL);
    const reserialized = (JSON.parse(JSON.stringify(findings, null, 4)) as Array<Record<string, unknown>>).map((f) => {
      const flipped: Record<string, unknown> = {};
      for (const k of Object.keys(f).reverse()) flipped[k] = f[k];
      return flipped as unknown as SlitherFinding;
    });
    expect(canonicalAllFindingsSha256(reserialized)).to.equal(BASE());
  });

  const mutate = (fn: (f: Record<string, any>) => void) => {
    const findings = JSON.parse(JSON.stringify(load(RAW_LOCAL)));
    fn(findings[0]);
    return canonicalAllFindingsSha256(findings);
  };

  it("KILL: a changed detector moves the digest", () => {
    expect(mutate((f) => { f.check = "reentrancy-eth"; })).to.not.equal(BASE());
  });
  it("KILL: a changed impact moves the digest", () => {
    expect(mutate((f) => { f.impact = "Critical"; })).to.not.equal(BASE());
  });
  it("KILL: a changed confidence moves the digest", () => {
    expect(mutate((f) => { f.confidence = "Low"; })).to.not.equal(BASE());
  });
  it("KILL: a meaningfully changed detector message moves the digest", () => {
    expect(mutate((f) => { f.description = f.description + " AND SENDS TO AN ATTACKER"; })).to.not.equal(BASE());
  });
  it("KILL: a changed repo-relative source moves the digest", () => {
    expect(mutate((f) => { f.elements[0].source_mapping.filename_relative = "contracts/Other.sol"; })).to.not.equal(BASE());
  });
  it("KILL: a changed element line span moves the digest", () => {
    expect(mutate((f) => { f.elements[0].source_mapping.lines = [9001, 9002]; })).to.not.equal(BASE());
  });
  it("KILL: a changed element signature moves the digest", () => {
    expect(mutate((f) => { f.elements[0].type_specific_fields = { ...(f.elements[0].type_specific_fields || {}), signature: "attack()" }; })).to.not.equal(BASE());
  });
  it("KILL: a removed finding moves the digest", () => {
    expect(canonicalAllFindingsSha256(load(RAW_LOCAL).slice(1))).to.not.equal(BASE());
  });
  it("KILL: an added finding moves the digest", () => {
    const findings = load(RAW_LOCAL);
    const extra = JSON.parse(JSON.stringify(findings[0]));
    extra.check = "brand-new-detector";
    expect(canonicalAllFindingsSha256([...findings, extra])).to.not.equal(BASE());
  });

  it("KILL: a changed classification moves the OWN digest but not the ALL digest", () => {
    const findings = load(RAW_LOCAL);
    const read: SourceReader = () => [];
    const { byId } = indexFindings(findings, read);
    const triage = JSON.parse(fs.readFileSync(TRIAGE_PATH, "utf8")).classifications;
    const honest = (id: string) => triage[id]?.classification ?? "UNTRIAGED";
    const first = [...byId.keys()].sort()[0];
    const tampered = (id: string) => (id === first ? "SUDDENLY_FINE" : honest(id));
    expect(canonicalDistinctOwnFindingsSha256(byId, tampered)).to.not.equal(canonicalDistinctOwnFindingsSha256(byId, honest));
    expect(canonicalAllFindingsSha256(findings), "adjudication is not part of the scanner-output digest").to.equal(BASE());
  });

  it("the classification census is serialized in a deterministic key order", () => {
    // Object insertion order survives into JSON.stringify. Counting findings in the scanner's own
    // emission order made these keys land differently on different machines -- the same five
    // counts, different receipt bytes -- and the receipt regenerated from the CI raw output
    // differed from the local one by nothing else. Sorted keys make the census depend on counts.
    const receipt = JSON.parse(fs.readFileSync(path.join("prototype", "vnext-kernel", "SCANNER_EVIDENCE.json"), "utf8"));
    const keys = Object.keys(receipt.scanners.slither.triagedByClassification);
    expect(keys).to.deep.equal([...keys].sort());
    expect(keys.length, "a single-key census could not detect ordering at all").to.be.greaterThan(1);
  });

  it("the receipt carries both canonical digests and no raw-file hash", () => {
    const receipt = JSON.parse(fs.readFileSync(path.join("prototype", "vnext-kernel", "SCANNER_EVIDENCE.json"), "utf8"));
    expect(receipt.scanners.slither.canonicalAllFindingsSha256).to.match(/^[0-9a-f]{64}$/);
    expect(receipt.scanners.slither.canonicalDistinctOwnFindingsSha256).to.match(/^[0-9a-f]{64}$/);
    expect(receipt.scanners.slither, "a whole-file hash cannot reproduce across machines").to.not.have.property("rawOutputSha256");
  });
});

describe("the scanner receipt's input domain is an allowlist", () => {
  const INPUTS = path.join("prototype", "vnext-kernel", "scanner-evidence-inputs.json");
  const tempInputs = (o: Record<string, unknown>) => {
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "in-")), "scanner-evidence-inputs.json");
    fs.writeFileSync(f, JSON.stringify(o, null, 2));
    return f;
  };
  const valid = () => JSON.parse(fs.readFileSync(INPUTS, "utf8"));

  it("the committed inputs file is v2 and carries only the allowed domain", () => {
    const j = valid();
    expect(j.$schema).to.equal("vnext-kernel-scanner-evidence-inputs.v2");
    expect(Object.keys(j).sort()).to.deep.equal(["$schema", "description", "solhint"]);
    expect(() => readScannerEvidenceInputs(INPUTS)).to.not.throw();
  });

  it("KILL: an exact-schema mismatch is refused", () => {
    expect(() => readScannerEvidenceInputs(tempInputs({ ...valid(), $schema: "vnext-kernel-scanner-evidence-inputs.v1" }))).to.throw(/requires vnext-kernel-scanner-evidence-inputs.v2/);
  });

  // The invariant is UNKNOWN FIELD => FAIL, not "four known-bad names => FAIL". A denylist would
  // have stopped prototypeTests returning and waved through any alias nobody thought to forbid.
  for (const key of ["prototypeTests", "productionNormal", "productionCoverage", "tests", "testExecutionSummary", "prototype_tests", "suiteTotals"]) {
    it(`KILL: reintroducing "${key}" is refused as an unknown input field`, () => {
      expect(() => readScannerEvidenceInputs(tempInputs({ ...valid(), [key]: { passing: 816, failing: 0 } }))).to.throw(/unknown top-level key/);
    });
  }

  it("KILL: solhint with a wrong shape is refused", () => {
    expect(() => readScannerEvidenceInputs(tempInputs({ ...valid(), solhint: { warnings: "36", errors: 0 } }))).to.throw(/solhint must be/);
    expect(() => readScannerEvidenceInputs(tempInputs({ ...valid(), solhint: { warnings: 36, errors: 0, prototypeTests: 816 } }))).to.throw(/unexpected keys/);
  });

  it("POSITIVE CONTROL: the legitimate domain still parses, and yields solhint only", () => {
    const parsed = readScannerEvidenceInputs(INPUTS);
    expect(Object.keys(parsed)).to.deep.equal(["solhint"]);
    expect(parsed.solhint.warnings).to.be.a("number");
  });

  it("the generator declares receipt schema v3", () => {
    expect(RECEIPT_SCHEMA).to.equal("vnext-kernel-scanner-evidence.v3");
  });

  // The GENERATOR is what cannot emit a test count -- asserted as a rule, not as a snapshot of the
  // currently committed file. A snapshot assertion would be red on the implementation commit and
  // green only after the next publication, which is exactly the ordering trap that produced the
  // stale figures. The committed receipt is proven separately, and mechanically, by --check.
  it("KILL: the generator refuses to emit any test-execution field", () => {
    for (const k of OUT_OF_DOMAIN_RECEIPT_FIELDS) {
      expect(() => assertReceiptDomain({ [k]: { passing: 816 } }), k).to.throw(/out of domain for scanner evidence/);
    }
  });

  it("KILL: it refuses one nested anywhere in the receipt", () => {
    expect(() => assertReceiptDomain({ scanners: { slither: { tests: { prototype: 1 } } } })).to.throw(/scanners\.slither\.tests/);
  });

  it("POSITIVE CONTROL: the in-domain scanner fields are accepted", () => {
    expect(() =>
      assertReceiptDomain({
        schema: RECEIPT_SCHEMA,
        sourceSubject: "a".repeat(40),
        scanners: { slither: { rawFindingCount: 217, triagedByClassification: { FALSE_POSITIVE: 8 } }, solhint: { warnings: 36, errors: 0 } },
      }),
    ).to.not.throw();
  });
});

describe("the exact crytic-compile pin", () => {
  const tempReq = (contents: string) => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "req-")), "scanner-requirements.txt");
    fs.writeFileSync(file, contents);
    return file;
  };

  it("scanner-requirements.txt pins exactly the hashed version", () => {
    expect(assertScannerRequirementsPinned().get("crytic-compile")).to.equal(PINNED_SEMANTIC_CONFIG.crypticCompile);
  });

  it("the workflow actually hands that file to the action", () => {
    expect(() => assertWorkflowUsesRequirements()).to.not.throw();
  });

  it("KILL: a simulated 0.4.3 cannot pass the scanner-config authority check", () => {
    expect(() => assertScannerRequirementsPinned(tempReq("crytic-compile==0.4.3\n"))).to.throw(
      /pins crytic-compile==0\.4\.3 but PINNED_SEMANTIC_CONFIG hashes 0\.4\.2/,
    );
  });

  it("KILL: a RANGE is refused — a range is what left it unpinned before", () => {
    expect(() => assertScannerRequirementsPinned(tempReq("crytic-compile<0.5.0,>=0.4.1\n"))).to.throw(/is not an EXACT pin/);
  });

  it("KILL: an empty requirements file is refused, not read as nothing to check", () => {
    expect(() => assertScannerRequirementsPinned(tempReq("# only a comment\n"))).to.throw(/crytic-compile is not pinned/);
  });

  it("KILL: the workflow dropping slither-plugins is refused", () => {
    const wf = workflowWith([
      "          slither-plugins: prototype/vnext-kernel/scanner-requirements.txt",
      "          # removed",
    ]);
    expect(() => assertWorkflowUsesRequirements(wf)).to.throw(/slither-plugins is not set/);
  });

  it("WORKFLOW_UNPINNED is now empty — the gap is closed, not documented", () => {
    expect(Object.keys(WORKFLOW_UNPINNED)).to.deep.equal([]);
  });
});
