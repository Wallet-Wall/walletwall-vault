/**
 * STABLE SEMANTIC FINDING IDENTITY — the behaviour, under test.
 *
 * WHAT WAS WRONG. `slither-triage.json` was keyed by `<check>|<sorted filename:firstLine>`, a
 * LOCATOR. Between c32e0d74 and aaa21d09 two commits moved code by +120 and +133 lines. The
 * finding SET did not change at all — 33 distinct own-code findings, 0 added, 0 removed — but 21
 * of 33 keys stopped matching, so the repository's own `--validate` reported 21 untriaged
 * findings that had each been adjudicated firsthand.
 *
 * WHY THE EXISTING GATES DID NOT CATCH IT. Nothing in CI ran `--validate` at all, and the
 * quantities that WERE published all stayed equal across the drift: 217 raw, 54 own, 33 distinct.
 * A count assertion cannot distinguish "the same findings, moved" from "different findings that
 * happen to number the same". Only an identity that ignores position can.
 *
 * THE KILL BLOCKS. `relocation preserves identity` and `line drift does not re-key` fail against
 * locator keying and pass against semantic identity. `a context change is not carried forward as a
 * relocation` fails against any scheme that treats the +113 shift of
 * `timestamp|_requireIncomingPossession` as an ordinary move, which is what a line-arithmetic
 * model does.
 *
 * EVERY ATTACK BLOCK IS PAIRED WITH A POSITIVE CONTROL. A test that rejects a synthetic collision
 * proves nothing unless the 21 real recompile duplicates — which share an identity legitimately —
 * are shown NOT to trip it.
 */
import { expect } from "chai";
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

import {
  broadFingerprint,
  canonicalLocator,
  indexFindings,
  matchFindings,
  narrowFingerprint,
  semanticId,
  semanticIdParts,
  normaliseSolidity,
  type FindingRow,
  type PriorEntry,
  type SlitherFinding,
  type SourceReader,
} from "../scanner-finding-identity.js";
import {
  assertScopeEquality,
  compareScopes,
  externalImportClosure,
  scopeAt,
  scannerSemanticConfigSha256,
  OUTPUT_ONLY_FLAGS,
  PINNED_SEMANTIC_CONFIG,
} from "../scanner-input-scope.js";
import { assertReceiptDoesNotNameContainer } from "../verify-receipt-container.js";

const FIXTURES = path.join("prototype", "vnext-kernel", "test", "fixtures", "scanner");
const HEAD_SUBJECT = "aaa21d093876d23d9e2d790400661d3d242caa31";
const PRIOR_SUBJECT = "a46bc50c130dd1eea0969a2fae50ee124ad4c332";

/**
 * Fixtures store contiguous line arrays as `[start, end]` and drop parent-chain spans, both of
 * which are lossless for what identity and fingerprints read. This expands them back to the raw
 * Slither shape so the modules under test see exactly what they see in production.
 */
function loadFixture(subject: string): { detectors: SlitherFinding[]; ownRawCount: number } {
  const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES, `own-findings.${subject.slice(0, 8)}.json`), "utf8"));
  const expand = (e: Record<string, any>): Record<string, any> => {
    const r = e.source_mapping?.lineRange;
    const lines: number[] = [];
    if (Array.isArray(r) && r.length === 2) for (let n = r[0]; n <= r[1]; n++) lines.push(n);
    return {
      ...e,
      source_mapping: e.source_mapping ? { filename_relative: e.source_mapping.filename_relative, lines } : undefined,
    };
  };
  return {
    detectors: raw.detectors.map((f: Record<string, any>) => ({ ...f, elements: f.elements.map(expand) })),
    ownRawCount: raw.ownRawCount,
  };
}

/** Reads a file at a revision from git. The workflow checks out with `fetch-depth: 0` for this. */
function gitReaderAt(subject: string): SourceReader {
  const cache = new Map<string, string[]>();
  return (rel: string) => {
    if (!cache.has(rel)) {
      let text = "";
      try {
        text = execFileSync("git", ["show", `${subject}:${rel}`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      } catch {
        text = "";
      }
      cache.set(rel, text.split(/\r?\n/));
    }
    return cache.get(rel)!;
  };
}

/** In-memory source, so the unit blocks below need neither git nor a scanner. */
function fakeReader(files: Record<string, string>): SourceReader {
  return (rel: string) => (files[rel] ?? "").split("\n");
}

function fn(name: string, contract: string, lines: number[], file = "A.sol"): Record<string, any> {
  return {
    type: "function",
    name,
    source_mapping: { filename_relative: file, lines },
    type_specific_fields: { signature: `${name}()`, parent: { type: "contract", name: contract } },
  };
}
function node(expr: string, fname: string, contract: string, line: number, file = "A.sol"): Record<string, any> {
  return {
    type: "node",
    name: expr,
    source_mapping: { filename_relative: file, lines: [line] },
    type_specific_fields: { parent: { type: "function", name: fname, type_specific_fields: { parent: { type: "contract", name: contract } } } },
  };
}

describe("scanner finding identity", () => {
  describe("identity is line-independent", () => {
    it("contains no line numbers, offsets or spans in the hashed tuple", () => {
      const f: SlitherFinding = {
        check: "timestamp",
        impact: "Low",
        confidence: "Medium",
        description: "C.f() uses timestamp for comparisons (A.sol#640-683)\n\t- x > y (A.sol#651)\n",
        elements: [fn("f", "C", [640, 641]), node("x > y", "f", "C", 651)] as any,
      };
      const serialized = JSON.stringify(semanticIdParts(f));
      expect(serialized).to.not.match(/640|641|651|683/);
      expect(serialized).to.contain("#L");
    });

    it("is identical for the same finding shifted to different lines", () => {
      const at = (a: number, b: number): SlitherFinding => ({
        check: "timestamp",
        impact: "Low",
        confidence: "Medium",
        description: `C.f() uses timestamp for comparisons (A.sol#${a}-${a + 40})\n\t- x > y (A.sol#${b})\n`,
        elements: [fn("f", "C", [a, a + 1]), node("x > y", "f", "C", b)] as any,
      });
      expect(semanticId(at(640, 651))).to.equal(semanticId(at(753, 764)));
      // and the LOCATOR, which is retained as metadata, does differ — proving the test is not vacuous
      expect(canonicalLocator(at(640, 651))).to.not.equal(canonicalLocator(at(753, 764)));
    });
  });

  describe("the real corpus: a46bc50c -> aaa21d09", () => {
    let prior: PriorEntry[];
    let current: Map<string, FindingRow>;
    let currentAmbiguities: number;
    let priorRows: Map<string, FindingRow>;

    before(() => {
      const p = indexFindings(loadFixture(PRIOR_SUBJECT).detectors, gitReaderAt(PRIOR_SUBJECT));
      const c = indexFindings(loadFixture(HEAD_SUBJECT).detectors, gitReaderAt(HEAD_SUBJECT));
      priorRows = p.byId;
      current = c.byId;
      currentAmbiguities = c.ambiguities.length + p.ambiguities.length;
      prior = [...p.byId.values()].map((r) => ({
        semanticId: r.semanticId,
        locator: r.locator,
        narrowFingerprint: r.narrow,
        broadFingerprint: r.broad,
      }));
    });

    it("collapses 54 own raw rows to 33 distinct findings at both subjects, with no ambiguity", () => {
      expect(loadFixture(HEAD_SUBJECT).ownRawCount).to.equal(54);
      expect(loadFixture(PRIOR_SUBJECT).ownRawCount).to.equal(54);
      expect(current.size).to.equal(33);
      expect(priorRows.size).to.equal(33);
      expect(currentAmbiguities).to.equal(0);
    });

    it("KILL: relocation preserves identity — 33/33 match, 0 added, 0 removed", () => {
      const m = matchFindings(prior, current);
      expect(m.filter((x) => x.klass === "ADDED"), "added findings").to.have.length(0);
      expect(m.filter((x) => x.klass === "REMOVED"), "removed findings").to.have.length(0);
      expect(m).to.have.length(33);
    });

    it("KILL: line drift does not re-key — 20 relocations keep identity and both fingerprints", () => {
      const m = matchFindings(prior, current);
      const relocated = m.filter((x) => x.klass === "RELOCATED");
      expect(relocated).to.have.length(20);
      for (const r of relocated) {
        expect(r.current!.locator, "locator must have moved").to.not.equal(r.prior!.locator);
        expect(r.current!.broad, "source must be byte-identical").to.equal(r.prior!.broad);
        expect(r.lineDelta, "delta is recorded as an output").to.not.be.undefined;
      }
      // Within one finding every element shifts by the SAME amount. A delta that varies inside a
      // single relocated finding means the elements were paired wrongly, not that code moved.
      for (const r of relocated) {
        expect(new Set(r.lineDelta), `non-uniform shift in ${r.current!.locator}`).to.have.property("size", 1);
      }
      // ACROSS findings the shift is NOT uniform — two edits moved different regions by different
      // amounts — which is precisely why line arithmetic cannot be the matcher.
      const deltas = new Set(relocated.map((r) => r.lineDelta![0]));
      expect([...deltas].sort((a, b) => a - b)).to.deep.equal([120, 133]);
    });

    it("12 findings did not move at all", () => {
      expect(matchFindings(prior, current).filter((x) => x.klass === "UNCHANGED")).to.have.length(12);
    });

    it("KILL: a context change is not carried forward as a relocation", () => {
      const m = matchFindings(prior, current);
      const flagged = m.filter((x) => x.klass === "SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION");
      expect(flagged, "exactly one finding's enclosing source changed").to.have.length(1);
      expect(flagged[0].current!.check).to.equal("timestamp");
      expect(flagged[0].current!.description).to.contain("_requireIncomingPossession");
      expect(flagged[0].klass).to.not.equal("RELOCATED");
    });

    it("claims no PROVEN semantic change, because the flagged construct itself is unchanged", () => {
      const m = matchFindings(prior, current);
      expect(m.filter((x) => x.klass === "SEMANTIC_CHANGE_PROVEN"), "narrow fingerprints are all equal").to.have.length(0);
      const flagged = m.find((x) => x.klass === "SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION")!;
      expect(flagged.current!.narrow, "the node fingerprint is what proves relevance").to.equal(flagged.prior!.narrow);
      expect(flagged.current!.broad).to.not.equal(flagged.prior!.broad);
    });

    it("POSITIVE CONTROL: the recompile duplicates share an identity without being ambiguous", () => {
      const c = indexFindings(loadFixture(HEAD_SUBJECT).detectors, gitReaderAt(HEAD_SUBJECT));
      expect(c.ownRawCount - c.byId.size, "21 duplicate rows collapse").to.equal(21);
      expect(c.ambiguities, "duplicates agree, so none is ambiguous").to.have.length(0);
    });
  });

  describe("change detection cannot assert more than it proves", () => {
    const base = { check: "timestamp", impact: "Low", confidence: "Medium", description: "C.f() uses timestamp (A.sol#L)\n" };
    const withNode: SlitherFinding = { ...base, elements: [fn("f", "C", [1, 2, 3]), node("a > b", "f", "C", 2)] as any };
    const noNode: SlitherFinding = { ...base, elements: [fn("f", "C", [1, 2, 3])] as any };

    it("narrow fingerprint is UNDEFINED when a finding has no node element", () => {
      const read = fakeReader({ "A.sol": "line1\nif (a > b) {}\nline3" });
      expect(narrowFingerprint(noNode, read)).to.be.undefined;
      expect(narrowFingerprint(withNode, read)).to.be.a("string");
      expect(broadFingerprint(noNode, read)).to.be.a("string");
    });

    it("KILL: an undefined narrow fingerprint never yields SEMANTIC_CHANGE_PROVEN", () => {
      const before = fakeReader({ "A.sol": "line1\nif (a > b) {}\nline3" });
      const after = fakeReader({ "A.sol": "line1\nif (a > b) {}\nCOMPLETELY DIFFERENT" });
      const id = semanticId(noNode);
      const prior: PriorEntry[] = [{ semanticId: id, locator: canonicalLocator(noNode), narrowFingerprint: narrowFingerprint(noNode, before), broadFingerprint: broadFingerprint(noNode, before) }];
      const cur = indexFindings([noNode], after).byId;
      const [m] = matchFindings(prior, cur);
      expect(m.klass).to.equal("SOURCE_CONTEXT_CHANGED_REQUIRES_READJUDICATION");
    });

    it("a changed flagged construct IS proven, when the node fingerprint can see it", () => {
      const before = fakeReader({ "A.sol": "line1\nif (a > b) {}\nline3" });
      const after = fakeReader({ "A.sol": "line1\nif (a >= b) {}\nline3" });
      const id = semanticId(withNode);
      const prior: PriorEntry[] = [{ semanticId: id, locator: canonicalLocator(withNode), narrowFingerprint: narrowFingerprint(withNode, before), broadFingerprint: broadFingerprint(withNode, before) }];
      const [m] = matchFindings(prior, indexFindings([withNode], after).byId);
      expect(m.klass).to.equal("SEMANTIC_CHANGE_PROVEN");
    });

    it("comment and whitespace edits are not source changes", () => {
      expect(normaliseSolidity("if (a > b) {} // note")).to.equal(normaliseSolidity("if  (a  >  b)  {}   /* other */"));
    });
  });

  describe("ambiguity is a hard failure", () => {
    it("KILL: two findings sharing an identity at different locators are reported", () => {
      const a: SlitherFinding = { check: "timestamp", impact: "Low", confidence: "Medium", description: "C.f() uses timestamp (A.sol#L)\n", elements: [fn("f", "C", [10, 11])] as any };
      const b: SlitherFinding = JSON.parse(JSON.stringify(a));
      b.elements[0].source_mapping.lines = [90, 91];
      expect(semanticId(a), "same identity by construction").to.equal(semanticId(b));
      const read = fakeReader({ "A.sol": Array.from({ length: 100 }, (_, i) => `l${i}`).join("\n") });
      const r = indexFindings([a, b], read);
      expect(r.ambiguities).to.have.length(1);
      expect(r.ambiguities[0].reason).to.contain("different locators");
    });

    it("KILL: same identity and locator but disagreeing source is reported", () => {
      const a: SlitherFinding = { check: "timestamp", impact: "Low", confidence: "Medium", description: "C.f() uses timestamp (A.sol#L)\n", elements: [fn("f", "C", [1, 2])] as any };
      const b: SlitherFinding = { ...a, elements: [fn("f", "C", [1, 2], "B.sol")] as any };
      // identical identity requires identical file, so force the collision through the reader
      const read: SourceReader = (rel) => (rel === "A.sol" ? ["x", "y"] : ["x", "DIFFERENT"]);
      const forced: SlitherFinding[] = [a, JSON.parse(JSON.stringify(a))];
      forced[1].elements[0].source_mapping.filename_relative = "A.sol";
      const readDrift: SourceReader = (() => {
        let n = 0;
        return () => (n++ === 0 ? ["x", "y"] : ["x", "DIFFERENT"]);
      })();
      const r = indexFindings(forced, readDrift);
      expect(r.ambiguities, "disagreeing fingerprints under one identity").to.have.length(1);
      expect(r.ambiguities[0].reason).to.contain("source fingerprint");
      void b;
      void read;
    });

    it("POSITIVE CONTROL: identical duplicates are collapsed silently", () => {
      const a: SlitherFinding = { check: "timestamp", impact: "Low", confidence: "Medium", description: "C.f() uses timestamp (A.sol#L)\n", elements: [fn("f", "C", [1, 2])] as any };
      const read = fakeReader({ "A.sol": "x\ny" });
      const r = indexFindings([a, JSON.parse(JSON.stringify(a))], read);
      expect(r.ambiguities).to.have.length(0);
      expect(r.byId.size).to.equal(1);
      expect(r.ownRawCount).to.equal(2);
    });
  });

  describe("scanner-input scope is the only currency licence", () => {
    it("KILL: a source subject whose contracts tree differs is refused", () => {
      expect(() => assertScopeEquality(PRIOR_SUBJECT, HEAD_SUBJECT, ".")).to.throw(/scanner-input scope differs/);
    });

    it("names the actual differing digest, not just 'mismatch'", () => {
      let msg = "";
      try {
        assertScopeEquality(PRIOR_SUBJECT, HEAD_SUBJECT, ".");
      } catch (e) {
        msg = (e as Error).message;
      }
      expect(msg).to.contain("contractsTree");
      expect(msg).to.contain("dcc42e76a22b2491e05a6f7ccbc98f447e6acbc5");
      expect(msg).to.contain("da8aef1f7d55d637d6ca5556c229b3d648be625d");
    });

    it("POSITIVE CONTROL: a subject compared against itself is licensed", () => {
      expect(() => assertScopeEquality(HEAD_SUBJECT, HEAD_SUBJECT, ".")).to.not.throw();
    });

    it("KILL: equal finding counts do not license currency", () => {
      // 217 raw / 54 own / 33 distinct are EQUAL across these two commits, and ancestry holds.
      const prior = loadFixture(PRIOR_SUBJECT);
      const head = loadFixture(HEAD_SUBJECT);
      expect(prior.ownRawCount, "counts agree").to.equal(head.ownRawCount);
      // ...and the scope check still refuses, because counts are not inputs
      expect(() => assertScopeEquality(PRIOR_SUBJECT, HEAD_SUBJECT, ".")).to.throw();
    });

    it("derives the external import closure rather than trusting a hand-written list", () => {
      const closure = externalImportClosure(".");
      expect(closure).to.have.length(12);
      expect(closure).to.include("proxy/Clones.sol");
      expect(closure, "reached only transitively").to.include("utils/Bytes.sol");
    });

    it("excludes output-only flags from the semantic config digest", () => {
      const serialized = JSON.stringify(PINNED_SEMANTIC_CONFIG);
      for (const flag of OUTPUT_ONLY_FLAGS) expect(serialized, `${flag} must not affect the digest`).to.not.contain(flag);
      expect(scannerSemanticConfigSha256()).to.match(/^[0-9a-f]{64}$/);
    });

    it("a scope comparison with a missing field fails closed", () => {
      const a = scopeAt(HEAD_SUBJECT, ".");
      const b = { ...a, contractsTree: undefined } as unknown as typeof a;
      expect(compareScopes(a, b).equal).to.equal(false);
    });
  });

  describe("a receipt may not name its own publication container", () => {
    const CONTAINER = "5555555555555555555555555555555555555555";

    it("KILL: a receipt containing the container id is refused", () => {
      const receipt = JSON.stringify({ sourceSubject: HEAD_SUBJECT, publishedIn: CONTAINER });
      expect(() => assertReceiptDoesNotNameContainer(receipt, CONTAINER)).to.throw(/names its own publication container/);
    });

    it("KILL: it is refused under any field name, including an unforeseen one", () => {
      const receipt = JSON.stringify({ sourceSubject: HEAD_SUBJECT, notes: { someFutureField: CONTAINER } });
      expect(() => assertReceiptDoesNotNameContainer(receipt, CONTAINER)).to.throw(/names its own publication container/);
    });

    it("POSITIVE CONTROL: naming the source and triage subjects stays legal", () => {
      const receipt = JSON.stringify({ sourceSubject: HEAD_SUBJECT, triageSubject: PRIOR_SUBJECT });
      expect(() => assertReceiptDoesNotNameContainer(receipt, CONTAINER)).to.not.throw();
    });

    it("NO-OP CONTROL: the check discriminates on the container id, not on 40-hex strings", () => {
      const receipt = JSON.stringify({ sourceSubject: HEAD_SUBJECT });
      expect(() => assertReceiptDoesNotNameContainer(receipt, CONTAINER)).to.not.throw();
      expect(() => assertReceiptDoesNotNameContainer(receipt, HEAD_SUBJECT)).to.throw();
    });
  });
});
