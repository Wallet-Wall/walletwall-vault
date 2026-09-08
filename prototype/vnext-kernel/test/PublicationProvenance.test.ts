/**
 * INTEGRATION-AWARE PUBLICATION PROVENANCE — the behaviour, under test.
 *
 * WHAT WAS WRONG. The verifier required the commit under test to BE the publication container:
 * `HEAD^1 == triageSubject` and `diff triageSubject..HEAD == the receipt only`. True at the
 * publication commit; false forever after. When PR #181 was merged into #179 with an ordinary
 * merge commit, CI failed:
 *
 *   container c6c99478, first parent 71aee6f3, expected ada95399
 *
 * Nothing was wrong with the evidence — receipt, triage, contracts tree and scanner scope were all
 * byte-identical to the publication commit. Only the assumption was wrong. The dangerous failure
 * mode is not the red X: it is that a check which cries wolf on every legitimate merge invites
 * someone to skip it on merge commits, which is precisely where a silent receipt swap would hide.
 *
 * SO THE CONTROLS BELOW ARE SYMMETRIC. Half prove legitimate integration still passes; half prove
 * tampering under an integration head still fails. A model that only did the first would be the
 * old bug inverted.
 *
 * The history is driven through an INJECTED git runner rather than real throwaway repositories.
 * That is deliberate: it makes each control a statement about one graph property, with no
 * dependence on a working tree, a network, or an OpenZeppelin install.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";

import {
  assertReceiptDoesNotNameContainer,
  findPublicationContainer,
  verifyPublicationProvenance,
  type ScannerReceipt,
} from "../verify-receipt-container.js";
import { type GitRunner } from "../scanner-input-scope.js";

const RECEIPT = "prototype/vnext-kernel/SCANNER_EVIDENCE.json";
const TRIAGE = "prototype/vnext-kernel/slither-triage.json";
const CONTRACTS = "prototype/vnext-kernel/contracts";

/** Deterministic, valid 40-hex object ids. A readable stand-in like "tree-aaa1..." is not hex,
 *  and the verifier rejects non-oids before any graph rule runs. */
const oid = (seed: string) => createHash("sha1").update(seed).digest("hex");
/** One derivation for a commit's tree id, shared by the fake repo and the fixture receipts, so a
 *  tree mismatch in a control means the RULE fired rather than the harness disagreeing with itself. */
const treeOf = (commit: string) => oid(`tree:${commit}`);
const SOURCE = oid("aaa1");
const T = oid("7777"); // triage / generation subject
const P = oid("8888"); // publication container
const H = oid("9999"); // integration head

interface Commit {
  parents: string[];
  files: Record<string, string>;
  contractsTree: string;
  lock: string;
}

/** A tiny git model: enough graph and content for the provenance rules, and nothing else. */
class FakeRepo {
  constructor(readonly commits: Record<string, Commit>) {}

  private ancestors(c: string, seen = new Set<string>()): Set<string> {
    if (seen.has(c)) return seen;
    seen.add(c);
    for (const p of this.commits[c]?.parents ?? []) this.ancestors(p, seen);
    return seen;
  }

  runner: GitRunner = (args: string[]): string => {
    const [cmd, ...rest] = args;

    if (cmd === "rev-parse") {
      const spec = rest[rest.length - 1];
      if (spec.endsWith("^{tree}")) return treeOf(spec.replace("^{tree}", ""));
      const m = spec.match(/^([0-9a-f]+):(.+)$/);
      if (m) {
        const c = this.commits[m[1]];
        if (!c) throw new Error(`unknown rev ${m[1]}`);
        if (m[2] === CONTRACTS) return c.contractsTree;
        throw new Error(`unknown path ${m[2]}`);
      }
      if (!this.commits[spec]) throw new Error(`unknown rev ${spec}`);
      return spec;
    }

    if (cmd === "rev-list" && rest[0] === "--ancestry-path") {
      const [from, to] = rest[1].split("..");
      // commits reachable from `to` that have `from` as an ancestor, excluding `from`
      return [...this.ancestors(to)].filter((c) => c !== from && this.ancestors(c).has(from)).join("\n");
    }

    if (cmd === "rev-list" && rest[0] === "--parents") {
      const c = rest[rest.length - 1];
      return [c, ...(this.commits[c]?.parents ?? [])].join(" ");
    }

    if (cmd === "diff" && rest[0] === "--name-only") {
      const [a, b] = [rest[1], rest[2]];
      const fa = this.commits[a].files;
      const fb = this.commits[b].files;
      const keys = new Set([...Object.keys(fa), ...Object.keys(fb)]);
      return [...keys].filter((k) => fa[k] !== fb[k]).sort().join("\n");
    }

    if (cmd === "show") {
      const m = rest[0].match(/^([0-9a-f]+):(.+)$/)!;
      const c = this.commits[m[1]];
      if (!c) throw new Error(`unknown rev ${m[1]}`);
      if (m[2] === "package-lock.json") return c.lock;
      const v = c.files[m[2]];
      if (v === undefined) throw new Error(`path ${m[2]} absent at ${m[1]}`);
      return v;
    }

    if (cmd === "merge-base" && rest[0] === "--is-ancestor") {
      if (!this.ancestors(rest[2]).has(rest[1])) throw new Error("not an ancestor");
      return "";
    }

    throw new Error(`FakeRepo: unhandled git ${args.join(" ")}`);
  };
}

const receiptOf = (over: Partial<ScannerReceipt> = {}): ScannerReceipt => ({
  schema: "vnext-kernel-scanner-evidence.v3",
  sourceSubject: SOURCE,
  sourceTree: treeOf(SOURCE),
  triageSubject: T,
  triageTree: treeOf(T),
  scanners: { slither: { rawFindingCount: 217 } },
  ...over,
});

const LOCK = JSON.stringify({ packages: { "node_modules/@openzeppelin/contracts": { version: "5.6.1", integrity: "sha512-x" } } });
const CT = oid("cccc"); // the one legitimate contracts tree

function build(over: Record<string, Partial<Commit>> = {}, receipt = receiptOf()) {
  const base: Record<string, Commit> = {
    [SOURCE]: { parents: [], files: { [RECEIPT]: "old", [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
    [T]: { parents: [SOURCE], files: { [RECEIPT]: "old", [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
    [P]: { parents: [T], files: { [RECEIPT]: JSON.stringify(receipt), [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
    [H]: { parents: [P], files: { [RECEIPT]: JSON.stringify(receipt), [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
  };
  for (const [k, v] of Object.entries(over)) base[k] = { ...base[k], ...v } as Commit;
  return new FakeRepo(base);
}

const verify = (repo: FakeRepo, head = H) => verifyPublicationProvenance(head, ".", repo.runner);

describe("integration-aware publication provenance", () => {
  it("baseline: publication container is discovered and the head is current", () => {
    const r = verify(build());
    expect(r.container).to.equal(P);
    expect(r.proofs.map((p) => p.step)).to.include.members([
      "declared-subjects-truthful",
      "publication-container-located",
      "container-is-ancestor-of-head",
      "receipt-bytes-unchanged-since-publication",
      "triage-semantics-unchanged-since-publication",
      "scanner-scope-equal-source-container-head",
    ]);
  });

  it("1. valid P followed by an unrelated docs-only descendant outside scanner scope => PASS", () => {
    const repo = build({ [H]: { parents: [P], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "REWRITTEN", "docs/new.md": "n" } } });
    expect(verify(repo).container).to.equal(P);
  });

  it("2. valid P followed by an ordinary merge commit preserving receipt + scope => PASS", () => {
    const SIDE = oid("5555");
    const repo = build({
      [SIDE]: { parents: [SOURCE], files: { [RECEIPT]: "old", [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
      // first parent is the branch tip, NOT T -- exactly the shape that broke the old verifier
      [H]: { parents: [SIDE, P], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "d" } },
    });
    expect(verify(repo).container, "P must still be found through the merge").to.equal(P);
  });

  it("3. descendant changes one scanner contract byte => FAIL", () => {
    const repo = build({ [H]: { contractsTree: oid("dddd") } });
    expect(() => verify(repo)).to.throw(/scanner-input scope at head/);
  });

  it("4. descendant changes scanner-semantic config => FAIL", () => {
    // the OZ pin is part of the hashed scope; moving it at the head is a semantic-config change
    const repo = build({ [H]: { lock: JSON.stringify({ packages: { "node_modules/@openzeppelin/contracts": { version: "5.7.0", integrity: "sha512-y" } } }) } });
    expect(() => verify(repo)).to.throw(/scanner-input scope at head/);
  });

  it("5. descendant hand-edits SCANNER_EVIDENCE.json => FAIL", () => {
    const tampered = JSON.stringify(receiptOf()).replace('"rawFindingCount":217', '"rawFindingCount":217 ');
    const repo = build({ [H]: { files: { [RECEIPT]: tampered, [TRIAGE]: "triage", "docs/x.md": "d" } } });
    expect(() => verify(repo)).to.throw(/not byte-identical to the copy published at/);
  });

  it("6. descendant replaces the receipt with a byte-different but count-equivalent one => FAIL", () => {
    const equivalent = JSON.stringify({ ...receiptOf(), _reformatted: true });
    const repo = build({ [H]: { files: { [RECEIPT]: equivalent, [TRIAGE]: "triage", "docs/x.md": "d" } } });
    expect(() => verify(repo), "equal counts are not currency").to.throw(/not byte-identical to the copy published at/);
  });

  it("7. no qualifying publication container on ancestry => FAIL", () => {
    // P also changes the triage, so it is not a receipt-only publication
    const repo = build({ [P]: { files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "CHANGED", "docs/x.md": "d" } } });
    expect(() => verify(repo)).to.throw(/no publication container found/);
  });

  it("8. two plausible publication containers for one unsuperseded receipt => FAIL_AMBIGUOUS", () => {
    const P2 = oid("8889");
    const repo = build({
      [P2]: { parents: [T], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
      [H]: { parents: [P, P2], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "d" } },
    });
    expect(() => verify(repo)).to.throw(/FAIL_AMBIGUOUS/);
  });

  it("9. a synthetic refs/pull/N/merge commit never becomes P", () => {
    const SYNTH = oid("beef");
    const repo = build({
      // trigger-dependent merge of the head with a base, reachable from no branch
      [SYNTH]: { parents: [H, SOURCE], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
    });
    // Verifying the REAL head still resolves the real publication container...
    expect(verify(repo, H).container).to.equal(P);
    // ...and even when the synthetic commit is handed in as the head, P is the real commit,
    // never the synthetic one.
    const viaSynthetic = verify(repo, SYNTH);
    expect(viaSynthetic.container).to.equal(P);
    expect(viaSynthetic.container).to.not.equal(SYNTH);
  });

  it("10. the historical publication container is not an ancestor of the branch head => FAIL", () => {
    // The branch head carries the published receipt but P is on a line this head never reaches.
    // X is interposed so H is not itself a receipt-only child of T -- the first attempt at this
    // control made H a direct child of T changing only the receipt, which legitimately made H its
    // OWN publication container and passed. The control was wrong, not the rule.
    const X = oid("aaaa");
    const repo = build({
      [X]: { parents: [T], files: { [RECEIPT]: "old", [TRIAGE]: "triage", "docs/x.md": "MOVED ON" }, contractsTree: CT, lock: LOCK },
      [H]: { parents: [X], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "MOVED ON" } },
    });
    expect(() => verify(repo)).to.throw(/no publication container found/);
    // and P really is unreachable from H, which is what the rule is refusing on
    expect(() => repo.runner(["merge-base", "--is-ancestor", P, H])).to.throw();
  });

  it("locates P only from commits reachable from the real head", () => {
    const UNREACHABLE = oid("dead");
    const repo = build({
      [UNREACHABLE]: { parents: [T], files: { [RECEIPT]: JSON.stringify(receiptOf()), [TRIAGE]: "triage", "docs/x.md": "d" }, contractsTree: CT, lock: LOCK },
    });
    // UNREACHABLE has T as first parent and changes only the receipt, but no branch reaches it,
    // so it must not be considered -- otherwise every abandoned attempt would create ambiguity.
    expect(findPublicationContainer(T, H, repo.runner).candidates).to.deep.equal([P]);
  });

  it("still refuses a receipt that names its own container", () => {
    expect(() => assertReceiptDoesNotNameContainer(JSON.stringify({ publishedIn: P }), P)).to.throw(/names its own publication container/);
    expect(() => assertReceiptDoesNotNameContainer(JSON.stringify({ triageSubject: T }), P)).to.not.throw();
  });
});
