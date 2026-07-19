/**
 * Docs guard for the Hosted Evidence Endpoint Deployment Plan
 * (docs/Hosted_Evidence_Endpoint_Deployment_Plan.md).
 *
 * This is a deployment-plan / spec / docs PR: it deploys nothing and adds no
 * server. The guard therefore checks the *document*, not a service:
 *
 *   - the plan doc exists,
 *   - its required structural headings are present,
 *   - the required read-only safety boundaries are stated,
 *   - the required adaptive Mermaid sources exist and use simple, renderable syntax
 *     (no parentheses, only flowchart/graph),
 *   - the acceptable deployment options are documented,
 *   - no forbidden overclaim language appears in affirmative (non-negated) form,
 *   - the README documentation map points to the plan.
 *
 * Pure, fast, static file reads — no network, no contracts, no deployment. This
 * complements (does not replace) DocsBoundary.test.ts and
 * DocsDisclaimerCoverage.test.ts, which still sweep this new doc too.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const PLAN_PATH = resolve("docs/Hosted_Evidence_Endpoint_Deployment_Plan.md");
const README_PATH = resolve("README.md");
const ADAPTIVE_MANIFEST_PATH = resolve("docs/diagrams/adaptive-manifest.json");

function read(path: string): string {
  return readFileSync(path, "utf8");
}

/** Lowercase + strip markdown emphasis/heading/quote markers + collapse whitespace. */
function normalize(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[*_`>#]/g, " ")
    .replace(/\s+/g, " ");
}

/** Read the canonical Mermaid sources mapped to one documentation page. */
function mermaidSources(file: string): string[] {
  const manifest = JSON.parse(read(ADAPTIVE_MANIFEST_PATH)) as {
    diagrams: Array<{ file: string; source: string }>;
  };
  return manifest.diagrams.filter((entry) => entry.file === file).map((entry) => read(resolve(entry.source)));
}

describe("Hosted Evidence Endpoint Deployment Plan — docs guard", function () {
  it("the plan doc exists", function () {
    expect(existsSync(PLAN_PATH), `${PLAN_PATH} must exist`).to.equal(true);
  });

  const raw = read(PLAN_PATH);
  const norm = normalize(raw);

  it("carries a prototype / testnet / not-audited / no-real-funds disclaimer", function () {
    expect(norm).to.match(/research prototype/);
    expect(norm).to.match(/not audited/);
    expect(norm).to.match(/testnet/);
    expect(norm).to.match(/no real funds/);
  });

  it("contains every required structural heading", function () {
    const requiredHeadings = [
      "Purpose",
      "Non-goals",
      "Current status",
      "Endpoint contract summary",
      "Deployment architecture",
      "Artifact generation flow",
      "Validation flow",
      "Cache and ETag model",
      "App-consumption model",
      "Security boundaries",
      "Deployment options",
      "Rollout phases",
      "Operational checklist",
      "Contributor tasks",
      "Open questions",
      "Acceptance criteria",
    ];
    for (const heading of requiredHeadings) {
      const escaped = heading.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
      const re = new RegExp(`^##\\s+${escaped}\\s*$`, "im");
      expect(re.test(raw), `missing heading: ## ${heading}`).to.equal(true);
    }
  });

  it("states the required read-only safety boundaries", function () {
    const requiredBoundaries = [
      "get-only",
      "no wallet data is sent",
      "no credentials",
      "no private keys",
      "no transactions",
      "no deploys",
      "no on-chain writes",
      "no proving in the private app",
      "no mutation endpoint",
      "no user-specific evidence",
      "no mainnet custody claims",
      "no production zk claims",
    ];
    for (const phrase of requiredBoundaries) {
      expect(norm).to.include(phrase, `missing safety boundary: ${phrase}`);
    }
  });

  it("does not claim the active Sepolia deployment is reproducible from public HEAD", function () {
    // The boundary must be stated as a *conditional/negated* claim, not an assertion.
    expect(norm).to.include("no claim that the active sepolia deployment is reproducible from public head");
  });

  it("documents the four acceptable deployment options without selecting one", function () {
    expect(norm).to.match(/github pages/);
    expect(norm).to.match(/serverless read-only endpoint/);
    expect(norm).to.match(/cdn .{0,8}static object hosting/);
    expect(norm).to.match(/hosted verifier service/);
    // Each option documents pros, risks, required controls, and out of scope.
    for (const facet of ["pros:", "risks:", "required controls:", "out of scope"]) {
      expect(norm).to.include(facet, `deployment options must document: ${facet}`);
    }
  });

  describe("Mermaid diagrams", function () {
    const blocks = mermaidSources("docs/Hosted_Evidence_Endpoint_Deployment_Plan.md");

    it("includes at least the four required diagrams", function () {
      expect(blocks.length).to.be.greaterThanOrEqual(4, `found only ${blocks.length} mermaid blocks`);
    });

    it("every block uses simple flowchart/graph syntax", function () {
      for (const block of blocks) {
        const head = block.trim().split(/\n/)[0].trim();
        expect(head).to.match(/^(flowchart|graph)\b/, `unsupported mermaid header: ${head}`);
      }
    });

    it("no block uses parentheses (kept simple to render on GitHub/Mintlify)", function () {
      for (const block of blocks) {
        expect(block).to.not.match(/[()]/, "mermaid blocks must avoid parentheses for portable rendering");
      }
    });

    it("renders the required diagram chains", function () {
      const all = blocks.join(" ").toLowerCase();
      // Architecture flow.
      expect(all).to.include("committed evidence artifacts");
      expect(all).to.include("vault candidate readiness packet");
      // Rollout sequence.
      expect(all).to.include("local artifact validation");
      expect(all).to.include("production endpoint approval");
      // Contribution lanes.
      expect(all).to.include("security review");
      expect(all).to.include("test fixtures");
      // Trust boundary "no ..." constraints.
      expect(all).to.include("no wallet connection");
      expect(all).to.include("no prover execution in app");
    });
  });

  it("uses no forbidden overclaim language in affirmative form", function () {
    // Terms that may only appear when clearly negated (no/not/never/without/non/gated).
    const forbidden = [
      "quantum-proof",
      "quantum-safe",
      "quantum-resistant platform",
      "guaranteed",
      "insured",
      "protected funds",
      "earn",
      "yield",
      "apy",
      "production custody",
      "mainnet-ready",
      "audited",
    ];
    const NEGATION = /\b(no|not|never|without|non|cannot|avoid|avoids|gated|nor|neither)\b/;
    const offenders: string[] = [];

    for (const term of forbidden) {
      const re = new RegExp(`(^|[^a-z])${term.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")}([^a-z]|$)`, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(norm)) !== null) {
        const start = m.index;
        const before = norm.slice(Math.max(0, start - 45), start);
        if (!NEGATION.test(before)) {
          offenders.push(`${term} @${start} ("...${norm.slice(Math.max(0, start - 30), start + term.length + 5)}...")`);
        }
      }
    }

    expect(offenders).to.deep.equal(
      [],
      `forbidden overclaim language used affirmatively:\n  ${offenders.join("\n  ")}`,
    );
  });

  it("is pointed to from the README documentation map", function () {
    const readme = read(README_PATH);
    expect(readme).to.include("docs/Hosted_Evidence_Endpoint_Deployment_Plan.md");
  });
});
