/**
 * Docs guard for the Static Hosted Evidence Artifact — Reviewed Publishing Controls
 * (docs/Static_Hosted_Evidence_Publishing_Controls.md).
 *
 * This is a docs/spec/control-plan PR: it publishes nothing and adds no server,
 * no GitHub Pages workflow, and no CI publish step. The guard checks that the
 * control-plan document:
 *   - exists and carries the required structural headings,
 *   - states plainly whether anything is published by this PR (it is not),
 *   - identifies the committed static artifact path,
 *   - requires both TypeScript and Rust validation before publish,
 *   - documents the cache/ETag policy and the CORS policy,
 *   - documents the rollback process,
 *   - states that app consumption and connector/plugin integration are future work,
 *   - preserves every safety boundary,
 *   - uses no forbidden overclaim language in affirmative form (including the
 *     production-ZK / mainnet-custody / wallet-safety / live-proving /
 *     dynamic-endpoint / deployment-reproducibility categories),
 *   - and is pointed to from the README documentation map.
 *
 * Pure, fast, static file reads — no network, no contracts, no deployment.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const DOC_PATH = resolve("docs/Static_Hosted_Evidence_Publishing_Controls.md");
const README_PATH = resolve("README.md");
const STATIC_ARTIFACT_REL = "evidence/zk/hosted/v1/zk-adapter-evidence-response.json";

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

const NEGATION = /\b(no|not|never|without|non|cannot|avoid|avoids|gated|nor|neither)\b/;

/** Find forbidden terms used in affirmative (non-negated) form within `text`. */
function findOverclaims(text: string, forbidden: string[]): string[] {
  const offenders: string[] = [];
  for (const term of forbidden) {
    const re = new RegExp(`(^|[^a-z])${term.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")}([^a-z]|$)`, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const start = m.index;
      const before = text.slice(Math.max(0, start - 45), start);
      if (!NEGATION.test(before)) {
        offenders.push(`${term} @${start} ("...${text.slice(Math.max(0, start - 30), start + term.length + 5)}...")`);
      }
    }
  }
  return offenders;
}

describe("Static Hosted Evidence Publishing Controls — docs guard", function () {
  it("the controls doc exists", function () {
    expect(existsSync(DOC_PATH), `${DOC_PATH} must exist`).to.equal(true);
  });

  const raw = read(DOC_PATH);
  const norm = normalize(raw);
  // Collapse hyphens too, so hyphenated and spaced overclaim phrases are caught alike.
  const normNoHyphen = norm.replace(/-/g, " ").replace(/\s+/g, " ");

  it("carries a prototype / testnet / not-audited / no-real-funds disclaimer", function () {
    expect(norm).to.match(/research prototype/);
    expect(norm).to.match(/not audited/);
    expect(norm).to.match(/testnet/);
    expect(norm).to.match(/no real funds/);
  });

  it("contains every required structural heading", function () {
    const requiredHeadings = [
      "Publishing decision",
      "Source of truth",
      "Artifact path",
      "Publish boundary",
      "Hosting controls",
      "Release controls",
      "App consumption boundary",
      "Security-review gate",
      "Safety boundaries preserved",
      "Acceptance criteria",
    ];
    for (const heading of requiredHeadings) {
      const escaped = heading.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
      const re = new RegExp(`^##\\s+${escaped}\\s*$`, "im");
      expect(re.test(raw), `missing heading: ## ${heading}`).to.equal(true);
    }
  });

  it("states plainly that this PR publishes nothing", function () {
    expect(norm).to.include("this pr publishes nothing");
    expect(norm).to.include("publishes nothing");
  });

  it("identifies the committed static artifact path", function () {
    expect(raw).to.include(STATIC_ARTIFACT_REL);
    expect(STATIC_ARTIFACT_REL, "artifact path must carry a version segment").to.match(/(^|\/)v\d+\//);
  });

  it("requires TypeScript validation of the artifact before publish", function () {
    expect(norm).to.include("typescript validator role");
    expect(norm).to.include("validate:static-artifact");
  });

  it("requires Rust validation of the artifact before publish", function () {
    expect(norm).to.include("rust validator role");
    expect(norm).to.include("evidence-validator");
  });

  it("documents the cache and ETag policy", function () {
    expect(norm).to.include("cache");
    expect(norm).to.include("etag");
    expect(norm).to.include("if-none-match");
  });

  it("documents the CORS policy", function () {
    expect(norm).to.include("cors");
    // CORS must be future-scoped (read-only GET, app origin only, no wildcard).
    expect(norm).to.match(/read-only get/);
  });

  it("documents the rollback process and the incident/offline fallback", function () {
    expect(norm).to.include("rollback");
    expect(norm).to.match(/fallback/);
  });

  it("requires a reviewed PR and a security review before any publish", function () {
    expect(norm).to.include("publishing requires a reviewed pr");
    expect(norm).to.include("security review");
  });

  it("states that app consumption and connector/plugin integration are future work", function () {
    expect(norm).to.include("app consumption is future work");
    expect(norm).to.match(/connector \/ plugin integration is future work/);
  });

  it("preserves every safety boundary", function () {
    const requiredBoundaries = [
      "no prover execution",
      "no sp1 proving",
      "no rpc",
      "no chain calls",
      "no http fetching for artifact generation",
      "no private keys",
      "no credentials",
      "no api keys",
      "no wallet data",
      "no mutation endpoint",
      "no serverless write path",
      "no app integration",
      "no private app changes",
      "no contract / abi / deployment changes",
      "no production-zk claims",
      "no mainnet-custody claims",
      "no wallet-safety guarantees",
      "no live proving",
      "no dynamic endpoint deployment",
      "no deployment-reproducibility claims",
    ];
    for (const phrase of requiredBoundaries) {
      expect(norm).to.include(phrase, `missing safety boundary: ${phrase}`);
    }
  });

  it("uses no forbidden overclaim language in affirmative form", function () {
    // The proven denylist shared with the upstream Option A docs guards. Terms may
    // appear only when clearly negated (no/not/never/without/non/gated/...).
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
    const offenders = findOverclaims(norm, forbidden);
    expect(offenders).to.deep.equal(
      [],
      `forbidden overclaim language used affirmatively:\n  ${offenders.join("\n  ")}`,
    );
  });

  it("avoids affirmative overclaims around the gated capability categories", function () {
    // These multi-word categories are scanned against the hyphen-collapsed norm so
    // that "production-ZK" and "production ZK" (etc.) are both caught. Each may
    // appear only when negated.
    const forbidden = [
      "production zk",
      "mainnet custody",
      "wallet safety guarantee",
      "live proving",
      "dynamic endpoint deployment",
      "deployment reproducibility",
    ];
    const offenders = findOverclaims(normNoHyphen, forbidden);
    expect(offenders).to.deep.equal([], `gated-capability overclaim used affirmatively:\n  ${offenders.join("\n  ")}`);
  });

  it("is pointed to from the README documentation map", function () {
    expect(read(README_PATH)).to.include("docs/Static_Hosted_Evidence_Publishing_Controls.md");
  });
});
