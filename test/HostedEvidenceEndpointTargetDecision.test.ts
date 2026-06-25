/**
 * Docs guard for the Hosted Evidence Endpoint Target Decision
 * (docs/Hosted_Evidence_Endpoint_Target_Decision.md).
 *
 * This is a docs/spec/decision PR: it deploys nothing and adds no server.
 * The guard checks:
 *   - the decision doc exists,
 *   - its required structural headings are present,
 *   - Option A is selected and Options B, C, D are explicitly deferred,
 *   - the required read-only safety boundaries are all stated,
 *   - the rollout gate and security-review gate are stated,
 *   - no forbidden overclaim language appears in affirmative form,
 *   - the README documentation map points to this decision.
 *
 * Pure, fast, static file reads — no network, no contracts, no deployment.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const DECISION_PATH = resolve("docs/Hosted_Evidence_Endpoint_Target_Decision.md");
const README_PATH = resolve("README.md");

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

describe("Hosted Evidence Endpoint Target Decision — docs guard", function () {
  it("the decision doc exists", function () {
    expect(existsSync(DECISION_PATH), `${DECISION_PATH} must exist`).to.equal(true);
  });

  const raw = read(DECISION_PATH);
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
      "Selected target",
      "Why Option A",
      "Options deferred",
      "Required controls",
      "Rollout gate",
      "Security-review gate",
      "App-consumption boundary",
      "Acceptance criteria",
    ];
    for (const heading of requiredHeadings) {
      const escaped = heading.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
      const re = new RegExp(`^##\\s+${escaped}\\s*$`, "im");
      expect(re.test(raw), `missing heading: ## ${heading}`).to.equal(true);
    }
  });

  it("selects Option A and explicitly defers Options B, C, and D", function () {
    // Option A must be selected.
    expect(norm).to.match(/selects? option a|option a.*is selected/, "must state that Option A is selected");
    // Each of B, C, D must be explicitly deferred.
    for (const opt of ["b", "c", "d"]) {
      expect(norm).to.match(
        new RegExp(`option ${opt}.*deferred|deferred.*option ${opt}`),
        `must explicitly defer Option ${opt.toUpperCase()}`,
      );
    }
    // Rationale phrases for Option A must be present.
    expect(norm).to.include("no server required");
    expect(norm).to.include("no secrets or credentials");
    expect(norm).to.include("simplest path");
  });

  it("states all required read-only safety boundaries", function () {
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

  it("states the rollout gate: implementation PR must merge before going live", function () {
    expect(norm).to.include("implementation pr");
    expect(norm).to.include("reviewed and merged");
  });

  it("states the security-review gate before production activation", function () {
    expect(norm).to.include("security review");
    expect(norm).to.include("no production endpoint");
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
    expect(readme).to.include("docs/Hosted_Evidence_Endpoint_Target_Decision.md");
  });
});
