/**
 * Repo-wide documentation disclaimer coverage guard.
 *
 * This is a BROAD, topic-driven complement to DocsBoundary.test.ts (which pins
 * specific phrases in seven named docs). It sweeps EVERY markdown doc in the
 * repo — including any newly added one — and enforces a single launch-safety
 * invariant:
 *
 *   Any doc that discusses a risk-bearing topic (deposits, withdrawals, custody,
 *   yield/APY/APR/interest/returns, real funds/value, mainnet, or production
 *   deposit/withdrawal) MUST also carry at least one prototype / testnet /
 *   not-audited / no-real-funds disclaimer.
 *
 * Why presence-of-disclaimer rather than a banned-phrase denylist: this repo's
 * safety style is to repeatedly NEGATE overclaims ("not production-ready", "not
 * a mainnet write path", "should not be described as production-ready, audited,
 * quantum-proof, safe for real funds…"). A substring denylist would false-flag
 * that careful language and fight DocsBoundary.test.ts. Requiring a disclaimer
 * wherever a risk topic appears is robust (no fragile negation parsing) and
 * directly targets the real launch risk: a NEW doc that talks about funds /
 * mainnet / yield without the testnet/prototype framing.
 *
 * Pure, fast, static file reads — no network, no contracts, no deployment.
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";

import { expect } from "chai";

const REPO_ROOT = resolve(import.meta.dirname, "..");

// Topics that, if discussed, require a nearby safety disclaimer somewhere in the
// same document.
const RISK_TOPIC =
  /\b(deposit|withdraw|withdrawal|custody|custodial|yield|apy|apr|interest|returns|real funds|real value|mainnet|production deposit|production withdrawal)\b/i;

// Any one of these satisfies the disclaimer requirement.
const DISCLAIMER =
  /research prototype|not audited|unaudited|testnet|local only|local-only|no real value|no real funds|no real yield|not production|non-production|not for production|\bprototype\b|no mainnet|not a mainnet|no custody|does not custody|no monetary value/i;

// Root-level docs that are part of the public surface, plus everything under docs/.
const ROOT_DOCS = ["README.md", "SECURITY.md", "Project_Phases.md"];

// Anchors that MUST be in the scanned set, so the guard can never silently
// no-op if discovery breaks or a key doc is renamed.
const REQUIRED_ANCHORS = [
  "README.md",
  "SECURITY.md",
  "docs/THREAT_MODEL.md",
  "docs/ROADMAP.md",
  "docs/ZK_PQ_Status_Matrix.md",
  "docs/WALLETWALL_APP_BOUNDARY.md",
];

function walkMarkdown(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkMarkdown(full));
    else if (entry.name.endsWith(".md")) out.push(full);
  }
  return out;
}

function collectDocs(): string[] {
  const docs = ROOT_DOCS.map((f) => join(REPO_ROOT, f)).filter(existsSync);
  docs.push(...walkMarkdown(join(REPO_ROOT, "docs")));
  return docs;
}

const rel = (f: string): string => relative(REPO_ROOT, f).split(sep).join("/");

describe("docs — disclaimer coverage for risk-bearing topics", () => {
  const docs = collectDocs();

  it("discovers a broad, non-trivial set of docs including the key anchors", () => {
    const relPaths = docs.map(rel);
    expect(docs.length).to.be.greaterThanOrEqual(20, `expected a broad doc sweep, found only ${docs.length}`);
    for (const anchor of REQUIRED_ANCHORS) {
      expect(relPaths).to.include(anchor, `scanned doc set must include ${anchor}`);
    }
  });

  it("every doc that discusses a risk-bearing topic carries a disclaimer", () => {
    const offenders: string[] = [];
    for (const file of docs) {
      const text = readFileSync(file, "utf8");
      if (RISK_TOPIC.test(text) && !DISCLAIMER.test(text)) {
        offenders.push(rel(file));
      }
    }
    expect(offenders).to.deep.equal(
      [],
      `these docs mention deposits/withdrawals/custody/yield/mainnet/production ` +
        `but contain no prototype/testnet/not-audited/no-real-funds disclaimer:\n` +
        offenders.map((o) => `  - ${o}`).join("\n"),
    );
  });

  it("the two repo-root entry docs are themselves risk-topic docs that disclaim", () => {
    // README and SECURITY both describe what the prototype is and is not, so they
    // must both trip the risk-topic check AND satisfy the disclaimer requirement.
    for (const name of ["README.md", "SECURITY.md"]) {
      const text = readFileSync(join(REPO_ROOT, name), "utf8");
      expect(RISK_TOPIC.test(text)).to.equal(true, `${name} should discuss risk topics`);
      expect(DISCLAIMER.test(text)).to.equal(true, `${name} must carry a disclaimer`);
    }
  });
});
