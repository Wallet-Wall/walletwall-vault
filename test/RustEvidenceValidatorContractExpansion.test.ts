/**
 * Docs guard for the Rust Evidence Validator — Contract-Validation Expansion
 * document (docs/Rust_Evidence_Validator_Contract_Expansion.md) and its README
 * pointer.
 *
 * The expansion strengthens the Phase 1 offline validator
 * (zkvm/evidence-validator/) with more deterministic contract checks. This guard
 * is a pure, fast, static file read — no network, no contracts, no deployment, no
 * Rust toolchain. It checks that the doc:
 *
 *   - exists,
 *   - carries the prototype / testnet / not-audited / no-real-funds disclaimer,
 *   - states the validator is offline-only,
 *   - lists the deterministic contract fields it now validates,
 *   - documents that the keccak256 etag cross-check stays deferred to TypeScript
 *     (nothing is verified cryptographically here),
 *   - states no prover execution,
 *   - states no network / RPC calls,
 *   - states no endpoint deployment,
 *   - states no contract / ABI / deployment changes,
 *   - explains its relationship to docs/Rust_Implementation_Path.md (Phase 1),
 *   - documents how to run it offline with cargo,
 *   - is pointed to from the README documentation map,
 *   - uses no affirmative overclaims about production ZK, mainnet custody, wallet
 *     safety guarantees, live proving, active endpoint deployment, or deployment
 *     reproducibility.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const DOC_PATH = resolve("docs/Rust_Evidence_Validator_Contract_Expansion.md");
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

describe("Rust Evidence Validator Contract Expansion — docs guard", function () {
  it("the expansion doc exists", function () {
    expect(existsSync(DOC_PATH), `${DOC_PATH} must exist`).to.equal(true);
  });

  const raw = read(DOC_PATH);
  const norm = normalize(raw);

  it("carries a prototype / testnet / not-audited / no-real-funds disclaimer", function () {
    expect(norm).to.match(/research prototype/);
    expect(norm).to.match(/not audited/);
    expect(norm).to.match(/testnet/);
    expect(norm).to.match(/no real funds/);
  });

  it("states the validator is offline-only", function () {
    expect(norm).to.match(/offline[-\s]only/);
  });

  it("lists the deterministic contract fields it validates", function () {
    for (const field of [
      "status",
      "ok",
      "consistency",
      "servedat",
      "etag",
      "adapter",
      "identity",
      "limitations",
      "regeneration",
    ]) {
      expect(norm, `expansion doc must mention the validated field/topic: ${field}`).to.include(field);
    }
  });

  it("documents that the keccak256 etag cross-check stays deferred (nothing verified cryptographically)", function () {
    expect(norm).to.include("keccak256");
    expect(norm).to.include("deferred");
    expect(norm).to.include("cryptographic");
    expect(norm).to.include("no proof is generated");
  });

  it("states no prover execution", function () {
    expect(norm).to.include("no prover execution");
  });

  it("states no network and no RPC calls", function () {
    expect(norm).to.include("no network");
    expect(norm).to.include("no rpc");
  });

  it("states no endpoint deployment", function () {
    expect(norm).to.include("no endpoint deployment");
  });

  it("states no contract or ABI changes", function () {
    expect(norm).to.include("no contract or abi changes");
  });

  it("explains its relationship to the Rust implementation path (Phase 1)", function () {
    // normalize() turns underscores into spaces, so the filename reads as words.
    expect(norm).to.include("rust implementation path");
    expect(norm).to.include("phase 1");
  });

  it("documents how to run it offline with cargo", function () {
    expect(norm).to.include("cargo test");
    expect(norm).to.include("cargo run");
  });

  it("is pointed to from the README documentation map", function () {
    const readme = read(README_PATH);
    expect(readme).to.include("docs/Rust_Evidence_Validator_Contract_Expansion.md");
  });

  it("uses no forbidden overclaim language in affirmative form", function () {
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
      "mainnet custody",
      "production zk",
      "production-zk",
      "mainnet-ready",
    ];
    const NEGATION = /\b(no|not|never|without|non|cannot|avoid|avoids|gated|nor|neither|must not|may not)\b/;
    const offenders: string[] = [];

    for (const term of forbidden) {
      const re = new RegExp(`(^|[^a-z])${term.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")}([^a-z]|$)`, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(norm)) !== null) {
        const start = m.index;
        const before = norm.slice(Math.max(0, start - 55), start);
        if (!NEGATION.test(before)) {
          offenders.push(`${term} @${start} ("...${norm.slice(Math.max(0, start - 35), start + term.length + 5)}...")`);
        }
      }
    }

    expect(offenders).to.deep.equal(
      [],
      `forbidden overclaim language used affirmatively:\n  ${offenders.join("\n  ")}`,
    );
  });

  it("does not claim production ZK, live proving, active endpoint deployment, or deployment reproducibility in affirmative form", function () {
    const deployClaims = [
      "endpoint is live",
      "endpoint is active",
      "active endpoint deployment",
      "proof is generated",
      "proof is produced",
      "live proving",
      "wallet safety",
      "deployment-reproducibility",
      "reproducible from public head",
      "reproducible from current head",
    ];
    const NEGATION = /\b(no|not|never|without|non|cannot|pending|gated|nor|neither|not yet|must not)\b/;
    for (const phrase of deployClaims) {
      const idx = norm.indexOf(phrase);
      if (idx !== -1) {
        const before = norm.slice(Math.max(0, idx - 55), idx);
        expect(
          NEGATION.test(before),
          `affirmative production-ZK / proving / endpoint / reproducibility claim: "${phrase}"`,
        ).to.equal(true);
      }
    }
  });
});
