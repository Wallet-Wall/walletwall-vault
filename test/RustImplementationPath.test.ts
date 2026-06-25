/**
 * Docs guard for the Rust Implementation Path document
 * (docs/Rust_Implementation_Path.md).
 *
 * This is a docs/spec/planning PR: it changes no Rust crates, no contracts,
 * no evidence artifacts, and no CI jobs. The guard checks:
 *
 *   - the doc exists,
 *   - the disclaimer is present (prototype / testnet / not-audited / no-real-funds),
 *   - Rust's approved role is bounded to deterministic/offline tooling,
 *   - the non-goals block is present and covers all required categories,
 *   - the TypeScript/Rust split is present,
 *   - all five rollout phases (0–5) are present,
 *   - acceptance criteria for the first real Rust scaffold PR are present,
 *   - the README points to this document,
 *   - no affirmative overclaims about production ZK, mainnet custody, wallet
 *     safety guarantees, live proving, active endpoint deployment, or
 *     deployment reproducibility appear in the doc.
 *
 * Pure, fast, static file reads — no network, no contracts, no deployment.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const DOC_PATH = resolve("docs/Rust_Implementation_Path.md");
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

describe("Rust Implementation Path — docs guard", function () {
  it("the doc exists", function () {
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

  it("contains every required structural heading", function () {
    const requiredHeadings = [
      "Purpose",
      "Rust's approved role",
      "Non-goals",
      "TypeScript / Rust split",
      "Rollout phases",
      "Acceptance criteria for the first real Rust scaffold PR",
      "Security boundaries",
      "Related",
    ];
    for (const heading of requiredHeadings) {
      const escaped = heading.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
      const re = new RegExp(`^##\\s+${escaped}\\s*$`, "im");
      expect(re.test(raw), `missing heading: ## ${heading}`).to.equal(true);
    }
  });

  describe("Rust approved role", function () {
    it("names deterministic evidence tooling as an approved use", function () {
      expect(norm).to.include("deterministic evidence tooling");
    });

    it("names canonical artifact normalization as an approved use", function () {
      expect(norm).to.include("canonical artifact normalization");
    });

    it("names proof-input validation as an approved use", function () {
      expect(norm).to.include("proof-input validation");
    });

    it("names fixture parity checks as an approved use", function () {
      expect(norm).to.include("fixture parity checks");
    });

    it("names offline CLI validation as an approved use", function () {
      expect(norm).to.include("offline cli validation");
    });

    it("names SP1 adapter boundary support as an approved use", function () {
      expect(norm).to.include("sp1 adapter boundary support");
    });

    it("states no app custody", function () {
      expect(norm).to.include("no app custody");
    });

    it("states no app wallet interaction", function () {
      expect(norm).to.include("no app wallet interaction");
    });

    it("states no default prover execution", function () {
      expect(norm).to.include("no default prover execution");
    });
  });

  describe("Non-goals block", function () {
    it("forbids mainnet custody", function () {
      expect(norm).to.include("mainnet custody");
    });

    it("forbids production-zk claims", function () {
      expect(norm).to.include("production-zk claims");
    });

    it("forbids private keys", function () {
      expect(norm).to.include("private keys");
    });

    it("forbids wallet connection", function () {
      expect(norm).to.include("wallet connection");
    });

    it("forbids transaction signing", function () {
      expect(norm).to.include("transaction signing");
    });

    it("forbids on-chain writes", function () {
      expect(norm).to.include("on-chain writes");
    });

    it("forbids app runtime proving", function () {
      expect(norm).to.include("app runtime proving");
    });

    it("forbids network-required prover jobs by default", function () {
      expect(norm).to.include("network-required prover jobs by default");
    });

    it("forbids endpoint deployment", function () {
      expect(norm).to.include("endpoint deployment");
    });

    it("forbids hosted artifact publishing", function () {
      expect(norm).to.include("hosted artifact publishing");
    });

    it("forbids evidence semantic changes", function () {
      expect(norm).to.include("evidence semantic changes");
    });

    it("forbids contract or abi changes", function () {
      expect(norm).to.include("contract or abi changes");
    });
  });

  describe("TypeScript / Rust split", function () {
    it("states TypeScript retains ownership of docs guard tests", function () {
      expect(norm).to.include("docs guard tests");
    });

    it("states TypeScript retains endpoint response schema checks", function () {
      expect(norm).to.include("endpoint response schema checks");
    });

    it("states TypeScript retains app-facing json contract tests", function () {
      expect(norm).to.include("app-facing json contract tests");
    });

    it("states TypeScript retains existing validator orchestration", function () {
      expect(norm).to.include("existing validator orchestration");
    });

    it("describes what Rust may later own", function () {
      expect(norm).to.include("rust may later own");
    });

    it("states rust may own canonical evidence serialization", function () {
      expect(norm).to.include("canonical evidence serialization");
    });

    it("states rust may own fixture drift detection", function () {
      expect(norm).to.include("fixture drift detection");
    });

    it("states rust may own sp1 adapter input preparation", function () {
      expect(norm).to.include("sp1 adapter input preparation");
    });
  });

  describe("Rollout phases", function () {
    it("includes Phase 0 — docs/spec/test guard", function () {
      expect(norm).to.include("phase 0");
      expect(norm).to.match(/phase 0.*docs|docs.*spec.*guard/);
    });

    it("includes Phase 1 — Rust crate boundary", function () {
      expect(norm).to.include("phase 1");
      expect(norm).to.match(/phase 1.*rust crate boundary|rust crate boundary/);
    });

    it("includes Phase 2 — fixture parity", function () {
      expect(norm).to.include("phase 2");
      expect(norm).to.match(/phase 2.*fixture parity|fixture parity/);
    });

    it("includes Phase 3 — adapter validation", function () {
      expect(norm).to.include("phase 3");
      expect(norm).to.match(/phase 3.*adapter validation|adapter validation/);
    });

    it("includes Phase 4 — reviewed prover path", function () {
      expect(norm).to.include("phase 4");
      expect(norm).to.match(/phase 4.*reviewed prover path|reviewed prover path/);
    });

    it("includes Phase 5 — hosted evidence artifact integration after separate security review", function () {
      expect(norm).to.include("phase 5");
      expect(norm).to.include("hosted evidence artifact integration");
      expect(norm).to.include("security review");
    });
  });

  describe("Acceptance criteria for first scaffold PR", function () {
    it("requires the crate to be in zkvm/", function () {
      expect(norm).to.include("zkvm/");
    });

    it("requires cargo build to succeed offline", function () {
      expect(norm).to.include("cargo build");
    });

    it("requires cargo test to pass with no external network call", function () {
      expect(norm).to.include("cargo test");
      expect(norm).to.include("no external network call");
    });

    it("requires npm test to still pass", function () {
      expect(norm).to.include("npm test");
    });

    it("requires npm run format:check to still pass", function () {
      expect(norm).to.include("npm run format:check");
    });

    it("requires npm run typecheck to still pass", function () {
      expect(norm).to.include("npm run typecheck");
    });

    it("requires npm run lint to still pass", function () {
      expect(norm).to.include("npm run lint");
    });

    it("requires a safety-boundaries-preserved section in the PR", function () {
      expect(norm).to.include("safety boundaries preserved");
    });
  });

  it("is pointed to from the README documentation map", function () {
    const readme = read(README_PATH);
    expect(readme).to.include("docs/Rust_Implementation_Path.md");
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

  it("does not claim active endpoint deployment, live proving, or deployment reproducibility in affirmative form", function () {
    const deployClaims = [
      "endpoint is live",
      "endpoint is active",
      "proof is generated",
      "proof is produced",
      "reproducible from public head",
      "reproducible from current head",
    ];
    for (const phrase of deployClaims) {
      const NEGATION = /\b(no|not|never|without|non|cannot|pending|gated|nor|neither|not yet|must not)\b/;
      const idx = norm.indexOf(phrase);
      if (idx !== -1) {
        const before = norm.slice(Math.max(0, idx - 55), idx);
        expect(NEGATION.test(before), `affirmative endpoint/proof/reproducibility claim: "${phrase}"`).to.equal(true);
      }
    }
  });
});
