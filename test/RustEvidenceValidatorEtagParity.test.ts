/**
 * Docs guard for the Rust Evidence Validator — Canonical ETag / keccak256 Parity
 * document (docs/Rust_Evidence_Validator_Etag_Parity.md) and its README pointer.
 *
 * The ETag-parity step lets the offline Rust validator
 * (zkvm/evidence-validator/) recompute the canonical keccak256 `etag` of a
 * committed evidence artifact and check it for deterministic parity against the
 * value the TypeScript serializer committed. This guard is a pure, fast, static
 * file read — no network, no contracts, no deployment, no Rust toolchain. It
 * checks that the doc:
 *
 *   - exists,
 *   - carries the prototype / testnet / not-audited / no-real-funds disclaimer,
 *   - states the validator is offline-only,
 *   - lists what ETag / canonical parity validates (keccak256, etag, adapter,
 *     canonical, parity),
 *   - states this is not proof verification and not cryptographic truth,
 *   - states no proof is generated / no prover execution,
 *   - states no network / RPC calls,
 *   - states no endpoint deployment,
 *   - states no hosted artifact publishing,
 *   - states no contract / ABI / deployment changes,
 *   - documents how to run it offline with cargo,
 *   - is pointed to from the README documentation map,
 *   - uses no affirmative overclaims about production ZK, mainnet custody, wallet
 *     safety guarantees, live proving, active endpoint deployment, or deployment
 *     reproducibility.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const DOC_PATH = resolve("docs/Rust_Evidence_Validator_Etag_Parity.md");
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

describe("Rust Evidence Validator ETag Parity — docs guard", function () {
  it("the ETag parity doc exists", function () {
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

  it("lists what ETag / canonical parity validates", function () {
    for (const topic of ["keccak256", "etag", "adapter", "canonical", "parity"]) {
      expect(norm, `parity doc must mention: ${topic}`).to.include(topic);
    }
  });

  it("states it is not proof verification and not cryptographic truth", function () {
    expect(norm).to.include("not proof verification");
    expect(norm).to.include("not cryptographic truth");
  });

  it("states no proof is generated and no prover execution", function () {
    expect(norm).to.include("no proof is generated");
    expect(norm).to.include("no prover execution");
  });

  it("states no network and no RPC calls", function () {
    expect(norm).to.include("no network");
    expect(norm).to.include("no rpc");
  });

  it("states no endpoint deployment", function () {
    expect(norm).to.include("no endpoint deployment");
  });

  it("states no hosted artifact publishing", function () {
    expect(norm).to.include("no hosted artifact");
  });

  it("states no contract / ABI / deployment changes", function () {
    expect(norm).to.include("no contract, abi, or deployment changes");
  });

  it("documents how to run it offline with cargo", function () {
    expect(norm).to.include("cargo test");
    expect(norm).to.include("cargo run");
  });

  it("is pointed to from the README documentation map", function () {
    const readme = read(README_PATH);
    expect(readme).to.include("docs/Rust_Evidence_Validator_Etag_Parity.md");
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
      "wallet-safety",
      "deployment-reproducibility",
      "deployment reproducibility",
      "reproducible from public head",
      "reproducible from current head",
    ];
    const NEGATION = /\b(no|not|never|without|non|cannot|pending|gated|nor|neither|not yet|must not|offers)\b/;
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
