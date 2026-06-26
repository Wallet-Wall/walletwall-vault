/**
 * Tests + guards for the Option A static hosted evidence Reviewed Publish Workflow
 * (.github/workflows/publish-static-evidence.yml,
 * scripts/prepare-static-evidence-publish.ts, and
 * docs/Static_Hosted_Evidence_Publish_Workflow.md).
 *
 * This PR adds the actual reviewed, validation-gated publish workflow for the
 * already-checked-in Option A artifact. These guards prove, offline, that:
 *   - the doc identifies the source + staged/published paths, requires both the
 *     TypeScript and Rust validators before publish, documents cache/ETag, CORS,
 *     rollback, and disabling, scopes app/connector consumption as future work,
 *     preserves every safety boundary, and uses no affirmative overclaim language;
 *   - the workflow is manual-dispatch only, runs validation before any deploy, the
 *     deploy is gated by the explicit input + protected environment, it references
 *     only the single staging path, runs no prover/SP1/RPC/contract-call/chain step,
 *     references no secret, and contains no wildcard copy; and
 *   - the staging script copies ONLY the one approved artifact, byte-for-byte.
 *
 * Pure, fast, static reads plus a deterministic staging into a gitignored temp dir —
 * no server, no network, no proving, no publish.
 */
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { expect } from "chai";

import { STATIC_ARTIFACT_PATH, STATIC_ARTIFACT_REL } from "../scripts/generate-static-evidence-artifact";
import {
  STAGED_ARTIFACT_REL,
  STAGING_DIR_REL,
  buildPublishStaging,
  verifyPublishStaging,
} from "../scripts/prepare-static-evidence-publish";

const DOC_PATH = resolve("docs/Static_Hosted_Evidence_Publish_Workflow.md");
const README_PATH = resolve("README.md");
const WORKFLOW_PATH = resolve(".github/workflows/publish-static-evidence.yml");
const SCRIPT_PATH = resolve("scripts/prepare-static-evidence-publish.ts");

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

describe("Option A static hosted evidence — reviewed publish workflow", function () {
  describe("docs guard (docs/Static_Hosted_Evidence_Publish_Workflow.md)", function () {
    it("the workflow doc exists", function () {
      expect(existsSync(DOC_PATH), `${DOC_PATH} must exist`).to.equal(true);
    });

    const raw = read(DOC_PATH);
    const norm = normalize(raw);
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
        "Workflow",
        "Artifact source path",
        "Staged and published path",
        "Validation gates before publish",
        "Cache and ETag",
        "CORS",
        "Rollback",
        "Manual approval and protected environment",
        "App consumption boundary",
        "Safety boundaries preserved",
        "Acceptance criteria",
      ];
      for (const heading of requiredHeadings) {
        const escaped = heading.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
        const re = new RegExp(`^##\\s+${escaped}\\s*$`, "im");
        expect(re.test(raw), `missing heading: ## ${heading}`).to.equal(true);
      }
    });

    it("states plainly what is published (nothing on merge)", function () {
      expect(norm).to.include("merging this pr publishes nothing");
      expect(norm).to.include("publishes nothing");
    });

    it("identifies the source artifact path", function () {
      expect(raw).to.include(STATIC_ARTIFACT_REL);
      expect(STATIC_ARTIFACT_REL, "source path must carry a version segment").to.match(/(^|\/)v\d+\//);
    });

    it("identifies the staged/published path", function () {
      expect(raw).to.include(STAGED_ARTIFACT_REL);
      expect(raw).to.include(STAGING_DIR_REL);
    });

    it("requires TypeScript validation before publish", function () {
      expect(norm).to.include("typescript validator role");
      expect(norm).to.include("validate:static-artifact");
    });

    it("requires Rust validation before publish", function () {
      expect(norm).to.include("rust validator role");
      expect(norm).to.include("evidence-validator");
    });

    it("documents the cache and ETag behavior", function () {
      expect(norm).to.include("cache");
      expect(norm).to.include("etag");
      expect(norm).to.include("if-none-match");
    });

    it("documents the CORS behavior", function () {
      expect(norm).to.include("cors");
      expect(norm).to.match(/read-only get/);
    });

    it("documents the rollback process and how to disable publishing", function () {
      expect(norm).to.include("rollback");
      expect(norm).to.match(/disable|disabling/);
    });

    it("documents the manual-dispatch + protected-environment approval", function () {
      expect(norm).to.match(/manual-dispatch|workflow dispatch/);
      expect(norm).to.include("github-pages");
      expect(norm).to.include("environment");
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
      const forbidden = [
        "production zk",
        "mainnet custody",
        "wallet safety guarantee",
        "live proving",
        "dynamic endpoint deployment",
        "deployment reproducibility",
      ];
      const offenders = findOverclaims(normNoHyphen, forbidden);
      expect(offenders).to.deep.equal(
        [],
        `gated-capability overclaim used affirmatively:\n  ${offenders.join("\n  ")}`,
      );
    });

    it("is pointed to from the README documentation map", function () {
      expect(read(README_PATH)).to.include("docs/Static_Hosted_Evidence_Publish_Workflow.md");
    });
  });

  describe("workflow guard (.github/workflows/publish-static-evidence.yml)", function () {
    it("the workflow exists", function () {
      expect(existsSync(WORKFLOW_PATH), `${WORKFLOW_PATH} must exist`).to.equal(true);
    });

    const raw = read(WORKFLOW_PATH);
    // Strip comment lines so trigger checks inspect real YAML keys, not prose.
    const code = raw
      .split("\n")
      .filter((line) => !/^\s*#/.test(line))
      .join("\n");

    it("is manual-dispatch only (no push/schedule/release publish trigger)", function () {
      expect(code).to.match(/workflow_dispatch:/);
      expect(code).to.not.match(/^\s+push:/m);
      expect(code).to.not.match(/^\s+schedule:/m);
      expect(code).to.not.match(/^\s+release:/m);
    });

    it("uploads only the single static-artifact staging path", function () {
      expect(code).to.match(/path:\s*dist\/hosted-evidence\b/);
      expect(STAGING_DIR_REL).to.equal("dist/hosted-evidence");
    });

    it("runs the TypeScript + Rust validators before any deploy", function () {
      expect(code).to.include("validate:zk-response");
      expect(code).to.include("validate:static-artifact");
      expect(code).to.include("static:publish:prepare");
      expect(code).to.include("cargo fmt --check --manifest-path zkvm/evidence-validator/Cargo.toml");
      expect(code).to.include("cargo check --locked --manifest-path zkvm/evidence-validator/Cargo.toml");
      expect(code).to.include("cargo test --locked --manifest-path zkvm/evidence-validator/Cargo.toml");
    });

    it("gates the deploy job behind the validators, the explicit input, and a protected environment", function () {
      expect(code).to.match(/needs:\s*\[[^\]]*validate-and-stage[^\]]*evidence-validator[^\]]*\]/);
      expect(code).to.include("if: ${{ inputs.publish }}");
      expect(code).to.match(/environment:\s*[\s\S]*?name:\s*github-pages/);
    });

    it("references no repository secret", function () {
      expect(raw).to.not.match(/secrets\./);
    });

    it("runs no prover / SP1 / RPC / chain / contract-call step", function () {
      const banned = [
        /\bsp1\b/i,
        /run_sp1/i,
        /\bprover\b/i,
        /\bproving\b/i,
        /--network\b/,
        /hardhat run\b/,
        /deploy:sepolia/i,
        /deploy:base/i,
        /\beth_call\b/i,
        /\beth_send/i,
        /\brpc\b/i,
        /cast call/i,
        /forge script/i,
      ];
      // Scan the comment-stripped YAML: an executable step is never a comment, so a
      // negated safety note ("never runs a prover") must not trip the denylist.
      const hits = banned.filter((re) => re.test(code)).map((re) => re.toString());
      expect(hits).to.deep.equal([], `workflow references a forbidden execution step:\n  ${hits.join("\n  ")}`);
    });

    it("contains no wildcard copy command", function () {
      expect(raw).to.not.match(/\bcp\s+-[rRa]/);
      expect(raw).to.not.match(/\brsync\b/);
      expect(raw).to.not.match(/\*\*/);
      expect(raw).to.not.match(/xcopy/i);
    });
  });

  describe("staging script guard + behavior (scripts/prepare-static-evidence-publish.ts)", function () {
    const TMP = resolve("dist/.test-publish-staging");

    after(function () {
      rmSync(TMP, { recursive: true, force: true });
    });

    it("the staging script exists and targets only the approved artifact", function () {
      expect(existsSync(SCRIPT_PATH), `${SCRIPT_PATH} must exist`).to.equal(true);
      const src = read(SCRIPT_PATH);
      expect(src).to.include("STATIC_ARTIFACT_PATH");
      expect(src).to.include("STATIC_ARTIFACT_REL");
      // Single-file copy only: it writes the one artifact and never reaches for a
      // multi-file/recursive copy primitive. The "exactly one file" behavior test
      // below is the binding proof; these are belt-and-suspenders source checks.
      expect(src).to.include("writeFileSync");
      expect(src).to.not.match(/cpSync/);
      expect(src).to.not.match(/\brsync\b/);
    });

    it("stages exactly the one approved artifact, byte-for-byte", function () {
      const { files, stagedArtifactPath } = buildPublishStaging(TMP);
      expect(files).to.deep.equal([STATIC_ARTIFACT_REL]);
      expect(read(stagedArtifactPath)).to.equal(read(STATIC_ARTIFACT_PATH));
      expect(() => verifyPublishStaging(TMP)).to.not.throw();
    });

    it("rejects an extra file in the staging tree", function () {
      buildPublishStaging(TMP);
      writeFileSync(join(TMP, "stray.json"), "{}");
      expect(() => verifyPublishStaging(TMP)).to.throw(/exactly the approved artifact/);
    });

    it("rejects drift between the staged and checked-in artifact", function () {
      const { stagedArtifactPath } = buildPublishStaging(TMP);
      writeFileSync(stagedArtifactPath, "{}\n");
      expect(() => verifyPublishStaging(TMP)).to.throw(/differs from the checked-in artifact/);
    });
  });
});
