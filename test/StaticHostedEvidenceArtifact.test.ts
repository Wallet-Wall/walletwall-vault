/**
 * Tests + docs guard for the Option A static hosted evidence artifact
 * (evidence/zk/hosted/v1/zk-adapter-evidence-response.json and
 * docs/Static_Hosted_Evidence_Artifact.md).
 *
 * The static artifact is the byte-for-byte copy of the committed canonical example
 * that a static host WOULD serve under Option A. These tests prove, offline, that
 * it is faithful, valid, ETag-correct, served from a versioned path, and has not
 * drifted — and that the doc carries the disclaimers, the publishes-nothing
 * boundary, and no affirmative overclaim language.
 *
 * Pure, fast, static file reads — no server, no network, no proving, no publish.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  computeAdapterETag,
  validateAdapterEvidenceResponse,
  type ZKAdapterEvidenceResponse,
} from "../scripts/lib/zk-adapter-endpoint";
import {
  CANONICAL_PATH,
  STATIC_ARTIFACT_PATH,
  STATIC_ARTIFACT_REL,
  buildStaticArtifactBytes,
} from "../scripts/generate-static-evidence-artifact";

const DOC_PATH = resolve("docs/Static_Hosted_Evidence_Artifact.md");
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

describe("Option A static hosted evidence artifact", function () {
  describe("committed artifact (faithful, valid, versioned, no drift)", function () {
    it("exists at a versioned path", function () {
      expect(existsSync(STATIC_ARTIFACT_PATH), `${STATIC_ARTIFACT_PATH} must exist`).to.equal(true);
      expect(STATIC_ARTIFACT_REL, "static artifact path must carry a version segment").to.match(/(^|\/)v\d+\//);
    });

    it("is byte-for-byte identical to the canonical example", function () {
      expect(read(STATIC_ARTIFACT_PATH)).to.equal(read(CANONICAL_PATH));
      expect(read(STATIC_ARTIFACT_PATH)).to.equal(buildStaticArtifactBytes());
    });

    it("is a valid zk-adapter-evidence-response.v1", function () {
      const onDisk = JSON.parse(read(STATIC_ARTIFACT_PATH));
      const res = validateAdapterEvidenceResponse(onDisk);
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
    });

    it("carries an etag that is keccak256 of its served adapter", function () {
      const onDisk = JSON.parse(read(STATIC_ARTIFACT_PATH)) as ZKAdapterEvidenceResponse;
      expect(onDisk.etag).to.equal(computeAdapterETag(onDisk.adapter));
    });
  });

  describe("docs guard (docs/Static_Hosted_Evidence_Artifact.md)", function () {
    it("the doc exists", function () {
      expect(existsSync(DOC_PATH), `${DOC_PATH} must exist`).to.equal(true);
    });

    const raw = read(DOC_PATH);
    const norm = normalize(raw);

    it("carries a prototype / not-audited / testnet / no-real-funds disclaimer", function () {
      expect(norm).to.match(/research prototype/);
      expect(norm).to.match(/not audited/);
      expect(norm).to.match(/testnet/);
      expect(norm).to.match(/no real funds/);
    });

    it("states the publishes-nothing boundary (no server / deploy / pages)", function () {
      expect(norm).to.include("publishes nothing");
      expect(norm).to.match(/no server|no deploy|github pages/);
    });

    it("references the versioned static artifact path", function () {
      expect(raw).to.include(STATIC_ARTIFACT_REL);
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
      const NEGATION = /\b(no|not|never|without|non|cannot|avoid|avoids|gated|nor|neither)\b/;
      const offenders: string[] = [];

      for (const term of forbidden) {
        const re = new RegExp(`(^|[^a-z])${term.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")}([^a-z]|$)`, "g");
        let m: RegExpExecArray | null;
        while ((m = re.exec(norm)) !== null) {
          const start = m.index;
          const before = norm.slice(Math.max(0, start - 45), start);
          if (!NEGATION.test(before)) {
            offenders.push(
              `${term} @${start} ("...${norm.slice(Math.max(0, start - 30), start + term.length + 5)}...")`,
            );
          }
        }
      }

      expect(offenders).to.deep.equal(
        [],
        `forbidden overclaim language used affirmatively:\n  ${offenders.join("\n  ")}`,
      );
    });

    it("is pointed to from the README documentation map", function () {
      expect(read(README_PATH)).to.include("docs/Static_Hosted_Evidence_Artifact.md");
    });
  });
});
