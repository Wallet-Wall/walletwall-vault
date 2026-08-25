/**
 * SP1 pin-parity gate.
 *
 * zkvm/host/Cargo.toml states the invariant this enforces:
 *
 *   "sp1-sdk / sp1-build are pinned to the same SP1 release as the guest's
 *    sp1-zkvm dependency (zkvm/guest/Cargo.toml). If you bump one, bump all
 *    three together, then re-extract the program vKey."
 *
 * WHAT THIS CLOSES. Ignoring `sp1-*` in .github/dependabot.yml stops the
 * automated split bump (#150 moved only the guest's sp1-zkvm to 6.4.0), but it
 * constrains only Dependabot. A human, an agent, or a script can still edit one
 * pin and land it: zkvm/host is deliberately outside CI, the "Validate SP1 host
 * Cargo.lock" job checks that lockfile's own internal consistency and never
 * guest-vs-host parity, the TS<->Rust differential test that would exercise the
 * guest is skipped, and no ELF or vKey is committed whose drift would reveal it.
 * So a split SP1 upgrade currently goes fully green. This gate makes it fail.
 *
 * WHAT THIS DELIBERATELY DOES NOT PROVE. This is a declaration-parity check, not
 * a build. It proves the three DECLARED releases match and are exact-pinned. It
 * does NOT prove the declared release builds, executes, or proves correctly —
 * that needs the SP1 toolchain (`sp1up`), a guest rebuild, and vKey
 * re-extraction, which stay a maintainer procedure per docs/ZK_Prover_Runbook.md.
 * Keeping that boundary explicit is the point: CI proves what CI can prove.
 *
 * Pure TOML/text inspection — no SP1 toolchain, no cargo, no network, no Rust
 * build. Cheap enough to belong in ordinary CI.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 *       npm run validate:sp1-pin-parity   (dedicated CI step)
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect } from "chai";

import { checkSp1PinParity, readSp1Manifests, SP1_PINNED_CRATES } from "../scripts/lib/sp1-pin-parity";

const REPO_ROOT = join(import.meta.dirname, "..");

/** Minimal guest manifest carrying one sp1-zkvm pin. */
function guestToml(sp1Zkvm: string | null): string {
  return [
    "[package]",
    'name = "mldsa65-guest"',
    'version = "0.1.0"',
    "",
    "[dependencies]",
    ...(sp1Zkvm === null ? [] : [`sp1-zkvm = "${sp1Zkvm}"`]),
    'ml-dsa = "=0.1.1"',
    'serde = { version = "1.0", features = ["derive"] }',
    "",
  ].join("\n");
}

/** Minimal host manifest carrying sp1-sdk (deps) and sp1-build (build-deps). */
function hostToml(sp1Sdk: string | null, sp1Build: string | null): string {
  return [
    "# Version note: sp1-sdk / sp1-build are pinned to the same SP1 release as the",
    "# guest's sp1-zkvm dependency. If you bump one, bump all three together.",
    "[package]",
    'name = "mldsa65-host"',
    "",
    "[dependencies]",
    ...(sp1Sdk === null ? [] : [`sp1-sdk = "${sp1Sdk}"`]),
    'anyhow = "1.0"',
    "",
    "[build-dependencies]",
    ...(sp1Build === null ? [] : [`sp1-build = "${sp1Build}"`]),
    "",
  ].join("\n");
}

/** The three-pin world under test, as the gate sees it. */
function check(zkvm: string | null, sdk: string | null, build: string | null) {
  return checkSp1PinParity({ guestToml: guestToml(zkvm), hostToml: hostToml(sdk, build) });
}

describe("SP1 pin parity", function () {
  describe("agreement across the three crates", function () {
    it("accepts all three exact-pinned to the same release", function () {
      const r = check("=6.3.1", "=6.3.1", "=6.3.1");
      expect(r.errors, r.errors.join("\n")).to.deep.equal([]);
      expect(r.ok).to.equal(true);
    });

    it("accepts a coordinated bump of all three together", function () {
      const r = check("=6.4.0", "=6.4.0", "=6.4.0");
      expect(r.errors, r.errors.join("\n")).to.deep.equal([]);
      expect(r.ok).to.equal(true);
    });

    // One mutation per crate: each must be caught on its own, so a gate that
    // only ever compares two of the three cannot pass this suite.
    it("rejects a guest-only bump (the #150 shape)", function () {
      const r = check("=6.4.0", "=6.3.1", "=6.3.1");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-zkvm/);
      expect(r.errors.join("\n")).to.match(/6\.4\.0/);
    });

    it("rejects an sdk-only bump", function () {
      const r = check("=6.3.1", "=6.4.0", "=6.3.1");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-sdk/);
    });

    it("rejects a build-only bump", function () {
      const r = check("=6.3.1", "=6.3.1", "=6.4.0");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-build/);
    });
  });

  describe("exact-pin requirement", function () {
    // Parity alone is not enough: three matching caret ranges can still resolve
    // to different releases at build time, which is the same failure by a slower
    // route. The pins must be exact.
    for (const [label, spec] of [
      ["a caret range", "^6.3.1"],
      ["a tilde range", "~6.3.1"],
      ["a bare version", "6.3.1"],
      ["a wildcard minor", "6.3"],
    ] as const) {
      it(`rejects ${label} even when all three agree`, function () {
        const r = check(spec, spec, spec);
        expect(r.ok, `expected ${spec} to be rejected`).to.equal(false);
        expect(r.errors.join("\n")).to.match(/exact/i);
      });
    }

    it("rejects a single pin loosened to a range while the others stay exact", function () {
      const r = check("=6.3.1", "^6.3.1", "=6.3.1");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-sdk/);
      expect(r.errors.join("\n")).to.match(/exact/i);
    });
  });

  describe("missing declarations", function () {
    it("rejects a missing guest sp1-zkvm", function () {
      const r = check(null, "=6.3.1", "=6.3.1");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-zkvm/);
    });

    it("rejects a missing host sp1-sdk", function () {
      const r = check("=6.3.1", null, "=6.3.1");
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-sdk/);
    });

    it("rejects a missing host sp1-build", function () {
      const r = check("=6.3.1", "=6.3.1", null);
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-build/);
    });

    it("names all three crates it governs", function () {
      expect(SP1_PINNED_CRATES.map((c) => c.crate).sort()).to.deep.equal(["sp1-build", "sp1-sdk", "sp1-zkvm"]);
    });
  });

  describe("prose cannot satisfy the gate", function () {
    // zkvm/host/Cargo.toml's own comment names sp1-sdk and sp1-build in prose.
    // A reader that matched anywhere in the file would read the comment as a
    // declaration and pass with no real pins present.
    it("does not accept a crate named only inside a comment", function () {
      const commentOnly = [
        "[package]",
        'name = "mldsa65-host"',
        "",
        "[dependencies]",
        '# sp1-sdk = "=6.3.1"',
        '# sp1-build = "=6.3.1"',
        'anyhow = "1.0"',
        "",
      ].join("\n");
      const r = checkSp1PinParity({ guestToml: guestToml("=6.3.1"), hostToml: commentOnly });
      expect(r.ok).to.equal(false);
      expect(r.errors.join("\n")).to.match(/sp1-sdk/);
    });
  });

  describe("the repository as it stands", function () {
    // The in-suite half of the gate: npm run validate:sp1-pin-parity is the
    // dedicated CI step, and this makes a plain `npm test` fail on drift too.
    it("has all three SP1 pins in agreement and exact", function () {
      const r = checkSp1PinParity(readSp1Manifests(REPO_ROOT));
      expect(r.errors, r.errors.join("\n")).to.deep.equal([]);
      expect(r.ok).to.equal(true);
    });

    it("reads the real manifests, not a stand-in", function () {
      const { guestToml: g, hostToml: h } = readSp1Manifests(REPO_ROOT);
      expect(g).to.equal(readFileSync(join(REPO_ROOT, "zkvm/guest/Cargo.toml"), "utf8"));
      expect(h).to.equal(readFileSync(join(REPO_ROOT, "zkvm/host/Cargo.toml"), "utf8"));
    });
  });
});
