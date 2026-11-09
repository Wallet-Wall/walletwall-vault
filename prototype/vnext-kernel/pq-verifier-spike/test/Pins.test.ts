/**
 * GEN2-PQ-CONFORMANCE-1 — provenance pins: every vendored byte, every fixture, every licence, re-verified.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. This suite does not run the verifier; it establishes that what the
 * other suites run is exactly what SOURCE_PINS.json says it is, and that the fixtures are the files they claim
 * to be.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { SOURCE_UNITS, SPIKE_DIR, VENDOR_DIR, sha256Hex } from "../lib/compile.js";
import { FIXTURES_DIR, helperRuntimeHex, hex, pinnedHelperCodehash, unhex } from "../lib/world.js";

interface Pins {
  upstreams: Record<
    string,
    {
      repository: string;
      commit: string;
      licence: string;
      licenceFile: string;
      files: Record<string, { upstreamPath: string; bytes: number; sha256: string }>;
    }
  >;
}

const walk = (dir: string): string[] =>
  fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));

describe("pq-verifier-spike — provenance pins", function () {
  const pins = JSON.parse(fs.readFileSync(path.join(SPIKE_DIR, "SOURCE_PINS.json"), "utf8")) as Pins;

  it("every vendored file is listed in SOURCE_PINS.json with its exact size and sha256, and nothing unlisted sits under vendor/", function () {
    const listed = new Set<string>();
    for (const [dir, u] of Object.entries(pins.upstreams)) {
      for (const [local, f] of Object.entries(u.files)) {
        const p = path.join(VENDOR_DIR, dir, local);
        listed.add(path.resolve(p));
        const bytes = fs.readFileSync(p);
        expect(bytes.length, `${dir}/${local} size`).to.equal(f.bytes);
        expect(sha256Hex(bytes), `${dir}/${local} sha256`).to.equal(f.sha256);
      }
      expect(
        fs.existsSync(path.join(VENDOR_DIR, dir, u.licenceFile)),
        `${dir}: licence file ${u.licenceFile}`,
      ).to.equal(true);
      expect(fs.readFileSync(path.join(VENDOR_DIR, dir, u.licenceFile), "utf8")).to.match(/MIT License/);
      expect(u.commit).to.match(/^[0-9a-f]{8,40}$/);
    }
    const present = walk(VENDOR_DIR).map((p) => path.resolve(p));
    expect(
      present.filter((p) => !listed.has(p)),
      "unlisted files under vendor/",
    ).to.deep.equal([]);
    expect(listed.size).to.equal(present.length);
  });

  it("the compiled closure is exactly the vendored ZKNOX, sstore2 and InterfaceVerifier files", function () {
    for (const rel of Object.values(SOURCE_UNITS))
      expect(fs.existsSync(path.join(VENDOR_DIR, rel)), rel).to.equal(true);
    const zknox = pins.upstreams["zknox-ethdilithium-4c370bb5"]!;
    expect(zknox.commit).to.equal("4c370bb5ff90d98e1ce8fb96f867126f0fbb9046");
    expect(
      Object.keys(zknox.files)
        .filter((f) => f.endsWith(".sol"))
        .sort(),
    ).to.deep.equal(
      Object.values(SOURCE_UNITS)
        .filter((r) => r.startsWith("zknox-"))
        .map((r) => r.replace("zknox-ethdilithium-4c370bb5/", ""))
        .sort(),
    );
  });

  it("the Keccak-f[1600] helper bytes hash (keccak256) to the F1600_CODEHASH constant the verifier pins, are 21,622 bytes, and match the pinned sha256", function () {
    const runtime = unhex(helperRuntimeHex());
    expect(runtime.length).to.equal(21_622);
    expect("0x" + hex(keccak_256(runtime))).to.equal(pinnedHelperCodehash());
    const fb = pins.upstreams["fireblocks-evm-ml-dsa-verifier-cca262b5"]!;
    expect(fb.files["helpers/f1600_170.hex"]!.sha256).to.equal(
      "f26320c4be54bdf71270d0ca92a6cf665966f0a320b84676aa75d5fa3dc612c4",
    );
    // the core the dispatcher wraps: its generator is lost upstream; only its hash is pinned
    expect(fb.files["helpers/f1600_core.hex"]!.sha256).to.equal(
      "46fbc67c4040f22929be6abb43abb935a3f2ae6b03398729c09afe0c898764ee",
    );
  });

  it("the helper dispatcher rebuilds from the core with the vendor's tool (python3, when available)", function () {
    const dir = path.join(VENDOR_DIR, "fireblocks-evm-ml-dsa-verifier-cca262b5");
    let python: string | null = null;
    for (const candidate of ["python3", "python"]) {
      try {
        const v = execFileSync(candidate, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        if (/Python 3\./.test(v)) {
          python = candidate;
          break;
        }
      } catch {
        /* not available */
      }
    }
    if (!python) {
      console.log(
        "[pins] python3 not available: helper rebuild check NOT run here (recorded in SPIKE_RECORD.md from a local run)",
      );
      this.skip();
    }
    const out = execFileSync(python!, ["-I", "tools/build_f1600_batch.py", "--check"], { cwd: dir, encoding: "utf8" });
    expect(out).to.match(/--check: helpers\/f1600_170\.hex matches this build/);
    expect(out).to.include(pinnedHelperCodehash());
  });

  it("fixtures: the Wycheproof file is the pinned upstream bytes; the extracts declare their sources and counts", function () {
    const wp = fs.readFileSync(path.join(FIXTURES_DIR, "wycheproof-mldsa_65_verify_test.json"));
    const rec = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, "wycheproof-record.json"), "utf8")) as {
      sha256: string;
      numberOfTests: number;
    };
    expect(sha256Hex(wp)).to.equal(rec.sha256);
    expect(rec.sha256).to.equal("1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034");
    expect((JSON.parse(wp.toString("utf8")) as { numberOfTests: number }).numberOfTests).to.equal(210);
    const acvp = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, "acvp-mldsa65-sigver-tgid3.json"), "utf8")) as {
      source: { sha256: string };
      count: number;
      tests: unknown[];
    };
    expect(acvp.source.sha256).to.equal("47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437");
    expect(acvp.count).to.equal(15);
    expect(acvp.tests.length).to.equal(15);
    const rsp = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, "nist-rsp-dilithium3-counts0-9.json"), "utf8")) as {
      source: { sha256: string };
      count: number;
    };
    expect(rsp.source.sha256).to.equal("46b223fcc82cfc456007b305d85b5ad9dbdfcc511853314b42d3b7b0c8b29795");
    expect(rsp.count).to.equal(10);
    const vendor = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, "vendor-vectors.json"), "utf8")) as {
      source: { sha256: string; commit: string };
      count: number;
    };
    expect(vendor.source.sha256).to.equal("fc38096dddfd0125128022cb3f7f3e4e58fa9cfa195155cb259c20049fec8ff8");
    expect(vendor.source.commit).to.equal("4c370bb5ff90d98e1ce8fb96f867126f0fbb9046");
    expect(vendor.count).to.equal(28);
    const gen = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, "generated-vectors.json"), "utf8")) as {
      counts: Record<string, number>;
      vectors: unknown[];
    };
    expect(gen.counts).to.deep.equal({
      digest32_valid: 32,
      digest32_negative: 10,
      znorm_boundary: 3,
      hint_canonicality: 6,
      degenerate_key: 1,
    });
    expect(gen.vectors.length).to.equal(52);
  });

  it("every vendored Solidity file keeps its upstream licence header and pragma", function () {
    for (const rel of Object.values(SOURCE_UNITS)) {
      const text = fs.readFileSync(path.join(VENDOR_DIR, rel), "utf8");
      expect(text, rel).to.match(/SPDX-License-Identifier: MIT/);
      expect(text, rel).to.match(/pragma solidity/);
    }
  });
});
