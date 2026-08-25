/**
 * Runtime-byte claim SOURCE collection tests
 * (scripts/lib/runtime-byte-claim-sources.ts).
 *
 * The reconciler in RuntimeByteClaimBinding.test.ts proves the decision logic.
 * This file proves the harder half: that the set of declarations handed to it
 * is actually COMPLETE. A gate that only checks the claims someone remembered
 * to register does not close a defect whose root cause is "someone forgot" —
 * so a prose claim that no registered site watches must fail the build, and a
 * registered site that no longer matches anything must fail too rather than
 * silently watching nothing.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";

import { expect } from "chai";

import {
  COVERED_PROSE_FILES,
  collectRuntimeByteClaims,
  extractProseDeclarations,
  findUnregisteredProseClaims,
  parseRuntimeByteTables,
  PROSE_CLAIM_SITES,
  RUNTIME_BYTE_SUBJECTS,
} from "../scripts/lib/runtime-byte-claim-sources";
import { collectReports, TARGET_CONTRACTS } from "../scripts/validate-bytecode-size";

const REPO_ROOT = join(import.meta.dirname, "..");

describe("runtime-byte claim sources", function () {
  describe("subject binding table", function () {
    it("binds each subject to exactly one artifact", function () {
      const names = RUNTIME_BYTE_SUBJECTS.map((s) => s.name);
      expect(new Set(names).size).to.equal(names.length, "a duplicate subject would make the authority ambiguous");
    });

    it("never diverges from the EIP-170 gate's artifact path for a shared contract", function () {
      // One measurement primitive means one artifact path per contract. If these
      // two lists could disagree, "the size" would depend on which gate asked.
      for (const target of TARGET_CONTRACTS) {
        const shared = RUNTIME_BYTE_SUBJECTS.find((s) => s.name === target.name);
        if (!shared) continue;
        expect(shared.artifactRelPath, `${target.name}`).to.equal(target.artifactRelPath);
      }
    });

    it("every bound artifact actually exists after a compile", function () {
      for (const s of RUNTIME_BYTE_SUBJECTS) {
        const path = join(REPO_ROOT, "artifacts", "contracts", s.artifactRelPath);
        expect(existsSync(path), `${s.name}: ${path}`).to.equal(true);
      }
    });
  });

  describe("parseRuntimeByteTables — a self-describing markdown table needs no hand-written locator", function () {
    const TABLE = [
      "| Contract | Manifest | Deployment runtime bytes | Executable code match |",
      "| --- | --- | --- | --- |",
      "| `MockUSDC` | [`x`](y) | `1,994` | ok |",
      "| `MockMLDSAVerifier` | [`x`](y) | `569` | ok |",
      "",
      "trailing prose",
    ].join("\n");

    it("reads subject and value out of the table's own columns", function () {
      const { declarations, errors } = parseRuntimeByteTables(TABLE, "docs/Deployments.md");
      expect(errors).to.deep.equal([]);
      expect(declarations.map((d) => [d.subject, d.slot, d.value])).to.deep.equal([
        ["MockUSDC", "observed-live", 1994],
        ["MockMLDSAVerifier", "observed-live", 569],
      ]);
    });

    it("maps a public-HEAD column header to the public-head slot", function () {
      const text = [
        "| Contract | Public HEAD runtime bytes |",
        "| --- | --- |",
        "| `WalletWallVault` | `22,701` |",
      ].join("\n");
      const { declarations } = parseRuntimeByteTables(text, "docs/Deployments.md");
      expect(declarations.map((d) => [d.subject, d.slot, d.value])).to.deep.equal([
        ["WalletWallVault", "public-head", 22701],
      ]);
    });

    it("ignores tables that carry no runtime-byte column", function () {
      const text = ["| Contract | Address |", "| --- | --- |", "| `MockUSDC` | `0xabc` |"].join("\n");
      const { declarations, errors } = parseRuntimeByteTables(text, "docs/Deployments.md");
      expect(declarations).to.deep.equal([]);
      expect(errors).to.deep.equal([]);
    });

    it("rejects a runtime-byte column whose cell is not a byte count", function () {
      const text = ["| Contract | Deployment runtime bytes |", "| --- | --- |", "| `MockUSDC` | pending |"].join("\n");
      const { errors } = parseRuntimeByteTables(text, "docs/Deployments.md");
      expect(errors.join("\n")).to.match(/MockUSDC/);
    });

    it("rejects a table that declares a runtime-byte column but no Contract column", function () {
      const text = ["| Thing | Deployment runtime bytes |", "| --- | --- |", "| `x` | `1,994` |"].join("\n");
      const { errors } = parseRuntimeByteTables(text, "docs/Deployments.md");
      expect(errors.join("\n")).to.match(/Contract/i);
    });
  });

  describe("extractProseDeclarations — a registered site must watch exactly one line", function () {
    const site = {
      file: "README.md",
      subject: "WalletWallVault",
      slot: "public-head" as const,
      pattern: /^recompiles to `([\d,]+)` bytes;/,
      note: "test fixture",
    };

    it("extracts the captured value, comma separators removed", function () {
      const { declarations, errors } = extractProseDeclarations("recompiles to `22,701` bytes; and more", "README.md", [
        site,
      ]);
      expect(errors).to.deep.equal([]);
      expect(declarations.map((d) => d.value)).to.deep.equal([22701]);
    });

    it("fails when the site matches nothing — a guard watching nothing is worse than no guard", function () {
      const { errors } = extractProseDeclarations("the sentence was reworded", "README.md", [site]);
      expect(errors.join("\n")).to.match(/matched no line/i);
    });

    it("fails when the site matches more than one line — an ambiguous locator proves nothing", function () {
      const text = ["recompiles to `22,701` bytes;", "recompiles to `22,701` bytes;"].join("\n");
      const { errors } = extractProseDeclarations(text, "README.md", [site]);
      expect(errors.join("\n")).to.match(/matched 2 lines/i);
    });

    it("records the file and line number so a failure is directly actionable", function () {
      const { declarations } = extractProseDeclarations("x\ny\nrecompiles to `22,701` bytes;", "README.md", [site]);
      expect(declarations[0].location).to.equal("README.md:3");
    });
  });

  describe("findUnregisteredProseClaims — completeness, the property that closes the defect", function () {
    const site = {
      file: "README.md",
      subject: "WalletWallVault",
      slot: "public-head" as const,
      pattern: /^recompiles to `([\d,]+)` bytes;/,
      note: "test fixture",
    };

    it("passes when every byte-claim line is watched by a registered site", function () {
      const errors = findUnregisteredProseClaims("recompiles to `22,701` bytes;", "README.md", [site], []);
      expect(errors).to.deep.equal([]);
    });

    it("FAILS on a newly added, unwatched prose copy of a byte claim", function () {
      // The whole defect class in one test: someone adds a fifth place that
      // quotes the size, nobody registers it, and it silently rots.
      const text = ["recompiles to `22,701` bytes;", "the vault is `22,701` bytes today"].join("\n");
      const errors = findUnregisteredProseClaims(text, "README.md", [site], []);
      expect(errors.join("\n")).to.match(/README\.md:2/);
      expect(errors.join("\n")).to.match(/unregistered/i);
    });

    it("accepts a byte-claim line already accounted for by a parsed table row", function () {
      const text = "| `MockUSDC` | [`x`](y) | `1,994` bytes |";
      const errors = findUnregisteredProseClaims(text, "docs/Deployments.md", [], ["docs/Deployments.md:1"]);
      expect(errors).to.deep.equal([]);
    });

    it("recognises both spellings a claim can take: `N` bytes and `N`-byte", function () {
      const errors = findUnregisteredProseClaims("its `20,508`-byte runtime", "README.md", [], []);
      expect(errors.join("\n")).to.match(/README\.md:1/);
    });

    it("counts OCCURRENCES, not lines — a second claim cannot hide behind a registered one", function () {
      // JSON prose puts several claims on one physical line. Line-level coverage
      // would mark the whole line watched the moment one site matched it, and the
      // rest would ride along unchecked.
      const line = "recompiles to a `22,701`-byte runtime rather than the deployed `20,508`-byte runtime";
      const registered = {
        file: "README.md",
        subject: "WalletWallVault",
        slot: "public-head" as const,
        pattern: /recompiles to a `([\d,]+)`-byte runtime/,
        note: "fixture",
      };
      const errors = findUnregisteredProseClaims(line, "README.md", [registered], []);
      expect(errors.join("\n")).to.match(/README\.md:1/);
      expect(errors.join("\n")).to.match(/1 unregistered/);
    });

    it("is satisfied when every occurrence on a shared line has its own registered site", function () {
      const line = "recompiles to a `22,701`-byte runtime rather than the deployed `20,508`-byte runtime";
      const sites = [
        {
          file: "README.md",
          subject: "WalletWallVault",
          slot: "public-head" as const,
          pattern: /recompiles to a `([\d,]+)`-byte runtime/,
          note: "a",
        },
        {
          file: "README.md",
          subject: "WalletWallVault",
          slot: "observed-live" as const,
          pattern: /the deployed `([\d,]+)`-byte runtime/,
          note: "b",
        },
      ];
      expect(findUnregisteredProseClaims(line, "README.md", sites, [])).to.deep.equal([]);
    });
  });

  describe("reproducibility-manifest prose is swept too", function () {
    it("sweeps unbackticked byte claims, which is how they are written inside JSON", function () {
      const json = '  "rationale": "public HEAD recompiles it to a 22,701-byte runtime.",';
      const errors = findUnregisteredProseClaims(json, "deployments/reproducibility/x.json", [], []);
      expect(errors.join("\n")).to.match(/unregistered/);
    });

    it("does NOT sweep solc CBOR metadata-region accounting, which sizes a sub-region not a contract", function () {
      // "53 bytes total: a 2-byte length suffix plus a 51-byte CBOR map", "32 bytes
      // differ" and friends appear in every evidence-bearing manifest's notes and
      // disclosures. None is a runtime-size claim and none is the compiler's to
      // adjudicate.
      const notes =
        '  "notes": "the decoded trailing solc CBOR metadata region (53 bytes total: a 2-byte length ' +
        'suffix plus a 51-byte CBOR map); of that 53-byte region only 32 bytes differ (the 32-byte sha256 digest)",';
      expect(findUnregisteredProseClaims(notes, "deployments/reproducibility/x.json", [], [])).to.deep.equal([]);
    });

    it("binds the WalletWallVault remediation prose, the fourth hand-edited copy of the number", function () {
      const collected = collectRuntimeByteClaims(REPO_ROOT);
      const fromRationale = collected.declarations.filter((d) =>
        d.location.startsWith("deployments/reproducibility/walletwall-vault-sepolia.json:"),
      );
      expect(fromRationale.map((d) => d.slot)).to.have.members(["public-head", "observed-live", "observed-live"]);
    });
  });

  describe("collectRuntimeByteClaims — the real repository tree", function () {
    let collected: ReturnType<typeof collectRuntimeByteClaims>;

    before(function () {
      collected = collectRuntimeByteClaims(REPO_ROOT);
    });

    it("collects without error", function () {
      expect(collected.errors).to.deep.equal([]);
    });

    it("measures every subject through the same primitive the EIP-170 gate uses", function () {
      const eip170 = new Map(collectReports().map((r) => [r.name, r.runtimeBytes]));
      for (const m of collected.measurements) {
        if (!eip170.has(m.subject)) continue;
        expect(m.runtimeBytes, `${m.subject}`).to.equal(eip170.get(m.subject));
      }
    });

    it("requires coverage for every published reproducibility subject", function () {
      expect(collected.coverageRequired).to.have.members([
        "WalletWallVault",
        "StablecoinVaultSimulator",
        "MockUSDC",
        "MockMLDSAVerifier",
      ]);
    });

    it("binds every reproducibility manifest's publicHeadRuntimeBytes, including remediation-gated records", function () {
      // walletwall-vault-sepolia.json is the record that had no evidenceFile and
      // was therefore only ever type-checked. It must appear here.
      const publicHead = collected.declarations.filter((d) => d.slot === "public-head");
      const fromManifests = publicHead.filter((d) => d.location.includes("deployments/reproducibility/"));
      expect(fromManifests.map((d) => d.subject)).to.include.members([
        "WalletWallVault",
        "StablecoinVaultSimulator",
        "MockUSDC",
        "MockMLDSAVerifier",
      ]);
    });

    it("watches every prose file that publishes a runtime-byte claim", function () {
      expect(COVERED_PROSE_FILES).to.have.members(["README.md", "SECURITY.md", "docs/Deployments.md"]);
      for (const file of COVERED_PROSE_FILES) {
        expect(existsSync(join(REPO_ROOT, file)), file).to.equal(true);
      }
    });

    it("every registered prose site names a file that is actually swept", function () {
      // Swept surfaces are the covered markdown docs plus the reproducibility
      // manifests. A site pointing anywhere else would be checked but its file
      // never scanned for completeness — coverage without a backstop.
      for (const site of PROSE_CLAIM_SITES) {
        const swept =
          COVERED_PROSE_FILES.includes(site.file) ||
          (site.file.startsWith("deployments/reproducibility/") && site.file.endsWith(".json"));
        expect(swept, `${site.file} is not a swept surface`).to.equal(true);
        expect(existsSync(join(REPO_ROOT, site.file)), site.file).to.equal(true);
      }
    });
  });
});
