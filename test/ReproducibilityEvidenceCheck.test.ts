/**
 * Unit + adversarial tests for scripts/lib/reproducibility-evidence.ts — the
 * module that makes a reproducibility manifest's claims REPLAYABLE from a
 * committed evidence bundle instead of hand-asserted.
 *
 * Three layers:
 *   1. CBOR metadata-boundary decoder — proves it actually decodes a real
 *      solc metadata trailer, and rejects a corrupted one, rather than
 *      assuming a fixed byte count.
 *   2. Immutable-value derivation — proves each derivation method reproduces
 *      a known value from public inputs.
 *   3. checkEvidenceAgainstManifest — first confirms every REAL committed
 *      manifest+evidence pair replays clean (ok: true, zero errors), then
 *      an adversarial mutation matrix: one mutation at a time, on an
 *      in-memory clone (the committed files are never touched), and asserts
 *      the checker rejects it for the SPECIFIC intended reason. A checker
 *      that accepts any of these mutations would let a manifest overclaim.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */

import { existsSync, readFileSync, readdirSync } from "fs";
import { join } from "path";

import { expect } from "chai";

import {
  checkEvidenceAgainstManifest,
  decodeSolcMetadataBoundary,
  deriveImmutableExpectedBytes,
  encodeShortString,
  type EvidenceBundle,
} from "../scripts/lib/reproducibility-evidence";

const REPRO_DIR = join(import.meta.dirname, "..", "deployments", "reproducibility");
const EVIDENCE_DIR = join(REPRO_DIR, "evidence");

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

/** Deep clone via JSON round-trip — safe for these plain-data evidence/manifest objects. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Flip every hex nibble at a byte offset to something different but still valid hex. */
function mutateByteInHex(hex: string, byteOffset: number): string {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  const charOffset = byteOffset * 2;
  const original = body.slice(charOffset, charOffset + 2);
  const replacement = original === "ff" ? "00" : "ff";
  return "0x" + body.slice(0, charOffset) + replacement + body.slice(charOffset + 2);
}

describe("reproducibility-evidence — CBOR metadata boundary decoder", () => {
  it("decodes a real captured solc metadata trailer", () => {
    const evidence = loadJson<EvidenceBundle>(join(EVIDENCE_DIR, "mock-usdc-sepolia.json"));
    const boundary = decodeSolcMetadataBoundary(evidence.liveRuntime.runtimeBytecode);
    expect(boundary.ok).to.equal(true);
    expect(boundary.regionSize).to.equal(53);
    expect(boundary.decodedFields).to.have.property("solc");
    expect(boundary.decodedFields).to.have.property("ipfs");
  });

  it("rejects a bytecode too short to contain a length suffix", () => {
    const boundary = decodeSolcMetadataBoundary("0x00");
    expect(boundary.ok).to.equal(false);
  });

  it("rejects a declared length that exceeds the available bytecode", () => {
    // Last 2 bytes = 0xffff -> declares a metadata length far larger than the buffer.
    const boundary = decodeSolcMetadataBoundary("0x" + "00".repeat(10) + "ffff");
    expect(boundary.ok).to.equal(false);
    expect(boundary.error).to.match(/exceeds available bytecode/);
  });

  it("rejects a length suffix that is not self-consistent with the CBOR item it points at", () => {
    const evidence = loadJson<EvidenceBundle>(join(EVIDENCE_DIR, "mock-usdc-sepolia.json"));
    // Corrupt the 2-byte length suffix itself (not the CBOR body) so the declared
    // length no longer matches what actually decodes there.
    const corrupted = mutateByteInHex(
      evidence.liveRuntime.runtimeBytecode,
      evidence.liveRuntime.runtimeBytecode.length / 2 - 3,
    );
    const boundary = decodeSolcMetadataBoundary(corrupted);
    expect(boundary.ok).to.equal(false);
  });

  it("rejects a metadata map with an unrecognized key", () => {
    // Minimal well-formed CBOR: map{1 entry: text"xx" -> false}, length-prefixed correctly.
    // 0xa1 (map,1) 0x62 "xx" (text,2) 0xf4 (false) = 5 bytes; suffix = 0x0005.
    const hex = "0xa16278" + "78" + "f4" + "0005";
    const boundary = decodeSolcMetadataBoundary(hex);
    expect(boundary.ok).to.equal(false);
    expect(boundary.error).to.match(/unrecognized key/);
  });
});

describe("reproducibility-evidence — immutable value derivation", () => {
  const ctx = { deployedAddress: "0x32f489842DD515Fa4b4b258714F0067B8B8133ae", chainId: 11155111 };

  it("constructor-argument: zero-pads the given address to 32 bytes", () => {
    const v = deriveImmutableExpectedBytes(
      { method: "constructor-argument", value: "0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac15" },
      ctx,
    );
    expect(v).to.equal("0x0000000000000000000000008ffc8ce04789e9a7b53685a2d78cda54e6faac15");
  });

  it("self-address: zero-pads the context's deployed address", () => {
    const v = deriveImmutableExpectedBytes({ method: "self-address" }, ctx);
    expect(v).to.equal("0x00000000000000000000000032f489842dd515fa4b4b258714f0067b8b8133ae");
  });

  it("chain-id: zero-pads the context's chain id", () => {
    const v = deriveImmutableExpectedBytes({ method: "chain-id" }, ctx);
    expect(v).to.equal("0x0000000000000000000000000000000000000000000000000000000000aa36a7");
  });

  it("keccak256-utf8: hashes the UTF-8 bytes of the given string", () => {
    const v = deriveImmutableExpectedBytes({ method: "keccak256-utf8", value: "1" }, ctx);
    expect(v).to.equal("0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6");
  });

  it("short-string: matches OpenZeppelin ShortStrings.toShortString encoding", () => {
    expect(encodeShortString("1")).to.equal(
      "0x3100000000000000000000000000000000000000000000000000000000000001".slice(0, 66),
    );
    // length byte (0x01) must be the LAST byte of the 32-byte word.
    const v = encodeShortString("1");
    expect(v.slice(-2)).to.equal("01");
    expect(v.slice(2, 4)).to.equal("31"); // '1' == 0x31
  });

  it("short-string: rejects a string longer than 31 bytes", () => {
    expect(() => encodeShortString("x".repeat(32))).to.throw(/too long/);
  });

  it("eip712-domain-separator: matches the known WalletWallStablecoinVault/1 domain separator", () => {
    const v = deriveImmutableExpectedBytes(
      { method: "eip712-domain-separator", name: "WalletWallStablecoinVault", version: "1" },
      ctx,
    );
    expect(v).to.equal("0x0cd2059d28d0470e366d8f40ee5ca3ed50749f1956a3ddec3e4ed9bff73f1fb9".slice(0, 66));
  });
});

interface Fixture {
  slug: string;
  manifest: Record<string, unknown>;
  evidence: EvidenceBundle;
}

function loadFixtures(): Fixture[] {
  if (!existsSync(EVIDENCE_DIR)) return [];
  return readdirSync(EVIDENCE_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const slug = f.replace(/\.json$/, "");
      const manifestPath = join(REPRO_DIR, `${slug}.json`);
      return {
        slug,
        manifest: loadJson<Record<string, unknown>>(manifestPath),
        evidence: loadJson<EvidenceBundle>(join(EVIDENCE_DIR, f)),
      };
    });
}

describe("checkEvidenceAgainstManifest — real committed data replays clean", () => {
  for (const fixture of loadFixtures()) {
    it(`${fixture.slug}: evidence-derived facts agree with every claim in the manifest`, () => {
      const result = checkEvidenceAgainstManifest(fixture.evidence, fixture.manifest);
      expect(result.errors, result.errors.join("\n")).to.deep.equal([]);
      expect(result.ok).to.equal(true);
    });
  }

  it("at least one fixture with immutables was actually exercised (not a vacuously-empty matrix)", () => {
    const withImmutables = loadFixtures().filter((f) => (f.evidence.immutableIdentities ?? []).length > 0);
    expect(withImmutables.length).to.be.greaterThan(0);
  });
});

describe("checkEvidenceAgainstManifest — adversarial mutation matrix", () => {
  const baseFixture = loadFixtures().find((f) => f.slug === "stablecoin-vault-simulator-sepolia")!;
  const usdcFixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;

  before(function () {
    if (!baseFixture || !usdcFixture) this.skip();
  });

  it("1. tampered normalized bytecode hash is rejected", () => {
    const manifest = clone(usdcFixture.manifest);
    (manifest["artifactManifest"] as Record<string, unknown>)["bytecodeHash"] = "0x" + "ab".repeat(32);
    const result = checkEvidenceAgainstManifest(usdcFixture.evidence, manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /bytecodeHash/.test(e))).to.equal(true);
  });

  it("2. a real executable-byte divergence (outside metadata + immutables) is rejected", () => {
    const evidence = clone(usdcFixture.evidence);
    // Byte 0 is deep inside the executable prologue — nowhere near the metadata
    // trailer (regionStart=1941) and MockUSDC has no immutable ranges at all.
    evidence.liveRuntime.runtimeBytecode = mutateByteInHex(evidence.liveRuntime.runtimeBytecode, 0);
    const result = checkEvidenceAgainstManifest(evidence, usdcFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.facts.executableBytecodeMatch).to.equal(false);
    expect(result.errors.some((e) => /executableBytecodeMatch/.test(e))).to.equal(true);
  });

  it("3. a corrupted metadata boundary (length suffix) is rejected", () => {
    const evidence = clone(usdcFixture.evidence);
    const totalBytes = evidence.liveRuntime.runtimeBytecode.length / 2 - 1;
    evidence.liveRuntime.runtimeBytecode = mutateByteInHex(evidence.liveRuntime.runtimeBytecode, totalBytes - 1);
    const result = checkEvidenceAgainstManifest(evidence, usdcFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /metadata boundary/.test(e))).to.equal(true);
  });

  it("4. a wrong metadataTrailerBytesExcluded count is rejected", () => {
    const manifest = clone(usdcFixture.manifest);
    (manifest["artifactManifest"] as Record<string, unknown>)["metadataTrailerBytesExcluded"] = 999;
    const result = checkEvidenceAgainstManifest(usdcFixture.evidence, manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /metadataTrailerBytesExcluded/.test(e))).to.equal(true);
  });

  it("5. a tampered immutable derivation input (expected value) is rejected", () => {
    const evidence = clone(baseFixture.evidence);
    const tokenIdentity = evidence.immutableIdentities!.find((i) => i.name === "token")!;
    // @ts-expect-error narrowing a discriminated union for a test mutation
    tokenIdentity.derivation.value = "0x0000000000000000000000000000000000dEaD";
    const result = checkEvidenceAgainstManifest(evidence, baseFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /token/.test(e))).to.equal(true);
  });

  it("6. a tampered immutable observed value (live bytecode at that slot) is rejected", () => {
    const evidence = clone(baseFixture.evidence);
    const tokenRefs = evidence.deploymentCommitBuild.immutableReferences["9109"];
    evidence.liveRuntime.runtimeBytecode = mutateByteInHex(evidence.liveRuntime.runtimeBytecode, tokenRefs[0].start);
    const result = checkEvidenceAgainstManifest(evidence, baseFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /token/.test(e))).to.equal(true);
  });

  it("7. a tampered immutable byte-range reference (wrong offset) is rejected", () => {
    const evidence = clone(baseFixture.evidence);
    evidence.deploymentCommitBuild.immutableReferences["9109"][0].start += 1;
    const result = checkEvidenceAgainstManifest(evidence, baseFixture.manifest);
    expect(result.ok).to.equal(false);
    // Reading at the wrong offset yields bytes that no longer match the expected
    // derivation (or disagree with the other 3 physical occurrences of `token`).
    expect(result.errors.some((e) => /token/.test(e))).to.equal(true);
  });

  it("8. a mismatched deployment/source commit between evidence and manifest is rejected", () => {
    const evidence = clone(usdcFixture.evidence);
    evidence.deploymentCommitBuild.commit = "0".repeat(40);
    const result = checkEvidenceAgainstManifest(evidence, usdcFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /reportedSourceCommit/.test(e))).to.equal(true);
  });

  it("9. mismatched runtime evidence (wrong deployed address) is rejected", () => {
    const evidence = clone(usdcFixture.evidence);
    evidence.liveRuntime.address = "0x000000000000000000000000000000DeaDBeef";
    const result = checkEvidenceAgainstManifest(evidence, usdcFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /deployedAddress/.test(e))).to.equal(true);
  });

  it("bonus: excluding a REAL code byte by mislabeling it as metadata is still rejected", () => {
    // Adversarial case from the review: claim executableBytecodeMatch/metadataHashMatch
    // as if the divergence were metadata-only, while the actual differing byte is
    // provably outside the decoded metadata region. The checker must not accept the
    // manifest's self-report — it must derive the containment fact itself.
    const evidence = clone(usdcFixture.evidence);
    evidence.liveRuntime.runtimeBytecode = mutateByteInHex(evidence.liveRuntime.runtimeBytecode, 100);
    const manifest = clone(usdcFixture.manifest);
    // Manifest still (falsely) claims full executable match.
    const result = checkEvidenceAgainstManifest(evidence, manifest);
    expect(result.ok).to.equal(false);
    expect(result.facts.executableBytecodeMatch).to.equal(false);
  });
});
