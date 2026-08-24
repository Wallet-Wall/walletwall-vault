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
  checkCommitObjectAvailable,
  checkEvidenceAgainstManifest,
  decodeSolcMetadataBoundary,
  deriveFactsFromEvidence,
  deriveImmutableExpectedBytes,
  encodeShortString,
  validateImmutableAuthority,
  verifyPublicHeadCommitNotStale,
  verifyReportedCommitInPublicHistory,
  verifySourceDigestsAgainstCommit,
  type EvidenceBundle,
} from "../scripts/lib/reproducibility-evidence";

const REPO_ROOT = join(import.meta.dirname, "..");
const REPRO_DIR = join(REPO_ROOT, "deployments", "reproducibility");
const EVIDENCE_DIR = join(REPRO_DIR, "evidence");
const DEPLOYMENT_COMMIT = "35c25fa294bebea44b3089aa2435a190a5adf3fb";
const PUBLIC_HEAD_COMMIT = "5792975d4db331156845de72addbae95d079c0f8";

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

// ─────────────────────────────────────────────────────────────────────────
// Blocker B — public-history reachability is independently derived via local
// git plumbing, never trusted from the manifest's own boolean.
// ─────────────────────────────────────────────────────────────────────────

describe("verifyReportedCommitInPublicHistory — Blocker B", () => {
  it("the real deployment commit is confirmed present and an ancestor of HEAD in this repo", () => {
    const result = verifyReportedCommitInPublicHistory(DEPLOYMENT_COMMIT, REPO_ROOT);
    expect(result.isAncestorOfHead).to.equal(true);
  });

  it("a fabricated commit that does not exist anywhere returns null (inconclusive), never false", () => {
    const fabricated = "f".repeat(40);
    const result = checkCommitObjectAvailable(fabricated, REPO_ROOT);
    expect(result.commitObjectPresent).to.equal(false);
    const history = verifyReportedCommitInPublicHistory(fabricated, REPO_ROOT);
    expect(history.isAncestorOfHead).to.equal(null);
    expect(history.error).to.match(/not present locally/);
  });

  it("checkEvidenceAgainstManifest treats a manifest's reportedSourceCommitInPublicHistory as REQUIRING agreement with the independently-derived value, not as its own authority", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const manifest = clone(fixture.manifest);
    // Flip the flag against what git actually shows.
    manifest["reportedSourceCommitInPublicHistory"] = false;
    const result = checkEvidenceAgainstManifest(fixture.evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /reportedSourceCommitInPublicHistory/.test(e))).to.equal(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Blocker A (offline half) — sourceDigests are independently re-verified
// against the ACTUAL git objects at the claimed commit, not merely trusted
// as recorded by the capture tool.
// ─────────────────────────────────────────────────────────────────────────

describe("verifySourceDigestsAgainstCommit — Blocker A offline verification", () => {
  it("the real deployment-commit build's sourceDigests verify against actual git history", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const result = verifySourceDigestsAgainstCommit(
      DEPLOYMENT_COMMIT,
      fixture.evidence.deploymentCommitBuild.sourceDigests,
      REPO_ROOT,
    );
    expect(result.checked).to.equal(true);
    expect(result.ok, result.errors.join("\n")).to.equal(true);
  });

  it("the real public-head build's sourceDigests verify against actual git history", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const result = verifySourceDigestsAgainstCommit(
      PUBLIC_HEAD_COMMIT,
      fixture.evidence.publicHeadBuild.sourceDigests,
      REPO_ROOT,
    );
    expect(result.checked).to.equal(true);
    expect(result.ok, result.errors.join("\n")).to.equal(true);
  });

  it("a WRONG recorded digest for a real file at a real commit is rejected", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const tampered = { ...fixture.evidence.deploymentCommitBuild.sourceDigests };
    const [firstFile] = Object.keys(tampered);
    tampered[firstFile] = "0x" + "ab".repeat(32);
    const result = verifySourceDigestsAgainstCommit(DEPLOYMENT_COMMIT, tampered, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => e.includes(firstFile))).to.equal(true);
  });

  it("a file path that never existed at the claimed commit is rejected", () => {
    const result = verifySourceDigestsAgainstCommit(
      DEPLOYMENT_COMMIT,
      { "contracts/DoesNotExist.sol": "0x" + "00".repeat(32) },
      REPO_ROOT,
    );
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /not found at commit/.test(e))).to.equal(true);
  });

  it("checkEvidenceAgainstManifest rejects a manifest+evidence pair whose reportedSourceCommit is real public history but whose sourceDigests DON'T actually match that commit's content — the common-mode 'wrong build-info, consistently mislabeled' case", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const evidence = clone(fixture.evidence);
    // Relabel the WHOLE build capture as a DIFFERENT, real, public commit — self-consistent
    // between evidence.deploymentCommitBuild.commit and manifest.reportedSourceCommit — but
    // the sourceDigests still reflect the ORIGINAL commit's content, which the relabeled
    // commit's real git history does not match (package.json alone differs across commits
    // in this repo's history, let alone contracts/).
    const manifest = clone(fixture.manifest);
    evidence.deploymentCommitBuild.commit = PUBLIC_HEAD_COMMIT;
    manifest["reportedSourceCommit"] = PUBLIC_HEAD_COMMIT;
    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /source-commit binding/.test(e))).to.equal(true);
  });

  it("checkEvidenceAgainstManifest rejects a stale public-head commit even when evidence.publicHeadBuild.headCommit and manifest.publicHeadCommit are consistently (but wrongly) relabeled together", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const evidence = clone(fixture.evidence);
    const manifest = clone(fixture.manifest);
    // Both sides agree on the deployment commit's SHA instead of the real public-head SHA —
    // internally consistent with each other, but the sourceDigests (captured from the real
    // public-head worktree) do not match THIS commit's actual git content.
    evidence.publicHeadBuild.headCommit = DEPLOYMENT_COMMIT;
    manifest["publicHeadCommit"] = DEPLOYMENT_COMMIT;
    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /public-head binding/.test(e))).to.equal(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Blocker 2 (round 2) — a publicHeadBuild that is internally self-consistent
// (evidence.headCommit === manifest.publicHeadCommit, and sourceDigests that
// genuinely verify against THAT commit's real git content) can still be
// STALE: commits landing between it and the validating repo's current HEAD
// may have touched the very source files it claims to cover, without the
// capture ever being refreshed. Blocker A/B close "is this commit real and
// does its content match" — this closes "is this commit still current for
// the files it covers", a distinct temporal property neither of those checks
// can see.
// ─────────────────────────────────────────────────────────────────────────

describe("verifyPublicHeadCommitNotStale — Blocker 2", () => {
  it("the real, freshly-recaptured publicHeadCommit is NOT stale for its own covered files", () => {
    const fixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const result = verifyPublicHeadCommitNotStale(
      PUBLIC_HEAD_COMMIT,
      Object.keys(fixture.evidence.publicHeadBuild.sourceDigests),
      REPO_ROOT,
    );
    expect(result.stale, result.error).to.equal(false);
  });

  it("the old deployment commit IS stale relative to current HEAD for StablecoinVaultSimulator.sol (PR #152 changed it after DEPLOYMENT_COMMIT)", () => {
    const result = verifyPublicHeadCommitNotStale(
      DEPLOYMENT_COMMIT,
      ["contracts/StablecoinVaultSimulator.sol"],
      REPO_ROOT,
    );
    expect(result.stale).to.equal(true);
    expect(result.staleCommits.length).to.be.greaterThan(0);
  });

  it("a commit whose object is not locally available returns stale: null (inconclusive), never a false 'not stale'", () => {
    const fabricated = "e".repeat(40);
    const result = verifyPublicHeadCommitNotStale(fabricated, ["contracts/MockUSDC.sol"], REPO_ROOT);
    expect(result.stale).to.equal(null);
  });

  it("checkEvidenceAgainstManifest common-mode regression: an OLDER real commit, consistently relabeled as publicHeadCommit on BOTH evidence and manifest, with sourceDigests that are genuinely VALID for that older commit (so the source-commit binding check alone would pass), is still rejected — because it is stale, not because it is inconsistent or unverifiable", () => {
    const fixture = loadFixtures().find((f) => f.slug === "stablecoin-vault-simulator-sepolia")!;
    const evidence = clone(fixture.evidence);
    const manifest = clone(fixture.manifest);
    // Reuse the REAL, git-verified deploymentCommitBuild digests (genuinely valid for
    // DEPLOYMENT_COMMIT) as if they were the publicHeadBuild — self-consistent labeling on
    // both sides, and the digest/binding check on its own has nothing to object to here.
    evidence.publicHeadBuild.headCommit = DEPLOYMENT_COMMIT;
    evidence.publicHeadBuild.sourceDigests = clone(evidence.deploymentCommitBuild.sourceDigests);
    manifest["publicHeadCommit"] = DEPLOYMENT_COMMIT;

    // Confirm the digest/binding check by itself is satisfied — isolating that staleness,
    // not a digest mismatch, is what must fail this.
    const bindingOnly = verifySourceDigestsAgainstCommit(
      DEPLOYMENT_COMMIT,
      evidence.publicHeadBuild.sourceDigests,
      REPO_ROOT,
    );
    expect(bindingOnly.ok, bindingOnly.errors.join("\n")).to.equal(true);

    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /public-head staleness/.test(e))).to.equal(true);
    expect(result.errors.some((e) => /public-head binding/.test(e))).to.equal(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Blocker C — immutable byte-range AUTHORITY. An AST id may only claim an
// exclusion range if it is both declared in immutableIdentities AND actually
// present in the build's own machine-derived immutableAstDeclarations.
// ─────────────────────────────────────────────────────────────────────────

describe("validateImmutableAuthority — Blocker C", () => {
  const baseFixture = loadFixtures().find((f) => f.slug === "stablecoin-vault-simulator-sepolia")!;

  it("the real evidence's immutable authority is valid", () => {
    const result = validateImmutableAuthority(baseFixture.evidence);
    expect(result.ok, result.errors.join("\n")).to.equal(true);
  });

  it("an extra AST id in immutableReferences with no declared identity is rejected", () => {
    const evidence = clone(baseFixture.evidence);
    evidence.deploymentCommitBuild.immutableReferences["424242"] = [{ start: 100, length: 32 }];
    const result = validateImmutableAuthority(evidence);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /no corresponding immutableIdentities entry/.test(e))).to.equal(true);
  });

  it("COMMON-MODE: a fake AST id added to BOTH immutableReferences AND immutableIdentities self-consistently is still rejected, because it is not in the build's real immutableAstDeclarations", () => {
    // This is the exact attack the review described: mutate a real executable byte, then
    // try to launder it as an immutable by adding matching entries to every cooperating
    // field an attacker could edit by hand. The one thing they CANNOT fabricate is the
    // machine-derived AST snapshot captured once, mechanically, at capture time.
    const evidence = clone(baseFixture.evidence);
    const fakeAstId = "999999";
    const targetOffset = 100; // deep in real executable code, nowhere near any real immutable
    evidence.deploymentCommitBuild.immutableReferences[fakeAstId] = [{ start: targetOffset, length: 32 }];
    evidence.immutableIdentities!.push({
      astId: fakeAstId,
      name: "fakeImmutable",
      sourceFile: "contracts/StablecoinVaultSimulator.sol",
      typeString: "bytes32",
      derivation: { method: "constructor-argument", value: "0x8ffc8CE04789e9a7b53685a2d78CDa54E6Faac15" },
      expectedValueHex: "0x0000000000000000000000008ffc8ce04789e9a7b53685a2d78cda54e6faac15",
    });
    // Mutate the live byte at that offset to actually BE the fake identity's expected value's
    // first byte, and recompute the manifest's dependent claims as an attacker who checked
    // their work would.
    const liveBuf = Buffer.from(evidence.liveRuntime.runtimeBytecode.slice(2), "hex");
    Buffer.from("0000000000000000000000008ffc8ce04789e9a7b53685a2d78cda54e6faac15", "hex").copy(liveBuf, targetOffset);
    evidence.liveRuntime.runtimeBytecode = "0x" + liveBuf.toString("hex");

    const authority = validateImmutableAuthority(evidence);
    expect(authority.ok).to.equal(false);
    expect(
      authority.errors.some((e) => /does not correspond to anything the compiler actually emitted/.test(e)),
    ).to.equal(true);

    const manifest = clone(baseFixture.manifest);
    const facts = deriveFactsFromEvidence(evidence);
    // Even if the attacker recomputes bytecodeHash/executableBytecodeMatch to match the
    // (illegitimately masked) result, the authority check alone makes the whole replay fail.
    (manifest["artifactManifest"] as Record<string, unknown>)["bytecodeHash"] = facts.normalizedBytecodeHash;
    (manifest["artifactManifest"] as Record<string, unknown>)["executableBytecodeMatch"] =
      facts.executableBytecodeMatch;
    const result = checkEvidenceAgainstManifest(evidence, manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /immutable authority/.test(e))).to.equal(true);
  });

  it("a constructor-argument derivation whose value is not in the manifest's recorded constructorArgs is rejected — an attacker cannot invent an unrecorded 'public' argument", () => {
    const evidence = clone(baseFixture.evidence);
    const tokenIdentity = evidence.immutableIdentities!.find((i) => i.name === "token")!;
    // @ts-expect-error narrowing a discriminated union for a test mutation
    tokenIdentity.derivation.value = "0x000000000000000000000000000000DeaDBeef";
    const result = checkEvidenceAgainstManifest(evidence, baseFixture.manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /not present in artifactManifest.constructorArgs/.test(e))).to.equal(true);
  });

  it("overlapping immutable ranges are rejected", () => {
    const evidence = clone(baseFixture.evidence);
    const refs = evidence.deploymentCommitBuild.immutableReferences;
    const [firstId] = Object.keys(refs);
    const overlapStart = refs[firstId][0].start + 10; // overlaps the first range
    refs["888888"] = [{ start: overlapStart, length: 32 }];
    evidence.immutableIdentities!.push({
      astId: "888888",
      name: "overlapper",
      sourceFile: "contracts/StablecoinVaultSimulator.sol",
      typeString: "bytes32",
      derivation: { method: "chain-id" },
      expectedValueHex: "0x0000000000000000000000000000000000000000000000000000000000aa36a7",
    });
    const result = validateImmutableAuthority(evidence);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /overlap/.test(e))).to.equal(true);
  });

  it("an immutable range that enters the decoded metadata region is rejected", () => {
    const evidence = clone(baseFixture.evidence);
    const localLen = Buffer.from(evidence.deploymentCommitBuild.deployedBytecodeObject.slice(2), "hex").length;
    const boundary = decodeSolcMetadataBoundary(evidence.deploymentCommitBuild.deployedBytecodeObject);
    evidence.deploymentCommitBuild.immutableReferences["777777"] = [{ start: boundary.regionStart!, length: 8 }];
    evidence.immutableIdentities!.push({
      astId: "777777",
      name: "intoMetadata",
      sourceFile: "contracts/StablecoinVaultSimulator.sol",
      typeString: "bytes32",
      derivation: { method: "chain-id" },
      expectedValueHex: "0x0000000000000000000000000000000000000000000000000000000000aa36a7",
    });
    const result = validateImmutableAuthority(evidence);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /enters the decoded metadata region/.test(e))).to.equal(true);
    expect(localLen).to.be.greaterThan(0); // sanity: the buffer parsed
  });

  it("a contract with NO declared immutables but a non-empty immutableReferences is rejected", () => {
    const usdcFixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
    const evidence = clone(usdcFixture.evidence);
    evidence.deploymentCommitBuild.immutableReferences["1"] = [{ start: 0, length: 32 }];
    const result = validateImmutableAuthority(evidence);
    expect(result.ok).to.equal(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Blocker D — metadata exclusion requires DUAL authorization (live AND local
// boundaries must decode to the identical region), and the executable
// comparison is a full buffer equality on BOTH normalized sides, not an
// inference from one side's hash alone.
// ─────────────────────────────────────────────────────────────────────────

describe("Blocker D — dual metadata-boundary authorization", () => {
  const usdcFixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;

  it("real evidence: live and local metadata boundaries agree exactly", () => {
    const facts = deriveFactsFromEvidence(usdcFixture.evidence);
    expect(facts.metadataBoundariesAgree).to.equal(true);
    expect(facts.liveMetadataBoundary.regionStart).to.equal(facts.localMetadataBoundary.regionStart);
    expect(facts.liveMetadataBoundary.regionSize).to.equal(facts.localMetadataBoundary.regionSize);
  });

  it("both normalized hashes are computed independently and must agree for executableBytecodeMatch to be true", () => {
    const facts = deriveFactsFromEvidence(usdcFixture.evidence);
    expect(facts.normalizedLiveHash).to.equal(facts.normalizedLocalHash);
    expect(facts.executableBytecodeMatch).to.equal(true);
  });

  it("a shifted live metadata region (would otherwise let an executable difference near the boundary be laundered as metadata) revokes ALL metadata exclusion authority", () => {
    const evidence = clone(usdcFixture.evidence);
    const liveBuf = Buffer.from(evidence.liveRuntime.runtimeBytecode.slice(2), "hex");
    // Rewrite the live length suffix to declare a metadata region 4 bytes LARGER than it
    // really is — still a well-formed-looking length, but now the live boundary decodes to
    // a DIFFERENT regionStart than local's, because the extra 4 bytes it now claims as
    // "metadata" are actually still executable-region bytes in the real layout.
    const realBoundary = decodeSolcMetadataBoundary(evidence.liveRuntime.runtimeBytecode);
    const inflatedLength = realBoundary.regionSize! + 4;
    liveBuf.writeUInt16BE(inflatedLength, liveBuf.length - 2);
    evidence.liveRuntime.runtimeBytecode = "0x" + liveBuf.toString("hex");

    const facts = deriveFactsFromEvidence(evidence);
    // Either the live boundary now fails to decode cleanly, or it decodes but at a
    // DIFFERENT offset/size than local's — either way, no exclusion is authorized.
    if (facts.liveMetadataBoundary.ok) {
      expect(facts.metadataBoundariesAgree).to.equal(false);
    }
    const result = checkEvidenceAgainstManifest(evidence, usdcFixture.manifest);
    expect(result.ok).to.equal(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Common-mode mutation matrix — mutating manifest AND evidence TOGETHER,
// self-consistently, must still fail. The earlier 9-point matrix (above)
// proved disagreement detection when only one side is touched; these prove
// the false claim is structurally impossible even when an attacker updates
// every cooperating field at once.
// ─────────────────────────────────────────────────────────────────────────

describe("common-mode mutations — manifest and evidence updated together, self-consistently", () => {
  const usdcFixture = loadFixtures().find((f) => f.slug === "mock-usdc-sepolia")!;
  const simFixture = loadFixtures().find((f) => f.slug === "stablecoin-vault-simulator-sepolia")!;

  it("1. wrong build-info + matching fake commit labels on both manifest and evidence (git-checked)", () => {
    const evidence = clone(usdcFixture.evidence);
    const manifest = clone(usdcFixture.manifest);
    evidence.deploymentCommitBuild.commit = PUBLIC_HEAD_COMMIT;
    manifest["reportedSourceCommit"] = PUBLIC_HEAD_COMMIT;
    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
  });

  it("2. fake immutable range + executable mutation + recomputed dependent hash/claims", () => {
    const evidence = clone(simFixture.evidence);
    const manifest = clone(simFixture.manifest);
    const fakeAstId = "555555";
    const offset = 200;
    evidence.deploymentCommitBuild.immutableReferences[fakeAstId] = [{ start: offset, length: 32 }];
    evidence.immutableIdentities!.push({
      astId: fakeAstId,
      name: "forged",
      sourceFile: "contracts/StablecoinVaultSimulator.sol",
      typeString: "bytes32",
      derivation: { method: "chain-id" },
      expectedValueHex: "0x0000000000000000000000000000000000000000000000000000000000aa36a7",
    });
    const liveBuf = Buffer.from(evidence.liveRuntime.runtimeBytecode.slice(2), "hex");
    liveBuf.writeUInt32BE(0, offset); // arbitrary "mutation" — content doesn't matter here
    Buffer.from("0000000000000000000000000000000000000000000000000000000000aa36a7", "hex").copy(liveBuf, offset);
    evidence.liveRuntime.runtimeBytecode = "0x" + liveBuf.toString("hex");
    const facts = deriveFactsFromEvidence(evidence);
    (manifest["artifactManifest"] as Record<string, unknown>)["bytecodeHash"] = facts.normalizedBytecodeHash;
    (manifest["artifactManifest"] as Record<string, unknown>)["executableBytecodeMatch"] =
      facts.executableBytecodeMatch;
    (manifest["artifactManifest"] as Record<string, unknown>)["immutableValuesIndependentlyVerified"] =
      facts.immutableValuesIndependentlyVerified;
    const result = checkEvidenceAgainstManifest(evidence, manifest);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /immutable authority/.test(e))).to.equal(true);
  });

  it("3. stale/wrong public-head commit labeled consistently across evidence and manifest (git-checked)", () => {
    const evidence = clone(usdcFixture.evidence);
    const manifest = clone(usdcFixture.manifest);
    evidence.publicHeadBuild.headCommit = DEPLOYMENT_COMMIT;
    manifest["publicHeadCommit"] = DEPLOYMENT_COMMIT;
    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
  });

  it("4. a shifted metadata authority attempting to hide an executable difference, with dependent claims recomputed", () => {
    const evidence = clone(usdcFixture.evidence);
    const manifest = clone(usdcFixture.manifest);
    const liveBuf = Buffer.from(evidence.liveRuntime.runtimeBytecode.slice(2), "hex");
    const realBoundary = decodeSolcMetadataBoundary(evidence.liveRuntime.runtimeBytecode);
    liveBuf.writeUInt16BE(realBoundary.regionSize! + 4, liveBuf.length - 2);
    evidence.liveRuntime.runtimeBytecode = "0x" + liveBuf.toString("hex");
    const facts = deriveFactsFromEvidence(evidence);
    (manifest["artifactManifest"] as Record<string, unknown>)["bytecodeHash"] = facts.normalizedBytecodeHash;
    (manifest["artifactManifest"] as Record<string, unknown>)["executableBytecodeMatch"] =
      facts.executableBytecodeMatch;
    (manifest["artifactManifest"] as Record<string, unknown>)["metadataHashMatch"] = facts.metadataHashMatch;
    (manifest["artifactManifest"] as Record<string, unknown>)["metadataTrailerBytesExcluded"] =
      facts.metadataTrailerBytesExcluded;
    const result = checkEvidenceAgainstManifest(evidence, manifest);
    expect(result.ok).to.equal(false);
  });

  it("5. a stale publicHeadCommit consistently relabeled AND given genuinely valid sourceDigests for that older commit — self-consistent and digest-valid, still rejected as stale", () => {
    const evidence = clone(simFixture.evidence);
    const manifest = clone(simFixture.manifest);
    evidence.publicHeadBuild.headCommit = DEPLOYMENT_COMMIT;
    evidence.publicHeadBuild.sourceDigests = clone(evidence.deploymentCommitBuild.sourceDigests);
    manifest["publicHeadCommit"] = DEPLOYMENT_COMMIT;
    const result = checkEvidenceAgainstManifest(evidence, manifest, REPO_ROOT);
    expect(result.ok).to.equal(false);
    expect(result.errors.some((e) => /public-head staleness/.test(e))).to.equal(true);
  });
});
