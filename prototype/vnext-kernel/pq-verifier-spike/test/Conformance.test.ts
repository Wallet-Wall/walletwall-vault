/**
 * GEN2-PQ-CONFORMANCE-1 — the conformance campaign, re-run from committed fixtures against the vendored verifier.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. Passing every vector here is PARTIAL CONFORMANCE EVIDENCE for one
 * pinned implementation on one simulated EVM. It is not an independent cryptographic review, not an audit, and
 * says nothing about soundness beyond the vectors that were run.
 *
 * Families (fixtures/):
 *   acvp         NIST ACVP ML-DSA-65 sigVer, tgId 3 (external interface, pure): 15 vectors, NIST's verdicts
 *   wycheproof   C2SP Wycheproof mldsa_65_verify_test.json: 210 vectors, 25 keys (two of non-standard length)
 *   rsp          pq-crystals reference KAT PQCsignKAT_Dilithium3.rsp, counts 0..9: 10 valid vectors, empty context
 *   vendor       ZKNOX's own js-generated vectors (3) and the 32-byte-hash vector (1)
 *   generated    WalletWall-shaped 32-byte digests (32 valid, 10 negative), z-norm boundary (3), hint
 *                canonicality (6), degenerate key (1): 52 vectors, generated once and committed
 * Every public key is expanded by the VENDORED client module (js/mldsa65.js, byte-identical to upstream) and
 * the expansion is pinned by digest against two independent earlier runs (the feasibility run on the upstream
 * ESM module; the vendor's own test file). Every vector is also run through @noble/post-quantum 0.7.0 as a
 * second oracle; a chain/client split is a finding, not a pass.
 */
import { expect } from "chai";
import {
  createWorld,
  expandToBlob,
  nobleVerdict,
  loadFixture,
  readResults,
  sha256,
  toolchainRecord,
  unhex,
  with0x,
  writeResults,
  type Verdict,
  type World,
} from "../lib/world.js";

interface AcvpFixture {
  source: { sha256: string; vsId: number };
  group: { tgId: number; parameterSet: string };
  count: number;
  tests: { tcId: number; reason: string; testPassed: boolean; pk: string; message: string; context: string; signature: string }[];
}
interface WycheproofFixture {
  numberOfTests: number;
  testGroups: { publicKey: string; tests: { tcId: number; comment: string; msg: string; ctx?: string; sig: string; result: string; flags?: string[] }[] }[];
}
interface RspFixture {
  count: number;
  tests: { count: number; mlen: number; msg: string; pk: string; signature: string }[];
}
interface VendorFixture {
  count: number;
  jsVectors: { name: string; tcId: number; valid: boolean; pk: string; blobSha256: string; msg: string; ctx: string; sig: string }[];
  hash32: { key: string; hash: string; sig: string };
  blobDigests: { name: string; tcId: number; valid: boolean; blobSha256: string }[];
  acvpPkByTcId: Record<string, string>;
}
interface GeneratedFixture {
  counts: Record<string, number>;
  keys: { i: number; seed: string; pk: string }[];
  vectors: { id: number; family: string; source: string; note: string; pk: string; msg: string; sig: string; expected: boolean | "BADLEN"; noble: boolean | "THROW" }[];
}
interface ExpansionPins {
  count: number;
  byPkSha256: Record<string, { pkBytes: number; blobBytes: number; blobSha256: string; tr: string }>;
}

type Expected = boolean | "REJECT_AT_EXPANSION" | "REVERT:ContextTooLong" | "REVERT:InvalidSignatureLength" | "BADLEN";

interface Row {
  family: string;
  source: string;
  iface: "digest32" | "ctx";
  expected: Expected;
  outcome: Verdict["outcome"] | "NOT_RUN";
  detail: string;
  gas: number | null;
  noble: boolean | "THROW" | null;
  consistent: boolean;
  chainVsNobleSplit: boolean;
  note?: string;
}

const strip = (h: string): string => h.replace(/^0x/, "").toLowerCase();

function judge(expected: Expected, v: Verdict): boolean {
  if (expected === true) return v.outcome === "ACCEPT";
  if (expected === false) return v.outcome === "REJECT";
  if (expected === "BADLEN") return v.outcome === "REJECT" && v.detail === "0xffffffff";
  if (expected === "REVERT:ContextTooLong") return v.outcome === "REVERT" && v.detail === "ContextTooLong";
  if (expected === "REVERT:InvalidSignatureLength") return v.outcome === "REVERT" && v.detail === "InvalidSignatureLength";
  return false;
}

describe("pq-verifier-spike — conformance campaign (partial conformance evidence, not a review)", function () {
  this.timeout(1_800_000);
  let world: World;
  const rows: Row[] = [];
  const expansionChecks: { pkSha256: string; blobSha256: string; pinnedBy: string; matches: boolean }[] = [];

  const acvp = loadFixture<AcvpFixture>("acvp-mldsa65-sigver-tgid3.json");
  const wp = loadFixture<WycheproofFixture>("wycheproof-mldsa_65_verify_test.json");
  const rsp = loadFixture<RspFixture>("nist-rsp-dilithium3-counts0-9.json");
  const vendor = loadFixture<VendorFixture>("vendor-vectors.json");
  const gen = loadFixture<GeneratedFixture>("generated-vectors.json");
  const pins = loadFixture<ExpansionPins>("expanded-key-digests.json");

  before(async function () {
    world = await createWorld();
  });

  async function publishChecked(pkHex: string, pinnedBy: string, expectedBlobSha256?: string): Promise<string> {
    const pk = strip(pkHex);
    const blob = expandToBlob(pk);
    const blobSha = sha256(Buffer.from(unhex(blob)));
    const pkSha = sha256(Buffer.from(unhex(pk)));
    const pinned = expectedBlobSha256 ?? pins.byPkSha256[pkSha]?.blobSha256;
    if (!expansionChecks.some((e) => e.pkSha256 === pkSha)) {
      expansionChecks.push({ pkSha256: pkSha, blobSha256: blobSha, pinnedBy: pinned ? pinnedBy : "UNPINNED", matches: pinned ? pinned === blobSha : false });
    }
    const { handle } = await world.publish(pk);
    expect(handle.length, "a 40-byte handle (two SSTORE2 pointers)").to.equal(82);
    return handle;
  }

  function record(row: Row): void {
    rows.push(row);
    if (!row.consistent || row.chainVsNobleSplit) console.log("[FINDING]", JSON.stringify(row));
  }

  it("ACVP ML-DSA-65 sigVer tgId 3: 15 vectors return NIST's verdict", async function () {
    expect(acvp.count).to.equal(15);
    expect(acvp.group.parameterSet).to.equal("ML-DSA-65");
    for (const t of acvp.tests) {
      const vendorPk = vendor.acvpPkByTcId[String(t.tcId)];
      expect(strip(t.pk), `tcId ${t.tcId}: the vendor's test file carries the same NIST public key`).to.equal(vendorPk);
      const vendorBlob = vendor.blobDigests.find((d) => d.tcId === t.tcId && d.name.startsWith("ACVP"))?.blobSha256;
      const handle = await publishChecked(t.pk, "vendor test/KAT/mldsa65_vectors.json", vendorBlob);
      const v = await world.tryCtx(handle, t.message, t.signature, t.context);
      const noble = nobleVerdict(t.signature, t.message, t.pk, t.context);
      record({ family: "acvp", source: `ACVP vsId ${acvp.source.vsId} tgId 3 tcId ${t.tcId} (${t.reason})`, iface: "ctx", expected: t.testPassed, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(t.testPassed, v), chainVsNobleSplit: typeof noble === "boolean" && noble !== (v.outcome === "ACCEPT") });
    }
    expect(rows.filter((r) => r.family === "acvp" && !r.consistent)).to.deep.equal([]);
  });

  it("Wycheproof mldsa_65_verify_test: 210 vectors (valid, invalid, acceptable) return the expected verdict or the expected refusal", async function () {
    expect(wp.numberOfTests).to.equal(210);
    let run = 0;
    for (const g of wp.testGroups) {
      const pk = strip(g.publicKey);
      const pkLen = pk.length / 2;
      let handle: string | null = null;
      if (pkLen === 1952) handle = await publishChecked(pk, "feasibility run (upstream ESM js/mldsa65.js)");
      else {
        let threw = false;
        try {
          expandToBlob(pk);
        } catch {
          threw = true;
        }
        expect(threw, `pk of ${pkLen} bytes must be refused by the client expansion`).to.equal(true);
      }
      for (const t of g.tests) {
        const ctx = strip(t.ctx ?? "");
        const sig = strip(t.sig);
        const msg = strip(t.msg ?? "");
        let expected: Expected;
        let note = `${t.comment} [${(t.flags ?? []).join(",")}]`;
        if (pkLen !== 1952) {
          expected = "REJECT_AT_EXPANSION";
          note += " — refused before any chain state exists";
        } else if (ctx.length / 2 > 255) expected = "REVERT:ContextTooLong";
        else if (sig.length / 2 !== 3309) expected = "REVERT:InvalidSignatureLength";
        else expected = t.result === "valid";
        const noble = nobleVerdict(sig, msg, pk, ctx);
        if (handle === null) {
          record({ family: "wycheproof", source: `Wycheproof tcId ${t.tcId}`, iface: "ctx", expected, outcome: "NOT_RUN", detail: `pk length ${pkLen}`, gas: null, noble, consistent: true, chainVsNobleSplit: false, note });
          continue;
        }
        const v = await world.tryCtx(handle, msg, sig, ctx);
        run++;
        record({ family: "wycheproof", source: `Wycheproof tcId ${t.tcId}`, iface: "ctx", expected, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(expected, v), chainVsNobleSplit: typeof noble === "boolean" && typeof expected === "boolean" && noble !== (v.outcome === "ACCEPT"), note });
      }
    }
    console.log(`[wycheproof] ${run} run on chain, ${210 - run} refused at expansion`);
    expect(rows.filter((r) => r.family === "wycheproof" && !r.consistent)).to.deep.equal([]);
  });

  it("NIST reference KAT (.rsp counts 0..9): 10 valid vectors verify with an empty context", async function () {
    expect(rsp.count).to.equal(10);
    for (const t of rsp.tests) {
      const vendorBlob = vendor.blobDigests.find((d) => d.tcId === t.count && d.name.startsWith("PQCsignKAT"))?.blobSha256;
      const handle = await publishChecked(t.pk, "vendor test/KAT/mldsa65_vectors.json", vendorBlob);
      const v = await world.tryCtx(handle, t.msg, t.signature, "");
      const noble = nobleVerdict(t.signature, t.msg, t.pk, "");
      record({ family: "rsp", source: `PQCsignKAT_Dilithium3.rsp count ${t.count} (mlen ${t.mlen})`, iface: "ctx", expected: true, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(true, v), chainVsNobleSplit: typeof noble === "boolean" && noble !== (v.outcome === "ACCEPT") });
    }
    expect(rows.filter((r) => r.family === "rsp" && !r.consistent)).to.deep.equal([]);
  });

  it("vendor vectors: the three js-generated vectors and the 32-byte-hash vector behave as the vendor's suite expects", async function () {
    for (const t of vendor.jsVectors) {
      const handle = await publishChecked(t.pk, "vendor test/KAT/mldsa65_vectors.json", t.blobSha256);
      const v = await world.tryCtx(handle, strip(t.msg), strip(t.sig), strip(t.ctx));
      const noble = nobleVerdict(strip(t.sig), strip(t.msg), strip(t.pk), strip(t.ctx));
      record({ family: "vendor", source: t.name, iface: "ctx", expected: t.valid, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(t.valid, v), chainVsNobleSplit: typeof noble === "boolean" && noble !== (v.outcome === "ACCEPT") });
    }
    // hash32: the vendor's test publishes the blob of .rsp count 0 and verifies `.hash32.sig` over `.hash32.hash`
    // through ISigVerifier.verify(pk, hash, sig). `key` is whatever the vendor's generator wrote: a 1,952-byte
    // public key, a 40,320-byte setKey blob, or something else, in which case the rsp count 0 key is used as the
    // vendor's own test does.
    const key = strip(vendor.hash32.key);
    const rsp0 = rsp.tests.find((t) => t.count === 0)!;
    let pk: string;
    let handle: string;
    if (key.length / 2 === 1952) {
      pk = key;
      handle = await publishChecked(pk, "vendor test/KAT/mldsa65_vectors.json");
    } else if (key.length / 2 === 40_320) {
      pk = strip(rsp0.pk);
      expect(sha256(Buffer.from(unhex(key))), "the vendor's hash32 blob is the expansion of rsp count 0").to.equal(sha256(Buffer.from(unhex(expandToBlob(pk)))));
      handle = (await world.publishBlob(key)).handle;
    } else {
      pk = strip(rsp0.pk);
      handle = await publishChecked(pk, "vendor test/KAT/mldsa65_vectors.json");
    }
    const v = await world.try32(handle, strip(vendor.hash32.hash), strip(vendor.hash32.sig));
    const noble = nobleVerdict(strip(vendor.hash32.sig), strip(vendor.hash32.hash), pk, "");
    record({ family: "vendor", source: "hash32 (ISigVerifier.verify(pk, hash, sig), deterministic, rsp count 0 key)", iface: "digest32", expected: true, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(true, v), chainVsNobleSplit: typeof noble === "boolean" && noble !== (v.outcome === "ACCEPT") });
    const wrong = await world.try32(handle, strip(vendor.hash32.hash).replace(/^../, (b) => (parseInt(b, 16) ^ 0xff).toString(16).padStart(2, "0")), strip(vendor.hash32.sig));
    record({ family: "vendor", source: "hash32 with the first digest byte complemented", iface: "digest32", expected: false, outcome: wrong.outcome, detail: wrong.detail, gas: wrong.gas, noble: null, consistent: judge(false, wrong), chainVsNobleSplit: false });
    expect(rows.filter((r) => r.family === "vendor" && !r.consistent)).to.deep.equal([]);
  });

  it("generated vectors: 32-byte digests, z-norm boundary, hint canonicality and the degenerate key", async function () {
    expect(gen.vectors.length).to.equal(52);
    for (const t of gen.vectors) {
      const handle = await publishChecked(t.pk, "feasibility run (upstream ESM js/mldsa65.js)");
      const v = await world.try32(handle, t.msg, t.sig);
      const noble = nobleVerdict(t.sig, t.msg, t.pk, "");
      const expected: Expected = t.expected;
      record({ family: t.family, source: t.source, iface: "digest32", expected, outcome: v.outcome, detail: v.detail, gas: v.gas, noble, consistent: judge(expected, v), chainVsNobleSplit: typeof noble === "boolean" && typeof expected === "boolean" && noble !== (v.outcome === "ACCEPT"), note: t.note });
    }
    const bad = rows.filter((r) => r.family.startsWith("digest32") || r.family === "znorm_boundary" || r.family === "hint_canonicality" || r.family === "degenerate_key").filter((r) => !r.consistent);
    expect(bad).to.deep.equal([]);
    // the degenerate key is ACCEPTED, by FIPS 204 and by this verifier alike: that is the finding, recorded as such
    const degenerate = rows.find((r) => r.family === "degenerate_key");
    expect(degenerate?.outcome).to.equal("ACCEPT");
    expect(degenerate?.noble).to.equal(true);
    // the z-norm boundary: ||z|| = gamma1 - beta - 1 accepted; exactly gamma1 - beta rejected early (before any NTT)
    const boundary = rows.filter((r) => r.family === "znorm_boundary");
    expect(boundary.map((r) => r.outcome)).to.deep.equal(["ACCEPT", "REJECT", "REJECT"]);
    const accepted = boundary[0]!.gas!;
    for (const r of boundary.slice(1)) expect(r.gas!, "a norm-gate rejection costs a fraction of a full verification").to.be.lessThan(accepted / 5);
  });

  it("every expanded key matches an independent earlier expansion (feasibility run or the vendor's file)", function () {
    expect(expansionChecks.length).to.be.greaterThan(40);
    const unpinned = expansionChecks.filter((e) => e.pinnedBy === "UNPINNED");
    expect(unpinned, "every key has a pinned expansion digest").to.deep.equal([]);
    expect(expansionChecks.filter((e) => !e.matches)).to.deep.equal([]);
  });

  it("summary: no inconsistent vector, no chain/client split; the committed record is reproduced", async function () {
    const summary = {
      vectors: rows.length,
      runOnChain: rows.filter((r) => r.outcome !== "NOT_RUN").length,
      refusedAtExpansion: rows.filter((r) => r.outcome === "NOT_RUN").length,
      consistent: rows.filter((r) => r.consistent).length,
      inconsistent: rows.filter((r) => !r.consistent).length,
      chainVsNobleSplits: rows.filter((r) => r.chainVsNobleSplit).length,
      byFamily: rows.reduce<Record<string, { n: number; accept: number; reject: number; revert: number; notRun: number }>>((acc, r) => {
        const f = (acc[r.family] ??= { n: 0, accept: 0, reject: 0, revert: 0, notRun: 0 });
        f.n++;
        if (r.outcome === "ACCEPT") f.accept++;
        else if (r.outcome === "REJECT") f.reject++;
        else if (r.outcome === "REVERT") f.revert++;
        else if (r.outcome === "NOT_RUN") f.notRun++;
        return acc;
      }, {}),
      gasByOutcome: (["ACCEPT", "REJECT", "REVERT"] as const).reduce<Record<string, { n: number; min: number; max: number; mean: number }>>((acc, o) => {
        const g = rows.filter((r) => r.outcome === o && r.gas !== null).map((r) => r.gas as number);
        if (g.length) acc[o] = { n: g.length, min: Math.min(...g), max: Math.max(...g), mean: Math.round(g.reduce((a, b) => a + b, 0) / g.length) };
        return acc;
      }, {}),
      uniqueKeysPublished: expansionChecks.length,
    };
    console.log("[summary]", JSON.stringify(summary, null, 1));
    expect(summary.inconsistent).to.equal(0);
    expect(summary.chainVsNobleSplits).to.equal(0);
    expect(summary.vectors).to.equal(15 + 210 + 10 + 5 + 52);
    const record = { schema: "gen2-pq-conformance-1/conformance.v1", summary, expansionChecks, rows, environment: await toolchainRecord() };
    writeResults("conformance.json", record);
    const committed = readResults<typeof record>("conformance.json");
    if (committed) {
      expect(summary).to.deep.equal(committed.summary);
      expect(rows).to.deep.equal(committed.rows);
    } else {
      this.skip();
    }
  });
});
