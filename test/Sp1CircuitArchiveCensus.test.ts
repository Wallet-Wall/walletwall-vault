/**
 * The read-only archive census (scripts/lib/sp1-circuit-archive-census.ts): every tar entry listed, AppleDouble bodies
 * decoded, and each AppleDouble-shaped entry's relation to every other entry reported. It accepts and refuses nothing;
 * it throws only on a stream that is not tar. Synthetic archives only (scripts/lib/sp1-circuit-fixtures.ts).
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { PROVENANCE_PAX_KEY, PROVENANCE_VALUE } from "../scripts/lib/sp1-circuit-archive";
import {
  CENSUS_SCHEMA,
  appleDoubleRelations,
  censusArchive,
  decodeAppleDouble,
  type CensusEntry,
} from "../scripts/lib/sp1-circuit-archive-census";
import {
  APPLEDOUBLE_BODY,
  UPSTREAM_SHAPED_FILES,
  gz,
  paxData,
  provenancePax,
  tarBytes,
  upstreamShapedEntries,
  type TarSpec,
} from "../scripts/lib/sp1-circuit-fixtures";
import { tempDirs } from "./helpers/circuit-tooling";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

describe("SP1-PA2A amendment: the read-only archive census", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());
  const write = (bytes: Buffer, name = "a.tar.gz") => {
    const p = join(dirs.make(), name);
    writeFileSync(p, bytes);
    return p;
  };
  const census = (entries: TarSpec[], opts: Parameters<typeof tarBytes>[1] = {}) =>
    censusArchive(write(gz(tarBytes(entries, opts))));
  const ad = (name: string): TarSpec => ({ name, data: APPLEDOUBLE_BODY });

  it("lists every entry of the upstream-shaped archive, PAX headers included, and decodes each AppleDouble body", async function () {
    const archive = gz(tarBytes(upstreamShapedEntries()));
    const c = await censusArchive(write(archive));
    expect(c.schema).to.equal(CENSUS_SCHEMA);
    expect(c.archive).to.deep.equal({ bytes: archive.length, sha256: sha256(archive) });
    expect(c.tar.entries).to.equal(2 + 8 + 2 * UPSTREAM_SHAPED_FILES.length);
    expect(c.tar.trailingZeroBytes).to.equal(1024);
    const real = c.entries.filter((e) => e.typeflag !== "x");
    expect(real.map((e) => e.path)).to.deep.equal([
      "._.",
      "./",
      ...UPSTREAM_SHAPED_FILES.flatMap(([p]) => [`./._${p}`, `./${p}`]),
    ]);
    const vk = real.find((e) => e.path === "./groth16_vk.bin") as CensusEntry;
    expect(vk.dataSha256).to.equal(sha256(UPSTREAM_SHAPED_FILES[0][1]));
    expect(vk.pax.find((p) => p.key === PROVENANCE_PAX_KEY)).to.deep.equal({
      key: PROVENANCE_PAX_KEY,
      valueBytes: PROVENANCE_VALUE.length,
      valueSha256: sha256(PROVENANCE_VALUE),
    });
    const body = real[0].appleDouble;
    expect(body?.magic).to.equal("0x00051607");
    expect(body?.version).to.equal("0x00020000");
    expect(body?.filler).to.equal("Mac OS X        ");
    expect(body?.entries).to.deep.equal([
      { id: 9, offset: 50, length: 113 },
      { id: 2, offset: 163, length: 0 },
    ]);
    expect(body?.attributes).to.deep.equal([
      { name: "com.apple.provenance", bytes: 11, sha256: sha256(PROVENANCE_VALUE) },
    ]);
    expect(body?.error).to.equal(null);
    expect(c.appleDouble).to.have.length(8);
    for (const r of c.appleDouble) {
      expect(r.companionPresent && r.companionFollows, r.path).to.equal(true);
      expect([...r.sameAsOther, ...r.caseFoldSameAsOther, ...r.windowsNameSameAsOther], r.path).to.deep.equal([]);
      expect([...r.parentOfOther, ...r.otherIsParent], r.path).to.deep.equal([]);
    }
    expect(c.appleDouble[0]).to.include({ path: "._.", companion: ".", mode: "0755", size: 163 });
  });

  it("depends only on the archive's bytes, not on where it lies", async function () {
    const archive = gz(tarBytes(upstreamShapedEntries()));
    const a = await censusArchive(write(archive, "one.tar.gz"));
    const b = await censusArchive(write(archive, "two.tar.gz"));
    expect(JSON.stringify(a)).to.equal(JSON.stringify(b));
  });

  it("reports orphans and every collision an extractor could make", async function () {
    const c = await census([
      ad("._orphan"),
      { name: "y", data: "y" },
      ad("._a"),
      ad("._A"),
      ad("._w."),
      ad("._w"),
      ad("._d"),
      ad("._d/x"),
    ]);
    const at = (p: string) => c.appleDouble.find((r) => r.path === p);
    expect(at("._orphan")).to.include({ companion: "orphan", companionPresent: false, companionFollows: false });
    expect(at("._a")?.caseFoldSameAsOther).to.deep.equal(["._A"]);
    expect(at("._a")?.sameAsOther).to.deep.equal([]);
    expect(at("._w.")?.windowsNameSameAsOther).to.deep.equal(["._w"]);
    expect(at("._d")?.parentOfOther).to.deep.equal(["._d/x"]);
    expect(at("._d/x")?.otherIsParent).to.deep.equal(["._d"]);
    // Its "._" component is a directory: the census's basename rule names no entry ("._d/"), and none is present.
    expect(at("._d/x")).to.include({ companion: "._d/", companionPresent: false, companionFollows: false });
    const twice = await census([ad("._z"), ad("._z")]);
    expect(twice.appleDouble[0].sameAsOther).to.deep.equal(["._z"]);
  });

  it("names a nested AppleDouble entry's companion in its own directory", async function () {
    const c = await census([{ name: "d/", type: "5" }, ad("d/._f"), { name: "d/f", data: "f" }]);
    expect(c.appleDouble[0]).to.include({ path: "d/._f", companion: "d/f", companionFollows: true });
  });

  it("applies a PAX path and size to the next entry, never a global header's", async function () {
    const c = await census([
      { name: "g", type: "g", data: paxData({ comment: "global" }) },
      { name: "short", data: "abc", pax: { path: "long/name", size: "3" } },
    ]);
    const real = c.entries.filter((e) => e.typeflag !== "x" && e.typeflag !== "g");
    expect(real.map((e) => [e.path, e.size])).to.deep.equal([["long/name", 3]]);
    expect(c.entries[0].pax.map((p) => p.key)).to.deep.equal(["comment"]);
    expect(real[0].pax.map((p) => p.key)).to.deep.equal(["path", "size"]);
  });

  it("reads GNU headers and base-256 sizes, and hashes large AppleDouble-shaped entries without decoding them", async function () {
    const big = Buffer.alloc(1024 * 1024 + 1, 7);
    const c = await census([
      { name: "gnu", data: "g", format: "gnu" },
      { name: "b256", data: "bb", sizeEncoding: "base256" },
      { name: "._big", data: big },
    ]);
    expect(c.entries.map((e) => e.size)).to.deep.equal([1, 2, big.length]);
    expect(c.entries[2].appleDouble).to.equal(null);
    expect(c.entries[2].dataSha256).to.equal(sha256(big));
    expect(c.entries[0].magic).to.equal(Buffer.from("ustar  \0", "latin1").toString("hex"));
  });

  it("throws only on a stream that is not tar", async function () {
    const cases: [string, Buffer, RegExp][] = [
      ["a bad checksum", gz(tarBytes([{ name: "a", data: "x", badChecksum: true }])), /checksum/],
      ["no end block", gz(tarBytes([{ name: "a", data: "x" }], { end: false })), /ends before an end-of-archive block/],
      [
        "data after the end",
        gz(tarBytes([{ name: "a" }], { trailing: Buffer.from("x") })),
        /non-zero bytes after the end/,
      ],
      ["a mode that is not octal", gz(tarBytes([{ name: "a", mode: "rwxr-xr\0" }])), /the mode field is not octal/],
      ["a negative base-256 size", gz(tarBytes([{ name: "a", data: "x", sizeEncoding: "negative" }])), /size/],
      [
        "a malformed PAX record",
        gz(tarBytes([{ name: "a", pax: Buffer.from("99 mtime=0\n") }])),
        /malformed PAX record/,
      ],
    ];
    for (const [what, bytes, want] of cases) {
      let message = "NOT_THROWN";
      try {
        await censusArchive(write(bytes));
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message, what).to.match(want);
    }
    let gzipError = "NOT_THROWN";
    try {
      await censusArchive(write(tarBytes([{ name: "a" }])));
    } catch (error) {
      gzipError = String((error as NodeJS.ErrnoException).code);
    }
    expect(gzipError).to.match(/^Z_/);
  });

  describe("decodeAppleDouble", function () {
    it("reads the upstream body", function () {
      expect(decodeAppleDouble(APPLEDOUBLE_BODY).attributes?.map((a) => a.name)).to.deep.equal([
        "com.apple.provenance",
      ]);
    });
    it("names what it cannot read instead of throwing", function () {
      const at = (edit: (b: Buffer) => Buffer) => decodeAppleDouble(edit(Buffer.from(APPLEDOUBLE_BODY))).error;
      expect(at((b) => b.subarray(0, 25))).to.equal("SHORT_HEADER");
      expect(at((b) => (b.writeUInt16BE(100, 24), b))).to.equal("ENTRY_TABLE_OVERRUN");
      expect(at((b) => (b.writeUInt32BE(1000, 26 + 8), b))).to.equal("ENTRY_9_OVERRUN");
      expect(at((b) => (b.writeUInt32BE(1000, 120), b))).to.equal("ATTRIBUTE_OVERRUN");
    });
    it("reports no attributes when the Finder Info holds no ATTR block", function () {
      const b = Buffer.from(APPLEDOUBLE_BODY);
      b.write("XXXX", 84, "latin1");
      const d = decodeAppleDouble(b);
      expect(d.attributes).to.equal(null);
      expect(d.error).to.equal(null);
    });
  });

  it("relates only real entries (PAX headers are not companions)", function () {
    const e = (index: number, typeflag: string, path: string) =>
      ({ index, typeflag, path, mode: "0644", size: 1, dataSha256: "", pax: [] }) as unknown as CensusEntry;
    const r = appleDoubleRelations([e(0, "0", "._x"), e(1, "x", "PaxHeader/x"), e(2, "0", "x")]);
    expect(r).to.have.length(1);
    expect(r[0]).to.include({ companion: "x", companionPresent: true, companionFollows: true });
  });

  it("writes provenance records byte for byte through the fixture writer", function () {
    const data = paxData(provenancePax());
    expect(data.includes(PROVENANCE_VALUE)).to.equal(true);
  });
});
