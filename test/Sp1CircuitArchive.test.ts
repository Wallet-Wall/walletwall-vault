/**
 * SP1-PA2A: the archive record, the member-path rules and the structured tar parser (scripts/lib/sp1-circuit-archive.ts).
 *
 * SP1's own installer downloads the circuit, checks no digest and extracts with `tar -Pxzf`. WalletWall's path
 * authenticates an archive by sha256 before parsing it, reads its metadata with its own parser, and refuses every entry
 * that is not a regular file or directory under one canonical, portable path. Each refusal is pinned by code AND reason,
 * so a check that is removed is caught even when a later check would still refuse the same archive.
 *
 * Everything here is synthetic (scripts/lib/sp1-circuit-fixtures.ts). No network, no download, no SP1.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  ARCHIVE_RECORD_SCHEMA,
  MemberTree,
  REQUIRED_MEMBERS,
  TarParser,
  VK_FILE,
  acceptedRecord,
  archiveRecordErrors,
  entryPath,
  imageRefError,
  inspectArchive,
  measureArchive,
  memberPathError,
  memberSetErrors,
  parsePax,
  vkError,
  type ArchiveRecord,
} from "../scripts/lib/sp1-circuit-archive";
import {
  SAFE_FILES,
  SYNTHETIC_ANCHOR,
  gz,
  hostileCases,
  safeEntries,
  safeTar,
  syntheticRecord,
  tarBytes,
} from "../scripts/lib/sp1-circuit-fixtures";
import { refusalOf, tempDirs } from "./helpers/circuit-tooling";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const anchor = SYNTHETIC_ANCHOR;
const safeGz = gz(safeTar());
const baseRecord = () => syntheticRecord(safeGz, SAFE_FILES);
const reasons = (r: unknown) => archiveRecordErrors(r, anchor).map((e) => e.reason);
const limits = { maxEntries: 10_000, maxTotalBytes: 64 * 1024 ** 3, maxPaxBytes: 65_536 };

describe("SP1-PA2A circuit archive: record, paths and the tar parser", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  const write = (bytes: Buffer, name = "a.tar.gz") => {
    const p = join(dirs.make(), name);
    writeFileSync(p, bytes);
    return p;
  };

  describe("the archive record", function () {
    it("accepts the synthetic record for the synthetic anchor, and nothing else is needed", function () {
      expect(reasons(baseRecord())).to.deep.equal([]);
      expect(acceptedRecord(baseRecord(), anchor).schema).to.equal(ARCHIVE_RECORD_SCHEMA);
    });

    it("refuses a record that is not an object, an unknown field and a missing one", function () {
      expect(reasons(null)).to.deep.equal(["SHAPE"]);
      expect(reasons([])).to.deep.equal(["SHAPE"]);
      expect(reasons({ ...baseRecord(), extra: 1 })).to.deep.equal(["UNKNOWN_FIELD"]);
      const { mirrors: _m, ...noMirrors } = baseRecord();
      expect(reasons(noMirrors)).to.deep.equal(["MISSING_FIELD"]);
      const r = baseRecord() as any;
      r.subject.verifier.extra = 1;
      expect(reasons(r)).to.deep.equal(["UNKNOWN_FIELD"]);
    });

    it("refuses another schema", function () {
      expect(reasons({ ...baseRecord(), schema: "walletwall.sp1-proving-archive.v0" })).to.deep.equal(["SCHEMA"]);
    });

    it("binds the subject to the anchor field by field", function () {
      const edits: [string, (r: any) => void, string][] = [
        ["circuit system", (r) => (r.subject.circuitSystem = "plonk"), "CIRCUIT_SYSTEM_MISMATCH"],
        ["circuit version", (r) => (r.subject.circuitVersion = "v6.0.0"), "CIRCUIT_VERSION_MISMATCH"],
        ["designation", (r) => (r.subject.designation = "mldsa65-withdrawal-d1"), "SUBJECT_MISMATCH"],
        ["PROGRAM_VKEY", (r) => (r.subject.programVKey = `0x${"00".repeat(32)}`), "SUBJECT_MISMATCH"],
        ["verifier version", (r) => (r.subject.verifier.version = "v6.0.0"), "SUBJECT_MISMATCH"],
        ["verifier code", (r) => (r.subject.verifier.runtimeCodeKeccak = `0x${"11".repeat(32)}`), "SUBJECT_MISMATCH"],
        ["verifier hash", (r) => (r.subject.verifier.verifierHash = `0x${"22".repeat(32)}`), "SUBJECT_MISMATCH"],
        ["vk file", (r) => (r.subject.verifyingKey.file = "groth16_vk.json"), "VK_MISMATCH"],
        ["vk sha256", (r) => (r.subject.verifyingKey.sha256 = `0x${"33".repeat(32)}`), "VK_MISMATCH"],
        ["vk length", (r) => (r.subject.verifyingKey.bytes += 1), "VK_MISMATCH"],
      ];
      for (const [what, edit, reason] of edits) {
        const r = baseRecord();
        edit(r);
        expect(reasons(r), what).to.deep.equal([reason]);
      }
    });

    it("checks the archive fields, and keeps the source URL provenance only", function () {
      const edits: [string, (r: any) => void, string][] = [
        ["file", (r) => (r.archive.file = "../x.tar.gz"), "ARCHIVE_FIELD"],
        ["format", (r) => (r.archive.format = "zip"), "ARCHIVE_FIELD"],
        ["zero length", (r) => (r.archive.bytes = 0), "ARCHIVE_FIELD"],
        ["sha256", (r) => (r.archive.sha256 = r.archive.sha256.toUpperCase()), "ARCHIVE_FIELD"],
        ["timestamp", (r) => (r.archive.acquiredAtUtc = "2026-01-01"), "ARCHIVE_FIELD"],
        ["http", (r) => (r.archive.sourceUrl = "http://example.invalid/a.tar.gz"), "ARCHIVE_FIELD"],
        ["not a URL", (r) => (r.archive.sourceUrl = "not a url"), "ARCHIVE_FIELD"],
        ["source as authority", (r) => (r.archive.sourceUrlRole = "AUTHORITY"), "SOURCE_IS_AUTHORITY"],
      ];
      for (const [what, edit, reason] of edits) {
        const r = baseRecord();
        edit(r);
        const got = reasons(r);
        expect(got, what).to.include(reason);
        if (what !== "zero length" && what !== "sha256") expect(got, what).to.deep.equal([reason]);
      }
    });

    it("requires two agreeing acquisitions from distinct hosts", function () {
      const one = baseRecord();
      one.acquisitions = one.acquisitions.slice(0, 1);
      expect(reasons(one)).to.deep.equal(["ACQUISITIONS_MISSING"]);
      const same = baseRecord();
      same.acquisitions[1].host = same.acquisitions[0].host;
      expect(reasons(same)).to.deep.equal(["ACQUISITION_NOT_INDEPENDENT"]);
      const edits: [string, (q: any) => void, string][] = [
        ["sha256", (q) => (q.sha256 = "0".repeat(64)), "ACQUISITION_DISAGREES"],
        ["length", (q) => (q.bytes += 1), "ACQUISITION_DISAGREES"],
        ["agreement", (q) => (q.agreement = "DISAGREES"), "ACQUISITION_DISAGREES"],
        ["host label", (q) => (q.host = "Host A"), "ACQUISITION_FIELD"],
        ["timestamp", (q) => (q.observedAtUtc = "yesterday"), "ACQUISITION_FIELD"],
      ];
      for (const [what, edit, reason] of edits) {
        const r = baseRecord();
        edit(r.acquisitions[1]);
        expect(reasons(r), what).to.deep.equal([reason]);
      }
      const notArray = baseRecord() as any;
      notArray.acquisitions = {};
      expect(reasons(notArray)).to.deep.equal(["ACQUISITIONS_MISSING"]);
    });

    it("checks every member: canonical path, no collision, sorted, counted, hashed, required, the anchor's key", function () {
      const r0 = baseRecord();
      const edits: [string, (m: ArchiveRecord["members"]) => unknown, string][] = [
        ["no members", (m) => m.splice(0), "MEMBERS_MISSING"],
        ["traversal", (m) => (m[1].path = "../extra"), "MEMBER_PATH_INVALID"],
        ["not a string", (m) => ((m[1] as any).path = 7), "MEMBER_PATH_INVALID"],
        ["case collision", (m) => m.splice(1, 1, { ...m[1], path: "Constraints.json" }), "MEMBER_PATH_COLLISION"],
        ["out of order", (m) => m.reverse(), "MEMBERS_NOT_SORTED"],
        ["no byte count", (m) => ((m[1] as any).bytes = -1), "MEMBER_FIELD"],
        ["no sha256", (m) => (m[1].sha256 = "x"), "MEMBER_FIELD"],
        ["required member", (m) => m.splice(2, 1), "REQUIRED_MEMBER_MISSING"],
        ["too large", (m) => (m[1].bytes = 2 ** 40), "MEMBERS_TOO_LARGE"],
        ["vk sha256", (m) => (m[4].sha256 = "4".repeat(64)), "VK_MISMATCH"],
        ["vk length", (m) => (m[4].bytes += 1), "VK_MISMATCH"],
      ];
      expect(r0.members[4].path).to.equal(VK_FILE);
      for (const [what, edit, reason] of edits) {
        const r = baseRecord();
        edit(r.members);
        const got = reasons(r);
        expect(got, what).to.include(reason);
        if (!["no members", "case collision", "out of order"].includes(what)) expect(got, what).to.deep.equal([reason]);
      }
      const dup = baseRecord();
      dup.members.splice(1, 0, { ...dup.members[0] });
      expect(reasons(dup)).to.include("MEMBER_PATH_COLLISION");
    });

    it("requires the gnark image by digest; its tag is provenance only", function () {
      const edits: [string, (g: any) => void, string][] = [
        ["tag in the repository", (g) => (g.repository = `${g.repository}:v6.1.0`), "GNARK_NOT_DIGEST_PINNED"],
        ["malformed digest", (g) => (g.digest = "sha256:abc"), "GNARK_NOT_DIGEST_PINNED"],
        ["tag as authority", (g) => (g.tagRole = "AUTHORITY"), "TAG_IS_AUTHORITY"],
        ["empty tag", (g) => (g.tag = ""), "TAG_IS_AUTHORITY"],
        ["observation", (g) => (g.observation.method = ""), "GNARK_FIELD"],
        ["observation host", (g) => (g.observation.host = "A B"), "GNARK_FIELD"],
        ["observation time", (g) => (g.observation.observedAtUtc = "now"), "GNARK_FIELD"],
        [
          "mirror of another image",
          (g) => (g.mirror = { location: "m", digest: `sha256:${"9".repeat(64)}` }),
          "GNARK_FIELD",
        ],
        ["mirror without location", (g) => (g.mirror = { location: "", digest: g.digest }), "GNARK_FIELD"],
      ];
      for (const [what, edit, reason] of edits) {
        const r = baseRecord();
        edit(r.gnark);
        expect(reasons(r), what).to.deep.equal([reason]);
      }
      const mirrored = baseRecord();
      mirrored.gnark.mirror = { location: "walletwall-mirror", digest: mirrored.gnark.digest };
      expect(reasons(mirrored)).to.deep.equal([]);
    });

    it("requires two distinct mirrors, each naming the archive's sha256", function () {
      const one = baseRecord();
      one.mirrors = one.mirrors.slice(1);
      expect(reasons(one)).to.deep.equal(["MIRRORS_MISSING"]);
      const dup = baseRecord();
      dup.mirrors[1].location = dup.mirrors[0].location;
      expect(reasons(dup)).to.deep.equal(["MIRROR_FIELD"]);
      const other = baseRecord();
      other.mirrors[1].sha256 = "0".repeat(64);
      expect(reasons(other)).to.deep.equal(["MIRROR_DIGEST_MISMATCH"]);
      const empty = baseRecord();
      empty.mirrors[0].location = "";
      expect(reasons(empty)).to.deep.equal(["MIRROR_FIELD"]);
    });

    it("acceptedRecord names every reason in one RECORD_INVALID", async function () {
      const r = baseRecord() as any;
      r.subject.designation = "x";
      r.mirrors = [];
      expect(await refusalOf(() => acceptedRecord(r, anchor))).to.equal("RECORD_INVALID (SUBJECT_MISMATCH)");
      try {
        acceptedRecord(r, anchor);
      } catch (e) {
        expect((e as Error).message).to.include("MIRRORS_MISSING");
      }
    });
  });

  describe("image references", function () {
    const d = `sha256:${"a".repeat(64)}`;
    it("accepts registry/repository@sha256:<digest> only", function () {
      expect(imageRefError(`ghcr.io/succinctlabs/sp1-gnark@${d}`)).to.equal(null);
      expect(imageRefError(`localhost:5000/gnark@${d}`)).to.equal(null);
      expect(imageRefError(`registry.invalid/a/b__c@${d}`)).to.equal(null);
    });
    it("refuses tags, bare names, malformed digests and unqualified repositories", function () {
      expect(imageRefError("ghcr.io/succinctlabs/sp1-gnark:latest")).to.equal("NO_DIGEST");
      expect(imageRefError("ghcr.io/succinctlabs/sp1-gnark:v6.1.0")).to.equal("NO_DIGEST");
      expect(imageRefError("ghcr.io/succinctlabs/sp1-gnark")).to.equal("NO_DIGEST");
      expect(imageRefError(`ghcr.io/succinctlabs/sp1-gnark:v6.1.0@${d}`)).to.equal("TAG_AND_DIGEST");
      expect(imageRefError(`ubuntu:22.04@${d}`)).to.equal("TAG_AND_DIGEST");
      expect(imageRefError("ghcr.io/succinctlabs/sp1-gnark@sha256:ABC")).to.equal("MALFORMED_DIGEST");
      expect(imageRefError(`ghcr.io/succinctlabs/sp1-gnark@sha512:${"a".repeat(128)}`)).to.equal("MALFORMED_DIGEST");
      expect(imageRefError(`ghcr.io/succinctlabs/sp1-gnark@${d}x`)).to.equal("MALFORMED_DIGEST");
      expect(imageRefError(`ghcr.io/Succinct/sp1@${d}`)).to.equal("MALFORMED_REPOSITORY");
      expect(imageRefError(`ghcr.io@${d}`)).to.equal("MALFORMED_REPOSITORY");
      expect(imageRefError(`succinctlabs/sp1-gnark@${d}`)).to.equal("NOT_FULLY_QUALIFIED");
    });
  });

  describe("member paths", function () {
    it("accepts canonical portable relative paths", function () {
      for (const p of ["groth16_pk.bin", "a/b/c.json", "._x", "-dash", "A_1.2-3"])
        expect(memberPathError(p), p).to.equal(null);
      expect(memberPathError("n".repeat(100))).to.equal(null);
    });
    it("names the rule each hostile spelling breaks", function () {
      const cases: [string, string][] = [
        ["a\0b", "NUL_IN_PATH"],
        ["C:\\evil", "BACKSLASH_IN_PATH"],
        ["\\\\server\\share\\evil", "BACKSLASH_IN_PATH"],
        ["a\\..\\b/c", "BACKSLASH_IN_PATH"],
        ["C:/evil", "DRIVE_QUALIFIED_PATH"],
        ["c:evil", "DRIVE_QUALIFIED_PATH"],
        ["/etc/passwd", "ABSOLUTE_PATH"],
        ["//server/share", "ABSOLUTE_PATH"],
        ["n".repeat(101), "PATH_TOO_LONG"],
        ["../../escape", "TRAVERSAL"],
        ["a/../../../escape", "TRAVERSAL"],
        ["..", "TRAVERSAL"],
        ["a/./b", "DOT_COMPONENT"],
        [".", "DOT_COMPONENT"],
        ["a//b", "EMPTY_COMPONENT"],
        ["a/", "EMPTY_COMPONENT"],
        ["", "EMPTY_COMPONENT"],
        ["a b", "NON_PORTABLE_COMPONENT"],
        ["é", "NON_PORTABLE_COMPONENT"],
        ["ab:c", "NON_PORTABLE_COMPONENT"],
        ["a:b", "DRIVE_QUALIFIED_PATH"],
        ["evil.", "TRAILING_DOT"],
        ["a/b...", "TRAILING_DOT"],
        ["CON", "RESERVED_NAME"],
        ["nul.txt", "RESERVED_NAME"],
        ["x/com1", "RESERVED_NAME"],
        ["Lpt9.bin", "RESERVED_NAME"],
      ];
      for (const [p, why] of cases) expect(memberPathError(p), JSON.stringify(p)).to.equal(why);
      expect(memberPathError("console"), "a device name only as a whole component").to.equal(null);
      expect(memberPathError("com10")).to.equal(null);
    });
    it("normalizes a tar name: one leading ./ and a directory's trailing /", function () {
      expect(entryPath("./a", "file")).to.equal("a");
      expect(entryPath("././a", "file")).to.equal("./a");
      expect(entryPath("a/", "file")).to.equal("a/");
      expect(entryPath("a/", "directory")).to.equal("a");
      expect(entryPath("./", "directory")).to.equal("");
      expect(entryPath(".", "directory")).to.equal("");
      expect(entryPath("./a/b/", "directory")).to.equal("a/b");
    });
  });

  describe("the member tree", function () {
    const run = (...entries: [string, "file" | "directory"][]) => {
      const t = new MemberTree();
      for (const [p, k] of entries) {
        const r = t.add(p, k);
        if (r) return r;
      }
      return t.finish();
    };
    it("accepts files with their directories, in any order, a directory entry before or after its files", function () {
      expect(run(["a", "directory"], ["a/b", "file"], ["c", "file"])).to.equal(null);
      expect(run(["a/b", "file"], ["a", "directory"])).to.equal(null);
      expect(run(["a/b/c", "file"], ["a/d", "file"])).to.equal(null);
    });
    it("refuses duplicates, case collisions, file-directory collisions, file parents and empty directories", function () {
      expect(run(["a", "file"], ["a", "file"])).to.equal("DUPLICATE_PATH");
      expect(run(["a", "directory"], ["a/x", "file"], ["a", "directory"])).to.equal("DUPLICATE_PATH");
      expect(run(["a", "file"], ["A", "file"])).to.equal("CASE_COLLISION");
      expect(run(["D/x", "file"], ["d/y", "file"])).to.equal("CASE_COLLISION");
      expect(run(["d/x", "file"], ["D", "directory"])).to.equal("CASE_COLLISION");
      expect(run(["d", "file"], ["d", "directory"])).to.equal("FILE_DIRECTORY_COLLISION");
      expect(run(["d", "directory"], ["d", "file"])).to.equal("FILE_DIRECTORY_COLLISION");
      expect(run(["p", "file"], ["p/x", "file"])).to.equal("PARENT_IS_FILE");
      expect(run(["p/x", "file"], ["p", "file"])).to.equal("PARENT_IS_FILE");
      expect(run(["p/q/x", "file"], ["p/q", "file"])).to.equal("PARENT_IS_FILE");
      expect(run(["e", "directory"])).to.equal("EMPTY_DIRECTORY");
      expect(run(["e", "directory"], ["e/f", "directory"], ["g", "file"])).to.equal("EMPTY_DIRECTORY");
    });
  });

  describe("PAX records", function () {
    it("reads records strictly", function () {
      expect([...parsePax(Buffer.from("12 mtime=00\n16 path=a/b.bin\n"), 0)]).to.deep.equal([
        ["mtime", "00"],
        ["path", "a/b.bin"],
      ]);
      expect([...parsePax(Buffer.alloc(0), 0)]).to.deep.equal([]);
    });
    it("refuses malformed, non-UTF-8, keyless and repeated records", async function () {
      expect(await refusalOf(() => parsePax(Buffer.from("13 mtime=00\n"), 0))).to.equal(
        "ARCHIVE_CORRUPT (PAX_MALFORMED)",
      );
      expect(await refusalOf(() => parsePax(Buffer.from("x mtime=00\n"), 0))).to.equal(
        "ARCHIVE_CORRUPT (PAX_MALFORMED)",
      );
      expect(await refusalOf(() => parsePax(Buffer.from("012 mtime=0\n"), 0))).to.equal(
        "ARCHIVE_CORRUPT (PAX_MALFORMED)",
      );
      expect(await refusalOf(() => parsePax(Buffer.from("12mtime=00\n"), 0))).to.equal(
        "ARCHIVE_CORRUPT (PAX_MALFORMED)",
      );
      expect(await refusalOf(() => parsePax(Buffer.from("12 mtime=00x"), 0))).to.equal(
        "ARCHIVE_CORRUPT (PAX_MALFORMED)",
      );
      expect(await refusalOf(() => parsePax(Buffer.from("7 =abc\n"), 0))).to.equal("ARCHIVE_CORRUPT (PAX_MALFORMED)");
      expect(await refusalOf(() => parsePax(Buffer.from("8 abcde\n"), 0))).to.equal("ARCHIVE_CORRUPT (PAX_MALFORMED)");
      const bad = Buffer.concat([Buffer.from("10 path="), Buffer.from([0xff]), Buffer.from("\n")]);
      expect(await refusalOf(() => parsePax(bad, 0))).to.equal("ARCHIVE_CORRUPT (PAX_MALFORMED)");
      expect(await refusalOf(() => parsePax(Buffer.from("12 mtime=00\n12 mtime=00\n"), 0))).to.equal(
        "ARCHIVE_UNSAFE_ENTRY (PAX_DUPLICATE_KEY)",
      );
    });
  });

  describe("the parser, on archives it must accept", function () {
    const parse = (tar: Buffer, opts: Partial<ConstructorParameters<typeof TarParser>[0]> = {}) => {
      const p = new TarParser({ limits, ...opts });
      for (let i = 0; i < tar.length; i += 333) p.feed(tar.subarray(i, i + 333)); // chunk boundaries inside headers
      p.finish();
      return p;
    };
    it("reads the safe tree: root entry, ./ names, a directory entry, a PAX mtime header", function () {
      const p = parse(safeTar());
      expect(p.members.map((m) => m.path)).to.deep.equal(SAFE_FILES.map(([n]) => n));
      expect(p.members.map((m) => m.sha256)).to.deep.equal(SAFE_FILES.map(([, d]) => sha256(d)));
      expect(p.directories).to.deep.equal(["extra"]);
    });
    it("reads GNU headers, a base-256 size, a PAX path equal to the name, a 100-byte name and zero padding", function () {
      const name = "n".repeat(100);
      const tar = tarBytes(
        [
          { name: "g.bin", data: "gnu", format: "gnu" },
          { name: "b.bin", data: "base256", format: "gnu", sizeEncoding: "base256" },
          {
            name: "p.bin",
            data: "pax",
            pax: { path: "p.bin", size: "3", "SCHILY.xattr.user.x": "y", "LIBARCHIVE.creationtime": "0" },
          },
          { name, data: "long" },
        ],
        { trailing: Buffer.alloc(10_240) },
      );
      expect(parse(tar).members.map((m) => [m.path, m.bytes])).to.deep.equal([
        ["g.bin", 3],
        ["b.bin", 7],
        ["p.bin", 3],
        [name, 4],
      ]);
    });
    it("honors a PAX size only where an octal header cannot carry it (8 GiB and more)", async function () {
      const big = { maxEntries: 10, maxTotalBytes: 1024, maxPaxBytes: 512 };
      const octal = tarBytes([{ name: "a", data: "", pax: { size: String(8 * 1024 ** 3) } }], { end: false });
      expect(await refusalOf(() => parse(octal, { limits: big }))).to.equal("ARCHIVE_LIMIT_EXCEEDED (TOTAL_BYTES)");
      const b256 = tarBytes([
        { name: "a", data: "x", format: "gnu", sizeEncoding: "base256", pax: { size: String(8 * 1024 ** 3) } },
      ]);
      expect(await refusalOf(() => parse(b256))).to.equal("ARCHIVE_UNSAFE_ENTRY (PAX_SIZE_MISMATCH)");
      const small = tarBytes([{ name: "a", data: "x", pax: { size: String(2 ** 33 - 1) } }]);
      expect(await refusalOf(() => parse(small))).to.equal("ARCHIVE_UNSAFE_ENTRY (PAX_SIZE_MISMATCH)");
      const huge = tarBytes([{ name: "a", data: "", pax: { size: "9".repeat(20) } }]);
      expect(await refusalOf(() => parse(huge))).to.equal("ARCHIVE_CORRUPT (PAX_MALFORMED)");
    });
    it("refuses a base-256 size beyond 2^53 and an oversized base-256 lead byte", async function () {
      const h = tarBytes([{ name: "a", data: "", format: "gnu", sizeEncoding: "base256", size: 0 }]);
      const over = Buffer.from(h);
      over[125] = 0x01; // 2^80: above Number.MAX_SAFE_INTEGER
      fixChecksum(over);
      expect(await refusalOf(() => parse(over))).to.equal("ARCHIVE_LIMIT_EXCEEDED (SIZE)");
      const lead = Buffer.from(h);
      lead[124] = 0x81;
      fixChecksum(lead);
      expect(await refusalOf(() => parse(lead))).to.equal("ARCHIVE_CORRUPT (HEADER_FIELD)");
    });
    it("passes every regular file's bytes, and only those, to its sink", function () {
      const seen: Record<string, Buffer[]> = {};
      const closed: string[] = [];
      const dirsSeen: string[] = [];
      parse(safeTar(), {
        openFile: (path) => ({
          write: (c) => (seen[path] ??= []).push(Buffer.from(c)),
          close: () => closed.push(path),
        }),
        onDirectory: (d) => dirsSeen.push(d),
      });
      for (const [p, d] of SAFE_FILES) expect(Buffer.concat(seen[p] ?? []).equals(d), p).to.equal(true);
      expect(closed).to.deep.equal(SAFE_FILES.map(([n]) => n));
      expect(dirsSeen).to.deep.equal(["extra"]);
    });
    it("checks a record's member list at each header, before the member's bytes", async function () {
      const expectMap = new Map(SAFE_FILES.map(([p, d]) => [p, { bytes: d.length }]));
      let opened = 0;
      const extra = tarBytes([...safeEntries(), { name: "./z.bin", data: "z" }]);
      expect(
        await refusalOf(() =>
          parse(extra, { expect: expectMap, openFile: () => ((opened += 1), { write() {}, close() {} }) }),
        ),
      ).to.equal("ARCHIVE_MEMBER_MISMATCH (UNEXPECTED_MEMBER)");
      expect(opened).to.equal(SAFE_FILES.length);
    });
  });

  describe("every hostile archive in the catalog meets its refusal", function () {
    for (const c of hostileCases()) {
      it(`${c.id} ${c.title}: ${c.expect.code} (${c.expect.reason})`, async function () {
        const auto = syntheticRecord(c.archive, SAFE_FILES);
        const record = c.record === undefined ? undefined : c.record === "auto" ? auto : c.record(auto);
        expect(await refusalOf(() => inspectArchive(write(c.archive), { anchor, record, limits: c.limits }))).to.equal(
          `${c.expect.code} (${c.expect.reason})`,
        );
      });
    }
    it("covers every path, link, ambiguity, structure and integrity class the lane names", function () {
      const ids = hostileCases().map((c) => c.id);
      expect(new Set(ids).size).to.equal(ids.length);
      for (const group of ["P", "L", "A", "S", "I"])
        expect(
          ids.some((i) => i.startsWith(group)),
          group,
        ).to.equal(true);
      expect(ids.length).to.equal(70);
    });
  });

  describe("inspection", function () {
    it("measures the safe archive with and without its record (the positive control)", async function () {
      const path = write(safeGz);
      const withRecord = await inspectArchive(path, { anchor, record: baseRecord() });
      expect(withRecord.matchesRecord).to.equal(true);
      expect(withRecord.archive).to.deep.equal({ sha256: sha256(safeGz), bytes: safeGz.length });
      expect(withRecord.members).to.deep.equal(baseRecord().members);
      const measured = await inspectArchive(path, { anchor });
      expect(measured.matchesRecord).to.equal(false);
      expect(measured.members.map((m) => m.path).sort()).to.deep.equal(baseRecord().members.map((m) => m.path));
      expect(await measureArchive(path)).to.deep.equal({ sha256: sha256(safeGz), bytes: safeGz.length });
    });

    it("refuses, without a record, an archive whose groth16_vk.bin is not the anchor's", async function () {
      const files = SAFE_FILES.map(([p, d]) => [p, p === VK_FILE ? Buffer.from("other") : d] as const);
      expect(await refusalOf(() => inspectArchive(write(gz(tarBytes(safeEntries(files)))), { anchor }))).to.equal(
        "VK_MISMATCH (VK_MISMATCH)",
      );
      for (const req of REQUIRED_MEMBERS) {
        const without = gz(tarBytes(safeEntries(SAFE_FILES.filter(([p]) => p !== req))));
        expect(await refusalOf(() => inspectArchive(write(without), { anchor })), req).to.equal(
          "ARCHIVE_MEMBER_MISMATCH (MISSING_MEMBER)",
        );
      }
    });

    it("refuses an archive that changes between authentication and parsing", async function () {
      const path = write(safeGz);
      const other = gz(tarBytes(safeEntries(), { trailing: Buffer.alloc(512) }));
      expect(other.equals(safeGz)).to.equal(false);
      expect(
        await refusalOf(() =>
          inspectArchive(path, { anchor, record: baseRecord(), afterMeasure: () => writeFileSync(path, other) }),
        ),
      ).to.equal("ARCHIVE_CHANGED_DURING_USE (REREAD)");
      const same = write(safeGz, "b.tar.gz");
      expect(
        await refusalOf(() => inspectArchive(same, { anchor, afterMeasure: () => writeFileSync(same, other) })),
      ).to.equal("ARCHIVE_CHANGED_DURING_USE (REREAD)");
    });

    it("refuses a missing archive and a directory", async function () {
      const dir = dirs.make();
      expect(await refusalOf(() => inspectArchive(join(dir, "absent.tar.gz"), { anchor }))).to.equal(
        "ARCHIVE_UNREADABLE (OPEN)",
      );
      mkdirSync(join(dir, "d.tar.gz"));
      expect(await refusalOf(() => inspectArchive(join(dir, "d.tar.gz"), { anchor }))).to.equal(
        "ARCHIVE_UNREADABLE (NOT_A_FILE)",
      );
    });

    it("validates the record before reading the archive", async function () {
      const r = baseRecord() as any;
      r.subject.programVKey = `0x${"00".repeat(32)}`;
      const dir = dirs.make();
      expect(await refusalOf(() => inspectArchive(join(dir, "absent.tar.gz"), { anchor, record: r }))).to.equal(
        "RECORD_INVALID (SUBJECT_MISMATCH)",
      );
    });
  });

  describe("member sets", function () {
    const members = clone(baseRecord().members);
    it("accepts exactly the record's members", function () {
      expect(memberSetErrors(members, members, anchor)).to.deep.equal([]);
    });
    it("names unexpected, mis-sized, mis-hashed and missing members", function () {
      const why = (actual: typeof members) =>
        memberSetErrors(actual, members, anchor).map((e) => `${e.code} (${e.reason})`);
      expect(why([...members, { path: "z", bytes: 1, sha256: "0".repeat(64) }])).to.deep.equal([
        "ARCHIVE_MEMBER_MISMATCH (UNEXPECTED_MEMBER)",
      ]);
      expect(why(members.map((m) => (m.path === "groth16_pk.bin" ? { ...m, bytes: 1 } : m)))).to.deep.equal([
        "ARCHIVE_MEMBER_MISMATCH (SIZE_MISMATCH)",
      ]);
      expect(
        why(members.map((m) => (m.path === "groth16_pk.bin" ? { ...m, sha256: "0".repeat(64) } : m))),
      ).to.deep.equal(["ARCHIVE_MEMBER_MISMATCH (DIGEST_MISMATCH)"]);
      expect(why(members.filter((m) => m.path !== "groth16_pk.bin"))).to.deep.equal([
        "ARCHIVE_MEMBER_MISMATCH (MISSING_MEMBER)",
      ]);
    });
    it("refuses a groth16_vk.bin that is not the anchor's even when the expected set names it", function () {
      const forged = members.map((m) => (m.path === VK_FILE ? { ...m, sha256: "0".repeat(64) } : m));
      expect(memberSetErrors(forged, forged, anchor).map((e) => e.code)).to.deep.equal(["VK_MISMATCH"]);
      const longer = members.map((m) => (m.path === VK_FILE ? { ...m, bytes: m.bytes + 1 } : m));
      expect(memberSetErrors(longer, longer, anchor).map((e) => e.code)).to.deep.equal(["VK_MISMATCH"]);
      expect(
        vkError(
          members.filter((m) => m.path !== VK_FILE),
          anchor,
        )?.code,
      ).to.equal("VK_MISMATCH");
      expect(vkError(members, anchor)).to.equal(null);
    });
  });
});

/** Recomputes a 512-byte tar header's checksum after a test edits it. */
function fixChecksum(h: Buffer): void {
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += h[i];
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
}
