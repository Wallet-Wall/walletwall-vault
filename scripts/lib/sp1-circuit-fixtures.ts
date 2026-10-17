/**
 * SP1-PA2A synthetic fixtures: a tar writer that can spell every hostile header form, a synthetic anchor, a safe
 * synthetic circuit tree, and the hostile-archive catalog that test/Sp1CircuitArchive.test.ts and
 * `npm run validate:sp1-circuit-tooling` (its self-test) run.
 *
 * Everything here is SYNTHETIC. The anchor names no designation, its PROGRAM_VKEY and verifier are placeholders, and
 * its groth16_vk.bin is a short text that can never have the designated VERIFIER_HASH, so no fixture archive or record
 * can satisfy the production anchor (scripts/lib/sp1-circuit-tooling.ts refuses every one, and its self-test proves
 * it). Fixture files live only under test/fixtures/sp1-proving-archives, never under evidence/.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import {
  AGREES,
  ARCHIVE_FORMAT,
  ARCHIVE_RECORD_SCHEMA,
  CIRCUIT_SYSTEM,
  PROVENANCE_ONLY,
  VK_FILE,
  type ArchiveAnchor,
  type ArchiveRecord,
  type Limits,
} from "./sp1-circuit-archive";

export const FIXTURES_DIR = "test/fixtures/sp1-proving-archives";
export const SAFE_ARCHIVE_REL = `${FIXTURES_DIR}/synthetic-safe.tar.gz`;
export const SAFE_RECORD_REL = `${FIXTURES_DIR}/synthetic-safe.record.json`;
export const SYNTHETIC_ANCHOR_REL = `${FIXTURES_DIR}/synthetic-anchor.json`;

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

// ---------------------------------------------------------------------------------------------------------------
// The tar writer
// ---------------------------------------------------------------------------------------------------------------

export interface TarSpec {
  /** The ustar name field (UTF-8), or `nameBytes` verbatim. */
  name: string;
  nameBytes?: Buffer;
  /** POSIX prefix field. */
  prefix?: string;
  /** Typeflag; "0" (regular file) by default. */
  type?: string;
  data?: Buffer | string;
  linkname?: string;
  format?: "posix" | "gnu" | "v7";
  /** The size field: a declared size other than the data's, base-256, a negative base-256, or raw text. */
  size?: number;
  sizeEncoding?: "base256" | "negative" | { raw: string };
  badChecksum?: boolean;
  /** The mode field's raw text (8 bytes); 0644, or 0755 for a directory, by default. */
  mode?: string;
  /** A PAX extended header ("x") before this entry: records, or its raw data. */
  pax?: Record<string, string> | Buffer;
}

function paxData(records: Record<string, string>): Buffer {
  return Buffer.concat(
    Object.entries(records).map(([k, v]) => {
      const body = ` ${k}=${v}\n`;
      let len = Buffer.byteLength(body) + 1;
      while (String(len).length + Buffer.byteLength(body) !== len) len = String(len).length + Buffer.byteLength(body);
      return Buffer.from(`${len}${body}`, "utf8");
    }),
  );
}

function header(s: TarSpec, size: number): Buffer {
  const h = Buffer.alloc(512);
  (s.nameBytes ?? Buffer.from(s.name, "utf8")).copy(h, 0, 0, 100);
  h.write(s.mode ?? (s.type === "5" ? "0000755\0" : "0000644\0"), 100, "latin1");
  h.write("0000000\0", 108, "latin1");
  h.write("0000000\0", 116, "latin1");
  const enc = s.sizeEncoding;
  if (enc === "base256" || enc === "negative") {
    h[124] = enc === "negative" ? 0xff : 0x80;
    let v = BigInt(size);
    for (let i = 135; i > 124; i--) {
      h[i] = enc === "negative" ? 0xff : Number(v & 0xffn);
      v >>= 8n;
    }
  } else if (enc && typeof enc === "object") h.write(enc.raw.padEnd(12, "\0").slice(0, 12), 124, "latin1");
  else h.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  h.write("00000000000\0", 136, "latin1");
  h.write(s.type ?? "0", 156, "latin1");
  if (s.linkname) h.write(s.linkname, 157, "utf8");
  const format = s.format ?? "posix";
  if (format === "posix") h.write("ustar\u000000", 257, "latin1");
  if (format === "gnu") h.write("ustar  \0", 257, "latin1");
  if (s.prefix) h.write(s.prefix, 345, "utf8");
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${(sum + (s.badChecksum ? 1 : 0)).toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return h;
}

const padded = (b: Buffer) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);

/** The tar stream for `entries`, with its two end-of-archive blocks unless `end` is false, then `trailing`. */
export function tarBytes(entries: readonly TarSpec[], opts: { end?: boolean; trailing?: Buffer } = {}): Buffer {
  const parts: Buffer[] = [];
  for (const s of entries) {
    if (s.pax) {
      const data = Buffer.isBuffer(s.pax) ? s.pax : paxData(s.pax);
      parts.push(header({ name: "./PaxHeaders/entry", type: "x" }, data.length), padded(data));
    }
    const data = s.data === undefined ? Buffer.alloc(0) : Buffer.isBuffer(s.data) ? s.data : Buffer.from(s.data);
    parts.push(header(s, s.size ?? data.length), padded(data));
  }
  if (opts.end !== false) parts.push(Buffer.alloc(1024));
  if (opts.trailing) parts.push(opts.trailing);
  return Buffer.concat(parts);
}

/** gzip with a fixed header (no name, mtime 0), so a tar stream always compresses to the same bytes on one zlib. */
export const gz = (tar: Buffer) => gzipSync(tar, { level: 9 });

// ---------------------------------------------------------------------------------------------------------------
// The synthetic anchor, tree and record
// ---------------------------------------------------------------------------------------------------------------

export const SYNTHETIC_VK = Buffer.from("SYNTHETIC groth16_vk.bin: a WalletWall test fixture, not a verifying key\n");

/** The anchor every fixture is made for: it names no designation and can never be the production anchor. */
export const SYNTHETIC_ANCHOR: ArchiveAnchor = {
  designation: "synthetic-fixture-not-a-designation",
  circuitVersion: "v6.1.0",
  programVKey: `0x${"5f".repeat(32)}`,
  verifier: {
    version: "v6.1.0",
    runtimeCodeKeccak: `0x${"5e".repeat(32)}`,
    verifierHash: `0x${sha256(SYNTHETIC_VK)}`,
  },
  verifyingKey: { sha256: `0x${sha256(SYNTHETIC_VK)}`, bytes: SYNTHETIC_VK.length },
};

/** A deterministic, non-repeating byte pattern of `n` bytes (so a one-byte change is visible to every hash). */
export function pattern(seed: string, n: number): Buffer {
  const out = Buffer.alloc(n);
  for (let i = 0, block = 0; i < n; block++) {
    const d = createHash("sha256").update(`${seed}:${block}`).digest();
    i += d.copy(out, i);
  }
  return out;
}

/** The safe synthetic circuit tree: the four files SP1 reads plus one nested member. */
export const SAFE_FILES: readonly (readonly [string, Buffer])[] = [
  ["constraints.json", Buffer.from('{"synthetic":true,"note":"WalletWall test fixture, not a circuit"}\n')],
  ["extra/README.synthetic", Buffer.from("A nested member, so installation creates a directory.\n")],
  ["groth16_circuit.bin", pattern("circuit", 1500)],
  ["groth16_pk.bin", pattern("pk", 3000)],
  [VK_FILE, SYNTHETIC_VK],
];

/** The safe archive's entries: a root "./" entry, "./"-prefixed names, a directory entry and one PAX mtime header. */
export function safeEntries(files: readonly (readonly [string, Buffer])[] = SAFE_FILES): TarSpec[] {
  const out: TarSpec[] = [{ name: "./", type: "5" }];
  for (const [path, data] of files) {
    if (path === "extra/README.synthetic") out.push({ name: "./extra/", type: "5" });
    out.push({ name: `./${path}`, data, pax: path === "groth16_pk.bin" ? { mtime: "0" } : undefined });
  }
  return out;
}

export const safeTar = () => tarBytes(safeEntries());

export function membersOf(files: readonly (readonly [string, Buffer])[]) {
  return files
    .map(([path, data]) => ({ path, bytes: data.length, sha256: sha256(data) }))
    .sort((a, b) => (a.path < b.path ? -1 : 1));
}

/** A complete synthetic record for `archive` (its gzip bytes) and `files`, consistent with `anchor`. */
export function syntheticRecord(
  archive: Buffer,
  files: readonly (readonly [string, Buffer])[],
  anchor: ArchiveAnchor = SYNTHETIC_ANCHOR,
): ArchiveRecord {
  const digest = sha256(archive);
  const at = "2026-01-01T00:00:00Z";
  return {
    schema: ARCHIVE_RECORD_SCHEMA,
    subject: {
      circuitSystem: CIRCUIT_SYSTEM,
      circuitVersion: anchor.circuitVersion,
      designation: anchor.designation,
      programVKey: anchor.programVKey,
      verifier: { ...anchor.verifier },
      verifyingKey: { file: VK_FILE, ...anchor.verifyingKey },
    },
    archive: {
      file: "synthetic-safe.tar.gz",
      format: ARCHIVE_FORMAT,
      bytes: archive.length,
      sha256: digest,
      acquiredAtUtc: at,
      sourceUrl: "https://example.invalid/synthetic-safe.tar.gz",
      sourceUrlRole: PROVENANCE_ONLY,
    },
    acquisitions: ["synthetic-host-a", "synthetic-host-b"].map((host) => ({
      host,
      observedAtUtc: at,
      bytes: archive.length,
      sha256: digest,
      agreement: AGREES,
    })),
    members: membersOf(files),
    gnark: {
      repository: "registry.invalid/walletwall/synthetic-gnark",
      tag: "synthetic",
      tagRole: PROVENANCE_ONLY,
      digest: `sha256:${sha256("synthetic gnark image")}`,
      observation: { host: "synthetic-host-a", observedAtUtc: at, method: "synthetic fixture (no docker)" },
      mirror: null,
    },
    mirrors: ["synthetic-mirror-a.invalid", "synthetic-mirror-b.invalid"].map((m) => ({
      location: `${m}/synthetic-safe.tar.gz`,
      sha256: digest,
    })),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The hostile catalog
// ---------------------------------------------------------------------------------------------------------------

export interface HostileCase {
  id: string;
  title: string;
  /** The archive's gzip bytes. */
  archive: Buffer;
  /** A record to inspect against ("auto": a consistent record for the safe files; a function edits that one). */
  record?: "auto" | ((r: ArchiveRecord) => unknown);
  limits?: Limits;
  expect: { code: string; reason: string };
}

const file = (name: string, data: Buffer | string = "x", more: Partial<TarSpec> = {}): TarSpec => ({
  name,
  data,
  ...more,
});
const withSafe = (...extra: TarSpec[]) => gz(tarBytes([...safeEntries(), ...extra]));
const only = (...entries: TarSpec[]) => gz(tarBytes(entries));
const unsafe = (reason: string) => ({ code: "ARCHIVE_UNSAFE_ENTRY", reason });
const corrupt = (reason: string) => ({ code: "ARCHIVE_CORRUPT", reason });
const member = (reason: string) => ({ code: "ARCHIVE_MEMBER_MISMATCH", reason });
const small: Limits = { maxEntries: 8, maxTotalBytes: 6000, maxPaxBytes: 512 };

/** Every hostile archive, with the refusal it must meet. Inspection stops at the first refusal. */
export function hostileCases(): HostileCase[] {
  const vkOther = Buffer.from(SYNTHETIC_VK.toString().replace("SYNTHETIC", "SUBVERTED"));
  const wrongVkFiles = SAFE_FILES.map(([p, d]) => [p, p === VK_FILE ? vkOther : d] as const);
  const wrongVk = gz(tarBytes(safeEntries(wrongVkFiles)));
  const safe = gz(safeTar());
  const flipped = Buffer.from(safe);
  flipped[flipped.length - 8] ^= 0x01; // the gzip trailer's CRC-32: same length, other bytes
  return [
    // Path attacks
    { id: "P01", title: "absolute POSIX path", archive: only(file("/etc/passwd")), expect: unsafe("ABSOLUTE_PATH") },
    { id: "P02", title: "parent traversal", archive: only(file("../../escape")), expect: unsafe("TRAVERSAL") },
    {
      id: "P03",
      title: "traversal after a component",
      archive: only(file("a/../../../escape")),
      expect: unsafe("TRAVERSAL"),
    },
    {
      id: "P04",
      title: "Windows drive with backslash",
      archive: only(file("C:\\evil")),
      expect: unsafe("BACKSLASH_IN_PATH"),
    },
    {
      id: "P05",
      title: "Windows drive with slash",
      archive: only(file("C:/evil")),
      expect: unsafe("DRIVE_QUALIFIED_PATH"),
    },
    {
      id: "P06",
      title: "UNC path",
      archive: only(file("\\\\server\\share\\evil")),
      expect: unsafe("BACKSLASH_IN_PATH"),
    },
    { id: "P07", title: "mixed separators", archive: only(file("a\\..\\b/c")), expect: unsafe("BACKSLASH_IN_PATH") },
    { id: "P08", title: "repeated separators", archive: only(file("a//b")), expect: unsafe("EMPTY_COMPONENT") },
    { id: "P09", title: "a dot component", archive: only(file("a/./b")), expect: unsafe("DOT_COMPONENT") },
    {
      id: "P10",
      title: "NUL inside the name field",
      archive: only(file("a", "x", { nameBytes: Buffer.from("a\0/../../etc/passwd") })),
      expect: unsafe("NUL_IN_PATH"),
    },
    {
      id: "P11",
      title: "NUL in a PAX path",
      archive: only(file("ab", "x", { pax: { path: "a\0b" } })),
      expect: unsafe("PAX_PATH_MISMATCH"),
    },
    {
      id: "P12",
      title: "absolute path in the POSIX prefix",
      archive: only(file("passwd", "x", { prefix: "/etc" })),
      expect: unsafe("ABSOLUTE_PATH"),
    },
    { id: "P13", title: "Windows device name", archive: only(file("nul.txt")), expect: unsafe("RESERVED_NAME") },
    {
      id: "P14",
      title: "trailing dot (dropped by Windows)",
      archive: only(file("evil.")),
      expect: unsafe("TRAILING_DOT"),
    },
    {
      id: "P15",
      title: "non-portable character",
      archive: only(file("a b")),
      expect: unsafe("NON_PORTABLE_COMPONENT"),
    },
    {
      id: "P16",
      title: "path longer than the ustar name field",
      archive: only(file(`${"n".repeat(60)}`, "x", { prefix: "p".repeat(60) })),
      expect: unsafe("PATH_TOO_LONG"),
    },
    { id: "P17", title: "a file named ./", archive: only(file("./")), expect: unsafe("EMPTY_PATH") },
    { id: "P18", title: "bare ..", archive: only(file("..")), expect: unsafe("TRAVERSAL") },
    // Link and special-type attacks
    {
      id: "L01",
      title: "symlink to an outside path",
      archive: only(file("link", "", { type: "2", linkname: "/tmp/outside" })),
      expect: unsafe("SYMLINK"),
    },
    {
      id: "L02",
      title: "symlink then a file through it",
      archive: only(file("a", "", { type: "2", linkname: "../outside" }), file("a/x")),
      expect: unsafe("SYMLINK"),
    },
    {
      id: "L03",
      title: "hard link",
      archive: only(file("h", "", { type: "1", linkname: "/etc/passwd" })),
      expect: unsafe("HARDLINK"),
    },
    { id: "L04", title: "FIFO", archive: only(file("fifo", "", { type: "6" })), expect: unsafe("FIFO") },
    {
      id: "L05",
      title: "character device",
      archive: only(file("tty", "", { type: "3" })),
      expect: unsafe("CHARACTER_DEVICE"),
    },
    { id: "L06", title: "block device", archive: only(file("sda", "", { type: "4" })), expect: unsafe("BLOCK_DEVICE") },
    {
      id: "L07",
      title: "unsupported entry type",
      archive: only(file("z", "x", { type: "Z" })),
      expect: unsafe("UNSUPPORTED_ENTRY_TYPE"),
    },
    {
      id: "L08",
      title: "contiguous file (type 7)",
      archive: only(file("c", "x", { type: "7" })),
      expect: unsafe("UNSUPPORTED_ENTRY_TYPE"),
    },
    {
      id: "L09",
      title: "GNU sparse file",
      archive: only(file("s", "x", { type: "S", format: "gnu" })),
      expect: unsafe("UNSUPPORTED_ENTRY_TYPE"),
    },
    {
      id: "L10",
      title: "PAX global header",
      archive: only(file("g", "", { type: "g" })),
      expect: unsafe("PAX_GLOBAL_HEADER"),
    },
    {
      id: "L11",
      title: "GNU long name",
      archive: only(file("././@LongLink", "../../x\0", { type: "L", format: "gnu" })),
      expect: unsafe("GNU_LONG_NAME"),
    },
    {
      id: "L12",
      title: "GNU long link",
      archive: only(file("././@LongLink", "/etc\0", { type: "K", format: "gnu" })),
      expect: unsafe("GNU_LONG_LINK"),
    },
    {
      id: "L13",
      title: "PAX linkpath on a file",
      archive: only(file("f", "x", { pax: { linkpath: "/etc/passwd" } })),
      expect: unsafe("PAX_KEY_REFUSED"),
    },
    {
      id: "L14",
      title: "PAX sparse map",
      archive: only(file("f", "x", { pax: { "GNU.sparse.major": "1" } })),
      expect: unsafe("PAX_KEY_REFUSED"),
    },
    {
      id: "L15",
      title: "pre-ustar (v7) header",
      archive: only(file("f", "x", { format: "v7" })),
      expect: unsafe("UNSUPPORTED_FORMAT"),
    },
    {
      id: "L16",
      title: "setuid mode (tar(1) as root would apply it)",
      archive: only(file("suid", "x", { mode: "0004755\0" })),
      expect: unsafe("SPECIAL_MODE_BITS"),
    },
    {
      id: "L17",
      title: "sticky directory mode",
      archive: withSafe(file("./extra2/", "", { type: "5", mode: "0001777\0" }), file("./extra2/f", "x")),
      expect: unsafe("SPECIAL_MODE_BITS"),
    },
    {
      id: "L18",
      title: "mode field not octal",
      archive: only(file("f", "x", { mode: "rwxr-xr\0" })),
      expect: corrupt("HEADER_FIELD"),
    },
    // Ambiguity
    {
      id: "A01",
      title: "duplicate file entry",
      archive: withSafe(file("./groth16_pk.bin", "x")),
      expect: unsafe("DUPLICATE_PATH"),
    },
    {
      id: "A02",
      title: "duplicate normalized path",
      archive: only(file("./a"), file("a")),
      expect: unsafe("DUPLICATE_PATH"),
    },
    {
      id: "A03",
      title: "case-only collision",
      archive: only(file("A.bin"), file("a.bin")),
      expect: unsafe("CASE_COLLISION"),
    },
    {
      id: "A04",
      title: "file then directory of one name",
      archive: only(file("d"), file("d/", "", { type: "5" })),
      expect: unsafe("FILE_DIRECTORY_COLLISION"),
    },
    { id: "A05", title: "parent is a file", archive: only(file("p"), file("p/x")), expect: unsafe("PARENT_IS_FILE") },
    {
      id: "A06",
      title: "parent is a file (child first)",
      archive: only(file("p/x"), file("p")),
      expect: unsafe("PARENT_IS_FILE"),
    },
    {
      id: "A07",
      title: "case collision on a parent",
      archive: only(file("D/x"), file("d/y")),
      expect: unsafe("CASE_COLLISION"),
    },
    {
      id: "A08",
      title: "empty directory entry",
      archive: withSafe(file("./empty/", "", { type: "5" })),
      expect: unsafe("EMPTY_DIRECTORY"),
    },
    {
      id: "A09",
      title: "directory entry with data",
      archive: only(file("d/", "data", { type: "5" })),
      expect: unsafe("DIRECTORY_WITH_DATA"),
    },
    {
      id: "A10",
      title: "PAX path naming another member",
      archive: only(file("a", "x", { pax: { path: "b" } })),
      expect: unsafe("PAX_PATH_MISMATCH"),
    },
    {
      id: "A11",
      title: "PAX size disagreeing with the header",
      archive: only(file("a", "x", { pax: { size: "2" } })),
      expect: unsafe("PAX_SIZE_MISMATCH"),
    },
    {
      id: "A12",
      title: "two PAX headers for one entry",
      archive: gz(
        Buffer.concat([
          tarBytes([file("a", "", { type: "x", data: "12 mtime=00\n" })], { end: false }),
          tarBytes([file("b", "x", { pax: { mtime: "0" } })]),
        ]),
      ),
      expect: unsafe("PAX_REPEATED"),
    },
    {
      id: "A13",
      title: "PAX header describing no entry",
      archive: gz(tarBytes([file("a", "12 mtime=00\n", { type: "x" })])),
      expect: corrupt("DANGLING_PAX"),
    },
    {
      id: "A14",
      title: "PAX key given twice",
      archive: only(file("a", "x", { pax: Buffer.from("12 mtime=00\n12 mtime=00\n") })),
      expect: unsafe("PAX_DUPLICATE_KEY"),
    },
    {
      id: "A15",
      title: "unexpected extra member",
      archive: withSafe(file("./extra.bin", "x")),
      record: "auto",
      expect: member("UNEXPECTED_MEMBER"),
    },
    {
      id: "A16",
      title: "missing required member",
      archive: gz(tarBytes(safeEntries(SAFE_FILES.filter(([p]) => p !== "groth16_circuit.bin")))),
      record: "auto",
      expect: member("MISSING_MEMBER"),
    },
    {
      id: "A17",
      title: "unexpected member refused at its header (its declared bytes are never read)",
      archive: gz(tarBytes([...safeEntries(), file("./huge.bin", "x", { size: 1 << 30 })], { end: false })),
      record: "auto",
      expect: member("UNEXPECTED_MEMBER"),
    },
    {
      id: "A18",
      title: "missing required member (no record)",
      archive: gz(tarBytes(safeEntries(SAFE_FILES.filter(([p]) => p !== "constraints.json")))),
      expect: member("MISSING_MEMBER"),
    },
    // Structure and limits
    {
      id: "S01",
      title: "header checksum",
      archive: only(file("a", "x", { badChecksum: true })),
      expect: corrupt("HEADER_CHECKSUM"),
    },
    {
      id: "S02",
      title: "no end-of-archive block",
      archive: gz(tarBytes([file("a")], { end: false })),
      expect: corrupt("TRUNCATED"),
    },
    {
      id: "S03",
      title: "data after the end",
      archive: gz(tarBytes([file("a")], { trailing: Buffer.from("hidden") })),
      expect: corrupt("TRAILING_DATA"),
    },
    { id: "S04", title: "not gzip", archive: tarBytes([file("a")]), expect: corrupt("GZIP") },
    {
      id: "S05",
      title: "truncated member",
      archive: gz(tarBytes([file("a", "x", { size: 4096 })], { end: false })),
      expect: corrupt("TRUNCATED"),
    },
    {
      id: "S06",
      title: "negative base-256 size",
      archive: only(file("a", "x", { sizeEncoding: "negative" })),
      expect: corrupt("HEADER_FIELD"),
    },
    {
      id: "S07",
      title: "size field not octal",
      archive: only(file("a", "x", { sizeEncoding: { raw: "0000000001x" } })),
      expect: corrupt("HEADER_FIELD"),
    },
    {
      id: "S08",
      title: "too many entries",
      archive: only(...Array.from({ length: 9 }, (_, i) => file(`f${i}`))),
      limits: small,
      expect: { code: "ARCHIVE_LIMIT_EXCEEDED", reason: "ENTRIES" },
    },
    {
      id: "S09",
      title: "members too large",
      archive: only(file("a", pattern("a", 7000))),
      limits: small,
      expect: { code: "ARCHIVE_LIMIT_EXCEEDED", reason: "TOTAL_BYTES" },
    },
    {
      id: "S10",
      title: "decompression bomb after the end",
      archive: gz(tarBytes([file("a")], { trailing: Buffer.alloc(2 * 1024 * 1024) })),
      limits: small,
      expect: { code: "ARCHIVE_LIMIT_EXCEEDED", reason: "DECOMPRESSED_BYTES" },
    },
    {
      id: "S11",
      title: "PAX header too large",
      archive: only(file("a", "x", { pax: { comment: "c".repeat(600) } })),
      limits: small,
      expect: { code: "ARCHIVE_LIMIT_EXCEEDED", reason: "PAX_BYTES" },
    },
    // Integrity against a record
    {
      id: "I01",
      title: "wrong archive sha256",
      archive: safe,
      record: (r) => ({
        ...r,
        archive: { ...r.archive, sha256: "0".repeat(64) },
        acquisitions: r.acquisitions.map((q) => ({ ...q, sha256: "0".repeat(64) })),
        mirrors: r.mirrors.map((m) => ({ ...m, sha256: "0".repeat(64) })),
      }),
      expect: { code: "ARCHIVE_DIGEST_MISMATCH", reason: "SHA256" },
    },
    {
      id: "I02",
      title: "wrong archive length",
      archive: safe,
      record: (r) => ({
        ...r,
        archive: { ...r.archive, bytes: r.archive.bytes + 1 },
        acquisitions: r.acquisitions.map((q) => ({ ...q, bytes: q.bytes + 1 })),
      }),
      expect: { code: "ARCHIVE_SIZE_MISMATCH", reason: "SIZE" },
    },
    {
      id: "I03",
      title: "wrong member sha256 (record edited)",
      archive: safe,
      record: (r) => ({
        ...r,
        members: r.members.map((m) => (m.path === "groth16_pk.bin" ? { ...m, sha256: "1".repeat(64) } : m)),
      }),
      expect: member("DIGEST_MISMATCH"),
    },
    {
      id: "I04",
      title: "wrong member length (refused at its header)",
      archive: safe,
      record: (r) => ({
        ...r,
        members: r.members.map((m) => (m.path === "groth16_pk.bin" ? { ...m, bytes: m.bytes + 1 } : m)),
      }),
      expect: member("SIZE_MISMATCH"),
    },
    {
      id: "I05",
      title: "wrong groth16_vk.bin, honestly recorded",
      archive: wrongVk,
      record: () => syntheticRecord(wrongVk, wrongVkFiles),
      expect: { code: "RECORD_INVALID", reason: "VK_MISMATCH" },
    },
    {
      id: "I06",
      title: "wrong groth16_vk.bin, the record claiming the established key",
      archive: wrongVk,
      record: () => {
        const r = syntheticRecord(wrongVk, wrongVkFiles);
        return {
          ...r,
          members: r.members.map((m) =>
            m.path === VK_FILE ? { ...m, sha256: SYNTHETIC_ANCHOR.verifyingKey.sha256.slice(2) } : m,
          ),
        };
      },
      expect: member("DIGEST_MISMATCH"),
    },
    {
      id: "I07",
      title: "archive correct, record's member list edited",
      archive: safe,
      record: (r) => ({
        ...r,
        members: r.members.map((m) => (m.path === "extra/README.synthetic" ? { ...m, path: "extra/README.other" } : m)),
      }),
      expect: member("UNEXPECTED_MEMBER"),
    },
    {
      id: "I08",
      title: "record correct, archive altered (same length)",
      archive: flipped,
      record: () => syntheticRecord(safe, SAFE_FILES),
      expect: { code: "ARCHIVE_DIGEST_MISMATCH", reason: "SHA256" },
    },
    {
      id: "I09",
      title: "wrong member length refused at its header (its declared bytes are never read)",
      archive: gz(
        tarBytes(
          safeEntries().map((s) => (s.name === "./groth16_pk.bin" ? { ...s, size: 1 << 30 } : s)),
          { end: false },
        ),
      ),
      record: "auto",
      expect: member("SIZE_MISMATCH"),
    },
  ];
}
