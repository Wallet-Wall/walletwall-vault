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
 * One thing here is not synthetic: APPLEDOUBLE_BODY, the 163-byte macOS AppleDouble body every metadata entry of the
 * upstream v6.1.0 archive carries. The AppleDouble policy accepts that body and no other, so an archive that exercises
 * the policy's accepting path must hold it. It is metadata (an AppleDouble header, an empty Finder Info with one
 * com.apple.provenance attribute, an empty resource fork), never circuit data.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import {
  AGREES,
  APPLEDOUBLE_ROOT,
  ARCHIVE_FORMAT,
  ARCHIVE_RECORD_SCHEMA,
  CIRCUIT_SYSTEM,
  IGNORED_APPLEDOUBLE_METADATA,
  PROVENANCE_ONLY,
  PROVENANCE_PAX_KEY,
  PROVENANCE_VALUE,
  VK_FILE,
  type ArchiveAnchor,
  type ArchiveMetadata,
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
  /** A PAX extended header ("x") before this entry: records (a Buffer value is written raw), or its raw data. */
  pax?: Record<string, string | Buffer> | Buffer;
}

/** PAX records: "<len> <key>=<value>\n", the length counting itself; a Buffer value is written byte for byte. */
export function paxData(records: Record<string, string | Buffer>): Buffer {
  return Buffer.concat(
    Object.entries(records).map(([k, v]) => {
      const body = Buffer.concat([
        Buffer.from(` ${k}=`, "utf8"),
        Buffer.isBuffer(v) ? v : Buffer.from(v, "utf8"),
        Buffer.from("\n"),
      ]);
      let len = body.length + 1;
      while (String(len).length + body.length !== len) len = String(len).length + body.length;
      return Buffer.concat([Buffer.from(String(len), "latin1"), body]);
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

/** The upstream archive's AppleDouble body (census: 163 bytes, sha256 a8d7edca...0e0), byte for byte. */
export const APPLEDOUBLE_BODY = Buffer.from(
  "00051607000200004d6163204f5320582020202020202020000200000009000000320000007100000002000000a3000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000004154545200000000000000a3000000980000000b00000000000000" +
    "000000000000000001000000980000000b000015636f6d2e6170706c652e70726f76656e616e6365000102002d0e23b75bfde87a",
  "hex",
);

/**
 * The safe tree as macOS bsdtar packs it, in the upstream archive's shape: "._." before the root directory entry,
 * "._<name>" before each root-level file (none for the nested member, as the policy accepts root-level ones only),
 * every metadata entry the observed body without a PAX header, and a PAX header on each member.
 */
export function appleDoubleEntries(files: readonly (readonly [string, Buffer])[] = SAFE_FILES): TarSpec[] {
  const out: TarSpec[] = [
    { name: APPLEDOUBLE_ROOT, data: APPLEDOUBLE_BODY, mode: "0000755\0" },
    { name: ".", type: "5", pax: { mtime: "0" } },
  ];
  for (const [path, data] of files) {
    if (path === "extra/README.synthetic") out.push({ name: "./extra/", type: "5" });
    else out.push({ name: `./._${path}`, data: APPLEDOUBLE_BODY });
    out.push({ name: `./${path}`, data, pax: { mtime: "0" } });
  }
  return out;
}

/** The record metadata of appleDoubleEntries(files), sorted as a record lists it. */
export function appleDoubleMetadata(files: readonly (readonly [string, Buffer])[] = SAFE_FILES): ArchiveMetadata[] {
  return [APPLEDOUBLE_ROOT, ...files.filter(([p]) => !p.includes("/")).map(([p]) => `._${p}`)]
    .map((path): ArchiveMetadata => ({
      path,
      bytes: APPLEDOUBLE_BODY.length,
      sha256: sha256(APPLEDOUBLE_BODY),
      disposition: IGNORED_APPLEDOUBLE_METADATA,
    }))
    .sort((a, b) => (a.path < b.path ? -1 : 1));
}

/** The upstream archive's seven files, in its order, with SYNTHETIC contents (groth16_vk.bin the synthetic key). */
export const UPSTREAM_SHAPED_FILES: readonly (readonly [string, Buffer])[] = [
  [VK_FILE, SYNTHETIC_VK],
  ["groth16_circuit.bin", pattern("circuit", 1500)],
  ["SP1VerifierGroth16.sol", Buffer.from("// SYNTHETIC SP1VerifierGroth16.sol: a WalletWall test fixture\n")],
  ["groth16_pk.bin", pattern("pk", 3000)],
  ["Groth16Verifier.sol", Buffer.from("// SYNTHETIC Groth16Verifier.sol: a WalletWall test fixture\n")],
  ["constraints.json", Buffer.from('{"synthetic":true,"note":"WalletWall test fixture, not a circuit"}\n')],
  ["groth16_witness.json", Buffer.from('{"synthetic":true,"note":"WalletWall test fixture, not a witness"}\n')],
];

/** The PAX records libarchive writes for one com.apple.provenance attribute: base64, then the raw bytes. */
export const provenancePax = (more: Record<string, string | Buffer> = {}): Record<string, string | Buffer> => ({
  ...more,
  "LIBARCHIVE.xattr.com.apple.provenance": PROVENANCE_VALUE.toString("base64").replace(/=+$/, ""),
  [PROVENANCE_PAX_KEY]: Buffer.from(PROVENANCE_VALUE),
});

/**
 * The upstream archive's shape, entry for entry: "._." then the root directory (an mtime and the provenance records in
 * its PAX header), then per file its AppleDouble entry (no PAX header) and the file (the provenance records in its PAX
 * header). Every name, type and record is the census's; every member's bytes are synthetic.
 */
export function upstreamShapedEntries(
  files: readonly (readonly [string, Buffer])[] = UPSTREAM_SHAPED_FILES,
): TarSpec[] {
  const out: TarSpec[] = [
    { name: APPLEDOUBLE_ROOT, data: APPLEDOUBLE_BODY, mode: "0000755\0" },
    { name: "./", type: "5", pax: provenancePax({ mtime: "0" }) },
  ];
  for (const [path, data] of files) {
    out.push({ name: `./._${path}`, data: APPLEDOUBLE_BODY });
    out.push({ name: `./${path}`, data, pax: provenancePax() });
  }
  return out;
}

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
  metadata: ArchiveMetadata[] = [],
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
    metadata,
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
/** An AppleDouble entry with the observed body (the one body the policy accepts). */
const ad = (name: string, more: Partial<TarSpec> = {}) => file(name, APPLEDOUBLE_BODY, more);
const vkFile = () => file("groth16_vk.bin", SYNTHETIC_VK);
const adSafe = () => gz(tarBytes(appleDoubleEntries()));
const withMetadata =
  (edit: (m: ArchiveMetadata[]) => unknown[] = (m) => m) =>
  (r: ArchiveRecord) => ({ ...r, metadata: edit(appleDoubleMetadata()) });
/** The upstream-shaped archive, its entries edited first. */
const up = (edit: (e: TarSpec[]) => TarSpec[] = (e) => e) => gz(tarBytes(edit(upstreamShapedEntries())));
const setPax = (name: string, pax: TarSpec["pax"]) => (e: TarSpec[]) =>
  e.map((s) => (s.name === name ? { ...s, pax } : s));
const provenanceAs = (v: Buffer | string) => ({ ...provenancePax(), [PROVENANCE_PAX_KEY]: v });
const binaryUnder = (key: string, more: Record<string, string | Buffer> = {}) => ({
  ...more,
  [key]: Buffer.from(PROVENANCE_VALUE),
});
/** One PAX record from raw key and value bytes (a key that is not UTF-8). */
function rawRecord(key: Buffer, value: Buffer): Buffer {
  const body = Buffer.concat([Buffer.from(" "), key, Buffer.from("="), value, Buffer.from("\n")]);
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return Buffer.concat([Buffer.from(String(len), "latin1"), body]);
}

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
    // AppleDouble metadata: "._" names never smuggle, shadow or replace a member, and only the closed policy's
    // entries are ignored (scripts/lib/sp1-circuit-archive.ts, APPLEDOUBLE_BODIES and appleDoubleCompanion)
    {
      id: "M01",
      title: "the verifying key smuggled as ._groth16_vk.bin",
      archive: only(file("._groth16_vk.bin", SYNTHETIC_VK)),
      expect: unsafe("APPLEDOUBLE_UNEXPECTED_BODY"),
    },
    {
      id: "M02",
      title: "the policy's length with another body",
      archive: only(file("._groth16_vk.bin", Buffer.alloc(APPLEDOUBLE_BODY.length)), vkFile()),
      expect: unsafe("APPLEDOUBLE_UNEXPECTED_BODY"),
    },
    {
      id: "M03",
      title: "a size no accepted body has, refused at its header (its declared bytes are never read)",
      archive: gz(tarBytes([file("._groth16_vk.bin", "x", { size: 1 << 30 })], { end: false })),
      expect: unsafe("APPLEDOUBLE_UNEXPECTED_BODY"),
    },
    {
      id: "M04",
      title: "a nested ._ name",
      archive: only(ad("extra/._README.synthetic"), file("extra/README.synthetic")),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      id: "M05",
      title: "AppleDouble of an AppleDouble name",
      archive: only(ad("._._groth16_vk.bin")),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    { id: "M06", title: "a bare ._", archive: only(ad("._")), expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY") },
    {
      id: "M07",
      title: "a trailing dot after ._ (Windows drops it)",
      archive: only(ad("._evil.")),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      id: "M08",
      title: "._.. (a traversal spelled as metadata)",
      archive: only(ad("._..")),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      id: "M09",
      title: "a non-ASCII lookalike of a member's name",
      archive: only(ad("x", { nameBytes: Buffer.from("._grоth16_vk.bin", "utf8") })),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      id: "M10",
      title: "a ._ component in the POSIX prefix",
      archive: only(file("groth16_vk.bin", SYNTHETIC_VK, { prefix: "._x" })),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      id: "M11",
      title: "a ._ name inside __MACOSX/ (zip-style metadata)",
      archive: only(ad("__MACOSX/._groth16_vk.bin")),
      expect: unsafe("APPLEDOUBLE_OUTSIDE_POLICY"),
    },
    {
      // In an archive a root-level name is at most the 100-byte ustar field (a PAX path must equal it), so only a
      // record can spell this.
      id: "M12",
      title: "the record's ._ name of 101 bytes, its 99-byte companion a member",
      archive: adSafe(),
      record: (r) => ({
        ...r,
        members: [...r.members, { path: "n".repeat(99), bytes: 1, sha256: sha256("n") }],
        metadata: [...appleDoubleMetadata(), { ...appleDoubleMetadata()[0], path: `._${"n".repeat(99)}` }],
      }),
      expect: { code: "RECORD_INVALID", reason: "METADATA_PATH_INVALID" },
    },
    {
      id: "M13",
      title: "an AppleDouble name as a directory",
      archive: only(file("._groth16_vk.bin/", "", { type: "5" }), file("._groth16_vk.bin/x")),
      expect: unsafe("APPLEDOUBLE_NOT_A_FILE"),
    },
    {
      id: "M14",
      title: "an AppleDouble symlink to the verifying key",
      archive: only(file("._groth16_vk.bin", "", { type: "2", linkname: "groth16_vk.bin" })),
      expect: unsafe("SYMLINK"),
    },
    {
      id: "M15",
      title: "an AppleDouble hard link to the verifying key",
      archive: only(vkFile(), file("._groth16_vk.bin", "", { type: "1", linkname: "groth16_vk.bin" })),
      expect: unsafe("HARDLINK"),
    },
    {
      id: "M16",
      title: "an AppleDouble entry with a setuid mode",
      archive: only(ad("._groth16_vk.bin", { mode: "0004644\0" }), vkFile()),
      expect: unsafe("SPECIAL_MODE_BITS"),
    },
    {
      id: "M17",
      title: "a PAX header before an AppleDouble entry",
      archive: only(ad("._groth16_vk.bin", { pax: { mtime: "0" } }), vkFile()),
      expect: unsafe("APPLEDOUBLE_WITH_PAX"),
    },
    {
      id: "M18",
      title: "a PAX path renaming an AppleDouble entry to the verifying key",
      archive: only(ad("._groth16_vk.bin", { pax: { path: "groth16_vk.bin" } })),
      expect: unsafe("PAX_PATH_MISMATCH"),
    },
    {
      id: "M19",
      title: "a PAX path renaming the verifying key to an AppleDouble name",
      archive: only(file("groth16_vk.bin", SYNTHETIC_VK, { pax: { path: "._groth16_vk.bin" } })),
      expect: unsafe("PAX_PATH_MISMATCH"),
    },
    {
      id: "M20",
      title: "an orphan: another member follows",
      archive: only(ad("._groth16_vk.bin"), file("constraints.json")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M21",
      title: "followed by a case variant of its companion",
      archive: only(ad("._groth16_vk.bin"), file("GROTH16_VK.BIN", SYNTHETIC_VK)),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M22",
      title: "followed by a directory of its companion's name",
      archive: only(ad("._extra"), file("extra/", "", { type: "5" }), file("extra/x")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M23",
      title: "._. followed by a file, not the root",
      archive: only(ad("._."), file("constraints.json")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M37",
      title: "._. followed by a file named ./ (the root's name, not the root directory)",
      archive: only(ad("._."), file("./")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M24",
      title: "after its companion, the archive ending",
      archive: only(vkFile(), ad("._groth16_vk.bin")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M25",
      title: "after its companion, another member following",
      archive: only(vkFile(), ad("._groth16_vk.bin"), file("constraints.json")),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "M26",
      title: "a duplicate AppleDouble entry",
      archive: only(ad("._groth16_vk.bin"), vkFile(), ad("._groth16_vk.bin")),
      expect: unsafe("DUPLICATE_PATH"),
    },
    {
      id: "M27",
      title: "a duplicate normalized ._.",
      archive: only(ad("._."), file(".", "", { type: "5" }), ad("./._.")),
      expect: unsafe("DUPLICATE_PATH"),
    },
    {
      id: "M28",
      title: "AppleDouble entries colliding by case",
      archive: only(ad("._groth16_vk.bin"), vkFile(), ad("._GROTH16_VK.BIN")),
      expect: unsafe("CASE_COLLISION"),
    },
    {
      id: "M29",
      title: "metadata the record does not name",
      archive: adSafe(),
      record: "auto",
      expect: member("UNEXPECTED_METADATA"),
    },
    {
      id: "M30",
      title: "metadata the record names, absent from the archive",
      archive: safe,
      record: withMetadata(),
      expect: member("MISSING_METADATA"),
    },
    {
      id: "M31",
      title: "the record naming an AppleDouble entry as a member",
      archive: adSafe(),
      record: (r) => ({
        ...r,
        members: [
          { path: "._groth16_vk.bin", bytes: APPLEDOUBLE_BODY.length, sha256: sha256(APPLEDOUBLE_BODY) },
          ...r.members,
        ],
        metadata: appleDoubleMetadata().filter((m) => m.path !== "._groth16_vk.bin"),
      }),
      expect: { code: "RECORD_INVALID", reason: "APPLEDOUBLE_AS_MEMBER" },
    },
    {
      id: "M32",
      title: "the record giving metadata another disposition",
      archive: adSafe(),
      record: withMetadata((m) => m.map((x) => ({ ...x, disposition: "INSTALLED" }))),
      expect: { code: "RECORD_INVALID", reason: "METADATA_DISPOSITION" },
    },
    {
      id: "M33",
      title: "the record's metadata describing no member",
      archive: adSafe(),
      record: withMetadata((m) => [...m, { ...m[0], path: "._zz.bin" }]),
      expect: { code: "RECORD_INVALID", reason: "METADATA_WITHOUT_COMPANION" },
    },
    {
      id: "M34",
      title: "the record's metadata with another body",
      archive: adSafe(),
      record: withMetadata((m) => m.map((x) => ({ ...x, sha256: "2".repeat(64) }))),
      expect: { code: "RECORD_INVALID", reason: "METADATA_BODY_UNEXPECTED" },
    },
    {
      id: "M35",
      title: "the record's metadata outside the policy (nested)",
      archive: adSafe(),
      record: withMetadata((m) => [...m, { ...m[0], path: "extra/._README.synthetic" }]),
      expect: { code: "RECORD_INVALID", reason: "METADATA_PATH_INVALID" },
    },
    {
      id: "M36",
      title: "other macOS metadata (.DS_Store) stays an ordinary entry, refused unless the record names it",
      archive: withSafe(file("./.DS_Store", "x")),
      record: "auto",
      expect: member("UNEXPECTED_MEMBER"),
    },
    // Binary provenance (SCHILY.xattr.com.apple.provenance): only the characterized value, only on the characterized
    // entries, each once and all of them; every other key and value stays strict UTF-8
    // (scripts/lib/sp1-circuit-archive.ts, PROVENANCE_VALUE and PROVENANCE_ENTRIES)
    {
      id: "X01",
      title: "the provenance key with other binary bytes",
      archive: up(setPax("./groth16_pk.bin", provenanceAs(Buffer.alloc(PROVENANCE_VALUE.length, 0xff)))),
      expect: unsafe("PROVENANCE_VALUE_UNEXPECTED"),
    },
    {
      id: "X02",
      title: "the provenance value with one byte changed",
      archive: up(
        setPax(
          "./groth16_pk.bin",
          provenanceAs(Buffer.from(PROVENANCE_VALUE.map((b, i) => (i === PROVENANCE_VALUE.length - 1 ? b ^ 1 : b)))),
        ),
      ),
      expect: unsafe("PROVENANCE_VALUE_UNEXPECTED"),
    },
    {
      id: "X03",
      title: "a UTF-8 value under the provenance key (its base64 text)",
      archive: up(setPax("./groth16_pk.bin", provenanceAs(PROVENANCE_VALUE.toString("base64")))),
      expect: unsafe("PROVENANCE_VALUE_UNEXPECTED"),
    },
    {
      id: "X04",
      title: "the provenance value with one byte more",
      archive: up(setPax("./groth16_pk.bin", provenanceAs(Buffer.concat([PROVENANCE_VALUE, Buffer.from([0x7a])])))),
      expect: unsafe("PROVENANCE_VALUE_UNEXPECTED"),
    },
    {
      id: "X05",
      title: "the provenance value with one byte less",
      archive: up(setPax("./groth16_pk.bin", provenanceAs(PROVENANCE_VALUE.subarray(0, PROVENANCE_VALUE.length - 1)))),
      expect: unsafe("PROVENANCE_VALUE_UNEXPECTED"),
    },
    {
      id: "X06",
      title: "the right bytes on an uncharacterized member",
      archive: up((e) => [...e, { name: "./extra.bin", data: "x", pax: provenancePax() }]),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X07",
      title: "the right bytes on a nested member named like a characterized one",
      archive: up((e) => [
        ...e,
        { name: "./extra/", type: "5" },
        { name: "./extra/groth16_vk.bin", data: "x", pax: provenancePax() },
      ]),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X08",
      title: "the right bytes on a case variant of a characterized name",
      archive: up((e) => [...e, { name: "./CONSTRAINTS.JSON", data: "x", pax: provenancePax() }]),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X09",
      title: "the right bytes on a directory named like a characterized file",
      archive: only(
        file("SP1VerifierGroth16.sol/", "", { type: "5", pax: provenancePax() }),
        file("SP1VerifierGroth16.sol/x"),
      ),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X10",
      title: "the right bytes on a file named ./ (the root's path, not the root directory)",
      archive: only(file("./", "x", { pax: provenancePax() })),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X11",
      title: "the right bytes on an AppleDouble entry",
      archive: up(setPax("./._groth16_vk.bin", provenancePax())),
      expect: unsafe("PROVENANCE_ON_UNCHARACTERIZED_ENTRY"),
    },
    {
      id: "X12",
      title: "an extra occurrence: the root entry repeated",
      archive: up((e) => [e[0], e[1], { name: ".", type: "5", pax: provenancePax() }, ...e.slice(2)]),
      expect: unsafe("PROVENANCE_REPEATED"),
    },
    {
      id: "X13",
      title: "an extra occurrence: a second PAX header for one entry",
      archive: gz(
        Buffer.concat([
          tarBytes([file("p", paxData(provenancePax()), { type: "x" })], { end: false }),
          tarBytes([file("groth16_vk.bin", SYNTHETIC_VK, { pax: provenancePax() })]),
        ]),
      ),
      expect: unsafe("PAX_REPEATED"),
    },
    {
      id: "X14",
      title: "a missing occurrence: one characterized file without it",
      archive: up(setPax("./groth16_witness.json", undefined)),
      expect: unsafe("PROVENANCE_OCCURRENCE_MISSING"),
    },
    {
      id: "X15",
      title: "a missing occurrence: the root without it",
      archive: up(setPax("./", { mtime: "0" })),
      expect: unsafe("PROVENANCE_OCCURRENCE_MISSING"),
    },
    {
      id: "X16",
      title: "a lone occurrence",
      archive: only(file("constraints.json", "x", { pax: provenancePax() })),
      expect: unsafe("PROVENANCE_OCCURRENCE_MISSING"),
    },
    {
      id: "X17",
      title: "a suffix lookalike key with the binary value",
      archive: up(setPax("./groth16_vk.bin", binaryUnder(`${PROVENANCE_PAX_KEY}2`))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X18",
      title: "a truncated lookalike key with the binary value",
      archive: up(setPax("./groth16_vk.bin", binaryUnder(PROVENANCE_PAX_KEY.slice(0, -1)))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X19",
      title: "a case lookalike key with the binary value",
      archive: up(setPax("./groth16_vk.bin", binaryUnder(PROVENANCE_PAX_KEY.toLowerCase()))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X20",
      title: "the LIBARCHIVE twin key with the raw bytes",
      archive: up(setPax("./groth16_vk.bin", binaryUnder("LIBARCHIVE.xattr.com.apple.provenance"))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X21",
      title: "a lookalike key with a leading space",
      archive: up(setPax("./groth16_vk.bin", binaryUnder(` ${PROVENANCE_PAX_KEY}`))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X22",
      title: "the binary value under another metadata key (comment)",
      archive: up(setPax("./groth16_vk.bin", binaryUnder("comment", provenancePax()))),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X23",
      title: "the provenance bytes as a path",
      archive: only(file("groth16_vk.bin", SYNTHETIC_VK, { pax: binaryUnder("path") })),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X24",
      title: "the provenance bytes as a size",
      archive: only(file("groth16_vk.bin", SYNTHETIC_VK, { pax: binaryUnder("size") })),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X25",
      title: "the provenance bytes as a linkpath",
      archive: only(file("groth16_vk.bin", SYNTHETIC_VK, { pax: binaryUnder("linkpath") })),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X26",
      title: "a key that is not UTF-8",
      archive: only(
        file("groth16_vk.bin", SYNTHETIC_VK, {
          pax: rawRecord(Buffer.from([...Buffer.from("SCHILY.xattr."), 0xff]), Buffer.from(PROVENANCE_VALUE)),
        }),
      ),
      expect: corrupt("PAX_MALFORMED"),
    },
    {
      id: "X27",
      title: "the provenance key twice in one PAX header",
      archive: only(
        file("groth16_vk.bin", SYNTHETIC_VK, {
          pax: Buffer.concat([paxData(provenancePax()), paxData(provenancePax())]),
        }),
      ),
      expect: unsafe("PAX_DUPLICATE_KEY"),
    },
    {
      id: "X28",
      title: "a provenance PAX header describing no entry",
      archive: gz(tarBytes([file("p", paxData(provenancePax()), { type: "x" })])),
      expect: corrupt("DANGLING_PAX"),
    },
    {
      id: "X29",
      title: "provenance in a PAX global header",
      archive: only(file("g", paxData(provenancePax()), { type: "g" })),
      expect: unsafe("PAX_GLOBAL_HEADER"),
    },
    {
      id: "X30",
      title: "a provenance record beside a renaming path record",
      archive: only(file("evil.bin", "x", { pax: provenancePax({ path: "groth16_vk.bin" }) })),
      expect: unsafe("PAX_PATH_MISMATCH"),
    },
    {
      id: "X31",
      title: "a provenance PAX header cannot stand in for an AppleDouble entry's companion",
      archive: only(ad("._groth16_vk.bin"), file("constraints.json", "x", { pax: provenancePax() })),
      expect: unsafe("APPLEDOUBLE_WITHOUT_COMPANION"),
    },
    {
      id: "X32",
      title: "the provenance record before a PAX header's other records keeps them strict",
      archive: up(setPax("./groth16_vk.bin", { ...provenancePax(), ...binaryUnder("mtime") })),
      expect: corrupt("PAX_MALFORMED"),
    },
  ];
}
