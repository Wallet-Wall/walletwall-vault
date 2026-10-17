/**
 * SP1-PA2A: the WalletWall archive path for SP1's Groth16 circuit (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md).
 *
 * The pinned prover (sp1-prover 6.3.1) installs circuit v6.1.0 itself when $SP1_GROTH16_CIRCUIT_PATH/v6.1.0 is
 * absent: it downloads v6.1.0-groth16.tar.gz, checks no digest of it, and extracts it with `tar -Pxzf`, which keeps
 * absolute member names. On WalletWall's path SP1 never gets custody of unverified bytes. An archive is authenticated
 * by its sha256 against an archive record before any of it is parsed; its tar metadata is read by the structured
 * parser below (never by tar(1), never from a listing); and only a tree whose every member the record names is
 * installed (scripts/lib/sp1-circuit-install.ts), then re-verified before each proving session
 * (scripts/lib/sp1-prove-gate.ts).
 *
 * This module holds the archive record (walletwall.sp1-proving-archive.v2) and its validator, the member-path rules,
 * the closed AppleDouble metadata policy, the streaming tar parser and the archive inspection. Nothing here downloads,
 * and no record this lane can produce is an archived artifact: production records live only in
 * evidence/zk/sp1-impl/proving-archives, which holds none.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";

/** v2 adds `metadata` (AppleDouble entries, ignored): a v1 record names no disposition for them, so none is read. */
export const ARCHIVE_RECORD_SCHEMA = "walletwall.sp1-proving-archive.v2";
export const CIRCUIT_SYSTEM = "groth16";
export const ARCHIVE_FORMAT = "tar+gzip";
export const PROVENANCE_ONLY = "PROVENANCE_ONLY";
export const AGREES = "AGREES";
export const VK_FILE = "groth16_vk.bin";
/** The files SP1's Groth16 path reads (prove_groth16.go, groth16_bn254.rs): required, never the complete set. */
export const REQUIRED_MEMBERS: readonly string[] = [
  "constraints.json",
  "groth16_circuit.bin",
  "groth16_pk.bin",
  VK_FILE,
];
/** A member path is at most this many bytes, so the ustar name field alone always carries it (no long-name forms). */
export const MAX_PATH_BYTES = 100;
export const MIN_ACQUISITIONS = 2;
export const MIN_MIRRORS = 2;

/**
 * The AppleDouble policy, closed, and derived from the census of the upstream v6.1.0 archive (both acquisitions;
 * evidence/zk/sp1-impl/observations/circuit-archive-census-*.raw.json). macOS bsdtar writes, before each entry "x",
 * an AppleDouble file "._x" holding x's extended attributes (copyfile(3)); for the archive root it writes "._.". The
 * upstream archive holds eight: "._." before the root directory entry and "._<name>" before each of its seven files,
 * every one a 163-byte regular file without a PAX header, all with one body (an AppleDouble v2 header, an empty
 * Finder Info carrying a single com.apple.provenance attribute, and an empty resource fork).
 *
 * The rule: a path with any "._" component is AppleDouble-shaped and is never a circuit member. It is accepted only as
 * ignored metadata (never extracted, never installed, never read by SP1), and only when it is exactly "._." or
 * "._<name>" with <name> a canonical root-level name that is not itself AppleDouble-shaped; it is a regular file with
 * no PAX header and one of APPLEDOUBLE_BODIES' bodies; and the very next entry (PAX headers aside) is the entry it
 * describes: the root directory for "._.", the regular file <name> otherwise. Anything else AppleDouble-shaped
 * (nested, "._._x", "._", a directory, a link, another body, an orphan, one after its companion) is refused. Other
 * dotfiles and other macOS metadata are not covered: they stay ordinary entries under every member rule.
 */
export const APPLEDOUBLE_PREFIX = "._";
export const APPLEDOUBLE_ROOT = "._.";
export const IGNORED_APPLEDOUBLE_METADATA = "IGNORED_APPLEDOUBLE_METADATA";
/** The only AppleDouble bodies accepted: the one body every metadata entry of the upstream archive has. */
export const APPLEDOUBLE_BODIES: readonly { readonly bytes: number; readonly sha256: string }[] = [
  { bytes: 163, sha256: "a8d7edcaf5cde6ccdb9d056770ecd3edadcdd9010dad9d9b61e026f4732cd0e0" },
];

/**
 * The binary provenance policy, closed, and derived from the same census. libarchive writes each extended attribute
 * twice in an entry's PAX header: LIBARCHIVE.xattr.<name> (base64, so UTF-8) and SCHILY.xattr.<name> (the raw bytes).
 * In the upstream archive every PAX header (the root's and each of the seven files') carries
 * SCHILY.xattr.com.apple.provenance with one 11-byte value that is not UTF-8 (it holds a NUL): the only PAX value
 * there that is not UTF-8, and the same value the AppleDouble body's com.apple.provenance attribute holds.
 *
 * The rule: a PAX record keyed exactly PROVENANCE_PAX_KEY is accepted only with exactly PROVENANCE_VALUE as its raw
 * value (whatever its encoding), only on one of PROVENANCE_ENTRIES (the characterized upstream entries, by path and
 * kind), at most once per entry, and, once any entry carries it, on every one of them by the end of the archive. It is
 * ignored provenance metadata: never decoded, interpreted, applied as an extended attribute or extracted; it cannot
 * name a path, a size, a link or a type (only the `path` and `size` keys can, and they stay strict UTF-8). Every other
 * key, and every other value, keeps the parser's strict UTF-8 and key rules.
 */
export const PROVENANCE_PAX_KEY = "SCHILY.xattr.com.apple.provenance";
export const IGNORED_PROVENANCE_METADATA = "IGNORED_PROVENANCE_METADATA";
/** The raw value, byte for byte; the circuit-tooling validator binds it to the sha256 both census copies measured. */
export const PROVENANCE_VALUE: Readonly<Buffer> = Buffer.from("0102002d0e23b75bfde87a", "hex");
/** The entries that carry it upstream ("" is the archive root). */
export const PROVENANCE_ENTRIES: readonly { readonly path: string; readonly kind: EntryKind }[] = [
  { path: "", kind: "directory" },
  { path: "Groth16Verifier.sol", kind: "file" },
  { path: "SP1VerifierGroth16.sol", kind: "file" },
  { path: "constraints.json", kind: "file" },
  { path: "groth16_circuit.bin", kind: "file" },
  { path: "groth16_pk.bin", kind: "file" },
  { path: "groth16_vk.bin", kind: "file" },
  { path: "groth16_witness.json", kind: "file" },
];

export interface Limits {
  maxEntries: number;
  maxTotalBytes: number;
  maxPaxBytes: number;
}
export const DEFAULT_LIMITS: Readonly<Limits> = {
  maxEntries: 10_000,
  maxTotalBytes: 64 * 1024 ** 3,
  maxPaxBytes: 65_536,
};

export const REFUSAL_CODES = [
  "RECORD_INVALID",
  "RECORD_NOT_AUTHORITATIVE",
  "ARCHIVE_UNREADABLE",
  "ARCHIVE_SIZE_MISMATCH",
  "ARCHIVE_DIGEST_MISMATCH",
  "ARCHIVE_CHANGED_DURING_USE",
  "ARCHIVE_CORRUPT",
  "ARCHIVE_LIMIT_EXCEEDED",
  "ARCHIVE_UNSAFE_ENTRY",
  "ARCHIVE_MEMBER_MISMATCH",
  "VK_MISMATCH",
  "INSTALL_DESTINATION_INVALID",
  "INSTALL_TARGET_EXISTS",
  "INSTALL_FAILED",
  "CIRCUIT_ROOT_INVALID",
  "CIRCUIT_ARCHIVE_NOT_INSTALLED",
  "CIRCUIT_INTEGRITY_FAILED",
  "ENV_REFUSED",
  "GNARK_IMAGE_NOT_PINNED",
  "GNARK_IMAGE_CONFLICT",
  "GNARK_IMAGE_NOT_LOCAL",
  "PROVE_INPUT_INVALID",
  "PROVE_HOST_UNSUPPORTED",
  "EVIDENCE_NOT_COMMITTED",
  "PROVER_SPAWN_FAILED",
  "PROVER_FAILED",
  "CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE",
  "PROOF_OUTPUT_REFUSED",
] as const;
export type RefusalCode = (typeof REFUSAL_CODES)[number];

/** A refusal: `code` says which gate refused, `reason` the rule. Both are part of the contract tests pin. */
export class CircuitToolingError extends Error {
  constructor(
    readonly code: RefusalCode,
    readonly reason: string,
    detail: string,
  ) {
    super(`${code} (${reason}): ${detail}`);
    this.name = "CircuitToolingError";
  }
}
export const refuse = (code: RefusalCode, reason: string, detail: string) =>
  new CircuitToolingError(code, reason, detail);

// ---------------------------------------------------------------------------------------------------------------
// The anchor and the record
// ---------------------------------------------------------------------------------------------------------------

/** What an archive must serve, taken from the designation, never from the archive or its record. */
export interface ArchiveAnchor {
  designation: string;
  circuitVersion: string;
  programVKey: string;
  verifier: { version: string; runtimeCodeKeccak: string; verifierHash: string };
  /** The established groth16_vk.bin: sha256 (0x-prefixed, the designated VERIFIER_HASH) and length. */
  verifyingKey: { sha256: string; bytes: number };
}

export interface ArchiveMember {
  path: string;
  bytes: number;
  sha256: string;
}

/** An AppleDouble entry the archive holds: covered by the archive's sha256 and its own, never installed. */
export interface ArchiveMetadata {
  path: string;
  bytes: number;
  sha256: string;
  disposition: typeof IGNORED_APPLEDOUBLE_METADATA;
}

export interface ArchiveRecord {
  schema: string;
  subject: {
    circuitSystem: string;
    circuitVersion: string;
    designation: string;
    programVKey: string;
    verifier: { version: string; runtimeCodeKeccak: string; verifierHash: string };
    verifyingKey: { file: string; sha256: string; bytes: number };
  };
  archive: {
    file: string;
    format: string;
    bytes: number;
    sha256: string;
    acquiredAtUtc: string;
    sourceUrl: string;
    sourceUrlRole: string;
  };
  acquisitions: { host: string; observedAtUtc: string; bytes: number; sha256: string; agreement: string }[];
  members: ArchiveMember[];
  metadata: ArchiveMetadata[];
  gnark: {
    repository: string;
    tag: string;
    tagRole: string;
    digest: string;
    observation: { host: string; observedAtUtc: string; method: string };
    mirror: { location: string; digest: string } | null;
  };
  mirrors: { location: string; sha256: string }[];
}

/** The record's fields, level by level: a record names exactly these (an unknown field is refused, not ignored). */
export const RECORD_FIELDS = {
  record: ["schema", "subject", "archive", "acquisitions", "members", "metadata", "gnark", "mirrors"],
  subject: ["circuitSystem", "circuitVersion", "designation", "programVKey", "verifier", "verifyingKey"],
  verifier: ["version", "runtimeCodeKeccak", "verifierHash"],
  verifyingKey: ["file", "sha256", "bytes"],
  archive: ["file", "format", "bytes", "sha256", "acquiredAtUtc", "sourceUrl", "sourceUrlRole"],
  acquisition: ["host", "observedAtUtc", "bytes", "sha256", "agreement"],
  member: ["path", "bytes", "sha256"],
  metadata: ["path", "bytes", "sha256", "disposition"],
  gnark: ["repository", "tag", "tagRole", "digest", "observation", "mirror"],
  gnarkObservation: ["host", "observedAtUtc", "method"],
  gnarkMirror: ["location", "digest"],
  mirror: ["location", "sha256"],
} as const;

export interface Refusal {
  reason: string;
  detail: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isObject = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const isCount = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;
const isText = (x: unknown): x is string => typeof x === "string" && x.length > 0;
function isHttps(x: unknown): boolean {
  try {
    return typeof x === "string" && new URL(x).protocol === "https:";
  } catch {
    return false;
  }
}

/** Every reason `record` is not an archive record of `anchor`'s circuit; an empty list accepts it. */
export function archiveRecordErrors(record: unknown, anchor: ArchiveAnchor): Refusal[] {
  const out: Refusal[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const exactly = (o: unknown, keys: readonly string[], where: string): o is Record<string, any> => {
    if (!isObject(o)) {
      no("SHAPE", `${where} is not an object`);
      return false;
    }
    const extra = Object.keys(o).filter((k) => !keys.includes(k));
    const missing = keys.filter((k) => !(k in o));
    if (extra.length > 0) no("UNKNOWN_FIELD", `${where} names ${extra.join(", ")}`);
    if (missing.length > 0) no("MISSING_FIELD", `${where} lacks ${missing.join(", ")}`);
    return extra.length === 0 && missing.length === 0;
  };
  if (!exactly(record, RECORD_FIELDS.record, "the record")) return out;
  const r = record as unknown as ArchiveRecord;
  if (r.schema !== ARCHIVE_RECORD_SCHEMA) no("SCHEMA", `the schema must be ${ARCHIVE_RECORD_SCHEMA}`);

  const s = r.subject;
  if (exactly(s, RECORD_FIELDS.subject, "subject")) {
    if (s.circuitSystem !== CIRCUIT_SYSTEM)
      no("CIRCUIT_SYSTEM_MISMATCH", `the circuit system must be ${CIRCUIT_SYSTEM}`);
    if (s.circuitVersion !== anchor.circuitVersion) {
      no("CIRCUIT_VERSION_MISMATCH", `circuit ${String(s.circuitVersion)} is not ${anchor.circuitVersion}`);
    }
    if (s.designation !== anchor.designation) no("SUBJECT_MISMATCH", `designation ${String(s.designation)}`);
    if (s.programVKey !== anchor.programVKey) no("SUBJECT_MISMATCH", `PROGRAM_VKEY ${String(s.programVKey)}`);
    if (exactly(s.verifier, RECORD_FIELDS.verifier, "subject.verifier")) {
      for (const k of RECORD_FIELDS.verifier) {
        if (s.verifier[k] !== anchor.verifier[k]) no("SUBJECT_MISMATCH", `verifier ${k} ${String(s.verifier[k])}`);
      }
    }
    if (exactly(s.verifyingKey, RECORD_FIELDS.verifyingKey, "subject.verifyingKey")) {
      const vk = s.verifyingKey;
      if (vk.file !== VK_FILE || vk.sha256 !== anchor.verifyingKey.sha256 || vk.bytes !== anchor.verifyingKey.bytes) {
        no("VK_MISMATCH", `the verifying key must be ${VK_FILE}, sha256 ${anchor.verifyingKey.sha256}`);
      }
    }
  }

  const a = r.archive;
  if (exactly(a, RECORD_FIELDS.archive, "archive")) {
    if (!/^[A-Za-z0-9._-]+\.tar\.gz$/.test(String(a.file))) no("ARCHIVE_FIELD", "the file is not a .tar.gz name");
    if (a.format !== ARCHIVE_FORMAT) no("ARCHIVE_FIELD", `the format must be ${ARCHIVE_FORMAT}`);
    if (!isCount(a.bytes) || a.bytes === 0) no("ARCHIVE_FIELD", "the length is not a positive byte count");
    if (!HEX64.test(String(a.sha256))) no("ARCHIVE_FIELD", "the sha256 is not 64 lowercase hex digits");
    if (!UTC.test(String(a.acquiredAtUtc))) no("ARCHIVE_FIELD", "acquiredAtUtc is not a UTC timestamp");
    if (!isHttps(a.sourceUrl)) no("ARCHIVE_FIELD", "the source URL is not https");
    if (a.sourceUrlRole !== PROVENANCE_ONLY)
      no("SOURCE_IS_AUTHORITY", `the source URL is ${PROVENANCE_ONLY}, never authority`);
  }

  if (!Array.isArray(r.acquisitions) || r.acquisitions.length < MIN_ACQUISITIONS) {
    no("ACQUISITIONS_MISSING", `at least ${MIN_ACQUISITIONS} acquisition observations are required`);
  } else {
    const hosts = new Set<string>();
    r.acquisitions.forEach((q, i) => {
      if (!exactly(q, RECORD_FIELDS.acquisition, `acquisitions[${i}]`)) return;
      if (!HOST_LABEL.test(String(q.host))) no("ACQUISITION_FIELD", `acquisitions[${i}] host is not a host label`);
      if (hosts.has(q.host)) no("ACQUISITION_NOT_INDEPENDENT", `host ${String(q.host)} is counted twice`);
      hosts.add(q.host);
      if (!UTC.test(String(q.observedAtUtc))) no("ACQUISITION_FIELD", `acquisitions[${i}] observedAtUtc`);
      if (q.agreement !== AGREES || q.sha256 !== a?.sha256 || q.bytes !== a?.bytes) {
        no("ACQUISITION_DISAGREES", `acquisitions[${i}] (${String(q.host)}) does not agree with the archive`);
      }
    });
  }

  if (!Array.isArray(r.members) || r.members.length === 0) {
    no("MEMBERS_MISSING", "the record names no members");
  } else {
    const tree = new MemberTree();
    let total = 0;
    r.members.forEach((m, i) => {
      if (!exactly(m, RECORD_FIELDS.member, `members[${i}]`)) return;
      const bad = typeof m.path === "string" ? memberPathError(m.path) : "NOT_A_STRING";
      if (bad) return no("MEMBER_PATH_INVALID", `members[${i}] ${JSON.stringify(m.path)}: ${bad}`);
      if (isAppleDoubleShaped(m.path)) {
        return no("APPLEDOUBLE_AS_MEMBER", `members[${i}] ${m.path} is AppleDouble metadata, never a circuit member`);
      }
      const clash = tree.add(m.path, "file");
      if (clash) no("MEMBER_PATH_COLLISION", `${m.path}: ${clash}`);
      if (i > 0 && !(String(r.members[i - 1]?.path) < m.path)) no("MEMBERS_NOT_SORTED", `${m.path} is out of order`);
      if (!isCount(m.bytes)) no("MEMBER_FIELD", `${m.path} has no byte count`);
      else total += m.bytes;
      if (!HEX64.test(String(m.sha256))) no("MEMBER_FIELD", `${m.path} has no sha256`);
    });
    if (total > DEFAULT_LIMITS.maxTotalBytes) no("MEMBERS_TOO_LARGE", `the members total ${total} bytes`);
    const named = new Set(r.members.map((m) => m?.path));
    for (const req of REQUIRED_MEMBERS) {
      if (!named.has(req)) no("REQUIRED_MEMBER_MISSING", `the record names no ${req}`);
    }
    const vk = r.members.find((m) => m?.path === VK_FILE);
    if (vk && (`0x${vk.sha256}` !== anchor.verifyingKey.sha256 || vk.bytes !== anchor.verifyingKey.bytes)) {
      no("VK_MISMATCH", `members name a ${VK_FILE} that is not ${anchor.verifyingKey.sha256}`);
    }
  }

  if (!Array.isArray(r.metadata)) {
    no("METADATA_MISSING", "the record has no metadata list (an empty list names none)");
  } else {
    const members = new Set((Array.isArray(r.members) ? r.members : []).map((m) => m?.path));
    r.metadata.forEach((m, i) => {
      if (!exactly(m, RECORD_FIELDS.metadata, `metadata[${i}]`)) return;
      const companion = typeof m.path === "string" ? appleDoubleCompanion(m.path) : null;
      if (companion === null) return no("METADATA_PATH_INVALID", `metadata[${i}] ${JSON.stringify(m.path)}`);
      if (companion !== "" && !members.has(companion)) {
        no("METADATA_WITHOUT_COMPANION", `${m.path} describes ${companion}, which is not a record member`);
      }
      // Strictly ascending, so no path twice; a case variant ("._A", "._a") needs colliding members to describe.
      if (i > 0 && !(String(r.metadata[i - 1]?.path) < m.path)) no("METADATA_NOT_SORTED", `${m.path} is out of order`);
      if (!APPLEDOUBLE_BODIES.some((b) => b.bytes === m.bytes && b.sha256 === m.sha256)) {
        no("METADATA_BODY_UNEXPECTED", `${m.path} is not an AppleDouble body the policy accepts`);
      }
      if (m.disposition !== IGNORED_APPLEDOUBLE_METADATA) {
        no("METADATA_DISPOSITION", `${m.path}: the disposition must be ${IGNORED_APPLEDOUBLE_METADATA}`);
      }
    });
  }

  const g = r.gnark;
  if (exactly(g, RECORD_FIELDS.gnark, "gnark")) {
    const bad = imageRefError(`${String(g.repository)}@${String(g.digest)}`);
    if (bad) no("GNARK_NOT_DIGEST_PINNED", `${String(g.repository)}@${String(g.digest)}: ${bad}`);
    if (!isText(g.tag) || g.tagRole !== PROVENANCE_ONLY) no("TAG_IS_AUTHORITY", `the tag is ${PROVENANCE_ONLY}`);
    if (exactly(g.observation, RECORD_FIELDS.gnarkObservation, "gnark.observation")) {
      const o = g.observation;
      if (!HOST_LABEL.test(String(o.host)) || !UTC.test(String(o.observedAtUtc)) || !isText(o.method)) {
        no("GNARK_FIELD", "the gnark observation is incomplete");
      }
    }
    if (g.mirror !== null && exactly(g.mirror, RECORD_FIELDS.gnarkMirror, "gnark.mirror")) {
      if (!isText(g.mirror.location) || g.mirror.digest !== g.digest)
        no("GNARK_FIELD", "the gnark mirror is another image");
    }
  }

  if (!Array.isArray(r.mirrors) || r.mirrors.length < MIN_MIRRORS) {
    no("MIRRORS_MISSING", `at least ${MIN_MIRRORS} WalletWall-controlled archive locations are required`);
  } else {
    const seen = new Set<string>();
    r.mirrors.forEach((m, i) => {
      if (!exactly(m, RECORD_FIELDS.mirror, `mirrors[${i}]`)) return;
      if (!isText(m.location) || seen.has(m.location)) no("MIRROR_FIELD", `mirrors[${i}] is not a distinct location`);
      seen.add(m.location);
      if (m.sha256 !== a?.sha256) no("MIRROR_DIGEST_MISMATCH", `mirrors[${i}] names another archive`);
    });
  }
  return out;
}

/** Throws RECORD_INVALID naming every reason, or returns the record typed. */
export function acceptedRecord(record: unknown, anchor: ArchiveAnchor): ArchiveRecord {
  const errors = archiveRecordErrors(record, anchor);
  if (errors.length > 0) {
    throw refuse("RECORD_INVALID", errors[0].reason, errors.map((e) => `${e.reason}: ${e.detail}`).join("; "));
  }
  return record as ArchiveRecord;
}

// ---------------------------------------------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------------------------------------------

const REPOSITORY = /^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+$/;

/** Why `ref` is not `registry/repository@sha256:<digest>` (no tag, fully qualified), or null. */
export function imageRefError(ref: string): string | null {
  const at = ref.indexOf("@");
  if (at < 0) return "NO_DIGEST";
  const repository = ref.slice(0, at);
  if (!/^sha256:[0-9a-f]{64}$/.test(ref.slice(at + 1))) return "MALFORMED_DIGEST";
  if (/:[^/]*$/.test(repository.slice(repository.indexOf("/") + 1))) return "TAG_AND_DIGEST";
  if (!REPOSITORY.test(repository)) return "MALFORMED_REPOSITORY";
  const host = repository.split("/")[0];
  if (!host.includes(".") && !host.includes(":") && host !== "localhost") return "NOT_FULLY_QUALIFIED";
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Member paths and the tree they form
// ---------------------------------------------------------------------------------------------------------------

/** POSIX's portable filename character set: no separator, drive, stream, NUL, space or non-ASCII form survives. */
const PORTABLE = /^[A-Za-z0-9._-]+$/;
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;

/**
 * Why `path` is not a canonical member path (relative, "/"-separated, portable on POSIX and Windows), or null.
 * Canonical means no two spellings name one destination: no "." or ".." or empty component, no backslash, drive or
 * leading "/", no trailing dot (Windows drops it) and no device name (Windows opens the device instead).
 */
export function memberPathError(path: string): string | null {
  if (path.includes("\0")) return "NUL_IN_PATH";
  if (path.includes("\\")) return "BACKSLASH_IN_PATH";
  if (/^[A-Za-z]:/.test(path)) return "DRIVE_QUALIFIED_PATH";
  if (path.startsWith("/")) return "ABSOLUTE_PATH";
  if (Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) return "PATH_TOO_LONG";
  const parts = path.split("/");
  if (parts.includes("..")) return "TRAVERSAL";
  if (parts.includes(".")) return "DOT_COMPONENT";
  if (parts.includes("")) return "EMPTY_COMPONENT";
  for (const p of parts) {
    if (!PORTABLE.test(p)) return "NON_PORTABLE_COMPONENT";
    if (p.endsWith(".")) return "TRAILING_DOT";
    if (WINDOWS_DEVICE.test(p)) return "RESERVED_NAME";
  }
  return null;
}

/** Whether any component of `path` is AppleDouble-shaped ("._" first): such a path is never a circuit member. */
export const isAppleDoubleShaped = (path: string): boolean =>
  path.split("/").some((p) => p.startsWith(APPLEDOUBLE_PREFIX));

/**
 * The entry an AppleDouble path describes under the closed policy: "" (the archive root) for "._.", <name> for
 * "._<name>" with <name> a canonical root-level name that is not itself AppleDouble-shaped; null for any other path.
 */
export function appleDoubleCompanion(path: string): string | null {
  if (path === APPLEDOUBLE_ROOT) return "";
  if (!path.startsWith(APPLEDOUBLE_PREFIX) || path.includes("/") || memberPathError(path) !== null) return null;
  const name = path.slice(APPLEDOUBLE_PREFIX.length);
  // "._" alone names nothing: memberPathError("") is EMPTY_COMPONENT.
  return isAppleDoubleShaped(name) || memberPathError(name) !== null ? null : name;
}

export type EntryKind = "file" | "directory";

interface TreeNode {
  exact: string;
  kind: EntryKind;
  explicit: boolean;
  hasFile: boolean;
}

/**
 * The tree a set of member paths forms, compared case-insensitively (as NTFS and APFS do): a path may name one entry
 * once, under one spelling, and no file may be another entry's parent. Order-independent.
 */
export class MemberTree {
  private readonly nodes = new Map<string, TreeNode>();

  /** Adds `path` (already canonical); the reason it collides, or null. */
  add(path: string, kind: EntryKind): string | null {
    const parts = path.split("/");
    const ancestors: TreeNode[] = [];
    for (let i = 1; i < parts.length; i++) {
      const prefix = parts.slice(0, i).join("/");
      let n = this.nodes.get(prefix.toLowerCase());
      if (!n) {
        n = { exact: prefix, kind: "directory", explicit: false, hasFile: false };
        this.nodes.set(prefix.toLowerCase(), n);
      } else if (n.exact !== prefix) return "CASE_COLLISION";
      else if (n.kind === "file") return "PARENT_IS_FILE";
      ancestors.push(n);
    }
    const n = this.nodes.get(path.toLowerCase());
    if (!n) this.nodes.set(path.toLowerCase(), { exact: path, kind, explicit: true, hasFile: false });
    else if (n.exact !== path) return "CASE_COLLISION";
    else if (n.kind !== kind) return kind === "file" && !n.explicit ? "PARENT_IS_FILE" : "FILE_DIRECTORY_COLLISION";
    else if (kind === "file" || n.explicit) return "DUPLICATE_PATH";
    else n.explicit = true;
    if (kind === "file") for (const a of ancestors) a.hasFile = true;
    return null;
  }

  /** The reason the finished tree is refused (a directory with no member beneath it), or null. */
  finish(): string | null {
    for (const n of this.nodes.values()) {
      if (n.kind === "directory" && !n.hasFile) return "EMPTY_DIRECTORY";
    }
    return null;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The tar parser
// ---------------------------------------------------------------------------------------------------------------

const BLOCK = 512;
/** Entry types refused by name; any type not accepted below is refused as unsupported. */
const REFUSED_TYPES: Readonly<Record<string, string>> = {
  "1": "HARDLINK",
  "2": "SYMLINK",
  "3": "CHARACTER_DEVICE",
  "4": "BLOCK_DEVICE",
  "6": "FIFO",
  g: "PAX_GLOBAL_HEADER",
  L: "GNU_LONG_NAME",
  K: "GNU_LONG_LINK",
};
/** PAX keys that carry only metadata WalletWall never applies. `path` and `size` are honored; any other is refused. */
const PAX_METADATA =
  /^(mtime|atime|ctime|uid|gid|uname|gname|comment|SCHILY\.(dev|ino|nlink|fflags)|SCHILY\.(xattr|acl)\..+|LIBARCHIVE\.xattr\..+|LIBARCHIVE\.creationtime)$/;
const OCTAL_MAX_SIZE = 0o77777777777;

const unsafe = (reason: string, detail: string) => refuse("ARCHIVE_UNSAFE_ENTRY", reason, detail);
const corrupt = (reason: string, detail: string) => refuse("ARCHIVE_CORRUPT", reason, detail);
const utf8 = new TextDecoder("utf-8", { fatal: true });

/** A NUL-terminated header field; a byte other than NUL after the terminator is an embedded NUL. */
function textField(h: Buffer, from: number, len: number, at: number): string {
  const f = h.subarray(from, from + len);
  const nul = f.indexOf(0);
  if (nul >= 0 && f.subarray(nul).some((b) => b !== 0)) {
    throw unsafe("NUL_IN_PATH", `header at byte ${at}: a name field continues after its NUL`);
  }
  return f.subarray(0, nul < 0 ? len : nul).toString("latin1");
}

function octalField(h: Buffer, from: number, len: number, what: string, at: number): number {
  const m = /^ *([0-7]+)[ \0]*$/.exec(h.subarray(from, from + len).toString("latin1"));
  if (!m) throw corrupt("HEADER_FIELD", `header at byte ${at}: the ${what} field is not octal`);
  return parseInt(m[1], 8);
}

/** The size field: octal, or GNU base-256 for members of 8 GiB and more (negative values refused). */
function sizeField(h: Buffer, at: number): { size: number; base256: boolean } {
  if ((h[124] & 0x80) === 0) return { size: octalField(h, 124, 12, "size", at), base256: false };
  if (h[124] !== 0x80) throw corrupt("HEADER_FIELD", `header at byte ${at}: a negative or oversized base-256 size`);
  let v = 0n;
  for (let i = 125; i < 136; i++) v = (v << 8n) | BigInt(h[i]);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw refuse("ARCHIVE_LIMIT_EXCEEDED", "SIZE", `header at byte ${at}`);
  return { size: Number(v), base256: true };
}

/** PAX extended-header records ("<len> <key>=<value>\n"), strictly: one record per key. */
export function parsePax(data: Buffer, at: number): Map<string, string> {
  const out = new Map<string, string>();
  for (let i = 0; i < data.length;) {
    const sp = data.indexOf(0x20, i);
    const lenText = sp < 0 ? "" : data.toString("latin1", i, sp);
    const end = i + Number(lenText);
    // A record running past the data ends on undefined, never on "\n".
    if (!/^[1-9][0-9]*$/.test(lenText) || data[end - 1] !== 0x0a) {
      throw corrupt("PAX_MALFORMED", `PAX header at byte ${at}: a malformed record`);
    }
    const rec = data.subarray(sp + 1, end - 1);
    const eq = rec.indexOf(0x3d);
    let key: string;
    let value: string;
    try {
      key = utf8.decode(rec.subarray(0, Math.max(eq, 0)));
      // The provenance value is compared as raw bytes below, never decoded; every other value is strict UTF-8.
      value = key === PROVENANCE_PAX_KEY ? "" : utf8.decode(rec.subarray(eq + 1));
    } catch {
      throw corrupt("PAX_MALFORMED", `PAX header at byte ${at}: a record is not UTF-8`);
    }
    if (eq <= 0) throw corrupt("PAX_MALFORMED", `PAX header at byte ${at}: a record has no key`);
    if (key === PROVENANCE_PAX_KEY && !rec.subarray(eq + 1).equals(PROVENANCE_VALUE)) {
      throw unsafe("PROVENANCE_VALUE_UNEXPECTED", `PAX header at byte ${at}: ${key} is not the characterized value`);
    }
    if (out.has(key)) throw unsafe("PAX_DUPLICATE_KEY", `PAX header at byte ${at}: ${key} twice`);
    out.set(key, value);
    i = end;
  }
  return out;
}

/** The member path a tar entry name denotes: one leading "./" (and a directory's trailing "/") dropped; "" is the root. */
export function entryPath(name: string, kind: EntryKind): string {
  let p = name === "." ? "" : name.startsWith("./") ? name.slice(2) : name;
  if (kind === "directory" && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

export interface FileSink {
  write(chunk: Buffer): void;
  close(): void;
}

export interface ScannedMember {
  path: string;
  bytes: number;
  sha256: string;
}

export interface ParserOptions {
  limits: Limits;
  /** The record's members: an entry it does not name, or names at another size, is refused at its header. */
  expect?: ReadonlyMap<string, { bytes: number }>;
  /** The record's metadata: an AppleDouble entry it does not name, or names at another size, likewise. */
  expectMetadata?: ReadonlyMap<string, { bytes: number; sha256: string }>;
  /** Called for every accepted regular file before any of its bytes; its sink receives them. */
  openFile?: (path: string, bytes: number) => FileSink;
  /** Called for every accepted directory entry other than the root. */
  onDirectory?: (path: string) => void;
}

type State = "header" | "data" | "padding" | "end";

/**
 * A push parser for ustar and GNU tar streams that accepts only regular files and directories under canonical paths.
 * Every refusal is thrown from `feed` or `finish`, before the refused entry's bytes reach any sink.
 */
export class TarParser {
  readonly members: ScannedMember[] = [];
  readonly directories: string[] = [];
  /** The AppleDouble entries accepted as ignored metadata: hashed, never given to a sink. */
  readonly metadata: ArchiveMetadata[] = [];
  /** The characterized entries whose PAX header carried the provenance record ("" is the root), in archive order. */
  readonly provenance: string[] = [];
  private readonly tree = new MemberTree();
  /** The entry the last AppleDouble entry describes ("" for the root): the next entry must be it. */
  private companion: string | null = null;
  private state: State = "header";
  private header = Buffer.alloc(BLOCK);
  private headerFill = 0;
  private offset = 0;
  private entries = 0;
  private fileBytes = 0;
  private decompressed = 0;
  private remaining = 0;
  private padding = 0;
  private pax: Map<string, string> | null = null;
  private paxChunks: Buffer[] | null = null;
  private file: {
    path: string;
    bytes: number;
    hash: ReturnType<typeof createHash>;
    sink: FileSink | null;
    /** For an AppleDouble entry, the bodies it may have (the record's, else the policy's); null for a member. */
    bodies: readonly { readonly bytes: number; readonly sha256: string }[] | null;
  } | null = null;

  constructor(private readonly opts: ParserOptions) {}

  feed(chunk: Buffer): void {
    this.decompressed += chunk.length;
    const l = this.opts.limits;
    // Members, plus per entry a header, its padding and at most one PAX header's data, plus 1 MiB of end padding.
    if (this.decompressed > l.maxTotalBytes + l.maxEntries * (2 * BLOCK + l.maxPaxBytes) + 1024 * 1024) {
      throw refuse("ARCHIVE_LIMIT_EXCEEDED", "DECOMPRESSED_BYTES", "the archive decompresses past every limit");
    }
    let i = 0;
    while (i < chunk.length) {
      if (this.state === "end") {
        if (chunk.subarray(i).some((b) => b !== 0)) {
          throw corrupt("TRAILING_DATA", "bytes other than zero follow the end-of-archive block");
        }
        this.offset += chunk.length - i;
        return;
      }
      if (this.state === "header") {
        const n = Math.min(BLOCK - this.headerFill, chunk.length - i);
        chunk.copy(this.header, this.headerFill, i, i + n);
        this.headerFill += n;
        i += n;
        if (this.headerFill === BLOCK) {
          this.headerFill = 0;
          this.onHeader(this.header, this.offset);
          this.offset += BLOCK;
        }
        continue;
      }
      if (this.state === "data") {
        const n = Math.min(this.remaining, chunk.length - i);
        const part = chunk.subarray(i, i + n);
        if (this.paxChunks) this.paxChunks.push(Buffer.from(part));
        else if (this.file) {
          this.file.hash.update(part);
          this.file.sink?.write(part);
        }
        this.remaining -= n;
        this.offset += n;
        i += n;
        if (this.remaining === 0) this.endData();
        continue;
      }
      const n = Math.min(this.padding, chunk.length - i);
      this.padding -= n;
      this.offset += n;
      i += n;
      if (this.padding === 0) this.state = "header";
    }
  }

  finish(): void {
    if (this.state !== "end") throw corrupt("TRUNCATED", "the archive ends before its end-of-archive block");
    const empty = this.tree.finish();
    if (empty) throw unsafe(empty, "a directory entry has no member beneath it");
  }

  private onHeader(h: Buffer, at: number): void {
    if (h.every((b) => b === 0)) {
      if (this.pax) throw corrupt("DANGLING_PAX", "a PAX header describes no entry");
      if (this.companion !== null) {
        throw unsafe(
          "APPLEDOUBLE_WITHOUT_COMPANION",
          `the archive ends before the entry an AppleDouble entry describes`,
        );
      }
      const n = this.provenance.length;
      if (n > 0 && n !== PROVENANCE_ENTRIES.length) {
        throw unsafe(
          "PROVENANCE_OCCURRENCE_MISSING",
          `${PROVENANCE_PAX_KEY} is on ${n} of the ${PROVENANCE_ENTRIES.length} entries that carry it upstream`,
        );
      }
      this.state = "end";
      return;
    }
    if (++this.entries > this.opts.limits.maxEntries) {
      throw refuse("ARCHIVE_LIMIT_EXCEEDED", "ENTRIES", `more than ${this.opts.limits.maxEntries} entries`);
    }
    let sum = 0;
    for (let k = 0; k < BLOCK; k++) sum += k >= 148 && k < 156 ? 0x20 : h[k];
    if (octalField(h, 148, 8, "checksum", at) !== sum) {
      throw corrupt("HEADER_CHECKSUM", `header at byte ${at}: checksum mismatch`);
    }
    const magic = h.toString("latin1", 257, 265);
    const posix = magic === "ustar\u000000";
    if (!posix && magic !== "ustar  \0")
      throw unsafe("UNSUPPORTED_FORMAT", `header at byte ${at}: not ustar or GNU tar`);
    // Never applied here, but an archive WalletWall accepts must be benign under tar(1) too: no setuid, setgid, sticky.
    if (octalField(h, 100, 8, "mode", at) & 0o7000) {
      throw unsafe("SPECIAL_MODE_BITS", `header at byte ${at}: setuid, setgid or sticky mode`);
    }
    const type = h[156] === 0 ? "0" : String.fromCharCode(h[156]);
    const refused = REFUSED_TYPES[type];
    if (refused) throw unsafe(refused, `header at byte ${at}: entry type ${JSON.stringify(type)}`);
    if (type === "x") return this.onPaxHeader(h, at);
    if (type !== "0" && type !== "5") {
      throw unsafe("UNSUPPORTED_ENTRY_TYPE", `header at byte ${at}: entry type ${JSON.stringify(type)}`);
    }
    const kind: EntryKind = type === "5" ? "directory" : "file";
    const name = textField(h, 0, 100, at);
    const prefix = posix ? textField(h, 345, 155, at) : "";
    const raw = prefix ? `${prefix}/${name}` : name;
    let { size, base256 } = sizeField(h, at);
    const pax = this.pax;
    this.pax = null;
    if (pax) {
      const p = pax.get("path");
      if (p !== undefined && p !== raw) throw unsafe("PAX_PATH_MISMATCH", `header at byte ${at}: ${JSON.stringify(p)}`);
      const s = pax.get("size");
      if (s !== undefined) {
        if (!/^[0-9]+$/.test(s) || !Number.isSafeInteger(Number(s))) throw corrupt("PAX_MALFORMED", `size ${s}`);
        if (Number(s) !== size && (base256 || Number(s) <= OCTAL_MAX_SIZE)) {
          throw unsafe("PAX_SIZE_MISMATCH", `header at byte ${at}: PAX size ${s}, header ${size}`);
        }
        size = Number(s);
      }
    }
    const path = entryPath(raw, kind);
    const where = `header at byte ${at}: ${JSON.stringify(raw)}`;
    if (this.companion !== null) {
      const want = this.companion;
      this.companion = null;
      if (path !== want || kind !== (want === "" ? "directory" : "file")) {
        throw unsafe(
          "APPLEDOUBLE_WITHOUT_COMPANION",
          `${where} is not the entry the AppleDouble entry before it describes`,
        );
      }
    }
    if (pax?.has(PROVENANCE_PAX_KEY)) this.onProvenance(path, kind, where);
    if (isAppleDoubleShaped(path)) return this.onAppleDouble(path, kind, size, pax !== null, where);
    if (kind === "directory") {
      if (size !== 0) throw unsafe("DIRECTORY_WITH_DATA", where);
      if (path === "") return this.startData(0);
    }
    const bad = path === "" ? "EMPTY_PATH" : memberPathError(path);
    if (bad) throw unsafe(bad, `header at byte ${at}: ${JSON.stringify(raw)}`);
    const clash = this.tree.add(path, kind);
    if (clash) throw unsafe(clash, `header at byte ${at}: ${JSON.stringify(path)}`);
    if (kind === "directory") {
      this.directories.push(path);
      this.opts.onDirectory?.(path);
      return this.startData(0);
    }
    const want = this.opts.expect;
    if (want) {
      const w = want.get(path);
      if (!w) throw refuse("ARCHIVE_MEMBER_MISMATCH", "UNEXPECTED_MEMBER", `${path} is not a record member`);
      if (w.bytes !== size) throw refuse("ARCHIVE_MEMBER_MISMATCH", "SIZE_MISMATCH", `${path}: ${size} bytes`);
    }
    this.fileBytes += size;
    if (this.fileBytes > this.opts.limits.maxTotalBytes) {
      throw refuse(
        "ARCHIVE_LIMIT_EXCEEDED",
        "TOTAL_BYTES",
        `the members exceed ${this.opts.limits.maxTotalBytes} bytes`,
      );
    }
    this.file = {
      path,
      bytes: size,
      hash: createHash("sha256"),
      sink: this.opts.openFile?.(path, size) ?? null,
      bodies: null,
    };
    this.startData(size);
  }

  /** An entry whose PAX header carries the provenance record: a characterized one, once; its value is never read. */
  private onProvenance(path: string, kind: EntryKind, where: string): void {
    if (!PROVENANCE_ENTRIES.some((e) => e.path === path && e.kind === kind)) {
      throw unsafe(
        "PROVENANCE_ON_UNCHARACTERIZED_ENTRY",
        `${where} is not an entry the upstream archive carries it on`,
      );
    }
    if (this.provenance.includes(path)) throw unsafe("PROVENANCE_REPEATED", `${where} carries it again`);
    this.provenance.push(path);
  }

  /** An AppleDouble-shaped entry: ignored metadata under the closed policy, or refused. Never a member or a sink. */
  private onAppleDouble(path: string, kind: EntryKind, size: number, hadPax: boolean, where: string): void {
    const companion = appleDoubleCompanion(path);
    if (companion === null) throw unsafe("APPLEDOUBLE_OUTSIDE_POLICY", where);
    if (kind !== "file") throw unsafe("APPLEDOUBLE_NOT_A_FILE", where);
    if (hadPax) throw unsafe("APPLEDOUBLE_WITH_PAX", `${where}: a PAX header precedes it`);
    const clash = this.tree.add(path, "file");
    if (clash) throw unsafe(clash, where);
    let bodies = APPLEDOUBLE_BODIES;
    const want = this.opts.expectMetadata;
    if (want) {
      const w = want.get(path);
      if (!w) throw refuse("ARCHIVE_MEMBER_MISMATCH", "UNEXPECTED_METADATA", `${path} is not record metadata`);
      bodies = [w];
    }
    // Refused at its header: a declared size no accepted body has is never read.
    if (!bodies.some((b) => b.bytes === size)) throw unsafe("APPLEDOUBLE_UNEXPECTED_BODY", `${where}: ${size} bytes`);
    this.companion = companion;
    this.file = { path, bytes: size, hash: createHash("sha256"), sink: null, bodies };
    this.startData(size);
  }

  private onPaxHeader(h: Buffer, at: number): void {
    if (this.pax) throw unsafe("PAX_REPEATED", `header at byte ${at}: two PAX headers for one entry`);
    const { size } = sizeField(h, at);
    if (size > this.opts.limits.maxPaxBytes)
      throw refuse("ARCHIVE_LIMIT_EXCEEDED", "PAX_BYTES", `header at byte ${at}`);
    this.paxChunks = [];
    this.pax = new Map();
    this.startData(size);
  }

  private startData(size: number): void {
    this.remaining = size;
    this.padding = (BLOCK - (size % BLOCK)) % BLOCK;
    if (size === 0) this.endData();
    else this.state = "data";
  }

  private endData(): void {
    if (this.paxChunks) {
      const records = parsePax(Buffer.concat(this.paxChunks), this.offset);
      this.paxChunks = null;
      for (const key of records.keys()) {
        if (key !== "path" && key !== "size" && !PAX_METADATA.test(key)) {
          throw unsafe("PAX_KEY_REFUSED", `PAX key ${JSON.stringify(key)}`);
        }
      }
      this.pax = records;
    } else if (this.file) {
      const f = this.file;
      this.file = null;
      const sha256 = f.hash.digest("hex");
      if (f.bodies) {
        // Its length was one of these bodies' at its header; equal digests are then equal bodies.
        if (!f.bodies.some((b) => b.sha256 === sha256)) {
          throw unsafe("APPLEDOUBLE_UNEXPECTED_BODY", `${JSON.stringify(f.path)}: sha256 ${sha256}`);
        }
        this.metadata.push({ path: f.path, bytes: f.bytes, sha256, disposition: IGNORED_APPLEDOUBLE_METADATA });
      } else {
        f.sink?.close();
        this.members.push({ path: f.path, bytes: f.bytes, sha256 });
      }
    }
    this.state = this.padding === 0 ? "header" : "padding";
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------------------------------------------

export interface Measurement {
  sha256: string;
  bytes: number;
}

/** Opens `path` as a regular file (a directory, device or FIFO is refused) and streams it through `each`. */
async function streamRegularFile(path: string, each: (chunk: Buffer) => void): Promise<Measurement> {
  let fh;
  try {
    fh = await open(path, "r");
  } catch (error) {
    throw refuse("ARCHIVE_UNREADABLE", "OPEN", `${path}: ${(error as Error).message}`);
  }
  try {
    if (!(await fh.stat()).isFile()) throw refuse("ARCHIVE_UNREADABLE", "NOT_A_FILE", `${path} is not a regular file`);
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of fh.createReadStream({ autoClose: false })) {
      hash.update(chunk as Buffer);
      bytes += (chunk as Buffer).length;
      each(chunk as Buffer);
    }
    return { sha256: hash.digest("hex"), bytes };
  } finally {
    await fh.close();
  }
}

/** The archive's sha256 and length, read without parsing a byte of it. */
export function measureArchive(path: string): Promise<Measurement> {
  return streamRegularFile(path, () => {});
}

export interface Scan {
  raw: Measurement;
  members: ScannedMember[];
  directories: string[];
  metadata: ArchiveMetadata[];
  provenance: string[];
}

/** One pass: the archive's raw bytes hashed as they are read, gunzipped and parsed; refusals are thrown. */
export async function scanArchive(path: string, opts: ParserOptions): Promise<Scan> {
  let fh;
  try {
    fh = await open(path, "r");
  } catch (error) {
    throw refuse("ARCHIVE_UNREADABLE", "OPEN", `${path}: ${(error as Error).message}`);
  }
  const parser = new TarParser(opts);
  const hash = createHash("sha256");
  let bytes = 0;
  try {
    if (!(await fh.stat()).isFile()) throw refuse("ARCHIVE_UNREADABLE", "NOT_A_FILE", `${path} is not a regular file`);
    await pipeline(
      fh.createReadStream({ autoClose: false }),
      new Transform({
        transform(chunk: Buffer, _enc, cb) {
          hash.update(chunk);
          bytes += chunk.length;
          cb(null, chunk);
        },
      }),
      createGunzip(),
      new Writable({
        write(chunk: Buffer, _enc, cb) {
          try {
            parser.feed(chunk);
            cb();
          } catch (error) {
            cb(error as Error);
          }
        },
      }),
    );
  } catch (error) {
    if (error instanceof CircuitToolingError) throw error;
    const e = error as NodeJS.ErrnoException;
    if (String(e.code).startsWith("Z_")) throw corrupt("GZIP", e.message);
    throw refuse("ARCHIVE_UNREADABLE", "READ", e.message);
  } finally {
    await fh.close();
  }
  parser.finish();
  return {
    raw: { sha256: hash.digest("hex"), bytes },
    members: parser.members,
    directories: parser.directories,
    metadata: parser.metadata,
    provenance: parser.provenance,
  };
}

/** Every way `actual` (a scanned archive or an installed tree) is not exactly the record's members. */
export function memberSetErrors(
  actual: readonly ScannedMember[],
  expected: readonly ArchiveMember[],
  anchor: ArchiveAnchor,
): CircuitToolingError[] {
  const out: CircuitToolingError[] = [];
  const want = new Map(expected.map((m) => [m.path, m]));
  const got = new Map(actual.map((m) => [m.path, m]));
  for (const a of actual) {
    const w = want.get(a.path);
    if (!w) out.push(refuse("ARCHIVE_MEMBER_MISMATCH", "UNEXPECTED_MEMBER", `${a.path} is not a record member`));
    else if (a.bytes !== w.bytes)
      out.push(refuse("ARCHIVE_MEMBER_MISMATCH", "SIZE_MISMATCH", `${a.path}: ${a.bytes} bytes`));
    else if (a.sha256 !== w.sha256)
      out.push(refuse("ARCHIVE_MEMBER_MISMATCH", "DIGEST_MISMATCH", `${a.path}: ${a.sha256}`));
  }
  for (const w of expected) {
    if (!got.has(w.path)) out.push(refuse("ARCHIVE_MEMBER_MISMATCH", "MISSING_MEMBER", `${w.path} is absent`));
  }
  const vk = vkError(actual, anchor);
  if (vk) out.push(vk);
  return out;
}

/** The refusal when `members` holds no groth16_vk.bin with the anchor's bytes, whatever any record names. */
export function vkError(members: readonly ScannedMember[], anchor: ArchiveAnchor): CircuitToolingError | null {
  const vk = members.find((m) => m.path === VK_FILE);
  if (vk && `0x${vk.sha256}` === anchor.verifyingKey.sha256 && vk.bytes === anchor.verifyingKey.bytes) return null;
  return refuse("VK_MISMATCH", "VK_MISMATCH", `${VK_FILE} is not ${anchor.verifyingKey.sha256}`);
}

export interface Inspection {
  archive: Measurement;
  members: ScannedMember[];
  directories: string[];
  /** The AppleDouble entries the archive holds, each IGNORED_APPLEDOUBLE_METADATA: never members, never installed. */
  metadata: ArchiveMetadata[];
  /** The characterized entries ("." the root) whose PAX header carries the provenance record: ignored, never applied. */
  provenance: { entry: string; key: string; disposition: typeof IGNORED_PROVENANCE_METADATA }[];
  /** True when the archive was checked against an accepted record; false for a measurement of a candidate. */
  matchesRecord: boolean;
}

/**
 * Inspects an archive offline. With a record: the record is validated against the anchor, the archive's sha256 and
 * length are checked before any byte is parsed, every entry is checked as it is parsed, the bytes parsed must be the
 * bytes authenticated, and the members and the AppleDouble metadata must be exactly the record's. Without one
 * (measuring a candidate for a future record): every entry rule and the AppleDouble policy still apply, the required
 * members must be present and groth16_vk.bin must be the anchor's. Never invokes SP1 or tar(1).
 */
export async function inspectArchive(
  path: string,
  opts: {
    anchor: ArchiveAnchor;
    record?: unknown;
    limits?: Limits;
    /** Test seam: runs between the authentication pass and the parsing pass. */
    afterMeasure?: () => Promise<void> | void;
  },
): Promise<Inspection> {
  const record = opts.record === undefined ? null : acceptedRecord(opts.record, opts.anchor);
  const first = await measureArchive(path);
  if (record) {
    if (first.bytes !== record.archive.bytes) {
      throw refuse("ARCHIVE_SIZE_MISMATCH", "SIZE", `${first.bytes} bytes, the record names ${record.archive.bytes}`);
    }
    if (first.sha256 !== record.archive.sha256) {
      throw refuse("ARCHIVE_DIGEST_MISMATCH", "SHA256", `${first.sha256}, the record names ${record.archive.sha256}`);
    }
  }
  await opts.afterMeasure?.();
  const scan = await scanArchive(path, {
    limits: opts.limits ?? DEFAULT_LIMITS,
    expect: record ? new Map(record.members.map((m) => [m.path, m])) : undefined,
    expectMetadata: record ? new Map(record.metadata.map((m) => [m.path, m])) : undefined,
  });
  if (scan.raw.sha256 !== first.sha256) {
    throw refuse("ARCHIVE_CHANGED_DURING_USE", "REREAD", "the bytes parsed are not the bytes authenticated");
  }
  if (record) {
    const errors = memberSetErrors(scan.members, record.members, opts.anchor);
    if (errors.length > 0) throw errors[0];
    // Unexpected metadata, and metadata of another body, were refused at their headers and data.
    const seen = new Set(scan.metadata.map((m) => m.path));
    const absent = record.metadata.find((m) => !seen.has(m.path));
    if (absent) throw refuse("ARCHIVE_MEMBER_MISMATCH", "MISSING_METADATA", `${absent.path} is absent`);
  } else {
    const named = new Set(scan.members.map((m) => m.path));
    const missing = REQUIRED_MEMBERS.find((p) => !named.has(p));
    if (missing) throw refuse("ARCHIVE_MEMBER_MISMATCH", "MISSING_MEMBER", `${missing} is absent`);
    const vk = vkError(scan.members, opts.anchor);
    if (vk) throw vk;
  }
  return {
    archive: first,
    members: scan.members,
    directories: scan.directories,
    metadata: scan.metadata,
    provenance: scan.provenance.map((p) => ({
      entry: p === "" ? "." : p,
      key: PROVENANCE_PAX_KEY,
      disposition: IGNORED_PROVENANCE_METADATA,
    })),
    matchesRecord: record !== null,
  };
}
