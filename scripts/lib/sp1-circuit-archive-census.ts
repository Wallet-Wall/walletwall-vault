/**
 * SP1-PA2A amendment: a read-only census of every tar entry in a circuit archive
 * (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md, "AppleDouble metadata").
 *
 * The inspector (scripts/lib/sp1-circuit-archive.ts) stops at the first entry it refuses, so it cannot say what else
 * an archive holds. This census lists every entry: header offset, type, name fields, mode, owner, time, size, PAX
 * records and the sha256 of its data, and decodes the AppleDouble structure of every entry whose name has a "._"
 * component. It also reports, per AppleDouble-shaped entry, whether its path aliases, shadows, parents or collides with
 * any other entry. It is deliberately a second, independent tar walker, not TarParser in another mode, so that the two
 * can be compared. It never writes, never extracts, and never refuses an entry; it throws only when the stream is not a
 * tar stream at all (a bad checksum, truncation, non-zero bytes after the end).
 *
 * The output is a pure function of the archive's bytes (no host, path or time), so two hosts' census files must be
 * byte-identical when their archives are.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";

export const CENSUS_SCHEMA = "walletwall.sp1-circuit-archive-census.v1";
const BLOCK = 512;
/** AppleDouble-shaped entries up to this size are buffered and decoded; larger ones are only hashed. */
const DECODE_LIMIT = 1024 * 1024;

export interface CensusPax {
  key: string;
  valueBytes: number;
  valueSha256: string;
}

export interface AppleDoubleAttribute {
  name: string;
  bytes: number;
  sha256: string;
}

export interface AppleDoubleDecode {
  magic: string;
  version: string;
  filler: string;
  entries: { id: number; offset: number; length: number }[];
  attributes: AppleDoubleAttribute[] | null;
  error: string | null;
}

export interface CensusEntry {
  index: number;
  headerOffset: number;
  typeflag: string;
  magic: string;
  name: string;
  prefix: string;
  linkname: string;
  /** The path the entry names: its PAX path when it has one, else prefix/name. */
  path: string;
  mode: string;
  uid: number;
  gid: number;
  uname: string;
  gname: string;
  mtime: number;
  size: number;
  dataSha256: string;
  /** The PAX records applied to this entry (from the "x" header before it), in their order. */
  pax: CensusPax[];
  appleDouble: AppleDoubleDecode | null;
}

export interface AppleDoubleRelation {
  path: string;
  index: number;
  typeflag: string;
  mode: string;
  size: number;
  sha256: string;
  /** The entry an AppleDouble file describes: "._x" describes "x" in the same directory; "._." the directory. */
  companion: string;
  companionPresent: boolean;
  /** The next non-PAX entry is the companion (bsdtar writes "._x" immediately before "x"). */
  companionFollows: boolean;
  /** Collisions with every other entry, under the comparisons an extractor could apply. */
  sameAsOther: string[];
  caseFoldSameAsOther: string[];
  windowsNameSameAsOther: string[];
  parentOfOther: string[];
  otherIsParent: string[];
}

export interface Census {
  schema: string;
  archive: { bytes: number; sha256: string };
  tar: { decompressedBytes: number; entries: number; endOfArchiveOffset: number; trailingZeroBytes: number };
  entries: CensusEntry[];
  appleDouble: AppleDoubleRelation[];
}

const hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const cstr = (b: Buffer) => {
  const nul = b.indexOf(0);
  return b.subarray(0, nul < 0 ? b.length : nul).toString("latin1");
};
function octal(b: Buffer, what: string, at: number): number {
  const m = /^ *([0-7]+)[ \0]*$/.exec(b.toString("latin1"));
  if (!m) throw new Error(`census: header at byte ${at}: the ${what} field is not octal`);
  return parseInt(m[1], 8);
}
function size(h: Buffer, at: number): number {
  if ((h[124] & 0x80) === 0) return octal(h.subarray(124, 136), "size", at);
  let v = 0n;
  for (let i = 125; i < 136; i++) v = (v << 8n) | BigInt(h[i]);
  if (h[124] !== 0x80 || v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`census: header at byte ${at}: size`);
  return Number(v);
}

function paxRecords(data: Buffer): { key: string; value: Buffer }[] {
  const out: { key: string; value: Buffer }[] = [];
  for (let i = 0; i < data.length;) {
    const sp = data.indexOf(0x20, i);
    const len = Number(data.toString("latin1", i, sp));
    if (sp < 0 || !Number.isSafeInteger(len) || len <= 0 || data[i + len - 1] !== 0x0a) {
      throw new Error("census: a malformed PAX record");
    }
    const rec = data.subarray(sp + 1, i + len - 1);
    const eq = rec.indexOf(0x3d);
    out.push({ key: rec.subarray(0, Math.max(eq, 0)).toString("utf8"), value: rec.subarray(eq + 1) });
    i += len;
  }
  return out;
}

/** Decodes an AppleDouble v2 file and, in its Finder Info entry, macOS's "ATTR" extended-attribute block. */
export function decodeAppleDouble(b: Buffer): AppleDoubleDecode {
  const d: AppleDoubleDecode = { magic: "", version: "", filler: "", entries: [], attributes: null, error: null };
  try {
    if (b.length < 26) throw new Error("SHORT_HEADER");
    d.magic = `0x${b.readUInt32BE(0).toString(16).padStart(8, "0")}`;
    d.version = `0x${b.readUInt32BE(4).toString(16).padStart(8, "0")}`;
    d.filler = b.subarray(8, 24).toString("latin1");
    const n = b.readUInt16BE(24);
    if (26 + 12 * n > b.length) throw new Error("ENTRY_TABLE_OVERRUN");
    for (let k = 0; k < n; k++) {
      const at = 26 + 12 * k;
      d.entries.push({ id: b.readUInt32BE(at), offset: b.readUInt32BE(at + 4), length: b.readUInt32BE(at + 8) });
    }
    for (const e of d.entries) {
      if (e.offset + e.length > b.length) throw new Error(`ENTRY_${e.id}_OVERRUN`);
    }
    const fi = d.entries.find((e) => e.id === 9);
    // Finder Info: 32 bytes, 2 bytes of padding, then the "ATTR" header when extended attributes follow.
    if (fi && fi.length > 32 + 2 + 36 && b.toString("latin1", fi.offset + 34, fi.offset + 38) === "ATTR") {
      const base = fi.offset + 34;
      const count = b.readUInt16BE(base + 34);
      const attrs: AppleDoubleAttribute[] = [];
      let at = base + 36;
      for (let k = 0; k < count; k++) {
        const off = b.readUInt32BE(at);
        const len = b.readUInt32BE(at + 4);
        const nameLen = b[at + 10];
        const name = cstr(b.subarray(at + 11, at + 11 + nameLen));
        if (off + len > b.length) throw new Error("ATTRIBUTE_OVERRUN");
        attrs.push({ name, bytes: len, sha256: hex(b.subarray(off, off + len)) });
        at = (at + 11 + nameLen + 3) & ~3;
      }
      d.attributes = attrs;
    }
  } catch (error) {
    d.error = (error as Error).message;
  }
  return d;
}

const isAppleDoubleShaped = (path: string) => path.split("/").some((p) => p.startsWith("._"));
const strip = (p: string) => (p.startsWith("./") ? p.slice(2) : p).replace(/\/+$/, "");

/** How each AppleDouble-shaped entry relates to every other entry. */
export function appleDoubleRelations(entries: readonly CensusEntry[]): AppleDoubleRelation[] {
  const real = entries.filter((e) => e.typeflag !== "x" && e.typeflag !== "g");
  const out: AppleDoubleRelation[] = [];
  const winName = (p: string) =>
    p
      .split("/")
      .map((c) => c.replace(/[. ]+$/, ""))
      .join("/")
      .toLowerCase();
  for (const e of real) {
    const path = strip(e.path);
    if (!isAppleDoubleShaped(path)) continue;
    const slash = path.lastIndexOf("/");
    const dir = slash < 0 ? "" : path.slice(0, slash);
    const base = path.slice(slash + 1);
    const target = base.slice(2);
    const companion = target === "." ? dir || "." : dir ? `${dir}/${target}` : target;
    const others = real.filter((o) => o !== e).map((o) => ({ o, p: strip(o.path) || "." }));
    const next = real[real.indexOf(e) + 1];
    const under = (a: string, b: string) => b.startsWith(`${a}/`);
    out.push({
      path,
      index: e.index,
      typeflag: e.typeflag,
      mode: e.mode,
      size: e.size,
      sha256: e.dataSha256,
      companion,
      companionPresent: others.some(({ p }) => p === companion),
      companionFollows: next !== undefined && (strip(next.path) || ".") === companion,
      sameAsOther: others.filter(({ p }) => p === path).map(({ p }) => p),
      caseFoldSameAsOther: others.filter(({ p }) => p.toLowerCase() === path.toLowerCase()).map(({ p }) => p),
      windowsNameSameAsOther: others.filter(({ p }) => winName(p) === winName(path)).map(({ p }) => p),
      parentOfOther: others.filter(({ p }) => under(path, p)).map(({ p }) => p),
      otherIsParent: others.filter(({ p }) => under(p, path)).map(({ p }) => p),
    });
  }
  return out;
}

/** The census of the archive at `path`: every entry, never refusing one. */
export async function censusArchive(path: string): Promise<Census> {
  const fh = await open(path, "r");
  const raw = createHash("sha256");
  let rawBytes = 0;
  const entries: CensusEntry[] = [];
  let state: "header" | "data" | "padding" | "end" = "header";
  const header = Buffer.alloc(BLOCK);
  let fill = 0;
  let offset = 0;
  let remaining = 0;
  let padding = 0;
  let trailingZero = 0;
  let endAt = -1;
  let current: CensusEntry | null = null;
  let hash: ReturnType<typeof createHash> | null = null;
  let keep: Buffer[] | null = null;
  let pendingPax: { key: string; value: Buffer }[] | null = null;

  const startEntry = (h: Buffer, at: number) => {
    let sum = 0;
    for (let k = 0; k < BLOCK; k++) sum += k >= 148 && k < 156 ? 0x20 : h[k];
    if (octal(h.subarray(148, 156), "checksum", at) !== sum) throw new Error(`census: header at byte ${at}: checksum`);
    const magic = h.toString("latin1", 257, 265);
    const posix = magic === "ustar\u000000";
    const typeflag = h[156] === 0 ? "0" : String.fromCharCode(h[156]);
    const name = cstr(h.subarray(0, 100));
    const prefix = posix ? cstr(h.subarray(345, 500)) : "";
    let path = prefix ? `${prefix}/${name}` : name;
    const pax = pendingPax ?? [];
    if (typeflag !== "x" && typeflag !== "g") {
      pendingPax = null;
      const p = pax.find((r) => r.key === "path");
      if (p) path = p.value.toString("utf8");
    }
    let n = size(h, at);
    const s = pax.find((r) => r.key === "size");
    if (s && typeflag !== "x" && typeflag !== "g") n = Number(s.value.toString("latin1"));
    current = {
      index: entries.length,
      headerOffset: at,
      typeflag,
      magic: Buffer.from(magic, "latin1").toString("hex"),
      name,
      prefix,
      linkname: cstr(h.subarray(157, 257)),
      path,
      mode: octal(h.subarray(100, 108), "mode", at).toString(8).padStart(4, "0"),
      uid: octal(h.subarray(108, 116), "uid", at),
      gid: octal(h.subarray(116, 124), "gid", at),
      uname: cstr(h.subarray(265, 297)),
      gname: cstr(h.subarray(297, 329)),
      mtime: octal(h.subarray(136, 148), "mtime", at),
      size: n,
      dataSha256: "",
      pax: pax.map((r) => ({ key: r.key, valueBytes: r.value.length, valueSha256: hex(r.value) })),
      appleDouble: null,
    };
    entries.push(current);
    hash = createHash("sha256");
    const decode = typeflag === "x" || typeflag === "g" || (isAppleDoubleShaped(strip(path)) && n <= DECODE_LIMIT);
    keep = decode ? [] : null;
    remaining = n;
    padding = (BLOCK - (n % BLOCK)) % BLOCK;
    if (n === 0) endEntry();
    else state = "data";
  };
  const endEntry = () => {
    const e = current as unknown as CensusEntry;
    e.dataSha256 = (hash as ReturnType<typeof createHash>).digest("hex");
    const data = keep ? Buffer.concat(keep) : null;
    if (data && (e.typeflag === "x" || e.typeflag === "g")) {
      const recs = paxRecords(data);
      if (e.typeflag === "x") pendingPax = recs;
      e.pax = recs.map((r) => ({ key: r.key, valueBytes: r.value.length, valueSha256: hex(r.value) }));
    } else if (data) e.appleDouble = decodeAppleDouble(data);
    current = null;
    hash = null;
    keep = null;
    state = padding === 0 ? "header" : "padding";
  };
  const feed = (chunk: Buffer) => {
    let i = 0;
    while (i < chunk.length) {
      if (state === "end") {
        if (chunk.subarray(i).some((b) => b !== 0)) throw new Error("census: non-zero bytes after the end");
        trailingZero += chunk.length - i;
        offset += chunk.length - i;
        return;
      }
      if (state === "header") {
        const n = Math.min(BLOCK - fill, chunk.length - i);
        chunk.copy(header, fill, i, i + n);
        fill += n;
        i += n;
        if (fill === BLOCK) {
          fill = 0;
          const at = offset;
          offset += BLOCK;
          if (header.every((b) => b === 0)) {
            state = "end";
            endAt = at;
            trailingZero += BLOCK;
          } else startEntry(header, at);
        }
        continue;
      }
      if (state === "data") {
        const n = Math.min(remaining, chunk.length - i);
        const part = chunk.subarray(i, i + n);
        hash?.update(part);
        keep?.push(Buffer.from(part));
        remaining -= n;
        offset += n;
        i += n;
        if (remaining === 0) endEntry();
        continue;
      }
      const n = Math.min(padding, chunk.length - i);
      padding -= n;
      offset += n;
      i += n;
      if (padding === 0) state = "header";
    }
  };
  try {
    await pipeline(
      fh.createReadStream({ autoClose: false }),
      new Transform({
        transform(chunk: Buffer, _enc, cb) {
          raw.update(chunk);
          rawBytes += chunk.length;
          cb(null, chunk);
        },
      }),
      createGunzip(),
      new Writable({
        write(chunk: Buffer, _enc, cb) {
          try {
            feed(chunk);
            cb();
          } catch (error) {
            cb(error as Error);
          }
        },
      }),
    );
  } finally {
    await fh.close();
  }
  // `state` is assigned inside the closures above, which narrowing does not see.
  if ((state as string) !== "end") throw new Error("census: the stream ends before an end-of-archive block");
  return {
    schema: CENSUS_SCHEMA,
    archive: { bytes: rawBytes, sha256: raw.digest("hex") },
    tar: {
      decompressedBytes: offset,
      entries: entries.length,
      endOfArchiveOffset: endAt,
      trailingZeroBytes: trailingZero,
    },
    entries,
    appleDouble: appleDoubleRelations(entries),
  };
}
