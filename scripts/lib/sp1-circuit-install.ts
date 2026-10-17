/**
 * SP1-PA2A: installing a verified circuit archive, and re-verifying an installation (scripts/lib/sp1-circuit-archive.ts).
 *
 * The installer takes a local archive, an accepted archive record and an explicit destination root, and installs the
 * archive's members at <root>/<circuit version> (the directory SP1 reads as $SP1_GROTH16_CIRCUIT_PATH/<version>):
 *
 *   1. every archive and entry rule runs first (sha256 and length, then each entry), and nothing is written;
 *   2. the archive is extracted again into a fresh private staging directory beside the target (one filesystem, so the
 *      last step is one rename), creating each file exclusively (O_CREAT|O_EXCL) and each directory once;
 *   3. the bytes extracted must be the bytes authenticated, and the staged tree, re-read from disk, must be exactly the
 *      record's members (no link, no special file, no extra file or directory, groth16_vk.bin the anchor's);
 *   4. the tree is made read-only and renamed into place; a target that exists is refused, never merged or replaced.
 *
 * Any failure removes the staging directory and leaves the target path untouched. There is no force, merge or
 * overwrite mode. Read-only permissions are a liveness hardening, not the authority: an installation authenticates
 * bytes at installation time only, and the prove gate re-hashes every file before each proving session.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  rmSync,
  writeSync,
  type Stats,
} from "node:fs";
import { isAbsolute, join } from "node:path";

import {
  CircuitToolingError,
  DEFAULT_LIMITS,
  acceptedRecord,
  inspectArchive,
  memberSetErrors,
  refuse,
  scanArchive,
  type ArchiveAnchor,
  type ArchiveRecord,
  type FileSink,
  type Limits,
  type Measurement,
  type RefusalCode,
  type ScannedMember,
} from "./sp1-circuit-archive";

export const STAGING_PREFIX = ".staging-";
const READ_CHUNK = 4 * 1024 * 1024;
/** Never follow a final-component link, and never block on a FIFO swapped in for a file (POSIX; 0 on Windows). */
const OPEN_READ = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/** lstat, or undefined when nothing is there (any other failure throws). A link is never a directory to lstat. */
const lstatOrNull = (path: string): Stats | undefined => lstatSync(path, { throwIfNoEntry: false });

const toFs = (root: string, rel: string) => (rel === "" ? root : join(root, ...rel.split("/")));

/** The sha256 and length of the regular file at `full`, read through one descriptor that never follows a link. */
export function hashRegularFile(full: string, rel: string, code: RefusalCode): ScannedMember {
  let fd: number;
  try {
    fd = openSync(full, OPEN_READ);
  } catch (error) {
    const e = error as NodeJS.ErrnoException;
    throw refuse(code, e.code === "ELOOP" ? "LINK_IN_TREE" : "UNREADABLE", `${rel}: ${e.message}`);
  }
  try {
    if (!fstatSync(fd).isFile()) throw refuse(code, "SPECIAL_FILE_IN_TREE", `${rel} is not a regular file`);
    const hash = createHash("sha256");
    const buf = Buffer.allocUnsafe(READ_CHUNK);
    let bytes = 0;
    for (let n; (n = readSync(fd, buf, 0, READ_CHUNK, null)) > 0;) {
      hash.update(buf.subarray(0, n));
      bytes += n;
    }
    return { path: rel, bytes, sha256: hash.digest("hex") };
  } finally {
    closeSync(fd);
  }
}

/** The regular files and directories under `dir`, "/"-separated and sorted; a link or special file is refused. */
export function walkTree(dir: string, code: RefusalCode): { files: string[]; directories: string[] } {
  const files: string[] = [];
  const directories: string[] = [];
  const walk = (rel: string) => {
    const entries = readdirSync(toFs(dir, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const r = rel === "" ? e.name : `${rel}/${e.name}`;
      if (e.isSymbolicLink()) throw refuse(code, "LINK_IN_TREE", `${r} is a link`);
      if (e.isDirectory()) {
        directories.push(r);
        walk(r);
      } else if (e.isFile()) files.push(r);
      else throw refuse(code, "SPECIAL_FILE_IN_TREE", `${r} is neither a file nor a directory`);
    }
  };
  walk("");
  return { files, directories };
}

/** Every directory a record's members need: their ancestors, and nothing else. */
function ancestorsOf(members: readonly { path: string }[]): Set<string> {
  const out = new Set<string>();
  for (const m of members) {
    const parts = m.path.split("/");
    for (let i = 1; i < parts.length; i++) out.add(parts.slice(0, i).join("/"));
  }
  return out;
}

/**
 * Re-reads the tree at `dir` from disk and refuses it, under `code`, unless it is exactly the record's members: each
 * a regular file of the recorded length and sha256, no link, special file, extra file or extra directory, and a
 * groth16_vk.bin that is the anchor's whatever the record names.
 */
export function verifyTree(
  dir: string,
  record: ArchiveRecord,
  anchor: ArchiveAnchor,
  code: RefusalCode,
): ScannedMember[] {
  const { files, directories } = walkTree(dir, code);
  const needed = ancestorsOf(record.members);
  const extra = directories.find((d) => !needed.has(d));
  if (extra !== undefined) throw refuse(code, "EXTRA_DIRECTORY", `${extra} holds no record member`);
  const measured = files.map((rel) => hashRegularFile(toFs(dir, rel), rel, code));
  const errors = memberSetErrors(measured, record.members, anchor);
  if (errors.length > 0) throw refuse(code, errors[0].reason, errors.map((e) => e.message).join("; "));
  return measured;
}

/**
 * The installation SP1 would read for `record`: <circuitRoot>/<anchor's circuit version>, verified byte for byte.
 * Absent is CIRCUIT_ARCHIVE_NOT_INSTALLED; anything else that is not exactly the record is CIRCUIT_INTEGRITY_FAILED.
 */
export function verifyInstalledCircuit(
  circuitRoot: string,
  record: ArchiveRecord,
  anchor: ArchiveAnchor,
): { circuitDir: string; members: ScannedMember[] } {
  const code: RefusalCode = "CIRCUIT_INTEGRITY_FAILED";
  if (!isAbsolute(circuitRoot)) throw refuse("CIRCUIT_ROOT_INVALID", "RELATIVE", `${circuitRoot} is not absolute`);
  const root = lstatOrNull(circuitRoot);
  if (!root) throw refuse("CIRCUIT_ARCHIVE_NOT_INSTALLED", "ROOT_ABSENT", `${circuitRoot} does not exist`);
  if (!root.isDirectory()) throw refuse("CIRCUIT_ROOT_INVALID", "NOT_A_DIRECTORY", `${circuitRoot} is not a directory`);
  const circuitDir = join(circuitRoot, anchor.circuitVersion);
  const dir = lstatOrNull(circuitDir);
  if (!dir) throw refuse("CIRCUIT_ARCHIVE_NOT_INSTALLED", "CIRCUIT_ABSENT", `${circuitDir} does not exist`);
  if (!dir.isDirectory()) throw refuse(code, "NOT_A_DIRECTORY", `${circuitDir} is not a directory`);
  return { circuitDir, members: verifyTree(circuitDir, record, anchor, code) };
}

/** Applies `mode` to every file and directory under `dir` (never through a link), directories after their contents. */
function chmodTree(dir: string, fileMode: number, dirMode: number): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) chmodTree(full, fileMode, dirMode);
    else if (e.isFile()) chmodSync(full, fileMode);
  }
  chmodSync(dir, dirMode);
}

function removeStaging(staging: string): string | null {
  try {
    chmodTree(staging, 0o600, 0o700);
    rmSync(staging, { recursive: true, force: true });
    return null;
  } catch (error) {
    return (error as Error).message;
  }
}

function writeAll(fd: number, chunk: Buffer, rel: string): void {
  for (let at = 0; at < chunk.length;) {
    try {
      at += writeSync(fd, chunk, at, chunk.length - at);
    } catch (error) {
      throw refuse("INSTALL_FAILED", "WRITE", `${rel}: ${(error as Error).message}`);
    }
  }
}

export interface InstallInput {
  archivePath: string;
  record: unknown;
  anchor: ArchiveAnchor;
  destinationRoot: string;
  limits?: Limits;
  /** Test seams: let a test change the world between two steps (a swapped archive, a planted file, a racing target). */
  hooks?: {
    afterInspection?: () => Promise<void> | void;
    afterStaging?: (staging: string) => void;
    beforeRename?: () => void;
  };
}

export interface InstallResult {
  circuitDir: string;
  archive: Measurement;
  members: ScannedMember[];
}

/** Installs a verified archive at <destinationRoot>/<circuit version>, or refuses and leaves that path untouched. */
export async function installCircuitArchive(input: InstallInput): Promise<InstallResult> {
  const record = acceptedRecord(input.record, input.anchor);
  const limits = input.limits ?? DEFAULT_LIMITS;
  const root = input.destinationRoot;
  if (!isAbsolute(root)) throw refuse("INSTALL_DESTINATION_INVALID", "RELATIVE", `${root} is not absolute`);
  const rootStat = lstatOrNull(root);
  if (!rootStat) throw refuse("INSTALL_DESTINATION_INVALID", "ABSENT", `${root} does not exist`);
  if (!rootStat.isDirectory())
    throw refuse("INSTALL_DESTINATION_INVALID", "NOT_A_DIRECTORY", `${root} is not a directory`);
  const version = input.anchor.circuitVersion;
  const target = join(root, version);
  if (lstatOrNull(target))
    throw refuse("INSTALL_TARGET_EXISTS", "EXISTS", `${target} exists; it is never merged or replaced`);

  // 1. Every archive and entry rule, before anything is written.
  const inspected = await inspectArchive(input.archivePath, { anchor: input.anchor, record, limits });
  await input.hooks?.afterInspection?.();

  // 2. A fresh private staging directory beside the target.
  const staging = mkdtempSync(join(root, `.${version}${STAGING_PREFIX}`));
  let members: ScannedMember[];
  try {
    chmodSync(staging, 0o700);
    input.hooks?.afterStaging?.(staging);
    const made = new Set<string>([""]);
    const ensureDir = (rel: string) => {
      const parts = rel === "" ? [] : rel.split("/");
      for (let i = 1; i <= parts.length; i++) {
        const p = parts.slice(0, i).join("/");
        if (made.has(p)) continue;
        try {
          mkdirSync(toFs(staging, p), { mode: 0o700 });
        } catch (error) {
          throw refuse("INSTALL_FAILED", "MKDIR", `${p}: ${(error as Error).message}`);
        }
        made.add(p);
      }
    };
    const openFile = (rel: string): FileSink => {
      ensureDir(rel.split("/").slice(0, -1).join("/"));
      let fd: number;
      try {
        fd = openSync(toFs(staging, rel), "wx", 0o600);
      } catch (error) {
        const e = error as NodeJS.ErrnoException;
        throw refuse("INSTALL_FAILED", e.code === "EEXIST" ? "EXCLUSIVE_CREATE" : "OPEN", `${rel}: ${e.message}`);
      }
      return { write: (chunk) => writeAll(fd, chunk, rel), close: () => closeSync(fd) };
    };
    const extracted = await scanArchive(input.archivePath, {
      limits,
      expect: new Map(record.members.map((m) => [m.path, m])),
      openFile,
      onDirectory: ensureDir,
    });

    // 3. The bytes extracted are the bytes authenticated, and the staged tree is exactly the record.
    if (extracted.raw.sha256 !== record.archive.sha256) {
      throw refuse("ARCHIVE_CHANGED_DURING_USE", "REREAD", "the bytes extracted are not the bytes authenticated");
    }
    members = verifyTree(staging, record, input.anchor, "INSTALL_FAILED");

    // 4. Read-only, then the one rename; an existing target is refused.
    chmodTree(staging, 0o444, 0o555);
    if (lstatOrNull(target))
      throw refuse("INSTALL_TARGET_EXISTS", "APPEARED", `${target} appeared during installation`);
    input.hooks?.beforeRename?.();
    try {
      renameSync(staging, target);
    } catch (error) {
      const why = (error as Error).message;
      if (lstatOrNull(target)) throw refuse("INSTALL_TARGET_EXISTS", "APPEARED", `${target}: ${why}`);
      throw refuse("INSTALL_FAILED", "RENAME", why);
    }
  } catch (error) {
    const left = removeStaging(staging);
    if (left === null) throw error;
    const e = error instanceof CircuitToolingError ? error : refuse("INSTALL_FAILED", "UNEXPECTED", String(error));
    throw refuse(e.code, e.reason, `${e.message}; the staging directory ${staging} could not be removed: ${left}`);
  }

  // The tree renamed into place is the staged tree just verified; the prove gate re-hashes it before every session.
  return { circuitDir: target, archive: inspected.archive, members };
}
