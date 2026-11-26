/**
 * Write-once output on local filesystems that honor exclusive creation and report file identities.
 *
 * "wx" atomically creates or refuses one leaf. A reader can see incomplete bytes, a set can
 * become visible incrementally, and an interrupted process can leave outputs behind. Rollback
 * on a caught failure is best-effort. Validate completed output before accepting it as evidence.
 *
 * The operator must protect the canonical parent and its ancestors from replacement or writes
 * by untrusted users throughout the operation. POSIX checks the parent owner and mode. On
 * Windows the operator must restrict the directory ACLs, and the POSIX mode is inapplicable.
 * Network filesystems and device paths are outside this contract. Canonical paths and the
 * rollback identity check do not defend against a hostile namespace.
 */
import fs, { type BigIntStats } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const CHECKOUT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

function isWithin(root: string, directory: string): boolean {
  const rel = relative(root, directory);
  return rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel);
}

function outputLeaf(path: string): string {
  const leaf = basename(path);
  const windowsStream = process.platform === "win32" && leaf.includes(":");
  if (!leaf || leaf === "." || leaf === ".." || path.endsWith(sep) || path.endsWith("/") || windowsStream) {
    throw new Error(`Output path must name a file: ${path}`);
  }
  return leaf;
}

function trustedDirectory(directory: string, checkoutRoot: string): string {
  const canonical = fs.realpathSync.native(directory);
  const stat = fs.statSync(canonical);
  if (!stat.isDirectory()) throw new Error(`Output parent is not a directory: ${directory}`);

  if (isWithin(resolve(checkoutRoot, "evidence"), directory)) {
    const expected = resolve(fs.realpathSync.native(checkoutRoot), relative(checkoutRoot, directory));
    if (relative(expected, canonical) !== "") {
      throw new Error(`Output parent resolves outside its expected evidence directory: ${directory}`);
    }
  }

  const uid = process.geteuid?.();
  if (uid !== undefined && ((stat.uid !== uid && stat.uid !== 0) || (stat.mode & 0o022) !== 0)) {
    throw new Error(
      `Output parent must be owned by the operator or root and not group- or world-writable: ${directory}`,
    );
  }
  return canonical;
}

/** Makes a missing evidence directory only after checking the nearest existing ancestor. */
export function createEvidenceOutputDirectory(directory: string, checkoutRoot = CHECKOUT_ROOT): void {
  const root = resolve(checkoutRoot);
  const output = resolve(directory);
  if (!isWithin(resolve(root, "evidence"), output)) throw new Error(`Output parent is outside evidence: ${directory}`);

  let ancestor = output;
  while (!fs.lstatSync(ancestor, { throwIfNoEntry: false })) {
    const parent = dirname(ancestor);
    if (parent === ancestor) throw new Error(`No existing output ancestor: ${directory}`);
    ancestor = parent;
  }

  const canonical = trustedDirectory(ancestor, root);
  const expected = resolve(fs.realpathSync.native(root), relative(root, ancestor));
  if (relative(expected, canonical) !== "") {
    throw new Error(`Output ancestor resolves outside its expected evidence directory: ${ancestor}`);
  }
  fs.mkdirSync(resolve(canonical, relative(ancestor, output)), { recursive: true, mode: 0o755 });
}

/** Creates an evidence file and its directories under the same checkout root. */
export function writeNewEvidenceFile(path: string, data: string, what: string, checkoutRoot: string): void {
  createEvidenceOutputDirectory(dirname(path), checkoutRoot);
  writeNewFiles([[path, data]], what, checkoutRoot);
}

function sameRegularFile(entry: BigIntStats | undefined, opened: BigIntStats): boolean {
  return entry?.isFile() === true && opened.ino !== 0n && entry.dev === opened.dev && entry.ino === opened.ino;
}

/**
 * Legacy receipt rewrite on a trusted, stable local filesystem that reports file identities.
 * Windows has no portable O_NOFOLLOW through Node. It relies on the leaf checks and descriptor
 * identity comparison, and requires restricted ACLs on the directory and its ancestors.
 * Path checks cannot guarantee race-free containment in a hostile namespace on any platform.
 */
export function rewriteEvidenceFile(path: string, data: string, checkoutRoot: string): void {
  const leaf = outputLeaf(path);
  const root = resolve(checkoutRoot);
  const parent = resolve(dirname(path));
  createEvidenceOutputDirectory(parent, root);
  const canonical = resolve(trustedDirectory(parent, root), leaf);
  const previous = fs.lstatSync(canonical, { bigint: true, throwIfNoEntry: false });
  if (previous && !previous.isFile()) throw new Error(`Output is not a regular file: ${path}`);

  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
  const leafFlags = process.platform === "win32" ? 0 : (O_NOFOLLOW ?? 0) | (O_NONBLOCK ?? 0);
  const flags = O_WRONLY | leafFlags | (previous ? 0 : O_CREAT | O_EXCL);
  const fd = fs.openSync(canonical, flags, 0o666);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(canonical, { bigint: true, throwIfNoEntry: false });
    if (!opened.isFile() || !sameRegularFile(current, opened) || (previous && !sameRegularFile(previous, opened))) {
      throw new Error(`Output changed or could not be verified before rewriting: ${path}`);
    }
    fs.ftruncateSync(fd, 0);
    fs.writeFileSync(fd, data);
  } finally {
    fs.closeSync(fd);
  }
}

interface CreatedFile {
  path: string;
  identity?: BigIntStats;
}

/**
 * Creates every [path, data] with the existing serializers and order. Caller-selected paths
 * may use trusted parent aliases. Paths under checkout evidence keep their exact relative parent.
 * Use a private directory and umask 077 (or a private Windows ACL) for sensitive observations.
 */
export function writeNewFiles(
  files: readonly (readonly [path: string, data: string])[],
  what: string,
  checkoutRoot = CHECKOUT_ROOT,
): void {
  const root = resolve(checkoutRoot);
  const destinations = files.map(([path, data]) => {
    const leaf = outputLeaf(path);
    const parent = trustedDirectory(dirname(path), root);
    // Keep the caller's path for existing-file diagnostics, including relative paths.
    return { path, canonical: resolve(parent, leaf), data };
  });
  const created: CreatedFile[] = [];
  const cleanupErrors: unknown[] = [];
  let outputPath: string | undefined;
  try {
    for (const { path, canonical, data } of destinations) {
      outputPath = path;
      const fd = fs.openSync(canonical, "wx", 0o644);
      const entry: CreatedFile = { path: canonical };
      created.push(entry);
      try {
        entry.identity = fs.fstatSync(fd, { bigint: true });
        if (!entry.identity.isFile()) throw new Error(`Output is not a regular file: ${path}`);
        fs.writeFileSync(fd, data);
      } catch (error) {
        try {
          fs.closeSync(fd);
        } catch (closeError) {
          cleanupErrors.push(closeError);
        }
        throw error;
      }
      fs.closeSync(fd);
    }
  } catch (error) {
    for (const { path, identity } of created.reverse()) {
      try {
        const current = fs.lstatSync(path, { bigint: true, throwIfNoEntry: false });
        if (current === undefined) continue;
        if (!current.isFile() || !identity?.ino || current.dev !== identity.dev || current.ino !== identity.ino) {
          throw new Error(`Cannot verify ownership of created output: ${path}`);
        }
        fs.unlinkSync(path);
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    const code = (error as NodeJS.ErrnoException)?.code;
    const primary =
      code === "EEXIST" ? new Error(`${outputPath ?? "a file"} exists: ${what}`, { cause: error }) : error;
    if (cleanupErrors.length === 0) throw primary;

    const details = cleanupErrors.map((failure) => (failure instanceof Error ? failure.message : String(failure)));
    const message = primary instanceof Error ? primary.message : String(primary);
    throw Object.assign(
      new AggregateError([primary, ...cleanupErrors], `${message}\nOutput cleanup incomplete: ${details.join("\n")}`, {
        cause: primary,
      }),
      { code },
    );
  }
}
