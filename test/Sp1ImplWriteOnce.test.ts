/**
 * Published records are created once and never rewritten. The generators used to check that a record was absent and
 * then write it (CodeQL js/file-system-race): a file appearing in between was overwritten. writeNewFiles creates each
 * file exclusively (O_CREAT|O_EXCL) and attempts rollback on caught failures.
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import fs, { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { mock } from "node:test";

import { IMPL_RECEIPT_REL } from "../scripts/lib/sp1-impl-receipt";
import { IMPL_RECEIPT_INTEGRATION_REL } from "../scripts/lib/sp1-impl-receipt-integration";
import { PROOF_EXERCISES_DIR } from "../scripts/lib/sp1-proof-exercise";
import {
  createEvidenceOutputDirectory,
  rewriteEvidenceFile,
  writeNewEvidenceFile,
  writeNewFiles,
} from "../scripts/lib/write-once";

describe("SP1 implementation lane — records are created once, never checked and then written", function () {
  let dir: string;
  beforeEach(function () {
    dir = mkdtempSync(join(tmpdir(), "sp1-write-once-"));
  });
  afterEach(function () {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates new files with exactly the given bytes (the positive control)", function () {
    writeNewFiles(
      [
        [join(dir, "a.json"), '{"a":1}\n'],
        [join(dir, "b.json"), '{"b":2}\n'],
      ],
      "a record is never rewritten",
    );
    expect(readFileSync(join(dir, "a.json"), "utf8")).to.equal('{"a":1}\n');
    expect(readFileSync(join(dir, "b.json"), "utf8")).to.equal('{"b":2}\n');
  });

  it("refuses a file that exists, naming it, and leaves its bytes untouched", function () {
    const path = join(dir, "d1.json");
    writeFileSync(path, "the published record\n");
    expect(() => writeNewFiles([[path, "a rewrite\n"]], "a designation is never rewritten")).to.throw(
      `${path} exists: a designation is never rewritten`,
    );
    expect(readFileSync(path, "utf8")).to.equal("the published record\n");
  });

  it("rolls back files created before a later exclusive-open refusal", function () {
    const first = join(dir, "bundle.json");
    const second = join(dir, "designation.json");
    writeFileSync(second, "the published designation\n");
    expect(() =>
      writeNewFiles(
        [
          [first, "the bundle\n"],
          [second, "a rewrite\n"],
        ],
        "a designation and its evidence are never rewritten",
      ),
    ).to.throw(`${second} exists: a designation and its evidence are never rewritten`);
    expect(existsSync(first), "the bundle this call created is gone").to.equal(false);
    expect(readFileSync(second, "utf8")).to.equal("the published designation\n");
  });

  it("checks all parents before creating any output and preserves a missing-parent failure", function () {
    const created = join(dir, "created.json");
    const unwritable = join(dir, "missing-directory", "x.json");
    let failure: NodeJS.ErrnoException | undefined;
    try {
      writeNewFiles(
        [
          [created, "{}\n"],
          [unwritable, "{}\n"],
        ],
        "a record is never rewritten",
      );
    } catch (error) {
      failure = error as NodeJS.ErrnoException;
    }
    expect(failure?.code).to.equal("ENOENT");
    expect(existsSync(created)).to.equal(false);
  });

  it("refuses an existing leaf symlink and leaves its target alone", function () {
    const original = join(dir, "original.json");
    const alias = join(dir, "alias.json");
    writeFileSync(original, "original bytes");
    try {
      fs.symlinkSync(original, alias, "file");
    } catch (error) {
      if (process.platform === "win32" && ["EPERM", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")) {
        this.skip(); // Windows may require Developer Mode for file symlinks.
      }
      throw error;
    }
    expect(() => writeNewFiles([[alias, "new bytes"]], "keep the original")).to.throw("exists: keep the original");
    expect(readFileSync(original, "utf8")).to.equal("original bytes");
    expect(fs.lstatSync(alias).isSymbolicLink()).to.equal(true);
  });

  it("permits a trusted operator parent alias but refuses an evidence parent redirected to another directory", function () {
    const evidence = join(dir, "evidence");
    const outside = join(dir, "operator-output");
    const operatingAlias = join(dir, "operator-alias");
    const redirected = join(evidence, "redirected");
    fs.mkdirSync(evidence);
    fs.mkdirSync(outside);
    const linkType = process.platform === "win32" ? "junction" : "dir";
    fs.symlinkSync(outside, operatingAlias, linkType);
    fs.symlinkSync(outside, redirected, linkType);
    writeNewFiles([[join(operatingAlias, "observation.json"), "operator output"]], "keep observations", dir);
    expect(readFileSync(join(outside, "observation.json"), "utf8")).to.equal("operator output");
    expect(() => writeNewFiles([[join(redirected, "record.json"), "{}"]], "keep records", dir)).to.throw(
      "outside its expected evidence directory",
    );
    expect(existsSync(join(outside, "record.json"))).to.equal(false);
    expect(() => createEvidenceOutputDirectory(join(redirected, "missing"), dir)).to.throw(
      "outside its expected evidence directory",
    );
    expect(existsSync(join(outside, "missing"))).to.equal(false);

    const normal = join(evidence, "nested", "records");
    createEvidenceOutputDirectory(normal, dir);
    writeNewFiles([[join(normal, "record.json"), "{}"]], "keep records", dir);
    expect(readFileSync(join(normal, "record.json"), "utf8")).to.equal("{}");
  });

  it("refuses a POSIX output parent writable by other users", function () {
    if (!process.geteuid) this.skip();
    fs.chmodSync(dir, 0o770);
    const output = join(dir, "observation.json");
    expect(() => writeNewFiles([[output, "{}"]], "keep observations")).to.throw("not group- or world-writable");
    expect(existsSync(output)).to.equal(false);
  });

  for (const [mode, relativePath, rewrite] of [
    ["proof-exercise record", `${PROOF_EXERCISES_DIR}/record.json`, false],
    ["receipt integration", IMPL_RECEIPT_INTEGRATION_REL, true],
    ["default receipt", IMPL_RECEIPT_REL, true],
  ] as const) {
    const write = (path: string, content: string) =>
      rewrite
        ? rewriteEvidenceFile(path, content, dir)
        : writeNewEvidenceFile(path, content, "a proof-exercise record is never overwritten", dir);

    it(`${mode} refuses a redirected evidence ancestor before creating any directories`, function () {
      const other = join(dir, "other");
      fs.mkdirSync(other);
      fs.mkdirSync(join(dir, "evidence"));
      fs.symlinkSync(other, join(dir, "evidence", "zk"), process.platform === "win32" ? "junction" : "dir");

      expect(() => write(join(dir, relativePath), "{}\n")).to.throw("outside its expected evidence directory");
      expect(fs.readdirSync(other)).to.deep.equal([]);
    });

    it(`${mode} creates missing parents, writes exact bytes and preserves its existing-file contract`, function () {
      const path = join(dir, relativePath);
      const original = '{\n  "result": "é"\n}\n';
      const replacement = "{}\n";
      write(path, original);
      expect(readFileSync(path)).to.deep.equal(Buffer.from(original));
      if (rewrite) {
        write(path, replacement);
        expect(readFileSync(path)).to.deep.equal(Buffer.from(replacement));
      } else {
        expect(() => write(path, replacement)).to.throw("a proof-exercise record is never overwritten");
        expect(readFileSync(path)).to.deep.equal(Buffer.from(original));
      }
    });
  }

  for (const [mode, relativePath] of [
    ["receipt integration", IMPL_RECEIPT_INTEGRATION_REL],
    ["default receipt", IMPL_RECEIPT_REL],
  ] as const) {
    describe(mode, function () {
      let checkout: string;
      let output: string;
      beforeEach(function () {
        checkout = join(dir, "checkout");
        output = join(checkout, relativePath);
        fs.mkdirSync(dirname(output), { recursive: true });
      });

      for (const targetExists of [true, false]) {
        it(`refuses a ${targetExists ? "live" : "dangling"} leaf symlink and leaves its external target alone`, function () {
          const target = join(dir, "outside.json");
          if (targetExists) writeFileSync(target, "external bytes\n");
          try {
            fs.symlinkSync(target, output, "file");
          } catch (error) {
            if (
              process.platform === "win32" &&
              ["EPERM", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")
            ) {
              this.skip(); // Windows may require Developer Mode for file symlinks.
            }
            throw error;
          }

          expect(() => rewriteEvidenceFile(output, "{}\n", checkout)).to.throw("Output is not a regular file");
          expect(fs.lstatSync(output).isSymbolicLink()).to.equal(true);
          if (targetExists) expect(readFileSync(target, "utf8")).to.equal("external bytes\n");
          else expect(existsSync(target)).to.equal(false);
        });
      }

      it("refuses a directory at the destination and preserves its contents", function () {
        fs.mkdirSync(output);
        const sentinel = join(output, "sentinel");
        writeFileSync(sentinel, "keep me\n");

        expect(() => rewriteEvidenceFile(output, "{}\n", checkout)).to.throw("Output is not a regular file");
        expect(readFileSync(sentinel, "utf8")).to.equal("keep me\n");
      });

      it("validates the opened descriptor before truncating an existing file", function () {
        const other = join(dir, "other.json");
        writeFileSync(output, "original receipt\n");
        writeFileSync(other, "other file\n");
        const openSync = fs.openSync;
        const stub = mock.method(fs, "openSync", (_path: fs.PathLike, flags: number, mode?: number) =>
          openSync(other, flags, mode),
        );
        try {
          expect(() => rewriteEvidenceFile(output, "{}\n", checkout)).to.throw(
            "could not be verified before rewriting",
          );
        } finally {
          stub.mock.restore();
        }
        expect(readFileSync(output, "utf8")).to.equal("original receipt\n");
        expect(readFileSync(other, "utf8")).to.equal("other file\n");
      });
    });
  }

  it("caps the POSIX file mode and honors a private umask for observations", function () {
    if (!process.geteuid) this.skip();
    const previous = process.umask(0);
    try {
      const published = join(dir, "published.json");
      writeNewFiles([[published, "{}"]], "keep records");
      expect(fs.statSync(published).mode & 0o777).to.equal(0o644);

      process.umask(0o077);
      const privateObservation = join(dir, "private.json");
      writeNewFiles([[privateObservation, '{"observation":"synthetic"}']], "keep observations");
      expect(fs.statSync(privateObservation).mode & 0o777).to.equal(0o600);
    } finally {
      process.umask(previous);
    }
  });

  it("leaves a replaced entry alone, continues cleanup, and exposes the primary open failure", function () {
    const cleanup = join(dir, "cleanup.json");
    const replaced = join(dir, "replaced.json");
    const renamed = join(dir, "renamed.json");
    const collision = join(dir, "exists.json");
    writeFileSync(collision, "published");
    const openSync = fs.openSync;
    const canonicalDir = fs.realpathSync.native(dir);
    const stub = mock.method(fs, "openSync", (path: Parameters<typeof openSync>[0], flags: string, mode?: number) => {
      if (path === join(canonicalDir, "exists.json")) {
        fs.renameSync(replaced, renamed); // Simulate an unexpected change before cleanup.
        writeFileSync(replaced, "replacement");
      }
      return openSync(path, flags, mode);
    });
    try {
      let failure: (AggregateError & { code?: string }) | undefined;
      try {
        writeNewFiles(
          [
            [cleanup, "{}"],
            [replaced, "written by this call"],
            [collision, "refused"],
          ],
          "keep records",
        );
      } catch (error) {
        failure = error as AggregateError & { code?: string };
      }
      expect(failure).to.be.instanceOf(AggregateError);
      expect(failure?.code).to.equal("EEXIST");
      expect(failure?.cause).to.be.instanceOf(Error).and.have.property("message", `${collision} exists: keep records`);
      expect(failure?.message).to.include("Output cleanup incomplete");
      expect(readFileSync(replaced, "utf8")).to.equal("replacement");
      expect(readFileSync(renamed, "utf8")).to.equal("written by this call");
      expect(readFileSync(collision, "utf8")).to.equal("published");
      expect(existsSync(cleanup)).to.equal(false);
    } finally {
      stub.mock.restore();
    }
  });

  it("keeps the write error as the cause when rollback cannot unlink the created entry", function () {
    const output = join(dir, "output.json");
    const primary = Object.assign(new Error("synthetic write failure"), { code: "ENOSPC" });
    const writer = mock.method(fs, "writeFileSync", () => {
      throw primary;
    });
    const unlink = mock.method(fs, "unlinkSync", () => {
      throw new Error("synthetic cleanup failure");
    });
    try {
      let failure: (AggregateError & { code?: string }) | undefined;
      try {
        writeNewFiles([[output, "{}"]], "keep records");
      } catch (error) {
        failure = error as AggregateError & { code?: string };
      }
      expect(failure).to.be.instanceOf(AggregateError);
      expect(failure?.cause).to.equal(primary);
      expect(failure?.code).to.equal("ENOSPC");
      expect(failure?.message).to.include("synthetic cleanup failure");
      expect(existsSync(output)).to.equal(true);
    } finally {
      writer.mock.restore();
      unlink.mock.restore();
    }
  });

  it("can leave an incomplete file after process interruption and still refuses an overwrite", function () {
    const first = join(dir, "first.json");
    const second = join(dir, "second.json");
    const child = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--input-type=module",
        "--eval",
        `import fs from "node:fs";
       const { writeNewFiles } = await import(process.argv[1]);
       fs.writeFileSync = (fd) => {
         fs.writeSync(fd, "partial");
         process.exit(23);
       };
       writeNewFiles([[process.argv[2], "{}"], [process.argv[3], "{}"]], "keep records");`,
        new URL("../scripts/lib/write-once.ts", import.meta.url).href,
        first,
        second,
      ],
      { encoding: "utf8" },
    );

    expect(child.status, child.stderr).to.equal(23);
    expect(readFileSync(first, "utf8")).to.equal("partial");
    expect(existsSync(second)).to.equal(false);
    expect(() => writeNewFiles([[first, "{}"]], "keep records")).to.throw("exists: keep records");
    expect(readFileSync(first, "utf8")).to.equal("partial");
  });
});
