/**
 * Published records are created once and never rewritten. The generators used to check that a record was absent and
 * then write it (CodeQL js/file-system-race): a file appearing in between was overwritten. writeNewFiles creates each
 * file exclusively (O_CREAT|O_EXCL), so the refusal and the creation are one operation, and a set is all-or-nothing.
 */
import { expect } from "chai";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { writeNewFiles } from "../scripts/lib/write-once";

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

  it("is all-or-nothing: when a later file exists, the files this call created are removed again", function () {
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

  it("passes any other failure through unchanged, after removing what it created", function () {
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
});
