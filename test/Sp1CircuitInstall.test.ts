/**
 * SP1-PA2A: installing a verified archive and re-verifying an installation (scripts/lib/sp1-circuit-install.ts).
 *
 * The installer validates everything before it writes anything, extracts into a fresh private staging directory with
 * exclusive file creation, re-reads the staged tree from disk, makes it read-only and renames it into place; a target
 * that exists is refused and left exactly as it was, and any failure removes the staging directory. The installed
 * tree authenticates nothing later: verifyInstalledCircuit re-hashes it, and is what the prove gate runs.
 *
 * Synthetic fixtures only (scripts/lib/sp1-circuit-fixtures.ts). Link and FIFO cases run where the platform allows.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { VK_FILE } from "../scripts/lib/sp1-circuit-archive";
import {
  SAFE_FILES,
  SYNTHETIC_ANCHOR,
  gz,
  safeEntries,
  safeTar,
  syntheticRecord,
  tarBytes,
} from "../scripts/lib/sp1-circuit-fixtures";
import {
  STAGING_PREFIX,
  hashRegularFile,
  installCircuitArchive,
  installationIdentity,
  verifyInstalledCircuit,
  walkTree,
} from "../scripts/lib/sp1-circuit-install";
import { refusalOf, symlinkOrSkip, tempDirs } from "./helpers/circuit-tooling";

const anchor = SYNTHETIC_ANCHOR;
const archive = gz(safeTar());
const record = syntheticRecord(archive, SAFE_FILES);
const posix = process.platform !== "win32";

describe("SP1-PA2A circuit install", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  function setup(bytes: Buffer = archive) {
    const work = dirs.make();
    const archivePath = join(work, "a.tar.gz");
    writeFileSync(archivePath, bytes);
    const root = join(work, "circuits");
    mkdirSync(root);
    return { work, archivePath, root, target: join(root, anchor.circuitVersion) };
  }
  const install = (s: ReturnType<typeof setup>, over: Partial<Parameters<typeof installCircuitArchive>[0]> = {}) =>
    installCircuitArchive({ archivePath: s.archivePath, record, anchor, destinationRoot: s.root, ...over });
  const rootEntries = (root: string) => readdirSync(root).sort();

  describe("a verified archive", function () {
    it("is installed at <root>/<circuit version>, byte for byte, read-only, with no staging left", async function () {
      const s = setup();
      const result = await install(s);
      expect(result.circuitDir).to.equal(s.target);
      expect(result.archive.bytes).to.equal(archive.length);
      expect(result.members).to.deep.equal(record.members);
      expect(rootEntries(s.root)).to.deep.equal([anchor.circuitVersion]);
      const { files, directories } = walkTree(s.target, "CIRCUIT_INTEGRITY_FAILED");
      expect(files).to.deep.equal(SAFE_FILES.map(([p]) => p));
      expect(directories).to.deep.equal(["extra"]);
      for (const [p, d] of SAFE_FILES) {
        const full = join(s.target, ...p.split("/"));
        expect(readFileSync(full).equals(d), p).to.equal(true);
        expect(statSync(full).mode & 0o222, `${p} is read-only`).to.equal(0);
      }
      if (posix) {
        expect(statSync(s.target).mode & 0o777).to.equal(0o555);
        expect(statSync(join(s.target, "extra")).mode & 0o777).to.equal(0o555);
      }
      expect(verifyInstalledCircuit(s.root, record, anchor).members).to.deep.equal(record.members);
    });
  });

  describe("an existing target is refused and left untouched", function () {
    const cases: [string, (target: string) => void][] = [
      ["a populated directory", (t) => (mkdirSync(t), writeFileSync(join(t, "groth16_pk.bin"), "theirs"))],
      ["an empty directory", (t) => mkdirSync(t)],
      ["a file", (t) => writeFileSync(t, "theirs")],
    ];
    for (const [what, make] of cases) {
      it(`when it is ${what}`, async function () {
        const s = setup();
        make(s.target);
        expect(await refusalOf(() => install(s))).to.equal("INSTALL_TARGET_EXISTS (EXISTS)");
        expect(rootEntries(s.root)).to.deep.equal([anchor.circuitVersion]);
        if (what === "a populated directory") {
          expect(readdirSync(s.target)).to.deep.equal(["groth16_pk.bin"]);
          expect(readFileSync(join(s.target, "groth16_pk.bin"), "utf8")).to.equal("theirs");
        }
        if (what === "a file") expect(readFileSync(s.target, "utf8")).to.equal("theirs");
      });
    }
    it("when it is a dangling link", async function () {
      const s = setup();
      symlinkOrSkip(this, join(s.work, "nowhere"), s.target, "dir");
      expect(await refusalOf(() => install(s))).to.equal("INSTALL_TARGET_EXISTS (EXISTS)");
      expect(existsSync(join(s.work, "nowhere"))).to.equal(false);
    });
    it("a second installation of the same archive", async function () {
      const s = setup();
      await install(s);
      expect(await refusalOf(() => install(s))).to.equal("INSTALL_TARGET_EXISTS (EXISTS)");
    });
  });

  describe("the destination root", function () {
    it("must be absolute, exist and be a directory (never a link)", async function () {
      const s = setup();
      expect(await refusalOf(() => install(s, { destinationRoot: "circuits" }))).to.equal(
        "INSTALL_DESTINATION_INVALID (RELATIVE)",
      );
      expect(await refusalOf(() => install(s, { destinationRoot: join(s.work, "absent") }))).to.equal(
        "INSTALL_DESTINATION_INVALID (ABSENT)",
      );
      expect(await refusalOf(() => install(s, { destinationRoot: s.archivePath }))).to.equal(
        "INSTALL_DESTINATION_INVALID (NOT_A_DIRECTORY)",
      );
    });
    it("must not be a link to a directory", async function () {
      const s = setup();
      const link = join(s.work, "linked-root");
      symlinkOrSkip(this, s.root, link, "dir");
      expect(await refusalOf(() => install(s, { destinationRoot: link }))).to.equal(
        "INSTALL_DESTINATION_INVALID (NOT_A_DIRECTORY)",
      );
      expect(rootEntries(s.root)).to.deep.equal([]);
    });
  });

  describe("nothing is written unless everything validates first", function () {
    it("an invalid record, a hostile archive and a tampered archive leave the root empty", async function () {
      const bad = { ...record, subject: { ...record.subject, designation: "mldsa65-withdrawal-d1" } };
      const s1 = setup();
      expect(await refusalOf(() => install(s1, { record: bad }))).to.equal("RECORD_INVALID (SUBJECT_MISMATCH)");
      expect(rootEntries(s1.root)).to.deep.equal([]);
      const hostile = gz(tarBytes([...safeEntries(), { name: "../../escape", data: "x" }]));
      const s2 = setup(hostile);
      expect(await refusalOf(() => install(s2, { record: syntheticRecord(hostile, SAFE_FILES) }))).to.equal(
        "ARCHIVE_UNSAFE_ENTRY (TRAVERSAL)",
      );
      expect(rootEntries(s2.root)).to.deep.equal([]);
      expect(existsSync(join(s2.work, "escape"))).to.equal(false);
      const tampered = Buffer.from(archive);
      tampered[tampered.length - 8] ^= 1;
      const s3 = setup(tampered);
      expect(await refusalOf(() => install(s3))).to.equal("ARCHIVE_DIGEST_MISMATCH (SHA256)");
      expect(rootEntries(s3.root)).to.deep.equal([]);
    });
  });

  describe("failures after staging remove the staging directory", function () {
    const noStaging = (root: string) =>
      expect(rootEntries(root).filter((n) => n.includes(STAGING_PREFIX))).to.deep.equal([]);

    it("an archive swapped for other bytes after inspection is refused (the bytes extracted are not the bytes authenticated)", async function () {
      const s = setup();
      const other = gz(tarBytes(safeEntries(), { trailing: Buffer.alloc(512) }));
      expect(
        await refusalOf(() => install(s, { hooks: { afterInspection: () => writeFileSync(s.archivePath, other) } })),
      ).to.equal("ARCHIVE_CHANGED_DURING_USE (REREAD)");
      noStaging(s.root);
      expect(existsSync(s.target)).to.equal(false);
    });

    it("an archive swapped for a hostile one after inspection is refused during extraction", async function () {
      const s = setup();
      const hostile = gz(tarBytes([...safeEntries(), { name: "/etc/evil", data: "x" }]));
      expect(
        await refusalOf(() => install(s, { hooks: { afterInspection: () => writeFileSync(s.archivePath, hostile) } })),
      ).to.equal("ARCHIVE_UNSAFE_ENTRY (ABSOLUTE_PATH)");
      noStaging(s.root);
      expect(existsSync(s.target)).to.equal(false);
    });

    it("files are created exclusively: a file already in staging is never overwritten", async function () {
      const s = setup();
      let planted = "";
      expect(
        await refusalOf(() =>
          install(s, {
            hooks: {
              afterStaging: (staging) => {
                planted = join(staging, "groth16_pk.bin");
                writeFileSync(planted, "planted");
              },
            },
          }),
        ),
      ).to.equal("INSTALL_FAILED (EXCLUSIVE_CREATE)");
      expect(planted).to.not.equal("");
      noStaging(s.root);
      expect(existsSync(s.target)).to.equal(false);
    });

    it("directories are created once: a directory already in staging is refused", async function () {
      const s = setup();
      expect(
        await refusalOf(() => install(s, { hooks: { afterStaging: (st) => mkdirSync(join(st, "extra")) } })),
      ).to.equal("INSTALL_FAILED (MKDIR)");
      noStaging(s.root);
    });

    it("the staged tree is re-read: an extra file or directory in it is refused", async function () {
      const s1 = setup();
      expect(
        await refusalOf(() =>
          install(s1, { hooks: { afterStaging: (st) => writeFileSync(join(st, "planted.bin"), "x") } }),
        ),
      ).to.equal("INSTALL_FAILED (UNEXPECTED_MEMBER)");
      noStaging(s1.root);
      const s2 = setup();
      expect(
        await refusalOf(() => install(s2, { hooks: { afterStaging: (st) => mkdirSync(join(st, "empty")) } })),
      ).to.equal("INSTALL_FAILED (EXTRA_DIRECTORY)");
      noStaging(s2.root);
    });

    it("the staged tree is re-read: a link planted in it is refused", async function () {
      const s = setup();
      const outside = join(s.work, "outside");
      writeFileSync(outside, "x");
      let skipped = false;
      const got = await refusalOf(() =>
        install(s, {
          hooks: {
            afterStaging: (st) => {
              try {
                symlinkOrSkip(this, outside, join(st, "link"), "file");
              } catch (e) {
                skipped = true;
                throw e;
              }
            },
          },
        }),
      );
      if (skipped) this.skip();
      expect(got).to.equal("INSTALL_FAILED (LINK_IN_TREE)");
      noStaging(s.root);
      expect(readFileSync(outside, "utf8")).to.equal("x");
    });

    it("a target that appears during installation is refused before the rename, and kept", async function () {
      const s = setup();
      const make = () => (mkdirSync(s.target), writeFileSync(join(s.target, "theirs"), "theirs"));
      expect(await refusalOf(() => install(s, { hooks: { afterStaging: make } }))).to.equal(
        "INSTALL_TARGET_EXISTS (APPEARED)",
      );
      expect(readdirSync(s.target)).to.deep.equal(["theirs"]);
      noStaging(s.root);
    });

    it("an empty target that appears during installation is refused too (POSIX rename would replace it)", async function () {
      const s = setup();
      expect(await refusalOf(() => install(s, { hooks: { afterStaging: () => mkdirSync(s.target) } }))).to.equal(
        "INSTALL_TARGET_EXISTS (APPEARED)",
      );
      expect(readdirSync(s.target)).to.deep.equal([]);
      noStaging(s.root);
    });

    it("a target that appears at the rename itself is refused, and kept", async function () {
      const s = setup();
      const make = () => (mkdirSync(s.target), writeFileSync(join(s.target, "theirs"), "theirs"));
      expect(await refusalOf(() => install(s, { hooks: { beforeRename: make } }))).to.equal(
        "INSTALL_TARGET_EXISTS (APPEARED)",
      );
      expect(readdirSync(s.target)).to.deep.equal(["theirs"]);
      noStaging(s.root);
    });

    it("an empty directory created at the rename itself: replaced on POSIX (it holds nothing), refused on Windows", async function () {
      const s = setup();
      const got = await refusalOf(() => install(s, { hooks: { beforeRename: () => mkdirSync(s.target) } }));
      if (posix) {
        expect(got).to.equal("NOT_REFUSED");
        expect(verifyInstalledCircuit(s.root, record, anchor).members).to.deep.equal(record.members);
      } else {
        expect(got).to.equal("INSTALL_TARGET_EXISTS (APPEARED)");
        expect(readdirSync(s.target)).to.deep.equal([]);
      }
      noStaging(s.root);
    });

    it("a rename that fails for any other reason is INSTALL_FAILED, and leaves no target", async function () {
      const s = setup();
      const moved = join(s.work, "moved-away");
      let staging = "";
      const got = await refusalOf(() =>
        install(s, {
          hooks: {
            afterStaging: (st) => (staging = st),
            beforeRename: () => {
              chmodSync(staging, 0o700);
              renameSync(staging, moved);
            },
          },
        }),
      );
      expect(got).to.equal("INSTALL_FAILED (RENAME)");
      expect(existsSync(s.target)).to.equal(false);
      // `moved` (the read-only staged tree) sits inside the work directory, which the suite's cleanup removes.
    });
  });

  describe("verifyInstalledCircuit: the installation, re-hashed", function () {
    async function installed() {
      const s = setup();
      await install(s);
      const w = (rel: string) => {
        const full = join(s.target, ...rel.split("/"));
        if (existsSync(full)) chmodSync(full, 0o600);
        return full;
      };
      chmodSync(s.target, 0o700);
      return { ...s, w };
    }
    const check = (root: string) => refusalOf(() => verifyInstalledCircuit(root, record, anchor));

    it("refuses a relative root, an absent root or circuit, and a root that is not a directory", async function () {
      const s = setup();
      expect(await check("circuits")).to.equal("CIRCUIT_ROOT_INVALID (RELATIVE)");
      expect(await check(join(s.work, "absent"))).to.equal("CIRCUIT_ARCHIVE_NOT_INSTALLED (ROOT_ABSENT)");
      expect(await check(s.root)).to.equal("CIRCUIT_ARCHIVE_NOT_INSTALLED (CIRCUIT_ABSENT)");
      expect(await check(s.archivePath)).to.equal("CIRCUIT_ROOT_INVALID (NOT_A_DIRECTORY)");
      writeFileSync(s.target, "not a directory");
      expect(await check(s.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (NOT_A_DIRECTORY)");
    });

    it("refuses a changed, resized, missing or extra member, and an extra directory", async function () {
      const a = await installed();
      writeFileSync(a.w("groth16_pk.bin"), Buffer.alloc(3000));
      expect(await check(a.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)");
      const b = await installed();
      writeFileSync(b.w("groth16_circuit.bin"), Buffer.alloc(10));
      expect(await check(b.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (SIZE_MISMATCH)");
      const c = await installed();
      rmSync(c.w("constraints.json"));
      expect(await check(c.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (MISSING_MEMBER)");
      const d = await installed();
      writeFileSync(join(d.target, "extra.bin"), "x");
      expect(await check(d.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (UNEXPECTED_MEMBER)");
      const e = await installed();
      mkdirSync(join(e.target, "empty"));
      expect(await check(e.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (EXTRA_DIRECTORY)");
      const f = await installed();
      writeFileSync(f.w(VK_FILE), Buffer.from(readFileSync(f.w(VK_FILE)).toString().replace("SYNTHETIC", "SUBVERTED")));
      expect(await check(f.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)");
    });

    it("refuses a link in the tree, and a linked circuit directory", async function () {
      const a = await installed();
      rmSync(a.w("groth16_pk.bin"));
      const outside = join(a.work, "pk-copy");
      writeFileSync(outside, SAFE_FILES.find(([p]) => p === "groth16_pk.bin")![1]);
      symlinkOrSkip(this, outside, join(a.target, "groth16_pk.bin"), "file");
      expect(await check(a.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (LINK_IN_TREE)");
      const b = setup();
      const real = join(b.work, "real");
      mkdirSync(real);
      symlinkOrSkip(this, real, b.target, "dir");
      expect(await check(b.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (NOT_A_DIRECTORY)");
    });

    it("refuses a member with a second hard link (another path could change it)", async function () {
      const a = await installed();
      linkSync(join(a.target, "groth16_pk.bin"), join(a.work, "pk-alias"));
      expect(await check(a.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (HARDLINK_IN_TREE)");
    });

    it("refuses a root that holds anything besides the circuit version", async function () {
      const a = await installed();
      chmodSync(a.root, 0o755);
      mkdirSync(join(a.root, "v6.1.1"));
      expect(await check(a.root)).to.equal("CIRCUIT_ROOT_INVALID (UNEXPECTED_ENTRY)");
      const b = setup();
      writeFileSync(join(b.root, "README"), "x");
      expect(await check(b.root)).to.equal("CIRCUIT_ROOT_INVALID (UNEXPECTED_ENTRY)");
    });

    it("an installation's identity changes when it is re-created with the same bytes", async function () {
      const a = await installed();
      const before = installationIdentity(a.root, a.target);
      expect(installationIdentity(a.root, a.target)).to.deep.equal(before);
      expect(before[0].startsWith("<root>\t")).to.equal(true);
      expect(before.map((l) => l.split("\t")[0])).to.deep.equal([
        "<root>",
        "",
        "constraints.json",
        "extra",
        "extra/README.synthetic",
        "groth16_circuit.bin",
        "groth16_pk.bin",
        "groth16_vk.bin",
      ]);
      chmodSync(a.target, 0o700);
      renameSync(a.target, join(a.work, "away"));
      cpSync(join(a.work, "away"), a.target, { recursive: true });
      expect(verifyInstalledCircuit(a.root, record, anchor).members).to.deep.equal(record.members);
      expect(installationIdentity(a.root, a.target)).to.not.deep.equal(before);
    });

    it("refuses a FIFO in the tree, and never blocks on one", async function () {
      if (!posix) this.skip();
      const a = await installed();
      execFileSync("mkfifo", [join(a.target, "fifo")]);
      expect(await check(a.root)).to.equal("CIRCUIT_INTEGRITY_FAILED (SPECIAL_FILE_IN_TREE)");
      expect(
        await refusalOf(() => hashRegularFile(join(a.target, "fifo"), "fifo", "CIRCUIT_INTEGRITY_FAILED")),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED (SPECIAL_FILE_IN_TREE)");
    });

    it("hashes through one descriptor that never follows a link", async function () {
      const s = setup();
      const real = join(s.work, "real.bin");
      writeFileSync(real, "abc");
      expect(hashRegularFile(real, "real.bin", "CIRCUIT_INTEGRITY_FAILED")).to.deep.equal({
        path: "real.bin",
        bytes: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      });
      const link = join(s.work, "link.bin");
      symlinkOrSkip(this, real, link, "file");
      expect(await refusalOf(() => hashRegularFile(link, "link.bin", "CIRCUIT_INTEGRITY_FAILED"))).to.equal(
        "CIRCUIT_INTEGRITY_FAILED (LINK_IN_TREE)",
      );
      expect(
        await refusalOf(() => hashRegularFile(join(s.work, "absent"), "absent", "CIRCUIT_INTEGRITY_FAILED")),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED (UNREADABLE)");
    });
  });
});
