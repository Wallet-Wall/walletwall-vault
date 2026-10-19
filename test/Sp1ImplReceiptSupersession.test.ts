/**
 * SP1-PA2B: superseding the implementation receipt's PROVING_AVAILABILITY binding
 * (scripts/lib/sp1-impl-receipt.ts, "Supersession"). The historical receipt is never restamped: once an archive
 * record moves proving availability, a supersession pins the receipt's bytes and names the first-parent main commit
 * where it was live, and the superseded status is derived there. Every rule of that record can fail on its own:
 * the pinned bytes, the historical subject (on main's first-parent history, an ancestor of HEAD, carrying the same
 * receipt, with a pre-archive availability), the one supersedable status, the live availability (validating and
 * archived, else nothing was superseded), and the superseding records.
 */
import { expect } from "chai";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  IMPL_RECEIPT_REL,
  IMPL_SUPERSESSION_REL,
  IMPL_SUPERSESSION_SCHEMA,
  LIVE_AVAILABILITY_STATUSES,
  SUPERSEDABLE_STATUSES,
  boundSupersession,
  implSupersessionErrors,
  provingAvailabilityInputs,
  readImplSupersession,
  type ImplSupersession,
  type LiveAvailability,
} from "../scripts/lib/sp1-impl-receipt";
import { PROVING_ARCHIVES_DIR, PROVING_AVAILABILITY_REL } from "../scripts/lib/sp1-proving-availability";
import { tempDirs } from "./helpers/circuit-tooling";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const RECORD = `${PROVING_ARCHIVES_DIR}/v6.1.0-groth16.json`;
const RECEIPT = Buffer.from('{"schema":"walletwall.sp1-impl-receipt.v1","synthetic":true}\n');
const ARCHIVED: LiveAvailability = { errors: [], status: "ARCHIVED_VERIFIED_UNEXERCISED" };

describe("SP1-PA2B: the implementation receipt's supersession", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  /** main: m0 (receipt live, availability OWNER_DOWNLOAD_REQUIRED) -> m1 (an unrelated main commit); the lane forks at m1
   *  and admits the record (l1: the archive record and an archived availability). HEAD is the lane. */
  function world() {
    const d = dirs.make("sp1-supersession-");
    const git = (...args: string[]): string => {
      const run = () =>
        execFileSync(
          "git",
          [
            "-c",
            "core.autocrlf=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            ...args,
          ],
          { cwd: d, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
        ).trim();
      // On Windows a scanner can hold a just-written object file for a moment, and git's rename into .git/objects
      // then fails with "Permission denied". That is the host, not the code under test: retry it, and only it.
      for (let attempt = 1; ; attempt++) {
        try {
          return run();
        } catch (error) {
          const stderr = String((error as { stderr?: unknown }).stderr ?? "");
          if (attempt === 5 || !/unable to write file \.git\/objects\/.*: Permission denied/.test(stderr)) throw error;
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200 * attempt);
        }
      }
    };
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(d, rel)), { recursive: true });
      writeFileSync(join(d, rel), text);
    };
    const commit = (message: string) => {
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", message);
      return git("rev-parse", "HEAD");
    };
    git("init", "-q", "-b", "main");
    write(IMPL_RECEIPT_REL, RECEIPT.toString());
    write(PROVING_AVAILABILITY_REL, '{"status":"OWNER_DOWNLOAD_REQUIRED"}\n');
    const m0 = commit("m0: the receipt, live");
    write("README.md", "unrelated\n");
    const m1 = commit("m1: unrelated");
    git("update-ref", "refs/remotes/origin/main", m1);
    git("checkout", "-q", "-b", "lane");
    write(RECORD, '{"schema":"walletwall.sp1-proving-archive.v2","synthetic":true}\n');
    write(PROVING_AVAILABILITY_REL, '{"status":"ARCHIVED_VERIFIED_UNEXERCISED"}\n');
    const l1 = commit("l1: the archive record");
    const supersession = (over: Partial<ImplSupersession> = {}): ImplSupersession => ({
      schema: IMPL_SUPERSESSION_SCHEMA,
      receipt: IMPL_RECEIPT_REL,
      receiptSha256: sha256(RECEIPT),
      historicalSubject: m1,
      supersedes: [...SUPERSEDABLE_STATUSES],
      supersededBy: [{ lane: "SP1-PA2B", record: RECORD, reason: "the archive record moved proving availability" }],
      ...over,
    });
    return { d, git, write, commit, m0, m1, l1, supersession };
  }

  it("accepts a supersession pinned to the receipt, at the last main commit where it was live, once availability is archived", function () {
    this.timeout(60_000);
    const w = world();
    expect(implSupersessionErrors(w.supersession(), RECEIPT, w.d, ARCHIVED)).to.deep.equal([]);
    // m0 carries the same receipt and a live availability too: any such first-parent main commit is a valid subject.
    expect(implSupersessionErrors(w.supersession({ historicalSubject: w.m0 }), RECEIPT, w.d, ARCHIVED)).to.deep.equal(
      [],
    );
    expect(readImplSupersession(w.d)).to.equal(null);
    w.write(IMPL_SUPERSESSION_REL, `${JSON.stringify(w.supersession(), null, 2)}\n`);
    expect(readImplSupersession(w.d)).to.deep.equal(w.supersession());
  });

  it("pins the receipt's bytes and names: another schema, another file, other bytes, a restamped receipt", function () {
    this.timeout(60_000);
    const w = world();
    const errs = (s: ImplSupersession, bytes = RECEIPT) => implSupersessionErrors(s, bytes, w.d, ARCHIVED).join("\n");
    expect(errs(w.supersession({ schema: "walletwall.sp1-impl-receipt-supersession.v0" }))).to.match(/schema must be/);
    expect(errs(w.supersession({ receipt: "evidence/zk/sp1-p1/stop-receipt.json" }))).to.match(
      /must name evidence\/zk\/sp1-impl\/implementation-receipt.json/,
    );
    expect(errs(w.supersession({ receiptSha256: sha256("other") }))).to.match(/not the bytes the supersession pinned/);
    // The committed receipt restamped: the pinned digest no longer matches, and the subject no longer carries it.
    const restamped = Buffer.from('{"schema":"walletwall.sp1-impl-receipt.v1","restamped":true}\n');
    expect(errs(w.supersession(), restamped)).to.match(
      /not the bytes the supersession pinned[\s\S]*is not the committed receipt/,
    );
    expect(implSupersessionErrors("not an object", RECEIPT, w.d, ARCHIVED)).to.deep.equal([
      "the supersession record is not an object",
    ]);
  });

  it("the historical subject must be a first-parent main commit, an ancestor of HEAD, carrying the receipt, with a pre-archive availability", function () {
    this.timeout(60_000);
    const w = world();
    const errs = (s: ImplSupersession) => implSupersessionErrors(s, RECEIPT, w.d, ARCHIVED).join("\n");
    expect(errs(w.supersession({ historicalSubject: "m1" }))).to.match(/full commit id/);
    // The lane's own commit: not on main's first-parent history, and its availability is already archived.
    expect(errs(w.supersession({ historicalSubject: w.l1 }))).to.match(
      /no commit of origin\/main's first-parent history[\s\S]*was ARCHIVED_VERIFIED_UNEXERCISED, not a status this receipt derived live/,
    );
    // A main commit that is not an ancestor of HEAD (main moved on after the fork).
    w.git("checkout", "-q", "main");
    w.write("docs/later.md", "later\n");
    const m2 = w.commit("m2: later main");
    w.git("update-ref", "refs/remotes/origin/main", m2);
    w.git("checkout", "-q", "lane");
    expect(errs(w.supersession({ historicalSubject: m2 }))).to.match(/not an ancestor of HEAD/);
    // A commit git cannot read.
    expect(errs(w.supersession({ historicalSubject: "0".repeat(40) }))).to.match(
      /no commit of origin\/main[\s\S]*not an ancestor[\s\S]*not in the repository/,
    );
    // A side-branch merge whose first parent is main is on the first-parent history; a commit reachable only through a
    // second parent is not.
    w.git("checkout", "-q", "-b", "side", w.m1);
    w.write("side.md", "side\n");
    const s1 = w.commit("s1: side");
    w.git("checkout", "-q", "main");
    w.git("merge", "-q", "--no-ff", "-m", "merge side", "side");
    const m3 = w.git("rev-parse", "HEAD");
    w.git("update-ref", "refs/remotes/origin/main", m3);
    w.git("checkout", "-q", "lane");
    w.git("merge", "-q", "-m", "take main", "main");
    expect(errs(w.supersession({ historicalSubject: s1 }))).to.match(
      /no commit of origin\/main's first-parent history/,
    );
    expect(errs(w.supersession({ historicalSubject: m3 }))).to.equal("");
  });

  it("supersedes exactly PROVING_AVAILABILITY, and only once the live availability validates and is archived", function () {
    this.timeout(60_000);
    const w = world();
    const errs = (s: ImplSupersession, live: LiveAvailability = ARCHIVED) =>
      implSupersessionErrors(s, RECEIPT, w.d, live).join("\n");
    expect(errs(w.supersession({ supersedes: [] }))).to.match(/supersedes must be exactly PROVING_AVAILABILITY/);
    expect(errs(w.supersession({ supersedes: ["PROVING_AVAILABILITY", "PRODUCTION_SP1_BINDING_STATUS"] }))).to.match(
      /supersedes must be exactly/,
    );
    for (const status of LIVE_AVAILABILITY_STATUSES) {
      expect(errs(w.supersession(), { errors: [], status })).to.match(
        new RegExp(`still ${status}: nothing superseded the receipt`),
      );
    }
    expect(errs(w.supersession(), { errors: ["the observation drifted"], status: null })).to.match(
      /does not validate, so nothing supersedes the receipt: the observation drifted/,
    );
    expect(errs(w.supersession(), { errors: [], status: null })).to.match(/still null/);
  });

  it("names its superseding records: the archive record first, each with a lane and a reason, each present", function () {
    this.timeout(60_000);
    const w = world();
    const errs = (s: ImplSupersession) => implSupersessionErrors(s, RECEIPT, w.d, ARCHIVED).join("\n");
    expect(errs(w.supersession({ supersededBy: [] }))).to.match(/at least one superseding record/);
    expect(
      errs(w.supersession({ supersededBy: [{ lane: "SP1-PA2B", record: "docs/notes.md", reason: "r" }] })),
    ).to.match(/must be the archive record under evidence\/zk\/sp1-impl\/proving-archives[\s\S]*does not exist/);
    expect(errs(w.supersession({ supersededBy: [{ lane: "", record: RECORD, reason: "" }] }))).to.match(
      /each superseding record has a lane and a reason/,
    );
    expect(
      errs(
        w.supersession({
          supersededBy: [{ lane: "SP1-PA2B", record: `${PROVING_ARCHIVES_DIR}/absent.json`, reason: "r" }],
        }),
      ),
    ).to.match(/does not exist/);
  });

  it("derives the superseded availability at the historical subject, read from git, and binds the supersession before the receipt", function () {
    this.timeout(60_000);
    const w = world();
    // Live: the working tree's bytes, judged by the live validator (in this tiny repository: invalid, no status).
    const live = provingAvailabilityInputs(w.d, null);
    expect(live.bytes.toString()).to.equal('{"status":"ARCHIVED_VERIFIED_UNEXERCISED"}\n');
    expect(live.errors.length).to.be.greaterThan(0);
    expect(live.status).to.equal(null);
    // Superseded: the file as the historical subject committed it, its status, and no live errors.
    const then = provingAvailabilityInputs(w.d, { commit: w.m1 });
    expect(then).to.deep.equal({
      errors: [],
      status: "OWNER_DOWNLOAD_REQUIRED",
      bytes: Buffer.from('{"status":"OWNER_DOWNLOAD_REQUIRED"}\n'),
    });
    expect(provingAvailabilityInputs(w.d, { commit: w.l1 }).status).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
    expect(() => provingAvailabilityInputs(w.d, { commit: "0".repeat(40) })).to.throw();
    // The binding: none while no supersession is filed; the subject when it validates; a refusal naming the reasons.
    expect(boundSupersession(w.d, ARCHIVED)).to.equal(null);
    w.write(IMPL_SUPERSESSION_REL, `${JSON.stringify(w.supersession(), null, 2)}\n`);
    expect(boundSupersession(w.d, ARCHIVED)).to.deep.equal({ commit: w.m1 });
    expect(() => boundSupersession(w.d, { errors: [], status: "OWNER_DOWNLOAD_REQUIRED" })).to.throw(
      /receipt-supersession\.json is invalid: proving availability is still OWNER_DOWNLOAD_REQUIRED/,
    );
    w.write(IMPL_SUPERSESSION_REL, `${JSON.stringify(w.supersession({ historicalSubject: w.l1 }), null, 2)}\n`);
    expect(() => boundSupersession(w.d, ARCHIVED)).to.throw(/no commit of origin\/main's first-parent history/);
  });

  it("the committed repository holds no supersession while proving availability is not archived", function () {
    const pa = JSON.parse(readFileSync(PROVING_AVAILABILITY_REL, "utf8"));
    const s = readImplSupersession(".");
    if (LIVE_AVAILABILITY_STATUSES.includes(pa.status)) expect(s).to.equal(null);
    else expect(s).to.not.equal(null);
  });
});
