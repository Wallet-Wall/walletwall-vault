/**
 * SP1-PA3C integration test: the REAL observer on a real Linux kernel, in self-test mode. Opt-in only, and skipped
 * explicitly (pending, with the reason) anywhere it cannot run; it never passes by not running.
 *
 *   SP1_EGRESS_OBSERVER_INTEGRATION=1 SP1_EGRESS_OBSERVER_USER=<unprivileged user who can read this checkout> \
 *     node node_modules/tsx/dist/cli.mjs node_modules/mocha/bin/mocha.js test/Sp1EgressObserverLinux.test.ts   # as root
 *
 * It creates a private nft table refusing only 192.0.2.0/24 (TEST-NET-1, never routed), copies the observer to a
 * root-owned directory (the observer refuses any other location), and runs `self-test`: the observer installs its
 * probes in a private tracefs instance and starts the fixed workload (test/fixtures/sp1-egress-observer/workload.mjs)
 * as the unprivileged user, which probes 192.0.2.10:443 before and after and, between HOST_SPAWN and HOST_EXIT, starts
 * a child that sends one DNS query for pa3c-selftest.example to 192.0.2.53. The raw evidence must normalize
 * deterministically and derive, with no refusal: the child's query attributed to the proof's scope with its name, the
 * probes to the tool, every refused packet joined, the counters reconciled exactly, nothing left in the kernel. It runs
 * no SP1, makes no proof, touches no evidence and reaches no real host. Research prototype. Not audited.
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

import {
  assuranceOf,
  normalizeObserverRaw,
  observerEvidenceErrors,
  reconcile,
  userDev,
  type HostExecutable,
} from "../scripts/lib/sp1-egress-attribution";
import { RAW_FACTS_FILE, RAW_MANIFEST_FILE, RAW_TRACE_FILE } from "../scripts/sp1-egress-observer";

const TABLE = "sp1obs_selftest";
const USER = process.env.SP1_EGRESS_OBSERVER_USER ?? "";
const nft = (args: string[]) => spawnSync("nft", args, { encoding: "utf8" });
const kprobes = () => readFileSync("/sys/kernel/tracing/kprobe_events", "utf8");

/** Why this host cannot run the integration test, or null when it can. */
function unsupported(): string | null {
  if (process.env.SP1_EGRESS_OBSERVER_INTEGRATION !== "1") return "opt-in only: set SP1_EGRESS_OBSERVER_INTEGRATION=1";
  if (process.platform !== "linux") return `tracefs is Linux-only (this is ${process.platform})`;
  if (process.getuid?.() !== 0) return "the observer needs root";
  if (!/^[a-z_][a-z0-9_-]*$/.test(USER))
    return "set SP1_EGRESS_OBSERVER_USER to an unprivileged user who can read this checkout";
  if (!existsSync("/sys/kernel/tracing/kprobe_events")) return "tracefs is not mounted at /sys/kernel/tracing";
  for (const tool of ["nft", "setpriv", "ip", "getent", "cat"]) {
    if (spawnSync("sh", ["-c", `command -v ${tool}`]).status !== 0) return `${tool} is not installed`;
  }
  return null;
}

describe("SP1-PA3C — the real observer on this kernel (integration, opt-in)", function () {
  this.timeout(240_000);
  let dir = "";
  before(function () {
    const why = unsupported();
    if (why !== null) {
      console.log(`      skipped: ${why}`);
      this.skip();
    }
    dir = mkdtempSync("/root/sp1obs-int-");
    // Written, not copied: a copy can keep the checkout owner's uid, and the observer refuses a file root does not own.
    writeFileSync(join(dir, "sp1-egress-observer.ts"), readFileSync("scripts/sp1-egress-observer.ts"), { mode: 0o644 });
    writeFileSync(join(dir, "package.json"), '{ "type": "module" }\n');
    // nft reads a ruleset from a regular file (it refuses a pipe on stdin).
    const rules = join(dir, "table.nft");
    writeFileSync(
      rules,
      `table inet ${TABLE} {\n  chain output {\n    type filter hook output priority -10; policy accept;\n    ip daddr 192.0.2.0/24 meta l4proto tcp counter reject with tcp reset\n    ip daddr 192.0.2.0/24 counter reject\n  }\n}\n`,
    );
    const made = nft(["-f", rules]);
    if (made.status !== 0) throw new Error(`could not create the test table: ${made.stderr}`);
  });
  after(function () {
    if (dir === "") return;
    nft(["delete", "table", "inet", TABLE]);
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses to run from a path a non-root user could change", function () {
    // A root-owned file in a directory anyone may write to (/tmp): the file itself is fine, its path is not.
    const loose = mkdtempSync("/tmp/sp1obs-loose-");
    try {
      chmodSync(loose, 0o777);
      writeFileSync(join(loose, "sp1-egress-observer.ts"), readFileSync("scripts/sp1-egress-observer.ts"), {
        mode: 0o644,
      });
      writeFileSync(join(loose, "package.json"), '{ "type": "module" }\n');
      const r = spawnSync(
        process.execPath,
        [
          join(loose, "sp1-egress-observer.ts"),
          "self-test",
          "--as",
          USER,
          "--repo",
          resolve("."),
          "--table",
          "inet",
          TABLE,
          "--raw-dir",
          join(dir, "never"),
        ],
        { encoding: "utf8" },
      );
      expect(r.status).to.not.equal(0);
      expect(r.stderr).to.match(/OBSERVER_PATH_NOT_ROOT_OWNED/);
      expect(r.stderr).to.include(`${loose} is writable by group or others`);
      expect(r.stderr).to.not.match(/owned by uid/);
      expect(existsSync(join(dir, "never"))).to.equal(false);
    } finally {
      rmSync(loose, { recursive: true, force: true });
    }
  });

  it("observes the workload end to end: attributes its attempts, reconciles the counters, leaves nothing behind", function () {
    const raw = join(dir, "raw");
    const r = spawnSync(
      process.execPath,
      [
        join(dir, "sp1-egress-observer.ts"),
        "self-test",
        "--as",
        USER,
        "--repo",
        resolve("."),
        "--table",
        "inet",
        TABLE,
        "--raw-dir",
        raw,
      ],
      { encoding: "utf8", timeout: 180_000 },
    );
    expect(r.status, `${r.stdout}\n${r.stderr}`).to.equal(0);
    expect(r.stderr).to.match(/probe before: ECONNREFUSED/);
    expect(r.stderr).to.match(/host udp EPERM/);
    expect(kprobes()).to.not.match(/sp1obs_/);
    expect(readdirSync("/sys/kernel/tracing/instances").filter((n) => n.startsWith("sp1obs_"))).to.deep.equal([]);
    const evidence = {
      trace: readFileSync(join(raw, RAW_TRACE_FILE), "latin1"),
      facts: readFileSync(join(raw, RAW_FACTS_FILE), "latin1"),
      manifest: readFileSync(join(raw, RAW_MANIFEST_FILE), "latin1"),
    };
    const exe = statSync(process.execPath, { bigint: true });
    const host: HostExecutable = { path: process.execPath, dev: userDev(exe.dev), ino: Number(exe.ino) };
    const o = normalizeObserverRaw(evidence, host);
    expect(normalizeObserverRaw(evidence, host).normalizedSha256).to.equal(o.normalizedSha256);
    const j = observerEvidenceErrors(o, {
      observerScriptSha256: o.tool.scriptSha256,
      mode: "SELF_TEST",
      probes: [
        { phase: "before", kind: "tcp", target: "192.0.2.10:443" },
        { phase: "after", kind: "tcp", target: "192.0.2.10:443" },
      ],
      gate: null,
      run: { commit: "0".repeat(40), host: "self-test" },
    });
    expect(j.refusals).to.deep.equal([]);
    const a = j.attribution as NonNullable<typeof j.attribution>;
    const proof = a.attempts.filter((x) => x.scope === "PROOF" && !x.delegated);
    expect(proof.map((x) => [x.probe, x.dest?.addr, x.dest?.port, x.outcome, x.dns?.qname])).to.deep.equal([
      ["udp4", "192.0.2.53", 53, "REFUSED", "pa3c-selftest.example"],
    ]);
    const tool = a.attempts.filter((x) => x.scope === "TOOL" && x.kind === "connect");
    expect(tool.map((x) => [x.dest?.addr, x.dest?.port, x.outcome])).to.deep.equal([
      ["192.0.2.10", 443, "REFUSED"],
      ["192.0.2.10", 443, "REFUSED"],
    ]);
    expect(a.drops.every((d) => d.class === "ATTEMPT_PACKET")).to.equal(true);
    const rec = reconcile(a.drops, a.markers, o.boundary);
    expect(rec).to.deep.include({ ok: true, counted: 3, inner: 3, outer: 3 });
    expect(assuranceOf(o, a)).to.deep.include({
      level: "CONTINUOUS_ATTRIBUTED",
      processAttribution: "COMPLETE",
      unattributedEvents: 0,
    });
  });
});
