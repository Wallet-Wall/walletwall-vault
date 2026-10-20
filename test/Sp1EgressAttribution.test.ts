/**
 * SP1-PA3C: continuous egress attribution (scripts/lib/sp1-egress-attribution.ts), driven through every case with
 * synthetic raw evidence written line for line in tracefs's own format (test/helpers/sp1EgressTrace.ts) and checked
 * against a real capture (test/fixtures/sp1-egress-observer/selftest-capture). No kernel, no network, no proof.
 *
 * What it pins: a raw line is read exactly or refused; the normalized evidence is deterministic and privacy-minimal;
 * every claim is derived from facts (coverage, continuity, who made each attempt, how each refused packet joins an
 * attempt or why not, the reconciliation with the boundary's counters, leaks); and the assurance a v1 run carries is
 * EDGE_PROBES_ONLY with nothing measured read into it. Research prototype. Not audited.
 */
import { expect } from "chai";
import { PassThrough } from "node:stream";

import {
  EDGE_PROBES_ONLY,
  MAX_HEARTBEAT_GAP_US,
  ObserverClient,
  assuranceOf,
  counterDelta,
  deriveAttribution,
  dnsQuestion,
  ip4,
  ip6,
  kernelDev,
  normalizeObserverRaw,
  normalizedSha256Of,
  observerEvidenceErrors,
  packetOf,
  parseTrace,
  parseTraceLine,
  port16,
  reconcile,
  userDev,
  type NormEvent,
  type ObserverEvidence,
  type ObserverExpectations,
  type RawEvidence,
} from "../scripts/lib/sp1-egress-attribution";
import { OBSERVER_SCRIPT_REL, formatCtl } from "../scripts/sp1-egress-observer";
import {
  BOOT_ID,
  CONTAINER_NETNS,
  HOST,
  HOST_ADDR,
  HOST_EXE,
  IDLE,
  NONCE_A,
  OBSERVER,
  OBSERVER_SHA,
  RESOLVER,
  STANDARD_PROBES,
  TOOL,
  TraceBuilder,
  facts,
  ipv4,
  rawOf,
  refusedConnect,
  refusedLookup,
  standardRaw,
  standardRun,
  tcp,
  udp,
  dnsQuery,
  type Proc,
} from "./helpers/sp1EgressTrace";

const PROBE_LIST: ObserverExpectations["probes"] = (["before", "after"] as const).flatMap((phase) => [
  ...STANDARD_PROBES.dns.map((t) => ({ phase, kind: "dns" as const, target: t })),
  ...STANDARD_PROBES.tcpByName.map((t) => ({ phase, kind: "tcp" as const, target: `${t}:443` })),
  ...STANDARD_PROBES.tcpByAddress.map((t) => ({ phase, kind: "tcp" as const, target: `${t}:443` })),
]);
const EXPECT: ObserverExpectations = {
  observerScriptSha256: OBSERVER_SHA,
  mode: "RUN",
  probes: PROBE_LIST,
  gate: { startedAtUtc: "2026-11-01T10:00:00Z", finishedAtUtc: "2026-11-01T11:59:40Z" },
  run: { commit: "c".repeat(40), host: "proving-host-a" },
};
const normalize = (raw: RawEvidence = standardRaw()) => normalizeObserverRaw(raw, HOST_EXE);
const judge = (o: ObserverEvidence, expect: ObserverExpectations = EXPECT) => observerEvidenceErrors(o, expect);
const reasons = (o: ObserverEvidence, expect?: ObserverExpectations) => judge(o, expect).refusals.map((r) => r.reason);
/** Re-digests an edited observer section, so only the layer under test can refuse it. */
function resealed(o: ObserverEvidence, edit: (x: ObserverEvidence) => void): ObserverEvidence {
  const c = structuredClone(o);
  edit(c);
  const { normalizedSha256: _drop, ...body } = c;
  return { ...c, normalizedSha256: normalizedSha256Of(body) };
}
const OTHER: Proc = { comm: "systemd-timesyn", tid: 777, tgid: 777 };

describe("SP1-PA3C — continuous egress attribution", function () {
  describe("parse: one raw line, exactly", function () {
    // Real lines, as the WSL2 kernel printed them during the integration self-test.
    const real = {
      marker:
        "      MainThread-1727    (   1727) [002] ...1.    35.718469: tracing_mark_write: SP1OBS 7037f3dae02c457f 7 PHASE name=PROBES_BEFORE_BEGIN",
      tcp4: '      MainThread-1740    (   1740) [011] .....    35.719196: tcp4: (tcp_v4_connect+0x4/0x520) sk=0xffff89448a87d340 fam=2 port=0xbb01 addr=0xa0200c0 netns=4026531833 comm="MainThread"',
      ret: "      MainThread-1740    (   1740) [011] .....    35.719334: tcp4ret: (__inet_stream_connect+0x10c/0x3a0 <- tcp_v4_connect) ret=0 sk=0xffff89448a87d340 sport=38036",
      idle: "          <idle>-0       (-------) [000] ..s2.     5.801579: tcpst: (tcp_set_state+0x4/0x230) sk=0xffff8cab0a8ea500 state=1 old=2",
    };

    it("reads a real marker, a probe, a return probe and an idle-context event", function () {
      const m = parseTraceLine(real.marker, 0);
      expect([m.comm, m.tid, m.tgid, m.cpu, m.flags, m.t, m.event, m.marker]).to.deep.equal([
        "MainThread",
        1727,
        1727,
        2,
        "...1.",
        35_718_469,
        "tracing_mark_write",
        "SP1OBS 7037f3dae02c457f 7 PHASE name=PROBES_BEFORE_BEGIN",
      ]);
      const c = parseTraceLine(real.tcp4, 1);
      expect(c.fields).to.deep.equal({
        sk: "0xffff89448a87d340",
        fam: 2,
        port: 0xbb01,
        addr: 0xa0200c0,
        netns: 4026531833,
        comm: "MainThread",
      });
      expect(ip4(c.fields?.addr as number)).to.equal("192.0.2.10");
      expect(port16(c.fields?.port as number)).to.equal(443);
      expect(parseTraceLine(real.ret, 2).fields).to.deep.equal({ ret: 0, sk: "0xffff89448a87d340", sport: 38036 });
      const idle = parseTraceLine(real.idle, 3);
      expect([idle.comm, idle.tid, idle.tgid, idle.flags]).to.deep.equal(["<idle>", 0, null, "..s2."]);
    });

    it("refuses a line that does not read exactly: position, order, extra or missing fields, types, unknown events", function () {
      const bad = [
        real.tcp4.slice(1), // the comm column shifted: column 16 is no longer the separator
        real.tcp4.replace("fam=2 port=0xbb01", "port=0xbb01 fam=2"), // fields out of their defined order
        real.tcp4.replace(' comm="MainThread"', ""), // a field missing
        real.tcp4.replace('comm="MainThread"', 'comm="MainThread" extra=1'), // a field the probe never prints
        real.tcp4.replace("fam=2", "fam=x2"), // not its type
        real.tcp4.replace("addr=0xa0200c0", "addr=0xa0200c0 "), // trailing text
        real.tcp4.replace(": tcp4:", ": tcp9:"), // an event the observer never defined
        real.tcp4.replace('comm="MainThread"', `comm="${"x".repeat(16)}"`), // a comm longer than the kernel's 15 bytes
        real.tcp4.replace("(tcp_v4_connect+0x4/0x520) ", ""), // no probe location
      ];
      for (const line of bad) expect(() => parseTraceLine(line, 0), line).to.throw();
    });

    it("refuses an array with the wrong number of elements or an element out of range", function () {
      const b = new TraceBuilder();
      b.drop(TOOL, "0x0", ipv4("1.2.3.4", "5.6.7.8", 17, udp(1, 2, [])));
      const line = b.lines[0];
      expect(() => parseTraceLine(line.replace("h0={0x45,", "h0={"), 0)).to.throw();
      expect(() => parseTraceLine(line.replace("h0={0x45,", "h0={0x145,"), 0)).to.throw();
      expect(parseTraceLine(line, 0).fields?.h0).to.have.length(64);
    });

    it("a newline inside a string breaks the trace into lines that do not read: refused, never repaired", function () {
      const broken = `${real.tcp4.replace('comm="MainThread"', 'comm="Main')}\nThread"\n`;
      expect(() => parseTrace(broken)).to.throw(/line 0: (tcp4\.comm does not read|not a trace line)/);
    });

    it("counts lost-events lines, and refuses a trace that ends inside a line", function () {
      expect(parseTrace(`${real.marker}\nCPU:3 [LOST 17 EVENTS]\n${real.ret}\n`).lost).to.equal(1);
      expect(parseTrace("").events).to.deep.equal([]);
      expect(() => parseTrace(real.marker)).to.throw(/ends inside a line/);
    });
  });

  describe("addresses and packets", function () {
    it("reads addresses and ports the way the kernel printed them", function () {
      expect(ip4(0x350200c0)).to.equal("192.0.2.53");
      expect(port16(0x3500)).to.equal(53);
      const v6 = [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 0x53];
      expect(ip6(v6)).to.equal("2001:db8::53");
      expect(ip6([...new Array(15).fill(0), 1])).to.equal("::1");
      expect(ip6([...new Array(10).fill(0), 0xff, 0xff, 192, 0, 2, 1])).to.equal("192.0.2.1");
      expect(ip6([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8])).to.equal("1:2:3:4:5:6:7:8");
      expect(() => ip6([1, 2])).to.throw();
      expect(kernelDev(8388656)).to.equal("8:48");
      expect(userDev(2096n)).to.equal("8:48");
      expect(userDev((259n << 8n) | 3n)).to.equal("259:3");
    });

    it("decodes a DNS question, marks a truncated one, and refuses names that do not decode", function () {
      const q = dnsQuery(0x1234, "Sp1-Circuits.example");
      expect(dnsQuestion(q, 0, q.length)).to.deep.equal({ id: 0x1234, qname: "sp1-circuits.example" });
      expect(dnsQuestion(q, 0, 20)).to.deep.include({ truncated: true });
      const bad = [...q.slice(0, 12), 3, 0x41, 0x0a, 0x42, 0];
      expect(dnsQuestion(bad, 0, bad.length)).to.deep.equal({ id: 0x1234, qname: null, undecodable: true });
      const pointer = [...q.slice(0, 12), 0xc0, 12];
      expect(dnsQuestion(pointer, 0, pointer.length)).to.deep.equal({ id: 0x1234, qname: null, undecodable: true });
      expect(dnsQuestion(q, 0, 11)).to.equal(null);
    });

    it("reads the refused packet's headers: UDP with its DNS question, TCP flags, an ICMP error's quoted packet", function () {
      const query = ipv4("10.0.0.1", RESOLVER, 17, udp(5555, 53, dnsQuery(7, "ghcr.io")));
      expect(packetOf(query, query.length)).to.deep.equal({
        v: 4,
        proto: 17,
        src: "10.0.0.1",
        dst: RESOLVER,
        sport: 5555,
        dport: 53,
        dns: { id: 7, qname: "ghcr.io" },
      });
      const syn = ipv4(HOST_ADDR, "1.1.1.1", 6, tcp(40000, 443, 0x02));
      expect(packetOf(syn, syn.length)).to.deep.include({ proto: 6, dport: 443, tcpFlags: 2 });
      const icmp = ipv4(RESOLVER, RESOLVER, 1, [3, 3, 0, 0, 0, 0, 0, 0, ...query.slice(0, 28)]);
      expect(packetOf(icmp, icmp.length)).to.deep.include({ icmp: { type: 3, code: 3 } });
      expect(packetOf(icmp, icmp.length).inner).to.deep.equal({
        proto: 17,
        src: "10.0.0.1",
        dst: RESOLVER,
        sport: 5555,
        dport: 53,
      });
      expect(packetOf([], 0)).to.deep.equal({ v: null, proto: null, src: null, dst: null, sport: null, dport: null });
    });
  });

  describe("normalize: raw evidence -> the committed observer section", function () {
    it("is deterministic and binds the raw files by the manifest", function () {
      const raw = standardRaw();
      const a = normalize(raw);
      expect(normalize(raw).normalizedSha256).to.equal(a.normalizedSha256);
      expect(a.tool).to.deep.equal({ script: OBSERVER_SCRIPT_REL, scriptSha256: OBSERVER_SHA });
      expect(a.raw.files.map((f) => f.name)).to.deep.equal(["trace.txt", "facts.json"]);
      expect(() =>
        normalizeObserverRaw({ ...raw, trace: raw.trace.replace("PROBES_BEFORE_END", "PROBES_BEFORE_END ") }, HOST_EXE),
      ).to.throw(/does not bind trace.txt/);
      expect(() => normalizeObserverRaw({ ...raw, facts: raw.facts.replace('"RUN"', '"RUN" ') }, HOST_EXE)).to.throw(
        /does not bind facts.json/,
      );
      const extra = rawOf(standardRun().trace, facts(), [{ name: "other.txt", text: "x" }]);
      expect(() => normalizeObserverRaw(extra, HOST_EXE)).to.throw(/names other files/);
      expect(() =>
        normalizeObserverRaw({ ...raw, manifest: raw.manifest.replace("raw.v1", "raw.v0") }, HOST_EXE),
      ).to.throw(/not the observer's/);
    });

    it("derives nothing from a failed observer or facts of another schema", function () {
      expect(() => normalize(standardRaw({}, { failures: ["OBSERVER_LOSS: 3 events lost"] }))).to.throw(
        /the observer failed/,
      );
      const f = facts() as Record<string, unknown>;
      f.schema = "walletwall.sp1-egress-observer-facts.v0";
      expect(() => normalizeObserverRaw(rawOf(standardRun().trace, f), HOST_EXE)).to.throw(/not the observer's/);
    });

    it("keeps lineage at process level: thread creations and non-leader exits are not committed", function () {
      const raw = standardRaw({
        duringProof: (b) => {
          b.spawn(HOST, 2001, { thread: true });
          b.exit({ comm: "worker", tid: 2001, tgid: HOST.tgid });
        },
      });
      const o = normalize(raw);
      expect(o.events.some((e) => e.k === "spawn" && e.child === 2001)).to.equal(false);
      expect(o.events.some((e) => e.k === "exit" && e.tid === 2001)).to.equal(false);
    });

    it("withholds what lies outside the proof's scope: another process's DNS name, exec paths, spawn names", function () {
      const raw = standardRaw({
        beforeWindow: (b) => {
          b.spawn({ comm: "systemd", tid: 1, tgid: 1 }, OTHER.tid).exec(OTHER, "/usr/lib/systemd/systemd-timesyncd");
          refusedLookup(b, OTHER, "0xffff888000077700", "ntp.ubuntu.com", 51000);
        },
        duringProof: (b) =>
          refusedLookup(b, HOST, "0xffff888000055500", "sp1-circuits.s3-us-east-2.amazonaws.com", 52000),
      });
      const o = normalize(raw);
      const qnames = o.events.flatMap((e) => (e.k === "drop" && e.packet.dns ? [e.packet.dns] : []));
      expect(qnames.some((q) => q.qname === "sp1-circuits.s3-us-east-2.amazonaws.com")).to.equal(true);
      expect(qnames.some((q) => q.qname === "ntp.ubuntu.com")).to.equal(false);
      expect(qnames.filter((q) => q.withheld === true)).to.have.length(1);
      expect(o.events.some((e) => e.k === "exec" && e.path === "/usr/lib/systemd/systemd-timesyncd")).to.equal(false);
      const spawn = o.events.find((e) => e.k === "spawn" && e.child === OTHER.tid) as Extract<
        NormEvent,
        { k: "spawn" }
      >;
      expect(spawn.comm).to.equal(null);
      // The attempt itself stays attributed: process, address and outcome are the security fact.
      expect(o.events.some((e) => e.k === "send" && e.tgid === OTHER.tgid && e.comm === OTHER.comm)).to.equal(true);
      expect(judge(o).refusals).to.deep.equal([]);
    });
  });

  describe("derive: coverage and continuity", function () {
    it("accepts the standard run: no refusal, the whole window covered", function () {
      const j = judge(normalize());
      expect(j.refusals).to.deep.equal([]);
      expect(j.attribution?.window).to.not.equal(null);
      expect(j.attribution?.heartbeats).to.be.greaterThan(300);
    });

    it("refuses a capture that does not cover the run: any required marker missing, from READY to STOP", function () {
      for (const omit of [
        "READY",
        "COUNTERS_BEGIN:1",
        "COUNTERS_END:1",
        "SPAWNED",
        "HELLO",
        "PHASE:PROBES_BEFORE_BEGIN",
        "PHASE:PROBES_BEFORE_END",
        "PHASE:GATE_BEGIN",
        "PHASE:HOST_SPAWN",
        "PHASE:HOST_EXIT",
        "PHASE:GATE_END",
        "PHASE:PROBES_AFTER_BEGIN",
        "PHASE:PROBES_AFTER_END",
        "TOOL_DONE",
        "COUNTERS_BEGIN:2",
        "COUNTERS_END:2",
        "STOP",
      ]) {
        const raw = standardRaw({ omit: [omit] });
        let got: string[];
        try {
          got = reasons(normalize(raw));
        } catch {
          continue; // the lineage itself cannot be derived (no READY): nothing is normalized at all
        }
        expect(got, omit).to.include("OBSERVER_COVERAGE");
      }
    });

    it("refuses an observer that started late, stopped early, or marked out of order (deriveAttribution itself)", function () {
      const o = normalize();
      const markers = o.events.filter((e): e is Extract<NormEvent, { k: "marker" }> => e.k === "marker");
      const at = (kind: string) => markers.findIndex((m) => m.text.includes(` ${kind}`));
      const swap = (a: string, b: string) => {
        const ev = structuredClone(o.events);
        const ia = o.events.indexOf(markers[at(a)]);
        const ib = o.events.indexOf(markers[at(b)]);
        const ta = (ev[ia] as { text: string }).text;
        (ev[ia] as { text: string }).text = (ev[ib] as { text: string }).text;
        (ev[ib] as { text: string }).text = ta;
        return deriveAttribution(ev, ctxOf(o)).refusals.map((r) => r.reason);
      };
      expect(swap("READY", "name=PROBES_BEFORE_BEGIN")).to.include("OBSERVER_COVERAGE");
      expect(swap("STOP", "name=PROBES_AFTER_END")).to.include("OBSERVER_COVERAGE");
      expect(swap("name=HOST_SPAWN", "name=HOST_EXIT")).to.include("OBSERVER_COVERAGE");
    });

    it("refuses a marker repeated, missing from the sequence, of another nonce, or by a second writer", function () {
      const dup = standardRaw({ endOfWindow: (b) => b.marker("PHASE", { name: "GATE_BEGIN" }) });
      expect(reasons(normalize(dup))).to.include.members(["OBSERVER_MARKERS"]);
      const skipped = standardRaw({ endOfWindow: (b) => void (b.seq += 1) });
      expect(reasons(normalize(skipped))).to.include("OBSERVER_MARKERS");
      const foreign = standardRaw({
        endOfWindow: (b) => b.marker("HEARTBEAT", { n: 1 }, { nonce: "f".repeat(16), seq: 1 }),
      });
      expect(reasons(normalize(foreign))).to.include("OBSERVER_FOREIGN_MARKER");
      const writer = standardRaw({
        endOfWindow: (b) => b.marker("CONTAINER", { id: "a".repeat(64), pid: 1, netns: "unknown" }, { writer: TOOL }),
      });
      expect(reasons(normalize(writer))).to.include("OBSERVER_MARKERS");
      const text = standardRaw({
        endOfWindow: (b) =>
          b.raw(TraceBuilder.line(OBSERVER, 0, "...1.", b.t + 1, "tracing_mark_write", "hello world")),
      });
      expect(reasons(normalize(text))).to.include("OBSERVER_FOREIGN_MARKER");
    });

    it("refuses a failure the observer marked, a stalled observer, a lost heartbeat and lost events", function () {
      expect(
        reasons(normalize(standardRaw({ duringProof: (b) => b.marker("FAIL", { code: "OBSERVER_LOSS" }) }))),
      ).to.include("OBSERVER_FAILED");
      // A gap: the clock jumps beyond the bound between two heartbeats.
      const stalled = standardRaw({
        duringProof: (b) => {
          b.t += MAX_HEARTBEAT_GAP_US * 3;
        },
      });
      expect(reasons(normalize(stalled))).to.include("OBSERVER_GAP");
      expect(reasons(normalize(standardRaw({ heartbeatEvery: MAX_HEARTBEAT_GAP_US + 1_000_000 })))).to.include(
        "OBSERVER_GAP",
      );
      const o = normalize();
      const beats = o.events.filter((e) => e.k === "marker" && e.text.includes(" HEARTBEAT "));
      const lossy = resealed(o, (x) => {
        const k = x.events.findIndex((e) => e.i === beats[5].i);
        (x.events[k] as { text: string }).text = (x.events[k] as { text: string }).text.replace("loss=0", "loss=4");
      });
      expect(reasons(lossy)).to.include("OBSERVER_LOSS");
      const n = resealed(o, (x) => {
        const k = x.events.findIndex((e) => e.i === beats[5].i);
        (x.events[k] as { text: string }).text = (x.events[k] as { text: string }).text.replace(/ n=\d+ /, " n=999 ");
      });
      expect(reasons(n)).to.include("OBSERVER_GAP");
      expect(reasons(resealed(o, (x) => (x.stats[0].droppedEvents = 1)))).to.include("OBSERVER_LOSS");
      expect(reasons(resealed(o, (x) => (x.stats[2].overrun = 5)))).to.include("OBSERVER_LOSS");
      expect(reasons(resealed(o, (x) => (x.lostLines = 1)))).to.include("OBSERVER_LOSS");
      expect(reasons(resealed(o, (x) => (x.stats = [])))).to.include("OBSERVER_LOSS");
    });

    it("needs a heartbeat on each side of the window", function () {
      const o = normalize();
      const beats = o.events.filter((e) => e.k === "marker" && e.text.includes(" HEARTBEAT "));
      const last = beats.at(-1) as NormEvent;
      const noAfter = o.events.filter(
        (e) => !(e.k === "marker" && e.text.includes(" HEARTBEAT ") && e.i > (beats.at(-3) as NormEvent).i),
      );
      expect(deriveAttribution(noAfter, ctxOf(o)).refusals.map((r) => r.reason)).to.include("OBSERVER_GAP");
      expect(last.i).to.be.greaterThan(0);
    });

    it("refuses a capture of another mode, another boot or namespace, or with a clock that is not the observer's", function () {
      const o = normalize();
      expect(reasons(o, { ...EXPECT, mode: "SELF_TEST" })).to.include("OBSERVER_MODE");
      expect(reasons(resealed(o, (x) => (x.bootId = "00000000-0000-0000-0000-000000000000")))).to.include(
        "OBSERVER_HOST",
      );
      expect(reasons(resealed(o, (x) => (x.host.netns = 4026539999)))).to.include.members([
        "OBSERVER_CONFIG_NOT_BOUND",
        "OBSERVER_HOST",
      ]);
      const late = resealed(o, (x) => {
        const k = x.events.findIndex((e) => e.k === "marker" && e.text.includes(" READY "));
        (x.events[k] as { text: string }).text = (x.events[k] as { text: string }).text.replace(
          /monoNs=\d+/,
          "monoNs=1",
        );
      });
      expect(reasons(late)).to.include("OBSERVER_CLOCK");
      const gate = { ...EXPECT, gate: { startedAtUtc: "2026-11-01T08:00:00Z", finishedAtUtc: "2026-11-01T11:59:40Z" } };
      expect(reasons(o, gate)).to.include("OBSERVER_CLOCK");
    });

    it("refuses an empty capture: no marker, no coverage, no lineage", function () {
      const empty = rawOf("", facts());
      const o = normalizeObserverRaw(empty, HOST_EXE);
      expect(o.events).to.deep.equal([]);
      expect(reasons(o)).to.include.members(["OBSERVER_COVERAGE", "OBSERVER_LINEAGE", "HOST_NOT_OBSERVED"]);
    });
  });

  describe("derive: who made each attempt", function () {
    it("attributes the proof host's refused DNS lookup to PROOF, with the name it asked", function () {
      const o = normalize(
        standardRaw({ duringProof: (b) => refusedLookup(b, HOST, "0xffff888000055500", "ghcr.io", 52000) }),
      );
      const a = judge(o).attribution?.attempts.find((x) => x.tgid === HOST.tgid);
      expect(a).to.deep.include({ scope: "PROOF", outcome: "REFUSED", destClass: "RESOLVER" });
      expect(a?.dns?.qname).to.equal("ghcr.io");
      expect(a?.responses).to.have.length(1); // the boundary's own ICMP answer, refused by the same rule
      expect(judge(o).refusals).to.deep.equal([]);
    });

    it("attributes another process's lookup to OTHER (its name withheld), and a docker CLI the host started to PROOF", function () {
      const o = normalize(
        standardRaw({
          beforeWindow: (b) => refusedLookup(b, OTHER, "0xffff888000077700", "ntp.ubuntu.com", 51000),
          duringProof: (b) => {
            const cli: Proc = { comm: "docker", tid: 1020, tgid: 1020 };
            b.spawn(HOST, 1020).exec(cli, "/usr/bin/docker");
            refusedConnect(b, cli, "0xffff888000066600", "140.82.112.34", 443, 53000);
          },
        }),
      );
      const j = judge(o).attribution;
      expect(j?.attempts.find((x) => x.tgid === OTHER.tgid)).to.deep.include({ scope: "OTHER", outcome: "REFUSED" });
      expect(j?.attempts.find((x) => x.tgid === OTHER.tgid)?.dns).to.deep.include({ qname: null, withheld: true });
      expect(j?.attempts.find((x) => x.tgid === 1020)).to.deep.include({
        scope: "PROOF",
        outcome: "REFUSED",
        destClass: "EGRESS",
      });
    });

    it("attributes a direct TCP attempt, its retransmission and an attempt whose process exits at once", function () {
      const retx = (b: TraceBuilder) => {
        b.tcp4(HOST, "0xffff888000044400", "3.5.90.58", 443);
        b.tcpst(HOST, "0xffff888000044400", 7, 2);
        b.drop(HOST, "0xffff888000044400", ipv4(HOST_ADDR, "3.5.90.58", 6, tcp(54000, 443, 0x02)));
        b.tcp4ret(HOST, "0xffff888000044400", 0, 54000);
        b.drop(IDLE, "0xffff888000044400", ipv4(HOST_ADDR, "3.5.90.58", 6, tcp(54000, 443, 0x02)), { flags: "..s2." });
        b.tcpst(IDLE, "0xffff888000044400", 2, 7, "..s2.");
      };
      const quick: Proc = { comm: "curl", tid: 1030, tgid: 1030 };
      const o = normalize(
        standardRaw({
          duringProof: (b) => {
            retx(b);
            b.spawn(HOST, 1030);
            refusedConnect(b, quick, "0xffff888000033300", "8.8.4.4", 443, 55000);
            b.exit(quick);
          },
        }),
      );
      const j = judge(o).attribution;
      const a = j?.attempts.find((x) => x.sk === "0xffff888000044400");
      expect(a).to.deep.include({ scope: "PROOF", outcome: "REFUSED" });
      expect(a?.packets).to.have.length(2);
      expect(j?.drops.filter((d) => d.attempt?.i === a?.i).map((d) => d.class)).to.deep.equal([
        "ATTEMPT_PACKET",
        "ATTEMPT_PACKET",
      ]);
      expect(j?.attempts.find((x) => x.tgid === 1030)).to.deep.include({
        scope: "PROOF",
        outcome: "REFUSED",
        comm: "curl",
      });
    });

    it("attributes a container's datagram and connection by addresses and ports, refused in the host (no socket crosses)", function () {
      const c: Proc = { comm: "MainThread", tid: 3010, tgid: 3010 };
      const gnark = "f".repeat(64);
      const o = normalize(
        standardRaw({
          duringProof: (b) => {
            b.marker("CONTAINER", { id: gnark, pid: 4321, netns: CONTAINER_NETNS });
            b.udp4(c, "0xffff888000022200", RESOLVER, 53, { netns: CONTAINER_NETNS });
            b.udp4ret(c, "0xffff888000022200", 39, 36662);
            b.drop(c, "0x0", ipv4("172.17.0.2", RESOLVER, 17, udp(36662, 53, dnsQuery(9, "ghcr.io"))), {
              flags: "..s1.",
            });
            // The forwarded SYN is refused in softirq BEFORE the container's connect returns (as measured).
            b.tcp4(c, "0xffff888000011100", "192.0.2.81", 80, 4026532300);
            b.drop(c, "0x0", ipv4("172.17.0.2", "192.0.2.81", 6, tcp(50746, 80, 0x02)), { flags: ".Ns1." });
            b.tcp4ret(c, "0xffff888000011100", 0, 50746);
            b.tcpst(c, "0xffff888000011100", 2, 7);
          },
        }),
      );
      const j = judge(o).attribution;
      expect(j?.attempts.find((x) => x.sk === "0xffff888000022200")).to.deep.include({
        scope: "PROOF_CONTAINER",
        outcome: "REFUSED",
      });
      expect(j?.attempts.find((x) => x.sk === "0xffff888000022200")?.dns?.qname).to.equal("ghcr.io");
      expect(j?.attempts.find((x) => x.sk === "0xffff888000011100")).to.deep.include({
        scope: "CONTAINER",
        outcome: "REFUSED",
      });
      expect(j?.drops.filter((d) => d.class === "UNATTRIBUTED")).to.deep.equal([]);
    });

    it("counts every retry of one DNS request as its own refused attempt, with the same question", function () {
      const o = normalize(
        standardRaw({
          duringProof: (b) => {
            for (let k = 0; k < 4; k++)
              refusedLookup(b, HOST, `0xffff88800000a10${k}`, "ghcr.io", 56000 + k, { id: 0x4242 });
          },
        }),
      );
      const tries = judge(o).attribution?.attempts.filter((x) => x.tgid === HOST.tgid) ?? [];
      expect(tries.map((x) => [x.outcome, x.dns?.id, x.dns?.qname])).to.deep.equal(
        new Array(4).fill(["REFUSED", 0x4242, "ghcr.io"]),
      );
    });

    it("names an unknown process OTHER and a context without a process KERNEL; a reply the kernel sent is KERNEL_RESPONSE", function () {
      const stranger: Proc = { comm: "x", tid: 31337, tgid: 31337 };
      const o = normalize(
        standardRaw({
          duringProof: (b) => {
            refusedConnect(b, stranger, "0xffff888000099900", "9.9.9.9", 443, 57000);
            b.drop(IDLE, "0x0", ipv4(HOST_ADDR, "203.0.113.200", 6, tcp(22, 61000, 0x14)), { flags: "..s2." });
          },
        }),
      );
      const j = judge(o).attribution;
      expect(j?.attempts.find((x) => x.tgid === 31337)?.scope).to.equal("OTHER");
      expect(j?.drops.find((d) => d.class === "KERNEL_RESPONSE")).to.not.equal(undefined);
    });

    it("names a refused packet no observed attempt sent UNATTRIBUTED: recorded, counted, and the assurance says PARTIAL", function () {
      const o = normalize(
        standardRaw({
          duringProof: (b) =>
            b.drop(IDLE, "0x0", ipv4(HOST_ADDR, "198.51.100.7", 17, udp(1234, 9999, [1, 2, 3])), { flags: "..s2." }),
        }),
      );
      const j = judge(o);
      expect(j.refusals).to.deep.equal([]);
      expect(j.attribution?.drops.filter((d) => d.class === "UNATTRIBUTED")).to.have.length(1);
      const a = assuranceOf(o, j.attribution as NonNullable<typeof j.attribution>);
      expect([a.level, a.processAttribution, a.unattributedEvents]).to.deep.equal([
        "CONTINUOUS_PARTIALLY_ATTRIBUTED",
        "PARTIAL",
        1,
      ]);
    });

    it("places events by their position in the trace: outside the window, and exactly at its boundaries", function () {
      const o = normalize(
        standardRaw({
          beforeWindow: (b) => refusedConnect(b, OTHER, "0xffff888000088800", "4.4.4.4", 443, 58000),
          afterWindow: (b) => refusedConnect(b, OTHER, "0xffff888000088801", "4.4.4.5", 443, 58001),
        }),
      );
      const j = judge(o).attribution;
      const inWindow = (i: number) =>
        j?.window !== null && j?.window !== undefined && i > j.window.begin && i < j.window.end;
      const before = j?.attempts.find((x) => x.sk === "0xffff888000088800");
      const after = j?.attempts.find((x) => x.sk === "0xffff888000088801");
      expect(inWindow(before?.i ?? -1)).to.equal(false);
      expect(inWindow(after?.i ?? -1)).to.equal(false);
      expect(before?.phase).to.equal("COUNTERS_END:1");
      expect(after?.phase).to.equal("PHASE:PROBES_AFTER_END");
      // The same stamp as a marker: still ordered by position (the kernel merged the CPUs in time order).
      const tied = structuredClone(o.events);
      const k = tied.findIndex((e) => e.k === "marker" && e.text.includes("name=PROBES_BEFORE_BEGIN"));
      tied[k + 1] = { ...tied[k + 1], t: tied[k].t };
      expect(deriveAttribution(tied, ctxOf(o)).refusals).to.deep.equal([]);
    });

    it("refuses a return with no attempt open on its thread, and counts a delegated (IPv4-mapped) send once", function () {
      const o = normalize(standardRaw({ duringProof: (b) => b.udp4ret(HOST, "0xffff888000012300", -1, 1) }));
      expect(reasons(o)).to.include("OBSERVER_EVENT_INCONSISTENT");
      const mapped = normalize(
        standardRaw({
          duringProof: (b) => {
            b.probe(HOST, "udp6", {
              sk: "0xffff888000012400",
              len: 39,
              namelen: 28,
              nfam: 10,
              nport: 0x3500,
              na: [0, 0, 0xffff0000, 0xfeffff0a],
              dport: 0,
              da: [0, 0, 0, 0],
              netns: 4026531833,
            });
            b.udp4(HOST, "0xffff888000012400", RESOLVER, 53, { connected: true });
            b.drop(HOST, "0xffff888000012400", ipv4(RESOLVER, RESOLVER, 17, udp(59000, 53, dnsQuery(5, "ghcr.io"))));
            b.udp4ret(HOST, "0xffff888000012400", -1, 59000);
            b.probe(HOST, "udp6ret", { ret: -1, sk: "0xffff888000012400", sport: 59000 });
          },
        }),
      );
      const j = judge(mapped).attribution;
      const both = j?.attempts.filter((x) => x.sk === "0xffff888000012400") ?? [];
      expect(both.map((x) => x.delegated)).to.deep.equal([false, true]);
      expect(both[0]).to.deep.include({ outcome: "REFUSED", probe: "udp6" });
      expect(both[0].dest).to.deep.equal({ addr: RESOLVER, port: 53 });
      expect(assuranceOf(mapped, j as NonNullable<typeof j>).events?.byScope.PROOF).to.equal(1);
    });
  });

  describe("derive: leaks the boundary let through", function () {
    it("refuses a transmit through the uplink inside the window", function () {
      const frame = [...new Array(12).fill(0), 0x08, 0x00, ...ipv4(HOST_ADDR, "93.184.216.34", 6, tcp(1, 443, 0x02))];
      expect(reasons(normalize(standardRaw({ duringProof: (b) => b.xmit(HOST, 2, frame) })))).to.include(
        "EGRESS_LEAKED",
      );
      // On the docker bridge (not an uplink), or after the window: not egress through the boundary's window.
      expect(reasons(normalize(standardRaw({ duringProof: (b) => b.xmit(HOST, 3, frame) })))).to.not.include(
        "EGRESS_LEAKED",
      );
      expect(reasons(normalize(standardRaw({ afterWindow: (b) => b.xmit(HOST, 2, frame) })))).to.not.include(
        "EGRESS_LEAKED",
      );
    });

    it("refuses a send that went out unrefused, or a connection that was established, to an address beyond the VM", function () {
      const sent = standardRaw({
        duringProof: (b) => {
          b.udp4(HOST, "0xffff888000013300", "1.0.0.1", 53);
          b.udp4ret(HOST, "0xffff888000013300", 39, 60000);
        },
      });
      expect(reasons(normalize(sent))).to.include("EGRESS_LEAKED");
      const established = standardRaw({
        duringProof: (b) => {
          b.tcp4(HOST, "0xffff888000013400", "93.184.216.34", 443);
          b.tcpst(HOST, "0xffff888000013400", 7, 2);
          b.tcp4ret(HOST, "0xffff888000013400", 0, 60001);
          b.tcpst(IDLE, "0xffff888000013400", 2, 1, "..s2.");
        },
      });
      expect(reasons(normalize(established))).to.include("EGRESS_LEAKED");
      // To the host itself or a container bridge it is not egress.
      const local = standardRaw({
        duringProof: (b) => {
          b.udp4(HOST, "0xffff888000013500", "127.0.0.1", 9);
          b.udp4ret(HOST, "0xffff888000013500", 1, 60002);
          b.udp4(HOST, "0xffff888000013600", "172.17.0.5", 9);
          b.udp4ret(HOST, "0xffff888000013600", 1, 60003);
        },
      });
      expect(reasons(normalize(local))).to.not.include("EGRESS_LEAKED");
    });
  });

  describe("reconcile: the observer's refused packets against the boundary's counters", function () {
    it("is exact for the standard run, and bounded by the counters' read brackets", function () {
      const o = normalize();
      const j = judge(o).attribution as NonNullable<ReturnType<typeof judge>["attribution"]>;
      const r = reconcile(j.drops, j.markers, o.boundary);
      expect(r.ok).to.equal(true);
      expect(r.counted).to.equal(r.inner);
      expect(r.inner).to.equal(r.outer);
      expect(r.counted).to.be.greaterThan(0);
    });

    it("refuses a count the observer did not see (an observation gap) or a drop the table did not count (another boundary)", function () {
      const { trace, counted } = standardRun();
      const before = { resolver: 10, tcp: 3, other: 1 };
      const more = { resolver: 10 + counted.resolver, tcp: 3 + counted.tcp + 1, other: 1 + counted.other };
      expect(reasons(normalizeObserverRaw(rawOf(trace, facts({ counters: [before, more] })), HOST_EXE))).to.include(
        "BOUNDARY_RECONCILIATION",
      );
      const fewer = { resolver: 10 + counted.resolver - 1, tcp: 3 + counted.tcp, other: 1 + counted.other };
      expect(reasons(normalizeObserverRaw(rawOf(trace, facts({ counters: [before, fewer] })), HOST_EXE))).to.include(
        "BOUNDARY_RECONCILIATION",
      );
    });

    it("accepts a drop that fell while nft read the counters within the bracket, never outside it", function () {
      const b = standardRun({ beforeWindow: () => undefined }).b;
      expect(b.lines.length).to.be.greaterThan(0);
      const markers = [
        { i: 1, kind: "COUNTERS_BEGIN", n: "1" },
        { i: 3, kind: "COUNTERS_END", n: "1" },
        { i: 10, kind: "COUNTERS_BEGIN", n: "2" },
        { i: 12, kind: "COUNTERS_END", n: "2" },
      ].map((m) => ({ i: m.i, t: m.i, tid: 1, tgid: 1, nonce: NONCE_A, seq: m.i, kind: m.kind, fields: { n: m.n } }));
      const drop = (i: number) => ({ i, t: i, class: "ATTEMPT_PACKET" as const, attempt: null, why: "" });
      const boundary = (a: number, z: number) => [
        {
          n: 1,
          rules: [
            {
              family: "inet",
              table: "t",
              chain: "output",
              handle: 2,
              hook: "output",
              verdict: "reject" as const,
              counter: { packets: a, bytes: 0 },
              expr: "x",
            },
          ],
        },
        {
          n: 2,
          rules: [
            {
              family: "inet",
              table: "t",
              chain: "output",
              handle: 2,
              hook: "output",
              verdict: "reject" as const,
              counter: { packets: z, bytes: 0 },
              expr: "x",
            },
          ],
        },
      ];
      const drops = [drop(2), drop(5), drop(6), drop(11)]; // one inside each read bracket, two between
      expect(reconcile(drops, markers, boundary(0, 2)).ok).to.equal(true);
      expect(reconcile(drops, markers, boundary(0, 3)).ok).to.equal(true);
      expect(reconcile(drops, markers, boundary(0, 4)).ok).to.equal(true);
      expect(reconcile(drops, markers, boundary(0, 1)).ok).to.equal(false);
      expect(reconcile(drops, markers, boundary(0, 5)).ok).to.equal(false);
    });

    it("refuses a boundary that changed, was reset, counts nothing, or was not snapshotted twice", function () {
      const o = normalize();
      const rules = o.boundary[1].rules;
      expect(counterDelta(o.boundary).errors).to.deep.equal([]);
      const changed = structuredClone(o.boundary);
      changed[1].rules[0].expr = changed[1].rules[0].expr.replace(RESOLVER, "10.255.255.253");
      expect(counterDelta(changed).errors).to.include("the boundary's rules changed during the window");
      const reset = structuredClone(o.boundary);
      (reset[1].rules[0].counter as { packets: number }).packets = 0;
      expect(counterDelta(reset).errors.join()).to.match(/went backwards/);
      const none = structuredClone(o.boundary).map((s) => ({
        ...s,
        rules: s.rules.map((r) => ({ ...r, counter: null })),
      }));
      expect(counterDelta(none).errors.join()).to.match(/no counted refusing rule/);
      expect(counterDelta([o.boundary[0]]).delta).to.equal(null);
      expect(rules.length).to.equal(4);
      expect(reasons(resealed(o, (x) => (x.boundary = changed)))).to.include("BOUNDARY_RECONCILIATION");
    });
  });

  describe("the observer section, judged whole", function () {
    it("refuses an edited section (the digest), another tool, another mechanism, another configuration or filter", function () {
      const o = normalize();
      const edited = structuredClone(o);
      (edited.events.find((e) => e.k === "drop") as Extract<NormEvent, { k: "drop" }>).packet.dst = "1.2.3.4";
      expect(reasons(edited)).to.include("NORMALIZED_NOT_BOUND");
      expect(reasons(o, { ...EXPECT, observerScriptSha256: "00".repeat(32) })).to.include("TOOL_NOT_BOUND");
      expect(reasons(o, { ...EXPECT, observerScriptSha256: null })).to.include("TOOL_NOT_BOUND");
      expect(reasons(resealed(o, (x) => (x.tool.script = "scripts/other.ts")))).to.include("TOOL_NOT_BOUND");
      expect(reasons(resealed(o, (x) => (x.mechanism = "LINUX_AUDIT")))).to.include("OBSERVER_MECHANISM");
      expect(reasons(resealed(o, (x) => (x.config.filters.nfdrop = "reason == 3")))).to.include(
        "OBSERVER_CONFIG_NOT_BOUND",
      );
      expect(reasons(resealed(o, (x) => x.config.probes.pop()))).to.include("OBSERVER_CONFIG_NOT_BOUND");
      expect(reasons(resealed(o, (x) => (x.configSha256 = "00".repeat(32))))).to.include("OBSERVER_CONFIG_NOT_BOUND");
      expect(reasons(resealed(o, (x) => (x.host.nfDropReason = 3)))).to.include("OBSERVER_CONFIG_NOT_BOUND");
    });

    it("refuses a section whose raw evidence is not bound, or that is not exactly its shape (own keys only)", function () {
      const o = normalize();
      expect(reasons(resealed(o, (x) => (x.raw.manifestSha256 = "x")))).to.include("RAW_NOT_BOUND");
      expect(reasons(resealed(o, (x) => x.raw.files.pop()))).to.include("RAW_NOT_BOUND");
      expect(reasons({ ...o, extra: 1 } as unknown as ObserverEvidence)).to.include("OBSERVER_SHAPE");
      const { events: _e, ...missing } = o;
      expect(reasons(missing as unknown as ObserverEvidence)).to.include("OBSERVER_SHAPE");
      const proto = JSON.parse(JSON.stringify(o).replace('"tool":', '"__proto__":{"x":1},"tool":'));
      expect(reasons(proto)).to.include("OBSERVER_SHAPE");
      expect(reasons(null as unknown as ObserverEvidence)).to.include("OBSERVER_SHAPE");
    });

    it("needs each recorded edge probe in the trace: the tool's refused attempt in its own phase", function () {
      const fewer = standardRaw({ probes: { ...STANDARD_PROBES, tcpByAddress: ["203.0.113.5", "1.1.1.1"] } });
      expect(reasons(normalize(fewer))).to.include("PROBE_NOT_OBSERVED");
      // A by-name probe of a host is a lookup of it either way: only a name never looked up is unobserved.
      const renamed = standardRaw({
        probes: { ...STANDARD_PROBES, dns: ["example.invalid"], tcpByName: ["example.invalid"] },
      });
      const why = judge(normalize(renamed))
        .refusals.filter((r) => r.reason === "PROBE_NOT_OBSERVED")
        .map((r) => r.detail);
      expect(why).to.have.length(4);
      expect(why.every((d) => d.includes("registry.invalid"))).to.equal(true);
    });

    it("binds the capture to this run: the commit and host label the tool sent before its first phase", function () {
      expect(reasons(normalize(standardRaw({ commit: "d".repeat(40) })))).to.include("OBSERVER_NOT_THIS_RUN");
      expect(reasons(normalize(standardRaw({ host: "proving-host-b" })))).to.include("OBSERVER_NOT_THIS_RUN");
    });

    it("re-checks the privacy filter: a disclosed name withheld, or a withheld one kept, is refused", function () {
      const o = normalize(
        standardRaw({ beforeWindow: (b) => refusedLookup(b, OTHER, "0xffff888000077700", "ntp.ubuntu.com", 51000) }),
      );
      const kept = resealed(o, (x) => {
        const d = x.events.find((e) => e.k === "drop" && e.packet.dns?.withheld === true) as Extract<
          NormEvent,
          { k: "drop" }
        >;
        d.packet.dns = { id: d.packet.dns?.id ?? 0, qname: "ntp.ubuntu.com" };
      });
      expect(reasons(kept)).to.include("PRIVACY_FILTER");
      const hidden = resealed(o, (x) => {
        const d = x.events.find((e) => e.k === "drop" && e.packet.dns?.qname === "example.invalid") as Extract<
          NormEvent,
          { k: "drop" }
        >;
        d.packet.dns = { id: d.packet.dns?.id ?? 0, qname: null, withheld: true };
      });
      // (the probe is still observed: its by-name TCP probe looked the same name up again)
      expect(reasons(hidden)).to.deep.equal(["PRIVACY_FILTER"]);
    });
  });

  describe("the assurance each kind of evidence supports", function () {
    it("a v1 run (SP1-PA3B's) is edge-probed only: nothing measured is read into it, and unknown is never zero", function () {
      expect(EDGE_PROBES_ONLY).to.deep.equal({
        level: "EDGE_PROBES_ONLY",
        enforcement: "STATED",
        edgeProbes: "REFUSED_BEFORE_AND_AFTER",
        continuousObservation: "ABSENT",
        processAttribution: "ABSENT",
        coverage: null,
        events: null,
        unattributedEvents: null,
        observer: null,
        rawEvidence: null,
      });
      expect(Object.isFrozen(EDGE_PROBES_ONLY) || EDGE_PROBES_ONLY.unattributedEvents === null).to.equal(true);
    });

    it("accepted continuous evidence is CONTINUOUS_ATTRIBUTED, derived from the facts", function () {
      const o = normalize(
        standardRaw({ duringProof: (b) => refusedLookup(b, HOST, "0xffff888000055500", "ghcr.io", 52000) }),
      );
      const j = judge(o);
      const a = assuranceOf(o, j.attribution as NonNullable<typeof j.attribution>);
      expect(a).to.deep.include({
        level: "CONTINUOUS_ATTRIBUTED",
        enforcement: "STATED_AND_COUNTED",
        continuousObservation: "PRESENT",
        processAttribution: "COMPLETE",
        unattributedEvents: 0,
      });
      expect(a.events?.byScope).to.deep.equal({ TOOL: 14, PROOF: 1 });
      expect(a.events?.boundaryResponses).to.equal(9);
      expect(a.observer).to.deep.equal({
        mechanism: "LINUX_TRACEFS_KPROBES",
        script: OBSERVER_SCRIPT_REL,
        scriptSha256: OBSERVER_SHA,
        configSha256: o.configSha256,
      });
      expect(a.rawEvidence).to.deep.equal({ manifestSha256: o.raw.manifestSha256, retained: "OPERATOR_LOCAL" });
    });
  });

  describe("the tool's side of the protocol", function () {
    const pair = () => {
      const input = new PassThrough();
      const sent: string[] = [];
      return { input, sent, client: new ObserverClient(input, (l) => void sent.push(l)) };
    };

    it("waits for READY, asks one marker at a time and resolves with its sequence, and ends with STOPPED", async function () {
      const { input, sent, client } = pair();
      input.write(`${formatCtl("READY", NONCE_A, `sp1obs_${NONCE_A}`, BOOT_ID, "RUN")}\n`);
      expect(await client.ready()).to.deep.equal({
        nonce: NONCE_A,
        group: `sp1obs_${NONCE_A}`,
        bootId: BOOT_ID,
        mode: "RUN",
      });
      const a = client.request("PHASE", "PROBES_BEFORE_BEGIN");
      const b = client.request("PHASE", "PROBES_BEFORE_END");
      await new Promise((r) => setImmediate(r));
      expect(sent).to.deep.equal([formatCtl("PHASE", "PROBES_BEFORE_BEGIN")]);
      input.write(`${formatCtl("ACK", 7)}\nnoise\n`);
      expect(await a).to.equal(7);
      input.write(`${formatCtl("ACK", 8)}\n`);
      expect(await b).to.equal(8);
      const s = client.stop();
      input.write(`${formatCtl("STOPPED", "ab".repeat(32), "/root/raw")}\n`);
      expect(await s).to.deep.equal({ manifestSha256: "ab".repeat(32), rawDir: "/root/raw" });
    });

    it("refuses a start that is not the observer's, and fails every waiter at FAIL or when the observer goes away", async function () {
      const one = pair();
      one.input.write("SP1OBS-CTL HELLO there\n");
      let refused = "";
      await one.client.ready().catch((e: Error) => (refused = e.message));
      expect(refused).to.match(/not started by the egress observer/);
      const two = pair();
      const failed: string[] = [];
      two.client.onFail((r) => failed.push(r));
      two.input.write(`${formatCtl("READY", NONCE_A, "g", BOOT_ID, "RUN")}\n`);
      await two.client.ready();
      const pending = two.client.request("PHASE", "GATE_BEGIN");
      two.input.write(`${formatCtl("FAIL", "OBSERVER_LOSS")}\n`);
      let why = "";
      await pending.catch((e: Error) => (why = e.message));
      expect(why).to.match(/FAIL|the observer failed: OBSERVER_LOSS/);
      expect(failed).to.deep.equal(["OBSERVER_LOSS"]);
      let after = "";
      await two.client.request("PHASE", "GATE_END").catch((e: Error) => (after = e.message));
      expect(after).to.match(/the observer failed: OBSERVER_LOSS/);
      const three = pair();
      three.input.write(`${formatCtl("READY", NONCE_A, "g", BOOT_ID, "RUN")}\n`);
      await three.client.ready();
      const waiting = three.client.request("PHASE", "GATE_BEGIN");
      three.input.end();
      let gone = "";
      await waiting.catch((e: Error) => (gone = e.message));
      expect(gone).to.match(/gone/);
      expect(three.client.failure).to.equal("OBSERVER_GONE");
    });
  });
});

/** The derivation context of a normalized section (as observerEvidenceErrors builds it). */
function ctxOf(o: ObserverEvidence) {
  return {
    nonce: o.nonce,
    hostNetns: o.host.netns,
    uplinks: o.host.uplinks,
    localAddresses: o.host.interfaces.flatMap((i) => i.addresses.map((a) => a.split("/")[0])),
    inVmSubnets: [
      { base: "127.0.0.1", prefix: 8 },
      { base: "172.17.0.1", prefix: 16 },
    ],
    resolvers: o.host.resolvers,
    hostExecutable: o.hostExecutable,
    mode: o.mode,
    bootId: o.bootId,
  };
}
