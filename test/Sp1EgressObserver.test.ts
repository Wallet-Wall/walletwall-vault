/**
 * SP1-PA3C: the root egress observer (scripts/sp1-egress-observer.ts), its pure parts and its tracefs session driven
 * against an in-memory tracefs: the probe set never fetches an untrusted string as text, the configuration is
 * deterministic, every startup refusal happens before anything is left behind, a probe the kernel refuses part-way
 * undoes everything defined before it, and the markers carry one gap-free sequence. The real kernel is exercised by
 * test/Sp1EgressObserverLinux.test.ts (Linux, root, opt-in). Research prototype. Not audited.
 */
import { expect } from "chai";

import {
  BUFFER_KB,
  HEARTBEAT_MS,
  NONCE,
  ObserverRefusal,
  PHASES,
  PROBES,
  TRACE_CLOCK,
  TraceSession,
  canonicalJson,
  configSha256,
  formatCtl,
  formatMarker,
  groupOf,
  interfacesOf,
  netfilterDropReason,
  nsInode,
  observerConfig,
  parseCpuStats,
  parseCtl,
  probeFilters,
  renderProbes,
  resolversOf,
  rootOwnedPathErrors,
  uplinksOf,
  userOf,
  type TraceFs,
} from "../scripts/sp1-egress-observer";
import { fieldSpecs } from "../scripts/lib/sp1-egress-attribution";

const NONCE_A = "0123456789abcdef";
const ROOT = "/sys/kernel/tracing";
// The NETFILTER_DROP entry, as the kernel's kfree_skb format prints its reasons (an excerpt).
const FORMAT =
  'print fmt: "...", __print_symbolic(REC->reason, { 2, "NOT_SPECIFIED" }, { 12, "NETFILTER_DROP" }, { 13, "OTHERHOST" })';
const STATS =
  "entries: 3\noverrun: 0\ncommit overrun: 0\nbytes: 412\noldest event ts: 35.6\nnow ts: 35.9\ndropped events: 0\nread events: 61\n";

/** An in-memory tracefs: files, directories, and kprobe_events with the kernel's append and `-:` semantics. */
class FakeTraceFs implements TraceFs {
  files = new Map<string, string>();
  dirs = new Set<string>([ROOT, `${ROOT}/instances`]);
  writes: [string, string][] = [];
  markers: string[] = [];
  refuseProbe: string | null = null;
  dropFromReadBack: string | null = null;
  rmdirFails = false;
  constructor() {
    this.files.set(`${ROOT}/kprobe_events`, "");
    this.files.set(`${ROOT}/error_log`, "[ 4.85] trace_kprobe: error: something\n");
    this.files.set(`${ROOT}/events/skb/kfree_skb/format`, FORMAT);
  }
  read(p: string): string {
    if (p.endsWith("/kprobe_events")) {
      const lines = (this.files.get(p) ?? "").split("\n").filter((l) => l !== "");
      return lines
        .filter((l) => this.dropFromReadBack === null || !l.includes(`/${this.dropFromReadBack} `))
        .map((l) => l.replace(/^r:/, "r16:"))
        .join("\n");
    }
    if (p.endsWith("/tracing_on")) return this.files.get(p) ?? "0";
    const v = this.files.get(p);
    if (v === undefined) throw new Error(`ENOENT ${p}`);
    return v;
  }
  write(p: string, d: string): void {
    if (!this.dirs.has(p.slice(0, p.lastIndexOf("/"))) && !p.includes("/events/") && !p.includes("/options/"))
      throw new Error(`ENOENT ${p}`);
    this.writes.push([p, d]);
    this.files.set(p, d);
  }
  append(p: string, d: string): void {
    const line = d.trim();
    if (p.endsWith("/kprobe_events")) {
      const cur = (this.files.get(p) ?? "").split("\n").filter((l) => l !== "");
      if (line.startsWith("-:")) {
        this.files.set(
          p,
          cur.filter((l) => !l.startsWith(`p:${line.slice(2)} `) && !l.startsWith(`r:${line.slice(2)} `)).join("\n"),
        );
        return;
      }
      if (this.refuseProbe !== null && line.includes(`/${this.refuseProbe} `)) throw new Error("Invalid argument");
      this.files.set(p, [...cur, line].join("\n"));
      return;
    }
    this.files.set(p, (this.files.get(p) ?? "") + d);
  }
  exists(p: string): boolean {
    return this.files.has(p) || this.dirs.has(p);
  }
  mkdir(p: string): void {
    if (this.dirs.has(p)) throw new Error(`EEXIST ${p}`);
    this.dirs.add(p);
    for (let cpu = 0; cpu < 2; cpu++) this.files.set(`${p}/per_cpu/cpu${cpu}/stats`, STATS);
  }
  rmdir(p: string): void {
    if (this.rmdirFails) throw new Error("EBUSY");
    this.dirs.delete(p);
  }
  list(p: string): string[] {
    const prefix = `${p}/`;
    return [
      ...new Set(
        [...this.files.keys()].filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length).split("/")[0]),
      ),
    ];
  }
  openMarker(): { write(line: string): void; close(): void } {
    return { write: (l) => void this.markers.push(l), close: () => undefined };
  }
}

describe("SP1-PA3C — the root egress observer", function () {
  describe("the probe set", function () {
    it("fetches no string an unprivileged process controls as text: every value is typed, the comm last", function () {
      for (const p of PROBES) {
        const specs = fieldSpecs(p.fetch);
        const comms = specs.filter((s) => s.type === "comm");
        expect(comms.length, p.name).to.be.at.most(1);
        if (comms.length === 1) expect(specs.at(-1)?.type, p.name).to.equal("comm");
        expect(p.fetch, p.name).to.not.match(/:(string|ustring|symstr)\b|%p[dD]/);
        if (p.kind === "r") expect(comms, `${p.name}: a return probe needs no comm`).to.deep.equal([]);
      }
    });

    it("covers every way a process reaches the network and every refused or transmitted packet", function () {
      const symbols = new Set(PROBES.map((p) => `${p.kind}:${p.symbol}`));
      for (const s of [
        "udp_sendmsg",
        "udpv6_sendmsg",
        "tcp_v4_connect",
        "tcp_v6_connect",
        "raw_sendmsg",
        "rawv6_sendmsg",
        "ping_v4_sendmsg",
        "ping_v6_sendmsg",
        "packet_sendmsg",
      ]) {
        expect(symbols.has(`p:${s}`) && symbols.has(`r:${s}`), s).to.equal(true);
      }
      for (const s of [
        "p:tcp_set_state",
        "p:tcp_retransmit_skb",
        "p:sk_skb_reason_drop",
        "p:dev_hard_start_xmit",
        "p:wake_up_new_task",
        "p:begin_new_exec",
        "p:do_exit",
      ]) {
        expect(symbols.has(s), s).to.equal(true);
      }
      expect(new Set(PROBES.map((p) => p.name)).size).to.equal(PROBES.length);
    });

    it("renders one line per probe in its group, filters from the host's facts, and a deterministic configuration", function () {
      const lines = renderProbes(groupOf(NONCE_A));
      expect(lines).to.have.length(PROBES.length);
      expect(lines[0]).to.equal(`p:sp1obs_${NONCE_A}/newtask wake_up_new_task ${PROBES[0].fetch}`);
      expect(lines.find((l) => l.includes("/udp4ret "))).to.match(
        /^r:sp1obs_0123456789abcdef\/udp4ret udp_sendmsg ret=\$retval:s32 /,
      );
      expect(probeFilters(4026531833, 12)).to.deep.equal({
        nfdrop: "reason == 12",
        xmit: "netns == 4026531833 && ifindex != 1",
      });
      const c = observerConfig({ nonce: NONCE_A, hostNetns: 4026531833, nfDropReason: 12 });
      expect(c).to.deep.include({
        clock: TRACE_CLOCK,
        bufferKb: BUFFER_KB,
        overwrite: 0,
        recordTgid: 1,
        heartbeatMs: HEARTBEAT_MS,
      });
      expect(configSha256(c)).to.equal(
        configSha256(observerConfig({ nonce: NONCE_A, hostNetns: 4026531833, nfDropReason: 12 })),
      );
      expect(configSha256(c)).to.not.equal(
        configSha256(observerConfig({ nonce: NONCE_A, hostNetns: 4026531833, nfDropReason: 3 })),
      );
      expect(configSha256(c)).to.not.equal(
        configSha256(observerConfig({ nonce: "f".repeat(16), hostNetns: 4026531833, nfDropReason: 12 })),
      );
    });

    it("canonical JSON sorts keys and keeps an own __proto__ key as data", function () {
      expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }] })).to.equal('{"a":[{"c":2,"d":1}],"b":1}');
      const injected = JSON.parse('{"a":1,"__proto__":{"x":1}}');
      expect(canonicalJson(injected)).to.equal('{"__proto__":{"x":1},"a":1}');
      expect(canonicalJson(injected)).to.not.equal(canonicalJson({ a: 1 }));
    });
  });

  describe("markers and the control protocol", function () {
    it("formats a marker of plain tokens only", function () {
      expect(formatMarker(NONCE_A, 3, "PHASE", { name: "GATE_BEGIN" })).to.equal(
        `SP1OBS ${NONCE_A} 3 PHASE name=GATE_BEGIN`,
      );
      expect(() => formatMarker(NONCE_A, 1, "HELLO", { host: "a b" })).to.throw(/one plain token/);
      expect(() => formatMarker(NONCE_A, 1, "HELLO", { host: "a\nb" })).to.throw(/one plain token/);
    });

    it("parses the tool's vocabulary, leaves its log lines alone, and refuses anything else that claims to be control", function () {
      expect(parseCtl(formatCtl("HELLO", "c".repeat(40), "proving-host-a"))).to.deep.equal({
        kind: "HELLO",
        commit: "c".repeat(40),
        host: "proving-host-a",
      });
      for (const p of PHASES) expect(parseCtl(formatCtl("PHASE", p))).to.deep.equal({ kind: "PHASE", phase: p });
      expect(parseCtl(formatCtl("CONTAINER", "a".repeat(64), 4321))).to.deep.equal({
        kind: "CONTAINER",
        id: "a".repeat(64),
        pid: 4321,
      });
      expect(parseCtl(formatCtl("DONE"))).to.deep.equal({ kind: "DONE" });
      expect(parseCtl(formatCtl("ABORT", "PRECONDITION"))).to.deep.equal({ kind: "ABORT", reason: "PRECONDITION" });
      expect(parseCtl("gate 647 s")).to.equal(null);
      for (const bad of [
        formatCtl("PHASE", "STOP"),
        formatCtl("PHASE", "GATE_BEGIN", "x"),
        formatCtl("HELLO", "c".repeat(39), "h"),
        formatCtl("HELLO", "c".repeat(40), "Bad_Host"),
        formatCtl("CONTAINER", "a".repeat(63), 1),
        formatCtl("CONTAINER", "a".repeat(64), 0),
        formatCtl("READY"),
        formatCtl("DONE", "now"),
      ]) {
        expect(() => parseCtl(bad), bad).to.throw(/malformed control line/);
      }
    });
  });

  describe("host facts", function () {
    it("reads the drop reason, CPU stats, resolvers, namespaces, interfaces, uplinks and the user", function () {
      expect(netfilterDropReason(FORMAT)).to.equal(12);
      expect(() => netfilterDropReason("no reasons")).to.throw(/NETFILTER_DROP/);
      expect(parseCpuStats(3, STATS)).to.deep.equal({
        cpu: 3,
        entries: 3,
        overrun: 0,
        commitOverrun: 0,
        droppedEvents: 0,
        readEvents: 61,
      });
      expect(() => parseCpuStats(0, STATS.replace("dropped events: 0\n", ""))).to.throw(/dropped events/);
      expect(resolversOf("# generated\nnameserver 10.255.255.254\nsearch x\nnameserver 1.1.1.1\n")).to.deep.equal([
        "10.255.255.254",
        "1.1.1.1",
      ]);
      expect(nsInode("net:[4026531833]")).to.equal(4026531833);
      expect(() => nsInode("4026531833")).to.throw();
      const ifs = interfacesOf(
        JSON.stringify([
          { ifindex: 1, ifname: "lo", addr_info: [{ local: "127.0.0.1", prefixlen: 8 }] },
          { ifindex: 2, ifname: "eth0", addr_info: [{ local: "172.22.169.196", prefixlen: 20 }] },
        ]),
      );
      expect(ifs).to.deep.equal([
        { ifindex: 1, name: "lo", addresses: ["127.0.0.1/8"] },
        { ifindex: 2, name: "eth0", addresses: ["172.22.169.196/20"] },
      ]);
      expect(uplinksOf([JSON.stringify([{ dst: "default", dev: "eth0" }]), ""], ifs)).to.deep.equal([2]);
      expect(() => interfacesOf(JSON.stringify([{ ifname: "lo" }]))).to.throw();
      expect(userOf("prover:x:1001:1001::/home/prover:/bin/bash")).to.deep.equal({
        name: "prover",
        uid: 1001,
        gid: 1001,
        home: "/home/prover",
      });
      expect(() => userOf("root:x:0:0:root:/root:/bin/bash")).to.throw(/unprivileged/);
      expect(() => userOf("nonsense")).to.throw();
    });

    it("refuses an observer file a non-root user could change, along its whole path", function () {
      const stat = (owners: Record<string, { uid: number; mode: number }>) => (p: string) =>
        owners[p.replace(/\\/g, "/").replace(/^[A-Za-z]:/, "")] ?? { uid: 0, mode: 0o755 };
      const file = "/root/obs/sp1-egress-observer.ts";
      expect(rootOwnedPathErrors(file, stat({}))).to.deep.equal([]);
      expect(rootOwnedPathErrors(file, stat({ [file]: { uid: 1001, mode: 0o644 } })).join()).to.match(
        /owned by uid 1001/,
      );
      expect(rootOwnedPathErrors(file, stat({ "/root/obs": { uid: 0, mode: 0o777 } })).join()).to.match(
        /writable by group or others/,
      );
      expect(rootOwnedPathErrors(file, stat({ "/root": { uid: 0, mode: 0o775 } })).join()).to.match(
        /writable by group or others/,
      );
    });
  });

  describe("the tracefs session", function () {
    it("refuses before anything is touched: no tracefs, an instance or probes already there, no drop reason", function () {
      const fs = new FakeTraceFs();
      fs.files.delete(`${ROOT}/kprobe_events`);
      expect(() => new TraceSession(fs, NONCE_A).precheck()).to.throw(/TRACEFS_UNAVAILABLE/);
      const two = new FakeTraceFs();
      two.dirs.add(`${ROOT}/instances/sp1obs_${NONCE_A}`);
      expect(() => new TraceSession(two, NONCE_A).precheck()).to.throw(/INSTANCE_EXISTS/);
      const three = new FakeTraceFs();
      three.files.set(`${ROOT}/kprobe_events`, `p:sp1obs_${NONCE_A}/exit do_exit code=code:s64`);
      expect(() => new TraceSession(three, NONCE_A).precheck()).to.throw(/PROBES_EXIST/);
      const four = new FakeTraceFs();
      four.files.set(`${ROOT}/events/skb/kfree_skb/format`, "no reasons");
      expect(() => new TraceSession(four, NONCE_A).precheck()).to.throw(/NETFILTER_DROP/);
      expect(() => new TraceSession(new FakeTraceFs(), "not-a-nonce")).to.throw(/16 lowercase hex/);
      expect(NONCE.test(NONCE_A)).to.equal(true);
    });

    it("opens the instance, defines and verifies every probe, sets the filters, enables, and starts tracing last", function () {
      const fs = new FakeTraceFs();
      const s = new TraceSession(fs, NONCE_A);
      expect(s.precheck()).to.equal(12);
      const config = s.open(4026531833, 12);
      expect(config).to.deep.equal(observerConfig({ nonce: NONCE_A, hostNetns: 4026531833, nfDropReason: 12 }));
      const at = (f: string) => `${ROOT}/instances/sp1obs_${NONCE_A}/${f}`;
      const order = fs.writes.map(([p]) => p);
      expect(fs.writes.slice(0, 4)).to.deep.equal([
        [at("trace_clock"), "mono"],
        [at("options/record-tgid"), "1"],
        [at("options/overwrite"), "0"],
        [at("buffer_size_kb"), String(BUFFER_KB)],
      ]);
      expect(fs.files.get(at("events/sp1obs_0123456789abcdef/nfdrop/filter"))).to.equal("reason == 12");
      expect(fs.files.get(at("events/sp1obs_0123456789abcdef/xmit/filter"))).to.equal(
        "netns == 4026531833 && ifindex != 1",
      );
      expect(PROBES.every((p) => fs.files.get(at(`events/sp1obs_0123456789abcdef/${p.name}/enable`)) === "1")).to.equal(
        true,
      );
      expect(order.at(-1)).to.equal(at("tracing_on"));
      expect(fs.files.get(at("tracing_on"))).to.equal("1");
      expect(s.readBack).to.have.length(PROBES.length);
      expect(s.readBack.filter((l) => l.startsWith("r16:"))).to.have.length(
        PROBES.filter((p) => p.kind === "r").length,
      );
      expect([s.mark("READY", { mode: "RUN" }), s.mark("STOP")]).to.deep.equal([1, 2]);
      expect(fs.markers).to.deep.equal([`SP1OBS ${NONCE_A} 1 READY mode=RUN`, `SP1OBS ${NONCE_A} 2 STOP`]);
      expect(s.tracingOn()).to.equal(true);
      expect(s.stats().map((c) => c.cpu)).to.deep.equal([0, 1]);
      expect(s.close()).to.deep.equal([]);
      expect(fs.files.get(`${ROOT}/kprobe_events`)).to.equal("");
      expect(fs.exists(`${ROOT}/instances/sp1obs_${NONCE_A}`)).to.equal(false);
    });

    it("undoes everything when the kernel refuses a probe part-way, and names it", function () {
      const fs = new FakeTraceFs();
      fs.refuseProbe = "nfdrop";
      const s = new TraceSession(fs, NONCE_A);
      s.precheck();
      expect(() => s.open(4026531833, 12)).to.throw(ObserverRefusal, /PROBE_REFUSED: the kernel refused nfdrop/);
      expect(fs.files.get(`${ROOT}/kprobe_events`)).to.not.equal("");
      expect(s.close()).to.deep.equal([]);
      expect(fs.files.get(`${ROOT}/kprobe_events`)).to.equal("");
      expect(fs.exists(`${ROOT}/instances/sp1obs_${NONCE_A}`)).to.equal(false);
    });

    it("refuses a probe the kernel does not list after defining it, and reports what close() could not undo", function () {
      const fs = new FakeTraceFs();
      fs.dropFromReadBack = "xmit";
      const s = new TraceSession(fs, NONCE_A);
      expect(() => s.open(4026531833, 12)).to.throw(/PROBE_MISSING: p:sp1obs_0123456789abcdef\/xmit is not defined/);
      fs.rmdirFails = true;
      const left = s.close();
      expect(left.join()).to.match(/instance: EBUSY/);
      expect(left.join()).to.match(/remains/);
      expect(() => s.mark("STOP")).to.throw(/not open/);
    });
  });
});
