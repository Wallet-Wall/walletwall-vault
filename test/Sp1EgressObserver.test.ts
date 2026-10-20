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
  ControlProtocol,
  HEARTBEAT_MS,
  NONCE,
  ObserverRefusal,
  PHASES,
  PROBES,
  TRACE_CLOCK,
  TraceSession,
  canonicalJson,
  configSha256,
  containerNetns,
  formatCtl,
  formatMarker,
  groupOf,
  heartbeatOf,
  interfacesOf,
  netfilterDropReason,
  nsInode,
  observerConfig,
  parseCpuStats,
  parseCtl,
  probeFilters,
  probeMisses,
  rawDirErrors,
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
  /** Misses kprobe_profile reports per event name (every defined probe is listed, with 0 unless set here). */
  misses = new Map<string, number>();
  constructor() {
    this.files.set(`${ROOT}/kprobe_events`, "");
    this.files.set(`${ROOT}/error_log`, "[ 4.85] trace_kprobe: error: something\n");
    this.files.set(`${ROOT}/events/skb/kfree_skb/format`, FORMAT);
  }
  read(p: string): string {
    if (p === `${ROOT}/kprobe_profile`) {
      const names = (this.files.get(`${ROOT}/kprobe_events`) ?? "")
        .split("\n")
        .filter((l) => l !== "")
        .map((l) => l.split(" ")[0].split("/")[1]);
      return names
        .map((n) => `  ${n.padEnd(44)} ${"3".padStart(15)} ${String(this.misses.get(n) ?? 0).padStart(15)}\n`)
        .join("");
    }
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
        [...this.files.keys(), ...this.dirs]
          .filter((k) => k.startsWith(prefix))
          .map((k) => k.slice(prefix.length).split("/")[0]),
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

  describe("the observer's decisions", function () {
    const COMMIT = "c".repeat(40);
    const ID = "a".repeat(64);
    const hello = { kind: "HELLO", commit: COMMIT, host: "proving-host-a" } as const;
    const phase = (p: (typeof PHASES)[number]) => ({ kind: "PHASE", phase: p }) as const;
    const done = { kind: "DONE" } as const;
    const noNetns = () => {
      throw new Error("the namespace is resolved only for a container");
    };
    /** The refusal a request gets (its message, `code: why`), or null when it is served. */
    const refusal = (p: ControlProtocol, msg: Parameters<ControlProtocol["accept"]>[0]) => {
      try {
        p.accept(msg, noNetns);
        return null;
      } catch (error) {
        expect(error).to.be.instanceOf(ObserverRefusal);
        // The message is `code: why`, so it pins the code too.
        return (error as Error).message;
      }
    };

    it("serves HELLO, every phase in order, containers and DONE as markers, and passes ABORT through", function () {
      const p = new ControlProtocol();
      expect(p.accept({ kind: "ABORT", reason: "PRECONDITION" }, noNetns)).to.deep.equal({ abort: "PRECONDITION" });
      expect(p.accept(hello, noNetns)).to.deep.equal({
        mark: { kind: "HELLO", fields: { commit: COMMIT, host: "proving-host-a" } },
      });
      const asked: [string, number][] = [];
      const resolve = (id: string, pid: number) => {
        asked.push([id, pid]);
        return "4026532999";
      };
      for (const [i, name] of PHASES.entries()) {
        expect(p.accept(phase(name), noNetns), name).to.deep.equal({ mark: { kind: "PHASE", fields: { name } } });
        if (i === 3) {
          expect(p.accept({ kind: "CONTAINER", id: ID, pid: 4321 }, resolve)).to.deep.equal({
            mark: { kind: "CONTAINER", fields: { id: ID, pid: 4321, netns: "4026532999" } },
          });
        }
      }
      expect(asked).to.deep.equal([[ID, 4321]]);
      expect(p.accept(done, noNetns)).to.deep.equal({ done: true });
    });

    it("refuses HELLO twice, a phase or a container before HELLO, a phase out of order or repeated, and DONE early", function () {
      expect(refusal(new ControlProtocol(), phase(PHASES[0]))).to.equal("PHASE_ORDER: a phase before HELLO");
      expect(refusal(new ControlProtocol(), { kind: "CONTAINER", id: ID, pid: 1 })).to.equal(
        "PHASE_ORDER: a container before HELLO",
      );
      expect(refusal(new ControlProtocol(), done)).to.equal(`PHASE_ORDER: DONE before ${PHASES[0]}`);
      const twice = new ControlProtocol();
      twice.accept(hello, noNetns);
      expect(refusal(twice, hello)).to.equal("PHASE_ORDER: HELLO comes once, before the first phase");
      const after = new ControlProtocol();
      after.accept(hello, noNetns);
      after.accept(phase(PHASES[0]), noNetns);
      expect(refusal(after, hello)).to.equal("PHASE_ORDER: HELLO comes once, before the first phase");
      expect(refusal(after, phase(PHASES[0]))).to.equal(
        `PHASE_ORDER: ${PHASES[0]} out of order (expected ${PHASES[1]})`,
      );
      expect(refusal(after, phase(PHASES[2]))).to.equal(
        `PHASE_ORDER: ${PHASES[2]} out of order (expected ${PHASES[1]})`,
      );
      for (const name of PHASES.slice(1, -1)) after.accept(phase(name), noNetns);
      expect(refusal(after, done)).to.equal(`PHASE_ORDER: DONE before ${PHASES.at(-1)}`);
      after.accept(phase(PHASES.at(-1) as (typeof PHASES)[number]), noNetns);
      expect(refusal(after, phase(PHASES[0]))).to.equal(`PHASE_ORDER: ${PHASES[0]} out of order (expected none)`);
    });

    it("refuses every request after DONE, an ABORT included", function () {
      const p = new ControlProtocol();
      p.accept(hello, noNetns);
      for (const name of PHASES) p.accept(phase(name), noNetns);
      p.accept(done, noNetns);
      for (const msg of [done, hello, phase(PHASES[0]), { kind: "ABORT", reason: "LATE" } as const]) {
        expect(refusal(p, msg), msg.kind).to.equal("PHASE_ORDER: a request after DONE");
      }
    });

    it("records a container's namespace only when its cgroup names it, and says why not otherwise", function () {
      const cgroup = `0::/system.slice/docker-${ID}.scope\n`;
      const link = "net:[4026532999]";
      const seen: number[] = [];
      const read = (text: string) => (pid: number) => {
        seen.push(pid);
        return text;
      };
      const fails = () => {
        throw new Error("ENOENT");
      };
      expect(containerNetns(ID, read(cgroup), read(link), 4321)).to.equal("4026532999");
      expect(seen).to.deep.equal([4321, 4321]);
      expect(containerNetns(ID, read("0::/user.slice/session-3.scope\n"), fails, 4321)).to.equal("unverified");
      expect(containerNetns(ID, fails, read(link), 4321)).to.equal("unknown");
      expect(containerNetns(ID, read(cgroup), fails, 4321)).to.equal("unknown");
      expect(containerNetns(ID, read(cgroup), read("net:4026532999"), 4321)).to.equal("unknown");
    });

    it("lets a heartbeat pass only with tracing on, per-CPU stats read, and nothing lost on any CPU or by any probe", function () {
      const cpu = (n: number, overrun = 0, commitOverrun = 0, droppedEvents = 0) => ({
        cpu: n,
        entries: 9,
        overrun,
        commitOverrun,
        droppedEvents,
        readEvents: 61,
      });
      expect(heartbeatOf(4, [cpu(0), cpu(1)], true, 0, true)).to.deep.equal({
        fields: { n: 4, tracingOn: 1, loss: 0 },
        ok: true,
      });
      expect(heartbeatOf(5, [cpu(0), cpu(1)], false, 0, true)).to.deep.equal({
        fields: { n: 5, tracingOn: 0, loss: 0 },
        ok: false,
      });
      expect(heartbeatOf(6, [cpu(0, 2, 3), cpu(1, 0, 0, 5)], true, 7, true)).to.deep.equal({
        fields: { n: 6, tracingOn: 1, loss: 17 },
        ok: false,
      });
      for (const lost of [cpu(1, 1), cpu(1, 0, 1), cpu(1, 0, 0, 1)]) {
        expect(heartbeatOf(7, [cpu(0), lost], true, 0, true).ok, JSON.stringify(lost)).to.equal(false);
      }
      // A probe's miss is a lost event: a return the observer never saw leaves an attempt's outcome unknown.
      expect(heartbeatOf(8, [cpu(0), cpu(1)], true, 1, true)).to.deep.equal({
        fields: { n: 8, tracingOn: 1, loss: 1 },
        ok: false,
      });
      expect(heartbeatOf(9, [], true, 0, true)).to.deep.equal({ fields: { n: 9, tracingOn: 1, loss: 0 }, ok: false });
      // A probe switched off (tracing itself on) is tracing off for the evidence: the marker says 0 and the run stops.
      expect(heartbeatOf(10, [cpu(0), cpu(1)], true, 0, false)).to.deep.equal({
        fields: { n: 10, tracingOn: 0, loss: 0 },
        ok: false,
      });
    });

    it("reads the probes' misses from kprobe_profile as the kernel prints it, or refuses", function () {
      // The kernel's "  %-44s %15lu %15lu" per event (6.18: the event name only, never its group).
      const line = (name: string, hits: number, misses: number) =>
        `  ${name.padEnd(44)} ${String(hits).padStart(15)} ${String(misses).padStart(15)}`;
      expect(line("exitp", 0, 0)).to.equal(
        "  exitp                                                      0               0",
      );
      const profile = [line("udp4", 12, 0), line("udp4ret", 12, 2), line("tcp4", 3, 0), line("other", 9, 40)].join(
        "\n",
      );
      expect(probeMisses(`${profile}\n`, ["udp4", "udp4ret", "tcp4"])).to.equal(2);
      // Another group's event of one of these names is summed in: its miss stops the run too.
      expect(probeMisses(`${profile}\n${line("tcp4", 1, 3)}\n`, ["udp4", "udp4ret", "tcp4"])).to.equal(5);
      expect(() => probeMisses(profile, ["udp4", "exec"])).to.throw(/does not list exec/);
      expect(() => probeMisses(`${profile}\nudp4 1 x\n`, ["udp4"])).to.throw(/does not read/);
    });

    it("refuses a raw directory that exists, is not plain and absolute, or sits where a non-root user could swap it", function () {
      const owners: Record<string, { uid: number; mode: number }> = {
        "/srv/prover": { uid: 1001, mode: 0o755 },
        "/srv/shared": { uid: 0, mode: 0o1777 },
      };
      const stat = (p: string) => owners[p.replace(/\\/g, "/").replace(/^[A-Za-z]:/, "")] ?? { uid: 0, mode: 0o755 };
      const none = () => false;
      expect(rawDirErrors("/var/lib/sp1-observer/raw-20261101T100000Z", none, stat)).to.deep.equal([]);
      expect(rawDirErrors("/var/lib/sp1-raw", () => true, stat).join()).to.match(/does not exist yet/);
      expect(rawDirErrors("var/lib/sp1-raw", none, stat).join()).to.match(/absolute path/);
      expect(rawDirErrors("/var/lib/sp1 raw", none, stat).join()).to.match(/plain characters/);
      // A lexical parent is not the real one when a component is . or .. (a symlink above could lead anywhere).
      expect(rawDirErrors("/var/lib/sp1-observer/../raw", none, stat).join()).to.match(/no \. or \.\. component/);
      expect(rawDirErrors("/var/lib/./raw", none, stat).join()).to.match(/no \. or \.\. component/);
      expect(rawDirErrors("/srv/prover/raw", none, stat).join()).to.match(/owned by uid 1001/);
      expect(rawDirErrors("/srv/shared/raw", none, stat).join()).to.match(/writable by group or others/);
      // Root's own home (0700 on Ubuntu) is safe from the user, and closed to the tool: the proof's observation would
      // be lost after the proof, when the tool reads the raw evidence as the proving user.
      owners["/root"] = { uid: 0, mode: 0o700 };
      expect(rawDirErrors("/root/sp1-raw-20261101T100000Z", none, stat).join()).to.match(
        /root does not let others pass/,
      );
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
      // Another run's leftovers too (a crash): their probes would be counted with this run's.
      const left = new FakeTraceFs();
      left.files.set(`${ROOT}/kprobe_events`, `r32:sp1obs_${"f".repeat(16)}/udp4ret udp_sendmsg ret=$retval:s32`);
      expect(() => new TraceSession(left, NONCE_A).precheck()).to.throw(/PROBES_EXIST: 1 probes of an earlier/);
      const leftInstance = new FakeTraceFs();
      leftInstance.dirs.add(`${ROOT}/instances/sp1obs_${"f".repeat(16)}`);
      expect(() => new TraceSession(leftInstance, NONCE_A).precheck()).to.throw(/INSTANCE_EXISTS/);
      // Other tools' probes and instances are theirs.
      const others = new FakeTraceFs();
      others.files.set(`${ROOT}/kprobe_events`, "p:kprobes/my_probe do_sys_open");
      others.dirs.add(`${ROOT}/instances/foo`);
      expect(new TraceSession(others, NONCE_A).precheck()).to.equal(12);
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
      expect(s.misses()).to.equal(0);
      fs.misses.set("udp4ret", 2);
      fs.misses.set("newtask", 1);
      expect(s.misses()).to.equal(3);
      // Every probe enabled, and kprobes armed where debugfs shows it; one switched off, or all disarmed, is not.
      expect(s.armed()).to.equal(true);
      const enable = at("events/sp1obs_0123456789abcdef/xmit/enable");
      fs.files.set(enable, "0");
      expect(s.armed()).to.equal(false);
      fs.files.set(enable, "1");
      fs.files.set("/sys/kernel/debug/kprobes/enabled", "0\n");
      expect(s.armed()).to.equal(false);
      fs.files.set("/sys/kernel/debug/kprobes/enabled", "1\n");
      expect(s.armed()).to.equal(true);
      expect(s.close()).to.deep.equal([]);
      expect(fs.files.get(`${ROOT}/kprobe_events`)).to.equal("");
      expect(fs.exists(`${ROOT}/instances/sp1obs_${NONCE_A}`)).to.equal(false);
      // Its probes gone, the session vouches for nothing.
      expect(() => s.misses()).to.throw(/defined no probe/);
      expect(s.armed()).to.equal(false);
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
