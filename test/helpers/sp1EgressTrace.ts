/**
 * SP1-PA3C test helper: synthetic raw observer evidence, line for line in the exact text tracefs prints for a kprobe
 * event (the one format the real capture in test/fixtures/sp1-egress-observer/selftest-capture shows for the 9 probes
 * its self-test exercises, the other 18 printed by the same kernel function), so the parser, the normalizer and the
 * derivation can be driven through every case without a kernel, a network or a proof. TraceBuilder writes events in
 * order on a monotonic clock; standardRun() composes one complete, consistent attributed run (the observer, the tool,
 * its probes, the proof's host and a docker CLI, both counter snapshots) that each test changes in exactly one way.
 * Research prototype. Not audited.
 */
import {
  FACTS_SCHEMA,
  MANIFEST_SCHEMA,
  OBSERVER_SCRIPT_REL,
  PROBES,
  RAW_FACTS_FILE,
  RAW_TRACE_FILE,
  configSha256,
  formatMarker,
  observerConfig,
  sha256Hex,
} from "../../scripts/sp1-egress-observer";
import {
  fieldSpecs,
  type FieldValue,
  type HostExecutable,
  type RawEvidence,
} from "../../scripts/lib/sp1-egress-attribution";

export const NONCE_A = "0123456789abcdef";
export const HOST_NETNS = 4026531833;
export const CONTAINER_NETNS = 4026532235;
export const NF_DROP = 12;
export const BOOT_ID = "bef31ebf-fea0-4ee3-b462-d1c77fed4d42";
export const RESOLVER = "10.255.255.254";
export const HOST_ADDR = "172.22.169.196";
export const OBSERVER_SHA = "55".repeat(32);
export const READY_UTC = "2026-11-01T09:59:00Z";
export const T0 = 5_000_000;
export const HOST_EXE: HostExecutable = { path: "/srv/sp1/bin/mldsa65-host", dev: "8:48", ino: 4242 };
export const TABLE = "inet pa3c_test";

export interface Proc {
  comm: string;
  tid: number;
  tgid: number | null;
}
export const OBSERVER: Proc = { comm: "MainThread", tid: 1000, tgid: 1000 };
export const TOOL: Proc = { comm: "MainThread", tid: 1003, tgid: 1003 };
export const HOST: Proc = { comm: "mldsa65-host", tid: 1010, tgid: 1010 };
export const IDLE: Proc = { comm: "<idle>", tid: 0, tgid: null };

const SPEC = new Map(PROBES.map((p) => [p.name, { probe: p, fields: fieldSpecs(p.fetch) }]));

/** The little-endian u32 the kernel prints for an IPv4 address's network-order bytes. */
export const le32 = (ip: string) => {
  const [a, b, c, d] = ip.split(".").map(Number);
  return (a | (b << 8) | (c << 16) | (d << 24)) >>> 0;
};
/** The little-endian u16 the kernel prints for a network-order port. */
export const le16 = (port: number) => ((port & 0xff) << 8) | ((port >>> 8) & 0xff);
/** An IPv6 address's 16 bytes as the four little-endian u32 words the kernel prints. */
export function le128(bytes: number[]): number[] {
  return [0, 4, 8, 12].map((k) => (bytes[k] | (bytes[k + 1] << 8) | (bytes[k + 2] << 16) | (bytes[k + 3] << 24)) >>> 0);
}
const bytesOf = (text: string) => [...Buffer.from(text, "latin1")];
const pad = (b: number[], n: number) => [...b, ...new Array(Math.max(0, n - b.length)).fill(0)].slice(0, n);

export function dnsQuery(id: number, qname: string): number[] {
  const labels = qname.split(".").flatMap((l) => [l.length, ...bytesOf(l)]);
  return [id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1];
}

/** An IPv4 packet (header without options) carrying `l4` of protocol `proto`. */
export function ipv4(src: string, dst: string, proto: number, l4: number[]): number[] {
  const total = 20 + l4.length;
  return [
    0x45,
    0,
    total >> 8,
    total & 0xff,
    0,
    0,
    0x40,
    0,
    64,
    proto,
    0,
    0,
    ...src.split(".").map(Number),
    ...dst.split(".").map(Number),
    ...l4,
  ];
}
export const udp = (sport: number, dport: number, payload: number[]) => [
  sport >> 8,
  sport & 0xff,
  dport >> 8,
  dport & 0xff,
  (8 + payload.length) >> 8,
  (8 + payload.length) & 0xff,
  0,
  0,
  ...payload,
];
export const tcp = (sport: number, dport: number, flags: number) => [
  sport >> 8,
  sport & 0xff,
  dport >> 8,
  dport & 0xff,
  0,
  0,
  0,
  1,
  0,
  0,
  0,
  0,
  0x50,
  flags,
  0xff,
  0xff,
  0,
  0,
  0,
  0,
];
/** An ICMP error (type/code) quoting `original`'s header and first 8 bytes. */
export const icmpError = (type: number, code: number, original: number[]) => [
  type,
  code,
  0,
  0,
  0,
  0,
  0,
  0,
  ...original.slice(0, 28),
];

export interface FieldMap {
  [name: string]: FieldValue;
}

/** Writes raw trace lines in tracefs's record-tgid text format, in order, on a microsecond monotonic clock. */
export class TraceBuilder {
  readonly nonce: string;
  t: number;
  seq = 0;
  readonly lines: string[] = [];

  constructor(nonce = NONCE_A, t0 = T0) {
    this.nonce = nonce;
    this.t = t0;
  }

  /** The stamp of the next line: `at` when given (never backwards), else 100 us after the last. */
  private stamp(at?: number): number {
    this.t = at !== undefined ? Math.max(at, this.t) : this.t + 100;
    return this.t;
  }

  static line(p: Proc, cpu: number, flags: string, t: number, event: string, rest: string): string {
    const ts = `${Math.floor(t / 1_000_000)}.${String(t % 1_000_000).padStart(6, "0")}`;
    const tgid = p.tgid === null ? "-------" : String(p.tgid).padStart(7);
    return `${p.comm.padStart(16)}-${String(p.tid).padEnd(7)} (${tgid}) [${String(cpu).padStart(3, "0")}] ${flags} ${ts.padStart(12)}: ${event}: ${rest}`;
  }

  raw(line: string): this {
    this.lines.push(line);
    return this;
  }

  /** One probe event with `values` for every field of its definition, in the definition's order. */
  probe(p: Proc, name: string, values: FieldMap, opts: { cpu?: number; flags?: string; at?: number } = {}): this {
    const s = SPEC.get(name);
    if (!s) throw new Error(`no probe ${name}`);
    const fields = s.fields.map((f) => {
      const v = f.type === "comm" ? (values[f.name] ?? p.comm) : values[f.name];
      if (v === undefined) throw new Error(`${name} needs ${f.name}`);
      if (f.type === "comm") return `${f.name}="${String(v)}"`;
      if (f.type === "bytes" || f.type === "words") {
        const arr = v as number[];
        if (arr.length !== f.count) throw new Error(`${name}.${f.name} takes ${f.count} elements`);
        return `${f.name}={${arr.map((x) => `0x${x.toString(16)}`).join(",")}}`;
      }
      if (f.type === "x") return `${f.name}=${typeof v === "string" ? v : `0x${(v as number).toString(16)}`}`;
      return `${f.name}=${String(v)}`;
    });
    const loc = s.probe.kind === "r" ? `(caller+0x6e/0x80 <- ${s.probe.symbol})` : `(${s.probe.symbol}+0x4/0x100)`;
    return this.raw(
      TraceBuilder.line(
        p,
        opts.cpu ?? 1,
        opts.flags ?? ".....",
        this.stamp(opts.at),
        name,
        `${loc} ${fields.join(" ")}`,
      ),
    );
  }

  /** An observer marker (the next sequence number unless `seq` is given), written by `writer`. */
  marker(
    kind: string,
    fields: Record<string, string | number> = {},
    opts: { writer?: Proc; seq?: number; at?: number; nonce?: string } = {},
  ): this {
    const seq = opts.seq ?? ++this.seq;
    const text = formatMarker(opts.nonce ?? this.nonce, seq, kind, fields);
    return this.raw(
      TraceBuilder.line(opts.writer ?? OBSERVER, 2, "...1.", this.stamp(opts.at), "tracing_mark_write", text),
    );
  }

  spawn(parent: Proc, child: number, opts: { thread?: boolean; kthread?: boolean } = {}): this {
    return this.probe(parent, "newtask", {
      cpid: child,
      ctgid: opts.thread ? (parent.tgid ?? 0) : child,
      pflags: opts.kthread ? 0x00200040 : 0x400040,
    });
  }

  exec(p: Proc, path: string, dev = 8388656, ino = 777): this {
    const b = pad(bytesOf(path), 128);
    return this.probe(p, "exec", { ino, dev, f0: b.slice(0, 64), f1: b.slice(64) });
  }

  exit(p: Proc, code = 0): this {
    return this.probe(p, "exit", { code });
  }

  /** A UDP send: to `dst`:`port` by address (unconnected) or through a connected socket. */
  udp4(
    p: Proc,
    sk: string,
    dst: string,
    port: number,
    o: { connected?: boolean; netns?: number; len?: number } = {},
  ): this {
    const byName = !o.connected;
    return this.probe(p, "udp4", {
      sk,
      len: o.len ?? 39,
      namelen: byName ? 16 : 0,
      nfam: byName ? 2 : 0,
      nport: byName ? le16(port) : 0,
      naddr: byName ? le32(dst) : 0,
      n6t: 0,
      daddr: byName ? 0 : le32(dst),
      dport: byName ? 0 : le16(port),
      netns: o.netns ?? HOST_NETNS,
    });
  }

  udp4ret(p: Proc, sk: string, ret: number, sport: number): this {
    return this.probe(p, "udp4ret", { ret, sk, sport });
  }

  tcp4(p: Proc, sk: string, dst: string, port: number, netns = HOST_NETNS): this {
    return this.probe(p, "tcp4", { sk, fam: 2, port: le16(port), addr: le32(dst), netns });
  }

  tcp4ret(p: Proc, sk: string, ret: number, sport: number): this {
    return this.probe(p, "tcp4ret", { ret, sk, sport });
  }

  tcpst(p: Proc, sk: string, from: number, to: number, flags = "....."): this {
    return this.probe(p, "tcpst", { sk, state: to, old: from }, { flags });
  }

  /** A netfilter drop of `packet` (its first 192 bytes), by socket `sk` ("0x0" for none), in `p`'s context. */
  drop(p: Proc, sk: string, packet: number[], o: { flags?: string; skns?: number; ethertype?: number } = {}): this {
    const b = pad(packet, 192);
    return this.probe(
      p,
      "nfdrop",
      {
        reason: NF_DROP,
        sk,
        skns: o.skns ?? (sk === "0x0" ? 0 : HOST_NETNS),
        proto: le16(o.ethertype ?? 0x0800),
        len: packet.length,
        h0: b.slice(0, 64),
        h1: b.slice(64, 128),
        h2: b.slice(128, 192),
      },
      { flags: o.flags },
    );
  }

  xmit(
    p: Proc,
    ifindex: number,
    frame: number[],
    o: { netns?: number; ethertype?: number; flags?: string } = {},
  ): this {
    return this.probe(
      p,
      "xmit",
      {
        skb: "0xffff888000001000",
        ifindex,
        netns: o.netns ?? HOST_NETNS,
        proto: le16(o.ethertype ?? 0x0800),
        len: frame.length,
        h0: pad(frame, 64),
      },
      { flags: o.flags },
    );
  }

  text(): string {
    return this.lines.length === 0 ? "" : `${this.lines.join("\n")}\n`;
  }
}

/** The µs stamp of a UTC time on the standard run's clock (READY at T0 is READY_UTC). */
export const tAt = (utc: string) => T0 + (Date.parse(utc) - Date.parse(READY_UTC)) * 1000;

export interface Counted {
  resolver: number;
  tcp: number;
  other: number;
}

/** An `nft -j list table` of the standard boundary (PA3B's shape) with these counter values. */
export function nftListing(c: Counted, family = "inet", name = "pa3c_test") {
  const rule = (handle: number, match: unknown[], verdict: unknown, packets: number | null) => ({
    rule: {
      family,
      table: name,
      chain: "output",
      handle,
      expr: [...match, ...(packets === null ? [] : [{ counter: { packets, bytes: packets * 60 } }]), verdict],
    },
  });
  const dst = (right: string) => ({
    match: { op: "==", left: { payload: { protocol: "ip", field: "daddr" } }, right },
  });
  return {
    nftables: [
      { metainfo: { version: "1.0.9", json_schema_version: 1 } },
      { table: { family, name, handle: 1 } },
      {
        chain: {
          family,
          table: name,
          name: "output",
          handle: 1,
          type: "filter",
          hook: "output",
          prio: -10,
          policy: "accept",
        },
      },
      rule(2, [dst(RESOLVER)], { reject: { type: "icmpx", expr: "port-unreachable" } }, c.resolver),
      rule(
        3,
        [{ match: { op: "==", left: { fib: { result: "type", flags: ["daddr"] } }, right: "local" } }],
        { accept: null },
        null,
      ),
      rule(
        4,
        [{ match: { op: "==", left: { meta: { key: "l4proto" } }, right: "tcp" } }],
        { reject: { type: "tcp reset" } },
        c.tcp,
      ),
      rule(5, [], { reject: { type: "icmpx", expr: "admin-prohibited" } }, c.other),
    ],
  };
}

export interface FactsOpts {
  nonce?: string;
  mode?: "RUN" | "SELF_TEST";
  counters?: [Counted, Counted];
  stats?: { overrun?: number; droppedEvents?: number };
  failures?: string[];
  hostNetns?: number;
  nfDropReason?: number;
  /** The observer script's digest the facts name (a temporary repository binds its own committed observer). */
  observerSha?: string;
}

export function facts(o: FactsOpts = {}) {
  const nonce = o.nonce ?? NONCE_A;
  const hostNetns = o.hostNetns ?? HOST_NETNS;
  const nfDropReason = o.nfDropReason ?? NF_DROP;
  const config = observerConfig({ nonce, hostNetns, nfDropReason });
  const [c1, c2] = o.counters ?? [
    { resolver: 10, tcp: 3, other: 1 },
    { resolver: 10, tcp: 3, other: 1 },
  ];
  return {
    schema: FACTS_SCHEMA,
    mode: o.mode ?? "RUN",
    nonce,
    group: `sp1obs_${nonce}`,
    observer: { script: OBSERVER_SCRIPT_REL, scriptSha256: o.observerSha ?? OBSERVER_SHA },
    kernelRelease: "6.18.33.1-microsoft-standard-WSL2",
    bootId: BOOT_ID,
    hostNetns,
    resolvers: [RESOLVER],
    wslInterop: "enabled",
    interfaces: [
      { ifindex: 1, name: "lo", addresses: ["127.0.0.1/8", `${RESOLVER}/32`, "::1/128"] },
      { ifindex: 2, name: "eth0", addresses: [`${HOST_ADDR}/20`] },
      { ifindex: 3, name: "docker0", addresses: ["172.17.0.1/16"] },
    ],
    uplinks: [2],
    table: TABLE,
    user: { name: "prover", uid: 1001, gid: 1001 },
    command: [
      "/usr/local/bin/node",
      "<repo>/node_modules/tsx/dist/cli.mjs",
      "<repo>/scripts/measure-sp1-attributed-proof-exercise.ts",
    ],
    counters: [
      { n: 1, nft: nftListing(c1) },
      { n: 2, nft: nftListing(c2) },
    ],
    heartbeats: 0,
    failures: o.failures ?? [],
    nfDropReason,
    config,
    configSha256: configSha256(config),
    kprobeReadBack: config.probes,
    readyClock: { utc: READY_UTC, monoNs: String(BigInt(T0 - 50) * 1000n) },
    leftoverLines: 0,
    stats: Array.from({ length: 4 }, (_, cpu) => ({
      cpu,
      entries: 0,
      overrun: o.stats?.overrun ?? 0,
      commitOverrun: 0,
      droppedEvents: o.stats?.droppedEvents ?? 0,
      readEvents: 100,
    })),
    cleanup: [],
  };
}

export function rawOf(trace: string, factsObj: unknown, extra: { name: string; text: string }[] = []): RawEvidence {
  const factsText = `${JSON.stringify(factsObj, null, 2)}\n`;
  const files = [{ name: RAW_TRACE_FILE, text: trace }, { name: RAW_FACTS_FILE, text: factsText }, ...extra].map(
    (f) => {
      const bytes = Buffer.from(f.text, "latin1");
      return { name: f.name, bytes: bytes.length, sha256: sha256Hex(bytes) };
    },
  );
  return { trace, facts: factsText, manifest: `${JSON.stringify({ schema: MANIFEST_SCHEMA, files }, null, 2)}\n` };
}

/** A DNS lookup by `p` through a connected socket to the resolver, refused at the output hook, with the boundary's
 * own ICMP answer to the resolver address refused too (a resolver on lo answers itself: the PA3B shape). */
export function refusedLookup(
  b: TraceBuilder,
  p: Proc,
  sk: string,
  qname: string,
  sport: number,
  opts: { id?: number } = {},
): void {
  const query = ipv4(RESOLVER, RESOLVER, 17, udp(sport, 53, dnsQuery(opts.id ?? 0x1234, qname)));
  b.udp4(p, sk, RESOLVER, 53, { connected: true });
  b.drop(p, "0xffff888000009000", ipv4(RESOLVER, RESOLVER, 1, icmpError(3, 3, query)), { flags: "b..1." });
  b.drop(p, sk, query);
  b.udp4ret(p, sk, -1, sport);
}

/** A TCP connection by `p` to `dst`:`port`, refused (reset) at the output hook. */
export function refusedConnect(b: TraceBuilder, p: Proc, sk: string, dst: string, port: number, sport: number): void {
  b.tcp4(p, sk, dst, port);
  b.tcpst(p, sk, 7, 2);
  b.drop(p, sk, ipv4(HOST_ADDR, dst, 6, tcp(sport, port, 0x02)));
  b.tcp4ret(p, sk, 0, sport);
  b.tcpst(p, sk, 2, 7);
}

export interface RunHooks {
  /** Between READY and the window (after the first counters). */
  beforeWindow?: (b: TraceBuilder) => void;
  /** Inside the window, after PROBES_BEFORE_BEGIN and before the before-probes (the tool is running). */
  startOfWindow?: (b: TraceBuilder) => void;
  /** Inside the proof (after the host's exec, before its exit). */
  duringProof?: (b: TraceBuilder) => void;
  /** Inside the window, after the after-probes and before PROBES_AFTER_END. */
  endOfWindow?: (b: TraceBuilder) => void;
  /** After the window, before TOOL_DONE. */
  afterWindow?: (b: TraceBuilder) => void;
  /** The probes the tool makes in each phase (the standard set by default). */
  probes?: { dns: string[]; tcpByName: string[]; tcpByAddress: string[] };
  /** Skip one standard element by name (for the coverage tests). */
  omit?: string[];
  heartbeatEvery?: number;
  commit?: string;
  host?: string;
}

export const STANDARD_PROBES = {
  dns: ["example.invalid", "registry.invalid"],
  tcpByName: ["example.invalid", "registry.invalid"],
  tcpByAddress: ["203.0.113.5", "1.1.1.1", "8.8.8.8"],
};

/**
 * One complete attributed run, consistent with the synthetic run observation of test/helpers/sp1ProofExercise.ts
 * (its probe targets, its UTC stamps, its source commit and host label): returns the builder (for counting) and the
 * drops between the two counter snapshots (for the boundary's counters).
 */
export function standardRun(hooks: RunHooks = {}): { b: TraceBuilder; trace: string; counted: Counted } {
  const b = new TraceBuilder();
  const omit = new Set(hooks.omit ?? []);
  const beatEvery = hooks.heartbeatEvery ?? 20_000_000;
  let beats = 0;
  let lastBeat = 0;
  const beatUntil = (t: number) => {
    while (lastBeat + beatEvery < t) {
      lastBeat += beatEvery;
      if (!omit.has("HEARTBEAT")) b.marker("HEARTBEAT", { n: ++beats, tracingOn: 1, loss: 0 }, { at: lastBeat });
    }
  };
  const mark = (kind: string, fields: Record<string, string | number> = {}, at?: number) => {
    if (at !== undefined) beatUntil(at);
    if (!omit.has(kind) && !omit.has(`${kind}:${fields.name ?? fields.n ?? ""}`)) b.marker(kind, fields, { at });
  };
  b.spawn(OBSERVER, 1001).exec({ comm: "MainThread", tid: 1001, tgid: 1001 }, "/bin/cat");
  mark(
    "READY",
    {
      mode: "RUN",
      bootId: BOOT_ID,
      hostNetns: HOST_NETNS,
      config: configSha256(observerConfig({ nonce: NONCE_A, hostNetns: HOST_NETNS, nfDropReason: NF_DROP })),
      utc: READY_UTC,
      monoNs: String(BigInt(T0 - 50) * 1000n),
    },
    T0,
  );
  lastBeat = b.t;
  mark("COUNTERS_BEGIN", { n: 1 });
  b.spawn(OBSERVER, 1002)
    .exec({ comm: "MainThread", tid: 1002, tgid: 1002 }, "/usr/sbin/nft")
    .exit({ comm: "nft", tid: 1002, tgid: 1002 });
  mark("COUNTERS_END", { n: 1, sha256: "aa".repeat(32) });
  if (!omit.has("HEARTBEAT")) b.marker("HEARTBEAT", { n: ++beats, tracingOn: 1, loss: 0 });
  lastBeat = b.t;
  const counterStart = b.lines.length;
  hooks.beforeWindow?.(b);
  b.spawn(OBSERVER, TOOL.tid).exec({ comm: "MainThread", tid: TOOL.tid, tgid: TOOL.tgid }, "/usr/bin/setpriv");
  b.exec({ comm: "setpriv", tid: TOOL.tid, tgid: TOOL.tgid }, "/usr/local/bin/node", 8388656, 1021);
  mark("SPAWNED", { pid: 622 });
  mark("HELLO", { commit: hooks.commit ?? "c".repeat(40), host: hooks.host ?? "proving-host-a" });
  const probes = hooks.probes ?? STANDARD_PROBES;
  let sk = 0x9100;
  let sport = 40000;
  const probeSet = () => {
    for (const q of probes.dns) refusedLookup(b, TOOL, `0xffff8880000${(sk++).toString(16)}`, q, sport++);
    for (const q of probes.tcpByName) refusedLookup(b, TOOL, `0xffff8880000${(sk++).toString(16)}`, q, sport++);
    for (const ip of probes.tcpByAddress)
      refusedConnect(b, TOOL, `0xffff8880000${(sk++).toString(16)}`, ip, 443, sport++);
  };
  mark("PHASE", { name: "PROBES_BEFORE_BEGIN" }, tAt("2026-11-01T09:59:50Z"));
  hooks.startOfWindow?.(b);
  probeSet();
  mark("PHASE", { name: "PROBES_BEFORE_END" });
  mark("PHASE", { name: "GATE_BEGIN" }, tAt("2026-11-01T10:00:00Z"));
  mark("PHASE", { name: "HOST_SPAWN" }, tAt("2026-11-01T10:20:00Z"));
  b.spawn(TOOL, HOST.tid).exec(
    { comm: "MainThread", tid: HOST.tid, tgid: HOST.tgid },
    HOST_EXE.path,
    8388656,
    HOST_EXE.ino,
  );
  const docker: Proc = { comm: "docker", tid: 1011, tgid: 1011 };
  b.spawn(HOST, 1011).exec({ comm: "mldsa65-host", tid: 1011, tgid: 1011 }, "/usr/bin/docker").exit(docker);
  hooks.duringProof?.(b);
  beatUntil(tAt("2026-11-01T11:40:00Z"));
  b.exit(HOST, 0);
  mark("PHASE", { name: "HOST_EXIT" }, tAt("2026-11-01T11:40:01Z"));
  mark("PHASE", { name: "GATE_END" }, tAt("2026-11-01T11:59:40Z"));
  mark("PHASE", { name: "PROBES_AFTER_BEGIN" }, tAt("2026-11-01T11:59:50Z"));
  probeSet();
  hooks.endOfWindow?.(b);
  mark("PHASE", { name: "PROBES_AFTER_END" });
  hooks.afterWindow?.(b);
  if (!omit.has("HEARTBEAT")) b.marker("HEARTBEAT", { n: ++beats, tracingOn: 1, loss: 0 });
  mark("TOOL_DONE", { ok: 1 });
  const counterEnd = b.lines.length;
  mark("COUNTERS_BEGIN", { n: 2 });
  b.spawn(OBSERVER, 1090)
    .exec({ comm: "MainThread", tid: 1090, tgid: 1090 }, "/usr/sbin/nft")
    .exit({ comm: "nft", tid: 1090, tgid: 1090 });
  mark("COUNTERS_END", { n: 2, sha256: "bb".repeat(32) });
  if (!omit.has("HEARTBEAT")) b.marker("HEARTBEAT", { n: ++beats, tracingOn: 1, loss: 0 });
  mark("STOP", { failures: 0 });
  const counted: Counted = { resolver: 0, tcp: 0, other: 0 };
  for (const line of b.lines.slice(counterStart, counterEnd)) {
    if (!line.includes(": nfdrop: ")) continue;
    const h0 = /h0=\{([^}]*)\}/.exec(line)?.[1].split(",").map(Number) ?? [];
    const dst = h0.slice(16, 20).join(".");
    if (dst === RESOLVER) counted.resolver++;
    else if (h0[9] === 6) counted.tcp++;
    else counted.other++;
  }
  return { b, trace: b.text(), counted };
}

/** The standard run's raw evidence: trace, facts with the counters it implies, and a manifest binding both. */
export function standardRaw(hooks: RunHooks = {}, factsOpts: FactsOpts = {}): RawEvidence {
  const { trace, counted } = standardRun(hooks);
  const before: Counted = { resolver: 10, tcp: 3, other: 1 };
  const after: Counted = { resolver: 10 + counted.resolver, tcp: 3 + counted.tcp, other: 1 + counted.other };
  return rawOf(trace, facts({ counters: [before, after], ...factsOpts }));
}
