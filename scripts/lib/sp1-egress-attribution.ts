/**
 * SP1-PA3C: continuous egress attribution for a FUTURE proof exercise (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md,
 * "SP1-PA3C"). No proof is made here and no historical evidence is read differently: SP1-PA3B's run stays a v1
 * observation, attested at its edges, with its refused resolver packets refused but unattributed.
 *
 * Three steps, kept apart:
 *  - parse: the raw tracefs text the root observer drained (scripts/sp1-egress-observer.ts), one line per kernel
 *    event, read POSITIONALLY and field by field in the exact order the observer's PROBES define (a line that does not
 *    read exactly so is refused, never guessed at);
 *  - normalize: a deterministic, privacy-minimal projection of those lines (process creations, the proof's execs and
 *    exits, every send and connect with its return, TCP states of connected sockets, every netfilter drop with the
 *    refused packet's headers, every transmit on a host device), with DNS names and exec paths kept only for the
 *    observer, the measurement tool, the proof's process tree and the gnark containers;
 *  - derive: from the normalized events and facts alone, never from a claim in the observation, the coverage window,
 *    its continuity, which process caused every attempt, how every refused packet joins an attempt (or why it does
 *    not), the reconciliation with the enforcement table's counters, and the assurance the evidence supports.
 *
 * Boundary enforcement, packet observation, process attribution, target attribution, proof execution and production
 * readiness are separate facts: a refused packet is not an attributed one, a captured one is not a process's, and a
 * DNS name alone names no process. Research prototype. Not audited.
 */
import { isIP } from "node:net";
import { createInterface } from "node:readline";

import {
  CTL_TAG,
  FACTS_SCHEMA,
  MODES,
  MANIFEST_SCHEMA,
  MARKER_TAG,
  NONCE,
  OBSERVER_MECHANISM,
  OBSERVER_SCRIPT_REL,
  PHASES,
  PROBES,
  RAW_FACTS_FILE,
  RAW_MANIFEST_FILE,
  RAW_TRACE_FILE,
  canonicalJson,
  configSha256,
  formatCtl,
  observerConfig,
  sha256Hex,
  type CpuStats,
  type Interface,
  type Mode,
  type ObserverConfig,
} from "../sp1-egress-observer";

export interface Refusal {
  reason: string;
  detail: string;
}

/** A stalled observer: two heartbeats further apart than this leave a window in which a stopped trace could hide. */
export const MAX_HEARTBEAT_GAP_US = 30_000_000;
/** The READY marker's stamp must follow the observer's own monotonic reading by at most this much. */
export const READY_CLOCK_TOLERANCE_US = 2_000_000;
/** The tool's wall-clock stamps may differ from the trace's monotonic clock mapped to UTC by this much (WSL2's wall
 * clock can step; the run's stamps are second-resolution). */
export const UTC_TOLERANCE_SECONDS = 5;
export const AF_INET = 2;
export const AF_INET6 = 10;
export const EPERM = 1;
const TCP_ESTABLISHED = 1;
const TCP_SYN_SENT = 2;
const TCP_CLOSE = 7;
const PF_KTHREAD = 0x00200000;
const IPPROTO_ICMP = 1;
const IPPROTO_IGMP = 2;
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_ICMPV6 = 58;
const DNS_PORT = 53;

// ---------------------------------------------------------------------------------------------------------------
// Parse: one raw line -> one typed event
// ---------------------------------------------------------------------------------------------------------------

export type FieldType = "x" | "s" | "u" | "bytes" | "words" | "comm";
export interface FieldSpec {
  name: string;
  type: FieldType;
  /** Elements of an array field. */
  count?: number;
}

/** The fields a probe prints, in order, from the observer's own definition (one source of truth). */
export function fieldSpecs(fetch: string): FieldSpec[] {
  return fetch.split(" ").map((token) => {
    const eq = token.indexOf("=");
    const name = token.slice(0, eq);
    if (token.slice(eq + 1) === "$comm") return { name, type: "comm" };
    const type = token.slice(token.lastIndexOf(":") + 1);
    const array = /^(x8|x32)\[(\d+)\]$/.exec(type);
    if (array) return { name, type: array[1] === "x8" ? "bytes" : "words", count: Number(array[2]) };
    if (/^x(8|16|32|64)$/.test(type)) return { name, type: "x" };
    if (/^s(8|16|32|64)$/.test(type)) return { name, type: "s" };
    if (/^u(8|16|32|64)$/.test(type)) return { name, type: "u" };
    throw new Error(`unknown fetch type ${type} in ${token}`);
  });
}

const SPECS: ReadonlyMap<string, FieldSpec[]> = new Map(PROBES.map((p) => [p.name, fieldSpecs(p.fetch)]));

export type FieldValue = number | string | number[];
export interface TraceEvent {
  /** Position in the raw trace (0-based line): the kernel merged every CPU's events in time order. */
  i: number;
  comm: string;
  tid: number;
  /** null when the kernel printed no thread group (`-------`). */
  tgid: number | null;
  cpu: number;
  flags: string;
  /** Microseconds on the trace clock (CLOCK_MONOTONIC). */
  t: number;
  event: string;
  marker?: string;
  fields?: Record<string, FieldValue>;
}

const HEAD = /^(\d+) +\((-------| *\d+)\) \[(\d{3})\] (\S{5}) +(\d+)\.(\d{6}): ([a-z0-9_]+): (.*)$/;

function fieldValue(spec: FieldSpec, text: string): { value: FieldValue; rest: string } | null {
  if (spec.type === "comm") {
    if (!text.startsWith('"') || !text.endsWith('"') || text.length < 2) return null;
    const comm = text.slice(1, -1);
    return Buffer.byteLength(comm, "latin1") <= 15 ? { value: comm, rest: "" } : null;
  }
  // A value ends the line or is followed by exactly one space and the next field: no trailing or doubled space.
  const m =
    spec.type === "x"
      ? /^0x([0-9a-f]+)(?: (?=\S)|$)/.exec(text)
      : spec.type === "s"
        ? /^(-?\d+)(?: (?=\S)|$)/.exec(text)
        : spec.type === "u"
          ? /^(\d+)(?: (?=\S)|$)/.exec(text)
          : /^\{([0-9a-fx,]*)\}(?: (?=\S)|$)/.exec(text);
  if (!m) return null;
  const rest = text.slice(m[0].length);
  if (spec.type === "x") {
    const big = BigInt(`0x${m[1]}`);
    return { value: big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : `0x${m[1]}`, rest };
  }
  if (spec.type === "s" || spec.type === "u") {
    const n = Number(m[1]);
    return Number.isSafeInteger(n) ? { value: n, rest } : null;
  }
  const items = m[1] === "" ? [] : m[1].split(",");
  if (items.length !== spec.count || !items.every((x) => /^0x[0-9a-f]+$/.test(x))) return null;
  const values = items.map((x) => Number(x));
  const max = spec.type === "bytes" ? 0xff : 0xffffffff;
  return values.every((v) => v <= max) ? { value: values, rest } : null;
}

/**
 * One raw trace line (record-tgid format): the comm in the first 16 columns, `-`, the thread id, the thread group,
 * the CPU, five flag characters, the monotonic stamp, the event, and either a marker's text or the probe's fields in
 * exactly their defined order. Anything else is refused (a broken line is never repaired or skipped).
 */
export function parseTraceLine(line: string, i: number): TraceEvent {
  if (line.length < 18 || line[16] !== "-") throw new Error(`line ${i}: not a trace line`);
  const m = HEAD.exec(line.slice(17));
  if (!m) throw new Error(`line ${i}: not a trace line`);
  const [, tid, tgid, cpu, flags, sec, usec, event, rest] = m;
  const ev: TraceEvent = {
    i,
    comm: line.slice(0, 16).replace(/^ +/, ""),
    tid: Number(tid),
    tgid: tgid === "-------" ? null : Number(tgid.trim()),
    cpu: Number(cpu),
    flags,
    t: Number(sec) * 1_000_000 + Number(usec),
    event,
  };
  if (!Number.isSafeInteger(ev.t)) throw new Error(`line ${i}: the stamp is out of range`);
  if (event === "tracing_mark_write") {
    ev.marker = rest;
    return ev;
  }
  const specs = SPECS.get(event);
  if (!specs) throw new Error(`line ${i}: ${event} is no probe of the observer`);
  const loc = /^\(([^()]*)\) (.*)$/.exec(rest);
  if (!loc) throw new Error(`line ${i}: ${event} has no probe location`);
  let text = loc[2];
  const fields: Record<string, FieldValue> = {};
  for (const spec of specs) {
    if (!text.startsWith(`${spec.name}=`)) throw new Error(`line ${i}: ${event} lacks ${spec.name} where it belongs`);
    const parsed = fieldValue(spec, text.slice(spec.name.length + 1));
    if (parsed === null) throw new Error(`line ${i}: ${event}.${spec.name} does not read as its type`);
    fields[spec.name] = parsed.value;
    text = parsed.rest;
  }
  if (text !== "") throw new Error(`line ${i}: ${event} carries more than its fields`);
  ev.fields = fields;
  return ev;
}

/** Every line of a raw trace; a lost-events line (the ring buffer overflowed) is counted, never parsed as an event. */
export function parseTrace(text: string): { events: TraceEvent[]; lost: number } {
  if (text !== "" && !text.endsWith("\n")) throw new Error("the raw trace ends inside a line");
  const lines = text === "" ? [] : text.slice(0, -1).split("\n");
  let lost = 0;
  const events: TraceEvent[] = [];
  lines.forEach((line, i) => {
    if (/^CPU:\d+ \[LOST \d+ EVENTS\]$/.test(line)) {
      lost++;
      return;
    }
    events.push(parseTraceLine(line, i));
  });
  return { events, lost };
}

// ---------------------------------------------------------------------------------------------------------------
// Addresses and packets
// ---------------------------------------------------------------------------------------------------------------

/** An IPv4 address the kernel printed as the little-endian u32 of its network-order bytes. */
export const ip4 = (v: number) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255].join(".");
/** A port printed as the little-endian u16 of its network-order bytes. */
export const port16 = (v: number) => ((v & 0xff) << 8) | ((v >>> 8) & 0xff);
const bytesOfWords = (words: number[]) =>
  words.flatMap((w) => [w & 255, (w >>> 8) & 255, (w >>> 16) & 255, (w >>> 24) & 255]);

/** An IPv6 address from its 16 bytes (RFC 5952 text); an IPv4-mapped one reads as its IPv4 address. */
export function ip6(bytes: readonly number[]): string {
  if (bytes.length !== 16) throw new Error("an IPv6 address is 16 bytes");
  if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return bytes.slice(12).join(".");
  }
  const groups = Array.from({ length: 8 }, (_, k) => (bytes[2 * k] << 8) | bytes[2 * k + 1]);
  let best = -1;
  let bestLen = 0;
  for (let s = 0; s < 8; s++) {
    let e = s;
    while (e < 8 && groups[e] === 0) e++;
    if (e - s > bestLen && e - s >= 2) {
      best = s;
      bestLen = e - s;
    }
  }
  const hex = groups.map((g) => g.toString(16));
  if (best === -1) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

export interface Destination {
  addr: string;
  port: number | null;
}

export interface DnsQuestion {
  id: number;
  /** The question's name, or null when it was withheld (outside the proof's scope) or does not decode. */
  qname: string | null;
  withheld?: true;
  undecodable?: true;
  truncated?: true;
}

export interface Packet {
  v: 4 | 6 | null;
  proto: number | null;
  src: string | null;
  dst: string | null;
  sport: number | null;
  dport: number | null;
  tcpFlags?: number;
  icmp?: { type: number; code: number };
  /** The header an ICMP error quotes (what the refused packet it answers was). */
  inner?: { proto: number | null; src: string | null; dst: string | null; sport: number | null; dport: number | null };
  dns?: DnsQuestion;
}

const LABEL = /^[A-Za-z0-9_-]{1,63}$/;

/** The question name of a DNS query, from its wire bytes (null when it does not decode; truncated at the capture). */
export function dnsQuestion(b: readonly number[], at: number, end: number): DnsQuestion | null {
  if (at + 12 > end) return null;
  const id = (b[at] << 8) | b[at + 1];
  const labels: string[] = [];
  let p = at + 12;
  for (;;) {
    if (p >= end) return { id, qname: labels.length > 0 ? labels.join(".") : null, truncated: true };
    const n = b[p];
    if (n === 0) break;
    if (n > 63 || p + 1 + n > end) {
      if (n <= 63) return { id, qname: labels.length > 0 ? labels.join(".") : null, truncated: true };
      return { id, qname: null, undecodable: true };
    }
    const label = String.fromCharCode(...b.slice(p + 1, p + 1 + n));
    if (!LABEL.test(label)) return { id, qname: null, undecodable: true };
    labels.push(label.toLowerCase());
    p += 1 + n;
  }
  return labels.length > 0 ? { id, qname: labels.join(".") } : { id, qname: null, undecodable: true };
}

/** The headers of an IP packet captured from its first byte (`b`, `valid` bytes of it real). */
export function packetOf(b: readonly number[], valid: number): Packet {
  const end = Math.min(valid, b.length);
  const none: Packet = { v: null, proto: null, src: null, dst: null, sport: null, dport: null };
  if (end < 1) return none;
  const v = b[0] >> 4;
  const ports = (at: number) =>
    at + 4 <= end ? { s: (b[at] << 8) | b[at + 1], d: (b[at + 2] << 8) | b[at + 3] } : null;
  if (v === 4 && end >= 20) {
    const ihl = (b[0] & 15) * 4;
    const proto = b[9];
    const out: Packet = {
      v: 4,
      proto,
      src: b.slice(12, 16).join("."),
      dst: b.slice(16, 20).join("."),
      sport: null,
      dport: null,
    };
    if (ihl < 20) return out;
    if (proto === IPPROTO_TCP || proto === IPPROTO_UDP) {
      const p = ports(ihl);
      if (p) Object.assign(out, { sport: p.s, dport: p.d });
      if (proto === IPPROTO_TCP && ihl + 14 <= end) out.tcpFlags = b[ihl + 13];
      if (proto === IPPROTO_UDP && out.dport === DNS_PORT) {
        const q = dnsQuestion(b, ihl + 8, end);
        if (q) out.dns = q;
      }
    } else if (proto === IPPROTO_ICMP && ihl + 2 <= end) {
      out.icmp = { type: b[ihl], code: b[ihl + 1] };
      const at = ihl + 8;
      if ([3, 11, 12].includes(b[ihl]) && at + 20 <= end && b[at] >> 4 === 4) {
        const iihl = (b[at] & 15) * 4;
        const ip = ports(at + iihl);
        out.inner = {
          proto: b[at + 9],
          src: b.slice(at + 12, at + 16).join("."),
          dst: b.slice(at + 16, at + 20).join("."),
          sport: ip?.s ?? null,
          dport: ip?.d ?? null,
        };
      }
    }
    return out;
  }
  if (v === 6 && end >= 40) {
    const proto = b[6];
    const out: Packet = { v: 6, proto, src: ip6(b.slice(8, 24)), dst: ip6(b.slice(24, 40)), sport: null, dport: null };
    if (proto === IPPROTO_TCP || proto === IPPROTO_UDP) {
      const p = ports(40);
      if (p) Object.assign(out, { sport: p.s, dport: p.d });
      if (proto === IPPROTO_TCP && 54 <= end) out.tcpFlags = b[53];
      if (proto === IPPROTO_UDP && out.dport === DNS_PORT) {
        const q = dnsQuestion(b, 48, end);
        if (q) out.dns = q;
      }
    } else if (proto === IPPROTO_ICMPV6 && 42 <= end) {
      out.icmp = { type: b[40], code: b[41] };
    }
    return out;
  }
  return none;
}

// ---------------------------------------------------------------------------------------------------------------
// Normalized events: what the run observation commits
// ---------------------------------------------------------------------------------------------------------------

export type Ctx = "task" | "softirq" | "hardirq" | "nmi";
/** The context an event ran in, from ftrace's flag column ('s'/'S' softirq, 'h'/'H' hardirq, 'z'/'Z' NMI). */
export function ctxOf(flags: string): Ctx {
  const c = flags[2];
  if (c === "Z" || c === "z") return "nmi";
  if (c === "h" || c === "H") return "hardirq";
  if (c === "s" || c === "S") return "softirq";
  return "task";
}

export type SendProbe = "udp4" | "udp6" | "raw4" | "raw6" | "ping4" | "ping6" | "pkt";
export type ConnectProbe = "tcp4" | "tcp6";

interface Base {
  i: number;
  t: number;
  tid: number;
  tgid: number | null;
}
export type NormEvent =
  | (Base & { k: "marker"; text: string })
  | (Base & { k: "spawn"; child: number; kthread: boolean; comm: string | null })
  | (Base & { k: "exec"; dev: string; ino: number; path: string | null; comm: string | null })
  | (Base & { k: "exit"; code: number })
  | (Base & {
      k: "send";
      probe: SendProbe;
      comm: string;
      sk: string;
      netns: number;
      len: number;
      dest: Destination | null;
      ipProto?: number;
    })
  | (Base & { k: "sendret"; probe: SendProbe; sk: string; ret: number; sport: number | null })
  | (Base & { k: "connect"; probe: ConnectProbe; comm: string; sk: string; netns: number; dest: Destination | null })
  | (Base & { k: "connectret"; probe: ConnectProbe; sk: string; ret: number; sport: number | null })
  | (Base & { k: "tcpstate"; sk: string; from: number; to: number })
  | (Base & { k: "retransmit"; sk: string })
  | (Base & { k: "drop"; comm: string; ctx: Ctx; sk: string; skns: number | null; ethertype: number; packet: Packet })
  | (Base & {
      k: "xmit";
      comm: string;
      ctx: Ctx;
      ifindex: number;
      netns: number;
      ethertype: number;
      packet: Packet | null;
    });

const ptr = (v: FieldValue) => (typeof v === "number" ? `0x${v.toString(16)}` : String(v));
const num = (v: FieldValue) => {
  if (typeof v !== "number") throw new Error("a field that must be a number is not");
  return v;
};
const arr = (v: FieldValue) => {
  if (!Array.isArray(v)) throw new Error("a field that must be an array is not");
  return v;
};
/** A signed 32-bit return value (the kernel prints `$retval:s32` correctly; this only guards the range). */
const s32 = (v: FieldValue) => {
  const n = num(v);
  if (n < -2147483648 || n > 2147483647) throw new Error("a 32-bit return value is out of range");
  return n;
};
/** The kernel's dev_t (major << 20 | minor) as "major:minor". */
export const kernelDev = (dev: number) => `${Math.floor(dev / 1048576)}:${dev % 1048576}`;
/** glibc's dev_t encoding (what Node's bigint stat returns) as "major:minor": the same device kernelDev names. */
export function userDev(dev: bigint): string {
  const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn);
  const minor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn);
  return `${major}:${minor}`;
}
const swap16 = (v: number) => ((v & 0xff) << 8) | ((v >>> 8) & 0xff);
const bytesToText = (bytes: readonly number[]) => {
  const end = bytes.indexOf(0);
  return end === -1 ? null : Buffer.from(bytes.slice(0, end)).toString("latin1");
};

/** The destination an IPv4 send names: the message's address when one was given, else the connected peer. */
function v4Dest(f: Record<string, FieldValue>, withPort: boolean): Destination | null {
  const namelen = num(f.namelen);
  if (namelen >= 16 && num(f.nfam) === AF_INET)
    return { addr: ip4(num(f.naddr)), port: withPort ? port16(num(f.nport)) : null };
  if (namelen >= 24 && num(f.nfam) === AF_INET6 && f.n6t !== undefined) {
    return { addr: ip4(num(f.n6t)), port: withPort ? port16(num(f.nport)) : null };
  }
  if (namelen === 0 && num(f.daddr) !== 0)
    return { addr: ip4(num(f.daddr)), port: withPort ? port16(num(f.dport)) : null };
  return null;
}

function v6Dest(f: Record<string, FieldValue>, withPort: boolean): Destination | null {
  const namelen = num(f.namelen);
  if (namelen >= 24 && num(f.nfam) === AF_INET6)
    return { addr: ip6(bytesOfWords(arr(f.na))), port: withPort ? port16(num(f.nport)) : null };
  if (namelen === 0) {
    const bytes = bytesOfWords(arr(f.da));
    if (bytes.some((b) => b !== 0))
      return { addr: ip6(bytes), port: withPort && f.dport !== undefined ? port16(num(f.dport)) : null };
  }
  return null;
}

/** Turns one parsed event into its normalized form (redaction is applied separately, by scope). */
export function normalizeEvent(e: TraceEvent): NormEvent | null {
  const base: Base = { i: e.i, t: e.t, tid: e.tid, tgid: e.tgid };
  if (e.marker !== undefined) return { ...base, k: "marker", text: e.marker };
  const f = e.fields as Record<string, FieldValue>;
  switch (e.event) {
    case "newtask":
      if (num(f.cpid) !== num(f.ctgid)) return null; // a thread of an existing process: no new lineage
      return {
        ...base,
        k: "spawn",
        child: num(f.cpid),
        kthread: (num(f.pflags) & PF_KTHREAD) !== 0,
        comm: String(f.comm),
      };
    case "exec":
      return {
        ...base,
        k: "exec",
        dev: kernelDev(num(f.dev)),
        ino: num(f.ino),
        path: bytesToText([...arr(f.f0), ...arr(f.f1)]),
        comm: String(f.comm),
      };
    case "exit":
      if (e.tid !== e.tgid) return null; // only a thread group leader's exit ends a process
      return { ...base, k: "exit", code: num(f.code) };
    case "udp4":
      return {
        ...base,
        k: "send",
        probe: "udp4",
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        len: num(f.len),
        dest: v4Dest(f, true),
      };
    case "udp6":
      return {
        ...base,
        k: "send",
        probe: "udp6",
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        len: num(f.len),
        dest: v6Dest(f, true),
      };
    case "raw4":
    case "ping4":
      return {
        ...base,
        k: "send",
        probe: e.event,
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        len: num(f.len),
        dest: v4Dest(f, false),
        ...(e.event === "raw4" ? { ipProto: num(f.proto) } : {}),
      };
    case "raw6":
    case "ping6":
      return {
        ...base,
        k: "send",
        probe: e.event,
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        len: num(f.len),
        dest: v6Dest(f, false),
        ...(e.event === "raw6" ? { ipProto: num(f.proto) } : {}),
      };
    case "pkt":
      return {
        ...base,
        k: "send",
        probe: "pkt",
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        len: num(f.len),
        dest: null,
      };
    case "udp4ret":
    case "udp6ret":
      return {
        ...base,
        k: "sendret",
        probe: e.event.slice(0, 4) as SendProbe,
        sk: ptr(f.sk),
        ret: s32(f.ret),
        sport: num(f.sport),
      };
    case "raw4ret":
    case "raw6ret":
    case "ping4ret":
    case "ping6ret":
      return {
        ...base,
        k: "sendret",
        probe: e.event.slice(0, -3) as SendProbe,
        sk: ptr(f.sk),
        ret: s32(f.ret),
        sport: null,
      };
    case "pktret":
      return { ...base, k: "sendret", probe: "pkt", sk: ptr(f.sk), ret: s32(f.ret), sport: null };
    case "tcp4":
      return {
        ...base,
        k: "connect",
        probe: "tcp4",
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        dest: num(f.fam) === AF_INET ? { addr: ip4(num(f.addr)), port: port16(num(f.port)) } : null,
      };
    case "tcp6":
      return {
        ...base,
        k: "connect",
        probe: "tcp6",
        comm: String(f.comm),
        sk: ptr(f.sk),
        netns: num(f.netns),
        dest: num(f.fam) === AF_INET6 ? { addr: ip6(bytesOfWords(arr(f.a))), port: port16(num(f.port)) } : null,
      };
    case "tcp4ret":
    case "tcp6ret":
      return {
        ...base,
        k: "connectret",
        probe: e.event.slice(0, 4) as ConnectProbe,
        sk: ptr(f.sk),
        ret: s32(f.ret),
        sport: num(f.sport),
      };
    case "tcpst":
      return { ...base, k: "tcpstate", sk: ptr(f.sk), from: num(f.old), to: num(f.state) };
    case "tcpretx":
      return { ...base, k: "retransmit", sk: ptr(f.sk) };
    case "nfdrop": {
      const sk = ptr(f.sk);
      const ethertype = swap16(num(f.proto));
      const bytes = [...arr(f.h0), ...arr(f.h1), ...arr(f.h2)];
      const packet = ethertype === 0x0800 || ethertype === 0x86dd ? packetOf(bytes, num(f.len)) : packetOf([], 0);
      return {
        ...base,
        k: "drop",
        comm: String(f.comm),
        ctx: ctxOf(e.flags),
        sk,
        skns: sk === "0x0" ? null : num(f.skns),
        ethertype,
        packet,
      };
    }
    case "xmit": {
      const ethertype = swap16(num(f.proto));
      const h0 = arr(f.h0);
      const packet = ethertype === 0x0800 || ethertype === 0x86dd ? packetOf(h0.slice(14), num(f.len) - 14) : null;
      return {
        ...base,
        k: "xmit",
        comm: String(f.comm),
        ctx: ctxOf(e.flags),
        ifindex: num(f.ifindex),
        netns: num(f.netns),
        ethertype,
        packet,
      };
    }
    default:
      throw new Error(`no normalization for ${e.event}`);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Markers, lineage and scope (shared by the normalizer and the validator)
// ---------------------------------------------------------------------------------------------------------------

export interface Marker {
  i: number;
  t: number;
  tid: number;
  tgid: number | null;
  nonce: string;
  seq: number;
  kind: string;
  fields: Record<string, string>;
}

/** An observer marker (`SP1OBS <nonce> <seq> <KIND> k=v ...`); null for any other text. */
export function parseMarker(e: {
  i: number;
  t: number;
  tid: number;
  tgid: number | null;
  text: string;
}): Marker | null {
  const words = e.text.split(" ");
  if (words.length < 4 || words[0] !== MARKER_TAG || !NONCE.test(words[1]) || !/^[1-9]\d*$/.test(words[2])) return null;
  if (!/^[A-Z_]+$/.test(words[3])) return null;
  const fields: Record<string, string> = Object.create(null);
  for (const w of words.slice(4)) {
    const eq = w.indexOf("=");
    if (eq <= 0 || Object.hasOwn(fields, w.slice(0, eq))) return null;
    fields[w.slice(0, eq)] = w.slice(eq + 1);
  }
  return { i: e.i, t: e.t, tid: e.tid, tgid: e.tgid, nonce: words[1], seq: Number(words[2]), kind: words[3], fields };
}

export type Scope = "OBSERVER" | "TOOL" | "PROOF" | "PROOF_CONTAINER" | "CONTAINER" | "OTHER" | "KERNEL";
/** Scopes whose DNS names and exec paths the committed evidence keeps; everything else is withheld there. */
export const DISCLOSED: readonly Scope[] = ["OBSERVER", "TOOL", "PROOF", "PROOF_CONTAINER"];

export interface HostExecutable {
  path: string;
  /** "major:minor" of the device holding it. */
  dev: string;
  ino: number;
}

export interface Lineage {
  observerTgid: number | null;
  toolTgid: number | null;
  proofRoot: number | null;
  /** Scope of each process (by thread group) known to have lived in the window. */
  scopeOf: Map<number, Scope>;
  /** The gnark containers' network namespaces (from the observer's CONTAINER markers, verified by cgroup). */
  proofNetns: Set<number>;
  hostNetns: number;
  errors: Refusal[];
}

/**
 * Who is who, from facts only: the observer is the writer of READY; the tool is the observer's last child before
 * SPAWNED; the proof's root is the one exec, in the tool's process tree between HOST_SPAWN and HOST_EXIT, of exactly
 * the measured host executable (path, device and inode); a process created by a process in a scope joins that scope
 * (the proof's tree is carved out of the tool's).
 */
export function lineageOf(
  events: readonly NormEvent[],
  hostNetns: number,
  hostExecutable: HostExecutable | null,
): Lineage {
  const errors: Refusal[] = [];
  const no = (reason: string, detail: string) => errors.push({ reason, detail });
  const markers = events.map((e) => (e.k === "marker" ? parseMarker(e) : null)).filter((m): m is Marker => m !== null);
  const ready = markers.find((m) => m.kind === "READY");
  const spawned = markers.find((m) => m.kind === "SPAWNED");
  const hostSpawn = markers.find((m) => m.kind === "PHASE" && m.fields.name === "HOST_SPAWN");
  const hostExit = markers.find((m) => m.kind === "PHASE" && m.fields.name === "HOST_EXIT");
  const observerTgid = ready?.tgid ?? null;
  const scopeOf = new Map<number, Scope>();
  let toolTgid: number | null = null;
  if (observerTgid === null) no("OBSERVER_LINEAGE", "no READY marker names the observer");
  else {
    scopeOf.set(observerTgid, "OBSERVER");
    if (spawned) {
      const children = events.filter(
        (e): e is Extract<NormEvent, { k: "spawn" }> =>
          e.k === "spawn" && e.tgid === observerTgid && e.i > (ready?.i ?? -1) && e.i < spawned.i,
      );
      toolTgid = children.at(-1)?.child ?? null;
    }
    if (toolTgid === null)
      no("OBSERVER_LINEAGE", "no process the observer created before SPAWNED: the tool is not identified");
  }
  let proofRoot: number | null = null;
  const proofNetns = new Set<number>();
  for (const m of markers) {
    if (m.kind === "CONTAINER" && /^\d+$/.test(m.fields.netns ?? "")) proofNetns.add(Number(m.fields.netns));
  }
  // One pass in trace order: a spawn inherits its parent's scope; the tool's child that execs the host becomes PROOF.
  for (const e of events) {
    if (e.k === "spawn") {
      const parentScope = e.tgid === null ? undefined : scopeOf.get(e.tgid);
      if (e.child === toolTgid && e.tgid === observerTgid) scopeOf.set(e.child, "TOOL");
      else if (parentScope !== undefined) scopeOf.set(e.child, parentScope);
      else scopeOf.delete(e.child);
    } else if (e.k === "exec" && hostExecutable !== null && e.tgid !== null) {
      const inWindow = hostSpawn !== undefined && hostExit !== undefined && e.i > hostSpawn.i && e.i < hostExit.i;
      const isHost = e.dev === hostExecutable.dev && e.ino === hostExecutable.ino;
      if (isHost && inWindow && scopeOf.get(e.tgid) === "TOOL") {
        if (proofRoot !== null && proofRoot !== e.tgid)
          no("HOST_AMBIGUOUS", `the host executable was executed by ${proofRoot} and ${e.tgid}`);
        else if (e.path !== hostExecutable.path) {
          // A path the probe could not capture whole (longer than its 128 bytes) names nothing: refused, never assumed.
          no(
            "HOST_IDENTITY_MISMATCH",
            `the host exec named ${e.path ?? "a path longer than the probe captures"}, not ${hostExecutable.path}`,
          );
        } else {
          proofRoot = e.tgid;
          scopeOf.set(e.tgid, "PROOF");
        }
      }
    }
    // An exit ends nothing here: a leader may exit while its threads still send, and a reused number arrives with its
    // own creation, which sets its scope afresh.
  }
  if (hostExecutable !== null && proofRoot === null) {
    no("HOST_NOT_OBSERVED", "no exec of the measured host executable by the tool between HOST_SPAWN and HOST_EXIT");
  }
  return { observerTgid, toolTgid, proofRoot, scopeOf, proofNetns, hostNetns, errors };
}

// ---------------------------------------------------------------------------------------------------------------
// Normalize: raw evidence -> the committed observer section
// ---------------------------------------------------------------------------------------------------------------

export interface BoundaryRule {
  family: string;
  table: string;
  chain: string;
  handle: number;
  hook: string | null;
  verdict: "accept" | "drop" | "reject" | "other";
  counter: { packets: number; bytes: number } | null;
  /** The rule's expression with its counter values removed, as canonical JSON: a rule's identity across snapshots. */
  expr: string;
}

/** The declared table's rules from `nft -j list table`, in listing order. */
export function boundaryRules(nftJson: unknown): BoundaryRule[] {
  const items = (nftJson as { nftables?: unknown })?.nftables;
  if (!Array.isArray(items)) throw new Error("not an nft -j listing");
  const hooks = new Map<string, string | null>();
  const rules: BoundaryRule[] = [];
  for (const item of items as Record<string, any>[]) {
    if (item.chain) hooks.set(String(item.chain.name), typeof item.chain.hook === "string" ? item.chain.hook : null);
    if (!item.rule) continue;
    const r = item.rule;
    if (!Array.isArray(r.expr) || !Number.isSafeInteger(r.handle))
      throw new Error("an nft rule lacks its expression or handle");
    let counter: BoundaryRule["counter"] = null;
    let verdict: BoundaryRule["verdict"] = "other";
    const stripped = r.expr.map((x: Record<string, any>) => {
      if (x && typeof x === "object" && Object.hasOwn(x, "counter")) {
        const c = x.counter;
        if (!Number.isSafeInteger(c?.packets) || !Number.isSafeInteger(c?.bytes))
          throw new Error("an nft counter lacks its values");
        counter = { packets: c.packets, bytes: c.bytes };
        return { counter: {} };
      }
      if (x && typeof x === "object") {
        if (Object.hasOwn(x, "reject")) verdict = "reject";
        else if (Object.hasOwn(x, "drop")) verdict = "drop";
        else if (Object.hasOwn(x, "accept")) verdict = "accept";
      }
      return x;
    });
    rules.push({
      family: String(r.family),
      table: String(r.table),
      chain: String(r.chain),
      handle: r.handle,
      hook: hooks.get(String(r.chain)) ?? null,
      verdict,
      counter,
      expr: canonicalJson(stripped),
    });
  }
  return rules;
}

export interface ObserverEvidence {
  tool: { script: string; scriptSha256: string };
  mechanism: string;
  mode: Mode;
  nonce: string;
  kernelRelease: string;
  bootId: string;
  config: ObserverConfig;
  configSha256: string;
  host: {
    netns: number;
    nfDropReason: number;
    interfaces: Interface[];
    uplinks: number[];
    resolvers: string[];
    wslInterop: string;
  };
  table: string;
  boundary: { n: number; rules: BoundaryRule[] }[];
  stats: CpuStats[];
  lostLines: number;
  raw: { manifestSha256: string; files: { name: string; bytes: number; sha256: string }[] };
  hostExecutable: HostExecutable;
  events: NormEvent[];
  normalizedSha256: string;
}

export const OBSERVER_FIELDS = {
  observer: [
    "tool",
    "mechanism",
    "mode",
    "nonce",
    "kernelRelease",
    "bootId",
    "config",
    "configSha256",
    "host",
    "table",
    "boundary",
    "stats",
    "lostLines",
    "raw",
    "hostExecutable",
    "events",
    "normalizedSha256",
  ],
  host: ["netns", "nfDropReason", "interfaces", "uplinks", "resolvers", "wslInterop"],
  raw: ["manifestSha256", "files"],
  hostExecutable: ["path", "dev", "ino"],
} as const;

/** The digest of everything normalized from the raw evidence (all but the digest itself). */
export function normalizedSha256Of(o: Omit<ObserverEvidence, "normalizedSha256">): string {
  const {
    tool,
    mechanism,
    mode,
    nonce,
    kernelRelease,
    bootId,
    config,
    configSha256: c,
    host,
    table,
    boundary,
    stats,
    lostLines,
    raw,
    hostExecutable,
    events,
  } = o;
  return sha256Hex(
    canonicalJson({
      tool,
      mechanism,
      mode,
      nonce,
      kernelRelease,
      bootId,
      config,
      configSha256: c,
      host,
      table,
      boundary,
      stats,
      lostLines,
      raw,
      hostExecutable,
      events,
    }),
  );
}

export interface RawEvidence {
  trace: string;
  facts: string;
  manifest: string;
}

/**
 * The committed observer section, from the raw evidence and the measured host executable, deterministically: the same
 * raw bytes always give the same section and digest. Throws on any raw defect (a malformed line, a manifest that does
 * not bind the files, facts of another observer): a capture that does not read exactly derives nothing.
 */
export function normalizeObserverRaw(raw: RawEvidence, hostExecutable: HostExecutable): ObserverEvidence {
  const manifest = JSON.parse(raw.manifest) as {
    schema?: unknown;
    files?: { name: string; bytes: number; sha256: string }[];
  };
  if (manifest.schema !== MANIFEST_SCHEMA || !Array.isArray(manifest.files))
    throw new Error("the raw manifest is not the observer's");
  const want: [string, string][] = [
    [RAW_TRACE_FILE, raw.trace],
    [RAW_FACTS_FILE, raw.facts],
  ];
  for (const [name, text] of want) {
    const f = manifest.files.find((x) => x.name === name);
    const bytes = Buffer.from(text, "latin1");
    if (!f || f.bytes !== bytes.length || f.sha256 !== sha256Hex(bytes))
      throw new Error(`the raw manifest does not bind ${name}`);
  }
  if (manifest.files.length !== want.length) throw new Error("the raw manifest names other files");
  const facts = JSON.parse(raw.facts) as Record<string, any>;
  if (facts.schema !== FACTS_SCHEMA) throw new Error("the raw facts are not the observer's");
  if (Array.isArray(facts.failures) && facts.failures.length > 0)
    throw new Error(`the observer failed: ${facts.failures.join("; ")}`);
  const { events: parsed, lost } = parseTrace(raw.trace);
  const normalized = parsed.map(normalizeEvent).filter((e): e is NormEvent => e !== null);
  // Redaction replays the lineage in trace order, so each event is judged by the scope its process had then.
  const live = scopeReplayer(lineageOf(normalized, facts.hostNetns, hostExecutable));
  const events: NormEvent[] = [];
  const connected = new Set<string>();
  for (const e of normalized) {
    live.advance(e);
    // A spawn's name and an exec's or exit's presence follow the scope of the process at that moment.
    const disclosed = DISCLOSED.includes(live.scope({ tgid: e.tgid }));
    if (e.k === "spawn") {
      events.push({ ...e, comm: disclosed ? e.comm : null });
    } else if (e.k === "exec" || e.k === "exit") {
      if (disclosed) events.push(e);
    } else if (e.k === "connect") {
      connected.add(e.sk);
      events.push(e);
    } else if (e.k === "tcpstate" || e.k === "retransmit") {
      if (connected.has(e.sk)) events.push(e);
      if (e.k === "tcpstate" && e.to === TCP_CLOSE) connected.delete(e.sk);
    } else {
      events.push(e);
    }
  }
  // A DNS name stays only where the attempt it belongs to is in a disclosed scope; deriveAttribution re-checks that.
  const derived = deriveAttribution(events, contextOf(facts, hostExecutable), { redactionCheck: false });
  const disclosedDrop = new Set(
    derived.drops.filter((d) => d.attempt !== null && DISCLOSED.includes(d.attempt.scope)).map((d) => d.i),
  );
  const redacted = events.map((e): NormEvent => {
    if (e.k !== "drop" || e.packet.dns === undefined || disclosedDrop.has(e.i)) return e;
    return { ...e, packet: { ...e.packet, dns: { ...e.packet.dns, qname: null, withheld: true } } };
  });
  const body: Omit<ObserverEvidence, "normalizedSha256"> = {
    tool: { script: OBSERVER_SCRIPT_REL, scriptSha256: String(facts.observer?.scriptSha256) },
    mechanism: OBSERVER_MECHANISM,
    mode: facts.mode,
    nonce: facts.nonce,
    kernelRelease: facts.kernelRelease,
    bootId: facts.bootId,
    config: facts.config,
    configSha256: facts.configSha256,
    host: {
      netns: facts.hostNetns,
      nfDropReason: facts.nfDropReason,
      interfaces: facts.interfaces,
      uplinks: facts.uplinks,
      resolvers: facts.resolvers,
      wslInterop: facts.wslInterop,
    },
    table: facts.table,
    boundary: (facts.counters as { n: number; nft: unknown }[]).map((c) => ({ n: c.n, rules: boundaryRules(c.nft) })),
    stats: facts.stats,
    lostLines: lost,
    raw: { manifestSha256: sha256Hex(raw.manifest), files: manifest.files },
    hostExecutable,
    events: redacted,
  };
  return { ...body, normalizedSha256: normalizedSha256Of(body) };
}

/** Replays lineage in trace order so each event is judged by the scope its process had at that moment. */
export function scopeReplayer(final: Lineage) {
  const scopeOf = new Map<number, Scope>();
  if (final.observerTgid !== null) scopeOf.set(final.observerTgid, "OBSERVER");
  return {
    advance(e: NormEvent) {
      if (e.k === "spawn") {
        const parent = e.tgid === null ? undefined : scopeOf.get(e.tgid);
        if (e.child === final.toolTgid && e.tgid === final.observerTgid) scopeOf.set(e.child, "TOOL");
        else if (parent !== undefined) scopeOf.set(e.child, parent);
        else scopeOf.delete(e.child);
      } else if (e.k === "exec" && e.tgid !== null && e.tgid === final.proofRoot) {
        scopeOf.set(e.tgid, "PROOF");
      }
    },
    scope(e: { tgid: number | null; netns?: number }): Scope {
      if (e.netns !== undefined && e.netns !== final.hostNetns)
        return final.proofNetns.has(e.netns) ? "PROOF_CONTAINER" : "CONTAINER";
      if (e.tgid === null || e.tgid === 0) return "KERNEL";
      return scopeOf.get(e.tgid) ?? "OTHER";
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Derive: coverage, continuity, attribution, joins, reconciliation, leaks
// ---------------------------------------------------------------------------------------------------------------

export interface AttributionContext {
  nonce: string;
  hostNetns: number;
  uplinks: number[];
  /** The host's own addresses (any interface) and the in-VM subnets (non-uplink interfaces' networks). */
  localAddresses: string[];
  inVmSubnets: { base: string; prefix: number }[];
  resolvers: string[];
  hostExecutable: HostExecutable | null;
  /** Expected observer mode (RUN for a proof exercise; SELF_TEST for the integration test). */
  mode: Mode;
  bootId: string;
  readyClock?: { utc: string; monoNs: string };
}

export function contextOf(facts: Record<string, any>, hostExecutable: HostExecutable | null): AttributionContext {
  return contextFromHost(
    {
      netns: facts.hostNetns,
      nfDropReason: facts.nfDropReason,
      interfaces: facts.interfaces,
      uplinks: facts.uplinks,
      resolvers: facts.resolvers,
      wslInterop: facts.wslInterop,
    },
    { nonce: facts.nonce, mode: facts.mode, bootId: facts.bootId, hostExecutable },
  );
}

export function contextFromHost(
  host: ObserverEvidence["host"],
  run: { nonce: string; mode: Mode; bootId: string; hostExecutable: HostExecutable | null },
): AttributionContext {
  const localAddresses: string[] = [];
  const inVmSubnets: { base: string; prefix: number }[] = [];
  for (const i of host.interfaces ?? []) {
    for (const a of i.addresses) {
      const [addr, prefix] = a.split("/");
      localAddresses.push(addr);
      if (!host.uplinks.includes(i.ifindex) && isIP(addr) === 4 && Number(prefix) < 32)
        inVmSubnets.push({ base: addr, prefix: Number(prefix) });
    }
  }
  return {
    nonce: run.nonce,
    hostNetns: host.netns,
    uplinks: host.uplinks,
    localAddresses,
    inVmSubnets,
    resolvers: host.resolvers,
    hostExecutable: run.hostExecutable,
    mode: run.mode,
    bootId: run.bootId,
  };
}

const ip4Int = (a: string) => a.split(".").reduce((n, o) => n * 256 + Number(o), 0);
function inSubnet(addr: string, s: { base: string; prefix: number }): boolean {
  if (isIP(addr) !== 4 || isIP(s.base) !== 4) return false;
  const mask = s.prefix === 0 ? 0 : 2 ** 32 - 2 ** (32 - s.prefix);
  return (ip4Int(addr) & mask) >>> 0 === (ip4Int(s.base) & mask) >>> 0;
}
const isLoopback = (a: string) => a.startsWith("127.") || a === "::1";
/** fe80::/10, as ip6() writes it (lower case, the first group whole). */
const isLinkLocal6 = (a: string) => isIP(a) === 6 && /^fe[89ab][0-9a-f]:/.test(a);

/** Where a destination is: the host itself, a network inside the VM (a container bridge), or beyond (egress). */
export function destinationClass(ctx: AttributionContext, addr: string): "RESOLVER" | "LOCAL" | "IN_VM" | "EGRESS" {
  if (ctx.resolvers.includes(addr)) return "RESOLVER";
  if (isLoopback(addr) || ctx.localAddresses.includes(addr)) return "LOCAL";
  if (ctx.inVmSubnets.some((s) => inSubnet(addr, s))) return "IN_VM";
  return "EGRESS";
}

export type Outcome =
  "REFUSED" | "REFUSED_NO_PACKET_SEEN" | "NO_PACKET" | "SENT" | "CONNECTED" | "CLOSED_UNREFUSED" | "UNKNOWN";

export interface Attempt {
  i: number;
  t: number;
  tid: number;
  tgid: number | null;
  comm: string;
  kind: "send" | "connect";
  probe: SendProbe | ConnectProbe;
  sk: string;
  netns: number;
  scope: Scope;
  dest: Destination | null;
  destClass: ReturnType<typeof destinationClass> | null;
  ret: number | null;
  sport: number | null;
  /** The packets the boundary refused for it (drop indexes), and the boundary's own responses to it. */
  packets: number[];
  responses: number[];
  outcome: Outcome;
  dns: DnsQuestion | null;
  phase: string;
  /** Nested in another attempt on the same socket (an IPv4-mapped IPv6 send delegated to IPv4): not counted twice. */
  delegated: boolean;
}

export type DropClass = "ATTEMPT_PACKET" | "BOUNDARY_RESPONSE" | "KERNEL_RESPONSE" | "UNATTRIBUTED";
export interface DropJudgement {
  i: number;
  t: number;
  class: DropClass;
  attempt: { i: number; scope: Scope } | null;
  why: string;
}

export interface Attribution {
  refusals: Refusal[];
  markers: Marker[];
  lineage: Lineage;
  attempts: Attempt[];
  drops: DropJudgement[];
  leaks: { i: number; why: string }[];
  window: { begin: number; end: number } | null;
  heartbeats: number;
}

const isResponse = (p: Packet) =>
  (p.proto === IPPROTO_TCP && p.tcpFlags !== undefined && (p.tcpFlags & 0x04) !== 0) ||
  (p.proto === IPPROTO_ICMP && p.icmp !== undefined && [0, 3, 11, 12].includes(p.icmp.type)) ||
  (p.proto === IPPROTO_ICMPV6 &&
    p.icmp !== undefined &&
    [1, 2, 3, 4, 129, 133, 134, 135, 136, 143].includes(p.icmp.type));
const isMulticast4 = (a: string | null) =>
  a !== null && isIP(a) === 4 && Math.floor(Number(a.split(".")[0]) / 16) === 14;
/** What the kernel sends of itself: its answers (above) and its multicast membership reports (IGMP, to a group). */
const isKernelMessage = (p: Packet) => isResponse(p) || (p.proto === IPPROTO_IGMP && isMulticast4(p.dst));

/** The order the observer's markers must take (each once, CONTAINER and HEARTBEAT aside). */
const ORDER = [
  "READY",
  "COUNTERS_BEGIN:1",
  "COUNTERS_END:1",
  "SPAWNED",
  "HELLO",
  ...PHASES.map((p) => `PHASE:${p}`),
  "TOOL_DONE",
  "COUNTERS_BEGIN:2",
  "COUNTERS_END:2",
  "STOP",
];
const markerKey = (m: Marker) =>
  m.kind === "PHASE" ? `PHASE:${m.fields.name}` : m.kind.startsWith("COUNTERS_") ? `${m.kind}:${m.fields.n}` : m.kind;

/**
 * Everything the normalized events establish, and every reason they establish less than continuous attribution. Pure:
 * it reads the events and the context, nothing else.
 */
export function deriveAttribution(
  events: readonly NormEvent[],
  ctx: AttributionContext,
  opts: { redactionCheck: boolean } = { redactionCheck: true },
): Attribution {
  const refusals: Refusal[] = [];
  const no = (reason: string, detail: string) => refusals.push({ reason, detail });
  for (let k = 1; k < events.length; k++) {
    if (!(events[k].i > events[k - 1].i) || !(events[k].t >= events[k - 1].t)) {
      no("OBSERVER_EVENT_ORDER", `event ${k} is not after event ${k - 1} in the trace`);
      break;
    }
  }
  // Markers: ours, in sequence, from one writer, in the one order.
  const markers: Marker[] = [];
  for (const e of events) {
    if (e.k !== "marker") continue;
    const m = parseMarker(e);
    if (m === null || m.nonce !== ctx.nonce) {
      no(
        "OBSERVER_FOREIGN_MARKER",
        `the trace holds a marker the observer of nonce ${ctx.nonce} did not write: ${e.text.slice(0, 80)}`,
      );
      continue;
    }
    markers.push(m);
  }
  markers.forEach((m, k) => {
    if (m.seq !== k + 1)
      no("OBSERVER_MARKERS", `marker ${k + 1} carries sequence ${m.seq}: a marker is missing or repeated`);
  });
  const writers = new Set(markers.map((m) => m.tgid));
  if (writers.size > 1) no("OBSERVER_MARKERS", `the markers have ${writers.size} writers, not the observer alone`);
  const at = new Map<string, Marker>();
  for (const m of markers) {
    if (m.kind === "FAIL") no("OBSERVER_FAILED", `the observer marked a failure (${m.fields.code ?? "?"})`);
    if (m.kind === "HEARTBEAT" || m.kind === "CONTAINER" || m.kind === "FAIL") continue;
    const key = markerKey(m);
    if (!ORDER.includes(key)) no("OBSERVER_MARKERS", `an unknown marker ${key}`);
    else if (at.has(key)) no("OBSERVER_MARKERS", `${key} is marked twice`);
    else at.set(key, m);
  }
  let last = -1;
  for (const key of ORDER) {
    const m = at.get(key);
    if (!m) {
      no("OBSERVER_COVERAGE", `${key} is never marked: the observation does not cover the run`);
      continue;
    }
    if (m.i <= last) no("OBSERVER_COVERAGE", `${key} is out of order`);
    last = Math.max(last, m.i);
  }
  const ready = at.get("READY");
  if (ready) {
    if (ready.fields.mode !== ctx.mode)
      no("OBSERVER_MODE", `the observer ran in ${ready.fields.mode}, not ${ctx.mode}`);
    if (ready.fields.bootId !== ctx.bootId) no("OBSERVER_HOST", "READY names another boot of another host");
    if (Number(ready.fields.hostNetns) !== ctx.hostNetns) no("OBSERVER_HOST", "READY names another network namespace");
    const mono = Number(BigInt(ready.fields.monoNs ?? "0") / 1000n);
    if (!(ready.t >= mono && ready.t - mono <= READY_CLOCK_TOLERANCE_US)) {
      no("OBSERVER_CLOCK", "READY's trace stamp does not follow the observer's monotonic reading: not one clock");
    }
  }
  // Continuity: consecutive heartbeats, each with tracing on and nothing lost, bracketing the critical window.
  const beats = markers.filter((m) => m.kind === "HEARTBEAT");
  beats.forEach((b, k) => {
    if (b.fields.n !== String(k + 1)) no("OBSERVER_GAP", `heartbeat ${k + 1} carries n=${b.fields.n}`);
    if (b.fields.tracingOn !== "1" || b.fields.loss !== "0")
      no("OBSERVER_LOSS", `heartbeat ${k + 1} saw tracing off or lost events`);
    if (k > 0 && b.t - beats[k - 1].t > MAX_HEARTBEAT_GAP_US) {
      no(
        "OBSERVER_GAP",
        `${(b.t - beats[k - 1].t) / 1e6} s between heartbeats ${k} and ${k + 1} (at most ${MAX_HEARTBEAT_GAP_US / 1e6} s)`,
      );
    }
  });
  const begin = at.get("PHASE:PROBES_BEFORE_BEGIN");
  const end = at.get("PHASE:PROBES_AFTER_END");
  if (begin && !beats.some((b) => b.i < begin.i)) no("OBSERVER_GAP", "no heartbeat before the window opens");
  if (end && !beats.some((b) => b.i > end.i)) no("OBSERVER_GAP", "no heartbeat after the window closes");
  const window = begin && end ? { begin: begin.i, end: end.i } : null;

  const lineage = lineageOf(events, ctx.hostNetns, ctx.hostExecutable);
  refusals.push(...lineage.errors);
  const live = scopeReplayer(lineage);
  const phaseAt = (i: number) => {
    const keys = ORDER.filter((k) => at.has(k) && (at.get(k) as Marker).i < i);
    return keys.at(-1) ?? "BEFORE_READY";
  };

  // Attempts: entries and returns paired per thread; nested entries on the same socket are one attempt.
  const attempts: Attempt[] = [];
  const open = new Map<number, Attempt[]>();
  const sessions = new Map<string, Attempt>();
  const tcp = new Map<Attempt, { established: boolean; closedInSynSent: boolean }>();
  const deferred: Extract<NormEvent, { k: "drop" }>[] = [];
  const drops: DropJudgement[] = [];
  const leaks: { i: number; why: string }[] = [];
  const inWindow = (i: number) => window !== null && i > window.begin && i < window.end;
  // A container namespace that sent through a packet or raw socket (anywhere in the capture) could have crafted any
  // header, as any address: a copy of another container's leaked datagram, or a reset shaped like the kernel's. Then no
  // packet without a socket is joined to a container's attempt by addresses and ports, and none is the kernel's message.
  const containerCrafted = events.some(
    (e) => e.k === "send" && e.netns !== ctx.hostNetns && (e.probe === "pkt" || e.probe.startsWith("raw")),
  );
  for (const e of events) {
    live.advance(e);
    if (e.k === "send" || e.k === "connect") {
      const stack = open.get(e.tid) ?? [];
      const outer = stack.at(-1);
      const a: Attempt = {
        i: e.i,
        t: e.t,
        tid: e.tid,
        tgid: e.tgid,
        comm: e.comm,
        kind: e.k,
        probe: e.probe,
        sk: e.sk,
        netns: e.netns,
        scope: live.scope({ tgid: e.tgid, netns: e.netns }),
        dest: e.dest,
        destClass: e.dest === null ? null : destinationClass(ctx, e.dest.addr),
        ret: null,
        sport: null,
        packets: [],
        responses: [],
        outcome: "UNKNOWN",
        dns: null,
        phase: phaseAt(e.i),
        delegated: outer !== undefined && outer.sk === e.sk,
      };
      stack.push(a);
      open.set(e.tid, stack);
      attempts.push(a);
    } else if (e.k === "sendret" || e.k === "connectret") {
      const stack = open.get(e.tid) ?? [];
      const top = stack.at(-1);
      if (!top || top.probe !== e.probe || top.sk !== e.sk) {
        no(
          "OBSERVER_EVENT_INCONSISTENT",
          `event ${e.i}: a ${e.k} of ${e.probe} with no open attempt on thread ${e.tid}`,
        );
        continue;
      }
      stack.pop();
      top.ret = e.ret;
      top.sport = e.sport;
      if (top.kind === "connect" && e.ret >= 0 && !top.delegated) {
        sessions.set(top.sk, top);
        tcp.set(top, { established: false, closedInSynSent: false });
      }
    } else if (e.k === "tcpstate") {
      const s = sessions.get(e.sk);
      const st = s === undefined ? undefined : tcp.get(s);
      if (st === undefined) continue;
      if (e.from === TCP_SYN_SENT && e.to === TCP_ESTABLISHED) st.established = true;
      else if (e.from === TCP_SYN_SENT && e.to === TCP_CLOSE) st.closedInSynSent = true;
      if (e.to === TCP_CLOSE) sessions.delete(e.sk);
    } else if (e.k === "drop") {
      const judge = (cls: DropClass, a: Attempt | null, why: string) =>
        drops.push({ i: e.i, t: e.t, class: cls, attempt: a ? { i: a.i, scope: a.scope } : null, why });
      // J1: refused inside an attempt's own send, on its socket (the bottom-most attempt of that socket owns it).
      const stack = e.ctx === "task" ? (open.get(e.tid) ?? []) : [];
      const owner = stack.find((a) => a.sk === e.sk && !a.delegated);
      if (owner) {
        owner.packets.push(e.i);
        if (e.packet.dns && owner.dns === null) owner.dns = e.packet.dns;
        judge("ATTEMPT_PACKET", owner, "refused inside the attempt's own send, on its socket");
        continue;
      }
      // J1b: the boundary's own reset or ICMP answer, refused while the attempt it answers was being sent.
      if (stack.length > 0 && isResponse(e.packet)) {
        stack[0].responses.push(e.i);
        judge(
          "BOUNDARY_RESPONSE",
          stack[0],
          "the boundary's own reset or ICMP answer to the attempt, refused while it was being sent",
        );
        continue;
      }
      // J2: a later packet of a connection the attempt opened (a retransmitted SYN), by its socket.
      const session = e.sk === "0x0" ? undefined : sessions.get(e.sk);
      if (session) {
        session.packets.push(e.i);
        judge("ATTEMPT_PACKET", session, "a retransmission of the attempt's connection, by its socket");
        continue;
      }
      // J3 waits for every return: a container's packet reaches the host after it left the container's socket. A
      // socketless packet of a kernel message's shape is a kernel's only from one of the host's own addresses (as read
      // at the start) or from a link-scoped source a kernel uses before or beside them: the unspecified address
      // (duplicate-address detection, a membership report before an address) or IPv6 link-local (a bridge or a veth
      // gets one when it comes up, mid-run). From anywhere else it is someone's packet, whatever its shape, and none is
      // a kernel's once a container crafted. The drop records no direction, so a link neighbour's message from a
      // link-scoped source reads as a kernel's too: its reason says so.
      const src = e.packet.src;
      const hostSource = src !== null && (isLoopback(src) || ctx.localAddresses.includes(src));
      const linkScoped = src !== null && (src === "0.0.0.0" || src === "::" || isLinkLocal6(src));
      const kernelMessage = isKernelMessage(e.packet) && (hostSource || linkScoped) && !containerCrafted;
      if (e.sk === "0x0" && e.packet.v !== null && !kernelMessage) {
        deferred.push(e);
        continue;
      }
      if (kernelMessage)
        judge(
          "KERNEL_RESPONSE",
          null,
          hostSource
            ? "a reset, ICMP answer or neighbour/multicast message the kernel itself sent, refused"
            : "a kernel's message from a link-scoped source (the host's, a container namespace's or a link neighbour's: the drop does not tell them apart), refused",
        );
      else judge("UNATTRIBUTED", null, "refused, but no observed attempt sent it");
    } else if (e.k === "xmit") {
      if (ctx.uplinks.includes(e.ifindex) && e.netns === ctx.hostNetns && inWindow(e.i)) {
        leaks.push({
          i: e.i,
          why: `a frame (ethertype 0x${e.ethertype.toString(16)}) left through uplink ${e.ifindex}`,
        });
      }
    }
  }
  // J3: a container's datagram or connection, refused in the host (no socket crosses the namespaces), joined by its
  // protocol, addresses and ports to an earlier attempt from a container namespace; a datagram is one packet.
  const echo = (p: Packet) =>
    (p.proto === IPPROTO_ICMP && p.icmp?.type === 8) || (p.proto === IPPROTO_ICMPV6 && p.icmp?.type === 128);
  for (const e of deferred) {
    const candidates = attempts.filter(
      (a) =>
        !containerCrafted &&
        !a.delegated &&
        a.netns !== ctx.hostNetns &&
        a.i < e.i &&
        a.dest !== null &&
        a.dest.addr === e.packet.dst &&
        a.dest.port === e.packet.dport &&
        a.sport === e.packet.sport &&
        ((a.kind === "send" && a.probe.startsWith("udp") && e.packet.proto === IPPROTO_UDP && a.packets.length === 0) ||
          (a.kind === "send" && a.probe.startsWith("ping") && echo(e.packet) && a.packets.length === 0) ||
          (a.kind === "connect" && e.packet.proto === IPPROTO_TCP)),
    );
    // Attempts of two namespaces that could each have sent it name neither: a second container's datagram on the same
    // port numbers (ports are per namespace) would otherwise make another's leaked one read as refused.
    const a = new Set(candidates.map((x) => x.netns)).size === 1 ? candidates[0] : undefined;
    if (a) {
      a.packets.push(e.i);
      if (e.packet.dns && a.dns === null) a.dns = e.packet.dns;
      drops.push({
        i: e.i,
        t: e.t,
        class: "ATTEMPT_PACKET",
        attempt: { i: a.i, scope: a.scope },
        why: "a container's packet, refused in the host, by its addresses and ports",
      });
    } else {
      drops.push({
        i: e.i,
        t: e.t,
        class: "UNATTRIBUTED",
        attempt: null,
        why:
          candidates.length > 0
            ? "refused; attempts of more than one namespace could have sent it, so none is named"
            : "refused, but no observed attempt sent it",
      });
    }
  }
  drops.sort((x, y) => x.i - y.i);
  // Outcomes, from every join: a refused packet makes an attempt REFUSED whatever its sender was told.
  for (const a of attempts) {
    const s = tcp.get(a);
    if (a.packets.length > 0) a.outcome = "REFUSED";
    else if (a.kind === "connect" && s?.established) a.outcome = "CONNECTED";
    else if (a.kind === "connect" && s?.closedInSynSent) a.outcome = "CLOSED_UNREFUSED";
    else if (a.ret === null) a.outcome = "UNKNOWN";
    else if (a.ret === -EPERM) a.outcome = "REFUSED_NO_PACKET_SEEN";
    else if (a.ret < 0) a.outcome = "NO_PACKET";
    else a.outcome = a.kind === "send" ? "SENT" : "UNKNOWN";
    if (a.kind === "connect" && s?.established && a.packets.length > 0) a.outcome = "CONNECTED";
  }
  // Leaks an attempt shows directly (the boundary let a packet past), inside the window: from the host to a destination
  // beyond the VM, or from any namespace to a resolver (a resolver on the host forwards beyond the VM, on a channel no
  // transmit on a device would show).
  for (const a of attempts) {
    if (a.delegated || !inWindow(a.i)) continue;
    if (!(a.destClass === "RESOLVER" || (a.destClass === "EGRESS" && a.netns === ctx.hostNetns))) continue;
    if (a.outcome === "SENT" || a.outcome === "CONNECTED") {
      leaks.push({ i: a.i, why: `${a.comm} (${a.tgid}) ${a.outcome} to ${a.dest?.addr}:${a.dest?.port}` });
    }
  }
  if (leaks.length > 0)
    no("EGRESS_LEAKED", `${leaks.length} packet(s) passed the boundary inside the window: ${leaks[0].why}`);
  if (opts.redactionCheck) {
    for (const e of events) {
      if (e.k !== "drop" || e.packet.dns === undefined) continue;
      const d = drops.find((x) => x.i === e.i);
      const disclosed = d !== undefined && d.attempt !== null && DISCLOSED.includes(d.attempt.scope);
      if (disclosed && e.packet.dns.withheld)
        no("PRIVACY_FILTER", `event ${e.i}: a DNS name of the proof's scope was withheld`);
      if (!disclosed && e.packet.dns.qname !== null)
        no("PRIVACY_FILTER", `event ${e.i}: a DNS name outside the proof's scope was kept`);
    }
  }
  return { refusals, markers, lineage, attempts, drops, leaks, window, heartbeats: beats.length };
}

/** The packets the declared table's refusing rules counted between the two snapshots. */
export function counterDelta(boundary: ObserverEvidence["boundary"]): { delta: number | null; errors: string[] } {
  const errors: string[] = [];
  const s1 = boundary.find((b) => b.n === 1);
  const s2 = boundary.find((b) => b.n === 2);
  if (!s1 || !s2 || boundary.length !== 2)
    return { delta: null, errors: ["the boundary was not snapshotted exactly twice"] };
  const key = (r: BoundaryRule) => `${r.family} ${r.table} ${r.chain} ${r.handle} ${r.verdict} ${r.expr}`;
  const k1 = s1.rules.map(key);
  const k2 = s2.rules.map(key);
  if (k1.length !== k2.length || k1.some((k, i) => k !== k2[i]))
    errors.push("the boundary's rules changed during the window");
  let delta = 0;
  s1.rules.forEach((r, i) => {
    const r2 = s2.rules[i];
    if (!r2 || r.counter === null || r2.counter === null || (r.verdict !== "reject" && r.verdict !== "drop")) return;
    if (r2.counter.packets < r.counter.packets)
      errors.push(`rule ${r.handle}'s counter went backwards (reset during the window)`);
    delta += r2.counter.packets - r.counter.packets;
  });
  if (!s1.rules.some((r) => r.counter !== null && (r.verdict === "reject" || r.verdict === "drop"))) {
    errors.push("the declared table has no counted refusing rule: nothing to reconcile");
  }
  return { delta, errors };
}

export interface Reconciliation {
  counted: number | null;
  /** Netfilter drops strictly inside the counters' window, and inside its outer bracket (the reads take time). */
  inner: number;
  outer: number;
  ok: boolean;
}

/**
 * Two records of the same packets, cross-checked: every netfilter drop is the kernel's own record of one packet a rule
 * refused, and the declared table's refusing rules count one per packet they refuse; between the end of the first
 * counter read and the beginning of the second, both see the same packets. A drop that falls while nft was reading lies
 * in the brackets, so the count must lie between the drops strictly inside (inner) and the drops inside the outer marks.
 * A count below inner means a refusal the table did not count (another table refused it: the declared boundary is not
 * the boundary); above outer, a packet the table refused that the observer never saw (an observation gap). Both records
 * come from the operator's capture (the observer reads the counters into its facts): this finds a gap or a second
 * boundary in an honest capture, never an edited one.
 */
export function reconcile(
  drops: readonly DropJudgement[],
  markers: readonly Marker[],
  boundary: ObserverEvidence["boundary"],
): Reconciliation {
  const find = (kind: string, n: string) => markers.find((m) => m.kind === kind && m.fields.n === n);
  const b1 = find("COUNTERS_BEGIN", "1");
  const e1 = find("COUNTERS_END", "1");
  const b2 = find("COUNTERS_BEGIN", "2");
  const e2 = find("COUNTERS_END", "2");
  const { delta, errors } = counterDelta(boundary);
  if (!b1 || !e1 || !b2 || !e2 || delta === null) return { counted: delta, inner: 0, outer: 0, ok: false };
  const inner = drops.filter((d) => d.i > e1.i && d.i < b2.i).length;
  const outer = drops.filter((d) => d.i > b1.i && d.i < e2.i).length;
  return { counted: delta, inner, outer, ok: errors.length === 0 && inner <= delta && delta <= outer };
}

export type AssuranceLevel = "EDGE_PROBES_ONLY" | "CONTINUOUS_ATTRIBUTED" | "CONTINUOUS_PARTIALLY_ATTRIBUTED";

export interface EgressAssurance {
  level: AssuranceLevel;
  enforcement: "STATED" | "STATED_AND_COUNTED";
  edgeProbes: "REFUSED_BEFORE_AND_AFTER" | "REFUSED_BEFORE_AND_AFTER_AND_OBSERVED";
  continuousObservation: "ABSENT" | "PRESENT";
  processAttribution: "ABSENT" | "COMPLETE" | "PARTIAL";
  /** null where the evidence measured nothing (a v1 run): unknown is never zero. */
  coverage: { window: string; heartbeats: number; maxHeartbeatGapUs: number } | null;
  events: {
    attempts: number;
    attemptsInWindow: number;
    refusedPackets: number;
    byScope: Record<string, number>;
    boundaryResponses: number;
    kernelResponses: number;
    /** Refused packets no attempt sent, outside the critical window but in the capture (they too make the attribution
     * PARTIAL). */
    unattributedOutsideWindow: number;
    /** Attempts inside the window, to a resolver from any namespace or beyond the VM from the host, whose outcome the
     * capture does not show (no return, or a connection neither established nor closed): PARTIAL, never complete. */
    unknownOutcomes: number;
  } | null;
  /** Refused packets inside the critical window (the probes and the proof) that no observed attempt sent. */
  unattributedEvents: number | null;
  observer: { mechanism: string; script: string; scriptSha256: string; configSha256: string } | null;
  rawEvidence: { manifestSha256: string; retained: "OPERATOR_LOCAL" } | null;
}

/** What a v1 run (SP1-PA3B's) supports: refusal at the edges and a stated enforcement; nothing was watched or counted. */
export const EDGE_PROBES_ONLY: EgressAssurance = {
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
};

/** The assurance accepted continuous evidence supports, from the derivation (never from a claim in the evidence). */
export function assuranceOf(o: ObserverEvidence, a: Attribution): EgressAssurance {
  const byScope: Record<string, number> = {};
  const counted = a.attempts.filter((x) => !x.delegated);
  for (const x of counted) byScope[x.scope] = (byScope[x.scope] ?? 0) + 1;
  const inWindow = (i: number) => a.window !== null && i > a.window.begin && i < a.window.end;
  const unattributedAll = a.drops.filter((d) => d.class === "UNATTRIBUTED");
  const unattributed = unattributedAll.filter((d) => inWindow(d.i)).length;
  // An attempt that may have gone past the boundary, its outcome unseen, is not attributed either.
  const unknown = counted.filter(
    (x) =>
      inWindow(x.i) &&
      x.outcome === "UNKNOWN" &&
      (x.destClass === "RESOLVER" || (x.destClass === "EGRESS" && x.netns === o.host.netns)),
  ).length;
  // Complete means every refused packet the capture holds is attributed (its first line to its last, READY's
  // surroundings included) and no attempt that matters has an unseen outcome; the window's own count is reported apart.
  const complete = unattributedAll.length === 0 && unknown === 0;
  const beats = a.markers.filter((m) => m.kind === "HEARTBEAT");
  let maxGap = 0;
  for (let k = 1; k < beats.length; k++) maxGap = Math.max(maxGap, beats[k].t - beats[k - 1].t);
  return {
    level: complete ? "CONTINUOUS_ATTRIBUTED" : "CONTINUOUS_PARTIALLY_ATTRIBUTED",
    enforcement: "STATED_AND_COUNTED",
    edgeProbes: "REFUSED_BEFORE_AND_AFTER_AND_OBSERVED",
    continuousObservation: "PRESENT",
    processAttribution: complete ? "COMPLETE" : "PARTIAL",
    coverage: { window: "OBSERVER_READY..OBSERVER_STOP", heartbeats: beats.length, maxHeartbeatGapUs: maxGap },
    events: {
      attempts: counted.length,
      attemptsInWindow: counted.filter((x) => inWindow(x.i)).length,
      refusedPackets: a.drops.length,
      byScope,
      boundaryResponses: a.drops.filter((d) => d.class === "BOUNDARY_RESPONSE").length,
      kernelResponses: a.drops.filter((d) => d.class === "KERNEL_RESPONSE").length,
      unattributedOutsideWindow: unattributedAll.length - unattributed,
      unknownOutcomes: unknown,
    },
    unattributedEvents: unattributed,
    observer: {
      mechanism: o.mechanism,
      script: o.tool.script,
      scriptSha256: o.tool.scriptSha256,
      configSha256: o.configSha256,
    },
    rawEvidence: { manifestSha256: o.raw.manifestSha256, retained: "OPERATOR_LOCAL" },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The observer section of a v2 run observation, judged
// ---------------------------------------------------------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
function exactly(
  o: unknown,
  keys: readonly string[],
  where: string,
  no: (r: string, d: string) => void,
): o is Record<string, any> {
  if (!isObject(o)) {
    no("OBSERVER_SHAPE", `${where} is not an object`);
    return false;
  }
  const extra = Object.keys(o).filter((k) => !keys.includes(k));
  const missing = keys.filter((k) => !Object.hasOwn(o, k));
  if (extra.length > 0) no("OBSERVER_SHAPE", `${where} names ${extra.join(", ")}`);
  if (missing.length > 0) no("OBSERVER_SHAPE", `${where} lacks ${missing.join(", ")}`);
  return extra.length === 0 && missing.length === 0;
}

export interface ObserverExpectations {
  /** sha256 of the committed observer script's LF bytes (null when absent: then nothing binds). */
  observerScriptSha256: string | null;
  mode: Mode;
  /** The probes the tool recorded (run.egress.before/after), to be found in the trace. */
  probes: { phase: "before" | "after"; kind: "dns" | "tcp"; target: string }[];
  /** The tool's wall-clock gate stamps, which the trace's own timeline must agree with. */
  gate: { startedAtUtc: string; finishedAtUtc: string } | null;
  /** The run's commit and host label, which the tool told the observer (HELLO) before its first phase. */
  run: { commit: string; host: string } | null;
}

/** Every reason `value` is not continuous, attributed evidence of one observed run; [] accepts it. */
export function observerEvidenceErrors(
  value: unknown,
  expect: ObserverExpectations,
): { refusals: Refusal[]; attribution: Attribution | null } {
  const out: Refusal[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = "run.egress.observer";
  if (!exactly(value, OBSERVER_FIELDS.observer, where, no)) return { refusals: out, attribution: null };
  const o = value as ObserverEvidence;
  if (
    !isObject(o.tool) ||
    o.tool.script !== OBSERVER_SCRIPT_REL ||
    expect.observerScriptSha256 === null ||
    o.tool.scriptSha256 !== expect.observerScriptSha256
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${OBSERVER_SCRIPT_REL} as committed: re-observe`);
  }
  if (o.mechanism !== OBSERVER_MECHANISM) no("OBSERVER_MECHANISM", `${where}.mechanism is ${String(o.mechanism)}`);
  if (o.mode !== expect.mode) no("OBSERVER_MODE", `${where} ran in ${String(o.mode)}, not ${expect.mode}`);
  if (!NONCE.test(String(o.nonce))) no("OBSERVER_SHAPE", `${where}.nonce is not a nonce`);
  if (!isObject(o.host) || !exactly(o.host, OBSERVER_FIELDS.host, `${where}.host`, no))
    return { refusals: out, attribution: null };
  if (!Number.isSafeInteger(o.host.netns) || !Number.isSafeInteger(o.host.nfDropReason)) {
    no("OBSERVER_SHAPE", `${where}.host names no namespace or drop reason`);
    return { refusals: out, attribution: null };
  }
  // The configuration: rebuilt from the committed observer and these facts, never taken from the observation.
  let rebuilt: ObserverConfig | null = null;
  try {
    rebuilt = observerConfig({ nonce: o.nonce, hostNetns: o.host.netns, nfDropReason: o.host.nfDropReason });
  } catch (error) {
    no("OBSERVER_CONFIG_NOT_BOUND", (error as Error).message);
  }
  if (
    rebuilt !== null &&
    (canonicalJson(o.config) !== canonicalJson(rebuilt) || o.configSha256 !== configSha256(rebuilt))
  ) {
    no(
      "OBSERVER_CONFIG_NOT_BOUND",
      `${where}.config is not the committed observer's probes and filters for this run: another filter or configuration`,
    );
  }
  if (!exactly(o.raw, OBSERVER_FIELDS.raw, `${where}.raw`, no) || !HEX64.test(String(o.raw.manifestSha256))) {
    no("RAW_NOT_BOUND", `${where}.raw names no manifest digest`);
  } else {
    const names = Array.isArray(o.raw.files) ? o.raw.files.map((f) => f?.name).sort() : [];
    const ok =
      Array.isArray(o.raw.files) &&
      o.raw.files.every((f) => isObject(f) && Number.isSafeInteger(f.bytes) && HEX64.test(String(f.sha256))) &&
      canonicalJson(names) === canonicalJson([RAW_FACTS_FILE, RAW_TRACE_FILE]);
    if (!ok) no("RAW_NOT_BOUND", `${where}.raw does not bind the raw trace and facts by length and sha256`);
  }
  if (!exactly(o.hostExecutable, OBSERVER_FIELDS.hostExecutable, `${where}.hostExecutable`, no))
    return { refusals: out, attribution: null };
  if (!Array.isArray(o.events)) {
    no("OBSERVER_SHAPE", `${where}.events is not a list`);
    return { refusals: out, attribution: null };
  }
  const { normalizedSha256: claimed, ...body } = o;
  if (claimed !== normalizedSha256Of(body))
    no(
      "NORMALIZED_NOT_BOUND",
      `${where}.normalizedSha256 is not the digest of what it holds: edited after normalization`,
    );
  if (!Array.isArray(o.stats) || o.stats.length === 0) no("OBSERVER_LOSS", `${where}.stats holds no per-CPU stats`);
  else if (o.stats.some((s) => s.overrun !== 0 || s.commitOverrun !== 0 || s.droppedEvents !== 0)) {
    no("OBSERVER_LOSS", `${where}: the ring buffer lost events`);
  }
  if (o.lostLines !== 0) no("OBSERVER_LOSS", `${where}: ${o.lostLines} lost-events lines in the trace`);
  const ctx = contextFromHost(o.host, {
    nonce: o.nonce,
    mode: expect.mode,
    bootId: o.bootId,
    hostExecutable: o.hostExecutable,
  });
  let a: Attribution;
  try {
    a = deriveAttribution(o.events, ctx);
  } catch (error) {
    no("OBSERVER_EVENT_MALFORMED", `${where}.events: ${(error as Error).message}`);
    return { refusals: out, attribution: null };
  }
  out.push(...a.refusals);
  const r = reconcile(a.drops, a.markers, Array.isArray(o.boundary) ? o.boundary : []);
  if (!r.ok) {
    no(
      "BOUNDARY_RECONCILIATION",
      `the declared table counted ${r.counted ?? "nothing"} refused packets; the observer saw ${r.inner} inside the counters' window and ${r.outer} in its outer bracket: ${counterDelta(Array.isArray(o.boundary) ? o.boundary : []).errors.join("; ") || "the counts disagree"}`,
    );
  }
  // The recorded edge probes, each seen in the trace from the tool in its own phase.
  const phase = (p: "before" | "after") =>
    p === "before"
      ? ["PHASE:PROBES_BEFORE_BEGIN", "PHASE:PROBES_BEFORE_END"]
      : ["PHASE:PROBES_AFTER_BEGIN", "PHASE:PROBES_AFTER_END"];
  const markerAt = new Map(a.markers.map((m) => [markerKey(m), m]));
  for (const p of expect.probes) {
    const [b, e] = phase(p.phase).map((k) => markerAt.get(k));
    if (!b || !e) continue;
    const inside = a.attempts.filter((x) => x.scope === "TOOL" && x.i > b.i && x.i < e.i && !x.delegated);
    const host = p.kind === "tcp" ? p.target.slice(0, p.target.lastIndexOf(":")) : p.target;
    const byAddress = p.kind === "tcp" && isIP(host) !== 0;
    const seen = byAddress
      ? inside.some(
          (x) =>
            x.kind === "connect" &&
            x.dest?.addr === host &&
            x.dest?.port === Number(p.target.slice(p.target.lastIndexOf(":") + 1)) &&
            x.outcome === "REFUSED",
        )
      : inside.some((x) => x.dest?.port === DNS_PORT && x.dns?.qname === host.toLowerCase() && x.outcome === "REFUSED");
    if (!seen)
      no(
        "PROBE_NOT_OBSERVED",
        `the ${p.phase} probe ${p.kind}:${p.target} has no refused attempt by the tool in its phase of the trace`,
      );
  }
  const hello = markerAt.get("HELLO");
  if (
    expect.run !== null &&
    hello &&
    (hello.fields.commit !== expect.run.commit || hello.fields.host !== expect.run.host)
  ) {
    no(
      "OBSERVER_NOT_THIS_RUN",
      `the capture is of a run of ${hello.fields.commit ?? "?"} on ${hello.fields.host ?? "?"}, not ${expect.run.commit} on ${expect.run.host}`,
    );
  }
  if (expect.gate !== null) {
    const ready = markerAt.get("READY");
    const gb = markerAt.get("PHASE:GATE_BEGIN");
    const ge = markerAt.get("PHASE:GATE_END");
    const utc = ready?.fields.utc;
    if (ready && gb && ge && utc) {
      const toUtc = (t: number) => Date.parse(utc) / 1000 + (t - ready.t) / 1e6;
      const s = Date.parse(expect.gate.startedAtUtc) / 1000;
      const f = Date.parse(expect.gate.finishedAtUtc) / 1000;
      if (!(s >= toUtc(gb.t) - UTC_TOLERANCE_SECONDS && f <= toUtc(ge.t) + UTC_TOLERANCE_SECONDS)) {
        no(
          "OBSERVER_CLOCK",
          "the gate's recorded stamps fall outside GATE_BEGIN..GATE_END on the trace's clock: not this run's capture",
        );
      }
    }
  }
  return { refusals: out, attribution: a };
}

// ---------------------------------------------------------------------------------------------------------------
// The tool's side of the observer protocol (the attributed measurement tool and the self-test workload speak it on
// their own stdin and stdout, which none of their children inherit)
// ---------------------------------------------------------------------------------------------------------------

export interface ObserverReady {
  nonce: string;
  group: string;
  bootId: string;
  mode: Mode;
}
export interface ObserverStopped {
  manifestSha256: string;
  rawDir: string;
}

/**
 * READY first; every request waits for its ACK (so its marker is in the trace before the tool acts); STOPPED ends the
 * exchange. FAIL, or the end of the observer's stream, fails the client: every waiter and every onFail handler
 * learns it at once, and nothing is asked of a failed observer again.
 */
export class ObserverClient {
  failure: string | null = null;
  private readonly write: (line: string) => void;
  private readonly lines: string[] = [];
  private readonly waiters: ((line: string | null) => void)[] = [];
  private readonly handlers: ((reason: string) => void)[] = [];
  private ended = false;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(input: NodeJS.ReadableStream, write: (line: string) => void) {
    this.write = write;
    const rl = createInterface({ input });
    rl.on("line", (line) => this.receive(line));
    rl.on("close", () => {
      this.ended = true;
      this.fail("OBSERVER_GONE");
      for (const w of this.waiters.splice(0)) w(null);
    });
  }

  private receive(line: string): void {
    if (!line.startsWith(`${CTL_TAG} `)) return;
    if (line.split(" ")[1] === "FAIL") this.fail(line.split(" ")[2] ?? "UNKNOWN");
    const waiter = this.waiters.shift();
    if (waiter) waiter(line);
    else this.lines.push(line);
  }

  private next(timeoutMs: number): Promise<string> {
    const queued = this.lines.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.ended) return Promise.reject(new Error("the observer is gone"));
    return new Promise((resolve, reject) => {
      const waiter = (line: string | null) => {
        clearTimeout(timer);
        if (line === null) reject(new Error("the observer is gone"));
        else resolve(line);
      };
      const timer = setTimeout(() => {
        const k = this.waiters.indexOf(waiter);
        if (k !== -1) this.waiters.splice(k, 1);
        reject(new Error(`the observer did not answer within ${timeoutMs} ms`));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  fail(reason: string): void {
    if (this.failure !== null) return;
    this.failure = reason;
    for (const h of this.handlers) h(reason);
  }

  onFail(handler: (reason: string) => void): void {
    this.handlers.push(handler);
    if (this.failure !== null) handler(this.failure);
  }

  async ready(timeoutMs = 30_000): Promise<ObserverReady> {
    const line = await this.next(timeoutMs);
    const w = line.split(" ");
    if (w.length !== 6 || w[1] !== "READY" || !NONCE.test(w[2]) || !(MODES as readonly string[]).includes(w[5])) {
      throw new Error(`not started by the egress observer (it said: ${line.slice(0, 80)})`);
    }
    return { nonce: w[2], group: w[3], bootId: w[4], mode: w[5] as Mode };
  }

  private serialized<T>(act: () => Promise<T>): Promise<T> {
    const run = () => {
      if (this.failure !== null) return Promise.reject(new Error(`the observer failed: ${this.failure}`));
      return act();
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  /** Asks the observer to mark `words` and resolves with the marker's sequence number once it is in the trace. */
  request(...words: (string | number)[]): Promise<number> {
    return this.serialized(async () => {
      this.write(formatCtl(...words));
      const line = await this.next(30_000);
      const w = line.split(" ");
      if (w.length === 3 && w[1] === "ACK" && /^[1-9]\d*$/.test(w[2])) return Number(w[2]);
      throw new Error(`the observer answered ${line.slice(0, 80)} to ${words.join(" ")}`);
    });
  }

  /** Tells the observer the tool is done; resolves with where the raw evidence is and its manifest's digest. */
  stop(timeoutMs = 120_000): Promise<ObserverStopped> {
    return this.serialized(async () => {
      this.write(formatCtl("DONE"));
      const line = await this.next(timeoutMs);
      const w = line.split(" ");
      if (w.length === 4 && w[1] === "STOPPED" && HEX64.test(w[2]) && w[3].startsWith("/"))
        return { manifestSha256: w[2], rawDir: w[3] };
      throw new Error(`the observer answered ${line.slice(0, 80)} to DONE`);
    });
  }
}
