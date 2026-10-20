/**
 * SP1-PA3C: the root egress observer for a FUTURE proof exercise. It observes; it never enforces, never proves and
 * never invokes the prover (the archive-only gate stays the only proving path, run by the measurement tool it starts).
 *
 *   node <root-owned copy>/sp1-egress-observer.ts run --as <user> --repo <checkout> --table <family> <name> \
 *     --raw-dir <new directory> -- <arguments of scripts/measure-sp1-attributed-proof-exercise.ts>
 *   node <root-owned copy>/sp1-egress-observer.ts self-test --as <user> --repo <checkout> --table <family> <name> \
 *     --raw-dir <new directory>
 *
 * As root it opens a private tracefs instance (`sp1obs_<nonce>`), installs a fixed set of kprobes (PROBES: the
 * protocol send and connect entry points with their returns, TCP state and retransmission, every netfilter drop with
 * the refused packet's leading bytes, every transmit on a non-loopback device of the host's network namespace, and
 * process creation, exec and exit), snapshots the declared enforcement table's counters, and only then starts the
 * unprivileged measurement tool (`run`) or the fixed synthetic workload (`self-test`) through setpriv. The tool asks
 * for every phase marker over its own stdin and stdout, which none of its children inherit; this process writes the
 * marker as root with the run's nonce and a sequence number before it answers, so the marker precedes the tool's next
 * act in the trace. Heartbeats sample, once a second, that the instance is tracing and has lost nothing: no ring-buffer
 * overrun or dropped event on any CPU and no miss by any of its probes (a return probe misses when more calls are in
 * flight than it can follow); any loss stops the run. After the tool's DONE the counters
 * are snapshotted again, STOP is marked, the trace is drained into the raw directory with the host facts, every probe
 * and the instance are removed, and the tool is told where the raw evidence is (it normalizes it; the validators in
 * scripts/lib/sp1-egress-attribution.ts decide). Untrusted strings never reach the trace as text: paths and payloads
 * are fetched as hex arrays, and the only string field (a task's comm, at most 15 bytes) is last on its line.
 *
 * Node built-ins only, so root never executes code from node_modules; run it from a root-owned copy (it refuses a path
 * a non-root user could change). Linux only (tracefs, kprobes with BTF arguments). Research prototype. Not audited.
 */
import { spawn, spawnSync } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmdirSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, posix, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

export const OBSERVER_SCRIPT_REL = "scripts/sp1-egress-observer.ts";
export const OBSERVER_MECHANISM = "LINUX_TRACEFS_KPROBES";
export const FACTS_SCHEMA = "walletwall.sp1-egress-observer-facts.v1";
export const MANIFEST_SCHEMA = "walletwall.sp1-egress-observer-raw.v1";
export const TRACEFS = "/sys/kernel/tracing";
/** CLOCK_MONOTONIC: the clock Node's process.hrtime reads on Linux, so trace stamps and the tool's readings compare. */
export const TRACE_CLOCK = "mono";
/** Per-CPU ring buffer; a full buffer drops new events (overwrite 0), which the stats count and the validator refuses. */
export const BUFFER_KB = 4096;
export const HEARTBEAT_MS = 1000;
export const MARKER_TAG = "SP1OBS";
export const CTL_TAG = "SP1OBS-CTL";
export const RAW_TRACE_FILE = "trace.txt";
export const RAW_FACTS_FILE = "facts.json";
export const RAW_MANIFEST_FILE = "manifest.json";
/** The phases the tool marks, in the only order the observer accepts them. */
export const PHASES = [
  "PROBES_BEFORE_BEGIN",
  "PROBES_BEFORE_END",
  "GATE_BEGIN",
  "HOST_SPAWN",
  "HOST_EXIT",
  "GATE_END",
  "PROBES_AFTER_BEGIN",
  "PROBES_AFTER_END",
] as const;
export type Phase = (typeof PHASES)[number];
export const MODES = ["RUN", "SELF_TEST"] as const;
export type Mode = (typeof MODES)[number];
/** The fixed command each mode starts as the unprivileged user (relative to --repo); nothing else is ever started. */
export const TOOL_SCRIPT_REL = "scripts/measure-sp1-attributed-proof-exercise.ts";
export const TSX_CLI_REL = "node_modules/tsx/dist/cli.mjs";
export const SELF_TEST_WORKLOAD_REL = "test/fixtures/sp1-egress-observer/workload.mjs";

export interface ProbeSpec {
  name: string;
  kind: "p" | "r";
  symbol: string;
  /** The fetch arguments, `name=fetch:type` each; the only string (`comm=$comm`) is always last. */
  fetch: string;
  /** A filter the observer sets from host facts (see probeFilters). */
  filter?: "nfdrop" | "xmit";
}

const NS = "netns=sk->__sk_common.skc_net.net->ns.inum:u32";
const C = "comm=$comm";
const V4NAME = "namelen=msg->msg_namelen:s32 nfam=+0(msg->msg_name):u16";
const V6NAME =
  "namelen=msg->msg_namelen:s32 nfam=+0(msg->msg_name):u16 nport=+2(msg->msg_name):x16 na=+8(msg->msg_name):x32[4]";

/**
 * Every probe, as tracefs kprobe_events takes it (`<kind>:<group>/<name> <symbol> <fetch>`). Destinations come from
 * the message's address when one was given (`namelen`), else from the connected socket; netfilter drops carry the
 * refused packet's first 192 bytes from kernel memory (the DNS query a refused lookup asked, for one); transmits are
 * filtered to the host's namespace and non-loopback devices. Strings an unprivileged process controls (exec paths,
 * payloads) are hex arrays, never text.
 */
export const PROBES: readonly ProbeSpec[] = [
  {
    name: "newtask",
    kind: "p",
    symbol: "wake_up_new_task",
    fetch: `cpid=p->pid:s32 ctgid=p->tgid:s32 pflags=p->flags:x32 ${C}`,
  },
  {
    name: "exec",
    kind: "p",
    symbol: "begin_new_exec",
    fetch: `ino=bprm->file->f_inode->i_ino:u64 dev=bprm->file->f_inode->i_sb->s_dev:u32 f0=+0(bprm->filename):x8[64] f1=+64(bprm->filename):x8[64] ${C}`,
  },
  { name: "exit", kind: "p", symbol: "do_exit", fetch: `code=code:s64 ${C}` },
  {
    name: "udp4",
    kind: "p",
    symbol: "udp_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 ${V4NAME} nport=+2(msg->msg_name):x16 naddr=+4(msg->msg_name):x32 n6t=+20(msg->msg_name):x32 daddr=sk->__sk_common.skc_daddr:x32 dport=sk->__sk_common.skc_dport:x16 ${NS} ${C}`,
  },
  {
    name: "udp4ret",
    kind: "r",
    symbol: "udp_sendmsg",
    fetch: "ret=$retval:s32 sk=$arg1:x64 sport=sk->__sk_common.skc_num:u16",
  },
  {
    name: "udp6",
    kind: "p",
    symbol: "udpv6_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 ${V6NAME} dport=sk->__sk_common.skc_dport:x16 da=sk->__sk_common.skc_v6_daddr:x32[4] ${NS} ${C}`,
  },
  {
    name: "udp6ret",
    kind: "r",
    symbol: "udpv6_sendmsg",
    fetch: "ret=$retval:s32 sk=$arg1:x64 sport=sk->__sk_common.skc_num:u16",
  },
  {
    name: "tcp4",
    kind: "p",
    symbol: "tcp_v4_connect",
    fetch: `sk=$arg1:x64 fam=+0(uaddr):u16 port=+2(uaddr):x16 addr=+4(uaddr):x32 ${NS} ${C}`,
  },
  {
    name: "tcp4ret",
    kind: "r",
    symbol: "tcp_v4_connect",
    fetch: "ret=$retval:s32 sk=$arg1:x64 sport=sk->__sk_common.skc_num:u16",
  },
  {
    name: "tcp6",
    kind: "p",
    symbol: "tcp_v6_connect",
    fetch: `sk=$arg1:x64 fam=+0(uaddr):u16 port=+2(uaddr):x16 a=+8(uaddr):x32[4] ${NS} ${C}`,
  },
  {
    name: "tcp6ret",
    kind: "r",
    symbol: "tcp_v6_connect",
    fetch: "ret=$retval:s32 sk=$arg1:x64 sport=sk->__sk_common.skc_num:u16",
  },
  {
    name: "tcpst",
    kind: "p",
    symbol: "tcp_set_state",
    fetch: "sk=$arg1:x64 state=$arg2:s32 old=sk->__sk_common.skc_state:u8",
  },
  { name: "tcpretx", kind: "p", symbol: "tcp_retransmit_skb", fetch: "sk=$arg1:x64 segs=$arg3:s32" },
  {
    name: "raw4",
    kind: "p",
    symbol: "raw_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 proto=sk->__sk_common.skc_num:u16 ${V4NAME} naddr=+4(msg->msg_name):x32 daddr=sk->__sk_common.skc_daddr:x32 ${NS} ${C}`,
  },
  { name: "raw4ret", kind: "r", symbol: "raw_sendmsg", fetch: "ret=$retval:s32 sk=$arg1:x64" },
  {
    name: "raw6",
    kind: "p",
    symbol: "rawv6_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 proto=sk->__sk_common.skc_num:u16 ${V6NAME} da=sk->__sk_common.skc_v6_daddr:x32[4] ${NS} ${C}`,
  },
  { name: "raw6ret", kind: "r", symbol: "rawv6_sendmsg", fetch: "ret=$retval:s32 sk=$arg1:x64" },
  {
    name: "ping4",
    kind: "p",
    symbol: "ping_v4_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 ${V4NAME} naddr=+4(msg->msg_name):x32 daddr=sk->__sk_common.skc_daddr:x32 ${NS} ${C}`,
  },
  { name: "ping4ret", kind: "r", symbol: "ping_v4_sendmsg", fetch: "ret=$retval:s32 sk=$arg1:x64" },
  {
    name: "ping6",
    kind: "p",
    symbol: "ping_v6_sendmsg",
    fetch: `sk=$arg1:x64 len=len:u64 ${V6NAME} da=sk->__sk_common.skc_v6_daddr:x32[4] ${NS} ${C}`,
  },
  { name: "ping6ret", kind: "r", symbol: "ping_v6_sendmsg", fetch: "ret=$retval:s32 sk=$arg1:x64" },
  {
    name: "pkt",
    kind: "p",
    symbol: "packet_sendmsg",
    fetch: `sk=sock->sk:x64 len=len:u64 namelen=msg->msg_namelen:s32 nfam=+0(msg->msg_name):u16 nproto=+2(msg->msg_name):x16 nifindex=+4(msg->msg_name):s32 netns=sock->sk->__sk_common.skc_net.net->ns.inum:u32 ${C}`,
  },
  { name: "pktret", kind: "r", symbol: "packet_sendmsg", fetch: "ret=$retval:s32 sk=sock->sk:x64" },
  {
    name: "nfdrop",
    kind: "p",
    symbol: "sk_skb_reason_drop",
    fetch: `reason=reason:s32 sk=skb->sk:x64 skns=skb->sk->__sk_common.skc_net.net->ns.inum:u32 proto=skb->protocol:x16 len=skb->len:u32 h0=+0(skb->data):x8[64] h1=+64(skb->data):x8[64] h2=+128(skb->data):x8[64] ${C}`,
    filter: "nfdrop",
  },
  {
    name: "xmit",
    kind: "p",
    symbol: "dev_hard_start_xmit",
    fetch: `skb=first:x64 ifindex=dev->ifindex:s32 netns=dev->nd_net.net->ns.inum:u32 proto=first->protocol:x16 len=first->len:u32 h0=+0(first->data):x8[64] ${C}`,
    filter: "xmit",
  },
];

/** The kprobe group of a run: one per nonce, so a run never touches another's probes. */
export const groupOf = (nonce: string) => `sp1obs_${nonce}`;
export const NONCE = /^[0-9a-f]{16}$/;

/** The probe lines `group` installs, in PROBES order. */
export function renderProbes(group: string): string[] {
  return PROBES.map((p) => `${p.kind}:${group}/${p.name} ${p.symbol} ${p.fetch}`);
}

/** The filters set from the host's facts: netfilter drops only, and transmits of the host's non-loopback devices. */
export function probeFilters(hostNetns: number, nfDropReason: number): { nfdrop: string; xmit: string } {
  return { nfdrop: `reason == ${nfDropReason}`, xmit: `netns == ${hostNetns} && ifindex != 1` };
}

export interface ObserverConfig {
  mechanism: string;
  clock: string;
  bufferKb: number;
  overwrite: number;
  recordTgid: number;
  heartbeatMs: number;
  probes: string[];
  filters: { nfdrop: string; xmit: string };
}

/** The whole configuration a run installs; the validator rebuilds it from the facts and requires equality. */
export function observerConfig(input: { nonce: string; hostNetns: number; nfDropReason: number }): ObserverConfig {
  return {
    mechanism: OBSERVER_MECHANISM,
    clock: TRACE_CLOCK,
    bufferKb: BUFFER_KB,
    overwrite: 0,
    recordTgid: 1,
    heartbeatMs: HEARTBEAT_MS,
    probes: renderProbes(groupOf(input.nonce)),
    filters: probeFilters(input.hostNetns, input.nfDropReason),
  };
}

export const sha256Hex = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");

/** JSON with sorted keys and no whitespace; own keys only, `__proto__` included as data (never a prototype). */
export function canonicalJson(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = Object.create(null);
      for (const k of Object.keys(v as object).sort()) {
        Object.defineProperty(out, k, {
          value: sort((v as Record<string, unknown>)[k]),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(sort(value));
}

export const configSha256 = (config: ObserverConfig) => sha256Hex(canonicalJson(config));

const TOKEN = /^[A-Za-z0-9_.:/=+-]+$/;

/** One marker line (no newline): `SP1OBS <nonce> <seq> <KIND> k=v ...`; every value is one plain token. */
export function formatMarker(
  nonce: string,
  seq: number,
  kind: string,
  fields: Record<string, string | number> = {},
): string {
  const parts = [MARKER_TAG, nonce, String(seq), kind];
  for (const [k, v] of Object.entries(fields)) {
    const text = `${k}=${String(v)}`;
    if (!TOKEN.test(text)) throw new Error(`marker field ${k} is not one plain token`);
    parts.push(text);
  }
  return parts.join(" ");
}

export type CtlMessage =
  | { kind: "HELLO"; commit: string; host: string }
  | { kind: "PHASE"; phase: Phase }
  | { kind: "CONTAINER"; id: string; pid: number }
  | { kind: "DONE" }
  | { kind: "ABORT"; reason: string };

/** A control line from the tool, or null when the line is not one (then it is the tool's log output). */
export function parseCtl(line: string): CtlMessage | null {
  if (!line.startsWith(`${CTL_TAG} `)) return null;
  const words = line.slice(CTL_TAG.length + 1).split(" ");
  const [w, a, b] = words;
  if (w === "HELLO" && words.length === 3 && /^[0-9a-f]{40}$/.test(a) && HOST_LABEL.test(b))
    return { kind: "HELLO", commit: a, host: b };
  if (w === "PHASE" && words.length === 2 && (PHASES as readonly string[]).includes(a))
    return { kind: "PHASE", phase: a as Phase };
  if (w === "CONTAINER" && words.length === 3 && /^[0-9a-f]{64}$/.test(a) && /^[1-9][0-9]{0,9}$/.test(b)) {
    return { kind: "CONTAINER", id: a, pid: Number(b) };
  }
  if (w === "DONE" && words.length === 1) return { kind: "DONE" };
  if (w === "ABORT" && words.length === 2 && /^[A-Z_]{1,64}$/.test(a)) return { kind: "ABORT", reason: a };
  throw new Error(`malformed control line from the tool: ${line.slice(0, 120)}`);
}

export const formatCtl = (...words: (string | number)[]) => [CTL_TAG, ...words.map(String)].join(" ");
/** A host label, as the run observations name hosts. */
export const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** The NETFILTER_DROP value of the kernel's skb drop-reason enum, from the kfree_skb tracepoint's format. */
export function netfilterDropReason(formatText: string): number {
  const m = /\{\s*(\d+),\s*"NETFILTER_DROP"\s*\}/.exec(formatText);
  if (!m) throw new Error("the kernel's skb drop reasons name no NETFILTER_DROP");
  return Number(m[1]);
}

export interface CpuStats {
  cpu: number;
  entries: number;
  overrun: number;
  commitOverrun: number;
  droppedEvents: number;
  readEvents: number;
}

/** One per_cpu/cpuN/stats file; every counter the loss check needs must read as a whole number. */
export function parseCpuStats(cpu: number, text: string): CpuStats {
  const field = (name: string): number => {
    const m = new RegExp(`^${name}: (\\d+)$`, "m").exec(text);
    if (!m) throw new Error(`cpu${cpu} stats lack "${name}"`);
    return Number(m[1]);
  };
  return {
    cpu,
    entries: field("entries"),
    overrun: field("overrun"),
    commitOverrun: field("commit overrun"),
    droppedEvents: field("dropped events"),
    readEvents: field("read events"),
  };
}

/**
 * The misses of the probes `names` in tracefs's kprobe_profile (`  <event> <hits> <misses>` per kprobe event, every
 * group's, the group not printed): every line must read so, and every name must be listed, or nothing is vouched for.
 * A name another group also uses is summed with it: such a miss stops the run too (the safe side).
 */
export function probeMisses(profile: string, names: readonly string[]): number {
  const wanted = new Set(names);
  const seen = new Set<string>();
  let misses = 0;
  for (const line of profile.split("\n")) {
    if (line === "") continue;
    const m = /^ +(\S+) +(\d+) +(\d+)$/.exec(line);
    if (!m) throw new Error(`kprobe_profile holds a line that does not read: ${line.slice(0, 80)}`);
    if (!wanted.has(m[1])) continue;
    seen.add(m[1]);
    misses += Number(m[3]);
  }
  const absent = names.filter((n) => !seen.has(n));
  if (absent.length > 0) throw new Error(`kprobe_profile does not list ${absent.join(", ")}`);
  return misses;
}

/** The resolvers /etc/resolv.conf names (nameserver lines), in order. */
export function resolversOf(resolvConf: string): string[] {
  return resolvConf
    .split(/\r?\n/)
    .map((l) => /^\s*nameserver\s+(\S+)\s*$/.exec(l)?.[1])
    .filter((x): x is string => typeof x === "string");
}

/** `net:[4026531833]` -> 4026531833. */
export function nsInode(link: string): number {
  const m = /^[a-z]+:\[(\d+)\]$/.exec(link.trim());
  if (!m) throw new Error(`${link} is not a namespace link`);
  return Number(m[1]);
}

export interface Interface {
  ifindex: number;
  name: string;
  addresses: string[];
}

/** `ip -j addr show`: each interface's index, name and addresses (`<address>/<prefix>`). */
export function interfacesOf(ipAddrJson: string): Interface[] {
  const list = JSON.parse(ipAddrJson) as { ifindex?: unknown; ifname?: unknown; addr_info?: unknown }[];
  if (!Array.isArray(list)) throw new Error("ip -j addr is not a list");
  return list.map((i) => {
    if (!Number.isSafeInteger(i.ifindex) || typeof i.ifname !== "string")
      throw new Error("ip -j addr: an interface lacks its index or name");
    const addrs = Array.isArray(i.addr_info) ? (i.addr_info as { local?: unknown; prefixlen?: unknown }[]) : [];
    return {
      ifindex: i.ifindex as number,
      name: i.ifname,
      addresses: addrs
        .filter((a) => typeof a.local === "string")
        .map((a) => `${String(a.local)}/${String(a.prefixlen)}`),
    };
  });
}

/** The interfaces default routes leave through (`ip -j route show default`, both families): the uplinks. */
export function uplinksOf(routesJson: string[], interfaces: readonly Interface[]): number[] {
  const out = new Set<number>();
  for (const text of routesJson) {
    const routes = JSON.parse(text === "" ? "[]" : text) as { dev?: unknown }[];
    for (const r of routes) {
      const i = interfaces.find((x) => x.name === r.dev);
      if (i) out.add(i.ifindex);
    }
  }
  return [...out].sort((a, b) => a - b);
}

/** `getent passwd <user>` -> uid, gid, home; refuses root (the tool and the gate run unprivileged). */
export function userOf(passwdLine: string): { name: string; uid: number; gid: number; home: string } {
  const f = passwdLine.trim().split(":");
  if (f.length < 7 || !/^\d+$/.test(f[2]) || !/^\d+$/.test(f[3])) throw new Error("not a passwd entry");
  const uid = Number(f[2]);
  if (uid === 0) throw new Error("the tool must run as an unprivileged user, not root");
  return { name: f[0], uid, gid: Number(f[3]), home: f[5] };
}

// ---------------------------------------------------------------------------------------------------------------
// The tracefs session (injectable, so a suite can drive it against a fake tracefs)
// ---------------------------------------------------------------------------------------------------------------

export interface TraceFs {
  read(path: string): string;
  /** Opens, writes `data`, closes (a tracefs control file takes one write). */
  write(path: string, data: string): void;
  /** Appends `data` (kprobe_events keeps every other definition: never truncate it). */
  append(path: string, data: string): void;
  exists(path: string): boolean;
  mkdir(path: string): void;
  rmdir(path: string): void;
  list(path: string): string[];
  /** Opens the marker file for writing and returns a writer of one line. */
  openMarker(path: string): { write(line: string): void; close(): void };
}

export const realTraceFs: TraceFs = {
  read: (p) => readFileSync(p, "latin1"),
  write: (p, d) => writeFileSync(p, d),
  append: (p, d) => writeFileSync(p, d, { flag: "a" }),
  exists: (p) => existsSync(p),
  mkdir: (p) => mkdirSync(p),
  rmdir: (p) => rmdirSync(p),
  list: (p) => readdirSync(p),
  openMarker: (p) => {
    const fd = openSync(p, "w");
    return { write: (line) => void writeSync(fd, `${line}\n`), close: () => closeSync(fd) };
  },
};

export class ObserverRefusal extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

/** tracefs paths are POSIX paths on every host (the suite drives the session against an in-memory tracefs). */
const tjoin = posix.join;

/** One private instance with this run's probes; every step it took is undone by close(), whatever failed. */
export class TraceSession {
  readonly fs: TraceFs;
  readonly root: string;
  readonly nonce: string;
  readonly group: string;
  readonly instance: string;
  private defined: string[] = [];
  private enabled: string[] = [];
  private created = false;
  private marker: { write(line: string): void; close(): void } | null = null;
  private seq = 0;
  config: ObserverConfig | null = null;
  readBack: string[] = [];

  constructor(fs: TraceFs, nonce: string, root = TRACEFS) {
    if (!NONCE.test(nonce)) throw new Error("the nonce must be 16 lowercase hex digits");
    this.fs = fs;
    this.root = root;
    this.nonce = nonce;
    this.group = groupOf(nonce);
    this.instance = tjoin(root, "instances", this.group);
  }

  /** Refuses unless tracefs offers what the probes need; returns the NETFILTER_DROP reason value. */
  precheck(): number {
    for (const f of ["kprobe_events", "instances", "error_log", "events/skb/kfree_skb/format"]) {
      if (!this.fs.exists(tjoin(this.root, f)))
        throw new ObserverRefusal("TRACEFS_UNAVAILABLE", `${tjoin(this.root, f)} is missing`);
    }
    // Any observer's leftovers (a run that crashed): their probes could hit, miss and be counted as this run's.
    const leftInstances = this.fs.list(tjoin(this.root, "instances")).filter((n) => n.startsWith("sp1obs_"));
    if (leftInstances.length > 0)
      throw new ObserverRefusal(
        "INSTANCE_EXISTS",
        `an observer's instance is still there: ${leftInstances.join(", ")}`,
      );
    const left = this.fs
      .read(tjoin(this.root, "kprobe_events"))
      .split("\n")
      .filter((l) => /^[pr]\d*:sp1obs_/.test(l));
    if (left.length > 0)
      throw new ObserverRefusal("PROBES_EXIST", `${left.length} probes of an earlier observer are still defined`);
    return netfilterDropReason(this.fs.read(tjoin(this.root, "events/skb/kfree_skb/format")));
  }

  /** Creates the instance, defines and verifies every probe, sets the filters, enables everything, starts tracing. */
  open(hostNetns: number, nfDropReason: number): ObserverConfig {
    const config = observerConfig({ nonce: this.nonce, hostNetns, nfDropReason });
    this.fs.mkdir(this.instance);
    this.created = true;
    const at = (f: string) => tjoin(this.instance, f);
    this.fs.write(at("trace_clock"), TRACE_CLOCK);
    this.fs.write(at("options/record-tgid"), "1");
    this.fs.write(at("options/overwrite"), "0");
    this.fs.write(at("buffer_size_kb"), String(BUFFER_KB));
    const events = tjoin(this.root, "kprobe_events");
    config.probes.forEach((line, i) => {
      try {
        this.fs.append(events, `${line}\n`);
      } catch (error) {
        const log = this.fs.exists(tjoin(this.root, "error_log"))
          ? this.fs.read(tjoin(this.root, "error_log")).split("\n").slice(-4).join(" | ")
          : "";
        throw new ObserverRefusal(
          "PROBE_REFUSED",
          `the kernel refused ${PROBES[i].name} (${(error as Error).message}): ${log}`,
        );
      }
      this.defined.push(PROBES[i].name);
    });
    this.readBack = this.fs
      .read(events)
      .split("\n")
      .filter((l) => l.includes(`:${this.group}/`));
    // The kernel lists a return probe with its maxactive (`r16:group/event`); the probe's name is what must be there.
    const name = (l: string) =>
      l
        .trim()
        .split(" ")[0]
        .replace(/^r\d+:/, "r:");
    const want = config.probes.map(name);
    const got = this.readBack.map(name);
    for (const w of want) {
      if (!got.includes(w))
        throw new ObserverRefusal(
          "PROBE_MISSING",
          `${w} is not defined after its definition (the kernel lists: ${got.join(", ")})`,
        );
    }
    if (got.length !== want.length)
      throw new ObserverRefusal(
        "PROBE_MISSING",
        `${got.length} probes of ${this.group} are defined, not ${want.length}`,
      );
    for (const p of PROBES) {
      if (p.filter) this.fs.write(at(`events/${this.group}/${p.name}/filter`), config.filters[p.filter]);
    }
    for (const p of PROBES) {
      this.fs.write(at(`events/${this.group}/${p.name}/enable`), "1");
      this.enabled.push(p.name);
    }
    this.marker = this.fs.openMarker(at("trace_marker"));
    this.fs.write(at("tracing_on"), "1");
    this.config = config;
    return config;
  }

  /** Writes one marker as root and returns its sequence number (1, 2, ... with no gap). */
  mark(kind: string, fields: Record<string, string | number> = {}): number {
    if (this.marker === null) throw new Error("the session is not open");
    this.seq += 1;
    this.marker.write(formatMarker(this.nonce, this.seq, kind, fields));
    return this.seq;
  }

  tracingOn(): boolean {
    return this.fs.read(tjoin(this.instance, "tracing_on")).trim() === "1";
  }

  stats(): CpuStats[] {
    const dir = tjoin(this.instance, "per_cpu");
    return this.fs
      .list(dir)
      .filter((d) => /^cpu\d+$/.test(d))
      .map((d) => parseCpuStats(Number(d.slice(3)), this.fs.read(tjoin(dir, d, "stats"))))
      .sort((a, b) => a.cpu - b.cpu);
  }

  /**
   * Whether every probe is still enabled in the instance, and kprobes still armed where debugfs shows it. Sampled at each
   * heartbeat: a probe switched off and back on between two samples is not seen (a root process can do that: see the
   * docs' trust statement), one left off is.
   */
  armed(): boolean {
    if (this.enabled.length === 0) return false;
    const on = this.enabled.every(
      (name) => this.fs.read(tjoin(this.instance, `events/${this.group}/${name}/enable`)).trim() === "1",
    );
    const global = "/sys/kernel/debug/kprobes/enabled";
    return on && (!this.fs.exists(global) || this.fs.read(global).trim() === "1");
  }

  /** The misses of every probe this session defined, from kprobe_profile (a missed hit is a lost event). */
  misses(): number {
    if (this.defined.length === 0) throw new Error("the session defined no probe");
    return probeMisses(this.fs.read(tjoin(this.root, "kprobe_profile")), this.defined);
  }

  stopTracing(): void {
    if (this.created) this.fs.write(tjoin(this.instance, "tracing_on"), "0");
  }

  /** Disables, removes the instance and every probe this session defined; returns what it could not undo. */
  close(): string[] {
    const left: string[] = [];
    const attempt = (what: string, act: () => void) => {
      try {
        act();
      } catch (error) {
        left.push(`${what}: ${(error as Error).message}`);
      }
    };
    if (this.marker !== null) attempt("marker", () => this.marker?.close());
    this.marker = null;
    if (this.created) {
      attempt("tracing_on", () => this.fs.write(tjoin(this.instance, "tracing_on"), "0"));
      for (const name of [...this.enabled].reverse()) {
        attempt(`disable ${name}`, () =>
          this.fs.write(tjoin(this.instance, `events/${this.group}/${name}/enable`), "0"),
        );
      }
      this.enabled = [];
      attempt("instance", () => this.fs.rmdir(this.instance));
      if (!this.fs.exists(this.instance)) this.created = false;
    }
    for (const name of [...this.defined].reverse()) {
      attempt(`remove ${name}`, () => this.fs.append(tjoin(this.root, "kprobe_events"), `-:${this.group}/${name}\n`));
    }
    this.defined = [];
    attempt("verify", () => {
      const still = this.fs
        .read(tjoin(this.root, "kprobe_events"))
        .split("\n")
        .filter((l) => l.includes(`:${this.group}/`));
      if (still.length > 0) left.push(`${still.length} probes of ${this.group} remain defined`);
      if (this.fs.exists(this.instance)) left.push(`${this.instance} remains`);
    });
    return left;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The observer's decisions, pure (the command below only acts on them)
// ---------------------------------------------------------------------------------------------------------------

/**
 * The tool's requests, in the only order the observer serves them: HELLO once, before any phase; the phases in PHASES
 * order, each once; DONE only after the last. Each served request is a marker to write (then acknowledged); anything
 * out of order is refused, and a refusal fails the run.
 */
export class ControlProtocol {
  private next = 0;
  private hello = false;
  private done = false;

  accept(
    msg: CtlMessage,
    resolveNetns: (id: string, pid: number) => string,
  ): { mark: { kind: string; fields: Record<string, string | number> } } | { abort: string } | { done: true } {
    if (this.done) throw new ObserverRefusal("PHASE_ORDER", "a request after DONE");
    if (msg.kind === "HELLO") {
      // A phase needs HELLO first, so a second HELLO is the only HELLO that could follow a phase.
      if (this.hello) throw new ObserverRefusal("PHASE_ORDER", "HELLO comes once, before the first phase");
      this.hello = true;
      return { mark: { kind: "HELLO", fields: { commit: msg.commit, host: msg.host } } };
    }
    if (msg.kind === "PHASE") {
      if (!this.hello) throw new ObserverRefusal("PHASE_ORDER", "a phase before HELLO");
      if (PHASES[this.next] !== msg.phase) {
        throw new ObserverRefusal("PHASE_ORDER", `${msg.phase} out of order (expected ${PHASES[this.next] ?? "none"})`);
      }
      this.next++;
      return { mark: { kind: "PHASE", fields: { name: msg.phase } } };
    }
    if (msg.kind === "CONTAINER") {
      if (!this.hello) throw new ObserverRefusal("PHASE_ORDER", "a container before HELLO");
      return {
        mark: { kind: "CONTAINER", fields: { id: msg.id, pid: msg.pid, netns: resolveNetns(msg.id, msg.pid) } },
      };
    }
    if (msg.kind === "ABORT") return { abort: msg.reason };
    if (this.next !== PHASES.length) throw new ObserverRefusal("PHASE_ORDER", `DONE before ${PHASES[this.next]}`);
    this.done = true;
    return { done: true };
  }
}

/**
 * The network namespace of a container's process, as the observer may record it: its inode only when the process's
 * cgroup names the container (else "unverified": the tool cannot vouch a process into the proof's scope), "unknown"
 * when the process cannot be read (it ended, or it is not there).
 */
export function containerNetns(
  id: string,
  readCgroup: (pid: number) => string,
  readNetnsLink: (pid: number) => string,
  pid: number,
): string {
  try {
    if (!readCgroup(pid).includes(id)) return "unverified";
    return String(nsInode(readNetnsLink(pid)));
  } catch {
    return "unknown";
  }
}

/**
 * A heartbeat's marker fields and whether the run may continue: tracing on (the instance tracing and every probe still
 * armed: `tracingOn` is 1 only for both), per-CPU stats read, and nothing lost (`loss` counts every CPU's overruns and
 * dropped events and every probe's misses).
 */
export function heartbeatOf(
  n: number,
  stats: readonly CpuStats[],
  tracingOn: boolean,
  misses: number,
  armed: boolean,
): { fields: { n: number; tracingOn: number; loss: number }; ok: boolean } {
  const loss = stats.reduce((s, c) => s + c.overrun + c.commitOverrun + c.droppedEvents, 0) + misses;
  const on = tracingOn && armed;
  return { fields: { n, tracingOn: on ? 1 : 0, loss }, ok: on && loss === 0 && stats.length > 0 };
}

/**
 * Why `dir` may not hold the raw evidence: it must be an absolute path of plain characters, with no `.` or `..`
 * component, that does not exist yet, under directories only root can change (else the proving user could swap it under
 * the observer and have it bind a capture of the user's making) and that let anyone pass (the tool reads the raw
 * evidence as the proving user, after the proof: a directory it cannot enter would lose the proof's observation).
 */
export function rawDirErrors(
  dir: string,
  exists: (p: string) => boolean,
  statOf: (p: string) => { uid: number; mode: number },
): string[] {
  if (!isAbsolute(dir) || !RAW_DIR.test(dir) || dir.split("/").some((c) => c === "." || c === "..") || exists(dir)) {
    return [
      "--raw-dir must be an absolute path of plain characters, with no . or .. component, that does not exist yet",
    ];
  }
  const errors = rootOwnedPathErrors(dirname(dir), statOf);
  for (let p = dirname(resolve(dir)); ; p = dirname(p)) {
    if ((statOf(p).mode & 0o001) === 0)
      errors.push(`${p} does not let others pass: the tool could not read the raw evidence`);
    if (dirname(p) === p) break;
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------------------------
// The command (root): facts, session, the tool, heartbeats, stop, raw evidence
// ---------------------------------------------------------------------------------------------------------------

/** Every path from `file` up to `/` must be root-owned and writable by no one else, or a non-root user could swap it. */
export function rootOwnedPathErrors(file: string, statOf: (p: string) => { uid: number; mode: number }): string[] {
  const errors: string[] = [];
  let p = resolve(file);
  for (;;) {
    const s = statOf(p);
    if (s.uid !== 0) errors.push(`${p} is owned by uid ${s.uid}, not root`);
    if ((s.mode & 0o022) !== 0) errors.push(`${p} is writable by group or others`);
    const up = dirname(p);
    if (up === p) break;
    p = up;
  }
  return errors;
}

function run(cmd: string, args: string[]): string {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    shell: false,
    timeout: 30_000,
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
  });
  if (r.error || r.status !== 0)
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.error?.message ?? r.stderr.trim()})`);
  return r.stdout;
}

const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
/** The raw directory travels in one control line, so it is one plain token. */
const RAW_DIR = new RegExp("^/[A-Za-z0-9._/-]+$");

function argValue(argv: string[], name: string, count = 1): string[] {
  const i = argv.indexOf(name);
  const values = i === -1 ? [] : argv.slice(i + 1, i + 1 + count);
  if (values.length !== count || values.some((v) => v.startsWith("--"))) throw new Error(`${name} is required`);
  return values;
}

async function main(argv: string[]): Promise<number> {
  // The raw directory and files are made with the modes written below (0755, 0644), whatever root's umask: the tool
  // reads them as the proving user.
  process.umask(0o022);
  const mode: Mode | null = argv[0] === "run" ? "RUN" : argv[0] === "self-test" ? "SELF_TEST" : null;
  if (mode === null)
    throw new Error(
      "usage: sp1-egress-observer.ts run|self-test --as <user> --repo <dir> --table <family> <name> --raw-dir <new dir> [-- <tool arguments>]",
    );
  const own = argv.slice(0, argv.includes("--") ? argv.indexOf("--") : argv.length);
  const toolArgs = argv.includes("--") ? argv.slice(argv.indexOf("--") + 1) : [];
  if (mode === "SELF_TEST" && toolArgs.length > 0) throw new Error("self-test takes no tool arguments");
  if (process.platform !== "linux") throw new ObserverRefusal("NOT_LINUX", "tracefs and kprobes are Linux facilities");
  if (process.getuid?.() !== 0) throw new ObserverRefusal("NOT_ROOT", "tracefs control needs root");
  const self = fileURLToPath(import.meta.url);
  const pathErrors = rootOwnedPathErrors(self, (p) => lstatSync(p));
  if (pathErrors.length > 0) throw new ObserverRefusal("OBSERVER_PATH_NOT_ROOT_OWNED", pathErrors.join("; "));
  const [userName] = argValue(own, "--as");
  const [repoArg] = argValue(own, "--repo");
  const [family, table] = argValue(own, "--table", 2);
  const [rawArg] = argValue(own, "--raw-dir");
  if (!["inet", "ip", "ip6"].includes(family) || !/^[A-Za-z0-9_]{1,64}$/.test(table))
    throw new Error("--table takes a family (inet, ip, ip6) and a table name");
  const rawErrors = rawDirErrors(rawArg, existsSync, (p) => lstatSync(p));
  if (rawErrors.length > 0) throw new ObserverRefusal("RAW_DIR_REFUSED", rawErrors.join("; "));
  const repo = realpathSync(repoArg);
  const user = userOf(run("getent", ["passwd", userName]));
  const command =
    mode === "RUN"
      ? [process.execPath, join(repo, TSX_CLI_REL), join(repo, TOOL_SCRIPT_REL), ...toolArgs]
      : [process.execPath, join(repo, SELF_TEST_WORKLOAD_REL)];
  for (const f of command.slice(1, mode === "RUN" ? 3 : 2)) if (!existsSync(f)) throw new Error(`${f} is missing`);

  const nonce = randomBytes(8).toString("hex");
  const observerSha256 = sha256Hex(readFileSync(self, "utf8").replace(/\r\n/g, "\n"));
  const interfaces = interfacesOf(run("ip", ["-j", "addr", "show"]));
  const facts: Record<string, unknown> = {
    schema: FACTS_SCHEMA,
    mode,
    nonce,
    group: groupOf(nonce),
    observer: { script: OBSERVER_SCRIPT_REL, scriptSha256: observerSha256 },
    kernelRelease: readFileSync("/proc/sys/kernel/osrelease", "utf8").trim(),
    bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    hostNetns: nsInode(readlinkSync("/proc/self/ns/net")),
    resolvers: resolversOf(existsSync("/etc/resolv.conf") ? readFileSync("/etc/resolv.conf", "utf8") : ""),
    wslInterop: existsSync("/proc/sys/fs/binfmt_misc/WSLInterop")
      ? readFileSync("/proc/sys/fs/binfmt_misc/WSLInterop", "utf8").split("\n")[0].trim()
      : "absent",
    interfaces,
    uplinks: uplinksOf(
      [run("ip", ["-j", "route", "show", "default"]), run("ip", ["-6", "-j", "route", "show", "default"])],
      interfaces,
    ),
    table: `${family} ${table}`,
    user: { name: user.name, uid: user.uid, gid: user.gid },
    command: command.map((c) => (c.startsWith(repo) ? `<repo>${c.slice(repo.length)}` : c)),
    counters: [] as unknown[],
    heartbeats: 0,
    failures: [] as string[],
  };
  mkdirSync(rawArg, { mode: 0o755 });
  const rawTrace = join(rawArg, RAW_TRACE_FILE);
  const session = new TraceSession(realTraceFs, nonce);
  const failures = facts.failures as string[];
  let tool: ChildProcess | null = null;
  let drain: ChildProcess | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let stopping = false;
  const toTool = (...words: (string | number)[]) => {
    if (tool?.stdin && !tool.stdin.destroyed) tool.stdin.write(`${formatCtl(...words)}\n`);
  };
  const counters = (n: number) => {
    session.mark("COUNTERS_BEGIN", { n });
    const text = run("nft", ["-j", "list", "table", family, table]);
    JSON.parse(text);
    (facts.counters as unknown[]).push({ n, nft: JSON.parse(text) });
    session.mark("COUNTERS_END", { n, sha256: sha256Hex(text) });
  };
  const beat = () => {
    facts.heartbeats = (facts.heartbeats as number) + 1;
    const h = heartbeatOf(
      facts.heartbeats as number,
      session.stats(),
      session.tracingOn(),
      session.misses(),
      session.armed(),
    );
    session.mark("HEARTBEAT", h.fields);
    if (!h.ok)
      throw new ObserverRefusal("OBSERVER_LOSS", `tracing_on ${h.fields.tracingOn}, ${h.fields.loss} events lost`);
  };
  const fail = (code: string, why: string) => {
    if (failures.length === 0) process.stderr.write(`observer: ${code}: ${why}\n`);
    failures.push(`${code}: ${why}`);
    try {
      session.mark("FAIL", { code });
    } catch {
      // the session may already be gone; the failure is in the facts
    }
    toTool("FAIL", code);
  };

  let exitCode = 3;
  try {
    const nfDropReason = session.precheck();
    const config = session.open(facts.hostNetns as number, nfDropReason);
    Object.assign(facts, {
      nfDropReason,
      config,
      configSha256: configSha256(config),
      kprobeReadBack: session.readBack,
    });
    const rawFd = openSync(rawTrace, "wx", 0o644);
    drain = spawn("cat", [join(session.instance, "trace_pipe")], { stdio: ["ignore", rawFd, "pipe"], env: {} });
    closeSync(rawFd);
    const clock = { utc: utcNow(), monoNs: process.hrtime.bigint().toString() };
    facts.readyClock = clock;
    session.mark("READY", {
      mode,
      bootId: facts.bootId as string,
      hostNetns: facts.hostNetns as number,
      config: facts.configSha256 as string,
      utc: clock.utc,
      monoNs: clock.monoNs,
    });
    counters(1);
    beat();
    heartbeat = setInterval(() => {
      try {
        beat();
      } catch (error) {
        fail("OBSERVER_LOSS", (error as Error).message);
      }
    }, HEARTBEAT_MS);
    const done = new Promise<number | null>((resolveDone, rejectDone) => {
      tool = spawn(
        "setpriv",
        [
          `--reuid=${user.uid}`,
          `--regid=${user.gid}`,
          "--init-groups",
          "--reset-env",
          "--no-new-privs",
          "--",
          ...command,
        ],
        { cwd: repo, stdio: ["pipe", "pipe", "inherit"], env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" } },
      );
      session.mark("SPAWNED", { pid: tool.pid ?? 0 });
      toTool("READY", nonce, session.group, facts.bootId as string, mode);
      const protocol = new ControlProtocol();
      const resolveNetns = (id: string, pid: number) =>
        containerNetns(
          id,
          (p) => readFileSync(`/proc/${p}/cgroup`, "utf8"),
          (p) => readlinkSync(`/proc/${p}/ns/net`),
          pid,
        );
      const lines = createInterface({ input: tool.stdout as NodeJS.ReadableStream });
      lines.on("line", (line) => {
        let msg: CtlMessage | null;
        try {
          msg = parseCtl(line);
        } catch (error) {
          fail("CTL_MALFORMED", (error as Error).message);
          return;
        }
        if (msg === null) {
          process.stdout.write(`${line}\n`);
          return;
        }
        if (stopping) return;
        try {
          const act = protocol.accept(msg, resolveNetns);
          if ("mark" in act) toTool("ACK", session.mark(act.mark.kind, act.mark.fields));
          else if ("abort" in act) fail("TOOL_ABORTED", act.abort);
          else {
            stopping = true;
            resolveDone(null);
          }
        } catch (error) {
          fail((error as ObserverRefusal).code ?? "CTL_REFUSED", (error as Error).message);
        }
      });
      tool.on("error", rejectDone);
      tool.on("exit", (code, signal) => {
        facts.toolExit = { code, signal };
        if (!stopping) {
          stopping = true;
          fail("TOOL_EXITED", `the tool exited (${code ?? signal}) before DONE`);
          resolveDone(code ?? 1);
        }
      });
    });
    const early = await done;
    if (heartbeat) clearInterval(heartbeat);
    heartbeat = null;
    session.mark("TOOL_DONE", { ok: early === null && failures.length === 0 ? 1 : 0 });
    counters(2);
    beat();
    const stopFields = { failures: failures.length };
    const stopLine = `tracing_mark_write: ${formatMarker(nonce, session.mark("STOP", stopFields), "STOP", stopFields)}`;
    session.stopTracing();
    const deadline = Date.now() + 30_000;
    while (
      !readFileSync(rawTrace, "latin1")
        .split("\n")
        .some((l) => l.endsWith(stopLine))
    ) {
      if (Date.now() > deadline)
        throw new ObserverRefusal("DRAIN_INCOMPLETE", "the STOP marker never reached the raw trace");
      await new Promise((r) => setTimeout(r, 100));
    }
    const drainer = drain as ChildProcess;
    if (drainer.exitCode === null && drainer.signalCode === null) {
      const exited = new Promise((r) => drainer.once("exit", r));
      drainer.kill("SIGTERM");
      await exited;
    }
    drain = null;
    const leftover = readFileSync(join(session.instance, "trace"), "latin1")
      .split("\n")
      .filter((l) => l !== "" && !l.startsWith("#"));
    facts.leftoverLines = leftover.length;
    if (leftover.length > 0) writeFileSync(rawTrace, `${leftover.join("\n")}\n`, { flag: "a" });
    facts.stats = session.stats();
    facts.probeMisses = session.misses();
    if (early !== null) exitCode = early === 0 ? 4 : early;
    else exitCode = 0;
  } catch (error) {
    fail((error as ObserverRefusal).code ?? "OBSERVER_ERROR", (error as Error).message);
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    if (drain !== null) (drain as ChildProcess).kill("SIGTERM");
    const left = session.close();
    facts.cleanup = left;
    if (left.length > 0) failures.push(`CLEANUP_INCOMPLETE: ${left.join("; ")}`);
    const write = (name: string, text: string) => writeFileSync(join(rawArg, name), text, { mode: 0o644, flag: "wx" });
    write(RAW_FACTS_FILE, `${JSON.stringify(facts, null, 2)}\n`);
    const files = [RAW_TRACE_FILE, RAW_FACTS_FILE]
      .filter((name) => existsSync(join(rawArg, name)))
      .map((name) => {
        const bytes = readFileSync(join(rawArg, name));
        return { name, bytes: bytes.length, sha256: sha256Hex(bytes) };
      });
    const manifest = `${JSON.stringify({ schema: MANIFEST_SCHEMA, files }, null, 2)}\n`;
    write(RAW_MANIFEST_FILE, manifest);
    if (failures.length === 0) toTool("STOPPED", sha256Hex(manifest), rawArg);
    else toTool("FAIL", "OBSERVER_FAILED");
  }
  const toolExit = await new Promise<number>((r) => {
    const t = tool as ChildProcess | null;
    if (t === null || t.exitCode !== null || t.signalCode !== null) return r(t?.exitCode ?? 1);
    const timer = setTimeout(() => {
      t.kill("SIGKILL");
      r(1);
    }, 600_000);
    t.once("exit", (code) => {
      clearTimeout(timer);
      r(code ?? 1);
    });
  });
  if (failures.length > 0) return 3;
  return exitCode !== 0 ? exitCode : toolExit;
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error((error as Error).message);
      process.exitCode = 2;
    },
  );
}
