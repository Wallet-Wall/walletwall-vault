// SP1-PA3C self-test workload: the one command `sp1-egress-observer.ts self-test` starts (as an unprivileged user).
// It speaks the observer's control protocol exactly as the attributed measurement tool does and makes only harmless
// synthetic attempts at TEST-NET-1 (192.0.2.0/24, RFC 5737, never routed), which the integration test's private nft
// table refuses: a TCP "probe" before and after, and, between HOST_SPAWN and HOST_EXIT, a child process (the stand-in
// for the proof's host) that sends one DNS query for pa3c-selftest.example to 192.0.2.53. It proves nothing, pulls
// nothing and reaches no real host. It acts only when node runs it (the observer does); a test runner that loads every
// script under test/ finds nothing to run here. Research prototype. Not audited.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const TAG = "SP1OBS-CTL";
const HOST_CODE = [
  "const q = Buffer.concat([Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),",
  "  Buffer.from([13]), Buffer.from('pa3c-selftest'), Buffer.from([7]), Buffer.from('example'), Buffer.from([0, 0, 1, 0, 1])]);",
  "const d = require('node:dgram').createSocket('udp4');",
  "d.send(q, 53, '192.0.2.53', (e) => { console.error('host udp', e ? e.code : 'sent'); d.close(); });",
].join("\n");

const probe = () =>
  new Promise((resolve) => {
    const s = connect({ host: "192.0.2.10", port: 443 });
    const timer = setTimeout(() => {
      s.destroy();
      resolve("ETIMEDOUT");
    }, 5000);
    s.once("error", (e) => {
      clearTimeout(timer);
      resolve(e.code);
    });
    s.once("connect", () => {
      clearTimeout(timer);
      s.destroy();
      resolve("CONNECTED");
    });
  });

async function main() {
  const queue = [];
  const waiters = [];
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    if (!line.startsWith(`${TAG} `)) return;
    const w = waiters.shift();
    if (w) w(line);
    else queue.push(line);
  });
  rl.on("close", () => {
    for (const w of waiters.splice(0)) w(null);
  });
  const next = () => (queue.length > 0 ? Promise.resolve(queue.shift()) : new Promise((r) => waiters.push(r)));
  const send = (words) => process.stdout.write(`${TAG} ${words}\n`);
  const ask = async (words) => {
    send(words);
    const reply = await next();
    if (reply === null || !new RegExp(`^${TAG} ACK [1-9][0-9]*$`).test(reply))
      throw new Error(`the observer answered ${reply} to ${words}`);
  };

  const ready = await next();
  if (ready === null || !new RegExp(`^${TAG} READY [0-9a-f]{16} [a-z0-9_]+ [0-9a-f-]+ SELF_TEST$`).test(ready)) {
    console.error(`not started by the observer's self-test (${ready})`);
    process.exit(2);
  }
  await ask(`HELLO ${"0".repeat(40)} self-test`);
  await ask("PHASE PROBES_BEFORE_BEGIN");
  console.error(`probe before: ${await probe()}`);
  await ask("PHASE PROBES_BEFORE_END");
  await ask("PHASE GATE_BEGIN");
  await ask("PHASE HOST_SPAWN");
  const child = spawn(process.execPath, ["-e", HOST_CODE], { stdio: ["ignore", "ignore", "inherit"] });
  await new Promise((r) => child.once("exit", r));
  await ask("PHASE HOST_EXIT");
  await ask("PHASE GATE_END");
  await ask("PHASE PROBES_AFTER_BEGIN");
  console.error(`probe after: ${await probe()}`);
  await ask("PHASE PROBES_AFTER_END");
  send("DONE");
  const stopped = await next();
  console.error(stopped);
  const m = stopped === null ? null : new RegExp(`^${TAG} STOPPED ([0-9a-f]{64}) (/\\S+)$`).exec(stopped);
  if (m === null) process.exit(1);
  // As the attributed tool does after a proof, as this unprivileged user: read the raw evidence the observer names,
  // and find the manifest it bound (a raw directory this user cannot read would lose a real run's observation).
  const manifest = readFileSync(join(m[2], "manifest.json"));
  if (createHash("sha256").update(manifest).digest("hex") !== m[1]) {
    console.error("the raw manifest is not the one the observer named");
    process.exit(3);
  }
  console.error("raw evidence readable by the workload's user");
  process.exit(0);
}

const self = fileURLToPath(import.meta.url);
let isMain = false;
try {
  isMain = process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(self);
} catch {
  isMain = false;
}
if (isMain) await main();
