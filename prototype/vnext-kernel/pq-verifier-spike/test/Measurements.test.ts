/**
 * GEN2-PQ-CONFORMANCE-1 — gas, size and transaction-constraint measurements on the local simulated EVM.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. Every number here is a LOCAL figure: Hardhat 3 EDR under Osaka
 * rules (EIP-7825 per-transaction gas cap 16,777,216 enforced), the pinned solc 0.8.30 build, no L1 data fee,
 * no base fee. Base-specific economics stay UNKNOWN until measured on a Base fork or network. The figures are
 * deterministic for these bytes on this EVM, so the committed record (results/measurements.json) must be
 * reproduced exactly by every run.
 */
import { expect } from "chai";
import { byteLength } from "../lib/compile.js";
import {
  TX_GAS_CAP,
  accounts,
  createWorld,
  loadFixture,
  readResults,
  rpc,
  toolchainRecord,
  with0x,
  writeResults,
  type World,
} from "../lib/world.js";

interface GeneratedFixture {
  keys: { i: number; seed: string; pk: string }[];
  vectors: { id: number; family: string; source: string; pk: string; msg: string; sig: string; expected: boolean | "BADLEN" }[];
}

const stats = (xs: number[]): { n: number; min: number; max: number; mean: number } => ({ n: xs.length, min: Math.min(...xs), max: Math.max(...xs), mean: Math.round(xs.reduce((a, b) => a + b, 0) / xs.length) });

describe("pq-verifier-spike — measurements (local EVM only; Base economics UNKNOWN)", function () {
  this.timeout(1_800_000);
  let world: World;
  const gen = loadFixture<GeneratedFixture>("generated-vectors.json");
  const valid = gen.vectors.filter((v) => v.family === "digest32_valid");
  const record: Record<string, unknown> = {};

  before(async function () {
    world = await createWorld();
  });

  it("code sizes and deployment gas: helper, verifier, probe", async function () {
    record.code = {
      helperRuntimeBytes: world.helper.runtimeBytes,
      helperDeployGas: world.helper.gasUsed,
      verifierRuntimeBytes: world.verifier.runtimeBytes,
      verifierEip170Headroom: 24_576 - world.verifier.runtimeBytes,
      verifierDeployGas: world.verifier.gasUsed,
      verifierCreationBytes: byteLength(world.compiled.bytecode),
      probeRuntimeBytes: world.probe.runtimeBytes,
      probeDeployGas: world.probe.gasUsed,
    };
    expect(world.verifier.runtimeBytes).to.be.at.most(24_576);
    expect(world.verifier.gasUsed).to.be.at.most(TX_GAS_CAP);
    console.log("[code]", JSON.stringify(record.code));
  });

  it("key publication (setKey): two SSTORE2 halves of 20,160 bytes each, transaction gas and calldata", async function () {
    const pub: { pk: string; gasUsed: number; estimate: number; handle: string }[] = [];
    for (const k of gen.keys) {
      const p = await world.publish(k.pk);
      pub.push({ pk: k.pk.slice(0, 16) + "…", ...p });
    }
    const half0 = await rpc<string>("eth_getCode", ["0x" + pub[0]!.handle.slice(2, 42), "latest"]);
    const half1 = await rpc<string>("eth_getCode", ["0x" + pub[0]!.handle.slice(42, 82), "latest"]);
    record.setKey = {
      keys: pub.length,
      gasUsed: stats(pub.map((p) => p.gasUsed)),
      estimateGas: stats(pub.map((p) => p.estimate)),
      calldataBytes: 4 + 64 + 40_320,
      halfCodeBytes: [byteLength(half0), byteLength(half1)],
      halfPrefix: half0.slice(0, 4),
      note: "two CREATEs of 20,161 bytes (0x00 STOP prefix + 20,160 data bytes) inside one transaction; the 40-byte handle is the two addresses",
    };
    expect(byteLength(half0)).to.equal(20_161);
    expect(byteLength(half1)).to.equal(20_161);
    expect(half0.slice(0, 4)).to.equal("0x00");
    for (const p of pub) expect(p.gasUsed).to.be.at.most(TX_GAS_CAP);
    console.log("[setKey]", JSON.stringify(record.setKey));
  });

  it("verification: callee gas inside the call for the 32 WalletWall-shaped valid vectors, and direct transaction estimates with their calldata", async function () {
    const inside: number[] = [];
    for (const v of valid) {
      const h = (await world.publish(v.pk)).handle;
      const r = await world.try32(h, v.msg, v.sig);
      expect(r.outcome).to.equal("ACCEPT");
      inside.push(r.gas);
    }
    const direct: { estimate: number | string; calldataBytes: number }[] = [];
    for (const v of valid.slice(0, 6)) {
      const h = (await world.publish(v.pk)).handle;
      direct.push(await world.estimateDirect32(h, v.msg, v.sig));
    }
    record.verify32 = {
      insideCallGas: stats(inside),
      directTxEstimate: stats(direct.map((d) => d.estimate as number)),
      directTxCalldataBytes: direct[0]!.calldataBytes,
      note: "inside-call gas = the verifier's consumption in a STATICCALL from the probe; the direct estimate adds the 21,000 base and calldata (3,556 bytes: selector, three heads, a 40-byte handle, a 32-byte digest, a 3,309-byte signature)",
    };
    expect(direct.every((d) => typeof d.estimate === "number")).to.equal(true);
    console.log("[verify32]", JSON.stringify(record.verify32));
  });

  it("k verifications in one call (k = 1..10): callee gas, transaction estimate, and the EIP-7825 cap decides which k fit in one transaction", async function () {
    const distinct = gen.keys.map((k) => valid.find((v) => v.pk === k.pk)!);
    const rows: { k: number; accepted: number; gasInsideLoop: number; estimateGas: number | string; calldataBytes: number; fitsTxCap: boolean | null }[] = [];
    for (let k = 1; k <= 10; k++) {
      const vs = Array.from({ length: k }, (_, i) => distinct[i % distinct.length]!);
      const handles: string[] = [];
      for (const v of vs) handles.push((await world.publish(v.pk)).handle);
      const r = await world.tryK(handles, vs.map((v) => v.msg), vs.map((v) => v.sig));
      expect(r.accepted).to.equal(k);
      rows.push({ k, accepted: r.accepted, gasInsideLoop: r.gas, estimateGas: r.estimate, calldataBytes: r.calldataBytes, fitsTxCap: typeof r.estimate === "number" ? r.estimate <= TX_GAS_CAP : null });
    }
    // the largest k whose estimate fits is sent as a real transaction at exactly the cap; the next k is refused by the node
    const fits = rows.filter((r) => r.fitsTxCap === true);
    const largest = fits[fits.length - 1]!;
    const [from] = await accounts();
    const vs = Array.from({ length: largest.k }, (_, i) => distinct[i % distinct.length]!);
    const handles: string[] = [];
    for (const v of vs) handles.push((await world.publish(v.pk)).handle);
    const data = world.probeContract.interface.encodeFunctionData("tryK", [world.verifier.address, handles, vs.map((v) => with0x(v.msg)), vs.map((v) => with0x(v.sig))]);
    const txHash = await rpc<string>("eth_sendTransaction", [{ from, to: world.probe.address, data, gas: "0x" + TX_GAS_CAP.toString(16) }]);
    const receipt = await rpc<{ status: string; gasUsed: string }>("eth_getTransactionReceipt", [txHash]);
    expect(receipt.status).to.equal("0x1");
    let overCapError = "";
    try {
      await rpc("eth_sendTransaction", [{ from, to: world.probe.address, data, gas: "0x" + (TX_GAS_CAP + 1).toString(16) }]);
    } catch (e) {
      overCapError = String((e as Error).message);
    }
    expect(overCapError, "a transaction above the EIP-7825 cap is refused by the node").to.match(/gas cap|16777216/);
    record.quorum = {
      txGasCap: TX_GAS_CAP,
      rows,
      largestKInOneTransaction: { k: largest.k, gasUsedAtCap: Number(receipt.gasUsed) },
      overCapRefusal: overCapError.slice(0, 160),
      note: "k distinct-key verifications in one STATICCALL loop; keys repeat beyond 8. A k-member admissible set that must verify ALL members in one transaction is bounded by the row where fitsTxCap turns false",
    };
    console.log("[quorum]", JSON.stringify(record.quorum));
  });

  it("refusal costs: what a kernel pays when the verifier says no", async function () {
    const h = (await world.publish(gen.keys[0]!.pk)).handle;
    const v0 = valid.find((v) => v.pk === gen.keys[0]!.pk)!;
    const neg = gen.vectors.filter((v) => v.family === "digest32_negative");
    const rows: { case: string; outcome: string; detail: string; gas: number }[] = [];
    for (const v of neg) {
      const hh = (await world.publish(v.pk)).handle;
      const r = await world.try32(hh, v.msg, v.sig);
      rows.push({ case: v.source, outcome: r.outcome, detail: r.detail, gas: r.gas });
    }
    const zero = await world.try32("0x" + "00".repeat(40), v0.msg, v0.sig);
    rows.push({ case: "handle of 40 zero bytes", outcome: zero.outcome, detail: zero.detail, gas: zero.gas });
    const boundary = gen.vectors.filter((v) => v.family === "znorm_boundary");
    for (const v of boundary) {
      const r = await world.try32(h === "" ? h : (await world.publish(v.pk)).handle, v.msg, v.sig);
      rows.push({ case: v.source, outcome: r.outcome, detail: r.detail, gas: r.gas });
    }
    record.refusals = rows;
    console.log("[refusals]", JSON.stringify(rows));
  });

  it("records the measurements (results/measurements.json) and reproduces the committed record exactly", async function () {
    const full = { schema: "gen2-pq-conformance-1/measurements.v1", comparable: record, environment: await toolchainRecord() };
    writeResults("measurements.json", full);
    const committed = readResults<typeof full>("measurements.json");
    if (committed) expect(record).to.deep.equal(committed.comparable);
    else this.skip();
  });
});
