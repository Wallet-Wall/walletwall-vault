/**
 * GEN2-PQ-CONFORMANCE-1 — the world every spike suite drives: one simulated EVM (Hardhat 3 EDR, Osaka rules),
 * the pinned Keccak-f[1600] helper deployed from its vendored bytes, the vendored ML-DSA-65 verifier compiled
 * by `compile.ts`, and the SpikeProbe harness. Verdicts are reported as what the verifier returned, never as
 * an interpretation: ACCEPT (the ERC-7913 selector / `true`), REJECT (`0xFFFFFFFF` / `false`),
 * REVERT (named custom error) or UNEXPECTED.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION · NOT CONNECTED TO ANY KERNEL.
 */
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { network } from "hardhat";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { compileVendoredVerifier, SPIKE_DIR, VENDOR_DIR, byteLength, type CompiledVerifier } from "./compile.js";
import { expandPublicKey65, encodePublicKeyBlob65 } from "../vendor/zknox-ethdilithium-4c370bb5/js/mldsa65.js";

const connection = await network.create();
export const ethers = connection.ethers;
export const provider = connection.provider;
export const rpc = <T = unknown>(method: string, params: unknown[] = []): Promise<T> =>
  provider.request({ method, params }) as Promise<T>;

export const HELPER_HEX_PATH = path.join(
  VENDOR_DIR,
  "fireblocks-evm-ml-dsa-verifier-cca262b5",
  "helpers",
  "f1600_170.hex",
);
export const FIXTURES_DIR = path.join(SPIKE_DIR, "fixtures");
export const RESULTS_DIR = path.join(SPIKE_DIR, "results");

export const hex = (u8: Uint8Array | Buffer): string => Buffer.from(u8).toString("hex");
export const unhex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
export const with0x = (h: string): string => (h.startsWith("0x") ? h : "0x" + h);
export const sha256 = (data: Uint8Array | Buffer | string): string => createHash("sha256").update(data).digest("hex");
export const keccakHex = (data: Uint8Array | Buffer): string => "0x" + hex(keccak_256(data));

export const loadFixture = <T>(name: string): T =>
  JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8")) as T;

/** Write a results record when SPIKE_WRITE_RESULTS=1 (the committed records were produced this way). */
export function writeResults(name: string, data: unknown): boolean {
  if (process.env.SPIKE_WRITE_RESULTS !== "1") return false;
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(RESULTS_DIR, name), JSON.stringify(data, null, 1) + "\n");
  return true;
}
export const readResults = <T>(name: string): T | null => {
  const p = path.join(RESULTS_DIR, name);
  return fs.existsSync(p) ? (JSON.parse(fs.readFileSync(p, "utf8")) as T) : null;
};

// ---------------------------------------------------------------- raw deployments
export async function accounts(): Promise<string[]> {
  return rpc<string[]>("eth_accounts");
}

export interface Receipt {
  status: string;
  gasUsed: string;
  contractAddress: string | null;
  transactionHash: string;
}

/** EIP-7825 (Osaka): a transaction may not carry more than 16,777,216 gas; the simulated EVM enforces it. */
export const TX_GAS_CAP = 16_777_216;

export async function sendTx(tx: { to?: string; data: string; gas?: number; from?: string }): Promise<Receipt> {
  const [from] = await accounts();
  const h = await rpc<string>("eth_sendTransaction", [
    { from: tx.from ?? from, to: tx.to, data: tx.data, gas: "0x" + (tx.gas ?? TX_GAS_CAP).toString(16) },
  ]);
  const r = await rpc<Receipt | null>("eth_getTransactionReceipt", [h]);
  if (!r || r.status !== "0x1") throw new Error(`transaction failed: ${JSON.stringify(r)}`);
  return r;
}

/**
 * The intrinsic gas of a transaction carrying `dataHex`: 21,000 plus 4 per zero byte and 16 per non-zero byte
 * (EIP-2028). Addresses inside calldata have a run-dependent number of zero bytes, so a transaction's total gas
 * differs by a few units between runs; subtracting the intrinsic part leaves the execution gas, which does not.
 * (EIP-7623's calldata floor never binds here: every measured transaction executes far more than its floor.)
 */
export function intrinsicGas(dataHex: string): number {
  const bytes = unhex(dataHex);
  let g = 21_000;
  for (const b of bytes) g += b === 0 ? 4 : 16;
  return g;
}

/** initcode that returns `runtime` verbatim: PUSH2 len, DUP1, PUSH1 0x0c, PUSH1 0, CODECOPY, PUSH1 0, RETURN, runtime */
export const rawInitcode = (runtimeHex: string): string => {
  const rt = runtimeHex.replace(/^0x/, "");
  return "0x61" + (rt.length / 2).toString(16).padStart(4, "0") + "80600c6000396000f3" + rt;
};

export async function deployRaw(runtimeHex: string): Promise<{ address: string; gasUsed: number; code: string }> {
  const r = await sendTx({ data: rawInitcode(runtimeHex) });
  const code = await rpc<string>("eth_getCode", [r.contractAddress, "latest"]);
  return { address: r.contractAddress as string, gasUsed: Number(r.gasUsed), code };
}

export const helperRuntimeHex = (): string => "0x" + fs.readFileSync(HELPER_HEX_PATH, "utf8").trim().replace(/^0x/, "");

/** The F1600_CODEHASH constant, read from the vendored verifier source rather than retyped. */
export function pinnedHelperCodehash(): string {
  const src = fs.readFileSync(
    path.join(VENDOR_DIR, "zknox-ethdilithium-4c370bb5", "src", "ZKNOX_dilithium65.sol"),
    "utf8",
  );
  const m = src.match(/F1600_CODEHASH = (0x[0-9a-f]{64});/);
  if (!m) throw new Error("F1600_CODEHASH not found in the vendored verifier source");
  return m[1]!;
}

// ---------------------------------------------------------------- the world
export type Outcome = "ACCEPT" | "REJECT" | "REVERT" | "UNEXPECTED";
export interface Verdict {
  outcome: Outcome;
  /** custom error name on REVERT, raw selector on UNEXPECTED */
  detail: string;
  /** gasleft() delta around the probe's STATICCALL: the verifier's consumption plus the call opcode itself (~0.2 %) */
  gas: number;
  raw: string;
}

export interface World {
  compiled: CompiledVerifier;
  helper: { address: string; gasUsed: number; runtimeBytes: number; codehash: string };
  verifier: { address: string; gasUsed: number; runtimeBytes: number; codehash: string; code: string };
  probe: { address: string; gasUsed: number; runtimeBytes: number };
  verifierContract: InstanceType<typeof ethers.Contract>;
  probeContract: InstanceType<typeof ethers.Contract>;
  sel32: string;
  selCtx: string;
  /** expand a FIPS 204 public key (hex, 1,952 bytes) to the setKey argument (hex, 40,320 bytes); cached */
  blobFor(pkHex: string): string;
  /** publish a key through setKey; returns the 40-byte handle and the transaction gas; cached per pk */
  publish(pkHex: string): Promise<{ handle: string; gasUsed: number; estimate: number }>;
  /** publish an already-expanded blob (the exact setKey argument) through setKey; not cached */
  publishBlob(blobHex: string): Promise<{ handle: string; gasUsed: number; estimate: number }>;
  /** verify(bytes,bytes32,bytes) through the probe */
  try32(handle: string, digestHex: string, sigHex: string): Promise<Verdict>;
  /** verify(bytes,bytes,bytes,bytes) through the probe */
  tryCtx(handle: string, msgHex: string, sigHex: string, ctxHex: string): Promise<Verdict>;
  /** k verifications in one probe call */
  tryK(
    handles: string[],
    digests: string[],
    sigs: string[],
  ): Promise<{
    accepted: number;
    gas: number;
    calldataBytes: number;
    estimate: number | string;
    intrinsic: number;
    data: string;
  }>;
  estimateDirect32(
    handle: string,
    digestHex: string,
    sigHex: string,
  ): Promise<{ estimate: number | string; calldataBytes: number; intrinsic: number }>;
}

const blobCache = new Map<string, string>();
export function expandToBlob(pkHex: string): string {
  const key = pkHex.replace(/^0x/, "").toLowerCase();
  const hit = blobCache.get(key);
  if (hit) return hit;
  const expanded = expandPublicKey65(unhex(key));
  const { setKeyData } = encodePublicKeyBlob65(expanded);
  const blob = with0x(setKeyData.toLowerCase());
  blobCache.set(key, blob);
  return blob;
}

export function nobleVerdict(sigHex: string, msgHex: string, pkHex: string, ctxHex = ""): boolean | "THROW" {
  try {
    return ml_dsa65.verify(unhex(sigHex), unhex(msgHex), unhex(pkHex), { context: unhex(ctxHex) });
  } catch {
    return "THROW";
  }
}

export async function createWorld(): Promise<World> {
  const compiled = compileVendoredVerifier();
  const [from] = await accounts();
  const signer = await ethers.getSigner(from!);

  const helperDeploy = await deployRaw(helperRuntimeHex());
  const helper = {
    address: helperDeploy.address,
    gasUsed: helperDeploy.gasUsed,
    runtimeBytes: byteLength(helperDeploy.code),
    codehash: keccakHex(unhex(helperDeploy.code)),
  };

  const factory = new ethers.ContractFactory(compiled.abi as never, compiled.bytecode, signer);
  const deployed = await factory.deploy(helper.address);
  const deployTx = deployed.deploymentTransaction();
  if (!deployTx) throw new Error("no deployment transaction");
  const deployReceipt = await deployTx.wait();
  if (!deployReceipt) throw new Error("no deployment receipt");
  const verifierAddress = await deployed.getAddress();
  const verifierCode = await rpc<string>("eth_getCode", [verifierAddress, "latest"]);
  const verifierContract = new ethers.Contract(verifierAddress, compiled.abi as never, signer);
  const verifier = {
    address: verifierAddress,
    gasUsed: Number(deployReceipt.gasUsed),
    runtimeBytes: byteLength(verifierCode),
    codehash: keccakHex(unhex(verifierCode)),
    code: verifierCode,
  };

  const probeContract = await ethers.deployContract("SpikeProbe", [], signer);
  const probeReceipt = await probeContract.deploymentTransaction()!.wait();
  const probeAddress = await probeContract.getAddress();
  const probeCode = await rpc<string>("eth_getCode", [probeAddress, "latest"]);
  const probe = { address: probeAddress, gasUsed: Number(probeReceipt!.gasUsed), runtimeBytes: byteLength(probeCode) };

  const iface = verifierContract.interface;
  const sel32 = iface.getFunction("verify(bytes,bytes32,bytes)")!.selector;
  const selCtx = iface.getFunction("verify(bytes,bytes,bytes,bytes)")!.selector;

  const decodeRevert = (raw: string): string => {
    try {
      const parsed = iface.parseError(raw);
      return parsed ? parsed.name : raw.slice(0, 10);
    } catch {
      return raw.slice(0, 10);
    }
  };

  const handles = new Map<string, { handle: string; gasUsed: number; estimate: number }>();

  const world: World = {
    compiled,
    helper,
    verifier,
    probe,
    verifierContract,
    probeContract,
    sel32,
    selCtx,
    blobFor: expandToBlob,
    async publishBlob(blobHex) {
      const blob = with0x(blobHex.toLowerCase());
      const data = iface.encodeFunctionData("setKey", [blob]);
      const estimate = Number(await rpc<string>("eth_estimateGas", [{ from, to: verifierAddress, data }]));
      const handle = (await verifierContract.getFunction("setKey").staticCall(blob)) as string;
      const receipt = await sendTx({ to: verifierAddress, data, gas: 16_000_000 });
      return { handle: handle.toLowerCase(), gasUsed: Number(receipt.gasUsed), estimate };
    },
    async publish(pkHex) {
      const key = pkHex.replace(/^0x/, "").toLowerCase();
      const hit = handles.get(key);
      if (hit) return hit;
      const rec = await world.publishBlob(expandToBlob(key));
      handles.set(key, rec);
      return rec;
    },
    async try32(handle, digestHex, sigHex) {
      const [success, ret, gas] = (await probeContract
        .getFunction("try32")
        .staticCall(verifierAddress, handle, with0x(digestHex), with0x(sigHex))) as [boolean, string, bigint];
      if (!success) return { outcome: "REVERT", detail: decodeRevert(ret), gas: Number(gas), raw: ret };
      const sel = ret.slice(0, 10);
      if (sel === sel32 && ret.length === 66) return { outcome: "ACCEPT", detail: sel, gas: Number(gas), raw: ret };
      if (sel === "0xffffffff" && ret.length === 66)
        return { outcome: "REJECT", detail: sel, gas: Number(gas), raw: ret };
      return { outcome: "UNEXPECTED", detail: sel, gas: Number(gas), raw: ret };
    },
    async tryCtx(handle, msgHex, sigHex, ctxHex) {
      const [success, ret, gas] = (await probeContract
        .getFunction("tryCtx")
        .staticCall(verifierAddress, handle, with0x(msgHex), with0x(sigHex), with0x(ctxHex))) as [
        boolean,
        string,
        bigint,
      ];
      if (!success) return { outcome: "REVERT", detail: decodeRevert(ret), gas: Number(gas), raw: ret };
      if (ret.length !== 66) return { outcome: "UNEXPECTED", detail: ret.slice(0, 10), gas: Number(gas), raw: ret };
      const [ok] = ethers.AbiCoder.defaultAbiCoder().decode(["bool"], ret) as unknown as [boolean];
      return { outcome: ok ? "ACCEPT" : "REJECT", detail: ok ? "true" : "false", gas: Number(gas), raw: ret };
    },
    async tryK(hs, digests, sigs) {
      const data = probeContract.interface.encodeFunctionData("tryK", [
        verifierAddress,
        hs,
        digests.map(with0x),
        sigs.map(with0x),
      ]);
      const [accepted, gas] = (await probeContract
        .getFunction("tryK")
        .staticCall(verifierAddress, hs, digests.map(with0x), sigs.map(with0x))) as [bigint, bigint];
      let estimate: number | string;
      try {
        estimate = Number(await rpc<string>("eth_estimateGas", [{ from, to: probeAddress, data }]));
      } catch (e) {
        estimate = `ESTIMATE_FAILED: ${String((e as Error).message).slice(0, 120)}`;
      }
      return {
        accepted: Number(accepted),
        gas: Number(gas),
        calldataBytes: byteLength(data),
        estimate,
        intrinsic: intrinsicGas(data),
        data,
      };
    },
    async estimateDirect32(handle, digestHex, sigHex) {
      const data = iface.encodeFunctionData("verify(bytes,bytes32,bytes)", [handle, with0x(digestHex), with0x(sigHex)]);
      let estimate: number | string;
      try {
        estimate = Number(await rpc<string>("eth_estimateGas", [{ from, to: verifierAddress, data }]));
      } catch (e) {
        estimate = `ESTIMATE_FAILED: ${String((e as Error).message).slice(0, 120)}`;
      }
      return { estimate, calldataBytes: byteLength(data), intrinsic: intrinsicGas(data) };
    },
  };
  return world;
}

/** Environment facts recorded beside every measurement. */
export async function toolchainRecord(): Promise<Record<string, unknown>> {
  const pkg = (name: string): string => {
    try {
      return (
        JSON.parse(
          fs.readFileSync(path.join(SPIKE_DIR, "..", "..", "..", "node_modules", name, "package.json"), "utf8"),
        ) as { version: string }
      ).version;
    } catch {
      return "unknown";
    }
  };
  const chainId = await rpc<string>("eth_chainId");
  return {
    hardhat: pkg("hardhat"),
    edr: pkg("@nomicfoundation/edr"),
    ethers: pkg("ethers"),
    noblePostQuantum: pkg("@noble/post-quantum"),
    nobleHashes: pkg("@noble/hashes"),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    chainId: Number(chainId),
    hardfork: "osaka (hardhat.config.ts of this spike)",
  };
}
