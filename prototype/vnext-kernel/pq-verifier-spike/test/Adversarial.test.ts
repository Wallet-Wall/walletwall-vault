/**
 * GEN2-PQ-CONFORMANCE-1 — adversarial challenges against the vendored ML-DSA-65 verifier.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION. Each test records what the verifier DOES with a hostile or
 * malformed input; where the behaviour is a finding (something a kernel adapter, a key publisher or a
 * registration gate must handle because the verifier does not), the test asserts the finding and UNRESOLVED.md
 * carries it. Nothing here proves the absence of other weaknesses.
 *
 * Challenges: substituted and malformed 40-byte handles; expanded-key blobs built outside setKey and blobs with
 * a flipped byte; degenerate (t1 = 0) keys forged without any secret key; malformed signatures; malformed public
 * keys at expansion; helper code replaced at the bound address; the raw permutation and the batched sponge
 * against an independent Keccak implementation; the 800-byte preimage routing of shake256Any.
 */
import { expect } from "chai";
import { keccakP, shake256 } from "@noble/hashes/sha3.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { expandPublicKey65 } from "../vendor/zknox-ethdilithium-4c370bb5/js/mldsa65.js";
import {
  createWorld,
  deployRaw,
  expandToBlob,
  hex,
  loadFixture,
  nobleVerdict,
  readResults,
  rpc,
  toolchainRecord,
  unhex,
  with0x,
  writeResults,
  type Verdict,
  type World,
} from "../lib/world.js";

interface GeneratedFixture {
  keys: { i: number; seed: string; pk: string }[];
  vectors: { id: number; family: string; source: string; pk: string; msg: string; sig: string; expected: boolean | "BADLEN" }[];
}

const GAMMA1 = 1 << 19;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const strip = (h: string): string => h.replace(/^0x/, "").toLowerCase();

interface Finding {
  challenge: string;
  input: string;
  outcome: Verdict["outcome"] | string;
  detail: string;
  gas: number | null;
  finding: string;
}

describe("pq-verifier-spike — adversarial challenges (what the verifier does NOT protect against is recorded as a finding)", function () {
  this.timeout(1_800_000);
  let world: World;
  const findings: Finding[] = [];
  const gen = loadFixture<GeneratedFixture>("generated-vectors.json");
  const key0 = gen.keys[0]!;
  const key1 = gen.keys[1]!;
  let sk0: Uint8Array;
  let handle0: string;
  let handle1: string;
  let digest0: string;
  let sig0: string;

  const note = (f: Finding): void => {
    findings.push(f);
    console.log(`[${f.outcome}] ${f.challenge} :: ${f.detail} :: ${f.finding}`);
  };

  before(async function () {
    world = await createWorld();
    const k = ml_dsa65.keygen(unhex(key0.seed));
    expect(hex(k.publicKey)).to.equal(key0.pk);
    sk0 = k.secretKey;
    handle0 = (await world.publish(key0.pk)).handle;
    handle1 = (await world.publish(key1.pk)).handle;
    const valid = gen.vectors.find((v) => v.family === "digest32_valid" && v.pk === key0.pk)!;
    digest0 = valid.msg;
    sig0 = valid.sig;
    expect((await world.try32(handle0, digest0, sig0)).outcome).to.equal("ACCEPT");
  });

  it("handles: no substituted, truncated or foreign handle is ACCEPTED for a signature valid under the genuine key; trailing handle bytes are ignored (finding)", async function () {
    const junk = await deployRaw("00" + "ab".repeat(999));
    const eoa = "0x00000000000000000000000000000000000000ee";
    const half0 = handle0.slice(2, 42);
    const half1 = handle0.slice(42, 82);
    const other0 = handle1.slice(2, 42);
    const cases: [string, string, string][] = [
      ["40 zero bytes", "0x" + "00".repeat(40), "pointers without code"],
      ["two pointers to the probe (code of another shape)", world.probe.address + world.probe.address.slice(2), "non-key code"],
      ["two pointers to a 1,000-byte data contract", junk.address + junk.address.slice(2), "short blob"],
      ["two pointers to an address without code", eoa + eoa.slice(2), "no code"],
      ["genuine halves swapped", "0x" + half1 + half0, "wrong row order"],
      ["half0 of key 0 with half1 of key 1", "0x" + half0 + handle1.slice(42, 82), "hybrid key"],
      ["half0 of key 1 with half1 of key 0", "0x" + other0 + half1, "hybrid key"],
      ["39-byte handle (last byte dropped)", "0x" + handle0.slice(2, 80), "truncated"],
      ["20-byte handle (one pointer)", "0x" + half0, "truncated"],
      ["empty handle", "0x", "empty"],
      ["41-byte handle (genuine plus a trailing byte)", handle0 + "ff", "trailing byte"],
      ["72-byte handle (genuine plus 32 trailing bytes)", handle0 + "ff".repeat(32), "trailing bytes"],
    ];
    for (const [name, h, kind] of cases) {
      const v = await world.try32(h, digest0, sig0);
      const trailing = kind.startsWith("trailing");
      note({
        challenge: `handle: ${name}`,
        input: h.length > 90 ? h.slice(0, 90) + "…" : h,
        outcome: v.outcome,
        detail: v.detail,
        gas: v.gas,
        finding: trailing
          ? "the verifier reads only the first 40 bytes of `pk`; bytes beyond are ignored, so distinct handle encodings name one key: an adapter MUST enforce exactly 40 bytes before committing to keccak(handle)"
          : "no substituted or malformed handle verifies the genuine signature",
      });
      if (trailing) expect(v.outcome, name).to.equal("ACCEPT");
      else expect(v.outcome, name).to.not.equal("ACCEPT");
    }
  });

  it("blobs: a blob deployed outside setKey is indistinguishable from a published one; a flipped blob byte silently changes the verdict (finding: the verifier binds a handle to nothing)", async function () {
    const blob = strip(expandToBlob(key0.pk));
    const h0 = blob.slice(0, 20_160 * 2);
    const h1 = blob.slice(20_160 * 2);
    // SSTORE2 stores data behind a leading STOP byte (0x00) so the blob can never execute
    const raw0 = await deployRaw("00" + h0);
    const raw1 = await deployRaw("00" + h1);
    const rawHandle = raw0.address + raw1.address.slice(2);
    const v = await world.try32(rawHandle, digest0, sig0);
    note({ challenge: "blob: both halves deployed by a plain CREATE outside setKey, same bytes", input: rawHandle, outcome: v.outcome, detail: v.detail, gas: v.gas, finding: "setKey adds nothing the verifier later checks: any address pair holding the right bytes is a key, so handle-to-key binding must come from a publisher the kernel can audit (PUBLISHER_BINDING.md)" });
    expect(v.outcome).to.equal("ACCEPT");
    expect(await rpc<string>("eth_getCode", [raw0.address, "latest"])).to.equal(await rpc<string>("eth_getCode", ["0x" + handle0.slice(2, 42), "latest"]));

    // A census of single-byte flips in half 0, placed by CONTENT (the half is abi.encode(bytes aHat, bytes tr,
    // bytes t1); the reader follows the ABI offsets with bounds checks and never reads some framing words).
    const expanded = expandPublicKey65(unhex(key0.pk));
    const word = (v: bigint): string => v.toString(16).padStart(64, "0");
    const aPos = h0.indexOf(word(expanded.aHat[0]![0]![0]!)) / 2;
    const trPos = h0.indexOf(hex(expanded.tr)) / 2;
    const t1Pos = h0.indexOf(word(expanded.t1Hat[0]![0]!)) / 2;
    expect(aPos, "aHat[0][0] word 0 located in half 0").to.be.greaterThan(0);
    expect(trPos, "tr located in half 0").to.be.greaterThan(0);
    expect(t1Pos, "t1[0] word 0 located in half 0").to.be.greaterThan(0);
    const census: [string, number, "ACCEPT" | "REJECT" | "NOT_ACCEPT" | "RECORD"][] = [
      ["outer tuple: offset word of element 0, low byte (byte 31)", 31, "NOT_ACCEPT"],
      ["outer tuple: length word of element 0, byte 100 (a framing word the reader never loads)", 100, "ACCEPT"],
      ["aHat[0][0] word 0, byte 3: low byte of field 0 (a coefficient)", aPos + 3, "REJECT"],
      ["aHat[0][0] word 0, byte 31: low byte of field 7 (a coefficient)", aPos + 31, "REJECT"],
      ["aHat[0][0] word 0, byte 0: the padding bits above a 23-bit coefficient in a 32-bit field", aPos, "RECORD"],
      ["tr, byte 10", trPos + 10, "REJECT"],
      ["t1[0] word 0, byte 31: low byte of a coefficient", t1Pos + 31, "REJECT"],
      ["t1[0] word 0, byte 0: padding bits", t1Pos, "RECORD"],
    ];
    const unread: string[] = [];
    for (const [name, offset, expectation] of census) {
      const i = offset * 2;
      const flipped = h0.slice(0, i) + (parseInt(h0.slice(i, i + 2), 16) ^ 0x01).toString(16).padStart(2, "0") + h0.slice(i + 2);
      const d = await deployRaw("00" + flipped);
      const handle = d.address + raw1.address.slice(2);
      const r = await world.try32(handle, digest0, sig0);
      const ignored = r.outcome === "ACCEPT";
      if (ignored) unread.push(name);
      note({
        challenge: `blob: one bit flipped at half-0 byte ${offset} (${name})`,
        input: handle,
        outcome: r.outcome,
        detail: r.detail,
        gas: r.gas,
        finding: ignored
          ? "this byte is never read: two blobs with different code hashes name the same key, so a blob's EXTCODEHASH is not a key identity and a publisher must bind the canonical public key, not the blob bytes"
          : "a corrupted expansion is read as a different key with no integrity error: a wrong blob is silently a wrong key",
      });
      if (expectation === "ACCEPT") expect(r.outcome, name).to.equal("ACCEPT");
      else if (expectation === "REJECT") expect(r.outcome, name).to.equal("REJECT");
      else if (expectation === "NOT_ACCEPT") expect(r.outcome, name).to.not.equal("ACCEPT");
    }
    expect(unread.length, "at least one blob byte is unread by the verifier (the finding)").to.be.greaterThan(0);
  });

  it("degenerate keys: t1 = 0 keys are forgeable without any secret, and the verifier (like FIPS 204 and @noble) ACCEPTS the forgery (finding: registration must refuse them)", async function () {
    for (const label of ["degenerate rho A", "degenerate rho B"]) {
      const rho = shake256(utf8(`GEN2-PQ-CONFORMANCE-1 ${label}`), { dkLen: 32 });
      const pk = new Uint8Array(1952);
      pk.set(rho, 0);
      const m = shake256(utf8(`forged digest for ${label}`), { dkLen: 32 });
      const tr = shake256(pk, { dkLen: 64 });
      const mu = shake256(new Uint8Array([...tr, 0, 0, ...m]), { dkLen: 64 });
      const cTilde = shake256(new Uint8Array([...mu, ...new Uint8Array(768)]), { dkLen: 48 });
      const z = new Uint8Array(3200);
      for (let p = 0; p < 5; p++) {
        let r = 0n;
        for (let j = 0; j < 256; j++) r |= BigInt(GAMMA1) << BigInt(20 * j);
        for (let i = 0; i < 640; i++) z[640 * p + i] = Number((r >> BigInt(8 * i)) & 0xffn);
      }
      const sig = new Uint8Array([...cTilde, ...z, ...new Uint8Array(61)]);
      const handle = (await world.publish(hex(pk))).handle;
      const v = await world.try32(handle, hex(m), hex(sig));
      const noble = nobleVerdict(hex(sig), hex(m), hex(pk));
      note({ challenge: `degenerate key (${label}): pk = rho || 0^1920, sigma = c~ || zEncode(0) || 0^61`, input: hex(pk).slice(0, 64) + "…", outcome: v.outcome, detail: `${v.detail}; noble=${String(noble)}`, gas: v.gas, finding: "ML-DSA offers no exclusive ownership: a FIPS-conformant verifier accepts a key-free forgery for a degenerate key. The kernel cannot see t1; a registration gate must refuse pk[32..1952) == 0 (and the client must derive keys from a seed). Subtler degenerate classes are UNKNOWN here." });
      expect(v.outcome).to.equal("ACCEPT");
      expect(noble).to.equal(true);
      // the trivial gate
      expect(pk.slice(32).every((b) => b === 0)).to.equal(true);
    }
    // a genuine key is never all-zero in t1
    expect(unhex(key0.pk).slice(32).some((b) => b !== 0)).to.equal(true);
  });

  it("malformed signatures: wrong lengths are refused cheaply on both entry points; constant signatures are rejected", async function () {
    const cases: [string, string][] = [
      ["empty signature", ""],
      ["3,308 bytes", sig0.slice(0, 3308 * 2)],
      ["3,310 bytes", sig0 + "00"],
      ["4,096 bytes", sig0 + "00".repeat(4096 - 3309)],
      ["3,309 zero bytes", "00".repeat(3309)],
      ["3,309 bytes of 0xff", "ff".repeat(3309)],
    ];
    for (const [name, sig] of cases) {
      const a = await world.try32(handle0, digest0, sig);
      const b = await world.tryCtx(handle0, digest0, sig, "");
      const badLen = sig.length / 2 !== 3309;
      note({ challenge: `signature: ${name}`, input: `${sig.length / 2} bytes`, outcome: `3-arg ${a.outcome} / 4-arg ${b.outcome}`, detail: `3-arg ${a.detail} @ ${a.gas} gas; 4-arg ${b.detail} @ ${b.gas} gas`, gas: a.gas, finding: badLen ? "length is checked first: 0xFFFFFFFF on the ERC-7913 path, InvalidSignatureLength on the context path, both before any key read" : "a constant signature is rejected by the decoder or the final hash" });
      if (badLen) {
        expect(a.outcome).to.equal("REJECT");
        expect(a.gas).to.be.lessThan(10_000);
        expect(b.outcome).to.equal("REVERT");
        expect(b.detail).to.equal("InvalidSignatureLength");
      } else {
        expect(a.outcome).to.equal("REJECT");
        expect(b.outcome).to.equal("REJECT");
      }
    }
  });

  it("malformed public keys never reach the chain: the client expansion refuses 1,951 and 1,953 bytes", function () {
    for (const len of [0, 32, 1951, 1953, 40_320]) {
      let threw = false;
      try {
        expandToBlob("ab".repeat(len));
      } catch {
        threw = true;
      }
      expect(threw, `${len}-byte public key`).to.equal(true);
    }
    note({ challenge: "public key: lengths 0, 32, 1951, 1953, 40320 at expansion", input: "client", outcome: "REFUSED", detail: "expandPublicKey65 throws", gas: null, finding: "the verifier never sees a canonical public key; its only key input is the 40-byte handle, so canonical-key validation is entirely off-chain or in a publisher" });
  });

  it("helper: replacing the code at the bound helper address makes every verification revert BadHelper (the pin is re-checked per call); restoring it restores acceptance", async function () {
    const original = await rpc<string>("eth_getCode", [world.helper.address, "latest"]);
    const probeCode = await rpc<string>("eth_getCode", [world.probe.address, "latest"]);
    await rpc("hardhat_setCode", [world.helper.address, probeCode]);
    const v = await world.try32(handle0, digest0, sig0);
    note({ challenge: "helper: code at the bound address replaced by other code", input: world.helper.address, outcome: v.outcome, detail: v.detail, gas: v.gas, finding: "EXTCODEHASH binding holds: a helper with any other code is refused on every call, so the residual risk is the PROVENANCE of the pinned bytes themselves, not substitution" });
    expect(v.outcome).to.equal("REVERT");
    expect(v.detail).to.equal("BadHelper");
    // an identity permutation (returns its 800-byte input unchanged) also has a different code hash: refused
    const identity = "0x" + "610320600060003760003560003560005260206000f3"; // placeholder bytes with a distinct hash; never executed because the pin fails first
    await rpc("hardhat_setCode", [world.helper.address, identity]);
    const w = await world.try32(handle0, digest0, sig0);
    expect(w.outcome).to.equal("REVERT");
    expect(w.detail).to.equal("BadHelper");
    await rpc("hardhat_setCode", [world.helper.address, original]);
    const r = await world.try32(handle0, digest0, sig0);
    expect(r.outcome).to.equal("ACCEPT");
  });

  it("sponge: the pinned helper's raw permutation and batched SHAKE256 agree with an independent Keccak implementation (@noble/hashes keccakP / shake256)", async function () {
    const probe = world.probeContract;
    const lanesToWords = (state: Uint8Array): bigint[] => {
      const words: bigint[] = [];
      for (let i = 0; i < 25; i++) {
        let v = 0n;
        for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(state[8 * i + b]!);
        words.push(v);
      }
      return words;
    };
    const wordsToState = (words: bigint[]): Uint8Array => {
      const out = new Uint8Array(200);
      words.forEach((v, i) => {
        for (let b = 0; b < 8; b++) out[8 * i + b] = Number((v >> BigInt(8 * b)) & 0xffn);
      });
      return out;
    };
    const nobleF1600 = (state: Uint8Array): Uint8Array => {
      const s = new Uint32Array(50);
      for (let i = 0; i < 50; i++) s[i] = state[4 * i]! | (state[4 * i + 1]! << 8) | (state[4 * i + 2]! << 16) | (state[4 * i + 3]! << 24);
      keccakP(s, 24);
      const out = new Uint8Array(200);
      for (let i = 0; i < 50; i++) {
        out[4 * i] = s[i]! & 0xff;
        out[4 * i + 1] = (s[i]! >>> 8) & 0xff;
        out[4 * i + 2] = (s[i]! >>> 16) & 0xff;
        out[4 * i + 3] = (s[i]! >>> 24) & 0xff;
      }
      return out;
    };
    const states: [string, Uint8Array][] = [["zero state", new Uint8Array(200)], ["all-ones state", new Uint8Array(200).fill(0xff)]];
    for (let i = 0; i < 48; i++) states.push([`random state ${i}`, shake256(utf8(`GEN2-PQ-CONFORMANCE-1 state ${i}`), { dkLen: 200 })]);
    let permGas: number[] = [];
    for (const [name, st] of states) {
      const [ok, ret, gas] = (await probe.getFunction("permute").staticCall(world.helper.address, lanesToWords(st))) as [boolean, string, bigint];
      expect(ok, name).to.equal(true);
      expect(ret.length, name).to.equal(2 + 1600);
      const got = wordsToState(Array.from({ length: 25 }, (_, i) => BigInt("0x" + ret.slice(2 + 64 * i, 2 + 64 * (i + 1)))));
      expect(hex(got), name).to.equal(hex(nobleF1600(st)));
      permGas.push(Number(gas));
    }
    // Keccak-f[1600] of the zero state: first lane F1258F7940E1DDE7 (the standard known answer)
    const zero = nobleF1600(new Uint8Array(200));
    expect(hex(zero.slice(0, 8))).to.equal("e7dde140798f25f1");

    const lengths = [0, 1, 67, 98, 135, 136, 137, 271, 272, 799, 801, 832, 1360];
    for (let i = 0; i < 24; i++) lengths.push(1 + ((i * 7919) % 1500));
    const batchGas: { len: number; gas: number }[] = [];
    for (const len of lengths) {
      if (len === 800) continue;
      const msg = shake256(utf8(`GEN2-PQ-CONFORMANCE-1 message ${len}`), { dkLen: len });
      const [ok, ret, gas] = (await probe.getFunction("shakeBatch").staticCall(world.helper.address, with0x(hex(msg)))) as [boolean, string, bigint];
      expect(ok, `len ${len}`).to.equal(true);
      expect(ret.length, `len ${len}: one rate block`).to.equal(2 + 272);
      expect(ret.slice(2), `len ${len}`).to.equal(hex(shake256(msg, { dkLen: 136 })));
      batchGas.push({ len, gas: Number(gas) });
    }
    note({ challenge: `sponge: ${states.length} raw permutations and ${batchGas.length} batched SHAKE256 messages vs @noble/hashes`, input: "see test", outcome: "AGREE", detail: `permutation gas ${Math.min(...permGas)}..${Math.max(...permGas)}; batch gas ${Math.min(...batchGas.map((b) => b.gas))}..${Math.max(...batchGas.map((b) => b.gas))}`, gas: null, finding: "behavioural agreement with an independent implementation on these inputs; NOT a proof, and no substitute for the lost generator of f1600_core.hex" });
  });

  it("shake256Any routing: a context-path message whose mu preimage is exactly 800 bytes (the batched dispatch collision) still verifies", async function () {
    // mu preimage = tr (64) || 0x00 || len(ctx) || ctx || M; with an empty context, |M| = 734 gives 800 bytes
    for (const mlen of [733, 734, 735]) {
      const m = shake256(utf8(`GEN2-PQ-CONFORMANCE-1 routing ${mlen}`), { dkLen: mlen });
      const sig = ml_dsa65.sign(m, sk0, { extraEntropy: false });
      const v = await world.tryCtx(handle0, hex(m), hex(sig), "");
      note({ challenge: `routing: |M| = ${mlen}, empty context (mu preimage ${66 + mlen} bytes)`, input: `${mlen} bytes`, outcome: v.outcome, detail: `${v.detail} @ ${v.gas} gas`, gas: v.gas, finding: mlen === 734 ? "the 800-byte preimage takes shake256Fast (raw permutation protocol) because the batched helper entry cannot express it; verdict unchanged" : "batched path" });
      expect(v.outcome).to.equal("ACCEPT");
    }
    // and with a context, a 32-byte digest shape: mu preimage 64 + 2 + |ctx| + 32
    const ctx = utf8("WalletWall");
    const m = unhex(digest0);
    const sig = ml_dsa65.sign(m, sk0, { extraEntropy: false, context: ctx });
    const v = await world.tryCtx(handle0, digest0, hex(sig), hex(ctx));
    expect(v.outcome).to.equal("ACCEPT");
    const wrongCtx = await world.tryCtx(handle0, digest0, hex(sig), hex(utf8("WalletWal1")));
    expect(wrongCtx.outcome).to.equal("REJECT");
    const noCtxOn32 = await world.try32(handle0, digest0, hex(sig));
    expect(noCtxOn32.outcome, "a context-bound signature is not accepted by the context-free ERC-7913 path").to.equal("REJECT");
  });

  it("records the findings (results/adversarial.json) and reproduces the committed record", async function () {
    const comparable = findings.map(({ challenge, outcome, detail, finding }) => ({ challenge, outcome, detail: detail.replace(/noble=\w+/, (s) => s), finding }));
    const record = { schema: "gen2-pq-conformance-1/adversarial.v1", comparable, findings, environment: await toolchainRecord() };
    writeResults("adversarial.json", record);
    const committed = readResults<typeof record>("adversarial.json");
    if (committed) expect(comparable).to.deep.equal(committed.comparable);
    else this.skip();
  });
});
