/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SD-2 REMEDIATION — I-CONTAINMENT-BUDGET ENFORCED AS A TRUE ROLLING BUDGET.
 *
 * THE CONTRACT THIS FILE HOLDS THE KERNEL TO (frozen by the owner, 2026-09-14)
 * ------------------------------------------------------------------------
 *   In every rolling wall-clock interval of length CONTAINMENT_WINDOW, total effective
 *   CONTAINED time is at most CONTAINMENT_BUDGET.
 *
 * with CONTAINMENT_MAX = 3 d, CONTAINMENT_BUDGET = 6 d, CONTAINMENT_WINDOW = 30 d unchanged.
 *
 * THE SELECTED MECHANISM, derived in SD2_CONTAINMENT_BUDGET_ADJUDICATION.md §4 candidate 5:
 * because every successful containment lasts exactly CONTAINMENT_MAX, re-entry cannot extend
 * it, and CONTAINMENT_BUDGET == 2 * CONTAINMENT_MAX, admitting a new episode is legal iff
 * fewer than two prior starts exist or the second-most-recent start is at least
 * CONTAINMENT_WINDOW old. Section 0 pins those three algebraic preconditions mechanically.
 *
 * RED FIRST. Written against the TUMBLING kernel at 1d8c54c3 (the adjudication head), where
 * sections 1 and 3 must FAIL for exactly one reason — rolling enforcement is absent — while
 * sections 0, 2 and 4 pass on both kernels (they are the controls that keep the remediation
 * from being a disguised cooldown). The expected RED set, recorded before implementation:
 *   1.R1  A4 of the historical straddle is ADMITTED by the tumbling kernel; rolling refuses it.
 *   1.R2  T0+57d-1 is ADMITTED by the tumbling kernel; rolling refuses it until exactly T0+57d.
 *   1.R3  the tumbling kernel disagrees with the rolling model on every straddling plan.
 *   3.*   the two public budget getters report a per-epoch counter, not the rolling truth.
 *
 * Nothing in this file is shared with Sd2ContainmentBudgetAdjudication.test.ts, which stays
 * byte-identical as the historical reproduction of the defect.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  deployWorld,
  digestOf,
  pqKeyBytes,
  sign,
  spendParams,
  type World,
} from "../stateful/world.js";

const DAY = 24 * 60 * 60;
/** Frozen constants; asserted against the artifact in §0 before anything relies on them. */
const MAX = 3 * DAY;
const WINDOW = 30 * DAY;
const BUDGET = 6 * DAY;
/** Explicit gas so a REFUSED probe is still mined at its pinned instant (see W2RecoveryLifecycle). */
const MINED = { gasLimit: 2_000_000 };
const SAFE = { NORMAL: 0, CONTAINED: 1 } as const;

// ---------------------------------------------------------------------------
// Probes pinned to exact instants.
// ---------------------------------------------------------------------------

interface Probe {
  ok: boolean;
  reason: string;
  at: number;
  gasUsed: bigint;
}

const latest = async (): Promise<number> => Number((await ethers.provider.getBlock("latest"))!.timestamp);
const latestBlockNumber = async (): Promise<number> => (await ethers.provider.getBlock("latest"))!.number;

function reasonOf(iface: ethers.Interface, e: unknown): string {
  const seen = new Set<unknown>();
  const stack: unknown[] = [e];
  let message = "";
  while (stack.length > 0) {
    const cur = stack.pop();
    if (cur === null || cur === undefined || typeof cur !== "object" || seen.has(cur)) continue;
    seen.add(cur);
    const o = cur as Record<string, unknown>;
    if (typeof o.message === "string" && message === "") message = o.message;
    const revert = o.revert as { name?: unknown } | undefined;
    if (revert && typeof revert.name === "string") return revert.name;
    if (typeof o.data === "string" && /^0x[0-9a-fA-F]{8,}$/.test(o.data)) {
      try {
        const parsed = iface.parseError(o.data);
        if (parsed) return parsed.name;
      } catch {
        /* not one of ours */
      }
    }
    for (const k of ["error", "info", "cause", "innerError", "receipt"]) if (o[k]) stack.push(o[k]);
  }
  const m = /custom error '([A-Za-z0-9_]+)/.exec(message);
  return m ? m[1]! : "UNPARSED:" + message.slice(0, 160);
}

async function sendAt(w: World, t: number, build: () => Promise<ethers.ContractTransactionResponse>): Promise<Probe> {
  const before = await latest();
  if (t <= before) throw new Error("probe instant " + t + " is not after the latest block " + before);
  await networkHelpers.time.setNextBlockTimestamp(t);
  try {
    const tx = await build();
    const rec = await tx.wait();
    const at = Number((await ethers.provider.getBlock(rec!.blockNumber))!.timestamp);
    if (at !== t) throw new Error("accepted probe mined at " + at + ", not at the requested " + t);
    return { ok: true, reason: "OK", at, gasUsed: rec!.gasUsed };
  } catch (e) {
    const at = await latest();
    const reason = reasonOf(w.vault.interface, e);
    if (at !== t) throw new Error("refused probe was NOT mined at " + t + " (latest " + at + "): " + reason);
    // The refused transaction was mined (status 0); its receipt carries the gas it burnt.
    const blk = await ethers.provider.getBlock("latest");
    const hash = blk?.transactions[0];
    const rec = hash ? await ethers.provider.getTransactionReceipt(hash) : null;
    return { ok: false, reason, at, gasUsed: rec?.gasUsed ?? 0n };
  }
}

interface QuorumProof {
  members: string[];
  isContract: boolean[];
  attestingIndices: number[];
  attestations: string[];
}

async function containDigest(w: World, nonce: bigint): Promise<string> {
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  return digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: gGen,
    params: ethers.id("CONTAIN"),
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
}

const quorum = (w: World, digest: string, seats: number[] = [0, 1]): QuorumProof => ({
  members: w.guardians,
  isContract: w.guardianIsContract,
  attestingIndices: seats,
  attestations: seats.map((i) => sign(w.gKeys[i]!, digest)),
});

async function containAt(w: World, t: number): Promise<Probe> {
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const proof = quorum(w, await containDigest(w, nonce));
  return sendAt(w, t, () => w.vault.enterContainment(proof, nonce, FAR_DEADLINE, MINED));
}

async function spendAt(w: World, t: number): Promise<Probe> {
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const amount = ethers.parseEther("0.01");
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SPEND,
    authorityGeneration: credGen,
    params: spendParams(w.recipient, amount),
    domain: DOMAIN.SPEND,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return sendAt(w, t, () =>
    w.vault.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(w.credKey, d), sign(w.pqKey, d), pqKeyBytes(w.pqKey), MINED),
  );
}

async function branch<T>(fn: () => Promise<T>): Promise<T> {
  const snap = await networkHelpers.takeSnapshot();
  try {
    return await fn();
  } finally {
    await snap.restore();
  }
}

/** Containment state plus the guardian nonce: everything a refused attempt must leave untouched. */
async function containmentState(w: World) {
  return {
    stored: Number(await w.vault.safeState()),
    effective: Number(await w.vault.effectiveSafeState()),
    until: Number(await w.vault.containedUntil()),
    guardianNonce: (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint,
  };
}

// ---------------------------------------------------------------------------
// The rolling semantics, as a pure reference, in the two-start form the kernel must implement.
// Refusal reasons are the kernel's own custom-error names so verdicts compare reason for reason.
// ---------------------------------------------------------------------------

class RollingTwoStart {
  readonly starts: number[] = [];
  decide(t: number): string {
    const n = this.starts.length;
    const last = n > 0 ? this.starts[n - 1]! : null;
    if (last !== null && t < last + MAX) return "BadState";
    const previous = n > 1 ? this.starts[n - 2]! : null;
    if (previous !== null && t < previous + WINDOW) return "ContainmentBudget";
    return "OK";
  }
  commit(t: number): void {
    const v = this.decide(t);
    if (v !== "OK") throw new Error("rolling model: commit at " + t + " refused (" + v + ")");
    this.starts.push(t);
  }
  /** Earliest instant >= from that admits; admissibility for a fixed state is monotone in t. */
  earliest(from: number): number {
    if (this.decide(from) === "OK") return from;
    let lo = from;
    let step = 1;
    while (this.decide(lo + step) !== "OK") {
      lo += step;
      step *= 2;
      if (step > 400 * DAY) throw new Error("no admissible instant within the horizon");
    }
    let hi = lo + step;
    while (hi - lo > 1) {
      const mid = Math.floor((lo + hi) / 2);
      if (this.decide(mid) === "OK") hi = mid;
      else lo = mid;
    }
    return hi;
  }
}

/** The literal invariant, for the equivalence pin in §0: total contained in any window of W. */
function literalRollingAdmits(starts: readonly number[], t: number): boolean {
  const last = starts.length > 0 ? starts[starts.length - 1]! : null;
  if (last !== null && t < last + MAX) return false;
  const from = t + MAX - WINDOW;
  let history = 0;
  for (const s of starts) history += Math.max(0, Math.min(s + MAX, t) - Math.max(s, from));
  return history + MAX <= BUDGET;
}

/** Contained time inside ANY half-open window of length W over the given episode starts. */
function maxInAnyWindow(starts: readonly number[]): number {
  const breakpoints = new Set<number>();
  for (const s of starts) for (const b of [s, s + MAX, s - WINDOW, s + MAX - WINDOW]) breakpoints.add(b);
  let best = 0;
  for (const a of breakpoints) {
    let total = 0;
    for (const s of starts) total += Math.max(0, Math.min(s + MAX, a + WINDOW) - Math.max(s, a));
    best = Math.max(best, total);
  }
  return best;
}

/** Longest strictly contiguous run of episodes, as contained seconds. */
function maxContinuous(starts: readonly number[]): number {
  const s = [...starts].sort((a, b) => a - b);
  let best = 0;
  let run = 0;
  let runEnd = Number.NEGATIVE_INFINITY;
  for (const start of s) {
    run = start === runEnd ? run + MAX : MAX;
    runEnd = start + MAX;
    best = Math.max(best, run);
  }
  return best;
}

/** Observed contained seconds inside [from, to) for episodes of exactly MAX at `starts`. */
function observedWithin(starts: readonly number[], from: number, to: number): number {
  let total = 0;
  for (const s of starts) total += Math.max(0, Math.min(s + MAX, to) - Math.max(s, from));
  return total;
}

const fmtDays = (s: number): string => (s / DAY).toFixed(s % DAY === 0 ? 0 : 5) + "d";

// ===========================================================================

describe("vNext kernel — SD-2 REMEDIATION: I-CONTAINMENT-BUDGET enforced as a rolling budget in the two-start representation", function () {
  this.timeout(1_800_000);

  // -------------------------------------------------------------------------
  describe("0. ALGEBRAIC PRECONDITIONS — pinned mechanically, so a constants change cannot silently invalidate the representation", function () {
    let w: World;
    before(async function () {
      w = await deployWorld({ label: "sd2r-pins" });
    });

    it("0.1 — the frozen constants are exactly what the kernel deploys: MAX 3d, BUDGET 6d, WINDOW 30d, RECOVERY_DELAY 7d", async function () {
      expect(Number(await w.vault.CONTAINMENT_MAX())).to.equal(MAX);
      expect(Number(await w.vault.CONTAINMENT_BUDGET())).to.equal(BUDGET);
      expect(Number(await w.vault.CONTAINMENT_WINDOW())).to.equal(WINDOW);
      expect(Number(await w.vault.RECOVERY_DELAY())).to.equal(7 * DAY);
    });

    it("0.2 — BUDGET is exactly TWO whole episodes and both are shorter than the window: the identities the two-start form rests on", async function () {
      const max = Number(await w.vault.CONTAINMENT_MAX());
      const budget = Number(await w.vault.CONTAINMENT_BUDGET());
      const window = Number(await w.vault.CONTAINMENT_WINDOW());
      expect(budget % max, "BUDGET is a whole number of episodes").to.equal(0);
      expect(budget / max, "exactly two episodes per budget — the representation tracks TWO starts").to.equal(2);
      expect(budget, "B < W").to.be.lessThan(window);
      expect(max, "MAX < W").to.be.lessThan(window);
    });

    it("0.3 — every admitted episode lasts exactly MAX and re-entry while contained is refused without extension: the premises of 'starts determine everything'", async function () {
      await branch(async () => {
        const t0 = (await latest()) + DAY;
        const a1 = await containAt(w, t0);
        expect(a1.ok, a1.reason).to.equal(true);
        const s1 = await containmentState(w);
        expect(s1.until - t0, "episode length").to.equal(MAX);
        expect(s1.effective).to.equal(SAFE.CONTAINED);
        const again = await containAt(w, t0 + DAY);
        expect(again.ok).to.equal(false);
        expect(again.reason).to.equal("BadState");
        const s2 = await containmentState(w);
        expect(s2.until, "expiry not moved").to.equal(s1.until);
        expect(s2.guardianNonce, "nonce not burnt").to.equal(s1.guardianNonce);
      });
    });

    it("0.4 — with those identities the two-start rule is EXTENSIONALLY the literal invariant on 2,197 adversarial plans (pure models; would break if B/MAX stopped being 2)", function () {
      const t0 = 1_000_000 * DAY;
      const grid = [0, 1, 3 * DAY, 6 * DAY, 12 * DAY, 21 * DAY, 24 * DAY - 1, 24 * DAY, 24 * DAY + 1, 26 * DAY, 27 * DAY - 1, 27 * DAY, 30 * DAY];
      let compared = 0;
      const rec = (delays: number[]): void => {
        if (delays.length === 3) {
          const ring = new RollingTwoStart();
          ring.commit(t0);
          const literal: number[] = [t0];
          for (const d of delays) {
            const at = ring.earliest(ring.starts[ring.starts.length - 1]! + MAX) + d;
            // Literal invariant: the same instant must be admitted, and one second before the
            // ring's earliest instant must be refused by the literal invariant too.
            expect(literalRollingAdmits(literal, at), "plan " + delays.map(fmtDays).join(",") + " literal admits at " + at).to.equal(true);
            const earliest = at - d;
            expect(literalRollingAdmits(literal, earliest - 1), "literal refuses one second before the ring's earliest").to.equal(false);
            ring.commit(at);
            literal.push(at);
          }
          expect(maxInAnyWindow(ring.starts), "no window exceeds B").to.be.at.most(BUDGET);
          compared += 1;
          return;
        }
        for (const d of grid) rec([...delays, d]);
      };
      rec([]);
      expect(compared).to.equal(grid.length ** 3);
    });
  });

  // -------------------------------------------------------------------------
  describe("1. RED — rolling enforcement at the historical straddle and at the exact replacement instant", function () {
    let w: World;
    let T0: number;

    before(async function () {
      w = await deployWorld({ label: "sd2r-red" });
      T0 = (await latest()) + DAY;
      for (const [label, t] of [
        ["A1", T0],
        ["A2", T0 + 27 * DAY],
        ["A3", T0 + 30 * DAY],
      ] as const) {
        const p = await containAt(w, t);
        expect(p.ok, label + " must be legal under rolling semantics: " + p.reason).to.equal(true);
      }
      // State after A3: starts {T0, T0+27d, T0+30d}, contained until T0+33d.
    });

    it("1.R1 — A4 at T0+33d is REFUSED (ContainmentBudget): the second-most-recent start, T0+27d, is only 6 days old", async function () {
      await branch(async () => {
        const before = await containmentState(w);
        const a4 = await containAt(w, T0 + 33 * DAY);
        expect(a4.ok, "A4 must be refused under rolling semantics (the tumbling kernel admits it)").to.equal(false);
        expect(a4.reason).to.equal("ContainmentBudget");
        const after = await containmentState(w);
        expect(after.guardianNonce, "a refused budget attempt consumes no guardian nonce").to.equal(before.guardianNonce);
        expect(after.until, "and mutates no containment history").to.equal(before.until);
        expect(after.effective, "the vault is simply NORMAL").to.equal(SAFE.NORMAL);
        // The straddle now yields exactly B contiguous, never B + MAX.
        expect(maxContinuous([T0 + 27 * DAY, T0 + 30 * DAY]), "contiguous").to.equal(BUDGET);
        expect(maxInAnyWindow([T0, T0 + 27 * DAY, T0 + 30 * DAY]), "in any 30d window").to.equal(BUDGET);
      });
    });

    it("1.R2 — the exact earliest legal replacement: refused at T0+57d-1, admitted at T0+57d (= T0+27d + W)", async function () {
      await branch(async () => {
        const early = await containAt(w, T0 + 57 * DAY - 1);
        expect(early.ok, "one second before the second-most-recent start turns W old the budget still binds").to.equal(false);
        expect(early.reason).to.equal("ContainmentBudget");
        const exact = await containAt(w, T0 + 57 * DAY);
        expect(exact.ok, "at exactly W after T0+27d the episode is admitted: " + exact.reason).to.equal(true);
        const s = await containmentState(w);
        expect(s.until).to.equal(T0 + 60 * DAY);
      });
    });

    it("1.R3 — on every plan of the adjudication's delay grid the kernel agrees with the ROLLING model, admission for admission and refusal for refusal", async function () {
      const plans: Record<string, number[]> = {
        greedy: [0, 0, 0],
        "mid (A2 +12d)": [12 * DAY, 0, 0],
        "straddle-1s": [24 * DAY - 1, 0, 0],
        straddle: [24 * DAY, 0, 0],
        "straddle+1s": [24 * DAY + 1, 0, 0],
        "late (A2 +26d)": [26 * DAY, 0, 0],
      };
      for (const [label, delays] of Object.entries(plans)) {
        await branch(async () => {
          const wx = await deployWorld({ label: "sd2r-plan-" + label.replace(/[^a-z0-9]/gi, "") });
          const t0 = (await latest()) + DAY;
          const model = new RollingTwoStart();
          model.commit(t0);
          expect((await containAt(wx, t0)).ok).to.equal(true);
          for (const d of delays) {
            const earliest = model.earliest(model.starts[model.starts.length - 1]! + MAX);
            const justBefore = await branch(() => containAt(wx, earliest - 1));
            expect(justBefore.ok, label + ": kernel must refuse one second before the rolling earliest " + earliest).to.equal(false);
            expect(justBefore.reason, label + ": and for the rolling model's reason").to.equal(model.decide(earliest - 1));
            if (d !== 0) {
              const atEarliest = await branch(() => containAt(wx, earliest));
              expect(atEarliest.ok, label + ": kernel admits at the rolling earliest instant").to.equal(true);
            }
            const real = await containAt(wx, earliest + d);
            expect(real.ok, label + ": planned activation admitted at " + (earliest + d) + " (" + real.reason + ")").to.equal(true);
            model.commit(earliest + d);
          }
          console.log("      plan " + label.padEnd(16) + " starts T0+" + model.starts.map((s) => fmtDays(s - t0)).join(", T0+") + "  continuous " + fmtDays(maxContinuous(model.starts)) + "  in-window " + fmtDays(maxInAnyWindow(model.starts)));
          expect(maxInAnyWindow(model.starts), label + ": no 30d window exceeds B").to.be.at.most(BUDGET);
        });
      }
    });
  });

  // -------------------------------------------------------------------------
  describe("2. POSITIVE CONTROLS — the remediation is not a disguised cooldown (must pass on the tumbling kernel too)", function () {
    let w: World;
    let T0: number;

    before(async function () {
      w = await deployWorld({ label: "sd2r-controls" });
      T0 = (await latest()) + DAY;
    });

    it("2.1 — two back-to-back 3-day containments are legal: the full 6-day burst is reachable, and a third inside it is refused without burning a nonce", async function () {
      await branch(async () => {
        expect((await containAt(w, T0)).ok).to.equal(true);
        const a2 = await containAt(w, T0 + 3 * DAY);
        expect(a2.ok, "back-to-back second episode: " + a2.reason).to.equal(true);
        expect(maxContinuous([T0, T0 + 3 * DAY])).to.equal(BUDGET);
        const before = await containmentState(w);
        const a3 = await containAt(w, T0 + 6 * DAY);
        expect(a3.ok).to.equal(false);
        expect(a3.reason).to.equal("ContainmentBudget");
        const after = await containmentState(w);
        expect(after.guardianNonce).to.equal(before.guardianNonce);
        expect(after.until).to.equal(before.until);
        const spend = await spendAt(w, T0 + 6 * DAY + 1);
        expect(spend.ok, "spending is live the instant the burst ends: " + spend.reason).to.equal(true);
      });
    });

    it("2.2 — exact W-old boundary starts are legal: after A1@T0, A2@T0+3d, the next episode is refused at T0+30d-1 and admitted at exactly T0+30d; the following at exactly T0+33d — a second full 6-day burst", async function () {
      await branch(async () => {
        expect((await containAt(w, T0)).ok).to.equal(true);
        expect((await containAt(w, T0 + 3 * DAY)).ok).to.equal(true);
        const early = await containAt(w, T0 + 30 * DAY - 1);
        expect(early.ok).to.equal(false);
        expect(early.reason).to.equal("ContainmentBudget");
        const a3 = await containAt(w, T0 + 30 * DAY);
        expect(a3.ok, "A1 is exactly W old: " + a3.reason).to.equal(true);
        const early4 = await containAt(w, T0 + 33 * DAY - 1);
        expect(early4.reason, "still contained one second before A3 expires").to.equal("BadState");
        const a4 = await containAt(w, T0 + 33 * DAY);
        expect(a4.ok, "A2 is exactly W old at the instant A3 expires: " + a4.reason).to.equal(true);
        expect(maxContinuous([T0 + 30 * DAY, T0 + 33 * DAY]), "the maximum legal burst again").to.equal(BUDGET);
        expect(maxInAnyWindow([T0, T0 + 3 * DAY, T0 + 30 * DAY, T0 + 33 * DAY])).to.equal(BUDGET);
      });
    });

    it("2.3 — a lone episode never blocks the next: after A1@T0, A2 is legal at T0+3d, at T0+15d and at T0+29d alike (single-start history is never a refusal)", async function () {
      for (const gap of [3 * DAY, 15 * DAY, 29 * DAY]) {
        await branch(async () => {
          expect((await containAt(w, T0)).ok).to.equal(true);
          const a2 = await containAt(w, T0 + gap);
          expect(a2.ok, "A2 at T0+" + fmtDays(gap) + ": " + a2.reason).to.equal(true);
        });
      }
    });
  });

  // -------------------------------------------------------------------------
  describe("3. GETTERS — the two public budget getters keep their selectors and report the rolling truth", function () {
    let w: World;
    let T0: number;

    before(async function () {
      w = await deployWorld({ label: "sd2r-getters" });
      T0 = (await latest()) + DAY;
    });

    it("3.1 — both selectors exist, are views, and return uint64 (ABI preserved)", function () {
      for (const name of ["containmentWindowStart", "containmentUsedInWindow"]) {
        const fn = w.vault.interface.getFunction(name);
        expect(fn, name + " is in the ABI").to.not.equal(null);
        expect(fn!.stateMutability, name).to.equal("view");
        expect(fn!.inputs.length, name + " takes no arguments").to.equal(0);
        expect(fn!.outputs.map((o) => o.type), name + " returns uint64").to.deep.equal(["uint64"]);
      }
    });

    it("3.2 — containmentWindowStart() is the rolling origin, exactly W behind the block it is read in, and moves only with the clock", async function () {
      await branch(async () => {
        expect((await containAt(w, T0)).ok).to.equal(true);
        for (const t of [T0 + DAY, T0 + 10 * DAY, T0 + 40 * DAY]) {
          await networkHelpers.time.increaseTo(t);
          const bn = await latestBlockNumber();
          const origin = Number(await w.vault.containmentWindowStart({ blockTag: bn }));
          expect(origin, "origin at T0+" + fmtDays(t - T0)).to.equal(t - WINDOW);
        }
      });
    });

    it("3.3 — containmentUsedInWindow() equals the OBSERVED contained time inside [now - W, now), including the instant three episodes intersect the window", async function () {
      await branch(async () => {
        const starts = [T0, T0 + 3 * DAY, T0 + 30 * DAY];
        for (const t of starts) expect((await containAt(w, t)).ok, "start T0+" + fmtDays(t - T0)).to.equal(true);
        // At T0+31d the window [T0+1d, T0+31d) holds 2d of A1, all of A2 and 1d of the live A3: 6d.
        const checks: [number, number][] = [
          [T0 + 30 * DAY + DAY, 6 * DAY],
          [T0 + 33 * DAY, 6 * DAY],
          [T0 + 40 * DAY, 3 * DAY],
          [T0 + 63 * DAY, 0],
        ];
        for (const [t, expected] of checks) {
          await networkHelpers.time.increaseTo(t);
          const bn = await latestBlockNumber();
          const used = Number(await w.vault.containmentUsedInWindow({ blockTag: bn }));
          expect(used, "used at T0+" + fmtDays(t - T0)).to.equal(observedWithin(starts, t - WINDOW, t));
          expect(used, "and the hand-computed figure").to.equal(expected);
          expect(used, "never above B").to.be.at.most(BUDGET);
        }
      });
    });
  });

  // -------------------------------------------------------------------------
  describe("4. GAS — informational, recorded for the before/after delta", function () {
    it("4.1 — gas of the first, the back-to-back second, a refused third and a post-window admission", async function () {
      const w = await deployWorld({ label: "sd2r-gas" });
      const t0 = (await latest()) + DAY;
      const a1 = await containAt(w, t0);
      const a2 = await containAt(w, t0 + 3 * DAY);
      const a3 = await containAt(w, t0 + 6 * DAY);
      const a4 = await containAt(w, t0 + 30 * DAY);
      console.log("      gas enterContainment: first " + a1.gasUsed + ", back-to-back " + a2.gasUsed + ", refused (" + a3.reason + ") " + a3.gasUsed + ", after the window " + a4.gasUsed);
      expect(a1.ok && a2.ok && a4.ok).to.equal(true);
      expect(a3.ok).to.equal(false);
    });
  });
});
