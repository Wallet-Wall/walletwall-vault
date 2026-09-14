/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SD-2 ADJUDICATION — THE CONTAINMENT BUDGET, RE-DERIVED FROM THE EXECUTABLE KERNEL.
 *
 * THE QUESTION
 * ------------
 * docs/Vault_vNext_Architecture.md section 6 publishes `I-CONTAINMENT-BUDGET (T0)`:
 * "Over any rolling wall-clock window of length W, the total time spent in CONTAINED
 * ... is at most B, with B < W." The kernel's own NatSpec repeats "rolling". The ledger
 * (stateful/defects.ts, SD-2) says the accounting is TUMBLING and that k guardians can
 * hold 9 contiguous contained days against a declared 6. This file trusts neither the
 * prose nor the ledger: it re-derives the mechanism from the compiler's AST, searches the
 * boundary mechanically, reproduces the maximum on the exact kernel at exact legal
 * timestamps, measures what the excess actually denies and to whom, and discriminates the
 * kernel from a genuine rolling budget, from two permissive shapes and from two
 * over-strict shapes.
 *
 * FIVE QUANTITIES, KEPT APART — the ledger's "9 days" names only one of them:
 *   Q1 TOTAL contained time          the integral of CONTAINED over a horizon (duty cycle),
 *                                    here measured inside ONE window of length W.
 *   Q2 CONTINUOUS contained time     the longest wall-clock stretch with NO uncontained
 *                                    instant (episodes are [t, t+MAX) half-open, so two
 *                                    episodes touching at one instant ARE contiguous).
 *   Q3 ACTIVATIONS                   distinct successful `enterContainment` calls, each a
 *                                    fresh k-of-n quorum signature over a consumed nonce.
 *   Q4 ACCOUNTING-WINDOW STATE       `containmentWindowStart` / `containmentUsedInWindow`.
 *   Q5 AUTHORIZATION                 who can enter containment at all.
 *
 * EVIDENCE LABELS
 *   REACHABLE            a named principal calls a real function on the really deployed
 *                        kernel artifact, in a block whose timestamp is pinned exactly.
 *   REFERENCE_MODEL      a pure TypeScript semantics run on the SAME transcript. It is a
 *                        specification, never a kernel; nothing here implements a candidate.
 *   MUTANT               the real kernel source with ONE textual change, compiled in memory
 *                        and deployed through `deployWorld({ implOverride })`. Zero bytes of
 *                        Solidity change on disk.
 *
 * WHAT THIS FILE DOES NOT CLAIM
 *   - Anything about SD-4, SD-8 or SD-11 (frozen input).
 *   - That any candidate semantics should be adopted. Section D measures; it does not choose.
 *   - Anything about the numeric constants beyond what they are (D5 leaves them OPEN).
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ethers, networkHelpers } from "./connection.js";
import { compileDeployable } from "../stateful/mutants.js";
import { compileMutatedKernel, replaceWithinFunction } from "../authority/mutation-harness.js";
import { findContract, type AstNode } from "../authority/ast.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld as deployCurrentWorld,
  digestOf,
  migrationParams,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  sign,
  spendParams,
  type World,
  type WorldOptions,
} from "../stateful/world.js";

const abi = ethers.AbiCoder.defaultAbiCoder();
const DAY = 24 * 60 * 60;
/** The kernel's constants, asserted against the artifact in A5 before anything relies on them. */
const MAX = 3 * DAY;
const WINDOW = 30 * DAY;
const BUDGET = 6 * DAY;
/** An explicit gas limit so a REFUSED probe is still mined at its pinned instant (see W2RecoveryLifecycle). */
const MINED = { gasLimit: 2_000_000 };
const SAFE = { NORMAL: 0, CONTAINED: 1, RECOVERY_ONLY: 2, MIGRATION_ONLY: 3, RETIRED: 4 } as const;

/**
 * HISTORICAL HARNESS PIN (owner-approved, after remediation lane SD-2).
 *
 * This file is evidence about the TUMBLING kernel that existed at the adjudication subject
 * `1d8c54c3` — blob `c25e2184`, byte-identical at base `03ce978b` and at the RED commit
 * `63443163`. Since `da3e84ed` the kernel on disk enforces the rolling rule, so every kernel this
 * file compiles or deploys comes from a byte-exact copy of that historical blob, compiled IN
 * MEMORY and deployed through `deployWorld({ implOverride })` — the mechanism the SD-4 candidate
 * kernels already use. Nothing about WHAT is asserted changed; only WHICH kernel it is asserted
 * about. The remediated kernel is covered by test/Sd2RollingContainmentRemediation.test.ts against
 * the real artifact. The fixture's identity is asserted before anything runs, so an edit to it
 * fails this whole file loudly.
 */
const PRE_SD2_KERNEL_FIXTURE = path.join("prototype", "vnext-kernel", "test", "fixtures", "VaultKernelPrototype.pre-sd2.c25e2184.sol");
/** git blob id of prototype/vnext-kernel/contracts/VaultKernelPrototype.sol at 1d8c54c3 (== 03ce978b == 63443163). */
const PRE_SD2_KERNEL_BLOB = "c25e2184fc706bf3d67aafc0d0e54a34ed3ed51a";
/** sha256 of the same bytes — also the pre-remediation kernel digest MEASUREMENTS.json sourceDigests carried. */
const PRE_SD2_KERNEL_SHA256 = "a27ee47d89ba07739bfd87696a3236110934a20ccdd6e5ffd31c695086c94ff3";

/** Reads the frozen source and refuses to proceed unless BOTH identities match the pins. */
function assertPreSd2FixtureIdentity(): Buffer {
  const bytes = fs.readFileSync(PRE_SD2_KERNEL_FIXTURE);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  // git's blob id: sha1 over "blob <length>", a NUL byte, then the content.
  const blob = createHash("sha1").update(Buffer.from("blob " + bytes.length, "utf8")).update(Buffer.from([0])).update(bytes).digest("hex");
  if (sha256 !== PRE_SD2_KERNEL_SHA256 || blob !== PRE_SD2_KERNEL_BLOB) {
    throw new Error(
      "FROZEN KERNEL FIXTURE DOES NOT MATCH ITS PIN: " + PRE_SD2_KERNEL_FIXTURE + " has blob " + blob + " / sha256 " + sha256 +
        ", expected blob " + PRE_SD2_KERNEL_BLOB + " / sha256 " + PRE_SD2_KERNEL_SHA256 + ". Restore it with `git show 1d8c54c3:prototype/vnext-kernel/contracts/VaultKernelPrototype.sol`.",
    );
  }
  return bytes;
}
const preSd2Source = (): string => assertPreSd2FixtureIdentity().toString("utf8");

let preSd2Deployable: { abi: unknown[]; bytecode: string } | null = null;
/** The frozen kernel, compiled once per run with the pinned solc and the production settings. */
function preSd2Kernel(): { abi: unknown[]; bytecode: string } {
  if (preSd2Deployable === null) {
    const out = compileDeployable({ "VaultKernelPrototype.sol": preSd2Source() });
    if (!out.ok) throw new Error("the frozen pre-SD-2 kernel failed to compile: " + out.errors.join(";"));
    preSd2Deployable = out.kernel;
  }
  return preSd2Deployable;
}
/** Every world in this file runs the FROZEN kernel unless a mutant of it is supplied explicitly. */
const deployWorld = (partial: Partial<WorldOptions> = {}): Promise<World> =>
  deployCurrentWorld({ ...partial, implOverride: partial.implOverride ?? preSd2Kernel() });

// ---------------------------------------------------------------------------
// Probes: one transaction, pinned to one instant, with its verdict and reason.
// ---------------------------------------------------------------------------

interface Probe {
  ok: boolean;
  /** "OK", or the kernel's custom error name. */
  reason: string;
  /** The timestamp of the block the probe was MINED in. Always equal to the requested instant. */
  at: number;
}

const latest = async (): Promise<number> => Number((await ethers.provider.getBlock("latest"))!.timestamp);

/** Extracts the custom error name from whatever ethers/Hardhat threw, decoding revert data through the vault ABI when present. */
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

/**
 * Sends one transaction in a block whose timestamp is EXACTLY `t`. A refusal is only
 * accepted as evidence if the refusing transaction was really mined at `t`; a probe that
 * never reached the chain proves nothing about that instant and throws instead.
 */
async function sendAt(w: World, t: number, build: () => Promise<ethers.ContractTransactionResponse>): Promise<Probe> {
  const before = await latest();
  if (t <= before) throw new Error("probe instant " + t + " is not after the latest block " + before);
  await networkHelpers.time.setNextBlockTimestamp(t);
  try {
    const tx = await build();
    const rec = await tx.wait();
    const at = Number((await ethers.provider.getBlock(rec!.blockNumber))!.timestamp);
    if (at !== t) throw new Error("accepted probe mined at " + at + ", not at the requested " + t);
    return { ok: true, reason: "OK", at };
  } catch (e) {
    const at = await latest();
    const reason = reasonOf(w.vault.interface, e);
    if (at !== t) throw new Error("refused probe was NOT mined at " + t + " (latest " + at + "): " + reason);
    return { ok: false, reason, at };
  }
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

interface QuorumProof {
  members: string[];
  isContract: boolean[];
  attestingIndices: number[];
  attestations: string[];
}

const quorum = (w: World, digest: string, seats: number[] = [0, 1]): QuorumProof => ({
  members: w.guardians,
  isContract: w.guardianIsContract,
  attestingIndices: seats,
  attestations: seats.map((i) => sign(w.gKeys[i]!, digest)),
});

interface ContainOptions {
  seats?: number[];
  sender?: ethers.Signer;
  preSigned?: { proof: QuorumProof; nonce: bigint };
}

/** `enterContainment` at exactly `t`, signed by seats 0 and 1 unless told otherwise. */
async function containAt(w: World, t: number, opts: ContainOptions = {}): Promise<Probe> {
  const v = opts.sender ? (w.vault.connect(opts.sender) as ethers.Contract) : w.vault;
  const nonce = opts.preSigned ? opts.preSigned.nonce : ((await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint);
  const proof = opts.preSigned ? opts.preSigned.proof : quorum(w, await containDigest(w, nonce), opts.seats);
  return sendAt(w, t, () => v.enterContainment(proof, nonce, FAR_DEADLINE, MINED));
}

async function spendAt(
  w: World,
  t: number,
  cred: ethers.SigningKey = w.credKey,
  pq: ethers.SigningKey = w.pqKey,
): Promise<Probe> {
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
    w.vault.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(cred, d), sign(pq, d), pqKeyBytes(pq), MINED),
  );
}

async function initiateRecoveryAt(w: World, t: number, idx = 0): Promise<Probe> {
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const signer = addrOf(w.spareCred[idx]!);
  const h = pqHash(w.sparePq[idx]!);
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: gGen,
    params: recoverParams(signer, h, w.verifiers.honest),
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return sendAt(w, t, () =>
    w.vault.initiateRecovery(signer, h, w.verifiers.honest, quorum(w, d), nonce, FAR_DEADLINE, MINED),
  );
}

async function executeRecoveryAt(w: World, t: number, idx = 0): Promise<Probe> {
  const pop = (await w.vault.recoveryPossessionDigest()) as string;
  const c = w.spareCred[idx]!;
  const p = w.sparePq[idx]!;
  return sendAt(w, t, () =>
    w.vault.executeRecovery(
      {
        newSigner: addrOf(c),
        newPqKeyHash: pqHash(p),
        newPqKey: pqKeyBytes(p),
        newEcdsaPop: sign(c, pop),
        newPqPop: sign(p, pop),
      },
      MINED,
    ),
  );
}

async function cancelRecoveryAt(w: World, t: number): Promise<Probe> {
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: credGen,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return sendAt(w, t, () => w.vault.cancelRecovery(nonce, FAR_DEADLINE, sign(w.credKey, d), MINED));
}

async function bindMigrationAt(w: World, t: number): Promise<Probe> {
  const nonce = (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const dest = { vault: w.destination, codeHash: w.destinationCodeHash, generation: 2n };
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: gGen,
    params: migrationParams(dest.vault, dest.codeHash, dest.generation),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return sendAt(w, t, () => w.vault.bindMigration(dest, quorum(w, d), nonce, FAR_DEADLINE, sign(w.credKey, d), MINED));
}

/** Runs `fn` on a chain snapshot and restores it afterwards, so branches share one prefix. */
async function branch<T>(fn: () => Promise<T>): Promise<T> {
  const snap = await networkHelpers.takeSnapshot();
  try {
    return await fn();
  } finally {
    await snap.restore();
  }
}

async function containmentState(w: World) {
  return {
    stored: Number(await w.vault.safeState()),
    effective: Number(await w.vault.effectiveSafeState()),
    until: Number(await w.vault.containedUntil()),
    windowStart: Number(await w.vault.containmentWindowStart()),
    used: Number(await w.vault.containmentUsedInWindow()),
    guardianNonce: (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint,
  };
}

/** Every authority-bearing field that containment must NOT move. */
async function authorityState(w: World) {
  const floor = await w.vault.securityFloor();
  return {
    ecdsaSigner: (await w.vault.ecdsaSigner()) as string,
    pqPublicKeyHash: (await w.vault.pqPublicKeyHash()) as string,
    pqVerifier: (await w.vault.pqVerifier()) as string,
    guardianCommitment: (await w.vault.guardianCommitment()) as string,
    guardianThreshold: (await w.vault.guardianThreshold()) as bigint,
    guardianGeneration: (await w.vault.guardianGeneration()) as bigint,
    credentialGeneration: (await w.vault.credentialGeneration()) as bigint,
    policyEngine: (await w.vault.policyEngine()) as string,
    floor: [floor[0], floor[1], floor[2], floor[3]].map(String).join("/"),
    spendNonce: (await w.vault.nonces(DOMAIN.SPEND)) as bigint,
    credentialNonce: (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint,
    migrationNonce: (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint,
  };
}

// ---------------------------------------------------------------------------
// REFERENCE SEMANTICS — pure models of what "containment budget accounting" could
// mean. Each decides admission at an instant from the episodes it has seen. Every
// episode is exactly MAX long because no principal can exit early (section A proves
// that on the kernel). `decide` is PURE; `commit` records an admitted entry.
// ---------------------------------------------------------------------------

interface Verdict {
  admit: boolean;
  reason: string;
}
const ADMIT: Verdict = { admit: true, reason: "OK" };
const refuse = (reason: string): Verdict => ({ admit: false, reason });

abstract class Semantics {
  abstract readonly name: string;
  /** Storage the semantics needs on top of `containedUntil` + `safeState`, in 32-byte words (the kernel packs its two into uint64 slots). */
  abstract readonly storageWords: number;
  abstract readonly worstCaseWork: string;
  abstract readonly resetBehaviour: string;
  readonly starts: number[] = [];
  protected lastEnd = Number.NEGATIVE_INFINITY;

  decide(t: number): Verdict {
    // The no-extension rule is common to every candidate: nothing here ever
    // re-enters while contained. What differs is the ACCOUNTING that follows.
    if (t < this.lastEnd) return refuse("BadState");
    return this.account(t);
  }
  commit(t: number): void {
    const v = this.decide(t);
    if (!v.admit) throw new Error(this.name + ": commit at " + t + " refused (" + v.reason + ")");
    this.starts.push(t);
    this.lastEnd = t + MAX;
    this.onCommit(t);
  }
  protected abstract account(t: number): Verdict;
  protected abstract onCommit(t: number): void;
}

/** THE KERNEL AS IMPLEMENTED: a per-epoch counter whose origin jumps to the first activation after the epoch expires. Reasons mirror the kernel's custom errors. */
class TumblingAsImplemented extends Semantics {
  readonly name = "tumbling (kernel as implemented)";
  readonly storageWords = 2;
  readonly worstCaseWork = "2 SLOAD + 2 SSTORE, constant";
  readonly resetBehaviour = "origin := now and used := 0 on the first activation with now >= origin + W";
  windowStart = 0;
  used = 0;
  protected account(t: number): Verdict {
    const rolled = t >= this.windowStart + WINDOW;
    const used = rolled ? 0 : this.used;
    return used + MAX > BUDGET ? refuse("ContainmentBudget") : ADMIT;
  }
  protected onCommit(t: number): void {
    if (t >= this.windowStart + WINDOW) {
      this.windowStart = t;
      this.used = 0;
    }
    this.used += MAX;
  }
}

/** THE PUBLISHED INVARIANT, literally: admit iff no window of length W would ever hold more than B contained time. */
class RollingBudget extends Semantics {
  readonly name = "rolling budget (published invariant, literal)";
  readonly storageWords = 2;
  readonly worstCaseWork = "ring of B/MAX = 2 episode starts: 2 SLOAD + 2 SSTORE, constant";
  readonly resetBehaviour = "none; episodes age out of the window individually";
  protected account(t: number): Verdict {
    // An entry at t commits [t, t+MAX). The tightest window is the one ENDING at t+MAX,
    // which holds the new episode whole and the most recent W-MAX of history.
    const from = t + MAX - WINDOW;
    let history = 0;
    for (const s of this.starts) history += Math.max(0, Math.min(s + MAX, t) - Math.max(s, from));
    return history + MAX > BUDGET ? refuse("RollingBudget") : ADMIT;
  }
  protected onCommit(): void {
    /* nothing: history is the episode list itself */
  }
}

/**
 * CANDIDATE 5 — the simplest mechanism the measured property implies. With episodes of
 * fixed length MAX and B = 2*MAX exactly, "at most B contained in any W" is the same as
 * "at most two episode STARTS in any half-open window of length W", i.e. the
 * second-most-recent start must be at least W old. Two timestamps; no arithmetic.
 */
class TwoStartRing extends Semantics {
  readonly name = "two-start ring (candidate 5)";
  readonly storageWords = 2;
  readonly worstCaseWork = "2 SLOAD + 2 SSTORE, constant";
  readonly resetBehaviour = "none; the older start ages out at exactly start + W";
  prevStart = Number.NEGATIVE_INFINITY;
  lastStart = Number.NEGATIVE_INFINITY;
  protected account(t: number): Verdict {
    return this.prevStart + WINDOW > t ? refuse("RingBudget") : ADMIT;
  }
  protected onCommit(t: number): void {
    this.prevStart = this.lastStart;
    this.lastStart = t;
  }
}

/** CANDIDATE 2 — a token bucket refilling at B per W, spending MAX per activation. Integer arithmetic in fifths of a second. */
class TokenBucket extends Semantics {
  readonly name = "token bucket (B per W refill)";
  readonly storageWords = 2;
  readonly worstCaseWork = "2 SLOAD + 2 SSTORE + one multiplication, constant";
  readonly resetBehaviour = "none; continuous refill, capped at B";
  private tokens5 = 5 * BUDGET;
  private last: number | null = null;
  private refilled(t: number): number {
    if (this.last === null) return this.tokens5;
    // B / W = 6d / 30d = 1/5 per second, so fifths of a second keep this exact.
    return Math.min(5 * BUDGET, this.tokens5 + (t - this.last));
  }
  protected account(t: number): Verdict {
    return this.refilled(t) < 5 * MAX ? refuse("BucketEmpty") : ADMIT;
  }
  protected onCommit(t: number): void {
    this.tokens5 = this.refilled(t) - 5 * MAX;
    this.last = t;
  }
}

/** CANDIDATE 3 — a fixed cooldown after every expiry, sized so the long-run duty cycle equals B/W. */
class Cooldown extends Semantics {
  static readonly C = (MAX * (WINDOW - BUDGET)) / BUDGET;
  readonly name = "cooldown (" + (Cooldown.C / DAY).toFixed(0) + "d after every expiry)";
  readonly storageWords = 0;
  readonly worstCaseWork = "1 SLOAD (containedUntil already exists), constant";
  readonly resetBehaviour = "none; the cooldown is relative to the last expiry";
  protected account(t: number): Verdict {
    return t < this.lastEnd + Cooldown.C ? refuse("Cooldown") : ADMIT;
  }
  protected onCommit(): void {
    /* lastEnd is maintained by the base class */
  }
}

/** OBVIOUSLY TOO PERMISSIVE — the architecture's own mutant M24/M46: the window resets on EVERY trigger. */
class ResetEveryTrigger extends Semantics {
  readonly name = "reset on every trigger (M24/M46, permissive)";
  readonly storageWords = 2;
  readonly worstCaseWork = "constant";
  readonly resetBehaviour = "origin := now and used := 0 on EVERY activation";
  protected account(): Verdict {
    return ADMIT; // used is always 0 at the check, so MAX <= B always holds
  }
  protected onCommit(): void {
    /* nothing observable survives a reset */
  }
}

/** OVER-STRICT — the same tumbling accounting with a budget of ONE activation per epoch. */
class SingleActivationPerEpoch extends Semantics {
  readonly name = "tumbling with B = MAX (over-strict)";
  readonly storageWords = 2;
  readonly worstCaseWork = "constant";
  readonly resetBehaviour = "as the kernel, with half the budget";
  windowStart = 0;
  used = 0;
  protected account(t: number): Verdict {
    const rolled = t >= this.windowStart + WINDOW;
    const used = rolled ? 0 : this.used;
    return used + MAX > MAX ? refuse("ContainmentBudget") : ADMIT;
  }
  protected onCommit(t: number): void {
    if (t >= this.windowStart + WINDOW) {
      this.windowStart = t;
      this.used = 0;
    }
    this.used += MAX;
  }
}

type Factory = () => Semantics;
const CANDIDATES = {
  tumbling: () => new TumblingAsImplemented(),
  rolling: () => new RollingBudget(),
  ring: () => new TwoStartRing(),
  bucket: () => new TokenBucket(),
  cooldown: () => new Cooldown(),
  permissive: () => new ResetEveryTrigger(),
  overstrict: () => new SingleActivationPerEpoch(),
} satisfies Record<string, Factory>;
type CandidateKey = keyof typeof CANDIDATES;

// ---------------------------------------------------------------------------
// Metrics over a set of episode starts (each [s, s+MAX)).
// ---------------------------------------------------------------------------

/** Longest run of episodes with no uncontained instant between them (gap <= tolerance seconds). Returns the CONTAINED time in that run. */
function maxContinuous(starts: readonly number[], tolerance = 0): number {
  const s = [...starts].sort((a, b) => a - b);
  let best = 0;
  let runContained = 0;
  let runEnd = Number.NEGATIVE_INFINITY;
  for (const start of s) {
    if (start - runEnd <= tolerance) runContained += MAX;
    else runContained = MAX;
    runEnd = start + MAX;
    best = Math.max(best, runContained);
  }
  return best;
}

/** Maximum contained time inside ANY half-open window [a, a+W). The overlap function is piecewise linear in a, so its maximum is at a breakpoint. */
function maxInAnyWindow(starts: readonly number[], W = WINDOW): number {
  const breakpoints = new Set<number>();
  for (const s of starts) for (const b of [s, s + MAX, s - W, s + MAX - W]) breakpoints.add(b);
  let best = 0;
  for (const a of breakpoints) {
    let total = 0;
    for (const s of starts) total += Math.max(0, Math.min(s + MAX, a + W) - Math.max(s, a));
    best = Math.max(best, total);
  }
  return best;
}

/**
 * Earliest instant >= from at which `model` admits an entry, or null within the horizon.
 * For a FIXED state every candidate's admissibility is monotone in t (history only ages
 * out, buckets only refill, cooldowns only elapse, epochs only expire), which is what
 * makes a bracket-and-bisect search exact to the second. Monotonicity is asserted.
 */
function nextAdmissible(model: Semantics, from: number, horizon: number): number | null {
  if (model.decide(from).admit) return from;
  let lo = from; // refused
  let step = 1;
  while (!model.decide(lo + step).admit) {
    lo += step;
    step *= 2;
    if (lo + step > horizon) return null;
  }
  let hi = lo + step; // admitted
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (model.decide(mid).admit) hi = mid;
    else lo = mid;
  }
  if (model.decide(lo).admit || !model.decide(hi).admit)
    throw new Error(model.name + ": admissibility is not monotone near " + hi);
  return hi;
}

interface PlanResult {
  starts: number[];
  /** For each activation after the first: the earliest admissible instant, the instant actually used, and the refusal one second before the earliest. */
  steps: { earliest: number; at: number; refusalJustBefore: string }[];
}

/**
 * The adversary's strategy space. A1 fires at t0. Each later activation fires at the
 * EARLIEST admissible instant plus a chosen delay — delaying is the only freedom an
 * always-eventually-acting adversary has, so a grid over delays covers the space.
 */
function runPlan(factory: Factory, t0: number, delays: readonly number[], horizon = 400 * DAY): PlanResult {
  const model = factory();
  model.commit(t0);
  const steps: PlanResult["steps"] = [];
  for (const d of delays) {
    const earliest = nextAdmissible(model, model.starts[model.starts.length - 1]! + MAX, t0 + horizon);
    if (earliest === null) break;
    const at = earliest + d;
    steps.push({ earliest, at, refusalJustBefore: model.decide(earliest - 1).reason });
    model.commit(at);
  }
  return { starts: [...model.starts], steps };
}

/** Exhaustive search over a delay grid. Returns the best Q2 and Q1-in-window values and the plans that achieve them. */
function searchDelays(factory: Factory, t0: number, grid: readonly number[], free: number) {
  let bestContinuous = 0;
  let bestWindow = 0;
  const argmaxContinuous: number[][] = [];
  const argmaxWindow: number[][] = [];
  let plans = 0;
  const rec = (prefix: number[]): void => {
    if (prefix.length === free) {
      plans += 1;
      const r = runPlan(factory, t0, prefix);
      const c = maxContinuous(r.starts);
      const wnd = maxInAnyWindow(r.starts);
      if (c > bestContinuous) {
        bestContinuous = c;
        argmaxContinuous.length = 0;
      }
      if (c === bestContinuous) argmaxContinuous.push(prefix);
      if (wnd > bestWindow) {
        bestWindow = wnd;
        argmaxWindow.length = 0;
      }
      if (wnd === bestWindow) argmaxWindow.push(prefix);
      return;
    }
    for (const d of grid) rec([...prefix, d]);
  };
  rec([]);
  return { bestContinuous, bestWindow, argmaxContinuous, argmaxWindow, plans };
}

const fmtDays = (s: number): string => (s / DAY).toFixed(s % DAY === 0 ? 0 : 5) + "d";

// ---------------------------------------------------------------------------
// AST census helpers — every claim about writers, readers and gates comes from the
// compiler's own tree, never from text or from memory of the source.
// ---------------------------------------------------------------------------

type Visitor = (node: AstNode, parent: AstNode | null) => void;
function visit(node: AstNode, f: Visitor, parent: AstNode | null = null): void {
  if (node === null || node === undefined || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const n of node) visit(n, f, parent);
    return;
  }
  if (typeof node.nodeType === "string") f(node, parent);
  for (const k of Object.keys(node)) {
    if (k === "src" || k === "nameLocation" || k === "typeDescriptions") continue;
    const v = node[k];
    if (v !== null && typeof v === "object") visit(v, f, typeof node.nodeType === "string" ? node : parent);
  }
}

const functionsOf = (contract: AstNode): AstNode[] =>
  (contract.nodes as AstNode[]).filter((n) => n.nodeType === "FunctionDefinition" && n.kind === "function");

function stateVariable(contract: AstNode, name: string): AstNode {
  const hit = (contract.nodes as AstNode[]).find(
    (n) => n.nodeType === "VariableDeclaration" && n.stateVariable === true && n.name === name,
  );
  if (!hit) throw new Error("state variable " + name + " not found");
  return hit;
}

interface Access {
  writes: Record<string, number>;
  reads: Record<string, number>;
  deletes: Record<string, number>;
}

/** Writers and readers of one state variable, attributed to the function whose body contains them. */
function accessCensus(contract: AstNode, declId: number): Access {
  const out: Access = { writes: {}, reads: {}, deletes: {} };
  const bump = (m: Record<string, number>, fn: string): void => {
    m[fn] = (m[fn] ?? 0) + 1;
  };
  const refersTo = (n: AstNode): boolean => n?.nodeType === "Identifier" && n.referencedDeclaration === declId;
  for (const fn of functionsOf(contract)) {
    const lhsIds = new Set<number>();
    visit(fn.body, (n) => {
      if (n.nodeType === "Assignment" && refersTo(n.leftHandSide)) {
        lhsIds.add(n.leftHandSide.id);
        bump(out.writes, fn.name);
        if (n.operator !== "=") bump(out.reads, fn.name); // a compound assignment reads too
      }
      if (n.nodeType === "UnaryOperation" && n.operator === "delete" && refersTo(n.subExpression))
        bump(out.deletes, fn.name);
    });
    visit(fn.body, (n) => {
      if (refersTo(n) && !lhsIds.has(n.id)) bump(out.reads, fn.name);
    });
  }
  return out;
}

/** Names of functions called (directly) inside `fn`'s body. */
function calleesOf(fn: AstNode): string[] {
  const names: string[] = [];
  visit(fn.body, (n) => {
    if (n.nodeType !== "FunctionCall" || n.kind !== "functionCall") return;
    const e = n.expression;
    if (e?.nodeType === "Identifier") names.push(e.name);
    else if (e?.nodeType === "MemberAccess") names.push(e.memberName);
  });
  return names;
}

/** Functions whose body assigns `safeState = SafeState.<member>`. */
function safeStateAssigners(contract: AstNode, member: string): string[] {
  const out: string[] = [];
  for (const fn of functionsOf(contract)) {
    visit(fn.body, (n) => {
      if (n.nodeType === "Assignment" && n.leftHandSide?.name === "safeState" && n.rightHandSide?.memberName === member)
        out.push(fn.name);
    });
  }
  return out;
}

const isExternalMutator = (fn: AstNode): boolean =>
  (fn.visibility === "external" || fn.visibility === "public") &&
  (fn.stateMutability === "nonpayable" || fn.stateMutability === "payable");

// ===========================================================================

describe("vNext kernel — SD-2 ADJUDICATION: containment-budget accounting re-derived from the executable kernel", function () {
  this.timeout(1_800_000);

  before(function () {
    const bytes = assertPreSd2FixtureIdentity();
    console.log("      frozen pre-remediation kernel: blob " + PRE_SD2_KERNEL_BLOB + ", sha256 " + PRE_SD2_KERNEL_SHA256 + ", " + bytes.length + " bytes");
  });

  // -------------------------------------------------------------------------
  describe("A. MECHANISM — the containment state machine from the compiler's AST and the deployed constants", function () {
    let kernel: AstNode;
    let byName: Record<string, AstNode>;

    before(function () {
      const out = compileMutatedKernel({ "VaultKernelPrototype.sol": preSd2Source() });
      if (!out.ok) throw new Error("frozen kernel AST compile failed: " + out.errors.join(";"));
      kernel = findContract(out.compiled, "VaultKernelPrototype");
      byName = Object.fromEntries(functionsOf(kernel).map((f) => [f.name, f]));
    });

    it("A1 — the four containment words have exactly these writers: safeState by four transitions, the three budget words by enterContainment alone", function () {
      const safeState = accessCensus(kernel, stateVariable(kernel, "safeState").id);
      expect(safeState.writes, "safeState writers").to.deep.equal({
        initialize: 1,
        enterContainment: 1,
        bindMigration: 1,
        retire: 1,
      });
      expect(safeState.deletes, "safeState is never deleted").to.deep.equal({});

      const until = accessCensus(kernel, stateVariable(kernel, "containedUntil").id);
      expect(until.writes, "containedUntil writers").to.deep.equal({ enterContainment: 1 });
      expect(until.deletes).to.deep.equal({});

      const origin = accessCensus(kernel, stateVariable(kernel, "containmentWindowStart").id);
      expect(origin.writes, "containmentWindowStart writers").to.deep.equal({ enterContainment: 1 });
      expect(origin.deletes).to.deep.equal({});

      const used = accessCensus(kernel, stateVariable(kernel, "containmentUsedInWindow").id);
      expect(used.writes, "containmentUsedInWindow writers: the reset and the charge").to.deep.equal({
        enterContainment: 2,
      });
      expect(used.deletes).to.deep.equal({});
    });

    it("A2 — exit is AUTOMATIC: containedUntil is read only by _effectiveState, and no function ever writes safeState back to NORMAL after genesis", function () {
      const until = accessCensus(kernel, stateVariable(kernel, "containedUntil").id);
      expect(until.reads, "containedUntil readers").to.deep.equal({ _effectiveState: 1 });
      // The only NORMAL assignment is genesis. Every other exit from CONTAINED is the
      // derived view `_effectiveState`, evaluated at read time with no principal acting.
      expect(safeStateAssigners(kernel, "NORMAL"), "assignments of SafeState.NORMAL").to.deep.equal(["initialize"]);
      expect(safeStateAssigners(kernel, "CONTAINED"), "assignments of SafeState.CONTAINED").to.deep.equal([
        "enterContainment",
      ]);
      // And nothing reads the budget words except the function that writes them.
      expect(accessCensus(kernel, stateVariable(kernel, "containmentWindowStart").id).reads).to.deep.equal({
        enterContainment: 1,
      });
      expect(accessCensus(kernel, stateVariable(kernel, "containmentUsedInWindow").id).reads).to.deep.equal({
        enterContainment: 2,
      });
    });

    it("A3 — the action matrix: what containment WITHDRAWS (five credential/quorum mutations) and what it LEAVES LIVE (all four recovery actions, migration binding, retire, egress)", function () {
      const gatedNormal: string[] = [];
      const gatedRecoveryOpen: string[] = [];
      const ungated: string[] = [];
      for (const fn of functionsOf(kernel).filter(isExternalMutator)) {
        const callees = calleesOf(fn);
        if (callees.includes("_requireNormal")) gatedNormal.push(fn.name);
        else if (callees.includes("_requireRecoveryOpen")) gatedRecoveryOpen.push(fn.name);
        else ungated.push(fn.name);
      }
      expect(gatedNormal.sort(), "withdrawn under CONTAINED (need effective NORMAL)").to.deep.equal(
        ["execute", "rotateCredential", "setGuardians", "setPolicy", "setVerifier"].sort(),
      );
      expect(gatedRecoveryOpen.sort(), "live under CONTAINED (refuse only MIGRATION_ONLY/RETIRED)").to.deep.equal(
        ["cancelRecovery", "cancelRecoveryByQuorum", "executeRecovery", "initiateRecovery"].sort(),
      );
      // The remaining mutators carry their own gates, none of which mentions CONTAINED.
      expect(ungated.sort()).to.deep.equal(
        ["bindMigration", "egress", "enterContainment", "initialize", "retire"].sort(),
      );
      expect(
        calleesOf(byName.bindMigration!),
        "bindMigration consults effective state itself (RETIRED only)",
      ).to.include("_effectiveState");
      expect(calleesOf(byName.retire!), "retire never consults safe state").to.not.include("_effectiveState");
      expect(calleesOf(byName.egress!), "egress never consults safe state").to.not.include("_effectiveState");
    });

    it("A4 — AUTHORIZATION: the one entry path is a fresh k-of-n quorum over a consumed guardian-domain nonce, gated on effective NORMAL first", function () {
      const fn = byName.enterContainment!;
      const callees = calleesOf(fn);
      expect(callees, "quorum is required").to.include("_requireQuorum");
      expect(callees, "a nonce is consumed").to.include("_consume");
      expect(callees, "effective state is consulted").to.include("_effectiveState");
      expect(callees, "no credential authorisation is involved").to.not.include("_authorise");
      expect(callees).to.not.include("_floorAuthorises");
      let consumeDomain: string | null = null;
      let timestampReads = 0;
      visit(fn.body, (n) => {
        if (n.nodeType === "FunctionCall" && n.expression?.name === "_consume")
          consumeDomain = n.arguments?.[0]?.name ?? null;
        if (n.nodeType === "MemberAccess" && n.memberName === "timestamp" && n.expression?.name === "block")
          timestampReads += 1;
      });
      expect(consumeDomain, "the guardian nonce domain").to.equal("DOMAIN_GUARDIAN");
      expect(timestampReads, "one wall-clock read feeds origin, expiry and rollover").to.equal(1);
      // Statement order: the effective-state gate PRECEDES quorum and nonce, which both
      // PRECEDE the accounting, so a refused attempt burns nothing (executable in B3/B8).
      const stmts = (fn.body.statements as AstNode[]).map((s: AstNode) => JSON.stringify(s));
      const idx = (needle: string): number => stmts.findIndex((s) => s.includes(needle));
      expect(idx("_effectiveState")).to.be.at.least(0);
      expect(idx("_effectiveState")).to.be.lessThan(idx("_requireQuorum"));
      expect(idx("_requireQuorum")).to.be.lessThan(idx("_consume"));
      expect(idx("_consume")).to.be.lessThan(idx("ContainmentBudget"));
    });

    it("A5 — the deployed constants: MAX 3d, W 30d, B 6d; B < W; B is EXACTLY two whole activations; the recovery delay (7d) exceeds B", async function () {
      const w = await deployWorld({ label: "sd2-consts" });
      expect(Number(await w.vault.CONTAINMENT_MAX())).to.equal(MAX);
      expect(Number(await w.vault.CONTAINMENT_WINDOW())).to.equal(WINDOW);
      expect(Number(await w.vault.CONTAINMENT_BUDGET())).to.equal(BUDGET);
      expect(BUDGET, "B < W").to.be.lessThan(WINDOW);
      expect(BUDGET % MAX, "the budget is a whole number of activations").to.equal(0);
      expect(BUDGET / MAX, "exactly two activations per accounting epoch").to.equal(2);
      expect(Number(await w.vault.RECOVERY_DELAY()), "RECOVERY_DELAY").to.equal(7 * DAY);
      expect(7 * DAY, "one accounting epoch's budget cannot cover one recovery delay").to.be.greaterThan(BUDGET);
      // Genesis leaves the accounting words at zero, so the very first activation is
      // itself a rollover: origin := now, used := 0.
      const s = await containmentState(w);
      expect(s).to.include({ stored: SAFE.NORMAL, effective: SAFE.NORMAL, until: 0, windowStart: 0, used: 0 });
    });

    it("A6 — the kernel exposes NO emergency-principal trigger: the architecture's 'emergency principal, or guardian quorum' resolves to the quorum alone", function () {
      // Every path to CONTAINED is enterContainment (A2), whose only authorisation is
      // _requireQuorum (A4). No state variable or function names a second trigger.
      const stateNames = (kernel.nodes as AstNode[])
        .filter((n) => n.nodeType === "VariableDeclaration" && n.stateVariable)
        .map((n) => String(n.name).toLowerCase());
      const fnNames = functionsOf(kernel).map((f) => String(f.name).toLowerCase());
      const suspicious = [...stateNames, ...fnNames].filter(
        (n) => n.includes("emergency") || n.includes("trigger") || n.includes("adapter"),
      );
      expect(suspicious).to.deep.equal([]);
    });
  });

  // -------------------------------------------------------------------------
  describe("B. REPRODUCTION — the boundary searched mechanically, then executed on the exact kernel at exact legal timestamps", function () {
    /** Delays after the earliest admissible instant, in seconds. 24d is what pushes A2 to the end of epoch 1. */
    const GRID = [
      0,
      1,
      3600,
      1 * DAY,
      2 * DAY,
      3 * DAY,
      6 * DAY,
      12 * DAY,
      20 * DAY,
      23 * DAY,
      24 * DAY - 1,
      24 * DAY,
      24 * DAY + 1,
      25 * DAY,
      26 * DAY,
      27 * DAY - 1,
      27 * DAY,
      27 * DAY + 1,
      28 * DAY,
      30 * DAY - 1,
      30 * DAY,
      33 * DAY,
    ];
    const T0_MODEL = 1_000_000 * DAY; // any instant far past the zero origin, like every real chain

    it("B1 — MECHANICAL SEARCH (tumbling model, 4 activations, 3 free delays): max continuous = B + MAX = 9d, achieved exactly when A2 fires in the last MAX of epoch 1", function () {
      const r = searchDelays(CANDIDATES.tumbling, T0_MODEL, GRID, 3);
      console.log(
        "      tumbling search: " +
          r.plans +
          " plans; max continuous " +
          fmtDays(r.bestContinuous) +
          "; max in any 30d window " +
          fmtDays(r.bestWindow),
      );
      expect(r.bestContinuous, "Q2 max continuous").to.equal(BUDGET + MAX);
      expect(r.bestWindow, "Q1 max inside one rolling W").to.equal(BUDGET + MAX);
      // The argmax set for CONTINUOUS denial: A2 delayed by d in [24d, 27d), i.e. A2 at
      // T0 + [27d, 30d) so it ends at or after the epoch boundary; A3 and A4 immediate.
      const firstDelays = new Set(r.argmaxContinuous.map((p) => p[0]!));
      for (const d of firstDelays) {
        expect(d, "A2 delay in the argmax set is at least 24d").to.be.at.least(24 * DAY);
        expect(d, "and below 27d (at 27d A2 itself opens the new epoch)").to.be.lessThan(27 * DAY);
      }
      expect(firstDelays.has(24 * DAY - 1), "23d 23:59:59 is NOT in the argmax set").to.equal(false);
      expect(firstDelays.has(24 * DAY), "exactly 24d IS").to.equal(true);
      expect(firstDelays.has(26 * DAY), "26d IS (A2 straddles the boundary)").to.equal(true);
      expect(firstDelays.has(27 * DAY - 1), "27d - 1s IS").to.equal(true);
      expect(firstDelays.has(27 * DAY), "27d is NOT (A2 becomes the new epoch's first activation)").to.equal(false);
      for (const p of r.argmaxContinuous)
        expect(p.slice(1), "A3 and A4 fire immediately in every argmax plan").to.deep.equal([0, 0]);
      // The Q1 argmax set is WIDER: any A2 delay in [3d, 27d) already puts three
      // episodes inside one 30-day window, contiguous or not.
      const q1FirstDelays = [...new Set(r.argmaxWindow.map((p) => p[0]!))].sort((a, b) => a - b);
      expect(q1FirstDelays[0]!, "Q1 = 9d already from an A2 delay of 3d").to.equal(3 * DAY);
      expect(q1FirstDelays.includes(12 * DAY), "non-contiguous 9d-in-window at 12d").to.equal(true);
    });

    it("B1b — with a FOURTH free delay the maximum does not grow: 9d is the ceiling of the tumbling accounting, not of the search depth", function () {
      const coarse = GRID.filter((d) => d === 0 || d === 1 || d >= 3 * DAY);
      const r = searchDelays(CANDIDATES.tumbling, T0_MODEL, coarse, 4);
      console.log(
        "      tumbling search, 5 activations: " +
          r.plans +
          " plans; max continuous " +
          fmtDays(r.bestContinuous) +
          "; max in window " +
          fmtDays(r.bestWindow),
      );
      expect(r.bestContinuous).to.equal(BUDGET + MAX);
      expect(r.bestWindow).to.equal(BUDGET + MAX);
    });

    it("B1c — the same search on the PUBLISHED rolling semantics caps both quantities at B = 6d", function () {
      const r = searchDelays(CANDIDATES.rolling, T0_MODEL, GRID, 3);
      expect(r.bestContinuous, "rolling: continuous").to.equal(BUDGET);
      expect(r.bestWindow, "rolling: any window").to.equal(BUDGET);
    });

    // The maximal construction, executed on the real kernel.
    let w: World;
    let T0: number;
    /** Every mined containment transaction of the maximal construction: instant, nonce, block. */
    const ledger: {
      label: string;
      at: number;
      nonce: bigint;
      block: number;
      until: number;
      windowStart: number;
      used: number;
    }[] = [];
    let authorityBefore: Awaited<ReturnType<typeof authorityState>>;

    async function logContain(label: string, t: number, opts: ContainOptions = {}): Promise<Probe> {
      const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const p = await containAt(w, t, opts);
      if (p.ok) {
        const s = await containmentState(w);
        ledger.push({
          label,
          at: p.at,
          nonce,
          block: (await ethers.provider.getBlock("latest"))!.number,
          until: s.until,
          windowStart: s.windowStart,
          used: s.used,
        });
      }
      return p;
    }

    before(async function () {
      w = await deployWorld({ label: "sd2-repro" });
      T0 = (await latest()) + DAY;
      authorityBefore = await authorityState(w);
    });

    it("B2 — THE MAXIMUM ON THE EXACT KERNEL: A1@T0, A2@T0+27d, A3@T0+30d, A4@T0+33d — nine contiguous days, four quorum acts, exact instants", async function () {
      expect((await logContain("A1", T0)).ok, "A1 opens epoch 1 (origin := T0)").to.equal(true);
      let s = await containmentState(w);
      expect(s).to.include({
        windowStart: T0,
        used: MAX,
        until: T0 + MAX,
        stored: SAFE.CONTAINED,
        effective: SAFE.CONTAINED,
      });

      // Between A1's expiry and the end of the epoch the adversary WAITS: the budget is
      // spent late on purpose so that its second episode ends at the epoch boundary.
      expect((await logContain("A2", T0 + 27 * DAY)).ok, "A2 at T0+27d, still epoch 1").to.equal(true);
      s = await containmentState(w);
      expect(s).to.include({ windowStart: T0, used: BUDGET, until: T0 + 30 * DAY });
      const contiguousFrom = T0 + 27 * DAY;

      // A3 at the very instant A2 expires, which is also the very instant the epoch
      // rolls: origin := now, used := 0. No gap, no discretion.
      const a3 = await logContain("A3", T0 + 30 * DAY);
      expect(a3.ok, "A3 at T0+30d: " + a3.reason).to.equal(true);
      s = await containmentState(w);
      expect(s, "the origin JUMPED to the activation instant and the counter restarted").to.include({
        windowStart: T0 + 30 * DAY,
        used: MAX,
        until: T0 + 33 * DAY,
      });

      const a4 = await logContain("A4", T0 + 33 * DAY);
      expect(a4.ok, "A4 at T0+33d: " + a4.reason).to.equal(true);
      s = await containmentState(w);
      expect(s).to.include({ windowStart: T0 + 30 * DAY, used: BUDGET, until: T0 + 36 * DAY });

      const contiguousTo = s.until;
      const continuous = contiguousTo - contiguousFrom;
      console.log(
        "      measured continuous denial on the kernel: " +
          fmtDays(continuous) +
          " [" +
          contiguousFrom +
          ", " +
          contiguousTo +
          ") against I-CONTAINMENT-BUDGET's B = " +
          fmtDays(BUDGET),
      );
      expect(continuous, "Q2 on the kernel").to.equal(BUDGET + MAX);
      expect(maxContinuous(ledger.map((e) => e.at)), "computed from the mined instants").to.equal(BUDGET + MAX);
      expect(
        maxInAnyWindow(ledger.map((e) => e.at)),
        "Q1 inside one rolling 30d window, from the mined instants",
      ).to.equal(BUDGET + MAX);
      // Every episode was exactly MAX and every activation was a distinct nonce.
      expect(ledger.map((e) => e.until - e.at)).to.deep.equal([MAX, MAX, MAX, MAX]);
      expect(ledger.map((e) => e.nonce)).to.deep.equal([0n, 1n, 2n, 3n]);
      for (const e of ledger) {
        console.log(
          "        " +
            e.label +
            " block " +
            e.block +
            " t=" +
            e.at +
            " (T0+" +
            fmtDays(e.at - T0) +
            ") nonce " +
            e.nonce +
            " -> until T0+" +
            fmtDays(e.until - T0) +
            ", origin T0+" +
            fmtDays(e.windowStart - T0) +
            ", used " +
            fmtDays(e.used),
        );
      }
    });

    it("B3 — no-extension is enforced as a REVERT (BadState), not the documented no-op, and it burns no nonce", async function () {
      // Still inside A4's episode. A fifth attempt is refused before quorum or nonce are examined.
      const before = await containmentState(w);
      const p = await containAt(w, T0 + 34 * DAY);
      expect(p.ok).to.equal(false);
      expect(p.reason).to.equal("BadState");
      const after = await containmentState(w);
      expect(after.guardianNonce, "nonce not consumed").to.equal(before.guardianNonce);
      expect(after.until, "expiry not moved").to.equal(before.until);
    });

    it("B4 — RENEWABILITY: after the maximal chain the vault is FORCED uncontained for 24 days; the next epoch opens at exactly T0+60d", async function () {
      // Epoch 2 = [T0+30d, T0+60d) with its budget spent by T0+36d.
      const early = await branch(() => containAt(w, T0 + 60 * DAY - 1));
      expect(early.ok).to.equal(false);
      expect(early.reason, "one second before the epoch ends the budget still binds").to.equal("ContainmentBudget");
      const spendGap = await branch(() => spendAt(w, T0 + 48 * DAY));
      expect(spendGap.ok, "and spending is live throughout the forced gap: " + spendGap.reason).to.equal(true);
      const onTime = await branch(() => containAt(w, T0 + 60 * DAY));
      expect(onTime.ok, "at T0+60d a new epoch opens").to.equal(true);
      // Minimum forced gap after a maximal chain: 60d - 36d.
      expect(60 * DAY - 36 * DAY).to.equal(WINDOW - BUDGET);
    });

    it("B5 — the PRE-SIGNED variant: all four quorum attestations produced in one signing session and RELAYED by an outsider at the right instants (relayer holds nothing)", async function () {
      await branch(async () => {
        const w2 = await deployWorld({ label: "sd2-presigned" });
        const t0 = (await latest()) + DAY;
        const n0 = (await w2.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
        // Four digests, four consecutive nonces, one session. Nothing else must consume
        // a guardian nonce in between, and the roster generation must not move.
        const pre = await Promise.all(
          [0n, 1n, 2n, 3n].map(async (k) => ({ nonce: n0 + k, proof: quorum(w2, await containDigest(w2, n0 + k)) })),
        );
        const instants = [t0, t0 + 27 * DAY, t0 + 30 * DAY, t0 + 33 * DAY];
        for (let i = 0; i < 4; i += 1) {
          const p = await containAt(w2, instants[i]!, { sender: w2.outsider, preSigned: pre[i]! });
          expect(p.ok, "relayed A" + (i + 1) + ": " + p.reason).to.equal(true);
        }
        expect(maxContinuous(instants)).to.equal(BUDGET + MAX);
        // A single-seat attestation never gets there: k = 2 is binding on every act.
        const lone = await containAt(w2, t0 + 60 * DAY, { seats: [0] });
        expect(lone.ok).to.equal(false);
        expect(lone.reason).to.equal("QuorumNotMet");
      });
    });

    it("B6 — UNAUTHORISED PRINCIPALS gain nothing: an outsider, the credential and a stale-generation quorum are all refused; only a fresh quorum enters", async function () {
      await branch(async () => {
        const w3 = await deployWorld({ label: "sd2-unauth" });
        const t0 = (await latest()) + DAY;
        // An outsider with no attestations.
        const none = await sendAt(w3, t0, () =>
          (w3.vault.connect(w3.outsider) as ethers.Contract).enterContainment(
            { members: w3.guardians, isContract: w3.guardianIsContract, attestingIndices: [], attestations: [] },
            0n,
            FAR_DEADLINE,
            MINED,
          ),
        );
        expect(none.ok).to.equal(false);
        expect(none.reason).to.equal("QuorumNotMet");
        // The spending credential signing as if it were two guardians: wrong signers.
        const d = await containDigest(w3, 0n);
        const asCred = await sendAt(w3, t0 + 1, () =>
          w3.vault.enterContainment(
            {
              members: w3.guardians,
              isContract: w3.guardianIsContract,
              attestingIndices: [0, 1],
              attestations: [sign(w3.credKey, d), sign(w3.pqKey, d)],
            },
            0n,
            FAR_DEADLINE,
            MINED,
          ),
        );
        expect(asCred.ok).to.equal(false);
        expect(asCred.reason).to.equal("QuorumNotMet");
        // A proof signed over the WRONG guardian generation dies before its nonce.
        const stale = digestOf({
          chainId: w3.chainId,
          vault: w3.vaultAddress,
          kernelGeneration: 1n,
          actionType: ACTION.RECOVER,
          authorityGeneration: 7n,
          params: ethers.id("CONTAIN"),
          domain: DOMAIN.GUARDIAN,
          nonce: 0n,
          deadline: FAR_DEADLINE,
        });
        const wrongGen = await sendAt(w3, t0 + 2, () =>
          w3.vault.enterContainment(quorum(w3, stale), 0n, FAR_DEADLINE, MINED),
        );
        expect(wrongGen.ok).to.equal(false);
        expect(wrongGen.reason).to.equal("QuorumNotMet");
        // Positive control on the same vault: the real quorum enters at once.
        const real = await containAt(w3, t0 + 3);
        expect(real.ok, real.reason).to.equal(true);
        // Nothing any of the refused callers did moved the accounting words.
        const s = await containmentState(w3);
        expect(s).to.include({ windowStart: t0 + 3, used: MAX, until: t0 + 3 + MAX });
      });
    });

    it("B7 — BOUNDARY CONTROLS around the rollover (fresh vault): budget binds at T0+30d-1 (ContainmentBudget), lifts at exactly T0+30d; re-entry refused at until-1 (BadState), admitted at until", async function () {
      await branch(async () => {
        const wb = await deployWorld({ label: "sd2-boundary" });
        const t0 = (await latest()) + DAY;
        expect((await containAt(wb, t0)).ok).to.equal(true);
        // A2 at +26d ends at +29d: this leaves one uncontained day BEFORE the rollover in
        // which the budget, not the state, is what refuses.
        const a2 = await containAt(wb, t0 + 26 * DAY);
        expect(a2.ok).to.equal(true);
        // Contiguity boundary on A2 itself.
        const tooEarly = await branch(() => containAt(wb, t0 + 29 * DAY - 1));
        expect(tooEarly.reason, "one second before expiry: still CONTAINED").to.equal("BadState");
        const atExpiry = await branch(() => containAt(wb, t0 + 29 * DAY));
        expect(
          atExpiry.ok,
          "at the expiry instant the vault is effectively NORMAL, and the budget refuses instead",
        ).to.equal(false);
        expect(atExpiry.reason).to.equal("ContainmentBudget");
        // Rollover boundary.
        const beforeRoll = await branch(() => containAt(wb, t0 + 30 * DAY - 1));
        expect(beforeRoll.ok).to.equal(false);
        expect(beforeRoll.reason, "NEGATIVE control: T0+30d-1").to.equal("ContainmentBudget");
        const atRoll = await containAt(wb, t0 + 30 * DAY);
        expect(atRoll.ok, "POSITIVE control: T0+30d exactly: " + atRoll.reason).to.equal(true);
        const s = await containmentState(wb);
        expect(s).to.include({ windowStart: t0 + 30 * DAY, used: MAX });
        // Contiguity boundary on the new epoch's first episode, at the second.
        const gapProbe = await branch(() => containAt(wb, t0 + 33 * DAY - 1));
        expect(gapProbe.reason).to.equal("BadState");
        const contiguous = await containAt(wb, t0 + 33 * DAY);
        expect(contiguous.ok, "the second epoch-2 activation lands with zero gap").to.equal(true);
      });
    });

    it("B8 — WITHIN-EPOCH CONTROL: the budget really binds inside one epoch (A3 at T0+6d is refused), so the kernel is not simply permissive", async function () {
      await branch(async () => {
        const wc = await deployWorld({ label: "sd2-inepoch" });
        const t0 = (await latest()) + DAY;
        expect((await containAt(wc, t0)).ok).to.equal(true);
        expect((await containAt(wc, t0 + 3 * DAY)).ok, "the legitimate second activation, back to back").to.equal(true);
        const third = await containAt(wc, t0 + 6 * DAY);
        expect(third.ok).to.equal(false);
        expect(third.reason).to.equal("ContainmentBudget");
        expect(maxContinuous([t0, t0 + 3 * DAY]), "greedy from the epoch start yields exactly B").to.equal(BUDGET);
        const s = await containmentState(wc);
        expect(s.used, "a refused attempt writes nothing").to.equal(BUDGET);
        expect(s.guardianNonce, "and burns no nonce").to.equal(2n);
      });
    });

    it("B9 — SEQUENCER DISCRETION IS NOT NEEDED: a +1s slack at every step still yields 9d contained with 1s gaps; a straddling A2 (T0+29d) yields 9d strictly contiguous", async function () {
      await branch(async () => {
        const ws = await deployWorld({ label: "sd2-slack" });
        const t0 = (await latest()) + DAY;
        const starts = [t0, t0 + 27 * DAY + 1, t0 + 30 * DAY + 2, t0 + 33 * DAY + 3];
        for (const t of starts)
          expect((await containAt(ws, t)).ok, "slack run at T0+" + fmtDays(t - t0)).to.equal(true);
        expect(maxContinuous(starts, 0), "strictly, the 1s gaps break contiguity").to.equal(MAX);
        expect(maxContinuous(starts, 12), "at block granularity (<= 12s) it is one 9d run").to.equal(BUDGET + MAX);
        expect(maxInAnyWindow(starts), "and Q1 in a 30d window is 9d regardless").to.equal(BUDGET + MAX);
      });
      await branch(async () => {
        const wt = await deployWorld({ label: "sd2-straddle" });
        const t0 = (await latest()) + DAY;
        // A2 fires 29 days in: its episode [T0+29d, T0+32d) straddles the epoch boundary
        // at T0+30d. The remainder past the boundary is charged to NEITHER epoch.
        const starts = [t0, t0 + 29 * DAY, t0 + 32 * DAY, t0 + 35 * DAY];
        for (const t of starts)
          expect((await containAt(wt, t)).ok, "straddle run at T0+" + fmtDays(t - t0)).to.equal(true);
        const s = await containmentState(wt);
        expect(s, "epoch 2 opened at A3, not at the 30d mark").to.include({ windowStart: t0 + 32 * DAY, used: BUDGET });
        expect(maxContinuous(starts)).to.equal(BUDGET + MAX);
      });
    });

    it("B10 — MODEL <-> KERNEL cross-validation: on six plans the tumbling model predicts every earliest instant AND the refusal one second before it; the kernel confirms all of them", async function () {
      const plans: Record<string, number[]> = {
        greedy: [0, 0, 0],
        "mid (A2 +12d)": [12 * DAY, 0, 0],
        "max-1s": [24 * DAY - 1, 0, 0],
        max: [24 * DAY, 0, 0],
        "max+1s": [24 * DAY + 1, 0, 0],
        "late (A2 +26d)": [26 * DAY, 0, 0],
      };
      for (const [label, delays] of Object.entries(plans)) {
        await branch(async () => {
          const wx = await deployWorld({ label: "sd2-x-" + label.replace(/[^a-z0-9]/gi, "") });
          const t0 = (await latest()) + DAY;
          const predicted = runPlan(CANDIDATES.tumbling, t0, delays);
          expect((await containAt(wx, t0)).ok).to.equal(true);
          for (const step of predicted.steps) {
            const justBefore = await branch(() => containAt(wx, step.earliest - 1));
            expect(justBefore.ok, label + ": refusal predicted one second before " + step.earliest).to.equal(false);
            expect(justBefore.reason, label + ": refusal REASON predicted").to.equal(step.refusalJustBefore);
            if (step.at !== step.earliest) {
              const atEarliest = await branch(() => containAt(wx, step.earliest));
              expect(atEarliest.ok, label + ": the predicted earliest instant is admitted").to.equal(true);
            }
            const real = await containAt(wx, step.at);
            expect(real.ok, label + ": planned activation admitted at " + step.at + " (" + real.reason + ")").to.equal(
              true,
            );
          }
          const kernelStarts = [t0, ...predicted.steps.map((s) => s.at)];
          console.log(
            "      plan " +
              label.padEnd(16) +
              " continuous " +
              fmtDays(maxContinuous(kernelStarts)).padEnd(6) +
              " in-window " +
              fmtDays(maxInAnyWindow(kernelStarts)),
          );
          expect(kernelStarts).to.deep.equal(predicted.starts);
        });
      }
    });

    it("B11 — the maximal construction moved NO authority: credential, verifier, roster, floor, policy and every non-guardian nonce are byte-identical", async function () {
      const after = await authorityState(w);
      expect(after).to.deep.equal(authorityBefore);
      const s = await containmentState(w);
      expect(s.guardianNonce, "exactly four guardian acts").to.equal(4n);
    });
  });

  // -------------------------------------------------------------------------
  describe("C. CONSEQUENCE — what nine days of containment actually denies, to whom, and what stays live", function () {
    let w: World;
    let T0: number;

    before(async function () {
      w = await deployWorld({ label: "sd2-conseq" });
      T0 = (await latest()) + DAY;
      for (const t of [T0, T0 + 27 * DAY, T0 + 30 * DAY, T0 + 33 * DAY])
        expect((await containAt(w, t)).ok).to.equal(true);
      // Now at T0+33d, contained until T0+36d; the chain [T0+27d, T0+36d) is in force.
    });

    it("C1 — SPENDING by the legitimate credential is denied (BadState) throughout the nine days and restored at exactly T0+36d", async function () {
      for (const t of [T0 + 33 * DAY + 1, T0 + 34 * DAY, T0 + 36 * DAY - 1]) {
        const p = await branch(() => spendAt(w, t));
        expect(p.ok, "spend at T0+" + fmtDays(t - T0)).to.equal(false);
        expect(p.reason).to.equal("BadState");
      }
      const restored = await branch(() => spendAt(w, T0 + 36 * DAY));
      expect(restored.ok, "at the expiry instant spending is live again: " + restored.reason).to.equal(true);
      // The DENIAL is symmetric: it is not a capability the quorum gains over the
      // assets, it is a capability nobody has while contained.
    });

    it("C2 — RECOVERY is untouched: initiated and challenged under containment; on a second vault a full recovery is initiated AND executed inside the nine-day chain", async function () {
      await branch(async () => {
        const init = await initiateRecoveryAt(w, T0 + 33 * DAY + 10);
        expect(init.ok, "initiateRecovery under containment: " + init.reason).to.equal(true);
        const challenge = await cancelRecoveryAt(w, T0 + 33 * DAY + 20);
        expect(
          challenge.ok,
          "the credential's bounded challenge is live under containment: " + challenge.reason,
        ).to.equal(true);
      });
      await branch(async () => {
        const w2 = await deployWorld({ label: "sd2-recovery" });
        const t0 = (await latest()) + DAY;
        for (const t of [t0, t0 + 27 * DAY]) expect((await containAt(w2, t)).ok).to.equal(true);
        // Contained [t0+27d, t0+30d). Initiate at t0+27d+1; it matures at t0+34d+1.
        const init = await initiateRecoveryAt(w2, t0 + 27 * DAY + 1);
        expect(init.ok, init.reason).to.equal(true);
        for (const t of [t0 + 30 * DAY, t0 + 33 * DAY])
          expect((await containAt(w2, t)).ok, "containment continues over a live recovery").to.equal(true);
        // Contained until t0+36d. Execute at maturity, while contained.
        const before = await containmentState(w2);
        expect(before.effective, "still CONTAINED at execution time").to.equal(SAFE.CONTAINED);
        const exec = await executeRecoveryAt(w2, t0 + 34 * DAY + 1);
        expect(exec.ok, "executeRecovery under containment: " + exec.reason).to.equal(true);
        expect(await w2.vault.ecdsaSigner(), "the guardian-approved credential is installed").to.equal(
          addrOf(w2.spareCred[0]!),
        );
        expect(Number(await w2.vault.effectiveSafeState()), "and the vault is STILL contained afterwards").to.equal(
          SAFE.CONTAINED,
        );
      });
    });

    it("C3 — MIGRATION binding is live under containment (quorum + credential), so the universal escape is never gated by the excess", async function () {
      const bind = await branch(() => bindMigrationAt(w, T0 + 34 * DAY));
      expect(bind.ok, "bindMigration under containment: " + bind.reason).to.equal(true);
    });

    it("C4 — the DENIED set is exactly the five NORMAL-gated mutations (A3): a credential act (setPolicy) and a quorum act (setGuardians) are both refused BadState during the chain", async function () {
      const credGen = (await w.vault.credentialGeneration()) as bigint;
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const t = T0 + 34 * DAY;
      const nCred = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const dPolicy = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.SET_POLICY,
        authorityGeneration: credGen,
        params: setPolicyParams(w.policies.allow),
        domain: DOMAIN.CREDENTIAL,
        nonce: nCred,
        deadline: FAR_DEADLINE,
      });
      const setPolicy = await branch(() =>
        sendAt(w, t, () =>
          w.vault.setPolicy(
            w.policies.allow,
            nCred,
            FAR_DEADLINE,
            sign(w.credKey, dPolicy),
            sign(w.pqKey, dPolicy),
            pqKeyBytes(w.pqKey),
            MINED,
          ),
        ),
      );
      expect(setPolicy.reason, "setPolicy (credential, HYBRID) under containment").to.equal("BadState");

      const nG = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const dGuard = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.SET_GUARDIANS,
        authorityGeneration: gGen,
        params: ethers.keccak256(
          abi.encode(["uint64", "address[]", "bool[]"], [2n, w.guardians, w.guardianIsContract]),
        ),
        domain: DOMAIN.GUARDIAN,
        nonce: nG,
        deadline: FAR_DEADLINE,
      });
      const setGuardians = await branch(() =>
        sendAt(w, t, () =>
          w.vault.setGuardians(2n, w.guardians, w.guardianIsContract, quorum(w, dGuard), nG, FAR_DEADLINE, MINED),
        ),
      );
      expect(
        setGuardians.reason,
        "setGuardians (quorum) under containment: the containing quorum has frozen ITSELF out of roster changes",
      ).to.equal("BadState");
    });

    it("C5 — LONG HORIZON (model, 600 days, adversary repeating the maximal chain): the duty cycle is exactly B/W = 20% under tumbling and at most that under rolling; the 9d bursts recur only after 24d forced gaps", function () {
      const horizon = 600 * DAY;
      const t0 = 1_000_000 * DAY;
      const adversary = (factory: Factory): { starts: number[]; total: number } => {
        const model = factory();
        model.commit(t0);
        for (;;) {
          const k = model.starts.length;
          const last = model.starts[k - 1]!;
          const earliest = nextAdmissible(model, last + MAX, t0 + horizon);
          if (earliest === null) break;
          // The repeating maximal pattern per epoch pair: [open, delayed to the epoch's
          // end, immediate, immediate]. The delayed one is every fourth activation.
          const at = k % 4 === 1 ? earliest + 24 * DAY : earliest;
          if (at + MAX > t0 + horizon) break;
          model.commit(at);
        }
        return { starts: [...model.starts], total: model.starts.length * MAX };
      };
      const tum = adversary(CANDIDATES.tumbling);
      const rol = adversary(CANDIDATES.rolling);
      const share = (r: { total: number }): number => r.total / horizon;
      console.log(
        "      600d adversary: tumbling " +
          tum.starts.length +
          " activations, share " +
          (share(tum) * 100).toFixed(2) +
          "%, max continuous " +
          fmtDays(maxContinuous(tum.starts)) +
          "; rolling " +
          rol.starts.length +
          " activations, share " +
          (share(rol) * 100).toFixed(2) +
          "%, max continuous " +
          fmtDays(maxContinuous(rol.starts)),
      );
      expect(share(tum), "tumbling long-run share equals B/W exactly over whole epoch pairs").to.equal(BUDGET / WINDOW);
      expect(share(rol), "rolling long-run share never exceeds B/W").to.be.at.most(BUDGET / WINDOW);
      expect(maxContinuous(tum.starts)).to.equal(BUDGET + MAX);
      expect(maxContinuous(rol.starts)).to.equal(BUDGET);
      // The excess is not renewable without the forced gap: after every three-episode
      // chain the tumbling adversary is uncontained for exactly W - B.
      const sorted = [...tum.starts].sort((a, b) => a - b);
      const gapsAfterChains: number[] = [];
      for (let i = 2; i + 1 < sorted.length; i += 1) {
        if (sorted[i]! - sorted[i - 1]! === MAX && sorted[i - 1]! - sorted[i - 2]! === MAX)
          gapsAfterChains.push(sorted[i + 1]! - (sorted[i]! + MAX));
      }
      expect(gapsAfterChains.length, "chains observed").to.be.greaterThan(5);
      expect(new Set(gapsAfterChains), "uncontained gap after every 9d chain").to.deep.equal(
        new Set([WINDOW - BUDGET]),
      );
    });
  });

  // -------------------------------------------------------------------------
  describe("D. CANDIDATE SEMANTICS — measured side by side on the same adversarial search (reference models; nothing is implemented)", function () {
    const T0 = 1_000_000 * DAY;
    const GRID = [
      0,
      1,
      3 * DAY,
      6 * DAY,
      12 * DAY,
      21 * DAY,
      24 * DAY - 1,
      24 * DAY,
      24 * DAY + 1,
      26 * DAY,
      27 * DAY - 1,
      27 * DAY,
      30 * DAY,
    ];

    interface Row {
      name: string;
      maxContinuous: number;
      maxInWindow: number;
      legitimateDouble: boolean;
      storageWords: number;
      work: string;
      reset: string;
    }
    const rows = {} as Record<CandidateKey, Row>;

    before(function () {
      for (const key of Object.keys(CANDIDATES) as CandidateKey[]) {
        const factory: Factory = CANDIDATES[key];
        const r = searchDelays(factory, T0, GRID, 3);
        const probe = factory();
        probe.commit(T0);
        const legitimateDouble = probe.decide(T0 + MAX).admit;
        const m = factory();
        rows[key] = {
          name: m.name,
          maxContinuous: r.bestContinuous,
          maxInWindow: r.bestWindow,
          legitimateDouble,
          storageWords: m.storageWords,
          work: m.worstCaseWork,
          reset: m.resetBehaviour,
        };
      }
      console.log("");
      console.log("      " + "semantics".padEnd(46) + "max continuous  max in 30d  legit 6d back-to-back  words");
      for (const r of Object.values(rows)) {
        console.log(
          "      " +
            r.name.padEnd(46) +
            fmtDays(r.maxContinuous).padEnd(16) +
            fmtDays(r.maxInWindow).padEnd(12) +
            String(r.legitimateDouble).padEnd(23) +
            r.storageWords,
        );
      }
    });

    it("D1 — the kernel's tumbling accounting: 9d continuous, 9d in a window, legitimate 6d back-to-back preserved, two words", function () {
      expect(rows.tumbling).to.include({
        maxContinuous: BUDGET + MAX,
        maxInWindow: BUDGET + MAX,
        legitimateDouble: true,
        storageWords: 2,
      });
    });

    it("D2 — candidate 1, the literal rolling budget: 6d / 6d, legitimate double preserved, two words, no reset", function () {
      expect(rows.rolling).to.include({
        maxContinuous: BUDGET,
        maxInWindow: BUDGET,
        legitimateDouble: true,
        storageWords: 2,
      });
    });

    it("D3 — candidate 5, the two-start ring, is EXTENSIONALLY IDENTICAL to the rolling budget on every plan in the grid (because B = 2*MAX exactly)", function () {
      let compared = 0;
      const rec = (prefix: number[]): void => {
        if (prefix.length === 3) {
          const a = runPlan(CANDIDATES.rolling, T0, prefix);
          const b = runPlan(CANDIDATES.ring, T0, prefix);
          expect(b.starts, "plan " + prefix.map(fmtDays).join(",")).to.deep.equal(a.starts);
          compared += 1;
          return;
        }
        for (const d of GRID) rec([...prefix, d]);
      };
      rec([]);
      expect(compared).to.equal(GRID.length ** 3);
      // The reduction is exact only because BUDGET / MAX is an integer (A5). Stated so
      // that a constants change is known to break it.
      expect(BUDGET / MAX).to.equal(2);
    });

    it("D4 — candidate 2, the token bucket, caps continuous denial at 6d but PERMITS 9d inside one 30d window (burst then refill): it does not satisfy the published invariant either", function () {
      expect(rows.bucket).to.include({ maxContinuous: BUDGET, maxInWindow: BUDGET + MAX, legitimateDouble: true });
    });

    it("D5 — candidate 3, a 12d cooldown, satisfies the window bound but FORBIDS the legitimate 6d back-to-back containment: over-strict", function () {
      expect(rows.cooldown).to.include({ maxContinuous: MAX, maxInWindow: BUDGET, legitimateDouble: false });
    });

    it("D6 — the two mutant shapes: reset-on-every-trigger is unbounded within the search; one-activation-per-epoch is over-strict", function () {
      expect(rows.permissive.maxContinuous, "4 activations, all admitted back to back").to.equal(4 * MAX);
      expect(rows.permissive.legitimateDouble).to.equal(true);
      expect(rows.overstrict).to.include({ maxContinuous: MAX, legitimateDouble: false });
    });

    it("D7 — candidate 4 (keep the kernel, restate the invariant) is the tumbling row itself; the honest statement is: per accounting epoch <= B, hence any rolling W <= B + MAX, continuous <= B + MAX, long-run <= B/W", function () {
      // A window of length W meets at most two accounting epochs (each is at least W
      // long); the earlier one can contribute at most ONE episode that ends at or after
      // the boundary, the later one at most B. Measured: B + MAX for both quantities.
      expect(rows.tumbling.maxInWindow).to.equal(BUDGET + MAX);
      expect(rows.tumbling.maxContinuous).to.equal(BUDGET + MAX);
    });

    it("D8 — NONE of the candidates changes a principal cut: accounting decides WHEN a quorum may contain, never WHO (A4 puts quorum and nonce before any accounting), and none needs more than the two words the kernel already has", function () {
      for (const r of Object.values(rows)) expect(r.storageWords, r.name).to.be.at.most(2);
    });
  });

  // -------------------------------------------------------------------------
  describe("E. ADVERSARIAL DISCRIMINATION — the kernel against reference semantics on fixed transcripts, and kernel MUTANTS killed only by the containment-admission observation", function () {
    /**
     * Two transcripts, each a fixed list of instants at which a quorum attempts entry.
     *   CHAIN     the maximal straddle, then the post-chain and next-epoch controls.
     *   IN-EPOCH  the legitimate back-to-back pair, then the within-epoch control.
     * The same instants are fed to the kernel, to every reference model and to every mutant.
     */
    type TranscriptName = "CHAIN" | "IN-EPOCH";
    const TRANSCRIPTS: Record<TranscriptName, (t0: number) => { at: number; label: string }[]> = {
      CHAIN: (t0) => [
        { at: t0, label: "A1" },
        { at: t0 + 27 * DAY, label: "A2-late" },
        { at: t0 + 30 * DAY, label: "A3-at-rollover" },
        { at: t0 + 33 * DAY, label: "A4-chain" },
        { at: t0 + 36 * DAY, label: "A5-post-chain-control" },
        { at: t0 + 60 * DAY, label: "A6-next-epoch" },
      ],
      "IN-EPOCH": (t0) => [
        { at: t0, label: "A1" },
        { at: t0 + 3 * DAY, label: "A2-back-to-back" },
        { at: t0 + 6 * DAY, label: "A3-within-epoch-control" },
      ],
    };

    interface Trace {
      /** Per step: "OK" or the refusal reason. */
      reasons: string[];
      /** Per step: admitted or not — the cross-model comparable form. */
      verdicts: boolean[];
      starts: number[];
    }

    function modelTrace(factory: Factory, name: TranscriptName, t0: number): Trace {
      const m = factory();
      const reasons: string[] = [];
      const verdicts: boolean[] = [];
      for (const step of TRANSCRIPTS[name](t0)) {
        const v = m.decide(step.at);
        if (v.admit) m.commit(step.at);
        reasons.push(v.reason);
        verdicts.push(v.admit);
      }
      return { reasons, verdicts, starts: [...m.starts] };
    }

    async function kernelTrace(wk: World, name: TranscriptName, t0: number): Promise<Trace> {
      const reasons: string[] = [];
      const verdicts: boolean[] = [];
      const starts: number[] = [];
      for (const step of TRANSCRIPTS[name](t0)) {
        const p = await containAt(wk, step.at);
        reasons.push(p.reason);
        verdicts.push(p.ok);
        if (p.ok) starts.push(step.at);
      }
      return { reasons, verdicts, starts };
    }

    const real: Record<TranscriptName, Trace> = {} as Record<TranscriptName, Trace>;
    const t0Real: Record<TranscriptName, number> = {} as Record<TranscriptName, number>;

    before(async function () {
      for (const name of Object.keys(TRANSCRIPTS) as TranscriptName[]) {
        await branch(async () => {
          const wr = await deployWorld({ label: "sd2-disc-" + name.toLowerCase() });
          t0Real[name] = (await latest()) + DAY;
          real[name] = await kernelTrace(wr, name, t0Real[name]);
          console.log(
            "      kernel " +
              name.padEnd(9) +
              " " +
              TRANSCRIPTS[name](0)
                .map((s, i) => s.label + ":" + real[name].reasons[i])
                .join("  "),
          );
        });
      }
    });

    it("E1 — the kernel equals the TUMBLING model on both transcripts, reason for reason, and exhibits the 9d observation on CHAIN", function () {
      for (const name of Object.keys(TRANSCRIPTS) as TranscriptName[]) {
        expect(real[name].reasons, name).to.deep.equal(modelTrace(CANDIDATES.tumbling, name, t0Real[name]).reasons);
      }
      expect(maxContinuous(real.CHAIN.starts)).to.equal(BUDGET + MAX);
      expect(maxContinuous(real["IN-EPOCH"].starts)).to.equal(BUDGET);
    });

    it("E2 — the kernel differs from the ROLLING model at exactly one step of CHAIN, A4-chain (kernel admits, rolling refuses): that step IS the SD-2 observation", function () {
      const rolling = modelTrace(CANDIDATES.rolling, "CHAIN", t0Real.CHAIN);
      const diffs = real.CHAIN.verdicts.map((v, i) => (v === rolling.verdicts[i] ? -1 : i)).filter((i) => i >= 0);
      expect(diffs, "differing step indices").to.deep.equal([3]);
      expect(real.CHAIN.reasons[3]).to.equal("OK");
      expect(rolling.reasons[3]).to.equal("RollingBudget");
      expect(maxContinuous(rolling.starts), "rolling caps the same transcript at B").to.equal(BUDGET);
      // And on IN-EPOCH the two agree completely: the disagreement is the straddle, nothing else.
      expect(modelTrace(CANDIDATES.rolling, "IN-EPOCH", t0Real["IN-EPOCH"]).verdicts).to.deep.equal(
        real["IN-EPOCH"].verdicts,
      );
      // Vacuity guard: the ring model (candidate 5) makes the same single distinction.
      expect(modelTrace(CANDIDATES.ring, "CHAIN", t0Real.CHAIN).verdicts).to.deep.equal(rolling.verdicts);
    });

    it("E3 — the kernel differs from the PERMISSIVE model at the within-epoch control (kernel refuses, permissive admits) and at the post-chain control", function () {
      const inEpoch = modelTrace(CANDIDATES.permissive, "IN-EPOCH", t0Real["IN-EPOCH"]);
      expect(real["IN-EPOCH"].verdicts).to.deep.equal([true, true, false]);
      expect(inEpoch.verdicts).to.deep.equal([true, true, true]);
      const chain = modelTrace(CANDIDATES.permissive, "CHAIN", t0Real.CHAIN);
      expect(real.CHAIN.verdicts[4], "kernel: post-chain control refused").to.equal(false);
      expect(chain.verdicts[4], "permissive: post-chain admitted").to.equal(true);
    });

    it("E4 — the kernel differs from both OVER-STRICT models at the legitimate back-to-back step (kernel admits, they refuse)", function () {
      expect(real["IN-EPOCH"].verdicts[1]).to.equal(true);
      for (const key of ["cooldown", "overstrict"] as const) {
        expect(modelTrace(CANDIDATES[key], "IN-EPOCH", t0Real["IN-EPOCH"]).verdicts[1], key).to.equal(false);
      }
    });

    // ------------------------- kernel mutants -------------------------------
    interface Sd2Mutant {
      id: string;
      shape: "permissive" | "over-strict" | "boundary";
      apply: (src: string) => string;
      /** The transcript and step whose verdict must FLIP relative to the real kernel, and the direction. */
      killAt: { transcript: TranscriptName; step: number; real: string; mutant: string };
    }
    const kernelSource = preSd2Source;
    const replaceOnce = (src: string, oldText: string, newText: string): string => {
      const n = src.split(oldText).length - 1;
      if (n !== 1) throw new Error("anchor matched " + n + " times: " + oldText);
      return src.replace(oldText, newText);
    };
    const MUTANTS: readonly Sd2Mutant[] = [
      {
        id: "M-SD2-RESET-EVERY-TRIGGER",
        shape: "permissive",
        apply: (s) =>
          replaceWithinFunction(
            s,
            "enterContainment",
            "if (nowTs >= containmentWindowStart + CONTAINMENT_WINDOW) {",
            "if (nowTs >= containmentWindowStart) {",
          ),
        killAt: { transcript: "IN-EPOCH", step: 2, real: "ContainmentBudget", mutant: "OK" },
      },
      {
        id: "M-SD2-NO-CHARGE",
        shape: "permissive",
        apply: (s) => replaceWithinFunction(s, "enterContainment", "containmentUsedInWindow += CONTAINMENT_MAX;", ""),
        killAt: { transcript: "IN-EPOCH", step: 2, real: "ContainmentBudget", mutant: "OK" },
      },
      {
        id: "M-SD2-ORIGIN-NEVER-MOVES",
        shape: "permissive",
        apply: (s) => replaceWithinFunction(s, "enterContainment", "containmentWindowStart = nowTs;", ""),
        // With the origin stuck at 0 every activation 'rolls' and zeroes the counter:
        // the post-chain control at T0+36d is admitted.
        killAt: { transcript: "CHAIN", step: 4, real: "ContainmentBudget", mutant: "OK" },
      },
      {
        id: "M-SD2-ROLLOVER-STRICT",
        shape: "boundary",
        apply: (s) =>
          replaceWithinFunction(
            s,
            "enterContainment",
            "if (nowTs >= containmentWindowStart + CONTAINMENT_WINDOW) {",
            "if (nowTs > containmentWindowStart + CONTAINMENT_WINDOW) {",
          ),
        // The exact-instant rollover at T0+30d is what distinguishes >= from >.
        killAt: { transcript: "CHAIN", step: 2, real: "OK", mutant: "ContainmentBudget" },
      },
      {
        id: "M-SD2-BUDGET-HALVED",
        shape: "over-strict",
        apply: (s) =>
          replaceOnce(
            s,
            "uint64 public constant CONTAINMENT_BUDGET = 6 days;",
            "uint64 public constant CONTAINMENT_BUDGET = 3 days;",
          ),
        killAt: { transcript: "IN-EPOCH", step: 1, real: "OK", mutant: "ContainmentBudget" },
      },
    ];

    it("E5 — the mutant set is closed: five ids, distinct, each naming a step of a shared transcript", function () {
      expect(MUTANTS).to.have.length(5);
      expect(new Set(MUTANTS.map((m) => m.id)).size).to.equal(5);
      for (const m of MUTANTS) expect(m.killAt.step).to.be.within(0, TRANSCRIPTS[m.killAt.transcript](0).length - 1);
    });

    for (const m of MUTANTS) {
      it(
        "E6 — " +
          m.id +
          " (" +
          m.shape +
          ") is KILLED by the containment-admission observation at " +
          m.killAt.transcript +
          " step " +
          m.killAt.step +
          ", and agrees with the kernel on every earlier step",
        async function () {
          const built = compileDeployable({ "VaultKernelPrototype.sol": m.apply(kernelSource()) });
          if (!built.ok) throw new Error(m.id + " failed to compile: " + built.errors.join(";"));
          await branch(async () => {
            const wm = await deployWorld({ label: "sd2-" + m.id.toLowerCase(), implOverride: built.kernel });
            const t0 = (await latest()) + DAY;
            // INCONCLUSIVE guard: a mutant that cannot even enter containment once proves nothing.
            const control = await branch(() => containAt(wm, t0));
            expect(control.ok, "INCONCLUSIVE: " + m.id + " cannot contain at all: " + control.reason).to.equal(true);
            const trace = await kernelTrace(wm, m.killAt.transcript, t0);
            const realTrace = real[m.killAt.transcript];
            const labels = TRANSCRIPTS[m.killAt.transcript](0).map((s) => s.label);
            // Every step BEFORE the kill step agrees with the real kernel: the kill is
            // attributed to the named admission decision, not to earlier drift.
            for (let i = 0; i < m.killAt.step; i += 1)
              expect(trace.reasons[i], m.id + " at " + labels[i] + " must match the real kernel").to.equal(
                realTrace.reasons[i],
              );
            expect(realTrace.reasons[m.killAt.step], "real kernel at " + labels[m.killAt.step]).to.equal(m.killAt.real);
            expect(trace.reasons[m.killAt.step], m.id + " at " + labels[m.killAt.step]).to.equal(m.killAt.mutant);
            // The SD-2 quantity itself moves in the predicted direction on that transcript.
            const q2Mutant = maxContinuous(trace.starts);
            const q2Real = maxContinuous(realTrace.starts);
            if (m.shape === "permissive")
              expect(q2Mutant, m.id + " permits more continuous denial than the kernel").to.be.greaterThan(q2Real);
            else expect(q2Mutant, m.id + " permits less continuous denial than the kernel").to.be.lessThan(q2Real);
            console.log(
              "      " +
                m.id.padEnd(28) +
                " Q2 " +
                fmtDays(q2Mutant).padEnd(5) +
                " (kernel " +
                fmtDays(q2Real) +
                ")  " +
                labels.map((l, i) => l + ":" + trace.reasons[i]).join(" "),
            );
          });
        },
      );
    }

    it("E7 — the real kernel passes every discriminator the mutants fail (both directions asserted once, here)", function () {
      expect(real["IN-EPOCH"].reasons).to.deep.equal(["OK", "OK", "ContainmentBudget"]);
      expect(real.CHAIN.reasons).to.deep.equal(["OK", "OK", "OK", "OK", "ContainmentBudget", "OK"]);
      expect(maxContinuous(real.CHAIN.starts)).to.equal(BUDGET + MAX);
    });
  });
});
