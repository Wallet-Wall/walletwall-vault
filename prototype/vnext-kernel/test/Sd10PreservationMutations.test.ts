/**
 * EXPERIMENTAL PROTOTYPE — LANE SD-10: THE MUTATION CONTRACT FOR
 * APPROVED-REQUEST PRESERVATION.
 *
 * SD-10's correction REMOVES a statement. A removal is the one shape of change
 * that mutation testing does not automatically cover: the ordinary catalogue
 * mutates what the kernel DOES, and there is nothing left here to mutate. The
 * guard therefore has to be INVERTED — the permanent mutant is the reinstated
 * check, and the permanent property is the one that refuses it.
 *
 * WHAT IS PINNED HERE, and why each candidate earns a mutant rather than a
 * paragraph (Lane SD10-D1 adjudicated all four designs; three were rejected):
 *
 *   M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST   the BASE behaviour, i.e.
 *     the defect itself, reinserted. This is the mutant SD-10 exists for: it is
 *     what a future "the request should surely be re-checked against the current
 *     roster" cleanup would write, and it must die.
 *
 *   M-SD10-T-ROTATION-AUTO-TERMINATES-REQUEST        candidate T. `setGuardians`
 *     clears the request outright. A DIRECT violation of
 *     I-APPROVED-REQUEST-PRESERVATION and, unlike the base, it is not even
 *     recoverable by waiting: the effect is destroyed rather than stranded.
 *
 *   M-SD10-B-ROTATION-BLOCKED-WHILE-REQUEST-LIVE     candidate B. `setGuardians`
 *     reverts while a request is live — the reference model's historical
 *     semantics. B is CONFORMANT with I-APPROVED-REQUEST-PRESERVATION and is
 *     NOT an authority-cut violation; it is rejected as an unnecessary
 *     liveness/governance restriction, and it is guarded here so that a future
 *     design regression toward it is VISIBLE rather than silent.
 *
 *   candidate R (ratification) gets no mutant: it adds a selector, an event and
 *     ~292 bytes, so it cannot be expressed as a semantic edit to this kernel.
 *     Its absence is asserted structurally instead — see the final test.
 *
 *   M-SD10-S-QUORUM-ROSTER-PREIMAGE-UNBOUND          NOT a candidate design, and
 *     added after an independent review observed that the principal-separation
 *     property was carried without any mutant to prove it discriminating. It
 *     deletes the kernel's ONLY roster-preimage binding — BASE code enforcing
 *     I-GUARDIAN-AUTHORITY-CLOSURE, untouched by this lane. It therefore proves
 *     the property has TEETH; it is NOT evidence about anything SD10-I changed,
 *     and it is deliberately named for the breach it opens (universal quorum
 *     forgery) rather than for the narrower symptom the property observes.
 *
 * THE TWO RULES THIS SUITE INHERITS from W2RecoveryLifecycleMutations, verbatim
 * in intent:
 *
 *   1. A DISCRIMINATOR OBSERVES THE FAILURE; IT NEVER ASSERTS ON THE WAY TO IT.
 *      Every property is a boolean function. A step that cannot be set up
 *      returns `false` prefixed `setup:`, and a `setup:` result is never a kill.
 *      This matters more here than usual: candidate B REFUSES the rotation, so
 *      under B the preservation property cannot even reach its subject. That
 *      must read as INCONCLUSIVE for preservation — B is conformant with it —
 *      and B must be killed by its own property instead.
 *
 *   2. NO KILL CREDIT FOR COMPILE FAILURE, SETUP REVERTS, OR ANOTHER MUTANT'S
 *      SIDE EFFECT. Each mutant must compile, deploy, complete a positive
 *      control, and be killed by its assigned property reporting EXACTLY the
 *      observation it exists for.
 *
 * NOTHING HERE ASKS THE KERNEL WHAT TO SIGN: every digest is mirrored from
 * `stateful/world.ts` / `sd4-harness.ts`.
 */
import { expect } from "chai";
import * as fs from "node:fs";
import * as path from "node:path";
import { ethers, networkHelpers } from "./connection.js";
import { compileDeployable, type DeployableMutant } from "../stateful/mutants.js";
import { replaceWithinFunction } from "../authority/mutation-harness.js";
import { R, abi } from "./sd4-harness.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  sign,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;
const SRC = path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "VaultKernelPrototype.sol");
const kernelSource = (): string => fs.readFileSync(SRC, "utf8").split("\r\n").join("\n");

// ---------------------------------------------------------------------------
// The mutants.
// ---------------------------------------------------------------------------

type PropertyId =
  | "P-SD10-APPROVED-REQUEST-PRESERVED"
  | "P-SD10-ROTATION-REMAINS-AVAILABLE"
  | "P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY";

const PROPERTY_IDS: PropertyId[] = [
  "P-SD10-APPROVED-REQUEST-PRESERVED",
  "P-SD10-ROTATION-REMAINS-AVAILABLE",
  "P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY",
];

interface Sd10Mutant {
  id: string;
  breaks: string;
  killedBy: PropertyId;
  /** The kill is credited only when the assigned property reports EXACTLY this. */
  observation: string;
  apply: (s: string) => string;
}

/** The anchor the reinstated check attaches to — the last surviving gate above it. */
const EXPIRY_GATE = "        if (block.timestamp >= r.expiresAt) revert Expired();";
const GEN_CHECK = "        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();";
/**
 * The ONLY binding anywhere in the kernel between the caller-supplied roster
 * preimage and `guardianCommitment` (grep: exactly one occurrence in the file).
 */
const ROSTER_BINDING =
  "        if (rosterCommitment(guardianThreshold, p.members, p.isContract) != guardianCommitment) revert BadRoster();";

const SD10_MUTANTS: Sd10Mutant[] = [
  {
    id: "M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST",
    breaks:
      "executeRecovery re-validates an ALREADY-ADMITTED request against the CURRENT guardianGeneration, so a roster " +
      "replacement strands the request the same constituency approved — SD-10, reinstated verbatim.",
    killedBy: "P-SD10-APPROVED-REQUEST-PRESERVED",
    observation: "execution of a preserved, mature, validly-proven request was REFUSED (BadRoster)",
    apply: (s) => replaceWithinFunction(s, "executeRecovery", EXPIRY_GATE, EXPIRY_GATE + "\n" + GEN_CHECK),
  },
  {
    id: "M-SD10-T-ROTATION-AUTO-TERMINATES-REQUEST",
    breaks:
      "candidate T: setGuardians clears recovery.active, destroying the approved request outright rather than " +
      "preserving it — the most direct reading of I-APPROVED-REQUEST-PRESERVATION's prohibition.",
    killedBy: "P-SD10-APPROVED-REQUEST-PRESERVED",
    observation: "the guardian-set replacement CLEARED the approved request",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setGuardians",
        "        guardianCommitment = newCommitment;",
        "        recovery.active = false;\n        guardianCommitment = newCommitment;",
      ),
  },
  {
    id: "M-SD10-B-ROTATION-BLOCKED-WHILE-REQUEST-LIVE",
    breaks:
      "candidate B: setGuardians reverts while a recovery is effectively live. CONFORMANT with " +
      "I-APPROVED-REQUEST-PRESERVATION and NOT an authority-cut violation — rejected as an unnecessary " +
      "liveness/governance restriction, and guarded so a regression toward it is visible.",
    killedBy: "P-SD10-ROTATION-REMAINS-AVAILABLE",
    observation: "guardian replacement was REFUSED while an approved request was live",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setGuardians",
        "        _requireNormal();",
        "        _requireNormal();\n        if (_recoveryIsLive()) revert BadState();",
      ),
  },
  {
    id: "M-SD10-S-QUORUM-ROSTER-PREIMAGE-UNBOUND",
    breaks:
      "_requireQuorum stops binding the caller-supplied roster preimage to `guardianCommitment`. NAMED FOR WHAT IT " +
      "ACTUALLY DOES, not for the property that catches it: this is the ONLY such binding in the kernel, so removing " +
      "it is universal quorum forgery across all five quorum-gated entries (setGuardians, initiateRecovery, " +
      "cancelRecoveryByQuorum, enterContainment, bindMigration) by addresses that were never guardians at any " +
      "generation. What survives is canonicity of an attacker-supplied array plus signatures by that same array.",
    killedBy: "P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY",
    observation: "the REPLACED roster still holds fresh cancellation authority",
    apply: (s) => replaceWithinFunction(s, "_requireQuorum", ROSTER_BINDING, ""),
  },
];

// ---------------------------------------------------------------------------
// Rosters, credentials and acts — mirrors of the SD-10 regression suite.
// ---------------------------------------------------------------------------

interface Roster {
  readonly keys: ethers.SigningKey[];
  readonly members: string[];
  readonly isContract: boolean[];
}

const mkRoster = (tag: string): Roster => {
  const keys = [0, 1, 2]
    .map((i) => keyOf(`sd10m-${tag}-g${i}`))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  return { keys, members: keys.map(addrOf), isContract: [false, false, false] };
};

const genesisRoster = (w: World): Roster => ({
  keys: w.gKeys,
  members: w.guardians,
  isContract: w.guardianIsContract,
});

const quorumOf = (r: Roster, digest: string) => ({
  members: r.members,
  isContract: r.isContract,
  attestingIndices: [0, 1],
  attestations: [sign(r.keys[0]!, digest), sign(r.keys[1]!, digest)],
});

async function gDigest(w: World, v: ethers.Contract, action: string, params: string) {
  const nonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
  const gGen = (await v.guardianGeneration()) as bigint;
  return {
    nonce,
    digest: digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: KERNEL_GEN,
      actionType: action,
      authorityGeneration: gGen,
      params,
      domain: DOMAIN.GUARDIAN,
      nonce,
      deadline: FAR_DEADLINE,
    }),
  };
}

interface Cred {
  nominee: ethers.SigningKey;
  pqNominee: ethers.SigningKey;
  key32: string;
  hash: string;
}
const mkCred = (tag: string): Cred => {
  const nominee = keyOf(`sd10m-${tag}-s`);
  const pqNominee = keyOf(`sd10m-${tag}-p`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  return { nominee, pqNominee, key32, hash: ethers.keccak256(key32) };
};

const MINED = { gasLimit: 2_000_000 };

async function propose(w: World, v: ethers.Contract, r: Roster, c: Cred) {
  const params = ethers.keccak256(
    abi.encode(["address", "bytes32", "address"], [addrOf(c.nominee), c.hash, w.verifiers.honest]),
  );
  const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, params);
  return v.initiateRecovery(addrOf(c.nominee), c.hash, w.verifiers.honest, quorumOf(r, digest), nonce, FAR_DEADLINE);
}

async function replaceRoster(w: World, v: ethers.Contract, from: Roster, to: Roster) {
  const commitment = (await v.rosterCommitment(w.threshold, to.members, to.isContract)) as string;
  const { digest, nonce } = await gDigest(w, v, ACTION.SET_GUARDIANS, commitment);
  return v.setGuardians(w.threshold, to.members, to.isContract, quorumOf(from, digest), nonce, FAR_DEADLINE, MINED);
}

async function execute(v: ethers.Contract, c: Cred) {
  const pop = (await v.recoveryPossessionDigest()) as string;
  return v.executeRecovery(
    {
      newSigner: addrOf(c.nominee),
      newPqKeyHash: c.hash,
      newPqKey: c.key32,
      newEcdsaPop: sign(c.nominee, pop),
      newPqPop: sign(c.pqNominee, pop),
    },
    MINED,
  );
}

async function outcome(p: Promise<ethers.ContractTransactionResponse>): Promise<{ ok: boolean; err: string }> {
  try {
    await (await p).wait();
    return { ok: true, err: "" };
  } catch (e) {
    return { ok: false, err: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * The kernel's custom error inside a revert message, or "other". Kill-credit
 * observations must be DETERMINISTIC strings, and raw provider messages are not.
 */
const KNOWN_ERRORS = [
  "BadRoster",
  "BadState",
  "Expired",
  "TooEarly",
  "NoRecovery",
  "BadSignature",
  "QuorumNotMet",
  "ChallengeExhausted",
  "AlreadyBound",
  "ZeroAddress",
  "BadNonce",
];
/** 4-byte selector -> error name, derived from the NAMES rather than from any artifact. */
const SELECTORS = new Map(KNOWN_ERRORS.map((e) => [ethers.id(`${e}()`).slice(0, 10), e]));

/**
 * The kernel error behind a failed transaction, identified by its 4-byte
 * SELECTOR wherever the provider hands one back.
 *
 * A mutant deployed behind the factory is reached through a contract object
 * whose interface the provider does not always use to decode revert data — it
 * reports `unrecognized custom error (return data: 0x...)`. Matching the raw
 * selector is both provider-independent and stronger evidence than a substring
 * search of an English message: it names the error cryptographically.
 */
const errName = (msg: string): string => {
  const raw = /return data:\s*(0x[0-9a-fA-F]{8})/.exec(msg);
  if (raw) return SELECTORS.get(raw[1]!.toLowerCase()) ?? `unknown(${raw[1]})`;
  return KNOWN_ERRORS.find((e) => msg.includes(e)) ?? "other";
};

const snapshotOf = async (v: ethers.Contract) => {
  const r = await v.recovery();
  return {
    signer: String(r[R.SIGNER]),
    pqHash: String(r[R.PQ_KEY_HASH]),
    verifier: String(r[R.VERIFIER]),
    executableAt: r[R.EXECUTABLE_AT] as bigint,
    expiresAt: r[R.EXPIRES_AT] as bigint,
    boundGen: r[R.GUARDIAN_GEN] as bigint,
    challenges: r[R.CHALLENGES] as bigint,
    active: r[R.ACTIVE] as boolean,
  };
};

// ---------------------------------------------------------------------------
// The properties — boolean, non-asserting. `why` carries the observation.
// ---------------------------------------------------------------------------

type Property = (w: World, v: ethers.Contract, why: (s: string) => void) => Promise<boolean>;

const PROPERTIES: Record<PropertyId, Property> = {
  /**
   * I-APPROVED-REQUEST-PRESERVATION, end to end, with every kill-credit
   * precondition checked BEFORE the subject transaction is attempted:
   * R1 was quorum-approved; the rotation SUCCEEDED; R1 is still inside its
   * original window; possession is genuine. Only then is execution attempted,
   * so a refusal can be attributed to the generation and to nothing else.
   */
  "P-SD10-APPROVED-REQUEST-PRESERVED": async (w, v, why) => {
    const g0 = genesisRoster(w);
    const g1 = mkRoster("pres");
    const c = mkCred("pres");

    if (!(await outcome(propose(w, v, g0, c))).ok) return (why("setup: initiation failed"), false);
    const approved = await snapshotOf(v);
    if (!approved.active) return (why("setup: no approved request after initiation"), false);
    const g = (await v.guardianGeneration()) as bigint;
    if (approved.boundGen !== g) return (why("setup: request not bound to the approving generation"), false);

    const rot = await outcome(replaceRoster(w, v, g0, g1));
    // Candidate B refuses HERE. That is not a preservation violation — B is
    // conformant with this invariant — so it is reported as a setup failure and
    // scores nothing on this property.
    if (!rot.ok) return (why("setup: guardian replacement refused (" + errName(rot.err) + ")"), false);
    if (((await v.guardianGeneration()) as bigint) !== g + 1n)
      return (why("setup: generation did not advance"), false);

    const after = await snapshotOf(v);
    if (!after.active) return (why("the guardian-set replacement CLEARED the approved request"), false);
    if (
      after.signer !== approved.signer ||
      after.pqHash !== approved.pqHash ||
      after.verifier !== approved.verifier ||
      after.executableAt !== approved.executableAt ||
      after.expiresAt !== approved.expiresAt ||
      after.boundGen !== approved.boundGen ||
      after.challenges !== approved.challenges
    ) {
      return (why("the guardian-set replacement ALTERED the approved request"), false);
    }

    await networkHelpers.time.increaseTo(Number(approved.executableAt));
    const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
    if (now < approved.executableAt || now >= approved.expiresAt)
      return (why("setup: could not reach the request's live executable window"), false);

    const ex = await outcome(execute(v, c));
    if (!ex.ok)
      return (why("execution of a preserved, mature, validly-proven request was REFUSED (" + errName(ex.err) + ")"), false);
    if ((await v.ecdsaSigner()) !== addrOf(c.nominee))
      return (why("execution succeeded but installed material R1 did not commit to"), false);
    return true;
  },

  /**
   * The selected semantics keep guardian replacement INDEPENDENTLY available:
   * the quorum does not have to terminate its own pending remedy first in order
   * to rotate a compromised seat out. This is the axis on which candidate B
   * differs from the correction, and the only one.
   */
  "P-SD10-ROTATION-REMAINS-AVAILABLE": async (w, v, why) => {
    const g0 = genesisRoster(w);
    if (!(await outcome(propose(w, v, g0, mkCred("avail")))).ok) return (why("setup: initiation failed"), false);
    const g = (await v.guardianGeneration()) as bigint;

    const rot = await outcome(replaceRoster(w, v, g0, mkRoster("avail")));
    if (!rot.ok) return (why("guardian replacement was REFUSED while an approved request was live"), false);
    if (((await v.guardianGeneration()) as bigint) !== g + 1n)
      return (why("guardian replacement reported success but the generation did not advance"), false);
    return true;
  },

  /**
   * THE STANDING GUARD ON THE OTHER SIDE. Preservation must not become tenure:
   * the replaced roster keeps a pre-committed effect and NOT a seat.
   *
   * None of the four candidate DESIGNS (base, P, T, B) differ on principal
   * separation, so no design mutant exercises this property — an earlier draft
   * therefore carried it as a deliberately unkilled guard, which an independent
   * review correctly called out as weak assurance. It now has a killing mutant,
   * `M-SD10-S-QUORUM-ROSTER-PREIMAGE-UNBOUND`.
   *
   * BE PRECISE ABOUT WHAT THAT MUTANT PROVES. It deletes the kernel's only
   * roster-preimage binding, which is BASE code enforcing
   * `I-GUARDIAN-AUTHORITY-CLOSURE` and is untouched by this lane. So the mutant
   * demonstrates that this property has TEETH — that it would observe a
   * regression in principal separation rather than passing vacuously — but it
   * is not evidence about anything SD10-I changed. That distinction is the
   * whole reason it is spelled out here instead of being quietly counted as
   * SD-10 coverage.
   */
  "P-SD10-OLD-ROSTER-HOLDS-NO-FRESH-AUTHORITY": async (w, v, why) => {
    const g0 = genesisRoster(w);
    const g1 = mkRoster("sep");
    if (!(await outcome(propose(w, v, g0, mkCred("sep")))).ok) return (why("setup: initiation failed"), false);
    const rot = await outcome(replaceRoster(w, v, g0, g1));
    if (!rot.ok) return (why("setup: guardian replacement refused (" + errName(rot.err) + ")"), false);

    // The OLD roster, signing a FRESH cancellation at the CURRENT generation.
    const stale = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
    const bad = await outcome(
      v.cancelRecoveryByQuorum(quorumOf(g0, stale.digest), stale.nonce, FAR_DEADLINE, MINED),
    );
    if (bad.ok) return (why("the REPLACED roster still holds fresh cancellation authority"), false);

    // POSITIVE CONTROL: the refusal above must be about the signer, not the call.
    const fresh = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
    const good = await outcome(
      v.cancelRecoveryByQuorum(quorumOf(g1, fresh.digest), fresh.nonce, FAR_DEADLINE, MINED),
    );
    if (!good.ok) return (why("setup: the CURRENT roster could not cancel either (" + errName(good.err) + ")"), false);
    return true;
  },
};

interface Cell {
  mutant: string;
  property: PropertyId;
  holdsOnMutant: boolean;
  detail: string;
}

describe("SD-10 — the preservation mutation contract: the defect, two rejected candidates, and the principal-separation guard", function () {
  this.timeout(3_600_000);

  const compiled = new Map<string, DeployableMutant>();
  const compileFailures: { id: string; errors: string[] }[] = [];
  const realVerdicts = new Map<PropertyId, Promise<{ holds: boolean; detail: string }>>();
  const realVerdict = (p: PropertyId): Promise<{ holds: boolean; detail: string }> => {
    let pending = realVerdicts.get(p);
    if (pending === undefined) {
      pending = evaluate(p, "sd10m-real-" + p.toLowerCase());
      realVerdicts.set(p, pending);
    }
    return pending;
  };
  const matrix: Cell[] = [];

  before(function () {
    for (const m of SD10_MUTANTS) {
      let built: ReturnType<typeof compileDeployable>;
      try {
        built = compileDeployable({ "VaultKernelPrototype.sol": m.apply(kernelSource()) });
      } catch (e) {
        compileFailures.push({ id: m.id, errors: [e instanceof Error ? e.message : String(e)] });
        continue;
      }
      if (built.ok) compiled.set(m.id, built.kernel);
      else compileFailures.push({ id: m.id, errors: built.errors });
    }
  });

  /** Runs one scenario inside an EVM snapshot; see the W2 suite for why. */
  async function withSnapshot<T>(fn: () => Promise<T>): Promise<T> {
    const snap = await networkHelpers.takeSnapshot();
    try {
      return await fn();
    } finally {
      await snap.restore();
    }
  }

  async function evaluate(
    property: PropertyId,
    label: string,
    impl?: DeployableMutant,
  ): Promise<{ holds: boolean; detail: string }> {
    return withSnapshot(async () => {
      const w = await deployWorld({ label, implOverride: impl });
      let detail = "";
      const holds = await PROPERTIES[property](w, w.vault, (s) => {
        detail = s;
      });
      return { holds, detail };
    });
  }

  it("the contract is complete: four distinct mutants, every assigned property defined", function () {
    expect(SD10_MUTANTS).to.have.length(4);
    expect(new Set(SD10_MUTANTS.map((m) => m.id)).size).to.equal(4);
    for (const m of SD10_MUTANTS) expect(PROPERTY_IDS, m.id + " names an unknown property").to.include(m.killedBy);
  });

  it("every mutant applies to the CORRECTED source exactly once and compiles", function () {
    expect(
      compileFailures,
      "a mutant failed to apply or compile — its anchor is stale against the corrected kernel, so it would " +
        "test nothing:\n" + JSON.stringify(compileFailures, null, 2),
    ).to.deep.equal([]);
    expect(compiled.size).to.equal(SD10_MUTANTS.length);
  });

  it("the corrected kernel carries NO execution-time generation re-check (the anchor the inverse mutant restores)", function () {
    const src = kernelSource();
    const body = src.slice(src.indexOf("function executeRecovery"));
    const end = body.indexOf("\n    function ", 1);
    expect(
      (end === -1 ? body : body.slice(0, end)).includes("boundGuardianGeneration != guardianGeneration"),
      "executeRecovery must not re-validate an already-admitted request against the current generation",
    ).to.equal(false);
    // ...and the field itself is RETAINED, as approval provenance and as an
    // input to `recoveryPossessionDigest()`.
    expect(src.includes("uint64 boundGuardianGeneration;"), "the provenance field is retained").to.equal(true);
    expect(
      src.includes("boundGuardianGeneration: guardianGeneration,"),
      "and is still written at initiation",
    ).to.equal(true);
  });

  it("every property HOLDS on the corrected kernel (the positive direction of every discriminator)", async function () {
    const failures: string[] = [];
    for (const p of PROPERTY_IDS) {
      const r = await realVerdict(p);
      if (!r.holds) failures.push(p + ": " + r.detail);
    }
    expect(failures, "properties that FAIL on the corrected kernel").to.deep.equal([]);
  });

  for (const m of SD10_MUTANTS) {
    it("kills " + m.id + " by " + m.killedBy, async function () {
      const kernel = compiled.get(m.id);
      expect(kernel, m.id + " did not compile").to.not.equal(undefined);

      // VACUITY GUARD: a WORKING kernel, proven by a positive-control transition.
      const control = await withSnapshot(async () => {
        const wv = await deployWorld({ label: "sd10m-vac-" + m.id, implOverride: kernel });
        return outcome(propose(wv, wv.vault, genesisRoster(wv), mkCred("vac")));
      });
      expect(
        control.ok,
        "INCONCLUSIVE: mutant " + m.id + " cannot even initiate a recovery: " + control.err.slice(0, 120),
      ).to.equal(true);

      const real = await realVerdict(m.killedBy);
      expect(
        real.holds,
        "the assigned property must HOLD on the corrected kernel before it can kill anything: " + real.detail,
      ).to.equal(true);

      const r = await evaluate(m.killedBy, "sd10m-" + m.id + "-" + m.killedBy.toLowerCase(), kernel);
      matrix.push({ mutant: m.id, property: m.killedBy, holdsOnMutant: r.holds, detail: r.detail });
      expect(
        r.holds,
        "SURVIVOR: " + m.id + " was not killed by its assigned property " + m.killedBy + " (breaks: " + m.breaks + ")",
      ).to.equal(false);
      expect(
        r.detail.startsWith("setup:"),
        "the kill must be an OBSERVED violation, not a setup failure: " + r.detail,
      ).to.equal(false);
      expect(
        r.detail,
        "the kill must be THE observation this mutant exists for, not an unrelated refusal",
      ).to.equal(m.observation);
    });
  }

  it("candidate R leaves no trace: SD-10's target adds no ratification selector, event or request field", async function () {
    // R (ratify-after-rotation) was adjudicated and rejected in Lane SD10-D1:
    // +1 selector, +1 event, +292 bytes, an extra guardian act, and it REBINDS
    // the possession digest so a pre-signed proof is refused. It cannot be
    // expressed as a semantic edit to this kernel, so its absence is asserted
    // structurally rather than by mutant.
    const w = await deployWorld({ label: "sd10m-no-ratify" });
    const names = w.vault.interface.fragments
      .filter((f) => f.type === "function" || f.type === "event")
      .map((f) => JSON.parse(f.format("json")).name as string);
    for (const forbidden of ["ratify", "reaffirm", "rebind", "reapprove"]) {
      expect(
        names.filter((n) => n.toLowerCase().includes(forbidden)),
        "SD-10's target introduces no " + forbidden + " surface",
      ).to.deep.equal([]);
    }
    // The request's SHAPE is asserted through the ABI rather than by reading the
    // struct text: `recovery()` still returns exactly the eight fields it
    // returned at the base, in order. A ratification design would have had to
    // add at least one (a ratifying generation, or a ratified flag).
    const outputs = w.vault.interface.getFunction("recovery")!.outputs.map((o) => `${o.type} ${o.name}`);
    expect(outputs, "recovery() returns the SAME eight fields as the base kernel").to.deep.equal([
      "address proposedSigner",
      "bytes32 proposedPqKeyHash",
      "address proposedVerifier",
      "uint64 executableAt",
      "uint64 expiresAt",
      "uint64 boundGuardianGeneration",
      "uint32 challengesUsed",
      "bool active",
    ]);
  });

  it("prints the full mutant x property kill matrix (informational beyond the assigned diagonal)", async function () {
    const rows: string[] = [];
    rows.push("mutant".padEnd(52) + PROPERTY_IDS.map((_, i) => String(i + 1).padStart(3)).join(""));
    for (const m of SD10_MUTANTS) {
      const kernel = compiled.get(m.id);
      const cells: string[] = [];
      for (const p of PROPERTY_IDS) {
        const assigned = matrix.find((c) => c.mutant === m.id && c.property === p);
        let killed: boolean;
        if (assigned) killed = !assigned.holdsOnMutant;
        else {
          const r = await evaluate(p, "sd10m-x-" + m.id + "-" + p.toLowerCase(), kernel);
          if (!r.holds && r.detail.startsWith("setup:")) {
            cells.push("  ?");
            continue;
          }
          killed = !r.holds;
        }
        cells.push(p === m.killedBy ? (killed ? "  K" : "  S") : killed ? "  k" : "  .");
      }
      rows.push(m.id.padEnd(52) + cells.join(""));
    }
    rows.push("");
    rows.push(
      "legend: K = assigned property kills (load-bearing), k = another property also kills, " +
        ". = survives that property, ? = scenario not reachable on this mutant",
    );
    PROPERTY_IDS.forEach((p, i) => rows.push(String(i + 1).padStart(3) + " " + p));
    console.log("\n  SD-10 MUTATION KILL MATRIX\n" + rows.map((r) => "  " + r).join("\n") + "\n");
    expect(
      matrix.filter((c) => c.holdsOnMutant).map((c) => c.mutant),
      "survivors on the assigned diagonal",
    ).to.deep.equal([]);
    expect(matrix).to.have.length(SD10_MUTANTS.length);
  });
});
