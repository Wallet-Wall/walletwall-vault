/**
 * EXPERIMENTAL PROTOTYPE — LANE W2: THE FROZEN MUTATION CONTRACT, EXECUTED.
 *
 * W2_IMPLEMENTATION_CONTRACT.md defines fifteen mutants, one semantic break
 * each, and names the property that must kill every one; Lane W2P added a
 * sixteenth on the same terms (W2R-2 — the creator-side half of the
 * nonce-serialisation premise, see the catalogue). This suite compiles
 * each mutant IN MEMORY from the REAL W2 kernel source (never touching
 * `contracts/`), deploys it behind the real factory, and runs the named
 * property against it — and against the real artifact — asserting BOTH
 * directions: the property HOLDS on the shipped kernel and FAILS on the mutant.
 *
 * THE TWO RULES THIS SUITE IS BUILT AROUND (both learned the hard way in this
 * repository, see StatefulMutationAdequacy and VaultVNextArchitectureModel):
 *
 *   1. A DISCRIMINATOR OBSERVES THE FAILURE; IT NEVER ASSERTS ON THE WAY TO IT.
 *      Every property below is a boolean function. A step that cannot be set
 *      up returns `false` with a reason, and the harness then distinguishes
 *      "the scenario could not be set up" from "the invariant was violated" by
 *      requiring the SAME property to hold on the real kernel. A mutant that
 *      merely breaks the fixture is reported as INCONCLUSIVE, never as killed.
 *
 *   2. NO KILL CREDIT FOR COMPILE FAILURE, SETUP REVERTS, UNRELATED PROPERTIES
 *      OR ANOTHER MUTANT'S SIDE EFFECT. Each mutant must compile, must deploy,
 *      must complete a positive-control transition, and must be killed by the
 *      property the contract assigns to it. The full mutant x property matrix is
 *      printed so a reader can see which OTHER properties also caught it, but
 *      only the assigned cell is load-bearing.
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
import { QCANCEL_TAG, R, abi, guardianDigest, quorum } from "./sd4-harness.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  sign,
  type World,
} from "../stateful/world.js";

// ---------------------------------------------------------------------------
// The W2 kernel source, read at test time from the tracked file (never edited).
// ---------------------------------------------------------------------------

const SRC = path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "VaultKernelPrototype.sol");
const w2Source = (): string => fs.readFileSync(SRC, "utf8").split("\r\n").join("\n");

/** Whole-file replacement that REFUSES a non-unique or missing anchor. */
function replaceOnce(source: string, oldText: string, newText: string, label: string): string {
  const n = source.split(oldText).length - 1;
  if (n !== 1) throw new Error(`anchor "${label}" matched ${n} times, expected exactly 1`);
  return source.replace(oldText, newText);
}

/** Remove one `    function NAME(...) { ... }` block (NatSpec left in place), braces matched. */
function removeFunction(src: string, name: string): string {
  const re = new RegExp(`\\n    function ${name}\\s*\\(`);
  const m = re.exec(src);
  if (m === null) throw new Error(`function ${name} not found`);
  let i = src.indexOf("{", m.index + m[0].length);
  if (i === -1) throw new Error(`no body for ${name}`);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  return src.slice(0, m.index) + src.slice(i + 1);
}

// ---------------------------------------------------------------------------
// The fifteen mutants of the frozen contract, plus the sixteenth added in Lane
// W2P — one semantic break each.
// ---------------------------------------------------------------------------

type PropertyId =
  | "P-K9-QUORUM-CANCEL-CONFORMANCE"
  | "P-K9-QUORUM-CANCEL-REQUIRES-QUORUM"
  | "P-EPOCH-SURVIVES-QUORUM-CANCEL"
  | "P-EPOCH-SURVIVES-EXPIRY-NO-CLEANUP"
  | "P-EPOCH-SURVIVES-ROTATION"
  | "P-EPOCH-CARRIED-ON-INITIATION"
  | "P-EPOCH-RESETS-ON-SUCCESS"
  | "P-CHALLENGE-BOUNDED"
  | "P-LIVE-OVERWRITE-REFUSED"
  | "P-EXPIRED-DOES-NOT-BLOCK-MIGRATION"
  | "P-EXPIRED-DOES-NOT-BLOCK-INITIATION"
  | "P-EXPIRED-NOT-CHALLENGEABLE"
  | "P-EXPIRED-NOT-QUORUM-CANCELLABLE"
  | "P-HALF-OPEN-EXPIRY-BOUNDARY"
  | "P-STALE-QUORUM-CANCEL-REPLAY-EXCLUDED";

interface W2Mutant {
  id: string;
  breaks: string;
  killedBy: PropertyId;
  /**
   * When set, the kill is credited only if the assigned property's observation
   * is EXACTLY this string — the dangerous path the mutant exists to open — so
   * a mutant that merely breaks an earlier step of the scenario scores nothing.
   * Used by the two nonce-serialisation mutants.
   */
  observation?: string;
  apply: (s: string) => string;
}

const LIVE_GUARD = "        if (_recoveryIsLive()) revert BadState();";
const NOT_LIVE_GUARD = "        if (!_recoveryIsLive()) revert NoRecovery();";
const MIGRATION_GUARD = "        if (_recoveryIsLive()) revert NoRecovery();";

/**
 * THE observation the two nonce-serialisation mutants exist for: a cancellation
 * authorised for request R1 terminating request R2. A kill of either mutant is
 * credited only when the replay property reports exactly this (see the kill
 * test) — never for a setup failure or an unrelated refusal.
 */
const STALE_CANCEL_REACHED_R2 = "a cancellation pre-signed for R1 terminated R2";

export const W2_MUTANTS: readonly W2Mutant[] = [
  {
    id: "M-K9-guardian-cancel-missing",
    breaks: "K-9 mechanism B absent — the quorum has no exit from a live request",
    killedBy: "P-K9-QUORUM-CANCEL-CONFORMANCE",
    apply: (s) => removeFunction(s, "cancelRecoveryByQuorum"),
  },
  {
    id: "M-K9-guardian-cancel-wrong-authority",
    breaks:
      "principal separation — the quorum's cancellation accepts the credential's ECDSA signature instead of a quorum",
    killedBy: "P-K9-QUORUM-CANCEL-REQUIRES-QUORUM",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "cancelRecoveryByQuorum",
        "        _requireQuorum(digest, proof);",
        "        if (!_floorAuthorises(digest, proof.attestations[0])) revert BadSignature();",
      ),
  },
  {
    id: "M-K9-quorum-cancel-refunds-budget",
    breaks:
      "epoch persistence — the quorum's cancellation deletes the whole request, refunding the credential's budget",
    killedBy: "P-EPOCH-SURVIVES-QUORUM-CANCEL",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "cancelRecoveryByQuorum",
        "        recovery.active = false;",
        "        delete recovery;",
      ),
  },
  {
    id: "M-K9-expiry-refunds-budget",
    breaks:
      "epoch persistence across expiry — a permissionless sweeper deletes an expired request (the SD-9a remediation hazard)",
    killedBy: "P-EPOCH-SURVIVES-EXPIRY-NO-CLEANUP",
    apply: (s) =>
      replaceOnce(
        s,
        "    function cancelRecoveryByQuorum(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {",
        `    function sweepExpiredRecovery() external {
        if (!recovery.active) revert NoRecovery();
        if (block.timestamp < recovery.expiresAt) revert TooEarly();
        delete recovery;
    }

    function cancelRecoveryByQuorum(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {`,
        "cancelRecoveryByQuorum signature",
      ),
  },
  {
    id: "M-K9-rotation-refunds-budget",
    breaks: "epoch independence from credentialGeneration — ordinary rotation zeroes the budget",
    killedBy: "P-EPOCH-SURVIVES-ROTATION",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "rotateCredential",
        "        _installCredential(c.newSigner, c.newPqKeyHash);",
        "        _installCredential(c.newSigner, c.newPqKeyHash);\n        recovery.challengesUsed = 0;",
      ),
  },
  {
    id: "M-K9-initiation-refunds-budget",
    breaks: "carry-forward — a fresh initiation starts the budget at zero",
    killedBy: "P-EPOCH-CARRIED-ON-INITIATION",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "initiateRecovery",
        "            challengesUsed: recovery.challengesUsed,",
        "            challengesUsed: 0,",
      ),
  },
  {
    id: "M-K9-success-does-not-reset-budget",
    breaks: "the reset boundary — a successful recovery clears the request field-wise and keeps the spent budget",
    killedBy: "P-EPOCH-RESETS-ON-SUCCESS",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "executeRecovery",
        "        delete recovery;",
        `        recovery.active = false;
        recovery.proposedSigner = address(0);
        recovery.proposedPqKeyHash = bytes32(0);
        recovery.proposedVerifier = address(0);
        recovery.executableAt = 0;
        recovery.expiresAt = 0;
        recovery.boundGuardianGeneration = 0;`,
      ),
  },
  {
    id: "M-K9-challenge-limit-removed",
    breaks: "the bounded veto (the historical M27 class) — the credential may challenge without limit",
    killedBy: "P-CHALLENGE-BOUNDED",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "cancelRecovery",
        "        if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();",
        "",
      ),
  },
  {
    id: "M-K9-live-overwrite-allowed",
    breaks: "SD-9d — a fresh initiation silently replaces an effectively-live request",
    killedBy: "P-LIVE-OVERWRITE-REFUSED",
    apply: (s) => replaceWithinFunction(s, "initiateRecovery", LIVE_GUARD, ""),
  },
  {
    id: "M-K9-expired-request-blocks-migration",
    breaks: "SD-9b — bindMigration reads the raw stored flag, so an expired request blocks the exit",
    killedBy: "P-EXPIRED-DOES-NOT-BLOCK-MIGRATION",
    apply: (s) =>
      replaceWithinFunction(s, "bindMigration", MIGRATION_GUARD, "        if (recovery.active) revert NoRecovery();"),
  },
  {
    id: "M-K9-expired-request-blocks-initiation",
    breaks: "replaceability — initiateRecovery reads the raw stored flag, so stale storage blocks a fresh request",
    killedBy: "P-EXPIRED-DOES-NOT-BLOCK-INITIATION",
    apply: (s) =>
      replaceWithinFunction(s, "initiateRecovery", LIVE_GUARD, "        if (recovery.active) revert BadState();"),
  },
  {
    id: "M-K9-expired-request-still-challengeable",
    breaks:
      "zero cancellation-target authority — the credential's challenge reads the raw flag and spends budget on an expired request",
    killedBy: "P-EXPIRED-NOT-CHALLENGEABLE",
    apply: (s) =>
      replaceWithinFunction(s, "cancelRecovery", NOT_LIVE_GUARD, "        if (!recovery.active) revert NoRecovery();"),
  },
  {
    id: "M-K9-expired-request-still-quorum-cancellable",
    breaks: "zero cancellation-target authority, mechanism B — the quorum's cancellation reads the raw flag",
    killedBy: "P-EXPIRED-NOT-QUORUM-CANCELLABLE",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "cancelRecoveryByQuorum",
        NOT_LIVE_GUARD,
        "        if (!recovery.active) revert NoRecovery();",
      ),
  },
  {
    id: "M-K9-expiry-inclusive-off-by-one",
    breaks: "SD-9e — the window is closed again: live while now <= expiresAt, executable while now <= expiresAt",
    killedBy: "P-HALF-OPEN-EXPIRY-BOUNDARY",
    apply: (s) => {
      let t = replaceWithinFunction(
        s,
        "_recoveryIsLive",
        "        return recovery.active && block.timestamp < recovery.expiresAt;",
        "        return recovery.active && block.timestamp <= recovery.expiresAt;",
      );
      t = replaceWithinFunction(
        t,
        "executeRecovery",
        "        if (block.timestamp >= r.expiresAt) revert Expired();",
        "        if (block.timestamp > r.expiresAt) revert Expired();",
      );
      return t;
    },
  },
  {
    id: "M-K9-guardian-cancel-nonce-replay",
    breaks: "Recovery Amendment section 5 — the quorum's cancellation no longer consumes the DOMAIN_GUARDIAN nonce",
    killedBy: "P-STALE-QUORUM-CANCEL-REPLAY-EXCLUDED",
    observation: STALE_CANCEL_REACHED_R2,
    apply: (s) =>
      replaceWithinFunction(s, "cancelRecoveryByQuorum", "        _consume(DOMAIN_GUARDIAN, nonce, deadline);", ""),
  },
  {
    // Lane W2P (closing W2R-2). The creator-side half of the same premise:
    // Recovery Amendment section 5, premise 1 — "every fresh request consumes a
    // DOMAIN_GUARDIAN nonce". Remove it and a fresh request can exist WITHOUT
    // consuming the nonce a cancellation pre-signed for its predecessor needs,
    // so R1's authorisation reaches R2. Sd4LaneW12 section D asserts the premise
    // on the real kernel; this mutant proves the replay property would notice
    // its loss, and is the permanent guard on the nonce-serialisation premise.
    id: "M-K9-initiation-does-not-consume-guardian-nonce",
    breaks:
      "Recovery Amendment section 5, premise 1 — initiateRecovery no longer consumes the DOMAIN_GUARDIAN nonce, so request creation stops serialising the guardian domain",
    killedBy: "P-STALE-QUORUM-CANCEL-REPLAY-EXCLUDED",
    observation: STALE_CANCEL_REACHED_R2,
    apply: (s) =>
      replaceWithinFunction(s, "initiateRecovery", "        _consume(DOMAIN_GUARDIAN, nonce, deadline);", ""),
  },
];

// ---------------------------------------------------------------------------
// Harness — the W2 surface bound to whichever kernel a world deployed.
// ---------------------------------------------------------------------------

const QCANCEL_FN =
  "function cancelRecoveryByQuorum((address[] members,bool[] isContract,uint256[] attestingIndices,bytes[] attestations) proof,uint256 nonce,uint64 deadline)";
const QCANCEL_EVENT = "event RecoveryCancelledByQuorum(uint32 challengesUsed)";
const SWEEP_FN = "function sweepExpiredRecovery()";
const QCANCEL_SIGHASH = "cancelRecoveryByQuorum((address[],bool[],uint256[],bytes[]),uint256,uint64)";

/**
 * The vault addressed through the REAL artifact's ABI plus the frozen W2
 * fragments (so a kernel that dropped the function still receives the call and
 * reverts) plus the sweeper the expiry mutant adds (so the property can attempt
 * the cleanup transaction that must not be required).
 */
function bind(w: World): ethers.Contract {
  const base = w.vault.interface;
  const fragments: (string | Record<string, unknown>)[] = base.fragments.map(
    (f) => JSON.parse(f.format("json")) as Record<string, unknown>,
  );
  if (!base.hasFunction(QCANCEL_SIGHASH)) fragments.push(QCANCEL_FN);
  if (!base.hasEvent("RecoveryCancelledByQuorum")) fragments.push(QCANCEL_EVENT);
  fragments.push(SWEEP_FN);
  return new ethers.Contract(w.vaultAddress, fragments as ethers.InterfaceAbi, w.deployer);
}

interface Cred {
  nominee: ethers.SigningKey;
  pqNominee: ethers.SigningKey;
  key32: string;
  hash: string;
}
const mkCred = (tag: string): Cred => {
  const nominee = keyOf(`w2m-${tag}-s`);
  const pqNominee = keyOf(`w2m-${tag}-p`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  return { nominee, pqNominee, key32, hash: ethers.keccak256(key32) };
};

type Overrides = { gasLimit?: number };
const MINED: Overrides = { gasLimit: 2_000_000 };

async function propose(w: World, v: ethers.Contract, c: Cred, overrides: Overrides = {}) {
  const params = ethers.keccak256(
    abi.encode(["address", "bytes32", "address"], [addrOf(c.nominee), c.hash, w.verifiers.honest]),
  );
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.initiateRecovery(
    addrOf(c.nominee),
    c.hash,
    w.verifiers.honest,
    quorum(w, digest),
    nonce,
    FAR_DEADLINE,
    overrides,
  );
}

async function challenge(w: World, v: ethers.Contract, credKey: ethers.SigningKey, overrides: Overrides = {}) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await v.credentialGeneration()) as bigint;
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
  return v.cancelRecovery(nonce, FAR_DEADLINE, sign(credKey, d), overrides);
}

async function quorumCancel(w: World, v: ethers.Contract, overrides: Overrides = {}) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE, overrides);
}

async function presignQuorumCancel(w: World, v: ethers.Contract, nonce: bigint) {
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: QCANCEL_TAG,
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return { proof: quorum(w, d), nonce };
}

async function execute(w: World, v: ethers.Contract, c: Cred, overrides: Overrides = {}) {
  const pop = (await v.recoveryPossessionDigest()) as string;
  return v.executeRecovery(
    {
      newSigner: addrOf(c.nominee),
      newPqKeyHash: c.hash,
      newPqKey: c.key32,
      newEcdsaPop: sign(c.nominee, pop),
      newPqPop: sign(c.pqNominee, pop),
    },
    overrides,
  );
}

async function rotateInPlace(w: World, v: ethers.Contract) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.credentialGeneration()) as bigint;
  const signer = addrOf(w.credKey);
  const pqBytes = abi.encode(["address"], [addrOf(w.pqKey)]);
  const hash = ethers.keccak256(pqBytes);
  const pop = (await v.credentialPossessionDigest(signer, hash)) as string;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.ROTATE,
    authorityGeneration: gen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [signer, hash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.rotateCredential(
    {
      newSigner: signer,
      newPqKeyHash: hash,
      newPqKey: pqBytes,
      newEcdsaPop: sign(w.credKey, pop),
      newPqPop: sign(w.pqKey, pop),
    },
    nonce,
    FAR_DEADLINE,
    sign(w.credKey, d),
    sign(w.pqKey, d),
    pqBytes,
  );
}

async function bindMigration(w: World, v: ethers.Contract, overrides: Overrides = {}) {
  const dest = { vault: w.destination, codeHash: ethers.id("w2m-dest"), generation: 2n };
  const nonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: ethers.keccak256(
      abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation]),
    ),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.bindMigration(dest, quorum(w, d), nonce, FAR_DEADLINE, sign(w.credKey, d), overrides);
}

const challenges = async (v: ethers.Contract): Promise<bigint> => (await v.recovery())[R.CHALLENGES] as bigint;
const isActive = async (v: ethers.Contract): Promise<boolean> => (await v.recovery())[R.ACTIVE] as boolean;
const expiresAt = async (v: ethers.Contract): Promise<bigint> => (await v.recovery())[R.EXPIRES_AT] as bigint;

/** Await a transaction; report whether it succeeded and, if not, the revert text. */
async function outcome(p: Promise<ethers.ContractTransactionResponse>): Promise<{ ok: boolean; err: string }> {
  try {
    await (await p).wait();
    return { ok: true, err: "" };
  } catch (e) {
    return { ok: false, err: e instanceof Error ? e.message : String(e) };
  }
}
const revertedWith = (r: { ok: boolean; err: string }, name: string): boolean => !r.ok && r.err.includes(name);

/** Spend the credential's whole budget across two fresh requests; false if the fixture could not. */
async function exhaust(w: World, v: ethers.Contract, tag: string): Promise<boolean> {
  for (let i = 0; i < 2; i++) {
    if (!(await outcome(propose(w, v, mkCred(`${tag}-x${i}`)))).ok) return false;
    if (!(await outcome(challenge(w, v, w.credKey))).ok) return false;
  }
  return (await challenges(v)) === 2n;
}

// ---------------------------------------------------------------------------
// The properties — boolean, non-asserting. `why` carries the observation.
// ---------------------------------------------------------------------------

type Property = (w: World, v: ethers.Contract, why: (s: string) => void) => Promise<boolean>;

const PROPERTIES: Record<PropertyId, Property> = {
  "P-K9-QUORUM-CANCEL-CONFORMANCE": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("conf")))).ok) return (why("setup: initiation failed"), false);
    const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
    const used = await challenges(v);
    const r = await outcome(quorumCancel(w, v));
    if (!r.ok) return (why("quorum cancellation refused: " + r.err.slice(0, 120)), false);
    if (await isActive(v)) return (why("request still active after quorum cancellation"), false);
    if ((await challenges(v)) !== used) return (why("budget moved"), false);
    if (((await v.nonces(DOMAIN.GUARDIAN)) as bigint) !== gNonce + 1n)
      return (why("guardian nonce not consumed exactly once"), false);
    return true;
  },
  "P-K9-QUORUM-CANCEL-REQUIRES-QUORUM": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("req")))).ok) return (why("setup: initiation failed"), false);
    const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
    // The CREDENTIAL signs the quorum digest and presents itself at one seat.
    const credSigned = { ...quorum(w, digest), attestingIndices: [0], attestations: [sign(w.credKey, digest)] };
    const r = await outcome(v.cancelRecoveryByQuorum(credSigned, nonce, FAR_DEADLINE));
    if (r.ok) return (why("a credential signature with no quorum cancelled the request"), false);
    if (!(await isActive(v))) return (why("request not live after the refused call"), false);
    return true;
  },
  "P-EPOCH-SURVIVES-QUORUM-CANCEL": async (w, v, why) => {
    if (!(await exhaust(w, v, "eqc"))) return (why("setup: could not exhaust the budget"), false);
    if (!(await outcome(propose(w, v, mkCred("eqc-r3")))).ok) return (why("setup: third initiation failed"), false);
    if (!(await outcome(quorumCancel(w, v))).ok) return (why("setup: quorum cancellation failed"), false);
    if (!(await outcome(propose(w, v, mkCred("eqc-r4")))).ok) return (why("setup: re-initiation failed"), false);
    if ((await challenges(v)) !== 2n)
      return (why("budget after quorum cancel + re-initiation is " + (await challenges(v))), false);
    return revertedWith(await outcome(challenge(w, v, w.credKey)), "ChallengeExhausted")
      ? true
      : (why("a third challenge was accepted"), false);
  },
  "P-EPOCH-SURVIVES-EXPIRY-NO-CLEANUP": async (w, v, why) => {
    if (!(await exhaust(w, v, "eex"))) return (why("setup: could not exhaust the budget"), false);
    if (!(await outcome(propose(w, v, mkCred("eex-r3")))).ok) return (why("setup: third initiation failed"), false);
    await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
    // If the kernel offers a cleanup transaction, ATTEMPT it: none may be
    // required, and none may refund. On the real kernel the call has no
    // selector behind it and simply reverts.
    await outcome(v.sweepExpiredRecovery());
    if (!(await outcome(propose(w, v, mkCred("eex-r4")))).ok)
      return (why("setup: re-initiation after expiry failed"), false);
    if ((await challenges(v)) !== 2n)
      return (why("budget after expiry + re-initiation is " + (await challenges(v))), false);
    return revertedWith(await outcome(challenge(w, v, w.credKey)), "ChallengeExhausted")
      ? true
      : (why("a third challenge was accepted"), false);
  },
  "P-EPOCH-SURVIVES-ROTATION": async (w, v, why) => {
    if (!(await exhaust(w, v, "erot"))) return (why("setup: could not exhaust the budget"), false);
    if (!(await outcome(rotateInPlace(w, v))).ok) return (why("setup: rotation failed"), false);
    if (!(await outcome(propose(w, v, mkCred("erot-r3")))).ok) return (why("setup: re-initiation failed"), false);
    if ((await challenges(v)) !== 2n)
      return (why("budget after rotation + re-initiation is " + (await challenges(v))), false);
    return revertedWith(await outcome(challenge(w, v, w.credKey)), "ChallengeExhausted")
      ? true
      : (why("a third challenge was accepted"), false);
  },
  "P-EPOCH-CARRIED-ON-INITIATION": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("carry")))).ok) return (why("setup: initiation failed"), false);
    if (!(await outcome(challenge(w, v, w.credKey))).ok) return (why("setup: challenge failed"), false);
    if (!(await outcome(propose(w, v, mkCred("carry")))).ok) return (why("setup: re-initiation failed"), false);
    const used = await challenges(v);
    return used === 1n ? true : (why("budget after re-initiation is " + used + ", expected 1"), false);
  },
  "P-EPOCH-RESETS-ON-SUCCESS": async (w, v, why) => {
    if (!(await exhaust(w, v, "reset"))) return (why("setup: could not exhaust the budget"), false);
    const c = mkCred("reset-new");
    if (!(await outcome(propose(w, v, c))).ok) return (why("setup: initiation failed"), false);
    await networkHelpers.time.increase(7 * DAY + 1);
    if (!(await outcome(execute(w, v, c))).ok) return (why("setup: recovery did not execute"), false);
    if ((await challenges(v)) !== 0n)
      return (why("budget after a successful recovery is " + (await challenges(v))), false);
    if (!(await outcome(propose(w, v, mkCred("reset-later")))).ok)
      return (why("setup: later initiation failed"), false);
    return (await outcome(challenge(w, v, c.nominee))).ok
      ? true
      : (why("the recovered credential could not challenge"), false);
  },
  "P-CHALLENGE-BOUNDED": async (w, v, why) => {
    if (!(await exhaust(w, v, "bound"))) return (why("setup: could not exhaust the budget"), false);
    if (!(await outcome(propose(w, v, mkCred("bound-r3")))).ok) return (why("setup: third initiation failed"), false);
    return revertedWith(await outcome(challenge(w, v, w.credKey)), "ChallengeExhausted")
      ? true
      : (why("a third challenge was accepted"), false);
  },
  "P-LIVE-OVERWRITE-REFUSED": async (w, v, why) => {
    const c1 = mkCred("ow-1");
    if (!(await outcome(propose(w, v, c1))).ok) return (why("setup: initiation failed"), false);
    const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
    const r = await outcome(propose(w, v, mkCred("ow-2")));
    if (!revertedWith(r, "BadState"))
      return (why(r.ok ? "a live request was overwritten" : "wrong refusal: " + r.err.slice(0, 80)), false);
    if (((await v.nonces(DOMAIN.GUARDIAN)) as bigint) !== gNonce)
      return (why("refused overwrite consumed a nonce"), false);
    return (await v.recovery())[R.SIGNER] === addrOf(c1.nominee) ? true : (why("original request not intact"), false);
  },
  "P-EXPIRED-DOES-NOT-BLOCK-MIGRATION": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("mig")))).ok) return (why("setup: initiation failed"), false);
    await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
    const r = await outcome(bindMigration(w, v));
    return r.ok ? true : (why("expired request blocked migration: " + r.err.slice(0, 80)), false);
  },
  "P-EXPIRED-DOES-NOT-BLOCK-INITIATION": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("init")))).ok) return (why("setup: initiation failed"), false);
    if (!(await outcome(challenge(w, v, w.credKey))).ok) return (why("setup: challenge failed"), false);
    if (!(await outcome(propose(w, v, mkCred("init-2")))).ok) return (why("setup: second initiation failed"), false);
    await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
    const r = await outcome(propose(w, v, mkCred("init-3")));
    if (!r.ok) return (why("expired request blocked a fresh initiation: " + r.err.slice(0, 80)), false);
    return (await challenges(v)) === 1n ? true : (why("budget not preserved across expiry"), false);
  },
  "P-EXPIRED-NOT-CHALLENGEABLE": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("nch")))).ok) return (why("setup: initiation failed"), false);
    const E = await expiresAt(v);
    const cNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
    await networkHelpers.time.increaseTo(Number(E - 1n));
    await networkHelpers.time.setNextBlockTimestamp(Number(E));
    const r = await outcome(challenge(w, v, w.credKey, MINED));
    if (!revertedWith(r, "NoRecovery"))
      return (
        why(r.ok ? "an expired request was challenged at expiresAt" : "wrong refusal: " + r.err.slice(0, 80)),
        false
      );
    if ((await challenges(v)) !== 0n) return (why("a refused challenge consumed budget"), false);
    return ((await v.nonces(DOMAIN.CREDENTIAL)) as bigint) === cNonce
      ? true
      : (why("a refused challenge consumed a nonce"), false);
  },
  "P-EXPIRED-NOT-QUORUM-CANCELLABLE": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("nqc")))).ok) return (why("setup: initiation failed"), false);
    const E = await expiresAt(v);
    const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
    await networkHelpers.time.increaseTo(Number(E - 1n));
    await networkHelpers.time.setNextBlockTimestamp(Number(E));
    const r = await outcome(quorumCancel(w, v, MINED));
    if (!revertedWith(r, "NoRecovery"))
      return (
        why(r.ok ? "an expired request was quorum-cancelled at expiresAt" : "wrong refusal: " + r.err.slice(0, 80)),
        false
      );
    return ((await v.nonces(DOMAIN.GUARDIAN)) as bigint) === gNonce
      ? true
      : (why("a refused cancellation consumed a nonce"), false);
  },
  "P-HALF-OPEN-EXPIRY-BOUNDARY": async (w, v, why) => {
    const c = mkCred("half");
    if (!(await outcome(propose(w, v, c))).ok) return (why("setup: initiation failed"), false);
    const E = await expiresAt(v);
    await networkHelpers.time.increaseTo(Number(E - 1n));
    await networkHelpers.time.setNextBlockTimestamp(Number(E));
    const r = await outcome(execute(w, v, c, MINED));
    if (!revertedWith(r, "Expired"))
      return (why(r.ok ? "execution accepted AT expiresAt" : "wrong refusal: " + r.err.slice(0, 80)), false);
    // Positive half on a second world: E-1 is live and executes.
    const w2 = await deployWorld({ label: w.opts.label + "-em1", implOverride: w.opts.implOverride });
    const v2 = bind(w2);
    const c2 = mkCred("half-em1");
    if (!(await outcome(propose(w2, v2, c2))).ok) return (why("setup: second initiation failed"), false);
    const E2 = await expiresAt(v2);
    await networkHelpers.time.increaseTo(Number(E2 - 2n));
    await networkHelpers.time.setNextBlockTimestamp(Number(E2 - 1n));
    const r2 = await outcome(execute(w2, v2, c2, MINED));
    return r2.ok ? true : (why("execution at expiresAt-1 refused: " + r2.err.slice(0, 80)), false);
  },
  "P-STALE-QUORUM-CANCEL-REPLAY-EXCLUDED": async (w, v, why) => {
    if (!(await outcome(propose(w, v, mkCred("stale-r1")))).ok) return (why("setup: R1 failed"), false);
    const N1 = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
    const stale = await presignQuorumCancel(w, v, N1);
    if (!(await outcome(challenge(w, v, w.credKey))).ok) return (why("setup: R1 challenge failed"), false);
    const r2 = mkCred("stale-r2");
    if (!(await outcome(propose(w, v, r2))).ok) return (why("setup: R2 failed"), false);
    const r = await outcome(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE));
    if (r.ok) return (why(STALE_CANCEL_REACHED_R2), false);
    if (!(await isActive(v))) return (why("R2 not live after the stale cancel"), false);
    return (await v.recovery())[R.SIGNER] === addrOf(r2.nominee) ? true : (why("R2 not the stored request"), false);
  },
};

const PROPERTY_IDS = Object.keys(PROPERTIES) as PropertyId[];

// ---------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------

interface Cell {
  mutant: string;
  property: PropertyId;
  holdsOnReal: boolean;
  holdsOnMutant: boolean;
  detail: string;
}

describe("W2 — frozen mutation contract: fifteen mutants plus W2P's sixteenth, one property each", function () {
  this.timeout(3_600_000);

  const compiled = new Map<string, DeployableMutant>();
  const compileFailures: { id: string; errors: string[] }[] = [];
  /**
   * The real-kernel verdict of each property, computed LAZILY and memoised on
   * first use (Lane W2P, closing W2R-3). Every kill test needs the positive
   * direction of its own property; resolving it here rather than in a preceding
   * `it` makes each test independent of intra-file order, so any single kill
   * test runs alone (mocha --grep) with its vacuity guard intact.
   */
  const realVerdicts = new Map<PropertyId, Promise<{ holds: boolean; detail: string }>>();
  const realVerdict = (p: PropertyId): Promise<{ holds: boolean; detail: string }> => {
    let pending = realVerdicts.get(p);
    if (pending === undefined) {
      pending = evaluate(p, "w2m-real-" + p.toLowerCase());
      realVerdicts.set(p, pending);
    }
    return pending;
  };
  const matrix: Cell[] = [];

  before(function () {
    // Compile every mutant UP FRONT (execFileSync must not overlap the in-process EVM).
    for (const m of W2_MUTANTS) {
      let built: ReturnType<typeof compileDeployable>;
      try {
        built = compileDeployable({ "VaultKernelPrototype.sol": m.apply(w2Source()) });
      } catch (e) {
        compileFailures.push({ id: m.id, errors: [e instanceof Error ? e.message : String(e)] });
        continue;
      }
      if (built.ok) compiled.set(m.id, built.kernel);
      else compileFailures.push({ id: m.id, errors: built.errors });
    }
  });

  /**
   * Runs one scenario inside an EVM snapshot and rolls the chain back afterwards.
   *
   * The prototype suite shares ONE simulated chain across every test file
   * (`test/connection.ts`), and every world is funded with 10 ETH from the same
   * deployer account. This file evaluates 15 x 15 cells plus the real-kernel
   * baseline and the vacuity guards; left unrestored, those worlds alone spend
   * more than 2,000 ETH of that account, and in a full run they came last —
   * the informational matrix failed with "Sender doesn't have enough funds", a
   * resource artefact of test ORDER, not a semantic result. Restoring after
   * each scenario makes this file's chain footprint independent of how many
   * cells it evaluates and of how many worlds the files before it deployed.
   */
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
      const v = bind(w);
      let detail = "";
      const holds = await PROPERTIES[property](w, v, (s) => {
        detail = s;
      });
      return { holds, detail };
    });
  }

  it("the contract is complete: fifteen frozen mutants plus one, sixteen distinct ids, every assigned property defined", function () {
    expect(W2_MUTANTS).to.have.length(16);
    expect(new Set(W2_MUTANTS.map((m) => m.id)).size).to.equal(16);
    for (const m of W2_MUTANTS) expect(PROPERTY_IDS, m.id + " names an unknown property").to.include(m.killedBy);
  });

  it("every mutant applies to the W2 source exactly once and compiles", function () {
    expect(
      compileFailures,
      "a mutant failed to apply or compile — its anchor is stale against the W2 kernel, so it would test nothing:\n" +
        JSON.stringify(compileFailures, null, 2),
    ).to.deep.equal([]);
    expect(compiled.size).to.equal(W2_MUTANTS.length);
  });

  it("every property HOLDS on the shipped kernel (the positive direction of every discriminator)", async function () {
    const failures: string[] = [];
    for (const p of PROPERTY_IDS) {
      const r = await realVerdict(p);
      if (!r.holds) failures.push(p + ": " + r.detail);
    }
    expect(failures, "properties that FAIL on the real W2 kernel").to.deep.equal([]);
  });

  for (const m of W2_MUTANTS) {
    it("kills " + m.id + " by " + m.killedBy, async function () {
      const kernel = compiled.get(m.id);
      expect(kernel, m.id + " did not compile").to.not.equal(undefined);

      // VACUITY GUARD: the mutant must be a WORKING kernel — it must deploy and
      // complete a positive-control transition before any kill is credited.
      const control = await withSnapshot(async () => {
        const wv = await deployWorld({ label: "w2m-vac-" + m.id, implOverride: kernel });
        return outcome(propose(wv, bind(wv), mkCred("vac")));
      });
      expect(
        control.ok,
        "INCONCLUSIVE: mutant " + m.id + " cannot even initiate a recovery: " + control.err.slice(0, 120),
      ).to.equal(true);

      const real = await realVerdict(m.killedBy);
      expect(
        real.holds,
        "the assigned property must HOLD on the real kernel before it can kill anything: " + real.detail,
      ).to.equal(true);

      const r = await evaluate(m.killedBy, "w2m-" + m.id + "-" + m.killedBy.toLowerCase(), kernel);
      matrix.push({ mutant: m.id, property: m.killedBy, holdsOnReal: true, holdsOnMutant: r.holds, detail: r.detail });
      expect(
        r.holds,
        "SURVIVOR: " + m.id + " was not killed by its assigned property " + m.killedBy + " (breaks: " + m.breaks + ")",
      ).to.equal(false);
      expect(
        r.detail.startsWith("setup:"),
        "the kill must be an OBSERVED violation, not a setup failure: " + r.detail,
      ).to.equal(false);
      if (m.observation !== undefined) {
        expect(
          r.detail,
          "the kill must be THE observation this mutant exists for (the dangerous path), not an unrelated refusal",
        ).to.equal(m.observation);
      }
    });
  }

  it("prints the full mutant x property kill matrix (informational beyond the assigned diagonal)", async function () {
    const rows: string[] = [];
    const header = "mutant".padEnd(50) + PROPERTY_IDS.map((_, i) => String(i + 1).padStart(3)).join("");
    rows.push(header);
    for (const m of W2_MUTANTS) {
      const kernel = compiled.get(m.id);
      const cells: string[] = [];
      for (const p of PROPERTY_IDS) {
        const assigned = matrix.find((c) => c.mutant === m.id && c.property === p);
        let killed: boolean;
        if (assigned) killed = !assigned.holdsOnMutant;
        else {
          const r = await evaluate(p, "w2m-x-" + m.id + "-" + p.toLowerCase(), kernel);
          // A setup failure on an off-diagonal cell is NOT a kill: report it as "?".
          killed = !r.holds && !r.detail.startsWith("setup:");
          if (!r.holds && r.detail.startsWith("setup:")) {
            cells.push("  ?");
            continue;
          }
        }
        cells.push(p === m.killedBy ? (killed ? "  K" : "  S") : killed ? "  k" : "  .");
      }
      rows.push(m.id.padEnd(50) + cells.join(""));
    }
    rows.push("");
    rows.push(
      "legend: K = assigned property kills (load-bearing), k = another property also kills, . = survives that property, ? = scenario not reachable on this mutant",
    );
    PROPERTY_IDS.forEach((p, i) => rows.push(String(i + 1).padStart(3) + " " + p));
    console.log("\n  W2 MUTATION KILL MATRIX\n" + rows.map((r) => "  " + r).join("\n") + "\n");
    expect(
      matrix.filter((c) => c.holdsOnMutant).map((c) => c.mutant),
      "survivors on the assigned diagonal",
    ).to.deep.equal([]);
    expect(matrix).to.have.length(W2_MUTANTS.length);
  });
});
