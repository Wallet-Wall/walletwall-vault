/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE ACTION MODEL — the generated commands, and who issues them.
 *
 * Every action below has a REAL externally reachable counterpart on
 * VaultKernelPrototype / VaultKernelFactoryPrototype. There are deliberately no
 * synthetic actions: an action with no on-chain counterpart could only ever
 * exercise the harness.
 *
 * BOTH VALID AND ADVERSARIAL FORMS ARE GENERATED. An invalid call is not waste:
 * how a call FAILS is itself a security property (does it burn a nonce? leave
 * half-installed state? count a forged attestation?), so the generator is
 * allowed to attempt anything in any state and the campaign is NOT pre-filtered
 * to "sequences a human thinks would be attempted".
 *
 * CHAIN READS ARE FOR CONSTRUCTION, NEVER FOR JUDGEMENT
 * ----------------------------------------------------
 * Nonces, generations and the current floor are read from the kernel in order to
 * BUILD a well-formed call — exactly as any real caller must. They are never
 * used to decide whether an outcome was authorised. That decision comes only
 * from the harness's own record of which roots the issuing actor holds
 * (`rootsNow`) and from the declared cuts. Keeping those two uses apart is what
 * stops the oracle collapsing into a second copy of the implementation.
 */
import { ethers } from "../test/connection.js";
import { networkHelpers } from "../test/connection.js";
import type { Prng } from "./prng.js";
import type { AbstractState } from "./model.js";
import { recordCancellation, recordExecution, recordInitiation } from "./model.js";
import type { Actor, Floor, Root, VerifierKind, World } from "./world.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  ALL_MATERIAL,
  GUARDIAN_ROOTS,
  ZERO,
  addrOf,
  digestOf,
  keyOf,
  migrationParams,
  pqHash,
  pqKeyBytes,
  recoverParams,
  rosterCommitment,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
} from "./world.js";

// =====================================================================
// Live context — the harness's OWN bookkeeping of installed key material
// =====================================================================

export interface Ctx {
  world: World;
  abstract: AbstractState;
  /** The ECDSA credential key the harness believes is installed, and its label. */
  credKey: ethers.SigningKey;
  credLabel: string;
  /** The PQ credential key the harness believes is installed, and its label. */
  pqKey: ethers.SigningKey;
  pqLabel: string;
  /** The current roster, ASCENDING, with the labels of the keys behind each seat. */
  guardianKeys: ethers.SigningKey[];
  guardianLabels: string[];
  guardianIsContract: boolean[];
  threshold: bigint;
  /**
   * Which verifier mock is installed, tracked by the harness because IT issued
   * the transition that installed it. Used by `rootsNow` — see the Byzantine
   * degradation note there.
   */
  verifierKind: VerifierKind;
  /**
   * Whether the KERNEL currently demands the PQ conjunct. Tracked by the harness
   * because IT issued every transition that could change it. When false the PQ
   * factor is not a ROOT at all — the verifier is never consulted — so counting
   * it would inflate every root tally on an ECDSA-only vault.
   */
  requirePqNow: boolean;
  /** Which policy plane the harness installed. "deny" must make every spend fail. */
  policyKind: string;
  /**
   * When set, `ROTATE_CREDENTIAL` FABRICATES its incoming commitment on a
   * deterministic subset of steps: a hash whose preimage nothing in this
   * campaign holds, with an empty exhibit. This is the SD-6 attack, generated.
   *
   * It exists because `G-COMMITMENT-ATTESTED` would otherwise be green for the
   * worst possible reason — the bad transition being unreachable in every
   * profile rather than refused by the kernel. The subset is chosen from the
   * EXISTING `target` draw and never calls `prng` again, and the flag is set on
   * ONE APPENDED profile, so every historical campaign's action stream, kill
   * seed and step index are byte-identical.
   */
  fabricateCommitments: boolean;
  /** Raw calldata of every attempt, so REPLAY can resubmit one verbatim later. */
  history: Recorded[];
  step: number;
}

export interface Recorded {
  step: number;
  kind: string;
  actor: string;
  /** The roots the ORIGINAL issuer held when this calldata was signed. */
  authorRoots: Root[];
  to: string;
  data: string;
  value: bigint;
  ok: boolean;
}

/**
 * WHICH ROOTS THIS ACTOR HOLDS RIGHT NOW.
 *
 * Recomputed every step from the harness's bookkeeping: an actor holds the
 * ECDSA credential root exactly when the key CURRENTLY installed as the
 * credential is one whose label it owns. So an attacker who held the credential
 * before an honest recovery stops holding it the moment the recovery lands —
 * which is the difference between a model that tracks authority and one that
 * merely tracks a constant.
 */
export function rootsNow(actor: Actor, ctx: Ctx): Set<Root> {
  const held = new Set<Root>();
  if (owns(actor, ctx.credLabel)) held.add("CRED_ECDSA");
  // THE BYZANTINE DEGRADATION, MODELLED EXPLICITLY RATHER THAN PATCHED AWAY.
  //
  // An ALWAYS-TRUE verifier authenticates nobody: the PQ conjunct is satisfied
  // by any caller, so the PQ credential has stopped being a ROOT. AUTHORITY.md
  // says exactly this — "an always-true verifier collapses HYBRID to ECDSA
  // security and never to unauthenticated authorization" — and the model must
  // agree, or the campaign would score a legitimate degradation as a violation
  // and, far worse, would go on crediting the honest party with a second root
  // it no longer has.
  //
  // Installing such a verifier still costs the FULL hybrid authority
  // (setVerifier calls _authorise), so this degrades what a root is worth
  // AFTERWARDS; it never lowers the cost of the transition that caused it.
  if (ctx.requirePqNow && (owns(actor, ctx.pqLabel) || ctx.verifierKind === "alwaysTrue")) held.add("CRED_PQ");
  // GUARDIAN ROOTS ARE COUNTED BY DISTINCT ADDRESS, NEVER BY SEAT.
  //
  // An earlier version indexed roots by SEAT, reasoning that the kernel's
  // strictly-ascending roster makes seats and principals 1:1. That reasoning is
  // correct about the real kernel and WRONG as a model: it makes the oracle
  // inherit the very assumption under test. The mutation suite proved it. The
  // mutant that relaxes the roster to NON-DECREASING installs a roster in which
  // one principal holds two seats, and a seat-indexed model then credited that
  // principal with TWO guardian roots and saw no violation — the oracle agreed
  // with the defect it existed to catch.
  //
  // Counting distinct ADDRESSES is what "a principal is an ADDRESS, not a seat"
  // means on the model side, and it holds whatever the kernel does.
  const ownedAddresses = new Set<string>();
  for (let seat = 0; seat < ctx.guardianLabels.length; seat++) {
    if (owns(actor, ctx.guardianLabels[seat]!)) {
      const key = ctx.guardianKeys[seat];
      if (key !== undefined) ownedAddresses.add(addrOf(key).toLowerCase());
    }
  }
  [...ownedAddresses].sort().forEach((_addr, i) => {
    held.add(GUARDIAN_ROOTS[i] ?? (("GUARDIAN_" + i) as Root));
  });
  return held;
}

/**
 * `"*"` is the ALL-MATERIAL sentinel, held only by the fully-honest positive
 * control. Every other actor names the exact labels it owns, so its authority
 * shrinks automatically when a rotation or roster change moves the material.
 */
export const owns = (a: Actor, label: string): boolean =>
  a.ownedLabels.has(ALL_MATERIAL) || a.ownedLabels.has(label);

/**
 * The key an actor can actually sign the credential with — or a DECOY it holds
 * instead. Substituting a decoy rather than skipping the signature is what makes
 * these real attacks: the calldata is WELL FORMED and the signature RECOVERS to
 * a real address, just not the authorised one. A malformed blob would be
 * rejected earlier, on shape, and would never reach the authority seam.
 */
function credSigningKey(actor: Actor, ctx: Ctx): ethers.SigningKey {
  return owns(actor, ctx.credLabel) ? ctx.credKey : keyOf(actor.name + "-decoy-ecdsa");
}
function pqSigningKey(actor: Actor, ctx: Ctx): ethers.SigningKey {
  return owns(actor, ctx.pqLabel) ? ctx.pqKey : keyOf(actor.name + "-decoy-pq");
}
function guardianSigningKey(actor: Actor, ctx: Ctx, seat: number): ethers.SigningKey {
  return owns(actor, ctx.guardianLabels[seat]!)
    ? ctx.guardianKeys[seat]!
    : keyOf(actor.name + "-decoy-guardian-" + seat);
}

// =====================================================================
// Quorum construction, including the adversarial shapes
// =====================================================================

export type QuorumShape =
  | "honest"
  | "forgeMissing"
  | "duplicateIndex"
  | "sentinelMaxIndex"
  | "descendingIndices"
  | "outOfRangeIndex"
  | "emptyAttestations";

export const QUORUM_SHAPES: readonly QuorumShape[] = [
  "honest",
  "forgeMissing",
  "duplicateIndex",
  "sentinelMaxIndex",
  "descendingIndices",
  "outOfRangeIndex",
  "emptyAttestations",
];

const MAX_UINT256 = (1n << 256n) - 1n;

/**
 * Builds a QuorumProof. The adversarial shapes are the point:
 *
 *  - `duplicateIndex` and `descendingIndices` attack I-QUORUM-DISTINCTNESS;
 *  - `sentinelMaxIndex` attacks the `previous = type(uint256).max` SENTINEL in
 *    `_requireQuorum` directly. That sentinel disables the ordering comparison
 *    on its first iteration, so if an attacker can KEEP `previous` equal to it,
 *    the ordering check never engages. This is a classic sentinel-collision
 *    shape and the campaign submits it deliberately rather than reasoning about it;
 *  - `forgeMissing` is the ordinary attack: attest for every seat, forging the
 *    ones the actor does not hold.
 */
export function buildQuorum(
  actor: Actor,
  ctx: Ctx,
  digest: string,
  shape: QuorumShape,
  prng: Prng,
): { members: string[]; isContract: boolean[]; attestingIndices: bigint[]; attestations: string[] } {
  const members = ctx.guardianKeys.map(addrOf);
  const isContract = ctx.guardianIsContract;
  const seats = members.map((_, i) => i);

  const attestFor = (seat: number): string => sign(guardianSigningKey(actor, ctx, seat), digest);

  switch (shape) {
    case "honest": {
      const owned = seats.filter((s) => owns(actor, ctx.guardianLabels[s]!));
      return {
        members,
        isContract,
        attestingIndices: owned.map((s) => BigInt(s)),
        attestations: owned.map(attestFor),
      };
    }
    case "forgeMissing":
      return {
        members,
        isContract,
        attestingIndices: seats.map((s) => BigInt(s)),
        attestations: seats.map(attestFor),
      };
    case "duplicateIndex": {
      const s = prng.pick(seats);
      return {
        members,
        isContract,
        attestingIndices: [BigInt(s), BigInt(s)],
        attestations: [attestFor(s), attestFor(s)],
      };
    }
    case "sentinelMaxIndex": {
      // Feed the SENTINEL VALUE ITSELF as the first index, then a real seat
      // twice. If the sentinel comparison is confusable, the duplicate slips past.
      const s = prng.pick(seats);
      return {
        members,
        isContract,
        attestingIndices: [MAX_UINT256, BigInt(s), BigInt(s)],
        attestations: [attestFor(s), attestFor(s), attestFor(s)],
      };
    }
    case "descendingIndices": {
      const desc = seats.slice().reverse();
      return {
        members,
        isContract,
        attestingIndices: desc.map((s) => BigInt(s)),
        attestations: desc.map(attestFor),
      };
    }
    case "outOfRangeIndex":
      return {
        members,
        isContract,
        attestingIndices: [0n, BigInt(members.length + 3)],
        attestations: [attestFor(0), attestFor(0)],
      };
    case "emptyAttestations":
      return { members, isContract, attestingIndices: [], attestations: [] };
    default:
      return { members, isContract, attestingIndices: [], attestations: [] };
  }
}

// =====================================================================
// The action vocabulary
// =====================================================================

export const ACTION_KINDS = [
  "FUND",
  "SPEND",
  "ROTATE_CREDENTIAL",
  "SET_VERIFIER",
  "SET_POLICY",
  "SET_GUARDIANS",
  "INITIATE_RECOVERY",
  "CANCEL_RECOVERY",
  "EXECUTE_RECOVERY",
  "ENTER_CONTAINMENT",
  "BIND_MIGRATION",
  "RETIRE",
  "EGRESS_NATIVE",
  "EGRESS_TOKEN",
  "ADVANCE_TIME",
  "REPLAY_PAST_CALL",
  "FACTORY_DEPLOY_TWIN",
] as const;

export type ActionKind = (typeof ACTION_KINDS)[number];

/**
 * Actions the kernel makes PERMISSIONLESS on purpose, because they carry no
 * discretion: the recipient and the effect were fixed by an earlier, authorised
 * decision. Their effects are attributed to THAT decision's roots, never to
 * whoever pays the gas — including when they are reached by replay.
 */
export const PERMISSIONLESS_FINALISERS: ReadonlySet<string> = new Set([
  "EGRESS_NATIVE",
  "EGRESS_TOKEN",
  "RETIRE",
]);

export interface GeneratedAction {
  kind: ActionKind;
  actorName: string;
  /** Everything needed to replay this exact step, in JSON-safe form. */
  params: Record<string, string | number | boolean>;
}

export interface ExecOutcome {
  ok: boolean;
  revert: string | null;
  /** Set when the action deliberately proved possession of the OUTGOING factors (R4). */
  usedStalePossession?: boolean;
  /** Roots the model charges this action's effects to. Empty for a no-authority action. */
  attributedRoots: Set<Root>;
  /** Set when the model itself judged something wrong, independent of the kernel. */
  modelViolation: string | null;
}

const errName = (e: unknown): string => {
  const msg = e instanceof Error ? e.message : String(e);
  const m = /custom error '([A-Za-z0-9_]+)/.exec(msg) ?? /reverted with reason string '([^']*)'/.exec(msg);
  if (m) return m[1]!;
  if (/VerifierDenied/.test(msg)) return "VerifierDenied";
  return msg.slice(0, 160).replace(/\s+/g, " ");
};

/** Which mock a verifier ADDRESS is. Pure harness bookkeeping over its own deployments. */
export function verifierKindOf(w: World, address: string): VerifierKind {
  const lower = address.toLowerCase();
  for (const k of ["honest", "alwaysTrue", "alwaysFalse", "reverting"] as VerifierKind[]) {
    if (w.verifiers[k].toLowerCase() === lower) return k;
  }
  return "honest";
}

async function currentFloor(ctx: Ctx): Promise<Floor> {
  const f = await ctx.world.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

const signerOf = (actor: Actor, ctx: Ctx): ethers.Signer =>
  actor.sendsAs === "deployer" ? ctx.world.deployer : ctx.world.outsider;

/**
 * Runs one generated action against the real kernel. NEVER throws on a revert:
 * a revert is data, not a test failure, and several properties are ABOUT the
 * revert (see PHASE 10 atomicity). Only harness bugs propagate.
 */
export async function executeAction(
  action: GeneratedAction,
  actor: Actor,
  ctx: Ctx,
  prng: Prng,
): Promise<ExecOutcome> {
  const w = ctx.world;
  const vault = w.vault.connect(signerOf(actor, ctx)) as ethers.Contract;
  const held = rootsNow(actor, ctx);
  const kernelGen = 1n;
  const p = action.params;

  const record = (to: string, data: string, value: bigint, ok: boolean): void => {
    ctx.history.push({
      step: ctx.step,
      kind: action.kind,
      actor: actor.name,
      authorRoots: [...held],
      to,
      data,
      value,
      ok,
    });
  };

  const attempt = async (
    build: () => Promise<{ data: string; value?: bigint }>,
    onSuccess?: () => void,
  ): Promise<ExecOutcome> => {
    let built: { data: string; value?: bigint };
    try {
      built = await build();
    } catch (e) {
      // A call the harness could not even encode is recorded and skipped; it is
      // never silently dropped, because a silently-dropped action is a hole in
      // the campaign that looks like coverage.
      return { ok: false, revert: "HARNESS_ENCODE:" + errName(e), attributedRoots: held, modelViolation: null };
    }
    try {
      const tx = await signerOf(actor, ctx).sendTransaction({
        to: w.vaultAddress,
        data: built.data,
        value: built.value ?? 0n,
      });
      await tx.wait();
      record(w.vaultAddress, built.data, built.value ?? 0n, true);
      if (onSuccess) onSuccess();
      return { ok: true, revert: null, attributedRoots: held, modelViolation: null };
    } catch (e) {
      record(w.vaultAddress, built.data, built.value ?? 0n, false);
      return { ok: false, revert: errName(e), attributedRoots: held, modelViolation: null };
    }
  };

  switch (action.kind) {
    case "FUND": {
      const value = ethers.parseEther(String(p.eth ?? "1"));
      try {
        await (await signerOf(actor, ctx).sendTransaction({ to: w.vaultAddress, value })).wait();
        return { ok: true, revert: null, attributedRoots: new Set<Root>(), modelViolation: null };
      } catch (e) {
        return { ok: false, revert: errName(e), attributedRoots: new Set<Root>(), modelViolation: null };
      }
    }

    case "ADVANCE_TIME": {
      await networkHelpers.time.increase(Number(p.seconds ?? DAY));
      return { ok: true, revert: null, attributedRoots: new Set<Root>(), modelViolation: null };
    }

    case "SPEND":
      return attempt(async () => {
        const floor = await currentFloor(ctx);
        const nonce = (await vault.nonces(DOMAIN.SPEND)) as bigint;
        const credGen = (await vault.credentialGeneration()) as bigint;
        const to = p.toSelf ? w.vaultAddress : w.recipient;
        const amount = ethers.parseEther(String(p.eth ?? "1"));
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: kernelGen,
          actionType: ACTION.SPEND,
          authorityGeneration: credGen,
          params: spendParams(to, amount),
          domain: DOMAIN.SPEND,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const pqSig = floor.requirePq ? sign(pqSigningKey(actor, ctx), digest) : "0x";
        const pqKey = floor.requirePq ? pqKeyBytes(pqSigningKey(actor, ctx)) : "0x";
        return {
          data: vault.interface.encodeFunctionData("execute", [
            to,
            amount,
            nonce,
            FAR_DEADLINE,
            sign(credSigningKey(actor, ctx), digest),
            pqSig,
            pqKey,
          ]),
        };
      });

    case "ROTATE_CREDENTIAL": {
      const targetIdx = Number(p.target ?? 0) % w.spareCred.length;
      const newCred = w.spareCred[targetIdx]!;
      const newPq = w.sparePq[targetIdx]!;
      // THE SD-6 ATTACK, GENERATED. Derived from the EXISTING `target` draw, so
      // no `prng` call is added and every historical stream is unchanged; gated
      // on a flag only the appended `commitment-forgery` profile sets, so no
      // historical profile changes shape either.
      const fabricate = ctx.fabricateCommitments && targetIdx === 0;
      const installedHash = fabricate
        ? ethers.keccak256(ethers.toUtf8Bytes(w.opts.label + "-fabricated-" + ctx.step))
        : pqHash(newPq);
      const newCredLabel = w.opts.label + "-spare-cred-" + targetIdx;
      const newPqLabel = w.opts.label + "-spare-pq-" + targetIdx;
      // Captured BEFORE attempt(), whose onSuccess reassigns ctx.credKey.
      const outgoingCredAddr = addrOf(ctx.credKey);
      return attempt(
        async () => {
          const floor = await currentFloor(ctx);
          const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
          const credGen = (await vault.credentialGeneration()) as bigint;
          // `popStale` deliberately proves possession of the OUTGOING factors
          // instead of the incoming ones — property R4.
          const popStale = Boolean(p.popStale);
          const popKeyEc = popStale ? ctx.credKey : newCred;
          const popKeyPq = popStale ? ctx.pqKey : newPq;
          const pop = (await vault.credentialPossessionDigest(addrOf(newCred), installedHash)) as string;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.vaultAddress,
            kernelGeneration: kernelGen,
            actionType: ACTION.ROTATE,
            authorityGeneration: credGen,
            params: ethers.keccak256(
              ethers.AbiCoder.defaultAbiCoder().encode(
                ["address", "bytes32"],
                [addrOf(newCred), installedHash],
              ),
            ),
            domain: DOMAIN.CREDENTIAL,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const change = {
            newSigner: addrOf(newCred),
            newPqKeyHash: installedHash,
            // THE FABRICATED CASE EXHIBITS THE VAULT'S CURRENT KEY — public data
            // the attacker always has — while installing a DIFFERENT hash beside
            // it. An empty exhibit was tried first and was too weak: it dies on
            // any keccak comparison, so it could not distinguish a clause bound
            // to the INCOMING commitment from one bound to the OUTGOING one.
            // Mutation adequacy caught that (M22 survived), which is the whole
            // reason the mutant exists.
            newPqKey: fabricate ? pqKeyBytes(ctx.pqKey) : pqKeyBytes(newPq),
            newEcdsaPop: sign(popKeyEc, pop),
            newPqPop: fabricate ? "0x" : sign(popKeyPq, pop),
          };
          return {
            data: vault.interface.encodeFunctionData("rotateCredential", [
              change,
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
              floor.requirePq ? sign(pqSigningKey(actor, ctx), digest) : "0x",
              floor.requirePq ? pqKeyBytes(pqSigningKey(actor, ctx)) : "0x",
            ]),
          };
        },
        () => {
          ctx.credKey = newCred;
          ctx.credLabel = newCredLabel;
          // On a fabricated rotation the harness deliberately does NOT adopt a
          // PQ belief: it holds no preimage for what was written. Leaving the
          // stale belief in place is what makes a weakened kernel's acceptance
          // visible to G-COMMITMENT-ATTESTED instead of being papered over.
          if (!fabricate) {
            ctx.pqKey = newPq;
            ctx.pqLabel = newPqLabel;
          }
          ctx.abstract.credentialReplacements += 1;
        },
      ).then((r) => ({
        ...r,
        // A rotation whose TARGET is the key already installed makes "outgoing"
        // and "incoming" the same key, so a stale proof is a VALID proof and the
        // call is expected to succeed. Flagging it would be a false positive —
        // and it was one: three unrelated mutants were credited as killed by
        // this property before the equality was accounted for.
        usedStalePossession: Boolean(p.popStale) && outgoingCredAddr !== addrOf(newCred),
      }));
    }

    case "SET_VERIFIER": {
      const kind = String(p.verifier ?? "honest") as VerifierKind;
      let requirePqAfter = false;
      return attempt(async () => {
        const floor = await currentFloor(ctx);
        const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
        const credGen = (await vault.credentialGeneration()) as bigint;
        // The floor moves WITH the verifier. `bumpLevel` strengthens (allowed);
        // `shrinkLengths` keeps requirePq and pqParamLevel intact while changing
        // the two LENGTHS — the SD-1 seam, now refused by
        // `I-FLOOR-SHAPE-IMMUTABLE` whenever requirePq already holds.
        //
        // THE DIRECTION MATTERS, and it costs no prng draw to choose it. The
        // freeze is an INEQUALITY (`!=`) because `_requireIncomingPossession`
        // compares the shape for EXACT EQUALITY, so growing denies a
        // quorum-approved recovery exactly as shrinking does. A campaign that
        // only ever SHRINKS therefore cannot tell a correct `!=` from a
        // one-sided `<`, and such a weakening would survive every profile.
        //
        // So: where the clause is ARMED (`floor.requirePq`), the poisoning
        // attempt GROWS; where it is not, it shrinks to 1 exactly as before. On
        // the correct kernel both directions revert `Downgrade` identically, so
        // no reachable state moves and no history shifts — this buys mutant M18
        // for free. M17, which deletes the clause outright, dies on either.
        requirePqAfter = floor.requirePq || Boolean(p.raisePq);
        const growShape = floor.requirePq;
        const next: Floor = {
          requirePq: requirePqAfter,
          pqParamLevel: floor.pqParamLevel + (p.bumpLevel ? 1 : 0),
          pqPublicKeyLength: p.shrinkLengths
            ? growShape
              ? floor.pqPublicKeyLength + 1
              : 1
            : requirePqAfter && floor.pqPublicKeyLength === 0
              ? 32
              : floor.pqPublicKeyLength,
          pqSignatureLength: p.shrinkLengths
            ? growShape
              ? floor.pqSignatureLength + 1
              : 1
            : requirePqAfter && floor.pqSignatureLength === 0
              ? 65
              : floor.pqSignatureLength,
        };
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: kernelGen,
          actionType: ACTION.SET_VERIFIER,
          authorityGeneration: credGen,
          params: setVerifierParams(w.verifiers[kind], next),
          domain: DOMAIN.CREDENTIAL,
          nonce,
          deadline: FAR_DEADLINE,
        });
        return {
          data: vault.interface.encodeFunctionData("setVerifier", [
            w.verifiers[kind],
            [next.requirePq, next.pqParamLevel, next.pqPublicKeyLength, next.pqSignatureLength],
            nonce,
            FAR_DEADLINE,
            sign(credSigningKey(actor, ctx), digest),
            floor.requirePq ? sign(pqSigningKey(actor, ctx), digest) : "0x",
            // The `pqKey` slot serves TWO different roles depending on the edge,
            // and conflating them would silently hand an attacker a factor.
            //
            //   current requirePq TRUE — `_authorise` measures this against the
            //     vault's commitment, so it must stay the ACTOR's own key: an
            //     actor that does not hold the PQ root has to keep failing.
            //   current FALSE, next TRUE — the DECLARING edge. `_authorise`
            //     returns before reading it, and the kernel instead demands
            //     `I-DECLARATION-EXHIBITED`'s satisfiability witness for the
            //     shape being declared. That witness is the vault's committed
            //     PUBLIC key, so supplying it grants authority to nobody — every
            //     actor, attacker included, can read it off chain. On a vault
            //     with NO commitment it correctly fails to satisfy the witness,
            //     which is the SD-3 refusal the campaign should now see.
            //
            // No `prng` call is added, so no campaign history re-seeds.
            floor.requirePq
              ? pqKeyBytes(pqSigningKey(actor, ctx))
              : requirePqAfter
                ? pqKeyBytes(w.pqKey)
                : "0x",
          ]),
        };
      }, () => {
        ctx.verifierKind = kind;
        ctx.requirePqNow = requirePqAfter;
      });
    }

    case "SET_POLICY": {
      const which = String(p.policy ?? "allow");
      const target =
        which === "none" ? ZERO : (w.policies as Record<string, string>)[which] ?? w.policies.allow;
      return attempt(async () => {
        const floor = await currentFloor(ctx);
        const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
        const credGen = (await vault.credentialGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: kernelGen,
          actionType: ACTION.SET_POLICY,
          authorityGeneration: credGen,
          params: setPolicyParams(target),
          domain: DOMAIN.CREDENTIAL,
          nonce,
          deadline: FAR_DEADLINE,
        });
        return {
          data: vault.interface.encodeFunctionData("setPolicy", [
            target,
            nonce,
            FAR_DEADLINE,
            sign(credSigningKey(actor, ctx), digest),
            floor.requirePq ? sign(pqSigningKey(actor, ctx), digest) : "0x",
            floor.requirePq ? pqKeyBytes(pqSigningKey(actor, ctx)) : "0x",
          ]),
        };
      }, () => {
        ctx.policyKind = which;
      });
    }

    case "SET_GUARDIANS": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      const newThreshold = BigInt(Number(p.newThreshold ?? 2));
      // Rotate the roster to a fresh, canonical (ascending, distinct) set.
      const gen = Number(p.rosterGen ?? 1);
      let newKeys = [0, 1, 2]
        .map((i) => keyOf(w.opts.label + "-guardian-g" + gen + "-" + i))
        .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
      // A NON-CANONICAL roster: the same PRINCIPAL occupying two seats. The real
      // kernel makes this unrepresentable (_requireCanonicalRoster demands
      // STRICTLY ascending addresses), which is finding B's fix. Generating it is
      // how the campaign can tell that fix is still there: a kernel that relaxes
      // the comparison to non-decreasing accepts this roster, and one principal
      // then reaches a threshold of two.
      if (p.duplicateRoster) {
        // Built from the CURRENT roster, not from fresh keys. A duplicate roster
        // made of keys nobody holds proves nothing: the whole point is that a
        // principal ALREADY IN the constituency comes to occupy two seats, and
        // can then reach a threshold of two on its own.
        newKeys = [ctx.guardianKeys[0]!, ctx.guardianKeys[0]!, ctx.guardianKeys[1]!];
      }
      const currentByAddr = new Map(ctx.guardianKeys.map((k, i) => [addrOf(k), ctx.guardianLabels[i]!]));
      const newLabels = newKeys.map((k) => {
        const carried = currentByAddr.get(addrOf(k));
        if (carried !== undefined) return carried;
        const idx = [0, 1, 2].find((i) => addrOf(keyOf(w.opts.label + "-guardian-g" + gen + "-" + i)) === addrOf(k));
        return w.opts.label + "-guardian-g" + gen + "-" + idx;
      });
      const newMembers = newKeys.map(addrOf);
      const newIsContract = [false, false, false];
      return attempt(
        async () => {
          const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
          const gGen = (await vault.guardianGeneration()) as bigint;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.vaultAddress,
            kernelGeneration: kernelGen,
            actionType: ACTION.SET_GUARDIANS,
            authorityGeneration: gGen,
            params: rosterCommitment(newThreshold, newMembers, newIsContract),
            domain: DOMAIN.GUARDIAN,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const q = buildQuorum(actor, ctx, digest, shape, prng);
          return {
            data: vault.interface.encodeFunctionData("setGuardians", [
              newThreshold,
              newMembers,
              newIsContract,
              q,
              nonce,
              FAR_DEADLINE,
            ]),
          };
        },
        () => {
          ctx.guardianKeys = newKeys;
          ctx.guardianLabels = newLabels;
          ctx.guardianIsContract = newIsContract;
          ctx.threshold = newThreshold;
          ctx.abstract.guardianTransitions += 1;
        },
      );
    }

    case "INITIATE_RECOVERY": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      const targetIdx = Number(p.target ?? 1) % w.spareCred.length;
      const newCred = w.spareCred[targetIdx]!;
      const newPq = w.sparePq[targetIdx]!;
      const verifierKind = String(p.verifier ?? "honest") as VerifierKind;
      const proposedVerifier = w.verifiers[verifierKind];
      let boundGen = 0n;
      return attempt(
        async () => {
          const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
          boundGen = (await vault.guardianGeneration()) as bigint;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.vaultAddress,
            kernelGeneration: kernelGen,
            actionType: ACTION.RECOVER,
            authorityGeneration: boundGen,
            params: recoverParams(addrOf(newCred), pqHash(newPq), proposedVerifier),
            domain: DOMAIN.GUARDIAN,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const q = buildQuorum(actor, ctx, digest, shape, prng);
          return {
            data: vault.interface.encodeFunctionData("initiateRecovery", [
              addrOf(newCred),
              pqHash(newPq),
              proposedVerifier,
              q,
              nonce,
              FAR_DEADLINE,
            ]),
          };
        },
        () => {
          recordInitiation(
            ctx.abstract,
            ctx.step,
            addrOf(newCred),
            pqHash(newPq),
            proposedVerifier,
            Number(boundGen),
            held,
          );
        },
      );
    }

    case "CANCEL_RECOVERY":
      return attempt(
        async () => {
          const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
          const credGen = (await vault.credentialGeneration()) as bigint;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.vaultAddress,
            kernelGeneration: kernelGen,
            actionType: ACTION.RECOVER,
            authorityGeneration: credGen,
            params: ethers.id("CANCEL"),
            domain: DOMAIN.CREDENTIAL,
            nonce,
            deadline: FAR_DEADLINE,
          });
          return {
            data: vault.interface.encodeFunctionData("cancelRecovery", [
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
            ]),
          };
        },
        () => recordCancellation(ctx.abstract),
      );

    case "EXECUTE_RECOVERY": {
      // PERMISSIONLESS by design, so the effect is attributed to the ROOTS THAT
      // INITIATED the live episode, not to whoever pays the gas. See
      // RecoveryEvidence.authorizedBy.
      const live = ctx.abstract.liveEpisode === null ? null : ctx.abstract.episodes.get(ctx.abstract.liveEpisode);
      const attributed = new Set<Root>(live ? live.authorizedBy : []);
      const popStale = Boolean(p.popStale);
      let installedIdx = -1;
      let installedVerifier = "";
      // Captured BEFORE attempt(), whose onSuccess reassigns ctx.credKey.
      const outgoingCredAddr = addrOf(ctx.credKey);
      const res = await attempt(
        async () => {
          const r = await vault.recovery();
          const proposedSigner = r[0] as string;
          const proposedPqHash = r[1] as string;
          installedVerifier = r[2] as string;
          installedIdx = w.spareCred.findIndex((k) => addrOf(k) === proposedSigner);
          const popKeyEc = popStale ? ctx.credKey : (w.spareCred[installedIdx] ?? ctx.credKey);
          const popKeyPq = popStale ? ctx.pqKey : (w.sparePq[installedIdx] ?? ctx.pqKey);
          const pop = (await vault.recoveryPossessionDigest()) as string;
          const change = {
            newSigner: proposedSigner,
            newPqKeyHash: proposedPqHash,
            newPqKey: pqKeyBytes(w.sparePq[installedIdx] ?? ctx.pqKey),
            newEcdsaPop: sign(popKeyEc, pop),
            newPqPop: sign(popKeyPq, pop),
          };
          return { data: vault.interface.encodeFunctionData("executeRecovery", [change]) };
        },
        () => {
          if (installedIdx >= 0) {
            ctx.credKey = w.spareCred[installedIdx]!;
            ctx.credLabel = w.opts.label + "-spare-cred-" + installedIdx;
            ctx.pqKey = w.sparePq[installedIdx]!;
            ctx.pqLabel = w.opts.label + "-spare-pq-" + installedIdx;
          }
          // Recovery carries a REPLACEMENT VERIFIER — that is the escape from a
          // dead one — so the harness's belief about the installed verifier must
          // move with it, or the Byzantine degradation above goes stale.
          ctx.verifierKind = verifierKindOf(w, installedVerifier);
        },
      );
      let modelViolation: string | null = null;
      if (res.ok) {
        // JUDGED BY THE MODEL, not by the kernel: was there live evidence?
        if (live === undefined || live === null) {
          modelViolation = "R2/R3 — executeRecovery SUCCEEDED with no live recovery episode in the model";
        } else if (live.state !== "LIVE") {
          modelViolation = "R2/R3 — executeRecovery SUCCEEDED on evidence the model records as " + live.state;
        } else if (live.guardianTransitionsAtApproval !== ctx.abstract.guardianTransitions) {
          // R1. The constituency that APPROVED this recovery is no longer the
          // constituency in force. A request that survives the roster change
          // which replaced its approvers is a stale authorization retargeting
          // onto a configuration nobody approved it for.
          modelViolation =
            "R1 — executeRecovery SUCCEEDED after " +
            (ctx.abstract.guardianTransitions - live.guardianTransitionsAtApproval) +
            " guardian-roster transition(s) since the request was approved, so it was authorised by a " +
            "constituency that is no longer in force";
        }
        recordExecution(ctx.abstract, ctx.credLabel);
      }
      return {
        ...res,
        attributedRoots: attributed,
        modelViolation,
        usedStalePossession:
          popStale && installedIdx >= 0 && outgoingCredAddr !== addrOf(w.spareCred[installedIdx]!),
      };
    }

    case "ENTER_CONTAINMENT": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      return attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
        const gGen = (await vault.guardianGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: kernelGen,
          actionType: ACTION.RECOVER,
          authorityGeneration: gGen,
          params: ethers.id("CONTAIN"),
          domain: DOMAIN.GUARDIAN,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, ctx, digest, shape, prng);
        return { data: vault.interface.encodeFunctionData("enterContainment", [q, nonce, FAR_DEADLINE]) };
      });
    }

    case "BIND_MIGRATION": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      const res = await attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.MIGRATION)) as bigint;
        const gGen = (await vault.guardianGeneration()) as bigint;
        const destination = { vault: w.destination, codeHash: w.destinationCodeHash, generation: 2n };
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.vaultAddress,
          kernelGeneration: kernelGen,
          actionType: ACTION.BIND_MIGRATION,
          authorityGeneration: gGen,
          params: migrationParams(destination.vault, destination.codeHash, destination.generation),
          domain: DOMAIN.MIGRATION,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, ctx, digest, shape, prng);
        return {
          data: vault.interface.encodeFunctionData("bindMigration", [
            [destination.vault, destination.codeHash, destination.generation],
            q,
            nonce,
            FAR_DEADLINE,
            sign(credSigningKey(actor, ctx), digest),
          ]),
        };
      });
      if (res.ok) {
        ctx.abstract.migrationBound = true;
        ctx.abstract.migrationAuthorizedBy = new Set(held);
      }
      return res;
    }

    case "RETIRE": {
      const res = await attempt(async () => ({ data: vault.interface.encodeFunctionData("retire", []) }));
      if (res.ok) ctx.abstract.retired = true;
      // Permissionless finaliser of the migration decision.
      return { ...res, attributedRoots: new Set(ctx.abstract.migrationAuthorizedBy) };
    }

    case "EGRESS_NATIVE":
    case "EGRESS_TOKEN": {
      const asset = action.kind === "EGRESS_NATIVE" ? ZERO : w.token;
      const res = await attempt(async () => ({
        data: vault.interface.encodeFunctionData("egress", [asset]),
      }));
      // Same attribution rule as RETIRE: the authority decision was made at
      // bindMigration and the destination is pre-committed.
      return { ...res, attributedRoots: new Set(ctx.abstract.migrationAuthorizedBy) };
    }

    case "REPLAY_PAST_CALL": {
      // THE REPLAY CAMPAIGN. Resubmit a previously recorded call VERBATIM, after
      // arbitrary intervening transitions.
      //
      // ATTRIBUTION. Replaying confers NO authority, so a replayed SIGNED action
      // that succeeds is charged to the replayer's own (usually empty) roots —
      // which is precisely how a nonce that stopped being consumed shows up as a
      // cut violation.
      //
      // The PERMISSIONLESS finalisers are the exception, and getting this wrong
      // was a real defect in this harness that its own campaign caught: replaying
      // `egress` moved value and was charged to a stranger holding nothing,
      // reported as an asset-cut violation. But `egress` is permissionless BY
      // DESIGN and carries no discretion — the authority decision was made at
      // `bindMigration` — so a replay of it is charged exactly where a direct
      // call is charged. Anything else manufactures a violation on correct code.
      const prior = ctx.history.filter((h) => h.kind !== "REPLAY_PAST_CALL" && h.kind !== "FUND");
      if (prior.length === 0) {
        return { ok: false, revert: "NO_HISTORY", attributedRoots: new Set<Root>(), modelViolation: null };
      }
      const target = prior[Number(p.index ?? 0) % prior.length]!;
      const live =
        ctx.abstract.liveEpisode === null ? null : ctx.abstract.episodes.get(ctx.abstract.liveEpisode) ?? null;
      // WHOSE AUTHORITY DOES A REPLAY CARRY?
      //
      // If the original call SUCCEEDED, its authorization was CONSUMED — the
      // nonce advanced, the generation moved — so a second success on the same
      // calldata is a genuine replay and is charged to the REPLAYER, who holds
      // nothing. That is exactly how a kernel that stopped consuming nonces gets
      // caught.
      //
      // If the original call FAILED, nothing was consumed. The signatures inside
      // it are still the original issuer's, unspent, and resubmitting them later
      // — when the state-machine precondition that blocked them no longer holds
      // — is RELAYING an authorization, not forging one. Charging it to the
      // relayer manufactured a violation on correct code: a stranger rebroadcast
      // a guardian-signed setGuardians that had earlier failed on BadState, and
      // the campaign called it a guardian takeover at zero roots.
      const attributed = PERMISSIONLESS_FINALISERS.has(target.kind)
        ? new Set<Root>(ctx.abstract.migrationAuthorizedBy)
        : target.kind === "EXECUTE_RECOVERY"
          ? new Set<Root>(live ? live.authorizedBy : [])
          : target.ok
            ? held
            : new Set<Root>(target.authorRoots);
      try {
        const tx = await signerOf(actor, ctx).sendTransaction({
          to: target.to,
          data: target.data,
          value: target.value,
        });
        await tx.wait();
        // A REPLAYED executeRecovery that succeeds is judged by the MODEL exactly
        // as a direct one is: the question is whether live evidence existed, not
        // who sent the transaction.
        let modelViolation: string | null = null;
        if (target.kind === "EXECUTE_RECOVERY") {
          if (!live) modelViolation = "R3 — a REPLAYED executeRecovery succeeded with no live recovery episode";
          else if (live.state !== "LIVE") {
            modelViolation = "R3 — a REPLAYED executeRecovery succeeded on evidence the model records as " + live.state;
          }
          recordExecution(ctx.abstract, ctx.credLabel);
        }
        return { ok: true, revert: null, attributedRoots: attributed, modelViolation };
      } catch (e) {
        return { ok: false, revert: errName(e), attributedRoots: attributed, modelViolation: null };
      }
    }

    case "FACTORY_DEPLOY_TWIN": {
      // Identity binding: attempt to instantiate a vault at the SAME predicted
      // address with a DIFFERENT genesis authority. Under
      // I-COUNTERFACTUAL-IDENTITY-BINDING the salt differs, so this must land
      // somewhere else rather than occupying the victim's identity.
      const factory = await ethers.getContractAt(
        "VaultKernelFactoryPrototype",
        w.factoryAddress,
        signerOf(actor, ctx),
      );
      const hostileGenesis = {
        signer: addrOf(keyOf(actor.name + "-hostile")),
        pqKeyHash: pqHash(keyOf(actor.name + "-hostile-pq")),
        verifier: w.verifiers.alwaysTrue,
        threshold: 2,
        guardians: [0, 1, 2]
          .map((i) => addrOf(keyOf(actor.name + "-hostile-g" + i)))
          .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)),
        guardianIsContract: [false, false, false],
        floor: {
          requirePq: true,
          pqParamLevel: 3,
          pqPublicKeyLength: 32,
          pqSignatureLength: 65,
        },
      };
      const salt = ethers.id(w.opts.label + "-vault");
      try {
        const predicted: string = await factory.predictVault(salt, hostileGenesis);
        if (predicted.toLowerCase() === w.vaultAddress.toLowerCase()) {
          return {
            ok: true,
            revert: null,
            attributedRoots: new Set<Root>(),
            modelViolation:
              "I-COUNTERFACTUAL-IDENTITY-BINDING — a DIFFERENT genesis authority predicts the victim vault's address",
          };
        }
        // The genesis witness for `I-COMMITMENT-EXHIBITED-AT-ADMISSION`. The
        // attacker supplies a CORRECT one on purpose: a PQ public key is public,
        // so the exhibit is not an obstacle to them and must not be mistaken for
        // one. This action tests IDENTITY BINDING, and weakening it to an
        // admission failure would silently delete that coverage.
        await (
          await factory.deployVault(salt, hostileGenesis, pqKeyBytes(keyOf(actor.name + "-hostile-pq")))
        ).wait();
        return { ok: true, revert: null, attributedRoots: new Set<Root>(), modelViolation: null };
      } catch (e) {
        return { ok: false, revert: errName(e), attributedRoots: new Set<Root>(), modelViolation: null };
      }
    }

    default:
      return { ok: false, revert: "UNKNOWN_ACTION", attributedRoots: new Set<Root>(), modelViolation: null };
  }
}
