/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE GENERATION-2 ACTION MODEL. Every action has a real counterpart: a kernel entrypoint, or a lever
 * the world really has (a direct token transfer, an issuer's blocklist or upgrade). Valid and hostile
 * forms are both generated and nothing is pre-filtered, because how a call fails is itself a property.
 *
 * WHAT IS REUSED FROM stateful/ RATHER THAN RE-WRITTEN: the root and actor model (`rootsNow`, `owns`),
 * the adversarial quorum shapes (`buildQuorum`), the recovery-evidence model and the digest mirror.
 * Generation 1's `executeAction` is the one piece that cannot be reused: it hard-codes generation 1 in
 * every digest and native value in the spend. This file is that function with those two facts changed
 * and the ERC-20 world added; stateful/ itself is not edited, because any change there moves the
 * Generation-1 evidence subject.
 *
 * CHAIN READS ARE FOR CONSTRUCTION, as in stateful/actions.ts. The one extension is `syncModelFromChain` below,
 * whose comment says what it writes and when.
 */
import { ethers } from "../../test/connection.js";
import { networkHelpers } from "../../test/connection.js";
import type { Prng } from "../../stateful/prng.js";
import {
  judgeRecoveryExecution,
  recordCancellation,
  recordExecution,
  recordInitiation,
  type AbstractState,
} from "../../stateful/model.js";
import { buildQuorum, owns, rootsNow, type Ctx, type QuorumShape } from "../../stateful/actions.js";
import type { Actor, Root } from "../../stateful/world.js";
import { GENERATION_2 } from "../compile.js";
import {
  ACTION,
  BIND_DELAY_SECONDS,
  DAY,
  DESTINATION_GENERATION,
  DOMAIN,
  FAR_DEADLINE,
  MODE,
  UNIT,
  ZERO,
  addrOf,
  attest,
  digestOf,
  bindingParams,
  keyOf,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setPolicyParams,
  setVerifierParams,
  sign,
  spendParams,
  zoo,
  type Floor,
  type Gen2World,
  type ModeName,
  type VerifierKindG2,
} from "../world.js";

export { DAY, BIND_DELAY_SECONDS };

export const ACTION_KINDS_G2 = [
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
  "CANCEL_RECOVERY_BY_QUORUM",
  // ---- the ERC-20 world ----
  "DIRECT_TRANSFER",
  "UNSOLICITED_TRANSFER",
  "EGRESS_OTHER",
  "TOKEN_MODE",
  "TOKEN_BLOCKLIST",
  "TOKEN_REBASE",
  "ARM_HOOK",
  "RELAY_TAMPER",
  "CROSS_ASSET_REPLAY",
  "DESTINATION_MODE",
] as const;
export type ActionKindG2 = (typeof ACTION_KINDS_G2)[number];

/** Actions that change an asset's ledger with no kernel involved: never chargeable to an authority cut. */
export const ASSET_EXTERNAL_ACTIONS: ReadonlySet<string> = new Set(["TOKEN_REBASE"]);

export const PERMISSIONLESS_FINALISERS_G2: ReadonlySet<string> = new Set([
  "EGRESS_NATIVE",
  "EGRESS_TOKEN",
  "EGRESS_OTHER",
  "RETIRE",
]);

export interface GeneratedActionG2 {
  kind: ActionKindG2;
  actorName: string;
  params: Record<string, string | number | boolean>;
}

export interface Recorded {
  step: number;
  kind: string;
  actor: string;
  authorRoots: Root[];
  to: string;
  data: string;
  value: bigint;
  ok: boolean;
}

/** Gen2SwitchableDestination.Mode, by ordinal. */
export const DESTINATION_MODES = ["ACCEPT", "BOUNCE_ALL", "BOUNCE_HALF", "REFUSE"] as const;
export type DestinationMode = (typeof DESTINATION_MODES)[number];

export type HookKind =
  "readNonce" | "replaySpend" | "secondValidSpend" | "egress" | "contain" | "bindMigration" | "retire";

/** The harness's own bookkeeping: what it installed and signed, never read back to judge. */
export interface G2Ctx {
  world: Gen2World;
  abstract: AbstractState;
  credKey: ethers.SigningKey;
  credLabel: string;
  pqKey: ethers.SigningKey;
  pqLabel: string;
  guardianKeys: ethers.SigningKey[];
  guardianLabels: string[];
  guardianIsContract: boolean[];
  threshold: bigint;
  verifierKind: string;
  requirePqNow: boolean;
  policyKind: string;
  fabricateCommitments: boolean;
  history: Recorded[];
  step: number;
  /** The token's behaviour as the harness last set it. */
  tokenMode: ModeName;
  /** What the armed hook will do, as the harness armed it; null once fired or never armed. */
  armedHook: HookKind | null;
  /** The roots behind the signatures inside the armed hook. An effect of the hook is charged here too. */
  armedHookRoots: Set<Root>;
  armedHookAfterDebit: boolean;
  /** Which of the egress's two legs the harness has blocklisted and not lifted: what a freeze seam reads. */
  frozen: Set<string>;
  /** How the bound destination treats native value, as the harness last set it. */
  destinationMode: DestinationMode;
  /** The last spend calldata that succeeded, for the same-payload replay hook and cross-asset replay. */
  lastSpendData: string | null;
  /** Instant the harness saw the binding mined. The migration-time oracle reads this, not the kernel. */
  boundAtTimestamp: bigint | null;
}

export interface ExecOutcomeG2 {
  ok: boolean;
  revert: string | null;
  usedStalePossession?: boolean;
  attributedRoots: Set<Root>;
  modelViolation: string | null;
  minedAt?: bigint;
  /** The signed amount of a spend this action attempted, for the settlement oracle. */
  spend?: { to: string; amount: bigint };
  /** What a REPLAY_PAST_CALL replayed, and whether that call had succeeded the first time. */
  replayed?: { kind: string; priorOk: boolean };
  /** The total of the Egressed events this transaction published, read from its receipt. */
  published?: bigint;
}

function publishedEgress(w: Gen2World, receipt: ethers.TransactionReceipt | null): bigint | undefined {
  let total: bigint | undefined;
  for (const log of receipt?.logs ?? []) {
    if (log.address.toLowerCase() !== w.vaultAddress.toLowerCase()) continue;
    const parsed = w.vault.interface.parseLog(log);
    if (parsed?.name === "Egressed") total = (total ?? 0n) + (parsed.args[2] as bigint);
  }
  return total;
}

async function minedTimestamp(blockNumber: number | undefined): Promise<bigint> {
  if (blockNumber === undefined) return 0n;
  const block = await ethers.provider.getBlock(blockNumber);
  return BigInt(block?.timestamp ?? 0);
}

/** OpenZeppelin's Clones reverts with this when an identity is already occupied; it is not in the kernel's ABI. */
const FAILED_DEPLOYMENT = ethers.id("FailedDeployment()").slice(0, 10);

/** The error name, through the kernel's ABI: the candidate is not in Hardhat's artifacts. */
export function errNameG2(iface: ethers.Interface, e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  // A call into a codeless plane reverts with no data at all: the plane's denial, cut 1.
  if (msg.includes("reverted without a reason string")) return "EMPTY_REVERT";
  if (msg.includes(FAILED_DEPLOYMENT)) return "FailedDeployment";
  const named = /custom error '([A-Za-z0-9_]+)/.exec(msg) ?? /reverted with reason string '([^']*)'/.exec(msg);
  if (named) return named[1]!;
  const data = /return data: (0x[0-9a-fA-F]*)/.exec(msg);
  if (data) {
    if (data[1] === "0x") return "EMPTY_REVERT";
    try {
      const parsed = iface.parseError(data[1]!);
      if (parsed) return parsed.name;
    } catch {
      return "UNDECODED_ERROR:" + data[1]!.slice(0, 10);
    }
    return "UNDECODED_ERROR:" + data[1]!.slice(0, 10);
  }
  return msg.slice(0, 120).replace(/\s+/g, " ");
}

const credSigningKey = (actor: Actor, ctx: G2Ctx): ethers.SigningKey =>
  owns(actor, ctx.credLabel) ? ctx.credKey : keyOf(actor.name + "-decoy-ecdsa");

/**
 * The PQ leg an actor can actually produce. Under the ungated fixture it is a second ECDSA key standing
 * in for a PQ scheme; under the real root it is the admitted class's relation, an attestor statement,
 * and only the actor holding the PQ root can obtain one for the installed key. The key bytes are public.
 */
function pqLeg(actor: Actor, ctx: G2Ctx, digest: string): { sig: string; key: string } {
  const w = ctx.world;
  const holds = owns(actor, ctx.pqLabel);
  if (w.opts.authority === "root") {
    const verifier = w.verifiers[ctx.verifierKind as VerifierKindG2];
    const attestor = w.attestors[verifier.toLowerCase()];
    const key = pqKeyBytes(ctx.pqKey);
    const signer = holds && attestor ? attestor : keyOf(actor.name + "-decoy-attestor");
    return { sig: attest(signer, verifier, w.chainId, digest, key), key };
  }
  const k = holds ? ctx.pqKey : keyOf(actor.name + "-decoy-pq");
  return { sig: sign(k, digest), key: pqKeyBytes(k) };
}

/** Incoming possession against `verifier`: the proof a credential install requires. */
function incomingPq(ctx: G2Ctx, verifier: string, pop: string, keyHolder: ethers.SigningKey): string {
  const attestor = ctx.world.attestors[verifier.toLowerCase()];
  return attestor ? attest(attestor, verifier, ctx.world.chainId, pop, pqKeyBytes(keyHolder)) : sign(keyHolder, pop);
}

async function currentFloor(ctx: G2Ctx): Promise<Floor> {
  const f = await ctx.world.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

const signerOf = (actor: Actor, ctx: G2Ctx): ethers.Signer =>
  actor.sendsAs === "deployer" ? ctx.world.deployer : ctx.world.outsider;

/** What the mutants that take a caller-chosen token or recipient look for, and the real kernel ignores. */
export const APPEND_MARKER = "deadbeef";
const appended = (addr: string): string => addr.slice(2).toLowerCase() + APPEND_MARKER;

const asCtx = (c: G2Ctx): Ctx => c as unknown as Ctx;

/** Every guardian key this world can ever seat, by address, with the label its ownership is modelled under. */
function knownGuardians(ctx: G2Ctx): Map<string, { key: ethers.SigningKey; label: string }> {
  const label = ctx.world.opts.label;
  const known = new Map<string, { key: ethers.SigningKey; label: string }>();
  const add = (l: string): void => {
    const key = keyOf(l);
    known.set(addrOf(key).toLowerCase(), { key, label: l });
  };
  for (const i of [0, 1, 2]) {
    add(label + "-guardian-" + i);
    for (const gen of [1, 2, 3]) add(label + "-guardian-g" + gen + "-" + i);
  }
  return known;
}

function adoptRoster(ctx: G2Ctx, members: string[], threshold: bigint): void {
  const known = knownGuardians(ctx);
  const seats = members.map((m) => known.get(m.toLowerCase()));
  if (seats.some((seat) => seat === undefined)) return;
  ctx.guardianKeys = seats.map((seat) => seat!.key);
  ctx.guardianLabels = seats.map((seat) => seat!.label);
  ctx.guardianIsContract = members.map(() => false);
  ctx.threshold = threshold;
}

/**
 * A REPLAY OR A HOOK CAN MOVE A PRINCIPAL WITHOUT THE ACTION THAT MODELS IT RUNNING. Generation 1's harness
 * keeps signing with the old key from then on, so its "honest" actor is silently refused for the rest of the
 * campaign. This re-reads who holds what: what to sign next, and which actor owns which label FROM THEN ON, which
 * `rootsNow` reads. The step that caused the move has already been judged by the time this runs, against the roots
 * the actor held before it, and an address this world has no key for leaves the model as it is. So a stranger's
 * install is caught at its own step, and later steps are judged on who really holds the credential by then.
 */
export function syncModelFromChain(
  ctx: G2Ctx,
  onChain: {
    ecdsaSigner: string;
    pqPublicKeyHash: string;
    pqVerifier: string;
    policyEngine: string;
    requirePq: boolean;
  },
): void {
  const w = ctx.world;
  const label = w.opts.label;
  const creds: [ethers.SigningKey, string][] = [
    [w.credKey, label + "-cred"],
    ...w.spareCred.map((k, i): [ethers.SigningKey, string] => [k, label + "-spare-cred-" + i]),
  ];
  const cred = creds.find(([k]) => addrOf(k).toLowerCase() === onChain.ecdsaSigner.toLowerCase());
  if (cred) {
    ctx.credKey = cred[0];
    ctx.credLabel = cred[1];
  }
  const pqs: [ethers.SigningKey, string][] = [
    [w.pqKey, label + "-pq"],
    ...w.sparePq.map((k, i): [ethers.SigningKey, string] => [k, label + "-spare-pq-" + i]),
  ];
  const pq = pqs.find(([k]) => pqHash(k).toLowerCase() === onChain.pqPublicKeyHash.toLowerCase());
  if (pq) {
    ctx.pqKey = pq[0];
    ctx.pqLabel = pq[1];
  }
  const verifier = (Object.keys(w.verifiers) as VerifierKindG2[]).find(
    (k) => w.verifiers[k].toLowerCase() === onChain.pqVerifier.toLowerCase(),
  );
  if (verifier) ctx.verifierKind = verifier;
  const policies = w.policies as Record<string, string>;
  const policy =
    onChain.policyEngine === ZERO
      ? "none"
      : Object.keys(policies).find((k) => policies[k]!.toLowerCase() === onChain.policyEngine.toLowerCase());
  if (policy) ctx.policyKind = policy;
  ctx.requirePqNow = onChain.requirePq;
}

export async function executeActionG2(
  action: GeneratedActionG2,
  actor: Actor,
  ctx: G2Ctx,
  prng: Prng,
): Promise<ExecOutcomeG2> {
  const w = ctx.world;
  const vault = w.vault.connect(signerOf(actor, ctx)) as ethers.Contract;
  const held = rootsNow(actor, asCtx(ctx));
  const kernelGen = GENERATION_2;
  const p = action.params;
  const none = (): Set<Root> => new Set<Root>();

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
    via?: ethers.Signer,
  ): Promise<ExecOutcomeG2> => {
    let built: { data: string; value?: bigint };
    try {
      built = await build();
    } catch (e) {
      return {
        ok: false,
        revert: "HARNESS_ENCODE:" + errNameG2(w.vault.interface, e),
        attributedRoots: held,
        modelViolation: null,
      };
    }
    try {
      const tx = await (via ?? signerOf(actor, ctx)).sendTransaction({
        to: w.vaultAddress,
        data: built.data,
        value: built.value ?? 0n,
        gasLimit: 3_000_000n,
      });
      const receipt = await tx.wait();
      const minedAt = await minedTimestamp(receipt?.blockNumber);
      record(w.vaultAddress, built.data, built.value ?? 0n, true);
      if (onSuccess) onSuccess();
      return {
        ok: true,
        revert: null,
        attributedRoots: held,
        modelViolation: null,
        minedAt,
        published: publishedEgress(w, receipt),
      };
    } catch (e) {
      record(w.vaultAddress, built.data, built.value ?? 0n, false);
      return { ok: false, revert: errNameG2(w.vault.interface, e), attributedRoots: held, modelViolation: null };
    }
  };

  /** A lever pulled on the token, not the kernel: no authority is involved and none is charged. */
  const lever = async (run: () => Promise<{ wait: () => Promise<unknown> }>): Promise<ExecOutcomeG2> => {
    try {
      await (await run()).wait();
      return { ok: true, revert: null, attributedRoots: none(), modelViolation: null };
    } catch (e) {
      return {
        ok: false,
        revert: "LEVER:" + errNameG2(w.vault.interface, e),
        attributedRoots: none(),
        modelViolation: null,
      };
    }
  };

  const spendData = async (
    to: string,
    amount: bigint,
    signer: Actor,
    tamper?: { to?: string; amount?: bigint },
    forVault?: string,
  ): Promise<string> => {
    const floor = await currentFloor(ctx);
    const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await w.vault.credentialGeneration()) as bigint;
    const digest = digestOf({
      chainId: w.chainId,
      vault: forVault ?? w.signingDomainVault,
      kernelGeneration: kernelGen,
      actionType: ACTION.SPEND,
      authorityGeneration: credGen,
      params: spendParams(w.signedSpendRecipient ?? to, amount),
      domain: DOMAIN.SPEND,
      nonce,
      deadline: FAR_DEADLINE,
    });
    const pq = floor.requirePq ? pqLeg(signer, ctx, digest) : { sig: "0x", key: "0x" };
    return w.vault.interface.encodeFunctionData("execute", [
      tamper?.to ?? to,
      tamper?.amount ?? amount,
      nonce,
      FAR_DEADLINE,
      sign(credSigningKey(signer, ctx), digest),
      pq.sig,
      pq.key,
    ]);
  };

  switch (action.kind) {
    case "FUND": {
      const value = ethers.parseEther(String(p.eth ?? "1"));
      try {
        await (await signerOf(actor, ctx).sendTransaction({ to: w.vaultAddress, value })).wait();
        return { ok: true, revert: null, attributedRoots: none(), modelViolation: null };
      } catch (e) {
        return { ok: false, revert: errNameG2(w.vault.interface, e), attributedRoots: none(), modelViolation: null };
      }
    }

    case "ADVANCE_TIME": {
      await networkHelpers.time.increase(Number(p.seconds ?? DAY));
      return { ok: true, revert: null, attributedRoots: none(), modelViolation: null };
    }

    case "DIRECT_TRANSFER": {
      // An unsolicited credit of the ADMITTED asset: no kernel function runs, so no kernel gate can see it.
      const units = BigInt(Number(p.units ?? 1)) * UNIT;
      return lever(() => zoo(w).mint(w.vaultAddress, units));
    }

    case "UNSOLICITED_TRANSFER": {
      const units = BigInt(Number(p.units ?? 1)) * UNIT;
      const hostility = Number(p.hostility ?? 0);
      return lever(async () => {
        await (await w.other.setHostility(hostility)).wait();
        return w.other.mint(w.vaultAddress, units);
      });
    }

    case "TOKEN_MODE": {
      const mode = String(p.mode ?? "VANILLA") as ModeName;
      const res = await lever(() => zoo(w).setMode(MODE[mode]));
      if (res.ok) ctx.tokenMode = mode;
      return res;
    }

    case "TOKEN_BLOCKLIST": {
      const target = String(p.target ?? "recipient");
      const account = target === "vault" ? w.vaultAddress : target === "destination" ? w.destination : w.recipient;
      return lever(async () => {
        const tx = await zoo(w).setBlocklisted(account, Boolean(p.flag));
        if (target !== "recipient") {
          if (p.flag) ctx.frozen.add(target);
          else ctx.frozen.delete(target);
        }
        return tx;
      });
    }

    case "DESTINATION_MODE": {
      const mode = String(p.mode ?? "ACCEPT") as DestinationMode;
      const res = await lever(() => w.destinationFixture.setMode(DESTINATION_MODES.indexOf(mode)));
      if (res.ok) ctx.destinationMode = mode;
      return res;
    }

    case "TOKEN_REBASE": {
      // A balance move with no transfer at all: downwards too, which only a token can do to a vault.
      const factorBps = BigInt(Number(p.bps ?? 10_000));
      return lever(async () => {
        const have = (await zoo(w).realBalanceOf(w.vaultAddress)) as bigint;
        return zoo(w).rebaseAccount(w.vaultAddress, (have * factorBps) / 10_000n);
      });
    }

    case "ARM_HOOK": {
      const kind = String(p.hook ?? "readNonce") as HookKind;
      const after = Boolean(p.afterDebit);
      let payload = "0x";
      try {
        switch (kind) {
          case "readNonce":
            payload = w.vault.interface.encodeFunctionData("nonces", [DOMAIN.SPEND]);
            break;
          case "replaySpend":
            // A spend at the live nonce. The SPEND action swaps in its own calldata once it knows it, so the
            // hook replays the very call it sits inside, same signature and same nonce.
            payload = await spendData(w.recipient, 3n * UNIT, actor);
            break;
          case "secondValidSpend": {
            // nonce + 1, signed with whatever the armer actually holds: valid only for a credential holder.
            const floor = await currentFloor(ctx);
            const nonce = ((await w.vault.nonces(DOMAIN.SPEND)) as bigint) + 1n;
            const credGen = (await w.vault.credentialGeneration()) as bigint;
            const digest = digestOf({
              chainId: w.chainId,
              vault: w.signingDomainVault,
              kernelGeneration: kernelGen,
              actionType: ACTION.SPEND,
              authorityGeneration: credGen,
              params: spendParams(w.signedSpendRecipient ?? w.recipient, UNIT),
              domain: DOMAIN.SPEND,
              nonce,
              deadline: FAR_DEADLINE,
            });
            const pq = floor.requirePq ? pqLeg(actor, ctx, digest) : { sig: "0x", key: "0x" };
            payload = w.vault.interface.encodeFunctionData("execute", [
              w.recipient,
              UNIT,
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
              pq.sig,
              pq.key,
            ]);
            break;
          }
          case "egress":
            payload = w.vault.interface.encodeFunctionData("egress", [w.token]);
            break;
          case "contain": {
            const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
            const gGen = (await w.vault.guardianGeneration()) as bigint;
            const digest = digestOf({
              chainId: w.chainId,
              vault: w.signingDomainVault,
              kernelGeneration: kernelGen,
              actionType: ACTION.RECOVER,
              authorityGeneration: gGen,
              params: ethers.id("CONTAIN"),
              domain: DOMAIN.GUARDIAN,
              nonce,
              deadline: FAR_DEADLINE,
            });
            payload = w.vault.interface.encodeFunctionData("enterContainment", [
              buildQuorum(actor, asCtx(ctx), digest, "honest", prng),
              nonce,
              FAR_DEADLINE,
            ]);
            break;
          }
          case "bindMigration": {
            const nonce = (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint;
            const gGen = (await w.vault.guardianGeneration()) as bigint;
            const params = await bindingParams(w, w.destination, w.destinationCodeHash, DESTINATION_GENERATION);
            const digest = digestOf({
              chainId: w.chainId,
              vault: w.signingDomainVault,
              kernelGeneration: kernelGen,
              actionType: ACTION.BIND_MIGRATION,
              authorityGeneration: gGen,
              params,
              domain: DOMAIN.MIGRATION,
              nonce,
              deadline: FAR_DEADLINE,
            });
            payload = w.vault.interface.encodeFunctionData("bindMigration", [
              [w.destination, w.destinationCodeHash, DESTINATION_GENERATION],
              buildQuorum(actor, asCtx(ctx), digest, "honest", prng),
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
            ]);
            break;
          }
          case "retire":
            payload = w.vault.interface.encodeFunctionData("retire", []);
            break;
          default:
            break;
        }
      } catch (e) {
        return {
          ok: false,
          revert: "HARNESS_ENCODE:" + errNameG2(w.vault.interface, e),
          attributedRoots: none(),
          modelViolation: null,
        };
      }
      const res = await lever(() => zoo(w).armHook(w.vaultAddress, payload, after));
      if (res.ok) {
        ctx.armedHook = kind;
        ctx.armedHookRoots = held;
        ctx.armedHookAfterDebit = after;
      }
      return res;
    }

    case "SPEND": {
      const to = p.toSelf ? w.vaultAddress : w.recipient;
      // A spend of exactly the vault's balance is what the lenient balance read let settle with nothing moved.
      const amount =
        p.rawAmount !== undefined
          ? BigInt(String(p.rawAmount))
          : p.drain
            ? ((await zoo(w).realBalanceOf(w.vaultAddress)) as bigint)
            : BigInt(Number(p.units ?? 1)) * UNIT;
      const res = await attempt(
        async () => {
          const data = await spendData(to, amount, actor);
          // The relayer's other trick: trailing bytes the ABI decoder ignores. Real kernel: nothing happens.
          const sent = p.appendToken ? data + appended(w.otherToken) : data;
          if (ctx.armedHook === "replaySpend")
            await (await zoo(w).armHook(w.vaultAddress, sent, ctx.armedHookAfterDebit)).wait();
          return { data: sent };
        },
        undefined,
        p.relay ? w.outsider : undefined,
      );
      if (res.ok) ctx.lastSpendData = ctx.history[ctx.history.length - 1]!.data;
      return { ...res, spend: { to, amount } };
    }

    case "RELAY_TAMPER": {
      // A stranger holding nothing captures an HONEST signature and rewrites one signed field.
      const to = w.recipient;
      const amount = 2n * UNIT;
      const honest: Actor = { ...actor, ownedLabels: new Set([ctx.credLabel, ctx.pqLabel]) };
      const field = String(p.field ?? "recipient");
      const hostile = addrOf(keyOf(w.opts.label + "-hostile-recipient"));
      return attempt(async () => ({
        data: await spendData(to, amount, honest, field === "recipient" ? { to: hostile } : { amount: amount * 10n }),
      }));
    }

    case "CROSS_ASSET_REPLAY": {
      const sibling = w.sibling;
      if (sibling === null) return { ok: false, revert: "NO_SIBLING", attributedRoots: none(), modelViolation: null };
      const variant = String(p.variant ?? "mainSigAtSibling");
      if (variant === "mainSigAtSibling") {
        // Calldata that WORKED on this vault, verbatim, at the vault of the other asset.
        const data =
          ctx.lastSpendData ??
          (await spendData(w.recipient, UNIT, { ...actor, ownedLabels: new Set([ctx.credLabel, ctx.pqLabel]) }));
        try {
          await (
            await signerOf(actor, ctx).sendTransaction({ to: sibling.vaultAddress, data, gasLimit: 3_000_000n })
          ).wait();
          return { ok: true, revert: null, attributedRoots: none(), modelViolation: null };
        } catch (e) {
          return { ok: false, revert: errNameG2(w.vault.interface, e), attributedRoots: none(), modelViolation: null };
        }
      }
      // A signature the credential made for the OTHER asset's vault, submitted here.
      return attempt(async () => ({
        data: await spendData(
          w.recipient,
          UNIT,
          { ...actor, ownedLabels: new Set([ctx.credLabel, ctx.pqLabel]) },
          undefined,
          sibling.vaultAddress,
        ),
      }));
    }

    case "ROTATE_CREDENTIAL": {
      const targetIdx = Number(p.target ?? 0) % w.spareCred.length;
      const newCred = w.spareCred[targetIdx]!;
      const newPq = w.sparePq[targetIdx]!;
      const fabricate = ctx.fabricateCommitments && targetIdx === 0;
      const installedHash = fabricate
        ? ethers.keccak256(ethers.toUtf8Bytes(w.opts.label + "-fabricated-" + ctx.step))
        : pqHash(newPq);
      const newCredLabel = w.opts.label + "-spare-cred-" + targetIdx;
      const newPqLabel = w.opts.label + "-spare-pq-" + targetIdx;
      const outgoingCredAddr = addrOf(ctx.credKey);
      return attempt(
        async () => {
          const floor = await currentFloor(ctx);
          const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
          const credGen = (await vault.credentialGeneration()) as bigint;
          const popStale = Boolean(p.popStale);
          const pop = (await vault.credentialPossessionDigest(addrOf(newCred), installedHash)) as string;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.signingDomainVault,
            kernelGeneration: kernelGen,
            actionType: ACTION.ROTATE,
            authorityGeneration: credGen,
            params: ethers.keccak256(
              ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(newCred), installedHash]),
            ),
            domain: DOMAIN.CREDENTIAL,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const verifier = w.verifiers[ctx.verifierKind as VerifierKindG2];
          const change = {
            newSigner: addrOf(newCred),
            newPqKeyHash: installedHash,
            newPqKey: fabricate ? pqKeyBytes(ctx.pqKey) : pqKeyBytes(newPq),
            newEcdsaPop: sign(popStale ? ctx.credKey : newCred, pop),
            newPqPop: fabricate ? "0x" : incomingPq(ctx, verifier, pop, popStale ? ctx.pqKey : newPq),
          };
          const pq = floor.requirePq ? pqLeg(actor, ctx, digest) : { sig: "0x", key: "0x" };
          return {
            data: vault.interface.encodeFunctionData("rotateCredential", [
              change,
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
              pq.sig,
              pq.key,
            ]),
          };
        },
        () => {
          ctx.credKey = newCred;
          ctx.credLabel = newCredLabel;
          if (!fabricate) {
            ctx.pqKey = newPq;
            ctx.pqLabel = newPqLabel;
          }
          ctx.abstract.credentialReplacements += 1;
        },
      ).then((r) => ({ ...r, usedStalePossession: Boolean(p.popStale) && outgoingCredAddr !== addrOf(newCred) }));
    }

    case "SET_VERIFIER": {
      const kind = String(p.verifier ?? "honest") as VerifierKindG2;
      let requirePqAfter = false;
      return attempt(
        async () => {
          const floor = await currentFloor(ctx);
          const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
          const credGen = (await vault.credentialGeneration()) as bigint;
          requirePqAfter = floor.requirePq || Boolean(p.raisePq);
          const next: Floor = {
            requirePq: requirePqAfter,
            pqParamLevel: floor.pqParamLevel + (p.bumpLevel ? 1 : 0),
            pqPublicKeyLength: requirePqAfter && floor.pqPublicKeyLength === 0 ? 32 : floor.pqPublicKeyLength,
            pqSignatureLength: requirePqAfter && floor.pqSignatureLength === 0 ? 65 : floor.pqSignatureLength,
          };
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.signingDomainVault,
            kernelGeneration: kernelGen,
            actionType: ACTION.SET_VERIFIER,
            authorityGeneration: credGen,
            params: setVerifierParams(w.verifiers[kind], next),
            domain: DOMAIN.CREDENTIAL,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const pq = floor.requirePq
            ? pqLeg(actor, ctx, digest)
            : { sig: "0x", key: requirePqAfter ? pqKeyBytes(w.pqKey) : "0x" };
          return {
            data: vault.interface.encodeFunctionData("setVerifier", [
              w.verifiers[kind],
              [next.requirePq, next.pqParamLevel, next.pqPublicKeyLength, next.pqSignatureLength],
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
              pq.sig,
              pq.key,
            ]),
          };
        },
        () => {
          ctx.verifierKind = kind;
          ctx.requirePqNow = requirePqAfter;
        },
      );
    }

    case "SET_POLICY": {
      const which = String(p.policy ?? "allow");
      const target = which === "none" ? ZERO : ((w.policies as Record<string, string>)[which] ?? w.policies.allow);
      return attempt(
        async () => {
          const floor = await currentFloor(ctx);
          const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
          const credGen = (await vault.credentialGeneration()) as bigint;
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.signingDomainVault,
            kernelGeneration: kernelGen,
            actionType: ACTION.SET_POLICY,
            authorityGeneration: credGen,
            params: setPolicyParams(target),
            domain: DOMAIN.CREDENTIAL,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const pq = floor.requirePq ? pqLeg(actor, ctx, digest) : { sig: "0x", key: "0x" };
          return {
            data: vault.interface.encodeFunctionData("setPolicy", [
              target,
              nonce,
              FAR_DEADLINE,
              sign(credSigningKey(actor, ctx), digest),
              pq.sig,
              pq.key,
            ]),
          };
        },
        () => {
          ctx.policyKind = which;
        },
      );
    }

    case "SET_GUARDIANS": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      const newThreshold = BigInt(Number(p.newThreshold ?? 2));
      const gen = Number(p.rosterGen ?? 1);
      let newKeys = [0, 1, 2]
        .map((i) => keyOf(w.opts.label + "-guardian-g" + gen + "-" + i))
        .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
      if (p.duplicateRoster) newKeys = [ctx.guardianKeys[0]!, ctx.guardianKeys[0]!, ctx.guardianKeys[1]!];
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
          const params = ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["uint64", "address[]", "bool[]"],
              [newThreshold, newMembers, newIsContract],
            ),
          );
          const digest = digestOf({
            chainId: w.chainId,
            vault: w.signingDomainVault,
            kernelGeneration: kernelGen,
            actionType: ACTION.SET_GUARDIANS,
            authorityGeneration: gGen,
            params,
            domain: DOMAIN.GUARDIAN,
            nonce,
            deadline: FAR_DEADLINE,
          });
          const q = buildQuorum(actor, asCtx(ctx), digest, shape, prng);
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
      const proposedVerifier = w.verifiers[String(p.verifier ?? "honest") as VerifierKindG2];
      let boundGen = 0n;
      const initiated = await attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
        boundGen = (await vault.guardianGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.signingDomainVault,
          kernelGeneration: kernelGen,
          actionType: ACTION.RECOVER,
          authorityGeneration: boundGen,
          params: recoverParams(addrOf(newCred), pqHash(newPq), proposedVerifier),
          domain: DOMAIN.GUARDIAN,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, asCtx(ctx), digest, shape, prng);
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
      });
      if (!initiated.ok) return initiated;
      const { violation } = recordInitiation(
        ctx.abstract,
        ctx.step,
        addrOf(newCred),
        pqHash(newPq),
        proposedVerifier,
        Number(boundGen),
        held,
        initiated.minedAt ?? 0n,
      );
      return { ...initiated, modelViolation: violation };
    }

    case "CANCEL_RECOVERY": {
      const cancelled = await attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
        const credGen = (await vault.credentialGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.signingDomainVault,
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
      });
      if (!cancelled.ok) return cancelled;
      return {
        ...cancelled,
        modelViolation: recordCancellation(ctx.abstract, "CREDENTIAL_CHALLENGE", cancelled.minedAt ?? 0n),
      };
    }

    case "CANCEL_RECOVERY_BY_QUORUM": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      const quorumCancelled = await attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
        const gGen = (await vault.guardianGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.signingDomainVault,
          kernelGeneration: kernelGen,
          actionType: ACTION.RECOVER,
          authorityGeneration: gGen,
          params: ethers.id("QUORUM_CANCEL_RECOVERY"),
          domain: DOMAIN.GUARDIAN,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, asCtx(ctx), digest, shape, prng);
        return { data: vault.interface.encodeFunctionData("cancelRecoveryByQuorum", [q, nonce, FAR_DEADLINE]) };
      });
      if (!quorumCancelled.ok) return quorumCancelled;
      return {
        ...quorumCancelled,
        modelViolation: recordCancellation(ctx.abstract, "GUARDIAN_QUORUM", quorumCancelled.minedAt ?? 0n),
      };
    }

    case "EXECUTE_RECOVERY": {
      const live = ctx.abstract.liveEpisode === null ? null : ctx.abstract.episodes.get(ctx.abstract.liveEpisode);
      const attributed = new Set<Root>(live ? live.authorizedBy : []);
      const popStale = Boolean(p.popStale);
      let installedIdx = -1;
      let installedVerifier = "";
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
          const newPqKeyHolder = w.sparePq[installedIdx] ?? ctx.pqKey;
          const newPqPop = w.attestors[installedVerifier.toLowerCase()]
            ? attest(
                popStale ? keyOf(actor.name + "-decoy-attestor") : w.attestors[installedVerifier.toLowerCase()]!,
                installedVerifier,
                w.chainId,
                pop,
                pqKeyBytes(newPqKeyHolder),
              )
            : sign(popKeyPq, pop);
          const change = {
            newSigner: proposedSigner,
            newPqKeyHash: proposedPqHash,
            newPqKey: pqKeyBytes(newPqKeyHolder),
            newEcdsaPop: sign(popKeyEc, pop),
            newPqPop,
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
          const lower = installedVerifier.toLowerCase();
          ctx.verifierKind =
            (Object.keys(w.verifiers) as VerifierKindG2[]).find((k) => w.verifiers[k].toLowerCase() === lower) ??
            "honest";
        },
      );
      let modelViolation: string | null = null;
      if (res.ok) {
        modelViolation = judgeRecoveryExecution(ctx.abstract, res.minedAt ?? 0n);
        recordExecution(ctx.abstract, ctx.credLabel);
      }
      return {
        ...res,
        attributedRoots: attributed,
        modelViolation,
        usedStalePossession: popStale && installedIdx >= 0 && outgoingCredAddr !== addrOf(w.spareCred[installedIdx]!),
      };
    }

    case "ENTER_CONTAINMENT": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      return attempt(async () => {
        const nonce = (await vault.nonces(DOMAIN.GUARDIAN)) as bigint;
        const gGen = (await vault.guardianGeneration()) as bigint;
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.signingDomainVault,
          kernelGeneration: kernelGen,
          actionType: ACTION.RECOVER,
          authorityGeneration: gGen,
          params: ethers.id("CONTAIN"),
          domain: DOMAIN.GUARDIAN,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, asCtx(ctx), digest, shape, prng);
        return { data: vault.interface.encodeFunctionData("enterContainment", [q, nonce, FAR_DEADLINE]) };
      });
    }

    case "BIND_MIGRATION": {
      const shape = String(p.quorumShape ?? "honest") as QuorumShape;
      // The mistakes a binding can be signed with: a hash the destination's code does not have, or the vault itself.
      const bad = String(p.badBinding ?? "none");
      const res = await attempt(async () => {
        const destination = bad === "self" ? w.vaultAddress : w.destination;
        const codeHash =
          bad === "wrongHash"
            ? ethers.id(w.opts.label + "-not-the-code")
            : ethers.keccak256(await ethers.provider.getCode(destination));
        const nonce = (await vault.nonces(DOMAIN.MIGRATION)) as bigint;
        const gGen = (await vault.guardianGeneration()) as bigint;
        const params = await bindingParams(w, destination, codeHash, DESTINATION_GENERATION);
        const digest = digestOf({
          chainId: w.chainId,
          vault: w.signingDomainVault,
          kernelGeneration: kernelGen,
          actionType: ACTION.BIND_MIGRATION,
          authorityGeneration: gGen,
          params,
          domain: DOMAIN.MIGRATION,
          nonce,
          deadline: FAR_DEADLINE,
        });
        const q = buildQuorum(actor, asCtx(ctx), digest, shape, prng);
        return {
          data: vault.interface.encodeFunctionData("bindMigration", [
            [destination, codeHash, DESTINATION_GENERATION],
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
        ctx.boundAtTimestamp = res.minedAt ?? null;
      }
      return res;
    }

    case "RETIRE": {
      const res = await attempt(async () => ({ data: vault.interface.encodeFunctionData("retire", []) }));
      if (res.ok) ctx.abstract.retired = true;
      return { ...res, attributedRoots: new Set(ctx.abstract.migrationAuthorizedBy) };
    }

    case "EGRESS_NATIVE":
    case "EGRESS_TOKEN":
    case "EGRESS_OTHER": {
      const asset = action.kind === "EGRESS_NATIVE" ? ZERO : action.kind === "EGRESS_OTHER" ? w.otherToken : w.token;
      const hostileRecipient = addrOf(keyOf(w.opts.label + "-hostile-recipient"));
      const res = await attempt(async () => {
        const data = vault.interface.encodeFunctionData("egress", [asset]);
        return { data: p.appendRecipient ? data + appended(hostileRecipient) : data };
      });
      return { ...res, attributedRoots: new Set(ctx.abstract.migrationAuthorizedBy) };
    }

    case "REPLAY_PAST_CALL": {
      const prior = ctx.history.filter((h) => h.kind !== "REPLAY_PAST_CALL" && h.kind !== "FUND");
      if (prior.length === 0) return { ok: false, revert: "NO_HISTORY", attributedRoots: none(), modelViolation: null };
      const target = prior[Number(p.index ?? 0) % prior.length]!;
      const replayed = { kind: target.kind, priorOk: target.ok };
      const live =
        ctx.abstract.liveEpisode === null ? null : (ctx.abstract.episodes.get(ctx.abstract.liveEpisode) ?? null);
      const attributed = PERMISSIONLESS_FINALISERS_G2.has(target.kind)
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
          gasLimit: 3_000_000n,
        });
        const receipt = await tx.wait();
        const minedAt = await minedTimestamp(receipt?.blockNumber);
        let modelViolation: string | null = null;
        if (target.kind === "EXECUTE_RECOVERY") {
          modelViolation = judgeRecoveryExecution(ctx.abstract, minedAt);
          recordExecution(ctx.abstract, ctx.credLabel);
        } else if (target.kind === "INITIATE_RECOVERY") {
          const decoded = vault.interface.decodeFunctionData("initiateRecovery", target.data);
          const gGen = (await vault.guardianGeneration()) as bigint;
          modelViolation = recordInitiation(
            ctx.abstract,
            ctx.step,
            String(decoded[0]),
            String(decoded[1]),
            String(decoded[2]),
            Number(gGen),
            new Set(target.authorRoots),
            minedAt,
          ).violation;
        } else if (target.kind === "CANCEL_RECOVERY") {
          modelViolation = recordCancellation(ctx.abstract, "CREDENTIAL_CHALLENGE", minedAt);
        } else if (target.kind === "CANCEL_RECOVERY_BY_QUORUM") {
          modelViolation = recordCancellation(ctx.abstract, "GUARDIAN_QUORUM", minedAt);
        } else if (target.kind === "BIND_MIGRATION") {
          ctx.abstract.migrationBound = true;
          ctx.abstract.migrationAuthorizedBy = new Set(target.authorRoots);
          ctx.boundAtTimestamp = minedAt;
        } else if (target.kind === "ROTATE_CREDENTIAL") {
          ctx.abstract.credentialReplacements += 1;
        } else if (target.kind === "SET_GUARDIANS") {
          ctx.abstract.guardianTransitions += 1;
          const decoded = vault.interface.decodeFunctionData("setGuardians", target.data);
          adoptRoster(ctx, (decoded[1] as string[]).map(String), BigInt(decoded[0] as bigint));
        }
        return {
          ok: true,
          revert: null,
          attributedRoots: attributed,
          modelViolation,
          minedAt,
          replayed,
          published: publishedEgress(w, receipt),
        };
      } catch (e) {
        return {
          ok: false,
          revert: errNameG2(w.vault.interface, e),
          attributedRoots: attributed,
          modelViolation: null,
          replayed,
        };
      }
    }

    case "FACTORY_DEPLOY_TWIN": {
      const factory = w.factory.connect(signerOf(actor, ctx)) as ethers.Contract;
      const hostileGenesis = {
        signer: addrOf(keyOf(actor.name + "-hostile")),
        pqKeyHash: pqHash(keyOf(actor.name + "-hostile-pq")),
        verifier: w.verifiers.honest,
        threshold: 2,
        guardians: [0, 1, 2]
          .map((i) => addrOf(keyOf(actor.name + "-hostile-g" + i)))
          .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)),
        guardianIsContract: [false, false, false],
        floor: { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      };
      const salt = ethers.id(w.opts.label + "-vault");
      try {
        const predicted = (await factory.predictVault(salt, hostileGenesis)) as string;
        if (predicted.toLowerCase() === w.vaultAddress.toLowerCase()) {
          return {
            ok: true,
            revert: null,
            attributedRoots: none(),
            modelViolation:
              "I-COUNTERFACTUAL-IDENTITY-BINDING: a DIFFERENT genesis authority predicts the victim vault's address",
          };
        }
        await (
          await factory.deployVault(salt, hostileGenesis, pqKeyBytes(keyOf(actor.name + "-hostile-pq")), {
            gasLimit: 3_000_000n,
          })
        ).wait();
        return { ok: true, revert: null, attributedRoots: none(), modelViolation: null };
      } catch (e) {
        return { ok: false, revert: errNameG2(w.vault.interface, e), attributedRoots: none(), modelViolation: null };
      }
    }

    default:
      return { ok: false, revert: "UNKNOWN_ACTION", attributedRoots: none(), modelViolation: null };
  }
}
