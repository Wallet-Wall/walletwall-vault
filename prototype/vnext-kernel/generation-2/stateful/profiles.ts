/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * GENERATION-2 CAMPAIGN PROFILES. Every Generation-1 profile runs here too, with its adversary model
 * and its action mix intact and a light ERC-20 background added, so nothing Generation 1 composed goes
 * uncomposed on the candidate. The profiles after them put the new state under direct pressure.
 */
import {
  PROFILES,
  ALL_MATERIAL_ACTOR,
  ECDSA_ONLY_ATTACKER,
  MIXED_ATTACKER,
  ONE_GUARDIAN_ATTACKER,
  STRANGER,
  TWO_GUARDIAN_ATTACKER,
  type CampaignProfile,
} from "../../stateful/profiles.js";
import { makeActor, type Actor } from "../../stateful/world.js";
import type { ActionKindG2 } from "./actions.js";
import type { ModeName, VerifierKindG2 } from "../world.js";

export { ALL_MATERIAL_ACTOR };

export interface CampaignProfileG2 {
  name: string;
  description: string;
  actors: Actor[];
  actorWeights: number[];
  weights: Partial<Record<ActionKindG2, number>>;
  verifier?: VerifierKindG2;
  ecdsaOnlyFloor?: boolean;
  commitPqKeyOnEcdsaOnlyFloor?: boolean;
  fabricateCommitments?: boolean;
  timeBias?: "default" | "maturation" | "duty-cycle" | "straddle";
  honestRecoveryBias?: boolean;
  /** Mostly honest quorums on containment: the straddle needs several entries to succeed in sequence. */
  honestContainmentBias?: boolean;
  /** The token behaviours this profile generates, weighted by repetition. Default: vanilla only. */
  tokenModes?: readonly ModeName[];
  /** Bind the REAL verifier provenance root instead of the ungated fixture. */
  realRoot?: boolean;
  /** Deploy the same genesis under a second factory bound to a second asset. */
  sibling?: boolean;
}

/** The light ERC-20 background every inherited profile carries. */
const BACKGROUND: Partial<Record<ActionKindG2, number>> = { DIRECT_TRANSFER: 2, UNSOLICITED_TRANSFER: 1 };

const inherit = (p: CampaignProfile): CampaignProfileG2 => ({
  name: p.name,
  description: p.description,
  actors: p.actors,
  actorWeights: p.actorWeights,
  weights: { ...p.weights, ...BACKGROUND },
  verifier: p.verifier as VerifierKindG2 | undefined,
  ecdsaOnlyFloor: p.ecdsaOnlyFloor,
  commitPqKeyOnEcdsaOnlyFloor: p.commitPqKeyOnEcdsaOnlyFloor,
  fabricateCommitments: p.fabricateCommitments,
  timeBias: p.timeBias,
  honestRecoveryBias: p.honestRecoveryBias,
});

const BROAD_ERC20: Partial<Record<ActionKindG2, number>> = {
  FUND: 2,
  SPEND: 14,
  ROTATE_CREDENTIAL: 3,
  SET_VERIFIER: 3,
  SET_POLICY: 3,
  SET_GUARDIANS: 2,
  INITIATE_RECOVERY: 4,
  CANCEL_RECOVERY: 2,
  EXECUTE_RECOVERY: 4,
  ENTER_CONTAINMENT: 3,
  BIND_MIGRATION: 2,
  RETIRE: 1,
  EGRESS_NATIVE: 2,
  EGRESS_TOKEN: 4,
  EGRESS_OTHER: 2,
  ADVANCE_TIME: 8,
  REPLAY_PAST_CALL: 6,
  DIRECT_TRANSFER: 6,
  UNSOLICITED_TRANSFER: 3,
};

/** A signer who can never authorise anything, sending as the relayer. */
const RELAYER = makeActor("relayer-stranger", []);

const ERC20_PROFILES: readonly CampaignProfileG2[] = [
  {
    name: "erc20-settlement-zoo",
    description:
      "The token changes behaviour mid-history: lies, short-pays, charges the sender, settles dust short, reverts, returns false, returns nothing, or fails its own balance query after the transfer. The credential-holding actor keeps spending through all of it. P-SETTLEMENT-EXACT reads the real ledger, so a kernel that believes the token is caught.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [7, 2, 1],
    weights: {
      ...BROAD_ERC20,
      SPEND: 26,
      TOKEN_MODE: 16,
      TOKEN_BLOCKLIST: 3,
      ROTATE_CREDENTIAL: 2,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_TOKEN: 0,
      EGRESS_NATIVE: 0,
      EGRESS_OTHER: 0,
      INITIATE_RECOVERY: 1,
      EXECUTE_RECOVERY: 1,
      ENTER_CONTAINMENT: 1,
    },
    ecdsaOnlyFloor: true,
    tokenModes: [
      "VANILLA",
      "VANILLA",
      "VANILLA",
      "RETURN_FALSE_NO_MOVE",
      "RETURN_TRUE_NO_MOVE",
      "SHORT_PAY",
      "SENDER_FEE",
      "RECIPIENT_FEE",
      "DUST_SHORT",
      "REVERTS",
      "NO_RETURN",
      "RETURN_FALSE_BUT_MOVES",
      "QUERY_REVERTS_AFTER_TRANSFER",
      "QUERY_SHORT_AFTER_TRANSFER",
      "QUERY_LIES_EXACT_DEBIT",
    ],
  },
  {
    name: "erc20-direct-transfer",
    description:
      "Unsolicited credits and rebases, repeated, between spends: the vault has no ledger to desynchronise, so everything it holds stays spendable and a spend of more than the previous balance settles. Rebases are charged to nobody and are never an authority outcome.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [6, 2, 2],
    weights: { ...BROAD_ERC20, SPEND: 20, DIRECT_TRANSFER: 22, TOKEN_REBASE: 8, UNSOLICITED_TRANSFER: 8 },
    ecdsaOnlyFloor: true,
  },
  {
    name: "erc20-reentrancy",
    description:
      "A hook-bearing asset: before or after the debit the token calls back into the vault with a replay of the spend it sits inside, a second spend at nonce + 1, an egress, a containment, a binding or a retire, each signed only with what the arming actor holds. Serial equivalence is the claim: nothing the hook does may produce an outcome no ordering of authorised acts could.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, TWO_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [6, 3, 2, 3],
    weights: { ...BROAD_ERC20, SPEND: 24, ARM_HOOK: 22, TOKEN_MODE: 2, ADVANCE_TIME: 6 },
    ecdsaOnlyFloor: true,
    tokenModes: ["VANILLA", "VANILLA", "VANILLA", "NO_RETURN", "RETURN_FALSE_BUT_MOVES"],
  },
  {
    name: "erc20-reentrancy-armed-floor",
    description:
      "The reentrancy profile on a floor that mandates the PQ conjunct, so a nested spend needs both factors.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, MIXED_ATTACKER, STRANGER],
    actorWeights: [6, 3, 2, 3],
    weights: { ...BROAD_ERC20, SPEND: 24, ARM_HOOK: 22, ADVANCE_TIME: 6 },
  },
  {
    name: "erc20-migration-and-freeze",
    description:
      "Bindings under pressure: egress attempted before and after the delay, the issuer blocklisting recipient, vault and destination and lifting it again, hostile unsolicited holdings, appended recipients, retire, replays of every migration act. A hostile holding must veto nothing, and no holding may leave early or go anywhere but the destination.",
    actors: [ALL_MATERIAL_ACTOR, TWO_GUARDIAN_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [5, 3, 2, 4],
    weights: {
      ...BROAD_ERC20,
      BIND_MIGRATION: 12,
      EGRESS_TOKEN: 18,
      EGRESS_NATIVE: 8,
      EGRESS_OTHER: 12,
      RETIRE: 6,
      TOKEN_BLOCKLIST: 10,
      TOKEN_MODE: 8,
      DESTINATION_MODE: 6,
      UNSOLICITED_TRANSFER: 8,
      ADVANCE_TIME: 18,
      REPLAY_PAST_CALL: 10,
    },
    timeBias: "maturation",
    ecdsaOnlyFloor: true,
    tokenModes: [
      "VANILLA",
      "VANILLA",
      "VANILLA",
      "VANILLA",
      "SHORT_PAY",
      "RETURN_TRUE_NO_MOVE",
      "RETURN_FALSE_NO_MOVE",
      "QUERY_REVERTS_AFTER_TRANSFER",
      "QUERY_SHORT_AFTER_TRANSFER",
      "QUERY_LIES_EXACT_DEBIT",
    ],
  },
  {
    name: "erc20-cross-asset",
    description:
      "Two vaults with byte-identical genesis and one credential, two assets. Every working spend is replayed at the other asset's vault, and signatures made for the other vault are submitted here. P-CROSS-ASSET reads the other vault's ledger and nonce.",
    actors: [ALL_MATERIAL_ACTOR, RELAYER, STRANGER],
    actorWeights: [5, 4, 2],
    weights: {
      ...BROAD_ERC20,
      SPEND: 18,
      CROSS_ASSET_REPLAY: 24,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_TOKEN: 0,
      EGRESS_NATIVE: 0,
      EGRESS_OTHER: 0,
    },
    ecdsaOnlyFloor: true,
    sibling: true,
  },
  {
    name: "erc20-relayer",
    description:
      "A stranger submits everything: honest spends relayed verbatim, the same spends with the recipient or amount rewritten and a token address appended. A relayer may choose whether and when, and nothing else. A rewritten field that settles is charged to a stranger holding no roots, which the cut property refuses.",
    actors: [ALL_MATERIAL_ACTOR, RELAYER],
    actorWeights: [4, 8],
    weights: {
      ...BROAD_ERC20,
      SPEND: 24,
      RELAY_TAMPER: 26,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_TOKEN: 0,
      EGRESS_NATIVE: 0,
      EGRESS_OTHER: 0,
      ROTATE_CREDENTIAL: 1,
    },
    ecdsaOnlyFloor: true,
  },
  {
    name: "erc20-recovery-to-spend",
    description:
      "A recovery driven through to a new credential that then spends the admitted asset, under direct transfers and token-mode noise, including a recovery that begins while a zoo token is misbehaving.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [7, 2, 1],
    weights: {
      ...BROAD_ERC20,
      INITIATE_RECOVERY: 20,
      EXECUTE_RECOVERY: 18,
      CANCEL_RECOVERY: 3,
      CANCEL_RECOVERY_BY_QUORUM: 10,
      SET_GUARDIANS: 0,
      ADVANCE_TIME: 16,
      SPEND: 14,
      TOKEN_MODE: 3,
      BIND_MIGRATION: 1,
    },
    timeBias: "maturation",
    honestRecoveryBias: true,
    ecdsaOnlyFloor: true,
    tokenModes: ["VANILLA", "VANILLA", "VANILLA", "VANILLA", "REVERTS", "RETURN_TRUE_NO_MOVE"],
  },
  {
    name: "erc20-real-root-floor",
    description:
      "The real provenance root on the v1 floor: every verifier is root-created, the mocks are refused adversaries at all three edges, and verifier transitions are followed by spends. Requires no attestor signature anywhere while the floor is dormant, which is the point: G2-VERIFIER-2,3,8.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [6, 3, 2, 1],
    weights: {
      ...BROAD_ERC20,
      SET_VERIFIER: 16,
      INITIATE_RECOVERY: 12,
      EXECUTE_RECOVERY: 14,
      SPEND: 14,
      ADVANCE_TIME: 16,
    },
    timeBias: "maturation",
    honestRecoveryBias: true,
    ecdsaOnlyFloor: true,
    commitPqKeyOnEcdsaOnlyFloor: true,
    realRoot: true,
  },
  {
    name: "erc20-real-root-armed",
    description:
      "The real root on an armed floor: the second factor is an attestor statement over the admitted class's real relation, so an attacker without the PQ root faces the real verifier and not a stand-in.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [6, 4, 2, 1],
    weights: {
      ...BROAD_ERC20,
      SET_VERIFIER: 10,
      INITIATE_RECOVERY: 10,
      EXECUTE_RECOVERY: 12,
      SPEND: 14,
      ROTATE_CREDENTIAL: 8,
      ADVANCE_TIME: 14,
    },
    timeBias: "maturation",
    honestRecoveryBias: true,
    realRoot: true,
  },
  {
    name: "erc20-policy-then-spend",
    description:
      "The denying plane, the stateful plane and a codeless plane, each followed by spends, with direct credits between them. A plane may only refuse: under the denying plane no asset moves.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [7, 2, 1],
    weights: {
      ...BROAD_ERC20,
      SET_POLICY: 18,
      SPEND: 24,
      DIRECT_TRANSFER: 8,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_TOKEN: 0,
      EGRESS_NATIVE: 0,
      EGRESS_OTHER: 0,
    },
    ecdsaOnlyFloor: true,
  },
  {
    name: "erc20-containment-then-spend",
    description:
      "Spends straddling containment entry and wall-clock expiry: refused while contained, settled the moment it lapses, with no principal acting.",
    actors: [ALL_MATERIAL_ACTOR, TWO_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [6, 3, 1],
    weights: {
      ...BROAD_ERC20,
      ENTER_CONTAINMENT: 18,
      SPEND: 22,
      ADVANCE_TIME: 22,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_TOKEN: 0,
      EGRESS_NATIVE: 0,
      EGRESS_OTHER: 0,
    },
    timeBias: "duty-cycle",
    ecdsaOnlyFloor: true,
  },
  {
    name: "erc20-containment-straddle",
    description:
      "Generation 1's straddle timing with almost nothing else: repeated containment entries around a 30-day boundary, with spends only to show when the kernel lets them through. The tumbling-window defect (M23) survived every other profile here, because it needs several entries to succeed in sequence and most quorum shapes are adversarial, so this one mostly attempts honest ones. The oracle is unchanged and is the independent one: it rebuilds episodes from timestamps and reads no budget getter.",
    actors: [ALL_MATERIAL_ACTOR, TWO_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [8, 1, 1],
    weights: { ENTER_CONTAINMENT: 34, ADVANCE_TIME: 34, SPEND: 6, DIRECT_TRANSFER: 1 },
    timeBias: "straddle",
    honestContainmentBias: true,
    ecdsaOnlyFloor: true,
  },
];

/** Every Generation-1 profile, in its order, then the ERC-20 profiles. Names are unique across both. */
export const G2_PROFILES: readonly CampaignProfileG2[] = [...PROFILES.map(inherit), ...ERC20_PROFILES];

export const INHERITED_PROFILE_COUNT = PROFILES.length;
