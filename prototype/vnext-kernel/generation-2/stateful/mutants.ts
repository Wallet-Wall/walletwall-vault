/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * MUTATION ADEQUACY FOR THE GENERATION-2 CAMPAIGN. Each entry is a real, compiled, deployed weakening of
 * the candidate, applied to an in-memory copy of the source and never to the tracked file. A mutant counts
 * as KILLED only when (1) it compiled, (2) the named positive control still passed on it, so the kill is
 * not a broken deployment in disguise, and (3) the named property fired. Anything else is INCONCLUSIVE or
 * SURVIVED and is reported as that. Attribution is strict here, unlike Generation 1's fallback to the first
 * violation: these mutants are the admission's own adequacy evidence, so a kill by some other property
 * would say nothing about the rule the mutant removes.
 *
 * Generation 1's own catalogue also runs on the candidate: see GEN1_CATALOGUE_NOT_APPLICABLE below and
 * generation-2/test/Gen2MutationAdequacy.test.ts.
 */
import { replaceWithinFunction } from "../../authority/mutation-harness.js";
import { POSITIVE_CONTROL_LABELS as C } from "./campaign.js";
import { ZERO } from "../world.js";

const CALL = "(bool ok, ) = asset.call(abi.encodeWithSelector(0xa9059cbb, recipient, amount));";
const CALL_CHECK = "if (!ok) revert TransferFailed();";
const BEFORE = "uint256 before = _balanceOf(asset);";
const REMAINING = "uint256 remaining = _balanceOf(asset);";
const DELTA = "if (remaining > before || before - remaining != amount) revert TransferFailed();";
const CONSUME = "_consume(DOMAIN_SPEND, nonce, deadline);";
const ASSET_READ = "address asset = _admittedAsset();";
const BALANCE_FN = "function _balanceOf(address asset) internal view returns (uint256) {";
const CONTRACT_HEAD = "contract VaultKernelGen2Prototype";
/** Hardhat's second default account: the campaign's outsider, the signer every stranger sends as. */
const RELAYER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

function onceGlobal(source: string, oldSnippet: string, newSnippet: string): string {
  const n = source.split(oldSnippet).length - 1;
  if (n !== 1) throw new Error(`expected exactly one occurrence, found ${n}: ${oldSnippet.slice(0, 70)}`);
  return source.replace(oldSnippet, () => newSnippet);
}

/** What a mutant reads to take a caller's word for an address: trailing bytes the ABI decoder ignores. */
const TAIL_ADDRESS = `function _tailAddress(address fallback_) internal pure returns (address) {
        if (msg.data.length >= 24 && bytes4(msg.data[msg.data.length - 4:]) == bytes4(0xdeadbeef)) {
            return address(bytes20(msg.data[msg.data.length - 24:msg.data.length - 4]));
        }
        return fallback_;
    }

    `;
const withTailAddress = (s: string): string => onceGlobal(s, BALANCE_FN, TAIL_ADDRESS + BALANCE_FN);

const ASSET_OVERRIDE_READ =
  "bytes memory args = Clones.fetchCloneArgs(address(this));\n        if (args.length < 48) return address(0);";
const withAssetOverride = (s: string): string =>
  onceGlobal(
    replaceWithinFunction(
      s,
      "_admittedAsset",
      ASSET_OVERRIDE_READ,
      "if (_assetOverride != address(0)) return _assetOverride;\n        " + ASSET_OVERRIDE_READ,
    ),
    "function _admittedAsset() internal view returns (address) {",
    "address private _assetOverride;\n\n    function _admittedAsset() internal view returns (address) {",
  );

export interface G2Mutation {
  /** M-G2-1..10 are the brief's required classes; the rest are this lane's own findings put back. */
  id: string;
  expectedProperty: string;
  /** Further properties that must fire in the same campaign, so each has a mutant that shows its teeth. */
  alsoExpected?: readonly string[];
  /** The positive control that must still pass on this mutant, or the kill proves nothing. */
  liveControl: string;
  profiles: string[];
  rationale: string;
  apply: (kernelSource: string) => string;
  applyFactory?: (factorySource: string) => string;
  /** The verifying contract honest digests must name for this mutant to be live at all. */
  signingDomainVault?: string;
  /** The recipient honest spend digests must name for this mutant to be live at all. */
  signedSpendRecipient?: string;
}

export const G2_MUTATIONS: readonly G2Mutation[] = [
  {
    id: "M-G2-1-caller-chooses-token",
    expectedProperty: "P-SPEND-TOUCHES-ONLY-ASSET",
    liveControl: C.spend,
    profiles: ["erc20-relayer", "erc20-direct-transfer", "erc20-settlement-zoo"],
    rationale:
      "execute takes the token from trailing calldata, so a relayer holding no root picks which of the vault's holdings a signed spend moves. The signature still verifies, because the asset is not in the signed parameters: it never needed to be, while the asset is the vault's own code.",
    apply: (s) =>
      withTailAddress(
        replaceWithinFunction(s, "execute", ASSET_READ, "address asset = _tailAddress(_admittedAsset());"),
      ),
  },
  {
    id: "M-G2-2-asset-outside-the-identity",
    expectedProperty: "P-ASSET-CODE-IDENTITY",
    liveControl: C.spend,
    profiles: ["erc20-direct-transfer"],
    rationale:
      "The clone's args carry the factory instead of the asset and the kernel asks the factory, which has a mutable asset and an open setter. Every spend still settles; what is gone is the claim that the asset is the vault's identity, because one address can now mean any asset.",
    apply: (s) => {
      const withInterface = onceGlobal(
        s,
        CONTRACT_HEAD,
        "interface IAssetSourceMutant {\n    function admittedAsset() external view returns (address);\n}\n\n" +
          CONTRACT_HEAD,
      );
      return replaceWithinFunction(
        withInterface,
        "_admittedAsset",
        "return address(bytes20(word));",
        "return IAssetSourceMutant(address(bytes20(word))).admittedAsset();",
      );
    },
    applyFactory: (s) => {
      const mutable = onceGlobal(
        s,
        "address public immutable admittedAsset;",
        "address public admittedAsset;\n\n    function setAdmittedAsset(address asset) external {\n        admittedAsset = asset;\n    }",
      );
      return replaceWithinFunction(
        mutable,
        "_args",
        "return abi.encodePacked(generation, verifierAuthority, admittedAsset);",
        "return abi.encodePacked(generation, verifierAuthority, address(this));",
      );
    },
  },
  {
    id: "M-G2-3-cross-asset-replay-accepted",
    expectedProperty: "P-CROSS-ASSET",
    liveControl: C.spend,
    profiles: ["erc20-cross-asset"],
    rationale:
      "The domain separator stops naming the vault. Two vaults with one credential but different assets now accept each other's signatures: the only thing that made a signature asset-specific was that the asset is part of the vault's address, and the signature names the address.",
    apply: (s) =>
      replaceWithinFunction(s, "domainSeparator", "block.chainid, address(this)", "block.chainid, address(0)"),
    signingDomainVault: ZERO,
  },
  {
    id: "M-G2-4-boolean-trust",
    expectedProperty: "P-SETTLEMENT-EXACT",
    liveControl: C.spend,
    profiles: ["erc20-settlement-zoo"],
    rationale:
      "Settlement judged on the token's returned boolean, the SafeERC20 shape, with the observed balance never read. A token that says true and moves nothing settles and burns the nonce.",
    apply: (s) => {
      let out = replaceWithinFunction(s, "execute", BEFORE, "");
      out = replaceWithinFunction(
        out,
        "execute",
        CALL + "\n        " + CALL_CHECK,
        "(bool ok, bytes memory data) = asset.call(abi.encodeWithSelector(0xa9059cbb, recipient, amount));\n" +
          "        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();",
      );
      out = replaceWithinFunction(out, "execute", REMAINING, "");
      return replaceWithinFunction(out, "execute", DELTA, "");
    },
  },
  {
    id: "M-G2-5-any-decrease-accepted",
    expectedProperty: "P-SETTLEMENT-EXACT",
    liveControl: C.spend,
    profiles: ["erc20-settlement-zoo"],
    rationale:
      "Egress's full-balance rule applied to a sized spend: any decrease settles. A short-paying or sender-fee token now moves a different amount from the one the credential signed.",
    apply: (s) => replaceWithinFunction(s, "execute", DELTA, "if (remaining >= before) revert TransferFailed();"),
  },
  {
    id: "M-G2-6-nonce-after-token-call",
    expectedProperty: "P-NONCE-SPENT-BEFORE-TOKEN-RUNS",
    liveControl: C.spend,
    profiles: ["erc20-reentrancy", "erc20-reentrancy-armed-floor"],
    rationale:
      "The nonce is consumed after the asset call. The whole no-guard reentrancy argument rests on the opposite order, so the token itself reads the vault's nonce getter from inside its transfer.",
    apply: (s) => {
      const out = replaceWithinFunction(s, "execute", CONSUME, "");
      return replaceWithinFunction(out, "execute", DELTA, DELTA + "\n        " + CONSUME);
    },
  },
  {
    id: "M-G2-7-failed-transfer-ignored",
    expectedProperty: "P-SPEND-COMPLETED-TRANSFER",
    liveControl: C.spend,
    profiles: ["erc20-settlement-zoo", "erc20-reentrancy"],
    rationale:
      "A failed call is ignored and only the observed delta decides. For any non-zero amount the delta still refuses, so the only observable harm is a zero-amount spend settling over a reverted transfer, which is what the token's own completed-transfer count catches.",
    apply: (s) => replaceWithinFunction(s, "execute", CALL_CHECK, ""),
  },
  {
    id: "M-G2-8-migration-caller-chooses-token",
    expectedProperty: "P-EXIT-REACHABLE",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "The first egress caller's token is pinned as the only asset that can ever leave. Permissionless is safe only because a caller has no discretion, so a stranger who egresses a worthless token first traps the admitted asset: I-MIGRATION-NONTRAP(a) and I-EGRESS-INDEPENDENCE.",
    apply: (s) => {
      const pinned = onceGlobal(
        s,
        "function egress(address asset) external {",
        "address private _pinnedEgress;\n\n    function egress(address asset) external {",
      );
      return replaceWithinFunction(
        pinned,
        "egress",
        "if (!b.bound) revert NotBound();",
        "if (!b.bound) revert NotBound();\n        address pinnedKey = asset == address(0) ? address(1) : asset;\n        if (_pinnedEgress == address(0)) _pinnedEgress = pinnedKey;\n        else if (_pinnedEgress != pinnedKey) revert TransferFailed();",
      );
    },
  },
  {
    id: "M-G2-9-migration-caller-chooses-recipient",
    expectedProperty: "P-EGRESS-RECIPIENT",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "Egress reads the recipient from trailing calldata. Whoever submits first takes the vault's whole balance: the binding becomes advisory.",
    apply: (s) =>
      withTailAddress(
        replaceWithinFunction(
          s,
          "egress",
          "abi.encodeWithSelector(0xa9059cbb, b.destinationVault, before)",
          "abi.encodeWithSelector(0xa9059cbb, _tailAddress(b.destinationVault), before)",
        ),
      ),
  },
  {
    id: "M-G2-10-relayer-identity-gains-privilege",
    expectedProperty: "P-CUT/ASSET_MOVEMENT",
    liveControl: C.spend,
    profiles: ["stranger-only", "erc20-relayer"],
    rationale:
      "One submitter address passes the credential check. The architecture's zero-msg.sender rule is exactly what this removes: a relayer becomes a root nobody declared.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_authorise",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
        `if (msg.sender == ${RELAYER_ADDRESS}) return;\n        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();`,
      ),
  },
  {
    id: "M-G2-11-egress-delay-removed",
    expectedProperty: "P-MIGRATION-TIME",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "F-TIME, put back: measured Variant A and Generation 1 both have this. The binding's delay gates only retire, so {k guardians, ECDSA} drains an armed vault in the block after binding, against 7 days for its recovery path.",
    apply: (s) =>
      replaceWithinFunction(s, "egress", "if (block.timestamp < b.boundAt + BIND_DELAY) revert TooEarly();", ""),
  },
  {
    id: "M-G2-12-lenient-balance-read",
    expectedProperty: "P-SETTLEMENT-EXACT",
    liveControl: C.spend,
    profiles: ["erc20-settlement-zoo"],
    rationale:
      "F-SETTLE, put back: measured Variant A's read. A failed balance query reads as zero, and a zero after the transfer is exactly what a full-balance movement looks like, so a spend of the whole balance settles with nothing moved and the nonce burned.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_balanceOf",
        "if (!ok || data.length < 32) revert TransferFailed();",
        "if (!ok || data.length < 32) return 0;",
      ),
  },
  {
    id: "M-G2-13-spend-nonce-not-consumed",
    expectedProperty: "P-NONCE-ON-SPEND",
    liveControl: C.spend,
    profiles: ["replay-composition", "erc20-relayer"],
    rationale: "The spend path skips the nonce. One captured signature empties the vault through any relayer.",
    apply: (s) => replaceWithinFunction(s, "execute", CONSUME, ""),
  },
  {
    id: "M-G2-14-relayer-chooses-recipient",
    expectedProperty: "P-SPEND-PAYS-RECIPIENT",
    alsoExpected: ["P-CONSERVATION"],
    liveControl: C.spend,
    profiles: ["erc20-relayer", "erc20-direct-transfer"],
    rationale:
      "execute pays an address from trailing calldata instead of the signed recipient. The digest still names the signed one, so only the token's ledger can tell.",
    apply: (s) =>
      withTailAddress(
        replaceWithinFunction(
          s,
          "execute",
          "abi.encodeWithSelector(0xa9059cbb, recipient, amount)",
          "abi.encodeWithSelector(0xa9059cbb, _tailAddress(recipient), amount)",
        ),
      ),
  },
  {
    id: "M-G2-15-credential-moves-the-asset-in-place",
    expectedProperty: "P-ASSET-CODE-IDENTITY",
    liveControl: C.spend,
    profiles: ["erc20-policy-then-spend"],
    rationale:
      "G2-ASSET-5: a credential-signed setPolicy also rewrites a stored asset. Storage is movable by whoever can write it, which is why the asset is in code.",
    apply: (s) =>
      replaceWithinFunction(
        withAssetOverride(s),
        "setPolicy",
        "policyEngine = policy;",
        "policyEngine = policy;\n        if (policy != address(0)) _assetOverride = policy;",
      ),
  },
  {
    id: "M-G2-16-quorum-moves-the-asset-in-place",
    expectedProperty: "P-ASSET-CODE-IDENTITY",
    liveControl: C.spend,
    profiles: ["quorum-without-credential", "recovery-vs-roster"],
    rationale:
      "G2-ASSET-6: a guardian quorum's setGuardians also rewrites a stored asset, so k guardians choose which token the credential's next spend moves.",
    apply: (s) =>
      replaceWithinFunction(
        withAssetOverride(s),
        "setGuardians",
        "guardianThreshold = newThreshold;",
        "guardianThreshold = newThreshold;\n        _assetOverride = newMembers[0];",
      ),
  },
  {
    id: "M-G2-17-signed-recipient-unbound",
    expectedProperty: "P-UNAUTHORISED-INPUT-NEVER-SETTLES",
    liveControl: C.spend,
    profiles: ["erc20-relayer"],
    rationale:
      "The digest stops naming the recipient, so a relayer holding nothing rewrites where an honestly-signed spend goes. Honest digests are signed to match, or the mutant would be dead rather than caught.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "execute",
        "keccak256(abi.encode(recipient, amount))",
        "keccak256(abi.encode(address(0), amount))",
      ),
    signedSpendRecipient: ZERO,
  },
  {
    id: "M-G2-18-spent-nonce-accepted",
    expectedProperty: "P-NO-REPLAY",
    liveControl: C.spend,
    profiles: ["replay-composition", "erc20-relayer"],
    rationale:
      "_consume accepts any nonce at or below the counter, so bytes already spent settle again, whoever resubmits them.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_consume",
        "if (nonces[domain] != nonce) revert BadNonce();",
        "if (nonce > nonces[domain]) revert BadNonce();",
      ),
  },
  {
    id: "M-G2-19-replay-accepted-inside-the-transfer",
    expectedProperty: "P-REENTRY-NO-REPLAY",
    liveControl: C.spend,
    profiles: ["erc20-reentrancy", "erc20-reentrancy-armed-floor"],
    rationale:
      "The same weakening, seen from inside the call: a token replays the very spend it sits inside. For a non-zero amount the exact delta still refuses, so this dies on a zero-amount spend, which is the one place replay is otherwise invisible.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_consume",
        "if (nonces[domain] != nonce) revert BadNonce();",
        "if (nonce > nonces[domain]) revert BadNonce();",
      ),
  },
  {
    id: "M-G2-20-full-balance-unspendable",
    expectedProperty: "P-BALANCE-SPENDABLE",
    liveControl: C.spend,
    profiles: ["erc20-direct-transfer", "erc20-policy-then-spend"],
    rationale:
      "A spend of the whole balance is refused. Every partial spend still works, so only a property judged at the end of a history can see that something has been stranded.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "execute",
        BEFORE,
        BEFORE + "\n        if (amount != 0 && amount >= before) revert TransferFailed();",
      ),
  },
  {
    id: "M-G2-21-verifier-provenance-unchecked",
    expectedProperty: "P-VERIFIER-PROVENANCE",
    liveControl: C.spend,
    profiles: ["erc20-real-root-floor", "erc20-real-root-armed"],
    rationale:
      "The admission check accepts anything with code, at all three edges, so an always-true verifier becomes active under the real root: SD-11A and SD-11B reopened.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireAdmissibleVerifier",
        "if (!IKernelVerifierAuthority(_verifierAuthority()).isAdmissibleVerifier(verifier)) revert InadmissibleVerifier();",
        "verifier;",
      ),
  },
  {
    id: "M-G2-22-egress-publishes-the-whole-balance",
    expectedProperty: "P-EGRESS-PUBLISHES-THE-TRUTH",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "Egress reports the balance it started with instead of the decrease it observed: a token that short-pays or moves nothing is published as having moved everything. I-NO-FALSE-SETTLEMENT is about what is reported, so only a property reading the event against the real ledger can see it.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "egress",
        "uint256 remaining = _balanceOf(asset);\n                if (remaining >= before) revert TransferFailed();\n                moved = before - remaining;",
        "moved = before;",
      ),
  },
  {
    id: "M-G2-23-dead-binding-accepted",
    expectedProperty: "P-EXIT-REACHABLE",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "The bind-time hash check is removed, restoring both kernels' behaviour before this lane: a binding naming the wrong hash is accepted, egress refuses it forever, and nothing can rebind, spend or recover. I-MIGRATION-NONTRAP's trap, reachable by one honest mistake at k+1.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "bindMigration",
        "if (destination.vault.codehash != destination.codeHash) revert DestinationMismatch();",
        "",
      ),
  },
  {
    id: "M-G2-24-self-binding-accepted",
    expectedProperty: "P-EXIT-REACHABLE",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "A vault may bind to itself. It has the right hash, so nothing else stops it, and then its balance can never fall: the asset's egress refuses forever, native value is published as moved with nothing gone, and nothing can rebind, spend or recover.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "bindMigration",
        "if (destination.vault.code.length == 0 || destination.vault == address(this)) revert DestinationMismatch();",
        "if (destination.vault.code.length == 0) revert DestinationMismatch();",
      ),
  },
  {
    id: "M-G2-25-native-published-unobserved",
    expectedProperty: "P-EGRESS-PUBLISHES-THE-TRUTH",
    liveControl: C.egress,
    profiles: ["erc20-migration-and-freeze"],
    rationale:
      "F-SETTLE on native value, put back: measured Variant A and Generation 1 publish what they sent because the call returned. A destination that hands the value back leaves the balance where it was, with an event saying it all moved.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "egress",
        "uint256 remaining = address(this).balance;\n                if (remaining >= before) revert TransferFailed();\n                moved = before - remaining;",
        "moved = before;",
      ),
  },
];

/**
 * Generation 1's catalogue on the candidate: killed by any property, as in Generation 1, because these are
 * regression classes rather than this lane's own evidence. An entry belongs in the first map only if its
 * anchor was in the two functions this candidate rewrote, and the reason must name what covers the clause.
 */
export const GEN1_CATALOGUE_NOT_APPLICABLE: Readonly<Record<string, string>> = {};

/**
 * Profiles a Generation-1 mutant is hunted on in addition to its own. RECORDED AS A HARNESS FINDING: M23 survived
 * the inherited straddle profile, because it needs several containment entries to succeed in sequence and most
 * generated quorum shapes are adversarial. A scripted straddle showed the oracle fires on the reachable shape, so
 * the generator was at fault and not the property: a profile that reaches the seam was added, and the kill is by
 * the same independent oracle. test/Gen2KernelRows.test.ts also pins the straddle deterministically on the candidate.
 */
export const GEN1_CATALOGUE_EXTRA_PROFILES: Readonly<Record<string, readonly string[]>> = {
  "M23-tumbling-reset-restored": ["erc20-containment-straddle"],
};
