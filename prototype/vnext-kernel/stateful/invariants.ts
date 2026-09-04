/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE PROPERTIES. Asserted after EVERY generated step, successful or reverted.
 *
 * THE SOURCE-BINDING RULE, WHICH IS NOT OPTIONAL
 * ----------------------------------------------
 * An invariant is only admitted here if it can name the SOURCE MECHANISM that
 * establishes it. "Sounds sensible" is not a reason: an invariant with no source
 * binding is an assumption the harness would be smuggling in, and when it fails
 * nobody can tell whether the kernel broke a rule or the harness invented one.
 * Every entry below therefore carries `source`, quoting the construct in
 * VaultKernelPrototype.sol that makes it true.
 *
 * The candidates that did NOT survive that rule are recorded in
 * `REJECTED_INVARIANTS` rather than deleted, so the reader can see what was
 * considered and why it is absent.
 */
import { ethers } from "../test/connection.js";
import { pqHash } from "./world.js";
import type { World } from "./world.js";

/** A snapshot of every security-relevant storage slot the kernel exposes. */
export interface KernelSnapshot {
  safeStateStored: number;
  safeStateEffective: number;
  containedUntil: bigint;
  containmentWindowStart: bigint;
  containmentUsedInWindow: bigint;
  ecdsaSigner: string;
  pqPublicKeyHash: string;
  /**
   * Whether the stored commitment is one this campaign HOLDS A PREIMAGE FOR.
   *
   * A preimage is not decidable from storage, so this is the one snapshot field
   * derived from the harness's own key material rather than read from the chain.
   * The campaign generates every PQ key from a label, so the set of commitments
   * it can ever exhibit is enumerable, and a stored value outside that set is
   * one that nothing on chain ever witnessed. Zero counts as attestable because
   * it is the kernel's representation of "no PQ credential", not a commitment.
   *
   * Without this field `G-COMMITMENT-ATTESTED` would be undecidable, and
   * `G-PQ-COMMITMENT-SATISFIABLE`'s zero-only check would remain the whole of
   * the oracle's vision — which is exactly how SD-6 and SD-7 stayed invisible to
   * 224 green campaigns.
   */
  commitmentAttestable: boolean;
  credentialGeneration: bigint;
  floor: { requirePq: boolean; pqParamLevel: bigint; pqPublicKeyLength: bigint; pqSignatureLength: bigint };
  pqVerifier: string;
  pqVerifierHasCode: boolean;
  policyEngine: string;
  guardianCommitment: string;
  guardianThreshold: bigint;
  guardianGeneration: bigint;
  nonces: [bigint, bigint, bigint, bigint];
  recovery: {
    proposedSigner: string;
    proposedPqKeyHash: string;
    proposedVerifier: string;
    executableAt: bigint;
    expiresAt: bigint;
    boundGuardianGeneration: bigint;
    challengesUsed: bigint;
    active: boolean;
  };
  migration: {
    destinationVault: string;
    destinationVaultCodeHash: string;
    destinationGeneration: bigint;
    boundAt: bigint;
    bound: boolean;
  };
  nativeBalance: bigint;
  tokenBalance: bigint;
  blockTimestamp: bigint;
}

const ZERO = "0x0000000000000000000000000000000000000000";
const ZERO_HASH = "0x" + "0".repeat(64);

/**
 * Cached across a whole run: the token contract handle and the vault's verifier
 * code lookup are the only two reads here that are not a plain storage getter,
 * and re-resolving the contract object every step was measurable.
 */
let cachedToken: ethers.Contract | null = null;
let cachedTokenAddress = "";

/** Cached per world label — the key set is fixed once the world is built. */
const attestableCache = new Map<string, ReadonlySet<string>>();

/**
 * Every commitment this campaign can exhibit a preimage for: the vault's own PQ
 * key, every spare the action layer may rotate or recover to, and zero. Any
 * other value in `pqPublicKeyHash` was admitted without a witness.
 */
function attestableCommitments(world: World): ReadonlySet<string> {
  const hit = attestableCache.get(world.opts.label);
  if (hit !== undefined) return hit;
  const set = new Set<string>([ZERO_HASH]);
  for (const k of [world.pqKey, ...world.sparePq]) set.add(pqHash(k).toLowerCase());
  attestableCache.set(world.opts.label, set);
  return set;
}

export async function snapshot(world: World): Promise<KernelSnapshot> {
  const v = world.vault;
  const [
    safeStateStored,
    safeStateEffective,
    containedUntil,
    containmentWindowStart,
    containmentUsedInWindow,
    ecdsaSigner,
    pqPublicKeyHash,
    credentialGeneration,
    floorRaw,
    pqVerifier,
    policyEngine,
    guardianCommitment,
    guardianThreshold,
    guardianGeneration,
    recoveryRaw,
    migrationRaw,
  ] = await Promise.all([
    v.safeState(),
    v.effectiveSafeState(),
    v.containedUntil(),
    v.containmentWindowStart(),
    v.containmentUsedInWindow(),
    v.ecdsaSigner(),
    v.pqPublicKeyHash(),
    v.credentialGeneration(),
    v.securityFloor(),
    v.pqVerifier(),
    v.policyEngine(),
    v.guardianCommitment(),
    v.guardianThreshold(),
    v.guardianGeneration(),
    v.recovery(),
    v.migration(),
  ]);

  if (cachedToken === null || cachedTokenAddress !== world.token) {
    cachedToken = (await ethers.getContractAt("TestToken", world.token, world.deployer)) as ethers.Contract;
    cachedTokenAddress = world.token;
  }

  const [nonce0, nonce1, nonce2, nonce3, code, block, tokenBalance, nativeBalance] = await Promise.all([
    v.nonces(0),
    v.nonces(1),
    v.nonces(2),
    v.nonces(3),
    ethers.provider.getCode(pqVerifier),
    ethers.provider.getBlock("latest"),
    cachedToken.balanceOf(world.vaultAddress),
    ethers.provider.getBalance(world.vaultAddress),
  ]);
  const nonces: [bigint, bigint, bigint, bigint] = [
    nonce0 as bigint,
    nonce1 as bigint,
    nonce2 as bigint,
    nonce3 as bigint,
  ];

  return {
    safeStateStored: Number(safeStateStored),
    safeStateEffective: Number(safeStateEffective),
    containedUntil,
    containmentWindowStart,
    containmentUsedInWindow,
    ecdsaSigner,
    pqPublicKeyHash,
    commitmentAttestable: attestableCommitments(world).has(String(pqPublicKeyHash).toLowerCase()),
    credentialGeneration,
    floor: {
      requirePq: floorRaw[0] as boolean,
      pqParamLevel: floorRaw[1] as bigint,
      pqPublicKeyLength: floorRaw[2] as bigint,
      pqSignatureLength: floorRaw[3] as bigint,
    },
    pqVerifier,
    pqVerifierHasCode: code !== "0x",
    policyEngine,
    guardianCommitment,
    guardianThreshold,
    guardianGeneration,
    nonces,
    recovery: {
      proposedSigner: recoveryRaw[0] as string,
      proposedPqKeyHash: recoveryRaw[1] as string,
      proposedVerifier: recoveryRaw[2] as string,
      executableAt: recoveryRaw[3] as bigint,
      expiresAt: recoveryRaw[4] as bigint,
      boundGuardianGeneration: recoveryRaw[5] as bigint,
      challengesUsed: recoveryRaw[6] as bigint,
      active: recoveryRaw[7] as boolean,
    },
    migration: {
      destinationVault: migrationRaw[0] as string,
      destinationVaultCodeHash: migrationRaw[1] as string,
      destinationGeneration: migrationRaw[2] as bigint,
      boundAt: migrationRaw[3] as bigint,
      bound: migrationRaw[4] as boolean,
    },
    nativeBalance: nativeBalance as bigint,
    tokenBalance: tokenBalance as bigint,
    blockTimestamp: BigInt((block as { timestamp?: number } | null)?.timestamp ?? 0),
  };
}

/** A compact digest of a snapshot, for the replay artifact's pre/post fields. */
export function digestSnapshot(s: KernelSnapshot): string {
  return ethers.keccak256(
    ethers.toUtf8Bytes(
      JSON.stringify(s, (_k, val) => (typeof val === "bigint" ? val.toString() : val)),
    ),
  );
}

export interface InvariantViolation {
  name: string;
  detail: string;
}

interface Invariant {
  name: string;
  /** The construct in VaultKernelPrototype.sol that establishes this. */
  source: string;
  check: (now: KernelSnapshot, prev: KernelSnapshot | null, world: World) => string | null;
}

/**
 * `SafeState` members, by ordinal. RECOVERY_ONLY is declared by the enum and —
 * as G-STATE-REACHABILITY records below — is never ASSIGNED anywhere in the
 * kernel. It is listed here so the reachability invariant can name it.
 */
export const SAFE_STATE = { NORMAL: 0, CONTAINED: 1, RECOVERY_ONLY: 2, MIGRATION_ONLY: 3, RETIRED: 4 } as const;

export const GLOBAL_INVARIANTS: readonly Invariant[] = [
  {
    name: "G-SIGNER-NONZERO",
    source:
      "initialize reverts ZeroAddress on g.signer == 0; rotateCredential reverts ZeroAddress on c.newSigner == 0; initiateRecovery reverts ZeroAddress on proposedSigner == 0, and executeRecovery installs only that value",
    check: (s) => (s.ecdsaSigner === ZERO ? "ecdsaSigner is the zero address" : null),
  },
  {
    name: "G-THRESHOLD-SANE",
    source: "_requireCanonicalRoster reverts BadRoster when threshold == 0 or members.length < threshold",
    check: (s) => (s.guardianThreshold === 0n ? "guardianThreshold is zero" : null),
  },
  {
    name: "G-COMMITMENT-NONZERO",
    source: "initialize and setGuardians both write rosterCommitment(...) of a canonical roster",
    check: (s) => (s.guardianCommitment === ZERO_HASH ? "guardianCommitment is zero" : null),
  },
  {
    name: "G-CRED-GENERATION-MONOTONIC",
    source: "credentialGeneration is written ONLY by _installCredential, as `credentialGeneration += 1`",
    check: (s, p) =>
      p && s.credentialGeneration < p.credentialGeneration
        ? "credentialGeneration went backwards: " + p.credentialGeneration + " -> " + s.credentialGeneration
        : null,
  },
  {
    name: "G-GUARDIAN-GENERATION-MONOTONIC",
    source: "guardianGeneration is written ONLY by initialize (= 1) and setGuardians, as `guardianGeneration += 1`",
    check: (s, p) =>
      p && s.guardianGeneration < p.guardianGeneration
        ? "guardianGeneration went backwards: " + p.guardianGeneration + " -> " + s.guardianGeneration
        : null,
  },
  {
    name: "G-NONCES-MONOTONIC",
    source: "_consume is the only writer of nonces[domain] and sets it to nonce + 1 after requiring equality",
    check: (s, p) => {
      if (!p) return null;
      for (let d = 0; d < 4; d++) {
        if (s.nonces[d]! < p.nonces[d]!) return "nonce domain " + d + " went backwards";
      }
      return null;
    },
  },
  {
    /**
     * A mandatory PQ conjunct must declare a shape that is satisfiable at BOTH
     * ends. Zero is unsatisfiable because no preimage of a committed key has it;
     * an unbounded `uint32` is unsatisfiable because no block could carry the
     * calldata. The upper half is a REQUIREMENT-side property, not a restatement
     * of the implementation: a kernel that bounded the shape more tightly still
     * passes it.
     */
    name: "G-FLOOR-SANE",
    source:
      "_requireSaneFloor: requirePq implies 0 < pqPublicKeyLength <= MAX_PQ_LENGTH and 0 < pqSignatureLength <= MAX_PQ_LENGTH, on both initialize and setVerifier",
    check: (s) => {
      if (!s.floor.requirePq) return null;
      if (s.floor.pqPublicKeyLength === 0n || s.floor.pqSignatureLength === 0n) {
        return "requirePq is set with a zero-length key or signature shape";
      }
      // The literal mirrors VaultKernelPrototype.MAX_PQ_LENGTH. It is written out
      // rather than read from the kernel deliberately: this file is the ORACLE,
      // and an oracle that sources its threshold from the implementation cannot
      // detect the implementation moving it. Mutant M18's sibling reasoning
      // applies — the number is pinned in test/Sd1RecoveryFloorBinding.test.ts
      // against the contract's own getter, so drift is caught there.
      if (s.floor.pqPublicKeyLength > 65535n || s.floor.pqSignatureLength > 65535n) {
        return (
          "requirePq is set with a shape beyond any standardised PQ scheme (" +
          s.floor.pqPublicKeyLength +
          "/" +
          s.floor.pqSignatureLength +
          "), which the freeze would make a permanently unsatisfiable floor"
        );
      }
      return null;
    },
  },
  {
    /**
     * `I-FLOOR-SHAPE-IMMUTABLE` is the SD-1 remediation, and this is its
     * REQUIREMENT-side statement rather than a mirror of the new comparisons.
     * The requirement is that no principal may move state the recovery
     * satisfiability condition reads — `_requireIncomingPossession` measures an
     * already-quorum-approved recovery against the two STRUCTURAL fields LIVE,
     * and no guardian path can repair them, so a kernel that lets them move
     * while a PQ conjunct is mandatory hands the credential an uncounted veto. A
     * kernel that froze them even harder still passes this.
     */
    name: "G-FLOOR-NO-DOWNGRADE",
    source:
      "_requireNoDowngrade: requirePq may not go true -> false, pqParamLevel may not decrease, and neither structural length may change while requirePq already holds (I-FLOOR-SHAPE-IMMUTABLE)",
    check: (s, p) => {
      if (!p) return null;
      if (p.floor.requirePq && !s.floor.requirePq) return "requirePq was downgraded from true to false";
      if (s.floor.pqParamLevel < p.floor.pqParamLevel) return "pqParamLevel decreased";
      if (p.floor.requirePq && s.floor.pqPublicKeyLength !== p.floor.pqPublicKeyLength) {
        return (
          "pqPublicKeyLength moved (" +
          p.floor.pqPublicKeyLength +
          " -> " +
          s.floor.pqPublicKeyLength +
          ") while a PQ conjunct was already mandatory"
        );
      }
      if (p.floor.requirePq && s.floor.pqSignatureLength !== p.floor.pqSignatureLength) {
        return (
          "pqSignatureLength moved (" +
          p.floor.pqSignatureLength +
          " -> " +
          s.floor.pqSignatureLength +
          ") while a PQ conjunct was already mandatory"
        );
      }
      return null;
    },
  },
  {
    name: "G-VERIFIER-HAS-CODE",
    source:
      "initialize and setVerifier both reject verifier.code.length == 0; initiateRecovery rejects proposedVerifier.code.length == 0 at INITIATE time",
    check: (s) => (!s.pqVerifierHasCode ? "pqVerifier " + s.pqVerifier + " has no code" : null),
  },
  {
    name: "G-MIGRATION-BINDING-WELLFORMED",
    source: "bindMigration reverts DestinationMismatch when destination.vault == 0 or destination.codeHash == 0",
    check: (s) =>
      s.migration.bound && (s.migration.destinationVault === ZERO || s.migration.destinationVaultCodeHash === ZERO_HASH)
        ? "migration is bound to a malformed destination"
        : null,
  },
  {
    name: "G-MIGRATION-BINDING-IMMUTABLE",
    source: "bindMigration reverts AlreadyBound once migration.bound; nothing anywhere clears it",
    check: (s, p) => {
      if (!p || !p.migration.bound) return null;
      if (!s.migration.bound) return "a bound migration became unbound";
      if (
        s.migration.destinationVault !== p.migration.destinationVault ||
        s.migration.destinationVaultCodeHash !== p.migration.destinationVaultCodeHash
      ) {
        return "a bound migration destination changed";
      }
      return null;
    },
  },
  {
    name: "G-STATE-REACHABILITY",
    source:
      "safeState is assigned in exactly four places: initialize (NORMAL), enterContainment (CONTAINED), bindMigration (MIGRATION_ONLY), retire (RETIRED). RECOVERY_ONLY is declared by the enum and never assigned",
    check: (s) =>
      s.safeStateStored === SAFE_STATE.RECOVERY_ONLY
        ? "safeState reached RECOVERY_ONLY, which no assignment in the kernel produces"
        : null,
  },
  {
    name: "G-RETIRED-IS-TERMINAL",
    source: "retire sets RETIRED; no assignment anywhere moves safeState out of RETIRED",
    check: (s, p) =>
      p && p.safeStateStored === SAFE_STATE.RETIRED && s.safeStateStored !== SAFE_STATE.RETIRED
        ? "safeState left RETIRED"
        : null,
  },
  {
    name: "G-EFFECTIVE-STATE-DERIVATION",
    source:
      "_effectiveState returns NORMAL when safeState == CONTAINED and block.timestamp >= containedUntil, and the stored value otherwise",
    check: (s) => {
      const expected =
        s.safeStateStored === SAFE_STATE.CONTAINED && s.blockTimestamp >= s.containedUntil
          ? SAFE_STATE.NORMAL
          : s.safeStateStored;
      return s.safeStateEffective !== expected
        ? "effectiveSafeState " + s.safeStateEffective + " disagrees with the derivation from stored state " + s.safeStateStored
        : null;
    },
  },
  {
    name: "G-CONTAINMENT-BUDGET-BOUNDED",
    source:
      "enterContainment reverts ContainmentBudget unless containmentUsedInWindow + CONTAINMENT_MAX <= CONTAINMENT_BUDGET (3d and 6d)",
    check: (s) =>
      s.containmentUsedInWindow > 6n * 86400n
        ? "containmentUsedInWindow " + s.containmentUsedInWindow + " exceeds the 6-day budget"
        : null,
  },
  {
    name: "G-RECOVERY-ACTIVE-WELLFORMED",
    source: "initiateRecovery is the only writer of recovery.active = true, and it rejects a zero proposedSigner/proposedVerifier",
    check: (s) =>
      s.recovery.active && (s.recovery.proposedSigner === ZERO || s.recovery.proposedVerifier === ZERO)
        ? "an active recovery has a zero proposed signer or verifier"
        : null,
  },
  {
    name: "G-CHALLENGE-CAP",
    source: "cancelRecovery reverts ChallengeExhausted once challengesUsed >= CHALLENGE_LIMIT (2), and increments by 1",
    check: (s) =>
      s.recovery.challengesUsed > 2n ? "challengesUsed " + s.recovery.challengesUsed + " exceeds CHALLENGE_LIMIT" : null,
  },
  {
    /**
     * `I-COMMITMENT-EXHIBITED-AT-ADMISSION`, over the WHOLE ingress surface
     * rather than over any one function. `pqPublicKeyHash` has exactly two write
     * sites — `initialize` and `_installCredential` — and `_installCredential`
     * has exactly two callers, so this STATE-shaped property covers all three
     * admitting transitions (genesis, rotation, recovery) at once. A
     * transition-shaped version would cover only the two that occur mid-campaign
     * and would miss genesis entirely, which is where SD-7 lived.
     *
     * THE FOUR STATES THIS ORACLE DISTINGUISHES, because collapsing them is how
     * the previous oracle missed both defects:
     *   ADMITTED   — a value is in `pqPublicKeyHash`. Visible to every property.
     *   EXHIBITED  — a preimage was shown to the kernel when it was admitted.
     *                Visible ONLY through `commitmentAttestable`.
     *   ACTIVATED  — `floor.requirePq` holds, so a SHAPE now governs the
     *                commitment. `G-FLOOR-SANE` and `G-FLOOR-NO-DOWNGRADE`.
     *   REQUIRED   — `_authorise` consults it, which is implied by ACTIVATED.
     * This property is exactly the ADMITTED-implies-EXHIBITED edge, and it is
     * deliberately INDEPENDENT of activation: a dormant commitment is still a
     * credential, and SD-6's whole harm was that nothing checked it while it
     * was dormant.
     *
     * WHAT IT DOES NOT SEE, stated so the greenness is not over-read: an
     * exhibited preimage need not be a WELL-FORMED KEY of any scheme. No oracle
     * over storage can see that, and no admission check can either — the only
     * party who could judge it is a verifier the admitting principal chooses.
     * That residue is carried as SD-8.
     */
    name: "G-COMMITMENT-ATTESTED",
    source:
      "every accepted transition that writes a non-zero pqPublicKeyHash must exhibit a preimage of the value being written, so every reachable state holds either bytes32(0) or a commitment some principal demonstrated a preimage for — initialize (base case), rotateCredential and executeRecovery (inductive step, via _requireIncomingPossession)",
    check: (s) =>
      s.commitmentAttestable
        ? null
        : "pqPublicKeyHash " +
          s.pqPublicKeyHash +
          " is in storage but no principal ever exhibited a preimage for it — an unattested commitment was admitted",
  },
  {
    /**
     * The OBSERVABLE half of "a transition affecting authentication requirements
     * must leave the vault in a satisfiable authentication state". The oracle
     * cannot know the preimage LENGTH of a commitment — that is exactly what
     * `I-DECLARATION-EXHIBITED` makes the kernel prove on chain — but it can see
     * the degenerate case, where no preimage exists at all. Together with
     * `G-FLOOR-SANE`, which bounds the declared shape at both ends, this is
     * everything about post-transition satisfiability that is decidable from
     * storage alone.
     *
     * It was SD-3's property, and while SD-3 stood it sat in
     * `KNOWN_DEFECT_PROPERTIES`, so campaign violations were moved out of
     * `violations` and merely counted. With SD-3 remediated it leaves that set
     * automatically, and this becomes a HARD invariant with the whole campaign
     * behind it.
     */
    name: "G-PQ-COMMITMENT-SATISFIABLE",
    source:
      "initialize reverts BadSignature when g.floor.requirePq && g.pqKeyHash == 0, and setVerifier's I-DECLARATION-EXHIBITED refuses the requirePq false -> true edge unless a preimage of the committed hash is exhibited at the newly declared length — a mandatory PQ conjunct with no satisfiable committed key is unsatisfiable and bricks spending",
    check: (s) =>
      s.floor.requirePq && s.pqPublicKeyHash === ZERO_HASH
        ? "requirePq is set while pqPublicKeyHash is zero — the conjunct keccak256(pqKey) == pqPublicKeyHash is unsatisfiable, so no spend can ever authorise"
        : null,
  },
  {
    /**
     * `I-DECLARATION-SUBORDINATE-TO-LIVE-RECOVERY`, stated on the REQUIREMENT
     * side: an accepted configuration transition may not silently reduce the
     * satisfiability of a recovery the guardians have ALREADY approved.
     *
     * TRANSITION-SHAPED, not state-shaped, and deliberately so: the harm is the
     * MOMENT the requirements move under a live request, not the resulting
     * state. A state-shaped version would re-fire on every later step and inflate
     * the violation count by the campaign's tail length.
     *
     * The "live" test is the exact request set `executeRecovery` would still
     * admit — active, unexpired, generation-current — so a request nothing could
     * have executed anyway is correctly not counted as harmed. A kernel that
     * refused MORE transitions than this still passes, which is what makes this
     * a requirement and not a mirror of the implementation.
     */
    name: "G-DECLARATION-SUBORDINATE-TO-RECOVERY",
    source:
      "OPEN REQUIREMENT — NO KERNEL MECHANISM ESTABLISHES THIS, AND THAT IS DELIBERATE. Every other entry's `source` names the code that makes the property hold; this one has none, and an earlier revision of this field wrongly named `setVerifier`'s `I-DECLARATION-SUBORDINATE-TO-LIVE-RECOVERY` as though it did. No such identifier exists in the Solidity: `setVerifier` records at contracts/VaultKernelPrototype.sol:906-918 that precisely this interlock 'was written, measured and REMOVED', because refusing the declaration while a request is live hands the quorum an unbounded veto. The requirement stands anyway — an accepted configuration transition may not silently reduce the satisfiability of an already-quorum-approved recovery — so a firing here is a FINDING (this is how SD-4 is detected), never a regression. CONSUMERS MUST NOT READ THE REMOVED INTERLOCK AS THE INTENDED SEMANTICS: a remediation that leaves the edge permitted and instead lets the quorum re-authorise the request repairs the harm while still tripping this predicate, because the predicate observes the TRANSITION and cannot observe the repair. See test/Sd4PropertyOverApproximation.test.ts and defects.ts SD-4.",
    check: (s, p) => {
      if (!p) return null;
      const wasLive =
        p.recovery.active &&
        s.blockTimestamp <= p.recovery.expiresAt &&
        p.recovery.boundGuardianGeneration === p.guardianGeneration;
      if (!wasLive) return null;
      if (!p.floor.requirePq && s.floor.requirePq) {
        return (
          "the PQ conjunct was armed while a quorum-approved recovery was still executable (proposed " +
          p.recovery.proposedSigner +
          ", expires " +
          p.recovery.expiresAt +
          ") — that request is now measured against authentication requirements which did not exist when it was approved"
        );
      }
      return null;
    },
  },
];

/**
 * Candidates CONSIDERED and REJECTED for want of a source binding. Kept because
 * a list of invariants with the rejects deleted looks complete when it is not.
 */
export const REJECTED_INVARIANTS: readonly { name: string; whyRejected: string }[] = [
  {
    name: "policyEngine always has code",
    whyRejected:
      "NOT SOURCE-BOUND. Unlike setVerifier, setPolicy performs NO code-length check, and address(0) is a legal value meaning 'no plane'. Asserting this would assert a rule the kernel does not have. The reachable configuration is exercised by an ACTION instead (setPolicy to a codeless non-zero address) and its consequence is reported, not assumed.",
  },
  {
    name: "vault native balance never decreases without an Executed or Egressed event",
    whyRejected:
      "NOT SOURCE-BOUND as a global: gas is paid by callers, not the vault, but a plain `receive()` means the balance can also RISE from any account at any time. The asset property that IS source-bound is asserted per-action instead (P-ASSET-CUT), against the specific transfer the action attempted.",
  },
  {
    name: "recovery fields are zeroed whenever active is false",
    whyRejected:
      "NOT SOURCE-BOUND. cancelRecovery sets active = false WITHOUT clearing the other fields (only executeRecovery does `delete recovery`), so stale non-zero fields alongside active == false are the kernel's DESIGNED behaviour. Asserting the stronger form would fail on correct code.",
  },
  {
    name: "guardianThreshold <= roster size",
    whyRejected:
      "NOT CHECKABLE FROM STORAGE. The kernel stores a COMMITMENT, never the roster, so the harness cannot read the roster size back on chain. _requireCanonicalRoster enforces it on every supplied preimage; there is no post-state to assert it against.",
  },
];

/**
 * G-RECOVERY-COMMITMENT-BINDS.
 *
 * THE ONE PROPERTY IN THIS LANE THAT IS A SPEC MIRROR, AND WHY.
 *
 * R1 says a recovery authorisation must not silently retarget: the possession
 * proof must be bound to the configuration the quorum actually approved. A
 * MISSING field cannot be observed behaviourally without constructing two
 * configurations that differ ONLY in that field and catching one proof
 * satisfying both — which requires the attacker to already hold a proof for a
 * configuration that no longer exists, a coincidence a random campaign will not
 * manufacture. So this property recomputes the digest from the fields the
 * ARCHITECTURE requires it to bind and compares.
 *
 * This is a deliberate, single, declared exception to the no-mirroring rule in
 * model.ts. It is sound because the expected binding comes from the REQUIREMENT
 * (the proposed signer, key, verifier, the constituency that approved it, and
 * the maturity it was approved for), not from reading the implementation: a
 * kernel that binds MORE than this still passes, and only one that binds LESS
 * fails.
 */
export async function checkRecoveryCommitment(world: World, s: KernelSnapshot): Promise<InvariantViolation[]> {
  if (!s.recovery.active) return [];
  const actual = (await world.vault.recoveryPossessionDigest()) as string;
  const expected = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "uint64", "address", "bytes32", "address", "uint64", "uint64"],
      [
        ethers.id("INCOMING_CREDENTIAL_POSSESSION"),
        world.chainId,
        world.vaultAddress,
        1n,
        s.recovery.proposedSigner,
        s.recovery.proposedPqKeyHash,
        s.recovery.proposedVerifier,
        s.recovery.boundGuardianGeneration,
        s.recovery.executableAt,
      ],
    ),
  );
  if (actual !== expected) {
    return [
      {
        name: "G-RECOVERY-COMMITMENT-BINDS",
        detail:
          "the recovery possession digest does not bind the complete approved configuration " +
          "(proposed signer, PQ key commitment, REPLACEMENT VERIFIER, approving guardian generation, maturity). " +
          "A proof made for one approved configuration would then be valid for a materially different one (R1).",
      },
    ];
  }
  return [];
}

export function checkGlobals(
  now: KernelSnapshot,
  prev: KernelSnapshot | null,
  world: World,
): InvariantViolation[] {
  const out: InvariantViolation[] = [];
  for (const inv of GLOBAL_INVARIANTS) {
    const detail = inv.check(now, prev, world);
    if (detail !== null) out.push({ name: inv.name, detail });
  }
  return out;
}
