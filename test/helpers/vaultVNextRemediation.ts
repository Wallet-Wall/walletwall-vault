/**
 * WalletWall Vault vNext — remediation sub-models.
 *
 * WHY THIS IS A SEPARATE MODULE, AND NOT MORE OF `vaultVNextModel.ts`
 * ------------------------------------------------------------------
 * The three models below are pure, self-contained, and share no state with the
 * vault state machine. Keeping them separate is not tidiness — it is what makes
 * their mutants ATTRIBUTABLE. A mutation planted in the crypto lattice cannot be
 * accidentally killed by the vault model's fixture setup, and vice versa, because
 * neither can reach the other's state. That is the same discipline the vacuity
 * guard enforces within a model, applied across models.
 *
 * SCOPE OF THE PROOF — read this before citing anything here
 * ----------------------------------------------------------
 * Identical to `vaultVNextModel.ts`: these establish that a named set of rules is
 * COHERENT and DISCRIMINATING. They establish NOTHING about any Solidity.
 *
 * They additionally establish nothing about properties this representation cannot
 * express. That set is not empty and is enumerated rather than glossed:
 *   - bytecode shape, EXTCODEHASH, EIP-1167 template equality, immutable slots;
 *   - gas, calldata cost, memory expansion, the EIP-150 63/64 rule;
 *   - transaction ordering, front-running, reorgs;
 *   - a chain's fork level (on which EIP-6780 immutability depends).
 * Invariants that depend on those are tagged IMPLEMENTATION-LANE or OBSERVATORY in
 * docs/Vault_vNext_Architecture.md section 16 and carry NO assurance from this PR.
 * `CodeIdentityChain` below models the SHAPE of the evidence chain — which facts
 * must be obtained, from where, and in what order — never the bytes themselves.
 */

// ---------------------------------------------------------------------------
// Shared outcome type (structurally like the vault model's, kept local so this
// module has no import cycle with it)
// ---------------------------------------------------------------------------

export type SubOutcome = { readonly ok: true } | { readonly ok: false; readonly reason: string };

export const allow = (): SubOutcome => ({ ok: true });
export const refuse = (reason: string): SubOutcome => ({ ok: false, reason });

// ---------------------------------------------------------------------------
// Mutations for the remediation sub-models
// ---------------------------------------------------------------------------

/** Each disables exactly ONE guard, so a kill is attributable to one rule. */
export type RemediationMutation =
  | "M32_PROFILE_SUMMARY_IS_MAX_OVER_CLAUSES"
  | "M33_CLAUSE_COVERING_QUANTIFIER_FLIPPED"
  | "M34_CROSS_FAMILY_DOMINANCE_PERMITTED"
  | "M35_INDEPENDENCE_ROOTS_MAY_DECREASE"
  | "M36_ANCHORED_FACTOR_NOT_REQUIRED"
  | "M37_DISALLOWED_MAY_BE_REACTIVATED"
  | "M38_INCOMPARABLE_TRANSITIONS_PERMITTED"
  | "M39_ENTRY_FAILURE_ABORTS_EVERYTHING"
  | "M40_BINDING_FIXES_AMOUNTS_NOT_DISPOSITION"
  | "M41_RETIRED_CLOSES_EGRESS"
  | "M42_ABANDONED_IS_ABSORBING"
  | "M43_BIND_DELAY_BELOW_RECOVERY_DELAY"
  | "M44_EGRESS_RECIPIENT_FROM_CALLER"
  | "M45_SETTLEMENT_ON_NON_REVERT"
  | "M46_IMPL_ADDRESS_FROM_REGISTRY"
  | "M47_CLONE_MATCHED_BY_PREFIX"
  | "M48_IDENTITIES_PUBLISHED_AS_ONE_AGGREGATE"
  | "M49_IMPL_VACUITY_UNCHECKED"
  // --- added by the final architecture-correction pass ---
  | "M50_INITCODE_JUDGED_AGAINST_RUNTIME_LIMIT"
  | "M51_PORTABILITY_BUDGET_TRACKS_THE_NETWORK"
  | "M52_UNSOLICITED_ASSET_VETOES_MANIFESTED_EGRESS"
  | "M53_RETIREMENT_REQUIRES_GLOBAL_ZERO_BALANCE"
  | "M54_BUILD_IDENTITY_USED_AS_DEPLOYMENT_IDENTITY"
  | "M55_MASK_WITHOUT_REDERIVATION"
  | "M56_FACTORY_IMPLEMENTATION_RETARGETABLE"
  | "M57_BOUNDED_CHALLENGE_COUNTED_AS_A_CUT";

// ===========================================================================
// 1. SecurityProfile — a PARTIAL order over heterogeneous crypto assumptions
// ===========================================================================

/**
 * The assumption family a factor rests on. Comparison is meaningful WITHIN a
 * family and undefined ACROSS families; encoding that as a union rather than as
 * a number is what stops a scalar from inventing an order that does not exist.
 */
export type AuthFamily = "CLASSICAL_ECC" | "PQ_LATTICE" | "PQ_HASH" | "HARDWARE";

export type SchemeStatusV2 = "ACTIVE" | "DEPRECATED" | "DISALLOWED";

export interface Factor {
  readonly schemeId: string;
  readonly family: AuthFamily;
  /** Within-family level ONLY. ML-DSA-44 < -65 < -87 does not leave the family. */
  readonly paramLevel: number;
  /**
   * The independence ROOT. Two factors sharing a rootTag are ONE root however
   * different their algorithms — same seed, same HSM, same vendor. Modelled as
   * data because "independent" is an assumption, not a property of a name.
   */
  readonly rootTag: string;
  readonly verifierGeneration: number;
  /** True iff this factor's possession test is evaluated by the kernel itself. */
  readonly anchored: boolean;
}

/**
 * A profile is a DISJUNCTION of clauses; each clause is a CONJUNCTION of factors.
 * A clause is a complete path to authority on its own, which is exactly why the
 * anchoring requirement is applied clause-wise and never profile-wise.
 */
export interface SecurityProfile {
  readonly clauses: readonly (readonly Factor[])[];
}

export class CryptoLattice {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();
  private readonly status = new Map<string, SchemeStatusV2>();

  constructor(mutations: readonly RemediationMutation[] = []) {
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  setStatus(schemeId: string, next: SchemeStatusV2): SubOutcome {
    this.mark("lattice/status-transition");
    const current = this.status.get(schemeId) ?? "ACTIVE";
    if (current === "DISALLOWED" && next !== "DISALLOWED" && !this.has("M37_DISALLOWED_MAY_BE_REACTIVATED")) {
      return refuse("DISALLOWED is absorbing");
    }
    this.status.set(schemeId, next);
    return allow();
  }

  statusOf(schemeId: string): SchemeStatusV2 {
    return this.status.get(schemeId) ?? "ACTIVE";
  }

  /**
   * Distinct independence roots in ONE clause. This is the number that must not
   * decrease — never the factor count, which two correlated schemes inflate.
   */
  rootsOfClause(clause: readonly Factor[]): number {
    this.mark("lattice/roots-of-clause");
    return new Set(clause.map((f) => f.rootTag)).size;
  }

  /**
   * A profile's independence is the MINIMUM over its clauses, because an attacker
   * takes the cheapest disjunct. Taking the maximum reports the strength of the
   * best path while the attacker walks the worst — precisely the defect in the
   * withdrawn scalar rule, which summarised by MAX over ACTIVE schemes.
   */
  minRoots(profile: SecurityProfile): number {
    this.mark("lattice/profile-aggregate");
    const perClause = profile.clauses.map((c) => this.rootsOfClause(c));
    if (perClause.length === 0) return 0;
    return this.has("M32_PROFILE_SUMMARY_IS_MAX_OVER_CLAUSES") ? Math.max(...perClause) : Math.min(...perClause);
  }

  /** Every clause must carry at least one kernel-evaluable possession test. */
  everyClauseAnchored(profile: SecurityProfile): boolean {
    this.mark("lattice/anchored-factor");
    if (this.has("M36_ANCHORED_FACTOR_NOT_REQUIRED")) return true;
    return profile.clauses.every((c) => c.some((f) => f.anchored));
  }

  /** Within-family dominance only. There is no cross-family edge, ever. */
  private factorDominates(candidate: Factor, incumbent: Factor): boolean {
    this.mark("lattice/factor-dominance");
    const sameFamily = this.has("M34_CROSS_FAMILY_DOMINANCE_PERMITTED") ? true : candidate.family === incumbent.family;
    return (
      sameFamily &&
      candidate.paramLevel >= incumbent.paramLevel &&
      candidate.verifierGeneration >= incumbent.verifierGeneration
    );
  }

  clauseDominates(candidate: readonly Factor[], incumbent: readonly Factor[]): boolean {
    this.mark("lattice/clause-dominance");
    return incumbent.every((i) => candidate.some((c) => this.factorDominates(c, i)));
  }

  /**
   * The covering test in the ONLY safe quantifier direction: every NEW clause
   * must dominate some OLD clause. The reverse direction ("every old clause is
   * covered by some new one") lets a WEAK ALTERNATIVE be added while every old
   * clause stays covered — a silent downgrade that reads as an upgrade.
   */
  covers(oldProfile: SecurityProfile, newProfile: SecurityProfile): boolean {
    this.mark("lattice/covering");
    if (this.has("M33_CLAUSE_COVERING_QUANTIFIER_FLIPPED")) {
      return oldProfile.clauses.every((o) => newProfile.clauses.some((n) => this.clauseDominates(n, o)));
    }
    return newProfile.clauses.every((n) => oldProfile.clauses.some((o) => this.clauseDominates(n, o)));
  }

  /**
   * The transition relation. PARTIAL by construction: profiles where neither
   * dominates the other are REFUSED, because unknown must close to deny and a
   * refusal is recoverable while a permission is not.
   */
  transitionAllowed(oldProfile: SecurityProfile, newProfile: SecurityProfile): SubOutcome {
    this.mark("lattice/transition");

    for (const clause of newProfile.clauses) {
      for (const f of clause) {
        if (this.statusOf(f.schemeId) === "DISALLOWED") {
          return refuse("profile contains a DISALLOWED scheme");
        }
      }
    }
    if (!this.everyClauseAnchored(newProfile)) {
      return refuse("a clause has no kernel-evaluable possession test");
    }
    if (!this.covers(oldProfile, newProfile)) {
      if (this.has("M38_INCOMPARABLE_TRANSITIONS_PERMITTED")) return allow();
      return refuse("new profile does not dominate the old one (weaker or incomparable)");
    }
    // Marked OUTSIDE the conditional: a mutation that DELETES a check must still
    // record that the check was reached, or the vacuity guard cannot tell
    // "the rule was removed" from "the scenario never got here".
    this.mark("lattice/independence");
    if (!this.has("M35_INDEPENDENCE_ROOTS_MAY_DECREASE")) {
      if (this.minRoots(newProfile) < this.minRoots(oldProfile)) {
        return refuse("independent-root count decreased");
      }
    }
    return allow();
  }
}

// --- Canonical factors and profiles used by the suite and by the document ----

export const ECDSA: Factor = {
  schemeId: "ECDSA_SECP256K1",
  family: "CLASSICAL_ECC",
  paramLevel: 1,
  rootTag: "root/user-seed",
  verifierGeneration: 1,
  anchored: true,
};

export const ML_DSA_65: Factor = {
  schemeId: "ML_DSA_65",
  family: "PQ_LATTICE",
  paramLevel: 3,
  rootTag: "root/pq-key",
  verifierGeneration: 1,
  anchored: false,
};

export const ML_DSA_87: Factor = { ...ML_DSA_65, schemeId: "ML_DSA_87", paramLevel: 5 };

/** Same algorithm as ECDSA, but rooted in the SAME secret as the PQ key. */
export const ECDSA_CORRELATED: Factor = {
  ...ECDSA,
  schemeId: "ECDSA_SECP256K1_CORRELATED",
  rootTag: "root/pq-key",
};

export const HYBRID: SecurityProfile = { clauses: [[ECDSA, ML_DSA_65]] };
export const HYBRID_87: SecurityProfile = { clauses: [[ECDSA, ML_DSA_87]] };
export const PQ_ONLY_87: SecurityProfile = { clauses: [[ML_DSA_87]] };
export const ECDSA_ONLY: SecurityProfile = { clauses: [[ECDSA]] };
/** Hybrid with a bare-ECDSA escape hatch bolted on: the OR that must be refused. */
export const HYBRID_OR_ECDSA: SecurityProfile = { clauses: [[ECDSA, ML_DSA_65], [ECDSA]] };
/** Two factors, one root. Looks like 2FA; is 1FA. */
export const CORRELATED_PAIR: SecurityProfile = { clauses: [[ECDSA_CORRELATED, ML_DSA_65]] };

// ===========================================================================
// 2. Migration — a manifest state machine that must never trap assets
// ===========================================================================

/**
 * Asset behaviours the migration must survive. These are DATA, not exceptions,
 * for the same reason PlaneHealth is: "reverts" and "returns false" have
 * different consequences and collapsing them into "failed" erases the finding.
 */
export type AssetKind =
  | "ETH"
  | "ETH_FORCED"
  | "ERC20_WELL_BEHAVED"
  | "ERC20_RETURNS_FALSE"
  | "ERC20_REVERTS"
  | "ERC20_FEE_ON_TRANSFER"
  | "ERC721"
  | "ERC1155"
  | "ERC20_REENTRANT";

export type EntryStatus = "PENDING" | "MOVED" | "FAILED" | "ABANDONED";

export type MigrationState = "NORMAL" | "BOUND" | "RETIRED";

export interface Binding {
  readonly destinationVault: string;
  /** EXTCODEHASH of the destination VAULT, never of the implementation it delegates to. */
  readonly destinationVaultCodeHash: string;
  readonly destinationGeneration: number;
  readonly chainId: number;
  readonly nonce: number;
  readonly deadline: number;
  /**
   * FULL_BALANCE, never an amount. Binding an amount cannot be satisfied by a
   * fee-on-transfer or rebasing token and cannot cover an asset that arrives
   * after preparation.
   */
  readonly disposition: "FULL_BALANCE";
}

/**
 * How an asset came to be in the vault. This is BOOKKEEPING, never an
 * authorization input: `I-MIGRATION-NONTRAP` clause (b) requires an UNSOLICITED
 * asset to be egressable on exactly the same terms as a MANIFESTED one. The
 * dimension exists so the model can express the thing architecture section 13.0a
 * proves cannot be prevented — an asset arriving with no function call, or after
 * the manifest was bound — and so a mutant can try to let it veto the others.
 */
export type EntryOrigin = "MANIFESTED" | "UNSOLICITED";

export interface Entry {
  readonly assetId: string;
  readonly kind: AssetKind;
  readonly origin: EntryOrigin;
  status: EntryStatus;
  /** Present so settlement can be judged on an OBSERVED balance change. */
  sourceBalance: bigint;
}

export const RECOVERY_DELAY_DAYS = 7;
export const BIND_DELAY_DAYS = 7;

export class MigrationMachine {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();

  state: MigrationState = "NORMAL";
  binding: Binding | null = null;
  boundAt: number | null = null;
  clock = 0;
  pendingRecovery = false;
  readonly entries = new Map<string, Entry>();

  constructor(mutations: readonly RemediationMutation[] = []) {
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  warp(days: number): void {
    this.clock += days;
  }

  addAsset(assetId: string, kind: AssetKind, balance: bigint, origin: EntryOrigin = "MANIFESTED"): void {
    this.entries.set(assetId, { assetId, kind, origin, status: "PENDING", sourceBalance: balance });
  }

  /**
   * An asset nobody asked for: a direct ERC-20 transfer, forced ETH, an airdrop,
   * a rebase, or anything that arrived AFTER binding. It needs no call into the
   * vault, so no ingress gate can refuse it (architecture section 13.0a).
   */
  receiveUnsolicited(assetId: string, kind: AssetKind, balance: bigint): void {
    this.addAsset(assetId, kind, balance, "UNSOLICITED");
  }

  /** The bind delay must never be shorter than the recovery delay. */
  bindDelay(): number {
    this.mark("migration/bind-delay");
    return this.has("M43_BIND_DELAY_BELOW_RECOVERY_DELAY") ? RECOVERY_DELAY_DAYS - 1 : BIND_DELAY_DAYS;
  }

  /**
   * Bind requires guardian quorum AND credential authority, and is blocked while
   * a recovery is pending so migration can never front-run the remedy.
   */
  bind(byQuorum: boolean, byCredential: boolean, binding: Binding): SubOutcome {
    this.mark("migration/bind");
    if (this.state === "RETIRED") return refuse("terminal: no new binding");
    if (!byQuorum || !byCredential) return refuse("binding requires guardian quorum AND credential authority");
    if (this.pendingRecovery) return refuse("a recovery is pending");
    if (binding.deadline <= this.clock) return refuse("deadline in the past");
    if (binding.destinationVaultCodeHash === "") return refuse("destination vault code hash required");
    if (this.has("M40_BINDING_FIXES_AMOUNTS_NOT_DISPOSITION")) {
      // Mutant: freeze the asset set and its amounts at binding time.
      this.frozenAssetIds = new Set(this.entries.keys());
    }
    this.binding = binding;
    this.boundAt = this.clock;
    this.state = "BOUND";
    return allow();
  }

  private frozenAssetIds: Set<string> | null = null;

  retire(): SubOutcome {
    this.mark("migration/retire");
    if (this.state !== "BOUND") return refuse("nothing bound");
    if (this.boundAt === null || this.clock < this.boundAt + this.bindDelay()) return refuse("bind delay not elapsed");

    // I-MIGRATION-NONTRAP clause (c): retirement is conditioned on AUTHORITY, never
    // on global asset exhaustion. "Balance is zero across every possible token" is
    // not a decidable predicate — the set of contracts that may name this address
    // is unbounded, and a rebasing token can reintroduce a balance with no
    // transaction at all. A design that waits for the last token waits forever.
    this.mark("migration/retirement-condition");
    if (this.has("M53_RETIREMENT_REQUIRES_GLOBAL_ZERO_BALANCE")) {
      for (const e of this.entries.values()) {
        if (e.sourceBalance > 0n) return refuse("a token still holds a non-zero balance");
      }
    }

    this.state = "RETIRED";
    return allow();
  }

  /**
   * True iff an asset class's transfer would revert. Separate from
   * `returnsFalseWithoutReverting` so the two are never conflated.
   */
  private transferReverts(kind: AssetKind): boolean {
    return kind === "ERC20_REVERTS";
  }

  private returnsFalseWithoutReverting(kind: AssetKind): boolean {
    return kind === "ERC20_RETURNS_FALSE";
  }

  /**
   * Move ONE asset class to the BOUND destination. Permissionless, because it
   * carries no discretion: the recipient comes from the binding and the amount
   * is the whole balance. `requestedRecipient` exists ONLY so a mutant can try
   * to honour it; the clean model must ignore it entirely.
   */
  egress(assetId: string, requestedRecipient?: string): SubOutcome {
    this.mark("migration/egress");
    if (this.binding === null) return refuse("no binding");

    if (this.has("M41_RETIRED_CLOSES_EGRESS") && this.state === "RETIRED") {
      this.mark("migration/egress-in-terminal-state");
      return refuse("terminal state closes egress");
    }
    this.mark("migration/egress-in-terminal-state");

    const entry = this.entries.get(assetId);
    if (entry === undefined) return refuse("unknown asset");

    // I-MIGRATION-NONTRAP clause (a): an asset the vault never agreed to hold is
    // INSIDE the vault but is a gate on NOTHING. Whatever it does — revert,
    // rebase, blacklist the source — every other entry still reaches the bound
    // destination on its own.
    this.mark("migration/unsolicited-nonveto");
    if (this.has("M52_UNSOLICITED_ASSET_VETOES_MANIFESTED_EGRESS")) {
      for (const other of this.entries.values()) {
        if (other.assetId === assetId) continue;
        if (other.origin === "UNSOLICITED" && other.status !== "MOVED") {
          return refuse("an unsolicited asset is unresolved");
        }
      }
    }

    if (this.frozenAssetIds !== null && !this.frozenAssetIds.has(assetId)) {
      // Mutant M40: an asset that arrived after binding is not in the bound set.
      return refuse("asset not in the bound set");
    }
    if (this.has("M42_ABANDONED_IS_ABSORBING") && entry.status === "ABANDONED") {
      this.mark("migration/retry-from-abandoned");
      return refuse("abandoned is terminal for this entry");
    }
    this.mark("migration/retry-from-abandoned");
    if (entry.status === "MOVED") return allow();

    const recipient = this.has("M44_EGRESS_RECIPIENT_FROM_CALLER")
      ? (requestedRecipient ?? this.binding.destinationVault)
      : this.binding.destinationVault;
    this.mark("migration/recipient-source");
    this.lastRecipient = recipient;

    if (this.transferReverts(entry.kind)) {
      if (this.has("M39_ENTRY_FAILURE_ABORTS_EVERYTHING")) {
        // Mutant: one failing entry aborts everything and rolls the rest back.
        this.mark("migration/entry-isolation");
        for (const e of this.entries.values()) if (e.status === "MOVED") e.status = "PENDING";
        this.aborted = true;
        return refuse("a transfer failed: whole migration aborted");
      }
      this.mark("migration/entry-isolation");
      entry.status = "FAILED";
      return refuse("this entry's transfer reverted");
    }
    this.mark("migration/entry-isolation");

    // Settlement is judged on an OBSERVED balance decrease, never on "the call
    // did not revert" — which is exactly what a token returning false does.
    const before = entry.sourceBalance;
    const moved = this.returnsFalseWithoutReverting(entry.kind) ? 0n : before;
    entry.sourceBalance = before - moved;

    if (this.has("M45_SETTLEMENT_ON_NON_REVERT")) {
      this.mark("migration/settlement-evidence");
      entry.status = "MOVED";
      return allow();
    }
    this.mark("migration/settlement-evidence");
    if (entry.sourceBalance < before || before === 0n) {
      entry.status = "MOVED";
      return allow();
    }
    entry.status = "FAILED";
    return refuse("no observed decrease in the source balance");
  }

  lastRecipient: string | null = null;
  aborted = false;

  /** Bookkeeping only. It must never remove the ability to retry (M42). */
  abandon(assetId: string): SubOutcome {
    this.mark("migration/abandon");
    const entry = this.entries.get(assetId);
    if (entry === undefined) return refuse("unknown asset");
    if (entry.status === "MOVED") return refuse("already resolved");
    entry.status = "ABANDONED";
    return allow();
  }

  /**
   * The non-trap predicate: every asset the vault holds either left, or still has
   * a reachable path out. "Reachable" means egress can still be attempted at all.
   */
  everyAssetHasAnExit(): boolean {
    this.mark("migration/nontrap");
    if (this.aborted) return false;
    for (const entry of this.entries.values()) {
      if (entry.status === "MOVED") continue;
      if (this.egress(entry.assetId).ok) continue;
      // A refusal is only acceptable if the CAUSE is the asset itself refusing,
      // not the protocol having closed the door.
      const assetRefusedItself = this.transferReverts(entry.kind);
      if (!assetRefusedItself) return false;
    }
    return true;
  }

  /**
   * `I-MIGRATION-NONTRAP` clause (a), stated as its own predicate because the
   * general non-trap check above cannot distinguish "this asset refused" from
   * "another asset's presence refused on its behalf" — and that distinction is
   * the entire content of architecture section 13.0a.
   *
   * True iff every MANIFESTED entry that is independently recoverable does in
   * fact leave, in the presence of whatever unsolicited assets the vault holds.
   */
  manifestedEntriesExitIndependently(): boolean {
    this.mark("migration/manifested-independence");
    for (const entry of this.entries.values()) {
      if (entry.origin !== "MANIFESTED") continue;
      if (entry.status === "MOVED") continue;
      // An asset that refuses on its OWN behalf is an accepted residual
      // (section 13.4); anything else refusing for it is a trap.
      if (this.transferReverts(entry.kind)) continue;
      if (!this.egress(entry.assetId).ok) return false;
    }
    return true;
  }
}

// ===========================================================================
// 2a. Deployment size — FOUR quantities, never conflated (architecture 19.0)
// ===========================================================================

/**
 * A concrete deployment environment. `runtimeLimit` and `initcodeLimit` are
 * SEPARATE and are set by the NETWORK, per fork — which is why they are fields
 * on a target rather than module constants. A model with one global "EIP-170"
 * constant cannot express a portfolio of chains at different forks, and cannot
 * detect the category error this sub-model exists to discriminate.
 */
export interface DeploymentTarget {
  readonly chain: string;
  readonly fork: string;
  readonly runtimeLimit: number;
  readonly initcodeLimit: number;
}

/** What a compiler produces: two independent sizes governed by two different rules. */
export interface CompiledArtifact {
  readonly runtime: number;
  readonly initcode: number;
}

export class SizeModel {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();

  constructor(mutations: readonly RemediationMutation[] = []) {
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  /**
   * Can this artifact be deployed on this target?
   *
   * The rule that matters, and the one the architecture document got wrong:
   * initcode is judged against `initcodeLimit` and NEVER against `runtimeLimit`.
   * `initcode > runtimeLimit` is not a deployment event of any kind.
   */
  deployable(target: DeploymentTarget, artifact: CompiledArtifact): SubOutcome {
    this.mark("size/runtime-bound");
    if (artifact.runtime > target.runtimeLimit) {
      return refuse(`runtime ${artifact.runtime} exceeds ${target.chain} runtime limit ${target.runtimeLimit}`);
    }

    this.mark("size/initcode-bound");
    const initcodeBound = this.has("M50_INITCODE_JUDGED_AGAINST_RUNTIME_LIMIT")
      ? target.runtimeLimit
      : target.initcodeLimit;
    if (artifact.initcode > initcodeBound) {
      return refuse(`initcode ${artifact.initcode} exceeds bound ${initcodeBound}`);
    }
    return allow();
  }

  /**
   * The WalletWall portability budget is bounded by the SMALLEST runtime limit
   * across declared targets. A budget that tracks the LARGEST is not a budget:
   * it certifies a kernel as portable on the strength of the one chain that
   * raised its limit, while the chain that did not raise it still refuses it.
   */
  portabilityBudget(targets: readonly DeploymentTarget[]): number {
    this.mark("size/budget-aggregate");
    const limits = targets.map((t) => t.runtimeLimit);
    return this.has("M51_PORTABILITY_BUDGET_TRACKS_THE_NETWORK") ? Math.max(...limits) : Math.min(...limits);
  }

  /** A WalletWall POLICY check, deliberately distinct from `deployable`. */
  withinPortabilityBudget(targets: readonly DeploymentTarget[], artifact: CompiledArtifact): SubOutcome {
    this.mark("size/portability");
    const budget = this.portabilityBudget(targets);
    return artifact.runtime > budget
      ? refuse(`runtime ${artifact.runtime} exceeds portability budget ${budget}`)
      : allow();
  }

  /** Headroom the project withholds from itself. Never a protocol quantity. */
  targetCeiling(targets: readonly DeploymentTarget[], internalReserve: number): number {
    this.mark("size/internal-reserve");
    return this.portabilityBudget(targets) - internalReserve;
  }
}

// ===========================================================================
// 2b. Factory generation authority — owner decision D8
// ===========================================================================

/**
 * ONE IMMUTABLE FACTORY PER KERNEL GENERATION. The implementation choice is
 * consumed at construction; thereafter no principal — including the deployer —
 * can retarget it. The model exists so the ABSENCE of the authority is asserted
 * positively rather than left as a gap in the graph.
 */
export class FactoryGenerationModel {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();

  private implementation: string;
  readonly generation: number;

  constructor(implementation: string, generation: number, mutations: readonly RemediationMutation[] = []) {
    this.implementation = implementation;
    this.generation = generation;
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  implementationTarget(): string {
    return this.implementation;
  }

  /**
   * The rejected alternative, present ONLY so a mutant can enable it. Every
   * spelling of it — `setImplementation`, `upgradeFactory`, `registerNewKernel`
   * on an existing generation, a beacon, a mutable registry — is the same
   * capability, and the clean model refuses all of them identically.
   */
  setImplementation(next: string): SubOutcome {
    this.mark("factory/retarget");
    if (this.has("M56_FACTORY_IMPLEMENTATION_RETARGETABLE")) {
      this.implementation = next;
      return allow();
    }
    return refuse("the implementation target is immutable: deploy a new factory generation");
  }

  /**
   * A new generation is a DEPLOYMENT, not a permission: it produces a second,
   * independent factory and leaves this one untouched.
   */
  nextGeneration(nextImplementation: string): FactoryGenerationModel {
    this.mark("factory/generation-is-a-deployment");
    return new FactoryGenerationModel(nextImplementation, this.generation + 1, [...this.mutations]);
  }

  /** The property D8 buys: an attempted retarget changes nothing. */
  implementationIsImmutable(): boolean {
    const before = this.implementation;
    const attempt = this.setImplementation(before + "-ATTACKER");
    this.mark("factory/immutability");
    return !attempt.ok && this.implementation === before;
  }
}

// ===========================================================================
// 2c. Authority cuts — a delay is not a principal (owner decision D1)
// ===========================================================================

/**
 * A path to a catastrophic outcome. The ONLY input to a compromise cut is how
 * many INDEPENDENT principals are MANDATORY on the path. Delays, challenges and
 * timelocks are recorded separately precisely so they cannot be quietly summed
 * into the cut.
 */
export interface AttackPath {
  readonly name: string;
  readonly mandatoryIndependentPrincipals: number;
  /** Bounded challenges the attacker must outlast. Costs TIME, never a root. */
  readonly boundedChallenges: number;
}

export class AuthorityCutModel {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();

  constructor(mutations: readonly RemediationMutation[] = []) {
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  cut(path: AttackPath): number {
    this.mark("cuts/delay-is-not-a-principal");
    const delayBonus = this.has("M57_BOUNDED_CHALLENGE_COUNTED_AS_A_CUT") && path.boundedChallenges > 0 ? 1 : 0;
    return path.mandatoryIndependentPrincipals + delayBonus;
  }

  /** The minimum over paths — a system is as strong as its cheapest path. */
  systemCut(paths: readonly AttackPath[]): number {
    this.mark("cuts/minimum-over-paths");
    return Math.min(...paths.map((p) => this.cut(p)));
  }
}

// ===========================================================================
// 3. Code identity — a CHAIN of facts, not a hash
// ===========================================================================

/**
 * What an offline observer can actually obtain. Deliberately modelled as a
 * lookup keyed by ADDRESS, so that "hash the account you were pointed at" and
 * "read the identity from a registry" are DIFFERENT operations in the model —
 * which is the whole point of I-CODE-IDENTITY-LINKAGE.
 */
export interface ChainView {
  /** address -> its runtime code, as an opaque token. "" means no code. */
  readonly code: ReadonlyMap<string, string>;
}

/** A registry is a CLAIM, never evidence. Modelled so a mutant can trust it. */
export interface Registry {
  readonly claimedImplementationFor: ReadonlyMap<string, string>;
  readonly generationOfImplCode: ReadonlyMap<string, number>;
}

export type IdentityKind = "PROOF" | "OBSERVATION";

export interface PublishedIdentity {
  readonly name: string;
  readonly kind: IdentityKind;
  readonly value: string;
  /** OBSERVATIONs whose value can change with NO transaction need a valid-until. */
  readonly validUntil: number | null;
}

export const EMPTY_CODE_TOKEN = "";
export const CLONE_TEMPLATE_PREFIX = "1167:";

/** A canonical clone's code token: template prefix, implementation, exact length. */
export function cloneCode(implementation: string, args = ""): string {
  return `${CLONE_TEMPLATE_PREFIX}${implementation}${args === "" ? "" : `+args:${args}`}`;
}

export class CodeIdentityChain {
  private readonly mutations: ReadonlySet<RemediationMutation>;
  readonly exercised = new Set<string>();

  constructor(mutations: readonly RemediationMutation[] = []) {
    this.mutations = new Set(mutations);
  }

  private has(m: RemediationMutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  /**
   * Link 1 -> 2. The implementation address MUST be extracted from the OBSERVED
   * clone bytes. Taking it from a registry verifies a claim against itself.
   */
  implementationOf(view: ChainView, registry: Registry, clone: string): string | null {
    this.mark("identity/linkage");
    if (this.has("M46_IMPL_ADDRESS_FROM_REGISTRY")) {
      return registry.claimedImplementationFor.get(clone) ?? null;
    }
    const code = view.code.get(clone) ?? EMPTY_CODE_TOKEN;
    if (!code.startsWith(CLONE_TEMPLATE_PREFIX)) return null;
    return code.slice(CLONE_TEMPLATE_PREFIX.length).split("+args:")[0] ?? null;
  }

  /**
   * Link 1. Byte-exactness, not prefix matching. A "superset proxy" contains the
   * template AND extra dispatch that runs first; a prefix test accepts it.
   */
  cloneShapeIsCanonical(view: ChainView, clone: string, expectedImplementation: string): boolean {
    this.mark("identity/clone-exactness");
    const code = view.code.get(clone) ?? EMPTY_CODE_TOKEN;
    const canonical = cloneCode(expectedImplementation);
    if (this.has("M47_CLONE_MATCHED_BY_PREFIX")) {
      return code.startsWith(CLONE_TEMPLATE_PREFIX) && code.includes(expectedImplementation);
    }
    return code === canonical;
  }

  /**
   * Link 3. A clone pointing at a codeless address delegates into nothing: every
   * call returns success with empty returndata, which a naive checker reads as OK.
   */
  implementationIsNonVacuous(view: ChainView, implementation: string): boolean {
    this.mark("identity/impl-nonvacuity");
    if (this.has("M49_IMPL_VACUITY_UNCHECKED")) return true;
    const code = view.code.get(implementation);
    return code !== undefined && code !== EMPTY_CODE_TOKEN;
  }

  /**
   * The whole chain. Every link is obtained from the link before it, and each is
   * an independent fact. Returns false if ANY link fails.
   */
  chainHolds(
    view: ChainView,
    registry: Registry,
    clone: string,
    expected: { implementation: string; implementationCode: string; generation: number },
  ): boolean {
    this.mark("identity/chain");
    if (!this.cloneShapeIsCanonical(view, clone, expected.implementation)) return false;
    const impl = this.implementationOf(view, registry, clone);
    if (impl === null || impl !== expected.implementation) return false;
    if (!this.implementationIsNonVacuous(view, impl)) return false;
    const implCode = view.code.get(impl) ?? EMPTY_CODE_TOKEN;
    if (implCode !== expected.implementationCode) return false;
    const generation = registry.generationOfImplCode.get(implCode);
    return generation === expected.generation;
  }

  /**
   * The Observatory publishes SEPARATE typed identities. One aggregate cannot
   * fail partially, which is the failure mode that matters, and it mixes facts
   * of different epistemic kinds into a single undifferentiated badge.
   */
  publish(identities: readonly PublishedIdentity[]): readonly PublishedIdentity[] {
    this.mark("identity/publication-shape");
    if (this.has("M48_IDENTITIES_PUBLISHED_AS_ONE_AGGREGATE")) {
      return [
        {
          name: "aggregate",
          kind: "PROOF",
          value: identities.map((i) => i.value).join("|"),
          validUntil: null,
        },
      ];
    }
    return identities;
  }

  /** Every OBSERVATION that can change with no transaction needs a valid-until. */
  publicationIsWellTyped(published: readonly PublishedIdentity[]): boolean {
    this.mark("identity/typing");
    if (published.length === 1 && published[0]?.name === "aggregate") return false;
    return published.every((i) => (i.name === "safeState" ? i.kind === "OBSERVATION" && i.validUntil !== null : true));
  }

  // -------------------------------------------------------------------------
  // The THREE identities (architecture 15.1a). This NARROWS the earlier claim
  // that "there is no publishable kernel code hash" — it does NOT weaken the
  // five-link chain above, which is untouched.
  // -------------------------------------------------------------------------

  /**
   * A deployed implementation. `runtime` is what `eth_getCode` actually returns
   * at `address`, immutables and all — an AUTHORITATIVE fact about THIS account.
   */
  deploymentIdentity(address: string, runtime: string): DeploymentIdentity {
    this.mark("identity/deployment-identity");
    return { address, runtime };
  }

  /**
   * Compare a DEPLOYMENT identity to a BUILD identity.
   *
   * With NO declared immutable ranges the two coincide and this is a plain hash
   * comparison — which is the state `I-PURE-CONSTRUCTOR` exists to reach.
   *
   * With ranges declared it is a TWO-step check and both steps are load-bearing:
   *   (1) MASK the declared ranges and compare the remainder to the build's
   *       normalized runtime;
   *   (2) independently RE-DERIVE each masked word from the deployment address.
   * Step (1) alone discards exactly the bytes an attacker would choose.
   */
  matchesBuild(build: BuildIdentity, deployment: DeploymentIdentity): boolean {
    this.mark("identity/build-vs-deployment");

    if (this.has("M54_BUILD_IDENTITY_USED_AS_DEPLOYMENT_IDENTITY")) {
      // Mutant: assume ONE universal source-level runtime hash is valid at every
      // address. Rejects a CORRECT implementation whenever immutables are baked.
      return deployment.runtime === build.normalizedRuntime;
    }

    if (build.immutableRanges.length === 0) {
      return deployment.runtime === build.normalizedRuntime;
    }

    const masked = maskImmutablePayload(deployment.runtime);
    if (masked !== build.normalizedRuntime) return false;

    this.mark("identity/rederivation");
    if (this.has("M55_MASK_WITHOUT_REDERIVATION")) {
      // Mutant: mask and stop. A forged immutable payload now passes, because the
      // only bytes that could have revealed it were the ones just discarded.
      return true;
    }
    return immutablePayloadOf(deployment.runtime) === expectedPayloadFor(deployment.address);
  }
}

/**
 * SOURCE / BUILD identity: source + compiler + settings, plus the immutable
 * ranges that build DECLARES. Constant across every deployment of that build.
 */
export interface BuildIdentity {
  readonly buildTuple: string;
  readonly immutableRanges: readonly (readonly [number, number])[];
  /** The artifact's runtime with every declared immutable range zeroed. */
  readonly normalizedRuntime: string;
}

/** DEPLOYMENT identity: one address, and the runtime code actually at it. */
export interface DeploymentIdentity {
  readonly address: string;
  readonly runtime: string;
}

/**
 * Runtime code is modelled as `<body>|imm:<payload>` — SHAPE, never bytes. The
 * module header's scope note applies: this represents which facts must be
 * obtained and in what order, and represents no bytecode.
 */
export const IMMUTABLE_PAYLOAD_SEPARATOR = "|imm:";
export const ZERO_PAYLOAD = "0";

export function runtimeWithImmutables(body: string, payload: string): string {
  return `${body}${IMMUTABLE_PAYLOAD_SEPARATOR}${payload}`;
}

export function immutablePayloadOf(runtime: string): string {
  const i = runtime.indexOf(IMMUTABLE_PAYLOAD_SEPARATOR);
  return i === -1 ? ZERO_PAYLOAD : runtime.slice(i + IMMUTABLE_PAYLOAD_SEPARATOR.length);
}

export function maskImmutablePayload(runtime: string): string {
  const i = runtime.indexOf(IMMUTABLE_PAYLOAD_SEPARATOR);
  return i === -1 ? runtime : runtimeWithImmutables(runtime.slice(0, i), ZERO_PAYLOAD);
}

/** The re-derivation step: an address-derived immutable is a function of the address. */
export function expectedPayloadFor(address: string): string {
  return `derived(${address})`;
}
