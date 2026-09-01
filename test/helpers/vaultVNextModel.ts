/**
 * WalletWall Vault vNext — implementation-independent reference model.
 *
 * PURPOSE AND EXACT SCOPE OF THE PROOF
 * ------------------------------------
 * This module is a STATE MODEL of the vNext architecture adjudicated in
 * docs/Vault_vNext_Architecture.md. It is deliberately NOT a model of
 * `contracts/WalletWallVault.sol`, and it is NOT a Solidity simulator.
 *
 * What it CAN establish:
 *   - that a set of named invariants is mutually satisfiable by at least one
 *     coherent design (the architecture is not self-contradictory);
 *   - that each invariant is DISCRIMINATING — i.e. there exists a deliberately
 *     broken variant of the design that the invariant detects. This is the
 *     mutation matrix (M1..M18) in VaultVNextArchitectureModel.test.ts.
 *   - that certain hazards are REACHABLE under one identity model and
 *     UNREACHABLE under another. `IdentityModel` is a parameter precisely so
 *     the architecture verdict is executable rather than merely asserted.
 *
 * What it CANNOT establish, and must never be cited as establishing:
 *   - that any Solidity implementation conforms to it. No production contract
 *     is imported, deployed, or compared here. Conformance is future work and
 *     is listed as an open item in the architecture document.
 *   - anything about gas, bytecode size, EVM stack depth, or reentrancy at the
 *     opcode level. Those are measured elsewhere (`npm run validate:bytecode-size`).
 *   - that the invariant SET is complete. It is the set this adjudication
 *     derived; absence of an invariant here is not evidence that none is needed.
 *
 * MODELLING RULES OBSERVED (each exists to keep a hazard representable)
 *   1. Plane state is a SEPARATE object from kernel state and is never a
 *      computed view of it. If `PlaneState.generation` were derived from
 *      `KernelState.planeGenerations`, divergence (mutant M5) would be
 *      unrepresentable and the invariant guarding it would be vacuous.
 *   2. Failure is modelled as DATA (`PlaneHealth`), not as thrown exceptions,
 *      so that "Byzantine" and "unavailable" are distinguishable outcomes
 *      rather than one catch block.
 *   3. Every mutation flips exactly ONE guard. A mutation that changes two
 *      things cannot attribute a kill to either.
 *   4. Transitions return a discriminated `Outcome` rather than throwing, so a
 *      denied action and a crashed action are never confused.
 *
 * No new dependency is introduced by this module. It is pure TypeScript.
 */

// ---------------------------------------------------------------------------
// Identity and deployment model
// ---------------------------------------------------------------------------

/**
 * Which architecture is being modelled.
 *
 * - SHARED_MULTITENANT reproduces the CURRENT shape: one contract, many
 *   tenants, tenant identity is a mapping key and therefore immovable, and the
 *   governance/pause surface is global across every tenant.
 * - ACCOUNT_PER_VAULT reproduces the vNext shape: identity is the vault's own
 *   address, so identity is decoupled from authority and authority becomes
 *   rotatable internal state.
 *
 * This is a PARAMETER, not a constant, so that tests can demonstrate that a
 * hazard reachable under one model is structurally unreachable under the other.
 */
export type IdentityModel = "SHARED_MULTITENANT" | "ACCOUNT_PER_VAULT";

// ---------------------------------------------------------------------------
// Safe-state lattice
// ---------------------------------------------------------------------------

export type SafeState = "NORMAL" | "CONTAINED" | "RECOVERY_ONLY" | "MIGRATION_ONLY" | "RETIRED";

/**
 * Actions whose availability the safe-state lattice governs. Kept as a closed
 * union so that adding a state forces the availability table to be completed
 * for every action rather than silently defaulting to "allowed".
 */
export type GatedAction =
  | "ORDINARY_SPEND"
  | "LARGE_SPEND"
  | "QUEUE"
  | "SETTLE_EXISTING_QUEUE"
  | "POLICY_MUTATION"
  | "GUARDIAN_MUTATION"
  | "CREDENTIAL_ROTATION"
  | "RECOVERY_INITIATION"
  | "RECOVERY_SUPPORT"
  | "RECOVERY_CANCELLATION"
  | "RECOVERY_EXECUTION"
  | "PLANE_REPLACEMENT"
  | "MIGRATION_PREPARATION"
  | "MIGRATION_EXECUTION";

// ---------------------------------------------------------------------------
// Principals and capabilities
// ---------------------------------------------------------------------------

export type Principal =
  | "SPENDING_CREDENTIAL"
  | "PQ_CREDENTIAL"
  | "GUARDIAN"
  | "GUARDIAN_QUORUM"
  | "GUARDIAN_PLANE"
  | "POLICY_PLANE"
  | "CREDENTIAL_PLANE"
  | "VERIFIER"
  | "EMERGENCY"
  | "MIGRATION_AUTHORITY"
  | "KERNEL_ADMIN"
  | "ASSURANCE"
  | "WALLETWALL_INFRA"
  | "ANYONE";

export type Capability =
  | "MOVE_ASSETS"
  | "CHANGE_CREDENTIALS"
  | "CHANGE_GUARDIANS"
  | "CANCEL_RECOVERY"
  | "APPROVE_RECOVERY"
  | "CHANGE_POLICY"
  | "WEAKEN_POLICY"
  | "REPLACE_VERIFIER"
  | "ENTER_CONTAINMENT"
  | "EXIT_CONTAINMENT"
  | "MIGRATE"
  | "SELECT_DESTINATION_KERNEL"
  | "REPLACE_PLANE";

// ---------------------------------------------------------------------------
// Capability planes
// ---------------------------------------------------------------------------

export type PlaneId = "POLICY" | "GUARDIAN" | "CREDENTIAL" | "VERIFIER" | "ASSURANCE";

/**
 * A plane's operational condition.
 *
 * UNAVAILABLE and BYZANTINE are deliberately distinct: the whole TCB
 * classification in docs/Vault_vNext_Architecture.md turns on the fact that a
 * component can fail in two different ways with two different consequences.
 * Collapsing them into a single "broken" would erase that distinction.
 */
export type PlaneHealth = "AVAILABLE" | "UNAVAILABLE" | "BYZANTINE";

/**
 * A plane's OWN state. Never derived from KernelState — see modelling rule 1.
 */
export interface PlaneState {
  readonly id: PlaneId;
  health: PlaneHealth;
  /** The plane's own belief about its generation. May diverge from the kernel's. */
  generation: number;
  /** Set when the plane has been retired and replaced rather than resumed. */
  retired: boolean;
}

// ---------------------------------------------------------------------------
// Cryptographic scheme lifecycle
// ---------------------------------------------------------------------------

/**
 * Scheme status, ordered as a transition lattice.
 *
 * The security-transition rule (see docs/Vault_vNext_Architecture.md §12) is
 * stated over this status plus `strengthClass`, NOT over the numeric
 * generation. A larger generation number never implies greater strength.
 */
export type SchemeStatus = "ACTIVE" | "DEPRECATED" | "DISALLOWED";

export interface SchemeRecord {
  readonly schemeId: string;
  status: SchemeStatus;
  /**
   * Ordinal strength class. Higher is stronger. This is KERNEL-RECORDED at the
   * moment a scheme is activated, and is NOT read from the verifier — a
   * self-reported identifier carries no security guarantee, so it can never be
   * the source of a strength claim.
   */
  readonly strengthClass: number;
  /** Which verifier implementation generation currently serves this scheme. */
  verifierGeneration: number;
  /** Verifier implementations are replaceable WITHIN a scheme; the scheme is not. */
  verifierHealth: PlaneHealth;
}

// ---------------------------------------------------------------------------
// Credentials, guardians, recovery, migration
// ---------------------------------------------------------------------------

export interface Credential {
  commitment: string;
  schemeId: string;
  /** Monotonic. A credential from generation g is invalid once generation > g. */
  generation: number;
  /** Whether possession of the incoming credential was proven at install time. */
  possessionProven: boolean;
}

export interface GuardianSet {
  members: readonly string[];
  /** Monotonic. Recovery supported under generation g cannot execute under g+1. */
  generation: number;
}

export interface RecoveryRequest {
  readonly id: string;
  readonly incoming: Credential;
  /** Guardian generation under which this request was opened. */
  readonly boundGuardianGeneration: number;
  supports: readonly string[];
  readonly openedAt: number;
  readonly executableAt: number;
  /** Wall-clock expiry. Deliberately does NOT suspend while contained. */
  readonly expiresAt: number;
}

export interface MigrationBinding {
  readonly sourceVault: string;
  readonly destinationVault: string;
  /** Code hash of the destination KERNEL, not of the destination account. */
  readonly destinationKernelCodeHash: string;
  readonly destinationGeneration: number;
  readonly assetAmount: bigint;
  readonly credentialCommitment: string;
  readonly guardianCommitment: string;
  readonly policyCommitment: string;
  readonly expectedSafeState: SafeState;
  readonly chainId: number;
  readonly nonce: number;
  readonly deadline: number;
}

// ---------------------------------------------------------------------------
// Mutations — the deliberately broken discriminators
// ---------------------------------------------------------------------------

/**
 * Each mutation disables exactly ONE guard, so a kill is attributable.
 * See VaultVNextArchitectureModel.test.ts for the invariant that kills each.
 */
export type Mutation =
  | "M1_GENERIC_MODULE_EXECUTION"
  | "M2_STALE_CREDENTIAL_GENERATION_VALID"
  | "M3_STALE_GUARDIAN_GENERATION_VALID"
  | "M4_FAILED_PLANE_REQUIRED_FOR_ITS_OWN_RECOVERY"
  | "M5_CONTROLLER_KERNEL_DIVERGENCE_UNDETECTED"
  | "M6_EMERGENCY_CREATES_STRONGER_AUTHORITY"
  | "M7_EMERGENCY_PERMANENT_RECOVERY_VETO"
  | "M8_MIGRATION_OMITS_DESTINATION_CODEHASH"
  | "M9_MIGRATION_ALLOWS_GENERATION_SUBSTITUTION"
  | "M10_SILENT_CRYPTO_DOWNGRADE"
  | "M11_ALWAYS_TRUE_VERIFIER_IS_STRONG_EVIDENCE"
  | "M12_ASSURANCE_ACTUATES_CUSTODY"
  | "M13_POLICY_PLANE_GAINS_ASSET_AUTHORITY"
  | "M14_GUARDIAN_CONTROLLER_INDIRECT_TAKEOVER_OMITTED"
  | "M15_HOSTED_SERVICE_REQUIRED_FOR_RECOVERY"
  | "M16_ONE_SIDED_REFERENCE_MODEL_DIVERGENCE"
  | "M17_UNAVAILABLE_PLANE_STRANDS_LOCAL_RECOVERY"
  | "M18_OLD_GENERATION_CROSSES_BOUNDARY";

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/**
 * A discriminated outcome. `DENIED` (the design refused) and `UNAVAILABLE`
 * (a dependency failed) are separate on purpose: conflating them is exactly how
 * a liveness failure gets mistaken for a safety success.
 */
export type Outcome =
  | { readonly kind: "OK" }
  | { readonly kind: "DENIED"; readonly reason: string }
  | { readonly kind: "UNAVAILABLE"; readonly plane: PlaneId };

export const ok = (): Outcome => ({ kind: "OK" });
export const denied = (reason: string): Outcome => ({ kind: "DENIED", reason });
export const unavailable = (plane: PlaneId): Outcome => ({ kind: "UNAVAILABLE", plane });

// ---------------------------------------------------------------------------
// Kernel state
// ---------------------------------------------------------------------------

export interface KernelState {
  readonly identityModel: IdentityModel;
  /** In ACCOUNT_PER_VAULT this is the vault's own address and IS the identity. */
  readonly vaultId: string;
  /**
   * In SHARED_MULTITENANT this is the mapping key: an identity that no
   * transition can ever reassign. In ACCOUNT_PER_VAULT it is absent (null),
   * because identity is the address and administration is rotatable state.
   */
  readonly immovableTenantKey: string | null;
  /** Immutable code identity of the running kernel generation. */
  readonly kernelCodeHash: string;
  readonly kernelGeneration: number;
  custody: bigint;
  safeState: SafeState;
  credential: Credential;
  schemes: Map<string, SchemeRecord>;
  guardians: GuardianSet;
  recovery: RecoveryRequest | null;
  /** The KERNEL's belief about each plane's generation. */
  planeGenerations: Map<PlaneId, number>;
  migration: MigrationBinding | null;
  nonce: number;
  /**
   * True only if a generic `execute(target, data)` capability exists. The vNext
   * architecture requires this to be permanently false; it is modelled as state
   * so that an invariant can assert it rather than relying on its absence.
   */
  genericExecutionEnabled: boolean;
  /** Set when an emergency principal has entered containment. */
  containmentEnteredAt: number | null;
  /** Wall-clock bound on containment. null means unbounded — a hazard. */
  containmentExpiresAt: number | null;
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

export interface ModelOptions {
  readonly identityModel: IdentityModel;
  readonly mutations?: readonly Mutation[];
  readonly guardians?: readonly string[];
  readonly custody?: bigint;
}

/** Recovery delay and expiry, in abstract time units (days). */
export const RECOVERY_DELAY = 7;
export const RECOVERY_EXPIRY_AFTER_EXECUTABLE = 14;
export const CONTAINMENT_MAX_DURATION = 30;

/**
 * The reference model.
 *
 * Time is an explicit integer clock advanced by `warp`. There is no wall clock
 * and no randomness, so every scenario is deterministic and replayable.
 */
export class VaultVNextModel {
  readonly kernel: KernelState;
  readonly planes: Map<PlaneId, PlaneState>;
  private readonly mutations: ReadonlySet<Mutation>;
  private clock = 0;
  /**
   * Records which guards were actually EVALUATED during a scenario. This exists
   * to defeat vacuous mutation testing: a mutation on a guard the scenario
   * never reaches would otherwise "pass" while proving nothing.
   */
  readonly exercised = new Set<string>();

  constructor(opts: ModelOptions) {
    this.mutations = new Set(opts.mutations ?? []);
    const schemes = new Map<string, SchemeRecord>();
    schemes.set("ECDSA_SECP256K1", {
      schemeId: "ECDSA_SECP256K1",
      status: "ACTIVE",
      strengthClass: 1,
      verifierGeneration: 1,
      verifierHealth: "AVAILABLE",
    });
    schemes.set("ML_DSA_65", {
      schemeId: "ML_DSA_65",
      status: "ACTIVE",
      strengthClass: 2,
      verifierGeneration: 1,
      verifierHealth: "AVAILABLE",
    });

    this.kernel = {
      identityModel: opts.identityModel,
      vaultId: "vault-1",
      immovableTenantKey: opts.identityModel === "SHARED_MULTITENANT" ? "tenant-eoa-1" : null,
      kernelCodeHash: "0xKERNEL_GEN_1",
      kernelGeneration: 1,
      custody: opts.custody ?? 100n,
      safeState: "NORMAL",
      credential: {
        commitment: "cred-1",
        schemeId: "ECDSA_SECP256K1",
        generation: 1,
        possessionProven: true,
      },
      schemes,
      // ACCOUNT_PER_VAULT binds guardians at construction, so a vault is never
      // born unguarded. SHARED_MULTITENANT reproduces the observed defect that
      // createVault never writes the guardian set.
      guardians: {
        members: opts.guardians ?? (opts.identityModel === "ACCOUNT_PER_VAULT" ? ["g1", "g2", "g3"] : []),
        generation: 1,
      },
      recovery: null,
      planeGenerations: new Map<PlaneId, number>([
        ["POLICY", 1],
        ["GUARDIAN", 1],
        ["CREDENTIAL", 1],
        ["VERIFIER", 1],
        ["ASSURANCE", 1],
      ]),
      migration: null,
      nonce: 0,
      genericExecutionEnabled: this.has("M1_GENERIC_MODULE_EXECUTION"),
      containmentEnteredAt: null,
      containmentExpiresAt: null,
    };

    this.planes = new Map<PlaneId, PlaneState>(
      (["POLICY", "GUARDIAN", "CREDENTIAL", "VERIFIER", "ASSURANCE"] as const).map((id) => [
        id,
        { id, health: "AVAILABLE", generation: 1, retired: false },
      ]),
    );
  }

  private has(m: Mutation): boolean {
    return this.mutations.has(m);
  }

  private mark(guard: string): void {
    this.exercised.add(guard);
  }

  now(): number {
    return this.clock;
  }

  warp(days: number): void {
    this.clock += days;
  }

  plane(id: PlaneId): PlaneState {
    const p = this.planes.get(id);
    if (p === undefined) throw new Error(`unknown plane ${id}`);
    return p;
  }

  setPlaneHealth(id: PlaneId, health: PlaneHealth): void {
    this.plane(id).health = health;
  }

  requiredSupports(): number {
    return Math.floor(this.kernel.guardians.members.length / 2) + 1;
  }

  /**
   * Whether a generic `execute(target, data)` capability is reachable at all.
   * Exposed as a marking accessor so the invariant that forbids it records that
   * it actually evaluated the guard, rather than passing vacuously.
   */
  genericExecutionAvailable(): boolean {
    this.mark("execution/generic");
    return this.kernel.genericExecutionEnabled;
  }

  /**
   * Move assets out. Custody may only leave by an authorised spend or a bound
   * migration; every other path must be denied.
   */
  spend(by: Principal, amount: bigint): Outcome {
    this.mark("custody/spend");
    if (!this.isAvailable("ORDINARY_SPEND")) return denied("unavailable in current safe state");
    if (!this.authorityClosure(by).has("MOVE_ASSETS")) return denied("not authorised to move assets");
    if (amount > this.kernel.custody) return denied("insufficient custody");
    this.kernel.custody -= amount;
    this.kernel.nonce += 1;
    return ok();
  }

  // -------------------------------------------------------------------------
  // Safe-state availability table
  // -------------------------------------------------------------------------

  /**
   * Whether `action` is available in the CURRENT safe state.
   *
   * The table is exhaustive by construction: every state names every action it
   * permits, so a newly added action defaults to UNAVAILABLE rather than
   * silently inheriting permission.
   */
  isAvailable(action: GatedAction): boolean {
    const table: Readonly<Record<SafeState, readonly GatedAction[]>> = {
      NORMAL: [
        "ORDINARY_SPEND",
        "LARGE_SPEND",
        "QUEUE",
        "SETTLE_EXISTING_QUEUE",
        "POLICY_MUTATION",
        "GUARDIAN_MUTATION",
        "CREDENTIAL_ROTATION",
        "RECOVERY_INITIATION",
        "RECOVERY_SUPPORT",
        "RECOVERY_CANCELLATION",
        "RECOVERY_EXECUTION",
        "PLANE_REPLACEMENT",
        "MIGRATION_PREPARATION",
        "MIGRATION_EXECUTION",
      ],
      // CONTAINED withdraws SPENDING authority only. Every recovery action
      // stays live: an emergency transition must never reduce the reachability
      // of recovery, or the emergency principal acquires a veto (M7).
      CONTAINED: [
        "SETTLE_EXISTING_QUEUE",
        "RECOVERY_INITIATION",
        "RECOVERY_SUPPORT",
        "RECOVERY_CANCELLATION",
        "RECOVERY_EXECUTION",
        "MIGRATION_PREPARATION",
        "MIGRATION_EXECUTION",
      ],
      RECOVERY_ONLY: [
        "RECOVERY_INITIATION",
        "RECOVERY_SUPPORT",
        "RECOVERY_CANCELLATION",
        "RECOVERY_EXECUTION",
        "MIGRATION_PREPARATION",
        "MIGRATION_EXECUTION",
      ],
      MIGRATION_ONLY: ["MIGRATION_PREPARATION", "MIGRATION_EXECUTION", "RECOVERY_EXECUTION"],
      // RETIRED is terminal for NEW activity. Migration execution remains the
      // single exit so retirement is never an asset trap.
      RETIRED: ["MIGRATION_EXECUTION"],
    };

    if (this.has("M7_EMERGENCY_PERMANENT_RECOVERY_VETO") && this.kernel.safeState === "CONTAINED") {
      this.mark("safe-state/recovery-available-under-containment");
      // Mutant: containment additionally suppresses recovery.
      if (action === "RECOVERY_EXECUTION" || action === "RECOVERY_INITIATION" || action === "RECOVERY_SUPPORT") {
        return false;
      }
    }
    this.mark("safe-state/availability");
    return table[this.kernel.safeState].includes(action);
  }

  // -------------------------------------------------------------------------
  // Emergency transitions
  // -------------------------------------------------------------------------

  /**
   * Enter containment. Authority-reducing and time-bounded by construction.
   *
   * The bound is WALL-CLOCK and does not suspend. An expiry clock that pauses
   * while the system is paused can convert a suspensive state into a permanent
   * trap — the request becomes simultaneously unexecutable and undeletable.
   */
  enterContainment(by: Principal): Outcome {
    this.mark("emergency/enter");
    if (by !== "EMERGENCY" && by !== "GUARDIAN_QUORUM") {
      return denied("only the emergency principal or a guardian quorum may contain");
    }
    if (this.kernel.safeState === "RETIRED") return denied("terminal state");
    this.kernel.safeState = "CONTAINED";
    this.kernel.containmentEnteredAt = this.clock;
    this.kernel.containmentExpiresAt = this.has("M7_EMERGENCY_PERMANENT_RECOVERY_VETO")
      ? null // Mutant: unbounded containment.
      : this.clock + CONTAINMENT_MAX_DURATION;
    return ok();
  }

  /**
   * Containment lapses on its own once the wall-clock bound passes. No
   * principal needs to act, which is what prevents a disappeared emergency
   * principal from leaving the vault contained forever.
   */
  tickContainment(): void {
    this.mark("emergency/auto-expiry");
    const expiry = this.kernel.containmentExpiresAt;
    if (this.kernel.safeState === "CONTAINED" && expiry !== null && this.clock >= expiry) {
      this.kernel.safeState = "NORMAL";
      this.kernel.containmentEnteredAt = null;
      this.kernel.containmentExpiresAt = null;
    }
  }

  /**
   * The set of capabilities a principal holds in the CURRENT state. Used by the
   * authority-monotonicity invariant: an emergency transition may only ever
   * shrink this set.
   */
  capabilitiesOf(p: Principal): ReadonlySet<Capability> {
    const caps = new Set<Capability>();
    const contained = this.kernel.safeState === "CONTAINED";

    if (p === "SPENDING_CREDENTIAL" && !contained) {
      caps.add("MOVE_ASSETS");
      caps.add("CHANGE_CREDENTIALS");
    }
    if (p === "GUARDIAN_QUORUM") {
      caps.add("APPROVE_RECOVERY");
      caps.add("CANCEL_RECOVERY");
      caps.add("CHANGE_GUARDIANS");
      caps.add("ENTER_CONTAINMENT");
    }
    if (p === "EMERGENCY") {
      caps.add("ENTER_CONTAINMENT");
      // A containment authority that also gains EXIT authority holds a
      // reversible switch, which is strictly more authority than entering.
      if (this.has("M6_EMERGENCY_CREATES_STRONGER_AUTHORITY")) {
        this.mark("emergency/authority-monotonicity");
        caps.add("EXIT_CONTAINMENT");
        caps.add("REPLACE_PLANE");
        caps.add("WEAKEN_POLICY");
      }
    }
    if (p === "POLICY_PLANE") {
      caps.add("CHANGE_POLICY");
      if (this.has("M13_POLICY_PLANE_GAINS_ASSET_AUTHORITY")) {
        this.mark("plane/policy-asset-authority");
        caps.add("MOVE_ASSETS");
      }
    }
    if (p === "ASSURANCE") {
      // The assurance plane observes. It never actuates.
      if (this.has("M12_ASSURANCE_ACTUATES_CUSTODY")) {
        this.mark("assurance/non-actuation");
        caps.add("MOVE_ASSETS");
        caps.add("ENTER_CONTAINMENT");
      }
    }
    if (p === "MIGRATION_AUTHORITY") {
      caps.add("MIGRATE");
      if (this.has("M9_MIGRATION_ALLOWS_GENERATION_SUBSTITUTION")) {
        this.mark("migration/generation-substitution");
        caps.add("SELECT_DESTINATION_KERNEL");
      }
    }
    if (p === "KERNEL_ADMIN") {
      // In ACCOUNT_PER_VAULT there is NO per-vault kernel admin at all. This is
      // the architectural difference the identity model buys.
      if (this.kernel.identityModel === "SHARED_MULTITENANT") {
        this.mark("identity/global-admin-exists");
        caps.add("REPLACE_VERIFIER");
        caps.add("WEAKEN_POLICY");
        caps.add("ENTER_CONTAINMENT");
        caps.add("EXIT_CONTAINMENT");
      }
    }
    return caps;
  }

  /**
   * Transitive authority closure: capabilities a principal can reach by any
   * sequence of state changes it can itself authorize, not merely those it
   * holds directly.
   *
   * The closure rules below are the ones this adjudication established. A
   * principal that cannot directly move assets but can force eventual asset
   * control is classified as holding MOVE_ASSETS here.
   */
  authorityClosure(p: Principal): ReadonlySet<Capability> {
    const closure = new Set<Capability>(this.capabilitiesOf(p));
    this.mark("authority/closure");

    // Whoever can replace credentials can eventually move assets.
    if (closure.has("CHANGE_CREDENTIALS")) closure.add("MOVE_ASSETS");

    // A guardian quorum can approve a recovery that installs credentials it
    // chooses, and therefore reaches asset control. This is an ACCEPTED
    // residual, not a defect — but it must be recorded, not hidden.
    if (closure.has("APPROVE_RECOVERY")) {
      closure.add("CHANGE_CREDENTIALS");
      closure.add("MOVE_ASSETS");
    }

    // Replacing the verifier reaches credential authority ONLY where the
    // replaced scheme is the SOLE authenticator. Under a conjunctive
    // (multi-scheme) credential rule it does not.
    if (closure.has("REPLACE_VERIFIER") && this.soleAuthenticatorSchemeExists()) {
      this.mark("authority/verifier-is-sole-authenticator");
      closure.add("CHANGE_CREDENTIALS");
      closure.add("MOVE_ASSETS");
    }

    // Choosing the destination kernel of a migration reaches everything the
    // destination can do, which is unbounded unless the destination is bound.
    if (closure.has("SELECT_DESTINATION_KERNEL")) {
      closure.add("MOVE_ASSETS");
      closure.add("CHANGE_CREDENTIALS");
      closure.add("CHANGE_GUARDIANS");
    }

    // The omitted indirect path: a guardian-plane controller that can rewrite
    // the roster can install itself a quorum and thereby reach recovery.
    if (p === "GUARDIAN_PLANE" && !this.has("M14_GUARDIAN_CONTROLLER_INDIRECT_TAKEOVER_OMITTED")) {
      this.mark("authority/guardian-plane-indirect");
      closure.add("CHANGE_GUARDIANS");
      closure.add("APPROVE_RECOVERY");
      closure.add("CHANGE_CREDENTIALS");
      closure.add("MOVE_ASSETS");
    }

    return closure;
  }

  /**
   * True when some ACTIVE scheme is the only authenticator, so compromising its
   * verifier is sufficient to authorize. Under a conjunctive rule with two or
   * more independent active schemes this is false.
   */
  private soleAuthenticatorSchemeExists(): boolean {
    const active = [...this.kernel.schemes.values()].filter((s) => s.status === "ACTIVE");
    return active.length <= 1;
  }

  // -------------------------------------------------------------------------
  // Credential and scheme lifecycle
  // -------------------------------------------------------------------------

  /**
   * Replace the verifier IMPLEMENTATION serving a scheme. This never changes
   * which scheme is active and never changes strength.
   */
  replaceVerifierImplementation(schemeId: string, newGeneration: number): Outcome {
    this.mark("crypto/verifier-implementation-replacement");
    const scheme = this.kernel.schemes.get(schemeId);
    if (scheme === undefined) return denied("unknown scheme");
    if (!this.has("M18_OLD_GENERATION_CROSSES_BOUNDARY") && newGeneration <= scheme.verifierGeneration) {
      return denied("verifier generation must strictly increase");
    }
    scheme.verifierGeneration = newGeneration;
    return ok();
  }

  /**
   * Activate a scheme. The security-transition rule: a scheme may only be
   * activated if it is at least as strong as every currently ACTIVE scheme.
   * Strength is the kernel-recorded `strengthClass`, never the generation
   * number and never anything the verifier reports about itself.
   */
  activateScheme(schemeId: string): Outcome {
    this.mark("crypto/scheme-activation");
    const scheme = this.kernel.schemes.get(schemeId);
    if (scheme === undefined) return denied("unknown scheme");
    if (scheme.status === "DISALLOWED") return denied("scheme is disallowed");

    if (!this.has("M10_SILENT_CRYPTO_DOWNGRADE")) {
      const activeMax = Math.max(
        0,
        ...[...this.kernel.schemes.values()].filter((s) => s.status === "ACTIVE").map((s) => s.strengthClass),
      );
      if (scheme.strengthClass < activeMax) {
        return denied("activation would weaken the effective authorization strength");
      }
    }
    scheme.status = "ACTIVE";
    return ok();
  }

  /**
   * Whether a verifier's `true` answer counts as evidence of cryptographic
   * strength. It never does on its own: strength is a kernel-recorded property
   * of the SCHEME, and a verifier that is unavailable or Byzantine supplies no
   * evidence at all.
   */
  verifierAnswerIsStrongEvidence(schemeId: string): boolean {
    this.mark("crypto/evidence-quality");
    const scheme = this.kernel.schemes.get(schemeId);
    if (scheme === undefined) return false;
    if (this.has("M11_ALWAYS_TRUE_VERIFIER_IS_STRONG_EVIDENCE")) {
      return true; // Mutant: a bare `true` is trusted regardless of health.
    }
    return scheme.verifierHealth === "AVAILABLE" && scheme.status === "ACTIVE";
  }

  /** Rotate credentials. Requires proof of possession of the INCOMING credential. */
  rotateCredentials(incoming: Credential): Outcome {
    this.mark("credential/rotation");
    if (!this.isAvailable("CREDENTIAL_ROTATION")) return denied("unavailable in current safe state");
    if (!incoming.possessionProven) return denied("incoming credential lacks proof of possession");
    this.kernel.credential = { ...incoming, generation: this.kernel.credential.generation + 1 };
    this.kernel.nonce += 1;
    return ok();
  }

  /**
   * Whether a credential presented from `generation` is accepted now.
   * Monotonicity: only the current generation is valid.
   */
  credentialGenerationValid(generation: number): boolean {
    this.mark("generation/credential");
    if (this.has("M2_STALE_CREDENTIAL_GENERATION_VALID")) return true;
    return generation === this.kernel.credential.generation;
  }

  guardianGenerationValid(generation: number): boolean {
    this.mark("generation/guardian");
    if (this.has("M3_STALE_GUARDIAN_GENERATION_VALID")) return true;
    return generation === this.kernel.guardians.generation;
  }

  // -------------------------------------------------------------------------
  // Guardian administration
  // -------------------------------------------------------------------------

  replaceGuardians(by: Principal, members: readonly string[]): Outcome {
    this.mark("guardian/replacement");
    if (!this.isAvailable("GUARDIAN_MUTATION")) return denied("unavailable in current safe state");
    if (members.length === 0) return denied("guardian set may not be empty");

    // Under ACCOUNT_PER_VAULT, guardian administration is guardian-quorum
    // authority. Under SHARED_MULTITENANT it is the immovable tenant key, which
    // is precisely the root cause this architecture exists to remove.
    const authorised =
      this.kernel.identityModel === "ACCOUNT_PER_VAULT" ? by === "GUARDIAN_QUORUM" : by === "SPENDING_CREDENTIAL";
    if (!authorised) return denied("not authorised to replace the guardian set");

    // An approved request survives a guardian-set replacement.
    const req = this.kernel.recovery;
    if (req !== null && req.supports.length >= this.requiredSupports()) {
      return denied("an approved recovery request may not be cleared by a set replacement");
    }
    this.kernel.recovery = null;
    this.kernel.guardians = { members, generation: this.kernel.guardians.generation + 1 };
    return ok();
  }

  // -------------------------------------------------------------------------
  // Recovery
  // -------------------------------------------------------------------------

  /**
   * Whether the recovery path consults any external plane. The architecture
   * requires this to be false for every plane, always: a plane that recovery
   * depends on becomes a component whose failure removes the remedy for
   * component failure.
   */
  recoveryConsultsPlane(id: PlaneId): boolean {
    this.mark("recovery/locality");
    if (this.has("M17_UNAVAILABLE_PLANE_STRANDS_LOCAL_RECOVERY")) return true;
    if (this.has("M4_FAILED_PLANE_REQUIRED_FOR_ITS_OWN_RECOVERY") && id === "GUARDIAN") return true;
    if (this.has("M15_HOSTED_SERVICE_REQUIRED_FOR_RECOVERY")) return true;
    return false;
  }

  /**
   * Whether recovery depends on any state that is shared ACROSS vaults.
   *
   * "Recovery makes zero external CALLS" is necessary but NOT sufficient, and
   * conflating the two is a real error: in the observed architecture
   * `executeRecovery` is `whenNotPaused`, which reads a single global `_paused`
   * bit. No call is made, yet recovery is still coupled to a cross-tenant
   * object that one principal controls. Locality must therefore be stated over
   * BOTH external calls and globally-mutable state.
   *
   * Under ACCOUNT_PER_VAULT every gating flag lives in the vault's own storage,
   * so there is no cross-vault object to couple to.
   */
  recoveryDependsOnGlobalState(): boolean {
    this.mark("recovery/global-state-independence");
    return this.kernel.identityModel === "SHARED_MULTITENANT";
  }

  initiateRecovery(by: Principal, incoming: Credential): Outcome {
    this.mark("recovery/initiate");
    if (!this.isAvailable("RECOVERY_INITIATION")) return denied("unavailable in current safe state");
    if (by !== "GUARDIAN" && by !== "GUARDIAN_QUORUM") return denied("only a guardian may initiate");
    if (this.kernel.guardians.members.length === 0) return denied("vault has no guardian set");

    for (const id of this.planes.keys()) {
      if (this.recoveryConsultsPlane(id) && this.plane(id).health !== "AVAILABLE") {
        return unavailable(id);
      }
    }

    const existing = this.kernel.recovery;
    if (existing !== null) {
      if (this.clock < existing.executableAt) return denied("a live request may not be replaced");
      if (existing.supports.length >= this.requiredSupports()) {
        return denied("an approved request may not be replaced");
      }
    }

    this.kernel.recovery = {
      id: `rec-${this.kernel.nonce + 1}`,
      incoming,
      boundGuardianGeneration: this.kernel.guardians.generation,
      supports: [],
      openedAt: this.clock,
      executableAt: this.clock + RECOVERY_DELAY,
      expiresAt: this.clock + RECOVERY_DELAY + RECOVERY_EXPIRY_AFTER_EXECUTABLE,
    };
    return ok();
  }

  supportRecovery(guardian: string): Outcome {
    this.mark("recovery/support");
    if (!this.isAvailable("RECOVERY_SUPPORT")) return denied("unavailable in current safe state");
    const req = this.kernel.recovery;
    if (req === null) return denied("no request");
    if (!this.kernel.guardians.members.includes(guardian)) return denied("not a guardian");
    if (req.supports.includes(guardian)) return denied("already supported");
    this.kernel.recovery = { ...req, supports: [...req.supports, guardian] };
    return ok();
  }

  /**
   * Expiry requires no principal to act, which is what stops an approved
   * request becoming simultaneously unexecutable and undeletable.
   */
  tickRecoveryExpiry(): void {
    this.mark("recovery/expiry");
    const req = this.kernel.recovery;
    if (req !== null && this.clock >= req.expiresAt) this.kernel.recovery = null;
  }

  executeRecovery(): Outcome {
    this.mark("recovery/execute");
    if (!this.isAvailable("RECOVERY_EXECUTION")) return denied("unavailable in current safe state");
    const req = this.kernel.recovery;
    if (req === null) return denied("no request");
    if (this.clock < req.executableAt) return denied("not ready");
    if (this.clock >= req.expiresAt) return denied("request expired");
    if (req.supports.length < this.requiredSupports()) return denied("insufficient supports");

    // A request supported under guardian generation g may not execute under g+1.
    if (!this.guardianGenerationValid(req.boundGuardianGeneration)) {
      return denied("request bound to a superseded guardian generation");
    }

    for (const id of this.planes.keys()) {
      if (this.recoveryConsultsPlane(id) && this.plane(id).health !== "AVAILABLE") {
        return unavailable(id);
      }
    }

    this.kernel.credential = {
      ...req.incoming,
      generation: this.kernel.credential.generation + 1,
    };
    this.kernel.recovery = null;
    this.kernel.nonce += 1;
    return ok();
  }

  cancelRecovery(by: Principal): Outcome {
    this.mark("recovery/cancel");
    if (!this.isAvailable("RECOVERY_CANCELLATION")) return denied("unavailable in current safe state");
    // Under ACCOUNT_PER_VAULT only a guardian quorum may cancel; the spending
    // credential holds no veto, because recovery is the remedy for its own
    // compromise.
    const authorised =
      this.kernel.identityModel === "ACCOUNT_PER_VAULT" ? by === "GUARDIAN_QUORUM" : by === "SPENDING_CREDENTIAL";
    if (!authorised) return denied("not authorised to cancel");
    this.kernel.recovery = null;
    return ok();
  }

  // -------------------------------------------------------------------------
  // Plane synchrony
  // -------------------------------------------------------------------------

  /**
   * A PUSH transition from a plane to the kernel.
   *
   * The kernel verifies the EXPECTED PREVIOUS generation, which is what makes
   * the transition a compare-and-swap rather than a blind write. Note what this
   * does NOT verify: the kernel checks generation ORDINALITY, not roster
   * CONTENT. A plane that advances the generation correctly while pushing wrong
   * content is not detected here, and that residual is recorded explicitly in
   * the architecture document rather than hidden.
   */
  pushPlaneGeneration(id: PlaneId, expectedPrevious: number, next: number): Outcome {
    this.mark("synchrony/push");
    const p = this.plane(id);
    if (p.health === "UNAVAILABLE") return unavailable(id);

    const kernelView = this.kernel.planeGenerations.get(id) ?? 0;
    if (!this.has("M5_CONTROLLER_KERNEL_DIVERGENCE_UNDETECTED")) {
      if (expectedPrevious !== kernelView) return denied("expected-previous generation mismatch");
      if (next <= kernelView) return denied("generation must strictly increase");
    }

    // Atomic: both sides move, or neither does.
    this.kernel.planeGenerations.set(id, next);
    p.generation = this.has("M5_CONTROLLER_KERNEL_DIVERGENCE_UNDETECTED") ? next + 1 : next;
    return ok();
  }

  /** True when the kernel's view and a plane's own view disagree. */
  isDiverged(id: PlaneId): boolean {
    this.mark("synchrony/divergence-check");
    return (this.kernel.planeGenerations.get(id) ?? 0) !== this.plane(id).generation;
  }

  // -------------------------------------------------------------------------
  // Migration
  // -------------------------------------------------------------------------

  /** The full binding a migration must carry. Omitting any field is a mutant. */
  prepareMigration(binding: MigrationBinding): Outcome {
    this.mark("migration/prepare");
    if (!this.isAvailable("MIGRATION_PREPARATION")) return denied("unavailable in current safe state");
    if (!this.has("M8_MIGRATION_OMITS_DESTINATION_CODEHASH")) {
      if (binding.destinationKernelCodeHash === "") return denied("destination kernel code hash is required");
    }
    if (binding.chainId <= 0) return denied("chain binding required");
    if (binding.deadline <= this.clock) return denied("deadline in the past");
    this.kernel.migration = binding;
    return ok();
  }

  /**
   * Execute a migration against an observed destination. The observed code hash
   * must equal the bound one, so a destination that changed between preparation
   * and execution is rejected.
   */
  executeMigration(observedDestinationCodeHash: string, observedGeneration: number): Outcome {
    this.mark("migration/execute");
    if (!this.isAvailable("MIGRATION_EXECUTION")) return denied("unavailable in current safe state");
    const b = this.kernel.migration;
    if (b === null) return denied("no prepared migration");
    if (this.clock > b.deadline) return denied("migration expired");

    if (!this.has("M8_MIGRATION_OMITS_DESTINATION_CODEHASH")) {
      if (observedDestinationCodeHash !== b.destinationKernelCodeHash) {
        return denied("destination kernel code hash mismatch");
      }
    }
    if (!this.has("M9_MIGRATION_ALLOWS_GENERATION_SUBSTITUTION")) {
      if (observedGeneration !== b.destinationGeneration) {
        return denied("destination generation substitution");
      }
    }

    this.kernel.custody -= b.assetAmount;
    this.kernel.safeState = "RETIRED";
    this.kernel.migration = null;
    return ok();
  }

  // -------------------------------------------------------------------------
  // Reference-model parity
  // -------------------------------------------------------------------------

  /**
   * Parity between the kernel and its sibling reference implementation.
   * Modelled explicitly because parity coverage in the observed repository is
   * PARTIAL: `test/GuardianRecoverySimulatorParity.test.ts` (added by #176) pins
   * five guardian/recovery/treasury scenarios behaviourally across both
   * contracts, but nothing covers the withdrawal, policy, verifier-governance or
   * large-tx surfaces, and nothing asserts source-text equality (mutant M16).
   */
  parityDigest(): string {
    this.mark("parity/digest");
    const drift = this.has("M16_ONE_SIDED_REFERENCE_MODEL_DIVERGENCE") ? "-DRIFTED" : "";
    return (
      [
        `identity=${this.kernel.identityModel}`,
        `recoveryDelay=${RECOVERY_DELAY}`,
        `expiry=${RECOVERY_EXPIRY_AFTER_EXECUTABLE}`,
        `quorum=${this.requiredSupports()}`,
        `generic=${this.kernel.genericExecutionEnabled}`,
      ].join("|") + drift
    );
  }

  /** The sibling implementation's digest, which must equal `parityDigest()`. */
  siblingParityDigest(): string {
    return [
      `identity=${this.kernel.identityModel}`,
      `recoveryDelay=${RECOVERY_DELAY}`,
      `expiry=${RECOVERY_EXPIRY_AFTER_EXECUTABLE}`,
      `quorum=${this.requiredSupports()}`,
      `generic=${this.kernel.genericExecutionEnabled}`,
    ].join("|");
  }
}
