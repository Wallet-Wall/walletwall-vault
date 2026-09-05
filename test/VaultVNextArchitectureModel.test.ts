/**
 * WalletWall Vault vNext — executable architecture model suite.
 *
 * WHAT THIS SUITE PROVES, EXACTLY
 * -------------------------------
 * It exercises `test/helpers/vaultVNextModel.ts`, an implementation-independent
 * state model of the architecture adjudicated in docs/Vault_vNext_Architecture.md.
 *
 * It establishes THREE things and nothing else:
 *
 *   1. MUTUAL SATISFIABILITY — the named invariants hold simultaneously on at
 *      least one coherent design, so the architecture is not self-contradictory.
 *   2. DISCRIMINATION — every load-bearing invariant has at least one
 *      deliberately broken variant (M1..M18) that it detects. An invariant with
 *      no killing mutant is decoration, not assurance.
 *   3. IDENTITY-MODEL SEPARATION — specific hazards are reachable under
 *      SHARED_MULTITENANT and structurally unreachable under ACCOUNT_PER_VAULT.
 *      This is what makes the FQ1 verdict executable rather than merely argued.
 *
 * WHAT IT DOES NOT PROVE. It imports no production contract, deploys nothing,
 * and compares nothing to Solidity. It is NOT evidence that
 * `contracts/WalletWallVault.sol` conforms to the model; no such conformance is
 * claimed anywhere, and establishing it is listed as open work in the
 * architecture document. It says nothing about gas, bytecode size, or EVM stack
 * depth — those are measured by `npm run validate:bytecode-size`.
 *
 * VACUITY GUARD. Every mutation assertion additionally requires that the mutated
 * guard was actually EVALUATED during the scenario (`model.exercised`). Without
 * this, a mutation planted on a branch the scenario never reaches would report a
 * clean "kill" while proving nothing. See
 * docs/Vault_vNext_Architecture.md §17 for why this check is mandatory rather
 * than optional.
 *
 * Pure, fast, in-memory. No network, no contracts, no deployment.
 */

import { expect } from "chai";

import {
  CONTAINMENT_MAX_DURATION,
  CONTAINMENT_WINDOW,
  CREDENTIAL_CHALLENGE_LIMIT,
  RECOVERY_DELAY,
  VaultVNextModel,
  commitOf,
  type Capability,
  type Credential,
  type GuardianSeat,
  type IdentityModel,
  type MigrationBinding,
  type Mutation,
  type PlaneId,
  type Principal,
} from "./helpers/vaultVNextModel.js";
import {
  AuthorityCutModel,
  BIND_DELAY_DAYS,
  CORRELATED_PAIR,
  CodeIdentityChain,
  CryptoLattice,
  ECDSA,
  ECDSA_ONLY,
  FactoryGenerationModel,
  HYBRID,
  HYBRID_87,
  HYBRID_OR_ECDSA,
  ML_DSA_65,
  ML_DSA_87,
  MigrationMachine,
  PQ_ONLY_87,
  RECOVERY_DELAY_DAYS,
  SizeModel,
  ZERO_PAYLOAD,
  cloneCode,
  expectedPayloadFor,
  runtimeWithImmutables,
  type AssetKind,
  type AttackPath,
  type Binding,
  type BuildIdentity,
  type ChainView,
  type CompiledArtifact,
  type DeploymentTarget,
  type PublishedIdentity,
  type Registry,
  type RemediationMutation,
  type SecurityProfile,
} from "./helpers/vaultVNextRemediation.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ALL_PLANES: readonly PlaneId[] = ["POLICY", "GUARDIAN", "CREDENTIAL", "VERIFIER", "ASSURANCE"];

function makeModel(identityModel: IdentityModel, mutations: readonly Mutation[] = []): VaultVNextModel {
  return new VaultVNextModel({ identityModel, mutations });
}

function vnext(mutations: readonly Mutation[] = []): VaultVNextModel {
  return makeModel("ACCOUNT_PER_VAULT", mutations);
}

function heldCredential(commitment: string): Credential {
  return { commitment, schemeId: "ECDSA_SECP256K1", generation: 1, possessionProven: true };
}

function unheldCredential(commitment: string): Credential {
  return { commitment, schemeId: "ECDSA_SECP256K1", generation: 1, possessionProven: false };
}

function migrationBinding(overrides: Partial<MigrationBinding> = {}): MigrationBinding {
  return {
    sourceVault: "vault-1",
    destinationVault: "vault-2",
    destinationKernelCodeHash: "0xKERNEL_GEN_2",
    destinationGeneration: 2,
    assetAmount: 100n,
    credentialCommitment: "cred-1",
    guardianCommitment: "gset-1",
    policyCommitment: "pol-1",
    expectedSafeState: "NORMAL",
    chainId: 1,
    nonce: 1,
    deadline: 30,
    ...overrides,
  };
}

/**
 * Drive a recovery to the approved-and-executable point, ASSERTING each step.
 * Use this only in positive tests, never inside a mutation discriminator — an
 * asserting fixture conflates "the scenario could not be set up" with "the
 * invariant was violated", and only the second is a valid kill.
 */
function driveToApprovedRecovery(m: VaultVNextModel): void {
  expect(m.initiateRecovery("GUARDIAN", heldCredential("cred-2")).kind).to.equal("OK");
  expect(m.supportRecovery("g1").kind).to.equal("OK");
  expect(m.supportRecovery("g2").kind).to.equal("OK");
  m.warp(RECOVERY_DELAY);
}

/**
 * The non-asserting counterpart, for use INSIDE mutation discriminators.
 * Returns whether recovery completed end to end. A mutant that breaks recovery
 * at initiation is just as dead as one that breaks it at execution, but the
 * discriminator has to be able to OBSERVE that rather than crash on the way.
 */
function recoveryCompletesEndToEnd(m: VaultVNextModel): boolean {
  if (m.initiateRecovery("GUARDIAN", heldCredential("cred-2")).kind !== "OK") return false;
  if (m.supportRecovery("g1").kind !== "OK") return false;
  if (m.supportRecovery("g2").kind !== "OK") return false;
  m.warp(RECOVERY_DELAY);
  return m.executeRecovery().kind === "OK";
}

/**
 * The discriminator harness.
 *
 * `invariant` must return true on a clean model and false on the mutant. Both
 * directions are asserted: a check that only ever returns false would "kill"
 * every mutant while proving nothing, and a check that only ever returns true
 * would kill none.
 */
function assertMutantKilled(
  mutation: Mutation,
  guard: string,
  invariant: (m: VaultVNextModel) => boolean,
  identityModel: IdentityModel = "ACCOUNT_PER_VAULT",
): void {
  const clean = makeModel(identityModel);
  const mutant = makeModel(identityModel, [mutation]);

  expect(invariant(clean), `${mutation}: the invariant must HOLD on the unmutated model`).to.equal(true);
  expect(invariant(mutant), `${mutation}: the invariant must FAIL on the mutant`).to.equal(false);
  expect(
    mutant.exercised.has(guard),
    `${mutation}: guard "${guard}" was never evaluated — this mutation test is VACUOUS`,
  ).to.equal(true);
}

// ---------------------------------------------------------------------------

describe("WalletWall Vault vNext — architecture reference model", function () {
  // =========================================================================
  describe("T0 — catastrophic kernel invariants", function () {
    it("I-NO-GENERIC-EXECUTION — no generic execute(target, data) capability exists", function () {
      const m = vnext();
      expect(m.genericExecutionAvailable()).to.equal(false);
    });

    it("I-CUSTODY-CONSERVATION — custody leaves only by authorised spend or bound migration", function () {
      const m = vnext();
      const opening = m.kernel.custody;

      // An unauthorised principal cannot move assets.
      expect(m.spend("ASSURANCE", 1n).kind).to.equal("DENIED");
      expect(m.spend("POLICY_PLANE", 1n).kind).to.equal("DENIED");
      expect(m.kernel.custody).to.equal(opening);

      // The credential holder can.
      expect(m.spend("SPENDING_CREDENTIAL", 10n).kind).to.equal("OK");
      expect(m.kernel.custody).to.equal(opening - 10n);
    });

    it("I-CUSTODY-CONSERVATION — custody cannot exceed the opening balance by any transition", function () {
      const m = vnext();
      const opening = m.kernel.custody;
      driveToApprovedRecovery(m);
      expect(m.executeRecovery().kind).to.equal("OK");
      expect(m.kernel.custody).to.equal(opening);
    });

    it("the kernel code hash is a fixed generation identity and no transition rewrites it", function () {
      const m = vnext();
      const before = m.kernel.kernelCodeHash;
      driveToApprovedRecovery(m);
      m.executeRecovery();
      m.enterContainment("EMERGENCY");
      expect(m.kernel.kernelCodeHash).to.equal(before);
    });
  });

  // =========================================================================
  describe("T1 — authority and recovery boundaries", function () {
    it("I-RECOVERY-LOCALITY — recovery consults no external plane", function () {
      const m = vnext();
      for (const p of ALL_PLANES) {
        expect(m.recoveryConsultsPlane(p), `recovery must not consult ${p}`).to.equal(false);
      }
    });

    it("I-RECOVERY-LOCALITY — locality covers globally-mutable STATE, not only external calls", function () {
      // "Zero external calls" is necessary but not sufficient. In the observed
      // architecture `executeRecovery` is `whenNotPaused`, which reads a single
      // global `_paused` bit: no call is made, yet recovery is still coupled to
      // a cross-tenant object one principal controls.
      expect(makeModel("SHARED_MULTITENANT").recoveryDependsOnGlobalState()).to.equal(true);
      expect(vnext().recoveryDependsOnGlobalState()).to.equal(false);
    });

    it("I-RECOVERY-SOVEREIGNTY — recovery completes with EVERY plane permanently unavailable", function () {
      const m = vnext();
      for (const p of ALL_PLANES) m.setPlaneHealth(p, "UNAVAILABLE");

      driveToApprovedRecovery(m);
      const outcome = m.executeRecovery();
      expect(outcome.kind, "recovery must not depend on any plane's availability").to.equal("OK");
      expect(m.kernel.credential.commitment).to.equal("cred-2");
    });

    it("I-RECOVERY-SOVEREIGNTY — recovery completes with EVERY plane Byzantine", function () {
      const m = vnext();
      for (const p of ALL_PLANES) m.setPlaneHealth(p, "BYZANTINE");

      driveToApprovedRecovery(m);
      expect(m.executeRecovery().kind).to.equal("OK");
    });

    it("I-EXIT-REACHABILITY — every reachable state retains at least one plane-free exit", function () {
      // Recovery restores AUTHORITY, not LIQUIDITY. A vault whose credentials are
      // recovered but whose only exit consults a dead plane is recoverable and
      // still unusable. Every state must keep an exit that needs no plane.
      const states = ["NORMAL", "CONTAINED", "RECOVERY_ONLY", "MIGRATION_ONLY", "RETIRED"] as const;
      for (const s of states) {
        const m = vnext();
        for (const p of ALL_PLANES) m.setPlaneHealth(p, "UNAVAILABLE");
        m.kernel.safeState = s;
        const exit = m.isAvailable("ORDINARY_SPEND") || m.isAvailable("MIGRATION_EXECUTION");
        expect(exit, `state ${s} has no plane-free exit — assets would be trapped`).to.equal(true);
      }
    });

    it("I-NO-PERMANENT-VETO — containment lapses on wall clock with no principal acting", function () {
      const m = vnext();
      expect(m.enterContainment("EMERGENCY").kind).to.equal("OK");
      expect(m.kernel.safeState).to.equal("CONTAINED");

      // Nobody acts. The emergency principal has disappeared entirely.
      m.warp(CONTAINMENT_MAX_DURATION);
      m.tickContainment();
      expect(m.kernel.safeState, "containment must self-expire").to.equal("NORMAL");
    });

    it("I-NO-PERMANENT-VETO — recovery stays reachable throughout containment", function () {
      const m = vnext();
      expect(m.enterContainment("EMERGENCY").kind).to.equal("OK");
      expect(m.isAvailable("RECOVERY_INITIATION")).to.equal(true);
      expect(m.isAvailable("RECOVERY_SUPPORT")).to.equal(true);
      expect(m.isAvailable("RECOVERY_EXECUTION")).to.equal(true);
      // Spending, by contrast, IS withdrawn — containment reduces authority.
      expect(m.isAvailable("ORDINARY_SPEND")).to.equal(false);
    });

    it("emergency containment is authority-REDUCING: no principal gains a capability", function () {
      const m = vnext();
      const principals: readonly Principal[] = [
        "SPENDING_CREDENTIAL",
        "GUARDIAN_QUORUM",
        "EMERGENCY",
        "POLICY_PLANE",
        "ASSURANCE",
        "MIGRATION_AUTHORITY",
      ];
      const before = new Map<Principal, ReadonlySet<Capability>>(principals.map((p) => [p, m.capabilitiesOf(p)]));

      m.enterContainment("EMERGENCY");

      for (const p of principals) {
        const after = m.capabilitiesOf(p);
        const priorCaps = before.get(p);
        expect(priorCaps, `missing baseline for ${p}`).to.not.equal(undefined);
        for (const cap of after) {
          expect(
            priorCaps?.has(cap),
            `${p} GAINED ${cap} by entering containment — an emergency transition must never increase authority`,
          ).to.equal(true);
        }
      }
    });

    it("I-RECOVERY-TERMINATION — an approved request expires without any principal acting", function () {
      const m = vnext();
      driveToApprovedRecovery(m);
      expect(m.kernel.recovery).to.not.equal(null);

      // Contained, so nothing can execute it; nobody cancels it.
      m.enterContainment("EMERGENCY");
      m.warp(1000);
      m.tickRecoveryExpiry();
      expect(m.kernel.recovery, "a request must never be simultaneously unexecutable and undeletable").to.equal(null);
    });

    it("I-APPROVED-REQUEST-PRESERVATION — a guardian-set replacement cannot clear an approved request", function () {
      const m = vnext();
      driveToApprovedRecovery(m);
      const outcome = m.replaceGuardians("GUARDIAN_QUORUM", ["h1", "h2", "h3"]);
      expect(outcome.kind).to.equal("DENIED");
      expect(m.kernel.recovery).to.not.equal(null);
    });

    it("I-RECOVERY-CHALLENGE-EPOCH — the challenge budget survives quorum cancellation and rotation, and resets only when a guardian recovery executes", function () {
      // docs/Vault_vNext_Recovery_Amendment.md section 2 (DERIVED, adopted for
      // vNext): the credential's bounded budget is independent of request
      // lifetime and of credentialGeneration; it resets ONLY after a successful
      // guardian recovery — the one transition the outgoing credential cannot
      // authorise. Never resetting would delete the D1/H-15 defence for every
      // credential after the first; resetting on rotation would restore H-03.
      const m = vnext();
      for (let i = 0; i < CREDENTIAL_CHALLENGE_LIMIT; i++) {
        expect(m.initiateRecovery("GUARDIAN", heldCredential(`epoch-${i}`)).kind).to.equal("OK");
        expect(m.challengeRecoveryByCredential().kind).to.equal("OK");
      }
      expect(m.kernel.credentialChallengesUsed).to.equal(CREDENTIAL_CHALLENGE_LIMIT);

      // A guardian-quorum cancellation refunds nothing.
      expect(m.initiateRecovery("GUARDIAN", heldCredential("epoch-q")).kind).to.equal("OK");
      expect(m.cancelRecovery("GUARDIAN_QUORUM").kind).to.equal("OK");
      expect(m.kernel.credentialChallengesUsed, "quorum cancellation refunds nothing").to.equal(
        CREDENTIAL_CHALLENGE_LIMIT,
      );
      expect(m.initiateRecovery("GUARDIAN", heldCredential("epoch-r")).kind).to.equal("OK");
      expect(m.challengeRecoveryByCredential().kind, "still exhausted").to.equal("DENIED");
      expect(m.cancelRecovery("GUARDIAN_QUORUM").kind).to.equal("OK");

      // Ordinary credential rotation refunds nothing either (H-03 otherwise).
      expect(m.rotateCredentials(heldCredential("epoch-rotated")).kind).to.equal("OK");
      expect(m.kernel.credentialChallengesUsed, "rotation refunds nothing").to.equal(CREDENTIAL_CHALLENGE_LIMIT);

      // A successful guardian recovery is the single reset boundary.
      driveToApprovedRecovery(m);
      expect(m.executeRecovery().kind).to.equal("OK");
      expect(m.kernel.credentialChallengesUsed, "epoch reset at the authority transition").to.equal(0);
      expect(m.initiateRecovery("GUARDIAN", heldCredential("epoch-later")).kind).to.equal("OK");
      expect(
        m.challengeRecoveryByCredential().kind,
        "the recovered credential regains the full bounded allowance",
      ).to.equal("OK");
    });

    it("recovery installs only credentials whose possession was proven", function () {
      const m = vnext();
      expect(m.rotateCredentials(unheldCredential("ghost")).kind).to.equal("DENIED");
      expect(m.rotateCredentials(heldCredential("real")).kind).to.equal("OK");
      expect(m.kernel.credential.commitment).to.equal("real");
    });
  });

  // =========================================================================
  describe("T2 — capability-plane safety", function () {
    it("a plane may only SUBTRACT authority — no plane holds MOVE_ASSETS", function () {
      const m = vnext();
      const planes: readonly Principal[] = ["POLICY_PLANE", "CREDENTIAL_PLANE", "VERIFIER", "ASSURANCE"];
      for (const p of planes) {
        expect(
          m.authorityClosure(p).has("MOVE_ASSETS"),
          `${p} must not reach asset authority even transitively`,
        ).to.equal(false);
      }
    });

    it("I-ASSURANCE-NONACTUATION — the assurance plane holds no capability at all", function () {
      const m = vnext();
      expect([...m.authorityClosure("ASSURANCE")]).to.deep.equal([]);
    });

    it("I-SYNCHRONY — a PUSH with a wrong expected-previous generation is rejected", function () {
      const m = vnext();
      expect(m.pushPlaneGeneration("POLICY", 99, 2).kind).to.equal("DENIED");
      expect(m.pushPlaneGeneration("POLICY", 1, 2).kind).to.equal("OK");
      expect(m.isDiverged("POLICY")).to.equal(false);
    });

    it("I-SYNCHRONY — a generation may never move backwards or stand still", function () {
      const m = vnext();
      expect(m.pushPlaneGeneration("POLICY", 1, 1).kind).to.equal("DENIED");
      expect(m.pushPlaneGeneration("POLICY", 1, 0).kind).to.equal("DENIED");
    });

    it("an unavailable plane is reported as UNAVAILABLE, never silently as denial", function () {
      const m = vnext();
      m.setPlaneHealth("POLICY", "UNAVAILABLE");
      const outcome = m.pushPlaneGeneration("POLICY", 1, 2);
      expect(outcome.kind).to.equal("UNAVAILABLE");
    });

    it("I-NO-SILENT-DOWNGRADE — a weaker scheme cannot be activated alongside a stronger one", function () {
      const m = vnext();
      const weak = m.kernel.schemes.get("ECDSA_SECP256K1");
      expect(weak, "fixture scheme missing").to.not.equal(undefined);
      if (weak !== undefined) weak.status = "DEPRECATED";

      // ML_DSA_65 (strengthClass 2) remains ACTIVE; re-activating the weaker
      // scheme would lower the effective floor.
      expect(m.activateScheme("ECDSA_SECP256K1").kind).to.equal("DENIED");
    });

    it("a verifier's answer is not strong evidence when the verifier is unhealthy", function () {
      const m = vnext();
      expect(m.verifierAnswerIsStrongEvidence("ML_DSA_65")).to.equal(true);
      const scheme = m.kernel.schemes.get("ML_DSA_65");
      expect(scheme).to.not.equal(undefined);
      if (scheme !== undefined) scheme.verifierHealth = "BYZANTINE";
      expect(m.verifierAnswerIsStrongEvidence("ML_DSA_65")).to.equal(false);
    });

    it("a verifier implementation swap cannot move a generation backwards", function () {
      const m = vnext();
      expect(m.replaceVerifierImplementation("ML_DSA_65", 2).kind).to.equal("OK");
      expect(m.replaceVerifierImplementation("ML_DSA_65", 1).kind).to.equal("DENIED");
    });
  });

  // =========================================================================
  describe("migration", function () {
    it("I-MIGRATION-BINDING — a migration without a destination kernel code hash is refused", function () {
      const m = vnext();
      expect(m.prepareMigration(migrationBinding({ destinationKernelCodeHash: "" })).kind).to.equal("DENIED");
    });

    it("I-MIGRATION-BINDING — a destination whose observed code hash differs is refused", function () {
      const m = vnext();
      expect(m.prepareMigration(migrationBinding()).kind).to.equal("OK");
      expect(m.executeMigration("0xMALICIOUS", 2).kind).to.equal("DENIED");
      expect(m.executeMigration("0xKERNEL_GEN_2", 2).kind).to.equal("OK");
    });

    it("a generation substitution at the destination is refused", function () {
      const m = vnext();
      m.prepareMigration(migrationBinding());
      expect(m.executeMigration("0xKERNEL_GEN_2", 7).kind).to.equal("DENIED");
    });

    it("an expired migration binding cannot execute", function () {
      const m = vnext();
      m.prepareMigration(migrationBinding({ deadline: 5 }));
      m.warp(6);
      expect(m.executeMigration("0xKERNEL_GEN_2", 2).kind).to.equal("DENIED");
    });

    it("RETIRED is not an asset trap — migration execution remains available", function () {
      const m = vnext();
      m.prepareMigration(migrationBinding());
      m.kernel.safeState = "RETIRED";
      expect(m.isAvailable("MIGRATION_EXECUTION")).to.equal(true);
      expect(m.isAvailable("ORDINARY_SPEND")).to.equal(false);
    });

    it("the migration authority alone cannot choose the destination kernel", function () {
      const m = vnext();
      expect(m.authorityClosure("MIGRATION_AUTHORITY").has("SELECT_DESTINATION_KERNEL")).to.equal(false);
      expect(m.authorityClosure("MIGRATION_AUTHORITY").has("MOVE_ASSETS")).to.equal(false);
    });
  });

  // =========================================================================
  describe("authority closure", function () {
    it("a guardian quorum reaches asset control transitively — an ACCEPTED residual, recorded not hidden", function () {
      const m = vnext();
      const closure = m.authorityClosure("GUARDIAN_QUORUM");
      expect(closure.has("APPROVE_RECOVERY")).to.equal(true);
      expect(
        closure.has("MOVE_ASSETS"),
        "guardian-majority takeover is an accepted residual and MUST appear in the closure",
      ).to.equal(true);
    });

    it("the spending credential cannot cancel a recovery under the vNext identity model", function () {
      const m = vnext();
      driveToApprovedRecovery(m);
      expect(m.cancelRecovery("SPENDING_CREDENTIAL").kind).to.equal("DENIED");
      expect(m.cancelRecovery("GUARDIAN_QUORUM").kind).to.equal("OK");
    });

    it("replacing a verifier does not reach credential authority while two schemes are active", function () {
      const m = vnext();
      // Both ECDSA and ML-DSA are ACTIVE, so neither verifier is the sole authenticator.
      expect(m.authorityClosure("KERNEL_ADMIN").has("MOVE_ASSETS")).to.equal(false);
    });
  });

  // =========================================================================
  describe("identity-model separation — why the FQ1 verdict is executable", function () {
    it("SHARED_MULTITENANT exposes a global admin with cross-tenant capability; ACCOUNT_PER_VAULT does not", function () {
      const shared = makeModel("SHARED_MULTITENANT");
      const perVault = vnext();

      expect(shared.capabilitiesOf("KERNEL_ADMIN").size).to.be.greaterThan(0);
      expect(
        perVault.capabilitiesOf("KERNEL_ADMIN").size,
        "a per-vault account has no global admin principal at all",
      ).to.equal(0);
    });

    it("SHARED_MULTITENANT vaults are born UNGUARDED; ACCOUNT_PER_VAULT vaults are born guarded", function () {
      const shared = makeModel("SHARED_MULTITENANT");
      const perVault = vnext();

      expect(shared.kernel.guardians.members).to.have.length(0);
      expect(perVault.kernel.guardians.members.length).to.be.greaterThan(0);

      // The consequence: recovery is unreachable at birth under the shared model.
      expect(shared.initiateRecovery("GUARDIAN", heldCredential("x")).kind).to.equal("DENIED");
      expect(perVault.initiateRecovery("GUARDIAN", heldCredential("x")).kind).to.equal("OK");
    });

    it("SHARED_MULTITENANT keeps an immovable tenant key; ACCOUNT_PER_VAULT has none", function () {
      expect(makeModel("SHARED_MULTITENANT").kernel.immovableTenantKey).to.not.equal(null);
      expect(
        vnext().kernel.immovableTenantKey,
        "identity must be the vault address, decoupled from authority",
      ).to.equal(null);
    });

    it("under SHARED_MULTITENANT the spending credential holds a recovery veto; under ACCOUNT_PER_VAULT it does not", function () {
      const shared = new VaultVNextModel({ identityModel: "SHARED_MULTITENANT", guardians: ["g1", "g2", "g3"] });
      driveToApprovedRecovery(shared);
      expect(
        shared.cancelRecovery("SPENDING_CREDENTIAL").kind,
        "the observed defect: a credential-keyed veto over the remedy for credential compromise",
      ).to.equal("OK");

      const perVault = vnext();
      driveToApprovedRecovery(perVault);
      expect(perVault.cancelRecovery("SPENDING_CREDENTIAL").kind).to.equal("DENIED");
    });
  });

  // =========================================================================
  describe("mutation matrix — every load-bearing invariant has a killing mutant", function () {
    it("M1 — a generic module gains arbitrary execution", function () {
      assertMutantKilled("M1_GENERIC_MODULE_EXECUTION", "execution/generic", (m) => !m.genericExecutionAvailable());
    });

    it("M2 — a stale credential generation remains valid", function () {
      assertMutantKilled("M2_STALE_CREDENTIAL_GENERATION_VALID", "generation/credential", (m) => {
        m.rotateCredentials(heldCredential("cred-2"));
        return !m.credentialGenerationValid(1);
      });
    });

    it("M3 — a stale guardian generation remains valid", function () {
      assertMutantKilled("M3_STALE_GUARDIAN_GENERATION_VALID", "generation/guardian", (m) => {
        m.replaceGuardians("GUARDIAN_QUORUM", ["h1", "h2", "h3"]);
        return !m.guardianGenerationValid(1);
      });
    });

    it("M4 — a failed plane becomes mandatory for its own recovery", function () {
      assertMutantKilled("M4_FAILED_PLANE_REQUIRED_FOR_ITS_OWN_RECOVERY", "recovery/locality", (m) => {
        m.setPlaneHealth("GUARDIAN", "UNAVAILABLE");
        return recoveryCompletesEndToEnd(m);
      });
    });

    it("M5 — controller and kernel state diverge undetected", function () {
      assertMutantKilled("M5_CONTROLLER_KERNEL_DIVERGENCE_UNDETECTED", "synchrony/push", (m) => {
        m.pushPlaneGeneration("POLICY", 1, 2);
        return !m.isDiverged("POLICY");
      });
    });

    it("M6 — emergency authority creates stronger authority", function () {
      assertMutantKilled("M6_EMERGENCY_CREATES_STRONGER_AUTHORITY", "emergency/authority-monotonicity", (m) => {
        const before = m.capabilitiesOf("EMERGENCY");
        return !before.has("EXIT_CONTAINMENT") && !before.has("WEAKEN_POLICY");
      });
    });

    it("M7 — emergency authority permanently vetoes recovery", function () {
      assertMutantKilled(
        "M7_EMERGENCY_PERMANENT_RECOVERY_VETO",
        "safe-state/recovery-available-under-containment",
        (m) => {
          m.enterContainment("EMERGENCY");
          return m.isAvailable("RECOVERY_EXECUTION");
        },
      );
    });

    it("M8 — migration omits destination code-hash binding", function () {
      assertMutantKilled("M8_MIGRATION_OMITS_DESTINATION_CODEHASH", "migration/execute", (m) => {
        m.prepareMigration(migrationBinding());
        return m.executeMigration("0xMALICIOUS_DESTINATION", 2).kind === "DENIED";
      });
    });

    it("M9 — migration permits malicious generation substitution", function () {
      assertMutantKilled("M9_MIGRATION_ALLOWS_GENERATION_SUBSTITUTION", "migration/execute", (m) => {
        m.prepareMigration(migrationBinding());
        return m.executeMigration("0xKERNEL_GEN_2", 999).kind === "DENIED";
      });
    });

    it("M10 — a cryptographic generation can downgrade silently", function () {
      assertMutantKilled("M10_SILENT_CRYPTO_DOWNGRADE", "crypto/scheme-activation", (m) => {
        const weak = m.kernel.schemes.get("ECDSA_SECP256K1");
        if (weak !== undefined) weak.status = "DEPRECATED";
        return m.activateScheme("ECDSA_SECP256K1").kind === "DENIED";
      });
    });

    it("M11 — an always-true verifier is treated as strong PQ evidence", function () {
      assertMutantKilled("M11_ALWAYS_TRUE_VERIFIER_IS_STRONG_EVIDENCE", "crypto/evidence-quality", (m) => {
        const scheme = m.kernel.schemes.get("ML_DSA_65");
        if (scheme !== undefined) scheme.verifierHealth = "BYZANTINE";
        return !m.verifierAnswerIsStrongEvidence("ML_DSA_65");
      });
    });

    it("M12 — the Assurance Observatory directly actuates custody", function () {
      assertMutantKilled(
        "M12_ASSURANCE_ACTUATES_CUSTODY",
        "assurance/non-actuation",
        (m) => !m.authorityClosure("ASSURANCE").has("MOVE_ASSETS"),
      );
    });

    it("M13 — the policy plane transitively obtains asset authority", function () {
      assertMutantKilled(
        "M13_POLICY_PLANE_GAINS_ASSET_AUTHORITY",
        "plane/policy-asset-authority",
        (m) => !m.authorityClosure("POLICY_PLANE").has("MOVE_ASSETS"),
      );
    });

    it("M14 — the guardian controller's indirect takeover path is omitted from the closure", function () {
      // Inverted polarity by construction: the CLEAN model must REPORT the
      // indirect path (an honest closure), and the mutant is the one that hides
      // it. Omitting a real path from an authority graph is the defect.
      assertMutantKilled("M14_GUARDIAN_CONTROLLER_INDIRECT_TAKEOVER_OMITTED", "authority/closure", (m) =>
        m.authorityClosure("GUARDIAN_PLANE").has("MOVE_ASSETS"),
      );
    });

    it("M15 — a company-hosted service is required for recovery", function () {
      assertMutantKilled("M15_HOSTED_SERVICE_REQUIRED_FOR_RECOVERY", "recovery/locality", (m) => {
        for (const p of ALL_PLANES) m.setPlaneHealth(p, "UNAVAILABLE");
        return recoveryCompletesEndToEnd(m);
      });
    });

    it("M16 — one-sided reference-model divergence", function () {
      assertMutantKilled(
        "M16_ONE_SIDED_REFERENCE_MODEL_DIVERGENCE",
        "parity/digest",
        (m) => m.parityDigest() === m.siblingParityDigest(),
      );
    });

    it("M17 — an unavailable control plane strands already-safe local recovery", function () {
      assertMutantKilled("M17_UNAVAILABLE_PLANE_STRANDS_LOCAL_RECOVERY", "recovery/locality", (m) => {
        m.setPlaneHealth("POLICY", "UNAVAILABLE");
        return recoveryCompletesEndToEnd(m);
      });
    });

    it("M18 — an old generation crosses a generational boundary", function () {
      assertMutantKilled("M18_OLD_GENERATION_CROSSES_BOUNDARY", "crypto/verifier-implementation-replacement", (m) => {
        m.replaceVerifierImplementation("ML_DSA_65", 5);
        return m.replaceVerifierImplementation("ML_DSA_65", 2).kind === "DENIED";
      });
    });
  });

  // =========================================================================
  // PR #179 REMEDIATION — the seven adversarial blockers, made executable
  // =========================================================================

  describe("T0 — no sole external authenticator (blocker 2)", function () {
    it("a caller holding NO secret is refused under every ADMITTED credential mode, even with an always-true verifier", function () {
      for (const mode of ["ECDSA_ONLY", "HYBRID"] as const) {
        const m = new VaultVNextModel({
          identityModel: "ACCOUNT_PER_VAULT",
          credentialMode: mode,
          verifierBehaviour: "ALWAYS_TRUE",
        });
        expect(m.modeIsAdmissible(mode), `${mode} must be admitted`).to.equal(true);
        expect(m.forgeryReachable(), `${mode} must not be forgeable`).to.equal(false);
      }
    });

    it("PqOnly IS forgeable under an always-true verifier — which is why it is not admitted", function () {
      const m = new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        credentialMode: "PQ_ONLY",
        verifierBehaviour: "ALWAYS_TRUE",
        mutations: ["M19_PQ_ONLY_MODE_ADMITTED"],
      });
      // The floor is structural only, so "correctly-sized bytes" authorizes.
      expect(m.forgeryReachable()).to.equal(true);
      expect(m.hasKernelPositiveAuthenticator()).to.equal(false);
    });

    it("SCENARIO — an always-true verifier under Hybrid is a DOWNGRADE, not a forgery", function () {
      const honest = new VaultVNextModel({ identityModel: "ACCOUNT_PER_VAULT", credentialMode: "HYBRID" });
      const lying = new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        credentialMode: "HYBRID",
        verifierBehaviour: "ALWAYS_TRUE",
      });
      // Not catastrophic: the ECDSA conjunct still gates.
      expect(lying.forgeryReachable()).to.equal(false);
      // But the PQ leg now contributes nothing, so a key-holder alone suffices —
      // exactly the silent downgrade the SecurityProfile model must report.
      expect(lying.authorizeAssetMove({ holdsEcdsaKey: true, pqBytesWellFormed: true }).kind).to.equal("OK");
      expect(honest.authorizeAssetMove({ holdsEcdsaKey: true, pqBytesWellFormed: true }).kind).to.equal("DENIED");
    });

    it("SCENARIO — a reverting verifier is DENIAL under Hybrid and never loss", function () {
      const m = new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        credentialMode: "HYBRID",
        verifierBehaviour: "REVERTS",
      });
      expect(m.authorizeAssetMove({ holdsEcdsaKey: true, pqBytesWellFormed: true }).kind).to.equal("UNAVAILABLE");
      expect(m.forgeryReachable()).to.equal(false);
    });

    it("SCENARIO — with the external verifier omitted entirely, the floor alone still denies", function () {
      const m = new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        credentialMode: "HYBRID",
        externalVerifierPresent: false,
      });
      expect(m.forgeryReachable()).to.equal(false);
      expect(m.authorizeAssetMove({ holdsEcdsaKey: true, pqBytesWellFormed: true }).kind).to.equal("UNAVAILABLE");
    });

    it("I-NO-CIRCULAR-ESCAPE — a hostile verifier can be replaced without consulting it", function () {
      const hybrid = new VaultVNextModel({ identityModel: "ACCOUNT_PER_VAULT", credentialMode: "HYBRID" });
      expect(hybrid.verifierEscapeIsEvaluable()).to.equal(true);
      const pqOnly = new VaultVNextModel({ identityModel: "ACCOUNT_PER_VAULT", credentialMode: "PQ_ONLY" });
      expect(pqOnly.verifierEscapeIsEvaluable(), "PqOnly escape is authenticated BY the verifier").to.equal(false);
    });

    it("an IMMUTABLY BOUND verifier does not discharge the requirement — and cannot be escaped", function () {
      const m = new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        credentialMode: "PQ_ONLY",
        verifierImmutablyBound: true,
        verifierBehaviour: "ALWAYS_TRUE",
      });
      expect(m.hasKernelPositiveAuthenticator()).to.equal(false);
      expect(m.verifierEscapeIsEvaluable()).to.equal(false);
    });
  });

  describe("T0 — a bounded timer is not a bounded authority (blocker 7, D5)", function () {
    it("re-entry while contained cannot push the expiry", function () {
      const m = vnext();
      expect(m.enterContainmentBudgeted("EMERGENCY").kind).to.equal("OK");
      const firstExpiry = m.kernel.containmentExpiresAt;
      m.warp(5);
      expect(m.enterContainmentBudgeted("EMERGENCY").kind).to.equal("DENIED");
      expect(m.kernel.containmentExpiresAt).to.equal(firstExpiry);
    });

    it("I-CONTAINMENT-BUDGET — a hostile emergency principal cannot hold a rolling freeze", function () {
      expect(vnext().rollingFreezeReachable("EMERGENCY")).to.equal(false);
    });

    it("the budget yields uncontained intervals rather than merely a shorter freeze", function () {
      const m = vnext();
      let uncontainedDays = 0;
      for (let day = 0; day < CONTAINMENT_WINDOW; day++) {
        if (m.kernel.safeState !== "CONTAINED") m.enterContainmentBudgeted("EMERGENCY");
        if (m.kernel.safeState !== "CONTAINED") uncontainedDays += 1;
        m.warp(1);
        m.tickContainment();
      }
      expect(uncontainedDays).to.be.greaterThan(0);
    });

    it("recovery stays reachable for the whole of a contained window", function () {
      const m = vnext();
      expect(m.enterContainmentBudgeted("EMERGENCY").kind).to.equal("OK");
      for (let day = 0; day < CONTAINMENT_MAX_DURATION; day++) {
        expect(m.isAvailable("RECOVERY_EXECUTION")).to.equal(true);
        m.warp(1);
      }
    });
  });

  describe("T1 — ingress is gated with egress (blocker 4 composition)", function () {
    it("a state that cannot pay out does not take in", function () {
      const m = vnext();
      expect(m.ingressAvailable()).to.equal(true);
      expect(m.enterContainmentBudgeted("EMERGENCY").kind).to.equal("OK");
      expect(m.ingressAvailable()).to.equal(false);
    });
  });

  describe("T0 — a BOUNDED challenge is not a veto (blocker 7, D1)", function () {
    it("the spending credential may challenge, but only a bounded number of times", function () {
      const m = vnext();
      expect(m.credentialHoldsUnboundedVeto()).to.equal(false);
    });

    it("the bound is greater than zero, so a guardian majority is not unchallengeable", function () {
      expect(CREDENTIAL_CHALLENGE_LIMIT).to.be.greaterThan(0);
      const m = vnext();
      driveToApprovedRecovery(m);
      expect(m.challengeRecoveryByCredential().kind).to.equal("OK");
    });
  });

  describe("T0/T1 — the minimum guardian TCB (blocker 6)", function () {
    const seats: readonly GuardianSeat[] = [
      { address: "g1", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
      { address: "g2", authMode: "ERC1271", contractBehaviour: "ATTESTS" },
      { address: "g3", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
    ];

    function withSeats(mutations: readonly Mutation[] = [], overrides?: readonly GuardianSeat[]): VaultVNextModel {
      return new VaultVNextModel({
        identityModel: "ACCOUNT_PER_VAULT",
        guardianSeats: overrides ?? seats,
        mutations,
      });
    }

    it("the kernel holds a COMMITMENT, not the roster — and a forged constituency fails to hash", function () {
      const m = withSeats();
      expect(m.rosterIsAuthoritative(seats, 2)).to.equal(true);
      const forged: readonly GuardianSeat[] = [
        { address: "attacker", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
        ...seats.slice(1),
      ];
      expect(m.rosterIsAuthoritative(forged, 2)).to.equal(false);
    });

    it("the THRESHOLD is inside the commitment preimage, so it cannot be supplied by the caller", function () {
      const m = withSeats();
      expect(m.rosterIsAuthoritative(seats, 1), "a lowered threshold must not validate").to.equal(false);
      expect(commitOf(seats, 1)).to.not.equal(commitOf(seats, 2));
    });

    it("I-QUORUM-DISTINCTNESS — one seat presented twice is not a quorum", function () {
      const m = withSeats();
      expect(m.countDistinctAttestations([0, 1, 2])).to.equal(3);
      expect(m.countDistinctAttestations([1, 1, 1])).to.equal(1);
    });

    it("I-GUARDIAN-FAULT-ISOLATION — one reverting ERC-1271 guardian does not block the rest", function () {
      const hostile: readonly GuardianSeat[] = [
        { address: "g1", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
        { address: "g2", authMode: "ERC1271", contractBehaviour: "REVERTS" },
        { address: "g3", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
      ];
      const m = withSeats([], hostile);
      expect(m.quorumReachable(hostile, 2)).to.equal(true);
    });

    it("I-ATTESTATION-IS-AFFIRMATIVE — garbage from an ERC-1271 seat is NOT an attestation", function () {
      const garbage: readonly GuardianSeat[] = [
        { address: "g1", authMode: "ERC1271", contractBehaviour: "RETURNS_GARBAGE" },
        { address: "g2", authMode: "ERC1271", contractBehaviour: "SILENT" },
        { address: "g3", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
      ];
      const m = withSeats([], garbage);
      expect(m.quorumReachable(garbage, 2)).to.equal(false);
    });
  });

  describe("T1 — SecurityProfile replaces the scalar strength ordinal (blocker 3)", function () {
    function lattice(mutations: readonly RemediationMutation[] = []): CryptoLattice {
      return new CryptoLattice(mutations);
    }

    it("a within-family upgrade is ALLOWED — agility survives", function () {
      expect(lattice().transitionAllowed(HYBRID, HYBRID_87).ok).to.equal(true);
    });

    it("a higher parameter level with a WEAKER composition is REFUSED", function () {
      // ML-DSA-87 alone scores higher on any scalar, and drops a whole factor.
      expect(lattice().transitionAllowed(HYBRID, PQ_ONLY_87).ok).to.equal(false);
    });

    it("removing an independent factor is REFUSED", function () {
      expect(lattice().transitionAllowed(HYBRID, ECDSA_ONLY).ok).to.equal(false);
    });

    it("a silent OR is REFUSED — adding a weak alternative is a downgrade", function () {
      expect(lattice().transitionAllowed(HYBRID, HYBRID_OR_ECDSA).ok).to.equal(false);
    });

    it("two factors sharing ONE trust root do not count as two", function () {
      const l = lattice();
      expect(l.rootsOfClause([ECDSA, ML_DSA_65])).to.equal(2);
      expect(l.rootsOfClause(CORRELATED_PAIR.clauses[0]!)).to.equal(1);
      expect(l.transitionAllowed(HYBRID, CORRELATED_PAIR).ok).to.equal(false);
    });

    it("re-activating a DISALLOWED scheme is REFUSED", function () {
      const l = lattice();
      expect(l.setStatus("ML_DSA_65", "DISALLOWED").ok).to.equal(true);
      expect(l.setStatus("ML_DSA_65", "ACTIVE").ok).to.equal(false);
      expect(l.transitionAllowed(HYBRID, HYBRID).ok).to.equal(false);
    });

    it("INCOMPARABLE profiles are REFUSED, not permitted", function () {
      const hashBased: SecurityProfile = {
        clauses: [[ECDSA, { ...ML_DSA_65, schemeId: "SLH_DSA", family: "PQ_HASH", rootTag: "root/hash" }]],
      };
      // Neither dominates: PQ_LATTICE and PQ_HASH have no comparison edge.
      expect(lattice().transitionAllowed(HYBRID, hashBased).ok).to.equal(false);
      expect(lattice().transitionAllowed(hashBased, HYBRID).ok).to.equal(false);
    });

    it("every clause must carry a kernel-evaluable possession test", function () {
      expect(lattice().everyClauseAnchored(HYBRID)).to.equal(true);
      expect(lattice().everyClauseAnchored(PQ_ONLY_87)).to.equal(false);
    });

    it("a profile's independence is the MINIMUM over its clauses, never the maximum", function () {
      // HYBRID_OR_ECDSA has a 2-root clause and a 1-root clause. An attacker
      // takes the 1-root path, so the profile is worth 1.
      expect(lattice().minRoots(HYBRID_OR_ECDSA)).to.equal(1);
    });
  });

  describe("T0 — migration must survive real assets (blocker 4)", function () {
    const DESTINATION: Binding = {
      destinationVault: "vault-2",
      destinationVaultCodeHash: "0xVAULT2",
      destinationGeneration: 2,
      chainId: 1,
      nonce: 1,
      deadline: 1000,
      disposition: "FULL_BALANCE",
    };

    function machine(
      mutations: readonly RemediationMutation[] = [],
      assets: readonly (readonly [string, AssetKind])[] = [
        ["eth", "ETH"],
        ["usdc", "ERC20_WELL_BEHAVED"],
        ["nft", "ERC721"],
      ],
    ): MigrationMachine {
      const m = new MigrationMachine(mutations);
      for (const [id, kind] of assets) m.addAsset(id, kind, 100n);
      return m;
    }

    function bindAndRetire(m: MigrationMachine): void {
      expect(m.bind(true, true, DESTINATION).ok).to.equal(true);
      m.warp(m.bindDelay());
      expect(m.retire().ok).to.equal(true);
    }

    it("binding requires guardian quorum AND credential authority — neither alone", function () {
      expect(machine().bind(true, false, DESTINATION).ok).to.equal(false);
      expect(machine().bind(false, true, DESTINATION).ok).to.equal(false);
      expect(machine().bind(true, true, DESTINATION).ok).to.equal(true);
    });

    it("I-MIGRATION-SUBORDINATE-TO-RECOVERY — binding is never faster than recovery", function () {
      expect(machine().bindDelay()).to.be.at.least(RECOVERY_DELAY_DAYS);
    });

    it("a pending recovery blocks binding, so migration cannot front-run the remedy", function () {
      const m = machine();
      m.pendingRecovery = true;
      expect(m.bind(true, true, DESTINATION).ok).to.equal(false);
    });

    it("I-EGRESS-INDEPENDENCE — one reverting token does not abort the others", function () {
      const m = machine(
        [],
        [
          ["eth", "ETH"],
          ["blacklisted", "ERC20_REVERTS"],
          ["usdc", "ERC20_WELL_BEHAVED"],
        ],
      );
      bindAndRetire(m);
      expect(m.egress("eth").ok).to.equal(true);
      expect(m.egress("blacklisted").ok).to.equal(false);
      expect(m.egress("usdc").ok).to.equal(true);
      expect(m.entries.get("eth")!.status).to.equal("MOVED");
      expect(m.entries.get("usdc")!.status).to.equal("MOVED");
      expect(m.aborted).to.equal(false);
    });

    it("I-MIGRATION-NONTRAP — a hostile token planted by a stranger cannot veto the escape", function () {
      const m = machine();
      bindAndRetire(m);
      // An unprivileged third party sends a blacklisting token to the vault
      // AFTER binding. Under a bound asset set this would veto everything.
      m.addAsset("hostile", "ERC20_REVERTS", 1n);
      expect(m.everyAssetHasAnExit()).to.equal(true);
    });

    it("an airdrop arriving after binding is still claimable", function () {
      const m = machine();
      bindAndRetire(m);
      m.addAsset("airdrop", "ERC20_WELL_BEHAVED", 5n);
      expect(m.egress("airdrop").ok).to.equal(true);
    });

    it("a fee-on-transfer token settles, because the binding fixes a DISPOSITION not an amount", function () {
      const m = machine([], [["fot", "ERC20_FEE_ON_TRANSFER"]]);
      bindAndRetire(m);
      expect(m.egress("fot").ok).to.equal(true);
    });

    it("I-NO-FALSE-SETTLEMENT — a token returning false is NOT recorded as moved", function () {
      const m = machine([], [["liar", "ERC20_RETURNS_FALSE"]]);
      bindAndRetire(m);
      expect(m.egress("liar").ok).to.equal(false);
      expect(m.entries.get("liar")!.status).to.equal("FAILED");
    });

    it("RETIRED is terminal for AUTHORITY and permanently open for EGRESS", function () {
      const m = machine();
      bindAndRetire(m);
      expect(m.state).to.equal("RETIRED");
      expect(m.bind(true, true, DESTINATION).ok, "no new authority in a terminal state").to.equal(false);
      expect(m.egress("eth").ok, "egress is a pull against a prior commitment").to.equal(true);
    });

    it("I-EGRESS-RECIPIENT-FIXED — a permissionless caller cannot redirect the assets", function () {
      const m = machine();
      bindAndRetire(m);
      expect(m.egress("eth", "attacker").ok).to.equal(true);
      expect(m.lastRecipient).to.equal("vault-2");
    });

    it("ABANDONED is bookkeeping — retry remains available forever", function () {
      const m = machine();
      bindAndRetire(m);
      expect(m.abandon("usdc").ok).to.equal(true);
      expect(m.egress("usdc").ok).to.equal(true);
    });

    it("forced ETH and ERC-1155 are ordinary entries under per-vault custody", function () {
      const m = machine(
        [],
        [
          ["forced", "ETH_FORCED"],
          ["multi", "ERC1155"],
        ],
      );
      bindAndRetire(m);
      expect(m.egress("forced").ok).to.equal(true);
      expect(m.egress("multi").ok).to.equal(true);
    });
  });

  describe("T1 — code identity is a CHAIN, not a hash (blocker 5)", function () {
    const IMPL = "0xIMPL_GEN1";
    const IMPL_CODE = "kernel-gen-1-runtime";
    const CLONE = "0xCLONE";

    function view(overrides: Record<string, string> = {}): ChainView {
      return {
        code: new Map<string, string>(Object.entries({ [CLONE]: cloneCode(IMPL), [IMPL]: IMPL_CODE, ...overrides })),
      };
    }

    function registry(claimed = IMPL): Registry {
      return {
        claimedImplementationFor: new Map([[CLONE, claimed]]),
        generationOfImplCode: new Map([[IMPL_CODE, 1]]),
      };
    }

    const expected = { implementation: IMPL, implementationCode: IMPL_CODE, generation: 1 };

    it("the honest chain holds end to end", function () {
      expect(new CodeIdentityChain().chainHolds(view(), registry(), CLONE, expected)).to.equal(true);
    });

    it("THE DISCRIMINATOR — clone bytes correct, implementation identity WRONG, claim must FAIL", function () {
      const chain = new CodeIdentityChain();
      // The clone is a canonical EIP-1167 pointing at exactly the right address.
      expect(chain.cloneShapeIsCanonical(view(), CLONE, IMPL)).to.equal(true);
      // But that address holds different code than the audited kernel.
      const tampered = view({ [IMPL]: "some-other-runtime" });
      expect(chain.chainHolds(tampered, registry(), CLONE, expected)).to.equal(false);
    });

    it("I-CODE-IDENTITY-LINKAGE — the implementation address comes from the CLONE BYTES", function () {
      const chain = new CodeIdentityChain();
      expect(chain.implementationOf(view(), registry("0xLIAR"), CLONE)).to.equal(IMPL);
    });

    it("I-IMPL-NONVACUOUS — a clone delegating into a codeless address fails", function () {
      const chain = new CodeIdentityChain();
      const codeless = view({ [IMPL]: "" });
      expect(chain.implementationIsNonVacuous(codeless, IMPL)).to.equal(false);
      expect(chain.chainHolds(codeless, registry(), CLONE, expected)).to.equal(false);
    });

    it("I-CLONE-BYTES-EXACT — a superset proxy containing the template is rejected", function () {
      const chain = new CodeIdentityChain();
      const superset = view({ [CLONE]: `${cloneCode(IMPL)}+extra-dispatch` });
      expect(chain.cloneShapeIsCanonical(superset, CLONE, IMPL)).to.equal(false);
    });

    it("per-clone immutable ARGS change the clone's code identity", function () {
      expect(cloneCode(IMPL, "0xVERIFIER_A")).to.not.equal(cloneCode(IMPL, "0xVERIFIER_B"));
      expect(cloneCode(IMPL, "0xVERIFIER_A")).to.not.equal(cloneCode(IMPL));
    });

    it("I-IDENTITY-TYPE-SEPARATION — eight typed identities, never one badge", function () {
      const chain = new CodeIdentityChain();
      const identities: readonly PublishedIdentity[] = [
        { name: "cloneCode", kind: "PROOF", value: cloneCode(IMPL), validUntil: null },
        { name: "implementationCode", kind: "PROOF", value: IMPL_CODE, validUntil: null },
        { name: "kernelGeneration", kind: "PROOF", value: "1", validUntil: null },
        { name: "verifierGeneration", kind: "OBSERVATION", value: "1", validUntil: null },
        { name: "policyGeneration", kind: "OBSERVATION", value: "1", validUntil: null },
        { name: "credentialGeneration", kind: "OBSERVATION", value: "1", validUntil: null },
        { name: "guardianGeneration", kind: "OBSERVATION", value: "1", validUntil: null },
        // The one identity that changes with NO transaction: containment expiry.
        { name: "safeState", kind: "OBSERVATION", value: "CONTAINED", validUntil: 30 },
      ];
      const published = chain.publish(identities);
      expect(published).to.have.length(8);
      expect(chain.publicationIsWellTyped(published)).to.equal(true);
    });

    it("a safe-state identity published without a valid-until is malformed", function () {
      const chain = new CodeIdentityChain();
      const bad: readonly PublishedIdentity[] = [
        { name: "safeState", kind: "OBSERVATION", value: "CONTAINED", validUntil: null },
      ];
      expect(chain.publicationIsWellTyped(chain.publish(bad))).to.equal(false);
    });
  });

  describe("mutation matrix — remediation mutants M19..M31 (vault model)", function () {
    /**
     * Same contract as `assertMutantKilled`, but the model is built from an
     * arbitrary option set so a mutant can be exercised in the scenario it
     * actually breaks. The vacuity guard is unchanged and non-negotiable.
     */
    function assertKilledInScenario(
      mutation: Mutation,
      guard: string,
      options: Omit<ConstructorParameters<typeof VaultVNextModel>[0], "mutations">,
      invariant: (m: VaultVNextModel) => boolean,
    ): void {
      const clean = new VaultVNextModel({ ...options });
      const mutant = new VaultVNextModel({ ...options, mutations: [mutation] });
      expect(invariant(clean), `${mutation}: the invariant must HOLD on the unmutated model`).to.equal(true);
      expect(invariant(mutant), `${mutation}: the invariant must FAIL on the mutant`).to.equal(false);
      expect(
        mutant.exercised.has(guard),
        `${mutation}: guard "${guard}" was never evaluated — this mutation test is VACUOUS`,
      ).to.equal(true);
    }

    it("M19 — PqOnly is admitted, and an always-true verifier then forges", function () {
      assertKilledInScenario(
        "M19_PQ_ONLY_MODE_ADMITTED",
        "auth/mode-admission",
        { identityModel: "ACCOUNT_PER_VAULT", credentialMode: "PQ_ONLY", verifierBehaviour: "ALWAYS_TRUE" },
        (m) => !m.forgeryReachable(),
      );
    });

    it("M20 — a plane's answer is combined disjunctively with the floor", function () {
      assertKilledInScenario(
        "M20_PLANE_ANSWER_IS_DISJUNCTIVE",
        "auth/conjunctive-composition",
        { identityModel: "ACCOUNT_PER_VAULT", credentialMode: "HYBRID", verifierBehaviour: "ALWAYS_TRUE" },
        (m) => !m.forgeryReachable(),
      );
    });

    it("M21 — the floor admits on well-formedness, conflating shape with possession", function () {
      assertKilledInScenario(
        "M21_FLOOR_ADMITS_ON_WELL_FORMEDNESS",
        "auth/floor",
        // The scenario matters: with an HONEST verifier the conjunction denies
        // anyway, so the broken floor is unobservable and the "kill" would be
        // vacuous. The mutant is only visible where the PLANE also says true.
        { identityModel: "ACCOUNT_PER_VAULT", credentialMode: "HYBRID", verifierBehaviour: "ALWAYS_TRUE" },
        (m) => !m.forgeryReachable(),
      );
    });

    it("M22 — immutability is treated as discharging the authenticator requirement", function () {
      assertKilledInScenario(
        "M22_IMMUTABILITY_DISCHARGES_AUTHENTICATOR_REQUIREMENT",
        "auth/kernel-positive-authenticator",
        { identityModel: "ACCOUNT_PER_VAULT", credentialMode: "PQ_ONLY", verifierImmutablyBound: true },
        (m) => !m.hasKernelPositiveAuthenticator(),
      );
    });

    it("M23 — escaping a hostile verifier requires that verifier", function () {
      assertMutantKilled("M23_VERIFIER_ESCAPE_IS_CIRCULAR", "auth/escape-circularity", (m) =>
        m.verifierEscapeIsEvaluable(),
      );
    });

    it("M24 — the containment budget window resets on every trigger", function () {
      assertMutantKilled(
        "M24_CONTAINMENT_BUDGET_WINDOW_RESETS",
        "emergency/budget-window",
        (m) => m.rollingFreezeReachable("EMERGENCY") === false,
      );
    });

    it("M25 — re-entering containment extends the expiry", function () {
      assertMutantKilled("M25_CONTAINMENT_REENTRY_EXTENDS", "emergency/reentry-is-noop", (m) => {
        m.enterContainmentBudgeted("EMERGENCY");
        const first = m.kernel.containmentExpiresAt;
        m.warp(5);
        m.enterContainmentBudgeted("EMERGENCY");
        return m.kernel.containmentExpiresAt === first;
      });
    });

    it("M26 — ingress stays open while egress is closed", function () {
      assertMutantKilled("M26_INGRESS_OPEN_WHILE_EGRESS_CLOSED", "state/ingress", (m) => {
        m.enterContainmentBudgeted("EMERGENCY");
        return m.ingressAvailable() === false;
      });
    });

    it("M27 — the credential's challenge right is unbounded, restoring the H-03 veto", function () {
      assertMutantKilled(
        "M27_CREDENTIAL_CHALLENGE_UNBOUNDED",
        "recovery/veto-boundedness",
        (m) => m.credentialHoldsUnboundedVeto() === false,
      );
    });

    it("M28 — roster material is believed without checking it against the commitment", function () {
      assertMutantKilled(
        "M28_GUARDIAN_ROSTER_NOT_COMMITMENT_BOUND",
        "guardian/constituency-binding",
        (m) =>
          m.rosterIsAuthoritative([{ address: "attacker", authMode: "ECDSA", contractBehaviour: "ATTESTS" }], 1) ===
          false,
      );
    });

    it("M29 — quorum distinctness is dropped, so one seat is counted repeatedly", function () {
      assertMutantKilled(
        "M29_QUORUM_DISTINCTNESS_DROPPED",
        "guardian/quorum-distinctness",
        (m) => m.countDistinctAttestations([1, 1, 1]) === 1,
      );
    });

    it("M30 — one hostile ERC-1271 guardian aborts the whole recovery", function () {
      const seats: readonly GuardianSeat[] = [
        { address: "g1", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
        { address: "g2", authMode: "ERC1271", contractBehaviour: "REVERTS" },
        { address: "g3", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
      ];
      assertKilledInScenario(
        "M30_GUARDIAN_CONTRACT_FAILURE_ABORTS_RECOVERY",
        "guardian/fault-isolation",
        { identityModel: "ACCOUNT_PER_VAULT", guardianSeats: seats },
        (m) => m.quorumReachable(seats, 2),
      );
    });

    it("M31 — 'did not revert' is counted as an ERC-1271 attestation", function () {
      const seats: readonly GuardianSeat[] = [
        { address: "g1", authMode: "ERC1271", contractBehaviour: "RETURNS_GARBAGE" },
        { address: "g2", authMode: "ERC1271", contractBehaviour: "SILENT" },
        { address: "g3", authMode: "ECDSA", contractBehaviour: "ATTESTS" },
      ];
      assertKilledInScenario(
        "M31_ATTESTATION_COUNTED_ON_NON_REVERT",
        "guardian/attestation-affirmative",
        { identityModel: "ACCOUNT_PER_VAULT", guardianSeats: seats },
        (m) => m.quorumReachable(seats, 2) === false,
      );
    });

    it("M58 — a successful guardian recovery leaves the credential's spent challenge budget in place", function () {
      // Lane W2 / Recovery Amendment section 2: never resetting silently
      // deletes the D1/H-15 defence for every credential after the first. The
      // discriminator OBSERVES the budget after an end-to-end recovery; it never
      // asserts on the way there.
      assertMutantKilled("M58_RECOVERY_SUCCESS_DOES_NOT_RESET_CHALLENGE_BUDGET", "recovery/execute", (m) => {
        for (let i = 0; i < CREDENTIAL_CHALLENGE_LIMIT; i++) {
          if (m.initiateRecovery("GUARDIAN", heldCredential(`m58-${i}`)).kind !== "OK") return false;
          if (m.challengeRecoveryByCredential().kind !== "OK") return false;
        }
        if (m.kernel.credentialChallengesUsed !== CREDENTIAL_CHALLENGE_LIMIT) return false;
        if (!recoveryCompletesEndToEnd(m)) return false;
        // Re-read through a widened binding: control-flow narrowing would
        // otherwise pin the property to the literal limit across the call above.
        const budgetAfterRecovery: number = m.kernel.credentialChallengesUsed;
        return budgetAfterRecovery === 0;
      });
    });
  });

  describe("mutation matrix — remediation mutants M32..M57 (sub-models)", function () {
    /** Same three-part contract: holds clean, fails mutated, guard exercised. */
    function assertSubModelKilled<T extends { exercised: Set<string> }>(
      mutation: RemediationMutation,
      guard: string,
      build: (mutations: readonly RemediationMutation[]) => T,
      invariant: (subject: T) => boolean,
    ): void {
      const clean = build([]);
      const mutant = build([mutation]);
      expect(invariant(clean), `${mutation}: the invariant must HOLD on the unmutated model`).to.equal(true);
      expect(invariant(mutant), `${mutation}: the invariant must FAIL on the mutant`).to.equal(false);
      expect(
        mutant.exercised.has(guard),
        `${mutation}: guard "${guard}" was never evaluated — this mutation test is VACUOUS`,
      ).to.equal(true);
    }

    const lat = (ms: readonly RemediationMutation[]) => new CryptoLattice(ms);

    it("M32 — a profile is summarised by MAX over clauses instead of MIN", function () {
      assertSubModelKilled(
        "M32_PROFILE_SUMMARY_IS_MAX_OVER_CLAUSES",
        "lattice/profile-aggregate",
        lat,
        (l) => l.minRoots(HYBRID_OR_ECDSA) === 1,
      );
    });

    it("M33 — the clause-covering quantifier is flipped, admitting a weak alternative", function () {
      assertSubModelKilled(
        "M33_CLAUSE_COVERING_QUANTIFIER_FLIPPED",
        "lattice/covering",
        lat,
        // Observed on covers() directly. Through transitionAllowed the mutant is
        // MASKED by the independence rule, and a kill credited there would be
        // attributed to a guard this mutation did not break.
        (l) => l.covers(HYBRID, HYBRID_OR_ECDSA) === false,
      );
    });

    it("M34 — cross-family dominance is permitted", function () {
      assertSubModelKilled(
        "M34_CROSS_FAMILY_DOMINANCE_PERMITTED",
        "lattice/factor-dominance",
        lat,
        // Observed on clauseDominates directly: through transitionAllowed the
        // anchoring rule refuses first and would mask this mutation.
        (l) => l.clauseDominates([ML_DSA_87], [ECDSA]) === false,
      );
    });

    it("M35 — the independent-root count is allowed to decrease", function () {
      assertSubModelKilled(
        "M35_INDEPENDENCE_ROOTS_MAY_DECREASE",
        "lattice/independence",
        lat,
        (l) => l.transitionAllowed(HYBRID, CORRELATED_PAIR).ok === false,
      );
    });

    it("M36 — a clause need not carry a kernel-evaluable possession test", function () {
      assertSubModelKilled(
        "M36_ANCHORED_FACTOR_NOT_REQUIRED",
        "lattice/anchored-factor",
        lat,
        (l) => l.everyClauseAnchored(PQ_ONLY_87) === false,
      );
    });

    it("M37 — the status lattice is no longer absorbing", function () {
      assertSubModelKilled("M37_DISALLOWED_MAY_BE_REACTIVATED", "lattice/status-transition", lat, (l) => {
        l.setStatus("ML_DSA_65", "DISALLOWED");
        return l.setStatus("ML_DSA_65", "ACTIVE").ok === false;
      });
    });

    it("M38 — incomparable transitions are permitted instead of refused", function () {
      assertSubModelKilled(
        "M38_INCOMPARABLE_TRANSITIONS_PERMITTED",
        "lattice/transition",
        lat,
        (l) => l.transitionAllowed(HYBRID, ECDSA_ONLY).ok === false,
      );
    });

    const DEST: Binding = {
      destinationVault: "vault-2",
      destinationVaultCodeHash: "0xVAULT2",
      destinationGeneration: 2,
      chainId: 1,
      nonce: 1,
      deadline: 1000,
      disposition: "FULL_BALANCE",
    };

    function mig(
      ms: readonly RemediationMutation[],
      assets: readonly (readonly [string, AssetKind])[],
    ): MigrationMachine {
      const m = new MigrationMachine(ms);
      for (const [id, kind] of assets) m.addAsset(id, kind, 100n);
      m.bind(true, true, DEST);
      m.warp(m.bindDelay());
      m.retire();
      return m;
    }

    it("M39 — one failing entry aborts the whole migration", function () {
      const assets = [
        ["eth", "ETH"],
        ["blacklisted", "ERC20_REVERTS"],
      ] as const;
      assertSubModelKilled(
        "M39_ENTRY_FAILURE_ABORTS_EVERYTHING",
        "migration/entry-isolation",
        (ms) => mig(ms, assets),
        (m) => {
          m.egress("eth");
          m.egress("blacklisted");
          return m.entries.get("eth")!.status === "MOVED";
        },
      );
    });

    it("M40 — the binding freezes an asset SET, so an airdrop is unreachable", function () {
      assertSubModelKilled(
        "M40_BINDING_FIXES_AMOUNTS_NOT_DISPOSITION",
        "migration/egress",
        (ms) => mig(ms, [["eth", "ETH"]]),
        (m) => {
          m.addAsset("airdrop", "ERC20_WELL_BEHAVED", 5n);
          return m.egress("airdrop").ok;
        },
      );
    });

    it("M41 — the terminal state closes egress, making retirement a trap", function () {
      assertSubModelKilled(
        "M41_RETIRED_CLOSES_EGRESS",
        "migration/egress-in-terminal-state",
        (ms) => mig(ms, [["eth", "ETH"]]),
        (m) => m.egress("eth").ok,
      );
    });

    it("M42 — ABANDONED becomes absorbing, so a later transfer cannot resolve it", function () {
      assertSubModelKilled(
        "M42_ABANDONED_IS_ABSORBING",
        "migration/retry-from-abandoned",
        (ms) => mig(ms, [["usdc", "ERC20_WELL_BEHAVED"]]),
        (m) => {
          m.abandon("usdc");
          return m.egress("usdc").ok;
        },
      );
    });

    it("M43 — the bind delay drops below the recovery delay", function () {
      assertSubModelKilled(
        "M43_BIND_DELAY_BELOW_RECOVERY_DELAY",
        "migration/bind-delay",
        (ms) => new MigrationMachine(ms),
        (m) => m.bindDelay() >= RECOVERY_DELAY_DAYS,
      );
    });

    it("M44 — the egress recipient is taken from the caller", function () {
      assertSubModelKilled(
        "M44_EGRESS_RECIPIENT_FROM_CALLER",
        "migration/recipient-source",
        (ms) => mig(ms, [["eth", "ETH"]]),
        (m) => {
          m.egress("eth", "attacker");
          return m.lastRecipient === "vault-2";
        },
      );
    });

    it("M45 — settlement is recorded on a non-reverting call, not an observed decrease", function () {
      assertSubModelKilled(
        "M45_SETTLEMENT_ON_NON_REVERT",
        "migration/settlement-evidence",
        (ms) => mig(ms, [["liar", "ERC20_RETURNS_FALSE"]]),
        (m) => {
          m.egress("liar");
          return m.entries.get("liar")!.status !== "MOVED";
        },
      );
    });

    const IMPL = "0xIMPL_GEN1";
    const IMPL_CODE = "kernel-gen-1-runtime";
    const CLONE = "0xCLONE";
    const REGISTRY: Registry = {
      claimedImplementationFor: new Map([[CLONE, "0xLIAR"]]),
      generationOfImplCode: new Map([[IMPL_CODE, 1]]),
    };
    const VIEW: ChainView = {
      code: new Map([
        [CLONE, cloneCode(IMPL)],
        [IMPL, IMPL_CODE],
      ]),
    };

    const chainOf = (ms: readonly RemediationMutation[]) => new CodeIdentityChain(ms);

    it("M46 — the implementation address is read from a registry, not from the clone bytes", function () {
      assertSubModelKilled(
        "M46_IMPL_ADDRESS_FROM_REGISTRY",
        "identity/linkage",
        chainOf,
        (c) => c.implementationOf(VIEW, REGISTRY, CLONE) === IMPL,
      );
    });

    it("M47 — clone identity is matched by prefix, admitting a superset proxy", function () {
      const superset: ChainView = {
        code: new Map([
          [CLONE, `${cloneCode(IMPL)}+extra-dispatch`],
          [IMPL, IMPL_CODE],
        ]),
      };
      assertSubModelKilled(
        "M47_CLONE_MATCHED_BY_PREFIX",
        "identity/clone-exactness",
        chainOf,
        (c) => c.cloneShapeIsCanonical(superset, CLONE, IMPL) === false,
      );
    });

    it("M48 — the eight identities are published as one aggregate badge", function () {
      const identities: readonly PublishedIdentity[] = [
        { name: "cloneCode", kind: "PROOF", value: cloneCode(IMPL), validUntil: null },
        { name: "safeState", kind: "OBSERVATION", value: "CONTAINED", validUntil: 30 },
      ];
      assertSubModelKilled("M48_IDENTITIES_PUBLISHED_AS_ONE_AGGREGATE", "identity/publication-shape", chainOf, (c) =>
        c.publicationIsWellTyped(c.publish(identities)),
      );
    });

    it("M49 — a clone delegating into a codeless account passes unchecked", function () {
      const codeless: ChainView = {
        code: new Map([
          [CLONE, cloneCode(IMPL)],
          [IMPL, ""],
        ]),
      };
      assertSubModelKilled(
        "M49_IMPL_VACUITY_UNCHECKED",
        "identity/impl-nonvacuity",
        chainOf,
        (c) => c.implementationIsNonVacuous(codeless, IMPL) === false,
      );
    });

    // -----------------------------------------------------------------------
    // M50..M57 — the final architecture-correction pass
    // -----------------------------------------------------------------------

    /**
     * Two DECLARED targets. Nothing here asserts anything about any real
     * network: the point of the sub-model is that a limit is a per-target,
     * per-fork PARAMETER, so the test supplies parameters. `RAISED_LIMIT_CHAIN`
     * is a hypothetical used to prove the budget aggregates by MIN — it is not
     * a claim that any chain has these values.
     */
    const NARROW_TARGET: DeploymentTarget = {
      chain: "narrow-chain",
      fork: "current",
      runtimeLimit: 24_576,
      initcodeLimit: 49_152,
    };
    const RAISED_LIMIT_CHAIN: DeploymentTarget = {
      chain: "hypothetical-raised-limit-chain",
      fork: "hypothetical",
      runtimeLimit: 65_536,
      initcodeLimit: 131_072,
    };
    /** The shape of the real monolith: runtime UNDER the limit, initcode OVER it. */
    const MONOLITH: CompiledArtifact = { runtime: 23_239, initcode: 24_582 };

    const sizeOf = (ms: readonly RemediationMutation[]) => new SizeModel(ms);

    it("M50 — a child's INITCODE is judged against the RUNTIME limit", function () {
      // 23,239 <= 24,576 so it deploys; 24,582 > 24,576 but that comparison is
      // meaningless, and 24,582 <= 49,152 so nothing is breached. A model that
      // conflates the two bounds refuses a contract that deploys in reality.
      assertSubModelKilled(
        "M50_INITCODE_JUDGED_AGAINST_RUNTIME_LIMIT",
        "size/initcode-bound",
        sizeOf,
        (s) => s.deployable(NARROW_TARGET, MONOLITH).ok,
      );
    });

    it("M51 — the portability budget tracks the LARGEST network limit, not the smallest", function () {
      // A kernel of 30,000 fits the raised-limit chain and does NOT fit the
      // narrow one. Portability is the MIN, so it must be refused.
      const oversized: CompiledArtifact = { runtime: 30_000, initcode: 31_000 };
      assertSubModelKilled(
        "M51_PORTABILITY_BUDGET_TRACKS_THE_NETWORK",
        "size/budget-aggregate",
        sizeOf,
        (s) => s.withinPortabilityBudget([NARROW_TARGET, RAISED_LIMIT_CHAIN], oversized).ok === false,
      );
    });

    /** A vault holding one manifested token and one hostile UNSOLICITED token. */
    const migrationWithUnsolicited = (ms: readonly RemediationMutation[]) => {
      const m = new MigrationMachine(ms);
      m.addAsset("USDC", "ERC20_WELL_BEHAVED", 1_000n);
      m.receiveUnsolicited("HOSTILE", "ERC20_REVERTS", 1n);
      m.bind(true, true, {
        destinationVault: "0xDEST",
        destinationVaultCodeHash: "0xHASH",
        destinationGeneration: 2,
        chainId: 1,
        nonce: 1,
        deadline: 100,
        disposition: "FULL_BALANCE",
      });
      return m;
    };

    it("M52 — an unsolicited asset vetoes the egress of a manifested one", function () {
      assertSubModelKilled(
        "M52_UNSOLICITED_ASSET_VETOES_MANIFESTED_EGRESS",
        "migration/unsolicited-nonveto",
        migrationWithUnsolicited,
        (m) => m.manifestedEntriesExitIndependently(),
      );
    });

    it("M53 — retirement waits for a zero balance across every token", function () {
      assertSubModelKilled(
        "M53_RETIREMENT_REQUIRES_GLOBAL_ZERO_BALANCE",
        "migration/retirement-condition",
        (ms) => {
          const m = migrationWithUnsolicited(ms);
          // The manifested asset leaves; the hostile one cannot, and never will.
          m.egress("USDC");
          m.warp(BIND_DELAY_DAYS);
          return m;
        },
        (m) => m.retire().ok,
      );
    });

    const BUILD_WITH_IMMUTABLES: BuildIdentity = {
      buildTuple: "solc-0.8.24|cancun|opt-200",
      immutableRanges: [[18_627, 18_659]],
      normalizedRuntime: runtimeWithImmutables("kernel-gen-1-runtime", ZERO_PAYLOAD),
    };
    const ADDR = "0xIMPL_A";

    it("M54 — one universal source-level hash is assumed valid at every address", function () {
      // A CORRECT deployment: its immutable payload is genuinely derived from
      // its own address. A checker that compares straight to the build's
      // normalized runtime REJECTS it — the failure the narrowing names.
      const correct = {
        address: ADDR,
        runtime: runtimeWithImmutables("kernel-gen-1-runtime", expectedPayloadFor(ADDR)),
      };
      assertSubModelKilled(
        "M54_BUILD_IDENTITY_USED_AS_DEPLOYMENT_IDENTITY",
        "identity/build-vs-deployment",
        chainOf,
        (c) => c.matchesBuild(BUILD_WITH_IMMUTABLES, correct),
      );
    });

    it("M55 — the immutable ranges are masked but never independently re-derived", function () {
      // A FORGED deployment: correct everywhere except inside the masked range.
      const forged = { address: ADDR, runtime: runtimeWithImmutables("kernel-gen-1-runtime", "derived(0xATTACKER)") };
      assertSubModelKilled(
        "M55_MASK_WITHOUT_REDERIVATION",
        "identity/rederivation",
        chainOf,
        (c) => c.matchesBuild(BUILD_WITH_IMMUTABLES, forged) === false,
      );
    });

    it("M56 — the factory's implementation target can be retargeted after deployment", function () {
      assertSubModelKilled(
        "M56_FACTORY_IMPLEMENTATION_RETARGETABLE",
        "factory/retarget",
        (ms) => new FactoryGenerationModel("0xKERNEL_GEN1", 1, ms),
        (f) => f.implementationIsImmutable(),
      );
    });

    it("M57 — a bounded challenge is counted as an increase in the compromise cut", function () {
      // The SAME guardian path, with and without the bounded challenge. A delay
      // buys time, visibility and cost; it adds no mandatory principal, so the
      // two cuts must be equal.
      const withChallenge: AttackPath = {
        name: "guardian quorum, challengeable",
        mandatoryIndependentPrincipals: 2,
        boundedChallenges: 2,
      };
      const withoutChallenge: AttackPath = {
        name: "guardian quorum, unchallengeable",
        mandatoryIndependentPrincipals: 2,
        boundedChallenges: 0,
      };
      assertSubModelKilled(
        "M57_BOUNDED_CHALLENGE_COUNTED_AS_A_CUT",
        "cuts/delay-is-not-a-principal",
        (ms) => new AuthorityCutModel(ms),
        (c) => c.cut(withChallenge) === c.cut(withoutChallenge),
      );
    });
  });

  // =========================================================================
  describe("mutation matrix integrity", function () {
    it("covers every declared mutation exactly once", function () {
      const declared: readonly Mutation[] = [
        "M1_GENERIC_MODULE_EXECUTION",
        "M2_STALE_CREDENTIAL_GENERATION_VALID",
        "M3_STALE_GUARDIAN_GENERATION_VALID",
        "M4_FAILED_PLANE_REQUIRED_FOR_ITS_OWN_RECOVERY",
        "M5_CONTROLLER_KERNEL_DIVERGENCE_UNDETECTED",
        "M6_EMERGENCY_CREATES_STRONGER_AUTHORITY",
        "M7_EMERGENCY_PERMANENT_RECOVERY_VETO",
        "M8_MIGRATION_OMITS_DESTINATION_CODEHASH",
        "M9_MIGRATION_ALLOWS_GENERATION_SUBSTITUTION",
        "M10_SILENT_CRYPTO_DOWNGRADE",
        "M11_ALWAYS_TRUE_VERIFIER_IS_STRONG_EVIDENCE",
        "M12_ASSURANCE_ACTUATES_CUSTODY",
        "M13_POLICY_PLANE_GAINS_ASSET_AUTHORITY",
        "M14_GUARDIAN_CONTROLLER_INDIRECT_TAKEOVER_OMITTED",
        "M15_HOSTED_SERVICE_REQUIRED_FOR_RECOVERY",
        "M16_ONE_SIDED_REFERENCE_MODEL_DIVERGENCE",
        "M17_UNAVAILABLE_PLANE_STRANDS_LOCAL_RECOVERY",
        "M18_OLD_GENERATION_CROSSES_BOUNDARY",
        "M19_PQ_ONLY_MODE_ADMITTED",
        "M20_PLANE_ANSWER_IS_DISJUNCTIVE",
        "M21_FLOOR_ADMITS_ON_WELL_FORMEDNESS",
        "M22_IMMUTABILITY_DISCHARGES_AUTHENTICATOR_REQUIREMENT",
        "M23_VERIFIER_ESCAPE_IS_CIRCULAR",
        "M24_CONTAINMENT_BUDGET_WINDOW_RESETS",
        "M25_CONTAINMENT_REENTRY_EXTENDS",
        "M26_INGRESS_OPEN_WHILE_EGRESS_CLOSED",
        "M27_CREDENTIAL_CHALLENGE_UNBOUNDED",
        "M28_GUARDIAN_ROSTER_NOT_COMMITMENT_BOUND",
        "M29_QUORUM_DISTINCTNESS_DROPPED",
        "M30_GUARDIAN_CONTRACT_FAILURE_ABORTS_RECOVERY",
        "M31_ATTESTATION_COUNTED_ON_NON_REVERT",
        // Numbered after the remediation sub-model's M32..M57 so the two unions
        // stay disjoint and contiguous (asserted below). Added by Lane W2.
        "M58_RECOVERY_SUCCESS_DOES_NOT_RESET_CHALLENGE_BUDGET",
      ];
      expect(new Set(declared).size, "duplicate mutation identifier").to.equal(declared.length);
      expect(declared).to.have.length(32);

      const declaredRemediation: readonly RemediationMutation[] = [
        "M32_PROFILE_SUMMARY_IS_MAX_OVER_CLAUSES",
        "M33_CLAUSE_COVERING_QUANTIFIER_FLIPPED",
        "M34_CROSS_FAMILY_DOMINANCE_PERMITTED",
        "M35_INDEPENDENCE_ROOTS_MAY_DECREASE",
        "M36_ANCHORED_FACTOR_NOT_REQUIRED",
        "M37_DISALLOWED_MAY_BE_REACTIVATED",
        "M38_INCOMPARABLE_TRANSITIONS_PERMITTED",
        "M39_ENTRY_FAILURE_ABORTS_EVERYTHING",
        "M40_BINDING_FIXES_AMOUNTS_NOT_DISPOSITION",
        "M41_RETIRED_CLOSES_EGRESS",
        "M42_ABANDONED_IS_ABSORBING",
        "M43_BIND_DELAY_BELOW_RECOVERY_DELAY",
        "M44_EGRESS_RECIPIENT_FROM_CALLER",
        "M45_SETTLEMENT_ON_NON_REVERT",
        "M46_IMPL_ADDRESS_FROM_REGISTRY",
        "M47_CLONE_MATCHED_BY_PREFIX",
        "M48_IDENTITIES_PUBLISHED_AS_ONE_AGGREGATE",
        "M49_IMPL_VACUITY_UNCHECKED",
        "M50_INITCODE_JUDGED_AGAINST_RUNTIME_LIMIT",
        "M51_PORTABILITY_BUDGET_TRACKS_THE_NETWORK",
        "M52_UNSOLICITED_ASSET_VETOES_MANIFESTED_EGRESS",
        "M53_RETIREMENT_REQUIRES_GLOBAL_ZERO_BALANCE",
        "M54_BUILD_IDENTITY_USED_AS_DEPLOYMENT_IDENTITY",
        "M55_MASK_WITHOUT_REDERIVATION",
        "M56_FACTORY_IMPLEMENTATION_RETARGETABLE",
        "M57_BOUNDED_CHALLENGE_COUNTED_AS_A_CUT",
      ];
      expect(new Set(declaredRemediation).size, "duplicate remediation identifier").to.equal(
        declaredRemediation.length,
      );
      expect(declaredRemediation).to.have.length(26);

      // The two unions are disjoint and contiguous M1..M58. A gap or an overlap
      // means a mutant was renumbered without its matrix entry following it.
      const numbers = [...declared, ...declaredRemediation]
        .map((id) => Number(/^M(\d+)_/.exec(id)?.[1]))
        .sort((a, b) => a - b);
      expect(numbers).to.deep.equal(Array.from({ length: 58 }, (_, i) => i + 1));
    });

    /**
     * A REGRESSION assertion, not a mutant. It pins the four-way truth table of
     * architecture 19.0 directly, so the category error that revision corrected
     * — comparing a child's INITCODE against the RUNTIME limit — fails this
     * suite if it is ever reintroduced, including by a change that leaves every
     * mutant alive.
     */
    it("EIP-170 REGRESSION — initcode is never judged against the runtime limit", function () {
      const s = new SizeModel();
      const target: DeploymentTarget = {
        chain: "narrow-chain",
        fork: "current",
        runtimeLimit: 24_576,
        initcodeLimit: 49_152,
      };

      // 1. runtime over the runtime limit => deployment FAILS.
      expect(
        s.deployable(target, { runtime: 24_866, initcode: 25_000 }).ok,
        "runtime over the limit must fail",
      ).to.equal(false);

      // 2. initcode over the RUNTIME limit but under the INITCODE limit =>
      //    NOTHING FOLLOWS. This is the exact shape of the real monolith
      //    (runtime 23,239 / initcode 24,582) and it deploys today.
      expect(
        s.deployable(target, { runtime: 23_239, initcode: 24_582 }).ok,
        "initcode above the RUNTIME limit is not a deployment failure",
      ).to.equal(true);

      // 3. initcode over the INITCODE limit => creation FAILS.
      expect(
        s.deployable(target, { runtime: 1_000, initcode: 49_153 }).ok,
        "initcode over its own limit must fail",
      ).to.equal(false);

      // 4. The two bounds are DIFFERENT numbers. A model in which they coincide
      //    cannot discriminate cases 2 and 3 at all.
      expect(target.initcodeLimit).to.not.equal(target.runtimeLimit);
      expect(target.initcodeLimit).to.equal(2 * target.runtimeLimit);
    });

    it("PORTABILITY REGRESSION — the budget is the MIN over declared targets", function () {
      const s = new SizeModel();
      const narrow: DeploymentTarget = { chain: "a", fork: "f", runtimeLimit: 24_576, initcodeLimit: 49_152 };
      const wide: DeploymentTarget = { chain: "b", fork: "g", runtimeLimit: 65_536, initcodeLimit: 131_072 };

      expect(s.portabilityBudget([narrow, wide])).to.equal(24_576);
      expect(s.portabilityBudget([wide])).to.equal(65_536);

      // The internal reserve is a WalletWall quantity subtracted from a
      // WalletWall budget — never from a protocol limit.
      expect(s.targetCeiling([narrow, wide], 2_600)).to.equal(21_976);

      // A kernel one byte over the budget is a POLICY failure on the narrow
      // target while remaining perfectly deployable on the wide one.
      const oversized: CompiledArtifact = { runtime: 24_577, initcode: 25_000 };
      expect(s.withinPortabilityBudget([narrow, wide], oversized).ok).to.equal(false);
      expect(s.deployable(wide, oversized).ok).to.equal(true);
      expect(s.deployable(narrow, oversized).ok).to.equal(false);
    });

    it("D1 REGRESSION — a bounded challenge never moves a compromise cut", function () {
      const c = new AuthorityCutModel();
      const guardianPath: AttackPath = {
        name: "guardian quorum",
        mandatoryIndependentPrincipals: 2,
        boundedChallenges: 2,
      };
      const frontDoor: AttackPath = {
        name: "both credential factors",
        mandatoryIndependentPrincipals: 2,
        boundedChallenges: 0,
      };
      const migration: AttackPath = {
        name: "quorum AND credential",
        mandatoryIndependentPrincipals: 3,
        boundedChallenges: 0,
      };

      // guardian compromise cut = k, with or without the challenge
      expect(c.cut(guardianPath)).to.equal(2);
      expect(c.cut({ ...guardianPath, boundedChallenges: 0 })).to.equal(2);
      // the migration path is strictly dominated and never the system minimum
      expect(c.cut(migration)).to.be.greaterThan(c.cut(guardianPath));
      expect(c.systemCut([guardianPath, frontDoor, migration])).to.equal(2);
    });

    it("D8 REGRESSION — a new generation is a deployment, never a permission", function () {
      const gen1 = new FactoryGenerationModel("0xKERNEL_GEN1", 1);
      expect(gen1.implementationIsImmutable()).to.equal(true);
      expect(gen1.setImplementation("0xKERNEL_GEN2").ok).to.equal(false);
      expect(gen1.implementationTarget()).to.equal("0xKERNEL_GEN1");

      const gen2 = gen1.nextGeneration("0xKERNEL_GEN2");
      expect(gen2.generation).to.equal(2);
      expect(gen2.implementationTarget()).to.equal("0xKERNEL_GEN2");
      // The new generation leaves the old factory completely untouched.
      expect(gen1.implementationTarget()).to.equal("0xKERNEL_GEN1");
      expect(gen1.generation).to.equal(1);
    });

    it("an unmutated model satisfies every mutation-matrix invariant simultaneously", function () {
      const m = vnext();
      expect(m.genericExecutionAvailable()).to.equal(false);
      expect(m.authorityClosure("ASSURANCE").has("MOVE_ASSETS")).to.equal(false);
      expect(m.authorityClosure("POLICY_PLANE").has("MOVE_ASSETS")).to.equal(false);
      expect(m.parityDigest()).to.equal(m.siblingParityDigest());
      for (const p of ALL_PLANES) expect(m.recoveryConsultsPlane(p)).to.equal(false);
    });
  });
});
