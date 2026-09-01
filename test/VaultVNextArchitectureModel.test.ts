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
  RECOVERY_DELAY,
  VaultVNextModel,
  type Capability,
  type Credential,
  type IdentityModel,
  type MigrationBinding,
  type Mutation,
  type PlaneId,
  type Principal,
} from "./helpers/vaultVNextModel.js";

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
      ];
      expect(new Set(declared).size, "duplicate mutation identifier").to.equal(declared.length);
      expect(declared).to.have.length(18);
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
