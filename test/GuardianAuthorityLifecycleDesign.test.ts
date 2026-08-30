import { expect } from "chai";

/**
 * Executable design model for docs/Guardian_Authority_Design.md v4.
 *
 * This is deliberately not a model of code that already ships. It pins the locked
 * target state machine before the implementation lane starts, so reviewers can
 * distinguish proposed authority semantics from current WalletWallVault behavior.
 * The production and simulator contracts are exercised separately by
 * GuardianRecoverySimulatorParity.test.ts.
 */

const OWNER = "vault-owner";
const ADMIN = "contract-admin";
const CONTROLLER = "canonical-controller";
const RECOVERY_DELAY = 7;

type Recovery = {
  targetCredential: string;
  executeAfter: number;
  supports: Set<string>;
};

type GuardianIntent = {
  epoch: number;
  nonce: number;
  newGuardians: string[];
};

function required(count: number): number {
  return Math.floor(count / 2) + 1;
}

function unique(values: string[]): boolean {
  return new Set(values).size === values.length;
}

class VaultAuthorityModel {
  readonly stableOwner = OWNER;
  readonly contractAdmin = ADMIN;
  readonly canonicalController = CONTROLLER;
  guardians: string[] = [];
  recovery?: Recovery;
  credential = "credential-0";
  credentialEpoch = 0;
  paused = false;

  constructor(
    private readonly ownerReplacementMutant = false,
    private readonly ownerCancellationMutant = false,
  ) {}

  guardianQuorum(): number {
    return required(this.guardians.length);
  }

  recoveryApproved(): boolean {
    return this.recovery !== undefined && this.recovery.supports.size >= this.guardianQuorum();
  }

  /** PUSH sink: the vault authenticates provenance, while the controller authenticates quorum. */
  pushGuardianSet(caller: string, next: string[]): void {
    if (caller !== this.canonicalController && !(this.ownerReplacementMutant && caller === this.stableOwner)) {
      throw new Error("NotGuardianController");
    }
    if (next.length === 0 || !unique(next) || next.includes(this.stableOwner)) {
      throw new Error("InvalidGuardianSet");
    }
    if (this.recoveryApproved()) throw new Error("RecoveryAlreadyApproved");

    // A set change may clear an under-supported request, but never one that the
    // current constituency has already approved.
    this.recovery = undefined;
    this.guardians = [...next];
  }

  initiateRecovery(caller: string, targetCredential: string, now: number): void {
    if (this.paused) throw new Error("Paused");
    if (!this.guardians.includes(caller)) throw new Error("NotAGuardian");
    if (this.recovery !== undefined) {
      if (now < this.recovery.executeAfter) throw new Error("RecoveryAlreadyExists");
      if (this.recoveryApproved()) throw new Error("RecoveryAlreadyApproved");
    }
    this.recovery = { targetCredential, executeAfter: now + RECOVERY_DELAY, supports: new Set() };
  }

  supportRecovery(caller: string): void {
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    if (!this.guardians.includes(caller)) throw new Error("NotAGuardian");
    if (this.recovery.supports.has(caller)) throw new Error("AlreadySupported");
    this.recovery.supports.add(caller);
  }

  executeRecovery(now: number): void {
    if (this.paused) throw new Error("Paused");
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    if (now < this.recovery.executeAfter) throw new Error("RecoveryNotReady");
    if (!this.recoveryApproved()) throw new Error("InsufficientSupports");
    this.credential = this.recovery.targetCredential;
    this.credentialEpoch++;
    this.recovery = undefined;
  }

  rotateCredential(next: string): void {
    this.credential = next;
    this.credentialEpoch++;
    // Locked precedence: credential rotation never destroys guardian authority.
  }

  cancelRecovery(caller: string): void {
    const controllerAuthorized = caller === this.canonicalController;
    const ownerMutantAuthorized = this.ownerCancellationMutant && caller === this.stableOwner;
    if (!controllerAuthorized && !ownerMutantAuthorized) {
      throw new Error("RecoveryCancellationDisabled");
    }
    this.recovery = undefined;
  }

  pause(caller: string): void {
    if (caller !== this.contractAdmin) throw new Error("NotAdmin");
    this.paused = true;
  }

  unpause(caller: string): void {
    if (caller !== this.contractAdmin) throw new Error("NotAdmin");
    this.paused = false;
  }

  snapshot() {
    return {
      guardians: [...this.guardians],
      credential: this.credential,
      credentialEpoch: this.credentialEpoch,
      paused: this.paused,
      recovery: this.recovery
        ? {
            targetCredential: this.recovery.targetCredential,
            executeAfter: this.recovery.executeAfter,
            supports: [...this.recovery.supports].sort(),
          }
        : undefined,
    };
  }
}

class GuardianControllerModel {
  epoch = 0;
  nonce = 0;
  recoveryNonce = 0;
  paused = false;

  constructor(readonly vault: VaultAuthorityModel) {}

  bootstrap(caller: string, initialGuardians: string[]): void {
    if (caller !== this.vault.stableOwner) throw new Error("NotStableOwner");
    if (this.epoch !== 0 || this.vault.guardians.length !== 0) throw new Error("AlreadyBootstrapped");
    this.vault.pushGuardianSet(CONTROLLER, initialGuardians);
    this.epoch = 1;
  }

  intent(next: string[]): GuardianIntent {
    return { epoch: this.epoch, nonce: this.nonce, newGuardians: [...next] };
  }

  replace(intent: GuardianIntent, approvals: string[]): void {
    if (this.paused) throw new Error("ControllerPaused");
    if (intent.epoch !== this.epoch) throw new Error("StaleGuardianEpoch");
    if (intent.nonce !== this.nonce) throw new Error("InvalidGuardianNonce");
    if (!unique(approvals) || approvals.some((guardian) => !this.vault.guardians.includes(guardian))) {
      throw new Error("InvalidGuardianApproval");
    }
    if (approvals.length < this.vault.guardianQuorum()) throw new Error("InsufficientGuardianApprovals");

    // Success-only state advancement: a vault rejection rolls the controller
    // state back in the real atomic EVM transaction.
    this.vault.pushGuardianSet(CONTROLLER, intent.newGuardians);
    this.epoch++;
    this.nonce++;
  }

  cancelRecovery(approvals: string[], signedEpoch = this.epoch, signedNonce = this.recoveryNonce): void {
    if (this.paused) throw new Error("ControllerPaused");
    if (signedEpoch !== this.epoch) throw new Error("StaleGuardianEpoch");
    if (signedNonce !== this.recoveryNonce) throw new Error("InvalidRecoveryNonce");
    if (!unique(approvals) || approvals.some((guardian) => !this.vault.guardians.includes(guardian))) {
      throw new Error("InvalidGuardianApproval");
    }
    if (approvals.length < this.vault.guardianQuorum()) throw new Error("InsufficientGuardianApprovals");
    this.vault.cancelRecovery(CONTROLLER);
    this.recoveryNonce++;
  }

  emergencyPause(): void {
    this.paused = true;
  }

  adoptLegacyState(): never {
    throw new Error("NoSafeInPlaceMigration");
  }
}

function bootstrapped(guardians = ["g1", "g2", "g3"], ownerReplacementMutant = false, ownerCancellationMutant = false) {
  const vault = new VaultAuthorityModel(ownerReplacementMutant, ownerCancellationMutant);
  const controller = new GuardianControllerModel(vault);
  controller.bootstrap(OWNER, guardians);
  return { vault, controller };
}

function approve(vault: VaultAuthorityModel): string[] {
  return vault.guardians.slice(0, vault.guardianQuorum());
}

function rejectsOwnerReplacement(vault: VaultAuthorityModel): boolean {
  try {
    vault.pushGuardianSet(OWNER, ["attacker"]);
    return false;
  } catch {
    return true;
  }
}

function preservesApprovedRecoveryAgainstOwnerCancellation(vault: VaultAuthorityModel): boolean {
  vault.initiateRecovery("g1", "honest-target", 0);
  vault.supportRecovery("g1");
  vault.supportRecovery("g2");
  try {
    vault.cancelRecovery(OWNER);
  } catch {
    // The target rejects the call; the mutant accepts and erases the request.
  }
  return vault.recoveryApproved();
}

describe("Guardian Authority lifecycle design model", function () {
  it("1. compromised stable owner cannot replace an established guardian set alone", function () {
    const { vault } = bootstrapped();
    expect(() => vault.pushGuardianSet(OWNER, ["attacker"])).to.throw("NotGuardianController");
    expect(vault.guardians).to.deep.equal(["g1", "g2", "g3"]);
  });

  it("2. compromised spending credentials cannot replace guardians alone", function () {
    const { vault } = bootstrapped();
    expect(() => vault.pushGuardianSet(vault.credential, ["attacker"])).to.throw("NotGuardianController");
  });

  it("3. successful recovery does not orphan guardian administration", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "recovered-credential", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    vault.executeRecovery(RECOVERY_DELAY);

    controller.replace(controller.intent(["g2", "g3", "g4"]), ["g1", "g2"]);
    expect(vault.credential).to.equal("recovered-credential");
    expect(vault.guardians).to.deep.equal(["g2", "g3", "g4"]);
  });

  it("4. one malicious guardian cannot erase an honest quorum", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "honest-recovery", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    expect(() => vault.initiateRecovery("g3", "attacker", RECOVERY_DELAY)).to.throw("RecoveryAlreadyApproved");
  });

  it("5. a malicious guardian minority cannot seize guardian authority", function () {
    const { vault, controller } = bootstrapped();
    expect(() => controller.replace(controller.intent(["attacker"]), ["g1"])).to.throw("InsufficientGuardianApprovals");
    expect(vault.guardians).to.deep.equal(["g1", "g2", "g3"]);
  });

  it("6. a malicious guardian majority can replace the set and recover (accepted trust limit)", function () {
    const { vault, controller } = bootstrapped();
    controller.replace(controller.intent(["a1", "a2", "a3"]), ["g1", "g2"]);
    vault.initiateRecovery("a1", "attacker-credential", 0);
    vault.supportRecovery("a1");
    vault.supportRecovery("a2");
    vault.executeRecovery(RECOVERY_DELAY);
    expect(vault.credential).to.equal("attacker-credential");
  });

  it("7. compromised stable owner cannot veto an approved recovery", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "honest-recovery", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    expect(() => vault.cancelRecovery(OWNER)).to.throw("RecoveryCancellationDisabled");
    vault.executeRecovery(RECOVERY_DELAY);
    expect(vault.credential).to.equal("honest-recovery");
  });

  it("8. honest owner has no permanent veto over a malicious guardian majority (explicit trust choice)", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "majority-choice", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    expect(() => vault.cancelRecovery(OWNER)).to.throw("RecoveryCancellationDisabled");
    vault.executeRecovery(RECOVERY_DELAY);
    expect(vault.credential).to.equal("majority-choice");
  });

  it("guardian quorum may cancel an under-supported request; a minority may not", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "mistake", 0);
    expect(() => controller.cancelRecovery(["g1"])).to.throw("InsufficientGuardianApprovals");
    controller.cancelRecovery(["g1", "g2"]);
    expect(vault.recovery).to.equal(undefined);
  });

  it("guardian quorum may cancel its own approved request, with dedicated replay protection", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "mistake", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    const nonce = controller.recoveryNonce;
    controller.cancelRecovery(["g1", "g2"], controller.epoch, nonce);
    expect(vault.recovery).to.equal(undefined);

    vault.initiateRecovery("g1", "new-request", 1);
    expect(() => controller.cancelRecovery(["g1", "g2"], controller.epoch, nonce)).to.throw("InvalidRecoveryNonce");
  });

  it("9. legitimate credential rotation during active recovery leaves the request intact", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "recovery-target", 0);
    vault.supportRecovery("g1");
    const before = vault.snapshot().recovery;
    vault.rotateCredential("rotated-credential");
    expect(vault.snapshot().recovery).to.deep.equal(before);
  });

  it("10. guardian change during an under-supported recovery invalidates that request", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "old-target", 0);
    vault.supportRecovery("g1");
    controller.replace(controller.intent(["g2", "g3", "g4"]), ["g1", "g2"]);
    expect(vault.recovery).to.equal(undefined);
  });

  it("11. guardian change after recovery quorum is rejected", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "approved-target", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    expect(() => controller.replace(controller.intent(["g2", "g3", "g4"]), ["g1", "g2"])).to.throw(
      "RecoveryAlreadyApproved",
    );
    expect(vault.guardians).to.deep.equal(["g1", "g2", "g3"]);
  });

  it("12. pause before quorum blocks initiation but not support already in progress", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "target", 0);
    vault.pause(ADMIN);
    expect(() => vault.initiateRecovery("g2", "replacement", RECOVERY_DELAY)).to.throw("Paused");
    expect(() => vault.supportRecovery("g1")).to.not.throw();
  });

  it("13. pause after quorum suspends execution without destroying authority", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "target", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    vault.pause(ADMIN);
    expect(() => vault.executeRecovery(RECOVERY_DELAY)).to.throw("Paused");
    expect(vault.recoveryApproved()).to.equal(true);
    vault.unpause(ADMIN);
    vault.executeRecovery(RECOVERY_DELAY);
  });

  it("14. controller nonce makes an already-consumed authorization unreplayable", function () {
    const { vault, controller } = bootstrapped();
    const intent = controller.intent(["g2", "g3", "g4"]);
    controller.replace(intent, approve(vault));
    expect(() => controller.replace(intent, ["g2", "g3"])).to.throw("StaleGuardianEpoch");
  });

  it("15. guardian authorization intentionally survives credential recovery", function () {
    const { vault, controller } = bootstrapped();
    const intent = controller.intent(["g2", "g3", "g4"]);
    vault.initiateRecovery("g1", "recovered", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    vault.executeRecovery(RECOVERY_DELAY);
    controller.replace(intent, ["g1", "g2"]);
    expect(vault.guardians).to.deep.equal(["g2", "g3", "g4"]);
  });

  it("16. a guardian-epoch change invalidates every authorization from the prior constituency", function () {
    const { vault, controller } = bootstrapped();
    const first = controller.intent(["g2", "g3", "g4"]);
    const staleSibling = controller.intent(["g1", "g3", "g4"]);
    controller.replace(first, approve(vault));
    expect(() => controller.replace(staleSibling, ["g2", "g3"])).to.throw("StaleGuardianEpoch");
  });

  it("17. threshold edges n=1,2,3,4,5 and MAX_GUARDIANS=32 are exact", function () {
    const expected = new Map([
      [1, 1],
      [2, 2],
      [3, 2],
      [4, 3],
      [5, 3],
      [32, 17],
    ]);
    for (const [count, quorum] of expected) {
      const guardians = Array.from({ length: count }, (_, index) => `g${index + 1}`);
      expect(bootstrapped(guardians).vault.guardianQuorum(), `n=${count}`).to.equal(quorum);
    }
  });

  it("18. zero-guardian bootstrap is owner-authorized exactly once", function () {
    const vault = new VaultAuthorityModel();
    const controller = new GuardianControllerModel(vault);
    expect(() => controller.bootstrap("attacker", ["a1"])).to.throw("NotStableOwner");
    controller.bootstrap(OWNER, ["g1"]);
    expect(() => controller.bootstrap(OWNER, ["attacker"])).to.throw("AlreadyBootstrapped");
  });

  it("19. legacy vault state has no unsafe in-place adoption path", function () {
    const { controller } = bootstrapped();
    expect(() => controller.adoptLegacyState()).to.throw("NoSafeInPlaceMigration");
  });

  it("20. production and simulator target models produce identical state", function () {
    const prod = bootstrapped();
    const sim = bootstrapped();
    for (const { vault, controller } of [prod, sim]) {
      vault.initiateRecovery("g1", "target", 0);
      vault.supportRecovery("g1");
      controller.replace(controller.intent(["g2", "g3", "g4"]), ["g1", "g2"]);
      vault.initiateRecovery("g2", "target-2", 1);
      vault.supportRecovery("g2");
    }
    expect(prod.vault.snapshot()).to.deep.equal(sim.vault.snapshot());
    expect({
      epoch: prod.controller.epoch,
      nonce: prod.controller.nonce,
      recoveryNonce: prod.controller.recoveryNonce,
    }).to.deep.equal({
      epoch: sim.controller.epoch,
      nonce: sim.controller.nonce,
      recoveryNonce: sim.controller.recoveryNonce,
    });
  });

  it("principal matrix: admin, credentials, and arbitrary caller cannot mutate guardians or cancel recovery", function () {
    const { vault } = bootstrapped();
    vault.initiateRecovery("g1", "target", 0);
    for (const principal of [ADMIN, vault.credential, "arbitrary-caller"]) {
      expect(() => vault.pushGuardianSet(principal, ["attacker"]), principal).to.throw("NotGuardianController");
      expect(() => vault.cancelRecovery(principal), principal).to.throw("RecoveryCancellationDisabled");
    }
  });

  it("controller emergency pause freezes only guardian administration; recovery remains callback-free and live", function () {
    const { vault, controller } = bootstrapped();
    vault.initiateRecovery("g1", "target", 0);
    vault.supportRecovery("g1");
    vault.supportRecovery("g2");
    controller.emergencyPause();
    expect(() => controller.replace(controller.intent(["g2", "g3", "g4"]), ["g1", "g2"])).to.throw("ControllerPaused");
    vault.executeRecovery(RECOVERY_DELAY);
    expect(vault.credential).to.equal("target");
  });

  it("accepted controller trust boundary: malicious canonical controller code could push an unauthorized set", function () {
    const { vault } = bootstrapped();
    vault.pushGuardianSet(CONTROLLER, ["attacker"]);
    expect(vault.guardians).to.deep.equal(["attacker"]);
  });

  it("mutation kill: owner-only established-set replacement violates I-GUARDIAN-INDEPENDENCE", function () {
    const target = bootstrapped().vault;
    const mutant = bootstrapped(["g1", "g2", "g3"], true, false).vault;
    expect(rejectsOwnerReplacement(target)).to.equal(true);
    expect(rejectsOwnerReplacement(mutant)).to.equal(false, "the same invariant kills the owner-authority mutant");
  });

  it("mutation kill: owner cancellation restores HIGH-6's indefinite veto", function () {
    const target = bootstrapped().vault;
    const mutant = bootstrapped(["g1", "g2", "g3"], false, true).vault;
    expect(preservesApprovedRecoveryAgainstOwnerCancellation(target)).to.equal(true);
    expect(preservesApprovedRecoveryAgainstOwnerCancellation(mutant)).to.equal(
      false,
      "the same liveness invariant kills the owner-cancellation mutant",
    );
  });
});
