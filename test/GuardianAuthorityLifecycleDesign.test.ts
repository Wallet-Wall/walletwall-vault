import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect } from "chai";

/**
 * Executable design model for docs/Guardian_Authority_Design.md v5.
 *
 * This is deliberately not a model of code that already ships. It pins the
 * remediated target state machine before the implementation lane starts. The
 * controller and consumer keep independent authority/operational copies, and
 * approvals are digest abstractions over the exact fields future EIP-712
 * signatures must bind. This is state-machine evidence, not cryptographic proof.
 */

const OWNER = "vault-owner";
const ADMIN = "contract-admin";
const CONTROLLER = "canonical-controller";
const EMERGENCY_PAUSER = "emergency-pauser";
const CONSUMER = "walletwall-vault";
const OTHER_CONSUMER = "other-consumer";
const CHAIN_ID = 31_337;
const RECOVERY_DELAY = 7;

type Recovery = {
  targetSigner: string;
  targetPqKeyHash: string;
  executeAfter: number;
  owner: string;
  consumer: string;
  guardianEpoch: number;
  supports: Set<string>;
};

/**
 * The minimized consumer PUSH payload (docs §7.6). `expectedCurrentGeneration` is the ONLY
 * synchrony field the consumer holds — one uint64 per subject, measured at +265 bytes. There is
 * deliberately no roster hash: that variant measured +507 and takes vault headroom to 307, under
 * this repository's own 600-byte stop threshold (docs §14.1).
 */
type GuardianPush = {
  expectedCurrentGeneration: number;
  nextGuardians: string[];
  newTreasuryThreshold: number;
};

/** Wall-clock expiry window for a quorum-approved request (H2 / I-RECOVERY-TERMINATION). */
const RECOVERY_EXPIRY_WINDOW = 14;

type IntentDomain = {
  chainId: number;
  verifyingContract: string;
};

type SetGuardiansIntent = {
  action: "SET_GUARDIANS";
  domain: IntentDomain;
  consumer: string;
  owner: string;
  currentGuardianHash: string;
  newGuardianHash: string;
  newGuardians: string[];
  newTreasuryThreshold: number;
  guardianEpoch: number;
  setChangeNonce: number;
  deadline: number;
};

type CancelRecoveryIntent = {
  action: "CANCEL_RECOVERY";
  domain: IntentDomain;
  consumer: string;
  owner: string;
  recoveryId: string;
  guardianEpoch: number;
  recoveryActionNonce: number;
  deadline: number;
};

type GuardianIntent = SetGuardiansIntent | CancelRecoveryIntent;

type Approval = {
  signer: string;
  digest: string;
};

type VaultMutants = {
  ownerReplacement?: boolean;
  ownerCancellation?: boolean;
  acceptMismatchedGeneration?: boolean;
};

type ControllerMutants = {
  skipVaultPush?: boolean;
  skipControllerAdvance?: boolean;
  noAtomicRollback?: boolean;
};

function required(count: number): number {
  return Math.floor(count / 2) + 1;
}

function unique(values: string[]): boolean {
  return new Set(values).size === values.length;
}

function canonicalize(value: unknown): unknown {
  if (value instanceof Set) return [...value].sort();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)]),
    );
  }
  return value;
}

function digest(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function guardianHash(guardians: string[]): string {
  return digest({ guardians });
}

function authorizationDigest(intent: GuardianIntent): string {
  return digest(intent);
}

function recoveryId(recovery: Omit<Recovery, "supports">): string {
  return digest({
    targetSigner: recovery.targetSigner,
    targetPqKeyHash: recovery.targetPqKeyHash,
    executeAfter: recovery.executeAfter,
    owner: recovery.owner,
    consumer: recovery.consumer,
    guardianEpoch: recovery.guardianEpoch,
  });
}

function signed(intent: GuardianIntent, signers: string[]): Approval[] {
  const intentDigest = authorizationDigest(intent);
  return signers.map((signer) => ({ signer, digest: intentDigest }));
}

class VaultAuthorityModel {
  readonly stableOwner = OWNER;
  readonly contractAdmin = ADMIN;
  readonly canonicalController = CONTROLLER;
  readonly consumer = CONSUMER;
  guardians: string[] = [];
  guardianEpoch = 0;
  treasuryQuorumThreshold = 0;
  recovery?: Recovery;
  credential = "credential-0";
  credentialEpoch = 0;
  paused = false;

  constructor(private readonly mutants: VaultMutants = {}) {}

  guardianQuorum(): number {
    return required(this.guardians.length);
  }

  currentGuardianHash(): string {
    return guardianHash(this.guardians);
  }

  currentRecoveryId(): string {
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    return recoveryId(this.recovery);
  }

  recoveryApproved(): boolean {
    return this.recovery !== undefined && this.recovery.supports.size >= this.guardianQuorum();
  }

  /**
   * PUSH sink. Provenance plus GENERATION ORDINALITY protect the dual-state boundary.
   *
   * Deliberately does NOT compare roster content (docs §7.6a, §4.8). The consumer stores one
   * uint64 per subject and nothing else; it has no roster hash and no way to detect a push whose
   * generation is correct but whose roster is wrong. Modelling a content check here would be the
   * model asserting a check the consumer does not perform, which is the exact error Finding 2
   * flagged. `roster divergence is undetectable by the consumer` is pinned as its own test.
   *
   * Error precedence below is normative (docs §7.6) — generation, then set shape, then treasury
   * bound, then approved-request protection.
   */
  pushGuardianSet(caller: string, push: GuardianPush): void {
    if (caller !== this.canonicalController && !(this.mutants.ownerReplacement && caller === this.stableOwner)) {
      throw new Error("NotGuardianController");
    }
    if (!this.mutants.acceptMismatchedGeneration) {
      if (push.expectedCurrentGeneration !== this.guardianEpoch) {
        throw new Error("GuardianGenerationMismatch");
      }
    }
    if (
      push.nextGuardians.length === 0 ||
      push.nextGuardians.length > 32 ||
      !unique(push.nextGuardians) ||
      push.nextGuardians.includes(this.stableOwner)
    ) {
      throw new Error("InvalidGuardianSet");
    }
    // T2 (docs §7.4a): the quorum-authorized intent carries the threshold, so a stale armed
    // threshold can no longer veto a quorum-authorized shrink. The stable owner's own
    // setTreasuryThreshold authority is unchanged.
    if (push.newTreasuryThreshold > push.nextGuardians.length) {
      throw new Error("InvalidTreasuryThreshold");
    }
    if (this.recoveryApproved()) throw new Error("RecoveryAlreadyApproved");

    this.recovery = undefined;
    this.guardians = [...push.nextGuardians];
    this.treasuryQuorumThreshold = push.newTreasuryThreshold;
    this.guardianEpoch = push.expectedCurrentGeneration + 1;
  }

  setTreasuryThreshold(caller: string, threshold: number): void {
    if (caller !== this.stableOwner) throw new Error("NotStableOwner");
    if (threshold < 0 || threshold > this.guardians.length) throw new Error("InvalidTreasuryThreshold");
    this.treasuryQuorumThreshold = threshold;
  }

  initiateRecovery(caller: string, targetSigner: string, targetPqKeyHash: string, now: number): void {
    if (this.paused) throw new Error("Paused");
    if (!this.guardians.includes(caller)) throw new Error("NotAGuardian");
    if (this.recovery !== undefined) {
      if (now < this.recovery.executeAfter) throw new Error("RecoveryAlreadyExists");
      if (this.recoveryApproved()) throw new Error("RecoveryAlreadyApproved");
    }
    this.recovery = {
      targetSigner,
      targetPqKeyHash,
      executeAfter: now + RECOVERY_DELAY,
      owner: this.stableOwner,
      consumer: this.consumer,
      guardianEpoch: this.guardianEpoch,
      supports: new Set(),
    };
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
    this.credential = this.recovery.targetSigner;
    this.credentialEpoch++;
    this.recovery = undefined;
  }

  rotateCredential(next: string): void {
    this.credential = next;
    this.credentialEpoch++;
  }

  cancelRecovery(caller: string, expectedRecoveryId: string): void {
    const controllerAuthorized = caller === this.canonicalController;
    const ownerMutantAuthorized = this.mutants.ownerCancellation && caller === this.stableOwner;
    if (!controllerAuthorized && !ownerMutantAuthorized) throw new Error("RecoveryCancellationDisabled");
    if (expectedRecoveryId !== this.currentRecoveryId()) throw new Error("RecoveryIdMismatch");
    this.recovery = undefined;
  }

  /**
   * H2 / I-RECOVERY-TERMINATION (docs §4.9, §11). Permissionless, local, zero external calls, and
   * deliberately NOT gated by `paused` (condition C2). The clock is WALL-CLOCK and does not suspend
   * during vault pause: a suspendable clock protects nothing the contract admin cannot already deny
   * by keeping the vault paused, and — combined with the irreversible pause of docs §9a — it would
   * convert a frozen request into a permanently undeletable one, removing the last exit.
   *
   * This is the single mechanism that discharges the Finding-1 blocker: it is why an approved
   * request cannot be simultaneously unexecutable, uncancellable and undeletable.
   */
  expireRecovery(now: number): void {
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    if (!this.recoveryApproved()) throw new Error("RecoveryNotApproved");
    if (now < this.recovery.executeAfter + RECOVERY_EXPIRY_WINDOW) throw new Error("RecoveryNotExpired");
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
      guardianEpoch: this.guardianEpoch,
      treasuryQuorumThreshold: this.treasuryQuorumThreshold,
      credential: this.credential,
      credentialEpoch: this.credentialEpoch,
      paused: this.paused,
      recovery: this.recovery
        ? {
            targetSigner: this.recovery.targetSigner,
            targetPqKeyHash: this.recovery.targetPqKeyHash,
            executeAfter: this.recovery.executeAfter,
            owner: this.recovery.owner,
            consumer: this.recovery.consumer,
            guardianEpoch: this.recovery.guardianEpoch,
            supports: [...this.recovery.supports].sort(),
          }
        : undefined,
    };
  }

  restore(snapshot: ReturnType<VaultAuthorityModel["snapshot"]>): void {
    this.guardians = [...snapshot.guardians];
    this.guardianEpoch = snapshot.guardianEpoch;
    this.treasuryQuorumThreshold = snapshot.treasuryQuorumThreshold;
    this.credential = snapshot.credential;
    this.credentialEpoch = snapshot.credentialEpoch;
    this.paused = snapshot.paused;
    this.recovery = snapshot.recovery
      ? { ...snapshot.recovery, supports: new Set(snapshot.recovery.supports) }
      : undefined;
  }
}

class GuardianControllerModel {
  readonly domain: IntentDomain = { chainId: CHAIN_ID, verifyingContract: CONTROLLER };
  guardianEpoch = 0;
  guardianSet: string[] = [];
  setChangeNonce = 0;
  recoveryActionNonce = 0;
  guardianMutationsRetired = false;

  constructor(
    readonly vault: VaultAuthorityModel,
    private readonly mutants: ControllerMutants = {},
  ) {}

  bootstrap(caller: string, initialGuardians: string[]): void {
    if (this.guardianMutationsRetired) throw new Error("GuardianMutationsRetired");
    if (caller !== this.vault.stableOwner) throw new Error("NotStableOwner");
    if (this.guardianEpoch !== 0 || this.guardianSet.length !== 0) throw new Error("AlreadyBootstrapped");
    this.atomicTransition(() => {
      this.guardianSet = [...initialGuardians];
      this.guardianEpoch = 1;
      this.vault.pushGuardianSet(CONTROLLER, {
        expectedCurrentGeneration: 0,
        nextGuardians: initialGuardians,
        newTreasuryThreshold: 0,
      });
      this.assertSynchronized();
    });
  }

  setIntent(nextGuardians: string[], deadline = 100, newTreasuryThreshold?: number): SetGuardiansIntent {
    return {
      action: "SET_GUARDIANS",
      domain: { ...this.domain },
      consumer: this.vault.consumer,
      owner: this.vault.stableOwner,
      currentGuardianHash: guardianHash(this.guardianSet),
      newGuardianHash: guardianHash(nextGuardians),
      newGuardians: [...nextGuardians],
      // T2 (docs §7.4a): every intent carries an explicit threshold. Mandatory rather than an
      // "unchanged" sentinel, so every threshold value is attested by the quorum that signed it.
      newTreasuryThreshold: newTreasuryThreshold ?? Math.min(this.vault.treasuryQuorumThreshold, nextGuardians.length),
      guardianEpoch: this.guardianEpoch,
      setChangeNonce: this.setChangeNonce,
      deadline,
    };
  }

  cancelIntent(deadline = 100): CancelRecoveryIntent {
    return {
      action: "CANCEL_RECOVERY",
      domain: { ...this.domain },
      consumer: this.vault.consumer,
      owner: this.vault.stableOwner,
      recoveryId: this.vault.currentRecoveryId(),
      guardianEpoch: this.guardianEpoch,
      recoveryActionNonce: this.recoveryActionNonce,
      deadline,
    };
  }

  replace(intent: SetGuardiansIntent, approvals: Approval[], now = 0): void {
    if (this.guardianMutationsRetired) throw new Error("GuardianMutationsRetired");
    this.verifyCommon(intent, approvals, now);
    if (intent.action !== "SET_GUARDIANS") throw new Error("WrongAction");
    if (intent.currentGuardianHash !== guardianHash(this.guardianSet)) throw new Error("CurrentGuardianHashMismatch");
    if (intent.newGuardianHash !== guardianHash(intent.newGuardians)) throw new Error("NewGuardianHashMismatch");
    if (intent.setChangeNonce !== this.setChangeNonce) throw new Error("InvalidSetNonce");
    this.atomicTransition(() => {
      const previousEpoch = this.guardianEpoch;
      if (!this.mutants.skipControllerAdvance) {
        this.guardianSet = [...intent.newGuardians];
        this.guardianEpoch++;
        this.setChangeNonce++;
      }
      if (!this.mutants.skipVaultPush) {
        this.vault.pushGuardianSet(CONTROLLER, {
          expectedCurrentGeneration: previousEpoch,
          nextGuardians: intent.newGuardians,
          newTreasuryThreshold: intent.newTreasuryThreshold,
        });
      }
      this.assertSynchronized();
    });
  }

  cancelRecovery(intent: CancelRecoveryIntent, approvals: Approval[], now = 0): void {
    // P5 (docs §7.1a): retirement is UNIFORM over every controller-authorized write, cancellation
    // included. P1 — leaving cancellation live — was rejected because it leaves a defective
    // controller, the exact thing the pause exists to contain, with a permanent repeatable
    // capability to erase honest recoveries. The uncancellable-approved-request consequence is
    // discharged by wall-clock expiry (VaultAuthorityModel.expireRecovery), not by exempting
    // cancellation from the freeze.
    if (this.guardianMutationsRetired) throw new Error("GuardianMutationsRetired");
    this.verifyCommon(intent, approvals, now);
    if (intent.action !== "CANCEL_RECOVERY") throw new Error("WrongAction");
    if (intent.recoveryActionNonce !== this.recoveryActionNonce) throw new Error("InvalidRecoveryNonce");
    if (intent.recoveryId !== this.vault.currentRecoveryId()) throw new Error("RecoveryIdMismatch");
    this.vault.cancelRecovery(CONTROLLER, intent.recoveryId);
    this.recoveryActionNonce++;
  }

  retireGuardianMutations(caller: string): void {
    if (caller !== EMERGENCY_PAUSER) throw new Error("NotEmergencyPauser");
    this.guardianMutationsRetired = true;
  }

  synchronized(): boolean {
    return (
      this.guardianEpoch === this.vault.guardianEpoch &&
      guardianHash(this.guardianSet) === this.vault.currentGuardianHash()
    );
  }

  assertSynchronized(): void {
    if (!this.synchronized()) throw new Error("AuthorityStateDivergence");
  }

  adoptLegacyState(): never {
    throw new Error("NoSafeInPlaceMigration");
  }

  private verifyCommon(intent: GuardianIntent, approvals: Approval[], now: number): void {
    if (
      intent.domain.chainId !== this.domain.chainId ||
      intent.domain.verifyingContract !== this.domain.verifyingContract
    ) {
      throw new Error("WrongDomain");
    }
    if (intent.consumer !== this.vault.consumer) throw new Error("WrongConsumer");
    if (intent.owner !== this.vault.stableOwner) throw new Error("WrongOwner");
    if (intent.guardianEpoch !== this.guardianEpoch) throw new Error("StaleGuardianEpoch");
    if (now > intent.deadline) throw new Error("IntentExpired");
    const signers = approvals.map(({ signer }) => signer);
    if (!unique(signers) || [...signers].sort().some((signer, index) => signer !== signers[index])) {
      throw new Error("InvalidGuardianApprovalOrder");
    }
    if (approvals.some(({ signer }) => !this.guardianSet.includes(signer))) throw new Error("InvalidGuardianApproval");
    const expectedDigest = authorizationDigest(intent);
    if (approvals.some(({ digest: approvalDigest }) => approvalDigest !== expectedDigest)) {
      throw new Error("InvalidAuthorizationDigest");
    }
    if (approvals.length < required(this.guardianSet.length)) throw new Error("InsufficientGuardianApprovals");
  }

  private snapshot() {
    return {
      guardianEpoch: this.guardianEpoch,
      guardianSet: [...this.guardianSet],
      setChangeNonce: this.setChangeNonce,
      recoveryActionNonce: this.recoveryActionNonce,
      guardianMutationsRetired: this.guardianMutationsRetired,
    };
  }

  private restore(snapshot: ReturnType<GuardianControllerModel["snapshot"]>): void {
    this.guardianEpoch = snapshot.guardianEpoch;
    this.guardianSet = [...snapshot.guardianSet];
    this.setChangeNonce = snapshot.setChangeNonce;
    this.recoveryActionNonce = snapshot.recoveryActionNonce;
    this.guardianMutationsRetired = snapshot.guardianMutationsRetired;
  }

  private atomicTransition(transition: () => void): void {
    const controllerBefore = this.snapshot();
    const vaultBefore = this.vault.snapshot();
    try {
      transition();
    } catch (error) {
      if (!this.mutants.noAtomicRollback) {
        this.restore(controllerBefore);
        this.vault.restore(vaultBefore);
      }
      throw error;
    }
  }
}

function bootstrapped(
  guardians = ["g1", "g2", "g3"],
  vaultMutants: VaultMutants = {},
  controllerMutants: ControllerMutants = {},
  initialTreasuryThreshold = 0,
) {
  const vault = new VaultAuthorityModel(vaultMutants);
  const controller = new GuardianControllerModel(vault, controllerMutants);
  controller.bootstrap(OWNER, guardians);
  if (initialTreasuryThreshold > 0) vault.setTreasuryThreshold(OWNER, initialTreasuryThreshold);
  return { vault, controller };
}

function approveSet(controller: GuardianControllerModel, intent: SetGuardiansIntent): Approval[] {
  return signed(intent, controller.guardianSet.slice(0, required(controller.guardianSet.length)));
}

function approveCancel(controller: GuardianControllerModel, intent: CancelRecoveryIntent): Approval[] {
  return signed(intent, controller.guardianSet.slice(0, required(controller.guardianSet.length)));
}

function approvedRecovery(vault: VaultAuthorityModel, target = "honest-target"): void {
  vault.initiateRecovery("g1", target, `${target}-pq`, 0);
  vault.supportRecovery("g1");
  vault.supportRecovery("g2");
}

interface ParityAdapter {
  setTreasuryThreshold(threshold: number): void;
  initiate(caller: string, target: string, now: number): void;
  support(caller: string): void;
  replace(next: string[]): void;
  cancel(): void;
  snapshot(): unknown;
}

class ProductionTargetAdapter implements ParityAdapter {
  private readonly target = bootstrapped(["g1", "g2", "g3", "g4"]);

  setTreasuryThreshold(threshold: number): void {
    this.target.vault.setTreasuryThreshold(OWNER, threshold);
  }

  initiate(caller: string, target: string, now: number): void {
    this.target.vault.initiateRecovery(caller, target, `${target}-pq`, now);
  }

  support(caller: string): void {
    this.target.vault.supportRecovery(caller);
  }

  replace(next: string[]): void {
    const intent = this.target.controller.setIntent(next);
    this.target.controller.replace(intent, approveSet(this.target.controller, intent));
  }

  cancel(): void {
    const intent = this.target.controller.cancelIntent();
    this.target.controller.cancelRecovery(intent, approveCancel(this.target.controller, intent));
  }

  snapshot(): unknown {
    return {
      ...this.target.vault.snapshot(),
      controllerEpoch: this.target.controller.guardianEpoch,
      controllerGuardians: [...this.target.controller.guardianSet],
      setChangeNonce: this.target.controller.setChangeNonce,
      recoveryActionNonce: this.target.controller.recoveryActionNonce,
    };
  }
}

/** Independent simulator transition model used only for parity discrimination. */
class SimulatorTargetAdapter implements ParityAdapter {
  private guardians = ["g1", "g2", "g3", "g4"];
  private epoch = 1;
  private threshold = 0;
  private setNonce = 0;
  private cancelNonce = 0;
  private recovery?: { target: string; pq: string; executeAfter: number; supports: string[] };

  constructor(private readonly skipEpochAdvanceMutant = false) {}

  setTreasuryThreshold(threshold: number): void {
    if (threshold > this.guardians.length) throw new Error("InvalidTreasuryThreshold");
    this.threshold = threshold;
  }

  initiate(caller: string, target: string, now: number): void {
    if (!this.guardians.includes(caller)) throw new Error("NotAGuardian");
    if (this.recovery !== undefined) throw new Error("RecoveryAlreadyExists");
    this.recovery = { target, pq: `${target}-pq`, executeAfter: now + RECOVERY_DELAY, supports: [] };
  }

  support(caller: string): void {
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    if (!this.guardians.includes(caller) || this.recovery.supports.includes(caller)) {
      throw new Error("InvalidSupport");
    }
    this.recovery.supports.push(caller);
  }

  replace(next: string[]): void {
    if (this.recovery !== undefined && this.recovery.supports.length >= required(this.guardians.length)) {
      throw new Error("RecoveryAlreadyApproved");
    }
    // T2 mirror: the authorized intent carries the threshold, so a shrink clamps rather than
    // reverting. Independently implemented — this adapter shares no code with the production model.
    const nextThreshold = Math.min(this.threshold, next.length);
    if (nextThreshold > next.length) throw new Error("InvalidTreasuryThreshold");
    this.threshold = nextThreshold;
    this.recovery = undefined;
    this.guardians = [...next];
    if (!this.skipEpochAdvanceMutant) this.epoch++;
    this.setNonce++;
  }

  cancel(): void {
    if (this.recovery === undefined) throw new Error("RecoveryDoesNotExist");
    this.recovery = undefined;
    this.cancelNonce++;
  }

  snapshot(): unknown {
    return {
      guardians: [...this.guardians],
      guardianEpoch: this.epoch,
      treasuryQuorumThreshold: this.threshold,
      credential: "credential-0",
      credentialEpoch: 0,
      paused: false,
      recovery: undefined,
      controllerEpoch: this.epoch,
      controllerGuardians: [...this.guardians],
      setChangeNonce: this.setNonce,
      recoveryActionNonce: this.cancelNonce,
    };
  }
}

function runParityCorpus(adapter: ParityAdapter): unknown {
  adapter.setTreasuryThreshold(3);
  adapter.initiate("g1", "target-1", 0);
  adapter.support("g1");
  adapter.replace(["g2", "g3", "g4"]);
  adapter.initiate("g2", "target-2", 1);
  adapter.support("g2");
  adapter.support("g3");
  adapter.cancel();
  return adapter.snapshot();
}

describe("Guardian Authority lifecycle design model", function () {
  describe("authority and recovery lifecycle", function () {
    it("compromised owner or spending credentials cannot replace an established set", function () {
      const { vault } = bootstrapped();
      for (const principal of [OWNER, vault.credential, ADMIN, "arbitrary-caller"]) {
        expect(() =>
          vault.pushGuardianSet(principal, {
            expectedCurrentGeneration: vault.guardianEpoch,
            nextGuardians: ["attacker"],
            newTreasuryThreshold: 0,
          }),
        ).to.throw("NotGuardianController");
      }
    });

    it("guardian minority cannot replace, while a malicious majority remains the accepted root", function () {
      const { vault, controller } = bootstrapped();
      const intent = controller.setIntent(["a1", "a2", "a3"]);
      expect(() => controller.replace(intent, signed(intent, ["g1"]))).to.throw("InsufficientGuardianApprovals");
      controller.replace(intent, signed(intent, ["g1", "g2"]));
      vault.initiateRecovery("a1", "attacker", "attacker-pq", 0);
      vault.supportRecovery("a1");
      vault.supportRecovery("a2");
      vault.executeRecovery(RECOVERY_DELAY);
      expect(vault.credential).to.equal("attacker");
    });

    it("successful recovery and credential rotation preserve guardian authority", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault, "recovered");
      vault.rotateCredential("rotated-before-recovery");
      vault.executeRecovery(RECOVERY_DELAY);
      const intent = controller.setIntent(["g2", "g3", "g4"]);
      controller.replace(intent, approveSet(controller, intent));
      expect(vault.credential).to.equal("recovered");
      expect(vault.guardians).to.deep.equal(["g2", "g3", "g4"]);
    });

    it("approved recovery blocks set replacement but under-supported recovery is invalidated", function () {
      const under = bootstrapped();
      under.vault.initiateRecovery("g1", "under", "under-pq", 0);
      under.vault.supportRecovery("g1");
      const allowed = under.controller.setIntent(["g2", "g3", "g4"]);
      under.controller.replace(allowed, approveSet(under.controller, allowed));
      expect(under.vault.recovery).to.equal(undefined);

      const approved = bootstrapped();
      approvedRecovery(approved.vault);
      const blocked = approved.controller.setIntent(["g2", "g3", "g4"]);
      expect(() => approved.controller.replace(blocked, approveSet(approved.controller, blocked))).to.throw(
        "RecoveryAlreadyApproved",
      );
      expect(approved.controller.synchronized()).to.equal(true);
    });

    it("vault pause preserves existing authority and only suspends local initiation/execution", function () {
      const { vault } = bootstrapped();
      approvedRecovery(vault);
      vault.pause(ADMIN);
      expect(() => vault.initiateRecovery("g3", "replacement", "replacement-pq", RECOVERY_DELAY)).to.throw("Paused");
      expect(() => vault.executeRecovery(RECOVERY_DELAY)).to.throw("Paused");
      expect(vault.recoveryApproved()).to.equal(true);
      vault.unpause(ADMIN);
      vault.executeRecovery(RECOVERY_DELAY);
    });

    it("threshold edges n=1,2,3,4,5,32 are exact", function () {
      for (const [count, quorum] of new Map([
        [1, 1],
        [2, 2],
        [3, 2],
        [4, 3],
        [5, 3],
        [32, 17],
      ])) {
        const guardians = Array.from({ length: count }, (_, index) => `g${index + 1}`);
        expect(bootstrapped(guardians).vault.guardianQuorum(), `n=${count}`).to.equal(quorum);
      }
    });

    it("zero-guardian bootstrap is owner-authorized once and legacy adoption remains forbidden", function () {
      const vault = new VaultAuthorityModel();
      const controller = new GuardianControllerModel(vault);
      expect(() => controller.bootstrap("attacker", ["a1"])).to.throw("NotStableOwner");
      controller.bootstrap(OWNER, ["g1"]);
      expect(() => controller.bootstrap(OWNER, ["attacker"])).to.throw("AlreadyBootstrapped");
      expect(() => controller.adoptLegacyState()).to.throw("NoSafeInPlaceMigration");
    });
  });

  describe("emergency-state semantics", function () {
    it("P5: retirement freezes bootstrap, set replacement AND quorum cancellation uniformly", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      controller.retireGuardianMutations(EMERGENCY_PAUSER);

      const setIntent = controller.setIntent(["g2", "g3", "g4"]);
      expect(() => controller.replace(setIntent, approveSet(controller, setIntent))).to.throw(
        "GuardianMutationsRetired",
      );
      // P1 would have let this through. Under P5 it must not: a defective controller is exactly
      // what the pause exists to contain, and cancellation is a capability it would otherwise keep.
      const cancel = controller.cancelIntent();
      expect(() => controller.cancelRecovery(cancel, approveCancel(controller, cancel))).to.throw(
        "GuardianMutationsRetired",
      );
      expect(vault.recovery, "the approved request survives retirement").to.not.equal(undefined);
    });

    it("the pauser gets no cancel selector, and retirement does not suspend a live approved recovery", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const id = vault.currentRecoveryId();
      controller.retireGuardianMutations(EMERGENCY_PAUSER);
      expect(() => vault.cancelRecovery(EMERGENCY_PAUSER, id)).to.throw("RecoveryCancellationDisabled");
      vault.executeRecovery(RECOVERY_DELAY);
      expect(vault.credential).to.equal("honest-target");
    });

    it("only the emergency pauser may retire — v4's model let ANY caller pause", function () {
      const { controller } = bootstrapped();
      for (const caller of [OWNER, ADMIN, "g1", "arbitrary-relayer"]) {
        expect(() => controller.retireGuardianMutations(caller), caller).to.throw("NotEmergencyPauser");
      }
      controller.retireGuardianMutations(EMERGENCY_PAUSER);
      expect(controller.guardianMutationsRetired).to.equal(true);
    });

    it("BLOCKER: an approved request under retirement is uncancellable — and expiry is the only exit", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      controller.retireGuardianMutations(EMERGENCY_PAUSER);

      // Every other exit is closed. This is precisely the v4 state that had no terminator.
      const cancel = controller.cancelIntent();
      expect(() => controller.cancelRecovery(cancel, approveCancel(controller, cancel))).to.throw(
        "GuardianMutationsRetired",
      );
      const replacement = controller.setIntent(["g2", "g3", "g4"]);
      expect(() => controller.replace(replacement, approveSet(controller, replacement))).to.throw(
        "GuardianMutationsRetired",
      );
      expect(() => vault.expireRecovery(RECOVERY_DELAY)).to.throw("RecoveryNotExpired");

      // I-RECOVERY-TERMINATION: the wall clock removes it, with no principal's cooperation.
      vault.expireRecovery(RECOVERY_DELAY + RECOVERY_EXPIRY_WINDOW);
      expect(vault.recovery, "H2 expiry is what discharges the Finding-1 blocker").to.equal(undefined);
    });

    it("C2: expiry does NOT suspend while the vault is paused, so a frozen request still dies", function () {
      const { vault } = bootstrapped();
      approvedRecovery(vault);
      vault.pause(ADMIN);

      // The admin can block execution indefinitely — that veto is pre-existing (docs §9a).
      expect(() => vault.executeRecovery(RECOVERY_DELAY)).to.throw("Paused");
      // If the expiry clock suspended under pause, this request would be permanently undeletable:
      // unexecutable (paused), uncancellable (if also retired), and unexpirable. It must not.
      vault.expireRecovery(RECOVERY_DELAY + RECOVERY_EXPIRY_WINDOW);
      expect(vault.recovery).to.equal(undefined);
    });

    it("expiry is permissionless and applies only to APPROVED requests", function () {
      const { vault } = bootstrapped();
      vault.initiateRecovery("g1", "t", "t-pq", 0);
      vault.supportRecovery("g1"); // one support of the two required
      // C4: an under-supported request already has a local exit via initiateRecovery replacement.
      expect(() => vault.expireRecovery(RECOVERY_DELAY + RECOVERY_EXPIRY_WINDOW)).to.throw("RecoveryNotApproved");
    });

    it("a minority still cannot cancel while the controller is LIVE", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const intent = controller.cancelIntent();
      expect(() => controller.cancelRecovery(intent, signed(intent, ["g1"]))).to.throw("InsufficientGuardianApprovals");
    });
  });

  describe("typed recovery-cancellation bindings", function () {
    it("authorization for recovery R1 cannot cancel R2", function () {
      const { vault, controller } = bootstrapped();
      vault.initiateRecovery("g1", "r1", "r1-pq", 0);
      const r1 = controller.cancelIntent();
      const r1Approvals = approveCancel(controller, r1);
      vault.initiateRecovery("g2", "r2", "r2-pq", RECOVERY_DELAY);
      expect(() => controller.cancelRecovery(r1, r1Approvals)).to.throw("RecoveryIdMismatch");
      expect(vault.recovery?.targetSigner).to.equal("r2");
    });

    it("wrong consumer, owner, epoch, chain/domain, and expired cancellation intents reject", function () {
      const fields: Array<[string, (intent: CancelRecoveryIntent) => void, string]> = [
        ["consumer", (intent) => (intent.consumer = OTHER_CONSUMER), "WrongConsumer"],
        ["owner", (intent) => (intent.owner = "other-owner"), "WrongOwner"],
        ["epoch", (intent) => intent.guardianEpoch++, "StaleGuardianEpoch"],
        ["chain", (intent) => intent.domain.chainId++, "WrongDomain"],
        ["verifier", (intent) => (intent.domain.verifyingContract = "other-controller"), "WrongDomain"],
      ];
      for (const [label, mutate, error] of fields) {
        const { vault, controller } = bootstrapped();
        approvedRecovery(vault);
        const intent = controller.cancelIntent();
        mutate(intent);
        expect(() => controller.cancelRecovery(intent, approveCancel(controller, intent)), label).to.throw(error);
      }
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const expired = controller.cancelIntent(5);
      expect(() => controller.cancelRecovery(expired, approveCancel(controller, expired), 6)).to.throw("IntentExpired");
    });

    it("consumed recovery nonce rejects replay", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const first = controller.cancelIntent();
      const approvals = approveCancel(controller, first);
      controller.cancelRecovery(first, approvals);
      vault.initiateRecovery("g1", "r2", "r2-pq", 1);
      expect(() => controller.cancelRecovery(first, approvals)).to.throw("InvalidRecoveryNonce");
    });

    it("wrong action and cancel-to-set cross-action replay reject", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const cancel = controller.cancelIntent();
      const cancelApprovals = approveCancel(controller, cancel);
      const setIntent = controller.setIntent(["g2", "g3", "g4"]);
      expect(() => controller.replace(setIntent, cancelApprovals)).to.throw("InvalidAuthorizationDigest");
      expect(() =>
        controller.cancelRecovery(
          { ...cancel, action: "SET_GUARDIANS" } as unknown as CancelRecoveryIntent,
          cancelApprovals,
        ),
      ).to.throw("InvalidAuthorizationDigest");
    });

    it("recoveryId binds signer, PQ-key hash, time, owner, consumer, and guardian epoch", function () {
      const base = {
        targetSigner: "target",
        targetPqKeyHash: "pq-hash",
        executeAfter: 7,
        owner: OWNER,
        consumer: CONSUMER,
        guardianEpoch: 1,
      };
      const original = recoveryId(base);
      for (const variant of [
        { ...base, targetSigner: "other" },
        { ...base, targetPqKeyHash: "other" },
        { ...base, executeAfter: 8 },
        { ...base, owner: "other" },
        { ...base, consumer: OTHER_CONSUMER },
        { ...base, guardianEpoch: 2 },
      ]) {
        expect(recoveryId(variant)).to.not.equal(original);
      }
    });
  });

  describe("typed guardian-set bindings", function () {
    it("wrong consumer, owner, old epoch, chain/domain, and expired set intents reject", function () {
      const fields: Array<[string, (intent: SetGuardiansIntent) => void, string]> = [
        ["consumer", (intent) => (intent.consumer = OTHER_CONSUMER), "WrongConsumer"],
        ["owner", (intent) => (intent.owner = "other-owner"), "WrongOwner"],
        ["epoch", (intent) => intent.guardianEpoch++, "StaleGuardianEpoch"],
        ["chain", (intent) => intent.domain.chainId++, "WrongDomain"],
        ["verifier", (intent) => (intent.domain.verifyingContract = "other-controller"), "WrongDomain"],
      ];
      for (const [label, mutate, error] of fields) {
        const { controller } = bootstrapped();
        const intent = controller.setIntent(["g2", "g3", "g4"]);
        mutate(intent);
        expect(() => controller.replace(intent, approveSet(controller, intent)), label).to.throw(error);
      }
      const { controller } = bootstrapped();
      const expired = controller.setIntent(["g2", "g3", "g4"], 5);
      expect(() => controller.replace(expired, approveSet(controller, expired), 6)).to.throw("IntentExpired");
    });

    it("modified guardian list/hash rejects", function () {
      const { controller } = bootstrapped();
      const intent = controller.setIntent(["g2", "g3", "g4"]);
      intent.newGuardians = ["attacker"];
      expect(() => controller.replace(intent, signed(intent, ["g1", "g2"]))).to.throw("NewGuardianHashMismatch");
    });

    it("old epoch and consumed set nonce reject independently", function () {
      const { controller } = bootstrapped();
      const first = controller.setIntent(["g2", "g3", "g4"]);
      controller.replace(first, approveSet(controller, first));
      const oldEpoch = { ...first, setChangeNonce: controller.setChangeNonce };
      expect(() => controller.replace(oldEpoch, signed(oldEpoch, ["g2", "g3"]))).to.throw("StaleGuardianEpoch");
      const oldNonce = controller.setIntent(["g1", "g3", "g4"]);
      oldNonce.setChangeNonce = 0;
      expect(() => controller.replace(oldNonce, signed(oldNonce, ["g2", "g3"]))).to.throw("InvalidSetNonce");
    });

    it("set-to-cancel cross-action replay rejects", function () {
      const { vault, controller } = bootstrapped();
      approvedRecovery(vault);
      const setIntent = controller.setIntent(["g2", "g3", "g4"]);
      const cancelIntent = controller.cancelIntent();
      expect(() => controller.cancelRecovery(cancelIntent, approveSet(controller, setIntent))).to.throw(
        "InvalidAuthorizationDigest",
      );
    });
  });

  describe("authority-state synchrony and atomicity", function () {
    it("target transitions keep independent controller and vault copies synchronized", function () {
      const { controller } = bootstrapped();
      const intent = controller.setIntent(["g2", "g3", "g4"]);
      controller.replace(intent, approveSet(controller, intent));
      expect(controller.synchronized()).to.equal(true);
    });

    it("controller-advance-without-vault and vault-advance-without-controller mutants are killed", function () {
      for (const mutants of [
        { skipVaultPush: true, noAtomicRollback: true },
        { skipControllerAdvance: true, noAtomicRollback: true },
      ]) {
        const { controller } = bootstrapped(["g1", "g2", "g3"], {}, mutants);
        const intent = controller.setIntent(["g2", "g3", "g4"]);
        expect(() => controller.replace(intent, approveSet(controller, intent))).to.throw("AuthorityStateDivergence");
        expect(controller.synchronized()).to.equal(false, "synchrony invariant kills the one-sided state mutant");
      }
    });

    it("M-SYNC-3: the consumer rejects a PUSH whose expected generation is stale", function () {
      const target = bootstrapped();
      expect(() =>
        target.vault.pushGuardianSet(CONTROLLER, {
          expectedCurrentGeneration: 0, // consumer is already at generation 1
          nextGuardians: ["g2", "g3", "g4"],
          newTreasuryThreshold: 0,
        }),
      ).to.throw("GuardianGenerationMismatch");

      const mutant = bootstrapped(["g1", "g2", "g3"], { acceptMismatchedGeneration: true });
      mutant.vault.pushGuardianSet(CONTROLLER, {
        expectedCurrentGeneration: 0,
        nextGuardians: ["attacker"],
        newTreasuryThreshold: 0,
      });
      expect(mutant.controller.synchronized()).to.equal(false, "generation check kills the stale-PUSH mutant");
    });

    it("M-SYNC-3 HONEST LIMIT: roster divergence at a CORRECT generation is NOT detected", function () {
      // The design must not claim a check the consumer does not perform (docs §4.8, §7.6a). The
      // consumer stores one uint64 and no roster hash, so a controller that keeps generation
      // consistent while pushing a wrong roster passes. That is inside the accepted controller-code
      // TCB, and pinning it here stops a future reader from believing the boundary is stronger.
      //
      // The roster-hash variant WOULD catch this, and was rejected on measured cost alone:
      // +507 bytes takes vault headroom to 307, under this repo's 600-byte stop threshold.
      const target = bootstrapped(["g1", "g2", "g3"]);
      const generationBefore = target.vault.guardianEpoch;

      target.vault.pushGuardianSet(CONTROLLER, {
        expectedCurrentGeneration: generationBefore, // correct ordinality
        nextGuardians: ["attacker-1", "attacker-2", "attacker-3"], // wrong roster
        newTreasuryThreshold: 0,
      });

      expect(target.vault.guardians, "the consumer accepted it").to.deep.equal([
        "attacker-1",
        "attacker-2",
        "attacker-3",
      ]);
      expect(target.vault.guardianEpoch).to.equal(generationBefore + 1);
      // Detection exists, but only as an off-chain/controller-side property of the pair, never as
      // a consumer-enforced one.
      expect(target.controller.synchronized(), "divergence is observable in the MODEL, not by the consumer").to.equal(
        false,
      );
    });

    it("consumer rejection rolls controller writes back; a no-rollback ordering mutant diverges", function () {
      const target = bootstrapped();
      approvedRecovery(target.vault);
      const targetIntent = target.controller.setIntent(["g2", "g3", "g4"]);
      expect(() => target.controller.replace(targetIntent, approveSet(target.controller, targetIntent))).to.throw(
        "RecoveryAlreadyApproved",
      );
      expect(target.controller.synchronized()).to.equal(true);
      expect(target.controller.guardianEpoch).to.equal(1);

      const mutant = bootstrapped(["g1", "g2", "g3"], {}, { noAtomicRollback: true });
      approvedRecovery(mutant.vault);
      const mutantIntent = mutant.controller.setIntent(["g2", "g3", "g4"]);
      expect(() => mutant.controller.replace(mutantIntent, approveSet(mutant.controller, mutantIntent))).to.throw(
        "RecoveryAlreadyApproved",
      );
      expect(mutant.controller.synchronized()).to.equal(false, "atomic rollback invariant kills the ordering mutant");
    });
  });

  describe("treasury-threshold authority", function () {
    it("T1 MUTANT KILLED: the owner's armed threshold no longer vetoes a quorum-authorized shrink", function () {
      const { vault, controller } = bootstrapped(["g1", "g2", "g3", "g4", "g5"]);
      vault.setTreasuryThreshold(OWNER, 5); // the compromised-owner ratchet

      // Under T1 this reverted TreasuryCardinalityVeto and the set was frozen at 5 forever.
      const shrink = controller.setIntent(["g1", "g2", "g3"], 100, 2);
      controller.replace(shrink, approveSet(controller, shrink));
      expect(vault.guardians).to.deep.equal(["g1", "g2", "g3"]);
      expect(vault.treasuryQuorumThreshold, "threshold moves atomically with the set").to.equal(2);
    });

    it("a lost owner with a high armed threshold does not strand guardian repair", function () {
      const { vault, controller } = bootstrapped(["g1", "g2", "g3", "g4"], {}, {}, 4);
      const shrink = controller.setIntent(["g1", "g2", "g3"], 100, 3);
      controller.replace(shrink, approveSet(controller, shrink));
      expect(vault.snapshot()).to.include({ treasuryQuorumThreshold: 3 });
    });

    it("same-cardinality identity replacement preserves the threshold (true under T1 and T2 alike)", function () {
      const { vault, controller } = bootstrapped(["g1", "g2", "g3"], {}, {}, 3);
      const replace = controller.setIntent(["g2", "g3", "g4"], 100, 3);
      controller.replace(replace, approveSet(controller, replace));
      expect(vault.guardians).to.deep.equal(["g2", "g3", "g4"]);
      expect(vault.treasuryQuorumThreshold).to.equal(3);
    });

    it("the threshold cannot exceed the incoming set's cardinality", function () {
      const { controller } = bootstrapped(["g1", "g2", "g3"]);
      const overArmed = controller.setIntent(["g1", "g2"], 100, 3);
      expect(() => controller.replace(overArmed, approveSet(controller, overArmed))).to.throw(
        "InvalidTreasuryThreshold",
      );
    });

    it("threshold administration gives the owner NO route to guardian identities", function () {
      const { vault, controller } = bootstrapped();
      vault.setTreasuryThreshold(OWNER, 3);
      const intent = controller.setIntent(["attacker", "g2", "g3"], 100, 2);
      expect(() => controller.replace(intent, signed(intent, ["g1"]))).to.throw("InsufficientGuardianApprovals");
      expect(vault.guardians).to.deep.equal(["g1", "g2", "g3"]);
    });

    it("ACCEPTED T2 COST: a malicious majority may zero the treasury threshold atomically", function () {
      // Booked explicitly in docs §7.4a/§15.2 rather than discovered later. This is a SPENDING
      // parameter moved by the CREDENTIAL root — the partial trust-domain merge T2 costs. It is
      // accepted because that majority can already install attacker credentials outright, which
      // strictly dominates tampering with a withdrawal gate.
      const { vault, controller } = bootstrapped(["g1", "g2", "g3"], {}, {}, 3);
      const malicious = controller.setIntent(["a1", "a2", "a3"], 100, 0);
      controller.replace(malicious, approveSet(controller, malicious));
      expect(vault.treasuryQuorumThreshold).to.equal(0);
      expect(vault.guardians).to.deep.equal(["a1", "a2", "a3"]);
    });

    it("the stable owner retains unilateral threshold authority — T2 removes the VETO, not the role", function () {
      const { vault } = bootstrapped(["g1", "g2", "g3"]);
      vault.setTreasuryThreshold(OWNER, 3);
      expect(vault.treasuryQuorumThreshold).to.equal(3);
      expect(() => vault.setTreasuryThreshold("g1", 1)).to.throw("NotStableOwner");
    });
  });

  describe("parity and deliberate mutants", function () {
    it("independently implemented production and simulator adapters match over the transition corpus", function () {
      expect(runParityCorpus(new ProductionTargetAdapter())).to.deep.equal(
        runParityCorpus(new SimulatorTargetAdapter()),
      );
    });

    it("a one-sided simulator threshold-update mutant is killed by the parity assertion", function () {
      const production = runParityCorpus(new ProductionTargetAdapter());
      const mutantSimulator = runParityCorpus(new SimulatorTargetAdapter(true));
      expect(mutantSimulator).to.not.deep.equal(production);
    });

    it("owner replacement and owner cancellation mutants remain killed", function () {
      const ownerReplacement = bootstrapped(["g1", "g2", "g3"], { ownerReplacement: true });
      ownerReplacement.vault.pushGuardianSet(OWNER, {
        expectedCurrentGeneration: ownerReplacement.vault.guardianEpoch,
        nextGuardians: ["attacker"],
        newTreasuryThreshold: 0,
      });
      // The mutant succeeds at the consumer, and I-GUARDIAN-STATE-SYNCHRONY is what catches it:
      // the controller's authority state never moved, so the two copies diverge.
      expect(ownerReplacement.controller.synchronized()).to.equal(false);

      const ownerCancellation = bootstrapped(["g1", "g2", "g3"], { ownerCancellation: true });
      approvedRecovery(ownerCancellation.vault);
      ownerCancellation.vault.cancelRecovery(OWNER, ownerCancellation.vault.currentRecoveryId());
      expect(ownerCancellation.vault.recoveryApproved()).to.equal(false);
    });
  });
});

/**
 * §9a — the live, PRE-EXISTING defect found during v5 review.
 *
 * These assertions read the compiled ABI of the CURRENT production contracts. They are not part of
 * the TARGET model: they exist so the design document's §9a claim cannot silently rot, and so that
 * the day C6 lands, this suite tells the implementer to update the document rather than leaving a
 * stale "not closed" caveat behind.
 */
describe("§9a live defect — renounceOwnership makes the admin pause irreversible", function () {
  const CONSUMERS = [
    { name: "WalletWallVault", artifact: "WalletWallVault.sol/WalletWallVault.json" },
    { name: "StablecoinVaultSimulator", artifact: "StablecoinVaultSimulator.sol/StablecoinVaultSimulator.json" },
  ];

  function abiOf(artifactRelPath: string): { name?: string; type: string }[] {
    const path = join(import.meta.dirname, "..", "artifacts", "contracts", artifactRelPath);
    return JSON.parse(readFileSync(path, "utf8")).abi;
  }

  for (const { name, artifact } of CONSUMERS) {
    it(`${name} still exposes renounceOwnership, pause and unpause — C6 is NOT yet applied`, function () {
      const selectors = abiOf(artifact)
        .filter((entry) => entry.type === "function")
        .map((entry) => entry.name);

      // pause()/unpause() are onlyOwner; initiateRecovery and executeRecovery are whenNotPaused.
      expect(selectors, `${name}: pause`).to.include("pause");
      expect(selectors, `${name}: unpause`).to.include("unpause");

      // Ownable2Step overrides transferOwnership but NOT renounceOwnership, and neither vault
      // overrides it. pause() + renounceOwnership() therefore zeroes owner(), making unpause()
      // uncallable forever and freezing recovery for every tenant of this consumer.
      //
      // When C6 lands this assertion FAILS. That is the intended signal: update
      // docs/Guardian_Authority_Design.md §9a and §9b, and the HIGH-6 disposition, in the same PR.
      expect(
        selectors,
        `${name}: if this no longer includes renounceOwnership, C6 has landed — update §9a/§9b`,
      ).to.include("renounceOwnership");
    });
  }
});
