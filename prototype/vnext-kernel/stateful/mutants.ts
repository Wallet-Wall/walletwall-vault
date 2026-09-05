/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * MUTATION ADEQUACY — attacking the fuzzer itself.
 *
 * A campaign that finds nothing is worthless until you know it COULD have found
 * something. Every mutation below is a deliberately WEAKENED kernel, compiled in
 * memory and deployed, and the SAME campaign machinery is then pointed at it.
 * A mutation the campaign fails to kill is a hole in the properties, reported as
 * a SURVIVOR rather than quietly dropped.
 *
 * Nine of these reintroduce a defect that was ACTUALLY REPRODUCED against an
 * earlier revision of this kernel (AUTHORITY.md section 0, findings A1, A2, B,
 * D and F), so this is not a synthetic mutation score: it is a regression proof
 * that the historical bypass classes are still detected — now by COMPOSITION
 * over arbitrary histories rather than by a hand-written attack.
 *
 * THE VACUITY GUARD, WHICH IS NOT OPTIONAL
 * ----------------------------------------
 * A mutant that does not compile, does not deploy, or bricks the vault outright
 * would "die" for the wrong reason and would score as a kill while proving
 * nothing. Every mutant is therefore additionally required to REACH a working
 * kernel: it must deploy, and its campaign must complete at least one
 * SUCCESSFUL transition. A mutant that cannot clear that bar is reported as
 * INCONCLUSIVE, never as KILLED.
 *
 * Compilation drives the same PINNED solc binary reproduce.ts uses, via
 * --standard-json, and NEVER writes to prototype/vnext-kernel/contracts/ or to
 * its artifacts/cache. The mechanism mirrors authority/mutation-harness.ts; it
 * asks for BYTECODE rather than only an AST, because this lane must RUN the
 * mutant, not merely parse it.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { replaceWithinFunction } from "../authority/mutation-harness.js";

const SOLC_VERSION = "0.8.24";
const ROOT = path.join("prototype", "vnext-kernel");
const SRC = path.join(ROOT, "contracts");
const KERNEL_FILES = [
  "VaultKernelPrototype.sol",
  "VaultKernelFactoryPrototype.sol",
  "PrototypeMocks.sol",
  "interfaces/IKernelPlanes.sol",
];

// Duplicated from reproduce.ts / mutation-harness.ts deliberately, for the same
// reason those two duplicate each other: this module must stay runnable
// standalone without importing a CLI-oriented main().
function compilerCachePlatform(): string {
  switch (os.platform()) {
    case "win32":
      return "windows-amd64";
    case "linux":
      return os.arch() === "arm64" ? "linux-arm64" : "linux-amd64";
    case "darwin":
      return "macosx-amd64";
    default:
      throw new Error("no native solc cache layout known for platform " + os.platform() + "/" + os.arch());
  }
}

function hardhatCacheRoot(): string {
  const home = os.homedir();
  switch (os.platform()) {
    case "win32":
      return path.join(process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local"), "hardhat-nodejs", "Cache");
    case "darwin":
      return path.join(home, "Library", "Caches", "hardhat-nodejs");
    case "linux":
      return path.join(process.env.XDG_CACHE_HOME ?? path.join(home, ".cache"), "hardhat-nodejs");
    default:
      throw new Error("no known hardhat cache directory convention for platform " + os.platform());
  }
}

function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) throw new Error("pinned solc " + SOLC_VERSION + " not found in " + base);
  return path.join(base, hit);
}

export interface DeployableMutant {
  abi: unknown[];
  bytecode: string;
}

/** Compiles the kernel with `overrides` applied, returning DEPLOYABLE artifacts. */
export function compileDeployable(
  overrides: Readonly<Record<string, string>>,
): { ok: true; kernel: DeployableMutant } | { ok: false; errors: string[] } {
  const solc = solcPath();
  const sources: Record<string, { content: string }> = {};
  for (const relFile of KERNEL_FILES) {
    const key = path.posix.join("contracts", relFile.split(path.sep).join("/"));
    sources[key] = {
      content: overrides[relFile] ?? fs.readFileSync(path.join(SRC, relFile), "utf8"),
    };
  }

  const input = {
    language: "Solidity",
    sources,
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };

  const raw = execFileSync(solc, ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 256 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as {
    errors?: { severity: string; formattedMessage: string }[];
    contracts?: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string } } }>>;
  };
  const fatal = (parsed.errors ?? [])
    .filter((e) => e.severity === "error")
    .map((e) => e.formattedMessage);
  if (fatal.length > 0) return { ok: false, errors: fatal };

  const unit = parsed.contracts?.["contracts/VaultKernelPrototype.sol"]?.VaultKernelPrototype;
  if (!unit) return { ok: false, errors: ["VaultKernelPrototype missing from compiler output"] };
  return { ok: true, kernel: { abi: unit.abi, bytecode: "0x" + unit.evm.bytecode.object } };
}

const kernelSource = (): string => fs.readFileSync(path.join(SRC, "VaultKernelPrototype.sol"), "utf8");

export interface Mutation {
  id: string;
  /** The property this mutation is expected to violate. */
  expectedProperty: string;
  /** Why this mutation matters — historical finding, or the compositional class it models. */
  rationale: string;
  /**
   * Campaign profiles most likely to reach this mutation's seam. A mutation is
   * only reported KILLED if a listed profile actually catches it; listing the
   * wrong profile shows up as a SURVIVOR, not as a silent pass.
   */
  profiles: string[];
  /** Produces the mutated VaultKernelPrototype.sol source. */
  apply: (source: string) => string;
}

/**
 * THE MUTATION CATALOGUE.
 *
 * `replaceWithinFunction` (reused from authority/mutation-harness.ts) scopes each
 * edit to ONE function body by brace matching, so a mutation aimed at
 * `rotateCredential` cannot silently also mutate `execute`, `setVerifier` and
 * `setPolicy` — which share several byte-identical call sites. It throws when the
 * snippet is not found exactly once, so a mutation that silently became a no-op
 * fails loudly instead of scoring as a survivor.
 */
export const MUTATIONS: readonly Mutation[] = [
  {
    id: "M1-asset-path-one-root",
    profiles: ["ecdsa-only-attacker"],
    expectedProperty: "P-CUT/ASSET_MOVEMENT",
    rationale:
      "HISTORICAL. Weakens execute() to the ECDSA conjunct ALONE, dropping the PQ leg. This is the shape of findings A1/A2: the published min(2,k) claim becomes false and the real asset cut becomes 1.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "execute",
        "_authorise(digest, ecdsaSig, pqSig, pqKey);",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      ),
  },
  {
    id: "M2-rotate-floor-only",
    profiles: ["ecdsa-only-attacker","recovery-maturation"],
    expectedProperty: "P-CUT/CREDENTIAL_REPLACEMENT",
    rationale:
      "HISTORICAL — finding A1 exactly. rotateCredential gated on the ECDSA conjunct alone lets a single compromised root rewrite BOTH factors and then spend.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "rotateCredential",
        "_authorise(digest, ecdsaSig, pqSig, pqKey);",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      ),
  },
  {
    id: "M3-setverifier-floor-only",
    profiles: ["ecdsa-only-attacker"],
    expectedProperty: "P-CUT/VERIFIER_REPLACEMENT",
    rationale:
      "HISTORICAL — finding A2 exactly. A unilateral ECDSA verifier swap lets one root install an always-true verifier with the recorded floor untouched, so no downgrade rule fires, and then spend with the PUBLIC PQ key.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setVerifier",
        "_authorise(digest, ecdsaSig, pqSig, pqKey);",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      ),
  },
  {
    id: "M4-setpolicy-floor-only",
    profiles: ["ecdsa-only-attacker","containment-composition"],
    expectedProperty: "P-CUT/POLICY_CHANGE",
    rationale:
      "The POLICY_CHANGE cut has NO standalone row in AUTHORITY.md section 3 and is derived from source. This mutation is what makes that derived cut testable rather than assumed.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setPolicy",
        "_authorise(digest, ecdsaSig, pqSig, pqKey);",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      ),
  },
  {
    id: "M5-recovery-replay-enabled",
    profiles: ["recovery-composition"],
    expectedProperty: "P-MODEL",
    rationale:
      "R3. Removing `delete recovery` leaves the consumed request active, so the SAME recovery evidence can complete a second credential replacement. The model catches it because IT recorded the episode as CONSUMED, whatever the kernel now believes.",
    apply: (s) => replaceWithinFunction(s, "executeRecovery", "delete recovery;", "recovery.challengesUsed = 0;"),
  },
  {
    id: "M6-cancel-does-not-invalidate",
    profiles: ["recovery-maturation","recovery-composition"],
    expectedProperty: "P-MODEL",
    rationale:
      "R2. cancelRecovery stops clearing `active`, so a CANCELLED recovery stays finalizable — a cancellation that cancels nothing. Detected by the model's own CANCELLED record, not by re-reading recovery.active.",
    apply: (s) => replaceWithinFunction(s, "cancelRecovery", "recovery.active = false;", "recovery.active = true;"),
  },
  {
    id: "M7-pop-checks-outgoing-key",
    profiles: ["recovery-maturation","recovery-composition"],
    expectedProperty: "P-CUT/CREDENTIAL_REPLACEMENT",
    rationale:
      "R4 / HISTORICAL finding D inverted. Possession is proven against the OUTGOING signer instead of the incoming one, so an approved-but-unheld credential installs — and, worse, the outgoing holder satisfies the incoming proof.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireIncomingPossession",
        "if (popDigest.recover(c.newEcdsaPop) != expectedSigner) revert BadSignature();",
        "if (popDigest.recover(c.newEcdsaPop) != ecdsaSigner) revert BadSignature();",
      ),
  },
  {
    id: "M8-recovery-commitment-drops-verifier",
    profiles: ["recovery-maturation","recovery-composition"],
    expectedProperty: "P-CUT/VERIFIER_REPLACEMENT",
    rationale:
      "R1. The recovery possession digest stops binding `proposedVerifier`, so a possession proof made for one proposed configuration is valid for a DIFFERENT one — a stale authorization silently retargeting.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "recoveryPossessionDigest",
        "r.proposedVerifier,\n                    r.boundGuardianGeneration,",
        "r.boundGuardianGeneration,",
      ),
  },
  {
    id: "M9-duplicate-guardian-principal",
    profiles: ["quorum-without-credential","one-guardian-attacker"],
    expectedProperty: "P-CUT/GUARDIAN_TRANSITION",
    rationale:
      "HISTORICAL — finding B exactly. Relaxing the roster from STRICTLY ascending to non-decreasing makes a roster like [A, A, B] representable again, so ONE principal signing at two seats reaches a threshold of two and the guardian cut collapses to 1.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireCanonicalRoster",
        "if (members[i] <= previous) revert NotOrdered();",
        "if (members[i] < previous) revert NotOrdered();",
      ),
  },
  {
    id: "M10-nonce-not-consumed",
    profiles: ["replay-composition"],
    expectedProperty: "P-CUT/ASSET_MOVEMENT",
    rationale:
      "PHASE 9. `_consume` stops advancing the counter, so every signed action becomes infinitely replayable. A single captured spend signature drains the vault, and the replay campaign is what surfaces it.",
    apply: (s) => replaceWithinFunction(s, "_consume", "nonces[domain] = nonce + 1;", "nonces[domain] = nonce;"),
  },
  {
    id: "M11-plane-denial-ignored",
    profiles: ["policy-plane-denial"],
    expectedProperty: "P-PLANE-SUBTRACTIVE",
    rationale:
      "PHASE 10, finding F's neighbour. execute() consults the policy plane and then IGNORES its answer, so a plane that DENIES no longer denies and value moves without admission. " +
      "This replaces an earlier mutation that moved a state write in front of the authority check: that one is UNSOUND, because a reverting authorization rolls the whole transaction back, so the 'persisted' effect never persists and no property could ever observe it. " +
      "A mutation that cannot fail is not a test of anything. The gate-after-effect class needs a NON-REVERTING failure to be observable at all, and an ignored plane answer is exactly that.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "execute",
        "if (!IKernelPolicy(plane).admit(address(this), recipient, amount)) revert PolicyDenied();",
        "IKernelPolicy(plane).admit(address(this), recipient, amount);",
      ),
  },
  {
    id: "M12-migration-quorum-only",
    profiles: ["quorum-without-credential"],
    expectedProperty: "P-CUT/MIGRATION_BINDING",
    rationale:
      "I-F. bindMigration stops requiring the CREDENTIAL leg, dropping the declared k+1 cut to k. The `+1` in the published table is exactly this second principal, so this mutation is what proves the +1 is real and not decorative.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "bindMigration",
        "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
        "",
      ),
  },
  {
    id: "M13-quorum-counts-indices-not-principals",
    profiles: ["quorum-without-credential","one-guardian-attacker"],
    expectedProperty: "P-CUT/GUARDIAN_TRANSITION",
    rationale:
      "I-E. The ascending-INDEX check is removed from _requireQuorum, so one seat can be attested repeatedly. Distinct from M9: M9 attacks the committed ROSTER, this attacks the COUNTING. Both must be caught, because closing one never closed the other.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireQuorum",
        "if (previous != type(uint256).max && idx <= previous) revert NotOrdered();",
        "",
      ),
  },
  {
    id: "M14-containment-budget-removed",
    profiles: ["containment-duty-cycle","containment-composition"],
    expectedProperty: "G-CONTAINMENT-BUDGET-BOUNDED",
    rationale:
      "PHASE 8. Removing the rolling budget check turns containment from a bounded DUTY CYCLE into an unbounded denial state, which is the permanent-recovery-veto shape AUTHORITY.md declares unreachable.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "enterContainment",
        "if (containmentUsedInWindow + CONTAINMENT_MAX > CONTAINMENT_BUDGET) revert ContainmentBudget();",
        "",
      ),
  },
  {
    id: "M15-effective-state-ignores-expiry",
    profiles: ["containment-composition"],
    expectedProperty: "G-EFFECTIVE-STATE-DERIVATION",
    rationale:
      "PHASE 8. `_effectiveState` stops honouring wall-clock expiry, so the STORED value and the ENFORCED value diverge: observation and enforcement contradict each other, which is the stale-state hazard this getter exists to prevent.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_effectiveState",
        "if (safeState == SafeState.CONTAINED && block.timestamp >= containedUntil) return SafeState.NORMAL;",
        "",
      ),
  },
  /*
   * M16-recovery-ignores-roster-generation — RETIRED IN LANE SD10-I.
   * ----------------------------------------------------------------
   * RETIRED, NOT DELETED, because "the implementation now looks like the mutant"
   * is the weakest possible reason to drop a mutant and the adjudication is the
   * part worth keeping.
   *
   * WHAT IT DID. It removed, from `executeRecovery`, exactly this statement:
   *
   *     if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();
   *
   * That is BYTE-IDENTICAL to the correction Lane SD10-I makes (verified by
   * reconstructing the mutation against base a42f5c7e and comparing it to the
   * lane's removal). The mutant no longer applies at all: its anchor is gone,
   * and `replaceWithinFunction` would throw rather than silently no-op.
   *
   * WHAT ITS LABEL CLAIMED. `expectedProperty: "P-CUT/CREDENTIAL_REPLACEMENT"`,
   * rationale "a stale authorization surviving the transition that should have
   * killed it".
   *
   * WHAT ACTUALLY KILLED IT, MEASURED. Reconstructed against the base kernel and
   * run across both of its profiles at all eight campaign seeds (16 campaigns,
   * 22-44 successful transitions each), M16 produced exactly ONE violation:
   * `P-MODEL` at `recovery-vs-roster` seed 29. `P-CUT/CREDENTIAL_REPLACEMENT`
   * never fired once. The catalogue credited it because
   * StatefulMutationAdequacy's attribution falls back to `violations[0]` when the
   * expected property is absent, so a mutant's `expectedProperty` is a LABEL and
   * not a measurement.
   *
   * WHY THAT KILL DOES NOT SURVIVE SCRUTINY. `P-MODEL` here was the harness's own
   * R1 rule in `actions.ts`, which asserted that a roster transition after
   * approval must void the request. That rule was IMPLEMENTATION-DERIVED — it
   * agreed with the very statement M16 removed — and it contradicts
   * `docs/Vault_vNext_Architecture.md` I-APPROVED-REQUEST-PRESERVATION: "once a
   * request reaches quorum, a guardian-set replacement cannot clear it." It has
   * been retired for that reason, and with it M16's only killer.
   *
   * SO M16 IS NOT A MUTANT. Its "weakened" behaviour is the architecture-
   * conformant behaviour, and SD-10 was the defect it described. Retiring it
   * costs NO mutation coverage that anything else covered: it was killed by one
   * rule, on one seed, and that rule was wrong. The direction that DOES need
   * guarding is the inverse, and it is now guarded far more strictly than M16
   * ever was — `test/Sd10PreservationMutations.test.ts` carries
   * M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST (this statement REINSERTED),
   * killed deterministically, with kill credit refused unless the observation is
   * exactly "a preserved, mature, validly-proven request was REFUSED (BadRoster)".
   *
   * `recovery-vs-roster` keeps its place in `profiles.ts`: composing rotation
   * with maturing recoveries is still the composition that matters, and it is now
   * the composition the preservation property is measured over.
   */
  {
    id: "M17-floor-shape-mutable-again",
    profiles: ["ecdsa-only-attacker", "recovery-composition", "recovery-maturation", "mixed-roots-attacker"],
    expectedProperty: "G-FLOOR-NO-DOWNGRADE",
    rationale:
      "SD-1, REINTRODUCED. Deletes `I-FLOOR-SHAPE-IMMUTABLE` from `_requireNoDowngrade`, restoring the exact defect the remediation closed: `setVerifier` may move the two STRUCTURAL floor fields again, and `_requireIncomingPossession` measures an already-quorum-approved recovery against them LIVE. Since no guardian path writes `securityFloor`, one such move is an UNCOUNTED veto over guardian recovery — `challengesUsed` never advances. It is killed by the transition-level property, not by a downstream revert, so the kill is attributed to the clause that was removed.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireNoDowngrade",
        `if (
            current.requirePq &&
            (next.pqPublicKeyLength != current.pqPublicKeyLength ||
                next.pqSignatureLength != current.pqSignatureLength)
        ) revert Downgrade();`,
        "",
      ),
  },
  {
    id: "M18-floor-shape-freeze-is-one-sided",
    profiles: ["ecdsa-only-attacker", "recovery-composition", "recovery-maturation", "mixed-roots-attacker"],
    expectedProperty: "G-FLOOR-NO-DOWNGRADE",
    rationale:
      "SD-1, REINTRODUCED IN ONE DIRECTION ONLY — the subtler half, and the one a shrink-only campaign cannot see. `I-FLOOR-SHAPE-IMMUTABLE` is an INEQUALITY because `_requireIncomingPossession` compares the shape for EXACT EQUALITY: growing 1312 -> 2000 denies a quorum-approved recovery exactly as shrinking 1312 -> 1 does. Weakening the clause to `<` reads like a downgrade check and passes any campaign that only ever shrinks. It is killed only because `actions.ts` directs the poisoning attempt UPWARD wherever the clause is armed — a choice that costs no prng draw and moves no reachable state, since on the correct kernel a grow and a shrink revert `Downgrade` identically. That is the entire reason the direction is chosen rather than fixed.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireNoDowngrade",
        `(next.pqPublicKeyLength != current.pqPublicKeyLength ||
                next.pqSignatureLength != current.pqSignatureLength)`,
        `(next.pqPublicKeyLength < current.pqPublicKeyLength ||
                next.pqSignatureLength < current.pqSignatureLength)`,
      ),
  },
  {
    id: "M19-declaration-not-exhibited",
    profiles: ["ecdsa-only-floor", "ecdsa-only-committed"],
    expectedProperty: "G-PQ-COMMITMENT-SATISFIABLE",
    rationale:
      "SD-3, REINTRODUCED. Deletes `I-DECLARATION-EXHIBITED`'s two comparisons, so `setVerifier` may again arm the PQ conjunct against a commitment no code has ever measured — including the zero commitment `initialize` explicitly refuses. The killing property is the one SD-3 was filed under, and it only became ENFORCEABLE when SD-3 left KNOWN_DEFECT_PROPERTIES: while the defect stood, this very violation was counted and discarded rather than failing the run.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setVerifier",
        `if (!securityFloor.requirePq && floor.requirePq && pqKey.length != floor.pqPublicKeyLength) {
            revert BadSignature();
        }
        if (!securityFloor.requirePq && floor.requirePq && keccak256(pqKey) != pqPublicKeyHash) {
            revert BadSignature();
        }`,
        "",
      ),
  },
  {
    id: "M20-declaration-unbound-from-the-commitment",
    profiles: ["ecdsa-only-floor", "ecdsa-only-committed"],
    expectedProperty: "G-PQ-COMMITMENT-SATISFIABLE",
    rationale:
      "REMOVE THE BINDING TO THE COMMITTED MATERIAL while keeping the shape check — the half of `I-DECLARATION-EXHIBITED` that carries all of its meaning. The declaration still looks witnessed, because a byte string of the declared length is still demanded, but that string no longer has to be the vault's key: any blob of the right size passes, so a ZERO-commitment vault arms again and the exact SD-3 dead state returns. It is distinct from M19, which deletes the clause outright, and it is the mutant that proves the shape leg alone is worthless.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "setVerifier",
        `if (!securityFloor.requirePq && floor.requirePq && keccak256(pqKey) != pqPublicKeyHash) {
            revert BadSignature();
        }`,
        "",
      ),
  },
  {
    id: "M21-admission-not-exhibited",
    profiles: ["commitment-forgery"],
    expectedProperty: "G-COMMITMENT-ATTESTED",
    rationale:
      "SD-6, REINTRODUCED. Deletes `I-COMMITMENT-EXHIBITED-AT-ADMISSION`'s dormant clause, so `_requireIncomingPossession` again returns before every PQ check while `requirePq` is false, and BOTH of its callers — `rotateCredential` and `executeRecovery` — write a commitment attested by nothing. Killed by the property that watches the whole ingress surface rather than any one function.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireIncomingPossession",
        `if (!floor.requirePq && expectedPqKeyHash != bytes32(0) && keccak256(c.newPqKey) != expectedPqKeyHash) {
            revert BadSignature();
        }`,
        "",
      ),
  },
  {
    id: "M22-admission-bound-to-the-OUTGOING-commitment",
    profiles: ["commitment-forgery"],
    expectedProperty: "G-COMMITMENT-ATTESTED",
    rationale:
      "BIND THE WRONG VARIABLE. The clause still runs, still demands a preimage and still reverts on a mismatch — but it measures the exhibit against the commitment ALREADY IN STORAGE instead of the one being installed. An attacker exhibits the vault's current key, which is public data, and writes any hash it likes beside it. This is the old/new commitment confusion, and it proves the clause's value lies in WHICH value it binds rather than in the mere presence of a keccak comparison.",
    apply: (s) =>
      replaceWithinFunction(
        s,
        "_requireIncomingPossession",
        `if (!floor.requirePq && expectedPqKeyHash != bytes32(0) && keccak256(c.newPqKey) != expectedPqKeyHash) {`,
        `if (!floor.requirePq && expectedPqKeyHash != bytes32(0) && keccak256(c.newPqKey) != pqPublicKeyHash) {`,
      ),
  },
];

/**
 * A CLAUSE THIS CATALOGUE DELIBERATELY DOES NOT COVER, named rather than hidden.
 *
 * The SD-1 remediation's companion clause — the `MAX_PQ_LENGTH` magnitude bound
 * in `_requireSaneFloor` — has no mutant here, and the reason is a real trade
 * rather than an oversight. Reaching that seam requires the generator to emit an
 * oversized shape, which needs one more `prng` draw in `genParams`; every
 * campaign is a pure function of (profile, seed, depth), so a single extra draw
 * re-seeds every history and moves which seed catches which mutant. It was tried
 * firsthand and it turned M9 and M11 into survivors. Buying one new seam at the
 * price of two established ones is a worse catalogue, not a better one.
 *
 * The clause is instead covered deterministically, with both directions
 * asserted, by the BOUNDARY case in test/Sd1RecoveryFloorBinding.test.ts: a
 * shape above the bound is REFUSED, and a 49,856-byte SPHINCS+-256f signature
 * shape is ACCEPTED. Deleting the clause turns that test red, which is the same
 * evidence a mutant would have produced.
 */
export const UNMUTATED_CLAUSES: readonly { clause: string; coveredBy: string; whyNotMutated: string }[] = [
  {
    clause: "_requireSaneFloor's MAX_PQ_LENGTH magnitude bound",
    coveredBy:
      "test/Sd1RecoveryFloorBinding.test.ts — BOUNDARY (exactly MAX_PQ_LENGTH admitted, MAX_PQ_LENGTH + 1 refused, pinned against the contract's own getter) and GENESIS, both with positive controls",
    whyNotMutated:
      "Reaching the seam needs an extra prng draw in genParams, which re-seeds every campaign history; adding one was measured to turn M9-duplicate-guardian-principal and M11-plane-denial-ignored into survivors. The complete value space for floor lengths across the whole stateful model is {0, 1, 32, 65} plus the armed grow direction, so no campaign proposes an oversized shape and a mutant here would report SURVIVED for want of a generator rather than for want of a property.",
  },
  {
    clause: "I-DECLARATION-EXHIBITED's LENGTH leg (`pqKey.length != floor.pqPublicKeyLength`)",
    coveredBy:
      "test/Sd34DeclarationInvariants.test.ts — 'SD-3 FORM 2' (a shape the committed key cannot meet is refused in BOTH directions) and 'the ZERO-LENGTH trap stays closed', each with a positive control",
    whyNotMutated:
      "The oracle cannot see it. Deleting the length leg produces a state whose commitment is NON-ZERO and whose shape is merely wrong for that commitment, and no property computable from storage alone can detect that — knowing it requires the preimage LENGTH of a hash, which is exactly the fact `I-DECLARATION-EXHIBITED` makes the KERNEL establish on chain precisely because an observer cannot. A mutant here would report SURVIVED for want of an oracle rather than for want of coverage, so it is disclosed instead of faked. The HASH leg, which carries the clause's meaning, IS mutated — see M20.",
  },
  {
    clause:
      "I-COMMITMENT-EXHIBITED-AT-ADMISSION's two GENESIS legs in `initialize` (the preimage check on a non-zero `g.pqKeyHash`, and the length check under `g.floor.requirePq`)",
    coveredBy:
      "test/Sd67AdmissionInvariants.test.ts — four executed refusals (no preimage, wrong-length preimage, zero commitment under requirePq, unattested dormant commitment) against four positive controls (a legitimate PQ genesis that then SPENDS, the cold-ceremony zero-commitment deploy, the MAX_PQ_LENGTH shape with a genuine 65,535-byte key, and the pinned `genesisSalt` identity constant). test/Sd34AuthenticationSatisfiability.test.ts additionally runs the original 48-against-32 reproduction with its verdict moved.",
    whyNotMutated:
      "The campaign structurally cannot reach the seam. Every world is built by `deployWorld`, which constructs a genesis committing either `bytes32(0)` or `pqHash(world.pqKey)` — both attestable, both consistent with the declared shape — so no profile deploys a hostile genesis and no mutation of the genesis legs would change any campaign outcome. Making one reachable means letting the generator author arbitrary genesis configurations, which is a different harness (a deployment fuzzer, not a transition fuzzer) and would re-seed every existing history. A mutant here would report SURVIVED for want of a generator rather than for want of a property, so the coverage is carried by direct regression instead and disclosed here rather than faked. The INDUCTIVE half of the same invariant — the dormant clause in `_requireIncomingPossession`, which both mid-campaign writers route through — IS mutated twice, by M21 and M22.",
  },
];

/** Builds the mutated deployable kernel for one mutation. Throws if the edit did not apply. */
export function buildMutant(m: Mutation): { ok: true; kernel: DeployableMutant } | { ok: false; errors: string[] } {
  const mutated = m.apply(kernelSource());
  return compileDeployable({ "VaultKernelPrototype.sol": mutated });
}
