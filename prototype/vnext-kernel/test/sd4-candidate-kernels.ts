/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE SD-4 CANDIDATE FAMILIES, BUILT RATHER THAN ARGUED.
 *
 * PR #188 adjudicated exactly two designs — A (snapshot the proposed SHAPE into
 * the request and measure the recovery against it) and E (let a completed
 * recovery RE-DECLARE the floor shape) — and then generalised from those two to
 *
 *   "Every design that preserves the quorum's proposal across the declaring edge
 *    must either brick the vault or hand the quorum the shape ... No fifth
 *    family is known."
 *
 * That is a claim about the WHOLE design space, drawn from two points in it.
 * This module builds four more families so the claim is tested rather than
 * repeated. Every kernel below is compiled IN MEMORY from the real
 * `contracts/VaultKernelPrototype.sol` with a textual delta; ZERO bytes of
 * production or prototype Solidity are changed on disk.
 *
 * WHY THE DISAGREEMENT EXISTS AT ALL, stated once so each family can be read as
 * an answer to it. At `executeRecovery` two values must agree:
 *
 *   (i)  `recovery.proposedPqKeyHash` — fixed by the QUORUM at approval time;
 *   (ii) `securityFloor.pqPublicKeyLength` / `pqSignatureLength` — read LIVE,
 *        and movable exactly once, by the CREDENTIAL, on the declaring edge.
 *
 * There are only four structural ways to resolve a disagreement between them:
 * move (i), move (ii), change who authorises (i), or refuse the transition that
 * creates the disagreement. Design A moves (i) into the request and measures
 * against it — which relocates the disagreement to `_authorise` instead of
 * removing it. Design E moves (ii) — which hands the quorum the shape. The
 * families here take the two remaining directions, plus the one #188's own
 * argument leaves out: the disagreement need not be resolved at all if the
 * transition that CREATES it is METERED rather than free.
 *
 *   F         — change who authorises (i): the already-quorum-nominated INCOMING
 *               SIGNER binds its own PQ commitment at execution.
 *   F_SCOPED  — F, restricted to the window in which the disagreement can arise.
 *   G         — keep the quorum as the authoriser of (i), but let it AMEND (i)
 *               inside the SAME episode, without restarting the clock.
 *   H*        — do not resolve the disagreement; METER the transition that
 *               creates it, so it consumes the same budget `cancelRecovery`
 *               consumes.
 *
 * NONE of these writes `securityFloor` anywhere, so `I-FLOOR-SHAPE-IMMUTABLE`
 * survives every one of them by construction. That is checked executably in
 * `Sd4CandidateFamilies.test.ts` rather than asserted here.
 */
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { compileDeployable } from "../stateful/mutants.js";
import { replaceWithinFunction } from "../authority/mutation-harness.js";

const SRC = path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "VaultKernelPrototype.sol");
const MOCKS = path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "PrototypeMocks.sol");

export interface Deployable {
  abi: unknown[];
  bytecode: string;
}

export const kernelSource = (): string => fs.readFileSync(SRC, "utf8");

/** Whole-file replacement that REFUSES a non-unique or missing anchor. */
function replaceOnce(source: string, oldText: string, newText: string, label: string): string {
  const n = source.split(oldText).length - 1;
  if (n !== 1) throw new Error(`anchor "${label}" matched ${n} times, expected exactly 1`);
  return source.replace(oldText, newText);
}

function build(label: string, source: string): Deployable {
  const out = compileDeployable({ "VaultKernelPrototype.sol": source });
  if (!out.ok) throw new Error(`${label} failed to compile:\n${out.errors.join("\n")}`);
  return out.kernel;
}

// ---------------------------------------------------------------------
// An in-memory AUXILIARY contract compiler.
//
// `compileDeployable` extracts only `VaultKernelPrototype`, and the adjudication
// needs one contract it does not have: a verifier that performs a REAL
// possession check at a shape OTHER than the fixture's 32/65. Without it, the
// only way to accept a 64-byte signature in this repository is
// `ConfigurableVerifier(ALWAYS_TRUE)` — which would make every G-PRIME result
// indistinguishable from "the PQ conjunct was collapsed to nothing", exactly the
// objection the adversarial pass raises against it.
//
// The solc lookup below is duplicated from `authority/mutation-harness.ts`, which
// itself duplicates `reproduce.ts` and says so: these modules must stay runnable
// standalone. Nothing is written to `contracts/`.
// ---------------------------------------------------------------------

const SOLC_VERSION = "0.8.24";

function solcPath(): string {
  const home = os.homedir();
  const cacheRoot =
    os.platform() === "win32"
      ? path.join(process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local"), "hardhat-nodejs", "Cache")
      : os.platform() === "darwin"
        ? path.join(home, "Library", "Caches", "hardhat-nodejs")
        : path.join(process.env.XDG_CACHE_HOME ?? path.join(home, ".cache"), "hardhat-nodejs");
  const platform =
    os.platform() === "win32"
      ? "windows-amd64"
      : os.platform() === "darwin"
        ? "macosx-amd64"
        : os.arch() === "arm64"
          ? "linux-arm64"
          : "linux-amd64";
  const base = path.join(cacheRoot, "compilers-v3", platform);
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) throw new Error(`pinned solc ${SOLC_VERSION} not found in ${base}`);
  return path.join(base, hit);
}

/** Compiles `PrototypeMocks.sol` with `extra` appended and extracts one contract. */
export function compileAuxContract(contractName: string, extra: string): Deployable {
  const sources: Record<string, { content: string }> = {
    "contracts/PrototypeMocks.sol": { content: fs.readFileSync(MOCKS, "utf8") + "\n" + extra },
    "contracts/interfaces/IKernelPlanes.sol": {
      content: fs.readFileSync(
        path.join(process.cwd(), "prototype", "vnext-kernel", "contracts", "interfaces", "IKernelPlanes.sol"),
        "utf8",
      ),
    },
  };
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
  const raw = execFileSync(solcPath(), ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 256 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as {
    errors?: { severity: string; formattedMessage: string }[];
    contracts?: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string } } }>>;
  };
  const fatal = (parsed.errors ?? []).filter((e) => e.severity === "error").map((e) => e.formattedMessage);
  if (fatal.length > 0) throw new Error(`${contractName} failed to compile:\n${fatal.join("\n")}`);
  const unit = parsed.contracts?.["contracts/PrototypeMocks.sol"]?.[contractName];
  if (!unit) throw new Error(`${contractName} missing from compiler output`);
  return { abi: unit.abi, bytecode: "0x" + unit.evm.bytecode.object };
}

/**
 * A verifier that performs a GENUINE possession check at a 32-byte key and a
 * 64-BYTE signature: the 65-byte ECDSA encoding with the recovery byte dropped,
 * recovered by trying both parities. It is cryptographically as strong as the
 * fixture's `EcdsaBackedVerifier` and differs from it ONLY in declared shape,
 * which is exactly the variable under test.
 */
export const VERIFIER_32_64_SOURCE = `
contract EcdsaBackedVerifier64 is IKernelPQVerifier {
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature) external pure returns (bool) {
        if (publicKey.length != 32 || signature.length != 64) return false;
        address expected = address(uint160(uint256(bytes32(publicKey[0:32]))));
        if (expected == address(0)) return false;
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        for (uint8 v = 27; v <= 28; v++) {
            (address rec, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, v, r, s);
            if (err == ECDSA.RecoverError.NoError && rec == expected) return true;
        }
        return false;
    }
}
`;

// =====================================================================
// Shared deltas
// =====================================================================

/**
 * `recoveryPossessionDigest` becomes a FUNCTION OF THE COMMITMENT BEING
 * INSTALLED rather than a reader of the stored one.
 *
 * THIS IS THE ANTI-STRAWMAN CLAUSE, and it is why every family below is built
 * on top of it. If the PoP digest stayed insensitive to the late-bound hash, a
 * relayer could swap `c.newPqKeyHash` and reuse the nominee's signature, and
 * candidate F would be trivially dead for a reason that has nothing to do with
 * its architecture. Every other field the stored digest bound — chain, vault,
 * kernel generation, signer, verifier, guardian generation and `executableAt` —
 * is preserved EXACTLY, so nothing about cross-vault, cross-chain,
 * cross-generation or cross-episode separation is loosened.
 */
function digestTakesCommitment(source: string): string {
  let s = replaceOnce(
    source,
    "    function recoveryPossessionDigest() public view returns (bytes32) {",
    "    function recoveryPossessionDigest(bytes32 boundPqKeyHash) public view returns (bytes32) {",
    "recoveryPossessionDigest signature",
  );
  s = replaceWithinFunction(s, "recoveryPossessionDigest", "                    r.proposedPqKeyHash,", "                    boundPqKeyHash,");
  return s;
}

/** The exact `executeRecovery` block every family below rewrites. */
const EXEC_BLOCK = `        _requireIncomingPossession(
            recoveryPossessionDigest(),
            r.proposedSigner,
            r.proposedPqKeyHash,
            r.proposedVerifier,
            c
        );

        delete recovery;
        pqVerifier = r.proposedVerifier;
        _installCredential(r.proposedSigner, r.proposedPqKeyHash);`;

const INITIATE_SIG = `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {`;

// =====================================================================
// CANDIDATE F — nominee-late-bound PQ credential
// =====================================================================

/**
 * The quorum authorises WHO (the signer) and WHICH ORACLE (the verifier). The
 * PQ commitment is bound at execution by the SAME principal the quorum already
 * nominated, and is authenticated by that principal's ECDSA possession proof.
 *
 * The hidden assumption this attacks: that the quorum must name the exact
 * `proposedPqKeyHash` before any PQ shape exists. It need not, because
 * `executeRecovery` ALREADY refuses to install anything without an ECDSA
 * possession proof from `proposedSigner` — so the nominee is already a
 * mandatory participant, and giving it authority over its own second factor
 * introduces no new principal and no new liveness dependency.
 *
 * WHAT IS NOT WEAKENED, by construction:
 *   - `_requireIncomingPossession` still measures the LIVE floor, so the
 *     installed credential is always satisfiable by the vault's own policy —
 *     the exact failure design A produces is unreachable here;
 *   - `securityFloor` is never written, so `I-FLOOR-SHAPE-IMMUTABLE` holds;
 *   - the PQ possession leg still runs against the INCOMING verifier, so the
 *     installed second factor is one somebody demonstrably holds
 *     (`I-COMMITMENT-EXHIBITED-AT-ADMISSION` and its dormant half both survive);
 *   - the verifier stays QUORUM-chosen, so `I-NO-CIRCULAR-ESCAPE`'s guardian
 *     escape from a dead verifier is untouched.
 *
 * WHAT IS DELIBERATELY DIFFERENT, stated as the cost rather than buried: the
 * incoming PQ factor is designated by the incoming ECDSA factor instead of by
 * the quorum. `Sd4CandidateFamilies.test.ts` attacks exactly that.
 */
export function buildCandidateF(): Deployable {
  let s = digestTakesCommitment(kernelSource());

  s = replaceOnce(
    s,
    INITIATE_SIG,
    `    function initiateRecovery(
        address proposedSigner,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {`,
    "initiateRecovery signature (F)",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    "keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),",
    "keccak256(abi.encode(proposedSigner, proposedVerifier)),",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    "            proposedPqKeyHash: proposedPqKeyHash,",
    "            proposedPqKeyHash: bytes32(0),",
  );

  s = replaceOnce(
    s,
    EXEC_BLOCK,
    `        _requireIncomingPossession(
            recoveryPossessionDigest(c.newPqKeyHash),
            r.proposedSigner,
            c.newPqKeyHash,
            r.proposedVerifier,
            c
        );

        delete recovery;
        pqVerifier = r.proposedVerifier;
        _installCredential(r.proposedSigner, c.newPqKeyHash);`,
    "executeRecovery block (F)",
  );

  return build("candidate F", s);
}

/**
 * CANDIDATE F-SCOPED. Late binding is available ONLY in the window where the
 * disagreement can actually arise: the request was approved while `requirePq`
 * was FALSE and the live floor now mandates PQ. In every other state the
 * guardian-named commitment binds EXACTLY as it does today.
 *
 * `pqRequiredAtApproval` is a FACT ABOUT THE PAST, not a policy: it records what
 * the floor already was at approval, is written once by `initiateRecovery`, and
 * is read by nothing but the branch below. It is deliberately NOT a snapshot of
 * the SHAPE — that is design A, and design A is what bricks the vault.
 */
export function buildCandidateFScoped(): Deployable {
  let s = digestTakesCommitment(kernelSource());

  s = replaceOnce(
    s,
    `        uint32 challengesUsed;
        bool active;
    }`,
    `        uint32 challengesUsed;
        bool active;
        /// @dev What the floor ALREADY WAS at approval. A fact, never a policy.
        bool pqRequiredAtApproval;
    }`,
    "RecoveryRequest struct (F-SCOPED)",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    `            challengesUsed: recovery.challengesUsed,
            active: true`,
    `            challengesUsed: recovery.challengesUsed,
            active: true,
            pqRequiredAtApproval: securityFloor.requirePq`,
  );

  s = replaceOnce(
    s,
    EXEC_BLOCK,
    `        // LATE BINDING IS SCOPED TO THE ONE WINDOW THAT CREATES THE PROBLEM.
        // Outside it the quorum's commitment binds exactly as before, so no
        // recovery that could already succeed changes its authority model.
        bytes32 bound = (!r.pqRequiredAtApproval && securityFloor.requirePq)
            ? c.newPqKeyHash
            : r.proposedPqKeyHash;

        _requireIncomingPossession(
            recoveryPossessionDigest(bound),
            r.proposedSigner,
            bound,
            r.proposedVerifier,
            c
        );

        delete recovery;
        pqVerifier = r.proposedVerifier;
        _installCredential(r.proposedSigner, bound);`,
    "executeRecovery block (F-SCOPED)",
  );

  return build("candidate F-SCOPED", s);
}

// =====================================================================
// DESIGN A — #188's rejected snapshot, rebuilt for the CORRECTION tests
// =====================================================================

/**
 * A faithful reconstruction of the design PR #188 built and rejected: the two
 * length fields recorded in `RecoveryRequest`, bound into the guardian digest,
 * threaded into `_requireIncomingPossession`, with `rotateCredential` left on
 * the live floor and `executeRecovery` measuring against the REQUEST.
 *
 * It is rebuilt here rather than imported because #188's builder is a private
 * function of its own test file. Identity is established BEHAVIOURALLY — the
 * corrections suite reproduces both of #188's own observations about it (SD-4
 * closes; the installed credential cannot spend) before going on to test the
 * claim #188 drew FROM them, which is the part under review.
 */
export function buildDesignAReplica(): Deployable {
  let s = kernelSource();

  s = replaceOnce(
    s,
    `        uint32 challengesUsed;
        bool active;
    }`,
    `        uint32 challengesUsed;
        bool active;
        uint32 proposedPqKeyLength;
        uint32 proposedPqSigLength;
    }`,
    "RecoveryRequest struct (design A)",
  );
  s = replaceOnce(
    s,
    `        address verifierToUse,
        CredentialChange calldata c
    ) internal view {`,
    `        address verifierToUse,
        CredentialChange calldata c,
        uint32 expectedKeyLen,
        uint32 expectedSigLen
    ) internal view {`,
    "_requireIncomingPossession signature (design A)",
  );
  s = replaceWithinFunction(
    s,
    "_requireIncomingPossession",
    "if (c.newPqKey.length != floor.pqPublicKeyLength || c.newPqPop.length != floor.pqSignatureLength) {",
    "if (c.newPqKey.length != expectedKeyLen || c.newPqPop.length != expectedSigLen) {",
  );
  s = replaceWithinFunction(
    s,
    "rotateCredential",
    `            pqVerifier,
            c
        );`,
    `            pqVerifier,
            c,
            securityFloor.pqPublicKeyLength,
            securityFloor.pqSignatureLength
        );`,
  );
  s = replaceWithinFunction(
    s,
    "executeRecovery",
    `            r.proposedVerifier,
            c
        );`,
    `            r.proposedVerifier,
            c,
            r.proposedPqKeyLength,
            r.proposedPqSigLength
        );`,
  );
  s = replaceOnce(
    s,
    INITIATE_SIG,
    `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline,
        uint32 proposedPqKeyLength,
        uint32 proposedPqSigLength
    ) external {`,
    "initiateRecovery signature (design A)",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    "keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),",
    "keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier, proposedPqKeyLength, proposedPqSigLength)),",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    `            challengesUsed: recovery.challengesUsed,
            active: true`,
    `            challengesUsed: recovery.challengesUsed,
            active: true,
            proposedPqKeyLength: proposedPqKeyLength,
            proposedPqSigLength: proposedPqSigLength`,
  );

  return build("design A replica", s);
}

// =====================================================================
// CANDIDATE G — same-episode quorum ratification
// =====================================================================

/**
 * The quorum keeps sole authority over the commitment, and gains ONE new act:
 * amending that commitment inside the SAME recovery episode.
 *
 * WHAT IT MAY NOT TOUCH, enforced structurally rather than by comment — the
 * function takes no parameter for any of them, so no version of the calldata can
 * move them: `proposedSigner`, `proposedVerifier`, `executableAt`, `expiresAt`,
 * `boundGuardianGeneration`, `challengesUsed`, `active`.
 *
 * The ratification digest binds the EXISTING REQUEST IDENTITY — signer, verifier
 * and `executableAt` — so a quorum attestation collected for one episode cannot
 * be replayed into a different one, and a `RATIFY_TAG` keeps it out of the
 * `ACTION_RECOVER` initiation preimage. It consumes `DOMAIN_GUARDIAN`'s nonce
 * like every other guardian act.
 */
const RATIFY_FN = `
    /**
     * @notice Amend the PQ commitment of the LIVE recovery episode, by the same
     *         guardian authority that approved it, WITHOUT restarting its clock.
     *
     * @dev The timer is the credential's window to object, and it is left
     *      untouched: executableAt and expiresAt are not parameters and are
     *      not written. challengesUsed is not written either, so this cannot
     *      refund or consume the credential's bounded veto.
     */
    function ratifyRecoveryCommitment(
        bytes32 newPqKeyHash,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {
        _requireRecoveryOpen();
        RecoveryRequest memory r = recovery;
        if (!r.active) revert NoRecovery();
        if (block.timestamp > r.expiresAt) revert Expired();
        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            guardianGeneration,
            keccak256(abi.encode(RATIFY_TAG, newPqKeyHash, r.proposedSigner, r.proposedVerifier, r.executableAt)),
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        recovery.proposedPqKeyHash = newPqKeyHash;
        emit RecoveryRatified(r.proposedSigner, newPqKeyHash, r.executableAt);
    }
`;

export function buildCandidateG(): Deployable {
  let s = kernelSource();

  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant RATIFY_TAG = keccak256("RATIFY_RECOVERY_COMMITMENT");`,
    "POP_TAG constant (G)",
  );
  s = replaceOnce(
    s,
    `    event RecoveryCancelled(uint32 challengesUsed);`,
    `    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryRatified(address indexed proposedSigner, bytes32 pqKeyHash, uint64 executableAt);`,
    "RecoveryCancelled event (G)",
  );
  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }
${RATIFY_FN}`,
    "executeRecovery tail (G)",
  );

  return build("candidate G", s);
}

// =====================================================================
// CANDIDATE G-PRIME — ratify the COMMITMENT AND THE VERIFIER together
// =====================================================================

/**
 * G, REPAIRED AFTER ADVERSARIAL REVIEW. Plain G is INERT against the half of
 * SD-4 that runs through `pqSignatureLength`, and the reason is precise: the
 * possession check calls `IKernelPQVerifier(r.proposedVerifier).verify(...)`
 * with the verifier the quorum pinned at t0, while the credential chooses BOTH
 * structural lengths at t1. A verifier is a SHAPE-SPECIFIC oracle — the
 * fixture's `EcdsaBackedVerifier` accepts a 32-byte key and a 65-byte signature
 * and nothing else — so amending only the commitment repairs only the
 * commitment. Executed in `Sd4RedTeamRound2.test.ts`.
 *
 * G-PRIME amends the commitment AND the verifier as ONE quorum act, because
 * they are one decision: "which second factor, checked by which oracle". Both
 * were already the quorum's to choose at `initiateRecovery`, and both are
 * already re-choosable by re-initiation at the cost of a fresh delay — so this
 * grants the quorum NO end state it lacked, and that is asserted rather than
 * argued.
 *
 * The signer is still not a parameter. The two timers are still not written.
 * `challengesUsed` is still not written. `securityFloor` is still never written
 * by any guardian path, so `I-FLOOR-SHAPE-IMMUTABLE` is untouched.
 */
/**
 * THE TEMPORAL LADDER. Round 3 priced G-PRIME on the minimum-compromise-cut
 * axis alone and called it survivable. That census measures WHO must be
 * compromised; it is structurally blind to WHEN the values they install become
 * observable. These four rungs differ ONLY in that second quantity.
 *
 *  atomic — amend any time before expiry. Guaranteed notice on the payload that
 *           actually executes: ZERO (ratify and execute compose in one block).
 *  notice — amend only strictly before maturity. Guaranteed notice: STILL ZERO.
 *           "Before maturity" is unbounded below; maturity-minus-one-second is
 *           a legal amendment. This rung exists to be KILLED, and it is mine,
 *           not #188's — round 2 offered it as the fix for exactly this hazard.
 *   delay — the amended payload must itself age RATIFICATION_DELAY. First rung
 *           with a guarantee that is not zero.
 *   reset — the amended payload ages a full RECOVERY_DELAY, exactly as
 *           amendment-by-re-initiation would have.
 * clamped — `delay`, plus a refusal of any ratification that would push maturity
 *           PAST expiry. Added after lane T measured `delay` and `reset` both
 *           creating a window closed from both sides — a dead episode with no
 *           adversary, caused by the fix rather than by the defect.
 *
 * LANE U adds three more, distinguished by what the AUTHORITY-REQUIRED interval
 * is and what it is allowed to move:
 *
 *  u1full — the amended payload ages a full RECOVERY_DELAY, and an amendment
 *           that could not age and still execute is REFUSED. Expiry never moves.
 *     u2a — `reset`, renamed for the lane: executableAt := now + RECOVERY_DELAY,
 *           expiry untouched. Included to show what refusing to clamp costs.
 *     u2b — executableAt AND expiresAt both re-derived from now. This is the
 *           "new window" family, and the question it must answer is whether it
 *           is anything other than `initiateRecovery` spelled differently.
 */
export type GPrimeVariant =
  | "atomic"
  | "notice"
  | "delay"
  | "reset"
  | "clamped"
  | "u1full"
  | "u2a"
  | "u2b";

const NOTICE_GUARD = `        // NOTICE GUARD: amendment only INSIDE the delay, never after maturity,
        // so a ratification can never compose atomically with an execution.
        if (block.timestamp >= r.executableAt) revert TooEarly();
`;

const TIMER_CLAUSE: Record<GPrimeVariant, string> = {
  atomic: "",
  notice: "",
  // `max`, not assignment: an EARLY amendment must not be able to SHORTEN the
  // episode's original maturity, which a bare assignment would permit.
  delay: `        uint64 earliest = uint64(block.timestamp) + RATIFICATION_DELAY;
        recovery.executableAt = earliest > r.executableAt ? earliest : r.executableAt;
`,
  reset: `        recovery.executableAt = uint64(block.timestamp) + RECOVERY_DELAY;
`,
  // Reuses `Expired` rather than adding an error: the episode HAS expired for
  // amendment purposes, and the quorum's fallback is the one it always had —
  // re-initiate, and pay a fresh delay.
  clamped: `        uint64 earliest = uint64(block.timestamp) + RATIFICATION_DELAY;
        uint64 newExec = earliest > r.executableAt ? earliest : r.executableAt;
        if (newExec > r.expiresAt) revert Expired();
        recovery.executableAt = newExec;
`,
  // U1 — the same shape as `clamped` with the authority-derived interval rather
  // than a novel constant. The `max` is redundant at RECOVERY_DELAY and is kept
  // so the two clauses differ ONLY in the constant, which is the point.
  u1full: `        uint64 earliest = uint64(block.timestamp) + RECOVERY_DELAY;
        uint64 newExec = earliest > r.executableAt ? earliest : r.executableAt;
        if (newExec > r.expiresAt) revert Expired();
        recovery.executableAt = newExec;
`,
  u2a: `        recovery.executableAt = uint64(block.timestamp) + RECOVERY_DELAY;
`,
  // U2b/U3. Writing expiry is the whole question: it buys back the amendment
  // window U1 loses, at the price of a capability Part F must price.
  u2b: `        recovery.executableAt = uint64(block.timestamp) + RECOVERY_DELAY;
        recovery.expiresAt = uint64(block.timestamp) + RECOVERY_DELAY + RECOVERY_EXPIRY;
`,
};

const RATIFY_PRIME_FN = (variant: GPrimeVariant): string => `
    /**
     * @notice Amend the PQ commitment AND the verifier of the LIVE recovery
     *         episode, by the guardian authority that approved it, WITHOUT
     *         restarting its clock.
     *
     * @dev The verifier is included because a commitment and the oracle that
     *      validates it are ONE decision: the credential principal may declare a
     *      shape the pinned verifier cannot accept, and amending the commitment
     *      alone then repairs nothing. Both values were already quorum-chosen at
     *      initiation and both are already re-choosable by re-initiation, so no
     *      new end state is reachable — only a cheaper path to one.
     *
     *      The signer is NOT a parameter, so no version of this calldata can
     *      replace the principal the quorum approved.
     */
    function ratifyRecoveryCommitment(
        bytes32 newPqKeyHash,
        address newVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {
        _requireRecoveryOpen();
        RecoveryRequest memory r = recovery;
        if (!r.active) revert NoRecovery();
        if (block.timestamp > r.expiresAt) revert Expired();
${variant === "notice" ? NOTICE_GUARD : ""}        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();
        if (newVerifier == address(0) || newVerifier.code.length == 0) revert ZeroAddress();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            guardianGeneration,
            keccak256(abi.encode(RATIFY_TAG, newPqKeyHash, newVerifier, r.proposedSigner, r.executableAt)),
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        recovery.proposedPqKeyHash = newPqKeyHash;
        recovery.proposedVerifier = newVerifier;
${TIMER_CLAUSE[variant]}        emit RecoveryRatified(r.proposedSigner, newPqKeyHash, recovery.executableAt);
    }
`;

/** Distinct from RECOVERY_DELAY on purpose: a measured 3d proves the DELAY
 *  clause produced the interval, where 7d would be indistinguishable from the
 *  episode's original timer still being in force. */
const RATIFICATION_DELAY_DECL = `    uint64 public constant RECOVERY_DELAY = 7 days;
    uint64 public constant RATIFICATION_DELAY = 3 days;`;

function buildGPrime(variant: GPrimeVariant): Deployable {
  let s = kernelSource();
  if (variant === "delay" || variant === "clamped") {
    s = replaceOnce(
      s,
      `    uint64 public constant RECOVERY_DELAY = 7 days;`,
      RATIFICATION_DELAY_DECL,
      "RATIFICATION_DELAY constant (G-PRIME-DELAY)",
    );
  }
  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant RATIFY_TAG = keccak256("RATIFY_RECOVERY_COMMITMENT");`,
    "POP_TAG constant (G-PRIME)",
  );
  s = replaceOnce(
    s,
    `    event RecoveryCancelled(uint32 challengesUsed);`,
    `    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryRatified(address indexed proposedSigner, bytes32 pqKeyHash, uint64 executableAt);`,
    "RecoveryCancelled event (G-PRIME)",
  );
  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }
${RATIFY_PRIME_FN(variant)}`,
    "executeRecovery tail (G-PRIME)",
  );
  return build(`candidate G-PRIME (${variant})`, s);
}

/** G-PRIME: amendment any time before expiry. Maximum repair, ZERO guaranteed notice. */
export const buildCandidateGPrime = (): Deployable => buildGPrime("atomic");

/**
 * G-PRIME-NOTICE: amendment only strictly BEFORE maturity.
 *
 * ROUND 3 CLAIMED this "leaves the credential whatever remains of the original
 * delay". That is true and worthless: the remainder is unbounded BELOW, so the
 * guaranteed notice on the payload that executes is still zero. Retained as a
 * NAMED FAILURE so the ladder shows why separating the two transactions is not
 * the same as imposing an interval between them.
 */
export const buildCandidateGPrimeNotice = (): Deployable => buildGPrime("notice");

/** G-PRIME-DELAY: the amended payload must itself age RATIFICATION_DELAY (3d). */
export const buildCandidateGPrimeDelay = (): Deployable => buildGPrime("delay");

/** G-PRIME-RESET: the amended payload ages a full RECOVERY_DELAY (7d). */
export const buildCandidateGPrimeReset = (): Deployable => buildGPrime("reset");

/**
 * G-PRIME-CLAMPED: `delay`, refusing any amendment that could not itself age and
 * still execute. Built ONLY because lane T measured the unclamped rungs bricking
 * an episode with no adversary present — a defect introduced by the remediation.
 */
export const buildCandidateGPrimeClamped = (): Deployable => buildGPrime("clamped");

/** U1 — FULL-DELAY CLAMP. The amended payload ages RECOVERY_DELAY; expiry never moves. */
export const buildCandidateU1 = (): Deployable => buildGPrime("u1full");

/** U2a — FULL RESET, expiry untouched. */
export const buildCandidateU2a = (): Deployable => buildGPrime("u2a");

/** U2b / U3 — NEW WINDOW: both timers re-derived from the amendment instant. */
export const buildCandidateU2b = (): Deployable => buildGPrime("u2b");

// =====================================================================
// LANE V CONFORMANCE PROBES — not remediations, not G-PRIME
// =====================================================================

/**
 * K-9 declares recovery cancellation as "credential (bounded count), OR GUARDIAN
 * QUORUM" (`KERNEL_ADMISSION.md:37`), and `Vault_vNext_Architecture.md:832`
 * grants the quorum `CANCEL_RECOVERY` under the heading "Direct capabilities
 * (vNext)". The prototype implements only the credential half.
 *
 * These probes supply the missing half so the ARCHITECTURE-CONFORMANT path can
 * be measured rather than argued, and add the naive expiry sweep so the
 * composition warning can be tested rather than asserted. `refund` selects
 * whether clearing a request also destroys the credential's challenge budget —
 * which it does iff the budget lives INSIDE `RecoveryRequest`, as it does here
 * and does NOT in the reference model.
 */
function buildK9(refund: boolean): Deployable {
  const clear = refund ? "delete recovery;" : "recovery.active = false;";
  let s = kernelSource();

  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant QCANCEL_TAG = keccak256("QUORUM_CANCEL_RECOVERY");`,
    "POP_TAG constant (K9)",
  );
  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }

    /// @notice The half of K-9 the prototype does not implement.
    function cancelRecoveryByQuorum(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {
        _requireRecoveryOpen();
        if (!recovery.active) revert NoRecovery();
        bytes32 digest = _digest(
            ACTION_RECOVER, guardianGeneration, QCANCEL_TAG, DOMAIN_GUARDIAN, nonce, deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);
        ${clear}
        emit RecoveryCancelled(recovery.challengesUsed);
    }

    /// @notice The NAIVE remedy for a stranded expired request. Permissionless
    ///         because expiry "requires no principal to act".
    function sweepExpiredRecovery() external {
        if (!recovery.active) revert NoRecovery();
        if (block.timestamp <= recovery.expiresAt) revert TooEarly();
        ${clear}
    }`,
    "executeRecovery tail (K9)",
  );
  return build(`lane-V K9 probe (${refund ? "refunding" : "preserving"})`, s);
}

/**
 * LANE W — THE FROZEN CANDIDATE, BUILT SO THE SEMANTICS CAN BE MEASURED.
 *
 * Implements, together, exactly what Lane W proposes to freeze:
 *
 *   - the challenge budget moves OUT of `RecoveryRequest` into standalone
 *     storage, so a request ending cannot refund it;
 *   - ONE reset site, on the recovery-caused credential install only — never on
 *     `rotateCredential`, which shares `_installCredential` and is the credential's
 *     own authority (`resetOnRecovery` selects this, so the never-reset extreme
 *     can be measured too);
 *   - K-9's missing half: a quorum-authorised cancellation, distinct from the
 *     credential's bounded challenge at the authorisation and event layer;
 *   - EFFECTIVE liveness: an expired request has zero execution authority, zero
 *     cancellation-target authority and zero blocking effect, with no sweeper.
 *     Boundary taken as the kernel's own: live while `now <= expiresAt`;
 *   - a live request may not be overwritten; an expired one may be replaced.
 */
function buildLaneW(resetOnRecovery: boolean, halfOpen = false): Deployable {
  let s = kernelSource();

  // LANE W1: the boundary is a parameter so the two readings can be measured
  // against each other. `halfOpen` selects the cross-artifact reconciliation —
  // live on [executableAt, expiresAt), matching the model's uniform `>=` expiry
  // rule (vaultVNextModel.ts:696, :1031, :1040, :1358) and the kernel's OWN
  // containment rule (`:691`, `>= containedUntil`). It also has to move
  // executeRecovery's guard, or execution would accept at an instant
  // effectiveLive() calls dead.
  if (halfOpen) {
    s = replaceOnce(
      s,
      `        if (block.timestamp > r.expiresAt) revert Expired();`,
      `        if (block.timestamp >= r.expiresAt) revert Expired();`,
      "executeRecovery half-open expiry (W1)",
    );
  }

  s = replaceOnce(
    s,
    `    uint64 public credentialGeneration;`,
    `    uint64 public credentialGeneration;
    /// @notice The challenge epoch. Deliberately NOT inside RecoveryRequest.
    uint32 public recoveryChallengesUsed;`,
    "standalone epoch storage (W)",
  );
  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant QCANCEL_TAG = keccak256("QUORUM_CANCEL_RECOVERY");`,
    "QCANCEL_TAG (W)",
  );

  // Effective liveness, expressed once and used by every consumer.
  s = replaceOnce(
    s,
    `    function _requireRecoveryOpen() internal view {`,
    `    /// @notice I-RECOVERY-EFFECTIVE-LIVENESS. Expiry needs no principal.
    function effectiveLiveRecovery() public view returns (bool) {
        return recovery.active && block.timestamp ${halfOpen ? "<" : "<="} recovery.expiresAt;
    }

    function _requireRecoveryOpen() internal view {`,
    "effectiveLiveRecovery (W)",
  );

  // The credential's bounded challenge now reads and writes the epoch.
  s = replaceWithinFunction(
    s,
    "cancelRecovery",
    `        if (!recovery.active) revert NoRecovery();
        if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();`,
    `        if (!effectiveLiveRecovery()) revert NoRecovery();
        if (recoveryChallengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();`,
  );
  s = replaceWithinFunction(
    s,
    "cancelRecovery",
    `        unchecked {
            recovery.challengesUsed += 1;
        }
        recovery.active = false;
        emit RecoveryCancelled(recovery.challengesUsed);`,
    `        unchecked {
            recoveryChallengesUsed += 1;
        }
        recovery.active = false;
        emit RecoveryCancelled(recoveryChallengesUsed);`,
  );

  // A live request may not be replaced; an EXPIRED one may.
  s = replaceOnce(
    s,
    `        _requireRecoveryOpen();
        if (proposedSigner == address(0) || proposedVerifier == address(0)) revert ZeroAddress();`,
    `        _requireRecoveryOpen();
        if (effectiveLiveRecovery()) revert BadState();
        if (proposedSigner == address(0) || proposedVerifier == address(0)) revert ZeroAddress();`,
    "no live overwrite (W)",
  );
  // The request no longer carries the epoch.
  s = replaceOnce(
    s,
    `            challengesUsed: recovery.challengesUsed,`,
    `            challengesUsed: 0,`,
    "request drops the epoch (W)",
  );

  // Migration observes EFFECTIVE liveness, not the stale flag.
  s = replaceOnce(
    s,
    `        if (recovery.active) revert NoRecovery();`,
    `        if (effectiveLiveRecovery()) revert NoRecovery();`,
    "migration reads effective liveness (W)",
  );

  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
${resetOnRecovery ? "        recoveryChallengesUsed = 0;\n" : ""}    }

    /// @notice K-9's guardian half. A DISTINCT authority from the credential's
    ///         bounded challenge: it neither consumes nor refunds the epoch.
    function cancelRecoveryByQuorum(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {
        _requireRecoveryOpen();
        if (!effectiveLiveRecovery()) revert NoRecovery();
        bytes32 digest = _digest(
            ACTION_RECOVER, guardianGeneration, QCANCEL_TAG, DOMAIN_GUARDIAN, nonce, deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);
        recovery.active = false;
        emit RecoveryCancelledByQuorum(recoveryChallengesUsed);
    }`,
    "executeRecovery tail (W)",
  );
  s = replaceOnce(
    s,
    `    event RecoveryCancelled(uint32 challengesUsed);`,
    `    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryCancelledByQuorum(uint32 challengesUsed);`,
    "quorum cancel event (W)",
  );

  return build(`lane-W frozen candidate (${resetOnRecovery ? "reset-on-recovery" : "never-reset"})`, s);
}

/** The frozen candidate: epoch resets only on a recovery-caused install. */
export const buildLaneWResetting = (): Deployable => buildLaneW(true);

/** The opposite extreme, for B2: the epoch never resets at all. */
export const buildLaneWNeverReset = (): Deployable => buildLaneW(false);

/** LANE W1: the frozen candidate with the RECONCILED half-open expiry, live on [executableAt, expiresAt). */
export const buildLaneWHalfOpen = (): Deployable => buildLaneW(true, true);

/**
 * LANE W1.2 — SEMANTICALLY INDEPENDENT, PHYSICALLY CO-LOCATED.
 *
 * The challenge to W/W1's assumption that epoch independence requires moving
 * `challengesUsed` OUT of `RecoveryRequest`. This candidate leaves the struct,
 * the storage layout and the autogenerated `recovery()` getter byte-for-byte as
 * they are, and instead defines the field as epoch-scoped state whose lifetime
 * deliberately differs from the request's `active` authority:
 *
 *   credential challenge      challengesUsed++, active = false     (unchanged)
 *   guardian-quorum cancel    active = false, challengesUsed kept  (NEW)
 *   wall-clock expiry         effectiveLive == false, NO delete    (NEW semantics)
 *   fresh initiation          carries recovery.challengesUsed      (unchanged — :1177)
 *   ordinary rotation         untouched                            (unchanged)
 *   successful recovery       delete recovery => resets to zero    (unchanged — :1240)
 *
 * The whole-request `delete` on successful execution IS the frozen reset
 * boundary, so co-location turns the existing side effect into the intended
 * semantics. Nothing here adds a slot or moves a field.
 */
export function buildLaneWColocated(getterPublic = true): Deployable {
  let s = kernelSource();

  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant QCANCEL_TAG = keccak256("QUORUM_CANCEL_RECOVERY");`,
    "QCANCEL_TAG (W1.2)",
  );
  s = replaceOnce(
    s,
    `    function _requireRecoveryOpen() internal view {`,
    `    /// @notice I-RECOVERY-EFFECTIVE-LIVENESS, half-open: live on [executableAt, expiresAt).
    function effectiveLiveRecovery() ${getterPublic ? "public" : "internal"} view returns (bool) {
        return recovery.active && block.timestamp < recovery.expiresAt;
    }

    function _requireRecoveryOpen() internal view {`,
    "effectiveLiveRecovery (W1.2)",
  );
  s = replaceOnce(
    s,
    `        if (block.timestamp > r.expiresAt) revert Expired();`,
    `        if (block.timestamp >= r.expiresAt) revert Expired();`,
    "executeRecovery half-open (W1.2)",
  );
  // The credential's challenge: same increment target, same clear — only the
  // liveness test changes, so an expired request is no longer a target.
  s = replaceWithinFunction(
    s,
    "cancelRecovery",
    `        if (!recovery.active) revert NoRecovery();`,
    `        if (!effectiveLiveRecovery()) revert NoRecovery();`,
  );
  // A live request may not be replaced; an expired one may. The carry-forward
  // line `challengesUsed: recovery.challengesUsed` is deliberately LEFT ALONE.
  s = replaceOnce(
    s,
    `        _requireRecoveryOpen();
        if (proposedSigner == address(0) || proposedVerifier == address(0)) revert ZeroAddress();`,
    `        _requireRecoveryOpen();
        if (effectiveLiveRecovery()) revert BadState();
        if (proposedSigner == address(0) || proposedVerifier == address(0)) revert ZeroAddress();`,
    "no live overwrite (W1.2)",
  );
  s = replaceOnce(
    s,
    `        if (recovery.active) revert NoRecovery();`,
    `        if (effectiveLiveRecovery()) revert NoRecovery();`,
    "migration reads effective liveness (W1.2)",
  );
  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }

    /// @notice K-9's guardian half. Clears REQUEST authority only; the epoch
    ///         field in the same struct is deliberately left standing.
    function cancelRecoveryByQuorum(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {
        _requireRecoveryOpen();
        if (!effectiveLiveRecovery()) revert NoRecovery();
        bytes32 digest = _digest(
            ACTION_RECOVER, guardianGeneration, QCANCEL_TAG, DOMAIN_GUARDIAN, nonce, deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);
        recovery.active = false;
        emit RecoveryCancelledByQuorum(recovery.challengesUsed);
    }`,
    "executeRecovery tail (W1.2)",
  );
  s = replaceOnce(
    s,
    `    event RecoveryCancelled(uint32 challengesUsed);`,
    `    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryCancelledByQuorum(uint32 challengesUsed);`,
    "quorum cancel event (W1.2)",
  );

  return build(`lane-W1.2 co-located epoch (${getterPublic ? "E1 public view" : "E0 internal helper"})`, s);
}

/** LANE W1R Option E0: the same candidate with the liveness helper INTERNAL — no public selector. */
export const buildLaneWColocatedE0 = (): Deployable => buildLaneWColocated(false);

/**
 * THE EPOCH-KEY FALSIFICATION PROBE.
 *
 * The candidate semantic says the challenge epoch is "scoped to the currently
 * installed credential generation" and "resets only when guardian recovery
 * successfully installs a new credential generation". Those two clauses are
 * consistent only if recovery is the SOLE way to bump the generation. It is not:
 * `_installCredential` (`:952`) has two callers — `rotateCredential` (`:800`)
 * and `executeRecovery` (`:1242`) — and rotation is the CREDENTIAL's own path.
 *
 * This probe implements the candidate LITERALLY, so the consequence can be
 * measured instead of argued.
 */
export function buildEpochKeyedOnGeneration(): Deployable {
  let s = kernelSource();
  s = replaceOnce(
    s,
    `    uint64 public credentialGeneration;`,
    `    uint64 public credentialGeneration;
    uint64 public challengeEpochGeneration;`,
    "epoch key storage",
  );
  s = replaceWithinFunction(
    s,
    "cancelRecovery",
    `        if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();`,
    `        // "scoped to the currently installed credential generation"
        if (challengeEpochGeneration != credentialGeneration) {
            recovery.challengesUsed = 0;
            challengeEpochGeneration = credentialGeneration;
        }
        if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();`,
  );
  return build("lane-V epoch keyed on credentialGeneration", s);
}

/** Clearing a request DESTROYS the challenge budget stored inside it. */
export const buildK9Refunding = (): Deployable => buildK9(true);

/** Clearing a request leaves the budget standing, as `cancelRecovery` already does. */
export const buildK9Preserving = (): Deployable => buildK9(false);

// =====================================================================
// CANDIDATE U5 — THE TRILEMMA REFUTATION ATTEMPT
// =====================================================================

/**
 * U5 exists to REFUTE `SD4_TEMPORAL_TRILEMMA`, not to pass a test.
 *
 * The trilemma says a ratification design honouring (1) floor immutability,
 * (2) full notice on the final payload, (3) fixed expiry, (4) no challenge
 * refund and (5) no new principal must fail late SD-4, shorten notice, or move
 * a timer. The obvious escape is to make the amendment CHOOSE FROM SOMETHING
 * ALREADY PUBLISHED: if the quorum names a fallback verifier at
 * `initiateRecovery`, that verifier has been public for the whole delay by the
 * time it is selected, so notice is satisfied with NO timer moving at all.
 *
 * If that works, the trilemma is false. It is built here so the question is
 * settled by execution rather than by argument.
 */
export function buildCandidateU5(): Deployable {
  let s = kernelSource();

  s = replaceOnce(
    s,
    `        uint64 boundGuardianGeneration;`,
    `        uint64 boundGuardianGeneration;
        address fallbackVerifier;`,
    "RecoveryRequest field (U5)",
  );
  s = replaceOnce(
    s,
    `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,`,
    `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        address fallbackVerifier,`,
    "initiateRecovery signature (U5)",
  );
  s = replaceOnce(
    s,
    `            keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),`,
    `            keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier, fallbackVerifier)),`,
    "initiateRecovery digest (U5)",
  );
  s = replaceOnce(
    s,
    `            boundGuardianGeneration: guardianGeneration,`,
    `            boundGuardianGeneration: guardianGeneration,
            fallbackVerifier: fallbackVerifier,`,
    "RecoveryRequest construction (U5)",
  );

  // The amendment is a SELECTION, not a choice: no new value enters the system.
  s = replaceOnce(
    s,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }`,
    `        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }

    /**
     * @notice Switch the live request to the fallback the quorum PUBLISHED at
     *         initiation. Takes no value as a parameter, so nothing unobserved
     *         can enter, and writes no timer.
     */
    function selectFallbackVerifier(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {
        _requireRecoveryOpen();
        RecoveryRequest memory r = recovery;
        if (!r.active) revert NoRecovery();
        if (block.timestamp > r.expiresAt) revert Expired();
        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();
        if (r.fallbackVerifier == address(0)) revert ZeroAddress();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            guardianGeneration,
            keccak256(abi.encode(RATIFY_TAG, r.fallbackVerifier, r.proposedSigner, r.executableAt)),
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        recovery.proposedVerifier = r.fallbackVerifier;
        emit RecoveryRatified(r.proposedSigner, r.proposedPqKeyHash, r.executableAt);
    }`,
    "executeRecovery tail (U5)",
  );
  s = replaceOnce(
    s,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");`,
    `    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant RATIFY_TAG = keccak256("RATIFY_RECOVERY_COMMITMENT");`,
    "POP_TAG constant (U5)",
  );
  s = replaceOnce(
    s,
    `    event RecoveryCancelled(uint32 challengesUsed);`,
    `    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryRatified(address indexed proposedSigner, bytes32 pqKeyHash, uint64 executableAt);`,
    "RecoveryCancelled event (U5)",
  );

  return build("candidate U5 (pre-committed fallback)", s);
}

// =====================================================================
// CANDIDATE H — the declaring edge as a METERED cancellation
// =====================================================================

/**
 * #188 rejects metering with: "a counter has teeth only through its REFUSAL, and
 * refusing a ONE-SHOT transition is permanent deprivation". That argument is
 * about H3 alone. The counter's teeth here come from the FUTURE refusal of
 * `cancelRecovery` once the budget is spent, not from refusing the declaring
 * edge — so H1, H2 and H4 never refuse anything, and the argument does not
 * reach them. Each boundary semantics is built separately and attacked
 * separately, because the interesting question is entirely at
 * `recovery.active && challengesUsed == CHALLENGE_LIMIT`.
 *
 * `securityFloor.requirePq` is read BEFORE `securityFloor = floor` executes, so
 * the guard below sees the OUTGOING floor and fires only on the declaring edge.
 */
const H_ANCHOR = `        _consume(DOMAIN_CREDENTIAL, nonce, deadline);
        pqVerifier = verifier;
        securityFloor = floor;`;

function withHClause(body: string, label: string): Deployable {
  const s = replaceOnce(
    kernelSource(),
    H_ANCHOR,
    `${body}
${H_ANCHOR}`,
    `setVerifier consume anchor (${label})`,
  );
  return build(label, s);
}

/** H1 — always allow; always meter, even past the cap. */
export const buildCandidateH1 = (): Deployable =>
  withHClause(
    `        if (!securityFloor.requirePq && floor.requirePq && recovery.active) {
            recovery.active = false;
            unchecked {
                recovery.challengesUsed += 1;
            }
            emit RecoveryCancelled(recovery.challengesUsed);
        }`,
    "candidate H1",
  );

/** H2 — always allow; never meter. State coherence only. */
export const buildCandidateH2 = (): Deployable =>
  withHClause(
    `        if (!securityFloor.requirePq && floor.requirePq && recovery.active) {
            recovery.active = false;
            emit RecoveryCancelled(recovery.challengesUsed);
        }`,
    "candidate H2",
  );

/** H3 — refuse the declaration once the credential has spent its whole budget. */
export const buildCandidateH3 = (): Deployable =>
  withHClause(
    `        if (!securityFloor.requirePq && floor.requirePq && recovery.active) {
            if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();
            recovery.active = false;
            unchecked {
                recovery.challengesUsed += 1;
            }
            emit RecoveryCancelled(recovery.challengesUsed);
        }`,
    "candidate H3",
  );

/** H4 — always allow; meter, but SATURATE at the cap rather than exceed it. */
export const buildCandidateH4 = (): Deployable =>
  withHClause(
    `        if (!securityFloor.requirePq && floor.requirePq && recovery.active) {
            recovery.active = false;
            if (recovery.challengesUsed < CHALLENGE_LIMIT) {
                unchecked {
                    recovery.challengesUsed += 1;
                }
            }
            emit RecoveryCancelled(recovery.challengesUsed);
        }`,
    "candidate H4",
  );

/**
 * H-PRECISE — the fifth family, and the one #188's dichotomy has no name for.
 *
 * H1..H4 all OVER-APPROXIMATE: they destroy a pending recovery on every
 * declaring edge, including edges that would not have harmed it, because the
 * kernel cannot know the length of a key it only holds a hash of. That
 * over-approximation is itself a liveness regression against the unmodified
 * kernel, which lets a shape-compatible recovery survive.
 *
 * H-PRECISE removes it by having the quorum DECLARE the shape it is proposing
 * for — and this is NOT design A, which is the whole point. The two lengths are
 * carried in the request and bound into the guardian digest exactly as in design
 * A, but they are used for a COMPLETELY DIFFERENT PURPOSE:
 *
 *   design A  — the request's lengths REPLACE the live floor as the
 *               authentication predicate in `_requireIncomingPossession`.
 *               The installed commitment can then disagree with the frozen
 *               floor, and `_authorise` becomes unsatisfiable. That is the brick.
 *
 *   H-PRECISE — the request's lengths are read by NOTHING on the execution path.
 *               `_requireIncomingPossession` still measures the LIVE floor, so a
 *               credential that installs is always one the vault can authorise.
 *               They are read ONLY on the declaring edge, as a COMPATIBILITY
 *               PREDICATE deciding whether this declaration destroys the pending
 *               request — and therefore whether it must be METERED.
 *
 * The discriminator is executable: under design A the recovery SUCCEEDS into a
 * dead credential; under H-PRECISE a compatible declaration leaves the request
 * ALIVE and executable, and an incompatible one costs the credential a challenge.
 */
function buildHPrecise(strict: boolean): Deployable {
  let s = kernelSource();

  s = replaceOnce(
    s,
    `        uint32 challengesUsed;
        bool active;
    }`,
    `        uint32 challengesUsed;
        bool active;
        /// @dev COMPATIBILITY DECLARATION, read only by the declaring edge.
        ///      Never an authentication predicate — see H-PRECISE.
        uint32 proposedPqKeyLength;
        uint32 proposedPqSigLength;
    }`,
    "RecoveryRequest struct (H-PRECISE)",
  );

  s = replaceOnce(
    s,
    INITIATE_SIG,
    `    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline,
        uint32 proposedPqKeyLength,
        uint32 proposedPqSigLength
    ) external {`,
    "initiateRecovery signature (H-PRECISE)",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    "keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),",
    "keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier, proposedPqKeyLength, proposedPqSigLength)),",
  );
  s = replaceWithinFunction(
    s,
    "initiateRecovery",
    `            challengesUsed: recovery.challengesUsed,
            active: true`,
    `            challengesUsed: recovery.challengesUsed,
            active: true,
            proposedPqKeyLength: proposedPqKeyLength,
            proposedPqSigLength: proposedPqSigLength`,
  );

  s = replaceOnce(
    s,
    H_ANCHOR,
    `        // THE DECLARING EDGE, METERED ONLY WHEN IT ACTUALLY DESTROYS.
        // The request's declared shape is compared against the shape being
        // armed. Equal shapes leave the request untouched — the unmodified
        // kernel's behaviour, preserved. Unequal shapes destroy it, and that
        // destruction now costs the SAME budget cancelRecovery costs.
        if (!securityFloor.requirePq && floor.requirePq && recovery.active) {
            if (
                recovery.proposedPqKeyLength != floor.pqPublicKeyLength ||
                recovery.proposedPqSigLength != floor.pqSignatureLength
            ) {
${strict ? "                if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();\n" : ""}                recovery.active = false;
                unchecked {
                    recovery.challengesUsed += 1;
                }
                emit RecoveryCancelled(recovery.challengesUsed);
            }
        }
${H_ANCHOR}`,
    `setVerifier consume anchor (H-PRECISE${strict ? "-STRICT" : ""})`,
  );

  return build(`candidate H-PRECISE${strict ? "-STRICT" : ""}`, s);
}

/**
 * H-PRECISE, LENIENT BOUNDARY — the primary proposal. It NEVER refuses the
 * declaring edge, so #188's objection ("refusing a one-shot transition is
 * permanent deprivation") does not reach it at all, and no principal can ever be
 * permanently deprived of arming PQ. The counter may therefore exceed
 * CHALLENGE_LIMIT by AT MOST ONE, because the declaring edge is one-shot and
 * monotone; the worst case is exactly today's three denials, and the TYPICAL
 * case falls from three to two.
 */
export const buildCandidateHPrecise = (): Deployable => buildHPrecise(false);

/**
 * H-PRECISE, STRICT BOUNDARY — refuses the declaring edge once the credential
 * has spent its whole budget. Built ONLY so the refusal's cost can be executed
 * rather than argued: a quorum that keeps re-initiating holds recovery.active
 * true renewably, which converts the refusal into an indefinite block on arming
 * PQ. That is the failure #188 predicts, and it is reproduced here.
 */
export const buildCandidateHPreciseStrict = (): Deployable => buildHPrecise(true);
