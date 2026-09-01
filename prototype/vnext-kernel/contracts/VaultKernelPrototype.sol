// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./interfaces/IKernelPlanes.sol";

/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 * DO NOT MERGE INTO MAIN. This contract has no audit, no fuzzing campaign and
 * no formal verification, and it is not a production specification.
 *
 * vNext Assured Minimal Trust Kernel, prototype v0.
 *
 * WRITTEN FROM ZERO, not refactored from `contracts/WalletWallVault.sol`. Every
 * member below is admitted by a row of KERNEL_ADMISSION.md, which derives its
 * rows from PR #179 at 71aee6f3. The monolith was consulted for signature
 * encoding and compiler behaviour; it is NOT the structural template, and
 * nothing is here because the monolith has it.
 *
 * ONE CLONE IS ONE VAULT. There is deliberately no `mapping(owner => Vault)`
 * anywhere in this file. Vault identity is the CLONE ADDRESS (section 3.2 R1);
 * identity is therefore not a principal, which is what dissolves the guardian
 * rotation problem the monolith could not solve.
 *
 * CLONE-SAFE BY CONSTRUCTION:
 *   - no `immutable` state at all, so the implementation's runtime code is
 *     address-independent and one runtime hash identifies the generation
 *     (`I-PURE-CONSTRUCTOR`, section 15.1);
 *   - the EIP-712 domain is rebuilt per call from `block.chainid` and
 *     `address(this)`, so a signature for vault X is structurally invalid at
 *     vault Y (section 3.2 R4);
 *   - the constructor sets the replay guard, so the IMPLEMENTATION itself can
 *     never be initialised and can never hold custody.
 */
contract VaultKernelPrototype {
    using ECDSA for bytes32;

    // =====================================================================
    // K-10 — safe-state machine
    // =====================================================================

    enum SafeState {
        NORMAL,
        CONTAINED,
        RECOVERY_ONLY,
        MIGRATION_ONLY,
        RETIRED
    }

    // =====================================================================
    // K-3 — nonce domains, adjudicated in KERNEL_ADMISSION.md section 3
    // =====================================================================

    uint8 internal constant DOMAIN_SPEND = 0;
    uint8 internal constant DOMAIN_CREDENTIAL = 1;
    uint8 internal constant DOMAIN_GUARDIAN = 2;
    uint8 internal constant DOMAIN_MIGRATION = 3;

    // =====================================================================
    // Storage. ONE clone == ONE vault: every slot below describes THIS vault.
    // =====================================================================

    /// @dev Initialization replay guard (K-2/D3). Packed with the state byte.
    bool private _initialized;
    /// @dev K-10.
    SafeState public safeState;
    /// @dev K-4. The ECDSA credential — the kernel-evaluated possession root (K-5).
    address public ecdsaSigner;
    /// @dev K-11. Wall-clock expiry of CONTAINED. Never suspends, never extends.
    uint64 public containedUntil;
    /// @dev K-11. Rolling containment budget window origin (wall clock only).
    uint64 public containmentWindowStart;
    /// @dev K-11. Containment seconds consumed inside the current window.
    uint64 public containmentUsedInWindow;

    /// @dev K-4. Commitment to the PQ public key. The bytes live in calldata.
    bytes32 public pqPublicKeyHash;

    /**
     * @dev K-15 — the KERNEL-RECORDED cryptographic floor (architecture 4.3
     *      component 2, and 12). It is never read from the verifier, which is
     *      the whole point: a plane cannot report its own strength.
     *
     *      `requirePq` decides whether the PQ conjunct is MANDATORY. It is
     *      deliberately NOT the caller's choice — see `_authorise`.
     *      `pqParamLevel` is a WITHIN-FAMILY level and may only increase
     *      (I-NO-SILENT-DOWNGRADE). The two lengths are the structural
     *      rejection of component 1: pure integer comparisons the kernel
     *      performs itself, needing no trust in any verifier.
     */
    struct SecurityFloor {
        bool requirePq;
        uint16 pqParamLevel;
        uint32 pqPublicKeyLength;
        uint32 pqSignatureLength;
    }

    SecurityFloor public securityFloor;
    /// @dev K-4. Advances on every credential change; binds every signature.
    uint64 public credentialGeneration;
    /// @dev K-14. Verifier governance is KERNEL; the implementation is a PLANE.
    address public pqVerifier;
    /// @dev PLANE. Subtractive only. address(0) falls back to the kernel FLOOR.
    address public policyEngine;

    /// @dev K-6. G-B: commitment + threshold + generation. NOT the roster bytes.
    bytes32 public guardianCommitment;
    uint64 public guardianThreshold;
    uint64 public guardianGeneration;

    /// @dev K-3. One counter per authority domain.
    mapping(uint8 => uint256) public nonces;

    // ---- K-7 recovery request state -------------------------------------

    struct RecoveryRequest {
        address proposedSigner;
        bytes32 proposedPqKeyHash;
        /// @dev The replacement verifier this recovery installs (finding A).
        address proposedVerifier;
        uint64 executableAt;
        uint64 expiresAt;
        uint64 boundGuardianGeneration;
        uint32 challengesUsed;
        bool active;
    }

    RecoveryRequest public recovery;

    // ---- K-12 migration binding -----------------------------------------

    struct MigrationBinding {
        address destinationVault;
        bytes32 destinationVaultCodeHash;
        uint64 destinationGeneration;
        uint64 boundAt;
        bool bound;
    }

    MigrationBinding public migration;

    /**
     * @dev The guardian roster and its attestations, grouped so they cost ONE
     *      stack slot instead of four. Not cosmetic: without this the kernel
     *      hits "stack too deep" in `bindMigration`, and the alternative —
     *      enabling `viaIR` — would make every byte figure incomparable to the
     *      monolith's, which is measured without it.
     */
    struct QuorumProof {
        address[] members;
        bool[] isContract;
        uint256[] attestingIndices;
        bytes[] attestations;
    }

    /// @dev The migration destination, bound as a unit.
    struct Destination {
        address vault;
        bytes32 codeHash;
        uint64 generation;
    }

    /**
     * @dev An incoming credential and its POSSESSION PROOFS (finding D). The
     *      preimage `newPqKey` travels with the change because the kernel must
     *      verify possession against the INCOMING key, not the outgoing one.
     */
    struct CredentialChange {
        address newSigner;
        bytes32 newPqKeyHash;
        bytes newPqKey;
        bytes newEcdsaPop;
        bytes newPqPop;
    }

    /**
     * @dev The complete genesis authority of a vault. Every field here defines
     *      WHO controls the vault, so every field is bound into the CREATE2 salt
     *      (finding C) and validated by the kernel (genesis validation).
     */
    struct GenesisConfig {
        address signer;
        bytes32 pqKeyHash;
        address verifier;
        uint64 threshold;
        address[] guardians;
        bool[] guardianIsContract;
        SecurityFloor floor;
    }

    // =====================================================================
    // Constants. Illustrative values for a measurement prototype.
    // =====================================================================

    uint64 public constant RECOVERY_DELAY = 7 days;
    uint64 public constant RECOVERY_EXPIRY = 14 days;
    uint64 public constant BIND_DELAY = 7 days; // >= RECOVERY_DELAY (section 13.2)
    uint64 public constant CONTAINMENT_MAX = 3 days;
    uint64 public constant CONTAINMENT_WINDOW = 30 days;
    uint64 public constant CONTAINMENT_BUDGET = 6 days; // B < W
    uint32 public constant CHALLENGE_LIMIT = 2;

    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    uint256 private constant GUARDIAN_CALL_GAS = 30_000;

    // =====================================================================
    // Errors
    // =====================================================================

    error AlreadyInitialized();
    error NotInitialized();
    error ZeroAddress();
    error BadState();
    error BadSignature();
    error BadNonce();
    error Expired();
    error PolicyDenied();
    error VerifierDenied();
    error BadRoster();
    error QuorumNotMet();
    error NotOrdered();
    error NoRecovery();
    error TooEarly();
    error ChallengeExhausted();
    error NotBound();
    error AlreadyBound();
    error DestinationMismatch();
    error TransferFailed();
    error ContainmentBudget();
    error Downgrade();

    // =====================================================================
    // Events — K-1..K-14 observability. OBSERVATORY reads these; it holds
    // no capability whatsoever (architecture section 10).
    // =====================================================================

    event Initialized(address indexed signer, bytes32 pqKeyHash, bytes32 guardianCommitment, uint64 threshold);
    event Executed(address indexed recipient, uint256 amount, uint256 nonce);
    event CredentialRotated(address indexed newSigner, uint64 credentialGeneration);
    event VerifierChanged(address indexed verifier);
    event SecurityFloorChanged(bool requirePq, uint16 pqParamLevel);
    event PolicyChanged(address indexed policy);
    /// @dev I-CONSTITUENCY-RECONSTRUCTIBLE: the FULL preimage, every write.
    event GuardianCommitmentSet(bytes32 indexed commitment, uint64 generation, uint64 threshold, bytes preimage);
    event RecoveryInitiated(address indexed proposedSigner, uint64 executableAt, uint64 guardianGeneration);
    event RecoveryCancelled(uint32 challengesUsed);
    event RecoveryExecuted(address indexed newSigner, uint64 credentialGeneration);
    event SafeStateChanged(SafeState indexed previous, SafeState indexed next);
    event MigrationBound(address indexed destinationVault, bytes32 codeHash, uint64 destinationGeneration);
    event Egressed(address indexed asset, address indexed destination, uint256 amount);
    event Retired();

    // =====================================================================
    // Construction and initialization (K-2, dissent D3)
    // =====================================================================

    /// @dev The implementation permanently initialises ITSELF, so it can never
    ///      be initialised by a caller and can never become a usable vault.
    constructor() {
        _initialized = true;
    }

    /**
     * @notice One-shot initialization. The factory calls this ATOMICALLY in the
     *         same transaction as the clone deployment, so an uninitialised
     *         clone never exists between transactions and cannot be claimed.
     */
    function initialize(GenesisConfig calldata g) external {
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;

        // ---- GENESIS VALIDATION -----------------------------------------
        // The kernel validates its OWN genesis. It does not trust the factory
        // to have done so: the factory is a convenience, never an authority.

        // (3) of section 4.3a: the stored credential must be provably non-zero,
        // or a comparison against an uninitialised clone accidentally succeeds.
        if (g.signer == address(0) || g.verifier == address(0)) revert ZeroAddress();
        // A verifier with no code would STATICCALL into nothing.
        if (g.verifier.code.length == 0) revert ZeroAddress();
        // I-QUORUM-PRINCIPAL-DISTINCTNESS at admission: a vault can never be
        // created with a roster that could not reach an honest quorum.
        _requireCanonicalRoster(g.threshold, g.guardians, g.guardianIsContract);
        _requireSaneFloor(g.floor);
        // A mandatory PQ conjunct with no committed key is unsatisfiable, and
        // would brick spending from birth.
        if (g.floor.requirePq && g.pqKeyHash == bytes32(0)) revert BadSignature();

        securityFloor = g.floor;
        ecdsaSigner = g.signer;
        pqPublicKeyHash = g.pqKeyHash;
        pqVerifier = g.verifier;
        bytes32 commitment = rosterCommitment(g.threshold, g.guardians, g.guardianIsContract);
        guardianCommitment = commitment;
        guardianThreshold = g.threshold;
        guardianGeneration = 1;
        credentialGeneration = 1;
        safeState = SafeState.NORMAL;

        emit Initialized(g.signer, g.pqKeyHash, commitment, g.threshold);
        // I-CONSTITUENCY-RECONSTRUCTIBLE from the very first block.
        emit GuardianCommitmentSet(
            commitment,
            1,
            g.threshold,
            abi.encode(g.threshold, g.guardians, g.guardianIsContract)
        );
    }

    /// @dev A floor that demands a PQ conjunct must declare satisfiable shapes.
    function _requireSaneFloor(SecurityFloor calldata floor) internal pure {
        if (!floor.requirePq) return;
        if (floor.pqPublicKeyLength == 0 || floor.pqSignatureLength == 0) revert BadSignature();
    }

    /**
     * @notice The CREATE2 salt this vault's identity is derived from.
     *
     * @dev `I-COUNTERFACTUAL-IDENTITY-BINDING` — the fix for finding C. The salt
     *      binds the COMPLETE genesis authority, so an actor lacking the
     *      intended configuration cannot instantiate the predicted identity: a
     *      different signer, guardian set, threshold, verifier or floor yields a
     *      DIFFERENT address. A front-runner submitting the IDENTICAL authorised
     *      configuration lands on the same address and produces the same state —
     *      harmless permissionless execution, not a takeover.
     */
    function genesisSalt(bytes32 userSalt, GenesisConfig calldata g) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    userSalt,
                    g.signer,
                    g.pqKeyHash,
                    g.verifier,
                    g.threshold,
                    g.guardians,
                    g.guardianIsContract,
                    g.floor
                )
            );
    }

    /// @notice The per-clone immutable arguments, read out of THIS CLONE'S OWN
    ///         runtime code — never from storage, never from the factory.
    function genesisCommitments() external view returns (bytes memory) {
        return Clones.fetchCloneArgs(address(this));
    }

    // =====================================================================
    // K-1 — custody. Unsolicited value is ACCEPTED, never refused: section
    // 13.0a proves an ingress gate cannot stop it, and I-MIGRATION-NONTRAP
    // clause (a) requires it not to veto anything.
    // =====================================================================

    receive() external payable {}

    // =====================================================================
    // EIP-712 domain, rebuilt per call. No immutables, so the implementation's
    // runtime code is address-independent (I-PURE-CONSTRUCTOR).
    // =====================================================================

    bytes32 private constant TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant HASHED_NAME = keccak256("WalletWallVaultKernel");
    bytes32 private constant HASHED_VERSION = keccak256("0-prototype");

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, HASHED_NAME, HASHED_VERSION, block.chainid, address(this)));
    }

    /**
     * @dev Every signed action binds, per section 179's domain-separation rule:
     *      chainId and vault address (via the domain separator), KERNEL
     *      GENERATION, ACTION TYPE, the exact parameters, the AUTHORITY
     *      GENERATION, a domain-scoped NONCE, and a DEADLINE.
     */
    function _digest(
        bytes32 actionType,
        uint64 authorityGeneration,
        bytes32 params,
        uint8 domain,
        uint256 nonce,
        uint64 deadline
    ) internal view returns (bytes32) {
        return
            MessageHashUtils.toTypedDataHash(
                domainSeparator(),
                keccak256(
                    abi.encode(actionType, kernelGeneration(), authorityGeneration, params, domain, nonce, deadline)
                )
            );
    }

    /// @dev The kernel generation, read from the clone's own immutable args if
    ///      present. Generation 1 when no args were supplied.
    function kernelGeneration() public view returns (uint64) {
        bytes memory args = Clones.fetchCloneArgs(address(this));
        if (args.length < 8) return 1;
        return uint64(bytes8(args));
    }

    bytes32 private constant POP_TAG = keccak256("INCOMING_CREDENTIAL_POSSESSION");
    bytes32 private constant ACTION_SPEND = keccak256("SPEND");
    bytes32 private constant ACTION_ROTATE = keccak256("ROTATE_CREDENTIAL");
    bytes32 private constant ACTION_SET_VERIFIER = keccak256("SET_VERIFIER");
    bytes32 private constant ACTION_SET_POLICY = keccak256("SET_POLICY");
    bytes32 private constant ACTION_SET_GUARDIANS = keccak256("SET_GUARDIANS");
    bytes32 private constant ACTION_RECOVER = keccak256("RECOVER");
    bytes32 private constant ACTION_BIND_MIGRATION = keccak256("BIND_MIGRATION");

    // =====================================================================
    // K-5 — the FLOOR. The kernel evaluates possession ITSELF, using only its
    // own code and the ecrecover precompile. I-NO-SOLE-EXTERNAL-AUTHENTICATOR.
    // =====================================================================

    /**
     * @dev The floor. Returns true only on a kernel-verified possession
     *      witness. `ECDSA.recover` reverts rather than returning address(0),
     *      and rejects malleable `s` — conditions (1) and (2) of section 4.3a.
     *      Condition (3) is met by `initialize` refusing a zero signer.
     */
    function _floorAuthorises(bytes32 digest, bytes calldata ecdsaSig) internal view returns (bool) {
        return digest.recover(ecdsaSig) == ecdsaSigner;
    }

    /**
     * @dev FLOOR **AND** PLANE. The PQ verifier is a conjunctive barrier: an
     *      always-true verifier collapses HYBRID to ECDSA security and never to
     *      unauthenticated authorization, because the floor is evaluated first
     *      and independently. An unavailable verifier yields DENIAL.
     *
     *      WHETHER THE PQ LEG IS REQUIRED IS THE KERNEL'S DECISION, NEVER THE
     *      CALLER'S. An earlier draft of this prototype engaged the PQ leg only
     *      when the caller supplied a non-empty signature — which let anyone
     *      holding the ECDSA key alone downgrade HYBRID to ECDSA-only simply by
     *      passing an empty blob. That is exactly the silent downgrade section
     *      12 forbids, reached through the argument list instead of through a
     *      state transition. It was found by the authority-closure pass, not by
     *      a test, and it is recorded rather than quietly fixed.
     */
    function _authorise(
        bytes32 digest,
        bytes calldata ecdsaSig,
        bytes calldata pqSig,
        bytes calldata pqKey
    ) internal view {
        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();

        SecurityFloor memory floor = securityFloor;
        if (!floor.requirePq) return;

        // FLOOR component 1: structural length rejection. Pure integer
        // comparisons, performed by the kernel, trusting no verifier.
        if (pqKey.length != floor.pqPublicKeyLength || pqSig.length != floor.pqSignatureLength) {
            revert BadSignature();
        }
        if (keccak256(pqKey) != pqPublicKeyHash) revert BadSignature();

        // PLANE: consulted only to impose an ADDITIONAL requirement.
        if (!IKernelPQVerifier(pqVerifier).verify(digest, pqKey, pqSig)) revert VerifierDenied();
    }

    /**
     * @dev `I-NO-SILENT-DOWNGRADE`. A floor transition may only be neutral or
     *      strengthening. Turning `requirePq` off, or lowering the parameter
     *      level, is REFUSED outright rather than gated on a higher authority:
     *      there is no principal in this design entitled to weaken the floor.
     *      Length changes accompany a parameter change and move with it.
     */
    function _requireNoDowngrade(SecurityFloor memory next) internal view {
        SecurityFloor memory current = securityFloor;
        if (current.requirePq && !next.requirePq) revert Downgrade();
        if (next.pqParamLevel < current.pqParamLevel) revert Downgrade();
    }

    /**
     * @dev `I-INCOMING-CREDENTIAL-POSSESSION`. Proves the party proposing a new
     *      credential actually holds it, BEFORE the kernel commits to it.
     *
     *      The digest binds the vault, the chain, the kernel generation and the
     *      exact incoming credential — and DELIBERATELY NOTHING THE OUTGOING
     *      CREDENTIAL CAN MOVE. Binding it to a spend nonce would hand the
     *      compromised credential a repeatable veto over recovery: every spend
     *      would invalidate a guardian's pre-signed possession proof. That is
     *      the lesson PR #178 paid for, and it is preserved here.
     */
    function credentialPossessionDigest(address newSigner, bytes32 newPqKeyHash) public view returns (bytes32) {
        return
            keccak256(abi.encode(POP_TAG, block.chainid, address(this), kernelGeneration(), newSigner, newPqKeyHash));
    }

    /**
     * @dev The recovery variant. Binds the ACTIVE REQUEST — which the outgoing
     *      credential can only cancel (a bounded act already counted), never
     *      silently move.
     */
    function recoveryPossessionDigest() public view returns (bytes32) {
        RecoveryRequest memory r = recovery;
        return
            keccak256(
                abi.encode(
                    POP_TAG,
                    block.chainid,
                    address(this),
                    kernelGeneration(),
                    r.proposedSigner,
                    r.proposedPqKeyHash,
                    r.proposedVerifier,
                    r.boundGuardianGeneration,
                    r.executableAt
                )
            );
    }

    /**
     * @dev Verify possession of BOTH incoming factors against `verifierToUse`.
     *      For a rotation that is the current verifier; for a recovery it is the
     *      INCOMING one, so a vault escaping a dead verifier proves possession
     *      against the replacement rather than against the corpse.
     */
    function _requireIncomingPossession(
        bytes32 popDigest,
        address expectedSigner,
        bytes32 expectedPqKeyHash,
        address verifierToUse,
        CredentialChange calldata c
    ) internal view {
        // Cross-check: the supplied change must be the one the kernel expects.
        // For a rotation this is trivially true; for a recovery it binds the
        // caller-supplied material to the guardian-approved request.
        if (c.newSigner != expectedSigner || c.newPqKeyHash != expectedPqKeyHash) revert BadSignature();
        if (popDigest.recover(c.newEcdsaPop) != expectedSigner) revert BadSignature();

        SecurityFloor memory floor = securityFloor;
        if (!floor.requirePq) return;
        if (c.newPqKey.length != floor.pqPublicKeyLength || c.newPqPop.length != floor.pqSignatureLength) {
            revert BadSignature();
        }
        if (keccak256(c.newPqKey) != expectedPqKeyHash) revert BadSignature();
        if (!IKernelPQVerifier(verifierToUse).verify(popDigest, c.newPqKey, c.newPqPop)) revert BadSignature();
    }

    function _consume(uint8 domain, uint256 nonce, uint64 deadline) internal {
        if (nonces[domain] != nonce) revert BadNonce();
        if (block.timestamp > deadline) revert Expired();
        unchecked {
            nonces[domain] = nonce + 1;
        }
    }

    // =====================================================================
    // K-10 — the action matrix. Every gate is one of these two helpers, so the
    // matrix is auditable in one place rather than scattered across modifiers.
    // =====================================================================

    /**
     * @notice The state the kernel ACTUALLY enforces right now.
     *
     * @dev `safeState` is the STORED enum and goes stale: containment expires on
     *      wall clock with no transaction, so a vault can read CONTAINED while
     *      the kernel is already treating it as NORMAL. An observatory that
     *      published the stored value would be publishing a claim the kernel
     *      does not hold. This derived getter costs no storage write.
     */
    function effectiveSafeState() external view returns (SafeState) {
        return _effectiveState();
    }

    function _effectiveState() internal view returns (SafeState) {
        // Containment self-expires on WALL CLOCK with NO principal acting.
        if (safeState == SafeState.CONTAINED && block.timestamp >= containedUntil) return SafeState.NORMAL;
        return safeState;
    }

    function _requireNormal() internal view {
        if (_effectiveState() != SafeState.NORMAL) revert BadState();
    }

    function _requireRecoveryOpen() internal view {
        SafeState s = _effectiveState();
        if (s == SafeState.MIGRATION_ONLY || s == SafeState.RETIRED) revert BadState();
    }

    // =====================================================================
    // K-2 — asset execution. EXACT TYPED. There is no execute(address,bytes)
    // anywhere in this kernel (architecture section 5, goal G3).
    // =====================================================================

    function execute(
        address payable recipient,
        uint256 amount,
        uint256 nonce,
        uint64 deadline,
        bytes calldata ecdsaSig,
        bytes calldata pqSig,
        bytes calldata pqKey
    ) external {
        _requireNormal();
        if (recipient == address(0)) revert ZeroAddress();

        bytes32 digest = _digest(
            ACTION_SPEND,
            credentialGeneration,
            keccak256(abi.encode(recipient, amount)),
            DOMAIN_SPEND,
            nonce,
            deadline
        );
        _authorise(digest, ecdsaSig, pqSig, pqKey);
        _consume(DOMAIN_SPEND, nonce, deadline);

        // PLANE, SUBTRACTIVE. address(0) falls back to the kernel FLOOR, never
        // to "no restriction" (section 4.3).
        // PLANE, SUBTRACTIVE, and now a NON-VIEW ADMISSION call (finding F). A
        // `view` boundary reaches the plane by STATICCALL, so a plane can never
        // persist consumption and a cumulative rule (daily spend, velocity) is
        // unrepresentable — two individually-valid spends both pass. Admission
        // lets the plane record what it admitted.
        //
        // REENTRANCY: the nonce is consumed BEFORE this call, so a reentrant
        // plane calling back into `execute` needs a signature for nonce+1 that
        // only the credential holder can produce. LIVENESS: a reverting plane
        // denies, which is the already-accepted denial cut of 1.
        address plane = policyEngine;
        if (plane != address(0)) {
            if (!IKernelPolicy(plane).admit(address(this), recipient, amount)) revert PolicyDenied();
        }

        emit Executed(recipient, amount, nonce);
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // =====================================================================
    // K-4 — credential rotation. K-14 — verifier governance, gated on the
    // ECDSA conjunct ALONE so the escape is never authenticated by the
    // component being escaped (I-NO-CIRCULAR-ESCAPE).
    // =====================================================================

    /**
     * @notice Rotate the spending credential.
     *
     * @dev **HYBRID-AUTHORISED, and that is the fix for finding A1.** An earlier
     *      draft gated this on `_floorAuthorises` — the ECDSA conjunct ALONE —
     *      so a single compromised root could rewrite BOTH factors and then
     *      spend. The published `min(2, k)` claim was false: the real cut was 1.
     *      Rotation now requires the full outgoing authorization.
     *
     *      It additionally requires POSSESSION of both INCOMING factors
     *      (finding D), so an approved-but-unheld credential can never be
     *      installed and strand the vault.
     */
    function rotateCredential(
        CredentialChange calldata c,
        uint256 nonce,
        uint64 deadline,
        bytes calldata ecdsaSig,
        bytes calldata pqSig,
        bytes calldata pqKey
    ) external {
        _requireNormal();
        if (c.newSigner == address(0)) revert ZeroAddress();
        bytes32 digest = _digest(
            ACTION_ROTATE,
            credentialGeneration,
            keccak256(abi.encode(c.newSigner, c.newPqKeyHash)),
            DOMAIN_CREDENTIAL,
            nonce,
            deadline
        );
        _authorise(digest, ecdsaSig, pqSig, pqKey);
        _requireIncomingPossession(
            credentialPossessionDigest(c.newSigner, c.newPqKeyHash),
            c.newSigner,
            c.newPqKeyHash,
            pqVerifier,
            c
        );
        _consume(DOMAIN_CREDENTIAL, nonce, deadline);
        _installCredential(c.newSigner, c.newPqKeyHash);
    }

    /**
     * @notice Replace the verifier and, in the same act, declare the floor the
     *         new verifier is trusted for. The two are inseparable: a verifier
     *         swap that left the recorded strength behind would be a downgrade
     *         with no transition to refuse.
     *
     * @dev **HYBRID-AUTHORISED, and that is the fix for finding A2.** An earlier
     *      draft gated this on the ECDSA conjunct alone, reasoning that
     *      `I-NO-CIRCULAR-ESCAPE` demanded an escape that does not require the
     *      verifier to answer. That reasoning was right about the requirement
     *      and wrong about the remedy: a unilateral ECDSA verifier swap lets one
     *      root install an always-true verifier — keeping the recorded floor
     *      untouched, so no downgrade rule fires — and then spend using the
     *      PUBLIC PQ public key with a forged signature. Cut 1, again.
     *
     *      **The escape from a dead verifier is GUARDIAN RECOVERY, which carries
     *      a replacement verifier (see `initiateRecovery`).** That satisfies
     *      `I-NO-CIRCULAR-ESCAPE` without handing the surviving factor
     *      unilateral authority over the other factor's oracle.
     */
    function setVerifier(
        address verifier,
        SecurityFloor calldata floor,
        uint256 nonce,
        uint64 deadline,
        bytes calldata ecdsaSig,
        bytes calldata pqSig,
        bytes calldata pqKey
    ) external {
        _requireNormal();
        if (verifier == address(0)) revert ZeroAddress();
        if (verifier.code.length == 0) revert ZeroAddress();
        bytes32 digest = _digest(
            ACTION_SET_VERIFIER,
            credentialGeneration,
            keccak256(abi.encode(verifier, floor)),
            DOMAIN_CREDENTIAL,
            nonce,
            deadline
        );
        _authorise(digest, ecdsaSig, pqSig, pqKey);
        _requireNoDowngrade(floor);
        _requireSaneFloor(floor);
        _consume(DOMAIN_CREDENTIAL, nonce, deadline);
        pqVerifier = verifier;
        securityFloor = floor;
        emit VerifierChanged(verifier);
        emit SecurityFloorChanged(floor.requirePq, floor.pqParamLevel);
    }

    /// @dev HYBRID-authorised for the same reason as the other two: a plane
    ///      pointer is governance, and governance is not a one-factor act.
    function setPolicy(
        address policy,
        uint256 nonce,
        uint64 deadline,
        bytes calldata ecdsaSig,
        bytes calldata pqSig,
        bytes calldata pqKey
    ) external {
        _requireNormal();
        bytes32 digest = _digest(
            ACTION_SET_POLICY,
            credentialGeneration,
            keccak256(abi.encode(policy)),
            DOMAIN_CREDENTIAL,
            nonce,
            deadline
        );
        _authorise(digest, ecdsaSig, pqSig, pqKey);
        _consume(DOMAIN_CREDENTIAL, nonce, deadline);
        policyEngine = policy;
        emit PolicyChanged(policy);
    }

    function _installCredential(address newSigner, bytes32 newPqKeyHash) internal {
        ecdsaSigner = newSigner;
        pqPublicKeyHash = newPqKeyHash;
        unchecked {
            credentialGeneration += 1;
        }
        emit CredentialRotated(newSigner, credentialGeneration);
    }

    // =====================================================================
    // K-6 — guardian AUTHORITY. G-B: the kernel holds a commitment, threshold
    // and generation; the roster arrives as UNTRUSTED CALLDATA and is validated
    // against a value the kernel wrote itself. Nobody pushes.
    // =====================================================================

    /**
     * @dev I-GUARDIAN-CONSTITUENCY-BINDING. The encoding is INJECTIVE: the
     *      threshold is INSIDE the preimage (so an attacker cannot supply it),
     *      and `abi.encode` length-prefixes the arrays, so two different
     *      rosters cannot collide the way a packed encoding permits.
     *      I-GUARDIAN-AUTH-MODE-IS-COMMITTED: `isContract` is part of the
     *      commitment, never inferred from `extcodesize`.
     */
    /**
     * @dev `I-QUORUM-PRINCIPAL-DISTINCTNESS` — the fix for finding B.
     *
     *      **Every counted quorum unit must map to a DISTINCT committed guardian
     *      PRINCIPAL; distinct array indices alone are insufficient.** The
     *      earlier kernel enforced strictly-ascending INDICES, which proves the
     *      same slot is not counted twice and proves nothing about addresses. A
     *      roster `[A, A, B]` with threshold 2 reached quorum on ONE principal
     *      signing twice, so the guardian cut was 1 rather than `k`.
     *
     *      Enforced by requiring the committed roster to be in STRICTLY
     *      ASCENDING ADDRESS ORDER. That makes duplicates unrepresentable rather
     *      than merely detected, costs one comparison per member, and — because
     *      the ordering is part of what the commitment covers — every later
     *      quorum evaluation inherits it for free.
     *
     *      **A principal is an ADDRESS, not an (address, mode) pair.** The same
     *      address committed once as an EOA seat and once as an ERC-1271 seat
     *      would be one principal wearing two hats; ascending order over
     *      addresses alone rejects it.
     */
    function _requireCanonicalRoster(
        uint64 threshold,
        address[] calldata members,
        bool[] calldata isContract
    ) internal pure {
        if (members.length != isContract.length) revert BadRoster();
        if (threshold == 0 || members.length < threshold) revert BadRoster();
        address previous = address(0);
        for (uint256 i; i < members.length; ++i) {
            // Strictly ascending: rejects duplicates AND the zero address.
            if (members[i] <= previous) revert NotOrdered();
            previous = members[i];
        }
    }

    function rosterCommitment(
        uint64 threshold,
        address[] calldata members,
        bool[] calldata isContract
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(threshold, members, isContract));
    }

    /**
     * @notice Replace the guardian constituency. Authorized by a quorum
     *         evaluated against the IMMEDIATELY PRECEDING commitment
     *         (I-GUARDIAN-AUTHORITY-CLOSURE).
     */
    function setGuardians(
        uint64 newThreshold,
        address[] calldata newMembers,
        bool[] calldata newIsContract,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {
        _requireNormal();
        _requireCanonicalRoster(newThreshold, newMembers, newIsContract);

        bytes32 newCommitment = rosterCommitment(newThreshold, newMembers, newIsContract);
        bytes32 digest = _digest(
            ACTION_SET_GUARDIANS,
            guardianGeneration,
            newCommitment,
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );

        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        guardianCommitment = newCommitment;
        guardianThreshold = newThreshold;
        unchecked {
            guardianGeneration += 1;
        }
        // I-CONSTITUENCY-RECONSTRUCTIBLE: the FULL preimage, in this same tx.
        emit GuardianCommitmentSet(
            newCommitment,
            guardianGeneration,
            newThreshold,
            abi.encode(newThreshold, newMembers, newIsContract)
        );
    }

    /**
     * @dev Validates untrusted roster calldata against the kernel's own
     *      commitment, then counts STRICTLY ASCENDING distinct attesters
     *      (I-QUORUM-DISTINCTNESS). Reverts unless the threshold is met.
     */
    function _requireQuorum(bytes32 digest, QuorumProof calldata p) internal view {
        // I-QUORUM-PRINCIPAL-DISTINCTNESS, checked on the SUPPLIED preimage. A
        // vault whose genesis roster was not canonical can never reach quorum,
        // which is why the factory refuses to create one (see GenesisConfig).
        _requireCanonicalRoster(guardianThreshold, p.members, p.isContract);
        if (rosterCommitment(guardianThreshold, p.members, p.isContract) != guardianCommitment) revert BadRoster();
        if (p.attestingIndices.length != p.attestations.length) revert BadRoster();

        uint256 counted;
        uint256 previous = type(uint256).max;
        for (uint256 i; i < p.attestingIndices.length; ++i) {
            uint256 idx = p.attestingIndices[i];
            // Strictly ascending. The first iteration's sentinel makes any
            // index valid; every later one must exceed its predecessor, so no
            // index and therefore no address can be counted twice.
            if (previous != type(uint256).max && idx <= previous) revert NotOrdered();
            if (idx >= p.members.length) revert BadRoster();
            previous = idx;

            if (_attests(digest, p.members[idx], p.isContract[idx], p.attestations[i])) {
                unchecked {
                    ++counted;
                }
            }
        }
        if (counted < guardianThreshold) revert QuorumNotMet();
    }

    /**
     * @dev I-GUARDIAN-FAULT-ISOLATION + I-ATTESTATION-IS-AFFIRMATIVE. A
     *      contract guardian is consulted by STATICCALL under a gas cap with a
     *      bounded returndata copy, and NON-BUBBLING failure handling: revert,
     *      out-of-gas, unbounded returndata and attempted reentrancy all count
     *      as "did not attest" and change nothing for the other guardians.
     *      Only a 32-byte return equal to the ERC-1271 magic value counts.
     */
    function _attests(
        bytes32 digest,
        address guardian,
        bool isContract,
        bytes calldata signature
    ) internal view returns (bool) {
        if (!isContract) {
            // A malformed signature must not abort the whole quorum, so the
            // recovery is attempted in a way that cannot bubble.
            if (signature.length != 65) return false;
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
            return err == ECDSA.RecoverError.NoError && recovered == guardian && recovered != address(0);
        }

        bytes memory payload = abi.encodeWithSelector(IERC1271Guardian.isValidSignature.selector, digest, signature);
        bool ok;
        bytes32 answer;
        assembly ("memory-safe") {
            // Bounded returndata copy: exactly one word, into scratch space.
            let scratch := mload(0x40)
            ok := staticcall(GUARDIAN_CALL_GAS, guardian, add(payload, 0x20), mload(payload), scratch, 0x20)
            if ok {
                if eq(returndatasize(), 0x20) {
                    answer := mload(scratch)
                }
            }
        }
        return ok && bytes4(answer) == ERC1271_MAGIC;
    }

    // =====================================================================
    // K-7 / K-8 / K-9 — recovery. Consults ONLY the clone's own
    // implementation, the ecrecover precompile, and guardian principals named
    // in the vault's own committed constituency (I-RECOVERY-LOCALITY-V2).
    // It reads NO plane state and NO globally-mutable state.
    // =====================================================================

    function initiateRecovery(
        address proposedSigner,
        bytes32 proposedPqKeyHash,
        address proposedVerifier,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline
    ) external {
        _requireRecoveryOpen();
        if (proposedSigner == address(0) || proposedVerifier == address(0)) revert ZeroAddress();
        if (proposedVerifier.code.length == 0) revert ZeroAddress();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            guardianGeneration,
            keccak256(abi.encode(proposedSigner, proposedPqKeyHash, proposedVerifier)),
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        recovery = RecoveryRequest({
            proposedSigner: proposedSigner,
            proposedPqKeyHash: proposedPqKeyHash,
            // THE VERIFIER ESCAPE. Recovery carries a REPLACEMENT verifier, so a
            // permanently dead or Byzantine verifier is escapable by the
            // guardian quorum without ever granting the surviving ECDSA factor
            // unilateral authority over the other factor oracle. This is what
            // satisfies I-NO-CIRCULAR-ESCAPE now that setVerifier is HYBRID.
            proposedVerifier: proposedVerifier,
            executableAt: uint64(block.timestamp) + RECOVERY_DELAY,
            expiresAt: uint64(block.timestamp) + RECOVERY_DELAY + RECOVERY_EXPIRY,
            // Support is keyed to the generation, so a roster change cannot be
            // replayed into a pending request.
            boundGuardianGeneration: guardianGeneration,
            challengesUsed: recovery.challengesUsed,
            active: true
        });
        emit RecoveryInitiated(proposedSigner, recovery.executableAt, guardianGeneration);
    }

    /**
     * @notice The credential may cancel a pending recovery a BOUNDED number of
     *         times per episode. `I-VETO-BOUND`: unbounded would restore H-03,
     *         a permanent veto held by exactly the principal whose compromise
     *         recovery exists to remedy.
     */
    function cancelRecovery(uint256 nonce, uint64 deadline, bytes calldata ecdsaSig) external {
        _requireRecoveryOpen();
        if (!recovery.active) revert NoRecovery();
        if (recovery.challengesUsed >= CHALLENGE_LIMIT) revert ChallengeExhausted();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            credentialGeneration,
            keccak256("CANCEL"),
            DOMAIN_CREDENTIAL,
            nonce,
            deadline
        );
        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();
        _consume(DOMAIN_CREDENTIAL, nonce, deadline);

        unchecked {
            recovery.challengesUsed += 1;
        }
        recovery.active = false;
        emit RecoveryCancelled(recovery.challengesUsed);
    }

    /// @notice Permissionless once matured — it carries no discretion.
    /**
     * @notice Permissionless once matured, but only on PROOF OF POSSESSION of
     *         both incoming factors (finding D). Without it a guardian quorum
     *         could install a credential nobody holds and strand the vault
     *         behind a second recovery.
     *
     * @dev Possession is proven against the INCOMING verifier, so a vault
     *      escaping a dead verifier proves against the replacement rather than
     *      against the corpse.
     */
    function executeRecovery(CredentialChange calldata c) external {
        _requireRecoveryOpen();
        RecoveryRequest memory r = recovery;
        if (!r.active) revert NoRecovery();
        if (block.timestamp < r.executableAt) revert TooEarly();
        if (block.timestamp > r.expiresAt) revert Expired();
        // A roster change since the request invalidates it.
        if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();

        _requireIncomingPossession(
            recoveryPossessionDigest(),
            r.proposedSigner,
            r.proposedPqKeyHash,
            r.proposedVerifier,
            c
        );

        delete recovery;
        pqVerifier = r.proposedVerifier;
        _installCredential(r.proposedSigner, r.proposedPqKeyHash);
        emit VerifierChanged(r.proposedVerifier);
        emit RecoveryExecuted(r.proposedSigner, credentialGeneration);
    }

    // =====================================================================
    // K-11 — emergency transition RULES. The trigger is an ADAPTER; the rules
    // below are the kernel's, and they bound it.
    // =====================================================================

    /**
     * @notice Enter containment. Re-entry while already contained is a NO-OP
     *         (`I-CONTAINMENT-NO-EXTENSION`), and total contained time in any
     *         rolling window is capped at `CONTAINMENT_BUDGET < CONTAINMENT_WINDOW`
     *         (`I-CONTAINMENT-BUDGET`), so denial is a duty cycle, not a state.
     */
    function enterContainment(QuorumProof calldata proof, uint256 nonce, uint64 deadline) external {
        SafeState current = _effectiveState();
        if (current != SafeState.NORMAL) revert BadState();

        bytes32 digest = _digest(
            ACTION_RECOVER,
            guardianGeneration,
            keccak256("CONTAIN"),
            DOMAIN_GUARDIAN,
            nonce,
            deadline
        );
        _requireQuorum(digest, proof);
        _consume(DOMAIN_GUARDIAN, nonce, deadline);

        // The window origin advances ONLY by elapsed wall clock and can be
        // moved by no principal.
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= containmentWindowStart + CONTAINMENT_WINDOW) {
            containmentWindowStart = nowTs;
            containmentUsedInWindow = 0;
        }
        if (containmentUsedInWindow + CONTAINMENT_MAX > CONTAINMENT_BUDGET) revert ContainmentBudget();

        containmentUsedInWindow += CONTAINMENT_MAX;
        containedUntil = nowTs + CONTAINMENT_MAX;
        safeState = SafeState.CONTAINED;
        emit SafeStateChanged(SafeState.NORMAL, SafeState.CONTAINED);
    }

    // =====================================================================
    // K-12 / K-13 — migration. Binds the destination VAULT (never merely its
    // implementation), a disposition of FULL BALANCE (never an amount), and no
    // closed asset set.
    // =====================================================================

    function bindMigration(
        Destination calldata destination,
        QuorumProof calldata proof,
        uint256 nonce,
        uint64 deadline,
        bytes calldata ecdsaSig
    ) external {
        if (_effectiveState() == SafeState.RETIRED) revert BadState();
        if (migration.bound) revert AlreadyBound();
        if (destination.vault == address(0) || destination.codeHash == bytes32(0)) revert DestinationMismatch();
        // A pending recovery blocks binding: migration must never front-run the
        // remedy (I-MIGRATION-SUBORDINATE-TO-RECOVERY).
        if (recovery.active) revert NoRecovery();

        {
            bytes32 digest = _digest(
                ACTION_BIND_MIGRATION,
                guardianGeneration,
                keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation)),
                DOMAIN_MIGRATION,
                nonce,
                deadline
            );
            // BOTH principals: guardian quorum AND credential (section 22 D2).
            _requireQuorum(digest, proof);
            if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();
        }
        _consume(DOMAIN_MIGRATION, nonce, deadline);

        migration = MigrationBinding({
            destinationVault: destination.vault,
            destinationVaultCodeHash: destination.codeHash,
            destinationGeneration: destination.generation,
            boundAt: uint64(block.timestamp),
            bound: true
        });
        emit SafeStateChanged(safeState, SafeState.MIGRATION_ONLY);
        safeState = SafeState.MIGRATION_ONLY;
        emit MigrationBound(destination.vault, destination.codeHash, destination.generation);
    }

    /// @notice Freeze authority. Terminal by AUTHORITY, never by activity
    ///         (`I-TERMINALITY-IS-AUTHORITY`): egress stays open forever.
    function retire() external {
        if (!migration.bound) revert NotBound();
        if (block.timestamp < migration.boundAt + BIND_DELAY) revert TooEarly();
        SafeState previous = safeState;
        safeState = SafeState.RETIRED;
        emit SafeStateChanged(previous, SafeState.RETIRED);
        emit Retired();
    }

    /**
     * @notice Move ONE asset class to the bound destination. PERMISSIONLESS,
     *         because it carries no discretion: the recipient comes from the
     *         binding and the disposition is the FULL BALANCE.
     *
     *         `asset == address(0)` means native value.
     *
     *         Entries are INDEPENDENT (`I-EGRESS-INDEPENDENCE`): this function
     *         moves exactly one asset and touches no other, so an unsolicited
     *         or hostile token can never veto a manifested one
     *         (`I-MIGRATION-NONTRAP` clause (a)). It NEVER closes
     *         (`I-EGRESS-RETRY-PERPETUAL`), including from RETIRED.
     */
    function egress(address asset) external {
        MigrationBinding memory b = migration;
        if (!b.bound) revert NotBound();
        // The destination's identity is re-checked AT EXECUTION, not merely at
        // binding, so a destination whose code changed is refused.
        if (b.destinationVault.codehash != b.destinationVaultCodeHash) revert DestinationMismatch();

        uint256 moved;
        if (asset == address(0)) {
            moved = address(this).balance;
            if (moved != 0) {
                (bool ok, ) = payable(b.destinationVault).call{value: moved}("");
                if (!ok) revert TransferFailed();
            }
        } else {
            // Settlement is judged on an OBSERVED balance decrease, never on
            // "the call did not revert" (`I-NO-FALSE-SETTLEMENT`).
            uint256 before = _balanceOf(asset);
            if (before != 0) {
                (bool ok, ) = asset.call(abi.encodeWithSelector(0xa9059cbb, b.destinationVault, before));
                if (!ok) revert TransferFailed();
                uint256 remaining = _balanceOf(asset);
                if (remaining >= before) revert TransferFailed();
                moved = before - remaining;
            }
        }
        emit Egressed(asset, b.destinationVault, moved);
    }

    function _balanceOf(address asset) internal view returns (uint256) {
        (bool ok, bytes memory data) = asset.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || data.length < 32) return 0;
        return abi.decode(data, (uint256));
    }
}
