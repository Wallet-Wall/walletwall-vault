// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPQCVerifier.sol";
import "./verifiers/VerifierRotationGuard.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title WalletWallMultiSigVault
 * @notice Multi-signature version of the WalletWall Vault, supporting m-of-n ECDSA
 *         and p-of-q PQ signatures.
 * @dev SP1-TD2 (TD2-MULTISIG-ROTATION; docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md): {pqVerifier}
 *      moves only through the delayed proposal/apply flow, with {WalletWallVault}'s semantics (172,800 s
 *      delay, 14-day apply window), so a halted verifier wrapper can be left for a fresh one instead of
 *      locking every tenant (TD1-N11). That rotation is NEW AUTHORIZATION for the contract owner, not an
 *      authority-neutral change: after the delay the owner can install any code-bearing verifier, an
 *      accept-all one included, which voids every tenant's p-of-q PQ signatures at once and leaves each
 *      withdrawal guarded by the tenant's m-of-n ECDSA signatures alone. While a wrapper is halted no tenant
 *      can withdraw, so the delay offers no exit (TD1-N12). {VerifierRotationGuard} keeps a halt principal
 *      from owning or rotating the vault and refuses a halted wrapper or a halted identity as the target;
 *      whether a target passed the SP1 evidence gates is checked by process, not here.
 */
contract WalletWallMultiSigVault is ReentrancyGuard, Pausable, Ownable2Step, EIP712 {
    using ECDSA for bytes32;

    struct MultiSigVault {
        address[] ecdsaSigners;
        uint256 ecdsaThreshold;
        bytes[] pqPublicKeys;
        uint256 pqThreshold;
        uint256 nonce;
        uint256 balance;
        bool exists;
    }

    struct MultiSigWithdrawal {
        address vaultOwner;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 public constant MULTISIG_WITHDRAWAL_TYPEHASH = keccak256(
        "MultiSigWithdrawal(address vaultOwner,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    /// @notice Delay between proposing and applying a PQ verifier update ({WalletWallVault}'s value).
    uint256 public constant PQ_VERIFIER_UPDATE_DELAY = 2 days;

    /// @notice How long a matured verifier proposal stays applicable before it expires. An unbounded window
    ///         would let an owner pre-arm a swap and later apply it with no fresh notice; see
    ///         {WalletWallVault.GOVERNANCE_GRACE_PERIOD}.
    uint256 public constant GOVERNANCE_GRACE_PERIOD = 14 days;

    /// @notice Post-quantum verifier every tenant's PQ signatures are checked against.
    /// @dev Mutable only through {proposePQVerifier} and {applyPQVerifierUpdate}.
    IPQCVerifier public pqVerifier;

    /// @notice Verifier proposed for the next delayed update.
    address public pendingPQVerifier;

    /// @notice Earliest timestamp at which the pending verifier can be applied.
    uint256 public pendingPQVerifierValidAfter;

    /// @notice Identities (SP1 verifier code hash, PROGRAM_VKEY) of halted wrappers this vault rotated away from;
    ///         never accepted as a rotation target again. See {VerifierRotationGuard}.
    mapping(bytes32 identity => bool halted) public haltedVerifierIdentities;

    /// @notice The identity (SP1 verifier code hash, PROGRAM_VKEY) {pqVerifier} showed when it was installed, or
    ///         zero if it showed none. Measured once and never asked again, so the current verifier cannot
    ///         change which identity its halt refuses. See {VerifierRotationGuard}.
    bytes32 public pqVerifierIdentity;

    mapping(address => MultiSigVault) public vaults;

    event VaultCreated(
        address indexed owner,
        address[] ecdsaSigners,
        uint256 ecdsaThreshold,
        bytes[] pqPublicKeys,
        uint256 pqThreshold
    );
    event Deposited(address indexed owner, address indexed from, uint256 amount);
    event Withdrawn(address indexed owner, address indexed recipient, uint256 amount, uint256 nonce);
    event PQVerifierUpdateProposed(
        address indexed currentVerifier,
        address indexed proposedVerifier,
        uint256 validAfter
    );
    event PQVerifierUpdateCancelled(address indexed cancelledVerifier);
    event PQVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    error ZeroAddress();
    error ZeroAmount();
    error ZeroRecipient();
    error VaultAlreadyExists();
    error VaultDoesNotExist();
    error InsufficientBalance();
    error InvalidNonce(uint256 expected, uint256 provided);
    error DeadlineExpired(uint256 deadline, uint256 nowTimestamp);
    error InvalidThreshold();
    error DuplicateSigner();
    error InvalidSignature();
    error InsufficientSignatures();
    error TransferFailed();
    error OwnershipRenunciationDisabled();
    /// @notice A proposed or pending verifier has no runtime code.
    error NoCode(address account);
    error NoPendingPQVerifier();
    error PQVerifierUpdateNotReady(uint256 validAfter, uint256 currentTimestamp);
    /// @notice A matured verifier proposal outlived {GOVERNANCE_GRACE_PERIOD}; re-propose.
    error ProposalExpired(uint256 validAfter, uint256 expiresAt, uint256 currentTimestamp);

    constructor(address _pqVerifier) Ownable(msg.sender) EIP712("WalletWallMultiSigVault", "1") {
        if (_pqVerifier == address(0)) revert ZeroAddress();
        pqVerifier = IPQCVerifier(_pqVerifier);
        pqVerifierIdentity = VerifierRotationGuard.requireAdmissibleInitialVerifier(_pqVerifier, msg.sender);
    }

    function createVault(
        address[] calldata ecdsaSigners,
        uint256 ecdsaThreshold,
        bytes[] calldata pqPublicKeys,
        uint256 pqThreshold
    ) external whenNotPaused {
        if (vaults[msg.sender].exists) revert VaultAlreadyExists();
        if (ecdsaThreshold == 0 || ecdsaThreshold > ecdsaSigners.length) revert InvalidThreshold();
        if (pqThreshold == 0 || pqThreshold > pqPublicKeys.length) revert InvalidThreshold();

        // Check for duplicates in ECDSA signers
        for (uint256 i = 0; i < ecdsaSigners.length; i++) {
            if (ecdsaSigners[i] == address(0)) revert ZeroAddress();
            for (uint256 j = i + 1; j < ecdsaSigners.length; j++) {
                if (ecdsaSigners[i] == ecdsaSigners[j]) revert DuplicateSigner();
            }
        }

        // Check for duplicates in PQ public keys
        for (uint256 i = 0; i < pqPublicKeys.length; i++) {
            bytes32 hashI = keccak256(pqPublicKeys[i]);
            for (uint256 j = i + 1; j < pqPublicKeys.length; j++) {
                if (hashI == keccak256(pqPublicKeys[j])) revert DuplicateSigner();
            }
        }

        vaults[msg.sender] = MultiSigVault({
            ecdsaSigners: ecdsaSigners,
            ecdsaThreshold: ecdsaThreshold,
            pqPublicKeys: pqPublicKeys,
            pqThreshold: pqThreshold,
            nonce: 0,
            balance: 0,
            exists: true
        });

        emit VaultCreated(msg.sender, ecdsaSigners, ecdsaThreshold, pqPublicKeys, pqThreshold);
    }

    /// @notice Deposits ETH into the caller's own vault. Refused while paused; ETH that arrives
    ///         without a call (a `selfdestruct` beneficiary, a block's fee recipient) cannot be
    ///         refused by any modifier and is never credited.
    function deposit() external payable whenNotPaused {
        _deposit(msg.sender);
    }

    /// @notice Deposits ETH into the vault owned by `vaultOwner`. Refused while paused, exactly
    ///         like {deposit}.
    function depositFor(address vaultOwner) external payable whenNotPaused {
        _deposit(vaultOwner);
    }

    function _deposit(address vaultOwner) internal {
        if (msg.value == 0) revert ZeroAmount();
        MultiSigVault storage vault = vaults[vaultOwner];
        if (!vault.exists) revert VaultDoesNotExist();
        vault.balance += msg.value;
        emit Deposited(vaultOwner, msg.sender, msg.value);
    }

    /**
     * @notice Executes a multi-sig withdrawal.
     * @param request The withdrawal parameters.
     * @param ecdsaSignatures Array of ECDSA signatures, must be sorted by signer address.
     * @param pqSignatures Array of PQ signatures.
     * @param pqKeyIndices Array of indices mapping each PQ signature to a public key in the vault.
     */
    function withdraw(
        MultiSigWithdrawal calldata request,
        bytes[] calldata ecdsaSignatures,
        bytes[] calldata pqSignatures,
        uint256[] calldata pqKeyIndices
    ) external nonReentrant whenNotPaused {
        {
            MultiSigVault storage v = vaults[request.vaultOwner];
            if (!v.exists) revert VaultDoesNotExist();
            if (block.timestamp > request.deadline) revert DeadlineExpired(request.deadline, block.timestamp);
            if (request.amount == 0) revert ZeroAmount();
            if (request.recipient == address(0)) revert ZeroRecipient();
            if (request.nonce != v.nonce) revert InvalidNonce(v.nonce, request.nonce);
            if (v.balance < request.amount) revert InsufficientBalance();

            if (ecdsaSignatures.length < v.ecdsaThreshold) revert InsufficientSignatures();
            if (pqSignatures.length < v.pqThreshold) revert InsufficientSignatures();
            if (pqSignatures.length != pqKeyIndices.length) revert InvalidSignature();
        }

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MULTISIG_WITHDRAWAL_TYPEHASH,
                    request.vaultOwner,
                    request.recipient,
                    request.amount,
                    request.nonce,
                    request.deadline
                )
            )
        );

        _verifySignatures(vaults[request.vaultOwner], digest, ecdsaSignatures, pqSignatures, pqKeyIndices);

        MultiSigVault storage vault = vaults[request.vaultOwner];
        unchecked {
            vault.nonce++;
        }
        vault.balance -= request.amount;

        (bool success, ) = request.recipient.call{value: request.amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawn(request.vaultOwner, request.recipient, request.amount, vault.nonce - 1);
    }

    function _verifySignatures(
        MultiSigVault storage vault,
        bytes32 digest,
        bytes[] calldata ecdsaSignatures,
        bytes[] calldata pqSignatures,
        uint256[] calldata pqKeyIndices
    ) internal view {
        // Verify ECDSA signatures
        address lastSigner = address(0);
        for (uint256 i = 0; i < ecdsaSignatures.length; i++) {
            address signer = ECDSA.recover(digest, ecdsaSignatures[i]);
            if (signer <= lastSigner) revert InvalidSignature();

            bool isAuthorized = false;
            for (uint256 j = 0; j < vault.ecdsaSigners.length; j++) {
                if (vault.ecdsaSigners[j] == signer) {
                    isAuthorized = true;
                    break;
                }
            }
            if (!isAuthorized) revert InvalidSignature();
            lastSigner = signer;
        }

        // Verify PQ signatures
        for (uint256 i = 0; i < pqSignatures.length; i++) {
            uint256 keyIndex = pqKeyIndices[i];
            if (keyIndex >= vault.pqPublicKeys.length) revert InvalidSignature();
            if (i > 0 && keyIndex <= pqKeyIndices[i - 1]) revert InvalidSignature();

            if (!pqVerifier.verify(digest, vault.pqPublicKeys[keyIndex], pqSignatures[i])) {
                revert InvalidSignature();
            }
        }
    }

    function getVault(address owner) external view returns (MultiSigVault memory) {
        return vaults[owner];
    }

    /**
     * @notice Proposes a new PQ verifier. Admin-only.
     * @dev A later proposal replaces the pending one and restarts the delay; the active verifier is unchanged
     *      until {applyPQVerifierUpdate}. The target must have code, must not be halted or carry a halted
     *      identity, and neither the caller nor any other halt principal of either verifier may drive the
     *      rotation ({VerifierRotationGuard}). Nothing here proves the target passed the SP1 evidence gates.
     */
    function proposePQVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (newVerifier.code.length == 0) revert NoCode(newVerifier);
        VerifierRotationGuard.requireAdmissibleRotation(
            haltedVerifierIdentities,
            pqVerifierIdentity,
            address(pqVerifier),
            newVerifier,
            msg.sender
        );

        uint256 validAfter = block.timestamp + PQ_VERIFIER_UPDATE_DELAY;
        pendingPQVerifier = newVerifier;
        pendingPQVerifierValidAfter = validAfter;

        emit PQVerifierUpdateProposed(address(pqVerifier), newVerifier, validAfter);
    }

    /// @notice Cancels the pending PQ verifier update. Admin-only; reverts when nothing is pending.
    function cancelPQVerifierUpdate() external onlyOwner {
        address cancelledVerifier = pendingPQVerifier;
        if (cancelledVerifier == address(0)) revert NoPendingPQVerifier();

        pendingPQVerifier = address(0);
        pendingPQVerifierValidAfter = 0;

        emit PQVerifierUpdateCancelled(cancelledVerifier);
    }

    /**
     * @notice Applies the pending PQ verifier once the delay has passed and before the proposal expires.
     *         Admin-only. The one way {pqVerifier} changes after construction.
     * @dev Re-checks everything {proposePQVerifier} checked, since the delay separates the two: the target may
     *      have lost its code or been halted meanwhile, and the current verifier may have been halted. A
     *      rejected apply changes nothing, so the proposal stays cancellable. Leaving a halted wrapper records
     *      its identity, which is then refused as a target for good.
     */
    function applyPQVerifierUpdate() external onlyOwner {
        address newVerifier = pendingPQVerifier;
        if (newVerifier == address(0)) revert NoPendingPQVerifier();

        uint256 validAfter = pendingPQVerifierValidAfter;
        if (block.timestamp < validAfter) {
            revert PQVerifierUpdateNotReady(validAfter, block.timestamp);
        }
        uint256 expiresAt = validAfter + GOVERNANCE_GRACE_PERIOD;
        if (block.timestamp > expiresAt) revert ProposalExpired(validAfter, expiresAt, block.timestamp);

        if (newVerifier.code.length == 0) revert NoCode(newVerifier);

        address oldVerifier = address(pqVerifier);
        bytes32 newIdentity = VerifierRotationGuard.requireAdmissibleRotation(
            haltedVerifierIdentities,
            pqVerifierIdentity,
            oldVerifier,
            newVerifier,
            msg.sender
        );
        VerifierRotationGuard.recordHaltedIdentity(haltedVerifierIdentities, pqVerifierIdentity, oldVerifier);
        pqVerifier = IPQCVerifier(newVerifier);
        pqVerifierIdentity = newIdentity;

        pendingPQVerifier = address(0);
        pendingPQVerifierValidAfter = 0;

        emit PQVerifierUpdated(oldVerifier, newVerifier);
    }

    /// @notice Pauses deposits, vault creation and withdrawal. Admin-only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the vault. Admin-only.
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Ownership renunciation is permanently disabled. Always reverts.
     * @dev The inherited {Ownable.renounceOwnership} would set `owner()` to `address(0)`. {pause}
     *      and {unpause} are `onlyOwner` while {withdraw}, {deposit}, {depositFor} and
     *      {createVault} are `whenNotPaused`, so renouncing while paused would leave {unpause}
     *      uncallable forever — and this contract has no recovery path of any kind, so every
     *      tenant's withdrawal would be frozen permanently. Mirrors the override in
     *      {WalletWallVault} and {StablecoinVaultSimulator}. Declared `pure`, so an ABI that
     *      reports `nonpayable` for this selector shows the override has been removed. Ownership
     *      still moves through {transferOwnership} and {acceptOwnership}.
     */
    function renounceOwnership() public pure override {
        revert OwnershipRenunciationDisabled();
    }

    /// @dev Every completed ownership change (accepting a two-step transfer) refuses an account that can halt the
    ///      current or the pending verifier: the halt principal never holds the rotation (SP1-TD2). The
    ///      constructor makes the same check for the deployer once {pqVerifier} is set. Mirrors {WalletWallVault}.
    function _transferOwnership(address newOwner) internal override {
        VerifierRotationGuard.requireNotHaltPrincipal(newOwner, address(pqVerifier), pendingPQVerifier);
        super._transferOwnership(newOwner);
    }
}
