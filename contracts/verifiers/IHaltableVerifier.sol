// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IHaltableVerifier
 * @notice The surface of a WalletWall SP1 verifier wrapper that SP1-TD2 adds next to {IPQCVerifier}: a local,
 *         one-way circuit breaker and the identity a rotation compares against
 *         (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 * @dev Consumers never require this interface: they probe it with bounded static calls
 *      ({VerifierRotationGuard}) so a verifier without it (a mock, an attestation verifier) still works.
 *      `halted() == false` is the ACTIVE state, `true` is HALTED; nothing leads back.
 */
interface IHaltableVerifier {
    /// @notice The only account that can call {halt}. It holds no other power over the wrapper.
    function HALT_PRINCIPAL() external view returns (address);

    /// @notice False while ACTIVE, true once HALTED. Never true -> false.
    function halted() external view returns (bool);

    /// @notice The SP1 verifier the wrapper forwards to; its runtime code hash is half of the identity.
    function SP1_VERIFIER() external view returns (address);

    /// @notice The program verification key; the other half of the identity.
    function PROGRAM_VKEY() external view returns (bytes32);

    /// @notice ACTIVE -> HALTED. Callable once, by {HALT_PRINCIPAL} only.
    function halt() external;
}
