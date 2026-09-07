// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * The two plane boundaries the kernel consults. Both are CONJUNCTIVE: a plane
 * may only SUBTRACT authority (architecture section 4.3). Neither can be the
 * sole positive authenticator of anything (section 4.3a).
 */

/// @notice PQ verification plane. PLANE-SAFE: Byzantine => downgrade, unavailable => denial.
interface IKernelPQVerifier {
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature) external view returns (bool);
}

/**
 * @notice Policy plane. PLANE-SAFE and SUBTRACTIVE: it may only refuse.
 *
 * @dev NON-VIEW BY DESIGN (finding F). A `view` boundary is reached by
 *      STATICCALL, so the plane can never persist what it admitted and a
 *      CUMULATIVE rule — daily spend, velocity, rolling window — is
 *      unrepresentable: two individually-valid spends both pass. Admission is
 *      the minimum boundary that lets the ledger stay OUTSIDE the kernel while
 *      still being enforceable.
 *
 *      The kernel calls this AFTER consuming the nonce and BEFORE moving value,
 *      so a reentrant plane gains nothing it did not already have.
 */
interface IKernelPolicy {
    /// @return allowed false denies. A true answer grants NOTHING on its own.
    function admit(address vault, address recipient, uint256 amount) external returns (bool allowed);
}

/// @notice ERC-1271, for guardian seats that authenticate by contract (section 9).
interface IERC1271Guardian {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
