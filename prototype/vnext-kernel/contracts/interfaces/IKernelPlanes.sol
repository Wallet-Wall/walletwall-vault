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

/// @notice Policy plane. PLANE-SAFE and SUBTRACTIVE: it may only refuse.
interface IKernelPolicy {
    /// @return allowed false denies. A true answer grants NOTHING on its own.
    function check(address vault, address recipient, uint256 amount) external view returns (bool allowed);
}

/// @notice ERC-1271, for guardian seats that authenticate by contract (section 9).
interface IERC1271Guardian {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
