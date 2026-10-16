// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPQCVerifier.sol";

/**
 * @title UnhaltableZkVerifierMock
 * @notice TEST ONLY. A verifier on the SP1 path (it reports the ZK-ML-DSA-65 algorithm id and an SP1 identity)
 *         with no halt surface: it stands for a pre-SP1-TD2 ZKMLDSAVerifier build, or a non-haltable pinned
 *         wrapper, so the SP1-TD2 binding gate can be shown to refuse it where the halt must reach (a consumer
 *         in the halt's scope) and where the SP1 path must not reach at all (an excluded consumer). It verifies
 *         nothing.
 */
contract UnhaltableZkVerifierMock is IPQCVerifier {
    address public immutable SP1_VERIFIER;
    bytes32 public immutable PROGRAM_VKEY;

    constructor(address sp1Verifier, bytes32 programVKey) {
        SP1_VERIFIER = sp1Verifier;
        PROGRAM_VKEY = programVKey;
    }

    function algorithmId() external pure override returns (bytes32) {
        return keccak256("ZK-ML-DSA-65");
    }

    function verify(bytes32, bytes calldata, bytes calldata) external pure override returns (bool) {
        return false;
    }
}
