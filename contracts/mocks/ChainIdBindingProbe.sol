// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/ZKMLDSAVerifier.sol";

/**
 * @title ChainIdBindingProbe
 * @notice TEST ONLY. Exposes {ZKMLDSAVerifier}'s chain-id comparison (SP1-P1 finding F-1) for chain ids no
 *         development chain can run (2^64 and above), so the full-width comparison is executed rather than
 *         inferred. Everything else is the production wrapper, pin included.
 */
contract ChainIdBindingProbe is ZKMLDSAVerifier {
    constructor(
        address sp1Verifier,
        bytes32 programVKey,
        address haltPrincipal
    ) ZKMLDSAVerifier(sp1Verifier, programVKey, haltPrincipal) {}

    function chainIdMatches(uint64 committed, uint256 chainId) external pure returns (bool) {
        return _chainIdMatches(committed, chainId);
    }
}
