// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../verifiers/ZKMLDSAVerifier.sol";

/**
 * TEST ONLY — SP1-TD1 trust-target probes (docs/SP1_TD1_Trust_Target_Program_Identity.md).
 *
 * Never deployed. test/Sp1Td1TrustTargetProbes.test.ts runs them against the exact mainnet bytes of
 * Succinct's SP1VerifierGateway and SP1Verifier v6.0.0 / v6.1.0 (deployed in the test from the
 * CREATE2-authenticated initcode in evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json) to
 * test which verifier trust targets let a third party widen the relation ZKMLDSAVerifier accepts.
 * The design prototypes here (selector pin, route pin, code pin) are evidence for the TD1 decision,
 * not the production change; that is frozen for the next implementation lane.
 */

/// @notice The view the gateway exposes for its write-once route table.
interface ISp1GatewayRoutesProbe {
    function routes(bytes4 selector) external view returns (address verifier, bool frozen);
}

/**
 * @notice A verifier a gateway owner may route to: it reports any VERIFIER_HASH it is given and
 *         accepts every proof. It stands for a malicious, buggy or merely different verifier.
 */
contract AcceptAllRouteVerifierProbe is ISP1Verifier {
    bytes32 public immutable VERIFIER_HASH;

    constructor(bytes32 verifierHash) {
        VERIFIER_HASH = verifierHash;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

/**
 * @notice Accepts exactly the (program vkey, public values, proof bytes) tuples a test registered,
 *         so a test can show which tuple reached it through a gateway.
 */
contract ExactTupleVerifierProbe is ISP1Verifier {
    bytes32 public immutable VERIFIER_HASH;
    mapping(bytes32 tupleHash => bool registered) public registered;

    error TupleNotRegistered(bytes32 tupleHash);

    constructor(bytes32 verifierHash) {
        VERIFIER_HASH = verifierHash;
    }

    function register(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external {
        registered[keccak256(abi.encode(programVKey, publicValues, proofBytes))] = true;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view {
        bytes32 tupleHash = keccak256(abi.encode(programVKey, publicValues, proofBytes));
        if (!registered[tupleHash]) revert TupleNotRegistered(tupleHash);
    }
}

/**
 * @notice Option B, naive: WalletWall checks only the proof's 4-byte verifier selector, then forwards
 *         to the gateway. Safe only where the gateway already routes that selector to the verifier
 *         WalletWall means; the probe exists to show what happens where it does not.
 */
contract SelectorPinnedGatewayProbe is ISP1Verifier {
    address public immutable GATEWAY;
    bytes4 public immutable SELECTOR;

    error UnexpectedSelector(bytes4 received, bytes4 expected);

    constructor(address gateway, bytes4 selector) {
        GATEWAY = gateway;
        SELECTOR = selector;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view {
        bytes4 received = proofBytes.length < 4 ? bytes4(0) : bytes4(proofBytes[:4]);
        if (received != SELECTOR) revert UnexpectedSelector(received, SELECTOR);
        ISP1Verifier(GATEWAY).verifyProof(programVKey, publicValues, proofBytes);
    }
}

/**
 * @notice Option B, pinned: the selector pin plus, at construction, the gateway's code, the verifier
 *         the gateway routes that selector to, and that verifier's code. SP1VerifierGateway routes are
 *         write-once (addRoute reverts RouteAlreadyExists), so a route checked here cannot later be
 *         redirected; the owner keeps only freezeRoute.
 */
contract RoutePinnedGatewayProbe is ISP1Verifier {
    address public immutable GATEWAY;
    bytes4 public immutable SELECTOR;

    error GatewayCodeMismatch(bytes32 actual, bytes32 expected);
    error RouteVerifierMismatch(address routed, address expected);
    error VerifierCodeMismatch(bytes32 actual, bytes32 expected);
    error UnexpectedSelector(bytes4 received, bytes4 expected);

    constructor(address gateway, bytes32 gatewayCodehash, bytes4 selector, address verifier, bytes32 verifierCodehash) {
        if (gateway.codehash != gatewayCodehash) revert GatewayCodeMismatch(gateway.codehash, gatewayCodehash);
        (address routed, ) = ISp1GatewayRoutesProbe(gateway).routes(selector);
        if (routed != verifier) revert RouteVerifierMismatch(routed, verifier);
        if (verifier.codehash != verifierCodehash) revert VerifierCodeMismatch(verifier.codehash, verifierCodehash);
        GATEWAY = gateway;
        SELECTOR = selector;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view {
        bytes4 received = proofBytes.length < 4 ? bytes4(0) : bytes4(proofBytes[:4]);
        if (received != SELECTOR) revert UnexpectedSelector(received, SELECTOR);
        ISP1Verifier(GATEWAY).verifyProof(programVKey, publicValues, proofBytes);
    }
}

/**
 * @notice Option A: the production ZKMLDSAVerifier, unchanged, plus a construction-time pin of the
 *         SP1 verifier's runtime code hash. The trust target is a code identity, not an address: the
 *         pinned SP1Verifier has no owner, no storage writes and no immutables, so the same code can be
 *         recognised at any address. The code hash alone does not fix the accepted relation on a chain
 *         whose precompiles differ; that is a per-chain execution check, not something a pin can see.
 *         The implementation lane bakes the expected hash in as a constant; the probe takes it as an
 *         argument so a test can exercise both outcomes. Since SP1-TD2 the wrapper also takes a halt
 *         principal; the probes run it ACTIVE, where verify() is the logic TD1 measured.
 */
contract ZKMLDSAVerifierCodePinnedProbe is ZKMLDSAVerifier {
    error SP1VerifierCodeMismatch(bytes32 actual, bytes32 expected);

    constructor(
        address sp1Verifier,
        bytes32 programVKey,
        bytes32 expectedSp1VerifierCodehash,
        address haltPrincipal
    ) ZKMLDSAVerifier(sp1Verifier, programVKey, haltPrincipal) {
        bytes32 actual = sp1Verifier.codehash;
        if (actual != expectedSp1VerifierCodehash) revert SP1VerifierCodeMismatch(actual, expectedSp1VerifierCodehash);
    }
}

/**
 * @notice Option AF: the direct, code-pinned binding of A, plus a read-only coupling to the upstream gateway's
 *         freeze bit for the pinned selector: verification fails closed once upstream freezes that route. The
 *         gateway never routes anything here, so its owner gains no way to widen the relation; it gains a
 *         kill switch (protective when the verifier itself is unsound, a liveness cost otherwise). The route
 *         and both code hashes are checked at construction, as in the fully pinned gateway probe.
 */
contract FreezeCoupledSp1VerifierProbe is ISP1Verifier {
    address public immutable GATEWAY;
    bytes4 public immutable SELECTOR;
    address public immutable VERIFIER;

    error GatewayCodeMismatch(bytes32 actual, bytes32 expected);
    error RouteVerifierMismatch(address routed, address expected);
    error VerifierCodeMismatch(bytes32 actual, bytes32 expected);
    error PinnedRouteFrozen(bytes4 selector);

    constructor(address gateway, bytes32 gatewayCodehash, bytes4 selector, address verifier, bytes32 verifierCodehash) {
        if (gateway.codehash != gatewayCodehash) revert GatewayCodeMismatch(gateway.codehash, gatewayCodehash);
        (address routed, ) = ISp1GatewayRoutesProbe(gateway).routes(selector);
        if (routed != verifier) revert RouteVerifierMismatch(routed, verifier);
        if (verifier.codehash != verifierCodehash) revert VerifierCodeMismatch(verifier.codehash, verifierCodehash);
        GATEWAY = gateway;
        SELECTOR = selector;
        VERIFIER = verifier;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view {
        (, bool frozen) = ISp1GatewayRoutesProbe(GATEWAY).routes(SELECTOR);
        if (frozen) revert PinnedRouteFrozen(SELECTOR);
        ISP1Verifier(VERIFIER).verifyProof(programVKey, publicValues, proofBytes);
    }
}
