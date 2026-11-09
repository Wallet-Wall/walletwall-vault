// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * GEN2-PQ-CONFORMANCE-1 — TEST HARNESS ONLY. EXPERIMENTAL · UNAUDITED · NOT PRODUCTION.
 *
 * A measurement probe around an externally deployed ML-DSA-65 verifier. It never interprets a
 * verdict: it forwards the exact calldata a caller would send, reports whether the call succeeded,
 * returns the raw return data and the gas the callee consumed, so a test can record the verifier's
 * behaviour (selector / 0xFFFFFFFF / custom error) without wrapping it in an opinion.
 *
 * Nothing here is a kernel adapter and nothing here decides anything. The gas figures it reports
 * are the callee's consumption inside a STATICCALL on the local simulated EVM, not a cost claim for
 * any network.
 */
contract SpikeProbe {
    /// @notice The verifier's 3-argument (ERC-7913-style) entry point, by full signature, so the overload is unambiguous.
    bytes4 public constant SEL_VERIFY_32 = bytes4(keccak256("verify(bytes,bytes32,bytes)"));
    /// @notice The verifier's 4-argument (FIPS 204 context) entry point.
    bytes4 public constant SEL_VERIFY_CTX = bytes4(keccak256("verify(bytes,bytes,bytes,bytes)"));

    /// @notice Forward `verify(pk, digest, sig)` and report (success, raw return data, gas used by the callee).
    function try32(address verifier, bytes calldata pk, bytes32 digest, bytes calldata sig)
        external
        view
        returns (bool success, bytes memory ret, uint256 gasUsed)
    {
        bytes memory data = abi.encodeWithSelector(SEL_VERIFY_32, pk, digest, sig);
        uint256 g0 = gasleft();
        (success, ret) = verifier.staticcall(data);
        gasUsed = g0 - gasleft();
    }

    /// @notice Forward `verify(pk, m, sig, ctx)` and report (success, raw return data, gas used by the callee).
    function tryCtx(address verifier, bytes calldata pk, bytes calldata m, bytes calldata sig, bytes calldata ctx)
        external
        view
        returns (bool success, bytes memory ret, uint256 gasUsed)
    {
        bytes memory data = abi.encodeWithSelector(SEL_VERIFY_CTX, pk, m, sig, ctx);
        uint256 g0 = gasleft();
        (success, ret) = verifier.staticcall(data);
        gasUsed = g0 - gasleft();
    }

    /// @notice k verifications in one call, the shape a k-member admissible set or a k-of-n quorum would take.
    ///         Counts how many returned the success selector; records total callee gas.
    function tryK(address verifier, bytes[] calldata pks, bytes32[] calldata digests, bytes[] calldata sigs)
        external
        view
        returns (uint256 accepted, uint256 gasUsed)
    {
        require(pks.length == digests.length && pks.length == sigs.length, "length");
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < pks.length; i++) {
            (bool ok, bytes memory ret) = verifier.staticcall(abi.encodeWithSelector(SEL_VERIFY_32, pks[i], digests[i], sigs[i]));
            if (ok && ret.length >= 4 && bytes4(ret) == SEL_VERIFY_32) accepted++;
        }
        gasUsed = g0 - gasleft();
    }

    /// @notice Call the raw Keccak-f[1600] helper on a 200-byte state (25 little-endian lanes as 25 words), as the
    ///         verifier's sponge glue does: STATICCALL with the 800-byte word array in and out.
    function permute(address helper, uint256[25] calldata state)
        external
        view
        returns (bool success, bytes memory ret, uint256 gasUsed)
    {
        uint256 g0 = gasleft();
        (success, ret) = helper.staticcall(abi.encode(state));
        gasUsed = g0 - gasleft();
    }

    /// @notice Call the helper's batched-SHAKE256 entry (any calldata size other than 800 bytes is the raw message).
    function shakeBatch(address helper, bytes calldata message)
        external
        view
        returns (bool success, bytes memory ret, uint256 gasUsed)
    {
        uint256 g0 = gasleft();
        (success, ret) = helper.staticcall(message);
        gasUsed = g0 - gasleft();
    }
}
