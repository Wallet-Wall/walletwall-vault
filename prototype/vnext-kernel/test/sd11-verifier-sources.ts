/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * LANE SD-11 — the verifier fixtures, and the EVIDENCE LABEL each one carries.
 *
 * Every source below is compiled by the PINNED solc and deployed by an ordinary
 * transaction. None is installed with `setCode`. But "really deployed" is not by
 * itself a claim about production, so each fixture states which label its result
 * may carry, and the suite repeats that label at the assertion:
 *
 *   REACHABLE            a named principal, calling a real function on a really
 *                        deployed contract, moves the system into the state.
 *   REPRESENTABLE        the interface admits the shape; NOTHING is claimed
 *                        about any deployed or intended verifier exposing it.
 *   CONSTRUCTED_CONTROL  built only to test whether a PROPOSED CONTROL detects
 *                        a mechanism. Never evidence that a repository verifier
 *                        has that mechanism.
 *
 * WHAT IS DELIBERATELY *NOT* HERE: a re-implementation of
 * `AttestationPQCVerifier`. SD-11B is measured against the REAL contract, read
 * off disk by `sd11-verifier-compile.ts`, because a port is open to the exact
 * objection SD5-A1R had to accept once already — that the measurement described
 * the harness rather than the system.
 */

/**
 * SD-11A, REPRESENTABLE.
 *
 * ONE address exposing TWO accepting relations over the SAME committed key.
 *
 * STRONG is byte-for-byte the relation of `PrototypeMocks.EcdsaBackedVerifier` —
 * the honest second factor the rest of this suite uses, where "the attacker does
 * not hold the PQ root" is a real cryptographic fact rather than a mock waving
 * things through.
 *
 * WEAK sits at the SAME 65-byte shape as STRONG, which is the whole point and is
 * SD5-A1R's M6: a gate that rejects a forgeable relation only when its ENCODING
 * LENGTH differs from the declared one is shape-scoped, and a deliberate
 * adversary sets the lengths equal for free. Placing WEAK at the declared shape
 * is what makes this reproduction independent of the length gate SD5-I removed —
 * it would defeat the unamended kernel identically.
 *
 * WEAK REQUIRES POSSESSION OF NOTHING. Its tag is a pure function of the digest
 * and the PUBLIC key, so anyone who can read a public key can compute it. It is
 * also NOT always-true: 65,535 of every 65,536 two-byte prefixes are refused,
 * which is the vacuity guard — a relation that accepted everything would prove
 * nothing about relation MULTIPLICITY, only about a broken verifier.
 */
export const DUAL_RELATION_VERIFIER = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Sd11DualRelationVerifier {
    /// STRONG — the relation an admitting principal believes it is admitting.
    function strongAccepts(bytes32 digest, bytes calldata publicKey, bytes calldata signature)
        public
        pure
        returns (bool)
    {
        if (publicKey.length != 32 || signature.length != 65) return false;
        address expected = address(uint160(uint256(bytes32(publicKey[0:32]))));
        if (expected == address(0)) return false;
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        return err == ECDSA.RecoverError.NoError && recovered == expected;
    }

    /// WEAK — a forgeable second relation at the SAME declared shape.
    function weakAccepts(bytes32 digest, bytes calldata publicKey, bytes calldata signature)
        public
        pure
        returns (bool)
    {
        if (signature.length != 65) return false;
        return bytes2(signature[0:2]) == bytes2(keccak256(abi.encodePacked(digest, publicKey)));
    }

    /// The kernel sees ONE function returning ONE bool. Which relation answered is not in the return.
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        return strongAccepts(digest, publicKey, signature) || weakAccepts(digest, publicKey, signature);
    }
}
`;

/**
 * CONSTRUCTED_CONTROL for candidate control B (an EXTCODEHASH pin).
 *
 * The SD-11B ledger entry asserts, as prose, that a codehash pin "would NOT
 * close a delegatecall proxy, whose codehash is stable while its implementation
 * pointer moves". This fixture exists ONLY to convert that sentence from an
 * analytic claim into an executed one, and it is NOT evidence that any
 * repository verifier is a proxy — none is.
 *
 * The fallback returns RAW returndata through assembly rather than
 * `fallback(bytes) returns (bytes memory)`, because the latter would ABI-encode
 * the result a second time and the kernel's `bool` decode would then be reading
 * an offset. The kernel reaches `verify` by STATICCALL; DELEGATECALL is legal
 * inside a static context as long as nothing writes, and neither implementation
 * writes.
 */
export const VERIFIER_PROXY = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Sd11ProxyOwner {
    address public owner;
    address public implementation;

    constructor(address impl) {
        owner = msg.sender;
        implementation = impl;
    }

    function setImplementation(address impl) external {
        require(msg.sender == owner, "not owner");
        implementation = impl;
    }

    fallback() external {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
}

/// The implementation an admitting principal would review: a real possession test.
contract Sd11StrictImpl {
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        if (publicKey.length != 32 || signature.length != 65) return false;
        address expected = address(uint160(uint256(bytes32(publicKey[0:32]))));
        if (expected == address(0)) return false;
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        return err == ECDSA.RecoverError.NoError && recovered == expected;
    }
}

/// The implementation it can become, with the proxy's address and codehash unmoved.
contract Sd11PermissiveImpl {
    function verify(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
`;

/**
 * A PLATFORM MEASUREMENT, not a verifier.
 *
 * The SD-11B entry names "metamorphic redeploy" as the mechanism a codehash pin
 * WOULD address. Under EIP-6780 (Cancun — the evmVersion this prototype pins)
 * SELFDESTRUCT only deletes code when it runs in the SAME transaction that
 * created the account. This contract exists to MEASURE that on the pinned EVM
 * rather than to cite it, because the value of control B depends on it: if code
 * cannot be removed from an account that outlived its creation transaction, then
 * metamorphic replacement of an ALREADY-ADMITTED verifier is not reachable, and
 * a pin aimed at it is aimed at an empty class.
 */
export const DESTRUCTIBLE_VERIFIER = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sd11Destructible {
    /// Required by the vacuity guard: the suite funds this account so that the
    /// SWEEP proves SELFDESTRUCT actually executed. Without a payable path the
    /// funding transfer reverts and the measurement would degenerate into
    /// "destroy() did not revert", which is evidence about nothing.
    receive() external payable {}

    function verify(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return false;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
`;
