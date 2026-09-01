// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./interfaces/IKernelPlanes.sol";

/**
 * EXPERIMENTAL PROTOTYPE TEST FIXTURES — NOT PRODUCTION, NOT DEPLOYED.
 * Every contract here exists to be an adversary or a control in the prototype
 * test suite. None is measured by `measure.ts`.
 */

/// @notice A verifier that answers a fixed way. `ALWAYS_TRUE` is the M-K07 adversary.
contract ConfigurableVerifier is IKernelPQVerifier {
    enum Mode {
        ALWAYS_TRUE,
        ALWAYS_FALSE,
        REVERTS
    }

    Mode public mode;

    constructor(Mode m) {
        mode = m;
    }

    function verify(bytes32, bytes calldata, bytes calldata) external view returns (bool) {
        if (mode == Mode.REVERTS) revert("verifier down");
        return mode == Mode.ALWAYS_TRUE;
    }
}

/// @notice A subtractive policy plane. `deny` proves a plane can only refuse.
contract ConfigurablePolicy is IKernelPolicy {
    bool public allowAll;

    constructor(bool allow) {
        allowAll = allow;
    }

    function admit(address, address, uint256) external view returns (bool) {
        return allowAll;
    }
}

/// @notice An ERC-1271 guardian that behaves well.
contract GoodContractGuardian is IERC1271Guardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @notice Reverts. Under I-GUARDIAN-FAULT-ISOLATION this must count as "did not attest".
contract RevertingGuardian is IERC1271Guardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        revert("no");
    }
}

/**
 * @notice Burns every forwarded unit of gas, then would answer correctly. The
 *         kernel's forwarded-gas cap must contain it, so it never gets to
 *         answer and the surrounding quorum is unaffected. Deliberately NOT
 *         declared `IERC1271Guardian`, because the interface is `view` and this
 *         one must be free to spin without writing state.
 */
contract GasBurningGuardian {
    function isValidSignature(bytes32 h, bytes calldata) external view returns (bytes4) {
        bytes32 acc = h;
        for (uint256 i; i < type(uint256).max; ++i) {
            acc = keccak256(abi.encode(acc, i));
        }
        return acc == bytes32(0) ? bytes4(0) : bytes4(0x1626ba7e);
    }
}

/// @notice Returns 32 bytes that are NOT the magic value. Must not count.
contract WrongAnswerGuardian is IERC1271Guardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

/// @notice Returns a huge blob. The bounded returndata copy must contain it.
contract HugeReturnGuardian {
    fallback(bytes calldata) external returns (bytes memory) {
        return new bytes(10_000);
    }
}

/// @notice Minimal ERC-20 for migration egress tests.
contract TestToken {
    mapping(address => uint256) public balanceOf;
    bool public failTransfers;

    constructor(bool fail) {
        failTransfers = fail;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (failTransfers) revert("blacklisted");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice A token whose transfer returns false without reverting (M-K: no false settlement).
contract SilentlyFailingToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/// @notice Deploys a clone WITHOUT initializing it — the M-K01 takeover window.
contract RawCloner {
    address public lastClone;

    function cloneOnly(address implementation, bytes32 salt) external returns (address c) {
        c = Clones.cloneDeterministic(implementation, salt);
        lastClone = c;
    }

    function cloneWithArgs(address implementation, bytes calldata args, bytes32 salt) external returns (address c) {
        c = Clones.cloneDeterministicWithImmutableArgs(implementation, args, salt);
        lastClone = c;
    }
}

/// @notice A destination with code, so a migration binding has a real codehash.
contract DestinationStub {
    receive() external payable {}
}

/// @notice Re-enters the kernel during a value transfer.
contract ReentrantRecipient {
    address public kernel;
    bytes public payload;
    bool public tried;
    bool public succeeded;

    function arm(address k, bytes calldata p) external {
        kernel = k;
        payload = p;
    }

    receive() external payable {
        if (tried || kernel == address(0)) return;
        tried = true;
        (bool ok, ) = kernel.call(payload);
        succeeded = ok;
    }
}

/**
 * @notice An HONEST second factor, standing in for a real PQ scheme.
 *
 * Modelling asymmetric verification with a hash is impossible — anyone who can
 * read the public key can forge. So this verifier uses a SECOND, INDEPENDENT
 * ECDSA keypair as the stand-in: the "public key" is that keypair's address and
 * the "signature" is a real `ecrecover`-checkable signature over the digest.
 *
 * That matters for the authority-closure tests. An attack that succeeds against
 * THIS verifier cannot be dismissed as "the mock was weak" — the second factor
 * genuinely requires possession of a key the attacker does not hold.
 */
contract EcdsaBackedVerifier is IKernelPQVerifier {
    function verify(bytes32 digest, bytes calldata publicKey, bytes calldata signature) external pure returns (bool) {
        if (publicKey.length != 32 || signature.length != 65) return false;
        address expected = address(uint160(uint256(bytes32(publicKey[0:32]))));
        if (expected == address(0)) return false;
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        return err == ECDSA.RecoverError.NoError && recovered == expected;
    }
}

/**
 * @notice A policy plane that wants to enforce a CUMULATIVE (rolling) limit.
 *
 * It cannot, through a `view` interface: the kernel reaches it by STATICCALL, so
 * `spent` can never be written. Used by M-K37.
 */
contract StatefulPolicy is IKernelPolicy {
    uint256 public immutable limit;
    uint256 public spent;

    constructor(uint256 limit_) {
        limit = limit_;
    }

    /// @dev NOW it can persist what it admitted — the point of finding F.
    function admit(address, address, uint256 amount) external returns (bool) {
        if (spent + amount > limit) return false;
        spent += amount;
        return true;
    }
}
