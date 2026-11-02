// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * EXPERIMENTAL PROTOTYPE TEST FIXTURES — NOT PRODUCTION, NOT DEPLOYED.
 *
 * The adversarial ERC-20 zoo and the three settlement MODELS the ERC-20 spend-plane
 * measurement runs it against. Every contract here is a test adversary or a control:
 * none is measured, none is an admitted asset of anything real, and none models native
 * Base USDC beyond the vanilla ERC-20 surface the kernel consumes (`transfer`,
 * `balanceOf`). Every setter is deliberately permissionless, because a fixture's
 * authority model is the TEST's, not the contract's.
 */

// =============================================================================
// The vanilla asset
// =============================================================================

/**
 * @notice The vanilla ERC-20 the measurement admits. `transfer` returns true and moves
 *         exactly `amount`. An issuer-style blocklist makes `transfer` REVERT for a
 *         flagged sender or recipient — the only way a vanilla asset refuses a spend,
 *         and the behaviour the custody adjudication's "issuer controls are external"
 *         paragraph (section 7.1) describes.
 */
contract VanillaToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public blocklisted;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @dev The ISSUER's lever, modelled permissionlessly for the tests.
    function setBlocklisted(address account, bool flag) external {
        blocklisted[account] = flag;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (blocklisted[msg.sender] || blocklisted[to]) revert("Blocklistable: account is blocklisted");
        uint256 from = balanceOf[msg.sender];
        if (from < amount) revert("ERC20: transfer amount exceeds balance");
        balanceOf[msg.sender] = from - amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

// =============================================================================
// The adversaries — each one misreports settlement in exactly one way
// =============================================================================

/// @notice Returns FALSE and moves nothing (the egress suite's `SilentlyFailingToken`, kept here for the plane).
contract FalseReturningToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/// @notice LIES: returns TRUE and moves nothing. The adversary observed-balance settlement exists for.
contract LyingToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

/// @notice Settles HALF of what was asked and reports success — a partial settlement dressed as a full one.
contract ShortPayToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 moved = amount / 2;
        balanceOf[msg.sender] -= moved;
        balanceOf[to] += moved;
        return true;
    }
}

/// @notice Fee-on-transfer, SENDER leg: the sender is debited `amount + fee`, the recipient receives `amount`.
///         An over-debit the sender CAN observe.
contract SenderFeeToken {
    uint256 public constant FEE_BPS = 100;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        balanceOf[msg.sender] -= amount + fee;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Fee-on-transfer, RECIPIENT leg: the sender is debited exactly `amount`, the recipient receives
///         `amount - fee`. The sender's balance tells the truth about the sender; it cannot see the recipient's leg.
contract RecipientFeeToken {
    uint256 public constant FEE_BPS = 100;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        return true;
    }
}

/**
 * @notice Rebasing-like balance mutation. Balances are `shares * index / 1e18`. `rebase` moves EVERY balance
 *         with no transfer at all; `armRebaseOnTransfer` moves the index INSIDE the next `transfer`, so the
 *         sender's observed decrease is not the amount it asked to move. With the index at 1e18 the token is
 *         vanilla; at any other index `transfer` rounds shares down and settles dust short of `amount`.
 */
contract RebasingToken {
    uint256 private constant ONE = 1e18;
    mapping(address => uint256) public shares;
    uint256 public index = ONE;
    bool public rebaseOnTransfer;
    uint256 public pendingIndex;

    function mint(address to, uint256 amount) external {
        shares[to] += (amount * ONE) / index;
    }

    function balanceOf(address account) external view returns (uint256) {
        return (shares[account] * index) / ONE;
    }

    function rebase(uint256 newIndex) external {
        index = newIndex;
    }

    function armRebaseOnTransfer(uint256 newIndex) external {
        rebaseOnTransfer = true;
        pendingIndex = newIndex;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 s = (amount * ONE) / index;
        shares[msg.sender] -= s;
        shares[to] += s;
        if (rebaseOnTransfer) {
            index = pendingIndex;
            rebaseOnTransfer = false;
        }
        return true;
    }
}

/**
 * @notice A token with a transfer HOOK (ERC-777-shaped adversary): during `transfer` it calls a stored payload
 *         on a stored target exactly once, records whether that call succeeded, and then transfers honestly.
 *         It is how a malicious or merely hook-bearing admitted asset would try to re-enter the kernel.
 */
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    address public target;
    bytes public payload;
    bool public armed;
    bool public reentered;
    bool public reentrySucceeded;
    bytes public reentryReturn;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function arm(address target_, bytes calldata payload_) external {
        target = target_;
        payload = payload_;
        armed = true;
        reentered = false;
        reentrySucceeded = false;
        delete reentryReturn;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (armed && !reentered) {
            reentered = true;
            (bool ok, bytes memory ret) = target.call(payload);
            reentrySucceeded = ok;
            reentryReturn = ret;
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Returns NOTHING from `transfer` (the pre-ERC-20-final shape some live tokens still have). Moves
///         exactly `amount`. Not an adversary: the control for "the rule does not depend on the boolean".
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}

/**
 * @notice An issuer-governed proxy: the asset's ADDRESS never changes while its BEHAVIOUR is whatever
 *         `implementation` currently points at. The admitted asset of any real deployment would be exactly this
 *         shape — an upgradeable proxy under its issuer — so the kernel pins an ADDRESS and can pin nothing about
 *         the code behind it. The implementation slot is EIP-1967-style (a fixed hashed slot) so it never collides
 *         with the token logic's own storage; `setImplementation` is the issuer's lever, modelled permissionlessly.
 */
contract SwappableTokenProxy {
    bytes32 private constant IMPLEMENTATION_SLOT = bytes32(
        uint256(keccak256("erc20-spend-plane.swappable-token-proxy.implementation")) - 1
    );

    constructor(address implementation_) {
        _setImplementation(implementation_);
    }

    function setImplementation(address implementation_) external {
        _setImplementation(implementation_);
    }

    function implementation() external view returns (address) {
        return _implementation();
    }

    function _implementation() private view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly ("memory-safe") {
            impl := sload(slot)
        }
    }

    function _setImplementation(address impl) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly ("memory-safe") {
            sstore(slot, impl)
        }
    }

    fallback() external payable {
        address impl = _implementation();
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

    receive() external payable {}
}

// =============================================================================
// The three settlement MODELS — accounting rules only, deliberately WITHOUT any
// authorization, so a test can run one adversary against all three rules and read
// off which rule refuses it. The kernel implements model C; a test asserts that.
// =============================================================================

/**
 * @notice MODEL A — the INTERNAL LEDGER: `recordedBalance -= amount; token.transfer(...)`. The shape the custody
 *         adjudication rejected for real value (one address, one number next to the token's number). Present only
 *         to be measured against. The ledger learns of value through `credit` alone; a plain token `transfer` to
 *         this contract is invisible to it.
 */
contract LedgerSettlementModel {
    uint256 public recordedBalance;

    event Settled(address indexed token, address indexed to, uint256 amount);

    /// @dev The deposit path — the ONLY writer of the ledger.
    function credit(uint256 amount) external {
        recordedBalance += amount;
    }

    function spend(address token, address to, uint256 amount) external {
        if (recordedBalance < amount) revert("ledger: insufficient recorded balance");
        recordedBalance -= amount;
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert("ledger: transfer failed");
        emit Settled(token, to, amount);
    }
}

/**
 * @notice MODEL B — DIRECT TOKEN BALANCE with RETURN-VALUE TRUST (the SafeERC20 rule): spendability is
 *         `balanceOf(this)`, and settlement is whatever the token's boolean says.
 */
contract ReturnValueSettlementModel {
    event Settled(address indexed token, address indexed to, uint256 amount);

    function spend(address token, address to, uint256 amount) external {
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert("return-value: transfer failed");
        emit Settled(token, to, amount);
    }
}

/**
 * @notice MODEL C — OBSERVED-BALANCE SETTLEMENT, the kernel's rule verbatim: the sender's balance must decrease
 *         by EXACTLY `amount`, whatever the call returned.
 */
contract ObservedDeltaSettlementModel {
    event Settled(address indexed token, address indexed to, uint256 amount);

    function spend(address token, address to, uint256 amount) external {
        uint256 before = _balanceOf(token);
        (bool ok, ) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!ok) revert("observed: call failed");
        uint256 remaining = _balanceOf(token);
        if (remaining > before || before - remaining != amount) revert("observed: delta mismatch");
        emit Settled(token, to, amount);
    }

    function _balanceOf(address asset) internal view returns (uint256) {
        (bool ok, bytes memory data) = asset.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || data.length < 32) return 0;
        return abi.decode(data, (uint256));
    }
}
