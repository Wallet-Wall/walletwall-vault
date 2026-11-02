// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * EXPERIMENTAL PROTOTYPE TEST FIXTURES — NOT PRODUCTION, NOT DEPLOYED, NOT MEASURED.
 *
 * The adversaries the Generation-2 ADMISSION suites and the stateful campaign drive. None models a
 * real token and no real address appears anywhere in this tree. Every lever is permissionless,
 * because a fixture's authority model is the TEST's, not the contract's.
 */

/**
 * @notice ONE admitted asset whose behaviour the campaign can move mid-history, the shape an
 *         issuer-upgradeable token has: the ADDRESS never changes while the BEHAVIOUR does.
 *
 * @dev `realBalanceOf` and `sink` are the campaign's GROUND TRUTH and are NOT what the kernel reads.
 *      The kernel reads `balanceOf`, and in the two lying modes the two disagree on purpose: that
 *      gap is exactly what separates what a kernel can observe from what an asset must guarantee.
 */
contract Gen2ZooToken {
    enum Mode {
        VANILLA,
        RETURN_FALSE_NO_MOVE,
        RETURN_TRUE_NO_MOVE,
        SHORT_PAY,
        SENDER_FEE,
        RECIPIENT_FEE,
        DUST_SHORT,
        REVERTS,
        NO_RETURN,
        RETURN_FALSE_BUT_MOVES,
        QUERY_REVERTS_AFTER_TRANSFER,
        QUERY_SHORT_AFTER_TRANSFER,
        QUERY_LIES_EXACT_DEBIT
    }

    uint256 private constant FEE_BPS = 100;

    /// @dev The ledger. `balanceOf` reports this except in the query-adversary modes.
    mapping(address => uint256) public realBalanceOf;
    mapping(address => bool) public blocklisted;
    uint256 public totalSupply;
    /// @dev Where fees go, so conservation stays checkable: supply = sum of balances + sink.
    uint256 public sink;
    Mode public mode;
    /// @dev Set inside `transfer` by the query-adversary modes; `resetQuery` clears it.
    bool public queryPoisoned;
    /// @dev The balance `balanceOf` reports for `liedAccount` under QUERY_LIES_EXACT_DEBIT.
    address public liedAccount;
    uint256 public liedBalance;

    // ---- the hook: a stored call the token makes during the next `transfer`, at most once ----
    address public hookTarget;
    bytes public hookPayload;
    bool public hookArmed;
    bool public hookAfterDebit;
    bool public hookFired;
    bool public hookSucceeded;
    bytes public hookReturn;

    /// @dev Transfers observed, so an oracle can count them without trusting the kernel.
    uint256 public transferCalls;
    address public lastRecipient;
    uint256 public lastAmount;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        realBalanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function setMode(Mode m) external {
        mode = m;
        queryPoisoned = false;
    }

    function setBlocklisted(address account, bool flag) external {
        blocklisted[account] = flag;
    }

    function armHook(address target, bytes calldata payload, bool afterDebit) external {
        hookTarget = target;
        hookPayload = payload;
        hookArmed = true;
        hookAfterDebit = afterDebit;
        hookFired = false;
        hookSucceeded = false;
        delete hookReturn;
    }

    function disarmHook() external {
        hookArmed = false;
    }

    /// @dev A balance move with NO transfer at all: the rebase a vault never sees.
    function rebaseAccount(address account, uint256 newBalance) external {
        if (newBalance >= realBalanceOf[account]) {
            uint256 added = newBalance - realBalanceOf[account];
            totalSupply += added;
        } else {
            uint256 removed = realBalanceOf[account] - newBalance;
            totalSupply -= removed;
        }
        realBalanceOf[account] = newBalance;
    }

    /// @dev Reports what the mode dictates. A STATICCALL cannot move `queryPoisoned`, so the poison
    ///      is set by `transfer` and read here.
    function balanceOf(address account) external view returns (uint256) {
        if (queryPoisoned && mode == Mode.QUERY_REVERTS_AFTER_TRANSFER) revert("balance query down");
        if (queryPoisoned && mode == Mode.QUERY_SHORT_AFTER_TRANSFER) {
            assembly ("memory-safe") {
                mstore(0x00, 0)
                return(0x00, 0x01)
            }
        }
        if (queryPoisoned && mode == Mode.QUERY_LIES_EXACT_DEBIT && account == liedAccount) return liedBalance;
        return realBalanceOf[account];
    }

    function _fireHook() private {
        if (!hookArmed || hookFired) return;
        hookFired = true;
        (bool ok, bytes memory ret) = hookTarget.call(hookPayload);
        hookSucceeded = ok;
        hookReturn = ret;
    }

    function _move(address from, address to, uint256 debit, uint256 credit) private {
        uint256 have = realBalanceOf[from];
        if (have < debit) revert("ERC20: transfer amount exceeds balance");
        realBalanceOf[from] = have - debit;
        realBalanceOf[to] += credit;
        if (debit > credit) sink += debit - credit;
        emit Transfer(from, to, credit);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        transferCalls += 1;
        lastRecipient = to;
        lastAmount = amount;
        if (blocklisted[msg.sender] || blocklisted[to]) revert("Blocklistable: account is blocklisted");
        Mode m = mode;
        if (m == Mode.REVERTS) revert("token down");
        if (!hookAfterDebit) _fireHook();

        bool result = true;
        if (m == Mode.RETURN_FALSE_NO_MOVE) {
            result = false;
        } else if (m == Mode.RETURN_TRUE_NO_MOVE) {
            // moves nothing and says it did
        } else if (m == Mode.SHORT_PAY) {
            _move(msg.sender, to, amount / 2, amount / 2);
        } else if (m == Mode.SENDER_FEE) {
            uint256 fee = (amount * FEE_BPS) / 10_000;
            _move(msg.sender, to, amount + fee, amount);
        } else if (m == Mode.RECIPIENT_FEE) {
            uint256 fee = (amount * FEE_BPS) / 10_000;
            _move(msg.sender, to, amount, amount - fee);
        } else if (m == Mode.DUST_SHORT) {
            uint256 moved = amount == 0 ? 0 : amount - 1;
            _move(msg.sender, to, moved, moved);
        } else if (m == Mode.QUERY_REVERTS_AFTER_TRANSFER || m == Mode.QUERY_SHORT_AFTER_TRANSFER) {
            // moves nothing and then refuses to be asked about it
            queryPoisoned = true;
        } else if (m == Mode.QUERY_LIES_EXACT_DEBIT) {
            // moves nothing and then reports exactly the decrease the sender wanted to see
            queryPoisoned = true;
            liedAccount = msg.sender;
            liedBalance = realBalanceOf[msg.sender] - amount;
        } else {
            _move(msg.sender, to, amount, amount);
            if (m == Mode.RETURN_FALSE_BUT_MOVES) result = false;
        }

        if (hookAfterDebit) _fireHook();
        if (m == Mode.NO_RETURN) {
            assembly ("memory-safe") {
                return(0x00, 0x00)
            }
        }
        return result;
    }
}

/**
 * @notice A second, non-admitted holding: an unsolicited token anybody can send to a vault. Its
 *         `hostile` switch is a token that refuses to leave: reverts on transfer, returns a huge blob
 *         on balanceOf when asked to, the I-MIGRATION-NONTRAP clause (a) adversary.
 */
contract Gen2UnsolicitedToken {
    enum Hostility {
        NONE,
        REVERTS_ON_TRANSFER,
        RETURN_BOMB_ON_BALANCE
    }

    mapping(address => uint256) public realBalanceOf;
    Hostility public hostility;

    function setHostility(Hostility h) external {
        hostility = h;
    }

    function mint(address to, uint256 amount) external {
        realBalanceOf[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        if (hostility == Hostility.RETURN_BOMB_ON_BALANCE) {
            assembly ("memory-safe") {
                return(0x00, 100000)
            }
        }
        return realBalanceOf[account];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (hostility == Hostility.REVERTS_ON_TRANSFER) revert("hostile");
        realBalanceOf[msg.sender] -= amount;
        realBalanceOf[to] += amount;
        return true;
    }
}

/**
 * @notice A token with the signature-authorised debit paths real stablecoins carry: `permit` and a
 *         signature-authorised transfer, each accepting ERC-1271 for a contract owner. It exists to
 *         answer one question by execution: can such a path debit a Generation-2 vault, whose kernel
 *         has no `approve` call and no `isValidSignature`?
 */
contract Gen2SignatureDebitToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function _accepts(address owner, bytes32 digest, bytes calldata signature) private view returns (bool) {
        if (owner.code.length == 0) return false;
        (bool ok, bytes memory ret) = owner.staticcall(
            abi.encodeWithSelector(0x1626ba7e, digest, signature)
        );
        return ok && ret.length == 32 && bytes4(ret) == bytes4(0x1626ba7e);
    }

    /// @dev The ERC-2612 shape with the ERC-1271 branch only: an EOA is not what is under test here.
    function permit(address owner, address spender, uint256 value, bytes32 digest, bytes calldata signature) external {
        if (!_accepts(owner, digest, signature)) revert("permit: invalid signature");
        allowance[owner][spender] = value;
    }

    /// @dev The ERC-3009 shape, ERC-1271 branch only.
    function transferWithAuthorization(address from, address to, uint256 value, bytes32 digest, bytes calldata signature) external {
        if (!_accepts(from, digest, signature)) revert("authorization: invalid signature");
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
}

/// @notice A plain ERC-721-shaped holding: `balanceOf` answers, and there is no `transfer(address,uint256)`.
contract Gen2NonFungibleHolding {
    mapping(address => uint256) public balanceOf;

    function mintTo(address to) external {
        balanceOf[to] += 1;
    }
}

/**
 * @notice A subtractive policy plane that also tries to REACH THE ASSET from inside `admit`: it records
 *         whether a stored call succeeded and answers as told. Its only route to the vault's money would
 *         be through the vault, so the call is either refused or authorised on its own merits.
 */
contract Gen2ProbingPolicy {
    address public target;
    bytes public payload;
    bool public answer = true;
    bool public fired;
    bool public succeeded;

    function arm(address target_, bytes calldata payload_, bool answer_) external {
        target = target_;
        payload = payload_;
        answer = answer_;
        fired = false;
        succeeded = false;
    }

    function admit(address, address, uint256) external returns (bool) {
        if (target != address(0)) {
            fired = true;
            (succeeded, ) = target.call(payload);
        }
        return answer;
    }
}

/// @notice A destination that can lose its code: since EIP-6780 only within the transaction that created it.
contract Gen2EphemeralDestination {
    receive() external payable {}

    function destroy(address payable to) external {
        selfdestruct(to);
    }
}

/**
 * @notice Creates a destination, has the vault bind to it and destroys it, all in one transaction, which is the
 *         one way left for bound code to vanish. `redeploy` brings the same code back at the same address.
 */
contract Gen2BindThenDestroy {
    function run(bytes32 salt, address vault, bytes calldata bindCall) external returns (address destination) {
        destination = address(new Gen2EphemeralDestination{salt: salt}());
        (bool ok, bytes memory ret) = vault.call(bindCall);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        Gen2EphemeralDestination(payable(destination)).destroy(payable(address(this)));
    }

    function redeploy(bytes32 salt) external returns (address) {
        return address(new Gen2EphemeralDestination{salt: salt}());
    }

    receive() external payable {}
}

/// @notice Binds and egresses in one transaction, so both revert together. Possible only where egress has no delay.
contract Gen2AtomicMigrator {
    function run(address vault, bytes calldata bindCall, bytes calldata egressCall) external {
        _call(vault, bindCall);
        _call(vault, egressCall);
    }

    function _call(address target, bytes calldata data) private {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

/// @notice A bound destination whose behaviour a campaign can move: it keeps value, hands it back, or refuses it.
contract Gen2SwitchableDestination {
    enum Mode {
        ACCEPT,
        BOUNCE_ALL,
        BOUNCE_HALF,
        REFUSE
    }

    Mode public mode;

    function setMode(Mode m) external {
        mode = m;
    }

    receive() external payable {
        if (mode == Mode.REFUSE) revert("refused");
        uint256 back = mode == Mode.BOUNCE_ALL ? msg.value : mode == Mode.BOUNCE_HALF ? msg.value / 2 : 0;
        if (back != 0) {
            (bool ok, ) = msg.sender.call{value: back}("");
            require(ok, "no way back");
        }
    }
}

/// @notice Answers with the ERC-1271 magic value in its first four bytes and something else in the rest of the word.
contract Gen2DirtyMagicGuardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes32) {
        return bytes32((uint256(0x1626ba7e) << 224) | 1);
    }
}
