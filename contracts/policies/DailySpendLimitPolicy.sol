// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPolicyEngine.sol";

/// @title DailySpendLimitPolicy
/// @notice Caps total ETH withdrawn from a vault within any rolling 24-hour window.
/// @dev Each vault owner sets their own limit via setDailyLimit(). Spending is
///      recorded at check() time — for large-tx withdrawals this is at queue time,
///      not finalize time, which is intentional and conservative. If the outer
///      transaction reverts after check() (e.g. TransferFailed), all state
///      including the spend record is rolled back automatically.
///
///      A limit of 0 means unrestricted (default). Set a non-zero limit to enable.
contract DailySpendLimitPolicy is IPolicyEngine {
    uint256 public constant WINDOW = 24 hours;

    /// @notice Per-vault daily spend limit in wei. 0 = unrestricted.
    mapping(address => uint256) public dailyLimit;

    mapping(address => uint256) private _windowStart;
    mapping(address => uint256) private _windowSpent;

    event DailyLimitSet(address indexed vaultOwner, uint256 limit);

    /// @notice Sets the caller's daily spend limit.
    /// @param limit Max ETH (wei) withdrawable within a 24h window. 0 = unrestricted.
    function setDailyLimit(uint256 limit) external {
        dailyLimit[msg.sender] = limit;
        emit DailyLimitSet(msg.sender, limit);
    }

    /// @inheritdoc IPolicyEngine
    function check(
        address vaultOwner,
        address,
        uint256 amount,
        uint256
    ) external override returns (bool allowed, string memory reason) {
        uint256 limit = dailyLimit[vaultOwner];
        if (limit == 0) return (true, "");

        uint256 start = _windowStart[vaultOwner];
        uint256 spent = _windowSpent[vaultOwner];

        if (block.timestamp >= start + WINDOW) {
            start = block.timestamp;
            spent = 0;
        }

        if (spent + amount > limit) {
            return (false, "daily limit exceeded");
        }

        _windowStart[vaultOwner] = start;
        _windowSpent[vaultOwner] = spent + amount;

        return (true, "");
    }

    /// @notice Remaining spend allowance in the current 24h window.
    /// @return type(uint256).max when the vault has no limit set.
    function remainingAllowance(address vaultOwner) external view returns (uint256) {
        uint256 limit = dailyLimit[vaultOwner];
        if (limit == 0) return type(uint256).max;

        if (block.timestamp >= _windowStart[vaultOwner] + WINDOW) {
            return limit;
        }

        uint256 spent = _windowSpent[vaultOwner];
        return spent >= limit ? 0 : limit - spent;
    }
}
