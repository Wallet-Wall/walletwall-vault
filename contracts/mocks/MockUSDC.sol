// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockUSDC
 * @notice Test token for the WalletWall Stablecoin Vault Simulator.
 *
 * @dev  =======================================================================
 *       TESTNET / LOCAL DEMO ONLY. NOT AUDITED. NO MONETARY VALUE.
 *       This token is freely mintable by anyone. It has no value and is
 *       used exclusively to rehearse stablecoin vault interactions on test
 *       networks and local Hardhat/Anvil environments.
 *       DO NOT use real USDC or any real-value token with the simulator.
 *       =======================================================================
 *
 *       Plain OpenZeppelin ERC-20 with 6 decimals (matching real USDC).
 *       No pause, no blocklist, no fee-on-transfer, no rebasing.
 *       Fee-on-transfer and rebasing tokens are explicitly unsupported by
 *       the vault's accounting; do not attempt to use them.
 *
 *       Per-call mint cap of 1 000 000 mUSDC (1e12 base units) keeps test
 *       balances sane while still allowing generous testing.
 */
contract MockUSDC is ERC20 {
    /// @notice Maximum tokens that can be minted in a single faucet / mint call.
    uint256 public constant MAX_MINT_PER_CALL = 1_000_000 * 1e6; // 1 000 000 mUSDC

    error MintExceedsPerCallCap(uint256 requested, uint256 cap);

    constructor() ERC20("WalletWall Mock USD", "mUSDC") {}

    /// @notice Returns 6, matching real USDC.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /**
     * @notice Mints `amount` tokens to `to`.
     * @dev Permissionless faucet — any address can call this. Capped at
     *      {MAX_MINT_PER_CALL} per call to keep testnet balances sane.
     *      There is no per-account or global supply cap: this is a test token.
     */
    function mint(address to, uint256 amount) external {
        if (amount > MAX_MINT_PER_CALL) revert MintExceedsPerCallCap(amount, MAX_MINT_PER_CALL);
        _mint(to, amount);
    }

    /**
     * @notice Mints 1 000 mUSDC to the caller.
     * @dev Convenience faucet for quick testnet use.
     */
    function faucet() external {
        _mint(msg.sender, 1_000 * 1e6);
    }
}
