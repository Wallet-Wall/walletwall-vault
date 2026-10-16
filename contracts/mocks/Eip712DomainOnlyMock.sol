// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title Eip712DomainOnlyMock
 * @notice TEST ONLY. Reports a WalletWall consumer's EIP-712 domain name but has no pqVerifier, so the SP1-TD2
 *         rotation tooling can be shown to refuse an impostor rather than crash on it.
 */
contract Eip712DomainOnlyMock is EIP712 {
    constructor(string memory name) EIP712(name, "1") {}
}
