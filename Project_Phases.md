# WalletWall Vault

> ⚠️ **Pre-implementation design / vision document.**
>
> This file describes aspirational phases and a long-term vision. Not all features
> described here are implemented. It is retained for context but is **not the source of
> truth for current architecture, APIs, or security properties.**
>
> For the current implementation see:
> - **[README.md](README.md)** — current API, components, and signing flow
> - **[docs/Security_Assumptions.md](docs/Security_Assumptions.md)** — trust model
> - **[docs/Verifier_Roadmap.md](docs/Verifier_Roadmap.md)** — verifier phases
>
> **Naming note:** Where this document uses the older names CRYSTALS-Dilithium or
> Dilithium, the NIST-standardized name is **ML-DSA / FIPS 204**. Where it uses
> SPHINCS+, the standardized name is **SLH-DSA / FIPS 205**. Falcon is a separate
> NIST-selected algorithm (FIPS 206) not currently targeted by this prototype.

> A hybrid cryptographic vault for digital assets that combines traditional blockchain signatures with post-quantum cryptography (PQC) to provide a migration path toward a quantum-safe future.

---

# Overview

WalletWall Vault is a smart contract platform designed to protect digital assets against both current and future threats by requiring a combination of:

* Classical cryptographic signatures (ECDSA/secp256k1)
* Post-Quantum Cryptographic (PQC) signatures
* Configurable security policies
* Time-delayed recovery mechanisms
* On-chain auditability

The goal is to address a growing concern in blockchain security:

> Current blockchain wallets rely on elliptic curve cryptography, which may become vulnerable to sufficiently powerful quantum computers.

WalletWall Vault introduces a hybrid authorization model that allows users and organizations to secure assets today while preparing for a post-quantum future.

---

# Problem Statement

Most blockchain ecosystems currently rely on:

* ECDSA (Ethereum)
* Ed25519 (Solana)
* secp256k1 (Bitcoin)

These algorithms are considered secure against classical computers but are theoretically vulnerable to quantum attacks through algorithms such as:

* Shor's Algorithm
* Quantum discrete logarithm attacks

A future quantum-capable adversary could potentially:

* Recover private keys
* Forge transactions
* Drain wallets
* Compromise treasury funds
* Attack long-lived cold storage

WalletWall Vault is designed to mitigate this risk by introducing a second independent cryptographic verification layer.

---

# Core Security Model

Traditional Wallet:

```text
User Private Key
        |
        v
ECDSA Signature
        |
        v
Smart Contract
        |
        v
Funds Released
```

WalletWall Vault:

```text
ECDSA Signature
        +
PQC Signature
        |
        v
Verification Layer
        |
        v
Vault Smart Contract
        |
        v
Funds Released
```

An attacker must compromise both systems simultaneously.

---

# Hybrid Cryptographic Architecture

## Layer 1 - Classical Signatures

WalletWall supports existing blockchain standards.

Examples:

* Ethereum ECDSA
* secp256k1
* Hardware wallets
* Multi-signature wallets

Purpose:

* Native blockchain compatibility
* User familiarity
* Ecosystem interoperability

---

## Layer 2 - Post-Quantum Signatures

WalletWall introduces a quantum-resistant signature layer.

Potential algorithms:

### CRYSTALS-Dilithium

Recommended by:

* National Institute of Standards and Technology

Properties:

* Strong security
* Efficient verification
* NIST standardized

### SPHINCS+

Properties:

* Stateless
* Conservative design
* Hash-based security

### Falcon

Properties:

* Small signatures
* Fast verification

---

# Vault Authorization Flow

## Standard Withdrawal

```text
User Creates Transaction
          |
          v
Generate ECDSA Signature
          |
          v
Generate PQC Signature
          |
          v
Submit Request
          |
          v
Contract Verification
          |
          +--> Verify ECDSA
          |
          +--> Verify PQC
          |
          v
Funds Released
```

If either verification fails:

```text
Transaction Rejected
```

---

# Vault Types

## Personal Vault

Single owner.

Requirements:

* 1 Classical Key
* 1 PQC Key

Example:

```text
Alice Wallet
    +
Alice PQC Key
```

---

## Multi-Signature Vault

Designed for teams and DAOs.

Example:

```text
3 of 5 Classical Signers
AND
2 of 3 PQC Signers
```

Benefits:

* Distributed trust
* Protection against key compromise
* Quantum resilience

---

## Treasury Vault

Designed for:

* DAOs
* Exchanges
* Enterprises
* Protocol treasuries

Features:

* Multi-stage approvals
* Delayed execution
* Recovery mechanisms
* Emergency freeze

---

# Smart Contract Components

## Vault Contract

Responsibilities:

* Asset storage
* Withdrawal processing
* Policy enforcement

Example:

```solidity
contract WalletWallVault {
}
```

---

## Signature Verification Contract

Responsibilities:

* Classical signature verification
* PQC proof validation
* Signature policy enforcement

Example:

```text
verifyECDSA()
verifyDilithium()
verifySPHINCS()
```

---

## Recovery Contract

Responsibilities:

* Emergency recovery
* Guardian approval
* Key rotation

---

# Key Registration

When a vault is created:

```text
User Registers:

ECDSA Public Key

AND

PQC Public Key
```

Stored metadata includes:

```json
{
  "classicalKey": "...",
  "pqcKey": "...",
  "algorithm": "Dilithium3"
}
```

Private keys never leave the user's device.

---

# Key Rotation

WalletWall supports periodic key replacement.

Reasons:

* Employee departure
* Device compromise
* Security upgrades
* Algorithm migration

Flow:

```text
Old Keys Verify
      |
      v
Authorize Rotation
      |
      v
Register New Keys
```

---

# Emergency Recovery

Optional recovery system.

Example:

```text
User
+
2 Guardians
+
7 Day Delay
```

Recovery process:

1. Request recovery
2. Guardian approval
3. Delay period begins
4. Assets become accessible

This protects users against:

* Lost devices
* Lost hardware wallets
* Lost PQC credentials

---

# Quantum Readiness Levels

## Level 1

Classical Only

```text
ECDSA
```

Equivalent to current wallets.

---

## Level 2

Hybrid Mode

```text
ECDSA
+
Dilithium
```

Recommended default.

---

## Level 3

Quantum Preferred

```text
Dilithium
+
SPHINCS+
```

Minimal reliance on classical cryptography.

---

## Level 4

Quantum Only

Future mode when blockchain ecosystems fully support PQC.

```text
Dilithium
OR
SPHINCS+
```

---

# Threat Model

WalletWall Vault is designed to defend against:

### Stolen Private Keys

Mitigation:

```text
Attacker needs PQC key too
```

---

### Quantum Computing Attacks

Mitigation:

```text
PQC Signature Layer
```

---

### Insider Threats

Mitigation:

```text
Multi-signature approvals
```

---

### Exchange Treasury Attacks

Mitigation:

```text
Multi-layer authorization
```

---

### Wallet Malware

Mitigation:

```text
Separate signing systems
```

---

# Supported Assets

Future support may include:

* Ethereum
* Bitcoin
* Stablecoins
* ERC-20 tokens
* ERC-721 NFTs
* ERC-1155 assets

---

# Future Roadmap

## Phase 1 (Completed)

MVP

Features:

* Ethereum support
* ECDSA verification
* Off-chain PQC verification
* Basic vault operations

---

## Phase 2 (Completed)

Advanced Security

Features:

* Multi-signature vaults
* Guardian recovery
* Key rotation
* Audit logging

---

## Phase 3

Enterprise Features

Features:

* Treasury management
* Hardware security modules
* Compliance integrations
* Policy engine

---

## Phase 4

Full Quantum Migration

Features:

* Native PQC chains
* Quantum-only vaults
* Cross-chain vault management

---

# Design Principles

WalletWall Vault is built around five core principles:

1. Security First
2. Quantum Readiness
3. Backward Compatibility
4. Decentralization
5. User-Controlled Custody

The long-term vision is to provide a practical bridge between today's blockchain infrastructure and tomorrow's quantum-secure ecosystem, allowing users to protect assets without waiting for entire blockchains to migrate away from classical cryptography.
