# Deployment Records

> Research prototype. Not audited. Testnet only. Do not use real funds.

This file records public test deployments for integration and bytecode comparison. It
does not represent a production deployment, mainnet availability, an audit, or
production-grade post-quantum verification.

## Ethereum Sepolia - active testnet

Status: **active testnet**

| Field | Value |
| --- | --- |
| Network | Ethereum Sepolia |
| Chain ID | `11155111` |
| `WalletWallVault` | [`0x210ceD9C12AF27b10B06eB5506b24a51E11506E9`](https://sepolia.etherscan.io/address/0x210ceD9C12AF27b10B06eB5506b24a51E11506E9) |
| PQ verifier | [`0x832E223c6D889A96bCFF434a609e8a5782C706e9`](https://sepolia.etherscan.io/address/0x832E223c6D889A96bCFF434a609e8a5782C706e9) |
| Deployment transaction | [`0x8f15e6c99ee4ac789836716c75d26a8dc8df240dad731cbc8a7c9515e91cc3e1`](https://sepolia.etherscan.io/tx/0x8f15e6c99ee4ac789836716c75d26a8dc8df240dad731cbc8a7c9515e91cc3e1) |
| Reported source commit | `828bf219c0e2612fcd1aba5f085c4abeba29de88` |
| Live Sepolia runtime observed | `20,508` bytes |
| Current public HEAD runtime | `22,138` bytes |
| Reproducibility status | **Pending public artifact/source alignment** |
| Last independently re-checked | 2026-06-15 |

Read-only Sepolia RPC checks confirmed that the deployment transaction succeeded, the
transaction created the listed vault, the observed live runtime is `20,508` bytes, and
`WalletWallVault.pqVerifier()` returns the listed verifier address. These checks confirm
the live deployment record; they do not establish source-level reproducibility.

The verifier reports `keccak256("MOCK-ML-DSA-65")`. It is
`MockMLDSAVerifier`, which performs structural checks only and provides **no real
ML-DSA verification**. This deployment is suitable only for testnet integration,
contract-flow testing, and frontend testing with Sepolia test ETH.

### Deployment provenance

This is a valid, live, and tested Sepolia deployment. However, the reported source
commit `828bf219c0e2612fcd1aba5f085c4abeba29de88` is absent from the public repository
history, and the current public HEAD recompiles `WalletWallVault` to a `22,138`-byte
runtime rather than the observed `20,508`-byte deployed runtime.

The public repository therefore does **not** currently provide a clean third-party
reproduction path for this exact deployment. Reproducibility remains pending an aligned
public source tag and artifact manifest.

**Follow-up TODO:** publish the exact deployment source commit/tag and artifact manifest,
or redeploy from public HEAD and update this deployment record with the replacement
address, transaction, source tag, and runtime.

## StablecoinVaultSimulator — not yet deployed to testnet

The `StablecoinVaultSimulator` and `MockUSDC` contracts introduced in v0.4.22 have
**not yet been deployed** to Sepolia or Base Sepolia. This section will be updated with
deployment addresses, transaction hashes, and bytecode sizes once a testnet deployment
is performed.

**Local usage** (no deployment record needed):

```sh
# Start local node
npx hardhat node          # or: anvil

# Run demo in a second terminal
npm run demo:simulator    # deploys MockUSDC + MockMLDSAVerifier + StablecoinVaultSimulator
                          # then exercises faucet, approve+deposit, withdraw
```

**Testnet deployment (when ready)**:

```sh
# Requires DEPLOYER_PRIVATE_KEY + SEPOLIA_RPC_URL in .env
npx hardhat run scripts/demo-simulator.ts --network sepolia
```

**Limitations to record when this section is filled:**

- MockUSDC is freely mintable — no value, no purchase path.
- PQ gate uses `MockMLDSAVerifier` locally or `AttestationPQCVerifier` (trusted-attestor path)
  on testnet — ML-DSA is **not verified on-chain**.
- Simulator is a research prototype; it is not audited and makes no production claims.
- Fee-on-transfer / rebasing tokens are explicitly unsupported by the vault accounting.
- No mainnet deployment exists or is planned for this contract.

## Deprecated Ethereum Sepolia deployment

The older Sepolia deployment commonly referenced as `0x8c5B...CF24` (and sometimes
mistyped as `0x8cB5...`) is **deprecated and stale. Do not reuse it.**

Reasons:

- its historical runtime did not match the current `WalletWallVault` artifact; and
- the old vault was created with a 32-byte PQ key instead of an ML-DSA-65 public key.

It must not be used as a frontend default, deployment fallback, verification target, or
source of assumptions about the current contract state.

## Testnet usage

- Use Sepolia test ETH only.
- Do not send real funds.
- Frontend writes must remain testnet-only and explicitly gated to supported chain IDs.
- This repository documents no Ethereum mainnet deployment.
- No native ML-DSA/PQ precompile is live or used by these deployments.
