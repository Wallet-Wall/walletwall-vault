#!/bin/sh
# scripts/deploy-entrypoint.sh
#
# One-shot Sepolia deployment script that runs inside the Docker container.
# Validates required environment variables, runs the Hardhat deploy script,
# then prints the summary of deployed contract addresses.
#
# Usage (via docker compose):
#   docker compose --profile deploy run --rm vault-deploy
#
# Usage (via docker run directly):
#   docker run --rm \
#     -e DEPLOYER_PRIVATE_KEY=0x... \
#     -e SEPOLIA_RPC_URL=https://... \
#     walletwall-vault:latest \
#     /bin/sh /app/scripts/deploy-entrypoint.sh
#
# WARNING: TESTNET ONLY. Use test ETH only. Never use a key with real funds.
# This script will refuse to run if DEPLOYER_PRIVATE_KEY is not set.
#
set -e

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

echo ""
echo "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
echo "${YELLOW}║        WalletWall Vault — Sepolia Deployment Runner       ║${NC}"
echo "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "${RED}⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / SEPOLIA ONLY${NC}"
echo "${RED}   The PQ verifier deployed is a MOCK (no real ML-DSA verification)${NC}"
echo "${RED}   Use test ETH only. Never use a key that controls real funds.${NC}"
echo ""

# ── Environment validation ──────────────────────────────────────────────────
if [ -z "${DEPLOYER_PRIVATE_KEY}" ]; then
  echo "${RED}ERROR: DEPLOYER_PRIVATE_KEY is not set.${NC}"
  echo ""
  echo "Set it in your .env file or pass it via docker run -e:"
  echo "  docker compose --profile deploy run \\"
  echo "    -e DEPLOYER_PRIVATE_KEY=0x<your-sepolia-test-key> \\"
  echo "    --rm vault-deploy"
  echo ""
  echo "Get free Sepolia ETH from: https://sepoliafaucet.com"
  exit 1
fi

# Validate the key looks like a hex private key (64 hex chars, optionally 0x-prefixed).
# Strip the optional 0x prefix, then strip ALL whitespace / carriage returns
# (guards against CRLF .env files or accidental trailing spaces).
KEY_CLEAN=$(printf '%s' "${DEPLOYER_PRIVATE_KEY}" | sed 's/^0[xX]//' | tr -d '[:space:]')
KEY_LEN=$(printf '%s' "${KEY_CLEAN}" | wc -c | tr -d '[:space:]')
if [ "${KEY_LEN}" -ne 64 ]; then
  echo "${RED}ERROR: DEPLOYER_PRIVATE_KEY does not look like a 32-byte hex key.${NC}"
  echo "       Expected 64 hex characters (with or without 0x prefix)."
  echo "       Got ${KEY_LEN} characters after stripping prefix and whitespace."
  echo ""
  echo "       Common causes:"
  echo "         • Key was copied with leading/trailing spaces"
  echo "         • Key is truncated (check your wallet's export / private key section)"
  echo "         • Key has a Windows line ending (CRLF) in the .env file"
  echo "         • Leading zero bytes were dropped by your wallet UI"
  echo ""
  echo "       A valid Ethereum private key is exactly 32 bytes = 64 hex characters."
  echo "       Example format:  0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  echo "       Check length on the Droplet with:"
  echo "         grep DEPLOYER_PRIVATE_KEY /opt/walletwall-vault/.env | cut -d= -f2 | tr -d '[:space:]' | sed 's/^0[xX]//' | wc -c"
  exit 1
fi

SEPOLIA_RPC="${SEPOLIA_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
echo "${GREEN}✓ DEPLOYER_PRIVATE_KEY is set (not echoed for security)${NC}"
echo "${GREEN}✓ SEPOLIA_RPC_URL: ${SEPOLIA_RPC}${NC}"

if [ -n "${PQC_VERIFIER_ADDRESS}" ]; then
  echo "${GREEN}✓ PQC_VERIFIER_ADDRESS set — will reuse existing verifier: ${PQC_VERIFIER_ADDRESS}${NC}"
else
  echo "${YELLOW}  PQC_VERIFIER_ADDRESS not set — will deploy a new MockMLDSAVerifier${NC}"
fi

echo ""
echo "─────────────────────────────────────────────────────────"
echo "Network: sepolia (chain ID 11155111)"
echo "─────────────────────────────────────────────────────────"
echo ""

# ── Run deployment ──────────────────────────────────────────────────────────
npm run deploy:sepolia

echo ""
echo "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo "${GREEN}  Deployment complete.                                       ${NC}"
echo "${GREEN}  Verify contracts at: https://sepolia.etherscan.io         ${NC}"
echo "${GREEN}  Update deployments/sepolia/ with the addresses above.     ${NC}"
echo "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
