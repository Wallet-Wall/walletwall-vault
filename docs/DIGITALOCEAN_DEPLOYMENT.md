# Deploying walletwall-vault to DigitalOcean via Docker

> **⚠️ Testnet / Research Prototype Only**  
> These instructions deploy to **Ethereum Sepolia** (a public test network).  
> Never use real funds. Never use a wallet key that controls real ETH.  
> See [SECURITY.md](../SECURITY.md) and the root README for full disclaimers.

---

## Table of Contents

1. [What you get](#1-what-you-get)
2. [Prerequisites](#2-prerequisites)
3. [Local Docker build and test](#3-local-docker-build-and-test)
4. [DigitalOcean setup](#4-digitalocean-setup)
   - 4a. Create a Droplet
   - 4b. Connect to the Droplet
   - 4c. Install Docker on the Droplet
   - 4d. (Optional) Create a Container Registry
5. [Push the image to the Droplet](#5-push-the-image-to-the-droplet)
   - 5a. Using DOCR (Container Registry)
   - 5b. Direct `docker save` / `docker load` (simpler, no registry)
6. [Configure environment on the Droplet](#6-configure-environment-on-the-droplet)
7. [Run the Sepolia deployer](#7-run-the-sepolia-deployer)
8. [Run the persistent Hardhat node](#8-run-the-persistent-hardhat-node)
9. [Verify the deployment on Etherscan](#9-verify-the-deployment-on-etherscan)
10. [Firewall & Security](#10-firewall--security)
11. [Updating the deployment](#11-updating-the-deployment)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What you get

After completing this guide you will have:

| What | Where |
|---|---|
| A **Docker image** containing the compiled vault contracts + Hardhat CLI | Built locally, pushed to Droplet |
| A **persistent Hardhat node** on `<droplet-ip>:8545` (in-memory, for local dev use) | DigitalOcean Droplet |
| **Sepolia-deployed contracts** (MockMLDSAVerifier + WalletWallVault) | Ethereum Sepolia testnet |
| Deployment addresses written to `deployments/sepolia/` | Your local repo + Droplet |

The vault contracts run on Ethereum Sepolia — a **public testnet** — so they are
accessible to anyone with Sepolia ETH, without any ongoing hosting fee beyond the
Droplet itself (~$6/month).

---

## 2. Prerequisites

### On your local machine
- **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
  - Download: https://docs.docker.com/get-docker/
- **Git** (to clone/push the repo)

### On DigitalOcean
- A **DigitalOcean account** — https://cloud.digitalocean.com
- A **Personal Access Token (PAT)** with read/write access (only needed if using DOCR)
  - Create at: https://cloud.digitalocean.com/account/api/tokens

### On Ethereum Sepolia
- A **test wallet** private key — generate one in [Step 6a](#6a-generate-a-test-wallet) using the Docker image itself (no external tool needed)
- At least **0.05 Sepolia ETH** in that wallet for gas fees
  - Free faucets (no mainnet ETH required):
    - **https://cloud.google.com/application/web3/faucet/ethereum/sepolia** — 0.05 ETH/day, no account
    - **https://www.alchemy.com/faucets/ethereum-sepolia** — 0.5 ETH, free Alchemy account
    - **https://sepolia-faucet.pk910.de/** — PoW mining faucet, no account at all

> ⚠️ **Many faucets require you to have mainnet ETH to prevent spam.** If a faucet
> shows "Insufficient balance on Ethereum Mainnet", use the Google Cloud or PoW
> faucet above — neither requires any mainnet balance.

> **Never commit your private key.** The `.env` file is in `.gitignore` and
> `.dockerignore` — it is intentionally excluded from the image.

---

## 3. Local Docker build and test

Before pushing to DigitalOcean, verify the image builds and works locally.

```bash
# 1. Navigate to the vault directory
cd walletwall-vault

# 2. Build the image (multi-stage, ~2-5 min first time)
docker build -t walletwall-vault:latest .

# 3. Run tests inside the image to confirm compilation is correct
docker run --rm walletwall-vault:latest npm test

# 4. Start a local Hardhat node and confirm JSON-RPC responds
docker run --rm -p 8545:8545 walletwall-vault:latest &
sleep 5
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Expected: {"jsonrpc":"2.0","id":1,"result":"0x7a69"}   (31337 = Hardhat's chain ID)
```

### Using docker compose (dev mode)

> ⚠️ **Windows + Docker Desktop note:** the dev service uses named volumes to
> protect the Linux `node_modules` from being shadowed by the Windows host
> filesystem. After any `docker compose down -v`, the volumes are recreated on
> the next `up`.

```bash
# Start local keep-alive container (does NOT bind port — uses tail -f /dev/null)
docker compose up -d

# Run tests inside the container
docker compose exec walletwall-vault npm test

# Run a Hardhat JSON-RPC node inside the running container
docker compose exec walletwall-vault npx hardhat node --hostname 0.0.0.0

# Stop
docker compose down
```

---

## 4. DigitalOcean setup

### 4a. Create a Droplet

1. Log in to https://cloud.digitalocean.com
2. Click **Create → Droplets**
3. Choose these settings:

   | Setting | Recommended value |
   |---|---|
   | **Region** | Choose closest to you (e.g., NYC1, SFO3) |
   | **OS** | **Ubuntu 22.04 LTS** |
   | **Plan** | Basic — **$6/mo** (1 vCPU / 1 GB RAM) is sufficient for the Hardhat node; $12/mo (1 vCPU / 2 GB) is more comfortable |
   | **Authentication** | SSH Key (recommended) — paste your public key |
   | **Hostname** | e.g. `walletwall-vault-sepolia` |

4. Click **Create Droplet** and wait ~1 min for it to provision.
5. Note the **public IPv4 address** shown in the dashboard.

### 4b. Connect to the Droplet

```bash
# Replace <DROPLET_IP> with your Droplet's public IP
ssh root@<DROPLET_IP>
```

If you used a password instead of SSH key, DigitalOcean will email you the root
password (change it immediately with `passwd`).

### 4c. Install Docker on the Droplet

Run these commands on the Droplet:

```bash
# Update package index
apt-get update

# Install Docker
curl -fsSL https://get.docker.com | sh

# Verify Docker is running
docker --version

# Install Docker Compose plugin
apt-get install -y docker-compose-plugin

# Verify
docker compose version
```

### 4d. (Optional) Create a Container Registry

DigitalOcean Container Registry (DOCR) lets you push/pull images without copying
files manually. Skip this section if you prefer the simpler `docker save` approach
in [Step 5b](#5b-direct-docker-save--docker-load-simpler-no-registry).

1. In the DO console: **Container Registry → Create Registry**
2. Name it (e.g., `walletwall`) — free tier allows 1 private repo
3. Install the `doctl` CLI on your **local machine**:
   ```bash
   # macOS
   brew install doctl

   # Windows (winget)
   winget install DigitalOcean.doctl

   # Linux
   cd ~
   wget https://github.com/digitalocean/doctl/releases/download/v1.110.0/doctl-1.110.0-linux-amd64.tar.gz
   tar xf doctl-1.110.0-linux-amd64.tar.gz
   mv doctl /usr/local/bin
   ```
4. Authenticate:
   ```bash
   doctl auth init   # paste your PAT when prompted
   ```
5. Configure Docker to use DOCR:
   ```bash
   doctl registry login
   ```

---

## 5. Push the image to the Droplet

Choose **one** of the two methods below.

### 5a. Using DOCR (Container Registry)

> Requires completing Step 4d above.

On your **local machine**:

```bash
# Tag the image for DOCR
# Replace <registry-name> with your registry name (e.g., walletwall)
docker tag walletwall-vault:latest registry.digitalocean.com/<registry-name>/walletwall-vault:latest

# Push to DOCR
docker push registry.digitalocean.com/<registry-name>/walletwall-vault:latest
```

On the **Droplet**, authenticate and pull:

```bash
# Log in to DOCR (requires doctl installed on the Droplet too, or use the token directly)
docker login registry.digitalocean.com
# Username: your DO PAT
# Password: your DO PAT (same value)

# Pull the image
docker pull registry.digitalocean.com/<registry-name>/walletwall-vault:latest
```

### 5b. Direct `docker save` / `docker load` (simpler, no registry)

If you prefer not to set up a registry, save the image as a `.tar` file and copy
it to the Droplet with `scp`.

On your **local machine**:

```bash
# Save the image to a tar file (~800 MB)
docker save walletwall-vault:latest | gzip > walletwall-vault.tar.gz

# Copy to Droplet (replace <DROPLET_IP>)
scp walletwall-vault.tar.gz root@<DROPLET_IP>:/root/
```

On the **Droplet**:

```bash
# Load the image
docker load < /root/walletwall-vault.tar.gz

# Verify it loaded
docker images | grep walletwall-vault
```

---

## 6. Configure environment on the Droplet

On the **Droplet**, create the `.env` file. This file is **never committed to git**
and is excluded from the Docker image by `.dockerignore`.

```bash
# Create the project directory on the Droplet
mkdir -p /opt/walletwall-vault
cd /opt/walletwall-vault

# Copy the Droplet-specific compose file from your local machine.
# ⚠️  Always use docker-compose.droplet.yml on the Droplet — NOT docker-compose.yml.
#     docker-compose.yml has build: stanzas that require a Dockerfile and full source
#     tree. The droplet file uses walletwall-vault:latest directly (already loaded).
scp -i <your-ssh-key> /path/to/walletwall-vault/docker-compose.droplet.yml root@<DROPLET_IP>:/opt/walletwall-vault/
```

### 6a. Generate a test wallet

You need a private key that controls a Sepolia test wallet. Generate a fresh one
using the Docker image (ethers.js is already installed inside it — no extra tools):

```bash
# Run on the Droplet — prints a new private key + address
docker run --rm walletwall-vault:latest node -e "
const { ethers } = require('ethers');
const wallet = ethers.Wallet.createRandom();
console.log('');
console.log('=== NEW TEST WALLET — SEPOLIA ONLY ===');
console.log('Private Key: ' + wallet.privateKey);
console.log('Address:     ' + wallet.address);
console.log('');
console.log('NEXT: paste the private key into .env, then send Sepolia ETH to the address.');
console.log('WARNING: Never use this key with real money.');
"
```

Save both values. The **private key** goes into `.env`; the **address** is where
you send Sepolia ETH from a faucet.

### 6b. Get free Sepolia ETH

Paste the **address** (not the private key) into one of these faucets:

| Faucet | Amount | Requirements |
|---|---|---|
| https://cloud.google.com/application/web3/faucet/ethereum/sepolia | 0.05 ETH/day | None — just paste address |
| https://www.alchemy.com/faucets/ethereum-sepolia | 0.5 ETH | Free Alchemy account |
| https://sepolia-faucet.pk910.de/ | Variable | None — browser mines for ~5 min |

> ⚠️ If a faucet shows **"Insufficient balance on Ethereum Mainnet"** it is
> blocking you unless you have real ETH. Use Google Cloud or the PoW faucet
> instead — neither requires any mainnet balance.

Verify the ETH arrived (~30 seconds) at:
`https://sepolia.etherscan.io/address/<your-address>`

### 6c. Create the `.env` file

```bash
# Create the .env file (on the Droplet)
cat > /opt/walletwall-vault/.env << 'EOF'
# ⚠️ TESTNET / RESEARCH PROTOTYPE ONLY. NEVER USE REAL FUNDS.
# Use test ETH only. Never commit this file.

# Your Sepolia test wallet private key (0x-prefixed, 64 hex chars after the prefix)
# Generate one with: docker run --rm walletwall-vault:latest node -e "const {ethers}=require('ethers');const w=ethers.Wallet.createRandom();console.log(w.privateKey,w.address)"
DEPLOYER_PRIVATE_KEY=0x<your-generated-private-key>

# Public Sepolia RPC endpoints (free, no sign-up required)
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org

# If you already deployed MockMLDSAVerifier and just want to redeploy
# the vault pointing at it, set this to skip re-deploying the verifier:
PQC_VERIFIER_ADDRESS=

# Optional: Etherscan API key for contract source verification
ETHERSCAN_API_KEY=
EOF

# Restrict file permissions — only root can read it
chmod 600 /opt/walletwall-vault/.env
```

> **Security note:** On a shared server, consider using Docker secrets or a secrets
> manager instead of a plain `.env` file. For a personal research droplet, `chmod 600`
> is adequate.

---

## 7. Run the Sepolia deployer

> **This step deploys smart contracts to Ethereum Sepolia.**
> It costs Sepolia test ETH (free) and takes ~60-120 seconds.
> The contracts will be publicly visible on https://sepolia.etherscan.io

On the **Droplet**:

```bash
cd /opt/walletwall-vault

# Run the one-shot deploy container
# ⚠️  Always use -f docker-compose.droplet.yml on the Droplet.
#     The standard docker-compose.yml requires a Dockerfile that
#     is not present on the server.
docker compose -f docker-compose.droplet.yml --profile deploy run --rm vault-deploy
```

What this does:
1. Starts the `vault-deploy` container (from the `deploy` profile)
2. Runs `scripts/deploy-entrypoint.sh` which:
   - Validates `DEPLOYER_PRIVATE_KEY` is set and valid
   - Runs `npm run deploy:sepolia` → Hardhat deploys `MockMLDSAVerifier` then `WalletWallVault`
   - Prints the deployed contract addresses

**Example output:**

```
╔══════════════════════════════════════════════════════════╗
║        WalletWall Vault — Sepolia Deployment Runner       ║
╚══════════════════════════════════════════════════════════╝

⚠️  RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / SEPOLIA ONLY
   The PQ verifier deployed is a MOCK (no real ML-DSA verification)
   Use test ETH only. Never use a key that controls real funds.

✓ DEPLOYER_PRIVATE_KEY is set (not echoed for security)
✓ SEPOLIA_RPC_URL: https://ethereum-sepolia-rpc.publicnode.com

Network: sepolia (chain ID 11155111)
-────────────────────────────────────────────────────────
Deploying contracts...
Deployer: 0xYourAddress...
MockMLDSAVerifier (MOCK) deployed to: 0xABC...
WalletWallVault deployed to: 0xDEF...
Deployment complete!

════════════════════════════════════════════════════════════
  Deployment complete.
  Verify contracts at: https://sepolia.etherscan.io
  Update deployments/sepolia/ with the addresses above.
════════════════════════════════════════════════════════════
```

**Save the deployed addresses!** Update `deployments/sepolia/vault-do-dev.json` in your
local repo with these addresses (see [Step 9](#9-verify-the-deployment-on-etherscan)).

If the verifier deployed but the vault failed (network timeout, etc.), set
`PQC_VERIFIER_ADDRESS` in `.env` to the printed verifier address and re-run:

```bash
# Edit .env and set PQC_VERIFIER_ADDRESS=0x<verifier-address>
nano /opt/walletwall-vault/.env

# Re-run deploy — will reuse the existing verifier, skipping redeployment
docker compose -f /opt/walletwall-vault/docker-compose.droplet.yml --profile deploy run --rm vault-deploy
```

---

## 8. Run the persistent Hardhat node

The **Hardhat node** is useful for local testing against the Sepolia testnet, or
for exposing a JSON-RPC endpoint from the Droplet (e.g., for a frontend to connect
to during development).

> **Note:** This is an in-memory Hardhat node (chain ID 31337), NOT Sepolia itself.
> It resets on container restart. For reading from Sepolia, configure your frontend
> to use the Sepolia RPC URL directly.

```bash
cd /opt/walletwall-vault

# Start the production node using the droplet compose file
docker compose -f docker-compose.droplet.yml --profile node up -d walletwall-node

# Check it's running
docker compose -f docker-compose.droplet.yml ps

# Check the JSON-RPC endpoint responds
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Expected: {"jsonrpc":"2.0","id":1,"result":"0x7a69"}
```

The container restarts automatically on Droplet reboot (`restart: unless-stopped`).

**View logs:**
```bash
docker compose -f docker-compose.droplet.yml logs -f walletwall-node
```

**Stop:**
```bash
docker compose -f docker-compose.droplet.yml down
```

---

## 9. Verify the deployment on Etherscan

1. Open https://sepolia.etherscan.io
2. Search for your **deployer address** to see the deploy transactions
3. Search for the **`WalletWallVault` contract address** to confirm it's deployed
4. Click the contract address → **Contract** tab to see the bytecode

**Update the deployment record in your local repo:**

```bash
# In your local walletwall-vault directory
# Create or update deployments/sepolia/vault-do-dev.json
cat > deployments/sepolia/vault-do-dev.json << 'EOF'
{
  "$schema": "../schema/simulator-deployment.schema.json",
  "version": "1",
  "environment": "sepolia",
  "chainId": 11155111,
  "networkName": "sepolia",
  "walletWallVaultAddress": "0x<your-vault-address>",
  "pqcVerifierAddress": "0x<your-verifier-address>",
  "verifierType": "MockMLDSAVerifier",
  "deployedAt": "<ISO-timestamp>",
  "packageVersion": "0.4.26",
  "deployedVia": "Docker on DigitalOcean Droplet",
  "warnings": [
    "TESTNET ONLY — Ethereum Sepolia. No mainnet deployment exists or is planned.",
    "RESEARCH PROTOTYPE. Not audited. No production security guarantee.",
    "PQ gate uses MockMLDSAVerifier — structural checks only. No real on-chain ML-DSA cryptographic verification."
  ]
}
EOF

git add deployments/sepolia/vault-do-dev.json
git commit -m "chore(deployments): record Sepolia vault deployment"
git push
```

---

## 10. Firewall & Security

By default, DigitalOcean Droplets have **all ports open** unless you add a Cloud
Firewall. Here's the recommended firewall configuration:

| Direction | Protocol | Port | Source | Purpose |
|---|---|---|---|---|
| Inbound | TCP | 22 | Your IP only | SSH admin access |
| Inbound | TCP | 8545 | Your IP / frontend server | Hardhat JSON-RPC (optional) |
| Outbound | TCP | 443 | All | HTTPS to Sepolia RPC, npm, etc. |
| Outbound | TCP | 80 | All | HTTP (apt-get, etc.) |

To create the firewall:
1. DigitalOcean console → **Networking → Firewalls → Create Firewall**
2. Add the rules above
3. Assign the firewall to your Droplet

> **Port 8545:** Only expose this publicly if you intentionally want the Hardhat
> node to be accessible from the internet. For a research prototype, restrict it
> to your own IP or keep it closed — Sepolia deployments don't require an inbound
> node port to work.

---

## 11. Updating the deployment

When you push new code to the repo:

### Rebuild and update the image

On your **local machine**:

```bash
# Rebuild with latest code
docker build -t walletwall-vault:latest .

# Option A: Push to DOCR
docker tag walletwall-vault:latest registry.digitalocean.com/<registry>/walletwall-vault:latest
docker push registry.digitalocean.com/<registry>/walletwall-vault:latest

# Option B: Save and copy to Droplet
docker save walletwall-vault:latest | gzip > walletwall-vault.tar.gz
scp walletwall-vault.tar.gz root@<DROPLET_IP>:/root/
```

On the **Droplet**:

```bash
# Option A: Pull from DOCR
docker pull registry.digitalocean.com/<registry>/walletwall-vault:latest

# Option B: Load from tar
docker load < /root/walletwall-vault.tar.gz

# Restart the node with the new image
docker compose -f /opt/walletwall-vault/docker-compose.droplet.yml down
docker compose -f /opt/walletwall-vault/docker-compose.droplet.yml --profile node up -d walletwall-node
```

---

## 12. Troubleshooting

### `DEPLOYER_PRIVATE_KEY is not set`
You forgot to populate `.env` on the Droplet. See [Step 6c](#6c-create-the-env-file).

### `DEPLOYER_PRIVATE_KEY does not look like a 32-byte hex key`
The key in `.env` is not exactly 64 hex characters after the `0x` prefix. Diagnose with:
```bash
grep DEPLOYER_PRIVATE_KEY /opt/walletwall-vault/.env | cut -d= -f2 | tr -d '[:space:]' | sed 's/^0[xX]//' | wc -c
```
Expected output: `64`. Common causes:
- Key was pasted with a trailing space or newline
- Leading zero bytes were dropped by your wallet UI — pad with `00` on the left to reach 64 chars
- Key is genuinely truncated — regenerate with the Docker one-liner in [Step 6a](#6a-generate-a-test-wallet)

### `insufficient funds for gas`
Your Sepolia wallet is out of test ETH. Check your balance at
`https://sepolia.etherscan.io/address/<your-address>` and top up from a faucet
(see [Step 6b](#6b-get-free-sepolia-eth)).

### Faucet says "Insufficient balance on Ethereum Mainnet"
The faucet requires real ETH as an anti-spam gate. Use one that doesn't:
- **Google Cloud:** https://cloud.google.com/application/web3/faucet/ethereum/sepolia
- **PoW faucet:** https://sepolia-faucet.pk910.de/

### `failed to read dockerfile: open Dockerfile: no such file or directory`
You ran `docker compose` with the regular `docker-compose.yml` instead of the
Droplet-specific file. Always use `-f docker-compose.droplet.yml` on the server:
```bash
docker compose -f /opt/walletwall-vault/docker-compose.droplet.yml --profile deploy run --rm vault-deploy
```

### Container restarting / `MODULE_NOT_FOUND` in logs (local dev only)
On Windows + Docker Desktop the dev service's source mount can shadow the
container's Linux `node_modules`. Fix by tearing down with volumes and restarting:
```bash
docker compose down -v
docker compose up -d
```

### Port 8545 already allocated
Another container is already bound to port 8545. Find and stop it:
```bash
docker ps --filter publish=8545
docker stop <container-id>
```

### `connection refused` on port 8545
The Hardhat node container isn't running. Check:
```bash
docker ps
docker compose -f /opt/walletwall-vault/docker-compose.droplet.yml logs walletwall-node
```

### Image won't build — `npm ci` fails
Your `package-lock.json` may be out of sync with `package.json`. Fix locally:
```bash
npm install
git add package-lock.json
git commit -m "chore: sync package-lock.json"
docker build -t walletwall-vault:latest .
```

### `Error: No deployer signer is configured`
The `DEPLOYER_PRIVATE_KEY` value is set but empty (just `=`). Make sure you set
a real 64-hex-char key value after the `=` in `.env`.

### Sepolia RPC rate limiting / timeouts
The default public RPC (`ethereum-sepolia-rpc.publicnode.com`) is rate-limited.
For sustained use, get a free API key from:
- Alchemy: https://alchemy.com
- Infura: https://infura.io
- QuickNode: https://quicknode.com

Then update `SEPOLIA_RPC_URL` in `.env` with your private endpoint URL.
