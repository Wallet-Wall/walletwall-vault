# Node release for every stage (the runner executes the node_modules the builder installs). It must meet
# package.json `engines.node` and the floor the installed Hardhat CLI enforces; test/DockerNodeRuntime.test.ts checks
# this default, not a --build-arg override.
ARG NODE_VERSION=22.23.2

# ─────────────────────────────────────────────────────────────
# Stage 1 — builder
#   Installs all dev-dependencies, compiles Solidity contracts,
#   and generates TypeChain types. Nothing from this stage is
#   needed at runtime on DigitalOcean — only the compiled
#   artifacts and the node_modules are carried over.
# ─────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION}-bookworm-slim AS builder

WORKDIR /app

# Build-time system deps (native modules may need python/make/g++)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer-cached unless package files change)
COPY package*.json ./
RUN npm ci --include=dev

# Copy source and compile contracts
COPY . .
RUN npm run compile

# ─────────────────────────────────────────────────────────────
# Stage 2 — runner
#   Slim image. Contains only what is needed to:
#     a) run `npm run deploy:sepolia` (one-shot deploy mode), OR
#     b) run `npx hardhat node` (persistent JSON-RPC node mode)
#   SP1 / Rust / zkVM toolchains are intentionally excluded —
#   they are only needed for local zkVM development, not for
#   Sepolia testnet interaction.
# ─────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION}-bookworm-slim AS runner

LABEL org.opencontainers.image.title="walletwall-vault" \
      org.opencontainers.image.description="WalletWall hybrid PQ vault — Hardhat node + Sepolia deployer" \
      org.opencontainers.image.source="https://github.com/Wallet-Wall/walletwall-vault" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled artifacts + node_modules from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/artifacts    ./artifacts
COPY --from=builder /app/cache        ./cache
COPY --from=builder /app/typechain-types ./typechain-types

# Copy all project source files (scripts, contracts, config, etc.)
COPY . .

# Port for the Hardhat JSON-RPC node (used in local / demo mode)
EXPOSE 8545

# Health-check: poll the local JSON-RPC endpoint every 30 s.
# Only meaningful when the container is running in node mode.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -sf -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    || exit 1

# ── Default command ──────────────────────────────────────────
# Runs a persistent Hardhat in-memory node bound to all
# interfaces inside the container, which Docker needs in order to
# forward a published port to it. EXPOSE publishes nothing by itself;
# publish the port on the host's loopback interface only:
#   docker run --rm -p 127.0.0.1:8545:8545 walletwall-vault:latest
# Override with `docker compose exec` / `docker run`
# to run deploy or test scripts instead.
#
# For Sepolia deployment, use the entrypoint script:
#   docker compose --profile deploy run vault-deploy
CMD ["npx", "hardhat", "node", "--hostname", "0.0.0.0"]
