# Use an official Node.js runtime as a parent image
FROM node:20-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    make \
    g++ \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install SP1 toolchain
RUN curl -L https://sp1.succinct.xyz | bash && \
    /root/.sp1/bin/sp1up && \
    ln -s /root/.sp1/bin/cargo-prove /usr/local/bin/cargo-prove

# Copy package.json and package-lock.json
COPY package*.json ./

# Install project dependencies
RUN npm install

# Copy the rest of the project files
COPY . .

# Compile the Hardhat project
RUN npm run compile

# Expose port 8545 for hardhat node
EXPOSE 8545

# Set the default command to run tests
CMD ["npm", "test"]
