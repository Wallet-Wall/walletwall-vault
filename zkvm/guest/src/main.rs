#![no_main]
sp1_zkvm::entrypoint!(main);

use mldsa::mldsa65;
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GuestInputs {
    pub withdrawal_digest: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
}

pub fn main() {
    // Read inputs from the prover
    let inputs = sp1_zkvm::io::read::<GuestInputs>();

    // 1. Verify Public Key Hash (Public Input Commitment)
    let mut hasher = Keccak256::new();
    hasher.update(&inputs.public_key);
    let pk_hash: [u8; 32] = hasher.finalize().into();

    // 2. Verify Signature Hash (Public Input Commitment)
    let mut hasher = Keccak256::new();
    hasher.update(&inputs.signature);
    let sig_hash: [u8; 32] = hasher.finalize().into();

    // 3. Verify ML-DSA-65 Signature
    let is_valid = mldsa65::verify(&inputs.public_key, &inputs.withdrawal_digest, &inputs.signature, &[]);

    if !is_valid {
        panic!("Invalid ML-DSA-65 signature");
    }

    // Commit public inputs to the journal.
    // To match Solidity's abi.decode(publicValues, (bytes32, bytes32, bytes32, uint64, address)),
    // we must commit each value as a 32-byte word.

    // 1. withdrawal_digest (32 bytes)
    sp1_zkvm::io::commit_slice(&inputs.withdrawal_digest);

    // 2. pk_hash (32 bytes)
    sp1_zkvm::io::commit_slice(&pk_hash);

    // 3. sig_hash (32 bytes)
    sp1_zkvm::io::commit_slice(&sig_hash);

    // 4. chain_id (u64 -> 32 bytes, big-endian padded)
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..32].copy_from_slice(&inputs.chain_id.to_be_bytes());
    sp1_zkvm::io::commit_slice(&chain_id_bytes);

    // 5. verifier_address (20 bytes -> 32 bytes, padded)
    let mut verifier_addr_bytes = [0u8; 32];
    verifier_addr_bytes[12..32].copy_from_slice(&inputs.verifier_address);
    sp1_zkvm::io::commit_slice(&verifier_addr_bytes);
}
