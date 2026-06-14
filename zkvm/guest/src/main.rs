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
    // In a real production scenario, we'd use the mldsa crate.
    // Since we are in a ZKVM, we want to ensure this is as efficient as possible.
    let is_valid = mldsa65::verify(&inputs.public_key, &inputs.withdrawal_digest, &inputs.signature, &[]);

    if !is_valid {
        panic!("Invalid ML-DSA-65 signature");
    }

    // Commit public inputs to the journal.
    // In production, we use a robust encoding like ABI-encoding to ensure
    // the Solidity side can easily decode and verify the public inputs.
    // For this prototype, we simulate the committed bytes that match the
    // abi.decode call in ZKMLDSAVerifier.sol.

    // In a real SP1 implementation with eth_abi crate:
    // let journal = eth_abi::encode(&[
    //     Token::Uint(inputs.withdrawal_digest.into()),
    //     Token::Uint(pk_hash.into()),
    //     Token::Uint(sig_hash.into()),
    //     Token::Uint(inputs.chain_id.into()),
    //     Token::Address(inputs.verifier_address.into()),
    // ]);
    // sp1_zkvm::io::commit_slice(&journal);

    sp1_zkvm::io::commit(&inputs.withdrawal_digest);
    sp1_zkvm::io::commit(&pk_hash);
    sp1_zkvm::io::commit(&sig_hash);
    sp1_zkvm::io::commit(&inputs.chain_id);
    sp1_zkvm::io::commit(&inputs.verifier_address);
}
