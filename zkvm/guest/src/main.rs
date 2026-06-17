#![no_main]
sp1_zkvm::entrypoint!(main);

use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GuestInputs {
    pub withdrawal_digest: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
    /// Raw message that was signed, for FIPS 204 external/pure verification.
    /// Empty for the production withdrawal path, where the 32-byte
    /// `withdrawal_digest` is itself the signed message and the context is empty.
    /// Non-empty only for NIST ACVP differential-conformance runs, which sign
    /// arbitrary-length messages under an explicit domain-separation context.
    pub message: Vec<u8>,
    /// FIPS 204 context string. Empty for the withdrawal path; carries the ACVP
    /// vector's `context` field for conformance runs.
    pub context: Vec<u8>,
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

    // 3. Decode and verify the ML-DSA-65 signature.
    let public_key = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(inputs.public_key.as_slice())
        .expect("Invalid ML-DSA-65 public key length");
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&public_key);
    let signature =
        Signature::<MlDsa65>::try_from(inputs.signature.as_slice()).expect("Invalid ML-DSA-65 signature encoding");

    // The signed message is the 32-byte withdrawal digest on the production path
    // (empty `message`), or the raw ACVP message on a conformance run. Either way
    // we go through FIPS 204 Algorithm 3 (ML-DSA.Verify) with explicit context
    // separation: `verify_with_context(M, ctx, sig)`. For the withdrawal path both
    // `message` and `context` are empty, so this is identical to verifying the
    // digest under the empty context — the prior behavior.
    let signed_message: &[u8] = if inputs.message.is_empty() {
        &inputs.withdrawal_digest[..]
    } else {
        &inputs.message[..]
    };

    if !verifying_key.verify_with_context(signed_message, &inputs.context, &signature) {
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
