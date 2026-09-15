#![no_main]
sp1_zkvm::entrypoint!(main);

// SP1 program `mldsa65-withdrawal`: the program a ZKMLDSAVerifier pins as PROGRAM_VKEY.
//
// Accepting relation: ML-DSA-65.Verify(public_key, withdrawal_digest, empty context, signature)
// holds, and the program commits that same withdrawal_digest together with keccak256(public_key),
// keccak256(signature), chain_id and verifier_address. The input holds only those five values: no
// separate message, no context and no mode, so no stdin a prover supplies can make the program
// verify one value and commit another. NIST ACVP conformance runs use the separate `mldsa65-acvp`
// program (src/bin/acvp.rs), which has its own ELF and program vkey.

use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};

/// The withdrawal proof input. zkvm/host/src/main.rs mirrors it field for field.
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

    // 3. Decode and verify the ML-DSA-65 signature.
    let public_key = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(inputs.public_key.as_slice())
        .expect("Invalid ML-DSA-65 public key length");
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&public_key);
    let signature =
        Signature::<MlDsa65>::try_from(inputs.signature.as_slice()).expect("Invalid ML-DSA-65 signature encoding");

    // The signed message is exactly the 32-byte withdrawal digest committed below, under the empty
    // context the withdrawal signer uses: FIPS 204 Algorithm 3, `verify_with_context(M, ctx, sig)`.
    if !verifying_key.verify_with_context(&inputs.withdrawal_digest, &[], &signature) {
        panic!("Invalid ML-DSA-65 signature");
    }

    // Commit public inputs to the journal.
    // To match Solidity's abi.decode(publicValues, (bytes32, bytes32, bytes32, uint64, address)),
    // we must commit each value as a 32-byte word.

    // 1. withdrawal_digest (32 bytes): the digest verified above
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
