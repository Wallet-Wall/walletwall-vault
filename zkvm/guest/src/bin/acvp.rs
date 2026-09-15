#![no_main]
sp1_zkvm::entrypoint!(main);

// SP1 program `mldsa65-acvp`: NIST ACVP ML-DSA-65 sigVer conformance (FIPS 204 external interface,
// pure signing). Conformance tooling only.
//
// Accepting relation: ML-DSA-65.Verify(public_key, message, context, signature) holds for an
// arbitrary message and a context of at most 255 bytes; the program commits keccak256 of each of
// the four inputs. That is NOT a withdrawal authorization, so a ZKMLDSAVerifier must never pin this
// program's vkey. Withdrawals use the separate `mldsa65-withdrawal` program (src/bin/withdrawal.rs).

use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};

/// One ACVP sigVer test case. zkvm/host/src/main.rs mirrors it field for field.
#[derive(Serialize, Deserialize)]
struct AcvpInputs {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub context: Vec<u8>,
    pub signature: Vec<u8>,
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub fn main() {
    let inputs = sp1_zkvm::io::read::<AcvpInputs>();

    let public_key = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(inputs.public_key.as_slice())
        .expect("Invalid ML-DSA-65 public key length");
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&public_key);
    let signature =
        Signature::<MlDsa65>::try_from(inputs.signature.as_slice()).expect("Invalid ML-DSA-65 signature encoding");

    // FIPS 204 Algorithm 3 (ML-DSA.Verify) over the vector's message under the vector's context.
    if !verifying_key.verify_with_context(&inputs.message, &inputs.context, &signature) {
        panic!("Invalid ML-DSA-65 signature");
    }

    // Journal (128 bytes): keccak256 of the public key, message, context and signature verified above.
    sp1_zkvm::io::commit_slice(&keccak256(&inputs.public_key));
    sp1_zkvm::io::commit_slice(&keccak256(&inputs.message));
    sp1_zkvm::io::commit_slice(&keccak256(&inputs.context));
    sp1_zkvm::io::commit_slice(&keccak256(&inputs.signature));
}
