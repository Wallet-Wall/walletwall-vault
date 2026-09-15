//! Native relation tests for the SP1 ML-DSA-65 guest programs.
//!
//! This crate compiles the guest programs' own sources (the bin targets of zkvm/guest, see
//! build.rs) for the host target and runs them on stdin chosen the way a prover may choose it. It
//! needs stable Rust only: no SP1 toolchain, no proving, no network.
//!
//! Why that reaches the proven relation: SP1 proves executions of a program ELF, and its verifiers
//! check for exit code 0 by default. Under SP1's soundness and completeness, the public values a
//! valid proof for a program can carry are exactly those some prover-chosen stdin makes the program
//! commit on a run that returns normally. [`execute`] answers which runs return normally and what
//! they commit, and records what a rejected run had committed before it stopped.
//!
//! What this cannot show: a divergence between the host target and the zkVM target (the programs
//! have no target-specific code), the programs' ELF bytes or vkeys, or the behaviour of any deployed
//! SP1 verifier. Program identities are measured with the SP1 toolchain; see
//! docs/ZK_Prover_Runbook.md.

#[allow(dead_code, unused_imports)]
mod withdrawal_program {
    include!(concat!(env!("OUT_DIR"), "/withdrawal_body.rs"));

    /// Harness hook, not part of the program: decodes `bytes` as the program's own input type
    /// (`GuestInputs`, the type zkvm/host mirrors) and encodes that value again.
    pub(crate) fn reencode_input(bytes: &[u8]) -> Result<Vec<u8>, bincode::Error> {
        let inputs: GuestInputs = bincode::deserialize(bytes)?;
        bincode::serialize(&inputs)
    }
}

#[allow(dead_code, unused_imports)]
mod acvp_program {
    include!(concat!(env!("OUT_DIR"), "/acvp_body.rs"));
}

use serde::Serialize;
use sha3::{Digest, Keccak256};

/// The `mldsa65-withdrawal` program's source, verbatim.
pub const WITHDRAWAL_SOURCE: &str = include_str!(concat!(env!("OUT_DIR"), "/withdrawal_source.rs"));
/// Its path relative to zkvm/guest, as Cargo reports it for the bin target.
pub const WITHDRAWAL_SOURCE_PATH: &str = env!("WITHDRAWAL_SOURCE_PATH");
/// The `mldsa65-acvp` program's source, verbatim.
pub const ACVP_SOURCE: &str = include_str!(concat!(env!("OUT_DIR"), "/acvp_source.rs"));
/// Its path relative to zkvm/guest, as Cargo reports it for the bin target.
pub const ACVP_SOURCE_PATH: &str = env!("ACVP_SOURCE_PATH");
/// Every bin target Cargo reports for zkvm/guest, sorted and comma-separated.
pub const GUEST_BIN_TARGETS: &str = env!("GUEST_BIN_TARGETS");

/// A guest program, named by the bin target it is built as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    /// `mldsa65-withdrawal`: the program a `ZKMLDSAVerifier` pins by its vkey.
    Withdrawal,
    /// `mldsa65-acvp`: NIST ACVP conformance only.
    Acvp,
}

/// How one run of a program ended.
#[derive(Debug)]
pub enum Outcome {
    /// `main` returned normally (exit code 0) after committing these public values.
    Accepted(Vec<u8>),
    /// The program panicked or halted (a non-zero exit code). `committed` holds whatever it had
    /// written to the public-values stream before stopping.
    Rejected { reason: String, committed: Vec<u8> },
}

/// Runs `program` once on these stdin buffers (one buffer per `SP1Stdin::write`).
pub fn execute(program: Program, stdin: Vec<Vec<u8>>) -> Outcome {
    let entry: fn() = match program {
        Program::Withdrawal => withdrawal_program::main,
        Program::Acvp => acvp_program::main,
    };
    sp1_zkvm::harness::begin(stdin);
    let result = std::panic::catch_unwind(entry);
    let public_values = sp1_zkvm::harness::take_public_values();
    match result {
        Ok(()) => Outcome::Accepted(public_values),
        Err(payload) => Outcome::Rejected {
            reason: panic_message(payload.as_ref()),
            committed: public_values,
        },
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// One stdin buffer, serialized as `SP1Stdin::write` serializes it (bincode 1 defaults).
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("stdin value serializes")
}

/// The five withdrawal fields, in the order the withdrawal program's input declares them.
#[derive(Clone, Debug, Serialize)]
pub struct WithdrawalInputs {
    pub withdrawal_digest: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
}

/// The honest stdin for a withdrawal: the withdrawal program's own input type holding these values,
/// serialized as the host serializes it (one `SP1Stdin::write`).
///
/// The canonical encoding of the five withdrawal fields, followed by zero bytes, is decoded as the
/// program's input type and encoded again. A program whose input type holds exactly the withdrawal
/// fields gets exactly their encoding back; a program whose type declares further fields after them
/// gets those fields zero or empty, which is what an honest host that leaves them unset sends.
pub fn honest_withdrawal_stdin(inputs: &WithdrawalInputs) -> Vec<Vec<u8>> {
    let mut bytes = encode(inputs);
    bytes.extend_from_slice(&[0u8; 64]);
    let reencoded = withdrawal_program::reencode_input(&bytes).expect(
        "the withdrawal program's input type decodes the withdrawal fields followed by zero bytes",
    );
    vec![reencoded]
}

/// The ACVP program's input, field for field.
#[derive(Clone, Debug, Serialize)]
pub struct AcvpInputs {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub context: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The five words `ZKMLDSAVerifier.decodeProofPayload` reads from a withdrawal proof's public values.
#[derive(Debug, PartialEq, Eq)]
pub struct WithdrawalJournal {
    pub withdrawal_digest: [u8; 32],
    pub public_key_hash: [u8; 32],
    pub signature_hash: [u8; 32],
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
}

/// Decodes public values as `ZKMLDSAVerifier.decodeProofPayload` does: exactly 160 bytes,
/// `abi.decode(..., (bytes32, bytes32, bytes32, uint64, address))`, which rejects non-zero
/// high-order padding in the `uint64` and `address` words.
pub fn decode_withdrawal_journal(public_values: &[u8]) -> Result<WithdrawalJournal, String> {
    if public_values.len() != 160 {
        return Err(format!(
            "withdrawal public values are {} bytes, expected 160",
            public_values.len()
        ));
    }
    let word = |index: usize| -> [u8; 32] {
        public_values[index * 32..(index + 1) * 32]
            .try_into()
            .expect("a 32-byte word")
    };
    let chain_word = word(3);
    let address_word = word(4);
    if chain_word[..24].iter().any(|byte| *byte != 0) {
        return Err("the uint64 word has non-zero padding".to_string());
    }
    if address_word[..12].iter().any(|byte| *byte != 0) {
        return Err("the address word has non-zero padding".to_string());
    }
    Ok(WithdrawalJournal {
        withdrawal_digest: word(0),
        public_key_hash: word(1),
        signature_hash: word(2),
        chain_id: u64::from_be_bytes(chain_word[24..].try_into().expect("8 bytes")),
        verifier_address: address_word[12..].try_into().expect("20 bytes"),
    })
}

/// The ACVP program's journal: keccak256 of each input it verified.
#[derive(Debug, PartialEq, Eq)]
pub struct AcvpJournal {
    pub public_key_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub context_hash: [u8; 32],
    pub signature_hash: [u8; 32],
}

/// Decodes the ACVP program's 128 bytes of public values.
pub fn decode_acvp_journal(public_values: &[u8]) -> Result<AcvpJournal, String> {
    if public_values.len() != 128 {
        return Err(format!(
            "ACVP public values are {} bytes, expected 128",
            public_values.len()
        ));
    }
    let word = |index: usize| -> [u8; 32] {
        public_values[index * 32..(index + 1) * 32]
            .try_into()
            .expect("a 32-byte word")
    };
    Ok(AcvpJournal {
        public_key_hash: word(0),
        message_hash: word(1),
        context_hash: word(2),
        signature_hash: word(3),
    })
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
