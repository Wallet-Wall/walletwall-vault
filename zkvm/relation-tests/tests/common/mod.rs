//! Shared fixtures, signing helpers and the binding oracle for the relation tests.
#![allow(dead_code)]

use std::path::PathBuf;

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use mldsa65_relation_tests::{
    decode_acvp_journal, decode_withdrawal_journal, encode, execute, honest_withdrawal_stdin,
    keccak256, AcvpInputs, AcvpJournal, Outcome, Program, WithdrawalInputs, WithdrawalJournal,
};

pub const CHAIN_ID: u64 = 31337;
pub const VERIFIER_ADDRESS: [u8; 20] = [0x11; 20];

pub fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

pub fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim();
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).expect("hex")
}

pub fn read_hex_file(relative: &str) -> Vec<u8> {
    decode_hex(&std::fs::read_to_string(repo_path(relative)).expect("fixture is readable"))
}

pub struct Key {
    signing: SigningKey<MlDsa65>,
    pub public_key: Vec<u8>,
}

/// A deterministic ML-DSA-65 key from a one-byte seed.
pub fn key(seed: u8) -> Key {
    let signing = SigningKey::<MlDsa65>::from_seed(&Seed::from([seed; 32]));
    let public_key = signing.expanded_key().verifying_key().encode().to_vec();
    Key {
        signing,
        public_key,
    }
}

/// A deterministic FIPS 204 signature over `message` under `context`.
pub fn sign(key: &Key, message: &[u8], context: &[u8]) -> Vec<u8> {
    key.signing
        .expanded_key()
        .sign_deterministic(message, context)
        .expect("context is at most 255 bytes")
        .encode()
        .to_vec()
}

/// FIPS 204 ML-DSA.Verify: the oracle for the relation, never the code under test.
pub fn signature_verifies(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(encoded) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&encoded).verify_with_context(message, context, &signature)
}

/// The committed library-generated fixture (test/fixtures/mldsa/library-generated): a public key,
/// a 32-byte digest and one honest signature over it. No secret key for it is in the repository.
pub struct Fixture {
    pub public_key: Vec<u8>,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
}

pub fn library_fixture() -> Fixture {
    Fixture {
        public_key: read_hex_file("test/fixtures/mldsa/library-generated/public-key.hex"),
        digest: read_hex_file("test/fixtures/mldsa/library-generated/message.hex")
            .try_into()
            .expect("a 32-byte digest"),
        signature: read_hex_file("test/fixtures/mldsa/library-generated/signature.hex"),
    }
}

#[derive(serde::Deserialize)]
struct AcvpFile {
    vectors: Vec<AcvpVector>,
}

/// One NIST ACVP ML-DSA-65 sigVer vector (external interface, pure).
#[derive(Clone, serde::Deserialize)]
pub struct AcvpVector {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    pub pk: String,
    pub message: String,
    pub context: String,
    pub signature: String,
    #[serde(rename = "testPassed")]
    pub test_passed: bool,
}

pub fn acvp_vectors() -> Vec<AcvpVector> {
    let raw = std::fs::read_to_string(repo_path(
        "test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json",
    ))
    .expect("the ACVP fixture is readable");
    serde_json::from_str::<AcvpFile>(&raw)
        .expect("the ACVP fixture parses")
        .vectors
}

pub fn withdrawal_inputs(
    digest: [u8; 32],
    public_key: &[u8],
    signature: &[u8],
) -> WithdrawalInputs {
    WithdrawalInputs {
        withdrawal_digest: digest,
        public_key: public_key.to_vec(),
        signature: signature.to_vec(),
        chain_id: CHAIN_ID,
        verifier_address: VERIFIER_ADDRESS,
    }
}

/// The honest stdin for these inputs, in the withdrawal program's own input type.
pub fn honest_stdin(inputs: &WithdrawalInputs) -> Vec<Vec<u8>> {
    honest_withdrawal_stdin(inputs)
}

/// Stdin a prover may hand the withdrawal program to smuggle in an extra `message` and `context`:
/// the five withdrawal fields alone; the same buffer followed by both values (byte for byte the
/// seven-field input of the pre-remediation guest), by either value alone, or by a mode selector
/// set to 1 (as a u8 and as a bincode enum tag) and both values; and both values as additional
/// stdin buffers.
pub fn prover_stdin_layouts(
    inputs: &WithdrawalInputs,
    message: &[u8],
    context: &[u8],
) -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let fields = encode(inputs);
    let message_buffer = encode(&message.to_vec());
    let context_buffer = encode(&context.to_vec());
    let followed_by = |trailers: &[&[u8]]| {
        let mut buffer = fields.clone();
        for trailer in trailers {
            buffer.extend_from_slice(trailer);
        }
        buffer
    };
    vec![
        ("the five withdrawal fields", vec![fields.clone()]),
        (
            "the fields + message/context trailer",
            vec![followed_by(&[&message_buffer, &context_buffer])],
        ),
        (
            "the fields + message trailer",
            vec![followed_by(&[&message_buffer])],
        ),
        (
            "the fields + context trailer",
            vec![followed_by(&[&context_buffer])],
        ),
        (
            "the fields + mode 1 (u8) + message/context trailer",
            vec![followed_by(&[&[1u8], &message_buffer, &context_buffer])],
        ),
        (
            "the fields + mode 1 (u32 enum tag) + message/context trailer",
            vec![followed_by(&[
                &1u32.to_le_bytes(),
                &message_buffer,
                &context_buffer,
            ])],
        ),
        (
            "message/context as extra buffers",
            vec![
                fields.clone(),
                message_buffer.clone(),
                context_buffer.clone(),
            ],
        ),
    ]
}

pub fn accepted_withdrawal_journal(label: &str, stdin: Vec<Vec<u8>>) -> WithdrawalJournal {
    match execute(Program::Withdrawal, stdin) {
        Outcome::Accepted(public_values) => decode_withdrawal_journal(&public_values)
            .unwrap_or_else(|error| panic!("{label}: {error}")),
        Outcome::Rejected { reason, .. } => {
            panic!("{label}: the withdrawal program rejected: {reason}")
        }
    }
}

/// The run must be rejected, and a rejected run must not have committed anything first.
pub fn assert_withdrawal_rejected(label: &str, stdin: Vec<Vec<u8>>) {
    match execute(Program::Withdrawal, stdin) {
        Outcome::Accepted(public_values) => panic!(
            "{label}: the withdrawal program accepted and committed 0x{}",
            hex::encode(public_values)
        ),
        Outcome::Rejected { committed, .. } => assert!(
            committed.is_empty(),
            "{label}: rejected, but only after committing 0x{}",
            hex::encode(committed)
        ),
    }
}

/// THE BINDING PROPERTY, for stdin a prover chose. If the withdrawal program accepts, the digest it
/// commits was ML-DSA-65-signed as the message itself, under the empty FIPS 204 context, by the key
/// whose hash it commits. If it rejects, it committed nothing before stopping.
pub fn assert_withdrawal_bound(
    label: &str,
    public_key: &[u8],
    signature: &[u8],
    stdin: Vec<Vec<u8>>,
) {
    match execute(Program::Withdrawal, stdin) {
        Outcome::Rejected { committed, .. } => assert!(
            committed.is_empty(),
            "{label}: rejected, but only after committing 0x{}",
            hex::encode(committed)
        ),
        Outcome::Accepted(public_values) => {
            let journal = decode_withdrawal_journal(&public_values)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(
                journal.public_key_hash,
                keccak256(public_key),
                "{label}: committed key hash"
            );
            assert_eq!(
                journal.signature_hash,
                keccak256(signature),
                "{label}: committed signature hash"
            );
            assert!(
                signature_verifies(public_key, &journal.withdrawal_digest, &[], signature),
                "{label}: NOT BOUND. The withdrawal program accepted and committed digest 0x{} although \
                 that key never signed it under the empty context",
                hex::encode(journal.withdrawal_digest)
            );
        }
    }
}

/// The ACVP program's stdin for one vector: one buffer holding its input.
pub fn acvp_stdin(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Vec<Vec<u8>> {
    vec![encode(&AcvpInputs {
        public_key: public_key.to_vec(),
        message: message.to_vec(),
        context: context.to_vec(),
        signature: signature.to_vec(),
    })]
}

pub fn assert_acvp_accepted(label: &str, stdin: Vec<Vec<u8>>) -> AcvpJournal {
    match execute(Program::Acvp, stdin) {
        Outcome::Accepted(public_values) => {
            decode_acvp_journal(&public_values).unwrap_or_else(|error| panic!("{label}: {error}"))
        }
        Outcome::Rejected { reason, .. } => panic!("{label}: the ACVP program rejected: {reason}"),
    }
}

/// The run must be rejected, and a rejected run must not have committed anything first.
pub fn assert_acvp_rejected(label: &str, stdin: Vec<Vec<u8>>) {
    match execute(Program::Acvp, stdin) {
        Outcome::Accepted(public_values) => panic!(
            "{label}: the ACVP program accepted and committed 0x{}",
            hex::encode(public_values)
        ),
        Outcome::Rejected { committed, .. } => assert!(
            committed.is_empty(),
            "{label}: rejected, but only after committing 0x{}",
            hex::encode(committed)
        ),
    }
}
