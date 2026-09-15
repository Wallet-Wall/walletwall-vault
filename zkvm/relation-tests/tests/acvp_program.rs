//! The ACVP conformance program: FIPS 204 ML-DSA.Verify over an arbitrary message and context.
//! Each negative test first shows the matching valid run is accepted.

mod common;

use common::*;
use mldsa65_relation_tests::{keccak256, AcvpJournal};

#[test]
fn acvp_program_accepts_valid_vectors_and_commits_their_hashes() {
    let mut accepted = 0;
    for vector in acvp_vectors().iter().filter(|vector| vector.test_passed) {
        let public_key = decode_hex(&vector.pk);
        let message = decode_hex(&vector.message);
        let context = decode_hex(&vector.context);
        let signature = decode_hex(&vector.signature);
        let journal = assert_acvp_accepted(
            &format!("valid tcId {}", vector.tc_id),
            acvp_stdin(&public_key, &message, &context, &signature),
        );
        assert_eq!(
            journal,
            AcvpJournal {
                public_key_hash: keccak256(&public_key),
                message_hash: keccak256(&message),
                context_hash: keccak256(&context),
                signature_hash: keccak256(&signature),
            },
            "tcId {}",
            vector.tc_id
        );
        accepted += 1;
    }
    assert!(accepted > 0, "at least one valid ACVP vector");
}

#[test]
fn acvp_program_rejects_invalid_vectors_and_a_tampered_signature() {
    let vectors = acvp_vectors();
    let valid = vectors
        .iter()
        .find(|vector| vector.test_passed)
        .expect("a valid ACVP vector");
    let (public_key, message, context, signature) = (
        decode_hex(&valid.pk),
        decode_hex(&valid.message),
        decode_hex(&valid.context),
        decode_hex(&valid.signature),
    );
    assert_acvp_accepted(
        &format!("positive control: valid tcId {}", valid.tc_id),
        acvp_stdin(&public_key, &message, &context, &signature),
    );

    let mut rejected = 0;
    for vector in vectors.iter().filter(|vector| !vector.test_passed) {
        assert_acvp_rejected(
            &format!("invalid tcId {}", vector.tc_id),
            acvp_stdin(
                &decode_hex(&vector.pk),
                &decode_hex(&vector.message),
                &decode_hex(&vector.context),
                &decode_hex(&vector.signature),
            ),
        );
        rejected += 1;
    }
    assert!(rejected > 0, "at least one invalid ACVP vector");

    let mut tampered = signature.clone();
    tampered[0] ^= 0xff;
    assert_acvp_rejected(
        &format!("tcId {} with a tampered signature", valid.tc_id),
        acvp_stdin(&public_key, &message, &context, &tampered),
    );
}

#[test]
fn acvp_program_verifies_under_the_vector_context() {
    let vectors = acvp_vectors();
    let valid = vectors
        .iter()
        .find(|vector| vector.test_passed && !vector.context.is_empty())
        .expect("a valid ACVP vector with a non-empty context");
    let public_key = decode_hex(&valid.pk);
    let message = decode_hex(&valid.message);
    let context = decode_hex(&valid.context);
    let signature = decode_hex(&valid.signature);
    assert_acvp_accepted(
        &format!(
            "positive control: tcId {} under its own context",
            valid.tc_id
        ),
        acvp_stdin(&public_key, &message, &context, &signature),
    );

    let mut altered = context.clone();
    altered[0] ^= 0x01;
    assert_acvp_rejected(
        &format!("tcId {} with an altered context", valid.tc_id),
        acvp_stdin(&public_key, &message, &altered, &signature),
    );
    assert_acvp_rejected(
        &format!("tcId {} with its context dropped", valid.tc_id),
        acvp_stdin(&public_key, &message, &[], &signature),
    );
}
