//! Program identity: withdrawal authorization and ACVP conformance are separate SP1 programs.
//!
//! These tests cover the source side of the boundary. The verifier side (a `ZKMLDSAVerifier`
//! accepts only proofs for its own `PROGRAM_VKEY`) is tested in Solidity, and the two programs'
//! vkeys are measured with the SP1 toolchain.

mod common;

use common::*;
use mldsa65_relation_tests::{
    ACVP_SOURCE, ACVP_SOURCE_PATH, WITHDRAWAL_SOURCE, WITHDRAWAL_SOURCE_PATH,
};

#[test]
fn isolation_withdrawal_and_acvp_are_separate_programs() {
    assert_ne!(
        WITHDRAWAL_SOURCE_PATH, ACVP_SOURCE_PATH,
        "one entry point would give both relations one program identity"
    );
    assert_ne!(
        WITHDRAWAL_SOURCE, ACVP_SOURCE,
        "identical sources would give both relations one accepting relation"
    );
}

#[test]
fn isolation_input_the_acvp_program_accepts_is_rejected_by_the_withdrawal_program() {
    let mut exercised = 0;
    for vector in acvp_vectors().iter().filter(|vector| vector.test_passed) {
        let public_key = decode_hex(&vector.pk);
        let message = decode_hex(&vector.message);
        let context = decode_hex(&vector.context);
        let signature = decode_hex(&vector.signature);
        let stdin = acvp_stdin(&public_key, &message, &context, &signature);
        assert_acvp_accepted(
            &format!(
                "positive control: the ACVP program accepts tcId {}",
                vector.tc_id
            ),
            stdin.clone(),
        );
        assert_withdrawal_rejected(
            &format!(
                "the same tcId {} input handed to the withdrawal program",
                vector.tc_id
            ),
            stdin,
        );
        exercised += 1;
    }
    assert!(exercised > 0, "at least one valid ACVP vector");
}
