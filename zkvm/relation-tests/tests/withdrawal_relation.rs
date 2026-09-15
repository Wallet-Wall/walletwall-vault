//! The withdrawal program's accepting relation.
//!
//! - `control_*`: properties every sound withdrawal relation keeps; they must pass. Each negative
//!   control first shows the matching honest run is accepted, so no rejection passes vacuously.
//! - `input_*`: the withdrawal program reads exactly the withdrawal fields and nothing else.
//! - `binding_*`: the binding property. Each drives the withdrawal program the way a prover may and
//!   applies one oracle, `assert_withdrawal_bound`: if the program accepts, the digest it commits
//!   was ML-DSA-65-signed as the message itself, under the empty FIPS 204 context, by the key whose
//!   hash it commits; if it rejects, it committed nothing first.
//!
//! Signatures come from `sign_deterministic`, so every run is reproducible.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use mldsa65_relation_tests::{
    encode, keccak256, WithdrawalJournal, ACVP_SOURCE, ACVP_SOURCE_PATH, GUEST_BIN_TARGETS,
    WITHDRAWAL_SOURCE, WITHDRAWAL_SOURCE_PATH,
};

// ---------------------------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------------------------

#[test]
fn control_harness_compiles_exactly_the_programs_cargo_builds_from_zkvm_guest() {
    assert_eq!(
        GUEST_BIN_TARGETS, "mldsa65-acvp,mldsa65-withdrawal",
        "zkvm/guest must build exactly the programs these tests cover; a new program needs its own relation tests"
    );
    for (program, source, relative) in [
        (
            "mldsa65-withdrawal",
            WITHDRAWAL_SOURCE,
            WITHDRAWAL_SOURCE_PATH,
        ),
        ("mldsa65-acvp", ACVP_SOURCE, ACVP_SOURCE_PATH),
    ] {
        let on_disk = std::fs::read_to_string(repo_path("zkvm/guest").join(relative))
            .unwrap_or_else(|error| panic!("{program}: zkvm/guest/{relative}: {error}"));
        assert_eq!(
            source, on_disk,
            "{program}: the compiled source differs from zkvm/guest/{relative}"
        );
        println!(
            "{program}: zkvm/guest/{relative} keccak256 0x{}",
            hex::encode(keccak256(source.as_bytes()))
        );
    }
}

fn lock_versions(lock: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(value) = line.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').to_string());
        } else if let (Some(value), Some(current)) = (line.strip_prefix("version = "), name.take())
        {
            versions
                .entry(current)
                .or_default()
                .insert(value.trim_matches('"').to_string());
        }
    }
    versions
}

#[test]
fn control_harness_links_the_guest_lockfile_versions() {
    let harness = lock_versions(include_str!("../Cargo.lock"));
    let guest = lock_versions(include_str!("../../guest/Cargo.lock"));
    for required in ["ml-dsa", "sha3", "keccak", "bincode", "serde"] {
        assert!(
            harness.contains_key(required) && guest.contains_key(required),
            "{required} is in both lockfiles"
        );
    }
    let mut shared = 0;
    for (name, versions) in &harness {
        if let Some(guest_versions) = guest.get(name) {
            assert!(
                versions.is_subset(guest_versions),
                "{name}: the harness links {versions:?}, the guest lock pins {guest_versions:?}"
            );
            shared += 1;
        }
    }
    println!("{shared} packages shared with zkvm/guest/Cargo.lock, each at a version the guest lock pins");
}

#[test]
fn control_committed_withdrawal_fixture_is_accepted_with_its_journal() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct InputsFile {
        withdrawal_digest: String,
        public_key: String,
        signature: String,
        chain_id: u64,
        verifier_address: String,
    }
    let raw = std::fs::read_to_string(repo_path("zkvm/fixtures/mldsa65-withdrawal.inputs.json"))
        .expect("the committed withdrawal fixture is readable");
    let file: InputsFile = serde_json::from_str(&raw)
        .expect("the committed withdrawal fixture carries exactly the withdrawal fields");
    let mut inputs = withdrawal_inputs(
        decode_hex(&file.withdrawal_digest)
            .try_into()
            .expect("a 32-byte digest"),
        &decode_hex(&file.public_key),
        &decode_hex(&file.signature),
    );
    inputs.chain_id = file.chain_id;
    inputs.verifier_address = decode_hex(&file.verifier_address)
        .try_into()
        .expect("a 20-byte address");

    let journal = accepted_withdrawal_journal("committed fixture", honest_stdin(&inputs));
    assert_eq!(
        journal,
        WithdrawalJournal {
            withdrawal_digest: inputs.withdrawal_digest,
            public_key_hash: keccak256(&inputs.public_key),
            signature_hash: keccak256(&inputs.signature),
            chain_id: inputs.chain_id,
            verifier_address: inputs.verifier_address,
        }
    );
}

#[test]
fn control_honest_withdrawal_from_a_generated_key_is_accepted() {
    let owner = key(7);
    let digest = keccak256(b"relation tests: an honest withdrawal digest");
    let signature = sign(&owner, &digest, &[]);
    let inputs = withdrawal_inputs(digest, &owner.public_key, &signature);
    let journal = accepted_withdrawal_journal("honest withdrawal", honest_stdin(&inputs));
    assert_eq!(journal.withdrawal_digest, digest);
    assert_withdrawal_bound(
        "honest withdrawal",
        &owner.public_key,
        &signature,
        honest_stdin(&inputs),
    );
}

#[test]
fn control_tampered_signature_is_rejected() {
    let fixture = library_fixture();
    let untampered = withdrawal_inputs(fixture.digest, &fixture.public_key, &fixture.signature);
    accepted_withdrawal_journal(
        "positive control: untampered fixture",
        honest_stdin(&untampered),
    );

    let mut signature = fixture.signature.clone();
    signature[0] ^= 0xff;
    assert_withdrawal_rejected(
        "tampered signature",
        honest_stdin(&withdrawal_inputs(
            fixture.digest,
            &fixture.public_key,
            &signature,
        )),
    );
}

#[test]
fn control_signature_checked_against_another_key_is_rejected() {
    let fixture = library_fixture();
    let own_key = withdrawal_inputs(fixture.digest, &fixture.public_key, &fixture.signature);
    accepted_withdrawal_journal(
        "positive control: the signer's own key",
        honest_stdin(&own_key),
    );

    let other = key(8);
    assert_withdrawal_rejected(
        "another key",
        honest_stdin(&withdrawal_inputs(
            fixture.digest,
            &other.public_key,
            &fixture.signature,
        )),
    );
}

#[test]
fn control_signature_over_another_digest_is_rejected() {
    let fixture = library_fixture();
    let signed = withdrawal_inputs(fixture.digest, &fixture.public_key, &fixture.signature);
    accepted_withdrawal_journal("positive control: the signed digest", honest_stdin(&signed));

    let unsigned = keccak256(b"relation tests: a digest the fixture key never signed");
    assert_withdrawal_rejected(
        "unsigned digest",
        honest_stdin(&withdrawal_inputs(
            unsigned,
            &fixture.public_key,
            &fixture.signature,
        )),
    );
}

#[test]
fn control_journal_words_come_from_their_own_inputs() {
    let owner = key(7);
    let digest = keccak256(b"relation tests: journal words");
    let signature = sign(&owner, &digest, &[]);
    let first = withdrawal_inputs(digest, &owner.public_key, &signature);
    let mut second = first.clone();
    second.chain_id = 11_155_111;
    second.verifier_address = [0x22; 20];

    let a = accepted_withdrawal_journal("chain 31337", honest_stdin(&first));
    let b = accepted_withdrawal_journal("chain 11155111", honest_stdin(&second));
    assert_eq!((a.chain_id, a.verifier_address), (31_337, [0x11; 20]));
    assert_eq!((b.chain_id, b.verifier_address), (11_155_111, [0x22; 20]));
    assert_eq!(a.public_key_hash, keccak256(&owner.public_key));
    assert_eq!(a.signature_hash, keccak256(&signature));
    assert_ne!(a.public_key_hash, a.signature_hash);
    assert_eq!((a.withdrawal_digest, b.withdrawal_digest), (digest, digest));
}

// ---------------------------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------------------------

#[test]
fn input_is_exactly_the_five_withdrawal_fields() {
    let fixture = library_fixture();
    let inputs = withdrawal_inputs(fixture.digest, &fixture.public_key, &fixture.signature);
    assert_eq!(
        honest_stdin(&inputs),
        vec![encode(&inputs)],
        "the withdrawal program's input type must hold exactly withdrawal_digest, public_key, signature, \
         chain_id and verifier_address, in that order: any further field is prover-controlled input the \
         withdrawal relation does not need"
    );
}

// ---------------------------------------------------------------------------------------------
// Binding property
// ---------------------------------------------------------------------------------------------

#[test]
fn binding_signature_over_m1_cannot_commit_digest_d2() {
    let owner = key(7);
    let m1 = b"relation tests: message M1 that the owner really signed";
    let d2 = keccak256(b"relation tests: withdrawal D2 the owner never signed");
    let signature = sign(&owner, m1, &[]);
    assert!(
        signature_verifies(&owner.public_key, m1, &[], &signature),
        "precondition: valid over M1"
    );
    assert!(
        !signature_verifies(&owner.public_key, &d2, &[], &signature),
        "precondition: not valid over D2"
    );

    let inputs = withdrawal_inputs(d2, &owner.public_key, &signature);
    for (layout, stdin) in prover_stdin_layouts(&inputs, m1, &[]) {
        assert_withdrawal_bound(
            &format!("M1 signature, D2 digest, {layout}"),
            &owner.public_key,
            &signature,
            stdin,
        );
    }
}

#[test]
fn binding_one_observed_withdrawal_signature_cannot_authorize_another_withdrawal() {
    // No secret key: only the public key and one honest withdrawal signature, as anyone who built
    // or saw a proof witness for that withdrawal holds them.
    let fixture = library_fixture();
    assert!(
        signature_verifies(
            &fixture.public_key,
            &fixture.digest,
            &[],
            &fixture.signature
        ),
        "precondition: an honest withdrawal signature"
    );
    let d2 = keccak256(b"relation tests: an attacker-chosen withdrawal digest");

    let inputs = withdrawal_inputs(d2, &fixture.public_key, &fixture.signature);
    for (layout, stdin) in prover_stdin_layouts(&inputs, &fixture.digest, &[]) {
        assert_withdrawal_bound(
            &format!("replayed withdrawal signature, D2 digest, {layout}"),
            &fixture.public_key,
            &fixture.signature,
            stdin,
        );
    }
}

#[test]
fn binding_signature_under_a_foreign_context_cannot_authorize_a_withdrawal() {
    let owner = key(9);
    let digest = keccak256(b"relation tests: a digest signed for another protocol");
    let foreign_context = b"another-protocol/v1";
    let signature = sign(&owner, &digest, foreign_context);
    assert!(
        !signature_verifies(&owner.public_key, &digest, &[], &signature),
        "precondition: not a withdrawal signature"
    );

    let inputs = withdrawal_inputs(digest, &owner.public_key, &signature);
    for (layout, stdin) in prover_stdin_layouts(&inputs, &[], foreign_context) {
        assert_withdrawal_bound(
            &format!("foreign context, empty message, {layout}"),
            &owner.public_key,
            &signature,
            stdin,
        );
    }
    for (layout, stdin) in prover_stdin_layouts(&inputs, &digest, foreign_context) {
        assert_withdrawal_bound(
            &format!("foreign context, message = digest, {layout}"),
            &owner.public_key,
            &signature,
            stdin,
        );
    }
}

#[test]
fn binding_acvp_vectors_are_not_withdrawal_authorizations() {
    let d2 = keccak256(b"relation tests: a withdrawal digest attached to an ACVP vector");
    let mut exercised = 0;
    for vector in acvp_vectors().iter().filter(|vector| vector.test_passed) {
        let public_key = decode_hex(&vector.pk);
        let message = decode_hex(&vector.message);
        let context = decode_hex(&vector.context);
        let signature = decode_hex(&vector.signature);
        assert!(
            signature_verifies(&public_key, &message, &context, &signature),
            "precondition: tcId {}",
            vector.tc_id
        );
        let inputs = withdrawal_inputs(d2, &public_key, &signature);
        for (layout, stdin) in prover_stdin_layouts(&inputs, &message, &context) {
            assert_withdrawal_bound(
                &format!(
                    "ACVP tcId {} ({}-byte context), D2 digest, {layout}",
                    vector.tc_id,
                    context.len()
                ),
                &public_key,
                &signature,
                stdin,
            );
        }
        exercised += 1;
    }
    assert!(exercised > 0, "at least one valid ACVP vector");
}

#[test]
fn binding_committed_digest_is_the_verified_digest() {
    // The dual of the M1/D2 case: the committed value must be the verified value, never a
    // neighbouring input offered alongside it.
    let fixture = library_fixture();
    let d2 = keccak256(b"relation tests: a digest offered alongside a signed one");
    let inputs = withdrawal_inputs(fixture.digest, &fixture.public_key, &fixture.signature);
    for (layout, stdin) in prover_stdin_layouts(&inputs, &d2, &[]) {
        assert_withdrawal_bound(
            &format!("signed digest committed, other digest offered as message, {layout}"),
            &fixture.public_key,
            &fixture.signature,
            stdin,
        );
    }
}
