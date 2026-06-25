//! `evidence-validator` — offline, deterministic evidence-shape CLI (Phase 1 scaffold).
//!
//! SCAFFOLD / OFFLINE ONLY. Reads ONE committed evidence JSON artifact from disk
//! and reports whether it is shape-valid against
//! `walletwall.zk-adapter-evidence-response.v1`. It performs NO network I/O, NO
//! prover execution, NO SP1 SDK build, NO signing, NO key access, and NO chain
//! access, and it makes NO cryptographic truth claim (it does not recompute the
//! keccak256 `etag`). This is the offline-CLI analogue of the existing TypeScript
//! `validate:*` scripts; the TypeScript validators remain the CI source of truth.
//!
//! Usage:
//!   evidence-validator <path-to-evidence-response.json>
//!
//! Exit codes:
//!   0  the artifact is shape-valid
//!   1  the artifact failed validation, or could not be read
//!   2  usage error (no path argument)
//!
//! See `docs/Rust_Evidence_Tooling_Scaffold.md`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use evidence_validator::validate_evidence_response;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "evidence-validator".to_string());

    let path = match args.next() {
        Some(arg) if arg != "-h" && arg != "--help" => arg,
        _ => {
            eprintln!("usage: {program} <path-to-evidence-response.json>");
            eprintln!("  offline shape check of a zk-adapter-evidence-response.v1 artifact");
            eprintln!("  no network, prover, chain, or keys; not a cryptographic check");
            return ExitCode::from(2);
        }
    };

    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("error: could not read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = validate_evidence_response(&contents);
    if outcome.ok {
        println!("OK: {path} is shape-valid (offline shape check only; not cryptographic)");
        ExitCode::SUCCESS
    } else {
        eprintln!("FAIL: {path} did not pass the offline shape check:");
        for problem in &outcome.problems {
            eprintln!("  - {problem}");
        }
        ExitCode::FAILURE
    }
}
