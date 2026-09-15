//! Runs one guest program natively on one request, for the Solidity consumer tests
//! (test/ZKMLDSAWithdrawalRelationConsumers.test.ts): they learn which journals a program commits,
//! and so which proofs can exist, without the SP1 toolchain.
//!
//! usage: guest-native-execute <request.json>
//!   {"program": "withdrawal" | "acvp", "stdin": ["0x…", …]}   raw prover stdin, one hex buffer each
//!   {"program": "withdrawal", "honest": {"withdrawalDigest": "0x…", "publicKey": "0x…",
//!    "signature": "0x…", "chainId": 31337, "verifierAddress": "0x…"}}
//!                                                            the host's honest encoding of a withdrawal
//!
//! Prints `{"accepted": true, "publicValues": "0x…"}` or
//! `{"accepted": false, "reason": "…", "committed": "0x…"}` and exits 0 either way. Exits 2 when the
//! request itself is unusable.
use mldsa65_relation_tests::{
    execute, honest_withdrawal_stdin, Outcome, Program, WithdrawalInputs,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    program: String,
    #[serde(default)]
    stdin: Option<Vec<String>>,
    #[serde(default)]
    honest: Option<HonestWithdrawal>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HonestWithdrawal {
    withdrawal_digest: String,
    public_key: String,
    signature: String,
    chain_id: u64,
    verifier_address: String,
}

fn fail(message: String) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}

fn hex_bytes(label: &str, value: &str) -> Vec<u8> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .unwrap_or_else(|error| fail(format!("{label}: {error}")))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        fail("usage: guest-native-execute <request.json>".to_string());
    }
    let raw = std::fs::read_to_string(&args[1])
        .unwrap_or_else(|error| fail(format!("reading {}: {error}", args[1])));
    let request: Request = serde_json::from_str(&raw)
        .unwrap_or_else(|error| fail(format!("parsing the request: {error}")));
    let program = match request.program.as_str() {
        "withdrawal" => Program::Withdrawal,
        "acvp" => Program::Acvp,
        other => fail(format!("unknown program {other:?}")),
    };

    let stdin = match (request.stdin, request.honest) {
        (Some(buffers), None) => buffers
            .iter()
            .enumerate()
            .map(|(index, buffer)| hex_bytes(&format!("stdin[{index}]"), buffer))
            .collect(),
        (None, Some(honest)) if program == Program::Withdrawal => {
            let withdrawal_digest: [u8; 32] =
                hex_bytes("withdrawalDigest", &honest.withdrawal_digest)
                    .try_into()
                    .unwrap_or_else(|_| fail("withdrawalDigest must be 32 bytes".to_string()));
            let verifier_address: [u8; 20] = hex_bytes("verifierAddress", &honest.verifier_address)
                .try_into()
                .unwrap_or_else(|_| fail("verifierAddress must be 20 bytes".to_string()));
            honest_withdrawal_stdin(&WithdrawalInputs {
                withdrawal_digest,
                public_key: hex_bytes("publicKey", &honest.public_key),
                signature: hex_bytes("signature", &honest.signature),
                chain_id: honest.chain_id,
                verifier_address,
            })
        }
        _ => fail(
            "a request carries exactly one of `stdin` or, for the withdrawal program, `honest`"
                .to_string(),
        ),
    };

    // Most requests are expected to be rejected; keep the default hook from printing every panic.
    std::panic::set_hook(Box::new(|_| {}));
    let out = match execute(program, stdin) {
        Outcome::Accepted(public_values) => serde_json::json!({
            "accepted": true,
            "publicValues": format!("0x{}", hex::encode(public_values)),
        }),
        Outcome::Rejected { reason, committed } => serde_json::json!({
            "accepted": false,
            "reason": reason,
            "committed": format!("0x{}", hex::encode(committed)),
        }),
    };
    println!("{out}");
}
