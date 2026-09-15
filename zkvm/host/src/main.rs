//! SP1 host / prover for the ML-DSA-65 guest programs.
//!
//! zkvm/guest builds two SP1 programs with separate ELFs and program vkeys:
//!   mldsa65-withdrawal     Withdrawal authorization: the program ZKMLDSAVerifier.PROGRAM_VKEY pins.
//!   mldsa65-acvp           NIST ACVP sigVer conformance only. Never a verifier's program.
//!
//! Subcommands for the withdrawal program:
//!   execute <inputs.json>  Run the withdrawal program in SP1 execute mode (no proving) and
//!                          report the RISC-V cycle count. This is the feasibility
//!                          benchmark from docs/ZK_Verifier_Feasibility.md and needs
//!                          only the SP1 toolchain — no prover network credentials.
//!   vkey                   Print the withdrawal program's verification key (bytes32).
//!                          This is the value to deploy as ZKMLDSAVerifier.PROGRAM_VKEY.
//!   prove <inputs.json>    Generate a real Groth16 proof and emit JSON with the
//!                          vkey, public values, and proof bytes for on-chain
//!                          verification. Requires a configured SP1 prover (local
//!                          GPU/CPU or the Succinct Prover Network via SP1_PROVER /
//!                          NETWORK_PRIVATE_KEY).
//!
//! Subcommands for the ACVP conformance program:
//!   acvp-execute <inputs.json>  Run the ACVP program in SP1 execute mode on one sigVer case.
//!   acvp-vkey                   Print the ACVP program's verification key, for comparison only.
//!
//! This crate is NOT part of CI. See docs/ZK_Prover_Runbook.md.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, HashableKey, ProvingKey, SP1Stdin};

/// ELF of the withdrawal program (bin target `mldsa65-withdrawal` of zkvm/guest).
pub const WITHDRAWAL_ELF: Elf = include_elf!("mldsa65-withdrawal");

/// ELF of the ACVP conformance program (bin target `mldsa65-acvp` of zkvm/guest).
pub const ACVP_ELF: Elf = include_elf!("mldsa65-acvp");

/// Mirror of the withdrawal program's `GuestInputs`. Field order and types MUST match
/// zkvm/guest/src/bin/withdrawal.rs exactly, or serde deserialization in the guest fails.
#[derive(Serialize, Deserialize)]
struct GuestInputs {
    pub withdrawal_digest: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
}

/// JSON shape accepted on disk for `execute` / `prove`: exactly the withdrawal fields. Any other
/// key (an ACVP `message` or `context`, say) is refused instead of silently ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputsFile {
    #[serde(rename = "withdrawalDigest")]
    withdrawal_digest: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
    #[serde(rename = "chainId")]
    chain_id: u64,
    #[serde(rename = "verifierAddress")]
    verifier_address: String,
}

/// Mirror of the ACVP program's `AcvpInputs`. Field order and types MUST match
/// zkvm/guest/src/bin/acvp.rs exactly.
#[derive(Serialize, Deserialize)]
struct AcvpInputs {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub context: Vec<u8>,
    pub signature: Vec<u8>,
}

/// JSON shape accepted on disk for `acvp-execute`: one ACVP sigVer case, hex-encoded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcvpInputsFile {
    #[serde(rename = "publicKey")]
    public_key: String,
    message: String,
    context: String,
    signature: String,
}

fn strip0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn load_inputs(path: &str) -> Result<GuestInputs> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading inputs file {path}"))?;
    let file: InputsFile = serde_json::from_str(&raw).context("parsing inputs JSON")?;

    let digest = hex::decode(strip0x(&file.withdrawal_digest)).context("decoding withdrawalDigest")?;
    let verifier = hex::decode(strip0x(&file.verifier_address)).context("decoding verifierAddress")?;
    let public_key = hex::decode(strip0x(&file.public_key)).context("decoding publicKey")?;
    let signature = hex::decode(strip0x(&file.signature)).context("decoding signature")?;

    if digest.len() != 32 {
        return Err(anyhow!("withdrawalDigest must be 32 bytes, got {}", digest.len()));
    }
    if verifier.len() != 20 {
        return Err(anyhow!("verifierAddress must be 20 bytes, got {}", verifier.len()));
    }

    let mut withdrawal_digest = [0u8; 32];
    withdrawal_digest.copy_from_slice(&digest);
    let mut verifier_address = [0u8; 20];
    verifier_address.copy_from_slice(&verifier);

    Ok(GuestInputs {
        withdrawal_digest,
        public_key,
        signature,
        chain_id: file.chain_id,
        verifier_address,
    })
}

fn load_acvp_inputs(path: &str) -> Result<AcvpInputs> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading ACVP inputs file {path}"))?;
    let file: AcvpInputsFile = serde_json::from_str(&raw).context("parsing ACVP inputs JSON")?;
    Ok(AcvpInputs {
        public_key: hex::decode(strip0x(&file.public_key)).context("decoding publicKey")?,
        message: hex::decode(strip0x(&file.message)).context("decoding message")?,
        context: hex::decode(strip0x(&file.context)).context("decoding context")?,
        signature: hex::decode(strip0x(&file.signature)).context("decoding signature")?,
    })
}

fn stdin_for<T: Serialize>(inputs: &T) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(inputs);
    stdin
}

/// Executes `elf` on `stdin` (no proving) and prints the cycle count and public values.
fn execute_and_report(elf: Elf, stdin: SP1Stdin) -> Result<()> {
    let client = ProverClient::from_env();
    let (public_values, report) = client
        .execute(elf, stdin)
        .run()
        .map_err(|e| anyhow!("guest execution failed (invalid signature or bad inputs): {e}"))?;
    // sp1-sdk 6.x reports a guest panic (e.g. an invalid signature) as a non-zero exit code in the
    // execution report rather than as an error, so check it to keep rejections a failing command.
    if report.exit_code != 0 {
        return Err(anyhow!(
            "guest execution failed (invalid signature or bad inputs): exit code {}",
            report.exit_code
        ));
    }

    let cycles = report.total_instruction_count();
    let out = serde_json::json!({
        "cycles": cycles,
        "publicValues": format!("0x{}", hex::encode(public_values.as_slice())),
    });
    println!("{out}");
    Ok(())
}

/// Prints the program verification key (bytes32) of `elf`.
fn print_vkey(elf: Elf) -> Result<()> {
    let client = ProverClient::from_env();
    let pk = client.setup(elf)?;
    let out = serde_json::json!({ "vkey": pk.verifying_key().bytes32() });
    println!("{out}");
    Ok(())
}

fn cmd_execute(path: &str) -> Result<()> {
    let inputs = load_inputs(path)?;
    execute_and_report(WITHDRAWAL_ELF, stdin_for(&inputs))
}

fn cmd_acvp_execute(path: &str) -> Result<()> {
    let inputs = load_acvp_inputs(path)?;
    execute_and_report(ACVP_ELF, stdin_for(&inputs))
}

fn cmd_vkey() -> Result<()> {
    print_vkey(WITHDRAWAL_ELF)
}

fn cmd_acvp_vkey() -> Result<()> {
    print_vkey(ACVP_ELF)
}

fn cmd_prove(path: &str) -> Result<()> {
    let inputs = load_inputs(path)?;
    let stdin = stdin_for(&inputs);

    let client = ProverClient::from_env();
    let pk = client.setup(WITHDRAWAL_ELF)?;
    let vk = pk.verifying_key();

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("generating Groth16 proof")?;

    // Sanity-check the proof locally before emitting it.
    client.verify(&proof, vk, None).context("verifying generated proof")?;

    let out = serde_json::json!({
        "vkey": vk.bytes32(),
        "publicValues": format!("0x{}", hex::encode(proof.public_values.as_slice())),
        "proofBytes": format!("0x{}", hex::encode(proof.bytes())),
    });
    println!("{out}");
    Ok(())
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");

    match command {
        "execute" => {
            let path = args.get(2).ok_or_else(|| anyhow!("usage: mldsa65-host execute <inputs.json>"))?;
            cmd_execute(path)
        }
        "vkey" => cmd_vkey(),
        "prove" => {
            let path = args.get(2).ok_or_else(|| anyhow!("usage: mldsa65-host prove <inputs.json>"))?;
            cmd_prove(path)
        }
        "acvp-execute" => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow!("usage: mldsa65-host acvp-execute <inputs.json>"))?;
            cmd_acvp_execute(path)
        }
        "acvp-vkey" => cmd_acvp_vkey(),
        other => Err(anyhow!(
            "unknown command {other:?}; expected one of: execute, vkey, prove, acvp-execute, acvp-vkey"
        )),
    }
}
