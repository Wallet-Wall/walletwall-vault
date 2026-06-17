//! SP1 host / prover for the ML-DSA-65 guest.
//!
//! Subcommands:
//!   execute <inputs.json>  Run the guest in SP1 execute mode (no proving) and
//!                          report the RISC-V cycle count. This is the feasibility
//!                          benchmark from docs/ZK_Verifier_Feasibility.md and needs
//!                          only the SP1 toolchain — no prover network credentials.
//!   vkey                   Print the program verification key (bytes32) for the
//!                          compiled guest. This is the value to deploy as
//!                          ZKMLDSAVerifier.PROGRAM_VKEY.
//!   prove <inputs.json>    Generate a real Groth16 proof and emit JSON with the
//!                          vkey, public values, and proof bytes for on-chain
//!                          verification. Requires a configured SP1 prover (local
//!                          GPU/CPU or the Succinct Prover Network via SP1_PROVER /
//!                          NETWORK_PRIVATE_KEY).
//!
//! This crate is NOT part of CI. See docs/ZK_Prover_Runbook.md.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// ELF of the compiled ML-DSA-65 guest (package name `mldsa65-guest`).
pub const MLDSA_ELF: &[u8] = include_elf!("mldsa65-guest");

/// Mirror of the guest's `GuestInputs`. Field order and types MUST match
/// zkvm/guest/src/main.rs exactly, or serde deserialization in the guest fails.
#[derive(Serialize, Deserialize)]
struct GuestInputs {
    pub withdrawal_digest: [u8; 32],
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
    /// Raw signed message for FIPS 204 external/pure verification. Empty on the
    /// withdrawal path (the digest is the message); set only for ACVP conformance.
    pub message: Vec<u8>,
    /// FIPS 204 context string. Empty on the withdrawal path; ACVP vectors carry one.
    pub context: Vec<u8>,
}

/// JSON shape accepted on disk for `execute` / `prove`.
///
/// `message` and `context` are optional and default to empty: a withdrawal
/// `inputs.json` omits them and the guest verifies the 32-byte `withdrawalDigest`
/// under the empty context. NIST ACVP conformance inputs set both to route the
/// vector's arbitrary-length message and domain-separation context through the guest.
#[derive(Deserialize)]
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
    #[serde(default)]
    message: String,
    #[serde(default)]
    context: String,
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
    // Empty strings decode to empty vectors -> the withdrawal path. ACVP inputs
    // supply hex-encoded message/context that the guest verifies via verify_with_context.
    let message = hex::decode(strip0x(&file.message)).context("decoding message")?;
    let context = hex::decode(strip0x(&file.context)).context("decoding context")?;

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
        message,
        context,
    })
}

fn stdin_for(inputs: &GuestInputs) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(inputs);
    stdin
}

fn cmd_execute(path: &str) -> Result<()> {
    let inputs = load_inputs(path)?;
    let stdin = stdin_for(&inputs);

    let client = ProverClient::from_env();
    let (public_values, report) = client
        .execute(MLDSA_ELF, &stdin)
        .run()
        .map_err(|e| anyhow!("guest execution failed (invalid signature or bad inputs): {e}"))?;

    let cycles = report.total_instruction_count();
    let out = serde_json::json!({
        "cycles": cycles,
        "publicValues": format!("0x{}", hex::encode(public_values.as_slice())),
    });
    println!("{out}");
    Ok(())
}

fn cmd_vkey() -> Result<()> {
    let client = ProverClient::from_env();
    let (_pk, vk) = client.setup(MLDSA_ELF);
    let out = serde_json::json!({ "vkey": vk.bytes32() });
    println!("{out}");
    Ok(())
}

fn cmd_prove(path: &str) -> Result<()> {
    let inputs = load_inputs(path)?;
    let stdin = stdin_for(&inputs);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(MLDSA_ELF);

    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .context("generating Groth16 proof")?;

    // Sanity-check the proof locally before emitting it.
    client.verify(&proof, &vk).context("verifying generated proof")?;

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
        other => Err(anyhow!(
            "unknown command {other:?}; expected one of: execute, vkey, prove"
        )),
    }
}
