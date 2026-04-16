use anyhow::Context;
use fortgate_id::field_encoding::hex_decode_fr_bytes;
use fortgate_id::{create_fortgate_witness, parse_sp1_inputs};
use fortgate_sp1_shared::Limbs64;
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use std::env;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_path = env::args()
        .nth(1)
        .or_else(|| env::var("FORTGATE_CERT_DER").ok())
        .context("usage: fortgate-id-script <cert.der> or set FORTGATE_CERT_DER")?;

    let cert_der = fs::read(&cert_path).with_context(|| format!("read {cert_path}"))?;

    let sp1 = parse_sp1_inputs(&cert_der)?;
    let witness = create_fortgate_witness(&cert_der).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let rfc_commitment =
        hex_decode_fr_bytes(&witness.rfc_commitment).map_err(|e| anyhow::anyhow!(e))?;

    let elf = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();

    stdin.write(&Limbs64(sp1.modulus_limbs));
    stdin.write(&sp1.exponent);
    stdin.write(&Limbs64(sp1.signature_limbs));
    stdin.write(&sp1.tbs_sha256);
    stdin.write(&rfc_commitment);

    println!("Starting STARK proof generation...");
    let (pk, vk) = client.setup(elf);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .context("proving failed")?;

    let output_dir = Path::new("sp1_output");
    fs::create_dir_all(output_dir)?;

    fs::write(output_dir.join("proof.bin"), proof.bytes())?;
    let vk_json = serde_json::json!({
        "verifying_key_hash_hex": vk.bytes32(),
        "sp1_circuit_version": sp1_sdk::SP1_CIRCUIT_VERSION,
    });
    fs::write(
        output_dir.join("vkey.json"),
        serde_json::to_vec_pretty(&vk_json)?,
    )?;

    println!("Wrote sp1_output/proof.bin and sp1_output/vkey.json");
    Ok(())
}
