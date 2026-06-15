//! CLI PoC hardware trust (H1): keygen, challenge, sign, verify-local.

use anyhow::Context;
use clap::{Parser, Subcommand};
use fortgate_id::hw_trust::backends::{software_poc::SoftwarePocBackend, HwTrustBackend};
use fortgate_id::hw_trust::{
    default_software_backend, sign_challenge_with_backend, verify_handshake_local, HwBackend,
    HwHandshake, MHw, VerifyStatus,
};
use fortgate_id::types::SecurityTier;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fortgate-hw-poc", about = "Fortgate hardware trust PoC (H1)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Genera llave P-256 software_poc en ~/.fortgate/poc_hw/
    Keygen {
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Emite challenge.json (M_hw)
    Challenge {
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long, default_value = "software_poc")]
        backend: String,
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
    /// Firma challenge y escribe handshake.json
    Sign {
        #[arg(long, short)]
        challenge: PathBuf,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
    /// Verificación criptográfica local (sin ZK Midnight aún)
    VerifyLocal {
        #[arg(long, short)]
        handshake: PathBuf,
    },
    /// keygen → challenge → sign → verify-local
    Demo {
        #[arg(long)]
        tmp: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { out } => cmd_keygen(out),
        Commands::Challenge { out, backend, key_dir } => cmd_challenge(out, &backend, key_dir),
        Commands::Sign {
            challenge,
            out,
            key_dir,
        } => cmd_sign(challenge, out, key_dir),
        Commands::VerifyLocal { handshake } => cmd_verify_local(handshake),
        Commands::Demo { tmp } => cmd_demo(tmp),
    }
}

fn backend_from_name(name: &str, key_dir: Option<PathBuf>) -> anyhow::Result<SoftwarePocBackend> {
    match name {
        "software_poc" => {
            let b = key_dir
                .map(SoftwarePocBackend::new)
                .unwrap_or_else(default_software_backend);
            Ok(b)
        }
        other => anyhow::bail!("backend no soportado en H1: {other} (usa software_poc)"),
    }
}

fn cmd_keygen(out: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = out
        .map(SoftwarePocBackend::new)
        .unwrap_or_else(default_software_backend);
    let vk = backend.keygen().context("keygen")?;
    let spki = backend.pubkey_spki_der()?;
    eprintln!("⚠️  software_poc — no es Secure Enclave real (tier Medium)");
    eprintln!("Llave escrita en: {}", backend.key_path().display());
    eprintln!("pubkey commitment: {}", fortgate_id::hw_trust::pubkey_commitment_hex(&spki));
    eprintln!("verifying key ok: {} bytes SPKI", spki.len());
    let _ = vk;
    Ok(())
}

fn cmd_challenge(out: PathBuf, backend_name: &str, key_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = backend_from_name(backend_name, key_dir)?;
    if !backend.key_path().exists() {
        backend.keygen().context("auto keygen")?;
    }
    let spki = backend.pubkey_spki_der()?;
    let m_hw = MHw::new_challenge(
        HwBackend::SoftwarePoc,
        SecurityTier::Medium,
        &spki,
        Some("fortgate-hw-poc-cli".into()),
    )?;
    let json = serde_json::to_string_pretty(&m_hw)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&out, json)?;
    eprintln!("challenge → {}", out.display());
    eprintln!("challenge_hash = {}", hex::encode(m_hw.challenge_hash()?));
    Ok(())
}

fn cmd_sign(challenge: PathBuf, out: PathBuf, key_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let backend = backend_from_name("software_poc", key_dir)?;
    let raw = fs::read_to_string(&challenge)?;
    let m_hw: MHw = serde_json::from_str(&raw)?;
    let hs = sign_challenge_with_backend(&backend, &m_hw)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&out, hs.to_json_pretty()?)?;
    eprintln!("handshake → {}", out.display());
    eprintln!("hw_nullifier = {}", hs.hw_nullifier);
    Ok(())
}

fn cmd_verify_local(handshake: PathBuf) -> anyhow::Result<()> {
    let raw = fs::read_to_string(&handshake)?;
    let hs = HwHandshake::from_json(&raw)?;
    let res = verify_handshake_local(&hs)?;
    match res.status {
        VerifyStatus::Green => {
            eprintln!("✅ GREEN — {}", res.message);
            Ok(())
        }
        VerifyStatus::Red => {
            eprintln!("❌ RED — {}", res.message);
            std::process::exit(20);
        }
    }
}

fn cmd_demo(tmp: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = tmp.unwrap_or_else(|| PathBuf::from("/tmp/fg-hw-demo"));
    fs::create_dir_all(&dir)?;
    cmd_keygen(Some(dir.clone()))?;
    let challenge_path = dir.join("challenge.json");
    let handshake_path = dir.join("handshake.json");
    cmd_challenge(challenge_path.clone(), "software_poc", Some(dir.clone()))?;
    cmd_sign(challenge_path, handshake_path.clone(), Some(dir.clone()))?;
    cmd_verify_local(handshake_path)?;
    eprintln!("demo OK en {}", dir.display());
    Ok(())
}
